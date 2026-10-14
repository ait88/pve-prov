#!/usr/bin/env bash
# =============================================================================
# Smoke tests for prov.sh — no Proxmox host needed.
#
# Fake `qm`, `pct`, `pvesm`, `pvesh`, `pveam`, `getent`, `id` and `curl` binaries
# are put first on PATH. They keep a little state (which guests exist, what
# `cicustom` points at) and record every call, so we can assert on what prov.sh
# *would* do on a real host. Network access is faked too (canned release
# metadata and images), so the tests are hermetic.
#
# The stubs deliberately model the Proxmox behaviours that matter for the bugs
# this script has had: `qm start` FAILS if `cicustom` points at a missing
# snippet, `pvesm list --vmid` returns snippet files whatever the ID, and a
# storage that cannot be listed returns an error.
#
# This checks the script's logic and the commands it issues. It can NOT check
# that Proxmox accepts them — do a real VM and CT run on a PVE host before
# tagging a release.
#
# Usage: tests/smoke.sh        (from anywhere)
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROV="$ROOT/prov.sh"
T="$(mktemp -d)"
export T
trap 'rm -rf "$T"' EXIT

# The script reads PROV_* variables; make sure none leak in from the caller.
for _v in $(compgen -v | grep '^PROV_'); do unset "$_v"; done
unset _v

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  ok   $*"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

# --------------------------------------------------------------------------- stubs
BIN="$T/bin"
mkdir -p "$BIN" "$T/state" "$T/pushed" "$T/snippets" "$T/cache" "$T/nodes"
: > "$T/log"
: > "$T/used_ids"
: > "$T/orphans"

cat > "$BIN/id" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "-u" ]]; then echo 0; else exec /usr/bin/id "$@"; fi
EOF

cat > "$BIN/pveversion" <<'EOF'
#!/bin/bash
echo "pve-manager/9.0.3/abc123 (running kernel: 6.14.8-2-pve)"
EOF

cat > "$BIN/pvesh" <<'EOF'
#!/bin/bash
echo "pvesh $*" >> "$T/log"
if [[ "$1 $2" == "get /cluster/nextid" ]]; then
    if [[ "${3:-}" == "--vmid" ]]; then
        if grep -qx "$4" "$T/used_ids"; then
            echo "400 Parameter verification failed. vmid: VM $4 already exists on node 'pve'" >&2
            exit 255
        fi
        # RACE_ID: free on the first look, taken by the time we look again
        if [[ "${RACE_ID:-}" == "$4" ]]; then
            if [[ -f "$T/state/race-$4" ]]; then
                echo "400 Parameter verification failed. vmid: VM $4 already exists on node 'pve'" >&2
                exit 255
            fi
            touch "$T/state/race-$4"
        fi
        echo "$4"; exit 0
    fi
    echo "${NEXTID:-900}"; exit 0
fi
exit 0
EOF

cat > "$BIN/pvesm" <<'EOF'
#!/bin/bash
echo "pvesm $*" >> "$T/log"
case "$1" in
    status)
        echo "Name       Type     Status     Total   Used  Available  %"
        if [[ "${PVESM_NONE:-0}" != "1" ]]; then
            echo "local      dir      active      1000    100        900  10%"
            echo "local-zfs  zfspool  active      1000    100        900  10%"
        fi
        [[ "${PVESM_PBS:-0}" == "1" ]] && echo "pbs-store  pbs      active      1000    100        900  10%"
        [[ "${PVESM_INACTIVE:-0}" == "1" ]] && echo "ghost-pbs  pbs      inactive       0      0          0  N/A"
        exit 0 ;;
    list)
        # pvesm list <storage> --vmid <id>
        if [[ "${PVESM_FAIL_STORAGE:-}" == "$2" ]]; then
            echo "storage '$2' is not online" >&2
            exit 255
        fi
        echo "Volid Format Type Size VMID"
        # Like the real thing, snippet files are listed whatever the --vmid
        # (and a snippet's last column is its size, not a VMID).
        [[ "${SNIPPETS_ON:-0}" == "1" && "$2" == "local" ]] && echo "local:snippets/hook.pl snippet snippets 930"
        # orphans file lines: "<vmid> <storage> <volid> [type]"
        awk -v s="$2" -v id="$4" '$1 == id && $2 == s {t = ($4 == "" ? "images" : $4); print $3 " raw " t " 1 " $1}' "$T/orphans"
        exit 0 ;;
esac
EOF

cat > "$BIN/pveam" <<'EOF'
#!/bin/bash
echo "pveam $*" >> "$T/log"
case "$1" in
    available)
        for t in debian-13-standard_13.1-2_amd64.tar.zst debian-12-standard_12.12-1_amd64.tar.zst \
                 ubuntu-26.04-standard_26.04-1_amd64.tar.zst ubuntu-24.04-standard_24.04-2_amd64.tar.zst; do
            echo "system          $t"
        done ;;
esac
exit 0
EOF

# Guest-config helpers shared by the qm and pct stubs
cat > "$BIN/_guest.sh" <<'EOF'
tags_line() {
    if [[ "${NOTAG:-0}" == "1" ]]; then return 0; fi
    if [[ -n "${TAGS:-}" ]]; then echo "tags: $TAGS"; else echo "tags: pve-prov"; fi
}
EOF

cat > "$BIN/qm" <<'EOF'
#!/bin/bash
echo "qm $*" >> "$T/log"
source "$(dirname "$0")/_guest.sh"
S="$T/state"
case "$1" in
    create)
        [[ "${FAIL_AT:-}" == "create" ]] && exit 1
        echo "$*" > "$S/vm$2.create"; touch "$S/guest-$2" ;;
    set)
        id="$2"
        # KILL_PARENT_PIPE: deliver a SIGPIPE to the calling script right here (a dropped terminal)
        [[ "${KILL_PARENT_PIPE:-0}" == "1" && "$*" == *"--scsi0"* ]] && kill -PIPE "$PPID"
        if [[ "${FAIL_AT:-}" == "scsi0" && "$*" == *"--scsi0"* ]]; then sleep "${STUB_DELAY:-0}"; exit 1; fi
        if [[ "$*" == *"--cicustom user=local:snippets/"* ]]; then
            all="$*"; f="${all#*snippets/}"; f="${f%% *}"; echo "$f" > "$S/cicustom-$id"
        fi
        if [[ "$*" == *"--delete cicustom"* ]]; then
            [[ "${DELETE_FAIL:-0}" == "1" ]] && exit 1
            rm -f "$S/cicustom-$id"
        fi
        if [[ "$*" == *"--description"* ]]; then
            [[ "${DESC_FAIL:-0}" == "1" ]] && exit 1
            echo "$*" > "$S/desc-$id"
            echo "${LC_ALL:-unset}" > "$S/desc-locale-$id"
        fi ;;
    start)
        id="$2"
        [[ -f "$S/guest-$id" ]] || { echo "Configuration file 'qemu-server/$id.conf' does not exist" >&2; exit 2; }
        if [[ -f "$S/cicustom-$id" ]]; then
            f="$(cat "$S/cicustom-$id")"
            # What real Proxmox does: the cloud-init ISO is rebuilt at start, which needs the snippet.
            [[ -f "$PROV_SNIPPET_DIR/$f" ]] || { echo "TASK ERROR: volume 'local:snippets/$f' does not exist" >&2; exit 255; }
            cp "$PROV_SNIPPET_DIR/$f" "$T/captured-userdata.yml"
            stat -c %a "$PROV_SNIPPET_DIR/$f" > "$T/snippet-mode"
        fi
        [[ "${FAIL_AT:-}" == "start" ]] && exit 1 ;;
    destroy)
        [[ "${DESTROY_FAIL:-0}" == "1" ]] && exit 1
        rm -f "$S/guest-$2" "$S/cicustom-$2" ;;
    guest)
        case "$2" in
            cmd)
                [[ "${NOIP:-0}" == "1" ]] && exit 1
                echo '{"name":"ens18","ip-addresses":[{"ip-address":"10.0.0.77","ip-address-type":"ipv4"}]}' ;;
            exec)
                shift 4   # drop: guest exec <id> --
                cmd="$*"; ok=1
                case "$cmd" in
                    "test -f /var/lib/cloud/instance/boot-finished") ok="${GUEST_FINISHED:-1}" ;;
                    "test -f /var/lib/cloud/pve-prov.ok")            ok="${GUEST_OK:-1}" ;;
                    "cat /var/lib/cloud/pve-prov.failed")
                        printf '{\n   "exitcode" : 0,\n   "exited" : 1,\n   "out-data" : "%s\\n"\n}\n' "${FAILED_NAMES:-}"
                        exit 0 ;;
                esac
                if [[ "$ok" == "1" ]]; then echo '{ "exitcode" : 0, "exited" : 1 }'
                else
                    echo '{ "exitcode" : 1, "exited" : 1 }'
                    [[ "${GUEST_EXEC_RC0:-0}" == "1" ]] || exit 1
                fi ;;
        esac ;;
    config)
        [[ "${QM_CONFIG_FAIL:-0}" == "1" ]] && { echo "cannot read config" >&2; exit 1; }
        [[ -f "$S/guest-$2" ]] || { echo "Configuration file 'nodes/pve/qemu-server/$2.conf' does not exist" >&2; exit 2; }
        tags_line
        [[ -f "$S/cicustom-$2" ]] && echo "cicustom: user=local:snippets/$(cat "$S/cicustom-$2")"
        echo "name: test" ;;
esac
exit 0
EOF

cat > "$BIN/pct" <<'EOF'
#!/bin/bash
echo "pct $*" >> "$T/log"
source "$(dirname "$0")/_guest.sh"
S="$T/state"
case "$1" in
    create)
        [[ "${FAIL_AT:-}" == "pct_create" ]] && exit 1
        echo "$*" > "$S/ct$2.create"; touch "$S/guest-$2" ;;
    start) [[ "${FAIL_AT:-}" == "pct_start" ]] && exit 1 ;;
    exec)
        if [[ "$*" == *"hostname -I"* ]]; then echo "10.0.0.50 "; exit 0; fi
        if [[ -n "${PCT_EXEC_FAIL:-}" && "$*" == *"$PCT_EXEC_FAIL"* ]]; then echo "stub: command failed" >&2; exit 1; fi ;;
    push)
        # pct push <id> <src> <dest> [--perms m]
        cp "$3" "$T/pushed/$(echo "$4" | tr / _)"
        echo "$*" > "$T/pushed/args$(echo "$4" | tr / _)" ;;
    set)
        if [[ "$*" == *"--description"* ]]; then
            [[ "${DESC_FAIL:-0}" == "1" ]] && exit 1
            echo "$*" > "$S/desc-$2"
            echo "${LC_ALL:-unset}" > "$S/desc-locale-$2"
        fi ;;
    destroy)
        [[ "${DESTROY_FAIL:-0}" == "1" ]] && exit 1
        rm -f "$S/guest-$2" ;;
    config)
        [[ -f "$S/guest-$2" ]] || { echo "Configuration file 'nodes/pve/lxc/$2.conf' does not exist" >&2; exit 2; }
        tags_line ;;
esac
exit 0
EOF

cat > "$BIN/curl" <<'EOF'
#!/bin/bash
# Fake network. Last http(s) argument is the URL; -o gives the output file.
[[ "${CURL_OFFLINE:-0}" == "1" ]] && exit 6
url=""; out=""
while (( $# )); do
    case "$1" in
        -o) out="$2"; shift ;;
        http*) url="$1" ;;
    esac
    shift
done
echo "$url" >> "$T/curl.log"
fake_sha512() { printf 'FAKEIMAGE' | sha512sum | awk '{print $1}'; }
fake_sha256() { printf 'FAKEIMAGE' | sha256sum | awk '{print $1}'; }
case "$url" in
    */dists/stable/Release)    printf 'Origin: Debian\nCodename: trixie\nVersion: 13.7\n' ;;
    */dists/oldstable/Release) printf 'Origin: Debian\nCodename: bookworm\nVersion: 12.15\n' ;;
    */meta-release-lts)
        printf 'Dist: jammy\nVersion: 22.04.5 LTS\nSupported: 1\n\nDist: noble\nVersion: 24.04.5 LTS\nSupported: 1\n\nDist: resolute\nVersion: 26.04.1 LTS\nSupported: 1\n' ;;
    */SHA512SUMS)
        echo "$(fake_sha512)  debian-13-genericcloud-amd64.qcow2"
        echo "$(fake_sha512)  debian-12-genericcloud-amd64.qcow2" ;;
    */SHA256SUMS)
        echo "$(fake_sha256) *resolute-server-cloudimg-amd64.img"
        echo "$(fake_sha256) *noble-server-cloudimg-amd64.img" ;;
    *.qcow2|*.img)
        if [[ "${CORRUPT_DOWNLOAD:-0}" == "1" ]]; then printf 'CORRUPT' > "$out"; else printf 'FAKEIMAGE' > "$out"; fi ;;
    https://github.com/tester.keys)
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkeytestkeytestkeytestkeytestkeytestkey tester@test" ;;
    https://github.com/weird.keys)
        echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIweirdkeyweirdkeyweirdkeyweirdkeyweirdkey work: laptop # home" ;;
    https://github.com/garbage.keys)
        echo "<html>rate limited, try again later</html>" ;;
    *) exit 22 ;;
esac
exit 0
EOF

cat > "$BIN/getent" <<'EOF2'
#!/bin/bash
# Only the apt cache host resolves, and only when GETENT_OK=1.
if [[ "${GETENT_OK:-0}" == "1" && "${2:-}" == apt-cacher-ng.lan ]]; then echo "10.0.7.36  apt-cacher-ng.lan"; exit 0; fi
exit 2
EOF2
chmod +x "$BIN"/*

# --------------------------------------------------------------------------- helpers
echo "hunter22" > "$T/pw"
echo "-hunter22" > "$T/pw-dash"

reset_state() {
    : > "$T/log"; : > "$T/curl.log"
    rm -rf "$T/state"/* "$T/pushed"/* "$T/snippets"/* "$T/captured-userdata.yml" "$T/snippet-mode"
}

run_env() {
    PATH="$BIN:$PATH" PROV_CACHE_DIR="$T/cache" PROV_SNIPPET_DIR="$T/snippets" PROV_PVE_NODES_DIR="$T/nodes" \
        PROV_POLL_SECS=1 PROV_AGENT_WAIT=3 PROV_CLOUDINIT_WAIT=2 "$@"
}

run_prov() {
    # Runs prov.sh against the stubs; stdout+stderr -> $T/out; returns its exit code.
    reset_state
    run_env timeout 120 bash "$PROV" "$@" > "$T/out" 2>&1
}

run_prov_deadterm() {
    # Output goes to a pipe whose reader quits as soon as the guest exists (an SSH
    # session that drops mid-run). The script's next write then raises SIGPIPE.
    reset_state
    ( run_env timeout 120 bash "$PROV" "$@" 2>&1 \
        | { until grep -q '^qm create' "$T/log" 2>/dev/null; do sleep 0.02; done; exit 0; } ) >/dev/null 2>&1
}

second_start_ok() {   # a stopped VM must be startable again (Proxmox rebuilds the cloud-init ISO)
    PATH="$BIN:$PATH" PROV_SNIPPET_DIR="$T/snippets" qm start "$1" >/dev/null 2>&1
}

guest_exists() { [[ -f "$T/state/guest-$1" ]]; }
log_has()   { grep -qE -- "$1" "$T/log"; }
out_has()   { grep -qE -- "$1" "$T/out"; }
check() {   # check "description" command...
    local desc="$1"; shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}
not() { ! "$@"; }

# user-data helpers (PyYAML)
ud="$T/captured-userdata.yml"
ud_py() { python3 - "$ud" "$@"; }   # python code on stdin gets `d` (parsed user-data)
ud_assert() {
    python3 -c "
import sys, yaml
d = yaml.safe_load(open('$ud'))
$1
" 2>/dev/null
}
extract_firstboot() {   # extract_firstboot <dest>
    python3 - "$ud" "$1" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
for f in d['write_files']:
    if f['path'].endswith('pve-prov-firstboot'):
        open(sys.argv[2], 'w').write(f['content'])
PY
}

VM_ARGS=(--yes --type vm --os debian --id 930 --hostname t.lan --bridge lo
         --storage local-zfs --sysadmin-password-file "$T/pw")
CT_ARGS=(--yes --type lxc --os debian --id 931 --hostname ct.lan --bridge lo
         --storage local-zfs --template-storage local --sysadmin-password-file "$T/pw")

# --------------------------------------------------------------------------- tests
echo "== CLI basics"
check "--version works"        bash -c "bash '$PROV' --version | grep -q 'v1\.'"
check "--help works"           bash -c "bash '$PROV' --help | grep -q -- '--cpu-type'"
bash "$PROV" --bogus >/dev/null 2>&1; rc=$?
check "unknown flag exits 2"   test "$rc" -eq 2
check "runs via 'bash -c \"\$(cat prov.sh)\"'"  bash -c "bash -c \"\$(cat '$PROV')\" prov --version | grep -q 'v1\.'"
check "runs piped into bash"   bash -c "cat '$PROV' | bash -s -- --version | grep -q 'v1\.'"
PROV_KEEP_CLOUD_INIT=bogus bash "$PROV" --version >/dev/null 2>&1; rc=$?   # --version exits before validation
check "--version needs no valid env"  test "$rc" -eq 0

echo "== VM happy path (debian, defaults)"
run_prov "${VM_ARGS[@]}"; rc=$?
check "exit 0"                                       test "$rc" -eq 0
check "CPU type defaults to x86-64-v3"               log_has 'qm create 930 .*--cpu x86-64-v3'
check "guest is tagged pve-prov"                     log_has 'qm create 930 .*--tags pve-prov'
check "debian stable resolved live (13.7 -> debian-13)" out_has 'Debian 13 \(trixie'
check "image verified against checksum"              out_has 'downloaded and verified'
check "disk imported from the exact cached image path" log_has "scsi0 local-zfs:0,import-from=$T/cache/debian-13-genericcloud-amd64.qcow2,discard=on"
check "cicustom removed after cloud-init finished"   log_has '^qm set 930 --delete cicustom'
check "snippet file removed with it"                 test -z "$(ls "$T/snippets")"
check "VM can be started a second time"              second_start_ok 930
check "snippet was mode 600 while it existed"        test "$(cat "$T/snippet-mode" 2>/dev/null)" = "600"
check "no destroy on success"                        not log_has 'qm destroy'
check "validated ID cluster-wide"                    log_has 'pvesh get /cluster/nextid --vmid 930'
check "success banner, no problem banner"            bash -c "grep -q 'Provisioning Complete' '$T/out' && ! grep -qE 'WITH PROBLEMS|NOT CONFIRMED' '$T/out'"
if [[ -f "$ud" ]]; then
    check "user-data is valid YAML"          ud_assert "assert isinstance(d, dict)"
    check "hostname is the quoted short name" ud_assert "assert d['hostname'] == 't'"
    check "fqdn is the quoted FQDN"          ud_assert "assert d['fqdn'] == 't.lan'"
    check "sshd drop-in has the right body"  ud_assert "
f = [x for x in d['write_files'] if x['path'].endswith('00-pve-prov.conf')][0]
assert 'PermitRootLogin no' in f['content'] and 'PasswordAuthentication yes' in f['content']"
    check "no runcmd touches sshd_config"    not grep -q "sed -i.*sshd_config" "$ud"
    check "guest agent in packages"          ud_assert "assert 'qemu-guest-agent' in d['packages']"
    check "first-boot script is root-only 0700" ud_assert "
f = [x for x in d['write_files'] if x['path'].endswith('pve-prov-firstboot')][0]
assert f['permissions'] == '0700'"
    check "runcmd only runs the first-boot script" ud_assert "assert d['runcmd'] == [['/usr/local/sbin/pve-prov-firstboot']]"
    check "no apt cache unless asked"        not grep -q 'apt-proxy-detect' "$ud"
    check "…and no mirror rewriting without a cache" not grep -qE '^apt:|mirrors\(\)' "$ud"
    extract_firstboot "$T/fb-default.sh"
    check "first-boot script is valid bash"  bash -n "$T/fb-default.sh"
    check "…disables cloud-init by default"  grep -q 'touch /etc/cloud/cloud-init.disabled' "$T/fb-default.sh"
    check "…records failures and a success marker" grep -q 'pve-prov.ok' "$T/fb-default.sh"
    # credentials: sysadmin's hash verifies against the chosen password; root's differs
    check "sysadmin hash matches the chosen password" python3 - "$ud" <<'PY'
import sys, yaml, subprocess
d = yaml.safe_load(open(sys.argv[1]))
u = {x['name']: x for x in d['users'] if isinstance(x, dict)}
h = u['sysadmin']['hashed_passwd']
salt = h.split('$')[2]
calc = subprocess.run(['openssl', 'passwd', '-6', '-salt', salt, '-stdin'], input='hunter22\n', capture_output=True, text=True).stdout.strip()
assert calc == h, (calc, h)
assert u['root']['hashed_passwd'] != h
PY
    check "plaintext password not in user-data" not grep -q 'hunter22' "$ud"
else
    fail "user-data snippet was not captured"
fi

echo "== VM resources are passed through (non-default values)"
run_prov "${VM_ARGS[@]}" --cores 2 --ram 3 --disk 20
check "cores"                                   log_has 'qm create 930 .*--cores 2 '
check "memory = 3 GB in MiB (3072, not 3000)"   log_has 'qm create 930 .*--memory 3072 '
check "bridge"                                  log_has 'qm create 930 .*--net0 virtio,bridge=lo'
check "guest agent enabled (IP discovery needs it)" log_has 'qm create 930 .*--agent 1'
check "UEFI + q35"                              log_has 'qm create 930 .*--bios ovmf .*--machine q35'
check "disk resized to 20G"                     log_has 'qm disk resize 930 scsi0 20G'

echo "== Sysadmin password edge cases"
run_prov "${VM_ARGS[@]/$T\/pw/$T/pw-dash}"; rc=$?
check "a password starting with '-' works"      test "$rc" -eq 0
check "…and its hash is correct"                python3 - "$ud" <<'PY'
import sys, yaml, subprocess
d = yaml.safe_load(open(sys.argv[1]))
u = {x['name']: x for x in d['users'] if isinstance(x, dict)}
h = u['sysadmin']['hashed_passwd']
calc = subprocess.run(['openssl', 'passwd', '-6', '-salt', h.split('$')[2], '-stdin'], input='-hunter22\n', capture_output=True, text=True).stdout.strip()
assert calc == h
PY
echo "abc" > "$T/pw-short"
run_prov "${VM_ARGS[@]/$T\/pw/$T/pw-short}"; rc=$?
check "a password under 5 chars is rejected"    bash -c "test $rc -ne 0 && grep -q 'at least 5' '$T/out'"
run_prov --yes --type vm --os debian --id 930 --hostname t.lan --bridge lo --storage local-zfs; rc=$?
check "no password given with --yes: generated" test "$rc" -eq 0
check "…shown once in the summary"              out_has 'sysadmin PW:'
check "…and stored in the Proxmox notes"        grep -q 'description' "$T/state/desc-930"

echo "== Notes are written in a UTF-8 locale whatever the caller's locale is"
# Under C/POSIX Proxmox stores the emoji in the notes as garbage ("������")
LC_ALL=C run_prov "${VM_ARGS[@]}"
check "VM notes: written with LC_ALL=C.UTF-8 even when the caller has LC_ALL=C" test "$(cat "$T/state/desc-locale-930" 2>/dev/null)" = "C.UTF-8"
env -u LANG -u LC_ALL run_prov "${VM_ARGS[@]}"
check "VM notes: …and when the caller has no locale at all"   test "$(cat "$T/state/desc-locale-930" 2>/dev/null)" = "C.UTF-8"
LC_ALL=POSIX run_prov "${CT_ARGS[@]}"
check "CT notes: written with LC_ALL=C.UTF-8 even when the caller has LC_ALL=POSIX" test "$(cat "$T/state/desc-locale-931" 2>/dev/null)" = "C.UTF-8"
DESC_FAIL=1 run_prov "${VM_ARGS[@]}"
check "a refused notes update is reported, not hidden"          out_has 'Proxmox refused the notes|Could not write the Proxmox notes'

echo "== Environment is not trusted for internal state"
PROV_SSH_KEYS="ssh-ed25519 AAAAevilevilevil evil" run_prov "${VM_ARGS[@]}"
check "PROV_SSH_KEYS from the environment is ignored" not grep -q evil "$ud"
PROV_SYSADMIN_PW_GENERATED=y run_prov "${VM_ARGS[@]}"
check "PROV_SYSADMIN_PW_GENERATED from the environment is ignored" not out_has 'sysadmin PW:'
rm -f "$T/fb-keep.sh"
PROV_KEEP_CLOUD_INIT=yes run_prov "${VM_ARGS[@]}"; rc=$?
extract_firstboot "$T/fb-keep.sh"
check "PROV_KEEP_CLOUD_INIT=yes is accepted"    test "$rc" -eq 0
check "…and honoured (script generated, no disable step)" bash -c "test -s '$T/fb-keep.sh' && ! grep -q 'cloud-init.disabled' '$T/fb-keep.sh'"
PROV_KEEP_CLOUD_INIT=bogus run_prov "${VM_ARGS[@]}"; rc=$?
check "PROV_KEEP_CLOUD_INIT=bogus is rejected"  test "$rc" -eq 2

echo "== Hostnames that YAML would mangle"
for hn in no.lan null yes.lan 0123.lan; do
    run_prov "${VM_ARGS[@]/t.lan/$hn}"
    check "hostname '$hn' stays a string"       ud_assert "assert isinstance(d['hostname'], str) and isinstance(d['fqdn'], str)"
done

echo "== Package options"
run_prov "${VM_ARGS[@]}" --no-btop --no-git
check "--no-btop/--no-git drop the packages"    ud_assert "assert 'btop' not in d['packages'] and 'git' not in d['packages']"
run_prov "${VM_ARGS[@]}" --gh
extract_firstboot "$T/fb-gh.sh"
check "--gh adds the gh install step"           grep -q 'step gh gh_install' "$T/fb-gh.sh"
check "…which is valid bash"                    bash -n "$T/fb-gh.sh"

echo "== VM with apt cache + keep-cloud-init + explicit CPU type + GitHub keys"
run_prov "${VM_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142 --keep-cloud-init --cpu-type host --github-user tester; rc=$?
check "exit 0"                                  test "$rc" -eq 0
check "--cpu host honoured"                     log_has 'qm create 930 .*--cpu host'
check "apt-proxy-detect written, mode 0755"     ud_assert "
f = [x for x in d['write_files'] if x['path'] == '/usr/local/bin/apt-proxy-detect'][0]
assert f['permissions'] == '0755' and 'apt-cacher-ng.lan/3142' in f['content']"
check "https goes DIRECT (acng refuses CONNECT)" grep -q 'Acquire::https::Proxy "DIRECT"' "$ud"
check "user-data still valid YAML"              ud_assert "assert isinstance(d, dict)"
check "GitHub keys are under sysadmin, exact"   ud_assert "
u = [x for x in d['users'] if isinstance(x, dict) and x['name'] == 'sysadmin'][0]
assert u['ssh_authorized_keys'] == ['ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkeytestkeytestkeytestkeytestkeytestkey tester@test']"
check "Debian: cloud-init told to generate http mirrors" ud_assert "
assert d['apt']['primary'][0]['uri'].startswith('http://')
assert d['apt']['security'][0]['uri'].startswith('http://')"
extract_firstboot "$T/fb-cache.sh"
check "first-boot script rewrites any https mirror"  grep -q 'mirrors() {' "$T/fb-cache.sh"
check "…and is valid bash"                      bash -n "$T/fb-cache.sh"
run_prov "${VM_ARGS[@]}" --os ubuntu --apt-cache apt-cacher-ng.lan:3142
check "Ubuntu: no apt mirror override (sources already http)" not grep -q '^apt:' "$ud"
extract_firstboot "$T/fb-ubuntu.sh"
check "Ubuntu: first-boot rewrite still present" grep -q 'mirrors() {' "$T/fb-ubuntu.sh"
check "Ubuntu user-data valid YAML"             ud_assert "assert isinstance(d, dict)"

echo "== GitHub key import"
run_prov "${VM_ARGS[@]}" --github-user weird; rc=$?
check "a key comment with ': ' and ' #' stays one string" ud_assert "
u = [x for x in d['users'] if isinstance(x, dict) and x['name'] == 'sysadmin'][0]
k = u['ssh_authorized_keys']
assert len(k) == 1 and k[0].endswith('work: laptop # home'), k"
for who in nokeys garbage "bad name"; do
    run_prov "${VM_ARGS[@]}" --github-user "$who"; rc=$?
    check "requested key import that fails aborts ($who)" test "$rc" -ne 0
    check "…before any guest is created ($who)"   not log_has 'qm create'
done
check "…with a clear reason"                    out_has 'SSH key import from GitHub was requested but failed'

echo "== VM first boot: outcomes the host must report honestly"
# 1. cloud-init finished but a requested step failed
GUEST_OK=0 FAILED_NAMES="gh sshd" run_prov "${VM_ARGS[@]}"; rc=$?
check "failed first-boot step: exit 4"          test "$rc" -eq 4
check "…names the failed steps"                 out_has 'gh sshd'
check "…not a success banner"                   out_has 'WITH PROBLEMS'
check "…cicustom still detached (cloud-init is done)" log_has '^qm set 930 --delete cicustom'
check "…VM kept, not destroyed"                 bash -c "! grep -q 'qm destroy' '$T/log'"
check "…and still startable"                    second_start_ok 930
check "…and the notes carry the warning"        grep -q 'Some first-boot steps failed' "$T/state/desc-930"
# 2. cloud-init completion not confirmed
GUEST_FINISHED=0 run_prov "${VM_ARGS[@]}"; rc=$?
check "unconfirmed: exit 3"                     test "$rc" -eq 3
check "…cicustom NOT removed"                   not log_has '^qm set [0-9]+ --delete cicustom'
check "…snippet kept"                           test -n "$(ls "$T/snippets")"
check "…VM still startable (snippet + cicustom both kept)" second_start_ok 930
check "…banner says NOT CONFIRMED"              out_has 'NOT CONFIRMED'
check "…detach command printed"                 out_has 'qm set 930 --delete cicustom'
check "…and written into the notes"             grep -q 'was not confirmed' "$T/state/desc-930"
# 3. agent never reports an IP
NOIP=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "no IP from the guest agent: exit 3"      test "$rc" -eq 3
check "…cicustom NOT removed (nothing confirmed)" not log_has '^qm set [0-9]+ --delete cicustom'
check "…no 'ssh sysadmin@pending' suggestion"   not out_has 'ssh sysadmin@pending'
check "…still startable"                        second_start_ok 930
# 4. exitcode must be read from the JSON, not only from qm's own exit status
GUEST_FINISHED=0 GUEST_EXEC_RC0=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "exit status 0 but JSON exitcode 1 is not 'finished'" test "$rc" -eq 3
# 5. detaching cicustom fails: keep the snippet, do not destroy the VM
DELETE_FAIL=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "failed detach: exit 3"                   test "$rc" -eq 3
check "…snippet kept"                           test -n "$(ls "$T/snippets")"
check "…VM kept and startable"                  bash -c "! grep -q 'qm destroy' '$T/log'"
check "…second start works"                     second_start_ok 930
# 6. the notes cannot be written: the finished VM must survive
DESC_FAIL=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "notes failure does not fail provisioning" test "$rc" -eq 0
check "…the VM is not destroyed"                not log_has 'qm destroy'
check "…the user is told to record the passwords" out_has 'Record the passwords'

echo "== First-boot script, executed (against stub systemctl/sshd/apt/curl)"
run_fb() {   # run_fb <script> : runs it in a sandbox; leaves state in $T/fb
    local d="$T/fb"
    rm -rf "$d"; mkdir -p "$d/var/lib/cloud" "$d/etc/cloud" "$d/etc/apt/mirrors" "$d/etc/apt/keyrings" "$d/etc/apt/sources.list.d" "$d/run/sshd" "$d/bin"
    printf 'https://deb.debian.org/debian\n' > "$d/etc/apt/mirrors/debian.list"
    printf '#!/bin/bash\nexit 0\n' > "$d/bin/systemctl"
    printf '#!/bin/bash\nexit 0\n' > "$d/bin/apt-get"
    printf '#!/bin/bash\nexit 0\n' > "$d/bin/gh"
    # shellcheck disable=SC2016  # stub bodies: expansion must happen when the stub runs
    printf '#!/bin/bash\n[[ "${SSHD_BAD:-0}" == 1 ]] && exit 1\nif [[ "$1" == -T ]]; then echo "permitrootlogin no"; echo "passwordauthentication yes"; fi\nexit 0\n' > "$d/bin/sshd"
    # shellcheck disable=SC2016
    printf '#!/bin/bash\n[[ "${GH_FAIL:-0}" == 1 ]] && exit 22\nwhile (( $# )); do [[ "$1" == -o ]] && : > "$2"; shift; done\nexit 0\n' > "$d/bin/curl"
    chmod +x "$d/bin"/*
    sed -e "s#/var/lib/cloud#$d/var/lib/cloud#g" -e "s#/etc/cloud#$d/etc/cloud#g" \
        -e "s#/etc/apt#$d/etc/apt#g" -e "s#/run/sshd#$d/run/sshd#g" "$1" > "$d/script.sh"
    PATH="$d/bin:$PATH" bash "$d/script.sh"
}
run_prov "${VM_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142 --gh >/dev/null; extract_firstboot "$T/fb-all.sh"
run_fb "$T/fb-all.sh"; rc=$?
check "all steps succeed: exit 0"               test "$rc" -eq 0
check "…success marker written"                 test -f "$T/fb/var/lib/cloud/pve-prov.ok"
check "…failure list empty"                     test -z "$(tr -d ' \n' < "$T/fb/var/lib/cloud/pve-prov.failed")"
check "…cloud-init disabled"                    test -f "$T/fb/etc/cloud/cloud-init.disabled"
check "…the script removed itself"              test ! -e "$T/fb/script.sh"
check "…https mirror really rewritten to http"  grep -qx 'http://deb.debian.org/debian' "$T/fb/etc/apt/mirrors/debian.list"
SSHD_BAD=1 run_fb "$T/fb-all.sh"; rc=$?
check "sshd step failing: still exits 0 (cloud-init carries on)" test "$rc" -eq 0
check "…no success marker"                      test ! -e "$T/fb/var/lib/cloud/pve-prov.ok"
check "…failure recorded by name"               grep -qw sshd "$T/fb/var/lib/cloud/pve-prov.failed"
check "…other steps still ran (cloud-init disabled)" test -f "$T/fb/etc/cloud/cloud-init.disabled"
GH_FAIL=1 run_fb "$T/fb-all.sh"
check "gh install failing is recorded by name"  grep -qw gh "$T/fb/var/lib/cloud/pve-prov.failed"
check "…and only gh"                            bash -c "test \"\$(cat '$T/fb/var/lib/cloud/pve-prov.failed' | tr -d ' \n')\" = gh"
run_fb "$T/fb-keep.sh"
check "with --keep-cloud-init the marker is not created" test ! -e "$T/fb/etc/cloud/cloud-init.disabled"

echo "== ID safety"
echo 930 > "$T/used_ids"
run_prov "${VM_ARGS[@]}"; rc=$?
check "existing ID refused"                     test "$rc" -ne 0
check "reason shown"                            out_has 'already used|not available'
check "nothing created"                         not log_has 'qm create'
check "nothing destroyed"                       not log_has 'qm destroy|pct destroy'
: > "$T/used_ids"
mkdir -p "$T/nodes/othernode/qemu-server"; : > "$T/nodes/othernode/qemu-server/930.conf"
run_prov "${VM_ARGS[@]}"; rc=$?
check "ID used on another cluster node refused (config file check)" bash -c "test $rc -ne 0 && grep -q 'already used by a VM or container' '$T/out'"
rm -rf "$T/nodes"/*
echo "930 local-zfs vm-930-disk-0" > "$T/orphans"
run_prov "${VM_ARGS[@]}"; rc=$?
check "ID with leftover volume refused"         test "$rc" -ne 0
check "leftover volume named in error"          out_has 'vm-930-disk-0'
check "nothing created"                         not log_has 'qm create'
: > "$T/orphans"
for d in 01 02 03 04 05 06; do echo "930 local-zfs backup/vm/930/2026-01-${d}T00:00:00Z backup" >> "$T/orphans"; done
run_prov "${VM_ARGS[@]}"; rc=$?
check "many leftover backups refused"           test "$rc" -ne 0
check "count is reported"                       out_has '6 leftover'
check "list truncated to a few examples"        out_has '\.\.\. and 3 more'
check "not every volume is printed"             not out_has '2026-01-06'
: > "$T/orphans"
SNIPPETS_ON=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "snippet files on 'local' do not make every ID look taken" test "$rc" -eq 0
SNIPPETS_ON=1 PVESM_PBS=1 run_prov "${VM_ARGS[@]}"
check "…with a PBS storage present too"         log_has 'qm create 930'
echo "== No usable storage: stop, do not carry on with an empty name"
VM_ARGS_NOSTORE=(--yes --type vm --os debian --id 930 --hostname t.lan --bridge lo --sysadmin-password-file "$T/pw")
PVESM_NONE=1 run_prov "${VM_ARGS_NOSTORE[@]}"; rc=$?
check "no active storage: aborts"               test "$rc" -ne 0
check "…says so"                                out_has 'No active storage'
check "…and creates nothing (not a VM on storage '')" not log_has 'qm create'
echo "== Storages that cannot be checked fail closed"
PVESM_PBS=1 PVESM_FAIL_STORAGE=pbs-store run_prov "${VM_ARGS[@]}"; rc=$?
check "unlistable storage: ID refused"          test "$rc" -ne 0
check "…the storage is named"                   out_has 'pbs-store'
check "…and the override is explained"          out_has -- '--ignore-storage'
check "…nothing created"                        not log_has 'qm create'
PVESM_PBS=1 PVESM_FAIL_STORAGE=pbs-store run_prov "${VM_ARGS[@]}" --ignore-storage pbs-store; rc=$?
check "--ignore-storage skips it deliberately"  test "$rc" -eq 0
check "…and PBS is then never listed"           not log_has 'pvesm list pbs-store'
PVESM_PBS=1 PVESM_INACTIVE=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "an inactive storage is warned about up front" out_has 'Not checked for ID conflicts.*ghost-pbs'
check "…and does not block"                     test "$rc" -eq 0
echo "== Last-moment ID re-check (race)"
RACE_ID=930 run_prov "${VM_ARGS[@]}"; rc=$?
check "ID taken between check and create: aborts" test "$rc" -ne 0
check "…no create"                              not log_has 'qm create'
check "…and nothing destroyed"                  not log_has 'qm destroy'
echo "== Default ID steps past IDs with leftovers"
echo "900 local-zfs backup/vm/900/x backup" > "$T/orphans"
run_prov --yes --type vm --os debian --hostname t.lan --bridge lo --storage local-zfs --sysadmin-password-file "$T/pw"; rc=$?
check "next free ID has a backup: picks the next one" log_has 'qm create 901 '
check "…and says so"                            out_has 'ID 900 is not usable'
: > "$T/orphans"

echo "== Cleanup: only ever destroys what it created"
FAIL_AT=scsi0 run_prov "${VM_ARGS[@]}"; rc=$?
check "failure propagates"                      test "$rc" -ne 0
check "tagged VM destroyed"                     log_has 'qm destroy 930'
check "…really gone"                            bash -c "! test -f '$T/state/guest-930'"
check "…reported as cleaned up"                 out_has 'Cleaned up partial VM 930'
FAIL_AT=scsi0 NOTAG=1 run_prov "${VM_ARGS[@]}"
check "VM with no tags NOT destroyed"           not log_has 'qm destroy'
check "…and the reason is given"                out_has "missing the 'pve-prov' tag"
FAIL_AT=scsi0 TAGS=prod run_prov "${VM_ARGS[@]}"
check "VM tagged only 'prod' NOT destroyed"     not log_has 'qm destroy'
FAIL_AT=scsi0 TAGS=not-pve-prov run_prov "${VM_ARGS[@]}"
check "tag 'not-pve-prov' is not our tag"       not log_has 'qm destroy'
FAIL_AT=scsi0 TAGS="prod;pve-prov" run_prov "${VM_ARGS[@]}"
check "our tag among several is recognised"     log_has 'qm destroy 930'
FAIL_AT=scsi0 QM_CONFIG_FAIL=1 run_prov "${VM_ARGS[@]}"
check "unreadable config: not destroyed"        not log_has 'qm destroy'
check "…and says it could not read it (not 'missing tag')" out_has 'Cannot read the config'
FAIL_AT=create run_prov "${VM_ARGS[@]}"
check "failed 'qm create' never triggers destroy" not log_has 'qm destroy'
echo "-- failure AFTER the snippet and cicustom exist (the original bug's territory)"
FAIL_AT=start run_prov "${VM_ARGS[@]}"
check "tagged: VM destroyed"                    log_has 'qm destroy 930'
check "…and its snippet removed with it"        test -z "$(ls "$T/snippets")"
FAIL_AT=start NOTAG=1 run_prov "${VM_ARGS[@]}"
check "untagged VM survives"                    guest_exists 930
check "…so its snippet is KEPT"                 test -n "$(ls "$T/snippets")"
check "…and the surviving VM can still start"   second_start_ok 930
check "…with a message about the kept snippet"  out_has 'Kept .*snippet|Kept .*userdata'
FAIL_AT=start DESTROY_FAIL=1 run_prov "${VM_ARGS[@]}"
check "destroy that fails is reported, not 'cleaned up'" out_has 'Could NOT destroy'
check "…not claimed as cleaned up"              not out_has 'Cleaned up partial'
check "…snippet kept because the VM survives"   test -n "$(ls "$T/snippets")"
check "…and the VM can still start"             second_start_ok 930
echo "-- the terminal is gone (SSH dropped, SIGPIPE): cleanup must still run"
STUB_DELAY=1 FAIL_AT=scsi0 run_prov_deadterm "${VM_ARGS[@]}"
check "VM still destroyed when the terminal/pipe is gone" log_has 'qm destroy 930'
KILL_PARENT_PIPE=1 run_prov "${VM_ARGS[@]}"
check "SIGPIPE delivered mid-run still runs the cleanup" log_has 'qm destroy 930'
check "…and the VM is gone"                     bash -c "! test -f '$T/state/guest-930'"
echo "-- LXC"
FAIL_AT=pct_start run_prov "${CT_ARGS[@]}"
check "tagged CT destroyed"                     log_has 'pct destroy 931'
FAIL_AT=pct_start NOTAG=1 run_prov "${CT_ARGS[@]}"
check "untagged CT NOT destroyed"               not log_has 'pct destroy'
FAIL_AT=pct_start TAGS=prod run_prov "${CT_ARGS[@]}"
check "CT tagged only 'prod' NOT destroyed"     not log_has 'pct destroy'
check "LXC cleanup reads pct config, not qm"    not log_has 'qm config'
PCT_EXEC_FAIL="apt-get update" run_prov "${CT_ARGS[@]}"; rc=$?
check "failing guest step aborts"               test "$rc" -ne 0
check "…names the step and keeps the log"       bash -c "grep -q 'apt-get update failed' '$T/out' && grep -q 'Provisioning log kept' '$T/out'"
check "…and the half-built CT is destroyed"     log_has 'pct destroy 931'

echo "== Image cache"
run_prov "${VM_ARGS[@]}"
printf 'TRUNCATED' > "$T/cache/debian-13-genericcloud-amd64.qcow2"
run_prov "${VM_ARGS[@]}"; rc=$?
check "corrupt cached image is refreshed"       out_has 'outdated or incomplete'
check "…and the run succeeds"                   test "$rc" -eq 0
: > "$T/curl.log"
reset_state_keep_cache() { : > "$T/log"; : > "$T/curl.log"; rm -rf "$T/state"/* "$T/snippets"/*; }
reset_state_keep_cache
run_env timeout 120 bash "$PROV" "${VM_ARGS[@]}" > "$T/out" 2>&1
check "a good cached image is reused"           out_has 'cached and verified'
check "…without downloading it again"           bash -c "! grep -q 'genericcloud-amd64.qcow2$' '$T/curl.log'"
rm -f "$T/cache"/*
CORRUPT_DOWNLOAD=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "checksum mismatch aborts"                test "$rc" -ne 0
check "…says so"                                out_has 'Checksum mismatch'
check "…leaves no image behind"                 test -z "$(ls "$T/cache")"
check "…and creates no VM"                      not log_has 'qm create'

echo "== Input validation (non-interactive: exits instead of looping)"
while IFS='|' read -r bad why; do
    # shellcheck disable=SC2086
    run_prov "${VM_ARGS[@]}" $bad; rc=$?
    check "rejects: $bad" bash -c "test $rc -ne 0 && grep -q '$why' '$T/out'"
done <<'LIST'
--cores abc|CPU cores must
--cores 0|CPU cores must
--ram 4.5|RAM must
--ram 999999|RAM must
--disk -3|Disk size must
--disk 99999999|Disk size must
--hostname bad_name!|Hostname must
--cpu-type pentium|Unknown CPU type
--bridge nope0|bridge not found
--apt-cache nohostport|host:port
--type bogus|Invalid type
LIST
for badid in 5 abc 099 1000000000; do
    run_prov "${VM_ARGS[@]/930/$badid}"; rc=$?
    check "rejects --id $badid"                 bash -c "test $rc -ne 0 && grep -q 'ID must be' '$T/out'"
done
run_prov "${VM_ARGS[@]}" --os plan9; rc=$?
check "rejects unknown OS"                      test "$rc" -ne 0
run_prov "${VM_ARGS[@]}" --storage nosuchstore; rc=$?
check "rejects unknown storage"                 test "$rc" -ne 0
echo "-- the apt cache value is pasted into a root script in the guest: no injection"
# shellcheck disable=SC2016  # the literal text '$(id)' is the injection attempt
for bad in 'a;id:80' '$(id):80' 'host:65536' 'host:0' 'host name:80' 'host:80;id'; do
    check "valid_apt_cache rejects: $bad"       bash -c "source '$PROV'; ! valid_apt_cache '$bad'"
done
check "valid_apt_cache accepts the default"     bash -c "source '$PROV'; valid_apt_cache apt-cacher-ng.lan:3142"

echo "== OS selection (live-resolved) and the images/templates actually requested"
for pair in "debian:Debian 13" "debian-oldstable:Debian 12" "ubuntu:Ubuntu 26.04" "noble:Ubuntu 24.04" "2:Debian 12" "ubuntu-26.04:Ubuntu 26.04"; do
    os="${pair%%:*}"; want="${pair#*:}"
    run_prov "${VM_ARGS[@]}" --os "$os"
    check "--os $os -> $want"                   out_has "OS: .*${want}"
done
rm -f "$T/cache"/*
run_prov "${VM_ARGS[@]}" --os debian
check "debian stable image URL"                 grep -qx 'https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2' "$T/curl.log"
check "debian checksum URL"                     grep -qx 'https://cloud.debian.org/images/cloud/trixie/latest/SHA512SUMS' "$T/curl.log"
rm -f "$T/cache"/*
run_prov "${VM_ARGS[@]}" --os noble
check "ubuntu 24.04 image URL"                  grep -qx 'https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img' "$T/curl.log"
check "ubuntu checksum URL"                     grep -qx 'https://cloud-images.ubuntu.com/noble/current/SHA256SUMS' "$T/curl.log"

echo "== LXC path"
run_prov "${CT_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142; rc=$?
check "exit 0"                                  test "$rc" -eq 0
check "tagged pve-prov"                         log_has 'pct create 931 .*--tags pve-prov'
check "unprivileged"                            log_has 'pct create 931 .*--unprivileged 1'
check "debian-13 template picked from pveam"    log_has 'pct create 931 local:vztmpl/debian-13-standard'
check "apt detect script pushed, mode 0755"     grep -q -- '--perms 0755' "$T/pushed/args_usr_local_bin_apt-proxy-detect"
check "apt conf pushed (https DIRECT)"          grep -q 'https::Proxy "DIRECT"' "$T/pushed/_etc_apt_apt.conf.d_01acng"
check "sshd drop-in pushed"                     grep -q 'PermitRootLogin no' "$T/pushed/_etc_ssh_sshd_config.d_00-pve-prov.conf"
check "https mirrors switched to http for the cache" log_has 'pct exec 931 .*find /etc/apt .*sed -i -E .*https://'
check "sshd config tested before restart"       log_has '^ +sshd -t$'
check "sshd settings verified in effect"        log_has 'sshd -T \| grep -qix "permitrootlogin no"'
check "no sed on sshd_config"                   not log_has "sed -i.*sshd_config"
check "sysadmin user created"                   log_has 'useradd -m -s /bin/bash -G sudo sysadmin'
check "…with the chosen password pushed"        grep -qx 'sysadmin:hunter22' "$T/pushed/_tmp_.pve-pw"
check "…and applied with chpasswd"              log_has 'chpasswd'
check "no destroy on success"                   not log_has 'pct destroy'
PCT_EXEC_FAIL="sshd -t" run_prov "${CT_ARGS[@]}"; rc=$?
check "an sshd that does not verify aborts the CT" bash -c "test $rc -ne 0 && grep -q 'SSH configuration failed' '$T/out'"
run_prov "${CT_ARGS[@]}" --os ubuntu
check "LXC ubuntu 26.04 template"               log_has 'pct create 931 local:vztmpl/ubuntu-26.04-standard'
DESC_FAIL=1 run_prov "${CT_ARGS[@]}"; rc=$?
check "LXC: notes failure does not destroy the finished CT" bash -c "test $rc -eq 0 && ! grep -q 'pct destroy' '$T/log'"
echo 931 > "$T/used_ids"
run_prov "${CT_ARGS[@]}"; rc=$?
check "LXC: existing ID refused"                test "$rc" -ne 0
check "LXC: nothing destroyed"                  not log_has 'pct destroy'
: > "$T/used_ids"

echo "== The apt https->http rewrite and the cache probe, executed"
aptroot="$T/aptroot"; rm -rf "$aptroot"; mkdir -p "$aptroot/mirrors" "$aptroot/sources.list.d"
printf 'https://deb.debian.org/debian\n'      > "$aptroot/mirrors/debian.list"
printf 'https://deb.debian.org/debian-security\n' > "$aptroot/mirrors/debian-security.list"
printf 'Types: deb\nURIs: https://deb.debian.org/debian\n' > "$aptroot/sources.list.d/debian.sources"
printf 'Types: deb\nURIs: https://security.ubuntu.com/ubuntu\n' > "$aptroot/sources.list.d/ubuntu.sources"
printf 'Types: deb\nURIs: http://au.archive.ubuntu.com/ubuntu\n' > "$aptroot/sources.list.d/ubuntu-au.sources"
printf 'deb [signed-by=/k] https://cli.github.com/packages stable main\n' > "$aptroot/sources.list.d/github-cli.list"
rewrite_cmd="$(bash -c "source '$PROV'; apt_https_to_http_cmd")"
bash -c "${rewrite_cmd//\/etc\/apt/$aptroot}"
check "debian mirror list rewritten"            grep -qx 'http://deb.debian.org/debian' "$aptroot/mirrors/debian.list"
check "debian-security mirror rewritten"        grep -qx 'http://deb.debian.org/debian-security' "$aptroot/mirrors/debian-security.list"
check "deb822 debian.sources rewritten"         grep -q 'URIs: http://deb.debian.org/debian' "$aptroot/sources.list.d/debian.sources"
check "ubuntu security rewritten"               grep -q 'URIs: http://security.ubuntu.com' "$aptroot/sources.list.d/ubuntu.sources"
check "an already-http regional mirror untouched" grep -q 'URIs: http://au.archive.ubuntu.com' "$aptroot/sources.list.d/ubuntu-au.sources"
check "other vendors' repos (gh) left on https"  grep -q 'https://cli.github.com' "$aptroot/sources.list.d/github-cli.list"
cp -r "$aptroot" "$aptroot.again"; bash -c "${rewrite_cmd//\/etc\/apt/$aptroot.again}"
check "idempotent"                              diff -r "$aptroot" "$aptroot.again"
bash -c "source '$PROV'; apt_proxy_detect_script 127.0.0.1:1" > "$T/probe-closed.sh"
check "cache probe falls back to DIRECT when nothing listens" test "$(bash "$T/probe-closed.sh")" = DIRECT
python3 - "$T/port" <<'PY' &
import socket, sys, time
s = socket.socket(); s.bind(('127.0.0.1', 0)); s.listen(5)
open(sys.argv[1], 'w').write(str(s.getsockname()[1]))
time.sleep(8)
PY
for _ in $(seq 1 40); do [[ -s "$T/port" ]] && break; sleep 0.1; done
port="$(cat "$T/port")"
bash -c "source '$PROV'; apt_proxy_detect_script 127.0.0.1:$port" > "$T/probe-open.sh"
check "cache probe returns the cache when it answers" test "$(bash "$T/probe-open.sh")" = "http://127.0.0.1:$port"
kill %1 2>/dev/null || true

echo "== Interactive mode (pty): menus, re-prompt on a used ID, defaults"
if command -v script >/dev/null; then
    run_pty() {   # run_pty <answers-file> [env...]
        reset_state
        run_env timeout 60 script -qec "bash '$PROV'" /dev/null < "$1" > "$T/out" 2>&1
    }
    echo 930 > "$T/used_ids"
    # type=VM, OS=default, ID=930 (used -> re-asked) then 931, hostname, cores/cpu/ram/disk=defaults,
    # bridge, storage menu #2, btop/git/gh=defaults, apt cache=default, pw x2, github=n, proceed
    printf '%s\n' 2 "" 930 931 it.lan "" "" "" "" lo 2 "" "" "" "" hunter22 hunter22 n "" > "$T/answers"
    run_pty "$T/answers"; rc=$?
    check "interactive run exits 0"                  test "$rc" -eq 0
    check "used ID rejected, then re-asked"          out_has 'already used|not available'
    check "second ID accepted"                       log_has 'qm create 931 '
    check "default CPU type applied"                 log_has 'qm create 931 .*--cpu x86-64-v3'
    check "disk went to 2nd storage (local-zfs)"     log_has 'scsi0 local-zfs:0,import-from'
    check "password prompt used (no generated pw)"   not out_has 'sysadmin PW:'
    : > "$T/used_ids"
    # apt cache host resolves -> prompt defaults to yes, then accept the default host:port
    printf '%s\n' 2 "" 932 it.lan "" "" "" "" lo 1 "" "" "" "" "" hunter22 hunter22 n "" > "$T/answers"
    GETENT_OK=1 run_pty "$T/answers"; rc=$?
    check "apt-cache run exits 0"                    test "$rc" -eq 0
    check "apt cache offered as default-yes when it resolves" out_has 'Use an apt cache.*Y/n'
    check "default cache host:port used"             grep -q 'apt-cacher-ng.lan/3142' "$T/captured-userdata.yml"
    # same, but decline at the final confirmation: nothing must be created
    printf '%s\n' 2 "" 933 it.lan "" "" "" "" lo 1 "" "" "" "" hunter22 hunter22 n n > "$T/answers"
    run_pty "$T/answers"; rc=$?
    check "declining the confirmation exits 0"       test "$rc" -eq 0
    check "…and creates nothing"                     not log_has 'qm create|pct create'
    check "…and downloads no image"                  not grep -q 'qcow2$' "$T/curl.log"
else
    echo "  skip (no 'script' binary)"
fi

echo "== Offline fallback for release data"
out=$( PATH="$BIN:$PATH" CURL_OFFLINE=1 bash -c "source '$PROV'; resolve_os_catalog; echo \"\${OS_ORDER[*]}\"" 2>&1 )
check "falls back to built-in releases"         grep -q 'debian-13 debian-12 ubuntu-26.04 ubuntu-24.04' <<<"$out"
check "warns about it"                          grep -q 'fallback' <<<"$out"

echo
echo "passed: $PASS   failed: $FAIL"
if (( FAIL )); then
    echo "(last run output: $T/out — kept for inspection)"; trap - EXIT
    exit 1
fi
