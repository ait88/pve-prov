#!/usr/bin/env bash
# =============================================================================
# Smoke tests for prov.sh — no Proxmox host needed.
#
# Fake `qm`, `pct`, `pvesm`, `pvesh`, `pveam` and `curl` binaries are put first
# on PATH; they record every call, so we can assert on what prov.sh *would* do
# on a real host. Network access is faked too (canned release metadata and
# images), so the tests are hermetic.
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

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); echo "  ok   $*"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }

# --------------------------------------------------------------------------- stubs
BIN="$T/bin"
mkdir -p "$BIN" "$T/state" "$T/pushed" "$T/snippets" "$T/cache"
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
        echo "$4"; exit 0
    fi
    echo 900; exit 0
fi
exit 0
EOF

cat > "$BIN/pvesm" <<'EOF'
#!/bin/bash
echo "pvesm $*" >> "$T/log"
case "$1" in
    status)
        echo "Name       Type     Status     Total   Used  Available  %"
        echo "local      dir      active      1000    100        900  10%"
        echo "local-zfs  zfspool  active      1000    100        900  10%"
        ;;
    list)
        # pvesm list <storage> --vmid <id>
        echo "Volid Format Type Size VMID"
        awk -v s="$2" -v id="$4" '$1 == id && $2 == s {print $3 " raw images 1 " $1}' "$T/orphans"
        ;;
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

cat > "$BIN/qm" <<'EOF'
#!/bin/bash
echo "qm $*" >> "$T/log"
case "$1" in
    create)
        echo "$*" > "$T/state/vm$2.create"
        if [[ "${FAIL_AT:-}" == "create" ]]; then exit 1; fi ;;
    set)
        if [[ "${FAIL_AT:-}" == "scsi0" && "$*" == *"--scsi0"* ]]; then exit 1; fi
        if [[ "$*" == *"--delete cicustom"* ]]; then echo "$2" >> "$T/state/cicustom_deleted"; fi ;;
    start)
        cp "$PROV_SNIPPET_DIR"/*.yml "$T/captured-userdata.yml" 2>/dev/null || true ;;
    guest)
        case "$2" in
            cmd) echo '{"name":"ens18","ip-addresses":[{"ip-address":"10.0.0.77","ip-address-type":"ipv4"}]}' ;;
            exec)
                if [[ "${GUEST_FINISHED:-1}" == "1" ]]; then echo '{ "exitcode" : 0, "exited" : 1 }'
                else echo '{ "exitcode" : 1, "exited" : 1 }'; exit 1; fi ;;
        esac ;;
    config)
        if [[ "${NOTAG:-0}" != "1" ]]; then echo "tags: pve-prov"; fi
        echo "name: test" ;;
esac
exit 0
EOF

cat > "$BIN/pct" <<'EOF'
#!/bin/bash
echo "pct $*" >> "$T/log"
case "$1" in
    create) echo "$*" > "$T/state/ct$2.create" ;;
    exec)
        if [[ "$*" == *"hostname -I"* ]]; then echo "10.0.0.50 "; fi ;;
    push)
        # pct push <id> <src> <dest> [--perms m]
        cp "$3" "$T/pushed/$(echo "$4" | tr / _)" ;;
    config)
        if [[ "${NOTAG:-0}" != "1" ]]; then echo "tags: pve-prov"; fi ;;
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

run_prov() {
    # Runs prov.sh against the stubs; stdout+stderr -> $T/out; returns its exit code.
    : > "$T/log"; rm -rf "$T/state"/* "$T/pushed"/* "$T/snippets"/* "$T/captured-userdata.yml"
    PATH="$BIN:$PATH" PROV_CACHE_DIR="$T/cache" PROV_SNIPPET_DIR="$T/snippets" \
        PROV_POLL_SECS=1 PROV_AGENT_WAIT=3 PROV_CLOUDINIT_WAIT=2 \
        bash "$PROV" "$@" > "$T/out" 2>&1
}

log_has()   { grep -qE -- "$1" "$T/log"; }
out_has()   { grep -qE -- "$1" "$T/out"; }
check() {   # check "description" command...
    local desc="$1"; shift
    if "$@"; then pass "$desc"; else fail "$desc"; fi
}
not() { ! "$@"; }

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

echo "== VM happy path (debian, defaults)"
run_prov "${VM_ARGS[@]}"; rc=$?
check "exit 0"                                       test "$rc" -eq 0
check "CPU type defaults to x86-64-v3"               log_has 'qm create 930 .*--cpu x86-64-v3'
check "guest is tagged pve-prov"                     log_has 'qm create 930 .*--tags pve-prov'
check "debian stable resolved live (13.7 -> debian-13)" out_has 'Debian 13 \(trixie'
check "image verified against checksum"              out_has 'downloaded and verified'
check "cicustom removed after cloud-init finished"   log_has 'qm set 930 --delete cicustom'
check "snippet file removed with it"                 test -z "$(ls "$T/snippets")"
check "no destroy on success"                        not log_has 'qm destroy'
check "validated ID cluster-wide"                    log_has 'pvesh get /cluster/nextid --vmid 930'
if [[ -f "$T/captured-userdata.yml" ]]; then
    ud="$T/captured-userdata.yml"
    check "user-data is valid YAML"          python3 -c "import yaml,sys; yaml.safe_load(open('$ud'))"
    check "short hostname + fqdn"            grep -qE '^hostname: t$' "$ud"
    check "fqdn set"                         grep -qE '^fqdn: t\.lan$' "$ud"
    check "sshd drop-in (not sed)"           grep -q '00-pve-prov.conf' "$ud"
    check "guest agent in packages"          grep -q -- '- qemu-guest-agent' "$ud"
    check "cloud-init disabled after first boot" grep -q 'cloud-init.disabled' "$ud"
    check "no apt cache unless asked"        not grep -q 'apt-proxy-detect' "$ud"
    check "…and no mirror rewriting without a cache" not grep -qE '^apt:|sed -i -E' "$ud"
else
    fail "user-data snippet was not captured"
fi

echo "== VM with apt cache + keep-cloud-init + explicit CPU type"
run_prov "${VM_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142 --keep-cloud-init --cpu-type host --github-user tester; rc=$?
check "exit 0"                                  test "$rc" -eq 0
check "--cpu host honoured"                     log_has 'qm create 930 .*--cpu host'
ud="$T/captured-userdata.yml"
check "apt-proxy-detect written"                grep -q '/usr/local/bin/apt-proxy-detect' "$ud"
check "https goes DIRECT (acng refuses CONNECT)" grep -q 'Acquire::https::Proxy "DIRECT"' "$ud"
check "cache host:port in detect script"        grep -q 'apt-cacher-ng.lan/3142' "$ud"
check "user-data still valid YAML"              python3 -c "import yaml; yaml.safe_load(open('$ud'))"
check "cloud-init left enabled with --keep-cloud-init" not grep -q 'cloud-init.disabled' "$ud"
check "GitHub SSH keys included"                grep -q 'ssh-ed25519 AAAA' "$ud"
check "Debian: cloud-init told to generate http mirrors" python3 -c "
import yaml
d = yaml.safe_load(open('$ud'))
assert d['apt']['primary'][0]['uri'].startswith('http://'), d.get('apt')
assert d['apt']['security'][0]['uri'].startswith('http://'), d.get('apt')"
check "…plus a final runcmd rewrite as safety net"  python3 -c "
import yaml
d = yaml.safe_load(open('$ud'))
cmds = [c for c in d['runcmd'] if isinstance(c, str) and 'sed -i -E' in c and 'https://' in c]
assert cmds, d['runcmd']"
run_prov "${VM_ARGS[@]}" --os ubuntu --apt-cache apt-cacher-ng.lan:3142
ud="$T/captured-userdata.yml"
check "Ubuntu: no apt mirror override (sources already http)" not grep -q '^apt:' "$ud"
check "Ubuntu: runcmd rewrite still present"    grep -q 'sed -i -E' "$ud"
check "Ubuntu user-data valid YAML"             python3 -c "import yaml; yaml.safe_load(open('$ud'))"
run_prov "${VM_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142 --keep-cloud-init --cpu-type host --github-user tester
ud="$T/captured-userdata.yml"

echo "== VM: cloud-init completion NOT confirmed -> snippet and cicustom both kept"
GUEST_FINISHED=0 run_prov "${VM_ARGS[@]}"; rc=$?
check "exit 0"                                  test "$rc" -eq 0
check "cicustom NOT removed"                    not log_has 'delete cicustom'
check "snippet kept"                            test -n "$(ls "$T/snippets")"
check "tells the user how to detach"            out_has 'qm set 930 --delete cicustom'

echo "== ID safety"
echo 930 > "$T/used_ids"
run_prov "${VM_ARGS[@]}"; rc=$?
check "existing ID refused"                     test "$rc" -ne 0
check "reason shown"                            out_has 'already used|not available'
check "nothing created"                         not log_has 'qm create'
check "nothing destroyed"                       not log_has 'qm destroy|pct destroy'
: > "$T/used_ids"
echo "930 local-zfs vm-930-disk-0" > "$T/orphans"
run_prov "${VM_ARGS[@]}"; rc=$?
check "ID with leftover volume refused"         test "$rc" -ne 0
check "leftover volume named in error"          out_has 'vm-930-disk-0'
check "nothing created"                         not log_has 'qm create'
# many backups: the message must be summarised, not dump every volume
: > "$T/orphans"
for d in 01 02 03 04 05 06; do echo "930 local-zfs backup/vm/930/2026-01-${d}T00:00:00Z" >> "$T/orphans"; done
run_prov "${VM_ARGS[@]}"; rc=$?
check "many leftovers refused"                  test "$rc" -ne 0
check "count is reported"                       out_has '6 leftover'
check "list truncated to a few examples"        out_has '\.\.\. and 3 more'
check "not every volume is printed"             not out_has '2026-01-06'
: > "$T/orphans"

echo "== Cleanup trap only destroys guests it created"
FAIL_AT=scsi0 run_prov "${VM_ARGS[@]}"; rc=$?
check "failure propagates"                      test "$rc" -ne 0
check "tagged guest cleaned up"                 log_has 'qm destroy 930'
FAIL_AT=scsi0 NOTAG=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "untagged guest NOT destroyed"            not log_has 'qm destroy'
check "says why"                                out_has "NOT destroying"
FAIL_AT=create run_prov "${VM_ARGS[@]}"; rc=$?
check "failed 'qm create' never triggers destroy" not log_has 'qm destroy'

echo "== Image cache"
run_prov "${VM_ARGS[@]}"
printf 'TRUNCATED' > "$T/cache/debian-13-genericcloud-amd64.qcow2"
run_prov "${VM_ARGS[@]}" >/dev/null; rc=$?
check "corrupt cached image is refreshed"       out_has 'outdated or incomplete'
check "…and the run succeeds"                   test "$rc" -eq 0
rm -f "$T/cache"/*
CORRUPT_DOWNLOAD=1 run_prov "${VM_ARGS[@]}"; rc=$?
check "checksum mismatch aborts"                test "$rc" -ne 0
check "…and leaves no image behind"             test -z "$(ls "$T/cache")"
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
LIST
run_prov "${VM_ARGS[@]}" --os plan9; rc=$?
check "rejects unknown OS"                      test "$rc" -ne 0
run_prov "${VM_ARGS[@]}" --storage nosuchstore; rc=$?
check "rejects unknown storage"                 test "$rc" -ne 0

echo "== OS selection (live-resolved)"
for pair in "debian:Debian 13" "debian-oldstable:Debian 12" "ubuntu:Ubuntu 26.04" "noble:Ubuntu 24.04" "2:Debian 12" "ubuntu-26.04:Ubuntu 26.04"; do
    os="${pair%%:*}"; want="${pair#*:}"
    run_prov "${VM_ARGS[@]}" --os "$os"
    check "--os $os -> $want"                   out_has "OS: .*${want}"
done

echo "== LXC path"
run_prov "${CT_ARGS[@]}" --apt-cache apt-cacher-ng.lan:3142; rc=$?
check "exit 0"                                  test "$rc" -eq 0
check "tagged pve-prov"                         log_has 'pct create 931 .*--tags pve-prov'
check "debian-13 template picked from pveam"    log_has 'pct create 931 local:vztmpl/debian-13-standard'
check "apt detect script pushed"                test -f "$T/pushed/_usr_local_bin_apt-proxy-detect"
check "apt conf pushed (https DIRECT)"          grep -q 'https::Proxy "DIRECT"' "$T/pushed/_etc_apt_apt.conf.d_01acng"
check "sshd drop-in pushed"                     grep -q 'PermitRootLogin no' "$T/pushed/_etc_ssh_sshd_config.d_00-pve-prov.conf"
check "https mirrors switched to http for the cache" log_has 'pct exec 931 .*find /etc/apt .*sed -i -E .*https://'
check "no sed on sshd_config"                   not log_has "sed -i.*sshd_config"
check "no destroy on success"                   not log_has 'pct destroy'
run_prov "${CT_ARGS[@]}" --os ubuntu; rc=$?
check "LXC ubuntu 26.04 template"               log_has 'pct create 931 local:vztmpl/ubuntu-26.04-standard'
echo 931 > "$T/used_ids"
run_prov "${CT_ARGS[@]}"; rc=$?
check "LXC: existing ID refused"                test "$rc" -ne 0
check "LXC: nothing destroyed"                  not log_has 'pct destroy'
: > "$T/used_ids"

echo "== Interactive mode (pty): menus, re-prompt on a used ID, defaults"
if command -v script >/dev/null; then
    : > "$T/log"; rm -rf "$T/state"/* "$T/snippets"/* "$T/captured-userdata.yml"
    echo 930 > "$T/used_ids"
    # type=VM, OS=default, ID=930 (used -> re-asked) then 931, hostname, cores/cpu/ram/disk=defaults,
    # bridge, storage menu #2, btop/git/gh=defaults, apt cache=default, pw x2, github=n, proceed
    printf '%s\n' 2 "" 930 931 it.lan "" "" "" "" lo 2 "" "" "" "" hunter22 hunter22 n "" > "$T/answers"
    PATH="$BIN:$PATH" PROV_CACHE_DIR="$T/cache" PROV_SNIPPET_DIR="$T/snippets" \
        PROV_POLL_SECS=1 PROV_AGENT_WAIT=3 PROV_CLOUDINIT_WAIT=2 \
        timeout 60 script -qec "bash '$PROV'" /dev/null < "$T/answers" > "$T/out" 2>&1
    rc=$?
    check "interactive run exits 0"                  test "$rc" -eq 0
    check "used ID rejected, then re-asked"          out_has 'already used|not available'
    check "second ID accepted"                       log_has 'qm create 931 '
    check "default CPU type applied"                 log_has 'qm create 931 .*--cpu x86-64-v3'
    check "disk went to 2nd storage (local-zfs)"     log_has 'scsi0 local-zfs:0,import-from'
    check "password prompt used (no generated pw)"   not out_has 'sysadmin PW:'
    : > "$T/used_ids"
    # apt cache host resolves -> prompt defaults to yes, then accept the default host:port
    : > "$T/log"; rm -rf "$T/state"/* "$T/snippets"/* "$T/captured-userdata.yml"
    printf '%s\n' 2 "" 932 it.lan "" "" "" "" lo 1 "" "" "" "" "" hunter22 hunter22 n "" > "$T/answers"
    GETENT_OK=1 PATH="$BIN:$PATH" PROV_CACHE_DIR="$T/cache" PROV_SNIPPET_DIR="$T/snippets" \
        PROV_POLL_SECS=1 PROV_AGENT_WAIT=3 PROV_CLOUDINIT_WAIT=2 \
        timeout 60 script -qec "bash '$PROV'" /dev/null < "$T/answers" > "$T/out" 2>&1
    rc=$?
    check "apt-cache run exits 0"                    test "$rc" -eq 0
    check "apt cache offered as default-yes when it resolves" out_has 'Use an apt cache.*Y/n'
    check "default cache host:port used"             grep -q 'apt-cacher-ng.lan/3142' "$T/captured-userdata.yml"
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
