#!/usr/bin/env bash
# =============================================================================
# pve-provision.sh v1.3
# Self-contained Proxmox VE LXC/VM provisioner (Debian + Ubuntu)
#
# No external script sourcing. No telemetry. Audit once, run forever.
# Run-once tool: when it finishes, the guest is self-contained and this script
# is no longer involved. See CHANGELOG.md for release notes.
#
# Requirements: Run as root on a Proxmox VE host
# Tested on:    Proxmox VE 8.x / 9.x
# =============================================================================
set -euo pipefail
# Without this, a failing command inside $(...) does not abort the caller, so a
# helper that prints an error and exits would be silently ignored.
shopt -s inherit_errexit

# =============================================================================
# CONSTANTS & DEFAULTS
# =============================================================================
SCRIPT_VERSION="1.3"

DEFAULT_HOSTNAME="hostname.lan"
DEFAULT_CPU=4                    # cores
DEFAULT_CPU_TYPE="x86-64-v3"     # VM only
DEFAULT_RAM=4                    # GB
DEFAULT_DISK=50                  # GB
DEFAULT_BRIDGE="vmbr0"
DEFAULT_APT_CACHE="${PROV_DEFAULT_APT_CACHE:-apt-cacher-ng.lan:3142}"

BASE_PACKAGES="util-linux curl wget net-tools sudo openssh-server nano"
VM_EXTRA_PACKAGES="qemu-guest-agent"

# Guests created by this script carry this tag. The failure-cleanup trap will
# refuse to destroy a guest that doesn't have it.
GUEST_TAG="pve-prov"

# CPU models offered for VMs
CPU_TYPES=(x86-64-v2 x86-64-v2-AES x86-64-v3 x86-64-v4 host kvm64)

# APT options: non-interactive, keep existing configs on upgrade
APT_OPTS="-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

# Cloud image cache directory (override with PROV_CACHE_DIR)
CLOUD_IMG_DIR="${PROV_CACHE_DIR:-/var/lib/vz/template/cloud}"

# Cluster-wide guest configs (one directory per node). Overridable for testing.
PVE_NODES_DIR="${PROV_PVE_NODES_DIR:-/etc/pve/nodes}"

# Where cloud-init user-data snippets live (the "local" storage's snippets dir)
SNIPPET_DIR="${PROV_SNIPPET_DIR:-/var/lib/vz/snippets}"

# VM first-boot waits (seconds) and poll interval; overridable mainly for testing
AGENT_WAIT_MAX="${PROV_AGENT_WAIT:-420}"
CLOUDINIT_WAIT_MAX="${PROV_CLOUDINIT_WAIT:-600}"
POLL_SECS="${PROV_POLL_SECS:-5}"

# Provisioning log file (guest-side apt output). Kept on failure, removed on success.
PROVISION_LOG="/tmp/pve-provision-$$.log"

# Set by --yes: never prompt, take defaults for anything not supplied.
ASSUME_YES=0

# OS catalogue, filled in at run time by resolve_os_catalog()
declare -A OS_NAMES=() OS_FAMILY=() OS_CODENAME=() OS_VERSION=()
OS_ORDER=()

# =============================================================================
# COLOUR & OUTPUT HELPERS
# =============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

info()    { echo -e "  ${BLUE}ℹ${RESET}  $*"; }
ok()      { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn()    { echo -e "  ${YELLOW}⚠${RESET}  $*" >&2; }
err()     { echo -e "  ${RED}✖${RESET}  $*" >&2; }
header()  { echo -e "\n${BOLD}${BLUE}═══ $* ═══${RESET}\n"; }
divider() { echo -e "${DIM}$(printf '%.0s─' {1..60})${RESET}"; }

# Menu/explanatory text: only shown when we may actually prompt.
show() {
    if (( ! ASSUME_YES )); then echo -e "$@"; fi
}

usage() {
    cat <<EOF
pve-provision.sh v${SCRIPT_VERSION} — provision a Debian/Ubuntu LXC container or VM on Proxmox VE

Usage: $(basename "$0") [options]

With no options the script is fully interactive. Any value supplied as a flag
(or as the matching PROV_* environment variable) is not asked for again.
With --yes nothing is ever asked: unsupplied values take their defaults.

Guest:
  --type lxc|vm             guest type (default: lxc)
  --os ID                   debian-13, ubuntu-26.04, ... or: debian, debian-oldstable,
                            ubuntu, a release codename, or a menu number
  --id N                    guest ID (must be unused; default: next free)
  --hostname NAME           hostname or FQDN (default: ${DEFAULT_HOSTNAME})
  --cores N                 CPU cores (default: ${DEFAULT_CPU})
  --cpu-type TYPE           VM CPU model: ${CPU_TYPES[*]} (default: ${DEFAULT_CPU_TYPE})
  --ram GB                  memory in GB (default: ${DEFAULT_RAM})
  --disk GB                 disk size in GB (default: ${DEFAULT_DISK})
  --bridge NAME             network bridge (default: ${DEFAULT_BRIDGE})
  --storage NAME            storage for the disk/rootfs
  --template-storage NAME   storage for LXC templates

Software / access:
  --btop | --no-btop        install btop        (default: yes)
  --git  | --no-git         install git         (default: yes)
  --gh   | --no-gh          install GitHub CLI  (default: no)
  --apt-cache HOST:PORT     use an apt cache (apt-cacher-ng); --no-apt-cache to disable
  --github-user NAME        import SSH keys from github.com/NAME
  --sysadmin-password-file F  read the sysadmin password from F (or PROV_SYSADMIN_PW);
                            if neither is given with --yes, a random one is generated
                            and stored in the Proxmox notes
  --keep-cloud-init         VMs: leave cloud-init enabled after first boot
                            (default: disabled, so a later reboot can't re-run it)

Safety:
  --ignore-storage NAME     do not check this storage for leftover volumes/backups of the
                            chosen ID (repeatable). Only for storages you know are
                            irrelevant: if a storage can't be listed, the ID is refused.

Other:
  -y, --yes                 non-interactive, skip the confirmation
  --version                 print version
  -h, --help                this help

Exit codes:
  0  guest provisioned and verified
  1  error or refusal (nothing left behind: a half-built guest is removed)
  2  bad usage
  3  VM built, but cloud-init completion could not be confirmed: its snippet and
     cicustom were left in place; the command to detach them is printed
  4  VM built and cloud-init finished, but a first-boot step failed (named in the output)
EOF
}

# =============================================================================
# ARGUMENT PARSING
# =============================================================================
# User-facing PROV_* settings may be preset by flag or environment variable;
# empty means "ask (or default)".
PROV_VARS=(PROV_TYPE PROV_OS PROV_ID PROV_HOSTNAME PROV_CPU PROV_CPU_TYPE PROV_RAM PROV_DISK
    PROV_BRIDGE PROV_DISK_STORAGE PROV_TPL_STORAGE PROV_OPT_BTOP PROV_OPT_GIT PROV_OPT_GH
    PROV_SYSADMIN_PW PROV_GITHUB_USER PROV_APT_CACHE PROV_KEEP_CLOUD_INIT PROV_IGNORE_STORAGES)
for _v in "${PROV_VARS[@]}"; do
    printf -v "$_v" '%s' "${!_v:-}"
done
unset _v
# Internal state: always starts empty, never read from the environment (an
# imported PROV_SSH_KEYS would bypass key validation, for example).
PROV_SSH_KEYS="" PROV_ROOT_PW="" PROV_SYSADMIN_PW_GENERATED="" PROV_KEYS_FAILED=""
# Outcome of a VM first boot: ok | degraded | unconfirmed (drives banner + exit code)
PROV_STATUS="ok"
PROV_DETACH_CMD=""

parse_args() {
    need_arg() {
        if [[ $# -lt 2 || "$2" == --* ]]; then
            err "Option $1 requires a value"
            exit 2
        fi
    }
    while (( $# )); do
        case "$1" in
            -h|--help)          usage; exit 0 ;;
            --version)          echo "pve-provision.sh v${SCRIPT_VERSION}"; exit 0 ;;
            -y|--yes)           ASSUME_YES=1 ;;
            --type)             need_arg "$@"; PROV_TYPE="$2"; shift ;;
            --os)               need_arg "$@"; PROV_OS="$2"; shift ;;
            --id)               need_arg "$@"; PROV_ID="$2"; shift ;;
            --hostname)         need_arg "$@"; PROV_HOSTNAME="$2"; shift ;;
            --cores)            need_arg "$@"; PROV_CPU="$2"; shift ;;
            --cpu-type)         need_arg "$@"; PROV_CPU_TYPE="$2"; shift ;;
            --ram)              need_arg "$@"; PROV_RAM="$2"; shift ;;
            --disk)             need_arg "$@"; PROV_DISK="$2"; shift ;;
            --bridge)           need_arg "$@"; PROV_BRIDGE="$2"; shift ;;
            --storage)          need_arg "$@"; PROV_DISK_STORAGE="$2"; shift ;;
            --template-storage) need_arg "$@"; PROV_TPL_STORAGE="$2"; shift ;;
            --btop)             PROV_OPT_BTOP="y" ;;
            --no-btop)          PROV_OPT_BTOP="n" ;;
            --git)              PROV_OPT_GIT="y" ;;
            --no-git)           PROV_OPT_GIT="n" ;;
            --gh)               PROV_OPT_GH="y" ;;
            --no-gh)            PROV_OPT_GH="n" ;;
            --apt-cache)        need_arg "$@"; PROV_APT_CACHE="$2"; shift ;;
            --no-apt-cache)     PROV_APT_CACHE="none" ;;
            --github-user)      need_arg "$@"; PROV_GITHUB_USER="$2"; shift ;;
            --sysadmin-password-file)
                need_arg "$@"
                [[ -r "$2" ]] || { err "Cannot read password file: $2"; exit 2; }
                PROV_SYSADMIN_PW="$(head -n1 "$2")"
                shift ;;
            --keep-cloud-init)  PROV_KEEP_CLOUD_INIT="y" ;;
            --ignore-storage)   need_arg "$@"; PROV_IGNORE_STORAGES+=" $2"; shift ;;
            *)                  err "Unknown option: $1 (see --help)"; exit 2 ;;
        esac
        shift
    done

    # Normalise y/n style values from flags or the environment (1/yes/true -> y)
    case "${PROV_KEEP_CLOUD_INIT,,}" in
        y|yes|1|true)  PROV_KEEP_CLOUD_INIT="y" ;;
        ""|n|no|0|false) PROV_KEEP_CLOUD_INIT="n" ;;
        *) err "Invalid PROV_KEEP_CLOUD_INIT: ${PROV_KEEP_CLOUD_INIT} (use y or n)"; exit 2 ;;
    esac
    local s
    for s in $PROV_IGNORE_STORAGES; do
        [[ "$s" =~ ^[A-Za-z0-9._-]+$ ]] || { err "Invalid storage name for --ignore-storage: $s"; exit 2; }
    done
}

# =============================================================================
# PROMPT HELPERS
# =============================================================================
prompt() {
    # Usage: prompt "Label" "default" VARNAME
    # - VARNAME already set (flag/env)  -> keep it, don't ask
    # - --yes                           -> take the default, don't ask
    # - otherwise ask on /dev/tty (so prompts work inside $() substitution)
    local label="$1" default="$2" varname="$3"
    local input
    if [[ -n "${!varname:-}" ]]; then
        return 0
    fi
    if (( ASSUME_YES )); then
        printf -v "$varname" '%s' "$default"
        return 0
    fi
    echo -en "  ${BOLD}${label}${RESET}" >/dev/tty
    [[ -n "$default" ]] && echo -en " ${DIM}[${default}]${RESET}" >/dev/tty
    echo -en ": " >/dev/tty
    read -r input </dev/tty
    printf -v "$varname" '%s' "${input:-$default}"
}

# Validators set VALIDATION_MSG to explain a rejection.
VALIDATION_MSG=""

prompt_valid() {
    # Usage: prompt_valid VARNAME "Label" "default" validator_fn "fallback error message"
    # Interactive: re-asks until valid. Preset (flag/env) or --yes: exit on invalid.
    local varname="$1" label="$2" default="$3" validator="$4" errmsg="$5"
    local preset=0
    [[ -n "${!varname:-}" ]] && preset=1
    while true; do
        prompt "$label" "$default" "$varname"
        VALIDATION_MSG=""
        if "$validator" "${!varname}"; then
            return 0
        fi
        err "${VALIDATION_MSG:-$errmsg}"
        if (( preset || ASSUME_YES )); then
            exit 1
        fi
        printf -v "$varname" '%s' ""
    done
}

prompt_secret() {
    # Usage: prompt_secret "Label" VARNAME
    local label="$1" varname="$2"
    local pw1 pw2
    while true; do
        echo -en "  ${BOLD}${label}${RESET}: " >/dev/tty
        IFS= read -rs pw1 </dev/tty; echo >/dev/tty
        echo -en "  ${BOLD}Confirm${RESET}: " >/dev/tty
        IFS= read -rs pw2 </dev/tty; echo >/dev/tty
        if [[ "$pw1" == "$pw2" ]]; then
            if [[ ${#pw1} -lt 5 ]]; then
                warn "Password must be at least 5 characters. Try again."
                continue
            fi
            printf -v "$varname" '%s' "$pw1"
            return
        fi
        warn "Passwords don't match. Try again."
    done
}

prompt_yesno() {
    # Usage: prompt_yesno "Question" [default: y/n]   (returns 0 for yes)
    local question="$1" default="${2:-y}"
    local yn
    if [[ "$default" == "y" ]]; then
        echo -en "  ${BOLD}${question}${RESET} ${DIM}[Y/n]${RESET}: " >/dev/tty
    else
        echo -en "  ${BOLD}${question}${RESET} ${DIM}[y/N]${RESET}: " >/dev/tty
    fi
    read -r yn </dev/tty
    yn="${yn:-$default}"
    [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]]
}

ask_flag() {
    # Usage: ask_flag VARNAME "Question" default(y/n)
    # Sets VARNAME to y/n. Preset values are normalised; --yes takes the default.
    local varname="$1" question="$2" default="$3"
    if [[ -n "${!varname:-}" ]]; then
        case "${!varname,,}" in
            y|yes|1|true)  printf -v "$varname" '%s' "y" ;;
            n|no|0|false)  printf -v "$varname" '%s' "n" ;;
            *) err "Invalid value for ${varname}: ${!varname} (use y or n)"; exit 1 ;;
        esac
        return 0
    fi
    if (( ASSUME_YES )); then
        printf -v "$varname" '%s' "$default"
    elif prompt_yesno "$question" "$default"; then
        printf -v "$varname" '%s' "y"
    else
        printf -v "$varname" '%s' "n"
    fi
}

# =============================================================================
# CLEANUP TRAP
# =============================================================================
CLEANUP_CTID=""
CLEANUP_TYPE=""
CLEANUP_SNIPPET=""
CLEANUP_FILES=()

cleanup() {
    local exit_code=$?
    # A cleanup trap must run to the end whatever fails inside it. Under set -e a
    # failing message (dead terminal, closed stdout) would otherwise abort the trap
    # before the destroy.
    set +e
    # If the terminal or pipe we were writing to is gone, a message would raise SIGPIPE
    # and kill this trap before the destroy. Ignore it: writes then just fail quietly.
    trap '' PIPE
    if [[ $exit_code -ne 0 && -n "$CLEANUP_CTID" ]]; then
        local tool="pct"
        [[ "$CLEANUP_TYPE" == "vm" ]] && tool="qm"
        local conf cfg_rc gone=0
        conf=$("$tool" config "$CLEANUP_CTID" 2>&1)
        cfg_rc=$?
        echo
        warn "Script failed (exit $exit_code). Cleaning up..."
        # Only ever destroy a guest that we created (carries our tag, matched exactly).
        if (( cfg_rc != 0 )); then
            warn "Cannot read the config of ${CLEANUP_TYPE} ${CLEANUP_CTID} (${conf}); NOT destroying it."
        elif grep -qE "^tags:[[:space:]]*(.*[;, ])?${GUEST_TAG}([;, ].*)?$" <<<"$conf"; then
            "$tool" stop "$CLEANUP_CTID" >/dev/null 2>&1
            "$tool" destroy "$CLEANUP_CTID" --purge >/dev/null 2>&1
            # Judge the outcome by whether the guest is really gone, not by exit codes.
            if "$tool" config "$CLEANUP_CTID" >/dev/null 2>&1; then
                warn "Could NOT destroy ${CLEANUP_TYPE} ${CLEANUP_CTID}. Remove it by hand: ${tool} destroy ${CLEANUP_CTID} --purge"
            else
                gone=1
                ok "Cleaned up partial ${CLEANUP_TYPE^^} ${CLEANUP_CTID}"
            fi
        else
            warn "Guest ${CLEANUP_CTID} is missing the '${GUEST_TAG}' tag — NOT destroying it."
        fi
        # The snippet may only go if the guest that points at it (cicustom) is gone;
        # otherwise that guest could no longer start.
        if [[ -n "$CLEANUP_SNIPPET" ]]; then
            if (( gone )); then
                rm -f "$CLEANUP_SNIPPET"
            else
                warn "Kept ${CLEANUP_SNIPPET}: the surviving guest may still reference it (cicustom)."
            fi
        fi
    fi
    for f in "${CLEANUP_FILES[@]}"; do
        rm -f "$f" 2>/dev/null || true
    done
    # Keep the provisioning log when something failed so it can be read.
    if [[ $exit_code -eq 0 ]]; then
        rm -f "$PROVISION_LOG" 2>/dev/null || true
    elif [[ -s "$PROVISION_LOG" ]]; then
        warn "Provisioning log kept: ${PROVISION_LOG}"
    fi
}
trap cleanup EXIT
# A bash killed by SIGPIPE (the terminal or pipe we print to went away) dies at once
# WITHOUT running its EXIT trap, leaving a half-built guest behind. Turn it into a
# normal exit so cleanup always runs. (A handler, not 'ignore': the pipelines inside
# this script, e.g. `... | head -1`, must keep their usual behaviour.)
trap 'exit 141' PIPE

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
preflight() {
    header "Pre-flight Checks"

    # Root check
    if [[ "$(id -u)" -ne 0 ]]; then
        err "This script must be run as root on your Proxmox host."
        exit 1
    fi
    ok "Running as root"

    # Proxmox check
    if ! command -v pveversion &>/dev/null; then
        err "pveversion not found — is this a Proxmox VE host?"
        exit 1
    fi
    local pve_ver
    pve_ver=$(pveversion | awk -F'/' '{print $2}' | awk -F'-' '{print $1}')
    ok "Proxmox VE ${pve_ver} detected"

    # Architecture check
    if [[ "$(dpkg --print-architecture)" != "amd64" ]]; then
        err "Only amd64 architecture is supported."
        exit 1
    fi
    ok "Architecture: amd64"

    # Required tools
    for tool in curl openssl pvesh pvesm pct qm pveam timeout sha256sum sha512sum getent; do
        if ! command -v "$tool" &>/dev/null; then
            err "Required tool '${tool}' not found."
            exit 1
        fi
    done
    ok "All required tools available"

    # Storages that aren't active can't be searched for an ID's leftover volumes/backups
    local inactive
    inactive=$(pvesm status 2>/dev/null | awk 'NR>1 && $3!="active" {print $1}' | tr '\n' ' ') || inactive=""  # advisory only; find_id_leftovers fails closed if storage can't be listed
    if [[ -n "${inactive// /}" ]]; then
        warn "Not checked for ID conflicts (storage not active): ${inactive}"
    fi

    # Interactive mode needs a terminal
    if (( ! ASSUME_YES )) && ! { : </dev/tty; } 2>/dev/null; then
        err "No terminal available for prompts. Use --yes (and flags) to run non-interactively."
        exit 1
    fi
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

get_next_free_id() {
    pvesh get /cluster/nextid 2>/dev/null || {
        err "Could not ask Proxmox for the next free ID (cluster not quorate?). Pass --id."
        exit 1
    }
}

# Looks for volumes/backups belonging to <id> on every active storage (disks left
# behind by an earlier guest, backups on PBS/dir storage, ...). Prints one line per
# finding: "L <volid>" for a leftover, "E <storage>: <reason>" for a storage that
# could not be listed (so the caller can fail closed rather than assume it is empty).
#
# Only guest-owned content types count. For snippets/import files, `pvesm list
# --vmid` returns every file whatever the ID, which would make every ID look taken.
find_id_leftovers() {
    local id="$1" s out rc storages
    storages=$(pvesm status 2>&1) || { echo "E pvesm status: ${storages//$'\n'/ }"; return 0; }
    while IFS= read -r s; do
        [[ -n "$s" ]] || continue
        if [[ " $PROV_IGNORE_STORAGES " == *" $s "* ]]; then continue; fi
        rc=0
        out=$(timeout 60 pvesm list "$s" --vmid "$id" 2>&1) || rc=$?
        if (( rc != 0 )); then
            out="${out:-no output; exit ${rc}, timed out after 60s?}"
            echo "E ${s}: $(head -c 200 <<<"${out//$'\n'/ }")"
            continue
        fi
        awk 'NR>1 && ($3=="images" || $3=="rootdir" || $3=="backup") {print "L " $1}' <<<"$out"
    done < <(awk 'NR>1 && $3=="active" {print $1}' <<<"$storages")
    return 0
}

validate_id() {
    # Rejects any ID that is, or recently was, in use. Sets VALIDATION_MSG.
    local id="$1"
    if ! [[ "$id" =~ ^[1-9][0-9]*$ ]] || (( id < 100 || id > 999999999 )); then
        VALIDATION_MSG="ID must be a number between 100 and 999999999."
        return 1
    fi
    # Configs on any cluster node
    if compgen -G "${PVE_NODES_DIR}/*/qemu-server/${id}.conf" >/dev/null \
        || compgen -G "${PVE_NODES_DIR}/*/lxc/${id}.conf" >/dev/null; then
        VALIDATION_MSG="ID ${id} is already used by a VM or container in this cluster."
        return 1
    fi
    # Authoritative cluster-wide check
    if ! pvesh get /cluster/nextid --vmid "$id" >/dev/null 2>&1; then
        VALIDATION_MSG="Proxmox reports ID ${id} is not available (in use, or cluster not quorate)."
        return 1
    fi
    # Orphaned disks and backups
    local scan leftovers errors
    scan=$(find_id_leftovers "$id")
    leftovers=$(sed -n 's/^L //p' <<<"$scan")
    errors=$(sed -n 's/^E //p' <<<"$scan")
    if [[ -n "$leftovers" ]]; then
        local n shown
        n=$(grep -c . <<<"$leftovers")
        shown=$(head -3 <<<"$leftovers" | sed 's/^/        /')
        if (( n > 3 )); then shown+=$'\n'"        ... and $((n - 3)) more"; fi
        VALIDATION_MSG="ID ${id} has ${n} leftover volume(s) or backup(s); refusing to reuse it:
${shown}"
        return 1
    fi
    # A storage we could not read might hold backups for this ID (a Proxmox Backup
    # Server datastore that times out is exactly that case). Fail closed.
    if [[ -n "$errors" ]]; then
        # shellcheck disable=SC2001  # per-line indent of multi-line text
        VALIDATION_MSG="Cannot confirm ID ${id} is free: these storages could not be checked for leftover volumes/backups:
$(sed 's/^/        /' <<<"$errors")
        Fix the storage, or skip it with --ignore-storage NAME if it cannot hold this ID's data."
        return 2
    fi
    return 0
}

suggest_free_id() {
    # The lowest unused ID is often a deleted guest's that still has backups, so
    # step up from it to the first ID that passes every check.
    local id tries=0 rc
    id=$(get_next_free_id)
    while (( tries < 50 )); do
        rc=0
        validate_id "$id" || rc=$?
        if (( rc == 0 )); then echo "$id"; return 0; fi
        if (( rc == 2 )); then break; fi   # cannot tell; don't hammer the storages
        local why="${VALIDATION_MSG%%$'\n'*}"
        info "ID ${id} is not usable (${why%:}); trying the next one" >&2
        id=$((id + 1))
        tries=$((tries + 1))
    done
    echo "$id"
}

is_posint()      { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }
valid_cores()    { is_posint "$1" && (( $1 <= 512 )); }
valid_ram()      { is_posint "$1" && (( $1 <= 4096 )); }
valid_disk()     { is_posint "$1" && (( $1 <= 65536 )); }
valid_hostname() {
    [[ ${#1} -le 253 && "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}
valid_bridge() {
    [[ "$1" =~ ^[A-Za-z0-9_.-]+$ && -e "/sys/class/net/$1" ]]
}
valid_cpu_type() {
    local t
    for t in "${CPU_TYPES[@]}"; do
        [[ "$1" == "$t" ]] && return 0
    done
    VALIDATION_MSG="Unknown CPU type '$1'. Choose one of: ${CPU_TYPES[*]}"
    return 1
}
valid_apt_cache() {
    # host:port
    [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?:([0-9]{1,5})$ ]] && (( BASH_REMATCH[2] >= 1 && BASH_REMATCH[2] <= 65535 ))
}

# Warn (never fail) if this host's CPU lacks features of the requested level.
check_host_cpu_support() {
    local want="$1" need="" flags missing="" f
    case "$want" in
        x86-64-v2)     need="cx16 popcnt sse4_1 sse4_2 ssse3" ;;
        x86-64-v2-AES) need="cx16 popcnt sse4_1 sse4_2 ssse3 aes" ;;
        x86-64-v3)     need="avx avx2 bmi1 bmi2 fma f16c movbe abm xsave" ;;
        x86-64-v4)     need="avx avx2 bmi1 bmi2 fma f16c movbe abm xsave avx512f avx512bw avx512cd avx512dq avx512vl" ;;
        *)             return 0 ;;
    esac
    flags=" $(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null | cut -d: -f2 || true) "
    for f in $need; do
        [[ "$flags" == *" $f "* ]] || missing+=" $f"
    done
    if [[ -n "$missing" ]]; then
        warn "This host's CPU lacks:${missing} (needed by ${want}). The VM may fail to start here."
    fi
    return 0
}

generate_password() {
    openssl rand -base64 16 | tr -d '=/+' | head -c 20
}

hash_password() {
    # SHA-512 hash for cloud-init / chpasswd. Read from stdin: as an argument a password
    # starting with "-" is parsed as an option, and it would show up in `ps`.
    openssl passwd -6 -stdin <<<"$1"
}

detect_storage() {
    # Find active storage backends for a given content type.
    local content_type="$1"
    local storages
    storages=$(pvesm status -content "$content_type" 2>/dev/null \
        | awk 'NR>1 && $3=="active" {print $1}')

    if [[ -z "${storages// /}" ]]; then
        err "No active storage found for content type '${content_type}'."
        exit 1
    fi

    echo "$storages"
}

select_storage() {
    # Usage: select_storage content_type label [preset]
    local content_type="$1" label="$2" preset="${3:-}"
    local storages
    storages=$(detect_storage "$content_type")
    local count
    count=$(echo "$storages" | wc -l)

    if [[ -n "$preset" ]]; then
        if ! grep -qxF -- "$preset" <<<"$storages"; then
            err "Storage '${preset}' is not an active ${content_type} storage. Available: $(echo "$storages" | tr '\n' ' ')"
            exit 1
        fi
        echo "$preset"
        return
    fi

    if [[ "$count" -eq 1 ]]; then
        echo "$storages"
        return
    fi

    if (( ASSUME_YES )); then
        local first
        first=$(echo "$storages" | head -1)
        info "Using storage ${first} for ${label} (first of: $(echo "$storages" | tr '\n' ' '))" >&2
        echo "$first"
        return
    fi

    # Display output must go to /dev/tty since this function is called
    # inside $() command substitution — stdout is captured, not displayed.
    echo >/dev/tty
    echo -e "  ${BLUE}ℹ${RESET}  Multiple storage backends available for ${label}:" >/dev/tty
    local i=1
    while IFS= read -r s; do
        # pvesm status columns: Name  Type  Status  Total  Used  Available  %
        # Column 6 (Available) is reported in KiB (1024-byte blocks), NOT bytes.
        local avail_kib
        avail_kib=$(pvesm status -content "$content_type" \
            | awk -v st="$s" '$1==st {print $6}')
        local avail_human
        avail_human=$(awk -v k="${avail_kib:-0}" 'BEGIN {
            b = k * 1024
            split("B KiB MiB GiB TiB PiB", u, " ")
            n = 1
            while (b >= 1024 && n < 6) { b /= 1024; n++ }
            printf "%.1f %s", b, u[n]
        }' 2>/dev/null || echo "?")
        echo -e "    ${BOLD}${i})${RESET} ${s} ${DIM}(${avail_human} free)${RESET}" >/dev/tty
        ((i++))
    done <<< "$storages"

    local choice
    while true; do
        prompt "Select storage for ${label} (1-$((i-1)))" "1" choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice < i )); then
            break
        fi
        echo -e "  ${YELLOW}⚠${RESET}  Enter a number between 1 and $((i-1))." >/dev/tty
        choice=""
    done
    echo "$storages" | sed -n "${choice}p"
}

fetch_github_keys() {
    # Prints the user's well-formed public keys, one per line. Returns 1 (with a
    # warning saying why) if none could be obtained.
    local username="$1" keys="" rc=0
    if ! [[ "$username" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38})$ ]]; then
        warn "'${username}' is not a valid GitHub username"
        return 1
    fi
    keys=$(curl -fsSL --connect-timeout 10 --max-time 15 \
        "https://github.com/${username}.keys" 2>/dev/null) || rc=$?
    if (( rc != 0 )); then
        warn "Could not fetch github.com/${username}.keys (curl exit ${rc}; 22 = HTTP error such as unknown user or rate limit)"
        return 1
    fi
    # Keep only well-formed key lines: they go into a root-owned cloud-init file,
    # so anything else in the response must not get through.
    keys=$(grep -E '^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-[a-z0-9]+|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com) [A-Za-z0-9+/=]+( [^[:cntrl:]]*)?$' <<<"$keys") || true
    if [[ -z "$keys" ]]; then
        warn "github.com/${username}.keys contained no valid SSH public keys"
        return 1
    fi
    echo "$keys"
}

wait_for_network() {
    # Wait for an LXC container to have network connectivity
    local id="$1" max_wait="${2:-30}"
    local elapsed=0

    # stdout is captured via $(...) — keep status on stderr, IP on stdout.
    info "Waiting for guest networking..." >&2
    while (( elapsed < max_wait )); do
        local ip
        ip=$(pct exec "$id" -- hostname -I 2>/dev/null | awk '{print $1}') || true
        if [[ -n "$ip" && "$ip" != "127.0.0.1" ]]; then
            ok "Guest network ready: ${ip}" >&2
            echo "$ip"
            return 0
        fi
        sleep 2
        (( elapsed += 2 ))
    done
    warn "Timed out waiting for network (${max_wait}s)"
    echo "pending"
}

# Run a command inside an LXC container with strict error handling.
# Logs output to PROVISION_LOG. On failure, shows the tail and exits.
lxc_exec() {
    local id="$1"
    shift
    local desc="$1"
    shift

    if ! pct exec "$id" -- bash -c "set -euo pipefail; $*" >> "$PROVISION_LOG" 2>&1; then
        err "${desc} failed. Last 15 lines of log:"
        echo "--- log tail ---"
        tail -15 "$PROVISION_LOG" 2>/dev/null || true
        echo "--- end ---"
        err "Full log: ${PROVISION_LOG}"
        exit 1
    fi
}

# Single source of truth for what gets installed in the guest.
# "install" excludes gh (separate apt repo); "display" includes it.
guest_packages() {
    local mode="${1:-install}" pkgs="$BASE_PACKAGES"
    [[ "$PROV_TYPE" == "vm" ]] && pkgs+=" ${VM_EXTRA_PACKAGES}"
    [[ "$PROV_OPT_BTOP" == "y" ]] && pkgs+=" btop"
    [[ "$PROV_OPT_GIT" == "y" ]] && pkgs+=" git"
    [[ "$mode" == "display" && "$PROV_OPT_GH" == "y" ]] && pkgs+=" gh"
    echo "$pkgs"
}

# Content of the sshd drop-in. Drop-ins in sshd_config.d are read before the
# main file's own settings and sshd keeps the FIRST value it sees, so ours wins
# over cloud-init's 50-cloud-init.conf (editing sshd_config with sed does not).
sshd_dropin_content() {
    cat <<'EOF'
PermitRootLogin no
PasswordAuthentication yes
EOF
}

# apt Proxy-Auto-Detect helper: use the cache if it answers within 1s, else DIRECT,
# so a dead cache never breaks apt / unattended-upgrades.
apt_proxy_detect_script() {
    local hostport="$1"
    cat <<EOF
#!/bin/bash
# apt Proxy-Auto-Detect: print the cache if its port answers within 1s, else DIRECT.
timeout 1 bash -c '</dev/tcp/${hostport%:*}/${hostport#*:}' 2>/dev/null && echo "http://${hostport}" || echo DIRECT
EOF
}

# HTTPS repos go direct: apt-cacher-ng refuses CONNECT tunnels (403 CONNECT denied).
apt_proxy_conf() {
    cat <<'EOF'
Acquire::http::Proxy-Auto-Detect "/usr/local/bin/apt-proxy-detect";
Acquire::https::Proxy "DIRECT";
EOF
}

# Some images ship https mirrors (e.g. the Debian 13 cloud image's
# /etc/apt/mirrors/*.list), and https goes DIRECT (see above), so the cache would
# never be used. With a cache enabled, point the distro mirrors at plain http;
# apt still verifies package signatures. Idempotent; leaves other repos alone.
apt_https_to_http_cmd() {
    cat <<'EOF'
find /etc/apt -maxdepth 2 -type f \( -name '*.list' -o -name '*.sources' \) -exec sed -i -E 's#https://(deb\.debian\.org|security\.debian\.org|([a-z]{2}\.)?archive\.ubuntu\.com|security\.ubuntu\.com)#http://\1#g' {} +
EOF
}

# =============================================================================
# OS CATALOGUE (resolved live; Debian + Ubuntu only)
# =============================================================================
add_os() {
    # Usage: add_os id label family codename version
    OS_ORDER+=("$1")
    OS_NAMES["$1"]="$2"
    OS_FAMILY["$1"]="$3"
    OS_CODENAME["$1"]="$4"
    OS_VERSION["$1"]="$5"
}

resolve_os_catalog() {
    # Debian: stable + oldstable straight from the Release files.
    # Ubuntu: the two newest supported LTS releases from Canonical's metadata.
    # If a source can't be reached we fall back to the last known releases.
    local suite rel code ver fb_code fb_ver used_fallback=0
    for suite in stable oldstable; do
        if [[ "$suite" == "stable" ]]; then fb_code="trixie"; fb_ver="13"; else fb_code="bookworm"; fb_ver="12"; fi
        rel=$(curl -fsSL --connect-timeout 10 --max-time 20 \
            "https://deb.debian.org/debian/dists/${suite}/Release" 2>/dev/null) || rel=""
        code=$(awk -F': ' '$1=="Codename" {print $2; exit}' <<<"$rel")
        ver=$(awk -F': ' '$1=="Version" {print $2; exit}' <<<"$rel")
        if [[ -z "$code" || ! "$ver" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
            code="$fb_code"; ver="$fb_ver"; used_fallback=1
        fi
        add_os "debian-${ver%%.*}" "Debian ${ver%%.*} (${code}, ${suite} ${ver})" debian "$code" "$ver"
    done

    local meta lts
    meta=$(curl -fsSL --connect-timeout 10 --max-time 20 \
        "https://changelogs.ubuntu.com/meta-release-lts" 2>/dev/null) || meta=""
    # Supported LTS entries, newest first: "codename version"
    lts=$(awk 'BEGIN {RS=""; FS="\n"}
        {d=""; v=""; s="";
         for (i = 1; i <= NF; i++) {
             if ($i ~ /^Dist: /)      d = substr($i, 7)
             else if ($i ~ /^Version: /)   v = substr($i, 10)
             else if ($i ~ /^Supported: /) s = substr($i, 12)
         }
         if (s == 1 && d != "" && v != "") print d, v}' <<<"$meta" | tail -2 | tac) || lts=""
    if [[ -z "$lts" ]]; then
        lts=$'resolute 26.04.1 LTS\nnoble 24.04.5 LTS'
        used_fallback=1
    fi
    local dist vfull vshort
    while read -r dist vfull _; do
        vshort=$(awk -F. '{print $1 "." $2}' <<<"$vfull")
        add_os "ubuntu-${vshort}" "Ubuntu ${vshort} LTS (${dist})" ubuntu "$dist" "$vshort"
    done <<<"$lts"

    if (( used_fallback )); then
        warn "Could not read live release data; using built-in fallback releases."
    fi
}

os_nth_of_family() {
    # Usage: os_nth_of_family family n   -> prints the n-th (1-based) matching id
    local family="$1" n="$2" id count=0
    for id in "${OS_ORDER[@]}"; do
        if [[ "${OS_FAMILY[$id]}" == "$family" ]]; then
            count=$((count + 1))
            if (( count == n )); then echo "$id"; return 0; fi
        fi
    done
    return 1
}

resolve_os_choice() {
    # Accepts a menu number, an id, a codename, or an alias. Prints the id.
    local want="${1,,}" id
    if [[ "$want" =~ ^[0-9]+$ ]] && (( want >= 1 && want <= ${#OS_ORDER[@]} )); then
        echo "${OS_ORDER[want-1]}"
        return 0
    fi
    for id in "${OS_ORDER[@]}"; do
        if [[ "$want" == "$id" || "$want" == "${OS_CODENAME[$id]}" ]]; then
            echo "$id"
            return 0
        fi
    done
    case "$want" in
        debian|debian-stable)  os_nth_of_family debian 1 ;;
        debian-oldstable)      os_nth_of_family debian 2 ;;
        ubuntu|ubuntu-lts)     os_nth_of_family ubuntu 1 ;;
        ubuntu-lts-prev)       os_nth_of_family ubuntu 2 ;;
        *)                     return 1 ;;
    esac
}

os_image_url() {
    local id="$1" code="${OS_CODENAME[$1]}" ver="${OS_VERSION[$1]}"
    if [[ "${OS_FAMILY[$id]}" == "debian" ]]; then
        echo "https://cloud.debian.org/images/cloud/${code}/latest/debian-${ver%%.*}-genericcloud-amd64.qcow2"
    else
        echo "https://cloud-images.ubuntu.com/${code}/current/${code}-server-cloudimg-amd64.img"
    fi
}

os_sums_url() {
    local id="$1" code="${OS_CODENAME[$1]}"
    if [[ "${OS_FAMILY[$id]}" == "debian" ]]; then
        echo "https://cloud.debian.org/images/cloud/${code}/latest/SHA512SUMS"
    else
        echo "https://cloud-images.ubuntu.com/${code}/current/SHA256SUMS"
    fi
}

sha_of() {
    # Usage: sha_of family file   (Debian publishes SHA512SUMS, Ubuntu SHA256SUMS)
    if [[ "$1" == "debian" ]]; then
        sha512sum "$2" | awk '{print $1}'
    else
        sha256sum "$2" | awk '{print $1}'
    fi
}

# =============================================================================
# COLLECT USER INPUT
# =============================================================================
collect_input() {
    header "Provisioning Configuration"

    # --- Type ---
    divider
    if [[ -z "$PROV_TYPE" ]]; then
        show "  ${BOLD}Guest Type${RESET}"
        show "    1) LXC Container ${DIM}(lightweight, shared kernel)${RESET}"
        show "    2) Virtual Machine ${DIM}(full isolation, own kernel)${RESET}"
    fi
    prompt "Select type" "1" PROV_TYPE
    case "${PROV_TYPE,,}" in
        1|lxc)  PROV_TYPE="lxc" ;;
        2|vm)   PROV_TYPE="vm" ;;
        *)      err "Invalid type '${PROV_TYPE}'. Use lxc or vm."; exit 1 ;;
    esac
    ok "Type: ${PROV_TYPE^^}"

    # --- OS ---
    divider
    if [[ -z "$PROV_OS" ]]; then
        show "  ${BOLD}Operating System${RESET} ${DIM}(current releases, resolved live)${RESET}"
        local i=1 id
        for id in "${OS_ORDER[@]}"; do
            show "    ${i}) ${OS_NAMES[$id]}"
            i=$((i + 1))
        done
    fi
    prompt "Select OS" "1" PROV_OS
    local resolved
    resolved=$(resolve_os_choice "$PROV_OS") || {
        err "Unknown OS '${PROV_OS}'. Available: ${OS_ORDER[*]}"
        exit 1
    }
    PROV_OS="$resolved"
    ok "OS: ${OS_NAMES[$PROV_OS]}"

    # --- ID ---
    divider
    local suggested_id=""
    if [[ -z "$PROV_ID" ]]; then
        suggested_id=$(suggest_free_id)
    fi
    prompt_valid PROV_ID "Guest ID (100+)" "$suggested_id" validate_id "Invalid or already-used ID."
    ok "ID: ${PROV_ID}"

    # --- Hostname ---
    divider
    prompt_valid PROV_HOSTNAME "Hostname" "$DEFAULT_HOSTNAME" valid_hostname \
        "Hostname must be a valid DNS name (letters, digits, hyphens, dots)."
    PROV_HOSTNAME="${PROV_HOSTNAME,,}"
    ok "Hostname: ${PROV_HOSTNAME}"

    # --- Resources ---
    divider
    prompt_valid PROV_CPU "CPU cores" "$DEFAULT_CPU" valid_cores "CPU cores must be a whole number (1-512)."
    if [[ "$PROV_TYPE" == "vm" ]]; then
        show "  ${DIM}CPU type: x86-64-v3 suits any host from ~2015 on; use x86-64-v2-AES for mixed/older"
        show "  clusters, or 'host' for best performance (no live migration across CPU generations).${RESET}"
        prompt_valid PROV_CPU_TYPE "CPU type" "$DEFAULT_CPU_TYPE" valid_cpu_type "Invalid CPU type."
        check_host_cpu_support "$PROV_CPU_TYPE"
    fi
    prompt_valid PROV_RAM "RAM (GB)" "$DEFAULT_RAM" valid_ram "RAM must be a whole number of GB (1-4096)."
    prompt_valid PROV_DISK "Disk size (GB)" "$DEFAULT_DISK" valid_disk "Disk size must be a whole number of GB (1-65536)."
    if [[ "$PROV_TYPE" == "vm" ]]; then
        ok "Resources: ${PROV_CPU} CPU (${PROV_CPU_TYPE}) / ${PROV_RAM}GB RAM / ${PROV_DISK}GB Disk"
    else
        ok "Resources: ${PROV_CPU} CPU / ${PROV_RAM}GB RAM / ${PROV_DISK}GB Disk"
    fi

    # --- Network ---
    divider
    prompt_valid PROV_BRIDGE "Network bridge" "$DEFAULT_BRIDGE" valid_bridge "Network interface/bridge not found on this host."
    ok "Bridge: ${PROV_BRIDGE}"

    # --- Storage ---
    divider
    if [[ "$PROV_TYPE" == "lxc" ]]; then
        PROV_TPL_STORAGE=$(select_storage "vztmpl" "templates" "$PROV_TPL_STORAGE")
        PROV_DISK_STORAGE=$(select_storage "rootdir" "container rootfs" "$PROV_DISK_STORAGE")
    else
        # For VMs: cloud images are downloaded to a local cache dir, not managed
        # by Proxmox storage content types. We only need disk storage for the VM.
        PROV_TPL_STORAGE=""
        PROV_DISK_STORAGE=$(select_storage "images" "VM disks" "$PROV_DISK_STORAGE")
    fi
    if [[ -n "$PROV_TPL_STORAGE" ]]; then
        ok "Template storage: ${PROV_TPL_STORAGE}"
    fi
    ok "Disk storage: ${PROV_DISK_STORAGE}"

    # --- Optional Packages ---
    header "Optional Packages"
    ask_flag PROV_OPT_BTOP "Install btop (system monitor)?" "y"
    ask_flag PROV_OPT_GIT "Install git?" "y"
    ask_flag PROV_OPT_GH "Install GitHub CLI (gh)?" "n"

    # --- Apt cache ---
    divider
    if [[ -z "$PROV_APT_CACHE" ]]; then
        # Interactive: offer it, defaulting to yes when the cache host resolves from here.
        # Non-interactive: off unless asked for.
        if (( ASSUME_YES )); then
            PROV_APT_CACHE="none"
        else
            local cache_default="n"
            getent hosts "${DEFAULT_APT_CACHE%:*}" >/dev/null 2>&1 && cache_default="y"
            if prompt_yesno "Use an apt cache (apt-cacher-ng)?" "$cache_default"; then
                PROV_APT_CACHE=""
                prompt_valid PROV_APT_CACHE "Apt cache (host:port)" "$DEFAULT_APT_CACHE" valid_apt_cache \
                    "Apt cache must look like host:port."
            else
                PROV_APT_CACHE="none"
            fi
        fi
    elif [[ "${PROV_APT_CACHE,,}" == "none" ]]; then
        PROV_APT_CACHE="none"
    else
        valid_apt_cache "$PROV_APT_CACHE" || { err "Apt cache must look like host:port."; exit 1; }
    fi
    if [[ "$PROV_APT_CACHE" == "none" ]]; then
        PROV_APT_CACHE=""
    else
        ok "Apt cache: ${PROV_APT_CACHE} (falls back to direct if unreachable)"
    fi

    # --- User Configuration ---
    header "User Configuration"
    info "Root will get a random password (stored in Proxmox notes; console login only)"
    PROV_ROOT_PW=$(generate_password)
    ok "Root password generated"

    divider
    info "Creating 'sysadmin' user with sudo access"
    if [[ -n "$PROV_SYSADMIN_PW" ]]; then
        if [[ ${#PROV_SYSADMIN_PW} -lt 5 ]]; then
            err "sysadmin password must be at least 5 characters."
            exit 1
        fi
    elif (( ASSUME_YES )); then
        PROV_SYSADMIN_PW=$(generate_password)
        PROV_SYSADMIN_PW_GENERATED="y"
        ok "sysadmin password generated (stored in Proxmox notes)"
    else
        prompt_secret "Set sysadmin password" PROV_SYSADMIN_PW
    fi

    divider
    local keys_requested=0
    [[ -n "$PROV_GITHUB_USER" ]] && keys_requested=1
    if [[ -z "$PROV_GITHUB_USER" && "$ASSUME_YES" -eq 0 ]]; then
        if prompt_yesno "Import SSH keys from GitHub?" "y"; then
            prompt "GitHub username" "" PROV_GITHUB_USER
        fi
    fi
    if [[ -n "$PROV_GITHUB_USER" ]]; then
        if PROV_SSH_KEYS=$(fetch_github_keys "$PROV_GITHUB_USER"); then
            local key_count
            key_count=$(echo "$PROV_SSH_KEYS" | wc -l)
            ok "Fetched ${key_count} SSH key(s) from github.com/${PROV_GITHUB_USER}"
        else
            PROV_SSH_KEYS=""
            PROV_KEYS_FAILED="y"
            # Asked for explicitly (flag/env) = a requirement: don't build a guest the
            # caller may be unable to log in to. Typed at the prompt = shown in the review.
            if (( keys_requested )); then
                err "SSH key import from GitHub was requested but failed. Fix it, or drop --github-user to continue with password login only."
                exit 1
            fi
        fi
    fi
}

# =============================================================================
# CONFIRMATION
# =============================================================================
confirm_settings() {
    header "Review Configuration"
    echo -e "  ${BOLD}Type:${RESET}        ${PROV_TYPE^^}"
    echo -e "  ${BOLD}OS:${RESET}          ${OS_NAMES[$PROV_OS]}"
    echo -e "  ${BOLD}ID:${RESET}          ${PROV_ID}"
    echo -e "  ${BOLD}Hostname:${RESET}    ${PROV_HOSTNAME}"
    echo -e "  ${BOLD}CPU:${RESET}         ${PROV_CPU} cores"
    [[ "$PROV_TYPE" == "vm" ]] && echo -e "  ${BOLD}CPU type:${RESET}    ${PROV_CPU_TYPE}"
    echo -e "  ${BOLD}RAM:${RESET}         ${PROV_RAM} GB"
    echo -e "  ${BOLD}Disk:${RESET}        ${PROV_DISK} GB"
    echo -e "  ${BOLD}Bridge:${RESET}      ${PROV_BRIDGE}"
    echo -e "  ${BOLD}Disk Store:${RESET}  ${PROV_DISK_STORAGE}"
    echo -e "  ${BOLD}Apt cache:${RESET}   ${PROV_APT_CACHE:-none}"
    echo -e "  ${BOLD}Root PW:${RESET}     ${DIM}(random — stored in notes, console login only)${RESET}"
    echo -e "  ${BOLD}sysadmin:${RESET}    password auth + sudo"
    [[ -n "$PROV_SSH_KEYS" ]] && echo -e "  ${BOLD}SSH Keys:${RESET}    from github.com/${PROV_GITHUB_USER}"
    [[ "$PROV_KEYS_FAILED" == "y" ]] && echo -e "  ${BOLD}SSH Keys:${RESET}    ${RED}NONE — GitHub import failed; password login only${RESET}"
    echo -e "  ${BOLD}Packages:${RESET}    ${DIM}$(guest_packages display)${RESET}"
    echo

    if (( ASSUME_YES )); then
        return 0
    fi
    if ! prompt_yesno "Proceed with provisioning?" "y"; then
        info "Aborted by user."
        exit 0
    fi
}

# =============================================================================
# LXC CREATION
# =============================================================================
find_lxc_template() {
    local os="$1" storage="$2"
    local search_term
    if [[ "${OS_FAMILY[$os]}" == "debian" ]]; then
        search_term="debian-${OS_VERSION[$os]%%.*}-standard"
    else
        search_term="ubuntu-${OS_VERSION[$os]}-standard"
    fi

    # Check if already downloaded
    local local_template
    local_template=$(pveam list "$storage" 2>/dev/null \
        | grep "$search_term" | sort -V | tail -1 | awk '{print $1}') || true

    if [[ -n "$local_template" ]]; then
        echo "$local_template"
        return
    fi

    # Find available template online (refresh the index once if it's missing)
    local available
    available=$(pveam available --section system 2>/dev/null \
        | grep "$search_term" | sort -V | tail -1 | awk '{print $2}') || true
    if [[ -z "$available" ]]; then
        pveam update >&2 || true
        available=$(pveam available --section system 2>/dev/null \
            | grep "$search_term" | sort -V | tail -1 | awk '{print $2}') || true
    fi

    if [[ -z "$available" ]]; then
        err "No LXC template found for ${OS_NAMES[$os]}."
        err "Check: pveam available --section system | grep '${search_term}'"
        err "(Proxmox may not publish a template for the newest release yet; a VM works regardless.)"
        exit 1
    fi

    # stdout is captured via $(...) — keep status on stderr, path on stdout.
    info "Downloading template: ${available}" >&2
    pveam download "$storage" "$available" >&2 || {
        err "Template download failed."
        exit 1
    }

    echo "${storage}:vztmpl/${available}"
}

# Push a file into a container with a mode: lxc_push_file id mode dest <<< content
lxc_push_file() {
    local id="$1" mode="$2" dest="$3" tmp
    tmp=$(mktemp /tmp/pve-push-XXXXXX)
    CLEANUP_FILES+=("$tmp")
    cat > "$tmp"
    pct push "$id" "$tmp" "$dest" --perms "$mode" >> "$PROVISION_LOG" 2>&1
    rm -f "$tmp"
}

create_lxc() {
    header "Creating LXC Container"

    local template
    template=$(find_lxc_template "$PROV_OS" "$PROV_TPL_STORAGE")
    ok "Template: ${template}"

    local ram_mb=$(( PROV_RAM * 1024 ))

    # Last-moment re-check: never create over (or later destroy) an existing guest.
    validate_id "$PROV_ID" || { err "$VALIDATION_MSG"; exit 1; }

    info "Creating container ${PROV_ID}..."
    pct create "$PROV_ID" "$template" \
        --hostname "$PROV_HOSTNAME" \
        --cores "$PROV_CPU" \
        --memory "$ram_mb" \
        --rootfs "${PROV_DISK_STORAGE}:${PROV_DISK}" \
        --net0 "name=eth0,bridge=${PROV_BRIDGE},ip=dhcp" \
        --unprivileged 1 \
        --features "nesting=1" \
        --tags "$GUEST_TAG" \
        --onboot 0 \
        --start 0 \
        --password "$PROV_ROOT_PW"

    # Only now is there something of ours to clean up on failure.
    CLEANUP_CTID="$PROV_ID"
    CLEANUP_TYPE="lxc"
    ok "Container created"

    info "Starting container..."
    pct start "$PROV_ID"
    ok "Container started"

    # Wait for networking
    sleep 3
    local guest_ip
    guest_ip=$(wait_for_network "$PROV_ID" 30)
    if [[ "$guest_ip" == "pending" ]]; then
        err "Container has no network (DHCP on bridge ${PROV_BRIDGE}?). Cannot install packages."
        exit 1
    fi

    configure_lxc_guest "$PROV_ID" "$guest_ip"
}

configure_lxc_guest() {
    local id="$1" ip="$2"

    header "Configuring LXC Guest"

    # Apt cache first, so the package installs below use it
    if [[ -n "$PROV_APT_CACHE" ]]; then
        info "Configuring apt cache ${PROV_APT_CACHE}..."
        apt_proxy_detect_script "$PROV_APT_CACHE" | lxc_push_file "$id" 0755 /usr/local/bin/apt-proxy-detect
        apt_proxy_conf | lxc_push_file "$id" 0644 /etc/apt/apt.conf.d/01acng
        lxc_exec "$id" "apt mirror scheme" "$(apt_https_to_http_cmd)"
        ok "Apt cache configured"
    fi

    local packages
    packages=$(guest_packages install)

    info "Updating package lists..."
    lxc_exec "$id" "apt-get update" \
        "apt-get update -qq"
    ok "Package lists updated"

    info "Installing packages: ${packages}"
    lxc_exec "$id" "Package installation" \
        "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${APT_OPTS} ${packages}"
    ok "Base packages installed"

    # GitHub CLI (needs separate repo)
    if [[ "$PROV_OPT_GH" == "y" ]]; then
        info "Installing GitHub CLI..."
        # shellcheck disable=SC2016  # single quotes intentional: expanded inside the guest
        lxc_exec "$id" "GitHub CLI installation" '
            mkdir -p -m 755 /etc/apt/keyrings
            curl -fsSL --connect-timeout 10 --max-time 30 \
                https://cli.github.com/packages/githubcli-archive-keyring.gpg \
                | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
            chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
                > /etc/apt/sources.list.d/github-cli.list
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq '"${APT_OPTS}"' gh
        '
        ok "GitHub CLI installed"
    fi

    # Create sysadmin user — pass password via temp file to avoid shell expansion issues
    info "Creating sysadmin user..."
    local pw_tmpfile
    pw_tmpfile=$(mktemp /tmp/pve-pw-XXXXXX)
    CLEANUP_FILES+=("$pw_tmpfile")
    echo "sysadmin:${PROV_SYSADMIN_PW}" > "$pw_tmpfile"
    chmod 600 "$pw_tmpfile"

    pct exec "$id" -- bash -c "set -euo pipefail; useradd -m -s /bin/bash -G sudo sysadmin" >> "$PROVISION_LOG" 2>&1
    pct push "$id" "$pw_tmpfile" /tmp/.pve-pw 2>/dev/null
    pct exec "$id" -- bash -c "set -euo pipefail; chpasswd < /tmp/.pve-pw && rm -f /tmp/.pve-pw" >> "$PROVISION_LOG" 2>&1
    rm -f "$pw_tmpfile"
    ok "sysadmin user created with sudo"

    # SSH configuration (drop-in, so cloud-init/other drop-ins can't override it)
    info "Configuring SSH..."
    pct exec "$id" -- mkdir -p /etc/ssh/sshd_config.d >> "$PROVISION_LOG" 2>&1
    sshd_dropin_content | lxc_push_file "$id" 0644 /etc/ssh/sshd_config.d/00-pve-prov.conf
    # Verified, not assumed: valid config, service really running, and the settings we
    # promise actually in effect (a conflicting earlier drop-in would win otherwise).
    lxc_exec "$id" "SSH configuration" '
        mkdir -p /run/sshd
        sshd -t
        systemctl enable ssh 2>/dev/null || systemctl enable sshd
        systemctl restart ssh 2>/dev/null || systemctl restart sshd
        systemctl is-active --quiet ssh || systemctl is-active --quiet sshd
        sshd -T | grep -qix "permitrootlogin no"
        sshd -T | grep -qix "passwordauthentication yes"
    '
    ok "SSH configured and verified (password auth enabled, root login disabled)"

    # Import SSH keys if provided — use pct push to avoid heredoc expansion issues
    if [[ -n "$PROV_SSH_KEYS" ]]; then
        info "Installing SSH keys for sysadmin..."
        local keys_tmpfile
        keys_tmpfile=$(mktemp /tmp/pve-keys-XXXXXX)
        CLEANUP_FILES+=("$keys_tmpfile")
        echo "$PROV_SSH_KEYS" > "$keys_tmpfile"
        chmod 600 "$keys_tmpfile"

        pct exec "$id" -- bash -c "set -euo pipefail; mkdir -p /home/sysadmin/.ssh && chmod 700 /home/sysadmin/.ssh" >> "$PROVISION_LOG" 2>&1
        pct push "$id" "$keys_tmpfile" /home/sysadmin/.ssh/authorized_keys 2>/dev/null
        pct exec "$id" -- bash -c "set -euo pipefail; chmod 600 /home/sysadmin/.ssh/authorized_keys && chown -R sysadmin:sysadmin /home/sysadmin/.ssh" >> "$PROVISION_LOG" 2>&1
        rm -f "$keys_tmpfile"
        ok "SSH keys installed for sysadmin"
    fi

    # Clean up inside guest
    pct exec "$id" -- bash -c "apt-get clean; rm -rf /var/lib/apt/lists/*" >/dev/null 2>&1 || true

    # Get the actual IP (may have changed after SSH restart)
    local final_ip
    final_ip=$(pct exec "$id" -- hostname -I 2>/dev/null | awk '{print $1}') || final_ip=""
    [[ -n "$final_ip" ]] || final_ip="$ip"

    # The container is fully provisioned. From here on a failure must never destroy it.
    CLEANUP_CTID=""

    # Notes are best effort: the guest works without them.
    local notes_html
    if notes_html=$(generate_notes_html "$final_ip") && pct set "$id" --description "$notes_html"; then
        ok "Proxmox notes updated"
    else
        warn "Could not write the Proxmox notes. Record the passwords shown below now: they are not stored anywhere else."
    fi

    # Done!
    print_summary "$final_ip"
}

# =============================================================================
# VM CREATION
# =============================================================================
download_cloud_image() {
    # NOTE: this function's stdout is captured via $(...), so it must emit
    # ONLY the image path on stdout. All human-readable status goes to stderr;
    # otherwise the status text is spliced into the --scsi0 import-from path
    # and `qm set` fails with "invalid format ... missing key".
    local os="$1"
    local family="${OS_FAMILY[$os]}"
    local url sums_url filename filepath
    url=$(os_image_url "$os")
    sums_url=$(os_sums_url "$os")
    filename=$(basename "$url")
    filepath="${CLOUD_IMG_DIR}/${filename}"

    mkdir -p "$CLOUD_IMG_DIR"

    # Upstream checksum: used to verify downloads and to notice stale cache entries
    local sums want have
    sums=$(curl -fsSL --connect-timeout 15 --max-time 60 "$sums_url") || {
        err "Could not fetch checksums: ${sums_url}"
        exit 1
    }
    want=$(awk -v f="$filename" '{n = $2; sub(/^\*/, "", n); if (n == f) {print $1; exit}}' <<<"$sums")
    if [[ -z "$want" ]]; then
        err "No checksum for ${filename} in ${sums_url}"
        exit 1
    fi

    if [[ -f "$filepath" ]]; then
        have=$(sha_of "$family" "$filepath")
        if [[ "$have" == "$want" ]]; then
            ok "Cloud image cached and verified: ${filename}" >&2
            echo "$filepath"
            return
        fi
        info "Cached image is outdated or incomplete — refreshing: ${filename}" >&2
    fi

    info "Downloading cloud image: ${filename}" >&2
    info "URL: ${url}" >&2
    CLEANUP_FILES+=("${filepath}.part")
    curl -fL --progress-bar \
        --connect-timeout 15 \
        --max-time 900 \
        -o "${filepath}.part" "$url" || {
        rm -f "${filepath}.part"
        err "Cloud image download failed."
        exit 1
    }
    have=$(sha_of "$family" "${filepath}.part")
    if [[ "$have" != "$want" ]]; then
        rm -f "${filepath}.part"
        err "Checksum mismatch for ${filename} (the image may have just been updated upstream — try again)."
        exit 1
    fi
    mv -f "${filepath}.part" "$filepath"
    ok "Cloud image downloaded and verified" >&2
    echo "$filepath"
}

guest_file_exists() {
    # Usage: guest_file_exists vmid path   (via the QEMU guest agent)
    local out
    out=$(qm guest exec "$1" -- test -f "$2" 2>/dev/null) || return 1
    grep -qE '"exitcode"[[:space:]]*:[[:space:]]*0' <<<"$out"
}

create_vm() {
    header "Creating Virtual Machine"

    local image_path
    image_path=$(download_cloud_image "$PROV_OS")

    local ram_mb=$(( PROV_RAM * 1024 ))

    # Last-moment re-check: never create over (or later destroy) an existing guest.
    validate_id "$PROV_ID" || { err "$VALIDATION_MSG"; exit 1; }

    info "Creating VM ${PROV_ID}..."

    # Create the VM shell with modern settings
    qm create "$PROV_ID" \
        --name "$PROV_HOSTNAME" \
        --cores "$PROV_CPU" \
        --cpu "$PROV_CPU_TYPE" \
        --memory "$ram_mb" \
        --net0 "virtio,bridge=${PROV_BRIDGE}" \
        --scsihw virtio-scsi-single \
        --bios ovmf \
        --machine q35 \
        --efidisk0 "${PROV_DISK_STORAGE}:0,efitype=4m" \
        --agent 1 \
        --tags "$GUEST_TAG" \
        --onboot 0 \
        --ostype l26

    # Only now is there something of ours to clean up on failure.
    CLEANUP_CTID="$PROV_ID"
    CLEANUP_TYPE="vm"
    ok "VM shell created"

    # Import the cloud image as the boot disk
    info "Importing cloud image to disk..."
    qm set "$PROV_ID" --scsi0 "${PROV_DISK_STORAGE}:0,import-from=${image_path},discard=on,iothread=1,ssd=1"
    ok "Disk imported"

    # Resize to requested size
    info "Resizing disk to ${PROV_DISK}GB..."
    qm disk resize "$PROV_ID" scsi0 "${PROV_DISK}G"
    ok "Disk resized"

    # Set boot order
    qm set "$PROV_ID" --boot order=scsi0

    # --- Cloud-init configuration ---
    info "Configuring cloud-init..."

    # Add cloud-init drive
    qm set "$PROV_ID" --ide2 "${PROV_DISK_STORAGE}:cloudinit"

    # Ensure snippets dir exists
    mkdir -p "$SNIPPET_DIR"

    # Generate and install custom cloud-init user-data. The snippet only has to
    # exist until cloud-init has finished; it is removed again (together with the
    # cicustom setting that points at it) once the guest reports it is done.
    local snippet_file="pve-provision-${PROV_ID}-userdata.yml"
    local snippet_path="${SNIPPET_DIR}/${snippet_file}"
    CLEANUP_SNIPPET="$snippet_path"

    generate_cloudinit_userdata > "$snippet_path"
    chmod 600 "$snippet_path"
    ok "Cloud-init user-data generated (mode 600)"

    # Apply cloud-init config
    qm set "$PROV_ID" \
        --cicustom "user=local:snippets/${snippet_file}" \
        --ipconfig0 "ip=dhcp"
    ok "Cloud-init configured"

    # Start the VM
    info "Starting VM..."
    qm start "$PROV_ID"
    ok "VM started"

    info "Waiting for cloud-init + guest agent (this may take a few minutes)..."
    local elapsed=0
    local max_wait="$AGENT_WAIT_MAX"
    local guest_ip=""

    while (( elapsed < max_wait )); do
        # Try to get IP via guest agent
        local agent_info
        agent_info=$(qm guest cmd "$PROV_ID" network-get-interfaces 2>/dev/null) || true
        if [[ -n "$agent_info" ]]; then
            guest_ip=$(echo "$agent_info" \
                | grep -oP '"ip-address"\s*:\s*"\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
                | grep -v '^127\.' | head -1) || true
            if [[ -n "$guest_ip" ]]; then
                ok "VM network ready: ${guest_ip}"
                break
            fi
        fi
        sleep "$POLL_SECS"
        (( elapsed += POLL_SECS ))
        echo -en "\r  ⏳  Waiting... (${elapsed}s / ${max_wait}s)  "
    done
    echo

    if [[ -z "$guest_ip" ]]; then
        guest_ip="pending"
        warn "Could not detect IP via guest agent after ${max_wait}s."
        warn "Possible causes:"
        warn "  - cloud-init still running (give it another minute)"
        warn "  - qemu-guest-agent failed to install (check VM console)"
        warn "  - DHCP not responding on bridge ${PROV_BRIDGE}"
        warn "Debug: qm guest cmd ${PROV_ID} network-get-interfaces"
    fi

    # Wait for cloud-init to finish, then detach the snippet so the VM no longer
    # depends on anything outside its own config. If we can't confirm it finished,
    # LEAVE the snippet and cicustom in place: removing only one of them is what
    # makes a VM fail to start next time.
    PROV_DETACH_CMD="qm set ${PROV_ID} --delete cicustom && rm -f ${snippet_path}"
    local finished=0
    if [[ "$guest_ip" != "pending" ]]; then
        info "Waiting for cloud-init to finish..."
        local waited=0
        while (( waited < CLOUDINIT_WAIT_MAX )); do
            if guest_file_exists "$PROV_ID" /var/lib/cloud/instance/boot-finished; then
                finished=1
                break
            fi
            sleep "$POLL_SECS"
            (( waited += POLL_SECS ))
        done
    fi
    if (( finished )); then
        # cloud-init is done, so the snippet is no longer needed whatever happened in it.
        # Delete cicustom first and confirm it is really gone before removing the file.
        local vm_conf=""
        if qm set "$PROV_ID" --delete cicustom >/dev/null && vm_conf=$(qm config "$PROV_ID") \
            && ! grep -q '^cicustom:' <<<"$vm_conf"; then
            rm -f "$snippet_path"
            CLEANUP_SNIPPET=""
            ok "Cloud-init finished; user-data snippet and cicustom removed"
        else
            PROV_STATUS="unconfirmed"
            warn "Cloud-init finished, but cicustom could not be removed — snippet kept so the VM can still start."
        fi
        if [[ "$PROV_KEEP_CLOUD_INIT" == "y" ]]; then
            warn "Cloud-init left enabled: a later restart re-runs it with default data (SSH host keys are regenerated)."
        fi
        # "cloud-init finished" only means it ran to the end. Our own first-boot script
        # records whether every step we asked for actually worked.
        if ! guest_file_exists "$PROV_ID" /var/lib/cloud/pve-prov.ok; then
            [[ "$PROV_STATUS" == "ok" ]] && PROV_STATUS="degraded"
            local failed_steps
            failed_steps=$(guest_failed_steps "$PROV_ID")
            warn "Cloud-init finished, but not every first-boot step succeeded: ${failed_steps:-unknown}"
            warn "Inspect /var/log/cloud-init-output.log inside the VM (console or SSH)."
        fi
    else
        # Keep the snippet: cicustom still points at it. (CLEANUP_SNIPPET stays set so
        # that it is only removed if a later failure also destroys the VM.)
        PROV_STATUS="unconfirmed"
        warn "Could not confirm cloud-init finished — snippet and cicustom left in place."
        warn "Once the VM is up, detach them together:"
        warn "  ${PROV_DETACH_CMD}"
    fi

    # The VM is built. From here on a failure must never destroy it.
    CLEANUP_CTID=""

    # Notes are best effort: the VM works without them.
    local notes_html
    if notes_html=$(generate_notes_html "$guest_ip") && qm set "$PROV_ID" --description "$notes_html"; then
        ok "Proxmox notes updated"
    else
        warn "Could not write the Proxmox notes. Record the passwords shown below now: they are not stored anywhere else."
    fi

    print_summary "$guest_ip"
    # Distinct exit codes so automation can tell "done" from "done but check it"
    case "$PROV_STATUS" in
        degraded)    exit 4 ;;
        unconfirmed) exit 3 ;;
    esac
}

guest_failed_steps() {
    # Names of the first-boot steps that failed, as recorded by our first-boot script.
    # `qm guest exec` answers with JSON; the file content is in "out-data".
    local out
    out=$(qm guest exec "$1" -- cat /var/lib/cloud/pve-prov.failed 2>/dev/null) || return 0
    tr -d '\n' <<<"$out" \
        | sed -n 's/.*"out-data"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        | sed 's/\\n//g; s/^ *//; s/ *$//'
}

generate_cloudinit_userdata() {
    local root_hash sysadmin_hash
    root_hash=$(hash_password "$PROV_ROOT_PW")
    sysadmin_hash=$(hash_password "$PROV_SYSADMIN_PW")

    # Package list (single source of truth: guest_packages)
    local pkg_list="" p
    for p in $(guest_packages install); do
        pkg_list+="  - ${p}
"
    done
    pkg_list="${pkg_list%$'\n'}"

    # Short hostname + FQDN
    local short_name="${PROV_HOSTNAME%%.*}" fqdn="$PROV_HOSTNAME"

    # Build SSH keys block for sysadmin user. Each key is single-quoted: a comment
    # containing ": " or " #" would otherwise turn the line into a YAML mapping or
    # truncate it.
    local ssh_keys_block="" sq="'"
    if [[ -n "$PROV_SSH_KEYS" ]]; then
        ssh_keys_block="    ssh_authorized_keys:"
        while IFS= read -r key; do
            ssh_keys_block+="
      - '${key//$sq/$sq$sq}'"
        done <<< "$PROV_SSH_KEYS"
    fi

    # write_files: sshd drop-in, first-boot script (+ apt cache). write_files runs
    # before the package install.
    local write_files
    write_files="  - path: /etc/ssh/sshd_config.d/00-pve-prov.conf
    permissions: '0644'
    content: |
$(sshd_dropin_content | sed 's/^/      /')
  - path: /usr/local/sbin/pve-prov-firstboot
    permissions: '0700'
    content: |
$(firstboot_script | sed 's/^/      /')"
    if [[ -n "$PROV_APT_CACHE" ]]; then
        write_files+="
  - path: /usr/local/bin/apt-proxy-detect
    permissions: '0755'
    content: |
$(apt_proxy_detect_script "$PROV_APT_CACHE" | sed 's/^/      /')
  - path: /etc/apt/apt.conf.d/01acng
    permissions: '0644'
    content: |
$(apt_proxy_conf | sed 's/^/      /')"
    fi

    # With an apt cache on Debian, tell cloud-init to generate http mirrors: Debian's
    # cloud-init regenerates /etc/apt/mirrors/*.list in its config stage
    # (generate_mirrorlists), so editing the files early gets overwritten. This makes
    # the first-boot upgrade use the cache; the first-boot script then rewrites any
    # remaining https mirrors so the final state is right whatever generated them.
    local apt_block=""
    if [[ -n "$PROV_APT_CACHE" && "${OS_FAMILY[$PROV_OS]}" == "debian" ]]; then
        apt_block="
apt:
  primary:
    - arches: [default]
      uri: http://deb.debian.org/debian
  security:
    - arches: [default]
      uri: http://deb.debian.org/debian-security
"
    fi

    # hostname/fqdn are quoted: bare, YAML turns names like "no.lan" or "null" into
    # booleans/null and cloud-init would set the hostname to "False".
    cat <<CLOUDINIT
#cloud-config
hostname: '${short_name}'
fqdn: '${fqdn}'
manage_etc_hosts: true
package_update: true
package_upgrade: true

# Preserve default cloud-image user and their hooks (disk resize, SSH keygen etc.)
users:
  - default
  - name: root
    lock_passwd: false
    hashed_passwd: '${root_hash}'
  - name: sysadmin
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    hashed_passwd: '${sysadmin_hash}'
${ssh_keys_block}

write_files:
${write_files}
${apt_block}
packages:
${pkg_list}

ssh_pwauth: true

runcmd:
  - [ /usr/local/sbin/pve-prov-firstboot ]

final_message: "pve-provision: cloud-init complete after \$UPTIME seconds"
CLOUDINIT
}

# The VM's first-boot steps, as one real bash script (written by cloud-init, run from
# runcmd, deletes itself). A runcmd list is a /bin/sh script without `set -e`, so a
# failing line is invisible and "cloud-init finished" proves nothing. This script
# records which steps failed in /var/lib/cloud/pve-prov.failed and only writes
# pve-prov.ok if all of them worked; the provisioning host checks that marker.
firstboot_script() {
    cat <<'EOF'
#!/bin/bash
# pve-prov first-boot steps. Runs once from cloud-init, then removes itself.
set -u
failed=""
step() { local name="$1"; shift; "$@" || failed+=" ${name}"; }

agent_up() { systemctl enable qemu-guest-agent && systemctl start qemu-guest-agent; }
sshd_up() {
    mkdir -p /run/sshd && sshd -t \
        && { systemctl restart ssh || systemctl restart sshd; } \
        && sshd -T | grep -qix "permitrootlogin no" \
        && sshd -T | grep -qix "passwordauthentication yes"
}
step agent agent_up
step sshd sshd_up
EOF
    if [[ -n "$PROV_APT_CACHE" ]]; then
        printf 'mirrors() {\n    %s\n}\nstep mirrors mirrors\n' "$(apt_https_to_http_cmd)"
    fi
    if [[ "$PROV_OPT_GH" == "y" ]]; then
        cat <<EOF
gh_install() {
    mkdir -p -m 755 /etc/apt/keyrings \\
        && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \\
        && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \\
        && echo "deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \\
        && apt-get update -qq \\
        && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${APT_OPTS} gh \\
        && command -v gh >/dev/null
}
step gh gh_install
EOF
    fi
    echo 'apt-get clean'
    # Run-once tool: switch cloud-init off after this first boot so a later restart
    # can't re-run it (new instance-id -> regenerated SSH host keys, new DHCP lease).
    if [[ "$PROV_KEEP_CLOUD_INIT" != "y" ]]; then
        echo 'touch /etc/cloud/cloud-init.disabled'
    fi
    cat <<'EOF'
echo "${failed# }" > /var/lib/cloud/pve-prov.failed
if [[ -z "$failed" ]]; then touch /var/lib/cloud/pve-prov.ok; fi
rm -f -- "$0"
exit 0
EOF
}

# =============================================================================
# HTML NOTES FOR PROXMOX
# =============================================================================
generate_notes_html() {
    local ip="${1:-pending}"
    local created_at
    created_at=$(date -u '+%Y-%m-%d %H:%M UTC')
    local type_label cpu_type_row="—"
    if [[ "$PROV_TYPE" == "lxc" ]]; then
        type_label="LXC Container"
    else
        type_label="Virtual Machine"
        cpu_type_row="${PROV_CPU_TYPE}"
    fi

    # Build package list for display
    local pkg_display
    pkg_display=$(guest_packages display | sed 's/ /, /g')

    local ssh_info="Password authentication"
    [[ -n "$PROV_SSH_KEYS" ]] && ssh_info="Password + SSH keys (github.com/${PROV_GITHUB_USER})"

    local sysadmin_pw_row=""
    if [[ "$PROV_SYSADMIN_PW_GENERATED" == "y" ]]; then
        sysadmin_pw_row="<code style=\"background: #dcfce7; padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-left: 8px;\">${PROV_SYSADMIN_PW}</code>"
    fi

    # A visible warning in the notes if provisioning did not fully succeed
    local status_html=""
    case "$PROV_STATUS" in
        unconfirmed)
            status_html="  <div style=\"background: #fef3c7; padding: 10px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; font-size: 12px; color: #92400e;\">⚠️ <strong>Provisioning was not confirmed.</strong> When the VM is up, run on the Proxmox host: <code>${PROV_DETACH_CMD}</code></div>" ;;
        degraded)
            status_html="  <div style=\"background: #fef3c7; padding: 10px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0; font-size: 12px; color: #92400e;\">⚠️ <strong>Some first-boot steps failed.</strong> See /var/log/cloud-init-output.log inside the VM.</div>" ;;
    esac

    cat <<'HTMLEOF'
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; color: #1a1a2e;">
HTMLEOF

    cat <<HTMLEOF
  <!-- Header -->
  <div style="background: linear-gradient(135deg, #0f3460 0%, #16213e 100%); border-radius: 10px 10px 0 0; padding: 20px; text-align: center;">
    <h2 style="color: #e0e0e0; margin: 0 0 4px 0; font-size: 20px;">⚙️ ${PROV_HOSTNAME}</h2>
    <span style="color: #94a3b8; font-size: 13px;">${type_label} · ${OS_NAMES[$PROV_OS]} · ID ${PROV_ID}</span>
  </div>
${status_html}
  <!-- Resources -->
  <div style="background: #f8fafc; padding: 14px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0;">
    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
      <tr>
        <td style="padding: 4px 0;"><strong>🧠 CPU</strong></td>
        <td style="padding: 4px 0; text-align: right;">${PROV_CPU} cores</td>
        <td style="padding: 4px 0; width: 20px;"></td>
        <td style="padding: 4px 0;"><strong>💾 Disk</strong></td>
        <td style="padding: 4px 0; text-align: right;">${PROV_DISK} GB</td>
      </tr>
      <tr>
        <td style="padding: 4px 0;"><strong>🛠️ RAM</strong></td>
        <td style="padding: 4px 0; text-align: right;">${PROV_RAM} GB</td>
        <td style="padding: 4px 0;"></td>
        <td style="padding: 4px 0;"><strong>🌉 Bridge</strong></td>
        <td style="padding: 4px 0; text-align: right;">${PROV_BRIDGE}</td>
      </tr>
      <tr>
        <td style="padding: 4px 0;"><strong>⚡ CPU type</strong></td>
        <td style="padding: 4px 0; text-align: right;">${cpu_type_row}</td>
        <td style="padding: 4px 0;"></td>
        <td style="padding: 4px 0;"><strong>🗄️ Apt cache</strong></td>
        <td style="padding: 4px 0; text-align: right;">${PROV_APT_CACHE:-none}</td>
      </tr>
    </table>
  </div>

  <!-- Access -->
  <div style="background: #ffffff; padding: 14px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0;">
    <h3 style="margin: 0 0 10px 0; font-size: 14px; color: #0f3460;">🔐 Access Credentials</h3>
    <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
      <tr>
        <td style="padding: 6px 8px; background: #fef2f2; border-radius: 4px;" colspan="2">
          <strong>root</strong>
          <code style="background: #fee2e2; padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-left: 8px;">${PROV_ROOT_PW}</code>
          <span style="color: #991b1b; font-size: 11px; margin-left: 4px;">⚠️ SSH disabled · console only</span>
        </td>
      </tr>
      <tr><td style="padding: 3px;"></td></tr>
      <tr>
        <td style="padding: 6px 8px; background: #f0fdf4; border-radius: 4px;" colspan="2">
          <strong>sysadmin</strong>${sysadmin_pw_row}
          <span style="color: #166534; font-size: 11px; margin-left: 8px;">✔ sudo · ${ssh_info}</span>
        </td>
      </tr>
    </table>
  </div>

  <!-- Network -->
  <div style="background: #f8fafc; padding: 14px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0;">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: #0f3460;">📡 Network</h3>
    <table style="width: 100%; font-size: 13px;">
      <tr><td><strong>IP Address</strong></td><td style="text-align: right;"><code>${ip}</code></td></tr>
      <tr><td><strong>SSH</strong></td><td style="text-align: right;"><code>ssh sysadmin@${ip}</code></td></tr>
    </table>
  </div>

  <!-- Packages -->
  <div style="background: #ffffff; padding: 14px 20px; border-left: 1px solid #e2e8f0; border-right: 1px solid #e2e8f0;">
    <h3 style="margin: 0 0 8px 0; font-size: 14px; color: #0f3460;">📦 Installed Packages</h3>
    <p style="font-size: 12px; color: #64748b; margin: 0;">${pkg_display}</p>
  </div>

  <!-- Footer -->
  <div style="background: #f1f5f9; border-radius: 0 0 10px 10px; padding: 12px 20px; border: 1px solid #e2e8f0; border-top: none; text-align: center;">
    <span style="font-size: 11px; color: #94a3b8;">
      Provisioned by <strong>pve-provision.sh v${SCRIPT_VERSION}</strong> · ${created_at}
    </span>
  </div>
</div>
HTMLEOF
}

# =============================================================================
# FINAL SUMMARY
# =============================================================================
print_summary() {
    local ip="${1:-pending}"

    case "$PROV_STATUS" in
        ok)          header "Provisioning Complete! 🎉" ;;
        degraded)    header "Provisioning finished WITH PROBLEMS ⚠" ;;
        unconfirmed) header "Provisioning NOT CONFIRMED ⚠" ;;
    esac
    echo -e "  ${BOLD}${PROV_TYPE^^} ${PROV_ID}${RESET} — ${OS_NAMES[$PROV_OS]}"
    echo -e "  ${BOLD}Hostname:${RESET}    ${PROV_HOSTNAME}"
    if [[ "$ip" == "pending" ]]; then
        echo -e "  ${BOLD}IP:${RESET}          ${YELLOW}not detected${RESET} (see the warnings above)"
    else
        echo -e "  ${BOLD}IP:${RESET}          ${ip}"
        echo
        echo -e "  ${BOLD}Connect:${RESET}     ${GREEN}ssh sysadmin@${ip}${RESET}"
    fi
    if [[ "$PROV_STATUS" == "unconfirmed" ]]; then
        echo
        echo -e "  ${YELLOW}${BOLD}Required, once the VM is up:${RESET} ${PROV_DETACH_CMD}"
    elif [[ "$PROV_STATUS" == "degraded" ]]; then
        echo
        echo -e "  ${YELLOW}Some first-boot steps failed (listed above). Check /var/log/cloud-init-output.log in the VM.${RESET}"
    fi
    echo -e "  ${BOLD}Root PW:${RESET}     ${DIM}${PROV_ROOT_PW}${RESET} ${DIM}(also in Proxmox notes; console login only)${RESET}"
    if [[ "$PROV_SYSADMIN_PW_GENERATED" == "y" ]]; then
        echo -e "  ${BOLD}sysadmin PW:${RESET} ${DIM}${PROV_SYSADMIN_PW}${RESET} ${DIM}(generated; also in Proxmox notes)${RESET}"
    fi
    echo
    divider
    echo -e "  ${DIM}Full details stored in the Proxmox notes tab for this guest.${RESET}"
    echo

    # Clear cleanup trap state — we succeeded
    CLEANUP_CTID=""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    parse_args "$@"

    if (( ! ASSUME_YES )); then clear 2>/dev/null || true; fi
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║        Proxmox VE Guest Provisioner          ║"
    echo "  ║          pve-provision.sh v${SCRIPT_VERSION}               ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"

    preflight
    resolve_os_catalog
    collect_input
    confirm_settings

    if [[ "$PROV_TYPE" == "lxc" ]]; then
        create_lxc
    else
        create_vm
    fi
}

# Run only when executed (not when sourced, e.g. by the tests).
if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
    main "$@"
fi
