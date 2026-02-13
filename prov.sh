#!/usr/bin/env bash
# =============================================================================
# pve-provision.sh v1.1
# Self-contained Proxmox VE LXC/VM provisioner
#
# No external script sourcing. No telemetry. Audit once, run forever.
#
# Requirements: Run as root on a Proxmox VE host
# Tested on:    Proxmox VE 8.x / 9.x
#
# Changelog v1.1:
#   - Replaced eval with printf -v in prompt functions
#   - Fixed storage detection empty-string false positive
#   - Fixed pvesm status column parsing in select_storage
#   - Expanded valid guest ID range to 100–999999999
#   - VM storage: no longer selects "iso" storage for cloud images
#   - Cloud-init: preserves default user with "- default" entry
#   - Cloud-init snippet gets chmod 600 + auto-cleanup after boot
#   - apt-get: logs to file, shows tail on error, uses force-conf flags
#   - apt-get: set -euo pipefail inside pct exec subshells
#   - curl: added --connect-timeout and --max-time for cloud images
#   - Password: passed via pct push tempfile instead of shell expansion
#   - Package display: "gh" not "gh-cli"
#   - Ubuntu 25.04: marked as non-LTS in menu
# =============================================================================
set -euo pipefail

# =============================================================================
# CONSTANTS & DEFAULTS
# =============================================================================
SCRIPT_VERSION="1.1"

DEFAULT_TYPE="lxc"
DEFAULT_OS="debian-13"
DEFAULT_ID=""                    # Auto-detect next free ID
DEFAULT_HOSTNAME="hostname.lan"
DEFAULT_CPU=4
DEFAULT_RAM=4                    # GB
DEFAULT_DISK=50                  # GB
DEFAULT_BRIDGE="vmbr0"
DEFAULT_STORAGE=""               # Auto-detect

BASE_PACKAGES="util-linux curl wget net-tools sudo openssh-server nano"
VM_EXTRA_PACKAGES="qemu-guest-agent"

# APT options: non-interactive, keep existing configs on upgrade
APT_OPTS="-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"

# Cloud image URLs for VM creation
declare -A CLOUD_IMAGES=(
    ["debian-13"]="https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2"
    ["debian-12"]="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2"
    ["ubuntu-24.04"]="https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    ["ubuntu-25.04"]="https://cloud-images.ubuntu.com/plucky/current/plucky-server-cloudimg-amd64.img"
)

# Human-readable OS names
declare -A OS_NAMES=(
    ["debian-13"]="Debian 13 (Trixie)"
    ["debian-12"]="Debian 12 (Bookworm)"
    ["ubuntu-24.04"]="Ubuntu 24.04 LTS (Noble)"
    ["ubuntu-25.04"]="Ubuntu 25.04 (Plucky)"
)

# Cloud image cache directory
CLOUD_IMG_DIR="/var/lib/vz/template/cloud"

# Provisioning log file (guest-side apt output)
PROVISION_LOG="/tmp/pve-provision-$$.log"

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

prompt() {
    # Usage: prompt "Label" "default" VARNAME
    # Safe: uses printf -v instead of eval
    local label="$1" default="$2" varname="$3"
    local input
    echo -en "  ${BOLD}${label}${RESET}"
    [[ -n "$default" ]] && echo -en " ${DIM}[${default}]${RESET}"
    echo -en ": "
    read -r input
    printf -v "$varname" '%s' "${input:-$default}"
}

prompt_secret() {
    # Usage: prompt_secret "Label" VARNAME
    # Safe: uses printf -v instead of eval
    local label="$1" varname="$2"
    local pw1 pw2
    while true; do
        echo -en "  ${BOLD}${label}${RESET}: "
        read -rs pw1; echo
        echo -en "  ${BOLD}Confirm${RESET}: "
        read -rs pw2; echo
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
    # Usage: prompt_yesno "Question" [default: y/n]
    local question="$1" default="${2:-y}"
    local yn
    if [[ "$default" == "y" ]]; then
        echo -en "  ${BOLD}${question}${RESET} ${DIM}[Y/n]${RESET}: "
    else
        echo -en "  ${BOLD}${question}${RESET} ${DIM}[y/N]${RESET}: "
    fi
    read -r yn
    yn="${yn:-$default}"
    [[ "${yn,,}" == "y" || "${yn,,}" == "yes" ]]
}

# =============================================================================
# CLEANUP TRAP
# =============================================================================
CLEANUP_CTID=""
CLEANUP_TYPE=""
CLEANUP_FILES=()

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 && -n "$CLEANUP_CTID" ]]; then
        echo
        warn "Script failed (exit $exit_code). Cleaning up..."
        if [[ "$CLEANUP_TYPE" == "lxc" ]]; then
            pct stop "$CLEANUP_CTID" 2>/dev/null || true
            pct destroy "$CLEANUP_CTID" 2>/dev/null || true
        elif [[ "$CLEANUP_TYPE" == "vm" ]]; then
            qm stop "$CLEANUP_CTID" 2>/dev/null || true
            qm destroy "$CLEANUP_CTID" --purge 2>/dev/null || true
        fi
        ok "Cleaned up partial ${CLEANUP_TYPE^^} ${CLEANUP_CTID}"
    fi
    for f in "${CLEANUP_FILES[@]}"; do
        rm -f "$f" 2>/dev/null || true
    done
    rm -f "$PROVISION_LOG" 2>/dev/null || true
}
trap cleanup EXIT

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
    for tool in curl openssl pvesh pct qm pveam; do
        if ! command -v "$tool" &>/dev/null; then
            err "Required tool '${tool}' not found."
            exit 1
        fi
    done
    ok "All required tools available"
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

get_next_free_id() {
    pvesh get /cluster/nextid 2>/dev/null || echo "100"
}

validate_id() {
    local id="$1"
    # Proxmox supports IDs 100–999999999
    [[ "$id" =~ ^[0-9]+$ ]] || return 1
    (( id >= 100 && id <= 999999999 )) || return 1
    # Check it's not already in use by a VM or LXC
    [[ ! -f "/etc/pve/qemu-server/${id}.conf" ]] || return 1
    [[ ! -f "/etc/pve/lxc/${id}.conf" ]] || return 1
    # Also check LVM volumes
    if command -v lvs &>/dev/null; then
        if lvs --noheadings -o lv_name 2>/dev/null | grep -qE "(^|[-_])${id}($|[-_])"; then
            return 1
        fi
    fi
    return 0
}

generate_password() {
    openssl rand -base64 16 | tr -d '=/+' | head -c 20
}

hash_password() {
    # SHA-512 hash for cloud-init / chpasswd
    openssl passwd -6 "$1"
}

detect_storage() {
    # Find active storage backends for a given content type.
    # Returns newline-separated list, or exits on failure.
    local content_type="$1"
    local storages
    storages=$(pvesm status -content "$content_type" 2>/dev/null \
        | awk 'NR>1 && $3=="active" {print $1}')

    # Guard against empty result
    if [[ -z "${storages// /}" ]]; then
        err "No active storage found for content type '${content_type}'."
        exit 1
    fi

    echo "$storages"
}

select_storage() {
    local content_type="$1" label="$2"
    local storages
    storages=$(detect_storage "$content_type")
    local count
    count=$(echo "$storages" | wc -l)

    if [[ "$count" -eq 1 ]]; then
        echo "$storages"
        return
    fi

    echo
    info "Multiple storage backends available for ${label}:"
    local i=1
    while IFS= read -r s; do
        # pvesm status columns: Name  Type  Status  Total  Used  Available  %
        # We want column 6 (Available) which is in bytes
        local avail_bytes
        avail_bytes=$(pvesm status -content "$content_type" \
            | awk -v st="$s" '$1==st {print $6}')
        local avail_human
        avail_human=$(awk "BEGIN {printf \"%.1f GiB\", ${avail_bytes:-0}/1073741824}" 2>/dev/null || echo "? GiB")
        echo -e "    ${BOLD}${i})${RESET} ${s} ${DIM}(${avail_human} free)${RESET}"
        ((i++))
    done <<< "$storages"

    local choice
    prompt "Select storage for ${label} (1-$((i-1)))" "1" choice
    echo "$storages" | sed -n "${choice}p"
}

fetch_github_keys() {
    local username="$1"
    local keys
    keys=$(curl -fsSL --connect-timeout 10 --max-time 15 \
        "https://github.com/${username}.keys" 2>/dev/null || true)
    if [[ -z "$keys" ]]; then
        warn "No SSH keys found for GitHub user '${username}'"
        return 1
    fi
    # Validate they look like SSH keys
    if ! echo "$keys" | head -1 | grep -qE '^(ssh-|ecdsa-|sk-)'; then
        warn "Response doesn't look like SSH keys for '${username}'"
        return 1
    fi
    echo "$keys"
}

wait_for_network() {
    # Wait for an LXC container to have network connectivity
    local id="$1" max_wait="${2:-30}"
    local elapsed=0

    info "Waiting for guest networking..."
    while (( elapsed < max_wait )); do
        local ip
        ip=$(pct exec "$id" -- hostname -I 2>/dev/null | awk '{print $1}') || true
        if [[ -n "$ip" && "$ip" != "127.0.0.1" ]]; then
            ok "Guest network ready: ${ip}"
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

# =============================================================================
# COLLECT USER INPUT
# =============================================================================

declare PROV_TYPE PROV_OS PROV_ID PROV_HOSTNAME PROV_CPU PROV_RAM PROV_DISK
declare PROV_BRIDGE PROV_DISK_STORAGE PROV_TPL_STORAGE
declare PROV_OPT_BTOP PROV_OPT_GIT PROV_OPT_GH
declare PROV_SYSADMIN_PW PROV_GITHUB_USER PROV_SSH_KEYS
declare PROV_ROOT_PW

collect_input() {
    header "Provisioning Configuration"

    # --- Type ---
    divider
    echo -e "  ${BOLD}Guest Type${RESET}"
    echo -e "    1) LXC Container ${DIM}(lightweight, shared kernel)${RESET}"
    echo -e "    2) Virtual Machine ${DIM}(full isolation, own kernel)${RESET}"
    local type_choice
    prompt "Select type" "1" type_choice
    case "$type_choice" in
        1|lxc)  PROV_TYPE="lxc" ;;
        2|vm)   PROV_TYPE="vm" ;;
        *)      err "Invalid type. Use 1 or 2."; exit 1 ;;
    esac
    ok "Type: ${PROV_TYPE^^}"

    # --- OS ---
    divider
    echo -e "  ${BOLD}Operating System${RESET}"
    echo -e "    1) Debian 13 (Trixie)"
    echo -e "    2) Debian 12 (Bookworm)"
    echo -e "    3) Ubuntu 24.04 LTS (Noble)"
    echo -e "    4) Ubuntu 25.04 (Plucky) ${DIM}— non-LTS, EOL Jan 2026${RESET}"
    local os_choice
    prompt "Select OS" "1" os_choice
    case "$os_choice" in
        1) PROV_OS="debian-13" ;;
        2) PROV_OS="debian-12" ;;
        3) PROV_OS="ubuntu-24.04" ;;
        4) PROV_OS="ubuntu-25.04" ;;
        *) err "Invalid OS choice."; exit 1 ;;
    esac
    ok "OS: ${OS_NAMES[$PROV_OS]}"

    # --- ID ---
    divider
    local suggested_id
    suggested_id=$(get_next_free_id)
    while true; do
        prompt "Guest ID (100+)" "$suggested_id" PROV_ID
        if validate_id "$PROV_ID"; then
            break
        fi
        warn "ID ${PROV_ID} is invalid or already in use. Try another."
    done
    ok "ID: ${PROV_ID}"

    # --- Hostname ---
    divider
    prompt "Hostname" "$DEFAULT_HOSTNAME" PROV_HOSTNAME
    PROV_HOSTNAME=$(echo "${PROV_HOSTNAME,,}" | tr -d ' ')
    ok "Hostname: ${PROV_HOSTNAME}"

    # --- Resources ---
    divider
    prompt "CPU cores" "$DEFAULT_CPU" PROV_CPU
    prompt "RAM (GB)" "$DEFAULT_RAM" PROV_RAM
    prompt "Disk size (GB)" "$DEFAULT_DISK" PROV_DISK
    ok "Resources: ${PROV_CPU} CPU / ${PROV_RAM}GB RAM / ${PROV_DISK}GB Disk"

    # --- Network ---
    divider
    prompt "Network bridge" "$DEFAULT_BRIDGE" PROV_BRIDGE
    ok "Bridge: ${PROV_BRIDGE}"

    # --- Storage ---
    divider
    if [[ "$PROV_TYPE" == "lxc" ]]; then
        PROV_TPL_STORAGE=$(select_storage "vztmpl" "templates")
        PROV_DISK_STORAGE=$(select_storage "rootdir" "container rootfs")
    else
        # For VMs: cloud images are downloaded to a local cache dir, not managed
        # by Proxmox storage content types. We only need disk storage for the VM.
        PROV_TPL_STORAGE=""
        PROV_DISK_STORAGE=$(select_storage "images" "VM disks")
    fi
    if [[ -n "$PROV_TPL_STORAGE" ]]; then
        ok "Template storage: ${PROV_TPL_STORAGE}"
    fi
    ok "Disk storage: ${PROV_DISK_STORAGE}"

    # --- Optional Packages ---
    header "Optional Packages"
    PROV_OPT_BTOP="n"
    PROV_OPT_GIT="n"
    PROV_OPT_GH="n"
    prompt_yesno "Install btop (system monitor)?" "y" && PROV_OPT_BTOP="y"
    prompt_yesno "Install git?" "y" && PROV_OPT_GIT="y"
    prompt_yesno "Install GitHub CLI (gh)?" "n" && PROV_OPT_GH="y"

    # --- User Configuration ---
    header "User Configuration"
    info "Root will get a random password (stored in Proxmox notes)"
    PROV_ROOT_PW=$(generate_password)
    ok "Root password generated"

    divider
    info "Creating 'sysadmin' user with sudo access"
    prompt_secret "Set sysadmin password" PROV_SYSADMIN_PW

    divider
    PROV_GITHUB_USER=""
    PROV_SSH_KEYS=""
    if prompt_yesno "Import SSH keys from GitHub?" "y"; then
        prompt "GitHub username" "" PROV_GITHUB_USER
        if [[ -n "$PROV_GITHUB_USER" ]]; then
            PROV_SSH_KEYS=$(fetch_github_keys "$PROV_GITHUB_USER") || true
            if [[ -n "$PROV_SSH_KEYS" ]]; then
                local key_count
                key_count=$(echo "$PROV_SSH_KEYS" | wc -l)
                ok "Fetched ${key_count} SSH key(s) from github.com/${PROV_GITHUB_USER}"
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
    echo -e "  ${BOLD}RAM:${RESET}         ${PROV_RAM} GB"
    echo -e "  ${BOLD}Disk:${RESET}        ${PROV_DISK} GB"
    echo -e "  ${BOLD}Bridge:${RESET}      ${PROV_BRIDGE}"
    echo -e "  ${BOLD}Disk Store:${RESET}  ${PROV_DISK_STORAGE}"
    echo -e "  ${BOLD}Root PW:${RESET}     ${DIM}(random — stored in notes)${RESET}"
    echo -e "  ${BOLD}sysadmin:${RESET}    password auth + sudo"
    [[ -n "$PROV_SSH_KEYS" ]] && echo -e "  ${BOLD}SSH Keys:${RESET}    from github.com/${PROV_GITHUB_USER}"

    local pkgs="$BASE_PACKAGES"
    [[ "$PROV_TYPE" == "vm" ]] && pkgs+=" ${VM_EXTRA_PACKAGES}"
    [[ "$PROV_OPT_BTOP" == "y" ]] && pkgs+=" btop"
    [[ "$PROV_OPT_GIT" == "y" ]] && pkgs+=" git"
    [[ "$PROV_OPT_GH" == "y" ]] && pkgs+=" gh"
    echo -e "  ${BOLD}Packages:${RESET}    ${DIM}${pkgs}${RESET}"
    echo

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

    case "$os" in
        debian-13)    search_term="debian-13-standard" ;;
        debian-12)    search_term="debian-12-standard" ;;
        ubuntu-24.04) search_term="ubuntu-24.04-standard" ;;
        ubuntu-25.04) search_term="ubuntu-25.04-standard" ;;
    esac

    # Check if already downloaded
    local local_template
    local_template=$(pveam list "$storage" 2>/dev/null \
        | grep "$search_term" | sort -V | tail -1 | awk '{print $1}') || true

    if [[ -n "$local_template" ]]; then
        echo "$local_template"
        return
    fi

    # Find available template online
    local available
    available=$(pveam available --section system 2>/dev/null \
        | grep "$search_term" | sort -V | tail -1 | awk '{print $2}') || true

    if [[ -z "$available" ]]; then
        err "No template found for ${OS_NAMES[$os]}."
        err "Check: pveam available --section system | grep '${search_term}'"
        exit 1
    fi

    info "Downloading template: ${available}"
    pveam download "$storage" "$available" || {
        err "Template download failed."
        exit 1
    }

    echo "${storage}:vztmpl/${available}"
}

create_lxc() {
    header "Creating LXC Container"

    local template
    template=$(find_lxc_template "$PROV_OS" "$PROV_TPL_STORAGE")
    ok "Template: ${template}"

    local ram_mb=$(( PROV_RAM * 1024 ))

    info "Creating container ${PROV_ID}..."
    CLEANUP_CTID="$PROV_ID"
    CLEANUP_TYPE="lxc"

    pct create "$PROV_ID" "$template" \
        --hostname "$PROV_HOSTNAME" \
        --cores "$PROV_CPU" \
        --memory "$ram_mb" \
        --rootfs "${PROV_DISK_STORAGE}:${PROV_DISK}" \
        --net0 "name=eth0,bridge=${PROV_BRIDGE},ip=dhcp" \
        --unprivileged 1 \
        --features "nesting=1" \
        --onboot 0 \
        --start 0 \
        --password "$PROV_ROOT_PW"

    ok "Container created"

    info "Starting container..."
    pct start "$PROV_ID"
    ok "Container started"

    # Wait for networking
    sleep 3
    local guest_ip
    guest_ip=$(wait_for_network "$PROV_ID" 30)

    configure_lxc_guest "$PROV_ID" "$guest_ip"
}

configure_lxc_guest() {
    local id="$1" ip="$2"

    header "Configuring LXC Guest"

    # Build package list
    local packages="$BASE_PACKAGES"
    [[ "$PROV_OPT_BTOP" == "y" ]] && packages+=" btop"
    [[ "$PROV_OPT_GIT" == "y" ]] && packages+=" git"

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

    # SSH configuration
    info "Configuring SSH..."
    lxc_exec "$id" "SSH configuration" '
        systemctl enable ssh 2>/dev/null || systemctl enable sshd 2>/dev/null || true
        systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true
        sed -i "s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config
        sed -i "s/^#\?PermitRootLogin.*/PermitRootLogin no/" /etc/ssh/sshd_config
        systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
    '
    ok "SSH configured (password auth enabled, root login disabled)"

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
    final_ip=$(pct exec "$id" -- hostname -I 2>/dev/null | awk '{print $1}') || final_ip="$ip"

    # Set notes
    local notes_html
    notes_html=$(generate_notes_html "$final_ip")
    pct set "$id" --description "$notes_html"
    ok "Proxmox notes updated"

    # Done!
    print_summary "$final_ip"
}

# =============================================================================
# VM CREATION
# =============================================================================
download_cloud_image() {
    local os="$1"
    local url="${CLOUD_IMAGES[$os]}"
    local filename
    filename=$(basename "$url")
    local filepath="${CLOUD_IMG_DIR}/${filename}"

    mkdir -p "$CLOUD_IMG_DIR"

    if [[ -f "$filepath" ]]; then
        ok "Cloud image cached: ${filename}"
        echo "$filepath"
        return
    fi

    info "Downloading cloud image: ${filename}"
    info "URL: ${url}"
    curl -fL --progress-bar \
        --connect-timeout 15 \
        --max-time 900 \
        -o "$filepath" "$url" || {
        rm -f "$filepath"
        err "Cloud image download failed."
        exit 1
    }
    ok "Cloud image downloaded"
    echo "$filepath"
}

create_vm() {
    header "Creating Virtual Machine"

    local image_path
    image_path=$(download_cloud_image "$PROV_OS")

    local ram_mb=$(( PROV_RAM * 1024 ))

    info "Creating VM ${PROV_ID}..."
    CLEANUP_CTID="$PROV_ID"
    CLEANUP_TYPE="vm"

    # Create the VM shell with modern settings
    qm create "$PROV_ID" \
        --name "$PROV_HOSTNAME" \
        --cores "$PROV_CPU" \
        --memory "$ram_mb" \
        --net0 "virtio,bridge=${PROV_BRIDGE}" \
        --scsihw virtio-scsi-single \
        --bios ovmf \
        --machine q35 \
        --efidisk0 "${PROV_DISK_STORAGE}:0,efitype=4m" \
        --agent 1 \
        --onboot 0 \
        --ostype l26
    ok "VM shell created"

    # Import the cloud image as the boot disk
    info "Importing cloud image to disk..."
    qm set "$PROV_ID" --scsi0 "${PROV_DISK_STORAGE}:0,import-from=${image_path}"
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
    mkdir -p /var/lib/vz/snippets

    # Generate and install custom cloud-init user-data
    local snippet_file="pve-provision-${PROV_ID}-userdata.yml"
    local snippet_path="/var/lib/vz/snippets/${snippet_file}"
    CLEANUP_FILES+=("$snippet_path")

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

    info "Waiting for cloud-init + guest agent (this may take 1-3 minutes)..."
    local elapsed=0
    local max_wait=180
    local guest_ip="pending"

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
        sleep 5
        (( elapsed += 5 ))
        echo -en "\r  ⏳  Waiting... (${elapsed}s / ${max_wait}s)  "
    done
    echo

    if [[ "$guest_ip" == "pending" ]]; then
        warn "Could not detect IP via guest agent after ${max_wait}s."
        warn "Possible causes:"
        warn "  - cloud-init still running (give it another minute)"
        warn "  - qemu-guest-agent failed to install (check VM console)"
        warn "  - DHCP not responding on bridge ${PROV_BRIDGE}"
        warn "Debug: qm guest cmd ${PROV_ID} network-get-interfaces"
    fi

    # Set notes
    local notes_html
    notes_html=$(generate_notes_html "$guest_ip")
    qm set "$PROV_ID" --description "$notes_html"
    ok "Proxmox notes updated"

    # Background cleanup: wait for cloud-init to finish, then delete the snippet
    info "Cloud-init snippet will be auto-deleted after boot completes."
    (
        sleep 10
        for _attempt in $(seq 1 36); do  # 36 x 10s = 6 min max
            if qm guest cmd "$PROV_ID" exec -- test -f /var/lib/cloud/instance/boot-finished 2>/dev/null; then
                rm -f "$snippet_path" 2>/dev/null
                break
            fi
            sleep 10
        done
        # If timed out, remove anyway — cloud-init has had its chance
        rm -f "$snippet_path" 2>/dev/null || true
    ) &
    disown

    print_summary "$guest_ip"
}

generate_cloudinit_userdata() {
    local root_hash sysadmin_hash
    root_hash=$(hash_password "$PROV_ROOT_PW")
    sysadmin_hash=$(hash_password "$PROV_SYSADMIN_PW")

    # Build package list
    local pkg_list="  - util-linux
  - curl
  - wget
  - net-tools
  - sudo
  - openssh-server
  - nano
  - qemu-guest-agent"
    [[ "$PROV_OPT_BTOP" == "y" ]] && pkg_list+="
  - btop"
    [[ "$PROV_OPT_GIT" == "y" ]] && pkg_list+="
  - git"

    # Build SSH keys block for sysadmin user
    local ssh_keys_block=""
    if [[ -n "$PROV_SSH_KEYS" ]]; then
        ssh_keys_block="    ssh_authorized_keys:"
        while IFS= read -r key; do
            ssh_keys_block+="
      - ${key}"
        done <<< "$PROV_SSH_KEYS"
    fi

    # Build gh-cli runcmd block
    local gh_runcmd=""
    if [[ "$PROV_OPT_GH" == "y" ]]; then
        gh_runcmd="
  - mkdir -p -m 755 /etc/apt/keyrings
  - curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
  - chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
  - echo \"deb [arch=\$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main\" > /etc/apt/sources.list.d/github-cli.list
  - apt-get update -qq
  - DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${APT_OPTS} gh"
    fi

    cat <<CLOUDINIT
#cloud-config
hostname: ${PROV_HOSTNAME}
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

packages:
${pkg_list}

ssh_pwauth: true

runcmd:
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent
  - sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
  - systemctl restart ssh || systemctl restart sshd || true${gh_runcmd}
  - apt-get clean

final_message: "pve-provision: cloud-init complete after \$UPTIME seconds"
CLOUDINIT
}

# =============================================================================
# HTML NOTES FOR PROXMOX
# =============================================================================
generate_notes_html() {
    local ip="${1:-pending}"
    local created_at
    created_at=$(date -u '+%Y-%m-%d %H:%M UTC')
    local type_label
    [[ "$PROV_TYPE" == "lxc" ]] && type_label="LXC Container" || type_label="Virtual Machine"

    # Build package list for display
    local pkg_display="util-linux, curl, wget, net-tools, sudo, ssh, nano"
    [[ "$PROV_TYPE" == "vm" ]] && pkg_display+=", qemu-guest-agent"
    [[ "$PROV_OPT_BTOP" == "y" ]] && pkg_display+=", btop"
    [[ "$PROV_OPT_GIT" == "y" ]] && pkg_display+=", git"
    [[ "$PROV_OPT_GH" == "y" ]] && pkg_display+=", gh"

    local ssh_info="Password authentication"
    [[ -n "$PROV_SSH_KEYS" ]] && ssh_info="Password + SSH keys (github.com/${PROV_GITHUB_USER})"

    cat <<'HTMLEOF'
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 600px; margin: 0 auto; color: #1a1a2e;">
HTMLEOF

    cat <<HTMLEOF
  <!-- Header -->
  <div style="background: linear-gradient(135deg, #0f3460 0%, #16213e 100%); border-radius: 10px 10px 0 0; padding: 20px; text-align: center;">
    <h2 style="color: #e0e0e0; margin: 0 0 4px 0; font-size: 20px;">⚙️ ${PROV_HOSTNAME}</h2>
    <span style="color: #94a3b8; font-size: 13px;">${type_label} · ${OS_NAMES[$PROV_OS]} · ID ${PROV_ID}</span>
  </div>

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
          <strong>sysadmin</strong>
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

    header "Provisioning Complete! 🎉"
    echo -e "  ${BOLD}${PROV_TYPE^^} ${PROV_ID}${RESET} — ${OS_NAMES[$PROV_OS]}"
    echo -e "  ${BOLD}Hostname:${RESET}    ${PROV_HOSTNAME}"
    echo -e "  ${BOLD}IP:${RESET}          ${ip}"
    echo
    echo -e "  ${BOLD}Connect:${RESET}     ${GREEN}ssh sysadmin@${ip}${RESET}"
    echo -e "  ${BOLD}Root PW:${RESET}     ${DIM}${PROV_ROOT_PW}${RESET} ${DIM}(also in Proxmox notes)${RESET}"
    echo
    divider
    echo -e "  ${DIM}Full details stored in the Proxmox notes tab for this guest.${RESET}"
    echo

    # Clear cleanup trap — we succeeded
    CLEANUP_CTID=""
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    clear
    echo -e "${BOLD}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║        Proxmox VE Guest Provisioner          ║"
    echo "  ║          pve-provision.sh v${SCRIPT_VERSION}               ║"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"

    preflight
    collect_input
    confirm_settings

    if [[ "$PROV_TYPE" == "lxc" ]]; then
        create_lxc
    else
        create_vm
    fi
}

main "$@"
