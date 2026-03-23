#!/usr/bin/env bash
# =============================================================================
# audit_ubuntu_config.sh
# Comprehensive Ubuntu 22.04 configuration audit script
#
# Usage: sudo ./audit_ubuntu_config.sh
# Output: ubuntu_config_audit_YYYY-MM-DD.csv
#
# Detects deviations from stock Ubuntu 22.04 across 12 categories:
#   1. Network Configuration
#   2. Kernel and Boot
#   3. Storage and Filesystems
#   4. GPU and Hardware Drivers
#   5. Services and Daemons
#   6. Package Management
#   7. User Environment and Shell
#   8. Programming Languages and Runtimes
#   9. Security Configuration
#  10. Containerization and Virtualization
#  11. System Configuration Files
#  12. Desktop Environment
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Constants and globals
# ---------------------------------------------------------------------------
SCRIPT_VERSION="1.0.0"
DATE_TAG="$(date +%Y-%m-%d)"
OUTPUT_CSV="ubuntu_config_audit_${DATE_TAG}.csv"
LOG_FILE="/tmp/audit_ubuntu_config_${DATE_TAG}.log"

# Category counters (associative array)
declare -A CATEGORY_COUNTS
CATEGORIES=(
    "Network Configuration"
    "Kernel and Boot"
    "Storage and Filesystems"
    "GPU and Hardware Drivers"
    "Services and Daemons"
    "Package Management"
    "User Environment and Shell"
    "Programming Languages and Runtimes"
    "Security Configuration"
    "Containerization and Virtualization"
    "System Configuration Files"
    "Desktop Environment"
)
for cat in "${CATEGORIES[@]}"; do
    CATEGORY_COUNTS["$cat"]=0
done

TOTAL_CHANGES=0

# ---------------------------------------------------------------------------
# Color codes for terminal output
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $*"
    log "INFO: $*"
}

section() {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  $*${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════${NC}"
    log "SECTION: $*"
}

found() {
    echo -e "  ${YELLOW}[FOUND]${NC} $*"
    log "FOUND: $*"
}

ok() {
    echo -e "  ${GREEN}[OK]${NC} $*"
}

warn() {
    echo -e "  ${RED}[WARN]${NC} $*"
    log "WARN: $*"
}

# Escape a value for CSV: wrap in quotes, double any embedded quotes
csv_escape() {
    local val="$1"
    # Replace " with ""
    val="${val//\"/\"\"}"
    echo "\"${val}\""
}

# Write one row to the CSV output file and increment counters
write_csv() {
    local category="$1"
    local file_loc="$2"
    local detail="$3"
    local current_val="$4"
    local default_val="$5"

    local row
    row="$(csv_escape "$category"),$(csv_escape "$file_loc"),$(csv_escape "$detail"),$(csv_escape "$current_val"),$(csv_escape "$default_val")"
    echo "$row" >> "$OUTPUT_CSV"

    CATEGORY_COUNTS["$category"]=$(( ${CATEGORY_COUNTS["$category"]:-0} + 1 ))
    TOTAL_CHANGES=$(( TOTAL_CHANGES + 1 ))
    found "$category | $file_loc | $detail"
}

# Check if a command exists
cmd_exists() {
    command -v "$1" &>/dev/null
}

# Run a command and return its output, or empty string on failure
safe_run() {
    "$@" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Initialise CSV with header
# ---------------------------------------------------------------------------
init_csv() {
    echo '"Category","File/Location","Detail","Current Value","Default/Expected Value"' > "$OUTPUT_CSV"
    log "CSV initialised: $OUTPUT_CSV"
}

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
preflight_checks() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root (or with sudo).${NC}" >&2
        exit 1
    fi

    info "Script version   : $SCRIPT_VERSION"
    info "Output CSV       : $OUTPUT_CSV"
    info "Log file         : $LOG_FILE"
    info "Audit started at : $(date)"

    # Detect Ubuntu 22.04
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        info "OS detected      : $PRETTY_NAME"
        if [[ "${VERSION_ID:-}" != "22.04" ]]; then
            warn "This script is designed for Ubuntu 22.04 — results on other versions may be inaccurate."
        fi
    fi
}

# ===========================================================================
# CATEGORY 1: Network Configuration
# ===========================================================================
audit_network() {
    section "1. Network Configuration"

    # --- MTU settings ---
    info "Checking interface MTU settings..."
    if cmd_exists ip; then
        while IFS= read -r line; do
            iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
            mtu=$(echo "$line" | grep -oP 'mtu \K[0-9]+' || true)
            [[ -z "$mtu" ]] && continue
            if [[ "$mtu" != "1500" && "$mtu" != "65536" ]]; then
                write_csv "Network Configuration" \
                    "ip link / interface $iface" \
                    "Non-standard MTU on interface $iface" \
                    "$mtu" "1500 (Ethernet default)"
            fi
        done < <(ip link show 2>/dev/null | grep -P '^\d+:')
    fi

    # --- DNS / systemd-resolved ---
    info "Checking DNS configuration..."
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        ok "systemd-resolved is active (default)."
    else
        write_csv "Network Configuration" \
            "/etc/systemd/resolved.conf" \
            "systemd-resolved is not active (may be replaced by dnsmasq/unbound/NetworkManager)" \
            "inactive" "active"
    fi

    # dnsmasq
    if cmd_exists dnsmasq && systemctl is-enabled --quiet dnsmasq 2>/dev/null; then
        local ver; ver=$(dnsmasq --version 2>/dev/null | head -1 || echo "unknown")
        write_csv "Network Configuration" \
            "/etc/dnsmasq.conf" \
            "dnsmasq is installed and enabled as DNS resolver" \
            "$ver" "Not installed (stock Ubuntu uses systemd-resolved)"
    fi

    # unbound
    if cmd_exists unbound && systemctl is-enabled --quiet unbound 2>/dev/null; then
        write_csv "Network Configuration" \
            "/etc/unbound/unbound.conf" \
            "unbound is installed and enabled as DNS resolver" \
            "enabled" "Not installed"
    fi

    # /etc/resolv.conf — check if it's a custom file (not a symlink to systemd-resolved stub)
    if [[ -e /etc/resolv.conf ]]; then
        local rc_target; rc_target=$(readlink -f /etc/resolv.conf 2>/dev/null || echo "/etc/resolv.conf")
        if [[ "$rc_target" != "/run/systemd/resolve/stub-resolv.conf" && \
              "$rc_target" != "/run/systemd/resolve/resolv.conf" ]]; then
            local rc_content; rc_content=$(cat /etc/resolv.conf 2>/dev/null | tr '\n' ';')
            write_csv "Network Configuration" \
                "/etc/resolv.conf" \
                "resolv.conf is not pointing to systemd-resolved stub (custom DNS config)" \
                "$rc_target" "/run/systemd/resolve/stub-resolv.conf"
        fi
    fi

    # --- Netplan customisations ---
    info "Checking Netplan configurations..."
    local netplan_dir="/etc/netplan"
    if [[ -d "$netplan_dir" ]]; then
        while IFS= read -r f; do
            local content; content=$(cat "$f" 2>/dev/null | tr '\n' ' ')
            # Flag static IP addresses
            if grep -qP 'addresses:|dhcp4:\s*false|dhcp4:\s*no' "$f" 2>/dev/null; then
                write_csv "Network Configuration" \
                    "$f" \
                    "Netplan file contains static IP assignment or disabled DHCP" \
                    "$content" "DHCP-based configuration"
            fi
            # Flag custom nameservers
            if grep -q 'nameservers:' "$f" 2>/dev/null; then
                write_csv "Network Configuration" \
                    "$f" \
                    "Netplan file specifies custom DNS nameservers" \
                    "$content" "Default (systemd-resolved)"
            fi
            # Flag bonding/bridging/VLANs
            for keyword in bonds bridges vlans tunnels; do
                if grep -q "^${keyword}:" "$f" 2>/dev/null; then
                    write_csv "Network Configuration" \
                        "$f" \
                        "Netplan file configures $keyword" \
                        "$content" "No $keyword (stock)"
                fi
            done
            # Flag custom routes
            if grep -q 'routes:' "$f" 2>/dev/null; then
                write_csv "Network Configuration" \
                    "$f" \
                    "Netplan file contains custom static routes" \
                    "$content" "No custom routes (stock)"
            fi
        done < <(find "$netplan_dir" -maxdepth 2 -name '*.yaml' -o -name '*.yml' 2>/dev/null)
    fi

    # Legacy /etc/network/interfaces
    if [[ -f /etc/network/interfaces ]]; then
        local ni_content; ni_content=$(grep -v '^#\|^$' /etc/network/interfaces 2>/dev/null | tr '\n' ';')
        if [[ -n "$ni_content" && "$ni_content" != *"source"* ]] || \
           grep -qP '(iface|auto)\s+(?!lo)' /etc/network/interfaces 2>/dev/null; then
            write_csv "Network Configuration" \
                "/etc/network/interfaces" \
                "Legacy /etc/network/interfaces contains custom network configuration" \
                "$ni_content" "Minimal/empty (Ubuntu 22.04 uses Netplan)"
        fi
    fi

    # --- iptables / nftables rules ---
    info "Checking firewall rules (iptables/nftables)..."
    if cmd_exists iptables; then
        local ipt_rules; ipt_rules=$(iptables-save 2>/dev/null | grep -v '^#\|^:.*\[0:0\]' | grep -v '^\*\|^COMMIT' | wc -l)
        if [[ "$ipt_rules" -gt 0 ]]; then
            local ipt_summary; ipt_summary=$(iptables-save 2>/dev/null | grep -v '^#' | head -30 | tr '\n' ';')
            write_csv "Network Configuration" \
                "iptables (kernel)" \
                "Custom iptables rules are present ($ipt_rules non-default rule lines)" \
                "$ipt_summary" "No custom iptables rules (stock)"
        fi
    fi

    if cmd_exists nft; then
        local nft_rules; nft_rules=$(nft list ruleset 2>/dev/null | grep -v '^#' | wc -l)
        if [[ "$nft_rules" -gt 2 ]]; then
            local nft_summary; nft_summary=$(nft list ruleset 2>/dev/null | head -20 | tr '\n' ';')
            write_csv "Network Configuration" \
                "nftables (kernel)" \
                "Custom nftables ruleset present ($nft_rules lines)" \
                "$nft_summary" "No custom nftables rules (stock)"
        fi
    fi

    # --- sysctl net.* parameters ---
    info "Checking sysctl net.* parameters..."
    # Known Ubuntu 22.04 defaults for commonly changed net params
    declare -A NET_DEFAULTS=(
        ["net.core.rmem_max"]="212992"
        ["net.core.wmem_max"]="212992"
        ["net.core.rmem_default"]="212992"
        ["net.core.wmem_default"]="212992"
        ["net.core.netdev_max_backlog"]="1000"
        ["net.core.somaxconn"]="4096"
        ["net.ipv4.tcp_rmem"]="4096 131072 6291456"
        ["net.ipv4.tcp_wmem"]="4096 16384 4194304"
        ["net.ipv4.tcp_max_syn_backlog"]="512"
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_fin_timeout"]="60"
        ["net.ipv4.tcp_keepalive_time"]="7200"
        ["net.ipv4.tcp_keepalive_intvl"]="75"
        ["net.ipv4.tcp_keepalive_probes"]="9"
        ["net.ipv4.conf.all.accept_redirects"]="1"
        ["net.ipv4.conf.all.send_redirects"]="1"
        ["net.ipv6.conf.all.forwarding"]="0"
        ["net.ipv6.conf.all.accept_redirects"]="1"
    )
    for key in "${!NET_DEFAULTS[@]}"; do
        local cur; cur=$(sysctl -n "$key" 2>/dev/null || true)
        [[ -z "$cur" ]] && continue
        # normalise whitespace
        cur=$(echo "$cur" | tr -s ' ')
        local def="${NET_DEFAULTS[$key]}"
        if [[ "$cur" != "$def" ]]; then
            write_csv "Network Configuration" \
                "sysctl $key" \
                "TCP/UDP/network sysctl parameter differs from Ubuntu 22.04 default" \
                "$cur" "$def"
        fi
    done

    # Check for any net.* overrides in /etc/sysctl.conf and /etc/sysctl.d/
    local sysctl_files=()
    [[ -f /etc/sysctl.conf ]] && sysctl_files+=("/etc/sysctl.conf")
    while IFS= read -r f; do sysctl_files+=("$f"); done < <(find /etc/sysctl.d -name '*.conf' 2>/dev/null | sort)
    for sf in "${sysctl_files[@]}"; do
        if grep -qP '^net\.' "$sf" 2>/dev/null; then
            local net_lines; net_lines=$(grep -P '^net\.' "$sf" | tr '\n' ';')
            write_csv "Network Configuration" \
                "$sf" \
                "sysctl file contains net.* overrides" \
                "$net_lines" "(none in stock Ubuntu)"
        fi
    done
}

# ===========================================================================
# CATEGORY 2: Kernel and Boot
# ===========================================================================
audit_kernel_boot() {
    section "2. Kernel and Boot"

    # --- GRUB customisations ---
    info "Checking GRUB configuration..."
    local grub_default="/etc/default/grub"
    if [[ -f "$grub_default" ]]; then
        # GRUB_CMDLINE_LINUX
        local cmdline; cmdline=$(grep -P '^GRUB_CMDLINE_LINUX=' "$grub_default" | head -1 || true)
        if [[ -n "$cmdline" ]]; then
            local val; val=$(echo "$cmdline" | sed 's/GRUB_CMDLINE_LINUX=//' | tr -d '"')
            if [[ -n "$val" ]]; then
                write_csv "Kernel and Boot" \
                    "$grub_default" \
                    "GRUB_CMDLINE_LINUX contains custom kernel parameters" \
                    "$val" "(empty — stock Ubuntu 22.04)"
            fi
        fi
        # GRUB_CMDLINE_LINUX_DEFAULT
        local cmdline_def; cmdline_def=$(grep -P '^GRUB_CMDLINE_LINUX_DEFAULT=' "$grub_default" | head -1 || true)
        if [[ -n "$cmdline_def" ]]; then
            local cval; cval=$(echo "$cmdline_def" | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=//' | tr -d '"')
            if [[ "$cval" != "quiet splash" && -n "$cval" ]]; then
                write_csv "Kernel and Boot" \
                    "$grub_default" \
                    "GRUB_CMDLINE_LINUX_DEFAULT differs from default" \
                    "$cval" "quiet splash"
            fi
        fi
        # GRUB_TIMEOUT
        local timeout; timeout=$(grep -P '^GRUB_TIMEOUT=' "$grub_default" | head -1 || true)
        if [[ -n "$timeout" ]]; then
            local tval; tval=$(echo "$timeout" | cut -d= -f2)
            if [[ "$tval" != "0" && "$tval" != "5" && "$tval" != "\"0\"" && "$tval" != "\"5\"" ]]; then
                write_csv "Kernel and Boot" \
                    "$grub_default" \
                    "GRUB_TIMEOUT differs from default" \
                    "$tval" "0 or 5"
            fi
        fi
        # Any other non-default/non-comment overrides
        local other_overrides; other_overrides=$(grep -P '^[A-Z_]+=' "$grub_default" | grep -vP '^(GRUB_DEFAULT|GRUB_TIMEOUT|GRUB_DISTRIBUTOR|GRUB_CMDLINE_LINUX|GRUB_CMDLINE_LINUX_DEFAULT|GRUB_TERMINAL)=' || true)
        if [[ -n "$other_overrides" ]]; then
            write_csv "Kernel and Boot" \
                "$grub_default" \
                "Additional non-default GRUB settings detected" \
                "$(echo "$other_overrides" | tr '\n' ';')" "(stock Ubuntu 22.04 defaults)"
        fi
    fi

    # Custom grub.d snippets
    if [[ -d /etc/grub.d ]]; then
        while IFS= read -r f; do
            local bname; bname=$(basename "$f")
            # Files not part of standard grub-pc/grub2 package
            if [[ ! "$bname" =~ ^(00_header|05_debian_theme|10_linux|20_linux_xen|20_memtest86\+|30_os-prober|30_uefi-firmware|40_custom|41_custom|README)$ ]]; then
                write_csv "Kernel and Boot" \
                    "$f" \
                    "Custom GRUB snippet found in /etc/grub.d/" \
                    "$(head -3 "$f" 2>/dev/null | tr '\n' ';')" "(not in stock grub-pc package)"
            fi
        done < <(find /etc/grub.d -maxdepth 1 -type f 2>/dev/null | sort)
    fi

    # --- Installed kernel versions ---
    info "Checking installed kernel versions..."
    local running_kernel; running_kernel=$(uname -r)
    local installed_kernels; installed_kernels=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | tr '\n' ';')
    local kernel_count; kernel_count=$(dpkg -l 'linux-image-*' 2>/dev/null | grep -c '^ii' || true)
    if [[ "$kernel_count" -gt 1 ]]; then
        write_csv "Kernel and Boot" \
            "dpkg (installed kernels)" \
            "Multiple kernel images installed ($kernel_count); non-standard kernels may be present" \
            "$installed_kernels" "Single generic kernel (stock)"
    fi
    # Check for non-generic/non-virtual kernel
    if ! echo "$running_kernel" | grep -qP '-generic$|-virtual$'; then
        write_csv "Kernel and Boot" \
            "/boot/vmlinuz-$running_kernel" \
            "Running kernel is not the standard generic/virtual kernel" \
            "$running_kernel" "*-generic (stock Ubuntu 22.04)"
    fi

    # Mainline/custom kernel packages (linux-image-X.Y.Z-YYYYMMDD)
    local custom_kernels; custom_kernels=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -vP 'linux-image-(generic|virtual|unsigned|lowlatency|aws|azure|gcp|oracle)' || true)
    if [[ -n "$custom_kernels" ]]; then
        write_csv "Kernel and Boot" \
            "dpkg (custom kernel packages)" \
            "Non-stock kernel package(s) installed" \
            "$(echo "$custom_kernels" | tr '\n' ';')" "linux-image-generic (stock)"
    fi

    # --- sysctl.conf / sysctl.d customisations ---
    info "Checking sysctl customisations..."
    local sysctl_override_files=()
    [[ -f /etc/sysctl.conf ]] && sysctl_override_files+=("/etc/sysctl.conf")
    while IFS= read -r f; do sysctl_override_files+=("$f"); done < <(find /etc/sysctl.d -name '*.conf' 2>/dev/null | sort)
    for sf in "${sysctl_override_files[@]}"; do
        local active_lines; active_lines=$(grep -vP '^\s*#|^\s*$' "$sf" 2>/dev/null | tr '\n' ';')
        if [[ -n "$active_lines" ]]; then
            write_csv "Kernel and Boot" \
                "$sf" \
                "Custom sysctl settings file contains active (non-commented) entries" \
                "$active_lines" "(empty / commented-out — stock)"
        fi
    done

    # --- initramfs customisations ---
    info "Checking initramfs configuration..."
    if [[ -d /etc/initramfs-tools ]]; then
        # modules file
        if [[ -f /etc/initramfs-tools/modules ]]; then
            local mods; mods=$(grep -vP '^\s*#|^\s*$' /etc/initramfs-tools/modules 2>/dev/null | tr '\n' ';')
            if [[ -n "$mods" ]]; then
                write_csv "Kernel and Boot" \
                    "/etc/initramfs-tools/modules" \
                    "Custom modules listed in initramfs-tools/modules" \
                    "$mods" "(empty — stock)"
            fi
        fi
        # hooks/scripts
        if [[ -d /etc/initramfs-tools/hooks ]]; then
            local hooks; hooks=$(find /etc/initramfs-tools/hooks -maxdepth 1 -type f 2>/dev/null | tr '\n' ';')
            if [[ -n "$hooks" ]]; then
                write_csv "Kernel and Boot" \
                    "/etc/initramfs-tools/hooks" \
                    "Custom initramfs hook scripts present" \
                    "$hooks" "(none — stock)"
            fi
        fi
        # conf.d overrides
        if [[ -d /etc/initramfs-tools/conf.d ]]; then
            local confs; confs=$(find /etc/initramfs-tools/conf.d -maxdepth 1 -type f 2>/dev/null | tr '\n' ';')
            if [[ -n "$confs" ]]; then
                local conf_content=""
                for cf in /etc/initramfs-tools/conf.d/*; do
                    [[ -f "$cf" ]] || continue
                    conf_content+="$(basename "$cf"): $(grep -vP '^\s*#|^\s*$' "$cf" 2>/dev/null | tr '\n' ';')  "
                done
                write_csv "Kernel and Boot" \
                    "/etc/initramfs-tools/conf.d/" \
                    "Custom initramfs config overrides present" \
                    "$conf_content" "(none — stock)"
            fi
        fi
    fi

    # --- Loaded kernel modules not in stock set ---
    info "Checking loaded kernel modules..."
    # Known extra/non-default modules that indicate customisation
    local unusual_modules=(
        "nvidia" "nvidia_drm" "nvidia_modeset" "nvidia_uvm"
        "zfs" "spl"
        "vboxdrv" "vboxnetflt" "vboxnetadp"
        "wireguard"
        "bonding" "8021q" "bridge"
        "nbd" "iscsi_tcp" "ceph"
        "v4l2loopback" "snd_aloop"
        "kvmgt" "vfio" "vfio_pci"
        "tcp_bbr" "tcp_cubic"
    )
    for mod in "${unusual_modules[@]}"; do
        if lsmod 2>/dev/null | grep -q "^${mod}\s"; then
            write_csv "Kernel and Boot" \
                "lsmod (loaded modules)" \
                "Non-default kernel module is loaded: $mod" \
                "loaded" "Not loaded (stock Ubuntu 22.04)"
        fi
    done
}

# ===========================================================================
# CATEGORY 3: Storage and Filesystems
# ===========================================================================
audit_storage() {
    section "3. Storage and Filesystems"

    # --- ZFS ---
    info "Checking ZFS configuration..."
    if cmd_exists zpool; then
        local zpools; zpools=$(zpool list -H -o name 2>/dev/null | tr '\n' ';')
        if [[ -n "$zpools" ]]; then
            local zpool_detail; zpool_detail=$(zpool status 2>/dev/null | head -30 | tr '\n' ';')
            write_csv "Storage and Filesystems" \
                "zpool" \
                "ZFS pool(s) present: $zpools" \
                "$zpool_detail" "No ZFS pools (stock Ubuntu 22.04)"
        fi
        # ZFS module params
        if [[ -d /etc/modprobe.d ]]; then
            local zfs_conf; zfs_conf=$(grep -rl 'zfs\|spl' /etc/modprobe.d/ 2>/dev/null | tr '\n' ';')
            if [[ -n "$zfs_conf" ]]; then
                write_csv "Storage and Filesystems" \
                    "/etc/modprobe.d/ (ZFS options)" \
                    "Custom ZFS/SPL module options configured" \
                    "$(grep -rh 'zfs\|spl' /etc/modprobe.d/ 2>/dev/null | tr '\n' ';')" "(none — stock)"
            fi
        fi
    fi

    # --- LVM ---
    info "Checking LVM configuration..."
    if cmd_exists lvs; then
        local lv_list; lv_list=$(lvs --noheadings -o lv_name,vg_name,lv_size 2>/dev/null | tr '\n' ';')
        if [[ -n "$lv_list" ]]; then
            write_csv "Storage and Filesystems" \
                "LVM (lvs)" \
                "LVM logical volumes present" \
                "$lv_list" "No LVM (stock cloud/desktop Ubuntu uses plain partitions)"
        fi
    fi

    # --- mdadm RAID ---
    info "Checking mdadm RAID configuration..."
    if [[ -f /etc/mdadm/mdadm.conf || -f /proc/mdstat ]]; then
        local md_active; md_active=$(grep -c '^md' /proc/mdstat 2>/dev/null || echo 0)
        if [[ "$md_active" -gt 0 ]]; then
            local md_detail; md_detail=$(cat /proc/mdstat 2>/dev/null | tr '\n' ';')
            write_csv "Storage and Filesystems" \
                "/proc/mdstat" \
                "Active mdadm RAID arrays detected ($md_active)" \
                "$md_detail" "No RAID arrays (stock)"
        fi
    fi

    # --- fstab non-default entries ---
    info "Checking /etc/fstab for custom entries..."
    if [[ -f /etc/fstab ]]; then
        while IFS= read -r line; do
            # Skip blank lines and comments
            [[ "$line" =~ ^#|^$ ]] && continue
            local fs_spec fs_type mount_point
            read -r fs_spec _ mount_point fs_type _ <<< "$line"
            # Skip standard mounts
            if [[ "$mount_point" =~ ^(/|/boot/efi|/boot|swap)$ && \
                  "$fs_type" =~ ^(ext4|xfs|btrfs|vfat|fat32|swap)$ ]]; then
                continue
            fi
            # Flag NFS, CIFS, fuse, overlay, bind, etc.
            if [[ "$fs_type" =~ ^(nfs|nfs4|cifs|smbfs|fuse|overlay|tmpfs|ramfs)$ ]] || \
               echo "$line" | grep -qP '(bind|rbind|nfs|cifs|smb|fuse)'; then
                write_csv "Storage and Filesystems" \
                    "/etc/fstab" \
                    "Non-standard or network filesystem mount: $mount_point ($fs_type)" \
                    "$line" "(stock: only / /boot swap)"
            else
                # Any extra local mounts with custom options
                if echo "$line" | grep -qP '(noexec|nosuid|nodev|relatime|discard|errors=|usrquota|grpquota|compress|subvol=)'; then
                    write_csv "Storage and Filesystems" \
                        "/etc/fstab" \
                        "Custom mount options on $mount_point" \
                        "$line" "(stock defaults)"
                fi
            fi
        done < /etc/fstab
    fi

    # --- Custom disk I/O scheduler ---
    info "Checking disk I/O schedulers..."
    for dev in /sys/block/sd* /sys/block/nvme* /sys/block/vd* /sys/block/xvd*; do
        [[ -e "${dev}/queue/scheduler" ]] || continue
        local sched; sched=$(cat "${dev}/queue/scheduler" 2>/dev/null | grep -oP '\[.*?\]' | tr -d '[]' || true)
        local devname; devname=$(basename "$dev")
        # Default is typically mq-deadline or none for NVMe
        if [[ -z "$sched" ]]; then continue; fi
        if [[ "$sched" != "mq-deadline" && "$sched" != "none" && "$sched" != "bfq" ]]; then
            write_csv "Storage and Filesystems" \
                "/sys/block/${devname}/queue/scheduler" \
                "Non-default I/O scheduler on $devname" \
                "$sched" "mq-deadline or none (stock)"
        fi
    done

    # --- SMART monitoring ---
    info "Checking SMART monitoring (smartd)..."
    if cmd_exists smartd || dpkg -l smartmontools &>/dev/null; then
        if systemctl is-enabled --quiet smartd 2>/dev/null || \
           systemctl is-active  --quiet smartd 2>/dev/null; then
            write_csv "Storage and Filesystems" \
                "/etc/smartd.conf" \
                "smartd (SMART monitoring daemon) is installed and enabled" \
                "enabled" "Not installed/enabled (stock)"
        fi
    fi

    # --- NFS/CIFS mounts currently active ---
    info "Checking active NFS/CIFS mounts..."
    local net_mounts; net_mounts=$(mount 2>/dev/null | grep -P '\s(nfs|nfs4|cifs|smbfs)\s' || true)
    if [[ -n "$net_mounts" ]]; then
        write_csv "Storage and Filesystems" \
            "mount (active)" \
            "Active NFS/CIFS network filesystem mounts detected" \
            "$(echo "$net_mounts" | tr '\n' ';')" "No network mounts (stock)"
    fi
}

# ===========================================================================
# CATEGORY 4: GPU and Hardware Drivers
# ===========================================================================
audit_gpu_drivers() {
    section "4. GPU and Hardware Drivers"

    # --- NVIDIA ---
    info "Checking NVIDIA drivers..."
    if lsmod 2>/dev/null | grep -q '^nvidia'; then
        local nv_ver; nv_ver=$(cat /proc/driver/nvidia/version 2>/dev/null | head -1 || \
                               nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || \
                               echo "unknown")
        local nv_pkg; nv_pkg=$(dpkg -l 'nvidia-driver-*' 2>/dev/null | grep '^ii' | awk '{print $2" "$3}' | tr '\n' ';' || echo "")
        write_csv "GPU and Hardware Drivers" \
            "/proc/driver/nvidia" \
            "Proprietary NVIDIA driver loaded (not the stock nouveau open-source driver)" \
            "version: $nv_ver; packages: $nv_pkg" "nouveau (stock Ubuntu 22.04)"
    elif lsmod 2>/dev/null | grep -q '^nouveau'; then
        ok "Stock nouveau driver in use."
    fi

    # CUDA toolkit
    if cmd_exists nvcc || [[ -d /usr/local/cuda ]]; then
        local cuda_ver; cuda_ver=$(nvcc --version 2>/dev/null | grep -oP 'release \K[\d.]+' || \
                                   ls /usr/local/ 2>/dev/null | grep cuda | tr '\n' ';')
        write_csv "GPU and Hardware Drivers" \
            "/usr/local/cuda" \
            "CUDA toolkit installed" \
            "$cuda_ver" "Not installed (stock)"
    fi

    # --- Other proprietary drivers (ubuntu-drivers) ---
    info "Checking other proprietary drivers..."
    if cmd_exists ubuntu-drivers; then
        local active_drivers; active_drivers=$(ubuntu-drivers list 2>/dev/null | tr '\n' ';' || true)
        if [[ -n "$active_drivers" ]]; then
            write_csv "GPU and Hardware Drivers" \
                "ubuntu-drivers" \
                "ubuntu-drivers reports active/available proprietary drivers" \
                "$active_drivers" "(depends on hardware — indicates proprietary driver use)"
        fi
    fi

    # AMD proprietary (amdgpu-pro)
    if dpkg -l amdgpu-pro 2>/dev/null | grep -q '^ii'; then
        local amd_ver; amd_ver=$(dpkg -l amdgpu-pro 2>/dev/null | grep '^ii' | awk '{print $3}')
        write_csv "GPU and Hardware Drivers" \
            "dpkg (amdgpu-pro)" \
            "AMD proprietary AMDGPU-Pro driver installed" \
            "$amd_ver" "amdgpu open-source (stock)"
    fi

    # --- Custom Xorg configuration ---
    info "Checking Xorg configuration..."
    if [[ -f /etc/X11/xorg.conf ]]; then
        local xorg_content; xorg_content=$(cat /etc/X11/xorg.conf 2>/dev/null | tr '\n' ';')
        write_csv "GPU and Hardware Drivers" \
            "/etc/X11/xorg.conf" \
            "Custom /etc/X11/xorg.conf present" \
            "$xorg_content" "(none — stock Ubuntu auto-configures Xorg)"
    fi
    if [[ -d /etc/X11/xorg.conf.d ]]; then
        local xorg_snippets; xorg_snippets=$(find /etc/X11/xorg.conf.d -maxdepth 1 -name '*.conf' 2>/dev/null | tr '\n' ';')
        if [[ -n "$xorg_snippets" ]]; then
            write_csv "GPU and Hardware Drivers" \
                "/etc/X11/xorg.conf.d/" \
                "Custom Xorg configuration snippets present" \
                "$xorg_snippets" "(none — stock)"
        fi
    fi

    # --- Firmware packages ---
    info "Checking firmware packages..."
    local fw_pkgs; fw_pkgs=$(dpkg -l '*firmware*' 2>/dev/null | grep '^ii' | awk '{print $2}' | \
                              grep -vP '^(linux-firmware|firmware-sof-signed|amd64-microcode|intel-microcode)$' | \
                              tr '\n' ';' || true)
    if [[ -n "$fw_pkgs" ]]; then
        write_csv "GPU and Hardware Drivers" \
            "dpkg (firmware packages)" \
            "Non-stock firmware packages installed" \
            "$fw_pkgs" "linux-firmware + microcode only (stock)"
    fi
}

# ===========================================================================
# CATEGORY 5: Services and Daemons
# ===========================================================================
audit_services() {
    section "5. Services and Daemons"

    # Stock Ubuntu 22.04 enabled services (approximate baseline)
    local -r STOCK_ENABLED=(
        "apparmor" "apport" "apt-daily" "apt-daily-upgrade"
        "cloud-config" "cloud-final" "cloud-init" "cloud-init-local"
        "cron" "dbus" "dm-event" "fstrim" "getty@tty1"
        "grub-common" "irqbalance" "keyboard-setup" "lvm2-monitor"
        "ModemManager" "multipathd" "networkd-dispatcher"
        "NetworkManager" "NetworkManager-wait-online"
        "plymouth" "plymouth-quit" "plymouth-quit-wait"
        "polkit" "rsyslog" "setvtrgb"
        "snapd" "snapd.apparmor" "snapd.seeded"
        "ssh" "systemd-journal-flush" "systemd-networkd"
        "systemd-networkd-wait-online" "systemd-random-seed"
        "systemd-resolved" "systemd-timesyncd" "systemd-udev-trigger"
        "udisks2" "ufw" "unattended-upgrades" "upower" "whoopsie"
    )

    info "Checking for non-stock enabled systemd services..."
    # Get all enabled services
    local enabled_services
    mapfile -t enabled_services < <(systemctl list-unit-files --state=enabled --type=service 2>/dev/null | \
        awk '/\.service/ {print $1}' | sed 's/\.service$//' | sort)

    for svc in "${enabled_services[@]}"; do
        local is_stock=false
        for stock in "${STOCK_ENABLED[@]}"; do
            if [[ "$svc" == "$stock" ]]; then
                is_stock=true
                break
            fi
        done
        if ! $is_stock; then
            local svc_desc; svc_desc=$(systemctl show "$svc" -p Description --value 2>/dev/null | head -1 || echo "N/A")
            write_csv "Services and Daemons" \
                "/etc/systemd/system/${svc}.service (or /lib/...)" \
                "Non-stock systemd service is enabled: $svc" \
                "enabled; Description: $svc_desc" "Not enabled in stock Ubuntu 22.04"
        fi
    done

    # --- Disabled/masked stock services ---
    info "Checking for disabled/masked stock services..."
    local important_stock_services=(
        "apparmor" "ufw" "systemd-resolved" "cron" "rsyslog"
        "unattended-upgrades" "ssh" "networkd-dispatcher"
    )
    for svc in "${important_stock_services[@]}"; do
        local state; state=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
        if [[ "$state" == "disabled" || "$state" == "masked" ]]; then
            write_csv "Services and Daemons" \
                "systemctl ($svc)" \
                "Stock Ubuntu service is $state" \
                "$state" "enabled (stock)"
        fi
    done

    # --- Custom unit files in /etc/systemd/ ---
    info "Checking for custom systemd unit files..."
    while IFS= read -r f; do
        local unit; unit=$(basename "$f")
        write_csv "Services and Daemons" \
            "$f" \
            "Custom systemd unit file present in /etc/systemd/system/" \
            "$(head -5 "$f" 2>/dev/null | tr '\n' ';')" "(not in stock Ubuntu)"
    done < <(find /etc/systemd/system -maxdepth 1 \
        \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.mount' \) \
        -not -name '*.wants' -not -name 'multi-user.target.wants' 2>/dev/null | sort)

    # --- SSH configuration changes ---
    info "Checking SSH daemon configuration..."
    local sshd_conf="/etc/ssh/sshd_config"
    if [[ -f "$sshd_conf" ]]; then
        declare -A SSH_DEFAULTS=(
            ["PermitRootLogin"]="prohibit-password"
            ["PasswordAuthentication"]="yes"
            ["PubkeyAuthentication"]="yes"
            ["X11Forwarding"]="no"
            ["UsePAM"]="yes"
            ["AllowTcpForwarding"]="yes"
            ["MaxAuthTries"]="6"
            ["Port"]="22"
        )
        for param in "${!SSH_DEFAULTS[@]}"; do
            local cur_val; cur_val=$(grep -iP "^\s*${param}\s+" "$sshd_conf" 2>/dev/null | \
                awk '{print $2}' | tail -1 || true)
            [[ -z "$cur_val" ]] && continue
            local def_val="${SSH_DEFAULTS[$param]}"
            if [[ "${cur_val,,}" != "${def_val,,}" ]]; then
                write_csv "Services and Daemons" \
                    "$sshd_conf" \
                    "SSH parameter '$param' differs from default" \
                    "$cur_val" "$def_val"
            fi
        done
    fi

    # --- Cron jobs ---
    info "Checking cron jobs..."
    # /etc/crontab
    if [[ -f /etc/crontab ]]; then
        local cron_entries; cron_entries=$(grep -vP '^\s*#|^\s*$|SHELL=|PATH=|MAILTO=' /etc/crontab 2>/dev/null | tr '\n' ';')
        if [[ -n "$cron_entries" ]]; then
            write_csv "Services and Daemons" \
                "/etc/crontab" \
                "Custom entries in /etc/crontab" \
                "$cron_entries" "(standard Ubuntu cron entries)"
        fi
    fi
    # /etc/cron.d/ — already excludes known stock files via find's ! -name flags below
    while IFS= read -r f; do
        local cron_content; cron_content=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
        if [[ -n "$cron_content" ]]; then
            write_csv "Services and Daemons" \
                "$f" \
                "Custom cron job file in /etc/cron.d/" \
                "$cron_content" "(none — stock)"
        fi
    done < <(find /etc/cron.d -maxdepth 1 -type f \
        ! -name 'e2scrub_all' ! -name 'popularity-contest' 2>/dev/null | sort)

    # Per-user crontabs
    if [[ -d /var/spool/cron/crontabs ]]; then
        local user_crons; user_crons=$(ls /var/spool/cron/crontabs/ 2>/dev/null | tr '\n' ';')
        if [[ -n "$user_crons" ]]; then
            for u in $(ls /var/spool/cron/crontabs/ 2>/dev/null); do
                local uc; uc=$(crontab -l -u "$u" 2>/dev/null | grep -vP '^\s*#|^\s*$' | tr '\n' ';')
                if [[ -n "$uc" ]]; then
                    write_csv "Services and Daemons" \
                        "/var/spool/cron/crontabs/$u" \
                        "User crontab exists for $u" \
                        "$uc" "(no user crontabs — stock)"
                fi
            done
        fi
    fi

    # --- Systemd timers ---
    info "Checking non-stock systemd timers..."
    while IFS= read -r timer; do
        local tname; tname=$(echo "$timer" | awk '{print $1}')
        local tstatus; tstatus=$(echo "$timer" | awk '{print $2}')
        if [[ "$tstatus" == "enabled" && ! "$tname" =~ ^(apt-daily|apt-daily-upgrade|e2scrub_all|fstrim|logrotate|man-db|motd-news|ua-timer|update-notifier-download|ua-messaging|systemd-tmpfiles-clean)\.timer$ ]]; then
            write_csv "Services and Daemons" \
                "$tname" \
                "Non-stock systemd timer is enabled" \
                "enabled" "Not enabled in stock Ubuntu 22.04"
        fi
    done < <(systemctl list-unit-files --type=timer --state=enabled 2>/dev/null | awk '/\.timer/ {print $1,$2}')
}

# ===========================================================================
# CATEGORY 6: Package Management
# ===========================================================================
audit_packages() {
    section "6. Package Management"

    # --- Extra APT repositories ---
    info "Checking APT repositories..."
    # /etc/apt/sources.list
    if [[ -f /etc/apt/sources.list ]]; then
        local extra_sources; extra_sources=$(grep -vP '^\s*#|^\s*$' /etc/apt/sources.list 2>/dev/null | \
            grep -v 'archive.ubuntu.com\|security.ubuntu.com\|ports.ubuntu.com' || true)
        if [[ -n "$extra_sources" ]]; then
            write_csv "Package Management" \
                "/etc/apt/sources.list" \
                "Non-Ubuntu entries in /etc/apt/sources.list" \
                "$(echo "$extra_sources" | tr '\n' ';')" "(only Ubuntu official repos)"
        fi
    fi
    # /etc/apt/sources.list.d/
    while IFS= read -r f; do
        local repo_content; repo_content=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
        if [[ -n "$repo_content" ]]; then
            write_csv "Package Management" \
                "$f" \
                "Third-party APT repository configured" \
                "$repo_content" "(not in stock Ubuntu)"
        fi
    done < <(find /etc/apt/sources.list.d -maxdepth 1 -name '*.list' -o -name '*.sources' 2>/dev/null | sort)

    # --- PPAs ---
    info "Checking for PPAs..."
    local ppas; ppas=$(find /etc/apt/sources.list.d -maxdepth 1 -name '*.list' 2>/dev/null \
        -exec grep -lP 'ppa\.launchpad\.net' {} \; 2>/dev/null | tr '\n' ';')
    if [[ -n "$ppas" ]]; then
        write_csv "Package Management" \
            "/etc/apt/sources.list.d/ (PPAs)" \
            "Launchpad PPAs are configured" \
            "$ppas" "(no PPAs — stock)"
    fi

    # --- Held packages ---
    info "Checking for held packages..."
    local held; held=$(dpkg --get-selections 2>/dev/null | grep '\bhold$' | awk '{print $1}' | tr '\n' ';')
    if [[ -n "$held" ]]; then
        write_csv "Package Management" \
            "dpkg (held packages)" \
            "Packages are on hold (pinned at current version)" \
            "$held" "(no holds — stock)"
    fi

    # --- APT pinning / preferences ---
    info "Checking APT preferences..."
    if [[ -f /etc/apt/preferences ]]; then
        local pin_content; pin_content=$(grep -vP '^\s*#|^\s*$' /etc/apt/preferences 2>/dev/null | tr '\n' ';')
        if [[ -n "$pin_content" ]]; then
            write_csv "Package Management" \
                "/etc/apt/preferences" \
                "APT package pinning/preferences configured" \
                "$pin_content" "(none — stock)"
        fi
    fi
    while IFS= read -r f; do
        local pref_content; pref_content=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
        if [[ -n "$pref_content" ]]; then
            write_csv "Package Management" \
                "$f" \
                "APT preferences file (package pinning)" \
                "$pref_content" "(none — stock)"
        fi
    done < <(find /etc/apt/preferences.d -maxdepth 1 -type f 2>/dev/null | sort)

    # --- Snap packages ---
    info "Checking Snap packages..."
    if cmd_exists snap; then
        local stock_snaps=("bare" "core" "core18" "core20" "core22" "snapd" "gnome-3-38-2004" "gnome-42-2204" "gtk-common-themes" "snap-store")
        local installed_snaps; installed_snaps=$(snap list 2>/dev/null | tail -n +2 | awk '{print $1}' || true)
        while IFS= read -r snap_name; do
            [[ -z "$snap_name" ]] && continue
            local is_stock_snap=false
            for s in "${stock_snaps[@]}"; do
                [[ "$snap_name" == "$s" ]] && is_stock_snap=true && break
            done
            if ! $is_stock_snap; then
                local snap_ver; snap_ver=$(snap list "$snap_name" 2>/dev/null | tail -1 | awk '{print $2}' || echo "unknown")
                write_csv "Package Management" \
                    "snap ($snap_name)" \
                    "Non-default Snap package installed: $snap_name" \
                    "version: $snap_ver" "Not installed in stock Ubuntu 22.04"
            fi
        done <<< "$installed_snaps"
    fi

    # --- Flatpak ---
    info "Checking Flatpak packages..."
    if cmd_exists flatpak; then
        local flatpaks; flatpaks=$(flatpak list 2>/dev/null | awk '{print $2}' | tr '\n' ';' || true)
        if [[ -n "$flatpaks" ]]; then
            write_csv "Package Management" \
                "flatpak (installed)" \
                "Flatpak packages installed" \
                "$flatpaks" "No Flatpak packages (stock Ubuntu 22.04 doesn't include Flatpak)"
        fi
    fi

    # --- dpkg-verify: modified conffiles ---
    info "Checking for modified package-managed config files (dpkg --verify)..."
    # dpkg --verify output: lines starting with '??' or '5.' indicate changed files
    if dpkg --verify &>/dev/null 2>&1 || true; then
        local modified_conf; modified_conf=$(dpkg --verify 2>/dev/null | grep -P '^..5' | head -50 || true)
        if [[ -n "$modified_conf" ]]; then
            while IFS= read -r modline; do
                local modfile; modfile=$(echo "$modline" | awk '{print $NF}')
                write_csv "Package Management" \
                    "$modfile" \
                    "Package-managed config file has been modified (dpkg --verify)" \
                    "$modline" "(unmodified — as shipped by package)"
            done <<< "$modified_conf"
        fi
    fi
}

# ===========================================================================
# CATEGORY 7: User Environment and Shell
# ===========================================================================
audit_user_environment() {
    section "7. User Environment and Shell"

    # --- System-wide shell files ---
    info "Checking system-wide shell configuration files..."

    local skel_dir="/etc/skel"
    local system_shell_files=(
        "/etc/bash.bashrc"
        "/etc/profile"
        "/etc/environment"
    )
    for sf in "${system_shell_files[@]}"; do
        [[ -f "$sf" ]] || continue
        # Check if file has been modified by dpkg (exit code 1 = changes found)
        if ! dpkg --verify "$sf" &>/dev/null || dpkg --verify "$sf" 2>/dev/null | grep -q '5'; then
            local content; content=$(grep -vP '^\s*#|^\s*$' "$sf" 2>/dev/null | tr '\n' ';')
            write_csv "User Environment and Shell" \
                "$sf" \
                "System shell config file has custom content (modified from package default)" \
                "$content" "(stock Ubuntu 22.04 default)"
        fi
    done

    # /etc/environment custom entries
    if [[ -f /etc/environment ]]; then
        local env_content; env_content=$(grep -vP '^\s*#|^\s*$|^PATH=' /etc/environment 2>/dev/null | tr '\n' ';')
        if [[ -n "$env_content" ]]; then
            write_csv "User Environment and Shell" \
                "/etc/environment" \
                "Custom environment variables set in /etc/environment" \
                "$env_content" "(only PATH — stock)"
        fi
    fi

    # Custom PATH in /etc/environment or /etc/profile.d/
    if [[ -f /etc/environment ]]; then
        local cur_path; cur_path=$(grep '^PATH=' /etc/environment 2>/dev/null | head -1 || true)
        local stock_path='PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"'
        if [[ -n "$cur_path" && "$cur_path" != "$stock_path" ]]; then
            write_csv "User Environment and Shell" \
                "/etc/environment" \
                "System PATH differs from stock Ubuntu 22.04 default" \
                "$cur_path" "$stock_path"
        fi
    fi

    # /etc/profile.d/ custom scripts
    info "Checking /etc/profile.d/ custom scripts..."
    local stock_profiled=("apps-bin-path.sh" "bash_completion.sh" "cedilla-portuguese.sh"
                          "debuginfod.sh" "gawk.sh" "im-config_wayland.sh" "jvm.sh" "vte-2.91.sh")
    while IFS= read -r f; do
        local bname; bname=$(basename "$f")
        local is_stock=false
        for s in "${stock_profiled[@]}"; do [[ "$bname" == "$s" ]] && is_stock=true && break; done
        if ! $is_stock; then
            local pcontent; pcontent=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
            write_csv "User Environment and Shell" \
                "$f" \
                "Custom /etc/profile.d/ script present" \
                "$pcontent" "(not in stock Ubuntu)"
        fi
    done < <(find /etc/profile.d -maxdepth 1 -name '*.sh' 2>/dev/null | sort)

    # --- Per-user shell config changes ---
    info "Checking per-user shell configuration files..."
    local skel_bashrc; skel_bashrc=$(cat /etc/skel/.bashrc 2>/dev/null)
    local skel_profile; skel_profile=$(cat /etc/skel/.profile 2>/dev/null)

    while IFS=: read -r username _ uid _ _ homedir shell; do
        # Only check regular users (uid 1000+) and root
        if [[ "$uid" -lt 1000 && "$uid" -ne 0 ]]; then continue; fi
        [[ -d "$homedir" ]] || continue

        # .bashrc
        if [[ -f "${homedir}/.bashrc" ]]; then
            local user_bashrc; user_bashrc=$(cat "${homedir}/.bashrc" 2>/dev/null)
            if [[ "$user_bashrc" != "$skel_bashrc" ]]; then
                local diff_summary; diff_summary=$(diff <(echo "$skel_bashrc") <(echo "$user_bashrc") 2>/dev/null | \
                    grep '^[<>]' | head -20 | tr '\n' ';' || echo "differs from /etc/skel/.bashrc")
                write_csv "User Environment and Shell" \
                    "${homedir}/.bashrc" \
                    "User $username's .bashrc differs from /etc/skel/.bashrc" \
                    "$diff_summary" "(stock /etc/skel/.bashrc)"
            fi
        fi

        # .profile
        if [[ -f "${homedir}/.profile" ]]; then
            local user_profile; user_profile=$(cat "${homedir}/.profile" 2>/dev/null)
            if [[ "$user_profile" != "$skel_profile" ]]; then
                write_csv "User Environment and Shell" \
                    "${homedir}/.profile" \
                    "User $username's .profile differs from /etc/skel/.profile" \
                    "$(diff <(echo "$skel_profile") <(echo "$user_profile") 2>/dev/null | grep '^[<>]' | head -10 | tr '\n' ';')" "(stock /etc/skel/.profile)"
            fi
        fi

        # .bash_aliases (not in /etc/skel by default — any file is custom)
        if [[ -f "${homedir}/.bash_aliases" ]]; then
            local aliases_content; aliases_content=$(cat "${homedir}/.bash_aliases" 2>/dev/null | tr '\n' ';')
            write_csv "User Environment and Shell" \
                "${homedir}/.bash_aliases" \
                "User $username has a .bash_aliases file" \
                "$aliases_content" "(no .bash_aliases in stock /etc/skel)"
        fi

        # .zshrc, .zprofile — custom shell config
        for zf in .zshrc .zprofile .zshenv .fishrc .config/fish/config.fish; do
            if [[ -f "${homedir}/${zf}" ]]; then
                write_csv "User Environment and Shell" \
                    "${homedir}/${zf}" \
                    "User $username has custom $zf (non-default shell config)" \
                    "$(head -5 "${homedir}/${zf}" 2>/dev/null | tr '\n' ';')" "(not in stock /etc/skel)"
            fi
        done

    done < /etc/passwd

    # --- Custom shell installations ---
    info "Checking for custom shells..."
    local stock_shells=("/bin/sh" "/bin/bash" "/bin/dash" "/bin/rbash")
    while IFS= read -r sh; do
        local is_stock=false
        for s in "${stock_shells[@]}"; do [[ "$sh" == "$s" ]] && is_stock=true && break; done
        if ! $is_stock; then
            local sh_ver; sh_ver=$(safe_run "$sh" --version 2>/dev/null | head -1 || echo "installed")
            write_csv "User Environment and Shell" \
                "$sh ($(which "$sh" 2>/dev/null || echo 'unknown'))" \
                "Non-stock shell installed: $sh" \
                "$sh_ver" "bash/dash/sh (stock)"
        fi
    done < /etc/shells
}

# ===========================================================================
# CATEGORY 8: Programming Languages and Runtimes
# ===========================================================================
audit_languages() {
    section "8. Programming Languages and Runtimes"

    # Stock Ubuntu 22.04 Python is 3.10
    local STOCK_PYTHON="3.10"

    # --- Python ---
    info "Checking Python versions..."
    # All python3 binaries
    while IFS= read -r pybin; do
        [[ -x "$pybin" ]] || continue
        local ver; ver=$(safe_run "$pybin" --version 2>&1 | awk '{print $2}')
        if [[ -n "$ver" && "$ver" != "${STOCK_PYTHON}"* ]]; then
            write_csv "Programming Languages and Runtimes" \
                "$pybin" \
                "Non-stock Python version installed" \
                "$ver" "3.10.x (stock Ubuntu 22.04)"
        fi
    done < <(find /usr /usr/local /opt -maxdepth 5 -name 'python3*' -type f 2>/dev/null | sort -u)

    # pyenv
    if [[ -d "$HOME/.pyenv" || -d /usr/local/pyenv || -d /opt/pyenv ]]; then
        write_csv "Programming Languages and Runtimes" \
            "~/.pyenv or /usr/local/pyenv" \
            "pyenv Python version manager installed" \
            "present" "Not installed (stock)"
    fi

    # conda / miniconda / anaconda
    for conda_dir in /opt/conda /opt/miniconda3 /opt/anaconda3 "$HOME/miniconda3" "$HOME/anaconda3" /usr/local/miniconda3; do
        if [[ -d "$conda_dir" ]]; then
            local conda_ver; conda_ver=$(safe_run "${conda_dir}/bin/conda" --version 2>/dev/null || echo "present")
            write_csv "Programming Languages and Runtimes" \
                "$conda_dir" \
                "Conda/Miniconda/Anaconda installed" \
                "$conda_ver" "Not installed (stock)"
        fi
    done

    # Global pip packages (beyond stdlib)
    if cmd_exists pip3; then
        local pip_pkgs; pip_pkgs=$(pip3 list --format=columns 2>/dev/null | tail -n +3 | awk '{print $1}' | tr '\n' ';')
        if [[ -n "$pip_pkgs" ]]; then
            local pip_count; pip_count=$(pip3 list 2>/dev/null | tail -n +3 | wc -l)
            write_csv "Programming Languages and Runtimes" \
                "pip3 (global packages)" \
                "Python packages installed globally via pip3 ($pip_count packages)" \
                "$pip_pkgs" "(no global pip packages — stock)"
        fi
    fi

    # --- Node.js ---
    info "Checking Node.js..."
    if cmd_exists node; then
        local node_ver; node_ver=$(node --version 2>/dev/null || echo "unknown")
        local node_path; node_path=$(which node)
        # Detect non-apt installations (nvm, n, nodejs.org tarball)
        if [[ "$node_path" != "/usr/bin/node" && "$node_path" != "/usr/bin/nodejs" ]]; then
            write_csv "Programming Languages and Runtimes" \
                "$node_path" \
                "Node.js installed via non-APT method (path not /usr/bin)" \
                "$node_ver @ $node_path" "/usr/bin/node via apt (stock)"
        else
            write_csv "Programming Languages and Runtimes" \
                "$node_path" \
                "Node.js installed (not in stock Ubuntu 22.04 minimal install)" \
                "$node_ver" "Not installed (stock)"
        fi
    fi

    # nvm
    for nvm_dir in "$HOME/.nvm" /usr/local/nvm /opt/nvm; do
        if [[ -d "$nvm_dir" ]]; then
            write_csv "Programming Languages and Runtimes" \
                "$nvm_dir" \
                "nvm (Node Version Manager) installed" \
                "present" "Not installed (stock)"
        fi
    done

    # Global npm packages
    if cmd_exists npm; then
        local npm_global; npm_global=$(npm list -g --depth=0 2>/dev/null | tail -n +2 | tr '\n' ';')
        if [[ -n "$npm_global" ]]; then
            write_csv "Programming Languages and Runtimes" \
                "npm (global packages)" \
                "Global npm packages installed" \
                "$npm_global" "(none — stock)"
        fi
    fi

    # --- Java / JDK ---
    info "Checking Java..."
    if cmd_exists java; then
        local java_ver; java_ver=$(java -version 2>&1 | head -1)
        local java_path; java_path=$(which java)
        write_csv "Programming Languages and Runtimes" \
            "$java_path" \
            "Java/JDK installed" \
            "$java_ver" "Not installed (stock Ubuntu 22.04 minimal)"
    fi
    # SDKMan
    for sdk_dir in "$HOME/.sdkman" /usr/local/sdkman; do
        if [[ -d "$sdk_dir" ]]; then
            write_csv "Programming Languages and Runtimes" \
                "$sdk_dir" \
                "SDKMan version manager installed" \
                "present" "Not installed (stock)"
        fi
    done

    # --- Go ---
    info "Checking Go..."
    for go_bin in /usr/local/go/bin/go /usr/bin/go /snap/bin/go; do
        if [[ -x "$go_bin" ]]; then
            local go_ver; go_ver=$(safe_run "$go_bin" version 2>/dev/null || echo "unknown")
            write_csv "Programming Languages and Runtimes" \
                "$go_bin" \
                "Go language runtime installed" \
                "$go_ver" "Not installed (stock)"
            break
        fi
    done

    # --- Rust ---
    info "Checking Rust..."
    if cmd_exists rustc || [[ -d "$HOME/.cargo" ]]; then
        local rust_ver; rust_ver=$(safe_run rustc --version 2>/dev/null || echo "present")
        write_csv "Programming Languages and Runtimes" \
            "$(which rustc 2>/dev/null || echo ~/.cargo/bin/rustc)" \
            "Rust toolchain installed" \
            "$rust_ver" "Not installed (stock)"
    fi

    # --- Ruby ---
    info "Checking Ruby..."
    if cmd_exists ruby; then
        local ruby_ver; ruby_ver=$(ruby --version 2>/dev/null || echo "unknown")
        local ruby_path; ruby_path=$(which ruby)
        write_csv "Programming Languages and Runtimes" \
            "$ruby_path" \
            "Ruby installed" \
            "$ruby_ver" "Not installed (stock)"
        # Gem global packages
        if cmd_exists gem; then
            local gems; gems=$(gem list 2>/dev/null | tr '\n' ';')
            if [[ -n "$gems" ]]; then
                write_csv "Programming Languages and Runtimes" \
                    "gem (global)" \
                    "Ruby gems installed globally" \
                    "$gems" "(none — stock)"
            fi
        fi
    fi
    # rbenv / rvm
    for rbenv_dir in "$HOME/.rbenv" /usr/local/rbenv /opt/rbenv; do
        if [[ -d "$rbenv_dir" ]]; then
            write_csv "Programming Languages and Runtimes" \
                "$rbenv_dir" \
                "rbenv Ruby version manager installed" \
                "present" "Not installed (stock)"
        fi
    done
    if [[ -d "$HOME/.rvm" || -d /usr/local/rvm ]]; then
        write_csv "Programming Languages and Runtimes" \
            "~/.rvm or /usr/local/rvm" \
            "rvm Ruby version manager installed" \
            "present" "Not installed (stock)"
    fi
}

# ===========================================================================
# CATEGORY 9: Security Configuration
# ===========================================================================
audit_security() {
    section "9. Security Configuration"

    # --- UFW firewall ---
    info "Checking UFW firewall..."
    if cmd_exists ufw; then
        local ufw_status; ufw_status=$(ufw status verbose 2>/dev/null | head -5 | tr '\n' ';')
        local ufw_state; ufw_state=$(ufw status 2>/dev/null | head -1 | awk '{print $2}')
        if [[ "$ufw_state" == "inactive" ]]; then
            write_csv "Security Configuration" \
                "ufw (firewall)" \
                "UFW firewall is installed but inactive (disabled)" \
                "inactive" "active (stock Ubuntu 22.04 enables ufw)"
        else
            # Check for custom rules beyond defaults
            local ufw_rules; ufw_rules=$(ufw status numbered 2>/dev/null | grep '^\[' | head -30 | tr '\n' ';')
            if [[ -n "$ufw_rules" ]]; then
                write_csv "Security Configuration" \
                    "ufw (rules)" \
                    "Custom UFW firewall rules configured" \
                    "$ufw_rules" "(no custom rules — stock)"
            fi
        fi
    fi

    # --- AppArmor ---
    info "Checking AppArmor..."
    if cmd_exists aa-status; then
        local aa_profiles_complain; aa_profiles_complain=$(aa-status 2>/dev/null | grep -c 'profiles are in complain mode' || echo 0)
        local aa_profiles_disabled; aa_profiles_disabled=$(find /etc/apparmor.d/disable -maxdepth 1 -type l 2>/dev/null | wc -l)
        if [[ "$aa_profiles_complain" -gt 0 ]]; then
            write_csv "Security Configuration" \
                "AppArmor" \
                "AppArmor profiles set to complain mode ($aa_profiles_complain)" \
                "$aa_profiles_complain profiles in complain mode" "0 in complain mode (stock enforces all)"
        fi
        if [[ "$aa_profiles_disabled" -gt 0 ]]; then
            local disabled_list; disabled_list=$(ls /etc/apparmor.d/disable/ 2>/dev/null | tr '\n' ';')
            write_csv "Security Configuration" \
                "/etc/apparmor.d/disable/" \
                "AppArmor profiles disabled ($aa_profiles_disabled)" \
                "$disabled_list" "No disabled profiles (stock)"
        fi
    fi
    if ! systemctl is-active --quiet apparmor 2>/dev/null; then
        write_csv "Security Configuration" \
            "systemctl (apparmor)" \
            "AppArmor service is not active" \
            "inactive" "active (stock)"
    fi

    # --- sudoers ---
    info "Checking sudoers configuration..."
    if [[ -f /etc/sudoers ]]; then
        # Check for NOPASSWD
        if grep -qP 'NOPASSWD' /etc/sudoers 2>/dev/null; then
            local nopass; nopass=$(grep -P 'NOPASSWD' /etc/sudoers | tr '\n' ';')
            write_csv "Security Configuration" \
                "/etc/sudoers" \
                "NOPASSWD sudo access granted in /etc/sudoers" \
                "$nopass" "(no NOPASSWD — stock)"
        fi
    fi
    # sudoers.d
    while IFS= read -r f; do
        local sudo_content; sudo_content=$(cat "$f" 2>/dev/null | grep -vP '^\s*#|^\s*$' | tr '\n' ';')
        if [[ -n "$sudo_content" ]]; then
            local nopass_flag=""
            grep -qP 'NOPASSWD' "$f" 2>/dev/null && nopass_flag=" [NOPASSWD detected]"
            write_csv "Security Configuration" \
                "$f" \
                "Custom sudoers drop-in file${nopass_flag}" \
                "$sudo_content" "(not in stock Ubuntu)"
        fi
    done < <(find /etc/sudoers.d -maxdepth 1 -type f ! -name 'README' 2>/dev/null | sort)

    # --- PAM configuration ---
    info "Checking PAM configuration..."
    local stock_pam_files=("common-account" "common-auth" "common-password" "common-session"
                           "common-session-noninteractive" "login" "sshd" "su" "sudo" "passwd")
    while IFS= read -r pam_file; do
        local bname; bname=$(basename "$pam_file")
        # Check if modified from package
        if dpkg --verify "$pam_file" 2>/dev/null | grep -q '5'; then
            write_csv "Security Configuration" \
                "$pam_file" \
                "PAM configuration file modified from package default" \
                "$(cat "$pam_file" 2>/dev/null | grep -vP '^\s*#|^\s*$' | tr '\n' ';')" "(stock PAM config)"
        fi
    done < <(find /etc/pam.d -maxdepth 1 -type f 2>/dev/null)

    # --- Fail2ban ---
    info "Checking Fail2ban..."
    if cmd_exists fail2ban-client || dpkg -l fail2ban &>/dev/null 2>&1; then
        local f2b_status; f2b_status=$(fail2ban-client status 2>/dev/null | head -3 | tr '\n' ';' || echo "installed")
        write_csv "Security Configuration" \
            "/etc/fail2ban/" \
            "fail2ban intrusion prevention installed and configured" \
            "$f2b_status" "Not installed (stock)"
    fi

    # --- SSH ---
    info "Checking SSH key-based configuration..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        # Check PermitRootLogin
        local root_login; root_login=$(grep -iP '^\s*PermitRootLogin\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1 || echo "prohibit-password")
        if [[ "${root_login,,}" == "yes" ]]; then
            write_csv "Security Configuration" \
                "/etc/ssh/sshd_config" \
                "SSH PermitRootLogin is set to 'yes' (security risk)" \
                "yes" "prohibit-password (stock)"
        fi
        # Check PasswordAuthentication
        local pw_auth; pw_auth=$(grep -iP '^\s*PasswordAuthentication\s+' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | tail -1 || echo "yes")
        if [[ "${pw_auth,,}" == "no" ]]; then
            write_csv "Security Configuration" \
                "/etc/ssh/sshd_config" \
                "SSH PasswordAuthentication is disabled (only key auth)" \
                "no" "yes (stock)"
        fi
    fi

    # Authorised keys in sensitive locations
    for home_dir in /root $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
        if [[ -f "${home_dir}/.ssh/authorized_keys" ]]; then
            local key_count; key_count=$(wc -l < "${home_dir}/.ssh/authorized_keys" 2>/dev/null || echo 0)
            if [[ "$key_count" -gt 0 ]]; then
                local user; user=$(stat -c '%U' "${home_dir}" 2>/dev/null || echo "unknown")
                write_csv "Security Configuration" \
                    "${home_dir}/.ssh/authorized_keys" \
                    "SSH authorized_keys present for $user ($key_count key(s))" \
                    "$key_count key(s)" "(none — stock)"
            fi
        fi
    done

    # --- SSL certificates ---
    info "Checking custom SSL/TLS certificates..."
    local custom_certs; custom_certs=$(find /usr/local/share/ca-certificates /usr/share/ca-certificates/local \
        -maxdepth 2 -name '*.crt' -o -name '*.pem' 2>/dev/null | tr '\n' ';')
    if [[ -n "$custom_certs" ]]; then
        write_csv "Security Configuration" \
            "/usr/local/share/ca-certificates/" \
            "Custom SSL/TLS root certificates installed" \
            "$custom_certs" "(none — stock)"
    fi

    # --- Unattended-upgrades ---
    info "Checking unattended-upgrades configuration..."
    local uu_conf="/etc/apt/apt.conf.d/50unattended-upgrades"
    if [[ -f "$uu_conf" ]]; then
        if dpkg --verify "$uu_conf" 2>/dev/null | grep -q '5'; then
            local uu_content; uu_content=$(grep -vP '^\s*//|^\s*$' "$uu_conf" 2>/dev/null | tr '\n' ';')
            write_csv "Security Configuration" \
                "$uu_conf" \
                "unattended-upgrades configuration modified" \
                "$uu_content" "(stock Ubuntu 22.04 default)"
        fi
    fi
}

# ===========================================================================
# CATEGORY 10: Containerization and Virtualization
# ===========================================================================
audit_containers_virt() {
    section "10. Containerization and Virtualization"

    # --- Docker ---
    info "Checking Docker..."
    if cmd_exists docker; then
        local docker_ver; docker_ver=$(docker --version 2>/dev/null || echo "installed")
        local docker_info; docker_info=$(docker info 2>/dev/null | grep -P '(Server Version|Storage Driver|Logging Driver|Cgroup Driver|Containers|Images)' | tr '\n' ';' || echo "n/a")
        write_csv "Containerization and Virtualization" \
            "/etc/docker/daemon.json (or default config)" \
            "Docker Engine installed" \
            "$docker_ver; $docker_info" "Not installed (stock)"

        # Custom daemon.json
        if [[ -f /etc/docker/daemon.json ]]; then
            local daemon_json; daemon_json=$(cat /etc/docker/daemon.json 2>/dev/null | tr '\n' ';')
            write_csv "Containerization and Virtualization" \
                "/etc/docker/daemon.json" \
                "Custom Docker daemon configuration present" \
                "$daemon_json" "(none — stock Docker defaults)"
        fi
    fi

    # --- Podman ---
    info "Checking Podman..."
    if cmd_exists podman; then
        local podman_ver; podman_ver=$(podman --version 2>/dev/null || echo "installed")
        write_csv "Containerization and Virtualization" \
            "$(which podman)" \
            "Podman container runtime installed" \
            "$podman_ver" "Not installed (stock)"
    fi

    # --- containerd ---
    if cmd_exists containerd || systemctl is-active --quiet containerd 2>/dev/null; then
        local ctrd_ver; ctrd_ver=$(safe_run containerd --version 2>/dev/null || echo "running")
        write_csv "Containerization and Virtualization" \
            "$(which containerd 2>/dev/null || echo 'containerd')" \
            "containerd container runtime installed" \
            "$ctrd_ver" "Not installed (stock)"
    fi

    # --- Kubernetes tools ---
    info "Checking Kubernetes tools..."
    local k8s_tools=("kubectl" "kubeadm" "kubelet" "helm" "k3s" "k0s" "minikube" "kind")
    for tool in "${k8s_tools[@]}"; do
        if cmd_exists "$tool"; then
            local t_ver; t_ver=$(safe_run "$tool" version --client 2>/dev/null | head -1 || \
                                safe_run "$tool" version 2>/dev/null | head -1 || echo "installed")
            write_csv "Containerization and Virtualization" \
                "$(which "$tool")" \
                "Kubernetes tool installed: $tool" \
                "$t_ver" "Not installed (stock)"
        fi
    done

    # --- libvirt / KVM / QEMU ---
    info "Checking libvirt/KVM/QEMU..."
    if cmd_exists virsh; then
        local vms; vms=$(virsh list --all 2>/dev/null | tail -n +3 | head -20 | tr '\n' ';' || echo "n/a")
        local libvirt_ver; libvirt_ver=$(virsh version 2>/dev/null | head -1 || echo "installed")
        write_csv "Containerization and Virtualization" \
            "libvirt/virsh" \
            "libvirt/KVM virtualization installed and configured" \
            "version: $libvirt_ver; VMs: $vms" "Not installed (stock)"
    fi
    if cmd_exists qemu-system-x86_64; then
        local qemu_ver; qemu_ver=$(qemu-system-x86_64 --version 2>/dev/null | head -1 || echo "installed")
        write_csv "Containerization and Virtualization" \
            "$(which qemu-system-x86_64)" \
            "QEMU hypervisor installed" \
            "$qemu_ver" "Not installed (stock)"
    fi

    # --- VirtualBox ---
    info "Checking VirtualBox..."
    if cmd_exists VBoxManage; then
        local vbox_ver; vbox_ver=$(VBoxManage --version 2>/dev/null || echo "installed")
        write_csv "Containerization and Virtualization" \
            "$(which VBoxManage)" \
            "Oracle VirtualBox installed" \
            "$vbox_ver" "Not installed (stock)"
    fi
}

# ===========================================================================
# CATEGORY 11: System Configuration Files
# ===========================================================================
audit_system_config() {
    section "11. System Configuration Files"

    # --- /etc/hosts ---
    info "Checking /etc/hosts..."
    if [[ -f /etc/hosts ]]; then
        # Count non-comment, non-default entries
        local custom_hosts; custom_hosts=$(grep -vP '^\s*#|^\s*$|^127\.0\.0\.1\s+localhost|^127\.0\.1\.1\s+|^::1\s+localhost|^ff02::|^fe80::' \
            /etc/hosts 2>/dev/null | tr '\n' ';')
        if [[ -n "$custom_hosts" ]]; then
            write_csv "System Configuration Files" \
                "/etc/hosts" \
                "Custom entries in /etc/hosts" \
                "$custom_hosts" "(only localhost entries — stock)"
        fi
    fi

    # --- Hostname ---
    info "Checking hostname configuration..."
    if [[ -f /etc/hostname ]]; then
        local hostname; hostname=$(cat /etc/hostname 2>/dev/null | tr -d '\n')
        if [[ "$hostname" != "ubuntu" && "$hostname" != "ubuntu2204" && -n "$hostname" ]]; then
            write_csv "System Configuration Files" \
                "/etc/hostname" \
                "Hostname has been changed from stock default" \
                "$hostname" "ubuntu (stock)"
        fi
    fi

    # --- Timezone ---
    info "Checking timezone..."
    local tz; tz=$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo "UTC")
    if [[ "$tz" != "UTC" && "$tz" != "Etc/UTC" ]]; then
        write_csv "System Configuration Files" \
            "/etc/timezone" \
            "System timezone changed from default (UTC)" \
            "$tz" "UTC (stock)"
    fi

    # --- Locale ---
    info "Checking locale settings..."
    local locale_conf="/etc/locale.gen"
    if [[ -f /etc/default/locale ]]; then
        local cur_locale; cur_locale=$(grep '^LANG=' /etc/default/locale 2>/dev/null | cut -d= -f2 | tr -d '"')
        if [[ -n "$cur_locale" && "$cur_locale" != "en_US.UTF-8" && "$cur_locale" != "C.UTF-8" ]]; then
            write_csv "System Configuration Files" \
                "/etc/default/locale" \
                "System locale differs from Ubuntu default" \
                "$cur_locale" "en_US.UTF-8 (stock)"
        fi
    fi

    # --- NTP / timesyncd / chrony ---
    info "Checking time synchronization..."
    if cmd_exists chronyc && systemctl is-active --quiet chrony 2>/dev/null; then
        local chrony_sources; chrony_sources=$(chronyc sources 2>/dev/null | head -10 | tr '\n' ';')
        write_csv "System Configuration Files" \
            "/etc/chrony.conf" \
            "chrony NTP daemon installed (replacing stock systemd-timesyncd)" \
            "$chrony_sources" "systemd-timesyncd (stock)"
    fi
    if [[ -f /etc/systemd/timesyncd.conf ]]; then
        local ts_custom; ts_custom=$(grep -vP '^\s*#|^\s*$|\[Time\]' /etc/systemd/timesyncd.conf 2>/dev/null | tr '\n' ';')
        if [[ -n "$ts_custom" ]]; then
            write_csv "System Configuration Files" \
                "/etc/systemd/timesyncd.conf" \
                "Custom NTP server(s) in systemd-timesyncd config" \
                "$ts_custom" "(Ubuntu/Canonical NTP pool — stock)"
        fi
    fi

    # --- Swap ---
    info "Checking swap configuration..."
    local swappiness; swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
    if [[ "$swappiness" != "60" ]]; then
        write_csv "System Configuration Files" \
            "sysctl vm.swappiness" \
            "vm.swappiness differs from default" \
            "$swappiness" "60 (stock)"
    fi

    # zswap / zram
    if [[ -f /sys/module/zswap/parameters/enabled ]]; then
        local zswap_en; zswap_en=$(cat /sys/module/zswap/parameters/enabled 2>/dev/null)
        if [[ "$zswap_en" == "Y" ]]; then
            write_csv "System Configuration Files" \
                "/sys/module/zswap/parameters/enabled" \
                "zswap compressed swap cache is enabled" \
                "enabled" "disabled (stock Ubuntu 22.04)"
        fi
    fi
    if [[ -b /dev/zram0 ]] || lsmod 2>/dev/null | grep -q '^zram\s'; then
        write_csv "System Configuration Files" \
            "/dev/zram*" \
            "zram compressed RAM block device is configured" \
            "present" "Not configured (stock)"
    fi

    # Swap file size/usage
    local swap_size; swap_size=$(free -h 2>/dev/null | grep -i swap | awk '{print $2}')
    if [[ -n "$swap_size" && "$swap_size" != "0B" && "$swap_size" != "0" ]]; then
        write_csv "System Configuration Files" \
            "/swapfile or swap partition" \
            "Swap configured: $swap_size" \
            "$swap_size" "(varies by install)"
    fi

    # --- ulimits / limits.conf ---
    info "Checking ulimits/limits.conf..."
    if [[ -f /etc/security/limits.conf ]]; then
        local limits_custom; limits_custom=$(grep -vP '^\s*#|^\s*$' /etc/security/limits.conf 2>/dev/null | tr '\n' ';')
        if [[ -n "$limits_custom" ]]; then
            write_csv "System Configuration Files" \
                "/etc/security/limits.conf" \
                "Custom ulimit entries in /etc/security/limits.conf" \
                "$limits_custom" "(empty/commented — stock)"
        fi
    fi
    while IFS= read -r f; do
        local lc; lc=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
        if [[ -n "$lc" ]]; then
            write_csv "System Configuration Files" \
                "$f" \
                "Custom ulimit drop-in file in /etc/security/limits.d/" \
                "$lc" "(none — stock)"
        fi
    done < <(find /etc/security/limits.d -maxdepth 1 -name '*.conf' 2>/dev/null | sort)

    # --- logrotate customisations ---
    info "Checking logrotate configuration..."
    while IFS= read -r f; do
        local bname; bname=$(basename "$f")
        # Files not from standard packages
        local pkg; pkg=$(dpkg -S "$f" 2>/dev/null | cut -d: -f1 || echo "")
        if [[ -z "$pkg" ]]; then
            write_csv "System Configuration Files" \
                "$f" \
                "Custom logrotate configuration (not from a package)" \
                "$(cat "$f" 2>/dev/null | tr '\n' ';')" "(not in stock)"
        fi
    done < <(find /etc/logrotate.d -maxdepth 1 -type f 2>/dev/null | sort)

    # --- rsyslog / journald ---
    info "Checking rsyslog/journald configuration..."
    local journald_conf="/etc/systemd/journald.conf"
    if [[ -f "$journald_conf" ]]; then
        local jd_custom; jd_custom=$(grep -vP '^\s*#|^\s*$|\[Journal\]' "$journald_conf" 2>/dev/null | tr '\n' ';')
        if [[ -n "$jd_custom" ]]; then
            write_csv "System Configuration Files" \
                "$journald_conf" \
                "Custom journald settings (e.g. Storage, RateLimitBurst, MaxRetentionSec)" \
                "$jd_custom" "(commented defaults — stock)"
        fi
    fi
    while IFS= read -r f; do
        local rsc; rsc=$(grep -vP '^\s*#|^\s*$' "$f" 2>/dev/null | tr '\n' ';')
        if [[ -n "$rsc" ]]; then
            write_csv "System Configuration Files" \
                "$f" \
                "Custom rsyslog configuration in /etc/rsyslog.d/" \
                "$rsc" "(standard rsyslog rules — stock)"
        fi
    done < <(find /etc/rsyslog.d -maxdepth 1 -name '*.conf' 2>/dev/null | sort)
}

# ===========================================================================
# CATEGORY 12: Desktop Environment
# ===========================================================================
audit_desktop() {
    section "12. Desktop Environment"

    # Check if a desktop environment is present at all
    local de_present=false
    if [[ -d /usr/share/gnome || -d /usr/share/xfce4 || -d /usr/share/kde4 || \
          -d /usr/share/plasma ]] || cmd_exists gnome-shell || cmd_exists Xorg; then
        de_present=true
    fi

    if ! $de_present; then
        ok "No desktop environment detected (headless/server install)."
        return
    fi

    # --- Display manager ---
    info "Checking display manager..."
    local dm_link; dm_link=$(cat /etc/X11/default-display-manager 2>/dev/null || \
                             readlink -f /etc/alternatives/x-display-manager 2>/dev/null || echo "unknown")
    if [[ -n "$dm_link" && "$dm_link" != "/usr/sbin/gdm3" && "$dm_link" != "unknown" ]]; then
        write_csv "Desktop Environment" \
            "/etc/X11/default-display-manager" \
            "Display manager is not the stock GDM3" \
            "$dm_link" "/usr/sbin/gdm3 (stock Ubuntu Desktop)"
    fi

    # --- GNOME extensions ---
    info "Checking GNOME extensions..."
    # System-wide extensions
    local sys_exts; sys_exts=$(find /usr/share/gnome-shell/extensions -maxdepth 1 -mindepth 1 -type d 2>/dev/null | tr '\n' ';')
    local stock_exts=("ubuntu-dock@ubuntu.com" "ubuntu-appindicators@ubuntu.com"
                      "ding@rastersoft.com" "desktopicons-neo@rastersoft.com")
    while IFS= read -r ext_dir; do
        [[ -d "$ext_dir" ]] || continue
        local ext_id; ext_id=$(basename "$ext_dir")
        local is_stock=false
        for se in "${stock_exts[@]}"; do [[ "$ext_id" == "$se" ]] && is_stock=true && break; done
        if ! $is_stock; then
            write_csv "Desktop Environment" \
                "$ext_dir" \
                "Custom GNOME extension installed system-wide: $ext_id" \
                "$(cat "${ext_dir}/metadata.json" 2>/dev/null | tr '\n' ';' | head -c 200)" "(not in stock Ubuntu)"
        fi
    done < <(find /usr/share/gnome-shell/extensions -maxdepth 1 -mindepth 1 -type d 2>/dev/null)

    # Per-user GNOME extensions
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -lt 1000 ]] && continue
        [[ -d "${homedir}/.local/share/gnome-shell/extensions" ]] || continue
        while IFS= read -r ext_dir; do
            local ext_id; ext_id=$(basename "$ext_dir")
            write_csv "Desktop Environment" \
                "$ext_dir" \
                "User $username has a local GNOME extension: $ext_id" \
                "$(grep -m1 '"'"'\"name\"'"'"' "${ext_dir}/metadata.json" 2>/dev/null | sed 's/.*: *"\([^"]*\)".*/\1/' || echo 'installed')" "(not in stock Ubuntu)"
        done < <(find "${homedir}/.local/share/gnome-shell/extensions" -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    done < /etc/passwd

    # --- Custom themes ---
    info "Checking custom themes/icons..."
    if [[ -d /usr/share/themes ]]; then
        while IFS= read -r theme_dir; do
            local tname; tname=$(basename "$theme_dir")
            if [[ ! "$tname" =~ ^(Adwaita|Adwaita-dark|HighContrast|HighContrastInverse|Yaru|Yaru-dark|Yaru-light|Default|Emacs)$ ]]; then
                write_csv "Desktop Environment" \
                    "$theme_dir" \
                    "Custom GTK theme installed: $tname" \
                    "present" "(not in stock Ubuntu)"
            fi
        done < <(find /usr/share/themes -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    fi

    # --- Autostart applications ---
    info "Checking desktop autostart applications..."
    local autostart_dirs=("/etc/xdg/autostart")
    # System-wide autostart
    while IFS= read -r f; do
        local bname; bname=$(basename "$f")
        local pkg; pkg=$(dpkg -S "$f" 2>/dev/null | cut -d: -f1 || echo "")
        if [[ -z "$pkg" ]]; then
            write_csv "Desktop Environment" \
                "$f" \
                "Custom autostart desktop entry (not from a package)" \
                "$(grep -P '(Name|Exec)=' "$f" 2>/dev/null | tr '\n' ';')" "(not in stock)"
        fi
    done < <(find /etc/xdg/autostart -maxdepth 1 -name '*.desktop' 2>/dev/null | sort)

    # Per-user autostart
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -lt 1000 ]] && continue
        [[ -d "${homedir}/.config/autostart" ]] || continue
        while IFS= read -r f; do
            write_csv "Desktop Environment" \
                "$f" \
                "User $username has an autostart application: $(basename "$f")" \
                "$(grep -P '(Name|Exec)=' "$f" 2>/dev/null | tr '\n' ';')" "(none — stock)"
        done < <(find "${homedir}/.config/autostart" -maxdepth 1 -name '*.desktop' 2>/dev/null)
    done < /etc/passwd
}

# ===========================================================================
# Summary
# ===========================================================================
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${GREEN}║              AUDIT COMPLETE — SUMMARY            ║${NC}"
    echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${BOLD}Output CSV:${NC} $OUTPUT_CSV"
    echo -e "  ${BOLD}Log file  :${NC} $LOG_FILE"
    echo ""
    echo -e "  ${BOLD}Changes by category:${NC}"
    local total=0
    for cat in "${CATEGORIES[@]}"; do
        local count=${CATEGORY_COUNTS["$cat"]:-0}
        total=$(( total + count ))
        printf "  %-45s %3d\n" "$cat" "$count"
    done
    echo ""
    echo -e "  ${BOLD}${YELLOW}TOTAL CHANGES DETECTED: $total${NC}"
    echo ""

    # Write summary rows to CSV
    echo "" >> "$OUTPUT_CSV"
    echo '"--- SUMMARY ---","","","",""' >> "$OUTPUT_CSV"
    for cat in "${CATEGORIES[@]}"; do
        local count=${CATEGORY_COUNTS["$cat"]:-0}
        echo "$(csv_escape "SUMMARY"),$(csv_escape "$cat"),$(csv_escape "Total changes detected"),$(csv_escape "$count"),$(csv_escape "")" >> "$OUTPUT_CSV"
    done
    echo "$(csv_escape "SUMMARY"),$(csv_escape "ALL CATEGORIES"),$(csv_escape "Grand total changes detected"),$(csv_escape "$total"),$(csv_escape "")" >> "$OUTPUT_CSV"

    log "Audit complete. Total changes: $total. CSV: $OUTPUT_CSV"
}

# ===========================================================================
# Main entry point
# ===========================================================================
main() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔═══════════════════════════════════════════════════════╗"
    echo "  ║   Ubuntu 22.04 Configuration Audit Script v${SCRIPT_VERSION}     ║"
    echo "  ╚═══════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    preflight_checks
    init_csv

    audit_network
    audit_kernel_boot
    audit_storage
    audit_gpu_drivers
    audit_services
    audit_packages
    audit_user_environment
    audit_languages
    audit_security
    audit_containers_virt
    audit_system_config
    audit_desktop

    print_summary
}

main "$@"
