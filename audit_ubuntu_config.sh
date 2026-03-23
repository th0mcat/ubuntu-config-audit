#!/usr/bin/env bash
# =============================================================================
# audit_ubuntu_config.sh
# Comprehensive Ubuntu 22.04 Configuration Audit Script
#
# Detects changes made from a stock Ubuntu 22.04 installation and outputs
# a timestamped CSV file suitable for Excel.
#
# Usage:   sudo ./audit_ubuntu_config.sh [--output <file>] [--no-color]
# Requires: root / sudo
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
OUTPUT_FILE=""
NO_COLOR=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output|-o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --no-color)
            NO_COLOR=1
            shift
            ;;
        --help|-h)
            echo "Usage: sudo $0 [--output <file>] [--no-color]"
            echo "  --output, -o  Specify output CSV file path"
            echo "  --no-color    Disable colored terminal output"
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            echo "Use --help for usage information." >&2
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Color definitions (disabled when --no-color is set or not a TTY)
# ---------------------------------------------------------------------------
if [[ $NO_COLOR -eq 0 ]] && [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' RESET=''
fi

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
log_section() { echo -e "\n${BOLD}${BLUE}>>> $* ${RESET}"; }

# ---------------------------------------------------------------------------
# Root check
# ---------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root.  Try: sudo $0"
    exit 1
fi

# ---------------------------------------------------------------------------
# Output file
# ---------------------------------------------------------------------------
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
DATE_LABEL=$(date +%Y-%m-%d)
if [[ -z "$OUTPUT_FILE" ]]; then
    OUTPUT_FILE="ubuntu_config_audit_${DATE_LABEL}.csv"
fi

log_info "Audit started at $(date)"
log_info "Output file: ${OUTPUT_FILE}"

# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------

# Associative array to count findings per category
declare -A CATEGORY_COUNT

# Write the CSV header
csv_init() {
    printf '%s\n' "Category,File/Location,Detail,Current Value,Default/Expected Value" > "$OUTPUT_FILE"
}

# Escape a single field for RFC-4180 CSV:
# wrap in quotes, escape internal quotes with ""
csv_field() {
    local val="$1"
    val="${val//\"/\"\"}"          # double any existing double-quotes
    printf '"%s"' "$val"
}

# Append one row to the CSV
# Usage: csv_row CATEGORY LOCATION DETAIL CURRENT DEFAULT
csv_row() {
    local category="$1" location="$2" detail="$3" current="$4" default="$5"
    printf '%s,%s,%s,%s,%s\n' \
        "$(csv_field "$category")" \
        "$(csv_field "$location")" \
        "$(csv_field "$detail")" \
        "$(csv_field "$current")" \
        "$(csv_field "$default")" >> "$OUTPUT_FILE"
    CATEGORY_COUNT["$category"]=$(( ${CATEGORY_COUNT["$category"]:-0} + 1 ))
}

# Check if a command exists
cmd_exists() { command -v "$1" &>/dev/null; }

# Run a command with a timeout; suppress output and return empty on timeout/failure
# Usage: run_timeout <seconds> <cmd> [args...]
run_timeout() {
    local secs="$1"; shift
    timeout "$secs" "$@" 2>/dev/null || true
}

csv_init

# ===========================================================================
# 1. NETWORK CONFIGURATION
# ===========================================================================
log_section "1. Network Configuration"
CAT="Network Configuration"

# --- MTU settings ---
log_info "Checking MTU settings..."
if cmd_exists ip; then
    while IFS= read -r line; do
        iface=$(echo "$line" | awk '{print $2}' | tr -d ':')
        mtu=$(echo "$line" | grep -oP 'mtu \K[0-9]+' || true)
        [[ -z "$mtu" ]] && continue
        [[ "$iface" == "lo" ]] && continue
        if [[ "$mtu" -ne 1500 ]]; then
            csv_row "$CAT" "ip link / interface $iface" \
                "Non-default MTU on interface $iface" \
                "$mtu" "1500"
        fi
    done < <(ip link show 2>/dev/null | grep -E '^[0-9]+:')
fi

# --- DNS configuration ---
log_info "Checking DNS configuration..."
# systemd-resolved status
if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    : # default – running
else
    if systemctl list-unit-files systemd-resolved.service &>/dev/null; then
        res_state=$(systemctl is-enabled systemd-resolved 2>/dev/null || echo "unknown")
        csv_row "$CAT" "/etc/systemd/system/systemd-resolved.service" \
            "systemd-resolved is not active (state: $res_state)" \
            "$res_state" "enabled/active"
    fi
fi

# dnsmasq
if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    csv_row "$CAT" "/etc/dnsmasq.conf" \
        "dnsmasq is running (replaces systemd-resolved)" \
        "active" "not installed (stock)"
fi

# unbound
if systemctl is-active --quiet unbound 2>/dev/null; then
    csv_row "$CAT" "/etc/unbound/unbound.conf" \
        "unbound DNS resolver is running" \
        "active" "not installed (stock)"
fi

# /etc/resolv.conf symlink / content
if [[ -f /etc/resolv.conf ]]; then
    if [[ -L /etc/resolv.conf ]]; then
        link_target=$(readlink -f /etc/resolv.conf)
        default_target="/run/systemd/resolve/stub-resolv.conf"
        if [[ "$link_target" != "$default_target" ]]; then
            csv_row "$CAT" "/etc/resolv.conf" \
                "resolv.conf symlink points to non-default target" \
                "$link_target" "$default_target"
        fi
    else
        csv_row "$CAT" "/etc/resolv.conf" \
            "resolv.conf is a regular file, not a symlink (manually managed)" \
            "$(grep -v '^#' /etc/resolv.conf | grep -v '^$' | head -5 | tr '\n' ';')" \
            "symlink -> /run/systemd/resolve/stub-resolv.conf"
    fi
fi

# --- Static IP vs DHCP (Netplan) ---
log_info "Checking Netplan configurations..."
for np_file in /etc/netplan/*.yaml /etc/netplan/*.yml; do
    [[ -f "$np_file" ]] || continue
    if grep -qiE '^\s+addresses:' "$np_file" 2>/dev/null; then
        addrs=$(grep -A1 'addresses:' "$np_file" | grep -v 'addresses:' | tr -d ' -' | head -5 | tr '\n' ';')
        csv_row "$CAT" "$np_file" \
            "Static IP assignment found in Netplan config" \
            "$addrs" "DHCP (stock)"
    fi
    if grep -qiE 'dhcp4:\s*no|dhcp6:\s*no' "$np_file" 2>/dev/null; then
        csv_row "$CAT" "$np_file" \
            "DHCP explicitly disabled in Netplan config" \
            "$(grep -E 'dhcp[46]:' "$np_file" | tr '\n' ';')" "dhcp4: true"
    fi
done

# /etc/network/interfaces customizations
if [[ -f /etc/network/interfaces ]]; then
    non_default=$(grep -v '^#' /etc/network/interfaces | grep -v '^$' | grep -v 'source ' || true)
    if [[ -n "$non_default" ]]; then
        csv_row "$CAT" "/etc/network/interfaces" \
            "Custom network interface configuration present" \
            "$(echo "$non_default" | head -10 | tr '\n' ';')" \
            "managed by Netplan (stock Ubuntu 22.04)"
    fi
fi

# --- Custom routes ---
log_info "Checking custom routes..."
if cmd_exists ip; then
    custom_routes=$(ip route show 2>/dev/null | grep -v '^default' | grep -v '^169.254' | grep -v 'proto kernel' || true)
    if [[ -n "$custom_routes" ]]; then
        while IFS= read -r route; do
            [[ -z "$route" ]] && continue
            csv_row "$CAT" "ip route" \
                "Custom static route configured" \
                "$route" "No custom routes (stock)"
        done <<< "$custom_routes"
    fi
fi

# --- iptables rules ---
log_info "Checking iptables/nftables rules..."
if cmd_exists iptables; then
    ipt_rules=$(iptables -S 2>/dev/null | grep -v '^-P .* ACCEPT$' | grep -v '^-P .* DROP$' | grep -c '^-A' || true)
    if [[ "${ipt_rules:-0}" -gt 0 ]]; then
        csv_row "$CAT" "iptables" \
            "Custom iptables rules present ($ipt_rules rules)" \
            "$ipt_rules rules" "0 custom rules (stock)"
    fi
fi
if cmd_exists ip6tables; then
    ipt6_rules=$(ip6tables -S 2>/dev/null | grep -c '^-A' || true)
    if [[ "${ipt6_rules:-0}" -gt 0 ]]; then
        csv_row "$CAT" "ip6tables" \
            "Custom ip6tables rules present ($ipt6_rules rules)" \
            "$ipt6_rules rules" "0 custom rules (stock)"
    fi
fi
if cmd_exists nft; then
    nft_rules=$(nft list ruleset 2>/dev/null | grep -c 'rule' || true)
    if [[ "${nft_rules:-0}" -gt 0 ]]; then
        csv_row "$CAT" "nftables" \
            "Custom nftables rules present ($nft_rules entries)" \
            "$nft_rules entries" "0 custom rules (stock)"
    fi
fi

# Persistent iptables
if [[ -f /etc/iptables/rules.v4 ]]; then
    rule_count=$(grep -c '^-A' /etc/iptables/rules.v4 2>/dev/null || true)
    rule_count=${rule_count:-0}
    if [[ "$rule_count" -gt 0 ]]; then
        csv_row "$CAT" "/etc/iptables/rules.v4" \
            "Persistent iptables IPv4 rules present ($rule_count rules)" \
            "$rule_count rules" "not present (stock)"
    fi
fi
if [[ -f /etc/iptables/rules.v6 ]]; then
    rule_count=$(grep -c '^-A' /etc/iptables/rules.v6 2>/dev/null || true)
    rule_count=${rule_count:-0}
    if [[ "$rule_count" -gt 0 ]]; then
        csv_row "$CAT" "/etc/iptables/rules.v6" \
            "Persistent iptables IPv6 rules present ($rule_count rules)" \
            "$rule_count rules" "not present (stock)"
    fi
fi

# --- Bonding / Bridging / VLAN ---
log_info "Checking bonding/bridging/VLAN..."
if cmd_exists ip; then
    bond_ifaces=$(ip link show type bond 2>/dev/null | grep -oP '^\d+: \K[^:@]+' || true)
    for b in $bond_ifaces; do
        csv_row "$CAT" "/proc/net/bonding/$b" \
            "Network bonding interface configured: $b" \
            "present" "not present (stock)"
    done
    bridge_ifaces=$(ip link show type bridge 2>/dev/null | grep -oP '^\d+: \K[^:@]+' | grep -v '^(virbr|docker|br-)' || true)
    for br in $bridge_ifaces; do
        csv_row "$CAT" "ip link (bridge)" \
            "Network bridge interface configured: $br" \
            "present" "not present (stock)"
    done
    vlan_ifaces=$(ip link show type vlan 2>/dev/null | grep -oP '^\d+: \K[^:@]+' || true)
    for vl in $vlan_ifaces; do
        csv_row "$CAT" "ip link (vlan)" \
            "VLAN interface configured: $vl" \
            "present" "not present (stock)"
    done
fi

# --- TCP/UDP sysctl net.* parameters ---
log_info "Checking net.* sysctl parameters..."
declare -A NET_DEFAULTS=(
    ["net.core.rmem_max"]="212992"
    ["net.core.wmem_max"]="212992"
    ["net.core.rmem_default"]="212992"
    ["net.core.wmem_default"]="212992"
    ["net.core.netdev_max_backlog"]="1000"
    ["net.core.somaxconn"]="4096"
    ["net.ipv4.tcp_rmem"]="4096 131072 6291456"
    ["net.ipv4.tcp_wmem"]="4096 16384 4194304"
    ["net.ipv4.tcp_congestion_control"]="cubic"
    ["net.ipv4.ip_forward"]="0"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.tcp_tw_reuse"]="2"
    ["net.ipv6.conf.all.forwarding"]="0"
    ["net.ipv4.conf.all.rp_filter"]="2"
    ["net.ipv4.conf.default.rp_filter"]="2"
    ["net.ipv4.tcp_keepalive_time"]="7200"
    ["net.ipv4.tcp_keepalive_probes"]="9"
    ["net.ipv4.tcp_keepalive_intvl"]="75"
    ["net.ipv4.tcp_fin_timeout"]="60"
)
for key in "${!NET_DEFAULTS[@]}"; do
    current_val=$(sysctl -n "$key" 2>/dev/null | tr '\t' ' ' || true)
    default_val="${NET_DEFAULTS[$key]}"
    if [[ -n "$current_val" && "$current_val" != "$default_val" ]]; then
        csv_row "$CAT" "sysctl $key" \
            "Non-default TCP/IP kernel parameter" \
            "$current_val" "$default_val"
    fi
done

# ===========================================================================
# 2. KERNEL AND BOOT
# ===========================================================================
log_section "2. Kernel and Boot"
CAT="Kernel and Boot"

# --- GRUB customizations ---
log_info "Checking GRUB configuration..."
if [[ -f /etc/default/grub ]]; then
    cmdline=$(grep '^GRUB_CMDLINE_LINUX=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX=//' | tr -d '"' || true)
    cmdline_default=$(grep '^GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | sed 's/GRUB_CMDLINE_LINUX_DEFAULT=//' | tr -d '"' || true)

    if [[ -n "$cmdline" ]]; then
        csv_row "$CAT" "/etc/default/grub" \
            "Custom GRUB_CMDLINE_LINUX parameters set" \
            "$cmdline" "(empty string)"
    fi
    # Default is 'quiet splash'
    if [[ "$cmdline_default" != "quiet splash" ]]; then
        csv_row "$CAT" "/etc/default/grub" \
            "GRUB_CMDLINE_LINUX_DEFAULT differs from default" \
            "$cmdline_default" "quiet splash"
    fi
    grub_timeout=$(grep '^GRUB_TIMEOUT=' /etc/default/grub | sed 's/GRUB_TIMEOUT=//' || true)
    if [[ -n "$grub_timeout" && "$grub_timeout" != "0" ]]; then
        csv_row "$CAT" "/etc/default/grub" \
            "GRUB_TIMEOUT changed from default" \
            "$grub_timeout" "0"
    fi
fi

# Custom grub.d snippets
if [[ -d /etc/grub.d ]]; then
    for f in /etc/grub.d/*; do
        fname=$(basename "$f")
        [[ "$fname" =~ ^(00_header|05_debian_theme|10_linux|20_linux_xen|30_os-prober|40_custom|41_custom|README)$ ]] && continue
        [[ -f "$f" ]] || continue
        csv_row "$CAT" "$f" \
            "Custom GRUB script present in /etc/grub.d/" \
            "present" "not present (stock)"
    done
fi

# --- Non-default kernel versions ---
log_info "Checking installed kernels..."
running_kernel=$(uname -r)
if cmd_exists dpkg; then
    mapfile -t installed_kernels < <(dpkg --list 'linux-image-*' 2>/dev/null | awk '/^ii/{print $2}' | grep -v 'linux-image-generic' || true)
    for k in "${installed_kernels[@]}"; do
        kver=$(echo "$k" | sed 's/linux-image-//')
        if [[ "$kver" != "$running_kernel" && ! "$kver" =~ ^[0-9]+\.[0-9]+-generic$ ]]; then
            csv_row "$CAT" "dpkg / /boot" \
                "Additional kernel package installed: $k" \
                "$kver" "single stock kernel"
        fi
    done
fi
# Flag non-LTS kernels (stock Ubuntu 22.04 uses 5.15)
if [[ "$running_kernel" != 5.15* ]]; then
    csv_row "$CAT" "uname -r" \
        "Running kernel is not the stock Ubuntu 22.04 kernel" \
        "$running_kernel" "5.15.x-xx-generic"
fi

# --- Custom kernel modules ---
log_info "Checking loaded kernel modules..."
# Known non-stock modules (common additions)
NON_STOCK_MODULES=(zfs spl nvidia nvidia_drm nvidia_modeset nvidia_uvm vboxdrv vboxnetflt vboxnetadp wireguard)
for mod in "${NON_STOCK_MODULES[@]}"; do
    if lsmod 2>/dev/null | grep -qw "^${mod}"; then
        csv_row "$CAT" "lsmod / /etc/modules" \
            "Non-stock kernel module loaded: $mod" \
            "loaded" "not loaded (stock)"
    fi
done

# Custom module load files
for f in /etc/modules-load.d/*.conf; do
    [[ -f "$f" ]] || continue
    fname=$(basename "$f")
    content=$(grep -v '^#' "$f" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    csv_row "$CAT" "$f" \
        "Custom kernel module autoload file: $fname" \
        "$content" "not present (stock)"
done

# --- sysctl.conf and sysctl.d/ ---
log_info "Checking sysctl configurations..."
sysctl_files=(/etc/sysctl.conf)
mapfile -t sysctl_d_files < <(find /etc/sysctl.d/ -name '*.conf' 2>/dev/null | sort || true)
sysctl_files+=("${sysctl_d_files[@]}")

for sf in "${sysctl_files[@]}"; do
    [[ -f "$sf" ]] || continue
    custom_params=$(grep -v '^#' "$sf" | grep -v '^$' | grep '=' || true)
    [[ -z "$custom_params" ]] && continue
    fname=$(basename "$sf")
    # Skip stock files
    [[ "$fname" == "10-console-messages.conf" ]] && continue
    [[ "$fname" == "10-ipv6-privacy.conf" ]] && continue
    [[ "$fname" == "10-kernel-hardening.conf" ]] && continue
    [[ "$fname" == "10-magic-sysrq.conf" ]] && continue
    [[ "$fname" == "10-network-security.conf" ]] && continue
    [[ "$fname" == "10-ptrace.conf" ]] && continue
    [[ "$fname" == "10-zeropage.conf" ]] && continue
    [[ "$fname" == "99-sysctl.conf" ]] && continue
    while IFS= read -r param; do
        key=$(echo "$param" | cut -d= -f1 | tr -d ' ')
        val=$(echo "$param" | cut -d= -f2- | tr -d ' ')
        csv_row "$CAT" "$sf" \
            "Custom sysctl parameter: $key" \
            "$key=$val" "not set (stock)"
    done <<< "$custom_params"
done

# --- initramfs customizations ---
log_info "Checking initramfs configurations..."
if [[ -d /etc/initramfs-tools ]]; then
    for f in /etc/initramfs-tools/modules; do
        [[ -f "$f" ]] || continue
        custom_mods=$(grep -v '^#' "$f" | grep -v '^$' || true)
        if [[ -n "$custom_mods" ]]; then
            csv_row "$CAT" "$f" \
                "Custom modules added to initramfs" \
                "$custom_mods" "(empty)"
        fi
    done
    for hook in /etc/initramfs-tools/hooks/*; do
        [[ -f "$hook" ]] || continue
        csv_row "$CAT" "$hook" \
            "Custom initramfs hook script present" \
            "$(basename "$hook")" "not present (stock)"
    done
    for script_dir in /etc/initramfs-tools/scripts/init-bottom /etc/initramfs-tools/scripts/init-premount; do
        [[ -d "$script_dir" ]] || continue
        for s in "$script_dir"/*; do
            [[ -f "$s" ]] || continue
            [[ "$(basename "$s")" == "ORDER" ]] && continue
            csv_row "$CAT" "$s" \
                "Custom initramfs script present in $(basename "$script_dir")" \
                "$(basename "$s")" "not present (stock)"
        done
    done
fi

# ===========================================================================
# 3. STORAGE AND FILESYSTEMS
# ===========================================================================
log_section "3. Storage and Filesystems"
CAT="Storage and Filesystems"

# --- ZFS ---
log_info "Checking ZFS configuration..."
if cmd_exists zpool; then
    zpool_list=$(zpool list -H 2>/dev/null || true)
    if [[ -n "$zpool_list" ]]; then
        while IFS= read -r pool_line; do
            pool_name=$(echo "$pool_line" | awk '{print $1}')
            pool_size=$(echo "$pool_line" | awk '{print $2}')
            csv_row "$CAT" "zpool" \
                "ZFS pool configured: $pool_name ($pool_size)" \
                "present" "not present (stock)"
        done <<< "$zpool_list"
    fi
fi
if [[ -f /etc/modprobe.d/zfs.conf ]]; then
    zfs_opts=$(grep -v '^#' /etc/modprobe.d/zfs.conf | grep -v '^$' || true)
    if [[ -n "$zfs_opts" ]]; then
        csv_row "$CAT" "/etc/modprobe.d/zfs.conf" \
            "Custom ZFS module parameters set" \
            "$zfs_opts" "not present (stock)"
    fi
fi

# --- LVM ---
log_info "Checking LVM configuration..."
if cmd_exists pvs; then
    pvs_out=$(pvs --noheadings -o pv_name,vg_name 2>/dev/null || true)
    if [[ -n "$pvs_out" ]]; then
        while IFS= read -r pv_line; do
            pv=$(echo "$pv_line" | awk '{print $1}')
            vg=$(echo "$pv_line" | awk '{print $2}')
            csv_row "$CAT" "lvs / pvs" \
                "LVM physical volume $pv in volume group $vg" \
                "present" "no LVM (stock)"
        done <<< "$pvs_out"
    fi
fi

# --- Custom fstab entries ---
log_info "Checking /etc/fstab..."
if [[ -f /etc/fstab ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^# ]] && continue
        [[ -z "$line" ]] && continue
        dev=$(echo "$line" | awk '{print $1}')
        mnt=$(echo "$line" | awk '{print $2}')
        fstype=$(echo "$line" | awk '{print $3}')
        opts=$(echo "$line" | awk '{print $4}')
        # Skip standard stock entries
        [[ "$mnt" == "/" ]] && continue
        [[ "$mnt" == "/boot" ]] && continue
        [[ "$mnt" == "/boot/efi" ]] && continue
        [[ "$mnt" == "none" ]] && continue
        [[ "$fstype" == "swap" ]] && continue
        [[ "$dev" == "tmpfs" ]] && continue
        [[ "$dev" == "proc" ]] && continue
        csv_row "$CAT" "/etc/fstab" \
            "Custom fstab entry: $mnt ($fstype)" \
            "$dev $mnt $fstype $opts" "not present (stock)"
    done < /etc/fstab

    # Check for non-default mount options on root
    root_line=$(grep -E '\s+/\s+' /etc/fstab | grep -v '^#' | head -1 || true)
    if [[ -n "$root_line" ]]; then
        root_opts=$(echo "$root_line" | awk '{print $4}')
        if [[ "$root_opts" != *"defaults"* ]] && [[ "$root_opts" != "errors=remount-ro" ]]; then
            csv_row "$CAT" "/etc/fstab" \
                "Non-default mount options on root filesystem" \
                "$root_opts" "errors=remount-ro"
        fi
    fi
fi

# --- mdadm RAID ---
log_info "Checking mdadm RAID..."
if [[ -f /proc/mdstat ]]; then
    raid_devs=$(grep '^md' /proc/mdstat 2>/dev/null || true)
    if [[ -n "$raid_devs" ]]; then
        while IFS= read -r r; do
            csv_row "$CAT" "/proc/mdstat" \
                "Software RAID device configured: $(echo "$r" | awk '{print $1}')" \
                "$r" "not present (stock)"
        done <<< "$raid_devs"
    fi
fi
if [[ -f /etc/mdadm/mdadm.conf ]]; then
    arrays=$(grep '^ARRAY' /etc/mdadm/mdadm.conf 2>/dev/null || true)
    if [[ -n "$arrays" ]]; then
        csv_row "$CAT" "/etc/mdadm/mdadm.conf" \
            "mdadm RAID arrays defined in configuration" \
            "$(echo "$arrays" | wc -l) array(s)" "not present (stock)"
    fi
fi

# --- NFS/CIFS/SMB mounts ---
log_info "Checking NFS/CIFS mounts..."
if cmd_exists findmnt; then
    nfs_mounts=$(findmnt -t nfs,nfs4,cifs,smb2 --noheadings 2>/dev/null || true)
    if [[ -n "$nfs_mounts" ]]; then
        while IFS= read -r m; do
            target=$(echo "$m" | awk '{print $1}')
            source=$(echo "$m" | awk '{print $2}')
            fstype=$(echo "$m" | awk '{print $3}')
            csv_row "$CAT" "findmnt ($fstype)" \
                "Network filesystem mounted: $target" \
                "$source -> $target" "not mounted (stock)"
        done <<< "$nfs_mounts"
    fi
fi

# --- Disk scheduler settings ---
log_info "Checking disk schedulers..."
for dev in /sys/block/*/queue/scheduler; do
    [[ -f "$dev" ]] || continue
    disk=$(echo "$dev" | cut -d/ -f4)
    [[ "$disk" == loop* ]] && continue
    [[ "$disk" == ram* ]] && continue
    scheduler=$(cat "$dev" 2>/dev/null || true)
    active=$(echo "$scheduler" | grep -oP '\[\K[^\]]+' || true)
    if [[ -n "$active" && "$active" != "none" && "$active" != "mq-deadline" ]]; then
        csv_row "$CAT" "/sys/block/$disk/queue/scheduler" \
            "Non-default I/O scheduler for $disk" \
            "$active" "mq-deadline (stock)"
    fi
done

# --- SMART monitoring ---
if cmd_exists smartctl || [[ -f /etc/smartd.conf ]]; then
    if systemctl is-active --quiet smartd 2>/dev/null || systemctl is-enabled --quiet smartd 2>/dev/null; then
        csv_row "$CAT" "/etc/smartd.conf" \
            "SMART disk monitoring daemon (smartd) is configured" \
            "active/enabled" "not present (stock)"
    fi
fi

# ===========================================================================
# 4. GPU AND HARDWARE DRIVERS
# ===========================================================================
log_section "4. GPU and Hardware Drivers"
CAT="GPU and Hardware Drivers"

# --- NVIDIA drivers ---
log_info "Checking GPU/NVIDIA drivers..."
if cmd_exists nvidia-smi; then
    nvidia_version=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1 || true)
    csv_row "$CAT" "nvidia-smi" \
        "NVIDIA proprietary driver installed (nouveau replaced)" \
        "$nvidia_version" "nouveau (stock open-source)"
fi
if dpkg --list 'nvidia-driver-*' 2>/dev/null | grep -q '^ii'; then
    nvidia_pkgs=$(dpkg --list 'nvidia-driver-*' 2>/dev/null | awk '/^ii/{print $2" "$3}' | tr '\n' ';' || true)
    csv_row "$CAT" "dpkg (nvidia)" \
        "NVIDIA driver package(s) installed" \
        "$nvidia_pkgs" "not installed (stock)"
fi

# --- CUDA ---
if [[ -d /usr/local/cuda ]]; then
    cuda_ver=$(cat /usr/local/cuda/version.txt 2>/dev/null || cat /usr/local/cuda/version.json 2>/dev/null | grep -oP '"cuda"\s*:\s*"\K[^"]+' || ls -d /usr/local/cuda-* 2>/dev/null | head -1 | grep -oP 'cuda-\K.*' || echo "unknown")
    csv_row "$CAT" "/usr/local/cuda" \
        "CUDA toolkit installed" \
        "${cuda_ver:-unknown}" "not installed (stock)"
fi

# --- Other proprietary drivers ---
if cmd_exists ubuntu-drivers; then
    prop_drivers=$(run_timeout 30 ubuntu-drivers list || true)
    if [[ -n "$prop_drivers" ]]; then
        while IFS= read -r drv; do
            csv_row "$CAT" "ubuntu-drivers" \
                "Proprietary driver recommended/available: $drv" \
                "$drv" "open-source driver (stock)"
        done <<< "$prop_drivers"
    fi
fi

# --- Custom Xorg/display configuration ---
log_info "Checking Xorg/display configuration..."
for xorg_conf in /etc/X11/xorg.conf /etc/X11/xorg.conf.d/*.conf; do
    [[ -f "$xorg_conf" ]] || continue
    csv_row "$CAT" "$xorg_conf" \
        "Custom Xorg configuration file present" \
        "$(wc -l < "$xorg_conf") lines" "not present (stock)"
done

# --- Hardware firmware packages ---
if cmd_exists dpkg; then
    fw_pkgs=$(dpkg --list '*firmware*' 2>/dev/null | awk '/^ii/{print $2" "$3}' | grep -v 'linux-firmware' || true)
    if [[ -n "$fw_pkgs" ]]; then
        while IFS= read -r pkg; do
            csv_row "$CAT" "dpkg (firmware)" \
                "Additional firmware package installed: $pkg" \
                "$pkg" "only linux-firmware (stock)"
        done <<< "$fw_pkgs"
    fi
fi

# ===========================================================================
# 5. SERVICES AND DAEMONS
# ===========================================================================
log_section "5. Services and Daemons"
CAT="Services and Daemons"

# Known stock Ubuntu 22.04 enabled services
STOCK_SERVICES=(
    apparmor atd cron dbus e2scrub_reap fwupd irqbalance
    keyboard-setup logrotate lvm2-monitor
    ModemManager multipathd NetworkManager
    plymouth rsyslog secureboot-db snapd ssh
    systemd-journald systemd-logind systemd-networkd
    systemd-resolved systemd-timesyncd systemd-udevd
    thermald ufw unattended-upgrades upower
    accounts-daemon avahi-daemon bluetooth cups
    networkd-dispatcher packagekit polkit udisks2
    wpa_supplicant gdm
)

log_info "Checking enabled services (non-stock)..."
mapfile -t all_enabled < <(systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' || true)
for svc in "${all_enabled[@]}"; do
    found=0
    for stock in "${STOCK_SERVICES[@]}"; do
        [[ "$svc" == "$stock" ]] && found=1 && break
    done
    if [[ $found -eq 0 ]]; then
        csv_row "$CAT" "systemctl / /etc/systemd/system/" \
            "Non-stock service is enabled: $svc" \
            "enabled" "not enabled (stock)"
    fi
done

# --- Stock services that have been disabled/masked ---
log_info "Checking disabled/masked stock services..."
for svc in "${STOCK_SERVICES[@]}"; do
    state=$(systemctl is-enabled "${svc}.service" 2>/dev/null || echo "not-found")
    if [[ "$state" == "disabled" ]]; then
        csv_row "$CAT" "systemctl $svc" \
            "Stock service has been disabled" \
            "disabled" "enabled (stock)"
    elif [[ "$state" == "masked" ]]; then
        csv_row "$CAT" "systemctl $svc" \
            "Stock service has been masked" \
            "masked" "enabled (stock)"
    fi
done

# --- Custom systemd unit files ---
log_info "Checking custom systemd unit files..."
for unit_dir in /etc/systemd/system /etc/systemd/user; do
    [[ -d "$unit_dir" ]] || continue
    while IFS= read -r unit_file; do
        fname=$(basename "$unit_file")
        # Skip override directories (*.d) and stock targets
        [[ "$fname" == *.d ]] && continue
        [[ "$unit_file" == *.d/* ]] && continue
        [[ -d "$unit_file" ]] && continue
        # Skip well-known symlinks that just enable stock units
        if [[ -L "$unit_file" ]]; then
            link_target=$(readlink "$unit_file" 2>/dev/null || true)
            [[ "$link_target" == /lib/systemd/* ]] && continue
            [[ "$link_target" == /usr/lib/systemd/* ]] && continue
        fi
        csv_row "$CAT" "$unit_file" \
            "Custom systemd unit file present: $fname" \
            "present" "not present (stock)"
    done < <(find "$unit_dir" -maxdepth 2 \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.mount' -o -name '*.target' \) 2>/dev/null | sort)
done

# Check for drop-in override files
for override in /etc/systemd/system/*.d/*.conf /etc/systemd/system/*.service.d/*.conf; do
    [[ -f "$override" ]] || continue
    csv_row "$CAT" "$override" \
        "Systemd service override/drop-in file present" \
        "present" "not present (stock)"
done

# --- SSH configuration changes ---
log_info "Checking SSH configuration..."
if [[ -f /etc/ssh/sshd_config ]]; then
    declare -A SSH_DEFAULTS=(
        ["PermitRootLogin"]="prohibit-password"
        ["PasswordAuthentication"]="yes"
        ["PubkeyAuthentication"]="yes"
        ["X11Forwarding"]="no"
        ["UsePAM"]="yes"
        ["Port"]="22"
    )
    for key in "${!SSH_DEFAULTS[@]}"; do
        current_val=$(grep -iE "^\s*${key}\s+" /etc/ssh/sshd_config 2>/dev/null | tail -1 | awk '{print $2}' || true)
        [[ -z "$current_val" ]] && continue
        if [[ "$current_val" != "${SSH_DEFAULTS[$key]}" ]]; then
            csv_row "$CAT" "/etc/ssh/sshd_config" \
                "SSH config: $key changed from default" \
                "$current_val" "${SSH_DEFAULTS[$key]}"
        fi
    done
fi

# --- Cron jobs ---
log_info "Checking cron jobs..."
for cron_file in /etc/cron.d/* /var/spool/cron/crontabs/*; do
    [[ -f "$cron_file" ]] || continue
    fname=$(basename "$cron_file")
    # Skip stock cron files
    [[ "$fname" == "e2scrub_all" ]] && continue
    [[ "$fname" == ".placeholder" ]] && continue
    content=$(grep -v '^#' "$cron_file" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    csv_row "$CAT" "$cron_file" \
        "Custom cron job defined: $fname" \
        "$(echo "$content" | head -3 | tr '\n' ';')" "not present (stock)"
done
for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$cron_dir" ]] || continue
    for f in "$cron_dir"/*; do
        [[ -f "$f" ]] || continue
        fname=$(basename "$f")
        # Skip stock scripts
        [[ "$fname" == "0anacron" ]] && continue
        [[ "$fname" == "apt-compat" ]] && continue
        [[ "$fname" == "dpkg" ]] && continue
        [[ "$fname" == "logrotate" ]] && continue
        [[ "$fname" == "man-db" ]] && continue
        [[ "$fname" == "update-notifier-common" ]] && continue
        [[ "$fname" == "popularity-contest" ]] && continue
        [[ "$fname" == "bsdmainutils" ]] && continue
        csv_row "$CAT" "$f" \
            "Custom cron script in $(basename "$cron_dir"): $fname" \
            "present" "not present (stock)"
    done
done

# --- Timer units ---
log_info "Checking systemd timers..."
mapfile -t active_timers < <(systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $NF}' | sed 's/\.timer$//' | grep -v '^$' || true)
STOCK_TIMERS=(
    apt-daily apt-daily-upgrade dpkg-db-backup e2scrub_all e2scrub_reap
    fwupd-refresh logrotate man-db motd-news snapd-holdback systemd-tmpfiles-clean
    ua-timer update-notifier-download ureadahead-stop
)
for timer in "${active_timers[@]}"; do
    found=0
    for stock_t in "${STOCK_TIMERS[@]}"; do
        [[ "$timer" == "$stock_t" ]] && found=1 && break
    done
    if [[ $found -eq 0 ]]; then
        csv_row "$CAT" "systemctl / timers" \
            "Non-stock systemd timer active: $timer" \
            "active" "not present (stock)"
    fi
done

# ===========================================================================
# 6. PACKAGE MANAGEMENT
# ===========================================================================
log_section "6. Package Management"
CAT="Package Management"

# --- Additional APT repositories ---
log_info "Checking APT repositories..."
if [[ -f /etc/apt/sources.list ]]; then
    non_default=$(grep -v '^#' /etc/apt/sources.list | grep -v '^$' | grep -v 'ubuntu.com/ubuntu' || true)
    if [[ -n "$non_default" ]]; then
        csv_row "$CAT" "/etc/apt/sources.list" \
            "Non-Ubuntu repository entries in sources.list" \
            "$(echo "$non_default" | head -5 | tr '\n' ';')" "Ubuntu repos only (stock)"
    fi
fi
for repo_file in /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ -f "$repo_file" ]] || continue
    content=$(grep -v '^#' "$repo_file" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    fname=$(basename "$repo_file")
    csv_row "$CAT" "$repo_file" \
        "Additional APT repository file: $fname" \
        "$(echo "$content" | head -3 | tr '\n' ';')" "not present (stock)"
done

# --- PPAs ---
ppa_entries=$(grep -r 'ppa.launchpad.net' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -v '^Binary' | grep -v '^#' || true)
if [[ -n "$ppa_entries" ]]; then
    while IFS= read -r ppa; do
        ppa_name=$(echo "$ppa" | grep -oP 'ppa.launchpad.net/\K[^/]+/[^/]+' || true)
        csv_row "$CAT" "$(echo "$ppa" | cut -d: -f1)" \
            "PPA repository added: $ppa_name" \
            "$ppa_name" "not present (stock)"
    done <<< "$ppa_entries"
fi

# --- Snap packages (non-default) ---
log_info "Checking Snap packages..."
STOCK_SNAPS=(bare core core20 core22 gnome-3-38-2004 gtk-common-themes snapd firefox snap-store)
if cmd_exists snap; then
    mapfile -t installed_snaps < <(run_timeout 30 snap list | tail -n +2 | awk '{print $1}' || true)
    for s in "${installed_snaps[@]}"; do
        found=0
        for stock_s in "${STOCK_SNAPS[@]}"; do
            [[ "$s" == "$stock_s" ]] && found=1 && break
        done
        if [[ $found -eq 0 ]]; then
            snap_ver=$(run_timeout 15 snap list "$s" | tail -1 | awk '{print $2}' || true)
            csv_row "$CAT" "snap list" \
                "Non-stock Snap package installed: $s" \
                "${snap_ver:-unknown}" "not installed (stock)"
        fi
    done
fi

# --- Flatpak packages ---
if cmd_exists flatpak; then
    flatpak_list=$(run_timeout 20 flatpak list --app --columns=application,version | tail -n +1 || true)
    if [[ -n "$flatpak_list" ]]; then
        while IFS= read -r fpk; do
            [[ -z "$fpk" ]] && continue
            app=$(echo "$fpk" | awk '{print $1}')
            ver=$(echo "$fpk" | awk '{print $2}')
            csv_row "$CAT" "flatpak list" \
                "Flatpak application installed: $app" \
                "$ver" "not installed (stock)"
        done <<< "$flatpak_list"
    fi
fi

# --- Held packages ---
log_info "Checking held packages..."
if cmd_exists apt-mark; then
    held=$(apt-mark showhold 2>/dev/null || true)
    if [[ -n "$held" ]]; then
        while IFS= read -r pkg; do
            [[ -z "$pkg" ]] && continue
            csv_row "$CAT" "apt-mark showhold" \
                "Package held at current version: $pkg" \
                "held" "auto-upgrade (stock)"
        done <<< "$held"
    fi
fi

# --- Pinned packages ---
for pref_file in /etc/apt/preferences /etc/apt/preferences.d/*; do
    [[ -f "$pref_file" ]] || continue
    content=$(grep -v '^#' "$pref_file" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    csv_row "$CAT" "$pref_file" \
        "APT package pinning/preferences configured: $(basename "$pref_file")" \
        "$(echo "$content" | head -6 | tr '\n' ';')" "not present (stock)"
done

# --- Manually installed .deb packages ---
log_info "Checking manually installed packages..."
manual_pkgs=$(apt-mark showmanual 2>/dev/null | wc -l || true)
if [[ "${manual_pkgs:-0}" -gt 50 ]]; then
    csv_row "$CAT" "apt-mark showmanual" \
        "Significant number of manually installed packages detected ($manual_pkgs)" \
        "$manual_pkgs packages" "~20-30 (stock minimal)"
fi

# ===========================================================================
# 7. USER ENVIRONMENT AND SHELL
# ===========================================================================
log_section "7. User Environment and Shell"
CAT="User Environment and Shell"

# --- System-wide shell config ---
log_info "Checking system-wide shell configs..."
for sysfile in /etc/bash.bashrc /etc/profile /etc/environment; do
    [[ -f "$sysfile" ]] || continue
    custom_lines=$(grep -v '^#' "$sysfile" | grep -v '^$' | grep -v '^umask' | grep -v '^if ' | grep -v '^fi' | grep -v '^then' | grep -v '^\s*\.' | grep -v '^elif' || true)
    if [[ -n "$custom_lines" ]]; then
        echo_count=$(echo "$custom_lines" | grep -cE '^(export |alias |PATH=|source )' || true)
        echo_count=$(echo "$echo_count" | tr -d '[:space:]')
        if [[ "${echo_count:-0}" -gt 0 ]]; then
            csv_row "$CAT" "$sysfile" \
                "System-wide shell configuration customizations ($echo_count entries)" \
                "$(echo "$custom_lines" | grep -E '^(export |alias |PATH=|source )' | head -5 | tr '\n' ';')" "stock defaults"
        fi
    fi
done

# --- /etc/profile.d/ scripts ---
for pd_file in /etc/profile.d/*.sh; do
    [[ -f "$pd_file" ]] || continue
    fname=$(basename "$pd_file")
    # Skip known stock files
    [[ "$fname" =~ ^(apps-bin-path\.sh|bash_completion\.sh|byobu\.sh|cedilla-pt\.sh|debuginfod\.sh|gawk\.sh|im-config_wayland\.sh|jvm\.sh|vte\.sh|Z97-byobu\.sh|update-motd\.sh|01-locale-fix\.sh)$ ]] && continue
    csv_row "$CAT" "$pd_file" \
        "Custom /etc/profile.d script: $fname" \
        "present" "not present (stock)"
done

# --- Per-user .bashrc / .profile modifications ---
log_info "Checking per-user shell configs..."
skel_bashrc=/etc/skel/.bashrc
skel_profile=/etc/skel/.profile
while IFS=: read -r username _ uid _ _ homedir shell; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$uid" -gt 60000 ]] && continue
    [[ -z "$homedir" || ! -d "$homedir" ]] && continue
    for dotfile in .bashrc .profile .bash_aliases .zshrc .bash_profile; do
        user_file="${homedir}/${dotfile}"
        [[ -f "$user_file" ]] || continue
        skel_file="/etc/skel/${dotfile}"
        if [[ -f "$skel_file" ]]; then
            diff_lines=$(diff "$skel_file" "$user_file" 2>/dev/null | grep -c '^[<>]' || true)
            if [[ "${diff_lines:-0}" -gt 0 ]]; then
                csv_row "$CAT" "$user_file" \
                    "User $username: $dotfile differs from /etc/skel (${diff_lines} changed lines)" \
                    "${diff_lines} changed lines" "matches /etc/skel (stock)"
            fi
        else
            csv_row "$CAT" "$user_file" \
                "User $username: custom $dotfile present (no skel equivalent)" \
                "present" "not present (stock)"
        fi
    done
done < /etc/passwd

# --- Custom shells installed ---
log_info "Checking custom shells..."
STOCK_SHELLS=(/bin/sh /bin/bash /bin/dash /usr/bin/bash /usr/bin/sh)
while IFS= read -r sh; do
    [[ -z "$sh" ]] && continue
    found=0
    for stock_sh in "${STOCK_SHELLS[@]}"; do
        [[ "$sh" == "$stock_sh" ]] && found=1 && break
    done
    [[ $found -eq 1 ]] && continue
    sh_name=$(basename "$sh")
    csv_row "$CAT" "/etc/shells" \
        "Non-stock shell installed: $sh_name" \
        "$sh" "bash/dash/sh only (stock)"
done < /etc/shells

# --- System-wide PATH additions ---
path_additions=$(grep -rh 'PATH=' /etc/environment /etc/profile /etc/profile.d/ 2>/dev/null | grep -v 'manpath\|MANPATH' | grep -v '^#' || true)
if [[ -n "$path_additions" ]]; then
    csv_row "$CAT" "/etc/environment and /etc/profile.d/" \
        "System-wide PATH modifications found" \
        "$(echo "$path_additions" | head -5 | tr '\n' ';')" "stock default PATH"
fi

# --- System-wide aliases ---
alias_lines=$(grep -rh '^alias ' /etc/bash.bashrc /etc/profile.d/ 2>/dev/null | grep -v '^#' || true)
if [[ -n "$alias_lines" ]]; then
    csv_row "$CAT" "/etc/bash.bashrc / /etc/profile.d/" \
        "System-wide shell aliases defined" \
        "$(echo "$alias_lines" | head -5 | tr '\n' ';')" "no aliases (stock)"
fi

# ===========================================================================
# 8. PROGRAMMING LANGUAGES AND RUNTIMES
# ===========================================================================
log_section "8. Programming Languages and Runtimes"
CAT="Programming Languages and Runtimes"

# --- Python ---
log_info "Checking Python installations..."
STOCK_PYTHON="3.10"
for pybin in python python3 python3.10 python3.11 python3.12 python3.9 python3.8; do
    cmd_exists "$pybin" || continue
    py_ver=$("$pybin" --version 2>&1 | awk '{print $2}' || true)
    [[ -z "$py_ver" ]] && continue
    py_maj=$(echo "$py_ver" | cut -d. -f1-2)
    py_path=$(command -v "$pybin" 2>/dev/null || true)
    if [[ "$py_maj" != "$STOCK_PYTHON" ]]; then
        csv_row "$CAT" "$py_path" \
            "Non-stock Python version installed: $pybin" \
            "$py_ver" "Python ${STOCK_PYTHON}.x (stock)"
    fi
done

# pyenv
if [[ -d "$HOME/.pyenv" ]] || [[ -d /usr/local/pyenv ]] || cmd_exists pyenv; then
    csv_row "$CAT" "~/.pyenv or /usr/local/pyenv" \
        "pyenv Python version manager installed" \
        "present" "not installed (stock)"
fi

# conda/miniconda/anaconda
for conda_dir in /opt/conda /opt/miniconda3 /opt/anaconda3 "$HOME/miniconda3" "$HOME/anaconda3" "$HOME/miniforge3"; do
    [[ -d "$conda_dir" ]] || continue
    conda_ver=$("${conda_dir}/bin/conda" --version 2>/dev/null | awk '{print $2}' || echo "unknown")
    csv_row "$CAT" "$conda_dir" \
        "Conda/Miniconda/Anaconda installed" \
        "${conda_ver}" "not installed (stock)"
done

# Global pip packages
if cmd_exists pip3; then
    pip_count=$(run_timeout 30 pip3 list --format=columns | tail -n +3 | wc -l || echo "0")
    if [[ "${pip_count:-0}" -gt 10 ]]; then
        csv_row "$CAT" "pip3 list" \
            "Significant number of global pip packages installed ($pip_count)" \
            "$pip_count packages" "minimal (stock)"
    fi
fi

# --- Node.js ---
log_info "Checking Node.js..."
if cmd_exists node; then
    node_ver=$(node --version 2>/dev/null || true)
    node_path=$(command -v node)
    if [[ "$node_path" == /usr/local/* || "$node_path" == /opt/* || "$node_path" == "$HOME"* ]]; then
        csv_row "$CAT" "$node_path" \
            "Node.js installed from non-system location (likely nvm/manual)" \
            "$node_ver" "not installed (stock)"
    else
        csv_row "$CAT" "$node_path" \
            "Node.js installed" \
            "$node_ver" "not installed (stock)"
    fi
fi
# nvm
if [[ -d "$HOME/.nvm" ]] || [[ -d /usr/local/nvm ]]; then
    csv_row "$CAT" "~/.nvm" \
        "nvm (Node Version Manager) installed" \
        "present" "not installed (stock)"
fi
# npm global packages
if cmd_exists npm; then
    npm_global=$(run_timeout 30 npm list -g --depth=0 | tail -n +2 | wc -l || echo "0")
    if [[ "${npm_global:-0}" -gt 2 ]]; then
        csv_row "$CAT" "npm -g list" \
            "Global npm packages installed ($npm_global packages)" \
            "$npm_global packages" "none (stock)"
    fi
fi

# --- Java ---
log_info "Checking Java installations..."
if cmd_exists java; then
    java_ver=$(java -version 2>&1 | head -1 || true)
    java_path=$(command -v java)
    csv_row "$CAT" "$java_path" \
        "Java runtime installed" \
        "$java_ver" "not installed (stock)"
fi
for java_dir in /usr/lib/jvm/*/; do
    [[ -d "$java_dir" ]] || continue
    jdk_name=$(basename "$java_dir")
    [[ "$jdk_name" == "default-java" ]] && continue
    csv_row "$CAT" "$java_dir" \
        "JVM/JDK installation: $jdk_name" \
        "present" "not installed (stock)"
done

# sdkman
if [[ -d "$HOME/.sdkman" ]]; then
    csv_row "$CAT" "~/.sdkman" \
        "SDKMAN SDK version manager installed" \
        "present" "not installed (stock)"
fi

# --- Go ---
if cmd_exists go; then
    go_ver=$(go version 2>/dev/null || true)
    go_path=$(command -v go)
    csv_row "$CAT" "$go_path" \
        "Go programming language installed" \
        "$go_ver" "not installed (stock)"
fi

# --- Rust ---
if cmd_exists rustc; then
    rust_ver=$(rustc --version 2>/dev/null || true)
    csv_row "$CAT" "$(command -v rustc)" \
        "Rust programming language installed" \
        "$rust_ver" "not installed (stock)"
fi
if [[ -d "$HOME/.cargo" ]]; then
    cargo_pkgs=$(ls "$HOME/.cargo/bin/" 2>/dev/null | wc -l || echo "0")
    if [[ "${cargo_pkgs:-0}" -gt 5 ]]; then
        csv_row "$CAT" "~/.cargo/bin" \
            "Cargo global packages/binaries installed ($cargo_pkgs binaries)" \
            "$cargo_pkgs binaries" "none (stock)"
    fi
fi

# --- Ruby ---
if cmd_exists ruby; then
    ruby_ver=$(ruby --version 2>/dev/null || true)
    ruby_path=$(command -v ruby)
    csv_row "$CAT" "$ruby_path" \
        "Ruby runtime installed" \
        "$ruby_ver" "not installed (stock)"
fi
if cmd_exists gem; then
    gem_count=$(run_timeout 30 gem list | wc -l || echo "0")
    if [[ "${gem_count:-0}" -gt 5 ]]; then
        csv_row "$CAT" "gem list" \
            "Global Ruby gems installed ($gem_count gems)" \
            "$gem_count gems" "none (stock)"
    fi
fi

# ===========================================================================
# 9. SECURITY CONFIGURATION
# ===========================================================================
log_section "9. Security Configuration"
CAT="Security Configuration"

# --- UFW firewall ---
log_info "Checking firewall configuration..."
if cmd_exists ufw; then
    ufw_status=$(ufw status 2>/dev/null | head -1 | awk '{print $2}' || true)
    if [[ "$ufw_status" == "inactive" ]]; then
        csv_row "$CAT" "ufw status" \
            "UFW firewall is inactive (disabled)" \
            "inactive" "active (stock Ubuntu server)"
    elif [[ "$ufw_status" == "active" ]]; then
        ufw_rules=$(ufw status numbered 2>/dev/null | grep -c '^\[' || true)
        if [[ "${ufw_rules:-0}" -gt 0 ]]; then
            csv_row "$CAT" "ufw status" \
                "UFW firewall active with custom rules ($ufw_rules rules)" \
                "$ufw_rules rules" "default deny/allow (stock)"
        fi
    fi
fi

# --- AppArmor ---
log_info "Checking AppArmor..."
if cmd_exists aa-status; then
    aa_disabled=$(run_timeout 15 aa-status | grep 'profiles are in' | grep -c 'complain\|disabled' || true)
    if [[ "${aa_disabled:-0}" -gt 0 ]]; then
        csv_row "$CAT" "aa-status / AppArmor" \
            "AppArmor profiles in complain or disabled mode ($aa_disabled profiles)" \
            "$aa_disabled profiles" "all enforcing (stock)"
    fi
    # Custom AppArmor profiles
    for aa_local in /etc/apparmor.d/local/*; do
        [[ -f "$aa_local" ]] || continue
        content=$(grep -v '^#' "$aa_local" | grep -v '^$' || true)
        [[ -z "$content" ]] && continue
        csv_row "$CAT" "$aa_local" \
            "Custom AppArmor local profile override: $(basename "$aa_local")" \
            "present" "not present (stock)"
    done
fi

# --- sudoers modifications ---
log_info "Checking sudoers..."
if [[ -f /etc/sudoers ]]; then
    # Look for NOPASSWD entries
    nopasswd=$(grep -v '^#' /etc/sudoers | grep 'NOPASSWD' || true)
    if [[ -n "$nopasswd" ]]; then
        csv_row "$CAT" "/etc/sudoers" \
            "NOPASSWD sudo access configured" \
            "$(echo "$nopasswd" | head -5 | tr '\n' ';')" "not set (stock)"
    fi
    # Extra sudoers entries
    extra=$(grep -v '^#' /etc/sudoers | grep -v '^$' | grep -v '^Defaults' | grep -v '^%' | grep -v '^root' | grep -v '^@' || true)
    if [[ -n "$extra" ]]; then
        csv_row "$CAT" "/etc/sudoers" \
            "Custom sudoers rules present" \
            "$(echo "$extra" | head -5 | tr '\n' ';')" "root and %sudo only (stock)"
    fi
fi
for sudoers_d in /etc/sudoers.d/*; do
    [[ -f "$sudoers_d" ]] || continue
    fname=$(basename "$sudoers_d")
    [[ "$fname" == "README" ]] && continue
    [[ "$fname" == "90-cloud-init-users" ]] && continue
    content=$(grep -v '^#' "$sudoers_d" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    csv_row "$CAT" "$sudoers_d" \
        "Custom sudoers drop-in file: $fname" \
        "$(echo "$content" | head -3 | tr '\n' ';')" "not present (stock)"
done

# --- PAM configuration changes ---
log_info "Checking PAM configuration..."
# Custom PAM modules (third-party)
if ls /etc/pam.d/ | grep -qE '(google|okta|duo|radius)' 2>/dev/null; then
    custom_pam=$(ls /etc/pam.d/ | grep -E '(google|okta|duo|radius)' || true)
    csv_row "$CAT" "/etc/pam.d/" \
        "Third-party PAM configuration present" \
        "$custom_pam" "not present (stock)"
fi

# --- Fail2ban ---
if systemctl is-active --quiet fail2ban 2>/dev/null || cmd_exists fail2ban-client; then
    csv_row "$CAT" "/etc/fail2ban/jail.local" \
        "fail2ban intrusion prevention installed and running" \
        "active" "not installed (stock)"
fi

# --- SSL/TLS certificates ---
log_info "Checking SSL/TLS certificates..."
custom_certs=$(find /usr/local/share/ca-certificates/ -name '*.crt' 2>/dev/null | wc -l || true)
if [[ "${custom_certs:-0}" -gt 0 ]]; then
    csv_row "$CAT" "/usr/local/share/ca-certificates/" \
        "Custom CA certificates installed ($custom_certs certificates)" \
        "$custom_certs certs" "0 (stock)"
fi

# --- Unattended upgrades ---
log_info "Checking unattended-upgrades..."
if [[ -f /etc/apt/apt.conf.d/50unattended-upgrades ]]; then
    unattended_auto=$(grep -v '^#' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep 'Automatic-Reboot\|AutoFixInterruptedDpkg\|Remove-Unused' | head -5 || true)
    if [[ -n "$unattended_auto" ]]; then
        csv_row "$CAT" "/etc/apt/apt.conf.d/50unattended-upgrades" \
            "Unattended-upgrades configuration customized" \
            "$(echo "$unattended_auto" | tr '\n' ';')" "default settings"
    fi
fi

# --- SSH authorized keys ---
while IFS=: read -r username _ uid _ _ homedir _; do
    [[ "$uid" -lt 1000 ]] && continue
    [[ "$uid" -gt 60000 ]] && continue
    [[ -z "$homedir" || ! -d "$homedir" ]] && continue
    auth_keys="${homedir}/.ssh/authorized_keys"
    [[ -f "$auth_keys" ]] || continue
    key_count=$(grep -c '^ssh-\|^ecdsa-\|^sk-\|^sk-ssh' "$auth_keys" 2>/dev/null || true)
    key_count=${key_count:-0}
    if [[ "${key_count:-0}" -gt 0 ]]; then
        csv_row "$CAT" "$auth_keys" \
            "SSH authorized keys configured for user $username ($key_count keys)" \
            "$key_count keys" "0 keys (stock)"
    fi
done < /etc/passwd

# ===========================================================================
# 10. CONTAINERIZATION AND VIRTUALIZATION
# ===========================================================================
log_section "10. Containerization and Virtualization"
CAT="Containerization and Virtualization"

# --- Docker ---
log_info "Checking Docker..."
if cmd_exists docker; then
    docker_ver=$(run_timeout 15 docker version --format '{{.Server.Version}}' \
                 || run_timeout 5 docker --version | awk '{print $3}' | tr -d ',' \
                 || echo "unknown")
    csv_row "$CAT" "/etc/docker/daemon.json" \
        "Docker container runtime installed" \
        "v${docker_ver}" "not installed (stock)"
    if [[ -f /etc/docker/daemon.json ]]; then
        csv_row "$CAT" "/etc/docker/daemon.json" \
            "Custom Docker daemon configuration present" \
            "$(tr '\n' ' ' < /etc/docker/daemon.json)" "not present (stock)"
    fi
    # Docker networks
    custom_nets=$(run_timeout 15 docker network ls | grep -v 'NETWORK ID\|bridge\|host\|none' | wc -l | tr -d '[:space:]' || echo "0")
    if [[ "${custom_nets:-0}" -gt 0 ]]; then
        csv_row "$CAT" "docker network ls" \
            "Custom Docker networks configured ($custom_nets networks)" \
            "$custom_nets networks" "bridge/host/none only (stock)"
    fi
fi

# --- Podman ---
if cmd_exists podman; then
    podman_ver=$(run_timeout 10 podman version --format '{{.Version}}' || echo "unknown")
    csv_row "$CAT" "$(command -v podman)" \
        "Podman container runtime installed" \
        "v${podman_ver}" "not installed (stock)"
fi

# --- containerd ---
if systemctl is-active --quiet containerd 2>/dev/null; then
    csv_row "$CAT" "/etc/containerd/config.toml" \
        "containerd container runtime is active" \
        "active" "not installed (stock)"
fi

# --- Kubernetes tools ---
log_info "Checking Kubernetes tools..."
for k8s_tool in kubectl kubeadm kubelet helm k3s k9s; do
    cmd_exists "$k8s_tool" || continue
    k8s_ver=$(run_timeout 10 "$k8s_tool" version --client --short | head -1 \
              || run_timeout 10 "$k8s_tool" version | head -1 \
              || echo "unknown")
    csv_row "$CAT" "$(command -v "$k8s_tool")" \
        "Kubernetes tool installed: $k8s_tool" \
        "$k8s_ver" "not installed (stock)"
done
if [[ -f /etc/kubernetes/admin.conf ]]; then
    csv_row "$CAT" "/etc/kubernetes/" \
        "Kubernetes cluster configuration present" \
        "present" "not present (stock)"
fi

# --- libvirt/KVM/QEMU ---
if cmd_exists virsh; then
    csv_row "$CAT" "$(command -v virsh)" \
        "libvirt/KVM virtualization installed" \
        "present" "not installed (stock)"
    active_domains=$(run_timeout 10 virsh list --all | grep -c 'running\|shut off' || true)
    if [[ "${active_domains:-0}" -gt 0 ]]; then
        csv_row "$CAT" "virsh list" \
            "Virtual machines defined in libvirt ($active_domains VMs)" \
            "$active_domains VMs" "0 VMs (stock)"
    fi
fi

# --- VirtualBox ---
if cmd_exists vboxmanage; then
    vbox_ver=$(vboxmanage --version 2>/dev/null | head -1 || echo "unknown")
    csv_row "$CAT" "$(command -v vboxmanage)" \
        "VirtualBox hypervisor installed" \
        "$vbox_ver" "not installed (stock)"
fi

# ===========================================================================
# 11. SYSTEM CONFIGURATION FILES
# ===========================================================================
log_section "11. System Configuration Files"
CAT="System Configuration Files"

# --- /etc/hosts ---
log_info "Checking /etc/hosts..."
if [[ -f /etc/hosts ]]; then
    custom_hosts=$(grep -v '^#' /etc/hosts | grep -v '^$' \
        | grep -v '^127\.0\.0\.1\s*localhost' \
        | grep -v '^127\.0\.1\.1' \
        | grep -v '^::1\s' \
        | grep -v '^fe80' \
        | grep -v '^ff0' \
        | grep -v '^ff2' \
        || true)
    if [[ -n "$custom_hosts" ]]; then
        while IFS= read -r host_entry; do
            csv_row "$CAT" "/etc/hosts" \
                "Custom /etc/hosts entry" \
                "$host_entry" "localhost only (stock)"
        done <<< "$custom_hosts"
    fi
fi

# --- Hostname ---
log_info "Checking hostname..."
if [[ -f /etc/hostname ]]; then
    hostname=$(cat /etc/hostname | tr -d '\n')
    if [[ "$hostname" != "ubuntu" ]] && [[ "$hostname" != *"ubuntu"* ]]; then
        csv_row "$CAT" "/etc/hostname" \
            "Custom hostname set (not default 'ubuntu')" \
            "$hostname" "ubuntu (stock)"
    fi
fi

# --- Timezone ---
log_info "Checking timezone..."
current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || echo "unknown")
if [[ "$current_tz" != "UTC" && "$current_tz" != "Etc/UTC" ]]; then
    csv_row "$CAT" "/etc/timezone" \
        "Non-UTC timezone configured" \
        "$current_tz" "UTC (stock)"
fi

# --- Locale ---
log_info "Checking locale..."
system_locale=$(localectl status 2>/dev/null | grep 'System Locale' | cut -d= -f2 || grep 'LANG=' /etc/default/locale 2>/dev/null | cut -d= -f2 || echo "unknown")
if [[ -n "$system_locale" && "$system_locale" != "en_US.UTF-8" && "$system_locale" != "C.UTF-8" ]]; then
    csv_row "$CAT" "/etc/default/locale" \
        "Non-default locale configured" \
        "$system_locale" "en_US.UTF-8 (stock)"
fi
# Additional generated locales
extra_locales=$(locale -a 2>/dev/null | grep -v '^C$\|^C\.UTF-8$\|^en_US\.utf8$\|^POSIX$\|^en_US$' | head -10 || true)
if [[ -n "$extra_locales" ]]; then
    csv_row "$CAT" "/etc/locale.gen" \
        "Additional locales generated" \
        "$(echo "$extra_locales" | tr '\n' ';')" "en_US.UTF-8 only (stock)"
fi

# --- NTP/timesyncd/chrony ---
log_info "Checking time synchronization..."
if [[ -f /etc/chrony/chrony.conf ]] && systemctl is-active --quiet chronyd 2>/dev/null; then
    csv_row "$CAT" "/etc/chrony/chrony.conf" \
        "chrony NTP daemon in use (replaces systemd-timesyncd)" \
        "active" "systemd-timesyncd (stock)"
fi
if [[ -f /etc/timesyncd.conf ]]; then
    custom_ntp=$(grep -v '^#' /etc/timesyncd.conf | grep -v '^$' | grep -i 'NTP=' | grep -v 'ntp.ubuntu.com' || true)
    if [[ -n "$custom_ntp" ]]; then
        csv_row "$CAT" "/etc/timesyncd.conf" \
            "Custom NTP servers configured in timesyncd" \
            "$(echo "$custom_ntp" | tr '\n' ';')" "ntp.ubuntu.com (stock)"
    fi
fi

# --- Swap configuration ---
log_info "Checking swap configuration..."
swap_total=$(free -m 2>/dev/null | awk '/^Swap:/{print $2}' || echo "0")
if [[ "${swap_total:-0}" -eq 0 ]]; then
    csv_row "$CAT" "/proc/swaps" \
        "No swap configured (disabled)" \
        "0 MB" "auto-configured by installer"
elif [[ "${swap_total:-0}" -gt 0 ]]; then
    csv_row "$CAT" "/proc/swaps" \
        "Swap configured ($swap_total MB)" \
        "${swap_total} MB" "depends on RAM"
fi

swappiness=$(sysctl -n vm.swappiness 2>/dev/null || echo "60")
if [[ "$swappiness" -ne 60 ]]; then
    csv_row "$CAT" "sysctl vm.swappiness" \
        "Non-default swap tendency (swappiness) configured" \
        "$swappiness" "60 (stock)"
fi

# zswap/zram
if [[ -f /sys/module/zswap/parameters/enabled ]]; then
    zswap_enabled=$(cat /sys/module/zswap/parameters/enabled)
    if [[ "$zswap_enabled" == "Y" ]]; then
        csv_row "$CAT" "/sys/module/zswap/parameters/enabled" \
            "zswap compressed swap cache enabled" \
            "enabled" "disabled (stock)"
    fi
fi
if ls /dev/zram* &>/dev/null 2>&1; then
    csv_row "$CAT" "/dev/zram*" \
        "zram compressed block device(s) present" \
        "present" "not present (stock)"
fi

# --- ulimits / limits.conf ---
log_info "Checking ulimits..."
if [[ -f /etc/security/limits.conf ]]; then
    custom_limits=$(grep -v '^#' /etc/security/limits.conf | grep -v '^$' || true)
    if [[ -n "$custom_limits" ]]; then
        csv_row "$CAT" "/etc/security/limits.conf" \
            "Custom system ulimits configured" \
            "$(echo "$custom_limits" | head -5 | tr '\n' ';')" "default ulimits (stock)"
    fi
fi
for lf in /etc/security/limits.d/*.conf; do
    [[ -f "$lf" ]] || continue
    content=$(grep -v '^#' "$lf" | grep -v '^$' || true)
    [[ -z "$content" ]] && continue
    csv_row "$CAT" "$lf" \
        "Custom ulimits drop-in file: $(basename "$lf")" \
        "$(echo "$content" | head -5 | tr '\n' ';')" "not present (stock)"
done

# --- logrotate customizations ---
for lr_file in /etc/logrotate.d/*; do
    [[ -f "$lr_file" ]] || continue
    fname=$(basename "$lr_file")
    # Skip known stock logrotate configs
    stock_lr=(apt btmp dpkg rsyslog syslog ufw unattended-upgrades wtmp ubuntu-advantage-tools)
    found=0
    for stock_f in "${stock_lr[@]}"; do
        [[ "$fname" == "$stock_f" ]] && found=1 && break
    done
    [[ $found -eq 1 ]] && continue
    csv_row "$CAT" "$lr_file" \
        "Custom logrotate configuration: $fname" \
        "present" "not present (stock)"
done

# --- rsyslog/journald customizations ---
log_info "Checking logging configuration..."
if [[ -f /etc/rsyslog.conf ]]; then
    custom_rsyslog=$(grep -v '^#' /etc/rsyslog.conf | grep -v '^$' | grep -v '^\$\|^\*\|^auth\|^daemon\|^kern\|^mail\|^news\|^syslog\|^user\|^uucp\|^local' || true)
    if [[ -n "$custom_rsyslog" ]]; then
        csv_row "$CAT" "/etc/rsyslog.conf" \
            "Custom rsyslog configuration entries" \
            "$(echo "$custom_rsyslog" | head -5 | tr '\n' ';')" "stock defaults"
    fi
fi
if [[ -f /etc/systemd/journald.conf ]]; then
    custom_journald=$(grep -v '^#' /etc/systemd/journald.conf | grep -v '^$' | grep -v '^\[' || true)
    if [[ -n "$custom_journald" ]]; then
        csv_row "$CAT" "/etc/systemd/journald.conf" \
            "Custom journald configuration" \
            "$(echo "$custom_journald" | head -5 | tr '\n' ';')" "stock defaults (commented out)"
    fi
fi

# ===========================================================================
# 12. DESKTOP ENVIRONMENT
# ===========================================================================
log_section "12. Desktop Environment"
CAT="Desktop Environment"

log_info "Checking desktop environment..."

# Is a desktop environment installed?
if ! cmd_exists gnome-shell && ! cmd_exists plasmashell && ! cmd_exists xfwm4 && ! dpkg --list 'ubuntu-desktop*' 2>/dev/null | grep -q '^ii'; then
    log_info "No desktop environment detected, skipping desktop checks."
else
    # --- Display manager ---
    log_info "Checking display manager..."
    active_dm=""
    for dm in gdm3 lightdm sddm xdm; do
        if systemctl is-active --quiet "$dm" 2>/dev/null; then
            active_dm="$dm"
            break
        fi
    done
    if [[ -n "$active_dm" && "$active_dm" != "gdm3" ]]; then
        csv_row "$CAT" "systemctl $active_dm" \
            "Non-default display manager in use: $active_dm" \
            "$active_dm" "gdm3 (stock Ubuntu desktop)"
    fi

    # --- GNOME extensions ---
    log_info "Checking GNOME extensions..."
    if cmd_exists gnome-extensions; then
        mapfile -t gnome_exts < <(run_timeout 15 gnome-extensions list || true)
        STOCK_GNOME_EXTS=(
            "ubuntu-dock@ubuntu.com"
            "ubuntu-appindicators@ubuntu.com"
            "ding@rastersoft.com"
        )
        for ext in "${gnome_exts[@]}"; do
            found=0
            for stock_ext in "${STOCK_GNOME_EXTS[@]}"; do
                [[ "$ext" == "$stock_ext" ]] && found=1 && break
            done
            if [[ $found -eq 0 ]]; then
                csv_row "$CAT" "gnome-extensions" \
                    "Custom GNOME extension installed: $ext" \
                    "installed" "not present (stock)"
            fi
        done
    fi

    # System-wide GNOME extensions
    for ext_dir in /usr/share/gnome-shell/extensions/*/; do
        [[ -d "$ext_dir" ]] || continue
        ext_name=$(basename "$ext_dir")
        [[ "$ext_name" == "ubuntu-dock@ubuntu.com" ]] && continue
        [[ "$ext_name" == "ubuntu-appindicators@ubuntu.com" ]] && continue
        csv_row "$CAT" "$ext_dir" \
            "System-wide GNOME extension installed: $ext_name" \
            "present" "only stock extensions (stock)"
    done

    # Custom GNOME extensions per user
    while IFS=: read -r username _ uid _ _ homedir _; do
        [[ "$uid" -lt 1000 ]] && continue
        [[ "$uid" -gt 60000 ]] && continue
        [[ -z "$homedir" || ! -d "$homedir" ]] && continue
        ext_path="${homedir}/.local/share/gnome-shell/extensions"
        [[ -d "$ext_path" ]] || continue
        for ext in "$ext_path"/*/; do
            [[ -d "$ext" ]] || continue
            ext_name=$(basename "$ext")
            csv_row "$CAT" "$ext" \
                "User $username: custom GNOME extension: $ext_name" \
                "installed" "not present (stock)"
        done
    done < /etc/passwd

    # --- Custom themes/icons ---
    for theme_dir in /usr/share/themes/*/; do
        [[ -d "$theme_dir" ]] || continue
        theme_name=$(basename "$theme_dir")
        # Skip stock themes
        [[ "$theme_name" =~ ^(Ambiance|Radiance|Yaru|HighContrast|Adwaita|Default|Emacs|gtk20|Raleigh|Clearlooks|Mist|Industrial|ThinIce|Crux|Glide)$ ]] && continue
        csv_row "$CAT" "$theme_dir" \
            "Custom desktop theme installed: $theme_name" \
            "present" "Yaru/Adwaita only (stock)"
    done

    # --- Autostart applications ---
    log_info "Checking autostart applications..."
    for autostart_dir in /etc/xdg/autostart /usr/share/gnome/autostart; do
        [[ -d "$autostart_dir" ]] || continue
        for f in "$autostart_dir"/*.desktop; do
            [[ -f "$f" ]] || continue
            fname=$(basename "$f" .desktop)
            # Skip known stock autostart entries
            [[ "$fname" =~ ^(gnome-keyring|nm-applet|polkit-gnome|spice-vdagent|ubuntu-advantage-notification|update-notifier|snap-userd-autostart|at-spi-dbus-bus|zeitgeist-datahub|ibus|indicator-messages|indicator-keyboard|indicator-power|indicator-sound)$ ]] && continue
            csv_row "$CAT" "$f" \
                "Custom autostart application: $fname" \
                "present" "not present (stock)"
        done
    done
fi

# ===========================================================================
# SUMMARY
# ===========================================================================
log_section "Audit Complete"

TOTAL=0
echo ""
echo -e "${BOLD}========================================${RESET}"
echo -e "${BOLD}  AUDIT SUMMARY - Changes by Category  ${RESET}"
echo -e "${BOLD}========================================${RESET}"

for cat in \
    "Network Configuration" \
    "Kernel and Boot" \
    "Storage and Filesystems" \
    "GPU and Hardware Drivers" \
    "Services and Daemons" \
    "Package Management" \
    "User Environment and Shell" \
    "Programming Languages and Runtimes" \
    "Security Configuration" \
    "Containerization and Virtualization" \
    "System Configuration Files" \
    "Desktop Environment"; do
    count=${CATEGORY_COUNT["$cat"]:-0}
    TOTAL=$((TOTAL + count))
    if [[ "$count" -gt 0 ]]; then
        printf "  ${YELLOW}%-40s${RESET} ${RED}%3d changes${RESET}\n" "$cat" "$count"
    else
        printf "  ${GREEN}%-40s${RESET} ${GREEN}%3d changes${RESET}\n" "$cat" "$count"
    fi
done

echo -e "${BOLD}----------------------------------------${RESET}"
printf "  ${BOLD}%-40s %3d total${RESET}\n" "TOTAL" "$TOTAL"
echo -e "${BOLD}========================================${RESET}"
echo ""
log_ok "Audit CSV written to: ${OUTPUT_FILE}"
log_info "Completed at $(date)"
