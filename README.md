# ubuntu-config-audit

A comprehensive Bash script that audits an Ubuntu 22.04 installation and
identifies every significant change made from the stock/default operating system
configuration.  Output is a timestamped CSV file compatible with Microsoft Excel
and any spreadsheet application.

---

## Table of Contents

1. [Overview](#overview)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Output Format](#output-format)
6. [Audit Categories](#audit-categories)
7. [Example Output](#example-output)
8. [Notes and Limitations](#notes-and-limitations)

---

## Overview

When you need to rebuild or document a customized Ubuntu 22.04 server or
workstation, knowing *exactly* what changed from a vanilla installation is
invaluable.  `audit_ubuntu_config.sh` automates that discovery by inspecting
hundreds of configuration files, runtime state, and installed packages, then
writes every detected deviation to a single CSV file.

**Key features:**

- Single self-contained Bash script — no extra dependencies required
- Covers **12 audit categories** with hundreds of individual checks
- Generates a timestamped CSV (`ubuntu_config_audit_YYYY-MM-DD.csv`) with five
  columns: *Category*, *File/Location*, *Detail*, *Current Value*,
  *Default/Expected Value*
- CSV values are fully escaped (RFC 4180) — safe to open directly in Excel
- Color-coded terminal progress output
- Per-category change summary printed at the end
- Gracefully skips checks when optional tools (docker, zpool, snap, etc.) are
  not installed
- Accepts `--output` and `--no-color` CLI flags

---

## Requirements

| Requirement | Notes |
|---|---|
| Ubuntu 22.04 LTS | Tested on Jammy Jellyfish; may work on similar releases |
| Bash 5+ | Ships with Ubuntu 22.04 |
| **Root / sudo** | Required to read all system files |
| Standard coreutils | `awk`, `grep`, `sed`, `find`, `diff` — all pre-installed |

Optional tools (checks are skipped if not present):

`zpool`, `docker`, `podman`, `snap`, `flatpak`, `nvidia-smi`, `virsh`,
`vboxmanage`, `ufw`, `aa-status`, `fail2ban-client`, `kubectl`, `helm`,
`pyenv`, `nvm`, `go`, `rustc`, `ruby`

---

## Installation

```bash
# Clone the repository
git clone https://github.com/th0mcat/ubuntu-config-audit.git
cd ubuntu-config-audit

# Make the script executable
chmod +x audit_ubuntu_config.sh
```

---

## Usage

```bash
# Basic usage (writes ubuntu_config_audit_YYYY-MM-DD.csv in the current directory)
sudo ./audit_ubuntu_config.sh

# Specify a custom output file
sudo ./audit_ubuntu_config.sh --output /tmp/my_audit.csv

# Disable color output (useful for logging to file)
sudo ./audit_ubuntu_config.sh --no-color

# Combine options
sudo ./audit_ubuntu_config.sh --output /var/log/audit.csv --no-color

# Show help
./audit_ubuntu_config.sh --help
```

The script prints colored progress lines to the terminal as it runs each
category, then writes a summary table at the end.

---

## Output Format

The CSV has five columns:

| Column | Description |
|---|---|
| **Category** | One of the 12 audit categories (e.g., `Network Configuration`) |
| **File/Location** | The file path, command, or subsystem where the change was found |
| **Detail** | Human-readable description of the detected change |
| **Current Value** | What is actually configured on this system |
| **Default/Expected Value** | What a stock Ubuntu 22.04 installation would have |

All fields are double-quoted and internal double-quotes are escaped as `""` per
RFC 4180, making the file safe to open in Microsoft Excel, LibreOffice Calc, or
Google Sheets.

The filename includes the run date:

```
ubuntu_config_audit_2026-03-23.csv
```

---

## Audit Categories

### 1. Network Configuration
- MTU settings on all interfaces (flags anything other than 1500)
- DNS resolver status — detects dnsmasq, unbound, or manual `/etc/resolv.conf`
- systemd-resolved enabled/disabled/masked state
- Static IP assignments detected in Netplan YAML files
- `/etc/network/interfaces` customizations
- Custom static routes (`ip route`)
- iptables / ip6tables / nftables rule counts; persistent rule files
- Network bonding, bridging, and VLAN interfaces
- Key `net.*` sysctl parameters compared against Ubuntu 22.04 defaults

### 2. Kernel and Boot
- `GRUB_CMDLINE_LINUX` and `GRUB_CMDLINE_LINUX_DEFAULT` changes in
  `/etc/default/grub`; non-default `GRUB_TIMEOUT`
- Custom scripts in `/etc/grub.d/`
- Non-stock kernel packages installed; running kernel version vs. stock 5.15
- Non-stock kernel modules currently loaded (ZFS, NVIDIA, VirtualBox, WireGuard, …)
- Custom module autoload files in `/etc/modules-load.d/`
- sysctl settings in `/etc/sysctl.conf` and `/etc/sysctl.d/`
- Custom initramfs modules, hooks, and scripts

### 3. Storage and Filesystems
- ZFS pools (`zpool list`) and custom ZFS module parameters
- LVM physical volumes and volume groups
- Non-default `/etc/fstab` entries (network mounts, custom options)
- Software RAID arrays (`/proc/mdstat`, `mdadm.conf`)
- Mounted NFS / CIFS / SMB filesystems
- Per-disk I/O scheduler (flags anything other than `mq-deadline`)
- SMART monitoring daemon (smartd)

### 4. GPU and Hardware Drivers
- NVIDIA proprietary driver version (vs. stock `nouveau`)
- NVIDIA driver packages installed via dpkg
- CUDA toolkit (`/usr/local/cuda`)
- Recommendations from `ubuntu-drivers`
- Custom Xorg configuration files
- Additional firmware packages beyond `linux-firmware`

### 5. Services and Daemons
- Systemd services that are enabled but not part of a stock Ubuntu 22.04
  installation
- Stock services that have been disabled or masked
- Custom unit files in `/etc/systemd/system/` and `/etc/systemd/user/`
- Systemd service override/drop-in files (`.d/*.conf`)
- SSH daemon (`sshd_config`) key parameter changes from defaults
- Custom cron jobs in `/etc/cron.d/`, `/var/spool/cron/crontabs/`, and
  `cron.{hourly,daily,weekly,monthly}/`
- Non-stock systemd timers

### 6. Package Management
- Additional entries in `/etc/apt/sources.list` beyond Ubuntu repos
- Custom APT repository files in `/etc/apt/sources.list.d/`
- PPAs (ppa.launchpad.net entries)
- Snap packages installed beyond the stock set
- Flatpak applications installed
- Packages held at a fixed version (`apt-mark showhold`)
- APT pinning / preferences files
- Number of manually installed packages (large counts are flagged)

### 7. User Environment and Shell
- Customizations in `/etc/bash.bashrc`, `/etc/profile`, `/etc/environment`
- Custom scripts in `/etc/profile.d/`
- Per-user `.bashrc`, `.profile`, `.bash_aliases`, `.zshrc`, `.bash_profile`
  files diffed against `/etc/skel/`
- Non-stock shells listed in `/etc/shells` (zsh, fish, tcsh, …)
- System-wide `PATH` additions
- System-wide shell aliases

### 8. Programming Languages and Runtimes
- Non-stock Python versions (stock is Python 3.10); pyenv; conda/Miniconda/
  Anaconda; large number of global pip packages
- Node.js installation and installation method; nvm; global npm packages
- Java/JDK installations; SDKMAN
- Go runtime
- Rust toolchain; large number of Cargo binaries
- Ruby runtime; global gems

### 9. Security Configuration
- UFW firewall status and custom rules
- AppArmor profiles in complain/disabled mode; custom local profile overrides
- `sudoers` NOPASSWD entries and custom rules; `/etc/sudoers.d/` drop-in files
- PAM configuration changes (dpkg verify); third-party PAM modules
- fail2ban installation and status
- Custom CA certificates in `/usr/local/share/ca-certificates/`
- Unattended-upgrades configuration customizations
- SSH authorized keys (counts per user)

### 10. Containerization and Virtualization
- Docker version and custom `daemon.json`; custom Docker networks
- Podman container runtime
- containerd runtime
- Kubernetes tools: `kubectl`, `kubeadm`, `kubelet`, `helm`, `k3s`, `k9s`
- Kubernetes cluster configuration (`/etc/kubernetes/`)
- libvirt/KVM — `virsh` presence and defined VMs
- VirtualBox (`vboxmanage`)

### 11. System Configuration Files
- Custom `/etc/hosts` entries beyond localhost/loopback
- Custom hostname (non-"ubuntu")
- Non-UTC timezone
- Non-`en_US.UTF-8` system locale; additional generated locales
- chrony replacing systemd-timesyncd; custom NTP servers in `timesyncd.conf`
- Swap amount and `vm.swappiness` value; zswap and zram presence
- Custom ulimits in `/etc/security/limits.conf` and `limits.d/`
- Non-stock logrotate configurations in `/etc/logrotate.d/`
- Custom rsyslog and journald configurations

### 12. Desktop Environment
- Non-default display manager (lightdm, sddm instead of gdm3)
- GNOME extensions beyond the stock Ubuntu dock/appindicator set (per-user
  and system-wide)
- Custom desktop themes in `/usr/share/themes/`
- Custom autostart entries in `/etc/xdg/autostart/`
- Skipped automatically if no desktop environment is detected

---

## Example Output

Terminal output while running:

```
[INFO]  Audit started at Mon Mar 23 20:00:00 UTC 2026
[INFO]  Output file: ubuntu_config_audit_2026-03-23.csv

>>> 1. Network Configuration
[INFO]  Checking MTU settings...
[INFO]  Checking DNS configuration...
...

>>> Audit Complete

========================================
  AUDIT SUMMARY - Changes by Category
========================================
  Network Configuration                      7 changes
  Kernel and Boot                            3 changes
  Storage and Filesystems                    5 changes
  GPU and Hardware Drivers                   2 changes
  Services and Daemons                      12 changes
  Package Management                         8 changes
  User Environment and Shell                 4 changes
  Programming Languages and Runtimes         6 changes
  Security Configuration                     3 changes
  Containerization and Virtualization        4 changes
  System Configuration Files                 5 changes
  Desktop Environment                        0 changes
----------------------------------------
  TOTAL                                     59 total
========================================

[OK]    Audit CSV written to: ubuntu_config_audit_2026-03-23.csv
```

Excerpt from the CSV file:

```
"Category","File/Location","Detail","Current Value","Default/Expected Value"
"Network Configuration","ip link / interface eth0","Non-default MTU on interface eth0","9000","1500"
"Network Configuration","/etc/netplan/01-netcfg.yaml","Static IP assignment found in Netplan config","192.168.1.10/24;","DHCP (stock)"
"Kernel and Boot","/etc/default/grub","GRUB_CMDLINE_LINUX_DEFAULT differs from default","quiet splash intel_iommu=on","quiet splash"
"Storage and Filesystems","zpool","ZFS pool configured: tank (3.62T)","present","not present (stock)"
"GPU and Hardware Drivers","nvidia-smi","NVIDIA proprietary driver installed (nouveau replaced)","535.129.03","nouveau (stock open-source)"
"Services and Daemons","systemctl / /etc/systemd/system/","Non-stock service is enabled: docker","enabled","not enabled (stock)"
"Package Management","/etc/apt/sources.list.d/docker.list","Additional APT repository file: docker.list","deb [arch=amd64] https://download.docker.com/...","not present (stock)"
"Security Configuration","/etc/ssh/sshd_config","SSH config: PasswordAuthentication changed from default","no","yes"
"Programming Languages and Runtimes","/usr/local/bin/node","Node.js installed","v20.11.0","not installed (stock)"
"System Configuration Files","/etc/hostname","Custom hostname set (not default 'ubuntu')","myserver","ubuntu (stock)"
```

---

## Notes and Limitations

- The script must be run as **root** (`sudo`) to access all system paths.
- Some checks (e.g., `dpkg --verify`) are best-effort and depend on package
  database integrity.
- The list of "stock" services and timers is based on a typical Ubuntu 22.04
  LTS server installation; a desktop installation will have additional stock
  services that may appear as "non-stock".
- Per-user checks iterate over all users with UID 1000–60000.  On systems with
  many users this may take longer.
- The script does **not** modify any system configuration — it is read-only.
- Run time is typically 30–120 seconds depending on the number of packages and
  users on the system.
