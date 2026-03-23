# ubuntu-config-audit

A comprehensive Bash script that audits an Ubuntu 22.04 system and identifies
every significant deviation from the stock installation. Results are written to
a timestamped CSV file that opens directly in Excel or any spreadsheet tool.

---

## Features

- **12 audit categories** covering the entire system (see below)
- **Color-coded terminal output** with progress indicators
- **Per-category and grand-total summary** printed at the end of each run
- **CSV output** with proper quoting — safe for values containing commas and
  quotes
- **Graceful degradation** — sections that rely on missing tools (e.g. Docker,
  ZFS, NVIDIA) are skipped automatically
- **No extra dependencies** — only standard Ubuntu utilities used; optionally
  uses `debsums`/`dpkg --verify` when available
- **Detailed log file** written to `/tmp/` for debugging

---

## Requirements

| Requirement | Details |
|-------------|---------|
| OS | Ubuntu 22.04 LTS (Jammy Jellyfish) — other Ubuntu versions produce warnings |
| Privileges | Must be run as **root** or with **sudo** |
| Shell | Bash 5.x (ships with Ubuntu 22.04) |
| Disk space | ~1 MB for CSV and log output |

---

## Usage

```bash
# Clone or download the script
git clone https://github.com/th0mcat/ubuntu-config-audit.git
cd ubuntu-config-audit

# Make executable
chmod +x audit_ubuntu_config.sh

# Run as root
sudo ./audit_ubuntu_config.sh
```

The script will:
1. Print colour-coded progress to the terminal as each category is audited.
2. Write every detected change to `ubuntu_config_audit_YYYY-MM-DD.csv` in the
   current directory.
3. Write a detailed run log to `/tmp/audit_ubuntu_config_YYYY-MM-DD.log`.
4. Print a per-category summary table when finished.

---

## Output Format

The CSV file has the following columns:

| Column | Description |
|--------|-------------|
| **Category** | Which of the 12 audit categories the change belongs to |
| **File/Location** | The file path, command, or kernel subsystem involved |
| **Detail** | Human-readable description of what was changed |
| **Current Value** | The value detected on this system |
| **Default/Expected Value** | The stock Ubuntu 22.04 default for comparison |

A summary section is appended to the bottom of the CSV with a count of changes
per category.

### Example rows

```
"Network Configuration","/etc/netplan/01-netcfg.yaml","Netplan file contains static IP assignment","addresses: [192.168.1.10/24]","DHCP-based configuration"
"Kernel and Boot","/etc/default/grub","GRUB_CMDLINE_LINUX contains custom kernel parameters","iommu=pt intel_iommu=on","(empty — stock Ubuntu 22.04)"
"GPU and Hardware Drivers","/proc/driver/nvidia","Proprietary NVIDIA driver loaded","version: 535.104.05","nouveau (stock Ubuntu 22.04)"
"Services and Daemons","systemctl (apparmor)","Stock Ubuntu service is disabled","disabled","enabled (stock)"
"Security Configuration","/etc/sudoers.d/90-cloud-init-users","Custom sudoers drop-in file [NOPASSWD detected]","user ALL=(ALL) NOPASSWD:ALL","(not in stock Ubuntu)"
```

---

## Audit Categories

### 1. Network Configuration
- MTU values on every interface (flags anything other than 1500)
- DNS resolver in use — systemd-resolved, dnsmasq, unbound, or custom
  `/etc/resolv.conf`
- Static IP assignments and disabled DHCP in Netplan configs
- Custom DNS nameservers in Netplan
- Bonding, bridging, VLAN, and tunnel configurations
- Custom static routes
- Legacy `/etc/network/interfaces` customisations
- iptables and nftables rule sets
- `sysctl net.*` parameters that differ from Ubuntu 22.04 defaults
- `net.*` overrides in `/etc/sysctl.conf` and `/etc/sysctl.d/`

### 2. Kernel and Boot
- Custom `GRUB_CMDLINE_LINUX` and `GRUB_CMDLINE_LINUX_DEFAULT` in
  `/etc/default/grub`
- Non-default `GRUB_TIMEOUT` and other GRUB settings
- Custom scripts in `/etc/grub.d/`
- Multiple kernel images or non-`*-generic` running kernel
- Custom/mainline kernel packages
- All active non-comment lines in `/etc/sysctl.conf` and `/etc/sysctl.d/`
- Custom modules in `/etc/initramfs-tools/modules`
- Custom initramfs hooks and `conf.d/` overrides
- Unusual loaded kernel modules (NVIDIA, ZFS, WireGuard, vboxdrv, etc.)

### 3. Storage and Filesystems
- ZFS pools (`zpool list`) and custom ZFS/SPL modprobe options
- LVM logical volumes (`lvs`)
- Active mdadm RAID arrays (`/proc/mdstat`)
- Non-standard or network (NFS, CIFS, fuse, overlay) entries in `/etc/fstab`
- Custom mount options on local filesystems
- Non-default I/O schedulers on block devices
- `smartd` SMART monitoring installation
- Currently active NFS/CIFS mounts

### 4. GPU and Hardware Drivers
- Proprietary NVIDIA driver vs stock `nouveau` — includes driver version and
  package name
- CUDA toolkit installation (`/usr/local/cuda`, `nvcc`)
- Active/available proprietary drivers via `ubuntu-drivers`
- AMD proprietary `amdgpu-pro` driver
- Custom `/etc/X11/xorg.conf` and `/etc/X11/xorg.conf.d/` snippets
- Non-stock firmware packages

### 5. Services and Daemons
- Enabled systemd services not present in a stock Ubuntu 22.04 install
- Stock services that have been disabled or masked
- Custom unit files in `/etc/systemd/system/`
- SSH daemon (`sshd_config`) parameter changes vs defaults
- Custom entries in `/etc/crontab` and `/etc/cron.d/`
- Per-user crontabs in `/var/spool/cron/crontabs/`
- Non-stock enabled systemd timers

### 6. Package Management
- Third-party entries in `/etc/apt/sources.list`
- Third-party `.list` / `.sources` files in `/etc/apt/sources.list.d/`
- Launchpad PPAs
- Held (pinned) packages (`dpkg --get-selections`)
- APT preferences/pinning (`/etc/apt/preferences` and `preferences.d/`)
- Non-default Snap packages
- Any Flatpak packages
- Package-managed config files modified on disk (`dpkg --verify`)

### 7. User Environment and Shell
- Modified system shell files: `/etc/bash.bashrc`, `/etc/profile`,
  `/etc/environment`
- Custom environment variables in `/etc/environment`
- Non-stock PATH in `/etc/environment`
- Custom scripts in `/etc/profile.d/`
- Per-user `.bashrc` / `.profile` differences vs `/etc/skel/`
- Per-user `.bash_aliases` files
- Per-user zsh, fish, and other non-bash shell config files
- Non-standard shells listed in `/etc/shells`

### 8. Programming Languages and Runtimes
- Non-stock Python versions (anything other than 3.10.x)
- pyenv, conda, Miniconda, Anaconda installations
- Globally installed pip3 packages
- Node.js — version and whether installed via APT or another method
- nvm (Node Version Manager)
- Global npm packages
- Java/JDK installation and SDKMan
- Go runtime
- Rust toolchain and `~/.cargo`
- Ruby, rbenv, rvm, and globally installed gems

### 9. Security Configuration
- UFW firewall status and custom rules
- AppArmor profiles in complain mode or disabled
- AppArmor service status
- NOPASSWD entries in `/etc/sudoers` and `sudoers.d/`
- Modified PAM configuration files
- fail2ban installation
- SSH `PermitRootLogin` and `PasswordAuthentication` settings
- SSH `authorized_keys` files for root and all real users
- Custom root CA certificates in `/usr/local/share/ca-certificates/`
- Modified `unattended-upgrades` configuration

### 10. Containerization and Virtualization
- Docker Engine — version, `daemon.json` customisations
- Podman container runtime
- containerd runtime
- Kubernetes tools: kubectl, kubeadm, kubelet, helm, k3s, k0s, minikube, kind
- libvirt/KVM — version and list of VMs
- QEMU hypervisor
- Oracle VirtualBox

### 11. System Configuration Files
- Custom entries in `/etc/hosts`
- Hostname change from stock default
- Timezone (flags anything other than UTC)
- System locale (flags anything other than `en_US.UTF-8`)
- chrony as a replacement for systemd-timesyncd
- Custom NTP servers in `systemd-timesyncd.conf`
- `vm.swappiness` sysctl value
- zswap and zram configuration
- Swap size
- Custom entries in `/etc/security/limits.conf` and `limits.d/`
- Custom logrotate drop-ins not belonging to any package
- Custom journald settings in `/etc/systemd/journald.conf`
- Custom rsyslog rules in `/etc/rsyslog.d/`

### 12. Desktop Environment
- Non-GDM3 display manager
- Custom GNOME extensions (system-wide and per-user)
- Custom GTK themes in `/usr/share/themes/`
- System-wide autostart applications not from any package
- Per-user autostart applications in `~/.config/autostart/`

---

## Security Notes

- The script **reads** configuration files but never modifies them.
- CSV output may contain **sensitive values** (e.g. NTP server addresses, SSH
  public keys). Store and share it accordingly.
- Running with `sudo` gives the script full read access to all user home
  directories.

---

## License

MIT — see [LICENSE](LICENSE) for details.
