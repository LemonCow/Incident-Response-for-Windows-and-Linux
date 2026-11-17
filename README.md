# Incident Response Toolkit

Live-response data collection scripts for **Windows** and **Ubuntu**, written as a class project. Each script gathers volatile and non-volatile artifacts from a running system, records chain-of-custody details, and hashes everything it collects.

> **Authorized use only.** Run these scripts only on systems you own or have explicit written permission to investigate.

## Repository layout

```
incident-response-toolkit/
├── windows/
│   ├── IR_Response.ps1     # Windows live-response collector (PowerShell)
│   └── README.md
├── linux/                  # Mirrors the layout of the Ubuntu thumb drive
│   ├── response            # Ubuntu live-response collector (Bash)
│   ├── README              # On-drive usage guide
│   ├── tools/              # Trusted binaries (not committed, see docs/linux-tools.md)
│   ├── ldd_output/         # Shared-library analysis of lsof
│   └── data/               # Created at runtime; output is git-ignored
├── docs/
│   ├── linux-tools.md      # How to build linux/tools/
│   └── required-tools.txt
├── .gitignore              # Keeps collected evidence and binaries out of the repo
├── LICENSE
└── README.md
```

## Collection order

Both collectors follow the order of volatility: the most short-lived data first, disk-resident data after.

1. **Volatile** (memory-resident / changes quickly): time, processes, services, network connections, routing, ARP, DNS cache, shell history, logged-on users
2. **Non-volatile** (persists on disk): system info, logs, scheduled jobs, drivers, disks, network config, accounts, browser artifacts, directory listings
3. **Finalize:** hash every collected file and close out the chain-of-custody record

## Windows collector

**Requirements:** Windows 10/11 or Server 2016+, PowerShell 5.1+, run as Administrator.

```powershell
# From an elevated PowerShell prompt
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\windows\IR_Response.ps1
```

The script prompts for your name, case ID, and a reference time from a phone or watch (to document clock skew), then runs unattended. Event logs and directory listings can take several minutes.

### What it collects

| Category | Artifacts | Output |
|---|---|---|
| Volatile | System time (local + UTC) | `volatile/systemtime.txt` |
| | Running processes | `volatile/processes.csv` |
| | Services | `volatile/services.csv` |
| | NetBIOS / established connections | `volatile/netbios.txt` |
| | Loaded modules per process | `volatile/open_handles.csv` |
| | TCP / UDP connections | `volatile/tcp_connections.csv`, `udp_connections.csv` |
| | Routing table | `volatile/routing_table.csv` |
| | ARP cache | `volatile/arp_cache.csv` |
| | DNS cache | `volatile/dns_cache.csv` |
| | PowerShell history | `volatile/history.txt` |
| | Logged-on users | `volatile/loggedon_users.txt` |
| Non-volatile | OS, computer, and BIOS info | `non_volatile/sysinfo.txt` |
| | Event logs (all non-empty, multithreaded) | `non_volatile/event_logs.csv` |
| | Prefetch files (copied) | `non_volatile/Prefetch/` |
| | Scheduled tasks | `non_volatile/sched_tasks.csv` |
| | Drivers | `non_volatile/drivers.csv` |
| | Disk space | `non_volatile/logical_disks.csv` |
| | Network adapter config | `non_volatile/ipconfig.txt` |
| | Local users and group members | `non_volatile/users.csv`, `group_members.csv` |
| | Pagefile / hibernation info | `non_volatile/pagefile_hibernation.txt` |
| | Disk drives and volumes | `non_volatile/disk_drive.csv`, `volume.csv` |
| | Chrome / Edge / Firefox history and cache listing | `non_volatile/browser_*.txt`, `non_volatile/BrowserCache/` |
| | Full directory listing per drive | `non_volatile/dirlisting_<drive>.csv` |
| Integrity | SHA-1 hashes of all output | `volatile_hashes.csv`, `non_volatile_hashes.csv` |
| Custody | Investigator, case, timestamps | `chain_of_custody.txt`, `collection_log.txt` |

### Notes and limitations

- Output is written to the script's own folder. **Run it from removable or dedicated evidence media**, not from a clone of this repo, so you don't write to the system you're investigating or commit evidence by accident.
- `open_handles.csv` lists loaded modules per process, not true file handles. For full handle enumeration, run Sysinternals `Handle.exe -a` separately.
- Running PowerShell itself changes system state (new processes, history, prefetch entries). This is unavoidable in live response and should be documented in your notes.

## Linux (Ubuntu) collector

A Bash script designed to run from a thumb drive. It calls every command from the drive's own `tools/` directory instead of the target's `PATH`.

**Requirements:** Ubuntu 64-bit (24.04 tested), run as root, drive mounted with exec permission, about 32 GB free if you capture RAM.

1. Build `linux/tools/` from trusted binaries. See [docs/linux-tools.md](docs/linux-tools.md).
2. Copy the contents of `linux/` to the root of the thumb drive.
3. On the target:

```bash
sudo mount -o remount,exec /dev/<device> <MOUNTPOINT>   # only if the drive is noexec
sudo bash <MOUNTPOINT>/response
```

The script prompts for investigator name, case name, date, and time, then asks whether to capture memory with `avml`. Full instructions and the complete output list are in [linux/README](linux/README).

### What it collects

| Category | Artifacts | Output (`data/<volatile\|nonvolatile>_<case>/`) |
|---|---|---|
| Volatile | System time | `systemtime.txt` |
| | Processes and process tree | `processes.txt`, `proc_tree.txt` |
| | systemd services | `systemd_services.txt` |
| | Uptime, vmstat, memory usage | `uptime.txt`, `vmstat.txt`, `memory_usage.txt` |
| | Network connections and sockets | `netstat.txt`, `ss_sockets.txt` |
| | DNS cache and hosts file | `dns_data.txt`, `hosts_file.txt` |
| | Open files (lsof) | `open_files.txt` |
| | Kernel ring buffer | `dmesg-kernel.txt` |
| | Routing table | `routing_table.txt`, `route.txt` |
| | ARP cache | `arp_cache.txt` |
| | Kernel modules | `lsmod.txt` |
| | Shell history, all users | `shell_history.txt` |
| | Shell variables | `sys-var.txt` |
| | RAM image (optional, avml) | `memory.lime` |
| Non-volatile | OS and host info | `sysinfo.txt` |
| | Cron jobs | `cron_root.txt`, `crontab.txt`, `cron_dirs.txt`, `cron_users.txt` |
| | Installed packages | `installed_pkgs.txt` |
| | System logs | `log/` (copy of `/var/log`) |
| | Recursive directory listing of `/` | `directory-la.txt` |
| | Mounts, disk usage, block devices | `mounted_vols.txt`, `disk_usage.txt`, `block_devices.txt` |
| | Network configuration | `ipconfig.txt` |
| | Logged-on users, login history, failed logins | `users_logged_on.txt`, `login_history.txt`, `failed_logins.txt` |
| Integrity | SHA-1 hashes | `volatile_hashes.txt`, `non_volatile_hashes.txt` |
| Custody | Console log and errors | `data/<case>.log`, `data/<case>.err` |

See [linux/ldd_output/](linux/ldd_output/) for the `ldd` analysis of `lsof`, which documents why the drive's binaries must be static or compatible with the target.

## Class information

- **Course:** DFOR 660, Project 3
- **Author:** Philip Isaacs

## License

MIT, see [LICENSE](LICENSE).
