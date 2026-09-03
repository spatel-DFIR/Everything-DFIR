# Linux DFIR Field Reference

Hands-on reference for Linux forensics and incident response across Debian/Ubuntu and RHEL/CentOS/Rocky/Alma/Fedora distributions. Covers OS internals, system logs, persistence mechanisms, filesystem forensics, live response, and memory analysis. Every note opens with Quick Triage (native bash/find/grep commands), then deepens through artifact mechanics and hunting.

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Start with [`00 - Cross-Artifact Correlation`](<00 - Cross-Artifact Correlation.md>) — pick your investigative goal (deleted file, program execution, exfil, persistence, rootkit, ransomware) and it tells you which notes to open in order. [`00b - ATT&CK to Evidence Map`](<00b - ATT&CK to Evidence Map.md>) is the reverse lookup (MITRE technique → evidence location).

**Common Scenarios — which notes to open:**

| Scenario | Start With | Then Read |
|----------|-----------|-----------|
| **Suspected persistence / backdoor** | [Persistence Overview](<09 - Persistence Mechanisms/Persistence Overview and Sweep.md>) | Mechanism-specific notes (Cron, Systemd, SSH, etc.), [Event Log Analysis](<06 - Logs/>) |
| **Webshell / RCE incident** | [Web Exploitation Playbook](<15 - Threat Landscape and Playbooks/Web Exploitation and Webshell Playbook.md>) | [Live Response](<10 - Live Response and Volatile Data.md>), [Process Trees](<10b - Process Trees and Execution Lineage.md>), [App Logs](<06 - Logs/Application and Database Logs.md>) |
| **Rootkit / hidden process detection** | [Linux Rootkit Playbook](<15 - Threat Landscape and Playbooks/Linux Rootkit Playbook.md>) | [Live Response](<10 - Live Response and Volatile Data.md>), [Memory Forensics](<11 - Memory Forensics.md>), [Rootkit Tools](<11c - Rootkit Detection Tooling.md>) |
| **SSH brute-force / foothold** | [SSH Brute-Force Playbook](<15 - Threat Landscape and Playbooks/SSH Brute-Force and Foothold Playbook.md>) | [Auth Logs](<06 - Logs/Authentication and Login Records.md>), [SSH Artifacts](<08 - Artifacts/SSH Artifacts.md>), [Timeline](<13 - Timelining.md>) |
| **Ransomware / file encryption** | [ESXi & Linux Ransomware Playbook](<15 - Threat Landscape and Playbooks/ESXi and Linux Ransomware Playbook.md>) | [Live Response](<10 - Live Response and Volatile Data.md>), [File Trees](<07 - File Systems/Filesystem Triage and Identification.md>), [Timeline](<13 - Timelining.md>) |
| **Cryptojacking / resource abuse** | [Cryptojacking Playbook](<15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md>) | [Live Response](<10 - Live Response and Volatile Data.md>), [Scheduled Tasks](<08 - Artifacts/Scheduled Tasks Spool and State.md>) |
| **Deleted files / anti-forensics** | [Artifact - Trash & Deletion](<08 - Artifacts/Trash and Deleted File Artifacts.md>) | [Filesystem depth](<07 - File Systems/ext4.md>), [Anti-Forensics](<13b - Anti-Forensics and Evidence Destruction.md>) |
| **Post-incident cleanup / rebuild** | [Remediation & Containment](<14 - Remediation and Containment.md>) | [Persistence sweep](<09 - Persistence Mechanisms/Persistence Overview and Sweep.md>), [Package integrity](<08 - Artifacts/Package Managers and Integrity.md>) |

**Tip:** Use GitHub anchors to jump within notes; in Obsidian, use the **Outline** panel.

---

## How This Platform Is Organized

Linux notes are organized by investigation phase and artifact family:

**Core Concepts (01–05):** Filesystem layout, permissions, users/auth, shells, and kernel hardening — foundational for all other investigation steps.

**System Logs (06):** Logging architecture, journald, syslog, auditd, Sysmon for Linux, and application logs — the primary evidence source for most investigations.

**Filesystems (07):** Filesystem identification, ext4/XFS/Btrfs internals, and deleted-file recovery using The Sleuth Kit and carving.

**Artifacts (08):** Package managers, cron/scheduled tasks, SSH keys, trash, desktop artifacts, and temp staging locations.

**Persistence Mechanisms (09):** Thirteen distinct persistence families with master sweep and per-mechanism hunting commands. Start with the overview, then drill into the mechanism matching your findings.

**Live Response & Memory (10–11):** Volatile data collection, process trees, network forensics, eBPF tracing, memory acquisition, malware triage, and rootkit detection.

**Evidence Collection & Timelining (12–14):** Collection methodology, super-timeline creation, anti-forensics detection, and remediation/rebuild playbooks.

**Threat Playbooks (15):** End-to-end scenarios (webshell, rootkit, SSH brute-force, ransomware, cryptojacking) synthesizing evidence from multiple sections.

**Enterprise & Virtualization (16–17):** Enterprise baseline, cloud-init, ESXi/vCenter forensics.

**Triage Scripts:** Two read-only, non-destructive bash scripts (hunt_persistence.sh, hunt_intrusion.sh) for live-host enumeration and anomaly detection.

**Distro Coverage:** Primary coverage is Debian/Ubuntu and RHEL/CentOS/Rocky/Alma/Fedora. SUSE/Arch/Alpine differences are called out where they change commands. Container and Kubernetes forensics are in [Container/](../Container/README.md).

---

## Module Status

- ✅ **In Depth:** 81 markdown files across 17 sections; persistence sweep script (v2.3); intrusion-hunting script (v1.1); playbooks for webshell, rootkit, SSH, ransomware, cryptojacking
- 🟡 **Evolving:** Enterprise baseline deepening; cloud-init investigation expanding
- ⏳ **Deferred:** YARA hunting workflows, advanced EDR evasion detection

---

## Module Structure

```
Linux/ (81 files total)
├── README.md (172 lines) ⭐ START HERE
│   ├── Quick Navigation Table (8 scenarios)
│   ├── Scope Clarity (distro coverage, script tools)
│   └── Module Status & Contents
├── 00 - Cross-Artifact Correlation.md (226 lines) ⭐ ENTRY POINT
│   └── Goal-driven playbook & order of volatility
├── 00b - ATT&CK to Evidence Map.md (101 lines)
│   └── MITRE Technique → Evidence lookup
├── 01–05 - Core Linux Fundamentals (3–4 KB each)
│   └── Filesystem layout, permissions, users/auth, shells, SELinux, AppArmor
├── 06 - Logs/ ⭐ PRIMARY EVIDENCE
│   ├── Architecture & Triage, Systemd Journal, Auth, Auditd, Syslog, Sysmon, App Logs
│   └── Focus: Logging architecture + hunting commands
├── 07 - File Systems/
│   ├── Triage/Identification, ext4, XFS, Btrfs, The Sleuth Kit
│   └── Focus: Filesystem internals + deleted-file recovery
├── 08 - Artifacts/
│   ├── Package managers, Scheduled tasks, SSH, Trash, Desktop, Temp, Staging
│   └── Focus: User activity & persistence evidence
├── 09 - Persistence Mechanisms/
│   ├── Overview & sweep, Cron, Systemd, SSH, RC files, Init.d, Kernel modules
│   ├── eBPF, MOTD, XDG, Docker, Container escapes
│   └── Focus: All persistence families + master sweep script
├── 10–11 - Live Response & Memory/
│   ├── Volatile data, Process trees, Network forensics, Memory acquisition
│   ├── Malware triage, Rootkit detection
│   └── Focus: Live evidence collection + eBPF/strace tracing
├── 12 - Evidence Collection & Triage/ (1 file, 15+ KB)
│   └── Collection methodology for dead-box & live-host workflows
├── 13–14 - Timelining & Anti-Forensics/
│   ├── Super-timeline creation, anti-forensics detection, remediation
│   └── Focus: Timeline correlation + evidence destruction patterns
├── 15 - Threat Landscape and Playbooks/
│   └── Webshell, Rootkit, SSH brute-force, Ransomware, Cryptojacking
├── 16–17 - Enterprise & Virtualization/
│   └── Enterprise baseline, cloud-init, ESXi/vCenter forensics
├── Linux-RTR/ (4 scripts, 20+ KB)
│   ├── hunt_persistence.sh (v2.3) - Comprehensive persistence sweep
│   ├── hunt_intrusion.sh (v1.1) - Intrusion detection & anomaly hunting
│   └── Real-time & post-incident analysis
├── Linux Posters/ (3 PDFs)
│   └── SANS & community reference materials (see README.md in folder)
└── Scripts/ (8 files)
    └── Live response & analysis scripts
```

---

## Contents

### Start Here
- [00 - Cross-Artifact Correlation](<00 - Cross-Artifact Correlation.md>) — order of volatility, timestamp epochs, distro fingerprint, goal-driven case playbooks, live-vs-image cheatsheet
- [00b - ATT&CK to Evidence Map](<00b - ATT&CK to Evidence Map.md>) — MITRE technique → evidence (reverse lookup)

### Core Linux
- [01 - Root Directory Structure and Filesystem Layout](<01 - Root Directory Structure and Filesystem Layout.md>) — FHS, per-dir DFIR value, system-identity profiling
- [02 - File and Directory Permissions](<02 - File and Directory Permissions.md>) — POSIX, SUID/SGID/sticky, capabilities, ACLs, xattrs, immutability, timestomping
- [03 - Users Groups and Authentication](<03 - Users Groups and Authentication.md>) — passwd/shadow/group, sudoers, PAM, NSS/SSSD
- [04 - Shells and Command History](<04 - Shells and Command History.md>) — rc files, all history artifacts, anti-forensics
- [05 - SELinux AppArmor and Kernel Hardening](<05 - SELinux AppArmor and Kernel Hardening.md>) — MAC denials as evidence, kernel taint

### 06 - Logs
- [Logging Architecture and Triage](<06 - Logs/Logging Architecture and Triage.md>) — journald vs rsyslog, log map, rotation, tampering
- [Systemd Journal](<06 - Logs/Systemd Journal.md>) — `journalctl` fields + hunting
- [Authentication and Login Records](<06 - Logs/Authentication and Login Records.md>) — wtmp/btmp/utmp/lastlog, auth.log/secure, SSH
- [Auditd](<06 - Logs/Auditd.md>) — `ausearch`, the execution chain, PROCTITLE decode
- [Syslog and Rsyslog](<06 - Logs/Syslog and Rsyslog.md>) — syslog/messages, kernel log, remote logging
- [Sysmon for Linux](<06 - Logs/Sysmon for Linux.md>) — event IDs, process/network chaining
- [Application and Database Logs](<06 - Logs/Application and Database Logs.md>) — Apache/nginx, webshell hunt, MySQL/DB

### 07 - File Systems
- [Filesystem Triage and Identification](<07 - File Systems/Filesystem Triage and Identification.md>) — LVM, LUKS, RAID, tmpfs/overlay, timestamp reality
- [ext4](<07 - File Systems/ext4.md>) — inodes, crtime, journal, deleted-file recovery
- [XFS](<07 - File Systems/XFS.md>) — structure, no-undelete reality, carving
- [Btrfs](<07 - File Systems/Btrfs.md>) — subvolumes and snapshots as evidence
- [The Sleuth Kit](<07 - File Systems/The Sleuth Kit.md>) — image/partition/filesystem/inode/block analysis, content extraction, deleted-file recovery, filesystem timeline

### 08 - Artifacts
- [Package Managers and Integrity](<08 - Artifacts/Package Managers and Integrity.md>) — inventory, install history, `rpm -Va`/`debsums`, repo/key tampering
- [Scheduled Tasks Spool and State](<08 - Artifacts/Scheduled Tasks Spool and State.md>) — cron/at/timer artifacts
- [SSH Artifacts](<08 - Artifacts/SSH Artifacts.md>) — authorized_keys, known_hosts, private keys, sshd_config
- [Trash and Deleted File Artifacts](<08 - Artifacts/Trash and Deleted File Artifacts.md>) — `.trashinfo`, deleted-but-open, thumbnails
- [GUI and Desktop Artifacts](<08 - Artifacts/GUI and Desktop Artifacts.md>) — recently-used, autostart, GVFS mounts
- [Temp and Staging Locations](<08 - Artifacts/Temp and Staging Locations.md>) — /tmp, /var/tmp, /dev/shm, fileless staging

### 09 - Persistence Mechanisms
One note per mechanism (13cubed-style), each with its own intro, "how the persistence works," locations, hunting guidance, and red flags.
- [Persistence Overview and Sweep](<09 - Persistence Mechanisms/Persistence Overview and Sweep.md>) — **start here**: the master sweep across all mechanisms + how to rank findings
- [Cron and at Jobs](<09 - Persistence Mechanisms/Cron and at Jobs.md>)
- [Systemd Units Timers and Generators](<09 - Persistence Mechanisms/Systemd Units Timers and Generators.md>)
- [Shell Startup and Profile Scripts](<09 - Persistence Mechanisms/Shell Startup and Profile Scripts.md>)
- [SSH Keys](<09 - Persistence Mechanisms/SSH Keys.md>)
- [PAM Backdoors](<09 - Persistence Mechanisms/PAM Backdoors.md>)
- [Preload Hijacking](<09 - Persistence Mechanisms/Preload Hijacking.md>) — `LD_PRELOAD` / `ld.so.preload`
- [Kernel Modules and LKM Rootkits](<09 - Persistence Mechanisms/Kernel Modules and LKM Rootkits.md>)
- [More Persistence Mechanisms](<09 - Persistence Mechanisms/More Persistence Mechanisms.md>) — udev, XDG autostart, MOTD, NetworkManager, legacy init, package/git hooks, caps/SUID, trojaned binaries

### Response and Timelining
- [10 - Live Response and Volatile Data](<10 - Live Response and Volatile Data.md>) — processes, `/proc` goldmine, network, fileless, firewall
- [10b - Process Trees and Execution Lineage](<10b - Process Trees and Execution Lineage.md>) — classifying an alerted process by its ancestry + cgroup: service vs SSH vs cron vs web-spawned vs container vs daemonized implant; why `PPID 1` is ambiguous; `systemctl status <pid>` and cgroup as the authoritative owner
- [10c - Network and PCAP Forensics](<10c - Network and PCAP Forensics.md>) — tcpdump/tshark capture + analysis, DNS tunneling, C2 beaconing, Zeek/Suricata, file carving from traffic
- [10d - eBPF Tooling for DFIR](<10d - eBPF Tooling for DFIR.md>) — bpftrace/bcc live tracing (fileless exec, hidden listeners), Falco/Tracee, detecting malicious eBPF
- [11 - Memory Forensics](<11 - Memory Forensics.md>) — AVML/LiME acquisition, Volatility 3 Linux, rootkit checks
- [11b - ELF and Malware Triage](<11b - ELF and Malware Triage.md>) — static triage of a recovered binary (file/strings/readelf, packers, imports) + sandboxed behavioral triage
- [11c - Rootkit Detection Tooling](<11c - Rootkit Detection Tooling.md>) — unhide/rkhunter/chkrootkit + Volatility rootkit plugins; why a clean scan clears nothing
- [11d - IOC and YARA Scanning](<11d - IOC and YARA Scanning.md>) — YARA against files and process memory, Loki/THOR/Fenrir, fleet-wide IOC hunting
- [12 - Evidence Collection and Triage](<12 - Evidence Collection and Triage.md>) — UAC, core triage set, imaging, enterprise scale
- [13 - Timelining](<13 - Timelining.md>) — The Sleuth Kit, mactime, Plaso super timeline, Timesketch
- [13b - Anti-Forensics and Evidence Destruction](<13b - Anti-Forensics and Evidence Destruction.md>) — consolidated hunt for log clearing, history evasion, timestomping, wtmp wiping, immutable persistence, secure deletion
- [14 - Remediation and Containment](<14 - Remediation and Containment.md>) — kill without respawn, foothold removal, credential rotation, rebuild decision

### 15 - Threat Landscape and Playbooks
- [Linux Malware and Threat Landscape](<15 - Threat Landscape and Playbooks/Linux Malware and Threat Landscape.md>) — families, LOLbins mapped to ATT&CK, hunting overview
- [Cryptojacking Playbook](<15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md>)
- [Web Exploitation and Webshell Playbook](<15 - Threat Landscape and Playbooks/Web Exploitation and Webshell Playbook.md>)
- [SSH Brute-Force and Foothold Playbook](<15 - Threat Landscape and Playbooks/SSH Brute-Force and Foothold Playbook.md>)
- [Linux Rootkit Playbook](<15 - Threat Landscape and Playbooks/Linux Rootkit Playbook.md>)
- [ESXi and Linux Ransomware Playbook](<15 - Threat Landscape and Playbooks/ESXi and Linux Ransomware Playbook.md>)
- [WIP Progress - Playbook Ideas](<15 - Threat Landscape and Playbooks/WIP Progress - Playbook Ideas.md>) — backlog

### Enterprise
- [16 - Enterprise Management and Baseline](<16 - Enterprise Management and Baseline.md>) — config mgmt, agents, domain join, TLS trust, cloud-init
- [17 - ESXi and vCenter](<17 - ESXi and vCenter.md>) — hypervisor log locations, `esxcli`/`vim-cmd` triage, ransomware hooks

### Triage Scripts
Read-only, non-destructive, console-only hunters for **live hosts** (run under `sudo` / an EDR live-response shell). Both share one engine and doctrine — *flag on evidence, enumerate everything else* — and are runtime-validated to `0 HIGH · 0 NOTABLE` on a clean SANS SIFT.
- [`scripts/`](scripts/README.md) — the two-script overview and shared design
- [`hunt_persistence.sh`](<scripts/hunt_persistence/README.md>) **(v2.3)** — persistence foothold: host triage, newest-first persistence timeline, what's armed *and running now*, evidence-backed anomaly queue
- [`hunt_intrusion.sh`](<scripts/hunt_intrusion/README.md>) **(v1.1)** — active intrusion: process lineage (webshell/RCE), network-backed shells, masquerade / fake kernel threads, self-hiding cross-view diffs, timestomp, log evasion; `--json` NDJSON for fleet rarity stacking

---

## Conventions & Voice

- **Quick Triage** block first — the run-now essentials (bash/find/grep/journalctl one-liners); deeper context follows
- 🔴 marks high-value / red-flag items — easily missed indicators or high-confidence evidence
- Commands are blank-line separated; tables explain what output means and how to interpret it
- MITRE ATT&CK technique IDs are tagged per note (verify against current Linux matrix)
- Commands shown for both live systems and mounted images (`/mnt/evidence/...`)
- Distribution differences (Debian vs RHEL vs SUSE vs Arch) are called out where they change commands

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify artifact behavior against the specific distro and kernel in front of you — paths, package names, and log locations evolve.
- **Built from Linux internals research and public DFIR sources.** Not affiliated with or endorsing any vendor or training provider.
- **Primary coverage:** Debian/Ubuntu and RHEL/CentOS/Rocky/Alma/Fedora. SUSE/Arch/Alpine differences noted where applicable. Browser forensics is maintained separately. Container/Kubernetes forensics live in [Container/](../Container/README.md).

---

## License

The notes in this repository are released under the [MIT License](../LICENSE).
