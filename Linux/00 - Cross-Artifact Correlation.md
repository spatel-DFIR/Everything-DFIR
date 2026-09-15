# Cross-Artifact Correlation

A **playbook** view of the Linux section: pick the investigative **goal** (or an attacker **technique**), get the **artifacts to pull and the order** to combine them. No single Linux artifact tells the whole story — a login comes from one source, what that session ran from another, the file it dropped from a third. This note maps goals → sources and **MITRE ATT&CK** techniques → evidence; the detailed commands live in each topic note.

> 🔴 Golden rule: **one artifact = a lead; corroborated artifacts = a finding.** Build every timeline from ≥2 independent sources, normalize everything to **UTC** first (the host timezone from note 01 governs how local-time logs map), and capture the **volatile tier before you reboot or image** — `/proc`, memory, and network state don't exist on a dead disk.

## Contents

- [First Five Minutes](#first-five-minutes)
- [Order of Volatility](#order-of-volatility)
- [Timestamp Epochs and Conversions](#timestamp-epochs-and-conversions)
- [Distro Fingerprint](#distro-fingerprint)
- [Prove Program Execution](#prove-program-execution)
- [Recover a Deleted File](#recover-a-deleted-file)
- [Persistence Sweep](#persistence-sweep)
- [Intrusion from Initial Access](#intrusion-from-initial-access)
- [Lateral Movement](#lateral-movement)
- [Privilege Escalation](#privilege-escalation)
- [Suspected Rootkit](#suspected-rootkit)
- [Cryptojacking](#cryptojacking)
- [Data Exfiltration](#data-exfiltration)
- [Anti-Forensics and Tampering](#anti-forensics-and-tampering)
- [Container or Kubernetes Incident](#container-or-kubernetes-incident)
- [Live vs Image Cheatsheet](#live-vs-image-cheatsheet)

## First Five Minutes

```bash
# Context - record ALL of this before touching anything (governs every timestamp after)
date -u; uptime; hostnamectl; cat /etc/os-release; timedatectl; id; who; w

# Capture volatile state (lost on reboot) - see Live Response + Memory notes
ps -eo pid,ppid,user,stat,lstart,cmd --forest > /evidence/ps.txt
ss -tunap > /evidence/net.txt
ls -l /proc/*/exe 2>/dev/null | grep -E "deleted|memfd" > /evidence/deleted_exe.txt

# The cheap high-yield anomaly checks
cat /etc/ld.so.preload 2>/dev/null; cat /proc/sys/kernel/tainted
```

## Order of Volatility

Collect most-volatile first — each step down survives longer, and rebooting/imaging first destroys everything above it.

| # | Tier | Note | Gone on reboot? |
|---|------|------|-----------------|
| 1 | **RAM** (full memory image) | Memory Forensics | ✅ yes |
| 2 | **`/proc`** (cmdline/exe/maps/environ/fd) | Live Response | ✅ yes |
| 3 | **Network** (connections, listeners, ARP, firewall) | Live Response, Network Forensics | ✅ yes |
| 4 | **Sessions** (logged-in users, running processes) | Live Response | ✅ yes |
| 5 | **Disk** (image last) | Evidence Collection | ❌ persists |

## Timestamp Epochs and Conversions

🔴 Different artifacts use different time formats — convert everything to **UTC** before correlating, or events silently misorder.

| Source | Format | Convert |
|--------|--------|---------|
| Filesystem (`stat`) | Unix epoch seconds (+ nanoseconds) | `date -d @<epoch>` |
| ext4/XFS/Btrfs crtime (birth) | inode field, not shown by `stat` | `debugfs -R 'stat <inode>'` / `statx` |
| journald | microseconds since epoch (`__REALTIME_USTAMP`) | `journalctl -o json`; ÷ 1e6 |
| auditd | epoch seconds (`msg=audit(EPOCH:ID)`) | `date -d @<epoch>` |
| syslog (RFC3164) | `Mon DD HH:MM:SS`, **no year** | infer year from file/rotation |
| syslog (RFC5424) | ISO-8601 with offset | direct |
| wtmp/btmp/utmp | binary struct time | `last -F` / `utmpdump` |
| bash history | none (unless `HISTTIMEFORMAT`) | order only |
| zsh ext history | `: <epoch>:<dur>;cmd` | `date -d @<epoch>` |
| `/proc/net/tcp` | little-endian hex addr:port | endianness swap (CyberChef) |

> The classic mistake: comparing a local-time syslog line against a UTC filesystem time without normalizing — a multi-hour skew that breaks the whole sequence.

## Distro Fingerprint

Which family you're on decides which paths and tools apply — establish it first (full detail in note 01).

| Family | Auth log | Package | Integrity | MAC | Firewall |
|--------|----------|---------|-----------|-----|----------|
| Debian/Ubuntu | `auth.log` | dpkg/apt | `debsums` | AppArmor | ufw/nftables |
| RHEL/Rocky/Alma/Fedora | `secure` | rpm/dnf | `rpm -Va` | SELinux | firewalld/nftables |
| SUSE | `messages` | rpm/zypper | `rpm -Va` | AppArmor | firewalld |
| Alpine | `messages` | apk | — | — | iptables/nftables |
| Arch | journal | pacman | `pacman -Qkk` | — | nftables |

## Prove Program Execution

**ATT&CK:** Unix Shell (T1059.004) · Python (T1059.006)

| Order | Source (note) | What it gives |
|-------|---------------|---------------|
| 1 | **Auditd** (`EXECVE`/`SYSCALL`) | Highest-fidelity: the binary + full args + as whom (if rules exist) |
| 2 | **Systemd Journal** (`_CMDLINE`/`_EXE`) | Full command line + owning unit + login UID |
| 3 | **Live Response** (`/proc/PID/{cmdline,exe}`) | What's running now; recover a deleted-exe binary |
| 4 | **Shells** (history) | The exact interactive commands typed |
| 5 | **Memory** (`linux.bash`) | Recovered history even if the on-disk copy was cleared |
| 6 | **Process Trees** | Classify how it was launched (service / SSH / cron / web) |

## Recover a Deleted File

**ATT&CK:** File Deletion (T1070.004)

| Order | Source (note) | What it gives |
|-------|---------------|---------------|
| 1 | **Trash** (`.trashinfo`) | Original path + exact deletion time |
| 2 | **Live Response** (`lsof +L1`, `/proc/PID/fd`) | Recover a file still held open by a process |
| 3 | **Live Response** (`/proc/PID/exe`) | Recover a running-but-deleted binary |
| 4 | **File Systems** (ext4 `extundelete` / XFS carving / Btrfs snapshot) | Filesystem-level recovery (varies by FS) |
| 5 | **The Sleuth Kit** (`fls -rd`, `icat`) | Deleted inodes + content by inode from an image |

## Persistence Sweep

**ATT&CK:** T1053 · T1543 · T1546 · T1547.006 · T1556.003 · T1574.006

| Mechanism | Note (in Persistence folder) |
|-----------|------------------------------|
| Master sweep + ranking | Persistence Overview and Sweep (**start here**) |
| Cron / at | Cron and at Jobs |
| Systemd units/timers/generators | Systemd Units Timers and Generators |
| Shell startup / profile | Shell Startup and Profile Scripts |
| SSH keys | SSH Keys |
| PAM backdoors | PAM Backdoors |
| LD_PRELOAD / ld.so.preload | Preload Hijacking |
| Kernel modules / LKM | Kernel Modules and LKM Rootkits |
| udev / XDG / MOTD / rc / hooks / caps / trojaned bins | More Persistence Mechanisms |

> Corroborate any hit with file mtime/ctime (when it was planted), package ownership (`dpkg -S`/`rpm -qf` — hand-dropped?), and the immutable bit (`lsattr` — armored?).

## Intrusion from Initial Access

**ATT&CK:** Exploit Public-Facing App (T1190) · Valid Accounts (T1078) · Brute Force (T1110)

| Order | Source (note) | What it gives |
|-------|---------------|---------------|
| 1 | **Auth and Login Records** | The entry login (fail→success brute force, source IP) |
| 2 | **Application and Database Logs** | Web/DB exploitation (webshell POST, `INTO OUTFILE`) |
| 3 | **Process Trees** | A shell child of `nginx`/`sshd` = the foothold's execution |
| 4 | **Persistence** | What they planted to stay |
| 5 | **Timelining** | Order the whole chain, anchored on the entry event |

## Lateral Movement

**ATT&CK:** Remote Services: SSH (T1021.004)

| Source (note) | What it gives |
|---------------|---------------|
| **Auth and Login Records** | `Accepted` from an internal host / to the next hop |
| **SSH Artifacts** (`known_hosts`) | Every host this account SSH'd out to (the map) |
| **SSH Artifacts** (private keys) | Credentials staged to pivot with |
| **Live Response** (network) | Live outbound SSH/other sessions |

## Privilege Escalation

**ATT&CK:** Setuid (T1548.001) · Sudo (T1548.003) · Exploitation (T1068)

| Source (note) | What it gives |
|---------------|---------------|
| **Permissions** (`find -perm -4000`, `getcap`) | SUID/capability privesc primitives |
| **Users Groups and Auth** (sudoers) | `NOPASSWD` grants, `docker`/`lxd` membership |
| **Auditd** (`USER_CMD`) | The privileged commands actually run |
| **SELinux/AppArmor** (AVC denials) | The MAC layer catching the escalation attempt |
| **Journal/dmesg** | Exploit crashes (segfaults) around the escalation |

## Suspected Rootkit

**ATT&CK:** Rootkit (T1014) · Kernel Modules (T1547.006) · LD_PRELOAD (T1574.006)

| Order | Source (note) | What it gives |
|-------|---------------|---------------|
| 1 | **Rootkit Playbook** | The detection-by-inconsistency method |
| 2 | **Live Response** (view mismatches) | `/proc` vs `ps`, `/proc/net` vs `ss` |
| 3 | **Rootkit Detection Tooling** (`unhide`, `rkhunter`) | Automated hidden-process/port/file finding |
| 4 | **SELinux/Kernel** (`tainted`) + **Preload** (`ld.so.preload`) | Kernel vs userland rootkit indicators |
| 5 | **Memory Forensics** (`psscan`, `check_syscall`) | Conclusive proof → rebuild decision |

## Cryptojacking

**ATT&CK:** Resource Hijacking (T1496)

| Source (note) | What it gives |
|---------------|---------------|
| **Cryptojacking Playbook** | The end-to-end scenario |
| **Live Response** (`/proc`, top CPU) | The miner process (often masqueraded/deleted-exe) |
| **Network Forensics** | The mining-pool connection (`stratum`) |
| **Persistence** | The cron/systemd that redeploys it |

## Data Exfiltration

**ATT&CK:** Archive (T1560) · Exfil Over C2/Alt Protocol (T1041/T1048)

| Source (note) | What it gives |
|---------------|---------------|
| **Temp and Staging** | The staged archive awaiting pickup |
| **Live Response** + **Network Forensics** | The egress connection / DNS tunnel / large upload |
| **Application and Database Logs** | Large web responses / `INTO OUTFILE` DB dumps |
| **Shells** (history) | `tar`/`scp`/`rclone`/`curl` commands |

## Anti-Forensics and Tampering

**ATT&CK:** Clear Logs (T1070.002) · Clear History (T1070.003) · Timestomp (T1070.006)

| Tell | Where to look (note) |
|------|----------------------|
| Consolidated hunt for all of these | **Anti-Forensics and Evidence Destruction** |
| Logs zeroed / `journalctl --verify` fails | Logging Architecture |
| History disabled / redirected | Shells and Command History |
| Timestomping (`ctime` > `mtime`) | Permissions; File Systems |
| `wtmp`/`btmp` wiped | Auth and Login Records |
| Immutable persistence (`+i`) | Permissions; Persistence |
| Hidden processes/files (rootkit) | Rootkit Playbook; Rootkit Detection Tooling |

## Container or Kubernetes Incident

If cgroups show `docker/…` or `kubepods/…`, or the host runs containers, jump to the **Container** section (Fundamentals → Runtime Triage → Escapes → Kubernetes). A container process is a host process — map container PID ↔ host PID early (Process Trees note).

## Live vs Image Cheatsheet

| Evidence | Live host | Mounted image |
|----------|-----------|---------------|
| Processes, `/proc`, network, `lsmod` | ✅ only source | ❌ gone |
| RAM | ✅ acquire now | ❌ (unless captured) |
| Logs, `/etc`, cron, systemd, histories, SSH | ✅ | ✅ (`/mnt/evidence/...`) |
| journald | `journalctl` | `journalctl -D /mnt/evidence/var/log/journal` |
| wtmp/btmp | `last`/`lastb` | `last -f /mnt/evidence/var/log/wtmp` |
| auditd | `ausearch` | `ausearch -if /mnt/evidence/...` |
| Deleted files | `/proc`, `lsof +L1` | filesystem carving / The Sleuth Kit |

> Detailed commands, interpretation tables, and red flags for each source are in its own note. This page is the index that tells you **which notes to open** for the case in front of you.
