# Root Directory Structure and Filesystem Layout

The Filesystem Hierarchy Standard (FHS) is the map every Linux investigation starts from: where configuration, logs, user data, and executables *should* live — which makes anything out of place immediately suspicious. Attackers use the same map in reverse: they **stage** payloads in the world-writable, lightly-monitored corners (`/tmp`, `/dev/shm`, `/var/tmp`) and hide **persistence** in the high-trust ones (`/etc`, `/usr/lib`, systemd units). This note orients you to the tree and to the **system-identity profiling** you run first on any host or image — because everything you interpret afterward (timestamps, log paths, package tooling, memory symbols) depends on knowing exactly what you're looking at.

> 🔴 Profile **before** you touch anything else. The host **timezone** decides how every local-time log maps to UTC; the **distro family** decides which paths and tools apply (`auth.log` vs `secure`, `apt` vs `dnf`, AppArmor vs SELinux); the **kernel version** is required later for memory analysis. Getting these wrong silently corrupts the whole timeline.

> ⚠️ On a **mounted image** the live tier (`/proc`, `lsmod`, `ss`, RAM) does **not** exist — collect it on the live host *before* imaging. Everything below that reads `/etc`, `/var`, config, and logs works on both live and image (prefix `/mnt/evidence/…`).

## Contents

- [Quick Triage](#quick-triage)
- [Root Directory Map](#root-directory-map)
- [usr-merge and Symlinks](#usr-merge-and-symlinks)
- [What to Check for What](#what-to-check-for-what)
- [System Identity and Device Profiling](#system-identity-and-device-profiling)
- [Time and Timezone](#time-and-timezone)
- [Host Resolution and Network Identity](#host-resolution-and-network-identity)
- [Logging Configuration](#logging-configuration)
- [Disks Partitions and Mounts](#disks-partitions-and-mounts)
- [Hunt the High-Risk Zones](#hunt-the-high-risk-zones)
- [Mounted Image Orientation](#mounted-image-orientation)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

Run top to bottom — this *is* the profiling order. Capture it before anything else; it governs every timestamp and path you read afterward.

```bash
# Who/what am I on (record all of this first)
hostnamectl

cat /etc/os-release

uname -a

# Timezone drives every timestamp you read next — and NTP-sync state
timedatectl

# Boot parameters — was security disabled at boot? (selinux=0, init=, single)
cat /proc/cmdline

# Disks, filesystems, mounts
lsblk -f

# Live mounts vs configured intent (hidden/attacker mounts stand out)
cat /proc/mounts

# Loaded kernel modules (rootkit / driver persistence) — snapshot it
lsmod | tee /evidence/lsmod.txt

# High-risk staging dirs — anything here is suspect
ls -alht /tmp /var/tmp /dev/shm
```

## Root Directory Map

Linux treats "everything as a file," and the top-level directories partition the system by *purpose*. Knowing each directory's intended role is what lets you say "a compiled ELF in `/dev` is wrong" at a glance. The **DFIR value** column flags where attackers plant tools (writable/unmonitored areas) and where they persist (high-trust areas that survive reboot).

| Path | Purpose | DFIR value |
|------|---------|------------|
| `/bin` → `/usr/bin` | Essential user binaries (`ls`, `cp`, `rm`) | 🔴 Binary replacement / PATH hijack; verify integrity (`rpm -Va`/`debsums`) |
| `/sbin` → `/usr/sbin` | System/admin binaries | 🔴 Privesc targets; trojaned `sshd`, `init` |
| `/lib` `/lib64` → `/usr/lib*` | Shared objects (`.so`) | 🔴 `LD_PRELOAD`/library hijack; PAM modules in `/lib*/security` |
| `/usr` | Userland programs, libraries, local installs | Large attack surface; `/usr/local` is admin-writable and unmonitored |
| `/etc` | System-wide config | 🔴 **HIGHEST VALUE** — persistence, creds, config: `passwd shadow sudoers ssh cron systemd ld.so.preload` |
| `/var` | Logs, spool, caches, mail, web data | 🔴 `/var/log`, `/var/spool/cron`, `/var/tmp`, `/var/www`, `/var/lib/docker` |
| `/home` | User home directories | 🔴 User persistence, SSH keys, shell rc, history, downloads |
| `/root` | Root's home | 🔴 High-value; root history, `.ssh`, dropped tools |
| `/opt` | Third-party / vendor software | 🔴 Stealthy installs; often admin-writable, unmonitored by EDR |
| `/srv` | Service data (web, ftp) | 🔴 Web roots → webshells |
| `/tmp` | World-writable temp | 🔴 **VERY HIGH RISK** — malware staging, payload dropping |
| `/var/tmp` | Persistent temp (survives reboot) | 🔴 Staging that outlives `/tmp` cleaning |
| `/dev/shm` | tmpfs shared memory (world-writable) | 🔴 Fileless malware, in-memory `.so`, staging |
| `/dev` | Device files | Should be device nodes; a *regular* file here is suspicious |
| `/proc` | Virtual FS: process + kernel runtime | 🔴 **CRITICAL live forensics** — deleted binaries, maps, env, fd |
| `/sys` | Kernel/device interface | `/sys/module` cross-check for hidden kernel modules |
| `/run` → `/var/run` | tmpfs runtime data | Ephemeral: PID files, sockets, `/run/user/<uid>` |
| `/boot` | Kernel, initramfs, GRUB | Unauthorized kernel/initrd/bootloader changes |
| `/mnt` `/media` | Mount points (manual / auto) | Hidden mounts, USB exfil/staging |
| `/lost+found` | fsck-recovered files (ext) | Occasionally recovers attacker artifacts |

**How this gets abused:** two dominant patterns — (1) *staging*: dropping a downloader/payload into a world-writable dir (`/tmp`, `/dev/shm`, `/var/tmp`) any user can write and tooling often doesn't watch; (2) *persistence*: writing into a high-trust dir (`/etc/systemd`, `/usr/lib`, `/etc/cron.d`) so the payload survives reboot and blends in. Treat the two zones differently in your sweep: **assume nothing legitimately new appears in `/dev/shm`**, but expect constant legitimate churn in `/etc`.

## usr-merge and Symlinks

Modern distros symlink `/bin /sbin /lib /lib64` into `/usr` (the "usr-merge"). Confirm the layout before reasoning about paths — a real directory where you expect a symlink (or vice-versa) is itself an anomaly worth explaining.

```bash
ls -ld /bin /sbin /lib /lib64
```

On a merged distro these are symlinks into `/usr`. On a **mounted image**, resolve symlinks relative to the *image root*, not your analysis host's `/` — a naive `cat /bin/ls` could read your own binary instead of the evidence.

## What to Check for What

The fast index for host orientation.

| Investigative question | Command / source |
|------------------------|------------------|
| What distro & version? | `cat /etc/os-release` |
| What exact kernel (for memory analysis)? | `uname -r`; `cat /proc/version` |
| Was security disabled at boot? | `cat /proc/cmdline` (`selinux=0`, `init=`, `single`) |
| What timezone (timeline base)? | `timedatectl`; `ls -l /etc/localtime` |
| Is the clock trustworthy (NTP)? | `timedatectl` → `System clock synchronized` |
| Which auth log / package tool applies? | distro family from `os-release` (see note 00 fingerprint) |
| Do logs survive reboot? | `grep -i storage /etc/systemd/journald.conf` |
| How far back do logs actually go? | `cat /etc/logrotate.conf`; `ls -al /etc/logrotate.d/` |
| Any hidden / attacker-added mounts? | `cat /proc/mounts` vs `cat /etc/fstab` |
| Anything staged in world-writable dirs? | `ls -alht /tmp /var/tmp /dev/shm` |
| Recently changed system config? | `find /etc -type f -mmin -180 -ls` |
| Host resolution / DNS tampered? | `cat /etc/hosts /etc/resolv.conf` |
| Rogue / recently loaded kernel module? | `lsmod`; `dmesg | grep -i module` |

## System Identity and Device Profiling

Answers "what exactly am I investigating," the foundation for interpreting everything else. Distro family → which auth log, package tool, MAC layer. Kernel version → what you feed Volatility to parse a memory image.

```bash
# Hostname (three sources — they should agree)
cat /etc/hostname

cat /proc/sys/kernel/hostname

hostnamectl

# OS / distribution fingerprint
cat /etc/os-release

cat /etc/*-release

cat /etc/lsb-release 2>/dev/null

lsb_release -a 2>/dev/null

# Kernel version and build
uname -a

cat /proc/version

# Debian/Ubuntu: kernel ABI + build signature (spots a repackaged kernel)
cat /proc/version_signature 2>/dev/null

# Boot parameters
cat /proc/cmdline
```

| Artifact | Tells you | Signal to watch |
|----------|-----------|-----------------|
| `/etc/os-release` | Distro family + version → which paths/tools apply | — |
| `uname -r` / `/proc/version` | Exact kernel → memory-analysis symbol tables | Kernel newer than package history = out-of-band build |
| `/proc/cmdline` | Boot parameters | 🔴 `selinux=0`, unexpected `init=`, `single` = security/boot tampering |
| `/etc/hostname` vs `hostnamectl` | System identity | Mismatch = tampering or a cloned/imaged host |
| `/proc/version_signature` | Debian/Ubuntu kernel signature | Doesn't match distro kernel = custom/repacked kernel |

🔴 A `selinux=0` or an unexpected `init=` in `/proc/cmdline` means someone changed how the box boots (SELinux disabled, or an alternate init to bypass startup). Put it in the timeline.

## Time and Timezone

Timezone is the single most important profiling fact: most Linux text logs (syslog, `auth.log`) record *local* time with no offset. Assume UTC on an `America/Toronto` host and every event shifts hours — correlation collapses.

```bash
# System time, timezone, NTP sync state
timedatectl

# Timezone config (two representations)
cat /etc/timezone

ls -l /etc/localtime

# Convert a Unix epoch to human time
date -d @1679084718

# Show the offset for a named zone
TZ="America/Toronto" date "+%:z"
```

🔴 Record timezone and NTP-sync state before anything else. If NTP was disabled or the clock skewed (attackers occasionally do this to poison timelines), `timedatectl` shows it and you must account for the drift.

## Host Resolution and Network Identity

How the host maps names and where it points for updates/DNS — quiet but high-value tamper targets. A hijacked `hosts` file can silently redirect update/telemetry/C2 domains; a rogue `resolv.conf` points all DNS at an attacker resolver.

```bash
# Static host mappings (hijack: legit domain -> attacker IP)
cat /etc/hosts

# DNS resolvers (rogue nameserver = full DNS control)
cat /etc/resolv.conf

# Name-resolution order (files vs dns vs sss/ldap)
cat /etc/nsswitch.conf

# TCP wrappers allow/deny (legacy access control)
cat /etc/hosts.allow /etc/hosts.deny 2>/dev/null
```

| Signal | Meaning |
|--------|---------|
| A public domain mapped to an internal/odd IP in `/etc/hosts` | 🔴 Redirect of updates/telemetry/C2 |
| `nameserver` pointing to an unexpected external IP in `resolv.conf` | 🔴 Attacker-controlled DNS |
| `nsswitch.conf` lists `ldap`/`sss` | Host is domain-joined → users may not be in `/etc/passwd` (→ note 03) |

## Logging Configuration

Before concluding "there's no evidence of X," confirm the host was *capable* of logging X and the logs weren't rotated away. This establishes your evidence sources and their retention.

```bash
# rsyslog / syslog-ng routing (what gets logged, and whether it's forwarded off-box)
cat /etc/rsyslog.conf

ls -al /etc/rsyslog.d/

# journald storage (persistent vs volatile) + retention caps
cat /etc/systemd/journald.conf

# Rotation = how far back logs actually go
cat /etc/logrotate.conf

ls -al /etc/logrotate.d/
```

🔴 `Storage=volatile` in `journald.conf` (or no `/var/log/journal/` dir) means the journal lives only in RAM and dies on reboot — after which `wtmp`/`auth.log` may be your only login record. If the host was rebooted post-incident, that binary journal is already gone. A remote-forwarding line in `rsyslog.conf` (`@@host:514`) is good news — a second copy may survive on the collector even if local logs were wiped.

## Disks Partitions and Mounts

The mount picture tells you where the real data lives (LVM, LUKS, network mounts) and exposes hiding tricks — a bind mount over a directory, a `tmpfs` holding tools, an attacker-mounted external drive.

```bash
# Block devices with filesystem type and label
lsblk -f

# Filesystem type per mount
df -T

# Currently mounted (kernel view)
cat /proc/mounts

mount | grep "^/dev"

# Configured mounts (persistent intent)
cat /etc/fstab

# Partition table
cat /proc/partitions

# Identify a filesystem on a raw device
file -sL /dev/sda1
```

🔴 Cross-check `/proc/mounts` (live reality) against `/etc/fstab` (intent). A mount in one but not the other — especially a `tmpfs`, bind mount, or something under `/mnt` — is a hiding trick or an attacker volume. For LUKS/LVM specifics (`cryptsetup`, `lvs`/`vgs`/`pvs`) → File Systems (07).

## Hunt the High-Risk Zones

First-pass anomaly sweep across the staging and persistence zones. Tune the time window (`-mmin`/`-newermt`) to your incident. *(These map the "where evidence lives" tree to concrete hunts; exhaustive `find` recipes → Artifacts / Timelining.)*

```bash
# Anything written to staging + config zones in the last 3h
find /tmp /var/tmp /dev/shm /etc /var/www -type f -mmin -180 -ls 2>/dev/null

# Recently modified system config
find /etc -type f -mtime -3 -ls 2>/dev/null

find /etc -type f -mmin -180 -ls 2>/dev/null

# Executable files sitting in user homes (droppers)
find /home -type f -perm -111 -ls 2>/dev/null

# Suspicious file types written in the last 3h (prune noisy trees)
find / \( -path /proc -o -path /sys -o -path /run -o -path /var/lib -o -path /usr/lib -o -path /usr/share -o -path /var/log \) -prune -o \
  -type f \( -name "*.so*" -o -name "*.deb" -o -name "*.rpm" -o -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.tar" -o -name "*.gz" -o -name "*.zip" -o -name "*.xz" -o -perm /111 \) -mmin -180 -ls 2>/dev/null

# Same, bounded to an exact window (start .. end)
find / \( -path /proc -o -path /sys -o -path /run -o -path /var/lib -o -path /usr/lib -o -path /usr/share -o -path /var/log \) -prune -o \
  -type f -newermt "2026-04-27 00:00:00" ! -newermt "2026-04-27 03:00:00" \
  \( -name "*.so*" -o -name "*.deb" -o -name "*.rpm" -o -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -perm /111 -o ! -name "*.*" \) -ls 2>/dev/null

# Regular files under /dev (should be device nodes only)
find /dev -type f 2>/dev/null

file /dev/* | grep -vE "special|directory|symbolic"

# Hidden files & directories (attacker "dotfile" hiding)
find / -type d -iname '.*' -exec ls -alht {} \; 2>/dev/null

find / -type f -iname '.*' -mmin -1440 -ls 2>/dev/null

# Large files anywhere (staged exfil archive)
find / -type f -size +1G -ls 2>/dev/null
```

**Hunt ideas:**

- **Cluster by time, not name.** Sort every hit by mtime — files written within the same minute are usually one drop event; that cluster is your lead.
- **Diff the tree against a peer.** `find /etc /usr/local /opt -type f | sort` on the suspect vs a known-good sibling host; the delta is candidate tampering.
- **Follow the extension-less executables.** `! -name "*.*"` with an exec bit in `/tmp`/`/home` is a classic dropped-ELF pattern.
- **Cross-ref ownership.** Anything found here that a package doesn't own (`dpkg -S`/`rpm -qf` → "no path found") was hand-placed.

## Mounted Image Orientation

Working an acquired image, prefix artifact paths with the mount root (this repo uses `/mnt/evidence`):

```bash
# e.g. auth.log on the image
/mnt/evidence/var/log/auth.log

# Read-only loop mount of a raw image at a partition offset (offset = 512 * start-sector)
mount -o ro,loop,offset=$((512*227328)) disk.raw /mnt/evidence
```

The live-only tier — `/proc`, `lsmod`, `ss`, running-process memory — does **not** exist on a mounted image. Collect it on the live host *before* imaging (→ Live Response, Evidence Collection).

## Correlate With

Note 01 tells you *what the host is*; pivot to act on it.

| To answer… | Pivot to |
|------------|----------|
| Interpret the timestamps you found / build the sequence | **Cross-Artifact Correlation** (00), **Timelining** (13) |
| SUID/caps/xattrs/timestomp of a suspicious file | **File and Directory Permissions** (02) |
| Who owns / uses the accounts (sudoers, groups) | **Users Groups and Authentication** (03) |
| Read the logs you located | **06 - Logs** (Journal / Auth / Auditd) |
| Deep-dive a loaded kernel module | **Kernel Modules and LKM Rootkits** (persistence) |
| Recover deleted / fileless artifacts | **Live Response** (10), **File Systems** (07) |
| Verify integrity of system binaries | **Package Managers and Integrity** (08) |
| Filesystem-specific timestamp caveats (crtime, relatime) | **File Systems** (07) |

## Scenarios

- **New host handoff:** profile end-to-end before touching anything — TZ, distro, kernel, mounts, logging capability — so every later finding is interpreted correctly.
- **Mounted-image triage:** orient to the image root, resolve symlinks against it, read config/logs (not live state).
- **"Nothing in the logs":** prove the host could log it and retained it (journald storage + logrotate) before writing a non-finding.
- **Timeline skew:** a local-time syslog line vs a UTC filesystem time — the TZ established here reconciles them.
- **Boot tampering:** `selinux=0` / alternate `init=` in `/proc/cmdline` shows defenses were dropped at boot.
- **Hidden mount:** a `tmpfs` or bind mount in `/proc/mounts` but not `/etc/fstab`, concealing a payload or data store.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| Executable / recently-modified files in `/tmp` `/var/tmp` `/dev/shm` | Prime malware staging |
| Regular files under `/dev` | `/dev` should hold device nodes, not payloads |
| Unexpected mount in `/proc/mounts` not in `/etc/fstab` | Hidden data store or bind-mount trick |
| `journald` volatile + thin `/var/log` | Logs may not survive reboot — capture now |
| Host timezone mismatched to log-tool assumption | Timeline skew |
| Recently loaded / out-of-tree kernel module (`lsmod`, `dmesg`) | Possible LKM rootkit or driver persistence |
| `selinux=0` or unexpected `init=` in `/proc/cmdline` | Security disabled / alternate boot path |
| Public domain → odd IP in `/etc/hosts`, or rogue `resolv.conf` nameserver | Resolution hijack for redirect / C2 |
| Large (>1G) archive in a user home or `/tmp` | Staged exfil |
| Kernel/`version_signature` inconsistent with distro | Custom or repackaged kernel |

## Resources

- Filesystem Hierarchy Standard (FHS) — https://refspecs.linuxfoundation.org/fhs.shtml
- `hier(7)`, `os-release(5)`, `timedatectl(1)`, `proc(5)` man pages
- MITRE ATT&CK: T1082 (System Information Discovery), T1614 (System Location Discovery), T1070.006 (Timestomp — timezone/clock context), T1564 (Hide Artifacts)
