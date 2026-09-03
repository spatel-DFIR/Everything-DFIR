# Temp and Staging Locations

`/tmp`, `/var/tmp`, `/dev/shm`, and `/run/user` are world-writable and lightly monitored, which makes them the default staging grounds for droppers, payloads, and exfil archives — check them on every Linux case. The nuance worth internalizing is that these directories differ in *persistence* and *backing store*: `/tmp` is often RAM-backed and cleaned periodically, `/var/tmp` survives reboots, and `/dev/shm` is pure RAM and a favorite for fileless malware. Where you find something matters as much as what you find.

> 🔴 `/dev/shm` is RAM-backed and world-writable — the perfect home for fileless malware: drop a `.so`, `LD_PRELOAD` it into a process, delete it, and it lives only in memory. An executable with no extension in `/tmp`/`/dev/shm`, or a `.so` in `/dev/shm`, is a payload until proven otherwise.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [The Staging Directories](#the-staging-directories)
- [Hunting Temp Locations](#hunting-temp-locations)
- [Hiding Inside Legit Dot-Dirs](#hiding-inside-legit-dot-dirs)
- [dev shm and Fileless Staging](#dev-shm-and-fileless-staging)
- [Service PrivateTmp Namespaces](#service-privatetmp-namespaces)
- [tmpfiles Cleanup Timing](#tmpfiles-cleanup-timing)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Everything recently written to staging dirs (last 3h)
find /tmp /var/tmp /dev/shm /run/user -type f -mmin -180 -ls 2>/dev/null

# Executables in world-writable temp areas
find /tmp /var/tmp /dev/shm -type f -perm -111 -ls 2>/dev/null

# Large files (exfil archives staged for pickup)
find /tmp /var/tmp /dev/shm -type f -size +50M -ls 2>/dev/null

# Shared objects in /dev/shm (fileless malware)
ls -la /dev/shm/*.so 2>/dev/null
```

## What to Check for What

| Investigative question | Command / filter |
|------------------------|------------------|
| Dropped ELF payload? | `find /tmp /var/tmp /dev/shm -type f ! -name '*.*' -perm -111` |
| Fileless `.so` in shared memory? | `ls -la /dev/shm/*.so`; deleted mappings |
| Payload hidden in a legit dot-dir? | `find /tmp/.*-unix /dev/shm -type f` |
| Known miner/bot dropped? | `find … -iname 'kdevtmpfsi*' -o -iname 'xmrig*' -o -iname '.configrc*'` |
| Reboot-surviving staging? | `find /var/tmp -type f -mmin -… -ls` (disk-backed) |
| Exfil archive staged? | `find /tmp /var/tmp -type f -size +50M` |
| A staged file actively running? | `fuser -v <file>`; tie file → process |
| Payload in a service's private /tmp? | `ls /tmp/systemd-private-*/tmp/` |
| How long could a file have survived? | `tmpfiles.d` cleanup age |

> ⚠️ **Disk-image caveat:** `/tmp` and `/dev/shm` are usually **tmpfs (RAM)** — they're *empty* on a dead-disk image. Only `/var/tmp` persists offline; capture `/tmp`/`/dev/shm` (and a memory image) on the **live host**.

## The Staging Directories

The four staging directories differ in ways that change how you interpret a finding — a file in `/var/tmp` outlived a reboot (so it's older, more deliberate persistence), while one in `/dev/shm` is RAM-only and tied to the current boot.

| Path | Backing | Survives reboot? | Notes |
|------|---------|------------------|-------|
| `/tmp` | disk or tmpfs | often no (tmpfs) | World-writable + sticky; #1 dropper target 🔴 |
| `/var/tmp` | disk | **yes** | Persistent temp — staging that outlives `/tmp` cleaning 🔴 |
| `/dev/shm` | tmpfs (RAM) | no | World-writable shared memory; fileless `.so`, in-RAM payloads 🔴 |
| `/run/user/<uid>` | tmpfs (RAM) | no | Per-user runtime; sockets, keyrings, staged files |
| `/run` `/var/run` | tmpfs | no | PID files, sockets |

```bash
# Inspect with timestamps, including hidden files
ls -alht /tmp /var/tmp /dev/shm

ls -alht /run/user/*/ 2>/dev/null

# Hidden files/dirs in temp (dot-prefixed to evade a casual ls)
find /tmp /var/tmp /dev/shm -name ".*" -ls 2>/dev/null
```

🔴 A file in `/var/tmp` tied to the incident is notable precisely *because* it survives reboots — an attacker who wants their staging to persist past a restart chooses `/var/tmp` over `/tmp`. And dot-prefixed (hidden) files in any of these are a deliberate evasion of a casual `ls`.

## Hunting Temp Locations

```bash
# Suspicious files modified in temp + common web/config dirs (last 3h)
find /tmp /var/tmp /dev/shm /etc /var/www -type f -mmin -180 -ls 2>/dev/null

# Suspicious extensions and executables system-wide, pruned for speed (last 3h)
find / \( -path /proc -o -path /sys -o -path /run -o -path /var/lib -o -path /usr/lib -o -path /usr/share -o -path /var/log \) -prune -o \
  -type f \( -name "*.so*" -o -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.elf" -o -name "*.bin" -o -perm /111 \) \
  -mmin -180 -ls 2>/dev/null

# Time-window variant (bracket the incident)
find / \( -path /proc -o -path /sys -o -path /run \) -prune -o \
  -type f -newermt "2026-04-27 00:00:00" ! -newermt "2026-04-27 03:00:00" \
  \( -name "*.sh" -o -name "*.py" -o -perm /111 -o ! -name "*.*" \) -ls 2>/dev/null

# Files with no extension that are executable (common for dropped ELF payloads)
find /tmp /var/tmp /dev/shm -type f ! -name "*.*" -perm -111 -ls 2>/dev/null
```

The `! -name "*.*"` filter is deliberate: dropped ELF payloads are frequently *extensionless* and given innocuous or random names (`kdevtmpfsi`, `xmrig`, a hex string), so "executable with no extension in a temp dir" is a high-signal pattern that a simple `*.sh`/`*.py` search would miss.

## Hiding Inside Legit Dot-Dirs

🔴 A favorite evasion: attackers drop payloads *inside* the legitimate dot-prefixed socket directories in `/tmp` (`/tmp/.ICE-unix`, `/tmp/.X11-unix`, etc.). These dirs are real and expected, so they blend in and survive a casual `ls /tmp` — but they should contain only **sockets**, never regular files or executables.

```bash
# Regular files inside dirs that should hold ONLY sockets
find /tmp/.ICE-unix /tmp/.X11-unix /tmp/.font-unix /tmp/.Test-unix /tmp/.XIM-unix \
     /dev/shm -type f 2>/dev/null

# Known miner / bot names + config drops in staging
find /tmp /var/tmp /dev/shm /run -maxdepth 3 \
  \( -iname 'kdevtmpfsi*' -o -iname 'xmrig*' -o -iname 'kinsing*' -o -iname '.configrc*' -o -iname '.x' \) -ls 2>/dev/null

# Weird directory names (dots/spaces) used purely to hide
find /tmp /var/tmp /dev/shm -maxdepth 2 \( -name '...' -o -name '... ' -o -name ' ' \) 2>/dev/null
```

🔴 A **regular file or ELF inside `/tmp/.ICE-unix`** or `/tmp/.X11-unix` is essentially always malicious — those directories are for X11/ICE sockets only.

## dev shm and Fileless Staging

```bash
# .so files staged in shared memory (LD_PRELOAD payloads, injected libs)
ls -la /dev/shm/

# Processes mapping a deleted/shm shared object
lsof +L1 | grep -E "/dev/shm|deleted"

fuser -v /dev/shm/* 2>/dev/null

# Deleted .so still mapped by a process
for p in /proc/[0-9]*; do ls -la "$p/map_files/" 2>/dev/null | grep -q "\.so.*(deleted)" && \
  ps -p "$(basename "$p")" -o user,pid,ppid,cmd --no-headers; done
```

🔴 `/dev/shm` being RAM-backed and world-writable makes it the textbook fileless technique: an attacker writes a shared object there, `LD_PRELOAD`s it into a process (hiding files/PIDs at the libc level, or just executing code), then deletes it — after which it exists only in the mapped memory of the victim process. The full deleted-mapping hunt is in the Live Response and Memory notes.

## Service PrivateTmp Namespaces

🔴 systemd services with `PrivateTmp=yes` get their **own private `/tmp` and `/dev/shm`**, mounted under `/tmp/systemd-private-<id>-<service>-*/tmp/`. A payload dropped by (or into) a compromised service lives there, *not* in the shared `/tmp` — so a top-level `/tmp` sweep misses it.

```bash
# Every service's private tmp — a compromised service stages here
ls -la /tmp/systemd-private-*/tmp/ /tmp/systemd-private-*/tmp/.* 2>/dev/null

find /tmp/systemd-private-*/tmp -type f -perm -111 -ls 2>/dev/null
```

## tmpfiles Cleanup Timing

Evidence lifespan in temp directories is governed by systemd-tmpfiles, not chance — knowing the cleanup age tells you how long a dropped file *could* have survived and whether an absence is meaningful.

```bash
# Cleanup rules (age thresholds that delete files in /tmp, /var/tmp, etc.)
cat /usr/lib/tmpfiles.d/tmp.conf /etc/tmpfiles.d/*.conf 2>/dev/null

# When cleanup last/next runs
systemctl list-timers | grep -i tmpfiles
```

The common defaults are ~10 days for `/tmp` and ~30 days for `/var/tmp`. So if the incident is within that window, a dropped file *should* still be present; if it's gone, that could be either cleanup or deliberate deletion — the config tells you which explanation is even possible.

## Deep Threat Hunts

Full staging sweep with content triage + process attribution. *(seasoned-DFIR)*

```bash
# 1. Extensionless executables in staging (top dropper pattern)
find /tmp /var/tmp /dev/shm /run/user -type f ! -name '*.*' -perm -111 -ls 2>/dev/null

# 2. Payloads hidden inside legit dot-socket dirs
find /tmp/.*-unix /dev/shm -type f 2>/dev/null

# 3. Service PrivateTmp namespaces
find /tmp/systemd-private-*/tmp -type f -perm -111 -ls 2>/dev/null

# 4. Triage every staged binary: type + hash (feed hashes to IOC/YARA)
for f in $(find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null); do
  echo "== $f =="; file "$f"; sha256sum "$f"
done

# 5. Is the staged file actively RUNNING? (leftover vs active malware)
for f in $(find /tmp /var/tmp /dev/shm -type f -perm -111 2>/dev/null); do
  fuser -v "$f" 2>/dev/null
done

# 6. Immutable-armored or SUID staging
lsattr /tmp/* /var/tmp/* /dev/shm/* 2>/dev/null | grep -E '^....i'

find /tmp /var/tmp /dev/shm -perm -4000 -ls 2>/dev/null

# 7. Deleted .so still mapped by a process (fileless survivor)
grep -l '/dev/shm' /proc/*/maps 2>/dev/null | while read m; do grep -q deleted "$m" && echo "$m"; done
```

**Hunt ideas:**

- **Extensionless + executable in a temp dir is the single highest-signal dropper pattern** — miners like `kdevtmpfsi`/`xmrig` use exactly this.
- **Attackers hide inside legit dot-dirs** (`/tmp/.ICE-unix`, `/tmp/.X11-unix`) that should hold only sockets — a regular file there is almost always malicious.
- **Check service `PrivateTmp` namespaces**, not just top-level `/tmp` — a compromised systemd service stages in its own private `/tmp`.
- **Tie every staged binary to a process** (`fuser`/`lsof`) — a staged file that's *running* is active malware, not leftover junk.
- **On a disk image `/tmp` and `/dev/shm` are empty** (tmpfs) — capture them live or from a memory image.

## Getting Max Value

- **Live capture is essential** for `/tmp` and `/dev/shm` (tmpfs) — they don't exist on a dead-disk image; grab their contents plus a RAM image before reboot.
- **Triage each staged binary** (`file`/`sha256sum`/`strings`) and **tie it to a running process** (`fuser`) to separate active malware from residue.
- **Use `tmpfiles.d` cleanup age** to reason about whether a file's absence is routine cleanup or deliberate deletion.
- **Check the sneaky spots** — legit dot-socket dirs and `PrivateTmp` namespaces, not just top-level `/tmp`.
- **Hash → IOC/YARA + reputation** for every dropped binary.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| The fileless `/dev/shm` `.so` in depth | **Live Response** (10), **Memory Forensics** (11), **Persistence → Preload** |
| Reverse/triage the dropped binary | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| Is it running + its lineage | **Live Response** (10), **Process Trees** (10b) |
| How it got there (web/exec) | **Application and Database Logs**, **Auditd** |
| When it was dropped | **Timelining** (13), file mtime |
| Miner-campaign context | **Cryptojacking Playbook** (15) |

## Scenarios

- **Dropper:** an extensionless ELF in `/tmp` that's actively running — active malware, not residue.
- **Fileless:** a `.so` in `/dev/shm`, `LD_PRELOAD`ed then deleted — lives only in the victim process's memory.
- **Hidden in plain sight:** a payload tucked inside `/tmp/.ICE-unix`, blending with X11 sockets.
- **Reboot-surviving:** staging placed in `/var/tmp` so it outlives a restart.
- **Service compromise:** a payload in `/tmp/systemd-private-*/tmp/` that a top-level `/tmp` sweep never sees.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| Executable / ELF with no extension in `/tmp`/`/dev/shm` | Dropped payload |
| `.so` in `/dev/shm` | Fileless injection library |
| Large archive staged in a temp dir | Exfil awaiting pickup |
| Hidden (dot) files/dirs in temp | Evasion |
| Files in `/var/tmp` (persistent) tied to the incident | Reboot-surviving staging |
| Deleted `.so` still mapped by a process | In-memory malware |
| Regular file inside `/tmp/.ICE-unix` / `.X11-unix` | Payload hidden in a socket dir |
| Executable in `/tmp/systemd-private-*/tmp/` | Compromised service staging |
| `kdevtmpfsi`/`xmrig`/`.configrc` in staging | Cryptominer campaign |

## Resources

- `systemd-tmpfiles(8)`, `tmpfiles.d(5)`, `systemd.exec(5)` (PrivateTmp) man pages
- MITRE ATT&CK: T1036 (Masquerading), T1564 (Hide Artifacts), T1574.006 (LD_PRELOAD), T1496 (Resource Hijacking), T1027 (Obfuscated Files)
