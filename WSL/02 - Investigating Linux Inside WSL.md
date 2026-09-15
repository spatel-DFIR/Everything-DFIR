# Investigating Linux Inside WSL

The **Linux-side** of WSL DFIR: you're working inside (or against the mounted filesystem of) a WSL distribution, and you want to run your normal Linux investigation — with the WSL-specific caveats that change what applies. WSL is *mostly* real Linux, so the entire Linux note-set works here, but four things differ enough to trip you up: **no `systemd` by default**, a Microsoft **`/init`** instead of the usual init, the **`/mnt/c` + interop** bridge to Windows, and WSL-native **persistence** spots. This note covers confirming you're in WSL, those differences, and where WSL persistence and cross-OS pivots hide.

> 🔴 Treat a WSL distro as a Linux host *with a door to Windows*. The two WSL-specific hunts that a bare-metal Linux sweep misses: **`/etc/wsl.conf` `[boot] command=`** (runs as root on every distro start) and **interop** (Linux launching `powershell.exe`/`cmd.exe`, and the Windows `%LOCALAPPDATA%` reachable via `/mnt/c`) — the cross-OS pivot that lets a Linux payload evade Windows EDR and still own the host.

## Contents

- [Confirm You Are in WSL](#confirm-you-are-in-wsl)
- [WSL1 vs WSL2 Differences](#wsl1-vs-wsl2-differences)
- [Init and systemd](#init-and-systemd)
- [The Windows Bridge mnt c and Interop](#the-windows-bridge-mnt-c-and-interop)
- [WSL-Native Persistence](#wsl-native-persistence)
- [Networking](#networking)
- [Running the Linux Notes Here](#running-the-linux-notes-here)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Confirm You Are in WSL

```bash
# The kernel banner names Microsoft/WSL
cat /proc/version              # ...-microsoft-standard-WSL2...  or  "Microsoft" (WSL1)
uname -r                       # contains 'microsoft' / 'WSL2'
cat /proc/sys/kernel/osrelease # same tell

# WSL environment variables
env | grep -Ei 'WSL_DISTRO_NAME|WSL_INTEROP|WSLENV'

# The interop socket + Microsoft init existing
ls -l /run/WSL/ 2>/dev/null; ls -l /init 2>/dev/null
```

🔴 `microsoft` in the kernel release, `WSL_DISTRO_NAME`/`WSL_INTEROP` in the environment, and `/init` as PID 1's binary are the confirmations. Knowing you're in WSL changes your expectations (init, systemd, network, the Windows bridge).

## WSL1 vs WSL2 Differences

```bash
# WSL2 has a real kernel + full /proc + modules; WSL1 translates syscalls (limited)
cat /proc/version | grep -q 'WSL2' && echo "WSL2 (real kernel)" || echo "WSL1 (syscall translation)"

lsmod 2>/dev/null            # WSL2: real modules; WSL1: often empty / unsupported
ls /proc/sys/kernel/         # WSL1 is missing much of this
```

- **WSL1** — no real kernel, so kernel-rootkit / LKM / eBPF checks don't apply, and parts of `/proc` are absent. The filesystem is NTFS-backed (Linux metadata in NTFS EAs).
- **WSL2** — a genuine Linux kernel in a VM, so most Linux techniques (LKM, eBPF, memory, full `/proc`) work; the filesystem is `ext4.vhdx`.

## Init and systemd

🔴 WSL does **not** use the normal init. PID 1 is Microsoft's **`/init`**; `systemd` runs only if a distro opted in via `/etc/wsl.conf` `[boot] systemd=true` (a relatively recent feature).

```bash
# What's PID 1?
ps -p 1 -o pid,comm,args         # 'init' (Microsoft) unless systemd was enabled

# Is systemd actually running here?
[ -d /run/systemd/system ] && echo "systemd active" || echo "NO systemd (WSL default)"
grep -i systemd /etc/wsl.conf 2>/dev/null
```

🔴 If systemd is **off** (the WSL default), then **systemd-unit / timer persistence, journald, and cron-via-systemd don't run** — so those Linux persistence checks are moot here, and you must lean on the WSL-native and shell-based ones. If systemd **is** on, the normal Linux → Systemd persistence applies. Always establish which.

## The Windows Bridge mnt c and Interop

The defining WSL feature — and the cross-OS attack surface:

```bash
# Windows drives mounted into Linux (drvfs)
mount | grep -Ei 'drvfs|9p|drive'          # /mnt/c, /mnt/d ...
ls -la /mnt/c/Users/                        # the Windows user profiles, reachable from Linux

# Interop: is launching Windows .exe from Linux enabled?
cat /proc/sys/fs/binfmt_misc/WSLInterop 2>/dev/null    # 'enabled' = Linux can run Windows exes
grep -i interop /etc/wsl.conf 2>/dev/null

# Evidence of interop USE — Windows binaries invoked from the Linux history
grep -Ei '\.exe|cmd\.exe|powershell|/mnt/c/' /home/*/.bash_history /root/.bash_history 2>/dev/null
```

🔴 `/mnt/c` gives Linux read/write to the Windows filesystem — a payload can drop to Windows startup folders, read Windows creds, or stage there. **Interop** (`WSLInterop` binfmt handler) lets Linux execute `powershell.exe`/`cmd.exe` directly. A `.exe` or `/mnt/c/...` in the Linux shell history is the Linux→Windows pivot — hunt it.

## WSL-Native Persistence

Beyond standard Linux persistence, WSL adds its own — and *removes* some (no systemd/cron by default):

| Vector | Location | Note |
|--------|----------|------|
| 🔴 `[boot] command=` | `/etc/wsl.conf` | Runs as **root** on every distro start |
| Shell startup | `~/.bashrc`, `~/.profile`, `/etc/profile.d/*` | Fires when the user opens a WSL shell (very common WSL persistence) |
| systemd units/timers | (only if `[boot] systemd=true`) | Applies *only* when systemd is enabled |
| cron | `/etc/crontab`, `/var/spool/cron` | Only runs if `cron`/systemd is actually started (often **not** in WSL) |
| Windows side | Scheduled Task / Run key → `wsl.exe -e` | Windows-side auto-start of the Linux payload (see the Windows-artifacts note) |

```bash
# The WSL-native boot command + the shell-startup surface
grep -A2 '\[boot\]' /etc/wsl.conf 2>/dev/null
grep -rIE 'curl|wget|/dev/tcp|base64|powershell|/mnt/c' /home/*/.bashrc /home/*/.profile /etc/profile.d/* 2>/dev/null
```

🔴 Because cron/systemd frequently aren't running, WSL persistence gravitates to `[boot] command=`, shell-startup files, and the **Windows-side launcher** — check those first, not the systemd sweep.

## Networking

```bash
# WSL2 has its own NAT'd network (a vEthernet on the Windows side)
ip a; ip route
cat /etc/resolv.conf            # 🔴 often auto-generated pointing at the Windows host; a rogue edit = DNS control
ss -tunap 2>/dev/null           # listeners/connections (WSL2 forwards localhost to Windows)
```

🔴 WSL2 localhost is forwarded to/from Windows, so a listener inside WSL can be reachable from the Windows host's `localhost` — a subtle way to expose a Linux backdoor to Windows-side tooling or the network.

## Running the Linux Notes Here

Once you've established WSL version + init/systemd status, run the standard Linux investigation with these substitutions:

- **Live triage** — Live Response, Process Trees, Shells, Users all work (WSL2). On WSL1, skip kernel-rootkit/LKM/eBPF.
- **Logs** — no journald unless systemd is on; check shell histories, `/var/log` (sparse in WSL), and the Windows-side execution artifacts.
- **Persistence** — WSL-native (above) + shell-startup; systemd/cron only if actually running.
- **Filesystem/timeline** — WSL2 `ext4.vhdx` supports ext4 + Sleuth Kit + mactime; image the vhdx (Windows-artifacts note) for offline work.
- **Malware** — a Linux ELF payload here is invisible to Windows EDR — triage it with ELF and Malware Triage; check for the `/mnt/c` + interop pivot.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| The Windows-host side (vhdx, registry, launchers) | [**WSL → 01 - WSL Artifacts on the Windows Host**](<01 - WSL Artifacts on the Windows Host.md>) — vhdx location, LXSS registry keys, Windows-side execution traces, event logs |
| Windows-side launcher artifacts (prefetch, scheduled tasks) | [**Windows → 06 - Evidence of Program Execution**](<../Windows/06 - Evidence of Program Execution/Prefetch.md>) — wsl.exe/wslhost.exe prefetch analysis, execution timeline |
| Standard live triage inside the distro | [**Linux → 10 - Live Response and Volatile Data**](<../Linux/10 - Live Response and Volatile Data.md>) — process inspection, `/proc` goldmine, running-process artifacts |
| Shell history analysis + anti-forensics | [**Linux → 04 - Shells and Command History**](<../Linux/04 - Shells and Command History.md>) — bash/zsh history format, hidden history, evidence evasion |
| Cron jobs and scheduled tasks (if running) | [**Linux → 09 - Persistence Mechanisms → Cron and at Jobs**](<../Linux/09 - Persistence Mechanisms/Cron and at Jobs.md>) — **WSL note:** cron often does NOT run by default; prioritize `[boot] command=` and shell startup instead |
| systemd persistence (only if `[boot] systemd=true`) | [**Linux → 09 - Persistence Mechanisms → Systemd Units Timers and Generators**](<../Linux/09 - Persistence Mechanisms/Systemd Units Timers and Generators.md>) — units, timers, systemd.d overrides (applies only when systemd is enabled in wsl.conf) |
| Triage a Linux ELF payload found in the distro | [**Linux → 11b - ELF and Malware Triage**](<../Linux/11b - ELF and Malware Triage.md>) — static and dynamic analysis, imports, sandboxed execution (payload is invisible to Windows EDR) |
| ext4 forensics on the mounted vhdx | [**Linux → 07 - File Systems → ext4**](<../Linux/07 - File Systems/ext4.md>) — inode inspection, journal recovery, deleted-file carving |
| Timeline generation from the vhdx | [**Linux → 13 - Timelining**](<../Linux/13 - Timelining.md>) — The Sleuth Kit mactime, Plaso timeline building, event correlation |
| Package install / system integrity | [**Linux → 08 - Artifacts → Package Managers and Integrity**](<../Linux/08 - Artifacts/Package Managers and Integrity.md>) — rpm/dpkg logs, package tampering, supply-chain compromise |
| WSL-specific registry config (from Windows side) | [**WSL → 03 - WSL Registry & Configuration Deep-Dive**](<03 - WSL Registry & Configuration Deep-Dive.md>) — detailed LXSS key reference, unauthorized distro detection |
| WSL hunting: cross-OS activity | [**WSL → 04 - WSL-Specific Hunting & Detection**](<04 - WSL-Specific Hunting & Detection.md>) — VHD access patterns, wsl.exe ancestry, interop pivots |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `[boot] command=` in `/etc/wsl.conf` | Root persistence on distro start |
| `.exe`/`powershell`/`/mnt/c/` in the Linux shell history | Linux→Windows interop pivot |
| Payload written to `/mnt/c/...` (Windows startup, profiles) | Cross-OS drop / staging |
| Linux ELF miner/backdoor running in the distro | EDR-evasion (Windows tooling can't see it) |
| `resolv.conf` pointing at a non-host DNS | DNS redirection |
| systemd enabled + a rogue unit | Standard Linux persistence, now applicable |

## Resources

- WSL for Linux DFIR — https://learn.microsoft.com/windows/wsl/
- `wsl.conf` `[boot]`/`[interop]` — https://learn.microsoft.com/windows/wsl/wsl-config
- WSL interop (`binfmt_misc` `WSLInterop`) — https://learn.microsoft.com/windows/wsl/interop
