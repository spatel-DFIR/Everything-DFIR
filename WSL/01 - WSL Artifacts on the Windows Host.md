# WSL Artifacts on the Windows Host

Windows Subsystem for Linux (WSL) runs Linux distributions on a Windows machine — and from a DFIR standpoint it's a **blind spot attackers exploit**: a Linux payload running inside WSL is frequently invisible to Windows EDR, which doesn't inspect the Linux VM's processes or its `ext4.vhdx` disk. This note is the **Windows-host side**: where WSL stores its state, how to find and mount the Linux filesystem offline, and the registry/config/log artifacts that reveal which distros exist and how they're used. (The Linux-side investigation — running DFIR *inside* the distro — is the companion note.)

> 🔴 The Linux root filesystem of a WSL2 distro lives in a single **`ext4.vhdx`** virtual disk under the user's `%LOCALAPPDATA%\Packages\...`. That VHDX *is* the evidence container — mount it read-only from Windows and run the entire Linux note-set against it. Windows EDR usually treats WSL as opaque, so this is where the Linux malware, its persistence, and its history actually are.

## Contents

- [WSL1 vs WSL2](#wsl1-vs-wsl2)
- [The Lxss Registry Keys](#the-lxss-registry-keys)
- [Where the Linux Filesystem Lives](#where-the-linux-filesystem-lives)
- [Mounting the Distro Offline](#mounting-the-distro-offline)
- [Configuration Files](#configuration-files)
- [Execution and Usage Evidence](#execution-and-usage-evidence)
- [Interop and the Windows Boundary](#interop-and-the-windows-boundary)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## WSL1 vs WSL2

The two versions store evidence very differently — identify which a distro uses (registry `Version`/`Flags`, below):

| | WSL1 | WSL2 |
|-|------|------|
| Kernel | None — syscall translation to the NT kernel | A **real Linux kernel** in a lightweight Hyper-V VM |
| Linux filesystem | Files on **NTFS**, Linux metadata in NTFS **extended attributes** | A single **`ext4.vhdx`** virtual disk |
| Where | `%LOCALAPPDATA%\lxss\rootfs\` (legacy) | `%LOCALAPPDATA%\Packages\<PFN>\LocalState\ext4.vhdx` |
| Offline analysis | Read NTFS + decode the EAs (`$LXUID`, `$LXMOD`, `lxattrb`) | Mount the `.vhdx`, parse the ext4 inside |
| Real kernel artifacts (LKM, full `/proc`) | No | Yes |

## The Lxss Registry Keys

The authoritative inventory of installed distros lives in the user's registry hive:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss\
  DefaultDistribution        = GUID of the default distro
  {GUID}\                     = one subkey per installed distro
      DistributionName        = e.g. "Ubuntu-22.04"
      BasePath                = 🔴 where the distro's files/vhdx live (can be ANY path)
      PackageFamilyName        = the Store package (maps to %LOCALAPPDATA%\Packages\...)
      Version                  = 1 or 2 (WSL1 vs WSL2)
      Flags                    = interop / mount / drive-mount bits
      DefaultUid               = default Linux user (0 = root default = suspicious)
      State                    = install state
```

🔴 Read this offline from `NTUSER.DAT` (per user). A distro with **`DefaultUid = 0`** (root by default), a **`BasePath` in an unusual location** (an imported/side-loaded distro, e.g. under a temp or Downloads path), or a distro name you don't recognise is a lead. Imported distros (`wsl --import`) are the attacker's favourite — arbitrary rootfs, arbitrary location.

**See also:** [**WSL → 03 - WSL Registry & Configuration Deep-Dive**](<03 - WSL Registry & Configuration Deep-Dive.md>) for a complete registry key-by-key reference and flag bit interpretation. For generic registry-hive acquisition and LastWrite mechanics, see [**Windows → 04 - Registry Forensics Fundamentals**](<../Windows/04 - Registry Forensics Fundamentals.md>).

## Where the Linux Filesystem Lives

```
# WSL2 (Store-installed) — the ext4 virtual disk holding the whole Linux root
%LOCALAPPDATA%\Packages\<PackageFamilyName>\LocalState\ext4.vhdx
   e.g. C:\Users\<u>\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu22.04LTS_<hash>\LocalState\ext4.vhdx

# WSL2 (imported / wsl --import) — vhdx at the registry BasePath (anywhere)

# WSL1 (legacy) — files directly on NTFS with metadata in extended attributes
%LOCALAPPDATA%\lxss\rootfs\           and  %LOCALAPPDATA%\lxss\home\
```

🔴 The `ext4.vhdx` is a full Linux disk image — everything from Linux → Evidence Collection applies to it once mounted. It also holds Linux timestamps (real ext4 crtime/mtime), so the Linux timelining techniques work.

## Mounting the Distro Offline

```powershell
# Preferred forensic path: image ext4.vhdx, then parse the ext4 offline (Arsenal Image Mounter,
# FTK Imager, The Sleuth Kit against the extracted ext4) — read-only.

# Quick live triage (Windows): attach the VHDX read-only, then read the ext4 inside
#   (needs an ext4-capable reader; Windows can attach the VHDX but not natively read ext4)
Mount-VHD -Path "...\ext4.vhdx" -ReadOnly

# WSL's own mount (live host) — exposes the distro's filesystem
wsl --mount --vhd "...\ext4.vhdx" --bare       # then read via a helper distro
wsl --list --verbose                            # distros + version + state
wsl --status                                    # default distro/version, kernel
```

🔴 On a live box, `\\wsl$\<distro>\` (or `\\wsl.localhost\<distro>\`) exposes a *running* distro's filesystem to Windows tools — handy for quick triage, but for evidence, image the `ext4.vhdx` and work on the copy (the running distro is volatile and mutable).

## Configuration Files

```
# Global WSL2 settings (Windows side) — memory, networking, kernel override
%USERPROFILE%\.wslconfig
   [wsl2] kernel=<path>       # 🔴 a custom kernel path = a modified/backdoored kernel
   [wsl2] networkingMode=...

# Per-distro settings (INSIDE the Linux fs, at /etc/wsl.conf)
/etc/wsl.conf
   [boot] command=<cmd>       # 🔴 runs as ROOT on every distro start = WSL persistence
   [boot] systemd=true         # whether systemd (and systemd persistence) is active
   [interop] enabled=...       # can WSL launch Windows .exe?
   [automount] enabled=...     # is C: auto-mounted at /mnt/c?
```

🔴 `[boot] command=` in a distro's `/etc/wsl.conf` runs as root every time the distro starts — a WSL-native persistence spot. A **custom `kernel=`** in `.wslconfig` points WSL2 at an attacker-supplied kernel image.

## Execution and Usage Evidence

Windows-side traces that WSL was used (and how):

```
# Windows execution artifacts for the launchers
Prefetch:   WSL.EXE-*.pf, WSLHOST.EXE-*.pf, BASH.EXE-*.pf
Amcache / SRUM:  wsl.exe, wslhost.exe execution + network usage
Task Scheduler:  a task launching wsl.exe / bash.exe = Windows-side auto-start of WSL

# Command history that shows wsl usage
%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Windows Terminal state / settings.json (WSL profiles)

# WSL / Hyper-V event logs
Microsoft-Windows-Hyper-V-* , and the WSL service (LxssManager) events
```

🔴 A **Scheduled Task or Run key launching `wsl.exe -e <cmd>`** is Windows-side persistence that executes *inside* Linux — bridging the two OSes and dodging Linux-only and Windows-only hunts alike.

## Interop and the Windows Boundary

WSL deliberately bridges the two OSes — the boundary is an attack surface:

- **Windows drives are mounted into Linux** at `/mnt/c`, `/mnt/d` (drvfs) — WSL can read/write the Windows filesystem, drop payloads on it, or read Windows credentials.
- **WSL can launch Windows binaries** (interop): `cmd.exe`, `powershell.exe`, any `.exe` runs from inside the distro — Linux→Windows pivot / execution.
- **Windows can launch Linux commands**: `wsl.exe <cmd>`, `wsl -e bash -c '...'` — Windows→Linux pivot.

🔴 The cross-OS pivot is the whole point for an attacker: run the payload in WSL to evade Windows EDR, then reach back to Windows via interop (drop to `/mnt/c`, launch `powershell.exe`). Look for WSL processes spawning Windows processes and vice-versa.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| Investigating the Linux side (running in the distro) | [**WSL → Investigating Linux Inside WSL**](<02 - Investigating Linux Inside WSL.md>) — confirmation steps, init/systemd status, persistence, interop pivots |
| Registry mechanics: how to read LXSS keys offline | [**Windows → 04 - Registry Forensics Fundamentals**](<../Windows/04 - Registry Forensics Fundamentals.md>) — hive structure, LastWrite, transaction logs, `NTUSER.DAT` live-hive reads |
| Event log hunting for WSL activity | [**Windows → 11 - Event Log Analysis**](<../Windows/11 - Event Log Analysis.md>) — LxssManager event parsing, Hyper-V-* provider events, process-creation event 4688 |
| Parsing the mounted ext4 (inodes/timeline/deleted files) | [**Linux → 07 - File Systems → ext4**](<../Linux/07 - File Systems/ext4.md>) — inode structure, journal recovery, deleted-file carving, ext4 timestamps |
| ext4 forensic timeline generation | [**Linux → 13 - Timelining**](<../Linux/13 - Timelining.md>) — The Sleuth Kit mactime, Plaso, Timesketch against mounted vhdx |
| Persistence mechanisms inside the distro | [**Linux → 09 - Persistence Mechanisms**](<../Linux/09 - Persistence Mechanisms/Persistence Overview and Sweep.md>) — cron, systemd units, shell startup, SSH keys (WSL-specific note: cron often doesn't run; see **WSL/02** for `[boot] command=`) |
| Shell history analysis (Linux commands inside distro) | [**Linux → 04 - Shells and Command History**](<../Linux/04 - Shells and Command History.md>) — bash/zsh history format, history evasion, anti-forensics |
| Evidence collection workflow (vhdx as evidence container) | [**Linux → 12 - Evidence Collection and Triage**](<../Linux/12 - Evidence Collection and Triage.md>) — imaging the ext4.vhdx, hash/chain of custody, media handling |
| WSL-specific registry configuration deep-dive | [**WSL → 03 - WSL Registry & Configuration Deep-Dive**](<03 - WSL Registry & Configuration Deep-Dive.md>) — registry key-by-key reference, Flags bits, detection of unauthorized distro installation |
| Cross-OS hunting: tracking WSL→Windows interop | [**WSL → 04 - WSL-Specific Hunting & Detection**](<04 - WSL-Specific Hunting & Detection.md>) — VHD access patterns, wsl.exe process ancestry, hunting queries |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Distro with `DefaultUid = 0` (root by default) | Everything runs as root |
| Imported distro (`BasePath` in an odd/temp/Downloads path) | Side-loaded, arbitrary rootfs |
| Custom `kernel=` in `.wslconfig` | Attacker-supplied WSL2 kernel |
| `[boot] command=` in a distro's `/etc/wsl.conf` | Root persistence on distro start |
| Scheduled Task / Run key launching `wsl.exe -e` | Windows-side auto-start of a Linux payload |
| WSL process spawning `powershell.exe`/`cmd.exe` (or vice-versa) | Cross-OS pivot / EDR evasion |
| WSL used at all on a host where it isn't expected | Shadow Linux environment |

## Resources

- Microsoft WSL docs — https://learn.microsoft.com/windows/wsl/
- `.wslconfig` / `wsl.conf` reference — https://learn.microsoft.com/windows/wsl/wsl-config
- Forensicating WSL (Lxss keys, ext4.vhdx) — SANS / community WSL DFIR research
