# Registry Forensics Fundamentals

The registry is Windows' hierarchical configuration database — and, almost by accident, one of the richest activity logs on the entire host. Every key carries its own last-write timestamp, and thousands of keys record what software is installed, what devices were attached, what a user typed, opened, or ran. Nothing in this note is itself an "artifact" in the evidentiary sense the way Prefetch or a Security event is — it's the mechanics every later registry-backed note (Evidence of Program Execution, Persistence Mechanisms, Users/Groups & Authentication, Removable Device (USB) Forensics, and others) assumes you already have: which hive holds what, how to reach it live or offline, and the two gotchas (`CurrentControlSet` resolution, unflushed transaction logs) that trip up anyone who skips straight to artifact-hunting.

> 🔴 **A registry key's last-write time is forensic gold, and it is a single timestamp for the entire key — not per-value.** If a key holds five values and an attacker modifies one of them, all five appear to have changed at the same instant. Know this before you over-interpret a key's timestamp as pinpointing one specific value's change.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why the Registry Matters to DFIR](#why-the-registry-matters-to-dfir)
- [The Hive Files](#the-hive-files)
- [Live vs Offline Hives](#live-vs-offline-hives)
- [CurrentControlSet Resolution](#currentcontrolset-resolution)
- [Registry Transaction Logs](#registry-transaction-logs)
- [RegBack](#regback)
- [Parsing Tools: Which One When](#parsing-tools-which-one-when)
- [Where Things Live: A Navigational Map](#where-things-live-a-navigational-map)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for orienting on a live registry before any parsing tool comes out — no third-party modules required:

```powershell
# Every registry root PowerShell currently exposes - confirms you're pointed at the hive you think you are
Get-PSDrive -PSProvider Registry

# Every loaded user hive on this box RIGHT NOW - profiles actually logged on, not just present on disk
Get-ChildItem Registry::HKEY_USERS | Select-Object Name

# CurrentControlSet resolution at a glance - flag if Failed is populated (prior failed boot)
Get-ItemProperty 'HKLM:\SYSTEM\Select'

# Transaction logs present alongside primary hives - their absence means an offline parse of the bare
# hive alone may be missing the most recent, unflushed registry writes
Get-ChildItem C:\Windows\System32\config -Filter *.LOG* | Select-Object Name,Length,LastWriteTime

# RegBack backup copies - 0 bytes is expected default behavior on Windows 10 1803+, not tampering
Get-ChildItem C:\Windows\System32\config\RegBack -ErrorAction SilentlyContinue | Select-Object Name,Length,LastWriteTime

# Quick recursive sweep of a hive subtree for a suspicious string in any value - generic triage net,
# not a substitute for the artifact-specific searches covered in later notes
Get-ChildItem -Path HKCU:\Software -Recurse -ErrorAction SilentlyContinue |
    Get-ItemProperty -ErrorAction SilentlyContinue |
    Where-Object { $_.PSObject.Properties.Value -match 'suspiciousPattern' }
```

## Why the Registry Matters to DFIR

Two facts make the registry disproportionately valuable in almost every Windows exam:

- **It's a hierarchical config database that doubles as a timeline.** Every key has a last-write time recorded by NTFS's underlying structures, exposed the same way a file's modified time is — except a registry key's last-write time is *always* current, there's no separate "created" vs "modified" distinction to reason about the way there is for files. A key that was last written at 03:14:07 UTC tells you something happened at that exact second, even if you don't yet know what.
- **It records things no other artifact does.** Installed software, attached USB devices, typed paths, opened files, run commands, network profiles joined, service and driver configuration, local accounts and their SIDs — much of this exists *only* in the registry, with no filesystem or event-log equivalent.

The rest of this note is the map that makes those two facts usable: which physical file holds which logical hive, how to get at that file whether the host is live or dead, and the two structural gotchas that catch analysts who go straight from "I found the key in a reference" to "I opened the hive and it wasn't there."

## The Hive Files

A **hive** is a self-contained tree of keys/values backed by one file on disk. Windows loads some hives at boot (machine-wide) and others per-user, at logon.

| Hive file | Disk path | Mounted registry root | What lives there | Typical size |
|---|---|---|---|---|
| `SYSTEM` | `C:\Windows\System32\config\SYSTEM` | `HKEY_LOCAL_MACHINE\SYSTEM` | Boot config, `CurrentControlSet`/`Select` (services, drivers, device enumeration), USB/PnP device history, computer name, network interfaces, time zone, shutdown info | Tens of MB |
| `SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | `HKEY_LOCAL_MACHINE\SOFTWARE` | Installed applications, OS version/build values, App Paths, Windows Update history, most machine-wide application configuration | Often the largest hive — can run 100+ MB |
| `SAM` | `C:\Windows\System32\config\SAM` | `HKEY_LOCAL_MACHINE\SAM` | Local user/group accounts, RIDs, password hashes (protected further by SYSKEY/boot key in `SYSTEM`), group memberships | Small — typically under 1 MB unless the local account count is unusually high |
| `SECURITY` | `C:\Windows\System32\config\SECURITY` | `HKEY_LOCAL_MACHINE\SECURITY` | Local security policy, cached domain credentials, LSA secrets | Small, under 1 MB typically |
| `DEFAULT` | `C:\Windows\System32\config\DEFAULT` | `HKEY_USERS\.DEFAULT` | Template profile used before any user logs on (welcome screen, default profile settings) | Small |
| `NTUSER.DAT` | `C:\Users\<user>\NTUSER.DAT` | `HKEY_USERS\<user SID>` (mounted as `HKEY_CURRENT_USER` for the logged-on user) | Per-user shell settings, RecentDocs, typed paths, UserAssist, RunMRU, Office MRU/trusted-document records, mapped drives | Varies widely with profile age — commonly tens of MB |
| `USRCLASS.DAT` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\USRCLASS.DAT` | `HKEY_USERS\<user SID>_Classes` | Per-user COM/shell extension registrations, **shellbags** (folder-view state), Store app data | Varies, often smaller than `NTUSER.DAT` |

```
HKEY_LOCAL_MACHINE (HKLM)
├── SYSTEM     ← SYSTEM hive file
├── SOFTWARE   ← SOFTWARE hive file
├── SAM        ← SAM hive file
└── SECURITY   ← SECURITY hive file

HKEY_USERS (HKU)
├── .DEFAULT           ← DEFAULT hive file
├── <user SID>         ← that user's NTUSER.DAT   (mounted as HKEY_CURRENT_USER while logged on)
└── <user SID>_Classes ← that user's USRCLASS.DAT

HKEY_CURRENT_CONFIG    ← a live-session view, not a separate hive file
HKEY_CLASSES_ROOT      ← a merged view of HKLM\SOFTWARE\Classes + the active user's classes, not a separate hive file
```

🔴 **`HKEY_CURRENT_USER` and `HKEY_CLASSES_ROOT` are not hive files** — they're views the running kernel constructs at logon (per-session merges/pointers). You will never find a hive file literally named `NTUSER.DAT` mounted at `HKEY_CURRENT_USER` on an offline system; you load the user's `NTUSER.DAT` file directly and reason about its contents as if it were `HKEY_CURRENT_USER` for that user.

### PowerShell

The registry provider lets you browse keys/values like a filesystem:

```powershell
Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion       # list child keys
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion    # read the values under a key
```

🔴 **Limitation:** neither `Get-Item` nor `Get-ItemProperty` exposes a key's last-write time — PowerShell's registry provider has no `LastWriteTime` property the way the filesystem provider does for files. Getting it natively requires a thin P/Invoke wrapper around `advapi32.dll`'s `RegQueryInfoKey`:

```powershell
Add-Type -Namespace Native -Name Advapi32 -MemberDefinition @'
[DllImport("advapi32.dll")]
public static extern int RegQueryInfoKey(
    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey, System.Text.StringBuilder lpClass, ref uint lpcchClass,
    IntPtr lpReserved, out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen,
    out uint lpcValues, out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen, out uint lpSecurityDescriptor,
    out long lpftLastWriteTime);
'@

function Get-KeyLastWriteTime {
    param([Microsoft.Win32.RegistryKey]$Key)
    $subKeys = $maxSubKeyLen = $maxClassLen = $values = $maxValueNameLen = $maxValueLen = $sd = [uint32]0
    $class = New-Object System.Text.StringBuilder 256
    $classLen = [uint32]256
    $lastWrite = [long]0
    [Native.Advapi32]::RegQueryInfoKey($Key.Handle, $class, [ref]$classLen, [IntPtr]::Zero, [ref]$subKeys,
        [ref]$maxSubKeyLen, [ref]$maxClassLen, [ref]$values, [ref]$maxValueNameLen, [ref]$maxValueLen,
        [ref]$sd, [ref]$lastWrite) | Out-Null
    [DateTime]::FromFileTime($lastWrite)
}

$key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion')
Get-KeyLastWriteTime -Key $key
```

## Live vs Offline Hives

The same logical data can be examined two structurally different ways, and which one you're doing changes what you can trust:

| | Live/mounted registry | Offline hive file |
|---|---|---|
| Access method | `reg.exe`, PowerShell (`Get-ItemProperty`, `Get-ChildItem HKLM:\...`), RegEdit, live-response scripts — all query the *running* registry through the OS's own APIs | A registry-parsing tool (Registry Explorer, RECmd, RegRipper) opens the raw hive file directly — pulled from a triage collection, a mounted image, or a dead disk |
| Why you'd use it | System is in scope and running, need current state, or need something only visible live (in-memory-only keys, currently-loaded `HKEY_CURRENT_USER` for a session) | System is off, disk-only evidence, hive file is locked by the OS on a live system (you cannot simply copy `C:\Windows\System32\config\SYSTEM` off a running Windows box with a normal file copy — it's held open), or you need a defensible point-in-time snapshot rather than "whatever the registry looks like right now" |
| What you're actually seeing | The current merged state, including anything still sitting unflushed in the transaction log (see below) — the OS applies pending log records transparently when it opens the hive | Exactly what's checkpointed into the hive file at the moment of acquisition — **if there's an unreplayed transaction log alongside the hive, the raw hive file alone is missing those writes** unless your tool also parses the log |
| `CurrentControlSet` | Resolves automatically and transparently — Windows itself does the pointer resolution, so it simply looks like a normal key | Does **not** exist as a literal key in the raw `SYSTEM` hive — see the next section |
| Forensic soundness | Lower — querying a live system can itself write to the registry (e.g., some queries touch MRU/last-accessed-style keys), and the state changes under you as the system keeps running | Higher — a copied/imaged hive file is a static, hashable, repeatable point-in-time artifact, the same soundness argument that favors dead-box disk imaging generally (see Evidence Acquisition & Imaging, note 02) |

Why offline parsing is the DFIR default rather than the exception: the primary hive files are held open exclusively by the OS while Windows is running, so a plain file copy fails (`Access is denied`) — acquisition tools instead use a volume-shadow-copy-based read, a raw disk read, or pull the hive from a KAPE/triage collection that already knows how to do this. Once acquired, that hive is analyzed offline, which is also what makes results deterministic and repeatable in the same way a disk image is preferable to poking a live system.

### PowerShell

For cross-host live registry hunting, you can query the same key across a fleet:

```powershell
# Query the same key across a fleet - live registry only, this is not offline hive parsing
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKLM:\SYSTEM\Select'
} | Select-Object PSComputerName,Current,Default,Failed
```

To load an *offline* hive file into a namespace PowerShell can browse, use the native (if clunky) reg.exe load workaround and then browse it with ordinary registry cmdlets. Keep in mind that PowerShell itself has no offline hive parser, and this does NOT replay unflushed .LOG1/.LOG2 transaction log records the way Registry Explorer/RECmd do — treat it as a quick-look convenience, not a substitute for proper offline parsing when transaction-log completeness matters:

```powershell
reg.exe load HKLM\OfflineSystem C:\triage\SYSTEM
Get-ChildItem HKLM:\OfflineSystem\ControlSet001\Services | Select-Object Name
reg.exe unload HKLM\OfflineSystem
```

For generic key/value removal mechanics, capture evidence (export, hash) *before* running either of these commands, and see the artifact-specific notes (Persistence Mechanisms, etc.) for which keys/values actually warrant removal:

```powershell
Remove-ItemProperty -Path HKCU:\Software\Example -Name 'MaliciousValue' -WhatIf
Remove-Item -Path HKLM:\SOFTWARE\Example\MaliciousKey -Recurse -WhatIf
```

## CurrentControlSet Resolution

`HKLM\SYSTEM` stores one or more **control sets** — numbered configurations (`ControlSet001`, `ControlSet002`, ...) — plus a `Select` key that says which one is active:

| `Select` value | Meaning |
|---|---|
| `Current` | Control set number Windows is running on right now |
| `Default` | Control set that will be used on the next normal boot |
| `LastKnownGood` | Control set saved as "known good" after a successful boot with a user logged on — historically the fallback for Last Known Good Configuration recovery |
| `Failed` | Control set that failed to boot last time, if any |

`CurrentControlSet` is not a real, on-disk key at all — it is a **symbolic pointer that the OS resolves at parse time** to whichever `ControlSetNNN` the `Select\Current` value names. This is a classic gotcha for anyone browsing an *offline* `SYSTEM` hive expecting to see a literal `CurrentControlSet` subkey the way it appears live:

- On a **live** system (or any tool that replicates the OS's own resolution logic), `CurrentControlSet` behaves normally — you can browse straight to `HKLM\SYSTEM\CurrentControlSet\Services\...` and it just works.
- On a **raw offline hive** opened naively, there is no `CurrentControlSet` key — only `ControlSet001`, `ControlSet002` (etc.) and `Select`. You must read `Select\Current`, then manually substitute — e.g. if `Current = 1`, every reference to `CurrentControlSet\Services\...` in a reference table actually means `ControlSet001\Services\...` in that hive.
- Registry-parsing tools built for DFIR (Registry Explorer, RegRipper) handle this resolution automatically when you load the `SYSTEM` hive, presenting a resolved `CurrentControlSet` view — but know the mechanic underneath, because a raw hex/text dump, a script you write yourself, or a tool that doesn't do this resolution will show you the literal `ControlSetNNN` structure instead, and multiple control sets existing side by side (e.g. after a failed boot) is itself sometimes forensically relevant.

### PowerShell

To resolve `CurrentControlSet` the same way Windows does and flag a prior failed boot:

```powershell
$sel = Get-ItemProperty 'HKLM:\SYSTEM\Select'
'ControlSet{0:D3}' -f $sel.Current                       # the control set actually active right now
if ($sel.Failed -ne 0) { 'Failed control set: ControlSet{0:D3}' -f $sel.Failed }
```

## Registry Transaction Logs

Each primary hive file is normally accompanied by one or more log files in the same directory, used for crash-consistency (write-ahead-log style) journaling:

| File pattern | Era | Purpose |
|---|---|---|
| `<HiveName>.LOG` | Older (pre-Vista style, single log) | Legacy single transaction log |
| `<HiveName>.LOG1` / `<HiveName>.LOG2` | Vista and later | Dual alternating transaction logs — Windows writes changes here first, then periodically checkpoints (flushes) them into the primary hive file |

🔴 **Data written to the log but not yet checkpointed into the primary hive file exists ONLY in the log — not in the hive.** Windows batches registry writes and flushes them to the primary hive file on its own schedule (at shutdown, or periodically), not instantly on every write. An analyst who acquires a hive file and its `.LOG1`/`.LOG2` companions but only parses the primary hive is silently missing the most recent registry activity on that system — potentially the exact writes closest to the incident.

Practical implications:

- Always collect the `.LOG1`/`.LOG2` (or `.LOG`) files **alongside** every primary hive you acquire — never grab the hive alone.
- **Registry Explorer / RECmd** (Eric Zimmerman suite) has built-in transaction-log-replay support: point it at the primary hive and its logs together, and it merges unflushed log records into the view before you analyze it — the FOR500 personal index calls this out explicitly ("registry in memory, not saved to original registry files yet... Registry Explorer, RECmd").
- If you only have the bare hive file with no accompanying logs (common in some older triage collections that didn't know to grab them), assume you may be looking at a slightly stale snapshot and say so in your findings.

## RegBack

`C:\Windows\System32\config\RegBack\` historically held periodic scheduled-task backup copies of the SYSTEM-critical hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, `DEFAULT`), useful for baseline/rollback comparison — diffing a current hive against its RegBack copy can surface exactly what changed between the backup and now.

🔴 Since **Windows 10 1803**, Microsoft disabled the automatic RegBack scheduled task by default to save disk space — the backup copies are typically **empty placeholder files (0 bytes)** on 1803+ systems unless an administrator explicitly re-enabled the task or a third-party backup solution populates the folder. Don't assume RegBack is useful without checking file size and the host's build number first; on older builds (or hosts where the task was manually restored) it remains a genuinely valuable point-in-time comparison baseline.

### PowerShell

To pair the RegBack listing from Hunt Evil above with the host's build number so a 0-byte result reads as "expected" rather than "suspicious":

```powershell
$build = (Get-CimInstance Win32_OperatingSystem).BuildNumber
Get-ChildItem C:\Windows\System32\config\RegBack -ErrorAction SilentlyContinue |
    Select-Object Name,Length,LastWriteTime,@{N='HostBuild';E={$build}}    # build 17134+ (1803+) explains 0-byte files
```

## Parsing Tools: Which One When

| Tool | Form | Best for |
|---|---|---|
| **Registry Explorer** (Eric Zimmerman) | GUI | Interactive, exploratory analysis of a single hive (or hive + logs) — browsing, bookmarking, resolving `CurrentControlSet` and transaction logs automatically, viewing deleted/unallocated registry cells |
| **RECmd** (Eric Zimmerman) | CLI | Scripted, repeatable, batch extraction across many hives/hosts — same engine as Registry Explorer, built for KAPE modules and automation pipelines |
| **RegRipper** | Plugin-based CLI/GUI | Fast, automated first-pass triage — a library of community plugins each targets one known artifact (UserAssist, RunMRU, USB history, etc.) and outputs a readable report; strong for "run everything and see what's interesting" rather than deep manual exploration |
| **TZWorks** utilities (e.g. `cafae.exe`) | CLI | Narrow, artifact-specific parsing (named per the FOR500 index alongside Registry Explorer/RECmd/RegRipper as an alternative toolset) — useful when you need a specific TZWorks parser's particular output format |

Rule of thumb: **RegRipper first for broad automated triage**, **Registry Explorer when you need to manually explore, verify, or dig into raw cell structure (including deleted values)**, **RECmd when the same extraction has to run at scale or fit into a KAPE/automation pipeline**.

## Where Things Live: A Navigational Map

This table is a pointer, not a lesson — each artifact family gets full field-level treatment in its own later note. Use this only to know which hive to reach for.

| Artifact category | Hive(s) | Covered in depth |
|---|---|---|
| Evidence of Program Execution (UserAssist, BAM/DAM, Task Bar Feature Usage) | `NTUSER.DAT` (UserAssist), `SYSTEM` (BAM/DAM, Feature Usage) | Evidence of Program Execution (note 06 series) |
| USB / removable device history | `SYSTEM` (USBSTOR, USB, SCSI, HID, MTP keys) | Removable Device (USB) Forensics (note 09) |
| Installed software | `SOFTWARE` (Uninstall keys, App Paths) | — (not yet written, see Persistence Mechanisms for autorun-relevant software entries) |
| Local accounts, groups, RIDs | `SAM`, `SECURITY` (policy/LSA secrets) | Users, Groups & Authentication (note 05) |
| OS version/build fingerprint | `SOFTWARE` (`CurrentVersion` subkey) | Windows OS Fundamentals & Versions (note 01) |
| Typed paths, RecentDocs, Office MRU/trust records, RunMRU | `NTUSER.DAT` | File and Folder Opening — User Activity (note 07) |
| Shellbags | `USRCLASS.DAT` (and `NTUSER.DAT` on older OS versions) | File and Folder Opening — User Activity (note 07) |
| Autostart/persistence (Run, RunOnce, Services) | `SOFTWARE`, `NTUSER.DAT` (Run/RunOnce), `SYSTEM` (Services) | Persistence Mechanisms (note 10 series) |
| SRUM registry keys | `SOFTWARE` | Evidence of Program Execution (SRUM, note 06 series) |
| Network profiles / MAC-based geolocation, computer name, time zone | `SYSTEM` | Event Log Analysis (note 11) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Hive acquired without its `.LOG1`/`.LOG2` companions | Recent, unflushed registry writes are invisible to you — you may be analyzing a stale snapshot without knowing it |
| Analyst manually browsing an offline `SYSTEM` hive and reporting `CurrentControlSet` doesn't exist | Expected — resolve via `Select\Current` → `ControlSetNNN`, or use a tool that resolves it automatically |
| Multiple `ControlSetNNN` keys present, `Select\Failed` populated | Indicates a prior failed boot — may be relevant to an incident timeline (e.g., a crash coinciding with malware activity) |
| RegBack hive files present but 0 bytes | Expected default behavior on Windows 10 1803+ — not evidence tampering, just the disabled backup task; confirm build number before drawing conclusions |
| A key's last-write time attributed to one specific value inside a multi-value key | Last-write time is per-*key*, not per-value — any value under that key could have caused it |
| Hive parsed live via `reg.exe`/RegEdit for a case requiring defensible point-in-time evidence | Live queries can themselves alter registry state and lack the reproducibility of a hashed offline hive copy |

## Correlate With

| To go deeper on… | Open |
|---|---|
| UserAssist, BAM/DAM, Task Bar Feature Usage, SRUM registry keys | **Evidence of Program Execution** |
| Run/RunOnce autostart keys, Services persistence | **Persistence Mechanisms** |
| SAM account structure, logon types, cached credentials | **Users, Groups & Authentication** |
| USBSTOR/USB/SCSI/HID/MTP device history | **Removable Device (USB) Forensics** |
| Shellbags, RecentDocs, typed paths, Office MRU | **File and Folder Opening (User Activity)** |
| OS build/version fingerprint fields | **Windows OS Fundamentals & Versions** |
| Acquiring locked hive files from a live or dead host in the first place | **Evidence Acquisition & Imaging** |

## Resources

- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- RegRipper — https://github.com/keydet89/RegRipper3.0
- Microsoft Learn — Windows registry information for advanced users: https://learn.microsoft.com/troubleshoot/windows-server/performance/windows-registry-advanced-users
- Microsoft Learn — Registry hives: https://learn.microsoft.com/windows/win32/sysinfo/registry-hives
- SANS FOR500 course syllabus (public) — registry hive types, transaction logs, CurrentControlSet coverage checklist
