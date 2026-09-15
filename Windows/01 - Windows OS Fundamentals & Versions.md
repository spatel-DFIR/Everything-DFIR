# Windows OS Fundamentals & Versions

Every later note in this module assumes you can look at a process list, a registry hive, or a build number and immediately say "that's normal" or "that's not." This note is that baseline: the session model that separates system processes from user processes, the small set of legitimate processes every Windows host runs before a single user logs on, and the version landscape (XP through 11, plus Server) that changes where artifacts live and what they look like. Nothing here is an "artifact" in the evidentiary sense — it's the map you need before the artifact notes make sense.

> 🔴 **The core skill this note teaches: know normal well enough that abnormal jumps out.** Malware rarely invents a new process name — it reuses one of the dozen names below (`svchost.exe`, `lsass.exe`, `explorer.exe`...) because analysts pattern-match on names, not on paths and parents. Every table below is built to defeat that shortcut.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why It Matters to IR](#why-it-matters-to-ir)
- [The Windows Session Model](#the-windows-session-model)
- [Know Normal: The Core Process Tree](#know-normal-the-core-process-tree)
  - [Legitimate Process Tree Diagram](#legitimate-process-tree-diagram)
  - [Per-Process Reference Table](#per-process-reference-table)
  - [Impersonation Tells](#impersonation-tells)
- [Fingerprinting the OS Version On Disk](#fingerprinting-the-os-version-on-disk)
- [Version Landscape: WinXP to Win11](#version-landscape-winxp-to-win11)
- [Windows Server Parity](#windows-server-parity)
- [Feature-Update Forensic Residue](#feature-update-forensic-residue)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for "is this normal" — no third-party tools, safe to paste into a live session before you trust a single process name or version string:

```powershell
# Exact build/UBR/edition/install-type in one shot - the fast path to fingerprinting the OS
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName,CurrentBuild,UBR,DisplayVersion,InstallationType

# Full live process tree with path, parent PID, and session - the single view the whole note is built around
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,SessionId | Sort-Object SessionId

# Architecturally-singular processes with more than one instance - smss.exe/services.exe/lsass.exe/wininit.exe duplicates are impersonation
Get-CimInstance Win32_Process | Group-Object Name | Where-Object {$_.Count -gt 1 -and $_.Name -in 'smss.exe','services.exe','lsass.exe','wininit.exe'}

# Any child process of lsass.exe - lsass.exe should almost never spawn anything
Get-CimInstance Win32_Process | Where-Object {(Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name -eq 'lsass.exe'}

# svchost.exe outside System32 or missing its -k service-group argument - the most common process-masquerade target
Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" | Where-Object {$_.ExecutablePath -notlike 'C:\Windows\System32\*' -or $_.CommandLine -notmatch '-k '}

# System-side processes (lsass/services/wininit) outside Session 0, or user-shell processes (winlogon/explorer) inside Session 0 - a name-independent tell
Get-Process | Select-Object ProcessName,Id,SessionId | Where-Object {(($_.ProcessName -in 'lsass','services','wininit') -and $_.SessionId -ne 0) -or (($_.ProcessName -in 'winlogon','explorer') -and $_.SessionId -eq 0)}

# explorer.exe running from anywhere other than %SystemRoot% - classic hide-in-plain-sight shell-name reuse
Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | Where-Object {$_.ExecutablePath -ne "$env:SystemRoot\explorer.exe"}
```

## Why It Matters to IR

Two questions recur in almost every Windows case: **"is this process legitimate?"** and **"what version/build was this host running when X happened?"** Both questions are answered by facts, not intuition — an exact expected path, an exact expected parent, an exact expected session, and an exact registry value for build/OS. Get this note wrong and every later hunt (persistence, lateral movement, process injection) inherits the error.

## The Windows Session Model

Windows partitions everything that runs into numbered **sessions**. This is the single most important piece of context missing from a bare process list.

| Session | What it is | What runs there |
|---|---|---|
| **Session 0** | Non-interactive, no logged-on user, no desktop the user can see | Services (`services.exe` and everything it starts), drivers, `lsass.exe`, `wininit.exe`'s children — the entire "system" side of the machine |
| **Session 1+** | Interactive, one per logged-on console/RDP/fast-user-switching user | `winlogon.exe`, `explorer.exe`, the user's shell and applications |

- **Session 0 isolation** (introduced Vista, universal since) was a security change: prior to Vista, services and the first interactive user shared Session 0, which let a compromised service interact with the visible desktop ("shatter attacks"). Since Vista, services are permanently walled off in Session 0 with no desktop a user can see.
- Every new interactive logon — console, RDP, or Fast User Switching — gets its **own new session number** (2, 3, 4...), each with its own `csrss.exe` and `winlogon.exe` instance.
- **Session number is a triage field, not a footnote.** `lsass.exe`, `services.exe`, and `wininit.exe` living outside Session 0, or `winlogon.exe`/`explorer.exe` living inside it, is itself an anomaly worth chasing before you even look at paths or hashes.
- Get the session number for any PID: `Get-Process -Id <pid> | Select SessionId` (PowerShell) or the `Session` column in Task Manager/Process Explorer/System Informer.

### PowerShell

To list every process with its session number, sorted so Session 0 and each interactive session group together:

```powershell
Get-Process | Select-Object ProcessName,Id,SessionId | Sort-Object SessionId
```

To roll processes up by session so a Session 0 that includes a user-shell process (or a Session 1+ that includes a system process) jumps out immediately:

```powershell
Get-Process | Group-Object SessionId | Select-Object Name, Count, @{n='Processes';e={($_.Group.ProcessName | Sort-Object -Unique) -join ', '}}
```

To pull the session table from every host in scope at once, for a fleet-wide "does Session 0 look normal everywhere" sweep:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-Process | Select-Object ProcessName,Id,SessionId
} | Export-Csv .\session_audit.csv -NoTypeInformation
```

## Know Normal: The Core Process Tree

The dozen processes below exist on every Windows host, in the same shape, before any user-installed software runs. This baseline comes from the SANS FOR508 "Hunt Evil" poster's "Find Evil – Know Normal" panel — rewritten here in table form so it's fast to scan mid-incident, and to underline the four facts that actually matter for each process: **path, parent, instance count, and session.**

### Legitimate Process Tree Diagram

```
System Idle Process (PID 0)
└── System (PID 4)                                          [Session 0]
    └── smss.exe (master instance)                          [Session 0]
        │     spawns one child smss.exe per new session, then that child exits —
        │     so every smss.exe you see running is technically "orphaned" by design
        │
        ├── csrss.exe (Session 0)                            [Session 0]
        ├── wininit.exe                                       [Session 0]
        │   └── services.exe                                  [Session 0]
        │       ├── svchost.exe (many — often 10 to 50+)       [Session 0]
        │       │   ├── RuntimeBroker.exe
        │       │   ├── taskhostw.exe
        │       │   ├── WmiPrvSE.exe
        │       │   ├── dllhost.exe
        │       │   └── ...(one per -k service group / -s service)
        │       ├── lsass.exe                                  [Session 0]
        │       └── lsaiso.exe (only if VBS/Credential Guard)  [Session 0]
        │
        ├── csrss.exe (Session 1)                             [Session 1]
        └── winlogon.exe (Session 1, one per interactive user) [Session 1+]
            ├── fontdrvhost.exe
            ├── dwm.exe
            └── explorer.exe (via userinit.exe, which exits)   [Session 1+]
                ├── RuntimeBroker.exe (one per running UWP app)
                ├── OneDrive.exe / Teams.exe / <user apps>
                └── powershell.exe / cmd.exe → conhost.exe
```

### Per-Process Reference Table

| Process | Legitimate image path | Legitimate parent | Expected instances | Account context | Typical start time |
|---|---|---|---|---|---|
| `System` | None — PID 4 is not backed by an executable on disk | None (root of the tree) | Exactly **one** | Local System | At boot |
| `smss.exe` | `%SystemRoot%\System32\smss.exe` | `System` | One master + one short-lived child per new session | Local System | Master: seconds after boot. Child: at each new session's creation |
| `csrss.exe` | `%SystemRoot%\System32\csrss.exe` | An `smss.exe` instance that has already exited (parent shows as gone) | Two or more — one per session (Session 0 and Session 1 at minimum) | Local System | Within seconds of boot for the first two; new instances as new sessions are created (RDP, fast user switching) |
| `wininit.exe` | `%SystemRoot%\System32\wininit.exe` | An `smss.exe` instance that has already exited | Exactly **one**, lives in Session 0 | Local System | Within seconds of boot |
| `services.exe` | `%SystemRoot%\System32\services.exe` | `wininit.exe` | Exactly **one** | Local System | Within seconds of boot |
| `svchost.exe` | `%SystemRoot%\system32\svchost.exe` (lowercase `system32` in the poster's own capture) | `services.exe` (almost always) | Many — commonly 10+, frequently 50+ on Windows 10 1703 and later (per-service-group split raised the count on systems with >3.5 GB RAM) | Varies: Local System / Network Service / Local Service, plus Windows 10+ per-user service accounts running at Medium integrity | Mostly at/near boot, but new instances appear any time a service starts, including well after logon |
| `lsaiso.exe` | `%SystemRoot%\System32\lsaiso.exe` | `wininit.exe` | **Zero** on hosts without Virtualization-Based Security / Credential Guard; **one** when it's enabled | Local System | Within seconds of boot, only if VBS/Credential Guard is on |
| `lsass.exe` | `%SystemRoot%\System32\lsass.exe` | `wininit.exe` | Exactly **one** | Local System | Within seconds of boot |
| `winlogon.exe` | `%SystemRoot%\System32\winlogon.exe` | An `smss.exe` instance that has already exited | One per interactive session (Session 1, plus one more per RDP/fast-user-switching session) | Local System | First instance within seconds of boot; later instances at each new interactive logon |
| `explorer.exe` | `%SystemRoot%\explorer.exe` (note: **root of `%SystemRoot%`, not `System32`**) | An instance of `userinit.exe` that has already exited | One or more per interactively logged-on user (more than one if "launch folder windows in a separate process" is enabled) | The logged-on user | At that user's first interactive logon |
| `RuntimeBroker.exe` | `%SystemRoot%\System32\RuntimeBroker.exe` | `svchost.exe` | One or more — one per running UWP/Store (sandboxed) app | Typically the logged-on user | Varies widely, on demand as UWP apps launch |
| `taskhostw.exe` | `%SystemRoot%\System32\taskhostw.exe` | `svchost.exe` | One or more | Logged-on user and/or local service accounts | Varies widely — fires on Task Scheduler triggers (logon, idle, time, event); a default Windows 11 install pre-configures 200+ scheduled tasks |

### Impersonation Tells

The same names, worn wrong. Every row below is a real technique seen in the wild:

| Process | Common masquerade | 🔴 The tell |
|---|---|---|
| `System` | An attacker binary literally named `System` or `svchost.exe` planted next to it | `System` (PID 4) has **no image path at all** — any process claiming that name with a real EXE on disk is fake |
| `smss.exe` / `services.exe` / `lsass.exe` / `wininit.exe` | A second copy running to blend into a busy process list | **Any of these with more than one instance** (outside the documented smss.exe master+child pattern) is anomalous — these are architecturally singular |
| `csrss.exe` / `winlogon.exe` | Malware spawned as a "child" of a still-running process to fake the orphan pattern, or launched from a non-System32 path | Legitimate `csrss.exe`/`winlogon.exe` parents (`smss.exe`) are **already exited** by the time you look — a *live, visible* parent for either is wrong. Also check the path is exactly `System32`, not `system32 ` with a trailing space or a similar Unicode homoglyph |
| `svchost.exe` | Malware run as `svchost.exe -k netsvcs` from `C:\Users\...\AppData` or `C:\ProgramData`, or launched with **no `-k` parameter at all** | Any `svchost.exe` outside `%SystemRoot%\System32`, or one with no `-k` group / no matching real service, or parented by anything other than `services.exe` |
| `lsass.exe` | Credential-dumping tools inject into it or spawn from it (Mimikatz, comsvcs.dll `MiniDump` technique) | **`lsass.exe` should almost never have a child process.** Any child of `lsass.exe` is a strong indicator of credential access |
| `lsaiso.exe` | Rarely spoofed directly, but its *absence or presence* is itself diagnostic | `lsaiso.exe` running on a host whose policy says VBS/Credential Guard is **disabled** — or missing on a host that should have it enforced — both merit a config check |
| `explorer.exe` | A payload named `explorer.exe` run from `%TEMP%`/`%APPDATA%`, or a real `explorer.exe` with a parent other than `userinit.exe` | Path outside `%SystemRoot%`, or a parent that isn't an already-exited `userinit.exe` (e.g. spawned directly by another user process) |
| `RuntimeBroker.exe` / `taskhostw.exe` | Payload dropped under a trusted-sounding name, parented directly under `explorer.exe` or a user shell instead of `svchost.exe` | Wrong parent (should be `svchost.exe`, not `explorer.exe` or a browser), or wrong path (should be exactly `System32`) |
| Any process | Session mismatch | A "system" process (`lsass.exe`, `services.exe`, `wininit.exe`) found outside **Session 0**, or a "user" process (`winlogon.exe`, `explorer.exe`) found **inside Session 0** |

### PowerShell

To dump the live process tree with image path and parent PID for every process on the box:

```powershell
Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine
```

To resolve each process's parent by *name*, not just PID, so you can eyeball parent/child pairs directly against the Per-Process Reference Table above:

```powershell
$procs = Get-CimInstance Win32_Process
$procs | Select-Object ProcessId, Name, ExecutablePath, @{n='ParentName';e={($procs | Where-Object ProcessId -eq $_.ParentProcessId).Name}}
```

To count instances of the architecturally-singular processes across every host in scope in one CSV, so the one host with a duplicate stands out instead of requiring a host-by-host check:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-CimInstance Win32_Process -Filter "Name='smss.exe' or Name='services.exe' or Name='lsass.exe' or Name='wininit.exe'" |
    Group-Object Name | Select-Object Name, Count
} | Export-Csv .\singular_process_audit.csv -NoTypeInformation
```

## Fingerprinting the OS Version On Disk

Before you can apply any of the version-specific deltas below to a case, confirm exactly what the host was running. These registry values (all under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, readable live or from an offline `SOFTWARE` hive) are the fast path:

| Value | Tells you | Notes |
|---|---|---|
| `ProductName` | Marketing name (e.g. "Windows 10 Pro", "Windows Server 2019 Standard") | Doesn't distinguish feature-update level on its own |
| `CurrentBuild` / `CurrentBuildNumber` | The build number (e.g. `19045`, `22631`, `26100`) | The most reliable single field for pinning exact OS generation |
| `UBR` (UpdateBuildRevision) | The cumulative-update revision on top of the build | `CurrentBuild.UBR` together = the exact patch level at time of image |
| `DisplayVersion` (Win10 2004+/Win11) or `ReleaseId` (older Win10) | The feature-update label (e.g. `22H2`) | `ReleaseId` is frozen at whatever it was when `DisplayVersion` was introduced — trust `CurrentBuild`/`UBR` over either if they disagree |
| `InstallDate` | Unix epoch of original OS install | Doesn't move on feature updates — good provenance for "how old is this box," bad for "when was it last updated" |
| `InstallationType` | `Client` / `Server` / `Server Core` | Server Core hosts run **no `explorer.exe`** — the interactive-shell branch of the process tree above simply doesn't exist |
| `CurrentMajorVersionNumber` / `CurrentMinorVersionNumber` | Coarse OS generation (10 vs 6.x-era) | Legacy field, still present |

### PowerShell

To read every version-fingerprint value from the `CurrentVersion` key in one call:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object ProductName,CurrentBuild,CurrentBuildNumber,UBR,DisplayVersion,ReleaseId,InstallationType,InstallDate
```

To assemble the exact patch level as one string and convert `InstallDate` from Unix epoch to a readable date, so the raw registry dump becomes a one-line answer to "what was this host running":

```powershell
$v = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
[PSCustomObject]@{
    Build       = "$($v.CurrentBuild).$($v.UBR)"
    Edition     = $v.ProductName
    FeatureRel  = if ($v.DisplayVersion) { $v.DisplayVersion } else { $v.ReleaseId }
    InstallType = $v.InstallationType
    InstallDate = [DateTimeOffset]::FromUnixTimeSeconds($v.InstallDate).LocalDateTime
}
```

To build a build/UBR inventory across every host in scope in one CSV, to spot the outlier before chasing it host by host:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | Select-Object PSComputerName,ProductName,CurrentBuild,UBR,DisplayVersion,InstallationType
} | Export-Csv .\version_inventory.csv -NoTypeInformation
```

## Version Landscape: WinXP to Win11

Every note after this one calls out version deltas per artifact — this table is the index of *which* versions matter and *why*, so those callouts make sense in context.

| OS | Released | DFIR-relevant changes introduced | Forensic artifacts introduced/changed |
|---|---|---|---|
| **Windows XP** | 2001 (SP3: 2008) | FAT32 still common alongside NTFS 3.1; no Volume Shadow Copy for user data; no BitLocker | Prefetch introduced (capped at 128 entries); binary `.evt` event logs |
| **Windows Vista** | 2007 | UAC introduced; Session 0 isolation begins here; Volume Shadow Copy Service used broadly (System Restore); BitLocker introduced; Windows Search indexing begins | `.evtx` (XML-based) event logs replace `.evt`; `Windows.edb` search index; SuperFetch |
| **Windows 7** | 2009 | Refines Vista's model; still enterprise-standard until 2020 EOL | Jump Lists introduced (AutomaticDestinations/CustomDestinations); Libraries; BitLocker To Go |
| **Windows 8 / 8.1** | 2012 / 2013 | Modern/UWP apps + AppContainer sandboxing — **`RuntimeBroker.exe` first appears here**; Storage Spaces; fast/hybrid boot changes `hiberfil.sys` behavior | ReFS introduced (limited adoption); Start-screen-driven shell changes some User Activity artifacts |
| **Windows 10 (1507–1607)** | 2015–2016 | "Windows as a Service" begins — twice-yearly feature updates identified by `YYMM`; Windows Hello; WSL1 introduced (1607) | Feature-update cadence itself becomes a forensic timeline anchor (`Windows.old`, Panther logs — see below) |
| **Windows 10 1703 ("Creators Update")** | 2017 | 🔴 `svchost.exe` service-grouping changed — systems with **>3.5 GB RAM** now run many more `svchost.exe` instances (each service commonly gets its own host) by default | Directly changes the "expected instance count" baseline in the process tree above |
| **Windows 10 1803** | 2018 | Timeline feature introduced | `ActivitiesCache.db` — cross-device user-activity history, a major new artifact for "what did the user do" |
| **Windows 10 1809** | 2018 | Clipboard history, dark File Explorer theme | Notable inflection point the FOR500 exam index calls out for OS-version/Windows Update registry-timestamp questions |
| **Windows 10 1903/1909** | 2019 | Windows Sandbox, Reserved Storage, light theme default | — |
| **Windows 10 2004+** | 2020+ | WSL2; `DisplayVersion` registry value replaces reliance on `ReleaseId` | — |
| **Windows 10 20H2–22H2** | 2020–2022 | Enablement-package servicing model — a feature update can now be a small "flip a switch" patch rather than a full OS swap | Shrinks the on-disk footprint/timeline signature of a "feature update" vs. earlier Win10 releases |
| **Windows 11 (21H2–23H2)** | 2021–2023 | TPM 2.0 + Secure Boot are hard requirements — raises real-world adoption of VBS/Credential Guard, so **`lsaiso.exe` being present is normal far more often** than on Win10 fleets; redesigned Start menu/taskbar; Android subsystem (WSA) adds attack surface (23H2) | Fluent-redesigned File Explorer changes some thumbnail/Jump List rendering paths in later builds |
| **Windows 11 24H2** | 2024 | Major update: redesigned File Explorer, native `sudo` command, Windows Recall (Copilot+ hardware); "Moment" update cadence introduces smaller incremental updates between annual releases | 🔴 Windows Recall's continuous screenshot/context database is a first-class new forensic (and privacy/legal) artifact — treat any host with Recall enabled as having a rolling visual activity log |

## Windows Server Parity

Server releases track a client-OS "base" but diverge in ways that matter for the process tree and artifact availability:

| Server release | Client-OS base | Key deltas from client Windows |
|---|---|---|
| Server 2003 | XP-era | Same limitations as XP (no VSC for user files, `.evt` logs) |
| Server 2008 / 2008 R2 | Vista/7-era | Session 0 isolation, `.evtx`, VSC all apply |
| Server 2012 / 2012 R2 | Win8/8.1-era | ReFS more commonly deployed for data volumes than on client |
| Server 2016 / 2019 | Win10 1607-era / Win10 1809-era | — |
| Server 2022 | Win10 21H2 / early Win11-era | — |
| Server 2025 | Win11 24H2-era | — |

Deltas that matter regardless of exact version pairing:

- 🔴 **Multiple concurrent RDP sessions are the norm on Server**, not the exception — several simultaneous `csrss.exe`/`winlogon.exe`/`explorer.exe` instances are *expected*, unlike on a client workstation where more than one interactive session is comparatively unusual and worth a second look.
- **Server Core has no shell** — no `explorer.exe` branch of the process tree exists at all; everything is managed via PowerShell/`sconfig`/remote tools. Don't flag the absence of `explorer.exe` as suspicious on a Core install.
- **Domain Controllers add their own process/artifact set** (`lsass.exe` additionally hosts AD DS, `ntdsutil`, NTDS.dit, SYSVOL replication) — deferred in full to Active Directory & Domain Forensic Artifacts (05b) rather than covered here.
- Consumer-facing features (Timeline, Recall, consumer telemetry tiers) generally do not ship on Server SKUs — don't expect those artifacts there.

## Feature-Update Forensic Residue

A Windows 10/11 feature update (not just a monthly cumulative patch) leaves disk evidence of the prior OS state and the exact upgrade time — useful for "was this host patched before or after the intrusion":

| Artifact | What it tells you |
|---|---|
| `C:\Windows.old\` | The entire prior OS install, preserved for ~10 days by default — a snapshot of pre-upgrade state (old hives, old logs, old user data) if it hasn't been purged |
| `$WINDOWS.~BT` / `$WINDOWS.~WS` | Staging folders used during the upgrade itself; presence/timestamps bound the upgrade window |
| `C:\Windows\Panther\setupact.log` / `setuperr.log` | Detailed upgrade log — exact timestamps, source and target build numbers |
| `DeviceMigration` registry subkey (under `HKLM\SYSTEM`) | Carries forward removable/PnP device history (VID/PID/serial/DiskID/last-seen date) across a feature update so it isn't lost when device keys are recreated — relevant when USB history has to survive an OS upgrade (deep dive: Removable Device (USB) Forensics, note 09) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `System` (PID 4) backed by a real file on disk | `System` has no image path by design — any EXE claiming to be it is fake |
| A second instance of `smss.exe` (beyond documented master+child), `services.exe`, `lsass.exe`, or `wininit.exe` | These are architecturally singular; duplicates are impersonation |
| `csrss.exe` or `winlogon.exe` with a live, visible parent | Both should show an **already-exited** `smss.exe` as parent — a running parent breaks the expected orphan pattern |
| `svchost.exe` outside `%SystemRoot%\System32`, with no `-k` group, or parented by anything but `services.exe` | The single most common process-masquerade target |
| Any child process of `lsass.exe` | `lsass.exe` should almost never spawn children — strong credential-access indicator |
| `explorer.exe` running from outside `%SystemRoot%`, or parented by anything other than an exited `userinit.exe` | Classic "hide in plain sight" shell-name reuse |
| A "system" process (`lsass.exe`/`services.exe`/`wininit.exe`) outside Session 0, or a "user" process (`winlogon.exe`/`explorer.exe`) inside Session 0 | Session mismatch is a fast, name-independent tell |
| `lsaiso.exe` present when VBS/Credential Guard policy says disabled (or absent when policy says enforced) | Config drift or an attempt to disable Credential Guard protections |
| Registry `CurrentBuild`/`UBR` inconsistent with `Windows.old`/Panther log timestamps | Possible tampering with the host's apparent patch level |
| Explorer-shell artifacts expected on a Server Core box that has no shell at all | Analyst assumption error, not attacker activity — but worth catching before you chase a ghost |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The registry hive mechanics behind the version-fingerprint values above | **Registry Forensics Fundamentals** (04) |
| Whether a suspicious process actually executed, and when | **Evidence of Program Execution** (Prefetch / ShimCache / Amcache / BAM-DAM) |
| How malware gets itself launched as one of these legitimate-looking parents | **Persistence Mechanisms** (Autostart keys, Services, Scheduled Tasks, WMI Event Consumers) |
| Process hollowing / DLL injection into these exact processes | **Memory Forensics** (Processes, Injection, Rootkits) |
| The authoritative timestamped record of process creation, parent PID, and session | **Event Log Analysis** (Security 4688 and related) |
| Placing a rogue process's start time against OS/update history | **Timeline Analysis** |
| MACE/MACB timestamp rules applied to the feature-update residue above | **NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes** |
| Session 0 vs Session 1+ as it relates to logon types | **Users, Groups & Authentication** |
| Capturing this exact process tree live, before it changes | **Live Response and Volatile Data** |

## Resources

- SANS FOR508 "Hunt Evil" poster, "Find Evil – Know Normal" panel — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Microsoft Learn — Session 0 Isolation: https://learn.microsoft.com/windows/win32/services/interactive-services
- Microsoft Learn — Virtualization-based Security and Credential Guard: https://learn.microsoft.com/windows/security/identity-protection/credential-guard/
- Microsoft Learn — Windows 10/11 release information (build numbers by feature update): https://learn.microsoft.com/windows/release-health/
- Sysinternals / System Informer (process-tree inspection tooling referenced throughout this note): https://learn.microsoft.com/sysinternals/ and https://systeminformer.sourceforge.io/
