# COM Hijacking

The Component Object Model is one of the oldest and most deeply embedded pieces of Windows plumbing — an enormous share of built-in Windows components, shell operations, MMC snap-ins, scheduled tasks with COM-handler actions, and third-party applications create objects by calling `CoCreateInstance` against a CLSID (a GUID identifying a specific COM class) rather than launching an executable directly. COM hijacking replaces the DLL that a chosen CLSID resolves to, so that the next time anything on the host instantiates that class — through completely normal, unmodified application behavior — Windows loads the attacker's DLL instead of the legitimate one.

What makes this persistence mechanism unusually effective is precedence, not obscurity: `HKEY_CLASSES_ROOT`, the merged view every COM lookup actually resolves through, combines `HKLM\SOFTWARE\Classes` (machine-wide, admin-writable) with `HKCU\Software\Classes` (per-user, writable by any standard account) — and HKCU wins whenever both define the same CLSID. A huge number of CLSIDs are defined only in HKLM and have no HKCU counterpart at all, which means a completely unprivileged user can create a brand-new `HKCU\Software\Classes\CLSID\<CLSID>\InprocServer32` entry for one of these, and it will take effect immediately, with no admin rights, no service restart, and no elevation prompt of any kind.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A COM hijack is only as suspicious as the DLL it points to and how the CLSID is normally used.** The `CLSID` hive contains many thousands of entries on any given Windows install — the vast majority entirely legitimate, many with no `InprocServer32` at all (out-of-process or well-known system CLSIDs). The finding is never "a CLSID has an `InprocServer32` value," it's an `InprocServer32` in `HKCU` for a CLSID that's normally only defined in `HKLM`, pointing at an unsigned DLL in a user-writable location, especially for a CLSID that's known to be instantiated by a frequently-running or high-privilege process.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Where the Hijack Lives](#where-the-hijack-lives)
- [Why COM Hijacking Is So Effective](#why-com-hijacking-is-so-effective)
- [Watchlist vs. Full Sweep](#watchlist-vs-full-sweep)
- [Known-Abused CLSIDs](#known-abused-clsids)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to COM Hijacking](#red-flags-specific-to-com-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

```powershell
# Fast watchlist pass - a small set of historically-abused CLSIDs, checked in HKCU first since HKCU-only registration is the classic tell
$watchlist = @(
    'A6BA00FE-40E8-477C-B713-C64A14F18ADB'   # Task Scheduler "Automatic App Update" custom handler
    '42AEDC87-2188-41FD-B9A3-0C966FEABEC1'   # MruPidlList
    'F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1'   # Microsoft WBEM New Event Subsystem
    '3543619C-D563-43F7-95EA-4DA7E1CC396A'   # Shell Icon Overlay handler
)
$watchlist | ForEach-Object {
    $hkcu = Get-ItemProperty "HKCU:\Software\Classes\CLSID\{$_}\InprocServer32" -ErrorAction SilentlyContinue
    if ($hkcu) { [PSCustomObject]@{ CLSID = $_; Location = 'HKCU'; DllPath = $hkcu.'(default)' } }
}

# Every CLSID with an InprocServer32 defined in HKCU - the location that never requires admin rights to write
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc) { [PSCustomObject]@{ CLSID = $_.PSChildName; DllPath = $inproc.'(default)' } }
}

# HKCU CLSID entries that ALSO have a legitimate HKLM-only definition - the direct precedence-override signature
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $clsid = $_.PSChildName
    $hkcuInproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    $hklmExists = Test-Path "HKLM:\SOFTWARE\Classes\CLSID\$clsid"
    if ($hkcuInproc -and $hklmExists) {
        [PSCustomObject]@{ CLSID = $clsid; HKCU_Dll = $hkcuInproc.'(default)'; HasHKLMEquivalent = $true }
    }
}

# HKCU InprocServer32 values pointing outside expected binary locations - the drop-and-persist pattern applied to COM
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc.'(default)' -match '\\(Temp|AppData|Users)\\' -and $inproc.'(default)' -notmatch '\\Windows\\') {
        [PSCustomObject]@{ CLSID = $_.PSChildName; DllPath = $inproc.'(default)' }
    }
}

# Full sweep (slow, noisy) - every InprocServer32 in HKLM whose target DLL doesn't exist on disk, or isn't Authenticode-signed
Get-ChildItem 'HKLM:\SOFTWARE\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    $dll = $inproc.'(default)' -replace '"',''
    if ($dll -and -not (Test-Path $dll -ErrorAction SilentlyContinue)) {
        [PSCustomObject]@{ CLSID = $_.PSChildName; DllPath = $dll; Issue = 'Target does not exist' }
    }
}
```

## Where the Hijack Lives

Every registered COM class has a subkey under `CLSID`, and the `InprocServer32` value beneath it names the DLL loaded into the calling process's address space when that CLSID is instantiated in-process (the common case; out-of-process COM servers use a different, less commonly hijacked mechanism):

```
HKEY_CURRENT_USER\Software\Classes\CLSID\<CLSID>\InprocServer32     (Default) = <path to DLL>
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32    (Default) = <path to DLL>
HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\<CLSID>\InprocServer32   (32-bit view on a 64-bit OS)
```

`HKEY_CLASSES_ROOT` is the merged, read-through view every COM lookup actually queries — built from `HKLM\SOFTWARE\Classes` layered under `HKCU\Software\Classes`, with **HKCU always taking precedence** when both define the same CLSID. That precedence rule, combined with the fact that a huge number of legitimate CLSIDs are defined only in HKLM (system components, Microsoft applications, third-party software installed for all users) with no corresponding HKCU entry at all, is the entire mechanism: writing a new `HKCU\Software\Classes\CLSID\<CLSID>\InprocServer32` value for a CLSID that has no pre-existing HKCU definition requires nothing more than standard user write access, and it silently wins every subsequent lookup for that CLSID on that account.

`InprocServer32` also carries a `ThreadingModel` value (`Apartment`, `Free`, `Both`, `Neutral`) that a legitimate replacement DLL needs to match or closely approximate to avoid crashing the calling application — worth checking as a secondary signal when a hijacked entry's `ThreadingModel` doesn't match what the original, legitimate registration (if recoverable from a clean baseline or another host) specified.

### PowerShell

Pull every CLSID with an `InprocServer32` defined in `HKCU` — this is the location worth checking first on every engagement, since it never requires admin rights and is where an unprivileged-account compromise would land:

```powershell
Get-ChildItem 'HKCU:\Software\Classes\CLSID' -ErrorAction SilentlyContinue | ForEach-Object {
    $inproc = Get-ItemProperty "$($_.PSPath)\InprocServer32" -ErrorAction SilentlyContinue
    if ($inproc) { [PSCustomObject]@{ CLSID = $_.PSChildName; DllPath = $inproc.'(default)'; ThreadingModel = $inproc.ThreadingModel } }
}
```

For a specific CLSID of interest, compare the HKCU and HKLM definitions side by side to see exactly what's being overridden and by what:

```powershell
$clsid = '<CLSID-without-braces>'
[PSCustomObject]@{
    HKCU_Dll = (Get-ItemProperty "HKCU:\Software\Classes\CLSID\{$clsid}\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    HKLM_Dll = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\{$clsid}\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
}
```

Check the Authenticode signature and file existence for any suspicious `InprocServer32` target once identified:

```powershell
$dll = (Get-ItemProperty "HKCU:\Software\Classes\CLSID\{$clsid}\InprocServer32").'(default)' -replace '"',''
if (Test-Path $dll) { Get-AuthenticodeSignature $dll | Select-Object Path, Status, SignerCertificate } else { "Target does not exist: $dll" }
```

## Why COM Hijacking Is So Effective

The strength of this technique isn't stealth in the sense of hiding a file or a process — it's riding a trigger the attacker doesn't have to build or maintain. An enormous number of built-in Windows components, MMC snap-ins, Explorer shell operations, scheduled tasks configured with a COM-handler action, and ordinary third-party applications instantiate well-known CLSIDs as a completely routine part of their normal operation, none of it attacker-influenced. Hijacking one of these means the payload fires whenever that everyday operation happens — a shell icon renders, a specific MMC console opens, a scheduled task with a COM-handler action runs on its normal trigger — rather than needing its own dedicated Run key, service, or scheduled task that has to be independently discovered and, from an attacker's perspective, independently defended against removal.

This is also why COM hijacking sits naturally alongside the other "hijack a routine, already-normal Windows trigger" techniques in this family, particularly File Association & Screensaver Hijacking — the underlying logic is the same (replace what a legitimate, frequent action resolves to, rather than adding a brand-new autostart entry of your own), just applied to a different resolution mechanism.

## Watchlist vs. Full Sweep

Hunting COM hijacking splits into two genuinely different tiers of effort, and knowing which one a given investigation calls for matters:

A **watchlist pass** checks a small, curated set of CLSIDs already known to be both frequently instantiated and previously abused in the wild — the kind of list in the Hunt Evil block above. This is fast, produces almost no false positives, and is the right first move on every engagement, but it only catches hijacks of CLSIDs someone has already documented; a novel CLSID choice by a sufficiently deliberate attacker will not appear.

A **full sweep** walks every `InprocServer32` value under the entire `CLSID` hive — thousands of entries on a typical Windows install, the overwhelming majority completely legitimate. This is comprehensive but slow, and requires a real baseline (a known-clean host of the same build, or a documented "normal" DLL-path list) to separate signal from noise; without one, an analyst is left eyeballing thousands of paths looking for the handful that don't belong.

This two-tier framing matches how this repo's own persistence-hunting tooling treats the technique — a fast `ComWatchlist` module for the known-abused subset, and a slower `ComFull` module for the exhaustive sweep — precisely because the tradeoff between speed/precision and completeness/noise is real and worth making explicit rather than defaulting to only one approach.

## Known-Abused CLSIDs

A handful of CLSIDs recur across public COM-hijacking research because they're both easy to reach (instantiated by something that runs routinely or at logon) and well-documented enough that public tooling exists to abuse them. These are useful watchlist seeds, not an exhaustive or permanent list — treat any specific CLSID as a starting point to verify against current research rather than a fixed catalog:

| CLSID | Associated with | Source |
|---|---|---|
| `{A6BA00FE-40E8-477C-B713-C64A14F18ADB}` | The COM handler invoked by the built-in "Automatic App Update" scheduled task at user logon — demonstrated by enigma0x3 as a way to combine scheduled-task COM-handler hijacking with logon-triggered persistence | enigma0x3, "Userland Persistence with Scheduled Tasks and COM Handler Hijacking" |
| `{42AEDC87-2188-41FD-B9A3-0C966FEABEC1}` | MruPidlList — a commonly-cited example CLSID in COM-hijacking writeups | Public COM-hijacking research (Penetration Testing Lab, HackTricks) |
| `{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}` | Microsoft WBEM New Event Subsystem | Public COM-hijacking research |
| `{3543619C-D563-43F7-95EA-4DA7E1CC396A}` | Shell Icon Overlay handler — instantiated by Explorer as part of ordinary shell icon rendering, making it attractive for its near-continuous trigger frequency | Public COM-hijacking research |

Enigma0x3's `Get-ScheduledTaskComHandler.ps1` is specifically worth knowing about as a detection-relevant tool here: it enumerates scheduled tasks configured with a `<ComHandler>` action and cross-references each referenced CLSID against the current HKCU/HKLM registration, surfacing exactly the class of task-plus-CLSID combination that made the `{A6BA00FE-...}` example above practical in the first place.

## Event Log Evidence

Like the other registry-write-based, per-user mechanisms in this family, COM hijacking has no dedicated Windows Event Log source of its own.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **"Audit Registry" (Object Access)** enabled *and* a SACL configured on the specific `CLSID` key — neither is default |
| Filesystem MACB on the `InprocServer32` target DLL | n/a | Creation/modification timestamps | See NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes |
| Prefetch / ShimCache / Amcache | n/a | Confirms the hijacked DLL actually loaded into the calling process, and first/last-seen timing | See note 06 — a hijacked `InprocServer32` DLL loaded into, say, `explorer.exe` or `svchost.exe` leaves the same module-load trail any DLL loaded into that process would; process-level EDR telemetry showing an unexpected module loaded into a well-known process is often the most direct corroborating evidence available |
| Sysmon Event ID 7 (Image Loaded) | n/a | Direct evidence of the hijacked DLL being loaded into a specific process, if Sysmon is deployed with DLL/image-load logging enabled | Not default-on Windows logging — requires Sysmon or equivalent EDR telemetry; where present, this is the single best confirmation that a suspicious `InprocServer32` registration actually fired |

🔴 **Registry auditing for `CLSID` keys is essentially never configured by default.** As with File Association/Screensaver hijacking and Office persistence, expect the registry value's own last-write time, the target DLL's filesystem timestamps, and process/module-load evidence to carry the investigation rather than a native Windows event trail.

## Red Flags Specific to COM Hijacking

- **`InprocServer32` defined in `HKCU` for a CLSID that has no corresponding `HKCU` definition normally, but does have a legitimate `HKLM` one.** This is the core precedence-override signature — the HKCU entry didn't need to exist at all for the CLSID to function normally, so its presence is itself the finding, independent of what it points to.
- **`InprocServer32` target DLL sitting in `%TEMP%`, `%AppData%`, or another user-writable location rather than `Program Files`/`Windows`/`System32`.** Same drop-and-persist logic applied throughout this family — legitimate COM servers essentially never live in user-writable paths.
- **The hijacked CLSID is one instantiated by a frequently-running or logon-triggered process.** A CLSID tied to Explorer's routine shell operations, a logon-triggered scheduled task's COM handler, or another high-frequency trigger is a materially more dangerous find than one tied to a rarely-used administrative tool — trigger frequency is the entire point of this technique.
- **Target DLL is unsigned, or signed by a certificate unrelated to the CLSID's documented legitimate owner.** A CLSID belonging to a well-known Microsoft or major third-party component, now resolving to a DLL signed by neither (or not signed at all), is a strong tell independent of the file path.
- **`InprocServer32` target path references a DLL that no longer exists on disk.** Worth checking both directions — a dangling reference can mean a hijack was partially cleaned up (registry entry survived, payload didn't), or, less commonly, a staged hijack waiting for the payload to be dropped separately.
- **A scheduled task configured with a `<ComHandler>` action whose referenced CLSID has an HKCU `InprocServer32` override.** This is the enigma0x3 pattern specifically — the task itself may look completely legitimate and untouched, with the actual hijack living entirely in the CLSID registration rather than the task definition.

## Tooling

| Tool | Use |
|---|---|
| **Direct registry query (`Get-ItemProperty`, Registry Editor)** | The primary tool for both the watchlist and full-sweep approaches — no specialized parser required, `CLSID\<CLSID>\InprocServer32` is a plain registry value |
| **`Get-ScheduledTaskComHandler.ps1`** (enigma0x3) | Enumerates scheduled tasks with `<ComHandler>` actions and cross-references their CLSIDs against current HKCU/HKLM registration — directly targets the scheduled-task-plus-COM-hijack combination |
| **Autoruns** (Sysinternals) | Includes COM hijacking coverage as part of its broader autostart sweep, cross-referencing signature status — a reasonable first pass, though its CLSID coverage should be treated as watchlist-tier rather than an exhaustive full sweep |
| **Sysmon (Event ID 7 — Image Loaded)** | If deployed, the most direct available evidence that a hijacked `InprocServer32` DLL actually loaded into a specific process — not default-on, requires prior deployment |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `Software\Classes\CLSID` from an acquired `NTUSER.DAT`/`SOFTWARE` hive rather than a live host — see Registry Forensics Fundamentals (note 04) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `InprocServer32` defined in HKCU for a CLSID with a legitimate HKLM-only definition and no normal HKCU counterpart | The core precedence-override signature — requires no admin rights and wins every subsequent lookup |
| `InprocServer32` target DLL in `%TEMP%`, `%AppData%`, or another user-writable path | Drop-and-persist for COM — legitimate COM servers essentially never live in user-writable locations |
| Hijacked CLSID tied to a frequently-running or logon-triggered process/component | Trigger frequency is the entire point of the technique — a rarely-instantiated CLSID is a far less dangerous find |
| Target DLL unsigned or signed by an unrelated certificate | Legitimate COM servers for well-known CLSIDs are normally signed by their documented owner |
| `InprocServer32` target path references a non-existent DLL | Partial cleanup, or a staged hijack awaiting a separately-dropped payload |
| Scheduled task `<ComHandler>` action referencing a CLSID with an HKCU override | The task definition itself can look completely untouched — the hijack lives entirely in the CLSID registration |
| No Security-log 4657 despite a suspicious `InprocServer32` value | Registry-object-access auditing is off by default for `CLSID` keys — rely on the value's own last-write time and module-load evidence (Prefetch/Sysmon/EDR) instead |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure, `NTUSER.DAT`/`SOFTWARE` offline access mechanics | Registry Forensics Fundamentals (note 04) |
| Scheduled-task COM-handler actions as the specific trigger enigma0x3's technique abuses | Scheduled Tasks (this family) |
| Another "hijack a routine Windows trigger" technique using the same HKCU-precedence logic | File Association & Screensaver Hijacking (this family) |
| Confirming actual load/execution of a hijacked `InprocServer32` DLL | ShimCache (AppCompatCache).md, Amcache.md, Prefetch.md (note 06) |
| Full registry-auditing/event-log and Sysmon image-load mechanics | Event Log Analysis (note 11) |

## Resources

- MITRE ATT&CK T1546.015 (Event Triggered Execution: Component Object Model Hijacking) — https://attack.mitre.org/techniques/T1546/015/
- enigma0x3, "Userland Persistence with Scheduled Tasks and COM Handler Hijacking" — https://enigma0x3.net/2016/05/25/userland-persistence-with-scheduled-tasks-and-com-handler-hijacking/
- bohops, "Abusing the COM Registry Structure (Part 2): Hijacking & Loading Techniques for Evasion and Persistence" — https://bohops.com/2018/08/18/abusing-the-com-registry-structure-part-2-loading-techniques-for-evasion-and-persistence/
- Penetration Testing Lab, "Persistence – COM Hijacking" — https://pentestlab.blog/2020/05/20/persistence-com-hijacking/
- HackTricks, COM Hijacking — https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/com-hijacking
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
