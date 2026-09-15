# Autostart (Run/RunOnce) Keys

Every persistence mechanism answers the same question for an attacker: *how do I survive a reboot or a killed process without having to break in again?* The Run/RunOnce registry key family is the oldest, crudest, and still most common answer on Windows — a handful of registry values that Windows itself reads at boot or logon and unconditionally executes. No exploit needed, no scheduling engine, no service to install — just a string value pointing at a command line. That simplicity is exactly why it remains a first-choice mechanism for everything from adware to ransomware loaders to nation-state implants: it is trivial to plant, requires only a registry write, and — unless an analyst specifically knows to look — blends into a key that also holds Adobe's updater, OneDrive, and a dozen other legitimate entries.

This is the first note in the Persistence Mechanisms family. It opens with a family-wide orientation table, then goes deep on the Run/RunOnce keys specifically — Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking each get their own note.

> 🔴 **A Run/RunOnce entry is only as suspicious as its target.** The keys themselves are 100% legitimate Windows functionality used by nearly every installed application — Dropbox, Steam, printer utilities, antivirus. The finding is never "a Run key exists," it's "this specific value points somewhere it shouldn't."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Persistence Mechanisms at a Glance](#persistence-mechanisms-at-a-glance)
- [What Autostart/Run Keys Are](#what-autostartrun-keys-are)
- [The Core Key Family](#the-core-key-family)
- [Not an Exhaustive List — Where Autoruns Comes In](#not-an-exhaustive-list--where-autoruns-comes-in)
- [Forensic Value: Baseline Auditing](#forensic-value-baseline-auditing)
- [Red Flags Specific to Run/RunOnce](#red-flags-specific-to-runrunonce)
- [Timestamp Value](#timestamp-value)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across every documented key in the core family before reaching for Autoruns — this is one of the few persistence mechanisms where the whole registry-side sweep is doable with `Get-ItemProperty`/`Get-Item`, no external parser required.

```powershell
# All Run/RunOnce values across HKLM/HKCU and the WOW6432Node 32-bit view - the full core-family sweep in one pass
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$runKeys | ForEach-Object {
    $k = $_
    Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object { [PSCustomObject]@{ Key = $k; Name = $_; Value = (Get-ItemProperty -Path $k).$_ } }
    }
}

# Flag values whose command line points into Temp/AppData/Downloads - the classic drop-and-persist path
$runKeys | ForEach-Object {
    $k = $_
    Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object {
            $v = (Get-ItemProperty -Path $k).$_
            if ($v -match 'Temp\\|AppData\\|Downloads\\') { [PSCustomObject]@{ Key = $k; Name = $_; Value = $v } }
        }
    }
}

# Flag obfuscated/encoded command lines - -EncodedCommand plus a long base64-looking blob
$runKeys | ForEach-Object {
    $k = $_
    Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object {
            $v = (Get-ItemProperty -Path $k).$_
            if ($v -match '-[Ee]nc(odedCommand)?\s|[A-Za-z0-9+/]{60,}={0,2}') { [PSCustomObject]@{ Key = $k; Name = $_; Value = $v } }
        }
    }
}

# Flag entries whose target file no longer exists on disk - the executable was deleted after the value was planted
$runKeys | ForEach-Object {
    $k = $_
    Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object {
            $v = (Get-ItemProperty -Path $k).$_
            $path = ($v -replace '^"([^"]+)".*$', '$1') -replace "^'([^']+)'.*$", '$1'
            if ($path -and -not (Test-Path $path -ErrorAction SilentlyContinue)) { [PSCustomObject]@{ Key = $k; Name = $_; Value = $v } }
        }
    }
}

# Cross-host sweep for one specific suspicious value name across an estate
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdateChecker' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, UpdateChecker
}
```

## Persistence Mechanisms at a Glance

A quick orientation across the five mechanisms in this folder before going deep on any one of them. "Stealth" here means how easily the mechanism blends with legitimate system activity; "detection difficulty" means how much specialized tooling/knowledge an analyst needs to reliably surface it.

| Mechanism | Where It Lives | Stealth Level | Typical Detection Difficulty | Covered In |
|---|---|---|---|---|
| Autostart (Run/RunOnce) keys | A handful of well-known `SOFTWARE`/`NTUSER.DAT` registry values | Low-moderate — a fixed, well-known set of keys any analyst can check by hand | Low — small, enumerable key set; the hard part is judgment (legitimate vs not), not discovery | **This note** |
| Services | `SYSTEM\CurrentControlSet\Services`, runs as SYSTEM/LocalService by default | Moderate — hundreds of legitimate services provide effective camouflage | Moderate — requires diffing against a known-good service baseline or event-log correlation (7045/4697) | Services |
| Scheduled Tasks | Task Scheduler XML under `C:\Windows\System32\Tasks\` + `Schedule\TaskCache` registry | Moderate-high — huge legitimate task volume, flexible triggers (logon, idle, time, event) add cover | Moderate-high — must separate genuinely unusual triggers/actions from the large legitimate baseline | Scheduled Tasks |
| WMI event consumers | WMI repository (`OBJECTS.DATA`), not the filesystem or a simple registry value | High — fileless, no scheduled-task or service entry, invisible to casual inspection | High — requires WMI-repository-specific parsing tools; most first responders don't know to look here at all | WMI Event Consumers |
| DLL hijacking / search-order abuse | A planted DLL in a directory the OS's DLL search order checks before the legitimate one | High — the malicious file often *is* a plausible-looking DLL name, and the triggering process is legitimate | High — requires knowing the expected DLL set/load order for the specific legitimate binary being abused | DLL Hijacking |

Autostart/Run keys sit at the "easiest to find, hardest to definitively judge" end of the spectrum — the opposite problem from WMI consumers or DLL hijacking, which are hard to find but usually unambiguous once found.

## What Autostart/Run Keys Are

Windows reads a small, fixed set of registry values at boot (machine-wide) and at logon (per-user), and launches whatever command line each value contains — no user interaction, no confirmation, no sandboxing. This was designed for legitimate software (an antivirus tray icon, a cloud-sync client, a printer monitor) to reliably relaunch itself every time the machine starts, and it has been abused for exactly as long as it has existed, because it does precisely what an attacker wants: guaranteed re-execution with zero ongoing effort.

## The Core Key Family

| Key | Scope | Trigger | Self-deletes? | Notes |
|---|---|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | All users on the machine | Every boot | No | The most common legitimate *and* malicious location — machine-wide persistence, survives any user's logoff/logon cycle |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | All users on the machine | Once, at next boot | **Yes** — Windows deletes the value after successfully launching it | Meant for installers that need "run once more after reboot to finish setup" — see Red Flags below for what it means when a RunOnce value *doesn't* self-delete |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Current user only | Every logon by that user | No | Lives in `NTUSER.DAT` — ties the entry to a specific user profile, useful for scoping which account an attacker compromised or was operating as |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` | Current user only | Once, at next logon | **Yes** | Per-user version of the same "finish setup" mechanism |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | All users, GPO-pushed | Every logon | No | Populated by Group Policy rather than an installer — a value appearing here that the organization doesn't recognize is a strong indicator of a compromised or maliciously-authored GPO, not a compromised endpoint; see Active Directory & Domain Forensic Artifacts (note 05b), GPO Forensics section, before assuming this is host-local |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | All users, 32-bit apps on a 64-bit OS | Every boot | No | The WOW6432Node mirror of the first row — exists only on 64-bit Windows, holds Run entries for 32-bit executables, and is the location analysts most commonly forget to check because it isn't the "obvious" path |

All of these live in the `SOFTWARE` and `NTUSER.DAT` hives — see Registry Forensics Fundamentals (note 04) for hive locations, live-vs-offline access, and `CurrentControlSet`/transaction-log mechanics that apply the same way here.

🔴 **If a Run-key entry was pushed via GPO** (the `Policies\Explorer\Run` row above), the compromise you're chasing may not be on the endpoint at all — it may be the domain controller or the GPO object itself. Pull that thread into Active Directory & Domain Forensic Artifacts (note 05b) rather than continuing to treat it as a single-host finding.

### PowerShell

Enumerate all six documented Run/RunOnce locations natively using `Get-Item`/`GetValueNames()` to read value names and data with no third-party module required:

```powershell
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($key in $runKeys) {
    Get-Item -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object {
            [PSCustomObject]@{ Key = $key; Name = $_; Value = (Get-ItemProperty -Path $key).$_ }
        }
    }
}
```

## Not an Exhaustive List — Where Autoruns Comes In

The five keys above are the classic, most-searched-for Run/RunOnce family — they are **not** a complete inventory of every place Windows will autostart a program. Dozens of other legitimate autostart locations exist and are routinely abused, among them:

- The **Startup folder** — shortcuts in `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (per-user) or its all-users equivalent, no registry involved at all.
- **Winlogon** `Shell` and `Userinit` values (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`) — these define what actually runs as the user's shell and pre-shell initialization; tampering here can replace or chain onto `explorer.exe` itself.
- **AppInit_DLLs** and similar DLL-injection-via-registry mechanisms that force a DLL to load into every process using User32.dll.
- Browser Helper Objects, Office add-ins, `Image File Execution Options` debugger hijacks, and a long tail of other locations covered by neither this note nor any single reference table.

No manually-maintained list of registry keys — including this one — can ever be complete; new autostart locations get discovered continually, and comprehensively enumerating all of them by hand every time is not a realistic workflow. This is precisely the problem **Autoruns (Sysinternals)** was built to solve: it ships with a maintained, continually-updated catalog of every known Windows autostart location — Run/RunOnce, Startup folder, Winlogon, services, scheduled tasks, drivers, browser extensions, and dozens more — and surfaces all of them in one pass, cross-referenced against code-signing status and (optionally) VirusTotal. For any investigation asking "what's set to autostart on this box," Autoruns is the tool of first resort; this note's key family is what you check by hand when you already have a specific hive in front of you and want to go straight to the highest-yield locations.

## Forensic Value: Baseline Auditing

The practical workflow for Run/RunOnce keys is comparative, not just observational:

- **Baseline comparison** — diff a live or acquired system's Run/RunOnce contents against a known-good baseline of the same build/image (see Enterprise Management and Baseline, note 22, for building and maintaining that baseline). Anything present on the suspect host and absent from the baseline is your candidate list.
- **Eyeball triage when no baseline exists** — absent a formal baseline, scan the small set of values for anything unfamiliar, misspelled (`scvhost.exe` instead of `svchost.exe`), or oddly pathed (see Red Flags below). Because these keys hold a small, bounded number of entries on most hosts, this is one of the few persistence mechanisms where a manual read-through is genuinely tractable in minutes.

## Red Flags Specific to Run/RunOnce

- **Path outside `Program Files`/`Windows`.** A legitimate autostart entry almost always points into `C:\Program Files\`, `C:\Program Files (x86)\`, or `C:\Windows\`. An entry pointing into `%APPDATA%`, `%TEMP%`, `%LOCALAPPDATA%\Temp`, or a user's Downloads folder is the classic drop-and-persist pattern — malware writes itself to a user-writable location, then adds a Run entry to relaunch it.
- **Obfuscated or encoded command lines.** A value invoking `powershell.exe -enc <base64>`, `-WindowStyle Hidden`, `-NoProfile` paired with a long encoded blob, or a heavily escaped/quoted command string is far more consistent with a dropped payload than a normal installer's launch line.
- **Masquerading — legitimate-sounding name, wrong path.** A value named `OneDrive` or `WindowsUpdate` that points somewhere other than the real product's install directory (or lacks that product's expected code signature) is a strong signal — check the path and, where possible, the target file's signing certificate, not just the value name.
- **A RunOnce value that's still there.** RunOnce is *designed* to self-delete immediately after Windows successfully launches the target. A RunOnce entry that persists well past the boot/logon it should have fired on means one of two things: the launched program never signaled successful completion back to Windows (a crash, a hang, or a program that was never designed to be RunOnce-compatible), or someone is deliberately abusing the RunOnce mechanism in a way that defeats its self-cleanup — either way, it's worth chasing down.

### PowerShell

Validate each value's target path and existence, flag suspicious Temp/AppData/Downloads locations, and decode any embedded `-EncodedCommand` base64 blob:

```powershell
$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
$runKeys | ForEach-Object {
    $k = $_
    Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
        $_.GetValueNames() | ForEach-Object {
            $v = (Get-ItemProperty -Path $k).$_
            $path = ($v -replace '^"([^"]+)".*$', '$1') -replace "^'([^']+)'.*$", '$1'
            $decoded = $null
            if ($v -match '-[Ee]nc(odedCommand)?\s+([A-Za-z0-9+/=]+)') {
                $decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[2]))
            }
            [PSCustomObject]@{
                Key            = $k
                Name           = $_
                Value          = $v
                TargetExists   = if ($path) { Test-Path $path -ErrorAction SilentlyContinue } else { $null }
                SuspiciousPath = $v -match 'Temp\\|AppData\\|Downloads\\'
                DecodedCommand = $decoded
            }
        }
    }
}
```

Sweep an estate with `Invoke-Command`, export to CSV, and flag outliers — value names present on only a minority of hosts — as a lightweight baseline diff:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
$sweep = Invoke-Command -ComputerName $computers -ScriptBlock {
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    $runKeys | ForEach-Object {
        $k = $_
        Get-Item -Path $k -ErrorAction SilentlyContinue | ForEach-Object {
            $_.GetValueNames() | ForEach-Object {
                [PSCustomObject]@{ ComputerName = $env:COMPUTERNAME; Key = $k; Name = $_; Value = (Get-ItemProperty -Path $k).$_ }
            }
        }
    }
}
$sweep | Export-Csv C:\hunt\run_key_sweep.csv -NoTypeInformation

# Outliers: value names present on fewer than half the swept hosts - candidates for a non-standard/malicious entry
$sweep | Group-Object Name | Where-Object { $_.Count -lt ($computers.Count / 2) } | Select-Object Name, Count
```

Export the value for the case file before removing it; deletion is not reversible from the registry alone, so treat this as a last step after evidence is preserved:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdateChecker' |
    Select-Object PSPath, UpdateChecker |
    Export-Clixml C:\hunt\evidence\UpdateChecker_RunValue.xml

Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name 'UpdateChecker' -WhatIf
```

## Timestamp Value

The registry key's own last-write time is a reasonable proxy for "when was this persistence entry created or last modified" — the same mechanic covered in Registry Forensics Fundamentals (note 04): every key carries a single last-write timestamp for the whole key, not per-value, so if the Run key holds several entries and only one was added by an attacker, the key's last-write time still reflects that most recent change across all of them.

🔴 On a **live-acquired** system, a very recent Run-key write may exist only in the `SOFTWARE`/`NTUSER.DAT` transaction log (`.LOG1`/`.LOG2`) and not yet be checkpointed into the primary hive file — see note 04's Registry Transaction Logs section. If you pull only the primary hive and skip its accompanying logs, the most recently planted persistence entry can be invisible to your parser even though it is actively running on the host.

## Tooling

| Tool | Use |
|---|---|
| **Autoruns** (Sysinternals) | Primary, comprehensive autostart-location tool — surfaces Run/RunOnce alongside every other known autostart mechanism in one pass, with code-signing and VirusTotal cross-reference; the go-to for "what's set to run on this box" rather than checking keys one at a time |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Direct hive inspection when you already know which hive/key you want — view the key's last-write time, values, and (with logs supplied) replay unflushed transaction-log writes automatically |
| **KAPE** (Kroll Artifact Parser and Extractor) | Triage collection of `SOFTWARE`, `NTUSER.DAT`, and their transaction logs at scale across many endpoints — see Evidence Acquisition & Imaging (note 02) for the targets/modules model; pair collected hives with RECmd or Autoruns' offline-analysis mode for batch review |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Run/RunOnce entry pointing into `%TEMP%`, `%APPDATA%`, or a Downloads folder | Classic drop-and-persist — legitimate autostart entries almost never live in user-writable temp locations |
| Base64/encoded PowerShell or heavily obfuscated command line in a value | Consistent with a delivered payload, not a normal installer launch string |
| Value name matches a trusted product but path/signature doesn't | Masquerading — verify the target file's actual location and code signature, not just the value's name |
| RunOnce entry still present well after the boot/logon that should have consumed it | RunOnce is supposed to self-delete on success — persistence here means the launched program failed to signal completion, or the mechanism is being deliberately abused |
| Unexpected value under `Policies\Explorer\Run` | GPO-pushed autostart — pivot to Active Directory & Domain Forensic Artifacts (05b) rather than treating this as host-local |
| Analyst checked only `HKLM\...\Run` and skipped `WOW6432Node`, `HKCU`, and `RunOnce` variants | Incomplete sweep — all five (six, counting WOW6432Node) locations in the core family should be checked, and Autoruns should be run for anything beyond them |
| Hive collected without its `.LOG1`/`.LOG2` companions on a live-response triage | A very recent Run-key write may exist only in the unflushed transaction log — see note 04 |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Hive locations, live-vs-offline access, transaction-log replay mechanics used to read these keys correctly | Registry Forensics Fundamentals (note 04) |
| GPO-pushed autostart entries, malicious GPO changes, SYSVOL/AD-object evidence | Active Directory & Domain Forensic Artifacts (note 05b) |
| Service-based persistence (SYSTEM-level, `SYSTEM\CurrentControlSet\Services`) | Services |
| Scheduled-task persistence (Task Scheduler XML, flexible triggers) | Scheduled Tasks |
| Fileless, event-triggered persistence in the WMI repository | WMI Event Consumers |
| Search-order/DLL side-loading persistence with no registry footprint | DLL Hijacking |
| Building and maintaining a known-good baseline to diff Run/RunOnce contents against | Enterprise Management and Baseline (note 22) |
| Triage collection of these keys at scale across many endpoints | Evidence Acquisition & Imaging (note 02) |

## Resources

- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- KAPE (Kroll Artifact Parser and Extractor) — https://www.kroll.com/kape
- SANS FOR500 poster, "System Boot & Autostart Programs" panel — coverage checklist for the core key paths, rewritten in this note's own words
- SANS FOR508 poster — Malware Persistence coverage checklist
- MITRE ATT&CK T1547.001 (Registry Run Keys / Startup Folder) — https://attack.mitre.org/techniques/T1547/001/
