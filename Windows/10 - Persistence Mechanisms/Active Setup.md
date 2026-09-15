# Active Setup

Active Setup is a Windows mechanism, dating back to Internet Explorer 4 and still functional today, whose entire purpose is to run a command once for every user account the first time that account logs onto the machine after a component's version changes. It exists so software installed machine-wide by an administrator (running once, with elevated rights, for the whole computer) can still perform a per-user setup step — registering a per-profile COM object, seeding per-user settings, repairing a user's copy of a shared component — the first time each individual user actually sits down at the keyboard. That's a legitimate and still-common pattern; Windows itself uses Active Setup for several built-in components.

It's also a durable, if narrow, persistence primitive. A component registered under `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>` with a `StubPath` value gets that command line executed automatically, with no user interaction beyond logging in, in the context and privilege level of *whichever user logs on*. Because the trigger is "first qualifying logon of this profile," it fires for every existing user the first time they next log on after the component is planted or its version is bumped — and, notably, it also fires automatically for any *newly created* user profile the first time that brand-new account logs on, since a fresh profile has no `HKCU` copy of the component at all. That makes Active Setup worth a specific look on any host with multiple local or domain-cached profiles, including hosts an attacker may be using as a stepping stone precisely because many different users touch it.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing Active Setup against Run keys, Services, Scheduled Tasks, and WMI Event Consumers.

> 🔴 **Active Setup is only as suspicious as its `StubPath` and its version history.** A handful of legitimate `Installed Components` entries exist on every Windows install — Windows Media Player, Internet Explorer/Edge components, occasionally an OEM utility. The finding is never "an Active Setup component exists," it's "this `StubPath` points somewhere it shouldn't, or this component's `Version` string was bumped in `HKLM` without a corresponding legitimate software change — which forces re-execution across every user profile on the box the next time each one logs on."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Where Active Setup Lives — Registry](#where-active-setup-lives--registry)
- [The Version-Comparison Mechanism](#the-version-comparison-mechanism)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Active Setup](#red-flags-specific-to-active-setup)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry-only triage — Active Setup has no dedicated PowerShell module or cmdlet, so every one of these reads `HKLM`/`HKCU` directly.

```powershell
# Every HKLM Installed Components entry with its StubPath, Version, and IsInstalled flag in one pass
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' | ForEach-Object {
    $c = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ GUID = $_.PSChildName; ComponentName = $c.'(default)'; StubPath = $c.StubPath; Version = $c.Version; IsInstalled = $c.IsInstalled }
}

# StubPath pointing outside Windows/System32/Program Files - the drop-and-persist pattern for this mechanism
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' | ForEach-Object {
    $c = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($c.StubPath -and $c.StubPath -notmatch '\\(Windows|Program Files)\\') {
        [PSCustomObject]@{ GUID = $_.PSChildName; StubPath = $c.StubPath }
    }
}

# StubPath referencing PowerShell, rundll32, mshta, or cmd - LOLBIN/obfuscation red flags in the launched command line
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' | ForEach-Object {
    $c = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($c.StubPath -match 'powershell|rundll32|mshta|cmd\.exe|-enc|-e ') {
        [PSCustomObject]@{ GUID = $_.PSChildName; StubPath = $c.StubPath }
    }
}

# Component GUIDs present under HKLM with no plausible legitimate name/vendor - unrecognized components worth a second look
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' |
    ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } |
    Select-Object PSChildName, @{N='ComponentName';E={$_.'(default)'}}, StubPath, Version

# HKLM components whose Version is NEWER than the current user's own HKCU copy - about to fire (or already forced) on next/this logon
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' | ForEach-Object {
    $hklm = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    $hkcuPath = "HKCU:\Software\Microsoft\Active Setup\Installed Components\$($_.PSChildName)"
    $hkcu = Get-ItemProperty $hkcuPath -ErrorAction SilentlyContinue
    if ($hklm.StubPath -and ($hklm.Version -ne $hkcu.Version)) {
        [PSCustomObject]@{ GUID = $_.PSChildName; StubPath = $hklm.StubPath; HKLMVersion = $hklm.Version; HKCUVersion = $hkcu.Version }
    }
}

# Every local user's HKCU copy compared against HKLM, walked via mounted NTUSER.DAT hives - catches profiles other than the one currently logged on
Get-ChildItem 'C:\Users' -Directory | ForEach-Object {
    $hive = Join-Path $_.FullName 'NTUSER.DAT'
    if (Test-Path $hive) { [PSCustomObject]@{ Profile = $_.Name; NTUSERPath = $hive } }
}
```

## Where Active Setup Lives — Registry

Active Setup's machine-wide definition and its per-user execution-tracking copy live in parallel key structures, one under `HKLM` and one under each user's `HKCU`:

| Key | Scope | Purpose |
|---|---|---|
| `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>` | Machine-wide, one subkey per component | The **authoritative definition** — this is what an attacker plants or modifies. On a 32-bit component running on a 64-bit OS, check `HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components` as well, mirroring the WOW6432Node gotcha covered for Run keys in Autostart (Run/RunOnce) Keys |
| `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components\<GUID>` | Per-user, one subkey per component, keyed by the **same GUID** as the `HKLM` entry | The **per-user execution record** — written the first time `StubPath` successfully runs for that user; its `Version` value is what gets compared against `HKLM`'s `Version` on every subsequent logon |

Values under the `HKLM` (definition) side of a component:

| Value | Meaning | Forensic relevance |
|---|---|---|
| `(Default)` | Human-readable component name | Legitimate components have plausible, vendor-consistent names — a blank or nonsensical default value is a mild signal |
| `StubPath` | The command line executed for a user the first time the component's version check indicates it should run | 🔴 The single most important value — apply the same red flags used for Run-key command lines in Autostart (Run/RunOnce) Keys: paths outside `Windows`/`Program Files`, LOLBIN launchers, encoded PowerShell |
| `Version` | A version string (commonly four dot-separated integers, e.g. `1,0,0,0` or `1,0,0,1`) | Compared against the same-named value in the user's `HKCU` copy — see the version-comparison mechanism below; this is the field an attacker manipulates to force re-execution |
| `IsInstalled` | `1` or `0` (DWORD) | Gates whether the component runs *at all*, independent of the version check — `IsInstalled = 0` (or the value's absence, on older components) disables the component; a component that was quietly flipped to `1` is worth checking against its own change history |
| `ComponentID` | Optional GUID/string identifying the component to its installer | Vendor bookkeeping; a mismatch between this and the subkey name itself is unusual |
| `Locale` | Optional, restricts execution to a specific system locale | Rarely present; legitimate for localization-specific setup steps only |

### PowerShell

Enumerate every `HKLM` component definition and pull the fields that matter for triage in one shot, including the WOW6432Node view for 32-bit-registered components on a 64-bit host:

```powershell
$paths = 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components'
$paths | Where-Object { Test-Path $_ } | ForEach-Object {
    Get-ChildItem $_ | ForEach-Object {
        Get-ItemProperty $_.PSPath | Select-Object PSChildName, @{N='Name';E={$_.'(default)'}}, StubPath, Version, IsInstalled
    }
}
```

Read a specific user's `HKCU` copy — useful when working from a mounted `NTUSER.DAT` hive during offline analysis rather than a live session:

```powershell
reg load HKU\TempHive "C:\Users\<user>\NTUSER.DAT"
Get-ChildItem 'HKU:\TempHive\Software\Microsoft\Active Setup\Installed Components' | ForEach-Object { Get-ItemProperty $_.PSPath }
reg unload HKU\TempHive
```

## The Version-Comparison Mechanism

This is the mechanic that makes Active Setup a distinct forensic story from a simple autostart key, and it's worth understanding precisely because it's also the mechanic an attacker abuses to force re-execution across every profile on the box.

On every qualifying user logon, Windows walks each `<GUID>` subkey under `HKLM\...\Installed Components` and compares its `Version` string against the `Version` string recorded under that same `<GUID>` in the *current user's* `HKCU\...\Installed Components` key. If the `HKCU` copy is missing entirely (a brand-new profile, or a component that has simply never run for this user), or if the `HKCU` `Version` is lower than — or simply different from — the `HKLM` `Version`, Windows executes `StubPath` for that user and then writes the `HKLM` `Version` value into the user's `HKCU` copy so the same component won't fire again for that user until `HKLM`'s version is bumped further. `IsInstalled` is checked separately from this version logic and gates the component regardless of version state.

🔴 **The abuse case follows directly from that logic.** An attacker who already has write access to `HKLM` (this requires administrative privilege — Active Setup's `HKLM` branch is not user-writable, which is a real barrier worth noting, but a barrier attackers with local admin or SYSTEM clear routinely) doesn't need to touch every user's `HKCU` at all. Planting a malicious `StubPath` under a *new* `<GUID>` guarantees it fires the next time any user — including a user who has never logged on before — logs on. Alternatively, an attacker who compromises an *existing*, legitimate component's `HKLM` entry can simply increment its `Version` string; on next logon, every user whose recorded `HKCU` version is now "stale" relative to the bumped `HKLM` value has the (now attacker-controlled) `StubPath` executed for them, even if that user had already run the legitimate original version months earlier. This is a cheap way to force re-execution across an entire multi-user host without writing to each profile individually — which is precisely why the version-delta hunt query above (comparing every `HKLM` `Version` against every enumerable `HKCU` copy) belongs ahead of a simple "does `StubPath` look weird" pass on a host with many profiles.

## Event Log Evidence

Active Setup has no dedicated event log or event ID of its own — evidence comes entirely from generic registry-auditing telemetry, and only if that auditing is explicitly configured.

| Source | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **non-default auditing** ("Audit Registry" under Object Access) plus a SACL configured specifically on the `Installed Components` key — this is not enabled out of the box on any standard Windows build; do not assume 4657 will be present |
| Sysmon (if deployed) | 12 | Registry object created/deleted | Fires for `Installed Components\<GUID>` key creation if Sysmon's config includes this registry path |
| Sysmon (if deployed) | 13 | Registry value set | Fires for `StubPath`/`Version`/`IsInstalled` value writes if Sysmon's config includes this registry path — this is the most practical *real-time* detection signal for this mechanism, but it depends entirely on Sysmon being installed and configured to watch `Active Setup`, which is not a default rule in most baseline Sysmon configs |
| Security log | 4624 (Logon Type 2 or 10) | User logon | Correlate against `StubPath` execution timing — a component's `StubPath` runs *during* the logon sequence, so its side effects (process creation, file writes) should cluster tightly around a 4624 event for that user |
| Security log | 4688 (if command-line auditing enabled) | Process creation | Shows the actual `StubPath` command line executing, if process-creation auditing with command-line logging is turned on — otherwise the process is visible by name only |

Because there is no dedicated "Active Setup fired" event, this note leans harder than most in this family on the registry state itself (the `HKLM`/`HKCU` version delta) and on general execution artifacts — Prefetch, ShimCache, Amcache — for the launched `StubPath` binary, rather than on any single authoritative log entry.

### PowerShell

Correlate a component's `StubPath` against Prefetch/execution evidence for the binary or interpreter it launches, once the command line has been parsed apart from its arguments:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components' | ForEach-Object {
    $c = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($c.StubPath -match '^"?([^"]+\.exe)"?') {
        [PSCustomObject]@{ GUID = $_.PSChildName; Executable = $Matches[1]; FullStubPath = $c.StubPath }
    }
}
```

## Red Flags Specific to Active Setup

- **`StubPath` pointing outside `Windows`/`Program Files`.** Same drop-and-persist logic as every other mechanism in this family — a legitimate Active Setup component almost never launches from `%APPDATA%`, `%TEMP%`, `%ProgramData%`, or a user profile directory, since it exists specifically to support machine-wide software.
- **A new, unrecognized `<GUID>` subkey appearing under `HKLM\...\Installed Components` with no corresponding software install event.** Active Setup components are typically registered by an MSI or installer at software-install time — a new component appearing with no install-log correlation is worth tracing.
- **An existing, previously-legitimate component's `Version` value incremented with no corresponding vendor update.** This is the version-bump abuse case described above — it forces re-execution of whatever `StubPath` currently points at, across every profile, without the attacker needing to touch each user's `HKCU` individually.
- **`StubPath` referencing a LOLBIN (`rundll32.exe`, `mshta.exe`, `regsvr32.exe`) or an interpreter with encoded/obfuscated arguments (`powershell.exe -enc`, `cmd.exe /c`).** Legitimate Active Setup stubs are usually straightforward calls to `regsvr32`, a vendor-signed installer helper, or a simple executable — heavy obfuscation in the command line itself is atypical.
- **`IsInstalled` flipped from `0` to `1` on a component with no corresponding legitimate change.** This re-enables a component that was previously disabled, without needing to touch `StubPath` or `Version` at all — a quieter re-activation path worth checking when comparing current state against a known-good baseline.
- **A `StubPath` that differs between the `HKLM` definition and what actually executed, per Prefetch/Amcache/process-creation evidence.** If the registry has since been modified or restored, the artifact trail for what actually ran during a suspicious logon window may no longer match the current `HKLM` state — corroborate with execution evidence rather than trusting the live registry value alone.

## Tooling

| Tool | Use |
|---|---|
| **Registry Editor / `reg query`** | Live enumeration of `HKLM`/`HKCU` `Installed Components` — Active Setup has no dedicated native CLI tool of its own beyond direct registry access |
| **Autoruns** (Sysinternals) | Already introduced in Autostart (Run/RunOnce) Keys — its Logon tab includes Active Setup entries alongside Run keys, with code-signing and VirusTotal cross-reference, so a suspicious `StubPath` surfaces in the same single pass as a suspicious Run key |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of both the `SOFTWARE` hive (`HKLM` component definitions) and each user's `NTUSER.DAT` (`HKCU` execution-tracking copies) — see Registry Forensics Fundamentals (note 04) for hive access mechanics; comparing many users' `NTUSER.DAT` copies against one `SOFTWARE` hive is exactly the version-delta hunt described above, done offline at scale |
| **KAPE** | Targets covering `SOFTWARE` and all `NTUSER.DAT` hives on the host in one collection pass — necessary here specifically because this mechanism's evidence is split across one machine hive and every user hive |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `StubPath` pointing into `%APPDATA%`, `%TEMP%`, `%ProgramData%`, or a user profile | Drop-and-persist — legitimate components launch from `Windows`/`Program Files` |
| New `<GUID>` subkey under `HKLM\...\Installed Components` with no corresponding software-install evidence | Component planted directly rather than registered by a legitimate installer |
| `Version` value incremented on an existing component with no vendor update | Forces `StubPath` re-execution across every user profile on next logon, without touching each `HKCU` individually |
| `StubPath` invoking a LOLBIN or an interpreter with encoded/obfuscated arguments | Obfuscation atypical of legitimate, usually-simple Active Setup stub commands |
| `IsInstalled` flipped to `1` on a component with no corresponding legitimate change | Quiet re-activation path that doesn't require touching `StubPath` or `Version` |
| `HKLM` `Version` newer than a given user's `HKCU` `Version` for a suspicious component | That component's `StubPath` is about to fire — or already has — for that user on next/this logon |
| No Security 4657 or Sysmon 12/13 coverage of the `Active Setup` registry path | Neither is enabled by default — absence of these events does not mean no registry change occurred; treat registry-state comparison as the primary evidence source |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure, `HKLM` vs. `HKCU`/`NTUSER.DAT` access mechanics, offline hive loading | Registry Forensics Fundamentals (note 04) |
| Run/RunOnce key command-line obfuscation red flags, applied the same way to `StubPath` | Autostart (Run/RunOnce) Keys |
| Service-based persistence and its own registry/event-log evidence chain | Services |
| Task-based persistence and its own event/registry/filesystem evidence chain | Scheduled Tasks |
| First/last-seen evidence and hash identity of a `StubPath`-launched executable | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of a `StubPath`-launched executable | Prefetch.md (note 06) |

## Resources

- MITRE ATT&CK T1547.014 (Boot or Logon Autostart Execution: Active Setup) — https://attack.mitre.org/techniques/T1547/014/
- Microsoft, "About Active Setup" / Installed Components registry reference (Sysinternals/legacy MSDN documentation, mirrored across current community references) — see Sysinternals Autoruns documentation for a current, maintained description of the mechanism
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- Atomic Red Team, T1547.014 — https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1547.014/T1547.014.md
