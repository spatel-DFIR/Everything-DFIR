# PowerShell Profiles & PSModulePath Hijacking

A PowerShell profile is a script that runs automatically, with no explicit invocation, every time a matching PowerShell host starts a session. There are up to four of these per host (more on a host running both Windows PowerShell 5.1 and PowerShell 7 side by side, since each engine maintains its own set), and Windows ships none of them populated by default — the files simply don't exist until something creates them. That combination — automatic execution, zero built-in content to compare against, and a location almost nobody thinks to check — makes profile scripts an extremely high-frequency, low-visibility persistence trigger: append one line to a profile and it runs every single time that user (or, for the AllUsers variants, *any* user) opens a console, ISE window, or VS Code integrated terminal on that host.

PSModulePath hijacking is a related but distinct trigger living in the same neighborhood. PowerShell auto-loads modules by searching, in order, every directory listed in the `PSModulePath` environment variable whenever a command name doesn't match a currently-loaded function or cmdlet, and whenever a script explicitly calls `Import-Module <name>`. An attacker who can prepend a directory to that search order, or who plants a same-named malicious module ahead of the legitimate one in an existing search path, gets code execution at module-import time — for any script or profile on the host that ever imports a commonly-used module name, not just the specific one the attacker is impersonating.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A profile script is only as suspicious as content that shouldn't be there.** Windows creates none of these files by default, so the mere *existence* of a profile file is already worth a look — but plenty of admins and power users legitimately populate `$PROFILE` with aliases, prompt customization, and module imports. The finding is never "a profile exists," it's "this profile downloads/decodes/executes something, references a path outside the user's own tooling, or was modified/created around the same time as other evidence of attacker activity." The same logic applies to `PSModulePath`: the variable legitimately holds multiple entries (user, system, and often vendor-specific paths for tools like Azure PowerShell or VMware PowerCLI) — the finding is an *unexpected* entry, not the variable having more than one value.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Four Profile Locations](#the-four-profile-locations)
- [Why This Is Attractive](#why-this-is-attractive)
- [PSModulePath Hijacking](#psmodulepath-hijacking)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Profiles & PSModulePath](#red-flags-specific-to-profiles--psmodulepath)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, no-third-party-tool triage against the profile locations and `PSModulePath`, on both PowerShell engines if both are present on the host.

```powershell
# Every profile path for this host/session (all four, including ones that don't exist yet) with existence and size
$PROFILE | Select-Object AllUsersAllHosts, AllUsersCurrentHost, CurrentUserAllHosts, CurrentUserCurrentHost |
    ForEach-Object { $_.PSObject.Properties } | ForEach-Object {
        $exists = Test-Path $_.Value
        [PSCustomObject]@{ Scope = $_.Name; Path = $_.Value; Exists = $exists; SizeBytes = if ($exists) { (Get-Item $_.Value).Length } } }

# Full content of every profile that actually exists - read them all in one pass, nothing to page through manually
Get-ChildItem $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost -ErrorAction SilentlyContinue |
    ForEach-Object { "=== $($_.FullName) ==="; Get-Content $_.FullName }

# Profile content containing encoding/download/obfuscation red flags - same patterns used for Run-key and task command lines
Get-ChildItem $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost -ErrorAction SilentlyContinue |
    Select-String -Pattern 'FromBase64String|-enc(odedcommand)?\s|IEX|Invoke-Expression|DownloadString|Net\.WebClient|-WindowStyle Hidden|-noprofile' |
    Select-Object Path, LineNumber, Line

# Current PSModulePath entries in load-search order, flagging anything outside the standard three locations
$env:PSModulePath -split ';' | ForEach-Object {
    [PSCustomObject]@{
        Path       = $_
        Standard   = $_ -match '\\(WindowsPowerShell|PowerShell)\\Modules$|\\System32\\WindowsPowerShell\\v1\.0\\Modules$'
        Writable   = (Get-Acl $_ -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference -match 'Everyone|Users' -and $_.FileSystemRights -match 'Write' }
    }
}

# Modules sitting in a non-standard PSModulePath directory ahead of (or shadowing) a known-good module name
$env:PSModulePath -split ';' | Get-ChildItem -Directory -ErrorAction SilentlyContinue |
    Where-Object { $_.Parent.FullName -notmatch '\\(WindowsPowerShell|PowerShell)\\Modules$|\\System32\\WindowsPowerShell\\v1\.0\\Modules$' } |
    Select-Object FullName, LastWriteTime

# Machine-wide PSModulePath value straight from the registry/environment key - the persistence-relevant, reboot-surviving copy
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath -ErrorAction SilentlyContinue

# Filesystem creation/modification times for every profile that exists - a profile "created" long after the user account itself is worth a look
Get-ChildItem $PROFILE.AllUsersAllHosts, $PROFILE.AllUsersCurrentHost, $PROFILE.CurrentUserAllHosts, $PROFILE.CurrentUserCurrentHost -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime
```

## The Four Profile Locations

PowerShell loads up to four profile scripts, in a fixed order, every time a session starts — later ones can override earlier ones, and all of them run unless the host was launched with `-NoProfile`:

| Load order | `$PROFILE` property | Default path (Windows PowerShell 5.1) | Default path (PowerShell 7+) | Scope |
|---|---|---|---|---|
| 1 | `AllUsersAllHosts` | `$PSHOME\profile.ps1` (`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1`) | `$PSHOME\profile.ps1` (`C:\Program Files\PowerShell\7\profile.ps1`) | Every user, every PowerShell host program (console, ISE, VS Code) — the broadest-blast-radius location and, because it lives under a system directory, the one that requires admin rights to write in a properly-permissioned environment |
| 2 | `AllUsersCurrentHost` | `$PSHOME\Microsoft.PowerShell_profile.ps1` | `$PSHOME\Microsoft.PowerShell_profile.ps1` | Every user, but only the specific host program named in the filename (the console host here; ISE and VS Code each have their own equivalent `*_profile.ps1` name) |
| 3 | `CurrentUserAllHosts` | `$HOME\Documents\WindowsPowerShell\profile.ps1` | `$HOME\Documents\PowerShell\profile.ps1` | Just the current user, every host program — the location most individual users and admins actually populate for their own aliases/prompt customization |
| 4 | `CurrentUserCurrentHost` | `$HOME\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` | `$HOME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1` | Just the current user, just the console host — runs last, so it can override anything set by the three profiles before it |

Windows PowerShell 5.1 and PowerShell 7 maintain **entirely separate profile sets** — a 5.1 profile under `WindowsPowerShell\` has no effect on a 7 session and vice versa, because each engine points `$HOME\Documents\<engine-folder>` at a different subdirectory. On a host with both engines installed (increasingly the default on modern Windows), that means checking eight file paths, not four, to be thorough. `$PSHOME` itself also differs per engine and per architecture — a 32-bit PowerShell host on a 64-bit OS resolves `$PSHOME` under `SysWOW64` rather than `System32`, mirroring the same 32/64-bit split covered for Run keys and Scheduled Tasks elsewhere in this family.

None of these eight files exist on a stock Windows install. Every one of them is created lazily, the first time something (a user, an installer, a malicious script) actually writes to that path — which means `Test-Path` returning `$true` for any of them is itself a data point worth having, independent of content.

### PowerShell

Enumerate the exact profile paths for the current host/PS-version combination directly from the live `$PROFILE` automatic variable rather than hardcoding paths, since `$PSHOME` and `$HOME` resolve differently across engine versions, architectures, and user profile locations:

```powershell
$PROFILE | Select-Object AllUsersAllHosts, AllUsersCurrentHost, CurrentUserAllHosts, CurrentUserCurrentHost
```

Because none of the four exist by default, always test for existence before reading — the property values above are just strings, populated whether or not a file backs them:

```powershell
$PROFILE.PSObject.Properties | ForEach-Object {
    if (Test-Path $_.Value) { Get-Content $_.Value }
}
```

When working from an acquired image or offline copy of a user's profile rather than a live session, reconstruct the same four paths manually, substituting the target user's actual home directory and remembering to check both the `WindowsPowerShell` and `PowerShell` subtrees:

```powershell
$targetHome = 'C:\Users\<username>'
@(
    "$targetHome\Documents\WindowsPowerShell\profile.ps1"
    "$targetHome\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
    "$targetHome\Documents\PowerShell\profile.ps1"
    "$targetHome\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
) | Where-Object { Test-Path $_ } | Get-Content
```

## Why This Is Attractive

A Run key fires once, at logon. A profile script fires every single time anyone on the host opens a PowerShell console, ISE window, or VS Code integrated terminal — which for an administrator or a developer working the host regularly can be dozens of times a day. That trigger frequency, combined with the fact that profile files are essentially never reviewed by end users (most people who have one didn't write it themselves, or wrote it once years ago and never looked at it again), makes this one of the more durable and least-monitored persistence mechanisms in this family. It also blends naturally into legitimate customization: a malicious `Invoke-Expression (New-Object Net.WebClient).DownloadString(...)` line appended to the bottom of a profile that already contains a dozen benign alias definitions and prompt-color tweaks is easy to miss on a casual read.

The `AllUsersAllHosts` location deserves particular attention during triage precisely because of its blast radius — a single file write there means the payload runs for every user who ever opens a PowerShell session on that host, not just the account the attacker initially compromised. Reaching that location does require the same write access an attacker would need for most other system-wide persistence mechanisms in this family, so its presence there is a strong signal of an attacker who already had (or escalated to) local admin.

## PSModulePath Hijacking

`PSModulePath` is a standard Windows environment variable — visible and editable the same way `PATH` is — that lists the directories PowerShell searches, in order, for module folders. It exists in two forms worth distinguishing: the process-level value inherited from the environment at session start (`$env:PSModulePath`), and the persistent machine-wide value stored under the same `Environment` registry key that holds `PATH` and every other system environment variable:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\PSModulePath
```

A per-user override can also be set under `HKCU\Environment\PSModulePath`, which — like most HKCU-vs-HKLM environment-variable precedence — is appended to (not overridden by) the machine-wide value at logon rather than fully replacing it, so both locations are worth checking.

The abuse pattern has two variants. The first is straightforward path prepending: an attacker with write access to the machine-wide `Environment` key adds their own directory to the front of `PSModulePath`, so any subsequent auto-load or `Import-Module` call that resolves a module by name checks the attacker's directory *first*. The second is module shadowing without even touching the variable itself: dropping a malicious module folder with the same name as a legitimate, commonly-imported module (a company-internal utility module, or even a well-known third-party one like `AzureAD` or `ImportExcel`) into a directory that already sits earlier in the existing search order than the real module's location. Either variant achieves code execution the moment any script, profile, or scheduled task on the host imports that module name — which, unlike a profile script that only runs at session start, can be triggered by any automation on the host that happens to `Import-Module` something with the hijacked name.

### PowerShell

Enumerate the live search order and flag anything outside PowerShell's own standard install/user-module locations — the three paths every stock Windows install ships with:

```powershell
$env:PSModulePath -split ';' | Where-Object {
    $_ -notmatch '\\(WindowsPowerShell|PowerShell)\\Modules$|\\System32\\WindowsPowerShell\\v1\.0\\Modules$'
}
```

Pull the persistent, reboot-surviving machine-wide value directly from the registry rather than the current process's environment, since the two can differ if the variable was changed after the current session started:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath
Get-ItemProperty 'HKCU:\Environment' -Name PSModulePath -ErrorAction SilentlyContinue
```

Check whether any legitimately-named, commonly-imported module exists in more than one location on the search path — if it does, whichever copy sits in the earlier-searched directory wins, and that's the one worth inspecting first:

```powershell
$moduleName = '<module-name>'
$env:PSModulePath -split ';' | ForEach-Object {
    $candidate = Join-Path $_ $moduleName
    if (Test-Path $candidate) { [PSCustomObject]@{ SearchOrder = $_; ModulePath = $candidate; LastWriteTime = (Get-Item $candidate).LastWriteTime } }
}
```

## Event Log Evidence

Neither profile-script execution nor `PSModulePath` changes generate a dedicated event ID of their own — there is no equivalent of Scheduled Tasks' 106 or Services' 7045 here. Evidence instead comes from PowerShell's own general-purpose logging, which is off by default and must be enabled through Group Policy (`Turn on Module Logging`, `Turn on Script Block Logging`) before an incident, not after.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| `Microsoft-Windows-PowerShell/Operational` | 4103 | Module logging — pipeline execution details | Requires **Module Logging** GPO enabled; captures cmdlet invocations within a session, including ones a profile script triggers |
| `Microsoft-Windows-PowerShell/Operational` | 4104 | Script Block Logging — the actual script text executed | 🔴 Requires **Script Block Logging** GPO enabled — when on, this is the single best source for recovering a profile script's *content* even after the file itself has been modified or deleted, since PowerShell logs the block of code as it executes, not just that something ran |
| Windows PowerShell log (legacy `Windows PowerShell` channel) | 400 / 800 | Engine state change / pipeline execution details | Older, less detailed equivalent present even on hosts that haven't enabled the newer Operational-log auditing |
| Filesystem MACB on the profile file itself | n/a | Creation/modification timestamps | See NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes — in the absence of enabled PowerShell logging, the file's own timestamps are often the only install-time evidence available |

🔴 **Assume PowerShell logging is off until proven otherwise.** Unlike Scheduled Tasks' 106 or Services' 7045, there is no default-enabled log this note can lead with — 4103/4104 depend entirely on whether Module Logging and Script Block Logging were turned on before the incident. Where they weren't, the profile file's own content and filesystem timestamps are the primary evidence, which is exactly why the Hunt Evil block above reads file content directly rather than assuming a log trail exists.

## Red Flags Specific to Profiles & PSModulePath

- **A profile file exists at all where the host/user baseline says it shouldn't.** None of the eight possible profile paths exist by default — simple existence, especially of `AllUsersAllHosts` on a host with no legitimate reason for centrally-managed PowerShell customization, is worth investigating on its own before even reading the content.
- **Profile content containing download-and-execute patterns.** `Invoke-Expression`/`IEX`, `Net.WebClient`/`Invoke-WebRequest` piped into execution, or `-EncodedCommand`-style base64 blobs inside a profile script are the same red flags used for Run-key and scheduled-task command lines, just relocated to a file that fires on every session start instead of every logon or boot.
- **`AllUsersAllHosts` populated on a host where no other centralized PowerShell configuration exists.** This location requires admin-equivalent write access and affects every user — its use for anything other than deliberate, documented environment standardization (common in managed enterprise images, rare on a typical workstation) is itself informative.
- **A `PSModulePath` entry pointing into `%TEMP%`, `%APPDATA%`, `%ProgramData%`, or any other user-writable location.** Same drop-and-persist logic as `ImagePath` for services and `<Command>` for scheduled tasks — legitimate module locations are the three standard paths plus known vendor install directories (Program Files-rooted), not user-writable temp space.
- **A module folder name that exactly matches a well-known or organization-internal module, sitting in a non-standard, earlier-searched location.** This is module shadowing rather than a `PSModulePath` variable change — the search order silently resolves to the attacker's copy without the variable itself looking unusual at all, which is why the Hunt Evil block above walks every search-path directory for name collisions rather than only inspecting the variable's string value.
- **Profile or module file timestamps that don't align with account creation, software installation, or other expected baseline events.** A `CurrentUserCurrentHost` profile with a creation time weeks after the user account itself was provisioned, with no corresponding software install to explain it, is worth tracing back to whatever else happened on the host around that time.

## Tooling

| Tool | Use |
|---|---|
| **`$PROFILE`** (built-in automatic variable) | Live, host/version-accurate enumeration of all four profile paths for the current session — the fastest and most reliable way to get exact paths without hardcoding assumptions about `$PSHOME`/`$HOME` resolution |
| **`Get-Content` / `Select-String`** (built-in) | Direct content review and pattern-matching against profile files — no specialized parser needed, these are plain text |
| **Group Policy — PowerShell logging settings** | Not a hunt tool but a prerequisite: Module Logging and Script Block Logging must be enabled *before* an incident for 4103/4104 to exist at all |
| **Autoruns** (Sysinternals) | Does not natively enumerate PowerShell profile scripts or `PSModulePath` — this is a genuine coverage gap worth knowing about; profile-based persistence requires the manual/scripted approach in this note rather than a single-pass Autoruns sweep |
| **KAPE** (Kroll Artifact Parser and Extractor) | Targets covering `Documents\WindowsPowerShell`, `Documents\PowerShell`, and the `PowerShell/Operational` and legacy `Windows PowerShell` event logs at scale across many endpoints — see Evidence Acquisition & Imaging (note 02) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Any of the four/eight profile files exists on a host/user with no baseline reason to have one | None exist by default — existence alone is a data point before content is even reviewed |
| Profile content containing `IEX`/`Invoke-Expression`, `Net.WebClient`/`DownloadString`, or `-EncodedCommand` base64 | Same download-and-execute/obfuscation patterns flagged for Run keys and scheduled-task command lines, now firing on every session start |
| `AllUsersAllHosts` populated with no documented centralized-configuration reason | Requires admin-equivalent access and affects every user on the host — the highest blast-radius profile location |
| `PSModulePath` entry pointing into `%TEMP%`, `%APPDATA%`, `%ProgramData%`, or another user-writable location | Drop-and-persist for the module search path — legitimate entries are the three standard paths or vendor Program Files directories |
| Module folder name matching a well-known/internal module, present in an earlier-searched, non-standard directory | Module shadowing — the search order resolves to the attacker's copy without the `PSModulePath` string itself looking unusual |
| Profile/module file timestamps inconsistent with account creation or software install history | Suggests post-provisioning tampering; worth correlating against other host activity from the same window |
| No 4103/4104 PowerShell-logging events despite suspicious profile content | Logging is off by default — absence doesn't mean nothing ran, it means the log source was never enabled; rely on file content and filesystem timestamps as the baseline instead |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics for the machine-wide `Environment` key | Registry Forensics Fundamentals (note 04) |
| Obfuscated/encoded PowerShell command-line patterns applied the same way to Run-key values | Autostart (Run/RunOnce) Keys |
| Service- and task-based persistence and their own registry/event-log evidence chains | Services, Scheduled Tasks |
| Confirming actual execution of a payload a hijacked module or profile launched | ShimCache (AppCompatCache).md, Amcache.md, Prefetch.md (note 06) |
| Full PowerShell logging/event mechanics (4103/4104/400/800) in depth | Event Log Analysis (note 11) |

## Resources

- MITRE ATT&CK T1546.013 (Event Triggered Execution: PowerShell Profile) — https://attack.mitre.org/techniques/T1546/013/
- Microsoft, about_Profiles — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_profiles
- Microsoft, about_PSModulePath — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_psmodulepath
- Microsoft, about_Logging_Windows (Module Logging / Script Block Logging) — https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- `PSModulePath` hijack: Unmapped — no confidently-known MITRE sub-technique ID exists for this specific mechanism; used rather than guessing one, per this repo's documented convention (see `Windows/Scripts/persistence/README.md`)
