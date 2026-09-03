# File Association & Screensaver Hijacking

Both mechanisms in this note work the same way at their core: hijack a default Windows handler that already fires on a routine, user-initiated action, and Windows will keep launching the attacker's payload every time that action recurs — without the user ever running an installer, clicking a suspicious link, or doing anything that looks out of the ordinary. File association hijacking rewrites what command line runs when a file of a given extension is opened; screensaver hijacking rewrites what executable runs after the configured idle timeout. Neither requires elevated privileges when scoped to the current user, and both are persistent across reboots because the trigger — a double-click, or sitting idle — is something that happens naturally, not something an attacker has to re-engineer each time.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **Both mechanisms are only as suspicious as the command line they point at.** Every file extension has *some* association, and every account has *some* screensaver configuration — that's normal Windows behavior, not a finding. The finding is a `(Default)`/`SCRNSAVE.EXE` value pointing at an unexpected binary, a command line that chains the original file/action through to a legitimate handler so nothing looks broken, or a change to either value that lines up in time with other evidence of attacker activity.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [File Association Hijacking](#file-association-hijacking)
- [Screensaver Hijacking](#screensaver-hijacking)
- [Scoping: Per-User vs. Per-Machine](#scoping-per-user-vs-per-machine)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to File Association & Screensaver Hijacking](#red-flags-specific-to-file-association--screensaver-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

```powershell
# Every HKCU per-user file-association override (the precedence winner when both HKCU and HKCR define the same extension)
Get-ChildItem 'HKCU:\Software\Classes' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\.' } | ForEach-Object {
    $progId = (Get-ItemProperty $_.PSPath).'(default)'
    if ($progId) {
        $cmd = (Get-ItemProperty "HKCU:\Software\Classes\$progId\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
        [PSCustomObject]@{ Extension = $_.PSChildName; ProgId = $progId; Command = $cmd }
    }
}

# High-frequency extensions (.txt, .lnk, .htm/.html) whose open command doesn't point at the expected native handler
'.txt','.lnk','.htm','.html' | ForEach-Object {
    $ext = $_
    $progId = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$ext" -ErrorAction SilentlyContinue).'(default)'
    $cmd = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
    [PSCustomObject]@{ Extension = $ext; ProgId = $progId; Command = $cmd }
}

# Any open-command across HKCR whose command line references a second file path after its own executable - the "%1 passthrough" chaining pattern
Get-ChildItem 'Registry::HKEY_CLASSES_ROOT' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -notmatch '^\.' } | ForEach-Object {
    $cmd = (Get-ItemProperty "$($_.PSPath)\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
    if ($cmd -match '%1.*%1|cmd\.exe|powershell|wscript|cscript|mshta|rundll32') {
        [PSCustomObject]@{ ProgId = $_.PSChildName; Command = $cmd }
    }
}

# Current user's screensaver configuration in one pass - executable, whether it's active, and the idle timeout
Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE, ScreenSaveActive, ScreenSaveTimeOut, ScreenSaverIsSecure -ErrorAction SilentlyContinue |
    Select-Object 'SCRNSAVE.EXE', ScreenSaveActive, ScreenSaveTimeOut, ScreenSaverIsSecure

# SCRNSAVE.EXE pointing outside the standard System32 screensaver location
$scr = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue).'SCRNSAVE.EXE'
if ($scr -and $scr -notmatch '^C:\\Windows\\System32\\') { "Non-standard screensaver path: $scr" }

# Sweep every local user hive for a hijacked association or screensaver value - loop NTUSER.DAT-backed HKEY_USERS SIDs
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-.*[^_Classes]$' } | ForEach-Object {
    $sid = $_.PSChildName
    Get-ItemProperty "Registry::HKEY_USERS\$sid\Control Panel\Desktop" -Name SCRNSAVE.EXE -ErrorAction SilentlyContinue |
        Select-Object @{N='SID';E={$sid}}, 'SCRNSAVE.EXE'
}
```

## File Association Hijacking

Every registered file extension on Windows resolves, through a ProgID indirection, to an `open` command that Explorer (and anything else that calls `ShellExecute`) invokes when a file of that type is double-clicked:

```
HKEY_CLASSES_ROOT\<extension>                    (Default) = <ProgId>
HKEY_CLASSES_ROOT\<ProgId>\shell\open\command     (Default) = <command line, typically "C:\...\app.exe" "%1">
```

`HKEY_CLASSES_ROOT` (HKCR) itself isn't a real hive — it's a merged, read-through view built from `HKLM\SOFTWARE\Classes` (the machine-wide, admin-writable definitions) and `HKCU\Software\Classes` (the per-user overrides), with HKCU winning whenever both define the same extension or ProgID. That precedence rule is exactly what makes the per-user path attractive to an attacker: a standard, non-elevated user account can write `HKCU\Software\Classes\.txt\shell\open\command` and immediately override the machine-wide Notepad association for that one account, with no admin rights and no UAC prompt required.

A hijacked association almost never breaks the file type outright — the useful attack pattern chains the original file straight through to its legitimate handler after the payload runs, so `open\command` becomes something like `cmd.exe /c start evil.exe & notepad.exe "%1"` or a script that launches the payload and then re-invokes the real application with the same `%1` argument. The user double-clicks a `.txt` file, Notepad opens exactly as expected, and nothing about the visible behavior signals that anything else just ran.

**Extension choice is a frequency play.** `.txt`, `.lnk`, and other extensions opened constantly in the course of normal work maximize trigger frequency compared to a rarely-touched extension — the same "ride a high-frequency, already-normal event" logic that makes COM hijacking of a commonly-instantiated CLSID effective (see COM Hijacking, this family).

### PowerShell

Walk the ProgID indirection for a specific extension to see exactly what command Explorer will run — this two-step lookup (extension → ProgID → command) mirrors what `ShellExecute` itself does internally:

```powershell
$ext = '.txt'
$progId = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$ext").'(default)'
(Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\$progId\shell\open\command").'(default)'
```

Check specifically for a per-user override that would take precedence over any machine-wide definition, since `HKCR` alone shows only the merged, already-resolved result and won't tell you *which* hive actually supplied the winning value:

```powershell
Get-ItemProperty "HKCU:\Software\Classes\$ext" -ErrorAction SilentlyContinue
Get-ItemProperty "HKLM:\SOFTWARE\Classes\$ext" -ErrorAction SilentlyContinue
```

Sweep every extension in one pass and flag any `open\command` value referencing an interpreter or LOLBIN rather than a dedicated application binary:

```powershell
Get-ChildItem 'Registry::HKEY_CLASSES_ROOT' | Where-Object { $_.PSChildName -notmatch '^\.' } | ForEach-Object {
    $cmd = (Get-ItemProperty "$($_.PSPath)\shell\open\command" -ErrorAction SilentlyContinue).'(default)'
    if ($cmd -match 'cmd\.exe|powershell|wscript|cscript|mshta|rundll32') { [PSCustomObject]@{ ProgId = $_.PSChildName; Command = $cmd } }
}
```

## Screensaver Hijacking

Windows treats a `.scr` file as nothing more than a renamed Portable Executable — there is no separate screensaver runtime or sandbox, `.scr` is executed exactly like a `.exe` once the idle timeout fires. The relevant values all live under the per-user Desktop control-panel key:

| Value | Location | Meaning |
|---|---|---|
| `SCRNSAVE.EXE` | `HKCU\Control Panel\Desktop` | Full path to the `.scr` file that Windows launches after the idle timeout — the direct hijack point |
| `ScreenSaveActive` | `HKCU\Control Panel\Desktop` | `"1"` = screensaver enabled and will fire on idle timeout, `"0"` = disabled | 🔴 A critical nuance: if this is `"0"`, `SCRNSAVE.EXE`'s value never fires *regardless of what it points to* — always check this value alongside `SCRNSAVE.EXE`, not instead of it |
| `ScreenSaveTimeOut` | `HKCU\Control Panel\Desktop` | Idle time, in seconds, before the screensaver launches | A very short timeout paired with a suspicious `SCRNSAVE.EXE` value tightens the trigger window; an unusually long one may indicate an attacker deliberately reducing how often the payload fires to stay under the radar |
| `ScreenSaverIsSecure` | `HKCU\Control Panel\Desktop` | `"1"` = workstation locks on screensaver dismissal, `"0"` = does not | Not itself a persistence value, but worth noting during the same review — a `"0"` here paired with a hijacked `SCRNSAVE.EXE` means the payload's window (if it has one) is reachable without re-authenticating |

Because these are ordinary Desktop control-panel settings, they're also reachable and settable through the same Control Panel/Settings UI a legitimate user would use to pick a screensaver — an attacker doesn't need anything more sophisticated than a registry write or, with local access, the Personalization settings page itself.

### PowerShell

Pull the full screensaver configuration for the current user in one call, checking `ScreenSaveActive` alongside `SCRNSAVE.EXE` since the enabled/disabled state determines whether the value even matters:

```powershell
Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE, ScreenSaveActive, ScreenSaveTimeOut
```

Verify the target file is genuinely a `.scr`-renamed PE and check its Authenticode signature — a legitimate screensaver from a reputable vendor is normally signed, an attacker's renamed payload typically is not:

```powershell
$scr = (Get-ItemProperty 'HKCU:\Control Panel\Desktop' -Name SCRNSAVE.EXE).'SCRNSAVE.EXE'
Get-AuthenticodeSignature $scr | Select-Object Path, Status, SignerCertificate
```

Sweep every loaded local user hive under `HKEY_USERS` for a per-account hijack, since `HKCU` from a live administrative session only reflects the currently-logged-on user's own configuration:

```powershell
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-.*[^_Classes]$' } | ForEach-Object {
    Get-ItemProperty "Registry::HKEY_USERS\$($_.PSChildName)\Control Panel\Desktop" -Name SCRNSAVE.EXE, ScreenSaveActive -ErrorAction SilentlyContinue
}
```

## Scoping: Per-User vs. Per-Machine

Both mechanisms are **per-user (`HKCU`-scoped) by default**, and that scoping has direct investigative value: a hijacked association or screensaver value found in one user's hive implicates that specific user profile, not the machine as a whole, and a suspect logged into a shared or multi-user host with a clean `HKCU` for their own account while another account's hive is hijacked points toward either a compromised second account or an attacker who pivoted to it. Both *can* be set at machine scope — `HKLM\SOFTWARE\Classes` for a machine-wide file association override, or a Group Policy-pushed screensaver — but that requires admin rights (for the association) or domain/local policy authority (for the screensaver), so a machine-wide finding is a stronger signal of privileged access than a single hijacked `HKCU` entry.

## Event Log Evidence

Neither mechanism has a dedicated event ID — both are ordinary registry-value writes with no specialized Windows Event Log source of their own. Evidence comes from general-purpose registry auditing (off by default) and the filesystem timestamps of the payload files involved.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **"Audit Registry" (Object Access)** enabled *and* a SACL configured on the specific key — neither is default; without both in place ahead of time, this event will not exist for these keys |
| Filesystem MACB on the payload `.scr`/hijacked-handler executable | n/a | Creation/modification timestamps | See NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes — in the near-universal absence of registry auditing, the dropped payload's own timestamps are usually the primary install-time evidence |
| Prefetch | n/a | Confirms the hijacked handler or screensaver actually executed | See Prefetch.md (note 06) — a `.scr` payload leaves the same Prefetch trail any other executed binary would |

🔴 **Do not expect a log trail for either mechanism absent pre-configured registry auditing.** This is one of the more forensically quiet corners of this family — the primary evidence is the registry value itself (current state, no history unless a registry-transaction-log/backup comparison is available) plus whatever the dropped payload leaves behind in Prefetch, ShimCache, or Amcache once it actually runs.

## Red Flags Specific to File Association & Screensaver Hijacking

- **`open\command` chaining the original file through to a legitimate application after the payload.** The `... & notepad.exe "%1"` or equivalent pattern is specifically designed so the hijack is invisible to the user — the expected application still opens. Don't stop investigating a command line just because it *also* launches the legitimate handler; check everything before the `%1` reference, not just the end of the string.
- **A high-frequency, ubiquitous extension hijacked rather than an obscure one.** `.txt`, `.lnk`, `.htm`/`.html`, and similar everyday extensions maximize trigger frequency — a hijack on an extension the user opens dozens of times a day is a more effective (and thus more likely to be attacker-chosen) target than a rarely-used one.
- **`SCRNSAVE.EXE` pointing outside `C:\Windows\System32\`.** Legitimate, vendor-shipped screensavers on a standard Windows install live in `System32`; third-party screensaver software is uncommon on modern enterprise endpoints, and a path into `%TEMP%`, `%APPDATA%`, or a user profile directory is the screensaver-persistence equivalent of the drop-and-persist pattern flagged throughout this family.
- **`ScreenSaveActive = "0"` alongside a suspicious `SCRNSAVE.EXE` value.** Don't assume a hijacked screensaver value is inert just because the check confirms `SCRNSAVE.EXE` looks wrong — but also don't over-flag it: if `ScreenSaveActive` is `"0"`, the trigger is currently disabled and the finding is dormant persistence, worth noting but not currently firing. Conversely, an attacker who *enables* `ScreenSaveActive` as part of planting the hijack, on a host/user where it was previously off, is itself a change worth explaining.
- **HKCU-scoped file-association override present when the corresponding HKLM/HKCR default is unmodified.** Because HKCU wins the merge, a clean-looking `HKCR` view from a live session can be masking a per-user override entirely — always check `HKCU\Software\Classes` explicitly rather than trusting the merged `HKCR` read alone.
- **Registry value modification time inconsistent with other account activity.** A `SCRNSAVE.EXE` or association override written at a time the account's own logon history says nobody was actively using Personalization settings is worth tracing back to what else was happening on the host at that moment — see Registry Forensics Fundamentals (note 04) for how to pull a key's own last-write time.

## Tooling

| Tool | Use |
|---|---|
| **`assoc` / `ftype`** (built-in `cmd.exe`) | Quick live query of an extension's ProgID (`assoc`) and its associated open command (`ftype`) — fast, but only reads the merged `HKCR` view, so it won't tell you which hive (HKCU vs HKLM) actually supplied the value |
| **Registry Editor / direct `Get-ItemProperty`** | Direct inspection of `HKCU\Software\Classes`, `HKLM\SOFTWARE\Classes`, and `HKCU\Control Panel\Desktop` — the only way to distinguish a per-user override from the machine-wide default |
| **Autoruns** (Sysinternals) | Its "Explorer" tab surfaces certain shell-integration points, though full extension-by-extension association hijacking is not one of its dedicated tabs — treat Autoruns as a partial-coverage tool here and rely on the direct registry queries in this note for a complete sweep |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `Software\Classes` and `Control Panel\Desktop` from an acquired `NTUSER.DAT`/`UsrClass.dat` rather than a live host — see Registry Forensics Fundamentals (note 04) |
| Direct Authenticode check (`Get-AuthenticodeSignature`) | Verifying whether a suspect `.scr` or hijacked-handler executable is legitimately signed |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `HKCU\...\shell\open\command` overriding a clean HKLM/HKCR default for the same extension | HKCU wins the merge — a per-user override is invisible unless checked explicitly, and requires no admin rights to plant |
| `open\command` chaining to a legitimate app after the payload (`... & app.exe "%1"`) | Designed specifically so the hijack is invisible to the user — the expected application still opens as normal |
| Hijack on a high-frequency, ubiquitous extension (`.txt`, `.lnk`, `.htm`) | Maximizes trigger frequency — attacker-preferred targets over rarely-used extensions |
| `SCRNSAVE.EXE` pointing outside `C:\Windows\System32\` | Legitimate screensavers live in System32 on a standard install; anywhere else is the screensaver-persistence drop-and-persist pattern |
| `ScreenSaveActive` toggled to `"1"` on a host/user where it was previously disabled, alongside a suspicious `SCRNSAVE.EXE` | The enabling write itself is the signal — a dormant hijack was just switched live |
| Command line referencing an interpreter/LOLBIN (`powershell`, `mshta`, `rundll32`, `wscript`) instead of a dedicated application binary | Same LOLBIN-abuse pattern flagged for Run keys and scheduled-task actions elsewhere in this family |
| No Security-log 4657 despite a suspicious value | Registry-object-access auditing is off by default for these keys — absence of the event doesn't mean the value wasn't changed; rely on the value's own last-write time and the payload's filesystem/Prefetch trail instead |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure, `NTUSER.DAT`/`UsrClass.dat` offline access mechanics | Registry Forensics Fundamentals (note 04) |
| LOLBIN and obfuscated command-line patterns applied the same way to hijacked handlers | Autostart (Run/RunOnce) Keys |
| Another "hijack a routine, high-frequency Windows trigger" persistence mechanism | COM Hijacking (this family) |
| Confirming actual execution of a hijacked handler or renamed `.scr` payload | ShimCache (AppCompatCache).md, Amcache.md, Prefetch.md (note 06) |
| Office-specific default-handler abuse (Trusted Locations, Add-ins, Office Test) | Office Persistence Abuse (this family) |
| Full registry-auditing/event-log mechanics (4657 and SACL configuration) | Event Log Analysis (note 11) |

## Resources

- MITRE ATT&CK T1546.001 (Event Triggered Execution: Change Default File Association) — https://attack.mitre.org/techniques/T1546/001/
- MITRE ATT&CK T1546.002 (Event Triggered Execution: Screensaver) — https://attack.mitre.org/techniques/T1546/002/
- Microsoft, File Types and File Associations — https://learn.microsoft.com/windows/win32/shell/fa-file-types
- Microsoft, About Screen Savers — https://learn.microsoft.com/windows/win32/dxtecharts/screen-saver
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
