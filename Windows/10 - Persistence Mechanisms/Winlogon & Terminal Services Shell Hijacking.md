# Winlogon & Terminal Services Shell Hijacking

`winlogon.exe` is the process responsible for the entire interactive logon sequence — presenting the credential UI, handling the secure attention sequence (Ctrl-Alt-Del), and, once a user authenticates, launching the two programs that turn a bare desktop session into something usable: an initialization process (`userinit.exe`) that sets up the user's environment, and a shell (`explorer.exe`) that the user actually interacts with for the rest of the session. Both of those launch targets are read from the registry rather than hardcoded, which means anything that can write to a handful of `Winlogon` values controls what runs, as what account, at the start of every single logon on the box — no exploit, no service install, just a string.

That makes Winlogon hijacking one of the most durable and self-sustaining persistence mechanisms in Windows: unlike a Run key, which competes for attention among dozens of other legitimate entries in the same key, a hijacked `Shell` or `Userinit` value *is* the logon sequence — every console logon by every user re-executes it, and because it's baked into how the session bootstraps rather than layered on top of an already-running desktop, it survives even fairly aggressive cleanup of Run keys, scheduled tasks, and services. Terminal Services carries a parallel, session-type-specific version of the same idea — a registry value that determines what program launches instead of (or before) the normal shell specifically for RDP sessions, independent of whatever `Winlogon\Shell` says for console logons.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **The finding is never "Winlogon has a Shell value" — it always does.** Every Windows install has `Shell = explorer.exe` and `Userinit = C:\Windows\system32\userinit.exe,` (note the trailing comma) by default. The finding is a `Shell` pointing anywhere other than `explorer.exe`, a `Userinit` with *more than one* comma-separated path, an unexpected `Notify` subkey referencing a DLL that isn't part of the OS, or a Terminal Services `InitialProgram` configured to launch something other than the session's normal shell.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Winlogon Shell and Userinit](#winlogon-shell-and-userinit)
- [Per-User Shell Override](#per-user-shell-override)
- [The Legacy Notify Subkey](#the-legacy-notify-subkey)
- [Terminal Services / RDP Shell Hijack](#terminal-services--rdp-shell-hijack)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Winlogon & Terminal Services Hijacking](#red-flags-specific-to-winlogon--terminal-services-hijacking)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the values this note keys on — every check below reads a handful of registry values directly, no third-party parser required.

```powershell
# Shell and Userinit as actually configured, machine-wide and for the current user - compare against the known-good defaults
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' | Select-Object Shell, Userinit
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue | Select-Object Shell

# Userinit with MORE than one comma-separated path - the classic "append, don't replace" tell (legit value has exactly one path plus a trailing comma)
$userinit = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Userinit
if (($userinit -split ',' | Where-Object { $_.Trim() }).Count -gt 1) { "SUSPECT Userinit: $userinit" }

# Shell not equal to the default explorer.exe, machine-wide or per-user - the primary self-sustaining red flag in this whole note
$hklmShell = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').Shell
if ($hklmShell -and $hklmShell -ne 'explorer.exe') { "SUSPECT HKLM Shell: $hklmShell" }
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match 'S-1-5-21.*[^_Classes]$' } | ForEach-Object {
    $s = Get-ItemProperty "$($_.PSPath)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
    if ($s.Shell) { [PSCustomObject]@{ SID = $_.PSChildName; Shell = $s.Shell } }
}

# Legacy Notify subkey - any DLL registered here at all is worth a look, since post-Vista GPO Software Restriction/logon scripts replaced legitimate use
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select-Object PSChildName, DllName, Impersonate, Asynchronous
}

# Terminal Services InitialProgram override for RDP sessions - fInheritInitialProgram=1 means InitialProgram runs instead of the normal shell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue |
    Select-Object InitialProgram, fInheritInitialProgram

# Authenticode status of whatever Shell/Userinit/Notify DLLs actually resolve to - a fast triage pass across all three at once
@($hklmShell, ($userinit -split ',' | Where-Object { $_.Trim() })) | Where-Object { $_ } | ForEach-Object {
    $p = [System.Environment]::ExpandEnvironmentVariables($_.Trim())
    if (Test-Path $p) { Get-AuthenticodeSignature $p | Select-Object Path, Status }
}
```

## Winlogon Shell and Userinit

The core values live under:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

| Value | Default | Meaning | Forensic relevance |
|---|---|---|---|
| `Userinit` | `C:\Windows\system32\userinit.exe,` (note the trailing comma) | The user-initialization process Winlogon launches first — sets up the user environment (drive mappings, group policy processing, restoring the environment) before handing off to the shell | 🔴 **The high-value tell here is a value with more than one comma-separated path.** `Userinit` is a comma-separated *list*, and malware commonly appends its own binary after the legitimate `userinit.exe,` rather than replacing the value outright — `userinit.exe,evil.exe` runs `userinit.exe` normally and then launches `evil.exe` immediately after, both under the logging-on user's context, before `explorer.exe` even starts |
| `Shell` | `explorer.exe` | The default shell Winlogon launches for the session | 🔴 **The primary self-sustaining persistence red flag in this note.** Winlogon does not "add to" the shell the way `Userinit` is often appended to — it simply launches whatever `Shell` says. A value that isn't `explorer.exe` (or isn't the expected full path to it) means the attacker's binary *is* the user's entire shell, relaunched at every logon with zero further action required |

Both values are read from the machine-wide `HKLM` key at every console logon. Because `Userinit` legitimately ends in a trailing comma even with nothing appended, a naive string-equality check against the default will pass a benign install — the check that matters is *how many* comma-separated entries are present, not simply whether the value differs from the literal default string.

### PowerShell

Pull both core values in one call and compare `Userinit`'s comma count against the expected single-entry baseline:

```powershell
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
[PSCustomObject]@{
    Shell         = $wl.Shell
    Userinit      = $wl.Userinit
    UserinitCount = ($wl.Userinit -split ',' | Where-Object { $_.Trim() }).Count
}
```

Resolve whatever `Shell` and each `Userinit` entry actually point to on disk, and check them for a valid Authenticode signature — a hijacked shell binary dropped by malware is very rarely signed:

```powershell
$targets = @($wl.Shell) + ($wl.Userinit -split ',' | Where-Object { $_.Trim() })
$targets | ForEach-Object {
    $p = [System.Environment]::ExpandEnvironmentVariables($_.Trim())
    if (-not (Split-Path $p -IsAbsolute)) { $p = "C:\Windows\System32\$p" }
    if (Test-Path $p) { Get-AuthenticodeSignature $p | Select-Object Path, Status, SignerCertificate }
    else { "MISSING: $p" }
}
```

Check the 32-bit `WOW6432Node` mirror on 64-bit hosts, the same gotcha covered for Run keys in Autostart (Run/RunOnce) Keys — Winlogon itself is not a WOW-aware component the way Run keys are, but always verify both locations exist as expected rather than assuming:

```powershell
Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon'
```

## Per-User Shell Override

A per-user override of the same `Shell` value exists under each user's hive:

```
HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell
```

This key is not present by default for most users — its mere presence is itself a mild signal, and if it exists, it takes precedence over the `HKLM` value for that specific user's console logons only. Because it lives in a per-user, user-writable location (`NTUSER.DAT`, or the live `HKCU` hive), an attacker with only standard-user code execution — no elevation required — can plant this override to hijack their own logon sessions, which is a materially lower bar than the elevated access needed to write the machine-wide `HKLM\...\Winlogon` key covered above.

### PowerShell

Sweep every loaded user hive under `HKEY_USERS` for a per-user `Shell` override, since `HKCU` alone only reflects the currently-interactive session:

```powershell
Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-\d+-\d+-\d+-\d+$' } | ForEach-Object {
    $key = "$($_.PSPath)\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $val = Get-ItemProperty $key -ErrorAction SilentlyContinue
    if ($val.Shell) { [PSCustomObject]@{ SID = $_.PSChildName; Shell = $val.Shell } }
}
```

When working from an acquired image rather than a live host, the same value is read from each user's `NTUSER.DAT` hive under `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` — see Registry Forensics Fundamentals (note 04) for hive-loading mechanics against an offline `NTUSER.DAT`.

## The Legacy Notify Subkey

Before Windows Vista, third-party software (and, historically, malware) registered **notification package DLLs** under a `Notify` subkey to receive callbacks on Winlogon events — logon, logoff, startup, shutdown, lock, unlock, and the secure-attention-sequence itself:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\<PackageName>
```

Microsoft deprecated this mechanism starting with Vista in favor of Group Policy-based logon/logoff scripts and event-driven service notifications, and it carries no legitimate role in a modern, fully-patched Windows install. It's still worth checking for two reasons: legacy or poorly-maintained enterprise images can carry stale entries forward from a Windows 7-era build, and the registry values themselves — while functionally inert on modern Windows in the sense that Winlogon no longer calls arbitrary `Notify` DLLs the way it once did — can still be present and are a real artifact an analyst may encounter when triaging an older or migrated image.

| Value (under `Notify\<PackageName>`) | Meaning |
|---|---|
| `DllName` | The DLL loaded for this notification package |
| `Impersonate` | `1` = the DLL's callback runs impersonating the logging-on/off user; `0` = runs as the Winlogon process itself (higher-privilege context) |
| `Asynchronous` | `1` = the callback runs on a separate thread rather than blocking the logon sequence |
| `Logon` / `Logoff` / `Startup` / `Shutdown` / `Lock` / `Unlock` / `StartShell` | Named exported functions within `DllName` — each value names the function called for that specific Winlogon event |

Any `Notify` subkey present at all on a modern (Vista+) host is worth investigating on that basis alone, since there is essentially no current legitimate software that still relies on this mechanism rather than the GPO-based replacement.

### PowerShell

Enumerate every registered notification package and resolve the DLL each one points to:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify' -ErrorAction SilentlyContinue | ForEach-Object {
    $pkg = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{
        Package      = $_.PSChildName
        DllName      = $pkg.DllName
        Impersonate  = $pkg.Impersonate
        Asynchronous = $pkg.Asynchronous
    }
}
```

## Terminal Services / RDP Shell Hijack

Terminal Services (RDP) sessions have their own, independent initial-program mechanism, configured per-listener under the WinStations control key:

```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `fInheritInitialProgram` | `1` / `0` | Whether the session should launch the program named in `InitialProgram` automatically on connection, rather than falling back to the session's normal shell |
| `InitialProgram` | Path to an executable | The program launched on RDP connection when `fInheritInitialProgram = 1` |

When `fInheritInitialProgram` is set to `1` and `InitialProgram` points at an attacker binary, that binary launches automatically for every RDP session against that listener — functionally the same outcome as a `Winlogon\Shell` hijack, but scoped specifically to RDP/Terminal Services sessions rather than every console logon, and configured through a completely separate registry path that a Winlogon-focused sweep alone will not surface. Both mechanisms answer the same underlying question — *what launches instead of, or alongside, the session's normal shell* — for two different session types: console logon for Winlogon, RDP for Terminal Services. Treat them as the same detection pattern applied to two different entry points, and check both whenever RDP access is in scope for an investigation.

### PowerShell

Read the RDP listener's initial-program configuration directly:

```powershell
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue |
    Select-Object InitialProgram, fInheritInitialProgram
```

## Event Log Evidence

Winlogon and Terminal Services registry modifications are not logged by a dedicated, mechanism-specific event the way service installs (7045) or scheduled-task creation (106) are. Detection here relies on registry-auditing infrastructure rather than a purpose-built log source.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **non-default "Audit Registry" auditing plus a SACL configured on the specific `Winlogon` key** — without both, no event is generated for a `Shell`/`Userinit`/`Notify` write. This is not enabled out of the box on any Windows edition |
| Security log | 4611 | A trusted logon process has been registered with the Local Security Authority | Logged for legitimate logon-process registrations (`winlogon.exe`, `services.exe`) at boot and occasionally afterward; an unexpected registration outside of boot, or from a `Subject\Security ID` that isn't SYSTEM, is worth investigating alongside a Winlogon-value change |
| Application log | 1000 (Application Error) | Faulting application crash | Correlate against a `Shell`/`Userinit` change if `explorer.exe` or the injected binary crashes at logon — a malformed or incompatible replacement shell producing a black-screen/crash-loop symptom is a common real-world tell of a botched Winlogon hijack |

🔴 **Because there is no reliable default-on event for this mechanism, registry-value evidence (the `Winlogon` key's own last-write timestamp) and filesystem timestamps on whatever binary `Shell`/`Userinit`/`InitialProgram` now points to matter more here than for mechanisms with a strong operational-log baseline.** See Registry Forensics Fundamentals (note 04) for reading a key's `LastWriteTime` directly.

### PowerShell

Pull the `Winlogon` key's own last-write time as a install-time proxy, since no reliable creation-event exists for this mechanism:

```powershell
$key = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
[PSCustomObject]@{ Key = $key.Name; LastWriteTime = $key.GetValue('', $null); }
# LastWriteTime requires a native call - .NET does not expose it directly; RegistryKey does not surface it via PowerShell without P/Invoke or an offline parser (e.g. Registry Explorer) against an acquired hive
```

## Red Flags Specific to Winlogon & Terminal Services Hijacking

- **`Userinit` with more than one comma-separated path.** The legitimate value is exactly `C:\Windows\system32\userinit.exe,` — one path plus a trailing comma with nothing after it. Malware overwhelmingly *appends* rather than replaces, producing `userinit.exe,evil.exe` — both binaries run in sequence at every logon, and the presence of the legitimate `userinit.exe` first means the user's session still boots up normally, making the added binary easy to miss unless the value is inspected field-by-field.
- **`Shell` pointing at anything other than `explorer.exe`.** This is the single highest-confidence finding in this note — Winlogon launches exactly what `Shell` names, no fallback, no secondary check. A non-default value here means the attacker's binary runs as the user's entire shell, every logon, indefinitely, until the value is reverted.
- **A per-user `HKCU\...\Winlogon\Shell` override present at all.** This key does not exist for most users by default; its mere presence — regardless of what it points to — is worth investigating, and it can be planted without any elevation since it lives in a user-writable hive.
- **Any `Notify` subkey present on a modern (Vista+) host.** There is essentially no legitimate current software that still relies on this mechanism; a populated `Notify\<PackageName>` on a recent Windows version is anomalous on that basis alone, independent of what the referenced DLL does.
- **`fInheritInitialProgram = 1` with an unexpected `InitialProgram`.** Easy to miss because it lives under a completely different registry path (`Terminal Server\WinStations`) than the Winlogon keys an analyst instinctively checks first — a host can pass a clean Winlogon sweep and still have RDP sessions silently launching an attacker binary.
- **`Shell`/`Userinit`/`Notify` targets that fail Authenticode verification or resolve to a path outside `System32`.** Legitimate values point at signed Microsoft binaries in well-known system locations; anything resolving to `%TEMP%`, `%AppData%`, or an unsigned binary anywhere is the drop-and-persist pattern applied to this mechanism.

## Tooling

| Tool | Use |
|---|---|
| **Registry Editor / direct `Get-ItemProperty`** | The fastest live check — every value covered in this note is a single flat string read, no special tooling required |
| **Autoruns** (Sysinternals) | Its Logon tab specifically enumerates `Winlogon\Shell`, `Winlogon\Userinit`, and `Winlogon\Notify` alongside every other autostart mechanism, with code-signing and VirusTotal cross-reference in the same pass |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` and per-user `NTUSER.DAT` equivalents, including key `LastWriteTime`, when working from an acquired image rather than a live host |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `Userinit` with more than one comma-separated path | Legitimate value has exactly one path plus a trailing comma; malware appends a second binary rather than replacing the value outright |
| `Shell` not equal to `explorer.exe` | The primary, highest-confidence finding — Winlogon launches whatever this value names as the user's entire shell, every logon |
| `HKCU\...\Winlogon\Shell` present at all | Not present by default for most users; plantable without elevation since it lives in a user-writable hive |
| Any `Notify` subkey on a Vista+ host | Deprecated post-Vista in favor of GPO; no current legitimate software relies on it |
| `fInheritInitialProgram = 1` with an unexpected `InitialProgram` | RDP-specific shell hijack — invisible to a Winlogon-only sweep since it lives under a different registry path |
| `Shell`/`Userinit`/`Notify` target unsigned or outside `System32` | Drop-and-persist pattern — legitimate targets are signed Microsoft binaries in well-known locations |
| Security 4657 present for the `Winlogon` key | Direct evidence of the registry modification — requires non-default registry auditing plus a SACL on the key, so absence proves nothing |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics for `NTUSER.DAT`/`SOFTWARE` | Registry Forensics Fundamentals (note 04) |
| Boot-time, pre-authentication code execution via a debugger hijack on accessibility binaries invoked from the same RDP/console logon screen | Image File Execution Options (IFEO) |
| Boot-time code execution inside `lsass.exe` itself, the credential-material-adjacent sibling of logon-time hijacking | LSA Packages & Credential Providers |
| Service-based and scheduled-task-based persistence for comparison against this mechanism's registry/event-log evidence gap | Services, Scheduled Tasks |
| Fileless, event-triggered persistence in the WMI repository | WMI Event Consumers |
| First/last-seen evidence and hash identity of a dropped shell/`Userinit` binary | ShimCache (AppCompatCache).md, Amcache.md (note 06) |

## Resources

- MITRE ATT&CK T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL) — https://attack.mitre.org/techniques/T1547/004/
- Terminal Services `InitialProgram`/`fInheritInitialProgram` — Attack = Unmapped; no confident current ATT&CK sub-technique ID covers this specific WinStations registry mechanism, tracked here as a conceptual sibling of T1547.004 rather than under an invented ID
- Microsoft Learn, Winlogon architecture and registry entries — https://learn.microsoft.com/windows/win32/secauthn/winlogon
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
