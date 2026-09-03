# Image File Execution Options (IFEO)

Image File Execution Options exists for a legitimate development purpose: it lets a developer attach a debugger to a specific executable, so that every time Windows launches that binary, the debugger runs instead — with the original binary's path handed to the debugger as an argument — rather than requiring the developer to manually attach a debugger after the fact. Windows implements this at the process-creation level, in `CreateProcess` itself, which means the substitution is unconditional and total: nothing downstream of `CreateProcess` distinguishes between "this launched normally" and "this launched under a debugger because IFEO said so."

That single design decision — a registry key that silently redirects execution of a *named* binary, checked by the OS on every single launch attempt — is exactly what makes IFEO valuable to an attacker independent of any actual debugging use case. Point the `Debugger` value at your own binary, and every future launch of the target executable runs your code instead, with the legitimate binary's path as an argument your code can choose to honor (spawn the real thing after doing something first) or ignore (replace it outright). It requires no service, no scheduled task, and — because it hooks the launch of an *existing, already-trusted* binary rather than introducing a new one — it inherits whatever trust an analyst places in seeing that binary's name in a process list or startup sweep.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A `Debugger` value on an accessibility binary invocable from the logon screen is conclusive regardless of what the debugger binary itself is or whether it's signed.** `cmd.exe` as the `Debugger` for `sethc.exe` is legitimate, signed, and completely benign in every other context — the finding isn't "this binary is malicious," it's "this specific registry value redirects a pre-authentication logon-screen trigger to a command shell," and that fact alone is the entire signal. For every other target binary, judge the `Debugger` value the normal way: does this specific redirection make sense for this specific executable.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Debugger Value](#the-debugger-value)
- [The Accessibility-Binary Special Case (T1546.008)](#the-accessibility-binary-special-case-t1546008)
- [Silent Process Exit — The Second IFEO Abuse Path](#silent-process-exit--the-second-ifeo-abuse-path)
- [Access Requirements and Investigative Scoping](#access-requirements-and-investigative-scoping)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to IFEO](#red-flags-specific-to-ifeo)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the IFEO key — no third-party tooling required for the initial sweep.

```powershell
# Every binary with a Debugger value set - the entire attack surface this note covers, in one pass
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { [PSCustomObject]@{ TargetBinary = $_.PSChildName; Debugger = $dbg } }
}

# Accessibility binaries specifically - a Debugger value here is conclusive regardless of what the debugger itself is
$accessibilityBins = 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe'
$accessibilityBins | ForEach-Object {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
    $dbg = (Get-ItemProperty $path -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { "CONCLUSIVE HIT: $_ -> Debugger = $dbg" }
}

# Check the 32-bit WOW6432Node mirror too - the same view-redirection gotcha covered elsewhere in this family
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { [PSCustomObject]@{ TargetBinary = $_.PSChildName; Debugger = $dbg } }
}

# GlobalFlag with FLG_SILENT_PROCESS_EXIT (0x200) set, paired with a SilentProcessExit MonitorProcess - the second, less-known IFEO abuse path
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $gf = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).GlobalFlag
    if ($gf -band 0x200) {
        $mon = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($_.PSChildName)" -ErrorAction SilentlyContinue).MonitorProcess
        [PSCustomObject]@{ TargetBinary = $_.PSChildName; GlobalFlag = $gf; MonitorProcess = $mon }
    }
}

# Every Debugger target resolved and checked for Authenticode status - distinguishes "legit dev debugger" noise from unsigned payloads
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg -match '^"?([^"]+\.exe)"?') {
        $exe = [System.Environment]::ExpandEnvironmentVariables($Matches[1])
        if (Test-Path $exe) { [PSCustomObject]@{ Target = $_.PSChildName; DebuggerExe = $exe; Signed = (Get-AuthenticodeSignature $exe).Status } }
    }
}
```

## The Debugger Value

Each target binary gets its own subkey, named after the binary itself (not a full path — just the filename), under:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary.exe>
```

| Value | Meaning | Forensic relevance |
|---|---|---|
| `Debugger` | The full command line launched **instead of** `<binary.exe>` whenever anything invokes it; the original binary's resolved path is appended as an argument to the debugger | The core hijack primitive. Not present by default for the vast majority of binaries — a `Debugger` value existing at all on a given target is the finding, and what it's set to determines severity |

Because the redirection happens inside `CreateProcess`, it applies regardless of *how* the target binary was invoked — double-clicking it, launching it from a script, or the logon screen calling it directly (relevant to the accessibility case below) all go through the same substitution. This is also a 64-bit/32-bit split point worth checking both sides of: a target's IFEO entry can exist under the native key or under `WOW6432Node`, mirroring the gotcha already documented for Run keys in Autostart (Run/RunOnce) Keys.

### PowerShell

Enumerate every subkey under the IFEO root and pull `Debugger` where set — most subkeys that exist for other reasons (compatibility flags, `GlobalFlag` settings unrelated to debugging) will have no `Debugger` value at all, so filtering on its presence is the fast triage path:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $props = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
    if ($props.Debugger) {
        [PSCustomObject]@{ TargetBinary = $_.PSChildName; Debugger = $props.Debugger; GlobalFlag = $props.GlobalFlag }
    }
}
```

Split the `Debugger` command line into its executable and arguments, then check the resolved executable's Authenticode signature — a redirection to an unsigned or unfamiliar binary is a strong signal on any target, not just the accessibility set:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $dbg = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger
    if ($dbg -match '^"?([^"]+\.exe)"?\s*(.*)$') {
        $exe = [System.Environment]::ExpandEnvironmentVariables($Matches[1])
        [PSCustomObject]@{
            Target    = $_.PSChildName
            DebuggerExe = $exe
            Arguments = $Matches[2]
            Signed    = if (Test-Path $exe) { (Get-AuthenticodeSignature $exe).Status } else { 'NOT FOUND' }
        }
    }
}
```

## The Accessibility-Binary Special Case (T1546.008)

A specific set of executables can be invoked **from the Windows logon screen itself, before any user has authenticated**, via built-in keyboard-accessibility shortcuts or on-screen prompts:

| Binary | Invocation trigger |
|---|---|
| `sethc.exe` | Sticky Keys — press Shift five times |
| `utilman.exe` | Ease of Access / Utility Manager — the accessibility icon on the logon screen, or Win+U |
| `osk.exe` | On-Screen Keyboard |
| `magnify.exe` | Magnifier |
| `narrator.exe` | Narrator |
| `displayswitch.exe` | Display switching (Win+P equivalent, also reachable pre-auth) |
| `atbroker.exe` | Accessibility Technology Broker — coordinates which accessibility tool launches |

Because Windows launches these directly from the logon screen — running as SYSTEM, before any credential has been entered — an IFEO `Debugger` hijack on any one of them becomes a **pre-authentication, SYSTEM-privilege code-execution primitive**. The canonical example is setting `Debugger` for `sethc.exe` to `cmd.exe`: from that point forward, pressing Shift five times at *any* logon screen — including over RDP, without ever authenticating — spawns a SYSTEM command prompt. This is one of the oldest and most well-documented Windows backdoor techniques, precisely because it requires nothing more than a single registry write and survives indefinitely until removed.

🔴 **This is why presence alone is treated as conclusive for this specific target set, independent of the debugger binary's own trust status.** `cmd.exe` is signed, well-known, and completely unremarkable in a thousand other contexts — the signal isn't "an untrusted binary is present," it's "this specific, well-documented pre-auth trigger has been redirected at all." A model or detection script that only scores IFEO findings by the debugger binary's signature/trust status will systematically under-rate the single highest-severity variant of this technique. This repo's own `hunt_persistence.ps1` (`Windows/Scripts/persistence/hunt_persistence.ps1`) encodes exactly this reasoning — it flags a `Debugger` value on any of the accessibility binaries above as an absolute HIGH-severity finding regardless of score, rather than folding it into the same weighted-evidence scoring used for other IFEO targets, because the mere existence of the redirection is itself the entire finding.

### PowerShell

Check every accessibility binary explicitly, rather than relying on spotting it in a full IFEO dump — this is the highest-value single check in this note:

```powershell
$accessibilityBins = 'sethc.exe','utilman.exe','osk.exe','magnify.exe','narrator.exe','displayswitch.exe','atbroker.exe'
$accessibilityBins | ForEach-Object {
    $path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_"
    $dbg = (Get-ItemProperty $path -ErrorAction SilentlyContinue).Debugger
    if ($dbg) { [PSCustomObject]@{ AccessibilityBinary = $_; Debugger = $dbg; Verdict = 'CONCLUSIVE - presence alone is the finding' } }
}
```

## Silent Process Exit — The Second IFEO Abuse Path

A second, less-known mechanism lives under the same `Image File Execution Options` root and a sibling key: **Silent Process Exit monitoring**, a legitimate Windows Error Reporting feature that lets a monitor application run automatically whenever a specific process terminates.

| Value | Location | Meaning |
|---|---|---|
| `GlobalFlag` | `Image File Execution Options\<binary.exe>\GlobalFlag` | Must include the `FLG_SILENT_PROCESS_EXIT` flag (`0x200`) for the target binary for silent-exit monitoring to be active |
| `MonitorProcess` | `SilentProcessExit\<binary.exe>\MonitorProcess` | The program launched by `WerSvc.dll`/`werfault.exe` when the target binary exits (normally or via `TerminateProcess`), once `GlobalFlag`'s `0x200` bit is set for that target |

The abuse path mirrors the `Debugger` hijack conceptually but triggers on process *exit* rather than *launch*: set `GlobalFlag` to include `0x200` for a binary an attacker expects to be run and terminated routinely, then point `MonitorProcess` at an attacker binary — every time the target process ends, Windows Error Reporting's silent-exit handler launches the monitor. Because this mechanism is genuinely obscure relative to the `Debugger` value — most defenders check IFEO for `Debugger` entries and stop there — a `SilentProcessExit`-based hijack is comparatively likely to be missed by a sweep that only looks at the primary value this note leads with.

### PowerShell

Check for the `FLG_SILENT_PROCESS_EXIT` bit across every IFEO target and pull the paired `MonitorProcess` value where set:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ForEach-Object {
    $gf = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).GlobalFlag
    if ($gf -and ($gf -band 0x200)) {
        $mon = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($_.PSChildName)" -ErrorAction SilentlyContinue).MonitorProcess
        [PSCustomObject]@{ TargetBinary = $_.PSChildName; GlobalFlagHex = ('0x{0:X}' -f $gf); MonitorProcess = $mon }
    }
}
```

## Access Requirements and Investigative Scoping

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` is writable only by Administrators by default. A finding here — of any kind, `Debugger` or `SilentProcessExit` — therefore implies the attacker already had local administrator or SYSTEM-equivalent access at the time the value was written. This is useful scoping context for an investigation: an IFEO finding is not itself the initial-access vector, it's evidence of what an already-elevated attacker did next, and the timeline should be built backward from there to establish how that elevated access was obtained in the first place.

## Event Log Evidence

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **non-default "Audit Registry" auditing plus a SACL configured on the IFEO key or the specific target subkey** — without both, no event is generated for the `Debugger`/`GlobalFlag`/`MonitorProcess` write |
| Application log | 1000 / WER-related events | Silent Process Exit relies on Windows Error Reporting's `WerSvc.dll` handler | A `SilentProcessExit`-triggered `MonitorProcess` launch is not logged as a distinct, purpose-built event — corroborate via process-creation logging (Security 4688 with command-line auditing, or EDR telemetry) for the monitor process itself rather than relying on a WER-specific log entry |
| Security log | 4688 (with command-line auditing) | Process creation | The most direct corroborating evidence that an IFEO `Debugger` substitution actually fired — look for the debugger binary's process creation event carrying the original target's path as a command-line argument, which is the signature shape of an IFEO-redirected launch |

🔴 **There is no default-on, mechanism-specific creation event for either IFEO abuse path.** As with Winlogon hijacking, registry-value evidence (the key's own last-write time) and process-creation correlation via 4688 matter more here than for mechanisms with a strong operational-log baseline like Scheduled Tasks' 106 or Services' 7045.

## Red Flags Specific to IFEO

- **A `Debugger` value on any accessibility binary (`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`, `narrator.exe`, `displayswitch.exe`, `atbroker.exe`).** Conclusive on presence alone — this redirects a pre-authentication, SYSTEM-privilege logon-screen trigger, regardless of what the debugger binary itself is or whether it's signed.
- **A `Debugger` value on a security-relevant binary — AV/EDR executables, `taskmgr.exe`, `regedit.exe`, `cmd.exe`, `powershell.exe`.** A classic defense-impairment use of IFEO: setting `Debugger` to something invalid or non-existent (or to a binary that immediately exits) effectively disables the target executable entirely — the tool appears to "not launch" rather than showing an obvious error, which can read to a user as a routine glitch rather than active tampering.
- **`GlobalFlag` with `FLG_SILENT_PROCESS_EXIT` (`0x200`) set, paired with a `MonitorProcess` pointing at an unexpected binary.** The less-known abuse path — worth checking explicitly since a `Debugger`-only sweep will not surface it.
- **A `Debugger` command line that appends unusual arguments beyond simply relaunching the original binary.** A legitimate developer debugger use case is typically a straightforward debugger-plus-target invocation; an attacker's `Debugger` value more often either ignores the appended target path entirely or uses it as a decoy while separately launching a payload.
- **Any IFEO entry present with no corresponding, documented development or compatibility-shim purpose.** Because IFEO's legitimate use is niche (developer debugging workflows, and some application-compatibility shims), an entry on a typical end-user or server host that isn't explainable by either is itself notable, independent of what it points to.

## Tooling

| Tool | Use |
|---|---|
| **Direct registry read (`Get-ItemProperty`/`Get-ChildItem`)** | The fastest live check — the entire IFEO key and its `SilentProcessExit` sibling are readable with no special parser |
| **Autoruns** (Sysinternals) | Its Image Hijacks tab is purpose-built for this exact mechanism — enumerates every `Debugger` value across the IFEO key with code-signing and VirusTotal cross-reference in the same pass as every other autostart mechanism |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` and `SilentProcessExit` when working from an acquired `SOFTWARE` hive rather than a live host |
| **GFlags** (Windows Debugging Tools) | The legitimate Microsoft tool for setting `GlobalFlag`/silent-exit monitoring — useful reference for what a genuine, developer-intended configuration looks like versus an attacker-planted one |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `Debugger` set on any accessibility binary (`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`, `narrator.exe`, `displayswitch.exe`, `atbroker.exe`) | Conclusive regardless of the debugger binary's trust status — redirects a pre-authentication, SYSTEM-privilege logon-screen trigger |
| `Debugger` set on a security tool (AV/EDR, Task Manager, Registry Editor, `cmd.exe`, `powershell.exe`) | Classic defense-impairment use — an invalid or decoy debugger silently disables the target |
| `GlobalFlag` with `0x200` (`FLG_SILENT_PROCESS_EXIT`) paired with an unexpected `MonitorProcess` | The less-known abuse path — missed by a `Debugger`-only sweep |
| `Debugger` value present on any binary with no documented development/compatibility purpose | IFEO's legitimate use is niche; unexplained presence is itself notable |
| Security 4657 present for the IFEO key or a target subkey | Direct evidence of the write — requires non-default auditing plus a SACL, so absence proves nothing |
| Security 4688 showing the debugger binary launched with the original target's path as an argument | Direct corroborating evidence the redirection actually fired at runtime |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics for the `SOFTWARE` hive | Registry Forensics Fundamentals (note 04) |
| The logon-screen-adjacent Winlogon Shell/Userinit hijack, and RDP-specific InitialProgram hijack | Winlogon & Terminal Services Shell Hijacking |
| In-process, credential-material-adjacent boot-time persistence inside `lsass.exe` | LSA Packages & Credential Providers |
| First/last-seen evidence and hash identity of a dropped debugger/monitor binary | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of the redirected debugger binary | Prefetch.md (note 06) |

## Resources

- MITRE ATT&CK T1546.012 (Event Triggered Execution: Image File Execution Options Injection) — https://attack.mitre.org/techniques/T1546/012/
- MITRE ATT&CK T1546.008 (Event Triggered Execution: Accessibility Features) — https://attack.mitre.org/techniques/T1546/008/
- Microsoft Learn / Windows Hardware Dev Center, Monitoring Silent Process Exit — https://learn.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
