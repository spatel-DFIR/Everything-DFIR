# AppInit_DLLs & AppCertDLLs

Windows exposes two little-known registry keys that both accomplish the same broad goal by different means: getting an attacker's DLL loaded into a large, unpredictable set of other processes without touching any of those processes individually. `AppInit_DLLs` piggybacks on `user32.dll` — list a DLL there, and it loads into every process that loads `user32.dll`, which in practice is nearly every process with a graphical user interface on the system. `AppCertDLLs` piggybacks on process creation itself — list a DLL there, and it loads into every process created via `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, or `WinExec`, which is a broader and more reliable trigger surface than `AppInit_DLLs` since it doesn't depend on any particular library being loaded by the target.

Both mechanisms are attractive for the same reason: a single registry write buys code execution inside an enormous, constantly-refreshing population of processes, with no per-process configuration and no need to predict in advance which specific application the attacker wants to hook. That breadth is also what makes them comparatively rare in real-world use relative to Run keys or services — they're powerful but blunt, and a DLL that misbehaves inside the wrong host process (a security tool, a critical system component) can cause visible, disruptive failures that draw attention rather than staying quiet.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **`AppInit_DLLs` is effectively dead weight on a modern, Secure Boot-enabled host — which makes a populated value there even more anomalous, not less.** Windows disables the AppInit_DLLs loading path (or requires the listed DLLs to be signed) once Secure Boot is enabled, which is the default posture on essentially every Windows 8-and-later machine sold with UEFI firmware. A finding here on a hardened, Secure-Boot host is either leftover cruft from a legacy image, evidence the host isn't as hardened as assumed, or — worth checking directly — evidence the attacker already has enough access to have addressed the signing requirement. `AppCertDLLs` carries no equivalent Secure Boot mitigation, which makes it the more durable of the two on a modern host despite being far less documented.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [AppInit_DLLs](#appinit_dlls)
- [Secure Boot's Effect on AppInit_DLLs](#secure-boots-effect-on-appinit_dlls)
- [AppCertDLLs](#appcertdlls)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to AppInit_DLLs & AppCertDLLs](#red-flags-specific-to-appinit_dlls--appcertdlls)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against both keys — no third-party tooling required for the initial pass.

```powershell
# AppInit_DLLs value, whether it's actually active, and the Secure Boot / signing-requirement context that determines viability
$appInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
[PSCustomObject]@{
    AppInit_DLLs            = $appInit.AppInit_DLLs
    LoadAppInit_DLLs        = $appInit.LoadAppInit_DLLs
    RequireSignedAppInit_DLLs = $appInit.RequireSignedAppInit_DLLs
    SecureBootEnabled       = (Confirm-SecureBootUEFI -ErrorAction SilentlyContinue)
}

# Populated AND active AppInit_DLLs - the mechanism only actually loads anything when both conditions hold
if ($appInit.AppInit_DLLs -and $appInit.LoadAppInit_DLLs -eq 1) { "ACTIVE: $($appInit.AppInit_DLLs)" }

# Every AppInit_DLLs entry resolved and checked for Authenticode status
if ($appInit.AppInit_DLLs) {
    ($appInit.AppInit_DLLs -split '[\s,]+') | Where-Object { $_ } | ForEach-Object {
        $p = [System.Environment]::ExpandEnvironmentVariables($_)
        if (Test-Path $p) { Get-AuthenticodeSignature $p | Select-Object Path, Status } else { "MISSING: $p" }
    }
}

# AppCertDLLs - a much rarer legitimate finding than AppInit_DLLs, so any entry here deserves immediate attention
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue | Select-Object AppCertDLLs

# WOW6432Node mirror of AppInit_DLLs on 64-bit hosts - the same view-redirection gotcha covered elsewhere in this family
Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue | Select-Object AppInit_DLLs, LoadAppInit_DLLs

# AppCertDLLs entries resolved and signature-checked - same treatment as AppInit_DLLs above
$appCert = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).AppCertDLLs
if ($appCert) {
    ($appCert -split '[\s,]+') | Where-Object { $_ } | ForEach-Object {
        $p = [System.Environment]::ExpandEnvironmentVariables($_)
        if (Test-Path $p) { Get-AuthenticodeSignature $p | Select-Object Path, Status } else { "MISSING: $p" }
    }
}
```

## AppInit_DLLs

The controlling values live under:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
```

| Value | Type | Meaning | Forensic relevance |
|---|---|---|---|
| `AppInit_DLLs` | `REG_SZ` | A space-delimited list of full paths to DLLs | The payload list — every DLL named here loads into every process that loads `user32.dll`, which covers nearly all GUI-based applications on the system |
| `LoadAppInit_DLLs` | `REG_DWORD` | Master on/off switch | Must be `1` for the mechanism to be active at all — a populated `AppInit_DLLs` with `LoadAppInit_DLLs = 0` is inert, present but not currently loading anything. Both conditions must hold for this to be a live finding, not just a registry-hygiene one |
| `RequireSignedAppInit_DLLs` | `REG_DWORD` | Signing enforcement | When set, only Authenticode-signed DLLs are permitted to load via this mechanism — see the Secure Boot discussion below for when this is enforced automatically regardless of this value |

Because the trigger is "loads `user32.dll`," the practical reach of this mechanism is close to universal for interactive, GUI-facing processes — `explorer.exe`, browsers, Office applications, and the vast majority of third-party desktop software all load `user32.dll` early in their startup. Command-line-only tools and services that never touch the GUI subsystem are the main category that doesn't trigger this hook.

### PowerShell

Read both controlling values together, since either one alone is an incomplete picture of whether the mechanism is actually live:

```powershell
$appInit = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
[PSCustomObject]@{
    DllList  = $appInit.AppInit_DLLs
    Active   = ($appInit.LoadAppInit_DLLs -eq 1)
    SignedOnly = ($appInit.RequireSignedAppInit_DLLs -eq 1)
}
```

Split the space-delimited `AppInit_DLLs` list into individual paths and check each for existence and Authenticode signature — an entry pointing at a path that no longer exists is a leftover artifact worth dating via the registry value's own last-write time, while an existing-but-unsigned entry on a `RequireSignedAppInit_DLLs = 1` host indicates the value was written before that enforcement was turned on, or that the enforcement isn't actually taking effect:

```powershell
($appInit.AppInit_DLLs -split '\s+') | Where-Object { $_ } | ForEach-Object {
    $p = [System.Environment]::ExpandEnvironmentVariables($_)
    [PSCustomObject]@{
        Path   = $p
        Exists = Test-Path $p
        Signed = if (Test-Path $p) { (Get-AuthenticodeSignature $p).Status } else { $null }
    }
}
```

Check the `WOW6432Node` mirror on 64-bit hosts — a 32-bit process loading the 32-bit `user32.dll` reads the `WOW6432Node` copy of these values, so a hijack targeting 32-bit-only software will not appear in the native-view sweep above:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows' -ErrorAction SilentlyContinue |
    Select-Object AppInit_DLLs, LoadAppInit_DLLs, RequireSignedAppInit_DLLs
```

## Secure Boot's Effect on AppInit_DLLs

Starting with Windows 8, Microsoft tied `AppInit_DLLs` viability to Secure Boot: when Secure Boot is enabled, the OS enforces the signing requirement regardless of the `RequireSignedAppInit_DLLs` registry value, and on Windows 8 and later the mechanism is effectively neutered for unsigned payloads on any properly Secure-Boot-enforced system. Because Secure Boot is the out-of-box default posture on essentially every UEFI-based Windows 8-and-later machine, `AppInit_DLLs` has quietly gone from "a real, viable persistence technique" on Windows 7-and-earlier hosts to "largely non-viable without a signed DLL or a firmware-level bypass" on the current fleet.

This has a direct triage implication: on a modern, Secure-Boot-enabled host, a populated and active `AppInit_DLLs` value is *more* suspicious than the same finding would be on a legacy Windows 7 image, not less — either the DLL is genuinely signed (unusual for malware, though not impossible with a stolen or abused code-signing certificate), the host's Secure Boot posture isn't what it appears to be, or the finding predates the current OS/firmware configuration and is worth dating against when Secure Boot was actually enabled on that specific machine. Confirm Secure Boot status directly rather than assuming it from OS version alone — some legacy-BIOS or intentionally-downgraded systems still run modern Windows without UEFI Secure Boot active:

```powershell
Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
```

## AppCertDLLs

A separate, considerably lesser-known mechanism lives under a completely different registry path:

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs
```

| Value | Type | Meaning | Forensic relevance |
|---|---|---|---|
| `AppCertDLLs` | `REG_MULTI_SZ` | A list of DLL paths | Every listed DLL is loaded into any process that calls `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLogonW`, or `WinExec` — this fires on process *creation itself*, not on a particular library being loaded by the new process, which gives it a broader and more OS-fundamental trigger surface than `AppInit_DLLs` |

Because `AppCertDLLs` hooks the process-creation API family directly rather than depending on `user32.dll`, it catches command-line tools, services, and headless processes that `AppInit_DLLs` would miss entirely — and unlike `AppInit_DLLs`, it has **no Secure Boot-driven signing enforcement**, making it the more durable and less-mitigated of the two mechanisms on a modern, hardened host. It's also considerably less documented and less commonly checked by defenders, which is precisely why it's worth including in this note's routine sweep rather than treating it as an afterthought to the better-known `AppInit_DLLs`.

### PowerShell

Read the value directly — there is no active/inactive toggle equivalent to `LoadAppInit_DLLs`; a populated `AppCertDLLs` value is live the moment it's written:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).AppCertDLLs
```

Resolve and signature-check every listed entry, exactly as with `AppInit_DLLs` — given how rarely this key is legitimately populated, treat any entry here as a high-priority finding regardless of signature status, and use the signature check to help distinguish a plausible legitimate use (rare, but exists for some low-level system-monitoring and compatibility tooling) from an obvious payload:

```powershell
$appCert = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue).AppCertDLLs
if ($appCert) {
    $appCert | ForEach-Object {
        $p = [System.Environment]::ExpandEnvironmentVariables($_)
        [PSCustomObject]@{ Path = $p; Exists = Test-Path $p; Signed = if (Test-Path $p) { (Get-AuthenticodeSignature $p).Status } else { $null } }
    }
}
```

## Event Log Evidence

Neither mechanism has a dedicated, mechanism-specific creation event — detection relies on registry-auditing infrastructure and DLL-load telemetry rather than a purpose-built log source.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4657 | A registry value was modified | 🔴 Requires **non-default "Audit Registry" auditing plus a SACL on the specific `Windows` or `Session Manager` key** — without both, no event exists for the underlying `AppInit_DLLs`/`AppCertDLLs` write |
| Sysmon (if deployed) | Event ID 7 (Image loaded) | DLL load into a process | The most direct corroborating evidence for `AppInit_DLLs`, since it fires for the injected DLL loading into each `user32.dll`-loading process — not a native Windows event log source, requires Sysmon or equivalent EDR image-load telemetry |
| Sysmon (if deployed) | Event ID 1 (Process Create) | Correlated against `AppCertDLLs` | `AppCertDLLs` itself has no direct DLL-load event equivalent to Sysmon 7 in most default configurations; corroboration is typically indirect, via anomalous DLL presence inside processes that have no legitimate reason to have loaded it |

🔴 **Native Windows logging has no reliable, default-on signal for either mechanism.** This is one of the weaker event-log evidence chains in the Persistence Mechanisms family — registry-value last-write time and DLL-load telemetry from Sysmon or EDR carry proportionally more weight here than for mechanisms like Scheduled Tasks or Services that have a strong default-on operational log.

## Red Flags Specific to AppInit_DLLs & AppCertDLLs

- **`AppInit_DLLs` populated and `LoadAppInit_DLLs = 1` on a Secure Boot-enabled host.** As covered above, this combination is more anomalous on a modern hardened host than on a legacy one — verify Secure Boot status directly and treat a live finding here as higher-priority than the same finding on an older, non-Secure-Boot image.
- **Any entry in `AppCertDLLs` at all.** This value is legitimately populated far less often than `AppInit_DLLs` — its mere presence, independent of signature status, is a strong signal given how few defenders and how little tooling routinely check this specific key.
- **`AppInit_DLLs` or `AppCertDLLs` entries resolving to paths outside `System32`/`Program Files`, or to a path that no longer exists on disk.** The drop-and-persist pattern applied to this mechanism — a legitimate reason for either key to reference `%TEMP%`, `%AppData%`, or a user profile directory essentially never exists.
- **`LoadAppInit_DLLs = 0` with a populated `AppInit_DLLs` value.** Currently inert, but worth flagging as a dormant artifact — either a remnant of a disabled/removed tool, or evidence the attacker is staging the value for later activation (flipping `LoadAppInit_DLLs` to `1` is a single, fast follow-up write).
- **A `RequireSignedAppInit_DLLs` value that doesn't match the host's actual Secure Boot enforcement state.** Worth reconciling — a host claiming to require signed DLLs via the registry value while Secure Boot is disabled is weaker than it appears, and worth noting in the investigation's scoping of what protections were actually active.

## Tooling

| Tool | Use |
|---|---|
| **Direct registry read (`Get-ItemProperty`)** | The fastest live check — both keys are flat, readable values with no special parser required |
| **Autoruns** (Sysinternals) | Its "AppInit" tab covers `AppInit_DLLs` directly with code-signing and VirusTotal cross-reference; `AppCertDLLs` is covered less consistently across Autoruns versions — always cross-check the raw registry value directly rather than relying on Autoruns alone for `AppCertDLLs` |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SOFTWARE\...\Windows` and `SYSTEM\CurrentControlSet\Control\Session Manager` when working from an acquired hive rather than a live host |
| **Sysmon** (Event ID 7, Image Loaded) | Direct corroborating evidence of an `AppInit_DLLs`-injected DLL actually loading at runtime — not deployed by default, but high-value if present |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `AppInit_DLLs` populated and `LoadAppInit_DLLs = 1` on a Secure Boot-enabled host | More anomalous on a modern hardened host than a legacy one — Secure Boot normally neutralizes this mechanism for unsigned payloads |
| Any entry in `AppCertDLLs` | Legitimately populated far less often than `AppInit_DLLs`; presence alone is a strong signal given low routine scrutiny of this key |
| Either value resolving to a path outside `System32`/`Program Files`, or a path that no longer exists | Drop-and-persist pattern, or a stale remnant worth dating |
| `LoadAppInit_DLLs = 0` with a populated `AppInit_DLLs` value | Currently inert, but a dormant artifact — could be staged for later activation with a single follow-up write |
| `RequireSignedAppInit_DLLs` inconsistent with actual Secure Boot enforcement | Worth reconciling as part of scoping what protections were genuinely active on the host |
| Security 4657 present for either key | Direct evidence of the write — requires non-default auditing plus a SACL, so absence proves nothing |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics for the `SOFTWARE` and `SYSTEM` hives | Registry Forensics Fundamentals (note 04) |
| Another registry-driven, near-universal-reach code-execution hook checked earlier in this family | Image File Execution Options (IFEO) |
| First/last-seen evidence and hash identity of a dropped `AppInit_DLLs`/`AppCertDLLs` payload | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual runtime loading of an injected DLL when Sysmon/EDR image-load telemetry is available | Prefetch.md (note 06) |

## Resources

- MITRE ATT&CK T1546.010 (Event Triggered Execution: AppInit DLLs) — https://attack.mitre.org/techniques/T1546/010/
- MITRE ATT&CK T1546.009 (Event Triggered Execution: AppCert DLLs) — https://attack.mitre.org/techniques/T1546/009/
- Microsoft Learn, AppInit DLLs and Secure Boot — https://learn.microsoft.com/windows/win32/dlls/secure-boot-and-appinit-dlls
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
