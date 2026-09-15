# LSA Packages & Credential Providers

The Local Security Authority Subsystem Service (`lsass.exe`) is the process Windows trusts to authenticate logons, enforce local security policy, and generate access tokens — and it does most of that work by loading a set of Security Support Provider (SSP) and Authentication Package (AP) DLLs at boot, before any user has logged on. Which DLLs get loaded is entirely registry-driven: a short list of bare DLL names (no path, no extension — Windows resolves them from `System32`) under a single LSA control key. Add a name to that list, drop a correctly-implemented DLL in `System32`, and `lsass.exe` loads and runs it as part of its own boot sequence, with the same access to credential material that every other SSP/AP has.

That's what makes this mechanism disproportionately valuable to an attacker relative to how rarely it's actually seen in the wild: code registered here doesn't just survive reboot — it runs *inside `lsass.exe` itself*, at boot, before any interactive session exists, with in-process visibility into the authentication data `lsass.exe` handles (password hashes, Kerberos tickets, and — depending on the SSP interface implemented — plaintext credentials as they're validated). Compare that to a Run key or a service: both survive reboot and can run as SYSTEM, but neither one gets to execute *inside the process that owns credential material* the way an LSA package does. Credential Providers occupy an adjacent but distinct role — they're COM DLLs that render the actual logon UI and gather what the user types, which means a malicious credential provider can capture a plaintext password at the moment of entry, before it's even hashed, rather than having to intercept it in-process inside `lsass.exe` afterward.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing this mechanism against Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **Any DLL name appearing in `Authentication Packages`, `Notification Packages`, or `Security Packages` that isn't a recognized, signed Microsoft component is inherently high-confidence.** Unlike Run keys or scheduled tasks, where dozens of legitimate entries exist on any given host, these three values are short — typically a handful of entries, all Microsoft-supplied on an unmodified system (`msv1_0`, `kerberos`, `negotiate`, `schannel`, `wdigest`, `pku2u`, `tspkg`, `cloudap`, and similar). A genuinely new entry, especially one resolving to a path outside `System32` or failing signature verification, warrants investigation as a near-default-positive rather than one signal among many.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The LSA Packages Registry Key](#the-lsa-packages-registry-key)
- [Why This Runs Inside lsass.exe — and What That Costs an Attacker](#why-this-runs-inside-lsassexe--and-what-that-costs-an-attacker)
- [Password Filter DLLs — Same Key, Adjacent Purpose](#password-filter-dlls--same-key-adjacent-purpose)
- [Credential Providers](#credential-providers)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to LSA Packages & Credential Providers](#red-flags-specific-to-lsa-packages--credential-providers)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against the LSA control key and the Credential Providers key — no third-party tooling required for the initial pass.

```powershell
# All three LSA package lists in one read - the entire attack surface this note's first half covers
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
    Select-Object 'Authentication Packages', 'Notification Packages', 'Security Packages'

# Resolve every listed DLL name to its actual on-disk path and Authenticode status - the fast pass that surfaces an unsigned/unknown entry immediately
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
@($lsa.'Authentication Packages' + $lsa.'Notification Packages' + $lsa.'Security Packages') | Where-Object { $_ -and $_ -ne 'msv1_0' } | ForEach-Object {
    $path = "C:\Windows\System32\$_.dll"
    if (Test-Path $path) { Get-AuthenticodeSignature $path | Select-Object Path, Status }
    else { "NOT FOUND: $path (check WOW6432Node / actual load path)" }
}

# OSConfig mirror of Security Packages - the boot-time-authoritative copy some malware forgets to update in lockstep
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig' -ErrorAction SilentlyContinue | Select-Object 'Security Packages'

# Every registered Credential Provider CLSID with its underlying DLL and signature status
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' | ForEach-Object {
    $clsidKey = "HKLM:\SOFTWARE\Classes\CLSID\$($_.PSChildName)\InprocServer32"
    $dll = (Get-ItemProperty $clsidKey -ErrorAction SilentlyContinue).'(default)'
    [PSCustomObject]@{
        CLSID = $_.PSChildName
        Name  = (Get-ItemProperty $_.PSPath).'(default)'
        Dll   = $dll
        Signed = if ($dll -and (Test-Path $dll)) { (Get-AuthenticodeSignature $dll).Status } else { 'NOT FOUND' }
    }
}

# 4611 trusted-logon-process registrations where the Subject isn't SYSTEM - unexpected registration outside the normal boot sequence
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4611} -MaxEvents 100 -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[1].Value -notmatch 'SYSTEM' } |
    Select-Object TimeCreated, @{N='Subject';E={$_.Properties[1].Value}}, @{N='Process';E={$_.Properties[5].Value}}
```

## The LSA Packages Registry Key

The controlling key lives under:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

| Value | Type | What it lists | Forensic relevance |
|---|---|---|---|
| `Authentication Packages` | `REG_MULTI_SZ` | Authentication Package (AP) DLL names — implement the actual credential-validation logic for a given authentication protocol | Corresponds to MITRE ATT&CK T1547.002 (Authentication Package) — a closely related sibling technique to this note's primary focus |
| `Notification Packages` | `REG_MULTI_SZ` | Notification Package DLLs — receive callbacks on password-change events; this is also where legitimate **password filter DLLs** register (see below) | A favorite injection point precisely because a legitimate, well-known use case (password policy enforcement) already populates this value on many hardened/enterprise hosts, giving a malicious entry cover to hide among expected ones |
| `Security Packages` | `REG_MULTI_SZ` | Security Support Provider (SSP) DLLs — the primary target of T1547.005, these implement the SSPI interface and are loaded directly into `lsass.exe` at boot | The core value this note's MITRE mapping (T1547.005) targets |

Each entry is a bare DLL name with **no path and no `.dll` extension** — Windows resolves it against `%SystemRoot%\System32` (and `SysWOW64` for the 32-bit view on a 64-bit host) at load time. A malicious entry therefore requires the attacker to have already dropped a correctly-named DLL into `System32`, which — combined with the registry write itself — typically implies local administrator or SYSTEM-level access was used to plant the persistence, the same scoping implication called out for IFEO in Image File Execution Options (IFEO).

A second, boot-time-authoritative copy of `Security Packages` exists under:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages
```

Windows consults this `OSConfig` value at boot in addition to the primary key; some tooling and some malware update only one of the two locations, so comparing both is worth doing rather than assuming they're always in sync.

### PowerShell

Pull all three lists plus the `OSConfig` mirror in one pass and flag any entry that isn't part of the well-known Microsoft baseline:

```powershell
$knownGood = 'msv1_0','kerberos','negotiate','schannel','wdigest','pku2u','tspkg','cloudap','ntlm','pkuap','livessp'
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
@($lsa.'Authentication Packages' + $lsa.'Notification Packages' + $lsa.'Security Packages') |
    Where-Object { $_ -and ($_ -notin $knownGood) } |
    ForEach-Object { "Unrecognized package: $_" }
```

Resolve each listed name to its actual `System32` path and check both existence and Authenticode signature — a name present in the registry with no corresponding file on disk, or resolving to an unsigned DLL, is the primary tell:

```powershell
@($lsa.'Authentication Packages' + $lsa.'Notification Packages' + $lsa.'Security Packages') | Where-Object { $_ } | ForEach-Object {
    $path = "$env:SystemRoot\System32\$_.dll"
    [PSCustomObject]@{
        Name   = $_
        Path   = $path
        Exists = Test-Path $path
        Signed = if (Test-Path $path) { (Get-AuthenticodeSignature $path).Status } else { $null }
    }
}
```

## Why This Runs Inside lsass.exe — and What That Costs an Attacker

An SSP/AP DLL must correctly implement the SSPI (`SpLsaModeInitialize` and related entry points) or authentication-package interface `lsass.exe` expects — this isn't a loose convention, it's a hard functional requirement. If `lsass.exe` fails to load or initialize a listed package correctly, the failure isn't silent: it can prevent `lsass.exe` from starting cleanly, or crash it outright. That's a real constraint an attacker has to engineer around (a malformed or hastily-written injected DLL is a plausible cause of an unexpected `lsass.exe` crash), and it's forensically useful in the other direction too — **an `lsass.exe` crash (Application-log Event ID 1000, faulting module named) occurring close in time to a change in the `Authentication Packages`/`Notification Packages`/`Security Packages` value is worth treating as a single correlated event rather than two unrelated ones**, since a hastily-deployed or buggy malicious package is a plausible root cause the crash dump and the registry timeline should be checked against together.

This is also the detail that separates this mechanism from Run keys, services, and scheduled tasks in terms of both sophistication required and payoff: getting code to run as SYSTEM at boot is achievable multiple ways, but getting it to run *in-process inside `lsass.exe`*, with the same memory-space access to credential material that legitimate SSPs have, is a materially higher bar — and a materially higher-value outcome for an attacker who clears it.

## Password Filter DLLs — Same Key, Adjacent Purpose

Legitimate password-policy enforcement software (and, correspondingly, some credential-theft tooling) registers via the **exact same** `Notification Packages` value covered above. A password filter DLL is validated by `lsass.exe` on every password change — before the change is committed — giving it visibility into the new plaintext password at the moment it's set. Microsoft's own guidance for implementing a legitimate password filter is to *append* the DLL's name to the existing `Notification Packages` `REG_MULTI_SZ` value rather than overwrite it, which is precisely the "append, don't replace" pattern this family already flags for `Userinit` in Winlogon & Terminal Services Shell Hijacking — the same detection logic (does this list have an entry that doesn't belong, not just "is the list non-empty") applies here.

Because legitimate enterprise password-policy tooling is a real, common reason for `Notification Packages` to be populated, an analyst can't treat *any* non-empty value as inherently suspicious the way an unrecognized `Security Packages` entry can be — verify each individual entry against known-good password-policy software in the environment (vendor, signature, install provenance) rather than flagging the value's mere non-emptiness.

## Credential Providers

Credential Providers are COM-based DLLs that implement the actual logon UI and credential-gathering experience — the box the user types their password into, the fingerprint prompt, the smart-card PIN entry. They're registered under:

```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\<CLSID>
```

Each subkey is named for the provider's CLSID, with a default value holding the provider's display name; the actual DLL is registered the standard COM way, under `HKLM\SOFTWARE\Classes\CLSID\<CLSID>\InprocServer32`. Because a Credential Provider is directly in the path of what the user types at logon — before Windows has even validated it — a malicious provider can:

- Capture the plaintext credential as it's entered, either logging it locally or exfiltrating it, functioning as a logon-time keylogger with a legitimate-looking UI surface.
- Serve as a logon-time execution hook in its own right — the provider DLL is loaded and its code runs as part of every logon attempt on the machine, independent of whether that attempt succeeds.

This is a genuinely different attack surface from the LSA packages covered above: LSA packages run inside `lsass.exe` after credentials reach the LSA for validation, while a malicious Credential Provider intercepts credentials at the UI layer, before they're even submitted for validation — the plaintext-capture angle is stronger here precisely because there's no hashing or protocol-specific transform between what the user types and what the provider DLL sees.

### PowerShell

Enumerate every registered Credential Provider, resolve its backing DLL, and check its signature:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' | ForEach-Object {
    $clsid = $_.PSChildName
    $name  = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).'(default)'
    $dll   = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32" -ErrorAction SilentlyContinue).'(default)'
    [PSCustomObject]@{
        CLSID   = $clsid
        Name    = $name
        Dll     = $dll
        Signed  = if ($dll -and (Test-Path $dll)) { (Get-AuthenticodeSignature $dll).Status } else { 'NOT FOUND' }
    }
}
```

Cross-reference the CLSID list against a known-good baseline (a clean install of the same Windows build/edition) — the built-in Password provider and PIN/biometric providers that ship with Windows are well-documented; anything beyond that set on a standard corporate laptop is worth a second look:

```powershell
# Compare against a saved baseline list of expected CLSIDs for this build
$baseline = Get-Content C:\hunt\credprov_baseline.txt
$current  = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers' | Select-Object -ExpandProperty PSChildName
Compare-Object $baseline $current
```

## Event Log Evidence

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4610 | An authentication package has been loaded by the Local Security Authority | Logged for legitimate package loads at boot; an unexpected package name here (or one appearing outside the normal boot window) is a direct signal |
| Security log | 4611 | A trusted logon process has been registered with the Local Security Authority | Legitimate registrations (`winlogon.exe`, `services.exe`) occur at boot with `Subject\Security ID = SYSTEM`; flag registrations where the subject isn't SYSTEM or that occur well outside the boot window |
| Security log | 4614 | A notification package has been loaded by the Security Account Manager | Direct load-event evidence for `Notification Packages` entries, including password filter DLLs |
| Security log | 4657 | A registry value was modified | Requires **non-default "Audit Registry" auditing plus a SACL on the `Lsa` key** — without both configured in advance, no event exists for the underlying registry write that added the package name |
| Application log | 1000 | Application Error (process crash) | Correlate an `lsass.exe` crash against a nearby `Lsa` key modification — see the SSP/AP interface-requirement discussion above |

🔴 **4610/4611/4614 are logged as part of normal boot activity for every legitimate package already present — they are not "absence means nothing happened" events the way 4657 is.** The hunting value is in reviewing the *full* set of packages these events report for anything unrecognized, not in whether the events exist at all.

## Red Flags Specific to LSA Packages & Credential Providers

- **A `Security Packages`, `Authentication Packages`, or `Notification Packages` entry that isn't part of the well-known Microsoft baseline set.** Because these lists are short and change rarely on a legitimate host, a genuinely new entry is close to a default-positive rather than one signal among several — verify it against a known-good baseline for the same OS build before ruling it benign.
- **A listed package name with no corresponding DLL in `System32`, or one that fails Authenticode verification.** The registry entry and the on-disk file are two independently-checkable artifacts; a mismatch between what's listed and what actually exists (or its trust status) is a strong tell on its own.
- **`OSConfig\Security Packages` out of sync with the primary `Lsa\Security Packages` value.** Legitimate changes typically update both; a discrepancy suggests either incomplete malicious tooling or a change made through a path that didn't touch both locations consistently.
- **An `lsass.exe` crash (Application log 1000) occurring close in time to an LSA package registry change.** A malformed injected SSP/AP DLL is a plausible cause — treat the crash and the registry timeline as a single correlated event, not two separate findings.
- **A Credential Provider CLSID with no corresponding, well-documented Microsoft or known-vendor provider.** Given how rarely legitimate software adds new Credential Providers on a standard endpoint, an unrecognized CLSID pointing at an unsigned or unfamiliar DLL is worth escalating quickly — this is a logon-time credential-capture surface, not just a persistence mechanism.
- **Any `Notification Packages` entry that doesn't map to known, sanctioned password-policy software in the environment.** Because this value has a legitimate, common use case (password filters), don't treat mere non-emptiness as the signal — verify each entry individually.

## Tooling

| Tool | Use |
|---|---|
| **Direct registry read (`Get-ItemProperty`)** | The fastest live check — all three LSA package lists and the Credential Providers key are flat, readable values with no special parser required |
| **Autoruns** (Sysinternals) | Its "Winlogon" and "LSA Providers"/security-provider tabs surface `Authentication Packages`, `Notification Packages`, `Security Packages`, and Credential Providers alongside every other autostart mechanism, with signature and VirusTotal cross-reference |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SYSTEM\CurrentControlSet\Control\Lsa` (and `OSConfig`) and `SOFTWARE\...\Authentication\Credential Providers` when working from an acquired hive rather than a live host |
| **Mimikatz-adjacent SSP research/detection references** | Understanding legitimate SSP/AP implementation requirements (SPI entry points) is useful background for judging whether a suspect DLL is a plausible, functional package versus a hastily-written stub likely to crash `lsass.exe` |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Unrecognized entry in `Authentication Packages` / `Notification Packages` / `Security Packages` | These lists are short and Microsoft-populated on an unmodified host — a new entry is close to a default-positive |
| Listed package name with no matching `System32` DLL, or an unsigned/untrusted one | Direct mismatch between the registry claim and what's actually on disk |
| `OSConfig\Security Packages` differs from the primary `Lsa\Security Packages` value | Legitimate changes typically keep both in sync — a mismatch suggests incomplete or unusual tooling |
| `lsass.exe` crash (Application log 1000) near an LSA package registry change | A malformed injected SSP/AP DLL is a plausible cause — correlate the two rather than treating them separately |
| Credential Provider CLSID with no known-vendor provenance | Direct logon-time credential-capture surface, not just persistence — escalate quickly |
| Security log 4657 present for the `Lsa` key | Direct evidence of the write — requires non-default auditing plus a SACL, so absence proves nothing |
| 4610/4611/4614 reporting a package name outside the expected baseline | Boot-time load evidence corroborating a registry-side finding |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics for the `SYSTEM` and `SOFTWARE` hives | Registry Forensics Fundamentals (note 04) |
| The other logon-time hijack surface — Winlogon Shell/Userinit and Terminal Services InitialProgram | Winlogon & Terminal Services Shell Hijacking |
| Pre-authentication, debugger-based code execution on the logon screen itself | Image File Execution Options (IFEO) |
| Service-based persistence and its own SYSTEM-privilege scoping logic | Services |
| First/last-seen evidence and hash identity of a dropped SSP/AP/Credential Provider DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |

## Resources

- MITRE ATT&CK T1547.005 (Boot or Logon Autostart Execution: Security Support Provider) — https://attack.mitre.org/techniques/T1547/005/
- MITRE ATT&CK T1547.002 (Boot or Logon Autostart Execution: Authentication Package) — https://attack.mitre.org/techniques/T1547/002/
- MITRE ATT&CK T1556.002 (Modify Authentication Process: Password Filter DLL) — https://attack.mitre.org/techniques/T1556/002/
- Credential Providers — Attack = Unmapped; no confident current ATT&CK sub-technique ID covers malicious Credential Provider registration specifically
- Microsoft Learn, Installing and Registering a Password Filter DLL — https://learn.microsoft.com/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll
- Microsoft Learn, Credential Providers in Windows — https://learn.microsoft.com/windows/win32/secauthn/credential-providers-in-windows
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
