# Safe Mode, BootExecute & Network Provider Order Persistence

This note groups three unrelated-on-the-surface techniques under one heading because they share a single defining trait: each one tampers with a narrow, low-level piece of system configuration that runs earlier, more privileged, or in more contexts than the mechanisms covered elsewhere in this family, and each is correspondingly a very high-confidence finding precisely because the legitimate configuration space around it is so small and stable. None of these three is a place where dozens of legitimate third-party entries are expected to accumulate the way Run keys or services are — a deviation here is rarely noise.

**SafeBoot persistence** is the odd one out functionally: rather than trying to survive a reboot, it specifically targets surviving the one remediation step an analyst or user is likely to reach for *in response* to a compromise — booting into Safe Mode to strip away as much running software as possible, including, ideally, the malware and anything interfering with removing it. A service or driver listed under the `SafeBoot` registry keys keeps running anyway, defeating that exact defensive move.

**BootExecute tampering** targets the earliest practical code-execution point in the entire Windows startup sequence available to a persistence technique — before the kernel has finished initializing much of anything, before most drivers have loaded, and certainly before any user-mode security tooling has had a chance to start. Nothing else in this persistence family runs this early.

**Network Provider Order hijacking** is different in kind from the other two — it's not about *when* code runs but about inserting a malicious DLL into a call chain that legitimate Windows components (and every application doing UNC-path or network-resource resolution) will invoke on the attacker's behalf, including, notably, cleartext credential material passed through the logon-notification path.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table.

> 🔴 **All three techniques in this note have essentially no reason to vary from a narrow, well-known default state.** Unlike Run keys or services, where dozens of legitimate entries are expected, `SafeBoot\Minimal`/`SafeBoot\Network` should list only the handful of core boot-critical drivers and services Windows itself installs there, `BootExecute` should read exactly `autocheck autochk *`, and `NetworkProvider\Order` should list only the built-in providers present on that OS SKU. Any addition to any of the three is worth investigating on its own merits — the finding here is closer to "this value exists at all" than the "is this specific entry suspicious" judgment call the rest of this family usually requires.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [SafeBoot Persistence](#safeboot-persistence)
- [BootExecute Tampering](#bootexecute-tampering)
- [Network Provider Order Hijack](#network-provider-order-hijack)
- [Red Flags Specific to This Note](#red-flags-specific-to-this-note)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry-read triage against all three keys — every value here is small and stable enough that a full dump is cheap to review by eye.

```powershell
# Full dump of both SafeBoot subkeys - anything here beyond core Windows drivers/services is worth reviewing
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal' | Select-Object PSChildName
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network' | Select-Object PSChildName

# BootExecute - flag anything beyond the single expected default entry
$bootExec = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute).BootExecute
if (($bootExec -join ';') -ne 'autocheck autochk *') { Write-Output "NON-DEFAULT BootExecute: $($bootExec -join '; ')" }

# NetworkProvider order - flag anything beyond the standard built-in providers
$order = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order').ProviderOrder
$known = @('LanmanWorkstation', 'RDPNP', 'webclient', 'LanmanServer', 'Fax')
($order -split ',') | Where-Object { $_ -and $_ -notin $known }

# Cross-reference each non-standard entry in ProviderOrder against its own service key and DLL
$order = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order').ProviderOrder
($order -split ',') | ForEach-Object {
    $dll = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$_\NetworkProvider" -ErrorAction SilentlyContinue).ProviderPath
    if ($dll) { [PSCustomObject]@{ Provider = $_; ProviderPath = $dll } }
}

# Cross-reference every SafeBoot-listed service/driver against its own live registration - confirm each entry is a real, resolvable service
'Minimal', 'Network' | ForEach-Object {
    $mode = $_
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" | ForEach-Object {
        $svc = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($_.PSChildName)" -ErrorAction SilentlyContinue
        [PSCustomObject]@{ SafeBootMode = $mode; ServiceName = $_.PSChildName; ImagePath = $svc.ImagePath }
    }
}
```

## SafeBoot Persistence

```
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\<ServiceName>
HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\<ServiceName>
```

Windows determines which services and drivers are allowed to start when the system boots into Safe Mode by checking these two keys. `Minimal` corresponds to standard Safe Mode (no networking); `Network` corresponds to Safe Mode with Networking. Each subkey is simply the short service/driver name (matching the corresponding `SYSTEM\CurrentControlSet\Services\<ServiceName>` key), with a default value of `Service` or `Driver` indicating the entry's type — the presence of the subkey is itself the whitelist entry; Windows consults these lists during Safe Mode boot and skips starting anything not listed, regardless of that service's own `Start` value under its normal `Services` key.

🔴 **This is fundamentally a defender-countermeasure technique, not a stealth technique.** Adding an entry here doesn't hide the malware or make it harder to find in a normal boot — it specifically defeats the *remediation* step of booting into Safe Mode to strip away interfering or actively-defending-itself malware. An analyst who boots a suspected-compromised host into Safe Mode expecting a clean baseline to work from, only to find the same malicious service or driver still running, should immediately suspect a `SafeBoot` entry rather than assuming Safe Mode failed to isolate the threat. Because the legitimate population of `SafeBoot`-listed entries is small and Microsoft-curated, any third-party or unrecognized name here is worth treating as a serious finding on its own.

### PowerShell

Enumerate both Safe Mode variants and check each listed name against the actual `Services` key it corresponds to, since the `SafeBoot` entry alone doesn't show what the service actually does:

```powershell
'Minimal', 'Network' | ForEach-Object {
    $mode = $_
    Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode" | ForEach-Object {
        $name = $_.PSChildName
        $svc = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$name" -ErrorAction SilentlyContinue
        [PSCustomObject]@{ SafeBootMode = $mode; ServiceName = $name; ImagePath = $svc.ImagePath; ObjectName = $svc.ObjectName }
    }
}
```

Compare the current host's `SafeBoot` entries against a known-clean baseline from a same-build reference system — because this population changes rarely and only with OS updates or specific driver/AV installs, a diff is usually decisive:

```powershell
Compare-Object `
    (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal' | Select-Object -ExpandProperty PSChildName) `
    (Get-ChildItem '\\<baseline-host>\HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal' | Select-Object -ExpandProperty PSChildName)
```

## BootExecute Tampering

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute
```

`BootExecute` is a multistring (`REG_MULTI_SZ`) value read by the Session Manager Subsystem (`smss.exe`) — the very first user-mode process Windows starts, before `winlogon.exe`, before `services.exe`, before the graphical shell, before essentially all security tooling has any chance to load. Its default value is exactly `autocheck autochk *`, the invocation that performs the disk-integrity check on a volume flagged dirty at shutdown. `smss.exe` executes every entry listed in `BootExecute` in sequence, and because this happens so early in the boot chain, anything added here runs with a level of environmental primacy nothing else in this persistence family can match.

🔴 **This is the single narrowest, most stable value covered anywhere in the Persistence Mechanisms family.** There is essentially no legitimate reason for a third-party product to add an entry here — the only expected content, on effectively any Windows install, is the single default string. Any deviation is a very high-confidence red flag, not a "worth a second look" finding the way most entries in this family are, precisely because the space of legitimate variation is close to zero and the execution timing is uniquely privileged.

### PowerShell

Read the value directly and diff it against the known-good default — the entire check for this technique in two lines:

```powershell
$bootExec = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name BootExecute).BootExecute
if (($bootExec -join ';') -ne 'autocheck autochk *') { Write-Warning "Non-default BootExecute entries present: $($bootExec -join '; ')" }
```

When working from an offline `SYSTEM` hive, resolve `CurrentControlSet` to the correct literal `ControlSetNNN` first — see Registry Forensics Fundamentals (note 04) for that resolution mechanic — before reading the equivalent `Session Manager\BootExecute` path in the acquired hive.

## Network Provider Order Hijack

```
HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order  (ProviderOrder value)
HKLM\SYSTEM\CurrentControlSet\Services\<ProviderName>\NetworkProvider  (per-provider registration, one per name listed in ProviderOrder)
```

Windows resolves network resource requests — UNC path access, mapped-drive authentication, and other Multiple Provider Router (MPR)-mediated operations — by walking through a chain of registered network providers in the order listed in the `ProviderOrder` value, a comma-separated string of provider names (the built-in providers on a typical Windows host include `LanmanWorkstation` for SMB, `RDPNP` for RDP-redirected drives, and `webclient` for WebDAV). `ProviderOrder` itself holds only names, not paths — each name is resolved to an actual DLL by looking up `SYSTEM\CurrentControlSet\Services\<ProviderName>\NetworkProvider`, whose `ProviderPath` value points at the DLL Windows loads to service that provider's requests.

An attacker registers a new service key with its own `NetworkProvider\ProviderPath` pointing at a malicious DLL, then appends (or inserts) that provider's name into `ProviderOrder`. Once registered, the malicious DLL is loaded into the provider chain and receives the same calls every legitimate provider does — most significantly, during interactive logon, `winlogon.exe` hands credentials to `mpnotify.exe`, which in turn notifies every registered network provider of the logon event via each provider's `NPLogonNotify()` export, passing along the credential material in the process. A malicious provider implementing that export receives — and can capture — user credentials in cleartext on every logon, in addition to intercepting whatever ordinary network-resource resolution calls route through the provider chain. The load trigger for the malicious DLL isn't a boot or logon *event* in the way a service or Run key fires — it's any process (starting with `mpnotify.exe`/`winlogon.exe` at logon, but potentially any process performing MPR-mediated network resource access) walking the provider chain and loading each registered provider's DLL as part of that walk.

### PowerShell

Read the current provider order and flag any name beyond the small set of built-in Windows providers:

```powershell
$order = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order').ProviderOrder
$known = @('LanmanWorkstation', 'RDPNP', 'webclient', 'LanmanServer', 'Fax')
($order -split ',') | Where-Object { $_ -and $_ -notin $known }
```

For each provider name in the order, resolve it back to its registered DLL — this is the artifact that actually matters, since `ProviderOrder` alone is just a list of names:

```powershell
($order -split ',') | Where-Object { $_ } | ForEach-Object {
    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$_\NetworkProvider" -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Provider = $_; ProviderPath = $reg.ProviderPath; Name = $reg.Name }
}
```

Verify the Authenticode signature of any provider DLL that resolves outside the expected `System32` location, exactly as with a suspicious service binary elsewhere in this family:

```powershell
Get-AuthenticodeSignature '<ResolvedProviderPath>' | Select-Object Path, Status, SignerCertificate
```

## Red Flags Specific to This Note

- **Any unrecognized service/driver name under `SafeBoot\Minimal` or `SafeBoot\Network`.** The legitimate population here is small, Microsoft- and vendor-security-product-curated, and changes rarely — a name that doesn't correspond to a well-known Windows component or an installed security product deserves the same scrutiny as an unfamiliar Auto-start service, but with a higher prior of suspicion given how narrow the legitimate baseline is.
- **A host that keeps running malware after being booted into Safe Mode specifically to remediate it.** This is the practical, in-the-field symptom of `SafeBoot` abuse — if a Safe Mode boot was performed as a defensive step and the expected clean-slate result didn't materialize, check `SafeBoot\Minimal`/`Network` before assuming the boot itself failed.
- **Any entry in `BootExecute` beyond the single default `autocheck autochk *` string.** Given how early and how privileged this execution point is — ahead of virtually every security control on the host — treat any addition as presumptively malicious pending strong evidence otherwise, rather than the "investigate before judging" posture used for noisier locations elsewhere in this family.
- **`ProviderOrder` listing a provider name with no corresponding, or a suspicious, `NetworkProvider\ProviderPath` registration.** A name added to the order string with no real service backing it, or one whose `ProviderPath` resolves outside `System32`, is the setup step for credential interception via `NPLogonNotify()`.
- **A network provider DLL that isn't signed, or is signed by an unrecognized publisher, positioned early in the provider order.** Position in the chain affects how early the malicious provider gets a chance to intercept a given request relative to the legitimate providers — an attacker aiming for reliable credential capture has an incentive to place their provider ahead of, not after, `LanmanWorkstation`.

## Tooling

| Tool | Use |
|---|---|
| `Get-ItemProperty` / `Get-ChildItem` (native PowerShell) | Direct read of all three registry locations covered in this note — no third-party tool required for the core hunt |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `SafeBoot`, `Session Manager\BootExecute`, and `NetworkProvider\Order` when working from an acquired `SYSTEM` hive rather than a live host — see Registry Forensics Fundamentals (note 04) for `CurrentControlSet` resolution |
| **Autoruns** (Sysinternals) | Does not have a dedicated tab for any of the three techniques in this note — noted explicitly because analysts should not assume Autoruns' broad autostart coverage extends here; these require a manual, targeted registry check |
| `Get-AuthenticodeSignature` | Verifying the code-signing status of a resolved `NetworkProvider\ProviderPath` DLL or a `SafeBoot`-listed driver/service binary |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Unrecognized entry under `SafeBoot\Minimal` or `SafeBoot\Network` | Small, stable, Microsoft-curated population — a deviation is a high-confidence finding, and one specifically aimed at surviving the analyst's own remediation step |
| Malware continues running after a Safe Mode boot intended to remediate it | Practical field symptom of SafeBoot persistence — check the registry keys before assuming Safe Mode failed |
| Any entry in `BootExecute` beyond the single default `autocheck autochk *` | Executes earlier and more privileged than virtually any other mechanism in this family — near-zero legitimate variation |
| `ProviderOrder` entry with no or a suspicious `NetworkProvider\ProviderPath` registration | Setup for credential interception via `NPLogonNotify()` or network-resource-resolution interception |
| Unsigned or unrecognized-publisher DLL registered as a network provider, especially positioned early in the order | Determines how reliably the malicious provider intercepts requests ahead of legitimate providers |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all Persistence Mechanisms notes | Autostart (Run/RunOnce) Keys |
| Registry hive structure and `CurrentControlSet` resolution used to read `SYSTEM`-hive values correctly, on and offline | Registry Forensics Fundamentals (note 04) |
| Service registry structure (`ImagePath`, `Start`, `ObjectName`) referenced when a `SafeBoot` entry or network provider resolves to a `Services` key | Services |
| First/last-seen and hash identity of a planted `SafeBoot` driver/service binary or network-provider DLL | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of a `BootExecute`-launched program | Prefetch.md (note 06) |

## Resources

- SafeBoot service/driver persistence — **Unmapped** (no dedicated MITRE ATT&CK sub-technique ID for this specific mechanism)
- BootExecute tampering — **Unmapped** (documented as an example within T1547.001's broader coverage of Registry Run Keys/Startup Folder, but has no dedicated sub-technique ID of its own)
- Network Provider Order hijack — **Unmapped** for the general resource-resolution interception described here; MITRE ATT&CK T1556.008 (Modify Authentication Process: Network Provider DLL) covers the closely related credential-interception use of this same mechanism via `NPLogonNotify()` — https://attack.mitre.org/techniques/T1556/008/
- MITRE ATT&CK T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) — mentions `BootExecute` as a documented example — https://attack.mitre.org/techniques/T1547/001/
- Microsoft, Authentication Registry Keys — https://learn.microsoft.com/windows/win32/secauthn/authentication-registry-keys
- Microsoft, BCDLibrary — Safeboot element — https://learn.microsoft.com/previous-versions/windows/desktop/bcd/bcdlibrary-safeboot
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
