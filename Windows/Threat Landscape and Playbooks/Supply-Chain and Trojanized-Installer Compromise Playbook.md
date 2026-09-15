# Supply-Chain and Trojanized-Installer Compromise Playbook

The scenario this playbook owns: a trusted vendor's installer, update package, or build pipeline was compromised, and the malicious code rode that trust relationship onto your estate through a channel that looked completely legitimate — an auto-update, a signed installer from the vendor's own download page, a routine patch cycle. [`Windows Malware and Threat Landscape`](<Windows Malware and Threat Landscape.md#supply-chain-and-trusted-software-abuse>) already frames this narratively as a landscape category; this note is the investigative sequence that category was missing. Nothing here is exotic once the vector is known — detection converges on the same execution-evidence and persistence artifacts every other playbook in this folder uses ([`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>), [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>)) — but the *hard part is different*: recognizing that a trusted, often validly-signed binary is the vector at all, usually only surfacing from a vendor advisory or threat-intel report rather than from anything anomalous the host itself shows you.

> 🔴 **A valid Authenticode signature does not mean the binary is clean — it means the vendor's certificate signed it, and if the vendor's build pipeline was compromised, the attacker's code inherits that same valid signature.** SolarWinds, 3CX, and CCleaner are the reference cases: in each, the malicious binary was legitimately signed, distributed through the vendor's own official channel, and passed every signature check a defender would normally trust. Don't clear a binary because `Get-AuthenticodeSignature` returns `Valid` — cross-reference the specific file hash against the vendor's advisory or a known-good build list instead.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Confirm the Compromise](#confirm-the-compromise)
- [Scope the Exposure](#scope-the-exposure)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Attack Chain

A vendor's build pipeline, update infrastructure, or code-signing certificate is compromised upstream, outside your environment entirely → the attacker inserts malicious code into an otherwise-legitimate installer or update package, which is then signed by the vendor's own (uncompromised, or itself-stolen) certificate → the trojanized package is distributed through the vendor's normal, trusted channel — auto-update, official download page, patch-management feed — to every customer who installs or updates during the compromise window → the payload executes with whatever privilege the legitimate software normally runs at (often high, if the product is a monitoring/management/security tool) → this typically lands as a broad, often dormant foothold across many hosts, not a targeted single-host compromise → the attacker later selectively activates a second-stage payload only on the small subset of footholds that turn out to be high-value targets, leaving the rest dormant. This selective, delayed activation is what distinguishes a supply-chain compromise from ordinary malware — most infected hosts may never see a second stage at all, which is exactly why fleet-wide scoping (not just the hosts already showing symptoms) matters here more than in most other playbooks.

## Quick Triage

The trigger for this playbook is almost always external — a vendor advisory, a threat-intel report, or an IOC list naming a specific affected version/hash — rather than an internal anomaly. Start from that IOC, not from host symptoms.

```powershell
# Is the affected product/version installed on this host at all - registry Uninstall keys are the fastest check
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object DisplayName -match '<vendor_product_name>' | Select-Object DisplayName, DisplayVersion, InstallDate, InstallLocation

# Does the installed binary's hash match a known-bad (or known-good) hash from the vendor advisory
Get-FileHash '<InstallLocation>\<binary>.exe' -Algorithm SHA256

# Signature check - a Valid result does NOT clear it (see the callout above); it's a data point, not a verdict
Get-AuthenticodeSignature '<InstallLocation>\<binary>.exe' | Select-Object Path, Status, SignerCertificate

# Amcache is the fleet-wide pivot point: its SHA-1 hash lets you match the exact affected build across
# every host, independent of install path or renamed files (note 06's Amcache.md)
Get-ChildItem 'C:\Windows\AppCompat\Programs\Amcache.hve' -ErrorAction SilentlyContinue
```

## Confirm the Compromise

A hash match against a vendor advisory or threat-intel IOC list is the strongest confirmation available — much stronger than anything derivable from host behavior alone, since the whole point of this vector is that it doesn't look anomalous.

1. **Match the installed binary's hash against the vendor advisory's published affected-version hash list.** This is definitive where available — a signed binary matching a known-trojanized hash is compromised regardless of what its signature check says.
2. **If no hash list is published, or the binary was patched/updated since**, check Amcache (note 06) for the SHA-1 of the binary as it existed *during the disclosed compromise window* — Amcache's persistence-independent-of-the-file-still-existing property (already the core reasoning in the Ransomware Playbook's Amcache section) matters here too, since the vendor's own subsequent clean update may have already overwritten the trojanized file on disk.
3. **Check the process tree for anomalous children spawned by the legitimate binary or its installer/updater process**, shortly after install or update — a monitoring agent or update service spawning `cmd.exe`, `powershell.exe`, or `rundll32.exe` with no corresponding legitimate feature is the loader-stage tell:

```powershell
Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -in (Get-Process -Name '<vendor_process_name>').Id } |
    Select-Object Name, ProcessId, CommandLine, CreationDate
```

4. **Check for a companion malicious DLL sitting alongside the legitimate binary** — some supply-chain implants ship as a second, non-vendor DLL loaded by the legitimate binary at startup, distinct from a classic search-order DLL hijack (note 10's DLL Hijacking.md) but detected the same way: an unsigned or oddly-timestamped DLL in an otherwise fully vendor-signed application directory.

```powershell
Get-ChildItem '<InstallLocation>\*.dll' | Get-AuthenticodeSignature | Where-Object Status -ne 'Valid' |
    Select-Object Path, Status
```

**Key evidence artifact to check first:** the installed binary's hash against the vendor advisory's IOC list; Amcache if the on-disk file has since been overwritten by a legitimate update.

**What a positive finding looks like in practice:** an installed binary or DLL whose hash exactly matches a vendor-published IOC, or a validly-signed vendor process spawning an unexplained child process shortly after an install/update event that falls inside the disclosed compromise window.

## Scope the Exposure

Unlike most playbooks in this folder, scoping here is not "which hosts show symptoms" — it's "which hosts installed or updated during the compromise window," because most of them will show nothing at all until/unless second-stage activation happens.

```powershell
# Fleet-wide inventory of the affected product/version, across every host - the honest scope,
# independent of which hosts are visibly acting up
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object DisplayName -match '<vendor_product_name>' | Select-Object DisplayName, DisplayVersion, InstallDate
} | Where-Object { $_.InstallDate -ge '<window_start>' -and $_.InstallDate -le '<window_end>' }

# Narrower sub-scope: hosts that ALSO show the second-stage activation tell (anomalous child process,
# unsigned companion DLL, or a beacon IOC below) - these are the ones that matter most urgently
```

Report both numbers separately when this goes to leadership: total hosts with the affected version installed during the window (the honest exposure), and the smaller subset showing actual second-stage activation evidence (the active compromise). Conflating the two either understates urgency for the active subset or overstates panic for the dormant majority.

## Timeline

```powershell
# Install/update timestamp vs the vendor's disclosed compromise window
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<ProductKey>').InstallDate

# First-execution evidence for the binary itself (Prefetch creation time / run count, note 06)
Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" | Where-Object Name -match '<VENDOR_BINARY_NAME>'

# First anomalous child-process timestamp, if found in Confirm the Compromise step 3 - this is
# the second-stage activation moment, distinct from the (often much earlier, dormant) install date
```

Bracket the case as: install/update date → vendor-disclosed compromise window (confirms exposure) → first anomalous child-process or beacon timestamp, if any (confirms activation). A long gap between install and activation is itself informative — it's the dormant-foothold pattern this vector is known for, not evidence the finding is stale or irrelevant.

## Eradication

```powershell
# 1. Uninstall the trojanized version, or apply the vendor's clean patched version per their advisory -
#    do not simply let auto-update "fix itself" without confirming which build actually lands
Invoke-Command -ComputerName (Get-Content C:\hunt\affected_hosts.txt) -ScriptBlock {
    Start-Process msiexec.exe -ArgumentList '/x <ProductGUID> /qn' -Wait
}

# 2. Remove any confirmed second-stage implant/companion DLL identified in Confirm the Compromise step 4
Invoke-Command -ComputerName (Get-Content C:\hunt\active_hosts.txt) -ScriptBlock {
    Remove-Item '<companion_dll_path>' -Force -ErrorAction SilentlyContinue
}

# 3. Block known C2 IOCs from the vendor advisory / threat-intel report at DNS/firewall/proxy,
#    fleet-wide, not just on confirmed-active hosts
```

Disable-before-delete (note 21) still applies to any persistence mechanism (scheduled task, service, Run key — note 10) the second-stage payload added on its own, distinct from the vendor product itself.

## Credential Reset

Supply-chain implants frequently target the elevated access the compromised product itself carries — a monitoring or management tool with broad network visibility, or stored service-account/API credentials it uses to reach other systems (the SolarWinds Orion case is the reference example: broad network-management credentials plus a path to forged SAML tokens).

```powershell
# Rotate any credential/API key/service account the affected product itself stores or uses to authenticate outward
# - check the product's own credential store/config first, not just domain accounts
```

Rotate: the affected product's own service-account or API credentials; any domain credentials cached on hosts where second-stage activation was confirmed; certificates or tokens the product uses for its own management-plane authentication, since a compromised management tool is a direct path to the credentials/tokens it was trusted to hold.

## Fleet Hunt

```powershell
# Hash sweep for the exact trojanized build, fleet-wide, independent of which hosts already flagged
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-FileHash '<InstallLocation>\<binary>.exe' -Algorithm SHA256 -ErrorAction SilentlyContinue
} | Where-Object Hash -eq '<known_bad_sha256>'

# Same sweep against Amcache where the on-disk file may have already been overwritten by a later clean update
# (note 06's Amcache.md hash-matching workflow)

# C2 IOC sweep from the vendor advisory / threat-intel feed
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.txt) -ScriptBlock {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object RemoteAddress -in @('<C2_IP_1>', '<C2_IP_2>')
}
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| Landscape framing of this threat category | [`Windows Malware and Threat Landscape`](<Windows Malware and Threat Landscape.md#supply-chain-and-trusted-software-abuse>) |
| Amcache SHA-1 fleet-wide hash matching, Prefetch first-execution timestamps, ShimCache corroboration | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| Persistence mechanisms a second-stage payload may add (scheduled task, service, Run key, WMI subscription) | [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>) |
| Companion-DLL detection technique (distinct root cause, same signature-check method) | [`10 - Persistence Mechanisms/DLL Hijacking.md`](<../10 - Persistence Mechanisms/DLL Hijacking.md>) |
| The threat-intel feedback loop that typically originates this playbook's trigger (vendor advisory → IOC hunt) | [`20 - Threat Hunting Methodology and Intelligence`](<../20 - Threat Hunting Methodology and Intelligence.md>) |
| What second-stage activation escalates into once a dormant foothold is actually used | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) |
| Disable-before-delete containment discipline, credential-reset sequencing | [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>) |
| Fleet-wide baselining and post-fix return-to-known-good-state | [`22 - Enterprise Management and Baseline`](<../22 - Enterprise Management and Baseline.md>) |

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| Installed binary hash matches a vendor advisory's or threat-intel report's known-bad hash | Definitive confirmation, independent of signature validity |
| Valid Authenticode signature on a binary from a vendor with a disclosed pipeline/cert compromise | Does NOT clear the binary — the compromised cert signs the attacker's code too |
| Vendor process/service spawning an unexplained child process (`cmd`, `powershell`, `rundll32`) shortly after install/update | Loader-stage / second-stage activation tell |
| Unsigned or oddly-timestamped DLL sitting in an otherwise fully vendor-signed application directory | Companion-implant pattern, distinct from classic DLL hijacking but detected the same way |
| Install/update timestamp falling inside a vendor-disclosed compromise window | Confirms exposure — doesn't by itself confirm activation |
| Long gap between install date and any anomalous activity | The expected dormant-foothold pattern for this vector, not evidence against the finding |
| Elevated service-account/API credential used by the affected product, resident on many hosts | The high-value target of this vector — often more consequential than the initial foothold itself |
| Outbound connection to a C2 IOC from the vendor advisory/threat-intel feed | Confirmed second-stage activation on that specific host |

## Resources

- MITRE ATT&CK **T1195** (Supply Chain Compromise) — https://attack.mitre.org/techniques/T1195/
- MITRE ATT&CK **T1195.002** (Compromise Software Supply Chain) — https://attack.mitre.org/techniques/T1195/002/
- MITRE ATT&CK **T1553.002** (Subvert Trust Controls: Code Signing) — https://attack.mitre.org/techniques/T1553/002/
- MITRE ATT&CK **T1554** (Compromise Client Software Binary) — https://attack.mitre.org/techniques/T1554/
- CISA/FireEye SolarWinds Orion supply-chain compromise reporting — consulted generically for the reference-case pattern (broad dormant foothold, selective second-stage activation, Golden SAML), not fabricated to a specific advisory page
