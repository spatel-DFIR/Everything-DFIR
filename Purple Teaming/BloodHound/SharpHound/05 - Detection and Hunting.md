# BloodHound — SharpHound — Detection and Hunting

## Contents
- [Hunting Priority — Ranked by Evasion Survivability](#hunting-priority--ranked-by-evasion-survivability)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target — Domain Controller (Phase 1)](#hunting-on-target--domain-controller-phase-1)
- [Hunting on Target — Member Computers (Phase 2)](#hunting-on-target--member-computers-phase-2)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Ranked by Evasion Survivability

SharpHound exposes more footprint-shaping options than most tools this repo documents (`--Stealth`, `-c DCOnly`, `--Throttle`/`--Jitter`, `--ComputerFile`, `--RandomFileNames`, `--MemCache`, and the fileless `Invoke-BloodHound` loading path) — no single hunt is reliable against all of them at once. Ranked strongest-survivor first, verified against how each flag's logic actually works in source (`01 - Overview.md`), not assumed:

| Rank | Signal | What defeats it | What survives it |
|---|---|---|---|
| 1 (strongest) | **DC-side LDAP volumetric anomaly** — object-count-returned per session/query far above baseline | Nothing in SharpHound's own flag set — **Phase 1's LDAP sweep has no throttle option at all** (`--Throttle`/`--Jitter` only apply to Phase 2's per-computer requests, verified in source). Only a manually `--LDAPFilter`/`--DistinguishedName`-narrowed run reduces this, and even then the narrowed volume is still anomalous relative to that scope | `--Stealth`, `-c DCOnly`, `--Throttle`/`--Jitter`, `--RandomFileNames`, `--MemCache`, and the fileless loading path — **all of them**, since every one of these leaves Phase 1 untouched |
| 2 | **Event 1644 with `SDFlags=0x5`** on the DC | Not logging it in the first place (Field Engineering diagnostics is **off by default** — this is a logging-configuration gap, not an operator evasion choice) | Identical survival profile to Rank 1 — this is Rank 1's evidence made precise and attributable (exact filter, exact control value) rather than just volumetric |
| 3 | **SAMR/SRVSVC/LSARPC network fan-out** (Sysmon 18, Zeek `dce_rpc.log`) — one source touching many computers in a window | `-c DCOnly` (Phase 2 never runs at all) eliminates this entirely; `--Stealth` reduces it (drops `LocalAdmin`/`RDP`/`DCOM`/`PSRemote`, keeps `Session` if requested); heavy `--Throttle`+`--Jitter` combined with `--Loop` spreads the same total connection count across a much wider window, requiring a longer observation baseline to catch as anomalous rather than defeating it outright | `--RandomFileNames`, `--MemCache`, fileless loading — none of these touch network behavior |
| 4 | **MDI/EDR behavioral reconnaissance alert** (volumetric SAMR/LDAP profiling) | Narrow `--ComputerFile` scoping + aggressive throttling that stays under the product's learning-period baseline; a fileless or recompiled binary doesn't defeat this since it's behavioral, not signature-based | Binary renaming, recompilation, obfuscation, the fileless path — all irrelevant to a behavior-based alert |
| 5 | **Collecting-host Sysmon 1 / Security 4688** process-creation command line | **Fully defeated by the fileless `Invoke-BloodHound` path** — no `SharpHound.exe` process exists to log, unless PowerShell ScriptBlock Logging (4104) is separately enabled and captures the wrapper's own invocation | Nothing about `.exe`-delivered runs evades this — full command line, every flag, always logged if process-creation auditing is on |
| 6 | **Cache file discovery** — `<Base64(MachineGuid)>.bin` on the collecting host | `--MemCache` (never written to disk at all) | **Not affected by `--RandomFileNames`** — verified against source: `ResolveFileName`'s randomization branch only fires for `"json"`/`"zip"` extensions, the cache file's `.bin` path bypasses that function entirely. An operator who remembers to randomize output filenames but forgets `--MemCache` still leaves this exact, predictable filename behind |
| 7 (weakest) | **Output filename pattern hunt** (`*_BloodHound.zip`, `*_users.json`, etc.) and **static AV hash/signature** on `SharpHound.exe` | `--RandomFileNames`, `--NoZip` + custom naming, `--ZipFileName`, recompilation/obfuscation of the binary, or the fileless loading path entirely | Nothing meaningfully — treat a filename/hash-only hunt as a bonus catch against an unsophisticated run, never as primary coverage |

**Practical takeaway:** if only one hunt can be stood up, it's **Rank 1/2** — enabling AD LDAP diagnostic logging (Field Engineering) on Domain Controllers and watching for `SDFlags=0x5`-tagged, high-volume searches. It is the only signal on this list that survives literally every evasion option SharpHound currently exposes.

## Hunting on Source

Applies when the collecting host is in scope for investigation (a suspected compromised workstation/jump box), independent of whether the DC/member-computer evidence in this file's other sections is also available.

```powershell
# Live process check — .exe-delivered runs only
Get-Process -Name SharpHound -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'SharpHound|CollectionMethod|Invoke-BloodHound' }

# Sysmon/Security process-creation history for the binary itself
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'SharpHound' }

# PowerShell ScriptBlock Logging — the ONLY reliable catch for the fileless Invoke-BloodHound path
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Invoke-BloodHound|CollectionMethods' }

# The cache file — survives --RandomFileNames, only defeated by --MemCache (see Rank 6 above)
Get-ChildItem -Path C:\ -Recurse -Include '*.bin' -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -match '^[A-Za-z0-9+/=]{16,}\.bin$' }

# Output loot — JSON/zip, even with randomized names, the internal Newtonsoft-JSON "data"/"meta" 
# structure and BloodHound-schema type names (users/computers/groups/...) fingerprint the content
Get-ChildItem -Path C:\ -Recurse -Include '*.json','*.zip' -ErrorAction SilentlyContinue |
  Select-String -Path {$_.FullName} -Pattern '"CollectionMethods"|"CollectorVersion"' -ErrorAction SilentlyContinue

# PSReadLine console history — persists cmd-line-flag intent even after the process exits
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'SharpHound|Invoke-BloodHound|CollectionMethod'
```

## Hunting on Target — Domain Controller (Phase 1)

```powershell
# Prerequisite check: is Field Engineering / expensive-search diagnostic logging even enabled?
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '15 Field Engineering' -ErrorAction SilentlyContinue

# 1. HIGHEST CONFIDENCE (Rank 1/2): Event 1644 hits carrying the SDFlags=0x5 ACL-collection control
Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=1644} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'SDFlags' -and $_.Message -match '0x5|(?<!\d)5(?!\d)' }

# 2. Volumetric fallback when 1644 logging isn't enabled: 4624 Type-3 logons followed by an
#    outsized downstream LDAP query volume from the same account, in a tight window
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Logon Type:\s*3' } |
  Group-Object { ($_.Message -split "`r`n" | Where-Object {$_ -match 'Account Name:'})[0] } |
  Sort-Object Count -Descending

# 3. perfmon-based LDAP query rate — an environment-specific baseline is required to make this useful
Get-Counter '\NTDS\LDAP Searches/sec' -ErrorAction SilentlyContinue
```

## Hunting on Target — Member Computers (Phase 2)

```powershell
# 1. Sysmon 18 — named-pipe connections to SAMR/SRVSVC/LSARPC, the strongest per-host signal
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=18} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\samr|\\srvsvc|\\lsarpc' }

# 2. IPC$ share access (requires object-access auditing / 5145)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5145} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'IPC\$' -and $_.Message -match 'samr|srvsvc|lsarpc' }

# 3. 4672 (special privileges) correlated with 4624 Type 3 — flags the PRIVILEGED legs
#    specifically (LoggedOn, UserRights), distinct from the unprivileged Session leg
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} -ErrorAction SilentlyContinue

# 4. WMI-Activity log — root\cimv2 / StdRegProv method calls, the NTLMRegistry leg's primary path
Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'StdRegProv|root\\cimv2' }
```

**Fan-out is the pattern to chase, not any single host's evidence in isolation:** group Security 4624/Sysmon 18 hits by **source account across many destination computers** in a short window — one host showing a SAMR query is unremarkable; the same account touching hundreds of hosts back-to-back is not.

## Fleet-Wide Sweep

```powershell
# Domain-wide: correlate 4624 Type-3 logons by source account across ALL domain-joined computers,
# looking for the fan-out shape rather than any single host's activity
$targets = (Get-ADComputer -Filter *).Name

$sweepResults = Invoke-Command -ComputerName $targets -ScriptBlock {
  $logons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'Logon Type:\s*3' }
  $pipeHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=18} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '\\samr|\\srvsvc|\\lsarpc' }
  [PSCustomObject]@{
    Host = $env:COMPUTERNAME
    Type3Logons = ($logons | Measure-Object).Count
    SamrSrvsvcLsarpcPipeHits = ($pipeHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

# Group by source account (requires the raw event objects, not just counts, for real fan-out analysis)
# then flag any single account touching an outlier fraction of the fleet in one sitting.
$sweepResults | Where-Object { $_.SamrSrvsvcLsarpcPipeHits -gt 0 } |
  Export-Csv -Path .\sharphound_phase2_sweep.csv -NoTypeInformation

# DC-side sweep, run against every Domain Controller specifically
$domainControllers = (Get-ADDomainController -Filter *).HostName
Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Directory Service'; Id=1644} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SDFlags' }
} -ErrorAction SilentlyContinue
```

## Remediation

**Capture evidence first** — export the surviving 4624/1644/Sysmon 18 event sequence and, if found, the collecting-host's cache/output files before any cleanup, since a completed collection run means the attacker already has the full attack-path graph regardless of what happens next.

**Close the underlying exposure, not just this incident:**
- SharpHound's entire technique surface is **built on legitimate, by-design AD/Windows read access** — there is no patch or single control that eliminates it. Remediation is about **reducing the value and visibility of what it finds**, not blocking the tool itself.
- Enable **Field Engineering diagnostic logging** (Event 1644) on Domain Controllers if not already on — this repo's own analysis above makes it the highest-value single logging change for this specific tool, and it's off by default in most environments.
- Audit and reduce **local Administrators group sprawl** across the fleet (LAPS for unique local-admin passwords, minimizing standing domain-wide local-admin grants) — this is what SharpHound's `LocalAdmin`/`RDP`/`DCOM`/`PSRemote` legs are mapping, and shrinking it directly shrinks the attack-path graph an attacker can build regardless of whether collection itself is detected.
- Review and minimize **ACL grants that create short attack paths** (`GenericAll`/`WriteDacl`/`WriteOwner`/`ForceChangePassword` on privileged objects, `DS-Replication-Get-Changes-All` delegation) — BloodHound's whole value proposition to a defender is running the **same** analysis proactively and fixing what it finds before an attacker collects the data to find it themselves.
- Deploy Microsoft Defender for Identity (or equivalent) for its behavioral reconnaissance detections (Rank 4), which remain effective against binary-level evasion (renaming, recompilation, the fileless loading path) that defeats every signature-based control on this page.
- If a `DCOnly`-scoped ACL pull is suspected and DCSync-capable rights were among what got mapped, treat the underlying rights delegation itself as the thing to fix — cross-reference `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`'s remediation guidance if a subsequent DCSync pull is also suspected as part of the same intrusion.
