# Mimikatz — lsadump (DCSync) — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion](#hunting-priority--which-signal-survives-which-evasion)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion

DCSync has essentially no file-based or loader-based evasion surface at all — it's a protocol operation, identical whether mimikatz is dropped to disk, reflectively loaded, or reimplemented entirely in a different tool (Impacket's `secretsdump.py -just-dc`, DSInternals' `Get-ADReplAccount`, a custom script). The only thing that changes detection posture is **which target-side telemetry is actually configured**, since — unlike `sekurlsa`'s Sysmon 10, which is generated unconditionally by the kernel — DCSync's strongest log-based signal (Event 4662) has real prerequisites that are frequently missing.

| Rank | Signal | Requires specific config to exist? | Survives tool substitution (mimikatz vs. secretsdump.py vs. custom)? |
|---|---|---|---|
| 1 (strongest) | Network-layer: `IDL_DRSGetNCChanges`/drsuapi traffic (Zeek `dce_rpc.log` or equivalent NDR) from a source that isn't a known DC | Requires network visibility (a Zeek sensor, NDR product, or DC-side packet capture) but **not** any Windows audit-policy configuration | ✅ Yes — the protocol is identical no matter which tool speaks it |
| 2 | Microsoft Defender for Identity alert **2006** ("Suspected DCSync attack") | Requires MDI/Defender for Identity deployed with sensors on the DCs | ✅ Yes — sensor observes the DRS traffic directly, not tool-specific behavior |
| 3 | Security **Event 4662** with `AccessMask 0x100` and a replication-rights GUID, `SubjectUserSid` not a DC/allow-listed account | Requires **both** "Audit Directory Service Access" enabled **and** a matching SACL on the domain NC head object — **neither is on by default** | ✅ Yes, once configured |
| 4 | Volumetric pattern — many 4662 hits or many DRS round-trips from one `SubjectUserSid` in a short window (a full-domain `/all` pull) | Same prerequisites as rank 3, or network-layer visibility for rank 1/2 | ✅ Yes — the shape of a full-domain pull is the same regardless of tool |
| 5 | Network segmentation violation — a DC receiving *any* connection on RPC ports from an unexpected subnet | Requires segmentation to exist and be monitored | ✅ Yes, and this is a **preventive** control as much as a detective one |
| 6 (weakest, situational) | Operator-side correlation — `Get-NetTCPConnection`/Kerberos ticket cache on the source host (`03 - Source Evidence.md`) | Requires the operator's own host to be in scope for investigation | ✅ Yes, but only useful in a compromised-infrastructure or insider-threat investigation where that host is reachable |

**Build detections on ranks 1-3. Rank 4 is high-value enrichment that helps separate a targeted pull from a domain-wide one. Ranks 5-6 are posture/investigative context, not primary alerting.** Unlike `sekurlsa`'s hunting priority (where the Sysmon 10 kernel signal is unconditionally present), **confirm ranks 2-3's prerequisites are actually deployed in a given environment before trusting an absence of hits as "clean."**

## Hunting on Source

Applies when the operator's own host is in scope — a compromised-infrastructure investigation, insider-threat case, or purple-team review. Finds the artifacts documented in `03 - Source Evidence.md`.

```powershell
# PSReadLine history — full lsadump command text, including the exact /user:/domain: targets
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
  -Pattern 'lsadump::|dcsync|secretsdump' -ErrorAction SilentlyContinue

# Outbound connections to DC-typical RPC ports — endpoint mapper and dynamic high ports
Get-NetTCPConnection -ErrorAction SilentlyContinue |
  Where-Object { $_.RemotePort -eq 135 -or ($_.RemotePort -ge 49152 -and $_.RemotePort -le 65535) } |
  Select-Object LocalAddress, RemoteAddress, RemotePort, State, CreationTime

# Kerberos ticket cache — a TGS tied to a DC's service class, timestamped near a suspected DCSync window
klist

# Security 4688 (command-line auditing, if enabled) — durable, process-creation-time record
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|lsadump|dcsync|secretsdump' }

# Locally staged loot — redirected /csv output, or copied SAM/SYSTEM/SECURITY hive files
Get-ChildItem -Path C:\ -Recurse -Include '*.csv','SAM','SYSTEM','SECURITY' -ErrorAction SilentlyContinue -Force |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
```

```bash
# Linux operator box — DCSync-equivalent tooling (Impacket) rather than mimikatz itself
grep -iE "secretsdump|just-dc" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live outbound RPC connection to a DC, port 135 or a dynamic high port
ss -tnp | grep -E ':135|:4[0-9]{4}|:5[0-9]{4}|:6[0-4][0-9]{3}'
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE (if network telemetry available): review Zeek dce_rpc.log (or equivalent)
#    for drsuapi/IDL_DRSGetNCChanges sessions where the source is not a known DC —
#    example assumes a Zeek log already ingested into a queryable store; adapt to your stack
# zeek-cut orig_h resp_h endpoint operation < dce_rpc.log | grep -i drsuapi

# 2. Security 4662 — the replication-rights signature, excluding known-legitimate holders.
#    REQUIRES "Audit Directory Service Access" + a SACL on the domain NC head object —
#    confirm both are actually configured before trusting an empty result
$knownGoodPattern = '\$$|^NT AUTHORITY|MSOL_'   # computer accounts, SYSTEM, Azure AD Connect/Entra Connect sync account
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} |
  Where-Object {
    $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' -and
    $_.Message -match 'AccessMask:\s*0x100' -and
    $_.Message -notmatch $knownGoodPattern
  }

# 3. Volumetric enrichment — group hits by SubjectUserSid to separate a single-object pull
#    from a full-domain (/all) sweep
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} |
  Where-Object { $_.Message -match '1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2' } |
  Group-Object { ($_.Message -split "`r`n" | Where-Object { $_ -match 'Account Name:' })[0] } |
  Sort-Object Count -Descending

# 4. Microsoft Defender for Identity alert 2006, if deployed — query via the Defender/MDI
#    portal API or your SIEM's MDI-alert ingestion rather than the raw Security log

# 5. On the DC itself — confirm the prerequisite audit configuration actually exists
#    (posture check, not incident hunt — an empty rank-2 result means nothing without this)
auditpol /get /subcategory:"Directory Service Access"
Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)" -Audit -ErrorAction SilentlyContinue

# 6. sam/secrets/cache local extraction — SYSTEM-token usage correlated with mimikatz-style
#    process creation, and VSS shadow-copy creation (offline hive extraction)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|lsadump' }
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=8222} `
  -ErrorAction SilentlyContinue    # VSS shadow copy created

# 7. trust /patch — write-capable Sysmon 10 against lsass.exe, same reasoning as
#    sekurlsa::pth (see sekurlsa/05 - Detection and Hunting.md's Hunting Priority table)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} |
  Where-Object { $_.Message -match 'lsass\.exe' -and $_.Message -match '0x1038|PROCESS_VM_WRITE' }
```

## Fleet-Wide Sweep

Two distinct fleet-wide questions for this module: an **incident sweep** (did DCSync happen anywhere against our DCs?) and a **posture sweep** (are we even instrumented to detect it if it did?). The posture question matters more here than for most sub-tools in this repo, since DCSync's primary log-based signal depends entirely on configuration that's commonly absent.

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

# Incident sweep — 4662 replication-rights hits across every DC, excluding known-legitimate holders
$incidentResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  $knownGoodPattern = '\$$|^NT AUTHORITY|MSOL_'
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Message -match '1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2|89e95b76-444d-4c62-991a-0facbeda640c' -and
      $_.Message -notmatch $knownGoodPattern
    } |
    Select-Object @{n='DC';e={$env:COMPUTERNAME}}, TimeCreated
} -ErrorAction SilentlyContinue

# Posture sweep — is the prerequisite auditing actually configured on every DC?
$postureResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  [PSCustomObject]@{
    DC                 = $env:COMPUTERNAME
    DSAccessAuditing   = (auditpol /get /subcategory:"Directory Service Access" /r | ConvertFrom-Csv).'Inclusion Setting'
  }
} -ErrorAction SilentlyContinue

$postureResults | Where-Object { $_.DSAccessAuditing -notmatch 'Success' } |
  Export-Csv -Path .\dcsync_detection_gaps.csv -NoTypeInformation

# Complementary: inventory of every account/group actually holding replication rights on the
# domain object, independent of any log — the authoritative "who COULD DCSync" list, not just
# "who has been observed doing it"
dsacls "DC=corp,DC=local" | Select-String "Replicating Directory Changes"
```

## Remediation

**Capture evidence before acting.** DCSync's real damage — every credential it read — is already done the moment the RPC call completes; nothing about killing a process or a session on the DC undoes it, since the DC itself was never compromised in the traditional sense. Export the 4662/MDI-alert evidence and the recovered-account list (which accounts' `unicodePwd`/`supplementalCredentials` were part of the replication reply, if determinable from the request scope) before proceeding.

```powershell
# 1. Determine blast radius first — a single-object DCSync (/user:) compromises one account's
#    credential material; a full-domain pull (/all) should be treated as total domain compromise,
#    full stop, regardless of what else is known about the intrusion

# 2. If the source of the request was a legitimate account whose rights were abused (not a
#    newly-created rogue account), the ACL grant itself may be the actual root cause — audit
#    when/how that account received DS-Replication-Get-Changes[-All], not just that it used them
dsacls "DC=corp,DC=local" | Select-String "Replicating Directory Changes"

# 3. Force credential rotation for every account whose material was in scope of the request —
#    for a full-domain pull, this means EVERY account in the domain, starting with krbtgt
#    (rotate krbtgt TWICE, with the default replication interval between rotations, to fully
#    invalidate any Golden Tickets that may already have been forged from the recovered key —
#    see the planned kerberos (Golden-Silver Ticket)/ sub-module for why a single rotation
#    isn't sufficient)

# 4. Isolate/disable the account that performed the replication request if it isn't a
#    legitimate DC or sync-service account
Disable-ADAccount -Identity "svc-compromised"
```

**Close the underlying exposure, not just this incident:**
- Enable the **Advanced Audit Policy "Directory Service Access"** subcategory (Success) fleet-wide across every DC, **and** configure the corresponding SACL on the domain NC head object — neither alone is sufficient, and this is the single highest-leverage detection-engineering step for this entire module.
- Deploy **Microsoft Defender for Identity** (or an equivalent identity-threat-detection product) on every DC if not already present — its DCSync detection doesn't depend on the audit-policy/SACL configuration above, giving a second, independent detection layer.
- **Audit and minimize the population holding `DS-Replication-Get-Changes-All`** on the domain object — this is standard AD hygiene, not a DCSync-specific control, but it directly reduces which accounts becoming compromised would even enable this technique. Pay specific attention to any account outside Domain Admins/Enterprise Admins/DC computer accounts holding this right, and confirm each one (Azure AD Connect/Entra Connect being the most common legitimate case) is actually still in use and still needs it.
- **Network-segment Domain Controllers** so that RPC (TCP/135 + dynamic high ports) is reachable only from other DCs and explicitly-approved management hosts — this is a genuine preventive control against DCSync specifically (`04 - Target Evidence.md`'s network-layer section), not just detective.
- Rotate `krbtgt` (twice, per the remediation steps above) as standard incident-closure practice any time DCSync — successful or merely suspected against `krbtgt` specifically — cannot be ruled out.
