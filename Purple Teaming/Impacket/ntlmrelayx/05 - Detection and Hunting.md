# Impacket — ntlmrelayx.py — Detection and Hunting

## Contents
- [Hunting Priority — Ranked by What Survives Which Evasion Option](#hunting-priority--ranked-by-what-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Ranked by What Survives Which Evasion Option

`ntlmrelayx.py` has more operator-facing evasion/customization surface than any other tool in this `Impacket/` folder — `--remove-mic`, `--remove-sign-seal`, `-i` (interactive mode bypasses the canned attack module entirely), `-ra`/`-w`/`-tf` targeting variety, `-remove-target`, and per-protocol suppress flags (`--no-da`, `--no-acl`, `--no-dump`). Rank hunting signals by what actually keeps working when an operator reaches for these, not by how "important" each signal sounds in isolation.

| Rank | Signal | What defeats it | What doesn't |
|---|---|---|---|
| **1 (strongest — structural, not protocol-level)** | Target B's Security 4624: `IpAddress` = relay host, `WorkstationName` doesn't match the victim's real hostname | **Nothing in this tool's flag set.** This is a structural property of relaying — Target B's TCP connection always terminates at the relay host — not an NTLM-protocol trick `--remove-mic`/`--remove-sign-seal` can touch | Survives `--remove-mic`, `--remove-sign-seal`, `-i`, `-socks`, every targeting flag, every attack-module suppress flag |
| **1 (tied — also structural)** | Network-flow correlation: one host simultaneously acting as an inbound listening server (victim's session) and an outbound client (to Target B) in the same narrow time window | Nothing — same reasoning as above, this is what relaying *is* | Requires Zeek/NetFlow-level visibility rather than a single host's logs; unaffected by any CLI flag |
| **2 (a control, not a signal — but the single biggest lever)** | SMB session signing required + LDAP signing/channel binding enforced on Target B | **Nothing general.** `--remove-mic` (CVE-2019-1040) and `--remove-sign-seal` (CVE-2025-33073) are narrow, **patched**, scenario-specific bypasses — neither defeats signing enforcement on a target that is both patched and configured to require it. This is a prevention control that also functions as the strongest possible "signal absence" — a relay attempt against a signing-enforced target simply fails and produces no attack-module evidence at all | Confirm patch status + enforcement before concluding "no relay happened" from a quiet log — a relay against a non-enforcing target leaves the full evidence trail below |
| **3** | Attack-module-specific artifacts (SAM-dump Sysmon 11 `.tmp` file, LDAP 5136 attribute writes, service-install 7045, TaskScheduler 106/200/201, CA 4886/4887) | **`-i` (interactive mode) kills this entire evidence class outright** — an operator who drops into an interactive SMB/LDAP/SQL/WinRM shell instead of letting the automatic attack module fire never generates any of the canned, module-specific artifacts documented in `04 - Target Evidence.md`, because that code path is never executed. `--no-da`/`--no-acl`/`--no-dump` similarly suppress specific sub-signatures within the LDAP module | Survives if the operator lets the default/automatic attack module run — which is the common case, since `-i` requires actively maintaining an interactive session rather than a fire-and-forget attack |
| **4 (scoped to one relay target only)** | Netlogon 5827/5828/5829 or raw RPC-call-volume flood, for the DCSync/Zerologon relay path specifically | Only applies at all if `-t dcsync://` is the relay target — irrelevant to every other protocol | Not evadable by any flag *within* that path — the Zerologon exploit mechanism itself requires the up-to-6,000-attempt loop; an operator can't quiet it down |
| **5 (weakest — availability, not reliability)** | Source-side artifacts (`03`): multiple simultaneously bound listening ports, heterogeneous loot files, long-lived process | Not defeated by any flag — this is a visibility problem, not an evasion problem. A blue team investigating from the victim/Target-B side essentially never has this vantage point at all, since it requires EDR/host access **on the attacker's own machine** | Extremely strong if that access exists (an internal host bound to SMB+MSSQL+RDP+RPC simultaneously has almost no innocent explanation) |

## Hunting on Source

Same commands as `03 - Source Evidence.md`'s artifacts, framed as active hunts — relevant when the suspected relay host is itself under investigation (an internal pivot box, a compromised workstation being used as the relay point):

```bash
# Shell history - flag combinations reveal intent directly (e.g. dcsync:// + no -auth-smb = Zerologon attempt)
grep -iE "ntlmrelayx|dcsync://|delegate-access|shadow-credentials|sccm-policies|sccm-dp|adcs" ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process - long-running by design, unlike the one-shot sibling tools in this folder
ps aux | grep -i ntlmrelayx

# THE distinctive source-side signature: multiple simultaneously bound listening ports on one PID
ss -tlnp | grep -E ':445|:80|:9389|:6666|:135|:1433|:3389|:5985|:5986'
lsof -i -P -n 2>/dev/null | grep ntlmrelayx

# Heterogeneous loot - hashes, .pfx certs, .eml files, and SCCM loot dirs sitting side by side
# in one location is itself a strong tell (see 03's loot-file table)
find / \( -iname "*_samhashes.sam" -o -iname "*.pfx" -o -iname "*_sccm_*_loot" -o -iname "mail_*.eml" \) 2>/dev/null

# auditd execve record - survives a shell-history wipe
ausearch -x ntlmrelayx.py 2>/dev/null
```

## Hunting on Target

### The universal check — run this first, regardless of which relay-target protocol is suspected

```powershell
# Security 4624 Type 3 logons where WorkstationName is blank, generic, or resolves to a
# host that doesn't match the SourceIP's own reverse-DNS — the Rank-1 signal from the
# table above, applicable to every relay-target protocol at once
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[8].Value -eq 3 } |
  Select-Object TimeCreated,
    @{N='Account';E={$_.Properties[5].Value}},
    @{N='WorkstationName';E={$_.Properties[11].Value}},
    @{N='SourceIP';E={$_.Properties[18].Value}} |
  Where-Object { [string]::IsNullOrWhiteSpace($_.WorkstationName) -or $_.WorkstationName -eq '-' }
```
Full Logon Type field semantics and property-index caveats (locale sensitivity of `.Message`, why `.Properties[]` indexing is preferred) are documented in `Windows/05 - Users, Groups & Authentication.md` — not re-derived here.

### SMB relay target

```powershell
# Sysmon 11 - the __output relay file (shared signature with wmiexec.py) or the SAM
# temp-hive-copy pattern (shared signature with secretsdump.py Path 1)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '\\ADMIN\$\\Temp\\__output' -or $_.Message -match '\\Windows\\Temp\\[A-Za-z]{8}\.tmp' }

# System 7045 - service install pattern (-e), reusing psexec.py's own detection query
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'ImagePath.*\\Windows\\[A-Za-z]{8}\.exe' }
```
See `Impacket/psexec/05 - Detection and Hunting.md` and `Impacket/secretsdump/05 - Detection and Hunting.md` for the full ranked hunt sets these two signatures come from.

### LDAP(S) relay target

```powershell
# 5136 - the highest-value single query for this relay target: catches RBCD grants,
# Shadow Credentials writes, and the default ACL-attack's nTSecurityDescriptor edit,
# all in one filter (requires DS Access auditing + SACLs on the relevant objects)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity|msDS-KeyCredentialLink|nTSecurityDescriptor' }

# 4720/4741 immediately followed by 4728/4732 or another 5136, from the SAME actor,
# within seconds - the create-then-escalate pattern
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4741,4728,4732} -ErrorAction SilentlyContinue |
  Sort-Object TimeCreated

# Resulting state check - accounts that already hold the write, independent of when it happened
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }
```
The `msDS-AllowedToActOnBehalfOfOtherIdentity`/DCSync-rights hunt queries already built in `Windows/05b - Active Directory & Domain Forensic Artifacts.md`'s Hunt Evil section apply directly — not duplicated here.

### DCSync relay target (Zerologon path)

```powershell
# The volumetric tell - a burst of Netlogon-vulnerable-connection events is the strongest
# signal this specific relay path has, and it precedes any DRSUAPI activity
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Netlogon'; Id=5827,5828,5829} -ErrorAction SilentlyContinue |
  Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Where-Object Count -gt 5

# If audit policy allows it - the actual DRSUAPI leg, using the same 4662 query as
# Mimikatz/lsadump (DCSync)/05 - but expect only ~3 hits (krbtgt, DC machine account,
# Administrator) when -auth-smb wasn't supplied, versus a full-domain volumetric pull
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662} -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match '1131f6a[ad]-9c07-11d1-f79f-00c04fc2dcd2' }
```
Full DRSUAPI/4662 mechanics: `Mimikatz/lsadump (DCSync)/05 - Detection and Hunting.md`. **Confirm every DC in scope is patched for CVE-2020-1472 and enforcing** before assuming this path is closed on an absence of 5827/5828/5829 — a DC that was never patched won't generate the denial events either, it will simply comply.

### ADCS relay target

```powershell
# 4886/4887 pairs where the certificate's SAN/CN doesn't match the requesting account -
# requires "Issue and manage certificate requests" auditing enabled on the CA (non-default)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4886,4887,4888} -ErrorAction SilentlyContinue |
  Sort-Object TimeCreated

# IIS log sweep on the CA's web-enrollment role (HTTP/ESC8 path only) - run where IIS
# logs are collected centrally, not natively expressible as a Get-WinEvent query
# findstr /C:"certfnsh.asp" /C:"certnew.cer" C:\inetpub\logs\LogFiles\W3SVC1\*.log
```

### MSSQL / WinRM / RPC(TSCH) relay targets

```powershell
# WinRM - reuse Windows/12's existing WinRM row directly
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -ErrorAction SilentlyContinue

# RPC/TSCH - reuse the atexec.py-equivalent TaskScheduler hunt: register-then-delete
# within seconds is the anomaly, not the task's existence alone
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106,200,201} -ErrorAction SilentlyContinue |
  Group-Object { ($_.Message -split "`r`n" | Select-String 'Task Name').ToString() } |
  Where-Object { $_.Count -ge 2 }

# MSSQL - no native Windows event; requires SQL Server Audit configured ahead of time
# SELECT * FROM sys.fn_get_audit_file('C:\SQLAudit\*.sqlaudit', DEFAULT, DEFAULT)
```

### SCCM Management Point / Distribution Point relay target

```
# No Windows Security-log signal exists for this relay target - hunt in IIS W3C logs
# on the MP/DP role directly. The two-POST registration-then-policy pattern with a
# ~180s gap is the MP tell; recursive Datalib/packageID crawling from one source in a
# short window is the DP tell (User-Agent alone is legitimate SCCM traffic, not a filter)
findstr /C:"ccm_system_windowsauth/request" /C:"ccm_system/request" C:\inetpub\logs\LogFiles\*\*.log
findstr /C:"sms_dp_smspkg$" C:\inetpub\logs\LogFiles\*\*.log
```

## Fleet-Wide Sweep

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

# Rank-1 signal, fleet-wide - anomalous WorkstationName/IpAddress 4624s across every DC
# and every member server that logs Security events centrally
$anomalousLogons = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 3 -and [string]::IsNullOrWhiteSpace($_.Properties[11].Value) } |
    Select-Object @{N='Host';E={$env:COMPUTERNAME}}, TimeCreated,
      @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
} -ErrorAction SilentlyContinue

# Netlogon flood check, every DC at once - the DCSync/Zerologon path's strongest signal
$netlogonFlood = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Netlogon'; Id=5827,5828,5829} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } | Where-Object Count -gt 5
} -ErrorAction SilentlyContinue

# msDS-AllowedToActOnBehalfOfOtherIdentity / msDS-KeyCredentialLink sweep - resulting
# state, independent of when the write happened (from Windows/05b, run domain-wide)
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, msDS-KeyCredentialLink |
  Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' -or $_.'msDS-KeyCredentialLink' } |
  Select-Object Name, DistinguishedName |
  Export-Csv -Path .\ntlmrelayx_delegation_shadowcreds_sweep.csv -NoTypeInformation

$anomalousLogons | Export-Csv -Path .\ntlmrelayx_anomalous_4624_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — before disabling or resetting anything, export the anomalous 4624 events, any 5136/4886/4887/Netlogon-flood events found above, and the resulting-state ACL/`msDS-*` attribute values (they're the only record of the pre-attack state if `ntlmrelayx.py`'s own restore-data file, `03`'s "Local Output Files" table, isn't recoverable from the operator side).

```powershell
# Remove a confirmed RBCD grant
Set-ADComputer -Identity <computername> -Clear msDS-AllowedToActOnBehalfOfOtherIdentity

# Remove a confirmed Shadow Credentials write - inspect the attribute's individual values
# first (it can legitimately hold Windows Hello for Business keys) rather than blind-clearing
Get-ADObject -Identity <targetDN> -Properties msDS-KeyCredentialLink
Set-ADObject -Identity <targetDN> -Clear msDS-KeyCredentialLink   # only after confirming which entries are illegitimate

# Revoke a fraudulently issued ADCS certificate
certutil -revoke <certificate-serial-number>
```

**Close the underlying exposure, not just this incident:**
- **Structural fix that closes the most relay paths at once:** enforce SMB session signing and both LDAP signing **and** LDAP channel binding domain-wide — per `01 - Overview.md`'s own citation of the tool's docstring, this is the mechanism the tool's own authors say is the actual stop, not a detection improvement.
- **DCSync/Zerologon path specifically:** confirm every DC has the August 2020 CVE-2020-1472 patch **and** is in Netlogon secure-channel enforcement mode (the default since Microsoft's February 2021 enforcement phase) — an environment still running a DC in the vulnerable/non-enforcing state has a structural hole no amount of event-log monitoring substitutes for.
- **Root cause upstream of the relay itself:** the relay only ever happens because *something* delivered an inbound authentication attempt — close whichever of `Responder/`'s LLMNR/NBT-NS/mDNS poisoning surface or the coercion primitive (PetitPotam/PrinterBug/ShadowCoerce, [T1187](https://attack.mitre.org/techniques/T1187/)) actually fed this specific incident, per those notes' own Remediation sections, or the same relay opportunity simply recurs with a different downstream attack module next time.
- **ADCS specifically:** disable HTTP web enrollment where it isn't required, or require HTTPS + Extended Protection for Authentication on it if it must stay — this is the standard ESC8 closure, independent of `ntlmrelayx.py`.
- **SCCM specifically:** review whether automatic client approval is enabled on the MP (it's the precondition the tool's own comment notes as needed for `--sccm-policies` to work "best") and rotate the Network Access Account if `--sccm-policies` succeeded against your environment.
