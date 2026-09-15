# Impacket — GetUserSPNs.py (Kerberoasting) — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which signal survives which operator evasion option (`-stealth`, `-no-rc4`, targeted single-account requests instead of a broad sweep) — strongest and most invariant first.

| Rank | Signal | Survives which evasions | Notes |
|---|---|---|---|
| 1 (strongest) | **One requesting principal, many distinct target SPNs, tight time window** — aggregated from Security 4769 | Survives `-stealth` (doesn't change the TGS-REQ leg at all) and `-no-rc4` (doesn't change *which* accounts get targeted). **Defeated by**: an operator deliberately throttling requests over a long window, or using `-request-user`/`-usersfile` to target only one or a few accounts at a time | The single highest-confidence, environment-independent signal in this whole page — depends only on the near-universally-enabled Kerberos Service Ticket Operations audit subcategory |
| 2 | **A single RC4 (`0x17`) TGS-REQ issued for an account, in a domain where AES is otherwise broadly supported** | Defeated entirely by `-no-rc4` **combined with** the target account actually being AES-only (`msDS-SupportedEncryptionTypes` = `24`) — but `-no-rc4` alone doesn't defeat this, since the *issued* etype is still governed by the target account, not the client's TGT etype (`04 - Target Evidence.md`) | Weak alone (RC4 offering is common/legitimate); strong when combined with rank 1 |
| 3 | **LDAP reconnaissance signal** — Directory Service Event 1644 (`Field Engineering=5`), a SACL-backed Security 4662, or an MDI "Security principal reconnaissance (LDAP)"/"SPN enumeration" alert | Defeated by `-stealth` **for signature/filter-string-keyed detections specifically** (removes the literal `(servicePrincipalName=*)` filter) — but Microsoft ships a dedicated MDI alert ("Possible Kerberoasting attack using a stealthy LDAP search") built specifically to catch that evasion, and 1644's "expensive query" threshold is arguably **more** likely to trip under `-stealth` (unfiltered result set), not less | Entirely dependent on non-default logging/SACL configuration — treat as enrichment, not a standalone detection to rely on |
| 4 (weakest) | **A single 4769 in isolation, any etype, any target** | Provides essentially no signal on its own — every legitimate authenticated user requesting a service ticket for a service they're about to actually use looks identical | Never alert on this alone; use only as raw material for ranks 1-2's aggregation |

## Hunting on Source

```bash
# Shell history — flag combination reveals operator intent (see 03's table)
grep -iE "GetUserSPNs|kerberoast|request-user|request-machine|no-preauth|stealth|usersfile" \
  ~/.bash_history ~/.zsh_history 2>/dev/null

# Live process check
ps aux | grep -i GetUserSPNs

# Confirm impacket install + version (flag surface varies by release — see 03)
pip3 show impacket 2>/dev/null

# The single most direct local artifact: files containing the Kerberoast hash signature,
# regardless of filename
grep -rl '\$krb5tgs\$' / 2>/dev/null

# Saved tickets from -save
find / -iname "*.ccache" -newer /etc/hostname 2>/dev/null

# Live network state — LDAP (389/636) immediately followed by Kerberos (88), with NO SMB/RPC
# alongside it — a distinctive shape versus every other Impacket tool in this repo
ss -tnp | grep -E ':389|:636|:88'

# auditd execve record — survives a shell-history wipe
ausearch -x GetUserSPNs.py 2>/dev/null
```

## Hunting on Target

**PowerShell-first, built around Event 4769 with etype- and count-based aggregation — this is the single most important hunt for this technique.**

```powershell
# 1. THE CENTERPIECE HUNT: aggregate Security 4769 by requesting principal, count DISTINCT
#    target service names in a rolling window. A legitimate user requests tickets to a
#    small, stable set of services they actually use — Kerberoasting requests tickets to
#    many DIFFERENT services in a short burst.
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddHours(-4)} |
  Where-Object { $_.Message -notmatch 'krbtgt' }   # exclude routine TGT-renewal-adjacent noise

$parsed = foreach ($e in $events) {
  [PSCustomObject]@{
    Time            = $e.TimeCreated
    Account         = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Account Name:'})[0].Split(':')[1].Trim()
    ServiceName     = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Service Name:'})[0].Split(':')[1].Trim()
    EncryptionType  = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Ticket Encryption Type:'})[0].Split(':')[1].Trim()
    ClientAddress   = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Client Address:'})[0].Split(':')[1].Trim()
  }
}

$parsed | Group-Object Account | Where-Object { ($_.Group.ServiceName | Select-Object -Unique).Count -ge 5 } |
  Select-Object Name, @{N='DistinctSPNsRequested';E={($_.Group.ServiceName | Select-Object -Unique).Count}},
                @{N='WindowStart';E={($_.Group.Time | Measure-Object -Minimum).Minimum}},
                @{N='WindowEnd';E={($_.Group.Time | Measure-Object -Maximum).Maximum}},
                @{N='RC4Count';E={($_.Group | Where-Object {$_.EncryptionType -match '0x17'}).Count}} |
  Sort-Object DistinctSPNsRequested -Descending

# 2. RC4-specific view — isolate 0x17 tickets and rank by requester, useful even below the
#    rank-1 threshold for a smaller/slower sweep
$parsed | Where-Object { $_.EncryptionType -match '0x17' } | Group-Object Account |
  Sort-Object Count -Descending | Select-Object Name, Count

# 3. DES tickets — should essentially never appear; treat any hit as worth immediate review
$parsed | Where-Object { $_.EncryptionType -match '0x1$|0x3$' }

# 4. LDAP-side, if Event 1644 (Field Engineering=5) is enabled on the DC — filter string
#    directly visible in the message
Get-WinEvent -LogName 'Directory Service' -FilterXPath "*[System[EventID=1644]]" -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'servicePrincipalName' }
```

## Fleet-Wide Sweep

Event 4769 is generated **by the Domain Controller that processed the request**, not the requester's own host — run the centerpiece hunt against every DC in the domain, not just one, since load-balanced or site-local DC selection means a single operator's burst can land split across multiple DCs.

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

$fleetResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769; StartTime=(Get-Date).AddHours(-4)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -notmatch 'krbtgt' }

  foreach ($e in $events) {
    [PSCustomObject]@{
      DC              = $env:COMPUTERNAME
      Time            = $e.TimeCreated
      Account         = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Account Name:'})[0].Split(':')[1].Trim()
      ServiceName     = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Service Name:'})[0].Split(':')[1].Trim()
      EncryptionType  = ($e.Message -split "`r`n" | Where-Object {$_ -match 'Ticket Encryption Type:'})[0].Split(':')[1].Trim()
    }
  }
} -ErrorAction SilentlyContinue

# Aggregate ACROSS all DCs by requesting account — a burst split across three DCs still
# reassembles into one clear signal once merged
$fleetResults | Group-Object Account | Where-Object { ($_.Group.ServiceName | Select-Object -Unique).Count -ge 5 } |
  Select-Object Name, @{N='DistinctSPNs';E={($_.Group.ServiceName | Select-Object -Unique).Count}},
                @{N='DCsInvolved';E={($_.Group.DC | Select-Object -Unique) -join ','}} |
  Export-Csv -Path .\kerberoast_fleet_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — export the relevant 4769 window (and 1644/4662 if available) and any recovered hash file/`.ccache` before making any account-level changes, since resetting a targeted service account's password destroys the ability to confirm whether a recovered hash actually matched it.

**This is a credential-hygiene problem with real structural fixes — treat this section as substantive, not a "monitor and hope" afterthought:**

- **AES-only enforcement via `msDS-SupportedEncryptionTypes`** — the single highest-leverage fix. Setting this attribute to `24` (`0x18` = AES128 + AES256, RC4 bit cleared) on every SPN-bearing account means even a successful, undetected Kerberoast run only ever yields AES128/256 tickets (hashcat modes `19600`/`19700`), which are dramatically more expensive to crack than RC4 (`13100`) — verified against `01 - Overview.md`'s etype table and Microsoft's own [RC4 detection/remediation guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos). This doesn't stop the technique from working structurally (any authenticated user can still request a ticket), it just makes the resulting ticket far less practically crackable.
  ```powershell
  Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
    Where-Object { $_.'msDS-SupportedEncryptionTypes' -eq $null -or ($_.'msDS-SupportedEncryptionTypes' -band 4) } |
    Select-Object SamAccountName, ServicePrincipalName, 'msDS-SupportedEncryptionTypes'
  # Set-ADUser -Identity <account> -Replace @{'msDS-SupportedEncryptionTypes' = 24}
  ```
  Test thoroughly before a domain-wide rollout — legacy applications that only speak RC4 will break outright, which is exactly why this is a project with a rollout plan, not a one-line fix.
- **gMSA/dMSA adoption — eliminate the crackable static password entirely.** A Group Managed Service Account (gMSA) uses a 240-byte, automatically-rotated, machine-managed password that is not practically crackable even if an RC4 ticket is obtained — the root problem (a human-set, often-weak, rarely-rotated static service-account password) is removed rather than merely hardened. Windows Server 2025's **delegated Managed Service Account (dMSA)** goes further, additionally binding the account to specific machine identities so even a captured ticket/credential is far less portable — see Microsoft's [Delegated Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-overview). (Flag honestly: dMSA has its own published attack research — the "Golden dMSA" line of work — so treat it as a strong mitigation for *this* technique specifically, not a categorical guarantee against every credential-theft technique.)
- **Honeypot/canary SPN accounts as a detection amplifier.** Create one or more decoy accounts with an attractive `servicePrincipalName` (e.g. `MSSQLSvc/legacy-db01.corp.local`) and a name suggesting privilege (`svc-sql-admin`), never used for any real authentication. **Any** 4769 naming that account as the Service Name is unambiguous — there is no legitimate reason for it to ever occur. This directly counters rank-1's one weakness (a slow, low-and-slow operator staying under a volumetric threshold): a canary doesn't depend on volume or timing at all, a single request is the alert.
- **Reduce blast radius for whatever does still crack** — service accounts recovered via Kerberoasting are only as dangerous as their actual privilege; auditing and minimizing which service accounts hold Domain Admin-equivalent rights (a service account rarely needs it) limits what a successfully-cracked password actually buys an attacker, independent of whether the roasting itself was ever detected.
- **Enable the LDAP-side telemetry deliberately, don't assume it's on** — Directory Service Event 1644 (`Field Engineering=5`) and/or Directory Service Access auditing with a SACL on sensitive OUs gives the earlier-stage reconnaissance signal `04 - Target Evidence.md` describes as non-default; enabling it converts a detection posture that starts at "the TGS-REQ burst" into one that starts at "the LDAP query that preceded it," buying earlier warning.
