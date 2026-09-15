# Mimikatz — kerberos (Golden/Silver Ticket) — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion](#hunting-priority--which-signal-survives-which-evasion)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion

This module's evasion surface is unusually structured compared to its siblings: it isn't one operator posture defeating one detection layer (as with `sekurlsa`'s file-vs-memory split), it's a **choice baked into which key the operator forges from**, made once, upfront — Golden vs. Silver — that permanently determines the entire detection surface available afterward. Rank accordingly: Golden Ticket signals first (real, if defeatable), then the much shorter list of what remains for Silver.

| Rank | Signal | Applies to | Requires specific config? | Survives AES key material? | Survives lifetime-matching (`/endin`/`/renewmax` set to real policy)? |
|---|---|---|---|---|---|
| 1 (strongest) | Zeek `kerberos.log`: TGS-REQ with no matching prior AS-REQ/AS-REP for the same client principal | Golden only | Network visibility (Zeek/NDR sensor), **not** any Windows audit policy | ✅ Yes — the missing-AS-exchange pattern is independent of encryption type | ✅ Yes — independent of stated lifetime |
| 2 | Security 4769 with no plausible preceding 4768 for the same account | Golden only | On by default (Kerberos service-ticket auditing is part of the default Account Logon audit subcategory on modern DCs) | ✅ Yes | ✅ Yes |
| 3 | MDI "nonexistent account" (2027) / "ticket anomaly" (2032/2040) alerts | Golden only | Requires MDI/Defender for Identity deployed with DC sensors | ✅ Yes | ✅ Yes — these don't key on encryption type or lifetime at all |
| 4 | MDI "time anomaly" (2022) | Golden only | Requires MDI deployed | ✅ Yes | ❌ **No** — this is exactly what lifetime-matching defeats |
| 5 | Encryption-type anomaly — Event 4769 field or MDI "encryption downgrade" (2009) | Golden only | Requires either a 4769-capable hunt or MDI | ❌ **No** — this is exactly what AES forging defeats | ✅ Yes (orthogonal) |
| 6 | Target application server's own access/authorization anomaly (behavioral) | **Golden AND Silver** — the only signal that applies to both | Requires the target service to have meaningful access/authorization logging and a baseline of "normal" access patterns to compare against | ✅ Yes — orthogonal to ticket internals entirely | ✅ Yes — orthogonal |
| 7 (weakest, situational) | Operator-side artifacts — shell history, local ticket cache, network connections (`03 - Source Evidence.md`) | Golden AND Silver | Requires the operator's own/pivot host to be in scope | ✅ Yes, but only useful in a compromised-infrastructure investigation | ✅ Yes |

**Build primary detections on ranks 1-3 for Golden Ticket coverage. Rank 6 is the only lever available at all against Silver Ticket, and it's the weakest, hardest-to-operationalize signal in the whole table — treat any Silver Ticket detection program as a behavioral-analytics problem on the target application, not a log-signature problem.** An organization relying solely on MDI/Kerberos-log-based detection has, by construction, **zero** visibility into Silver Ticket use — this should be stated explicitly in any detection-coverage assessment, not left implicit.

## Hunting on Source

Applies when the operator's own host, or a pivot host reached via a prior compromise, is itself in scope. Finds the artifacts documented in `03 - Source Evidence.md`.

```powershell
# PSReadLine history — full command text, including the forged identity and the raw
# key material used to build the ticket (treat any hit as a live-credential exposure,
# not just evidence a forging attempt occurred)
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
  -Pattern 'kerberos::golden|kerberos::ptt|kerberos::purge|ticketer\.py' -ErrorAction SilentlyContinue

# Local ticket cache — a forged ticket sitting live in THIS host's own session, whether
# it was the operator's workstation or a compromised pivot host
klist

# Outbound connections to a DC on Kerberos ports — present for Golden Ticket use,
# absent for Silver (compare against the direct-to-target-service pattern below)
Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -eq 88 -or $_.RemotePort -eq 464 }

# Locally staged .kirbi/.ccache files — the forged ticket itself, if /ptt wasn't used
Get-ChildItem -Path C:\ -Recurse -Include '*.kirbi','*.ccache' -ErrorAction SilentlyContinue -Force |
  Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }

# Security 4688 (command-line auditing, if enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|kerberos::golden|kerberos::ptt' }
```

```bash
# Linux operator/pivot box — Impacket ticketer.py or equivalent, instead of mimikatz
grep -iE "ticketer\.py|getTGT\.py" ~/.bash_history ~/.zsh_history 2>/dev/null
klist   # MIT Kerberos ticket cache — same evidentiary role as klist.exe above
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE (Golden only, requires network telemetry): Zeek kerberos.log —
#    TGS-REQ entries with no matching prior AS-REQ/AS-REP for the same client principal.
#    Adapt to your own log pipeline; shown as a zeek-cut sketch:
# zeek-cut ts id.orig_h client service request_type success cipher < kerberos.log | grep TGS

# 2. Security 4769 — group by account, flag accounts with 4769s but no corresponding
#    4768 in a reasonable preceding window. Golden Ticket only.
$tgsEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 2000
$tgtEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 2000
$tgtAccounts = $tgtEvents | ForEach-Object { ($_.Properties[0].Value) } | Sort-Object -Unique
$tgsEvents | Where-Object { $tgtAccounts -notcontains $_.Properties[0].Value } |
  Select-Object TimeCreated, @{n='Account';e={$_.Properties[0].Value}}, @{n='Service';e={$_.Properties[2].Value}}

# 3. Encryption-type anomaly on 4769 — RC4 (0x17) usage where AES is otherwise the norm.
#    Config-dependent signal, defeated by AES forging — enrichment, not primary.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} |
  Where-Object { $_.Message -match 'Ticket Encryption Type:\s*0x17' }

# 4. Microsoft Defender for Identity — query the MDI/Defender XDR portal or SIEM
#    ingestion for the Golden-Ticket-family alerts (external IDs 2027/2032/2040/
#    2022/2009/2013), rather than the raw Security log
# See 04 - Target Evidence.md for the full alert table

# 5. Target-application-server behavioral anomaly — THE ONLY LEVER FOR SILVER TICKETS.
#    Example: an account authenticating to a file server it has never accessed before,
#    or accessing far more of a share than its historical baseline
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} |
  Where-Object { $_.Message -match 'Logon Type:\s*3' -and $_.Message -match 'Kerberos' } |
  Group-Object { ($_.Message -split "`r`n" | Where-Object { $_ -match 'Account Name:' })[0] } |
  Where-Object { $_.Count -eq 1 }   # first-ever-seen access from this account to this server — enrich/baseline before alerting

# 6. Posture check — is the domain's krbtgt password stale? (proactive hygiene hunt,
#    not an incident hunt — a long-unrotated krbtgt widens the window any stolen key
#    remains useful for, for BOTH Golden and Silver against krbtgt-derived keys)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet
```

## Fleet-Wide Sweep

Two distinct fleet-wide questions, same framing as `lsadump (DCSync)/05 - Detection and Hunting.md`: an **incident sweep** (has this happened anywhere?) and a **posture sweep** (are we even positioned to detect it?). The posture question is unusually important here because of the Golden/Silver split — a fleet fully covered for Golden Ticket detection can still have **zero** coverage for Silver Ticket, and that gap doesn't show up in any dashboard unless it's explicitly checked for.

```powershell
$domainControllers = (Get-ADDomainController -Filter *).HostName

# Incident sweep — 4769-without-4768 heuristic across every DC (Golden Ticket only)
$incidentResults = Invoke-Command -ComputerName $domainControllers -ScriptBlock {
  $tgs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4769} -MaxEvents 1000 -ErrorAction SilentlyContinue
  $tgt = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4768} -MaxEvents 1000 -ErrorAction SilentlyContinue
  $tgtAccounts = $tgt | ForEach-Object { $_.Properties[0].Value } | Sort-Object -Unique
  $tgs | Where-Object { $tgtAccounts -notcontains $_.Properties[0].Value } |
    Select-Object @{n='DC';e={$env:COMPUTERNAME}}, TimeCreated, @{n='Account';e={$_.Properties[0].Value}}
} -ErrorAction SilentlyContinue

# Posture sweep — krbtgt rotation age (organization-wide, not per-DC) and MDI deployment
# status per DC. A krbtgt that hasn't rotated in a long time widens the blast radius of
# ANY historical DCSync/LSASS-read incident that may have gone undetected.
[PSCustomObject]@{
  KrbtgtPasswordLastSet = (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet
  KrbtgtAgeInDays        = ((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet).PasswordLastSet).Days
}

# Complementary: current domain Kerberos policy values, so a "time anomaly" hunt's
# threshold is set to what's ACTUALLY configured, not an assumed 10-hour default
Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue   # Kerberos policy specifically requires GPMC/gpresult review — not exposed via a single cmdlet
```

## Remediation

**Capture evidence before acting.** As with DCSync (`lsadump (DCSync)/05 - Detection and Hunting.md`), the credential material this module exploits was already stolen by whatever technique obtained the krbtgt/service key in the first place — remediation here is about **cutting off continued use of the forged ticket(s)**, not undoing a read that already happened.

```powershell
# 1. Determine blast radius — this is where Golden vs. Silver matters enormously for
#    scoping the response:
#    - Golden Ticket (krbtgt-derived): treat as FULL DOMAIN compromise. The forged
#      ticket's scope is bounded only by what group memberships were forged into it
#      and the domain's trust relationships (wider still if /sids was used) — assume
#      worst case (Domain/Enterprise Admin) unless the specific forging parameters
#      are known.
#    - Silver Ticket (service-key-derived): scope is bounded to the ONE service the
#      key belongs to. Rotating that one account's password invalidates it completely
#      — a materially narrower, faster remediation than a Golden Ticket response.

# 2. For Golden Ticket: rotate krbtgt TWICE, separated by the domain's replication
#    convergence time, to fully invalidate every outstanding forged ticket regardless
#    of when it was created or how long it claims to be valid for. A single rotation
#    is NOT sufficient — the account's key-history depth means a stale key can still
#    validate old tickets until the second rotation pushes it out of history entirely.
#    (Same guidance as lsadump (DCSync)/05 - Detection and Hunting.md's remediation —
#    not re-derived here, this is the same underlying krbtgt-rotation requirement.)

# 3. For Silver Ticket: rotate the specific service/computer account's password
Set-ADAccountPassword -Identity "svc-mssql" -Reset

# 4. Terminate any live sessions authenticated via the forged ticket, on every target
#    host it was used against — identified from the target-application-server
#    evidence in 04 - Target Evidence.md, since DC-side evidence alone won't surface
#    a Silver Ticket's targets at all
```

**Close the underlying exposure, not just this incident:**
- **Rotate krbtgt on a regular schedule** (Microsoft's own guidance is at minimum annually; more frequently in higher-risk environments) as standing hygiene, independent of any known incident — this directly bounds how long a historically-stolen krbtgt key (from an undetected DCSync, LSASS read, or NTDS.dit theft that predates current monitoring) remains useful for Golden Ticket forgery.
- **Deploy Microsoft Defender for Identity** (or an equivalent DC-sensor-based identity threat detection product) if not already present — this is the only meaningful automated coverage this module has for its Golden Ticket variant, and it has **zero** coverage for Silver Ticket, so don't treat its deployment as closing this module's full exposure.
- **Build target-application-layer behavioral baselines** for high-value services (file servers, database services, anything with its own SPN) specifically because it's the only detection lever available against Silver Ticket at all — this is a genuinely different, harder investment than the DC-centric tooling above, and shouldn't be deprioritized just because it's less mature/available off-the-shelf.
- **Enable full PAC validation** (`KERB_VERIFY_PAC` callback to a DC) on high-value application servers where the performance cost is acceptable — this is the one control that directly exploits the Silver Ticket's structurally-invalid KDC signature (`01 - Overview.md`), but confirm it's actually supported and enabled per-service before relying on it; it is not a domain-wide default.
- **Minimize and audit which accounts hold rights that lead to krbtgt/service-key exposure in the first place** (`lsadump (DCSync)/05 - Detection and Hunting.md`'s DS-Replication-Get-Changes-All hygiene, and `sekurlsa (Credential Dumping)/05 - Detection and Hunting.md`'s LSASS-protection posture) — this module is entirely downstream of one of those two prior compromises; closing the upstream exposure is more leverage than anything achievable at the forging/injection layer itself.
