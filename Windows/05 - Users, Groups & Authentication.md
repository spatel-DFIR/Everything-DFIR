# Users, Groups & Authentication

Every intrusion eventually answers to a question about *who*: who logged on, from where, as what, and with which rights. This note is the local-host half of that answer — the SAM hive's per-account bookkeeping, the ProfileList key that outlives deleted accounts, the Microsoft-account/DPAPI wrinkle that trips up password-recovery attempts, and the Security-log event IDs (4624/4625/4648/4672 and friends) that turn "an account exists" into "this account authenticated, this way, at this time." Domain-specific depth — Kerberos ticket internals, AD replication metadata, delegation abuse, Domain Controller-only event fields — is deferred to **Active Directory & Domain Forensic Artifacts (05b)**; this note stops at what a single host's own hives and Security log can tell you, and forward-references 05b wherever a topic clearly continues there.

> 🔴 **Logon Type is the single highest-value field in this entire note.** The same account, the same success/failure outcome, the same time of day mean completely different things depending on whether Logon Type says 2 (someone at the keyboard), 3 (a network connection), 9 (a `runas`-style credential switch), or 10 (RDP). Read the type before you read anything else in a 4624/4625 event.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why It Matters to IR](#why-it-matters-to-ir)
- [SAM Hive Account Structure](#sam-hive-account-structure)
  - [Well-Known RIDs](#well-known-rids)
  - [Per-Account Fields Recorded in SAM](#per-account-fields-recorded-in-sam)
  - [Well-Known Local Group RIDs](#well-known-local-group-rids)
- [ProfileList: Enumerating Every Account That Ever Logged On](#profilelist-enumerating-every-account-that-ever-logged-on)
- [Microsoft (Cloud) Accounts vs Local Accounts](#microsoft-cloud-accounts-vs-local-accounts)
- [Logon Types (Event ID 4624 / 4625)](#logon-types-event-id-4624--4625)
- [Core Authentication & Account Event IDs](#core-authentication--account-event-ids)
- [4648: Explicit Credentials — The Lateral Movement Tell](#4648-explicit-credentials--the-lateral-movement-tell)
- [RDP Usage Tracking](#rdp-usage-tracking)
- [Logon-Type Triage: What to Suspect](#logon-type-triage-what-to-suspect)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for user/group/auth anomalies before any deep-dive — no third-party modules required:

```powershell
# Local admin group membership - the group every privilege-escalation finding checks against
Get-LocalGroupMember -Group Administrators

# Local accounts sorted by creation-adjacent activity - a recently created or recently enabled
# account with no obvious business reason is a persistence-account red flag
Get-LocalUser | Select-Object Name,Enabled,PasswordLastSet,LastLogon

# Accounts with password-never-expires set - a common attacker convenience setting on a
# freshly created account, not a typical admin default
Get-LocalUser | Where-Object PasswordExpires -eq $null | Select-Object Name,Enabled,PasswordLastSet

# Built-in Administrator (RID 500) - re-enabled with a recent password change is a classic
# re-activation-for-persistence tell
Get-LocalUser -Name Administrator | Select-Object Name,Enabled,PasswordLastSet

# Who can RDP in, independent of admin rights - membership here alone grants RDP logon
Get-LocalGroupMember -Group "Remote Desktop Users"

# Successful/failed logons in the last 24h with Logon Type - read the type before anything else
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddDays(-1)} |
    Select-Object TimeCreated,Id,@{N='LogonType';E={$_.Properties[8].Value}},@{N='Account';E={$_.Properties[5].Value}}

# 4672 special-privilege logons - which accounts got admin-equivalent rights, and when
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672;StartTime=(Get-Date).AddDays(-1)} |
    Select-Object TimeCreated,@{N='Account';E={$_.Properties[1].Value}}

# Accounts that have never logged on - stale/orphaned accounts worth explaining, or confirming dormant
Get-LocalUser | Where-Object { $_.Enabled -and -not $_.LastLogon }
```

## Why It Matters to IR

Two artifacts do almost all of the work in an account/authentication investigation on a single host: the **SAM hive** (who this account *is* — RID, creation time, password history, group membership) and the **Security event log** (what this account *did* — every logon, logoff, privilege escalation, and explicit-credential switch, each timestamped and typed). Neither is useful alone: SAM tells you an account exists and when it was created, but not when it was used for what; the Security log tells you a logon happened, but the account's SAM record is what tells you whether RID 1000 was a legitimate hire or a same-day-created backdoor account. This note treats them as one investigative unit.

## SAM Hive Account Structure

The `SAM` hive (`C:\Windows\System32\config\SAM`, mounted live at `HKLM\SAM`) stores every **local** account and group on the machine, indexed by **RID (Relative Identifier)** — the last component of a full SID (`S-1-5-21-<domain/machine ID>-<RID>`). Domain accounts authenticate against a Domain Controller's copy of Active Directory, not this hive; a domain user who has merely logged on to this host leaves *profile* and *event log* traces here (ProfileList, Security log) but no SAM account record — see the note below and 05b for the domain-side account object.

### Well-Known RIDs

| RID | Account | Notes |
|---|---|---|
| **500** | Built-in **Administrator** | Present on every Windows install regardless of whether it's enabled; disabled by default since Vista in favor of UAC-elevated standard accounts, but the account itself is never deleted, only disabled — a re-enabled RID 500 mid-incident is always worth asking why |
| **501** | Built-in **Guest** | Disabled by default since XP SP2; a Guest account showing recent logon activity is a strong anomaly on a modern host |
| 502 | `KRBTGT` | Domain Controller-only — Kerberos ticket-granting service account, not present in a local (non-DC) SAM hive; full depth in 05b |
| **1000+** | User-created accounts (local or domain-joined-machine local accounts) | RIDs assigned sequentially as accounts are created — a gap in the sequence, or a RID far higher than the account count would suggest, means accounts were created and later deleted; SAM does not reuse a deleted RID |

🔴 **A RID sequence with unexplained gaps is itself an artifact.** If a host has three visible local accounts (500, 501, 1005) but the next RID assigned would logically be 1001, accounts 1001–1004 existed and were deleted — ProfileList (below) is usually the fastest way to recover *what* they were even after SAM's own account record is gone, since profile folders and their SID-keyed registry entries often outlive account deletion.

### Per-Account Fields Recorded in SAM

Each user RID under `SAM\Domains\Account\Users\<RID>` carries an `F` (fixed-length) value and a `V` (variable-length) value that together hold:

| Field | What it records | Analyst value |
|---|---|---|
| **Username** | Account logon name | Ties the RID to a human-readable identity |
| **RID** | Numeric identifier (see above) | Stable even if the username is later renamed |
| **Account creation time** | Timestamp the account object was created | Same-day-as-intrusion account creation is one of the strongest "attacker made a persistence account" indicators available |
| **Last login time** | Timestamp of the account's most recent successful logon | Cross-reference against 4624 events for that account — a SAM last-login time with no corresponding 4624 in the retained Security log window means the log has rolled past that event |
| **Last password change/reset time** | Timestamp the password was last set | A password change immediately preceding or during known attacker dwell time is worth explaining — could be the attacker locking out the legitimate user, or IR/helpdesk response already in motion |
| **Login count** | Number of successful logons recorded for the account | A near-zero count on an account that supposedly has years of legitimate history is a red flag; a very high count on a newly created account across a short window suggests scripted/automated use |
| **Account flags** | Disabled / locked out / password-never-expires / password-not-required / normal account, etc. | "Password never expires" set on a freshly created account is a common attacker convenience setting, not a typical admin default |
| **Group membership (RIDs)** | Which local groups (Administrators, Remote Desktop Users, etc.) the account belongs to | Directly answers "does this account have admin rights or RDP access" without needing a live `net user` query |

Parsing: **RegRipper**'s `samparse` plugin is the fast first pass (dumps every account's RID, times, flags, and group membership from an offline `SAM` + `SYSTEM` hive pair in one report — SYSTEM is required alongside SAM because the boot key needed to unlock certain SAM structures lives in SYSTEM). **Registry Explorer** (Eric Zimmerman) opens the raw hive for manual verification or when you need to see values RegRipper's plugin doesn't surface. Live, `Get-LocalUser` / `net user <name>` (PowerShell/cmd) query the same data through the OS but carry the same live-vs-offline soundness tradeoffs covered in Registry Forensics Fundamentals.

### PowerShell

To get the live equivalent of a SAM dump, one account or all of them:

```powershell
Get-LocalUser                                    # every local account: name, enabled, last logon
Get-LocalUser -Name jsmith | Format-List *        # single account, every property including SID
Get-LocalGroup                                    # every local group and its RID-bearing SID
Get-LocalGroupMember -Group Administrators        # who actually has admin rights right now
```

To flag the account-flag and gap anomalies called out above:

```powershell
# Password-never-expires + recently created = classic attacker convenience setting
Get-LocalUser | Where-Object { $_.PasswordExpires -eq $null -and $_.PasswordLastSet -gt (Get-Date).AddDays(-30) }

# RID extracted from the SID for gap-hunting against the SAM sequence
Get-LocalUser | Select-Object Name,@{N='RID';E={($_.SID.Value -split '-')[-1]}} | Sort-Object {[int]$_.RID}
```

Before disabling or removing anything, evidence-first: export/hash the account and group state above:

```powershell
Disable-LocalUser -Name jsmith -WhatIf
Remove-LocalGroupMember -Group Administrators -Member jsmith -WhatIf
```

### Well-Known Local Group RIDs

| RID | Group | Relevance |
|---|---|---|
| 544 | **Administrators** | Full local admin rights — the group every privilege-escalation finding ultimately checks membership against |
| 545 | **Users** | Standard, unprivileged local account |
| 546 | **Guests** | Should be empty/disabled on a hardened host |
| 555 | **Remote Desktop Users** | Membership here (independent of Administrators) grants RDP logon rights — check this explicitly, since an account can RDP in without being a local admin |

## ProfileList: Enumerating Every Account That Ever Logged On

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` holds one subkey per **SID** that has ever logged on interactively to the machine — local accounts, domain accounts, service accounts that were granted an interactive profile, and Microsoft/cloud accounts alike.

| Value (under each SID subkey) | What it tells you |
|---|---|
| `ProfileImagePath` | Full path to that SID's profile folder (`C:\Users\<name>`) — the mapping from opaque SID back to a human-readable folder name |
| `Sid` (binary) | The raw SID bytes, redundant with the subkey name but occasionally useful for tool cross-checks |
| `ProfileLoadTimeLow` / `ProfileLoadTimeHigh` (newer builds) | First/last profile load timestamps on builds that record them |
| State/flags | Whether the profile is fully loaded, a mandatory/temporary profile, etc. |

🔴 **Why this is the fastest "who has ever logged onto this box" answer, even for deleted accounts:** deleting a local user account through normal means (Control Panel, `net user /delete`) removes the SAM account record but frequently leaves the `ProfileList` subkey and the on-disk profile folder behind untouched. An analyst who only checks SAM will miss every account whose SAM record is gone; checking `ProfileList` against SAM and reconciling the two is the standard move — a `ProfileList` SID with no matching SAM RID (for a local, non-domain SID) is a deleted local account, and its `ProfileImagePath` folder name is very often still the deleted account's original username even after the SAM record is gone.

This is also the fastest way to enumerate **domain accounts that logged on locally to this workstation** without a SAM record at all — their SID will resolve to a domain SID prefix (`S-1-5-21-<domain SID>-<RID>`) rather than this machine's own machine SID, distinguishing "domain user who once logged on here" from "local account." Cross-reference `ProfileImagePath` folder names against known domain usernames if the SID itself doesn't resolve (e.g., the DC is gone or unreachable).

Parsing: RegRipper's `profilelist` plugin, Registry Explorer against the offline `SOFTWARE` hive, or live via `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'`.

### PowerShell

To enumerate every profile SID and reconcile against SAM's live account list:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' |
    ForEach-Object { Get-ItemProperty $_.PSPath | Select-Object PSChildName,ProfileImagePath }
```

A `ProfileList` SID with no matching `Get-LocalUser` SID is a deleted local account (or a domain SID, distinguishable by prefix):

```powershell
$profileSids = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').PSChildName
$localSids   = (Get-LocalUser).SID.Value
Compare-Object $profileSids $localSids | Where-Object SideIndicator -eq '<='   # ProfileList-only = deleted or domain
```

## Microsoft (Cloud) Accounts vs Local Accounts

Windows 8 onward lets a user sign in with a **Microsoft (cloud) account** — an email-linked identity — instead of, or in addition to, a purely local account. The SAM hive still creates a normal local account record (RID, profile, group membership) for a cloud-linked sign-in, but a specific value distinguishes it:

| Indicator | Where | What it means |
|---|---|---|
| `InternetUserName` | Inside the account's `V` value data in `SAM\Domains\Account\Users\<RID>` | Present only when the account is linked to a Microsoft account; stores the associated email address (or `@outlook.com`/`@hotmail.com`/custom-domain alias) — the direct link between a local RID and a real-world identity/email, without needing any other artifact |
| Account type flag | Same `V` value structure | Distinguishes "local account" from "Microsoft account bound to this Windows profile" — tools that parse SAM (RegRipper `samparse`, Registry Explorer) surface this alongside the username |

🔴 **The DPAPI password substitution — the part that actually matters to an analyst.** For a Microsoft-account-linked user, Windows 10/11 does **not** store (and cannot locally verify against) the user's real cloud account password. Instead, at sign-in Windows generates a **44-character random password**, uses *that* to protect the account's DPAPI master key material locally, and caches it for offline logon. The real Microsoft-account password is verified only against Microsoft's cloud identity service when the machine has connectivity; when offline, Windows falls back to the cached 44-character surrogate for unlocking DPAPI-protected data.

Why this matters in practice: DPAPI protects an enormous amount of what an analyst wants to decrypt post-compromise — saved browser passwords, Wi-Fi keys, Credential Manager entries, some VPN client secrets. For a **local** account, DPAPI master keys can often be recovered offline given the account's actual logon password (or its NTLM hash, with the right tooling). For a **Microsoft-account-linked** user, that same offline recovery path requires the **44-character surrogate password**, not the human-memorable real password the user actually types — and that surrogate is not something you can obtain by cracking what looks like a normal password hash, nor is it something the user can "just give you." Practical implications:

- You cannot correlate a cracked/brute-forced "password" for a Microsoft-account-linked user directly to their real cloud credential — what you'd be attacking is the random surrogate, and there is nothing meaningful to crack it *into*.
- Live extraction of the cached 44-character surrogate (where recoverable from LSA secrets/DPAPI cache while the system is running or the correct keys are available) is the realistic offline-decryption path for cloud-linked accounts, not a password-guessing attack.
- When reporting DPAPI-protected findings (recovered browser passwords, etc.) tied to a Microsoft-account user, be explicit that the underlying key material traces to the surrogate password, not the account's real, human-usable credential — the two must not be conflated in a report.
- The `InternetUserName` email value is still the correct field to cite when you need to say "this local profile corresponds to this real-world email identity" — it's an identity link, not a credential.

## Logon Types (Event ID 4624 / 4625)

Every successful (4624) or failed (4625) logon carries a **Logon Type** field — the single most-referenced value in Windows authentication forensics. Full reference:

| Type | Name | What it means | Typical legitimate source | 🔴 Suspicious when |
|---|---|---|---|---|
| 0 | System | Used only by the `System` account at boot | Boot sequence | Essentially never seen outside boot; anomalous elsewhere |
| **2** | **Interactive (Console)** | Logon at the physical keyboard/console | Someone physically at the machine | Off-hours console logon on a server with no expected physical access |
| **3** | **Network** | Authenticated connection over the network — SMB share access, `net use`, most service-to-service auth | Mapped drives, file share access, many lateral-movement tools | Repeated Type 3 attempts from one source (spray pattern), or Type 3 success from an unfamiliar external/internal IP |
| **4** | **Batch** | Scheduled Task execution | Task Scheduler-launched jobs | A batch logon for an account that shouldn't have scheduled tasks, or timed suspiciously close to a persistence event |
| **5** | **Service** | Service startup using stored credentials | Windows services starting at boot or on-demand | A service logon for a newly created service around the time of an intrusion |
| **7** | **Unlock** | Workstation unlock **or** reconnect to an existing disconnected RDP session | User returning to keyboard, or RDP client reconnecting | Unlock at an unusual hour, or immediately following an unexplained disconnect |
| **8** | **NetworkCleartext** | Network logon where credentials were sent in cleartext to the authenticating machine (e.g., IIS Basic authentication) | Legacy web-auth scenarios, some scripted/basic-auth integrations | Any modern host doing this routinely suggests a legacy/misconfigured auth path worth hardening, and cleartext creds in transit are themselves a risk regardless of intrusion status |
| **9** | **NewCredentials** | `runas /netonly`-style — process keeps its original logon session but presents alternate credentials for outbound network connections | Legitimate admin use of `runas /netonly` for cross-credential remote administration | A very common lateral-movement/credential-testing pattern (e.g., pass-the-hash tooling) — always cross-reference against a nearby **4648** (below) |
| **10** | **RemoteInteractive** | RDP logon | Legitimate remote desktop administration/use | Outside business hours, from an unfamiliar source, or immediately following a burst of 4625 failures on the same account (brute-force-then-success) |
| **11** | **CachedInteractive** | Interactive logon using **cached domain credentials** because a Domain Controller wasn't reachable | Laptop logging on off-network (no VPN yet), DC outage | A domain account cached-logging-on while the DC is actually reachable is unusual and worth explaining |
| **12** | **CachedRemoteInteractive** | RDP logon using cached domain credentials (DC unreachable at logon time) | Same DC-unavailability scenario as Type 11, over RDP | Same reasoning as Type 11 — check whether DC unavailability was real or the account/session was manipulated |
| **13** | **CachedUnlock** | Unlock event using cached domain credentials | Workstation unlock while disconnected from the domain | Same DC-unavailability caveat as Types 11/12 |

### PowerShell

Pull 4624/4625 events natively, most-recent first:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625} -MaxEvents 200
```

Decode the Logon Type field (property index 8 for 4624, differs slightly by event schema — verify against `$_.Properties` for the specific ID) into the plain-English names from the table above:

```powershell
$logonTypeName = @{0='System';2='Interactive';3='Network';4='Batch';5='Service';7='Unlock';
    8='NetworkCleartext';9='NewCredentials';10='RemoteInteractive';11='CachedInteractive';
    12='CachedRemoteInteractive';13='CachedUnlock'}

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 500 | ForEach-Object {
    [pscustomobject]@{
        Time      = $_.TimeCreated
        Account   = $_.Properties[5].Value
        LogonType = $logonTypeName[[int]$_.Properties[8].Value]
        Source    = $_.Properties[18].Value
    }
}
```

Correlate 4624→4634 by Logon ID to compute session duration, and hunt across multiple hosts at once:

```powershell
# Session duration for one host: pair each 4624's Logon ID with its closing 4634
$logons  = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 1000
$logoffs = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4634} -MaxEvents 1000
foreach ($l in $logons) {
    $logonId = $l.Properties[7].Value
    $off = $logoffs | Where-Object { $_.Properties[3].Value -eq $logonId } | Select-Object -First 1
    if ($off) { [pscustomobject]@{ Account=$l.Properties[5].Value; LogonId=$logonId; Logon=$l.TimeCreated; Logoff=$off.TimeCreated; Duration=($off.TimeCreated - $l.TimeCreated) } }
}

# Cross-host: same query fanned out via PSRemoting, exported for timeline pivoting
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4625;StartTime=(Get-Date).AddDays(-7)}
} | Select-Object PSComputerName,TimeCreated,Id | Export-Csv .\fleet_logons.csv -NoTypeInformation
```

## Core Authentication & Account Event IDs

All events below are logged to `Security.evtx` on the **local host** unless marked DC-only. Field-level parsing/collection mechanics for the Security log generally are covered in **Event Log Analysis (11)**; this table is the account/authentication-specific subset.

| Event ID | Name | What it tells you | Logged where |
|---|---|---|---|
| **4624** | Logon success | Account, Logon Type, source IP/workstation, logon package (NTLM/Kerberos), new Logon ID | Local `Security.evtx` (every host) |
| **4625** | Logon failure | Same fields as 4624 plus a failure reason/status code (bad password, account disabled, account locked, time restriction, etc.) | Local `Security.evtx` |
| **4634** | Logoff | Closes out a Logon ID opened by a 4624 — pair the two by Logon ID to compute session duration | Local `Security.evtx` |
| **4647** | User-initiated logoff | Same purpose as 4634, specifically for an explicit user-driven logoff rather than session teardown by other means | Local `Security.evtx` |
| **4648** | Logon with explicit credentials | A process running as one account explicitly authenticates as a *different* account (`runas`, mapped drives with alternate creds, some lateral-movement tooling) | Local `Security.evtx` — **see dedicated section below** |
| **4672** | Special privileges assigned to new logon | Fires alongside a 4624 when the logon carries admin-equivalent rights (SeDebugPrivilege, SeTcbPrivilege, etc.) | Local `Security.evtx` — correlate by Logon ID with its paired 4624 to see *which* logon type got admin rights |
| **4720** | User account created | New account, initiator, timestamp | Local `Security.evtx` (local account) / DC (domain account, full depth in 05b) |
| 4722 / 4725 / 4726 / 4724 / 4738 | Account lifecycle siblings (enabled / disabled / deleted / password reset / account changed) | Same lifecycle family as 4720 — full event-by-event depth deferred to Event Log Analysis (11) | Local `Security.evtx` |
| **4800 / 4801** | Workstation locked / unlocked | Pairs with Logon Type 7/13 above — bounds the "away from keyboard" window during an active session | Local `Security.evtx` |
| **4776** | NTLM credential validation attempt | The **DC or local SAM** validated an NTLM credential — success/failure and the calling workstation name; the primary NTLM-specific auth event when Kerberos isn't in play | Local `Security.evtx` (validating a local SAM account) or DC (validating a domain account) |
| 4768 | Kerberos TGT (Authentication Service) request | Initial ticket-granting-ticket issuance — full field depth in 05b | **Domain Controller only** |
| 4769 | Kerberos service ticket (Ticket-Granting Service) request | Ticket for a specific service — full field depth in 05b | **Domain Controller only** |
| 4771 | Kerberos pre-authentication failed | Failed Kerberos logon attempt, precursor to brute-force/spray detection on Kerberos — full field depth in 05b | **Domain Controller only** |

### PowerShell

Pull the account-lifecycle and privilege events natively by ID:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672,4720,4722,4725,4726,4724,4738} -MaxEvents 200
```

Filter 4776 (NTLM validation) to a specific account/workstation pair, success vs failure:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4776} -MaxEvents 500 | ForEach-Object {
    [pscustomobject]@{
        Time    = $_.TimeCreated
        Account = $_.Properties[1].Value
        Source  = $_.Properties[0].Value
        Success = $_.Id -eq 4776 -and $_.Properties[3].Value -eq 0   # non-zero Properties[3] = failure code
    }
}
```

Kerberos-specific decoding of 4768/4769/4771 (Domain Controller-only) is covered in **Active Directory & Domain Forensic Artifacts (05b)**; high-volume/XPath-filtered `Get-WinEvent` querying for speed at scale is covered in **Event Log Analysis (11)** rather than duplicated per event ID here.

## 4648: Explicit Credentials — The Lateral Movement Tell

🔴 **4648 deserves its own callout because it is one of the most reliable lateral-movement indicators available on a single host.** It fires whenever a process explicitly supplies credentials different from the ones its own logon session already holds — the canonical `runas /user:` pattern, but also the mechanism underlying many attacker tools that pivot using a harvested credential (mapped drives with alternate creds, some PsExec-style invocations, credential-switching malware).

What to check on every 4648:

- **Subject account vs Target account** — the account that *initiated* the explicit-credential logon vs the account whose credentials were *used*. A mismatch where the subject account has no legitimate reason to hold or use the target account's credentials is the core anomaly.
- **Target Server Name** — where those credentials were then used; chain this against the destination host's own 4624 (Type 3 or Type 9-adjacent) to confirm the credential actually reached its target.
- **Timing against 4625 clusters** — 4648 immediately following a burst of failed logons for the same target account suggests credential validation succeeded just before the explicit-credential use.
- **Pair with Logon Type 9** — a Type 9 (NewCredentials) 4624 on the source host and a 4648 close in time are frequently two views of the same `runas /netonly`-style event; seeing one without a plausible explanation for the other is worth chasing.

### PowerShell

Pull Subject vs Target account side by side, the core anomaly check for this event:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} -MaxEvents 500 | ForEach-Object {
    [pscustomobject]@{
        Time           = $_.TimeCreated
        SubjectAccount = $_.Properties[1].Value
        TargetAccount  = $_.Properties[5].Value
        TargetServer   = $_.Properties[8].Value
    }
} | Where-Object { $_.SubjectAccount -ne $_.TargetAccount }
```

## RDP Usage Tracking

This note's scope is the **account/authentication angle** of RDP — confirming *who* connected, *as what account*, *when*, and whether the pattern looks like legitimate remote administration or brute-force/lateral movement. The full RDP artifact chain (client-side `Terminal Server Client\Servers` registry history, bitmap cache reconstruction, jump list evidence of RDP client use) is deferred to the forthcoming **Lateral Movement** note — duplicating that depth here would just be the same tables twice.

| Event ID | Name | What it tells you | Logged where |
|---|---|---|---|
| **4624** (Type 10) | RDP logon success | Account, source IP, Logon ID — the authentication half of an RDP session | Destination host's `Security.evtx` |
| **4778** | Session reconnected | An existing RDP session was reattached (client reconnect, or resuming after a network blip) — includes source workstation/IP | Destination host's `Security.evtx` |
| **4779** | Session disconnected | RDP session went to a disconnected (not logged off) state — pairs with 4778 to bound how long a session sat disconnected before reconnecting | Destination host's `Security.evtx` |

Cross-reference these three against Logon Type 10's row in the triage table below for what pattern of Type-10 + 4778/4779 timing should raise suspicion.

### PowerShell

Pull RDP-specific logon (Type 10) and session reconnect/disconnect events natively:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4778,4779} |
    Where-Object { $_.Id -ne 4624 -or $_.Properties[8].Value -eq 10 }
```

Same query fanned out across a fleet, exported for pivoting into a timeline:

```powershell
Invoke-Command -ComputerName (Get-Content .\hosts.txt) -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624,4778,4779;StartTime=(Get-Date).AddDays(-14)} |
        Where-Object { $_.Id -ne 4624 -or $_.Properties[8].Value -eq 10 }
} | Select-Object PSComputerName,TimeCreated,Id | Export-Csv .\fleet_rdp_sessions.csv -NoTypeInformation
```

The client-side registry/bitmap-cache/jump-list depth for confirming an RDP client was *used* (not just the server-side auth events above) belongs in the forthcoming **Lateral Movement** note per this note's existing scope note above.

## Logon-Type Triage: What to Suspect

Given a 4624/4625 with a specific Logon Type, source, and account, here's the first-pass read before deeper investigation:

| Logon Type | Context observed | First-pass suspicion |
|---|---|---|
| 3 (Network) | Success from an unfamiliar external IP | Possible network-based attack (SMB/share enumeration, external actor who already has a foothold reaching this host) — check for a preceding 4625 cluster on the same account |
| 3 (Network) | Many failures across many accounts, same source | Password spray — tally accounts-per-source, not just failures-per-account |
| 9 (NewCredentials) | Any occurrence without known admin `runas` usage | `runas`-style credential switch — pull nearby 4648 events to confirm and identify the target account/host |
| 10 (RemoteInteractive) | Success outside business hours, or from a source IP with no prior RDP history for that account | Possible RDP brute-force-then-success — check the immediately preceding window for a 4625 burst on the same account/source, and pair with 4778 to see how long the session persisted |
| 10 (RemoteInteractive) | Success on a server, source = internal admin subnet, business hours | Routine administrative RDP — lowest-priority read, but still worth confirming against a change ticket if the environment tracks them |
| 4 (Batch) | Logon tied to an account with no expected scheduled tasks | Correlate with Persistence Mechanisms → Scheduled Tasks — may indicate a newly created malicious task |
| 5 (Service) | Logon for a newly created service around intrusion timeframe | Correlate with Persistence Mechanisms → Services — classic service-based persistence tell |
| 7 (Unlock) | Unlock immediately after an unexplained 4779 disconnect | May indicate a reconnect to a session established by someone other than the expected user |
| 11/12/13 (Cached*) | Cached-credential logon while the Domain Controller is actually reachable | Unexpected — cached logons should only occur when the DC genuinely can't be reached; investigate why the cache path was used |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| RID 500 (built-in Administrator) re-enabled with a recent password-change timestamp | Classic re-activation of the default admin account for persistence/lateral movement |
| A user RID with an account-creation timestamp inside the known intrusion window | Attacker-created local account for persistence |
| `ProfileList` SID with no corresponding SAM RID (local machine SID) | Account was deleted, but the profile folder/registry trace survives — recover the original username from `ProfileImagePath` |
| `InternetUserName` present on an account no one recalls being cloud-linked | Confirms a Microsoft-account sign-in occurred on this host — worth tying to the associated email for identity correlation |
| DPAPI recovery attempted using a Microsoft-account-linked user's real password | Won't work — that account's DPAPI keys are protected by the cached 44-character surrogate, not the real credential |
| 4648 where Subject Account and Target Account differ with no documented admin reason | Explicit-credential (lateral movement) tell — chain against the Target Server Name's own logon events |
| Logon Type 9 with no paired 4648 nearby | Incomplete picture — look harder for the corresponding explicit-credential event, possibly on a different host in the chain |
| Logon Type 10 success immediately following a 4625 cluster on the same account | Brute-force-then-success pattern |
| 4776 NTLM validation for an account/host pair on a network where Kerberos should be in use | Possible NTLM downgrade / forced-authentication attack, or simply a legacy client — confirm before concluding either way |
| RID sequence gaps in SAM with no corresponding `ProfileList` explanation | Deleted accounts whose profile trace was itself cleaned up — treat as a stronger anomaly than a gap that ProfileList explains |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Hive structure, live vs offline SAM/SOFTWARE acquisition, transaction-log gotchas | **Registry Forensics Fundamentals** |
| Domain accounts, Kerberos ticket internals (4768/4769/4771 field depth), AD replication metadata, delegation abuse | **Active Directory & Domain Forensic Artifacts** (05b) |
| Full RDP artifact chain — client-side connection history, bitmap cache, jump lists | **Lateral Movement** (forthcoming) |
| Broader Security/System/Application event log collection, retention, and the account-lifecycle sibling events (4722/4725/4726/4724/4738) in full | **Event Log Analysis** |
| DPAPI-protected browser passwords and other credential stores on disk | **Web Browser Forensics** (Chromium/Firefox notes, forthcoming) |
| Session model (Session 0 vs interactive sessions) underlying logon type behavior | **Windows OS Fundamentals & Versions** |

## Resources

- SANS FOR500 course syllabus (public) — SAM hive/local user profiling, ProfileList, cloud account details, logon event coverage checklist
- SANS FOR508 "Hunt Evil" poster — Account Usage panel (logon types, 4624/4625/4634/4647/4672/4800/4801, RDP session events)
- Microsoft Learn — Audit logon events: https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624
- Microsoft Learn — Windows security event IDs reference: https://learn.microsoft.com/windows/security/threat-protection/auditing/
- Microsoft Learn — How Windows uses the DPAPI to protect data: https://learn.microsoft.com/windows/win32/seccng/cng-dpapi
- RegRipper (samparse, profilelist plugins) — https://github.com/keydet89/RegRipper3.0
- Eric Zimmerman's tools (Registry Explorer) — https://ericzimmerman.github.io/
