# Active Directory & Domain Forensic Artifacts

Everything in note 05 (Users, Groups & Authentication) lives and dies on the workstation — `SAM`, local logon types, `4624`/`4625` on the box the user sat at. The moment a domain is in play, a second, parallel evidence trail opens up on the **Domain Controller**, and it records things a workstation never can: Kerberos ticket issuance, replication traffic, and directory-object changes. Most Golden Ticket, Kerberoasting, and DCSync detections live or die on whether the analyst thought to pull the DC's `Security.evtx` at all — a huge fraction of "we found nothing" domain-compromise reviews are actually "we only looked at the workstation."

This note assumes the workstation-side authentication model (interactive vs network logon, 4624/4625) is already covered — see note 05 — and builds the domain layer on top of it: Kerberos mechanics, the specific DC-side event IDs each ticket type produces, the four classic Kerberos abuse techniques and how each one breaks the normal event pattern, DCSync/replication abuse, AD replication metadata for timeline corroboration, and a brief flag on SID history/trust abuse. GPO/SYSVOL forensics, including the legacy GPP `cpassword` flaw, now has its own standalone folder — see [`GPO/`](<GPO/00 - GPO Fundamentals and Architecture.md>).

> 🔴 **The single most common mistake in a domain-compromise review: never pulling the Domain Controller's Security log.** Kerberos ticket events (4768/4769/4770/4771), the DCSync replication signature (4662), and GPO/SYSVOL object-change events (5136) do not exist on the workstation — they only exist on the DC that serviced the request. If your evidence list is "the compromised workstation's Security.evtx" and stops there, you have no way to see a Golden Ticket, a Kerberoasting spree, or a DCSync pull, no matter how carefully you re-read that one host's log.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why This Is Its Own Note](#why-this-is-its-own-note)
- [Kerberos Fundamentals for DFIR](#kerberos-fundamentals-for-dfir)
  - [TGT vs Service Ticket](#tgt-vs-service-ticket)
  - [The Authentication Flow](#the-authentication-flow)
  - [DC-Side Event IDs](#dc-side-event-ids)
- [Kerberos Abuse Techniques and Their DFIR Signatures](#kerberos-abuse-techniques-and-their-dfir-signatures)
  - [Golden Ticket](#golden-ticket)
  - [Silver Ticket](#silver-ticket)
  - [Kerberoasting](#kerberoasting)
  - [AS-REP Roasting](#as-rep-roasting)
- [DCSync / Replication Abuse](#dcsync--replication-abuse)
- [AD Replication Metadata for Timeline Corroboration](#ad-replication-metadata-for-timeline-corroboration)
- [Domain Trust and SID History Abuse](#domain-trust-and-sid-history-abuse)
- [Where These Events Actually Live](#where-these-events-actually-live)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Domain-side triage — unlike most other notes in this module, this one is **not purely native**: it assumes the `ActiveDirectory` PowerShell module (an RSAT feature, not shipped by default on a workstation, though it is present on every Domain Controller and any admin workstation with RSAT installed). Where a fully native no-module fallback exists it's called out separately elsewhere in this note. (For GPO/SYSVOL friendly-name↔GUID resolution and other no-RSAT-required fallbacks, see [`GPO/00`](<GPO/00 - GPO Fundamentals and Architecture.md>) and [`GPO/03`](<GPO/03 - Domain Controller GPO Investigation.md>).)

```powershell
# SPNs on privileged (AdminSDHolder-protected) accounts - Kerberoastable, and a high-value SPN misconfiguration
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName,AdminCount |
    Where-Object AdminCount -eq 1 | Select-Object Name,ServicePrincipalName

# Accounts flagged "Do not require Kerberos preauthentication" - AS-REP roastable by design, flag even absent active abuse
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

# Unconstrained delegation (TRUSTED_FOR_DELEGATION) - historically the highest-value delegation misconfiguration to find
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation,servicePrincipalName
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Constrained delegation - which accounts can impersonate users to a specific list of target services
Get-ADObject -Filter {'msDS-AllowedToDelegateTo' -like '*'} -Properties msDS-AllowedToDelegateTo,servicePrincipalName |
    Select-Object Name,msDS-AllowedToDelegateTo

# Resource-based constrained delegation - set on the resource (target) rather than the front-end account, easy to miss
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } | Select-Object Name

# Principals holding DCSync-capable extended rights on the domain object - anything other than DCs/Domain-Enterprise Admins is a finding
(Get-Acl "AD:\$((Get-ADDomain).DistinguishedName)").Access |
    Where-Object { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
    Select-Object IdentityReference,ActiveDirectoryRights

# Most recently changed attributes on krbtgt - corroborates or contradicts a claimed timeline for a suspected Golden Ticket / krbtgt reset event
Get-ADReplicationAttributeMetadata -Object (Get-ADUser krbtgt).DistinguishedName -Server (Get-ADDomainController).HostName |
    Sort-Object LastOriginatingChangeTime -Descending | Select-Object -First 5 AttributeName,LastOriginatingChangeTime,LastOriginatingChangeDirectoryServerIdentity
```

## Why This Is Its Own Note

Host forensics (notes 01-05) answers "what did this machine do." Domain forensics answers a different question: "did this machine — or an attacker holding a stolen credential — get the domain itself to do something on its behalf." That second question can only be answered from the DC, because the DC is the only system that:

- issues and validates every Kerberos ticket on the domain,
- replicates password-hash data between DCs (and can be tricked into replicating it to something that isn't a DC),
- stores the authoritative copy of every GPO and every directory object, with its own change-tracking metadata.

None of that is visible from a compromised workstation's own logs — it's visible only from the DC(s) servicing that workstation's requests, which is why this note exists as its own section rather than a subsection of note 05.

## Kerberos Fundamentals for DFIR

### TGT vs Service Ticket

| | Ticket Granting Ticket (TGT) | Service Ticket (ST) |
|---|---|---|
| Issued by | Key Distribution Center (KDC) — Authentication Service (AS) role, which runs on every DC | KDC — Ticket Granting Service (TGS) role, also on every DC |
| Proves | "This principal authenticated to the domain and is who they say they are" | "This principal is authorized to use *this specific service*" |
| Encrypted with | The **krbtgt** account's password hash (domain-wide, shared by all DCs) | The **target service account's** password hash (or the computer account's hash, for machine-based services) |
| Lifetime (default) | 10 hours, renewable up to 7 days (domain default policy — tunable) | 10 hours (tied to the TGT's remaining lifetime, tunable) |
| Used for | Requesting service tickets from the TGS — a client never touches a service directly with a TGT | Presenting directly to the target service (a file share, a SQL instance, an HTTP service running under a service account, etc.) to get access |
| Forensic weight | Compromise of the krbtgt hash = forge *any* TGT for *any* user, domain-wide, indefinitely until krbtgt is reset (twice) | Compromise of one service account's hash = forge tickets for *that service only* |

### The Authentication Flow

```
Client (workstation)                         KDC / Domain Controller
      │                                                │
      │ 1. AS-REQ  (I am <user>, here's my             │
      │    pre-auth encrypted with my password hash)   │
      ├───────────────────────────────────────────────▶│
      │                                                │  DC validates pre-auth,
      │                                                │  builds TGT encrypted
      │                                                │  with krbtgt hash
      │ 2. AS-REP  (session key + TGT)                 │
      │◀───────────────────────────────────────────────┤
      │                                                │
      │  ... client now holds a TGT, cached ...        │
      │                                                │
      │ 3. TGS-REQ (here's my TGT, I want a             │
      │    ticket for service X)                       │
      ├───────────────────────────────────────────────▶│
      │                                                │  DC validates TGT,
      │                                                │  builds ST encrypted
      │                                                │  with service acct hash
      │ 4. TGS-REP (session key + service ticket)      │
      │◀───────────────────────────────────────────────┤
      │                                                │
      │ 5. Client presents ST directly to the target service (not shown — no DC round trip)
```

- **Pre-authentication** (step 1) is what stops an offline password-guessing attack against the AS-REQ itself — the client must prove it already knows the password (by encrypting a timestamp with a hash derived from it) *before* the KDC will issue anything. Accounts with **"Do not require Kerberos preauthentication"** set skip this check — see AS-REP Roasting below.
- Steps 1-2 happen **once per logon session** (or on TGT renewal); steps 3-4 happen **every time the client wants to reach a new service** — this is why you see far more 4769 events than 4768 events in a busy environment.

### DC-Side Event IDs

These four event IDs are logged **only on the Domain Controller that services the request** — never on the requesting workstation.

| Event ID | Name | Fires when | Key fields to pull |
|---|---|---|---|
| **4768** | A Kerberos authentication ticket (TGT) was requested | AS-REQ/AS-REP exchange succeeds — i.e., a TGT was issued | Account Name, Client Address, **Ticket Encryption Type** (`0x12`=AES256, `0x17`=RC4), **Pre-Authentication Type** |
| **4769** | A Kerberos service ticket was requested | TGS-REQ/TGS-REP exchange succeeds — i.e., a service ticket was issued | Account Name (requesting principal), **Service Name** (the SPN/account the ticket is for), Client Address, Ticket Encryption Type, **Failure Code** (0x0 = success) |
| **4770** | A Kerberos service ticket was renewed | A client renews an existing service ticket rather than requesting a fresh one | Account Name, Service Name, Client Address |
| **4771** | Kerberos pre-authentication failed | AS-REQ pre-auth check fails (wrong password, clock skew, etc.) — the TGT is **not** issued | Account Name, Client Address, **Failure Code** (`0x18` = bad password is the common one) |

🔴 Contrast with the workstation-side model in note 05: **4624/4625 record the *result* of a logon on the machine the user sat down at or connected to; 4768/4769/4770/4771 record the *Kerberos ticket transactions* on the DC that made that logon possible.** A single interactive domain logon can produce a 4768 and a 4769 on the DC, plus a 4624 on the workstation — three events, two different hosts' logs, all describing one action.

## Kerberos Abuse Techniques and Their DFIR Signatures

| Technique | What's forged / abused | DC event signature | Red flag detail |
|---|---|---|---|
| **Golden Ticket** | A TGT is forged entirely offline using the domain's **krbtgt** account hash — no DC round trip needed to mint it | The forged TGT is later used to request service tickets, producing **4769 events with no corresponding legitimate 4768** for that logon session; if the attacker also forges timestamps/lifetimes, tickets may show unusually long lifetimes (default policy exceeded) | **RC4 (0x17) ticket encryption in a domain that has been AES-only (0x12) for years** is the classic tell — many Golden Ticket tools default to RC4 even when Mimikatz/impacket support AES, so an RC4-encrypted TGT/ST appearing in an AES-standardized environment is a strong signal; also watch for a TGT used for services in a different domain/forest than where it was issued when SID history is forged alongside it |
| **Silver Ticket** | A **service ticket** is forged directly using one **service account's** (or computer account's) password hash — the krbtgt is never touched, and no TGT is involved at all | **No 4769 on the DC for that service ticket** (it was never actually requested from the TGS — it was minted offline) — the *first* the DC or the service itself ever "sees" of the session may be the service being accessed directly, often with **no 4768 either**, since Silver Ticket doesn't require any TGT at all | The complete absence of *both* 4768 and 4769 events for a service access event that clearly happened (visible in the service's own application log, or in file-share access) is the signature — Silver Ticket abuse is invisible to Kerberos event logging by design, which is precisely why it's the harder of the two to catch via DC logs alone |
| **Kerberoasting** | Any authenticated domain user requests service tickets for accounts that have an **SPN (Service Principal Name)** set — service tickets are encrypted with the *target* account's password hash, so the requester takes the ticket offline and brute-forces/cracks the service account's password | **Unusual volume of 4769 events, encryption type `0x17` (RC4)**, requested by a single account against **multiple distinct SPNs in a short window** — a normal user rarely legitimately requests service tickets for more than one or two services in a session, let alone a batch of unrelated SPNs in seconds | RC4 (`0x17`) stands out sharply once you know most modern AD environments prefer AES for service tickets when the target account supports it — tools requesting RC4 explicitly (to make offline cracking cheaper) against an AES-capable domain is the strongest single indicator; also flag **high-privilege service accounts with SPNs set** (common misconfiguration) being targeted |
| **AS-REP Roasting** | Targets accounts with **"Do not require Kerberos preauthentication"** enabled — the KDC will issue a TGT (AS-REP) to *anyone* who asks for that account, no password proof required up front, and the AS-REP is encrypted with a key derived from the account's password, crackable offline | **A 4768 (TGT issued) with no preceding 4771** for that account, or a 4768 whose Pre-Authentication Type field shows no pre-auth was performed — compare against that same account's normal logon pattern, where a legitimate password-based logon always shows pre-auth | Any account with "Do not require Kerberos preauthentication" set is inherently AS-REP-roastable — flag the UAC-flag setting itself as a finding even before you see abuse, and treat repeated/scripted 4768 requests for the same no-preauth account from a single source as active roasting in progress |

### PowerShell

To pull the raw properties each technique above actually depends on for one account (requires `ActiveDirectory` module):

```powershell
Get-ADUser -Identity <samAccountName> -Properties ServicePrincipalName,DoesNotRequirePreAuth,TrustedForDelegation,userAccountControl
```

To decode the raw `userAccountControl` bitmask directly — useful when working from a raw LDAP/ADSI dump that has no derived boolean properties to fall back on:

```powershell
$flags = @{
    0x800000  = 'DONT_REQUIRE_PREAUTH'           # AS-REP Roastable
    0x80000   = 'TRUSTED_FOR_DELEGATION'          # Unconstrained delegation
    0x1000000 = 'TRUSTED_TO_AUTH_FOR_DELEGATION'  # Constrained delegation w/ protocol transition
}
$uac = (Get-ADUser <samAccountName> -Properties userAccountControl).userAccountControl
$flags.Keys | Where-Object { $uac -band $_ } | ForEach-Object { $flags[$_] }
```

To cross-reference every SPN-bearing or no-preauth account against actual DC-side ticket volume, separating "roastable" (a static exposure) from "being actively roasted" (an event):

```powershell
$targets = Get-ADUser -Filter {ServicePrincipalName -like '*' -or DoesNotRequirePreAuth -eq $true} -Properties ServicePrincipalName,DoesNotRequirePreAuth
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName='Security';Id=4768,4769} -MaxEvents 5000 |
        Where-Object { $targets.SamAccountName -contains ($_.Properties[0].Value -replace '\$$','') } |
        Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 10 Count,Name
}
```

Before touching any account, capture the evidence above (SPN list, UAC flags, ticket volume). Removing the underlying exposure is itself native:

```powershell
# Kerberoasting exposure: remove the SPN, or rotate/lengthen the account's password so an offline crack is infeasible
Set-ADUser -Identity <samAccountName> -ServicePrincipalNames @{Remove='<SPN-value>'}

# AS-REP Roasting exposure: require preauth
Set-ADAccountControl -Identity <samAccountName> -DoesNotRequirePreAuth $false

# Unconstrained delegation exposure: remove the flag (confirm nothing legitimate depends on it first - this can break production delegation)
Set-ADAccountControl -Identity <samAccountName> -TrustedForDelegation $false
```

## DCSync / Replication Abuse

**DCSync** abuses the legitimate Active Directory replication protocol (MS-DRSR, over RPC) to make a domain controller believe the requester *is* another domain controller asking to replicate data — including password hashes — rather than exploiting a bug. Any principal holding the right AD permissions can run it without ever touching a real DC's disk or memory.

- **Permissions required** (either is sufficient, both are commonly granted together): **Replicating Directory Changes** and **Replicating Directory Changes All** — these are Active Directory *extended rights*, normally held only by Domain Controllers, Domain Admins, Enterprise Admins, and a small number of built-in service accounts (e.g., Azure AD Connect/Entra Connect's sync account, which is why that account is such a high-value target).
- The attack: from any host with network access to a DC and an account holding those rights, request replication of a target object (commonly `krbtgt` or a Domain/Enterprise Admin) — the DC dutifully replicates the requested attributes, including the NT hash, back to the requester, exactly as it would to a peer DC.
- **Event signature: Event ID 4662** ("An operation was performed on an object") on the DC (specifically observable on the PDC emulator, since it's authoritative for many replication-triggering operations), where the **Object Type/Properties field references the replication GUIDs** for `DS-Replication-Get-Changes` (`{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}`) and `DS-Replication-Get-Changes-All` (`{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`).

🔴 **The 4662 replication-GUID event is a major red flag when the source computer in the event is anything other than a Domain Controller.** Legitimately, only DCs replicating with each other generate this event — a 4662 with these replication GUIDs sourced from a workstation, a member server, or any account/host that is not itself a DC is one of the highest-confidence single-event indicators of credential-dumping-via-replication in the entire Windows event catalog. Requires Advanced Auditing / object-level SACL auditing to be enabled on the relevant AD objects to actually generate — confirm audit policy is on before concluding "no DCSync happened" from an absence of 4662 events.

### PowerShell

To pair the ACL check from Hunt Evil above (which principals *hold* DCSync-capable rights) with the actual 4662 events on the DC, filter to sources that aren't themselves a DC — the real red flag, not just the permission grant (requires `ActiveDirectory` module):

```powershell
$dcs = (Get-ADDomainController -Filter *).Name
Get-WinEvent -ComputerName (Get-ADDomainController).HostName -FilterHashtable @{LogName='Security';Id=4662} |
    Where-Object { $_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
    Where-Object { ($_.Properties[1].Value -replace '\$$','') -notin $dcs }
```

## AD Replication Metadata for Timeline Corroboration

Every AD object carries built-in change-tracking attributes independent of the Security event log — useful when you need to corroborate (or contradict) a claim about *when* an object was actually last modified, especially if event logs have rolled over or auditing wasn't enabled at the time:

| Attribute / tool | What it tells you |
|---|---|
| `whenCreated` | Timestamp the object was originally created in AD |
| `whenChanged` | Timestamp of the object's most recent attribute change (any attribute, any DC) — coarse, object-level, not per-attribute |
| `uSNChanged` (Update Sequence Number) | A monotonically increasing, per-DC counter — not a timestamp, but establishes strict *ordering* of changes, and diverges across DCs until replication converges, which itself can flag replication problems or a change made on an unexpected DC |
| `repadmin /showobjmeta <object DN>` | The single most useful command here — dumps **per-attribute** replication metadata: which attribute changed, the **originating DC**, the **local and originating change timestamps**, the version number, and the USN at time of change. This is where you get attribute-level granularity that `whenChanged` alone can't give you (`whenChanged` only tells you *an* attribute changed, not which one or from where) |

Use case: an attacker claims (or a suspicious log entry suggests) that a group membership or GPO link was modified at a specific time — `repadmin /showobjmeta` against that object will show you the actual originating DC and timestamp for that specific attribute's last write, which either corroborates or directly contradicts the claim, independent of whether Security-log auditing was even enabled for that change at the time.

### PowerShell

The PowerShell-native equivalent of `repadmin /showobjmeta` (requires `ActiveDirectory` module):

```powershell
Get-ADReplicationAttributeMetadata -Object '<object DN>' -Server '<DC-FQDN>'
```

To narrow to one attribute and sort so the most recent write is on top, directly answering "when/where was this specific attribute last changed":

```powershell
Get-ADReplicationAttributeMetadata -Object '<object DN>' -Server '<DC-FQDN>' -Properties member |
    Select-Object AttributeName,LastOriginatingChangeTime,LastOriginatingChangeDirectoryServerIdentity,Version
```

To pull metadata for the same object from every DC and compare, catching replication divergence or a change accepted by a DC other than the one expected:

```powershell
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    Get-ADReplicationAttributeMetadata -Object '<object DN>' -Server $dc |
        Select-Object @{N='DC';E={$dc}},AttributeName,LastOriginatingChangeTime,Version
}
```

> 📁 **Group Policy Object (GPO) forensics — SYSVOL/AD-object location, malicious-change detection, event 5136, and the legacy GPP `cpassword` flaw — now has its own standalone folder: [`GPO/`](<GPO/00 - GPO Fundamentals and Architecture.md>).** Start at [`GPO/03 - Domain Controller GPO Investigation`](<GPO/03 - Domain Controller GPO Investigation.md>) for the DC/AD-object-side workflow this section previously covered (it leans on this note's `repadmin /showobjmeta` mechanics below, applied specifically to a GPO object).

## Domain Trust and SID History Abuse

Trust relationships (parent/child domains within a forest, or explicit cross-forest trusts) let a security principal authenticated in one domain be granted access to resources in another. **SID history** is the specific mechanism most commonly abused here: it's an attribute meant to preserve a user's old SIDs across a legitimate domain migration (so access based on the old SID keeps working), but if an attacker can write to it directly (typically requiring the same krbtgt-level compromise that enables Golden Ticket forgery), they can inject the SID of a highly privileged group — Enterprise Admins, for example — into a low-privileged account's SID history, or into a forged ticket's PAC (Privilege Attribute Certificate), granting that account's tickets privileges it was never actually assigned through normal group membership.

🔴 This is a brief flag, not a deep-dive here — treat any of the following as reasons to escalate scope to a full cross-domain/forest review: an account's SID history containing SIDs from a domain it was never legitimately migrated from; forged tickets carrying SID history entries for privileged groups in a *different* domain than the one that issued the ticket; unexplained access across a trust boundary that doesn't match any documented migration or delegation. Cross-domain/forest privilege escalation via SID history is itself a large enough topic (and typically only relevant once a Golden Ticket or krbtgt-level compromise is already confirmed) to warrant its own dedicated treatment in a future pass rather than full depth here.

### PowerShell

To pull an account's SID history directly and resolve each entry to a domain/account name, check that any SID resolving to a domain with no documented migration is the finding described above (requires `ActiveDirectory` module):

```powershell
Get-ADUser -Identity <samAccountName> -Properties SIDHistory |
    Select-Object -ExpandProperty SIDHistory | ForEach-Object { $_.Translate([Security.Principal.NTAccount]) }
```

## Where These Events Actually Live

> 🔴 **Callout: every event ID in this note — 4768, 4769, 4770, 4771, the 4662 DCSync signature, and 5136 GPO/object changes — is logged on the DOMAIN CONTROLLER's `Security.evtx`, never on the workstation.** This trips up junior analysts constantly: they pull the compromised workstation's Security log, correctly find the 4624 logon (note 05's territory), and conclude the investigation because they don't see any Kerberos ticket events — because those events were never going to be there. If you need to see the Kerberos/AD side of an incident, you must identify **which DC(s) served the affected accounts/computers** and collect *their* Security logs specifically. In a multi-DC environment, this also means checking more than one DC, since a client's requests aren't guaranteed to hit the same DC every time (site-affinity and load distribution can spread a single user's ticket requests across several DCs over the course of an investigation window).

| Event / signature | Logged where |
|---|---|
| 4768, 4769, 4770, 4771 | The DC that serviced the AS-REQ/TGS-REQ — not the client |
| 4662 (DCSync replication GUIDs) | The DC targeted by the replication request (commonly observed on/near the PDC emulator) |
| 5136 (directory service object modified) | The DC that processed the write (replicates to all DCs, but originates from whichever DC accepted the change) |
| 4624/4625 (logon result) | The workstation or member server the user actually authenticated to — see note 05 |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| 4769 with encryption type `0x17` (RC4) against multiple SPNs from one account in a short window | Kerberoasting — especially significant in an AES-standardized environment |
| 4768 with no preceding 4771, for an account flagged "Do not require Kerberos preauthentication" | AS-REP Roasting |
| Service ticket used against a service, with no matching 4769 (or no matching 4768 at all) | Silver Ticket (forged service ticket) or Golden Ticket (forged TGT) — absence of the expected DC-side event is itself the signature |
| RC4-encrypted TGT/ST in a domain that has been AES-only for years | Likely forged (Golden/Silver Ticket tooling often defaults to RC4) |
| 4662 referencing `DS-Replication-Get-Changes`/`-All` GUIDs, sourced from a non-DC computer | DCSync — near-certain credential-replication abuse |
| SID history containing SIDs from a domain with no documented migration | Possible SID history injection / cross-domain privilege escalation |
| `repadmin /showobjmeta` shows an attribute's last write from an unexpected DC or time inconsistent with the incident narrative | Corroborates or contradicts a claimed timeline — check before trusting `whenChanged` alone |
| Investigation scope limited to workstation Security.evtx with no DC logs collected | Kerberos/AD-level abuse (Golden/Silver Ticket, Kerberoasting, DCSync, GPO tampering) is structurally invisible without DC-side logs |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Local account structure, logon types, workstation-side 4624/4625/4672/4776 | **Users, Groups & Authentication** (note 05) |
| Full event-log taxonomy, audit policy prerequisites for 4662/5136, log rollover/retention | **Event Log Analysis** |
| How stolen tickets/hashes get used to move to other hosts (Pass-the-Ticket, Pass-the-Hash, overlap with PsExec/WMI/PowerShell Remoting) | **Lateral Movement** |
| Kerberos abuse and DCSync as named techniques within a broader intrusion narrative, ATT&CK mapping | **Threat Hunting Methodology and Intelligence** |
| GPO/SYSVOL forensics — fundamentals, storage/replication, content, DC-side and domain-joined-host investigation, abuse/hunting | **[GPO/ folder](<GPO/00 - GPO Fundamentals and Architecture.md>)**, starting at 00 |

## Resources

- Microsoft Learn — Kerberos authentication overview: https://learn.microsoft.com/windows-server/security/kerberos/kerberos-authentication-overview
- Microsoft Learn — 4768/4769/4770/4771 event descriptions: https://learn.microsoft.com/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor
- Microsoft Learn — Monitoring Active Directory for Signs of Compromise (DCSync, replication rights): https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/monitoring-active-directory-for-signs-of-compromise
- `repadmin` command reference: https://learn.microsoft.com/windows-server/administration/windows-commands/repadmin
- SANS FOR508 course syllabus (public) — Kerberos abuse, DCSync, lateral movement coverage checklist

