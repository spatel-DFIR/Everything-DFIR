# Impacket — ticketer.py — Overview

> 🔴 **Red Flag Principle:** `ticketer.py`'s default forging step is a Python script doing local ASN.1 construction and AES/RC4 encryption — it opens **zero network sockets** and touches no Domain Controller. There is nothing to catch at creation time, full stop. Every real detection opportunity lives one step later, at **use**: an authentication event with no plausible prior legitimate logon for that identity, or a presented PAC that a KDC never actually issued. The deep mechanics of that gap — the PAC-carry-forward model, the 20-minute revalidation rule, the exact MDI alert IDs — are already built out in `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md` and are **not re-derived here**; this note's job is what's specific to `ticketer.py` as a standalone offline tool, including two of its modes (`-request`, `-impersonate`) that break the "silent" assumption entirely by making genuine, loggable KDC contact **before** the forgery is even applied.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`ticketer.py` lives in [`fortra/impacket`](https://github.com/fortra/impacket)'s `examples/` folder, same lineage as `psexec.py`/`wmiexec.py`/`smbexec.py`/`secretsdump.py` (CORE Security → HelpSystems → Fortra). Its source header credits **Alberto Solino (`@agsolino`)** as author, with the file's own `References` section citing its direct lineage explicitly: the **Black Hat USA 2014** talk "Abusing Microsoft Kerberos: Sorry You Guys Don't Get It" by Alva "Skip" Duckwall and Benjamin Delpy, and **Benjamin Delpy's (`@gentilkiwi`) original mimikatz implementation** — `ticketer.py` is, by its own header, a Linux/Python reimplementation of the same technique `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md` covers, not an independently invented one.

The file's own `ToDo` comment block is a useful, source-verified timeline marker: `[X] Silver tickets still not implemented - DONE by @machosec and fixes by @br4nsh` — meaning Silver Ticket support (the `-spn` flag) was **not** in the tool's original release and was added later by community contributors, unlike Mimikatz where Golden and Silver were always the same command from the start.

Two more capabilities exist in current source beyond plain offline Golden/Silver forgery, both verified directly against `examples/ticketer.py`:

- **`-request`** — clones a *genuinely KDC-issued* TGT/TGS as a template and modifies only the specified fields before re-signing, rather than building a ticket from nothing. This is the mechanism the security community calls a **Diamond Ticket**, credited to **Charlie Clark and Andrew Schwartz (TrustedSec)**. `ticketer.py`'s own source and help text never use the word "Diamond" — the term is entirely a community label for what the code's comments describe plainly as requesting a real ticket "to use as basis" for customization.
- **`-impersonate`** — layers an **S4U2Self + U2U** exchange on top of `-request` to steal a real high-privilege account's PAC and splice it into the forged ticket, rather than fabricating group SIDs by hand. This one **is** named in the source itself: the code's own log/error strings say `"Doing Sapphire Ticket"` and `"missing parameters to do sapphire ticket"`. The Sapphire Ticket technique is credited to **Charlie Bromberg (`@_nwodtuhs`)**, refining Diamond Ticket to avoid its PAC-inconsistency tells by borrowing a *real* PAC instead of hand-editing one.

## How It Works

### Offline forgery — the default path (no `-request`, no `-impersonate`)

`ticketer.py`'s `TICKETER` class runs a fixed four-step pipeline (`run()` in source), and in default mode every step is pure local computation:

```
Operator (ticketer.py, offline — no network I/O at all)
─────────────────────────────────────────────────────────
1. createBasicTicket()
   Builds an empty AS_REP (Golden — no -spn) or TGS_REP
   (Silver — -spn given) ASN.1 skeleton from scratch:
   principal name, realm, target SPN, encryption type
   selected from whichever key material was supplied
   (-nthash → RC4, -aesKey → AES128/256, -keytab → whatever
   the keytab's own enctype is)

2. createBasicValidationInfo() / createBasicPac()
   Fabricates a PAC_LOGON_INFO structure LOCALLY — user RID
   (-user-id, default 500), group RIDs (-groups, default
   513/512/520/518/519 — the SAME default set as Mimikatz's
   kuhl_m_pac_stringTogroups_defaultGroups), extra SIDs
   (-extra-sid). NO LDAP LOOKUP, NO AD QUERY OF ANY KIND —
   none of this needs to correspond to a real account

3. customizeTicket()
   Sets ticket times (start/end/renew, from -duration,
   default 87600 hours) and attaches the PAC as
   authorization-data inside the EncTicketPart

4. signEncryptTicket()
   Computes the PAC's Server + KDC checksums using the
   SAME supplied key for both (mirrors Mimikatz's identical
   both-signatures-one-key limitation exactly — a lone
   offline tool never has two different real keys to work
   with), then encrypts the whole EncTicketPart with that key

5. saveTicket()
   Writes a standard MIT-format .ccache file to disk —
   NOT a memory injection, NOT a .kirbi. If $KRB5CCNAME
   already points at an existing ccache, that file is
   loaded and UPDATED rather than a fresh one always created

[Steps 1-5 generate ZERO network traffic of any kind —
 the tool's own source header states this explicitly:
 "No traffic is generated against the KDC."]
```

**This is the single most important structural contrast with `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md`'s `kerberos::golden`:** Mimikatz runs *in-process*, in an already-authenticated Windows session, and can optionally inject the forged ticket directly into that session's LSA cache via `/ptt` in the same command. `ticketer.py` has **no equivalent injection capability of its own** — it is a standalone script with no relationship to any live Windows logon session. Its *only* output is a `.ccache` file; getting that ticket actually *used* is always a separate, subsequent step performed by a different tool (`-k`/`KRB5CCNAME` on another Impacket script, or `kerberos::ptc` back on a Windows host — see Quick Use-Case List, below).

### The exception — `-request` and `-impersonate` DO contact a live KDC at creation time

This is a real, source-verified deviation from the "always offline" framing that applies to plain Golden/Silver forging, and it matters directly for `03`/`04`:

```
Operator (ticketer.py -request ...)                         KDC (Domain Controller)
──────────────────────────────────────────────────────      ───────────────────────
createBasicTicket(), -request branch:
  getKerberosTGT(-user, -password/-hashes, -domain)  ─────▶  Genuine AS-REQ/AS-REP —
                                                               a REAL Event 4768 fires
                                                               for the -user account
  [if -spn is ALSO given: getKerberosTGS() follows]  ─────▶  Genuine TGS-REQ/TGS-REP —
                                                               a REAL Event 4769 fires

customizeTicket() then DECRYPTS this genuine ticket
using the supplied key, MODIFIES only the target
identity/PAC fields, re-signs, and re-encrypts — the
ticket's outer structure (timestamps, flags, kvno) is
whatever the real KDC actually issued, not a hand-built
skeleton
```

If `-impersonate` is added on top of `-request`, a **second**, separate live exchange happens: `getKerberosS4U2SelfU2U()` builds a genuine S4U2Self+U2U `TGS-REQ` (PA-FOR-USER padata naming the impersonated user, `enc-tkt-in-skey` requesting a user-to-user ticket) and sends it with `sendReceive()` — another **real, DC-logged TGS-REQ/TGS-REP**, this one carrying the impersonated high-privilege user's genuine PAC, which is then extracted and spliced into the final forged ticket in place of a hand-fabricated one.

**Practical read:** plain Golden/Silver forging (no `-request`) is exactly as silent as Mimikatz's `kerberos::golden` at the creation step. `-request` (Diamond) and `-impersonate` (Sapphire) are **not** — they generate real, DC-observable Kerberos traffic and real Security 4768/4769 events tied to whatever account was used for `-user`, *before* any forgery is even applied. An analyst who only checks "was a 4768 ever issued for this eventual forged identity" (the Mimikatz-style hunt) will miss this entirely, because the 4768/4769 that fires is tied to the **template account**, not the identity the final ticket claims to be.

### Default lifetime — the same ~10-year tell as Mimikatz, expressed differently

`-duration` defaults to **`87600` hours**. That's exactly `24 × 365 × 10` — precisely the same ~10-year span as Mimikatz's `/endin` default of `5256000` minutes (`5256000 / 60 = 87600` hours — the two tools converge on the identical value, just expressed in different units). Compare against Active Directory's actual default Kerberos policy (`Maximum lifetime for user ticket`: 10 hours) — the same order-of-magnitude anomaly Mimikatz's note documents in depth applies identically here; **not re-derived** — see that note's "Default lifetime" section and MDI alert 2022 ("time anomaly") coverage. One difference worth flagging: **`-duration` is silently ignored whenever `-request` is used** — the tool's own help text says so plainly ("Ignored with `-request`, which preserves the KDC-issued lifetime") — meaning a Diamond/Sapphire ticket's lifetime is whatever the real template ticket's lifetime was, which is by construction a policy-compliant value and therefore **immune** to the time-anomaly signal entirely, not just resistant to it.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Core protocol | **Kerberos** (RFC 4120) — same AS/TGS/AP exchange baseline as `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md`, not re-derived |
| Authorization data | **MS-PAC** — `PAC_LOGON_INFO`, Server + KDC signatures, `PAC_CLIENT_INFO`; `-extra-pac` additionally builds `PAC_UPN_DNS_INFO`; `-old-pac` deliberately omits `PAC_ATTRIBUTES_INFO`/`PAC_REQUESTOR` (newer PAC buffer types added to counter some forged-ticket detections) |
| Constrained delegation extension (Sapphire only) | **MS-SFU** — S4U2Self (`PA-FOR-USER` padata) + User-to-User (`enc-tkt-in-skey`), used by `-impersonate` to pull a real target user's PAC via a genuine TGS-REQ |
| Ticket container format | **MIT/Heimdal `.ccache`** — the tool's sole output format, distinct from Mimikatz's native `.kirbi` (see `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md`'s `kerberos::ptc`/`kerberos::clist` for the cross-format interop primitive) |
| Credential material exploited | krbtgt's NTLM/AES key (Golden) or a specific service/computer account's NTLM/AES key or keytab (Silver) — obtaining either is out of scope here; see `Impacket/secretsdump/01 - Overview.md`'s DRSUAPI (`-just-dc-user krbtgt`) path, the realistic chained prerequisite for this tool |
| Downstream consumption | `KRB5CCNAME` environment variable, read by every other Impacket example script's `-k` flag (`Impacket/psexec/`, `Impacket/wmiexec/`, `Impacket/smbexec/`, `Impacket/secretsdump/` all support `-k`) — or `kerberos::ptc` back on a Windows host for import into an LSA session |

## Command-Line Switches — Quick Reference

Verified directly against the `argparse` block in `examples/ticketer.py` in [fortra/impacket](https://github.com/fortra/impacket).

**Positional**

| Argument | Meaning |
|---|---|
| `target` | Username the forged ticket will be issued **for** — arbitrary for a plain forge (need not exist in AD, same 20-minute-rule exploitation as Mimikatz), or the account being cloned when combined with `-request` |

**Ticket Content / Mode**

| Switch | Plain-English meaning |
|---|---|
| `-spn <service/host>` | Target service SPN, format `service/hostname` (e.g. `cifs/filesrv01.corp.local`). **Omit for a Golden Ticket; set for a Silver Ticket** — same golden-vs-silver branch logic as Mimikatz, but via a distinct flag rather than a shared `/service` |
| `-request` | **Diamond Ticket.** Authenticate to the real KDC first (via `-user`/`-password` or `-hashes`), obtain a genuine TGT (or TGS if `-spn` is also set), then decrypt/modify/re-sign that real ticket instead of building one from scratch. Requires `-user` |
| `-domain <FQDN>` | **Required.** Fully qualified target domain name |
| `-domain-sid <SID>` | **Required.** Domain SID — needed to build a PAC at all, same as Mimikatz's `/sid` |
| `-aesKey <hex>` | AES128/256 key material for signing — key type inferred from hex length (32 chars = AES128, 64 = AES256) |
| `-nthash <hex>` | NTLM hash for signing (RC4) — krbtgt's hash for Golden, the target service/computer account's hash for Silver |
| `-keytab <path>` | **Silver ticket only.** Read the service account's key(s) from a keytab file instead of `-nthash`/`-aesKey` directly |
| `-groups <RIDs>` | Comma-separated group RIDs for the PAC. Default **`513, 512, 520, 518, 519`** — identical default set to Mimikatz's `/groups` (Domain Users, Domain Admins, GPO Creator Owners, Schema Admins, Enterprise Admins) |
| `-user-id <RID>` | RID of the forged user. Default **`500`** (built-in Administrator) — equivalent to Mimikatz's `/id` |
| `-extra-sid <SIDs>` | Comma-separated extra SIDs injected into the PAC's SID-history field — same cross-domain/forest escalation primitive as Mimikatz's `/sids`, not re-derived (`Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md`) |
| `-extra-pac` | Additionally populate `PAC_UPN_DNS_INFO` in the forged PAC |
| `-old-pac` | Use the legacy PAC structure — **excludes** `PAC_ATTRIBUTES_INFO` and `PAC_REQUESTOR`, newer buffer types some detection logic keys on |
| `-duration <hours>` | Ticket lifetime in hours. Default **`87600`** (10 years — see How It Works). **Silently ignored if `-request` is used**, which preserves the real template ticket's KDC-issued lifetime instead |
| `-ts` | Prefix log output with a timestamp |
| `-debug` | Verbose debug output |

**Authentication (used only with `-request`/`-impersonate`)**

| Switch | Plain-English meaning |
|---|---|
| `-user <domain/username>` | Account to authenticate as when fetching the real template ticket. **Required if `-request` is set** |
| `-password <pw>` | Password for `-user`. If omitted and no `-hashes` given, `ticketer.py` prompts interactively (`getpass`) rather than ever accepting a blank |
| `-hashes LMHASH:NTHASH` | NTLM hash for `-user`, pass-the-hash style, instead of a password |
| `-dc-ip <ip>` | Domain Controller IP for the `-request`/`-impersonate` live exchange |

**Sapphire Ticket**

| Switch | Plain-English meaning |
|---|---|
| `-impersonate <username>` | **Sapphire ticket.** Target user to impersonate via S4U2Self+U2U — their real PAC is fetched live and spliced into the forged ticket. **Requires** `-request`, `-aesKey`, `-nthash`, `-domain`, `-user`, `-password`, `-domain-sid`, and `-user-id` (source's own validation block enforces all of these) unless `-old-pac` is also set. **Ignores** `-extra-pac`, `-extra-sid`, `-groups`, and `-duration` entirely — the PAC and lifetime come from the real cloned ticket, not from these fabrication flags, and the tool logs an explicit warning if any are supplied alongside `-impersonate` |

**Validation notes verified directly from source** (not documented in `--help`, only enforced at runtime): at least one of `-aesKey`/`-nthash`/`-keytab` **must** be supplied; `-aesKey` and `-nthash` **cannot both** be given unless `-request` is also set (a `-request`-cloned ticket may need both, since the real ticket's own encryption type dictates which key is actually used).

## Quick Use-Case List

- Golden Ticket forged from krbtgt's NTLM hash, RC4-encrypted, default Administrator/Domain-Admins group set
- Golden Ticket forged from krbtgt's AES key instead — avoids the RC4-encryption-type detection signal, same evasion logic as Mimikatz's AES forging
- Silver Ticket against a specific file-server SPN (`-spn cifs/...`) using that computer account's own NTLM hash — no krbtgt hash needed, no DC contact ever at use time
- Silver Ticket built from a keytab file (`-keytab`) instead of a raw hash — useful when key material was recovered as a keytab (e.g. from a `*NIX`-integrated service account) rather than a hex hash
- Custom group-SID injection (`-extra-sid`) for cross-domain/forest privilege escalation, same mechanism as Mimikatz's `/sids`
- Custom ticket lifetime (`-duration`) matched to the domain's real Kerberos policy, defeating the default-10-year time-anomaly signal
- Diamond Ticket (`-request`) — clone a genuinely KDC-issued TGT and modify only the target fields, inheriting a real ticket's structure and policy-compliant lifetime
- Diamond-Ticket-style Silver forgery (`-request` + `-spn` together) — clone a real TGS as the template instead of a TGT
- Sapphire Ticket (`-request` + `-impersonate`) — steal a real high-privilege user's PAC via S4U2Self+U2U and splice it into the forged ticket, avoiding Diamond Ticket's hand-fabricated-PAC tells
- Legacy PAC structure (`-old-pac`) — omit newer PAC buffer types some detection tooling keys on
- Chained from `secretsdump.py -just-dc-user krbtgt` — DRSUAPI recovers the krbtgt key, `ticketer.py` forges from it, in two Linux-side commands with no interactive DC access (`Impacket/secretsdump/01 - Overview.md`)
- Chained into `psexec.py`/`wmiexec.py`/`smbexec.py`/`secretsdump.py -k` — the forged `.ccache`, exported via `KRB5CCNAME`, authenticates any of the other already-built Impacket sub-tools using ticket-based Kerberos auth instead of a password or hash
- Cross-platform handoff to a Windows host via `kerberos::ptc` (`Mimikatz/kerberos (Golden-Silver Ticket)/02 - Hands-On Use Cases.md`) — forge on Linux, use from Windows

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| krbtgt account's NTLM or AES key (**Golden**) | Typically `secretsdump.py -just-dc-user krbtgt` (`Impacket/secretsdump/01 - Overview.md`) or Mimikatz `lsadump::dcsync /user:krbtgt` (`Mimikatz/lsadump (DCSync)/`) — this tool covers forging/using the key, not obtaining it |
| Target service/computer account's NTLM/AES key or keytab (**Silver**) | Same recovery paths, scoped to the specific service/computer account instead of krbtgt |
| Domain SID (`-domain-sid`) | Required to build any PAC — recoverable via `lookupsid.py`, a prior LDAP query, or `Get-ADDomain` |
| Domain FQDN (`-domain`) | Required for both offline forging and `-request`/`-impersonate`'s live exchange |
| **No live DC connectivity needed for plain Golden/Silver forging** | `createBasicTicket()`'s non-`-request` branch is pure local ASN.1 construction and encryption — confirmed directly in source and in the tool's own `--help` examples text ("No traffic is generated against the KDC") |
| **Live DC reachability + valid domain credentials IS required for `-request`/`-impersonate`** | These modes authenticate for real (`-user`/`-password` or `-hashes`) to fetch a genuine template ticket before forging — a materially different prerequisite from plain forging, and one that generates real, DC-logged Kerberos traffic (`03`/`04`) |
| Kerberos must actually be the authentication protocol in use at the target | Same caveat as every ticket-forging technique — confirm SPN registration and Kerberos reachability before forging for a specific service |
