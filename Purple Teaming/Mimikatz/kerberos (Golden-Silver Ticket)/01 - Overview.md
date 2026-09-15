# Mimikatz — kerberos (Golden/Silver Ticket) — Overview

> 🔴 **Red Flag Principle:** A Golden or Silver Ticket is never issued by a Domain Controller — it's assembled entirely offline from a stolen key and injected straight into a session's ticket cache. That means there is **no Event 4768 anywhere, ever, for its creation**. Worse for defenders: a **Silver Ticket never touches a Domain Controller at all**, at any point in its lifecycle — it goes directly from the operator's machine to the target application server via `AP-REQ`, so DC-side logging (Security 4768/4769, Microsoft Defender for Identity) has **nothing to see, period**. A Golden Ticket at least re-enters the legitimate protocol at the TGS-REQ step (see **How It Works** below), which is where every DC-side detection in this module lives. Every technique here is a variation on the same fact: *forging* leaves no trace, only *using* the forgery does — and how much trace that leaves depends entirely on which key was forged.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

The `kerberos` module is one of mimikatz's original modules, part of the core [`gentilkiwi/mimikatz`](https://github.com/gentilkiwi/mimikatz) repository (source: `mimikatz/modules/kerberos/kuhl_m_kerberos.c`, `kuhl_m_kerberos_ticket.c`, `kuhl_m_kerberos_pac.c`), authored and maintained by Benjamin Delpy (`@gentilkiwi`) under the project's CC BY 4.0 license — see `00 - Mimikatz Overview.md` for the tool-level history.

**The "Golden Ticket" name and technique were popularized publicly at Black Hat USA 2014**, in the talk ["Abusing Microsoft Kerberos: Sorry You Guys Don't Get It"](https://www.blackhat.com/docs/us-14/materials/us-14-Duckwall-Abusing-Microsoft-Kerberos-Sorry-You-Guys-Don't-Get-It-wp.pdf) by Alva "Skip" Duckwall and Benjamin Delpy, delivered August 7, 2014 — the talk that framed the krbtgt account's key as "the most important password in your Active Directory" and demonstrated forging a TGT with unlimited scope and lifetime once that key is known. The `kuhl_m_kerberos_golden` function's own registered help string in the source — `L"Willy Wonka factory"` — is a direct nod to this: a golden ticket that grants the bearer the run of the whole factory. Sean Metcalf's [ADSecurity.org write-ups](https://adsecurity.org/?p=1515) followed shortly after and remain among the most-cited references for how the attack is detected, alongside the `lsadump (DCSync)/` folder's citation of his DCSync research — Metcalf and Delpy's work sits at the foundation of most practical AD-attack detection literature from this era.

**There is no separate "Silver Ticket" command in mimikatz.** `kuhl_m_c_kerberos[]` — the module's registered command table, verified directly against the source — lists exactly one ticket-forging command: `golden`. What the security community calls a "Silver Ticket" is the **same `kerberos::golden` command, called with a target service's own key instead of krbtgt's, and a `/service` argument instead of leaving it defaulted** — covered in depth below. The term "Silver Ticket" itself is a later community coinage (continuing the "ticket" metaphor a notch below "Golden") describing this specific parameterization, not a distinct mimikatz feature.

The module also carries the ticket-cache manipulation primitives this technique depends on operationally: `kerberos::ptt` (pass-the-ticket — inject a forged or stolen ticket into the current session), `kerberos::list`/`kerberos::purge` (enumerate/clear the current session's cache), and `kerberos::tgt` (retrieve the current session's real TGT). These all predate the Golden Ticket technique's public popularization — mimikatz already had the ability to manipulate the Windows ticket cache via documented LSA Kerberos-package messages before "Golden Ticket" was a term anyone used, which is precisely what made forging a ticket offline and then handing it to `kerberos::ptt` such a natural next step once the krbtgt-key insight landed.

## How It Works

### Kerberos, briefly, as a baseline

Understanding what a forged ticket exploits requires the legitimate exchange as a reference point:

```
Client                                                    KDC (Domain Controller)
──────                                                    ───────────────────────
1. AS-REQ (username, pre-auth encrypted with the          Verifies pre-auth, looks up the
   user's own key)                            ─────────▶  REAL account in AD: SID, RID,
                                                            group memberships, UAC flags
2. AS-REP: TGT — encrypted+signed with the                Builds a PAC from that LDAP data,
   krbtgt account's key, contains that PAC    ◀─────────  signs it (Server + KDC checksums,
                                                            both ultimately keyed off krbtgt)
3. TGS-REQ: present the TGT, ask for a
   ticket to a specific service (SPN)         ─────────▶  Decrypts TGT with krbtgt's key,
                                                            COPIES the PAC forward unchanged
4. TGS-REP: service ticket — PAC carried                  into a fresh service ticket, now
   over from the TGT, re-signed for the       ◀─────────  signed for [that service's key +
   target service                                          a fresh KDC signature]
5. AP-REQ: present the service ticket
   directly to the target server                                              Target Server
                                               ──────────────────────────────▶ decrypts with
                                                                                its own key,
                                                                                trusts the PAC
```

Two facts from this baseline matter for everything below: **the PAC is built once, from a real LDAP lookup, at step 1–2**, and then simply **carried forward and re-signed** at every subsequent step — nothing downstream re-verifies its *contents* against AD by default, only its *signature* (and even that isn't universally checked — see PAC validation below).

### Forging a Golden Ticket — entirely offline

```
Operator (mimikatz.exe, offline — no network I/O at all)      Domain Controller (KDC)         Target Server
──────────────────────────────────────────────────────────    ────────────────────────        ─────────────
1. kerberos::golden /user:evil /domain:corp.local
   /sid:S-1-5-21-... /krbtgt:<NTLM or AES hash>

   kuhl_m_kerberos_golden_data() builds all 3 pieces of a
   KRB-CRED (.kirbi) purely from local computation:

   a. A SYNTHETIC PAC (kuhl_m_pac_infoToValidationInfo /
      kuhl_m_pac_validationInfo_to_PAC) — fabricated SID,
      RID (/id, default 500 = built-in Administrator),
      and group RIDs (/groups, default 513/512/520/518/519
      — Domain Users, Domain Admins, Group Policy Creator
      Owners, Schema Admins, Enterprise Admins). NO LDAP
      LOOKUP IS EVER PERFORMED — none of this needs to
      correspond to a real account at all.

   b. PAC Server + KDC signatures (kuhl_m_pac_signature) —
      MS-PAC's normal two-checksum chain (Server signature
      over the whole PAC, KDC signature over the Server
      signature), but BOTH computed with the SAME provided
      key, since mimikatz only has one key to work with.

   c. The EncTicketPart itself — session key, flags, the
      PAC — encrypted with that same krbtgt key
      (kuhl_m_kerberos_encrypt). This is what makes the
      ticket cryptographically "valid": it decrypts
      correctly downstream because the key genuinely
      matches what the real KDC uses.

2. kerberos::ptt <ticket.kirbi>  (or /ptt on the golden       (steps 1-2 generate zero network
   command itself)                                             traffic of any kind — everything
   → KerbSubmitTicketMessage via LsaCallAuthenticationPackage,  happens locally, in-process, on
     injected into the CURRENT session's ticket cache — the     whatever machine is running
     SAME documented LSA API a legitimate ticket-import tool     mimikatz)
     would use, not a memory patch or undocumented structure

3. Windows itself, transparently, later
   requests a TGS using this forged           ────────────▶   KDC decrypts the presented ticket
   "TGT" the first time the operator                            with krbtgt's REAL key — SUCCEEDS,
   accesses any Kerberos-authenticated                          because the forged ticket really
   resource                                                     was encrypted with the correct key

                                                                 Per MS-KILE's "20-minute rule": the
                                                                 KDC does NOT re-verify the named
                                                                 account exists, is enabled, or that
                                                                 its real group memberships match the
                                                                 PAC for a TGT under ~20 minutes old
                                                                 — it trusts the PAC's contents as-is
                                                                 and COPIES them forward into a new,
                                                                 legitimately DC-signed service ticket
                                             ◀────────────    TGS-REP: service ticket carrying the
                                                                 forged privileges — now genuinely
                                                                 issued and signed by a real DC
4. AP-REQ: present the service ticket                                                    ───────▶ Target
                                                                                                     decrypts
                                                                                                     with its
                                                                                                     own key,
                                                                                                     trusts the
                                                                                                     PAC (rarely
                                                                                                     re-validated
                                                                                                     against a DC
                                                                                                     — see below),
                                                                                                     grants access
                                                                                                     as the forged
                                                                                                     identity
```

**This is the single most consequential mechanic in the whole module: step 3 is where a Golden Ticket re-enters the legitimate protocol, and it's the only point where a Domain Controller ever sees any of this.** Everything before it is undetectable at the network/log layer by construction (it never leaves the operator's machine); everything from step 3 onward is detectable, because a real DC and a real target server are now doing real, loggable work on the forged ticket's behalf.

### Golden vs. Silver — same command, different key and different blast radius

| | Golden Ticket | Silver Ticket |
|---|---|---|
| Key used (`/krbtgt`, `/rc4`, `/aes128`, `/aes256`) | The **krbtgt account's** key | A specific **service/computer account's** own key (e.g. a file server's machine-account hash for CIFS, a service account's hash for MSSQL) |
| `/service` argument | Omitted — defaults to `"krbtgt"`, and the ticket is flagged `KERB_TICKET_FLAGS_initial` (verified in `kuhl_m_kerberos_golden_data`: `ticket.TicketFlags = (servicename ? 0 : KERB_TICKET_FLAGS_initial) \| ...`) — it's shaped like a genuine TGT | Set explicitly (e.g. `cifs`, `http`, `mssqlsvc`) — the ticket is **not** flagged `initial`; it's shaped like a TGS-issued service ticket, not a TGT |
| Ever touches a DC? | **Yes** — step 3 above, when Windows silently converts the forged "TGT" into a real TGS-REQ | **Never.** The forged ticket already *is* a service ticket — it goes straight from the operator to the target server via `AP-REQ`. No AS-REQ, no TGS-REQ, no DC contact, ever |
| Scope | Every Kerberos-authenticated service in the domain (and cross-domain/forest, with `/sids` — see below) that trusts the DC's krbtgt-signed tickets | Exactly the one service the forging key belongs to — a Silver Ticket for a file server's CIFS SPN does not grant access to any other service |
| PAC signature validity | Both PAC signatures (Server + KDC) are computed with a key the real KDC actually holds (krbtgt) — structurally correct even though the PAC's *contents* are fabricated | The PAC's **KDC signature is computed with the service key, not the real krbtgt key** (mimikatz only has the one key it was given) — architecturally invalid if the target server ever performs full PAC validation (calls back to a DC), though this is opt-in and uncommon by default (`04 - Target Evidence.md`) |
| DC-side/MDI detection surface | Real — Security 4769, Microsoft Defender for Identity's Golden-Ticket-specific alerts (`04`/`05`) | **None.** No DC-side telemetry exists for a Silver Ticket at all — detection is limited to the target application server itself |

Obtaining the krbtgt key is out of scope for this note — see `lsadump (DCSync)/01 - Overview.md` for `lsadump::dcsync /user:krbtgt`, the standard modern method. Obtaining a target service's own key is likewise typically `lsadump::dcsync` against that computer/service account, or a live `sekurlsa` LSASS read on a host actually running that service — see `sekurlsa (Credential Dumping)/`. This folder picks up **after** the key is already in hand: forging and using it.

### Cross-domain/forest Golden Tickets — `/sids` (SID History injection)

`/sids` adds arbitrary extra SIDs into the forged PAC's `ExtraSids`/SID-history field (`kuhl_m_pac_stringToSids`, verified in source) — the same field AD itself uses legitimately for migrated-account SID history. Injecting, for example, a parent domain's or a trusted forest's **Enterprise Admins** SID (well-known RID 519, at the domain SID of whichever domain is meant to be escalated into) grants the forged ticket's bearer that domain's rights **without ever authenticating to that domain at all** — the local DC copies the PAC's SID list forward into the TGS-REP exactly as it does the rest of the PAC. This is what makes a single compromised child domain's krbtgt hash a forest-wide risk, not just a domain-wide one, and it's the same underlying mechanism (SID filtering/quarantine on trusts is the mitigating control) referenced in `lsadump (DCSync)/01 - Overview.md`'s discussion of `lsadump::trust`.

### PAC validation — the gap this whole technique exploits

Two separate, both-optional checks exist in the Kerberos/PAC ecosystem, and understanding which ones are (and aren't) on by default is the crux of why forged tickets work at all:

1. **The 20-minute rule** — the KDC itself doesn't re-verify a presented TGT's named account against AD (existence, enabled state, current group membership) until that TGT is more than ~20 minutes old (documented in Microsoft's own [PAC validation guidance](https://learn.microsoft.com/en-us/archive/blogs/openspecification/understanding-microsoft-kerberos-pac-validation) and widely cited, e.g. [Still Passing the Hash 15 Years Later](http://passing-the-hash.blogspot.com/2014/09/pac-validation-20-minute-rule-and.html)). A short-lived forged ticket sails through this check entirely; even mimikatz's absurd ~10-year default lifetime (below) doesn't matter for this specific check, since it's evaluated relative to the ticket's own age at time of use, not its stated expiry.
2. **Target-server PAC validation (`KERB_VERIFY_PAC`)** — an application server *can* forward the PAC signature it received back to a DC for independent verification via Netlogon (`[MS-APDS]`), but this is opt-in, adds a round-trip per authentication, and is not the default behavior for most services. When it isn't performed (the common case), the target server trusts the PAC's signature and contents as presented — which is exactly what lets a Silver Ticket's mis-keyed KDC signature (above) go unnoticed in practice.

Neither gap is a bug — both are documented, intentional performance/compatibility tradeoffs in the Kerberos delegation model. The technique's entire premise is that a valid *key* is treated as sufficient proof of a valid *identity*, and Windows Kerberos has no independent way to check that assumption cheaply at every hop.

### Default lifetime — the other classic tell

Verified directly from `kuhl_m_kerberos_golden`'s source: absent `/endin`, the forged ticket's expiry defaults to **`5256000` minutes — approximately 10 years** (the source comments this literally as `// ~ 10 years`), and `/renewmax` defaults to the same value if not separately specified. Compare this to Active Directory's own default Kerberos policy — **Maximum lifetime for user ticket: 10 hours**, **Maximum lifetime for user ticket renewal: 7 days** (Default Domain Policy, `Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Kerberos Policy`). A default-configuration Golden Ticket is therefore requesting a lifetime roughly **8,700× longer** than policy allows — this exact mismatch is what Microsoft Defender for Identity's "time anomaly" alert (`04`/`05`) is built to catch, and it's trivially defeated by an operator who sets `/endin`/`/renewmax` to match the real policy window — a real evasion tradeoff covered in `05 - Detection and Hunting.md`'s priority ranking.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Core protocol | **Kerberos** (RFC 4120) — ticket structure, encryption types, the AS/TGS/AP exchange |
| Authorization data | **MS-PAC** (Privilege Attribute Certificate) — `PAC_LOGON_INFO` (group SIDs, RID, flags), `PAC_CLIENT_INFO`, Server Signature, KDC Signature |
| Microsoft Kerberos extensions | **MS-KILE** — ticket flags (`forwardable`, `renewable`, `initial`, `pre_authent`, etc.), the 20-minute PAC-revalidation rule, RODC key-list semantics |
| PAC cross-verification (optional) | **MS-APDS** `KERB_VERIFY_PAC` — application-server-to-DC callback for independent PAC signature verification, not on by default |
| Local ticket-cache manipulation | **LSA Authentication Package messages** — `KerbSubmitTicketMessage` (`ptt`), `KerbQueryTicketCacheExMessage` (`list`), `KerbPurgeTicketCacheMessage` (`purge`), `KerbRetrieveTicketMessage`/`KerbRetrieveEncodedTicketMessage` (`tgt`/`ask`/`list /export`) — **semi-documented, legitimate LSA message types** (defined in the Windows SDK's `ntsecapi.h`/`NTSecPkg.h`), not reverse-engineered undocumented memory structures. This makes `kerberos`'s ticket-cache commands mechanically the "cleanest," most-legitimate-API-driven part of mimikatz covered across this Mimikatz folder set — contrast with `sekurlsa`'s undocumented `LogonSessionList` pattern-scanning or `lsadump`'s reverse-engineered boot-key math |
| Credential material exploited | The **krbtgt account's** NTLM/AES key (Golden) or a **specific service/computer account's** NTLM/AES key (Silver) — obtaining either is covered by `lsadump (DCSync)/` or `sekurlsa (Credential Dumping)/`, not repeated here |

## Command-Line Switches — Quick Reference

### `kerberos` module commands

Verified directly against `kuhl_m_c_kerberos[]` in `kuhl_m_kerberos.c` — every command below is registered exactly as listed there.

| Command | Plain-English meaning |
|---|---|
| `kerberos::golden` | **Forge a Golden or Silver Kerberos ticket** — same command for both; see the flag table below. Registered help string in source: `"Willy Wonka factory"` |
| `kerberos::ptt <file\|dir> [...]` | **Pass-the-ticket.** Inject one `.kirbi` file (or every `.kirbi` in a directory) into the current logon session's ticket cache |
| `kerberos::list [/export]` | List every ticket in the current session's cache; `/export` additionally writes each one to a `.kirbi` file |
| `kerberos::purge` | Purge every ticket from the current session's cache (no selective options — it's all-or-nothing) |
| `kerberos::tgt` | Retrieve and display the current session's **real** TGT, including its session key (only non-null if `allowtgtsessionkey=1` is set — see Prerequisites) |
| `kerberos::ask /target:<SPN> [/rc4\|/des\|/aes128\|/aes256] [/export] [/tkt] [/nocache]` | Request a TGS for a specific SPN using the current session's own TGT — a legitimate LSA ticket request, not a forgery |
| `kerberos::hash /password:<pw> /user:<u> /domain:<d> [/count:<n>]` | Derive RC4/AES128/AES256/DES Kerberos keys from a **known plaintext password**, entirely offline |
| `kerberos::ptc <ccache-file>` | **Pass-the-ccache** — import an MIT/Heimdal-format ticket cache (e.g. one generated by Impacket on Linux) into the current Windows LSA session |
| `kerberos::clist <ccache-file>` | List tickets inside an MIT/Heimdal ccache file, without importing them |
| `kerberos::decrypt` / `kerberos::pacinfo` | Ticket/PAC decode helpers — only present in builds compiled with `KERBEROS_TOOLS` defined; **not present in the standard public releases** |

### `kerberos::golden` — full flag reference

Verified directly against `kuhl_m_kerberos_golden()` in `kuhl_m_kerberos.c`.

| Flag | Meaning |
|---|---|
| `/user` or `/admin` | Username to forge — **arbitrary**, need not exist in AD at all (see the 20-minute rule, above) |
| `/domain` | FQDN of the target domain — mimikatz explicitly checks for a `.` and refuses (`"Domain name does not look like a FQDN"`) if the argument doesn't look like one |
| `/sid` | Domain SID. **Required to generate a PAC at all** — omit it and mimikatz produces a ticket with no PAC, which is of little practical offensive value against a modern, PAC-aware environment |
| `/krbtgt` or `/rc4` | krbtgt's (Golden) or the target service account's (Silver) **NTLM hash**, hex — used as both the ticket-encryption key and, if `/sid` is given, the PAC signing key. `/krbtgt` and `/rc4` are interchangeable aliases for the exact same RC4 key type in source |
| `/aes128` / `/aes256` | AES key material instead of RC4/NTLM — avoids the RC4-encryption-type detection signal (`05 - Detection and Hunting.md`) |
| `/des` | Legacy DES key type — effectively obsolete on any modern domain |
| `/id` | RID of the forged user. Default **`500`** — the built-in Administrator RID |
| `/groups` | Comma-separated group RIDs to embed in the PAC. Default (verified from source, `kuhl_m_pac_stringTogroups_defaultGroups`): **`513, 512, 520, 518, 519`** — Domain Users, Domain Admins, Group Policy Creator Owners, Schema Admins, Enterprise Admins |
| `/sids` | Extra SID(s) injected into the PAC's SID-history/`ExtraSids` field — the cross-domain/forest escalation primitive (above) |
| `/service` | Target SPN service class (e.g. `cifs`, `http`, `mssqlsvc`, `ldap`, `time`). **Omit for a Golden Ticket** (defaults to `"krbtgt"`, ticket flagged `initial` = shaped like a real TGT). **Set for a Silver Ticket** (ticket is not flagged `initial` — shaped like a TGS-issued service ticket) |
| `/target` | Hostname/FQDN the service ticket is issued "for." Defaults to `/domain` if omitted — set explicitly alongside `/service` for a Silver Ticket targeting a specific server |
| `/rodc` | RODC krbtgt variant — sets the ticket's key-version number to `(1 \| rodc_id << 16)` instead of the hardcoded default, relevant to Kerberos "key list" attacks against Read-Only Domain Controllers |
| `/claims` | Inject a Dynamic Access Control claims set into the forged ticket |
| `/startoffset` | Minutes offset from "now" for the ticket's start time. Default `0`; can be **negative** to backdate the ticket |
| `/endin` | Minutes until expiry. Default **`5256000`** (~10 years — see above) |
| `/renewmax` | Minutes until the max-renewal cutoff. Default: **same value as `/endin`** if not separately specified |
| `/ptt` | Inject the forged ticket directly into the current session (via the same path as `kerberos::ptt`) instead of writing a `.kirbi` file |
| `/ticket` | Output filename when not using `/ptt`. Default **`ticket.kirbi`** |

## Quick Use-Case List

- Forge a Golden Ticket for durable domain-wide persistence, using the default Administrator/Domain-Admins-scoped groups
- Forge and inject in a single step (`/ptt`) — skip ever writing a `.kirbi` file to disk
- Forge with AES128/AES256 key material specifically to avoid the RC4-encryption-type detection signal
- Cross-domain/forest Golden Ticket via `/sids` — inject a parent domain's or trusted forest's Enterprise Admins SID for escalation without ever authenticating there
- RODC-scoped Golden Ticket via `/rodc` — the precursor primitive behind Microsoft's "Kerberos key list attack" alert family
- Forge a Silver Ticket for a specific file server's CIFS service, using only that machine account's own hash — no krbtgt hash needed, no DC contact ever
- Forge a Silver Ticket for a high-value application service account (e.g. `mssqlsvc`) using that service account's own key
- Backdate a forged ticket's start time (`/startoffset`, negative) to make it appear issued earlier, blending with a plausible session window
- Purge the current session's ticket cache (`kerberos::purge`) immediately before injecting a forged ticket, so Windows doesn't prefer an existing legitimate cached ticket over the injected one
- List every ticket in the current session's cache (`kerberos::list`) — verify an injected ticket actually landed, or reconnaissance on what's already cached
- Export every ticket in the current session's cache to `.kirbi` files (`kerberos::list /export`) for reuse on another machine
- Retrieve the current session's real TGT and session key (`kerberos::tgt`) — feeds an overpass-the-hash/ticket-relay workflow, requires `allowtgtsessionkey=1`
- Request an arbitrary TGS for any SPN using the current session's TGT (`kerberos::ask`) — the foundational primitive Kerberoasting-style tooling builds on
- Derive Kerberos keys from a plaintext password recovered by some other means (`kerberos::hash`), entirely offline
- Pass-the-ccache from a Linux/Impacket-generated MIT ccache file into a Windows LSA session (`kerberos::ptc`) — cross-platform ticket interoperability
- Fleet-wide lateral movement using a single forged Golden Ticket — because the ticket's scope isn't tied to any one host, the same `.kirbi` authenticates to every Kerberos-speaking service in the domain the forged group memberships would legitimately reach
- Chained immediately after `lsadump::dcsync /user:krbtgt` — DCSync obtains the key, `kerberos::golden /ptt` uses it, in two commands total, without ever touching a DC's filesystem or LSASS interactively

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| krbtgt account's NTLM or AES key (**Golden**) | Typically obtained via `lsadump::dcsync /user:krbtgt` (see `lsadump (DCSync)/`) or a captured `ntds.dit` — this module covers forging/using the key, not obtaining it |
| Target service/computer account's NTLM or AES key (**Silver**) | Obtained via a live `sekurlsa` LSASS read on a host running that service, `lsadump::dcsync` against the specific service/computer account, or offline cracking |
| Domain SID | Needed to generate a PAC at all (`/sid`) — recoverable via `whoami /user`, a prior LDAP query, or `Get-ADDomain` |
| FQDN of the target domain | `kerberos::golden` refuses a `/domain` argument that doesn't look like a FQDN |
| **No special privilege to forge** | Building the `.kirbi` itself (`kuhl_m_kerberos_golden_data`) is 100% local, offline computation — no administrator rights, no network access, no target-host access of any kind required to run this step |
| Logon session access to **inject** (`/ptt`) | `kerberos::ptt` calls `LsaCallAuthenticationPackage` against the calling process's own logon session — ordinary user rights suffice to inject into your **own** current session; injecting into a **different** logon session (someone else's) requires SYSTEM/impersonation rights on that machine |
| Kerberos must actually be the authentication protocol in use | If the target relationship is NTLM-only, or the service isn't Kerberos-aware, ticket forgery is irrelevant — confirm SPN registration and Kerberos reachability first |
