# Impacket — GetUserSPNs.py (Kerberoasting) — Overview

> 🔴 **Red Flag Principle:** The single strongest signal for this technique isn't any one TGS-REQ — it's the **shape of a burst**: **one user principal requesting Kerberos service tickets (Event 4769) for multiple *different* SPN-bearing accounts in a tight time window**, something a legitimate client (which only ever needs a ticket to the *one* service it's actually about to use) never does. Layer on top of that burst a **Ticket Encryption Type of `0x17` (RC4-HMAC)** rather than `0x11`/`0x12` (AES128/AES256), and confidence goes up sharply — RC4-encrypted service tickets are dramatically cheaper to crack offline, and `GetUserSPNs.py` is deliberately biased (not guaranteed — see **How It Works** below) toward requesting exactly that encryption type. Neither signal alone is fully reliable (see `05 - Detection and Hunting.md`'s Hunting Priority table), but the two together — one requester, many SPNs, RC4 — is close to a smoking gun.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`GetUserSPNs.py` lives in the same [`fortra/impacket`](https://github.com/fortra/impacket) `examples/` folder as `psexec.py`/`secretsdump.py`, authored by **Alberto Solino (`@agsolino`)** per the script's own source header. That header is unusually candid about its lineage, and worth quoting directly rather than paraphrasing (verified against the live `examples/GetUserSPNs.py` file):

> *"This module will try to find Service Principal Names that are associated with normal user accounts. Since normal account's password tend to be shorter than machine accounts, and knowing that a TGS request will encrypt the ticket with the account the SPN is running under, this could be used for an offline bruteforcing attack of the SPNs account NTLM hash if we can gather valid TGS for those SPNs. This is part of the kerberoast attack researched by Tim Medin (`@timmedin`)... Original idea of implementing this in Python belongs to `@skelsec` and his [PyKerberoast](https://github.com/skelsec/PyKerberoast) project."*

Three distinct attributions matter here, and this repo keeps them separate rather than crediting Impacket alone:

1. **The technique itself — "Kerberoasting"** — was researched and publicly named by **Tim Medin**, presented at the **SANS Hackfest 2014** conference in the talk *"Kicking the Guard Dogs of Hades — Attacking Microsoft Kerberos"* (the source header links directly to the SANS-hosted slide PDF). This is the technique's origin point, the same way the Golden Ticket technique traces to Duckwall/Delpy's Black Hat USA 2014 talk (see `Mimikatz/kerberos (Golden-Silver Ticket)/01 - Overview.md`) — both 2014, both landmark Kerberos-abuse research, different techniques entirely.
2. **The first Python implementation idea** is credited to **`@skelsec`**'s `PyKerberoast` project, which predates `GetUserSPNs.py`.
3. **`GetUserSPNs.py` itself**, as it ships in Impacket today, is Alberto Solino's implementation — adding pass-the-hash/pass-the-ticket/pass-the-key authentication support and JtR/hashcat-format output on top of the core idea.

The source header also states the operational thesis plainly, and it's worth carrying forward verbatim since it's the reason this technique targets **user** service accounts specifically rather than every Kerberos-authenticated principal: normal-user-account passwords tend to be **shorter and weaker** than the long, auto-generated passwords Windows assigns to computer/machine accounts — so an attacker Kerberoasting `svc-sql`, `svc-backup`, or similar service accounts is fishing in a pool of much more crackable material than Kerberoasting a machine account would yield. (The tool *can* target machine accounts too, via `-machine-only` — see below — but the technique's real payoff has always been user-driven service accounts.)

## How It Works

### Step 1 — LDAP enumeration of SPN-bearing accounts

`GetUserSPNs.py` first authenticates to the domain's LDAP service and issues **one** paged search (page size 1000, per Active Directory's own hard result-set limit) to find every account carrying a `servicePrincipalName` value. The exact filter string is built at runtime from four literal fragments — verified directly against the `run()` method in `examples/GetUserSPNs.py`:

```
filter_spn      = "servicePrincipalName=*"
filter_person   = "objectCategory=person"
filter_computer = "objectCategory=computer"
filter_not_disabled = "!(userAccountControl:1.2.840.113556.1.4.803:=2)"
```

Assembled into the **default filter** (no flags beyond a bare `-request`):

```
(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))
```

`1.2.840.113556.1.4.803` is the standard **`LDAP_MATCHING_RULE_BIT_AND`** OID; `:=2` tests the `ADS_UF_ACCOUNTDISABLE` bit (`0x2`) of `userAccountControl`, negated — so disabled accounts are excluded **server-side**, before results ever reach the operator. (The client also re-checks the same `UF_ACCOUNTDISABLE` bit locally as a second pass over the returned rows — belt-and-suspenders, not a separate control.) Three flags change this filter:

| Flag | Effect on the filter |
|---|---|
| `-machine-only` | Swaps `objectCategory=person` → `objectCategory=computer` — targets machine accounts' SPNs instead |
| `-request-user <name>` / `-request-machine <name>` | Adds `(sAMAccountName:=<name>)` inside the `(&...)` clause — narrows to one specific account |
| `-stealth` | **Drops the `(servicePrincipalName=*)` clause entirely.** The DC now walks and returns *every* enabled person (or computer, with `-machine-only`) object in the search base — `GetUserSPNs.py` still only prints/requests accounts that actually carry an SPN, but that filtering now happens **client-side**, after the full result set is already transferred. This is exactly what the tool's own help text warns about ("may cause huge memory consumption / errors on large domains") and it's also the exact evasion Microsoft names its own detection after — see `04 - Target Evidence.md` |

Attributes requested per entry: `servicePrincipalName`, `sAMAccountName`, `pwdLastSet`, `MemberOf`, `userAccountControl`, `lastLogon`. The console table this produces includes a **`Delegation`** column derived from two `userAccountControl` bits (`UF_TRUSTED_FOR_DELEGATION` = unconstrained, `UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION` = constrained) — an operator reads this table not just to pick Kerberoast targets, but to spot delegation-abuse targets in the same single query.

### Step 2 — obtaining a TGT, then one TGS-REQ per unique account

```
Attacker (GetUserSPNs.py)                                    KDC (Domain Controller)
──────────────────────────                                   ───────────────────────
1. LDAP bind + paged search, filter above          ────────▶ Returns every enabled SPN-
                                                                bearing person/computer object
                                                                (paged, 1000/page)

2. getTGT(): AS-REQ for the OPERATOR'S OWN account  ────────▶ AS-REP: ordinary TGT for the
   (skipped if -k/ccache already has a valid TGT)             operator's own account — this
                                                                step needs NO special rights,
                                                                it's a routine domain logon

3. For each UNIQUE (account, SPN) pair returned
   in step 1 — one TGS-REQ per account, using the    ────────▶ KDC decrypts the TGT, sees a
   TGT from step 2, naming that account's own SPN               VALID request for a ticket to
   as the requested service                                     an SPN it doesn't need to
                                                                  authorize — issues it anyway
                                                                  (see below for why)
                                                     ◀──────── TGS-REP: service ticket for
                                                                that SPN, encrypted with the
                                                                TARGET SERVICE ACCOUNT'S OWN
                                                                key (not the KDC's, not the
                                                                operator's)

4. Parse enc-part of each TGS-REP, format as
   $krb5tgs$<etype>$... (JtR/hashcat), print or
   write to -outputfile / -save as .ccache
   (zero further network traffic — cracking, if
   any, happens entirely offline, see Hashcat/)
```

**Why no special privilege is needed, structurally:** Kerberos ticket *issuance* and *access authorization* are two separate, separately-timed checks. The KDC's job at TGS-REQ time is only to verify the presented TGT is valid and encrypt a new ticket with the named service's key — it does **not** check whether the requesting principal is actually permitted to *use* that service (that check happens later, at the application server, using the PAC's group memberships). Any authenticated domain principal already holds a TGT from an ordinary logon, and `servicePrincipalName` is a readable attribute for `Authenticated Users` under AD's default schema ACLs — so both prerequisites (a TGT, and the target SPN's name) are available to essentially every domain user by default. This is the structural fact that makes Kerberoasting universal rather than privilege-gated, and it's why the technique has no patch — it abuses intended Kerberos behavior, not a bug.

### Step 3 — the etype negotiation/downgrade, verified against source

This is the part most write-ups get vague about, and it needs precision because the whole "RC4 = suspicious" detection heuristic depends on getting it right. There are **two separate, independent bias points**, both verified directly against Impacket's source (`examples/GetUserSPNs.py` and the shared `impacket/krb5/kerberosv5.py`):

**Bias point 1 — the operator's own TGT (step 2 above).** Unless `-no-rc4` is passed, and a cleartext password (not a hash or AES key) was supplied, `GetUserSPNs.py` converts that password to an NTLM hash first and requests the TGT specifically via RC4-HMAC — the source comment states the intent outright: *"In order to maximize the probability of getting session tickets with RC4 etype, we will convert the password to ntlm hashes (that will force to use RC4 for the TGT)."* If that fails, it falls back to a normal cleartext-password Kerberos exchange (whatever etype the KDC and account negotiate).

**Bias point 2 — the TGS-REQ's own advertised etype list.** `getKerberosTGS()` (the shared function `GetUserSPNs.py` calls once per SPN-bearing account) builds every TGS-REQ with the exact same offered-etype list, **RC4-HMAC listed first**, regardless of what encryption type the operator's own TGT used:

```python
seq_set_iter(reqBody, 'etype',
    (
        int(constants.EncryptionTypes.rc4_hmac.value),
        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),
        int(constants.EncryptionTypes.des_cbc_md5.value),
        int(cipher.enctype)
    ))
```
If the KDC rejects this with `KDC_ERR_ETYPE_NOSUPP` (none of those types are acceptable — e.g. the domain enforces AES-only), Impacket automatically retries with only `aes256_cts_hmac_sha1_96`/`aes128_cts_hmac_sha1_96` offered.

**What this bias does NOT do: it does not force RC4.** The encryption type the KDC actually **issues** the TGS-REP with is determined by the **target service account's own `msDS-SupportedEncryptionTypes` attribute** (verified against Microsoft's own [Kerberos RC4 detection/remediation guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)) — if that attribute is unset or still permits RC4, the KDC honors the client's RC4 preference and a crackable ticket comes back; if the account has been hardened to AES-only (`msDS-SupportedEncryptionTypes` = `24`/`0x18`), the KDC issues AES128 or AES256 regardless of what `GetUserSPNs.py` requested. **The operator's request is a preference, not a guarantee — the target account's own encryption-type configuration is what actually decides crackability**, which is exactly why `05 - Detection and Hunting.md`'s Remediation section treats `msDS-SupportedEncryptionTypes` hardening as the real fix rather than framing this purely as a detect-and-respond problem.

### Step 4 — output format

`outputTGS()` parses each `TGS-REP`'s `enc-part` and branches on the **actual issued etype**, producing a distinct JtR/hashcat-format string per case (verified directly against source):

| Etype | Format produced | Hashcat mode |
|---|---|---|
| RC4-HMAC (23 / `0x17`) | `$krb5tgs$23$*<user>$<realm>$<spn>*$<cipher[:16] hex>$<cipher[16:] hex>` | **`13100`** — verified against `Hashcat/01 - Overview.md`'s own already-verified mode table in this repo |
| AES128-CTS-HMAC-SHA1-96 (17 / `0x11`) | `$krb5tgs$17$<user>$<realm>$*<spn>*$<cipher[-12:] hex>$<cipher[:-12] hex>` | **`19600`** — verified against `hashcat/hashcat`'s own mode catalog (not yet documented in this repo's `Hashcat/` folder; cite this page rather than duplicating a second, possibly-drifting mode table) |
| AES256-CTS-HMAC-SHA1-96 (18 / `0x12`) | `$krb5tgs$18$<user>$<realm>$*<spn>*$<cipher[-12:] hex>$<cipher[:-12] hex>` | **`19700`** — same caveat as above |
| DES-CBC-MD5 (3) | `$krb5tgs$3$*<user>$<realm>$<spn>*$<cipher[:16] hex>$<cipher[16:] hex>` | Not independently verified in this repo — DES Kerberos support is effectively extinct on a modern domain (requires explicit legacy configuration essentially nobody runs), so no widely-used hashcat mode for it is cited here rather than guessing one |
| Anything else | Skipped, with a logged warning (`Skipping <spn> due to incompatible e-type`) | N/A |

Note the **asterisk placement differs** between RC4/DES and AES formats — RC4/DES wrap `*<user>$<realm>$<spn>*` around the whole client/realm/SPN block, AES wraps only `*<spn>*`. This is a real formatting quirk in the tool's own output, not a typo — matching either shape is how you tell which etype a given hash line represents at a glance, before even reading the leading `$krb5tgs$<N>$`.

`-save` additionally writes each requested ticket as a standalone `<username>.ccache` file (full ticket, not just the crackable hash) and implicitly turns on `-request`; `-outputfile` writes the JtR/hashcat lines to a named file instead of stdout and also implicitly turns on `-request`. **Cracking a recovered `$krb5tgs$...` hash is out of scope for this page** — see `Hashcat/01 - Overview.md` and `Hashcat/02 - Hands-On Use Cases.md`'s "Cracking Kerberoasted TGS-REP Tickets" section for attack-mode/wordlist/rule guidance; this page only covers obtaining the hash.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Directory query | **LDAP** — paged search (`SimplePagedResultsControl`, size 1000) against the domain naming context, filtered by `servicePrincipalName`/`objectCategory`/`userAccountControl` |
| Core protocol | **Kerberos** (RFC 4120) — one AS-REQ/AS-REP for the operator's own TGT (unless already cached), then one TGS-REQ/TGS-REP **per unique SPN-bearing account** |
| Encryption negotiation | Kerberos `etype` field in both the TGT request and every TGS-REQ — RC4-HMAC preferred by default (see **How It Works**), overridable per-request by the target account's `msDS-SupportedEncryptionTypes` |
| Authentication (to LDAP and to Kerberos) | NTLM (password or pass-the-hash) or Kerberos (existing ccache, AES key) |
| Credential material recovered | The crackable portion of each TGS-REP's `enc-part` — a hash keyed off the **target service account's own password**, not the operator's |

## Command-Line Switches — Quick Reference

Verified against the current `argparse` block in `examples/GetUserSPNs.py` in [fortra/impacket](https://github.com/fortra/impacket).

**Positional**

| Argument | Meaning |
|---|---|
| `target` | `domain[/username[:password]]` |

**General / targeting**

| Switch | Plain-English meaning |
|---|---|
| `-target-domain <domain>` | Query/request against a **different** domain than the authenticating user's own — enables Kerberoasting across a trust |
| `-no-preauth <account>` | Name of an account that has **Kerberos pre-authentication disabled** — used together with `-usersfile` to source AS-REQ-based (not TGS-REQ-based) tickets for a list of target accounts, bypassing the normal TGT-then-TGS two-step. Niche technique, covered in `02` |
| `-stealth` | Drops the `(servicePrincipalName=*)` clause from the LDAP filter, forcing the DC to return every enabled person/computer object for **client-side** SPN filtering instead of server-side. Trades LDAP query stealth (evades signatures keyed on the literal filter string) for a much larger returned result set |
| `-machine-only` | Targets computer accounts' SPNs instead of user accounts' (`objectCategory=computer` instead of `=person`). AD's default 1000-object LDAP result cap applies — the tool's own paging handles this, but very large domains may still need multiple runs |
| `-usersfile <path>` | Skip LDAP enumeration entirely — read a list of account names from a file and request a TGS for each directly (paired with `-no-preauth`, sources AS-REQ tickets instead) |
| `-request` | Request a TGS for every SPN-bearing account found and print the resulting hash in JtR/hashcat format (default: off — a bare enumeration pass without this flag never sends a single TGS-REQ) |
| `-request-user <username>` | Request a TGS for only the named user's SPN. Mutually exclusive with `-request-machine` |
| `-request-machine <machinename>` | Request a TGS for only the named machine account's SPN (e.g. `workstation01$`). Mutually exclusive with `-request-user` |
| `-save` | Save each requested TGS to disk as `<username>.ccache` (the full ticket, not just the crackable hash). Auto-enables `-request` |
| `-outputfile <path>` | Write the JtR/hashcat-format hash lines to a file instead of stdout. Auto-enables `-request` |
| `-no-rc4` | Do **not** force RC4-HMAC when requesting the operator's own TGT — see **How It Works**'s etype-negotiation section |
| `-ts` | Prefix every log line with a timestamp |
| `-debug` | Verbose debug output |

**Authentication**

| Switch | Plain-English meaning |
|---|---|
| `-hashes LMHASH:NTHASH` | Authenticate via NTLM hash — pass-the-hash |
| `-no-pass` | Don't prompt for a password (pairs with `-k` or `-hashes`) |
| `-k` | Kerberos authentication — read from the `KRB5CCNAME` ccache if present, falling back to command-line credentials otherwise |
| `-aesKey <hex>` | Kerberos AES key (128 or 256-bit) for authentication |

**Connection**

| Switch | Plain-English meaning |
|---|---|
| `-dc-ip <ip>` | IP of a Domain Controller — needed for Kerberos if DNS won't resolve one from the target's domain part |
| `-dc-host <hostname>` | Hostname of a specific Domain Controller to use, if the domain part in `target` shouldn't be relied on for resolution |

## Quick Use-Case List

- Baseline enumeration-only pass — list every SPN-bearing account with zero TGS-REQ traffic (no `-request`/`-request-user`/`-request-machine`/`-save`/`-outputfile`)
- Full `-request` pass against every SPN-bearing account found — the standard "roast everything" run
- Targeting a single high-value account via `-request-user`
- Machine-account-only SPN enumeration/request via `-machine-only` (with `-request-machine` to narrow further)
- Stealthier enumeration via `-stealth` — trades a bigger LDAP result set for evading filter-string-based detections
- Saving raw tickets to `.ccache` (`-save`) versus hash-only output to a file (`-outputfile`)
- Forcing away from the RC4 bias via `-no-rc4`
- Using an already-obtained TGT/ccache (`-k`, `KRB5CCNAME`) rather than a password
- Pass-the-hash authentication (`-hashes`)
- AES-key authentication (`-aesKey`)
- Bulk targeting a pre-known account list via `-usersfile`, skipping LDAP enumeration entirely (lower-noise when targets are already known from a prior pass)
- Niche AS-REQ-sourced ticket requests via `-usersfile` + `-no-preauth`, bypassing the TGT-then-TGS two-step
- Cross-trust Kerberoasting via `-target-domain`
- Chained after `secretsdump.py`/a password spray/an initial foothold for the domain credential that authenticates the LDAP bind and TGS-REQs
- Chained into `Hashcat/` for offline cracking of the recovered `$krb5tgs$...` hashes

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Valid domain authentication material | Cleartext password, NTLM hash, Kerberos ticket, or AES key for **any** domain account — no elevated group membership or delegated rights of any kind, this is the entire point of the technique |
| Network reachability to a Domain Controller | LDAP (TCP 389, or LDAPS 636) for enumeration; Kerberos (TCP/UDP 88) for the AS-REQ/TGS-REQ exchanges |
| Readable `servicePrincipalName` attribute | True by default under AD's out-of-the-box schema ACLs for `Authenticated Users` — an environment that has specifically locked this down (uncommon) would break the LDAP enumeration step, though `-usersfile` with an already-known target list bypasses the need for it entirely |
| For any use case producing a crackable hash: target account still permits a weak-enough etype | See **How It Works**'s etype section — an AES-only-hardened target account (`msDS-SupportedEncryptionTypes` = `24`) still yields a technically valid ticket, just one that's dramatically harder to crack; see `05 - Detection and Hunting.md`'s Remediation for why this is the single most effective structural mitigation |
| For cracking the recovered hash | GPU/CPU compute and hashcat/John — see `Hashcat/01 - Overview.md`'s Prerequisites, not repeated here |
