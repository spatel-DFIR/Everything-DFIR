# Impacket — GetUserSPNs.py (Kerberoasting) — Target Evidence

This is a **Domain-Controller-side evidence story**, not a workstation one — nothing about this technique ever touches the SPN-bearing service account's own host, and nothing about it touches whatever host the operator ran `GetUserSPNs.py` from beyond what's already covered in `03 - Source Evidence.md`. Everything below happens on, or is logged by, the DC(s) that processed the LDAP query and the Kerberos exchanges.

## Contents
- [Security 4769 — the Centerpiece Event](#security-4769--the-centerpiece-event)
- [Ticket Encryption Type — Exact Field Values](#ticket-encryption-type--exact-field-values)
- [Security 4768 — Why It's Usually Not Informative Here](#security-4768--why-its-usually-not-informative-here)
- [LDAP Query Logging — What Actually Gets Logged, and What Doesn't](#ldap-query-logging--what-actually-gets-logged-and-what-doesnt)
- [The RC4-Downgrade Signal, Precisely](#the-rc4-downgrade-signal-precisely)
- [Microsoft Defender for Identity Alerts](#microsoft-defender-for-identity-alerts)
- [Building a Timeline](#building-a-timeline)

---

## Security 4769 — the Centerpiece Event

**Event ID 4769 — "A Kerberos service ticket was requested"** fires on every Domain Controller that processes a TGS-REQ, regardless of outcome (success or failure — the event's own `S`/`F` subtype distinguishes them). This is generated whenever **Success** auditing is enabled for the **Audit Kerberos Service Ticket Operations** subcategory (under **Account Logon**) — enabled by default via the Default Domain Controllers Policy in most modern AD deployments, but worth confirming rather than assuming in any specific environment. Every field below is drawn from the event's own schema (verified against Microsoft's [4769 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769) and cross-checked against multiple independent Windows-security references):

| Field | What it shows | Why it matters here |
|---|---|---|
| **Account Name** / **Account Domain** | The principal that **requested** the ticket — the `GetUserSPNs.py` operator's own authenticated identity, not the target service account | This is the "one user" half of the burst signal — group every 4769 by this field to find one principal requesting tickets for many different services |
| **Service Name** | The `sAMAccountName` of the **target** SPN-bearing account whose key encrypted the returned ticket | This is the "many different SPNs" half of the burst signal — a legitimate client only ever needs a ticket to the one service it's about to actually use |
| **Service ID** | The SID of the target service account | Cross-references cleanly against AD even if the account is later renamed |
| **Client Address** | Source IP of the requester | Ties the burst to a specific host — correlate against `03 - Source Evidence.md`'s network-evidence window on that host |
| **Ticket Options** | Kerberos ticket flags requested (hex) | Generally unremarkable for this technique — a normal-looking TGS-REQ is expected, since `GetUserSPNs.py` doesn't forge anything, it makes a legitimate request |
| **Ticket Encryption Type** | The etype the KDC actually **issued** the service ticket with | **The single most distinctive field for this technique** — see below |
| **Failure Code** | `0x0` on success; nonzero on a failed request (e.g. `0x1F`/`KDC_ERR_ETYPE_NOSUPP` if the target only supports encryption types the client didn't offer) | A run peppered with 4769 failures against AES-only-hardened accounts, interleaved with 4769 successes against still-RC4-capable ones, is itself a distinctive pattern — it shows the operator sweeping a domain that's been **partially** hardened |

## Ticket Encryption Type — Exact Field Values

Verified against Microsoft's own documentation and cross-checked against the RFC 3961/4757 encryption-type registry these values derive from:

| Hex value | Decimal | Encryption type | Detection relevance |
|---|---|---|---|
| `0x1` / `0x3` | 1 / 3 | DES-CBC-CRC / DES-CBC-MD5 | **Highest concern if seen at all** — DES is cryptographically broken and its presence indicates either a severely legacy configuration or an operator specifically forcing a downgrade; Microsoft's own guidance flags any DES usage as worth immediate investigation |
| `0x11` | 17 | AES128-CTS-HMAC-SHA1-96 | Expected/modern — a Kerberoasted ticket with this etype is still crackable (hashcat mode `19600`, see `01 - Overview.md`), just far more expensive per-guess than RC4 |
| `0x12` | 18 | AES256-CTS-HMAC-SHA1-96 | Expected/modern — same as above, hashcat mode `19700`, the most expensive of the three to crack |
| `0x17` | 23 | RC4-HMAC | **The Kerberoasting-specific tell** — hashcat mode `13100`, dramatically cheaper to crack per-guess than either AES mode; this is the etype `GetUserSPNs.py` biases toward by default (see `01 - Overview.md`'s etype-negotiation section) |

Microsoft's own security-monitoring guidance states this plainly: *monitor for a Ticket Encryption Type other than `0x11`/`0x12`* (the two AES types), and *monitor especially for `0x1`/`0x3`* (DES). A `0x17` on a domain where AES is broadly supported is not, by itself, definitive proof of an attack — legitimate legacy applications that still only speak RC4 exist in some environments — but it is always **worth investigating**, and becomes far more actionable once correlated with the burst pattern (one requester, many services) from the 4769 table above.

## Security 4768 — Why It's Usually Not Informative Here

**Event 4768 — "A Kerberos authentication ticket (TGT) was requested"** fires when the operator's own account obtains its TGT (`GetUserSPNs.py`'s `getTGT()` step). In the overwhelming majority of real cases this is **indistinguishable from an ordinary domain logon** — it's the same AS-REQ any user makes when they log on, and `GetUserSPNs.py` doesn't need to request it in any unusual way (unless `KRB5CCNAME` already has a valid TGT, in which case no 4768 fires at all for this run). The one place 4768 becomes relevant: if the operator's own TGT was obtained via NTLM-hash-derived RC4 specifically to bias the downstream TGS-REQs (per `01 - Overview.md`'s Bias point 1), the 4768's own **Ticket Encryption Type** field will show `0x17` for that logon — worth capturing as corroborating context, but not a standalone signal, since plenty of legitimate RC4 TGT issuance still happens on domains that haven't fully enforced AES.

## LDAP Query Logging — What Actually Gets Logged, and What Doesn't

The LDAP enumeration step (`01 - Overview.md`'s Step 1) is, **by default, not logged at all** on a Domain Controller. Two separate, both non-default mechanisms exist, and neither should be assumed present without confirming:

**1. Directory Service Access auditing (Security Event 4662)** — requires **both** the **Audit Directory Service Access** advanced audit subcategory enabled **and** a SACL configured on the specific AD objects being queried, set to audit **read** access to the relevant attribute(s) (e.g. `servicePrincipalName`). Neither is on by default, and configuring read-access auditing broadly enough to catch an LDAP *search* filtering on `servicePrincipalName=*` (as opposed to a targeted read of one known object) is unusual in practice — most environments that enable 4662 at all scope it to writes/modifications on Tier-0 objects, not read-access sweeps across every user object in the domain. **Do not assume 4662 coverage for this technique's LDAP leg without explicitly confirming the relevant SACLs exist** — this is the same caveat `Mimikatz/lsadump (DCSync)/`'s 4662 coverage carries for DRSUAPI traffic, for the identical underlying reason (SACL-dependent, non-default).

**2. LDAP diagnostic/"expensive and inefficient query" logging (Directory Service Event 1644)** — requires setting `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering` to `5` (or higher) on the DC, which is **not** a default configuration. Once enabled, Event 1644 fires for LDAP searches that exceed configurable inefficiency/expense thresholds and includes the **filter string itself** — meaning a `-request`/default-mode run's literal `(servicePrincipalName=*)` filter, or `-stealth`'s absence of it (replaced by a much larger unfiltered person-object walk that's *more* likely to trip the "expensive search" threshold, not less), is directly visible in this log if it's enabled. This is the mechanism behind community detection content that keys specifically on the `servicePrincipalName=*` filter string appearing in 1644.

**Practical takeaway:** absent one of these two non-default configurations, the LDAP enumeration leg of a `GetUserSPNs.py` run is **invisible on the DC**. This is exactly why `05 - Detection and Hunting.md`'s Hunting Priority table ranks LDAP-side signals below the 4769 burst — they depend on optional configuration most environments haven't turned on, where 4769 requires only the far more commonly-enabled Kerberos Service Ticket Operations auditing.

## The RC4-Downgrade Signal, Precisely

Stated carefully, because an imprecise version of this claim is easy to get wrong: **the client (`GetUserSPNs.py`) offering RC4-HMAC first in its TGS-REQ etype list is not, by itself, suspicious** — plenty of legitimate Windows clients still include RC4 in their offered-etype list for backward compatibility, and the KDC routinely honors whatever the **target account's** `msDS-SupportedEncryptionTypes` attribute permits regardless of client preference (verified against Microsoft's own [RC4 detection/remediation guidance](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) — see `01 - Overview.md`'s etype-negotiation section for the full mechanics). **What actually is suspicious is the *issued* etype in the 4769 — an RC4-encrypted (`0x17`) service ticket being handed out for an account, in a domain where AES support is otherwise broadly enforced, to a requester who is simultaneously pulling tickets for several *other* SPN-bearing accounts in the same short window.** The downgrade signal only earns its weight when read together with the burst pattern — an isolated `0x17` 4769 is weak evidence on its own; a `0x17` embedded in a many-SPNs-one-requester burst is strong evidence.

## Microsoft Defender for Identity Alerts

Verified directly against Microsoft's published Defender for Identity alert catalog (`defender-for-identity/alerts-mdi-classic.md` and `alerts-xdr.md`, [fortra/impacket](https://github.com/fortra/impacket)-independent, MicrosoftDocs-sourced):

| Alert | Classic external ID | MITRE mapping | What it specifically catches |
|---|---|---|---|
| **Security principal reconnaissance (LDAP)** | 2038 | T1087.002 | The LDAP enumeration leg — profiles a computer's normal LDAP query pattern over a 15-day learning period per machine, then alerts on queries deviating from it. Explicitly documented as commonly the **first phase of a Kerberoasting attack** |
| **Suspected Kerberos SPN exposure** | 2410 | T1558.003 | The TGS-REQ burst itself — MDI's dedicated Kerberoasting alert |
| **Possible Kerberoasting attack** *(unified XDR catalog)* | — (detector `xdr_PossibleKerberoastingAttack`) | T1558.003 | Suspicious TGS-REQ volume/pattern from one source IP |
| **Possible Kerberoasting attack following a suspicious LDAP query** | — (`xdr_PossibleKerberoastingFollowingSuspiciousLdapQuery`) | T1558.003, T1087.002 | Correlates the LDAP recon alert with a subsequent TGS-REQ burst from the same source — the two-stage version of the technique |
| **Possible Kerberoasting attack using a stealthy LDAP search** | — (`xdr_PossibleStealthyLdapKerberoastingAttack`) | T1558.003, T1087.002 | **Specifically targets `-stealth`'s evasion** — Microsoft's own description names avoiding the `(servicePrincipalName=*)` filter directly as the pattern this alert is built to catch |
| **Possible SPN enumeration via LDAP** | — (`xdr_PossibleSpnEnumerationLdap`) | T1087.002 | Broader SPN-scanning-via-LDAP detection, not Kerberoasting-specific |
| **Suspected AS-REP Roasting attack** | 2412 | T1558.004 | Not this technique, but the sibling alert for `-no-preauth`-adjacent AS-REQ-based ticket sourcing (`02 - Hands-On Use Cases.md`'s no-preauth use case) |

## Building a Timeline

1. **LDAP query time** (if Event 1644 or a SACL-backed 4662 is available) — establishes when reconnaissance began, from which source.
2. **First 4769 in the burst** — establishes when active roasting began, and the requesting principal's identity.
3. **Every subsequent 4769 from the same Account Name, grouped by time proximity** — reconstructs exactly which accounts were targeted, in what order, and with what etype each one yielded (cross-reference each `Service Name` + `Ticket Encryption Type` pair against `msDS-SupportedEncryptionTypes` on that account to confirm whether the operator actually got a crackable RC4 ticket or was forced to AES).
4. **Correlate against `03 - Source Evidence.md`'s operator-host network window** — the LDAP-then-Kerberos connection sequence on the source host should align tightly with steps 1-3 above, turning "a burst of 4769s happened" into "this specific host, at this specific time, ran this specific tool against these specific accounts."
5. **Any downstream authentication using a cracked service account's actual password** — the real end-of-chain event; a service account authenticating from an unusual source shortly after appearing in a Kerberoasting burst is the strongest possible confirmation the offline cracking step succeeded.
