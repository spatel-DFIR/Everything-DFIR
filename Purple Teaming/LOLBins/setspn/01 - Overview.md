# LOLBins — setspn.exe — Overview

> 🔴 **Red Flag Principle:** `setspn.exe` plays **two structurally different attacker roles**, and conflating them is the single easiest mistake in hunting this binary. Role one is pure **recon** — `setspn -Q */*` (or `-T <domain> -Q */*`) is a fully native, no-extra-tooling equivalent of Impacket's `GetUserSPNs.py` enumeration pass, listing every SPN-bearing account a domain already has without sending a single TGS-REQ. Role two is a **write primitive**: unlike `GetUserSPNs.py`, which can only Kerberoast accounts that *already* carry an SPN, `setspn -S <fake/spn> <targetuser>` can **create** one on any account the operator holds `GenericWrite`/`GenericAll`/`Validated write to service principal name` rights over — turning an otherwise non-roastable account into a roastable one on demand, a technique the community calls **Targeted Kerberoasting**. The tell for role two is a `setspn -S` immediately followed (often within seconds) by a Kerberos TGS-REQ for that exact SPN and then a `setspn -D` removing it again — an add/roast/remove triplet with no legitimate administrative reason to occur in that sequence or that time window. See `01`'s History section for why `setspn.exe` itself is absent from both the LOLBAS catalog and MITRE's named Kerberoasting procedure-example list despite this.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`setspn.exe` is a first-party Microsoft administrative tool, not an offensive-security-authored one — the same category as `sc.exe` and `wmic.exe` elsewhere in this folder. Verified against contemporaneous documentation of the **Windows 2000 Resource Kit**: the shipped `setspn.exe` binary in that kit carries an internal date of **1999-11-30**, and it was also bundled among the roughly 50 tools included in the separate, more widely-distributed **Windows 2000 Support Tools** package on the Windows 2000 CD — the same Resource-Kit-then-inbox lineage `sc.exe` followed (see [`LOLBins/sc/01 - Overview.md`](<../sc/01 - Overview.md>)). It became a fully **inbox** component — no separate download required — once the **Active Directory Domain Services (AD DS) server role** existed to host it, and per Microsoft's own current [`setspn` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn), that AD DS role dependency still holds today: `setspn` "is available if you have the Active Directory Domain Services (AD DS) server role installed," and it "must be ran through an elevated command prompt." On a non-Domain-Controller host (an operator's own workstation, or a compromised member server), the binary is **not present by default at all** — it only exists there if the machine has the **RSAT: Active Directory Domain Services and Lightweight Directory Services Tools** Feature-on-Demand installed (Windows capability name `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`), which is itself a durable, host-level artifact worth checking for — the same "capability install as a footprint" pattern already documented for `wmic.exe`'s removal path in [`LOLBins/wmic/01 - Overview.md`](<../wmic/01 - Overview.md>), just in the opposite direction (a capability an attacker needs *added*, not one a defender can remove).

**`setspn.exe` has zero presence in the LOLBAS Project's catalog** — verified live against the [`LOLBAS-Project/LOLBAS`](https://github.com/LOLBAS-Project/LOLBAS) repository tree (`yml/OSBinaries/`, master branch): no `Setspn.yml` exists, and no other LOLBAS entry references the binary. This is the same structural gap already documented for `winrar/` and `netcat/` in this folder, though for a different underlying reason in this case — `setspn.exe` doing `-S`/`-D`/`-Q` is normal, fully-documented Windows administration of a normal AD attribute, not "unexpected functionality" abusing a side-effect the vendor never intended, which is LOLBAS's actual scoping bar.

**MITRE ATT&CK's own [T1558.003 (Kerberoasting)](https://attack.mitre.org/techniques/T1558/003/) page does not name `setspn.exe` as a procedure-example tool either** — verified live against the technique page: it names Rubeus, PowerSploit's `Invoke-Kerberoast`, Impacket's `GetUserSPNs`, Empire, SILENTTRINITY, and Brute Ratel C4 as tools that perform the TGS-REQ/crack half of the technique. `setspn.exe`'s own Microsoft syntax reference is cited exactly once, in the page's **references list** as background documentation on what an SPN is — not as a named attacker tool. This tracks with a genuine capability gap: `setspn.exe` **requests no Kerberos tickets and cracks nothing** — it only reads and writes the `servicePrincipalName` LDAP attribute. Its actual attacker role (recon for role one, the write primitive for role two above) sits one layer beneath the TGS-REQ/cracking step ATT&CK's procedure examples focus on. Independent detection-engineering content fills this gap directly, though: Splunk's published security-content analytic ["ServicePrincipalNames Discovery with SetSPN"](https://research.splunk.com/endpoint/ae8b3efc-2d2e-11ec-8b57-acde48001122/) maps `setspn.exe` command-line enumeration patterns to T1558.003 by name and lists it as observed tradecraft associated with several tracked intrusion sets (FIN7, Indrik Spider, Leviathan, Wizard Spider, per that analytic's own group tagging) — real-world usage exists and is tracked, it simply isn't catalogued as a named ATT&CK procedure example the way `GetUserSPNs.py` is.

Tim Medin's original Kerberoasting research (SANS Hackfest 2014) and the RC4-bias/hashcat-mode mechanics of the TGS-REQ/crack step itself are **not re-derived here** — see [`Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>) for that history and the full etype-negotiation mechanics, which apply identically regardless of which tool enumerates the SPNs or requests the ticket.

## How It Works

`setspn.exe` is a thin CLI front end over two very different Active Directory operations depending on the switch used: an **LDAP read** (`-L`, `-Q`, `-X`) or an **LDAP write** (`-S`/`-A`, `-D`, `-R`) against the target account object's `servicePrincipalName` multi-valued attribute. It authenticates using the operator's own current security context (Kerberos or NTLM, whatever the calling process already negotiated with the DC) — there is no `-hashes`/`-k`/`/user:` equivalent, the same "rides an existing session" model documented for `sc.exe` (see [`LOLBins/sc/01 - Overview.md`](<../sc/01 - Overview.md>) How It Works §2).

**1. `-L` — direct object lookup, not a search.** `setspn -L <accountname>` binds directly to the named account object and reads its `servicePrincipalName` values — a targeted, low-noise read of one already-known object, not a domain-wide query. This is the "check one account" primitive; `-Q` is the "find every account" primitive.

**2. `-Q`/`-X` — a paged LDAP search across the domain or forest.** `setspn -Q <pattern>` (pattern may use `*` wildcards on either side of the `/`, e.g. `*/*` for "every SPN of any kind") issues an LDAP search filtered on `servicePrincipalName`. Verified against a Microsoft AskDS engineering blog post analyzing a live network trace of `setspn -X -F`: a **forest-wide** query (`-F`) is sent to the **Global Catalog on TCP 3268** rather than a domain-scoped LDAP port, using the filter `(servicePrincipalName=*)` and Microsoft's own **paged-search page size of 100** objects per page — a different page size than Impacket's `GetUserSPNs.py`, which pages at 1000 (see [`Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>)). A domain-scoped `-Q` (no `-F`) instead queries ordinary LDAP (TCP 389, or LDAPS 636) against a DC for that one domain. Either way, **`-Q` never itself contacts the Kerberos protocol at all** — it is purely an LDAP read, exactly like `GetUserSPNs.py`'s own enumeration step, just without a Python interpreter or third-party package involved.

**3. `-S`/`-A` — a write to `servicePrincipalName`, gated by AD's own ACL model, not by `setspn.exe`.** `setspn -S <spn> <accountname>` performs an LDAP modify (add-value) on the target object's `servicePrincipalName` attribute, after first verifying no duplicate of that exact SPN string exists anywhere reachable from the querying DC (duplicate SPNs break Kerberos authentication for every client that resolves them, which is why Microsoft added the check). The older `-A` switch historically skipped that duplicate check; per Microsoft's own [`SETSPN -A with Windows 2012 does a duplicate check upfront`](https://learn.microsoft.com/en-us/archive/blogs/psssql/setspn-a-with-windows-2012-does-a-duplicate-check-upfront) engineering post, Windows Server 2012 and later made `-A` behave identically to `-S` — both now block a would-be duplicate with `"Duplicate SPN found, aborting operation!"` before writing anything. **This write succeeds or fails purely on the caller's own AD permissions, not on any privilege check inside `setspn.exe` itself** — any principal holding `GenericWrite`, `GenericAll`, `WriteProperty` scoped to `servicePrincipalName`, or the narrower `Validated write to service principal name` extended right over the target object can add an SPN to it, exactly the class of misconfigured/over-delegated ACE BloodHound surfaces (see [`BloodHound/BloodHound/02 - Hands-On Use Cases.md`](<../../BloodHound/BloodHound/02 - Hands-On Use Cases.md>)'s `GenericWrite`/`GenericAll` shortest-path queries). This is the structural basis for **Targeted Kerberoasting**: an operator who cannot enumerate any already-SPN-bearing weak account can instead manufacture one, provided they hold write rights over *some* user object.

**4. `-D` — the mirror of `-S`.** Removes a specific SPN value. Its main attacker-relevant use is cleanup immediately after a Targeted-Kerberoasting SPN injection — see the red-flag callout.

**5. `-R` — resets a computer account's default host SPNs.** Rebuilds the standard `HOST/`-family SPN set for a computer object from its current name; rarely attacker-relevant on its own, but a legitimate administrative action worth distinguishing from `-S`/`-D` when reading a change history.

```
Attacker (already authenticated, standard domain session)         Domain Controller / Global Catalog
─────────────────────────────────────────────────────             ──────────────────────────────────
Role 1 — Recon (no write, no ticket request):
  setspn -Q */*  (or -T <domain> -Q */*)          ────────────▶   LDAP search, (servicePrincipalName=*),
                                                                     paged 100/page (GC:3268 if -F, else
                                                                     domain LDAP:389/636) — same evidentiary
                                                                     shape as GetUserSPNs.py's own LDAP leg

Role 2 — Targeted Kerberoasting (write, then roast, then cleanup):
  setspn -S http/fakesvc.corp.local targetuser    ────────────▶   LDAP MODIFY (add value) on
                                                                     targetuser's servicePrincipalName —
                                                                     requires GenericWrite/Validated-SPN
                                                                     over targetuser specifically
  (separate tool: GetUserSPNs.py -request-user
   targetuser, or Rubeus kerberoast /user:
   targetuser)                                    ────────────▶   TGS-REQ/TGS-REP for the newly-added
                                                                     SPN — Event 4769, same as any
                                                                     Kerberoast (see Impacket/GetUserSPNs/)
  setspn -D http/fakesvc.corp.local targetuser     ────────────▶   LDAP MODIFY (delete value) — SPN
                                                                     removed, account reverts to
                                                                     appearing non-roastable again
```

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique (recon role) | [T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) (SPN-enumeration leg) + [T1087.002 — Account Discovery: Domain Account](https://attack.mitre.org/techniques/T1087/002/) |
| MITRE technique (write/injection role) | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Targeted Kerberoasting is documented community tradecraft under this same sub-technique, not a separately numbered one) |
| Related technique class (the write's real prerequisite) | [T1078.002 — Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) combined with an existing over-permissive ACE — BloodHound's `GenericWrite`/`GenericAll`/`WriteDACL` edges are the reconnaissance step that identifies which account is writable in the first place |
| Directory protocol | **LDAP** — direct object read (`-L`), paged search (`-Q`/`-X`, filter `servicePrincipalName=*`, page size 100 per Microsoft's own network-trace analysis), and LDAP modify (`-S`/`-A`/`-D`/`-R`) |
| Transport | LDAP (TCP 389) or LDAPS (TCP 636) for domain-scoped operations; **Global Catalog (TCP 3268/3269)** for forest-scoped (`-F`) operations |
| Authentication | **None of `setspn.exe`'s own** — rides the calling process's existing Kerberos/NTLM session, identical model to `sc.exe` (see [`LOLBins/sc/01 - Overview.md`](<../sc/01 - Overview.md>)) |
| Authorization boundary | Standard AD DACL evaluation on the target object — `GenericWrite`/`GenericAll`/`WriteProperty(servicePrincipalName)`/`Validated write to service principal name`, or Domain Admin-equivalent rights |
| Kerberos protocol itself | **Never touched by `setspn.exe`.** The actual TGS-REQ/TGS-REP that produces a crackable hash is always a separate tool/step — see [`Impacket/GetUserSPNs (Kerberoasting)/`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>) |
| Binary location | `%SystemRoot%\System32\setspn.exe` — present by default only on Domain Controllers (AD DS role), elsewhere only if the RSAT AD DS/LDS Tools capability is installed |

## Command-Line Switches — Quick Reference

Verified against Microsoft's official [`setspn` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/setspn). Syntax model: **`setspn <modifier> <accountname> [options]`** — `accountname` can be a bare NetBIOS/sAMAccountName or a `domain\name` form, and resolves against a computer object first, falling back to a user object, unless `-C`/`-U` force one or the other.

| Switch | Plain-English meaning |
|---|---|
| `-L <accountname>` | **List** — direct read of every SPN currently registered on the named account object. Fast, targeted, does not search the directory |
| `-Q <SPN-pattern>` | **Query** — searches the domain (or forest, with `-F`) for any account carrying an SPN matching the pattern; wildcards (`*`) accepted on either side of the `/`, so `*/*` matches every SPN of any kind. This is `setspn.exe`'s enumeration/recon primitive — the native equivalent of `GetUserSPNs.py`'s LDAP leg |
| `-S <SPN> <accountname>` | **Set** — adds `<SPN>` to the named account after checking for and blocking a duplicate elsewhere in the queried scope. **The recommended way to add an SPN** per Microsoft's own guidance, and the write primitive behind Targeted Kerberoasting |
| `-A <SPN> <accountname>` | **Add (legacy)** — older equivalent of `-S`. On Windows Server 2012 and later, behaves identically (duplicate-checked); on pre-2012 DCs, added the SPN without checking for duplicates first |
| `-D <SPN> <accountname>` | **Delete** — removes `<SPN>` from the named account. The cleanup half of a Targeted-Kerberoasting add/roast/remove sequence |
| `-R <accountname>` | **Reset** — rebuilds the standard default `HOST/`-family SPN set for a computer account from its current name, discarding any custom SPNs previously set |
| `-X` | **Cross-check for duplicates** — searches the queried scope (domain, or forest with `-F`, or multiple explicit `-T` targets) for any SPN value registered on more than one account, without adding or removing anything. Recon-only, useful for finding pre-existing duplicate-SPN authentication problems an attacker could also exploit for ticket confusion |
| `-C` | Forces `accountname` to be interpreted as a **computer account** specifically |
| `-U` | Forces `accountname` to be interpreted as a **user account** specifically (mutually exclusive with `-C`) |
| `-F` | Performs the operation at **forest** scope (via the Global Catalog) rather than the default domain scope |
| `-T <domain>` | Targets a **specific domain** (or, combined with `-F`, a specific forest) for the query — can be repeated to target several domains in one `-X`/`-Q` pass; `""` or `*` means the current domain/forest |
| `-P` | Suppresses interactive progress output — no console output until the operation fully completes. Useful for unattended/scripted invocation, and for keeping a live console clean during a scripted sweep |
| `-?` / `/?` | Displays help. Running `setspn` with no arguments at all also displays help |

## Quick Use-Case List

- Baseline enumeration — single-account SPN read (`setspn -L <account>`), targeted recon on one already-known service account
- Domain-wide SPN enumeration (`setspn -Q */*`) — the native, no-extra-tooling equivalent of `GetUserSPNs.py`'s recon pass, feeding a standard Kerberoasting target list
- Forest-wide SPN enumeration via the Global Catalog (`setspn -T <domain> -F -Q */*`) — reaches every domain in a multi-domain forest from a single query, useful once a foothold exists anywhere in the forest
- Cross-domain/forest duplicate-SPN discovery (`-X`, optionally with multiple `-T`) — recon that doubles as legitimate troubleshooting cover, since duplicate SPNs are a genuine, commonly-encountered admin problem
- **Targeted Kerberoasting** — injecting a throwaway SPN (`-S`) onto an account that has none but is otherwise writable (`GenericWrite`/`GenericAll`/Validated-SPN rights), requesting a TGS via a separate tool, then removing the SPN (`-D`) to erase the roastability window
- Cleanup/anti-forensics after a Targeted-Kerberoasting run — the `-D` half of the pattern above, run promptly to minimize the account's roastable window
- Pre-attack triage of delegation-adjacent misconfigurations — reading SPNs (`-L`/`-Q`) alongside a broader AD-enumeration pass (BloodHound, PowerView) to decide which SPN-bearing accounts are also high-privilege
- Chained after a BloodHound `GenericWrite`/`GenericAll` shortest-path result — BloodHound identifies *which* account is writable; `setspn -S` is the concrete step that exploits it
- Chained before `Impacket/GetUserSPNs.py` or Rubeus's `kerberoast` — `setspn -Q */*` for recon, then a dedicated Kerberoasting tool for the actual TGS-REQ/crack, since `setspn.exe` alone never requests a ticket
- Legitimate-cover recon — an operator running only read-only switches (`-L`, `-Q`, `-X`) leaves a command line indistinguishable from routine AD service-account administration, useful specifically because it doesn't look like attacker tooling the way `GetUserSPNs.py`'s process name/import footprint would
- Fleet/forest-wide sweep for stale or orphaned SPNs pointing at decommissioned hosts — dual-use: a genuine hygiene task, and also a way to fingerprint retired infrastructure during recon
- Renamed or relocated binary to dodge simple image-name-keyed detection rules, riding on the fact that `setspn.exe` is a small, rarely-baselined administrative utility

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| The `setspn.exe` binary itself present on the operating host | Default only on Domain Controllers (AD DS role). On any other Windows host, requires the **RSAT: Active Directory Domain Services and Lightweight Directory Services Tools** Feature-on-Demand (`Rsat.ActiveDirectory.DS-LDS.Tools`) to be installed — itself a checkable artifact, see `03 - Source Evidence.md` |
| An elevated command prompt | Per Microsoft's own documentation, `setspn` "must be ran through an elevated command prompt" — local admin rights on the *operating* host, distinct from the AD rights needed against the *target* object |
| An already-authenticated domain session | `setspn.exe` carries no credential switches of its own — see How It Works. Requires an existing Kerberos TGT/NTLM session for whatever account is running it |
| Network reachability to a DC (domain scope) or a Global Catalog (`-F` forest scope) | LDAP (TCP 389) or LDAPS (TCP 636) for domain-scoped `-L`/`-Q`/`-S`/`-D`/`-X`; Global Catalog (TCP 3268/3269) for `-F` |
| Read access to `servicePrincipalName` (read use cases: `-L`, `-Q`, `-X`) | Readable by `Authenticated Users` under AD's default schema ACLs — no special rights needed for enumeration, same structural fact that makes standard Kerberoasting universal (see [`Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>)) |
| Write access to `servicePrincipalName` on the specific target object (write use cases: `-S`/`-A`/`-D`/`-R`) | **Not granted by default to ordinary users over an arbitrary account.** Requires `GenericWrite`/`GenericAll`/`WriteProperty(servicePrincipalName)`/`Validated write to service principal name` over that specific object, or Domain Admin-equivalent rights. This is the gating factor for Targeted Kerberoasting specifically — BloodHound's `GenericWrite`/`GenericAll` edges (see [`BloodHound/BloodHound/02 - Hands-On Use Cases.md`](<../../BloodHound/BloodHound/02 - Hands-On Use Cases.md>)) are the standard way to find a qualifying target |
| A separate ticket-requesting tool for any use case that actually produces a crackable hash | `setspn.exe` never sends a TGS-REQ itself — pair with `Impacket/GetUserSPNs.py`, Rubeus, or PowerView's `Get-DomainSPNTicket` |
| GPU/CPU compute for cracking the recovered hash | See [`Hashcat/01 - Overview.md`](<../../Hashcat/01 - Overview.md>)'s Prerequisites, not repeated here |
