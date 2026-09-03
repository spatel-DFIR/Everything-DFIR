# LOLBins — setspn.exe — Target Evidence

This is a **Domain-Controller-side (and, for `-F`, Global-Catalog-side) evidence story**, the same evidentiary shape as [`Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md>) — nothing about `setspn.exe`'s own read/write operations ever touches the SPN-bearing account's own host. This file keeps two evidentiary tracks separate throughout, since they're governed by different audit mechanisms:

- **The read/recon track** (`-L`, `-Q`, `-X`) — an LDAP search, no directory object is modified.
- **The write track** (`-S`, `-A`, `-D`, `-R`) — an LDAP modify, which is what actually creates the Targeted-Kerberoasting attack surface and is what the events below are mostly built to catch.

## Contents
- [LDAP Query Logging — Recon Track](#ldap-query-logging--recon-track)
- [Directory Service Change Auditing — Write Track (the Centerpiece)](#directory-service-change-auditing--write-track-the-centerpiece)
- [A Common Misconception — Event 4738 Does NOT Show SPN Changes](#a-common-misconception--event-4738-does-not-show-spn-changes)
- [Security 4769 — Correlating the Roast That Follows](#security-4769--correlating-the-roast-that-follows)
- [Duplicate-SPN Errors as a Side Effect](#duplicate-spn-errors-as-a-side-effect)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Building a Timeline](#building-a-timeline)
- [Contrast With GetUserSPNs.py](#contrast-with-getuserspnspy)

---

## LDAP Query Logging — Recon Track

`setspn -Q`/`-X`'s LDAP search leg is, **by default, not logged at all** on a Domain Controller — the identical non-default-logging story already documented in depth in [`Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md>), cross-linked here rather than re-derived:

- **Directory Service Access auditing (Security 4662)** requires both the **Audit Directory Service Access** subcategory and a SACL configured for read access on the relevant objects — neither on by default.
- **LDAP diagnostic/"expensive query" logging (Directory Service Event 1644)** requires `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering = 5` (or higher) — not default. Where enabled, 1644 captures the literal filter string, `(servicePrincipalName=*)`, the same filter `GetUserSPNs.py` issues, confirmed by a Microsoft AskDS network-trace analysis of `setspn -X -F` specifically — that analysis also confirmed a forest-scoped query lands on the **Global Catalog, TCP 3268**, paged at **100 objects per page** (a different page size than `GetUserSPNs.py`'s 1000-per-page default).

**Practical takeaway, identical to `GetUserSPNs.py`'s own:** absent one of those two non-default configurations, a `setspn -Q`/`-X` recon pass is invisible on the DC. Rank this track below the write-track evidence in `05 - Detection and Hunting.md`'s Hunting Priority table for exactly this reason.

## Directory Service Change Auditing — Write Track (the Centerpiece)

**Security Event 5136 — "A directory service object was modified"** is the correct, authoritative event for an SPN add or delete via `-S`/`-A`/`-D`/`-R`. Verified against Microsoft's [5136 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) and cross-checked against independent Windows-security references: 5136 fires when the **Audit Directory Service Changes** advanced audit subcategory is enabled **and** a SACL is configured on the target object (or its parent OU) to audit write access to the `servicePrincipalName` attribute specifically — **neither is on by default**, the same SACL-dependent caveat this module has already flagged for DRSUAPI DCSync traffic (`Mimikatz/lsadump (DCSync)/`) and for 4662 above. Where enabled, an SPN change produces a **pair** of 5136 events for one logical change — one `Value Deleted`/`Value Added` pair if replacing a value, or a single `Value Added` for a pure `-S` addition and a single `Value Deleted` for a pure `-D` removal — each carrying:

| Field | What it shows |
|---|---|
| `Object DN` | The full distinguished name of the account object whose `servicePrincipalName` changed |
| `Attribute LDAP Display Name` | `servicePrincipalName` — confirms this is an SPN change specifically, not some other account-attribute edit |
| `Attribute Value` | The exact SPN string added or removed — e.g. `http/fakesvc.corp.local` from `02`'s Targeted Kerberoasting example |
| `Operation Type` | `%%14674` (Value Added) or `%%14675` (Value Deleted) |
| `Subject Account Name`/`Subject Account SID` | The identity that performed the write — the account whose `GenericWrite`/Validated-SPN rights made the change possible |
| `DC Name` | Which DC processed the modify — useful for the fleet-wide sweep in `05`, since writes can land on any DC in a multi-DC environment |

**This is the single most important native signal for the write track**, because unlike the recon track's 4662/1644 dependency, an environment that has SACL'd its Tier-0/service-account OUs for `servicePrincipalName` writes specifically (a reasonable, targeted hardening step, much cheaper than auditing every read) catches every `-S`/`-A`/`-D` regardless of which tool performed it — `setspn.exe`, PowerView's `Set-DomainObject`, ADSI Edit, or the Active Directory Users and Computers GUI all funnel through the identical LDAP modify and the identical 5136.

## A Common Misconception — Event 4738 Does NOT Show SPN Changes

**Security Event 4738 — "A user account was changed"** is frequently assumed to be the event that captures SPN additions, since it's the general "something about this user object changed" event and fires on a broad set of account-attribute modifications. **This assumption is wrong, and worth correcting explicitly:** verified against Microsoft's [4738 field reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4738), the event's fixed field set covers things like `UserAccountControl` flag changes, password-last-set, home directory/script path, logon hours, primary group, and a dedicated `AllowedToDelegateTo` field — but **that `AllowedToDelegateTo` field tracks the `msDS-AllowedToDelegateTo` attribute (constrained-delegation targets), not the account's own `servicePrincipalName` list.** The two attributes are easy to conflate because both relate to Kerberos service identity, but they are structurally different AD attributes governed by different write permissions and different abuse patterns (constrained-delegation/S4U2Proxy abuse for `msDS-AllowedToDelegateTo`, versus Kerberoasting for `servicePrincipalName`). **Do not rely on 4738 to catch a `setspn -S`/`-D` operation** — it is not the event that reflects that specific attribute, and treating it as such produces a detection gap. Event 5136 (above) is the correct signal.

## Security 4769 — Correlating the Roast That Follows

`setspn.exe` never requests a Kerberos ticket itself (see `01 - Overview.md`), so **Security 4769 — "A Kerberos service ticket was requested"** only enters this picture via whatever separate tool performs the actual TGS-REQ after a `-S` injection or a `-Q` recon pass. Its field structure, the RC4-bias mechanics, the hashcat-mode-per-etype mapping, and the MDI alert catalog are all covered in full in [`Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/04 - Target Evidence.md>) and not re-derived here. **The one setspn-specific addition**: for the Targeted-Kerberoasting use case, the 4769's `Service Name` field naming an account that had **no SPN a few minutes earlier** (confirmed by correlating against the immediately-preceding 5136 `Value Added` event above) is a materially stronger signal than an isolated 4769 alone — it proves the account was made roastable on the spot, not that it was simply an existing, always-roastable service account.

## Duplicate-SPN Errors as a Side Effect

A `-S`/`-A` attempt that collides with an existing SPN elsewhere in the queried scope fails outright with `"Duplicate SPN found, aborting operation!"` (Windows Server 2012+, per Microsoft's own engineering blog on this behavior) **and writes nothing** — no 5136 fires for a failed write, since the directory object was never actually modified. An operator's Targeted-Kerberoasting attempt using a poorly-chosen, already-registered-elsewhere SPN string therefore fails silently from a DC-audit perspective; only the source-side command-line evidence (`03 - Source Evidence.md`) would show the attempt was ever made.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `ldap.log` / `ldap_search.log` | The bind, the search filter (`servicePrincipalName=*` for `-Q`/`-X`), and any modify operations — the richest network-layer signal, naming the exact LDAP operation rather than just "some LDAP traffic occurred" |
| NetFlow / firewall logs | A short TCP 389/636 (domain scope) or TCP 3268/3269 (`-F` forest scope) session between the source host and a DC/GC — without payload decoding, this alone can't distinguish `setspn.exe` from any other LDAP client (ADUC, PowerShell's AD module, `ldapsearch`, `GetUserSPNs.py`'s own LDAP leg), so it's corroborating, not standalone |

## Endpoint Security Product Signatures

`setspn.exe` is a signed, first-party Microsoft binary — static file-signature detection has no purchase, identical to `sc.exe`'s and `wmic.exe`'s own evidentiary story elsewhere in this folder. Detection realistically depends on the DC-side audit evidence above (5136 for writes) plus behavioral heuristics layered on top: an `-S` write originating from a non-Tier-0, non-administrative source host; a write immediately followed by a 4769 for the same account; or the account-attribute-write pattern reaching a SIEM correlation rule keyed on "5136 `servicePrincipalName` add, then 4769 for that same account, within N minutes, then a matching 5136 `servicePrincipalName` delete" — the full injection/roast/cleanup fingerprint from `01`'s red-flag callout, expressed as a correlation rule rather than a single event.

## Building a Timeline

A representative Targeted-Kerberoasting sequence, correlated across source and target evidence:

1. **Source host:** Sysmon 1 / Security 4688 for `setspn -L targetuser` (pre-check) and then `setspn -S http/fakesvc.corp.local targetuser`, full command line captured
2. **DC:** Security 5136 (`Value Added`, `servicePrincipalName` = `http/fakesvc.corp.local`, `Subject Account Name` = the operator's identity) — **requires the non-default SACL/audit-subcategory combination above; absence here does not mean the write didn't happen**
3. **Source host (or a separate tool's host):** the TGS-REQ tool's own execution evidence (see [`Impacket/GetUserSPNs (Kerberoasting)/03 - Source Evidence.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/03 - Source Evidence.md>) if Impacket was the tool used)
4. **DC:** Security 4769 for `http/fakesvc.corp.local`, `Ticket Encryption Type` recorded — cross-reference the requesting `Account Name` against step 2's `Subject Account Name`; a match strongly ties the injection and the roast to the same operator
5. **Source host:** Sysmon 1 / Security 4688 for `setspn -D http/fakesvc.corp.local targetuser` (cleanup)
6. **DC:** Security 5136 (`Value Deleted`) for the same SPN, closing the window
7. *(if the recovered hash was later cracked and used)* — the real end-of-chain event: `targetuser` authenticating from an unusual source shortly after appearing in steps 2-6, the strongest possible confirmation the whole chain succeeded. Not `setspn.exe`-specific evidence, but the natural next correlation point.

## Contrast With GetUserSPNs.py

| | `setspn.exe` | Impacket `GetUserSPNs.py` |
|---|---|---|
| Can enumerate existing SPNs | Yes (`-L`/`-Q`/`-X`) | Yes (default LDAP filter) |
| Can request a Kerberos TGS | **No — never** | Yes (`-request`/`-request-user`/`-request-machine`) |
| Can **create** an SPN on an account that has none | **Yes (`-S`/`-A`)** — the capability `GetUserSPNs.py` structurally lacks | No |
| Requires special AD rights for enumeration | No (readable by `Authenticated Users` by default) | No (same default readability) |
| Requires special AD rights for the write use case | Yes — `GenericWrite`/`GenericAll`/Validated-SPN over the specific target | N/A (no write capability at all) |
| Default presence on a non-DC host | **No** — requires RSAT AD DS/LDS Tools | N/A (third-party install, Python/pip) |
| Primary DC-side evidence | Security 5136 (write track) / 4662+1644 (recon track, both non-default) | Security 4662 + 1644 (recon), Security 4769 (the roast itself) |

`setspn.exe`'s unique contribution to this technique family is the **write** capability — see [`Impacket/GetUserSPNs (Kerberoasting)/`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>) for everything downstream of "a TGS-REQ was requested," which applies identically regardless of whether the target SPN was always there or was injected moments earlier by `setspn -S`.
