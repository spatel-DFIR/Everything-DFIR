# Rubeus — Overview

> 🔴 **Red Flag Principle:** Rubeus is a raw Kerberos protocol client written in C# — for every action that talks to a KDC (`asktgt`, `asktgs`, `s4u`, `brute`, `kerberoast`, `asreproast`, `changepw`), it builds and sends AS-REQ/TGS-REQ traffic to **UDP/TCP 88 directly from whatever process is hosting the Rubeus code**, never from `lsass.exe`. On a Windows host, Kerberos port-88 traffic should only ever originate from `lsass.exe` — a non-`lsass.exe` process (`Rubeus.exe`, or any process the assembly was reflectively loaded into) sending raw port-88 traffic is Rubeus's single hardest-to-avoid tell, acknowledged explicitly by the tool's own author in its README. Layer on top of that the tool's own second-favorite signal: **RC4 (`rc4_hmac`) ticket material in a domain running functional level 2008+**, where AES is the default — an "encryption downgrade" visible at the host, network, and domain-controller-log layers simultaneously.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/Rubeus`](https://github.com/GhostPack/Rubeus), and its `README.md`/`CHANGELOG.md`:

- **Primary author:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`), part of the same GhostPack author family as `Seatbelt/` (already built in this repo). **Charlie Clark** and **Ceri Coburn** are credited as significant co-developer contributors; **Elad Shamir** contributed the resource-based constrained delegation work.
- **License:** BSD 3-Clause, copyright 2018 Will Schroeder.
- **Lineage — Rubeus is explicitly a C# port/adaptation, not an original protocol implementation.** The README states plainly it is "**heavily** adapted from" two prior projects: Benjamin Delpy (`@gentilkiwi`, Mimikatz's author)'s **Kekeo** (CC BY-NC-SA 4.0), and Vincent LE TOUX's **MakeMeEnterpriseAdmin** (GPL v3.0) — "without their prior work this project would not exist," in the author's own words. PKINIT support was adapted from Steve Syfuhs's Kerberos.NET (`Bruce`); PAC NDR encoding/decoding is based on Google Project Zero's `NtApiDotNet`.
- **Purpose:** where Kekeo was the original proof-of-concept for raw Kerberos abuse (TGT/TGS requests, S4U abuse, ticket forging) in unmanaged C++, Rubeus reimplements the same primitives natively in C#/.NET — making it trivially embeddable in other C#-based tradecraft (Cobalt Strike's `execute-assembly`, Covenant, PowerShell reflection) without shelling out to a separate native binary.
- **No compiled binaries are ever released.** The README states this explicitly under Compile Instructions: *"We are not planning on releasing binaries for Rubeus, so you will have to compile yourself."* Every real-world Rubeus binary in circulation is therefore a custom, operator-specific compile — filename, PDB path, and PE metadata (`AssemblyTitle`/`AssemblyProduct`/etc., all editable at compile time) are **not** stable, known-bad indicators the way a vendor-shipped tool's are. This is a materially different starting position from something like Sysinternals PsExec or AdFind, where a canonical shipped binary exists to fingerprint against.
- **Current release:** the CHANGELOG's most recent entry is **`[3.3.1]`** — a Unicode-domain-name fix and a UTC timestamp correction for `s4u /opsec`. Worth flagging: the illustrative console-output banners throughout the README itself display an older `v2.3.3`/`v1.x` string in different examples (they're leftover screenshots from various points in the project's history, not a live version indicator) — don't treat the banner text in a captured Rubeus console transcript as a reliable version fingerprint.
- Rubeus's `kerberoast` action is the documented successor to the standalone **[SharpRoast](https://github.com/GhostPack/SharpRoast)** project (folded in and superseded); `asreproast` is the documented successor to the standalone **[ASREPRoast](https://github.com/HarmJ0y/ASREPRoast/)** project (which used the heavier BouncyCastle library).

## How It Works

Rubeus's real value is that it implements the **Kerberos wire protocol itself** in managed code, rather than shelling out to `klist`/`kinit` or reading LSASS memory. This has one crucial forensic consequence spelled out directly in the project's own "Opsec Notes" section: **Rubeus does not touch LSASS memory, ever, by design** ("Rubeus doesn't have any code to touch LSASS (and none is intended)"). Where Mimikatz's `sekurlsa::*` commands open a read/write handle to `lsass.exe` and walk its memory, every Rubeus command falls into one of three mechanically distinct buckets:

| Bucket | Mechanism | Commands |
|---|---|---|
| **Raw protocol traffic** | Hand-built ASN.1 AS-REQ/TGS-REQ/AP-REQ/KRB-PRIV messages sent directly over a TCP/UDP socket to port 88 (or 464 for `changepw`) | `asktgt`, `asktgs`, `renew`, `brute`/`spray`, `preauthscan`, `s4u`, `kerberoast` (some modes), `asreproast`, `changepw` |
| **LSA API calls (no memory read)** | `LsaCallAuthenticationPackage()` against the already-running Kerberos SSP, asking the OS itself to hand back or accept ticket data — the same API legitimate Windows components use | `ptt`, `purge`, `triage`, `klist`, `dump`, `monitor`, `harvest` |
| **Offline cryptography / ASN.1 manipulation** | No network or LSA calls at all — pure local key derivation, PAC construction, or ticket parsing | `golden`, `silver` (unless `/ldap` is used), `hash`, `describe`, `tgssub`, `kirbi`, `asrep2kirbi` |

### Requesting and applying a TGT (`asktgt` → `ptt`)

```
Operator host (Rubeus.exe)                              KDC (Domain Controller, port 88)
───────────────────────────                              ─────────────────────────────────
1. Build AS-REQ for /user:X, pre-auth encrypted   ─────▶  Validate pre-auth timestamp against
   with the supplied /rc4|/aes128|/aes256|/des             the account's own key; if valid,
   key (or /password, defaulting to RC4)                   build TGT + PAC from real AD data

2. Receive AS-REP, decrypt with the same key      ◀─────  AS-REP: KRB-CRED (the TGT) encrypted
                                                             with the krbtgt account's key

3. [/ptt] LsaCallAuthenticationPackage()
   KERB_SUBMIT_TKT_REQUEST — inject the decoded
   KRB-CRED into the CURRENT logon session's
   ticket cache via the Kerberos SSP (no LSASS
   memory write — this goes through the API)
```

This is the C#/raw-protocol equivalent of Mimikatz's `sekurlsa::pth` (over-pass-the-hash) — but where Mimikatz patches a hash into a sacrificial logon session's LSASS memory to force a *real* Windows logon to derive the ticket, Rubeus simply builds the AS-REQ itself and hands the KDC's answer straight to the ticket cache API. **No administrative rights are required** to request a TGT or apply it via `/ptt` to the *current* logon session — only the target account's key. Administrative rights are only needed for `/luid:0xA..` (targeting a different logon session) or `/createnetonly` (spawning a fresh sacrificial process/session, the `runas /netonly` equivalent via `CreateProcessWithLogonW()`).

### Constrained delegation abuse (`s4u`)

`s4u` chains two separate Kerberos extensions (S4U2Self, then S4U2Proxy) against an account configured for constrained delegation (a value in `msDS-AllowedToDelegateTo` plus `TrustedToAuthForDelegation` in `userAccountControl`):

```
1. S4U2Self:  "patsy" (the delegation-trusted account) asks the KDC for a
              forwardable ticket TO ITSELF, but naming /impersonateuser:dfm.a
              as the client — the KDC honors this because patsy is trusted
              for constrained delegation, no dfm.a credential needed.

2. S4U2Proxy: patsy presents that S4U2Self ticket back to the KDC, asking
              for a service ticket to /msdsspn:<SPN in AllowedToDelegateTo>,
              impersonating dfm.a — the resulting ticket lets patsy access
              that specific SPN AS dfm.a.

3. /altservice substitutes the sname field of the final ticket for any
   OTHER service name (the underlying server object isn't re-validated —
   Alberto Solino's finding that only the SERVER name, not the SERVICE
   name, is protected in a KRB-CRED) — turning access to one nominal SPN
   into de facto access to every service running on that same server.
```

### Ticket forgery — three distinct trust models, not one

The `golden`/`silver`/`diamond` commands are frequently treated as interchangeable "make a fake ticket" tools. They are not — they differ in exactly what gets contacted and when, which is the single most important distinction for a defender to internalize:

| Command | What it actually does | KDC contact at creation? |
|---|---|---|
| `golden` | Builds a **TGT from nothing** — hand-crafts the PAC and `EncTicketPart`, signs/encrypts with a supplied `krbtgt` key. `/ldap` optionally queries LDAP (and mounts SYSVOL) to populate realistic PAC fields, but this is a normal authenticated LDAP read, not a Kerberos ticket request | **No** (unless `/ldap` — LDAP/SMB traffic only, no AS-REQ/TGS-REQ) |
| `silver` | Same offline-forge mechanic as `golden`, but for a **service ticket** (or a TGT with more granular control) encrypted with the *service account's* key instead of `krbtgt`'s | **No** (same `/ldap` caveat) |
| `diamond` | Requests a **genuine TGT via a real AS-REQ** (or via the `tgtdeleg` trick) for `/user:X`, **decrypts it, modifies the PAC in place** (`/ticketuser`, `/groups`, `/sids`), **re-signs with `/krbkey`, and re-encrypts** — a real ticket, surgically edited, not built from nothing | **Yes** — the initial AS-REQ/AS-REP for the base TGT is genuine, DC-logged Kerberos traffic |

This directly parallels — and shares its name with — the community-coined **"Diamond Ticket"** technique already documented against Impacket's `ticketer.py -request` flag in `Impacket/ticketer/01 - Overview.md`. The two tools converge on the identical idea (clone a real ticket, edit its PAC, re-sign) from different implementations; **Rubeus's `diamond` is a first-class, source-named command**, not a repurposed flag the way Impacket's is. Neither tool has an equivalent to Impacket's `-impersonate` ("Sapphire Ticket" — S4U2Self+U2U theft of a *real* target user's PAC); Rubeus's closest analog is `silver /s4uproxytarget`/`/s4utransitedservices`, which adds a hand-built S4U delegation-info PAC section rather than stealing a genuine one.

### Elevated ticket extraction — the winlogon.exe token-duplication path

`triage`, `klist`, `dump`, `monitor`, `harvest`, and any use of `/luid:0xA..`/`ptt`/`purge` targeting a **different** logon session all require elevated, all-users enumeration. The README's own prose describes this step as registering "a fake logon application... with the `LsaRegisterLogonProcess()` API call" — **this is stale relative to the current source.** Reading `Rubeus/lib/LSA.cs`'s `GetLsaHandle()` directly: when the process is high-integrity but not already SYSTEM, Rubeus calls `Helpers.GetSystem()` first — which opens `winlogon.exe` with `OpenProcessToken(..., TOKEN_DUPLICATE, ...)`, `DuplicateToken()`s its SYSTEM token, and `ImpersonateLoggedOnUser()`s it — **then calls the exact same `LsaConnectUntrusted()`** used for the non-elevated path. There is no `LsaRegisterLogonProcess()` P/Invoke declaration anywhere in `Interop.cs`, and grepping every call site in `LSA.cs` turns up `LsaConnectUntrusted()` in all five instances. The actual forensic signal for elevated Rubeus ticket extraction is therefore **a handle opened to `winlogon.exe` by an unusual process, followed by that process impersonating a SYSTEM token** — a well-known, specifically-watched token-theft pattern — not a distinctive LSA logon-process registration event. Treat the README's own "fake logon application" framing as describing the *design intent* other GhostPack-lineage tools use, not this code path as it exists in the current repository.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Kerberos (core) | Raw AS-REQ/AS-REP, TGS-REQ/TGS-REP, AP-REQ, KRB-PRIV over TCP/UDP 88 to a domain controller, or MS-KKDCP (`/proxyurl`) HTTPS to a KDC proxy |
| Kerberos password change | RFC 3244 (`kadmin/changepw`) over UDP/TCP **464** for `changepw` |
| LDAP/LDAPS | `golden`/`silver /ldap` PAC-field population; `kerberoast`/`asreproast`/`preauthscan` target-account discovery (389/636) |
| SMB | `golden`/`silver /ldap` mounts a DC's `SYSVOL` share to read the Default Domain Policy file for password-age fields |
| LSA API (SSP-level, not LSASS memory) | `LsaConnectUntrusted()`, `LsaCallAuthenticationPackage()` (`KerbRetrieveEncodedTicketMessage`, `KerbQueryTicketCacheMessage`, `KerbSubmitTicketMessage`, `KerbPurgeTicketCacheMessage`) |
| Windows token APIs | `OpenProcessToken`/`DuplicateToken`/`ImpersonateLoggedOnUser` against `winlogon.exe` (elevated `GetSystem()`); `CreateProcessWithLogonW` (`/createnetonly`, logon type 9) |
| Kerberos GSS-API | `AcquireCredentialsHandle()`/`InitializeSecurityContext()` with `ISC_REQ_DELEGATE` — the `tgtdeleg` "fake delegation" trick, also used internally by `diamond /tgtdeleg` |
| PKINIT | RFC 4556 certificate-based Kerberos pre-authentication (`asktgt`/`diamond /certificate:X.pfx`) |

## Command-Line Switches — Quick Reference

Verified live against [`GhostPack/Rubeus`](https://github.com/GhostPack/Rubeus)'s `README.md` and the `Rubeus/Commands/*.cs`/`Rubeus/lib/*.cs` source. Rubeus has **17 top-level commands**, each with its own switch surface — the table below groups them by the README's own section headers; every command and every switch used in this note's examples is verified against source, not guessed.

| Command | Group | What it does |
|---|---|---|
| `asktgt` | Ticket requests | Request a TGT from a password/hash/certificate |
| `asktgs` | Ticket requests | Request a service ticket from an existing TGT |
| `renew` | Ticket requests | Renew a TGT (optionally `/autorenew` up to its renew-till limit) |
| `brute` (alias `spray`) | Ticket requests | Kerberos-based password brute-force/spray via AS-REQ |
| `preauthscan` | Ticket requests | Find accounts with Kerberos pre-auth disabled |
| `s4u` | Delegation abuse | S4U2Self/S4U2Proxy constrained-delegation abuse |
| `golden` | Ticket forgery | Offline-forge a TGT |
| `silver` | Ticket forgery | Offline-forge a service ticket (or TGT with finer control) |
| `diamond` | Ticket forgery | Request a real TGT, then decrypt/modify/re-sign its PAC |
| `ptt` | Ticket management | Import a ticket into a logon session |
| `purge` | Ticket management | Clear a logon session's ticket cache |
| `describe` | Ticket management | Parse and print a ticket's fields |
| `triage` | Extraction/harvesting | Summary table of cached tickets (current user, or all users if elevated) |
| `klist` | Extraction/harvesting | Detailed per-session ticket listing |
| `dump` | Extraction/harvesting | Extract full base64 KRB-CRED blobs of cached tickets |
| `tgtdeleg` | Extraction/harvesting | Unprivileged, usable-TGT extraction via the GSS-API delegation trick |
| `monitor` | Extraction/harvesting | Poll for new TGTs (elevated) — unconstrained-delegation harvesting |
| `harvest` | Extraction/harvesting | `monitor` + automatic renewal + periodic cache dump |
| `kerberoast` | Roasting | Request and dump crackable TGS-REP hashes for SPN-bearing accounts |
| `asreproast` | Roasting | Request and dump crackable AS-REP hashes for pre-auth-disabled accounts |
| `changepw` | Misc | Reset a password using a TGT ("Aorato"/kpasswd technique) |
| `hash` | Misc | Calculate RC4/AES128/AES256/DES Kerberos keys from a password |
| `tgssub` | Misc | Swap the service name (sname) in an existing service ticket |
| `createnetonly` | Misc | Spawn a hidden `runas /netonly`-style sacrificial process |
| `currentluid` / `logonsession` | Misc | Display the current/target logon session ID and metadata |
| `asrep2kirbi` / `kirbi` | Misc | Convert/manipulate raw AS-REP or KRB-CRED data into a usable `.kirbi` |

**Cross-cutting switches** (apply across most commands, not just one):

| Switch | Plain-English meaning |
|---|---|
| `/ptt` | Pass-the-ticket — immediately import the result into the current logon session |
| `/luid:0xA..` | Target a specific logon session ID instead of the current one (requires elevation) |
| `/nowrap` | Don't column-wrap base64 ticket output — easier to script against |
| `/opsec` | Reshape the request to look more like a genuine Windows-issued one (see **Opsec-relevant flags**, below). Restricted to AES256 by default; combine with `/force` to allow other encryption types |
| `/createnetonly:PATH` | Spawn a hidden (unless `/show`) sacrificial process (logon type 9) and apply the ticket there instead of the current session |
| `/proxyurl:URL` | Route the Kerberos exchange through an MS-KKDCP HTTPS KDC proxy instead of a direct port-88 connection |
| `/consoleoutfile:PATH` | Redirect all console output to a file |
| `/debug` | Print raw ASN.1 debugging output |
| `/nopac` | Request/forge a ticket without a PAC |
| `/enctype:DES\|RC4\|AES128\|AES256` | Force a specific Kerberos encryption type for the exchange |

**Opsec-relevant flags worth calling out individually** — each ties directly to a specific detection this repo tracks:

| Switch | Command(s) | Why it matters |
|---|---|---|
| `/opsec` | `asktgt`, `asktgs`, `s4u` | Sends an initial AS-REQ **without** pre-auth first (matching genuine client behavior) before falling back to a pre-authenticated request — the default (non-`/opsec`) request shape differs structurally from a real Windows client's |
| `/rc4opsec` | `kerberoast` | Uses the `tgtdeleg` trick and **filters LDAP results to only AES-disabled accounts**, so every roasted ticket is RC4 *because the account genuinely only supports RC4* — not because Rubeus forced a downgrade against an AES-capable account |
| `/tgtdeleg` | `kerberoast` | Forces RC4 tickets for AES-enabled accounts too (a genuine downgrade, unlike `/rc4opsec`) |
| **(no flag)** | `kerberoast` | **Default behavior requests each account's *highest supported* encryption type via `KerberosRequestorSecurityToken`** — Rubeus prints `"NOTICE: AES hashes will be returned for AES-enabled accounts. Use /ticket:X or /tgtdeleg to force RC4_HMAC for these accounts."` on every run with no other flags |
| `/nopreauth:USER` | `kerberoast` | Sends AS-REQ's instead of TGS-REQ's, generating Event 4768 instead of the 4769 most Kerberoast detections watch for |
| `/oldpac` | `golden` | Omits the newer *Requestor*/*Attributes* PAC buffers added in response to **CVE-2021-42287** (sAMAccountName spoofing) |
| `/nofullpacsig` | `silver` | Omits the *FullPacChecksum* introduced to close **CVE-2022-37967** (PAC signature bypass) — included by default in any ticket not signed with the real `krbtgt` key |
| `/bronzebit` | `s4u` | Implements **CVE-2020-17049** — flips the *forwardable* flag on an S4U2Self ticket by decrypting/re-encrypting it, which requires the service account's own key |

## Quick Use-Case List

- Requesting a TGT from a password, NTLM hash, or AES key — the C#/raw-protocol equivalent of over-pass-the-hash
- Requesting a TGT via PKINIT certificate authentication, with optional NT-hash recovery via `/getcredentials` (U2U)
- Requesting a service ticket directly via AS-REQ (no separate TGT step) with `/service:SPN`
- Requesting/applying a service ticket from an existing TGT (`asktgs`), including cross-realm enterprise-principal requests
- Renewing a TGT up to its renew-till limit, including unattended auto-renewal
- Kerberos-native password brute-forcing/spraying (`brute`/`spray`) against a user list
- Discovering accounts with Kerberos pre-authentication disabled (`preauthscan`), as an AS-REP-roasting precursor
- Constrained-delegation abuse via S4U2Self/S4U2Proxy, including cross-domain S4U and alternate-service (`/altservice`) substitution
- The Bronze Bit exploit (CVE-2020-17049) against protected-users S4U2Self restrictions
- Offline Golden Ticket forgery (LDAP-assisted or fully manual PAC field-setting)
- Offline Silver Ticket forgery, including S4U delegation-info PAC injection and referral-ticket crafting
- Diamond Ticket forgery — cloning and surgically re-signing a genuine TGT
- Pass-the-ticket (`ptt`), ticket-cache purging, and parsing/describing an arbitrary `.kirbi`
- Unprivileged ticket triage/listing (`triage`/`klist`) and full extraction (`dump`) of the current user's cached tickets
- Unprivileged, usable-TGT extraction without elevation via the `tgtdeleg` GSS-API delegation trick
- Elevated, all-users ticket monitoring/harvesting (`monitor`/`harvest`) — the standard play against unconstrained-delegation hosts
- Kerberoasting, across at least five distinct opsec postures (default, `/rc4opsec`, `/tgtdeleg`, `/aes`, `/nopreauth`)
- AS-REP roasting pre-auth-disabled accounts, with direct Hashcat/John output formatting
- Resetting another user's password using a stolen TGT (`changepw`, the "Aorato" kpasswd technique)
- Calculating Kerberos encryption keys from a known plaintext password (`hash`) for use with other `/rc4`/`/aes256` switches
- Substituting an alternate service name into an existing ticket (`tgssub`) for RBCD/S4U chaining without repeating the whole abuse chain
- Spawning a sacrificial `runas /netonly`-style process (`createnetonly`) to avoid stomping the operator's own logon session TGT
- A chained BloodHound-identified attack path → Rubeus `s4u`/`kerberoast` → lateral movement workflow

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are released — every deployment is a custom Visual Studio (.NET 3.5 default, 4.x/4.5 supported by changing the target framework) build, run as a standalone EXE, loaded as a library/DLL, or reflectively loaded (Cobalt Strike `execute-assembly`, Covenant, PowerShell `[System.Reflection.Assembly]::Load`) |
| Network reachability | UDP/TCP 88 to a domain controller (or an MS-KKDCP HTTPS proxy) for any command that builds live Kerberos traffic; TCP 464 for `changepw`; LDAP/LDAPS (389/636) and SMB (445) for `golden`/`silver /ldap` and `kerberoast`/`asreproast` target discovery |
| Credential material | Varies per command — a password, NTLM hash, or AES key for `asktgt`/`brute`/`diamond`; a PFX certificate for PKINIT; a `krbtgt` (or service account) key for `golden`/`silver`; an existing TGT/service ticket `.kirbi` for `asktgs`/`s4u`/`ptt`/`renew`/`describe`/`tgssub` |
| Elevation | **Not required** for requesting/forging/applying tickets to the *current* logon session, or for non-elevated `triage`/`klist`/`dump`/`tgtdeleg`. **Required** for `/luid:0xA..` (any other session), `/createnetonly`, and all-users `triage`/`klist`/`dump`/`monitor`/`harvest`/`purge` |
| Domain-side condition, per use case | S4U abuse requires a compromised account with `TrustedToAuthForDelegation` + `msDS-AllowedToDelegateTo` set; `monitor`/`harvest` are only useful run on a host with unconstrained delegation enabled; Kerberoasting/AS-REP roasting require SPN-bearing/pre-auth-disabled accounts to exist, discoverable via any authenticated domain read (see `Impacket/GetUserSPNs (Kerberoasting)/` and `LOLBins/setspn/`) |
