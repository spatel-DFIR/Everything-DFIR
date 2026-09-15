# BloodHound — SharpHound — Overview

> 🔴 **Red Flag Principle:** SharpHound doesn't attack anything — it **asks questions Active Directory is designed to answer**. Its AD-wide phase is a burst of **signed LDAP queries against a Domain Controller** requesting the `nTSecurityDescriptor` attribute with a **non-default `SDFlags` control value of `0x5`** (owner + DACL, not just DACL) — a search-control combination essentially no legitimate admin tool sets, and the single highest-signal artifact this tool produces (Domain Controller **Event ID 1644**, if expensive/inefficient LDAP-query logging is enabled). Its per-host phase is a burst of **SAMR local-group queries and `NetSessionEnum`/`NetWkstaUserEnum` calls against every live computer in the domain in a short window** — individually indistinguishable from routine admin tooling, but volumetrically obvious: no legitimate process enumerates local Administrators membership and active sessions on *every* domain-joined computer, from one source, back to back.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

BloodHound was first released at DEF CON 24 (2016) by **Andy Robbins (`@_wald0`)**, **Rohan Vazarkar (`@CptJesus`)**, and **Will Schroeder (`@harmj0y`)**, then members of Veris Group's Adaptive Threat Division. The original ingestor was a pure PowerShell script (`Invoke-BloodHound`) that leaned on the high-level `System.DirectoryServices` / `DirectorySearcher` .NET classes to pull AD data. In **October 2017**, Rohan Vazarkar published the "SharpHound: Technical Details" post ([specterops.io](https://specterops.io/blog/2017/10/23/sharphound-technical-details-2/)) introducing **SharpHound** proper — a compiled C# ingestor rewritten against the lower-level `System.DirectoryServices.Protocols` namespace, which was faster, more reliable, and could still be reflectively loaded and run entirely from a PowerShell one-liner (`Invoke-BloodHound`) without touching disk.

The BloodHound/SharpHound project lived under the **`BloodHoundAD`** GitHub org through the "Legacy" era (BloodHound 1.x-4.x: a Neo4j-desktop-backed Electron GUI, ingested from a **single combined JSON export**). In 2022-2023 the creators — by then operating as the company **SpecterOps** — rewrote the entire stack as **BloodHound Community Edition (CE)**: a containerized, API-driven web application (Postgres + Neo4j backend, Docker Compose deployment) with a matching ingestor rewrite. Both projects now live under the **[`SpecterOps`](https://github.com/SpecterOps) GitHub org**: the collector itself at **[`SpecterOps/SharpHound`](https://github.com/SpecterOps/SharpHound)**, with shared collection primitives factored out into **[`SpecterOps/SharpHoundCommon`](https://github.com/SpecterOps/SharpHoundCommon)** (the library both SharpHound and SpecterOps' internal Enterprise collector build on).

**This note documents current SharpHound (Community Edition), verified directly against the live `SpecterOps/SharpHound` source** — its own startup banner states *"This version of SharpHound is compatible with the 5.0.0 Release of BloodHound"*, confirming CE and this ingestor version are a matched pair. **Version-dependency flag:** Legacy BloodHound's ingestor (`BloodHoundAD/SharpHound3`, versions 1.x-3.x, paired with `Invoke-BloodHound.ps1`) used a materially different **single-JSON-per-run output format** and a smaller collection-method set than what's documented below — do not assume flag names or output structure transfer between the two. Where the difference matters for evidence interpretation, it's called out explicitly (see **How It Works** and `04 - Target Evidence.md`).

The companion collector for cloud identity, **AzureHound**, is developed and released alongside SharpHound in the same [`SpecterOps`](https://github.com/SpecterOps/AzureHound) org — a separate Go binary, not a SharpHound mode — see the note on it at the end of **How It Works**.

## How It Works

SharpHound is a **read-only data collector**, not an exploitation tool: every technique below is an operation Active Directory and Windows expose to any authenticated domain user by design. Its value to an attacker (and to BloodHound as the downstream graph-analysis engine) comes from **doing this exhaustively and mechanically**, at a scale and speed no human operator would replicate by hand, then handing the result to BloodHound's graph queries to find the shortest privilege-escalation path.

Collection happens in two structurally distinct phases, and most collection methods belong to only one of them:

```
Phase 1 — Directory-Wide Enumeration (LDAP, against a Domain Controller)
──────────────────────────────────────────────────────────────────────
SharpHound.exe ──(TCP 389/636, signed/sealed LDAP bind)──▶ Domain Controller
   │
   ├─ paged LDAP search: objectClass=user/computer/group/organizationalUnit/
   │    groupPolicyContainer/domain/trustedDomain/pKICertificateTemplate/...
   │    across the domain's default naming context (or -DistinguishedName/
   │    -LDAPFilter-scoped subset)
   │
   ├─ requests nTSecurityDescriptor with SDFlags=0x5 (OWNER_SECURITY_INFORMATION
   │    | DACL_SECURITY_INFORMATION) on every returned object ─▶ ACL collection
   │    (CollectionMethod.ACL) — this specific control-value combination is the
   │    single most distinctive artifact this tool leaves, see the Red Flag above
   │
   └─ walks CN=Configuration and CN=Sites for AD CS (pKIEnrollmentService,
        certificationAuthority, pKICertificateTemplate) and forest-trust objects

   Result: users.json, computers.json, groups.json, domains.json, gpos.json,
   ous.json, containers.json, rootcas.json, aiacas.json, ntauthstores.json,
   enterprisecas.json, certtemplates.json, issuancepolicies.json — one JSON
   file per object type (13 total types in current CE schema, see Output
   Options below), each independent of live host reachability.

Phase 2 — Per-Computer Local Enumeration (SMB/RPC, against every live host)
──────────────────────────────────────────────────────────────────────
For each computer object pulled in Phase 1 (or from -ComputerFile), in
parallel across -Threads worker threads:

  1. TCP 445 port-check (skippable: -SkipPortCheck) — dead hosts are
     never touched further, this is the "is this box even alive" gate

  2. SAMR bind (\PIPE\samr) ──▶ NetLocalGroupGetMembers-equivalent query
       against Administrators, Remote Desktop Users, Distributed COM
       Users, Remote Management Users (CollectionMethod.LocalAdmin/RDP/
       DCOM/PSRemote, collectively "LocalGroups") — requires local admin
       by default on Windows 10 1607+/Server 2016+ (SAMR hardening)

  3. SRVSVC bind (\PIPE\srvsvc) ──▶ NetSessionEnum ─────▶ active/logged-on
       sessions (CollectionMethod.Session) — non-privileged by default;
       LoggedOn is a separate, privileged variant using registry-based
       HKU enumeration (remote registry, or WMI as of current source) for
       genuinely logged-on (not just "has an open session") accounts

  4. LSARPC bind ──▶ LsaOpenPolicy + LsaEnumerateAccountsWithUserRight ──▶
       User Rights Assignment (CollectionMethod.UserRights) — requires
       local Administrators, no delegation path exists (LsaOpenPolicy is
       admin-gated at the API level, not an ACL SharpHound can be granted)

  5. WMI (primary) / remote registry (failover) ──▶ specific Lsa/
       LanmanServer registry values used to build NTLM-relay edges
       (CollectionMethod.NTLMRegistry), and on CA/DC hosts specifically,
       ADCS-relevant registry values (CARegistry/DCRegistry)

  Each leg is independently toggleable via its own CollectionMethod flag —
  a DC-only or ACL-only run touches ZERO of these per-computer legs.
```

Object identity resolution (SID↔name, well-known-principal handling, domain-SID caching) is backed by a **local cache file** — `<Base64(MachineGuid)>.bin` by default (see `03 - Source Evidence.md`) — so repeat runs on the same collecting host don't re-resolve the same objects from scratch.

**`--Stealth`** doesn't add a new technique — it **subtracts** the noisiest per-computer legs (see the exact removal list in **Command-Line Switches** below) and substitutes `GPOLocalGroup` (deriving local-admin membership from Group Policy `Restricted Groups`/`Group Policy Preferences` XML, read purely over LDAP/SYSVOL, no per-host SMB touch) wherever local-group data was requested — trading completeness (GPO-derived membership misses any manually-added local admin) for near-total avoidance of Phase 2's SMB/RPC fan-out.

**AzureHound**, in one sentence: a separate Go binary (also SpecterOps-maintained) that performs the same graph-collection *mission* against **Entra ID (via Microsoft Graph API)** and **Azure Resource Manager (via the ARM REST API)** instead of on-prem AD/LDAP — different protocols, different auth model (OAuth/JWT/service-principal rather than Kerberos/NTLM), but its output lands in the **same BloodHound CE ingest pipeline** as SharpHound's, which is precisely how BloodHound visualizes hybrid on-prem-to-cloud attack paths (e.g., an on-prem account that's a Hybrid Identity Administrator, discovered via SharpHound, pivoting into Entra Global Admin, discovered via AzureHound). It is not a SharpHound collection method or flag — a separate tool, separate binary, separate invocation.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Directory query (Phase 1) | LDAP / LDAPS (TCP 389/636) against a Domain Controller — signed and sealed by default unless `-DisableSigning`; paged search with `SDFlags=0x5` control for ACL collection |
| Local group enumeration | SAMR (Security Account Manager Remote Protocol) over `\PIPE\samr` — `LocalAdmin`/`RDP`/`DCOM`/`PSRemote` collection methods |
| Session enumeration | SRVSVC — `NetSessionEnum` (`\PIPE\srvsvc`) for `Session`; privileged registry/WMI-based `NetWkstaUserEnum`-equivalent for `LoggedOn` |
| Rights enumeration | LSARPC — `LsaOpenPolicy`/`LsaEnumerateAccountsWithUserRight` for `UserRights` |
| Registry-derived data | WMI (primary) with Remote Registry (`\PIPE\winreg`) as failover — `NTLMRegistry`, `CARegistry`, `DCRegistry` |
| Certificate Services (AD CS) | LDAP against `CN=Configuration` (`CertServices`) plus registry (`CARegistry`) for ADCS misconfiguration data feeding BloodHound's ADCS attack-path edges |
| Transport/RPC plumbing | RPC endpoint mapper (TCP 135) → dynamic high port for SAMR/SRVSVC/LSARPC binds; TCP 445 (SMB) named-pipe transport |
| Authentication | Current logon session's Kerberos ticket (typical) or explicit NTLM/Kerberos creds via `-LDAPUsername`/`-LDAPPassword` |
| Output packaging | Per-object-type JSON files (13 types), zipped (DEFLATE level 9) via SharpZipLib — see **Command-Line Switches → Output Options** |
| Companion (cloud) | AzureHound — Microsoft Graph API + Azure Resource Manager REST API, OAuth-based, entirely separate binary/protocol stack, output feeds the same ingest pipeline |

## Command-Line Switches — Quick Reference

Verified directly against `src/Options.cs` in [`SpecterOps/SharpHound`](https://github.com/SpecterOps/SharpHound) (current CE source) — every flag below is a real, current option. Parsing is **case-insensitive** (`CaseSensitive = false` in the source's parser config), so `-c`, `-C`, `--collectionmethods`, and `--CollectionMethods` are all equivalent; this note uses the PascalCase form the official docs site uses for readability.

**Collection Scope**

| Switch | Plain-English meaning |
|---|---|
| `-c`, `--CollectionMethods` | Which collection method(s) to run, comma-separated. **Default: `Default`**. See the dedicated table below for every named method |
| `-d`, `--Domain` | Target a specific AD domain rather than the collecting host's current domain |
| `-s`, `--SearchForest` | Also enumerate every domain in the current forest, not just the target/current one |
| `--RecurseDomains` | Follow domain trusts outward and enumerate trusted domains too (broader than `-SearchForest`'s forest-only scope) |
| `--Stealth` | Swap the collection-method set for a quieter one — see **How It Works** for exactly what's removed/substituted |
| `-f`, `--LDAPFilter` | Append an additional raw LDAP filter to SharpHound's built-in query, narrowing which objects are pulled |
| `--DistinguishedName` | Start the LDAP search at a specific base DN (e.g. one OU) instead of the domain root |
| `--ComputerFile` | Path to a line-separated text file of computer names/IPs — restricts Phase 2 (per-host) collection to exactly this list instead of every computer object found in Phase 1 |

**Output**

| Switch | Plain-English meaning |
|---|---|
| `--OutputDirectory` | Where to write JSON/zip output. **Default: current directory** |
| `--OutputPrefix` | String prepended to every output filename |
| `--ZipFileName` | Custom name for the output zip. **Default: `BloodHound`** (→ `<timestamp>_BloodHound.zip`) |
| `--NoZip` | Leave the per-type JSON files unzipped on disk |
| `--ZipPassword` | Password-protect the output zip |
| `--RandomFileNames` | Replace the predictable `<timestamp>_<type>.json`/`<timestamp>_BloodHound.zip` naming with random filenames — an evasion-relevant flag, see `05 - Detection and Hunting.md` |
| `--PrettyPrint` | Indent the JSON output for human readability (larger files, no functional difference to BloodHound's ingest) |
| `--TrackComputerCalls` | Write a CSV logging the outcome of every per-computer connection attempt (useful for troubleshooting a run, also a durable local artifact — see `03`) |

**Connection / Authentication**

| Switch | Plain-English meaning |
|---|---|
| `--DomainController` | Force a specific DC (by IP or name) for LDAP rather than auto-locating one — source's own help text warns this "can result in data loss" if the forced DC doesn't hold all requested data |
| `--LdapPort` / `--LdapSSLPort` | Override the default LDAP (389) / LDAPS (636) port |
| `--SecureLDAP`, i.e. `--ForceSecureLDAP` | Require LDAPS only, no fallback to plaintext LDAP |
| `--DisableCertVerification` | Skip TLS certificate validation on an LDAPS connection |
| `--DisableSigning` | Turn off LDAP signing/sealing — **reduces integrity/confidentiality of the LDAP traffic itself**, not a stealth feature |
| `--LdapUsername` / `--LdapPassword` | Authenticate LDAP queries with different credentials than the current logon session |
| `--DoLocalAdminSessionEnum` | Use a **separate** local-administrator credential pair (below) specifically for session enumeration, instead of the primary/current credentials |
| `--LocalAdminUsername` / `--LocalAdminPassword` | The alternate local-admin credential pair used only when `--DoLocalAdminSessionEnum` is set |
| `--OverrideUserName` | Override which username SharpHound filters for when parsing `NetSessionEnum` results (advanced/edge-case use — mismatched proxy/relay auth scenarios) |
| `--RealDNSName` | Manually supply a DNS suffix when AD's DNS zone and the environment's real DNS don't match |

**Performance / Footprint**

| Switch | Plain-English meaning |
|---|---|
| `-t`, `--Threads` | Number of parallel worker threads for Phase 2 host enumeration. **Default: 50** |
| `--Throttle` | Milliseconds to pause after each per-computer request. **Default: 0 (no delay)** |
| `--Jitter` | Percentage of randomized variance applied on top of `--Throttle`, so delays aren't a perfectly uniform interval. **Default: 0** |
| `--SkipPortCheck` | Skip the TCP 445 reachability pre-check and attempt full enumeration against every host regardless |
| `--PortCheckTimeout` | Milliseconds to wait on the port-445 check before giving up on a host. **Default: 10000** |
| `--SkipPasswordCheck` | Skip filtering out computer accounts whose `pwdLastSet` suggests a stale/decommissioned machine |
| `--SkipRegistryLoggedOn` | Skip the registry-based leg of `LoggedOn` session detection |
| `--ExcludeDCs` | Exclude Domain Controllers from Phase 2 (per-host) session/local-group enumeration — source comment notes this is aimed at reducing noise picked up by legacy ATA/Defender for Identity sensors |
| `--CollectAllProperties` | Pull **every** string-valued LDAP attribute per object, not just the curated set BloodHound's schema uses — substantially larger output, useful for custom post-processing |
| `--PartitionLdapQueries` | Break the main LDAP query into smaller chunks, trading query count for reduced per-query load on the DC |

**Cache**

| Switch | Plain-English meaning |
|---|---|
| `--CacheName` | Filename for the local object-resolution cache. **Default: `<Base64(MachineGuid)>.bin`** — see `03 - Source Evidence.md` |
| `--MemCache` | Keep the cache in memory only, never write it to disk |
| `--RebuildCache` | Discard the existing cache file's contents and rebuild from scratch |

**Looping**

| Switch | Plain-English meaning |
|---|---|
| `-l`, `--Loop` | Repeat Phase 2 (computer-based) collection methods on an interval instead of running once |
| `--LoopDuration` | Total time to keep looping, `HH:MM:SS` format. **Default: 2 hours** |
| `--LoopInterval` | Pause between loop iterations, `HH:MM:SS` format |

**Misc**

| Switch | Plain-English meaning |
|---|---|
| `-v`, `--Verbosity` | Console log verbosity level |
| `--StatusInterval` | Milliseconds between status-line updates during a run. **Default: 30000** |
| `--Metrics` | Emit additional internal performance metrics |

**Collection Methods (`-c` values)** — verified against `CollectionMethod.cs`'s `[Flags]` enum in [`SpecterOps/SharpHoundCommon`](https://github.com/SpecterOps/SharpHoundCommon):

| Method | What it collects |
|---|---|
| `Default` | The everyday baseline: `Group + Session + Trusts + ACL + ObjectProps + LocalGroups(LocalAdmin+RDP+DCOM+PSRemote) + SPNTargets + Container + CertServices + LdapServices + SmbInfo + WebClientService` |
| `All` | Everything `Default` collects, **plus** `LoggedOn + GPOLocalGroup + UserRights + CARegistry + DCRegistry + NTLMRegistry` — the exhaustive, loudest run |
| `DCOnly` | LDAP-only, zero per-computer SMB/RPC touch: `ACL + Container + Group + ObjectProps + Trusts + GPOLocalGroup + CertServices` |
| `ComputerOnly` | The inverse of `DCOnly` — every per-host leg and nothing from the domain-wide LDAP sweep: `LocalGroups + Session + UserRights + CARegistry + DCRegistry + WebClientService + SmbInfo + NTLMRegistry` |
| `Group` | Domain group membership (LDAP) |
| `LocalAdmin` | Local Administrators group membership per computer (SAMR) |
| `RDP` | Remote Desktop Users group membership per computer (SAMR) |
| `DCOM` | Distributed COM Users group membership per computer (SAMR) |
| `PSRemote` | Remote Management Users group membership per computer (SAMR) |
| `GPOLocalGroup` | Local-admin/group membership **derived from Group Policy** (`Restricted Groups`/GPP), LDAP + SYSVOL only, no per-host touch |
| `Session` | Active sessions per computer, unprivileged (`NetSessionEnum`/SRVSVC) |
| `LoggedOn` | Genuinely logged-on users per computer, **privileged** (registry/WMI-based) |
| `Trusts` | Domain/forest trust relationships (LDAP) |
| `ACL` | Security descriptors (owner + DACL, `SDFlags=0x5`) on AD objects — feeds most of BloodHound's abusable-permission edges |
| `Container` | GPO links, OU structure, container hierarchy (LDAP) |
| `ObjectProps` | Standard object properties for users/computers/groups (LDAP) |
| `SPNTargets` | Service Principal Name targets — currently MSSQL SPNs, for BloodHound's `SQLAdmin` edge |
| `UserRights` | User Rights Assignment per computer, **privileged** (`LsaOpenPolicy`) |
| `CARegistry` | ADCS-relevant registry values from Certificate Authority hosts |
| `DCRegistry` | Registry values from Domain Controllers (cert-binding enforcement, Netlogon allowlists, etc.) |
| `CertServices` | AD CS objects — templates, Enterprise/Root CAs, NTAuth store (LDAP against `CN=Configuration`) |
| `WebClientService` | Whether the WebClient (WebDAV) service is running on a host — feeds NTLM-coercion-relevant edges |
| `LdapServices` | Tests whether LDAP signing/channel binding is enforced on ports 389/636 — feeds relay-relevant edges |
| `SmbInfo` | SMB signing configuration per host |
| `NTLMRegistry` | NTLM-relay-relevant `Lsa`/`LanmanServer` registry values (WMI primary, registry failover) |

## Quick Use-Case List

- Baseline `Default` collection against the current domain — the everyday "map this environment" run
- Full `All` sweep — every collection method, maximum data, maximum noise
- `DCOnly` collection — LDAP-only, zero per-host SMB/RPC touch, the quietest full-domain-graph option
- `--Stealth` collection — trims the loudest per-host legs automatically rather than hand-picking methods
- `--Throttle`/`--Jitter` tuning — deliberate pacing to blend into normal traffic volume over a longer window
- `--DistinguishedName`/`-LDAPFilter`-scoped collection — one OU or a filtered object subset instead of the whole domain
- `--ComputerFile`-scoped collection — a defined list of hosts (e.g. a specific subnet or server tier) instead of every computer AD knows about
- `--Loop` session collection — repeated `Session`-only passes over time to build a logon-pattern picture (who logs on where, and when)
- Alternate-credential collection (`-LdapUsername`/`-LdapPassword`) — running as a different account than the current logon session
- `--DoLocalAdminSessionEnum` — using separately-supplied local-admin credentials just for the session-enumeration leg
- Alternate-DC / LDAPS collection (`--DomainController`, `--SecureLDAP`) — targeting a specific DC or forcing encrypted LDAP
- Output-hardening collection — `--ZipPassword`, `--RandomFileNames`, `--NoZip`, `--OutputPrefix` combined for handling/exfil discipline
- `--CollectAllProperties` deep-property pull — every LDAP attribute, not just BloodHound's curated schema set
- Forest-wide / trust-recursive sweep (`--SearchForest`, `--RecurseDomains`) — multi-domain or multi-forest graph in one pass
- In-memory reflective execution via `Invoke-BloodHound` (the PowerShell `Template.ps1` wrapper still shipped in current source) — runs the same collector without dropping `SharpHound.exe` to disk
- Chained workflow: SharpHound collection → BloodHound graph analysis → pivot into `Rubeus`, `Mimikatz`, or `Impacket` on a discovered attack path
- AzureHound companion collection for hybrid on-prem/Entra ID attack-path visibility (separate tool, same downstream graph)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Any authenticated domain account | Phase 1 (LDAP/AD-structure collection) needs nothing more — `Authenticated Users` can read almost all of the schema SharpHound queries by default, including `nTSecurityDescriptor` for ACL collection and most Certificate Services data |
| Local Administrator on target computers | Required for `LocalAdmin`/`RDP`/`DCOM`/`PSRemote` (SAMR remote enumeration is admin-gated by default since Win10 1607/Server 2016), `LoggedOn`, and `UserRights` (`LsaOpenPolicy` is unconditionally admin-gated — no delegation path exists). Without it, these legs silently return nothing for that host rather than failing the whole run |
| Network reachability | TCP 389/636 to a DC for Phase 1; TCP 445 + RPC endpoint mapper (135) + dynamic high port to each target computer for Phase 2 — routinely blocked between untrusted segments and servers/DCs in a segmented environment, which is itself why `DCOnly` exists as a fallback |
| A Windows host to run from | Unlike the Linux-native Impacket family documented elsewhere in this repo, SharpHound is a .NET assembly — it runs from a Windows host (compromised workstation, jump box, or a domain-joined attacker-controlled VM), either as `SharpHound.exe` on disk or reflectively via the `Invoke-BloodHound` PowerShell wrapper. This materially changes where "source evidence" lives — see `03 - Source Evidence.md` |
| GPO-read access (for `GPOLocalGroup`/`Stealth`) | Reading `Restricted Groups`/Group Policy Preferences XML from SYSVOL requires the same baseline domain-user read access as the rest of Phase 1 — no elevated rights beyond authenticated-user |
