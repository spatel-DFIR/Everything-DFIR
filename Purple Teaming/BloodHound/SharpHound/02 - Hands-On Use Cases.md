# BloodHound — SharpHound — Hands-On Use Cases

All commands below invoke the compiled ingestor directly (`SharpHound.exe -c ...` from a `cmd.exe`/PowerShell prompt on a Windows collecting host) unless a use case specifically demonstrates the reflective PowerShell wrapper. Flag names are case-insensitive; this file uses the PascalCase form for readability, matching `01 - Overview.md`.

## Contents
- [Baseline Default Collection](#baseline-default-collection)
- [Full "All" Collection Sweep](#full-all-collection-sweep)
- [DC-Only Collection — Zero Per-Host Touch](#dc-only-collection--zero-per-host-touch)
- [Stealth Collection](#stealth-collection)
- [Throttle and Jitter — Pacing an Enumeration](#throttle-and-jitter--pacing-an-enumeration)
- [Targeted OU / LDAP-Filtered Collection](#targeted-ou--ldap-filtered-collection)
- [Computer-File Targeted Sweep](#computer-file-targeted-sweep)
- [Session-Loop Monitoring](#session-loop-monitoring)
- [Alternate LDAP Credentials](#alternate-ldap-credentials)
- [Local-Admin-Credential Session Enumeration](#local-admin-credential-session-enumeration)
- [Alternate Domain Controller and LDAPS](#alternate-domain-controller-and-ldaps)
- [Output Handling — Encrypted, Randomized, Unzipped](#output-handling--encrypted-randomized-unzipped)
- [Deep Property Collection](#deep-property-collection)
- [Forest-Wide and Trust-Recursive Sweep](#forest-wide-and-trust-recursive-sweep)
- [Fileless Collection via Invoke-BloodHound](#fileless-collection-via-invoke-bloodhound)
- [Chained Workflow: Collection → Analysis → Pivot](#chained-workflow-collection--analysis--pivot)
- [AzureHound as a Hybrid-Identity Companion Run](#azurehound-as-a-hybrid-identity-companion-run)

---

## Baseline Default Collection

**MITRE ATT&CK:** [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account), [T1069.002](https://attack.mitre.org/techniques/T1069/002/) (Permission Groups Discovery: Domain Groups), [T1482](https://attack.mitre.org/techniques/T1482/) (Domain Trust Discovery), [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery)

```powershell
SharpHound.exe -c Default -d corp.local
```
The everyday "map this environment" run — `Group + Session + Trusts + ACL + ObjectProps + LocalGroups + SPNTargets + Container + CertServices + LdapServices + SmbInfo + WebClientService` (see `01`'s Command-Line Switches table for the exact expansion). Produces a `<timestamp>_BloodHound.zip` in the current directory, ready to upload directly into BloodHound CE's ingest UI.

## Full "All" Collection Sweep

**MITRE ATT&CK:** T1087.002, T1069.002, T1482, T1018, [T1615](https://attack.mitre.org/techniques/T1615/) (Group Policy Discovery)

```powershell
SharpHound.exe -c All -d corp.local
```
Adds `LoggedOn + GPOLocalGroup + UserRights + CARegistry + DCRegistry + NTLMRegistry` on top of `Default` — the exhaustive, loudest option, and the only single run that also captures `UserRights`/`LoggedOn` (both privileged, admin-gated legs). Reserved for engagements where completeness matters more than footprint, or a short assessment window where a second pass isn't realistic.

## DC-Only Collection — Zero Per-Host Touch

**MITRE ATT&CK:** T1087.002, T1069.002, T1482, T1615

```powershell
SharpHound.exe -c DCOnly -d corp.local
```
`ACL + Container + Group + ObjectProps + Trusts + GPOLocalGroup + CertServices` — every one of these is a pure LDAP query against the DC. **No SAMR, SRVSVC, LSARPC, or WMI/registry call ever touches a member computer.** This is the quietest way to get the full domain-wide attack-path graph (ACLs, group memberships, trusts, GPO-derived local-admin data via `GPOLocalGroup`) — the only real gap versus `Default` is *actual* (not GPO-inferred) local-admin membership and live session data, which only a per-host touch can reveal. The official docs' own guidance, echoed in the source's `--Stealth` help text ("Prefer DCOnly whenever possible!"), makes this the recommended default for footprint-conscious engagements.

## Stealth Collection

**MITRE ATT&CK:** T1087.002, T1069.002, T1482

```powershell
SharpHound.exe -c Default --Stealth -d corp.local
```
Automatically strips `LoggedOn`, `RDP`, `DCOM`, `PSRemote`, `LocalAdmin`, `CARegistry`, `DCRegistry`, and `NTLMRegistry` from whatever collection-method set was requested, and substitutes `GPOLocalGroup` if any local-group method was removed — the exact swap logic lives in `Options.cs`'s `ResolveCollectionMethods` (verified directly against source). Unlike `DCOnly`, `--Stealth` can still be combined with `Session` for live logon data — it's a footprint dial, not a strict LDAP-only mode. `--Stealth` combined with `-c DCOnly` is a no-op for the removal logic (DCOnly never included those methods to begin with) but is still valid syntax.

## Throttle and Jitter — Pacing an Enumeration

**MITRE ATT&CK:** T1087.002, T1069.002, T1018

```powershell
SharpHound.exe -c Session,LocalAdmin -d corp.local --Throttle 2000 --Jitter 30
```
Adds a 2-second pause after each per-computer request, randomized ±30% (source: `--Jitter` is a percentage variance applied on top of `--Throttle`, not an independent delay) — deliberately slows Phase 2's per-host fan-out so requests don't arrive as an obvious, tightly-clustered burst against every live host. Has **zero effect on Phase 1** (the LDAP sweep runs at full speed regardless) — pair this with a narrowed `-c` scope (as above) if the LDAP volume itself, not just the per-host rate, needs to stay low.

## Targeted OU / LDAP-Filtered Collection

**MITRE ATT&CK:** T1087.002, T1069.002

```powershell
# Scope to a single OU
SharpHound.exe -c Default --DistinguishedName "OU=Finance,DC=corp,DC=local" -d corp.local

# Scope to accounts matching an additional LDAP filter (appended to SharpHound's own filter)
SharpHound.exe -c Default --LDAPFilter "(adminCount=1)" -d corp.local
```
`--DistinguishedName` moves the LDAP search base itself, so both Phase 1 objects **and** anything Phase 2 would have touched are limited to that subtree. `--LDAPFilter` narrows which objects match within whatever base is in effect, without moving the base — here, only privileged (`adminCount=1`) accounts. Useful when a prior engagement phase (a target list, a specific business unit) has already scoped the assessment and a whole-domain pull would be unnecessarily broad.

## Computer-File Targeted Sweep

**MITRE ATT&CK:** T1018, T1069.002

```powershell
SharpHound.exe -c LocalAdmin,Session -d corp.local --ComputerFile hosts.txt
```
Restricts Phase 2 to exactly the hosts listed (one per line) in `hosts.txt`, regardless of what Phase 1's LDAP sweep would otherwise have returned — useful for a defined server tier, a specific subnet from a prior Nmap/Masscan sweep (see `Nmap/`/`Masscan/` in this repo), or re-running just the per-host legs against a known-live subset after an earlier `DCOnly` pass already established the domain-wide graph.

## Session-Loop Monitoring

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033/) (System Owner/User Discovery), T1018

```powershell
SharpHound.exe -c Session --Loop --LoopDuration 08:00:00 --LoopInterval 00:15:00 -d corp.local
```
Repeats `Session`-only collection every 15 minutes for 8 hours (source defaults: `--LoopDuration` 2 hours if unset, `--LoopInterval` has no default and must be supplied for `--Loop` to be meaningful). Session data is inherently a point-in-time snapshot — a single pass only shows who's logged on *right now*. Looping builds a **logon-pattern picture over a shift or a full business day**, which is what actually reveals a high-value account's habitual logon targets (a Domain Admin who RDPs into three specific jump boxes every morning is a session-loop finding, not a single-pass one).

## Alternate LDAP Credentials

**MITRE ATT&CK:** T1087.002, T1069.002

```powershell
SharpHound.exe -c Default -d corp.local --LdapUsername svc-recon --LdapPassword 'P@ssw0rd!'
```
Authenticates the LDAP legs as `svc-recon` rather than the current interactive/service logon session — relevant when SharpHound is launched from a context (a scheduled task, a different user's RunAs session) that shouldn't be the identity actually querying AD, or when operating from a non-domain-joined Windows host against a domain the operator has separate credentials for.

## Local-Admin-Credential Session Enumeration

**MITRE ATT&CK:** T1069.002, T1018

```powershell
SharpHound.exe -c Session -d corp.local --DoLocalAdminSessionEnum --LocalAdminUsername Administrator --LocalAdminPassword 'LocalAdm1n!'
```
Uses a **separate**, explicitly-supplied local-administrator credential pair just for the session-enumeration leg, independent of whatever identity is driving the LDAP queries — relevant in environments where a shared/LAPS-unmanaged local admin password is known and usable across a target set, but the operator's domain credentials are intentionally being kept out of that specific SMB/RPC traffic.

## Alternate Domain Controller and LDAPS

**MITRE ATT&CK:** T1087.002, T1069.002

```powershell
SharpHound.exe -c DCOnly -d corp.local --DomainController dc02.corp.local --SecureLDAP
```
Pins LDAP traffic to a specific DC (`dc02`) rather than letting DC-locator pick one, and forces LDAPS (TCP 636) rather than plaintext LDAP with in-band signing. Useful when a specific DC is known to have weaker logging/monitoring, or when operating in an environment where cleartext LDAP is actively being inspected and LDAPS blends in better with legitimate encrypted-LDAP traffic. Source's own help text flags `--DomainController` as a "can result in data loss" option if the pinned DC doesn't hold every object the query needs (e.g. a partial/RODC replica) — worth validating against a full DC first if completeness matters.

## Output Handling — Encrypted, Randomized, Unzipped

**MITRE ATT&CK:** [T1560](https://attack.mitre.org/techniques/T1560/) (Archive Collected Data)

```powershell
SharpHound.exe -c Default -d corp.local --OutputPrefix engagement01 --RandomFileNames --ZipPassword 'Loot#2026' --OutputDirectory C:\Windows\Temp
```
Password-protects the output zip (`--ZipPassword`), replaces the predictable `<timestamp>_<type>.json`/`<timestamp>_BloodHound.zip` naming with randomized filenames (`--RandomFileNames`), and stages everything under a directory more likely to blend in on a shared/jump-box host. **`--NoZip`** is the inverse choice — leave the per-type JSON files unzipped, relevant only if a downstream automation pipeline expects raw JSON rather than an archive. None of this changes what's collected, only how the loot is packaged and named on disk — see `03 - Source Evidence.md` for why filename randomization specifically matters for hunting.

## Deep Property Collection

**MITRE ATT&CK:** T1087.002, T1069.002

```powershell
SharpHound.exe -c Default --CollectAllProperties -d corp.local
```
Pulls every string-valued LDAP attribute per object instead of just the curated property set BloodHound's schema visualizes — meaningfully larger output and LDAP query cost, but useful when the operator plans custom post-processing of the raw JSON outside BloodHound itself (e.g. hunting for a specific attribute value across every user object).

## Forest-Wide and Trust-Recursive Sweep

**MITRE ATT&CK:** T1482, T1087.002, T1069.002

```powershell
SharpHound.exe -c Default --SearchForest --RecurseDomains -d corp.local
```
`--SearchForest` extends collection to every domain in the current forest; `--RecurseDomains` goes further, following trust relationships **outward** across forest boundaries. Produces a single combined output covering a multi-domain or multi-forest environment in one pass — the natural next step after `Trusts` collection in a smaller initial run reveals trust relationships worth mapping fully.

## Fileless Collection via Invoke-BloodHound

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell), [T1106](https://attack.mitre.org/techniques/T1106/) (Native API), T1087.002

```powershell
. .\Invoke-BloodHound.ps1
Invoke-BloodHound -CollectionMethods Default -Domain corp.local
```
`Template.ps1` (still shipped in current `SpecterOps/SharpHound` source under `src/PowerShell/`) embeds the compiled SharpHound assembly base64-encoded inside the script and reflectively loads it via `Assembly.Load` at runtime — the same collection logic as `SharpHound.exe`, but **`SharpHound.exe` itself is never written to disk** on the collecting host. Same underlying `CollectionMethod` bitmask and output format; only the loader mechanism and on-disk footprint differ. See `03 - Source Evidence.md`'s memory-forensics section for what this specifically changes about where evidence lives.

## Chained Workflow: Collection → Analysis → Pivot

**MITRE ATT&CK:** T1087.002, T1069.002, T1482, T1018 (collection); downstream techniques vary by discovered path

```powershell
SharpHound.exe -c All -d corp.local
```
This is where SharpHound's output actually pays off: import the resulting zip into BloodHound CE, run a **Shortest Path to Domain Admins** (or a custom Cypher query) from the compromised account's node, and let the graph name the next move. Depending on what the path reveals:

- **A Kerberoastable service account or a `GenericAll`/`WriteDacl` edge onto an AD CS template** → pivot into `Mimikatz/kerberos (Golden-Silver Ticket)/` or `Impacket/GetUserSPNs (Kerberoasting)/` and `Impacket/ticketer/`
- **DCSync rights (`DS-Replication-Get-Changes-All`) surfaced on the ACL edge from a discovered node** → pivot into `Mimikatz/lsadump (DCSync)/` or `Impacket/secretsdump/` (`-just-dc`)
- **A `CanRDP`/local-admin edge onto a specific host holding cached credentials or an active session for a higher-privileged account** → pivot into `Mimikatz/sekurlsa (Credential Dumping)/` after landing on that host via `Impacket/wmiexec/`, `Impacket/smbexec/`, or `Impacket/psexec/`
- **An NTLM-relay-relevant edge** (`WebClientService`/`NTLMRegistry`/`LdapServices` data showing unsigned LDAP or an active WebClient service) → pivot into `Impacket/ntlmrelayx/`

BloodHound's graph is the map; it does not itself execute any of these next steps — SharpHound's job ends the moment the zip is produced.

## AzureHound as a Hybrid-Identity Companion Run

**MITRE ATT&CK:** T1087.002 (Entra ID equivalent), T1069.002

```powershell
# Separate Go binary, separate auth model — not a SharpHound flag or mode
azurehound.exe list -u user@corp.onmicrosoft.com -p 'P@ssw0rd!' -t <tenant-id> -o azure_output.json
```
Run alongside (not instead of) SharpHound when the environment has Entra ID/hybrid-identity exposure — AzureHound enumerates Entra ID objects and role assignments via Microsoft Graph and Azure Resource Manager resources via the ARM REST API, and its output ingests into the **same** BloodHound CE graph. The payoff is specifically **cross-boundary edges**: an on-prem account discovered as a local admin via SharpHound that's *also* an Entra ID Global Administrator or Hybrid Identity Administrator only becomes visible as an attack path once both collectors' output sits in the same graph. Full command/flag coverage for AzureHound is out of scope for this SharpHound-focused note — see the official [AzureHound documentation](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound) if this becomes a recurring engagement need.
