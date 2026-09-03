# BloodHound — SharpHound — Target Evidence

SharpHound's two collection phases (`01 - Overview.md`) hit **structurally different targets** — Phase 1 lands entirely on a Domain Controller as LDAP traffic, Phase 2 lands on **every live computer object in scope** as SMB/RPC traffic. This file is organized the same way; which sections apply to a given run depends entirely on the `-c`/`--CollectionMethods` value used (a `DCOnly` run generates **zero** Phase 2 evidence anywhere, by design — see `01`).

## Contents
- [Phase 1 — Domain Controller (LDAP)](#phase-1--domain-controller-ldap)
- [Phase 2 — Member Computers (SMB/RPC)](#phase-2--member-computers-smbrpc)
- [What SharpHound Does *Not* Touch](#what-sharphound-does-not-touch)
- [Legacy BloodHound Ingestor — What's Different](#legacy-bloodhound-ingestor--whats-different)
- [Building a Timeline](#building-a-timeline)

---

## Phase 1 — Domain Controller (LDAP)

### The Headline Signal: Event ID 1644 and SDFlags

> 🔴 **Not enabled by default.** Windows Server's "expensive/inefficient LDAP query" diagnostic logging that produces **Event ID 1644** (source: `Microsoft-Windows-ActiveDirectory_DomainService`, or the legacy `NTDS`/`Directory Service` log depending on OS build) is gated by the **`15 Field Engineering`** diagnostics registry value under `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics`, and further gated by a search-cost threshold (`Expensive/inefficient search threshold` under the same key path) — most environments run with this at its quiet default. **Deliberately raising Field Engineering logging (or lowering the search-cost threshold) on DCs before an assessment/hunt is itself the single highest-value proactive step for catching SharpHound's Phase 1**, and its absence in an investigation is a logging-configuration gap, not evidence the tool didn't run.

When 1644 logging **is** enabled, each captured search event records the **base DN, search filter, requested attributes, and any extended controls** attached to the query. The one control value essentially unique to SharpHound-style tooling: an **`SDFlags` LDAP control (OID `1.2.840.113556.1.4.801`) with a value of `0x5`** (`OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION`) attached to a request for the `nTSecurityDescriptor` attribute — this is exactly what SharpHound's `ACL` collection method sets to pull owner-plus-DACL data for every object, and it is a search-control combination essentially no legitimate day-to-day admin tooling sets. A DC producing 1644 events with this control value, especially at volume (thousands of objects, one source, a short window) is as close to a smoking gun as this tool leaves anywhere.

### Volumetric Signal

Regardless of whether 1644 logging is enabled, SharpHound's Phase 1 is a **paged LDAP search across the domain's entire default naming context** (unless `--DistinguishedName`/`--LDAPFilter` narrowed it) — every user, computer, group, GPO, OU, container, and (for `CertServices`) every AD CS object, from **one authenticated principal, in a tight window**. Any AD-query-volume baseline (a DC's own LDAP interface statistics via `perfmon`'s `NTDS\LDAP Searches/sec` counter, or a SIEM correlation rule on Security 4624 Type 3 logons followed by an unusually large downstream query volume from the same account) surfaces this independent of 1644.

### Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | 4624 (Logon Type 3) | Network logon from the collecting host's account, immediately preceding the LDAP query burst |
| Directory Service / `Microsoft-Windows-ActiveDirectory_DomainService` | **1644** | Expensive/inefficient LDAP search — **not enabled by default**, see callout above. Highest-fidelity signal when present, especially with the `SDFlags=0x5` control |
| Security | 4662 (Object Access) | **Only** fires for `nTSecurityDescriptor`/other attribute reads if Directory Service Access auditing **and** a SACL on the relevant objects are both configured — uncommon by default, same rarity caveat that recurs throughout this repo's registry/LDAP-object hunts (see `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md` for the same caveat applied to DRSUAPI reads) |

### Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `ldap.log` | Search filter, base object, requested attributes, and extended controls (including `SDFlags`) for every LDAP search — visible in plaintext even without host-side logging, **unless** the query traveled over LDAPS (`--SecureLDAP`) and the sensor lacks TLS decryption |
| NetFlow / connection metadata | A sustained connection to TCP 389/636 from one source, with a search-response volume (bytes/packets) far above a typical single-object LDAP lookup |

### Endpoint/Domain-Security Product Behavior

Microsoft Defender for Identity (and legacy ATA) profile SAMR/LDAP query patterns over a learning period and then alert on high-volume, broadly-distributed reconnaissance queries under its **User and Group Membership Reconnaissance** and related reconnaissance-and-discovery alert categories — this is a **behavioral/volumetric** detection, not keyed to any single event ID, and is one of the few detections that doesn't depend on 1644 logging being enabled at all. `--ExcludeDCs` (Phase 2 only) and `--Throttle`/`--Jitter` reduce the volumetric signature this class of detection relies on; nothing about Phase 1's LDAP sweep itself can be throttled by any SharpHound flag (see `01`).

---

## Phase 2 — Member Computers (SMB/RPC)

Only generated by collection methods that actually touch member computers: `LocalAdmin`, `RDP`, `DCOM`, `PSRemote` (collectively `LocalGroups`), `Session`, `LoggedOn`, `UserRights`, `CARegistry`, `DCRegistry`, `NTLMRegistry`. A `DCOnly`/pure-`ACL`/pure-`Trusts` run leaves **none** of this.

### Windows Event Logs (per target computer)

| Log | Event ID | Signal |
|---|---|---|
| Security | 4624 (Logon Type 3) | Network logon from the collecting host's account onto each touched computer |
| Security | 4672 | Special privileges assigned at logon — expected for the **privileged** legs (`LoggedOn`, `UserRights`) since both require local-Administrator-equivalent access; **not** expected for the unprivileged `Session` leg (`NetSessionEnum`) |
| Security | 5140 / 5145 | `IPC$` share access, including the specific named-pipe connections (`\PIPE\samr`, `\PIPE\srvsvc`, `\PIPE\lsarpc`) if object-access auditing (5145) is enabled — the exact pipe name distinguishes which collection method(s) ran |
| Security | 4661 | Handle requested to a specific object — fires for SAMR-mediated local-group queries **only if a SACL is configured** on the relevant SAM object, same rarity caveat as elsewhere in this repo |
| WMI-Activity Operational | — | `Microsoft-Windows-WMI-Activity/Operational` records a `root\cimv2` connection and `StdRegProv` class method invocation for the `NTLMRegistry` leg's **primary** access path (WMI-based remote registry reads, verified against `DotNetWmiRegistryStrategy.cs` in `SpecterOps/SharpHoundCommon`) — a real signal even where no traditional Remote Registry service event exists, since this path doesn't necessarily start/stop that service the way `Impacket/secretsdump/`'s Path 1 does. **Whether SharpHound's registry-read failover path (WMI unreachable → Remote Registry) explicitly starts a stopped `RemoteRegistry` service is not confirmed against source for this build — flag rather than assert either way if that specific event is the deciding evidence in an investigation** |

### Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 3 (Network Connection) | Inbound SMB (445) from the collecting host's source, if the target's own Sysmon config logs inbound connections (uncommon default tuning, but high-value where enabled) |
| 18 (Pipe Connected) | Connections to `\PIPE\samr`, `\PIPE\srvsvc`, `\PIPE\lsarpc` — collectively the strongest **Sysmon-native** signal for Phase 2, since these named pipes have a narrower set of legitimate high-volume callers than, say, `winreg` |
| 1 (Process Create) | **Not generated by this tool's own activity** — SharpHound executes no code on target computers, only RPC/WMI queries against already-running services. A Sysmon 1 hit correlated with a SharpHound-style Phase 2 burst indicates a **different** tool/technique chained in immediately after (see the chained-workflow use case in `02`) |

### Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | Named SAMR/SRVSVC/LSARPC operations (`SamrQueryInformationAlias`, `NetrSessionEnum`, `LsaOpenPolicy`) from one source against many destinations in a short window — the DCE/RPC-layer equivalent of the volumetric argument made for Phase 1's LDAP sweep |
| NetFlow / connection metadata | A **fan-out pattern**: one source host opening TCP 445 (+135/dynamic) connections to a large fraction of the domain's live computer objects, back to back — this shape is close to unique to a domain-wide enumeration tool; almost nothing else in a normal environment connects to *every* computer object from one source in one sitting |

### Endpoint Security Product Signatures

Same behavioral-detection framing as Phase 1's Defender for Identity note — a "many hosts, many SAMR/session queries, one source, short window" pattern is a recognized reconnaissance signature across most EDR/domain-security products, independent of whether the specific binary (`SharpHound.exe`, a renamed/recompiled variant, or the fileless `Invoke-BloodHound` path) matches any static signature.

---

## What SharpHound Does *Not* Touch

Worth stating plainly rather than leaving as an assumed gap: SharpHound **never reads LSASS memory, never creates a service, never drops a payload on a target computer, and never authenticates interactively (RDP/console) anywhere**. Its entire footprint on a target computer is read-only RPC/WMI querying against services that are already running by design (SAMR, SRVSVC, LSARPC, WMI's registry provider). **No Prefetch, Amcache, or ShimCache entry is ever generated on a target computer by SharpHound's own activity**, because no new process ever executes there — this is the same evidentiary shape as `Impacket/secretsdump/`'s Path 1 (Remote Registry) leg, not the shape of `psexec.py`/`wmiexec.py`-style code execution. If a discovered attack path is subsequently *exploited* (a pivot into `Mimikatz`/`Impacket`/`Rubeus`-style tooling per `02`'s chained-workflow use case), that exploitation leaves its **own**, separately-documented evidence trail on whatever host it targets — don't conflate SharpHound's reconnaissance footprint with a later tool's exploitation footprint just because they're part of the same engagement.

## Legacy BloodHound Ingestor — What's Different

**Version-dependent, flagged explicitly per this repo's accuracy standard:** the Legacy BloodHound ingestor (`BloodHoundAD/SharpHound3`, versions 1.x-3.x, typically invoked via `Invoke-BloodHound.ps1`) used a **single combined JSON export per run** rather than CE's 13-separate-file-per-type schema, had a smaller collection-method set (no `CertServices`/`CARegistry`/`DCRegistry`/`WebClientService`/`LdapServices`/`SmbInfo`/`NTLMRegistry` — all ADCS/relay-focused methods added later), and predates the `SDFlags=0x5` ACL-collection signature in some earlier builds. **Do not assume the JSON `meta`/`data` structure, the 13-file naming convention, or the full collection-method list documented above apply to a Legacy-era collection** — if an investigation involves an older/Legacy BloodHound deployment, verify against that specific version's own source/docs rather than this note.

## Building a Timeline

- **Phase 1 (LDAP):** `[4624 Type 3 logon on the DC] → [sustained LDAP search burst, TCP 389/636] → [Event 1644 if enabled, showing SDFlags=0x5 for ACL collection] → [search completes, connection drops]` — typically minutes for a mid-size domain, longer for `--CollectAllProperties` or a large forest with `--SearchForest`.
- **Phase 2 (SMB/RPC):** `[4624 Type 3 logons fanning out across many computers, clustered in time] → [SAMR/SRVSVC/LSARPC named-pipe connections, Sysmon 18] → [per-host queries complete] → [collecting host moves to the next batch]` — the fan-out shape itself, not any single host's evidence, is the strongest indicator; correlate 4624 logons **by source account, across many destination computers, in a tight window** rather than hunting host-by-host.
- **Cross-phase correlation:** Phase 1's LDAP timestamp precedes Phase 2's fan-out in a normal run (SharpHound needs the computer-object list from LDAP before it can enumerate them) — a Phase 2 burst with **no** preceding Phase 1 LDAP activity from the same source suggests either a `--ComputerFile`-scoped run (which skips relying on Phase 1's own computer list) or a separate/different tool producing a similar-looking fan-out.
- Pair against `03 - Source Evidence.md`'s collecting-host artifacts (the Sysmon 1/4688 command line, if the `.exe` path was used) to convert "an enumeration burst happened somewhere in the domain" into a fully attributed, flag-scoped collection event.
