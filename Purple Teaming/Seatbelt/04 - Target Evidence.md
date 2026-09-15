# Seatbelt — Target Evidence

Set expectations correctly before anything else: Seatbelt is a **read-only enumeration tool**. Its checks query WMI, read the registry, check file existence/metadata, and read event logs — they don't create files, write registry values, install services, or modify anything on a system they run against (the one exception is a *standalone* `Seatbelt.exe`, whose own presence on disk is itself a filesystem artifact — see below). This means the artifact classes that anchor most other tool pages in this repo (file-created events, registry-modified events, a dropped service) are largely **absent** here. What's left is process-level, network-level, and — for a narrow set of checks — access-pattern evidence.

## Contents
- [Filesystem — Standalone Binary Only](#filesystem--standalone-binary-only)
- [Process Creation Evidence](#process-creation-evidence)
- [Registry — What's Read, Not What's Written](#registry--whats-read-not-what's-written)
- [WMI-Activity Operational Log](#wmi-activity-operational-log)
- [Network-Layer Evidence (Remote Enumeration Only)](#network-layer-evidence-remote-enumeration-only)
- [Endpoint Security Product Detections](#endpoint-security-product-detections)
- [Memory Forensics](#memory-forensics)
- [Distinguishing From Legitimate Enumeration](#distinguishing-from-legitimate-enumeration)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem — Standalone Binary Only

If, and only if, `Seatbelt.exe` was dropped and run as a standalone binary (not reflectively loaded in-memory by a C2 loader — see `03 - Source Evidence.md`):

| Artifact | Notes |
|---|---|
| The binary itself | No canonical hash (project ships no prebuilt binaries) — filename is whatever the operator chose, not fixed by the project |
| Prefetch | `SEATBELT.EXE-<hash>.pf` (or the operator's chosen filename) if Prefetch is enabled on the host (default on client Windows, off by default on Server SKUs) |
| Shimcache / Amcache | Standard execution-evidence artifacts for any executed binary — cross-reference `Windows/` module's existing coverage of these artifact classes rather than re-deriving it here |
| `-outputfile=` target | A `.txt` or `.json` file at the operator-chosen path, if used — content matches Seatbelt's own DTO field names per check and is straightforward to fingerprint once you know the field vocabulary |

For **in-memory/loader-hosted execution**, none of the above exist — no `Seatbelt.exe` file, no Prefetch entry for it, no Shimcache/Amcache entry — because the assembly is copied directly into an already-running process's memory and never touches disk.

## Process Creation Evidence

The most consistently present target-side artifact, and the one worth prioritizing:

| Log | Event ID | Signal |
|---|---|---|
| Sysmon | 1 (Process Create) | Standalone `Seatbelt.exe` execution, with the **full command line** — `-group=`, `-full`, `-computername=`, and (if used) `-username=`/`-password=` in cleartext |
| Security | 4688 (Process Creation) | Same, if command-line auditing is enabled (`Include command line in process creation events` GPO) — **not enabled by default**, verify before relying on this |
| Sysmon | 1 (Process Create) — indirect | For **Meterpreter's `SPAWN_AND_INJECT` technique specifically**: a new process is spawned purely to host the CLR (the module's own default is `notepad.exe`, per `PROCESS` datastore option verified in `execute_dotnet_assembly.rb`). `notepad.exe` — or any process not normally expected to load the .NET CLR — appearing, then immediately exhibiting network/named-pipe I/O it has no legitimate reason for, is a strong, distinctive signal even with zero knowledge of Seatbelt specifically |
| Sysmon | 7 (Image Load) | `clr.dll`/`clrjit.dll`/`mscoree.dll` loading into a process that doesn't normally host the CLR (e.g. `notepad.exe`, or the C2 implant's own process if `TECHNIQUE SELF`/`--in-process` was used) |
| Sysmon | 8 (CreateRemoteThread) | For `INJECT`/`SPAWN_AND_INJECT` techniques — a remote thread created in the target hosting process from the loader's own process |

For **in-memory execution inside the implant's own process** (`TECHNIQUE SELF` in Meterpreter, `--in-process` in Sliver, or Cobalt Strike's default in-Beacon execution), there is **no separate "Seatbelt" process creation event at all** — the only process-level anomaly is whatever already made the implant's own process suspicious, which existed before Seatbelt ran and isn't specific to it.

## Registry — What's Read, Not What's Written

Seatbelt's registry checks (`AutoRuns`, `LSASettings`, `WindowsDefender`, `UAC`, `NTLMSettings`, and many more) are pure reads. **Standard Windows auditing does not log registry value reads by default** — Security Event ID 4657 (Registry value modified) fires on writes, and object-access auditing for reads requires an explicit SACL configured on the specific key, which is uncommon outside hardened/high-security environments. Practically: **expect no registry-based event log evidence for Seatbelt's registry checks in a typical environment.** If a target has an EDR product with kernel-level registry-read instrumentation (many modern EDR products do this independent of native Windows auditing), that product's own telemetry — not a native Windows log — is the source to check.

## WMI-Activity Operational Log

Applies to any check using `System.Management` (local `AntiVirus`, `Hotfixes`, `NetworkShares`, etc., or any remote check via `-computername=`) — the `Microsoft-Windows-WMI-Activity/Operational` channel, verified against Microsoft's own documentation (not Seatbelt's source, since this is a Windows platform behavior, not tool-specific):

| Event ID | Signal |
|---|---|
| 5857 | A WMI provider is loaded into a hosting process (typically `WmiPrvSE.exe`) to service a query — fires when the required provider isn't already resident. Includes the hosting process ID and provider name |
| 5858 | A WMI query **error** — includes `ClientProcessId` and the `Operation` field, which contains the actual query text (e.g. `Start IWbemServices::ExecQuery - root\SecurityCenter2 : SELECT * FROM AntiVirusProduct`). This only fires on failure (e.g. hitting `root\SecurityCenter2` on a Windows Server host, where the namespace doesn't exist — see `01 - Overview.md`'s Prerequisites) — a genuinely useful, if narrow, source of query-text evidence precisely in the failure case |

This channel does not require special configuration to be enabled on modern Windows (unlike, e.g., the DNS Client Operational log used in `Responder/04 - Target Evidence.md`), making it one of the more reliably-present sources for Seatbelt's WMI-based checks specifically — though it does not cover the registry-read or filesystem-check categories at all.

## Network-Layer Evidence (Remote Enumeration Only)

Only applies when `-computername=` targets this host from elsewhere — a purely local Seatbelt run generates no network traffic.

| Source | What It Shows |
|---|---|
| Windows Firewall (if logging enabled) | Inbound connection on TCP 135 (RPC Endpoint Mapper) followed by a connection on the dynamically negotiated DCOM port, from the source/operator host |
| Zeek `dce_rpc.log` | Captures the DCERPC bind/call activity for the WMI session if the network segment is monitored — the specific interface UUID negotiated for `IWbemServices` is a stronger, protocol-level indicator than port number alone |
| NetFlow / switch logs | An internal host receiving a connection on 135 followed immediately by a connection on an ephemeral high port from the same source, especially from a host with no legitimate WMI-management relationship to this one |

## Endpoint Security Product Detections

Seatbelt is a well-known, publicly documented GhostPack tool with years of exposure to AV/EDR vendors — most mainstream products carry both static signatures (for unmodified, publicly-available builds) and behavioral heuristics (for the check-burst pattern itself, independent of the specific binary). Two important caveats, stated explicitly rather than assumed:

- **No canonical hash exists** (the project ships no binaries), so static/hash-based detection coverage varies enormously by build — a freshly-recompiled-from-source copy with renamed types defeats hash and often static-signature detection entirely, while behavioral detection (the WMI/registry/file-access burst pattern) is unaffected by recompilation.
- Reflective, in-memory loading via a C2 loader's assembly-execution capability is specifically designed to reduce the standalone-binary detection surface (no file on disk, no distinct process in the `TECHNIQUE SELF`/`--in-process` case) — treat "no EDR alert for a dropped/executed Seatbelt.exe" as inconclusive, not as evidence the tool wasn't used.

## Memory Forensics

For in-memory/loader-hosted execution (the common case), memory capture of the hosting process is the **primary** viable forensic avenue, since disk and registry leave little to nothing:

- The `Seatbelt.Commands.*` namespace and the large, distinctive set of `*Command` class names in loaded-assembly metadata
- The version string `"1.2.2"` (verified in `Seatbelt.cs`) and/or the banner text's `v1.2.1` string
- Command-line argument strings matching Seatbelt's flag vocabulary (`-group=`, `-outputfile=`, `-computername=`, `-delaycommands=`) even absent a distinct process, since the argument string exists in memory regardless of how the assembly was invoked
- For Meterpreter's module specifically: the named-pipe name pattern (`\\.\pipe\<8 random alphanumeric chars>`) and AppDomain name (`<9 random alpha chars>`) used to stream output back — both randomly generated per run (`Rex::Text.rand_text_alphanumeric(8)` / `rand_text_alpha(9)`, verified in `execute_dotnet_assembly.rb`), so they won't repeat across runs but are identifiable *as a pattern* (short random pipe name actively receiving data from an unexpected process)

## Distinguishing From Legitimate Enumeration

Every individual artifact class Seatbelt touches has a legitimate counterpart — AV products query `root\SecurityCenter2` themselves, IT asset-management tooling reads Run keys and scheduled tasks fleet-wide, help-desk tooling checks browser presence for support purposes. What distinguishes Seatbelt's pattern from legitimate tooling is the **combination and speed**: one process, in a tight time window, touching AV/EDR WMI classes, registry autorun locations, multiple unrelated browser/credential-store file paths, and event-log history simultaneously — a breadth of unrelated artifact classes that legitimate single-purpose management tools don't typically combine. See `05 - Detection and Hunting.md`'s Hunting Priority table for how to operationalize this distinction.

## Building a Timeline

Because there's rarely a single definitive "Seatbelt ran" event, timeline-building here is a correlation exercise across thin signal: **[process creation for a standalone binary, or an anomalous CLR-hosting process for in-memory execution, Sysmon 1/7]** → **[WMI-Activity 5857/5858 entries for `root\SecurityCenter2`/`root\cimv2` queries in the same window, if AV/system checks ran]** → **[any recoverable loader/C2-side task log, per `03 - Source Evidence.md`, showing the exact command line and timestamp]**. Given how thin the on-host evidence is by design, a tight timestamp match between a process-creation anomaly and a WMI-Activity log entry is often the strongest correlation available — treat a wide gap between them as either clock skew (normalize both to a common reference) or two unrelated events sharing a host.
