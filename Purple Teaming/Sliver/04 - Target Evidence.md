# Sliver — Target Evidence

Evidence left on the **implanted/victim** host and the network it sits on. Because every Sliver binary is freshly compiled per-generation (per-binary keypair, randomized/obfuscated symbols unless `--skip-symbols`), **static file-hash and string-based detection is unreliable by design** — the durable target-side signal is behavioral: process lineage, the specific in-memory execution techniques used (`execute-assembly`/`sideload`/`spawn-dll`/`migrate`), and network/protocol-level traffic patterns per C2 transport.

## Contents
- [Process Artifacts](#process-artifacts)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon)
- [Network-Layer Evidence by Transport](#network-layer-evidence-by-transport)
- [Named-Pipe / TCP Pivot Evidence](#named-pipe--tcp-pivot-evidence)
- [Endpoint Security Product Detections](#endpoint-security-product-detections)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Process Artifacts

| Artifact | Detail |
|---|---|
| Initial implant process | Whatever executed the delivered artifact — an `.exe` directly, `rundll32.exe`/`regsvr32.exe` for a `shared`-format DLL, or a service host for a `service`-format implant staged via `psexec` |
| `execute-assembly` child process | By default a **new, sandboxed child process** (default `notepad.exe`) hosting the .NET assembly — an unexpected `notepad.exe` (or whatever `--process` value was chosen) with no user-visible window and a short-lived child of the implant process is a strong signal; `--in-process` avoids creating this child entirely, trading a process-tree indicator for staying inside the already-running implant |
| `sideload`/`spawn-dll` host process | Same pattern — an unexpected process (default `notepad.exe`) hosting injected code, parented by the implant's own process unless further migration/parent-spoofing occurred |
| `migrate` target process | The implant's *entire* running context relocates — expect implant network behavior (C2 callbacks) to suddenly originate from a process that has no independent reason to make that connection (e.g. `explorer.exe` suddenly beaconing to an external IP) |
| `psexec`-staged service process | A newly created Windows service (operator-chosen `--service-name`, default `Sliver`) running from `--binpath` (default `C:\Windows\Temp`) — same SCM/service-creation mechanism as any other PsExec-family tool, see `Purple Teaming/PsExec/` and `Purple Teaming/Impacket/psexec/` for the shared underlying evidence pattern |
| `msf`/`msf-inject` | A Metasploit payload (default `meterpreter_reverse_https`) running either in the implant's own process or injected into another PID — carries Meterpreter's own process/network signature layered on top of Sliver's, see `Purple Teaming/Metasploit/Meterpreter/04 - Target Evidence.md` |

## Filesystem Artifacts

| Artifact | Notes |
|---|---|
| Dropped implant binary | No fixed name/hash — `--name` is either operator-chosen or a randomly generated codename (e.g. `SNOWY_TIGER`-style two-word names observed in the project's own documentation examples); file size and PE characteristics vary by `--format`/`--os`/`--arch`/obfuscation settings |
| Named-pipe artifact (Windows) | `\\.\pipe\<name>` for the duration the pivot listener is active — `--name` is operator-chosen, no fixed default, but the pipe itself is enumerable while live |
| Loot/dump files | `procdump`, `execute-assembly --save`, etc. write to operator-specified local paths on the **operator's** machine by default (not the target) unless staged temporarily on the target filesystem before exfil — check for transient `.dmp`/output files in common staging directories (`%TEMP%`, `C:\Windows\Temp`) that were cleaned up but may survive in `$MFT`/USN journal records |
| Stager artifact | A small stub binary distinct from the full implant — if recovered, its embedded `--lhost`/`--lport` staging target directly identifies the Sliver server's stage-listener endpoint |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | **4688** (Process Creation, if command-line auditing enabled) | Captures the initial implant execution and any `execute-assembly`/`sideload`/`spawn-dll` child-process creation — the single most useful native event ID for this tool class if enabled |
| Security | 4697 (Service Installed) | For `psexec`-staged execution — a new service matching the operator's `--service-name` (default `Sliver`) |
| Security | 4624/4625 (Logon) | Relevant only if `psexec`/lateral movement used explicit alternate credentials — same pattern as any other SMB-based remote-execution tool |
| System | 7045 (Service Install, System log) | Companion to Security 4697 for the same `psexec` staging event |

Cross-reference exact field mechanics (logon type, service-install event schema) in `Windows/12 - Lateral Movement.md` and `Windows/05 - Users, Groups & Authentication.md` — this note gives the tool-specific pattern, not a re-derivation of the base event schema.

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | Implant execution, `execute-assembly`/`sideload`/`spawn-dll` child processes, `migrate` target process — the `ParentImage`/`Image` relationship is the strongest single Sysmon signal for this tool class since the binary itself has no fixed hash |
| 3 (Network Connect) | The C2 callback itself — outbound connection to the mTLS/HTTP(S)/DNS/WG listener's port. For mTLS specifically, an outbound connection to **TCP 8888** (the framework default, if unchanged by the operator) from a process with no legitimate reason to make it is a high-value, low-noise-ratio hunt |
| 7 (Image/DLL Load) | `sideload`/`spawn-dll` reflective/unmanaged DLL loads frequently **do not** appear here at all, since reflective loading bypasses the normal Windows loader Sysmon 7 instruments — its *absence* alongside other injection indicators (Sysmon 8/10) is itself informative |
| 8 (CreateRemoteThread) | `execute-shellcode` injection into another PID, `sideload`/`spawn-dll` targeting a process other than the implant's own |
| 10 (ProcessAccess) | `migrate`, `execute-shellcode --pid <target>`, and `msf-inject` all require opening a handle to the target process first — Sysmon 10 with a `GrantedAccess` mask consistent with code-injection rights (`PROCESS_VM_WRITE`, `PROCESS_CREATE_THREAD`, etc.) against an unrelated process is a strong corroborating signal, same evidentiary logic as `Purple Teaming/Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md`'s `GrantedAccess` mask discussion for LSASS access |
| 22 (DNS Query) | For DNS C2: repeated queries to the operator-controlled delegated domain, often with structurally unusual subdomain patterns (encoded task/response data as DNS labels) — see the DNS-transport row below |

## Network-Layer Evidence by Transport

| Transport | What to look for |
|---|---|
| mTLS | Outbound TLS handshake to the listener's `lhost:lport` (default TCP 8888) that is **not** a standard HTTPS/443 connection — an unusual destination port doing a TLS handshake is itself a mild anomaly; the mutual-auth cert exchange (client cert presented) is visible at the TLS layer even without decrypting application data |
| HTTP(S) | Requests to the listener's domain/IP with **procedurally-generated but structurally consistent URL paths** per the operator's chosen `--c2profile` — individual implants won't share an identical static path, but requests from the same C2 profile share the same *shape* (path-segment count/pattern, header set); Zeek `http.log`/`ssl.log` filtered for repeated connections to one destination with irregular-but-patterned URIs is the practical hunt |
| DNS | Repeated `A`/`TXT` (or similar) queries to a domain delegated via `NS` record to an external/unusual authoritative server, often with base32/base64-like encoded subdomain labels carrying task data — Zeek `dns.log` filtered for high query volume to a single non-corporate parent domain, or for TXT-record-heavy query patterns, is the practical hunt. `--no-canaries` (if disabled by the operator) removes Sliver's own canary-domain self-monitoring but has no effect on this detection surface |
| WireGuard | UDP traffic to the listener's port (default 53 for the listener, plus 8888/1337 for the virtual-interface/key-exchange ports) — WireGuard's own handshake has a recognizable packet-size/timing signature distinct from generic UDP, and its use as a C2 transport at all is comparatively rare, making it a higher-confidence flag when observed on an endpoint with no legitimate VPN use case |

## Named-Pipe / TCP Pivot Evidence

| Signal | Detail |
|---|---|
| Named-pipe enumeration | `\\.\pipe\<operator-chosen-name>` visible on the **pivot host** while the listener is active (`pivots named-pipe` output shows the exact pipe name chosen) — enumerable via `Get-ChildItem \\.\pipe\` or Sysmon Event ID 17/18 (Pipe Created/Connected) if configured |
| Sysmon 17/18 | Named-pipe creation/connection events on the pivot host — the strongest native signal for this specific technique, since named-pipe C2 traffic itself doesn't traverse the network the way TCP pivoting does |
| TCP pivot | A **second, internal-only** listening port (operator-chosen via `-l`, default 9898) on the pivot host, receiving connections from the pivoted host — Sysmon 3 on the pivot host for the *inbound* side, and on the pivoted host for the *outbound* side to an internal (not external) IP |
| No direct egress from the pivoted host | The defining characteristic — a host showing implant-consistent behavior (execute-assembly children, injection patterns) with **no corresponding outbound connection to an external IP** should immediately raise pivoting as the explanation, and should redirect the hunt toward the pivot host's own C2 traffic instead |

## Endpoint Security Product Detections

Mainstream EDR products increasingly carry **behavioral signatures for Sliver specifically** (not just generic Go-binary or C2-pattern heuristics) given its public MITRE ATT&CK Software entry (**S0633**) and its adoption by real threat actors in the wild (documented by multiple vendor blogs, e.g. Cybereason's "Sliver C2 Leveraged by Many Threat Actors"). Expect detections keyed on: Go-runtime binary characteristics combined with the mTLS/gRPC handshake shape, `execute-assembly`'s in-process AMSI/ETW-bypass pattern when `--amsi-bypass`/`--etw-bypass` is used, and known-bad C2 profile URL-shaping patterns from leaked/default configurations. As with any actively maintained framework, evasion flags (`--evasion`, `--skip-symbols` *not* set, traffic encoders) are specifically designed to reduce the reliability of static/signature-based product detections — treat an EDR "no detection" result as weak evidence of absence, not strong evidence.

## Memory Forensics

The implant process's memory holds its **decrypted C2 configuration** (transport endpoints, encryption keys) for as long as it runs — a memory capture of a live/recently-terminated implant process can recover the exact server address/port it was calling back to even where network capture wasn't in place, and can recover in-memory-only artifacts from `--in-process` `execute-assembly`/`sideload` runs that never touched disk.

## Building a Timeline

There is no single "Sliver ran here" event on the target — timeline-building is a correlation exercise across process lineage and network evidence: **[initial delivery artifact execution, Sysmon 1] → [first outbound C2 connection, Sysmon 3, matched against a known/suspected listener port or DNS pattern] → [any execute-assembly/sideload/migrate child-process or injection events, Sysmon 1/8/10] → [source-side session/beacon check-in timestamp from `03 - Source Evidence.md`'s server database, if accessible]**. Because beacons check in on an interval+jitter rather than continuously, a target host showing periodic (not constant) outbound connections to the same destination at roughly-but-not-exactly regular intervals is itself a beacon-consistent pattern worth flagging even before any single connection is confirmed malicious.