# Cobalt Strike — Target Evidence

What an operation leaves on the **target/victim** host and the network it sits on. Because a Malleable C2 profile can rewrite nearly every network-observable field (`01 - Overview.md`), the artifacts below split cleanly into two confidence tiers: **operator-configurable** (URIs, User-Agent, headers, `spawnto`, service names — trivially changed) and **structural** (the underlying protocol handshake shape, the injection primitive's API call sequence, named-pipe naming conventions the operator would have to recompile the Artifact Kit to fully change). `05 - Detection and Hunting.md`'s priority table ranks every signal below against that split explicitly.

## Contents
- [Process Artifacts](#process-artifacts)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon)
- [Named-Pipe Evidence](#named-pipe-evidence)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Process Artifacts

| Artifact | Detail |
|---|---|
| Initial Beacon process | Whatever executed the delivered artifact — a direct `.exe`, a spawned process from a macro/script loader, or (for `jump psexec`) a newly created Windows service host |
| `spawnto` sacrificial process | The temporary process Beacon spawns for post-exploitation jobs — historically/commonly **`rundll32.exe`** by default (`01 - Overview.md`), operator-overridable via `spawnto x86`/`spawnto x64` or the Malleable profile. An unexpected `rundll32.exe` (or whatever `spawnto` value is in play) making an **outbound HTTP(S) connection with no DLL/export argument on its command line** is a well-documented anomaly — per Fortra's own ["Why is rundll32.exe connecting to the internet?"](https://www.cobaltstrike.com/blog/why-is-rundll32-exe-connecting-to-the-internet) post acknowledging this exact pattern |
| `spawn`/`inject` target process | A new sacrificial process (`spawn`) or an existing PID (`inject`) receiving `VirtualAllocEx`/`WriteProcessMemory`/remote-thread injection by default — fully custom via a licensed UDRL, so treat the specific API sequence as a medium-confidence signal on a well-resourced engagement |
| `jump psexec`/`psexec64` service process | A newly created Windows service running the Service EXE artifact — classic PsExec-family evidence pattern, see `Purple Teaming/PsExec/` (Sysinternals, Wave 2) and `Purple Teaming/Impacket/psexec/` for the shared SMB/SCM mechanics this rides on |
| `jump winrm`/`winrm64` process | A PowerShell process launched under the WinRM service host (`wsmprovhost.exe`) rather than a new Windows service — quieter from a service-creation-event standpoint, noisier from a PowerShell-logging standpoint |
| `execute-assembly` child process | A sacrificial process hosting the injected .NET assembly, subject to AMSI scanning if active |
| `logonpasswords`/`mimikatz` process | A temporary sacrificial process running Mimikatz against LSASS — shares the LSASS-`GrantedAccess` evidentiary pattern documented in depth in `Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md`, cross-linked rather than re-derived here |
| `browserpivot` target process | An existing, already-running browser process receiving injection — network traffic from that browser process suddenly proxying through an unfamiliar local port is the operational tell |

## Filesystem Artifacts

| Artifact | Notes |
|---|---|
| Dropped stager/loader | Variable — macro dropper, PowerShell one-liner, or a compiled EXE/DLL/service binary depending on delivery method and Artifact Kit customization; no fixed filename/hash to rely on for a licensed, customized deployment |
| `jump psexec` service binary | Written to the target over SMB/ADMIN$ before the SCM starts it — filename/path is operator-chosen or Artifact-Kit-default, not a fixed constant |
| Staged-payload download | If staging is enabled (`host_stage true`, the default), the full Beacon backdoor is retrievable from the Team Server at runtime via the 4-character-alphanumeric-with-checksum8 stager URI (`01 - Overview.md`) — a transient network fetch, not necessarily a persisted file if loaded directly into memory |
| `execute-assembly`/BOF output | BOFs execute inside Beacon's own process and generally leave **no separate on-disk artifact**; `execute-assembly` results are typically piped back over C2 rather than written to disk unless the assembly itself writes output files |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Security | 4688 | Process creation — captures the `spawnto` sacrificial process, any `jump`/`remote-exec` child process, and (with command-line auditing enabled) the actual command line, critical since many Beacon actions otherwise leave no argument trail |
| Security | 4697 | New service installed (`jump psexec`/`psexec64`) — logs the service name/binary path |
| System | 7045 | Service Control Manager service install — the System-log counterpart to 4697, fires on the same `jump psexec` event |
| Security | 4624 | Logon events — Logon Type 3 (network) for SMB/ADMIN$ access during `jump psexec`; Logon Type 9 (NewCredentials) is the signature of a `make_token`/pass-the-hash operation, since the token is created locally without a corresponding interactive/network logon of its own |
| Security | 5140 / 5145 | Network share/file access — ADMIN$/C$ access during `jump psexec`'s binary drop |
| Microsoft-Windows-PowerShell/Operational | 4103 / 4104 | Module/Script Block Logging — captures `jump winrm`'s underlying PowerShell one-liner and any `powershell`/`powerpick` Beacon command content, if logging is enabled (off by default on many builds — see `LOLBins/powershell/04 - Target Evidence.md` for the same off-by-default caveat applied generically) |
| Microsoft-Windows-WinRM/Operational | — | WinRM session establishment corresponding to `jump winrm`/`winrm64` |

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The `spawnto` sacrificial process, `jump`/`remote-exec` child processes, `execute-assembly` sacrificial child — parent-child lineage back to the initial Beacon process is the key correlation |
| 3 (Network Connect) | Beacon's own C2 callback, and — critically — an unexpected connection **from the `spawnto` process itself** (e.g. `rundll32.exe` reaching out) rather than from the process that originally executed the payload |
| 8 (CreateRemoteThread) | The default `VirtualAllocEx`/`WriteProcessMemory`/thread-creation injection sequence for `spawn`/`inject`/`execute-assembly` |
| 10 (ProcessAccess) | Handle-open step preceding injection — `GrantedAccess` mask interpretation for LSASS specifically (the `logonpasswords`/`mimikatz` path) follows the same evidentiary logic as `Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md`, cross-linked rather than re-derived |
| 11 (FileCreate) | Any dropped stager/loader/service-binary artifact |
| 17 / 18 (PipeCreated / PipeConnected) | SMB-chained Beacon named-pipe creation/connection — see [Named-Pipe Evidence](#named-pipe-evidence) below; **not enabled by default**, must be explicitly configured in the Sysmon config |
| 22 (DNSEvent) | DNS-listener beaconing — repeated queries to a single parent domain with encoded-looking subdomain/TXT-record content |

## Named-Pipe Evidence

Cobalt Strike's SMB-chained Beacon relay and post-exploitation jobs use named pipes with **commonly observed default naming patterns**, corroborated across multiple independent detection write-ups (Hive Security's defender playbook, Microsoft Sentinel's community hunting content, SigmaHQ's `pipe_created_hktl_cobaltstrike` rule):

| Pipe pattern | Purpose |
|---|---|
| `\msagent_*` | Post-exploitation job relay |
| `\postex_*` (Cobalt Strike 4.2+) | Shell command output relay |
| `\status_*` | Beacon status reporting |
| `\MSSE-*-server` | Default SMB listener naming |

**Caveat, stated per §10's accuracy-discipline rule:** these patterns are consistently reported across multiple independent third-party detection sources rather than confirmed against Fortra's own source (which isn't public), so treat them as well-corroborated community-verified defaults, not vendor-documented constants. They are changeable by an operator willing to modify Artifact Kit source and recompile — in practice, several of the same sources note operators frequently don't bother, making unmodified default-pipe hunting still a real-world productive signal despite being trivially defeatable in principle.

## Network-Layer Evidence

| Signal | Detail | Confidence |
|---|---|---|
| TLS JA3 (client) | `72a589da586844d7f0818ce684948eea` and `a0e9f5d64349fb13191bc781f81f42e1` reported across independent write-ups as common default-Java-TLS-stack fingerprints associated with unmodified Cobalt Strike clients | Medium — JA3 fingerprints the TLS *library* stack (Java's), not Cobalt Strike specifically; a shared value alone is not proof, only a candidate filter |
| TLS JA3S (server) | `ae4edc6faf64d08308082ad26be60767` and `b742b407517bac9536a77a7b0fee28e9` reported similarly for the server side | Medium, same caveat |
| JARM (default Team Server) | `07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2`, actively obtained by sending 10 crafted TLS ClientHellos and hashing the combined response shape | Medium-High for an **un-customized** listener; directly reflects the underlying Java TLS stack, so it drifts across JDK versions and is defeated by operator TLS reconfiguration |
| Default self-signed certificate | Historically `CN=jquery.com`, serial `146473198`, `O=Strategic Cyber LLC` on older/un-customized installs — a Shodan query of `ssl.cert.serial:146473198 AND ssl.cert.subject.cn:jquery.com` surfaces exposed default-cert Team Servers | Low — operators overwhelmingly replace the default cert (Let's Encrypt or a supplied cert) on any real engagement; useful only against sloppy/unmaintained infrastructure |
| Default HTTP GET/POST URIs | `/jquery-3.3.1.min.js`, `/jquery-3.3.2.min.js`, `/submit.php?id=` observed on un-customized/example profiles | Low — the entire point of Malleable C2 is that this is operator-rewritable; useful only against the (still common, per `01 - Overview.md`) population running unmodified or lightly modified public profiles |
| Default User-Agent | `Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko` on un-customized profiles | Low, same caveat — but a badly mismatched UA/TLS-version pairing (an IE11-era UA over a TLS 1.3 handshake, for example) is itself a durable *tell*, since fixing that mismatch requires more profile sophistication than most operators apply |
| Beacon check-in periodicity | Default 60-second sleep, 0% jitter unless configured otherwise (`01 - Overview.md`) — statistically visible as near-fixed-interval outbound connections even once URI/UA/cert content is fully customized | **High** — surviving profile customization is exactly why beaconing-interval statistical analysis (RITA-style scoring) remains one of the most durable network hunts against this tool class |

## Endpoint Security Product Behavior

Modern EDR products commonly flag the default `VirtualAllocEx`/`WriteProcessMemory`/remote-thread injection sequence, unsigned/unusually-metadata'd binaries, and known Artifact Kit-derived PE templates via behavioral and static signatures respectively — but Cobalt Strike's licensed Artifact Kit/Sleep Mask Kit/UDRL Kit customization surface (`01 - Overview.md`) exists specifically to erode static-signature and in-memory-scan detection over an engagement. Treat AV/EDR silence as inconclusive on a well-resourced/licensed deployment, and prioritize the behavioral/network signals in `05 - Detection and Hunting.md`'s priority table over vendor-flag presence alone.

## Memory Forensics

A live Beacon process's memory holds the decrypted Malleable C2 profile in effect, the sleep/jitter configuration, and (for a `spawnto`-injected sacrificial process) the injected shellcode/DLL itself before any Sleep Mask Kit obfuscation reapplies at the next sleep cycle. Public config-extraction tooling — e.g. Didier Stevens' `1768.py` and Sentinel-One's `CobaltStrikeParser` — decode a captured Beacon's embedded configuration block (listener endpoints, sleep/jitter, `spawnto`, watermark value) directly from a memory dump or the binary itself where XOR-obfuscation (historically keyed with `0x2E`, per widely corroborated community reverse-engineering) hasn't been further customized. A successfully extracted config is one of the highest-value single artifacts available — it directly confirms C2 infrastructure, timing, and (via the watermark) which license/auth-file family generated this specific Beacon.

## Building a Timeline

1. Delivery/execution — initial stager or stageless artifact execution (Sysmon 1, Security 4688)
2. First callback — Beacon's initial C2 connection (Sysmon 3, correlates to the Team Server's `events.log` per `03 - Source Evidence.md`)
3. `spawnto`/injection activity for any post-exploitation job (Sysmon 8/10, unexpected `rundll32.exe`-or-equivalent network activity)
4. Credential access (LSASS `GrantedAccess`, per `Mimikatz/sekurlsa (Credential Dumping)/`'s shared evidentiary pattern)
5. Lateral movement (`jump psexec`: Security 4697/System 7045/4688; `jump winrm`: WinRM operational log + PowerShell 4103/4104)
6. Pivoting (Sysmon 17/18 for SMB-chained Beacons; a second internal-only listening port for TCP pivots)
7. Data staging/exfil (chunked outbound transfer volume against the same beaconing C2 channel identified in step 2)

Cross-reference every step against the Team Server's `beacon-id.log` timestamps (`03 - Source Evidence.md`) wherever both sides of the evidence are recoverable — the strongest possible confirmation that a target-host event was Cobalt Strike-driven rather than inferred from indicators alone.
