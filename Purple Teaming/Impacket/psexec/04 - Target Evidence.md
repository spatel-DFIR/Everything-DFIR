# Impacket — psexec.py — Target Evidence

Evidence left on the **target/destination** host. This is the deep end of the note — psexec.py's evidence trail spans filesystem, registry, three separate logging subsystems (Security, System, Sysmon), and the network layer.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Named Pipe Detail](#named-pipe-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing from Genuine Sysinternals PsExec](#distinguishing-from-genuine-sysinternals-psexec)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Dropped service binary | `C:\Windows\<8-random-mixed-case-letters>.exe` by default (`ADMIN$` maps to `%SystemRoot%`) — name changes with `-remote-binary-name`, location changes if `ADMIN$` wasn't writable and `findWritableShare()` fell back to a different share |
| Second dropped file (if `-c` used) | A **separate**, operator-chosen local file uploaded and executed as the actual payload — see `02 - Hands-On Use Cases.md`'s "Uploading and Running a Custom Local Tool." Two independent files, two independent hashes, potentially two independent drop locations if a custom `-path` was also used |
| File hash | **SHA1/SHA256 of the default dropped service binary is consistent across engagements and hosts** — the same embedded RemCom-derived template each run, version-pinned to the Impacket release in use. **This does not hold if `-file` was used** — see the caveat in `05 - Detection and Hunting.md` |
| Prefetch | `C:\Windows\Prefetch\<8-RANDOM-LETTERS>.EXE-<HASH>.pf` — created if the binary fully executes and Prefetch tracing is enabled (default on workstations; verify on servers, since server SKUs have historically varied on this by version/edition). See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Both record the dropped binary's path and SHA1 (Amcache also a compile timestamp). **The compile timestamp is a known constant** for the default binary, not a genuine "first seen in the wild" indicator — don't over-read it as evidence of when the *attacker's copy* of the tool was built. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | **Absent.** Delivery is over SMB, not web/email/an archive extraction, so no Mark-of-the-Web alternate data stream is ever written. A brand-new EXE sitting directly in `C:\Windows\` root with *no* Zone.Identifier is itself a subtle tell — legitimate installers land via MSI into `Program Files`, and genuinely web-downloaded tools normally carry MOTW |

## Registry

| Key | Detail |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | Newly created service key. `ServiceName` is a **separate random 4-character string** from the 8-character binary filename — don't expect them to match. `ImagePath` points at the dropped binary; `Start=3` (`SERVICE_DEMAND_START`, i.e. it never auto-starts on boot — it only ran because `psexec.py` explicitly started it once) |
| Service lifecycle anomaly | A service that is created, started exactly once, and then deleted within seconds-to-minutes is itself anomalous — legitimate software installers create services that persist and follow normal start-type conventions (`Auto`/`Boot`/`System`), not a create-start-stop-delete cycle this tight |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **System** | **7045** | **The single highest-value signal for this tool.** "A service was installed in the system" — captures `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, `Account` (SYSTEM). See `Windows/11 - Event Log Analysis.md` |
| System | 7036 | Service Control Manager start/stop notification for the same service, moments after 7045, then again moments later for the stop half of cleanup |
| Security | 4624 (Logon Type 3 — Network) | Inbound SMB authentication from the operator's source IP; check `AuthenticationPackageName` for `NTLM` vs `Kerberos` to distinguish which auth variant from `02 - Hands-On Use Cases.md` was used |
| Security | 4672 | Special privileges assigned to the new logon — confirms an admin-equivalent token, expected for this technique to succeed at all |
| Security | 5140 | Network share object accessed — `ADMIN$` (or whichever share `findWritableShare()` landed on) accessed from the operator's source IP |
| Security | 5145 | Detailed share-file access (only if the more granular object-access auditing subcategory is enabled) — shows the exact file write inside the share, including the random filename |
| Security | 4697 | "A service was installed" — Security-log twin of System 7045, only present if "Audit Security System Extension" is explicitly enabled (far less commonly on than 7045 by default) |
| Security | 4688 | Process creation — if command-line auditing is enabled, shows the dropped binary launching, then `cmd.exe`, then whatever the operator actually ran, as a full process chain |
| Security | 4689 | Process termination — the tail end of the cleanup teardown |
| Security | 4673/4674 | Sensitive privilege use — may appear depending on what the operator's remote command does once inside the shell (e.g. `SeDebugPrivilege` use if they pivot into credential dumping from the SYSTEM shell) |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The dropped binary launching under `services.exe`, then its `cmd.exe` child, then grandchild commands — see the process tree in `01 - Overview.md` |
| 3 (Network Connect) | Inbound TCP 445 (or 139) connection from the operator |
| 11 (File Create) | The binary write into `C:\Windows\` — and a second File Create event if `-c` uploaded a separate payload |
| 13 (Registry Value Set) | Service key creation under `CurrentControlSet\Services\` |
| **17 / 18 (Pipe Created / Pipe Connected)** | **`\PIPE\RemCom_communicaton`** plus the per-invocation `\PIPE\RemCom_stdin/stdout/stderr<machine><pid>` pipes — see [Named Pipe Detail](#named-pipe-detail) below. This is the **strongest single Sysmon signature** in this entire note |
| 22 (DNS Query) | Only relevant if Kerberos auth forced a DNS lookup for the target's SPN from a *different* host in the chain — not typically generated on the target itself |

## Named Pipe Detail

The RemCom protocol's pipe names are **hard-coded in Impacket's client-side expectations**, not derived from whichever binary got uploaded — this is why they remain a reliable signature even when `-file` swaps out the actual dropped executable (see `05 - Detection and Hunting.md`).

| Pipe | Purpose |
|---|---|
| `\PIPE\RemCom_communicaton` | Fixed control channel name (note the preserved misspelling — "communicaton," missing an "i") |
| `\PIPE\RemCom_stdin<machine><pid>` | Per-invocation stdin relay, suffixed with a random 4-letter "machine" tag and the remote process ID |
| `\PIPE\RemCom_stdout<machine><pid>` | Per-invocation stdout relay |
| `\PIPE\RemCom_stderr<machine><pid>` | Per-invocation stderr relay |

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `smb_files.log` / `smb_mapping.log` | Tree-connect to `ADMIN$` (or fallback share), followed by a file write matching the dropped binary's name and size |
| Zeek `dce_rpc.log` | The `svcctl` operations sequence — `OpenSCManagerW`/`CreateServiceW`/`StartServiceW` — visible as named DCE/RPC operations against the `\PIPE\svcctl` endpoint, independent of host-based logging entirely |
| NetFlow / firewall logs | A short burst of TCP 445 traffic from one internal host to another, often the first indicator available in environments without endpoint logging at all — especially valuable for the fleet-wide/mass-execution scenario in `02 - Hands-On Use Cases.md`, where dozens of hosts show the identical pattern within a tight window |

## Endpoint Security Product Signatures

Most mainstream AV/EDR products carry **static signatures for the default RemCom-derived binary** specifically (not just generic "hacktool" heuristics), since it's been publicly known and unchanged in its default form for years. A target with any modern endpoint product should, in the default `-file`-less case, generate its own product-specific alert independent of anything in this note — the *absence* of such an alert on a host that otherwise shows the Event 7045/Sysmon 17-18 pattern is itself worth investigating (product disabled, exclusion misconfigured, or `-file` was used to evade signature matching).

## Memory Forensics

The dropped service binary runs as a distinct process under `services.exe` for its (typically short) lifetime — if memory is captured while it's still resident, standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) will show it as a normal, non-injected, un-hidden process — it has no rootkit or hiding behavior of its own. Its forensic value in memory is mainly for recovering the **exact command(s)** the operator ran through the RemCom pipe relay, which may not otherwise be captured if 4688 process-creation auditing wasn't enabled for the downstream `cmd.exe` children.

## Building a Timeline

The tightest, highest-confidence timeline anchor is the sequence: **4624 (Type 3 logon) → 5140 (share access) → File Create → 7045 (service install) → 7036 (service start) → Sysmon 1 (process create) → Sysmon 17/18 (pipe create/connect) → [operator activity] → 7036 (stop) → Security 4689 → File deletion.** All of these typically land within a span of a few seconds to low minutes on a normal, uninterrupted run — a wider spread (e.g. the service key persisting for hours) suggests either an interrupted cleanup or a deliberately slower, evasive operator.

## Distinguishing from Genuine Sysinternals PsExec

> 🔴 **Critical for triage — don't conflate the two.** Genuine `PsExec.exe` (Sysinternals) uses service name **`PSEXESVC`**, drops **`PSEXESVC.exe`** by default (configurable via its own `-r` flag), and opens the pipe **`\PIPE\psexecsvc`**. Impacket's `psexec.py` uses random 4/8-character names by default and the pipe family **`\PIPE\RemCom_*`**. If you see the RemCom pipe names or a service that isn't `PSEXESVC`, you are **not** looking at the legitimate Sysinternals tool.

See `Windows/12 - Lateral Movement.md` for the broader PsExec-family comparison table (Impacket vs. Sysinternals vs. `wmiexec.py`/`smbexec.py`) and `Windows/10 - Persistence Mechanisms/Services.md` for general service-based persistence/execution artifacts this note deliberately doesn't re-derive.
