# Impacket — wmiexec.py — Target Evidence

Evidence left on the **target/destination** host. This is a fundamentally thinner filesystem/registry trail than `psexec.py`'s — no service, no persistent binary drop by default — but a **richer** protocol/event trail across DCOM, WMI-Activity, and (conditionally) PowerShell logging that psexec never touches at all.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [DCOM / RPC Detail](#dcom--rpc-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Contrast with psexec.py / smbexec.py](#contrast-with-psexecpy--smbexecpy)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Output-relay file | `C:\Windows\__<unix-epoch-timestamp>` by default (`ADMIN$` maps to `%SystemRoot%`) — e.g. `C:\Windows\__1754176575.883421`. **No file extension.** Location changes with `-share`. **Only exists** if output capture is enabled — completely absent with `-nooutput`/`-silentcommand` |
| File lifecycle | Created, written to by the target's own `cmd.exe`/`powershell.exe` (via loopback SMB), read once by the operator's SMB session, then deleted — typically within a couple of seconds. The **same filename is reused for every command in one session** (see `01 - Overview.md`), so a live host may show a rapid create→delete→create→delete cycle against one identical filename if command execution is caught mid-session |
| `lput`-dropped payload (if used) | A **separate, persistent** file at whatever path the operator chose in the interactive shell — independent of the transient output file, with its own hash and its own forensic footprint. See `02 - Hands-On Use Cases.md` |
| Prefetch | Created for `cmd.exe`, `powershell.exe`, or whatever binary was actually launched — but **not** for a uniquely-named dropped executable, since none exists in the default case. `WMIPRVSE.EXE-<HASH>.pf` itself may also appear/update. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `cmd.exe`/`powershell.exe`/`WmiPrvSE.exe` executions — all common, low-uniqueness binaries already present on every Windows host, which makes these **far weaker** signals here than they are for psexec's uniquely-named dropped binary. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | Not applicable in the default configuration — there's no delivered file to carry it. If `lput` was used, the uploaded file also carries **no MOTW**, since delivery is over SMB, not web/email |

## Registry

**No new service key is created — this is the core forensic distinction from `psexec.py`/`smbexec.py`.** `wmiexec.py`'s use of `Win32_Process.Create()` is a one-shot, transient WMI method call; it does **not** touch `HKLM\SOFTWARE\Microsoft\WBEM` or the WMI repository, and does not register anything under `CurrentControlSet\Services`. Don't confuse this with **WMI Event Subscription persistence** (a separate technique, [T1546.003](https://attack.mitre.org/techniques/T1546/003/)) — that technique registers permanent `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` objects in the WMI repository and *does* leave registry/repository artifacts. `wmiexec.py` as covered in this note does not do that; it only ever performs an immediate, one-time process creation.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Microsoft-Windows-WMI-Activity/Operational** | **5857** | `Operation_Started` — a WMI provider (CIMWin32, which hosts `Win32_Process`) was loaded, with `HostProcess` set to `wmiprvse.exe`. Fires for essentially **every** WMI provider operation, including this one — this is the closest WMI-side analog to psexec's Event 7045 |
| Microsoft-Windows-WMI-Activity/Operational | 5858 | `Operation_ClientFailure` — only logged on an **error** (e.g. access denied, malformed query). Won't appear on a clean, successful run; useful for catching *attempted but blocked* execution |
| Security | 4624 (Logon Type 3 — Network) | Expect **up to two** of these per session — one for the SMB output-relay connection (only if output capture is on) and a separate one for the DCOM/RPC authentication that actually drives execution. Check `AuthenticationPackageName` for `NTLM` vs `Kerberos` on each |
| Security | 4672 | Special privileges assigned to the new logon — confirms an admin-equivalent token, required for `Win32_Process.Create()` to succeed at all |
| Security | 5140 | Network share object accessed — `ADMIN$` (or whatever `-share` targets) — **only present if output capture is enabled** |
| Security | 5145 | Detailed share-file access (if the granular object-access auditing subcategory is enabled) — shows the exact `__<timestamp>` filename being written/read/deleted |
| Security | 4688 | Process creation — if command-line auditing is enabled, shows `WmiPrvSE.exe` launching `cmd.exe` (or `powershell.exe`, or the raw command directly under `-silentcommand`), then the operator's actual command as a child |
| Security | 4689 | Process termination — end of the executed command |
| System | 10016 (Microsoft-Windows-DistributedCOM) | A common, frequently-noisy System-log event that fires when an account lacks the DCOM launch/activation permissions WMI needs — worth checking as a *failed-attempt* indicator alongside WMI-Activity 5858, even though it's not exclusive to this tool |

**Accuracy note:** WMI-Activity Operational Event IDs **5860** (`Operation_TemporaryEssStarted`) and **5861** (`Operation_ESStoConsumerBinding`) are specifically about **permanent WMI event subscriptions** — they fire when an `__EventFilter`/`__EventConsumer` binding is registered, which is how WMI-based *persistence* mechanisms work. `wmiexec.py`'s transient `Win32_Process.Create()` calls do **not** register any such binding and do **not** generate 5860/5861. Don't include those two IDs in a wmiexec hunt — they belong to the WMI Event Subscription persistence technique (T1546.003), a different tool/technique family entirely, and including them here would be a false-confidence signal.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | `WmiPrvSE.exe` launching `cmd.exe /Q /c <command> 1> \\127.0.0.1\ADMIN$\__<timestamp> 2>&1` (or the base64 PowerShell wrapper, or the raw command directly under `-silentcommand`, with `WmiPrvSE.exe` as its **direct** parent) — the full command line is captured verbatim, making this the single most information-dense artifact for this tool |
| 3 (Network Connect) | Inbound TCP 135 + dynamic RPC port (DCOM, always present) and inbound TCP 445 (SMB, only if output capture is on) — both from the operator's source IP |
| 11 (File Create) | The `__<timestamp>` output file being written — **only** if output capture is enabled. No equivalent event exists for `-nooutput`/`-silentcommand` sessions, since no file is ever created |
| 22 (DNS Query) | Not typically generated on the target itself for this tool |
| **Not generated** | Sysmon 13 (Registry Value Set) — no service key is created, so there's nothing here to log, unlike psexec |
| **Not generated** | Sysmon 17/18 (Pipe Created/Connected) tied to this tool's own protocol — wmiexec's execution channel rides DCE/RPC over TCP, not SMB named pipes, so there is no `RemCom_*`-style pipe signature to look for here |

## DCOM / RPC Detail

The execution channel is DCE/RPC over TCP, reached via the standard DCOM bootstrap sequence: a bind to the RPC endpoint mapper on **TCP 135**, which hands back a dynamically assigned high port for the actual `IWbemLevel1Login`/`IWbemServices` interface calls. This is architecturally different from psexec/smbexec, which do everything over a single SMB session (TCP 445) using named pipes for RPC transport (`\PIPE\svcctl`). A host-based or network view that only watches TCP 445 will **miss the execution channel entirely** for a `-nooutput`/`-silentcommand` wmiexec session — the DCOM/RPC connection on 135+dynamic-port is the one channel that's never optional.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | The RPC bind to the endpoint mapper and the subsequent operations against the WMI interface UUIDs — visible independent of host-based logging entirely. Full method-level decoding of `IWbemServices::ExecMethod` calls may require an additional Zeek WMI-decode script beyond the stock `dce_rpc` analyzer |
| Zeek `smb_files.log` / `smb_mapping.log` | Tree-connect to `ADMIN$` (or the `-share` target) followed by a tiny file write/read/delete matching the `__<timestamp>` pattern — **only present when output capture is enabled** |
| NetFlow / firewall logs | A short burst of TCP 135 + a dynamic high port (always), plus TCP 445 (conditionally) from one internal host to another — the 135+dynamic-port pairing without a corresponding 445 burst is itself a signature of a `-nooutput`/`-silentcommand` session |

## Endpoint Security Product Signatures

Because there is **no dropped executable to hash** in the default configuration, static file-signature detection — the primary mechanism most AV/EDR products use against `psexec.py` — largely **doesn't apply here**. Detection instead depends on behavioral heuristics: `WmiPrvSE.exe` spawning a command interpreter (or, for `-silentcommand`, spawning an unexpected process directly) shortly after a network-authenticated DCOM connection, AMSI/script-content scanning of the base64-decoded PowerShell payload when `-shell-type powershell` is used, and ETW consumption of the WMI-Activity provider. A target with a modern EDR product should generate a WMI-execution-specific behavioral alert independent of any hash match — the *absence* of such an alert on a host that otherwise shows the WMI-Activity 5857 / Sysmon 1 pattern is worth investigating on its own.

## Memory Forensics

`WmiPrvSE.exe` and its spawned child (`cmd.exe`, `powershell.exe`, or the raw command process) run as ordinary, non-hidden processes for their typically short lifetime — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing unusual about them structurally. Their forensic value in memory is recovering the **exact command line**, which for `-shell-type powershell` sessions means the plaintext, pre-decode command may be recoverable from `powershell.exe`'s process memory even if only the base64 blob was captured in Sysmon/4688. If PowerShell Script Block Logging (Microsoft-Windows-PowerShell/Operational Event ID **4104**) is enabled on the target, it independently decodes and logs the full script block content — a strong, memory-independent recovery path specific to the `-shell-type powershell` variant.

## Building a Timeline

The tightest, highest-confidence timeline anchor is: **4624 (Type 3, DCOM auth) → [4624 (Type 3, SMB auth), if output enabled] → WMI-Activity 5857 → Sysmon 1 (`WmiPrvSE.exe` → child process) → [Sysmon 11 File Create of `__<timestamp>`, if output enabled] → [SMB read + delete of that file] → repeat for each subsequent command → Security 4689 (process termination) → DCOM disconnect.** All of these typically land within a span of a few seconds to low minutes on a normal, uninterrupted run per command — a session with many rapid create/delete cycles against the *same* `__<timestamp>` filename is the signature of an active semi-interactive shell rather than a single one-shot command.

## Contrast with psexec.py / smbexec.py

> 🔴 **Why this matters for triage.** `wmiexec.py`'s own source-code header states it plainly: it avoids `smbexec.py`'s and `psexec.py`'s noisy service-creation event trail (System 7045/7036) specifically because it never touches the Service Control Manager at all. If you're triaging a host and find System 7045/7036 events tied to lateral movement, you're looking at `psexec.py` or `smbexec.py`, **not** `wmiexec.py` — this tool's fingerprint lives in the WMI-Activity Operational log and the `WmiPrvSE.exe` process-creation chain instead. Execution context is also the inverse: psexec/smbexec run as **SYSTEM** (service context); `wmiexec.py` runs as the **authenticating user**, which is itself a strong differentiator when reviewing which account a suspicious process ran under.

See `Windows/12 - Lateral Movement.md` for the broader PsExec-family comparison table (Impacket vs. Sysinternals vs. `wmiexec.py`/`smbexec.py`) and `Windows/10 - Persistence Mechanisms/Services.md` for general service-based execution artifacts this note deliberately doesn't re-derive.
