# Seatbelt — Source Evidence

Seatbelt has an unusual "source" story compared to most tools in this repo. In its **most common real-world use** — reflectively loaded in-memory by a C2 loader and run against the host the operator is *already* standing on — there is no second host at all: the machine running Seatbelt **is** the target, and the meaningful "source-side" evidence is actually the **C2/loader-side** telemetry of the module being tasked and executed, not a distinct attacking machine. Seatbelt only produces a genuine second, distinct source host in the **remote-enumeration case** (`-computername=`), where an operator/foothold host queries a second target purely over WMI. This file covers both.

## Contents
- [Loader-Side Evidence (In-Memory / Local Execution — the Common Case)](#loader-side-evidence-in-memory--local-execution--the-common-case)
- [Standalone-Binary Source Evidence](#standalone-binary-source-evidence)
- [Remote-Enumeration Case — Genuine Operator/Foothold-Host Evidence](#remote-enumeration-case--genuine-operatorfoothold-host-evidence)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Loader-Side Evidence (In-Memory / Local Execution — the Common Case)

When Seatbelt is reflectively loaded by a C2 loader's "execute .NET assembly" capability (see `02 - Hands-On Use Cases.md`'s "In-Memory Execution via a C2 Loader"), the strongest evidence isn't on the compromised host at all — it's in the **operator's own C2 tooling**:

| Loader | Verified artifact |
|---|---|
| Meterpreter (`post/windows/manage/execute_dotnet_assembly`) | The module writes captured output to a log file on the **attacking/operator** machine, verified directly in source: `Msf::Config.log_directory` (default `~/.msf4/logs`) `+ "/dotnet/log_<assembly-basename>_<YYYYMMDDHHMMSS>"` — e.g. `~/.msf4/logs/dotnet/log_Seatbelt.exe_20260802143011`. This file contains Seatbelt's **complete captured stdout**, giving an incident responder with access to the operator's own Metasploit instance a full record of exactly what was enumerated and when |
| Cobalt Strike | `execute-assembly` tasking and the assembly's captured output are recorded in the team server's own logs/event log and Beacon log files — exact file layout is Cobalt Strike's own (closed-source) implementation and not verified against source in this session; treat as present but unconfirmed in specifics |
| Sliver | The client console records `execute-assembly` command invocations and captured implant output in its own session history/event log — exact on-disk format not verified against source in this session |

Where any of these logs are recoverable (operator infrastructure seizure, a red-team's own after-action review, or an MSSP/purple-team engagement with access to both sides), they are the single most complete record of a Seatbelt run — better than anything recoverable from the compromised host itself, since the host-side footprint is deliberately minimal (see `04 - Target Evidence.md`).

## Standalone-Binary Source Evidence

If `Seatbelt.exe` is dropped and run directly rather than reflectively loaded (less common, but happens — e.g. an operator without loader tooling, or a script-kiddie reuse of a leaked/public build), the "source" artifacts are just the ordinary drop-and-execute footprint on that same host:

| Artifact | Notes |
|---|---|
| The binary itself | No canonical hash exists — the project explicitly ships no prebuilt binaries ("We are not planning on releasing binaries for Seatbelt" — README), so every real-world sample is either operator-compiled or redistributed by a third party. Hash-based detection is unreliable; behavior/string-based detection (see `05 - Detection and Hunting.md`) is the durable signal |
| `-outputfile=` target, if used | A flat `.txt`, structured `.json`, or (only for `jsonstring`) no file at all — a text/JSON file matching Seatbelt's known field names (`Command`, `Description`, per-check DTO property names) sitting alongside the binary is a strong corroborating artifact |
| Shell/console history | If launched interactively from `cmd.exe` or PowerShell rather than by a loader, the invocation line (full command including `-group=`, `-full`, any `-computername=`/`-username=`/`-password=` values) lands in PowerShell's `ConsoleHost_history.txt` or is simply visible in a live console session — the same significant OPSEC exposure noted below applies here too if remote credentials were passed |

## Remote-Enumeration Case — Genuine Operator/Foothold-Host Evidence

Only when `-computername=` is used does Seatbelt produce a real, distinct source host — the machine `Seatbelt.exe` (standalone or loader-hosted) is actually running on, reaching out to a **second** target over WMI.

```bash
# Process check (if standalone)
tasklist | findstr /i seatbelt

# Outbound network state — RPC Endpoint Mapper + the dynamic DCOM port
# negotiated for the WMI session
netstat -ano | findstr :135
```

**The single most significant source-side artifact in this entire tool: `-username=`/`-password=` are plaintext command-line arguments.** Any process-command-line auditing on the source host (Sysmon Event ID 1, Security Event ID 4688 with command-line logging enabled) captures the full remote credential in cleartext the moment `-computername=` is combined with explicit alternate credentials — this is true regardless of which loader or execution method was used, since the argument string is passed to and parsed by `SeatbeltArgumentParser` either way. An operator relying on the current token (no `-username=`/`-password=`) avoids this specific exposure entirely.

| Artifact | Notes |
|---|---|
| Shell/console history | Full command line including `-computername=`, and critically `-username=`/`-password=` if used |
| Process command-line logging | Sysmon 1 / Security 4688 on the source host, if command-line auditing is enabled there — captures everything, including credentials |
| Outbound network connections | To the target's TCP 135 (RPC Endpoint Mapper) and the subsequently negotiated dynamic DCOM port — visible in `netstat`, or via the source host's own EDR network telemetry |

## Memory Forensics

Because the standalone binary ships no canonical hash, and in-memory/loader-hosted execution never touches disk at all, **memory capture of a still-running process is disproportionately valuable** here compared to disk forensics. A process (the loader's own process, or a standalone `Seatbelt.exe`) with a loaded assembly matching Seatbelt's distinctive internals is identifiable by:

- The assembly/type namespace `Seatbelt.Commands.*` and the dozens of concrete `*Command` class names (`AntiVirusCommand`, `CloudCredentialsCommand`, `AutoRunsCommand`, etc.) — a large, distinctive set of type names unlikely to appear together in any legitimate application
- The version constant string `"1.2.2"` embedded in `Seatbelt.cs`, alongside the ASCII-art banner text (which itself still reads `v1.2.1` in the README's own usage example — both strings are worth searching for, they may not match on a given build)
- Command-line argument strings matching Seatbelt's specific flag vocabulary (`-group=`, `-outputfile=`, `-computername=`, `-delaycommands=`) present in the hosting process's memory even when execution was in-memory/reflective and no `Seatbelt.exe` process ever existed as such

## Timeline Correlation Value

Because Seatbelt's own on-host footprint is deliberately minimal (it's a read-only tool — see `04 - Target Evidence.md`), the real timeline value comes from correlating **loader/C2-side task timestamps** (when was `execute-assembly`/`execute_dotnet_assembly` tasked, and when did output return) against whatever sparse target-side signal exists (a WMI-Activity Operational log entry, an unexpected `notepad.exe` process hosting the CLR under Meterpreter's `SPAWN_AND_INJECT` technique, or the C2 implant's own already-anomalous process). A source-side task timestamp that lines up tightly with a target-side WMI provider-load event is what turns "Seatbelt ran somewhere in this environment" into a specific, provable host-and-time pairing — the same evidentiary logic `Responder/03 - Source Evidence.md` and `Impacket/psexec/03 - Source Evidence.md` use, applied here to a tool whose target-side footprint is unusually thin by design.
