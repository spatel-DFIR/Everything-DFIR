# Atomic Red Team — Target Evidence

Set expectations correctly before anything else: **what a specific atomic test leaves behind is defined entirely by that test's own `command` field**, not by the framework. A `T1003.001-2` run leaves LSASS-dump evidence identical to any other `comsvcs.dll`/`MiniDump` use (already covered in `../Mimikatz/sekurlsa (Credential Dumping)/`); a `T1003.006` run leaves DCSync/DRSUAPI evidence identical to Mimikatz's own `lsadump::dcsync` (`../Mimikatz/lsadump (DCSync)/`); a Kerberoasting atomic leaves the same Event 4769/RC4 signature as `../Impacket/GetUserSPNs (Kerberoasting)/`. This file does **not** re-derive those 1,800+ individual technique footprints — it documents the **framework-level artifacts that are consistent regardless of which specific atomic ran**, which is this tool's actual original contribution to a target's evidence picture: a predictable, labeled audit layer sitting on top of whatever the underlying technique already does.

## Contents
- [Filesystem](#filesystem)
- [The Execution Log — the Framework's Signature Artifact](#the-execution-log--the-frameworks-signature-artifact)
- [Event Logs](#event-logs)
- [Sysmon](#sysmon)
- [PowerShell Remoting / WinRM (Remote-Session Case Only)](#powershell-remoting--winrm-remote-session-case-only)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Distinguishing Legitimate Exercise From Adversarial Reuse](#distinguishing-legitimate-exercise-from-adversarial-reuse)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | Path | Notes |
|---|---|---|
| Framework install | `C:\AtomicRedTeam\invoke-atomicredteam\` (Windows) / `~/AtomicRedTeam/invoke-atomicredteam` (Linux/macOS) | Default `Install-AtomicRedTeam` target; PowerShell-Gallery installs land in the standard module path instead (`$env:PSModulePath`) |
| Atomics library | `C:\AtomicRedTeam\atomics\` / `~/AtomicRedTeam/atomics` | Hundreds of `T*` folders, each with a `.yaml`, a generated `.md`, and (for tests with bundled payloads) a `src\` subfolder |
| Staged external payloads | `C:\AtomicRedTeam\ExternalPayloads\` (i.e. `atomics\..\ExternalPayloads\`) | Where `get_prereq_command`s drop fetched tools — ProcDump, Mimikatz, PsExec, NanoDump, Dumpert, etc., per the specific atomics run. **This directory existing and being populated is itself strong corroborating evidence** that `-GetPrereqs` ran at some point, even without an execution-log entry for the attack step itself |
| Execution log (default) | `$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv` (Windows) / `/tmp/Invoke-AtomicTest-ExecutionLog.csv` (Linux/macOS) | See the dedicated section below — the single highest-value framework artifact |
| Timeout marker files (**uncommon — read carefully**) | `$env:TEMP\art-out.txt` / `art-err.txt` (or `/tmp/...`) | **Verified directly in `Private/Invoke-Process.ps1`: these literal filenames are only ever written to disk if a test's process times out** (`-TimeoutSeconds`, default 120). In the normal, non-timing-out case, stdout/stderr are captured entirely in memory via .NET event-driven redirection and never touch disk. Do **not** treat `art-out.txt`/`art-err.txt` as a universal per-run artifact — their presence specifically indicates a test that ran past its timeout |
| Per-test artifacts | Whatever that specific `command`/`cleanup_command` creates | E.g. `C:\Windows\Temp\lsass_dump.dmp`/`$env:TEMP\lsass-comsvcs.dmp` for T1003.001, a `spawn` scheduled task's XML under `C:\Windows\System32\Tasks\` for T1053.005, `/tmp/T1087.001.txt` for the Linux account-discovery test — cross-reference the relevant technique-specific tool page in this repo or the `Windows/`/`Linux/`/`macOS/` artifact modules rather than expecting this page to enumerate all 1,800+ variants |

## The Execution Log — the Framework's Signature Artifact

Unless `-NoExecutionLog` is explicitly passed, **every genuine test execution** (not `-ShowDetails`/`-CheckPrereqs`/`-GetPrereqs`/`-Cleanup` — verified in `Public/Invoke-AtomicTest.ps1`: `Write-ExecutionLog` is only called from the final `else` branch, i.e. an actual attack-command run) appends one record. Four logger implementations ship with the framework, verified directly against `Public/*-ExecutionLogger.psm1`:

| Logger | Where it lands | Fields |
|---|---|---|
| `Default-ExecutionLogger` (default, no `-LoggingModule` needed) | CSV, `$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv` / `/tmp/...` | Execution Time (UTC), Execution Time (Local), Technique, Test Number, Test Name, Hostname, IP Address, Username, GUID, ProcessId, ExitCode |
| `WinEvent-ExecutionLogger` (opt-in, Windows only) | **A dedicated Windows Event Log channel literally named `Atomic Red Team`**, Event ID **3001** | Same fields plus `Tag` = `"atomicrunner"` and a configurable `CustomTag` |
| `Syslog-ExecutionLogger` (opt-in, or auto-selected if `config.ps1`'s `syslogServer`/`syslogPort` are set) | UDP/TCP/TCP+TLS to a configured syslog server, JSON-encoded | Same field set, `Tag`/`CustomTag` included |
| `Attire-ExecutionLogger` (opt-in, community-contributed by Security Risk Advisors) | JSON file, ATTIRE format v1.1, `Invoke-AtomicTest-ExecutionLog-<unixtime>.json` | Adds a base64-encoded execution ID and target user/host/IP/`$env:PATH` alongside a `procedures` array |

**Every one of these four formats includes the exact ATT&CK technique ID and test name at minimum.** This is the tool's defining target-side artifact: an analyst who finds any of the four doesn't need to reverse-engineer what happened — the tool already labeled it. The trade-off cuts both ways, exactly as the `01 - Overview.md` red-flag callout states: this is a gift when the log is present (instant, authoritative ground truth for correlation) and a strong signal when it's conspicuously **absent** relative to other evidence of the framework's use (`-NoExecutionLog` was used, or the CSV/event log was deliberately cleared) — either way, its state (present, absent, or tampered) is informative.

## Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **`Atomic Red Team` (custom channel)** | **3001** | Only present if `WinEvent-ExecutionLogger` was explicitly selected — see above. The single most specific, unambiguous artifact in this entire page when present |
| Security | 4688 (Process Creation) | `cmd.exe`/`powershell.exe`/`pwsh` child-process creation from the `Invoke-AtomicTest` parent, **with full command line only if** "Include command line in process creation events" is enabled (not default) |
| Security | 4624 / 4625, Logon Type 3 | For the remote-session case (`-Session`) — the WinRM logon on the target from the operator host |
| Microsoft-Windows-PowerShell/Operational | 4103 (Module Logging) | Records `Invoke-AtomicTest`/`Merge-InputArgs`/etc. being invoked with their parameter values, if Module Logging is enabled for the `invoke-atomicredteam` module (or `*`) |
| Microsoft-Windows-PowerShell/Operational | 4104 (Script Block Logging) | Captures the full text of any downloaded/`IEX`'d script content for download-cradle-style atomics (Invoke-Mimikatz, Invoke-Kerberoast, the install script itself) — frequently the richest single artifact for this class of test |
| Microsoft-Windows-WinRM/Operational | Various (session creation/command invocation) | Remote-session case only — WSMan provider activity on the **target** side corresponding to the staged `Invoke-Process.ps1`/`Invoke-KillProcessTree.ps1` push and the atomic's own remote invocation |
| Microsoft-Windows-TaskScheduler/Operational | 106 (Task Registered) | For any scheduled-task-based persistence atomic (e.g. T1053.005) — technique-specific, not framework-specific, listed here as a common example |

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | The `powershell.exe`/`pwsh` process running `Invoke-AtomicTest` (command line contains `Invoke-AtomicTest`, a technique ID, and possibly `-InputArgs`), and its child per the executor mapping — `cmd.exe /c ...`, a nested `powershell.exe`/`pwsh`, or `/bin/sh -c`/`/bin/bash -c` on non-Windows |
| 3 (Network Connection) | Outbound HTTPS to `raw.githubusercontent.com` / `api.github.com` (atomics or payload downloads, or the framework's own install cradle), `download.sysinternals.com` (ProcDump/PsExec `get_prereq_command`s), or PowerShell Gallery endpoints |
| 7 (Image Load) | Technique-dependent — e.g. `comsvcs.dll` loading into `rundll32.exe` for T1003.001's test #2, or `clr.dll`/`mscoree.dll` if a .NET payload (Mimikatz, NanoDump) is invoked |
| 11 (File Create) | `ExternalPayloads\` staging, per-test dump/output files, the default CSV execution log itself (first write creates it — `Test-Path`/`New-Item` in `Default-ExecutionLogger.psm1`) |
| 22 (DNS Query) | `raw.githubusercontent.com`, `github.com`, `download.sysinternals.com`, `www.powershellgallery.com` — a burst of these specific domains from a `powershell.exe` process is a reasonable ART-adjacent signal even before any specific technique is identified |

## PowerShell Remoting / WinRM (Remote-Session Case Only)

Only relevant when `-Session` targeted this host from elsewhere (see `03 - Source Evidence.md`'s Remote-Session section for the operator-side half of this picture):

- The staged helper scripts (`Invoke-Process.ps1`, `Invoke-KillProcessTree.ps1`) are pushed into the target's PSSession runspace via `Invoke-Command -FilePath` and never touch the target's disk as files — they exist only in the session's in-memory function table for the session's lifetime
- The actual atomic subprocess (`cmd.exe`/`powershell.exe`/`sh`/`bash`) is spawned **by the PSSession's own remote runspace process** (`wsmprovhost.exe` is the typical parent for WinRM-hosted PowerShell on the target) — a `wsmprovhost.exe` parent spawning `cmd.exe` or a nested `powershell.exe` is the process-tree signature to hunt, distinct from the parent process seen in local execution
- The execution log's `Hostname`/`Username` fields, if a logger is active, record the **target's own** identity (see `03 - Source Evidence.md`) — meaning if the log lands anywhere on the target itself (a non-default `-ExecutionLogPath` pointed locally, or the `WinEvent-ExecutionLogger`/local syslog-forwarder path), it is self-consistent target-side evidence, not a mismatched operator artifact

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `http.log` / `ssl.log` | TLS connections to `raw.githubusercontent.com`, `api.github.com`, `objects.githubusercontent.com` (release asset redirects), `download.sysinternals.com`, `www.powershellgallery.com` — the shared distribution infrastructure behind most `get_prereq_command`s and download-cradle atomics |
| Zeek `dce_rpc.log` / `smb_files.log` | Technique-dependent — e.g. T1003.006's DRSUAPI replication call (same signature as `../Mimikatz/lsadump (DCSync)/04 - Target Evidence.md`), or T1021.002's admin-share file copy |
| WinRM traffic (remote-session case) | TCP 5985/5986 between operator and target — standard PSRemoting network signature, not tool-specific |
| NetFlow / proxy logs | A host with no legitimate reason to reach GitHub's raw-content CDN doing so repeatedly in a tight window, especially followed by a burst of otherwise-unrelated process creations, is a reasonable network-only ART-adjacent indicator even without endpoint visibility |

## Endpoint Security Product Behavior

Atomic Red Team is the **most widely used purple-team validation library in the industry** — most mainstream EDR/AV vendors both (a) ship detection content explicitly validated against it, and (b) flag the framework's own installation footprint:

- The project's own wiki explicitly warns that the `atomics` folder "contains many files likely to trigger AV alerts on the endpoint" — meaning a fresh `Install-AtomicsFolder` run frequently gets partially quarantined before any test is ever fired, which is itself diagnostic (quarantine events referencing paths under `AtomicRedTeam\atomics\` or `ExternalPayloads\`)
- Because most individual atomics are themselves well-known technique implementations (Mimikatz, Rubeus, PsExec, comsvcs.dll, etc.), EDR behavioral/signature coverage for the **underlying technique** applies regardless of whether it was fired by hand or via `Invoke-AtomicTest` — the framework adds a labeled audit trail on top, it doesn't suppress the underlying technique's own detectability
- Several EDR vendors' detection-engineering teams publish content keyed specifically to the `Atomic Red Team` custom Event Log channel (Event ID 3001) as a coverage-validation signal in their own documentation — its presence in a customer environment is a known, expected artifact of legitimate purple-team practice, which is exactly why its presence *without* a corresponding scheduled exercise is worth escalating

## Memory Forensics

The framework's own code is unobfuscated PowerShell with no anti-analysis behavior — the forensic value of memory capture here is almost entirely about the **specific atomic's own payload**, not the framework:

- A `powershell.exe`/`pwsh` process with `Invoke-AtomicTest`/`Merge-InputArgs`/`Invoke-ExecuteCommand` function definitions loaded, if the module was imported reflectively rather than from disk
- Any download-cradle atomic's fetched-but-transient script content (Invoke-Mimikatz, Invoke-Kerberoast) — see `../Mimikatz/` and `../Impacket/GetUserSPNs (Kerberoasting)/` for what to look for once that specific payload is identified
- `$artConfig`'s `syslogServer`/`syslogPort` values, if populated, pointing an analyst at the SIEM-side copy of the execution-log evidence

## Distinguishing Legitimate Exercise From Adversarial Reuse

Every artifact on this page has a fully legitimate explanation — purple-team exercises, detection-engineering test-firing, and SOC tabletop rehearsals produce exactly this footprint by design. What separates legitimate use from adversarial reuse (the scenario in `02 - Hands-On Use Cases.md`'s "Adversarial Reuse" section) is **context, not the artifact itself**:

- Does a scheduled purple-team exercise, change-control ticket, or detection-engineering calendar entry exist for this host/window? If not, the same execution-log entry that would otherwise be routine becomes a strong indicator of unauthorized use
- Is `-NoExecutionLog` present in the recovered command line/script-block log, but the underlying technique's own evidence (a `.dmp` file, a DRSUAPI call, a new scheduled task) is present anyway? That combination — technique executed, audit trail deliberately suppressed — is a stronger adversarial signal than either fact alone
- Does the technique/test selection match a documented exercise scope (e.g. "we're validating Credential Access coverage this week"), or does it look like opportunistic, single-technique reuse matched to whatever the intruder actually needed at that moment (e.g. one LSASS-dump test fired in isolation, no broader sweep, no `-ShowDetails` review beforehand)?

## Building a Timeline

The execution log makes timeline-building for this tool unusually direct compared to most entries in this repo: **[execution-log entry — UTC timestamp, technique ID, test name, GUID]** → **[the Sysmon 1/Security 4688 process-creation event for the mapped executor, same host, same tight window]** → **[the technique-specific artifact the individual test's own `description` predicts — a dump file, a DRSUAPI call, a new scheduled task, cross-referenced against whichever tool page in this repo already documents that underlying technique]** → **[if `-Session` was used, the WinRM operational-log entries on both operator and target tying the two hosts together]**. Where the execution log is absent entirely, fall back to the process-tree and network-layer signals above — weaker individually, but a `powershell.exe`-parented `cmd.exe`/nested-`powershell.exe` child alongside a burst of GitHub-raw-content DNS queries is still a reasonable starting hypothesis worth testing against the rest of this page.
