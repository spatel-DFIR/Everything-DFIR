# Atomic Red Team — Source Evidence

Atomic Red Team has an unusual source/target relationship, worth stating up front: in its **overwhelmingly common use** — an operator running `Invoke-AtomicTest` directly on the box being validated — **there is no second host at all.** The machine running the framework **is** the target; "source-side" evidence here means the operator's own PowerShell session/host artifacts on that same machine, not a distinct attacking box. A genuine second, distinct source host only exists in the **remote-execution case** (`-Session`), and even then the actual attack subprocess (`cmd.exe`/`powershell.exe`/`sh`/`bash`) is spawned **inside the target's own PSSession runspace**, verified directly in `Private/Invoke-ExecuteCommand.ps1` — meaning almost all process-level evidence still lands on the target, not the operator's box, even in the remote case. This file covers both.

## Contents
- [Local Execution — the Common Case](#local-execution--the-common-case)
- [Installation Footprint](#installation-footprint)
- [Remote-Session Case — Genuine Operator/Foothold-Host Evidence](#remote-session-case--genuine-operatorfoothold-host-evidence)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Local Execution — the Common Case

When `Invoke-AtomicTest` runs against the local host (no `-Session`), the "source" artifacts are simply the operator's own PowerShell session footprint on the box that is also the target:

| Artifact | Notes |
|---|---|
| PowerShell console/command history | `(Get-PSReadlineOption).HistorySavePath` — by default `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — captures the **full invocation line**, including `-InputArgs` values, `-PathToAtomicsFolder`, and any `-TestGuids`/`-TestNumbers` used. If `-InputArgs` carried a real target username/domain (as in `../02 - Hands-On Use Cases.md`'s DCSync example), that value is now sitting in plaintext history |
| Parent process | The `powershell.exe`/`pwsh` process hosting `Invoke-AtomicTest` itself — spawns the per-test child process (`cmd.exe`, a second `powershell.exe`/`pwsh`, `/bin/sh`, or `/bin/bash`) as documented in `01 - Overview.md`'s executor table. This parent-child relationship (a `powershell.exe` whose command line contains `Invoke-AtomicTest`, spawning `cmd.exe /c` or a nested `powershell.exe`) is itself a distinctive process-tree signature, independent of which specific test ran |
| PowerShell script-block logging | Event ID 4104 (`Microsoft-Windows-PowerShell/Operational`), if enabled — captures the **actual script block text**, meaning for any test whose command is itself a download cradle (e.g. T1059.001's `IEX (New-Object Net.WebClient).DownloadString(...)`, T1558.003's `iex(iwr .../Invoke-Kerberoast.ps1)`), 4104 can capture the **downloaded script's own content** at execution time, not just the outer `Invoke-AtomicTest` call. This is frequently the single richest recoverable artifact for any atomic that fetches a remote payload |
| Module import | `Import-Module ...\Invoke-AtomicRedTeam.psd1` (or `Install-Module invoke-atomicredteam` leaving an entry in the PowerShell Gallery's local package cache / `$env:PSModulePath`) — evidence the framework was ever present on the host, independent of any specific test having run |
| Network state (only if the specific test downloads something) | Outbound HTTPS to GitHub raw-content URLs (`raw.githubusercontent.com`), the PowerShell Gallery, or Sysinternals' download CDN — not from the framework itself, but from whichever atomic's `command` or `get_prereq_command` reaches out (ProcDump, Mimikatz, PsExec, Empire's Invoke-Kerberoast, etc. — see `02 - Hands-On Use Cases.md`) |

**The execution log itself is both source- and target-side evidence in the local case**, since they're the same host — see `04 - Target Evidence.md` for the full CSV/Windows-Event-Log/syslog artifact breakdown; it's the single strongest artifact this tool leaves behind regardless of which "side" you're analyzing.

## Installation Footprint

Distinct from any individual test run, the framework's own install method leaves a recognizable pattern:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics
```

This is a textbook `IEX`/`IWR` download-cradle — the same shape defenders are trained to flag regardless of what's actually inside it — and it's the project's **own documented, first-party install method** for anyone not using the PowerShell Gallery. Script-block logging (4104) captures the full cradle text; process-creation logging (Sysmon 1 / Security 4688) shows `powershell.exe` reaching out to `raw.githubusercontent.com` at the moment of install. The resulting `C:\AtomicRedTeam\` (or `~/AtomicRedTeam` on Linux/macOS) directory tree — `invoke-atomicredteam\` (the module) plus, if `-getAtomics` was used, `atomics\` (hundreds of YAML files and, unless `-noPayloads` was passed, cached binaries under per-technique `src\` folders and a shared `ExternalPayloads\`) — is a durable filesystem artifact independent of whether any test has actually been run yet.

## Remote-Session Case — Genuine Operator/Foothold-Host Evidence

Only when `-Session` is used does a real, distinct operator/foothold host exist — verified directly in `Private/Get-TargetInfo.ps1` and `Private/Invoke-ExecuteCommand.ps1`:

```powershell
$session = New-PSSession -ComputerName TARGET01.CORP.LOCAL -Credential $cred
Invoke-AtomicTest T1082 -Session $session
```

| Artifact | Notes |
|---|---|
| `PSSession` creation | `New-PSSession`/`Enter-PSSession` invocation in the operator's own PowerShell history and script-block log — the WinRM connection itself, distinct from anything the atomic test does |
| WinRM client-side network state | Outbound TCP 5985 (HTTP) or 5986 (HTTPS) from the operator host to the target — visible via `Get-NetTCPConnection`/`netstat` on the operator's own box |
| Staged helper scripts | Before the atomic ever runs, the framework pushes `Invoke-Process.ps1` and `Invoke-KillProcessTree.ps1` into the **target's** remote runspace via `Invoke-Command -Session ... -FilePath` — this is a one-time, session-scoped push; it doesn't persist as a file on either host, but the `Invoke-Command -FilePath` call itself is a distinctive PSRemoting operation recorded in both endpoints' WinRM operational logs |
| **The execution log's own hostname/username fields point at the TARGET, not the operator** | Verified in `Get-TargetInfo.ps1`: when `-Session` is set, `hostname`/`whoami` are run **inside the session** (i.e., against the target), and those values — not the operator's own hostname/username — populate the `Hostname`/`Username` columns of the execution-log row. Critically, `-ExecutionLogPath` still defaults to a **local** path on the operator's own disk. Net effect: the operator's own machine ends up holding a CSV (or JSON/syslog record) that is effectively a call log of *which remote targets were hit, when, with which technique* — a single artifact of significant forensic value if the operator's own infrastructure is ever seized or reviewed (the same evidentiary logic `Seatbelt/03 - Source Evidence.md` uses for Meterpreter's own operator-side log files) |
| Attack subprocess itself | Spawns **on the target**, inside the PSSession's remote runspace — not on the operator's box. All the process-creation/registry/filesystem evidence in `04 - Target Evidence.md` applies to the target host even in this remote-execution case |

## Memory Forensics

The framework itself is ordinary, unobfuscated PowerShell — there is no packing, no reflective loading, no anti-analysis behavior in `invoke-atomicredteam`'s own code. Memory capture of a still-running `powershell.exe`/`pwsh` host process is valuable primarily for:

- Recovering the **loaded function definitions** (`Invoke-AtomicTest`, `Merge-InputArgs`, `Invoke-ExecuteCommand`, etc.) if the module was imported reflectively (`IEX (IWR ...)` piping module content directly into the session rather than `Import-Module` from disk) — these function names and their distinctive parameter sets (`-TestGuids`, `-PathToAtomicsFolder`, `-SupressPathToAtomicsFolder`) are a strong fingerprint even absent any file on disk
- Recovering a **downloaded-but-not-yet-executed or already-executed remote script** for any download-cradle-style atomic (Invoke-Mimikatz, Invoke-Kerberoast, etc.) that never touched disk — the same "in-memory PowerShell tradecraft" forensic angle covered generally in this repo's `../Mimikatz/` and `../Impacket/` pages, here specifically triggered by the atomic's own `command` field rather than a separate operator choice
- `$artConfig` (the framework's loaded configuration object, `Public/config.ps1`) sitting in the process's PowerShell runspace — if populated, its `syslogServer`/`syslogPort` fields reveal where execution telemetry was being shipped, useful for an analyst trying to locate the SIEM-side copy of the same evidence

## Timeline Correlation Value

Because the execution-log entry (CSV row, Event ID 3001, syslog message, or ATTIRE JSON procedure — see `04 - Target Evidence.md` and `05 - Detection and Hunting.md`) carries an explicit UTC **and** local timestamp plus the exact technique/test/GUID that ran, it is unusually strong ground truth for timeline-building compared to most tools in this repo — most attacker tooling requires *inferring* what happened from indirect artifacts; Atomic Red Team, run as designed, tells you outright. The correlation exercise is straightforward: **[execution-log timestamp + technique ID]** → **[the specific process-creation/registry/network event that technique's own `command` field predicts, per `04 - Target Evidence.md`]** → **[the downstream detection or alert, if any, in the same window]**. A wide gap between the logged execution time and the corresponding process-creation event is either clock skew (normalize both to UTC) or evidence the execution log was tampered with/disabled (`-NoExecutionLog`) for that specific run — itself a meaningful finding, since it means whoever ran the test deliberately suppressed the tool's own audit trail.
