# Atomic Red Team — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal Survives Which Evasion Option](#hunting-priority--which-signal-survives-which-evasion-option)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal Survives Which Evasion Option

Atomic Red Team exposes several operator/attacker choices that materially change its footprint: `-NoExecutionLog` (removes the CSV/Event-Log/syslog/ATTIRE audit trail entirely — a single flag, verified in `Public/Invoke-AtomicTest.ps1`), `-Session` (moves the actual attack subprocess onto the target, thinning the operator-side footprint — see `03 - Source Evidence.md`), authoring/running a **custom private atomic** (bypasses any detection content keyed to the exact literal command text of a *public*-library test), and — the ceiling case — **copying a test's command by hand and running it without `Invoke-AtomicTest` at all**, which defeats every framework-specific artifact on this page while leaving the underlying technique's own evidence completely untouched. Rank hunts accordingly — signals tied to the *technique* survive everything; signals tied to the *framework* survive only some of these:

| Rank | Signal | Survives `-NoExecutionLog`? | Survives `-Session` (evaluated on the **operator** host)? | Survives manual copy-paste without `Invoke-AtomicTest`? |
|---|---|---|---|---|
| 1 (strongest) | The specific atomic's own underlying technique artifact (per that test's `command` — an LSASS dump file, a DRSUAPI DCSync call, a new scheduled task, etc.) | ✅ Yes — entirely independent of the framework's logging | ✅ Yes — the technique still executes wherever the subprocess actually runs | ✅ Yes — this is the technique itself, not a framework artifact |
| 2 | Process-tree signature: a `powershell.exe`/`pwsh` parent whose command line contains `Invoke-AtomicTest`, spawning `cmd.exe`, a nested `powershell.exe`/`pwsh`, or `sh`/`bash` per the executor mapping | ✅ Yes | ⚠️ **Partial** — on the target, the parent becomes `wsmprovhost.exe` (WinRM-hosted), not a `powershell.exe` bearing `Invoke-AtomicTest` in its own command line; the operator-side parent process never existed there at all | ❌ **No** — there is no `Invoke-AtomicTest` parent if the command was typed/pasted directly |
| 3 | Execution log (CSV / `Atomic Red Team` Event ID 3001 / syslog / ATTIRE JSON) naming the exact technique ID, test name, and GUID | ❌ **No** — this is precisely what `-NoExecutionLog` removes | ✅ Yes, if a logger is active — though the `Hostname`/`Username` fields describe the **target**, not the operator, even when the file lands on the operator's disk (see `03 - Source Evidence.md`) | ❌ **No** — the log is written by `Invoke-AtomicTest` itself; bypassing the framework bypasses the log |
| 4 | Network/DNS burst to `raw.githubusercontent.com`/`api.github.com`/`download.sysinternals.com`/PowerShell-Gallery endpoints | ✅ Yes | N/A — only applies to whichever host actually performs the fetch (target, in the `-Session` case) | ⚠️ **Partial** — only if the copy-pasted command itself still includes a download step (many do; a locally-staged payload wouldn't) |
| 5 (weakest) | Filesystem footprint of the framework install (`AtomicRedTeam\invoke-atomicredteam\`, `AtomicRedTeam\atomics\`, `ExternalPayloads\`) | ✅ Yes — pre-execution artifact, unaffected by any run-time flag | N/A — describes wherever the framework was installed, not execution | ❌ **No** — hand-copying one command needs none of this on disk |

**Build hunts on rank 1 first — hunt the technique, using this repo's other tool pages (`../Mimikatz/`, `../Impacket/`, `../BloodHound/`, etc.) for the specific artifact each underlying technique produces — since it's the only signal every evasion option in this table leaves untouched.** Ranks 2-3 are what actually make Atomic Red Team *usage specifically* identifiable (versus the same technique run by hand or by a different tool), and are the layer worth prioritizing in an environment where legitimate purple-team exercises are expected and need to be distinguished from unauthorized reuse.

## Hunting on Source

Meaningful for the operator's own PowerShell session (local case) or the genuine second host in the remote-session case — see `03 - Source Evidence.md` for why local execution means "source" and "target" are usually the same box.

```powershell
# Command history for the framework's own invocation pattern, including any
# InputArgs values that may carry real target account/domain names
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
  Select-String -Pattern 'Invoke-AtomicTest|Invoke-AtomicRunner|Install-AtomicRedTeam|Install-AtomicsFolder'

# Script-block log entries for the framework's own install cradle or any
# download-cradle atomic's fetched content — HIGH VALUE, often the only
# recoverable copy of a payload that never touched disk
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -MaxEvents 2000 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Invoke-AtomicTest|invoke-atomicredteam|redcanaryco|Invoke-Kerberoast|Invoke-Mimikatz' }

# Presence of the framework/library on disk — rank 5 signal, but a fast
# first check
Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam', 'C:\AtomicRedTeam\atomics', 'C:\AtomicRedTeam\ExternalPayloads'

# Outbound PSSession creation — the remote-session case only
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'} -MaxEvents 500 -ErrorAction SilentlyContinue

# The operator's own local execution log, if a logger wrote here — treat
# Hostname/Username fields as describing the TARGET when -Session was used
Import-Csv "$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv" -ErrorAction SilentlyContinue |
  Select-Object 'Execution Time (UTC)', Technique, 'Test Name', Hostname, Username, GUID
```

## Hunting on Target

```powershell
# 1. The framework's own dedicated Windows Event Log channel — HIGHEST
#    CONFIDENCE single signal when present (rank 3, but unambiguous:
#    nothing else writes to a channel named "Atomic Red Team")
Get-WinEvent -LogName 'Atomic Red Team' -ErrorAction SilentlyContinue |
  Where-Object { $_.Id -eq 3001 } |
  Select-Object TimeCreated, Message

# 2. Process creation for the framework's parent/child pattern (rank 2) —
#    catches local execution AND a WinRM-hosted target-side run
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 5000 -ErrorAction SilentlyContinue |
  Where-Object {
    $_.Message -match 'Invoke-AtomicTest' -or
    ($_.Message -match 'ParentImage.*(powershell\.exe|wsmprovhost\.exe)' -and $_.Message -match 'CommandLine.*(T[0-9]{4}(\.[0-9]{3})?)')
  }

# 3. Security 4688, if command-line auditing is enabled — same pattern,
#    native-log fallback where Sysmon isn't deployed
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 5000 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'Invoke-AtomicTest|T[0-9]{4}\.[0-9]{3}' }

# 4. The default CSV execution log, if it landed locally on this host —
#    parses directly into the exact technique/test/GUID that ran
Import-Csv "$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv" -ErrorAction SilentlyContinue

# 5. Filesystem footprint (rank 5) — install directory, staged payloads,
#    and the timeout-only marker files (present ONLY if a test timed out —
#    see 04 - Target Evidence.md, do not expect these on every run)
Get-ChildItem 'C:\AtomicRedTeam\ExternalPayloads' -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, CreationTime, LastWriteTime
Get-ChildItem "$env:TEMP\art-out.txt", "$env:TEMP\art-err.txt" -ErrorAction SilentlyContinue

# 6. DNS/network burst to the shared distribution infrastructure behind
#    most get_prereq_commands and download-cradle atomics (rank 4)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=22} -MaxEvents 2000 -ErrorAction SilentlyContinue |
  Where-Object { $_.Message -match 'raw\.githubusercontent\.com|download\.sysinternals\.com|powershellgallery\.com' }
```

## Fleet-Wide Sweep

```powershell
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
    [PSCustomObject]@{
        Host                = $env:COMPUTERNAME
        FrameworkInstalled  = Test-Path 'C:\AtomicRedTeam\invoke-atomicredteam'
        AtomicsInstalled    = Test-Path 'C:\AtomicRedTeam\atomics'
        ExecLogExists       = Test-Path "$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv"
        CustomEventLogExists = [bool](Get-WinEvent -ListLog 'Atomic Red Team' -ErrorAction SilentlyContinue)
        LastExecLogWrite    = if (Test-Path "$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv") {
                                 (Get-Item "$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv").LastWriteTime
                               } else { $null }
    }
} -ErrorAction SilentlyContinue

# Hosts showing the framework's footprint with NO scheduled purple-team
# exercise on record for that window are the ones to escalate first
$results | Where-Object { $_.FrameworkInstalled -or $_.ExecLogExists -or $_.CustomEventLogExists } |
  Sort-Object LastExecLogWrite -Descending

$results | Export-Csv -Path .\atomic_red_team_sweep.csv -NoTypeInformation
```

## Remediation

**Capture evidence first** — pull the execution log (CSV/Event ID 3001/ATTIRE JSON, whichever exists), the relevant Sysmon 1/4104 events, and the `ExternalPayloads\` directory listing before removing the framework or killing a running test, since the execution log in particular is the one artifact that turns "something technique-shaped happened" into "this exact labeled test ran, at this exact time, on this exact host" — destroying it first throws away the strongest available evidence.

Atomic Red Team itself isn't the thing to fix — it's a legitimate, widely-adopted validation tool, and its presence is *expected* in any environment running a real purple-team program. The response differs by finding:

```powershell
# If this IS an authorized exercise: confirm against the change-control /
# exercise calendar before treating any of the signals above as an incident.
# This is the single highest-leverage step — most "Atomic Red Team detected"
# alerts in a mature program are false positives against a scheduled test.

# If this is NOT authorized: the framework's own artifacts (rank 2-3 above)
# only get you to "someone ran Invoke-AtomicTest" — pivot immediately to
# rank-1 hunting for the SPECIFIC underlying technique(s) the execution log
# or process tree names, using this repo's per-technique tool pages
# (Mimikatz/, Impacket/, BloodHound/, etc.) for the deeper target-side
# evidence and remediation steps that technique itself requires.

# Compensating controls that materially improve coverage against this
# tool class specifically:
# - PowerShell Script Block Logging (4104) + Module Logging (4103), since
#   several atomics are download-cradle-shaped and 4104 recovers content
#   that never touches disk
# - Command-line auditing on process creation (Security 4688 / Sysmon 1),
#   not enabled by default — the rank-2 process-tree signal depends on it
# - Restrict/monitor outbound access to raw.githubusercontent.com,
#   api.github.com, and the PowerShell Gallery from hosts with no
#   legitimate reason to reach them (rank-4 signal, and it also blocks
#   the framework's own IEX/IWR install cradle on unauthorized hosts)
# - If WinEvent-ExecutionLogger or a syslog sink is part of your own
#   purple-team tooling, forward the "Atomic Red Team" channel / syslog
#   feed into the SIEM as a first-class expected-activity source, so its
#   absence during a claimed exercise (or presence outside one) is itself
#   an alertable condition
```

Enabling Script Block Logging and command-line process-creation auditing where they aren't already deployed is the single highest-leverage step from this note's perspective — both are off by default, and both are exactly what the rank-2/rank-4 signals in the priority table above depend on.
