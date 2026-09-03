# LOLBins — bitsadmin.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Network-Layer Hunting](#network-layer-hunting)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

`bitsadmin`'s abuse surface gives an operator several independent evasion knobs: renaming/relocating the binary, choosing `LOW` priority to blend into idle bandwidth, using SMB instead of HTTP(S) to avoid web-proxy visibility entirely, and — most importantly — the fact that the persistence payload never runs as a child of `bitsadmin.exe` at all. Rank hunts by what survives which:

| Rank | Signal | Survives binary rename/relocation? | Survives SMB-sourced (no HTTP) use? | Survives the delay between job creation and notify-command execution? | Notes |
|---|---|---|---|---|---|
| 1 (strongest) | BITS-Client Operational log (Event IDs 3/59/60/4/5) + QMGR queue database contents (including the configured `SetNotifyCmdLine`) | ✅ Yes — logged/stored by the BITS **service**, independent of what created the job or what it was named | ✅ Yes — the service logs job activity regardless of transport | ✅ Yes — the QMGR database holds the job's configuration from creation until it's cancelled/completed, so it's recoverable even if the notify command hasn't fired yet | The single most durable artifact class — recoverable even from a job that never executes its payload during the investigation window |
| 2 | A Sysmon 1 (Process Create) event with `ParentImage` = `svchost.exe` (BITS service host) and an unexpected child command line | ✅ Yes — the parent-process relationship doesn't depend on what `bitsadmin.exe` was named or where it ran from | ✅ Yes | ✅ Yes, once it fires — but by definition this signal doesn't exist until the notify command actually executes | **This is the signal that directly catches the persistence mechanic** — requires knowing to look at `svchost.exe`'s children, not `bitsadmin.exe`'s (which will have none) |
| 3 | Command-line argument shape (`/create`, `/addfile`, `/SetNotifyCmdLine`, `/resume`, `/transfer`) in Sysmon 1 or Security 4688 for the **initiating** `bitsadmin.exe` process | ✅ Yes — argument parsing is unaffected by binary rename | ✅ Yes | ❌ N/A — this only captures the creation moment, not the later execution | Requires Sysmon or 4688 command-line auditing deployed; without it, this rank is invisible |
| 4 | Proxy/firewall HTTP(S) request logs for the download-sourced variant | ❌ No independent evasion resistance — simply doesn't exist for the SMB-sourced variant | ❌ N/A — only applies to HTTP(S) jobs | N/A | No `bitsadmin`-specific User-Agent is verified to exist the way `certutil`'s is — weaker network signal than in that sibling entry |
| 5 | Image/file-path check: `bitsadmin`-shaped activity from anywhere other than `System32`/`SysWOW64` | ❌ No — defeats itself against the unmodified, in-place binary | ✅ Yes | ✅ Yes | Combine with Authenticode/`OriginalFileName` verification to catch a renamed-but-genuine binary specifically |
| 6 (weakest) | Bare `bitsadmin.exe` process-creation frequency/presence | ❌ No | ❌ No | ❌ No | Lower false-positive rate than `certutil.exe`'s equivalent (interactive `bitsadmin.exe` use is rarer than `certutil.exe` use on most estates, since deployment tools call the BITS API directly), but still not a finding on its own — never hunt on this alone |

**Build hunts on ranks 1-2 as primary detections — rank 1 is uniquely valuable because it's recoverable independent of process-creation logging and independent of whether the notify command has fired yet. Rank 2 is the only signal that directly proves the persistence mechanic rather than just the job's existence. Treat ranks 3-4 as strong corroborators. Treat ranks 5-6 as enrichment only.**

## Hunting on Source

Source-side hunting for this tool means pivoting through the infrastructure/tasking layer described in `03 - Source Evidence.md`, not an "operator machine" in the usual sense of this module:

```
# If attacker web-hosting infrastructure is ever recovered: grep access logs for
# requests matching a filename or timestamp already confirmed from target-side evidence
grep -E "beacon\.exe|stage2\.exe" access.log

# If C2 server task history is available (red-team retrospective, or recovered
# attacker infrastructure): search issued-command history for bitsadmin verbs
grep -iE "bitsadmin.*(/create|/addfile|/setnotifycmdline|/transfer|/resume)" c2_task_history.log
```

See this module's `Sliver/`, `PowerShell Empire/`, and other C2-framework folders for how each framework's own task-history logging is structured, rather than re-deriving it here.

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: enumerate every current BITS job and its notify-command
#    configuration directly via the BITS PowerShell module — works regardless of
#    whether bitsadmin.exe or the PowerShell cmdlets created the job
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
  Select-Object DisplayName, JobId, JobState, OwnerAccount, TransferType,
    @{n='NotifyCmdLine'; e={$_.NotifyCmdLine}}

# 2. BITS-Client operational log — job created / transfer initiated / completed / cancelled
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Bits-Client/Operational'; Id=3,4,5,59,60} -ErrorAction SilentlyContinue |
  Select-Object TimeCreated, Id, Message

# 3. RANK-2 SIGNAL: find child processes of the BITS service host that are NOT
#    part of the expected BITS-service process tree — this is what catches a
#    SetNotifyCmdLine payload actually firing
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'ParentImage:.*\\svchost\.exe' -and
    $_.Message -match 'ParentCommandLine:.*-s BITS'
  } |
  Select-Object TimeCreated,
    @{n='Image'; e={($_.Message -split "`n" | Select-String '^Image:').ToString()}},
    @{n='CommandLine'; e={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# 4. Command-line argument-shape hunt for the INITIATING bitsadmin.exe invocation —
#    survives a renamed/relocated binary since it matches on argument shape, not image name
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)/create|/addfile|/setnotifycmdline|/transfer\s' }

# 5. Same argument-shape hunt against native Security 4688, if Sysmon isn't deployed
#    but command-line auditing IS enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)/create|/addfile|/setnotifycmdline|/transfer\s' }

# 6. Path/location check: a bitsadmin-signed binary (by OriginalFileName/Authenticode)
#    running from anywhere other than the two legitimate install paths
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {
    $_.Message -match 'OriginalFileName:\s*BITSADMIN\.EXE' -and
    $_.Message -notmatch 'Image:.*\\(System32|SysWOW64)\\bitsadmin\.exe'
  }

# 7. Corroboration only — do NOT hunt on this alone (rank 6, weakest)
Get-Process -Name bitsadmin -ErrorAction SilentlyContinue
```

## Fleet-Wide Sweep

```powershell
# Run from a hunting workstation with rights across the estate. Because the persistence
# job may not have fired its notify command yet on any given host, this sweep checks BOTH
# the live job queue (Get-BitsTransfer) and the historical event log — a host with a
# suspicious job that hasn't executed yet is just as much a finding as one where it has.
$targets = Get-Content .\hosts.txt

$results = Invoke-Command -ComputerName $targets -ScriptBlock {
  $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
    Where-Object { $_.NotifyCmdLine -and $_.NotifyCmdLine -notmatch '^\s*$' }

  $bitsLogHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Bits-Client/Operational'; Id=3,59,60} -MaxEvents 200 -ErrorAction SilentlyContinue

  $sysmonHits = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '(?i)/create|/addfile|/setnotifycmdline|/transfer\s' }

  [PSCustomObject]@{
    Host                  = $env:COMPUTERNAME
    JobsWithNotifyCmdLine = ($jobs | Measure-Object).Count
    NotifyCmdLineSample   = ($jobs | Select-Object -First 1 -ExpandProperty NotifyCmdLine)
    BitsLogHitCount       = ($bitsLogHits | Measure-Object).Count
    BitsadminCmdHitCount  = ($sysmonHits | Measure-Object).Count
  }
} -ErrorAction SilentlyContinue

$results | Where-Object { $_.JobsWithNotifyCmdLine -gt 0 -or $_.BitsadminCmdHitCount -gt 0 } |
  Sort-Object JobsWithNotifyCmdLine -Descending

$results | Export-Csv -Path .\bitsadmin_sweep_results.csv -NoTypeInformation
```

## Network-Layer Hunting

For environments with a network sensor (Zeek, Suricata, proxy logs) — weaker in isolation for this tool than for `certutil.exe`, since no `bitsadmin`-specific User-Agent is verified, but still useful for the HTTP(S)-sourced variant and essential for catching the SMB-sourced variant that never touches a web proxy at all:

```
# Zeek: correlate HTTP(S) requests against a filename/timestamp already
# confirmed from a target-side BITS-Client log entry — no distinctive UA to
# filter on, so this is a targeted pivot, not a broad sweep
zeek-cut ts id.orig_h id.resp_h host uri < http.log | grep -F "<confirmed-filename>"

# Zeek smb_files.log: for the SMB-sourced variant, file reads against an
# internal share from hosts with no legitimate reason to reach it
zeek-cut ts id.orig_h id.resp_h name path < smb_files.log
```

## Remediation

**Capture evidence first** — export the job's full configuration via `Get-BitsTransfer` (especially `NotifyCmdLine`, `TransferType`, and `OwnerAccount`) and pull the corresponding BITS-Client Operational log entries **before** cancelling anything. Per `01 - Overview.md`, `/cancel` (and its PowerShell equivalent, `Remove-BitsTransfer`) **deletes all downloaded/partial files** — cancelling a job you haven't fully documented first destroys the payload evidence along with the job itself.

```powershell
# 1. Document every job with a configured notify command BEFORE touching anything
Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue |
  Where-Object { $_.NotifyCmdLine } |
  Select-Object DisplayName, JobId, JobState, OwnerAccount, NotifyCmdLine, FileList |
  Export-Csv -Path .\bits_jobs_before_remediation.csv -NoTypeInformation

# 2. If the downloaded file already landed at its local path, copy it to
#    quarantine BEFORE cancelling the job (cancel deletes it)
Copy-Item "<RecoveredLocalNamePath>" "C:\Quarantine\" -Force -ErrorAction SilentlyContinue

# 3. Now cancel/remove the malicious job(s) by JobId
Remove-BitsTransfer -BitsJob (Get-BitsTransfer -AllUsers | Where-Object { $_.JobId -eq "<JobGUID>" })

# 4. Kill a live bitsadmin.exe process if caught mid-execution
Get-Process -Name bitsadmin -ErrorAction SilentlyContinue | Stop-Process -Force

# 5. Block the source URL/domain/share at proxy/firewall/DNS or SMB access controls
```

Address whatever the downloaded/decoded payload actually was — a C2 agent, a ransomware stage, a credential stealer — using that payload's own dedicated tool folder in this module or the relevant `Windows/Threat Landscape and Playbooks/` playbook; this section covers only the `bitsadmin`/BITS delivery-and-persistence step itself.

Real hardening — beyond evidence capture:

- **Enable and forward the `Microsoft-Windows-Bits-Client/Operational` log** — per `04 - Target Evidence.md`, this is the rank-1 signal and it isn't always enabled or centrally collected by default; without it, an investigator is limited to whatever Sysmon/4688 process-creation telemetry happens to be configured.
- **Alert on `svchost.exe -k netsvcs -s BITS` spawning an unexpected child process** — this is the rank-2 signal that directly catches the persistence mechanic, and it's rarely covered by generic "suspicious LOLBIN command line" detections that only look at `bitsadmin.exe`'s own arguments.
- **Constrain `bitsadmin.exe` via AppLocker/WDAC** on hosts with no legitimate need for the interactive CLI — since Windows Update/WSUS/SCCM call the BITS API directly rather than shelling out to `bitsadmin.exe`, most endpoints in most estates have no legitimate reason to run this binary interactively at all.
- **Alert on the argument shape and the notify-command target, not the binary name** — a detection keyed only on `Image` = `bitsadmin.exe` is defeated by the renamed-binary variant in `02 - Hands-On Use Cases.md`; a detection keyed only on the initiating command line misses jobs created weeks earlier whose notify command only fires later.
- **Periodically audit the live BITS job queue fleet-wide** (`Get-BitsTransfer -AllUsers`) for any `NotifyCmdLine` value pointed at a script interpreter, `cmd.exe`, or a non-standard path — per the Fleet-Wide Sweep above, this catches persistence jobs that haven't executed yet, which event-log-only hunting cannot.
- **Consider tightening the `JobInactivityTimeout` Group Policy** (`HKLM\Software\Policies\Microsoft\Windows\BITS`, verified in `04 - Target Evidence.md`) below its 90-day default on estates where that ceiling represents an unacceptably long persistence window — a real, if blunt, hardening lever unique to this tool's abuse model.
