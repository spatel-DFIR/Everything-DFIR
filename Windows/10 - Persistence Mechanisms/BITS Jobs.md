# BITS Jobs

The Background Intelligent Transfer Service (BITS) is a Windows service originally built to make Windows Update, WSUS, and other Microsoft download traffic resumable and bandwidth-throttled — a transfer can survive a network drop, a reboot, or a user logging off, and it politely yields bandwidth to whatever else is happening on the network. That functionality is exposed to anyone on the host through `bitsadmin.exe` (deprecated since Windows 7/Server 2008 R2 but still present and fully functional on every supported version of Windows) and through the `BitsTransfer` PowerShell module, and it requires no special privilege beyond the calling user's own — no admin rights needed to queue a job that runs in that user's context.

What makes BITS attractive well beyond its file-transfer role is a single feature: a BITS job can be configured with a *notify command line* — a command line that the BITS service itself launches when the job transitions into a completed, error, or (with modern acknowledgment/reply support) modified state. That single property turns BITS into a triggered code-execution primitive that lives entirely outside Task Scheduler and outside the Run-key family — a job can sit dormant in the BITS queue for its full lifetime (90 days by default, and extendable) and fire its notify command line on completion, on error, or after a reboot resumes an interrupted transfer, with no scheduled-task XML, no registry autostart value, and no new file dropped anywhere obvious. Analysts who triage "the usual" autostart locations — Run keys, services, scheduled tasks — walk straight past this one unless they specifically think to check the BITS queue.

Like Services and Scheduled Tasks earlier in this family, BITS legitimately occupies two roles here and this note touches both, briefly. On the download side, a BITS job is an attractive way to stage a malicious payload: the transfer is resumable and throttled exactly like legitimate Windows Update traffic, and it can blend into network monitoring that already expects to see BITS-attributed connections. On the execution side, the notify command line is the actual trigger/persistence mechanism — the thing that turns "a file got downloaded" into "code ran." Full C2/download-mechanics analysis (how attackers use BITS for staged payload delivery, exfiltration via `BITS_JOB_TYPE_UPLOAD`, and the network-traffic side of detection) belongs in a future Command and Control or Exfiltration note; this note stays on the host-artifact and persistence angle.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing BITS Jobs against Run Keys, Services, Scheduled Tasks, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A BITS job is only as suspicious as its remote URL, its owning process, and its notify command line.** BITS legitimately carries Windows Update, Microsoft Store, and a wide range of vendor-update traffic at any given moment — the finding is never "a BITS job exists," it's "this job's notify command line launches something unexpected, this job's target URL doesn't belong to any known update channel, or this job was created by a process that has no business calling the BITS API."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Where BITS Job State Lives](#where-bits-job-state-lives)
- [The Notify Command Line — The Execution Primitive](#the-notify-command-line--the-execution-primitive)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to BITS Jobs](#red-flags-specific-to-bits-jobs)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, module-only triage using the built-in `BitsTransfer` PowerShell module — the reliable live-enumeration path regardless of what the underlying queue-storage format happens to be on that OS build.

```powershell
# Every BITS job for every user, with owner, state, and transfer size in one pass (requires admin for -AllUsers)
Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobId, JobState, OwnerAccount, TransferType, BytesTotal, BytesTransferred

# Jobs sitting in a non-terminal state for an unusually long time - the "still queued weeks later" pattern
Get-BitsTransfer -AllUsers | Where-Object { $_.JobState -in @('Transferring','Suspended','Queued') -and $_.CreationTime -lt (Get-Date).AddDays(-7) } |
    Select-Object DisplayName, JobId, JobState, CreationTime, OwnerAccount

# Full job detail via BITS COM, including NotifyCmdLine - not exposed by Get-BitsTransfer's default view
$bitsManager = New-Object -ComObject 'Microsoft.BackgroundIntelligentTransferManagement.5.1'
$bitsManager.EnumJobs(0) | ForEach-Object {
    [PSCustomObject]@{ DisplayName = $_.DisplayName; JobId = $_.JobId; NotifyCmdLine = $_.NotifyCmdLine; State = $_.State }
} | Where-Object { $_.NotifyCmdLine }

# Remote URLs that don't resolve to a known Microsoft/vendor update domain - the staged-download pattern
Get-BitsTransfer -AllUsers | ForEach-Object { $_.FileList } | Select-Object RemoteName, LocalName

# Job-creation events (3), most recent first - direct evidence of when and by what process a job was queued
Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -FilterXPath '*[System[EventID=3]]' |
    Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, Message

# bitsadmin.exe still present and callable - a quick live cross-check against the module output above
bitsadmin /list /allusers /verbose
```

## Where BITS Job State Lives

BITS maintains its own persistent job database, independent of both the registry and Task Scheduler, so that a job can survive a reboot and resume where it left off. The storage format and exact location have shifted across Windows versions — older systems (Windows XP/Server 2003-era through roughly Windows 7) stored the queue as a pair of files named `qmgr0.dat`/`qmgr1.dat` under `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\`, using an internal binary format that required a dedicated parser (e.g. the community `BitsParser` tool) to read offline. Modern Windows (Windows 10/11 and current Server releases) stores the same queue as an ESE (Extensible Storage Engine) database, typically `qmgr.db`, with accompanying ESE transaction log files, still rooted under `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\` (`C:\ProgramData\Microsoft\Network\Downloader\` by default). Because that storage-format detail can and has changed across OS builds, don't hard-code a parser or an assumed file format without first confirming the OS version of the host or image under analysis.

Given that variability, the single reliable, version-agnostic way to enumerate BITS jobs on a live system is the built-in `BitsTransfer` PowerShell module (`Get-BitsTransfer`) or the underlying BITS COM interface — both talk to the live BITS service itself rather than parsing the on-disk queue file directly, so they return correct results regardless of whether that host happens to store its queue as legacy `.dat` files or a modern ESE database. Offline/dead-box analysis of an acquired image is the one scenario where the underlying file format actually matters, since there's no running BITS service to query.

| Value | Meaning | Forensic relevance |
|---|---|---|
| `JobId` | GUID uniquely identifying the job | The stable identifier to correlate a job across `Get-BitsTransfer` output, the BITS-Client operational log, and (if parsed) the raw queue database |
| `DisplayName` | Analyst- or attacker-chosen friendly name for the job | Legitimate Windows Update-related jobs typically use recognizable, Microsoft-styled names; a generic or oddly-named job is a mild signal worth checking further |
| `OwnerAccount` | The account context the job runs and notifies under | A job owned by a low-privilege or unexpected account executing a notify command line is a meaningful signal — same logic as `ObjectName` on a service |
| `TransferType` | `Download` or `Upload` | `Upload`-type jobs are far less common in legitimate use and worth extra scrutiny — this is the exfiltration-adjacent direction |
| `JobState` | `Queued`, `Connecting`, `Transferring`, `Suspended`, `Error`, `TransientError`, `Transferred`, `Acknowledged`, `Cancelled` | `Transferred` (complete, awaiting acknowledgment) is the state immediately before a completion-type notify command line fires |
| `FileList` (RemoteName/LocalName) | Source URL and destination path for each file in the job | The URL is the single best indicator of legitimate vs. staged-malicious use — cross-reference against known Microsoft/vendor update domains |
| `NotifyCmdLine` | The command line BITS itself will execute on the configured trigger condition | 🔴 **The execution primitive this whole note is about** — not exposed by `Get-BitsTransfer`'s default properties, only via the underlying COM object (see Hunt Evil above) or `bitsadmin /info /verbose` |

### PowerShell

Enumerate every job across every user with the built-in module — the fastest, most portable first pass, and the one that works identically regardless of underlying queue-file format:

```powershell
Get-BitsTransfer -AllUsers | Select-Object DisplayName, JobId, JobState, OwnerAccount, TransferType, CreationTime
```

Pull the full file list (source URL and local destination) for a specific job of interest, since `Get-BitsTransfer`'s default view doesn't surface it:

```powershell
(Get-BitsTransfer -Name '<JobName>').FileList | Select-Object RemoteName, LocalName
```

Because `NotifyCmdLine` isn't exposed through the `BitsTransfer` module's own cmdlets, go through the BITS COM interface directly to read it — this is the one property in this entire note that actually proves whether a job is wired to execute anything at all:

```powershell
$bitsManager = New-Object -ComObject 'Microsoft.BackgroundIntelligentTransferManagement.5.1'
$bitsManager.EnumJobs(0) | Select-Object DisplayName, JobId, NotifyCmdLine, NotifyFlags, State
```

## The Notify Command Line — The Execution Primitive

`SetNotifyCmdLine` (via `bitsadmin.exe`) or the equivalent COM/`NotifyCmdLine` property configures a program and its arguments to run when the job reaches a state matched by the job's `NotifyFlags` — most commonly job completion (`BG_NOTIFY_JOB_TRANSFERRED`) or job error (`BG_NOTIFY_JOB_ERROR`). The classic `bitsadmin` syntax makes the mechanic explicit:

```
bitsadmin /SetNotifyCmdLine <job> <program_name> <program_parameters>
```

`program_parameters`, when not `NULL`, must repeat `program_name` as its own first token (an artifact of how the underlying Win32 API expects `argv[0]`) — so a real-world malicious example typically looks like `bitsadmin /SetNotifyCmdLine MyJob c:\windows\system32\cmd.exe "cmd.exe /c c:\programdata\update.exe"`. Because BITS itself — not the calling process, not a scheduled task, not `explorer.exe` — is what launches the notify command line, the parent process for that execution is `svchost.exe` (hosting the BITS service), which is a legitimate-looking parent for essentially anything and doesn't stand out the way a suspicious script host spawned from an odd parent would.

The trigger doesn't require the job to actually succeed. A job configured to notify on error just as readily provides a code-execution trigger, and because BITS jobs can be created with no real transfer intent at all — a job pointed at a URL that's expected to fail, purely to fire the error-state notify command line — this is sometimes used purely as an execution mechanism with almost no genuine transfer behavior to speak of. Either way, once the trigger condition is met, the command line runs with no further logging beyond what's covered below — treat a populated `NotifyCmdLine` on any job you can't immediately attribute to a known Windows or vendor update channel as a high-priority finding.

## Event Log Evidence

`Microsoft-Windows-Bits-Client/Operational` is enabled by default on modern Windows and is the primary log for this mechanism — there is no separate Security-log auditing gap to work around here the way there is for Services (4697) and Scheduled Tasks (4698), which makes this one of the more reliably-logged mechanisms in the family.

| Event ID | Meaning | Notes |
|---|---|---|
| 3 | BITS created a new job | Records job name, owner, job ID, and job type — the creation-time baseline to hunt against, and the entry point for tying a job back to the process that requested it |
| 4 | The transfer job completed | Confirms a `Transferred`-state job actually finished moving data — correlate against `NotifyCmdLine` execution timing if the job is configured to notify on completion |
| 59 | BITS started transferring a `/Download` job | Shows job type and target URL directly in the event — useful when the job itself has since been deleted from the live queue |
| 60 | BITS stopped transferring a `/Download` job | Pairs with 59 to bound the transfer window |

🔴 Because event 3 records the job's owning process at creation time, it's the fastest way to answer "what created this job" without needing to correlate against Prefetch, ShimCache, or process-creation logging separately — treat it the way this family treats System log 7045 for services and TaskScheduler/Operational 106 for tasks: the default-on, reliable baseline to lead with.

### PowerShell

Pull job-creation events and cross-reference against the currently live BITS queue to spot a job that was created (and logged) but has since completed, errored out, or been deliberately removed from the visible queue:

```powershell
$events = Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -FilterXPath '*[System[EventID=3]]'
$live   = Get-BitsTransfer -AllUsers | Select-Object -ExpandProperty JobId
$events | ForEach-Object {
    [PSCustomObject]@{ Time = $_.TimeCreated; Message = $_.Message; StillQueued = $_.Message -match ($live -join '|') }
} | Sort-Object Time -Descending
```

Sweep an estate for job-creation events across multiple hosts in a single pass, useful for spotting a BITS-based technique deployed identically across several endpoints:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-Bits-Client/Operational' -FilterXPath '*[System[EventID=3]]' -MaxEvents 20 |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Message
} | Export-Csv C:\hunt\bits_job_sweep.csv -NoTypeInformation
```

## Red Flags Specific to BITS Jobs

- **A populated `NotifyCmdLine` on a job you can't attribute to a known update channel.** This is the single highest-value finding in the entire note — a job with no notify command line is, at worst, a staged download; a job with one is a confirmed triggered-execution primitive, and the command line itself deserves the same obfuscation/LOLBIN scrutiny (base64-encoded PowerShell, `cmd.exe /c`, `rundll32`, `mshta`) applied to Run-key values and scheduled-task actions elsewhere in this family.
- **A job configured to notify only on error, with a target URL that looks designed to fail.** This is a purpose-built execution trigger rather than a genuine transfer — the "download" is a pretext for reaching the error-state notify command line, not the actual goal.
- **`TransferType = Upload` on a host with no legitimate reason to be uploading anything via BITS.** Upload jobs are comparatively rare in normal enterprise use and are the exfiltration-adjacent direction of this technique — full network/C2 analysis belongs elsewhere, but the job's mere existence and destination URL are worth flagging from the host side.
- **A job that's remained in a non-terminal state (`Queued`, `Suspended`, `Transferring`) for far longer than any normal update-style transfer would need.** BITS jobs can legitimately persist up to their configured lifetime (90 days by default, extendable), which is itself the point — a long-lived job is functioning exactly as designed as a dormant, reboot-surviving trigger waiting on its notify command line.
- **`OwnerAccount` inconsistent with the job's stated purpose**, e.g. a job that looks like a system update component but is owned by a standard user account rather than SYSTEM or a service account — mirrors the `ObjectName`/`RunAs` red flags used for Services and Scheduled Tasks.
- **BITS activity with no corresponding legitimate software inventory reason** — cross-reference the job's target URL and owning process against what's actually installed and expected to phone home on that host; an environment with disciplined baseline knowledge of its own update traffic will make an attacker-created job stand out quickly.

## Tooling

| Tool | Use |
|---|---|
| **`Get-BitsTransfer`** (BitsTransfer PowerShell module) | Built into PowerShell — the reliable live-enumeration method regardless of underlying queue-storage format; the fastest path to the fields covered in this note from a live system |
| **`bitsadmin.exe`** | Deprecated but still present through the currently-supported Windows lifecycle — `bitsadmin /list /allusers /verbose` and `bitsadmin /info <job> /verbose` (the latter exposes `NotifyCmdLine` directly without needing the COM object) |
| **BITS COM interface** (`Microsoft.BackgroundIntelligentTransferManagement.5.1`) | The only path (alongside `bitsadmin /info /verbose`) to `NotifyCmdLine` when scripting — `Get-BitsTransfer` alone does not expose it |
| **BitsParser** (community tool) | Offline parser for the legacy `qmgr0.dat`/`qmgr1.dat` binary format found on older systems — necessary when working from an acquired image where the BITS service isn't running to query live, and the host predates the ESE-based `qmgr.db` format |
| **Autoruns** (Sysinternals) | Does not enumerate BITS jobs — noted here explicitly because analysts accustomed to Autoruns catching "everything" in this family should not assume it covers this mechanism; `Get-BitsTransfer`/`bitsadmin` are the dedicated tools |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Populated `NotifyCmdLine` with no attribution to a known update channel | Confirmed triggered-execution primitive — apply the same obfuscation/LOLBIN scrutiny used elsewhere in this family to the command line itself |
| Job configured to notify on error only, with a target URL that appears designed to fail | Execution-trigger pretext rather than a genuine transfer attempt |
| `TransferType = Upload` with no legitimate business reason | Exfiltration-adjacent direction of this technique |
| Job in a non-terminal state far longer than any normal update transfer would need | BITS jobs can legitimately persist up to 90 days by design — functioning as intended as a dormant trigger |
| `OwnerAccount` inconsistent with the job's apparent purpose | Same logic as `ObjectName`/`RunAs` red flags for Services and Scheduled Tasks |
| Job-creation event (3) present with no corresponding legitimate software/update activity | Default-on, reliably-logged signal of an unattributed BITS job — this log has no equivalent to the Security-log auditing gap seen elsewhere in this family |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all Persistence Mechanisms notes | Autostart (Run/RunOnce) Keys |
| Obfuscation/LOLBIN patterns to apply to a `NotifyCmdLine` value | Autostart (Run/RunOnce) Keys, Scheduled Tasks |
| Registry hive access mechanics for the `BITS` service key itself | Registry Forensics Fundamentals (note 04) |
| Service-based persistence and its own registry/event-log evidence chain | Services |
| Trigger-driven, dormant persistence in Task Scheduler | Scheduled Tasks |
| First/last-seen evidence and hash identity of a payload staged via BITS download | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of a `NotifyCmdLine`-launched program | Prefetch.md (note 06) |
| Full C2/download-mechanics and exfiltration-direction analysis | Command and Control / Exfiltration (future note) |

## Resources

- MITRE ATT&CK T1197 (BITS Jobs) — https://attack.mitre.org/techniques/T1197/
- Microsoft, `bitsadmin setnotifycmdline` — https://learn.microsoft.com/windows-server/administration/windows-commands/bitsadmin-setnotifycmdline
- Microsoft, `Get-BitsTransfer` (BitsTransfer module) — https://learn.microsoft.com/powershell/module/bitstransfer/get-bitstransfer
- Microsoft, Using Windows PowerShell to Create BITS Transfer Jobs — https://learn.microsoft.com/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs
- FireEye/Mandiant, BitsParser (offline `qmgr0.dat`/`qmgr1.dat` parser) — https://github.com/fireeye/BitsParser
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
