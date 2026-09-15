# Scheduled Tasks

The Windows Task Scheduler runs a program on a trigger — a time, a logon, a boot, a specific event in the Windows event log, or the system going idle — with zero user interaction. Functionally that makes it a superset of both the Run-key model (fire at logon) and the service model (fire at boot as a privileged account): Task Scheduler can do either of those *and* fire on a trigger that has nothing to do with the boot/logon cycle at all, which is exactly what makes it such a flexible persistence mechanism and, on the right host with the right credentials, a first-class remote-execution primitive.

Like Services, this note covers scheduled tasks from **both** angles it legitimately occupies — the persistence angle (a task planted on this host, decoded from its XML and registry footprint) and the remote-execution angle (`schtasks /create /s <host>`, used to push and run a task on a different machine as part of lateral movement). Full lateral-movement depth — session semantics, credential requirements, how this technique compares to `sc create`, WMI, and PowerShell Remoting — belongs in Lateral Movement (note 12) and is only summarized here.

This is the third note in the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing Scheduled Tasks against Services, WMI Event Consumers, and DLL Hijacking.

> 🔴 **A scheduled task is only as suspicious as its action, trigger, and run-as context.** A default Windows install carries well over a hundred legitimate scheduled tasks (Microsoft telemetry, Defender scans, certificate maintenance, disk cleanup). The finding is never "a task exists," it's "this task points at an unexpected binary, runs with privilege it shouldn't need, fires on a trigger that makes no sense for its stated purpose, or was created moments before other evidence of attacker activity."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Where Tasks Live — Filesystem](#where-tasks-live--filesystem)
- [Where Tasks Live — Registry (TaskCache)](#where-tasks-live--registry-taskcache)
- [OS-Version Deltas: AT Jobs vs. Task Scheduler 2.0](#os-version-deltas-at-jobs-vs-task-scheduler-20)
- [Task XML Structure](#task-xml-structure)
- [Event Log Evidence](#event-log-evidence)
- [Remote Task Creation for Lateral Movement](#remote-task-creation-for-lateral-movement)
- [Red Flags Specific to Scheduled Tasks](#red-flags-specific-to-scheduled-tasks)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, module-only triage against the `ScheduledTasks` module (built into PowerShell on Windows 8/Server 2012 and later — no `schtasks.exe` parsing or third-party tooling required) before reaching for the XML/registry/event-log detail below.

```powershell
# Every scheduled task with its action, trigger type, run-as context, and last/next run time in one pass
Get-ScheduledTask | ForEach-Object {
    $info = $_ | Get-ScheduledTaskInfo
    [PSCustomObject]@{
        TaskName = $_.TaskName; TaskPath = $_.TaskPath; State = $_.State
        Action   = ($_.Actions.Execute -join '; ')
        Triggers = ($_.Triggers.CimClass.CimClassName -join '; ')
        RunAs    = $_.Principal.UserId
        LastRun  = $info.LastRunTime; NextRun = $info.NextRunTime
    }
} | Sort-Object LastRun -Descending

# Actions pointing into Temp/AppData/a user profile rather than Windows/Program Files - the drop-and-persist pattern
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match '\\(Temp|AppData|Users)\\' -and $_.Actions.Execute -notmatch '\\Windows\\'
} | Select-Object TaskName, TaskPath, @{N='Action';E={$_.Actions.Execute}}

# Logon-triggered tasks also marked Hidden - the fileless-adjacent combination worth chasing first
Get-ScheduledTask | Where-Object {
    $_.Settings.Hidden -eq $true -and $_.Triggers.CimClass.CimClassName -match 'LogonTrigger'
} | Select-Object TaskName, TaskPath, State

# Recurring triggers firing more often than every 15 minutes - abnormally tight for legitimate scheduled work
Get-ScheduledTask | ForEach-Object {
    $task = $_
    $task.Triggers | Where-Object { $_.Repetition.Interval } | ForEach-Object {
        if ([System.Xml.XmlConvert]::ToTimeSpan($_.Repetition.Interval) -lt (New-TimeSpan -Minutes 15)) {
            [PSCustomObject]@{ TaskName = $task.TaskName; Interval = $_.Repetition.Interval }
        }
    }
}

# SYSTEM-context tasks whose underlying XML file was created in the last 7 days
Get-ScheduledTask | Where-Object { $_.Principal.UserId -eq 'SYSTEM' } | ForEach-Object {
    $xmlPath = "C:\Windows\System32\Tasks$($_.TaskPath)$($_.TaskName)"
    $file = Get-Item $xmlPath -ErrorAction SilentlyContinue
    if ($file -and $file.CreationTime -gt (Get-Date).AddDays(-7)) {
        [PSCustomObject]@{ TaskName = $_.TaskName; TaskPath = $_.TaskPath; Created = $file.CreationTime }
    }
}

# Task-creation events (106), most recent first - the reliable, default-on baseline this note leads with
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FilterXPath '*[System[EventID=106]]' |
    Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, Message

# Raw XML for one task of interest, straight from disk - no schtasks.exe or module call needed
[xml](Get-Content 'C:\Windows\System32\Tasks\Microsoft\Windows\UpdateOrchestrator\Schedule Scan')
```

## Where Tasks Live — Filesystem

Every Task Scheduler 2.0 task (Vista and later) is stored as an individual XML file, one file per task, named after the task itself with **no file extension**:

| Path | Scope |
|---|---|
| `C:\Windows\System32\Tasks\<TaskName>` | 64-bit tasks, and all tasks on a 32-bit OS |
| `C:\Windows\SysWOW64\Tasks\<TaskName>` | Historically used for 32-bit task compatibility on some builds — check both locations, mirroring the `WOW6432Node` gotcha covered for Run keys in Autostart (Run/RunOnce) Keys |

Tasks organized into Task Scheduler Library "folders" (visible as a tree in `taskschd.msc`, e.g. `\Microsoft\Windows\...`) exist as a matching subdirectory structure on disk — `C:\Windows\System32\Tasks\Microsoft\Windows\<Category>\<TaskName>`. A task sitting directly at the root of `Tasks\` rather than filed under a plausible subfolder is itself a mild signal — most Microsoft and third-party software registers its tasks into a named subfolder, not loose at the top level.

**Filesystem timestamps as install-time evidence.** The XML file's own creation time is a strong proxy for when the task was installed — see NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes for the MACB rules and caveats that apply to any file on the volume, including these. Because the file is plain XML, it is also trivially readable with nothing more than a text editor once acquired — no proprietary parser required, which is not true of the registry-side artifact covered next.

## Where Tasks Live — Registry (TaskCache)

Task Scheduler maintains its own registry-side index independent of the XML files, under:

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\
```

| Subkey | Structure | Forensic relevance |
|---|---|---|
| `Tree` | Mirrors the Task Scheduler Library folder hierarchy — one subkey per folder/task name, each holding a default value that is a GUID | The **path index** — walk `Tree` to enumerate every task by its human-readable library path, then use the GUID at each leaf to jump to the matching `Tasks` entry below |
| `Tasks` | One subkey per task, **keyed by the GUID** from `Tree`, not by name | Holds the values below — this is where the task's actual configuration lives from the registry's point of view |
| `Tasks\<GUID>\Path` | String value | The task's full library path/name — the human-readable link back to the `Tree` structure and to the on-disk XML file location |
| `Tasks\<GUID>\Id` | GUID | Matches the subkey name itself; also referenced inside the task's own XML (`RegistrationInfo\URI`/task metadata) |
| `Tasks\<GUID>\SD` | Binary security descriptor | Defines who can view/modify/run the task — worth decoding when a task's permissions look deliberately restrictive, which is atypical for legitimate scheduled software |
| `Tasks\<GUID>\Actions` | Binary blob | A serialized copy of the task's `<Actions>` element (see Task XML Structure below) — useful corroboration if the on-disk XML has been altered or deleted but the registry copy survives |
| `Tasks\<GUID>\DynamicInfo` | Binary blob containing FILETIME values | Records **last run time**, **last successful run time**, and **last task result/exit code** — this is genuine execution evidence, distinct from and complementary to the install-time evidence the XML file's creation timestamp gives you |
| `TaskCache\Boot` | List of GUIDs (as value names) | Tasks with a `BootTrigger` configured — a **pre-filtered, high-value subset** to check first, since boot-triggered tasks are the scheduled-task equivalent of an Auto-start service |
| `TaskCache\Logon` | List of GUIDs (as value names) | Tasks with a `LogonTrigger` configured — the equivalent pre-filtered subset for logon-triggered tasks |

🔴 **`DynamicInfo`'s last-run timestamp survives even if the task itself was later deleted from the Task Scheduler UI**, in some cases, if the registry key wasn't fully cleaned up — always check for `TaskCache\Tasks` GUID subkeys with no corresponding on-disk XML file (or vice versa: XML present but no matching `Tasks` entry, which suggests the task was deleted from the scheduler's live index but the file was never cleaned up, or was planted to run via a mechanism other than the scheduler's own registration path).

See Registry Forensics Fundamentals (note 04) for hive access mechanics (live vs. offline `SOFTWARE` hive, transaction-log replay) that apply the same way here.

## OS-Version Deltas: AT Jobs vs. Task Scheduler 2.0

Scheduled-task forensics splits cleanly into two forensically distinct artifact families depending on OS version and which scheduling mechanism was actually used:

| | Legacy AT jobs (`at.exe`) | Task Scheduler 2.0 |
|---|---|---|
| OS availability | Pre-Vista natively; `at.exe` binary remained present (deprecated) through Windows 7, **removed in Windows 8+** | Vista and later — the system in place on every currently-supported version of Windows |
| Storage format | Binary `.job` files (Task Scheduler 1.0 job-file format, documented under MS-TSCH) | Plain XML, one file per task, no extension |
| Storage location | `C:\Windows\Tasks\At<N>.job` | `C:\Windows\System32\Tasks\<TaskName>` / `SysWOW64\Tasks\` |
| Registry footprint | Minimal/legacy `Schedule` service keys — no `TaskCache` structure | Full `TaskCache\Tree`/`Tasks`/`Boot`/`Logon` structure described above |
| Naming | Sequential, generic (`At1.job`, `At2.job`, ...) — no descriptive task name at all | Analyst- or attacker-chosen task name, filed into a Library folder |
| Creation tool | `at.exe` (command line) or the deprecated GUI | `schtasks.exe`, Task Scheduler MMC, `ITaskService` COM API, PowerShell `ScheduledTasks` module |
| Historical relevance | Still worth knowing for older/legacy images, and because `schtasks.exe /create /sc ONCE ...` can superficially resemble an "AT job" in intent even though it creates a full Task Scheduler 2.0 XML task under the hood | The system you will encounter on essentially every live engagement today |

Because `at.exe` jobs and Task Scheduler 2.0 tasks are genuinely different artifacts on disk and in the registry, don't assume a `.job`-file search will surface anything on a modern (Windows 8+) host, and don't assume `TaskCache` will hold anything for a genuinely AT-created job on a legacy system that still has both mechanisms present.

## Task XML Structure

A Task Scheduler 2.0 XML file breaks into a handful of elements worth reading field-by-field — this is the single richest source of intent in the entire artifact.

| Element | What it holds | Forensic relevance |
|---|---|---|
| `<RegistrationInfo>` | `Author`, `Description`, `URI` (the task's library path), `Date` (creation time as recorded by the scheduler itself) | 🔴 A blank or spoofed `Author`/`URI`, or a `Date` that doesn't line up with the file's own filesystem creation time, is a real signal — legitimate Microsoft and vendor tasks almost always populate these fields consistently |
| `<Triggers>` | One or more trigger definitions — see table below | The *when* — often the most revealing element for judging intent |
| `<Principal>` | `UserId` (the account context) and `RunLevel` (`LeastPrivilege` or `HighestAvailable`) | The *as whom* — see Red Flags below; `RunLevel = HighestAvailable` paired with `UserId = SYSTEM` for a task with no plausible need for that privilege is a strong escalation signal |
| `<Actions><Exec>` | `<Command>` (the executable/interpreter) and `<Arguments>` (the command line passed to it) | The *what* — apply the same obfuscation/encoding red flags used for Run-key command lines (see Autostart (Run/RunOnce) Keys) to this field: base64-encoded PowerShell, `-WindowStyle Hidden`, `-NoProfile`, LOLBIN abuse (`rundll32`, `regsvr32`, `mshta`) |
| `<Settings>` | `Hidden`, `Enabled`, `DisallowStartIfOnBatteries`, `AllowHardTerminate`, `ExecutionTimeLimit`, and others | 🔴 `Hidden = true` suppresses the task from the default Task Scheduler MMC view (it's still enumerable with `schtasks /query` or by reading the XML directly) — legitimate tasks essentially never set this |

**Trigger types** (inside `<Triggers>`):

| Trigger | Fires when | Persistence relevance |
|---|---|---|
| `TimeTrigger` | A specific date/time, optionally repeating | Straightforward scheduled execution — flag unusual recurrence intervals (e.g. every few minutes, indefinitely) |
| `LogonTrigger` | Any user logon, or a specific user's logon if `UserId` is set | Functionally equivalent to a Run key, but routed through the scheduler instead — same detection logic as Run-key analysis applies to *who* logging in fires it |
| `BootTrigger` | System boot | Functionally equivalent to an Auto-start service — the scheduled-task analogue of `Start = 0x02`, runs before any user interaction |
| `EventTrigger` | A specific event ID being logged to a specified Windows event log/source | 🔴 **A favorite fileless-adjacent persistence technique** — the task itself sits dormant on disk, invisible in a simple "what's about to run" view, until a chosen event (which can be as mundane as an application launch, a specific logon type, or even an event the attacker's own tooling generates) fires it. This is conceptually the same fileless, trigger-driven persistence model that WMI Event Consumers uses via the WMI repository instead of the Task Scheduler — see WMI Event Consumers (note in this family) once written; the two mechanisms are worth hunting together, since an attacker who understands one usually understands the other |
| `IdleTrigger` | System entering an idle state | Less common for persistence, more common for legitimate maintenance tasks — still worth checking the paired action |
| `RegistrationTrigger` | Task registration/update itself | Rare in legitimate use; fires once, immediately, whenever the task is created or modified |

### PowerShell

Enumerate tasks and pull their full detail, including run history, via the built-in `ScheduledTasks` module without requiring `schtasks.exe` parsing:

```powershell
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
Get-ScheduledTask -TaskName '<TaskName>' | Get-ScheduledTaskInfo
```

Read a task's XML straight off disk and cast it to `[xml]` to walk the same elements documented above (`<Actions>`, `<Triggers>`, `<Principal>`, `<Settings>`, `<RegistrationInfo>`) without going through the module at all — this approach is useful when working from an acquired image rather than a live host:

```powershell
[xml]$taskXml = Get-Content 'C:\Windows\System32\Tasks\<TaskPath>\<TaskName>'
$taskXml.Task.Actions.Exec
$taskXml.Task.Principal
```

## Event Log Evidence

Two logs carry scheduled-task evidence, with the same detection-gap pattern already established for Services in this family — one log is enabled by default, the other requires non-default auditing.

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| `Microsoft-Windows-TaskScheduler/Operational` | 106 | Task registered (created) | **Primary, reliably-logged detection signal** — this operational log is enabled by default on modern Windows, unlike the Security-log equivalent below |
| `Microsoft-Windows-TaskScheduler/Operational` | 140 | Task updated | Existing task's definition changed — worth diffing old vs. new XML if both are recoverable |
| `Microsoft-Windows-TaskScheduler/Operational` | 141 | Task deleted | Confirms removal — pair with the `TaskCache` GUID-orphan check described above to see if registry remnants outlived the deletion |
| `Microsoft-Windows-TaskScheduler/Operational` | 200 | Action started (task executed) | Direct execution evidence — the task's action actually ran |
| `Microsoft-Windows-TaskScheduler/Operational` | 201 | Action completed | Pairs with 200 to bound the execution window and capture the return code |
| Security log | 4698 | Scheduled task created | 🔴 Requires **non-default auditing** ("Audit Other Object Access Events") to be enabled — same detection gap already covered for service-creation event 4697 in Services.md; do not assume 4698 will be present just because a task was created |
| Security log | 4699 | Scheduled task deleted | Same auditing prerequisite as 4698 |
| Security log | 4700 | Scheduled task enabled | Same auditing prerequisite |
| Security log | 4701 | Scheduled task disabled | Same auditing prerequisite |
| Security log | 4702 | Scheduled task updated | Same auditing prerequisite |

🔴 **Lead with 106/200/201 in the TaskScheduler/Operational log, not 4698.** The operational log's default-on state makes it the far more reliable baseline, exactly mirroring how System log 7045 (service installed) is the reliable baseline for services while Security log 4697 depends on non-default auditing. Full mechanics of correlating these events across logs — including how to reconstruct a deleted task's history from surviving operational-log entries — belongs in Event Log Analysis (note 11).

### PowerShell

Decode `Action`/`Trigger`/`Principal` into one readable row per task, then correlate 106/140/141 events against the task's current live state to catch a task that shows as deleted in the log but is still present, or vice versa:

```powershell
Get-ScheduledTask | ForEach-Object {
    [PSCustomObject]@{
        TaskName  = $_.TaskName
        Command   = ($_.Actions | ForEach-Object Execute) -join '; '
        Arguments = ($_.Actions | ForEach-Object Arguments) -join '; '
        Triggers  = ($_.Triggers.CimClass.CimClassName -join '; ')
        RunAs     = $_.Principal.UserId
        RunLevel  = $_.Principal.RunLevel
        Hidden    = $_.Settings.Hidden
        State     = $_.State
    }
}

$events = Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FilterXPath '*[System[(EventID=106 or EventID=140 or EventID=141)]]'
$live   = Get-ScheduledTask | Select-Object -ExpandProperty TaskName
$events | ForEach-Object {
    [PSCustomObject]@{
        Time        = $_.TimeCreated; EventId = $_.Id
        TaskName    = $_.Properties[0].Value
        StillExists = $_.Properties[0].Value -in $live
    }
} | Sort-Object Time -Descending
```

Flag tasks that are `Hidden = true` or `Disabled` but still present — both are suppressed from the default view or won't currently fire, yet remain fully enumerable:

```powershell
Get-ScheduledTask | Where-Object { $_.Settings.Hidden -eq $true -or $_.State -eq 'Disabled' } |
    Select-Object TaskName, TaskPath, State, @{N='Hidden';E={$_.Settings.Hidden}}
```

Sweep an estate for outliers by pulling every task's action, trigger, and principal from each host and exporting for comparison, then pull 106 at scale with an XPath time-window filter instead of the module for faster results across many hosts and logs:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-ScheduledTask | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME; TaskName = $_.TaskName; TaskPath = $_.TaskPath
            Action = ($_.Actions.Execute -join '; '); RunAs = $_.Principal.UserId; State = $_.State
        }
    }
} | Export-Csv C:\hunt\scheduledtask_sweep.csv -NoTypeInformation

# Same 106 pull as Hunt Evil, XPath-filtered to the last 24 hours for scale across a large operational log
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FilterXPath '*[System[EventID=106 and TimeCreated[timediff(@SystemTime) <= 86400000]]]'
```

Export the task's XML before disabling or removing it — evidence first — since `Unregister-ScheduledTask` deletes the on-disk XML and `TaskCache` entry this note relies on. Prefer disabling over deleting while the investigation is still open:

```powershell
Export-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>' | Out-File 'C:\hunt\<TaskName>_export.xml'

# Disable rather than delete when the investigation isn't finished - keeps the task and its history intact
Disable-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>'

# Full removal - only after the XML above is exported and the task's evidentiary value is captured
Unregister-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>' -Confirm:$false
```

## Remote Task Creation for Lateral Movement

Because the Task Scheduler service accepts remote connections from an authenticated, sufficiently-privileged user (over RPC, the same transport `sc.exe` uses for remote service control), a task can be pushed to and started on a remote host in effectively one command:

```
schtasks /create /s <host> /tn <taskname> /tr "c:\temp\evil.exe" /sc onstart /ru SYSTEM
schtasks /run /s <host> /tn <taskname>
```

This sits alongside `sc \\host create` (Services.md) and WMI process creation as one of the three classic native-Windows remote-execution primitives — an attacker with valid credentials rarely needs to drop new tooling to move laterally when any of these three already ship on every Windows host. Full source/destination lateral-movement depth (session semantics, credential requirements, comparison against `sc create`/WMI/PowerShell Remoting/`net use`) belongs in Lateral Movement (note 12); the table below is the destination-host evidence chain this technique leaves behind, matching the layout used for Services' remote-creation section and the FOR508 poster's lateral-movement panel.

| Evidence Source | What It Shows | Notes |
|---|---|---|
| Security log 4624 (Logon Type 3) | Network logon from the source host | Establishes who connected and from where |
| Security log 4672 | Admin-equivalent privileges assigned at logon | Confirms the account had rights sufficient to create a remote task |
| TaskScheduler/Operational 106 | Task registered on the destination | Reliable, default-on detection signal — check this before the audited-only Security-log equivalent |
| Security log 4698 (task created) | Direct record of task creation | 🔴 Requires non-default auditing — same gap as above, do not rely on this alone |
| TaskScheduler/Operational 200/201 | Confirms the pushed task actually executed | Pairs with the registration event to bound install-to-execution time, often measured in seconds for scripted lateral movement |
| `C:\Windows\System32\Tasks\<TaskName>` XML file + `TaskCache\Tasks\<GUID>` registry entry | The task's own footprint on the destination host | Same structure as any locally-created task — read `<Actions>`, `<Principal>`, `<Triggers>` exactly as described above |
| ShimCache / Amcache | First/last-seen evidence and (Amcache) SHA1 hash identity of the pushed executable | See ShimCache (AppCompatCache).md and Amcache.md (note 06) — Amcache's hash is particularly useful for confirming the exact binary matches other hosts in the intrusion |
| Prefetch | Confirms the pushed executable actually ran, with run count and timestamps | See Prefetch.md (note 06) |

## Red Flags Specific to Scheduled Tasks

- **`RunLevel = HighestAvailable` / `UserId = SYSTEM` with no plausible need.** A task purporting to do something mundane (a helper utility, a "cleanup" script) that runs as SYSTEM at the highest available privilege level anyway is a strong escalation signal — the same logic used for `ObjectName = LocalSystem` on services.
- **`Hidden = true` in `<Settings>`.** Suppresses the task from the default MMC view; legitimate tasks essentially never set this. Still fully enumerable with `schtasks /query` or by reading the XML — this is UI-level concealment, not a real hiding mechanism, but it's a reliable tell when found.
- **Task name mimics a legitimate Microsoft task, or is filed into a Microsoft library folder it doesn't belong in.** A task named to look like `\Microsoft\Windows\UpdateOrchestrator\...` content but with an unrelated action, or a plausible-looking name sitting loose at the root of `Tasks\` instead of a real subfolder, banks on an analyst pattern-matching the path alone.
- **`<Actions><Exec><Command>` pointing outside expected binary locations.** Same logic as Run-key and service `ImagePath` analysis — a task launching something from `%APPDATA%`, `%TEMP%`, `%ProgramData%`, or a user profile directory is the scheduled-task equivalent of drop-and-persist.
- **Task created via the `ITaskService` COM API rather than `schtasks.exe`.** Task Scheduler exposes a full COM interface (`ITaskService`/`ITaskFolder`/`ITaskDefinition`) that PowerShell, C#, and native tooling can call directly to register a task without ever invoking `schtasks.exe` as a child process — this evades command-line-logging tooling (e.g. Security log 4688 with command-line auditing enabled, or EDR command-line capture) that specifically watches for `schtasks.exe /create`. The task still shows up in the filesystem, `TaskCache`, and the TaskScheduler/Operational log exactly as any other task would — those artifacts don't care how the task was registered — which is why this note leans on the XML/registry/operational-log evidence chain rather than command-line logging alone.
- **`EventTrigger` bound to an obscure or attacker-relevant event ID.** A task that only fires on a specific, unusual event (rather than a normal time/logon/boot trigger) is worth tracing back to what generates that event — this is the fileless-adjacent persistence pattern called out in the Task XML Structure section above.
- **Blank or spoofed `<RegistrationInfo>` fields, or a `Date` that doesn't match the file's own filesystem creation time.** Legitimate vendor/Microsoft tasks populate `Author`/`URI` consistently; a mismatch between the XML's internal `Date` and the file's actual MACB timestamps suggests the file was copied, restored, or otherwise manipulated after initial creation.
- **Unusual trigger/action combinations for the task's stated purpose.** E.g. a task named for disk cleanup with a `LogonTrigger` for a specific non-administrative user, or an update-sounding task with an `EventTrigger` — the mismatch between the name/description and the actual configured behavior is often more revealing than either element alone.

## Tooling

| Tool | Use |
|---|---|
| **`schtasks.exe /query /v /fo list`** | Live enumeration of every scheduled task with full verbose detail (trigger, action, run-as context, last/next run time) in one command — the fastest way to pull the fields covered in this note from a live system |
| **Task Scheduler MMC (`taskschd.msc`)** | Live, GUI-based inspection — useful for a quick visual sweep of the Library folder tree, though it will not surface `Hidden = true` tasks by default the way `schtasks.exe` or a direct XML read will |
| **Autoruns** (Sysinternals) | Already introduced in Autostart (Run/RunOnce) Keys and Services — its Scheduled Tasks tab enumerates tasks alongside every other autostart mechanism, with code-signing and VirusTotal cross-reference, so a suspicious task surfaces in the same single pass as a suspicious Run key or service |
| **KAPE** (Kroll Artifact Parser and Extractor) | Targets/modules covering `C:\Windows\System32\Tasks`, `SysWOW64\Tasks`, and the `SOFTWARE` hive (for `TaskCache`) at scale across many endpoints — see Evidence Acquisition & Imaging (note 02); there is no dedicated Eric Zimmerman parser for task XML specifically (unlike RECmd/MFTECmd for other artifact families), so offline review after KAPE collection is typically manual XML inspection paired with Autoruns' offline-analysis mode against the collected `Tasks` folder |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `Schedule\TaskCache\Tree`/`Tasks`/`Boot`/`Logon` when working from an acquired `SOFTWARE` hive rather than a live host |
| Direct XML review (any text editor) | Task files require no proprietary parser — once acquired, `<Triggers>`, `<Actions>`, `<Principal>`, `<Settings>`, and `<RegistrationInfo>` are all plain, human-readable text |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `RunLevel = HighestAvailable` / `UserId = SYSTEM` for a task with no plausible need | Privilege-escalation signal — verify the task's stated function actually requires that level of access |
| `Hidden = true` in `<Settings>` | Suppresses the task from the default MMC view — legitimate tasks essentially never set this; still visible via `schtasks /query` or direct XML read |
| Task name/library-folder mimics a legitimate Microsoft task | Banks on the analyst pattern-matching the name/path and skipping verification of the actual action |
| `<Actions><Exec><Command>` pointing outside expected binary locations (`%APPDATA%`, `%TEMP%`, `%ProgramData%`, user profile) | Drop-and-persist — legitimate tasks essentially never launch from user-writable locations |
| Task present in filesystem/`TaskCache`/operational log with no corresponding `schtasks.exe` command-line evidence | Possible `ITaskService` COM-API creation — evades command-line-based detection while leaving the full artifact chain intact |
| `EventTrigger` bound to an obscure or attacker-relevant event ID | Fileless-adjacent, trigger-driven persistence — trace back to what generates the triggering event |
| Blank/spoofed `<RegistrationInfo>` fields, or internal `Date` mismatched against the file's own filesystem creation time | Legitimate tasks populate these consistently; mismatch suggests post-creation manipulation or a copied/restored file |
| `TaskCache\Tasks\<GUID>` entry with no matching on-disk XML file, or vice versa | Incomplete cleanup after deletion, or a task registered/executed through a path that bypassed the normal registration flow — worth reconciling both artifacts |
| TaskScheduler/Operational 106 present with no corresponding change-management record | Primary, reliably-logged signal of an unauthorized task creation — investigate before checking for the audited-only 4698 |
| 4698/4699/4700/4701/4702 absent | Does not mean no task activity occurred — these events require non-default auditing; rely on the TaskScheduler/Operational log (106/140/141/200/201) as the baseline |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline access mechanics used to read `TaskCache` correctly | Registry Forensics Fundamentals (note 04) |
| Filesystem timestamp rules applied to the task's on-disk XML file | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes |
| Service-based persistence and its own registry/event-log evidence chain, including the parallel Security-log auditing gap | Services |
| Fileless, event-triggered persistence in the WMI repository — the conceptual sibling of `EventTrigger` tasks | WMI Event Consumers (this family) |
| Search-order/DLL side-loading persistence with no service or task footprint of its own | DLL Hijacking (this family) |
| First/last-seen evidence and hash identity of a dropped or remotely-pushed task executable | ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Confirming actual execution of a task-launched executable | Prefetch.md (note 06) |
| Full lateral-movement depth — source/destination pairing for `schtasks /s`, `sc create`, WMI/WMIC, PowerShell Remoting, `net use` | Lateral Movement (note 12) |
| Security/TaskScheduler-operational log event mechanics in full | Event Log Analysis (note 11) |

## Resources

- SANS FOR508 poster, "Hunt Evil: Malware Persistence" and "Hunt Evil: Lateral Movement" panels — Scheduled Tasks coverage checklist for the XML/registry/event-log chains, rewritten in this note's own words
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd) — https://ericzimmerman.github.io/
- KAPE (Kroll Artifact Parser and Extractor) — https://www.kroll.com/kape
- Microsoft, Task Scheduler Schema (XML elements reference) — https://learn.microsoft.com/windows/win32/taskschd/task-scheduler-schema
- Microsoft, MS-TSCH: Task Scheduler Service Remoting Protocol (covers legacy AT job-file format and the remote task-creation RPC interface) — https://learn.microsoft.com/openspecs/windows_protocols/ms-tsch/
- MITRE ATT&CK T1053.005 (Scheduled Task/Job: Scheduled Task) — https://attack.mitre.org/techniques/T1053/005/
