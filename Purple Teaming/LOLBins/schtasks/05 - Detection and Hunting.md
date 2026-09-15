# LOLBins — schtasks.exe — Detection and Hunting

`schtasks.exe` exposes several genuinely distinct evasion paths — `/xml` import, full `ITaskService` COM-API creation that never touches `schtasks.exe` as a process, binary renaming, `/change`-based task hijacking, and (as a real-world precedent) Tarrask's registry-level `SD`-value deletion — so no single hunting signal covers every case. This file ranks signals by which of those evasion options they survive, **before** giving the hunt commands themselves, per this module's Writing Style Guide. Hunting on Source targets the artifacts documented in `03 - Source Evidence.md`; Hunting on Target targets `04 - Target Evidence.md`.

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked strongest (survives the most evasion variants) to weakest. "Survives" means the signal still exists and is still discoverable; it does not mean the signal is easy to interpret at scale.

| Rank | Signal | Survives | Defeated by |
|---|---|---|---|
| 1 | **Direct filesystem enumeration of `C:\Windows\System32\Tasks\`** (raw directory listing, not `schtasks /query`) | `/xml` creation, `ITaskService` COM-API creation, renamed/relocated `schtasks.exe` binary, **and Tarrask-style `TaskCache\Tree\...\SD` deletion** — the XML file itself is never touched by any of these | A task genuinely never written to disk in the first place is not possible for this artifact type — every Task Scheduler 2.0 task has a backing XML file by design. The only way to defeat this is to delete the file outright, which itself is a detectable filesystem event |
| 2 | **`TaskCache\Tasks\<GUID>` registry subkey** (`Actions`, `Path`, `Triggers` — reached by walking `Tree`, or by scanning `Tasks\*` directly and ignoring `Tree`'s `SD`-dependent enumeration) | Same list as above, including Tarrask — the `Tasks\<GUID>` entry is a separate registry location from the `SD` value Tarrask deletes | Direct manual deletion of the `Tasks\<GUID>` key itself (a more aggressive, more detectable cleanup than Tarrask's single-value approach) |
| 3 | **`TaskScheduler/Operational` 106/129/140/141/200/201** | `/xml` creation (fires 106 regardless of how the task was assembled), Tarrask (the operational log is untouched by the `SD`-value deletion), renamed binary | `ITaskService` COM-API creation still fires these events too — **Task Scheduler logs task registration and execution regardless of what created the task, command line included or not** — so this survives essentially everything except outright event-log clearing (itself logged as Security 1102 / System 104) or a deliberate `wevtutil` size/retention manipulation |
| 4 | **Security 4698/4699/4700/4701/4702** | Everything rows 1–3 survive, **plus** it uniquely captures the full `TaskContent` XML and (1903+) the creating process's PID/PPID/FQDN inline | Requires **"Audit Other Object Access Events"** — not default-on. Absence proves nothing; presence is the richest single event in the whole chain |
| 5 | **`schtasks.exe` command-line logging** (Sysmon 1 / Security 4688 with command-line auditing, either host) | Plain switch-based `/create`/`/change` with `/tr` visible in the command line | `/xml` (the actual `/tr` payload path is hidden inside the XML file, not the command line), `ITaskService` COM-API creation (no `schtasks.exe` process exists at all), Authenticode-blind rules keyed on `Image` = `schtasks.exe` (defeated by renaming the binary — though `OriginalFileName`/hash-based rules are not) |
| 6 | **Target-side Sysmon 1 for the payload process** (child of `svchost.exe -k netsvcs -p -s Schedule`) | The strongest possible proof the task actually **executed**, tied to a specific task via the 129 event's process ID — survives every creation-side evasion trick above, since it doesn't care how the task was made | Only fires at trigger time — for a dormant persistence task, this could be absent for weeks/months after creation, and is meaningless if the analyst is instead watching for children of `schtasks.exe` or (pre-1511 muscle memory) `taskeng.exe` per `01 - Overview.md`'s red-flag callout |
| 7 | **Network-layer RPC signature** (TCP 135 + dynamic port, or SMB/445 `\PIPE\atsvc` for legacy tooling) | Only relevant to the remote-creation use case in the first place | Transient — only visible during the brief creation-time RPC exchange unless full packet capture or NetFlow/Zeek retention covers that window; irrelevant to every local-only use case |

## Hunting on Source

Targets `03 - Source Evidence.md`'s artifact set on the **issuing** host — most relevant to the remote-creation/lateral-movement use case, where a genuine source↔target pair exists.

```powershell
# schtasks.exe command lines with /create or /s — Sysmon 1, if present
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)schtasks(\.exe)?\s' -and $_.Message -match '(?i)(/create|/change|/s\s)' } |
  Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "`n" | Select-String 'CommandLine:').ToString()}}

# Same via Security 4688 (requires command-line auditing enabled)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match '(?i)schtasks\.exe' }

# Inline /p or /rp credential exposure — flag any hit for immediate credential rotation
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match '(?i)schtasks.*(/p\s|/rp\s)' }

# PowerShell console history, if the operator ran schtasks.exe from a PS prompt
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern 'schtasks' -SimpleMatch

# Live RPC connection state during/just after a remote-creation window (TCP 135 + dynamic high port)
Get-NetTCPConnection -RemotePort 135 -State Established -ErrorAction SilentlyContinue

# Renamed-binary check — walk running/recent processes for schtasks.exe's Authenticode identity under a different name
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath } | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.ExecutablePath -ErrorAction SilentlyContinue
    if ($sig.SignerCertificate.Subject -match 'Microsoft Windows' -and $_.Name -ne 'schtasks.exe') {
        [PSCustomObject]@{ PID = $_.ProcessId; Path = $_.ExecutablePath; Name = $_.Name; Signer = $sig.SignerCertificate.Subject }
    }
}
```

## Hunting on Target

Targets `04 - Target Evidence.md`'s artifact set. Leads with the filesystem/registry enumeration from Hunting Priority rows 1–2, since those are the only signals that survive Tarrask-style concealment — **do not rely on `schtasks /query` or the Task Scheduler MMC alone.**

```powershell
# Row 1: raw filesystem enumeration of the Tasks directory — catches Tarrask-hidden tasks
# that schtasks /query and Get-ScheduledTask will both silently omit
Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File

# Row 2: TaskCache\Tasks GUID subkeys with no matching schtasks /query result — the
# concrete Tarrask signature (task present in Tasks\<GUID>, absent from Tree-based enumeration)
$liveTasks = (Get-ScheduledTask).TaskName
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks' | ForEach-Object {
    $taskPath = (Get-ItemProperty $_.PSPath -Name Path -ErrorAction SilentlyContinue).Path
    if ($taskPath -and ($taskPath.Split('\')[-1] -notin $liveTasks)) {
        [PSCustomObject]@{ GUID = $_.PSChildName; Path = $taskPath; Note = 'Registered but not enumerable via Get-ScheduledTask/schtasks /query — check for a missing Tree\...\SD value' }
    }
}

# Row 3: TaskScheduler/Operational 106 (creation) and 129 (process-ID assignment) together —
# 129 without a corresponding recent 106 is expected for a long-dormant recurring task,
# but a 129 with NO 106 ever present in the retained log window is worth investigating
Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' -FilterXPath '*[System[(EventID=106 or EventID=129 or EventID=140)]]' |
    Sort-Object TimeCreated -Descending | Select-Object TimeCreated, Id, Message

# Row 4: Security 4698 — full TaskContent XML plus (1903+) ClientProcessId/ParentProcessId/FQDN, if audited
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4698,4699,4700,4701,4702} -ErrorAction SilentlyContinue

# Credential Manager check for stored /rp passwords tied to non-SYSTEM run-as identities
cmdkey /list | Select-String -Context 1,1 'TaskScheduler'

# Target-side Sysmon 1: children of the Task Scheduler service host — the correct parent
# from Windows 10 1511 onward, per 01 - Overview.md's red-flag callout
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ParentImage:.*svchost\.exe' -and $_.Message -match 'ParentCommandLine:.*-s Schedule' }

# Cross-reference against Windows/10 - Persistence Mechanisms/Scheduled Tasks.md's own
# Hunt Evil block for action-path/hidden/recurrence-interval red flags — not restated here
Get-ScheduledTask | Where-Object {
    $_.Actions.Execute -match '\\(Temp|AppData|Users)\\' -and $_.Actions.Execute -notmatch '\\Windows\\'
} | Select-Object TaskName, TaskPath, @{N='Action';E={$_.Actions.Execute}}
```

## Fleet-Wide Sweep

For the remote-creation/lateral-movement and C2-tasking-at-scale use cases in `02 - Hands-On Use Cases.md`, the strongest signal is the **same task name/action pattern appearing across many hosts in a tight creation window** — a single host's task rarely stands out on its own against the "well over a hundred legitimate tasks" baseline, but an identical or near-identical task landing on 40 hosts inside a five-minute window does.

```powershell
$computers = Get-Content C:\hunt\hosts.txt

# Pull every non-Microsoft-signed task's action/trigger/run-as across the fleet in one pass,
# plus a direct filesystem listing to catch any Tarrask-hidden tasks the module misses
Invoke-Command -ComputerName $computers -ScriptBlock {
    $viaModule = Get-ScheduledTask | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' } | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME; Source = 'Get-ScheduledTask'
            TaskName = $_.TaskName; TaskPath = $_.TaskPath
            Action = ($_.Actions.Execute -join '; '); RunAs = $_.Principal.UserId
        }
    }
    $viaFilesystem = Get-ChildItem 'C:\Windows\System32\Tasks' -Recurse -File | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME; Source = 'Filesystem'
            TaskName = $_.Name; TaskPath = $_.DirectoryName; Action = $null; RunAs = $null
        }
    }
    $viaModule + $viaFilesystem
} | Export-Csv C:\hunt\schtasks_fleet_sweep.csv -NoTypeInformation

# TaskScheduler/Operational 106 across the fleet, XPath-filtered to a tight recent window —
# faster at scale than the module call above, and catches creation timing precisely
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-TaskScheduler/Operational' `
        -FilterXPath '*[System[EventID=106 and TimeCreated[timediff(@SystemTime) <= 3600000]]]' -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Message
} | Group-Object { $_.Message } | Where-Object Count -gt 3 | Sort-Object Count -Descending
```

## Remediation

🔴 **Capture evidence before disabling or deleting.** `Unregister-ScheduledTask` removes the on-disk XML and the `TaskCache` registry entry this entire evidence chain depends on — export first, exactly as `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s own Remediate block specifies (cross-linked here rather than restated). For the `schtasks.exe`-specific remote-creation and credential-exposure findings this note adds:

```powershell
# Export the task definition XML before touching it
Export-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>' | Out-File 'C:\hunt\<TaskName>_export.xml'

# Export the TaskCache registry branch for the specific GUID identified above
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\<GUID>" "C:\hunt\<GUID>_taskcache.reg"

# Export the relevant event-log window before any retention rollover
wevtutil epl Microsoft-Windows-TaskScheduler/Operational C:\hunt\taskscheduler_operational.evtx
wevtutil epl Security C:\hunt\security_relevant.evtx

# Disable rather than delete while the investigation is open — preserves the task and its history
Disable-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>'

# If a /rp password was found stored in Credential Manager (see Hunting on Target), rotate that
# account's credential — the stored value is recoverable by any administrator on the host, not
# just the original operator
cmdkey /delete:TaskScheduler:<TaskName>   # only after the credential itself has been captured/rotated

# Full removal — only after every export above is complete
Unregister-ScheduledTask -TaskName '<TaskName>' -TaskPath '<TaskPath>' -Confirm:$false
```

For the remote-creation use case, also rotate/investigate the account used for `/u`/`/ru` on the target — a successful `schtasks /create /s` with `/ru SYSTEM` demonstrates the operator already held Administrators-equivalent rights on that host (per `01 - Overview.md`'s Prerequisites table), which is itself the higher-priority finding relative to any single task artifact.
