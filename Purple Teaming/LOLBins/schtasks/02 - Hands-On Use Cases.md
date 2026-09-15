# LOLBins — schtasks.exe — Hands-On Use Cases

Every scenario issues its commands through `schtasks.exe`, but per `01 - Overview.md`'s How It Works section, the task's actual action executes later — as a child of the Task Scheduler service host (`svchost.exe -k netsvcs -p -s Schedule` on Windows 10 1511+, `taskeng.exe` before it) — not as a child of `schtasks.exe` itself. Command syntax is verified against Microsoft Learn's per-sub-command reference pages and the [LOLBAS Project's `Schtasks.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Schtasks.yml). MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Local Persistence via a Logon/Boot Trigger](#local-persistence-via-a-logonboot-trigger)
- [Recurring Short-Interval Execution to Keep a Session Alive](#recurring-short-interval-execution-to-keep-a-session-alive)
- [Remote Task Creation for Lateral Movement](#remote-task-creation-for-lateral-movement)
- [SYSTEM-Context Execution via /ru](#system-context-execution-via-ru)
- [XML-Based Stealth Task Import](#xml-based-stealth-task-import)
- [Event-Triggered Fileless-Adjacent Persistence](#event-triggered-fileless-adjacent-persistence)
- [Interactive-Only Task Scoped to a Compromised User](#interactive-only-task-scoped-to-a-compromised-user)
- [Task Deletion and Cleanup](#task-deletion-and-cleanup)
- [Query and Enumeration for Recon](#query-and-enumeration-for-recon)
- [Immediate Ad Hoc Execution via /run](#immediate-ad-hoc-execution-via-run)
- [Stopping a Task's Running Process via /end](#stopping-a-tasks-running-process-via-end)
- [Hijacking an Existing Legitimate Task](#hijacking-an-existing-legitimate-task)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Fleet-Wide Mass Use](#fleet-wide-mass-use)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Local Persistence via a Logon/Boot Trigger

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Persistence)

```cmd
schtasks /create /tn "Windows Update Assistant" /tr "C:\Users\Public\svc.exe" /sc onlogon /ru SYSTEM /rl HIGHEST /f
```

Verified against the exact pattern MITRE attributes to **APT3** (`schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"`). `/sc onlogon` fires whenever any user logs on; `/ru SYSTEM` and `/rl HIGHEST` combine to run the payload with full SYSTEM privilege regardless of which user actually triggered the logon event. `/f` suppresses the "task already exists" prompt if the operator re-runs the command. The task persists across reboots by design — it's stored on disk and in `TaskCache` independent of the process that created it.

## Recurring Short-Interval Execution to Keep a Session Alive

**MITRE ATT&CK:** T1053.005 (Persistence, Execution)

```cmd
schtasks /create /sc minute /mo 1 /tn "Reverse shell" /tr "C:\Users\Public\beacon.exe"
```

Verified verbatim against LOLBAS's own documented technique for this binary. `/sc minute /mo 1` re-fires the task every minute — a crude but effective way to keep re-launching a reverse shell or beacon that dies or gets killed, without needing a persistent listener or watchdog process of its own. No `/ru` means the task runs as whoever created it, and LOLBAS tags this pattern as requiring only **User** privilege — no administrator rights needed for a task that runs as yourself.

## Remote Task Creation for Lateral Movement

**MITRE ATT&CK:** T1053.005 (Execution, Persistence — used operationally for lateral movement), [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts)

```cmd
schtasks /create /s 10.10.10.50 /tn "MyTask" /tr "C:\Windows\Temp\beacon.exe" /sc daily /ru SYSTEM /rp * /f
schtasks /run /s 10.10.10.50 /tn "MyTask"
```

The other LOLBAS-documented technique for this binary, tagged **Administrator** privilege. `/s <target>` redirects the entire operation to a remote host over RPC (per `01 - Overview.md`, the `ITaskSchedulerService` interface — `ncacn_ip_tcp`, TCP 135 endpoint mapper plus a dynamic high port). Because `/sc daily` won't fire until the next scheduled time, the immediate follow-up `schtasks /run /s <target> /tn "MyTask"` (its own sub-command, not a flag on `/create`) forces execution right away — the same two-step pattern MITRE documents for **Operation CuckooBees**' lateral movement (`SCHTASKS /Create /S <IP> /U <Username> /p <Password> /SC ONCE /TN test /TR <Batch Path> /ST <Time> /RU SYSTEM`) and consistent with **BRONZE BUTLER**'s use of `schtasks` during lateral movement. Requires the calling account to already be an Administrator on the target — see `01 - Overview.md`'s Prerequisites table for the domain-trust caveat on `/u`. Note the payload (`beacon.exe`) must already be staged at that path on the target — see the chained workflow below.

## SYSTEM-Context Execution via /ru

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Privilege Escalation)

```cmd
schtasks /create /tn "DiagTrack Helper" /tr "C:\Windows\Temp\svc.exe" /sc once /st 00:00 /ru SYSTEM /f
schtasks /run /tn "DiagTrack Helper"
```

Verified against **Earth Lusca**'s documented pattern (`schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR "[path]" /ru system`), adapted here to a one-shot `/sc once` trigger fired immediately via `/run` rather than waiting on a logon event. An operator who has landed as a local administrator but not SYSTEM uses this to escalate: creating the task requires only local admin rights, but the task itself executes as `NT AUTHORITY\SYSTEM` once triggered — `/ru SYSTEM` needs no `/rp` password, since the SYSTEM account has none.

## XML-Based Stealth Task Import

**MITRE ATT&CK:** T1053.005, [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```cmd
schtasks /create /tn "Adobe Acrobat Update Task" /xml C:\Users\Public\task.xml /ru SYSTEM /f
```

Verified against Microsoft's own `/create` reference, which documents `/xml <xmlfile>` as an alternative to assembling the task from individual switches. Two operational advantages over the switch-based form: (1) the `/tr` action path never appears as a literal command-line argument to `schtasks.exe` — anything logging `schtasks.exe`'s command line (Sysmon 1, Security 4688) only sees `/xml <path>`, not the actual payload path or arguments, which are hidden inside the XML file's own `<Actions><Exec>` element instead; and (2) a hand-built XML file can specify a **`<ComHandler>`** action — invoking an arbitrary registered COM object by CLSID — a task-action type the switch-based `/create .../tr` form has no equivalent for at all. See `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` for the full `<Actions>` element schema this XML populates.

## Event-Triggered Fileless-Adjacent Persistence

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Persistence, Defense Evasion)

```cmd
schtasks /create /tn "Log Monitor" /tr "C:\Windows\Temp\svc.exe" /sc onevent /ec Application /f
```

`/sc onevent` requires `/ec <channelname>` (the event-log channel to match) per Microsoft's own reference — the operator would additionally scope this to a specific EventID/source via the XML-import form for a real deployment, since the switch-based form's event-matching filter is limited. The task sits completely dormant — invisible in any "what's about to run soon" view — until the chosen event fires, which can be as mundane as an application launch or a specific logon type. This is the exact fileless-adjacent trigger model `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` documents as the Task Scheduler's conceptual sibling to WMI Event Consumers — the two are worth hunting together.

## Interactive-Only Task Scoped to a Compromised User

**MITRE ATT&CK:** T1053.005

```cmd
schtasks /create /tn "Security Script" /tr "C:\Users\Public\svc.exe" /sc daily /mo 70 /it /f
```

Adapted from Microsoft's own documented `/it` example. `/it` restricts the task to only run while the `/ru` user (here, the implicit current user, since no `/ru` is given) is actually logged on locally — useful when an operator wants a payload to run under a specific compromised user's session context and nothing else, and per Microsoft's docs **this property cannot later be removed via `/change`** once set. Verbose query (`schtasks /query /v`) shows `Logon Mode: Interactive only` for tasks with this property — a durable identifying marker.

## Task Deletion and Cleanup

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/), [T1070](https://attack.mitre.org/techniques/T1070/) (Indicator Removal)

```cmd
schtasks /delete /tn "Windows Update Assistant" /f
```

Verified against Microsoft's `/delete` reference — `/f` suppresses the confirmation prompt for a scripted/unattended cleanup. Per Microsoft's own docs, this **does not** stop a currently-running instance of the task's program (use `/end` first if the payload might still be executing) and does not touch the payload binary itself — it removes only the schedule entry, the on-disk XML, and the `TaskCache` registry structure. `/delete /tn *` (with a bare wildcard) deletes **every** task on the system, including other users' — a scorched-earth option real operators rarely use since it's maximally conspicuous.

## Query and Enumeration for Recon

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (used for discovery in practice, though ATT&CK does not tag T1053.005 with a Discovery tactic)

```cmd
schtasks /query /fo LIST /v
schtasks /query /s 10.10.10.50 /u DOMAIN\admin /fo LIST /v
schtasks /query /xml /tn "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan"
```

`/query` with no other arguments (or bare `schtasks`) lists every task on the local computer; `/fo LIST /v` requests the full verbose detail — run-as identity, next/last run time, logon mode — in one pass. Pointed at a remote host via `/s` (with `/u`/`/p` if the current session's credentials don't already have rights there), this becomes remote recon of every scheduled task an operator can reach — useful for finding an existing SYSTEM-context task worth hijacking (see below) rather than creating a new, more conspicuous one. `/query /xml /tn <path>` dumps a specific task's **full XML definition** to stdout, including its complete `<Actions>` content, in a single command.

## Immediate Ad Hoc Execution via /run

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)

```cmd
schtasks /run /tn "Security Script"
```

Verified against Microsoft's own `/run` reference: *"Starts a scheduled task immediately. The run operation ignores the schedule... Running a task does not affect the task schedule and does not change the next run time."* Used throughout this file to force immediate execution of a task whose configured trigger (`/sc daily`, `/sc once` at a future time, etc.) wouldn't otherwise fire during the operator's session — turning any schedule type into an ad hoc "run now" primitive.

## Stopping a Task's Running Process via /end

**MITRE ATT&CK:** Not independently technique-mapped — an operational/cleanup action supporting whichever primary technique the task itself was tagged with

```cmd
schtasks /end /tn "Reverse shell"
```

Per Microsoft's `/end` reference, this stops **only** the process instance that this specific task started — it is not a general process-kill (`taskkill` covers that) and has no effect on processes started some other way. Useful when an operator needs to interrupt a runaway recurring task (like the minute-interval reverse-shell keeper above) without deleting the task definition itself, e.g., to pause activity during a suspected detection event without losing the persistence mechanism.

## Hijacking an Existing Legitimate Task

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Defense Evasion angle — no new task artifact), T1036 (Masquerading)

```cmd
schtasks /query /fo LIST /v | findstr /i "SYSTEM"
schtasks /change /tn "\Microsoft\Windows\SomeExistingTask" /tr "C:\Windows\Temp\svc.exe"
```

Verified against Microsoft's `/change` reference, which documents `/tr` as replacing "the original program run by the task" — the task's **name cannot be changed**, but its action can be, in place. An operator first enumerates for an existing task that already runs as SYSTEM with an innocuous, Microsoft-looking name and a trigger that will fire soon (the query above), then repoints its `/tr` at a payload. This produces **no new `TaskName`, no new `TaskCache` GUID, and no Event ID 106 (task registered)** — only a **140 (task updated)** and, if audited, a **4702 (scheduled task updated)** — a meaningfully quieter footprint than creating a fresh task from scratch, at the cost of needing a suitable existing task to hijack in the first place.

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), plus whichever primary technique it's paired with

```cmd
copy C:\Windows\System32\schtasks.exe C:\Users\Public\svchost_helper.exe
C:\Users\Public\svchost_helper.exe /create /tn "Update" /tr "C:\Users\Public\svc.exe" /sc onlogon /ru SYSTEM
```

Not a LOLBAS-documented technique specifically for this binary, but the same masquerading logic this module's `certutil/` and `bitsadmin/` entries cover applies equally: copying the legitimate, Microsoft-signed binary under a new name/path defeats a detection rule keyed purely on `Image` = `schtasks.exe` at `System32`/`SysWOW64`. Authenticode/`OriginalFileName` checks still identify the underlying binary correctly even when renamed. Renaming the client does nothing to hide the resulting **task** itself, though — the XML file, `TaskCache` entry, and TaskScheduler/Operational log all record the task exactly the same way regardless of what created it, and (per `01 - Overview.md`) an `ITaskService` COM-API creation bypasses the command-line evidence entirely without even needing a renamed binary.

## Fleet-Wide Mass Use

**MITRE ATT&CK:** T1053.005, T1078

```cmd
:: Issued near-identically across many already-compromised hosts via C2 tasking
schtasks /create /tn "Windows Defender Verification" /tr "C:\Windows\Temp\stage2.exe" /sc onstart /ru SYSTEM /f
```

The same boot-persistence pattern pushed across an entire compromised fleet at once — common in the pre-detonation staging phase of a ransomware intrusion or anywhere an operator needs guaranteed reboot-survival for a second-stage payload across many hosts simultaneously. See the fleet-wide sweep block in `05 - Detection and Hunting.md` for the corresponding hunt; a stronger signal here than a single host's task is the **same task name and action pattern appearing across many hosts in a tight creation window**.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
schtasks /query /fo LIST /v | findstr /i "Microsoft"
```

Per `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s own red-flag framing: *"A default Windows install carries well over a hundred legitimate scheduled tasks"* — Defender scans, certificate maintenance, telemetry, disk cleanup, and third-party software update checks all register tasks routinely, most filed neatly into a `\Microsoft\...` or vendor-named library subfolder with populated `<RegistrationInfo>` fields. The finding is never "a task exists," it's a task whose action, trigger, run-as context, or library placement doesn't match its stated purpose — see that note's Red Flags table for the full list this module's `05 - Detection and Hunting.md` builds on rather than repeats.
