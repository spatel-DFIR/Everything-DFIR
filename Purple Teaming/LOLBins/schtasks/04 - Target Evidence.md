# LOLBins — schtasks.exe — Target Evidence

Because a scheduled task is designed to sit dormant and fire later — potentially long after the `schtasks.exe` process that created it has exited — the **target host** carries two forensically distinct evidence generations: the **creation-time** artifacts (XML file, `TaskCache` registry entries, 106/4698-class events) written the moment `/create` or `/change` runs, and the **trigger-fire** artifacts (Sysmon/4688 process creation, 129/200/201 events) written later, possibly across one or more reboots. Both generations matter for a complete timeline. Per `01 - Overview.md` and `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`, this note does not re-derive the full XML schema or `TaskCache` structure already documented there — it cross-links to that note for the artifact anatomy and focuses on the event-log sequencing, Sysmon correlation, remote-creation network chain, and the specific evasion mechanics (`/xml`, `ITaskService` COM creation, Tarrask-style SD deletion) that shape how an analyst should actually hunt this evidence.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Event Logs](#event-logs)
- [Sysmon](#sysmon)
- [Remote-Creation Protocol Detail](#remote-creation-protocol-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint-Security-Product Signature Behavior](#endpoint-security-product-signature-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing From Legitimate Use](#distinguishing-from-legitimate-use)

---

## Filesystem

The full on-disk XML schema (`<RegistrationInfo>`, `<Triggers>`, `<Principal>`, `<Actions><Exec>`, `<Settings>`) is already documented field-by-field in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s Task XML Structure section — not repeated here. `schtasks.exe`-specific filesystem notes:

| Artifact | Location | Notes |
|---|---|---|
| Task XML file | `C:\Windows\System32\Tasks\<TaskPath>\<TaskName>` (no file extension); `C:\Windows\SysWOW64\Tasks\` for some 32-bit-compatibility builds | Written the instant `/create` or `/xml` succeeds — the file's own `$STANDARD_INFORMATION` creation timestamp is the single most reliable install-time proxy for this artifact class |
| Prefetch | `C:\Windows\Prefetch\SCHTASKS.EXE-<HASH>.pf` | Standard Prefetch behavior for any executed binary — see `Windows/06 - Evidence of Program Execution/Prefetch.md`. Only fires if `schtasks.exe` itself ran on **this** host; a remotely-issued `/s <target>` creation leaves no Prefetch entry for `schtasks.exe` on the target, since the target-side Task Scheduler service handled the RPC call, not a local `schtasks.exe` process |
| Prefetch for the eventual payload | `C:\Windows\Prefetch\<PAYLOAD>.pf` | Written when the task's `/tr` action actually executes — this is genuine execution evidence for the **payload**, timestamped at trigger-fire time, not creation time |
| ShimCache / Amcache | See `Windows/06 - Evidence of Program Execution/ShimCache (AppCompatCache).md` and `Amcache.md` | Same first/last-seen + (Amcache) SHA1 hash-identity value this module's other LOLBins entries document — applies to both `schtasks.exe` itself (if run locally) and the `/tr` payload once it executes |
| Renamed/relocated `schtasks.exe` copy | Wherever the operator staged it (see `02 - Hands-On Use Cases.md`'s masquerading variant) | Authenticode signature and `OriginalFileName` PE metadata still identify the underlying binary correctly regardless of the on-disk filename — see Detection & Hunting for the hash/signature-based hunt this survives |

## Registry

The full `TaskCache\Tree`/`Tasks`/`Boot`/`Logon` structure under `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\` is already documented in depth in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s Where Tasks Live — Registry (TaskCache) section — not repeated here. Two `schtasks.exe`-specific registry findings that note doesn't cover:

🔴 **A `/ru <domain\user> /rp <password>` task (any non-SYSTEM run-as identity requiring the task to run whether or not that user is logged on) stores the password in Windows Credential Manager, in a form recoverable with administrative access.** Verified against Microsoft's own [Event 4698 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698): *"If the new task XML contains `<LogonType>Password</LogonType>`, the password for the account that will be used to run the scheduled task will be saved in Credential Manager in cleartext format, and can be extracted using Administrative privileges."* This is a genuine, checkable artifact independent of the event log — enumerate with `cmdkey /list` (native) or a Credential Manager/DPAPI-aware tool, looking for a generic credential tied to `TaskScheduler` and the target `/ru` account. `/ru SYSTEM` never triggers this — the SYSTEM account has no password to store.

🔴 **Tarrask-style evasion deletes only the `SD` (security descriptor) value under `TaskCache\Tree\<TaskPath>\<TaskName>`, not the task itself.** Documented by Microsoft's own [Tarrask malware blog post](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/) (attributed to **HAFNIUM**): removing this single registry value makes the task **disappear from `schtasks /query` and the Task Scheduler MMC** — both rely on the `SD` value being present to enumerate the task — while every other artifact survives untouched: the `Tasks\<GUID>` subkey (`Actions`, `Path`, `Triggers`, `Id`), the on-disk XML file under `C:\Windows\System32\Tasks\`, and both the `TaskScheduler/Operational` and Security event-log entries from creation time. The task keeps running on its schedule until reboot or the hosting `svchost.exe` is terminated. This is the single strongest reason to enumerate `TaskCache` and the `Tasks\` directory **directly**, rather than trusting `schtasks /query` or the GUI alone — see `05 - Detection and Hunting.md`'s Hunting Priority table.

## Event Logs

Both logs' baseline mechanics (which is default-on, which requires non-default auditing) are already covered in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s Event Log Evidence section. This table adds the full `TaskScheduler/Operational` ID set relevant to `schtasks.exe` specifically, including the trigger-fire IDs that note's own table abbreviates:

| Log | Event ID | Meaning | Notes |
|---|---|---|---|
| `Microsoft-Windows-TaskScheduler/Operational` | 106 | Task registered | Written the moment `/create` or `/xml` succeeds, locally or via `/s`. **Default-on** — the reliable creation-time baseline |
| `Microsoft-Windows-TaskScheduler/Operational` | 107 | Task triggered by the scheduler | Fires when a time-based trigger condition is met |
| `Microsoft-Windows-TaskScheduler/Operational` | 108 | Task triggered by an event | Fires for `/sc onevent /ec <channel>` tasks — the specific event that satisfied the `EventTrigger` |
| `Microsoft-Windows-TaskScheduler/Operational` | 110 | Task triggered by a user (manual run) | Corresponds to `schtasks /run` or a GUI "Run" action |
| `Microsoft-Windows-TaskScheduler/Operational` | 111 | Task terminated | The task's process ended, normally or via `/end` |
| `Microsoft-Windows-TaskScheduler/Operational` | 118 | Task triggered by computer startup | `/sc onstart` firing |
| `Microsoft-Windows-TaskScheduler/Operational` | 119 | Task triggered by user logon | `/sc onlogon` firing |
| `Microsoft-Windows-TaskScheduler/Operational` | 129 | Task Scheduler launched a process for the task instance | 🔴 **Names the exact process ID (`%3`) assigned to the task's action** — the direct, built-in bridge from "which task fired" to "which PID to chase in Sysmon 1/Security 4688," verified against the event's documented message text (`Task Scheduler launched the "%2" instance of the "%1" task, with process ID %3`) |
| `Microsoft-Windows-TaskScheduler/Operational` | 140 | Task registration updated | Fires on `/change` — including the task-hijack use case in `02 - Hands-On Use Cases.md`, which produces **this** event instead of a new 106 |
| `Microsoft-Windows-TaskScheduler/Operational` | 141 | Task registration deleted | Fires on `/delete` |
| `Microsoft-Windows-TaskScheduler/Operational` | 200 | Action started | The `<Actions><Exec>` action actually began executing |
| `Microsoft-Windows-TaskScheduler/Operational` | 201 | Action completed | Pairs with 200 to bound the execution window and capture the return code |
| Security log | 4698 | Scheduled task created | Requires **"Audit Other Object Access Events"** subcategory enabled (verified against Microsoft's [Event 4698 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698)) — **not default-on**. When present, this is the single richest event for `schtasks.exe`: it embeds the entire `TaskContent` XML inline, plus (Windows 10 1903+) `ClientProcessId`/`ParentProcessId`/`FQDN` fields identifying exactly which process on which host issued the creation call |
| Security log | 4699 / 4700 / 4701 / 4702 | Task deleted / enabled / disabled / updated | Same "Audit Other Object Access Events" prerequisite as 4698 |

Full switch-to-event mapping for `/create`, `/change`, `/delete`, `/run`, `/end` is implicit in the table above — every sub-command in `01 - Overview.md`'s switches table maps to exactly one of these IDs.

## Sysmon

| Event ID | What it captures | Notes |
|---|---|---|
| 1 (Process Create) | The `/tr` payload's own launch, as a **direct child of `svchost.exe -k netsvcs -p -s Schedule`** (Windows 10 1511+) or `taskeng.exe` (pre-1511) | Per `01 - Overview.md`'s red-flag callout — this is the execution-time evidence, correlated to a specific task via the 129 event's process ID. **Not** a child of `schtasks.exe`, which exits long before this fires |
| 1 (Process Create) | `schtasks.exe` itself, if it ran locally (creation, query, delete, etc.) | Full command line, including `/tr`, `/ru`, and (if used inline) `/p`/`/rp` credential material — see `03 - Source Evidence.md` for the issuing-host mirror of this same event |
| 3 (Network Connection) | Outbound connection from the payload process, or the RPC connection window during a remote `/s` creation | See Network-Layer Evidence below for the specific port pattern |
| 11 (File Create) | The task XML file being written under `C:\Windows\System32\Tasks\` | Only fires if Sysmon's config explicitly includes that path — not universally true of default/community configs (e.g. SwiftOnSecurity's baseline does not specifically target `System32\Tasks`), so treat this as config-dependent rather than guaranteed |
| 12 / 13 / 14 (Registry Create/Set/Rename) | Writes to `TaskCache\Tree\...` and `TaskCache\Tasks\<GUID>\...`, including a Tarrask-style `SD` value deletion | Also config-dependent — most default Sysmon configs do not include the full `TaskCache` key path by default; if present, a registry-**delete** event for the `SD` value specifically is a strong Tarrask-pattern signal worth adding to a custom config given the finding above |

## Remote-Creation Protocol Detail

`Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s Remote Task Creation for Lateral Movement section already documents the full destination-host evidence chain (4624 Type 3 → 4672 → 106 → 4698 → 200/201 → ShimCache/Amcache/Prefetch) for `schtasks /create /s`. Per `01 - Overview.md`'s protocol analysis, that RPC call is understood to ride the **`ITaskSchedulerService`** interface (`ncacn_ip_tcp` — TCP 135 endpoint-mapper query, then a dynamic high port), distinct from the legacy `ATSvc`/`SASec` named-pipe interface (`ncacn_np`, SMB/TCP 445) that older AT-job-era tooling and some third-party tools (e.g., Impacket's `atexec.py`) target instead. On the **target** side specifically:

- The 4624 (Type 3 network logon) event's `IpAddress` field ties the connection back to the issuing host — cross-reference against `03 - Source Evidence.md`'s issuing-host TCP-135/dynamic-port connection window for the strongest available source↔target correlation, since (unlike psexec's ADMIN$ copy) this RPC call leaves no separate file-transfer artifact of its own.
- 4672 (special privileges assigned) confirms the authenticating account actually held Administrators-equivalent rights on the target at logon time — a prerequisite `01 - Overview.md`'s Prerequisites table already states, now with its event-log proof.

## Network-Layer Evidence

| Signal | Where to look | Notes |
|---|---|---|
| TCP 135 (RPC endpoint mapper) inbound, immediately followed by a dynamic high-port TCP session from the same source IP | Zeek `dce_rpc.log` / `conn.log`, NetFlow | The modern `ITaskSchedulerService` transport pattern — endpoint-mapper query resolves the dynamic port, then the actual `SchRpcRegisterTask`-class call rides that port. Zeek's `dce_rpc` analyzer decodes the interface UUID directly where available, which is the most authoritative way to distinguish this from unrelated RPC/DCOM traffic on the same port range |
| SMB/TCP 445 named-pipe traffic to `\PIPE\atsvc` | Zeek `smb_files.log`/`dce_rpc.log`, packet capture | Only relevant for the legacy `ATSvc`/`SASec` interface — a different network shape than `schtasks.exe`'s own default. If seen, it indicates tooling other than `schtasks.exe` itself is driving the remote creation (see `01 - Overview.md`'s caveat) |
| No outbound payload-delivery traffic tied to `schtasks.exe`'s own connection | N/A | Reinforces `01 - Overview.md`'s How It Works point 2 — `schtasks.exe` never transfers the payload itself, so there is no equivalent to `certutil`'s or `bitsadmin`'s download traffic to correlate against this specific process. Payload-delivery traffic, if any, belongs to whatever tool staged `/tr`'s target beforehand |

## Endpoint-Security-Product Signature Behavior

- **SigmaHQ** maintains a substantial rule set specifically for `schtasks.exe`'s abuse-relevant switch combinations, verified live against the [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/process_creation) repository's `process_creation` rules — including `proc_creation_win_schtasks_schedule_via_masqueraded_xml_file.yml` (an `/xml` argument pointing at a file without a `.xml` extension), `proc_creation_win_schtasks_env_folder.yml` (`/tr` pointing into an environment-variable-referenced or otherwise suspicious folder), `proc_creation_win_schtasks_guid_task_name.yml` (a GUID-formatted `/tn`, a common malware-generated-name pattern), `proc_creation_win_schtasks_schedule_type_system.yml` and `proc_creation_win_schtasks_schedule_type.yml` (high-privilege run level paired with an unusual `/sc` value), `proc_creation_win_schtasks_creation_temp_folder.yml` (`/tr` pointing into a Temp path), and `proc_creation_win_schtasks_change.yml` (the exact task-hijack pattern this module's `02 - Hands-On Use Cases.md` documents). Every one of these is a **command-line-based** rule — they inherit the same blind spot the Hunting Priority table in `05 - Detection and Hunting.md` calls out: `/xml`-based creation and `ITaskService` COM-API creation both produce no matching command line to alert on.
- **Microsoft Defender for Endpoint** ships a built-in "Suspicious Scheduled Task" class of alert logic that, per Microsoft's own detection guidance, keys on `schtasks.exe` invoked with `/Create`/`/Change`/`/Run`/`/Delete`/`/Query` plus argument combinations like `/tr`, `/sc`, or `/ru`, weighted further when the parent process is itself unusual for a scheduled-task operation (`cmd.exe`, `wscript.exe`, `cscript.exe` spawning `schtasks.exe` rather than an interactive user session). Same command-line dependency and same blind spot as the Sigma rules above.
- **Tarrask** (HAFNIUM, see Registry above) is the concrete, Microsoft-documented case of an actor deliberately building tooling around this exact detection gap — it doesn't touch `schtasks.exe`'s command line at all, so no signature keyed on that process's arguments will ever fire for it. Any EDR/AV product's `schtasks.exe`-argument-based detection coverage should be assumed to have this same structural gap unless the vendor explicitly documents registry-level (`TaskCache\Tree\...\SD`) or filesystem-level (`System32\Tasks\` directory listing vs. `schtasks /query` output) monitoring alongside it.

## Memory Forensics

The task's actual command-line arguments (including any `/p`/`/rp` credential material) are already fully recoverable from Sysmon 1/Security 4688/4698 if any are enabled — memory forensics adds comparatively little for the **creation** step itself. Two angles that do add value:

- **The Task Scheduler service process** (`svchost.exe -k netsvcs -p -s Schedule`, hosting `schedsvc.dll`) holds the in-memory task-execution context briefly around trigger-fire time — a live memory capture taken during or shortly after that window can corroborate the parent/child relationship documented in `01 - Overview.md`'s red-flag callout even if the child process itself has already exited and Prefetch/Sysmon logging was disabled.
- **A scripting-language wrapper driving the RPC calls directly** (rather than shelling out to `schtasks.exe`) can retain a plaintext `/rp`-equivalent credential string in its own process memory well past the point it was used — the same reference-counting/garbage-collection timing lag `03 - Source Evidence.md` documents for the issuing-host side of this same concern.

## Building a Timeline

For a **local** creation-to-execution chain:

```
1. TaskScheduler/Operational 106  ── task registered (creation time)
2. [dormant period — minutes to months, possibly across reboots]
3. TaskScheduler/Operational 107/108/110/118/119  ── the specific trigger fires
4. TaskScheduler/Operational 129  ── names the process ID assigned to the task instance
5. Sysmon 1 / Security 4688 (that PID)  ── the payload's own process-creation record,
                                             parent = svchost.exe -k netsvcs -p -s Schedule
6. TaskScheduler/Operational 200  ── action started
7. TaskScheduler/Operational 201  ── action completed
8. TaskScheduler/Operational 111  ── task terminated (if applicable)
```

For a **remote** creation (lateral movement), prepend the issuing-host side documented in `03 - Source Evidence.md` and the destination-host authentication chain documented in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s Remote Task Creation table:

```
Issuing host: Sysmon 1 (schtasks.exe /create /s <target>) + TCP 135/dynamic-port connection window
        │
        ▼
Target:  Security 4624 (Type 3 logon) ── Security 4672 (admin rights confirmed)
        │
        ▼
Target:  TaskScheduler/Operational 106 ── (Security 4698, if audited)
        │
        ▼
        [same local trigger-fire chain as above, once /run forces it or the schedule arrives]
```

If a task appears to be missing steps 1–2 above (i.e., 129/200/201 exist with no matching 106), check for a Tarrask-style `SD`-value deletion (Registry section above) or a log-retention gap — `TaskScheduler/Operational` is a fixed-size circular log and can roll over 106 events from months earlier while retaining more recent 129/200/201 entries for a still-active recurring task.

## Distinguishing From Legitimate Use

🔴 Per `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s own framing, a default Windows install carries well over a hundred legitimate scheduled tasks — the finding is never "a `TaskScheduler/Operational` 106 event exists," it's a 106/129/200 chain whose task name, library placement, `<Actions>` target, run-as identity, or trigger type doesn't match what that name/placement implies. See that note's own Red Flags table for the full checklist (`RunLevel = HighestAvailable` + `UserId = SYSTEM` with no plausible need, `Hidden = true`, action paths outside expected binary locations, name/folder mimicry, blank/spoofed `<RegistrationInfo>`) — `05 - Detection and Hunting.md` builds its hunt queries directly on top of that checklist rather than restating it.
