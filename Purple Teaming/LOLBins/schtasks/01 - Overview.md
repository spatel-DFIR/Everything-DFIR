# LOLBins — schtasks.exe — Overview

> 🔴 **Red Flag Principle:** On every currently supported version of Windows, the process that actually runs a scheduled task's action is **not** `schtasks.exe` (which creates the task and exits) and, despite what a great deal of older blog-era guidance still says, **not `taskeng.exe` either** — that helper process was retired starting with **Windows 10 Version 1511**. Since 1511, the Task Scheduler service itself, running as `svchost.exe -k netsvcs -p -s Schedule`, spawns the task's action as its own **direct child** the moment a trigger fires — potentially minutes, days, or months after the task was created, and possibly after one or more reboots. A hunt that looks for suspicious children of `schtasks.exe` will always come up empty; a hunt still keyed on `taskeng.exe` as the expected parent is hunting for a process that hasn't existed on a supported Windows release in over a decade. The correct parent to watch is `svchost.exe` hosting the `Schedule` service — verified against a live process-hierarchy deep-dive by detection engineer Nasreddine Bencherchali (`@nas_bench`).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`schtasks.exe` is a native Windows command-line utility, not a third-party or offensive-security-authored tool — it is Microsoft's own CLI front end to the **Windows Task Scheduler** service. It has shipped since Windows XP Professional / Windows Server 2003 (fronting the older Task Scheduler 1.0 `.job`-file engine on those releases) and was carried forward as the CLI for **Task Scheduler 2.0** starting with Windows Vista, the XML-based engine still in use today — see `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` for the full AT-jobs-vs-Task-Scheduler-2.0 artifact-format comparison, which this note does not re-derive. Full current switch-set documentation lives at Microsoft Learn's [`schtasks` command reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks), split into one page per sub-command (`/create`, `/change`, `/delete`, `/run`, `/end`, `/query`, `/showsid`) — every switch in this note's tables is verified against those individual pages, not the tool's general landing page alone.

Its abuse as a "living-off-the-land binary" (LOLBIN) is catalogued by the community-maintained [**LOLBAS Project**](https://lolbas-project.github.io/lolbas/Binaries/Schtasks/) (`LOLBAS-Project/LOLBAS` on GitHub), authored by **Oddvar Moe** (`@oddvarmoe`) on **2018-05-25**. **Verified directly against the live `Schtasks.yml` source**, LOLBAS's catalog for this binary is unusually thin relative to most other entries in this module — it documents exactly **two** commands: a recurring-execution pattern (`/create /sc minute /mo 1 ...`, tagged `User` privilege) and a remote task-creation pattern for lateral movement (`/create /s <target> ...`, tagged `Administrator` privilege). Both are tagged `T1053.005`. Treat LOLBAS's catalog here as a floor, not the ceiling — the real breadth of documented `schtasks.exe` abuse comes from **MITRE ATT&CK's own T1053.005 (Scheduled Task) procedure-example library**, verified live against [attack.mitre.org](https://attack.mitre.org/techniques/T1053/005/), which names `schtasks` explicitly for **APT3** (`schtasks /create /tn "mysc" /tr C:\Users\Public\test.exe /sc ONLOGON /ru "System"`), **BRONZE BUTLER** (lateral movement), **Lazarus Group** (periodic remote XSL-script execution and dropped-VBS persistence), **Operation CuckooBees** (`SCHTASKS /Create /S <IP> /U <Username> /p <Password> /SC ONCE /TN test /TR <Batch Path> /ST <Time> /RU SYSTEM`), and **Earth Lusca** (`schtasks /Create /SC ONLOgon /TN WindowsUpdateCheck /TR "[path]" /ru system`) — plus documented usage by APT32, APT33, APT37, FIN7, FIN10, Gamaredon Group, Kimsuky, Mustang Panda, OilRig, and Naikon. ATT&CK lists T1053.005's own tactics as **Execution, Persistence, and Privilege Escalation** — it does not carry a separate "Lateral Movement" tactic tag, even though several of the procedure examples above (BRONZE BUTLER, Operation CuckooBees) are explicitly lateral-movement operations that simply route through the Execution/Persistence tactic instead.

The remote-creation mechanic itself is formally specified in **[MS-TSCH: Task Scheduler Service Remoting Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931)**, cited directly below and in `04 - Target Evidence.md`.

## How It Works

**1. `schtasks.exe` is a thin client, not the execution engine.** Every sub-command (`/create`, `/change`, `/delete`, `/run`, `/end`, `/query`) is a short call into the Task Scheduler service's API and returns almost immediately — `schtasks.exe` itself does not stay resident, does not hold the task open, and is not present at all by the time a task's trigger actually fires. This is the same client/service split this module's `bitsadmin/` and `certutil/` entries document for their own services, but the gap between "command typed" and "payload executes" is typically far larger here: a scheduled task can legitimately sit dormant for months.

**2. No payload delivery of its own.** Unlike `bitsadmin.exe` or `certutil.exe`, `schtasks.exe` does not fetch, download, or stage bytes anywhere — `/tr <taskrun>` only records a **path** to a program, script, or batch file that must already exist on the target (or be reachable via a UNC path) at the moment the task actually fires. An operator using `schtasks.exe` for execution or persistence needs the payload delivered by some other means first — this note's Quick Use-Case List below cross-links to this module's actual delivery-primitive tools (`certutil/`, `bitsadmin/`) where that handoff is realistic.

**3. Local task storage and structure — cross-linked, not re-derived.** Every task `schtasks.exe` creates on Windows Vista and later is stored as an XML file under `C:\Windows\System32\Tasks\<TaskName>` (and mirrored into the `TaskCache` registry structure at `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`). The full XML schema (`<RegistrationInfo>`, `<Triggers>`, `<Principal>`, `<Actions><Exec>`, `<Settings>`), the `TaskCache\Tree`/`Tasks`/`Boot`/`Logon` registry layout, and the AT-jobs-vs-Task-Scheduler-2.0 version split are already covered in full depth in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` — this note does not repeat that schema, only the `schtasks.exe`-specific command syntax that populates it and the event-log/process detail unique to this tool.

**4. Remote creation — two RPC interfaces, verified against MS-TSCH's own transport specification.** The Task Scheduler Remoting Protocol exposes three RPC interfaces: legacy **ATSvc**/**SASec** (the old Net Schedule / Task Scheduler Agent interfaces, inherited from `at.exe`'s era) and the modern **ITaskSchedulerService** interface introduced with Vista. Per Microsoft's own [MS-TSCH Transport](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/400d77fe-2f1a-4a8e-a90b-a8f82fad5a20) specification: *"When using the ATSvc and SASec interfaces, the Task Scheduler Remoting Protocol client and server MUST specify **ncacn_np**"* — RPC over a **named pipe** (`\PIPE\atsvc`, carried over SMB, TCP 445) — *"When using the ITaskSchedulerService interface, the Task Scheduler Remoting Protocol client and server MUST specify **ncacn_ip_tcp**"* — RPC directly over **TCP**, using a **dynamic endpoint** resolved through the RPC endpoint mapper (TCP 135) rather than a fixed, well-known port. Because `schtasks.exe /create /s <host>` builds a modern Task Scheduler 2.0 XML task (not a legacy AT job), it is understood to drive the **ITaskSchedulerService** interface for remote creation — the same TCP-135-plus-dynamic-port RPC shape that WMI/DCOM-based remote execution produces, and visibly different from the SMB-named-pipe shape that `sc.exe`'s SVCCTL remote service control and Impacket-style `psexec`/`smbexec`/`wmiexec` all use. **Caveat:** no single source consulted for this note states in so many words "schtasks.exe always uses ITaskSchedulerService, never ATSvc" — that conclusion is inferred from schtasks.exe's Task Scheduler 2.0 XML output plus the interface's own Vista-and-later framing in the MS-TSCH spec, not quoted verbatim from one document. What is independently confirmed: public tooling that specifically targets the **older** ATSvc/SASec pipe (e.g., Impacket's `atexec.py`, not yet built as its own folder in this module) exists precisely because that legacy interface is still present and produces a different, SMB-445-based network signature than a modern `schtasks.exe /s` invocation — worth knowing if a hunt built around this note's network-layer guidance in `05 - Detection and Hunting.md` sees the "wrong" transport for a given tool.

**5. The RunLevel and run-as identity model.** A task's `<Principal>` carries both **who** it runs as (`/ru`) and **at what privilege level** (`/rl LIMITED` or `/rl HIGHEST`) — per Microsoft's own `/create` and `/change` references, **`LIMITED` is the documented default** for `/rl` if omitted. A task created with `/ru SYSTEM` runs as `NT AUTHORITY\SYSTEM` regardless of the privilege level of the account that *created* it (subject to that creating account being an administrator in the first place — creating any task, of any run-as identity, requires local/remote Administrators-group membership). This is the mechanic behind the SYSTEM-context execution and privilege-escalation use cases below.

```
Local creation → later, unrelated-in-time trigger fire:

  operator ──▶ schtasks.exe /create /tn ... /tr ... /sc <trigger> /ru <identity>
                    │
                    └─▶ (schtasks.exe exits immediately — task now sits in the
                          Task Scheduler's queue, on disk as XML, and in TaskCache)

  ... time passes — possibly across reboots, possibly months later ...

  Task Scheduler service (svchost.exe -k netsvcs -p -s Schedule)
                    │
                    └─▶ trigger condition is met (logon / boot / time / idle / event)
                              │
                              └─▶ spawns the /tr target as a DIRECT CHILD of THIS
                                        svchost.exe instance — NOT of schtasks.exe,
                                        and (Windows 10 1511+) NOT of taskeng.exe

Remote creation for lateral movement:

  attacker host ──▶ schtasks.exe /create /s <target> /tn ... /tr ... /ru SYSTEM
                    │  (RPC — ITaskSchedulerService interface, ncacn_ip_tcp,
                    │   TCP 135 endpoint-mapper query → dynamic high port)
                    ▼
              [ network ]
                    ▼
  target host: Task Scheduler service registers the task exactly as it would
               a locally-created one — same XML file, same TaskCache entry,
               same eventual svchost.exe-child execution model as above
```

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique | [T1053.005 — Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/), tactics **Execution**, **Persistence**, **Privilege Escalation** (no dedicated Lateral Movement tag, despite real-world lateral-movement usage) |
| Related technique classes | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) (payload must be staged separately — see How It Works §2), [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/) (remote creation requires a real admin credential), [T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/) (task naming/binary-rename variants) |
| Local RPC/COM path | `ITaskService`/`ITaskFolder`/`ITaskDefinition` COM interfaces — the same API `schtasks.exe` itself calls under the hood locally, and the path PowerShell's `ScheduledTasks` module and custom tooling can call directly to register a task **without ever invoking `schtasks.exe` as a process** (see `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`'s own note on this evasion property) |
| Remote transport — legacy | **ATSvc / SASec** RPC interfaces, `ncacn_np` (named pipe `\PIPE\atsvc`, carried over SMB/TCP 445) — the interface `at.exe`-era tooling and some third-party tools (e.g., Impacket's `atexec.py`) target |
| Remote transport — modern | **ITaskSchedulerService** RPC interface, `ncacn_ip_tcp` (direct TCP, dynamic port resolved via the RPC endpoint mapper on TCP 135) — the interface `schtasks.exe /s` is understood to use for Task Scheduler 2.0 XML tasks, per [MS-TSCH's own transport specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/400d77fe-2f1a-4a8e-a90b-a8f82fad5a20) |
| Authentication (remote) | RPC-layer Negotiate/Kerberos or NTLM (`RPC_C_AUTHN_GSS_NEGOTIATE`/`RPC_C_AUTHN_WINNT`), authentication level Packet Privacy preferred — per MS-TSCH; the calling account must be a member of the target's local **Administrators** group, and cross-domain use of `/u` requires the same-domain-or-trusted-domain relationship Microsoft documents for `/create` |
| Execution mechanism (trigger fire) | A direct child process of the Task Scheduler service host — **`taskeng.exe` before Windows 10 Version 1511**, **`svchost.exe -k netsvcs -p -s Schedule` from Version 1511 onward** (verified against Nasreddine Bencherchali's process-hierarchy research); COM-Handler task actions are instead hosted by `taskhostw.exe` |
| Binary location | `C:\Windows\System32\schtasks.exe` and `C:\Windows\SysWOW64\schtasks.exe`, per LOLBAS's `Full_Path` listing |

## Command-Line Switches — Quick Reference

Verified against Microsoft Learn's per-sub-command `schtasks` reference pages ([`create`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create), [`change`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-change), [`delete`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-delete), [`run`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-run), [`end`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-end), [`query`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query)) and the [LOLBAS Project's `Schtasks.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Schtasks.yml). `schtasks` with no sub-command is a documented alias for `schtasks /query`.

**`/create` — register a new task (the abuse-critical sub-command)**

| Switch | Plain-English meaning |
|---|---|
| `/sc <type>` | **Required.** Schedule type: `MINUTE`, `HOURLY`, `DAILY`, `WEEKLY`, `MONTHLY`, `ONCE`, `ONSTART` (boot), `ONLOGON` (any/specific user logon), `ONIDLE`, `ONEVENT` (fires on a matching Windows event-log entry) |
| `/tn <taskname>` | **Required.** Task name, up to 238 characters; `/tn "<folder>\<name>"` files it into a Task Scheduler Library subfolder |
| `/tr <taskrun>` | **Required.** Full path to the executable/script/batch file to run. If no path is given, assumes `<systemroot>\System32` — **does not fetch or drop anything itself**, the target must already exist |
| `/s <computer>` | Targets a remote computer by name or IP. Default is the local computer — **this is the remote-creation/lateral-movement switch** |
| `/u [domain\]user` | Credentials used to **schedule** the task on a remote computer (must be Administrators-group member there). Valid only with `/s` |
| `/p <password>` | Password for `/u`. If omitted, `schtasks` prompts interactively |
| `/ru {[domain\]user \| system}` | Identity the task **runs as** once triggered — independent of who scheduled it. `system`/`""`/`"NT AUTHORITY\SYSTEM"` all mean the SYSTEM account, per Microsoft's `/change` reference |
| `/rp <password>` | Password for the `/ru` account. Not used/needed for `/ru system` — the SYSTEM account has no password |
| `/mo <modifier>` | How often within the schedule type (e.g., every *n* minutes/hours/days/weeks/months, or `LASTDAY`, `FIRST`/`SECOND`/`THIRD`/`FOURTH`). **Documented defaults: 1 for MINUTE/HOURLY/DAILY/WEEKLY** |
| `/d <day>[,<day>...]` | Day-of-week (`WEEKLY`) or day-of-month (`MONTHLY`) restriction |
| `/m <month>[,<month>...]` | Month restriction for `MONTHLY` schedules; default `*` (every month) |
| `/i <idletime>` | Minutes of idle time required — mandatory with, and only valid with, `ONIDLE` |
| `/st <starttime>` | Start time, 24-hour `HH:mm`. Default is the current local time |
| `/ri <interval>` | Repetition interval in minutes (1–599940). **Default 10 minutes** if `/et` or `/du` is also specified |
| `/et <endtime>` / `/du <duration>` | End time or maximum duration for a `MINUTE`/`HOURLY` schedule's repeating window |
| `/k` | Kills the running task program once `/et`/`/du` is reached (only valid alongside them) |
| `/sd <startdate>` / `/ed <enddate>` | Start/end date bounding the whole schedule. Defaults to the current date / no end date |
| `/ec <channelname>` | Event-log channel to match for `ONEVENT` schedules — the fileless-adjacent, event-triggered persistence pattern documented in `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` |
| `/it` | Interactive-only: only runs while the `/ru` user is logged on locally. Cannot later be removed via `/change` |
| `/np` | No password stored — task runs non-interactively with access to local resources only |
| `/z` | Deletes the task automatically once its schedule completes — a self-cleaning task, useful for minimizing the post-execution filesystem/registry footprint |
| `/xml <xmlfile>` | Creates the task from a pre-built XML file instead of assembling one from switches — the vector for importing a fully custom `<Actions>`/`<Triggers>` definition, including a `<ComHandler>` action type not exposed by the switch-based form at all |
| `/v1` | Creates a task in the older, pre-Vista-compatible format. Not usable with `/xml` |
| `/f` | Suppresses the "task already exists" confirmation prompt — overwrites silently |
| `/rl <level>` | Run level: `LIMITED` (default) or `HIGHEST` |
| `/delay <delaytime>` | Delay (mmmm:ss) before running after an `ONSTART`/`ONLOGON`/`ONEVENT` trigger fires |
| `/hresult` | Returns the process exit code in HRESULT format rather than a plain integer |

**`/change` — modify an existing task in place**

| Switch | Plain-English meaning |
|---|---|
| `/tn <taskname>` | **Required.** Task to modify — the task **name itself cannot be changed** |
| `/tr <taskrun>` | Replaces the program the task runs — **the "hijack an existing trusted task" primitive**: swap the action of a task that already has a SYSTEM run-as identity and an innocuous-looking trigger, without creating a new task at all |
| `/ru` / `/rp` | Change the run-as identity/password |
| `/ENABLE` / `/DISABLE` | Toggles the task without deleting it |
| `/it` | Adds the interactive-only property (cannot be removed once set via `/change`) |
| `/rl`, `/st`, `/ri`, `/et`, `/du`, `/k`, `/sd`, `/ed`, `/z` | Same meanings as the `/create` equivalents, updated in place |

**`/delete`, `/run`, `/end`, `/query`, `/showsid`**

| Switch | Plain-English meaning |
|---|---|
| `/delete /tn {<taskname> \| *}` | Removes a task (or, with `*`, **every task on the system**, including other users' tasks) from the schedule. `/f` suppresses the confirmation prompt. Does not stop a currently-running instance of the task's program |
| `/run /tn <taskname>` | Starts the task **immediately**, ignoring its configured schedule — uses the task's already-saved program path, run-as identity, and password. Does not change the task's next scheduled run time |
| `/end /tn <taskname>` | Stops the running instance of the program **that this specific task started** — not a general process-kill (use `taskkill` for that) |
| `/query [/fo TABLE\|LIST\|CSV] [/nh] [/v] [/tn <taskname>] [/xml]` | Lists task(s). `/v` (List/CSV only) adds full advanced properties; `/xml` dumps the full task definition XML to stdout — a fast way to exfiltrate every task's `<Actions>`/`<Principal>` content from a remote host in one call |
| `/showsid /tn <taskname>` | Computes and displays the task's associated security identifier, in the form `NT TASK\<task-name-with-\-replaced-by-->` — used when a task runs as `NETWORK SERVICE`/`LOCAL SERVICE` and needs its own SID-scoped ACL entries. **The task does not need to exist for this to return a result** — the SID is deterministically derived from the name string alone |

**Shared remote-connection switches** (`/s`, `/u`, `/p`) apply identically to `/create`, `/change`, `/delete`, `/run`, `/end`, and `/query` — every sub-command in this table can target a remote host.

## Quick Use-Case List

- Local persistence via a logon/boot/idle trigger (`ONLOGON`/`ONSTART`/`ONIDLE`)
- Recurring short-interval execution to keep a reverse shell or C2 beacon session alive (LOLBAS's own documented technique)
- Remote task creation for lateral movement — push and run a task on another host in one command (LOLBAS's other documented technique; also MITRE's Operation CuckooBees/Earth Lusca/BRONZE BUTLER pattern)
- SYSTEM-context execution/privilege escalation via `/ru SYSTEM` or `/ru ""`
- XML-based stealth task import via `/xml` — avoids exposing `/tr` as a literal command-line argument and can smuggle in a `<ComHandler>` action type the switch-based form doesn't expose
- Event-triggered, fileless-adjacent persistence via `/sc onevent /ec <channel>`
- Interactive-only (`/it`) task scoped to fire only while a specific compromised user session is active
- Task deletion/cleanup via `/delete` — removing evidence of a used persistence/lateral-movement task
- Query/enumeration for recon — `/query /v` locally or against a remote host to map existing tasks, run-as identities, and (via `/xml`) full task content
- Immediate ad hoc execution via `/run` — trigger a task's action right now without waiting for its schedule
- Stopping a runaway or now-unwanted task's live process via `/end`
- Hijacking an existing legitimate task's action via `/change /tr` — reusing a trusted task's SYSTEM identity and innocuous trigger instead of creating a new, more conspicuous one
- Renamed or relocated binary to dodge simple image-name detections
- Fleet-wide/mass use — the same remote-creation command pushed near-identically across many hosts via C2 tasking
- Legitimate-baseline contrast — the overwhelming majority of scheduled tasks on any Windows host are Microsoft/vendor-authored and entirely benign

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target (local use) | Any existing foothold that can run a command line. `schtasks.exe` is not itself an initial-access vector |
| Privilege level — local creation | Creating a task under your **own** identity requires no special privilege; creating a task that runs as a **different** user or as SYSTEM (`/ru`) requires the creating account to already be an administrator |
| Privilege level — remote creation (`/s`) | The account used (current session, or explicit `/u`) **must be a member of the Administrators group on the remote computer**, per Microsoft's own `/create` documentation |
| Domain trust (for `/u` specifically) | The local computer must be in the same domain as the remote computer, or in a domain the remote computer's domain trusts — otherwise the remote computer cannot authenticate the specified account, and Microsoft's own docs show this failing silently into an empty, non-functional task rather than an outright error |
| Network reachability (remote use) | TCP 135 (RPC endpoint mapper) plus the resulting dynamic high TCP port for the modern `ITaskSchedulerService` interface; TCP 445 (SMB) for the legacy `ATSvc`/`SASec` named-pipe interface some third-party tooling targets instead |
| Payload already staged | `/tr`'s target program/script must already exist at the given path (locally or via UNC) at the moment the task fires — `schtasks.exe` does not deliver it |
| OS version | Windows XP/Server 2003 onward for the tool itself; Task Scheduler 2.0 XML-based tasks from Vista onward; the `svchost.exe`-hosts-the-action execution model from Windows 10 Version 1511 onward (pre-1511, `taskeng.exe` is the correct parent to expect instead) |
