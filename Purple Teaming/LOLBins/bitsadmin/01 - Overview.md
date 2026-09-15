# LOLBins — bitsadmin.exe — Overview

> 🔴 **Red Flag Principle:** `bitsadmin.exe` isn't the process that does the actual work — it's a thin control-plane client that hands a job to the **BITS service** (`svchost.exe -k netsvcs -s BITS`, backed by `qmgr.dll`) and can then exit immediately. The download, the retry logic, and — critically — the **`SetNotifyCmdLine` payload execution on job completion/error** all happen later, asynchronously, as activity of the BITS service host, not as a child process of `bitsadmin.exe`. An analyst who hunts for "what did `bitsadmin.exe` spawn" will typically find nothing, because by the time the notify command fires — possibly minutes, hours, or (since jobs default to a 90-day inactivity timeout) days after the operator typed the command — `bitsadmin.exe` is long gone. The real parent process of the notify-command payload is `svchost.exe` hosting the BITS service, confirmed directly in MITRE ATT&CK's own T1197 detection guidance. That parent-process mismatch is the single most distinctive tell for this technique.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`bitsadmin.exe` is a native Windows command-line front-end for the **Background Intelligent Transfer Service (BITS)**, a first-party Windows OS component (not a third-party or offensive-security-authored tool). Per Microsoft's own current documentation:

> "Bitsadmin is a command-line tool used to create, download or upload jobs, and to monitor their progress. The bitsadmin tool uses switches to identify the work to perform."
> — [Microsoft Learn, `bitsadmin` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin)

**Deprecation status — verify before assuming it's gone:** Microsoft's Windows Server command reference page for `bitsadmin` carries no formal deprecation banner as of this writing, but the tool itself emits a runtime deprecation warning when invoked — quoted directly from a user's reported console output on Microsoft Q&A: *"Bits admin may be deprecated and is not guaranteed to be available in future windows versions. Administrative tools for BITS are now provided by BITS PowerShell cmdlets."* ([Microsoft Q&A, "Bits deprecated"](https://learn.microsoft.com/en-us/answers/questions/2619972/bits-deprecated)). Microsoft's own `BitsTransfer` PowerShell module documentation (`Start-BitsTransfer`, `Get-BitsTransfer`, `Complete-BitsTransfer`, `Import-Module BitsTransfer`) is the actively-documented current path — see [Using Windows PowerShell to Create BITS Transfer Jobs](https://learn.microsoft.com/en-us/windows/win32/bits/using-windows-powershell-to-create-bits-transfer-jobs). **Bottom line: `bitsadmin.exe` still ships and still works on current Windows releases, but treat it as legacy/unsupported tooling that could be pulled from a future release rather than a permanently guaranteed binary** — this note's abuse techniques are unaffected either way, since the target is whatever machine still has it.

The tool's exact origin date isn't spelled out in Microsoft's current docs (unlike `certutil.exe`'s archived Windows Server 2003 documentation, which this module's `LOLBins/certutil/` entry was able to cite directly) — BITS as a Windows service predates Vista, but the earliest OS version the community-maintained [**LOLBAS Project**](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/) (`LOLBAS-Project/LOLBAS` on GitHub) verifies its abuse techniques against is **Windows Vista through Windows 11**. Treat Vista as the verified floor for the techniques in this note, not necessarily the tool's ship date.

`bitsadmin.exe`'s abuse as a LOLBIN was first catalogued by the LOLBAS Project on **2018-05-25**, authored by **Oddvar Moe** (`@oddvarmoe`), with technique acknowledgement credited to **Rob Fuller** (`@mubix`) and **Chris Gates** (`@carnal0wnage`) — verified directly against LOLBAS's current [`Bitsadmin.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Bitsadmin.yml) source, which is what this note's abuse-technique syntax and MITRE ATT&CK mappings are cross-checked against.

## How It Works

Unlike `certutil.exe`'s single-process download/encode model, `bitsadmin.exe`'s abuse surface is inseparable from the **BITS job lifecycle** — a stateful, asynchronous, resumable transfer object managed entirely by the BITS service, not by the `bitsadmin.exe` process itself.

**1. The client/service split.** `bitsadmin.exe` is a thin COM client over the `IBackgroundCopyManager`/`IBackgroundCopyJob` interfaces. Every meaningful verb (`/create`, `/addfile`, `/resume`, `/complete`) is a short-lived RPC/COM call into the **BITS service** — Windows Service short name `BITS`, hosted in a shared `svchost.exe -k netsvcs -s BITS` process backed by `qmgr.dll`. Once `/resume` is issued, `bitsadmin.exe` can exit; the job keeps running (or waiting) inside the service, independent of whether the process or even the operator's logon session that created it still exists (subject to the user/network-connection constraints in the Prerequisites table below).

**2. Job lifecycle — states and transitions.** Per Microsoft's own [Life Cycle of a BITS Job](https://learn.microsoft.com/en-us/windows/win32/bits/life-cycle-of-a-bits-job) reference, every job moves through four state classes — **starting, action, transferred, final** — driven by four state-changing methods (`Suspend`, `Resume`, `Cancel`, `Complete`, exposed by `bitsadmin` as `/suspend`, `/resume`, `/cancel`, `/complete`):

```
                 /create                      /resume
                    │                            │
                    ▼                            ▼
              ┌───────────┐   /addfile     ┌───────────┐
              │ SUSPENDED │ ─────────────▶ │  QUEUED   │◀────────────────┐
              │ (start)   │   (add files,  └─────┬─────┘                 │
              └───────────┘    set props)        │ scheduler's turn      │ retry after
                    ▲                             ▼                      │ TRANSIENT_ERROR
                    │                       ┌───────────┐                │
              /suspend anytime              │CONNECTING │                │
                    │                       └─────┬─────┘                │
                    │                             ▼                      │
                    │                       ┌─────────────┐              │
                    └───────────────────────│ TRANSFERRING│              │
                                             └──────┬──────┘              │
                                     all files OK   │    transfer fails   │
                                    ┌────────────────┴───────────┐        │
                                    ▼                             ▼       │
                            ┌──────────────┐            ┌──────────────────┐
                            │ TRANSFERRED  │            │ TRANSIENT_ERROR  │──┘
                            └──────┬───────┘            └────────┬─────────┘
                                   │                     no-progress timeout
                        /complete  │                     exceeded (SetNoProgressTimeout)
                                   ▼                              ▼
                            ┌──────────────┐            ┌──────────────┐
                            │ ACKNOWLEDGED │            │    ERROR     │
                            │  (FINAL)     │            └──────┬───────┘
                            └──────────────┘          /cancel  │  /complete (retry via resume)
                                                                ▼
                                                        ┌──────────────┐
                                                        │  CANCELLED   │
                                                        │  (FINAL)     │
                                                        └──────────────┘
```

Key mechanics an analyst needs, all verified against Microsoft's lifecycle reference:

- **`/create`** starts a job in the `SUSPENDED` state — no transfer happens until `/resume` is called.
- **`/addfile <job> <remoteURL> <localname>`** attaches one file to the job; the `remoteURL` must be an HTTP, HTTPS, or SMB path (upload jobs may only carry one file).
- **`/resume`** moves the job from `SUSPENDED` to `QUEUED`, then the BITS scheduler advances it through `CONNECTING` → `TRANSFERRING` on a round-robin, time-sliced basis alongside other jobs at the same priority.
- **`/complete`** is the step that actually makes a downloaded file available on disk and moves the job to the final `ACKNOWLEDGED` state — a job stuck at `TRANSFERRED` without a `/complete` call has already pulled the bytes but hasn't released them to the target path yet.
- **`/cancel`** deletes all downloaded/partial files and moves the job to `CANCELLED` — **capture evidence before doing this** (see `05 - Detection and Hunting.md`'s Remediation section).
- Jobs left unresolved don't linger forever: **BITS automatically cancels jobs after a default `JobInactivityTimeout` of 90 days**, per Microsoft's own lifecycle documentation — a real, if generous, upper bound on how long an abandoned or forgotten malicious job can persist in the queue.

**3. The `SetNotifyCmdLine` persistence/execution mechanic.** `bitsadmin /SetNotifyCmdLine <job> <program> [parameters]` registers a program to run when the job enters a notification-triggering state (see `/SetNotifyFlags` below) — normally intended for a legitimate app to get notified its download finished. Set on a job whose target file is `cmd.exe`, a script interpreter, or the payload itself, this becomes **arbitrary code execution triggered by the BITS service, not by the operator directly** — and because it fires on job completion *or error*, and jobs can sit `QUEUED`/`TRANSFERRING`/in `TRANSIENT_ERROR` for a long time (up to the 90-day inactivity ceiling), this doubles as a persistence mechanism that survives reboots: the BITS service reloads its job queue from disk on every service start and resumes evaluating notification triggers. MITRE ATT&CK's own T1197 detection guidance names the exact process-tree signature this produces: **"BITS launches a notify command (SetNotifyCmdLine) from `svchost.exe -k netsvcs -s BITS`, often establishing persistence by keeping long-lived jobs."**

```
Persistence / delayed-execution chain:

  operator/script ──▶ bitsadmin.exe /create, /addfile, /SetNotifyCmdLine, /resume
                            │
                            └─▶ (bitsadmin.exe exits — nothing further to see here)

  ... time passes (job is QUEUED/TRANSFERRING/TRANSIENT_ERROR, possibly across reboots) ...

  BITS service (svchost.exe -k netsvcs -s BITS, qmgr.dll)
                            │
                            └─▶ job reaches a notify-triggering state
                                        │
                                        └─▶ spawns <program> <parameters> as a CHILD OF svchost.exe
                                                  (NOT of bitsadmin.exe — which is long gone)
```

**4. The BITS service's own startup behavior.** Per Microsoft's [BITS Startup Type](https://learn.microsoft.com/en-us/windows/win32/bits/bits-startup-type) reference: *"The Startup Type for BITS is delayed auto-start (if there are active BITS jobs) or demand start (if there are no active jobs)."* In other words, the service doesn't need to already be running for an operator's first `bitsadmin /create` to work — creating a job is itself what starts it, and the service's Startup Type flips back to demand-start once every job is completed or cancelled. This matters operationally: there's no "BITS service already running" precondition to check, and a host with zero visible BITS activity can go from cold to an active job in one command.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique (umbrella) | [T1197 — BITS Jobs](https://attack.mitre.org/techniques/T1197/), tactics **Defense Evasion** and **Persistence** |
| Transport | **HTTP, HTTPS, or SMB** — per Microsoft's [Life Cycle of a BITS Job](https://learn.microsoft.com/en-us/windows/win32/bits/life-cycle-of-a-bits-job) reference, "the remote file name must use the HTTP, HTTPS, or SMB protocol." SMB support means BITS can pull a payload from an internal file share with no Internet egress at all |
| Authentication | Runs under the identity of whoever created the job; supports the calling user's own network credentials for HTTP(S)/SMB auth — no separate BITS-specific auth model for the abuse techniques in this note |
| Payload delivery mechanism | Asynchronous, resumable, bandwidth-throttled background transfer — the same mechanism Windows Update, WSUS, and many enterprise software-deployment tools use for **legitimate** payload delivery, which is exactly what makes BITS traffic and BITS-service activity blend into normal host/network baselines |
| Execution mechanism | `SetNotifyCmdLine` — arbitrary program execution triggered by the BITS service on job completion or error, spawned as a child of `svchost.exe -k netsvcs -s BITS` |
| Process model | `bitsadmin.exe` itself is short-lived and typically exits after `/resume`; all sustained activity (transfer, retry, notify) happens inside the BITS service host, independent of the calling process's lifetime |
| Execution context | Runs as whatever user/token created the job — LOLBAS lists every technique in this note as requiring only `User` privilege, not `Administrator` (viewing/managing another user's jobs does require admin — see `/list /allusers` in the switches table) |
| Binary location | `C:\Windows\System32\bitsadmin.exe` and `C:\Windows\SysWOW64\bitsadmin.exe` — the only two legitimate install paths, per LOLBAS's `Full_Path` listing |
| Related technique classes | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) (download/copy use), [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) (notify-triggered execute-only use, per LOLBAS's mapping), [T1564.004 — Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/) (Alternate Data Stream variant) |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's `bitsadmin` reference and its per-switch pages](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bitsadmin) and the [LOLBAS Project's `Bitsadmin.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Bitsadmin.yml). `bitsadmin` exposes dozens of switches (get/set pairs for nearly every job property) — this table covers the ones relevant to job lifecycle, abuse, and hunting; it is not exhaustive of every `get*` property accessor.

**Job lifecycle**

| Switch | Plain-English meaning |
|---|---|
| `/create [type] <displayname>` | Creates a new job in the `SUSPENDED` state. `type` is `/Download` (default), `/Upload`, or `/Upload-Reply`. Returns the job's GUID |
| `/addfile <job> <remoteURL> <localname>` | Attaches one file to the job — `remoteURL` is the HTTP/HTTPS/SMB source, `localname` must be an absolute local path. Repeat per file |
| `/resume <job>` | Moves the job from `SUSPENDED`/error states into the active transfer queue |
| `/suspend <job>` | Pauses an active job — transfers stop until `/resume` |
| `/complete <job>` | Finalizes a fully-transferred job — releases the downloaded file(s) to their local path and moves the job to the final `ACKNOWLEDGED` state |
| `/cancel <job>` | Removes the job from the queue and **deletes all downloaded/partial files** — capture evidence first |
| `/reset [/allusers]` | Cancels *all* jobs owned by the current user (or, with admin rights, all users' jobs with `/allusers`) |
| `/transfer <name> [/DOWNLOAD\|/UPLOAD] [/priority <level>] <remotefilename> <localfilename>` | **One-shot synchronous alternative** to create/addfile/resume/complete — runs in the foreground, blocks until done or a critical error, and auto-completes/auto-cancels the job for you. The simplest single-line downloader form |

**Persistence / notification (the abuse-critical pair)**

| Switch | Plain-English meaning |
|---|---|
| `/SetNotifyCmdLine <job> <program> [parameters]` | Registers a program to launch (as a child of the BITS service host) when the job hits a notify-triggering state. `program` can be set to `NULL` to clear it, but then `parameters` must also be `NULL`. **This is the persistence/execution primitive** |
| `/SetNotifyFlags <job> <flags>` | Controls *which* state changes fire the notify command: `1` = job fully transferred, `2` = job errored, `3` = either transferred or errored, `4` = disable notifications entirely (values are as documented by Microsoft, not a conventional bitmask — use exactly these) |
| `/GetNotifyCmdLine <job>` / `/GetNotifyFlags <job>` | Read back the currently configured notify command/flags for a job — useful for the operator to confirm, and for a defender who has recovered a job GUID to inspect it live |

**Priority / throttling (stealth knobs)**

| Switch | Plain-English meaning |
|---|---|
| `/SetPriority <job> <FOREGROUND\|HIGH\|NORMAL\|LOW>` | Sets the job's transfer priority. Higher-priority jobs preempt lower ones; `LOW` blends a transfer into idle bandwidth behind everything else — the stealth choice for an operator who doesn't want a transfer to be conspicuous by its speed |
| `/SetMinRetryDelay <job> <seconds>` | Minimum wait time after a transient error before BITS retries the transfer — no documented default value on Microsoft's reference page; don't assume one |
| `/SetNoProgressTimeout <job> <seconds>` | How long BITS keeps retrying after the *first* transient error before giving up and moving the job to the fatal `ERROR` state — again, no documented default; the timer resets on any successful byte transferred |

**Info / monitoring**

| Switch | Plain-English meaning |
|---|---|
| `/list [/allusers] [/verbose]` | Lists jobs owned by the current user (or, with admin rights, `/allusers` for every user's jobs) |
| `/info <job> [/verbose]` | Detailed properties of a specific job |
| `/monitor` | Live-updating console view of all jobs' progress |
| `/getstate <job>` | Returns the job's current state string: `Queued`, `Connecting`, `Transferring`, `Transferred`, `Suspended`, `Error`, `Transient_Error`, `Acknowledged`, or `Canceled` |

**Job-type / misc**

| Switch | Plain-English meaning |
|---|---|
| `/util /repairservice` | Repairs/restarts the BITS service infrastructure — legitimate admin recovery action, occasionally seen in troubleshooting rather than abuse contexts |
| `/cache /list`, `/cache /info` | Inspect BITS's own peer-caching (BranchCache) content — not used by the abuse techniques in this note but worth recognizing as legitimate-baseline noise |

## Quick Use-Case List

- Baseline file download via the full `/create` → `/addfile` → `/resume` → `/complete` job lifecycle
- One-shot synchronous download via `/transfer` — the simplest single-line form
- Local file copy (source and destination both local paths) rather than a network download
- Persistence via `/SetNotifyCmdLine` — code execution on job completion/error, potentially long after creation and across reboots
- Immediate "execute" use of `/SetNotifyCmdLine` — treating the notify trigger as an execution primitive rather than a persistence one
- Payload hidden in an NTFS Alternate Data Stream, executed via the notify command
- SMB-sourced transfer — pulling a payload from an internal file share instead of the Internet, avoiding any outbound HTTP(S) at all
- Low-priority (`/SetPriority LOW`) throttled transfer to blend into idle-bandwidth background traffic
- Resuming a suspended/queued job across a reboot or user logoff/logon cycle, relying on the BITS service's own job-persistence and the up-to-90-day inactivity ceiling
- Chained downloader-then-execute one-liner, handing the fetched file to another LOLBIN or the shell for execution
- Fleet-wide/mass use — the same job created identically across many already-compromised hosts via C2 tasking
- Renamed or relocated binary to dodge simple image-name detections (general masquerading technique, not BITS-specific)
- Legitimate-baseline contrast — Windows Update, WSUS, and enterprise software-deployment tools all use BITS jobs for entirely benign reasons

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line. `bitsadmin.exe` is not itself an initial-access vector |
| Privilege level | **User** is sufficient for creating and managing your own jobs — LOLBAS lists every abuse technique in this note as requiring only `User` privilege. Viewing/managing **another user's** jobs (`/list /allusers`, `/reset /allusers`) requires administrator rights, per Microsoft's own switch documentation |
| Job persistence across sessions | A job survives BITS-service restarts and reboots, but per Microsoft's [Users and Network Connections](https://learn.microsoft.com/en-us/windows/win32/bits/users-and-network-connections) model, a job only makes progress while the creating user has an active local logon or network connection — relevant when planning a persistence use case, since a job created under a session that never logs back in may simply sit `QUEUED` |
| Network reachability | Outbound HTTP/HTTPS to the payload host, or SMB reachability to an internal file share, depending on which transport is used |
| BITS service | Starts on demand the moment a job is created (Startup Type: delayed auto-start with active jobs, demand-start otherwise) — no precondition that it already be running |
| OS version | Windows Vista through Windows 11 for every technique LOLBAS documents for this binary |
| Notify-command payload staged | For `SetNotifyCmdLine` use cases, the target program (a script interpreter, `cmd.exe`, or the payload binary itself) must already exist at the path given — `bitsadmin` doesn't drop it for you |
