# LOLBins — bitsadmin.exe — Target Evidence

Evidence left on the **target/victim** host, where every technique in this note actually executes. Because the real work happens inside the BITS service rather than `bitsadmin.exe` itself, the strongest evidence classes here are the **BITS-Client operational event log** and the **BITS queue database (QMGR)** the service maintains independent of the calling process — both of which persist even after `bitsadmin.exe` has long since exited.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Abuse from Legitimate BITS Use](#distinguishing-abuse-from-legitimate-bits-use)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Explicit output file | Whatever `localname` path the operator gave to `/addfile` or `/transfer` — no fixed naming convention, entirely operator-controlled |
| **BITS queue database (QMGR)** | `C:\ProgramData\Microsoft\Network\Downloader\` — holds the service's own job/file/state database. On current Windows releases this is an ESE database (commonly referenced as `qmgr.db`, alongside log files); older systems used `qmgr0.dat`/`qmgr1.dat`. **Verified against community DFIR tooling and research rather than an official Microsoft forensic-schema doc** — specifically ANSSI-FR's [`bits_parser`](https://github.com/ANSSI-FR/bits_parser) (built specifically to extract BITS jobs from this database) and Mandiant/FireEye's "Back in a BITS" research on attacker use of BITS — both independently confirm the location and that it holds source URLs, local destination paths, job names/owners, and — critically — the **configured `SetNotifyCmdLine` value**, including for jobs later cancelled or deleted, recoverable from slack space/transaction logs |
| Downloaded/copied payload | Wherever the job's `localname` pointed, once `/complete` has run (a job stuck at `TRANSFERRED` without a completed `/complete` call hasn't released the file to that path yet — check job state, not just file presence) |
| ADS technique output | `<hostfile>:<streamname>` — invisible to a default directory listing; requires `Get-Item -Stream *` (PowerShell) or `dir /r` to enumerate. See `Windows/08 - Deleted Items and File Existence.md` for the general ADS-enumeration technique this note doesn't re-derive |
| Prefetch | `BITSADMIN.EXE-<HASH>.pf` updates on every run — **low-uniqueness on its own**, but unlike `certutil.exe`, legitimate `bitsadmin.exe` invocations by an interactive user are rare on most estates (Windows Update/WSUS/SCCM call the BITS API directly, not via the CLI), so a Prefetch hit for this specific binary is a meaningfully stronger baseline signal here than for `certutil`. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `bitsadmin.exe` executions — same corroboration role as Prefetch. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | Not verified either way for BITS-downloaded files against Microsoft's documentation reviewed for this note — unlike a browser download, no source consulted here confirms BITS applies a Mark-of-the-Web `Zone.Identifier` stream to files it transfers. Treat this as unconfirmed rather than assuming either outcome |

## Registry

No `bitsadmin`/BITS-job-specific registry key was found or verified across the sources reviewed for this note (Microsoft Learn's BITS/`bitsadmin` documentation, LOLBAS, ANSSI's `bits_parser` research) beyond the **Group Policy** keys that configure service-wide BITS behavior, verified directly against Microsoft's [Group Policies for BITS](https://learn.microsoft.com/en-us/windows/win32/bits/group-policies) reference — every BITS policy lives at **`HKLM\Software\Policies\Microsoft\Windows\BITS`** (only policies actually configured appear there), including `JobInactivityTimeout` (default 90 days before an inactive job auto-cancels), `MaxDownloadTime` (default 90 days), `MaxJobsPerUser`/`MaxJobsPerMachine` (60/300 by default), and `MaxInternetBandwidth`/bandwidth-throttling policies — none of which apply to administrator or service-account contexts. These are administrative *configuration* keys, not per-job evidence artifacts — a non-default value here (e.g. a shortened inactivity timeout, or unusually high job-count ceilings) is itself worth noting as environment tampering. Per-job state (including the notify command) lives in the QMGR database above, not the registry. Treat "no distinctive per-job registry artifact" as the accurate, verified position here.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Microsoft-Windows-Bits-Client/Operational** | **3** | BITS job created — the primary "a new job exists" signal |
| Microsoft-Windows-Bits-Client/Operational | **4** | BITS job completed |
| Microsoft-Windows-Bits-Client/Operational | **5** | BITS job cancelled |
| Microsoft-Windows-Bits-Client/Operational | **59** | BITS transfer initiated |
| Microsoft-Windows-Bits-Client/Operational | **60** | BITS transfer terminated |
| Security | **4688** (Process Creation) | Captures the `bitsadmin.exe` command line verbatim if command-line auditing is enabled — shows the operator's *initial* command, but **not** the later notify-command execution, which is attributed to `svchost.exe`, not `bitsadmin.exe` |

**Caveat on the BITS-Client event IDs above:** this note could not locate an official Microsoft schema reference enumerating these specific event IDs and field names — they're verified here against a community DFIR parsing tool ([`dfir-scripts/WinEventLogs`'s `parse_evtx_BITS.py`](https://github.com/dfir-scripts/WinEventLogs)) that extracts them directly from the log's XML schema, cross-checked against multiple independent DFIR write-ups (SANS ISC's "Investigating Microsoft BITS Activity", GIAC's "BITS Forensics" paper). Treat the ID-to-meaning mapping as well-corroborated but not Microsoft-authoritative the way Security 4688 is. **This log is not enabled by default on all Windows versions** — verify `Microsoft-Windows-Bits-Client/Operational` is actually enabled (`wevtutil gl Microsoft-Windows-Bits-Client/Operational`) before relying on it in an investigation.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | Captures `bitsadmin.exe`'s initial invocation and full command line — the `/create`/`/addfile`/`/SetNotifyCmdLine`/`/resume` sequence or the one-shot `/transfer` form. **Does not** capture the later notify-command execution as a child of `bitsadmin.exe`, because there isn't one — see the next row |
| 1 (Process Create), separately | The notify-command payload itself shows up as a **new, unrelated Sysmon 1 event** with `ParentImage` = `svchost.exe` and a command line matching `-k netsvcs -s BITS` (or the equivalent service-hosting arguments) — this is the event that actually matters for catching the persistence mechanic, and it will not correlate to the original `bitsadmin.exe` PID/GUID in any parent-child chain |
| 3 (Network Connect) | Outbound HTTP/HTTPS connection for Internet-sourced transfers, attributed to the `svchost.exe` BITS service host, not to `bitsadmin.exe` |
| 11 (File Create) | Fires for the job's `localname` output path once `/complete` releases it |
| 13 (Registry Value Set) | Not expected for per-job activity, consistent with the "no verified per-job registry artifact" finding above |
| 22 (DNS Query) | Hostname resolution preceding the download, again attributed to the service host process rather than `bitsadmin.exe` |

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Proxy / firewall access logs | The HTTP(S) request itself — no `bitsadmin`-specific User-Agent string is documented/verified for this tool the way `Microsoft-CryptoAPI/10.0` is for `certutil`; correlate on destination reputation, timing, and requested filename instead |
| SMB traffic logs / Zeek `smb_files.log` | For the SMB-sourced transfer variant — file read against an internal share, visible even when no Internet egress occurs at all |
| Zeek `http.log` | Full request URI and response size for HTTP(S)-sourced jobs — useful for a fleet-wide pivot once one host's BITS-Client log confirms a suspicious source URL |
| NetFlow | A resumable, potentially long-lived or intermittent connection pattern (BITS retries and throttles) — visually different from a single short-lived GET, which can itself be a soft signal versus a one-shot downloader tool |

## Endpoint Security Product Signatures

Because `bitsadmin.exe` is a legitimate, Microsoft-signed binary and the BITS transfer mechanism itself is not inherently malicious, static file-signature detection is a non-starter — detection depends on behavioral/command-line heuristics, same as `certutil.exe`. Public detection-rule repositories carry maintained rules for exactly these patterns, cited directly from the LOLBAS Project's own `Bitsadmin.yml` detection catalog:

- **Sigma:** [`proc_creation_win_bitsadmin_download.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_bitsadmin_download.yml), [`proc_creation_win_bitsadmin_potential_persistence.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/windows/process_creation/proc_creation_win_bitsadmin_potential_persistence.yml), [`proxy_ua_bitsadmin_susp_tld.yml`](https://github.com/SigmaHQ/sigma/blob/62d4fd26b05f4d81973e7c8e80d7c1a0c6a29d0e/rules/web/proxy_generic/proxy_ua_bitsadmin_susp_tld.yml)
- **Splunk:** [`bitsadmin_download_file.yml`](https://github.com/splunk/security_content/blob/3f77e24974239fcb7a339080a1a483e6bad84a82/detections/endpoint/bitsadmin_download_file.yml)

Most mainstream EDR products carry equivalent built-in behavioral detections for the `SetNotifyCmdLine`/`/create`-`/addfile`-`/resume` command-line pattern given how long this technique has been public (documented since 2018) — the absence of an alert on a host that otherwise shows the BITS-Client-log/Sysmon pattern above is itself worth investigating.

## Memory Forensics

`bitsadmin.exe` instances run as ordinary, short-lived processes with no long-lived secrets in memory — the command-line arguments are already fully recoverable from Sysmon 1/Security 4688 if either is enabled. The more interesting memory-forensics angle here is the **BITS service host process** (`svchost.exe -k netsvcs -s BITS`) itself: since it's a long-running shared-`svchost` process, standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) is the right lens for confirming the notify-command child process's true parent, rather than trusting any renamed/spoofed parent-image claim recorded elsewhere.

## Building a Timeline

The tightest anchor sequence, per job: **BITS-Client Event ID 3 (job created) → Sysmon 1 for the initiating `bitsadmin.exe` command → Sysmon 22/3 (DNS/network connect, HTTP(S)-sourced jobs only, attributed to the service host) → BITS-Client Event ID 59 (transfer initiated) → Sysmon 11 (file create at the `localname` path) → BITS-Client Event ID 60/4 (transfer terminated/completed) → a SEPARATE Sysmon 1 event for the notify-command payload, `ParentImage` = `svchost.exe` → Security 4688 corroboration where command-line auditing is enabled.** For a persistence-oriented job, the gap between "job created" (Event ID 3) and "notify command fires" (the separate Sysmon 1 event) can span hours to weeks — **do not assume these two events are close together in time**; recovering the job's GUID from either event and pivoting through the QMGR queue database is what ties them together definitively when the BITS-Client log has rolled over or wasn't enabled at creation time.

## Distinguishing Abuse from Legitimate BITS Use

> 🔴 A BITS-Client Event ID 3 (job created) alone is not a finding — Windows Update, WSUS, and enterprise deployment tooling create BITS jobs constantly and legitimately on any managed estate. **The presence and target of a `SetNotifyCmdLine` value, and the job's source URL/share, are the actual signal.**

| Dimension | Legitimate BITS use | Abuse (this note) |
|---|---|---|
| Job creator | Windows Update Agent, WSUS client, SCCM/deployment-tool service account — almost never an interactively-run `bitsadmin.exe` | `bitsadmin.exe` invoked directly by a user, script, or C2 implant |
| Source URL/share | Microsoft Update endpoints, or an internal, known-good software-distribution share | Attacker-controlled Internet infrastructure, or an unexpected/unauthorized internal share |
| `SetNotifyCmdLine` value | Rare in ordinary use, and when present, points at a legitimate signed application's own update-completion handler | Points at `cmd.exe`, a script interpreter, or the downloaded payload itself |
| Job owner | SYSTEM or a well-known service account | An interactive user account or a service-account context inconsistent with that host's normal deployment tooling |
| Job priority | Typically NORMAL or unset, matching deployment-tool defaults | Frequently `LOW` (stealth) when the operator has deliberately chosen to throttle for OPSEC reasons — see the Hunting Priority table in `05 - Detection and Hunting.md` |
