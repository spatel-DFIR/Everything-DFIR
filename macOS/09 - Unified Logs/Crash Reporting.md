# Unified Logs – Crash Reporting

How macOS records **crashes, hangs/spins, and kernel panics** in the Unified Logs, and where the full crash **reports** live on disk. Crash logs aren't just for buggy software — **malware crashes too**, and failed **exploit attempts** leave footprints. Repeated crashes of a process, crashes in an unexpected binary, or panics during suspicious activity are all leads.

> 🔴 An absent process that keeps **crashing**, or a binary crashing in `/tmp`/`~/Library`, is a strong IOC. Exploit attempts often show as crashes/exceptions in the **target** process right before code execution.

> Kernel panic as a *live kernel log signal* is also in the System and Kernel Events note; here we cover the crash-reporting framework and the on-disk report artifacts.

## Contents
- [Quick Triage](#quick-triage)
- [Handles](#handles)
- [CrashReporter Logs](#crashreporter-logs)
- [Crashes and Exceptions](#crashes-and-exceptions)
- [Spindump Hangs and Spins](#spindump-hangs-and-spins)
- [diagnosticd](#diagnosticd)
- [Kernel Panics](#kernel-panics)
- [On-Disk Crash Reports](#on-disk-crash-reports)
- [Live Streaming and Preserving](#live-streaming-and-preserving)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate 'eventMessage CONTAINS "crash" OR eventMessage CONTAINS "exception"' --last 24h

ls -lt /Library/Logs/DiagnosticReports/ ~/Library/Logs/DiagnosticReports/ 2>/dev/null

log show --predicate 'eventMessage CONTAINS "panic" OR subsystem == "com.apple.kext"' --last 24h
```

---

## Handles

| Area | Handle |
|---|---|
| Crash-reporting framework | `subsystem == "com.apple.crashreporter"` (process `ReportCrash`) |
| Crash / exception keywords | `eventMessage CONTAINS "crash" OR eventMessage CONTAINS "exception"` |
| Hangs / spins | `process == "spindump"` |
| Diagnostic coordination | `process == "diagnosticd"` |
| Kernel panics | `eventMessage CONTAINS "panic"`; `subsystem == "com.apple.kext"` |

---

## CrashReporter Logs

```bash
# CrashReporter subsystem logs (last 24 hours)
log show --predicate 'subsystem == "com.apple.crashreporter"' --last 24h
```

🔴 Shows which processes crashed and when. `ReportCrash` writes the full report to `DiagnosticReports` (below). Correlate crash times with logins, downloads, or exploit delivery.

---

## Crashes and Exceptions

```bash
# Crash or exception keywords (last 24 hours)
log show --predicate 'eventMessage CONTAINS "crash" OR eventMessage CONTAINS "exception"' --last 24h
```

| Signal | Meaning |
|---|---|
| 🔴 Repeated crashes of the **same** process | Unstable malware, failed persistence, or beaconing that keeps dying |
| 🔴 Crash in a binary under `/tmp`, `~/Library`, `/Users/Shared` | Dropped payload misbehaving |
| Exceptions in a **targeted** app (browser, Office, viewer) | Possible exploit attempt against it |
| `EXC_BAD_ACCESS` / `EXC_CRASH` bursts | Memory corruption — exploitation or instability |

---

## Spindump Hangs and Spins

`spindump` samples processes that **hang/spin** (unresponsive).

```bash
# spindump references (hung processes / spins)
log show --predicate 'process == "spindump"' --last 24h
```

🔴 A process spinning at high CPU can be malware (mining, brute-forcing, packing) or an app being exploited. Spindump reports land in `DiagnosticReports` as `*.spin`/`*.hang`.

---

## diagnosticd

`diagnosticd` coordinates diagnostic/crash data collection.

```bash
# diagnosticd logs (coordinates crash/diagnostic data)
log show --predicate 'process == "diagnosticd"' --last 24h
```

> Useful to see when diagnostic captures (incl. sysdiagnose) were triggered and what they covered.

---

## Kernel Panics

```bash
# Kernel panics (keyword + kext subsystem)
log show --predicate 'eventMessage CONTAINS "panic" OR subsystem == "com.apple.kext"' --last 24h
```

🔴 Repeated panics can mean a **rogue/buggy kext**, kernel-level exploitation, or hardware fault. The full panic report is written to `DiagnosticReports/*.panic`. (For the live kernel-message side of panics, see System and Kernel Events.)

---

## On-Disk Crash Reports

The reports themselves survive **far longer** than the rolling Unified Log buffer — always collect them.

| Path | Holds |
|---|---|
| 🔴 `/Library/Logs/DiagnosticReports/` | System-wide crash/panic/spin reports |
| 🔴 `~/Library/Logs/DiagnosticReports/` | Per-user app crash reports |
| `…/DiagnosticReports/Retired/` | Older rotated-out reports |

Report extensions:

| Ext | Type |
|---|---|
| `.ips` | Modern crash report (JSON) — current macOS |
| `.crash` | Legacy crash report (text) |
| `.panic` | Kernel panic report |
| `.spin` / `.hang` | Spindump (unresponsive process) |
| `.diag` / `.wakeups` / `.cpu_resource` | Resource/diagnostic reports |

```bash
# List recent reports (newest first)
ls -lt /Library/Logs/DiagnosticReports/ ~/Library/Logs/DiagnosticReports/ 2>/dev/null

# Read a modern .ips report (line 1 = JSON summary header; rest = JSON body)
head -1 ~/Library/Logs/DiagnosticReports/<name>.ips | jq .          # quick metadata (app, version, time)

tail -n +2 ~/Library/Logs/DiagnosticReports/<name>.ips | jq '{proc:.procName, path:.procPath, parent:.parentProc, responsible:.responsibleProc, signal:.exception, reason:.termination}'

# Find reports for a specific (suspicious) process
grep -rl "suspicious_proc" /Library/Logs/DiagnosticReports/ ~/Library/Logs/DiagnosticReports/ 2>/dev/null
```

🔴 Each report contains the **process path, parent, responsible process, signing info, faulting thread, and binary images loaded** — rich IOCs (path, hashes via signing, injected dylibs).

---

## Live Streaming and Preserving

```bash
# Monitor crash-related events in real time (resource-intensive)
log stream --predicate 'subsystem == "com.apple.crashreporter" OR eventMessage CONTAINS "crash"' --info

# Preserve crash-related logs
log show --predicate 'subsystem == "com.apple.crashreporter" OR process == "spindump" OR process == "diagnosticd"' --last 24h > crash_logs_snapshot.txt

# ALSO copy the on-disk reports (survive rollover)
cp -R /Library/Logs/DiagnosticReports /evidence/DiagnosticReports_system

cp -R ~/Library/Logs/DiagnosticReports /evidence/DiagnosticReports_user
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Repeated crashes of the same process | Unstable malware / failing persistence |
| Crash report for a binary in `/tmp`, `~/Library`, `/Users/Shared` | Dropped payload misbehaving |
| Exceptions in a targeted app right before new activity | Exploit attempt → code execution |
| Crash report for a process that **no longer exists on disk** | Malware ran then self-deleted (report = proof) |
| Report shows injected/unexpected **dylib** in binary images | Code injection |
| Repeated **kernel panics** | Rogue kext / kernel exploitation |
| Process **spinning** at high CPU (spindump) | Miner / brute-forcer / packer |
| DiagnosticReports recently **cleared** | Anti-forensics |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
