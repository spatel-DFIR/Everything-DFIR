# Unified Logs – System and Kernel Events

The **Unified Logging System (ULS)** replaced ASL/syslog in **Sierra (10.12)**. It is a single, high-performance, binary, system-wide log store covering kernel, system daemons, frameworks, and apps. You query it with the **`log`** command (`log show` = historical, `log stream` = live). The forensic crux:

> 🔴 **The log buffer is ROLLING.** Persisted `.tracev3` data typically spans only **days to a couple of weeks** (heavy logging shortens it). High-value events age out fast — **collect to a file early** (`log show … > out.txt` or grab the whole store / `logarchive`).

> ⚠️ Much of the most useful detail is logged at **`info`** and **`debug`** levels, which are **NOT persisted by default** — they live only in the in-memory ring buffer. `log show` of past data will be missing them unless `--info`/`--debug` was being captured. For live work, add `--info` (and `--debug`) to see them.

## Contents
- [Quick Triage](#quick-triage)
- [Where the Data Lives](#where-the-data-lives)
- [The log Command and Modes](#the-log-command-and-modes)
- [Predicate Filtering](#predicate-filtering)
- [Kernel Events and Kexts](#kernel-events-and-kexts)
- [launchd and Service Events](#launchd-and-service-events)
- [Sandbox and AMFI Code-Signing](#sandbox-and-amfi-code-signing)
- [Boot, Shutdown, Sleep, Wake, and Power](#boot-shutdown-sleep-wake-and-power)
- [Clock and Time Changes](#clock-and-time-changes)
- [Kernel Faults](#kernel-faults)
- [Preserving Log Data](#preserving-log-data)
- [Limitations and Anti-Forensics](#limitations-and-anti-forensics)
- [Time and Triage Tips](#time-and-triage-tips)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
sudo log collect --output /evidence/host.logarchive                 # preserve FIRST

log show --predicate 'process == "kernel" AND eventMessage CONTAINS "kext"' --last 1h

kextstat | grep -v com.apple                                        # third-party kexts (live)

log show --predicate '(process == "kernel") AND (eventMessage CONTAINS "sandbox" OR eventMessage CONTAINS "AMFI")' --last 1h

log show --predicate 'eventMessage CONTAINS[c] "Previous shutdown cause"' --last 30d

log show --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "settimeofday"' --info --last 30d

log show --style syslog --last 30d | head -1                        # log-wipe check (oldest entry)
```

---

## Where the Data Lives

| Path | Holds |
|---|---|
| `/var/db/diagnostics/` | 🔴 Primary **`.tracev3`** log chunks (Persist/, Special/, Signpost/, HighVolume/) + `timesync/` |
| `/var/db/diagnostics/Persist/` | Persisted log entries (the bulk of historical data) |
| `/var/db/uuidtext/` | String/format catalogs — **required** to decode `.tracev3` (offline parsing needs both dirs) |
| `/var/db/diagnostics/timesync/` | Boot/wall-clock correlation (Mach continuous time → real time) |
| `/Library/Logs/DiagnosticReports/` | 🔴 **Kernel panics** (`*.panic`), crashes, spins — **persist far longer than ULS** (parsing → Crash Reporting note) |
| `/private/var/log/` | Legacy plaintext logs still in use (`install.log`, `system.log` (sparse), `wifi.log`, `*.asl`) |
| `/Library/Logs/`, `~/Library/Logs/` | App / DiagnosticReports crash & spin logs |

> Offline analysis needs **both** `/var/db/diagnostics` and `/var/db/uuidtext`. Best practice: collect a **logarchive** (see Preserving) so the format strings travel with the data.

---

## The log Command and Modes

| Mode | Purpose |
|---|---|
| `log show` | Query **historical** persisted log (dead-box or live) |
| `log stream` | **Live** real-time tail (resource-intensive) |
| `log collect` | Bundle current store into a `.logarchive` for offline analysis |
| `log config` | View/change subsystem logging levels |
| `log stats` | Storage stats per subsystem |
| 🔴 `log erase` | **Deletes** the persisted log store — anti-forensics; see Limitations |

Key flags: `--predicate '<filter>'` · `--last 1h|30m|7d` · `--start`/`--end "YYYY-MM-DD HH:MM:SS"` · `--info` `--debug` (include those levels) · `--style syslog|compact|json|ndjson` · `--source` (caller source info) · `--archive <path>` (query a collected archive) · `--timezone "UTC"` (force a time zone — normalize to UTC for correlation) · `--process <pid|name>` (filter to one process).

---

## Predicate Filtering

Predicates use NSPredicate syntax. Common fields:

| Field | Matches |
|---|---|
| `process` | Process name (e.g. `"kernel"`, `"launchd"`, `"sandboxd"`) |
| `processImagePath` | Full path to the process binary |
| `eventMessage` | The log message text |
| `subsystem` | Reverse-DNS subsystem (e.g. `"com.apple.launchd"`, `"com.apple.TCC"`) |
| `category` | Subsystem category |
| `senderImagePath` | Library/framework that emitted the line |
| `messageType` | `Default`/`Info`/`Debug`/`Error`/`Fault` |

Operators: `==` `!=` `&&`/`AND` `||`/`OR` · `CONTAINS` · `CONTAINS[c]` (case-insensitive) · `BEGINSWITH` · `ENDSWITH` · `LIKE` (glob `*`/`?`) · `MATCHES` (regex) · `IN { … }`.

```bash
# Template
log show --predicate '<field> <op> "<value>"' --last <time> [--info] [--style syslog]
```

> 🔴 **Private data redaction:** dynamic values often print as `<private>`. On a live box you can reveal them (research/debug) by enabling private-data logging via a config profile or `sudo log config --mode "private_data:on"` — note this is a system change; document it.

### System/Kernel quick-reference — what to query for what

| Investigative question | process / subsystem to filter on |
|---|---|
| Kernel / drivers / low-level events | `process == "kernel"` |
| Kext load/management | `kernel` + `"kext"`/`"kmod"`/`"KextManager"`; daemons `kernelmanagerd`, legacy `kextd` |
| Service start/stop/respawn | `subsystem == "com.apple.launchd"` |
| Sandbox denials | `process == "sandboxd"` or `kernel` + `"Sandbox"` |
| Code-signing / AMFI | `process == "amfid"`, `"taskgated"`; `kernel` + `"AMFI"` |
| Power / sleep / wake | `process == "powerd"`; `kernel` + `"Wake reason"` |
| Boot / shutdown | `kernel` (boot banner); `process == "shutdown"` |
| System config / network stack | `process == "configd"` |
| Kernel panics / faults | `messageType == "Fault"`; `kernel` + `"panic"` (+ DiagnosticReports) |

---

## Kernel Events and Kexts

```bash
# All kernel-process entries, last hour
log show --predicate 'process == "kernel"' --last 1h

# Kext-related kernel events
log show --predicate 'process == "kernel" AND eventMessage CONTAINS "kext"' --last 1h

# Live kernel stream (resource-intensive)
log stream --predicate 'process == "kernel"' --info

# Redirect kernel logs to a file for later analysis
log show --predicate 'process == "kernel"' --last 1h > kernel_events_last_hour.txt
```

🔴 Kext / driver hunt commands:

```bash
# Kext load/start activity (KextManager / kmod / kernelmanagerd)
log show --predicate '(process == "kernel" AND (eventMessage CONTAINS[c] "kext" OR eventMessage CONTAINS[c] "kmod" OR eventMessage CONTAINS[c] "KextManager")) OR process == "kernelmanagerd"' --info --last 7d

# Unsigned / dev-mode / AMFI-blocked kext attempts
log show --predicate 'eventMessage CONTAINS[c] "kext" AND (eventMessage CONTAINS[c] "denied" OR eventMessage CONTAINS[c] "invalid" OR eventMessage CONTAINS[c] "dev-mode" OR eventMessage CONTAINS[c] "AMFI" OR eventMessage CONTAINS[c] "not allowed")' --info --last 7d

# Live: currently loaded kexts — third-party = NOT com.apple.* (cross-ref SIP)
kextstat | grep -v com.apple

kmutil showloaded --no-kernel-components 2>/dev/null
```

| Pattern | Meaning |
|---|---|
| `kext … loaded` / `KextManager` / `kmod start` | Driver loaded — match against expected/Apple kexts |
| Non-`com.apple.*` bundle ID | 🔴 Third-party kernel code (System Extensions now preferred; legacy KEXT is suspicious on modern macOS) |
| `kext-dev-mode` / `AMFI: … kext … invalid` | 🔴 Unsigned/dev-mode kext attempt (needs SIP weakening) |
| `kext … denied` / `not allowed` | Blocked load — note what tried to load and from where |
| `IOAccelerator`, `AppleHV`, etc. | Normal Apple — baseline so anomalies stand out |

---

## launchd and Service Events

```bash
# launchd subsystem, last 30 min, human-readable
log show --predicate 'subsystem == "com.apple.launchd"' --last 30m --info --style syslog

# A specific service label spawning/exiting
log show --predicate 'subsystem == "com.apple.launchd" AND eventMessage CONTAINS[c] "<label>"' --info --last 7d

# Respawn/throttle (crashing or beaconing jobs)
log show --predicate 'subsystem == "com.apple.launchd" AND eventMessage CONTAINS[c] "throttl"' --info --last 7d
```

🔴 Hunt for: unexpected service **labels** being spawned, jobs that **respawn rapidly** ("service exited … throttling respawn"), and labels matching newly dropped LaunchAgents/Daemons.

---

## Sandbox and AMFI Code-Signing

```bash
# Kernel events referencing sandbox or AMFI (code-signing) checks
log show --predicate '(process == "kernel") AND (eventMessage CONTAINS "sandbox" OR eventMessage CONTAINS "AMFI")' --last 1h

# Code-signing daemons + library-validation failures
log show --predicate 'process == "amfid" OR process == "taskgated"' --info --last 7d

log show --predicate 'eventMessage CONTAINS[c] "Library Validation failed" OR eventMessage CONTAINS[c] "code signature"' --info --last 7d
```

| Signal | Meaning |
|---|---|
| 🔴 `AMFI: … code signature … invalid` / `Library Validation failed` | Unsigned/tampered binary or injected dylib blocked (or attempted) |
| 🔴 `AMFI: allowing … get-task-allow` / `amfid` exceptions | Debug/entitlement abuse, possible bypass |
| `Sandbox: <proc>(pid) deny(1) file-read-data …` | A sandboxed process tried something outside its profile — maps attacker probing |
| `sandboxd … deny mach-lookup` | Blocked IPC/service access |
| `taskgated`/`amfid` faults | Code-signing daemon anomalies |

> AMFI (Apple Mobile File Integrity) enforces code signing & library validation. AMFI denials are some of the highest-signal lines for spotting unsigned/injected code.

---

## Boot, Shutdown, Sleep, Wake, and Power

Anchors the timeline: each boot starts a new log epoch; reboots **re-lock FileVault** and **roll the buffer**.

```bash
# System boots (kernel boot banner — one per boot)
log show --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "Darwin Kernel Version"' --last 30d

# What woke the machine
log show --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "Wake reason"' --info --last 7d

# Sleep / wake transitions
log show --predicate '(process == "kernel" OR process == "powerd") AND (eventMessage CONTAINS[c] "sleep" OR eventMessage CONTAINS[c] "wake")' --info --last 7d

# Shutdown cause + full power-event timeline (clean vs forced)
log show --predicate 'eventMessage CONTAINS[c] "Previous shutdown cause"' --last 30d

pmset -g log | grep -Ei 'Sleep|Wake|Shutdown|Start|Charge'

# Uptime / last boots & reboots
uptime

last reboot

last shutdown
```

🔴 **Shutdown cause codes** (`Previous shutdown cause: N`):

| Code | Meaning |
|---|---|
| `5` | Clean / normal shutdown |
| `3` | 🔴 Forced — power button held / dirty shutdown |
| `0` | Power removed / hard power loss |
| `-128` | Unknown / unexpected |
| negative (e.g. `-60`, `-71`, `-86`, `-95`) | Ungraceful: dirty FS, memory/SMC fault, thermal, etc. |

> A forced/unexpected shutdown right before or during suspicious activity can indicate anti-forensics, a crash from exploitation, or someone yanking power to avoid a clean acquisition.

---

## Clock and Time Changes

Clock manipulation enables timestomping and breaks timelines — flag it.

```bash
# Wall-clock / time-of-day changes (settimeofday)
log show --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "settimeofday"' --info --last 30d

# Time-zone / clock adjustments (timed + system)
log show --predicate 'process == "timed" OR eventMessage CONTAINS[c] "time zone" OR eventMessage CONTAINS[c] "clock change"' --info --last 30d
```

> 🔴 **Backward jumps or large skews** in the timeline are red flags. Cross-check against `timesync/` (in `/var/db/diagnostics`) which records the boot/continuous-time → wall-clock mapping — manual clock edits show up as discontinuities there.

---

## Kernel Faults

Kernel **log lines** for faults live here; parsing the on-disk `*.panic`/crash reports in `/Library/Logs/DiagnosticReports` is in the Crash Reporting note.

```bash
# Kernel panic log lines
log show --predicate 'process == "kernel" AND eventMessage CONTAINS[c] "panic"' --last 30d

# Memory pressure / OOM jetsam kills (can mask crashing malware or exhaustion)
log show --predicate 'eventMessage CONTAINS[c] "memorystatus" OR eventMessage CONTAINS[c] "jetsam" OR eventMessage CONTAINS[c] "low swap"' --last 7d

# I/O errors / disk faults (failing media → acquisition urgency)
log show --predicate 'process == "kernel" AND (eventMessage CONTAINS[c] "I/O error" OR eventMessage CONTAINS[c] "media is not present" OR eventMessage CONTAINS[c] "disk0")' --last 7d

# All Errors & Faults (high-signal, narrow the window)
log show --predicate 'messageType == "Error" OR messageType == "Fault"' --last 1h
```

| Signal | Meaning |
|---|---|
| 🔴 Repeated **panics** | Possible kernel-level exploitation, bad/rogue kext, or hardware fault |
| `jetsam`/`memorystatus` killing processes | Memory exhaustion — DoS, runaway malware, or anti-analysis |
| `I/O error` / `disk0` faults | Failing disk → **image immediately**, evidence may be degrading |
| Bursts of `Error`/`Fault` around a process | Instability tied to malicious or injected code |

---

## Preserving Log Data

Beat the rolling buffer:

```bash
# Redirect a targeted query to a text file
log show --predicate 'process == "kernel"' --last 1h > kernel_events_last_hour.txt

# Collect the ENTIRE current log store into a portable archive (best for evidence)
sudo log collect --output /evidence/host.logarchive

sudo log collect --last 7d --output /evidence/host_7d.logarchive   # bounded window

# Query a collected archive (offline, on your analysis box)
log show --archive /evidence/host.logarchive --predicate 'process == "kernel"' --info

# Dead-box: copy the raw stores, then parse offline
#   /var/db/diagnostics/   AND   /var/db/uuidtext/   (need BOTH)
```

| Method | Use when | Note |
|---|---|---|
| `log show … > file.txt` | Quick targeted preservation | Loses structure; text only |
| `log collect` → `.logarchive` | Proper evidence capture | Self-contained (carries format strings) |
| Copy `/var/db/diagnostics` + `/var/db/uuidtext` | Full forensic image / dead-box | Parse with `log --archive` or third-party tools |
| **sysdiagnose** | Broad system snapshot incl. logs | `sudo sysdiagnose` or **⇧⌃⌥⌘ + .** (Shift-Ctrl-Opt-Cmd-Period) |

> `.tracev3` is a compressed binary format. Decode with Apple's `log` (best) or third-party parsers (Ulbow/Consolation, Mandiant `macos-UnifiedLogs` Rust crate, etc.).

---

## Limitations and Anti-Forensics

| Limitation / risk | Implication |
|---|---|
| 🔴 **Rolling buffer** (days–weeks) | Old events are gone — collect early; "not in log" ≠ "didn't happen" |
| `info`/`debug` **not persisted** by default | Historical depth is shallow; use `--info --debug` live, or capture continuously |
| `<private>` **redaction** | Many values hidden unless private-data logging was on; corroborate elsewhere |
| **No built-in full exec/command-line audit** | ULS is *not* a process-execution log — for exec telemetry pivot to OpenBSM (`/var/audit`, if enabled) or an Endpoint Security/EDR tool |
| `.tracev3` needs **both** `diagnostics` + `uuidtext` | Copying only one dir = undecodable offline; prefer `logarchive` |
| Panic/crash reports live **outside** ULS | Check `/Library/Logs/DiagnosticReports` — they survive log rollover |
| 🔴 **`sudo log erase --all`** wipes the store | Attacker can clear Unified Logs in one command — see below |

🔴 **Detecting log wiping:** `log erase` clears persisted `.tracev3` data. Tells: a suspiciously **young oldest-entry** (`log show --start "<long ago>"` returns little), and recent **mtimes** on `/var/db/diagnostics` chunks that don't match expected volume.

```bash
log show --style syslog --last 30d | head -1                 # how far back does data actually go?

ls -lat /var/db/diagnostics/Persist/ | head                  # newest persist chunks vs expected history

log show --predicate 'eventMessage CONTAINS[c] "log erase" OR process == "logd"' --info --last 7d
```

---

## Time and Triage Tips

- Use **absolute windows** for evidence: `--start "2026-06-01 00:00:00" --end "2026-06-02 00:00:00"`.
- Normalize with `--timezone "UTC"` when correlating across hosts/sources.
- ULS timestamps are local; `timesync/` reconciles boot/continuous time — keep it when copying raw stores.
- Add `--info --debug` for depth, but expect huge volume; narrow with a tight predicate + time window.
- `--style syslog` for readable triage, `--style ndjson`/`json` for parsing/ingestion.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `AMFI: … code signature invalid` / `Library Validation failed` | Unsigned/tampered binary or dylib injection attempt |
| Non-Apple **kext loaded** in kernel log | Third-party/rogue kernel code (cross-ref SIP) — KEXT on modern macOS is itself suspicious |
| Kext load needing **dev-mode / SIP weakened** | Attacker disabled protections to load a driver |
| launchd label **respawning / throttling** | Crashing or beaconing mechanism |
| Repeated **kernel panics** | Possible kernel exploitation, rogue kext, or instability from malicious code |
| `jetsam`/`memorystatus` mass kills | Memory exhaustion — DoS or runaway process |
| `I/O error` / `disk0` faults | Failing media — **image now**, evidence degrading |
| 🔴 **Backward clock jump** / `settimeofday` change | Timestomping enabler / anti-forensics |
| Forced/unexpected **shutdown cause** at a key moment | Power-pull to dodge clean acquisition, or crash from exploitation |
| 🔴 Log history **far shorter** than expected / `log erase` evidence | Unified Logs wiped — anti-forensics |
| **Gap / truncation** in the log timeline | Log tampering, clock change, or buffer wiped/rolled |
| `log config` changes / logging disabled for a subsystem | Anti-forensics — attacker quieting telemetry |
| Many `<private>` entries around suspect activity | Expected, but limits visibility — corroborate elsewhere |

---

## Resources

**Apple official**
- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac

**GUI tools**
- Console (built into macOS) — native Unified Log browser; slow on large sets, fine for quick looks.
- XProCheck, T2M2, Ulbow, and Consolation (The Eclectic Light Company): https://eclecticlight.co/consolation-t2m2-and-log-utilities/

**sysdiagnose (built in)** — captures extensive diagnostics including Unified Logs for offline analysis. Generate with **⇧⌃⌥⌘ + .** (Shift-Ctrl-Opt-Cmd-Period) or `sudo sysdiagnose`. Useful for handling `.tracev3` files (compressed Unified Logging archives) and supplementing the command-line methods above.
