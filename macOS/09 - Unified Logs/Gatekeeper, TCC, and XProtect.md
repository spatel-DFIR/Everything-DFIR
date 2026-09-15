# Unified Logs – Gatekeeper, TCC, and XProtect

The **Unified Log view** of macOS's three core security gates: **Gatekeeper** (`syspolicyd` — code-signing/notarization checks and blocks), **TCC** (privacy permission grants/denials), and **XProtect** (signature anti-malware + Remediator). This is the *log/event* angle — the on-disk databases and bundles are covered elsewhere.

> 🔴 These logs catch the moment malware is **blocked, allowed, or remediated**: a Gatekeeper block, a user **override** of an unsigned app, a TCC grant to a spyware-like process, or an **XProtect detection**. They roll out of the buffer fast — snapshot them.

> The persistent **artifacts** behind these gates are in their own notes: TCC.db (Transparency, Consent, and Control), XProtect bundles/Remediator reports (XProtect), and the quarantine xattr (File and Directory Permissions). This note is the **log/event** view.

## Contents
- [Quick Triage](#quick-triage)
- [Handles](#handles)
- [How These Gates Differ](#how-these-gates-differ)
- [Gatekeeper syspolicyd and spctl](#gatekeeper-syspolicyd-and-spctl)
- [TCC Grants and Denials](#tcc-grants-and-denials)
- [XProtect and Remediator](#xprotect-and-remediator)
- [Live Streaming](#live-streaming)
- [Preserving the Logs](#preserving-the-logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate 'process == "syspolicyd"' --last 24h          # Gatekeeper decisions

log show --predicate 'eventMessage CONTAINS "TCC" AND eventMessage CONTAINS "grant"' --last 24h

log show --predicate 'eventMessage CONTAINS "XProtect"' --last 24h # detections / remediation

spctl --status                                                     # Gatekeeper on/off
```

---

## Handles

| Gate | What it logs | Query handle |
|---|---|---|
| **Gatekeeper** | Code-signing/notarization assessment, allow/deny, quarantine launch checks | `process == "syspolicyd"`; older `spctl`; `subsystem == "com.apple.security.assessment"` |
| **TCC** | Privacy permission grants/denials (camera, mic, screen, FDA, etc.) | `eventMessage CONTAINS "TCC"`; `subsystem == "com.apple.TCC"` |
| **XProtect** | Signature scans/detections; Remediator scan results | `eventMessage CONTAINS "XProtect"`; `subsystem == "com.apple.XprotectFramework"`; `xprotectservice`/`XProtectService` |

---

## How These Gates Differ

These three are easy to confuse but answer **different questions** — knowing which is which tells you what a log line actually means:

| Feature | Job |
|---|---|
| **Gatekeeper** | *Should this app be allowed to launch?* — signing + notarization + quarantine check, mostly at **first run** (`syspolicyd`) |
| **XProtect** | *Is this known malware?* — Apple's built-in **signature-based** detection/removal (XProtect + Remediator) |
| **TCC** | *Can this app touch my camera, mic, files, screen?* — **privacy** consent, separate from whether it can run |
| **Notarization** | The Apple **pre-screening service** Gatekeeper relies on (developer submits app → Apple scans → issues a ticket) |

**Rough flow of a downloaded app (and where each logs):**

```
download  →  quarantine xattr set (com.apple.quarantine)
          →  first launch
          →  GATEKEEPER (syspolicyd): signed? notarized? quarantine?  →  allow / block / user override
          →  XPROTECT: matches a known-malware signature?            →  detect / remediate
          →  runs
          →  TCC: prompts/decides for camera, mic, files, screen…    →  grant / deny
```

> 🔴 Reading logs with this flow in mind: a **Gatekeeper deny → app runs anyway** = user override of untrusted code; an **XProtect detection** = known malware was present; a **TCC grant of FDA/Screen Recording** = capability gained *after* the app was already allowed to run. Different stages, different severity.

---

## Gatekeeper syspolicyd and spctl

`syspolicyd` is the Gatekeeper daemon (current macOS); `spctl` is the older/CLI face.

```bash
# Gatekeeper logs (last 24 hours)
log show --predicate 'process == "syspolicyd"' --last 24h

# Older references (spctl) — rare on modern macOS
log show --predicate 'process == "spctl"' --last 24h

# Security-assessment subsystem (Gatekeeper allow/deny decisions)
log show --predicate 'subsystem == "com.apple.security.assessment"' --last 24h
```

Live posture / on-demand assessment + download provenance of a suspect binary:

```bash
spctl --status                                   # Gatekeeper on/off

spctl -a -vvv /path/to/App.app                   # assess a specific bundle (accepted/rejected + source)

codesign -dvvv /path/to/App.app 2>&1             # signing identity / Team ID / notarization

xattr -p com.apple.quarantine /path/to/file      # quarantine stamp (agent, time, download UUID)

xattr -l /path/to/file                           # all xattrs incl. where-from URL
```

> 🔴 A binary that **executed but has no quarantine xattr** may have been delivered by a method that bypasses it (e.g. `curl`/`scp`/archive extraction) — a deliberate evasion. The quarantine `LSQuarantineEventIdentifier` ties back to `QuarantineEventsV2` (download URL/agent) — see the File Permissions note.

| Signal | Meaning |
|---|---|
| 🔴 Assessment **deny/reject** then the app runs anyway | User **override** (right-click → Open) of unsigned/un-notarized malware |
| 🔴 `spctl --master-disable` / Gatekeeper **off** | Protections disabled to run untrusted code |
| Quarantined binary assessed from `~/Downloads`, `/tmp`, `/Users/Shared` | Classic initial-execution path |
| Repeated assessments of the same odd binary | Malware launch attempts |

---

## TCC Grants and Denials

Privacy/permission decisions as they happen (the live record; the persistent grants are in TCC.db).

```bash
# Basic TCC events (last 24 hours)
log show --predicate 'eventMessage CONTAINS "TCC"' --last 24h

# TCC denials
log show --predicate 'eventMessage CONTAINS "TCC" AND eventMessage CONTAINS "deny"' --last 24h

# TCC grants
log show --predicate 'eventMessage CONTAINS "TCC" AND eventMessage CONTAINS "grant"' --last 24h

# Subsystem-level TCC
log show --predicate 'subsystem == "com.apple.TCC"' --info --last 24h
```

🔴 What to look for:

| Signal | Meaning |
|---|---|
| 🔴 **Grant** of Full Disk Access / Accessibility / Screen Recording to an odd app | Spyware-like capability gained (keylogging, screen capture, data theft) |
| Repeated **deny** for mic/camera/screen by one process | Spyware attempting capture without permission |
| A grant immediately after install of an unknown app | Permission-abuse chain |
| Grants to command-line/`osascript` clients | Automation abuse |

> Grant/deny in the log is the *event*; confirm the persisted state in **TCC.db** (system + user) per the TCC artifact note.

---

## XProtect and Remediator

XProtect = Apple's built-in signature scanner; **XProtect Remediator (XPR)** runs periodic scans and can **remove** malware.

```bash
# Any XProtect references (last 24 hours)
log show --predicate 'eventMessage CONTAINS "XProtect"' --last 24h

# Legacy XProtect framework subsystem
log show --predicate 'subsystem == "com.apple.XprotectFramework"' --last 24h

# XProtect Remediator service logs
log show --predicate 'eventMessage CONTAINS "xprotectservice" OR eventMessage CONTAINS "XProtectService"' --last 24h
```

🔴 What to look for:

| Signal | Meaning |
|---|---|
| 🔴 XProtect **detection / match** | Known malware was present on the host |
| 🔴 Remediator **removed/remediated** an item | Malware was found and deleted — file may now be absent (the log is the proof it existed) |
| Scan results naming a malware family (e.g. `MACOS.*`) | Identify the threat; pivot to IOCs |
| XProtect signatures **stale** / not updating | Reduced detection (cross-ref XProtect artifact note) |

> Remediator scan results also persist on disk per-user (`~/Library/Caches/…`/`.../XProtect` reports) — see the XProtect artifact note for parsing.

---

## Live Streaming

```bash
# Monitor Gatekeeper, TCC, and XProtect in real time (resource-intensive)
log stream --predicate '(process == "syspolicyd") OR (eventMessage CONTAINS "TCC") OR (eventMessage CONTAINS "XProtect") OR (eventMessage CONTAINS "xprotectservice")' --info
```

---

## Preserving the Logs

```bash
# Preserve Gatekeeper, TCC, and XProtect logs (last 24 hours)
log show --predicate '(process == "syspolicyd") OR (eventMessage CONTAINS "TCC") OR (eventMessage CONTAINS "XProtect") OR (eventMessage CONTAINS "xprotectservice")' --last 24h > gatekeeper_tcc_xprotect_snapshot.txt

# Full store for evidence
sudo log collect --output /evidence/host.logarchive
```

> Corroborate with the **persisted artifacts**: TCC.db (grants), quarantine `QuarantineEventsV2`/xattr (download provenance), XProtect version + Remediator reports.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Gatekeeper **deny** then the binary executes | User override of unsigned/un-notarized malware |
| `spctl --master-disable` / Gatekeeper off | Protections disabled to run untrusted code |
| Quarantined binary assessed/launched from Downloads/tmp | Initial execution of dropped payload |
| TCC **grant** of FDA/Accessibility/Screen Recording to an odd app | Spyware capability gained |
| Repeated TCC **deny** for mic/camera/screen | Covert-capture attempts |
| XProtect **detection** / Remediator **removal** | Known malware was present (log proves it even if file is gone) |
| XProtect signatures stale | Weakened detection |
| Security logs with surrounding **timeline gaps** | Possible tampering |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
