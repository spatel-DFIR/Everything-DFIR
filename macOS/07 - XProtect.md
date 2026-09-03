# XProtect

XProtect is Apple's **built-in, silent, signature-based anti-malware** (since Snow Leopard, 2009). No UI, no user interaction — it scans, blocks, quarantines, and (on modern macOS) **removes** known malware in the background. For DFIR it matters two ways: its **logs timestamp detections/blocks/removals**, and its **Remediator may have already deleted the malware** — so an *absent* file plus an XProtect removal log means it **was** there.

Three generations now run together:

| Component | Role | Since |
|---|---|---|
| 🔴 **XProtect** (signatures) | Yara-rule scan of **quarantined files at first launch**; blocks known malware ("…will damage your computer") | 2009 |
| 🔴 **XProtect Remediator (XPR)** | Standalone scanners that **proactively scan + remove** malware on a schedule (launchd) | Monterey 12.3 (2022) |
| **XProtect Behavior Service (XBS)** | Monitors malicious **behavior**, records violations to a local DB | Ventura/Sonoma |
| *MRT (Malware Removal Tool)* | XPR's predecessor — **deprecated/removed** in favor of Remediator | retired ~macOS 14 |

## Contents
- [Quick Triage](#quick-triage)
- [Components & On-Disk Locations](#components--on-disk-locations)
- [How It Works (the three engines)](#how-it-works-the-three-engines)
- [Versions & Updates](#versions--updates)
- [Monitoring via Logs](#monitoring-via-logs)
- [Quarantine Attribute (the XProtect/Gatekeeper hook)](#quarantine-attribute-the-xprotectgatekeeper-hook)
- [XProtect vs Gatekeeper vs Notarization](#xprotect-vs-gatekeeper-vs-notarization)
- [Forensic Relevance](#forensic-relevance)
- [Tampering / Evasion to Check](#tampering--evasion-to-check)
- [Best Practices](#best-practices)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# --- Versions / currency ---
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString

system_profiler SPInstallHistoryDataType | grep -A4 -i xprotect

# --- Detections / removals across the log ---
log show --info --predicate 'process == "XProtectService"' --last 24h

log show --info --predicate 'process == "XProtectRemediator"' --last 24h

log show --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"' --info --last 7d

log show --predicate 'process CONTAINS "XProtect" AND (eventMessage CONTAINS[c] "remediat" OR eventMessage CONTAINS[c] "detected")' --info --last 30d

# --- Are the XPR scan jobs disabled? ---
/usr/libexec/PlistBuddy -c Print /private/var/db/com.apple.xpc.launchd/disabled.plist 2>/dev/null | grep -i xprotect

launchctl print-disabled system 2>/dev/null | grep -i xprotect

# --- Update blocking via hosts file ---
grep -Ei 'apple|swcdn|swscan|xp\.apple' /etc/hosts 2>/dev/null

# --- Inspect signatures / scanner inventory ---
ls /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/

grep -aoE 'rule [A-Za-z0-9_]+' /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara | sort -u | head

# --- Quarantine on a suspect file ---
xattr -p com.apple.quarantine /path/to/file

ls -l@ /path/to/file
```

---

## Components & On-Disk Locations

> Modern path root is `/Library/Apple/System/Library/...` (Big Sur+). These bundles are **SIP-protected** (`restricted`) — Apple-only.

| Path | What it is |
|---|---|
| `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara` | 🔴 The **Yara signatures** (grep for malware family names) |
| `…/XProtect.bundle/Contents/Resources/XProtect.plist` | Legacy signature definitions |
| `…/XProtect.bundle/Contents/Resources/XProtect.meta.plist` | Blocked browser plug-ins + minimum versions |
| `…/XProtect.bundle/Contents/Info.plist` | 🔴 **Signature version** (`CFBundleShortVersionString`) |
| `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator*` | 🔴 The **Remediator scanner binaries** (one per malware family) |
| `…/XProtect.app/Contents/MacOS/XProtectReporter` | Reports XPR results |
| `…/XProtect.app/Contents/MacOS/XProtectBehaviorService` | The behavior monitor (XBS) |
| `/Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist` | 🔴 launchd job that runs XPR scans (~every 24h) |
| `…/com.apple.XProtect.daemon.scan.startup.plist` | XPR scan at startup |

Remediator scanners are named per family, e.g. `XProtectRemediatorAdload`, `…Bundlore`, `…Pirrit`, `…Genieo`, `…Trovi`, `…ColdSnap`, `…DubRobber`, `…SnowDrift`, `…Eicar` (test), `…MRTv3`. New families arrive with signature updates.

```bash
ls /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/   # list all scanners
```

---

## How It Works (the three engines)

| Engine | Trigger | Action | Forensic trace |
|---|---|---|---|
| Signature scan | Opening a **quarantined** file (ties into Gatekeeper flow) | Block + alert if Yara match | Unified log (XProtectService); quarantine xattr |
| Remediator (XPR) | launchd schedule (~daily) + startup, when idle | **Scan and delete** detections | Unified log (per-scanner); 🔴 malware may be gone |
| Behavior (XBS) | Continuous behavioral monitoring | Record violation | Local behavior DB |

---

## Versions & Updates

XProtect updates ship **silently** as background "system data files" — **not** full OS updates — via two payloads:
- **`XProtectPlistConfigData`** = signature/Yara updates
- **`XProtectPayloads`** = Remediator binaries

Auto-installed when *"Install system data files and security updates"* is enabled. The install history is a **timeline of signature currency**.

```bash
# Current signature + Remediator versions
defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist CFBundleShortVersionString

defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist CFBundleShortVersionString

# Update history (dates of every XProtect signature/payload update)
system_profiler SPInstallHistoryDataType | grep -A4 -i xprotect

softwareupdate --history 2>/dev/null | grep -i xprotect
```
> 🔴 A **stale** XProtect version (months old) suggests updates were blocked (e.g., `/etc/hosts` pointing Apple update domains to nowhere) → the host was flying blind at incident time.

---

## Monitoring via Logs

Provided commands (note: `--last` suffixes are `s`/`m`/`h`/`d` only — **no week/month**; use `7d` for a week, `30d` ≈ a month):

```bash
log show --info --predicate 'process == "XProtectService"' --last 24h

# Views recent XProtect signature-service log entries (adjust the window: 1s, 2m, 3h, 4d…)

log show --info --predicate 'process == "XProtectRemediator"' --last 24h

# Shows logs related to the XProtect Remediator component on modern macOS
```

More precise predicates (Remediator runs as the per-family binaries and reports via the framework):

```bash
# Any XProtect-related process
log show --info --predicate 'process CONTAINS "XProtect"' --last 24h

# Remediator framework events (scan results / detections / remediations)
log show --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI"' --info --last 7d

# Just detections/removals
log show --predicate 'process CONTAINS "XProtect" AND (eventMessage CONTAINS[c] "remediat" OR eventMessage CONTAINS[c] "detected" OR eventMessage CONTAINS[c] "malware")' --info --last 30d
```
> XPR scan results are recorded in the **unified log** — capture them live; the log rolls. See the Resources link for deep XPR result parsing.

---

## Quarantine Attribute (the XProtect/Gatekeeper hook)

XProtect's signature scan fires on files carrying the **quarantine** xattr (set by browsers/Mail/AirDrop). Provided commands:

```bash
xattr -p com.apple.quarantine /path/to/file

# Checks the quarantine attribute for a specific file

ls -l@ /path/to/file

# Lists extended attributes, which can help reveal quarantine info
```

Quarantine value = `flags;hex-epoch;agent;UUID` (full parsing in the **File and Directory Permissions** note). The agent + timestamp show **how/when** the file arrived; XProtect evaluated it at first launch.

---

## XProtect vs Gatekeeper vs Notarization

These overlap at the "first launch of a downloaded file" choke point — easy to confuse:

| Mechanism | What it does | When | Check |
|---|---|---|---|
| **XProtect** | **Signature** (Yara) detection of *known* malware → block/quarantine/remove | On quarantined-file launch + scheduled (XPR) | logs, `XProtect.yara` |
| **Gatekeeper** | Policy enforcement: is the app **signed + notarized**, and is quarantine satisfied? Allows/denies *running* | First launch of quarantined app | `spctl --assess -vv app`; `spctl --status` |
| **Notarization** | Apple's automated malware **scan of developer-submitted** software → issues a stapled **ticket** | At developer submission; checked by Gatekeeper | `stapler validate app`, `codesign -dv` |

> Mental model: **Notarization** = pre-publication scan (developer side); **Gatekeeper** = signature/notarization *policy* at launch; **XProtect** = known-malware *signatures* at launch + background removal.

---

## Forensic Relevance

| Point | Why it matters |
|---|---|
| 🔴 Remediator **deletes** malware | An absent file + an XPR removal log = malware **was present**. Don't read "clean" as "never infected" |
| Detection logs are **timestamped** | Anchor when malware was seen/blocked/removed |
| XProtect **version** at incident time | Was the threat *known* to Apple then? Explains why it was/wasn't caught |
| **Minimal imaging impact** | XProtect only acts on a **live** system; it does not run against a dead disk image, so it won't alter evidence during analysis. (But the live host's XPR may have remediated *before* you imaged) |
| Quarantine xattr | Ties the file to its origin + the XProtect/Gatekeeper evaluation |

---

## Tampering / Evasion to Check

| Technique | Detection |
|---|---|
| 🔴 Block signature updates (stale XProtect) | Old `CFBundleShortVersionString`; Apple update domains redirected in `/etc/hosts` |
| 🔴 Disable the XPR scan launchd jobs | Entries in `/private/var/db/com.apple.xpc.launchd/disabled.plist`; `launchctl print-disabled system` |
| Malware not yet in signatures | XProtect is **signature-based** — novel/targeted malware passes; never treat "no XProtect hit" as clean |
| Strip quarantine xattr | File evades the on-launch scan entirely (see Permissions note) |

---

## Best Practices

1. During **live triage**, immediately record XProtect **and** Remediator versions and **pull their logs** (`log show … process CONTAINS "XProtect"`) — the unified log rolls.
2. Check `system_profiler SPInstallHistoryDataType` for the **signature-update timeline** vs the incident window.
3. **Search XPR logs for remediation events** — the offending file may already be gone.
4. Treat XProtect as **one signal among many** (it's signature-only); corroborate with quarantine, FSEvents, persistence, and unified log.
5. For dead-box analysis, note XProtect's **minimal imaging impact** — analyze the image freely.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| XProtect signature version months out of date | Updates blocked → host blind to known malware |
| Apple update domains redirected in `/etc/hosts` | Deliberate signature-update sabotage |
| XPR scan launchd jobs in `disabled.plist` | Background scanning disabled |
| XPR **remediation** log entry but file now absent | Malware was present and auto-removed — pivot from the log |
| XProtect "will damage your computer" / detection event in logs | Confirmed known-malware encounter — get the file path + time |
| Quarantine xattr stripped from a suspect executable | Evading the on-launch signature scan |

---

## Resources

- **The Secrets of XProtectRemediator** — https://alden.io/posts/secrets-of-xprotect/ (deep dive on the XPR binaries and parsing their scan/remediation results)
