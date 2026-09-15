# Program Execution Evidence

macOS has **no single "did this run" artifact** like Windows Prefetch — execution evidence is **scattered** across a dozen sources, and each only tells part of the story. This note is the consolidated map: given *"did program X run, and when?"*, here's **every place** to look and what each proves. The power is in **stacking** them — one source is a lead, several agreeing is a finding.

> 🔴 No source is authoritative alone. `knowledgeC`/`Biome` give usage timelines, `quarantine` proves a download was opened, `XProtect`/`Gatekeeper` logs prove an assessment at launch, `TCC` proves the app requested a capability (so it ran), and crash reports prove it ran *and* died. Correlate across them.

## Contents
- [Quick Triage](#quick-triage)
- [Execution Evidence Sources](#execution-evidence-sources)
- [Usage and Focus Databases](#usage-and-focus-databases)
- [Launch and Open Evidence](#launch-and-open-evidence)
- [Indirect Execution Proof](#indirect-execution-proof)
- [Building the Picture](#building-the-picture)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Usage timeline (older) — app + start/end
sqlite3 ~/Library/Application\ Support/Knowledge/knowledgeC.db "SELECT ZVALUESTRING, DATETIME(ZSTARTDATE+978307200,'unixepoch') FROM ZOBJECT WHERE ZSTREAMNAME='/app/usage' ORDER BY ZSTARTDATE DESC LIMIT 20;" 2>/dev/null

# Spotlight last-used + use count for a binary
mdls -name kMDItemLastUsedDate -name kMDItemUseCount /path/to/binary

# Launch/exec + code-signing checks in the log
log show --predicate 'subsystem == "com.apple.launchd" OR eventMessage CONTAINS[c] "AMFI"' --info --last 1d
```

---

## Execution Evidence Sources

🔴 The full map — where execution leaves a trace:

| Source | What it proves | Note |
|---|---|---|
| **knowledgeC.db** `/app/usage`,`/app/inFocus` | App used + duration | knowledgeC.db |
| **Biome** | Same on modern macOS | Biome |
| **Spotlight** `kMDItemLastUsedDate`/`kMDItemUseCount` | File last opened + run count | Additional Topics |
| **quarantine** xattr (`LSQuarantineTimeStamp`) | Downloaded item was **opened/run** | File Permissions |
| **XProtect / Gatekeeper** logs | Assessed/scanned **at launch** | Gatekeeper-TCC-XProtect |
| **Unified Logs** (launchd, AMFI, `exec`) | Spawn + code-sign check | System & Kernel |
| **TCC.db** | App **requested a permission** → it ran | TCC |
| **Crash / spindump** reports | Process ran **and crashed/hung** | Crash Reporting |
| **Shell history** | Command launched from terminal | Shells |
| **Recent items / SharedFileList** | Doc/app opened | Login Items / mac_apt |
| **Saved Application State** | App had a window/session | Persistence |
| **Dock / LaunchServices** | App registered/launched | below |
| **FSEvents** | Binary written/accessed | FSEvents |

---

## Usage and Focus Databases

```bash
# knowledgeC: app usage with duration
sqlite3 ~/Library/Application\ Support/Knowledge/knowledgeC.db \
"SELECT ZVALUESTRING App, DATETIME(ZSTARTDATE+978307200,'unixepoch') Start, (ZENDDATE-ZSTARTDATE) Secs FROM ZOBJECT WHERE ZSTREAMNAME='/app/usage' ORDER BY ZSTARTDATE DESC LIMIT 25;"

# Biome (modern) — enumerate streams, parse SEGB
find ~/Library/Biome -type f 2>/dev/null | head
```

> These are the closest macOS has to an execution **timeline** — but they cover *foreground/usage*, not every background exec. (Cross-ref knowledgeC.db and Biome notes.)

---

## Launch and Open Evidence

```bash
# Spotlight metadata — last used + use count
mdls -name kMDItemLastUsedDate -name kMDItemUseCount -name kMDItemDateAdded /path/to/app

# Quarantine — when a downloaded item was first opened
xattr -p com.apple.quarantine /path/to/downloaded.app

#   field 3 = timestamp the item was approved/opened

# LaunchServices registration (apps known/launched)
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump 2>/dev/null | grep -iE 'path:|bundle id'
```

🔴 `kMDItemUseCount` > 0 and a `kMDItemLastUsedDate` = the file was **opened**; the quarantine timestamp marks the **first run** of a downloaded item (after the Gatekeeper prompt).

---

## Indirect Execution Proof

Sometimes the app/binary is gone, but it **ran** — proven indirectly:

| Trace | Inference |
|---|---|
| 🔴 **TCC** grant/denial for an app | The app executed to request the permission |
| 🔴 **Crash/spindump** report naming the process | It ran (and crashed) — report has path/signing/dylibs |
| **XProtect remediation** of an item | It was present and got removed |
| **Unified Log** AMFI/sandbox lines for the proc | It tried to run (allowed or blocked) |
| **FSEvents** access of the binary | It was touched/executed |
| **Shell history** entry | It was launched from a terminal |

---

## Building the Picture

🔴 Stack the sources for confidence:

```
quarantine (downloaded 14:02, opened 14:05)
  + Gatekeeper log (assessed 14:05)
  + knowledgeC /app/usage (foreground 14:05–14:31)
  + TCC grant (FDA at 14:06)
  + crash report (crashed 14:31)
= the app was downloaded, opened, ran ~26 min, gained Full Disk Access, then crashed.
```

> Always convert timestamps to one TZ and mind the **epochs** (knowledgeC = 2001/Cocoa; stat = 1970) — cross-ref the Cross-Artifact Correlation note.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| knowledgeC/Biome usage of an unknown app | Malware/tool execution with timing |
| `kMDItemUseCount`/last-used on a binary in `/tmp`,`~/Library` | A dropped payload was opened |
| TCC grant to an odd app but no install record | It ran and gained capability (cross-ref Install Receipts) |
| Crash report for a process **gone from disk** | Ran then self-deleted (report = proof) |
| Execution evidence at odd hours | Activity when user claims absence |
| Quarantine "opened" timestamp on a malicious download | First-run time of the payload |

---

## Resources

- Cross-ref: knowledgeC.db, Biome, Crash Reporting, TCC, Gatekeeper-TCC-XProtect, FSEvents, Cross-Artifact Correlation
- `man mdls` · `man xattr`
