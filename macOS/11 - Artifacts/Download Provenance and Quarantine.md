# Download Provenance and Quarantine

The single best answer to **"where did this file come from, what downloaded it, and when?"** macOS tags every file written by a *quarantine-aware* app (browsers, Mail, Messages, AirDrop, Slack, etc.) with the **`com.apple.quarantine`** extended attribute and logs a row in the per-user **`QuarantineEventsV2`** database — capturing the **source URL, the referring page, the downloading agent, and a timestamp**. This is the macOS "Mark-of-the-Web."

> 🔴 Two questions, two artifacts, one GUID: the **xattr** on the file proves *this* file was downloaded (and by which agent); the **QuarantineEventsV2** row (joined by GUID) gives the **actual URL and referrer**. Attackers strip the xattr (`xattr -d`) to defeat Gatekeeper — so a payload that *should* be quarantined but isn't is itself a finding.

## Contents
- [Quick Triage](#quick-triage)
- [The Quarantine xattr](#the-quarantine-xattr)
- [QuarantineEventsV2 Database](#quarantineeventsv2-database)
- [Where-From Metadata (kMDItemWhereFroms)](#where-from-metadata-kmditemwherefroms)
- [Provenance xattr (Ventura+)](#provenance-xattr-ventura)
- [Correlating the Chain](#correlating-the-chain)
- [Gatekeeper / Quarantine Bypass](#gatekeeper--quarantine-bypass)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Every download the user ever made (URL + referrer + agent + time) — the crown jewel
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch') t, LSQuarantineAgentName agent,
   LSQuarantineDataURLString url, LSQuarantineOriginURLString referrer
   FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 40;"

# Quarantine tag on a suspect file: flags;hex-epoch;agent;GUID
xattr -p com.apple.quarantine /path/to/suspect

# Human-readable source URL(s) of a file
mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate /path/to/suspect

# Sweep a staging dir for what's quarantined vs what ISN'T (stripped = suspicious)
find ~/Downloads ~/Library/Application\ Support /Users/Shared -type f 2>/dev/null \
  -exec sh -c 'xattr -p com.apple.quarantine "$1" >/dev/null 2>&1 && echo "Q  $1" || echo "-- $1"' _ {} \;
```

---

## The Quarantine xattr

`com.apple.quarantine` is set by the downloading app. It's what triggers the Gatekeeper "downloaded from the Internet" prompt and, for apps, notarization assessment on first launch.

```bash
xattr -l /path/to/file                       # all xattrs
xattr -p com.apple.quarantine /path/to/file  # just the quarantine value
```

Value = four semicolon-separated fields: `0081;66b1f2a0;Safari;A1B2C3D4-...-GUID`

| Field | Example | Meaning |
|---|---|---|
| **Flags** | `0081` | Hex bitfield — quarantine type + whether the user has approved (assessed) it. `00c1`/`0081` common; low bit set once the user OK'd it |
| **Timestamp** | `66b1f2a0` | **Hex** seconds since Unix epoch — **when it was downloaded**. `printf '%d\n' 0x66b1f2a0` → decimal → `date -r` |
| **Agent** | `Safari` / `Google Chrome` / `com.apple.AirDrop` | The app that wrote the file |
| **GUID** | `A1B2C3D4-…` | Joins to the `LSQuarantineEvent` row for the URL/referrer |

```bash
# Decode the download time from the hex field
HEX=$(xattr -p com.apple.quarantine file | cut -d';' -f2); date -r $((16#$HEX)) -u
```

> The xattr lives in the file's extended attributes — it **survives copy on the same APFS/HFS+ volume** but is **stripped by** moving to a non-native FS, `zip`/`tar` round-trips that drop xattrs, or an explicit `xattr -c/-d`. FSEvents/Spotlight retain traces even after the file is gone.

---

## QuarantineEventsV2 Database

Per-user SQLite at `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`. One row per download event, keyed by the GUID in the xattr. **Persists even after the file is deleted** — a durable download history.

```bash
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 ".schema LSQuarantineEvent"

# Full detail for one file's GUID (pulled from its xattr)
G=$(xattr -p com.apple.quarantine /path/to/file | cut -d';' -f4)
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
  "SELECT * FROM LSQuarantineEvent WHERE LSQuarantineEventIdentifier='$G';"
```

| Column | Forensic value |
|---|---|
| `LSQuarantineEventIdentifier` | GUID — joins to the file's xattr |
| `LSQuarantineTimeStamp` | Mac epoch (`+978307200` → Unix) — download time |
| `LSQuarantineAgentName` / `…BundleIdentifier` | App that downloaded it (Safari, Chrome, Slack, curl-wrapped installers…) |
| **`LSQuarantineDataURLString`** | 🔴 The **direct URL the file came from** |
| **`LSQuarantineOriginURLString`** | 🔴 The **referring page** — the phishing/malvertising site |
| `LSQuarantineSenderName` / `…SenderAddress` | For Messages/Mail/AirDrop — **who sent it** |
| `LSQuarantineTypeNumber` | Web download vs email attachment vs message vs calendar |

> For **AirDrop / Messages / Mail** the sender fields attribute the delivery to a person/device — pivot into [`Messages and Mail`](<Messages and Mail.md>) and the Bluetooth/AWDL logs.

---

## Where-From Metadata (kMDItemWhereFroms)

A parallel record stored as the **`com.apple.metadata:kMDItemWhereFroms`** xattr (a binary plist array: `[dataURL, originURL]`) and mirrored in the Spotlight metadata store.

```bash
mdls -name kMDItemWhereFroms /path/to/file                     # decoded array
xattr -p com.apple.metadata:kMDItemWhereFroms /path/to/file | xxd | head   # raw bplist
# Decode the raw plist to text
xattr -px com.apple.metadata:kMDItemWhereFroms file | xxd -r -p | plutil -p -
```

`kMDItemWhereFroms` often survives when the quarantine xattr was stripped (different attribute) — check both. Spotlight also indexes it, so `mdfind "kMDItemWhereFroms == '*evil.com*'"` finds every file sourced from a domain.

---

## Provenance xattr (Ventura+)

Newer macOS adds **`com.apple.provenance`** to app bundles under App Management — a compact record tying a running app back to its install/first-launch provenance (used to enforce that a modified app can't silently inherit an original's TCC grants).

```bash
xattr -p com.apple.provenance /Applications/Suspect.app 2>/dev/null | xxd | head
```

Value is opaque, but its **presence/absence and change** on a bundle is a tamper/repackage signal — a stealer that re-signs and re-drops an app breaks the original provenance.

---

## Correlating the Chain

The full download-to-execution story stacks these:

| Question | Artifact |
|---|---|
| Was it downloaded, by which app, when? | `com.apple.quarantine` xattr |
| From what URL / referring page? | `LSQuarantineEvent` row (join GUID) + `kMDItemWhereFroms` |
| When was it opened/run? | `kMDItemLastUsedDate`, `knowledgeC`, Gatekeeper/XProtect log → [`Program Execution Evidence`](<Program Execution Evidence.md>) |
| Did Gatekeeper assess it? | unified log → [`Gatekeeper, TCC, and XProtect`](<../09 - Unified Logs/Gatekeeper, TCC, and XProtect.md>) |
| Where is it now / where did it move? | [`FSEvents`](<File System Events (FSEvents).md>), [`Spotlight`](Spotlight.md) |

```bash
# One-shot: recent downloads that are executables/DMGs/pkgs (the interesting ones)
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
 "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString
  FROM LSQuarantineEvent
  WHERE LSQuarantineDataURLString LIKE '%.dmg' OR LSQuarantineDataURLString LIKE '%.pkg'
     OR LSQuarantineDataURLString LIKE '%.zip' OR LSQuarantineDataURLString LIKE '%.app%'
  ORDER BY 1 DESC;"
```

---

## Gatekeeper / Quarantine Bypass

Removing the quarantine xattr makes Gatekeeper treat a file as locally-created (no notarization check). This is a **standard step in macOS malware installers**.

```bash
# What malware does (do NOT run) — recognize it in scripts/history:
#   xattr -d com.apple.quarantine /path/payload
#   xattr -c /path/payload
#   /usr/bin/xattr -rd com.apple.quarantine /Applications/Evil.app
```

Hunt for the technique and its aftermath:
```bash
# The bypass command in shell history / scripts
grep -rEn 'xattr .*(-d|-c|-rd).*com\.apple\.quarantine' /Users/*/.*_history /Users/*/Library 2>/dev/null

# Recently-run apps in user-writable dirs with NO quarantine (downloaded but tag removed)
for a in ~/Applications/*.app /Applications/*.app /Users/Shared/*.app; do
  [ -e "$a" ] || continue
  xattr -p com.apple.quarantine "$a" >/dev/null 2>&1 || echo "no-quarantine: $a"
done
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `LSQuarantineDataURLString` = raw IP, paste site, temp file host, or `*.top`/`*.xyz` throwaway | Malware delivery URL |
| `LSQuarantineOriginURLString` = a fake-update / cracked-software / malvertising page | Drive-by / social-engineering origin |
| Agent = `curl`, `nscurl`, an unknown helper, or a Terminal-spawned tool | Scripted/second-stage download, not a human browser |
| Executable/DMG/pkg in a user dir with the quarantine xattr **stripped** | Deliberate Gatekeeper bypass |
| `xattr -d com.apple.quarantine` in shell history or an installer script | Attacker removed Mark-of-the-Web |
| `LSQuarantineSenderName`/AirDrop for a payload | Targeted delivery — attribute the sender |
| Download time immediately precedes a new LaunchAgent / first app execution | Download → install → persist chain |
| `kMDItemWhereFroms` present but quarantine GUID missing from the DB | Tag tampered or DB reset — dig via Spotlight/FSEvents |

---

## Resources
- `man` pages: `xattr(1)`, `mdls(1)`, `mdfind(1)`, `sqlite3(1)`, `plutil(1)`
- [`Program Execution Evidence`](<Program Execution Evidence.md>) — proving the downloaded file then ran
- [`09 - Unified Logs/Gatekeeper, TCC, and XProtect`](<../09 - Unified Logs/Gatekeeper, TCC, and XProtect.md>) — the assessment at launch
- [`02 - File and Directory Permissions`](<../02 - File and Directory Permissions.md>) — extended attributes mechanics
