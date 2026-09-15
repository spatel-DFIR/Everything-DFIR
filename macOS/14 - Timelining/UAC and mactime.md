# UAC and mactime

A **bodyfile** is The Sleuth Kit's intermediate timeline format — one pipe-delimited line per file with its MACB timestamps. **UAC** can generate a bodyfile during collection; **`mactime`** (from TSK) turns that bodyfile into a **human-readable file-system timeline** sorted by time. Add **`grep`** to carve the timeline down to the dates, paths, or metadata you care about.

> 🔴 Flow: **UAC bodyfile → `mactime` → timeline (CSV) → `grep` filter**. The output's **MACB** column tells you *which* timestamp (Modified / Accessed / Changed / Birth) put that line at that moment — the key to reading the timeline correctly.

## Contents
- [Quick Triage](#quick-triage)
- [What a Bodyfile Is](#what-a-bodyfile-is)
- [Getting a Bodyfile from UAC](#getting-a-bodyfile-from-uac)
- [Running mactime](#running-mactime)
- [Reading the Output](#reading-the-output)
- [Filtering with grep](#filtering-with-grep)
- [Pitfalls](#pitfalls)
- [Resources](#resources)

---

## Quick Triage

```bash
# Locate the bodyfile inside an extracted UAC collection
find . -name 'bodyfile*' 2>/dev/null

# Convert to a timezone-correct CSV timeline
mactime -b bodyfile.txt -d -z UTC > timeline.csv

# Bound to the incident window
mactime -b bodyfile.txt -d -z UTC 2024-06-01..2024-06-30 > timeline_june.csv

# Filter for a date / path of interest
grep '2024-06-09' timeline.csv | grep -iE 'LaunchAgents|/tmp/'
```

---

## What a Bodyfile Is

TSK's bodyfile is **pipe-delimited**, one line per file:

```
MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
```

- The four timestamps (`atime`/`mtime`/`ctime`/`crtime`) are **epoch seconds**.
- `mactime` reads this and emits one **time-sorted** row per timestamp event.
- Sources of a bodyfile: **UAC** (live collection) or TSK's **`fls`** on an image (`fls -r -m / image.dd > bodyfile`).

---

## Getting a Bodyfile from UAC

```bash
# Extract the UAC archive
tar xzf uac-HOSTNAME.local-macos-*.tar.gz -C uac_out/

# Find the bodyfile UAC produced
find uac_out/ -iname 'bodyfile*'

#   commonly under  [root]/bodyfile/bodyfile.txt  (or similar)
```

> UAC builds the bodyfile from the live file system as part of its collection — so you get a timeline source without separately imaging the disk. (Cross-ref the UAC note in Evidence Collection.)

---

## Running mactime

```bash
# Basic: bodyfile -> CSV timeline, in UTC
mactime -b bodyfile.txt -d -z UTC > timeline.csv

# Date range (inclusive start .. end)
mactime -b bodyfile.txt -d -z UTC 2024-06-09..2024-06-10 > timeline_day.csv

# Human-readable (non-CSV) with day index
mactime -b bodyfile.txt -z UTC -y > timeline.txt
```

| Flag | Does |
|---|---|
| `-b <file>` | Input bodyfile |
| 🔴 `-d` | Output **comma-delimited (CSV)** |
| 🔴 `-z <TZ>` | Interpret times in this **time zone** (use `UTC` for consistency) |
| `-y` | ISO date format |
| `<start>..<end>` | Restrict to a date range |
| `-m` | Month names as numbers |

> 🔴 Always set `-z` — without it `mactime` uses the local TZ of the analysis box, skewing the timeline.

---

## Reading the Output

CSV columns:

| Column | Meaning |
|---|---|
| **Date** | Timestamp of this event |
| **Size** | File size (bytes) |
| 🔴 **Type** | **MACB** flags — which timestamp this row represents: `m`=modified, `a`=accessed, `c`=changed (inode), `b`=birth |
| **Mode** | Permissions string |
| **UID / GID** | Owner |
| **Meta** | Inode / metadata address |
| 🔴 **File Name** | Path |

🔴 A single file can appear on **multiple rows** (one per distinct timestamp). The **Type** column is everything: `...b` = the file was **created** at that time; `m.c.` = modified + inode-changed (e.g. a write/move); `.a..` = just accessed.

Example interpretation:
```
Sun Jun 09 2024 22:14:03, 53210, ...b, -rwxr-xr-x, 501, 20, 1234567, /Users/x/Library/LaunchAgents/com.evil.plist
```
→ `b` = the malicious LaunchAgent plist was **born (created)** at 22:14:03 (cross-ref the persistence note).

---

## Filtering with grep

```bash
# Only a specific date
grep '2024-06-09' timeline.csv

# Persistence / staging paths
grep -iE 'LaunchAgents|LaunchDaemons|/tmp/|/Users/Shared/|cron' timeline.csv

# Only file CREATION events (birth) on a date
grep '2024-06-09' timeline.csv | grep -E ',[^,]*b,'

# A specific user's activity
grep '/Users/jdoe/' timeline.csv | grep '2024-06-09'

# Exclude noise
grep '2024-06-09' timeline.csv | grep -vE '/System/|/usr/share/'
```

🔴 Combine a **date** grep with a **path/keyword** grep to build a focused timeline of exactly the activity in question.

---

## Pitfalls

| 🔴 Pitfall | Avoid by |
|---|---|
| Forgetting `-z` | Always set the time zone (`-z UTC`) |
| Misreading the **Type** column | Learn MACB — `b`=create, `m`=modify, `a`=access, `c`=inode-change |
| Treating one file = one row | A file appears once **per timestamp** |
| `ctime`/`atime` assumptions | `atime` often stale; `ctime` updates on moves/perm changes (timestomp tell) |
| Timestomped times | Corroborate with FSEvents / logs (file MACB can be faked) |
| Huge timeline | `grep` by date + path; or use a date range in `mactime` |

---

## Resources

- The Sleuth Kit (`mactime`, `fls`): https://www.sleuthkit.org/
- `man mactime` · bodyfile format: https://wiki.sleuthkit.org/index.php?title=Body_file
