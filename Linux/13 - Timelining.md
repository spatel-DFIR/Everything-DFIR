# Timelining

A timeline is what turns scattered artifacts into a story: the moment a file was created, then executed, then a config was modified, then a connection opened. On Linux you build it in layers — filesystem metadata (The Sleuth Kit → mactime), then a *super timeline* (Plaso) that fuses filesystem, syslog, journald, auditd, package history, and shell history into one sorted sequence, optionally reviewed in Timesketch. The craft is in anchoring to a known event and expanding outward, while staying alert to the timestamp pitfalls (unreliable atime, hard-to-get birth time, timestomping) that can quietly mislead you.

> 🔴 Normalize everything to **UTC** before you correlate, and know your timestamp traps: `atime` is unreliable under `relatime`/`noatime`, `crtime` isn't shown by plain `stat`, and `ctime` is your one anti-timestomp anchor because `touch` can't set it. A timeline built on local-time logs mixed with UTC filesystem times will silently misorder events.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Filesystem Timeline with The Sleuth Kit](#filesystem-timeline-with-the-sleuth-kit)
- [Reading MACB](#reading-macb)
- [Plaso Super Timeline](#plaso-super-timeline)
- [Timesketch](#timesketch)
- [Quick Filesystem Timelines](#quick-filesystem-timelines)
- [Timestamp Pitfalls](#timestamp-pitfalls)
- [Working the Timeline](#working-the-timeline)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Partition offset, then filesystem bodyfile -> mactime
mmls disk.img

fls -r -m / -o <offset> disk.img > bodyfile

mactime -b bodyfile -d -y -z UTC > timeline.csv

# Full super timeline (filesystem + logs + journal + history)
log2timeline.py --parsers linux timeline.plaso /mnt/evidence

psort.py -o l2tcsv -w supertimeline.csv timeline.plaso
```

## What to Check for What

| Investigative question | Command / action |
|------------------------|------------------|
| Filesystem timeline (deleted incl.)? | `fls -m` + `ils -m` → `mactime -z UTC` |
| Everything fused (fs + logs + journal + history)? | Plaso `log2timeline.py` → `psort.py` |
| Collaborative review of a huge timeline? | Timesketch import |
| Quick live-host recent-changes? | `find -newermt … ! -newermt …` |
| A single drop event (files in one minute)? | mtime-cluster sort |
| Was a file timestomped? | `ctime > mtime`; zeroed nanoseconds |
| Is a silent stretch tampering? | log-source gap vs expected retention |
| Confirm a chain at time T? | converge fs + auditd + auth + network at T |

## Filesystem Timeline with The Sleuth Kit

The filesystem-metadata timeline is the base layer — the MACB (modify/access/change/birth) sequence of every file, including deleted ones. The full Sleuth Kit toolkit (partition/filesystem/inode/block analysis, content extraction, deleted-file recovery) has its own note in the File Systems folder; here is just the timeline-building step, which feeds the super timeline below.

```bash
# Partition offset
mmls disk.img

# Bodyfile for the whole filesystem (deleted entries included)
fls -r -m / -o 227328 disk.img > bodyfile

# Add inode data so deleted/unallocated inodes appear too
ils -m -o 227328 disk.img >> bodyfile

# Sort into a dated, UTC timeline
mactime -b bodyfile -d -y -z UTC > timeline.csv

# Restrict to a date window
mactime -b bodyfile -d -y -z UTC 2026-04-23..2026-04-28 > window.csv
```

Each `mactime` line shows *which* of the four times fired, so you can watch a file be created, executed, then modified in sequence. Including `ils` captures unallocated inodes, so deleted files with intact inode data show up — often exactly the attacker artifacts you're after. For pulling those files back, resolving inodes, or reading the journal, see **The Sleuth Kit** note.

## Reading MACB

The `mactime` output prefixes each event with which of the four times fired — reading it correctly is what lets you sequence a file's life:

| Column | Time | Fires when |
|--------|------|-----------|
| **m** | modify (mtime) | File **content** last changed |
| **a** | access (atime) | File last **read** (unreliable under `relatime`) |
| **c** | change (ctime) | **Inode metadata** changed — the anti-timestomp anchor |
| **b** | birth (crtime) | File **created** (ext4/XFS/Btrfs) |

```
2026-04-27 02:03:11  ...  ..cb  /tmp/.x        <- created (b) + inode set (c): the drop
2026-04-27 02:03:14  ...  m...  /etc/cron.d/x  <- content modified: persistence written
2026-04-27 02:03:15  ...  .a..  /tmp/.x        <- accessed/executed
```

🔴 A line where **`m`/`a` are old but `c` is recent** (e.g. `..c.` in the incident window while the `m` time claims months ago) is the timestomp signature — `touch` moved `mtime`/`atime` back but couldn't touch `ctime`.

## Plaso Super Timeline

Plaso (`log2timeline`) is the power tool: it runs dozens of parsers to fuse filesystem times with syslog, journald, auditd, bash/zsh history, package history, wtmp/utmp, SELinux, and web logs into a single, sorted, filterable timeline — the closest you get to seeing the whole incident at once.

```bash
# Ingest a mounted image (or a device, or a directory of collected artifacts)
log2timeline.py --parsers linux storage.plaso /mnt/evidence

# Ingest a raw image with all applicable parsers
log2timeline.py storage.plaso disk.img

# Filter + output to CSV
psort.py -o l2tcsv -w supertimeline.csv storage.plaso

# Narrow to a time slice
psort.py -o l2tcsv -w window.csv storage.plaso \
  "date > '2026-04-23 00:00:00' AND date < '2026-04-28 00:00:00'"

# See what parsers ran / stats
pinfo.py storage.plaso
```

Useful Linux parsers to know: `syslog`, `systemd_journal`, `bash_history`, `zsh_extended_history`, `utmp`, `selinux`, `dpkg`, `apt_history`, `apache_access`. The `--parsers linux` preset restricts to the relevant set and keeps the output focused.

## Timesketch

For a large super timeline, reviewing a multi-million-line CSV by hand doesn't scale — **Timesketch** is the collaborative front-end for exactly this. Load the Plaso storage file, then search, tag, star, and annotate events, and lay multiple sources into named "sketches" so a team can work the same timeline.

```bash
# Import a Plaso storage file into Timesketch (web UI handles the rest)
timesketch_importer -u <user> --sketch_name "Case-1234" storage.plaso

# Or upload a CSV/JSONL timeline
timesketch_importer --sketch_name "Case-1234" supertimeline.csv
```

Timesketch shines when you need to *share* a timeline, tag the confirmed-malicious events, and build the incident narrative collaboratively — it turns the raw Plaso output into a workable investigation surface.

## Quick Filesystem Timelines

When you don't need full TSK, `find`/`stat` give a fast live-host timeline of recently-changed files:

```bash
# Everything changed in a window
find / -newermt "2026-04-23 00:00:00" ! -newermt "2026-04-28 00:00:00" -print 2>/dev/null

# With full metadata
find /etc /home /root /var/www -type f -newermt "2026-04-27" -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort

# Bodyfile-style output from stat (portable)
find / -xdev -printf '%T@ %p %s\n' 2>/dev/null | sort -n > fs_times.txt
```

## Timestamp Pitfalls

Read the File Systems and Permissions notes for the full treatment; the timeline-critical points:

- **atime is often unreliable** — `relatime`/`noatime` mounts don't update it per access. Check `mount` before using atime as "when it was read."
- **crtime/birth** isn't shown by default `stat`; get it via `statx`/`debugfs` (ext4) or TSK. Some filesystems (ext3, older) lack it entirely.
- **ctime can't be forged with `touch`** — it's your best anti-timestomp anchor. `mtime`/`atime` older than `ctime` = likely stomped.
- **Timezone:** normalize everything to UTC (`mactime -z UTC`, `journalctl --utc`, a fixed zone in `psort`) or events won't line up.

## Working the Timeline

- **Anchor** on a known event: the first alert, a specific login (auth log), a webshell's file mtime, a cron trigger.
- **Expand outward** from the anchor in both directions; the burst of activity around it is usually the intrusion.
- **Correlate sources:** a filesystem file-create + an auditd `execve` + an auth login + a network connection at the same second tell one coherent story — that convergence is how you confirm a chain.
- **Watch for gaps:** a silent stretch where logs should exist can be tampering (cross-ref the Logging Architecture note), not an absence of activity.

## Deep Threat Hunts

Anchor, converge, and hunt the tells. *(seasoned-DFIR)*

```bash
# 1. Base filesystem timeline (deleted included), bounded to the window
fls -r -m / -o <off> disk.img > body; ils -m -o <off> disk.img >> body
mactime -b body -d -y -z UTC 2026-04-23..2026-04-28 > window.csv

# 2. Super timeline fusing fs + logs + journal + auditd + history
log2timeline.py --parsers linux tl.plaso /mnt/evidence
psort.py -o l2tcsv -w super.csv tl.plaso "date > '2026-04-23 00:00:00' AND date < '2026-04-28 00:00:00'"

# 3. The 1-minute DROP CLUSTER: files created in the same minute = one event
find / -xdev -type f -newermt "2026-04-27 02:00" ! -newermt "2026-04-27 02:05" \
  -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort

# 4. Timestomp scan across the tree (ctime much newer than mtime)
find /etc /usr/bin /usr/sbin /tmp /home -type f -printf '%C@ %T@ %p\n' 2>/dev/null | awk '$1 > $2+86400{print}'

# 5. CONVERGENCE at a suspect timestamp — fs + auditd + auth + net in one window
ausearch -ts 04/27/2026 02:00:00 -te 04/27/2026 02:10:00 -i 2>/dev/null

journalctl --since "2026-04-27 02:00" --until "2026-04-27 02:10" --utc

# 6. Log-source GAP detection (silence where activity should be)
journalctl --list-boots; aureport -t 2>/dev/null; last -F | tail

# 7. Collaborative review + Sigma analyzer in Timesketch
timesketch_importer --sketch_name "Case-1234" tl.plaso
```

**Hunt ideas:**

- **Anchor on the first solid event** (alert / login / webshell mtime), then expand ±minutes — the burst around it is the intrusion.
- **Convergence is confirmation** — a filesystem file-create + an auditd `execve` + an auth login + a network connect in the same window is one coherent chain.
- **The 1-minute file-create cluster is a single drop/extract event** — sort by mtime to isolate it.
- **A timestomp scan** (`ctime ≫ mtime`, zeroed nanoseconds) surfaces buried files the timeline would otherwise misplace far in the past.
- **A log-source gap** (missing journal boot, short `aureport -t`, `wtmp` hole) at the incident window is *tampering*, not absence of activity.

## Getting Max Value

- **Normalize to UTC everywhere** — `mactime -z UTC`, `journalctl --utc`, a fixed zone in `psort` — or local-time logs misorder against UTC filesystem times.
- **Layer it:** TSK base timeline → Plaso super timeline → Timesketch for collaborative review of the big output.
- **Anchor + expand; convergence confirms** the chain; gaps flag tampering.
- **Trust `ctime` as the anti-timestomp anchor** and treat `atime` as unreliable.
- **Bound Plaso/psort to the incident window** so the multi-million-line output stays workable.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Build the fs bodyfile / recover deleted files | **The Sleuth Kit** (07) |
| Interpret timestamps / prove timestomp | **File and Directory Permissions** (02), **File Systems** (07) |
| Confirm a gap is tampering | **Logging Architecture** (06), **Anti-Forensics** (13b) |
| The command that ran at time T | **Auditd**, **Systemd Journal** |
| The login at time T | **Authentication and Login Records** |
| The network activity at time T | **Network and PCAP Forensics** (10c) |

## Scenarios

- **Anchor-and-expand:** from the first alert outward, the surrounding burst is the intrusion.
- **Drop→run:** a just-created `/tmp` file followed seconds later by an auditd `execve` of it.
- **Bulk drop:** 40 file-creates in a single minute — one archive extraction / mass drop.
- **Timestomp bust:** `ctime` in the incident window while `mtime` claims months ago.
- **Log gap:** a missing journal boot or short `aureport -t` exactly across the incident window.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `ctime` newer than `mtime`/`atime` in the timeline | Timestamping |
| A cluster of file-creates in one second | Bulk drop / archive extraction |
| Log-source gap around the incident | Anti-forensics |
| Filesystem event with no matching log event (or vice-versa) | Selective log deletion |
| Execution (auditd) from a just-created temp file | Dropper → run sequence |
| MACB line with old `m`/`a` but recent `c` | Timestomp (`touch` can't set `ctime`) |
| Convergence of fs+auditd+auth+net at one second | Confirmed activity chain |

## Resources

- The Sleuth Kit + `mactime` — https://sleuthkit.org
- Plaso / log2timeline — https://plaso.readthedocs.io
- Timesketch — https://timesketch.org
- MITRE ATT&CK: T1070.006 (Timestomp), T1070.002 (Clear Logs — gap detection)
