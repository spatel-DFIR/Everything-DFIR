# ext4

ext4 is the default on Debian/Ubuntu and a huge fraction of Linux servers, and it's the friendliest mainstream Linux filesystem for forensics: it's journaled, stores a birth timestamp you can reach, and — unlike XFS — gives you real prospects for recovering deleted files. Understanding its structure (superblock, inodes, block groups, journal) turns `stat`/`debugfs`/Sleuth-Kit output from noise into evidence, and lets you detect timestomping and recover an attacker's deleted tools.

> 🔴 `ctime` is your anti-timestomp anchor here. `touch` can set `mtime`/`atime` to any past date, but it **cannot** set `ctime`, which the inode updates on any change. When a dropped file's `mtime` looks old but its `ctime` is recent, you're looking at a timestomp — and `crtime` (birth) newer than `mtime` is physically impossible for an untouched file, so it's another tell.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Structure](#structure)
- [Timestamps and crtime](#timestamps-and-crtime)
- [Inode and Metadata Analysis](#inode-and-metadata-analysis)
- [The Journal](#the-journal)
- [Deleted File Recovery](#deleted-file-recovery)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Filesystem summary (block groups, inode count, features, times)
sudo dumpe2fs -h /dev/sda1

# Birth time of a file (statx)
stat --printf='%n  born:%w  mod:%y  chg:%z\n' /path/to/file

# Full inode detail incl. crtime, via debugfs
sudo debugfs -R "stat <inode>" /dev/sda1

# List recently deleted inodes
sudo debugfs -R "lsdel" /dev/sda1
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Is this file timestomped? | `debugfs -R "stat <inode>"` → compare `crtime`/`ctime` vs `mtime` |
| What's the file's real birth time? | `stat --printf='%w'`; `debugfs -R "stat <inode>"` |
| What deleted files can I recover? | `debugfs -R "lsdel" /dev/sdX` |
| Recover a specific deleted file | `extundelete --restore-file <path>` (on an image) |
| Was a system binary swapped? | journal `logdump`/`jls` for the prior inode state |
| Full filesystem timeline? | `fls -r -m / -o <off> img > bodyfile` → `mactime` |
| Metadata gone — raw payload still there? | carve unallocated (`foremost`/`photorec`) |
| Filesystem geometry / features? | `dumpe2fs -h`; `tune2fs -l` |
| Inode ↔ name mapping? | `ls -i` (name→inode); `debugfs -R "ncheck <inode>"` (inode→name) |

## Structure

ext4 divides the volume into **block groups**, each carrying a backup superblock, block/inode bitmaps, an inode table, and data blocks. File metadata lives in **inodes** (times, size, ownership, block pointers); directory entries map names → inode numbers. The practical takeaway: names and metadata are separable, which is exactly why a deleted file's inode data can survive after its directory entry is gone.

```bash
# Superblock + geometry (block size, inodes per group, features, mount count, last-check)
sudo dumpe2fs -h /dev/sda1

# Full block-group detail
sudo dumpe2fs /dev/sda1 | less

# Features enabled (has_journal, extent, 64bit, metadata_csum, etc.)
sudo tune2fs -l /dev/sda1
```

## Timestamps and crtime

ext4 inodes hold four timestamps with nanosecond precision. Knowing which `touch` can forge (and which it can't) is the whole basis of timestomp detection.

| Field | Meaning |
|-------|---------|
| `atime` | Last access (unreliable under `relatime`/`noatime`) |
| `mtime` | Content last modified (freely forgeable) |
| `ctime` | Inode last changed — **not forgeable by `touch`** |
| `crtime` | Creation / birth (ext4-only; not shown by plain `ls`) |

```bash
# Birth via statx (newer coreutils)
stat --printf='birth: %w\n' file

# Birth + all times from the inode directly
sudo debugfs -R "stat <inode>" /dev/sda1

# Find an inode number for a path
sudo debugfs -R "ncheck <inode>" /dev/sda1   # inode -> name

ls -i file                                    # name -> inode
```

🔴 The nanosecond field is a bonus timestomp tell: `touch -t` sets whole-second times with zeroed nanoseconds, so a dropped file showing `.000000000` among neighbors with real sub-second precision was time-set programmatically.

## Inode and Metadata Analysis

```bash
# Sleuth Kit inode detail (offset-aware, works on images)
istat -o <offset> disk.img <inode>

# Map path <-> inode on a live device
sudo debugfs -R "stat /etc/passwd" /dev/sda1

# Link count, block pointers, extents
sudo debugfs -R "dump_extents <inode>" /dev/sda1
```

An inode with a **zero link count but still-allocated data blocks** is a recently deleted file whose contents may be intact — the directory entry is gone, but the data hasn't been overwritten yet. That's the recovery opportunity below.

## The Journal

ext4's journal (jbd2, usually inode 8) records metadata changes before committing them, so it can contain *recent-but-superseded* metadata — a snapshot of how the filesystem looked moments ago.

```bash
# Journal is an internal inode (usually inode 8)
sudo debugfs -R "stat <8>" /dev/sda1

# Sleuth Kit: list and read journal blocks
jls -f ext4 -o <offset> disk.img

jcat -f ext4 -o <offset> disk.img <block>
```

Journal analysis can reveal that a file was recently modified or replaced even when the current inode has been overwritten — useful when an attacker swapped a binary and you want to see the prior state.

## Deleted File Recovery

This is ext4's forensic advantage. Deleted inodes and their data blocks often persist until reused, so recovery is frequently possible — *if* you work on an image and don't let the blocks get overwritten.

```bash
# List deleted inodes with size/time
sudo debugfs -R "lsdel" /dev/sda1

# Dump a deleted inode's content to a file
sudo debugfs -R "dump <inode> /tmp/recovered" /dev/sda1

# extundelete (recover by path or whole FS) - run on an UNMOUNTED device/image
sudo extundelete /dev/sda1 --restore-file path/to/deleted

sudo extundelete /dev/sda1 --restore-all

# ext4magic (alternative, uses the journal)
ext4magic /dev/sda1 -f path/ -r
```

🔴 Recovery odds fall fast as freed blocks get reused, so **image first and work on the copy** — never run recovery against a live source you're still writing to. ext4's use of extents (contiguous ranges) rather than old indirect blocks makes partial recovery of large files common. Deleted inodes for tools or logs in `lsdel` are a direct sign of attacker cleanup.

## Deep Threat Hunts

Recovery + tamper-proof pipeline. *(seasoned-DFIR; work on an image, never a live mounted source)*

```bash
# 1. All deleted inodes with size/time — attacker cleanup surfaces here
debugfs -R "lsdel" /dev/sda1 2>/dev/null

# 2. Recover a specific deleted file by path (unmounted device / image)
extundelete /dev/sda1 --restore-file path/to/deleted

# 3. Full filesystem timeline via a TSK bodyfile -> mactime
fls -r -m / -o <offset> disk.img > bodyfile.txt

mactime -b bodyfile.txt -d 2026-04-23 > timeline.csv

# 4. Journal replay — see PRIOR metadata (detect a swapped binary)
debugfs -R "logdump -S" /dev/sda1 2>/dev/null | less

# 5. Orphan-inode list (files deleted while still open — recoverable)
debugfs -R "stat <7>" /dev/sda1 2>/dev/null

# 6. When metadata is overwritten, carve unallocated space for the raw payload
foremost -i disk.img -o /evidence/carved 2>/dev/null

# 7. Backup superblocks (if the primary was wiped/corrupted)
dumpe2fs /dev/sda1 2>/dev/null | grep -i 'Backup superblock'

# 8. Recover a deleted inode's content by number (TSK)
icat -r -o <offset> disk.img <inode> > /evidence/recovered.bin
```

**Hunt ideas:**

- **`lsdel` + `dump`/`extundelete` recovers the attacker's deleted tools and logs** — the act of cleanup is itself the lead.
- **The jbd2 journal remembers prior state** — `logdump`/`jls` can show a binary's *previous* inode/metadata even after it was swapped in place.
- **When metadata is gone, carve** — `foremost`/`photorec`/`scalpel` pull the raw payload out of unallocated blocks by file signature.
- **Build one `fls -m` bodyfile → mactime timeline** — the drop cluster and the cleanup both stand out against normal churn.
- **`crtime > mtime` and zeroed-nanosecond times are the two ext4-specific timestomp proofs** — batch `debugfs stat` across suspect inodes.

## Getting Max Value

- **Image first, work on the copy.** Recovery odds crater as freed blocks are reused; never recover against a live, still-writing source.
- **Right tool per context:** `debugfs` (live, read-only) for `crtime`/`lsdel`; TSK `istat`/`icat`/`fls` for image work.
- **Preserve the journal** — it's a mini rollback log; `e2image` captures ext4 metadata compactly for offline analysis.
- **Extents make partial large-file recovery common** — attempt recovery even for big files, not just small ones.
- **Feed `fls -m` into `mactime`** for the master timeline (→ Timelining note).

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Full inode/block/journal/timeline pipeline on an image | **The Sleuth Kit** |
| Interpret the four timestamps / prove timestomp | **File and Directory Permissions** (02) |
| Build the mactime timeline | **Timelining** (13) |
| Recover a still-running deleted binary (live) | **Live Response** (10, `/proc/PID/exe`) |
| Confirm the volume is actually ext4 / its layering | **Filesystem Triage and Identification** |
| Anti-forensics context (`shred`, secure-wipe) | **Anti-Forensics and Evidence Destruction** (13b) |

## Scenarios

- **Recover deleted tools:** `lsdel`/`extundelete` pulls the attacker's removed binaries and logs back before block reuse.
- **Timestomp proof:** `ctime > mtime`, `crtime > mtime`, or zeroed nanoseconds on a dropped file.
- **Binary swap:** the journal shows the prior inode of a replaced system binary (`ls`, `sshd`).
- **Metadata wiped:** carve unallocated space for the raw payload when inodes are gone.
- **Full timeline:** an `fls -m` bodyfile clusters the drop and the cleanup in one view.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `ctime` newer than `mtime`/`atime` | Timestomping |
| `crtime` after `mtime` | Impossible for untouched file → tampering |
| Deleted inodes for tools/logs in `lsdel` | Cleanup after activity |
| Journal metadata contradicting current inode state | File was altered/replaced recently |
| Recently modified files clustering by inode range | Bulk drop in one operation |
| Zeroed-nanosecond timestamps | Programmatic time-setting |
| Deleted-while-open files in the orphan list | Recoverable attacker artifacts |
| Payloads found only in unallocated (carved) space | Metadata deleted to hide the file |

## Resources

- The Sleuth Kit — https://sleuthkit.org
- `debugfs(8)`, `dumpe2fs(8)`, `tune2fs(8)`, `extundelete(8)`, `e2image(8)`, `foremost(1)` man pages
- MITRE ATT&CK: T1070.004 (File Deletion), T1070.006 (Timestomp), T1485 (Data Destruction)
