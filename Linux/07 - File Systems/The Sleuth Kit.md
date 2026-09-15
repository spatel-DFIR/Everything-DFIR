# The Sleuth Kit

The Sleuth Kit (TSK) is the core open-source toolkit for filesystem forensics on a disk image — it works below the mounted-filesystem layer, letting you enumerate partitions, walk inodes, extract files (including deleted ones) by inode or block, read the journal, and generate a filesystem timeline. Every tool is offset-aware and image-format-aware, so it operates directly on a raw or E01 image without mounting it. This note is organized by the analysis pipeline: find the partition, understand the filesystem, list files, resolve names ↔ inodes, extract content, and recover deleted data.

> 🔴 TSK reads the image without mounting it, which is exactly what you want forensically — no accidental writes, no journal replay. Work on a **copy**, and remember every command needs the partition **offset** (`-o`, in sectors) from `mmls`; forget it and you're reading the partition table instead of the filesystem.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [The Analysis Pipeline](#the-analysis-pipeline)
- [Image and Partition Layer](#image-and-partition-layer)
- [Filesystem Layer](#filesystem-layer)
- [File and Directory Layer](#file-and-directory-layer)
- [Inode and Metadata Layer](#inode-and-metadata-layer)
- [Content and Block Extraction](#content-and-block-extraction)
- [Journal Analysis](#journal-analysis)
- [Filesystem Timeline](#filesystem-timeline)
- [Deleted File Recovery](#deleted-file-recovery)
- [String to File Mapping](#string-to-file-mapping)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# 1. Partition layout (get the offset)
mmls disk.img

# 2. Filesystem details at the offset
fsstat -o 227328 disk.img

# 3. Recursive file listing with timestamps (deleted entries marked *)
fls -r -l -o 227328 disk.img | less

# 4. Build a timeline
fls -r -m / -o 227328 disk.img > bodyfile; mactime -b bodyfile -d -y -z UTC > timeline.csv
```

## What to Check for What

| Investigative question | Tool / command |
|------------------------|----------------|
| What partitions / where's the offset? | `mmls disk.img` |
| What filesystem + inode range? | `fsstat -o <off> disk.img` |
| What files exist (incl. deleted)? | `fls -r -l -o <off> disk.img` (deleted marked `*`) |
| Deleted-only listing? | `fls -rd -o <off> disk.img` |
| Metadata/timestamps for one object? | `istat -o <off> disk.img <inode>` |
| Recover one file by inode? | `icat -o <off> disk.img <inode> > out` |
| Bulk-recover everything incl. deleted? | `tsk_recover -e -o <off> disk.img outdir/` |
| Full filesystem timeline? | `tsk_gettimes` (or `fls -m`+`ils -m`) → `mactime` |
| Which file owns a suspicious block? | `ifind -o <off> -d <block> disk.img` |
| Map a keyword hit back to its file? | `blkls`→`srch_strings`→`blkcalc`→`ifind -d`→`ffind` |
| Prior state of a swapped binary? | `jls`/`jcat` (ext journal) |

## The Analysis Pipeline

TSK tools are layered — each layer answers a different question, and the workflow moves top to bottom:

| Layer | Question | Tools |
|-------|----------|-------|
| Image | What image / partitions? | `mmls`, `img_stat`, `img_cat` |
| Filesystem | What FS, geometry, inode range? | `fsstat` |
| File/dir | What files exist (incl. deleted)? | `fls`, `ffind`, `ifind` |
| Inode | Metadata for one object? | `istat`, `ils` |
| Content | The actual bytes? | `icat`, `fcat` |
| Block | Raw/unallocated data? | `blkcat`, `blkls`, `blkstat` |
| Journal | Recent FS changes? | `jls`, `jcat` |

## Image and Partition Layer

```bash
# Partition table: offsets (in sectors), sizes, types
mmls disk.img

# Compute a partition's byte size (sectors * 512)
echo $((512 * 83658719))

# Metadata of an E01/EWF image (size, sector size, hashes)
img_stat -i ewf evidence.E01

# Extract a raw byte span from the image (carve by sector offset)
img_cat -s <start_sector> -e <end_sector> disk.E01 > span.raw
```

The `mmls` output gives the **starting sector** of each partition — that number is the `-o` offset every downstream tool needs.

## Filesystem Layer

```bash
# Filesystem details: type, block size, inode range, block groups, last mount/write
fsstat -o 227328 disk.img

# Specify FS type + image format explicitly (E01)
fsstat -f ext4 -i ewf -o 227328 evidence.E01
```

`fsstat` confirms the filesystem type (drives your recovery strategy — see the ext4/XFS/Btrfs notes) and gives the inode range you'll iterate over, plus last-mount/last-write times useful for the timeline.

## File and Directory Layer

```bash
# List files with inode + type; -l adds timestamps, -r recurses, deleted marked with *
fls -l -o 227328 disk.img

fls -r -l -o 227328 disk.img

# List a specific directory by its inode
fls -l -o 227328 disk.img <dir_inode>

# Resolve a path -> inode
ifind -o 227328 disk.img -n /etc/passwd

# Resolve an inode -> path/name
ffind -o 227328 disk.img <inode>
```

🔴 `fls` marks deleted entries with a `*` and shows their inode — deleted files whose inode is still intact are prime recovery targets (below). `fls -r` gives you the whole tree, deleted entries included.

## Inode and Metadata Layer

```bash
# Full metadata for one inode: times (MACB), size, ownership, allocated blocks
istat -o 227328 disk.img <inode>

# List all inodes (allocated + unallocated) - basis for a timeline incl. deleted
ils -o 227328 disk.img

# Just the unallocated (deleted) inodes with their times
ils -o 227328 -r disk.img
```

`istat` on a suspect inode gives you its exact timestamps (compare `ctime` vs `mtime` for timestomp tells — see Permissions) and its block list (needed to carve the content directly).

## Content and Block Extraction

```bash
# Extract a file's content by inode (works for deleted inodes with intact block pointers)
icat -o 227328 disk.img <inode> > recovered_file

# Extract by path
fcat /etc/passwd -o 227328 disk.img

# Read a specific data block
blkcat -o 227328 disk.img <block>

# Dump ALL unallocated blocks (feed to a carver / strings)
blkls -o 227328 disk.img > unallocated.blk

# Is a given block allocated?
blkstat -o 227328 disk.img <block>
```

🔴 `icat` on a deleted inode recovers the file content directly if the block pointers survive — often the fastest way to pull back a deleted attacker tool on ext4. `blkls` dumps unallocated space for carving or `strings` searching when the metadata is gone (e.g. on XFS).

## Journal Analysis

The ext filesystem journal can hold recent metadata that's since been overwritten — useful to see a file's prior state after an attacker replaced it.

```bash
# List journal entries
jls -f ext4 -o 227328 disk.img

# Read a specific journal block
jcat -f ext4 -o 227328 disk.img <block>
```

## Filesystem Timeline

TSK's `fls -m` + `mactime` produces the filesystem-metadata timeline — the MACB (modify/access/change/birth) sequence of every file, including deleted ones.

```bash
# Bodyfile for the whole filesystem
fls -r -m / -o 227328 disk.img > bodyfile

# Add inode data (captures deleted/unallocated inodes too)
ils -m -o 227328 disk.img >> bodyfile

# One-step alternative: tsk_gettimes builds the bodyfile in a single command
tsk_gettimes -o 227328 disk.img > bodyfile

# Sort into a dated, UTC timeline
mactime -b bodyfile -d -y -z UTC > timeline.csv

# Restrict to a date window
mactime -b bodyfile -d -y -z UTC 2026-04-23..2026-04-28 > window.csv
```

This filesystem timeline is one input to the broader **super timeline** (which fuses it with logs, journald, and history) — see the Timelining note for Plaso and Timesketch. Each `mactime` line shows *which* of the four times fired, so you can watch a file be created, executed, then modified.

## Deleted File Recovery

TSK is the manual-recovery path; combine it with the filesystem-specific tools (ext4 `extundelete`, XFS carving, Btrfs snapshots — see those notes).

```bash
# Find deleted entries, then recover by inode
fls -rd -o 227328 disk.img            # -d = deleted only

icat -o 227328 disk.img <deleted_inode> > /evidence/recovered

# When metadata is gone, carve unallocated space by signature
blkls -o 227328 disk.img | strings | grep -i "secret"

# Or hand blkls output to a carver
blkls -o 227328 disk.img > unalloc.blk; photorec unalloc.blk

# Bulk-recover EVERY file (allocated + deleted) from the image at once
tsk_recover -e -o 227328 disk.img /evidence/recovered/
```

🔴 Deleted tools/logs appearing in `fls -rd` are direct evidence of attacker cleanup. Recover promptly and work on a copy — the longer the source is live, the more freed blocks get reused. `tsk_recover -e` dumps the whole filesystem (including deleted files) so you can hash/YARA the entire set in one pass.

## String to File Mapping

🔴 The signature TSK technique: you find an attacker keyword (a C2 domain, a filename, a secret) in **unallocated space**, and you need to know *which deleted file it came from*. Map the raw offset back through the block layers to a name.

```bash
# 1. Dump unallocated blocks and string-search them (byte offsets with -t d)
blkls -o 227328 disk.img > unalloc.blk

srch_strings -t d unalloc.blk | grep -i "evil.com"
#   note the byte offset -> divide by block size (from fsstat) = blkls-relative block

# 2. Convert the blkls-relative block to an IMAGE block number
blkcalc -o 227328 -u <blkls_block> disk.img

# 3. Which inode owns that image block?
ifind -o 227328 -d <image_block> disk.img

# 4. Which filename is that inode?
ffind -a -o 227328 disk.img <inode>
```

This chain — `blkls` → `srch_strings` → `blkcalc` → `ifind -d` → `ffind` — turns a keyword hit in raw unallocated space into a named (often deleted) file. `ifind -d <block>` on its own answers "what file owns this block" for any suspicious block.

## Deep Threat Hunts

*(seasoned-DFIR; TSK's edge is reading the image without mounting + reaching deleted/unallocated data)*

```bash
# 1. Deleted-only listing = attacker cleanup, then recover
fls -rd -o 227328 disk.img

icat -o 227328 disk.img <deleted_inode> > /evidence/recovered

# 2. Bulk recover everything incl. deleted, then hash against known-bad
tsk_recover -e -o 227328 disk.img /evidence/rec/

find /evidence/rec -type f -exec sha256sum {} + | grep -Ff bad_hashes.txt

# 3. One-step timeline for the super-timeline pipeline
tsk_gettimes -o 227328 disk.img > bodyfile

mactime -b bodyfile -d -y -z UTC > timeline.csv

# 4. Keyword-in-unallocated -> file (see String to File Mapping)
blkls -o 227328 disk.img | srch_strings -t d | grep -i "c2-domain-or-secret"

# 5. What file owns a suspicious block?
ifind -o 227328 -d <block> disk.img

# 6. Journal: prior state of a replaced binary
jls -f ext4 -o 227328 disk.img

# 7. Carve unallocated for structured artifacts
blkls -o 227328 disk.img | foremost -o /evidence/carved
```

**Hunt ideas:**

- **The string→file chain is the killer move** — a C2 domain or secret found in unallocated maps back through `blkcalc`/`ifind -d`/`ffind` to the deleted file it lived in.
- **`tsk_recover -e` bulk-dumps everything** (incl. deleted) so you can YARA/hash the entire filesystem in one pass instead of picking inodes by hand.
- **`ifind -d <block>` names the owner of any suspicious block** — turns a raw-offset hit into a file.
- **`tsk_gettimes` is the fast one-command bodyfile** for feeding Plaso's super-timeline.
- **Deleted entries in `fls -rd`** are the cleanup evidence itself — recover before freed blocks get reused.

## Getting Max Value

- **Always use the `mmls` offset (`-o`, in sectors)** — the wrong offset reads the partition table, not the filesystem.
- **`tsk_recover -e` for bulk, `icat` for surgical single-inode** recovery — pick per need.
- **Build the bodyfile** (`tsk_gettimes`, or `fls -m` + `ils -m`) → `mactime`, then fuse it into the Plaso super-timeline (Timelining note).
- **Map keyword hits back to files** with the `blkls`→`srch_strings`→`blkcalc`→`ifind -d`→`ffind` chain.
- **E01 images:** add `-i ewf`, or `ewfmount` to expose the raw device; hash-verify the image before analysis.
- **Never mount the source** — TSK reads without mounting, which is the whole forensic advantage.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Filesystem-specific recovery (undelete/carve/snapshot) | **ext4**, **XFS**, **Btrfs** |
| Fuse the FS timeline with logs into a super-timeline | **Timelining** (13, Plaso/Timesketch) |
| Interpret MACB / prove timestomp | **File and Directory Permissions** (02) |
| Recover a still-running deleted binary (live) | **Live Response** (10, `/proc/PID/exe`) |
| YARA / hash triage of recovered files | **IOC and YARA Scanning** (11d), **ELF and Malware Triage** (11b) |
| Which partition / FS layering the image has | **Filesystem Triage and Identification** |

## Scenarios

- **Deleted-tool recovery:** `fls -rd` finds the cleanup, `icat`/`tsk_recover -e` pulls the bytes back.
- **Keyword-to-file:** a secret string in unallocated space mapped back to its deleted source file.
- **Timeline:** `tsk_gettimes` → `mactime` lays out the drop → execute → cleanup sequence.
- **Binary swap:** `jls` shows the prior inode of a replaced system binary.
- **Bulk triage:** `tsk_recover -e` then hash/YARA the whole dump for known-bad.

## Red Flags

| 🔴 Finding | Likely meaning |
|-----------|----------------|
| Deleted entries (`fls *`) for tools/logs | Attacker cleanup |
| `istat` shows `ctime` newer than `mtime`/`atime` | Timestomping |
| Recoverable deleted binary in a staging path | Dropped payload removed post-use |
| Journal metadata contradicting the live inode | File replaced recently |
| Carved unallocated content contradicting the live FS | Deleted attacker artifacts |

## Resources

- The Sleuth Kit — https://sleuthkit.org (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `blkls`, `blkcalc`, `ifind`, `ffind`, `jls`, `tsk_recover`, `tsk_gettimes`, `srch_strings` man pages)
- TSK wiki / usage — https://wiki.sleuthkit.org
- MITRE ATT&CK: T1070.004 (File Deletion), T1070.006 (Timestomp), T1005 (Data from Local System)
