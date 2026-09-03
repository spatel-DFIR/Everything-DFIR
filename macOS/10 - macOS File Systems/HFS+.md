# HFS+ (Mac OS Extended)

**HFS+** (Hierarchical File System Plus, marketed as *Mac OS Extended*) was Apple's default file system from **Mac OS 8.1 (1998)** until **APFS** took over in **High Sierra (10.13, 2017)**. You'll still meet it on older systems, mechanical/fusion drives, many external/backup disks, and **Time Machine** targets (HFS+ until Big Sur). It is **well supported by The Sleuth Kit (TSK)** — unlike APFS — so HFS+ images are very analyst-friendly.

> 🔴 Key forensic facts: catalog timestamps have **1-second resolution** (sub-second timestomping is truncated/visible), data can hide in **resource forks** and **extended attributes**, and `atime` is often stale (access-time updates throttled). TSK reads HFS+ fully.

## Contents
- [Quick Triage](#quick-triage)
- [History and Where You Still See It](#history-and-where-you-still-see-it)
- [On-Disk Structures](#on-disk-structures)
- [Forks](#forks)
- [Metadata and Timestamps](#metadata-and-timestamps)
- [Timestomping](#timestomping)
- [Extended Attributes](#extended-attributes)
- [Journaling](#journaling)
- [Analyzing with The Sleuth Kit](#analyzing-with-the-sleuth-kit)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
diskutil info / | grep -i "Type (Bundle)\|File System"   # confirm it's HFS+ (hfs)

fsstat hfsimage.dd                                        # TSK: volume header + structures

fls -r hfsimage.dd | head                                # TSK: recursive file listing (CNIDs)

istat hfsimage.dd 2                                       # TSK: metadata + MACB for a CNID (2 = root)

stat -f 'B=%SB m=%Sm c=%Sc a=%Sa %N' /path/file          # live: MACB on a mounted HFS+ volume

xattr -l /path/file                                       # live: extended attributes (quarantine, where-from)
```

---

## History and Where You Still See It

| Era | Role |
|---|---|
| Mac OS 8.1 (1998) | HFS+ replaces HFS (more files, Unicode names, smaller blocks) |
| 10.2.2 | **Journaling** added (HFS+J) |
| 10.3 | Case-sensitive variant (HFSX) + ACLs |
| High Sierra 10.13 (2017) | APFS becomes default on SSD; HFS+ legacy |

🔴 Still encountered on: **external/USB & mechanical drives**, **Fusion Drives**, **Time Machine** disks (pre–Big Sur), **bootable clones** of old systems, and any volume formatted "Mac OS Extended."

---

## On-Disk Structures

HFS+ is built from a set of **special files** (B-trees) described by the Volume Header.

| Structure | Role / DFIR value |
|---|---|
| **Volume Header** | At byte offset **1024**; volume size, block size, timestamps, pointers to the special files. Backup copy in the **second-to-last** block (recover a trashed VH) |
| 🔴 **Catalog File** | B-tree of **every file & folder** — names, **CNIDs** (Catalog Node ID = inode), timestamps, fork info. The heart of HFS+ forensics |
| **Extents Overflow File** | B-tree of extra extents when a file is fragmented past the 8 in-catalog extents |
| 🔴 **Attributes File** | B-tree storing **extended attributes** (and inline resource forks) |
| **Allocation File** | Bitmap of used/free allocation blocks (carving / unallocated analysis) |
| **Startup File** | Boot assistance data |
| **Journal** | Transaction replay log (consistency) |

Reserved CNIDs: `1` = parent-of-root, **`2` = root folder**, `3` = extents file, `4` = catalog file, `5` = bad blocks, `6` = allocation, `7` = startup, `8` = attributes. User files start at **16**.

---

## Forks

Every HFS+ object can have two forks:

| Fork | Holds |
|---|---|
| **Data fork** | The normal file contents |
| 🔴 **Resource fork** | Legacy structured metadata/resources — can **hide data**. Accessed as `file/..namedfork/rsrc` or the `com.apple.ResourceFork` xattr |

```bash
ls -l@  file                       # shows xattrs incl. com.apple.ResourceFork (size)

cat file/..namedfork/rsrc | xxd | head     # peek at resource-fork bytes
```

🔴 Data tucked in a resource fork won't show in a normal `cat` of the file — check fork sizes.

---

## Metadata and Timestamps

HFS+ timestamps are **32-bit, seconds since 1904-01-01, 1-second resolution**.

| Timestamp | Meaning (stat field) |
|---|---|
| **Create / Birth** | When the record was created (`%SB`) |
| **Content Modified** | Data last changed (`mtime`, `%Sm`) |
| **Attribute Modified** | Metadata/inode changed (`ctime`, `%Sc`) |
| **Accessed** | Last read (`atime`, `%Sa`) — often **stale** (updates throttled) |
| **Backup** | Last Time Machine backup (rarely set on normal volumes) |

> ⚠️ **Time-zone gotcha:** HFS+ **catalog** record dates are stored in **UTC**, but the **Volume Header** dates are in **local time**. Don't compare the two blindly.

```bash
# Full MACB on a live HFS+ file (BSD stat)
stat -f 'Birth: %SB%nModify: %Sm%nChange: %Sc%nAccess: %Sa%n' /path/file

# TSK on an image — MACB for a CNID
istat hfsimage.dd <CNID>
```

🔴 `atime` later than `mtime` is normal; **`create` later than `modify`** is suspicious (classic timestomp tell). 1-second resolution means **no sub-second precision** — a file showing `.000000000` everywhere on an otherwise-nanosecond timeline may have crossed from APFS, and uniform/round times suggest tampering.

---

## Timestomping

```bash
# Set access & modification times (POSIX)
touch -t 202001010000.00 file                  # [[CC]YY]MMDDhhmm[.SS]

touch -r referencefile file                     # copy another file's times

# Set CREATE (birth) and modified via developer tools (legacy)
SetFile -d '01/01/2020 00:00:00' file           # creation date

SetFile -m '01/01/2020 00:00:00' file           # modification date
```

🔴 **Detection:**
- `create` > `modify` (you can't normally create after you modified).
- All four times identical or suspiciously **round** (e.g. `00:00:00`).
- `mtime`/`atime` edited but **`ctime` (attribute-modified) updated to "now"** — `touch` can't backdate ctime without deeper tampering, so a fresh ctime next to old m/a times is a flag.
- Catalog dates contradicting **Spotlight** (`mdls` `kMDItem*Date`), **quarantine** event time, or Unified Log entries for the same file.

---

## Extended Attributes

xattrs live in the **Attributes File** B-tree: **inline** (small) or pointing to extents (large).

```bash
xattr -l file                                   # list all xattrs + values

xattr -p com.apple.quarantine file              # download provenance (cross-ref File Permissions)

xattr -p com.apple.metadata:kMDItemWhereFroms file | xxd   # source URL (binary plist)
```

Common high-value xattrs: `com.apple.quarantine`, `com.apple.metadata:kMDItemWhereFroms`, `com.apple.FinderInfo`, `com.apple.ResourceFork`. (Full xattr forensics → *File and Directory Permissions* note.)

---

## Journaling

The **HFS+ journal** (HFS+J) logs metadata transactions for crash consistency.

🔴 DFIR value: the journal can contain **recently changed catalog records** — sometimes recoverable evidence of files/metadata that were since altered or deleted. It's a wrap-around log, so coverage is recent-only.

---

## Analyzing with The Sleuth Kit

TSK has **full HFS+ support** — the go-to for dead-box HFS+ analysis.

```bash
# Volume / file-system structures
fsstat hfsimage.dd

# Recursive file & directory listing (with CNIDs); -d = deleted only
fls -r hfsimage.dd

fls -rd hfsimage.dd                              # deleted entries

# Metadata + MACB timestamps for a CNID
istat hfsimage.dd <CNID>

# Extract a file's content by CNID
icat hfsimage.dd <CNID> > recovered.bin

# Map a path/inode and timeline
ffind hfsimage.dd <CNID>                         # CNID -> path

fls -m / hfsimage.dd > body.txt                  # bodyfile for the timeline

mactime -b body.txt -d > timeline.csv            # MACB timeline
```

> If the image is split/E01, use `mmls` first to find the HFS+ partition offset, then pass `-o <offset>` to the TSK tools. For Time Machine HFS+ disks, hard-link "directories" make `fls` output large — expect that.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `create` newer than `modify` | Timestomping |
| All MACB times identical / suspiciously round | Timestamps faked |
| Fresh `ctime` (attribute-mod) next to old m/a times | `touch`-style tampering |
| Catalog times contradict Spotlight / quarantine / logs | Manipulated timestamps |
| Large **resource fork** on an ordinary file | Hidden data |
| Unexpected `com.apple.quarantine` absent on a downloaded binary | Quarantine stripped to evade Gatekeeper |
| Files only in the **journal** / unallocated, not the catalog | Deleted/altered evidence recoverable |
| Volume formatted HFS+ on a modern Mac's external drive | Possible staging/exfil media |

---

## Resources

- The Sleuth Kit: https://www.sleuthkit.org/
- Apple TN1150 — HFS Plus Volume Format: https://developer.apple.com/library/archive/technotes/tn/tn1150.html
