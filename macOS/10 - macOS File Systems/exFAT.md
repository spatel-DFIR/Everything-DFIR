# exFAT

**exFAT** (Extended File Allocation Table) is Microsoft's 2006 successor to FAT32, lifting FAT32's 4 GB file-size and ~32 GB volume limits while staying lightweight. macOS has supported it since **Mac OS X 10.6.5 (Snow Leopard)**. It's the **cross-platform** format of choice — USB sticks, SD cards, cameras, and external drives shared between **macOS, Windows, and Linux** — which is exactly why it matters in investigations: **removable media used to move data on/off a Mac**.

> 🔴 exFAT has **no permissions, no ownership, no native extended attributes, and no journaling**. So macOS stores its metadata (xattrs, quarantine, resource forks) in **AppleDouble `._` companion files**, and litters the volume with `.DS_Store`, `.Spotlight-V100`, `.Trashes`, `.fseventsd`, `.TemporaryItems`. Those Mac artifacts on an exFAT stick are proof a Mac touched it — and the `._` files can preserve the **download source / quarantine** of files that were exfiltrated.

## Contents
- [Quick Triage](#quick-triage)
- [What It Is and Where You See It](#what-it-is-and-where-you-see-it)
- [On-Disk Structure](#on-disk-structure)
- [Timestamps](#timestamps)
- [No Permissions so macOS Uses AppleDouble](#no-permissions-so-macos-uses-appledouble)
- [Mac Artifacts Left on exFAT Media](#mac-artifacts-left-on-exfat-media)
- [Deleted File Recovery](#deleted-file-recovery)
- [Analysis with The Sleuth Kit](#analysis-with-the-sleuth-kit)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
diskutil info /Volumes/USB | grep -i "File System"        # confirm exFAT

ls -la@ /Volumes/USB                                       # see ._* AppleDouble + .DS_Store etc.

find /Volumes/USB -name '._*' -print                       # AppleDouble metadata companions

xattr -l /Volumes/USB/suspicious_file                      # quarantine / where-from (read via ._ file)

fsstat exfatimage.dd ; fls -r exfatimage.dd                # TSK: structure + files (incl. deleted)
```

---

## What It Is and Where You See It

| Trait | exFAT |
|---|---|
| Origin | Microsoft, 2006 (successor to FAT32) |
| macOS support | Since 10.6.5 (Snow Leopard) |
| Max file/volume | Effectively unlimited for field use (no 4 GB cap) |
| Journaling | **None** |
| Permissions / ownership | **None** |
| Encryption | **None** (native) |

🔴 Where it shows up in cases: **USB flash drives**, **SD/CF cards** (cameras, drones, dashcams), large **external HDDs/SSDs** shared between Mac and Windows. Classic **data-exfiltration / data-transfer** medium — and cross-platform, so the same stick may have touched multiple OSes.

---

## On-Disk Structure

Simpler than HFS+/APFS — no B-trees, no journal.

| Region | Role |
|---|---|
| **Main + Backup Boot Region** | Boot sector, parameters (cluster size, FAT offset), checksum + a backup copy |
| **FAT (File Allocation Table)** | Cluster chains for fragmented files |
| 🔴 **Allocation Bitmap** | Tracks used/free clusters (allocation analysis) |
| **Up-case Table** | Case-insensitive name comparison data |
| **Root Directory + Cluster Heap** | Directory entries (file name, times, size, first cluster) and file data |

> Contiguous files can skip the FAT (a "no-FAT-chain" flag), which **helps carving**. Directory entries that are deleted are simply marked unused — names/metadata often remain.

---

## Timestamps

exFAT stores **Create, Modify, and Access** times — historically in **local time**, but the spec added explicit **UTC-offset** bytes per timestamp.

| Timestamp | Resolution |
|---|---|
| **Create** | 2-second + a 10 ms fraction field → ~**10 ms** |
| **Modify** | 2-second + a 10 ms fraction field → ~**10 ms** |
| **Access** | **2-second** (no fraction) |

🔴 Forensic gotchas:
- Coarse **2-second** granularity (10 ms at best) → don't expect APFS-style precision; round-looking times are normal here, **not** automatically timestomping.
- **Time-zone**: older FAT-lineage tools assume local time; exFAT's UTC-offset field may or may not be honored by the tool/OS that wrote it → **verify the offset**, and beware files written by Windows vs macOS showing different effective times.
- Because there's no ctime/inode-change concept, you have fewer cross-checks than on HFS+/APFS — corroborate with the **`._` AppleDouble** times and any embedded metadata.

```bash
stat -f 'B=%SB m=%Sm c=%Sc a=%Sa %N' /Volumes/USB/file     # macOS view (maps exFAT times)

istat exfatimage.dd <inode>                                 # TSK: directory-entry times
```

---

## No Permissions so macOS Uses AppleDouble

exFAT can't hold POSIX perms or xattrs, so macOS splits each file into two on disk:

| On-disk file | Holds |
|---|---|
| `filename` | The actual data fork |
| 🔴 `._filename` | **AppleDouble** — resource fork + **all extended attributes** (incl. `com.apple.quarantine`, `kMDItemWhereFroms`, Finder info) |

```bash
# macOS merges them transparently — xattr on the real name reads from ._:
xattr -l /Volumes/USB/report.pdf

# The companion file itself:
ls -la /Volumes/USB/._report.pdf

# Parse a ._ AppleDouble offline (it's a binary container; strings often reveals the source URL)
xxd /Volumes/USB/._report.pdf | head

strings /Volumes/USB/._report.pdf | grep -i 'http\|quarantine'
```

🔴 **Why this matters:** when a file is dragged from a Mac to an exFAT stick, its `._` file can carry the **quarantine record and original download URL**. On an exfil drive, the `._` companions can tell you *where the data originally came from* and that a **Mac** wrote it — even after the main files are gone (orphan `._` files persist).

---

## Mac Artifacts Left on exFAT Media

A Mac that mounts an exFAT volume scatters tell-tale files:

| Artifact | Reveals |
|---|---|
| 🔴 `._*` (AppleDouble) | Per-file xattrs/quarantine/resource forks |
| `.DS_Store` | Folder view state — **names of files that were in a folder** (even if deleted) |
| `.Spotlight-V100/` | Spotlight index attempt |
| `.Trashes/` | Items deleted to Trash **on the volume** (per-UID subfolders) |
| `.fseventsd/` | 🔴 **FSEvents** change log — history of file create/modify/delete on the volume |
| `.TemporaryItems/`, `.apDisk` | Temp/Finder bookkeeping |

🔴 `.fseventsd` and `.DS_Store` are gold: they can reconstruct **what files existed / were copied / were deleted** on the stick even after the data is removed.

```bash
ls -laO /Volumes/USB                                       # show hidden Mac artifacts + flags

find /Volumes/USB -maxdepth 2 -name '.DS_Store' -o -name '.fseventsd' -o -name '.Trashes'
```

---

## Deleted File Recovery

No journaling + simple FAT structures = **deleted data is often recoverable**:
- Deleted directory entries are flagged unused but **name/size/first-cluster usually remain**.
- Contiguous (no-FAT-chain) files carve cleanly.
- Orphan `._` files persist after their data file is deleted — recovering metadata of gone files.

```bash
fls -rd exfatimage.dd                                      # list deleted entries

icat exfatimage.dd <inode> > recovered.bin                 # recover by inode

# carve unallocated for known signatures
blkls exfatimage.dd > unalloc.bin                          # then run photorec/scalpel
```

---

## Analysis with The Sleuth Kit

TSK supports exFAT well.

```bash
mmls exfatimage.dd                                         # partition layout / offset

fsstat -o <offset> exfatimage.dd                          # boot region, cluster size, FAT info

fls -r -o <offset> exfatimage.dd                          # all files (incl. deleted)

istat -o <offset> exfatimage.dd <inode>                   # directory-entry metadata + times

fls -m / -o <offset> exfatimage.dd > body.txt             # bodyfile

mactime -b body.txt -d > timeline.csv                     # MACB timeline
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| exFAT removable drive present in a case | Cross-platform **data transfer / exfil** medium |
| Many `._*` AppleDouble files | A **Mac** wrote to the drive (with metadata) |
| `._` companion holding **quarantine / where-from** | Original **download source** of exfiltrated files |
| Orphan `._` files with no data file | Files **deleted** but metadata remains |
| `.fseventsd` / `.DS_Store` listing files not present | Reconstruct copied/deleted file history |
| `.Trashes` with user content | Items deleted on the volume — recoverable |
| Timestamps inconsistent between Mac view and Windows view | Local-time vs UTC-offset handling (verify offset) |
| Large recently-written files near an incident time | Staged exfil |

---

## Resources

- Microsoft exFAT specification: https://learn.microsoft.com/windows/win32/fileio/exfat-specification
- The Sleuth Kit: https://www.sleuthkit.org/
