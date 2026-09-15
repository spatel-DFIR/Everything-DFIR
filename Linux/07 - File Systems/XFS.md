# XFS

XFS is the default on RHEL/CentOS/Rocky/Alma/Fedora 7+ — so it's what you'll meet on most enterprise Red Hat–family servers. It's a high-performance, extent-based, journaled filesystem, and the one forensic fact that dominates your strategy is that **it has no practical undelete**: on deletion XFS zeroes the inode's extent map and aggressively reuses the space, with no `debugfs lsdel`/`extundelete` equivalent that reliably recovers files. Plan your evidence approach around that from the start.

> 🔴 Don't promise file recovery on XFS. When the case hinges on deleted content, pivot early to other evidence — memory (`/proc`, RAM capture on the live host), the metadata journal, backups/snapshots, and signature-based **carving** of unallocated space, which ignores the (destroyed) filesystem metadata entirely.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Structure](#structure)
- [Timestamps](#timestamps)
- [Metadata and Inode Analysis](#metadata-and-inode-analysis)
- [Journal](#journal)
- [Deletion and Recovery Reality](#deletion-and-recovery-reality)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Geometry, block/inode counts, version
xfs_info /dev/sda1

# or on an unmounted device / image
sudo xfs_db -r -c "sb 0" -c "print" /dev/sda1

# Inode detail
sudo xfs_db -r -c "inode <inode>" -c "print" /dev/sda1

# All four timestamps of a file
stat --printf='%n born:%w mod:%y chg:%z acc:%x\n' /path/to/file
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Can I recover a deleted file? | Usually **no** native undelete — pivot to memory/carving/journal |
| Recover a deleted-but-running binary? | `ls -l /proc/*/exe \| grep deleted` (live — often the only copy) |
| Full filesystem timeline? | `fls -r -m / -o <off> img > bodyfile` (TSK supports XFS) → `mactime` |
| Did a now-gone file ever exist? | `xfs_logprint -t` (metadata journal: create/rename/delete) |
| Recover deleted bytes from unallocated? | `photorec`/`foremost`/`scalpel` (signature carving) |
| Is a file timestomped? | `xfs_db -c "inode <n>" -c "print core.crtime core.mtime core.ctime"` |
| Geometry / version? | `xfs_info`; `xfs_db -c "sb 0" -c print` |
| Inode ↔ name? | `ls -i` (name→inode); `xfs_db -c "ncheck <inode>"` |

## Structure

XFS divides the volume into **allocation groups (AGs)**, each managing its own inodes and free space with B+ trees, which is what gives it parallel-I/O performance. Inodes are allocated dynamically (not from a fixed table like ext), and files use extents. For forensics the relevant consequence is that once an inode is freed, its identity and extent map are quickly recycled — there's no lingering deleted-inode list to walk.

```bash
# Mounted filesystem geometry
xfs_info /mnt/point

# Low-level inspection (read-only) of an unmounted device/image
sudo xfs_db -r /dev/sda1

# Inside xfs_db:
#   sb 0 / print          -> superblock
#   agf <n> / agi <n>     -> allocation group free/inode headers
#   inode <n> / print     -> a specific inode
```

## Timestamps

XFS (v5) records atime, mtime, ctime, and a creation time (`crtime`). The timestomp logic is identical to ext4: `ctime` can't be set by `touch`, so a recent `ctime` under an old `mtime`/`atime` is suspicious, and the `relatime`/`noatime` caveat still applies to atime.

```bash
# statx birth time
stat --printf='birth: %w\n' file

# From xfs_db
sudo xfs_db -r -c "inode <inode>" -c "print core.crtime" /dev/sda1
```

## Metadata and Inode Analysis

```bash
# Path -> inode
ls -i /etc/passwd

# Inode core (times, size, extents, mode, links)
sudo xfs_db -r -c "inode <inode>" -c "print" /dev/sda1

# Directory contents by inode
sudo xfs_db -r -c "inode <dir_inode>" -c "print" /dev/sda1

# Metadata dump for offline analysis (metadata only, no file data by default)
sudo xfs_metadump /dev/sda1 /tmp/xfs.metadump
```

`xfs_metadump` is useful for preserving the metadata structure for offline analysis without copying file *contents* — handy for structural questions, but remember it deliberately omits file data.

## Journal

XFS journals **metadata only** — it's a source of recent metadata operations, not file content.

```bash
# Inspect the log (internal journal)
sudo xfs_logprint /dev/sda1

# Summarize recent transactions
sudo xfs_logprint -t /dev/sda1
```

The log can show recent create/rename/delete operations, which occasionally lets you establish that a file existed and was removed even though its contents are unrecoverable.

## Deletion and Recovery Reality

🔴 **XFS has no practical undelete.** The implications shape the whole investigation:

- Don't promise file recovery from XFS — redirect to **other evidence**: memory (capture RAM and `/proc` on the live host *before* imaging), the metadata journal (existence/timing, not content), backups/snapshots, and `wtmp`/logs for activity.
- **File carving** on the raw image recovers unallocated content by file signature, independent of the destroyed filesystem metadata — often your best shot at a deleted tool's bytes.
- Capture volatile state on the live host *before* imaging, because for XFS a running process's memory may be the only place a deleted attacker binary still exists.

```bash
# Signature-based carving from a raw image (metadata-independent)
photorec disk.img

scalpel -o carved_out disk.img
```

## Deep Threat Hunts

XFS gives no undelete — so hunt the paths that ignore its zeroed metadata. *(seasoned-DFIR)*

```bash
# 1. TSK supports XFS: full metadata timeline even without native undelete
fls -r -m / -o <offset> disk.img > bodyfile.txt

mactime -b bodyfile.txt -d 2026-04-23 > timeline.csv

# 2. Inode content by number (TSK, offset-aware) — pull what metadata still points to
istat -o <offset> disk.img <inode>

icat -o <offset> disk.img <inode> > /evidence/out.bin

# 3. Deleted-but-RUNNING binary from live memory — often the ONLY copy on XFS
ls -l /proc/*/exe 2>/dev/null | grep deleted

# 4. Metadata journal: prove a now-gone file existed / was deleted (timing, not content)
xfs_logprint -t /dev/sda1 2>/dev/null

# 5. Carve unallocated for the deleted payload's bytes
photorec disk.img

foremost -i disk.img -o /evidence/carved 2>/dev/null

# 6. Safe offline structural analysis: metadata image -> restore -> xfs_db
xfs_metadump -o /dev/sda1 /evidence/xfs.metadump

xfs_mdrestore /evidence/xfs.metadump /evidence/xfs_meta.img

# 7. Map an inode back to its path
xfs_db -r -c "ncheck <inode>" /dev/sda1 2>/dev/null
```

**Hunt ideas:**

- **On XFS, `/proc/PID/exe` of a running process is frequently the *only* surviving copy** of a deleted attacker binary — capture it live *before* imaging.
- **TSK understands XFS** — you still get a full `fls -m` timeline and `icat`-by-inode content even though native undelete doesn't exist.
- **The metadata journal proves existence + timing** — `xfs_logprint` can show a file was created then deleted, anchoring the timeline even when content is gone.
- **Carving is your content path** — `photorec`/`foremost`/`bulk_extractor` recover bytes by signature, ignoring the destroyed metadata.
- **XFS hosts are almost always RHEL-family** — verify system binaries with `rpm -Va` and check for LVM snapshots that may hold pre-deletion state.

## Getting Max Value

- **Re-plan early:** XFS = no undelete. Prioritize live RAM + `/proc` capture *before* imaging, because memory may be the only place a deleted binary survives.
- **Use TSK on the image** (`fls`/`istat`/`icat`) for the timeline and by-inode content; `xfs_logprint` for existence/timing.
- **Carve unallocated** for deleted bytes; `xfs_metadump` → `xfs_mdrestore` for safe offline `xfs_db` analysis.
- **Check RHEL-native backups** — LVM snapshots are common on Red Hat servers and may hold the pre-deletion state.
- **Verify system binaries with `rpm -Va`** — the fast integrity win on the RHEL family XFS lives on.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Recover a deleted-but-running binary | **Live Response** (10), **Memory Forensics** (11) |
| Timeline pipeline / bodyfile from the image | **The Sleuth Kit**, **Timelining** (13) |
| Verify RHEL-family system binaries | **Package Managers and Integrity** (08, `rpm -Va`) |
| Timestamp / timestomp interpretation | **File and Directory Permissions** (02) |
| Confirm it's XFS / find LVM snapshots | **Filesystem Triage and Identification** |
| Why the content is unrecoverable (wiping) | **Anti-Forensics and Evidence Destruction** (13b) |

## Scenarios

- **Deleted tool on an XFS host:** no undelete → recover from `/proc/PID/exe` live, or carve the image.
- **Existence proof:** `xfs_logprint` shows a create-then-delete of a file whose content is gone.
- **RHEL timeline:** a TSK `fls -m` bodyfile gives a full timeline despite XFS having no native undelete.
- **Timestomp:** `ctime > mtime` read from `xfs_db` core times.
- **Snapshot save:** an LVM snapshot holds the pre-deletion state the filesystem discarded.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `ctime` newer than `mtime`/`atime` | Timestomping |
| Case depends on deleted-file recovery | XFS won't deliver — re-plan evidence around memory/carving/backups |
| Recently modified system binaries/configs | Tampering (verify via package DB — `rpm -Va`) |
| Carved artifacts contradicting live filesystem state | Deleted attacker files |
| Deleted binary still mapped as `/proc/PID/exe` | The only surviving copy — capture it now |
| `xfs_logprint` shows create+delete of a missing file | File existed and was removed |

## Resources

- `xfs_info(8)`, `xfs_db(8)`, `xfs_logprint(8)`, `xfs_metadump(8)`, `xfs_mdrestore(8)` man pages — https://xfs.org
- The Sleuth Kit (XFS support) — https://sleuthkit.org
- PhotoRec / Scalpel / foremost carving tools
- MITRE ATT&CK: T1070.004 (File Deletion), T1070.006 (Timestomp), T1485 (Data Destruction)
