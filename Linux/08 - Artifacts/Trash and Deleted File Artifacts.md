# Trash and Deleted File Artifacts

Deletion on Linux isn't as final as it looks, and this note covers the three places deleted things leave traces: the desktop **Trash** (which records a file's original path and exact deletion time), files that are **unlinked but still held open** by a running process (fully recoverable from `/proc`), and **unallocated blocks** that may still hold content. The highest-value move here is recovering a self-deleting malware binary from `/proc/PID/exe` while its process still runs — a technique that works even when the file is gone from every directory.

> 🔴 Malware routinely deletes its own binary right after launching, to defeat disk forensics. But while the process is alive, `/proc/PID/exe` still points at (and can copy back) the executable, and `lsof +L1` lists every deleted-but-open file. Grab these on the live host *before* the process exits — they're gone the moment it does.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Desktop Trash](#desktop-trash)
- [Deleted but Still Open](#deleted-but-still-open)
- [Fileless and memfd Execution](#fileless-and-memfd-execution)
- [Thumbnail and Cache Remnants](#thumbnail-and-cache-remnants)
- [Editor Swap and Backup Files](#editor-swap-and-backup-files)
- [Filesystem-Level Recovery](#filesystem-level-recovery)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Trash metadata: original path + deletion time
cat /home/*/.local/share/Trash/info/*.trashinfo 2>/dev/null

# Trashed file contents
ls -alh /home/*/.local/share/Trash/files/ 2>/dev/null

# Deleted files still held open by a process (recoverable now)
lsof +L1 2>/dev/null

# Deleted-but-running binaries
ls -l /proc/*/exe 2>/dev/null | grep deleted
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Recover a self-deleted running binary? | `cp /proc/<PID>/exe /evidence/bin` (while process lives) |
| Fileless execution (no disk path)? | `ls -l /proc/*/exe \| grep -E 'memfd:\|/dev/shm'` |
| Deleted file still held open? | `lsof +L1`; `find /proc/*/fd -lname '*(deleted)*'` |
| When/what was deleted (desktop)? | `cat ~/.local/share/Trash/info/*.trashinfo` (Path + DeletionDate) |
| Deletion event even when bytes are gone? | `.trashinfo` with no matching file in `files/` |
| Deleted content lingering elsewhere? | thumbnail cache, `recently-used.xbel`, `.swp`/`~`/`.bak` |
| Exfil via removable media? | `/media/*/.Trash-*`, `/mnt/*/.Trash-*` |
| Raw filesystem recovery? | ext4 undelete / XFS carve / Btrfs snapshot (FS notes) |

## Desktop Trash

The XDG Trash spec (used by GNOME/KDE) stores two parts per deleted item: the file itself and a `.trashinfo` metadata sidecar. That sidecar is the valuable piece — it records the original location and the deletion timestamp, giving you a clean timeline anchor even if the file itself was later purged.

| Path | Content |
|------|---------|
| `~/.local/share/Trash/files/` | The actual trashed files |
| `~/.local/share/Trash/info/*.trashinfo` | 🔴 Original path + deletion date/time |
| `~/.local/share/Trash/expunged/` | Partially-removed items |
| `/<mount>/.Trash-<uid>/` | Trash on other/removable mounts |
| `/root/.local/share/Trash/` | Root's trash |

```bash
# Read the metadata (INI-style: Path= and DeletionDate=)
cat /home/user/.local/share/Trash/info/report.pdf.trashinfo
# [Trash Info]
# Path=/home/user/Documents/report.pdf
# DeletionDate=2026-04-27T13:45:02

# List trashed files with timestamps
ls -alht /home/*/.local/share/Trash/files/ 2>/dev/null

# Trash on removable/other mounts
ls -la /media/*/.Trash-*/ /mnt/*/.Trash-*/ 2>/dev/null
```

🔴 `.trashinfo` gives you "user deleted *this file* from *this path* at *this time*" — a precise event for your timeline that survives even if the file's bytes were later removed. Trash on a *removable* mount (`/media/*/.Trash-*`) is also worth noting, as it points to external media used for staging or exfil.

## Deleted but Still Open

A file unlinked from disk but still held open by a running process is fully recoverable from `/proc` — one of the most useful live-forensics moves on Linux.

```bash
# All processes holding deleted files open
lsof +L1

# Deleted files a process still maps
ls -l /proc/<PID>/fd/ | grep deleted

# Recover the content directly from the file descriptor
cp /proc/<PID>/fd/<N> /tmp/recovered_file

# Deleted-but-running executable (malware that removed itself)
ls -l /proc/<PID>/exe        # shows "-> /path (deleted)"

cp /proc/<PID>/exe /tmp/recovered_binary
```

🔴 This is the counter to self-deleting malware: the kernel keeps the inode alive as long as a process holds the file open, so `/proc/PID/exe` (for the executable) and `/proc/PID/fd/N` (for any open deleted file) still yield the real bytes. Recover them before the process exits, because the kernel frees the inode the instant the last handle closes.

Deleted **mapped libraries** (an `LD_PRELOAD` `.so` unlinked after loading) show the same way:

```bash
# Processes with a deleted library still mapped in memory
grep -l '(deleted)' /proc/*/maps 2>/dev/null

# Recover the mapped file from map_files (needs root)
ls -la /proc/<PID>/map_files/ 2>/dev/null | grep deleted
```

## Fileless and memfd Execution

🔴 A step beyond "deleted-but-open": a **fileless** payload never touched the disk at all. `memfd_create` gives an anonymous in-memory file that's executed directly, so `/proc/PID/exe` reads `memfd:… (deleted)` — `/proc` is the **only** copy in existence.

```bash
# Fileless / in-memory execution — exe points at memfd or a RAM-backed path
ls -l /proc/*/exe 2>/dev/null | grep -E 'memfd:|/dev/shm|/tmp/|/run/'

# Recover the in-memory binary (only chance is while it runs)
cp /proc/<PID>/exe /evidence/memfd_<PID>.bin
```

A running process whose `exe` is `memfd:` or lives in `/dev/shm` is a top-tier red flag — legitimate software runs from a real path on disk. → Live Response for the deeper `/proc` treatment.

## Thumbnail and Cache Remnants

Even after a file is deleted, previews and cached copies of it can persist elsewhere on disk.

```bash
# Thumbnail cache can hold copies/previews of deleted images/docs
ls -la /home/*/.cache/thumbnails/{normal,large,fail}/ 2>/dev/null

# Recently-used file registry (references, even after deletion)
cat /home/*/.local/share/recently-used.xbel 2>/dev/null

# Application caches / temp copies
ls -la /home/*/.cache/ 2>/dev/null
```

The thumbnail cache in particular can preserve a viewable image of a document or photo that no longer exists on disk, and `recently-used.xbel` retains a reference (path + timestamps) to the deleted file.

## Editor Swap and Backup Files

Editors and tools leave shadow copies that frequently outlive the file an attacker deleted — a `.swp` can hold the entire content of a script that's since been removed.

```bash
# vim swap files (hold full buffer content of edited/deleted files)
find /home /root /var/www /tmp -name '.*.sw[po]' -ls 2>/dev/null

# Editor backups + tilde/bak copies
find /home /root /var/www -name '*~' -o -name '*.bak' -o -name '*.orig' 2>/dev/null

# Recover text from a vim swap file
vim -r /path/.script.sh.swp    # or: strings on the .swp
```

🔴 A `.swp`/`~`/`.bak` alongside where a deleted attacker script used to live often *is* the script — check these before concluding the content is gone.

## Filesystem-Level Recovery

Recovery from the raw filesystem depends heavily on which one it is — see the File Systems notes for the details:

- **ext4** — `debugfs lsdel`, `extundelete` (deleted inodes often survive).
- **XFS** — no practical undelete; carve unallocated space instead.
- **Btrfs** — check snapshots first; they may hold a pre-deletion copy.

```bash
# Signature-based carving, filesystem-independent (work on an image copy)
photorec disk.img

# Grep unallocated space for a known string (via Sleuth Kit)
blkls disk.img | strings | grep -i "secret"
```

## Deep Threat Hunts

Recover what was "deleted" — live first, then disk. *(seasoned-DFIR)*

```bash
# 1. Bulk-recover EVERY self-deleted running binary WITH process context (do this first)
for e in /proc/[0-9]*/exe; do
  ls -l "$e" 2>/dev/null | grep -q '(deleted)' || continue
  pid=$(echo "$e" | cut -d/ -f3); echo "== PID $pid =="
  ps -p "$pid" -o user,pid,ppid,cmd --no-headers
  cp "$e" "/evidence/recovered_$pid.bin" 2>/dev/null
done

# 2. Fileless / memfd execution (never had a disk path)
ls -l /proc/*/exe 2>/dev/null | grep -E 'memfd:|/dev/shm|/tmp/'

# 3. Every deleted file still held open (fd or mapping)
lsof +L1 2>/dev/null

find /proc/*/fd -lname '*(deleted)*' 2>/dev/null

grep -l '(deleted)' /proc/*/maps 2>/dev/null

# 4. All Trash: home + root + every mount root + removable
cat /home/*/.local/share/Trash/info/*.trashinfo /root/.local/share/Trash/info/*.trashinfo 2>/dev/null

ls -la /*/.Trash-* /media/*/.Trash-* /mnt/*/.Trash-* 2>/dev/null

# 5. Expunged: metadata present but bytes gone (deletion EVENT survives)
comm -23 <(ls ~/.local/share/Trash/info 2>/dev/null | sed 's/\.trashinfo$//' | sort) \
         <(ls ~/.local/share/Trash/files 2>/dev/null | sort)

# 6. Editor swap / backup remnants of deleted files
find /home /root /var/www -name '.*.sw[po]' -o -name '*~' -o -name '*.bak' 2>/dev/null
```

**Hunt ideas:**

- **The #1 loop is the single most valuable live move** — bulk-recover every self-deleted running binary *with its `ps` context* before the process exits.
- **`memfd:`/`/dev/shm` exe = fileless** — it never touched disk, so `/proc` is the *only* copy that exists anywhere.
- **A `.trashinfo` with no matching file** in `files/` means the bytes were purged but the deletion *event* (path + time) survives — a free timeline anchor.
- **Editor `.swp`/`~`/`.bak` files** often hold the full content of a deleted attacker script.
- **Trash on removable media** points to physical exfil/staging.

## Getting Max Value

- **Live-first, always** — `/proc/PID/exe`, `/proc/PID/fd`, and memfd recovery vanish the instant the process exits or the box reboots. Grab them before anything else.
- **Recover *with* context** (`ps` user/ppid/cmd) so the recovered binary is attributable, not an orphan blob.
- **`.trashinfo` is a precise deletion event** (path + local time — normalize it) even when the file's bytes are gone.
- **Then go to disk** — ext4 undelete, XFS carving, Btrfs snapshots (File Systems notes) for what `/proc` can't give you.
- **Sweep the shadow copies** — thumbnail cache, `recently-used.xbel`, editor swap/backup files all outlive the original.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Deeper `/proc` recovery of a deleted-but-running binary | **Live Response** (10) |
| Filesystem-level undelete / carve / snapshot | **ext4**, **XFS**, **Btrfs**, **The Sleuth Kit** |
| Triage the recovered binary | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| Exactly when the deletion happened | **Timelining** (13), `.trashinfo` timestamp |
| Secure-wipe / anti-forensics context | **Anti-Forensics and Evidence Destruction** (13b) |
| The fileless-execution technique in depth | **Live Response** (10), **ELF and Malware Triage** (11b) |

## Scenarios

- **Self-deleting malware:** the binary is gone from disk but `/proc/PID/exe` recovers it while the process runs.
- **Fileless payload:** a `memfd:` exe that never touched disk — `/proc` is the only copy.
- **Deletion-event proof:** a `.trashinfo` gives "user deleted *this* from *here* at *this time*" even after the bytes are purged.
- **Swap-file remnant:** a vim `.swp` holds the full text of a since-deleted attacker script.
- **USB exfil:** Trash on a removable mount points to external media used for staging.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `.trashinfo` for sensitive/tool files near incident time | User/attacker deleted evidence |
| `lsof +L1` shows deleted files held by odd processes | Recoverable payload/log |
| `/proc/PID/exe` deleted for a running process | Self-deleting malware (recover it now) |
| Thumbnails of documents no longer on disk | Deleted content still previewable |
| Trash on a removable mount | Exfil/staging via external media |
| `/proc/PID/exe` = `memfd:`/`/dev/shm` | Fileless execution — /proc is the only copy |
| Deleted `.so` still mapped (`/proc/*/maps`) | LD_PRELOAD library unlinked after load |
| `.trashinfo` with no matching file in `files/` | Bytes purged, deletion event survives |
| `.swp`/`~`/`.bak` where a deleted script lived | Full content of the removed file |

## Resources

- FreeDesktop Trash specification — https://specifications.freedesktop.org/trash-spec/
- `lsof(8)`, `proc(5)`, `memfd_create(2)` man pages
- MITRE ATT&CK: T1070.004 (File Deletion), T1620 (Reflective/Fileless Loading), T1564 (Hide Artifacts), T1027.011 (Fileless Storage)
