# Trash

The macOS **Trash** is where Finder-deleted files wait before permanent removal. It's deceptively simple but rich: trashed files keep their **original content and metadata**, their **`ctime` reveals when they were deleted**, and Finder's **"Put Back"** records expose each file's **original path**. There's a per-user Trash on the boot volume and a separate Trash per external volume.

> 🔴 Three high-value facts: (1) a file's **`ctime`** updates when it's moved to the Trash → `ctime` ≈ **deletion time**; (2) **"Put Back"** info in the Trash's `.DS_Store` (`ptbL`/`ptbN`) gives the **original location**; (3) trashed files still hold their original **xattrs** (quarantine/where-from) — so you can recover *what*, *from where*, and *when deleted*.

## Contents
- [Quick Triage](#quick-triage)
- [Where Trash Lives](#where-trash-lives)
- [ctime as the Deletion Timeline](#ctime-as-the-deletion-timeline)
- [Put Back and Original Paths](#put-back-and-original-paths)
- [What Else Survives in Trash](#what-else-survives-in-trash)
- [External and Network Volumes](#external-and-network-volumes)
- [Finding and Examining](#finding-and-examining)
- [Anti-Forensics and Caveats](#anti-forensics-and-caveats)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# User Trash (boot volume) — contents + xattrs
ls -la@ ~/.Trash

# Deletion time = ctime of each trashed item
stat -f 'Deleted(ctime)=%Sc  Mod=%Sm  Birth=%SB  %N' ~/.Trash/*

# Original paths via Put Back records in the Trash .DS_Store
strings -a ~/.Trash/.DS_Store | grep -iA1 ptb

# External / removable volume trashes
find /Volumes -maxdepth 3 -name ".Trashes" 2>/dev/null

ls -la "/Volumes/USB/.Trashes/$(id -u)/"
```

---

## Where Trash Lives

| Location | Scope |
|---|---|
| 🔴 `~/.Trash/` | Per-**user** Trash on the boot/internal volume |
| 🔴 `/Volumes/<vol>/.Trashes/<UID>/` | Per-**volume** Trash on **external** drives (one subfolder per user UID, e.g. `501`) |
| `/Volumes/<share>/.Trashes/<UID>/` | Network share trash (when supported) |
| `~/.Trash/.DS_Store` | Holds **Put Back** original-path records (cross-ref .DS_Store) |

> There is **no** central recycle-bin database like Windows `$Recycle.Bin` `$I` files — macOS spreads it across `.Trash`/`.Trashes` plus the `.DS_Store` Put-Back records and the file system's own timestamps.

---

## ctime as the Deletion Timeline

Moving a file to the Trash is a **rename/move** — it changes the inode's metadata, so the file's **`ctime` (change/attribute time) is set to the moment of deletion**, while **`mtime` (content)** and **birth time** stay original.

```bash
stat -f 'Birth=%SB%nModify(mtime)=%Sm%nChange(ctime)=%Sc%nAccess=%Sa%n  %N' ~/.Trash/secret.docx
```

🔴 So for each trashed item:
- **`ctime`** ≈ **when it was deleted** (moved to Trash).
- **`mtime`/birth** ≈ when it was originally last edited/created.
- A cluster of items sharing a `ctime` = a **bulk deletion** at that moment (often anti-forensics).

> Corroborate with **FSEvents** (the move/delete event) and **Unified Logs**; `ctime` is reliable but can itself be tampered (see the File Systems timestomping notes).

---

## Put Back and Original Paths

Finder's **"Put Back"** restores a trashed item to where it came from — which means Finder **stored that original location**. It lives in the Trash folder's **`.DS_Store`**:

| Record | Holds |
|---|---|
| 🔴 `ptbL` | **Put-Back Location** — original folder (alias/bookmark blob) |
| `ptbN` | **Put-Back Name** — original file name |

```bash
# Pull Put-Back records (original paths) from the Trash .DS_Store
strings -a ~/.Trash/.DS_Store | grep -iE 'ptbL|ptbN|/Users/'

# Better: parse the .DS_Store structurally (see .DS_Store note for tools)
python3 DSStoreParser.py -s ~/.Trash -o trash_dsstore_out
```

🔴 This recovers **where a deleted file originally lived** — e.g. a document trashed from a sensitive project folder, or a tool deleted from `/tmp`. Combine with `ctime` (when) for a full deletion story.

---

## What Else Survives in Trash

A trashed file is **moved, not altered** — so it retains:

| Survives | DFIR value |
|---|---|
| 🔴 File **content** | Recover the actual data |
| Original **name** | Unless a name clash forced a rename (Finder appends a number) |
| 🔴 **Extended attributes** | `com.apple.quarantine`, `kMDItemWhereFroms` → where the file was **downloaded from** |
| Original **mtime/birth** | When it was created/edited |
| Resource forks / AppleDouble | On external/foreign FS, metadata sits in `._` companions |

```bash
ls -la@ ~/.Trash                                   # see xattrs on trashed items

xattr -p com.apple.metadata:kMDItemWhereFroms ~/.Trash/installer.dmg | xxd | head
```

---

## External and Network Volumes

When a file is trashed on an **external** volume, it goes to `/<volume>/.Trashes/<UID>/` — **not** the user's home Trash.

```bash
find /Volumes -maxdepth 3 -name ".Trashes" 2>/dev/null

ls -la "/Volumes/MyUSB/.Trashes/$(id -u)/"

# Deletion times on the external trash
stat -f 'ctime=%Sc  %N' "/Volumes/MyUSB/.Trashes/$(id -u)/"*
```

🔴 `.Trashes/<UID>/` on a USB/exfil drive shows **what a specific user deleted on that media** — and the `<UID>` ties it to an account. On non-native file systems (exFAT/FAT) the metadata rides in **AppleDouble `._`** files (cross-ref the exFAT note).

---

## Finding and Examining

```bash
# All trashes on the system + mounted volumes
ls -la ~/.Trash

sudo find / /Volumes -maxdepth 4 \( -name ".Trash" -o -name ".Trashes" \) 2>/dev/null

# Per-item deletion timeline (ctime) sorted
stat -f '%Sc  %N' ~/.Trash/* | sort

# Recover content (just copy it out — it's a normal file)
cp ~/.Trash/secret.docx /evidence/recovered/

# On a disk image, list/recover with TSK (Trash is a normal folder)
fls -r -p image.dd | grep -iE "\.Trash(es)?/"
```

> On a dead-box image the Trash is just folders — list, timeline (`ctime`), and extract normally; parse the Trash `.DS_Store` for Put-Back paths.

---

## Anti-Forensics and Caveats

- **Emptying the Trash** unlinks the files → then it's an **unallocated/FSEvents** problem (carve + FSEvents paths). Empty-Trash itself may show in FSEvents/Unified Logs.
- Legacy **"Secure Empty Trash"** overwrote data (removed in 10.11) — modern empties just unlink (often recoverable, esp. on HDD; SSD TRIM shortens the window).
- Deleting via **Terminal `rm`** bypasses the Trash entirely → **no** `.Trash` entry, no Put-Back. Absence of a Trash record ≠ file never existed.
- `ctime` can be tampered; corroborate deletion time with FSEvents/logs.
- Name collisions cause Finder to **rename** on trashing — the in-Trash name may differ from the original (`ptbN` has the true name).

---

## Correlate With

| To answer | Pivot to |
|---|---|
| Confirm the deletion time (ctime) | **FSEvents** `Removed`/`Renamed` for the path · **Unified Logs** |
| Original location of a deleted file | **.DS_Store** Put-Back (`ptbL`) · Spotlight recent items |
| Where the deleted file was downloaded from | quarantine / `kMDItemWhereFroms` (**File and Directory Permissions**) |
| Files gone after Empty Trash | **FSEvents** + unallocated carving (**File Systems**) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Sensitive files sitting in `~/.Trash` | Deleted but not purged — recover content + provenance |
| Many items sharing one `ctime` | **Bulk deletion** at that instant (often anti-forensics) |
| Put-Back (`ptbL`) pointing at a sensitive/project folder | Where the deleted file originated |
| Trashed file with `quarantine`/`where-from` xattr | Downloaded item that was deleted — recover its source URL |
| `.Trashes/<UID>/` on a **USB/exfil drive** | A specific user deleted data on removable media |
| Trash empty but FSEvents shows recent deletes | Trash emptied / `rm` used — pivot to FSEvents + carving |
| In-Trash name differs from `ptbN` | Finder renamed on collision — use `ptbN` for the real name |

---

## Resources

- AppleSingle / AppleDouble — Python parsing library (Kaitai): https://formats.kaitai.io/apple_single_double/python.html
- AppleSingle / AppleDouble — Go parsing library (Kaitai): https://formats.kaitai.io/apple_single_double/go.html
