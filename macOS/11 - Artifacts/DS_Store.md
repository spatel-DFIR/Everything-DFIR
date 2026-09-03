# .DS_Store

`.DS_Store` ("**D**esktop **S**ervices **Store**") is a hidden file Finder drops into **every folder a user browses in the GUI**. It stores per-folder **Finder view preferences** — icon positions, window size/position, view style, sort order, background. For DFIR the *content* matters less than the *implication*: **its presence means that folder was opened in Finder**, and its records can reveal the **names of items that were in the folder** — even ones since deleted.

> 🔴 Think of it as the macOS cousin of Windows **ShellBags** (folder-browsing history) + **Desktop.ini** (folder view customization). A `.DS_Store` in a folder of interest = a user **viewed that folder in the Finder GUI** (knowledge/intent). One on a USB stick or network share = a **Mac browsed that media**. It also ties directly into Trash analysis (next lesson).

## Contents
- [Quick Triage](#quick-triage)
- [What It Is](#what-it-is)
- [Why It Matters for DFIR](#why-it-matters-for-dfir)
- [Where You Find Them](#where-you-find-them)
- [File Format](#file-format)
- [Key Record Types](#key-record-types)
- [Timestamps and the Trash Connection](#timestamps-and-the-trash-connection)
- [Finding and Parsing](#finding-and-parsing)
- [Anti-Forensics and Caveats](#anti-forensics-and-caveats)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# .DS_Store is hidden — find them everywhere (incl. external/network media)
find / -name ".DS_Store" 2>/dev/null

find /Volumes -name ".DS_Store" 2>/dev/null        # a Mac browsed this media

# Quick peek at item names recorded inside (binary file — don't cat it)
strings ~/Desktop/.DS_Store

# Confirm format (magic 'Bud1')
xxd ~/Desktop/.DS_Store | head

# Full parse to CSV with a dedicated tool (recursive)
python3 DSStoreParser.py -s /path/to/mount -o /path/to/output
```

---

## What It Is

- Created and maintained by the **Finder** (Desktop Services); **not** created by Terminal/`cd`/`ls` — it specifically tracks **GUI browsing**.
- One `.DS_Store` per folder, stored **inside** that folder, hidden (leading dot).
- Holds **view state per item**: icon X/Y positions, window bounds, list/icon/column/cover-flow view, sort order, background color/image, Spotlight comments.
- Records are keyed by **filename**, so a `.DS_Store` effectively lists items Finder tracked in that directory.

---

## Why It Matters for DFIR

| Question it helps answer | How |
|---|---|
| 🔴 Was this folder **opened in Finder** (GUI)? | Presence of `.DS_Store` = yes (a user browsed it) |
| 🔴 What **files were in** this folder? | Item-name records — can include files now **deleted/moved** |
| Did a **Mac** touch this USB / network share? | `.DS_Store` (+ `._*`, `.Trashes`) present on the volume |
| Roughly **when** was it last browsed/customized? | `.DS_Store` mtime (supporting, not exact) |
| What was **trashed**? | `.DS_Store` inside `.Trash` (see Trash connection) |

> 🔴 The strongest value is **user knowledge/intent**: a `.DS_Store` in a sensitive or staging folder shows someone navigated there in the GUI — and it may name files that no longer exist.

---

## Where You Find Them

| Location | Meaning |
|---|---|
| `~/Desktop/.DS_Store`, `~/Documents/.DS_Store`, any user folder | Folders the user browsed |
| `~/.Trash/.DS_Store` | 🔴 Trash view state — ties to deleted items (Trash lesson) |
| `/Volumes/<external>/.DS_Store` | 🔴 A Mac browsed this **USB / external** drive |
| `/Volumes/<share>/.DS_Store` (SMB/AFP) | A Mac browsed this **network share** |
| Inside ZIPs / extracted archives | Mac created them before zipping (provenance) |

> They're everywhere a Mac user has clicked around — which is exactly why they reconstruct browsing behavior so well.

---

## File Format

`.DS_Store` is a **binary** file using Apple's "**Buddy allocator**" container.

- Offset 0: `0x00000001` (alignment), then magic **`Bud1`** (`0x42756431`) at offset 4.
- A B-tree of **records**, each: **filename** (UTF-16BE) + a 4-char **structure ID** + a 4-char **data type** + the value.

Data types you'll see: `bool` (1B), `long`/`shor` (4B), `type` (4-char code), `comp`/`dutc` (8B int/date), `blob` (length-prefixed bytes, often an embedded plist), `ustr` (length-prefixed UTF-16BE string).

> Don't `cat` it. `strings` gives a fast read of item names + record codes; a parser decodes the structured values.

---

## Key Record Types

The 4-char structure IDs worth recognizing:

| ID | Meaning / DFIR value |
|---|---|
| 🔴 `Iloc` | **Icon location** (X/Y) of an item — item was present & positioned in this folder |
| `fwi0` | Finder **window info**: rect (top/left/bottom/right) + view code |
| `vstl` | **View style** (type): `icnv`=icon, `Nlsv`=list, `clmv`=column, `Flwv`=cover flow/gallery |
| `bwsp` | Browser **window settings** (blob/plist): bounds, sidebar width, toolbar/status bar (10.7+) |
| `icvp` / `lsvp` / `lsvP` | Icon-view / list-view property plists (sort, icon size, columns shown) |
| `fwsw` / `fwvh` | Finder window sidebar width / vertical height |
| `dscl` | List-view folder **expanded?** (bool) — user drilled into a subfolder |
| `BKGD` / `pict` | Folder **background** color / image |
| 🔴 `cmmt` | **Spotlight comment** text on an item |
| `modD` / `moDD` | Modification date record |
| `phyS` / `logS` | Physical / logical size |

> 🔴 The forensically richest are the **per-item name keys** themselves (what was in the folder) and `Iloc`/`cmmt`. View geometry (`fwi0`/`vstl`) is mostly supporting detail.

---

## Timestamps and the Trash Connection

- The `.DS_Store` **file mtime** approximates when Finder last wrote view changes for that folder — a rough "last interacted in Finder" marker. Corroborate with Spotlight `kMDItemLastUsedDate`, Unified Logs, and FSEvents (it's not a precise "viewed at" stamp).
- 🔴 **Trash:** Finder tracks items moved to the Trash; the `.DS_Store` in `~/.Trash` (and per-volume `.Trashes/<uid>/`) reflects that view state and item names — a lead-in to full **Trash** analysis (`.DS_Store` + the trashed files + their original-location metadata).

---

## Finding and Parsing

```bash
# Locate (hidden) — whole system, a user, or removable media
find / -name ".DS_Store" 2>/dev/null

find ~ -name ".DS_Store" 2>/dev/null

find /Volumes -name ".DS_Store" 2>/dev/null

# Quick triage without a parser
file ~/Desktop/.DS_Store          # 'Apple Desktop Services Store'

strings -a ~/Desktop/.DS_Store    # item names + 4-char record codes

xxd ~/Desktop/.DS_Store | head    # confirm 'Bud1' magic

# Full structured parse (recursive → CSV). Tools listed in Resources:
python3 DSStoreParser.py -s /evidence/mount -o /evidence/out

# On a disk image, extract .DS_Store files first with TSK, then parse
fls -r -p image.dd | grep -i "\.DS_Store"
```

> For dead-box work, pull every `.DS_Store` from the image and parse them in bulk — a folder-by-folder map of what the user browsed and what files were present.

---

## Anti-Forensics and Caveats

- 🔴 `.DS_Store` can be **deleted** by the user (or excluded). **Absence ≠ folder never opened** — it just means no record survived.
- Finder writing to network/USB can be **disabled**, so files there won't appear:
  ```bash
  defaults read com.apple.desktopservices DSDontWriteNetworkStores   # true = no .DS_Store on shares
  defaults read com.apple.desktopservices DSDontWriteUSBStores       # true = no .DS_Store on USB
  ```
  If these are `true`, expect missing `.DS_Store` on those volumes (and note it — could be policy or evasion).
- Item-name records reflect what Finder tracked, **not guaranteed every file** in the folder.
- Copying a folder can carry an old `.DS_Store` along — names inside may predate the current contents.

---

## Correlate With

| To answer | Pivot to |
|---|---|
| When was the folder actually browsed? | **FSEvents** (path activity) · **Unified Logs** |
| Were the listed files deleted? | **Trash** (ctime / Put-Back) · **FSEvents** `Removed` |
| Did a Mac write to this USB / share? | **exFAT** note (`._*`, `.Trashes`, `.fseventsd`) |
| Where did a listed file come from? | quarantine / `kMDItemWhereFroms` (**File and Directory Permissions**) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `.DS_Store` in a sensitive/staging folder | A user **browsed it in Finder** (knowledge/intent) |
| Item names in `.DS_Store` not present on disk | Files were **deleted/moved** — recover what was there |
| `.DS_Store` on a **USB/external** drive | A **Mac** browsed that media (cross-ref exFAT `._*`) |
| `.DS_Store` on a **network share** | A Mac navigated the share |
| `.DS_Store` in `~/.Trash` | View state of **trashed** items (Trash analysis) |
| `DSDontWriteNetworkStores`/`USBStores` = true | Finder set to **not** create `.DS_Store` there — policy or anti-forensics |
| `.DS_Store` with old/foreign item names | Folder copied from elsewhere — provenance |

---

## Resources

- .DS_Store-parser (used in the lesson): https://github.com/hanwenzhu/.DS_Store-parser
- DSStoreParser (Nicole Ibrahim): https://github.com/nicoleibrahim/DSStoreParser
- DSStoreParser — Python 3 fork (Mike Peterson / BeanBagKing): https://github.com/BeanBagKing/DSStoreParser
- DSStoreView: https://github.com/macmade/DSStoreView
