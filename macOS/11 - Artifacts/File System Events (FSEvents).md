# File System Events (FSEvents)

**FSEvents** is macOS's file-system change log — a per-volume record of **creations, deletions, renames, modifications, and metadata changes**. It's one of the **most valuable** macOS timeline artifacts because it captures activity the file system itself forgets: standard metadata only keeps the *last* timestamps, but FSEvents preserves a **history of changes**, including the **paths of files that were since deleted**.

> 🔴 If you come from Windows forensics, think **USN Journal**: FSEvents tells you **what changed and roughly when** across the whole volume — including external drives plugged into a Mac. The catch: records carry the **path + a bitmask of change types + an event ID**, but **no precise per-event timestamp** — timing is approximate (per log-file window / event-ID ordering). Combine it with timestamped artifacts.

## Contents
- [Quick Triage](#quick-triage)
- [What FSEvents Is](#what-fsevents-is)
- [Where It Lives](#where-it-lives)
- [What a Record Contains](#what-a-record-contains)
- [Event Flags](#event-flags)
- [The Timestamp Caveat](#the-timestamp-caveat)
- [Why It Matters for DFIR](#why-it-matters-for-dfir)
- [Parsing FSEvents](#parsing-fsevents)
- [Anti-Forensics and Caveats](#anti-forensics-and-caveats)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Modern macOS (Catalina+): boot-volume store is on the DATA volume
sudo ls -la /System/Volumes/Data/.fseventsd/

# Old macOS / non-boot & external volumes: at the volume root
sudo ls -la /.fseventsd/ /Volumes/USB/.fseventsd/ 2>/dev/null

# Preserve the whole store for offline parsing
sudo cp -R /System/Volumes/Data/.fseventsd /evidence/fseventsd_boot

# The logs are gzip — confirm, then parse with a tool (don't read raw)
file /System/Volumes/Data/.fseventsd/* | head

# Parse: FSEParser, or mac_apt's FSEVENTS plugin
python3 FSEParser.py -c /evidence/fseventsd_boot -o /evidence/fsevents.csv
```

---

## What FSEvents Is

- A kernel facility (`fseventsd`) that logs **changes to the file system** so apps (Spotlight, Time Machine, backup tools) can learn what changed without rescanning.
- **Per volume** — internal and **external** drives each get their own `.fseventsd/` store.
- Records the **full path** affected and a **bitmask of what happened** (create/remove/rename/modify/etc.), tagged with a monotonically increasing **event ID**.
- Persists historical activity → recover **paths of deleted files**, see mass changes, reconstruct a timeline.

---

## Where It Lives

🔴 **The path moved with the APFS System/Data split:**

| macOS | Boot-volume store |
|---|---|
| 🔴 **Modern** (Catalina 10.15+, sealed read-only System volume) | **`/System/Volumes/Data/.fseventsd/`** — the user-data FSEvents live on the **Data** volume; `/.fseventsd` does **not** exist on `/` |
| **Old** (pre-Catalina, HFS+ / single-volume) | `/.fseventsd/` at the volume root |
| **Any external / removable volume** (both eras) | `/Volumes/<vol>/.fseventsd/` at that volume's root |

Inside the `.fseventsd/` directory:

| File | Holds |
|---|---|
| `<hex>` | **gzip-compressed** log files, named by the last **event ID** they contain |
| `fseventsd-uuid` | The volume's FSEvents **UUID** (changes on reformat/restore — flags volume identity changes) |
| `no_log` | Marker that logging was off for a period |

> On a **dead-box image** the boot store is on the Data volume — look under `…/System/Volumes/Data/.fseventsd/` (or the Data volume directly). Don't assume `/.fseventsd` on modern systems.

---

## What a Record Contains

Each event record holds:

| Field | Meaning |
|---|---|
| 🔴 **Path** | Full path of the file/folder affected |
| 🔴 **Event flags** | Bitmask of change types (create/remove/rename/modify/…) |
| **Event ID** | Monotonic counter — establishes **order**, not wall-clock time |
| (derived) **Node/extra** | Some versions include node ID / file type bits |

> The log files themselves are named by event ID (hex), so you order activity by event ID; the **only timing anchor** is which log file (date range) a record falls in.

---

## Event Flags

Common `FSE_`/flag types you'll see decoded:

| Flag | Meaning |
|---|---|
| 🔴 `Created` | Item created |
| 🔴 `Removed` | Item deleted |
| 🔴 `Renamed` | Renamed/moved (incl. to Trash) |
| `Modified` | Content modified |
| `InodeMetaMod` | Metadata/inode change (perms, ctime) |
| `XattrModified` | Extended attribute changed (quarantine etc.) |
| `FinderInfoMod` | Finder info changed |
| `Cloned` | APFS clone created |
| `HardLink` / `SymbolicLink` | Link created |
| `IsFile` / `IsDir` / `IsSymlink` | Type of the affected node |
| `Mount` / `Unmount` | Volume mounted/unmounted |

> 🔴 Flags are **coalesced**: a single record's flags are the **union** of everything that happened to that path within the log window — so "Created + Removed" on one path means it was created *and* deleted in that span, but not the exact sub-order.

---

## The Timestamp Caveat

🔴 FSEvents records have **no precise timestamp**. You get:
- **Event ID ordering** (what happened before what), and
- **Approximate time** from the **date range of the log file** the record sits in (parsers often present a start/end window).

So treat FSEvents as **"what changed, in this order, roughly during this window."** For exact times, correlate the path with **filesystem MACB**, **Unified Logs**, **quarantine**, **knowledgeC**, etc.

---

## Why It Matters for DFIR

| Use | How FSEvents helps |
|---|---|
| 🔴 Recover **deleted file paths** | Paths of removed files persist in the log after the files are gone |
| 🔴 **Timeline** of activity | Order of create/modify/rename/delete across the volume |
| Malware staging/cleanup | See files dropped in `/tmp`, `~/Library`, then removed |
| **Exfil to removable media** | External drive's `/.fseventsd/` shows files written/deleted on it |
| Bridge metadata gaps | History the file system's last-timestamps can't show |
| Anti-forensics detection | Mass deletes, log wiping, volume re-format (UUID change) |

---

## Parsing FSEvents

```bash
# Preserve the store (boot = Data volume on modern macOS) + every mounted volume
sudo cp -R /System/Volumes/Data/.fseventsd /evidence/fseventsd_boot

sudo cp -R /Volumes/USB/.fseventsd /evidence/fseventsd_usb

# Parse to CSV (G-C Partners / Nicole Ibrahim FSEParser)
python3 FSEParser.py -c /evidence/fseventsd_boot -o /evidence/fsevents_boot.csv

# 🔴 mac_apt parses FSEvents directly — FSEVENTS plugin (bulk, against an image)
python3 mac_apt.py -o /evidence/out -x DMG /evidence/image.dmg FSEVENTS

# On a disk image, extract the store first with TSK, then parse
fls -r -p image.dd | grep -i "\.fseventsd/"
```

| Tool | Notes |
|---|---|
| 🔴 **mac_apt** (`FSEVENTS` plugin) | Parses FSEvents from a disk image into the `mac_apt.db` (cross-ref the mac_apt note) |
| **FSEParser** (G-C Partners / Nicole Ibrahim) | Standalone FSEvents → CSV |
| Commercial (AXIOM, Cellebrite) | Built-in FSEvents parsing |

> The individual `<hex>` files are **gzip** but contain a **binary record format** — a raw `zcat` won't be human-readable; use a dedicated parser. Always grab **every** volume's store (boot **Data volume** + externals).

---

## Anti-Forensics and Caveats

- Records can be **purged/rotated**; very old activity ages out. A `no_log` marker or missing logs = a coverage gap.
- A changed **`fseventsd-uuid`** means the volume was **reformatted/restored** — earlier history is gone.
- 🔴 An attacker can delete `/.fseventsd/` contents — but that itself is a tell (empty/short store on an old, active system).
- **No precise timestamps** (see caveat) — never present an FSEvents time as exact.
- Paths may be **coalesced**; rapid create/delete can collapse into one record.

---

## Correlate With

| To answer | Pivot to |
|---|---|
| Exact time of an event (FSEvents has none) | filesystem **MACB** · **Unified Logs** · **knowledgeC / Biome** |
| A `Removed` path — recover it | **Trash** (ctime / Put-Back) · unallocated carving |
| A `Created` download — provenance | quarantine / `kMDItemWhereFroms` (**File and Directory Permissions**) |
| External-drive activity | **exFAT** artifacts (`._*`, `.Trashes`) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Paths of **deleted** malware/tools in FSEvents | Files existed and were removed — recover names/locations |
| Burst of `Removed` events | Mass deletion / cleanup (anti-forensics) |
| Activity under `/tmp`, `~/Library/…`, `/Users/Shared` then removed | Malware staging then cleanup |
| External volume `/.fseventsd/` full of writes | Data **exfil** to removable media |
| `/.fseventsd/` empty/short on an old, busy system | FSEvents wiped (anti-forensics) |
| `no_log` marker / changed `fseventsd-uuid` | Logging was off / volume reformatted — history gap |
| FSEvents path activity contradicting file MACB times | Timestomping (FSEvents recorded the real change) |

---

## Resources

- FSEvents: How They Work and Why They Matter for Mac Analysis (Hexordia): https://www.hexordia.com/blog/mac-forensics-analysis
- mac_apt (FSEVENTS plugin): https://github.com/ydkhatri/mac_apt
- FSEParser (G-C Partners): https://github.com/dlcowen/FSEventsParser
