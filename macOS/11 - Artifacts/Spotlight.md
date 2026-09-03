# Spotlight

**Spotlight** indexes **metadata for nearly every file** on a volume into a per-volume store. For DFIR that metadata is gold: download **provenance** (`kMDItemWhereFroms`), **last-used** time + **use count**, content dates, tags — and the store can retain entries for files that have since been **deleted**. Query it live with `mdfind`/`mdls`, or parse the on-disk store offline.

> 🔴 `kMDItemWhereFroms` + `kMDItemDownloadedDate` corroborate where a file came from (even after the quarantine xattr is stripped), and `kMDItemLastUsedDate`/`kMDItemUseCount` prove a file was **opened** and how often. Every volume — including USB drives — has its own Spotlight store.

## Contents
- [Quick Triage](#quick-triage)
- [Where the Store Lives](#where-the-store-lives)
- [Querying Live](#querying-live)
- [Key kMDItem Attributes](#key-kmditem-attributes)
- [Parsing the Store Offline](#parsing-the-store-offline)
- [Index Control with mdutil](#index-control-with-mdutil)
- [Spotlight Exclusions and Store Config](#spotlight-exclusions-and-store-config)
- [Anti-Forensics](#anti-forensics)
- [Scenarios](#scenarios)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Index status per volume
mdutil -s /

# All metadata for a file (where-from, dates, use count, kind…)
mdls /path/to/file

# Targeted high-value attributes
mdls -name kMDItemWhereFroms -name kMDItemDownloadedDate -name kMDItemLastUsedDate -name kMDItemUseCount /path/to/file

# Search the index like Spotlight (live)
mdfind -onlyin ~/Downloads "keyword"
```

---

## Where the Store Lives

🔴 Like FSEvents, the boot store moved to the **Data volume** with the System/Data split:

| macOS | Boot-volume Spotlight store |
|---|---|
| 🔴 **Modern** (Catalina 10.15+) | `/System/Volumes/Data/.Spotlight-V100/Store-V2/<UUID>/` (`/.Spotlight-V100` does **not** exist on `/`) |
| **Old** (single-volume) | `/.Spotlight-V100/Store-V2/<UUID>/` |
| **External / removable** | `/Volumes/<vol>/.Spotlight-V100/` at that volume's root |
| App content index | `~/Library/Metadata/CoreSpotlight/` |

Inside `Store-V2/<UUID>/`: `store.db` / `.store.db` (the metadata database), plus journals.

---

## Querying Live

```bash
# Dump every attribute for a file
mdls /path/to/file

# Search by attribute
mdfind "kMDItemDisplayName == '*.dmg'"

mdfind -onlyin /Volumes/USB "secret"

# Files downloaded from a host (provenance pivot)
mdfind "kMDItemWhereFroms == '*evil.com*'"

# Recently used files
mdfind "kMDItemLastUsedDate >= \$time.today(-7)"
```

> `mdfind`/`mdls` only work on **indexed, mounted** volumes live. For a dead-box image, parse the store file directly (below).

---

## Key kMDItem Attributes

| Attribute | DFIR value |
|---|---|
| 🔴 `kMDItemWhereFroms` | **Download source URL(s)** (survives quarantine removal) |
| 🔴 `kMDItemDownloadedDate` | When it was downloaded |
| 🔴 `kMDItemLastUsedDate` | When the file was **last opened** |
| 🔴 `kMDItemUseCount` | How many times it was opened |
| `kMDItemContentCreationDate` / `…ModificationDate` | Content-level dates (can differ from FS MACB) |
| `kMDItemDisplayName` / `kMDItemFSName` | Name(s) |
| `kMDItemKind` / `kMDItemContentType` | File type |
| `kMDItemUserTags` | Finder tags |
| `kMDItemPhysicalSize` / `kMDItemFSSize` | Size |

---

## Parsing the Store Offline

```bash
# Locate the store (modern boot = Data volume; externals at root)
sudo ls -la /System/Volumes/Data/.Spotlight-V100/Store-V2/*/

# Parse with Yogesh Khatri's spotlight_parser
python3 spotlight_parser.py /path/to/store.db /path/to/output

# Or mac_apt's SPOTLIGHT plugin (against an image)
python3 mac_apt.py -o out -x DMG image.dmg SPOTLIGHT
```

🔴 The store can hold metadata for files **no longer on disk** — a way to learn that a (now-deleted) file existed, its name, where it came from, and when it was used.

---

## Index Control with mdutil

```bash
mdutil -s /                 # status (Indexing enabled?)

mdutil -s -a                # all volumes

sudo mdutil -i off /        # 🔴 DISABLE indexing (anti-forensics)

sudo mdutil -E /            # 🔴 ERASE & rebuild the index (destroys current store)
```

---

## Spotlight Exclusions and Store Config

The Spotlight **Privacy** list (System Settings → Spotlight → Privacy) and index bookkeeping live in a per-volume config plist. 🔴 The **`Exclusions`** array records folders/volumes the user chose **not** to index — an intent / anti-forensics signal (*what did they deliberately keep out of Spotlight?*). The **`Stores`** section dates the index.

| Path | Holds |
|---|---|
| 🔴 `…/.Spotlight-V100/VolumeConfiguration.plist` | `Exclusions` (the Privacy list) + `Stores` (indexed volumes, creation dates, macOS build) |

Modern boot store = **Data volume**: `/System/Volumes/Data/.Spotlight-V100/VolumeConfiguration.plist` (root-owned — read with `sudo`). External volumes: `/Volumes/<vol>/.Spotlight-V100/VolumeConfiguration.plist`.

```bash
# Excluded paths (Privacy list) + index store dates/versions
sudo plutil -p /System/Volumes/Data/.Spotlight-V100/VolumeConfiguration.plist | grep -A10 -iE 'Exclusion|Stores|CreationDate|CreationVersion'
```

| Field | DFIR value |
|---|---|
| 🔴 `Exclusions` | Folders/volumes the user told Spotlight to **skip** — deliberate hiding (excluded items also get **no** `kMDItem*` metadata and won't surface in search) |
| `Stores` → `CreationDate` / `CreationVersion` | When the index store was created + the macOS build — helps date **OS install / reformat / volume first-index** |
| `Stores` → `PartialPath` | Which volume/path each store covers |

> 🔴 An `Exclusions` entry pointing at a **user-data** folder (not a normal system/cache path) means the user actively removed it from indexing. Pair it with on-disk `.metadata_never_index` markers (see Anti-Forensics) for the full "what was hidden from Spotlight" picture.

---

## Anti-Forensics

| Technique | Tell |
|---|---|
| 🔴 `mdutil -E` (erase index) | Store suspiciously **fresh/empty** on an old, busy system |
| 🔴 `mdutil -i off` (disable) | `mdutil -s` shows indexing **disabled** |
| `.metadata_never_index` file in a folder | That folder is excluded from Spotlight (hiding contents) |
| `.noindex` extension on a dir | Excluded from indexing |

```bash
# Hunt for index-exclusion markers
sudo find / -name '.metadata_never_index*' 2>/dev/null
```

---

## Scenarios

🔴 When Spotlight earns its keep:

- **Provenance after quarantine is stripped** — an attacker removes `com.apple.quarantine` to dodge Gatekeeper, but `kMDItemWhereFroms`/`kMDItemDownloadedDate` in the Spotlight store still name the **download URL and time**.
- **Proving a deleted file existed** — the store retains a file's name, where-from, and dates after the file itself is gone; read those `kMDItem*` values to reconstruct what was there.
- **Removable-media recon** — each USB has its **own** `.Spotlight-V100`; mount it and `mdfind -onlyin` (or parse the store) to see what was indexed/accessed on that drive.
- **Execution corroboration** — `kMDItemLastUsedDate` + `kMDItemUseCount` confirm a binary/doc was **opened** and how many times (pairs with Program Execution Evidence).

> How to read it: `mdls` dumps every attribute for a live file; for a dead-box image, parse `store.db` with `spotlight_parser`/mac_apt — the output is one record per file with its `kMDItem*` attributes (treat dates as the artifact's own, and convert Cocoa epochs where shown).

---

## Correlate With

| To answer | Pivot to |
|---|---|
| Where did a file come from? | quarantine / `QuarantineEventsV2` (File Permissions) |
| Did it run / get opened? | Program Execution Evidence; knowledgeC/Biome |
| File deleted but in the store? | Trash; FSEvents `Removed`; carving |
| Activity on a USB | that volume's own `.Spotlight-V100` + FSEvents |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `kMDItemWhereFroms` pointing at a malicious host | Payload provenance (even if quarantine stripped) |
| `kMDItemLastUsedDate`/`UseCount` on a binary in `/tmp`,`~/Library` | A dropped payload was opened |
| Store metadata for files **gone from disk** | Deleted-file evidence |
| Spotlight index **disabled/erased** | Anti-forensics |
| `.metadata_never_index` in a sensitive folder | Hiding contents from search/timeline |
| Where-from/last-used contradicting the user's account | Movement/usage they didn't disclose |

---

## Resources

- spotlight_parser (Yogesh Khatri): https://github.com/ydkhatri/spotlight_parser
- mac_apt (`SPOTLIGHT` plugin): https://github.com/ydkhatri/mac_apt
- `man mdfind` · `man mdls` · `man mdutil`
