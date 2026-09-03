# Quick Look Thumbnails

When a file is **previewed** with Finder **Quick Look** (spacebar), shown as an icon thumbnail, or opened in many apps, macOS caches a **thumbnail image + metadata** in a per-user cache. For DFIR this proves a file was **viewed** — including files on **external drives** or files that have since been **deleted** — and you can **recover the actual thumbnail** (a visual of the content).

> 🔴 Quick Look is one of the few artifacts that gives you a **picture of the file's content** plus the **path** and **view time**, even when the original file is gone or was on a removable drive that's no longer attached.

## Contents
- [Quick Triage](#quick-triage)
- [Where It Lives](#where-it-lives)
- [The index.sqlite Database](#the-indexsqlite-database)
- [Recovering Thumbnails](#recovering-thumbnails)
- [Access and Parsing](#access-and-parsing)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Locate the cache (per-user, under the user's temp/cache dir)
ls -la "$(getconf DARWIN_USER_CACHE_DIR)com.apple.QuickLook.thumbnailcache/"

# Files that were previewed (path + last hit), from the index
sqlite3 "$(getconf DARWIN_USER_CACHE_DIR)com.apple.QuickLook.thumbnailcache/index.sqlite" \
"SELECT folder, file_name, datetime(last_hit_date+978307200,'unixepoch') FROM files ORDER BY last_hit_date DESC LIMIT 30;"
```

---

## Where It Lives

| Path | Holds |
|---|---|
| 🔴 `$DARWIN_USER_CACHE_DIR/com.apple.QuickLook.thumbnailcache/` | The cache dir (resolves to `/var/folders/XX/…/C/com.apple.QuickLook.thumbnailcache/`) |
| `…/index.sqlite` | 🔴 DB: previewed files (path, name, hit dates) + thumbnail index |
| `…/thumbnails.data` | Raw thumbnail **bitmap blobs** (referenced by offset/length in the DB) |

> `getconf DARWIN_USER_CACHE_DIR` prints the user's `/var/folders/…/C/` path. The `/var/folders` tree is per-user and access-restricted (needs FDA live, or read it from an image).

---

## The index.sqlite Database

| Table | Holds |
|---|---|
| 🔴 `files` | One row per previewed file: `folder`, `file_name`, `fs_id`, `version`, `last_hit_date` |
| 🔴 `thumbnails` | Thumbnail records: `file_id`, `size`, `width`/`height`, `bitsperpixel`, `bitmapdata_location`, `bitmapdata_length` |

```sql
-- Previewed files, newest first (Cocoa epoch + 978307200)
SELECT f.folder || '/' || f.file_name AS path,
       datetime(f.last_hit_date + 978307200, 'unixepoch') AS last_viewed
FROM files f
ORDER BY f.last_hit_date DESC;
```

🔴 The `folder` field shows the **full path** the file was previewed from — including `/Volumes/USB/…` for removable media. A path here for a file not on disk = it was viewed and later moved/deleted.

---

## Recovering Thumbnails

The `thumbnails` table points (`bitmapdata_location` + `bitmapdata_length`) into **`thumbnails.data`**, which stores raw **BGRA bitmap** pixels (not a standard image file) at those offsets. A parser carves the bytes and renders them to PNG.

```bash
# Use a dedicated parser to extract + render the thumbnails
python3 QuickLook_parser.py "$(getconf DARWIN_USER_CACHE_DIR)com.apple.QuickLook.thumbnailcache/" /output
```

🔴 Recovered thumbnail = a **visual** of the file's content at view time — powerful when the original is gone (deleted, on an unplugged drive, or in a wiped folder).

---

## Access and Parsing

- Live: the `/var/folders` cache is **access-restricted** — Terminal needs **Full Disk Access**, or copy it from a forensic image.
- Parsers: open-source Quick Look parsers (e.g. Mari DeGrazia's), **mac_apt** (`QUICKLOOK` plugin), commercial suites.
- Copy `index.sqlite` **with** `-wal`/`-shm` and `thumbnails.data` together.

```bash
# Preserve the whole cache for offline parsing
cp -R "$(getconf DARWIN_USER_CACHE_DIR)com.apple.QuickLook.thumbnailcache" /evidence/quicklook
```

---

## Scenarios

🔴 When Quick Look is the artifact that breaks a case:

- **Viewed-then-gone** — a file was previewed, then **deleted or moved off** the Mac; the `files` row + recovered thumbnail prove it existed and show its content.
- **Removable / network media** — a `folder` path under `/Volumes/…` means a file on an **external drive or share** (no longer attached) was opened here.
- **Visual content evidence** — the recovered thumbnail is a **picture of the document/image** at view time — decisive for contraband/IP cases even with no original file.
- **Placing intent on a timeline** — `last_hit_date` is a concrete "the user looked at this specific file at this time" event.

> How to read it: query `files` for path + `last_hit_date`, then map `thumbnails.bitmapdata_location/length` into `thumbnails.data` (raw BGRA pixels) — a parser renders that to a viewable PNG.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Previewed file path under `/Volumes/USB/` | A file on **removable media** was viewed on this Mac |
| `files` entry for a file **not on disk** | Viewed then moved/deleted — recover its thumbnail |
| Thumbnails of **sensitive/exfil** documents | The user looked at them (intent) |
| Preview times outside the user's claimed activity | Access they didn't disclose |
| Thumbnails of contraband/IP | Direct content evidence |

---

## Resources

- mac_apt (`QUICKLOOK` plugin): https://github.com/ydkhatri/mac_apt
- Quick Look thumbnail parsers (e.g. Mari DeGrazia): https://github.com/mdegrazia
- `getconf DARWIN_USER_CACHE_DIR`
