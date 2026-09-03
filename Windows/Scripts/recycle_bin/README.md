# `hunt_recyclebin.ps1` — Recycle Bin ($Recycle.Bin) triage

Read-only Recycle Bin triage for **live Windows incident response** — built to run over EDR
Real-Time Response (RTR) or an interactive session on a host you can't disturb. Parses every
`$I` metadata record under `$Recycle.Bin` on every fixed volume, pairs it with its `$R`
content counterpart, and prints the full deleted-file timeline plus an evidence-weighted
anomaly queue.

- **Script:** [`hunt_recyclebin.ps1`](hunt_recyclebin.ps1) · **version:** 1.0 · **author:** Suvas Patel
- **Siblings:** same doctrine as the Linux/macOS `hunt_persistence.sh` / `hunt_intrusion.sh` tools — evidence-weighted scoring, `[HIGH]`/`[NOTABLE]` tiers, "flag on evidence, enumerate everything else."

---

## Safety contract

**This tool is a passive reader. It is not, and will never become, a restore/delete/empty tool.**

- **Read-only / non-destructive.** The only I/O this script performs is: `Test-Path`, `Get-ChildItem`, `Get-Item`, `[System.IO.File]::ReadAllBytes`, and (only with `-Hash`) `Get-FileHash`. It never calls `Remove-Item`, never restores an item out of the Recycle Bin, never empties or truncates anything, and never writes a file to the host. There is no restore verb, no delete verb, no empty verb — none is planned, and none should be added.
- **Console-only.** No CSV, no JSON, no report file, no temp files. Output goes to the console only, matching the "no footprint on the host" constraint of an RTR session. (If you need machine-readable output, capture stdout at the console/RTR layer — this is a deliberate scope cut, not an oversight.)
- **No elevation required to run.** Administrator rights are needed to read *other users'* SID folders under `$Recycle.Bin` (an OS ACL, not a script requirement). Without elevation the script still runs, still reads what it can (its own SID folder, any world-readable roots), and **explicitly lists** every root/SID folder it could not read under `INACCESSIBLE ROOTS` and the summary tally — it degrades, it does not fail.
- **Single, self-contained `.ps1`.** No modules, no external dependencies beyond built-in .NET/PowerShell types. PowerShell 5.1-compatible (no PS7-only syntax) so it runs unmodified on Windows 10/11 out of the box.
- **Windows 10/11 (`$I` "version 2") format only.** Windows 7/8.0 ("version 1", legacy ANSI `$I` format) is explicitly out of scope — see [Why version matters](#why-version-matters) — and is detected and skipped with a one-line note and a tally entry, never guessed at or silently mis-parsed.

---

## The `$I` / `$R` format (brief)

When a file is sent to the Recycle Bin, Windows renames and splits it into two artifacts inside a per-owner SID folder under `$Recycle.Bin`:

| File | Contents |
|---|---|
| `$I<suffix>` | **Metadata only** — a small fixed header: version, original file size, delete time (as a Win32 `FILETIME`), the original path's length, then the original full path as UTF-16. No file content. |
| `$R<suffix>` | **The content** — the actual recovered file or folder, renamed but otherwise intact. |

### Why version matters

The `$I` header format changed between OS versions. Windows 10/11 uses **"version 2"**: an 8-byte version field (`== 2`) at offset 0, an 8-byte file size at offset 8, an 8-byte `FILETIME` delete time at offset 16, a 4-byte name length at offset 24, then the UTF-16 original path starting at offset 28. Windows 7/8.0 used a different ("version 1") layout with an ANSI/narrower path encoding.

This tool **only implements version 2**. Version 1 is rare in the field now (Windows 7 is long out of support and 8.0-era `$I` files are seen almost nowhere) — implementing a second, largely-dead parser and encoding path was judged not worth the added surface for a v1.0 tool. Critically, this is a **declared** limitation, not a silent one: every `$I` file's version field is checked, and anything other than `2` is skipped with a console note and counted in the **skipped-legacy-version** tally, so an analyst always knows when legacy-format items were present but not parsed — never a guess, never a garbage read, never a swallowed exception.

---

## Anomaly scoring

Every parsed item is scored from the evidence it carries. Tiers: **`HIGH` ≥ 6**, **`NOTABLE` ≥ 3**, else clean (not queued). The full per-item enumeration always shows every item regardless of tier — recovering the deleted-file timeline **is** this tool's core job, never hidden behind a severity filter. The `ANOMALY QUEUE` section is the ranked subset, filtered by `-MinSeverity`.

| Evidence | Weight | Condition |
|---|--:|---|
| `ORPHAN-I` | 3 | An `$I` file exists with **no matching `$R`** in the initial directory listing — metadata survives, content is gone. The pattern a "shift-delete the R, leave the I" or partial anti-forensic wipe produces. |
| `ORPHAN-R` | 3 | An `$R` file exists with **no matching `$I`** — the reverse: content survives, its metadata record is missing (metadata specifically destroyed). |
| `TIMESTAMP-ANOMALY` | 4 | The recovered `$R` item's current Creation or Modified time is **after** the recorded `DeleteTime` — an impossible causality that means something rewrote timestamps after the delete was recorded. |
| `SUSPICIOUS-ORIGINAL-EXT` | 3 | The original filename's extension is one of `ps1 psm1 vbs vbe js jse bat cmd hta exe dll scr` **and** the original path sat under a staging location (`\Temp\`, `\Downloads\`, drive root) rather than a normal installed-app path. |
| `DELETION-CLUSTER` | 3 | **Only evaluated when `-Since`/`-Days` is given.** ≥ 5 items from the same SID owner deleted within the same 5-minute bin → possible mass-delete / anti-forensic wipe event. |

Evidence stacks: e.g. `TIMESTAMP-ANOMALY` (4) + `SUSPICIOUS-ORIGINAL-EXT` (3) = 7 → `HIGH`.

### Why `DELETION-CLUSTER` is gated behind an incident window

Deleting a handful of files close together in time is completely normal (a folder cleanup, an uninstaller, a batch of downloads tidied up). Without a stated incident window there is no baseline to judge "this cluster is anomalous" against, so the check simply doesn't run — matching the sibling tools' doctrine that clustering-style heuristics need a window to mean anything. Give `-Since`/`-Days` when you have an incident timeframe, and the check activates.

### Other false-positive notes

- **`ORPHAN-I`/`ORPHAN-R` are determined from the very first directory listing**, not by re-checking `Test-Path` later — this keeps the finding honest about what was actually missing at scan time, as opposed to something purged mid-scan by a concurrent bin-empty (that's a separate, explicitly-tallied "inaccessible/purged during scan" condition, not treated as orphan evidence).
- **`TIMESTAMP-ANOMALY` only fires when the `$R` item was actually readable.** A `$R` that vanished mid-scan (TOCTOU) is not scored — it's noted in the item's `$R Status` line and tallied separately, not conflated with a genuine timestamp anomaly.
- **`ORPHAN-R` items have no recorded `DeleteTime`** (that's exactly what's missing), so they are never dropped by an active `-Since`/`-Days` window filter — excluding them would hide the exact evidence a window search is trying to surface.

---

## Quick start

```powershell
# Default fast pass -- all fixed volumes, no hashing (cheap pass first)
.\hunt_recyclebin.ps1

# Deep pass -- recursively SHA-256 hash recovered folder contents (opt-in, capped per file)
.\hunt_recyclebin.ps1 -Hash -MaxHashSizeMB 100

# Incident window -- filters to items deleted since a date, activates DELETION-CLUSTER
.\hunt_recyclebin.ps1 -Since 2026-07-20 -MinSeverity Notable

# Point at a mounted/offline image's Recycle Bin instead of (or alongside) live volumes
.\hunt_recyclebin.ps1 -Path 'E:\mounted_image'

# Scope to one owner
.\hunt_recyclebin.ps1 -User jdoe
.\hunt_recyclebin.ps1 -SID S-1-5-21-111111111-222222222-333333333-1001

# Also probe removable (USB) drives
.\hunt_recyclebin.ps1 -IncludeRemovable
```

---

## Options

| Option | Effect |
|---|---|
| `-Path string[]` | Add specific `$Recycle.Bin` roots to scan (live volume root, mount root, or the `$Recycle.Bin` folder itself) — in addition to the default live-volume sweep. |
| `-IncludeRemovable` | Also probe removable (`DriveType=2`, USB) drives' `$Recycle.Bin`, on top of the default fixed-drive sweep. |
| `-Since 'yyyy-MM-dd'` | Incident window (UTC). Filters the enumeration to items deleted on/after this date and activates `DELETION-CLUSTER`. Overrides `-Days`. |
| `-Days N` | Incident window: last N days (UTC, from now). Same effect as `-Since`. |
| `-User string` | Filter results to one owner (case-insensitive substring match on the resolved account name). |
| `-SID string` | Filter results to one owner by exact SID folder name. |
| `-Hash` (alias `-Deep`) | Opt-in recursive SHA-256 hashing of recovered folder contents (and the recovered file itself, for single-file items). Off by default — folders are still walked for file count/total size without this flag, just not hashed, so the default pass stays fast. |
| `-MaxHashSizeMB int` (default `200`) | Per-file cap when `-Hash` is enabled — files above this size are skipped for hashing (individually noted) rather than hanging the run on one huge recovered file. |
| `-MinSeverity High\|Notable\|Low` (default `Low`) | Filters the `ANOMALY QUEUE` section only. The full item enumeration always shows every item regardless of this setting. |
| `-Help` | Full comment-based help (`Get-Help -Full`) and exit. |

---

## Reading a finding

```
[HIGH] Recycle Bin item: C:\$Recycle.Bin\S-1-5-21-.../$ISTUVWX.ps1
   Deleted (UTC) : 2026-07-28 20:06:45 UTC
   Original Path : C:\Users\jdoe\Downloads\payload.ps1
   Original Size : 50 bytes
   $I File       : C:\$Recycle.Bin\S-1-5-21-.../$ISTUVWX.ps1
   $R File       : C:\$Recycle.Bin\S-1-5-21-.../$RSTUVWX.ps1
   Current Size  : 17 bytes
   Current Times : Created 2026-07-29 20:06:45 UTC | Modified 2026-07-29 20:06:45 UTC | Accessed 2026-07-29 20:06:45 UTC
   File Hash     : N/A (hashing disabled -- use -Hash to enable)
   Evidence      : TIMESTAMP-ANOMALY, SUSPICIOUS-ORIGINAL-EXT  (score 7, tier HIGH)
```

Read it as: a `.ps1` was deleted from `Downloads` (a staging location, not an installed app — `SUSPICIOUS-ORIGINAL-EXT`), and its recovered content's current Modified time (2026-07-29) is **after** the recorded delete time (2026-07-28) — an impossible causality (`TIMESTAMP-ANOMALY`) that means something touched the file's timestamps after it was already in the bin. Stacked evidence (4 + 3 = 7) crosses the `HIGH` threshold (≥ 6).

---

## Coverage / tallies

Every run ends with an explicit accounting of what it *couldn't* fully process, so gaps are visible rather than hidden:

| Tally | Meaning |
|---|---|
| Skipped (legacy `$I` version) | `$I` files whose version field wasn't `2` — Windows 7/8.0 format, out of scope, not parsed. |
| Malformed/truncated `$I` headers | `$I` files too short to safely read (corrupt, mid-write, or truncated) — never sliced blindly. |
| Unreadable `$I` files | `[System.IO.File]::ReadAllBytes` failed (locked, sharing violation, etc.). |
| Inaccessible `$R` files (TOCTOU/purged) | An `$R` file was present in the initial listing but couldn't be opened when the script got to it (e.g. a concurrent Recycle Bin empty). |
| Inaccessible roots/SID folders | A `$Recycle.Bin` root or SID subfolder existed but `Get-ChildItem` was denied — almost always needs elevation. |

An absent `$Recycle.Bin` on a volume (no deleted items ever, or the folder was never created) is logged in `VOLUMES SCANNED` but is **not** an error and is **not** tallied as a gap.

---

## Validation checklist

Run these on a disposable/lab machine (never on a production host you're trying to preserve):

1. **Basic recovery.** Delete a test file to the Recycle Bin, run the script with no options. Confirm it appears with the correct original path, original size, and delete time (UTC), and that its current size/timestamps match the still-present `$R` item.
2. **`ORPHAN-I`.** Delete a test file, then manually remove just its `$R` counterpart (e.g. `Remove-Item` the `$R<suffix>` file directly, leaving the `$I` in place). Re-run and confirm `ORPHAN-I` fires (score 3, `NOTABLE`).
3. **`ORPHAN-R`.** Reverse the above: leave a lone `$R` file with no matching `$I` in a SID folder. Confirm `ORPHAN-R` fires.
4. **`TIMESTAMP-ANOMALY`.** After deleting a test file, modify the recovered `$R` item's `LastWriteTime`/`CreationTime` to a point after the recorded delete time (e.g. `(Get-Item $rPath).LastWriteTime = Get-Date`). Confirm `TIMESTAMP-ANOMALY` fires.
5. **`SUSPICIOUS-ORIGINAL-EXT`.** Delete a `.ps1`/`.exe` from `%TEMP%` or `Downloads`. Confirm the flag fires; delete the same extension from a normal `Program Files` path and confirm it does **not**.
6. **`DELETION-CLUSTER`.** Delete 5+ files as the same user within a few seconds of each other, then run with `-Days 1` (or `-Since` covering today). Confirm `DELETION-CLUSTER` fires for all members of the cluster, and that a second, unrelated user's smaller batch at the same moment does **not** merge into it.
7. **Legacy-version handling.** If you have access to a genuine Windows 7/8.0 `$I` file (or a synthetic one with a non-`2` version field), confirm it is skipped with the one-line console note and counted under "skipped-legacy-version" — not parsed, not crashed on.
8. **Graceful degradation.** Run once elevated and once not. Confirm the non-elevated run still completes, still reports its own SID folder, and lists every inaccessible root/SID folder explicitly rather than failing.
9. **`-Hash` cap.** With `-Hash -MaxHashSizeMB 1`, recover a folder containing a file > 1 MB. Confirm that file is reported as skipped (with size and cap noted) rather than hashed, while smaller files in the same folder are hashed normally.

---

## Changelog

- **v1.0** — Initial professional rewrite from an ad hoc script. Multi-volume sweep (all fixed drives by default, `-IncludeRemovable` for USB, `-Path` for offline/mounted images); version-2-only `$I` parsing with explicit skip-and-tally of anything else (no more silent garbage reads on Windows 7/8.0 files); bounds-checked header/name parsing (no more ungraceful exceptions on truncated `$I` files); hashing made opt-in (`-Hash`/`-Deep`) with a per-file `-MaxHashSizeMB` cap (no more unbounded recursive hashing hangs); SID-translation failures now always retain the SID (`"Unknown User (SID: ...)"`, never a bare "Unknown User"); TOCTOU-safe `$R` access (a companion file purged mid-scan is noted, not a crash); locked/mid-write `$I` files tallied as "unreadable" instead of vanishing; new evidence-weighted anomaly engine (`ORPHAN-I`, `ORPHAN-R`, `TIMESTAMP-ANOMALY`, `SUSPICIOUS-ORIGINAL-EXT`, `DELETION-CLUSTER`) with `[HIGH]`/`[NOTABLE]` tiers and a ranked `ANOMALY QUEUE`; explicit coverage tallies (skipped-legacy-version, malformed headers, unreadable files, inaccessible `$R`/roots) so gaps are visible instead of hidden.
