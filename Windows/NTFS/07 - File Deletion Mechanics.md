# File Deletion Mechanics

Every other note in this folder describes one NTFS structure in isolation — the $MFT record, $SI/$FN, $DATA, $I30, $LogFile, $UsnJrnl. This note is the synthesis: it walks a single delete event through **all six** of those structures in the order they're touched, and shows exactly what evidence each one leaves behind and for roughly how long. If the rest of the folder is the reference manual, this is the worked example that ties the manual together.

> 🔴 **"Delete" in NTFS is a metadata operation, not a content-erasure operation.** At the instant a file is deleted, not one byte of its actual data is touched. What changes are pointers, flags, and index entries — the bytes those pointers used to reference sit exactly where they were until something else overwrites them. Every recovery technique in this folder, and every entry in the table below, exists because of that one fact.

## Contents

- [The Deletion Event Trail](#the-deletion-event-trail)
- [The Three-Layer View, and the Full Task List](#the-three-layer-view-and-the-full-task-list)
- [🎯 Hunt Evil](#-hunt-evil)
- [Stage 1 — The $MFT Record](#stage-1--the-mft-record)
- [Stage 2 — The Parent Directory's $I30](#stage-2--the-parent-directorys-i30)
- [Stage 3 — $Bitmap (Cluster Allocation)](#stage-3--bitmap-cluster-allocation)
- [Stage 4 — $LogFile](#stage-4--logfile)
- [Stage 5 — $UsnJrnl](#stage-5--usnjrnl)
- [Stage 6 — Recycle Bin (the Alternative First Stage)](#stage-6--recycle-bin-the-alternative-first-stage)
- [Deleted-File Recovery Concepts](#deleted-file-recovery-concepts)
  - [Orphan Files and the Recycle Bin Record Pair](#orphan-files-and-the-recycle-bin-record-pair)
  - [Copy-on-Write and Volume Shadow Copies](#copy-on-write-and-volume-shadow-copies)
  - [File-Index-Based vs File-Header-Based Recovery](#file-index-based-vs-file-header-based-recovery)
  - [Full-File Carving vs Segment/Fragment Carving](#full-file-carving-vs-segmentfragment-carving)
  - [SSD/TRIM: The Data-Recovery Ceiling](#ssdtrim-the-data-recovery-ceiling)
- [Search Methodology: String vs Indexed](#search-methodology-string-vs-indexed)
- [Recovery Priority: What to Check First](#recovery-priority-what-to-check-first)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Deletion Event Trail

One delete event, six structures, six different survival windows. Read this table as both a preview of the walkthrough below and a standalone cheat sheet — pin it.

| Structure | What changes at deletion | What survives, and roughly how long | Recovery tool |
|---|---|---|---|
| **$MFT record** | In-use flag flips to unallocated; record becomes eligible for reuse | Full record bytes ($SI/$FN, resident $DATA if any) survive **untouched** until this exact record slot is reused by a new file — no fixed time window, purely a function of volume churn | `istat` (TSK), MFTECmd |
| **Parent $I30 (directory index)** | Entry removed from the live B-tree | Removed entry's raw bytes frequently persist in **INDX-record slack** from B-tree rebalancing — often the **longest-surviving** trace of the file's name/size/timestamps, regularly outliving the $MFT record itself | Indx2Csv, Velociraptor (`Windows.NTFS.I30`), manual slack carving |
| **$Bitmap** | Occupied clusters (if $DATA was non-resident) marked free | Cluster **bytes** are untouched — only allocation status flips; freed clusters are immediately in-scope for reallocation, timing driven by proximity to the MFT Zone | PhotoRec, TSK `blkls`/unallocated-space carving |
| **$LogFile** | Deletion transaction logged at the moment it happens (LSN, affected record) | Short-lived — rolling, typically ~64MB; once that portion of the journal rolls over, this trace is gone, often before the other three | LogFileParser (🔴 not MFTECmd — verified not to support `$LogFile`, see note 05) |
| **$UsnJrnl ($J stream)** | `USN_REASON_FILE_DELETE` (+`CLOSE`) record appended, fully timestamped | Durable relative to the others — rolling ~32MB window managed independently of $MFT/$I30 survival; usually the easiest evidence to query at scale | MFTECmd |
| **Recycle Bin ($R/$I pair)** | *Alternative first stage* — Explorer delete moves the file into `$Recycle.Bin\<SID>\` instead of freeing it outright | Full file content ($R) + original path/size/delete-time ($I) survive until the bin is emptied or purged, at which point stages 1–5 above apply to the underlying record | RBCmd |

## The Three-Layer View, and the Full Task List

The Deletion Event Trail table above is organized by **structure** (six of them). A layer-based framing of the same event regroups it by **layer** instead — a useful zoomed-out cross-check that the six-structure trail hasn't missed anything conceptually:

```
┌─────────────────────────────────────────────────────────────────────┐
│  DATA LAYER                                                         │
│  $Bitmap marks clusters unallocated → data + slack space intact     │
│  until those specific clusters are reused                          │  → Stage 3
├─────────────────────────────────────────────────────────────────────┤
│  METADATA LAYER                                                     │
│  Single bit flips in the $MFT record → all metadata remains         │
│  readable until the record itself is reused; $LogFile/$UsnJrnl      │  → Stages 1, 4, 5
│  and other system logs still reference the file after deletion      │
├─────────────────────────────────────────────────────────────────────┤
│  FILENAME LAYER                                                     │
│  $FILE_NAME attribute preserved until $MFT record reused;           │
│  $I30 index entry in the parent directory may also be preserved     │  → Stage 2
└─────────────────────────────────────────────────────────────────────┘
```

| Layer | What changes | What survives, and until when |
|---|---|---|
| **Data Layer** | Clusters marked unallocated in `$Bitmap` | File data **and slack space** remain fully intact until those specific clusters are reused — the `$Bitmap` flip doesn't touch a single content byte |
| **Metadata Layer** | A single bit flips in the file's `$MFT` record | All file metadata (`$SI`, `$FN`, security/quota references) stays readable until the record itself is reused; `$LogFile`, `$UsnJrnl`, and other system logs continue to reference the file after deletion |
| **Filename Layer** | Entry removed from the parent directory's `$I30` B-tree | `$FILE_NAME` survives inside the (still-intact) `$MFT` record until reuse; the `$I30` index entry in the parent directory **may** also survive in INDX slack |

🔴 Same point this whole note makes, said a third way: **nothing is erased at deletion — only pointers and flags change**, and each layer decays on its own independent clock.

**The standard task list** for what NTFS actually does on delete (*"not necessarily in order, and in fact, this is not even all the steps that actually occur"* — treat as a checklist of mechanisms in play, not a strict sequence or an exhaustive one):

| NTFS task at deletion | Detail | Maps to |
|---|---|---|
| `$MFT` record marked available | Not immediately overwritten — may exist completely intact for some time | Stage 1 |
| `$Bitmap` marks associated clusters available | The clusters themselves are untouched; may or may not eventually be reused | Stage 3 |
| Parent directory's index marks the entry available | May trigger a B-tree rebalancing, which may or may not overwrite the file's own index entry | Stage 2 |
| `$LogFile` updated | Reflects that the deletion transaction occurred | Stage 4 |
| `$UsnJrnl` updated | Reflects the file's deletion — **only if enabled** (`$UsnJrnl` is not enabled by default on Windows XP and earlier) | Stage 5 |
| `$Secure`, `$ObjID`, and `$Quota` updated | If applicable to the file — see below | *(new — not a numbered Stage above)* |

🔴 **`$Secure`, `$ObjID`, and `$Quota` — the detail the six-structure trail above doesn't call out on its own**, because not every file touches these three, and when they don't apply they're forensically silent. When a deleted file *did* use them:

- **`$Secure`** — if the file held a unique (non-shared) security descriptor, that entry's reference count drops. Most files share a common `$Secure` entry with many others (see [00's NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table), so this rarely produces anything an examiner would notice.
- **`$ObjID`** — if the file had a Distributed Link Tracking object ID (uncommon outside NTFS junction/shortcut-tracking scenarios), that ID mapping is invalidated.
- **`$Quota`** — if disk quotas are enabled and the file's owner was being charged for its size, the quota accounting is adjusted to release that charge.

None of these three are primary recovery targets the way `$MFT`/`$I30`/`$LogFile`/`$UsnJrnl` are — they're conditional, low-volume, and rarely hold content of direct forensic interest — but they round out the complete picture of what NTFS actually touches at a delete event, so this note doesn't imply Stages 1–6 are the entire story.

## 🎯 Hunt Evil

The fast triage sequence for one specific deleted file — confirm it happened, then see how much is still recoverable, in two commands.

```bash
# 1. Confirm the deletion and get its exact time + parent path from the most durable source first
MFTECmd.exe -f '$J' --csv out.csv --csvf usnjrnl.csv
# then filter the CSV for the target filename with UpdateReasons containing "FileDelete"

# 2. Take the record number/inode surfaced by $J (or by fls) and check whether the $MFT slot has been reused
istat -o <offset> image.dd <record_number>
# "Not In Use" + timestamps/attributes still matching what $J reported = record not yet reused, full metadata (and resident content) recoverable
```

If `istat` on that record number instead shows an **allocated** entry for a different filename, the slot has already been reused — pivot straight to $I30 slack and unallocated-cluster carving rather than trusting the record.

## Stage 1 — The $MFT Record

The moment a delete is processed, NTFS clears the **in-use flag** in the target record's header — the same flag [01 - MFT Entry Structure and Attributes](01%20-%20MFT%20Entry%20Structure%20and%20Attributes.md) covers in depth. That single bit flip is the entire "delete" as far as the $MFT record itself is concerned: the record is now **unallocated** and eligible for a future file to claim, but nothing inside it is zeroed. $SI and $FN timestamps, any resident $DATA content, the full attribute list — all of it sits exactly as it was until some other file creation claims this exact record slot.

The record's **sequence number** does not change at deletion — it only increments the *next time this slot is reused*, per 01's FRN discussion. That's the mechanism behind $MFT-record-based deleted-file recovery: as long as no new file has claimed the slot, a tool like `istat` or MFTECmd reads a "deleted" file's full metadata — and any resident content — exactly as if it still existed. This is the fastest, richest recovery path in the whole trail, and the first one to check.

## Stage 2 — The Parent Directory's $I30

Independent of what happens to the $MFT record, the file's entry is removed from its **parent directory's $I30 index** — the B-tree structure covered in full by [04 - $I30 Directory Index and B-Trees](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md). Because B-tree rebalancing doesn't scrub the space it reclaims, the removed entry's raw bytes — name, size, timestamps — frequently persist in **INDX-record slack** long after the entry is gone from the live index. 04 covers this mechanic and its accompanying 🔴 callout (file-wiping tools that scrub file content routinely leave $I30 slack untouched) in depth; the point to carry forward here is simply that this is often the **longest-surviving** trace of a deleted file's identity in the entire trail — regularly outliving the $MFT record itself, since a directory's index churns at a different rate than the $MFT's record pool.

## Stage 3 — $Bitmap (Cluster Allocation)

If the file's `$DATA` attribute was non-resident (see [03 - $DATA Attribute and Resident vs Non-Resident Files](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md)), the clusters it occupied get marked **free** in the volume's `$Bitmap`, one of the NTFS Metadata Files. As with every other stage, only the allocation status changes; the cluster **bytes** are left exactly as written. That's the entire reason unallocated-space carving (PhotoRec and friends, covered below in [Full-File Carving vs Segment/Fragment Carving](#full-file-carving-vs-segmentfragment-carving)) works at all — it's reading freed-but-unwiped clusters directly, with no filesystem structure required.

This stage is also where the MFT Zone matters: MFT records for deleted files persist longest when the MFT Zone still has spare capacity, and the same logic applies to freed data clusters near that zone. A volume running near-full or under heavy churn burns through that runway fast; freed clusters immediately adjacent to the MFT Zone are exactly the ones most likely to be reclaimed first by new $MFT growth or new file writes, shrinking the carving window before an examiner ever gets there.

## Stage 4 — $LogFile

The deletion is itself a metadata transaction, so NTFS logs it — LSN, affected record, operation type — into `$LogFile` at the moment it happens, per [05 - $LogFile (NTFS Transaction Journal)](05%20-%20%24LogFile%20%28NTFS%20Transaction%20Journal%29.md). This is the shortest-lived trace in the whole trail: `$LogFile` is a small, rolling journal (~64MB in practice), so a busy volume can cycle through it in hours. But while that portion of the journal hasn't rolled over yet, it's uniquely valuable — it can confirm **that a deletion transaction occurred, its LSN, and which record it touched** even after stages 1–3 above have already been overwritten by later activity. Treat a live $LogFile hit as corroboration, not a primary source — it's usually gone long before $UsnJrnl is.

## Stage 5 — $UsnJrnl

A separate, durable, timestamped record of the deletion is appended to `$UsnJrnl`'s `$J` stream, carrying the `USN_REASON_FILE_DELETE` reason code (typically paired with `CLOSE`) — see [06 - $UsnJrnl (USN Change Journal)](06%20-%20%24UsnJrnl%20%28USN%20Change%20Journal%29.md) for the full record structure. This is usually the **most durable, easiest-to-query** evidence in the entire trail that "a file with this name, in this directory, was deleted at this time" — precisely because $UsnJrnl's ~32MB rolling window is managed independently of whether the $MFT record or $I30 slack has survived, and because MFTECmd makes filtering `$J` by reason code trivial at scale (06's filtering coverage). In practice this is the layer worth checking first on almost every case.

## Stage 6 — Recycle Bin (the Alternative First Stage)

Everything above describes what happens when a file's storage is actually freed. A normal Explorer delete (no Shift+Delete, no `Remove-Item -Force` bypass) doesn't do that immediately — it **moves** the file into `$Recycle.Bin\<SID>\` as a renamed `$R`/`$I` pair instead. See [Orphan Files and the Recycle Bin Record Pair](#orphan-files-and-the-recycle-bin-record-pair) below for the `$R`/`$I` mechanics in full.

The point that matters for this trail: the Recycle Bin move is an **alternative first stage**, not an addition to the six above. A file sitting in the Recycle Bin hasn't triggered stages 1–5 yet — its $MFT record is still allocated (now under the Recycle Bin path), its $I30 entry moved rather than vanished, and its clusters are still allocated in $Bitmap. Stages 1–5 only fire later, when the bin itself is emptied or auto-purged and the underlying record is genuinely freed.

## Deleted-File Recovery Concepts

Everything above walks one specific delete event through NTFS's own structures. This section pulls back to the general recovery toolbox — the concepts an examiner reaches for once "what does NTFS record about a deletion" gives way to "what can actually be gotten back, and how."

### Orphan Files and the Recycle Bin Record Pair

An **orphan file** is an $MFT record (or a recovered file fragment) whose parent directory reference no longer resolves — the file's data or metadata survives, but the folder it once lived in is gone from the live filesystem. Orphans are common carving output and need to be re-associated with a plausible path (often via $LogFile/$UsnJrnl history or Jump List/LNK cross-references) rather than trusted at face value.

The Recycle Bin itself stores a deleted file as a **matched pair** inside `$Recycle.Bin\<user SID>\`:

| File | Holds |
|---|---|
| **`$R<id>`** | The actual deleted file content, renamed |
| **`$I<id>`** | Metadata: original full path, original file size, and the deletion timestamp |

This pairing is the actual source of "when was this file deleted" — the file's own $MFT record timestamps do **not** change on deletion (per the MACE/MACB rules in [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md)); the deletion time lives in the `$I` record instead. (Pre-Windows 10, the equivalent was a single `INFO2` index file rather than per-item `$I`/`$R` pairs — parse either with **RBCmd**, Eric Zimmerman's Recycle Bin parser; it natively handles both the modern `$I`/`$R` pairs and the legacy `INFO2` format from the same binary.)

```bash
# Point RBCmd at a triage copy of the user's Recycle Bin folder and dump every $I/$R pair it finds to CSV
RBCmd.exe -d "C:\triage\$Recycle.Bin" --csv "C:\triage\out"

# Legacy pre-Win10 layout: a single INFO2 index file instead of per-item $I/$R pairs
RBCmd.exe -f "C:\triage\INFO2" --csv "C:\triage\out"
```

> 🔴 **Verify current flag names against `RBCmd.exe --help`** (or the tool's own docs) before scripting around a specific switch — this reflects RBCmd's documented syntax as of this writing, not a guarantee against future renames.

**Representative RBCmd CSV row** (illustrative — hand-assembled to show the shape and meaning of real RBCmd CSV output, not a literal capture from a specific parse; exact column names should be confirmed against a live run):

```
FileType, FileName, FileSize, DeletedOn
$I, C:\Users\jdoe\Desktop\invoice_final.xlsx, 245184, 2026-07-14 09:12:33
```

### Copy-on-Write and Volume Shadow Copies

**Copy-on-Write (COW)** is the underlying mechanism the **Volume Shadow Copy Service (VSS)** uses to create point-in-time snapshots: before a block on disk is overwritten, VSS copies the original block into the shadow storage area first, so the snapshot can reconstruct the volume as it existed at snapshot time even though the live volume has since changed. Practically, this means a **prior version of a deleted or modified file can survive inside a shadow copy long after it's gone from the live filesystem** — an entirely separate recovery avenue from carving, since a shadow copy holds a complete, structured, previous-state file rather than raw recovered bytes. **ShadowExplorer** is the standard free tool for browsing and extracting files directly out of existing shadow copies without needing native `vssadmin`/`mklink` steps.

Before reaching for ShadowExplorer (or escalating to 19's full coverage), the fastest way to confirm the claim above is concretely true on a *live* host — i.e. that shadow copies actually exist to check — is native and built into Windows:

```powershell
vssadmin list shadows
```

```
Contents of shadow copy set ID: {3a6e8451-1c2d-4f3a-9e21-7a5b6c8d1234}
   Contained 1 shadow copies at creation time: 7/18/2026 3:02:11 AM
      Shadow Copy ID: {b45fca23-88e1-4a90-9c7d-1f2e3a4b5c6d}
         Original Volume: (C:)\\?\Volume{c1a2b3d4-...}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: HOST01
         Service Machine: HOST01
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, Differential, Auto recovered
```

That `Shadow Copy Volume` device path can be exposed as a browsable directory with `mklink`, without ShadowExplorer:

```powershell
mklink /d C:\shadow_mount \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

This is deliberately the minimal live-host check, not a VSS tutorial — full shadow-copy forensic analysis (enumeration against offline images, timestamp implications of snapshot schedules, anti-forensic shadow-copy deletion as an attacker technique) belongs to `Windows/19 - Anti-Forensics and Evidence Destruction.md`.

### File-Index-Based vs File-Header-Based Recovery

Two fundamentally different strategies exist for finding what to recover:

| Approach | How it works | Strength | Weakness |
|---|---|---|---|
| **File-index-based** | Trusts filesystem structures ($MFT records, directory index entries) that still reference the file/its clusters even though the file is marked deleted | Recovers full metadata (original name, path, exact timestamps, exact size) — a much richer result | Only works as long as the index entry itself survives; useless once the $MFT record is reused |
| **File-header-based** (carving) | Ignores filesystem structures entirely; scans raw disk bytes for known file-type signatures (header/footer magic bytes) | Works even after the filesystem structures are completely gone — the only option left once index metadata is overwritten | No filename, no path, no reliable timestamp; high false-positive rate on file types with generic/common header bytes |

Practical order of operations: always attempt index-based recovery first (it's free, fast, and gives full metadata) — fall back to header-based carving only for what index recovery can't reach.

### Full-File Carving vs Segment/Fragment Carving

| Strategy | What it assumes | When it fails |
|---|---|---|
| **Full-file carving** | The file's data lives in one contiguous, unfragmented run of clusters between a recognized header and footer | Any fragmented file — carving stops at the first gap and either truncates the recovered file or produces garbage past that point |
| **Segment/fragment carving** | Reassembles a file from multiple non-contiguous pieces, using internal file-structure knowledge (e.g. JPEG restart markers, known compression block boundaries) to stitch fragments back together in the right order | Computationally far more expensive, and still fails when intervening clusters have been overwritten by unrelated data |

**PhotoRec** (paired with **TestDisk**, both free/open-source) is the field-standard carving tool — it works directly against raw disk images/partitions independent of the filesystem's own bookkeeping, which is exactly why it's the fallback tool once index-based recovery and even $MFT-record recovery are exhausted. Autopsy, The Sleuth Kit's `tsk_recover`, and FTK Imager all include carving capability as well, generally layered on the same header/footer-signature approach.

`tsk_recover` is the simplest of these to run from the command line — it walks an image (or a volume within one) and dumps recovered files straight to an output directory, no interactive session required:

```bash
# -e = recover both allocated and unallocated files (default is unallocated-only);
# -o = sector offset of the specific volume to recover, when the image has more than one
tsk_recover -e -o <sector_offset> image.dd output_dir
```

🔴 **Confirm `-e`/`-a`/`-o` and the unallocated-only default against `tsk_recover -h` or the current TSK docs** before relying on a specific behavior — the sleuthkit.org man page is authoritative.

**PhotoRec itself is primarily an interactive/TUI tool** — the workflow most examiners actually use is the on-screen partition/filesystem/file-type wizard, not a fully-scripted invocation. It does have a genuine documented non-interactive mode, though, via `/cmd`:

```bash
# /log = write photorec.log; /d = output directory; /cmd = scripted command section
# (device or image, followed by a comma-separated option string: partition table type, options, file options, then "search")
photorec /log /d /mnt/recover/case01 /cmd disk.dmp options,fileopt,everything,enable,search
```

This scripted form is real (documented at cgsecurity.org's "Scripted run" page) but its comma-separated option grammar is fussy and version-sensitive — 🔴 **treat the example above as illustrative of the shape, and verify the exact option tokens against `photorec` `/cmd` documentation for the installed version** before scripting a case around it. Most examiners still run PhotoRec interactively and reserve scripting for repetitive, already-validated jobs.

### SSD/TRIM: The Data-Recovery Ceiling

Everything above assumes the underlying storage keeps deleted data around until something overwrites it — true for spinning disks, but **not reliably true for SSDs**, and this changes analyst expectations fundamentally rather than just at the margins.

| Mechanic | What it does | DFIR consequence |
|---|---|---|
| **Wear leveling** | The SSD controller spreads writes across physical NAND cells to avoid wearing any one cell out faster than others, transparently to the OS | The OS/filesystem's idea of "where" a file's data lives on the physical media is no longer reliable — there is no stable physical-to-logical mapping an examiner can reason about the way they could with a spinning disk |
| **TRIM** | The OS proactively tells the SSD controller which logical blocks are no longer in use (right after deletion) so the controller can erase them ahead of the next write, which is required for SSD write performance | Once TRIM runs against a deleted file's blocks — often within seconds on a modern Windows host with TRIM enabled by default — **the underlying NAND cells are physically erased, not just marked free.** No index-based recovery, no carving, no forensic tool can bring that data back. This is a hardware-level erasure, not a filesystem-level deletion. |

🔴 **The practical shift this forces**: on a spinning disk, "was the file overwritten yet" is the operative question and the answer is often "no, not yet" for a long time. On an SSD with TRIM active, the operative question becomes "has TRIM run yet" — and if it has, the recovery conversation is over regardless of how quickly the examiner arrived or how sophisticated the carving tool is. Set client/case expectations accordingly: a deleted file on a modern SSD is frequently **not** recoverable at all, a categorically different answer than the "maybe, if it hasn't been overwritten" answer that applies to legacy media.

## Search Methodology: String vs Indexed

Once acquisition and carving are done, finding the needle in a disk image comes down to a genuine speed-vs-thoroughness tradeoff between two search strategies:

| Method | How it works | Speed | Thoroughness |
|---|---|---|---|
| **String/keyword (bit-for-bit) search** | Scans every byte of the target (allocated space, unallocated space, slack space, even inside unparsed structures) for a literal byte pattern, independent of any filesystem or file-format understanding | Slow — genuinely proportional to total bytes scanned, including everything the filesystem itself would ignore | Maximum — finds a hit anywhere the bytes physically exist, including inside deleted/unallocated space, embedded/compressed streams a parser might miss, and file types with no dedicated parser |
| **Indexed search** | Relies on a pre-built index (Windows Search's own `Windows.edb`, or a forensic tool's own indexing pass) that has already extracted and tokenized text from known, parseable file types | Fast — near-instant once the index exists | Bounded by what got indexed: skips unallocated space, skips file types the indexer doesn't understand, and is only as current as the last index update — a file created after indexing, or living in unallocated space, simply isn't there to find |

Field-standard tooling: `strings`/`bstrings.exe` (Eric Zimmerman) for raw string extraction across a whole image; forensic-suite indexed search (Autopsy's keyword-search module, X-Ways, FTK/EnCase's indexing engines) for fast, repeatable searches across a case once the index is built. Neither replaces the other — a competent exam typically runs an indexed search first for speed on the bulk of the case, then falls back to a full bit-for-bit string search specifically against unallocated space or when the indexed pass comes up empty on something known to exist.

```bash
# Sweep an extracted volume (or a mounted/raw image path) for a known IOC/ransom-note string,
# including unallocated space, with byte offsets recorded against each hit
bstrings.exe -d "C:\triage\volume" --ls "YOUR FILES HAVE BEEN ENCRYPTED" --off -o hits.txt
```

> 🔴 **Verify current flag names against `bstrings.exe --help`** before scripting around a specific switch — `-d` (directory), `--ls` (literal string filter), `--off` (append hit offsets), and `-o` (results file) reflect the tool's documented syntax as of this writing.

Representative output (illustrative — hand-assembled to show the shape of a `bstrings.exe --off` hit list, not a literal capture from a specific run):

```
YOUR FILES HAVE BEEN ENCRYPTED  Off: 41938176 (U)
YOUR FILES HAVE BEEN ENCRYPTED  Off: 118304512 (A)
```

## Recovery Priority: What to Check First

Given limited time on "was this file deleted, when, and can I get it back," work the trail in durability order, not disk-layout order:

1. **$UsnJrnl first.** Fast, durable, trivially filterable — confirms the fact and time of deletion before anything else.
2. **$MFT record directly**, if the record hasn't been reused — full metadata, and possibly resident content, in one read.
3. **$I30 slack in the parent directory**, if the $MFT record is already gone — name, size, and timestamps can still survive here even after the record itself is unrecoverable.
4. **$LogFile**, for transaction-level corroboration — LSN and operation confirmation, useful mainly to firm up a timeline already built from the steps above.
5. **Unallocated-cluster carving**, last resort for content recovery once every index-based avenue above is exhausted — see [File-Index-Based vs File-Header-Based Recovery](#file-index-based-vs-file-header-based-recovery) above for the full tradeoff.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| $UsnJrnl shows a clean `FILE_DELETE` trail for a file, but the $MFT record it pointed to now holds unrelated, allocated content | The recovery window has already closed — the record was reused before the examiner arrived; narrows what's still achievable and should be stated plainly in the report rather than implied |
| $I30 slack holds a full entry (name, size, timestamps) for a file with **no** corresponding $UsnJrnl deletion record at all | Possible USN journal clearing or a gap in journal coverage — cross-check against 06's Journal-ID-discontinuity red flag before assuming the file was simply never tracked |
| $LogFile shows a deletion transaction with no matching $UsnJrnl entry for the same record/time | $UsnJrnl may have rolled over or been cleared after the fact — treat as a possible anti-forensic gap, not a benign timing coincidence |
| A file recovered from unallocated-cluster carving has no corresponding hit anywhere in $UsnJrnl, $MFT, or $I30 slack | All three index-based layers have already rolled past this event — carving is the last remaining evidence, and its lack of metadata (name, path, exact time) should be flagged as a real limitation, not filled in by assumption |
| Deleted files sought on an SSD with TRIM enabled, well after the deletion event | Set expectations accordingly — recovery may not be possible regardless of tooling |

## Correlate With

- [00 - NTFS Deep Dive Overview](00%20-%20NTFS%20Deep%20Dive%20Overview.md) — folder map and mental model this walkthrough assumes.
- [01 - MFT Entry Structure and Attributes](01%20-%20MFT%20Entry%20Structure%20and%20Attributes.md) — in-use flag, sequence numbers, and FRN mechanics behind Stage 1.
- [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md) — the $SI/LSN and USN-sequence-number fields tying an $MFT record back to $LogFile/$UsnJrnl entries.
- [03 - $DATA Attribute and Resident vs Non-Resident Files](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md) — resident vs non-resident content, and why Stage 3 only applies to non-resident data.
- [04 - $I30 Directory Index and B-Trees.md](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md) — the INDX-slack survival mechanics behind Stage 2.
- [05 - $LogFile (NTFS Transaction Journal).md](05%20-%20%24LogFile%20%28NTFS%20Transaction%20Journal%29.md) — full transaction-record structure behind Stage 4.
- [06 - $UsnJrnl (USN Change Journal).md](06%20-%20%24UsnJrnl%20%28USN%20Change%20Journal%29.md) — full reason-code structure and filtering behind Stage 5.
- `Windows/08 - Deleted Items and File Existence.md` — the application-layer angle (Recycle Bin behavior from the user's perspective, Thumbs.db, and other deleted-item artifacts beyond the filesystem structures covered here).
- `Windows/19 - Anti-Forensics and Evidence Destruction.md` — full shadow-copy forensic analysis (enumeration, snapshot-schedule timestamp implications, anti-forensic shadow-copy deletion as an attacker technique) beyond the COW/VSS recovery angle covered here.

## Resources

- Eric Zimmerman's tools (MFTECmd, RBCmd, bstrings) — https://ericzimmerman.github.io/
- The Sleuth Kit (`istat`, `icat`, `fls`, `tsk_recover`) — https://www.sleuthkit.org/sleuthkit/
- Microsoft Learn — How NTFS Works: https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
