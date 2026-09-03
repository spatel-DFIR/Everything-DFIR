# NTFS Deep Dive Overview

Every note in this folder assumes one mental model is already loaded: **NTFS is a database, not a chain.** An analyst who carries over the older FAT mental model — "find the first cluster, follow the chain link by link" — will misread almost everything that follows, from why a fragmented file is still trivial to parse, to why a deleted file's metadata can outlive its data, to why a single 1024-byte record is worth opening in a hex editor before any tool touches it. This note is the map: the mental model, where the database physically sits on the volume, how to visually recognize its rows in a hex editor, what each note in this folder answers, and which tools this family of artifacts actually requires — because it is not the PowerShell-first family the rest of `Windows/` is.

> 🔴 **NTFS has no file allocation chain to walk.** FAT tracks a file as a linked list of cluster entries in the File Allocation Table — to read the file, you follow pointers cluster to cluster until you hit an end-of-chain marker. NTFS instead gives every file and folder one row in a central table (the $MFT) and describes where its data lives as a small set of **data runs** — compact (start-cluster, length) pairs. There is no chain to walk and nothing to reconstruct link by link; the row itself already knows where all its data is, contiguous or not.

## Contents

- [The Core Mental Model: Database vs Chain](#the-core-mental-model-database-vs-chain)
- [Where the $MFT Sits on a Volume](#where-the-mft-sits-on-a-volume)
- [NTFS Metadata Files](#ntfs-metadata-files)
- [MFT Attribute Types (Full Reference)](#mft-attribute-types-full-reference)
- [The MFT Zone and Fragmentation](#the-mft-zone-and-fragmentation)
- [Hex-Editor Primer: Recognizing a Record Boundary](#hex-editor-primer-recognizing-a-record-boundary)
- [Folder Map](#folder-map)
- [Tool Roster](#tool-roster)
- [How to Use This Folder](#how-to-use-this-folder)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Core Mental Model: Database vs Chain

| | FAT (chain model) | NTFS (database model) |
|---|---|---|
| Core structure | The **File Allocation Table** — one table entry per cluster on the volume | The **Master File Table ($MFT)** — one **record** per file/folder on the volume |
| How a file's data is located | A directory entry points to the file's *first* cluster; that FAT entry points to the *next* cluster, which points to the next, and so on until an end-of-chain marker | The file's $MFT record lists its **data runs** — a short set of (starting cluster, run length) pairs describing every extent of the file's data, fragmented or not, in one place |
| Cost of fragmentation | Every fragment adds another link that must be walked in sequence to reach the end of the file | Fragmentation just adds another data-run entry to the same record — no sequential walk required, the record already enumerates every extent |
| What "no exceptions" means | N/A — FAT has no comparable self-describing structure | Literally every file and folder on the volume gets an $MFT record, **including NTFS's own metadata files** ($MFT describes itself, $Bitmap, $LogFile, etc. — see [NTFS Metadata Files](#ntfs-metadata-files) below) |
| Forensic consequence | Deleted-file recovery on FAT depends on the chain surviving intact — break one link and the rest is unreachable without carving | Deleted-file recovery on NTFS can succeed even after the chain concept is irrelevant — a freed but unreused $MFT record still holds the full row: name, timestamps, security descriptor, and the data runs needed to pull the content back (see 07 in this folder) |

🔴 **This is the single idea to internalize before opening note 01.** Once "the $MFT is a database of rows, not a chain of links" is second nature, every subsequent structural detail in this folder — resident vs non-resident $DATA, B-tree directory indexes, journal replay — reads as a natural extension of "how does a database row describe itself and its contents," not a pile of unrelated trivia.

This pairing — **MFT's "data run"** vs **FAT's "chain"** — is the opening idea for the whole folder. Every other structural fact downstream (attributes, resident data, directory indexes, journaling) is really just "what else does a database row need to carry to fully describe a file."

## Where the $MFT Sits on a Volume

The $MFT is itself just record 0 of the table it describes — the very first thing an analyst needs is *how to find it* before parsing what's inside it.

| Question | Answer |
|---|---|
| What points to the $MFT's starting location? | `$Boot` — the volume boot sector stores the starting cluster of the $MFT (and of `$MFTMirr`, its backup) as one of its core fields |
| What keeps the $MFT from fragmenting immediately? | The **MFT Zone** — roughly 12.5% of the volume reserved immediately after the $MFT, kept off-limits to ordinary file data specifically so the table has room to grow. Full mechanics and DFIR implications are in [The MFT Zone and Fragmentation](#the-mft-zone-and-fragmentation) below. |
| Where do the first 16 records live? | Records 0–15 are reserved by convention for NTFS's own metadata files ($MFT, $MFTMirr, $LogFile, $Volume, $AttrDef, the root directory, $Bitmap, $Boot, $BadClus, $Secure, $UpCase, $Extend, and a few reserved slots after that) — the full roster with DFIR relevance per file is in [NTFS Metadata Files](#ntfs-metadata-files) below |
| Where do ordinary files start? | Record 16 onward, assigned sequentially as files are created; a freed record from a deleted file is reused before the table grows |

## NTFS Metadata Files

Records 0–15 aren't reserved arbitrarily — each holds one of NTFS's own bookkeeping files, and each of those files has its own forensic weight:

| File | Purpose | DFIR relevance |
|---|---|---|
| **$MFT** | The Master File Table itself — one 1KB (default) record per file/folder on the volume, holding all attributes ($SI, $FN, $DATA, security descriptor, etc.) | The single richest structured artifact on a Windows disk — every file/folder that ever existed (including deleted-but-not-yet-overwritten entries) has a record here. Parse with **MFTECmd** (Eric Zimmerman) or **MFT Explorer**. |
| **$MFTMirr** | A partial backup copy of the first few critical $MFT records (traditionally 4, more on modern volumes) | Recovery source if the primary $MFT's first records are corrupted; rarely an active analysis target but confirms $MFT integrity when compared against it |
| **$LogFile** | NTFS's own transaction journal (metadata journaling for crash consistency, not a user-facing "recent files" log) | Contains recent *metadata* operations (renames, attribute changes, some content-length changes) even after the corresponding $MFT record has been reused — a recovery source for very recent filesystem activity, including some anti-forensic/timestomping detection (values here can contradict a doctored $SI). Full depth: `05 - $LogFile (NTFS Transaction Journal).md`. |
| **$Volume** | Volume name, NTFS version, and the dirty-bit flag | Dirty bit indicates the volume wasn't cleanly unmounted (unexpected shutdown/crash) — minor but sometimes relevant corroboration for an incident timeline |
| **$AttrDef** | Defines the attribute types valid on this volume and their rules | Rarely inspected directly; underlies how forensic tools know how to parse $MFT attributes at all |
| **. (root directory)** | MFT record 5 — the volume's root directory, populated at format time like the other reserved records above, not merely an empty reserved slot | Anchors the entire directory namespace; parsed the same way as any ordinary directory via `$INDEX_ROOT`/`$INDEX_ALLOCATION` (see `04 - $I30 Directory Index and B-Trees.md`) — worth checking directly when tracing a path back to volume root or investigating root-level persistence artifacts |
| **$Bitmap** | One bit per cluster on the volume — tracks allocated vs free clusters | Directly drives carving strategy: "free" clusters per $Bitmap are the search space for unallocated-space carving (PhotoRec, `foremost`, Autopsy's unallocated-space module) |
| **$Boot** | The volume's boot sector (extended, NTFS-specific) — cluster size, MFT location, volume serial number (VSN) | The VSN here is the same value stamped into LNK files and Jump Lists, letting an examiner correlate "this LNK points to a file on removable media" back to a specific volume even after the drive letter changed |
| **$BadClus** | Tracks clusters marked bad/unusable by the filesystem | Low forensic value directly, but an unusually large bad-cluster list on an otherwise healthy disk is worth a second look (anti-forensic sector-damage claims, hardware failure cover stories) |
| **$Secure** | Central store of security descriptors (permissions/ACLs), deduplicated and shared across files that have identical permissions | Useful when investigating permission changes across many files at once — a shared $Secure entry means many files' ACLs moved together |
| **$UpCase** | Uppercase-mapping table used for case-insensitive filename comparison | Structural-only, essentially never a direct analysis target |
| **$Extend** | A directory holding optional/advanced NTFS features when enabled | Holds `$Extend\$Quota`, `$Extend\$ObjId`, `$Extend\$Reparse`, and (**Windows 10 1809+**) `$Extend\$UsrJrnl` — the **USN Change Journal**, a rolling log of file/folder create-rename-delete-modify events per volume, one of the strongest available correlation sources against $MFT timestamps and a primary anti-forensic-detection artifact. Full depth: `06 - $UsnJrnl (USN Change Journal).md`. |

## MFT Attribute Types (Full Reference)

Every record described above ([NTFS Metadata Files](#ntfs-metadata-files) and every ordinary file/folder record alike) is really just a shell holding a sequence of typed attributes. This is the full attribute-type roster with a plain DFIR-relevance verdict per row — byte-level field layout, resident-vs-non-resident mechanics, and the `$ATTRIBUTE_LIST` overflow case are note 01's job; see [01 - MFT Entry Structure and Attributes](01%20-%20MFT%20Entry%20Structure%20and%20Attributes.md#common-attribute-types) for that deep dive.

| Type code | Name | One-line purpose | DFIR relevance |
|---|---|---|---|
| 0x10 | $STANDARD_INFORMATION | Core file metadata — the $SI timestamp set, DOS attributes, owner/security IDs | High — the primary timestamp/attribute artifact and one half of the $SI-vs-$FN timestomping check |
| 0x20 | $ATTRIBUTE_LIST | Index of where a record's attributes actually live when they've spilled into extension records | High — its presence or absence determines whether a base-record-only parse actually saw everything |
| 0x30 | $FILE_NAME | Filename, parent directory reference, and the $FN timestamp set — one instance per hard link/name | High — the other half of the $SI-vs-$FN timestomping check, and the only attribute carrying the parent directory reference |
| 0x40 | $OBJECT_ID | A unique 128-bit ID for the file, used by Distributed Link Tracking to follow a file across moves/renames | Medium — occasionally useful for correlating a file across moves/renames, but rarely central to a finding on its own |
| 0x50 | $SECURITY_DESCRIPTOR | Legacy inline permissions/ACL storage (modern NTFS usually references a shared entry in `$Secure` instead) | Low — modern volumes resolve this through $Secure instead; occasionally relevant to permission-change investigations |
| 0x60 | $VOLUME_NAME | The volume's label — present only in the `$Volume` metadata file's own record | Low — cosmetic, appears once per volume |
| 0x70 | $VOLUME_INFORMATION | NTFS version and the dirty-bit flag — also only in `$Volume`'s record | Low — minor corroboration only (dirty bit can support an unexpected-shutdown narrative) |
| 0x80 | $DATA | The file's actual content — resident or non-resident | High — the actual evidentiary content of the file |
| 0x90 | $INDEX_ROOT | The root of a directory's B-tree index (small directories fit entirely here) — part of the $I30 structure | High — directory contents, including recoverable deleted-entry remnants |
| 0xA0 | $INDEX_ALLOCATION | Overflow B-tree index nodes for directories too large for $INDEX_ROOT alone | High — same directory-content value as $INDEX_ROOT, just for larger directories |
| 0xB0 | $BITMAP | Tracks which entries/nodes in an associated index are in use — accompanies $INDEX_ALLOCATION on larger directories | Medium — a supporting structure for index parsing/carving, rarely a direct analysis target itself |
| 0xC0 | $REPARSE_POINT | Holds reparse data for symbolic links, junctions, and mount points | Medium — relevant when symlinks/junctions are used for redirection-based persistence or evasion |
| 0xD0 | $EA_INFORMATION | Size/count metadata for OS/2-style extended attributes, kept for legacy HPFS/OS-2 subsystem compatibility | Low — rarely populated on modern Windows volumes; exists mainly for legacy compatibility and is almost never itself a finding |
| 0xE0 | $EA | The actual OS/2-style extended attribute key/value data, paired with $EA_INFORMATION above | Low — same OS/2-compatibility path as $EA_INFORMATION; essentially never present or meaningful on a modern Windows disk, though its rare presence is itself worth a second look |
| 0xF0 | $PROPERTY_SET | An NT-era mechanism tied to OLE/COM property sets | Low — Microsoft's own [MS-FSCC] reference lists this attribute as flatly "Obsolete"; not expected to be populated or forensically meaningful on any modern volume |
| 0x100 | $LOGGED_UTILITY_STREAM | Holds data for NTFS features that need their own logged stream, most notably EFS (Encrypting File System) metadata | Medium — relevant specifically when investigating encrypted files, otherwise rarely inspected |
| 0xFFFFFFFF | *(end-of-attributes marker)* | Not a real attribute — the 4-byte sentinel value that closes a record's attribute sequence | Structural only, not a real attribute — nothing to inspect, but its presence confirms the attribute sequence parsed to a valid end |

## The MFT Zone and Fragmentation

NTFS reserves roughly **12.5% of the volume** immediately following the $MFT as the **MFT Zone** — empty space kept off-limits to ordinary file data specifically so the $MFT itself has room to grow without immediately fragmenting across the disk.

| Why it exists | DFIR consequence |
|---|---|
| The $MFT grows continuously as files are created and is rarely shrunk back down even after mass deletion | If the MFT Zone fills (heavy file creation, near-full volume), NTFS is forced to let ordinary user data allocate *inside* the reserved zone, and further $MFT growth then fragments across the disk in pieces |
| A fragmented $MFT is still fully parseable by MFT-aware tools (MFTECmd resolves fragments transparently) | Fragmentation is more a performance/carving-difficulty signal than a data-loss risk — but a heavily fragmented $MFT is circumstantial evidence the volume was run near-full or under heavy churn (mass deletion/creation), which itself can corroborate anti-forensic wiping activity or simply an old, heavily used disk |
| MFT records for deleted files are marked free and reused, but not zeroed | The MFT Zone's spare capacity is exactly where **orphaned/deleted-file $MFT records survive** longest before being overwritten by a new file's record — a nearly-full MFT Zone means less runway before deleted-file metadata is gone for good |

## Hex-Editor Primer: Recognizing a Record Boundary

Before any parser touches a raw `$MFT` extract (pulled via FTK Imager's "Export Special Files," carved from an image, or copied off a mounted volume with a tool that can read locked system files), an analyst should be able to open it in a hex editor and immediately recognize where one record ends and the next begins by eye. Note 01 owns the full field-by-field walkthrough — this is only the visual anchor.

| What to look for | Detail |
|---|---|
| Record signature | The ASCII bytes `FILE0` or `FILE*` at offset 0 of every valid record — visually the first thing that should jump out scrolling through a raw $MFT dump |
| `FILE0` vs `FILE*` | `FILE0` = a normal, healthy record; `FILE*` (literal asterisk) = the record's fixup values didn't verify — usually a sign of a torn/partial read of that sector, not necessarily corruption of the actual file data |
| Record size | 1024 bytes by default since Windows XP (older/rare volumes formatted at 512 or 4096) — once the signature is found, the next one should appear exactly one record-size later if the extract is contiguous |
| Fastest way to eyeball record count | File size of the raw extract ÷ record size — a 100 MB `$MFT` extract at the 1024-byte default is roughly 100,000 records, a quick sanity check against what a parser later reports |
| Quick scan technique | Search the hex editor for the ASCII string `FILE` — every hit at a record-size-aligned offset is a record boundary; hits that aren't aligned are false positives inside record content (e.g. a filename or path string that happens to contain those bytes) |
| What comes right after the signature | The rest of the fixed record header (sequence number, hard-link count, offset to first attribute, flags including the in-use/allocated bit) — full field layout is note 01's job, not this one |

🔴 Getting comfortable finding `FILE0` by eye matters beyond curiosity — it's the same skill used to manually locate and re-carve an orphaned or partially-overwritten $MFT record when automated parsers choke on a damaged extract.

## Folder Map

| # | Note | What it answers |
|---|---|---|
| 00 | *This note* | What's the mental model, where does the $MFT live, how do I recognize a record in hex, and which tools does this family need? |
| 01 | MFT Entry Structure and Attributes | What does one full $MFT record look like byte-for-byte — header, sequence numbers, attribute list, allocated vs unallocated records — and how does `istat` surface all of it without a hex editor? |
| 02 | $STANDARD_INFORMATION and $FILE_NAME Attributes | What fields exist inside $SI and $FN at the byte level, and how does their structural layout explain the timestomping detection technique 03 already covers behaviorally? |
| 03 | $DATA Attribute and Resident vs Non-Resident Files | When does file content live directly inside the $MFT record itself (resident) versus out in data runs on disk (non-resident), and how do I pull either back out with `icat`? |
| 04 | $I30 Directory Index and B-Trees | How does NTFS store a folder's contents as a searchable B-tree index instead of a flat list, and what does a deleted directory entry look like inside $I30? |
| 05 | $LogFile (NTFS Transaction Journal) | What does NTFS's own crash-consistency journal record, and how far back can recent metadata operations be recovered from it after the $MFT record itself has changed? |
| 06 | $UsnJrnl (USN Change Journal) | What does the separate, longer-lived change journal record about file/folder create-rename-delete-modify events, and how do I filter and search it for a specific activity pattern? |
| 07 | File Deletion Mechanics | Pulling 01–06 together — exactly what changes, what doesn't, and what survives (record, index entry, journal entries, data runs) at each stage from Recycle Bin deletion through record reuse? |

Read 00→07 in order the first time through — each note leans on the one before it. After that, use this table as the index back into whichever structure is relevant to the artifact in front of you.

## Tool Roster

🔴 **This is a Sleuth-Kit-and-Eric-Zimmerman-tool-first family, not a PowerShell-first one.** The rest of `Windows/` defaults to native PowerShell wherever possible; this folder mostly can't, because raw $MFT/$LogFile/$UsnJrnl binary structure sits below what any native cmdlet reaches. Note 02 already flags this exact boundary for $SI — see its [PowerShell](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md#powershell) subsection under the timestamp section: `Get-Item`/`Get-ItemProperty` only ever surface $STANDARD_INFORMATION, never $FILE_NAME, and nothing native parses $LogFile or $UsnJrnl records at all. Every note in this folder leads with TSK/EZ commands accordingly; PowerShell appears only where something is genuinely natively reachable (e.g. `fsutil usn queryjournal` for a live $UsnJrnl read).

| Tool | Form | Primary artifact | Note |
|---|---|---|---|
| **The Sleuth Kit — `istat`** | CLI | $MFT record (any single record, by number) | Prints a full parsed record — header, $SI/$FN timestamps, attribute list, data runs — directly from an image or raw device, no extraction step needed |
| **The Sleuth Kit — `icat`** | CLI | $DATA content of a given $MFT record | Extracts a file's actual content by inode/record number, works whether the data is resident or non-resident |
| **The Sleuth Kit — `fsstat`** | CLI | Volume-level NTFS metadata | Dumps boot-sector-level facts (cluster size, $MFT location, volume serial number) — the volume-wide counterpart to `istat`'s single-record view |
| **The Sleuth Kit — `fls`** | CLI | Directory listings, including deleted entries | Lists file/directory names and their record numbers straight from $I30 structures, including entries marked deleted |
| **The Sleuth Kit — `mmls`** | CLI | Partition table / volume layout | Not NTFS-specific, but the usual first step before any of the above — confirms partition offsets so `istat`/`icat`/`fls` target the right volume |
| **MFTECmd** (Eric Zimmerman) | CLI | $MFT, $J (USN journal) | High-volume bulk parser — converts an entire $MFT or journal to CSV/JSON for timeline pivoting, rather than inspecting one record at a time like `istat`. 🔴 Does **not** parse `$LogFile` (verified against the tool's own source, which exits with "not supported yet" for that input) — use **LogFileParser** below for that artifact. |
| **Indx2Csv** | CLI | $I30 directory index | Parses $I30 index buffers (including slack/deleted entries) to CSV; verify exact flag names against the tool's current `--help` output before relying on a specific switch |
| **Velociraptor** | Agent/CLI, collection + parsing | $I30, $MFT, $UsnJrnl, and broad NTFS artifact collection at scale | Runs equivalent parsing logic across a fleet via VQL artifacts rather than one host at a time — the estate-wide complement to single-host TSK/EZ tools |
| **LogFileParser** (Joakim Schicht) | CLI | $LogFile | Purpose-built $LogFile transaction parser — decodes NTFS's internal redo/undo log records into a readable operation history; verify current flag names/output format against the tool's own documentation, as it's a smaller, less standardized project than the EZ suite |
| **KAPE** | CLI/GUI, triage collection | Feeds all of the above | Targets exist to collect raw $MFT/$LogFile/$J off a live or imaged host; modules chain straight into MFTECmd/Indx2Csv/LogFileParser as part of one triage pass, mirroring how KAPE is used elsewhere in this repo |

## How to Use This Folder

On a first pass, read 00 through 07 in numeric order — each note assumes the structural vocabulary built in the ones before it, and 07 specifically only makes sense once 01–06 have each been covered. After that first pass, treat the folder as a reference: jump straight to whichever note matches the structure in front of you (a hex dump needing field identification → 01 or 02; a file whose content needs pulling → 03; a directory listing showing deleted entries → 04; a metadata-operation history needed past what $MFT alone shows → 05 or 06; a "what actually happened when this got deleted" question → 07). This folder (00–07) is fully self-contained for NTFS structural and behavioral depth — the metadata-file roster and MFT Zone mechanics live in this note, MACE/MACB timestamp behavior is covered in note 02, and $DATA/ADS/Zone.Identifier material is covered in note 03; there's no need to keep a separate file open alongside.

## Correlate With

| To go deeper on… | Open |
|---|---|
| MACE/MACB timestamp behavior by operation | `02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md` |
| ADS and Zone.Identifier / MOTW | `03 - $DATA Attribute and Resident vs Non-Resident Files.md` |
| How $MFT/$LogFile/$UsnJrnl evidence corroborates registry-based persistence and object timestamps | `Windows/04 - Registry Forensics` |
| Deliberate timestamp manipulation, journal tampering, and shadow-copy/log destruction techniques that target the structures this folder describes | `Windows/19 - Anti-Forensics and Evidence Destruction` |
| Building a full cross-artifact timeline once $MFT/$LogFile/$UsnJrnl data has been extracted | `Windows/18 - Timeline Analysis` |

## Resources

- SANS FOR508 "Hunt Evil" / Advanced Incident Response poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- The Sleuth Kit documentation — https://wiki.sleuthkit.org/
- Eric Zimmerman's tools (MFTECmd and the wider suite) — https://ericzimmerman.github.io/
- Velociraptor documentation — https://docs.velociraptor.app/
