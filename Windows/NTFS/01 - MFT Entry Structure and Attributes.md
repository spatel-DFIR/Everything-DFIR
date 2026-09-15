# MFT Entry Structure and Attributes

Note 00 gave the mental model — the $MFT is a database, every file and folder gets one row, and a row describes its data with **data runs** instead of a FAT-style chain. This note opens that row. Every subsequent note in this folder ($SI/$FN in 02, $DATA in 03, $I30 in 04) is really just "what does this one field, inside this one record, actually contain" — this note is the record shell that holds all of them: the fixed-size envelope, the header fields, the attribute sequence, and the single tool (`istat`) that turns all of it into readable text without ever opening a hex editor.

> 🔴 **A naive single-record read can silently miss data.** A record is a fixed 1024 bytes. A file with enough attributes — heavy fragmentation, many alternate data streams, a long security history — can outgrow that space, and NTFS spills the overflow into separate **extension records** that a base-record-only parse never visits. Always check for an `$ATTRIBUTE_LIST` before trusting that one record told the whole story.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [NTFS Features: The MFT Record as the Atomic Unit](#ntfs-features-the-mft-record-as-the-atomic-unit)
- [Sequential MFT Entries: Allocation, Sequence Numbers, and the FRN](#sequential-mft-entries-allocation-sequence-numbers-and-the-frn)
- [Anatomy of an MFT Entry in a Hex Editor](#anatomy-of-an-mft-entry-in-a-hex-editor)
- [Common Attribute Types](#common-attribute-types)
- [The $ATTRIBUTE_LIST Special Case](#the-attribute_list-special-case)
- [The Sleuth Kit's istat Tool](#the-sleuth-kits-istat-tool)
- [MFTECmd for Bulk $MFT Parsing to CSV](#mftecmd-for-bulk-mft-parsing-to-csv)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

TSK/native one-liners for a fast triage pass against an image or a live host — no hex editor, no Eric Zimmerman GUI required. `<offset>` is the partition's starting sector (get it from `mmls <image>` first); `<inode>` is the $MFT record number.

```bash
# Full parsed dump of one MFT record - the single most useful command in this note (see istat section below)
istat -o <offset> <image> <inode>

# List a directory's contents including entries marked deleted (unallocated) but not yet reused - fastest way to find an inode worth istat-ing
fls -o <offset> -d <image> <parent-inode>

# Same, recursively across the whole volume - broad sweep for orphaned/deleted metadata
fls -o <offset> -r -d <image>

# Pull just the sequence number and allocation status for a fast reuse check against a stale FRN found elsewhere (LNK target, $LogFile, a prior report)
istat -o <offset> <image> <inode> | head -5
```

```powershell
# Native, live-host equivalent for volume-level NTFS facts (record size, MFT location, cluster size) - not a per-record view, but confirms the assumptions the rest of this note relies on before reasoning about a specific record
fsutil fsinfo ntfsinfo C:
```

**Representative `mmls <image>` output** (illustrative — hand-assembled to show the shape of a typical partition table listing, not a literal capture from a specific image):

```
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

     Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -----     0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0002099199   0002097152   NTFS (0x07)
```

The `Start` value of the NTFS partition row (`2048` here) is the `<offset>` every other TSK command in this note needs.

**Representative `fsstat -o <offset> <image>` output** (illustrative, trimmed to the fields this note relies on):

```
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: NTFS
Volume Serial Number: 0A1B2C3D4E5F6789

METADATA INFORMATION
--------------------------------------------
First Cluster of MFT: 786432
First Cluster of MFT Mirror: 2
Size of MFT Entries: 1024 bytes
Size of Index Records: 4096 bytes

CONTENT INFORMATION
--------------------------------------------
Sector Size: 512
Cluster Size: 4096
```

This is the volume-wide counterpart to `istat`'s single-record view — confirms record size, cluster size, and MFT location before reasoning about any specific record below.

🔴 `fls`/`istat` flags shown here are the common case — always confirm the exact flag set (`-z <timezone>`, `-f <fstype>`, output format switches) against `istat -h`/`fls -h` for the TSK version actually installed; flag names have shifted slightly across TSK major versions.

## NTFS Features: The MFT Record as the Atomic Unit

Every file and folder on an NTFS volume is described by exactly one **MFT record** — a fixed-size slot in the $MFT table. That fixed size is the first constraint everything else in this note works around.

| Fact | Detail |
|---|---|
| Default record size | **1024 bytes (1 KB)**, set at format time (older or unusual volumes may use 512 or 4096 — confirm with `fsstat`/`fsutil fsinfo ntfsinfo` rather than assuming) |
| Fixed record header | A constant-layout block at the start of every record (signature, fixup array, sequence number, flags, etc. — full field table below) — consumes a portion of the 1024 bytes before any attribute data begins |
| Usable space for attributes | Roughly **600-and-some bytes** after the header, fixup array, and end marker overhead — the exact figure varies slightly by record size and fixup-array length, but this is the budget every attribute (and its content, if resident) has to fit inside |
| **Resident** attribute data | Small attribute content stored **directly inside the record itself**, in that ~600-byte budget — no separate disk read needed to retrieve it |
| **Non-resident** attribute data | Attribute content too large for the record is stored **elsewhere in clusters** on the volume; the record instead holds a **data run** — a compact, run-length-encoded list of (starting cluster, run length) pairs describing every extent of that data |

One sentence of contrast worth internalizing here — full treatment lives in [00's core mental-model table](00%20-%20NTFS%20Deep%20Dive%20Overview.md#the-core-mental-model-database-vs-chain): a **data run** is a short, self-contained list the record already carries describing where all of its data lives, fragmented or not, while a FAT **chain** is a linked list of File Allocation Table entries that has to be walked link by link to reach the end of the file.

Resident-vs-non-resident is $DATA's own deep-dive topic — see [03 - $DATA Attribute and Resident vs Non-Resident Files](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md) for the size threshold, forensic implications, and `icat` extraction. This note's job is only the record-level mechanism that makes resident/non-resident possible.

## Sequential MFT Entries: Allocation, Sequence Numbers, and the FRN

Records are assigned **sequentially** — the next file or folder created on the volume gets the next available record number, whether that's a genuinely new slot at the end of the table or a freed slot left behind by an earlier deletion.

| Concept | Detail |
|---|---|
| Allocated vs unallocated | A single **in-use flag** inside the record header's flags field marks whether the record currently describes a live file/folder (**allocated**) or has been freed (**unallocated**) |
| What deletion actually does to the record | Flips the in-use flag to unallocated — it does **not** zero the record's bytes. The $SI/$FN/$DATA content, timestamps, and (if resident) file data all survive intact until something else reuses that record number |
| Sequence number | A field in the record header that **increments by one every time that record slot is reused** by a new file/folder after a deletion |
| **File Reference Number (FRN)** | Record number + sequence number, combined. The record number alone identifies a *slot*; the sequence number confirms *which occupant* of that slot is being referenced |

🔴 **Why the FRN matters forensically:** plenty of artifacts elsewhere on the volume — a directory's own index entries, a $LogFile transaction, a prior tool's report, even a stale reference cached inside another record — point at a target using a full FRN, not just a bare record number. If the sequence number in that stale reference doesn't match the sequence number currently in the record, the slot has been reused since that reference was written — the file being pointed at is **not** the file that currently occupies that record number. Checking sequence numbers is the standard way to catch this before misattributing evidence to the wrong file.

## Anatomy of an MFT Entry in a Hex Editor

Macro-layout first — the order these pieces appear in every valid record, signature to end marker:

```
Offset 0x000  ┌─────────────────────────────────────┐
              │  Signature: "FILE0" / "FILE*"  (4B)  │
              ├─────────────────────────────────────┤
              │  Fixed record header (~42-48B)       │
              │  (sequence #, flags, sizes, etc.)    │
              ├─────────────────────────────────────┤
              │  Update Sequence Array (fixup)        │
              │  (variable, small - a few bytes)      │
              ├─────────────────────────────────────┤
              │  Attribute 1  (header + content)      │
              ├─────────────────────────────────────┤
              │  Attribute 2  (header + content)      │
              ├─────────────────────────────────────┤
              │  ...                                  │
              ├─────────────────────────────────────┤
              │  End marker: 0xFFFFFFFF               │
              ├─────────────────────────────────────┤
              │  (unused padding to fill the record)  │
Offset 0x3FF  └─────────────────────────────────────┘
                        1024 bytes total (default)
```

Header field layout — this is the standard NTFS 3.1 layout; treat exact offsets as typical rather than gospel, and lean on `istat`'s parsed output (below) instead of hand-counting bytes whenever precision actually matters for a finding:

| Offset | Field | Size | Meaning |
|---|---|---|---|
| 0x00 | Signature | 4 bytes | `FILE0`/`FILE*` (or a plain `FILE` variant) — marks this as a valid record; `BAAD` or garbage here means a corrupted or overwritten record |
| 0x04 | Update Sequence Array offset | 2 bytes | Where the fixup array (below) is located within this record |
| 0x06 | Update Sequence Array size | 2 bytes | Number of fixup values present |
| 0x08 | $LogFile Sequence Number (LSN) | 8 bytes | The last $LogFile transaction that touched this record — ties the record to journal history (see note 05) |
| 0x10 | Sequence number | 2 bytes | Increments on every reuse of this record slot — half of the FRN, see above |
| 0x12 | Hard link count | 2 bytes | Number of directory entries (parent folders) referencing this record |
| 0x14 | Offset to first attribute | 2 bytes | Where attribute parsing begins, right after the fixup array |
| 0x16 | Flags | 2 bytes | Low bits include the in-use/allocated flag and a directory flag |
| 0x18 | Used size of record | 4 bytes | Actual bytes occupied by header + attributes + end marker |
| 0x1C | Allocated size of record | 4 bytes | Total record size, normally 1024 |
| 0x20 | Base record file reference | 8 bytes | Zero for a base record; for an **extension record**, the FRN of the base record it belongs to (see $ATTRIBUTE_LIST below) |
| 0x28 | Next attribute ID | 2 bytes | Counter used to assign the next new attribute's ID within this record |
| 0x2C | MFT record number | 4 bytes | This record's own number (NTFS 3.1+) — a self-reference, useful for sanity-checking a carved/orphaned record |

**Why the fixup array exists:** a 1024-byte record spans two 512-byte disk sectors, but Windows only guarantees atomic writes at the sector level, not across a whole record. Before writing, NTFS stashes the true last two bytes of each sector inside the fixup array and stamps a shared marker value (the **Update Sequence Number**) in their place. On read, a parser checks that every sector's stamped marker matches, then swaps the fixup array's saved bytes back in. A mismatch means only some of the record's sectors were actually written to disk — a **torn/partial write** — and is exactly what produces the `FILE*` signature variant instead of a clean `FILE0`.

**Attributes**, once parsing reaches the offset from 0x14, are each a self-contained unit: a small attribute header (type code, total length, a resident/non-resident flag, and an optional attribute name for named streams like ADS) followed immediately by that attribute's own content — resident data inline, or a data-run list if non-resident. The record's attribute sequence is closed by a 4-byte **end marker, `0xFFFFFFFF`**, with any remaining space to the record boundary left as padding.

## Common Attribute Types

The record shell above is generic — what actually makes a file a file is the specific attributes present. This table is the index; content-level detail for $SI/$FN/$DATA/$I30 lives in their own notes rather than here.

| Type code | Name | One-line purpose | DFIR relevance |
|---|---|---|---|
| 0x10 | $STANDARD_INFORMATION | Core file metadata — the $SI timestamp set, DOS attributes, owner/security IDs. Deep dive: [02](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md) | High — the primary timestamp/attribute artifact and one half of the $SI-vs-$FN timestomping check |
| 0x20 | $ATTRIBUTE_LIST | Index of where a record's attributes actually live when they've spilled into extension records — see below | High — its presence or absence determines whether a base-record-only parse actually saw everything |
| 0x30 | $FILE_NAME | Filename, parent directory reference, and the $FN timestamp set — one instance per hard link/name. Deep dive: [02](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md) | High — the other half of the $SI-vs-$FN timestomping check, and the only attribute carrying the parent directory reference |
| 0x40 | $OBJECT_ID | A unique 128-bit ID for the file, used by Distributed Link Tracking to follow a file across moves/renames on NTFS volumes that support it | Medium — occasionally useful for correlating a file across moves/renames, but rarely central to a finding on its own |
| 0x50 | $SECURITY_DESCRIPTOR | Legacy inline permissions/ACL storage (modern NTFS usually references a shared entry in `$Secure` instead — see note 00's [NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table) | Low — modern volumes resolve this through $Secure instead; occasionally relevant to permission-change investigations |
| 0x60 | $VOLUME_NAME | The volume's label — present only in the `$Volume` metadata file's own record | Low — cosmetic, appears once per volume |
| 0x70 | $VOLUME_INFORMATION | NTFS version and the dirty-bit flag — also only in `$Volume`'s record | Low — minor corroboration only (dirty bit can support an unexpected-shutdown narrative) |
| 0x80 | $DATA | The file's actual content — resident or non-resident. Deep dive: [03](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md) | High — the actual evidentiary content of the file |
| 0x90 | $INDEX_ROOT | The root of a directory's B-tree index (small directories fit entirely here) — part of the $I30 structure. Deep dive: [04](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md) | High — directory contents, including recoverable deleted-entry remnants |
| 0xA0 | $INDEX_ALLOCATION | Overflow B-tree index nodes for directories too large for $INDEX_ROOT alone. Deep dive: [04](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md) | High — same directory-content value as $INDEX_ROOT, just for larger directories |
| 0xB0 | $BITMAP | Tracks which entries/nodes in an associated index are in use — accompanies $INDEX_ALLOCATION on larger directories | Medium — a supporting structure for index parsing/carving, rarely a direct analysis target itself |
| 0xC0 | $REPARSE_POINT | Holds reparse data for symbolic links, junctions, and mount points | Medium — relevant when symlinks/junctions are used for redirection-based persistence or evasion |
| 0xD0 | $EA_INFORMATION | Size/count metadata for OS/2-style extended attributes, kept for legacy HPFS/OS-2 subsystem compatibility | Low — rarely populated on modern Windows volumes; exists mainly for legacy compatibility and is almost never itself a finding |
| 0xE0 | $EA | The actual OS/2-style extended attribute key/value data, paired with $EA_INFORMATION above | Low — same OS/2-compatibility path as $EA_INFORMATION; essentially never present or meaningful on a modern Windows disk, though its rare presence is itself worth a second look |
| 0xF0 | $PROPERTY_SET | An NT-era mechanism tied to OLE/COM property sets | Low — Microsoft's own [MS-FSCC] reference lists this attribute as flatly "Obsolete"; not expected to be populated or forensically meaningful on any modern volume |
| 0x100 | $LOGGED_UTILITY_STREAM | Holds data for NTFS features that need their own logged stream, most notably EFS (Encrypting File System) metadata | Medium — relevant specifically when investigating encrypted files, otherwise rarely inspected |
| 0xFFFFFFFF | *(end-of-attributes marker)* | Not a real attribute — the 4-byte sentinel value that closes a record's attribute sequence (see [Anatomy of an MFT Entry](#anatomy-of-an-mft-entry-in-a-hex-editor) above) | Structural only, not a real attribute — nothing to inspect, but its presence confirms the attribute sequence parsed to a valid end |

## The $ATTRIBUTE_LIST Special Case

A single 1024-byte record has a hard ceiling on how many attributes (and how much resident content) it can hold. A file that's heavily fragmented (long non-resident $DATA data-run lists), carries many alternate data streams, or has accumulated a long attribute history can exceed that ceiling.

When that happens, NTFS doesn't grow the base record — it spills the overflow into one or more **extension records** elsewhere in the $MFT (each pointing back to the base record via the base-record-reference field at header offset 0x20), and adds a **$ATTRIBUTE_LIST** attribute (type 0x20) to the base record that indexes every attribute the file actually has and which record — base or extension — each one physically lives in.

🔴 **Forensic relevance:** a tool or analyst that reads only the base record and stops has no way to know extension records exist unless it checks for $ATTRIBUTE_LIST first. Skipping that check means silently missing whatever attribute content — often additional $DATA runs or ADS — was pushed into the extension record(s).

## The Sleuth Kit's istat Tool

`istat` is The Sleuth Kit's single-metadata-structure inspector — point it at an image (or raw device) and one inode/record number, and it prints a fully parsed breakdown of that one $MFT record: allocation status, sequence number, link count, both timestamp blocks, and the complete attribute list with resident/non-resident status and data runs. This is the fastest way to get everything covered above in one readable pass, with no hex editor and no manual fixup handling required.

**Step 1 — find the inode of interest.** `istat` needs a specific record number as input, so start with `fls`:

```bash
# List a directory's entries (with record/"inode" numbers) starting from the root - find the record number of the file/folder of interest
fls -o <sector-offset> <image>

# Recursive, and include deleted-but-unallocated entries - the deleted-file-recovery pass
fls -o <sector-offset> -r -d <image>
```

**Step 2 — run istat against that record:**

```bash
istat -o <sector-offset> <image> <inode-number>
```

| Flag | Purpose |
|---|---|
| `-o <sector-offset>` | Partition start offset in sectors — get it from `mmls <image>` first if the image holds a full disk rather than a single partition |
| `-z <timezone>` | Display timestamps in a specific timezone rather than the tool's default |
| `-f <fstype>` | Force a specific filesystem type when auto-detection is ambiguous |

🔴 Hedge deliberately here: the exact flag roster (and any newly added flags) varies by TSK version — confirm the current set with `istat -h` for the installed build before relying on a flag not shown above.

**Representative output** (illustrative — hand-assembled to show the shape and meaning of real `istat` output, not a literal capture from a specific image):

```
MFT Entry Header Values:
Entry: 63625        Sequence: 4
$LogFile/$LSN: 27364583
Allocated File
Links: 1

$STANDARD_INFORMATION Attribute
Flags: Archive
Owner ID: 0
Security ID: 1282
Created:         2026-03-11 14:02:31 (UTC)
File Modified:   2026-03-11 14:02:31 (UTC)
MFT Modified:    2026-03-11 14:02:31 (UTC)
Accessed:        2026-03-11 14:02:31 (UTC)

$FILE_NAME Attribute
Flags: Archive
Name: evil.exe
Parent MFT Entry: 5124    Sequence: 2
Allocated Size: 45056    Actual Size: 44802
Created:         2026-03-11 14:02:31 (UTC)
File Modified:   2026-03-11 14:02:31 (UTC)
MFT Modified:    2026-03-11 14:02:31 (UTC)
Accessed:        2026-03-11 14:02:31 (UTC)

Attributes:
Type: $STANDARD_INFORMATION (16-0)   Name: N/A   Resident    size: 72
Type: $FILE_NAME (48-2)   Name: N/A   Resident    size: 96
Type: $DATA (128-3)   Name: N/A   Non-Resident   size: 44802   init_size: 44802
  1602311-1602319 (10 clusters)
  1650012-1650018 (7 clusters)
```

How to read this: **Entry/Sequence** at the top is the FRN (see above) — cross-check this sequence number against any stale reference to the same entry. **Allocated File** confirms the in-use flag; a deleted-but-not-reused record shows **Not Allocated** here instead. The **$STANDARD_INFORMATION** and **$FILE_NAME** blocks are each their own full four-timestamp set — compare them directly for the $SI-vs-$FN timestomping check (full behavioral and byte-level detail in note 02). The **Attributes** list at the bottom is the record's actual attribute sequence: note the `(128-3)` type-code/instance-ID pairing, the `Resident`/`Non-Resident` flag per attribute, and — critically — the **data run list** under the non-resident $DATA entry, each line a (cluster-range, run-length) pair recoverable directly with `icat` (note 03).

## MFTECmd for Bulk $MFT Parsing to CSV

`istat` is a one-record-at-a-time tool. **MFTECmd** (Eric Zimmerman) is its bulk equivalent — point it at an exported `$MFT` file and it parses every record in one pass into CSV/JSON, the format actually usable for timeline pivoting in Timeline Explorer or a SIEM, rather than one console dump per record. MFTECmd is named throughout this folder's [Tool Roster](00%20-%20NTFS%20Deep%20Dive%20Overview.md#tool-roster) and elsewhere; this is its first full command-and-output treatment.

**Command:**

```
MFTECmd.exe -f "C:\Temp\$MFT" --csv "C:\Temp\out" --csvf mft_output.csv
```

| Flag | Purpose |
|---|---|
| `-f <path>` | Input file to parse — required. Works against `$MFT`, and also `$J`/the USN journal, `$LogFile`, `$Boot`, or `$SDS` depending on what's supplied |
| `--csv <dir>` | Directory to write CSV output into |
| `--csvf <name>` | Custom CSV filename (default is auto-generated) |
| `--json <dir>` | JSON output instead of/alongside CSV |
| `--body <dir>` (with `--bdl <driveletter>`) | Bodyfile format for direct ingestion into a timeline tool |
| `--de <entry-seq>` | Dump full parsed detail for one entry/sequence number — the closest MFTECmd gets to `istat`'s single-record view |

🔴 Hedge deliberately, same as `istat` above: confirm exact flag names against `MFTECmd.exe --help` for the installed build — flag names have shifted across MFTECmd releases, and this is not the full flag set.

**Representative CSV row** (illustrative — hand-assembled to show the shape and meaning of real MFTECmd CSV output, not a literal capture from a specific parse; only a handful of the tool's ~40+ columns shown):

```
EntryNumber,SequenceNumber,InUse,ParentPath,FileName,Created0x10,Created0x30,IsDirectory
63625,4,True,.\Users\victim\Downloads,evil.exe,2026-03-11 14:02:31.1234567,2026-03-11 14:02:31.1234567,False
```

How to read this: **EntryNumber/SequenceNumber** is the same FRN pairing `istat`'s `Entry`/`Sequence` header shows for a single record — cross-check it the same way. **ParentPath** is MFTECmd's own resolved full path (built by walking parent references across the whole table), something `istat` alone doesn't give without separately resolving the parent inode. **Created0x10** vs **Created0x30** is the CSV-column equivalent of comparing the two $STANDARD_INFORMATION/$FILE_NAME timestamp blocks `istat` prints separately above — a mismatch here is the same timestomping signal, just now sortable/filterable across an entire volume at once instead of one record at a time.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Sequence number far higher than plausible for the file's age/host history | That record slot has been reused many times — worth asking why churn was so high, and treating any older reference to this FRN as stale |
| A stale FRN reference (LNK target, journal entry, prior report) whose sequence number no longer matches the current record | The slot has been reused since that reference was written — it no longer points at the file it once did |
| Resident $DATA on a record where the file's real size should force non-resident storage | Possible manual record tampering, or a size field that doesn't match the actual content — cross-check `$STANDARD_INFORMATION`'s reported size against the attribute's actual resident length |
| $ATTRIBUTE_LIST present pointing at extension records nobody expected | Confirms attribute content exists outside the base record — re-run analysis including the extension record(s) before concluding the record has been fully read |
| `FILE*` signature instead of `FILE0` | Fixup verification failed — a torn/partial sector write, worth treating as a data-integrity flag on that specific record rather than trusting it at face value |
| Record marked unallocated but still referenced as a live parent/target elsewhere | Inconsistent with normal deletion behavior — worth confirming whether the reference is simply stale (see sequence-number check above) or something more deliberate |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The database-vs-chain mental model, where the $MFT sits on the volume, the full tool roster for this folder | [00 - NTFS Deep Dive Overview](00%20-%20NTFS%20Deep%20Dive%20Overview.md) |
| Byte-level $SI/$FN field layout underlying the behavioral timestomping detection technique | [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md) |
| Resident vs non-resident $DATA in depth, and pulling content back out with `icat` | [03 - $DATA Attribute and Resident vs Non-Resident Files](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md) |
| MACE/MACB timestamp behavior by operation and the $SI-vs-$FN detection technique | [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md#macemacb-behavior-by-operation) |
| The NTFS metadata-file roster and the MFT Zone | [00 - NTFS Deep Dive Overview](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) |
| Deleted-file recovery strategy (orphans, carving, SSD/TRIM) | [07 - File Deletion Mechanics](07%20-%20File%20Deletion%20Mechanics.md#deleted-file-recovery-concepts) |

## Resources

- SANS FOR508 "Advanced Incident Response, Threat Hunting, and Digital Forensics" course materials / "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- The Sleuth Kit documentation (`istat`, `fls`, `mmls`) — https://wiki.sleuthkit.org/
- The Sleuth Kit tool reference — https://www.sleuthkit.org/sleuthkit/tools.php
- Eric Zimmerman's tools (MFTECmd for bulk $MFT parsing) — https://ericzimmerman.github.io/
- Microsoft Learn — How NTFS Works (MFT overview) — https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
