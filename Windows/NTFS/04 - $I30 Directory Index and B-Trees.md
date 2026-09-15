# $I30 Directory Index and B-Trees

Every **directory** on an NTFS volume needs a fast way to answer "what's in me?" without opening every child's own $MFT record one at a time. NTFS solves this with a **directory index** — a B-tree keyed by filename, built out of copies of each child's own $FILE_NAME attribute, stored as a named attribute on the directory's own $MFT record. That attribute is universally called **$I30**, and this note is arguably the single highest-value deleted-file-metadata technique in the entire NTFS folder: because NTFS never zeroes stale index content when the tree rebalances, a live, actively-used directory's $I30 structure routinely holds the names, sizes, and timestamps of files that were deleted long ago — sometimes long after the file's own $MFT record has been reused for something else entirely.

> 🔴 **A directory's $I30 can outlive the files it once listed.** Index nodes split and merge as a folder's contents churn, and NTFS does not clean up the bytes it leaves behind when it does. Recovering deleted filenames from $I30 slack is frequently possible even when every other trace of the file — its $MFT record, its $DATA content — is completely gone.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What $I30 Is](#what-i30-is)
- [$INDEX_ROOT vs $INDEX_ALLOCATION](#index_root-vs-index_allocation)
- [B-Tree Searching: Nodes and Sorted Entries](#b-tree-searching-nodes-and-sorted-entries)
- [B-Tree Rebalancing — the Forensic Payoff](#b-tree-rebalancing--the-forensic-payoff)
- [Parsing $I30](#parsing-i30)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

TSK-oriented, offline-image workflow — none of this is reachable from a live-OS directory listing (see the note below the block).

```bash
# Confirm the directory even HAS a non-resident index before bothering to extract anything.
# Look for attribute type 0xA0 ($INDEX_ALLOCATION) in the output - if it's absent, everything
# lives in $INDEX_ROOT alone and there's no INDX-record slack to chase.
istat -o <sector_offset> <image.dd> <directory_inode>

# Pull the raw $I30 stream off a directory of interest for offline parsing - this grabs
# live entries AND any slack bytes left behind by prior node splits/merges.
icat -o <sector_offset> <image.dd> <directory_inode>:$I30 > i30_extract.raw

# fls also reads $I30 directly and will surface entries flagged deleted-but-still-indexed
# (marked with '*') - a fast triage pass before a full Indx2Csv run.
fls -o <sector_offset> -rd <image.dd> <directory_inode>
```

🔴 **`Get-ChildItem` and every other live-OS listing tool are not equivalent to this.** The Windows API only ever returns the *current, in-use* entries — it walks the same B-tree these tools do, but it has no concept of "leftover bytes from a node that was rebalanced two years ago." Slack recovery inside $I30 is exclusively an offline/raw-parsing technique (`icat`, Indx2Csv, or a forensic suite reading the raw attribute); no amount of live PowerShell enumeration will ever surface it.

## What $I30 Is

| Fact | Detail |
|---|---|
| Where it lives | Inside the **directory's own $MFT record** — not a separate metadata file. A regular file has no $I30 at all; only directories do. |
| Why "$I30" | It's a **named attribute stream** — the attribute name literally is `I30` (Unicode, uppercase), addressed the same way any ADS is (`inode:$I30`), which is why analysts shorthand the whole structure as "$I30" |
| What it contains | The directory's **immediate children only** (files and subfolders one level down) — not a recursive listing of the whole subtree |
| What each entry actually is | A **copy of the child's $FILE_NAME attribute** — same fields, same values, duplicated into the parent so Windows can sort/enumerate without opening every child's own record |
| Structure | A **B-tree**, keyed by filename, so lookups and sorted enumeration don't require a linear scan of every entry |
| Not to confuse with | The volume-level metadata files ($MFT, $LogFile, $Bitmap, etc. — see 00's [NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table). $I30 is per-directory, one instance per folder, not a single volume-wide structure. |

Because each $I30 entry is a duplicate of the child's $FILE_NAME data, it carries the same field set covered in note 02's $FN field table: filename (in whichever namespace), parent directory MFT reference, the four **$FN-side** MACB timestamps, and allocated/real size. The practical consequence: **the parent directory keeps its own independent copy of a child's name and $FN timestamps**, separate from the child's own $MFT record — which is exactly what makes $I30 survive after that child record is gone.

| Index entry field | Meaning |
|---|---|
| MFT reference of the child | Which $MFT record this entry describes (record number + sequence number) |
| Copied $FILE_NAME data | Name (namespace-tagged), parent directory reference, $FN-side MACB timestamps, allocated size, real size, basic file attribute flags — see note 02 for the byte-level layout of these same fields |
| Entry flags | Marks whether this entry has a child subnode pointer, and whether it's the last entry in its node |
| VCN of child node (non-leaf entries only) | Pointer into $INDEX_ALLOCATION telling the B-tree where to descend next |

## $INDEX_ROOT vs $INDEX_ALLOCATION

A directory's index is split across up to three attributes on its own $MFT record, and which ones are present depends entirely on how many children the directory has ever needed to hold at once.

| Attribute | Type code | Residency | Role |
|---|---|---|---|
| **$INDEX_ROOT** | `0x90` | Always **resident** — lives directly inside the directory's own $MFT record | Holds the root node of the B-tree. A small directory whose entire child list fits in the record needs nothing else. |
| **$INDEX_ALLOCATION** | `0xA0` | **Non-resident** once present — only shows up when the directory outgrows $INDEX_ROOT | Stores the rest of the B-tree as a sequence of fixed-size **INDX records** (the FOR508 materials call these **Nodes**), allocated in clusters via data runs exactly like any other non-resident attribute — see note 03. Each INDX record opens with its own header and an `INDX` magic-byte signature, the directory-index analogue of an $MFT record's `FILE0` signature. |
| **$BITMAP** | `0xB0` | Resident, small | Companion to $INDEX_ALLOCATION only — one bit per INDX-record slot, tracking which are currently in-use vs free. Directly analogous to the volume-wide `$Bitmap` (03's metadata-file table), just scoped to this one directory's index allocation instead of the whole volume. |

**Small directory — root only:**

```
Directory MFT Record
├── $STANDARD_INFORMATION (0x10)
├── $FILE_NAME (0x30)
└── $INDEX_ROOT (0x90)              resident, holds the whole B-tree
      ├── entry: budget.xlsx
      ├── entry: notes.txt
      └── entry: Archive\           (subfolder)
   (every child fits here - nothing else needed)
```

**Large / heavily-churned directory — root + allocation + bitmap:**

```
Directory MFT Record
├── $STANDARD_INFORMATION (0x10)
├── $FILE_NAME (0x30)
├── $INDEX_ROOT (0x90)              resident root node - pointers into $INDEX_ALLOCATION
├── $INDEX_ALLOCATION (0xA0)        non-resident, data runs -> INDX records on disk
│     ├── INDX record #1  ("Node")  sorted entries + child-node pointers
│     ├── INDX record #2  ("Node")  sorted entries + child-node pointers
│     └── INDX record #N  ("Node")  ...
└── $BITMAP (0xB0)                  1 bit per INDX-record slot: in-use vs free
```

## B-Tree Searching: Nodes and Sorted Entries

Within any single **Node** (an INDX record, or the root node inside $INDEX_ROOT), entries are kept **sorted by filename**. That sort order is what makes the structure a search tree rather than a flat list:

| B-tree property | DFIR-relevant meaning |
|---|---|
| Entries sorted within a node | Windows can binary-search a node's entries instead of scanning linearly — this is *why* $I30 exists at all rather than a plain array |
| A non-leaf entry may carry a child-node pointer | Looking up or enumerating a name is a **descent** through the tree — compare against sorted entries in the current node, follow the child pointer for the branch that could contain the target, repeat |
| Leaf entries | Terminal entries with no child pointer — the actual file/subfolder records at the bottom of a given branch |
| Root node lives in $INDEX_ROOT | The first comparisons of any lookup always happen against the resident root node before ever touching $INDEX_ALLOCATION |

For an analyst, the "Node" terminology matters because it maps directly onto what a raw $I30 extract looks like on disk: a sequence of individually-parseable INDX records, each one internally sorted, each one independently recoverable even if its neighbors are damaged or already reused.

## B-Tree Rebalancing — the Forensic Payoff

Every create, delete, and rename inside a directory is a B-tree mutation. As entries are added, a Node can fill up and **split** into two; as entries are removed, a Node can empty out and get **merged/rebalanced** with a sibling to keep the tree efficient. This churn is invisible and automatic — Windows performs it as ordinary background bookkeeping, with no user-visible signal that it happened.

🔴 **NTFS does not zero out the bytes a Node leaves behind when it splits or merges.** When an entry is removed from a Node, or a Node's content is restructured during a split, the old entry's bytes commonly persist as **slack space within that INDX record** — the exact same phenomenon as MFT-record slack (note 01) or ordinary file slack (note 03, `icat -s`), just scoped to a directory-index node instead of a file record or a cluster. The result: a deleted file's **name, its $FN-copy MACB timestamps, and its allocated/real size** can survive inside a *live, currently-in-use* directory's $I30 structure long after:

- the file's own $MFT record has been marked free and reused for something else, and/or
- the file's actual content is long gone.

🔴 **This is one of the most important practical takeaways in the entire NTFS folder: common file-wiping tools that securely overwrite a file's $DATA content typically do not touch the parent directory's $I30 slack at all.** A tool that scrubs a file's content and then deletes it has done nothing to the bytes its old directory-index entry left behind inside an INDX record two nodes over. In practice this means a "securely wiped" file's *content* can be genuinely, unrecoverably gone (especially on SSD/TRIM — see 03's SSD section) while its *name, size, and timestamps* remain fully recoverable straight out of $I30. Never conclude "wiped = no metadata trail" without checking $I30 first.

## Parsing $I30

| Step | How |
|---|---|
| Confirm the structure exists | `istat` on the directory's inode — look for attribute `0xA0` ($INDEX_ALLOCATION) in the output. If only `0x90` ($INDEX_ROOT) shows, the directory never grew large enough to need INDX records, and there's no slack space to chase beyond whatever fits in the resident root. |
| Extract | `icat` addressed to the directory's inode with the `$I30` stream name — the same `inode:streamname` ADS-style addressing note 03 covers for regular alternate data streams: `icat -o <offset> <image> <inode>:$I30 > output.raw`. This pulls the full raw index buffer, live entries and slack alike. |
| Parse offline | **Indx2Csv** converts the extracted raw $I30 buffer into a readable CSV of index entries, including stale/slack-recovered entries the live tree no longer references. Flag names and current option set shift between tool versions — check the tool's own `--help`/documentation before scripting against a specific switch. |
| Parse without manual extraction | **Velociraptor** ships NTFS-oriented artifacts that can read $I30 (and other MFT-adjacent structures) directly off a live endpoint or an offline image, skipping the manual `icat` step entirely. Exact artifact name and current capabilities should be verified against Velociraptor's own artifact catalog/documentation — artifact names and coverage do shift across releases. |

Practical order of operations: `istat` first (cheap, confirms whether $INDEX_ALLOCATION even exists), then `icat ... :$I30` to pull the raw stream, then Indx2Csv (or Velociraptor's equivalent artifact) to turn it into something reviewable. Cross-reference every recovered name against the live filesystem and against carved/orphaned $MFT records (03's Orphan Files section) before drawing conclusions — an $I30 entry alone confirms a name *once existed in that directory*, not that the rest of the file is recoverable.

The four steps below walk through that exact order end to end, each one feeding the next.

### 1. `istat` — confirm $INDEX_ALLOCATION (0xA0) is actually present

Same command as the Hunt Evil block at the top of this note:

```bash
istat -o <sector_offset> <image.dd> <directory_inode>
```

Read the `Attributes:` block at the bottom of the output. A **small directory** — everything fits in the resident root, nothing to chase in slack — looks like this:

```
Attributes:
Type: $STANDARD_INFORMATION (16-1)   Name: N/A   Resident   size: 96
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 90
Type: $INDEX_ROOT (144-3)   Name: $I30   Resident   size: 56
```

No `0xA0` line at all — only `$INDEX_ROOT`. Per the table above, that means the whole B-tree lives in one resident attribute and there's no separately-allocated INDX-record slack to pull.

A **churned directory** that has outgrown the root node shows two more lines:

```
Attributes:
Type: $STANDARD_INFORMATION (16-1)   Name: N/A   Resident   size: 96
Type: $FILE_NAME (48-2)   Name: N/A   Resident   size: 90
Type: $INDEX_ROOT (144-3)   Name: $I30   Resident   size: 56
Type: $INDEX_ALLOCATION (160-4)   Name: $I30   Non-resident   size: 4096   init_size: 4096
Type: $BITMAP (176-5)   Name: $I30   Resident   size: 8
```

`$INDEX_ALLOCATION (160-...)` present — this directory has at least one 4096-byte INDX record on disk, which is exactly where node-split/merge slack accumulates. That's the signal to move on to `icat`.

🔴 **Exact attribute IDs, sizes, and column spacing shift slightly between TSK versions and NTFS cluster sizes** — the snippets above are illustrative of the *pattern* (presence/absence of the `0xA0` line), not a byte-for-byte guarantee of your build's output formatting.

### 2. `icat` — extract the raw $I30 stream

Same command as the Hunt Evil block — repeated here so this walkthrough doesn't require jumping back up:

```bash
icat -o <sector_offset> <image.dd> <directory_inode>:$I30 > i30_extract.raw
```

`i30_extract.raw` now holds the full raw index buffer for that one directory — every INDX record (Node) back to back, live entries and any leftover slack bytes alike. This is the file the next two tools consume.

### 3. `Indx2Csv` — parse the raw extract into readable rows

[Indx2Csv](https://github.com/jschicht/Indx2Csv) decodes INDX records (the `$I30` index as well as `$O`/`$R` indexes) into CSV. Two flags matter most for this workflow: `/Slack:1` turns on slack-space scanning — **without it, stale/deleted entries are not reported at all** — and `/Unicode:1` improves name decoding (at some cost to slack-recovery precision, per the tool's own notes).

```bash
Indx2Csv.exe /IndxFile:i30_extract.raw /OutputPath:out_dir /Slack:1 /Unicode:1
```

Representative output (column names/order can shift across versions — verify against your build's actual CSV header before scripting a parser against it):

```
FileName,FileSize,AllocatedSize,ParentMftRef,MftRef,CTime,ATime,MTime,RTime,InSlack
payroll_2026.xlsx,48213,49152,5-1,881-2,2026-03-02 09:14:01,2026-07-18 16:02:44,2026-07-18 16:02:44,2026-07-18 16:02:44,0
invoice_q1_draft.pdf,190447,192512,5-1,742-1,2025-11-08 11:20:33,2025-11-09 08:55:12,2025-11-09 08:55:12,2025-11-09 08:55:12,1
```

The first row is a normal, currently-live entry. The second row — `InSlack = 1` — is exactly the phenomenon this note's whole thesis rests on: `invoice_q1_draft.pdf` is no longer in the live directory listing, its own $MFT record (742) may already be reused, but its name, size, and $FN-copy MACB timestamps are still sitting in this directory's INDX slack because NTFS never zeroed them out when the node rebalanced.

🔴 **Flag names, the exact CSV header, and the slack-flag column name shift between tool versions** — confirm against the tool's own `--help`/GUI (running it with no parameters launches a GUI that documents each option) before relying on a specific column.

### 4. Velociraptor — parse without a manual extraction step

Velociraptor ships a client artifact purpose-built for this: **`Windows.NTFS.I30`**, which globs a set of directories, opens each one's $MFT record, and runs the `parse_ntfs_i30()` VQL plugin against its `$I30` stream directly — no `icat` step required. Key parameters: `DirectoryGlobs` (default `C:\Users\*`), `SlackOnly` (return only slack-recovered entries), and `AlsoUpload` (also pull the raw `$I30` stream to the server for offline work).

```bash
# Run the artifact against a live endpoint or mounted offline image, filtered to slack-only hits
velociraptor query -v "SELECT * FROM Artifact.Windows.NTFS.I30(DirectoryGlobs='C:/Users/*/Downloads/*', SlackOnly=true)"
```

Equivalent raw VQL, calling `parse_ntfs_i30()` directly against a single directory's MFT inode (the pattern the artifact itself uses internally):

```
SELECT OSPath, Name, NameType, Size, AllocatedSize, IsSlack, SlackOffset,
       Mtime, Atime, Ctime, Btime, MFTId
FROM parse_ntfs_i30(device='\\.\C:', inode='5-742-1')
WHERE IsSlack = true
```

`IsSlack = true` on a returned row is the VQL-native equivalent of the `InSlack` column above — a name recovered from node slack rather than the live tree. Both `Windows.NTFS.I30` and `parse_ntfs_i30()` are current, documented Velociraptor components as of this writing; exact parameter defaults and output columns should still be checked against `docs.velociraptor.app` before scripting a hunt against a specific field name, since both do shift across releases.

### Visualizing Node slack: before and after a delete

Same "Directory MFT Record" diagram style as the $INDEX_ROOT/$INDEX_ALLOCATION section above, zoomed into a single INDX record (Node) as one entry is removed:

```
INDX record #7 (4096-byte Node) — BEFORE deleting "invoice_q1_draft.pdf"
├── entry: bank_statement.pdf         sorted, live
├── entry: invoice_q1_draft.pdf       sorted, live   ← about to be removed
├── entry: payroll_2026.xlsx          sorted, live
└── (unused node capacity — never written)

INDX record #7 (same 4096-byte Node) — AFTER deleting "invoice_q1_draft.pdf"
├── entry: bank_statement.pdf         sorted, live
├── entry: payroll_2026.xlsx          sorted, live
│   ---- live entries now end here; node's logical entry count shrinks ----
├── [ SLACK: stale "invoice_q1_draft.pdf" bytes — name, $FN MACB copy, sizes ]
└── (remaining unused node capacity — never written)
```

The node's *physical* 4096 bytes never shrink — only the logical "live entries end here" boundary moves. Everything past that boundary, including the old entry's full name and $FN-copy timestamps, sits untouched until some future split/merge happens to overwrite that exact byte range. That's the window Indx2Csv's `/Slack:1` and Velociraptor's `IsSlack`/`SlackOnly` are reading.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Recovered $I30 slack entry naming a file with no corresponding live or carved $MFT record anywhere on the volume | Strong evidence of deliberate deletion, and — combined with an unrecoverable $DATA — possible deliberate wiping (see the callout above) |
| $INDEX_ALLOCATION present and disproportionately large relative to the directory's current live child count | Suggests heavy historical churn (mass creation/deletion) in that folder — worth investigating why, and worth prioritizing that directory for slack extraction |
| $I30-recovered $FN timestamps that don't match anything in $LogFile/$UsnJrnl for the same name | The index copy may predate the journal's retention window, or point to activity the journal already rolled past — treat as corroborating, not contradicting |
| A directory whose $INDEX_ROOT alone (no $INDEX_ALLOCATION) still shows signs of prior larger content via slack inside the root's own resident space | Smaller-scale version of the same phenomenon — even resident-only directories can retain limited stale bytes |

## Correlate With

| To go deeper on… | Open |
|---|---|
| MFT-record slack, the general "freed but not zeroed" pattern this note extends to directory nodes | `01 - MFT Entry Structure and Attributes.md` |
| Byte-level layout of the $FILE_NAME fields that $I30 entries duplicate | `02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md` |
| Data runs, non-resident attribute mechanics, and `icat -s` file-slack extraction | `03 - $DATA Attribute and Resident vs Non-Resident Files.md` |
| What happens to a file's $MFT record, $DATA, and its $I30 entry at each stage of deletion | `07 - File Deletion Mechanics.md` |
| Orphan files, carving, and SSD/TRIM limits on what's recoverable at all | [07 - File Deletion Mechanics](07%20-%20File%20Deletion%20Mechanics.md#deleted-file-recovery-concepts) |
| Deliberate anti-forensic wiping and why it so often misses $I30 | `Windows/19 - Anti-Forensics and Evidence Destruction.md` |

## Resources

- SANS FOR508 "Advanced Incident Response, Threat Hunting, and Digital Forensics" — $I30/B-tree index materials — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- The Sleuth Kit documentation (`istat`, `icat`, `fls`) — https://wiki.sleuthkit.org/
- Velociraptor documentation (NTFS/$I30 artifact catalog) — https://docs.velociraptor.app/
- Indx2Csv — verify current download location, options, and output schema against the tool's own `--help`/release notes before relying on a specific flag
- Microsoft Learn — How NTFS Works (directory indexes, B-trees) — https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
