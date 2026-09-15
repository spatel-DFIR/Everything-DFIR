# $LogFile (NTFS Transaction Journal)

NTFS keeps two separate logs of "what happened on this volume," and confusing them is the single most common mistake analysts make with this material. `$LogFile` is the older, lower-level one — the filesystem's own internal transaction journal, written for NTFS's own crash-recovery purposes, never intended as a user-facing activity log at all. It just happens to also be forensic gold, because it records metadata *operations* rather than just metadata *states* — which means it can outlive the very $MFT record it describes. This note covers `$LogFile` only: what it's for, how it's structured, why it survives record reuse, and how to pull it apart with the field-standard tooling. Its sibling journal, `$UsnJrnl`, gets its own note (**06 - $UsnJrnl (USN Change Journal).md**) — the two are complementary, not redundant, and mixing up which one you're citing in a report is an easy way to overstate or understate what the evidence actually shows.

> 🔴 **`$LogFile` retains evidence of operations, not just current state — and that's exactly why it can survive record reuse.** When an $MFT record is freed and handed to a brand-new file, the *record* only ever shows the new file's current metadata. But the transaction history describing everything that happened to the *old* file — renames, attribute changes, timestamp updates — was already written out to `$LogFile` as a separate, append-ish structure at the time those operations occurred. Reusing the record doesn't reach back and erase those earlier journal entries. That gap between "what the live record shows now" and "what the journal shows happened before" is where `$LogFile` earns its keep.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Two Journals, One Volume](#two-journals-one-volume)
- [What $LogFile Is and Why It Exists](#what-logfile-is-and-why-it-exists)
- [Structure: RCRD Pages, Log Records, and LSNs](#structure-rcrd-pages-log-records-and-lsns)
- [Why It Matters Beyond Crash Recovery](#why-it-matters-beyond-crash-recovery)
- [Tooling: LogFileParser](#tooling-logfileparser)
- [Extraction](#extraction)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

`$LogFile` is a binary transaction structure — RCRD pages of packed log records, not a text log and not something any native Windows tool exposes. Unlike `$UsnJrnl`, there is no `fsutil`-equivalent live interface here (see note 06's `fsutil usn queryjournal` for the contrast). There's nothing to paste into PowerShell; the fast path is a short collection-then-parse workflow.

```
# 1. Collect $LogFile off a live host or mounted image (TSK route — resolve the inode first with fls/istat)
icat -o <sector_offset> <image.dd> <LogFile_inode> > LogFile_extract.bin

# 2. Or collect via KAPE as part of a standard triage bundle (pulls $MFT/$LogFile/$UsnJrnl together)
kape.exe --tsource C: --tdest C:\triage --target MFT,LogFile,UsnJrnl

# 3. Parse the extracted $LogFile into a transaction timeline (verify current flags against --help)
LogFileParser.exe -f LogFile_extract.bin -o LogFile_transactions.csv

# 4. Pivot the output on a specific MFT record number or a narrow time window around
#    a suspect $SI timestamp — that's the whole point of steps 1-3
```

🔴 Treat step 3's exact flags as illustrative, not gospel — **LogFileParser** is a smaller, less standardized project than the Eric Zimmerman suite, and its CLI surface has shifted across releases. Confirm against the tool's own `--help`/documentation at time of use before scripting around a specific switch.

## Two Journals, One Volume

| | `$LogFile` (this note) | `$UsnJrnl` (note 06) |
|---|---|---|
| Level | **Low-level** — filesystem-metadata journal | **High-level** — change-tracking journal |
| Written by | NTFS itself, for its own crash-consistency needs | NTFS, for consumption by user-mode software |
| Consumed by | NTFS's own recovery logic on mount | AV, backup agents, search indexers (Windows Search), sync clients |
| What it records | Individual metadata *transactions* — the low-level steps of an operation | Higher-level *reasons* a file/folder changed (create, rename, delete, data-overwrite, etc.), one entry per change |
| Typical retention | **Minutes to hours** of activity on a busy volume — fixed size, rolls fast | **Days to weeks** — much larger, and Windows 10 1809+ made it effectively always-on |
| Location | Root metadata file, `$LogFile` (record ~2 in the reserved 0–15 range) | `$Extend\$UsrJrnl` (Windows 10 1809+; earlier builds required manual enablement) |
| Forensic framing | Short-window, high-fidelity: "exactly what operation happened to this record, recently" | Long-window, coarser: "what kind of change happened to this path, over a longer span" |

Same idea, drawn as a rough retention-window picture (not to scale — actual coverage is activity-dependent, not fixed, per the tables above and below):

```
                     ── how far back a typical exam can look, same volume ──

  $LogFile (~64 MB)   [XXX.........................]   minutes-to-hours of history
  $UsnJrnl (~32 MB)   [XXXXXXXXXXXXXXXXXXXX........]   days-to-weeks of history (smaller max size, but far lower per-entry footprint)

                        now                      →       further back in time
```

Both are introduced in [00's NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table; this note and note 06 are where each gets the depth that summary table doesn't have room for.

## What $LogFile Is and Why It Exists

`$LogFile` is a **write-ahead transaction log**. Before NTFS commits a metadata change — creating a file, renaming it, updating an attribute, adding or removing a directory-index entry, extending or truncating allocation — it first writes a record of the *intended* change to `$LogFile`. Only after that record is safely on disk does NTFS go modify the actual `$MFT`/`$I30`/etc. structures the change targets.

The payoff is crash and power-loss resilience. If the system dies mid-operation — between the journal write and the real structure update, or partway through updating the real structure — NTFS doesn't need a full disk scan on the next mount to figure out what state things are in. It replays (**redo**) transactions that were logged but never fully applied, and rolls back (**undo**) transactions that were partially applied and need to be cleanly reversed, using `$LogFile` itself as the source of truth. That's the entire reason NTFS doesn't need a `chkdsk`-style full-volume consistency check on every ordinary boot the way older filesystems did.

| Fact | Detail |
|---|---|
| Default size | **64 MB** — fixed, not something that grows with volume size by default |
| Behavior | Roughly circular/rolling — once full, older transaction records are overwritten by new ones |
| Retention window | Activity-dependent, not time-dependent — a busy server volume can cycle through 64 MB of transaction history in minutes; a quiet workstation volume might hold days of history in the same space |
| Consequence for analysts | There's no fixed "$LogFile covers the last N hours" rule — the only honest answer is "check what's actually in it," and act fast, because the window can be short |

## Structure: RCRD Pages, Log Records, and LSNs

`$LogFile` is organized as a sequence of fixed-size pages, each stamped with the signature **RCRD**. Each RCRD page packs one or more individual **log records** — the actual transaction entries. Every log record carries a **Log Sequence Number (LSN)**, a monotonically increasing identifier assigned in the order transactions are written.

This is the same LSN concept `Windows/NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md` covers at the byte level as one of $STANDARD_INFORMATION's own fields: every `$MFT` record stamps the LSN of the last `$LogFile` transaction that touched it. That stamp is a direct pointer — given a live `$MFT` record, an analyst knows exactly which `$LogFile` transaction (if it hasn't rolled out yet) last modified that record, and can go pull the full operation context around it rather than guessing.

Keep the conceptual model DFIR-practical rather than filesystem-theory-dense:

| Term | Practical meaning |
|---|---|
| **Redo information** | "What to reapply if this change didn't make it to the real structure yet" — the forward-looking half of the transaction |
| **Undo information** | "What to reverse if this change needs to be rolled back" — the backward-looking half, used when a transaction was only partially applied |
| **LSN** | A transaction's position in the sequence — lets a record ("this $MFT entry was last touched by LSN X") be tied directly back to the journal entry that describes exactly what happened at that moment |

An analyst doesn't need to reconstruct NTFS's internal recovery algorithm to use this — the practical takeaway is simpler: **each transaction record describes an operation, has a timestamp/LSN, and references the $MFT record(s) it affected.** That's the unit a parser like LogFileParser surfaces.

🔴 **Redo/undo records aren't just pointers to "an operation happened" — they routinely carry the actual bytes being changed.** For small, resident-sized changes (a $SI/$FN attribute update, a directory-index entry being added or removed, a short resident $DATA write), the redo/undo information embeds the literal before/after content of that change, not just a description of it. This is what makes `$LogFile` more than a crash-recovery breadcrumb trail for an examiner: a transaction that hasn't rolled out of the 64 MB window yet can hand back the actual old or new attribute value straight out of the log record, independent of whatever the live `$MFT` record currently shows. `LogFileParser` surfaces this embedded payload alongside the operation type and LSN — it's the reason $LogFile analysis can sometimes recover a prior filename or timestamp value directly, not just prove that a change occurred.

## Why It Matters Beyond Crash Recovery

Note 03's NTFS Metadata Files table already flags the headline fact: `$LogFile` can hold recent metadata operations even after the corresponding `$MFT` record has been reused. Here's the mechanical reason that's true.

An `$MFT` record is a fixed slot — record reuse means the *bytes at that record's location* get overwritten with a brand-new file's row: new name, new timestamps, new attributes, all of it. Whatever the previous occupant's `$SI`/`$FN` values were is now genuinely gone from the live record. But `$LogFile` transaction entries aren't stored inside the `$MFT` record they describe — they live in a **separate, largely append-driven structure** that gets written *at the time the operation happened*, independent of whatever later becomes of the record itself. Record reuse changes the record. It does nothing to the journal entries already written describing the record's *prior* history — those persist until `$LogFile`'s own rolling window cycles them out on its own schedule, unrelated to the record's reuse timeline.

This makes `$LogFile` a genuine **timestomping-detection** source, not just a crash-recovery mechanism:

- If an attacker's tool rewrites `$SI` timestamps directly (the common case — most timestomping tools only touch $SI, per note 02's $SI-vs-$FN discussion), the write itself is a metadata operation. If it happened recently enough that the relevant transaction hasn't rolled out of `$LogFile` yet, the journal still shows *that a timestamp-modification operation occurred*, at the *real* time it occurred — independent of what fake value got written.
- Cross-referencing that transaction's timing against the doctored `$SI` values is direct contradiction evidence: the file's current $SI claims one history, and $LogFile's transaction record for that same $MFT record shows a different operation timeline.
- The catch is the same 64 MB rolling-retention limit from above — this only works if the tampering is recent enough that the transaction hasn't cycled out yet. `Windows/19 - Anti-Forensics and Evidence Destruction.md` covers this exact technique in the wider anti-forensic-detection workflow (alongside the $UsnJrnl equivalent), including why timeliness of acquisition matters so much here specifically.

## Tooling: LogFileParser

**LogFileParser**, by Joakim Schicht, is the field-standard free/open tool for turning a raw `$LogFile` extract into a human-readable transaction history. In general terms, it walks the RCRD pages, decodes individual log records, and outputs — per transaction — the **operation type** (create, rename, attribute update, index change, etc.), the **affected $MFT record reference**, and the **LSN/timestamp** of that transaction. That output is exactly the pivot table an analyst needs to answer "what actually happened to this record, and when" independent of the record's current live content.

Typical workflow:

1. **Extract** `$LogFile` off the volume — FTK Imager's "Export Special Files," KAPE's `LogFile` target, or `icat` against the file's known inode via The Sleuth Kit.
2. **Run LogFileParser** against the extracted file.
3. **Pivot** the resulting transaction list on the $MFT record number(s) or time window of interest — usually the same record and window already under scrutiny from an $SI/$FN mismatch or a suspicious file surfaced elsewhere in the case.

🔴 Hedge on exact CLI syntax: LogFileParser's flag names and output format have shifted across releases, and it's a smaller, less actively standardized project than the Eric Zimmerman suite (MFTECmd, RECmd, etc.) that the rest of this repo leans on. State the general pattern with confidence — extract, then parse, then pivot — but verify the precise current flags against the tool's own `--help`/documentation before building a repeatable process around a specific switch.

**Command** (verified against the tool's own shipped `readme.txt` — LogFileParser actually takes `/SwitchName:value`-style flags, not the short `-f`/`-o` form used as a placeholder in the Hunt Evil block above; treat that earlier one-liner as shorthand, not literal syntax):

```
LogFileParser.exe /LogFileFile:C:\triage\LogFile_extract.bin /OutputPath:C:\triage\LFP-Output /TimeZone:0.00 /MftRecordSize:1024 /SectorsPerCluster:8 /TSFormat:1 /TSPrecision:MilliSec /Unicode:1
```

This writes `LogFile.csv` (the main transaction table) plus a set of specialized companion CSVs (index records, dataruns, resolved filenames, etc.) and an `ntfs.db` SQLite database — see the tool's `readme.txt` for the full output-file roster.

**Representative output** (`LogFile.csv`, illustrative — hand-assembled from the tool's documented `lf_*` column schema to show the shape and meaning of real output, not a literal capture from a specific parse; the real file ships 60+ columns, default separator `|`, only the DFIR-relevant subset shown here):

```
lf_LSN|lf_LSNPrevious|lf_MFTReference|lf_RedoOperation|lf_UndoOperation|lf_FileName|lf_FileNameModified|lf_SI_MTime|lf_TextInformation
1415242601|1415242600|1643|CreateAttribute|DeleteAttribute|invoice_2024.xlsx||2026-07-18 09:14:02.123|InitializeFileRecordSegment
1415242714|1415242713|1643|UpdateFileNameRoot|UpdateFileNameRoot|invoice_2024.xlsx|invoice_2024.xlsx.locked|2026-07-18 09:14:55.641|redo carries the new $FILE_NAME index entry, undo carries the prior one
1415242900|1415242899|1643|UpdateResidentValue|UpdateResidentValue|invoice_2024.xlsx.locked||2019-01-01 00:00:00.000|redo=$SI MTime overwritten to 2019-01-01; undo=prior value 2026-07-18 09:14:55.641
```

How to read this: **lf_LSN/lf_LSNPrevious** is the same LSN chain the Structure section above describes — each transaction points back to the one before it for that record. **lf_RedoOperation/lf_UndoOperation** name the specific NTFS-internal operation pair (`CreateAttribute`/`DeleteAttribute`, `UpdateFileNameRoot`, `UpdateResidentValue`, etc. — the tool's `readme.txt` documents roughly two dozen of these). The second row is a rename: **lf_FileName** and **lf_FileNameModified** carry the old and new names for the same `lf_MFTReference`, at adjacent LSNs — a direct old/new pair pulled straight out of the journal. The third row is exactly the embedded-payload case described above: an `UpdateResidentValue` transaction against `$STANDARD_INFORMATION` where the undo half of the record hands back the file's real prior `$SI` MTime, independent of whatever doctored value the live `$MFT` record shows now.

🔴 **MFTECmd does not currently parse `$LogFile`, despite listing it as an accepted input.** MFTECmd's own `-f` help text names `$LogFile` alongside `$MFT`, `$J`, `$Boot`, and `$SDS` as a recognized input type, but the tool's current published source (`MFTECmd/Program.cs`, master branch) handles that file type with nothing more than a warning and an exit: `$LogFile not supported yet. Exiting`. In practice, **LogFileParser above is the only `$LogFile`-capable tool this folder can point to** — don't build a triage pipeline that assumes MFTECmd can stand in for it here, and read any other reference in this repo to MFTECmd parsing `$LogFile` as describing the tool's advertised intent rather than its current behavior.

## Extraction

`$LogFile` sits among the volume's reserved root metadata files described in note 00's [NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table (records 0–15 by convention) and [Folder Map](00%20-%20NTFS%20Deep%20Dive%20Overview.md#where-the-mft-sits-on-a-volume) — it can be pulled the same way any of its neighbors ($MFT, $MFTMirr, $Bitmap) are pulled:

| Route | Fits when |
|---|---|
| **TSK `icat`** against the file's known inode | Working directly against a disk image or raw device, already have `mmls`/`fls` output resolving the inode |
| **FTK Imager** — "Export Special Files" | Live-friendly GUI collection off a mounted image or live system, no scripting needed |
| **KAPE** | Standard triage bundle collection — KAPE's typical use here is pulling `$MFT`, `$LogFile`, and `$UsnJrnl` **together** in one pass, since all three routinely get analyzed as a set (record-level state, transaction history, and change history, respectively) |

KAPE is the practical default for live-response triage specifically because it collects all three journaling/metadata artifacts in one bundle rather than requiring three separate collection steps.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `$LogFile` transaction history around a file's activity window contradicts its current `$SI` timestamps | Direct evidence the $SI values were altered after the fact — the journal preserves the real operation sequence even when $SI has been overwritten |
| Unusually short/thin `$LogFile` history for an actively-used volume | Possible deliberate log-clearing or manipulation — a busy volume should show a reasonably dense transaction history; a suspiciously empty or truncated journal is itself worth investigating rather than accepting at face value |
| Transactions referencing an `$MFT` record number whose current live content doesn't match those transactions at all | Reuse-detection lead — the record has been recycled to a new file since those transactions were written; pull the full prior transaction sequence for that record number before concluding what it used to hold |
| A transaction's LSN/timestamp lands well outside what the file's current $SI/$FN pair would suggest was possible | Worth treating as an anomaly requiring reconciliation, not dismissal — one of the two records is wrong |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The $MFT record header's LSN field at the byte level, and $SI-vs-$FN timestomping mechanics | `Windows/NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md` |
| The complementary, longer-retention change journal ($UsnJrnl) | `Windows/NTFS/06 - $UsnJrnl (USN Change Journal).md` |
| What survives at each stage of deletion — record, index entry, journal entries, data runs | `Windows/NTFS/07 - File Deletion Mechanics.md` |
| The full NTFS metadata-file roster and the one-line $LogFile summary this note expands on | [00 - NTFS Deep Dive Overview](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) |
| MACE/MACB behavior by operation | [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md#macemacb-behavior-by-operation) |
| Full timestomping-detection workflow ($SI/$FN compare → $LogFile → $UsnJrnl escalation) and journal/shadow-copy destruction techniques | `Windows/19 - Anti-Forensics and Evidence Destruction.md` |

## Resources

- SANS FOR508 "Advanced Incident Response, Threat Hunting, and Digital Forensics" — File System Journaling Overview / $LogFile sections — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- LogFileParser (Joakim Schicht) — https://github.com/jschicht/LogFileParser
- Eric Zimmerman's tools (MFTECmd, for $MFT/record-level cross-referencing) — https://ericzimmerman.github.io/
- The Sleuth Kit documentation (`icat`, `fls`, `istat`) — https://wiki.sleuthkit.org/
- Microsoft Learn — How NTFS Works (journaling/recovery overview) — https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
- MITRE ATT&CK: T1070.006 (Indicator Removal: Timestomp)
