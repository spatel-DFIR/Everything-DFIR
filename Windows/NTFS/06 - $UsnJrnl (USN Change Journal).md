# $UsnJrnl (USN Change Journal)

Note 05 covered `$LogFile` — NTFS's own low-level, crash-consistency journal, built so the filesystem can recover its own metadata after an unclean shutdown. This note covers its higher-level sibling: `$UsnJrnl`, the volume-wide **change tracking service** that lets ordinary software ask "what changed since I last checked" without re-scanning every file. Where `$LogFile` is written for NTFS itself, `$UsnJrnl` is written for everything *else* on the box — backup agents, antivirus, the Windows Search Indexer, File History, cloud-sync clients, DFSR replication — and that consumer-facing design is exactly what makes it one of the richest correlation sources in the whole NTFS family. For ransomware and any other mass-file-operation incident, this is arguably the single most load-bearing note in this folder: `$UsnJrnl` frequently captures every file an encryptor touched, even on files that carry no other trace of the intrusion anywhere else on disk.

> 🔴 **$LogFile answers "is the metadata consistent"; $UsnJrnl answers "what changed."** They are separate structures, sized and managed independently, retained for different windows, and consumed by entirely different audiences (NTFS itself vs. every other piece of software on the volume). Don't treat one as a substitute for the other — a mature exam checks both, in the order retention window dictates: `$LogFile` first (shorter, more likely to have cycled out already), then `$UsnJrnl` (longer, usually the better source once the incident window is more than a few hours old).

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What $UsnJrnl Is and Where It Lives](#what-usnjrnl-is-and-where-it-lives)
- [The Two Streams: $Max and $J](#the-two-streams-max-and-j)
- [USN Record Structure and Reason Codes](#usn-record-structure-and-reason-codes)
- [Activity Patterns in Journals](#activity-patterns-in-journals)
- [Filtering and Searching the Journal](#filtering-and-searching-the-journal)
- [Journal Tools](#journal-tools)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native `fsutil usn` commands are the one genuinely live-reachable piece of this folder (per 00's tool-roster note) — useful for fast triage on a running host, but they read the **live, mounted volume only** and have nothing to offer against a static image. MFTECmd is the offline equivalent and the tool that actually belongs in casework against acquired evidence.

```powershell
# Confirm the journal exists, and capture its Journal ID, MaxSize, and current USN -
# the baseline to compare against later if journal-reset tampering is suspected
fsutil usn queryjournal C:

# Live read of journal records from a given starting USN - quick look at recent activity
# without waiting for an offline parse; swap <StartUsn> for a value from queryjournal
# above, or 0 to start from the oldest surviving record
fsutil usn readjournal C: csv startusn=0 | Select-Object -First 50
```

**Illustrative `fsutil usn queryjournal C:` output** (representative — Microsoft's own `fsutil usn` reference documents the fields but doesn't publish a sample block, so this is hand-assembled to show the shape; actual values are volume-specific):

```
Usn Journal ID       :        0x01d7c8a2b3e4f610
First Usn            :        0
Next Usn             :        733206528
Lowest Valid Usn     :        0
Max Usn              :        0xffffffffffffffff
Maximum Size         :        33554432
Allocation Delta     :        8388608
Minimum record version supported : 2
Maximum record version supported : 4
```

How to read this: **Usn Journal ID** is the tamper-evidence field the `$Max` stream section below describes — record it early and treat any later mismatch against this baseline as a finding, not noise. **Maximum Size**/**Allocation Delta** are the same `$Max`-stream fields in live-query form. **Next Usn** is the current write cursor — hand this value to a later `readjournal`/`fsutil usn readjournal startusn=` call to pick up only what's new since this baseline was captured.

```bash
# Offline, image-safe equivalent - point MFTECmd at an extracted $UsnJrnl:$J stream
# (pull it first via KAPE, FTK Imager's "Export Special Files," or icat against the
# $Extend\$UsnJrnl record). Exact flag names vary by MFTECmd build - confirm with --help.
MFTECmd.exe -f "C:\triage\$J" --csv "C:\triage\out" --csvf usnjrnl.csv

# Point MFTECmd at the raw $MFT alongside the journal so filenames/parent paths
# resolve fully rather than showing bare FRNs
MFTECmd.exe -f "C:\triage\$MFT" -j "C:\triage\$J" --csv "C:\triage\out"

# Once parsed to CSV, pivot with a spreadsheet/PowerShell filter for the ransomware
# pattern - dense DATA_OVERWRITE + RENAME pairs across many distinct files in a tight window
Import-Csv C:\triage\out\usnjrnl.csv | Where-Object { $_.UpdateReasons -match 'DataOverwrite' -and $_.UpdateReasons -match 'Rename' } | Group-Object { $_.UpdateTimestamp.Substring(0,16) } | Sort-Object Count -Descending | Select-Object -First 10
```

**Representative `usnjrnl.csv` output** (illustrative — hand-assembled from MFTECmd's documented `$J` output fields (`Name`, `UpdateTimestamp`, `EntryNumber`/`SequenceNumber`, `ParentEntryNumber`/`ParentSequenceNumber`, `ParentPath`, `UpdateReasons`, among others) to show the shape of real output, not a literal capture from a specific parse; multiple reason bits on one record are pipe-separated in the tool's actual CSV, e.g. `DataExtend|DataOverwrite`):

```
Name,UpdateTimestamp,EntryNumber,SequenceNumber,ParentEntryNumber,ParentSequenceNumber,ParentPath,UpdateReasons
quarterly_report.docx,2026-07-18 09:41:02.1140000,81422,3,5124,2,.\Users\victim\Documents,FileCreate
quarterly_report.docx,2026-07-18 09:41:02.3980000,81422,3,5124,2,.\Users\victim\Documents,DataExtend|DataOverwrite
quarterly_report.docx,2026-07-18 09:41:02.4010000,81422,3,5124,2,.\Users\victim\Documents,Close
invoice_2024.xlsx,2026-07-18 14:02:55.0210000,91007,2,5124,2,.\Users\victim\Documents,DataOverwrite
invoice_2024.xlsx,2026-07-18 14:02:55.0230000,91007,2,5124,2,.\Users\victim\Documents,RenameOldName
invoice_2024.xlsx.locked,2026-07-18 14:02:55.0230000,91007,2,5124,2,.\Users\victim\Documents,RenameNewName
photo_family.jpg,2026-07-18 14:02:55.4470000,91055,2,5124,2,.\Users\victim\Documents,DataOverwrite
photo_family.jpg,2026-07-18 14:02:55.4490000,91055,2,5124,2,.\Users\victim\Documents,RenameOldName
photo_family.jpg.locked,2026-07-18 14:02:55.4490000,91055,2,5124,2,.\Users\victim\Documents,RenameNewName
```

How to read this: the first three rows (`quarterly_report.docx`) are the baseline **ordinary file write** pattern from the Activity Patterns table below — `FileCreate` → `DataExtend|DataOverwrite` → `Close`, one FRN, an unremarkable few-hundred-millisecond span. The last six rows are the **ransomware pattern**: two entirely unrelated files (`invoice_2024.xlsx`, `photo_family.jpg` — different `EntryNumber`s, same parent folder), each hit with `DataOverwrite` immediately followed by a `RenameOldName`/`RenameNewName` pair onto a `.locked` extension, all inside the same one-second window — exactly the dense, cross-file burst the Red Flags table below calls out as the encryption signature. Real casework shows this same shape repeating across every file the encryptor touches, often thousands of times inside the same tight window.

🔴 `fsutil usn` is **live-system-only** — it requires the volume to be mounted and reachable through the OS. It cannot be pointed at a `.E01`/`.dd`/raw image the way MFTECmd can, which is why it belongs in live-response triage, not evidence processing.

## What $UsnJrnl Is and Where It Lives

`$UsnJrnl` lives at **`\$Extend\$UsnJrnl`** — itself just an ordinary $MFT record, filed under the `$Extend` directory alongside `$Quota`, `$ObjId`, and `$Reparse` (the full `$Extend` roster is in [00's NTFS Metadata Files](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) table). Like every other NTFS structure in this folder, it's not a special file type — it's a hidden system file, described by a record, holding named data streams instead of a single `$DATA` blob.

| Fact | Detail |
|---|---|
| Path | `\$Extend\$UsnJrnl` |
| Introduced | Windows 10 1809+ per 00's metadata-file table (present much earlier in Server SKUs and enabled by default on modern client Windows) |
| Purpose | A **change tracking service** — records every create/rename/delete/modify event per volume so consuming software can query "what changed since USN N" instead of enumerating the entire volume on every check |
| Primary consumers | Backup software, antivirus/EDR, Windows Search Indexer, File History, OneDrive/cloud-sync clients, DFSR replication |
| Relationship to `$LogFile` | A **separate**, independently sized and managed journal — see the callout above |

## The Two Streams: $Max and $J

`$UsnJrnl`'s record doesn't carry the interesting data directly — it holds two named data streams (an ADS pair on the same underlying file — see [03's Zone.Identifier and Mark of the Web](03%20-%20%24DATA%20Attribute%20and%20Resident%20vs%20Non-Resident%20Files.md#zone-identifier-and-mark-of-the-web) for the mechanism behind named streams generally):

| Stream | Size | Contents |
|---|---|---|
| **`$Max`** | 32 bytes | Journal-level metadata: maximum journal size, the allocation delta (how much the journal grows by when it needs more space), and the current **Journal ID** |
| **`$J`** | Variable, default **~32 MB** | The actual rolling journal — the full sequence of USN change records, in order |

🔴 **The Journal ID inside `$Max` is a tamper-evidence field in its own right.** It's a unique value assigned when the journal is created, and it **changes if the journal is ever deleted and recreated**. If an examiner queries the journal and the Journal ID doesn't match a previously recorded baseline — or the journal's oldest surviving record is implausibly recent for an aged volume — that discontinuity is itself evidence the journal was cleared or reset, a known anti-forensic move (`fsutil usn deletejournal` is the native command that does it). Always capture the Journal ID early and treat any later mismatch as a finding, not noise.

`$J` is a **fixed-size, circular/rolling log** — once it fills, the oldest records are overwritten to make room for new ones, independent of file age or importance. At the default ~32 MB, retention depends entirely on how much file activity the volume sees: a quiet file server might retain months of history, while a host under heavy churn (or actively being encrypted by ransomware) can cycle through that same 32 MB in minutes. `$J`'s ~32 MB default is sized and managed completely independently of `$LogFile`'s own (typically 64 MB) allocation — don't assume the two journals cover the same time window just because they're both "the journal."

## USN Record Structure and Reason Codes

Every logged change produces one USN record containing (at minimum):

| Field | Meaning |
|---|---|
| File reference number (FRN) | Identifies the specific $MFT record (record number + sequence number, per note 01) that changed |
| Parent FRN | The FRN of the containing directory at the time of the change — the basis for parent-FRN filtering below |
| USN | A monotonically increasing byte-offset value into `$J`, unique per record — the "since when" cursor consuming software uses to know how far it's already read |
| Timestamp | When the change occurred |
| Attributes | The file/directory's attributes at the time of the change |
| Filename | The name in effect at the time of the change |
| Reason code | A **bitmask** describing what kind of change(s) occurred — a single record can (and often does) have multiple reason bits set at once |

The reason-code bitmask is the field an analyst spends the most time reading. This is the practically important subset for DFIR work, not Microsoft's full enumeration — check the current `USN_RECORD` documentation (linked below) if a code is encountered that isn't in this table:

| Reason code | Fires when… |
|---|---|
| `USN_REASON_FILE_CREATE` | A new file or directory was created |
| `USN_REASON_FILE_DELETE` | A file or directory was deleted |
| `USN_REASON_DATA_OVERWRITE` | Existing file data was overwritten |
| `USN_REASON_DATA_EXTEND` | Data was added, growing the file |
| `USN_REASON_DATA_TRUNCATION` | The file was truncated (shrunk) |
| `USN_REASON_RENAME_OLD_NAME` | The record just before a rename — carries the name being replaced |
| `USN_REASON_RENAME_NEW_NAME` | The record immediately after, carrying the new name — same FRN, adjacent USN |
| `USN_REASON_BASIC_INFO_CHANGE` | Attribute or timestamp metadata changed (owner, security, or the four $SI timestamps) — this is the bucket that covers some timestomping activity |
| `USN_REASON_SECURITY_CHANGE` | The file/directory's security descriptor (ACL) changed |
| `USN_REASON_EA_CHANGE` | Extended attributes changed |
| `USN_REASON_CLOSE` | Marks the final record of a burst of changes to that file — the handle was closed |

## Activity Patterns in Journals

Reason codes are far more useful read as **sequences** than as isolated values — most real operations produce a recognizable, repeatable pattern of two or three reason-coded records in a row for the same FRN. Learning to recognize these on sight is most of what makes journal review fast.

| Operation | Expected reason-code sequence | Notes |
|---|---|---|
| New file created and immediately written | `FILE_CREATE` → `DATA_EXTEND` (often `+DATA_OVERWRITE`) → `CLOSE` | The baseline "ordinary file write" pattern — most legitimate application activity looks like this |
| Rename | `RENAME_OLD_NAME` immediately followed by `RENAME_NEW_NAME` | Same FRN, adjacent USN values — the pair is the tell, not either code alone |
| Delete | `FILE_DELETE` → `CLOSE` | No content-change codes alongside it — a clean delete-only burst |
| Timestomp via API | `BASIC_INFO_CHANGE` with **no** nearby `DATA_OVERWRITE`/content-change code | Metadata moved without content moving — a strong correlation point against note 02's $SI/$FN mismatch detection (deep dive in `Windows/19`) |
| 🔴 **Ransomware / mass encryption** | Dense, rapid bursts of `DATA_OVERWRITE` + `RENAME_OLD_NAME`/`RENAME_NEW_NAME` pairs, repeated across a huge number of *unrelated* files in a short window | The "read → encrypt → write over original → rename to `.locked`/ransom-extension" cycle, run thousands of times |

🔴 **`$UsnJrnl` analysis is one of the primary forensic techniques for scoping ransomware blast radius and pinning encryption start/end time.** Because the journal captures every touched file regardless of whether the encryptor leaves any other trace on that specific file, it's frequently the *only* per-file record of what was hit and when — file content itself is gone (encrypted), but the change record survives until it cycles out of `$J`. Plot the burst's first and last USN-tagged timestamp for the affected file set and that window is a defensible encryption start/end time. See the [Ransomware Playbook](../Threat%20Landscape%20and%20Playbooks/Ransomware%20Playbook.md) for the full triage/response sequence this finding feeds into.

## Filtering and Searching the Journal

A parsed `$J` export (tens of thousands to millions of records on an active volume) is unusable without filtering. The axes that actually matter in casework:

| Filter | Use it to… |
|---|---|
| **Reason-code bitmask** | Isolate just deletes (`FILE_DELETE`), or just the ransomware-pattern overwrite+rename bursts (`DATA_OVERWRITE` AND `RENAME_*` together) — the single highest-value filter for incident work |
| **Filename / extension** | Hunt a known ransom-note filename (`README_TO_DECRYPT.txt`, etc.) or a newly appeared extension across the entire journal in one pass |
| **Time window** | Bracket a known incident window (e.g. the encryption burst identified above) to strip out unrelated day-to-day volume activity |
| **Parent FRN** | Reconstruct every recorded change within one specific directory over time — including files that have since been renamed or moved *out* of it, since the record captures the parent FRN at the moment of each change, not the file's current location |

## Journal Tools

| Tool | Form | What it gives you |
|---|---|---|
| **MFTECmd** (Eric Zimmerman) | CLI | The primary offline `$J` parser — decodes reason codes into readable names, resolves filenames/parent paths (especially when run alongside the corresponding `$MFT`), and outputs CSV/JSON ready for pivoting in a spreadsheet or timeline tool. This is the tool for casework against acquired images. |
| **`fsutil usn queryjournal <volume>`** | Native CLI | Confirms the journal exists, and reports its Journal ID, MaxSize, and current USN — the fast way to get a baseline (and check for a Journal ID discontinuity) on a live host |
| **`fsutil usn readjournal <volume>`** | Native CLI | Reads live journal records directly — useful for a fast look during live-response triage |

🔴 Both `fsutil usn` subcommands are **live-system-only**: they require the target volume to be mounted and addressable through the OS, and have no equivalent path for querying a static forensic image the way MFTECmd does. Treat them as a live-triage tool, not an evidence-processing one — extract `$J` (and ideally `$MFT` alongside it) and run MFTECmd for anything that needs to hold up in a report.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Journal ID discontinuity from a previously recorded baseline | The journal was deleted and recreated (`fsutil usn deletejournal` or equivalent) — a strong anti-forensic signal; clearing `$UsnJrnl` is a known evidence-destruction technique (deep dive: `Windows/19`) |
| Dense `DATA_OVERWRITE` + `RENAME_OLD_NAME`/`RENAME_NEW_NAME` bursts across many unrelated files/extensions in a tight time window | The ransomware signature — use it to scope blast radius and bracket encryption start/end time |
| `BASIC_INFO_CHANGE` with no corresponding content-change code nearby | Possible metadata-only manipulation (timestomping) — cross-check against `$SI`/`$FN` for the same FRN |
| A gap in USN sequence numbers larger than the volume's activity level would explain | Either the journal genuinely rolled past that range (normal on a busy volume with a small `$J`), or records were selectively removed — corroborate against `$LogFile`/$MFT before concluding either way |

## Correlate With

| To go deeper on… | Open |
|---|---|
| The lower-level, crash-consistency metadata journal `$UsnJrnl` is often paired against | `05 - $LogFile (NTFS Transaction Journal)` |
| Byte-level $SI/$FN fields underlying the `BASIC_INFO_CHANGE` timestomping correlation | `02 - $STANDARD_INFORMATION and $FILE_NAME Attributes` |
| What else changes (and survives) at each stage of a delete, to read `FILE_DELETE`/`CLOSE` bursts in full context | `07 - File Deletion Mechanics` |
| MACE/MACB behavioral timestamp chart | [02 - $STANDARD_INFORMATION and $FILE_NAME Attributes](02%20-%20%24STANDARD_INFORMATION%20and%20%24FILE_NAME%20Attributes.md#macemacb-behavior-by-operation) |
| The `$Extend` metadata-file roster this note's location sits inside | [00 - NTFS Deep Dive Overview](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) |
| The full timestomping-detection escalation ($SI/$FN → $LogFile → $UsnJrnl) and journal-clearing as an anti-forensic technique | `Windows/19 - Anti-Forensics and Evidence Destruction.md` |
| Full ransomware incident response sequence this note's blast-radius/timing findings feed into | `Windows/Threat Landscape and Playbooks/Ransomware Playbook.md` |

## Resources

- SANS FOR508 "Advanced Incident Response, Threat Hunting, and Digital Forensics" course materials / "Hunt Evil" poster — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools (MFTECmd) — https://ericzimmerman.github.io/
- Microsoft Learn — `USN_RECORD` structure reference (full reason-code enumeration) — https://learn.microsoft.com/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
- Microsoft Learn — Change Journals overview — https://learn.microsoft.com/windows/win32/fileio/change-journals
- Microsoft Learn — `fsutil usn` command reference — https://learn.microsoft.com/windows-server/administration/windows-commands/fsutil-usn
