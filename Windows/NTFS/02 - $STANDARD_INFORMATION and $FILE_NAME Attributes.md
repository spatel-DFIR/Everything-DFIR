# $STANDARD_INFORMATION and $FILE_NAME Attributes

Every file and folder's $MFT record carries two attributes that both look, at a glance, like "the file's timestamps" — but they are structurally distinct data structures, sitting in different attribute slots, written through different code paths, and reachable through different tools. This note covers both layers: the byte-level field layout of `$STANDARD_INFORMATION` (type `0x10`) and `$FILE_NAME` (type `0x30`) inside the record, plus the handful of record-header fields that set expectations before either attribute is even opened — **and** the behavioral layer, the full MACE/MACB chart showing exactly which field changes on which operation, split by Windows 10 and Windows 11 (see [MACE/MACB Behavior by Operation](#macemacb-behavior-by-operation) below).

> 🔴 **The structural fact underneath the detection technique below:** $SI is the only timestamp set exposed through the Win32 file-time API surface — `SetFileTime`/`GetFileTime`, and everything built on top of them, including Explorer's Properties dialog and PowerShell's `Set-ItemProperty`/`(Get-Item x).CreationTime = ...`. `timestomp.exe` and its equivalents rewrite $SI convincingly because that's the only timestamp attribute those APIs can reach. $FILE_NAME sits in a different attribute, touched only by namespace operations (create/rename/move), and ordinary file-time APIs never come near it — which is exactly why it survives as the tell.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [MFT Entry Header: What It Tells You First](#mft-entry-header-what-it-tells-you-first)
- [$STANDARD_INFORMATION — Attribute Type 0x10](#standard_information--attribute-type-0x10)
- [$FILE_NAME — Attribute Type 0x30](#file_name--attribute-type-0x30)
- [MACE/MACB Behavior by Operation](#macemacb-behavior-by-operation)
  - [PowerShell](#powershell)
- [exiftool: Embedded Metadata, Not Filesystem Metadata](#exiftool-embedded-metadata-not-filesystem-metadata)
- [Two Timestamp Sets, Not Two Kinds of Timestamp](#two-timestamp-sets-not-two-kinds-of-timestamp)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

`istat` and MFTECmd are the two tools that actually reach $FILE_NAME — native PowerShell cannot (see [Two Timestamp Sets](#two-timestamp-sets-not-two-kinds-of-timestamp) below).

```bash
# istat prints BOTH attribute blocks for one record, in order: "$STANDARD_INFORMATION Attribute Values"
# first, then "$FILE_NAME Attributes" (once per $FN present) - eyeball the two timestamp blocks side by side
istat -o 128 evidence.dd 64321

# fls confirms the parent-directory reference a $FILE_NAME claims actually resolves to a real, live directory
# entry - run this against the parent record number reported by istat's $FILE_NAME block
fls -o 128 evidence.dd 5-144-1
```

```powershell
# MFTECmd CSV output labels $SI-derived columns "...0x10" and $FN-derived columns "...0x30" - confirm the
# exact header row against your build before scripting (column names have shifted slightly across EZ releases)
.\MFTECmd.exe -f "C:\triage\$MFT" --csv C:\triage\out --csvf mft.csv
```

**Representative output** (illustrative — hand-assembled to show the shape of two `mft.csv` rows, not a literal capture from a specific $MFT):

```
EntryNumber,FileName,ParentPath,Created0x10,Created0x30,LastModified0x10,LastModified0x30
45123,invoice.pdf,C:\Users\user\Downloads,2026-07-18 18:02:11,2026-07-18 18:02:11,2026-07-18 18:02:11,2026-07-18 18:02:11
45210,evil.exe,C:\Windows\Temp,2023-01-05 09:14:00,2026-07-18 18:04:47,2023-01-05 09:14:00,2026-07-18 18:04:47
```

The first row is a normal file — $SI and $FN Created agree to the second. The second row is the timestomping signature: `Created0x10` (attacker-set, via `SetFileTime`) claims January 2023, while `Created0x30` (untouched by that API) shows the file actually landed on the volume minutes ago.

```powershell
# Flag records where $SI Created and $FN Created disagree by more than a few seconds - the structural
# $SI-vs-$FN mismatch that the Red Flags table below calls the strongest available timestomping indicator
Import-Csv C:\triage\out\mft.csv | Where-Object {
    $_.Created0x10 -and $_.Created0x30 -and
    [Math]::Abs(([datetime]$_.Created0x10 - [datetime]$_.Created0x30).TotalSeconds) -gt 60
} | Select-Object FileName, ParentPath, Created0x10, Created0x30
```

🔴 Both commands above are structural-comparison leads, not proof — treat a hit as a reason to open the full record in `istat` and cross-check against `$LogFile`/`$UsnJrnl` before writing it up.

Native PowerShell can only reach $SI (see [Two Timestamp Sets](#two-timestamp-sets-not-two-kinds-of-timestamp) below), but that's still enough to surface the file-copy and bulk-timestomping signatures described in [MACE/MACB Behavior by Operation](#macemacb-behavior-by-operation):

```powershell
# Files whose Created time is after LastWriteTime by more than a few seconds - the file-copy signature (see MACE table below); worth a second look combined with other flags
Get-ChildItem -Path C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $_.LastWriteTime.AddSeconds(5) } | Select-Object FullName, CreationTime, LastWriteTime

# Files whose LastWriteTime predates CreationTime by more than a year - beyond what a benign copy explains, worth treating as a possible timestomp
Get-ChildItem -Path C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime - $_.LastWriteTime -gt (New-TimeSpan -Days 365) } | Select-Object FullName, CreationTime, LastWriteTime

# Unrelated files in the same folder sharing the exact same timestamp to the second - a classic bulk-timestomping tell
Get-ChildItem -Path C:\Windows\System32 -Force -File | Group-Object LastWriteTime | Where-Object Count -gt 1 | Select-Object Count, Name
```

## MFT Entry Header: What It Tells You First

The fixed-length record header sits above every attribute in the record — full byte layout (signature, fixup array, sequence number, first-attribute offset) is [01 - MFT Entry Structure and Attributes](01%20-%20MFT%20Entry%20Structure%20and%20Attributes.md)'s job. Two header fields, plus three fields commonly *assumed* to be header-level but actually stored inside $SI, are worth knowing before opening either attribute:

| Field | Actually lives in | What it tells you |
|---|---|---|
| **Link count** | Record header | The number of hard links (names) the file has — sets the baseline expectation for how many $FILE_NAME attributes this record should carry, since Windows creates one $FN per hard link. See the namespace caveat under $FILE_NAME below — the real count can run one higher than link count. |
| **Allocation status** (in-use bit) | Record header `Flags` field | Whether the $MFT considers this record a live file/folder right now vs. freed and awaiting reuse — full flag-byte layout is 01's job. |
| **Object type** (file vs. directory) | Record header `Flags` field | The same `Flags` field carries a second low-order bit alongside the in-use bit: in-use (`0x0001`) and is-directory (`0x0002`) are the two bits worth knowing at this level — a record with the is-directory bit set is a folder, not a file, regardless of what its $FN namespace or extension implies. Full flag-byte layout, including any additional reserved bits, is 01's job. |
| **DOS-style file attributes** (Archive/Hidden/System/ReadOnly, etc.) | 🔴 **$STANDARD_INFORMATION, not the record header** | A common mix-up: the record header's own `Flags` field only encodes structural state (in-use / is-directory). The Explorer-visible Archive/Hidden/System/ReadOnly bits are a completely separate field, inside $SI — see the table below. |
| **Security ID** | $STANDARD_INFORMATION | An index into `$Secure`, NTFS's deduplicated security-descriptor store — see the [$Secure row](00%20-%20NTFS%20Deep%20Dive%20Overview.md#ntfs-metadata-files) in 00's NTFS Metadata Files table. Many files sharing one Security ID means their ACLs moved together. |
| **USN** | $STANDARD_INFORMATION | The USN of the last change `$UsnJrnl` recorded for this record — a direct structural pointer from the $MFT row to its most recent journal entry. Deep dive: [06 - $UsnJrnl (USN Change Journal)](06%20-%20%24UsnJrnl%20%28USN%20Change%20Journal%29.md). |
| **$LogFile Sequence Number (LSN)** | Record header (not $SI) | Points to the last `$LogFile` transaction that touched this record. Worth flagging precisely: some references lump this in as a $SI field alongside USN — it isn't; it's a header-level pointer that covers the whole record, not just $SI. Deep dive: [05 - $LogFile (NTFS Transaction Journal)](05%20-%20%24LogFile%20%28NTFS%20Transaction%20Journal%29.md). |

## $STANDARD_INFORMATION — Attribute Type 0x10

Always resident, always exactly one per record, present on every file and folder without exception. This is the attribute Explorer, `dir`, `Get-Item`, and most forensic tools read by default — call it the **front door** timestamp set, because it's the only one any of them reach without a dedicated $MFT parser.

| Field | Size | Notes |
|---|---|---|
| Created (B/C) | 8 bytes, FILETIME | See [MACE/MACB Behavior by Operation](#macemacb-behavior-by-operation) below for what changes this field per operation — this table only covers what the field *is*. |
| Modified (M) | 8 bytes, FILETIME | Same — behavior chart below, not this table. |
| MFT/Entry Modified (E/C) | 8 bytes, FILETIME | Same. |
| Accessed (A) | 8 bytes, FILETIME | Same. |
| DOS file attribute flags | 4 bytes | Archive/Hidden/System/ReadOnly and friends — bit table below. |
| Maximum versions | 4 bytes | Part of an NTFS file-versioning feature that was never fully exposed to end users — rarely populated, rarely useful. |
| Version number | 4 bytes | Same legacy versioning feature, rarely used. |
| Class ID | 4 bytes | Legacy/reserved, essentially never populated on modern volumes. |
| Owner ID | 4 bytes | NTFS 3.0+ quota-tracking field — identifies which quota owner this file is charged against. |
| Security ID | 4 bytes | Index into `$Secure` — see the header table above. |
| Quota charged | 8 bytes | Bytes charged against the owning user's disk quota, if quotas are enabled. |
| USN | 8 bytes | Last `$UsnJrnl` sequence number for this record — see the header table above. |

**DOS file attribute flags** (the field most examiners actually care about in $SI beyond the timestamps):

| Bit (hex) | Attribute |
|---|---|
| `0x0001` | Read-Only |
| `0x0002` | Hidden |
| `0x0004` | System |
| `0x0020` | Archive |
| `0x0080` | Normal (no other attributes set) |
| `0x0100` | Temporary |
| `0x0200` | Sparse File |
| `0x0400` | Reparse Point |
| `0x0800` | Compressed |
| `0x1000` | Offline |
| `0x2000` | Not Content Indexed |
| `0x4000` | Encrypted |

These match the standard Win32 `FILE_ATTRIBUTE_*` constants — $SI stores them directly, which is why `Get-ItemProperty`'s `Attributes` field is a straight read of this one $SI field. A couple of high-order bits are NTFS-internal-only (directory/index-related) and not worth asserting exact values for here; if a parser surfaces an unfamiliar high bit, check that tool's own documentation rather than assuming it maps to a Win32 constant.

## $FILE_NAME — Attribute Type 0x30

Always resident. Unlike $SI, **$FILE_NAME is not a singleton** — one $FN attribute exists per hard link/name the file has, tying directly back to the link-count field in the header above.

| Field | Size | Notes |
|---|---|---|
| Parent directory reference | 8 bytes | The containing folder's own $MFT record number (48 bits) + sequence number (16 bits), packed into one file reference. 🔴 This is the entire mechanism by which NTFS encodes "what folder is this file in" — there is no separate path string stored anywhere on disk. A full path is reconstructed at parse time by walking parent references record by record up to the volume root. |
| Created | 8 bytes, FILETIME | $FN's own copy, structurally independent of $SI's Created field — see [Two Timestamp Sets](#two-timestamp-sets-not-two-kinds-of-timestamp) below. |
| Modified | 8 bytes, FILETIME | Same — independent copy. |
| MFT Modified | 8 bytes, FILETIME | Same. |
| Accessed | 8 bytes, FILETIME | Same. |
| Allocated size | 8 bytes | Duplicated here from $DATA's own allocated size, so a directory listing built from `$I30` (deep dive: [04 - $I30 Directory Index and B-Trees](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md)) can show a size in Explorer without opening the file's own $DATA attribute. |
| Real size | 8 bytes | Same duplication, for the file's actual logical byte length rather than the cluster-rounded allocation. |
| Flags | 4 bytes | A duplicated copy of the DOS attribute flags (see $SI's bit table above) — again so `$I30` doesn't need to cross-reference $SI just to render an icon/attribute in a folder view. |
| Reparse value / EA size | 4 bytes | A union field used only when the file is a reparse point or carries extended attributes — hedge on exact sub-layout here; verify against your parser's own field breakdown if this matters to the case. |
| Filename length | 1 byte | Length of the filename that follows, in UTF-16 characters. |
| Namespace flag | 1 byte | Which naming convention this $FN uses — table below. |
| Filename | Variable, up to 255 UTF-16 characters | The actual Unicode name for this $FN entry. |

**Namespace flag values** — this is the field that explains why a single file can carry more than one $FN:

| Value | Namespace | When it's used |
|---|---|---|
| `0` | POSIX | Case-sensitive, permits nearly any Unicode character except the null byte and path separators — used by POSIX-subsystem-aware creation paths; no auto-generated 8.3 name accompanies it. |
| `1` | Win32 | The normal long filename most files carry. |
| `2` | DOS | An auto-generated 8.3 short name, created only when the Win32 long name doesn't already satisfy 8.3 rules (too long, contains spaces/invalid characters, mixed case not representable, etc.). |
| `3` | Win32 + DOS | A single, combined $FN entry used when the long name is *already* legal under 8.3 rules — in that case NTFS doesn't bother generating a separate short-name entry at all. |

🔴 **This is why link count and $FN count aren't always exactly equal.** A file with link count 1 can carry either one $FN (namespace 3, Win32+DOS combined, when the name is already 8.3-legal) or two $FN attributes (namespace 1 and namespace 2 separately, when a short name had to be generated). Expect `$FN count ≥ link count` as the baseline, not strict equality — factor in the 8.3-generation caveat before flagging a mismatch as anomalous (see [Red Flags](#red-flags)).

## MACE/MACB Behavior by Operation

"MACE" (EnCase/FTK/X-Ways convention: Modified/Accessed/Entry-modified/Created) and "MACB" (log2timeline/plaso convention: Modified/Accessed/Changed/Birth) are two different tool vendors' letter names for the **same four $SI fields** covered structurally above — not a different timestamp set. Behavior differs meaningfully between Windows 10 and Windows 11 (Windows 11 reintroduced Access-time updates that Windows 10, and every version back to Vista, suppresses by default), so the tables below are kept separate rather than merged with footnotes.

Read each cell as: field — what it becomes. "No Change" means the field retains whatever value it already held.

**Windows 10 (1903+)**

| Operation | Modified | Accessed | Metadata (Entry Modified) | Created |
|---|---|---|---|---|
| **File Creation** | Time of creation | Time of creation | Time of creation | Time of creation |
| **File Access** (open/read, no edit) | No change | No change (`NtfsDisableLastAccessUpdate` = 1 by default since Vista — reads don't move this field at all) | No change | No change |
| **File Modification** (content edited) | Time of edit | Time of edit | Time of edit | No change |
| **File Rename** (same folder) | No change | No change | Time of rename | No change |
| **File Copy** (creates a new file) | 🔴 **Inherited from the source file** | Time of copy | Time of copy | Time of copy |
| **Local File Move** (same volume, same drive letter) | No change | No change | Time of move | No change |
| **Volume File Move — CLI** (`move`/PowerShell across volumes) | Inherited from source | Time of move | Time of move | Inherited from source |
| **Volume File Move — cut/paste via Explorer** (across volumes) | Inherited from source | Time of cut/paste | Inherited from source | Inherited from source |
| **File Deletion** (Shift+Delete / Recycle Bin) | No change | No change | No change | No change |

**Windows 11 (22H2)**

| Operation | Modified | Accessed | Metadata (Entry Modified) | Created |
|---|---|---|---|---|
| **File Creation** | Time of creation | Time of creation | Time of creation | Time of creation |
| **File Access** (open/read, no edit) | No change | 🔴 **Time of access** (Windows 11 reintroduced this) | No change | No change |
| **File Modification** (content edited) | Time of edit | Time of edit* | Time of edit | No change |
| **File Rename** (same folder) | No change | Time of rename* | Time of rename | No change |
| **File Copy** (creates a new file) | Inherited from source | Time of copy | Time of copy | Time of copy |
| **Local File Move** (same volume, same drive letter) | No change | Time of move | Time of move | No change |
| **Volume File Move — CLI** | Inherited from source | Time of move | Time of move | Inherited from source |
| **Volume File Move — cut/paste via Explorer** | Inherited from source | Time of cut/paste | Inherited from source | Inherited from source |
| **File Deletion** (Shift+Delete / Recycle Bin) | No change | No change | No change | No change |

\* Marked fields are noted by SANS's own testing as **approximate on Windows 11** — the Access-time value can land a few seconds off the true time of activity. Treat Windows 11 access times as "roughly when," not "precisely when."

**What Changed Between Them**

| Behavior | Windows 10 | Windows 11 | Why it matters |
|---|---|---|---|
| Access time on a simple file open/read | Frozen — never updates | Updates, but only approximately | On Windows 11, "last accessed" is usable circumstantial evidence again; on Windows 10 it is frozen at whatever the last write/copy/move set it to, so don't read it as "last opened" |
| Access time on modification/rename | Follows the Modified/Metadata value (no independent movement) | Updates independently, imprecisely | A Windows 11 host can show an Access time that's a few seconds *after* the Modified time on the same operation — don't treat that ordering as anomalous on Windows 11 |
| Local move | Only Metadata updates | Access **and** Metadata update | A local drag-and-drop on Windows 11 leaves a slightly richer trail than the same action on Windows 10 |

Two rules that hold on every version and are worth memorizing on their own:

1. **A file copy always fabricates a new Creation and Access time, but *inherits* the Modified time from the source.** This is the single most exploitable/misread fact on the whole chart: a freshly copied file's Modified timestamp can predate its own Created timestamp — that is *normal*, not evidence of tampering, and is the standard giveaway that a file arrived via copy rather than being authored in place.
2. **File deletion changes nothing in $SI on the file record itself** — the file's own four timestamps freeze at whatever they were the instant before deletion. What *does* get a fresh timestamp is the Recycle Bin's own metadata record (the paired `$I` file — full mechanics in [07 - File Deletion Mechanics](07%20-%20File%20Deletion%20Mechanics.md)) — that's where "when was this deleted" actually lives, not on the deleted file's own MFT entry.

### PowerShell

Native PowerShell only reaches $SI, never $FN (see [Two Timestamp Sets](#two-timestamp-sets-not-two-kinds-of-timestamp) below for why) — but $SI alone is enough to pull and interpret the MACE/MACB behavior above.

**Basic:**

```powershell
Get-Item -Path 'C:\path\to\file.exe' | Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime
Get-ItemProperty -Path 'C:\path\to\file.exe' | Select-Object CreationTime, LastWriteTime, LastAccessTime, Attributes
```

**Interpret:**

```powershell
# Confirms the file-copy signature from the MACE table: Modified predates Created
$f = Get-Item 'C:\path\to\file.exe'
if ($f.LastWriteTime -lt $f.CreationTime) { "Copy signature: Modified ($($f.LastWriteTime)) predates Created ($($f.CreationTime))" }
```

**Advanced:**

```powershell
# Recursively export $SI timestamps for every file under a path to CSV for timeline pivoting
Get-ChildItem -Path D:\ -Recurse -Force -File -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime | Export-Csv -Path C:\triage\ntfs_timestamps.csv -NoTypeInformation

# Same copy-signature check run across a list of remote hosts, results tagged per host
Invoke-Command -ComputerName (Get-Content C:\triage\hosts.txt) -ScriptBlock { Get-ChildItem -Path C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $_.LastWriteTime.AddSeconds(5) } | Select-Object PSComputerName, FullName, CreationTime, LastWriteTime }
```

## exiftool: Embedded Metadata, Not Filesystem Metadata

**exiftool** is the field-standard tool for reading and writing **embedded, application-level metadata** carried *inside* a file's own format (EXIF/IPTC/XMP in images, document author/revision/company fields in Office files, PDF creator/producer/creation-date fields, and hundreds of other format-specific metadata schemas).

🔴 **exiftool complements filesystem timestamp analysis — it does not replace it, and the two frequently disagree on purpose.** The MACE/MACB chart above describes NTFS's own $SI/$FN timestamps — filesystem-level facts about operations performed on the file as an opaque blob of bytes. exiftool reads a completely separate set of values that the *authoring application* embedded inside the file's own content — a photo's EXIF "Date Taken" reflects when the camera's shutter fired, which can predate the filesystem's Creation time by years if the photo was copied from an SD card long after it was shot; a Word document's embedded author/last-saved-by fields can name a user who never touched the file's actual $MFT record on this host at all (e.g., a document authored elsewhere and only copied here). Cross-referencing the two — filesystem timestamps against embedded application metadata — is a standard technique for catching backdated or relocated evidence, and for attributing authorship independent of whichever account happened to touch the file on the host under examination.

**Commands:**

```bash
# Key embedded date fields most likely to diverge from filesystem timestamps
exiftool -AllDates -CreateDate -ModifyDate -FileModifyDate photo.jpg

# Recursive CSV export of embedded metadata for every file under a folder - built for
# timeline pivoting alongside the $SI/$FN exports covered under PowerShell above
exiftool -csv -r C:\Users\user\Downloads > embedded_metadata.csv
```

**Cross-referencing embedded metadata against filesystem timestamps on the same file** — the concrete version of the technique described above, not just the narrative:

```bash
exiftool -DateTimeOriginal -Author photo.jpg
```

```powershell
Get-Item photo.jpg | Select-Object CreationTime, LastWriteTime
```

**Representative output** (illustrative — hand-assembled to show the shape and meaning of a real cross-reference, not a literal capture from a specific file):

```
DateTimeOriginal                : 2023:04:12 09:14:33
Author                          : J. Alvarez

CreationTime                    : 7/18/2026 6:02:11 PM
LastWriteTime                   : 7/18/2026 6:02:11 PM
```

🔴 **The disagreement is the finding.** EXIF `DateTimeOriginal` says the shutter fired in April 2023; the filesystem's `CreationTime` says this copy landed on this host two days ago. Neither value is "wrong" — they answer different questions — but a photo whose embedded capture date is three years older than its filesystem Created time is exactly the kind of relocated/backdated-evidence signal the [Red Flags](#red-flags) table below calls out.

## Two Timestamp Sets, Not Two Kinds of Timestamp

The "2 types of timestamps" framing analysts sometimes reach for resolves to exactly this: **$SI's four-field set vs. $FN's four-field set** — not, as it's easy to assume at a glance, some split between "creation-type" timestamps and "modification-type" timestamps. Both $SI and $FN each carry a full Created/Modified/MFT-Modified/Accessed set; a single $MFT record can hold **eight timestamps total per name** once you count both attributes.

Why the two sets are reachable so differently comes down to which code path each one sits on:

| | $STANDARD_INFORMATION | $FILE_NAME |
|---|---|---|
| Reached by | `GetFileTime`/`SetFileTime` and everything built on them — Explorer Properties, PowerShell `Get-Item`/`Set-ItemProperty`, `timestomp.exe` | Only namespace operations (create/rename/move-between-directories); no Win32 file-time API touches it |
| Native PowerShell reach | Full — see [PowerShell](#powershell) under MACE/MACB Behavior above | None — requires a dedicated $MFT parser (`istat`, MFTECmd) |
| Structural reason | These APIs operate on an open file handle, which resolves through $SI | This is metadata about the file's *name and location*, which lives on the directory/namespace side of NTFS's structure, not the open-handle side |

**The mechanism of timestomping, at this structural level:** a tool like `timestomp.exe`, or PowerShell's `(Get-Item x).CreationTime = ...`, calls the same Win32 file-time APIs any legitimate application would use to set a timestamp. Those APIs have exactly one destination — $SI — because $SI is the only timestamp attribute exposed through that API surface at all. $FN is essentially unreachable through normal Win32 calls; nothing in ordinary file I/O ever asks NTFS to touch it. That's the whole reason $FN survives untouched as the tell: it isn't that timestomping tools *choose* to leave it alone, it's that the API surface they're built on never offers a way to reach it. For the actual detection technique — comparing the two sets and reading the mismatch — see the [Red Flags](#red-flags) row below on $SI-vs-$FN mismatch.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Link count and $FN count disagree by more than the 8.3-namespace caveat explains | Expect `$FN count ≥ link count`, with the gap explained by namespace-3 (combined) vs. namespace-1/2 (split) short-name generation — a gap beyond that is worth a second look, not an automatic anomaly |
| A $FN's parent directory reference doesn't resolve to a live, valid directory record | Either an orphaned name (see [Orphan Files and the Recycle Bin Record Pair](07%20-%20File%20Deletion%20Mechanics.md#orphan-files-and-the-recycle-bin-record-pair) in 07) or a deliberately forged reference — confirm with `fls`/`istat` against the claimed parent record number before trusting the reconstructed path |
| USN field in $SI is stale or zero on a record that otherwise shows recent activity | Either `$UsnJrnl` was cleared/disabled around that time, or the record was modified through a path that bypassed normal journaling — cross-check against [06 - $UsnJrnl](06%20-%20%24UsnJrnl%20%28USN%20Change%20Journal%29.md) directly |
| LSN in the record header is stale or zero despite a $SI/$FN change that should have generated a `$LogFile` transaction | Possible offline or non-transactional tampering with the record — cross-check against [05 - $LogFile](05%20-%20%24LogFile%20%28NTFS%20Transaction%20Journal%29.md) for the expected transaction |
| $SI and $FN timestamp sets disagree beyond what a legitimate operation explains | The single strongest structural timestomping indicator — see [Two Timestamp Sets](#two-timestamp-sets-not-two-kinds-of-timestamp) above and the MACE/MACB tables for what a legitimate operation would actually produce |
| Modified time earlier than Created time | Classic file-copy signature (Modified inherits from source, Created is fabricated fresh) — not inherently suspicious alone, but confirms the file arrived by copy rather than being authored in place |
| Access time behavior that doesn't match the host's actual OS version (e.g., Access time updating on simple read on a Windows 10 host) | Either a misidentified OS version, an unusual `NtfsDisableLastAccessUpdate` registry change, or the value came from something other than an ordinary read |
| exiftool embedded metadata (author, GPS, "date taken") contradicting the filesystem timestamps for the same file | Possible relocation/backdating of evidence, or the file simply originated elsewhere before arriving on this host |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full record header layout, fixup array, sequence numbers, allocation status byte details | [01 - MFT Entry Structure and Attributes](01%20-%20MFT%20Entry%20Structure%20and%20Attributes.md) |
| Recent metadata transactions that can contradict a doctored LSN/record | [05 - $LogFile (NTFS Transaction Journal)](05%20-%20%24LogFile%20%28NTFS%20Transaction%20Journal%29.md) |
| The longer-lived change history behind a record's USN field | [06 - $UsnJrnl (USN Change Journal)](06%20-%20%24UsnJrnl%20%28USN%20Change%20Journal%29.md) |
| How a directory listing built from $I30 uses $FN's duplicated size/flags fields | [04 - $I30 Directory Index and B-Trees](04%20-%20%24I30%20Directory%20Index%20and%20B-Trees.md) |
| What survives in $SI/$FN through Recycle Bin deletion and record reuse | [07 - File Deletion Mechanics](07%20-%20File%20Deletion%20Mechanics.md) |

## Resources

- SANS FOR508 "Advanced Incident Response" course material — MFT Entry Header & $STANDARD_INFORMATION, $FILE_NAME & Attributes Summary, Timestamps & Manipulation — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- The Sleuth Kit documentation (`istat`, `fls`) — https://wiki.sleuthkit.org/
- Eric Zimmerman's tools (MFTECmd) — https://ericzimmerman.github.io/
- Microsoft Learn — How NTFS Works (MFT record and attribute structure): https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
- MITRE ATT&CK: T1070.006 (Indicator Removal: Timestomp)
