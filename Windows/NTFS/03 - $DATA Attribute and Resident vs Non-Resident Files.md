# $DATA Attribute and Resident vs Non-Resident Files

Every question that starts with "where is this file's actual content" ends at the same attribute: $DATA. This note covers what $DATA is, the single most consequential fork in NTFS file storage — resident (content embedded in the $MFT record itself) versus non-resident (content out in data runs on the volume) — the three size fields that describe non-resident content precisely, and the two tools that pull that content back out: MFTECmd for resident data still sitting inside a raw $MFT, and The Sleuth Kit's `icat` for content addressed by inode number against an image.

> 🔴 **A file's content and a file's metadata are not guaranteed to be near each other on disk — unless the file is small enough that they're the same thing.** A resident file's bytes live inside its own $MFT record, a few hundred bytes from its own timestamps. A non-resident file's bytes can be anywhere on the volume the data runs point to. That fork changes what survives deletion, what a hex-editor pass over a raw $MFT extract can recover without ever touching the volume's clusters, and what "the file was overwritten" even means.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What $DATA Is](#what-data-is)
- [Resident vs Non-Resident: The Core Mechanic](#resident-vs-non-resident-the-core-mechanic)
- [Actual Size vs Initialized Size vs Allocated Size](#actual-size-vs-initialized-size-vs-allocated-size)
- [MFTECmd: Dumping Resident Data Straight From the $MFT](#mftecmd-dumping-resident-data-straight-from-the-mft)
- [Extracting Data with The Sleuth Kit's `icat`](#extracting-data-with-the-sleuth-kits-icat)
- [ADS Extraction with `icat`](#ads-extraction-with-icat)
- [Zone.Identifier and Mark of the Web](#zoneidentifier-and-mark-of-the-web)
  - [PowerShell](#powershell)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

TSK-oriented one-liners — run against a mounted image or raw device, `mmls` output in hand for the correct sector offset (see `00 - NTFS Deep Dive Overview.md`'s Tool Roster).

```bash
# Slack-space sweep across every inode in a directory listing - pulls file content
# PLUS trailing cluster slack for every entry fls reports, dumped to per-inode files
fls -o 128 image.dd 5-144-1 | grep -oE '[0-9]+$' | while read inode; do
    icat -o 128 -s image.dd "$inode" > "slack_${inode}.bin"
done

# istat first to confirm resident vs non-resident and get the raw attribute list,
# then icat to pull the content that record's $DATA attribute actually points to
istat -o 128 image.dd 45123
icat -o 128 image.dd 45123 > recovered_45123.bin

# Recover mode against a specific deleted-but-not-yet-reused inode, hex-eyeballed
# rather than trusted as a clean file - see -r caveats below
icat -o 128 -r image.dd 45123 | xxd | less
```

```powershell
# Native ADS listing one-liner (full ZoneId/ReferrerUrl decode owned by the
# Zone.Identifier section below - fast triage here, not duplicated) - anything beyond :$DATA is worth a look
Get-ChildItem -Path C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } | Where-Object { $_.Stream -notin ':$DATA','Zone.Identifier' } | Select-Object FileName, Stream, Length
```

## What $DATA Is

$DATA is attribute type **0x80** inside an $MFT record — the attribute that answers "where does this file's content actually live." Every file has at least one $DATA attribute: the **unnamed stream**, the "main" content a user or application means when they open the file. Nothing else in the record carries file content — $STANDARD_INFORMATION and $FILE_NAME (covered in `02 - $STANDARD_INFORMATION and $FILE_NAME Attributes.md`) carry timestamps and naming, not bytes.

**Alternate Data Streams are structurally nothing more than additional named $DATA attributes on the same $MFT record.** NTFS allows more than one $DATA attribute per record as long as each one beyond the first carries a name (`filename:streamname`); the unnamed stream and any number of named streams coexist on the same record, each independently resident or non-resident, each with its own size fields. The most consequential named stream an analyst will encounter is `Zone.Identifier` (Mark of the Web) — see [Zone.Identifier and Mark of the Web](#zoneidentifier-and-mark-of-the-web) below for its full structure (ZoneId values, ReferrerUrl/HostUrl, how attackers strip it); this note only establishes the mechanical fact that ADS *is* $DATA, not a separate structure, and covers extracting one with `icat` next.

## Resident vs Non-Resident: The Core Mechanic

Every $DATA attribute (unnamed or named) is stored one of two ways, signaled by a single **non-resident flag** in the attribute header:

| | Resident (flag 0x00) | Non-Resident (flag 0x01) |
|---|---|---|
| **Trigger** | Content small enough to fit in whatever space remains in the ~1024-byte $MFT record after $SI, $FN, attribute headers, and security descriptor pointer have already claimed their share — in practice a ceiling in the rough **~700–800 byte** range, not a fixed number (note 01's "~600 bytes usable" figure is the same ceiling, framed conservatively; the exact number is whatever's left over on that specific record, not a constant NTFS enforces) | Content exceeds whatever's left in the record |
| **Where content lives** | Embedded directly inside the $MFT record itself, immediately after the attribute header | Out in clusters elsewhere on the volume; the $DATA attribute stores only a compact **data run list** — (starting cluster, run length) pairs — plus the three size fields below. This is the same data-run mechanic the whole folder's mental model rests on (`00 - NTFS Deep Dive Overview.md#the-core-mental-model-database-vs-chain`) — far more compact than a FAT-style per-cluster chain, especially for a large contiguous file where one run entry covers the whole extent instead of one FAT table entry per cluster |
| **Survives file deletion how, and for how long** | Survives exactly as long as the $MFT record itself survives before the record is marked free and reused by a new file — content and metadata share one fate, one lifespan | Survives only as long as **both** the $MFT record *and* the specific clusters the data runs point to remain unreused — the record can survive deletion while its clusters get independently reallocated to an unrelated file, silently breaking the recovery even though the metadata still looks intact |
| **Forensic implication** | A stronger recovery case than non-resident for small files — recovering a freed-but-unreused record recovers the *complete* file, content included, no cluster allocation state to check. This is exactly what makes a raw $MFT extract worth mining on its own (see MFTECmd below) | Recovery requires the record **and** confirmation the referenced clusters haven't been reallocated (cross-check against `$Bitmap`) — a surviving record with reused clusters yields correct metadata (name, timestamps, size) but garbage or unrelated content when the data runs are followed |

🔴 **Resident content and non-resident content are addressed identically by `icat`** — the tool reads whichever the attribute header says, and the analyst doesn't need to know in advance which kind a given inode holds. But an analyst reading a hex dump or `istat` output directly absolutely does need to know which fork applies before drawing any conclusion about where else on the volume to look.

## Actual Size vs Initialized Size vs Allocated Size

Non-resident $DATA carries three separate size fields in its header, and the gaps between them are themselves forensic signal — this only applies to non-resident content, since resident content has no cluster allocation to round up to.

| Field | What it means | Relationship to the others |
|---|---|---|
| **Allocated size** | Total space physically reserved for the file across its clusters — always a multiple of the volume's cluster size | Always ≥ real size (rounding up to the next full cluster) |
| **Real size** (actual size) | The file's true logical byte length — what `dir`, Explorer, and every normal size display report | ≤ allocated size (the gap is ordinary cluster-rounding slack, forensically routine); ≥ initialized size |
| **Initialized size** | The boundary up to which data has actually been *written* — bytes between initialized size and real size have never been written and read back as zero on demand rather than existing on disk | ≤ real size |

🔴 **A real-size/initialized-size mismatch on a file that has no legitimate reason to be sparse is worth stopping on.** A file extended via `SetEndOfFile` (or an equivalent pre-allocation call) without writing all the way to the new logical end reports a real size larger than what's actually been committed to disk — the unwritten tail reads as zero rather than holding recoverable content. Two readings matter: this is exactly how legitimate sparse files and pre-allocated download/database files behave, **and** it's a known anti-forensic space-reservation trick (reserve a large logical size, write nothing) and a signature of an interrupted exfiltration or download — a file whose real size matches the expected complete artifact but whose initialized size stops short is evidence the write never finished, not evidence the content is all there.

## MFTECmd: Dumping Resident Data Straight From the $MFT

Because a resident $DATA attribute's bytes sit inside the $MFT record itself, **MFTECmd can export that content directly to disk while parsing the $MFT — no volume, no cluster allocation, no image mount required.** This matters for exactly the small-file cases where resident storage is common: an NTFS reparse point payload, a tiny text file or config, or a fragment of a deleted file whose $MFT record survived record reuse but whose clusters (if it had ever gone non-resident) would already be gone. Pulling resident content straight out of a raw `$MFT` extract sidesteps the whole "are the clusters still there" question this note's resident-vs-non-resident table raises — for a resident file, there's nothing else to check.

As of MFTECmd (EZ Tools) current releases, the flag is `--dr` ("dump resident"), used alongside the normal `$MFT` parse:

```powershell
# Dump every resident $DATA attribute to disk while parsing the $MFT - files land in a
# "Resident" subdirectory under the --csv output path, named
# <EntryNumber>-<SequenceNumber>-<AttributeNumber>_<FileName>.bin
.\MFTECmd.exe -f "C:\triage\$MFT" --csv C:\triage\out --csvf mft.csv --dr

# --ir instead embeds resident content directly as a column in the CSV/JSON row rather
# than writing separate files - handy for small text/config fragments you want inline
.\MFTECmd.exe -f "C:\triage\$MFT" --csv C:\triage\out --csvf mft.csv --ir
```

**Representative output** (illustrative — hand-assembled to show the shape of the `--dr` output folder, not a literal capture from a specific $MFT):

```
C:\triage\out\Resident\
    45123-2-1_config.txt.bin
    45876-1-1_reparse_target.bin
```

🔴 Flag names have shifted across EZ tool releases in the past (`--dd`/`--do` dump a **whole raw FILE record** by offset — useful for sharing a problem record with the tool author, not for isolating resident $DATA specifically). Confirm `--dr`/`--ir` are still current against `MFTECmd.exe --help` for your installed build before relying on this in a report.

## Extracting Data with The Sleuth Kit's `icat`

`icat` outputs a file's content — resident or non-resident, TSK resolves either transparently — given an image and an inode (MFT record) number, straight to stdout.

**Basic syntax:**

```bash
icat -o <sector-offset> <image> <inode> > output_file
```

The sector offset comes from `mmls` (partition table layout); the inode number comes from `fls` (directory listing, including deleted entries) or from the record number already surfaced in `istat`'s own output — see `01 - MFT Entry Structure and Attributes.md` for `istat`'s full field breakdown.

| Flag | Effect | When to use it |
|---|---|---|
| **`-r`** | Recover mode — applies TSK's recovery heuristics to reconstruct content for a **deleted** file whose $MFT record still exists but may be partially reused or internally inconsistent | Any inode `fls` reports as deleted; treat the output as best-effort — the file may be partially overwritten, and the result needs validation (file-type magic bytes, expected size, internal structure) rather than being trusted as a clean recovered file |
| **`-s`** | Include **slack space** in the output — reads past the file's logical EOF out to the end of its last allocated cluster | Classic file-slack recovery: the bytes between EOF and the cluster boundary can be **remnants of a previously larger file** that occupied those same clusters before this file's data was written there. This is the same slack concept as allocated-size-minus-real-size above, but surfaced as actual recoverable bytes rather than just a size delta |

**Hex-eyeballing instead of trusting a clean extraction** — pipe to `xxd` (or `hexdump`) when the goal is inspecting structure or magic bytes rather than producing a usable output file, especially useful alongside `-r` where the content may not be a clean, complete file at all:

```bash
icat -o 128 image.dd 45123 | xxd | less
```

**Representative output** (illustrative — hand-assembled to show the shape of an `xxd` pass, not a literal capture from a specific image):

```
00000000: 4d5a 9000 0300 0000 0400 0000 ffff 0000  MZ..............
00000010: b800 0000 0000 0000 4000 0000 0000 0000  ........@.......
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 8000 0000  ................
00000040: 0e1f ba0e 00b4 09cd 21b8 014c cd21 5468  ........!..L.Th
00000050: 6973 2070 726f 6772 616d 2063 616e 6e6f  is program canno
```

`4d 5a` ("MZ") at offset 0 is the DOS/PE magic bytes — confirms this is a Windows executable regardless of what its filename or extension claims, exactly the kind of eyeball check `-r` recovery output needs before it's trusted as a clean file.

## ADS Extraction with `icat`

The same `inode:streamname` addressing syntax NTFS itself uses works directly with `icat` — `icat -o 128 image.dd 45123:Zone.Identifier` pulls the named stream instead of the unnamed main stream, no separate tool or mode needed. Once extracted, interpret a `Zone.Identifier` stream's contents (ZoneId, ReferrerUrl, HostUrl) using the [Zone.Identifier and Mark of the Web](#zoneidentifier-and-mark-of-the-web) section below.

## Zone.Identifier and Mark of the Web

NTFS allows a single file to carry **Alternate Data Streams (ADS)** — additional named data streams attached to the same file record (as this note already establishes, ADS is structurally nothing but another named $DATA attribute), invisible in Explorer and invisible to a plain `dir` listing, addressed as `filename:streamname`. ADS has been used historically to hide executable payloads inside an otherwise innocuous-looking file, but the single most common ADS an analyst will encounter is entirely benign in origin and forensically gold: **`Zone.Identifier`**.

| Fact | Detail |
|---|---|
| What creates it | Any file downloaded via a browser, email client, or other "internet-aware" application that honors the Attachment Execution Service gets a `filename:Zone.Identifier` stream stamped on it automatically |
| What it contains | At minimum a `ZoneId` value (3 = Internet, 4 = Restricted Sites are the ones that matter most; 0/1/2 cover Local Machine/Intranet/Trusted Sites); modern Windows/Office builds often add `ReferrerUrl` and `HostUrl` — the literal source URL the file was downloaded from |
| Why it matters for IR | This is direct, first-party evidence that a specific file arrived from the internet rather than being authored locally — the backbone of "how did the malicious document get onto this host" in phishing and malware-delivery investigations, and `ReferrerUrl`/`HostUrl` can point straight at the delivery infrastructure |
| How it's read | `Get-Item -Path <file> -Stream Zone.Identifier` (PowerShell), or any forensic tool's ADS enumeration (MFTECmd surfaces ADS during $MFT parsing) |
| How attackers strip it | Extracting a file from a password-protected ZIP/archive (many archivers don't propagate MOTW to extracted contents), using ISO/IMG container files as a delivery wrapper (mounted ISOs historically did not propagate MOTW to their contents — a well-known 2022+ phishing technique), or simply deleting the stream directly (`Unblock-File`, or manually via `Streams.exe`/PowerShell `Remove-Item -Stream`) |

🔴 A **missing** `Zone.Identifier` stream on a file that should logically have arrived via download/email is itself worth flagging — it's consistent with either a legitimately locally-authored file, or an attacker who deliberately stripped MOTW to defeat SmartScreen/Office Protected View and analyst attention alike.

### PowerShell

**Basic:**

```powershell
# List every alternate data stream on a file, including Zone.Identifier if present
Get-Item -Path 'C:\Users\user\Downloads\invoice.pdf' -Stream *

# Read the Zone.Identifier stream's raw content (ZoneId, and ReferrerUrl/HostUrl on modern builds)
Get-Content -Path 'C:\Users\user\Downloads\invoice.pdf' -Stream Zone.Identifier
```

**Interpret:**

```powershell
# Decode ZoneId (3 = Internet, 4 = Restricted Sites are the two that matter most)
$zone = Get-Content -Path 'C:\Users\user\Downloads\invoice.pdf' -Stream Zone.Identifier -ErrorAction SilentlyContinue
if ($zone -match 'ZoneId=(\d)') { switch ($Matches[1]) { '3' { 'Internet zone' }; '4' { 'Restricted Sites zone' }; default { 'Local/Intranet/Trusted zone' } } }
```

**Advanced:**

```powershell
# Recursively enumerate ADS across a tree, flagging anything beyond the expected :$DATA and Zone.Identifier streams
Get-ChildItem -Path C:\Users -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue } | Where-Object { $_.Stream -notin ':$DATA','Zone.Identifier' } | Export-Csv -Path C:\triage\unexpected_ads.csv -NoTypeInformation
```

**Remediate** (capture the ADS as evidence *before* running either of these):

```powershell
# Remove just the Zone.Identifier stream, unblocking the file for execution
Unblock-File -Path 'C:\Users\user\Downloads\invoice.pdf'

# Equivalent, explicit stream-removal form
Remove-Item -Path 'C:\Users\user\Downloads\invoice.pdf' -Stream Zone.Identifier
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| A file is resident when its reported size should force non-resident storage | Possible parser misread, spoofed/truncated attribute header, or a deliberately crafted record — the reported size and the resident flag should always agree given the ~700–800 byte ceiling |
| Real size and initialized size mismatch on a file with no legitimate reason to be sparse | Possible anti-forensic space-reservation trick, or an incomplete/interrupted download or exfiltration write |
| `icat -s` slack space contains content inconsistent with the current file's evident purpose | Classic file-slack remnant of a previously larger file that occupied the same clusters — a distinct recovery lead from the current file's own content |
| `icat -r` output that doesn't validate against expected file-type magic bytes or structure | The record was likely partially reused before recovery — treat the output as a fragment, not a complete file, until independently confirmed |
| An ADS beyond the expected `:$DATA`/`Zone.Identifier` set, pulled via `icat inode:streamname` or the PowerShell sweep above | Potential hidden payload riding as a named $DATA attribute |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full $MFT record layout, attribute headers, and `istat`'s field-by-field output (where the resident-size ceiling and data-run list actually sit inside a record) | `01 - MFT Entry Structure and Attributes.md` |
| How a folder's contents are indexed, and what a deleted directory entry looks like structurally | `04 - $I30 Directory Index and B-Trees.md` |
| SSD/TRIM limits on recovering non-resident content that's been reallocated or deleted | `07 - File Deletion Mechanics.md` |

## Resources

- SANS FOR508 "Advanced Incident Response" course material — "Analyze $DATA," "Extracting Data with the Sleuth Kit's icat" — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- The Sleuth Kit documentation — `icat` — https://wiki.sleuthkit.org/index.php/Icat
- Eric Zimmerman's tools (MFTECmd) — https://ericzimmerman.github.io/
- Microsoft Learn — How NTFS Works (attributes, resident data) — https://learn.microsoft.com/windows-server/storage/file-server/ntfs-overview
