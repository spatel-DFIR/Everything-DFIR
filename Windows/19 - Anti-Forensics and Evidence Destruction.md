# Anti-Forensics and Evidence Destruction

A capable attacker (or a user trying to hide activity from an internal investigation) doesn't stop at the intrusion — they work to make it unprovable: backdating file timestamps so a dropped tool looks older than the intrusion window, deleting shadow copies so a victim (or an examiner) can't roll back to a clean prior state, wiping files, and clearing logs. This note is the full-depth landing page for the anti-forensic angle of artifacts introduced elsewhere in this module: the `NTFS/` folder establishes what `$SI`/`$FN`/`$LogFile`/`$UsnJrnl` *are*; this note goes deep on how to use them to **catch tampering**. The organizing idea, same as this note's Linux counterpart: **the tampering itself is evidence, and often better evidence than whatever it was meant to hide.** A file with no timestomping shows you what it shows you. A file *with* timestomping shows you that, plus the fact that someone cared enough to hide it — and usually a second artifact that didn't get the memo.

> 🔴 Destroying evidence via one avenue rarely closes all avenues. NTFS keeps more independent records of "what actually happened" than most attackers (and most naive anti-forensic tools) account for — `$FILE_NAME`, `$LogFile`, `$UsnJrnl`, and Volume Shadow Copies are four separate structures that a simple API-level timestomp or a `del` command doesn't touch at all. This note's throughline is checking all four before writing "unrecoverable" in a report.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Timestomping Detection](#timestomping-detection)
  - [$STANDARD_INFORMATION vs $FILE_NAME](#standard_information-vs-file_name)
  - [$LogFile Analysis](#logfile-analysis)
  - [$UsnJrnl (USN Change Journal) Analysis](#usnjrnl-usn-change-journal-analysis)
  - [Putting It Together](#putting-it-together)
- [Volume Shadow Copy Analysis](#volume-shadow-copy-analysis)
  - [What VSS Is and Why It's a Defender's Asset](#what-vss-is-and-why-its-a-defenders-asset)
  - [Where Shadow Copies Live](#where-shadow-copies-live)
  - [Accessing Shadow Copies](#accessing-shadow-copies)
  - [The Attacker Countermeasure: Shadow Copy Deletion](#the-attacker-countermeasure-shadow-copy-deletion)
- [General Evidence-Destruction Techniques](#general-evidence-destruction-techniques)
  - [Secure-Delete / Wiping Tools](#secure-delete--wiping-tools)
  - [Log Clearing](#log-clearing)
  - [Recycle Bin Bypass](#recycle-bin-bypass)
  - [Anti-Forensic Tool Detection, Generally](#anti-forensic-tool-detection-generally)
  - [Artifact-Specific Tampering Caveats](#artifact-specific-tampering-caveats)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across VSS state, USN journal liveness, and anti-forensic tool execution evidence — no third-party tool required. Log-clearing (1102/104) detection is deliberately not repeated here: note 11 (Event Log Analysis) owns that query and its meta-signal analysis in full, and this note's own Log Clearing section points there rather than re-deriving it.

```powershell
# Existing shadow copies - vssadmin is a native EXE, not a cmdlet, but it's the fastest live check for "is there recoverable prior state at all"
vssadmin list shadows

# Process-creation evidence for shadow-copy deletion commands - requires 4688 with command-line auditing enabled
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000 -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin.*delete\s+shadows' -or $_.Message -match 'wmic.*shadowcopy\s+delete' } |
    Select-Object TimeCreated, Message

# Interactively-typed VSS-deletion commands surviving in plaintext console history - catches it even without 4688 command-line auditing
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -ErrorAction SilentlyContinue |
    Select-String -Pattern 'vssadmin|shadowcopy|Remove-WmiObject.*ShadowCopy'

# Confirm the USN change journal is live and check its current ID/max size - fsutil is a native EXE, not a cmdlet; PowerShell has no native cmdlet that parses $UsnJrnl record content
fsutil usn queryjournal C:

# Prefetch entries for known anti-forensic command-line tools - execution evidence with no MFTECmd/registry step required
Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'SDELETE|CIPHER|WMIC|VSSADMIN' } | Select-Object Name, LastWriteTime
```

## Timestomping Detection

### $STANDARD_INFORMATION vs $FILE_NAME

NTFS/02 establishes that every NTFS `$MFT` record carries **two** independent sets of four timestamps: `$STANDARD_INFORMATION` (`$SI`) and `$FILE_NAME` (`$FN`). That fact, restated here for this note's purpose, is the single most important timestomping-detection technique on NTFS:

| Attribute | Who updates it | Who targets it |
|---|---|---|
| **$SI** | The filesystem, automatically, on the ordinary operations in NTFS/02's MACE/MACB tables | This is what Explorer, `dir`, and the Windows API (`SetFileTime` and equivalents) expose — virtually every common timestomping tool and technique (the classic `timestomp` utility, PowerShell `Set-ItemProperty`/`.LastWriteTime`, most "anti-forensic" scripts found in the wild) modifies **only** `$SI`, because that's the value both a human examiner and the OS's own file-properties dialog will look at |
| **$FN** | Only on namespace events — file creation, rename, move between directories — set once by the NTFS driver at those specific moments | Rarely known to exist outside forensic circles, and **not reachable via the standard Windows API calls** naive timestomping tools use. A tool that calls `SetFileTime()` changes `$SI` and leaves `$FN` exactly as it was |

**The detection technique**: parse both attribute sets for the file in question and compare them. A **mismatch** — especially `$SI` claiming an *older* creation time than `$FN` — is one of the strongest, most reliable timestomping indicators available on NTFS, because it requires the attacker to have known `$FN` exists at all, which most don't.

**How to view both sets**: Explorer, `dir`, PowerShell's default `Get-Item`, and most GUI forensic-tool default views show only `$SI`. To see `$FN` you need a tool that explicitly parses the `$MFT` record's `$FILE_NAME` attribute alongside `$STANDARD_INFORMATION`. **Eric Zimmerman's MFTECmd** (cross-ref NTFS/02) surfaces both timestamp sets side by side in its output — this is the field-standard workflow: run MFTECmd against the `$MFT` (or a live/extracted copy), open the CSV in Timeline Explorer or a spreadsheet, and diff the `$SI`-prefixed and `$FN`-prefixed timestamp columns for the record(s) in question.

🔴 **The caveat, stated plainly so it isn't overclaimed**: a `$SI`/`$FN` match does **not** prove the file wasn't tampered with — it only proves a *naive* tool wasn't used. Sophisticated timestomping techniques that manipulate the `$MFT` record more directly (rather than going through the standard Windows API) can alter `$FN` too. Treat a mismatch as strong positive evidence of tampering; treat a match as "no evidence of naive tampering," not as "confirmed untampered."

### PowerShell

NTFS/02's PowerShell section already covers the general live `$SI`-only sweep (copy-signature and predates-by-a-year checks) and the single-file $SI comparison — cross-ref there rather than repeating it here. `$FILE_NAME` remains unreachable by any native cmdlet either way (parsing the raw `$MFT` record structure is MFTECmd's job, not PowerShell's).

operationalize this note's own decision-diagram opening question (is `$SI` creation "suspiciously clean"?) by flagging timestamps landing exactly on a round boundary:

```powershell
Get-ChildItem -Path C:\Users -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime.Second -eq 0 -and $_.CreationTime.Millisecond -eq 0 } |
    Select-Object FullName, CreationTime
```

flag a specific file of interest as a candidate for the full MFTECmd `$SI`/`$FN` comparison; this is PowerShell's ceiling on a single file, not a conclusion:

```powershell
$f = Get-Item 'C:\path\to\suspect.exe'
if ($f.CreationTime.Second -eq 0 -and $f.CreationTime.Millisecond -eq 0) {
    "Candidate for MFTECmd `$SI/`$FN comparison: $($f.FullName) (Created $($f.CreationTime))"
}
```

### $LogFile Analysis

The NTFS `$LogFile` (introduced in NTFS/05 as the filesystem's own transaction/crash-consistency journal) records the actual **sequence of filesystem operations as they happened** — including attribute and timestamp modifications to a `$MFT` record. This makes it the answer to the obvious next question an attacker might ask: *what if I alter both `$SI` and `$FN` to a consistent, matching, fake timestamp?*

Even a fully consistent `$SI`/`$FN` fake doesn't erase the `$LogFile` record of the operation that *set* those fake values — the journal can still show that a timestamp-modification (or rename, or attribute-change) operation occurred at the true, real-world time, exposing the tampering even when the two attribute sets no longer disagree with each other.

**The limitation, and why timeliness matters**: `$LogFile` is a relatively small, limited-retention journal (NTFS/05 covers its role as NTFS's crash-consistency mechanism; exact current size varies by volume configuration — don't assume a fixed number without checking the live volume). Because it's small relative to `$MFT`/`$UsnJrnl`, its records get overwritten by subsequent filesystem activity comparatively quickly. This technique only works if the tampering happened recently enough that the relevant `$LogFile` records haven't yet cycled out — the earlier an examiner gets to the evidence, the more likely `$LogFile` still holds the tell.

**Tooling**: a dedicated `$LogFile` parser is required — this is not something Explorer or a generic `$MFT` viewer surfaces. Eric Zimmerman's toolset is the field-standard vendor for NTFS metadata-file parsing generally (cross-ref NTFS/05); confirm the current exact tool/mode for `$LogFile` parsing specifically against Zimmerman's tools page at time of use, since tool names and capabilities in this space have shifted over time and this note doesn't want to assert a specific current binary name with more confidence than is warranted.

### $UsnJrnl (USN Change Journal) Analysis

The **USN Change Journal** (`$Extend\$UsrJrnl`, Windows 10 1809+, introduced in NTFS/06) is a **separate** journal from `$LogFile` — a higher-level, per-volume rolling log of file/directory-level changes (create, delete, rename, data-overwrite, and more), each entry tagged with a reason code describing what kind of change occurred.

`$UsnJrnl` is forensically valuable for two distinct purposes:

1. **General activity-timeline source**, independent of a file's current `$MFT` state. Because `$UsnJrnl` records changes as they happen and retains them for a rolling window, it can show that a file was created, modified, or deleted **even if the file has since been fully removed from the live filesystem and its `$MFT` record reused** — a "what happened to this file over time" record that doesn't depend on the file still existing to query.
2. **Timestomping detection specifically**: a `$UsnJrnl` entry showing a reason code indicating a timestamp or basic-attribute change for a given file (Microsoft's USN reason-code set includes a basic-information-change category — treat the exact constant name as something to verify against current `$UsnJrnl` documentation or tool output rather than a name this note asserts with full confidence) occurring at a time **inconsistent** with that file's claimed `$SI` timestamps is another timestomping tell, working on the same principle as `$LogFile`: the journal records that *something* happened to the file's attributes at the real time, regardless of what the attributes were subsequently set to.

**Tooling**: **MFTECmd** (Eric Zimmerman) is commonly paired with `$UsnJrnl` parsing in current Windows-forensics tooling — verify at time of use whether the specific build in hand includes `$UsnJrnl` support directly or whether a separate dedicated USN-journal parser is needed; don't assume a specific flag/mode without checking current tool documentation.

### PowerShell

PowerShell has no native cmdlet that parses `$UsnJrnl` record structure — `fsutil usn` (a native EXE, not a cmdlet) is the ceiling for live triage; Hunt Evil above already confirms the journal is live via `fsutil usn queryjournal`. Treat everything below as raw, volume-wide triage output, not a substitute for MFTECmd's structured parse.

walk recent journal records and their reason codes in CSV form:

```powershell
fsutil usn readjournal C: csv | ConvertFrom-Csv | Select-Object -First 50
```

### Putting It Together

```
Is $SI creation time suspiciously "clean" (round, old, matches a known-good baseline)?
        │
        ▼
Pull $FN timestamps for the same $MFT record (MFTECmd)
        │
   ┌────┴────┐
   │         │
$SI ≠ $FN  $SI = $FN
   │         │
   ▼         ▼
STRONG      Check $LogFile for recent timestamp-modification
tampering   operations on this record (if within retention window)
evidence         │
              ┌───┴────┐
              │        │
         Found op   Nothing found (may be outside
         at real     retention window, or genuinely
         time →      untampered — can't fully rule out
         STRONG      sophisticated/direct-$MFT tampering)
         evidence         │
                          ▼
                    Check $UsnJrnl for reason-code entries
                    inconsistent with claimed $SI timestamps
                    (longer retention than $LogFile)
```

This escalation — `$SI`/`$FN` compare, then `$LogFile`, then `$UsnJrnl` — reflects both retention window (shortest to longest) and effort required (cheapest to most involved), and mirrors the same retention-window logic covered separately in NTFS/05's and NTFS/06's own Red Flags tables.

## Volume Shadow Copy Analysis

### What VSS Is and Why It's a Defender's Asset

The **Volume Shadow Copy Service (VSS)** is Windows' built-in point-in-time snapshot mechanism, underlying System Restore, File History, and most native/third-party Windows backup software. NTFS/07 introduces the **Copy-on-Write (COW)** mechanism VSS uses: before a block on disk is overwritten, VSS copies the original block into shadow storage first, so a shadow copy can reconstruct the volume as it existed at snapshot time even though the live volume has since changed.

This note frames VSS deliberately as **one of the single highest-value tools an analyst has**, not just a topic to cover because attackers abuse it: a shadow copy can contain **prior versions of files, registry hives, or entire filesystem state from before an attacker's changes or evidence-destruction attempt.** An attacker who deletes or modifies a file on the live filesystem frequently doesn't realize — or doesn't bother to check — that an older, unmodified copy of that same file may still exist inside a shadow copy taken before their action. Registry hives are a particularly high-value target here: a shadow copy can hold a `SYSTEM`/`SOFTWARE`/`SAM`/`NTUSER.DAT` snapshot from before an attacker cleared or modified relevant keys, letting an examiner diff "then" against "now" directly.

### Where Shadow Copies Live

Shadow copy storage lives under the hidden `System Volume Information\` folder at the root of each volume that has VSS enabled. The exact internal structure of shadow-copy storage inside that folder is not something Microsoft documents in full public detail, and this note won't assert specifics it can't back — the key operational point for an analyst is that **shadow copies are not simply files you can browse with normal Explorer/file-copy tools.** They require VSS-aware access — `vssadmin`, the `mklink`/`GLOBALROOT` technique below, or a forensic tool with native VSS support — rather than treating `System Volume Information` as a folder to browse directly.

### Accessing Shadow Copies

| Method | Context | Notes |
|---|---|---|
| `vssadmin list shadows` | Live host, admin rights required | Enumerates existing shadow copies on the live system — the fastest live-response check for "does this host even have recoverable prior state." Also run `vssadmin list shadowstorage` to see how much space is allocated to shadow storage and whether it's likely to still hold meaningful history |
| `mklink /d <link> \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\` | Live host, admin rights required | The well-known symbolic-link technique: creates a directory junction/symlink pointing at a specific shadow copy device object (`HarddiskVolumeShadowCopyN`, `N` from the `vssadmin list shadows` output), letting the shadow copy be browsed through the new link as if it were an ordinary folder/drive — genuinely one of the most useful single commands in Windows live-response anti-anti-forensics |
| **ShadowExplorer** | Live host or mounted image | Free GUI tool purpose-built for browsing and extracting files directly out of existing shadow copies without manually running the `mklink`/`GLOBALROOT` steps (cross-ref NTFS/07) |
| **Arsenal Image Mounter** | Offline image analysis | Already covered in note 02 for mounting forensic images as native Windows volumes generally — worth calling out specifically here because it also supports mounting the shadow copies *within* a mounted image, letting an examiner reach prior-version state without needing `vssadmin`/`mklink` against a live system at all |
| **FTK Imager** and other commercial suites | Offline image analysis | Generally include native VSS browsing built directly into the tool's image-navigation UI, no separate mount step required |

### PowerShell

the true-cmdlet equivalent of `vssadmin list shadows`, including `DeviceObject` (the value the `mklink`/`GLOBALROOT` technique above needs):

```powershell
Get-CimInstance Win32_ShadowCopy | Select-Object ID, VolumeName, InstallDate, DeviceObject
```

PowerShell-wrapped version of the `mklink`/`GLOBALROOT` technique from the table above (`New-Item -ItemType SymbolicLink` doesn't reliably target device paths, so `cmd /c mklink` is still the honest tool here):

```powershell
$shadow = Get-CimInstance Win32_ShadowCopy | Select-Object -First 1
cmd /c mklink /d C:\ShadowMount "$($shadow.DeviceObject)\"
```

### The Attacker Countermeasure: Shadow Copy Deletion

`vssadmin delete shadows /all` (and PowerShell/WMI equivalents — `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, `wmic shadowcopy delete`) is a well-known technique used specifically to **prevent recovery via shadow copies.** It's most famously associated with ransomware operators deliberately destroying System Restore/File History recovery points before or during encryption so the victim can't simply roll back — but it is directly and equally relevant as a general anti-forensic evidence-destruction technique outside the ransomware context, for exactly the reason the previous section frames VSS as valuable: destroying the shadow copies removes the "the attacker didn't know about the prior version" recovery avenue this note just described.

🔴 **Give this real prominence: execution evidence for `vssadmin delete shadows` (or its PowerShell/WMI equivalents) is one of the single strongest, most recognizable anti-forensic/ransomware-precursor red flags in Windows DFIR.** It is rarely, if ever, something a legitimate user runs incidentally — it is a deliberate, one-purpose command.

Detection evidence:

| Source | What to look for | Cross-ref |
|---|---|---|
| Security/System Event Log | `vssadmin.exe` invocation may surface via process-creation auditing (4688) if enabled, or via System log entries tied to the VSS service handling the delete request | Note 11 (Event Log Analysis) |
| Sysmon (if deployed) | Process-creation events (Event ID 1) for `vssadmin.exe`, `wmic.exe` with `shadowcopy delete` arguments, or `powershell.exe`/`pwsh.exe` invoking `Remove-WmiObject`/`Get-WmiObject Win32_ShadowCopy` | Note 11 |
| Evidence-of-execution artifacts | Prefetch/ShimCache/Amcache showing `vssadmin.exe` or `wmic.exe` ran, even without full command-line capture | Note 06 (Evidence of Program Execution family) |
| Command-line logging (if enabled) | The full command line including `/all` and any target-volume arguments, if process-creation command-line auditing is on | Note 11 |

### PowerShell

VSS-service log entries around a suspected deletion window, independent of process-creation auditing:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application','System'; ProviderName='VSS'} -ErrorAction SilentlyContinue |
    Where-Object TimeCreated -gt (Get-Date).AddDays(-7) |
    Select-Object TimeCreated, Id, Message
```

Sysmon process-creation (Event ID 1), if deployed, for the same delete commands Hunt Evil's Security-4688 query looks for — Sysmon's default command-line capture is a broader net than 4688 alone:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'vssadmin|shadowcopy|Remove-WmiObject.*ShadowCopy' } |
    Select-Object TimeCreated, Message
```

## General Evidence-Destruction Techniques

The theme running through this section, same as the timestomping and VSS sections above: **destroying evidence via one avenue rarely closes all avenues, and the act of destruction itself usually leaves a trace.**

### Secure-Delete / Wiping Tools

**SDelete** (Sysinternals — Microsoft's own tool) is worth naming specifically because it's genuinely dual-use: a legitimate admin utility for securely wiping sensitive data before disposal/repurposing a disk, *and* a potential anti-forensic tool depending entirely on who's running it and why. Various third-party "shredder"/privacy-cleaner utilities follow the same general approach: multi-pass overwrite of file content and/or free space, intended to defeat both simple deletion-recovery and (to varying, tool-dependent degrees) carving.

The forensic reality: overwriting is genuinely effective against **recovering the original file content** — once overwritten, that content is very likely gone in a way carving can't reach (compare NTFS/07's SSD/TRIM section, where the recovery ceiling is similarly hard). But **the act of running the wiping tool itself still generates execution evidence**: Prefetch/ShimCache/Amcache (note 06) can show that SDelete or an equivalent tool ran, and per the Timestomping Detection section above, `$UsnJrnl`/`$LogFile` records of the delete/overwrite operations on the targeted file(s) may well still exist even though the file's *content* is gone. **You can't unwrite the fact that you tried to destroy evidence** — the same framing this repo's Private Browsing & Anti-Forensic Recovery note (note 14) already applied to CCleaner-class tools, extended here to secure-wipe utilities specifically.

### Log Clearing

Note 11 (Event Log Analysis) already covers Security-log Event ID **1102** ("The audit log was cleared") in full depth, including why it's structurally very hard for an attacker to suppress — the clear operation itself is what generates the record. This note doesn't re-derive that; it points to it as the primary, best-documented example of a general principle worth stating plainly:

🔴 **Clearing a log is itself almost always *more* forensically suspicious than whatever the log would have shown.** A suspiciously short or gapped log combined with a 1102 event (or its System-log 104 corroborating counterpart, also covered in note 11) is a huge red flag on its own, independent of any specific event that got cleared — the absence itself, timed against the clear event, tells the analyst exactly which window of activity to treat as unaccounted-for and prioritize by every other means available (VSS, `$UsnJrnl`, memory, network logs).

### Recycle Bin Bypass

`Shift+Delete`, or any programmatic deletion (scripted, API-level) that skips the Recycle Bin entirely, removes the normal recoverable-staging behavior note 08 (Deleted Items and File Existence) covers as the Recycle Bin's default role. Bypassing the Recycle Bin removes **one** recovery avenue, but per this note's throughline, it rarely closes all of them:

- **$MFT-based/carving recovery** (NTFS/07) — the file's `$MFT` record may still be recoverable, or the file's data may still be carvable from unallocated clusters, depending on how much subsequent disk activity has occurred.
- **$UsnJrnl** (this note, above) — the deletion event itself is exactly the kind of change `$UsnJrnl` is built to record, independent of whether the file passed through the Recycle Bin on the way out.
- **Volume Shadow Copy** (this note, above) — if a shadow copy predating the deletion exists, the file may simply still be present in it, full content and all, regardless of how the live-filesystem deletion was performed.

🔴 Recycle-Bin-bypassed deletion of a file later found to be forensically significant via `$UsnJrnl` or VSS recovery is itself worth flagging — deliberately routing around the "obvious"/default recovery path (rather than an ordinary `Delete` keypress landing in the bin) suggests intent to avoid the recovery avenue a less careful actor wouldn't have thought to avoid.

### Anti-Forensic Tool Detection, Generally

The presence of known anti-forensic/wiping-tool execution evidence — SDelete (above), CCleaner (already named specifically in note 14's Private Browsing & Anti-Forensic Recovery note), and other privacy/wiping utilities — is a meta-artifact worth flagging on its own, the same pattern note 14 already established for CCleaner-class tools in the browser-artifact context: finding the tool's execution evidence (note 06) shortly before or after a suspected incident window is itself a red flag even when whatever it targeted is genuinely gone.

### PowerShell

sweep both Prefetch and the uninstall registry in one pass for named privacy/wiping tools (a broader net than command-line utilities alone, and catches a GUI tool removed after use but still listed until the uninstall-registry entry itself is cleaned up):

```powershell
$names = 'SDelete|CCleaner|Eraser|BleachBit|Privazer'
Get-ChildItem 'C:\Windows\Prefetch\*.pf' -ErrorAction SilentlyContinue | Where-Object Name -match $names | Select-Object Name, LastWriteTime
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object DisplayName -match $names | Select-Object DisplayName, InstallDate
```

### Artifact-Specific Tampering Caveats

Briefly, as a limitation acknowledgment rather than new depth: some of the artifacts covered elsewhere in this module carry their own "presence isn't absolute proof" caveats that a sufficiently sophisticated attacker can exploit. ShimCache's own note (06) already covers its "presence ≠ execution" caveat in the other direction (an entry existing doesn't prove the program ran) — the anti-forensic mirror of that is that a determined attacker with the right access can, in principle, manipulate registry-backed and file-backed execution artifacts directly rather than simply not triggering them. This is a caveat to carry into every artifact's interpretation, not a new technique to detail here — see each artifact's own note (06 subfolder) for its specific manipulation surface where documented.

## Red Flags

| 🔴 Finding | Technique |
|---|---|
| `$SI`/`$FN` timestamp mismatch on a file of investigative interest | Timestomping (naive tool) |
| `$LogFile`/`$UsnJrnl` records showing timestamp-modification or delete/overwrite operations inconsistent with the live filesystem's apparent state | Timestomping (sophisticated) or destruction with journal-visible residue |
| `vssadmin delete shadows` / `wmic shadowcopy delete` / PowerShell VSS-cmdlet execution evidence | Shadow-copy destruction — ransomware precursor and/or anti-forensic evidence destruction; give this its own priority given how strong and unambiguous the signal is |
| Security-log 1102 combined with a suspiciously short/gapped log | Log clearing |
| Execution evidence for known wiping/privacy tools (SDelete, CCleaner) with no legitimate administrative explanation | Secure deletion / privacy-tool cleanup |
| Recycle-Bin-bypassed deletion of a file later found to be forensically significant via `$UsnJrnl`/VSS recovery | Deliberate avoidance of the "obvious" recovery path |

## Tooling

| Tool | Use | Note |
|---|---|---|
| **MFTECmd** (Eric Zimmerman) | `$SI`/`$FN` comparison from `$MFT` records; may also surface `$UsnJrnl` data depending on current build | Field-standard first stop for this note's core detection technique — cross-ref NTFS/02 |
| A dedicated `$LogFile` parser | Recovering the true sequence/timing of recent metadata operations | Verify the current exact tool/mode against Eric Zimmerman's tools page at time of use — not asserted here with full confidence |
| `vssadmin.exe` | Live enumeration of existing shadow copies (`list shadows`, `list shadowstorage`) | Requires admin rights |
| `mklink` / `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyN\` | Mounting a specific shadow copy for direct browsing | Live host, admin rights required |
| **ShadowExplorer** | GUI shadow-copy browsing/extraction without manual `mklink` steps | Cross-ref NTFS/07 |
| **Arsenal Image Mounter** | Mounting shadow copies *within* a mounted forensic image | Cross-ref note 02 for its general acquisition-analysis role |
| **FTK Imager** | Native VSS browsing built into image navigation | Commercial suite |
| **SDelete** | *Not* a forensic analysis tool — named here as something to recognize the execution evidence *of* | Distinguish clearly from the analysis tools above |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Foundational `$SI`/`$FN` mechanics and MACE/MACB behavior by operation | NTFS/02 - $STANDARD_INFORMATION and $FILE_NAME Attributes — this note goes deeper specifically on the anti-forensic/detection angle of the same structures |
| `$LogFile`/`$UsnJrnl` structural mechanics | NTFS/05 - $LogFile; NTFS/06 - $UsnJrnl |
| COW/VSS introduction | NTFS/07 - File Deletion Mechanics |
| Arsenal Image Mounter's general role in acquisition/analysis | Evidence Acquisition & Imaging (note 02) |
| Execution evidence for `vssadmin`/wiping/privacy tools | Evidence of Program Execution family (note 06) |
| Recycle Bin's normal forensic role, contrasted against bypass | Deleted Items and File Existence (note 08) |
| Event Log 1102, System-log 104, `vssadmin`/process-creation logging | Event Log Analysis (note 11) |
| The browser-specific slice of evidence destruction (CCleaner, SQLite/ESE recovery) — this note fulfills that note's forward reference to full VSS/`$LogFile`/`$UsnJrnl`/timestomping depth | Private Browsing & Anti-Forensic Recovery (note 14) |
| Fitting anti-forensic indicators into a full cross-artifact timeline, `$SI`/`$FN` comparison in a super-timeline context | Timeline Analysis (note 18) |
| How anti-forensic indicators feed into broader kill-chain/threat-hunting reasoning | Threat Hunting Methodology and Intelligence (note 20, forward reference) |

## Resources

- SANS FOR508 poster/index — anti-forensics/timestomping/VSS coverage, used as a checklist only, rewritten in this note's own words, no verbatim reproduction — `Windows/SANS_DFPS_FOR508_v4.11_0624.pdf` (bundled in this repo)
- Eric Zimmerman's tools — https://ericzimmerman.github.io/ (MFTECmd and the wider NTFS-metadata-parsing toolset referenced throughout)
- ShadowExplorer — https://www.shadowexplorer.com/
- Microsoft Learn — Volume Shadow Copy Service overview and `vssadmin` reference: https://learn.microsoft.com/windows-server/storage/file-server/volume-shadow-copy-service
- Sysinternals — SDelete: https://learn.microsoft.com/sysinternals/downloads/sdelete
- MITRE ATT&CK: **T1070** (Indicator Removal, umbrella technique) — sub-techniques **T1070.004** (File Deletion) and **T1070.006** (Timestomp); **T1490** (Inhibit System Recovery) for the shadow-copy-deletion angle specifically
