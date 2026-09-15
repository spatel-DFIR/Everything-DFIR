# LOLBins — WinRAR — Hands-On Use Cases

Every scenario below assumes the target files are already collected/staged (WinRAR has no collection capability of its own — see `01 - Overview.md`'s Prerequisites). What changes per scenario is the switch combination and how the resulting archive is chained into the rest of an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Baseline Archive Creation](#baseline-archive-creation)
- [Content-Only Password Protection](#content-only-password-protection)
- [Full Header Encryption](#full-header-encryption)
- [Splitting Into Multi-Volume Archives](#splitting-into-multi-volume-archives)
- [Silent/Background Invocation](#silentbackground-invocation)
- [Recursive Directory Staging](#recursive-directory-staging)
- [Excluding Path Structure From Stored Names](#excluding-path-structure-from-stored-names)
- [Move-Then-Delete Originals](#move-then-delete-originals)
- [Self-Extracting Archive Creation](#self-extracting-archive-creation)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Fleet-Wide Mass Staging](#fleet-wide-mass-staging)
- [Chained With a C2 File-Transfer Primitive](#chained-with-a-c2-file-transfer-primitive)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Baseline Archive Creation

**MITRE ATT&CK:** [T1560.001](https://attack.mitre.org/techniques/T1560/001/) (Archive Collected Data: Archive via Utility)

```cmd
Rar.exe a -r C:\Windows\Temp\stage.rar D:\Finance\*
```

The simplest case — recursively adds everything under `D:\Finance\` into `stage.rar`, no password, no splitting. Functionally identical to a user manually compressing a folder, which is exactly why this alone is not a detection — see the Legitimate-Baseline Contrast scenario below and the Hunting Priority table in `05 - Detection and Hunting.md`.

## Content-Only Password Protection

**MITRE ATT&CK:** T1560.001, [T1027.013](https://attack.mitre.org/techniques/T1027/013/) (Obfuscated Files or Information: Encrypted/Encoded File)

```cmd
Rar.exe a -r -pS3cr3tP@ss D:\Finance\out.rar D:\Finance\*
```

`-p` encrypts file **contents** with AES-256 — the archive's internal file listing (names, sizes) is still visible to anything that opens or lists the archive without the password. This is the pattern **APT28** and **GALLIUM** are both tracked using per MITRE ATT&CK ("archive collected data with password protection" / "compress and encrypt stolen data prior to exfiltration").

## Full Header Encryption

**MITRE ATT&CK:** T1560.001, T1027.013

```cmd
Rar.exe a -r -hpS3cr3tP@ss D:\Finance\out.rar D:\Finance\*
```

`-hp` — "encrypt both file data and headers" per RARLAB's own switch reference — additionally hides the archive's own file listing, so nothing about what's inside (not even filenames) is visible without the password. This is the stronger variant specifically because it defeats a cursory content-inspection/DLP look at the archive in transit, not just an attempt to extract it. **MITRE's tracked TONESHELL** procedure example is the most specific real-world instance of this pattern: *"used WinRAR rar.exe to archive files for exfiltration"* with *"a unique 13-character password"* generated per intrusion.

## Splitting Into Multi-Volume Archives

**MITRE ATT&CK:** T1560.001, [T1030](https://attack.mitre.org/techniques/T1030/) (Data Transfer Size Limits)

```cmd
Rar.exe a -r -v100m -hpS3cr3tP@ss D:\Finance\out.rar D:\Finance\*
:: produces out.part1.rar, out.part2.rar, out.part3.rar, ...
```

`-v100m` splits the output into 100 MB volumes. Two independent motives make this common in exfil staging: fitting an exfil channel's own size ceiling (many cloud-API/webhook/C2 file-transfer primitives cap single-file upload size), and staying under a data-transfer-size-threshold alerting rule that would otherwise fire on one large outbound transfer — MITRE tracks this exact evasion rationale under T1030.

## Silent/Background Invocation

**MITRE ATT&CK:** T1560.001, [T1564.003](https://attack.mitre.org/techniques/T1564/003/) (Hide Artifacts: Hidden Window)

```cmd
:: Rar.exe (console) never shows a GUI window at all — no switch needed
Rar.exe a -r -inul -y C:\Windows\Temp\out.rar D:\Finance\*

:: WinRAR.exe (GUI binary) run from a script — -ibck suppresses its progress window
WinRAR.exe a -r -ibck -y C:\Windows\Temp\out.rar D:\Finance\*
```

`Rar.exe`'s complete lack of a GUI is itself the reason it's favored over `WinRAR.exe` for C2-tasked or scripted use — there's no window to suppress in the first place. `-y` (assume Yes) and `-inul` (suppress messages) round out a fully unattended, silent invocation.

## Recursive Directory Staging

**MITRE ATT&CK:** [T1074.001](https://attack.mitre.org/techniques/T1074/001/) (Data Staged: Local Data Staging), T1560.001

```cmd
Rar.exe a -r C:\Windows\Temp\stage.rar C:\Users\*\Documents\*.docx C:\Users\*\Documents\*.xlsx
```

`-r` pulls an entire directory tree into the archive rather than just the top-level path given — the typical shape of a document-hunting sweep that preceded a targeted archive rather than a single known folder. In a real intrusion this step usually follows a separate collection/discovery pass (`Get-ChildItem -Recurse`, `robocopy`, or a native `dir /s`) that already narrowed down which files matter; the archiving step itself is what T1074.001 and T1560.001 jointly describe.

## Excluding Path Structure From Stored Names

**MITRE ATT&CK:** T1560.001, [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```cmd
Rar.exe a -r -ep1 -hpS3cr3tP@ss D:\Finance\out.rar D:\Finance\*
```

`-ep1` excludes the base/starting folder from the paths stored inside the archive, which strips one layer of context an analyst would otherwise get for free (the original source-directory name) from a recovered or intercepted archive's file listing — relevant mainly in combination with `-p` (not `-hp`, where the whole listing is already hidden).

## Move-Then-Delete Originals

**MITRE ATT&CK:** T1560.001, [T1070.004](https://attack.mitre.org/techniques/T1070/004/) (Indicator Removal: File Deletion)

```cmd
Rar.exe m -r C:\Windows\Temp\out.rar D:\Finance\*
:: equivalent to: Rar.exe a -r -df C:\Windows\Temp\out.rar D:\Finance\*
```

The `m` (move) command adds files into the archive and then deletes the originals from their source location — same practical outcome as `a` combined with `-df`. Removes the operator's own staged copies once they're safely inside the archive, which both reduces the footprint left behind and (if the staging directory itself was attacker-created, e.g. under `C:\Windows\Temp`) can leave the archive as close to the only surviving evidence of the collection step.

## Self-Extracting Archive Creation

**MITRE ATT&CK:** T1560.001, [T1027.009](https://attack.mitre.org/techniques/T1027/009/) (Obfuscated Files or Information: Embedded Payloads) where the SFX is later used to deliver rather than purely to stage

```cmd
Rar.exe a -sfx -hpS3cr3tP@ss C:\Windows\Temp\update.exe D:\Finance\*
```

`-sfx` produces a self-extracting `.exe` instead of a `.rar` — worth flagging distinctly from every other scenario in this file because the *output itself is now a directly executable PE file*, not an archive that needs a separate archiver present to open. Less common for pure exfil-staging (where the destination side just needs to unpack a `.rar` with any RAR-capable tool), but relevant where the archive doubles as a delivery mechanism for a downstream stage.

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), T1560.001

```cmd
copy "C:\Program Files\WinRAR\Rar.exe" C:\Users\Public\svchost_util.exe
C:\Users\Public\svchost_util.exe a -r -hpS3cr3tP@ss C:\Users\Public\out.rar D:\Finance\*
```

Copies the legitimate signed binary under a different name and/or path before invoking it, defeating any detection rule keyed purely on `Image` = `Rar.exe`/`WinRAR.exe` at the vendor's default install path. The PE's own embedded metadata and RARLAB code signature don't change on rename or relocation — `OriginalFileName`/Authenticode still identify the genuine binary even when invoked under an arbitrary name from an arbitrary path (portable-copy behavior WinRAR fully supports, since it has no OS-enforced install location to begin with — see `01 - Overview.md`).

## Fleet-Wide Mass Staging

**MITRE ATT&CK:** T1560.001, T1074.001

```cmd
:: Issued identically across many already-compromised hosts via C2 tasking or a GPO
:: immediate task — same command, same password, same output naming on every host
Rar.exe a -r -v100m -hpS4meP@ssAcrossFleet C:\Windows\Temp\upd.rar C:\Users\Public\collected\*
```

The same archive-then-stage command, pushed to many hosts near-simultaneously — common where an operation needs the same collection-and-archive step run on every already-compromised host in an intrusion, whether for coordinated exfiltration or as a pre-detonation staging phase. The fleet-level signal is many hosts each independently generating the same argument shape (and often the literal same password) within a tight time window — see the fleet-wide sweep block in `05 - Detection and Hunting.md`.

## Chained With a C2 File-Transfer Primitive

**MITRE ATT&CK:** T1560.001, [T1041](https://attack.mitre.org/techniques/T1041/) (Exfiltration Over C2 Channel) or [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service), depending on the transport used

```cmd
Rar.exe a -r -v50m -hpS3cr3tP@ss C:\Windows\Temp\out.rar D:\Finance\*
:: followed by the C2 implant's own file-download/upload command, e.g.:
::   Sliver:  download-mode / a built-in file-exfil command against the resulting .part*.rar files
::   Empire:  the agent's file-download task pulling each volume back to the operator
```

The realistic end-to-end pattern: WinRAR does the compress/encrypt/split step, then a **separate** tool moves the finished volumes off-host — the C2 framework's own file-transfer primitive (see `Sliver/` and `PowerShell Empire/` in this module for how each logs that step), a dedicated exfil tool such as Rclone against cloud storage, or straightforward FTP/SFTP/HTTP upload. WinRAR's own evidence trail (covered in `03`/`04`) ends the moment the archive is written — everything after that belongs to whichever transport tool was used next.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
WinRAR.exe a "C:\Users\jdoe\Documents\Photos 2024.rar" "C:\Users\jdoe\Documents\Photos 2024\"
```

A user compressing their own vacation photos, a developer zipping a project folder for a colleague, or an IT admin running a scripted nightly backup job all generate `WinRAR.exe`/`Rar.exe` process-creation events too — targeting a known, user-owned source folder, with a descriptive output name, and with no subsequent exfil-channel activity. This is the baseline a hunt on this tool has to distinguish itself from; see the Hunting Priority table in `05 - Detection and Hunting.md`.
