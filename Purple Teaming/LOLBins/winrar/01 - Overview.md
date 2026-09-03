# LOLBins — WinRAR (`WinRAR.exe` / `Rar.exe`) — Overview

> 🔴 **Red Flag Principle:** WinRAR is not documented anywhere in the LOLBAS Project's catalog — verified live against the repo (`LOLBAS-Project/LOLBAS`): zero hits for `rar.exe` or `WinRAR` across all five of its categories (`OSBinaries`, `OSLibraries`, `OSScripts`, `OtherMSBinaries`, `HonorableMentions`), because LOLBAS is explicitly scoped to Microsoft-authored/OS-shipped binaries and WinRAR is third-party software from RARLAB — it structurally falls outside LOLBAS's remit, unlike every other tool in this `LOLBins/` folder. That means there is **no unique static signature, no side-effect cache write, no fixed OS install path** to hunt against the way `certutil.exe`'s `CryptnetUrlCache` or `msbuild.exe`'s temp-compile artifact give an analyst something free. Detection here rests entirely on **argument shape + behavioral correlation** — and the single highest-value fact to remember is that `-p`/`-hp` password protection, if not captured live in a command line at the moment `WinRAR.exe`/`Rar.exe` runs (Sysmon 1, EDR telemetry, 4688 with command-line auditing), is very likely **gone for good**: once the process exits, the resulting archive is AES-256-encrypted and cryptographically opaque to every downstream forensic technique, full-disk and memory analysis included. Capturing the command line at execution time is the whole game.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Legitimate vs. Abused Usage](#legitimate-vs-abused-usage)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

WinRAR is not an offensive-security-authored tool — it's a commercial, shareware-licensed Windows file archiver built around the **RAR** compression format, both created by **Eugene Roshal** ("RAR" = **R**oshal **AR**chive). The software is currently developed and distributed by **win.rar GmbH** (branded RARLAB), officially at [win-rar.com](https://www.win-rar.com/) / [rarlab.com](https://www.rarlab.com/). It is closed-source and proprietary — unlike most tools elsewhere in this repo's `Purple Teaming/` module, there is no public GitHub repository or changelog to cite for version history; licensing is shareware (a 40-day full-featured trial that continues to run with a reminder nag afterward rather than a hard functionality cutoff).

**WinRAR.exe** (the GUI application) and **Rar.exe** (a console/text-mode-only executable) ship together in the standard WinRAR installer. Per RARLAB's own official documentation (mirrored at [winrar-france.fr's "Console RAR version" help page](https://winrar-france.fr/winrar_instructions_for_use/source/html/HELPConsoleRAR.htm), sourced from the same WinRAR.chm help RARLAB ships): *"This is also RAR version for Windows, but it supports only the command line text mode interface."* The same page states console RAR *"supports a larger number of command line switches and commands comparing to WinRAR"* — meaning `Rar.exe` has console-only switches documented in a separate `rar.txt` file bundled with the install, not published on RARLAB's public web help. **This note's switches table (below) covers the switches documented on RARLAB's public help pages, common to both binaries — the console-only extras in `rar.txt` were not independently verified for this build and should not be assumed absent.**

Because WinRAR is third-party software with no LOLBAS entry, its abuse as an exfiltration-staging tool is documented instead through **MITRE ATT&CK's procedure-example library**, verified live against [attack.mitre.org/techniques/T1560/001](https://attack.mitre.org/techniques/T1560/001/) (**T1560.001 — Archive Collected Data: Archive via Utility**). The technique's own description states plainly: *"Adversaries may use also third party utilities, such as 7-Zip, WinRAR, and WinZip, to perform similar activities [compress/encrypt collected data]."* The procedure-example list names WinRAR or `rar.exe` specifically for dozens of tracked threat actors — a representative sample, not the full list:

| Actor / malware | Documented use (verbatim from ATT&CK) |
|---|---|
| **APT28** | "used a variety of utilities, including WinRAR, to archive collected data with password protection" |
| **GALLIUM** | "used WinRAR to compress and encrypt stolen data prior to exfiltration" |
| **Mustang Panda** | "used RAR to create password-protected archives of collected documents" and "used WinRAR 'Rar.exe' to archive stolen files" |
| **TONESHELL** | "used WinRAR rar.exe to archive files for exfiltration" with "a unique 13-character password" |
| **MirrorFace** | "used rar.exe and the Makecab utility to archive files of interest prior to exfiltration" |
| **BRONZE BUTLER** | "compressed data into password-protected RAR archives prior to exfiltration" |
| **Ke3chang** | "known to use 7Zip and RAR with passwords to encrypt data prior to exfiltration" |
| **Turla** | "encrypted files stolen from connected USB drives into a RAR file before exfiltration" |

This pattern — password-protect, then exfiltrate — recurs across unrelated APT groups and ransomware crews spanning over a decade of tracked intrusions, which is the strongest available evidence that this is a mature, well-understood real-world technique rather than a theoretical one.

## How It Works

There is no custom protocol or exploit here — WinRAR does exactly what it's designed to do. The "attack" is **100% behavioral**: a legitimate, signed compression utility, already present or trivially installed on a compromised host, pointed at previously-staged/collected files to compress and optionally encrypt them into a single archive before a separate exfiltration channel moves that archive off the network. WinRAR contributes zero exfiltration capability of its own — it only prepares the payload for whatever transport does the actual outbound transfer (Rclone, FTP/SFTP, a cloud-storage client, a C2 framework's built-in file-transfer primitive, or manual upload).

**Two entry points, one behavior:**
- **`Rar.exe`** — console/text-mode only, per RARLAB's own documentation. It never opens a GUI window under any circumstances, which is exactly why it's the more attractive of the two for scripted/unattended/C2-tasked use — nothing to suppress, nothing an interactively-watching user could stumble across.
- **`WinRAR.exe`** — the GUI application, but it accepts the identical `<command> -<switches> <archive> <files>` command-line syntax when launched from `cmd.exe`/PowerShell. Run this way it can still surface a small progress/status window during the operation unless the operator passes `-ibck` ("run WinRAR in background"), per RARLAB's own switch reference.

```
Operational chain (T1560.001 → T1074.001 → exfil):

  [1] Collection                  [2] Stage + Archive (WinRAR)                [3] Exfiltration
  ────────────────────            ─────────────────────────────              ──────────────────
  robocopy / xcopy /              Rar.exe a -r -hp<password> -v100m          Rclone / curl / FTP /
  Get-ChildItem -Recurse /        -ep1 C:\Windows\Temp\upd.part1.rar          cloud-storage client /
  a targeted `dir /s` sweep       D:\Finance\* D:\HR\*                        C2 built-in file
  pulls target files into                                                     upload (see Sliver/,
  one staging directory                                                       PowerShell Empire/
  (T1074.001)                                                                 in this module)
```

```
Process tree — a script or C2 implant driving the archive step:

  cmd.exe / powershell.exe (or a C2 implant, e.g. beacon.exe / sliver-implant.exe)
    └─ Rar.exe  a  -r  -hp<password>  -v200m  -ep1  C:\Users\Public\out.part1.rar  D:\Finance\*
         (no child process — the archive engine runs entirely inside this one process)
```

**Encryption mechanics** — verified against RARLAB's own [Encryption Technology page](https://www.win-rar.com/encryption-technology-winrar.html) and cross-checked with [ElcomSoft's published technical breakdown](https://blog.elcomsoft.com/2026/07/the-rar-mystery-breaking-rar4-and-rar5-encryption/): the current **RAR5** format encrypts with **AES-256**, deriving the key from the operator's password via **PBKDF2-HMAC-SHA256** (RARLAB's own page: *"The password-based key derivation function is now based on (PBKDF2) using HMAC-SHA256; this is the core of the WinRAR security mechanism"*), with a default iteration count of 2^15 (32,768) per ElcomSoft's analysis. **One detail this note could not confirm directly from RARLAB's own page**: the specific block-cipher mode (widely reported elsewhere as CBC) — treat that specific detail as commonly cited rather than found verbatim in RARLAB's own public documentation. What *is* directly confirmed from RARLAB's own switch reference is the practical difference that matters for a blue teamer: `-p` encrypts file **contents** only (an unencrypted archive listing still shows filenames/paths); `-hp` — "encrypt both file data and headers" — additionally hides the file listing itself, so nothing about the archive's contents, not even the names of what's inside it, is visible without the password. That's the flag that actually defeats a content-inspection proxy or DLP tool doing a cursory look inside an archive in transit.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport | **None** — WinRAR performs zero network I/O of its own; a separate tool/channel does the actual outbound transfer |
| Compression | Proprietary RAR4/RAR5 format (RARLAB, closed-source) |
| Encryption (optional, `-p`/`-hp`) | AES-256, key derived via PBKDF2-HMAC-SHA256 — verified against RARLAB's own encryption-technology page |
| Authentication | None — WinRAR itself has no auth concept; whatever downstream exfil channel is used carries its own auth (cloud API token, FTP creds, C2 session) |
| Execution context | Runs as whatever user/token invoked it — no elevation required beyond read access to the files being archived |
| Process model | Single process, no children spawned by WinRAR/Rar itself — a script or C2 implant is the parent, `Rar.exe`/`WinRAR.exe` is a leaf |
| Binary location | **Not** a fixed OS-shipped path (unlike LOLBAS-catalogued binaries) — default vendor install is `C:\Program Files\WinRAR\` (`WinRAR.exe` and `Rar.exe` side by side), or `C:\Program Files (x86)\WinRAR\` on some installs. Presence at all — anywhere — implies a deliberate install, by the legitimate user, IT, or the attacker themselves (portable copies dropped to an arbitrary path are common and trivial, since WinRAR has no OS-enforced install location the way a Microsoft-signed binary does) |

## Command-Line Switches — Quick Reference

Verified against RARLAB's own official command-line reference (mirrored content confirmed across [winrar-france.fr](https://winrar-france.fr/winrar_instructions_for_use/source/html/HELPSwitches.htm) and [documentation.help](https://documentation.help/WinRAR/HELPSwitches.htm), both direct copies of the WinRAR.chm help RARLAB ships). Syntax pattern: **`<Rar.exe|WinRAR.exe> <command> -<switch1> -<switchN> <archive> <files> <@listfiles> <path_to_extract\>`** — commands and switches are case-insensitive.

**Commands (the verb — what operation to perform)**

| Command | Plain-English meaning |
|---|---|
| `a` | Add files to an archive — the core "compress this" operation, and the one every use case below is built on |
| `x` | Extract files from an archive, preserving full paths |
| `e` | Extract files from an archive, ignoring/flattening paths |
| `d` | Delete files from an archive |
| `m` | Move files/folders into an archive (adds, then deletes the originals — same practical effect as `a` plus `-df`) |
| `l` / `v` | List archive contents (not documented in the switches table above but standard; used to inspect an archive without extracting) |
| `t` | Test archive integrity |
| `u` | Update files within an archive (add only what's newer than what's already archived) |
| `rr[N]` / `rv[N]` | Add a data-recovery record / create recovery volumes — legitimate resilience feature, no abuse relevance |

**Switches (modifiers on the command above)**

| Switch | Plain-English meaning |
|---|---|
| `-p[pwd]` | **Set a password.** Encrypts file *contents* with AES-256; the archive's file listing (names, sizes) remains visible without the password |
| `-hp[pwd]` | **Encrypt both file data and headers.** The stronger variant — hides the file listing itself in addition to content, so nothing about what's inside the archive is visible without the password. This is the flag that defeats a cursory content-inspection/DLP look at an archive in transit |
| `-v<n>[k\|b\|f\|m\|M\|g\|G]` | **Create volumes** — splits the archive into multiple fixed-size parts (e.g. `-v100m` = 100 MB parts). Used to fit an exfil channel's size limits or to stay under data-transfer-size-threshold alerting (MITRE **T1030**) |
| `-r` | Recurse subfolders — pulls in an entire directory tree rather than just the files in the top-level path given |
| `-ep` | Exclude paths from names — stores files without their directory structure |
| `-ep1` | Exclude the base folder from names — keeps subfolder structure but drops the top-level starting folder from the stored paths |
| `-x<file>` | Exclude the specified file/pattern from the operation |
| `-ac` | Clear the Archive attribute on source files after compression |
| `-ao` | Only add files that have the Archive attribute set (i.e., changed-since-last-backup semantics) |
| `-df` | **Delete files after archiving** — same practical outcome as running the `m` (move) command instead of `a`; removes the operator's own local copy of the staged files once they're safely inside the archive |
| `-m<n>` | Set compression method/level (`0`=store, through `5`=best) |
| `-s` | Create a solid archive (all files compressed as one continuous stream — smaller output, but the whole archive typically has to be processed together, not file-by-file) |
| `-sfx[name]` | Create a self-extracting executable archive (a `.exe` instead of a `.rar`) — worth flagging on its own since it turns the archive itself into an executable file |
| `-ag[format]` | Generate the archive's filename from the current date/time — useful for an operator wanting a unique/unpredictable-looking output name per run rather than the same static filename every time |
| `-tk` | Keep the archive's original modification timestamp (rather than stamping it with the time of the archiving operation) — a timestomping-adjacent option worth flagging for timeline analysis |
| `-y` | Assume "Yes" on all confirmation prompts — needed for unattended/scripted invocations |
| `-inul` | Disable error/status messages — suppresses console output |
| `-ibck` | Run `WinRAR.exe` in the background (suppresses the small progress window that otherwise appears during a CLI-driven GUI-binary invocation; `Rar.exe` never shows one in the first place) |
| `-o[+\|-]` | Set the overwrite mode for existing files/output |
| `-cfg-` | Ignore the default configuration profile and the `RAR`/`WINRAR` environment variable for this run — an operator's way of not depending on (or leaving evidence in) any pre-existing WinRAR settings |

## Legitimate vs. Abused Usage

Because WinRAR is genuinely dual-use — installed on a huge share of ordinary Windows workstations for entirely benign reasons — the contrast here is less about *which* verb is used (unlike `certutil.exe`, there's no verb that's inherently suspicious) and entirely about **what's being archived, where it's staged, and what happens next**:

| Dimension | Legitimate use | Abuse (this note) |
|---|---|---|
| Source path | User's own Documents/Desktop, a project folder, a backup job's known source tree | A staging directory freshly populated by `robocopy`/`xcopy`/a recursive `Copy-Item`, often outside any normal working directory (`C:\Windows\Temp`, `C:\Users\Public`, `C:\ProgramData`) |
| Password use | Occasional, for genuinely sensitive personal files, chosen and remembered by the same user who set it | Frequent on high-value data, often a machine-generated or attacker-standard password (TONESHELL's tracked "unique 13-character password" per intrusion) never intended to be recalled by anyone — it only needs to survive until the archive reaches attacker infrastructure |
| Output location/naming | Wherever the user chose, typically named descriptively | Frequently `C:\Windows\Temp`, `C:\Users\Public`, or a randomized/date-based name via `-ag` — optimized to blend in or avoid a fixed, predictable filename |
| What happens next | Archive stays put, gets emailed to a known recipient, or gets backed up | Archive is immediately picked up by a separate exfil tool/channel and deleted or moved off-host shortly after creation |
| Invocation pattern | Interactive, via the GUI's right-click "Add to archive" | Scripted/CLI-driven, often via `Rar.exe` specifically (no GUI trace at all) inside a broader script or C2-tasked command |

## Quick Use-Case List

- Baseline archive creation of a staging directory (`a -r`) — no password, no splitting, the simplest case
- Password-protected archive with content-only encryption (`-p`) — filenames still visible in an unencrypted listing
- Password-protected archive with full header encryption (`-hp`) — filenames and structure hidden too, defeats a cursory content-inspection look
- Splitting a large archive into fixed-size volumes (`-v`) to stay under an exfil channel's size limit or below a data-transfer-size-threshold detection rule
- Silent/background invocation (`Rar.exe`'s inherent no-GUI behavior, or `WinRAR.exe -ibck`) for unattended/scripted runs
- Recursive directory staging (`-r`) pulling an entire target folder tree into one archive
- Excluding paths from stored names (`-ep`/`-ep1`) to obscure the archive's original source-directory structure
- Move-then-delete originals (`m`, or `a` + `-df`) to remove the operator's own staged copies once safely archived
- Self-extracting archive creation (`-sfx`) — turns the output into a directly-executable `.exe`
- Renamed/relocated `Rar.exe`/`WinRAR.exe` invocation to dodge simple `Image`-name detections
- Fleet-wide/mass staging — the same archive-then-exfil command pushed identically across many already-compromised hosts via C2 tasking
- Chained with a dedicated exfiltration tool or channel (a cloud-storage sync client, FTP/SFTP, or a C2 framework's own file-transfer primitive — see `Sliver/` and `PowerShell Empire/` in this same module) once the archive is ready
- Legitimate-baseline contrast use: routine personal/IT backup or file-sharing activity an analyst should expect to see as background noise on any estate where WinRAR is installed

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line — WinRAR is not itself an initial-access vector, same prerequisite as every other tool in this folder |
| WinRAR installed (or a portable copy dropped) | **Not present by default on Windows** (unlike this folder's OS-shipped binaries) — requires either a pre-existing legitimate install, or the attacker dropping a portable copy of `Rar.exe`/`WinRAR.exe` (a small, easily-staged binary, and one that carries a valid RARLAB code-signature regardless of where it's copied to) |
| Privilege level | No elevation inherent to the archiving operation itself — runs as whatever user/token invoked it; only needs read access to the files being archived and write access to the output path |
| Files already collected/staged | WinRAR has no collection capability of its own — a separate step (script, native command, another tool) must already have gathered the target files into a location WinRAR can point at |
| A separate exfiltration channel | WinRAR produces a finished archive file only — actually moving it off the host requires a distinct mechanism (cloud sync client, FTP/SFTP, C2 file-transfer primitive, manual upload) |
| Password (optional, for `-p`/`-hp` use cases) | Operator-chosen or scripted/generated in advance; needed at invocation time, which is also the only reliable point a defender can ever capture it |
