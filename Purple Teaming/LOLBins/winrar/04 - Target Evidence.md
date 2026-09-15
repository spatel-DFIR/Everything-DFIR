# LOLBins — WinRAR — Target Evidence

Evidence left on the **target/victim** host — where the archiving step in this note always executes. Because WinRAR is a genuinely dual-use, third-party-signed tool with no LOLBAS catalog entry and no fixed OS install path (see `01 - Overview.md`), there is no side-effect cache write or download-URL artifact the way `certutil.exe` leaves behind — the strongest evidence classes here are **process command-line capture** (which may include the archive password, if the operator set it inline) and **WinRAR's own MRU registry history**.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Abuse from Legitimate Use](#distinguishing-abuse-from-legitimate-use)

---

## Filesystem

| Artifact | Detail |
|---|---|
| The archive itself (`.rar`, `.part*.rar`, or `.exe` if `-sfx`) | Wherever the operator's `OutFile` argument pointed — no fixed naming convention, entirely operator-controlled. If not yet moved off-host or deleted, this is the single most direct piece of evidence available |
| `Rar.exe` / `WinRAR.exe` binary itself, if a portable copy was dropped | No default OS-enforced location — could be anywhere the operator has write access. Authenticode/`OriginalFileName` still resolve it to the genuine RARLAB binary regardless of the name/path it was run under (see the Renamed-Binary use case in `02`) |
| Prefetch | `RAR.EXE-<HASH>.pf` / `WINRAR.EXE-<HASH>.pf` updates on every run — **low-uniqueness on its own** on any estate where WinRAR is legitimately installed. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `Rar.exe`/`WinRAR.exe` executions, including a full path — useful for confirming a renamed/relocated binary's actual on-disk path even after the file itself is deleted. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Staging directory remnants | If `-df`/the `m` command was **not** used, the original collected files remain in the staging location after archiving — a separate, independent artifact of the collection step that preceded this note's scope |
| Zone.Identifier / MOTW on the archive WinRAR *creates* | Not applicable — a locally-created archive has no download provenance to mark; MOTW propagation only matters for archives WinRAR *extracts from*, which is outside this note's exfil-staging scope |

## Registry

WinRAR maintains its own **MRU (Most Recently Used) history** in the user's registry hive — verified against the [winreg-kb project's WinRAR documentation](https://winreg-kb.readthedocs.io/en/latest/sources/application-keys/WinRAR.html) (cross-referenced against Plaso's dedicated `winrar_mru` parser plugin, confirming these keys are an established, actively-parsed forensic artifact):

| Key | Contents |
|---|---|
| `HKEY_CURRENT_USER\Software\WinRAR\ArcHistory` | A numbered list of recently accessed/created archive **paths** |
| `HKEY_CURRENT_USER\Software\WinRAR\DialogEditHistory\ArcName` | Archive-name values typed into WinRAR's own GUI dialogs |
| `HKEY_CURRENT_USER\Software\WinRAR\DialogEditHistory\ExtrPath` | Extraction-destination paths typed into WinRAR's own GUI dialogs |

**This note's one open caveat:** winreg-kb's own documentation flags its WinRAR section as preliminary/needing refinement — treat the exact per-value naming/format as generally reliable (it's independently corroborated by Plaso's parser) but not exhaustively verified here. Same MRU string-list mechanics as documented generically in `Windows/07 - File and Folder Opening (User Activity).md` — not re-derived here.

**Important limitation for this technique specifically:** these keys are populated by **WinRAR.exe's GUI dialogs**. A `Rar.exe` console invocation, or a `WinRAR.exe` invocation driven entirely by command-line switches with no dialog interaction, does **not** necessarily populate the same GUI-dialog-history keys the way an interactive "Add to archive..." click does — this note could not confirm from the sources reviewed whether CLI-driven `WinRAR.exe` runs populate `ArcHistory` at all. Treat `ArcHistory`/`DialogEditHistory` as strong evidence of **interactive GUI use** and weak-to-absent evidence of the CLI-driven, `Rar.exe`-favored pattern this note's use cases mostly describe.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Security** | **4688** (Process Creation) | **The primary native evidence source** — captures the full `Rar.exe`/`WinRAR.exe` command line verbatim, including an inline `-p`/`-hp` password, if command-line auditing is enabled. Without it, 4688 alone only confirms *that* the binary ran, not with what arguments |
| Security | 4689 | Process termination — limited independent value; archiving is typically a short, single-shot operation |
| System | 7036 | **Not applicable** — no service is created or started by this technique |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | **Highest-value single artifact.** `CommandLine` captures the full command including any inline password — `a -r -hpS3cr3tP@ss ...` — independent of whether native 4688 command-line auditing is separately enabled. `Image` reads `Rar.exe`/`WinRAR.exe` unless the renamed/relocated variant was used, in which case `OriginalFileName` (from the PE's own embedded metadata) and the Authenticode signature still tie it back to the genuine RARLAB binary |
| 3 (Network Connect) | **Not generated by WinRAR itself** — WinRAR performs no network I/O (see `01 - Overview.md`). A Sysmon 3 event around the same time as a WinRAR process-create belongs to whatever separate exfil tool/channel picked the archive up next, not to WinRAR |
| 11 (File Create) | Fires for the archive `OutFile` itself, and once per volume for a `-v`-split archive — several near-simultaneous Sysmon 11 events with sequential `.part1.rar`/`.part2.rar`/... names is a distinguishing pattern worth flagging on its own |
| 13 (Registry Value Set) | Would fire for `ArcHistory`/`DialogEditHistory` writes if a GUI-dialog-driven invocation occurred — not expected for a purely CLI-driven `Rar.exe` invocation, per the Registry caveat above |

## Network-Layer Evidence

WinRAR itself generates **zero** network traffic — any network-layer evidence around this technique belongs entirely to the separate exfiltration channel used after the archive is created:

| Source | What It Shows |
|---|---|
| Proxy / firewall / Zeek logs | Whatever the follow-on transport was — an FTP/SFTP session, an HTTPS upload to cloud storage, a C2 beacon's file-transfer traffic. Correlate the timestamp against the WinRAR archive-creation event (Sysmon 1 / Security 4688) — a short gap between "archive finishes writing" and "large outbound transfer begins" on the same host is the actual technique-level signal, not anything WinRAR itself produces on the wire |
| NetFlow | A distinctive **outbound data volume spike** shortly after the archive-creation timestamp, roughly matching the archive's on-disk size (or the sum of its volumes, if split) — a useful corroborating data point even without deep packet inspection |

## Endpoint Security Product Signatures

Because the delivery mechanism is a legitimate, RARLAB-signed binary and compression/encryption of arbitrary files is not inherently malicious, static file-signature detection on `Rar.exe`/`WinRAR.exe` itself is a non-starter — detection depends entirely on behavioral heuristics (source-path anomalies, password use combined with a non-standard staging location, immediate follow-on network activity). Because WinRAR has no LOLBAS catalog entry and no certutil/msbuild-style single "smoking gun" artifact, this technique is generally **less well-covered by off-the-shelf community detection-rule repositories** (Sigma/Elastic/Splunk) than the other binaries in this `LOLBins/` folder — most mature detections for this specific pattern are custom, built around the source-path/staging-location and password-plus-network-activity correlation described in `05 - Detection and Hunting.md`, rather than a single published rule this note can cite the way `../certutil/04 - Target Evidence.md` cites named Sigma/Elastic/Splunk rules.

## Memory Forensics

`Rar.exe`/`WinRAR.exe` instances run as ordinary, short-lived, non-hidden processes — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual. The one genuinely valuable memory-forensics angle: **if the process is still running (or was captured via a full memory acquisition close to the time it ran), the plaintext archive password may still be recoverable from the process's own memory space** — string-search a memory image or a live process dump for the password pattern near the `Rar.exe`/`WinRAR.exe` process, since this is one of the only surviving places a `-hp`-protected archive's password could still exist after the fact if command-line logging wasn't enabled and the C2 tasking layer isn't recoverable.

## Building a Timeline

The tightest anchor sequence, per invocation: **Sysmon 1 (process create, full command line including any password) → Sysmon 11 ×1 (or ×N for a `-v`-split archive, one per volume) → [gap] → network-layer evidence of the separate exfil channel picking up the archive.** Unlike this module's download-capable LOLBins, there's no DNS/network-connect step to anchor between process-create and file-create — WinRAR's own contribution to the timeline starts and ends with the archive being written to disk. The registry MRU keys (`ArcHistory`/`DialogEditHistory`), where populated, provide a secondary, independently-recoverable timestamp source specifically for GUI-driven use.

## Distinguishing Abuse from Legitimate Use

> 🔴 A `Rar.exe`/`WinRAR.exe` process-creation event alone is not a finding — this is a mainstream, widely-installed utility. **Source path, password use, output location, and what happens in the minutes after are the entire signal.**

| Dimension | Legitimate use | Abuse (this note) |
|---|---|---|
| Source path | User's own Documents/Desktop, a known project or backup source tree | A freshly-populated staging directory, often outside any normal working path (`C:\Windows\Temp`, `C:\Users\Public`, `C:\ProgramData`) |
| Password | Occasional, user-chosen and rememberable, or absent entirely | Frequent on high-value data; often machine-generated/attacker-standard and never meant to be recalled by a human |
| Output naming/location | Descriptive, wherever the user chose | Randomized (`-ag`) or blended-in naming, staged in a non-standard directory |
| Registry MRU (`ArcHistory`) | Populated — matches ordinary interactive GUI use | Frequently **absent**, since the favored `Rar.exe` console invocation and pure-CLI `WinRAR.exe` use may not populate it — an unusual gap between a Sysmon/4688-confirmed WinRAR execution and a matching `ArcHistory` entry is itself worth noting |
| What follows | Nothing unusual — archive stays put, gets emailed, gets backed up | A separate, often large, outbound network transfer within a short window of the archive-creation timestamp |
