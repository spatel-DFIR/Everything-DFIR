# Impacket — smbexec.py — Target Evidence

Evidence left on the **target/destination** host. `smbexec.py` produces the **highest-volume, most repetitive** event trail of the three Impacket lateral-movement tools in this folder — not because any single cycle is unusually rich, but because the *same* create-service/start/delete cycle documented in `01 - Overview.md` fires **once per command**, not once per session.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon-if-deployed)
- [Named Pipe Detail](#named-pipe-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Three-Way Contrast: psexec.py vs. smbexec.py vs. wmiexec.py](#three-way-contrast-psexecpy-vs-smbexecpy-vs-wmiexecpy)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Transient batch file | `%SystemRoot%\<8-random-letters>.bat` (e.g. `C:\Windows\aBcDeFgH.bat`) — created by the target's own `cmd.exe` via the `echo ... > <batchFile>` clause, executed by a **child** `cmd.exe`, then deleted by the trailing `del <batchFile>` clause of the *same* compound command line. Exists only for the brief window between service start and that final `del` — a command that runs long enough to hit Windows' service-start timeout can leave this file orphaned, since `del` never gets reached |
| Output-relay file (`SHARE` mode) | `\\<COMPUTERNAME>\<share>\__output_<8-random-letters>` — under the default `-share C$`, this resolves to `C:\__output_<8-random-letters>`. **Cleaned up every cycle** — the operator's SMB session explicitly calls `deleteFile()` after reading it back |
| Output-relay file (`SERVER` mode) | **Same filename, same location — but never explicitly deleted.** Verified directly against source: `get_output()`'s `SERVER`-mode branch only reads/deletes the *local* copy the target pushed via the batch command's `copy` clause; it never issues a `deleteFile()` against the original on the target. Since `OUTPUT_FILENAME` is a session-constant, every subsequent command simply **overwrites** the same file — the practical result is **one persistent, repeatedly-overwritten file abandoned on the target's share** for the life of the engagement and beyond, unless something else cleans it up. This is the single most useful `SERVER`-mode-specific artifact in this note |
| Prefetch | `CMD.EXE-<HASH>.pf` updates with each cycle — low-uniqueness (every Windows host already has this Prefetch entry from ordinary use), so this is a weak signal on its own. No uniquely-named dropped-binary Prefetch entry exists here, unlike `psexec.py`. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record `cmd.exe` executions — common, low-uniqueness, and **far weaker** here than for `psexec.py`'s uniquely-named dropped binary. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | Not applicable — nothing is delivered as a file from the operator; the only files created are written locally by the target's own `cmd.exe` |
| $MFT / $LogFile / $UsnJrnl | Given how transient the `.bat` and (`SHARE`-mode) output files are, NTFS-level artifact recovery is often the only way to reconstruct a `SHARE`-mode session after the fact — see `Windows/NTFS/01 - MFT Entry Structure and Attributes.md`, `Windows/NTFS/05 - $LogFile (NTFS Transaction Journal).md`, and `Windows/NTFS/06 - $UsnJrnl (USN Change Journal).md` for the general recovery techniques this note doesn't re-derive |

## Registry

| Key | Detail |
|---|---|
| `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` | Created and marked for deletion on **every** command cycle — `hRDeleteService()` fires unconditionally right after `hRStartServiceW()`, regardless of whether the start succeeded. `ServiceName` is a random 8-character string (or the operator's `-service-name` value) reused for every cycle in the session — don't expect a new name each time the way you'd see a new binary each time with `psexec.py`'s `-remote-binary-name` |
| Key lifetime | Actual removal of the registry key happens when the service *stops* (all handles closed, process exits), which for a fast command is well under a second — live registry capture or a crash dump is realistically the only way to catch the key present. A command that runs long enough to hit the SCM's start-timeout extends this window measurably, since Windows has to give up waiting before it kills the process |
| Service lifecycle anomaly | A service repeatedly created, started, and marked-for-deletion within the same second, **many times in a row under the same name**, is itself the anomaly — no legitimate software installer creates and destroys the same service key in a tight loop like this |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **System** | **7045** | "A service was installed in the system" — fires **once per command**, not once per session. Expect a **burst** of these sharing one identical `ServiceName`, arriving seconds apart. This is smbexec's single highest-value signal, and the burst pattern is what distinguishes it from `psexec.py`'s lone 7045 |
| System | 7036 | Service Control Manager start/stop notification — may or may not clearly register given how briefly the "service" actually runs before Windows tears it down |
| Security | 4624 (Logon Type 3 — Network) | Expect **just one** for the whole session — the SMB session (and its SVCCTL binding) is established once and reused. The contrast between "one 4624" and "many 7045" from the same source is itself a strong session-level heuristic |
| Security | 4672 | Special privileges assigned to the new logon — confirms an admin-equivalent token |
| Security | 5140 | Network share object accessed — `C$` by default (or whatever `-share` targets), repeated across the session as each cycle's output gets written/read |
| Security | 5145 | Detailed share-file access (if the granular object-access auditing subcategory is enabled) — shows the `__output_<rand8>` filename being written/read/deleted, repeatedly |
| Security | 4697 | "A service was installed" — Security-log twin of System 7045, only present if "Audit Security System Extension" is explicitly enabled. Same burst pattern as 7045 when it's on |
| Security | 4688 | Process creation — if command-line auditing is enabled, shows the **full** compound command line (`echo ... & cmd.exe /Q /c <batchFile> & del <batchFile>`) verbatim, then the child `cmd.exe` running the batch file, then whatever the operator's actual command spawns |
| Security | 4689 | Process termination — repeated per cycle |

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| **1 (Process Create)** | **The single most information-dense artifact for this tool.** The outer `cmd.exe`'s `CommandLine` field captures the **entire** batch/echo/redirect/del template verbatim — including the operator's actual command text, embedded directly in the `echo` clause, readable without needing to correlate against a separate file. A second Sysmon 1 event shows the **child** `cmd.exe` (`services.exe → cmd.exe → cmd.exe`) launched specifically to run the `.bat` file — a three-hop chain before the operator's own command even executes |
| 3 (Network Connect) | Inbound TCP 445 (or 139) from the operator, once for the session. `-mode SERVER` additionally generates an **outbound** connection from the target to the operator's IP on TCP 445 (the `copy` clause) — an unusual direction worth flagging on its own |
| 11 (File Create) | The `.bat` file create, plus the output-file create — both repeat per command |
| 13 (Registry Value Set) | Service key creation under `CurrentControlSet\Services\` — repeats per command, producing a high volume of near-identical events in a chatty session |
| 17 / 18 (Pipe Created / Connected) | `\PIPE\svcctl` — the standard MS-SCMR RPC pipe. **This is a materially weaker signature than `psexec.py`'s `\PIPE\RemCom_*` family**, because `\PIPE\svcctl` is the same pipe used by *any* legitimate remote service-management activity (`sc.exe \\host`, the Services MMC snap-in, RSAT, monitoring tooling). Pipe observation alone is not distinctive here — it only becomes meaningful correlated against the burst-timing pattern above |
| 22 (DNS Query) | Not typically generated on the target itself for this tool |

## Named Pipe Detail

Unlike `psexec.py`, `smbexec.py` introduces **no custom named pipe of its own** — it rides the generic, standard `\PIPE\svcctl` MS-SCMR pipe that any remote service-control operation uses. There is no equivalent of RemCom's misspelled `RemCom_communicaton` pipe family to hunt on here; the pipe itself is not a useful standalone IOC for this tool. See the hunting-priority ranking in `05 - Detection and Hunting.md`.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | Repeated `CreateServiceW`/`StartServiceW`/`DeleteService` **triplets** against `\PIPE\svcctl`, one triplet per command, all within a tight session window — the repetition count itself is the distinguishing feature versus a single legitimate remote-service-management operation |
| Zeek `smb_files.log` / `smb_mapping.log` | Repeated tiny write/read/delete cycles against the **same** `__output_<rand8>` filename under `C$` (or whatever `-share` targets) — `SHARE` mode shows a full write→read→delete pattern each cycle; `SERVER` mode shows writes with **no matching delete**, and a separate outbound file push to the operator's IP |
| NetFlow / firewall logs | A single sustained TCP 445 (or 139) connection from one internal host to another for the whole session — simpler than `wmiexec.py`'s split DCOM+SMB footprint, closer to `psexec.py`'s single-connection shape. `SERVER` mode additionally shows a short reverse-direction TCP 445 burst from the target back to the operator |

## Endpoint Security Product Signatures

Because there is **no dropped executable to hash** — the entire technique is a service `ImagePath` string — static file-signature detection largely doesn't apply here, similar to `wmiexec.py`. Detection instead depends on behavioral heuristics against the service-creation call itself: many EDR/SIEM rule packs carry specific detection logic for "service created with `cmd.exe`/`%COMSPEC%` as the binary path" and for the `echo ... ^> ... > *.bat` redirect pattern specifically, since this technique (and tools built on the same idea) has been public and well-documented for years. The *absence* of any such alert on a host that otherwise shows the 7045 burst pattern is worth investigating on its own.

## Memory Forensics

The `cmd.exe` instances involved run as ordinary, short-lived, non-hidden processes — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual about them. Their forensic value in memory is recovering the exact command text if it's caught live, since the `.bat` file is typically gone by the time an image is acquired — but because the operator's command is embedded directly in the **outer `cmd.exe`'s command line** (not hidden inside the batch file alone), Sysmon 1 / Security 4688 command-line logging recovers it just as completely as a live memory capture would, if either is enabled.

## Building a Timeline

The tightest, highest-confidence timeline anchor, **per command**, is: **7045 (service install) → 7036 (start, if it registers) → Sysmon 1 (outer `cmd.exe`, full command line visible) → Sysmon 11 (`.bat` file create) → Sysmon 1 (inner `cmd.exe`, batch execution) → Sysmon 11 (output file create) → [SMB read + delete of output, `SHARE` mode only] → Sysmon 11 (`.bat` file deleted by its own `del` clause).** All of this typically lands within a span of well under a second per command on a fast one, extending toward Windows' service-start timeout ceiling for a slow one. Stitch **many** of these cycles together, all sharing the same `ServiceName`, bounded by a single Security 4624 at the start of the session, to reconstruct the full command-by-command shape of the operator's session — this is smbexec's unique advantage for an analyst: the event log burst is, in effect, a command history.

## Three-Way Contrast: psexec.py vs. smbexec.py vs. wmiexec.py

> 🔴 **All three tools in this folder use the same admin-share/credential prerequisites, but leave structurally different evidence.** Use this table to tell them apart from evidence alone, without needing to have caught the live traffic.

| Dimension | `psexec.py` | `smbexec.py` | `wmiexec.py` |
|---|---|---|---|
| Service created? | **Yes — once per session** | **Yes — once per command** (burst) | **No — never** |
| Binary dropped? | Yes — RemCom-derived `.exe`, consistent hash by default | No — `cmd.exe`/`%COMSPEC%` only, nothing new written as an executable | No |
| Execution context | SYSTEM | SYSTEM | The authenticating user |
| System 7045 count per session | 1 | **N (one per command)** | 0 |
| Security 4624 count per session | 1 | 1 | Up to 2 (SMB + DCOM, unless output-suppressed) |
| Named pipe signature | `\PIPE\RemCom_*` (custom, misspelled, highly distinctive) | `\PIPE\svcctl` (generic MS-SCMR pipe, weak on its own) | None — DCE/RPC over TCP, no SMB pipe involved in execution |
| Default share | `ADMIN$` | `C$` | `ADMIN$` |
| Transport | SMB (445/139) only | SMB (445/139) only | DCOM/RPC (135 + dynamic port) always; SMB (445) only if output capture is on |
| Filesystem footprint | One persistent-until-cleanup binary + Prefetch/Amcache entry | Transient `.bat` + transient (`SHARE`) or abandoned (`SERVER`) output file | Transient `__<timestamp>` output file only, if output capture is on |
| One-shot CLI command support | Yes (`command` positional) | **No — always interactive; script via stdin piping** | Yes (`command` positional) |
| Built-in evasion flags | `-file` (swap binary), `-service-name`/`-remote-binary-name` (rename) | `-service-name` (rename only — no binary to swap) | `-silentcommand`/`-nooutput` (remove whole artifact classes), `-share` |
| Tool's own stated stealth posture | Not explicitly disclaimed | **Explicitly disclaimed in source: "Certainly not a stealthy way"** | Explicitly designed to avoid SCM noise |

See `Windows/12 - Lateral Movement.md` for the broader PsExec-family comparison table and `Windows/10 - Persistence Mechanisms/Services.md` for general service-based execution artifacts this note deliberately doesn't re-derive.
