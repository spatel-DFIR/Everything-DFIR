# SharpDump — Target Evidence

What SharpDump leaves on the host it actually runs against. The shared `dbghelp.dll!MiniDumpWriteDump()` mechanic, the `RunAsPPL` access-control gate, and the general Sysmon 7/10 image-load/process-access story are already documented in depth in `../../ProcDump/04 - Target Evidence.md` — apply that page's mechanics directly; this page covers what's specific to SharpDump's own fixed behavior.

## Filesystem — the Headline Artifact

**SharpDump's hardcoded output-path convention is the strongest, most distinctive artifact this tool leaves anywhere.** Verified directly against `Program.cs`: every single run, regardless of target, writes to exactly one of these two paths and no other:

| File | Path pattern | Notes |
|---|---|---|
| Raw minidump | `%SystemRoot%\Temp\debug<PID>.out` | Written by `MiniDumpWriteDump()`, then deleted automatically on success — normally only visible mid-run or if the tool crashed/was interrupted before the delete step |
| Compressed output | `%SystemRoot%\Temp\debug<PID>.bin` | **Genuine gzip content** (`1F 8B` magic bytes) despite the `.bin` extension — the file that normally survives a completed run |

Unlike ProcDump or `comsvcs.dll`, where the operator picks the output path and filename freely on every invocation, **this pattern cannot be changed by any command-line argument** — only by editing and recompiling the source (`02`'s "Recompiling From Source" use case). A `debug<PID>.out` or `debug<PID>.bin` file appearing anywhere under `%SystemRoot%\Temp\` — especially where `<PID>` resolves to `lsass.exe`'s PID at a plausible timestamp — is close to a direct fingerprint for this specific tool, not just "LSASS dumping happened."

**`.bin` file content matters more than its extension.** A defender's file-type-by-extension logic would treat `debug808.bin` as an arbitrary binary blob; opening its first two bytes shows valid gzip magic (`1F 8B 08 00 ...`) regardless of what the file is named — the same content-over-extension principle `../../LOLBins/certutil/`'s cache-write finding and `../../ProcDump/05 - Detection and Hunting.md`'s dump-size heuristics already lean on elsewhere in this repo.

## Registry

**Minimal — a read, not a write.** SharpDump's only registry interaction is a single read of `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName`, performed only on the default (no-argument, LSASS-targeting) path to populate the console's `Operating System` banner line. This produces no registry-modification artifact and, since it's a read of a common key, no meaningfully distinguishing registry-audit trail either — don't expect a registry-based signal from this tool the way `../../ProcDump/03 - Source Evidence.md` documents for ProcDump's `EulaAccepted` write.

## Event Logs

| Event | Source | What it captures |
|---|---|---|
| Security 4688 (if command-line auditing enabled) | Process creation | `SharpDump.exe` (or its renamed equivalent) launching, with its one positional argument if present |
| Sysmon 1 | Process creation | Same, with richer `OriginalFileName`/`CommandLine` fields — `OriginalFileName` only useful if unmodified `AssemblyInfo.cs` metadata survived the build |
| Sysmon 7 | Image/DLL load | `dbghelp.dll` loading into the SharpDump process (or the reflective-load host process) — the shared signal documented in depth in `../../ProcDump/05 - Detection and Hunting.md` |
| Sysmon 10 | Process access | `OpenProcess()` against the target, with a `GrantedAccess` value consistent with a near-maximal request (`PROCESS_ALL_ACCESS`, see `03`) — a louder mask than Mimikatz's or ProcDump's own typical request |
| Sysmon 11 | File creation | `debug<PID>.out` (transient) and `debug<PID>.bin` (persistent) under `%SystemRoot%\Temp\` — the strongest, most fixed-pattern signal on this page |
| WinInit Event 12 | System log | LSA-protection (PPL) state at boot — only relevant when LSASS is the target; identical mechanic to `../../ProcDump/04 - Target Evidence.md`'s coverage, not re-derived |

## Sysmon Detail Specific to SharpDump

- **Sysmon 10's `GrantedAccess` field is the one place this tool's behavior diverges measurably from ProcDump/`comsvcs.dll`/Mimikatz.** All three of those either request a narrower DbgHelp-driven mask or (Mimikatz) an explicitly minimal read-only one; SharpDump's `Process.Handle`-based request is `PROCESS_ALL_ACCESS`. A hunt scoped only to the specific `0x1010`/`0x1410` values documented for Mimikatz will not catch SharpDump — see `05` for a broader mask-based rule.
- **Sysmon 11's file-path/name pattern is deterministic and PID-derived.** `debug<PID>.out`/`.bin` where `<PID>` is a plausible process ID (typically 3-6 digits) under `%SystemRoot%\Temp\` specifically — this is a narrow enough pattern to alert on directly, unlike ProcDump/`comsvcs.dll`'s fully operator-chosen filenames, which force a size/path-heuristic approach instead of a filename-pattern one.

## Endpoint-Security-Product Signature Behavior

- Because no official binary is ever released (per `01`), static AV signatures are inherently brittle against SharpDump specifically, the same positioning as Rubeus and Seatbelt — EDR products lean on behavioral detections instead: the `dbghelp.dll` load, the broad `PROCESS_ALL_ACCESS` request against a sensitive process, and the fixed `debug<PID>.*` file-naming pattern are all realistic EDR rule targets that don't depend on matching a specific compiled binary.
- AMSI applies to the PowerShell-reflection delivery path's loader script content, and to the assembly itself if built against .NET 4.8+ (the project's stated default is 3.5, which predates AMSI's .NET-CLR-level integration — an operator building against the older default framework is not subject to that specific AMSI hook at the assembly level, only at the PowerShell-loader-script level if that's the delivery method used).

## Memory Forensics

- The dump file itself **is** the memory-forensics artifact here — recovering an intact or partial `debug<PID>.out`/`.bin` from disk (even post-deletion, via standard file-carving of the now-freed `.out` clusters, or from a Volume Shadow Copy / backup capturing the brief window before deletion) hands an analyst the exact same credential-bearing content the operator captured, parseable with the identical Mimikatz `sekurlsa::minidump` workflow documented in `../../Mimikatz/sekurlsa (Credential Dumping)/`.
- If LSASS is the target and PPL blocks the attempt outright (per `../../ProcDump/01 - Overview.md`'s shared gate), there is no dump file to recover at all — the attempt's only trace is the failed `OpenProcess()` call itself (Sysmon 10, if logged, or an Access Denied exception surfacing in whatever console/log captured SharpDump's own error output).

## Distinguishing SharpDump From ProcDump / comsvcs.dll on a Live or Imaged Host

| Question | Points to SharpDump |
|---|---|
| Is there a `debug<PID>.out`/`.bin` file under `%SystemRoot%\Temp\` specifically? | Yes — this exact naming/location pattern is unique to unmodified SharpDump; ProcDump/`comsvcs.dll` output can be named/placed anywhere |
| Is the `.bin`/output file's content valid gzip, but the file has a non-`.gz` extension? | Yes — ProcDump/`comsvcs.dll` write raw, uncompressed `.dmp` content by default |
| Does Sysmon 10's `GrantedAccess` against the target show a near-maximal mask rather than a narrow DbgHelp-typical one? | Yes, if capturable — SharpDump's `PROCESS_ALL_ACCESS` request is broader |
| Is there an `EulaAccepted` registry artifact? | No — that's ProcDump-specific (Sysinternals EULA gate); SharpDump has none |
| Was the target process anything other than `lsass.exe`? | Only SharpDump and ProcDump support this natively via a PID argument — `comsvcs.dll`'s documented syntax is also PID-driven and equally general-purpose in practice, so this alone doesn't discriminate between SharpDump and `comsvcs.dll` |

## Building a Timeline

1. **Delivery/execution event** — process creation (Sysmon 1/Security 4688) for `SharpDump.exe` or the reflective-load event, with its one positional argument (if any) captured in the command line.
2. **`dbghelp.dll` image load** (Sysmon 7) into the SharpDump process — shared signal, see `../../ProcDump/04 - Target Evidence.md`.
3. **Process access against the target** (Sysmon 10) — the `PROCESS_ALL_ACCESS` request against the resolved PID.
4. **Raw dump file creation** (Sysmon 11) — `debug<PID>.out`, typically short-lived.
5. **Compressed file creation** (Sysmon 11) — `debug<PID>.bin`, the file that normally persists; its creation timestamp closely follows step 4's, since compression happens immediately after a successful dump with no operator-driven delay in between.
6. **Raw file deletion** — the `.out` file's deletion (visible via `$MFT`/USN Journal analysis even after the file itself is gone) closes the loop and confirms a *successful*, complete run rather than an interrupted one.
7. **[If exfiltrated]** — correlate the `.bin` file's creation timestamp against whatever exfil tool's own Source Evidence page documents next in the chain (`../../Rclone/04 - Target Evidence.md` for the receiving side, or that page's own Source Evidence for the sending side).
