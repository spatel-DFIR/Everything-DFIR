# SharpDump — Source Evidence

## Where "Source" Evidence Actually Lives For This Technique

Like `../../ProcDump/03 - Source Evidence.md` already establishes for its own two techniques, SharpDump is most often run **directly on the host already being victimized** — an operator with sufficient access has landed on the box and is dumping a process on it in place, not reaching out to a separate target over the network (SharpDump has no network client of its own — see `01`). When that's the case, "source" and "target" evidence collapse onto the same machine, and the meaningful question shifts to *where did the compiled binary come from, and under what identity did it run*, since the mechanical dump/compress artifacts themselves are covered fully in `04`.

When SharpDump **is** fired remotely (per `02`'s fleet-wide use case), the actual source-side evidence — command history, authenticated session state, tool staging — belongs to whichever delivery vector did the work (`../../PsExec/03 - Source Evidence.md`, `../../Impacket/wmiexec/03 - Source Evidence.md`, `../../LOLBins/wmic/03 - Source Evidence.md`) and is cross-linked rather than re-derived here.

## Weaponization and Delivery Artifacts

**No official SharpDump binary exists to fingerprint against.** Per `01`, the project releases no compiled binaries — every real-world sample is a custom Visual Studio build.

- **PE metadata is not a reliable static indicator by default, but is a real lead if unmodified.** Unmodified source produces `AssemblyTitle("SharpDump")` and `AssemblyProduct("SharpDump")` (verified directly against `Properties/AssemblyInfo.cs`), with `AssemblyVersion`/`AssemblyFileVersion` both hardcoded to `1.0.0.0` — an operator who doesn't bother editing `AssemblyInfo.cs` before compiling leaves these strings intact even after renaming the output `.exe`. Treat as supplementary, not primary, since editing this file before a build takes seconds.
- **Compiled-to-disk EXE**: standard AV signature scanning applies; a stable file hash only exists per-compile, since (like Rubeus/Seatbelt) source is public and every build is operator-specific.
- **Download artifact, if staged from the internet directly**: a fetched `SharpDump.exe` or a cloned/downloaded repo carries a `Zone.Identifier` Alternate Data Stream (`ZoneId=3`) if pulled via a browser or `Invoke-WebRequest` without stream suppression — same MOTW pattern this repo has documented repeatedly (`../../LOLBins/certutil/`, `../../ProcDump/03 - Source Evidence.md`).
- **Unmanaged/reflective execution (Cobalt Strike `execute-assembly`, PowerShell `[Assembly]::Load()`)**: the CLR gets loaded into a process that may not normally host .NET at all — an anomaly signal independent of anything SharpDump-specific.
- **AMSI**: applies to the loader script's content when delivered via PowerShell reflection (the base64 blob and `[SharpDump.Program]::Main()` invocation lines), and to .NET 4.8+ assemblies directly if the operator targets a newer framework than the project's default 3.5.

## Command-Line / Shell History

- If invoked interactively, the full command (including any PID argument) lands in `ConsoleHost_history.txt` (PowerShell) or is visible via Sysmon Event ID 1's `CommandLine` field. SharpDump's command line carries **no credential material** at all — unlike Rubeus (`/rc4:HASH`) or Mimikatz, there is nothing secret to leak via command-line logging; the only sensitive value ever present is a numeric PID.
- A bare `SharpDump.exe` or `SharpDump.exe <number>` invocation is, on its own, low-signal text — the useful correlation is pairing this command-line entry with the file-creation timestamp of the resulting `debug<PID>.out`/`.bin` in `04`, not the command line in isolation.

## Process and Handle Artifacts

The single most distinctive source-side technical fact for this tool: **SharpDump's `targetProcess.Handle` call requests `PROCESS_ALL_ACCESS`** (`0x1F0FFF` — `STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF`, verified directly against .NET Framework's own reference source, `Process.cs`/`NativeMethods.cs`), because it uses the generic `Process.Handle` property rather than a narrow, purpose-built `OpenProcess()` call the way Mimikatz's `sekurlsa` module or ProcDump's DbgHelp-driven request do. This is a **maximal, all-rights access request**, not a minimal read-only ask:

| Tool | Access requested against target process |
|---|---|
| SharpDump (`Process.Handle`) | `PROCESS_ALL_ACCESS` (`0x1F0FFF`) |
| Mimikatz `sekurlsa::logonpasswords` | `PROCESS_VM_READ \| PROCESS_QUERY_LIMITED_INFORMATION` (`0x1010`) — see `../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md` |
| Mimikatz `sekurlsa::pth` | Adds `PROCESS_VM_OPERATION \| PROCESS_VM_WRITE` on top of the above — still narrower than SharpDump's blanket request |

A process (`SharpDump.exe`, or whatever host process it's reflectively loaded into) requesting near-full access rights against `lsass.exe` — or any other process it targets — is a louder, easier-to-flag signal than the deliberately minimal reads other credential-access tools in this repo make. Any GrantedAccess-mask-based Sysmon 10 rule tuned narrowly to Mimikatz's `0x1010`/`0x1410` values will **miss** this; a rule that also flags a broad/near-maximal `GrantedAccess` value against a sensitive process will catch it loudly.

## Network Connection State

None. SharpDump makes no network connections of any kind — the entire operation is a local `OpenProcess()`/`MiniDumpWriteDump()`/`GZipStream` sequence. Any network activity observed alongside a SharpDump run belongs to the delivery vector that got it onto the host, or the exfil step that moved the resulting `.bin` off afterward (`../../Rclone/`) — neither is SharpDump's own traffic.

## Memory Forensics

- If loaded reflectively (`execute-assembly`, `[Assembly]::Load()`), the SharpDump CLR module exists **in memory only**, with no corresponding on-disk PE — the standard "unbacked executable memory region" signature tools like Moneta, PE-sieve, or EDR memory-scan heuristics are built to catch, independent of anything SharpDump-specific.
- Unlike a live credential-dumping tool that decrypts and prints plaintext material to its own console (Mimikatz's `sekurlsa::logonpasswords`), SharpDump never decrypts or displays credential content itself — the raw dumped memory sits inside the `.out`/`.bin` file it writes to disk, not in the SharpDump process's own working memory beyond the brief buffer used during the `MiniDumpWriteDump()` call and the `File.ReadAllBytes()`/`GZipStream.Write()` compression pass. A live memory capture of the SharpDump process itself is therefore a much thinner lead than capturing the dump file it produced.

## Timeline Correlation Value

The strongest source-side timeline anchor is the process-creation event for `SharpDump.exe` (or the reflective-load event, if applicable) — since the command line carries no credential material and no operator-configurable output path, correlating this single event's timestamp against the resulting `debug<PID>.out`/`.bin` file-creation timestamp on the same host (`04`) is normally sufficient to tie "SharpDump ran" directly to "this specific dump file is the one it produced," with almost no ambiguity given the deterministic `debug<PID>` naming — a cleaner 1:1 correlation than tools whose output naming is fully operator-chosen (ProcDump, `comsvcs.dll`).
