# SafetyKatz — Overview

> 🔴 **Red Flag Principle:** SafetyKatz is not a standalone credential dumper — it's a **two-stage-in-one-process chain**: it calls the identical `dbghelp.dll!MiniDumpWriteDump()` API documented in `../SharpDump/01 - Overview.md` and `../../ProcDump/01 - Overview.md` to dump `lsass.exe` to a hardcoded, **non-PID-qualified** `%SystemRoot%\Temp\debug.bin`, then immediately **manually PE-loads a modified, pre-compiled Mimikatz binary directly into its own process memory** (a hand-rolled reflective-PE-loader, not `Assembly.Load` — this is unmanaged x64 mimikatz.exe, not a .NET assembly) and runs it in-thread against that dump file before deleting it — all inside a single `SafetyKatz.exe` execution, with no separate transfer/offline step required. Verified directly against the live source (`SafetyKatz/Program.cs`, `Constants.cs`): **the compiled tool takes zero command-line arguments** — `Main()` never reads `args` for targeting purposes and always resolves `lsass.exe` by name, unlike `../SharpDump/`'s PID-argument flexibility. And like SharpDump, it acquires its process handle via .NET's generic `Process.Handle` property — requesting **`PROCESS_ALL_ACCESS`**, not Mimikatz's own minimal `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION` ask.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/SafetyKatz`](https://github.com/GhostPack/SafetyKatz), its `README.md`, and its full commit/branch/tag history fetched live via the GitHub API (`curl -s https://raw.githubusercontent.com/GhostPack/SafetyKatz/master/README.md` and `curl -s https://api.github.com/repos/GhostPack/SafetyKatz` — both plain-text metadata lookups, no rendering or scraping involved):

- **Primary author:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`) — the same GhostPack author family as `../SharpUp/`, `../SharpDump/`, `../../Rubeus/`, and `../../Seatbelt/`, all already built in this repo. **License:** BSD 3-Clause, copyright 2018 Will Schroeder (confirmed against the repo's `LICENSE` file).
- **Composite tool, explicit lineage — not an original technique.** The README states this plainly: SafetyKatz is "a combination of a slightly modified version of [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project and [@subtee](https://twitter.com/subtee)'s [.NET PE Loader](https://github.com/re4lity/subTee-gits-backups/blob/master/PELoader.cs)." Two components, two separate upstream authors, glued together by harmj0y: a minidump writer (the same `MiniDumpWriteDump()` primitive as `../SharpDump/`) feeding a customized, pre-compiled Mimikatz binary that SafetyKatz loads and runs **entirely in its own process memory** via a manually-implemented PE loader/mapper — no `LoadLibrary`, no `Assembly.Load`, no dropped second EXE.
- **Documented modifications to each upstream component**, per the README's own "Modifications" section: (1) subtee's PE Loader was "slightly modified so some of the pointer arithmetic worked better on .NET 3.5"; (2) gentilkiwi's Mimikatz was "modified to strip some functionality for size reasons, and to automatically run the `sekurlsa::minidump` mode (deleting the minidump file after)." This second point is the mechanical core of the entire tool — the embedded Mimikatz build is hardcoded to open `debug.bin`, run `sekurlsa::minidump` against it, then (per the README's sample output and the tool's stated purpose) `sekurlsa::logonpasswords`/`sekurlsa::ekeys`, then delete the file — none of that sequence is driven by any SafetyKatz command-line flag; it's baked into the modified Mimikatz build itself, which is not included as buildable source in this repo (it ships only as a compressed, Base64-encoded blob in `Constants.cs`, generated via PowerSploit-style `Out-CompressedDLL`).
- **First commit:** 2018-07-24. **Total commit history: 6 commits**, verified live via the GitHub API (`gh api repos/GhostPack/SafetyKatz/commits`) — an initial commit, two README-formatting fixes, a community `.gitignore` PR (`cnotin`, 2018-07-25), and one final commit (2018-08-20) that moved the embedded compressed-Mimikatz blob into its own `Constants.cs` file. **Releases/tags: zero, ever** (`/releases` and `/tags` both return empty arrays) — same "compile it yourself" posture as every other GhostPack tool in this repo. The README states this explicitly: "We are not planning on releasing binaries for SafetyKatz, so you will have to compile yourself :)"
- **Development activity: frozen since 2018-08-20.** Only two contributors ever, verified via the GitHub API: `harmj0y` (5 commits) and `cnotin` (1, the `.gitignore` addition). A single branch (`master`) exists — no forks of note merged upstream, no version-currency updates to track. The repo is not archived, but has had no functional commits in over seven years as of this writing.
- **Build target:** .NET Framework **3.5**, confirmed directly in `SafetyKatz.csproj` (`<TargetFrameworkVersion>v3.5</TargetFrameworkVersion>`, `<OutputType>Exe</OutputType>`, `<AssemblyName>SafetyKatz</AssemblyName>`) — same generation as `../SharpDump/` and `../SharpUp/`. The embedded Mimikatz binary itself, per the README's own sample console output, is version **"2.1.1 (x64) built on Jul 7 2018."**
- **The embedded Mimikatz is a fixed, frozen snapshot — not the live upstream `sekurlsa` module.** Because the modified Mimikatz ships only as a pre-compiled, compressed blob (`Constants.cs`'s `compressedMimikatzString`, ~628 KB decompressed) rather than buildable source, SafetyKatz's actual credential-parsing logic never received any of the upstream Mimikatz project's post-2018 changes (new Windows-build LSASS-structure signatures, new credential providers) unless an operator manually recompiles their own updated variant — see `../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md` for what the *current* upstream `sekurlsa` module supports; SafetyKatz's embedded copy is a 2018 snapshot of that same engine's mechanics, not necessarily current build coverage.

## How It Works

SafetyKatz's entire logic lives in `SafetyKatz/Program.cs`. Verified line-by-line against the live source:

```csharp
[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall,
    CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile,
    uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);
```

```
SafetyKatz.exe (args are never consulted for targeting — see Switches table below)
──────────────────────────────────────────────────────────────────────────────────
1. IsHighIntegrity()?  →  WindowsPrincipal(identity).IsInRole(Administrator)
   FAIL → print "[X] Not in high integrity, unable to grab a handle to lsass!" and EXIT.
          Unlike SharpDump (gate only fires for a target literally named "lsass"),
          SafetyKatz's gate is UNCONDITIONAL — it always checks integrity first,
          before anything else runs, because it always targets lsass.

2. Sanity checks:
   ├─ %SystemRoot%\Temp\ must exist        → else print error and EXIT
   └─ IntPtr.Size == 8 (64-bit process)     → else print "Process is not 64-bit,
                                                this version of Mimikatz won't work
                                                yo'!" and EXIT (the embedded Mimikatz
                                                blob is a fixed x64 build only)

3. Minidump()  — no PID argument ever passed by Main(); always resolves
   Process.GetProcessesByName("lsass")[0]. (The Minidump() function signature
   DOES accept an optional pid parameter, but Main() never supplies one — this
   is dead flexibility in the current public source, not an exposed feature.)
   ├─ targetProcessHandle = targetProcess.Handle
   │    → .NET's generic Process.Handle property, NOT a narrow OpenProcess()
   │      call — requests PROCESS_ALL_ACCESS (0x1F0FFF), the same maximal-
   │      access pattern documented for ../SharpDump/01 - Overview.md, and a
   │      far louder ask than Mimikatz's own PROCESS_VM_READ |
   │      PROCESS_QUERY_LIMITED_INFORMATION (0x1010) — see
   │      ../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md
   └─ MiniDumpWriteDump(handle, pid, fileHandle, dumpType=2, ...)
        → dumpType is a hardcoded literal 2 == MiniDumpWithFullMemory, always
          a full dump, written RAW (no compression at this stage — contrast
          SharpDump's automatic GZip step) directly to:
          %SystemRoot%\Temp\debug.bin   ← no PID in the filename, unlike
                                            SharpDump's debug<PID>.out/.bin

4. Decompress the embedded, pre-modified Mimikatz PE from Constants.cs:
   Convert.FromBase64String(Constants.compressedMimikatzString) → DeflateStream
   → 628,736-byte raw x64 PE image held entirely in managed memory (never
     touches disk as a separate file)

5. Manually PE-load that image into THIS process's own memory (subtee's
   PELoader, ported into Program.cs):
   ├─ VirtualAlloc() the image size, PAGE_EXECUTE_READWRITE
   ├─ Copy each section from the decompressed image into the new allocation
   ├─ Walk the base-relocation table and patch absolute addresses for the
   │  new load address (delta = actual base − original ImageBase)
   ├─ Walk the import table and manually LoadLibrary()/GetProcAddress()
   │  resolve every imported function, patching the IAT by hand
   └─ CreateThread() at the mapped image's AddressOfEntryPoint, passing
      fakeArgs = { "privilege::debug" } as the command fed to the now-
      running Mimikatz's own command-line parser; WaitForSingleObject(30000)

6. [Inside the newly-running, in-memory Mimikatz thread — not SafetyKatz's own
   code, and not visible in this repo's source since it ships pre-compiled]:
   opens debug.bin, runs sekurlsa::minidump against it (per the README's
   Modifications note and sample output), extracts and prints credential
   material (sekurlsa::logonpasswords / sekurlsa::ekeys per the tool's stated
   purpose), then deletes debug.bin — all before SafetyKatz.exe's 30-second
   WaitForSingleObject() times out and the process exits.
```

**The dump and the parse happen in the same process, in the same execution, seconds apart — "offline" in mechanism (`sekurlsa::minidump` against a file) but not in operational tempo.** This is the key distinction from `../SharpDump/`, whose job ends at producing a portable `.bin` for a *separately-run* Mimikatz to parse later, possibly on a different machine. SafetyKatz collapses dump-then-parse into one binary, one launch, one host — the `debug.bin` file exists on disk only for the few seconds between step 3's write and step 6's delete, unless the run is interrupted mid-sequence (killed, crashed, or the 30-second thread-join times out) — see `04 - Target Evidence.md` for what that narrow window means for live-response recovery odds.

**PPL/`RunAsPPL` gates this identically to SharpDump and ProcDump.** SafetyKatz's step 3 is the exact same `OpenProcess()`-then-`MiniDumpWriteDump()` sequence — if LSASS is running as Protected Process Light, the handle acquisition fails outright regardless of the caller's privilege level. This mechanic, the registry key, and the WinInit Event 12 evidence are already documented in full in `../../ProcDump/01 - Overview.md` and `../../ProcDump/05 - Detection and Hunting.md` — apply directly, not re-derived here.

### Convergence and divergence — SafetyKatz vs. SharpDump vs. ProcDump vs. comsvcs.dll

| | SafetyKatz | SharpDump | ProcDump `-ma` | `comsvcs.dll` MiniDump |
|---|---|---|---|---|
| Underlying dump API | `dbghelp.dll!MiniDumpWriteDump()` | Same | Same | Same |
| Dump type | Always `MiniDumpWithFullMemory` (hardcoded `2`) | Same (hardcoded `2`) | Operator-selectable | Fixed at `full` |
| Output path/filename | Hardcoded, **no PID**: `%SystemRoot%\Temp\debug.bin` | Hardcoded, **PID-qualified**: `%SystemRoot%\Temp\debug<PID>.out`/`.bin` | Fully operator-controlled | Fully operator-controlled |
| Post-dump compression | None — raw dump written directly | Automatic GZip | None | None |
| Credential parsing | **Built in** — modified, pre-compiled Mimikatz PE-loaded and run in-process against the dump | **None** — operator runs Mimikatz/pypykatz separately, later, possibly elsewhere | None | None |
| Dump file lifetime on disk | Seconds — deleted by the embedded Mimikatz thread after parsing | Persists — `.bin` is the deliverable, meant to be exfiltrated | Persists until operator deletes it | Persists until operator deletes it |
| PID targeting | **None** — compiled tool always resolves `lsass` by name, no CLI arg reaches `Minidump()` | Yes — single positional PID argument | Yes | Yes |
| Access requested against target | `PROCESS_ALL_ACCESS` (via `Process.Handle`) | Same | Narrower, DbgHelp-driven | Narrower, DbgHelp-driven |
| Blocked by `RunAsPPL`? | Yes | Yes | Yes | Yes |
| Delivery to target | Must be compiled/staged (no binaries released) | Same | Real, signed binary delivered | None — DLL already present |

The PPL gate, remediation, and the shared `MiniDumpWriteDump()` mechanic are documented in full in `../../ProcDump/01 - Overview.md` and `../../ProcDump/05 - Detection and Hunting.md`; the `PROCESS_ALL_ACCESS`-via-`Process.Handle` pattern is documented in full in `../SharpDump/01 - Overview.md` and `../SharpDump/03 - Source Evidence.md` — this page's job is what's specific to SafetyKatz's own single-process, dump-then-parse design.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Purely **local** — no network client of its own. Remote use rides entirely on whatever lateral-movement/remote-execution tool delivers it (`../../PsExec/`, `../../Impacket/wmiexec/`, `../../LOLBins/wmic/`), same positioning as `../SharpDump/` |
| Target API | `DbgHelp!MiniDumpWriteDump()` (`dbghelp.dll`), identical to `../SharpDump/` and `../../ProcDump/` |
| Process access | .NET `Process.Handle` → `OpenProcess()` requesting `PROCESS_ALL_ACCESS`, identical pattern to `../SharpDump/` |
| Access control gate | Windows Protected Process Light (PPL) via `RunAsPPL` — same gate documented in `../../ProcDump/01 - Overview.md` |
| In-memory PE loading | A hand-rolled reflective PE loader (ported from subtee's public gist) — manual `VirtualAlloc`, section copy, base relocation, and IAT-patching of an **unmanaged x64 PE image**, not .NET `Assembly.Load()`/reflection (contrast `../SharpDump/`'s reflective-*.NET-assembly* loading, which uses the CLR's own loader) |
| Offline credential parsing | An embedded, modified, pre-compiled Mimikatz `sekurlsa` engine — same underlying LSASS-memory-structure parsing mechanics as `../../Mimikatz/sekurlsa (Credential Dumping)/`, cross-linked rather than re-derived here, but running against the just-written `debug.bin` inside the same process rather than as a separate, later invocation |
| Compression | None at the SafetyKatz layer — the raw dump is opened directly by the embedded Mimikatz; contrast `../SharpDump/`'s automatic `GZipStream` step |

## Command-Line Switches — Quick Reference

Verified directly against `Program.cs`'s `Main()` method. **SafetyKatz's compiled, public-source binary takes no meaningful command-line arguments at all** — this is a genuine, source-verified fact worth stating plainly, since operators and blog posts sometimes describe it (by analogy with SharpDump) as accepting a PID:

| Invocation | What happens |
|---|---|
| `SafetyKatz.exe` (with or without arguments) | `Main()` never reads `args` for targeting purposes — any arguments passed on the command line are silently ignored. The tool always resolves `lsass.exe` by name (`Process.GetProcessesByName("lsass")[0]`), dumps it, and runs the embedded Mimikatz against the dump. There is no flag to target a different process, change the output path, or suppress the automatic delete |
| *(internal, not exposed)* `Minidump(int pid)` | The underlying function signature accepts an optional PID and would target an arbitrary process if called with one — but `Main()`'s single call site (`Minidump();`) never supplies an argument, so this capability is unreachable from the compiled command line without editing the source |
| *(internal, not exposed)* `"privilege::debug"` | The one "argument" that does get passed anywhere is hardcoded inside `Main()` itself (`fakeArgs`), fed to the embedded Mimikatz's own command parser as its startup command — not something the SafetyKatz operator supplies or can change without recompiling |

**Practical consequence:** unlike `../SharpDump/`, `../../Rubeus/`, or `../../Seatbelt/`, there is no man-page-style switches table to give here beyond "it takes none." Any operator wanting PID-targeting, a different output path, or a different embedded Mimikatz command set must edit `Program.cs`/`Constants.cs` and recompile — the same "recompile from source" evasion/customization path `../SharpDump/02 - Hands-On Use Cases.md` documents as its own use case, but here it's the *only* way to get any behavior other than the single default LSASS-dump-and-parse run.

## Quick Use-Case List

- Baseline default run — dump LSASS and run the embedded, modified Mimikatz against it in a single execution, printing credentials straight to the console/C2 channel
- In-memory execution via a C2 loader's "execute .NET assembly" capability (Cobalt Strike `execute-assembly`, Covenant, Sliver `execute-assembly`) — SafetyKatz is a managed .NET 3.5 assembly itself even though it PE-loads an *unmanaged* Mimikatz inside it, so the outer tool is reflectively loadable the same way `../SharpDump/`/`../SharpUp/`/`../../Rubeus/`/`../../Seatbelt/` are
- In-memory execution via PowerShell reflection (`[Reflection.Assembly]::Load()` + `[SafetyKatz.Program]::Main()`), avoiding a dropped `SafetyKatz.exe` on disk entirely
- One-shot credential harvest on a foothold where the operator wants a single command to both dump and parse, rather than staging a `.bin` for later/offline analysis the way `../SharpDump/` requires
- A quieter alternative to running the full `mimikatz.exe` binary directly, since the credential-parsing engine here is a modified, non-default-named, differently-hashed build (defeats static signatures tuned to the stock `mimikatz.exe`/`.dll`)
- Renaming the compiled `SafetyKatz.exe` binary on disk to defeat filename-based detection — PE metadata (`AssemblyTitle`/`AssemblyProduct`, both `"SafetyKatz"` in unmodified source) survives the rename, same precedent as `../SharpDump/` and `../../PsExec/`
- Recompiling from modified source to add PID-targeting, change the fixed `debug.bin` output path, swap in a different/updated embedded Mimikatz build, or alter PE metadata — the only way to get any behavior beyond the single default LSASS run, since `Main()` ignores `args` entirely in the public source
- Fleet-wide deployment by chaining onto an already-built remote-execution tool (`../../PsExec/`, `../../Impacket/wmiexec/`, `../../LOLBins/wmic/`), the same convergence story `../../ProcDump/` and `../SharpDump/` already document for their own techniques
- Recovering/analyzing a leftover `debug.bin` if a SafetyKatz run was interrupted before the embedded Mimikatz thread's cleanup step — feeding it into a standalone Mimikatz (`../../Mimikatz/sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md`) or `pypykatz` for offline parsing, effectively converting an aborted SafetyKatz run into a SharpDump-style two-step workflow after the fact
- Comparative/purple-team use — running SafetyKatz alongside `../SharpDump/`, `../../ProcDump/`, and `../../Mimikatz/sekurlsa (Credential Dumping)/` on the same lab host to validate that a hunt tuned to the shared `dbghelp.dll`/`OpenProcess()` signal (per `../../ProcDump/05 - Detection and Hunting.md`'s Hunting Priority table) actually catches all four
- Sequential re-runs across several already-compromised hosts in the same engagement window, exploiting the tool's fully self-contained, single-command design (no separate exfil/parse step to schedule per host, unlike the SharpDump-to-Mimikatz chain)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are ever released — every deployment is a custom Visual Studio (.NET 3.5) build, run standalone or reflectively loaded (`execute-assembly`, `[Assembly]::Load()`) |
| Elevation / administrative rights | **Required and self-enforced, unconditionally.** `Main()` checks `IsHighIntegrity()` before anything else and exits immediately if it fails — unlike `../SharpDump/`, whose gate only fires for a target literally named `lsass`, SafetyKatz's gate always fires because it always targets `lsass` |
| Target process not running as PPL (`RunAsPPL`) | Required — `OpenProcess()`/`MiniDumpWriteDump()` fails outright otherwise, identical gate to `../SharpDump/`/`../../ProcDump/`/`comsvcs.dll` (see `../../ProcDump/01 - Overview.md`) |
| 64-bit process | Self-checked (`IntPtr.Size == 8`) — the embedded Mimikatz PE is a fixed x64 build; running SafetyKatz as a 32-bit process fails this check and exits before any dump is attempted |
| `%SystemRoot%\Temp\` must exist | Checked once at startup — a near-universal default on real Windows installs, but a real, source-verified precondition, same as `../SharpDump/` |
| No PID/target customization available | Operators needing to target a non-LSASS process must use `../SharpDump/` instead, or recompile SafetyKatz from modified source — the public binary has no such flag |
| Remote execution vector, if targeting another host | Required — SafetyKatz has no network client of its own, same as `../SharpDump/`/`../../ProcDump/`/`comsvcs.dll` |
