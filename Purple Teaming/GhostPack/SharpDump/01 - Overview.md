# SharpDump — Overview

> 🔴 **Red Flag Principle:** SharpDump calls the identical `dbghelp.dll!MiniDumpWriteDump()` API that ProcDump (`-ma`) and `comsvcs.dll`'s `MiniDump` export use — see `../../ProcDump/01 - Overview.md` for that shared mechanic, cross-linked rather than re-derived here. What's genuinely SharpDump-specific, and the single strongest artifact this page has to offer, is that its output path is **hardcoded into the compiled binary with no flag to change it**: every run writes `%SystemRoot%\Temp\debug<PID>.out` (raw dump) then `%SystemRoot%\Temp\debug<PID>.bin` (a real gzip file wearing a `.bin` extension), and deletes the `.out`. Unlike ProcDump or `comsvcs.dll` — where the operator freely picks the output path — defeating this pattern requires recompiling SharpDump from modified source, not just passing a different argument. On top of that, SharpDump requests **`PROCESS_ALL_ACCESS`** against its target (a side effect of using .NET's generic `Process.Handle` property instead of a narrow, purpose-built `OpenProcess()` call) — a far louder access mask than Mimikatz's minimal `PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION` read-only ask against the same process.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Arguments — Quick Reference](#command-line-arguments--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/SharpDump`](https://github.com/GhostPack/SharpDump), its `README.md`, and its full commit history (6 commits total, fetched live via the GitHub API):

- **Primary author:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`) — the README credits him directly ("`@harmj0y` is the primary author of this port"), the same GhostPack author family as `../../Rubeus/` and `../../Seatbelt/`, both already built in this repo.
- **License:** BSD 3-Clause.
- **Lineage — SharpDump is an explicit C# port, not an original technique.** The README states plainly: "SharpDump is a C# port of [PowerSploit's Out-Minidump.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Out-Minidump.ps1) functionality." PowerSploit itself is partially covered in this repo already (`../../PowerSploit/PowerView/`, `../../PowerSploit/PowerUp/`), though that build's scope was limited to those two modules — `Exfiltration/Out-Minidump.ps1`, SharpDump's direct PowerShell ancestor, was not built as its own page. The porting motive matches the rest of the GhostPack family: move a PowerShell primitive into managed C# so it can be compiled, reflectively loaded, or run via `execute-assembly` without a PowerShell host process or its associated logging surface (AMSI, Script Block Logging) in the picture at all.
- **The repository is a single-purpose, single-file tool and has been essentially frozen since 2019.** The entire implementation lives in one file, `SharpDump/Program.cs` (~170 lines) — there is no `CHANGELOG.md`, no tagged releases, and the full commit history is six commits: an initial commit and README (2018-07-24), a `.gitignore` addition (2018-07-25/2018-08-20), and one substantive behavioral change merged **2019-02-07** (PR #3, "Check if admin privilege only if trying to dump lsass" — detailed below). Nothing has landed since. Treat this as a stable, no-longer-evolving primitive rather than an actively maintained tool with a changelog to track.
- **No compiled binaries are ever released** — the README states this in the same words used across the GhostPack family: "We are not planning on releasing binaries for SharpDump, so you will have to compile yourself." Every real-world SharpDump binary is therefore a custom operator compile; PE metadata (`AssemblyTitle`/`AssemblyProduct`, both `"SharpDump"` in the unmodified source's `AssemblyInfo.cs`) and the on-disk filename are operator-controlled, not a stable fingerprint the way a vendor-shipped tool's would be.
- **Build target:** .NET Framework 3.5, built against Visual Studio 2015 Community Edition per the README's Compile Instructions — the same target framework generation as Rubeus and Seatbelt.
- **The one behavioral change in the tool's history is itself forensically relevant.** The original 2018 release ran its administrator/high-integrity self-check unconditionally, regardless of what process was being targeted. PR #3 (community contribution, merged by the maintainer 2019-02-07) narrowed that check to fire **only** when the target process is literally named `lsass` — see How It Works, below, for what that means for non-LSASS use.

## How It Works

SharpDump's entire logic lives in `Program.cs`'s `Minidump()` function. Verified line-by-line against the live source:

```csharp
[DllImport("dbghelp.dll", EntryPoint = "MiniDumpWriteDump", CallingConvention = CallingConvention.StdCall,
    CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
static extern bool MiniDumpWriteDump(IntPtr hProcess, uint processId, SafeHandle hFile,
    uint dumpType, IntPtr expParam, IntPtr userStreamParam, IntPtr callbackParam);
```

```
Operator (SharpDump.exe, or a host process it's reflectively loaded into)
────────────────────────────────────────────────────────────────────────
1. Resolve target process
   ├─ No argument  → Process.GetProcessesByName("lsass")[0]   (first match, by name)
   └─ Numeric arg  → Process.GetProcessById(<pid>)             (explicit PID, any process)

2. IF target.ProcessName == "lsass":
       IsHighIntegrity() check — WindowsPrincipal(identity).IsInRole(Administrator)
       FAIL → print "[X] Not in high integrity, unable to MiniDump!" and exit
   ELSE (any other process name):
       No self-imposed check at all — proceeds straight to step 3 regardless
       of the caller's privilege level

3. targetProcessHandle = targetProcess.Handle
   → .NET's generic Process.Handle property, NOT a narrow purpose-built
     OpenProcess() call — requests NativeMethods.PROCESS_ALL_ACCESS
     (0x1F0FFF: STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFF), verified
     directly against .NET Framework's own reference source
     (Process.cs / NativeMethods.cs) — a maximal, all-rights access
     request, not the minimal read-only ask Mimikatz's sekurlsa module
     makes against the same process (PROCESS_VM_READ |
     PROCESS_QUERY_LIMITED_INFORMATION, 0x1010 — see
     ../../Mimikatz/sekurlsa (Credential Dumping)/01 - Overview.md)

4. Open C:\Windows\Temp\debug<PID>.out for write, call
   MiniDumpWriteDump(handle, pid, fileHandle, dumpType=2, ...)
   → dumpType is a hardcoded literal 2 == MiniDumpWithFullMemory —
     always a full dump, no smaller-type option exists in this tool
     at all (contrast ProcDump's -mm/-mt/-mp/-mc/-ma choice)

5. On success: GZipStream-compress C:\Windows\Temp\debug<PID>.out
   into C:\Windows\Temp\debug<PID>.bin (a real gzip file — valid
   0x1F 0x8B magic bytes — the README instructs the operator to
   manually rename it to .gz before decompressing), then
   File.Delete() the raw .out — only the .bin normally survives
   a completed run

6. [Default LSASS path only] Read HKLM\SOFTWARE\Microsoft\Windows NT\
   CurrentVersion\ProductName and the PROCESSOR_ARCHITECTURE env var,
   print both plus the reminder: 'Use "sekurlsa::minidump debug.out"
   "sekurlsa::logonPasswords full" on the same OS/arch' — a convenience
   hint so the operator picks a matching-build Mimikatz for offline
   parsing later
```

**The PID-only targeting model is the whole story for "arbitrary process" use.** SharpDump does no name-to-PID resolution of its own beyond the single hardcoded `"lsass"` lookup — to dump anything else, the operator must already know the numeric PID (`tasklist`, `Get-Process`, `wmic process where name='X'`) and pass it as SharpDump's one and only argument. There is no `/name:` equivalent.

**The elevation gate is cosmetic for anything that isn't literally named `lsass`.** Because `IsHighIntegrity()` is only invoked inside the `ProcessName == "lsass"` branch, targeting any other PID skips SharpDump's own self-check entirely — whether the dump actually succeeds then depends solely on whatever access Windows' own DACL/token model grants the caller against that specific process, not on anything SharpDump itself enforces. A non-elevated operator can run SharpDump against a PID they already have sufficient rights to (e.g., another process running as the same user) with zero internal gate in the way.

**No filename, path, or dump-type flag exists to change any of step 4/5's hardcoded conventions** — this is the direct forensic payoff of the red-flag callout above, and is developed fully in `05 - Detection and Hunting.md`.

### Convergence with ProcDump / comsvcs.dll — and where it diverges

| | SharpDump | ProcDump `-ma` | `comsvcs.dll` MiniDump |
|---|---|---|---|
| Underlying API | `dbghelp.dll!MiniDumpWriteDump()` | Same | Same |
| Dump type | Always `MiniDumpWithFullMemory` (hardcoded `2`) — no other option | Operator-selectable (`-mm`/`-ma`/`-mt`/`-mp`/`-mc`) | Fixed at `full` per its documented syntax |
| Output path/filename | **Hardcoded**, not operator-settable without recompiling: `%SystemRoot%\Temp\debug<PID>.out`/`.bin` | Fully operator-controlled | Fully operator-controlled |
| Post-dump compression | **Automatic** — GZip, built into the tool itself | None — raw `.dmp` only | None — raw `.dmp`/`.bin` only |
| Access requested against target | `PROCESS_ALL_ACCESS` (via `Process.Handle`) | Narrower, DbgHelp-driven request | Narrower, DbgHelp-driven request |
| Blocked by `RunAsPPL`? | Yes — identical `OpenProcess()`-then-`MiniDumpWriteDump()` sequence, same gate | Yes | Yes |
| Delivery to target | Must be compiled/staged (no binaries released) | Must be delivered (real, signed binary) | None — DLL already present |

The PPL gate, remediation, and shared-mechanic framing are already fully documented in `../../ProcDump/01 - Overview.md` and `../../ProcDump/05 - Detection and Hunting.md` — apply those directly rather than re-deriving them here; this page's job is what's different about SharpDump specifically.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Purely **local** — no network client of its own, identical positioning to ProcDump/`comsvcs.dll`. Remote use rides entirely on whatever lateral-movement/remote-execution tool delivers the command (`../../PsExec/`, `../../Impacket/wmiexec/`, `../../LOLBins/wmic/`) |
| Target API | `DbgHelp!MiniDumpWriteDump()` (`dbghelp.dll`) |
| Process access | .NET `Process.Handle` → `OpenProcess()` requesting `PROCESS_ALL_ACCESS` |
| Access control gate | Windows Protected Process Light (PPL) via `RunAsPPL` — same gate documented in depth in `../../ProcDump/01 - Overview.md` |
| Compression | .NET's built-in `System.IO.Compression.GZipStream` — no external dependency |
| Offline follow-on | The resulting `.bin` (rename to `.gz`) is parsed offline via Mimikatz `sekurlsa::minidump` or `pypykatz` — see `../../Mimikatz/sekurlsa (Credential Dumping)/` |

## Command-Line Arguments — Quick Reference

Verified directly against `Program.cs`'s `Main()` and the README's own usage examples. **SharpDump has no named switches at all** — the entire command surface is a single optional positional argument:

| Invocation | What happens |
|---|---|
| `SharpDump.exe` (no arguments) | Dumps whatever process is currently named `lsass` (first match via `Process.GetProcessesByName`) — the default, credential-dumping use case. Prints OS `ProductName` and `PROCESSOR_ARCHITECTURE` on success, plus a reminder to use `sekurlsa::minidump`/`sekurlsa::logonPasswords full` for offline parsing |
| `SharpDump.exe <PID>` | Dumps the process with the given numeric Process ID — the **only** way to target anything other than LSASS. The operator must resolve the PID themselves beforehand; SharpDump does no other name lookup |
| `SharpDump.exe <arg1> <arg2>` (2 or more arguments) | Rejected outright — prints `"Please use \"SharpDump.exe [pid]\" format"` and exits without dumping anything |
| A non-numeric single argument | Rejected — same usage message, since `int.TryParse` fails |

### Fixed, non-configurable behavior (no flag exists to change any of these)

| Behavior | Value | Notes |
|---|---|---|
| Dump type | `MiniDumpWithFullMemory` (`0x2`) | Always a full-memory dump — no Mini/Triage/MiniPlus choice the way ProcDump exposes |
| Raw dump path | `%SystemRoot%\Temp\debug<PID>.out` | Hardcoded `String.Format` pattern — cannot be changed without editing and recompiling the source |
| Compressed output path | `%SystemRoot%\Temp\debug<PID>.bin` | Real gzip content (valid `1F 8B` magic bytes) despite the `.bin` extension — README instructs manually renaming to `.gz` before decompression |
| Raw `.out` cleanup | Deleted automatically after successful compression | Only the `.bin` normally remains after a clean run |
| Elevation self-check | Enforced only when the target's `ProcessName == "lsass"` | Added by community PR #3, merged 2019-02-07; any other PID skips this internal check entirely |
| Precondition | `%SystemRoot%\Temp\` must already exist | Checked once at the very start of `Main()` — if missing, the tool prints an error and takes no action at all |

## Quick Use-Case List

- Baseline default-argument LSASS dump — the tool's primary designed purpose
- Targeting an arbitrary process by PID — SharpDump is a general-purpose process dumper, not an LSASS-only tool
- Dumping a non-LSASS process from a non-elevated context, exploiting the fact that the internal admin self-check only fires for a target literally named `lsass`
- Chained offline credential extraction: SharpDump dump → rename `.bin` to `.gz` → decompress → Mimikatz `sekurlsa::minidump`
- Chained offline credential extraction using `pypykatz` instead of Mimikatz — a cross-platform, Linux-side alternative for parsing the same dump
- In-memory execution via Cobalt Strike `execute-assembly` — no binary ever touches disk on the target beyond the output dump itself
- In-memory execution via PowerShell reflection (`[System.Reflection.Assembly]::Load()` + `[SharpDump.Program]::Main()`), Covenant, or similar C# loaders
- Fleet-wide deployment by chaining onto an already-built remote-execution tool (`../../PsExec/`, `../../Impacket/wmiexec/`, `../../LOLBins/wmic/`), the same convergence story `../../ProcDump/` already documents for its own two techniques
- Exfiltrating the compressed `.bin` off the target host via an already-built exfil tool (`../../Rclone/`)
- Renaming the compiled `SharpDump.exe` binary on disk to defeat filename-based detection (PE metadata survives — same precedent as `../../PsExec/` and `../../Rclone/`)
- Recompiling from modified source to change the tool's hardcoded behavior (output path/filename pattern, dump type constant, PE metadata) — the only way to actually defeat the fixed-output-path signal, since no flag does it
- Sequential multi-process dump sweep on a single compromised host — running SharpDump repeatedly against several resolved PIDs to build a small evidentiary set of dumps before a single exfil pass

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are released — every deployment is a custom Visual Studio (.NET 3.5) build, run as a standalone EXE or reflectively loaded (Cobalt Strike `execute-assembly`, PowerShell `[Assembly]::Load`) |
| Elevation / administrative rights | **Required, self-enforced** only when the target is the process named `lsass` (the tool checks and exits otherwise). **Not self-enforced** for any other PID — success then depends entirely on the OS's own access-control decision for that specific process and the caller's actual token |
| Target process not running as PPL (`RunAsPPL`) | Required when LSASS is the target — `OpenProcess()`/`MiniDumpWriteDump()` fails outright otherwise, identical gate to ProcDump/`comsvcs.dll` (see `../../ProcDump/01 - Overview.md`) |
| `%SystemRoot%\Temp\` must exist | Checked once at startup — a near-universal default on real Windows installs, but a real, source-verified precondition |
| PID known in advance for non-LSASS targets | SharpDump does not resolve any name other than `lsass` itself — `tasklist`/`Get-Process`/`wmic` first |
| Remote execution vector, if targeting another host | Required — SharpDump has no network client of its own, same as ProcDump/`comsvcs.dll` |
