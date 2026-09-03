# SafetyKatz — Hands-On Use Cases

Every command and behavior below is verified against [`GhostPack/SafetyKatz`](https://github.com/GhostPack/SafetyKatz)'s `README.md` and `Program.cs`/`Constants.cs` source — none are inferred from memory. Because the compiled tool takes no command-line arguments (per `01`), most variation here is in *how* the binary/assembly is launched, not in flags passed to it.

## Contents
- [Baseline Default Run — Dump and Parse LSASS in One Command](#baseline-default-run--dump-and-parse-lsass-in-one-command)
- [In-Memory Execution via Cobalt Strike execute-assembly](#in-memory-execution-via-cobalt-strike-execute-assembly)
- [In-Memory Execution via PowerShell Reflection](#in-memory-execution-via-powershell-reflection)
- [Quiet Alternative to a Stock mimikatz.exe Drop](#quiet-alternative-to-a-stock-mimikatzexe-drop)
- [Renaming the Binary to Defeat Filename Matching](#renaming-the-binary-to-defeat-filename-matching)
- [Recompiling From Source to Add PID Targeting or Change Fixed Behavior](#recompiling-from-source-to-add-pid-targeting-or-change-fixed-behavior)
- [Fleet-Wide Deployment via an Existing Remote-Execution Tool](#fleet-wide-deployment-via-an-existing-remote-execution-tool)
- [Recovering an Interrupted Run — Chaining Into Standalone Mimikatz or pypykatz](#recovering-an-interrupted-run--chaining-into-standalone-mimikatz-or-pypykatz)
- [Comparative Purple-Team Validation Run](#comparative-purple-team-validation-run)
- [Sequential Multi-Host Deployment](#sequential-multi-host-deployment)

---

## Baseline Default Run — Dump and Parse LSASS in One Command

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```cmd
C:\Temp>SafetyKatz.exe
```

No arguments accepted or needed — SafetyKatz resolves `lsass.exe` itself, checks the caller is high-integrity/Administrator (unconditional, per `01`), writes a full-memory dump to `C:\Windows\Temp\debug.bin`, then PE-loads the embedded modified Mimikatz build directly into its own process memory and runs it against that file. Console output on success (from the README's own example):

```
[*] Dumping lsass (808) to C:\WINDOWS\Temp\debug.bin
[+] Dump successful!

[*] Executing loaded Mimikatz PE

  .#####.   mimikatz 2.1.1 (x64) built on Jul  7 2018 03:36:26 - lil!
  .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
  ## / \ ##  / *** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
  ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
  '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   *** /

mimikatz # Opening : 'C:\Windows\Temp\debug.bin' file for minidump...

Authentication Id : 0 ; 28935082 (00000000:01b983aa)
Session           : Interactive from 0
User Name         : blahuser
Domain            : WINDOWS10
...(snip)...

mimikatz # deleting C:\Windows\Temp\debug.bin
```

One command, one process, one execution — the operator never has to transfer a dump file anywhere or invoke a second tool. This is the single defining operational difference from `../SharpDump/`, whose equivalent baseline run only produces the compressed dump and requires a *separate* later step (`../SharpDump/02 - Hands-On Use Cases.md`'s chained-extraction use cases) to actually see any credentials.

## In-Memory Execution via Cobalt Strike execute-assembly

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading), [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```
beacon> execute-assembly C:\Tools\SafetyKatz.exe
```

Loads and runs the compiled SafetyKatz **.NET assembly** inside a sacrificial/forked beacon process's memory — no `SafetyKatz.exe` itself ever lands on the target's disk. Note the two distinct loading layers in play here: the **outer** SafetyKatz assembly is loaded reflectively by the C2 framework's own .NET-assembly loader (the same mechanism used for `../SharpDump/`, `../SharpUp/`, `../../Rubeus/`, `../../Seatbelt/`), while the **inner** embedded Mimikatz PE is then loaded a second time, by SafetyKatz's own hand-rolled unmanaged-PE loader, entirely independent of whatever loaded SafetyKatz itself. The `debug.bin` dump file is still written to and deleted from `%SystemRoot%\Temp\` exactly as in a standalone run, since that behavior lives inside the assembly's own code.

## In-Memory Execution via PowerShell Reflection

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell)

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Tools\SafetyKatz.exe")
[Reflection.Assembly]::Load($bytes)
[SafetyKatz.Program]::Main(@())
```

Standard reflective-load pattern, matching the assembly's actual namespace/class (`namespace SafetyKatz { class Program { static void Main(string[] args) ... } }`, verified against source). Passing any array other than `@()` makes no difference — `Main()` never reads its `args` parameter for anything (per `01`'s Switches table). PowerShell v5's usual protections apply to the loader script itself (AMSI, Script Block Logging Event 4104, Module Logging 4103 — see `../../LOLBins/powershell/` for the underlying logging-subsystem mechanics) but not to the loaded assembly's own execution, nor to the *second* PE-load of the embedded Mimikatz binary happening inside it — that inner load is unmanaged code mapped by hand, entirely outside .NET's own assembly-loading instrumentation.

## Quiet Alternative to a Stock mimikatz.exe Drop

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```cmd
C:\Temp>SafetyKatz.exe
```

Operationally identical to the baseline run above — called out separately here because the *reason* an operator reaches for SafetyKatz over running `mimikatz.exe` directly is specifically evasion-driven: the embedded Mimikatz build is a modified, stripped-down, non-default-named compile (per `01`'s History — "modified to strip some functionality for size reasons") that never exists as a standalone file on disk at all, defeating any static signature tuned to the stock `mimikatz.exe`/`.dll` file hash, filename, or PE metadata. See `../../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md`'s Hunting Priority table for why relying on that static signature alone (its own rank-6, weakest signal) is a poor primary control regardless of which delivery mechanism is used.

## Renaming the Binary to Defeat Filename Matching

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities)

```cmd
copy SafetyKatz.exe svchelper.exe
svchelper.exe
```

The compiled outer binary's filename is trivially operator-controlled and defeats any hunt matching on `SafetyKatz.exe` specifically. It changes nothing about internal behavior — the dump still lands at the same hardcoded `debug.bin` path regardless of what the launching binary is called, and unmodified PE `AssemblyTitle`/`AssemblyProduct` VERSIONINFO fields (both `"SafetyKatz"` in unmodified source) survive the rename untouched, the same pattern already established for `../SharpDump/`, `../../PsExec/`, and `../../ProcDump/`.

## Recompiling From Source to Add PID Targeting or Change Fixed Behavior

No dedicated MITRE mapping — a build-time customization step, not an execution technique in its own right (the same treatment `../SharpDump/02 - Hands-On Use Cases.md` gives its own "Recompiling From Source" use case).

Because the public `Main()` never passes a PID to `Minidump()` and never reads `args` (per `01`), an operator wanting to target a process other than LSASS, change the fixed `debug.bin` output path, suppress the automatic delete, or swap in an updated/different embedded Mimikatz build has exactly one option: edit `Program.cs`/`Constants.cs` directly and rebuild with Visual Studio 2015 (.NET 3.5 target). Since no official binaries are ever released (per `01`), every real-world SafetyKatz sample is already a custom compile — this is simply a further step on the same path, and it's the only way to defeat the fixed `debug.bin` filename signal documented in `04 - Target Evidence.md`.

## Fleet-Wide Deployment via an Existing Remote-Execution Tool

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares)

SafetyKatz has no network client of its own — chaining onto an already-built remote-execution tool is the realistic way it gets used against more than one host, the same convergence story `../../ProcDump/02 - Hands-On Use Cases.md` and `../SharpDump/02 - Hands-On Use Cases.md` document for their own techniques. Via Sysinternals PsExec (`../../PsExec/`):

```cmd
psexec.exe \\target -c SafetyKatz.exe
```

Or via WMI (`../../Impacket/wmiexec/`, `../../LOLBins/wmic/`), once the binary is already staged:

```cmd
wmic /node:target process call create "C:\Windows\Temp\SafetyKatz.exe"
```

Because SafetyKatz prints credential material to its own console rather than writing a portable file the way `../SharpDump/` does, remote/fleet-wide use over `psexec`/`wmic` depends on the delivery vector also capturing that console output (`psexec`'s interactive/redirected output does; a fire-and-forget `wmic process call create` does not, since it has no output channel back to the operator) — a real operational constraint worth knowing when comparing this tool to `../SharpDump/`'s file-based, output-channel-agnostic design.

## Recovering an Interrupted Run — Chaining Into Standalone Mimikatz or pypykatz

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```
mimikatz # sekurlsa::minidump debug.bin
mimikatz # sekurlsa::logonPasswords full
```

```bash
pypykatz lsa minidump debug.bin
```

If a SafetyKatz run is killed, crashes, or is otherwise interrupted between the dump-write (step 3) and the embedded Mimikatz's own delete step (step 6, per `01`'s How It Works), `debug.bin` survives on disk exactly like a `../SharpDump/`-produced dump — usable with a standalone Mimikatz's `sekurlsa::minidump` or `pypykatz` exactly as documented in `../SharpDump/02 - Hands-On Use Cases.md`'s chained-extraction use cases (not re-derived here). This effectively converts a botched single-process SafetyKatz run into a two-step SharpDump-style workflow after the fact — a real operational fallback, and a real forensic opportunity on the defender side (see `04 - Target Evidence.md`'s file-recovery discussion).

## Comparative Purple-Team Validation Run

No dedicated MITRE mapping — a detection-engineering validation exercise, not an attacker technique in its own right.

```cmd
:: Run all four in sequence on the same lab host, then confirm the shared
:: dbghelp.dll / OpenProcess() hunt (../../ProcDump/05 - Detection and Hunting.md's
:: Hunting Priority rank 1-2 signals) fires for every one
C:\Temp>SafetyKatz.exe
C:\Temp>SharpDump.exe
C:\Temp>procdump.exe -ma lsass.exe lsass_procdump.dmp
C:\Temp>rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 808 lsass_comsvcs.dmp full
```

A useful purple-team check precisely because SafetyKatz, `../SharpDump/`, ProcDump, and `comsvcs.dll` all converge on the identical `MiniDumpWriteDump()` API call and `PROCESS_ALL_ACCESS`-or-narrower `OpenProcess()` request (per `01`'s comparison table) — a detection tuned only to one tool's filename or output path will miss the other three, while a detection tuned to the shared API/access-mask signal (`../../ProcDump/05 - Detection and Hunting.md`) should catch all four.

## Sequential Multi-Host Deployment

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

```cmd
for %H in (host1 host2 host3) do psexec.exe \\%H -c SafetyKatz.exe
```

Because each run is fully self-contained (dump, parse, print, delete, all in one execution with no separate exfil/collection step to schedule), SafetyKatz is well suited to a simple sequential sweep across several already-compromised hosts in the same engagement window — each invocation leaves its own complete, short-lived artifact trail per `03`/`04`, with the operator collecting credential output directly from each `psexec` session rather than gathering dump files afterward the way a `../SharpDump/`-based sweep would require.
