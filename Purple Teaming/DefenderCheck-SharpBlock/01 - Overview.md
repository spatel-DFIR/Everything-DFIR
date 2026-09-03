# DefenderCheck-SharpBlock: Overview

🔴 **Critical Detection Principle:** Both tools operate entirely within a single process — DefenderCheck enumerates security products through WMI/registry without touching external binaries, while SharpBlock patches AMSI interfaces in-memory. Neither creates child processes, registry keys, or detectable file artifacts by default, making process-level memory forensics (AMSI stubbing patterns, patch signatures) the primary hunt vector.

## History

**DefenderCheck** — utility written by Andrew Chiles (@XORed, SpecterOps) to programmatically enumerate Windows Defender and third-party antivirus/EDR product presence. Created ~2018 as a reconnaissance tool for offensive infrastructure planning. No formal versioning; distributed as standalone C# source (DefenderCheck.cs, ~500 lines). Not actively maintained but remains functional against current Windows versions.

**SharpBlock** — tool written by Nick Landers (@RastaMouse, Sentinel One) to disable AMSI (Antimalware Scan Interface) by runtime patching of amsi.dll's stubbed interfaces within running processes. Released c. 2019; GitHub repository `rasta-mouse/SharpBlock` is archived but remains the definitive reference. Primary mechanism: patches the AMSI_RESULT enum validation or the AmsiScanBuffer export entry point in-memory, preventing EDR/AV runtime analysis of PowerShell/VBScript/CLR-hosted payloads.

Both are single-purpose C# utilities designed to run as standalone console applications with no installation step, distributed as either source (.cs) or pre-compiled .NET assemblies (.exe).

## How It Works

### DefenderCheck Mechanics

```
DefenderCheck.exe (runs on target)
  ↓
Query WMI (Win32_Product class, root\cimv2 namespace)
  ↓
  • Scans installed package GUIDs against known AV/EDR vendor strings
  • Matches display names against hardcoded product list (~50+ entries)
  • Returns installed + running status per product

Query registry (HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\)
  ↓
  • Supplement WMI check with legacy registry enumeration
  • Some vendors only register via installer keys, not WMI

Query file-system (common vendor install paths)
  ↓
  • Check C:\Program Files, C:\Program Files (x86) for executable paths
  • Validate running services against known AV/EDR service names (WmiPrvSE, MsMpEng, etc.)
```

DefenderCheck's output is human-readable console text; no artifact file written. Reconnaissance only — does not interact with running security products.

### SharpBlock Mechanics

```
SharpBlock.exe (runs inside target process or injected)
  ↓
Locate AMSI DLL in current process memory (amsi.dll loaded by .NET CLR)
  ↓
Patch AMSI_RESULT enum validation OR AmsiScanBuffer export
  ↓
  • AMSI_RESULT bypass: replace enum values with "AMSI_RESULT_CLEAN" (0x0)
  • AmsiScanBuffer patch: replace function prologue with `ret` (0xC3) or JMP to immediate-return
  • In-memory only; no disk write or new process
  ↓
Calling process's AMSI checks now return "clean" / bypass scanner entirely
```

SharpBlock typically runs as a child of or within the same process as the payload-execution context (e.g., injected into PowerShell, running inside a Cobalt Strike/Sliver beacon's CLR hosting). No persistence mechanism — effects revert on process termination.

## Techniques & Protocols Used

- **WMI (Windows Management Instrumentation)** — DefenderCheck queries Win32_Product class via COM interfaces (RPC to WmiPrvSE.exe). No authentication bypass needed; runs as-is.
- **Registry** — HKLM queries for Uninstall hives; requires read-only access (default on Windows).
- **Process Memory Patching** — SharpBlock uses .NET reflection to locate amsi.dll export tables and inline x86/x64 assembly patching. No external API calls; entirely in-process.
- **AMSI (Antimalware Scan Interface)** — Windows API contract (UE-V, AmsiInitializeAsync, AmsiScanBuffer, etc.); SharpBlock patches the runtime stub before calls reach the actual EDR agent.

## Command-Line Switches — Quick Reference

### DefenderCheck

| Flag | Purpose | Notes |
|------|---------|-------|
| (no args) | Run full scan | Default mode; outputs all detected products + status |
| `/verbose` | Expanded output | Not universally present in all variants; custom compiles may add |
| (custom compiles may vary) | Source is widely modified | No official switch standard; each variant may differ |

**Note:** DefenderCheck has no official versioning or maintained switch documentation. The source-code repository contains the authoritative command set. Most public compiles accept no flags at all and run in "full scan" mode by default.

### SharpBlock

| Flag | Purpose | Example |
|------|---------|---------|
| (no args) | Patch AMSI in current process | Direct execution: `SharpBlock.exe` patches the running console/injected-host process |
| `--log` (variant-dependent) | Output patch details | Some custom compiles log patch offsets/results; not standard |

**Note:** SharpBlock's primary distribution is source-code-only. Pre-compiled variants exist (community/team-specific compiles) with inconsistent switch support. Standard behavior: run with no arguments to patch AMSI in the calling process's memory.

## Quick Use-Case List

### DefenderCheck
1. Reconnaissance—enumerate installed security products during initial target assessment
2. Post-exploitation situational awareness—check EDR/AV posture after gaining code execution
3. Infrastructure hardening validation—verify deployed security tooling across fleet
4. Adversary-emulation exercises—baseline security-product detection as part of red-team assessment
5. Blue-team asset inventory—programmatically enumerate security software across domain

### SharpBlock
1. Bypass AMSI to run unencoded PowerShell payloads inside a victim process
2. Disable AMSI before executing C# malware (GhostPack tools, custom sharpies) via beacon CLR host
3. Evade script-based payload analysis in post-exploitation workflows (VBScript, JScript execution)
4. Reduce detection noise during emulation exercises by circumventing log-generating AMSI queries
5. Load and execute community offensive tooling (Empire agents, custom shellcode) without triggering scanner events

## Prerequisites

### DefenderCheck
- **Code execution** on target (local admin or standard user sufficient; WMI queries run under caller's context).
- **WMI access** — typically available to any authenticated user; requires RPC communication to WmiPrvSE.exe.
- **.NET Framework** or .NET Core runtime (if running compiled .exe; source requires compilation).
- **Read access to registry** (HKLM\Software\...\Uninstall); standard by default on any Windows system.

### SharpBlock
- **Code execution in the target process** where AMSI bypass is needed (e.g., already inside a PowerShell session, beacon CLR host, etc.). Cannot patch AMSI in a *different* process without cross-process injection.
- **.NET Framework / CLR** (SharpBlock is a .NET assembly; requires runtime to execute).
- **Windows 10+** or Windows Server 2016+ (AMSI availability; older OS versions not vulnerable to this technique).
- **amsi.dll loaded** in the process's memory space (automatic for PowerShell, VBScript hosts, CLR-based applications).

