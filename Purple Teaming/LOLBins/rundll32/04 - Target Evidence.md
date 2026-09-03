# LOLBins — rundll32.exe — Target Evidence

What an operator running `rundll32 <malicious.dll> <function>` leaves on the victim host: process-execution records, network events (if remote loading), DLL-load artifacts, and the evidence signatures needed to detect or investigate the intrusion.

## Contents
- [Process Creation — Sysmon and Security Events](#process-creation--sysmon-and-security-events)
- [DLL Loading (Sysmon Image Loaded)](#dll-loading-sysmon-image-loaded)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Network-Layer Artifacts](#network-layer-artifacts)
- [Child Process Spawning (Export-Dependent)](#child-process-spawning-export-dependent)
- [Timeline Building](#timeline-building)

---

## Process Creation — Sysmon and Security Events

`rundll32.exe` spawned from cmd.exe, PowerShell, or a macro generates process-creation events:

| Event Details | Value | Notes |
|---|---|---|
| **Image** | `C:\Windows\System32\rundll32.exe` or `C:\Windows\SysWOW64\rundll32.exe` | The two legitimate OS install paths. |
| **CommandLine** | `rundll32.exe C:\Users\Public\malicious.dll ExportedFunction` or `rundll32.exe http://...malicious.dll Run` | The DLL path/URL and export function name are **strongest detection signals**. |
| **ParentImage** | `cmd.exe`, `powershell.exe`, macro parent, or C2 framework | Depends on delivery mechanism. |
| **OriginalFileName** | `RUNDLL32.EXE` | From the binary's version resource; survives renaming. |

## DLL Loading (Sysmon Image Loaded)

When `rundll32.exe` loads a DLL, Sysmon Event 7 (Image Loaded) records the event:

| Event Details | Value | Notes |
|---|---|---|
| **Image** | `rundll32.exe` | The loading process. |
| **ImageLoaded** | `C:\Users\Public\malicious.dll` or `\\attacker.com\share\payload.dll` | The DLL being loaded — **critical forensic artifact**. |
| **Signed** | `false` (for attacker-authored DLL) | Attacker DLLs are typically unsigned; legitimate system DLLs are signed by Microsoft. |
| **OriginalFileName** (if available) | May be absent (unsigned) or contain attacker-supplied metadata | Worth checking. |

**Abnormal DLL load contexts:** rundll32 loading DLLs from `%TEMP%`, `%USERPROFILE%\Downloads\`, `\\attacker_share\`, or unusual paths is a high-confidence signal. Normal rundll32 operation loads system DLLs from `System32` or known application directories.

## Filesystem Artifacts

| Artifact | Location | Notes |
|---|---|---|
| **Malicious DLL** | Varies (often `%TEMP%`, `%USERPROFILE%`, attacker's staging location) | The actual `.dll` file is recoverable. Can be reverse-engineered to determine payload logic. |
| **DLL import/export table** | Inside the DLL | Forensic analysis tools can extract the DLL's list of exported functions — the function name(s) specified on the rundll32 command line may be cross-referenced here. |
| **PDB debug file** | If present in same directory as DLL | May disclose the source-code paths, function names, and internal structure of the malware. |
| **Prefetch entry** | `C:\Windows\Prefetch\RUNDLL32.EXE-*.pf` | May record the DLL's path in its prefetch data (if Prefetch is enabled on the host, which is default). |

## Network-Layer Artifacts

For remote DLL loading (support varies by Windows version):

| Artifact | Source | Notes |
|---|---|---|
| **HTTP/HTTPS outbound request** | Proxy logs, firewall, Zeek, packet capture | A request for `payload.dll` or similar with a `User-Agent` from rundll32 (typically `Mozilla/4.0` or minimal). The destination URL is **forensically invaluable**. |
| **DNS query** | DNS logs | A DNS query for the attacker's domain occurs just before the HTTP request. |
| **TLS handshake** | Packet capture, proxy logs | If HTTPS, an SSL/TLS session to the destination on port 443. |

**Local/UNC loading** produces no network events.

## Child Process Spawning (Export-Dependent)

Some DLL exports spawn child processes; others do not. Depends entirely on the export's code:

| Scenario | Parent | Child | Notes |
|---|---|---|---|
| **Malicious DLL with spawn logic** | `rundll32.exe` | `cmd.exe`, `powershell.exe`, etc. | If the DLL's export calls `CreateProcess()` or `WScript.Shell.Run()`, a child process appears with rundll32 as parent. |
| **DLL with no spawning** | `rundll32.exe` | None | Code execution happens entirely in-process; no child process is spawned. |
| **Reflective DLL injection (Meterpreter)** | `rundll32.exe` | Variable (agent-dependent) | Some injected agents spawn a secondary process; others inject into an existing process. Depends on the payload. |

## Timeline Building

A complete rundll32 attack timeline:

**1. Initial Access** (not rundll32-specific)
- Macro/phishing/script delivery

**2. DLL Pre-Staging** (if local/UNC loading)
- File creation event for the malicious DLL (Sysmon 11, or filesystem journal)
- Optional: UNC connection to attacker's share (Sysmon 3)

**3. Rundll32 Invocation**
- **Sysmon 1 / Security 4688:** `rundll32.exe <DLL> <function>` command-line event (timestamp T0)
- **DNS query:** Domain lookup (if remote loading; T0-1 second)
- **Sysmon 3 / Security 5156:** Network connection (if remote loading; T0+1-2 seconds)

**4. DLL Load & Execution**
- **Sysmon 7 (Image Loaded):** Malicious DLL loaded into rundll32 process (T0+1-5 seconds)
- **DLL code executes** in-process (no parent-child event, no Sysmon 1)

**5. Secondary Payload Execution** (payload-dependent)
- **Sysmon 1 (child process):** If the DLL spawns a child (rare; most modern payloads inject instead)
- **Secondary network connections:** C2 agent checkin, stager downloads

**6. C2 Foothold** (if applicable)
- Persistence mechanisms, credential theft, lateral movement
