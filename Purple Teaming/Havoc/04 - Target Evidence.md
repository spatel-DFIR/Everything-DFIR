# Havoc C2 — Target Evidence

Artifacts left on **target/victim machines** running the Havoc Demon agent. These are the primary DFIR recovery artifacts, as opposed to operator-side artifacts.

---

## Filesystem Evidence

### Demon Binary (if not staged)

**Location:** Depends on delivery method. Common locations:
- Downloads folder: `C:\Users\<user>\Downloads\demon-payload.exe`
- Temp folder: `C:\Users\<user>\AppData\Local\Temp\demon.exe` (if executed from temp)
- Arbitrary user-selected location: depends on attacker's delivery vector

**Artifact characteristics:**
- **Size:** 5-20 MB (depending on architecture x64/x86, included libraries)
- **Signature:** PE (x64/x86 executable), Go runtime binary, unsigned by default (unless `--spoof-metadata` applied)
- **Strings:** Embedded C2 configuration:
  - Team Server IP address and port (plaintext in binary, e.g., "192.168.1.100:8080")
  - Callback URI paths (per profile, e.g., "/api/inventory")
  - Process-injection targets (e.g., "C:\\Windows\\System32\\svchost.exe")
  - Sleep configuration (interval in milliseconds, jitter percentage)
  - Obfuscation method (if not default) — e.g., "ekko", "ziliean"

**Forensic recovery:** 
- Binary file carving from unallocated space (file header: `MZ`)
- Strings extraction with `strings.exe` or Sysinternals `strings` reveals C2 endpoints, URIs, process names
- PE analysis (OriginalFilename, FileDescription, ProductName, CompanyName) — typically blank or spoofed to legitimate processes (e.g., "svchost.exe", "explorer.exe")

**Timeline correlation:**
- File creation/modification time: when Demon was first executed on this machine
- File access time (if not disabled by system policy): last execution time
- MFT entry: can show file was moved/renamed (if attacker staged it before execution)

---

### DLL Sideload or Reflective DLL Injection Artifacts

**Location:** If operator uses `sideload` or `spawn-dll` commands, temporary DLL may be written:
- Temp folder: `C:\Users\<user>\AppData\Local\Temp\<random>.dll`
- System32: `C:\Windows\System32\<spoofed-name>.dll` (if sideloading)
- Memory-only (no disk artifact if pure reflective loading)

**Artifact characteristics:**
- **Format:** DLL (x64/x86), reflectively-loadable (ReflectiveLoader export)
- **PE metadata:** May be spoofed to impersonate legitimate DLL (msvcrt.dll, kernel32.dll, etc.)
- **Strings:** Same C2 configuration as exe binary

**Forensic recovery:**
- File carving (MZ header for PE)
- Filesystem journal (USN Journal) may show DLL creation even if file is deleted
- Memory acquisition: DLL base address in process VAD (Virtual Address Descriptor), memory dump may contain unloaded DLL from pagefile

---

### Staged Payloads / Stager Artifacts

**Location:** If stager was used:
- Stager binary: `C:\Users\<user>\Downloads\stager.exe`
- Downloaded full Demon: memory-only (no disk artifact for full Demon)
- Stager may create temporary files for decoding/decompression

**Artifact characteristics:**
- **Stager size:** 10-50 KB (small stub)
- **Stager strings:** Team Server IP:port, stager URL (where to download full Demon)
- **Full Demon (if recovered from memory):** 5-20 MB, same signatures as unstaged binary

**Forensic recovery:**
- Stager binary on disk (file carving or direct recovery)
- Full Demon recoverable from:
  - Process memory (live or crash dump)
  - Pagefile/hiberfil.sys (if Demon was running and system hibernated/crashed)
  - Cache files (if Demon was cached by Windows Update or antivirus engine)

---

## Process and Memory Artifacts

### Demon Process Creation

**Artifact:** Process list / task manager view during or after Demon execution

**Signatures:**
- **Parent process:** depends on delivery:
  - If executed directly from Downloads: parent = explorer.exe or cmd.exe
  - If executed via email attachment: parent = Outlook.exe
  - If executed via macro/script: parent = powershell.exe or cscript.exe
  
- **Command line:** depends on how operator executed it
  - Direct execution: `C:\Users\analyst\Downloads\demon-payload.exe`
  - Via cmd.exe: `cmd.exe /c demon-payload.exe`
  - Via PowerShell: `powershell.exe -Command C:\Users\analyst\Downloads\demon-payload.exe`

- **Child processes:** Depends on operator actions, but common patterns:
  - **Sacrificial process injection** (per profile's Spawn64): `notepad.exe`, `svchost.exe`, `explorer.exe` spawned as child of Demon
  - **Task execution:** cmd.exe, powershell.exe spawned as children of sacrificial process (not Demon directly, hiding Demon as parent)
  - **execute-assembly:** dotnet runtime injection into sacrificial process, no direct child
  - **sideload/spawn-dll:** unmanaged DLL execution in sacrificial process, no dedicated child

**Forensic indicators (Sysmon / Windows Event Logs):**

| Sysmon Event | Signature | Evidentiary Value |
|---|---|---|
| **Event 1: Process Creation** | Parent: explorer.exe, Child: demon-payload.exe | Direct execution from user interaction |
| **Event 1** | Parent: demon-payload.exe, Child: notepad.exe | Sacrificial process injection starting (per profile Spawn64) |
| **Event 1** | Parent: notepad.exe, Child: cmd.exe | Command execution via injected process |
| **Event 3: Network Connection** | Source: svchost.exe (if injected), Dest: 192.168.1.100:8080, Protocol: TCP | Demon callback from injected process |
| **Event 10: Process Access** | Source: demon process, Target: lsass.exe, GrantedAccess: 0x1010 | Token theft or credential dumping |
| **Event 6: Driver Load** | (Unlikely for Havoc, but if kernel-mode evasion used) | Advanced evasion |
| **Event 13: Registry Set** | Key: HKLM\Software\..., Data: (C2 config or persistence) | Persistence attempts |

---

### Injected Process Memory Artifacts

**Location:** Memory (RAM) of sacrificial process (e.g., notepad.exe injected with Demon)

**Signatures:**
- **Process memory layout anomaly:** legitimate notepad.exe shouldn't have large, executable RWX memory regions or suspicious allocations
- **Loaded DLLs:** injected process may have DLLs it normally wouldn't load (e.g., notepad.exe loaded with unusual libraries)
- **Shellcode/code caves:** RWX memory regions containing x64 shellcode (injected agent logic or staging code)
- **Strings:** C2 configuration, command buffers, task results in process memory

**Forensic recovery:**
- **Live memory acquisition:** Full memory dump using `volatility3` (if analysis workstation is available)
- **Crash dump:** If process crashes, Windows may generate minidump or full dump in `C:\Users\<user>\AppData\Local\Temp\`
- **Memory carving:** `volatility3 dumpfiles` or `bulk_extractor` to extract DLLs/shellcode from memory image

**Ekko sleep obfuscation signature (in memory):**
- Encrypted .text section (appears as random binary blob, not disassemblable)
- VEH (Vectored Exception Handler) entry point that decrypts on wake-up
- Look for `ntdll!RtlAddVectoredExceptionHandler` call, followed by encrypted code region

---

## Network Evidence

### HTTP/HTTPS Callback Traffic

**Characteristics (profile-malleable, but general pattern):**

**Default/example callback:**
```
GET /api/inventory HTTP/1.1
Host: 192.168.1.100:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Connection: Keep-Alive
<blank line>

HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 512
<blank line>
{"status":"ok","version":"1.2.3",...<encoded task data>...}
```

**Anomalies (indicators if profile is not heavily customized):**
1. **Regular check-in interval:** Every 2-5 seconds (default 2s + jitter), visible as periodic HTTP requests from same process
2. **Outbound connection from unexpected process:** svchost.exe, notepad.exe, explorer.exe making HTTP connections to non-standard port (e.g., 8080)
3. **User-Agent mismatch:** Legitimate processes don't normally make HTTP requests; if they do, User-Agent is typically specific to process (e.g., Windows Update has its own User-Agent)
4. **Request/response size pattern:** Requests small (header only), responses may be larger (task data), asymmetric traffic pattern
5. **No prior DNS query:** If target doesn't resolve Team Server hostname via DNS, direct IP connection is unusual (unless target has hardcoded IP or previous DNS cache)

**Zeek/Suricata IDS signatures (if rules are deployed):**
- **Rule 1:** Detect HTTP requests from process list (svchost, notepad) — legitimate processes shouldn't make HTTP requests
- **Rule 2:** Detect periodic HTTP requests to same destination (indicates C2 beaconing), interval pattern analysis
- **Rule 3:** Detect JSON responses containing specific keywords ("status", "task", "command") — may indicate C2 protocol

**Network capture analysis (pcap):**
- Filter: `tcp.dst_port == 8080` (or custom port per profile)
- Look for repeated connections from same source.process to same destination.IP
- Timeline: connections at regular intervals (2s ± jitter) indicate active C2 session

### SMB Named Pipe Pivoting Evidence

**Artifact (if peer-to-peer SMB pivoting used):**
- **SMB connection:** `\\192.168.1.100\IPC$` (inter-process communication share)
- **Named pipe name:** `\\192.168.1.100\pipe\<random>` or `\\192.168.1.100\pipe\havoc-<guid>`
- **SMB Session tree:** IPC$ mount for anonymous or authenticated session
- **SMB protocol negotiation:** NTLMv2 hash exchange (if not using passthrough auth)

**Forensic indicators (Sysmon / Windows Event Logs):**
- **Event 3 (Network Connection):** Source: Demon process, Dest: 192.168.1.100:445, Protocol: TCP (SMB)
- **Event 18 (Pipe Created):** Pipe name: `\Device\NamedPipe\havoc-*` (Sysmon detail level)
- **Security Event 5140 (Share access):** IPC$ accessed by Demon process

**Network capture (pcap):**
- Filter: `tcp.dst_port == 445 and smb` (SMB protocol)
- SMB tree connect to IPC$ (share ID 0xFFFF)
- Named pipe operations (create, read, write) on custom pipe name

---

## Registry Artifacts

### Persistence (if operator configures persistence modules)

**Locations (common persistence vectors):**

| Hive | Key | Value | Evidence of Persistence |
|---|---|---|---|
| HKLM | `Software\Microsoft\Windows\CurrentVersion\Run` | `<value-name>` = `C:\path\to\demon.exe` | Auto-run on boot |
| HKCU | `Software\Microsoft\Windows\CurrentVersion\Run` | Same as above | User-level auto-run |
| HKLM | `System\CurrentControlSet\Services\<ServiceName>` | `ImagePath` = `C:\path\to\demon.exe` | Service-based persistence |
| HKCU | `Software\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell` = `C:\path\to\demon.exe` | Shell replacement (advanced) |
| HKLM | `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<process.exe>` | `Debugger` = `C:\path\to\demon.exe` | IFEO hijacking |

**Forensic recovery:**
- Registry hive files (`C:\Windows\System32\config\SYSTEM`, `C:\Windows\System32\config\SOFTWARE`, `C:\Users\<user>\NTUSER.DAT`)
- Registry transaction logs (`.LOG1`, `.LOG2`) for deleted/overwritten entries
- Deleted entries recoverable from unallocated registry space (if hive is not actively rewriting)

### Recent Execution / Run Keys

**Evidence:**
- **AppCompatCache (Shimcache):** `HKLM\System\CurrentControlSet\Control\Session Manager\AppCompatFlags\AppCompatCache` — tracks program execution (path, last exec time, file size)
- **Prefetch:** `C:\Windows\Prefetch\demon-payload.exe-<hash>.pf` — if Prefetch is enabled (default on Windows 10+)
- **MRU lists:** Most-Recently-Used lists in various registry keys may show Demon binary in file open dialogs

### UAC Bypass / Privilege Escalation Artifacts

**If operator uses token theft or UAC bypass:**
- **Token vault credential caches:** Registry keys or file artifacts if operator stores harvested credentials
- **UAC log entries:** Event 4673 (Sensitive privilege use) if operations required high privileges

---

## Event Log Evidence

### Security Event Log (Windows Event Log)

**Key event IDs for Havoc C2 detection:**

| Event ID | Event Name | Indicator | Havoc-Specific Signature |
|---|---|---|---|
| **4688** | Process Creation | New process started | Demon binary execution; sacrificial process injection |
| **4689** | Process Termination | Process ended | Demon cleanup or crash |
| **4690** | Attempt to duplicate process handle | Token theft | Dem accessing lsass.exe or other process tokens |
| **4703** | Token Right Adjusted | Privilege escalation | Operator adjusting privileges (rare) |
| **4798** | User/Group enumeration | Recon activity | Demon's built-in user/group enumeration |
| **5140** | Network share accessed | SMB connection | Demon connecting to admin shares (C$, ADMIN$) for lateral movement |
| **5145** | Network share access details | SMB detailed access | Read/Write to shared resources |

**Example event 4688 (Havoc process creation):**
```
Process Information:
  New Process ID: 0x0FA8 (4024)
  New Process Name: C:\Users\analyst\Downloads\demon-payload.exe
  Token Elevation Type: Limited
  Mandatory Label: Medium Integrity
  Creator Process ID: 0x0C1C (3100, explorer.exe)
  Creator Process Name: C:\Windows\explorer.exe
  Process Command Line: C:\Users\analyst\Downloads\demon-payload.exe
  Parent Process ID: 3100
  Parent Process Name: C:\Windows\explorer.exe
  Logon ID: 0x25e85
  Subject: CORP\analyst
```

### Sysmon Event Log

**Key Sysmon event IDs:**

| Event ID | Event Name | Indicator |
|---|---|---|
| **1** | Process Creation | Demon binary + sacrificial process spawn |
| **3** | Network Connection | HTTP/S callbacks, SMB pivoting, lateral movement |
| **6** | Driver Load | (Unlikely unless evasion modules used) |
| **7** | Image Loaded (DLL Load) | Suspicious DLLs loaded into sacrificial process |
| **8** | CreateRemoteThread | Shellcode injection into other processes |
| **10** | Process Access | Demon accessing lsass.exe (token theft), other privileged processes |
| **11** | File Created | Temp files, dropped payloads, log files |
| **13** | Registry Set | Persistence, configuration changes |
| **17** | Pipe Created | Named pipe for SMB pivoting or command I/O |
| **18** | Pipe Connected | Pipe usage between processes |
| **23** | File Delete Detected | Cleanup of dropped artifacts |

**Example Sysmon Event 1 (Demon process creation):**
```
Process Create:
  UtcTime: 2025-12-18 14:24:00.123
  ProcessGuid: {12345678-1234-1234-1234-123456789012}
  ProcessId: 4024
  Image: C:\Users\analyst\Downloads\demon-payload.exe
  CommandLine: C:\Users\analyst\Downloads\demon-payload.exe
  CurrentDirectory: C:\Users\analyst
  User: CORP\analyst
  LogonGuid: {87654321-4321-4321-4321-210987654321}
  LogonId: 0x25e85
  TerminalSessionId: 1
  IntegrityLevel: Medium
  ParentProcessId: 3100
  ParentImage: C:\Windows\explorer.exe
  ParentCommandLine: explorer.exe
  ParentUser: CORP\analyst
```

**Example Sysmon Event 10 (Demon accessing lsass.exe for token theft):**
```
Process Access:
  UtcTime: 2025-12-18 14:24:15.456
  SourceProcessGuid: {12345678-1234-1234-1234-123456789012}
  SourceProcessId: 4024
  SourceImage: C:\Users\analyst\Downloads\demon-payload.exe
  TargetProcessGuid: {99999999-9999-9999-9999-999999999999}
  TargetProcessId: 504
  TargetImage: C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1010  (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
  CallTrace: C:\Windows\System32\ntdll.dll+0x52da4|C:\Windows\System32\kernel32.dll+0x17344|C:\Users\analyst\Downloads\demon-payload.exe+0x45120
  SourceUser: CORP\analyst
```

### PowerShell Event Log (if execution history enabled)

**Event IDs:**
- **4103:** Command line executed (if Module Logging enabled, non-default)
- **4104:** Script block executed (if Script Block Logging enabled, non-default)

**Example (if execute-assembly is logged via PowerShell):**
```
ScriptBlock Text:
  $SharpUpBytes = [Convert]::FromBase64String('TVqQAAM...')
  [Reflection.Assembly]::Load($SharpUpBytes)
  
Log Name: Windows PowerShell
Event ID: 4104
Level: Warning
```

---

## Prefetch File Analysis

**Location:** `C:\Windows\Prefetch\demon-payload.exe-<hash>.pf`

**Artifact value:** HIGH — Prefetch files contain:
- **Execution count:** how many times Demon was executed
- **Last execution time:** when Demon last ran (in UTC)
- **Process creation flags and arguments** (partial, truncated)
- **Loaded DLLs and file accesses during execution** (list of files/directories accessed in first 10 seconds of execution)

**Forensic extraction:**
- Tools: `PECmd.exe` (Eric Zimmerman), `WinPrefetchView.exe` (Nirsoft)
- Example parsed output:
  ```
  Executable: C:\Users\analyst\Downloads\demon-payload.exe
  Execution Times:
    Last Run: 2025-12-18 14:24:15 UTC
    Execution Count: 5
  
  Loaded Files:
    C:\Windows\System32\kernel32.dll
    C:\Windows\System32\ntdll.dll
    C:\Windows\System32\notepad.exe (if injected into notepad)
    C:\Users\analyst\AppData\Local\Temp\<random files>
  ```

---

## LNK File Analysis (Shortcut Files)

**Location:** If Demon was executed via shortcut:
- Desktop: `C:\Users\analyst\Desktop\<shortcut>.lnk`
- Start Menu: `C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\<shortcut>.lnk`
- Recent: `C:\Users\analyst\AppData\Roaming\Microsoft\Windows\Recent\<lnk-file>.lnk`

**Artifact value:** MEDIUM — LNK files contain:
- **Target path:** full path to Demon executable
- **Working directory:** where Demon was executed from
- **Icon location:** if spoofed icon used
- **Hotkey:** if shortcut has keyboard shortcut
- **DataBlock strings:** additional metadata (volume GUID, drive serial number, hostname where LNK was created)

**Forensic extraction:**
- Tools: `lnk-parser` (python-lnk), `ShellLink.exe` (Eric Zimmerman)

---

## Temporary File Artifacts

### Stager / Staging Artifacts

**Location:** `C:\Users\<user>\AppData\Local\Temp\` (or system temp `C:\Windows\Temp\`)

**Artifacts:**
- **Stager binary:** if not cleaned up after execution
- **Decoded payloads:** if stager decompresses full Demon to temp before loading into memory
- **Log files:** if Demon or modules create logs during execution
- **Clipboard data:** if clipboard module was loaded

**Forensic recovery:**
- File carving from disk unallocated space
- Temp folder enumeration (often overlooked, rarely cleaned on active systems)
- Prefetch file (shows which Temp files were accessed during Demon execution)

---

## Lateral Movement and Privilege Escalation Evidence

### PsExec / Remote Service Execution

**If operator uses `psexec` command to move laterally:**

**Target machine (CORP-SRV-001):**

| Artifact | Location | Signature |
|---|---|---|
| **Service creation log** | Event 7045 (Sysmon: Service Installed) or Event 4697 (Security log) | New service created (e.g., PSEXESVC, random name) |
| **Service binary** | `C:\Windows\System32\PSEXESVC.exe` (if using default name) | Dropped remote service binary (typically unique per execution) |
| **Service start log** | Event 7040 (Sysmon) or Task Scheduler logs | Service started and executed payload |
| **Payload output file** | `C:\Windows\<random>.tmp` or ADMIN$ share | Temp output file from smbexec-style lateral movement |
| **Named pipes** | Sysmon Event 17-18 (Pipe Create/Connect) | Temporary named pipes for SMB communication |

---

## Timeline Construction Example

```
2025-12-18 14:24:00 UTC
  Prefetch: demon-payload.exe first execution
  Event 4688: Process created (demon-payload.exe)
  Parent: explorer.exe (user double-clicked Downloads)

2025-12-18 14:24:05 UTC
  Sysmon Event 1: Demon spawns notepad.exe (sacrificial)
  Parent: demon-payload.exe → Child: notepad.exe (PID 5820)

2025-12-18 14:24:10 UTC
  Sysmon Event 8: CreateRemoteThread (Demon → notepad, shellcode injection)
  Sysmon Event 7: notepad.exe loads unexpected DLL (e.g., ntdll variant)

2025-12-18 14:24:15 UTC
  Sysmon Event 3: Network connection established
  Source: notepad.exe (injected), Dest: 192.168.1.100:8080, TCP

2025-12-18 14:24:20 UTC
  HTTP traffic (pcap): First HTTP GET /api/inventory request
  Response: 200 OK (task: execute-assembly SharpUp.exe)

2025-12-18 14:24:25 UTC
  Sysmon Event 10: notepad.exe accesses lsass.exe (token theft)
  GrantedAccess: 0x1010

2025-12-18 14:24:30 UTC
  Sysmon Event 1: cmd.exe spawned by notepad.exe
  Command line: (may be obfuscated or hidden)

2025-12-18 14:25:00 UTC
  HTTP traffic: POST request with SharpUp output (task result)

2025-12-18 14:25:10 UTC
  Sysmon Event 3: SMB connection to \\CORP-SRV-001\ADMIN$
  Lateral movement attempt initiated
```

---

## Detection Evasion vs. Unavoidable Signals

| Signal | Evasion Possible? | Reason |
|---|---|---|
| **Binary file on disk** | Yes | Use stager (stays in memory) or enable SMB pivoting (no disk artifact on target) |
| **Process creation (parent/child tree)** | Partial | Spoofing parent process is difficult; sacrificial process injection hides Demon's direct children |
| **Network check-in timing/interval** | No | Beacon interval (2s ± jitter) is deterministic given profile; observable via traffic analysis |
| **HTTP User-Agent / custom headers** | No | Can be customized in YAOTL profile, but operator must know network environment |
| **Sysmon Event 10 (lsass access)** | Partial | Can be hidden with userland hook patching (per-profile evasion setting), but direct API access to LSASS requires process handle |
| **Prefetch file** | No | Prefetch is automatic Windows behavior; can only be disabled system-wide (disables all prefetch) |
| **SMB named pipes (pivoting)** | No | SMB is inherently logged at protocol level; only alternative is HTTP (no SMB) |
| **Team Server IP:port in binary** | No | Embedded in compiled binary; reverse engineering any Demon payload reveals C2 infrastructure |

---

## Forensic Readiness Checklist

**For defenders expecting Havoc deployment:**

- [ ] **Enable Sysmon** with high-detail configuration (events 1, 3, 7, 8, 10, 11, 13, 17, 18)
- [ ] **Enable PowerShell Module Logging** (Event 4103) for command-line visibility
- [ ] **Monitor Event 4688 (Process Creation)** with command-line auditing enabled
- [ ] **Enable Windows Defender / AMSI** logging (if available via Microsoft Defender for Endpoint)
- [ ] **Deploy EDR agent** with behavioral/memory monitoring (Falcon, Sentinelone, etc.)
- [ ] **Configure Zeek / Suricata** for network-layer C2 detection (periodic HTTP requests, anomalous User-Agents)
- [ ] **Prefetch enabled** (default on Win10+, verify not disabled)
- [ ] **Collect full packet capture (PCAP)** for at least 24 hours to baseline network behavior
- [ ] **Image target systems regularly** to establish baseline for comparison post-compromise

---

