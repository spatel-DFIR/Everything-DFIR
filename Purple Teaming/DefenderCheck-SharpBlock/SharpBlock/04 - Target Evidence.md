# SharpBlock — Target Evidence

**Where to look on the target (victim) host for evidence of SharpBlock usage or its impact.**

Unlike DefenderCheck (a tool run on the attacker's machine), SharpBlock is **deployed and executed directly on the target**, making forensic evidence abundant and relatively straightforward to hunt.

---

## Direct SharpBlock Execution

### SharpBlock.exe Binary on Disk

**Locations:**
- `C:\Temp\SharpBlock.exe` (common staging location).
- `C:\Windows\Temp\SharpBlock.exe`.
- `C:\Users\<username>\AppData\Local\Temp\SharpBlock.exe`.
- `C:\Tools\`, `C:\Staging\`, or other attacker-created directories.

**Forensic Indicators:**
- **File timestamp**: When SharpBlock was written to disk (matches attacker's intrusion window).
- **File hash**: Correlate with known SharpBlock samples (GitHub hash, VirusTotal).
- **File metadata**: Executable properties, version info, compiler version.
- **Deleted file recovery**: If attacker deleted SharpBlock post-execution, file may be recoverable via forensic carving or $MFT analysis.

**Huntable via:**
```powershell
# Live host search
Get-ChildItem -Path C:\ -Recurse -Filter "*SharpBlock*" -ErrorAction SilentlyContinue

# Forensic search
Find all files named SharpBlock.exe in disk image
```

### Process Execution Evidence

**Windows Event Log: Security (Event ID 4688 - Process Creation)**
```
EventID: 4688
Image: C:\Temp\SharpBlock.exe
CommandLine: SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll -a "/c echo test"
ParentImage: cmd.exe or powershell.exe (typical)
LogonGuid: <GUID of attacker's logon session>
TerminalSessionId: <session ID>
TargetUserName: <compromised user account>
TargetDomainName: <domain>
```

**Huntable SIEM Query:**
```
EventID == 4688 AND Image LIKE "*SharpBlock*"
```

**Expected Finding:** SharpBlock process executed on target during intrusion window.

---

## Process Injection Evidence

### Suspicious Process Relationships

When SharpBlock injects a beacon into a legitimate process (e.g., `cmd.exe`, `notepad.exe`), the following anomalies appear:

#### 1. Unexpected Parent-Child Process Relationships
```
Example: svchost.exe → notepad.exe → (injected beacon)
OR: cmd.exe → rundll32.exe → (injected beacon)
```

**Normal Windows process trees rarely have:**
- `svchost.exe` spawning `notepad.exe` or `cmd.exe`.
- `cmd.exe` spawning multiple child processes with identical arguments but different PIDs in rapid succession.
- `rundll32.exe` spawning unprompted (unless legitimate DLL invocation).

**Event Log Evidence:**
```
Event ID 4688: notepad.exe spawned by svchost.exe (abnormal)
Event ID 4688: cmd.exe spawned by explorer.exe with suspicious arguments
```

#### 2. Process Suspension/Resumption Pattern

SharpBlock suspends a process during injection. This may be visible in:
- **Profiling data**: Process shows brief suspension (not typical for user-interactive processes).
- **Thread state**: If captured via forensic tool, some threads show "suspended" state.
- **EDR behavioral logs** (if available): Events showing process suspension followed by memory injection.

**Huntable via EDR:**
```
- Crowdstrike: Thread Execution Suspense Detection
- Microsoft Defender for Endpoint: Behavior-based alerts for process injection
- Sentinel One: Memory Injection Detection
```

#### 3. Memory Injection Events

**Windows Event Log: Windows Defender / Security Logs**
- If EDR is enabled (and not bypassed), injection attempts may trigger alerts before DLL blocking takes effect.
- **Event ID 1001** (threat detected): If beacon is detected before injection completes.
- **Event ID 5000** (service events): EDR service events related to injection detection.

**Expected finding (if EDR was NOT bypassed):**
```
Event ID: 1001
Threat: HackTool:MSIL/SharpBlock.A or Trojan:Win32/Beaconing
File: C:\Temp\SharpBlock.exe or injected process memory
Timestamp: During injection window
```

---

## Command-Line Spoofing Evidence

### Discrepancy Between Declared and Actual Command-Line

SharpBlock modifies the `PEB.ProcessParameters.CommandLine` to spoof arguments. However, multiple views of the command-line may exist:

#### View 1: Process Explorer / Task Manager
Shows the **spoofed** command line (PEB view):
```
cmd.exe /c echo test
notepad.exe -readme.txt
```

#### View 2: Event Log 4688
May show the **original** command line (if captured before PEB modification) or the spoofed one (if captured after):
```
ParentImage: C:\Windows\System32\cmd.exe
CommandLine: C:\Windows\System32\cmd.exe /c echo test
```

#### View 3: WMI / CIM (Common Information Model)
May show injected code's true behavior (attempting C2 connection, despite spoofed command-line).

**Huntable Pattern:** Discrepancy between command-line (innocent-looking) and process behavior (malicious):
- Command-line says: `cmd.exe /c echo test`
- Network evidence shows: Outbound connection to 192.0.2.10:4444 (C2 server).
- API call sequences show: VirtualAlloc, WriteProcessMemory (injection signatures).

---

## EDR DLL Tampering / Blocking Evidence

### DLL Load Events

**Windows Event Log: Sysmon (if deployed)**
- **Event ID 7** (Image Loaded): Logs when a DLL is loaded into a process.
- Anomalies:
  - **EDR DLL not loaded** when expected (e.g., `csagent.dll` should load in all processes, but doesn't in the injected beacon process).
  - **EDR DLL loaded, but entry point never executed** (unusual for EDR DLL).

**Sysmon Query Example:**
```
EventID == 7 AND Image == "beacon.exe" AND ImageLoaded NOT LIKE "*csagent.dll"
```

**Expected Finding:** EDR DLL conspicuously absent from the injected process's loaded modules.

### Registry Tampering (If Attacker Disables EDR)

If SharpBlock is preceded by EDR disable steps:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSFalconService
  Start: 4 (disabled) or 3 (manual)
```

**Event Log Evidence:**
```
Event ID: 7045 (New Service Installed) or 7040 (Service Start Type Changed)
ServiceName: CSFalconService
StartType: Disabled or Manual
Timestamp: Before SharpBlock execution
```

---

## Beacon / Payload Execution Indicators

### Payload Binary on Disk

**Locations:**
- `C:\Temp\beacon.exe` (most common).
- `C:\Windows\Temp\rubeus.exe`.
- Other attacker-controlled staging directories.

**Forensic Indicators:**
- File hash (correlate with known payloads).
- Timestamp (matches SharpBlock execution window).
- PE metadata (if signed, verify signature; if unsigned, suspicious).

### Network Indicators (C2 Callback)

**Firewall logs / Proxy logs:**
```
2024-01-15 14:00:30 — Outbound TCP 192.168.1.50:53928 → 192.0.2.10:4444
Beacon callback from cmd.exe (spoofed as innocent process)
```

**DNS logs:**
```
Query: beacon.attacker.com (if beacon uses domain for C2)
Source IP: 192.168.1.50 (target host)
Timestamp: 2024-01-15 14:00:30
```

**Network behavior (if captured):**
- **HTTP/HTTPS POST**: Typical Cobalt Strike beacon callback structure.
- **SSL/TLS certificate**: If beacon uses encrypted C2, certificate issuer may indicate Cobalt Strike (self-signed, specific certificate patterns).
- **Traffic pattern**: Regular beacons at interval (e.g., every 5 seconds, every 60 seconds).

### Process API Call Patterns (If EDR Monitoring is Active)

If EDR is monitoring despite DLL blocking, or if post-incident forensics capture API logs:
```
Process: cmd.exe (spoofed beacon)
API Calls:
  - VirtualAlloc(flAllocationType=MEM_COMMIT|MEM_RESERVE, flProtect=PAGE_EXECUTE_READWRITE)
  - WriteProcessMemory() — writes shellcode/beacon code
  - CreateRemoteThread() or SetThreadContext() — executes injected code
  - InternetConnectW(), HttpSendRequestW() — C2 callback APIs
```

**Indicator:** This API pattern is characteristic of process injection and C2 callback.

---

## Parent Process Spoofing Evidence

### Anomalous Parent-Child Relationships

If SharpBlock spoofs parent process ID via `--ppid`:

**Before Spoofing:**
```
Process Tree:
cmd.exe (PID 1024) spawned by explorer.exe
  └─ SharpBlock.exe (PID 4560)
    └─ notepad.exe (PID 6000, spoofed to appear as child of svchost.exe PID 512)
```

**After Spoofing (from Process Explorer view):**
```
Process Tree:
svchost.exe (PID 512)
  └─ notepad.exe (PID 6000) — SPOOFED parent; true parent is cmd.exe
```

**Detection Anomalies:**
- **Event Log 4688**: Shows notepad spawned by cmd.exe (true parent).
- **Process Tree tools** (Get-Process, Process Explorer): Show notepad as child of svchost.exe (spoofed).
- **Discrepancy alert**: Process monitoring should flag parent-child mismatches.

**Huntable Pattern:**
```
Correlation:
  Event 4688: cmd.exe spawned notepad.exe
  But Process Explorer shows: svchost.exe → notepad.exe
  Conflict = Parent spoofing detected
```

---

## Memory-Based Artifacts

### In-Memory Beacon Presence

If forensic memory capture is performed during or shortly after SharpBlock injection:

**Memory forensics (using Volatility, WinPmem):**
```
volatility -f memory.dmp windows.pslist | grep -E "(cmd|notepad|rundll32)"
  PID: 6000
  Name: notepad.exe
  Parent: svchost.exe (spoofed)
  
volatility -f memory.dmp windows.malfind | grep beacon
  [Injected beacon code detected in notepad.exe memory]
```

**Expected Finding:**
- Injected beacon code in process memory (recognizable by shellcode signatures, C2 strings, etc.).
- Mismatched parent PID (if spoofed).

### Beacon Configuration in Memory

If the beacon stores configuration (C2 server, encryption key, sleep interval) in memory:
```
Memory Contents:
String: 192.0.2.10:4444 (C2 server)
String: HTTPS (encryption)
DWORD: 5000 (sleep interval ms)
```

---

## Timeline Reconstruction

**Complete forensic timeline for SharpBlock injection:**

```
2024-01-15 14:00:00 — RDP/SSH logon from 203.0.113.45 (attacker)
2024-01-15 14:05:30 — Event 4688: cmd.exe spawned (attacker's reverse shell)
2024-01-15 14:06:00 — SharpBlock.exe written to C:\Temp\ (file timestamp)
2024-01-15 14:06:15 — Event 4688: SharpBlock.exe executed
                      Command: SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll -a "/c calc.exe"
2024-01-15 14:06:20 — Event 4688: cmd.exe created (suspended, by SharpBlock)
                      Parent: SharpBlock.exe
2024-01-15 14:06:25 — Memory injection occurs (EDR DLL blocked, no log)
2024-01-15 14:06:30 — Injected beacon executes, calls back to C2
2024-01-15 14:06:35 — Network: Outbound TCP 192.168.1.50:53928 → 192.0.2.10:4444
                      Beacon callback received
2024-01-15 14:07:00 — SharpBlock.exe deleted from disk (attacker cleanup)
2024-01-15 14:07:05 — beacon.exe deleted from disk (attacker cleanup)
[Attacker maintains C2 access via injected beacon]
```

---

## Defender Evasion Indicators

### Absence of EDR Alerts During Injection

**Key Indicator:** If Falcon, MDE, or Sentinel One is deployed but **no injection/process-manipulation alerts** are logged during the injection window, it strongly suggests EDR was bypassed.

**SIEM Hunt:**
```
Time Window: 2024-01-15 14:06:00 to 14:07:00
Falcon Alert: NONE (expected: multiple injection/process-hollow alerts)
Conclusion: EDR was bypassed (consistent with SharpBlock usage)
```

### Disabled EDR Service

**Registry evidence:**
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CSFalconService
  Start: 4 (disabled)
  LastWriteTime: 2024-01-15 14:00:00 (before injection)
```

**Event Log:**
```
Event ID: 7040 (Service Start Type Changed)
ServiceName: CSFalconService
PreviousState: Enabled (Auto/Manual)
NewState: Disabled
Timestamp: 2024-01-15 14:00:00
```

---

## Summary: On-Target Indicators Table

| Indicator | Severity | Confidence | Forensic Value |
|---|---|---|---|
| **SharpBlock.exe binary on disk** | Critical | Very High | Direct proof of SharpBlock usage; file hash, timestamps. |
| **Process: SharpBlock.exe execution (Event 4688)** | Critical | Very High | Exact timestamp, command-line arguments, parent process. |
| **Anomalous parent-child process relationships** | High | High | Parent spoofing, injection target identification. |
| **EDR DLL absent from injected process** | High | Medium | Indicates DLL blocking; correlate with EDR DLL name in SharpBlock args. |
| **Command-line spoofing discrepancy** | Medium | Medium | PEB vs. Event Log command-line mismatch. |
| **Beacon network callback (C2 connection)** | High | High | Network indicators; C2 domain/IP identification. |
| **Injected beacon code in memory** | High | Medium | Requires memory forensics; recognizable shellcode. |
| **EDR service disabled** | High | High | Registry timestamp correlates with injection window. |
| **Payload binary (beacon.exe, rubeus.exe)** | High | High | File hash, metadata, timestamps. |
| **Rapid file creation/deletion (beacon cleanup)** | Medium | Medium | $MFT records, $UsnJrnl; if attacker deleted payloads. |

---

## Response Playbook

### If SharpBlock is Detected

1. **Immediate Actions:**
   - Isolate the host from the network (prevent beacon callback).
   - Capture process memory (for in-memory beacon analysis).
   - Preserve disk image (for $MFT, file system journal analysis).
   - Collect event logs (Security, System, Application).

2. **Investigation:**
   - **Timeline**: When was SharpBlock executed? (Event 4688 timestamp, file timestamps).
   - **Injection target**: Which process was hollowed? (Event 4688 parent-child relationship).
   - **Payload**: What was injected? (beacon.exe hash, network indicators).
   - **EDR bypass**: Which EDR DLL was blocked? (SharpBlock command-line arguments).
   - **Attacker origin**: Where did attacker come from? (RDP logon source IP, reverse shell connection logs).

3. **Artifact Collection:**
   - File system search for SharpBlock, beacon, and other payloads.
   - Event Log dump (Security, System, Windows Defender, Application).
   - Registry hives (SYSTEM, SAM, SECURITY, NTUSER.DAT).
   - Memory dump (if possible, capture before shutting down).
   - Network logs (firewall, IDS/IPS, DNS, proxy).
   - Prefetch files (for execution history).

4. **Containment:**
   - Disable attacker's logon session (RDP session, service account).
   - Kill injected beacon process (if possible without alerting attacker).
   - Re-enable EDR service (if disabled).
   - Block C2 domain/IP at firewall.

5. **Eradication:**
   - Remove SharpBlock, beacon, and other payloads.
   - Remove persistence mechanisms (if attacker created any).
   - Reset compromised credentials.
   - Patch exploited vulnerabilities.

6. **Post-Incident:**
   - Write detailed timeline for incident report.
   - Correlate with other incident data (phishing emails, exploited vulnerabilities, etc.).
   - Share beacon hash + C2 infrastructure details with SOC.
   - Review EDR policies across enterprise (ensure EDR cannot be easily disabled).

---

## Cross-Links

- **EDR Architecture & Detection Bypass**: See `Windows/11 - Defense Evasion/AMSI, ETW, Windows Defender.md` for deep dives into AMSI/ETW bypass mechanisms.
- **Process Injection Fundamentals**: See `Windows/11 - Lateral Movement/Process Injection.md` for detailed process injection techniques and detection.
- **Forensic Analysis**: See `Windows/11 - Evidence Collection/Memory Forensics, Process Forensics.md` for memory-based artifact analysis.
