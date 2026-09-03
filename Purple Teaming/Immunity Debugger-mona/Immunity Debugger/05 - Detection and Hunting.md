# Immunity Debugger — Detection and Hunting

## Hunting Priority Table

| Signal | Survival vs. Evasion | Reliability | Notes |
|---|---|---|---|
| **Debugger64.exe process creation (source machine)** | Survives all exploit evasion | High | Direct indicator of debugging activity; requires access to source machine |
| **Sysmon Event 1: Debugger64.exe → debuggee child process** | Survives all evasion | High | Parent-child relationship is distinctive; typical suspicious pattern on user workstations |
| **.udd project file timestamps** | Survives all evasion | High | Directly correlates development timeline to exploit deployment; requires file system access on source machine |
| **mona.py plugin presence** | Survives all evasion | Medium | Plugin presence + modification timestamps indicate crash analysis; archived repo status affects current prevalence |
| **Crash dump (.dmp) file with exploit pattern** | Depends on post-exploitation cleanup | High | Stack/heap corruption, ROP gadget addresses, shellcode bytes are distinctive; operator may clean up dumps after development |
| **Target: Vulnerable app → unexpected child (cmd.exe, powershell.exe)** | Low (evasion via in-process shellcode) | Medium | If shellcode spawns a child, parent-child is distinctive; in-process shellcode avoids this signature entirely |
| **Target: Stack corruption + EIP control** | Survives all evasion | High | Memory dump/crash dump analysis; requires crash or memory forensics access on target |
| **Target: Precise ROP chain with badchar-free shellcode** | Low (trivially customizable) | Low-Medium | Suggests careful, local development; but ROP gadgets are specific to target binary version and ASLR state |
| **Registry/file persistence via ROP chain** | Low (easily re-targeted) | Medium | Persistence artifacts depend on exploit payload; ROP-chain technique is reusable but leaves post-exploitation traces |
| **Process behavior: Crash + immediate child process spawn** | Medium (in-process shellcode avoids this) | Medium | Temporal correlation: crash event + new process creation within 1s suggests exploitation success |

---

## Hunting on Source Machine

Detecting Immunity Debugger usage on the **attacker's workstation**.

### Process-Level Hunting

**Search for Debugger64.exe or Debugger.exe process creation:**

```powershell
# PowerShell: Search Security Event Log for Debugger process creation
Get-WinEvent -LogName Security -FilterHashtable @{
    EventID = 4688
    CommandLine = "*Debugger64.exe*" -or "*Debugger.exe*"
} | Select-Object TimeCreated, ProcessName, CommandLine, ParentProcessName
```

**Sysmon Event 1 (recommended):**
```powershell
# Query Sysmon for Debugger launches
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 1
    Image = "*Debugger64.exe"  # Executable path contains "Debugger64.exe"
} | Select-Object TimeCreated, Image, CommandLine, ParentImage, TargetFilename
```

**Expected Result:**
```
TimeCreated: 2026-08-11 14:32:45
Image: C:\Program Files\Immunity Inc\Debugger\Debugger64.exe
CommandLine: Debugger64.exe vulnerable.exe
ParentImage: C:\Windows\explorer.exe (or cmd.exe, powershell.exe)
```

---

### Project File Hunting (.udd Files)

**Search for .udd files and their timestamps:**

```powershell
# Find all .udd files on the machine (recursively)
Get-ChildItem -Path C:\ -Filter "*.udd" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullPath, CreationTime, LastWriteTime, Length

# Correlate with exploit deployment timeline
# If .udd file was created/modified 1-24 hours before an attack, suggests local exploit development
```

**Common .udd File Locations:**
- `C:\Users\<username>\Desktop\*.udd`
- `C:\Users\<username>\Documents\*.udd`
- `C:\Users\<username>\AppData\Local\Temp\*.udd`
- Project-specific folders (e.g., `C:\Pentests\<client>\*.udd`)

---

### Minidump Hunting (.dmp Files)

**Search for minidump files with suspicious content:**

```powershell
# Find all .dmp crash dump files
Get-ChildItem -Path C:\ -Filter "*.dmp" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullPath, CreationTime, Length

# Recent .dmp files with size > 1MB likely contain process memory snapshots
# Smaller .dmp files (< 100KB) are typically Windows Error Reporting minidumps (less useful for analysis)
```

**Analyze .dmp Content (Volatility/Rekall):**
```bash
# Extract and search for exploit patterns in .dmp files
strings crash.dmp | grep -E "Debugger64|mona\.py|pattern_create|shellcode" 

# Look for ROP gadget or stack corruption patterns
strings crash.dmp | grep -E "xchg.*eax|pop.*ret|add.*rsp"
```

---

### Debugging API Call Hunting

**Monitor for Debug API usage (Real-time Detection):**

```powershell
# Use Sysmon to monitor for DebugActiveProcess API calls
# (Requires Sysmon event source configuration; not all systems have this enabled)

# Alternative: Hunt for processes opening other processes with DEBUG access rights
# This requires Process Access event logging (Sysmon Event 10)

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 10  # Process Access
    GrantedAccess = @("0x1000", "0x1400", "0x1438", "0x143B")  # DEBUG_PROCESS rights
} | Select-Object TimeCreated, SourceProcessName, TargetProcessName, GrantedAccess
```

**Expected Result (suspicious):**
```
SourceProcessName: C:\Program Files\Immunity Inc\Debugger\Debugger64.exe
TargetProcessName: C:\path\to\vulnerable.exe
GrantedAccess: 0x1438 (DEBUG_PROCESS + other debug rights)
```

---

### Shell History Hunting

**PowerShell History (User-Level):**
```powershell
# Search for Debugger launches in PowerShell history
$HistoryPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $HistoryPath) {
    Get-Content $HistoryPath | Select-String "Debugger64|Debugger\.exe" -Context 2
}
```

**Expected Result:**
```
> C:\Program Files\Immunity Inc\Debugger\Debugger64.exe C:\path\to\vulnerable.exe
```

---

### Plugin Folder Hunting

**Search for mona.py in Immunity Debugger plugins:**

```powershell
# Check for mona.py installation
$PluginsPath = "$env:APPDATA\Immunity Inc\Debugger\PyCommands"
if (Test-Path $PluginsPath) {
    Get-ChildItem -Path $PluginsPath -Filter "*mona*" -Recurse |
      Select-Object FullPath, CreationTime, LastWriteTime
}

# List all Python scripts in the plugins folder (operator-created scripts are suspicious)
Get-ChildItem -Path $PluginsPath -Filter "*.py" -Recurse |
  Select-Object FullPath, Length, LastWriteTime
```

---

## Hunting on Target Machine

Detecting **exploits developed with Immunity Debugger** that were deployed on the target.

### Process Creation Anomalies

**Detect vulnerable app spawning unexpected children:**

```powershell
# Sysmon Event 1: Find suspicious process creation
# Specifically: known vulnerable application spawning cmd.exe or powershell.exe

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 1
} | Where-Object {
    ($_.Properties[1].Value -like "*vulnerable*.exe") -and  # Parent
    ($_.Properties[20].Value -like "*cmd.exe*" -or $_.Properties[20].Value -like "*powershell.exe*")  # Child
} | Select-Object TimeCreated, ParentProcessName, ProcessName, CommandLine
```

**Example Suspicious Pattern:**
```
TimeCreated: 2026-08-11 15:22:30
ParentProcessName: C:\path\to\vulnerable_app.exe
ProcessName: C:\Windows\System32\cmd.exe
CommandLine: cmd.exe /c whoami
```

---

### Stack Corruption & Crash Detection

**Hunt for crash events with memory corruption signatures:**

```powershell
# Windows Event ID 1001: Application Error (crash)
# Look for crashes with "Access Violation" or "Stack Corruption" indicators

Get-WinEvent -LogName "Application" -FilterHashtable @{
    EventID = 1001
    Source = "Windows Error Reporting"
} | Where-Object {
    $_.Message -match "Stack Overflow|Heap Corruption|Access Violation|Invalid Pointer"
} | Select-Object TimeCreated, Message | Format-List

# More specific: Sysmon Event 5 (Process Terminated with exception)
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 5
} | Where-Object {
    $_.Properties[2].Value -match "0xC0000005|0xC0000374"  # ACCESS_VIOLATION or HEAP_CORRUPTION
} | Select-Object TimeCreated, ProcessName, ExitStatus
```

---

### ROP Chain Indicators

**Search for ROP gadget execution patterns:**

```powershell
# ROP chains typically manifest as:
# 1. Unusual call patterns (call followed by immediate return)
# 2. Stack pivoting (ESP modification at unusual addresses)
# 3. API calls from unexpected addresses

# This requires memory analysis or crash dump analysis (not real-time event log hunting)
# Use Volatility or Windows Debugger to inspect crash dump:

# Via WinDbg (command-line):
# cdb.exe -z crash.dmp -c "u @rip L5; q"  # Unassemble code at crash point

# Via Volatility:
# volatility3 -f crash.dmp windows.dumpfiles --pid=<PID>  # Extract process memory
# strings process_memory | grep -E "pop.*ret|xchg.*esp|call.*esp"
```

---

### File Dropping Indicators

**Detect unexpected file creation by vulnerable applications:**

```powershell
# Sysmon Event 11: FileCreate
# Vulnerable app creating executables or scripts is suspicious

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 11
} | Where-Object {
    ($_.Properties[2].Value -like "*vulnerable*.exe") -and  # Image (process) is vulnerable app
    ($_.Properties[6].Value -like "*.exe" -or $_.Properties[6].Value -like "*.ps1" -or $_.Properties[6].Value -like "*.dll")  # TargetFilename is executable
} | Select-Object TimeCreated, ProcessName, TargetFilename, Initiated
```

**Example (suspicious):**
```
TimeCreated: 2026-08-11 15:22:35
ProcessName: C:\path\to\vulnerable_app.exe
TargetFilename: C:\Windows\Temp\random_payload.exe
```

---

### Badchar & Shellcode Pattern Detection

**EDR/YARA-based shellcode detection:**

```powershell
# Real-time: Windows Defender Behavior detection
# Symptoms: Process memory anomalies, shellcode injection attempts
# Logs: Windows Defender -> Application event log

# Manual: String search in crash dumps for shellcode signatures
$StringSearch = @(
    "\x90\x90\x90\x90",  # NOP sled
    "\xCC\xCC\xCC\xCC",  # INT3 (breakpoint)
    "\x55\x89\xE5\x83",  # Function prologue (push ebp; mov ebp, esp; sub esp, ...)
    "\xFF\xE4",          # JMP ESP
    "\x5B\xC3"           # POP EBX; RET (common ROP gadget)
)

# Search crash dump with YARA rules designed for shellcode:
yara -r shellcode_rules.yar crash.dmp
```

---

## Hunting by EDR / Endpoint Security

### Windows Defender for Endpoint

**Native Behavioral Alerts:**
- **"Suspicious process creation"** — Vulnerable app → cmd.exe spawn.
- **"Suspicious memory allocation"** — Large heap allocation + shellcode injection.
- **"Possible heap corruption"** — Heap metadata overwrite detected.

**Remediation:** Quarantine vulnerable process; collect crash dump for analysis.

### CrowdStrike Falcon

**Custom Detection Rules:**
```
event_type = ProcessExecution
parent_process_name = "*vulnerable*.exe" AND
child_process_name IN (cmd.exe, powershell.exe) AND
parent_process_id > 0 AND
CommandLine CONTAINS whoami OR CommandLine CONTAINS ipconfig
```

---

## Remediation & Evidence Collection

### Before Terminating the Process

1. **Capture Memory Dump:**
   ```powershell
   # Use ProcDump (included in Sysinternals) to capture process memory
   procdump.exe -ma <PID> crash.dmp
   ```

2. **Collect Event Logs:**
   ```powershell
   # Export Sysmon logs for the affected time window
   wevtutil epl "Microsoft-Windows-Sysmon/Operational" sysmon_export.evtx
   ```

3. **Preserve Filesystem:**
   - Copy any dropped files to a forensic archive.
   - Note file creation times, last modification times.

### After Mitigation

1. **Root Cause Analysis:**
   - Identify the vulnerable application and version.
   - Determine if updates or patches are available.
   - Assess whether the vulnerability is public (e.g., CVE database) or zero-day.

2. **Timeline Correlation:**
   - Match exploit deployment timestamp (from network logs, file creation) to:
     - Vulnerable app crash event.
     - Post-exploitation activity (child process spawns, registry changes, file creation).
   - Determine if there's an attacker's source machine visible in network logs (reverse shell connection, C2 callback).

3. **Preserve Evidence:**
   - Keep crash dumps, event logs, and memory forensics for investigation.
   - Correlate target evidence with any captured network traffic (PCAP, NetFlow, Zeek logs).

---

## Fleet-Wide Sweep (Mass Detection)

### Enterprise Endpoint Detection

**Sysmon-based:\*\*
```powershell
# Query all machines in the domain for Debugger.exe process creation
# (Requires centralized Sysmon log collection: Splunk, ELK, Windows Event Forwarding)

index="sysmon" EventCode=1 Image="*Debugger64.exe" OR Image="*Debugger.exe"
| stats count by host, Image, CommandLine, ParentImage
| where count > 0
```

**YARA Scanning (on-demand):**
```bash
# Scan all machines for .udd files and minidumps created in the last 24 hours
for machine in $(cat machines.txt); do
    ssh $machine "find /path -name '*.udd' -o -name '*.dmp' -mtime -1" 2>/dev/null
done
```

### Cloud/Container Environments

**If Immunity Debugger is running in a container (unusual but possible):**
```bash
# Detect process execution in container image
docker ps -a | grep -i debugger

# Inspect container filesystem for .udd/.dmp files
docker exec <container_id> find / -name "*.udd" -o -name "*.dmp"
```

---

## See Also

- [Immunity Debugger Source Evidence](../Immunity%20Debugger/03%20-%20Source%20Evidence.md) — complement with source-machine hunting.
- [mona.py Detection and Hunting](../mona.py/05%20-%20Detection%20and%20Hunting.md) — mona-specific signatures and behavioral indicators.
- **Windows/12 - Lateral Movement** — correlate exploit deployment with post-exploitation lateral movement.
- **Splunk/ELK/Sentinel query examples** — for enterprise-scale detection across multiple machines.
