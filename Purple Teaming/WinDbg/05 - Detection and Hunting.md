# WinDbg — Detection and Hunting

## Hunting Priority Table

WinDbg presents a asymmetric detection profile: **TTD recording (most common operator workflow) leaves no target-side artifacts**, while **live debugging (less common) is moderately easy to detect**. Remote debugging is rare and highly visible.

| Signal | Strength | TTD? | Live Debug? | Remote? | Evasion Resistance |
|---|---|---|---|---|---|
| **TTD trace files (`.run`, `.idx`) on source host** | 🔴 Critical | YES | Partial | YES | **Very High** (requires filesystem access to attacker's host) |
| **WinDbg process creation (Sysmon 1)** | 🟡 Medium | YES | YES | YES | Low (process name not spoofable without binary rename) |
| **Process handle open for debug access (Sysmon 10, target)** | 🟡 Medium | NO | YES | NO | Medium (only live debugging; TTD has no target-side handle) |
| **Unusual parent-child process tree** | 🟠 Low | Varies | YES | NO | Medium (can be obscured by spawning process differently) |
| **Remote debugging network connection (TCP on debug port)** | 🔴 Critical | NO | NO | YES | Low (port-based detection) |
| **Shell history containing `windbg.exe` invocation** | 🟡 Medium | YES | YES | YES | High (can be cleared, but may be logged in log aggregation) |
| **Crash dump files alongside TTD traces** | 🟡 Medium | YES (if crash occurs) | YES | YES | High (requires filesystem correlation) |
| **PDB symbol files for target binary** | 🟠 Low | YES | YES | YES | High (could be legitimate development) |

---

## Hunting on Source (Attacker's Host)

### Search for TTD trace files

**Goal:** Detect evidence of TTD recording for exploit development or crash analysis.

```powershell
# PowerShell: Find all .run and .idx files (TTD traces)
Get-ChildItem -Path "C:\Users" -Filter "*.run" -Recurse -Force | 
    Select-Object FullName, @{Name='SizeMB'; Expression={$_.Length / 1MB -as [int]}} | 
    Format-Table -AutoSize

Get-ChildItem -Path "C:\Users" -Filter "*.idx" -Recurse -Force | 
    Select-Object FullName, @{Name='SizeMB'; Expression={$_.Length / 1MB -as [int]}} | 
    Format-Table -AutoSize

# Check modification times (were they created recently? during suspected attack window?)
Get-ChildItem -Filter "*.run" -Recurse -Force | 
    Where-Object { $_.LastWriteTime -gt '2026-08-10' -and $_.LastWriteTime -lt '2026-08-12' } |
    Select-Object FullName, LastWriteTime

# Bulk search across entire filesystem (if full volume scan is feasible)
Get-ChildItem -Path "C:\" -Filter "*.run" -Recurse -Force -ErrorAction SilentlyContinue | 
    Measure-Object -Property Length -Sum

# Search $TEMP directories (TTD default location alternative)
Get-ChildItem -Path "$env:TEMP" -Filter "*.run" -Recurse | Select-Object FullName, Length
```

**Indicator interpretation:**
- ✅ **`.run` file >100 MB**: High confidence of TTD recording (normal crash dumps are typically 1-50 MB)
- ✅ **`.run` + `.idx` pair**: Confirms completed recording (index built after recording ended)
- ✅ **Modification time within attack window**: Timeline correlation

### Search for WinDbg process history

**Goal:** Detect WinDbg execution on the attacker's host.

```powershell
# Sysmon: Find all WinDbg process creation events
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1
} | Where-Object { $_.Message -match 'windbg|WinDbgX' } |
    Select-Object TimeCreated, @{N='CommandLine'; E={$_.Message}} |
    Format-Table -AutoSize -Wrap

# Windows Security: Process creation events (if cmd audit enabled)
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=4688
} | Where-Object { $_.Message -match 'windbg' } |
    Select-Object TimeCreated, Message

# Search PowerShell history
Select-String "windbg" "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | 
    Select-Object Line, @{N='File'; E={$_.Filename}}

# Alternative: Search cmd history (if available)
Get-Content "$env:APPDATA\Microsoft\Windows\cmd\history.txt" -ErrorAction SilentlyContinue | 
    Select-String "windbg"
```

**Indicator interpretation:**
- ✅ **`windbg.exe -record` or `windbg.exe -replay`**: Direct TTD usage
- ✅ **`windbg.exe -p <PID>` or `windbg.exe -dump <file>`**: Live debugging or crash analysis
- ✅ **Timestamps correlating with suspected attack**: Timeline match

### Search for crash dump files

**Goal:** Detect manual dump generation (sign of deliberate analysis).

```powershell
# Find all .dmp files
Get-ChildItem -Path "C:\Users" -Filter "*.dmp" -Recurse |
    Select-Object FullName, @{N='SizeMB'; E={$_.Length / 1MB -as [int]}}, LastWriteTime

# Check Windows' default minidump directory
Get-ChildItem -Path "C:\Windows\Minidump" -Filter "*.dmp" |
    Select-Object FullName, Length, LastWriteTime

# Find large .dmp files (full dumps are typically >100 MB)
Get-ChildItem -Filter "*.dmp" -Recurse -Force | 
    Where-Object { $_.Length -gt 100MB } |
    Select-Object FullName, @{N='SizeMB'; E={$_.Length / 1MB -as [int]}}

# Correlate with TTD traces: .dmp and .run files created within minutes of each other
$dumpFiles = Get-ChildItem -Filter "*.dmp" -Recurse -Force
$traceFiles = Get-ChildItem -Filter "*.run" -Recurse -Force
$dumpFiles | ForEach-Object {
    $dump = $_
    $traceFiles | Where-Object { 
        [Math]::Abs(($dump.LastWriteTime - $_.LastWriteTime).TotalMinutes) -lt 5
    } | Select-Object @{N='DumpFile'; E={$dump.FullName}}, 
                       @{N='TraceFile'; E={$_.FullName}},
                       @{N='TimeDiffSec'; E={[Math]::Abs(($dump.LastWriteTime - $_.LastWriteTime).TotalSeconds)}}
}
```

**Indicator interpretation:**
- ✅ **Manually-created `.dmp` (not in `C:\Windows\Minidump\` or in rare locations)**: Deliberate dump generation
- ✅ **`.dmp` + `.run` correlation**: Operator was analyzing a specific crash

### Search for PDB symbol files

**Goal:** Detect downloaded symbols for a target binary (sign of reverse engineering).

```powershell
# Find .pdb files (symbol files)
Get-ChildItem -Path "C:\Users" -Filter "*.pdb" -Recurse -Force |
    Select-Object FullName, LastWriteTime

# Check default symbol cache (if configured)
Get-ChildItem -Path "C:\Symbols" -Filter "*.pdb" -Recurse -ErrorAction SilentlyContinue

# Check user's custom symbol cache (look in .dbgrc or registry)
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Debugger" /s | 
    findstr /i "symbol path"

# Search for symbol server URLs in files (indicate symbol fetching)
Get-ChildItem -Filter ".dbgrc" -Recurse -Force | 
    ForEach-Object { 
        Select-String "msdl|symbols|symsrv" $_.FullName
    }
```

**Indicator interpretation:**
- ✅ **`.pdb` for a known vulnerability or proprietary binary**: Sign of targeted reverse engineering
- ✅ **`.pdb` with recent modification time**: Active symbol fetching during attack window

### Search shell history

**Goal:** Detect command-line invocations of WinDbg in shell history.

```powershell
# PowerShell history
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Get-Content $historyPath | Select-String "windbg" -Context 2
}

# cmd history (if available)
$cmdHistoryPath = "$env:APPDATA\Microsoft\Windows\cmd\history.txt"
if (Test-Path $cmdHistoryPath) {
    Get-Content $cmdHistoryPath | Select-String "windbg"
}

# Check for cleared history markers (unusual activity)
# (History files deleted/modified at odd times)
```

**Indicator interpretation:**
- ✅ **`windbg -record`**: TTD recording invocation
- ✅ **`windbg -p` or `-dump`**: Live debugging or crash analysis
- ✅ **`windbg -remote`**: Remote debugging (high-risk activity)

---

## Hunting on Target (Victim's Host)

### Detect WinDbg attachment (Sysmon Event 10)

**Goal:** Detect live debugging attempts on the target host.

```powershell
# Sysmon Event 10: Process Access with debug privileges
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10
} | Where-Object { 
    $_.Message -match 'windbg|WinDbgX|GrantedAccess.*0x1fffff|0x0410' 
} | Select-Object TimeCreated, @{N='Message'; E={$_.Message}} |
    Format-Table -AutoSize -Wrap

# Filter specifically for debug access mask (0x1fffff = all access, 0x0410 = specific debug access)
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=10
} | ForEach-Object {
    if ($_.Message -match 'GrantedAccess: 0x(?:1fffff|0410)') {
        $_
    }
} | Select-Object TimeCreated, Message
```

**Indicator interpretation:**
- 🔴 **Sysmon 10: `windbg.exe` accessing another process with `0x1fffff` or `0x0410`**: Debugger attachment
- 🟡 **`0x0410` (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`)**: Could be profiler or legitimate debugging
- ⚠️ **Multiple Sysmon 10 events from same source within seconds**: Possible brute-force process attach attempts

### Detect remote debugging listener

**Goal:** Detect a debug server listening on the target host.

```powershell
# Find listening ports that might be debugging servers
Get-NetTCPConnection -State Listen | 
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Where-Object { 
        # Common debug ports (default 5005, but operator-configurable)
        $_.LocalPort -in 5005, 5006, 5007, 9000, 9999
    }

# Specific check for port 5005 (default WinDbg remote debug port)
netstat -ano | findstr :5005

# Check process listening on suspicious ports
Get-Process | Where-Object { 
    $proc = $_
    (Get-NetTCPConnection -ErrorAction SilentlyContinue | 
        Where-Object { $_.OwningProcess -eq $proc.Id -and $_.State -eq 'Listen' }).Count -gt 0
} | Select-Object Name, Id
```

**Indicator interpretation:**
- 🔴 **Process listening on port 5005 (or other debug port) that is NOT the system debugger**: Possible debug server
- 🟠 **`windbg.exe` or unknown process listening**: High suspicion of remote debugging

### Detect crash dump generation

**Goal:** Find manually-created crash dumps on the target.

```powershell
# Check Windows' minidump directory for recent dumps
Get-ChildItem -Path "C:\Windows\Minidump" -Filter "*.dmp" |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-1) } |
    Select-Object FullName, LastWriteTime, @{N='SizeMB'; E={$_.Length / 1MB -as [int]}}

# Search alternative dump locations (user temp, desktop, documents)
Get-ChildItem -Path @("C:\Users\*\AppData\Local\Temp", "C:\Users\*\Desktop", "C:\Users\*\Documents") `
    -Filter "*.dmp" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Correlate with Sysmon 1: ProcDump or other dump-generation tool spawning
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1
} | Where-Object { $_.Message -match 'procdump|userdump|DumpChk' } |
    Select-Object TimeCreated, Message
```

**Indicator interpretation:**
- 🟠 **`.dmp` in non-standard location (not `C:\Windows\Minidump\`)**: Manual dump generation
- 🔴 **Sysmon 1: `procdump.exe -ma` or similar memory-dump command**: Intentional memory capture
- ⚠️ **Recent crash dumps correlating with suspected intrusion**: Timeline match

### Detect process parent-child anomaly (debugger as parent)

**Goal:** Identify processes launched by WinDbg.

```powershell
# Get current process tree showing windbg.exe as parent
Get-WmiObject Win32_Process | Where-Object { 
    $proc = Get-WmiObject Win32_Process -Filter "ProcessId=$($_.ParentProcessId)"
    $proc.Name -match 'windbg'
} | Select-Object Name, ProcessId, @{N='ParentName'; E={
    (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name
}}

# Sysmon: Historical view of process creation with debugger parent
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1
} | Where-Object { $_.Message -match 'ParentImage.*windbg' } |
    Select-Object TimeCreated, Message
```

**Indicator interpretation:**
- 🟡 **`windbg.exe` as parent of a target process**: Debugger launched the process (debugging scenario)
- ⚠️ **Multiple children under `windbg.exe`**: Possible fuzzing or payload testing

### Detect kernel debugging setup

**Goal:** Check if kernel debugging has been enabled (attacker preparing for kernel-level analysis).

```powershell
# Check if kernel debugging is enabled via bcdedit
bcdedit | findstr /i "debug"

# Query registry directly (may be more forensically sound)
reg query "HKLM\BCD00000000" | findstr /i "debug"

# Check for debug boot flag
reg query "HKLM\BCD00000000" /v "debugtype"
reg query "HKLM\BCD00000000" /v "debugport"

# Historical: check System event log for kernel debug boot attempts
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=7040  # Service status changed
} | Where-Object { $_.Message -match 'debug' }
```

**Indicator interpretation:**
- 🔴 **`bcdedit /debug on` or registry showing `debugtype=Serial/USB/Network`**: Kernel debugging explicitly enabled
- ⚠️ **Debug boot flag set**: Attacker is preparing for kernel-level introspection (advanced capability)

---

## Remediation & Evidence Preservation

### Before acting on detection

**Critical:** Do NOT immediately shut down or clear artifacts if WinDbg use is detected.

```powershell
# 1. Capture TTD trace files (if they exist on attacker's host — requires forensic access)
# DO NOT rely on hash-based matching; TTD traces are deterministic but not byte-identical 
# across systems. Capture the full .run and .idx files.

# 2. Capture memory dump files
Copy-Item -Path "C:\Windows\Minidump\*.dmp" -Destination "E:\Forensics\minidumps\"

# 3. Export Sysmon logs (Process Creation, Process Access, Network Connection events)
wevtutil epl "Microsoft-Windows-Sysmon/Operational" "E:\Forensics\Sysmon_Operational.evtx"

# 4. Export System and Security event logs
wevtutil epl "System" "E:\Forensics\System.evtx"
wevtutil epl "Security" "E:\Forensics\Security.evtx"

# 5. Capture live memory (if feasible, using safe dump tool like Comae DumpIt or win64dd)
# (Full memory dump for later analysis in Volatility, etc.)

# 6. Preserve shell history
Copy-Item -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" `
    -Destination "E:\Forensics\powershell_history.txt"
```

### Isolate and respond

```powershell
# 1. Isolate the host (network disconnection if feasible, or modify firewall rules)
# (Stop further exfiltration of TTD traces or other data)

# 2. Suspend the WinDbg process (if running)
Stop-Process -Name windbg -Force -ErrorAction SilentlyContinue

# 3. Do NOT delete TTD files immediately; preserve them as evidence
# (They will be key artifacts in post-incident analysis)

# 4. Restart the system in a controlled manner to capture crash dump if active debugging caused instability
```

---

## Evasion Considerations

### What TTD recording does NOT leave behind (on target)

- ❌ No network traffic (if recording locally)
- ❌ No child processes or service creation
- ❌ No registry modifications
- ❌ No debugger process attachment (recording is read-only, post-process)
- ❌ No parent-child relationship to debugger

**Implication:** TTD is **functionally undetectable** on the target host if the attacker records locally and doesn't exfiltrate the traces.

### What operators must do to be detected

1. **Exfiltrate TTD traces** — requires network traffic (SMB, HTTPS, etc.), which is detectable
2. **Use live debugging** — requires debugger attachment, creating Sysmon/WMI artifacts
3. **Use remote debugging** — requires listening port on target, highly detectable
4. **Leave crash dumps behind** — evidence of manual dump generation

### Operator best practices (to evade detection)

- ✅ Record and analyze locally (TTD on attacker's host, never on target)
- ✅ Exfiltrate traces over encrypted channels (HTTPS, TLS, VPN) to avoid content-inspection detection
- ✅ Delete local TTD traces after analysis (if not needed for report)
- ✅ Avoid live debugging on target (use local recording + offline replay instead)
- ✅ Avoid remote debugging (high visibility)
- ✅ If crash dumps must be collected, use legitimate tools that blend in (Windows' built-in crash dump service, rather than obvious ProcDump execution)

