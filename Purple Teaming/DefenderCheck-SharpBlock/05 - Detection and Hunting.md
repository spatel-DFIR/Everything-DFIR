# DefenderCheck-SharpBlock: Detection and Hunting

## Hunting Priority Matrix

Ranked by **detection invariance** — which signals survive which evasion techniques:

| Priority | Signal | Survives Inline Execution | Survives Injection | Survives Binary Rename | Survives Uninstall | Why |
|---|---|---|---|---|---|---|
| **1** | WMI query pattern (Win32_Product, Win32_Service) via non-System32 process | ❌ NO | ✅ YES | ✅ YES | ✅ YES | DefenderCheck *must* query WMI to function; inline/injected versions still execute the same queries. Binary rename does not affect query signatures. Uninstall doesn't matter—tool was already run. |
| **2** | Sysmon 1: DefenderCheck.exe / SharpBlock.exe child process (from cmd/powershell/beacon) | ❌ NO | ✅ YES | ❌ NO | ✅ YES | If tool is renamed (e.g., `system.exe`) OR injected, Sysmon 1 signal disappears. Injection bypasses this entirely. Only survives if operator does not avoid it. |
| **3** | AMSI.dll memory patching (byte signature in in-process memory) | ✅ YES | ✅ YES | ✅ YES | ❌ N/A | SharpBlock always patches AMSI the same way: function prologue rewrite (ret opcode, JMP pattern). Survives all evasion. Only defeated by not using SharpBlock at all. |
| **4** | Prefetch execution records (DefenderCheck.exe-*.pf, SharpBlock.exe-*.pf) | ❌ NO | ❌ NO | ❌ NO | ✅ YES | Prefetch keyed to binary name hash. Rename defeats this. Operator could disable Prefetch pre-deployment (rare). Once deleted, Prefetch recoverable only via forensic imaging. |
| **5** | Registry read pattern (HKLM\Software\...\Uninstall, Defender registry hives) | ❌ NO | ✅ YES | ✅ YES | ✅ YES | DefenderCheck *must* read these keys. Signature: non-System32 process accessing Uninstall registry shortly after process creation. Behavioral detection only (requires WMI-Activity + Object Access auditing, rarely enabled). |
| **6** | .NET Assembly metadata (PE headers, COFF timestamp, embedded strings) | ✅ YES | ✅ YES | ✅ YES | ✅ YES | If binary is recovered (disk, memory dump, wire capture), COFF/CLR metadata reveals it is DefenderCheck/SharpBlock. Static indicator; survives all execution methods. |

**Key Insight:** **Most process-level evasion (injection, renaming) defeats Sysmon-based detection**, but **WMI query patterns and AMSI memory patching are invariant**. Behavioral-based hunting is most reliable.

---

## Hunting on Source (Attacker's Machine)

### 1. PowerShell History — Command Execution on Operator's Machine

If DefenderCheck or SharpBlock were executed on the attacker's own machine (staging/testing), PowerShell command history captures them:

```powershell
# On attacker's machine (captured via forensic acquisition):
Get-Content (Get-PSReadlineOption).HistorySavePath

# Output might show:
C:\Users\attacker\Desktop> .\DefenderCheck.exe
C:\Users\attacker\Desktop> Invoke-Expression (Get-Content .\SharpBlock.cs); Patch-AMSI
```

**Hunt Command (on attacker's seized machine):**
```powershell
# Find PowerShell history with DefenderCheck / SharpBlock references
$historyPath = (Get-PSReadlineOption).HistorySavePath
Get-Content $historyPath | Select-String -Pattern "DefenderCheck|SharpBlock"

# Also check PSReadline history backup
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | `
    Select-String -Pattern "DefenderCheck|SharpBlock"
```

**Alternative:** Check Cobalt Strike/Sliver teamserver logs for beacon commands:
```bash
# On teamserver (Linux):
grep -r "DefenderCheck\|SharpBlock" ~/.cobaltstrike/logs/
grep -r "DefenderCheck\|SharpBlock" ~/.sliver/logs/
```

---

### 2. Web Server Access Logs — Tool Staging Downloads

If tools were staged via HTTP from an attacker-controlled server:

```bash
# On staging server (Apache):
tail -1000 /var/log/apache2/access.log | grep "DefenderCheck\|SharpBlock"

# Output:
203.0.113.45 - - [29/Aug/2026:14:23:15 +0000] "GET /tools/DefenderCheck.exe HTTP/1.1" 200 15360
203.0.113.45 - - [29/Aug/2026:14:24:02 +0000] "GET /tools/SharpBlock.exe HTTP/1.1" 200 18432
```

**Hunt Command:**
```bash
# Search for DefenderCheck / SharpBlock in all web server logs
grep -r "DefenderCheck\|SharpBlock" /var/log/apache2/ /var/log/nginx/ /var/log/httpd/
```

---

### 3. File System — Staging Artifacts on Attacker's Box

If attacker staged tools on their own machine before delivery:

```bash
# On attacker's machine (forensic acquisition):
find /home/attacker -name "*DefenderCheck*" -o -name "*SharpBlock*" 2>/dev/null

# Output:
/home/attacker/tools/DefenderCheck.exe
/home/attacker/tools/SharpBlock.cs
/home/attacker/.temp/SharpBlock.exe
```

**Hunt Command:**
```bash
# Recursive search across common staging directories
for dir in ~/tools ~/Desktop ~/Downloads ~/.temp; do
    find "$dir" -type f \( -name "*DefenderCheck*" -o -name "*SharpBlock*" \) 2>/dev/null
done

# Also check for recently-compiled .NET binaries in temp:
find /tmp -name "*.exe" -mtime -7 -type f | xargs file | grep "\.NET"
```

---

### 4. C2 Infrastructure Artifacts

If operator uses Cobalt Strike / Sliver:

```bash
# Search teamserver database/logs for tool delivery commands
cd ~/.cobaltstrike
grep -i "defendercheck\|sharpblock" *.log

# Extract beacon sessions and grep transcripts
ls logs/ | while read f; do grep -l "defendercheck\|sharpblock" "logs/$f"; done
```

**Dissect.cstrike (third-party Cobalt Strike parser):**
```bash
dissect.cstrike parse-sqlite ~/.cobaltstrike/teamserver.db | grep -i "defendercheck\|sharpblock"
```

---

## Hunting on Target (Compromised Endpoint)

### 1. Process Execution Logs — Sysmon & Security Events

Hunt for DefenderCheck / SharpBlock process creation on target systems:

```powershell
# On target machine (live or forensic):
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1
} | Where-Object { 
    $_.Properties[20].Value -match 'DefenderCheck|SharpBlock' -or
    $_.Properties[10].Value -match 'DefenderCheck|SharpBlock'
} | Select-Object TimeCreated, @{N='Image'; E={$_.Properties[20].Value}}, @{N='CmdLine'; E={$_.Properties[10].Value}}

# Or via cmdlet on Windows with event tracing:
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4688  # Process Creation
} | Where-Object {
    $_.Message -match 'DefenderCheck|SharpBlock'
}
```

**Expected Output (if tools were executed as separate processes):**
```
TimeCreated              Image                  CmdLine
-----------              -----                  -------
8/29/2026 2:16:05 PM    C:\Temp\DefenderCheck.exe    DefenderCheck.exe
8/29/2026 2:16:20 PM    C:\Temp\SharpBlock.exe       SharpBlock.exe
```

**Note:** If tools were injected into existing processes, you will see the parent process (cmd.exe, powershell.exe, beacon) but not the tool binary itself.

---

### 2. Prefetch Analysis — Execution Artifacts

Prefetch files survive process execution and deletion:

```powershell
# List prefetch entries for DefenderCheck / SharpBlock
Get-ChildItem C:\Windows\Prefetch\ | Where-Object {
    $_.Name -match 'DefenderCheck|SharpBlock'
}

# Output:
DEFENDERCHECK.EXE-A1B2C3D4.pf
SHARPBLOCK.EXE-E5F6G7H8.pf

# Extract last-run timestamp and execution count from prefetch (requires parsing):
# Use tools like Prefetch Parser (prefetchparse.exe) or Volatility Prefetch plugin
```

**Using Prefetch Parser (third-party tool):**
```bash
PrefetchParser.exe C:\Windows\Prefetch\DEFENDERCHECK.EXE-A1B2C3D4.pf

# Output includes:
# Last Execution: 2026-08-29 14:16:00 UTC
# Execution Count: 1
# DLL Dependencies: kernel32.dll, ntdll.dll, mscorlib.dll, System.Runtime.InteropServices.dll
```

---

### 3. WMI Event Logs — Query Patterns (If Enabled)

If WMI-Activity logging is enabled (rare):

```powershell
# Hunt for WMI queries from non-System32 processes
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-WMI-Activity/Operational'
    ID = 5860  # WMI consumer access
} | Where-Object {
    $_.Message -match 'Win32_Product|Win32_Service' -and
    $_.Properties[2].Value -notlike 'C:\Windows\System32\*'  # Exclude system processes
}
```

**Expected WMI Query Patterns:**
```
Query: SELECT * FROM Win32_Product WHERE Name LIKE '%Defender%'
Consumer: DefenderCheck.exe OR C2 beacon
Action: Reconnaissance
```

**Note:** Most organizations do **not** enable WMI-Activity auditing, so this signal is often unavailable.

---

### 4. Memory Analysis — AMSI Patching Signature

For SharpBlock, acquire process memory and scan for AMSI patches:

```bash
# Volatility 3: Check for patched amsi.dll in PowerShell processes
volatility3 -f memory.dmp windows.malfind | grep -i amsi

# Output:
pid: 4512 (powershell.exe)
Address: 0x7fff1234abcd
Found: ret (0xc3)  # AMSI patch signature
```

**YARA Rule for AMSI Patching:**
```yara
rule SharpBlock_AMSI_Patch {
    strings:
        $amsi_patch_1 = { C3 }  // ret opcode (immediate return from AmsiScanBuffer)
        $amsi_patch_2 = { EB FE }  // JMP $ (infinite loop, functionally a disable)
        $amsi_dll = "amsi" nocase
    condition:
        ($amsi_patch_1 or $amsi_patch_2) and $amsi_dll and in_file(0x400000, 0x7fffffff)
}
```

**Hunt Command (Volatility):**
```bash
volatility3 -f target.dmp windows.dlllist --pid <powershell_pid> | grep -i amsi
# If amsi.dll is listed but with modified pages, suspect SharpBlock
```

---

### 5. File System Artifacts

Search for staged DefenderCheck / SharpBlock binaries left on disk:

```powershell
# Find DefenderCheck / SharpBlock files in common staging locations
$stagingPaths = @(
    'C:\Temp\*',
    'C:\Windows\Temp\*',
    'C:\ProgramData\*',
    'C:\Users\*\AppData\Local\Temp\*'
)

foreach ($path in $stagingPaths) {
    Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -match 'DefenderCheck|SharpBlock' -or
        (Get-Content $_.FullName -Encoding Byte -TotalCount 2 -ErrorAction SilentlyContinue) -eq @(77, 90)  # MZ header
    }
}
```

**Hunt via MFT (if on compromised workstation with forensic tools):**
```bash
# Parse NTFS MFT to find DefenderCheck / SharpBlock entries
mftparser.exe C:\$MFT | grep -i "defendercheck\|sharpblock"
```

---

### 6. Behavioral Detection — Registry Access Patterns

Monitor for DefenderCheck's characteristic registry reads (requires behavioral EDR or Sysmon registry monitoring):

```powershell
# Hunt for processes accessing AV/EDR registry keys without being System32
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4663  # Object Access
} | Where-Object {
    $_.Message -match 'HKLM.*Uninstall' -or
    $_.Message -match 'HKLM.*Windows Defender' 
} | Where-Object {
    $_.Properties -notlike '*System32*'  # Non-system processes only
}
```

---

### 7. Live Endpoint Hunting — C2 Beacon Context

If suspicious beacon activity is observed (e.g., in Cobalt Strike teamserver logs), hunt the target endpoint:

```powershell
# On target machine during active compromise:

# Check running processes for C2 beacon + DefenderCheck/SharpBlock in same time window
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1
    StartTime = (Get-Date).AddHours(-1)  # Last hour
} | Where-Object {
    $_.Properties[20].Value -match 'cmd|powershell|beacon' -or
    $_.Properties[20].Value -match 'DefenderCheck|SharpBlock'
} | Sort-Object TimeCreated

# Check parent-child process relationships
Get-Process | Where-Object {
    $_.ProcessName -match 'cmd|powershell|beacon'
} | ForEach-Object {
    $parent = $_
    Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        ID = 1
    } | Where-Object {
        $_.Properties[11].Value -eq $parent.Id  # ParentProcessId
    }
}
```

---

## Hunting Command Examples

### PowerShell (Live Endpoint)

```powershell
# Comprehensive hunt for DefenderCheck / SharpBlock indicators
function Search-DefenderCheck-SharpBlock {
    param([string]$ComputerName = $env:COMPUTERNAME)
    
    Write-Host "Hunting on $ComputerName..." -ForegroundColor Yellow
    
    # 1. Sysmon Process Events
    Write-Host "[*] Searching Sysmon 1 (Process Creation)..."
    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterHashtable @{ID=1} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'DefenderCheck|SharpBlock' } |
        Select-Object TimeCreated, @{N='Image';E={$_.Properties[20].Value}}
    
    # 2. Prefetch Files
    Write-Host "[*] Searching Prefetch..."
    Get-ChildItem C:\Windows\Prefetch\ -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'DefenderCheck|SharpBlock' } |
        Select-Object Name, LastAccessTime
    
    # 3. File System Staging
    Write-Host "[*] Searching file system..."
    Get-ChildItem -Path 'C:\Temp\*', 'C:\Windows\Temp\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'DefenderCheck|SharpBlock' } |
        Select-Object FullName, CreationTime, LastWriteTime
}

Search-DefenderCheck-SharpBlock
```

### Bash / Linux (Target Endpoint via WMI, Impacket, etc.)

```bash
# Hunt via remote WMI query (from Linux attacker machine, for comparison):
python3 wmiexec.py DOMAIN/user:pass@TARGET 'Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | Where-Object {$_.Message -match "DefenderCheck|SharpBlock"} | Format-Table TimeCreated, @{N="Image";E={$_.Properties[20].Value}}'
```

### Splunk / SIEM Query

```spl
index=windows (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR source="WinEventLog:Security")
(EventCode=1 OR EventCode=4688)
(Image="*DefenderCheck*" OR Image="*SharpBlock*" OR CommandLine="*DefenderCheck*" OR CommandLine="*SharpBlock*")
| stats count, values(User), values(Image), values(ParentImage) by ComputerName
```

### YARA (File/Memory Scanning)

```yara
rule DefenderCheck_Binary {
    strings:
        $s1 = "DefenderCheck" nocase
        $s2 = "Win32_Product" nocase
        $s3 = "Win32_Service" nocase
        $pe = "MZ" at 0
    condition:
        $pe and 2 of ($s*)
}

rule SharpBlock_AMSI_Patch_Memory {
    strings:
        $amsi = "amsi" nocase
        $patch1 = { C3 }  // ret
        $patch2 = { E9 ?? ?? ?? ?? }  // jmp
    condition:
        $amsi and any of ($patch*)
}
```

---

## Detection Gaps & Limitations

| Scenario | Detection Gap | Why |
|----------|---|---|
| **In-process injection** (DefenderCheck/SharpBlock injected into existing PowerShell/beacon) | Sysmon 1 event only shows parent (PowerShell/beacon), not the tool | Requires advanced memory behavioral detection |
| **Binary rename** (DefenderCheck.exe → system.exe) | Sysmon 1 by name defeated | PE metadata / YARA rules still detect |
| **Prefetch disabled** | No Prefetch artifacts | Operator can disable via Group Policy pre-deployment (rare) |
| **WMI-Activity auditing disabled** | No WMI query logs | Default state on most systems |
| **Registry audit disabled** | No Object Access events | Requires non-default SACL configuration |
| **Memory overwritten** | AMSI patch no longer detectable | Operator runs AMSI bypass, then immediately clears memory / process terminates |

---

## Summary

**Most reliable hunting signals:**
1. **Sysmon 1 process creation** (DefenderCheck/SharpBlock child processes) — defeated by injection/rename
2. **Prefetch execution artifacts** — defeated by binary rename or Prefetch disable
3. **AMSI memory patching** (SharpBlock) — invariant; survives all evasion
4. **WMI query patterns** (DefenderCheck) — requires behavioral detection; defeated by living-off-the-land alternatives

**Recommendation:** Layer multiple detection methods (process-level + behavioral + memory-level) for defense-in-depth coverage. Most evasion methods succeed against *single* detection points but fail when multiple signals are correlated.

