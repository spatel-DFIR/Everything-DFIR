# mona.py — Detection and Hunting

## Hunting Priority Table

| Signal | Survival vs. Evasion | Reliability | Notes |
|---|---|---|---|
| **mona.py plugin file presence** | Survives all evasion | High | File on source disk; indicates exploit-dev setup |
| **mona_*.txt output files** | Survives all evasion | High | Direct artifacts of mona command execution; timeline correlation to exploit |
| **mona_chain.py (ROP chain)** | Low (reusable across targets, but binary-specific) | High | Smoking gun for ROP chain development; python code for exploit |
| **mona_gadgets.txt** | Low (gadgets are target/version-specific) | High | Lists ROP gadgets; used to build chain |
| **mona_pattern.txt** | Low (unique per crash, not reusable) | Medium | Pattern used for crash finding; correlates to exploit development stage |
| **mona commands in PowerShell history** | Survives all evasion | High | Literal `!mona` command text in shell history |
| **mona commands in .udd project file** | Low (binary format, must extract) | Medium | Immunity Debugger session metadata; requires parsing |
| **Debugger64.exe process + mona plugin loaded** | Survives all evasion | Medium | Process name visible, but requires memory inspection to confirm mona is loaded |
| **mona-generated ROP chain on target** | Very low (chain is generic, deployed binary is custom) | Low-Medium | Target shows ROP-chain structure; not distinctive to mona.py specifically |
| **Target: Badchar-free shellcode** | Low (easily re-generated without mona) | Low | Suggests badchar analysis was done; could be mona.py or another tool |

---

## Hunting on Source Machine

Detecting **mona.py plugin usage and exploit-development activity** on the attacker's workstation.

### mona.py Plugin Presence

**Direct File Search:**

```powershell
# Find mona.py installation
Get-ChildItem -Path "$env:APPDATA\Immunity Inc\Debugger\PyCommands" -Filter "mona.py" -Recurse

# If found, check timestamps
$monaPath = "$env:APPDATA\Immunity Inc\Debugger\PyCommands\mona.py"
if (Test-Path $monaPath) {
    Get-Item $monaPath | Select-Object FullName, CreationTime, LastWriteTime, Length
}
```

**Expected Result:**
```
FullName: C:\Users\<user>\AppData\Roaming\Immunity Inc\Debugger\PyCommands\mona.py
CreationTime: 2026-08-01 10:30:45
LastWriteTime: 2026-08-01 10:30:45
Length: 87234 bytes
```

---

### mona.py Output Files (.txt, .py)

**Recursive File Search for mona-Generated Files:**

```powershell
# Search for mona output files (working directory typically where Debugger64.exe was run)
$searchPaths = @(
    "$env:USERPROFILE\Desktop",
    "$env:USERPROFILE\Documents",
    "$env:USERPROFILE\Downloads",
    "$env:APPDATA\Immunity Inc",
    "$env:TEMP"
)

foreach ($path in $searchPaths) {
    if (Test-Path $path) {
        Get-ChildItem -Path $path -Filter "mona_*" -Recurse -ErrorAction SilentlyContinue |
            Select-Object FullPath, CreationTime, LastWriteTime, Length, Name
    }
}
```

**Common mona Output Files:**
- `mona_pattern.txt` (crash pattern for offset finding)
- `mona_gadgets.txt` (ROP gadget list)
- `mona_chain.py` (generated ROP chain Python code)
- `mona_crash_analysis.txt` (crash classification report)
- `mona_badchars.txt` (badchar analysis results)
- `mona_seh.txt` (SEH chain inspection results)
- `mona_modules.txt` (loaded modules list)

**Example Detection Result:**
```
FullPath: C:\Users\alice\Desktop\mona_gadgets.txt
CreationTime: 2026-08-11 14:40:22
LastWriteTime: 2026-08-11 14:40:22
Length: 45678 bytes

FullPath: C:\Users\alice\Desktop\mona_chain.py
CreationTime: 2026-08-11 14:45:30
LastWriteTime: 2026-08-11 14:45:30
Length: 2345 bytes
```

---

### Timeline Correlation: mona Commands to File Creation

```powershell
# Correlate mona_*.txt file creation times to exploit development timeline

$monaFiles = Get-ChildItem -Path $searchPaths -Filter "mona_*" -Recurse
$sortedByTime = $monaFiles | Sort-Object CreationTime

# Display timeline
$sortedByTime | ForEach-Object {
    Write-Host "$($_.CreationTime) - $($_.Name)"
}

# Example output:
# 08/11/2026 14:30:00 - mona_pattern.txt      (step 1: pattern generated)
# 08/11/2026 14:35:00 - mona_crash_analysis.txt (step 2: crash analyzed)
# 08/11/2026 14:40:00 - mona_gadgets.txt      (step 3: gadgets searched)
# 08/11/2026 14:45:00 - mona_chain.py         (step 4: chain generated)
# 08/11/2026 15:00:00 - exploit.exe           (step 5: exploit compiled)
```

---

### mona Commands in .udd Project Files

**.udd files are Immunity Debugger session files (binary format).**

```bash
# Extract text strings from .udd file to find mona commands
strings <project>.udd | grep -i "mona\|pattern\|gadget\|rop"

# Example output:
# !mona pattern_create -l 1000
# !mona analyze
# !mona rop --chain call esp
# !mona badchars -b "\x00\x0A"
```

**Forensic Value:**
- Strings search may reveal the exact mona commands executed during the session.
- Timestamps of .udd modifications correlate to exploit-development phases.

---

### mona Commands in PowerShell/Shell History

**PowerShell History File Search:**

```powershell
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

if (Test-Path $historyPath) {
    Get-Content $historyPath | Select-String "mona|Debugger64|pattern|gadget"
}
```

**Expected Result:**
```
C:\Program Files\Immunity Inc\Debugger\Debugger64.exe C:\path\to\vulnerable.exe
[in-debugger PyCommand console: !mona pattern_create -l 1000]
[in-debugger PyCommand console: !mona analyze]
...
```

**Note:** PyCommand console commands (those starting with `!mona`) are not automatically logged to PowerShell history; they're internal to Immunity Debugger unless the operator manually copies/saves them.

---

### Immunity Debugger Process & Module Loading

**Confirm mona.py Plugin Load:**

```powershell
# Use Sysmon or WMI to inspect loaded modules in running Debugger64.exe
# This requires Sysmon Event 7 (Image Load) or Live Process Inspection

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterHashtable @{
    EventID = 7  # Image Load
    Image = "*Debugger64.exe*"
} | Where-Object {
    $_.Properties[3].Value -match "mona|python"  # Look for Python module or mona load
} | Select-Object TimeCreated, Image, ImageLoaded
```

---

## Hunting on Target Machine

Target machines do **not** have mona.py installed, so there's no direct mona.py artifact to hunt. However, the **exploit artifacts** (which mona.py helped develop) ARE visible.

### Detecting ROP Chain Execution

**Memory-Based Detection:**

```powershell
# If a crash dump is available, analyze for ROP gadget patterns
# Strings containing xchg, pop, call, ret opcodes in sequence

# Use Volatility:
volatility3 -f crash.dmp windows.strings | grep -E "\\x(5[B-F]|FF|C3|E8|E9)"
# Look for byte patterns indicating gadgets (pop, ret, call, jmp instructions)
```

**Event Log Detection (If Crash Occurred):**

```powershell
# Search for crash events with stack corruption indicators
Get-WinEvent -LogName "Application" -FilterHashtable @{
    EventID = 1001
    Source = "Windows Error Reporting"
} | Where-Object {
    $_.Message -match "Stack|Heap|ROP|Gadget|Corruption"
} | Select-Object TimeCreated, Message
```

---

### Detecting Badchar-Aware Shellcode

**Signature-Based Detection (YARA):**

```yara
rule mona_badchar_aware_shellcode {
    description = "Badchar-aware shellcode (likely from mona.py badchars analysis)"
    strings:
        // Shellcode that avoids common badchars (0x00, 0x0A, 0x0D)
        // Typically uses encoding/XOR to obfuscate
        $encoded_shellcode = { 
            66 81 CA FF 0F     // or    edx, 0x0FFF (part of egg-hunter stub)
            42                 // inc   edx
            52                 // push  edx
        }
        // Look for extended ASCII ranges (128-255) suggesting XOR encoding
        $high_bytes = /[\x80-\xFF]{8,}/
    condition:
        any of them
}
```

**Practical Detection:**
- Badchar-free shellcode is indistinguishable from carefully hand-crafted shellcode.
- No mona-specific indicator is visible.

---

### Fleet-Wide Sweep: Exploit Development Indicators

**Enterprise-Wide Hunt (Centralized Logging):**

```splunk
# Splunk query for mona-generated artifacts across domain
index="sysmon" EventCode=11 FileName IN ("mona_*.txt", "mona_*.py", "mona_*.asm")
| stats count by host, FileName, TimeCreated
| where count > 0
```

```kusto
# Azure Sentinel / KQL for mona output files
DeviceFileEvents
| where FileName has "mona_" and FileName endswith (".txt", ".py")
| summarize by DeviceName, FileName, Timestamp
```

---

## Remediation & Evidence Collection

### Before Terminating Investigation

1. **Preserve mona Output Files:**
   ```powershell
   Copy-Item -Path "C:\Users\*\Desktop\mona_*" -Destination "E:\Forensics\mona_artifacts\" -Recurse
   Copy-Item -Path "C:\Users\*\AppData\Roaming\Immunity Inc" -Destination "E:\Forensics\immunity_config\" -Recurse
   ```

2. **Extract Strings from .udd Files:**
   ```bash
   for file in $(find /Users -name "*.udd"); do
       echo "=== $file ===" >> mona_udd_strings.txt
       strings "$file" >> mona_udd_strings.txt
   done
   ```

3. **Collect Immunity Debugger Configuration:**
   ```powershell
   reg export "HKCU\Software\Immunity Inc\Debugger" "immunity_debugger_registry.reg"
   ```

### Timeline Reconstruction

1. **Correlate File Timestamps:**
   - mona_pattern.txt created → T-1h (pattern generated)
   - mona_gadgets.txt created → T-45m (gadgets searched)
   - mona_chain.py created → T-30m (chain generated)
   - exploit.exe created → T-15m (exploit built)
   - Exploit deployed on target → T0 (deployment time)

2. **Cross-Reference with Target Timeline:**
   - Does target show evidence of exploitation at T0?
   - If yes, source machine's mona_*.txt timeline directly correlates to exploit development.

3. **Attribute Determination:**
   - Identify user who ran Debugger64.exe and mona commands.
   - Check if user is a known penetration tester (for testing/authorized) or unknown (incident).

---

## Distinguishing Authorized Exploit Development from Malicious Use

### Authorized Context (Red Team / Penetration Test)

- **Pre-Engagement:** Explicit scope document authorizing exploit development.
- **Source Machine:** Dedicated red-team lab machine (isolated, not on enterprise network).
- **Timeline:** Exploit development confined to agreed-upon testing window.
- **Artifacts:** Well-organized mona output, clear project documentation.

### Malicious Context (Attacker)

- **No Authorization:** No scope document; adversary has unauthorized access.
- **Source Machine:** Attacker's own machine (outside org control); may be compromised third-party system.
- **Timeline:** Exploit development may span days/weeks; time-of-attack is sudden.
- **Artifacts:** mona files scattered, minimal organization; evidence may be staged for exfiltration.

**Detection Strategy:**
1. Correlate mona artifact creation timeline to incident start time.
2. Verify whether source machine is known/controlled by organization.
3. Check if exploit-dev activity was pre-approved and in scope.

---

## Summary: Detecting mona.py Activity

| Activity | Detection Method | Reliability |
|---|---|---|
| **mona.py installed** | File search for `mona.py` in plugins folder | High |
| **mona.py recently used** | Timestamps on mona_*.txt output files | High |
| **Specific mona command executed** | String search in .udd file or PowerShell history | Medium-High |
| **Exploit development phase** | Timeline correlation of mona_pattern.txt → mona_chain.py creation | High |
| **Source machine identified** | File paths, user context, machine registration | High |
| **mona.py evasion attempt detected** | Custom badchar lists, obfuscated ROP chains | Low (evasion is subtle) |

---

## See Also

- [Immunity Debugger Detection and Hunting](../Immunity%20Debugger/05%20-%20Detection%20and%20Hunting.md) — complement with Immunity Debugger process/plugin detection.
- [mona.py Source Evidence](../mona.py/03%20-%20Source%20Evidence.md) — artifact types and locations.
- **Windows/12 - Lateral Movement** — post-exploitation activity detection.
- **Volatility Memory Analysis** — crash dump and live memory inspection techniques.
- **YARA/Sigma Rules** — custom detection rules for shellcode patterns and ROP chains.
