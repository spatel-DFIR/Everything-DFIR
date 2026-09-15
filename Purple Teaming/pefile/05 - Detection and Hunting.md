# pefile — Detection and Hunting

---

## Hunting on Source (Operator's/Analyst's Machine)

All evidence of pefile usage lives on the **attacker's own machine**. A defender with access to the analyst's computer can comprehensively reconstruct their workflow.

---

### Hunt 1: Detect Python process execution with pefile scripts

**Priority: HIGH** — Process-level logging captures the analyst's intent directly.

#### Windows (Sysmon Event 1 or Event 4688)

```powershell
# Detect python.exe processes with script names suggesting binary analysis
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4688
} | Where-Object {
    $_.Properties[5].Value -match 'python' -and (
        $_.Properties[8].Value -match 'pefile|analyze|malware|extract|parse' -or
        $_.Properties[8].Value -match '\.py' 
    )
} | Format-Table TimeCreated, @{Name='User';Expression={$_.Properties[1].Value}}, @{Name='CommandLine';Expression={$_.Properties[8].Value}}

# Sysmon Event 1 variant (if Sysmon is deployed)
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} | Where-Object {
    $_.Properties[10].Value -match 'python' -and $_.Properties[20].Value -match '\.py'
} | Format-Table TimeCreated, @{Name='Image';Expression={$_.Properties[10].Value}}, @{Name='CommandLine';Expression={$_.Properties[20].Value}}
```

**What to look for:**

- Command line contains a `.py` filename (analyst's script)
- Script name is descriptive: `analyze_malware.py`, `extract_imports.py`, `packer_detect.py`
- Binary path in command line (e.g., `python.exe analyze.py C:\temp\malware.exe`)
- Multiple sequential Python invocations (suggesting batch analysis)

**Evasion resistance:** **Very high** — the command line is logged at the OS level and difficult to fake. Renaming python.exe to something innocuous doesn't change the underlying Image path in Sysmon/auditd, which remains detectable.

---

### Hunt 2: Detect pefile module import and usage

**Priority: MEDIUM** — Python module-level detection requires custom instrumentation but is reliable.

#### Linux/macOS (auditd rules)

```bash
# Audit pefile module access
sudo auditctl -w /usr/lib/python3.9/site-packages/pefile.py -p r -k pefile_usage

# Review audit logs
sudo ausearch -k pefile_usage
```

#### Windows (ETW Process Tracing)

```powershell
# Start ETW tracing for Python module loads (requires admin)
$session = New-EtwTraceSession -Name PythonModuleTrace
$provider = Get-EtwEventProvider -Name 'Python'
Add-EtwTraceProvider -Session $session -Provider $provider
Start-EtwTraceSession $session

# After Python execution, extract logs
Get-EtwTraceEvent -Session $session | Where-Object {
    $_.Message -match 'pefile' -or $_.Message -match '\.pyc'
}
```

**What to look for:**

- Import of `pefile` module in a Python process
- Load of `pefile.py` from site-packages or a local directory
- Creation of `.pyc` compiled bytecode (indicates module was imported)
- Access to `ordlookup/` (PEiD signature database)

**Evasion resistance:** **Medium** — ETW can be disabled or spoofed at runtime by a sophisticated operator, but the `.pyc` cache files are persistent on disk and hard to completely remove.

---

### Hunt 3: Detect `.pyc` bytecode cache files

**Priority: HIGH** — Bytecode caches persist on disk and are easy to find.

#### Windows (Filesystem scan)

```powershell
# Find all .pyc files in site-packages and user directories
Get-ChildItem -Path 'C:\Python3*\Lib\site-packages\__pycache__\pefile*.pyc' -Recurse -ErrorAction SilentlyContinue |
    Format-Table FullName, CreationTime, LastWriteTime

# User-level Python cache (often more relevant)
Get-ChildItem -Path "$env:APPDATA\Python\site-packages\__pycache__\pefile*.pyc" -Recurse -ErrorAction SilentlyContinue

# Local project cache (if pefile was used locally)
Get-ChildItem -Path '*\__pycache__\pefile*.pyc' -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime
```

#### Linux/macOS (Filesystem scan)

```bash
# Search for pefile .pyc files
find / -name "*pefile*.pyc" -type f 2>/dev/null

# Check site-packages
ls -la /usr/lib/python3.*/site-packages/__pycache__/pefile*.pyc 2>/dev/null
ls -la ~/.local/lib/python*/site-packages/__pycache__/pefile*.pyc 2>/dev/null
```

**What to look for:**

- `.pyc` files indicate Python module import (creation time = approximate time of first import)
- Presence in multiple site-packages versions suggests pefile was installed in multiple Python environments
- Bytecode can be decompiled via `uncompyle6` or `decompyle3` to recover pefile source (which is unlikely to be interesting, but confirms analyst activity)

**Evasion resistance:** **Very high** — `.pyc` files are created automatically by Python and survive cache-clearing attempts unless explicitly targeted.

---

### Hunt 4: Detect analysis script output files

**Priority: HIGH** — Output files directly reveal analyst methodology.

#### Windows (Filesystem scan for analysis output)

```powershell
# Look for JSON/CSV/text output files with analysis-related naming
Get-ChildItem -Path 'C:\temp\', "$env:USERPROFILE\Documents\", "$env:USERPROFILE\Downloads\" -Include '*analysis*', '*malware*', '*packer*', '*import*', '*export*', '*pe*' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.json', '.csv', '.txt', '.log' } |
    Format-Table FullName, CreationTime, LastWriteTime, Length

# Search for recently-created JSON/CSV files (within last 7 days)
Get-ChildItem -Path 'C:\*' -Include '*.json', '*.csv' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } |
    Format-Table FullName, LastWriteTime, Length | Head -50
```

#### Linux/macOS (Filesystem scan)

```bash
# Search for analysis output files
find $HOME -name '*analysis*' -o -name '*malware*' -o -name '*packer*' 2>/dev/null
find /tmp -name '*.json' -o -name '*.csv' -mtime -7 2>/dev/null

# Check $HOME/Desktop and Downloads
ls -la $HOME/Desktop/*.{json,csv,txt} 2>/dev/null
ls -la $HOME/Downloads/*.{json,csv,txt} 2>/dev/null
```

**What to look for:**

- Output files with names like `binary_analysis.json`, `packer_report.txt`, `imports_extracted.csv`
- File content reveals:
  - Which binaries were analyzed (full paths)
  - Findings: packer type, imports, exports, entry points
  - Analyst's tooling/methodology (which functions were called, what filters applied)
- Creation time correlates with Python process execution (from Hunt 1)

**Evasion resistance:** **Very high** — output files must exist for the analyst to review results. Deletion is easily detected via unallocated-space forensics.

---

### Hunt 5: Detect pefile installation via pip

**Priority: MEDIUM** — Package metadata reveals installation time and version.

#### Windows

```powershell
# Check pip installation metadata
Get-ChildItem -Path 'C:\Python3*\Lib\site-packages\pefile*.dist-info' -ErrorAction SilentlyContinue |
    Format-Table FullName, CreationTime

# Read pefile version
Get-Content 'C:\Python3*\Lib\site-packages\pefile*.dist-info\METADATA' -ErrorAction SilentlyContinue |
    Select-String 'Version|Author|License'

# Check user-level pip cache
Get-ChildItem -Path "$env:APPDATA\pip\*" -Recurse -ErrorAction SilentlyContinue
```

#### Linux/macOS

```bash
# Check pip-installed pefile metadata
ls -la /usr/lib/python3.*/site-packages/pefile*.dist-info/ 2>/dev/null
cat /usr/lib/python3.*/site-packages/pefile*.dist-info/METADATA 2>/dev/null

# User-level install
ls -la ~/.local/lib/python*/site-packages/pefile*.dist-info/ 2>/dev/null

# Check pip list
pip list | grep pefile
pip3 list | grep pefile
```

**What to look for:**

- `.dist-info/` directory presence and creation time (install time)
- `METADATA` file lists version (e.g., `2024.8.26`)
- `RECORD` file lists all installed files
- Install timestamp can be correlated with analysis script creation time

**Evasion resistance:** **High** — pip metadata is created at install time and requires deliberate cleanup to remove.

---

### Hunt 6: Correlate analyst activity timeline

**Priority: HIGH** — Reconstructs complete workflow via multiple signals.

#### Windows (Comprehensive timeline)

```powershell
# Build timeline: script creation → import → binary access → output generation

# 1. Find analysis scripts
$scripts = Get-ChildItem -Path 'C:\*' -Include '*analyze*.py', '*malware*.py', '*pefile*.py' -Recurse -ErrorAction SilentlyContinue

# 2. Find output files
$outputs = Get-ChildItem -Path 'C:\*' -Include '*.json', '*.csv' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -gt $scripts[0].CreationTime }

# 3. Get process creation events
$processes = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688 } -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[5].Value -match 'python' } |
    Sort-Object TimeCreated

# 4. Combine into timeline
$timeline = @(
    $scripts | ForEach-Object { [PSCustomObject]@{ Time = $_.CreationTime; Event = "Script created: $($_.Name)" } }
    $processes | ForEach-Object { [PSCustomObject]@{ Time = $_.TimeCreated; Event = "Python executed: $($_.Properties[8].Value)" } }
    $outputs | ForEach-Object { [PSCustomObject]@{ Time = $_.CreationTime; Event = "Output created: $($_.Name)" } }
) | Sort-Object Time

$timeline | Format-Table Time, Event
```

**What to look for:**

1. Script creation (`.py` file)
2. Python process execution (includes script name and binary arguments)
3. Binary file access (if logged)
4. Output file creation
5. Correlated timestamps suggest a single analysis session

**Timeline interpretation:**

- **Close timestamps:** Suggests real-time interactive analysis
- **Spread over hours/days:** Suggests batch or automated analysis
- **Multiple script executions on same binary:** Deep analysis, multiple passes

**Evasion resistance:** **Very high** — timeline reconstruction relies on multiple independent log sources ($MFT, event logs, process logs); spoofing all simultaneously is impractical.

---

### Hunt 7: Detect suspicious script content

**Priority: MEDIUM** — Code review reveals analyst methodology.

#### Windows/Linux (Script content analysis)

```bash
# Search for python scripts containing pefile imports and analysis patterns
grep -r "import pefile" . --include="*.py" 2>/dev/null
grep -r "PE(" . --include="*.py" 2>/dev/null
grep -r "DIRECTORY_ENTRY_IMPORT\|DIRECTORY_ENTRY_EXPORT\|match_expr" . --include="*.py" 2>/dev/null

# Look for high-value APIs called in scripts
grep -r "get_section_by_name\|get_data\|write(" . --include="*.py" 2>/dev/null
```

**What to look for:**

- Imports of pefile and supporting libraries (json, csv, hashlib, etc.)
- Specific API calls (e.g., `pe.DIRECTORY_ENTRY_IMPORT`, `pe.match_expr()`)
- Output redirection (file writes, JSON/CSV generation)
- Loop structures (suggesting bulk analysis)
- Custom analysis logic (revealing analyst expertise and intent)

**Evasion resistance:** **High** — source code is plain text and recovered even if compiled to `.pyc`.

---

### Hunt 8: Detect memory traces of analysis

**Priority: LOW** — Requires live-memory capture, but conclusive.

#### Live memory dump and analysis

```bash
# Capture memory of running Python process (Windows, requires WinDbg or similar)
# On Linux (requires root or sudo):
sudo gcore -o python_dump $(pgrep python3)

# Search memory dump for pefile module strings
strings python_dump | grep -i "pefile\|DIRECTORY_ENTRY"

# On Windows (using Volatility 3):
python vol3.py -f memory.dmp windows.pslist | grep python
python vol3.py -f memory.dmp windows.memmap --pid <python_pid> | grep pefile
```

**What to look for:**

- Loaded pefile module in process memory
- PE object state (parsed headers, sections)
- Analyzed binary names in memory
- Output data structures (JSON, lists of imports/exports)

**Evasion resistance:** **Very high** — live-memory captures are conclusive if available, but require:
- Compromised endpoint with memory-capture capability
- Or incident response team with forensic access (defender scenario)
- Not practical for proactive hunting on live systems

---

## Hunting on Target

**Target-side hunting is inapplicable** — pefile generates zero artifacts on victim machines. All evidence is on the analyst's own machine.

**Instead, hunt for:**

1. **Upstream binary origin:** How did the malware/payload reach the target? (Impacket, C2, phishing, etc.)
2. **Execution evidence:** If the binary was run, standard process/behavioral forensics apply
3. **Lateral movement:** If pefile analysis was part of a larger campaign, look for the command-and-control or exfiltration infrastructure

See the relevant attack-path tool's own sections (e.g., `Impacket/psexec/ 04 - Target Evidence` for how the initial payload reached the target).

---

## Hunting Priority Table

Ranked by evasion survivability — which signals remain detectable even if the operator attempts to cover tracks.

| Rank | Signal | Survives Cleanup | Notes |
|---|---|---|---|
| 1 | Output files (JSON/CSV/text analysis results) | Partially (unallocated space) | Content directly reveals analyzed binaries and findings; deletion leaves traces in $MFT/$USN Journal |
| 2 | Process-level logs (4688, Sysmon 1) | Depends on log archival | Command line includes script name and binary arguments; Windows log archival makes this persistent |
| 3 | `.pyc` bytecode cache files | Yes (explicit deletion required) | Automatically created, decompilable, timestamp survives typical cleanup |
| 4 | $MFT/$USN Journal (script/output file access) | Depends on filesystem operations | Immutable on live NTFS; can be edited offline but recoverable from forensic images |
| 5 | pip metadata (`.dist-info/`) | Partially (requires full uninstall) | Installation timestamp and version metadata are granular; persist across pip cache clears |
| 6 | File association registry (Windows) | Partial | Script association with Python survives typical cleanup |
| 7 | ETW/auditd module-load logs | Yes (if archived) | Can be disabled by administrator, but if persisted, conclusive |
| 8 | Live-memory forensics | No | Volatile; lost on process exit/reboot; requires contemporary capture |

**For defenders:** Focus on Ranks 1–4 (persistent disk artifacts). Ranks 5–7 provide corroboration. Rank 8 is only available during active incident response.

---

## Detection Evasion Strategies (Red Team Perspective)

An operator aware of detection can attempt these mitigations:

| Evasion | Detectability |
|---|---|
| Rename python.exe | **Defeated:** Sysmon/4688 logs the *real* image path, not the on-disk name |
| Delete script files | **Partly defeated:** Unallocated-space recovery, $USN Journal, backup logs |
| Delete output files | **Partly defeated:** Same as above; forensic imaging recovers unallocated clusters |
| Disable command-line logging | **Defeated (mostly):** Requires admin, disables across all processes, and alerts defenders; Sysmon can still log via Process Creation rules |
| Clear .pyc cache | **Defeated (partially):** Re-importing pefile recreates `.pyc` files; historical `.pyc` files may persist in backups |
| Use Python virtual environment | **No evasion value:** Pip install still creates metadata; Python path still logged in command line |
| Embed pefile in compiled binary (PyInstaller, etc.) | **Partially effective:** Removes dependency on site-packages, but process-level logging and output files remain; no practical evasion of command line/output signals |

**Conclusion:** pefile analysis is difficult to hide if the operator must use standard Python tooling and must write analysis results to disk. The primary evasion is **operational security** (analyzing on an isolated system, using encrypted storage for output, careful cleanup) rather than tool-level obfuscation.

---

## Defensive Recommendations

For **blue teams** defending against pefile-based reconnaissance:

1. **Monitor Python process creation** — detect descriptive script names and binary arguments via SIEM
2. **Collect command-line logging** — ensure 4688 audit logging is enabled; ingest into SIEM
3. **Preserve .pyc cache files** — periodically collect and inventory `.pyc` files as proof of module usage
4. **Monitor for analysis output** — detect files with analysis-related names (JSON/CSV with binary metadata)
5. **Archive logs** — long-term retention of Sysmon, Event Logs, and filesystem audit to enable retrospective timeline reconstruction
6. **Credential isolation** — assume any analyst machine may have pefile installed; treat those machines as analysis sandboxes with restricted network access

---

