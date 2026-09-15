# PrintSpoofer — Detection and Hunting

## Hunting Priority table

| Signal | Evasion Survivability | Prevalence | Rank |
|---|---|---|---|
| **spoolsv.exe spawning interactive child (cmd.exe, powershell.exe, nc.exe)** | Very High — built-in Windows behavior, no evasion needed to preserve this signature. | **RARE** in legitimate Windows operation (should never happen). | 🔴 **#1** |
| **Process tree: low-privilege account → SYSTEM-context child via token impersonation** | Very High — structural, cannot be hidden without preventing the exploit entirely. | **RARE** in legitimate operation. | 🔴 **#2** |
| **Sysmon Event 1: ParentImage=spoolsv.exe, CommandLine contains suspicious payload (nc.exe, mimikatz, powershell IEX)** | High — attackers may obfuscate the command, but the parent-child pair is fixed. | Medium (depends on payload visibility). | 🟠 **#3** |
| **Event 4672: Special privileges assigned to spoolsv.exe or child process** | High — token impersonation is difficult to hide, though non-default audit policies may not catch it. | **RARE** if auditing is enabled. | 🟠 **#4** |
| **PrintSpoofer.exe binary name** | **Very Low** — binary can be renamed trivially; filename-based detection is ineffective. | Low (most operators rename). | 🟡 **#5** |
| **File creation by SYSTEM in suspicious locations (C:\Windows\Temp\, C:\Temp\) with timestamps correlating to PrintSpoofer execution** | High — file creation by SYSTEM is distinctive, but post-execution cleanup is easy. | Medium (depends on payload). | 🟠 **#6** |
| **Named Pipe creation/connection (RPC endpoint interaction)** | Medium — requires EDR visibility into RPC/named-pipe operations; not all tools log this. | Low (internal RPC is less visible). | 🟡 **#7** |

---

## Hunting on Source

### PowerShell query: Process tree anomaly

```powershell
# Hunt for spoolsv.exe spawning child processes (primary indicator)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='ParentImage']='C:\Windows\System32\spoolsv.exe']]" | 
  Select-Object TimeCreated, @{Name="ParentProcess";Expression={$_.Properties[20].Value}}, @{Name="ChildProcess";Expression={$_.Properties[10].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}} |
  Format-Table -AutoSize
```

**What this finds:**
- Any process created by spoolsv.exe (Print Spooler service).
- On normal systems, this list should be **empty or nearly empty** (Print Spooler doesn't typically spawn children).
- Any result is a **strong indicator of PrintSpoofer or similar token-impersonation exploit**.

### Event 4688 query: Process creation by spoolsv.exe

```powershell
# If Sysmon is not available, use Windows Security Event 4688
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='ParentProcessName']='C:\Windows\System32\spoolsv.exe']]" |
  Select-Object TimeCreated, @{Name="ParentProcess";Expression={$_.Properties[20].Value}}, @{Name="NewProcess";Expression={$_.Properties[5].Value}}, @{Name="CommandLine";Expression={$_.Properties[8].Value}} |
  Format-Table -AutoSize
```

### Behavioral hunt: Token impersonation events

```powershell
# Hunt for Event 4672 (Special Privileges Assigned) coinciding with unusual process spawns
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4672]]" |
  Where-Object { $_.Properties[3].Value -like "*SeImpersonate*" -or $_.Properties[3].Value -like "*SeAssignPrimaryToken*" } |
  Select-Object TimeCreated, @{Name="SubjectAccountName";Expression={$_.Properties[1].Value}} |
  Format-Table -AutoSize
```

**Then correlate:** Look for spoolsv.exe receiving SeImpersonate, followed by spoolsv.exe spawning a child process at nearly the same timestamp.

### Fleet-wide detection: Unusual spoolsv.exe activity

```powershell
# Gather spoolsv.exe child-process events across the fleet (via SIEM/Splunk)
# Splunk query example:
index=sysmon EventID=1 ParentImage="C:\\Windows\\System32\\spoolsv.exe" |
  stats count by Image, CommandLine, host |
  where count > 0
```

**Expected result:** Essentially empty. Any results warrant immediate investigation.

### Detection evasion considerations

**Attackers may attempt to:**
1. **Rename PrintSpoofer.exe** — mitigation: Hunt by behavior (spoolsv.exe → child), not binary name.
2. **Clear event logs** — mitigation: Use centralized logging (Splunk, ELK, Windows Event Forwarding).
3. **Disable Sysmon** — mitigation: Redundant detection (Windows Event 4688 as fallback).
4. **Obfuscate the command line** — mitigation: The parent-child pair (spoolsv.exe → cmd.exe) is still visible regardless of command content.

---

## Hunting on Target

### Sysmon Event 1: Interactive child of spoolsv.exe

```powershell
# Hunt for spoolsv.exe spawning interactive shells or suspicious binaries
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='ParentImage']='C:\Windows\System32\spoolsv.exe'] and (EventData[Data[@Name='Image'] and contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'cmd.exe')] or EventData[Data[@Name='Image'] and contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'powershell.exe')] or EventData[Data[@Name='Image'] and contains(translate(.,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz'),'nc.exe')])]" |
  Select-Object TimeCreated, @{Name="ParentImage";Expression={$_.Properties[20].Value}}, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="User";Expression={$_.Properties[1].Value}} |
  Format-Table -AutoSize
```

**Simplified (PowerShell 5.0+):**

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='ParentImage']='C:\Windows\System32\spoolsv.exe']]" |
  ForEach-Object {
    $childImage = $_.Properties[10].Value
    if ($childImage -match '(cmd\.exe|powershell\.exe|nc\.exe|mimikatz\.exe|implant\.exe)') {
      Write-Host "ALERT: Suspicious child spawned by spoolsv.exe: $childImage"
      $_
    }
  }
```

### Event 4672 correlation

```powershell
# Hunt for Event 4672 + 4688 within a short time window
# Splunk query:
index=windows EventID IN (4672, 4688) |
  where (EventID=4672 AND Privileges="*SeImpersonate*") OR (EventID=4688 AND User="NT AUTHORITY\SYSTEM") |
  stats earliest(TimeCreated) as start, latest(TimeCreated) as end by ComputerName, ProcessName |
  where (end - start) < 5
```

### File artifacts: Output redirection

```powershell
# Hunt for files created by SYSTEM in unusual locations, with timestamps matching PrintSpoofer execution
Get-ChildItem -Path 'C:\Windows\Temp\', 'C:\Temp\' -File -Recurse |
  Where-Object { $_.Owner -eq 'NT AUTHORITY\SYSTEM' -and $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
  Select-Object FullName, Owner, LastWriteTime, Length |
  Format-Table -AutoSize
```

**Look for:**
- Unusual file extensions (`.hive`, `.dmp`, `.txt` with credential-related names like `hashes.txt`, `mimi_output.txt`).
- Large files in temp (e.g., `ntds.dit` or `LSASS.dmp`).

### Reverse shell detection

```powershell
# Hunt for unusual outbound connections from system processes
Get-NetTCPConnection -State Established |
  Where-Object { $_.OwningProcess -notlike "svchost*" -and $_.OwningProcess -notlike "lsass*" -and $_.RemoteAddress -notmatch '127.0.0.1|192.168.*|10\.' } |
  ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($process) {
      Write-Host "Suspicious connection: $($process.Name) → $($_.RemoteAddress):$($_.RemotePort)"
      $_
    }
  }
```

### Scheduled task hunting (if persistence is deployed post-escalation)

```powershell
# Hunt for recently created tasks (especially those with /ru system)
Get-ScheduledTask |
  Where-Object { $_.State -eq 'Ready' } |
  ForEach-Object {
    $taskName = $_.TaskName
    $lastRun = (Get-ScheduledTaskInfo -InputObject $_).LastRunTime
    if ($lastRun -gt (Get-Date).AddMinutes(-10)) {
      Write-Host "Recently modified task: $taskName (last run: $lastRun)"
      Get-ScheduledTask -TaskName $taskName | Get-ScheduledTaskAction
    }
  }
```

---

## Detection evasion mitigation

### 1. Process tree protection (Sysmon/ETW enforcement)

**Mitigation:** Deploy mandatory Sysmon with Event ID 1 logging on all systems.

```xml
<!-- Sysmon config snippet: Alert on spoolsv.exe children -->
<RuleGroup name="spoolsv.exe Anomaly" groupRelation="or">
  <ProcessCreate onmatch="include">
    <ParentImage condition="image">spoolsv.exe</ParentImage>
    <Image condition="image">cmd.exe|powershell.exe|nc.exe|mimikatz.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

### 2. Disable Print Spooler (if not needed)

**Mitigation:** On systems that don't require printing, disable the Print Spooler service.

```powershell
Set-Service -Name spooler -StartupType Disabled
Stop-Service -Name spooler -Force
```

**Caveat:** Some Windows 10/11 features may depend on the Print Spooler being available (even if not actively used), so test this in your environment.

### 3. SeImpersonate privilege removal (application hardening)

**Mitigation:** For web applications (IIS) or database services, consider running them under application pools with reduced privileges.

However, this is **difficult to implement** for many applications and may break functionality. Monitor instead.

### 4. Centralized logging

**Mitigation:** Forward all Security and Sysmon logs to a centralized SIEM (Splunk, ELK, Azure Sentinel) to prevent local log tampering.

```powershell
# Windows Event Forwarding (WEF) example
# Configure a domain-joined machine to forward events to a collector:
wecutil cs http://collector.domain.local:5985/wsman/SubscriptionManager
```

### 5. AppContainer / Privilege boundary enforcement

**Mitigation:** Confine applications to AppContainers, which forbid token impersonation entirely.

Most applications cannot run in AppContainer mode; this is a last-resort option for specific, compatible applications.

---

## Fleet-wide sweep (post-compromise assessment)

**If you suspect PrintSpoofer or similar token-impersonation exploits have been used:**

```powershell
# 1. Search all machines for spoolsv.exe child processes in the past 30 days
# (via Splunk/SIEM):
index=sysmon EventID=1 ParentImage="C:\\Windows\\System32\\spoolsv.exe" 
  earliest=-30d |
  stats count by host, Image, CommandLine |
  where count > 0

# 2. Search for Event 4672 (SeImpersonate assigned) in the past 30 days
index=windows EventID=4672 Privileges="*SeImpersonate*" 
  earliest=-30d |
  stats count by ComputerName, SubjectAccountName

# 3. Search for files created by SYSTEM in temp directories
# (File Integrity Monitoring / FIM logs, if available)
index=fim path=C:\\Windows\\Temp\\* OR path=C:\\Temp\\* 
  user=SYSTEM action=created earliest=-30d |
  stats count by host, filename, owner
```

**Remediation:**
- Review all flagged processes for legitimacy.
- Correlate with authentication logs (4624/4625) to identify attacker entry points.
- Force password resets for any accounts that performed the escalation.
- If compromise is confirmed, reconstruct the full incident timeline using source-host logs.

---

## Summary

**PrintSpoofer detection is behavioral, not signature-based:**

1. **Primary hunt:** spoolsv.exe spawning cmd.exe/powershell.exe/suspicious binaries as SYSTEM (Sysmon 1, Event 4688).
2. **Secondary hunt:** Event 4672 (token impersonation) + process creation at the same timestamp.
3. **Tertiary hunt:** File/registry artifacts created by SYSTEM immediately after PrintSpoofer execution (filesystem timeline correlation).

**Evasion resistance:**
- **Binary rename:** Ineffective; the parent-child process tree survives renaming.
- **Log clearing:** Defeated by centralized logging (WEF, SIEM).
- **Disabling Sysmon:** Redundant detection via Windows Event 4688.
- **Obfuscating the command:** The process pair (spoolsv.exe → child) is still visible.

**Defenders win if they monitor for the structural anomaly (spoolsv.exe spawning interactive shells), not the payload details.**
