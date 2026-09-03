# JuicyPotato — Detection and Hunting

## Hunting Priority table

| Signal | Evasion Survivability | Prevalence | Rank |
|---|---|---|---|
| **Unexpected SYSTEM-context process spawn (token impersonation)** | Very High — structural, cannot hide without abandoning the exploit. | **RARE** in legitimate operation. | 🔴 **#1** |
| **Sysmon Event 1: Low-privilege parent → SYSTEM child (any parent)** | Very High — the core signature. | **RARE**. | 🔴 **#2** |
| **CLSID in command line (e.g., `-c {5E9DDC73-...}`)** | Medium — operators may omit or obscure the CLSID, but default CLSIDs leave this signature. | Medium (depends on operator behavior). | 🟠 **#3** |
| **Event 4672: Token privilege escalation coinciding with process spawn** | High — difficult to hide without disabling auditing. | **RARE** if auditing enabled. | 🟠 **#4** |
| **JuicyPotato.exe binary name** | **Very Low** — trivially renamed; filename matching is ineffective. | Low (most operators rename). | 🟡 **#5** |
| **Port binding on high ephemeral ports (COM server listen port)** | High — difficult to hide, but internal to the machine. | Medium (depends on network monitoring tools). | 🟡 **#6** |

---

## Hunting on Source

### PowerShell query: SYSTEM process spawned from non-SYSTEM context

```powershell
# Hunt for unexpected token impersonation (low-privilege → SYSTEM child)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='User']='NT AUTHORITY\SYSTEM']]" |
  Where-Object { 
    $parentUser = $_.Properties[1].Value
    $childUser = $_.Properties[1].Value
    # Compare parent and child user contexts
    # If spawned by non-SYSTEM parent running as SYSTEM child, flag it
  } |
  Select-Object TimeCreated, @{Name="ParentImage";Expression={$_.Properties[20].Value}}, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
```

**Simplified version:**

```powershell
# Hunt for any Sysmon event where the child runs as SYSTEM but parent is not system32\*.exe
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  Where-Object { 
    $childUser = ($_.Properties[1].Value)
    $parentImage = ($_.Properties[20].Value)
    if ($childUser -eq 'NT AUTHORITY\SYSTEM' -and $parentImage -notmatch 'System32\\(svchost|lsass|csrss|services|spoolsv)\.exe') {
      $_
    }
  }
```

### Command-line hunting: CLSID indicators

```powershell
# Hunt for known vulnerable CLSIDs in process-creation command lines
$suspiciousCLSIDs = @(
    "5E9DDC73-7E6D-4DA9-92BA-B23270F19C09",  # BITS
    "0FB0F995-*",                             # OneSyncSvc
    "14B59933-*"                              # NtmsSvc
)

Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  ForEach-Object {
    $commandLine = $_.Properties[10].Value
    if ($commandLine -match '(-c\s+{|CLSID)') {
      Write-Host "ALERT: JuicyPotato CLSID indicator in command line: $commandLine"
      $_
    }
  }
```

### Event 4672 correlation (token impersonation)

```powershell
# Hunt for Event 4672 (token privilege escalation) near process-creation events
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4672]]" |
  Where-Object { $_.Properties[3].Value -like "*SeImpersonate*" -or $_.Properties[3].Value -like "*SeAssignPrimaryToken*" } |
  Select-Object TimeCreated, @{Name="SubjectAccountName";Expression={$_.Properties[1].Value}}, @{Name="Privileges";Expression={$_.Properties[3].Value}}
```

---

## Hunting on Target

### Sysmon Event 1: Unexpected SYSTEM spawn

```powershell
# Hunt for Sysmon Event 1 with SYSTEM child but suspicious parent
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='User']='NT AUTHORITY\SYSTEM']]" |
  Select-Object TimeCreated, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}, @{Name="ParentImage";Expression={$_.Properties[20].Value}}
```

### Event 4688 (alternative if Sysmon unavailable)

```powershell
# Windows Security Event 4688 with SYSTEM spawned
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='TargetUserName']='NT AUTHORITY\SYSTEM']]" |
  Select-Object TimeCreated, @{Name="NewProcessName";Expression={$_.Properties[5].Value}}, @{Name="CommandLine";Expression={$_.Properties[8].Value}}
```

### Port binding detection (COM server listening)

```powershell
# Hunt for unusual port bindings by non-system processes
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -gt 1024 -and $_.LocalAddress -eq '127.0.0.1' } |
  ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($process -and $process.ProcessName -notmatch '(svchost|explorer|chrome|firefox)') {
      Write-Host "Suspicious port binding: $($process.Name) on $($_.LocalPort)"
      $_
    }
  }
```

### File artifacts created by SYSTEM

```powershell
# Hunt for files created by SYSTEM in unusual locations (same as PrintSpoofer)
Get-ChildItem -Path 'C:\Windows\Temp\', 'C:\Temp\' -File -Recurse |
  Where-Object { $_.Owner -eq 'NT AUTHORITY\SYSTEM' -and $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) } |
  Select-Object FullName, Owner, LastWriteTime
```

---

## Detection evasion mitigation

### 1. Process tree enforcement

**Mitigation:** Deploy Sysmon with Event ID 1 enabled on all systems.

```xml
<!-- Alert on unexpected SYSTEM spawn -->
<RuleGroup name="Token Impersonation" groupRelation="or">
  <ProcessCreate onmatch="include">
    <User condition="contains">NT AUTHORITY\SYSTEM</User>
    <ParentImage condition="image">JuicyPotato.exe|juicy.exe|potato.exe|jp.exe</ParentImage>
  </ProcessCreate>
</RuleGroup>
```

### 2. Disable vulnerable COM objects (OS hardening)

**Mitigation:** On Windows 10 1909+ and Server 2019+, many of the CLSIDs JuicyPotato relies on have been patched or removed. Ensure systems are fully patched.

### 3. SeImpersonate privilege auditing

**Mitigation:** Monitor and alert on SeImpersonate-bearing processes. Many organizations do not audit this by default.

### 4. Centralized logging

**Mitigation:** Use Windows Event Forwarding (WEF) to forward all Sysmon and Security events to a centralized SIEM.

```powershell
# Enable WEF
wecutil cs http://collector.domain.local:5985/wsman/SubscriptionManager
```

### 5. Behavioral monitoring

**Mitigation:** Most modern EDR tools detect the characteristic process tree (low-privilege parent → SYSTEM child via token impersonation) as a specific behavior pattern.

---

## Fleet-wide sweep

```powershell
# Search for JuicyPotato or similar token-impersonation exploits in the past 7 days
# (via Splunk/SIEM):
index=sysmon EventID=1 User="NT AUTHORITY\SYSTEM" earliest=-7d |
  stats count by host, ParentImage, Image, CommandLine |
  where count > 0 |
  search ParentImage != "System32*" AND ParentImage != "*\csrss.exe" AND ParentImage != "*\lsass.exe"
```

---

## Summary

**JuicyPotato detection is behavioral:**

1. **Primary hunt:** Unexpected SYSTEM-context process spawn from a non-system parent (Sysmon 1, Event 4688).
2. **Secondary hunt:** CLSID indicators in command lines (specific GUIDs).
3. **Tertiary hunt:** Event 4672 (token escalation) coinciding with process creation.
4. **Weakest signal:** Binary name (easily renamed).

**Evasion resistance:**
- **Renamed binary:** Ineffective; process tree survives.
- **Port concealment:** Difficult; COM server binding is still observable.
- **Log clearing:** Defeated by centralized logging.

**Modern defense:**
- Patched Windows 10 1909+ and Server 2019+ have many JuicyPotato CLSIDs removed/patched.
- Most EDR platforms detect the characteristic token-impersonation behavior.
- **JuicyPotato is a legacy tool (2018, abandoned 2020)**; any current sighting should be flagged as unusual.
