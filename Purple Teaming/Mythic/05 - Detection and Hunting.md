# Mythic C2 — Detection and Hunting

## Hunting Priority Table

Mythic's modular architecture means detection signals vary by agent type and C2 profile. The table below ranks signals by **invariant strength** — which survive evasion attempts (agent renaming, custom compilation, etc.).

| Rank | Signal Category | Detection Method | Evasion Resistance | Notes |
|---|---|---|---|---|
| **1** | **Infrastructure: Docker Network/Container** | Port 8443 listening on operator's host; docker-proxy processes; docker ps enumeration | Very High | Core to Mythic design; no operator alternative exists |
| **2** | **Database: PostgreSQL Artifact Pattern** | PostgreSQL dump with Mythic schema (callback, task, payload, operation tables) | Very High | Uniquely identifies Mythic, not easily spoofed |
| **3** | **Network: C2 Callback Pattern** | Regular TCP connections at fixed intervals (5s ±30% jitter) to same IP:port, regardless of protocol | Very High | Interval + jitter pattern is hardcoded, not configurable per agent |
| **4** | **Behavioral: Sysmon 1 + Sysmon 3 Correlation** | Unsigned binary in %TEMP% → multiple child cmd.exe → outbound TCP at intervals | Very High | Behavioral signature survives binary renaming/recompilation |
| **5** | **Process: Parent-Child Anomaly** | Unusual parent (apollo.exe, poseidon.exe, rogue) spawning cmd.exe/powershell.exe | Very High | Agent-specific, but pattern common across all Mythic agents |
| **6** | **Memory: Process Access to LSASS** | Sysmon Event 10: process accessing lsass.exe with access mask 0x1F3FFF | High | Specific to LSASS harvesting; evasion requires Process Injection (more complex) |
| **7** | **Persistence: Scheduled Task Anomaly** | Sysmon 1 (schtasks.exe) → Task creation in registry with unusual command (C:\Temp\*.exe) | High | Persistence-specific, only present if operator enables it |
| **8** | **Registry: Service Binpath** | Registry entry HKLM\System\CurrentControlSet\Services with ImagePath pointing to %TEMP% | High | Only if service persistence used |
| **9** | **File System: Staged Binary** | Unsigned executable in C:\Windows\Temp with creation time matching engagement | Medium | Can be deleted post-engagement; file carving required |
| **10** | **Network: User-Agent String** | Customizable HTTP User-Agent (default realistic Windows UA, but can be anything) | Low | Operator can change per-profile; not a reliable IOC |
| **11** | **Network: Certificate Pinning** | HTTPS C2 listener with self-signed cert (if HTTPS used) | Low | Operator can use Let's Encrypt or custom CA |
| **12** | **Process: Binary Name/Path** | apollo.exe, poseidon.exe in Process Explorer | Low | Operator can rename binary before deployment; file recovery required |

---

## Hunting on Source (Operator's Mythic Infrastructure)

### 1. Port-Based Network Discovery

**Goal:** Identify hosts running Mythic server.

**Signal:** Port 8443 (Mythic React UI) is distinctive and rarely used by other services.

#### PowerShell (From Network Segment)

```powershell
# Scan subnet for port 8443
1..254 | ForEach-Object {
  $ip = "192.168.1.$_"
  $sock = New-Object System.Net.Sockets.TcpClient
  $async = $sock.BeginConnect($ip, 8443, $null, $null)
  $wait = $async.AsyncWaitHandle.WaitOne(1000)
  if ($wait) {
    try {
      $sock.EndConnect($async)
      Write-Host "$ip:8443 OPEN"
    } catch {}
  }
  $sock.Close()
}
```

**Bash (Linux/macOS)**

```bash
# Scan subnet for port 8443
nmap -p 8443 192.168.1.0/24 --open
# OR
for i in {1..254}; do
  timeout 1 bash -c "echo >/dev/tcp/192.168.1.$i/8443" 2>/dev/null && echo "192.168.1.$i:8443 OPEN"
done
```

**Expected output:** Hosts with port 8443 open (only Mythic server in typical network).

### 2. Docker Container Enumeration

**Goal:** Find Docker-based Mythic infrastructure.

**Signal:** Container images with `mythic_` prefix or `itsafeaturemythic/` registry.

#### Bash (On Suspected Operator Host)

```bash
# List all Docker images
docker images | grep -i mythic
# OR
docker images | grep itsafeaturemythic

# Output:
# itsafeaturemythic/mythic_go:latest
# itsafeaturemythic/mythic_react:latest
# itsafeaturemythic/mythic_python_base:latest
# postgres:13
# rabbitmq:3-management
```

**Alternative:** Query Docker daemon if accessible via socket:

```bash
# List running containers
docker ps | grep mythic

# List all containers
docker ps -a | grep mythic
```

### 3. PostgreSQL Database Artifact Discovery

**Goal:** Recover Mythic database and extract operational data.

**Signal:** PostgreSQL database with Mythic-specific schema (callback, task, payload, operation tables).

#### Step 1: Locate Database Container/Volume

```bash
# Find PostgreSQL containers
docker ps | grep postgres

# Extract volume mount paths
docker inspect <mythic-postgres-container-id> | grep -A5 "Mounts"
# Output: "Source": "/var/lib/docker/volumes/mythic_database/_data"
```

#### Step 2: Dump PostgreSQL Database

```bash
# Option A: From within container (if you have shell access)
docker exec <postgres-container-id> pg_dump -U mythic mythic_db > mythic_backup.sql

# Option B: From filesystem (if volumes are accessible)
cp /var/lib/docker/volumes/mythic_database/_data/base/*/0 .
# (Raw PostgreSQL page files, requires PostgreSQL recovery tools)

# Option C: If running as current user (without sudo)
docker exec <container-id> psql -U mythic mythic_db -c "SELECT * FROM callback;"
```

#### Step 3: Analyze Dumped Database

```bash
# Import dump to local PostgreSQL
psql < mythic_backup.sql

# Query for operational data
psql mythic_db -c "SELECT id, operation_id, agent_type, host, user FROM callback;" 
# Returns: all compromised hosts registered in Mythic

psql mythic_db -c "SELECT id, callback_id, command, response FROM task LIMIT 20;"
# Returns: first 20 commands executed (full operational log)

psql mythic_db -c "SELECT id, payload_type, c2_profile, callback_host, callback_port, creation_time FROM payload;"
# Returns: all generated payloads (C2 endpoints exposed)
```

### 4. Filesystem Artifact Hunting

**Goal:** Find staged payloads and agent source code on operator's host.

#### Bash Commands

```bash
# Find Mythic installation directory
find /root -name "Mythic" -type d 2>/dev/null
find /home -name "Mythic" -type d 2>/dev/null

# List generated payloads
ls -la /root/Mythic/PayloadsGenerated/

# List installed agents/C2 profiles
ls -la /root/Mythic/InstalledServices/

# Find database backups
find /root -name "*.sql" -o -name "*.sql.gz" 2>/dev/null | head -20
find /var/backups -name "mythic*" 2>/dev/null

# Search for Docker-compose file
find / -name "docker-compose.yml" | xargs grep -l mythic 2>/dev/null
```

### 5. Process-Level Hunting (Memory Forensics)

**Goal:** Extract runtime secrets and active session state from running Mythic processes.

#### Extract Encryption Keys (If Mythic Server Running)

```bash
# Get mythic_go process ID
PID=$(docker inspect --format='{{.State.Pid}}' <mythic_go_container_id>)

# Dump memory of mythic_go process
gcore $PID
# OR
dd if=/proc/$PID/mem of=mythic_go_memory.dump bs=4096

# Analyze with Volatility (requires Linux profile)
volatility -f mythic_go_memory.dump linux.pslist | grep mythic_go

# Search for encryption keys (high-entropy 32-byte sequences)
strings mythic_go_memory.dump | grep -E "^[A-Za-z0-9]{64}$" | head -10
# (AES-256 keys are 32 bytes = 64 hex characters)
```

**Caveat:** Encryption keys are protected by Go runtime; memory extraction is difficult without specialized tools.

---

## Hunting on Target (Compromised Host)

### 1. Process-Based Hunting

**Goal:** Find running Mythic agents.

#### PowerShell (Windows)

```powershell
# List all running processes with unsigned binaries
Get-Process | Where-Object {
  $proc = Get-Item -Path "Variable:\_.Path" -ErrorAction SilentlyContinue
  if ($proc) {
    $sig = Get-AuthenticodeSignature -FilePath $proc.Path
    $sig.Status -ne "Valid"
  }
} | Select-Object Name, Id, Path | Format-Table

# Specific: Look for suspicious parent-child relationships
Get-WmiObject Win32_Process | Where-Object {
  $_.ParentProcessId -match "\d+" -and $_.Name -eq "cmd.exe"
} | ForEach-Object {
  $parentProc = Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue
  if ($parentProc -and ($parentProc.Path -like "*\Temp\*" -or $parentProc.Path -like "*\AppData\*")) {
    Write-Host "Suspicious: $($_.Name) (PID: $_.ProcessId) spawned by $($parentProc.Name) (PID: $_.ParentProcessId) from $($parentProc.Path)"
  }
}

# Hunt for specific agent names
Get-Process | Where-Object { $_.Name -match "^(apollo|poseidon|rogue|aspen|artemis|merlin)" } | Select-Object Name, Id, Path
```

#### Bash (Linux/macOS)

```bash
# List processes with unusual parent-child relationships
ps auxww | grep -E "(apollo|poseidon|rogue|aspen|artemis)" 

# Check for processes in /tmp or /var/tmp spawned by unusual parents
lsof +D /tmp +D /var/tmp | grep -E "^[a-z0-9]+\s+[0-9]+" | awk '{print $1, $2}' | sort -u
# Filter for executables, not shared libraries
```

### 2. Network-Based Hunting

**Goal:** Detect C2 callback traffic.

#### PowerShell (Windows)

```powershell
# List all established TCP connections
Get-NetTCPConnection -State Established | 
  Where-Object { $_.RemoteAddress -notmatch "^127\.|^169\.254\." } |
  Select-Object -Property LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
  ForEach-Object {
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and ($proc.Path -like "*\Temp\*" -or $proc.Path -like "*\AppData\*")) {
      Write-Host "Suspicious connection from $($proc.Name) ($($proc.Path)) to $($_.RemoteAddress):$($_.RemotePort)"
    }
  }

# Hunt for repeated connections to same IP:Port (C2 callback pattern)
Get-NetTCPConnection -State Established | 
  Group-Object -Property RemoteAddress, RemotePort |
  Where-Object { $_.Count -gt 5 } |
  Select-Object -Property Name, Count
# (Will show IPs/ports with multiple connections, typical of C2 beaconing)
```

#### Bash (Linux/macOS)

```bash
# List all established TCP connections
netstat -tlnpe | grep ESTABLISHED

# Filter for unusual remote destinations
ss -tlnpe | grep ESTABLISHED | grep -v "127.0.0.1\|169.254"

# Hunt for repeated connections (using tcpdump/netflow)
tcpdump -i any 'tcp and !host 127.0.0.1' -n | awk '{print $3}' | sort | uniq -c | sort -rn | head -10
# (Shows top 10 external IPs by connection count)
```

### 3. Event Log Hunting (Windows)

**Goal:** Find agents in Security/Sysmon logs.

#### PowerShell

```powershell
# Hunt for Sysmon Event 1 (Process Creation) with suspicious parent
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath '*[System[(EventID=1)]]' -MaxEvents 10000 |
  Where-Object {
    $event = ([xml]$_.ToXml()).Event.EventData.Data
    $parent = $event | Where-Object { $_.Name -eq "ParentImage" } | Select-Object -ExpandProperty "#text"
    $parent -like "*\Temp\*" -or $parent -like "*\AppData\*"
  } |
  Select-Object -Property TimeCreated, 
    @{Name="ProcessName"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "Image" })."#text"}},
    @{Name="ParentImage"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "ParentImage" })."#text"}}

# Hunt for Sysmon Event 3 (Network Connection) from unsigned binaries
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -FilterXPath '*[System[(EventID=3)]]' -MaxEvents 10000 |
  Where-Object {
    $event = ([xml]$_.ToXml()).Event.EventData.Data
    $srcIp = $event | Where-Object { $_.Name -eq "SourceIp" } | Select-Object -ExpandProperty "#text"
    $destIp = $event | Where-Object { $_.Name -eq "DestinationIp" } | Select-Object -ExpandProperty "#text"
    $destPort = $event | Where-Object { $_.Name -eq "DestinationPort" } | Select-Object -ExpandProperty "#text"
    # Filter for external destinations
    $destIp -notmatch "^127\.|^169\.254\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^192\.168\."
  } |
  Select-Object -Property TimeCreated,
    @{Name="SourceIp"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "SourceIp" })."#text"}},
    @{Name="DestinationIp"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "DestinationIp" })."#text"}},
    @{Name="DestinationPort"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "DestinationPort" })."#text"}}

# Hunt for Event 4688 (Process Creation) with cmd.exe parent=C:\Windows\Temp\*.exe
Get-WinEvent -LogName "Security" -FilterXPath '*[System[(EventID=4688)]]' -MaxEvents 10000 |
  Where-Object {
    $event = ([xml]$_.ToXml()).Event.EventData.Data
    $newProc = $event | Where-Object { $_.Name -eq "NewProcessName" } | Select-Object -ExpandProperty "#text"
    $parentProc = $event | Where-Object { $_.Name -eq "ParentProcessName" } | Select-Object -ExpandProperty "#text"
    $parentProc -like "*\Temp\*"
  } |
  Select-Object -Property TimeCreated,
    @{Name="ChildProcess"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessName" })."#text"}},
    @{Name="ParentProcess"; Expression={($_.ToXml().Event.EventData.Data | Where-Object { $_.Name -eq "ParentProcessName" })."#text"}}
```

### 4. Registry Hunting

**Goal:** Find persistence mechanisms (scheduled tasks, services).

#### PowerShell

```powershell
# Hunt for scheduled tasks with unusual commands
Get-ScheduledTask | Where-Object {
  $task = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
  if ($task) {
    $actions = $_.Actions
    $actions | Where-Object { $_.Execute -like "*\Temp\*" -or $_.Execute -like "*\AppData\*" }
  }
} | Select-Object -Property TaskName, @{Name="Command"; Expression={$_.Actions.Execute}}

# Hunt for services with unusual image paths
Get-Service | ForEach-Object {
  $svc = $_
  $regPath = "HKLM:\System\CurrentControlSet\Services\$($svc.Name)"
  $imagePath = (Get-ItemProperty -Path $regPath -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
  if ($imagePath -like "*\Temp\*" -or $imagePath -like "*\AppData\*") {
    Write-Host "Suspicious service: $($svc.Name) -> $imagePath"
  }
}

# Hunt for Run registry keys pointing to %TEMP%
Get-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty Property |
  ForEach-Object {
    $value = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $_ |
      Select-Object -ExpandProperty $_
    if ($value -like "*\Temp\*" -or $value -like "*\AppData\*") {
      Write-Host "Suspicious Run key: $_ -> $value"
    }
  }
```

### 5. File System Hunting

**Goal:** Find staged binaries and credential dump artifacts.

#### PowerShell

```powershell
# Hunt for recently created executables in %TEMP%
Get-ChildItem -Path $env:TEMP -Filter "*.exe" -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } |
  Select-Object -Property FullName, CreationTime, Length

# Hunt for LSASS dumps
Get-ChildItem -Path $env:TEMP -Filter "*lsass*", "*sam*", "*debug*" -ErrorAction SilentlyContinue |
  Select-Object -Property FullName, CreationTime, Length

# Hunt for unsigned executables
Get-ChildItem -Path $env:TEMP -Filter "*.exe" -ErrorAction SilentlyContinue |
  ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.FullName
    if ($sig.Status -ne "Valid") {
      Write-Host "Unsigned: $($_.FullName) (Status: $($sig.Status))"
    }
  }
```

#### Bash (Linux)

```bash
# Hunt for recently created executables in /tmp
find /tmp -type f -perm /111 -mtime -7 2>/dev/null | head -20

# Hunt for suspicious scripts
find /tmp /var/tmp -name "*.sh" -o -name "*.py" -o -name "*.pl" -mtime -7 2>/dev/null

# Check for persistence scripts in hidden directories
find ~/ -name ".mythic" -o -name ".beacon" -o -name ".implant" 2>/dev/null

# Hunt for LSASS/credential dumps
ls -la /tmp/*lsass* /tmp/*sam* /tmp/*debug* 2>/dev/null
ls -la /var/tmp/*lsass* 2>/dev/null
```

---

## Fleet-Wide Sweep Commands

### PowerShell Remoting (Windows Domain)

**Goal:** Scan all domain computers for Mythic agents in a single pass.

```powershell
# Get all domain computers
$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

# Run hunt queries on each computer (requires WinRM + admin rights)
$results = @()
foreach ($computer in $computers) {
  try {
    $proc = Invoke-Command -ComputerName $computer -ScriptBlock {
      Get-Process | Where-Object { $_.Name -match "^(apollo|poseidon|rogue)" } |
        Select-Object @{Name="Computer"; Expression={$env:COMPUTERNAME}}, Name, Id, Path
    } -ErrorAction SilentlyContinue
    $results += $proc
  } catch { <# Host offline or no access #> }
}

# Output findings
$results | Format-Table Computer, Name, Id, Path

# Export to CSV for analysis
$results | Export-Csv -Path "C:\temp\mythic_hunt_results.csv" -NoTypeInformation
```

### EDR Integration (If Available)

**Crowdstrike Falcon Query:**

```
event_type:ProcessRollup2 AND process_name:(apollo.exe OR poseidon.exe OR rogue.exe)
```

**Sentinel/Microsoft Defender:**

```kql
DeviceProcessEvents
| where ProcessName in ("apollo.exe", "poseidon.exe", "rogue.exe")
  or (InitiatingProcessFolderPath contains "Temp" and FileName in ("cmd.exe", "powershell.exe"))
| summarize Count=count() by DeviceName, ProcessName, InitiatingProcessFolderPath
```

### SIEM (Splunk/ELK) Query

**Splunk:**

```spl
index=main sourcetype=sysmon EventCode=1 ParentImage="*\Temp\*.exe" OR OriginalFileName in (apollo.exe, poseidon.exe, rogue.exe)
| stats count by host, ParentImage, Image
```

**Elasticsearch (KQL):**

```
process.parent.executable:(*\\Temp\\*) OR process.name:(apollo.exe OR poseidon.exe OR rogue.exe)
```

---

## Remediation: Evidence Preservation and Containment

### Immediate Actions (Upon Detection)

```powershell
# 1. Isolate compromised host from network
# (Physically disconnect Ethernet or disable WiFi)
# (Or: Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Block)

# 2. Capture memory dump (for later forensics)
Get-Process <agent-process-name> | ForEach-Object {
  # Use Sysinternals procdump (requires admin)
  & "C:\Program Files\Sysinternals Suite\procdump.exe" -ma $_.Id "C:\evidence\$($_.Name)_$(Get-Date -Format yyyyMMdd_HHmmss).dmp"
}

# 3. Acquire disk image (if possible)
# Physical disk imaging should be done by forensics team

# 4. Collect event logs for analysis
Get-WinEvent -LogName "Security" -MaxEvents 10000 | Export-Clixml "C:\evidence\Security_events.xml"
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 20000 | Export-Clixml "C:\evidence\Sysmon_events.xml"

# 5. Preserve running process list
Get-Process | Export-Csv "C:\evidence\running_processes.csv"
Get-NetTCPConnection | Export-Csv "C:\evidence\network_connections.csv"

# 6. Kill the agent (after evidence preservation)
Stop-Process -Name "apollo" -Force
Stop-Process -Name "poseidon" -Force
Stop-Process -Name "rogue" -Force
```

### Cleanup

```powershell
# 1. Remove agent binary
Remove-Item -Path "C:\Windows\Temp\*.exe" -Force -Confirm:$false -ErrorAction SilentlyContinue

# 2. Remove persistence
# Remove scheduled tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like "*Update*" -or $_.TaskName -like "*Protection*" } |
  Unregister-ScheduledTask -Confirm:$false

# Remove services
Remove-Item -Path "HKLM:\System\CurrentControlSet\Services\WindowsUpdate" -Force -ErrorAction SilentlyContinue

# Remove Run registry keys
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdate" -Force -ErrorAction SilentlyContinue

# 3. Force password resets for compromised accounts
# (Coordinate with Active Directory/IAM team)

# 4. Block C2 IP at network perimeter
# (Add firewall rule blocking destination IP/port)

# 5. Monitor for re-infection
# (Heightened alerting on the same IP:port for 30 days post-incident)
```

---

## Hunting Summary by Detection Capability

| If You Have... | What You Can Hunt | Commands |
|---|---|---|
| **Endpoint Detection & Response (EDR)** | Real-time process/network monitoring | Query EDR console for agent process names, network beaconing patterns |
| **Sysmon** | Detailed process/network events | PowerShell queries for Event 1 (process creation), Event 3 (network), Event 10 (LSASS access) |
| **Windows Security Event Logs** | Process creation (4688), Service creation (7045), Scheduled Tasks (4697) | PowerShell Get-WinEvent queries (see above) |
| **Network Monitoring (IDS/Netflow)** | C2 callback traffic | Look for repeated TCP connections to same external IP at regular intervals (5s ±30%) |
| **Memory Forensics (Volatility)** | In-memory agent processes | volatility pslist, handles, vads on memory dump of compromise time |
| **Filesystem (NTFS forensics)** | Staged binaries, deleted artifacts | Carving %TEMP%, %APPDATA%; MFT analysis for deleted files |
| **PostgreSQL Database** | Complete operational timeline | SQL queries to callback, task, payload, operation tables (if database seized) |
| **Docker** (If infrastructure compromised) | Container image/volume enumeration | docker ps, docker images, docker inspect, docker exec |

---

## Evasion Mitigations (By Detection Layer)

| Layer | Evasion Technique | Detection Mitigation |
|---|---|---|
| **Process** | Rename agent binary (apollo.exe → svchost.exe) | Hunt by parent-child relationship, not binary name; monitor %TEMP% spawning children |
| **Persistence** | Use built-in Windows RunOnce instead of scheduled tasks | Monitor all persistence mechanisms (Registry Run keys, Scheduled Tasks, Services, Startup folders) |
| **C2 Protocol** | Use DNS profile instead of HTTP | Monitor DNS query patterns (base64-like subdomains, queries to operator-controlled domain) |
| **Evasion: C2 Proxy** | Use redirector to hide Mythic server IP | Hunt the redirector's IP instead; network-based IOC detection on traffic pattern (not IP) |
| **Credential Access** | Process injection instead of cmd.exe → whoami | Sysmon Event 10 (process access to lsass) is harder to evade; requires Process Injection detection (behavioral) |
| **Cleanup** | Delete agent binary and event logs | Hunt for deletion timestamps (MFT, filesystem journal); memory forensics on running process |

---

## Key Takeaways

1. **Mythic's modular design means no single signature** — agents vary by type, C2 profiles vary by transport.
2. **Behavioral hunting is more reliable than signature-based** — the interval + jitter pattern of callbacks, or parent-child process relationships, survive agent renaming.
3. **Source (operator) infrastructure is highly distinctive** — Docker containers, PostgreSQL schema, port 8443 are Mythic-specific.
4. **Database seizure is the most valuable source** — the PostgreSQL dump contains the complete operational timeline and all generated payloads.
5. **Network-level signals (repeated callback pattern) survive most evasion** — even if the agent is renamed or recompiled, the callback interval is hardcoded by Mythic.
6. **Persistence-specific signals are only present if enabled** — if operator doesn't install scheduled tasks or services, those hunt signals won't apply.
