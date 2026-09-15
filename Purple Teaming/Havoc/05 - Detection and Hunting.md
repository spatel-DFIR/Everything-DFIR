# Havoc C2 — Detection and Hunting

---

## Hunting Priority — Signal Strength vs. Evasion Survivability

The Havoc framework's **core design principle** is operator malleability via YAOTL profiles, not built-in evasion. This means most network-layer signals (User-Agent, URIs, traffic encoding) are **fully operator-customizable** and **cannot be relied upon** as stable detection signatures. The hunting table below ranks signals by how likely they are to survive operator evasion, from strongest (unavoidable) to weakest (trivially defeated).

| Rank | Signal | Strength | Customizable? | Evasion Method | Confidence |
|---|---|---|---|---|---|
| **1** | **Process injection into sacrificial process** | Very Strong | No (inherent to Demon's architecture) | None — Demon must inject to hide itself; sacrificial process is listed in YAOTL Spawn64/Spawn32 but choice is limited | 95% |
| **2** | **Beacon check-in timing/interval pattern** | Very Strong | Partial (sleep interval is customizable, but patterns are visible with traffic analysis) | Randomize sleep interval heavily, use variable jitter | 80% |
| **3** | **Team Server IP:port embedded in binary** | Strong | No (embedded at compile-time) | Binary reverse engineering unavoidable; only alternative is stager + in-memory Demon | 90% |
| **4** | **Sysmon Event 10: Process access to lsass.exe** | Strong | Partial (token theft is necessary for priv escalation; can be avoided if not using that feature) | Skip token-theft operations, use alternative credential access methods | 85% |
| **5** | **HTTP/HTTPS callback from unexpected process** | Strong | Yes (User-Agent/headers fully customizable per profile) | Mimic legitimate process traffic (customize profile to match environment) | 70% |
| **6** | **Prefetch file (.pf) execution history** | Strong | No (Prefetch is Windows automatic behavior) | Disable Prefetch system-wide (enterprise would detect) or accept the artifact | 92% |
| **7** | **SMB named pipe creation (pivoting)** | Strong | No (SMB is inherent to named-pipe pivoting) | Use HTTP/HTTPS only (no SMB pivoting), or accept the artifact | 88% |
| **8** | **HTTP User-Agent / Request URIs** | Weak | Yes (fully operator-customizable in YAOTL profile) | Customize YAOTL profile to match environment HTTP traffic | 30% |
| **9** | **Binary file hash / PE metadata** | Weak | Yes (every binary is uniquely compiled; `--spoof-metadata` flag changes PE properties) | Recompile with spoofed metadata or sideload in-memory | 20% |
| **10** | **Known YARA rules for Havoc** | Very Weak | Yes (source code modifications or packing defeat all static signatures) | Modify source, use external packers/crypters, or recompile | 15% |

**Implication:** Assume the operator has **spent time tailoring their YAOTL profile** to match the target environment's legitimate HTTP traffic patterns. Do not rely on network-layer indicators alone. **Process-level signals (Sysmon, prefetch, process injection patterns) are more durable.**

---

## Hunting on Source (Operator's Infrastructure)

**Context:** These hunts target the operator's own Team Server, client workstations, relay infrastructure, and associated artifacts. Success requires access to operator infrastructure logs (seized Team Server, proxy/firewall logs capturing operator-to-server connections, or memory/disk artifacts from an operator workstation).

### Hunt 1: Recover YAOTL Profile File

**Goal:** Locate Team Server's YAOTL profile to confirm Havoc deployment and extract network IOCs (listener ports, URIs, operator credentials, C2 endpoints).

**Target:** Operator's Team Server host (Linux) or Docker container

**Commands:**

```bash
# On Team Server host:
find /home -name "*.yaotl" -type f
find /root -name "*.yaotl" -type f
find /data -name "*.yaotl" -type f  # Common Docker volume mount point

# Search for hidden/moved profiles:
find / -name "*.yaotl" 2>/dev/null
grep -r "Operators {" /home /root /data 2>/dev/null  # Search for profile blocks

# If Team Server binary is running, check process command line:
ps aux | grep teamserver
# Look for: ./teamserver server --profile <path>

# Check recent file access:
stat /home/<user>/Havoc/profiles/havoc.yaotl
lsof | grep -i yaotl  # If profile is still open
```

**Expected output (CRITICAL if recovered):**
```yaml
Teamserver {
    Host = "0.0.0.0"
    Port = 40056
}

Operators {
    user "attacker" {
        Password = "SuperSecure123!"  ← OPERATOR CREDENTIAL
    }
}

Listeners "HTTP" {
    Port = 8080
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    uripath = "/api/inventory", "/api/status"
}

Demon {
    Sleep = 2
    Jitter = 15
    Obfuscation = "ekko"
}
```

**Forensic value:** Plaintext credentials, listener configuration, sleep behavior, evasion methods — everything needed to understand and hunt the deployment.

---

### Hunt 2: Examine Team Server SQLite Database

**Goal:** Recover full operational history (agent sessions, all commands executed, task results).

**Target:** Team Server host

**Commands:**

```bash
# Locate database:
find /home -name "havoc.db" -type f
find /data -name "havoc.db" -type f  # Docker
ls -la /root/.havoc/
ls -la /home/<user>/.havoc/

# Copy database for offline analysis (if analysis workstation available):
cp /home/<user>/.havoc/havoc.db /tmp/havoc.db

# Query database (if sqlite3 is installed):
sqlite3 /tmp/havoc.db

# Inside sqlite3:
.tables  # List tables
.schema  # Print schema
SELECT * FROM sessions;  # All agent sessions
SELECT * FROM tasks;  # All commands queued
SELECT * FROM listeners;  # All listener jobs
SELECT * FROM results LIMIT 10;  # Task output (first 10 rows)

# Timeline query (if timestamp column exists):
SELECT datetime(queued_time, 'localtime'), command, arguments FROM tasks ORDER BY queued_time;
```

**Expected output (example query results):**
```
sqlite> SELECT * FROM sessions;
id|hostname|username|process_id|architecture|integrity|os|timestamp
demon-2d9f1a42|CORP-WKS-001|corp\analyst|4024|x64|Medium|Windows 10|2025-12-18 14:24:05
demon-5f7a3c11|CORP-SRV-001|corp\administrator|6120|x64|High|Windows Server 2019|2025-12-18 14:25:15

sqlite> SELECT datetime(queued_time, 'localtime') AS time, session_id, command FROM tasks;
time|session_id|command
2025-12-18 14:24:12|demon-2d9f1a42|execute-assembly SharpUp.exe
2025-12-18 14:24:45|demon-2d9f1a42|token steal 5820
2025-12-18 14:25:02|demon-2d9f1a42|psexec \\CORP-SRV-001 cmd.exe
```

**Forensic value:** Complete adversary timeline, target inventory, command sequence, and lateral-movement chain.

---

### Hunt 3: Locate Generated Payloads

**Goal:** Recover Demon binaries to extract embedded C2 configuration (Team Server IP, port, callback URIs, process-injection targets).

**Target:** Operator workstation or Team Server build directory

**Commands:**

```bash
# On operator workstation:
find ~/ -name "*.exe" -newer "$(date -d '7 days ago' '+%Y-%m-%d')" -type f
find ~/Havoc/builds/ -type f  # Default payload output directory
find ~/Downloads -name "*.exe" -o -name "*.dll" -o -name "*.bin"  # Common download locations

# On Team Server (if building payloads there):
find /tmp -name "*.exe" -o -name "*.dll" -o -name "*.bin"
/var/log/havoc/  # Check for payload generation logs

# Extract strings from Demon binary (reveals C2 config):
strings demon-payload.exe | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+$"  # IP:port
strings demon-payload.exe | grep -E "^/.*" | head -20  # URIs
strings demon-payload.exe | grep -E "notepad|svchost|explorer"  # Injection targets
strings demon-payload.exe | grep -E "ekko|ziliean|foliage"  # Obfuscation method
```

**Expected output:**
```
192.168.1.100:8080
/api/inventory
/api/status
C:\Windows\System32\svchost.exe
C:\Windows\SysWOW64\svchost.exe
ekko
```

**Forensic value:** Confirms C2 infrastructure IP/port, callback URIs, and evasion method. Different binaries with same C2 endpoint suggest multiple targets in same engagement.

---

### Hunt 4: Analyze Operator Client Credentials

**Goal:** Extract operator credentials and Team Server connection details.

**Target:** Operator workstation

**Commands:**

```bash
# Locate operator credentials:
find ~/ -name "*.cfg" -type f  # Operator config files (alice.cfg, bob.cfg, etc.)
cat ~/.havoc/config.json  # Havoc client default config
find ~ -name "*havoc*" -type f  # Any Havoc-related files

# Extract Team Server IP and operator username:
cat alice.cfg | grep -E "teamserver|username"
cat bob.cfg | jq '.teamserver, .username'  # If JSON format

# Extract embedded certificates:
cat alice.cfg | grep -A 50 "BEGIN CERTIFICATE"  # Operator's mTLS cert
# Copy certificate to analyze:
cat alice.cfg | grep -A 50 "BEGIN CERTIFICATE" | openssl x509 -text -noout
# Look for CN (Common Name), Issuer, Validity period — may contain operator name or engagement ID
```

**Expected output:**
```
teamserver: 192.168.1.100:40056
username: alice
cert:
    CN = alice@operator.local (or generic "Havoc Operator")
    Issuer CN = havoc-ca (or similar)
    Validity: 2025-12-18 to 2026-12-18
```

**Forensic value:** Confirms Havoc deployment infrastructure (Team Server IP), operator identity, and client certificate validity (timeline).

---

### Hunt 5: Identify Team Server Process and Network Listeners

**Goal:** Confirm active Team Server deployment and extract listener configuration.

**Target:** Team Server host (live)

**Commands:**

```bash
# Check for running Team Server:
ps aux | grep -i "teamserver\|havoc"
netstat -tlnp | grep -E ":(8080|40056|443|80)"  # Common Havoc listener ports
ss -tlnp | grep -E "havoc|teamserver"  # Alternative to netstat

# Check open file handles:
lsof -c teamserver  # All files/ports opened by teamserver process
lsof -p <PID>  # Specific process ID

# Check database size (rough indicator of operational intensity):
du -sh /home/<user>/.havoc/havoc.db
du -sh /data/havoc.db  # Docker

# Check log file timestamps (recent activity):
stat /var/log/havoc/*.log
tail -100 /var/log/havoc/teamserver.log  # Recent log entries
```

**Expected output:**
```
root      1234  0.0  0.5  123456  12345 ?  Ss  14:20  0:05 ./teamserver server --profile profiles/havoc.yaotl
LISTEN    TCP  0.0.0.0:8080  (HTTP listener)
LISTEN    TCP  0.0.0.0:443   (HTTPS listener)
LISTEN    TCP  0.0.0.0:40056 (Operator console)
```

**Forensic value:** Confirms Team Server is actively running; listener ports reveal network IOCs; log timestamps show engagement timeline.

---

## Hunting on Target (Compromised Machine)

**Context:** These hunts target a compromised Windows machine running the Havoc Demon agent.

### Hunt 1: Identify Demon Binary via Sysmon Event 1 (Process Creation)

**Goal:** Locate Demon binary by searching for unusual parent-child process relationships and unsigned executables.

**Target:** Compromised Windows machine

**PowerShell (live response):**

```powershell
# Query Sysmon for all process creations in last 24 hours:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1
    StartTime = (Get-Date).AddDays(-1)
} | Select-Object -ExpandProperty Message | Out-File processes.txt

# Search for suspicious indicators:
# 1. Unsigned executables spawning child processes (typical Demon behavior)
Get-ChildItem C:\Users\*\Downloads\*.exe | ForEach-Object {
    if (-not (Get-AuthenticodeSignature $_).SignerCertificate) {
        Write-Host "Unsigned: $_"
    }
}

# 2. Executables in temp folders with legitimate process names (masquerading):
Get-ChildItem C:\Users\*\AppData\Local\Temp\*.exe | Where-Object {
    ($_.Name -like "*svc*" -or $_.Name -like "*note*" -or $_.Name -like "*explore*")
}

# 3. Query Prefetch for recent unusual executables:
Get-ChildItem C:\Windows\Prefetch\*.pf | Sort-Object LastWriteTime -Descending | Select-Object Name, LastWriteTime | head -20
```

**Sysmon-based hunt (if Sysmon query available):**

```xml
<!-- Sysmon config rule: detect unsigned executables creating child processes -->
<RuleGroup name="" groupRelation="or">
  <ProcessCreate onmatch="include">
    <Image condition="ends with">demon.exe</Image>
    <CommandLine condition="contains">C:\Users\</CommandLine>
  </ProcessCreate>
  <!-- Legitimate process spawning unexpected children (sacrificial injection) -->
  <ProcessCreate onmatch="include">
    <ParentImage condition="end with">notepad.exe</ParentImage>
    <Image condition="contains">cmd.exe</Image>
  </ProcessCreate>
</RuleGroup>
```

---

### Hunt 2: Identify Sacrificial Process Injection

**Goal:** Detect process injection by identifying unexpected child processes or suspicious process attributes.

**Target:** Compromised Windows machine

**PowerShell:**

```powershell
# Detect notepad.exe spawning child processes (red flag):
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -match 'ParentImage.*notepad.exe' -and
    $_.Message -match 'Image.*(cmd|powershell|svchost)'
} | Select-Object TimeCreated, Message

# Detect svchost.exe spawned by non-system process:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 1
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -match 'Image.*svchost.exe' -and
    $_.Message -match 'ParentImage.*(?!Services.exe|svchost.exe)'
} | Select-Object TimeCreated, Message

# Check process handle tree (live system):
# Look for notepad.exe, explorer.exe, svchost.exe with unexpected parent:
Get-Process | Where-Object {
    ($_.ProcessName -eq 'notepad' -or $_.ProcessName -eq 'explorer' -or $_.ProcessName -eq 'svchost') -and
    $_.Parent.ProcessName -ne 'explorer' -and $_.Parent.ProcessName -ne 'services'
}

# Alternative: use wmic (if Sysmon not available):
wmic process list /format:csv | findstr "ParentProcessId=<PID-of-demon>"
```

**Expected output (if injection detected):**
```
ParentImage: C:\Users\analyst\Downloads\demon-payload.exe
Image: C:\Windows\System32\notepad.exe
ProcessId: 5820
CommandLine: notepad.exe

---

ParentImage: C:\Windows\System32\notepad.exe
Image: C:\Windows\System32\cmd.exe
ProcessId: 6024
CommandLine: cmd.exe /c ipconfig
```

---

### Hunt 3: Detect Network Callbacks (HTTP/HTTPS Beaconing)

**Goal:** Identify Demon callback traffic via process-level network connections and periodic callback patterns.

**Target:** Compromised Windows machine (or network monitoring)

**Sysmon Event 3 (Network Connection):**

```powershell
# Query Sysmon for unusual HTTP/HTTPS connections from unexpected processes:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 3
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    # Legitimate processes shouldn't make HTTP connections
    $_.Message -match 'SourceIp.*(10\.|192\.|172\.)' -and  # To private IP (Team Server)
    $_.Message -match 'DestinationPort.*(8080|40056|443|80)' -and
    $_.Message -match 'SourceImage.*(?!chrome|firefox|iexplore)'  # Not browser
} | Select-Object TimeCreated, Message

# Extract callback intervals (beaconing pattern):
$connections = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 3
} | Where-Object {
    $_.Message -match 'DestinationIp.*(192\.168\.1\.100)'  # Team Server IP
}
$connections | ForEach-Object {
    [datetime]$_.TimeCreated | ForEach-Object { $_.ToString('HH:mm:ss') }
} | Sort-Object
# Output: Regular 2-3 second intervals indicate C2 beaconing
```

**Network-level hunt (via packet capture / IDS logs):**

```bash
# Extract HTTP callbacks from PCAP:
tcpdump -r capture.pcap "tcp.dst_port == 8080" -w c2_traffic.pcap

# Analyze with Zeek:
zeek -r c2_traffic.pcap http.zeek
cat http.log | grep -E "192.168.1.100|Team Server IP" | awk '{print $1, $8}' | sort | uniq -c
# Output: multiple connections at regular 2-3s intervals

# IDS/firewall logs:
grep "192.168.1.100:8080" firewall.log | awk '{print $1}' | sort | uniq -c
# High count (60+ per minute) indicates active C2
```

---

### Hunt 4: Detect Process Access to lsass.exe (Token Theft)

**Goal:** Identify credential-harvesting attempts via lsass.exe access.

**Target:** Compromised Windows machine

**Sysmon Event 10 (Process Access):**

```powershell
# Hunt for process access to lsass.exe with suspicious GrantedAccess:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 10
    StartTime = (Get-Date).AddDays(-7)
} | Where-Object {
    $_.Message -match 'TargetImage.*lsass.exe' -and
    ($_.Message -match 'GrantedAccess.*(0x1010|0x1438|0x1410)' -or  # Token access
     $_.Message -match 'GrantedAccess.*0x40[0-9A-F]{2}')  # Memory read
} | Select-Object TimeCreated, Message

# List source processes that accessed lsass:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 10
} | Where-Object {
    $_.Message -match 'TargetImage.*lsass.exe'
} | ForEach-Object {
    # Extract SourceImage from Message field
    [regex]::Matches($_.Message, 'SourceImage: (.+?) ') | ForEach-Object { $_.Groups[1].Value }
} | Sort-Object | Get-Unique
```

**Event Tracing for Windows (ETW) alternative (if Sysmon not available):**

```powershell
# Enable WMI event tracing for process creation:
wevtutil.exe clear-log "Microsoft-Windows-PowerShell/Operational"
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4688  # Process creation
    StartTime = (Get-Date).AddHours(-1)
} | Where-Object {
    $_.Message -match 'lsass\.exe|token|credential' -or
    $_.Message -match 'mimikatz|mimid|procdump|csfls'
} | Select-Object TimeCreated, Message
```

**Expected output (if token theft occurred):**
```
Event ID 10 (Sysmon - Process Access):
  UtcTime: 2025-12-18 14:24:25
  SourceImage: C:\Users\analyst\Downloads\demon-payload.exe
  TargetImage: C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1010  (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
  CallTrace: [...ntdll.dll...kernel32.dll...]
```

---

### Hunt 5: Prefetch File Analysis

**Goal:** Extract execution timeline and loaded modules from Prefetch.

**Target:** Compromised Windows machine

**PowerShell (using PECmd from Eric Zimmerman's tools):**

```powershell
# Download PECmd (Eric Zimmerman's Prefetch parser):
# https://ericzimmerman.github.io/#!index.md
# Then:

.\PECmd.exe -d "C:\Windows\Prefetch\" --csv "."

# PowerShell alternative (manual parsing):
$prefetchFile = "C:\Windows\Prefetch\demon-payload.exe-*.pf"
Get-Item $prefetchFile | Select-Object Name, LastAccessTime, LastWriteTime

# Extract execution count and timestamps:
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID = 32  # Prefetch file access (if logged)
} | Where-Object {
    $_.Message -match 'demon-payload.exe'
} | Select-Object TimeCreated
```

**Expected Prefetch output:**
```
Executable: C:\Users\analyst\Downloads\demon-payload.exe
Execution Times:
  Last Run: 2025-12-18 14:24:15 UTC
  Execution Count: 5
  
Loaded Files/Directories:
  C:\Windows\System32\kernel32.dll
  C:\Windows\System32\ntdll.dll
  C:\Windows\System32\notepad.exe
  C:\Users\analyst\AppData\Local\Temp\
```

---

### Hunt 6: Lateral Movement via SMB / PsExec

**Goal:** Detect lateral movement attempts to other hosts.

**Target:** Compromised machine (source of lateral movement)

**Sysmon Event 3 (Network Connection to SMB/445):**

```powershell
# Hunt for SMB connections to non-standard targets:
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ID = 3
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -match 'DestinationPort.*445' -and  # SMB
    $_.Message -match 'SourceImage.*(demon|notepad|svchost)'  # Compromised process
} | Select-Object TimeCreated, Message

# Security Event 5140 (SMB share access):
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 5140
    StartTime = (Get-Date).AddDays(-1)
} | Where-Object {
    $_.Message -match '(ADMIN\$|C\$|IPC\$)'  # Administrative shares
} | Select-Object TimeCreated, Message
```

**Event 7045 / Event 4697 (Service Creation — lateral movement indicator):**

```powershell
# Hunt for service creations (PsExec-style lateral movement):
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    ID = 7045  # Service installed (Sysmon alternative)
} | Where-Object {
    $_.TimeCreated -gt (Get-Date).AddDays(-7)
} | Select-Object TimeCreated, Message

# Security Event 4697 (same, alternative source):
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4697
} | Where-Object {
    $_.Message -match '(PSEXESVC|Admin\$)' -or
    $_.Message -match 'Service Name: [A-Z]{8,12}'  # Random service names
} | Select-Object TimeCreated, Message
```

**Expected output (if lateral movement detected):**
```
Event 5140 (SMB share access):
  ShareName: \\CORP-SRV-001\ADMIN$
  AccessMask: READ | WRITE | CREATE | DELETE
  ClientAddress: 10.0.1.50 (compromised machine)
  
Event 4697 (Service creation):
  ServiceName: PSEXESVC (or random, e.g., PUl0F8dA)
  ServiceFileName: C:\Windows\PSEXESVC.exe
  ServiceAccountName: SYSTEM
```

---

### Hunt 7: Registry Persistence Checks

**Goal:** Identify persistence mechanisms if operator deployed persistent agent.

**Target:** Compromised machine

**PowerShell:**

```powershell
# Check common persistence locations:
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Get-Member -MemberType NoteProperty | ForEach-Object { $_.Name }
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"

# Hunt for suspicious entries:
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Where-Object {
    $_ -match '\.exe' -and
    $_ -match '(demon|havoc|temp|downloads)' -ilike '*'
}

# Check services:
Get-Service | Where-Object {
    $_.DisplayName -match '(Demon|Havoc)' -or
    $_.Status -eq 'Running' -and $_.Name -match '^[A-Z]{8,12}$'  # Random names
}

# Alternative: Registry export for offline analysis:
reg export "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" run.reg
reg export "HKLM\System\CurrentControlSet\Services" services.reg
```

**Expected output (if persistence found):**
```
Name              Value
----              -----
DailyBackup       C:\Users\analyst\AppData\Local\Temp\demon-payload.exe
SecurityCheck     C:\Windows\System32\svchost-[random].exe
```

---

## Fleet-Wide Hunting (EDR/SIEM)

**Context:** Enterprise deployment across multiple endpoints. Use EDR or centralized logging.

### Cluster Detections by Network Behavior

**Goal:** Identify multiple compromised machines with synchronized beacon patterns.

**Query (Splunk/ELK):**

```
# Splunk: Detect multiple hosts making HTTP requests to same IP:port at regular intervals
source="sysmon" EventCode=3 DestinationPort=8080 DestinationIp="192.168.1.100"
| stats count by SourceIp, SourceProcessName
| where count > 50  # High frequency indicates beaconing

# Alternative: Time-series clustering
source="sysmon" EventCode=3 DestinationPort=8080
| timechart count by SourceIp
| where column > 60 per_minute  # 60+ connections per minute = C2 beacon
```

**Query (Microsoft Defender for Endpoint - KQL):**

```kusto
// Detect multiple machines connecting to same IP:port
DeviceNetworkEvents
| where RemotePort == 8080 and RemoteIPType == "Private"
| where InitiatingProcessName !in ("chrome.exe", "firefox.exe", "iexplore.exe")
| summarize by InitiatingProcessName, RemoteIP, DeviceName
| join kind=inner (
    DeviceNetworkEvents
    | where RemotePort == 8080
    | summarize ConnectionCount = count() by RemoteIP
    | where ConnectionCount > 100
) on RemoteIP
```

---

## Remediation

**Before acting on compromise:** Capture full memory dump, disk image, and network traffic for forensics.

### Immediate Actions

1. **Isolate affected machine(s)** from network (segment, firewall rules, or physical disconnect)
2. **Terminate Demon process(es)** via Task Manager or `taskkill /PID <PID> /F`
3. **Kill Team Server** connection (block IP:port at firewall)
4. **Revoke/change credentials** of affected users (assume all tokens stolen if lsass.exe was accessed)
5. **Disable SMB** on critical servers if lateral movement occurred (or apply network segmentation rules)

### Investigation & Cleanup

6. **Preserve evidence** before any cleanup:
   - Full memory dump: `\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll MiniDump <PID> <output.dmp>`
   - Disk image: Physical forensics workstation or disk imaging tool
   - Sysmon/event log export: `wevtutil epl "Microsoft-Windows-Sysmon/Operational" sysmon.evtx`

7. **Identify all compromised hosts** via:
   - Network segmentation/flow logs (which hosts connected to Team Server IP?)
   - Prefetch files (demon-payload.exe-*.pf across domain)
   - Lateral movement breadcrumbs (Event 5140 SMB access, Event 4697 service creation)

8. **Patch & remediate**:
   - Apply Windows security updates (particularly SMB, RPC)
   - Restore from clean backups (if available) or full OS rebuild
   - Deploy EDR agent to monitor for re-exploitation

9. **Hunt for persistence**:
   - Check registry Run keys, Services, Scheduled Tasks
   - Scan for additional Demon binaries in temp, Downloads, AppData
   - Verify Prefetch and MFT for hidden execution history

10. **Threat intel on Team Server**:
    - Reverse engineering any recovered Demon binary to extract Team Server IP:port
    - Check for additional operational infrastructure (relay servers, domains, C2 endpoints)
    - Correlate with other incident intel (other organizations hit by same Team Server IP?)

---

## Detection Gaps & Caveats

| Detection Gap | Reason | Mitigation |
|---|---|---|
| **Stager-only deployment (no full Demon binary on disk)** | Stager is 10-50 KB; full Demon loaded into memory only. Disk-based file-hash detection fails. | Deploy EDR with memory scanning; monitor stager binary hash/behavior; network-level C2 detection (beaconing pattern) |
| **Custom YAOTL profile mimics legitimate traffic** | Operator can customize User-Agent, URIs, headers, response format to match environment. Network signature detection fails. | Process-level hunting (Sysmon) more reliable than network-layer; endpoint behavior analysis (sacrificial process injection) is harder to evade |
| **Sacrificial process injection (e.g., notepad.exe)** | Demon hides in notepad; notepad's legitimate process name evades simple process-name blacklisting. Parent-child relationship still visible in Sysmon. | Monitor for unexpected child processes of legitimate utilities (notepad→cmd is red flag); Sysmon Event 8 (CreateRemoteThread) if injection occurs |
| **Sleep obfuscation (Ekko, Ziliean, FOLIAGE)** | Memory dumping during sleep shows encrypted .text section, unrecognizable as malware. | Monitor for VEH (Vectored Exception Handler) installation; CPU exception patterns; process wake-up timing (encrypted code + exception handler = distinctive) |
| **Compiled-in Team Server IP** | Operator's C2 infrastructure hardcoded in binary. If Demon binary is never recovered, C2 IP remains hidden. | Network-level detection (identify callback traffic pattern); assume Demon will eventually callback; correlate timeline with data exfil or lateral movement |

---

## Recommended Tools & Queries

### Live Triage

- **Sysmon:** Windows event logging with high process-creation/network-connection detail
- **Velociraptor:** Endpoint visibility platform; query Prefetch, registry, process list, network connections
- **osquery:** Cross-platform endpoint monitoring (if Linux agents deployed)
- **wmi Explorer:** Query WMI event subscriptions (if external C2 modules used)

### Forensics

- **PECmd.exe** (Eric Zimmerman): Parse Prefetch files for execution timeline
- **MFTExplorer:** NTFS Master File Table analysis for file creation/modification
- **volatility3 / AVML:** Memory dump analysis (look for injected code, unencrypted Demon sections)
- **Zeek / Suricata:** Network PCAP analysis for HTTP C2 callback patterns

### Threat Hunting

- **Splunk/ELK:** Centralized log aggregation, C2 beaconing detection
- **YARA rules:** Static malware detection (limited for Havoc due to per-binary uniqueness, but useful for stager detection)
- **Network flow analysis:** Identify periodic outbound connections to suspicious IPs (Team Server candidates)

---

