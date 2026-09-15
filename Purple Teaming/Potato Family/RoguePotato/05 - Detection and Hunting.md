# RoguePotato — Detection and Hunting

## Hunting Priority table

| Signal | Evasion Survivability | Prevalence | Rank |
|---|---|---|---|
| **Outbound RPC connection from service account to external IP on non-standard port** | Very High — requires network blocking or obscuring the connection entirely. | **RARE** in legitimate operation. | 🔴 **#1** |
| **Sysmon Event 1: Service account → SYSTEM-context child process** | Very High — structural, cannot hide without abandoning exploit. | **RARE**. | 🔴 **#2** |
| **Firewall Event 5156: Outbound RPC connection to external/redirector IP** | Very High — requires firewall bypass or proxy spoofing. | Medium (depends on firewall logging). | 🟠 **#3** |
| **Redirector IP in RoguePotato command line (`-r <IP>`)** | Medium — operators may obfuscate IP, but the pattern is identifiable. | Medium (depends on operator opsec). | 🟠 **#4** |
| **RoguePotato.exe binary name** | **Very Low** — trivially renamed; filename matching is ineffective. | Low (most operators rename). | 🟡 **#5** |
| **WER service making unexpected outbound RPC calls** | High — WER's normal behavior is local-only; any external RPC is suspicious. | Low (depends on EDR capability). | 🟡 **#6** |

---

## Hunting on Source

### Network-based hunt: Outbound RPC to external IP

**This is the PRIMARY RoguePotato indicator.**

```powershell
# Hunt for outbound RPC connections on non-standard ports from service accounts
Get-NetTCPConnection -State Established |
  Where-Object { 
    $_.RemoteAddress -notmatch '127.0.0.1|192.168.*|10\.' -and
    $_.RemotePort -gt 1024 -and
    $_.OwningProcess -in @(Get-Process -Name 'svchost','mssqlserver','mysql' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
  } |
  ForEach-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Host "ALERT: Service account RPC to external IP: $($process.Name) → $($_.RemoteAddress):$($_.RemotePort)"
    $_
  }
```

### Firewall-based hunt: Event 5156 (Outbound connection)

```powershell
# Hunt for firewall allowed outbound connections from service processes
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5156]]" |
  Where-Object {
    $remoteAddr = $_.Properties[5].Value
    $sourcePort = $_.Properties[3].Value
    # Flag connections to external IPs from service account contexts
    if ($remoteAddr -notmatch '127.0.0.1|192.168.*|10\.') {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="Application";Expression={$_.Properties[0].Value}}, @{Name="RemoteAddress";Expression={$_.Properties[5].Value}}, @{Name="RemotePort";Expression={$_.Properties[6].Value}}
```

### Sysmon Event 3 (Network Connection)

```powershell
# Hunt for Sysmon network-connection events from service processes to external IPs
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=3]]" |
  Where-Object {
    $destIP = $_.Properties[8].Value
    if ($destIP -notmatch '127.0.0.1|192.168.*|10\.') {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="DestinationIp";Expression={$_.Properties[8].Value}}, @{Name="DestinationPort";Expression={$_.Properties[9].Value}}
```

### Command-line hunt: Redirector IP exposure

```powershell
# Hunt for RoguePotato command lines with `-r` flag (redirector IP)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  Where-Object { $_.Properties[10].Value -match '-r\s+\d+\.\d+\.\d+\.\d+' } |
  ForEach-Object {
    $cmdLine = $_.Properties[10].Value
    Write-Host "ALERT: RoguePotato command with redirector IP: $cmdLine"
    $_
  }
```

### Process tree hunt: Service account → SYSTEM child

```powershell
# Hunt for unexpected process elevation (same as PrintSpoofer/JuicyPotato)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='User']='NT AUTHORITY\SYSTEM']]" |
  Where-Object {
    $parentImage = $_.Properties[20].Value
    # Flag if parent is not a typical system process
    if ($parentImage -notmatch 'System32\\(svchost|services|csrss|lsass|explorer)\.exe' -and 
        $parentImage -match 'RoguePotato|potato\.exe') {
      $_
    }
  }
```

---

## Hunting on Target

### Network-based hunt: Outbound RPC on target

```powershell
# Hunt for outbound RPC connections (same as source, but executed on target)
Get-NetTCPConnection -State Established |
  Where-Object { 
    $_.RemoteAddress -notmatch '127.0.0.1|192.168.*|10\.' -and
    $_.RemotePort -gt 1024
  } |
  Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

### Firewall log hunt: Event 5156/5158 (connection open/close)

```powershell
# Hunt for firewall allowed outbound connections
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=5156 or EventID=5158]]" |
  Where-Object {
    $remoteAddr = $_.Properties[5].Value
    if ($remoteAddr -notmatch '127.0.0.1|192.168.*|10\.') {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="EventID";Expression={$_.Id}}, @{Name="RemoteAddress";Expression={$_.Properties[5].Value}}
```

### Sysmon Event 1: Unexpected SYSTEM process

```powershell
# Hunt for Sysmon Event 1 with SYSTEM child (same as PrintSpoofer/JuicyPotato)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='User']='NT AUTHORITY\SYSTEM']]" |
  Select-Object TimeCreated, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="ParentImage";Expression={$_.Properties[20].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
```

### Event 4688: Process creation with SYSTEM

```powershell
# Windows Security Event 4688 with SYSTEM spawned
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='TargetUserName']='NT AUTHORITY\SYSTEM']]" |
  Select-Object TimeCreated, @{Name="NewProcessName";Expression={$_.Properties[5].Value}}
```

---

## Hunting on Target (Extended)

### Named-pipe enumeration: RoguePotato-specific pipes

RoguePotato creates a **local named pipe** to receive the relayed SYSTEM token. By default, the pipe name is derived from the tool's own name, but can be randomized with the `-z` flag or customized with `-p <pipe_name>`.

**Default pipe names to hunt (per source code verification against `antonioCoco/RoguePotato`):**
- `RoguePotato` (default)
- `RoguePotato_<random>` (occasionally)
- Randomized names if `-z` flag is used (8+ hex chars, no fixed pattern)

**Hunt for pipe creation via registry:**

```powershell
# Query the Devices registry for named-pipe instantiation
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\npfs\Instances" -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty "*"

# Alternative: Use Process Monitor traces or Sysmon 17 (PipeEvent - Pipe Created)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=17]]" |
  Where-Object {
    $pipeName = $_.Properties[4].Value
    if ($pipeName -match '(?i)roguepotato|potato|relay') {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="PipeName";Expression={$_.Properties[4].Value}}, @{Name="Image";Expression={$_.Properties[1].Value}}
```

**Named-pipe connection hunt (Sysmon 18: PipeEvent - Pipe Connected):**

```powershell
# Hunt for processes connecting to suspicious named pipes
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=18]]" |
  Where-Object {
    $pipeName = $_.Properties[3].Value
    # Flag connections to potato-family pipes
    if ($pipeName -match '(?i)roguepotato|remcom|potato|relay' -or
        ($pipeName -match '^\w{8,}$' -and $_.Properties[1].Value -match 'services\.exe')) {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="PipeName";Expression={$_.Properties[3].Value}}, @{Name="ConnectingImage";Expression={$_.Properties[1].Value}}
```

**Limitation:** If RoguePotato is invoked with `-z` (random pipe name) or `-p <custom>`, pipe names become non-deterministic. However, **the WER service accessing an unusual pipe at all** is still suspicious, especially when paired with other signals.

### COM+ service artifacts

RoguePotato triggers COM+ services (Windows Error Reporting or other RPC services) to initiate the relay. Hunt for evidence of COM+ service activation and configuration changes.

**COM+ service enumeration (Windows Error Reporting):**

```powershell
# Query WER service registration
Get-WmiObject Win32_Service -Filter "Name='WER'" |
  Select-Object Name, State, StartMode, ProcessId, ExecutablePath

# Check for unexpected WER service state changes in the event log
Get-WinEvent -LogName 'System' -FilterXPath "*[System[EventID=7040 or EventID=7041 or EventID=7042 or EventID=7043]]" |
  Where-Object { $_.Message -match 'WER|Windows Error Reporting' } |
  Select-Object TimeCreated, ID, Message

# Query WER registry configuration
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WER" -ErrorAction SilentlyContinue |
  Select-Object DisplayName, ImagePath, ObjectName, Start, Type
```

**RoguePotato-triggered WER process spawning:**

```powershell
# Hunt for WER service spawning unexpected child processes
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='ParentImage']='C:\\Windows\\System32\\wer.exe']]" |
  Select-Object TimeCreated, @{Name="ParentImage";Expression={$_.Properties[20].Value}}, @{Name="Image";Expression={$_.Properties[10].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
```

### SeImpersonate privilege auditing

SeImpersonate is the precondition for all Potato-family exploits. Hunt for which accounts hold this privilege and track changes.

**Enumerate accounts with SeImpersonate:**

```powershell
# Check current process privileges
whoami /priv | Find /I "SeImpersonate"

# Query secedit output for privilege grants
secedit /export /cfg $env:TEMP\secedit_export.inf -areas USER_RIGHTS
Select-String "SeImpersonatePrivilege" $env:TEMP\secedit_export.inf

# More direct: Query via PowerShell
$privs = @()
Get-Process | Where-Object { $_.ProcessName -match 'svchost|mysqld|mssqlserver|w3wp|tomcat' } | ForEach-Object {
  try {
    $handle = [System.Diagnostics.Process]::GetProcessById($_.Id)
    # Direct privilege query requires Win32 API or accesschk.exe
    # Fallback to visual inspection via Process Explorer
  } catch { }
}

# Alternative: Use accesschk.exe (Sysinternals) from your own host
# accesschk.exe -nobanner -accepteula "\<targethost>\pipe\lsass" 2>&1 | findstr SeImpersonate
```

**Hunt for privilege escalation events (Event 4673 — audit on failure; Event 4672 — token privilege used):**

```powershell
# Event 4672: Special privileges assigned to new logon (background: triggers when SYSTEM token is created)
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4672]]" |
  Select-Object TimeCreated, @{Name="SubjectUserName";Expression={$_.Properties[1].Value}}, @{Name="LogonGUID";Expression={$_.Properties[3].Value}}, Message

# Event 4673: Privileged service called (if you audit "Use of Privileges")
Get-WinEvent -LogName 'Security' -FilterXPath "*[System[EventID=4673]]" |
  Where-Object { $_.Message -match 'SeImpersonate' } |
  Select-Object TimeCreated, Message
```

**Timeline-building: Correlate secedit output changes with Potato-family exploitation:**

```powershell
# Baseline SeImpersonate holders before and after suspected compromise
# If a new service account acquired SeImpersonate, hunt when/by what process
Get-EventLog Security -After (Get-Date).AddDays(-7) -InstanceId 4717, 4718 |
  Where-Object { $_.Message -match 'SeImpersonate' } |
  Select-Object TimeGenerated, Message
```

### Process injection and token impersonation signatures

RoguePotato's token impersonation occurs in kernel space (via Windows' token-impersonation APIs, not visible in ETW by default), but the resulting **parent-child process relationship** and **token access patterns** can be detected.

**Indirect signature: Service account spawning SYSTEM child (Sysmon 1 + Token context):**

```powershell
# Correlation: if `services.exe` (or a service account) spawns SYSTEM-context child rapidly,
# paired with RPC network traffic to an external IP, it's a high-confidence Potato match
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  Where-Object {
    $user = $_.Properties[11].Value  # User context
    $ppid = $_.Properties[21].Value  # Parent Process ID
    $image = $_.Properties[3].Value  # Image path
    if ($user -match 'NT AUTHORITY\\SYSTEM' -and ($image -match 'cmd|powershell|rundll' -or $_.Properties[20].Value -match 'services\.exe')) {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="Image";Expression={$_.Properties[3].Value}}, @{Name="User";Expression={$_.Properties[11].Value}}, @{Name="CommandLine";Expression={$_.Properties[10].Value}} |
  Sort-Object TimeCreated -Descending | Select-Object -First 20
```

**Token impersonation detection via kernel trace (EventLog-based, requires ETW trace capture):**

```powershell
# ETW trace to capture token impersonation calls (requires admin + ETW controller setup)
# This is NOT a post-fact hunt, but can be enabled proactively for high-value targets
# Providers: Microsoft-Windows-Security-Auditing, Microsoft-Windows-Kernel-TokenCore

# Alternative: AMSI-based detection if RoguePotato source is staged locally
# (AMSI can hook API calls if instrumenting .NET at runtime, but RoguePotato is native C++)
```

**Memory forensics signature (volatile, requires memory dump):**

```
RoguePotato characteristics in a MEMORY DUMP:
1. Strings in the binary's heap/sections:
   - "RoguePotato" or randomized pipe name
   - `\pipe\<name>` construction strings
   - CLSID GUIDs (default {6B3B8D23-FA8D-40B9-8DBD-B950333E2C52} for WER or custom)
   - "UuidCreate" or RPC UUID generation constants

2. Handles in process object table:
   - An open named-pipe handle (FILE_OBJECT) to the pipe created by RoguePotato
   - Active RPC client socket connections (TCP/UDP)

3. .data section signatures:
   - hardcoded redirector IP/port (if not passed via command line)
```

### Redirector setup artifacts on source

**Source-host hunting for RoguePotato's redirector and relay infrastructure:**

**Chisel (common redirector):**

```powershell
# Hunt for Chisel process/binary on the attacker's machine
Get-Process -Name chisel -ErrorAction SilentlyContinue | Select-Object Id, ProcessName, CommandLine

# Hunt Chisel on disk
Get-ChildItem -Path "C:\", "C:\Temp", "C:\Users\*\AppData\Local\Temp" -Recurse -Filter "*chisel*" -ErrorAction SilentlyContinue

# Check for Chisel listening ports (server mode, port 9999 or custom)
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in @(9999, 8080, 5000, 4444) } |
  Select-Object LocalAddress, LocalPort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}}

# Hunt for Chisel in process memory or command line (history)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=1]]" |
  Where-Object { $_.Properties[10].Value -match '(?i)chisel|server.*9999' } |
  Select-Object TimeCreated, @{Name="CommandLine";Expression={$_.Properties[10].Value}}
```

**Custom RPC relay listener:**

```powershell
# Hunt for raw listening sockets on ephemeral ports + unusual process
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -gt 1024 -and $_.LocalPort -lt 65535 } |
  Select-Object LocalAddress, LocalPort, @{Name="OwningProcess";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Name}} |
  Where-Object { $_.OwningProcess -notmatch '^(svchost|explorer|chrome|firefox|outlook)$' }
```

**Tunneling evidence (SSH, VPN, proxy):**

```powershell
# Hunt for SSH connections that might be tunneling RoguePotato traffic
Get-Process -Name ssh, putty, plink -ErrorAction SilentlyContinue |
  Select-Object Id, ProcessName, CommandLine

# Check SSH config for port forwarding
Get-Content $env:USERPROFILE\.ssh\config -ErrorAction SilentlyContinue | Select-String "LocalForward|RemoteForward"

# Hunt for proxy or VPN tools paired with RoguePotato execution
Get-Process -Name 'WireGuard', 'openvpn', 'tun2socks', 'proxychains' -ErrorAction SilentlyContinue
```

### Windows Registry artifacts for WER and COM+ configuration

RoguePotato may modify or query COM+ registry configuration to select a target service or validate its presence. Hunt for unexpected registry access patterns.

**WER registry keys to monitor:**

```powershell
# Query WER's disabled status and configuration
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\Windows Error Reporting" -ErrorAction SilentlyContinue |
  Select-Object -Property * | Format-List

# Check Event Viewer log registry (if WER publishes events, check if they're logged)
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autolog\DiagLog" -ErrorAction SilentlyContinue

# Hunt for recent modifications to COM+ service registry keys
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WER" |
  Select-Object LastWriteTime | Where-Object { (Get-Date) - $_.LastWriteTime -lt (New-TimeSpan -Hours 24) }
```

**Registry modification hunting (Sysmon 12/13: Registry Event):**

```powershell
# Hunt for registry modifications under HKLM:\SYSTEM\CurrentControlSet\Services\WER
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath "*[System[EventID=12 or EventID=13]]" |
  Where-Object {
    $targetObject = $_.Properties[4].Value
    if ($targetObject -match 'WER|COM\+|Windows Error Reporting') {
      $_
    }
  } |
  Select-Object TimeCreated, @{Name="TargetObject";Expression={$_.Properties[4].Value}}, @{Name="Details";Expression={$_.Properties[5].Value}}
```

---

## Evasion-resistant signals: Ranking by survivability

Not all detection signals are created equal. This section explicitly ranks which hunting approaches survive which RoguePotato evasion techniques, based on the tool's mechanics and verified against `antonioCoco/RoguePotato` source.

### Signals that survive binary renaming (`-p`, `-z`)

| Signal | Evasion Survives | Why |
|---|---|---|
| **Outbound RPC to external IP** | ✅ **YES** | The network traffic is independent of binary name; operator's relay infrastructure remains visible. |
| **WER service initiating outbound RPC** | ✅ **YES** | WER is Windows-native; RoguePotato triggers it regardless of the tool binary's name or pipe. |
| **Service account → SYSTEM process** | ✅ **YES** | The process tree and token context are structural; renaming the parent/child binary doesn't hide the escalation. |
| **Pipe name (`-p`, `-z`)** | ❌ **NO** | Trivially renamed or randomized; non-deterministic hunt. |
| **Command-line pattern (`-r`)** | ❌ **NO** | Can be obfuscated; operator may hide the redirector IP in a config file instead of CLI. |

### Signals that survive operator infrastructure changes (proxy, VPN, encrypted tunnel)

| Signal | Evasion Survives | Why |
|---|---|---|
| **Firewall Event 5156 (outbound connection)** | ✅ **Partially** | Network monitoring catches the *connection*, but not necessarily the *destination* if tunneled. Requires deep-packet inspection (DPI) or network flow analysis. |
| **Zeek/NetFlow detecting RPC handshake** | ✅ **YES** | RPC protocol handshake is visible at L4; encryption hides payload but not connection metadata (source, destination, port, timing). |
| **Process tree (service → SYSTEM)** | ✅ **YES** | Local host process events are independent of network routing. |
| **Named-pipe creation (Sysmon 17/18)** | ✅ **YES** | Local kernel event; proxy doesn't hide local pipe I/O. |
| **SEImpersonate privilege audit (Event 4672)** | ✅ **YES** | Kernel-level event; structural to token impersonation. |

### Signals MOST resistant to evasion (rank by unbypassable mechanics)

**Rank 1: Structural process tree (service account → SYSTEM child)**
- **Why:** Requires token impersonation and process creation, both kernel-level Windows primitives. Can't hide without changing the fundamental attack vector.
- **Caveat:** Only detectable if you have Sysmon 1 or EDR agents logging process creation. Vanilla Windows Event 4688 (depends on audit policy) may not always fire.
- **Bypass:** Operator runs exploit as SYSTEM already (not applicable for Potato-family's entire purpose).

**Rank 2: WER service + outbound network connection (correlation)**
- **Why:** WER is a Windows-native service. Operator doesn't control WER; RoguePotato must coerce it. Combined with outbound RPC, this is a high-confidence indicator.
- **Caveat:** Requires both Sysmon 3 (network connection) and WER process tracking.
- **Bypass:** Operator could patch/remove WER or use a different RPC target service, but any RPC target must still make outbound calls.

**Rank 3: Named-pipe creation + WER service**
- **Why:** Named pipes are kernel-level; RoguePotato's local-RPC endpoint (the pipe) is observable at OS level.
- **Caveat:** Only detectable via Sysmon 17/18; not visible in vanilla Windows logs.
- **Bypass:** Operator can randomize or customize the pipe name, but Sysmon still logs the creation event tied to WER's process context.

---

## Cross-linking and related forensics

### SeImpersonate privilege mechanics

For a detailed explanation of the `SeImpersonate` privilege, its requirements, and how Windows token impersonation works at the kernel level, see **`Windows/05 - Users, Groups & Authentication.md`** (Token Impersonation section). This Potato Family page assumes familiarity with that foundational content.

### Lateral movement and persistence following Potato exploitation

Once an operator achieves SYSTEM via Potato-family tools, the next phase is typically:
1. **Credential dumping** (Mimikatz, secretsdump, etc.) — see `Purple Teaming/Mimikatz/sekurlsa/` and `Purple Teaming/Impacket/secretsdump/`.
2. **Persistence creation** — see `Windows/10 - Persistence Mechanisms.md` for registry-run, scheduled-task, and service-based persistence options.
3. **Lateral movement** — see `Windows/12 - Lateral Movement.md` for pass-the-hash, over-pass-the-hash, and token-forwarding techniques enabled by SYSTEM context.

This file intentionally does not re-derive those signatures; refer to the cross-linked pages for the detection angles specific to post-Potato activity.

### Network monitoring and relay detection

For a detailed guide to detecting RPC relay traffic, named-pipe access, and NTLM relay patterns in general, see **`Windows/Threat Landscape and Playbooks/RPC and NTLM Relay Playbook.md`** (if it exists) or **`Purple Teaming/Impacket/ntlmrelayx/`** for the broader NTLM-relay detection context that RoguePotato's relay mechanism shares.

---

## Timeline building: End-to-end RoguePotato incident reconstruction

**Scenario:** You've detected an outbound RPC connection from MSSQL service account to an external IP. Follow this timeline-building workflow to confirm RoguePotato exploitation and establish time-of-compromise.

**Steps:**

1. **Identify the suspicious network connection** (Firewall Event 5156 or Sysmon Event 3)
   - Record timestamp (T0).
   - Record source service account (MSSQL, IIS, etc.).
   - Record destination IP/port (redirector).

2. **Correlate to process tree on the target** (Sysmon Event 1, within ±5 seconds of T0)
   - Hunt for SYSTEM-context child spawned within 5 seconds of T0.
   - Parent should be `services.exe` or the service account's own service host.

3. **Cross-check WER service activity** (Sysmon Event 1, parent = WER)
   - Did WER's process (`wer.exe` or the WER service host) spawn around T0?
   - This confirms RoguePotato coerced WER.

4. **Examine named-pipe creation** (Sysmon Event 17/18, or registry, ±2 seconds of T0)
   - Did the RoguePotato process or a service create a named pipe matching the tool's default name or a randomized pattern?
   - Tie this to WER's process ID.

5. **Backtrack to the source / redirector machine** (if accessible)
   - Hunt for Chisel or custom relay listener on the attacker's infrastructure (ports 9999, 8080, etc.).
   - Examine firewall rules on the redirector for inbound RPC traffic from the target.
   - Check for SSH tunnels or VPN connections that may have been established prior to RoguePotato invocation.

6. **Identify the attacker's initial access** (pre-RoguePotato)
   - RoguePotato assumes code execution as a service account already.
   - Hunt backward for the initial compromise: web-app exploitation (IIS), SQL injection (MSSQL), WinRM brute-force, etc.
   - See `Windows/Threat Landscape and Playbooks/` for playbooks on those access vectors.

7. **Establish time-to-SYSTEM**
   - T0 (network connection + process tree) = time RoguePotato escalated to SYSTEM.
   - Any SYSTEM-context commands or credential dumps AFTER T0 are post-escalation activity.

**Example timeline (all times UTC):**

```
2024-11-15 14:23:00 — IIS w3wp.exe process created (initial web-app compromise, external attacker)
2024-11-15 14:24:30 — RoguePotato.exe/jp.exe staging/download to C:\Temp (staged binary)
2024-11-15 14:25:15 — RoguePotato invoked with -r 203.0.113.42:9999 (outbound RPC connection initiated)
2024-11-15 14:25:16 — WER service spawns child process (RoguePotato coerced WER)
2024-11-15 14:25:17 — Named pipe "RoguePotato" created and connected
2024-11-15 14:25:18 — cmd.exe spawned as SYSTEM (escalation complete, T0)
2024-11-15 14:25:30 — Mimikatz.exe spawned as SYSTEM (post-escalation credential dump)
```

---

## Fleet-wide sweep

**RoguePotato is highly detectable due to network traffic.**

```powershell
# Splunk query for RoguePotato indicators across the fleet
index=sysmon EventID=3 OR index=firewall EventID=5156
  | where RemoteAddress NOT IN ("127.0.0.1", "192.168.*", "10.*")
  | where RemotePort > 1024
  | stats count by host, Image, RemoteAddress, RemotePort
  | where count > 0
```

**Also hunt for suspicious outbound RPC specifically:**

```powershell
# NetFlow / Zeek-based hunt for RPC traffic to external IPs
index=zeek destination != 127.0.0.1 AND destination NOT IN ("192.168.*", "10.*")
  | where service="rpc" OR port=9999 OR port=135
  | stats count by source, destination, destination_port
```

---

## Detection evasion mitigation

### 1. Network-based detection (strongest)

**Mitigation:** Deploy network monitoring (Zeek, NetFlow, firewall logs) to detect outbound RPC connections from service accounts to external IPs.

```
Alert if:
  - Source Process: Service account (MSSQL, WinRM, etc.)
  - Destination: External IP (not in private ranges)
  - Port: Unusual RPC port (not 135, 445)
  - Protocol: RPC handshake followed by brief connection
```

### 2. Firewall-based blocking

**Mitigation:** Implement firewall rules that block outbound RPC from service accounts to external IPs.

```
Rule: Block outbound TCP from MSSQL/WinRM service accounts to Internet
Port: >1024 (ephemeral range)
```

### 3. Process tree enforcement (EDR)

**Mitigation:** Alert on unexpected service account → SYSTEM child process spawn.

### 4. Redirector-cost mitigation

**Mitigation:** Require attackers to set up and expose a redirector machine, which creates operational burden and additional attack surface (redirector machine itself can be compromised/detected).

---

## RoguePotato vs. other Potato tools: Detection comparison

| Signal | PrintSpoofer | JuicyPotato | RoguePotato |
|---|---|---|---|
| **Process tree** | spoolsv.exe → child (distinctive) | Variable COM service → child (ambiguous) | Service account → child (expected) + network RPC |
| **Network traffic** | None (local-only) | None (local-only) | **Outbound RPC to redirector (highly visible)** |
| **Detectability** | High (specific parent) | Medium (variable parent) | **Very High (network traffic is smoking gun)** |
| **CLSID/GUID exposure** | No | Yes (in command line) | No (uses default WER or specified CLSID) |

**RoguePotato is the easiest to detect** due to network-observable traffic. Defenders should prioritize network monitoring for this tool.

---

## Summary

**RoguePotato detection is network-centric:**

1. **Primary hunt:** Outbound RPC connections from service accounts to external/redirector IPs (Firewall 5156, Zeek, NetFlow).
2. **Secondary hunt:** Command-line exposure of redirector IP (`-r <IP>` flag in Sysmon 1).
3. **Tertiary hunt:** Unexpected service account → SYSTEM process spawn (same as PrintSpoofer/JuicyPotato).

**Evasion resistance:**
- **Network blocking:** Very difficult; RPC relay requires external network connectivity.
- **Proxy/VPN redirection:** Possible but adds operational complexity.
- **Binary rename:** Ineffective; network traffic is the primary indicator.
- **Redirector IP obfuscation:** Possible (operators may use DNS, proxies) but still network-observable.

**RoguePotato's Achilles' heel is its network requirement.** Unlike PrintSpoofer/JuicyPotato (local-only, stealthy), RoguePotato's network traffic is inherently observable. Defenders with network monitoring in place have a significant advantage against this tool.
