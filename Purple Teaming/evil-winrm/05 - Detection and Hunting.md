# evil-winrm — Detection and Hunting

Hunting for evil-winrm usage focuses on **WinRM session artifacts** — the continuous event-log chain that distinguishes this tool from single-command executions like `psexec.py` or `wmiexec.py`. Because evil-winrm has no built-in evasion flags (unlike psexec's `-service-name` or wmiexec's `-silentcommand`), the signals are relatively invariant, though they can still be suppressed by disabling WinRM logging entirely (a noisy operational change that itself is detectable).

## Contents
- [Hunting Priority Table](#hunting-priority-table)
- [Hunting on Source (Attacker's Machine)](#hunting-on-source-attackers-machine)
- [Hunting on Target (Victim's Machine)](#hunting-on-target-victims-machine)
- [Fleet-Wide / Scaled Hunting](#fleet-wide--scaled-hunting)
- [Remediation & Response](#remediation--response)

---

## Hunting Priority Table

Ranked by invariant strength (which signals survive evasion/customization attempts). evil-winrm has no built-in evasion flags equivalent to psexec's `-service-name` or `-file`, so **all signals are equally strong** — the only way to suppress them is to disable WinRM logging entirely (a very visible operational change).

| Priority | Signal | Survives Evasion | Source | Confidence | Notes |
|---|---|---|---|---|---|
| **1 (Highest)** | WinRM Operational Event **15** (WSManCreateShell) + Event **91** (WSManCloseShell) pair | Yes — part of WinRM protocol itself, not spoofable without disabling WinRM logging entirely | Target host (WinRM Operational log) | Very High | A WinRM session lifecycle is **required** for evil-winrm to function. This pair signals a persistent remote shell session (not a single-command execution). Presence of both 15 and 91 with a time gap ≥ 1 second strongly indicates an interactive session. |
| **2** | Security Event **4624** (Type 3 — Network Logon) to the same user within seconds of WinRM Event 15 | Yes — logon is part of WinRM protocol | Target host (Security log) | Very High | Each WinRM session requires one logon. Temporal correlation with Event 15 is tight (usually <1 sec). One logon with many subsequent WinRM Event 33 commands is the session-reuse pattern. |
| **3** | WinRM Operational Event **33** (WSManOperationCommand) — multiple events for the same session/runspace | Yes — required for command execution | Target host (WinRM Operational log) | Very High | Multiple Event 33 entries (2+) for the same WinRM session indicate a multi-command session. Absence suggests a single-command execution (`psexec.py` equivalent) instead of evil-winrm's persistent shell. |
| **4** | Sysmon Event **1** (Process Create) — PowerShell spawning unexpected child processes within 1–5 seconds of WinRM Event 33 | Yes — the child process is a normal Windows executable | Target host (Sysmon log) | High | Evil-winrm doesn't spawn processes directly (they're spawned from PowerShell inside the runspace), so correlation is temporal, not parental. A `whoami.exe` process appearing shortly after WinRM Event 33 suggests a command was executed in the remote runspace. |
| **5** | Security Event **4688** (Process Creation) — PowerShell or its child processes, with command-line auditing enabled | Yes (if child process creation is happening, which is typical for many commands) | Target host (Security log) | Medium-High | Captures the exact command text if available. Sysmon 1 is superior for this (more detailed) if both are available. |
| **6** | **PowerShell Script Block Logging** (Event **4104**) — full PowerShell command text from a remote session | Yes | Target host (PowerShell Operational log) | High | Requires non-default Group Policy enablement. If enabled, directly captures every PowerShell command executed in the remote runspace. This is the **richest operational evidence** (exact commands) but depends on PSBloggin being on. |
| **7** | **Firewall inbound rule** — persistent TCP connection to port 5985/5986 from an external IP lasting minutes/hours | Yes | Firewall / IDS logs | Medium | Long-duration connections to WinRM ports are anomalous for most environments. Stateless detection systems may log individual packets rather than flows, making this signal noisier than event logs. |
| **8** | **Zeek HTTP logs** — repeated POST requests to `/wsman` endpoint with SOAP/PSRP payload, all from one source IP in a short time window | Yes (protocol structure is non-spoofable) | Network (Zeek, Suricata, NetWitness) | Medium-High (if traffic is in plaintext HTTP; HTTPS hides payload) | HTTPS (5986) encrypts the payloads, so Zeek can only see TCP-level patterns, not protocol detail. HTTP (5985) is cleartext; SOAP payload is visible and parseable. |
| **9** | **Session log file** (if operator used `-l` flag) — `evil-winrm_<timestamp>.log` in the current working directory | No — specific to evil-winrm with `-l` flag | Attacker's machine (file system) | Very High (if available) | Complete transcript of the remote session, including all commands and output. Only present if the `-l` flag was used (uncommon in real operations, more common in red team exercises). Post-compromise file discovery on the attacker's machine will surface this. |
| **10** | **Kerberos ccache file** — `.ccache` or `.kirbi` file left on the target or attacker machine if Kerberos auth was used | No (only present if Kerberos `-K` flag was used) | Attacker's machine or the target (if ccache was copied) | High | A `.ccache` file is a usable Kerberos ticket cache and is a direct indicator of Kerberos abuse. Presence on a non-DC is suspicious. |

## Hunting on Source (Attacker's Machine)

### Ruby Process Detection

```bash
# Find active evil-winrm processes
ps aux | grep -i "ruby.*evil-winrm" | grep -v grep

# Or: ps with full command lines
ps -ef | grep -i evil-winrm | grep -v grep

# Output: typically shows `ruby /path/to/evil-winrm -i <target> -u <user> ...`
#         but if credentials are passed via environment variables or prompted, they won't appear here.
```

**Forensic value:** If a `ruby` process is found running evil-winrm, the `-i` (target IP/hostname) is visible in the command line. Correlate with firewall logs to confirm network connection.

### Shell History

```bash
# Check bash history for evil-winrm commands
history | grep -i evil-winrm

# Or: examine the history file directly (if shell history persists)
cat ~/.bash_history | grep -i evil-winrm

# Look for credentials passed on the command line
cat ~/.bash_history | grep -E "evil-winrm.*-p |evil-winrm.*-H |evil-winrm.*-u "

# Check zsh history
cat ~/.zsh_history | grep -i evil-winrm

# Check fish shell history
cat ~/.local/share/fish/fish_history | jq '.entries[] | select(.cmd | contains("evil-winrm"))'
```

**Forensic value:** Shell history can reveal the target IP, username, and sometimes credentials (if typed directly on the command line instead of prompted). The timestamp of the history entry correlates with the session time.

### Kerberos Ticket Cache

```bash
# Check for leftover ccache files in standard locations
ls -la ~/.krb5cc_*
ls -la /tmp/krb5cc_*
ls -la /tmp/krb5_*.ccache

# List tickets in a ccache file (if Kerberos is installed)
klist -c ~/.krb5cc_0

# Check for .kirbi files (Mimikatz format)
find ~ -name "*.kirbi" -o -name "*.ccache"
```

**Forensic value:** A `.ccache` or `.kirbi` file is a live Kerberos ticket and a direct indicator of Kerberos abuse. The file's modification timestamp correlates with the session time.

### Evil-WinRM Log File (if `-l` was used)

```bash
# Find evil-winrm log files (if created with -l flag)
find . -name "evil-winrm_*.log" -type f

# View the log file contents
cat evil-winrm_<timestamp>.log

# Example output:
# [*] Target: 10.10.10.5
# [*] Connected to 10.10.10.5
# *Evil-WinRM* > whoami
# CORP\jsmith
# *Evil-WinRM* > Get-Process
# [list of processes...]
```

**Forensic value:** If present, this is a complete transcript of the remote session.

### Network Connections (at time of session)

```bash
# Check active connections (if captured live during the session)
netstat -ano | grep -E ":5985|:5986"

# Or with ss (modern systems)
ss -tuln | grep -E ":5985|:5986"

# For a running ruby process, check its file descriptors
ls -la /proc/<ruby_pid>/fd/ | grep socket
```

**Forensic value:** Identifies the target IP and confirms the connection was to port 5985 or 5986.

---

## Hunting on Target (Victim's Machine)

### 1. WinRM Event Log — Session Lifecycle (Highest Priority)

```powershell
# Query for WinRM session creation (Event 15)
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = 15
} | Select-Object -Property TimeCreated, Message | Format-Table -AutoSize

# Query for WinRM session closure (Event 91)
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = 91
} | Select-Object -Property TimeCreated, Message | Format-Table -AutoSize

# Find the correlation: Event 15 (create) followed by Event 91 (close) with a time gap
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = @(15, 91)
} | Sort-Object TimeCreated | 
  Select-Object -Property @{
    Name = 'Time'; Expression = { $_.TimeCreated }
  }, @{
    Name = 'EventID'; Expression = { $_.Id }
  }, @{
    Name = 'Message'; Expression = { $_.Message.split([Environment]::NewLine)[0] }
  } | Format-Table -AutoSize
```

**What to look for:** A sequence of Event 15 (shell create) followed by one or more Event 33 (command executed), followed by Event 91 (shell close). The time gap between 15 and 91 indicates session duration.

### 2. WinRM Event Log — Command Operations (Event 33)

```powershell
# Count WinRM commands (Event 33) per session
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = 33
} | Measure-Object  # Shows count of all Event 33s

# Get all Event 33s with timestamps (shows multi-command sessions)
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = 33
} | Select-Object -Property TimeCreated, Message | 
  Sort-Object TimeCreated | Format-Table -AutoSize

# Filter by time range (e.g., last 24 hours)
Get-WinEvent -LogName 'Microsoft-Windows-WinRM/Operational' -FilterHashtable @{
  ID = 33
  StartTime = (Get-Date).AddHours(-24)
} | Select-Object -Property TimeCreated | Format-Table
```

**What to look for:** Multiple Event 33 entries (2+) within a short time window (seconds to minutes) indicate a multi-command session, consistent with evil-winrm. A single Event 33 might indicate a different tool.

### 3. Security Event Log — Logon Events (4624)

```powershell
# Find network logons (Type 3) around the time of WinRM events
Get-WinEvent -LogName 'Security' -FilterHashtable @{
  ID = 4624
  LogonType = 3  # Network logon
  StartTime = (Get-Date).AddHours(-1)
} | Select-Object -Property @{
  Name = 'Time'; Expression = { $_.TimeCreated }
}, @{
  Name = 'User'; Expression = { $_.Properties[5].Value }  # TargetUserName
}, @{
  Name = 'SourceIP'; Expression = { $_.Properties[18].Value }  # SourceNetworkAddress
}, @{
  Name = 'AuthPackage'; Expression = { $_.Properties[10].Value }  # AuthenticationPackageName (NTLM, Kerberos, Negotiate)
} | Format-Table -AutoSize

# Correlate 4624 with WinRM Event 15: they should occur within 1–5 seconds of each other
# Example: 4624 at 14:32:00.123, Event 15 at 14:32:00.500 = strong correlation
```

**What to look for:** A 4624 event (Network logon) immediately preceding or concurrent with WinRM Event 15 (shell create). The source IP should be an external/attacker-controlled IP (not internal/trusted).

### 4. Security Event Log — Process Creation (4688, if auditing enabled)

```powershell
# Query for process creation (requires command-line auditing to capture full command)
Get-WinEvent -LogName 'Security' -FilterHashtable @{
  ID = 4688
  StartTime = (Get-Date).AddHours(-1)
} | Select-Object -Property @{
  Name = 'Time'; Expression = { $_.TimeCreated }
}, @{
  Name = 'ParentImage'; Expression = { $_.Properties[13].Value }  # ParentProcessName
}, @{
  Name = 'Image'; Expression = { $_.Properties[5].Value }  # NewProcessName
}, @{
  Name = 'CommandLine'; Expression = { $_.Properties[8].Value }  # CommandLine
} | Where-Object { $_.ParentImage -like "*powershell*" -or $_.Image -like "*powershell*" } |
  Format-Table -AutoSize

# Another approach: filter for non-standard processes spawned from PowerShell
Get-WinEvent -LogName 'Security' -FilterHashtable @{
  ID = 4688
} | Where-Object { $_.Properties[13].Value -like "*powershell*" } |
  Select-Object -Property @{
    Name = 'Time'; Expression = { $_.TimeCreated }
  }, @{
    Name = 'Child'; Expression = { $_.Properties[5].Value }  # NewProcessName (the spawned process)
  }, @{
    Name = 'CommandLine'; Expression = { $_.Properties[8].Value }
  } | Format-Table -AutoSize
```

**What to look for:** PowerShell spawning unexpected child processes (e.g., `whoami.exe`, `tasklist.exe`, `certutil.exe`) shortly after a WinRM Event 33, especially if the command line shows the exact command typed by the attacker.

### 5. Sysmon Event 1 — Process Create (if Sysmon is deployed)

```powershell
# Query Sysmon logs for PowerShell process creation
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterHashtable @{
  ID = 1
  StartTime = (Get-Date).AddHours(-1)
} | Where-Object { $_.Properties[20].Value -like "*powershell*" } |  # Image (parent process)
  Select-Object -Property @{
    Name = 'Time'; Expression = { $_.TimeCreated }
  }, @{
    Name = 'Parent'; Expression = { $_.Properties[20].Value }  # ParentImage
  }, @{
    Name = 'Child'; Expression = { $_.Properties[10].Value }  # Image
  }, @{
    Name = 'CommandLine'; Expression = { $_.Properties[20].Value }  # CommandLine
  } | Format-Table -AutoSize

# Focus on processes spawned from PowerShell
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterHashtable @{
  ID = 1
  StartTime = (Get-Date).AddHours(-1)
} | Where-Object { $_.Properties[20].Value -like "*powershell*" } |
  Sort-Object TimeCreated | Format-Table TimeCreated, @{
    N = 'Command'; E = { $_.Properties[10].Value }  # Image
  } -AutoSize
```

**What to look for:** A sequence of Sysmon 1 events showing PowerShell spawning child processes, correlated with WinRM Event 33 timestamps.

### 6. PowerShell Script Block Logging (Event 4104, if enabled)

```powershell
# Query PowerShell Script Block Logging (requires Group Policy enablement)
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterHashtable @{
  ID = 4104
  StartTime = (Get-Date).AddHours(-1)
} | Select-Object -Property TimeCreated, Message | 
  Format-List  # -List to see full message content (scripts are long)

# Parse for suspicious commands
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -FilterHashtable @{
  ID = 4104
  StartTime = (Get-Date).AddHours(-1)
} | ForEach-Object {
  if ($_.Message -match "(IEX|Invoke-Expression|DownloadString|DownloadFile)") {
    Write-Host "Suspicious command at $($_.TimeCreated):"
    Write-Host $_.Message
  }
}
```

**What to look for:** PowerShell commands that match the attacker's actions (e.g., `whoami`, `Get-Process`, `Invoke-Binary`, `Bypass-4MSI`). This log is the **richest source of operator intent** if enabled.

### 7. Firewall / Network Layer (WinRM port 5985/5986)

```powershell
# Check Windows Firewall logs for inbound 5985/5986 connections
Get-WinEvent -LogName 'Security' -FilterHashtable @{
  ID = 5156  # Windows Filtering Platform (WFP) — connection allowed
} | Where-Object { $_.Properties[4].Value -eq 5985 -or $_.Properties[4].Value -eq 5986 } |
  Select-Object -Property TimeCreated, @{
    N = 'SourceIP'; E = { $_.Properties[3].Value }
  }, @{
    N = 'DestPort'; E = { $_.Properties[4].Value }
  } | Format-Table -AutoSize

# Note: WFP logging (5156) must be enabled first (not default)
# Enable via: auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
```

**What to look for:** Inbound connections on 5985/5986 from external/untrusted IPs. Multiple connections from the same IP over time or a long-duration connection (firewall state table) is suspicious.

---

## Fleet-Wide / Scaled Hunting

For detecting evil-winrm across an entire organization, use a centralized log aggregation platform (ELK, Splunk, Windows Event Forwarding, etc.):

### Splunk Query

```spl
# Detect WinRM sessions (Event 15 + Event 91 pairs) across all hosts
index=windows_events source="WinRM" EventID IN (15, 91)
| stats min(_time) as session_start, max(_time) as session_end by ComputerName, user
| eval session_duration = session_end - session_start
| where session_duration >= 1
# Filter for sessions longer than 1 second (indicates multi-command, not one-off)
```

### Windows Event Forwarding (WEF)

Set up WEF to forward WinRM Operational logs from all domain-joined computers to a central server:

```xml
<!-- WinRM-ForwardingRules.xml -->
<Subscription>
  <SubscriptionId>WinRM-Operational</SubscriptionId>
  <LogName>Microsoft-Windows-WinRM/Operational</LogName>
  <Query>*[System[EventID=6 or EventID=15 or EventID=33 or EventID=91]]</Query>
</Subscription>
```

### Sysmon Detection Rule (Sigma/YARA)

```yaml
title: WinRM Session with Multiple Commands
detection:
  selection_winrm:
    EventID: 33
    LogName: 'Microsoft-Windows-WinRM/Operational'
  selection_process:
    EventID: 1
    LogName: 'Microsoft-Windows-Sysmon/Operational'
    ParentImage|endswith: 'powershell.exe'
  condition: selection_winrm and selection_process | timeframe(5s)
  # Detect: WinRM Event 33 (command) followed within 5 seconds by Sysmon 1 (child process spawn)
```

---

## Remediation & Response

### Immediate Actions

1. **Collect evidence before containment:**
   - Capture WinRM event logs (`Get-WinEvent -LogName 'Microsoft-Windows-WinRM/*' -Oldest > export.xml`)
   - Capture Security event logs for the same timeframe
   - If Sysmon is deployed, export Sysmon logs for the affected host
   - Capture network traffic (PCAP) if available from network taps or firewalls
   - Document the attacker's source IP(s)

2. **Isolate the affected host(s):**
   - Disconnect from the network (physically or via network segmentation) to prevent further C2 communication
   - Do **not** power off — live evidence (memory, network connections) may be recoverable

3. **Preserve attacker artifacts:**
   - Capture a memory dump of the `powershell.exe` process (if still running)
   - If evil-winrm was run from an attacker's machine on the network, preserve that machine's storage for forensics

4. **Kill the session:**
   - If the WinRM session is still active, forcibly close it: `wmic process where name="powershell.exe" delete` (requires admin)
   - Or kill the WinRM service: `net stop WinRM` (will disconnect all WinRM sessions)

### Containment

- **Disable WinRM** (if not required operationally): `Disable-PSRemoting -Force` or `Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled False`
- **Reset all potentially compromised credentials** (accounts that authenticated via WinRM during the suspected timeframe)
- **Review and revoke** Kerberos tickets for affected accounts (via `klist purge` on the affected system or via a KDC-level revocation, if available)
- **Review Domain Admin and other sensitive-account logon history** for unauthorized WinRM connections

### Hardening (to reduce future risk)

- **Enable WinRM logging:** Ensure `Microsoft-Windows-WinRM/Operational` logging is enabled (not default on all systems)
- **Enable command-line auditing:** Configure Group Policy: `Computer Configuration > Policies > Administrative Templates > System > Audit Process Creation > Include command line in process creation events` → **Enabled**
- **Enable PowerShell Script Block Logging:** Group Policy: `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging` → **Enabled**
- **Restrict WinRM listener to specific IP addresses** (if possible): Configure WinRM to listen only on internal/trusted subnets, not all 0.0.0.0
- **Enforce TLS/HTTPS for WinRM** (force `5986` instead of `5985`), which requires a valid certificate on the WinRM service
- **Require Kerberos authentication for WinRM** (if in an AD environment) — Kerberos is stronger than NTLM and leaves a different event trail (event ID 4768/4769 on the KDC)
- **Implement endpoint detection and response (EDR)** to alert on unexpected WinRM sessions, PowerShell in-memory execution, or DLL injection

