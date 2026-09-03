# 05 - Detection and Hunting

## Hunting Priority Table

Ranked by **evasion survivability** — signals that persist despite operator countermeasures like script cleanup, inline execution, or memory-clearing.

| Rank | Signal | Evasion Resistance | Method | Criticality |
|------|--------|----------|--------|-----|
| 1 | Network pcap (raw bytes on wire) | Very High | Firewall/IDS SPAN, network tap, tcpdump | Very High |
| 2 | Firewall/IDS connection logs + behavioral pattern | High | Firewall syslog, Suricata EVE, Zeek | Very High |
| 3 | Target-host event logs (exploit success) | High | Windows Event Log, Linux auditd, syslog | Very High |
| 4 | Script file on attacker host | High (if not cleaned up) | File forensics, MFT analysis | High |
| 5 | Python process + raw socket activity (live response) | Medium (ephemeral) | netstat/ss, ps, Sysmon 1/10 | High |
| 6 | Shell history (.bash_history, Event ID 4688) | Medium (operator may clear) | .bash_history, Windows Event Logs | Medium |
| 7 | Python bytecode cache (.pyc) | High (if missed) | `__pycache__/` directories, find | Medium |
| 8 | Memory dump (during/after execution) | Medium (ephemeral) | Volatility, WinDbg, GDB | Medium |
| 9 | Audit logs (auditd, Windows Audit) | Very High (write-protected) | journalctl, Event Viewer | High |
| 10 | Temporary output files (pcap, scan results) | Medium (operator often forgets) | `/tmp/` enumeration, file system scan | Medium |

**Key insight:** Network-side evidence (pcap + IDS logs) is the strongest signal because:
- It's captured by infrastructure, not host-based
- It persists in centralized logging (SIEM, Splunk)
- It's independent of operator cleanup actions
- It's difficult to alter retroactively

---

## Hunting on Source (Attacker Host)

### 1. Live Process Detection

**Objective:** Catch a Scapy script while it's running.

**PowerShell (Windows):**

```powershell
# Look for python.exe with raw socket activity
Get-Process python | ForEach-Object {
    $process = $_
    Write-Host "Process: $($process.ProcessName) PID: $($process.Id)"
    
    # Use netstat to find raw sockets associated with this PID
    netstat -ano | Select-String "UNCONN"
}

# More specific: Look for python with network activity
Get-NetTCPConnection -State SynSent | Where-Object { $_.OwningProcess -eq (Get-Process python).Id }
```

**Linux/macOS:**

```bash
# Find python3 processes with raw socket privileges
ps aux | grep python3 | grep -v grep

# Check network connections from python process
lsof -i -P -n | grep python

# Real-time: Monitor for new python processes
auditctl -w /usr/bin/python3 -p x

# Or use ss (socket statistics) to spot raw sockets
ss -tan | grep UNCONN
netstat -an | grep raw
```

**Expected output (if script is running):**

```
python3 12345 user 1024u IPv4 99999 0t0 ICMP -> *:*
python3 12345 user 1025u IPv4 100000 0t0 TCP -> 192.168.1.100:22 (SYN_SENT)
```

### 2. Script File Discovery

**Objective:** Find Scapy scripts staged on disk (before or after execution).

**Linux/macOS:**

```bash
# Search for files containing "scapy" import
find / -name "*.py" -type f -exec grep -l "from scapy" {} \; 2>/dev/null

# Search for common staging locations
find /tmp -name "*.py" -type f
find /root -name "*.py" -type f
find /home -name "*.py" -type f

# Check for .pyc bytecode files (may persist after script cleanup)
find / -name "*.pyc" -path "*scapy*" 2>/dev/null
find /tmp -name "__pycache__" -type d 2>/dev/null

# Look for recently modified Python files
find / -name "*.py" -type f -mtime -1 2>/dev/null  # Modified in last 24 hours
```

**Windows (PowerShell):**

```powershell
# Find all .py files on the system
Get-ChildItem -Path C:\ -Filter "*.py" -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Search temp directories
Get-ChildItem -Path $env:TEMP -Filter "*.py" -Recurse
Get-ChildItem -Path $env:SystemDrive\Windows\Temp -Filter "*.py" -Recurse

# Look for bytecode
Get-ChildItem -Path $env:TEMP -Filter "__pycache__" -Recurse
```

### 3. Shell History Analysis

**Objective:** Recover commands that launched Scapy scripts.

**Linux/macOS:**

```bash
# View bash history
cat ~/.bash_history | grep -i scapy
cat ~/.bash_history | grep "python3.*-c\|python3.*import"
cat ~/.bash_history | grep "from scapy\|sr1\|send\|sniff"

# View zsh history (stored as EXTENDED_HISTORY format)
cat ~/.zsh_history | grep -i scapy

# Python interactive shell history
cat ~/.python_history

# System-wide history (if available)
grep python /var/log/auth.log | grep -i scapy

# Real-time monitoring (forward-looking)
auditctl -w /root/.bash_history -p wa  # Watch for modifications
```

**Windows (Event Log):**

```powershell
# Search Event Log for python.exe invocations with "scapy"
Get-WinEvent -LogName Security -FilterHashtable @{
    EventID=4688
    NewProcessName="*python*"
} | Where-Object { $_.Message -match "scapy|from scapy" }

# More permissive: all python.exe process creations
Get-WinEvent -LogName Security -FilterHashtable @{
    EventID=4688
    NewProcessName="*python*"
} | Select-Object TimeCreated, Message
```

### 4. Audit Log Analysis (Linux auditd)

**Objective:** Recover execution audit trail (write-protected, difficult to alter).

**Linux:**

```bash
# Query auditd for python execution
aureport -c | grep python

# More detailed: Show all system calls from python
ausearch -c python -i | grep -E "EXECVE|SOCKETCALL"

# Look for raw socket creation
ausearch -m SOCKETCALL -i | grep -E "socket|icmp|raw"

# Full audit log dump for a user
ausearch -u <username> -i | grep python

# Watch for recent changes to audit config
auditctl -l  # List current audit rules

# Monitor for future Scapy activity
auditctl -a exit,always -F exe=/usr/bin/python3 -F arch=b64 -S socket -k scapy_monitor
```

### 5. Memory Forensics

**Objective:** Extract Scapy script source and packet data from a memory dump (if captured during or shortly after execution).

**Using Volatility (Windows memory dump):**

```bash
# Dump python process memory
volatility -f memory.img pslist | grep python
volatility -f memory.img memdump -p <python_pid> -D /tmp/

# Strings from dump (search for Scapy keywords)
strings /tmp/<python_pid>.dmp | grep -i "scapy\|send\|sr1\|sniff"

# Look for hardcoded target IPs in memory
strings /tmp/<python_pid>.dmp | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"

# Search for packet data (hex patterns for IP headers)
strings /tmp/<python_pid>.dmp | grep -i "^45[0-9a-f]{2}"  # IP version 4 + IHL
```

**Using GDB (live Linux target):**

```bash
# Attach to running python process
gdb -p <python_pid>

# Dump memory from the process
(gdb) dump memory /tmp/python_dump.bin 0x<start_addr> 0x<end_addr>

# Extract strings
strings /tmp/python_dump.bin | grep -i scapy
```

---

## Hunting on Target (Victim Host)

### 1. Network Connection State Analysis

**Objective:** Detect half-open SYN states, raw socket connections, or unusual connection patterns.

**Windows (PowerShell):**

```powershell
# List all connections with state SYN-SENT (half-open)
Get-NetTCPConnection -State SynSent | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort

# Example suspicious output:
# RemoteAddress      RemotePort
# 192.168.1.100      22
# 192.168.1.100      80
# 192.168.1.100      443

# More detail (with owning process)
Get-NetTCPConnection -State SynSent | 
    ForEach-Object { 
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $proc.ProcessName -PassThru
    } | Select-Object LocalAddress, RemoteAddress, RemotePort, ProcessName, State
```

**Linux (ss or netstat):**

```bash
# Look for SYN_SENT state connections
ss -tan | grep SYN-SENT

# Check for SYN_RECV state (indicates unfinished handshakes)
ss -tan | grep SYN-RECV

# Full connection state dump
netstat -an | grep -E "SYN_SENT|SYN_RECV|UNCONN"

# Check for raw socket connections
ss -tan | grep -E "raw|UNCONN"
```

### 2. Service-Specific Log Analysis

**Objective:** Hunt for malformed or unusual protocol-layer traffic in service logs.

**SSH (sshd) on Port 22:**

```bash
# Look for connection-reset, pre-auth disconnects
grep "Received disconnect\|Connection closed\|Invalid user" /var/log/auth.log | tail -20

# Count connections per source (rapid probes = scan)
grep "sshd" /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head

# Windows SSH logs (if OpenSSH is running)
Get-WinEvent -LogName "OpenSSH/Operational" -ErrorAction SilentlyContinue | 
    Where-Object { $_.Message -match "connection reset\|preauth" }
```

**HTTP (Apache/Nginx) on Port 80/443:**

```bash
# Look for malformed HTTP requests or non-HTTP traffic
grep "malformed\|invalid" /var/log/apache2/error.log | tail -20

# Count 400 (Bad Request) responses per source IP
grep "\" 400 " /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head

# Nginx version
grep "malformed" /var/log/nginx/error.log
tail -20 /var/log/nginx/error.log | grep -i "error\|malformed"
```

**DNS (BIND/Unbound) on Port 53:**

```bash
# Look for zone-transfer attempts (AXFR)
grep "AXFR" /var/log/syslog

# Check query log (if enabled)
grep "queries:" /var/log/syslog | grep "AXFR\|ANY"

# Count queries per source (anomaly detection)
grep "queries:" /var/log/syslog | awk '{print $7}' | sed 's/:.*//' | sort | uniq -c | sort -rn | head -10

# BIND9 specific
grep "zone transfer started" /var/log/bind/default
```

### 3. Windows Event Log Hunting

**Objective:** Correlate network probes with security events and process creation.

**PowerShell:**

```powershell
# Look for connection-reset events (IIS, SMB, etc.)
Get-WinEvent -LogName Security -FilterHashtable @{EventID=5156} | 
    Where-Object { $_.Message -match "Reset|Denied" } | 
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending | head -20

# Monitor for unusual TCP connection attempts (multiple ports on single target)
Get-WinEvent -LogName "Windows Firewall with Advanced Security" -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match "Connection blocked\|Inbound" } |
    Group-Object -Property { $_.Message.Split(" ")[0] } | Sort-Object Count -Descending

# Check for failed LDAP/Kerberos pre-auth (if Scapy was used for Kerberos attacks)
Get-WinEvent -LogName Security -FilterHashtable @{EventID=4768} |
    Where-Object { $_.Message -match "KDC_ERR_PREAUTH_REQUIRED" } |
    Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending
```

### 4. Firewall & IDS Log Analysis

**Objective:** Detect scanning patterns and protocol anomalies captured by network sensors.

**Suricata (Eve JSON format):**

```bash
# Look for "anomaly" alerts (malformed packets, invalid flags)
cat /var/log/suricata/eve.json | jq 'select(.alert.signature | contains("anomaly"))'

# Port scan detection
cat /var/log/suricata/eve.json | jq 'select(.event_type == "flow" and .flow.pkts_toserver < 3 and .flow.pkts_toclient < 3)'

# Extract all unique source IPs that triggered alerts
cat /var/log/suricata/eve.json | jq '.src_ip' | sort -u
```

**Zeek (Conn.log format):**

```bash
# Look for half-open connections (SYN sent, no ACK)
zeek-cut ts src_ip src_port dst_ip dst_port conn_state < conn.log | grep "S[H0]"

# Count connection attempts per source (anomaly detection)
zeek-cut src_ip dst_ip dst_port < conn.log | sort | uniq -c | sort -rn | head -20

# Extract all FTP/SSH/HTTP connection failures
zeek-cut ts src_ip dst_ip dst_port conn_state < conn.log | grep -E "(S[01]|REJ)"
```

**tcpdump (Packet capture analysis):**

```bash
# Replay pcap and filter for SYN packets
tcpdump -r capture.pcap "tcp[tcpflags] & tcp-syn != 0" | head -20

# Look for packets with invalid TCP flag combinations
tcpdump -r capture.pcap "tcp[tcpflags] = tcp-syn+tcp-fin"

# Extract all unique destination ports (scan map)
tcpdump -r capture.pcap "tcp[tcpflags] & tcp-syn != 0" -n | awk '{print $5}' | sed 's/.*\.//' | sort -u
```

---

## Fleet-Wide Sweep (Hunting at Scale)

### Organizational Hunt: Port Scans from Attacker Infrastructure

**Objective:** Find all hosts that were scanned by the attacker IP.

**Splunk / Elastic query (SIEM):**

```spl
# Splunk: Detect SYN scans (multiple ports from same source to single target within 60 seconds)
index=firewall OR index=ids
| stats dc(dst_port) as port_count by src_ip, dest_ip, earliest_time
| where port_count > 10
| table src_ip, dest_ip, port_count
```

**Elasticsearch / ELK:**

```json
{
  "query": {
    "bool": {
      "must": [
        { "term": { "event.action": "network-connection" } },
        { "match": { "network.community_id": "*" } }
      ]
    }
  },
  "aggs": {
    "scan_detection": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "targets": {
          "terms": { "field": "destination.ip" },
          "aggs": {
            "ports": {
              "cardinality": { "field": "destination.port" }
            }
          }
        }
      }
    }
  }
}
```

### Host-Based Hunt: Python with Raw Sockets

**Objective:** Find all hosts running python with raw socket activity across the organization.

**Sysmon (Windows) + Splunk:**

```xml
<!-- Sysmon rule to detect python.exe creating raw sockets -->
<Sysmon schemaversion="4.31">
  <EventFiltering>
    <RuleGroup name="Raw Socket Detection" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Image condition="image">python.exe</Image>
      </ProcessCreate>
      <CreateRemoteThread onmatch="include">
        <SourceImage condition="image">python.exe</SourceImage>
      </CreateRemoteThread>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

**Linux (auditd) hunt:**

```bash
# Across all hosts: look for auditd logs showing python + raw socket syscall
for host in $(cat /etc/hosts | grep prod | awk '{print $1}'); do
    ssh $host "ausearch -m SOCKETCALL -c python -i 2>/dev/null | grep -E 'socket|raw'"
done
```

---

## Threat Hunting Playbooks

### Playbook 1: Detect Scapy-Based Port Scan

**Phase 1: Triage**

```bash
# Step 1: Check firewall/IDS for SYN scans
grep "SYN" /var/log/suricata/eve.json | jq '.src_ip' | sort -u

# Step 2: Identify target hosts scanned
grep "SYN" /var/log/suricata/eve.json | jq '.dest_ip, .dest_port' | sort -u

# Step 3: Determine scan type
# If multiple ports on same target in < 1 sec = stateless scan (likely Scapy)
# If ports accessed sequentially = stateful scan (likely nmap -sS)
```

**Phase 2: Deep Dive**

```bash
# Step 1: Extract full pcap for this source IP
tcpdump -r traffic.pcap "src 192.168.1.99" -w attacker_traffic.pcap

# Step 2: Analyze packet structure (look for Scapy signatures)
tcpdump -r attacker_traffic.pcap -A | grep -i "python\|scapy"  # (unlikely, but check)

# Step 3: Check for script files on attacker host (live response)
ssh 192.168.1.99 "find /tmp -name '*.py' 2>/dev/null"  # May fail if attacker cleaned up

# Step 4: Check attacker's shell history
ssh 192.168.1.99 "cat ~/.bash_history | grep -i scapy"
```

**Phase 3: Confirmation**

```bash
# Step 1: Correlate with attacker host process logs
# If Event ID 4688 shows python.exe running at exact time of scan = confirmed

# Step 2: Check for follow-on exploitation (post-scan phase)
# If ports identified as open were subsequently probed with exploit payloads = attack chain
```

### Playbook 2: Detect Scapy-Based Exploitation

**Phase 1: Identify Malformed Traffic**

```bash
# Look for packets with invalid structure (Scapy fingerprint)
zeek-cut ts src_ip src_port dst_ip dst_port proto flags < conn.log | \
    grep -E "(S[FR]|SRA)" | head -20  # Invalid TCP flag combos
```

**Phase 2: Correlate with Target-Side Exploit Evidence**

```bash
# On target, look for process creation shortly after malformed packet
# If Apache/SSH/DNS logs show error at exact time malformed packet arrived = match

tail -100 /var/log/auth.log | grep -B 5 "Invalid\|malformed"

# Cross-reference timestamp with network capture
tcpdump -r capture.pcap "src attacker_ip" | grep -B 2 "19:23:45"  # Time from logs
```

**Phase 3: Verify Payload Delivery**

```bash
# If exploit succeeded: check for new processes, files, or network connections
# created by the service process (sshd, apache, etc.) immediately after attack

ps aux | grep -E "sshd|apache|nginx" -A 5 | grep "cmd.exe\|bash\|nc"

# Or check for reverse shell connections
netstat -an | grep -E "ESTABLISHED.*:4444\|:9999"  # Common reverse shell ports
```

---

## Remediation & Prevention

### Immediate Containment

```bash
# 1. Block attacker IP at firewall
ufw deny from 192.168.1.99  # Linux UFW
netsh advfirewall firewall add rule name="BlockScapy" dir=in action=block remoteip=192.168.1.99  # Windows

# 2. Kill python processes (if untrusted)
pkill -9 python3  # CAUTION: Use only if certain

# 3. Close half-open connections (netstat shows SYN_RECV)
# There's no single command; they timeout after ~60 seconds by default
```

### Evidence Preservation

```bash
# 1. Capture network traffic immediately
tcpdump -i any -w /tmp/incident_capture.pcap "src 192.168.1.99"  # Real-time capture

# 2. Dump attacker process memory (if still running)
gdb -p <python_pid>
(gdb) dump memory /tmp/python_mem.bin 0x0 0xffffffff

# 3. Preserve script files (before operator cleans up)
find /tmp -name "*.py" -exec cp {} /tmp/evidence/ \;
find /root -name "*.py" -exec cp {} /tmp/evidence/ \;

# 4. Export shell history
cp ~/.bash_history /tmp/evidence/
cp ~/.python_history /tmp/evidence/

# 5. Dump Event Logs (Windows)
wevtutil epl Security /tmp/evidence/Security.evtx
```

### Long-Term Prevention

**Network Level:**

- Deploy IDS/IPS (Suricata, Snort) with rules for:
  - TCP flag anomalies
  - Half-open connection spikes
  - Protocol malformations
- Enable SPAN/port mirroring on network switches
- Deploy centralized logging (Splunk, ELK, Graylog)
- Monitor for raw socket creation at scale

**Host Level:**

- Enable auditd with Python monitoring rules:
  ```bash
  auditctl -a exit,always -F exe=/usr/bin/python3 -F arch=b64 -S socket -k scapy_monitor
  ```
- Enable Sysmon process and network event logging (Windows)
- Deploy EDR (Endpoint Detection & Response) tools:
  - CrowdStrike, Sentinel One, Carbon Black
  - Flags unusual socket creation and process behavior

**Application Level:**

- Reduce exposure:
  - Close unnecessary ports (22, 80, 443, 53 if not needed)
  - Run services in containers with network restrictions
  - Implement network segmentation (VLANs, microsegmentation)
- Harden protocol parsers:
  - Update to patched versions of SSH, HTTP, DNS daemons
  - Use application-level WAF (Web Application Firewall) to reject malformed HTTP

**Incident Response:**

- Develop and test hunting playbooks quarterly
- Set alert thresholds for SYN scans: > 100 SYN packets from same source in < 1 min = alert
- Maintain forensic readiness: document evidence preservation process, backup procedures

---

## Detection Rules & Signatures

### Suricata Rule (Anomalous TTL)

```
alert ip any any -> any any (msg:"Anomalous TTL - possible custom packet crafting"; ttl:0-32|254-255; flow:established,stateless; sid:1000001; rev:1;)
```

### Sigma Rule (Python + Raw Socket)

```yaml
title: Python Process with Raw Socket
logsource:
  product: windows
  service: security
detection:
  process_creation:
    EventID: 4688
    NewProcessName|endswith: python.exe
    CommandLine|contains: 'scapy|sr1|send|sniff'
  condition: process_creation
falsepositives:
  - Legitimate network tools written in Python
level: high
```

### Zeek Intelligence Framework

```
192.168.1.99    scanner  Possible port scanner    -    -
192.168.1.99    attacker Scapy-based network tool -    -
```

---

## Summary: Hunt, Detect, Contain

**Speed of detection matters:** Scapy scripts run quickly (< 1 minute for typical scans). Real-time monitoring (IDS, firewall) is critical.

**Strongest signals (in order):**

1. **Network pcap + behavioral analysis** (very fast to detect: spike in SYN packets)
2. **IDS alerts for protocol anomalies** (immediate: flagged during transmission)
3. **Event Log analysis (Windows/Linux)** (post-incident: process execution timestamp)
4. **Memory forensics** (if captured during/after execution: script source + targets)
5. **Script file recovery** (lower priority: often cleaned up by operator)

**Response strategy:**

- **Real-time:** Monitor IDS for SYN scan patterns, protocol anomalies, half-open connections
- **Containment:** Block source IP, kill suspicious processes
- **Forensics:** Capture pcap, memory dumps, event logs, script files
- **Attribution:** Correlate source-host (Python process, script, shell history) with target-side evidence (network traffic, service logs)
- **Hardening:** Deploy EDR, enable auditd, segment networks, close unnecessary ports
