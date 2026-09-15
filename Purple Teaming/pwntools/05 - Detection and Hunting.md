# pwntools — Detection and Hunting

Hunting for pwntools-based exploits revolves around three distinct evidence categories: **(1) Python process execution with pwntools imports**, **(2) unexpected subprocess spawning from unrelated processes**, and **(3) memory/network anomalies at the moment of exploitation**.

This guide ranks detection signals by **invariant strength** — which survive operator evasion attempts (custom payloads, renamed binaries, obfuscated scripts).

---

## Detection Signal Ranking (by Evasion Survivability)

### Tier 1: Unbeatable Signatures (Survive All Evasion)

| Signal | Why Unbeatable | Operator Evasion Cost |
|--------|---|---|
| **Parent-child process tree** (vuln process → shell) | Exploit must call `system()`/`execve()`, which inherits parent PID invariantly. | N/A — impossible to defeat. |
| **Segmentation fault (signal 11)** on overflow | Overflowing stack requires corrupting memory; first-time exploit has >90% crash rate. | Leaking/calculating correct addresses (weeks of dev). |
| **Core dump analysis** (gadget addresses in registers) | ROP chain leaves gadget addresses in crashed process memory. | Using only unmodified binary gadgets (defeats polymorphism evasion). |
| **Memory corruption pattern** (0x41414141 in registers) | Test payload uses repeated bytes (A, B, C). | Switch to real addresses (defeats quick-test PoCs). |

### Tier 2: Strong Signatures (Survive Custom Payloads)

| Signal | Why Strong | Operator Evasion Cost |
|--------|---|---|
| **Python process** making TCP/SSH connections | Library-based exploitation always uses Python I/O. | Rewrite in C (weeks of work). |
| **Network connection from unexpected process** (vuln binary → attacker IP) | Exploit must communicate with target. | Only works against already-compromised host (no external recon). |
| **Call to ROP gadget** (ret2libc or ret2csu patterns) | Structured calling-convention layout is binary-invariant. | Use shellcode injection only (requires NX disabled). |
| **Stack layout anomalies** (abnormal spacing, repeated values) | Exploit payload has recognizable structure. | Custom padding/randomization (minor overhead). |

### Tier 3: Moderate Signatures (Evadable with Effort)

| Signal | Why Evadable | Operator Evasion Cost |
|---|---|---|
| **Shellcode patterns** (movabs, syscall, xor, loop sequences) | Can be polymorphic-encoded, obfuscated, or self-modifying. | Implement encoder (hours of work). |
| **Format-string exploit markers** (%x, %n, %s in input) | Operator can use binary format (avoid text markers). | Binary-based exploitation (higher complexity). |
| **File writes** to /tmp | Can write to /dev/shm, alternate directories, or memory-only staging. | Directory enumeration (low cost). |
| **GDB attachment** (spawned terminal, gdb process) | Can use remote GDB (gdbserver) or skip debugging in production. | Testing without debugger (increases risk). |

### Tier 4: Weak Signatures (Easily Evaded)

| Signal | Why Weak | Operator Evasion Cost |
|---|---|---|
| **Script filename** (exploit.py, pwn.py, etc.) | Operator can rename. | Rename to `analysis.py`, `config.py`, etc. (seconds). |
| **Bash history** | Operator can clear history (`history -c`, `export HISTFILE=/dev/null`). | Set before running (1 second). |
| **pwntools import statements** | Operator can use dynamic imports or write custom wrapper. | Import obfuscation (minutes). |
| **Python-specific artifacts** (__pycache__, .pyc files) | Operator can disable bytecode caching (`PYTHONDONTWRITEBYTECODE=1`). | Set env var (1 second). |

---

## Hunting on Source (Attacker's Host)

### 1. Python Process Execution

#### Live Process Monitoring

**Linux:**
```bash
# Find all python processes
ps aux | grep python

# Show full command-line of python processes
ps aux | grep python | awk '{print $2}' | xargs -I {} cat /proc/{}/cmdline | tr '\0' ' ' && echo

# Filter for pwntools-specific patterns
ps aux | grep -E 'python.*exploit|python.*pwn|python.*rop'

# Monitor new Python processes in real-time
auditctl -w /usr/bin/python3 -p x -k python_exec
ausearch -k python_exec
```

**Windows (PowerShell):**
```powershell
# Find python processes
Get-Process python* | Format-Table Name,Id,CommandLine

# Monitor for python starting with exploit-like names
Get-Process python* | Where-Object {$_.CommandLine -match "exploit|pwn|rop"}

# Enable Sysmon for process auditing
.\Sysmon64.exe -i -accepteula
# Query Sysmon logs for process creation
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} | 
  Where-Object {$_.Message -match "python|exploit"}
```

**macOS:**
```bash
# Monitor process creation
log stream --level debug --predicate 'message contains "python"' --type log

# Alternative: use fs_usage for system call monitoring
fs_usage -w | grep python
```

---

### 2. Pwntools Library Detection

#### File-Based Signatures

**Check for pwntools installation:**
```bash
# Locate pwntools library
python3 -m site | grep site-packages
find /usr -name "pwnlib" -o -name "pwntools*" 2>/dev/null

# Check installed pwntools version
pip show pwntools

# Verify pwntools import succeeds
python3 -c "from pwn import *; print('pwntools available')"
```

**Search for script imports:**
```bash
# Find all Python scripts that import pwntools
grep -r "from pwn import\|from pwnlib import\|import pwntools" /home /root /tmp --include="*.py"

# Alternative: detect __init__ pattern
grep -r "from pwn import \*" /home /root /tmp --include="*.py"

# Find scripts with ROP/shellcraft/tubes indicators
grep -r "shellcraft\|ROP(\|\.process(\|\.remote(" /home /root /tmp --include="*.py"
```

**Cache artifact detection:**
```bash
# Check for pwntools cache files
ls -la ~/.cache/pwntools/
find ~/.cache -name "*.cache" -path "*/pwntools/*"

# Examine gadget cache (indicates ROP development)
find ~/.cache/pwntools/gadgets -type f -mtime -1  # Modified in last 24 hours
```

---

### 3. Shell History Analysis

#### Bash/Zsh History

```bash
# Display shell history (export first if currently running)
history
cat ~/.bash_history | grep -E "python|exploit|pwntools|gdb|remote"

# Extract commands with timestamps (if configured)
export HISTTIMEFORMAT='%Y-%m-%d %H:%M:%S '
history

# Check for cleared history (suspicious indicator)
ls -la ~/.bash_history  # Very recent file with 0 size suggests clearing

# Find alternate history locations
find ~ -name "*history*" -o -name ".*history"
```

#### Command-Line Evidence

```bash
# Check currently running Python with arguments
ps aux | grep python | grep -v grep

# Extract full environment
strings /proc/PID/environ | grep -E "HOME|PYTHONPATH|PWD"

# Recover deleted history from unallocated filesystem space
# (Requires forensic tools; use for post-breach analysis)
```

---

### 4. Network Connections from Attacker Host

#### Active Connections

**Linux:**
```bash
# Show established connections
netstat -antp | grep ESTABLISHED

# Alternative (more modern)
ss -antp | grep ESTABLISHED

# Filter for Python processes
netstat -antp | grep python

# Show listening ports (for reverse shells)
netstat -antp | grep LISTEN | grep python
```

**Windows:**
```powershell
# Show established connections with process owner
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess

# Map to process
Get-NetTCPConnection -State Established | ForEach-Object {
  $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
  $_ | Add-Member -NotePropertyName ProcessName -NotePropertyValue $proc.ProcessName -Force
  $_
} | Select-Object ProcessName,LocalAddress,LocalPort,RemoteAddress,RemotePort
```

**macOS:**
```bash
# Show all established TCP connections
netstat -antp tcp | grep ESTABLISHED

# Alternative
lsof -i -n -P | grep ESTABLISHED
```

#### Historical Connections (pcap)

```bash
# Capture network traffic during exploit
sudo tcpdump -i any -w exploit_traffic.pcap 'tcp'

# Analyze capture
tcpdump -r exploit_traffic.pcap | grep -E "python|ESTABLISHED"
wireshark exploit_traffic.pcap
```

---

### 5. Subprocess and Child Process Activity

#### Process Tree Analysis

**Linux:**
```bash
# Show process hierarchy
pstree -p -u | grep python

# Get full process tree including command-line args
ps -ef --forest | grep python

# Monitor process creation in real-time
auditctl -a always,exit -F arch=b64 -S execve -F uid=1000 -k exec_monitoring
ausearch -k exec_monitoring --format text
```

**Windows (Sysmon):**
```powershell
# Query Sysmon Event 1 for process creation
Get-WinEvent -FilterHashtable @{
  LogName="Microsoft-Windows-Sysmon/Operational"
  ID=1
} | Where-Object {$_.Message -match "python"} | Format-Table TimeCreated,Message -AutoSize

# Filter for suspicious parent-child pairs
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} |
  Where-Object {($_.Message -match "ParentImage.*python") -or ($_.Message -match "Image.*python")} |
  Format-Table TimeCreated,Message
```

---

### 6. GDB and Debugging Evidence

#### Debugger Process Detection

```bash
# Find running GDB instances
ps aux | grep gdb

# Check for GDB history
cat ~/.gdb_history | head -20

# Locate GDB initialization file
cat ~/.gdbinit

# Search for GDB scripts
find /home /root /tmp -name "*gdb*" -type f
```

---

### 7. Git Repository History

#### Version Control Evidence

```bash
# Search for Git repos in likely locations
find /home /root -name ".git" -type d

# Check Git log for exploit development
cd /path/to/repo && git log --oneline | head -20

# View commit diffs
git log -p | grep -E "shellcode|ROP|exploit"

# Extract author information
git log --format="%an <%ae>" | sort | uniq -c

# Check for suspicious branch names
git branch -a | grep -E "exploit|pwn|test"

# Get repository remote URLs (may reveal infrastructure)
git remote -v
git config --list | grep url
```

---

## Hunting on Target (Compromised Host)

### 1. Process Evidence: Unexpected Child Processes

#### Live Process Inspection

**Linux:**
```bash
# List running processes with parents
ps -ef | head -20

# Focus on suspicious parent-child relationships
ps -ef | awk '$3 !~ /^(1|2|init|systemd)$/ {print $0}' | head -20
# (Filter for processes whose parent is not init, systemd, or PID 1/2)

# Check for shell spawned from unexpected binary
ps -ef | grep -E "bash|sh|cmd" | grep -v "bash -c|sh -c" | grep -v "^root"

# Deep process tree inspection
pstree -p | grep -A5 -B5 "bash\|cmd"
```

**Windows (Sysmon):**
```powershell
# Query for unexpected process spawning
Get-WinEvent -FilterHashtable @{
  LogName="Microsoft-Windows-Sysmon/Operational"
  ID=1
} | Where-Object {
  ($_.Message -match "ParentImage.*[^\\](python|java|node|dotnet)\.exe") -and
  ($_.Message -match "Image.*(cmd|powershell|bash)\.exe")
} | Format-Table TimeCreated,Message -AutoSize

# Alternative: look for process names that don't match their parent context
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1} |
  Select-Object @{N="ParentImage";E={$_.Message -replace '.*ParentImage: (.+?)\s.*','$1'}},
                @{N="Image";E={$_.Message -replace '.*Image: (.+?)\s.*','$1'}},
                TimeCreated
```

---

### 2. Memory Analysis: Core Dumps and Crashes

#### Core Dump Examination

**Linux:**
```bash
# List core dumps
ls -la /var/crash/ /tmp/cores/

# Analyze core dump with GDB
gdb /path/to/binary /path/to/core_dump

# Inside GDB:
# bt           — Backtrace (call stack)
# info registers  — Show register state
# x/100bx $rsp — Hex dump of stack (look for repeating patterns like 0x41414141)
# disassemble 0x401234  — Show instructions at address

# Extract memory from core dump
gdb -batch -ex 'target core core_dump' -ex 'dump memory dump.bin 0x7ffffffde000 0x7ffffffff000'

# Analyze memory dump for patterns
strings dump.bin | grep -E "shellcode|payload|gadget"
hexdump -C dump.bin | grep -E "41 41 41 41|48 c7 c7"  # Look for repeating bytes or assembly
```

**Windows:**
```powershell
# Locate crash dumps
Get-ChildItem C:\ProgramData\Microsoft\Windows\WER\ReportArchive -Recurse -Include *.dmp

# Analyze with WinDbg
# Open dump file in WinDbg: File > Open Crash Dump
# Commands:
#   !analyze -v   — Automated analysis
#   k             — Backtrace
#   r             — Registers (look for suspicious RIP values)
#   db rsp L100   — Dump stack memory (look for shellcode patterns)
```

---

### 3. Event Log Hunting

#### Linux Kernel and Audit Logs

**auditd events:**
```bash
# Search for process crashes (signal 11)
ausearch -m ANOM_ABEND | grep "signal=11"

# Look for EXECVE events (process spawning)
ausearch -m EXECVE

# Filter by PID of interest
ausearch -p PID_TO_HUNT

# Extract timeline
ausearch --start recent -m EXECVE -m FORK -m EXIT | sort -t'(' -k2 -n
```

**Kernel logs:**
```bash
# View segmentation faults
dmesg | grep -i "segfault\|signal 11\|killed"

# Check for out-of-memory kills (OOM)
journalctl -u kernel | grep -i "oom"

# View process termination
journalctl -u systemd | grep -i "terminated\|crashed"
```

#### Windows Event Logs

**Sysmon Process Creation (Event 1):**
```powershell
# Query for suspicious process parent-child relationships
$events = Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=1}

$events | Where-Object {
  # Look for unexpected shell spawning from non-system processes
  ($_.Message -match "ParentImage.*(?<!System32)[^\\].*\.(exe|dll)") -and
  ($_.Message -match "Image.*(cmd|powershell|powershell_ise|bash|sh)\.exe")
} | Sort-Object TimeCreated | Select-Object TimeCreated,Message | Format-Table -AutoSize
```

**Sysmon Image Load (Event 7) — Shellcode DLL Injection:**
```powershell
# Find unexpected DLL loads (e.g., WinINet from vuln process)
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; ID=7} |
  Where-Object {$_.Message -match "ImageLoaded.*\.(dll|so)"} |
  Sort-Object TimeCreated | Select-Object TimeCreated,Message | Format-Table -AutoSize
```

---

### 4. Network Evidence: Inbound Exploits

#### Connection Logs

**Linux:**
```bash
# Find established connections in netstat (if captured at time of exploit)
netstat -antp 2>/dev/null | grep ESTABLISHED

# Check SSH logs for unexpected logins
grep "Accepted password\|Failed password" /var/log/auth.log | tail -20

# Check for inbound connections on unusual ports
netstat -antp | grep LISTEN | grep -v "127.0.0\|:22\|:80\|:443"
```

**Windows:**
```powershell
# Query firewall logs for inbound connections
Get-WinEvent -FilterHashtable @{
  LogName="Microsoft-Windows-Firewall/Operational"
} | Where-Object {$_.Message -match "Inbound|5152"} | 
  Select-Object TimeCreated,Message | Sort-Object TimeCreated | Format-Table -AutoSize

# Check RDP connections (Security Event 4624 - Account Logon)
Get-WinEvent -FilterHashtable @{
  LogName="Security"
  ID=4624
} | Where-Object {$_.Message -match "RDP|Terminal"} | 
  Sort-Object TimeCreated | Select-Object TimeCreated,Message | Format-Table -AutoSize
```

#### Packet Capture Analysis

```bash
# Capture traffic during suspected attack window
sudo tcpdump -i any 'tcp and (dst port 9000 or src port 9000)' -w exploit.pcap

# Analyze for exploit patterns
tcpdump -r exploit.pcap -A | grep -E "shellcode|payload|ROP|0x[0-9a-f]{8,16}"

# Use Zeek for protocol analysis
zeek -r exploit.pcap
cat conn.log | grep "9000"  # Check for the vulnerable port
```

---

### 5. Filesystem Evidence

#### Temporary Files and Artifacts

**Linux:**
```bash
# Find recently modified files in /tmp
find /tmp -mtime -1 -ls 2>/dev/null | head -20

# Search for suspicious filenames
find /tmp /var/tmp -name "*shell*" -o -name "*payload*" -o -name "*exploit*"

# Check for modified binaries
find /usr/bin /usr/local/bin -mtime -1 -ls

# Look for LD_PRELOAD tricks (malicious .so files)
ldd /path/to/vuln_binary | grep -v "/lib\|/usr/lib"
```

**Windows:**
```powershell
# Find recently created files
Get-ChildItem -Path C:\temp,C:\Windows\temp -File -Recurse | 
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-1)} | 
  Select-Object FullName,LastWriteTime

# Search for suspicious file patterns
Get-ChildItem -Path C:\ -Recurse -Filter "*shell*" -o -Filter "*payload*" -ErrorAction SilentlyContinue
```

#### Binary Integrity Verification

```bash
# Compare binary hash before/after exploit
sha256sum /usr/bin/vulnerable_binary
# (Compare against known-good hash from vendor or baseline)

# Use tripwire/aide for file integrity monitoring
aide --check

# Binary diff to identify changes
hexdump -C vulnerable_binary.baseline > baseline.hex
hexdump -C /usr/bin/vulnerable_binary > current.hex
diff baseline.hex current.hex
```

---

### 6. Privilege Escalation Tracking

#### Root-Level Process Activity

```bash
# Check for unexpected setuid process execution
find / -perm -4000 -type f 2>/dev/null | while read binary; do
  # Check if recently executed
  stat "$binary" | grep Access
done

# Monitor for UID 0 (root) process creation
ausearch -m EXECVE -F uid=0 --format text | grep -v "kernel\|init\|systemd"
```

#### Sudo Access

```bash
# Check sudo logs for unauthorized usage
cat /var/log/auth.log | grep sudo | tail -20

# Alternative: check secure log (some systems)
grep sudo /var/log/secure
```

---

## Hunting Queries (SIEM/Detection)

### Splunk Queries

#### Pwntools Library Import on Endpoint

```spl
index=main source=*/auth.log OR source=*/syslog 
"from pwn import" OR "from pwnlib import" OR "import pwntools"
| stats count by host, user
```

#### Python Process with Suspicious Arguments

```spl
index=endpoint_process parent_process_name="python*" 
(process_name="cmd.exe" OR process_name="powershell.exe" OR process_name="/bin/bash")
| stats values(command_line) by host, parent_command_line
```

#### Unexpected Network Connections from Python

```spl
index=network protocol=tcp process_name="python*" 
dest_port NOT IN (80, 443, 22, 53, 3306, 5432, 27017)
| stats count by src_ip, dest_ip, dest_port, process_name
| where count > 5
```

#### Process Segmentation Fault (Signal 11)

```spl
index=main "segfault" OR "signal 11" OR "SIGSEGV"
| stats count by src_host, process_name | where count > 0
```

### Elastic/Kibana Queries

#### Sysmon Event 1: Suspicious Parent-Child

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": 1 } },
        { "match": { "process.parent.name": "python*" } },
        { "match": { "process.name": ["cmd.exe", "powershell.exe", "bash"] } }
      ]
    }
  }
}
```

#### Network Egress from Non-System Process

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "process.name": "python*" } },
        { "match": { "network.type": "ipv4" } },
        { "range": { "destination.port": { "gte": 1024 } } }
      ]
    }
  }
}
```

---

## Manual Hunting Workflow

### Incident Response Checklist

1. **Identify attack window** — Time of first suspicious event (network connection, crash, process spawning).
2. **Collect process tree** — `ps -ef`, Sysmon logs, auditd records.
3. **Extract core dump** — `/var/crash/`, `dmesg`, WinDbg crash dump analysis.
4. **Analyze memory** — Search for ROP gadget patterns, shellcode signatures, leaked addresses.
5. **Review event logs** — auditd EXECVE, Sysmon Event 1, Windows Security logs.
6. **Capture network evidence** — Check netstat (establish timing), review firewall/IDS logs.
7. **File system forensics** — Hash modified binaries, examine /tmp, check for backdoors.
8. **Timeline reconstruction** — Correlate all evidence sources (network, process, file timestamps).

### Prioritization Matrix

| Evidence Type | Collection Ease | Evasion Resistance | Priority |
|---|---|---|---|
| Core dump | Medium (requires crash)| High (process memory)| **CRITICAL** |
| Process tree (Sysmon) | Easy (logs exist) | High (OS-enforced) | **CRITICAL** |
| Network logs | Easy (firewall) | High (network-level) | **HIGH** |
| Event logs | Easy (available) | Medium (can be cleared) | **HIGH** |
| Shell history | Easy (filesystem) | Low (easily cleared) | MEDIUM |
| Temporary files | Medium (may be deleted)| Medium (can be cleaned) | MEDIUM |

