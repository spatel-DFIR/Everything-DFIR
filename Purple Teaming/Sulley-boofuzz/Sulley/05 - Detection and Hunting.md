# Sulley — Detection and Hunting

Hands-on commands to find Sulley activity on both source (attacker) and target (victim) systems.

---

## Hunting on Source (Attacker's Machine)

### Command 1: Find Sulley Fuzz Scripts

```bash
# Search for Sulley import statements in Python files
find /home /root /tmp -type f -name "*.py" 2>/dev/null | xargs grep -l "from sulley import" 2>/dev/null

# Or search for key Sulley API calls
find /home /root /tmp -type f -name "fuzz*.py" 2>/dev/null | xargs grep -l "sessions.Session" 2>/dev/null

# PowerShell equivalent (if Python on Windows):
Get-ChildItem -Path C:\Users -Recurse -Include "*.py" -EA SilentlyContinue | Select-String "from sulley import" -ErrorAction SilentlyContinue
```

**Expected Output:** Paths to fuzz scripts (e.g., `/home/attacker/fuzz_target_http.py`)

---

### Command 2: Locate Fuzz Results Directory

```bash
# Search for the characteristic "fuzz_results" directory and its contents
find /home /root /tmp -type d -name "fuzz_results" -o -name "fuzz_logs" 2>/dev/null

# Check for subdirectories:
find /home /root /tmp -type f -name "index.html" 2>/dev/null | grep -i fuzz

# List crash files:
find /home /root /tmp -type f -name "crash*" 2>/dev/null | head -20

# Check for process monitor logs:
find /home /root /tmp -type f -name "*process_monitor*" 2>/dev/null
```

**Expected Output:** Directories containing `index.html`, `crash/`, `logs/` subdirectories

**Forensic Value:** Finding this directory is **definitive proof** of Sulley fuzzing activity

---

### Command 3: Check Recent Python Process Execution

```bash
# On Linux, check process accounting (if enabled):
lastcomm | grep -i python | head -20

# Check shell history:
cat ~/.bash_history ~/.zsh_history 2>/dev/null | grep -i "fuzz\|sulley\|python.*fuzz" | head -20

# Check for Python processes in process monitor logs (Windows):
Get-Process python -ErrorAction SilentlyContinue | Select Name, CommandLine, ProcessId
```

**Expected Output:** Commands invoking `python3 fuzz_*.py` or similar

---

### Command 4: Identify Installed Sulley Library

```bash
# Check if Sulley is installed:
python3 -c "import sulley; print(sulley.__file__)" 2>/dev/null

# Or:
pip show sulley 2>/dev/null

# Find Sulley module files:
find /usr -name "sulley" -type d 2>/dev/null
find ~/.local -name "sulley" -type d 2>/dev/null
```

**Expected Output:** Path to Sulley installation (e.g., `/usr/local/lib/python3.9/dist-packages/sulley/`)

---

### Command 5: Monitor for Active Sulley Process

```bash
# Check for running Python processes with network connections:
netstat -anp | grep python | head -20

# Or (modern systems):
ss -anp | grep python | head -20

# Check what connections a specific Python process is making:
# (Replace 12345 with actual PID)
lsof -p 12345 | grep ESTABLISHED

# On Windows:
Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq (Get-Process python).Id} | Select LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

**Expected Output:** Python process with ESTABLISHED connections to unusual ports/IPs (fuzzing targets)

---

### Command 6: Check System Logs for Sulley Artifacts

```bash
# Search syslog for Python-related process crashes (if Sulley targets crashed):
grep -i "python\|segfault\|exception" /var/log/syslog /var/log/messages 2>/dev/null | head -20

# Check dmesg for kernel-level crashes:
dmesg | grep -i "segfault\|SEGV" | head -10
```

**Expected Output:** Correlation between Python process execution and target crashes

---

### Command 7: Disk Space Analysis

```bash
# Find large directories that might contain fuzz results:
du -sh /home/* /root/* /tmp/* 2>/dev/null | sort -rh | head -20

# Check for recent large file modifications:
find /home /root /tmp -type f -size +10M -mmin -120 2>/dev/null | head -20
```

**Expected Output:** Unusually large directories (fuzz_results with 100s of MB of logs)

---

## Hunting on Target (Victim's Machine)

### Command 1: Windows — Check Event Log for Crashes

```powershell
# PowerShell: Get all application crashes in the last hour
$startTime = (Get-Date).AddHours(-1)
Get-EventLog -LogName Application -InstanceId 1000, 1001 -After $startTime |
    Select TimeGenerated, EventID, Message |
    Format-Table -AutoSize

# Alternative: Check System log for service crashes
$startTime = (Get-Date).AddHours(-1)
Get-EventLog -LogName System -InstanceId 7034, 7035 -After $startTime |
    Select TimeGenerated, Source, EventID, Message |
    Format-Table -AutoSize

# More detailed: All errors for a specific service in the past 2 hours
$startTime = (Get-Date).AddHours(-2)
Get-EventLog -LogName Application -After $startTime |
    Where-Object {$_.EntryType -eq "Error" -or $_.EntryType -eq "Warning"} |
    Select TimeGenerated, Source, Message |
    Format-Table -AutoSize
```

**Expected Output:** Multiple crash events (Event ID 1000, 1001, 7034) with different fault addresses and timestamps clustered within minutes

---

### Command 2: Windows — Analyze Crash Dump Files

```powershell
# Find crash dump files:
Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER\ReportArchive -Recurse -Include *.dmp -EA SilentlyContinue | 
    Sort-Object LastWriteTime -Descending |
    Select FullName, LastWriteTime, Length |
    Head -20

# Or in user-specific temp directories:
Get-ChildItem -Path $env:LOCALAPPDATA\Temp -Include *.dmp -Recurse -EA SilentlyContinue |
    Sort-Object LastWriteTime -Descending
```

**Expected Output:** Multiple `.dmp` files with recent timestamps

**Analysis:** Open dump with WinDbg:
```cmd
windbg -z crash.dmp
# In WinDbg:
!analyze -v
# Shows crash information: exception type, address, call stack
```

---

### Command 3: Linux/Unix — Check System Logs for Crashes

```bash
# Search for segmentation fault messages:
grep -i "segfault\|segmentation\|signal.*11" /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | tail -30

# Or with timestamp:
journalctl --since "1 hour ago" | grep -i "segfault\|crashed" | head -20

# Check for service restart patterns:
journalctl --since "1 hour ago" -u myapp.service | grep -E "exited|failed|Attempting restart"
```

**Expected Output:**
```
Aug 11 14:23:47 target kernel: myapp[12456]: segmentation fault at ip 401234 sp 7fff1234
Aug 11 14:23:51 target kernel: myapp[12467]: segmentation fault at ip 401300 sp 7fff1230
Aug 11 14:23:55 target kernel: myapp[12478]: segmentation fault at ip 401244 sp 7fff122c
```

Multiple segfaults with **different IP (instruction pointer) addresses** = fuzzing

---

### Command 4: Check for Core Dump Files

```bash
# Find core dumps:
find /var/crash /tmp /home -name "core*" -type f 2>/dev/null | head -20

# Check size (large core dumps indicate process memory):
ls -lh /var/crash/core* /tmp/core* 2>/dev/null

# Check core dump timestamps:
stat /var/crash/core* 2>/dev/null | grep -i "access\|modify"

# Enable core dumps and check status:
ulimit -c  # Show current limit (0=disabled)
```

**Expected Output:** Multiple core files with timestamps clustered during suspected fuzzing window

**Analyze core dump:**
```bash
gdb ./target_binary /var/crash/core.12345
(gdb) where
# Shows call stack of crashed process
(gdb) print $rax
# Shows register contents at crash
```

---

### Command 5: Check Application Logs for Protocol Errors

```bash
# Search application logs for malformed protocol messages:
grep -i "error\|invalid\|malformed\|checksum\|syntax" /var/log/myapp.log 2>/dev/null | tail -50

# Count error types:
grep -i "error\|invalid" /var/log/myapp.log 2>/dev/null | cut -d' ' -f1-10 | sort | uniq -c | sort -rn

# Check for null bytes or unusual characters in log (indicates fuzzed payloads):
grep -P "\x00" /var/log/myapp.log 2>/dev/null | head -10

# Or search for specific fuzzing patterns:
grep -E "\\\\x[0-9a-f]{2}|\\\\xff|\\\\x00|AAAA" /var/log/myapp.log 2>/dev/null | head -10
```

**Expected Output:** High volume of error messages with field-level variations (same error type, different values)

---

### Command 6: Network Traffic Analysis (Packet Capture)

```bash
# Live packet capture from single source IP (attacker):
tcpdump -i any -n "src 192.168.1.50" -w /tmp/attacker.pcap

# Analyze captured packets:
tcpdump -r /tmp/attacker.pcap -n | head -30

# Show summary of source/destination pairs:
tcpdump -r /tmp/attacker.pcap -n | awk '{print $3, $5}' | sort | uniq -c | sort -rn

# Wireshark (GUI) — open pcap and apply filter:
# In Wireshark filter bar: "ip.src == 192.168.1.50"
# Look for repeated message structure with field variations
```

**Expected Output:** High volume of packets from single IP to one target:port, with repeated message structure but differing payloads

---

### Command 7: Check for Unusual Process Behavior (Restarts/Crashes)

```bash
# Monitor process restart rate (Windows):
Get-EventLog -LogName System -InstanceId 7034 -After ((Get-Date).AddHours(-1)) |
    Group-Object Source |
    Where-Object {$_.Count -gt 10} |
    Select Name, Count

# Linux — check systemd restart count:
systemctl status myapp.service
# Look for "Active: active (running)" with recent restart timestamps
# Or: journalctl -u myapp.service -n 100 | grep -i "exited\|restart"

# Unix process accounting — show process execution history:
lastcomm | grep myapp | head -20
# Look for multiple crash/restart entries clustered in time
```

**Expected Output:** Service restarting 50+ times in 1 hour (normal: 0-2 per day)

---

### Command 8: Identify Attack Source IP

```bash
# Extract source IP from network logs:
# (Assumes application or IDS logs traffic)
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" /var/log/myapp.log | sort | uniq -c | sort -rn | head -10

# Or from HTTP access log:
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Network view — show top talkers to this host:
netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

# Firewall/WAF logs:
grep "192.168.1.50" /var/log/ufw.log /var/log/suricata/stats.log 2>/dev/null | head -20
```

**Expected Output:** Single IP with disproportionately high connection/error count

---

### Command 9: Prefetch Analysis (Windows)

```powershell
# Tool: WinPrefetchView (download from nirsoft.net or use built-in)

# PowerShell approach — parse prefetch files:
# (Requires specialized parser; simpler: just check modification times)
Get-ChildItem C:\Windows\Prefetch -Include "*.pf" |
    Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-2)} |
    Sort-Object LastWriteTime -Descending |
    Select Name, LastWriteTime, @{Name="Size";Expression={$_.Length/1MB}}

# High hit count (run count) for a service indicates restarts:
# (Run count embedded in .pf file binary; requires hex dump or tool)
cmd /c "type C:\Windows\Prefetch\MYAPP.EXE-HASH.pf" | find "1e4d f6f6" # Run count pattern (for experienced analysts)
```

**Expected Output:** Recent `.pf` file modification times clustering during suspected fuzzing window

---

### Command 10: IDS/WAF Alert Correlation

```bash
# Check Snort/Suricata logs:
tail -100 /var/log/snort/alert | grep -i "protocol\|anomaly\|fuzzer"

# Check WAF logs (if present):
grep "192.168.1.50" /var/log/modsecurity_audit.log 2>/dev/null | tail -30

# Extract unique request patterns:
grep "192.168.1.50" /var/log/apache2/access.log 2>/dev/null |
    awk '{print $7}' | sort | uniq -c | sort -rn |
    head -20
```

**Expected Output:** Rules triggered for "malformed request," "protocol violation," "suspicious pattern," etc., from single source IP

---

## Hunting Priority: By Evasion Resistance

**Rank these signals by how well they survive evasion attempts:**

### Tier 1: Invariant Signals (Cannot be Hidden)

1. **Target crash with unique fault address** — Each fuzz variant that crashes may hit a different memory address; multiple different crash addresses in short time = fuzzing signature
   - Resistance: VERY HIGH — crashes are kernel-level, can't be hidden by user-mode code
2. **Crash dumps + multiple fault addresses** — Core dumps capture exact memory state
   - Resistance: VERY HIGH — would require disabling core dumps (suspicious) or kernel-level hooking (extremely rare)

### Tier 2: Protocol-Level Signals (Hard to Hide)

3. **Protocol error logs** — Service logs errors when receiving malformed messages
   - Resistance: HIGH — would require disabling logging (degrades security, suspicious)
   - Bypass: Operator could disable logging, but this leaves audit trail of logging-disable
4. **Network packet analysis** — tcpdump shows malformed messages
   - Resistance: HIGH — can't send valid packets if fuzzing; would require replay of valid messages (not fuzzing)

### Tier 3: System-Level Signals (Moderate Resistance)

5. **Event log crash entries** — Windows logs application crashes
   - Resistance: MEDIUM — operator with admin could delete event logs (forensic artifact itself)
6. **Service restart clustering** — Repeated restart events in systemd/Windows logs
   - Resistance: MEDIUM — can be log-deleted

### Tier 4: Source-Side Signals (Weakest, Requires Access to Attacker Machine)

7. **Fuzz scripts on disk** — Python scripts containing Sulley code
   - Resistance: LOW — operator could delete scripts (only if incident response hasn't imaged system)
8. **Fuzz results directory** — Crash files and logs
   - Resistance: LOW — operator could delete, but leaves filesystem artifacts (slack space, MFT entries)
9. **Shell history** — Records commands run
   - Resistance: LOW — can be edited or cleared (bash history file is user-writable)

---

## Hunting Strategy by Access Level

### If You Have Access to Target Only (Most Common DFIR Scenario)

**Priority order:**

1. **Search event logs** (Windows) or syslog (Linux) for crash clustering
2. **Analyze crash dumps** (Windows) or core dumps (Linux) for multiple fault addresses
3. **Search application logs** for protocol error patterns
4. **Packet capture analysis** (if pcap available) for malformed message patterns
5. **Timeline correlation:** Match network timestamps to crash event timestamps

### If You Have Access to Both Target and Attacker Machine

**Added investigative leverage:**

1. **Confirm fuzz script on attacker machine** — proves intent and target
2. **Match fuzz test case number to target crash timestamp** — definitive timeline proof
3. **Extract crash PoC** from attacker's fuzz_results directory — weaponizable evidence
4. **Correlate source/target timelines** — show exactly what was sent, when, and what crashed

### Indicator Combination (High Confidence)

**If you find ANY TWO of these together, Sulley fuzzing is almost certain:**

- Protocol error logs + service restart clustering (target-side)
- Crash dumps with multiple distinct fault addresses + network traffic analysis showing payload variations (target-side)
- Fuzz script + fuzz_results directory + crash files (attacker-side)
- Network traffic pattern (malformed messages with systematic variation) + application protocol errors (split observation)

**False positive risk: <5%**

---

## Sample Hunt Commands (Copy-Paste Ready)

### Unified Hunt (Linux Target, 1 Hour Window)

```bash
#!/bin/bash
# Hunt for Sulley activity on a compromised Linux system

echo "[+] Checking for crashes in the last hour..."
grep -i "segfault" /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | tail -20

echo "[+] Checking for service restarts..."
journalctl --since "1 hour ago" | grep -i "exited\|failed\|restart" | head -20

echo "[+] Checking for protocol error logs..."
grep -i "error\|invalid\|malformed" /var/log/myapp.log 2>/dev/null | wc -l

echo "[+] Looking for core dumps..."
find /var/crash /tmp -name "core*" -mmin -60 2>/dev/null

echo "[+] Checking netstat for sustained connections..."
netstat -an | grep ESTABLISHED | awk '{print $4, $5}' | sort | uniq -c | sort -rn | head -10

echo "[+] Done."
```

### Unified Hunt (Windows Target, 1 Hour Window)

```powershell
# Hunt for Sulley activity on a compromised Windows system

Write-Host "[+] Checking for application crashes in the last hour..."
$startTime = (Get-Date).AddHours(-1)
Get-EventLog -LogName Application -InstanceId 1000, 1001 -After $startTime | Select TimeGenerated, Message | Format-Table -AutoSize

Write-Host "[+] Checking for service restarts..."
Get-EventLog -LogName System -InstanceId 7034, 7035 -After $startTime | Select TimeGenerated, Source | Format-Table -AutoSize

Write-Host "[+] Counting crashes by process..."
Get-EventLog -LogName Application -InstanceId 1000, 1001 -After $startTime | Group-Object Message | Select Name, Count | Sort-Object Count -Descending

Write-Host "[+] Looking for crash dump files..."
Get-ChildItem -Path C:\ProgramData\Microsoft\Windows\WER\ReportArchive -Recurse -Include *.dmp -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select FullName, LastWriteTime | Head -10

Write-Host "[+] Checking network connections..."
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | Group-Object RemoteAddress | Sort-Object Count -Descending | Head -10

Write-Host "[+] Done."
```

---

## Summary: High-Confidence Hunting Checklist

- [ ] **1+ crash events with distinct fault addresses** (target)
- [ ] **3+ crashes within 1 hour** (vs. normal: 0-2 per week) (target)
- [ ] **Protocol error log entries** showing systematic field variation (target)
- [ ] **Fuzz script file** on attacker's machine (attacker)
- [ ] **fuzz_results/ directory** with crash files (attacker)
- [ ] **Network traffic analysis** showing repeated message structure with payload variation (network)
- [ ] **Timeline correlation:** network event → target crash log timestamp match (correlation)

**If ≥3 of these are true, Sulley fuzzing activity is high-confidence.**
