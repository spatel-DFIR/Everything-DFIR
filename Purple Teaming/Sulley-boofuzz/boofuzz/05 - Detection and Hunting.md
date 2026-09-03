# boofuzz — Detection and Hunting

## Hunting on Source (Attacker's Machine)

### Command 1: Find boofuzz Fuzz Scripts

```bash
# Search for boofuzz imports
find /home /root /tmp -type f -name "*.py" 2>/dev/null | xargs grep -l "from boofuzz import" 2>/dev/null

# Search for Session() calls specific to boofuzz
grep -r "Session(" /home /root /tmp --include="*.py" 2>/dev/null | grep -i boofuzz

# Find fuzz scripts by name pattern
find /home /root /tmp -type f -name "fuzz*.py" -o -name "*fuzz*.py" 2>/dev/null
```

**Expected Output:** Paths like `/home/attacker/fuzz_http_server.py`, `/tmp/fuzz_dns.py`

---

### Command 2: Locate boofuzz Results (SQLite Database)

```bash
# Find the boofuzz SQLite database (key artifact)
find /home /root /tmp -name "boofuzz.db" 2>/dev/null

# Find all boofuzz-related result directories
find /home /root /tmp -type d -name "*fuzz*" 2>/dev/null | xargs ls -la

# Check for CSV exports
find /home /root /tmp -name "boofuzz.csv" 2>/dev/null

# Look for crash files
find /home /root /tmp -name "crash_*" -type f 2>/dev/null | head -20
```

**Expected Output:** Directories containing `boofuzz.db`, `boofuzz.csv`, `crash/` subdirs

**Forensic Value:** **DEFINITIVE** — boofuzz.db is unmistakable proof of boofuzz activity

---

### Command 3: Query boofuzz SQLite Database (Forensic Analysis)

```bash
# If boofuzz.db found, analyze it directly

# Count total test cases
sqlite3 /path/to/boofuzz.db "SELECT COUNT(*) as total_tests FROM test_case;"

# Count crashes
sqlite3 /path/to/boofuzz.db "SELECT COUNT(*) as crash_count FROM test_case WHERE passed = 0;"

# List crash details
sqlite3 /path/to/boofuzz.db "SELECT test_case_num, crash_type, crash_address FROM test_case WHERE passed = 0 LIMIT 10;"

# Export all crash payloads (hex dump)
sqlite3 /path/to/boofuzz.db "SELECT test_case_num, payload FROM test_case WHERE passed = 0;" | while read num payload; do
    echo "Test case $num: $payload"
done

# Get fuzzing duration
sqlite3 /path/to/boofuzz.db "SELECT MIN(test_case_start_time), MAX(test_case_end_time) FROM test_case;"
```

**Output:** Complete reconstruction of fuzzing campaign (duration, target, crash details)

---

### Command 4: Analyze boofuzz.csv Spreadsheet Export

```bash
# View CSV summary
head -50 /path/to/boofuzz.csv | column -t -s,

# Count rows (test cases)
wc -l /path/to/boofuzz.csv

# Find crash rows
grep ",CRASH," /path/to/boofuzz.csv | wc -l

# Extract target information (if CSV contains it)
grep -i "target\|host\|port" /path/to/boofuzz.csv | head -5
```

**Expected Output:** Test case summary in tabular format (importable into Excel)

---

### Command 5: Check for Installed boofuzz Module

```bash
# Check Python path
python3 -c "import boofuzz; print(boofuzz.__file__)"

# List boofuzz package contents
ls -la /usr/local/lib/python3.*/dist-packages/boofuzz/ 2>/dev/null

# Check pip record
pip show boofuzz 2>/dev/null
```

**Expected Output:** Installation path confirms boofuzz is available/was installed

---

### Command 6: Monitor Active boofuzz Process

```bash
# Find running Python processes with network connections
netstat -anp 2>/dev/null | grep python

# More detailed: show PID and command
ps aux | grep "[p]ython.*fuzz"

# Check what networks/ports a Python process is connecting to
# (Replace PID with actual process ID)
lsof -p [PID] | grep ESTABLISHED

# Windows equivalent
Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq (Get-Process python).Id}
```

**Expected Output:** Python process with connections to unusual hosts/ports

---

### Command 7: Check Shell History for boofuzz Commands

```bash
# Search history for boofuzz or fuzz-related commands
grep -E "boofuzz|fuzz.*\.py|sqlite3.*boofuzz" ~/.bash_history ~/.zsh_history 2>/dev/null

# Search for Python execution of fuzz scripts
grep "python.*fuzz" ~/.bash_history ~/.zsh_history 2>/dev/null

# Look for database queries (analyzing results)
grep "sqlite3" ~/.bash_history ~/.zsh_history 2>/dev/null | grep -i fuzz
```

**Expected Output:** Command history confirming fuzzing activity and post-fuzz analysis

---

## Hunting on Target (Victim's Machine)

### Command 1: Windows — Query Event Logs for Crashes

```powershell
# Get crashes in last 2 hours
$startTime = (Get-Date).AddHours(-2)
Get-EventLog -LogName Application -InstanceId 1000, 1001, 1004 -After $startTime |
    Select TimeGenerated, Source, EventID, Message |
    Format-Table -AutoSize

# Group crashes by application
Get-EventLog -LogName Application -After $startTime |
    Where-Object {$_.EventID -eq 1000 -or $_.EventID -eq 1001} |
    Group-Object Source |
    Where-Object {$_.Count -gt 5} |
    Select Name, @{Name="CrashCount";Expression={$_.Count}}
```

**Expected Output:** Application crashes grouped by service (50+ crashes in 1 hour = fuzzing)

---

### Command 2: Linux — Search Logs for Crash Patterns

```bash
# Find segmentation faults in syslog
grep "segmentation fault\|segfault\|SIGSEGV" /var/log/syslog /var/log/messages /var/log/kern.log 2>/dev/null | tail -30

# Count unique crash addresses (multiple = fuzzing, single = reproducible bug)
grep "segmentation fault" /var/log/syslog 2>/dev/null | 
    grep -oE "ip [0-9a-f]+" | 
    awk '{print $2}' | 
    sort | uniq -c | sort -rn

# Check systemd logs for service restarts
journalctl -u myapp.service --since "1 hour ago" | 
    grep -E "exited|failed|restart" | 
    wc -l
    # High count = fuzzing
```

**Expected Output:** Multiple crash addresses, rapid restart clustering

---

### Command 3: Analyze Core Dump Files

```bash
# Find core dumps
find /var/crash /tmp /home -name "core*" -type f -mmin -120 2>/dev/null

# Check core dump timestamps and sizes
ls -lh /var/crash/core* 2>/dev/null | head -20

# Analyze with GDB
gdb ./target_binary /var/crash/core.12345
(gdb) where
# Shows call stack

(gdb) info registers
# Shows CPU state at crash
```

**Expected Output:** Multiple core files with different fault addresses

---

### Command 4: Search Application Logs for Protocol Errors

```bash
# High-volume error entries
grep -i "error\|invalid\|malformed\|checksum\|syntax" /var/log/myapp.log 2>/dev/null | wc -l
# High count in short time = fuzzing

# Extract error types and count
grep -i "error" /var/log/myapp.log 2>/dev/null | 
    cut -d' ' -f1-5 | 
    sort | uniq -c | sort -rn | head -10

# Look for null bytes or unusual characters
hexdump -C /var/log/myapp.log 2>/dev/null | grep "00" | head -10
```

**Expected Output:** High volume of protocol errors with field-level variation

---

### Command 5: Network Packet Analysis

```bash
# If pcap available, analyze packets
tcpdump -r /path/to/fuzz.pcap -n | head -30

# Count packets by source IP
tcpdump -r /path/to/fuzz.pcap -n | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn

# Wireshark (GUI) — filter for attacker IP
# In Wireshark: ip.src == 192.168.1.50
# Look for repeated message structure with field variations
```

**Expected Output:** High volume from single source IP with systematic payload variation

---

### Command 6: Identify Attack Source IP from Logs

```bash
# Extract IPs from application logs
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" /var/log/myapp.log 2>/dev/null | 
    sort | uniq -c | sort -rn | head -10

# From HTTP access logs
awk '{print $1}' /var/log/apache2/access.log | 
    sort | uniq -c | sort -rn | head -10

# From firewall/WAF logs
grep "192.168.1.50" /var/log/ufw.log 2>/dev/null | wc -l
# High count = suspicious
```

**Expected Output:** Single IP with disproportionately high error/connection count

---

### Command 7: Check for Prefetch/Execution Artifacts (Windows)

```powershell
# Find recent prefetch files for the crashed application
Get-ChildItem C:\Windows\Prefetch -Include "MYAPP.EXE-*.pf" -EA SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select Name, LastWriteTime

# Parse prefetch file (requires tool like WinPrefetchView or custom parser)
# Run count indicates number of process invocations
```

**Expected Output:** Recent prefetch modification, high run count (20+ in 1 hour)

---

### Command 8: IDS/WAF Alert Correlation

```bash
# Check Snort/Suricata alerts
tail -100 /var/log/snort/alert | grep -i "protocol\|anomaly\|malformed"

# Check WAF logs (ModSecurity)
grep -i "protocol\|anomaly" /var/log/modsecurity_audit.log 2>/dev/null | tail -20

# Count alerts by type
grep -i "protocol" /var/log/suricata/eve.json 2>/dev/null | wc -l
```

**Expected Output:** Multiple protocol anomaly alerts clustered in time

---

## Hunting Priority (By Evasion Resistance)

### Tier 1: Invariant Signals (Cannot Be Hidden)

1. **Multiple crash addresses in syslog/Event Log** — kernel-level, can't hide
2. **Core dumps or crash dumps** with different call stacks — OS-generated
3. **boofuzz.db SQLite database** (if found on source) — definitive proof

### Tier 2: High Resistance

4. **Protocol error logs** — application logs by design
5. **Network packet analysis** — can't send valid packets while fuzzing
6. **Service restart clustering** — event logs auto-generated

### Tier 3: Medium Resistance

7. **Event log entries** — can be deleted (but audit trail remains)
8. **Fuzz scripts on disk** — can be deleted (but filesystem artifacts remain)

### Tier 4: Low Resistance

9. **Shell history** — user-writable, can be cleared
10. **boofuzz.csv export** — can be deleted

---

## Hunt Strategy: Access-Based

### Source Access Only (Attacker's Machine Imaged)

**Priority:**
1. Find boofuzz.db or boofuzz.csv → **definitive proof**
2. Find fuzz scripts → **shows target and strategy**
3. Check shell history → **confirms operator intent**
4. Examine crash files → **weaponizable PoCs**

### Target Access Only (Most Common DFIR Scenario)

**Priority:**
1. Event logs/syslog → **crash clustering**
2. Core dumps → **fault addresses**
3. Application logs → **protocol errors**
4. Network packet analysis → **payload variation**
5. Timeline correlation → **network timestamps match crash timestamps**

### Both Source and Target Access

**Maximum forensic leverage:**
1. Correlate boofuzz.db test case #42 timestamp to target crash log timestamp
2. Extract crash PoC from boofuzz results
3. Prove exact bytes sent → exact crash produced
4. Establish full attack chain and timeline

---

## Copy-Paste Hunt Commands

### Linux Target Hunt (1 Hour Window)

```bash
#!/bin/bash
echo "[+] Searching for crashes..."
grep "segfault" /var/log/syslog | tail -20

echo "[+] Counting unique crash addresses..."
grep "segfault" /var/log/syslog | grep -oE "ip [0-9a-f]+" | wc -l

echo "[+] Checking service restarts..."
journalctl --since "1 hour ago" | grep -i "exited" | wc -l

echo "[+] Searching application error logs..."
grep -i "error\|invalid" /var/log/myapp.log 2>/dev/null | wc -l

echo "[+] Looking for attacker IP..."
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" /var/log/myapp.log 2>/dev/null | sort | uniq -c | sort -rn | head -5

echo "[+] Done."
```

### Windows Target Hunt (1 Hour Window)

```powershell
Write-Host "[+] Checking for application crashes..."
$startTime = (Get-Date).AddHours(-1)
Get-EventLog -LogName Application -InstanceId 1000, 1001 -After $startTime | Measure-Object | Select-Object Count

Write-Host "[+] Checking for service restarts..."
Get-EventLog -LogName System -InstanceId 7034 -After $startTime | Measure-Object | Select-Object Count

Write-Host "[+] Listing crash dump files..."
Get-ChildItem C:\ProgramData\Microsoft\Windows\WER\ReportArchive -Recurse -Include *.dmp -EA SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 10 FullName, LastWriteTime

Write-Host "[+] Done."
```

### Source Hunt (boofuzz Artifacts)

```bash
#!/bin/bash
echo "[+] Searching for boofuzz imports..."
grep -r "from boofuzz import" /home /root /tmp --include="*.py" 2>/dev/null

echo "[+] Finding boofuzz.db databases..."
find /home /root /tmp -name "boofuzz.db" 2>/dev/null

echo "[+] Analyzing boofuzz.db if found..."
if [ -f "/path/to/boofuzz.db" ]; then
    sqlite3 /path/to/boofuzz.db "SELECT COUNT(*) as crashes FROM test_case WHERE passed = 0;"
fi

echo "[+] Checking shell history..."
grep "boofuzz\|fuzz.*\.py" ~/.bash_history ~/.zsh_history 2>/dev/null | tail -10

echo "[+] Done."
```

---

## Detection Summary Table

| Indicator | Confidence | Detectability | Evasion Resistance |
|-----------|------------|----------------|-------------------|
| boofuzz.db SQLite DB | VERY HIGH | Hard to miss | VERY HIGH |
| Multiple crash addresses | HIGH | Easy (logs/dumps) | VERY HIGH |
| Protocol error logs | HIGH | Requires analysis | HIGH |
| Fuzz scripts on disk | HIGH | Medium (grep) | MEDIUM |
| Crash file clustering | MEDIUM | Requires timeline | HIGH |
| Service restart loop | MEDIUM | Easy (Event Log) | MEDIUM |

**Bottom line:** If you find boofuzz.db, **it's definitive**. Otherwise, look for the crash + restart + error log triad on target.
