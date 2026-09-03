# sqlmap — Detection and Hunting

---

## Hunting Priority Table

This table ranks detection signals by their **evasion-resistance**: which signals survive which operator evasion tactics (--tamper, --prefix/--suffix, custom User-Agent, etc.).

| Rank | Signal | Technique | Survives --tamper? | Survives --proxy? | Survives Timing Jitter? | Best Detection Method |
|------|--------|-----------|--------------------|--------------------|----------------------|----------------------|
| 1 | DNS exfiltration to attacker domain | Out-of-band (--dns-domain) | NO | NO | YES | DNS firewall logs, recursive resolver queries |
| 2 | Webshell creation on filesystem | File-write (--file-write) | NO | NO | YES | File integrity monitoring, ls -la with timestamps |
| 3 | Time-based delay clustering (5s, 10s, 15s) | Time-based blind (--time-sec) | NO | Partially | NO | Web server response time logs, APM metrics |
| 4 | Database query log with UNION/info_schema | Union-based (--union-cols) | NO | Partially | YES | MySQL general_query_log, PostgreSQL log_statement |
| 5 | SQL error messages in HTTP response | Error-based (--technique=E) | Partially (encoding hides) | Partially | YES | Web/App error logs, WAF alerts |
| 6 | WAF alert (ModSecurity, etc.) | Any (depends on rule) | YES (--tamper bypasses) | Partially | YES | WAF logs (but tamper scripts defeat this) |
| 7 | Rapid-fire HTTP requests, escalating complexity | Boolean-based (--technique=B) | Partially | Partially | YES | Web access log pattern analysis |
| 8 | Default User-Agent: sqlmap/1.10.8.29 | HTTP header fingerprint | YES (--random-agent) | Partially | YES | User-Agent whitelist/blacklist (weak signal) |
| 9 | Unusual parameter values (OR 1=1, SLEEP(n)) | Payload content | YES (--tamper, --prefix/--suffix) | Partially | YES | Regex pattern matching on params (weak) |

**Key insight:** Infrastructure-level signals (DNS logs, file integrity, response timing) are evasion-proof. Payload-level signals (WAF, User-Agent) are trivially defeated by tamper scripts.

---

## Hunting on Source (Operator's Machine)

### 1. Shell History Search for sqlmap Invocations

```bash
# Linux/macOS: Search bash/zsh history
grep -E "sqlmap|sqlmap\.py" ~/.bash_history ~/.zsh_history ~/.ksh_history 2>/dev/null | head -20

# Windows PowerShell: Search PowerShell history
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | Select-String "sqlmap" | head -20

# If history is cleared, try:
# Linux: Check disk for deleted history files (bleachbit, shred leave patterns)
# Windows: Use MFT analysis or volume shadow copy to recover deleted files
```

**What to look for:**
- Commands containing `-u`, `--url=`, `--data=`, `--dbs`, `--dump`
- DBMS force flags: `--dbms=MySQL`, `--dbms=MSSQL`
- Evasion flags: `--tamper=`, `--proxy=`, `--tor`
- Enumeration goals: `--tables`, `--columns`, `--passwords`

### 2. Session Cache Investigation

```bash
# Find all sqlmap session directories
find ~/.sqlmap -type d -name "*" 2>/dev/null | head -20

# List targets cached in sqlmap
ls -la ~/.sqlmap/

# Decode target URL from directory hash (sqlmap hashes URLs)
# Directory name structure: <hostname_hash>/<target_url_hash>/
# Manual correlation: Compare hash against known target URLs
```

**Query the session database (SQLite):**

```bash
# List all cached session scans
sqlite3 ~/.sqlmap/*/session.sqlite "SELECT id, url, test_parameter, injection_type FROM scan;"

# View cached payloads for a specific parameter
sqlite3 ~/.sqlmap/*/session.sqlite "SELECT payload, response_type FROM payload WHERE test_parameter='id';"

# Check enumerated databases
sqlite3 ~/.sqlmap/*/session.sqlite "SELECT * FROM enumeration WHERE type='database';"
```

### 3. Python Pickle Inspection (options.pkl)

```python
import pickle
import sys
import json

# Load pickle file
with open(sys.argv[1], 'rb') as f:
    options = pickle.load(f)

# Extract key indicators
print("=== sqlmap Execution Profile ===")
print(f"Target URL: {options.get('url', 'N/A')}")
print(f"Proxy: {options.get('proxy', 'None')}")
print(f"Tamper Scripts: {options.get('tamper', 'None')}")
print(f"DBMS Forced: {options.get('dbms', 'Auto-detect')}")
print(f"Techniques Used: {options.get('technique', 'BEUSTQ')}")
print(f"Risk Level: {options.get('risk', '1')}")
print(f"Test Level: {options.get('level', '1')}")
print(f"Batch Mode: {options.get('batch', False)}")
print(f"Data Enumeration: {options.get('dbs', False) or options.get('dump', False)}")
print(f"User-Agent: {options.get('agent', 'default')}")
```

**Output reveals operator's full exploitation playbook.**

### 4. Network Logs (if you control the network)

```bash
# If operator used --proxy=http://your-monitor:8080, check proxy logs
grep "sqlmap\|OR 1=1\|SLEEP\|UNION SELECT" proxy.log | head -30

# tcpdump to outbound DNS (if --dns-domain used)
tcpdump -i any 'udp port 53' -r pcap.pcapng | grep -E "[a-z0-9]{40,}\.(attacker|interactsh)\.com"

# Zeek DNS logs (if running Zeek on network)
grep "attacker\.com\|interactsh\.com" dns.log | zeek-log-parse -
```

### 5. Process and Memory Forensics

```bash
# If process is still running (unlikely, but possible):
ps aux | grep sqlmap

# Memory forensics (via Volatility, if you have a memory dump):
vol.py -f memory.dmp pslist | grep python  # Find python processes
vol.py -f memory.dmp memdump -p <pid> -D output/  # Dump process memory
strings output/python.mem | grep -E "sqlmap|OR 1=1|SELECT.*FROM" | head -20

# Or use Velociraptor (live response):
velociraptor.exe --config=config.yaml "SELECT Stdout FROM psutil.CallableVirtualMemory(pid=<pid>)" | strings
```

---

## Hunting on Target (Victim's Infrastructure)

### 1. Web Server Access Log Pattern Analysis

```bash
# Extract HTTP requests to parameters
grep -E "\?.*=" /var/log/apache2/access.log | awk '{print $7}' | sort | uniq -c | sort -rn

# Search for SQL injection payload signatures
grep -E "'.*OR.*'|UNION.*SELECT|SLEEP\(|extractvalue\|information_schema" /var/log/apache2/access.log

# Rapid-fire requests to same parameter (sign of automated tool)
awk '/vulnerable\.php\?id=/{count++} END {if (count > 20 && count < 300) print "SUSPICIOUS: " count " requests in short time"}' /var/log/apache2/access.log

# Time-based signature: requests with gaps (5s, 10s delays)
awk 'BEGIN{prev=0} {
  time = mktime(substr($4,2,20));
  if (prev > 0 && (time - prev == 5 || time - prev == 10)) {
    print "Time-based blind candidate:", $0;
  }
  prev = time;
}' /var/log/apache2/access.log
```

**Logstash/ELK pattern-matching:**

```json
{
  "fields": {
    "http_method": "GET",
    "uri_path": "/search.php",
    "query_string": ["*OR*", "*1=1*"],
    "response_time_ms": [5000, 10000, 15000]
  }
}
```

### 2. Database Query Log Analysis (MySQL)

```bash
# Enable query logging (if not already on; WARNING: performance impact)
mysql> SET GLOBAL general_log = 'ON';
mysql> SET GLOBAL log_output = 'TABLE';

# View logged queries
mysql> SELECT event_time, argument FROM mysql.general_log WHERE argument LIKE '%OR%' OR argument LIKE '%UNION%';

# Parse offline (if file-based logging)
grep -E "SELECT.*information_schema|SHOW DATABASES|SHOW TABLES|UNION SELECT" /var/log/mysql/general.log | head -50

# Detect info_schema scans (reconnaissance phase)
grep -c "information_schema" /var/log/mysql/general.log
```

### 3. Database Error Log Analysis

```bash
# MySQL
grep -E "Syntax error|Unexpected|near '|parse error" /var/log/mysql/error.log | tail -100

# PostgreSQL
grep -E "ERROR.*syntax|ERROR.*UNION|ERROR.*extractvalue" /var/log/postgresql/postgresql.log | tail -100

# MSSQL (via event viewer on Windows)
# Event Viewer → Application → Filter: Level=Error, Source=MSSQL
```

### 4. WAF/ModSecurity Detection

```bash
# ModSecurity audit log
grep "SQL Injection" /var/log/modsec_audit/modsec_audit.log | jq '.alert.msg, .http.request.headers'

# Check what rules triggered
grep -o "id: [0-9]*" /var/log/modsec_audit/modsec_audit.log | sort | uniq -c | sort -rn
# Top sqlmap-triggering rules: 942100 (basic SQL), 942200 (union), 942251 (stacked)
```

### 5. Time-Based Blind Detection (Response Timing)

```bash
# Extract response times from access logs (if configured)
# Nginx with $request_time:
grep "GET.*?" /var/log/nginx/access.log | awk '{print $NF}' | grep "^[5-9]\.|^[0-9][0-9]" | head -20
# Look for repeated 5.0, 10.0, 15.0 second response times (SLEEP delays)

# Apache with mod_logio:
grep "%D" /var/log/apache2/access.log | awk '{print $(NF-1)}' | awk '$1 > 5000000 {print $1/1000000 "s"}' | sort | uniq -c
# (time in microseconds; 5000000 μs = 5 seconds)

# Application Monitoring (New Relic, DataDog API):
# Query: Filter on response_time > 5s AND same endpoint AND rapid succession
curl -H "DD-API-KEY: $DATADOG_KEY" \
  "https://api.datadoghq.com/api/v1/query?query=avg:trace.web.request.duration{endpoint:/vulnerable.php}" \
  | jq '.series[] | select(.pointlist[] | .[1] > 5000)'
```

### 6. DNS Exfiltration Hunting

```bash
# Recursive resolver logs (if you run one)
grep -E "attacker\.com|interactsh\.com" /var/log/bind/query.log

# System resolver log (systemd-resolved)
journalctl -u systemd-resolved | grep attacker.com

# Zeek DNS logs
grep "attacker\.com\|interactsh\.com" dns.log | zeek-log-parse

# Count unique subdomains to attacker domain (base64 chunks)
grep "\.attacker\.com" /var/log/bind/query.log | awk -F. '{print $(NF-2)}' | sort | uniq | head -20
# Each chunk is a base64-encoded data segment
```

**Decode exfiltrated data:**

```bash
# Collect DNS queries
dig +short @<dns-server> $(grep "attacker.com" dns.log | awk '{print $1}' | tr '\n' ' ')

# Extract base64 chunks
grep "\.attacker\.com" dns.log | sed 's/.*\.\([a-zA-Z0-9_-]*\)\.attacker.com.*/\1/g' | sort

# Concatenate and decode
cat chunks.txt | tr -d '\n' | base64 -d
# Output: Exfiltrated SQL data (usernames, passwords, etc.)
```

### 7. Webshell Detection

```bash
# Find recently-created PHP files
find /var/www/html -name "*.php" -type f -newer /var/log/apache2/access.log.1 -ls

# Check file ownership (should match web server user)
ls -la /var/www/html | grep -v "www-data"  # Non-standard owner = suspicious

# Hash against known webshell signatures
sha256sum /var/www/html/*.php | while read hash file; do
  grep "$hash" ~/webshell_hashes.txt && echo "DETECTED: $file is a known webshell"
done

# String signature matching
grep -l "system\|exec\|passthru\|shell_exec\|popen" /var/www/html/*.php | while read file; do
  echo "SUSPICIOUS: $file contains shell execution functions"
done

# Check for single-letter variable names (common in minified shells)
grep -E 'function [a-z]\(' /var/www/html/*.php
```

### 8. Database Permission Changes / Backdoor Account Creation

```bash
# MySQL: List all users and their hosts
mysql> SELECT user, host, authentication_string FROM mysql.user ORDER BY user;
# Look for new/unexpected users (common backdoor names: backup, admin2, test123, oracle, support)

# PostgreSQL: List roles
postgres=# SELECT * FROM pg_roles ORDER BY rolname;
# Look for high-privilege roles created recently

# MSSQL (PowerShell):
Get-SqlLogin -ServerInstance MSSQL-01 | Select LoginName, LoginType, CreateDate | Sort-Object CreateDate -Descending | head -20
# Look for recent SA-equivalent logins

# Check database modification times (if using binary log)
mysql> SELECT * FROM mysql.innodb_table_stats WHERE LAST_UPDATE > DATE_SUB(NOW(), INTERVAL 1 HOUR);
```

### 9. Audit Log Analysis (if enabled)

```bash
# PostgreSQL (pgAudit extension)
grep -E "EXECUTE.*information_schema|CREATE.*DATABASE|ALTER.*USER|GRANT" /var/log/postgresql/postgresql.log

# MSSQL (SQL Agent audit)
# Event ID 20000: Authentication attempt
# Event ID 3035: DB creation
Get-EventLog -LogName Application -Source MSSQL -After (Get-Date).AddHours(-1) | Where-Object {$_.EventID -in 3035, 4624}

# MySQL (audit plugin, if installed)
grep -E "CONNECT|QUERY.*information_schema|DROP|ALTER" /var/log/mysql/audit.log
```

### 10. Fleet-Wide Hunting (SIEM/EDR)

```kql
# Azure Sentinel KQL query to detect sqlmap-like activity
SecurityAlert
| where AlertName contains "SQL Injection"
| union (
  Perf
  | where ObjectName == "SQLServer:General Statistics"
  | where CounterName == "General Statistics"
  | where CounterValue > 1000
  | where TimeGenerated > ago(1h)
)
| summarize AlertCount=dcount(AlertName), AvgResponseTime=avg(CounterValue) by Computer, bin(TimeGenerated, 5m)
| where AlertCount > 5 and AvgResponseTime > 5000
```

```sql
# Splunk SPL query to detect rapid SQLi testing
sourcetype="apache_common" uri="*?" 
| stats count by uri, src_ip, response_time 
| where count > 20 and response_time > 5000
| table src_ip, uri, count, response_time
```

```json
# Elasticsearch query to find time-based blind patterns
{
  "query": {
    "bool": {
      "must": [
        {"range": {"response_time_ms": {"gte": 5000, "lte": 15000}}},
        {"wildcard": {"query_string": "*SLEEP*"}},
        {"range": {"timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "by_source_ip": {"terms": {"field": "source_ip", "size": 100}}
  }
}
```

---

## Detection Avoidance (Attacker Perspective)

### What Operators Do to Evade Detection

| Technique | How It Works | Detection Bypass | Footprint |
|-----------|--------------|------------------|-----------|
| `--tamper=space2comment` | Replaces spaces with `/* */` | Bypasses string-based WAF rules | Still leaves rapid HTTP pattern |
| `--random-agent` | Changes User-Agent per request | Defeats User-Agent blacklist | Still matches payload patterns |
| `--proxy=http://internal:8080` | Routes through internal proxy | Hides operator's real IP | Proxy log shows full payload |
| `--dns-domain=interactsh` | Uses public OOB service | Exfiltrates via 3rd-party | DNS log shows attacker domain |
| `--prefix='\' --suffix=\'` | Escapes context manually | Hides injection attempt | Still shows error log or timing |
| Time-based delays (5s) | Inherent to technique | No way to hide timing | Response time clustering is obvious |
| Custom tamper scripts | Operator-written evasion | Depends on WAF signatures | Still shows data extraction pattern |
| `--flush-session` + delete logs | Removes evidence post-attack | Hides source artifacts | Doesn't remove target-side logs |

**Key finding:** No evasion defeats DNS exfiltration, webshell creation, or database query logs. Attackers must accept that infrastructure-level evidence is inevitable.

---

## Remediation

### Immediate Actions (If Attack is Ongoing)

1. **Kill the session:**
   ```bash
   # Find and terminate the sqlmap process
   ps aux | grep sqlmap | grep -v grep | awk '{print $2}' | xargs kill -9
   
   # Block attacker's IP at firewall
   iptables -I INPUT -s <attacker_ip> -j DROP
   ```

2. **Revoke compromised credentials:**
   ```sql
   -- MySQL
   REVOKE ALL PRIVILEGES ON *.* FROM 'backdoor'@'%';
   DROP USER 'backdoor'@'%';
   
   -- PostgreSQL
   DROP ROLE IF EXISTS backdoor;
   
   -- MSSQL
   DROP LOGIN [backdoor_user];
   ```

3. **Remove backdoors:**
   ```bash
   # Delete webshells
   rm /var/www/html/shell.php
   
   # Disable UDFs
   mysql> DROP FUNCTION IF EXISTS sys_exec;
   ```

### Hardening (Post-Compromise)

1. **Database-Level:**
   - Enable query logging: `SET GLOBAL general_log = 'ON'` (MySQL)
   - Set log_statement = 'all' (PostgreSQL)
   - Enable SQL audit policy (MSSQL)
   - Revoke dangerous privileges: `FILE`, `PROCESS`, `SUPER` (MySQL)
   - Disable stacked queries (use `mysqli_multi_query = 0` in PHP)

2. **Application-Level:**
   - Use parameterized queries / prepared statements (eliminate SQLi entirely)
   - Input validation (whitelist allowed characters, reject SQL keywords)
   - Least-privilege DB accounts (read-only for web tier, admin for migration scripts)

3. **Network-Level:**
   - WAF rules (ModSecurity, AWS WAF, Cloudflare)
   - DNS filtering (block known attacker-OOB domains)
   - Egress filtering (block outbound DNS to external resolvers)
   - IDS/IPS rules (Suricata, Snort for SQLi signatures)

4. **Monitoring-Level:**
   - Ensure database query logging is enabled and monitored
   - Set up alerting on rapid query patterns (>50 queries/min to information_schema)
   - Alert on webshell file creation (integrity monitoring + file-creation logs)
   - Alert on DNS queries to attacker domains (firewall, resolver logs)

---

## Summary: What Makes sqlmap Detectable

**In order of invariance:**

1. **Infrastructure events** (unbeatable):
   - DNS exfiltration to attacker domain
   - Webshell creation on filesystem
   - Database schema enumeration (information_schema queries)

2. **Timing-based patterns** (very hard to defeat):
   - 5s, 10s, 15s delay clustering (time-based blind)
   - Rapid-fire response pattern (boolean-based)

3. **Database-level artifacts** (hard to defeat):
   - Error log spam (SQL syntax errors)
   - Query log entries (if enabled)
   - Unusual account creation (backdoor users)

4. **Application-level artifacts** (medium difficulty):
   - HTTP response size changes
   - WAF alerts (bypassed by tamper scripts)
   - Error messages in HTML (defeated by error suppression)

5. **Operator-side artifacts** (easy to defeat):
   - Shell history (clear history)
   - Session cache (--flush-session)
   - Default User-Agent (--random-agent)

**Operator's dilemma:** Staying hidden requires post-attack cleanup (clearing .sqlmap/, shell history, flushing database logs) — which itself is suspicious if discovered. Most compromises are caught within days because the attacker didn't cleanup; forensic analysis then links source and target evidence into an airtight case.

