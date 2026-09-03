# Burp Suite — Detection and Hunting

---

## Hunting Priority

The signals below are ranked by which Burp evasion/customization options defeat them. **Strongest signals survive operator attempts to hide; weakest signals can be defeated with trivial configuration changes.**

| Rank | Signal | Survives User-Agent Rotation? | Survives Payload Randomization? | Survives Throttling? | Evasion Method | Notes |
|---|---|---|---|---|---|---|
| 🔴 1 | HTTP access log: Scanner payload patterns (SQL injection, XSS, path traversal strings visible in URI/body) | ✅ Yes — payloads are inherent to attack, not Burp-specific | ❌ No | ✅ Yes | None (payload randomization defeats this, requires custom scanner rules) | Operator cannot hide attack intent without changing attack methodology entirely |
| 🔴 2 | WAF/IDS alert rule: OWASP Top 10 attack patterns (OWASP CRS 3.2 ModSecurity rules, Snort/Suricata sigs) | ✅ Yes | ❌ No | ✅ Yes | Encode payloads, use WAF-bypass techniques (e.g., SQLi with `/**/`, case mixing, comment sequences) | WAF rules detect *patterns*, not tool signatures; can be evaded with obfuscation |
| 🟠 3 | HTTP access log: Rapid sequential requests (5–20 req/sec) from single source IP to same host | ✅ Yes | ✅ Yes | ❌ No — throttling defeats this | Increase request interval (`--request-interval 10s`) | Legitimate applications rarely emit 5+ req/sec from user sessions; manual testing is slower |
| 🟠 4 | Burp-specific User-Agent string (`Burp/YYYY.x.x` in HTTP headers) | ❌ No — cannot be customized without explicit Burp config change | ✅ Yes | ✅ Yes | Set custom User-Agent via Burp settings or proxy header injection | Operator must deliberately configure a fake User-Agent; stock Burp usage has 100% detection rate for this signal |
| 🟡 5 | Event Log 4625 (failed logon) + 4624 (success) cluster: 50+ failures in 60 seconds from single IP, followed by success | ✅ Yes | ✅ Yes | ✅ Yes | Add delays between Intruder payloads, use macro delays, distribute attack across multiple IPs | Rate-limiting and throttling directly defeat this; multi-IP distributed attack also defeats single-IP clustering |
| 🟡 6 | WAF rate-limit responses (HTTP 429) and subsequent request drops from single IP | ✅ Yes | ✅ Yes | ❌ No | Disable aggressive scanning; use low thread count (1–2 req/sec) | WAF rate-limiting is a direct function of request volume; operators can adapt if they see 429 responses in real-time |
| 🟡 7 | Query string / POST body payloads appearing in error messages or application logs (e.g., SQL syntax error reflecting the injection query) | ✅ Yes | ❌ No | ✅ Yes | Encode payloads, use blind SQL injection (no output required), use out-of-band callbacks (Collaborator) | If payloads appear in logs/errors unmodified, they are visible; blind techniques avoid this entirely |
| 🟢 8 | Intruder response-time distribution anomaly: successful credential matches (200 OK, 2500 bytes) vs. failures (401, 512 bytes) | ✅ Yes | ✅ Yes | ✅ Yes | Randomize response times via macro delays, use macro with multi-second delays between attempts | Response-time analysis is statistical; operator can defeat it by adding noise |
| 🟢 9 | Named pipes or temporary files created by Burp during operation (low priority — requires host access) | ✅ Yes | ✅ Yes | ✅ Yes | Run Burp on attacker's own machine (never touches target directly); no artifacts created on target | Burp is a client-side tool; it doesn't drop files on the target unless exploitation succeeds |
| 🟢 10 | Collaborator callback detection: DNS/HTTP requests to `burpcollaborator.net` domain from target | ✅ Yes | ✅ Yes | ✅ Yes | Use operator-owned callback server instead of PortSwigger's Collaborator; host on attacker's infrastructure | Burp Collaborator is optional; operator can self-host or use alternative OOB DNS/HTTP callback server |

---

## Hunting on Source

**Objective:** Find Burp artifacts on the **attacker's own machine** (requires host compromise, forensic access, or endpoint agent deployment).

### Search for Burp Project Files

**PowerShell (Windows):**
```powershell
# Find all .burp files (SQLite databases)
Get-ChildItem -Path "C:\Users\*" -Filter "*.burp" -Recurse -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime, Length

# Example output:
# C:\Users\attacker\Documents\target_assessment.burp      2024-06-15 10:45:00     45234567
# C:\Users\attacker\Downloads\engagement_2024.burp         2024-06-14 23:30:00     34567890

# Verify the file is actually SQLite (not just named .burp)
Get-Content -Path "C:\Users\attacker\Documents\target_assessment.burp" -Encoding Byte -TotalCount 16 |
  ForEach-Object { [char]$_ } |
  Join-String

# Output should start with: "SQLite format 3" — confirms it's a Burp project
```

**Bash (Linux/macOS):**
```bash
# Find all .burp files
find ~ -name "*.burp" -type f 2>/dev/null

# or more broadly, including hidden directories:
find ~ -name "*.burp" 2>/dev/null

# Verify SQLite header
file $(find ~ -name "*.burp" 2>/dev/null)  # Output: "SQLite 3.x database"

# Get metadata (size, modification time)
ls -lah $(find ~ -name "*.burp" 2>/dev/null)
stat $(find ~ -name "*.burp" 2>/dev/null)
```

### Extract Burp Project History via SQLite Query

```bash
# If you have access to a seized .burp file, query it directly:
sqlite3 target_assessment.burp

# Inside sqlite3 prompt:
.tables
# Output: Cookies Issues Macros Metadata Requests Responses Sites Tasks

# Query all requests
SELECT url, method, timestamp FROM Requests LIMIT 10;

# Example output:
# https://target.local/login|POST|2024-06-15 10:25:00
# https://target.local/search|GET|2024-06-15 10:25:01
# https://target.local/api/users|GET|2024-06-15 10:25:02

# Query all Scanner findings
SELECT issue_type, severity, url, evidence FROM Issues ORDER BY timestamp;

# Example output:
# SQL Injection|High|https://target.local/search?q=test|Unclosed quotation mark
# Cross-Site Scripting|High|https://target.local/comment|<img> tag reflected

# Export findings to a text report
.output findings_report.txt
SELECT * FROM Issues;
.output stdout

# Count requests by endpoint (reconnaissance footprint)
SELECT url, COUNT(*) as request_count FROM Requests GROUP BY url ORDER BY request_count DESC;
```

### Search for Intruder Wordlist Files

**PowerShell:**
```powershell
# Search for common wordlist file extensions and names
Get-ChildItem -Path "C:\Users\*" -Recurse -ErrorAction SilentlyContinue |
  Where-Object {
    ($_.Name -match "wordlist|passwords|rockyou|users|usernames" -and $_.Extension -match "txt|lst|csv") -or
    ($_.FullName -like "*\wordlists\*" -or $_.FullName -like "*\passwords\*")
  } |
  Select-Object FullName, Length, LastWriteTime |
  Sort-Object LastWriteTime -Descending

# Check for Intruder result exports (.csv or .txt with attack metadata)
Get-ChildItem -Path "C:\Users\*" -Recurse -Filter "*intruder*.csv" -ErrorAction SilentlyContinue |
  Select-Object FullName, LastWriteTime
```

**Bash:**
```bash
# Search for wordlists
find ~ -type f \( -name "*wordlist*" -o -name "*password*" -o -name "*rockyou*" \) 2>/dev/null

# Check for intruder result exports
find ~ -name "*intruder*.csv" -o -name "*intruder*.txt" 2>/dev/null

# Search /usr/share/wordlists/ for recent access
ls -lt /usr/share/wordlists/ | head -20  # Most recently modified files
find /usr/share/wordlists/ -newermt "2024-06-14" 2>/dev/null  # Files modified after 2024-06-14
```

### Search for Burp Extensions

**PowerShell:**
```powershell
# Burp extensions directory
Get-ChildItem -Path "C:\Users\*\AppData\Roaming\BurpSuite\extensions\" -ErrorAction SilentlyContinue |
  Where-Object { $_.Extension -eq ".jar" -or $_.Extension -eq ".py" } |
  Select-Object FullName, Length, CreationTime, LastWriteTime
```

**Bash:**
```bash
# Burp extensions directory
ls -la ~/.BurpSuite/extensions/ 2>/dev/null

# List .jar files with metadata
find ~/.BurpSuite/extensions/ -name "*.jar" -type f -exec ls -lah {} \; 2>/dev/null

# Extract metadata from .jar (Java archives are ZIP files)
for jar in ~/.BurpSuite/extensions/*.jar; do
  echo "=== $jar ==="
  unzip -l "$jar" | grep -E "META-INF|\.class|\.properties"
done
```

### Search for Shell History and Burp Invocation Commands

**Bash History (Linux/macOS/Git Bash on Windows):**
```bash
# Search for Burp-related commands
grep -i "burp" ~/.bash_history ~/.zsh_history ~/.sh_history 2>/dev/null

# Example findings:
# java -jar burp.jar --project-file target_assessment.burp --config-file scan_config.xml
# burpctl scan start --url https://target.local --config-file burp_scan_config.xml --wait
# java -Xmx4g -jar burp.jar --headless --batch-mode --logfile burp_output.txt
```

**PowerShell History (Windows):**
```powershell
# PowerShell command history
Get-Content -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" 2>/dev/null |
  Select-String -Pattern "burp|java.*jar"

# Example:
# java -jar C:\Tools\burp.jar --project-file C:\Users\attacker\Documents\target.burp
# burpctl --api-token MyToken scan start --url https://target.local
```

### Search for Proxy CA Certificates

**Burp CA Certificate Location:**
```bash
# Linux/macOS
ls -la ~/.BurpSuite/certs/

# Windows
dir "C:\Users\<username>\AppData\Roaming\BurpSuite\certs\"

# Examine certificate thumbprint
openssl x509 -in ~/.BurpSuite/certs/burp.cer -text -noout | grep -E "Issuer|Subject|SHA256 Fingerprint|Serial"

# Output example:
# Issuer: PortSwigger Web Security
# Subject: PortSwigger Web Security
# Serial: 0x123456789abcdef
# SHA256 Fingerprint: AB:CD:EF:12:34:56:78:90:...
```

---

## Hunting on Target

**Objective:** Find Burp scanning and attack signatures in **target-side artifacts** (web server logs, WAF alerts, event logs, packet captures). These hunts assume access to the **victim's** infrastructure (SIEM, log aggregation, endpoint agent, network sensors).

### Hunt #1: Burp User-Agent Across Web Server Logs

**PowerShell (if logs are available locally):**
```powershell
# Search IIS logs for Burp User-Agent
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex240615.log" |
  Select-String -Pattern "Burp/"

# Example output:
# 2024-06-15 10:24:33 192.168.1.100 GET /search?q='+OR+'1'='1 500 0 0 Burp/2024.12.1 45

# Count Burp requests by hour
Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\*.log" |
  Select-String -Pattern "Burp/" |
  ForEach-Object {
    $line = $_ -split " "
    $timestamp = $line[0] + " " + $line[1]
    $hour = [datetime]::ParseExact($timestamp, "yyyy-MM-dd HH:mm:ss", $null).ToString("yyyy-MM-dd HH:00:00")
    $hour
  } |
  Group-Object |
  Select-Object Name, Count

# Example output:
# 2024-06-15 10:00:00  |  287
# 2024-06-15 11:00:00  |  12
```

**Bash (Apache/Nginx logs):**
```bash
# Search Apache/Nginx access logs for Burp User-Agent
grep "Burp/" /var/log/apache2/access.log | head -20

# Example output:
# 192.168.1.100 - - [15/Jun/2024:10:24:33 +0000] "GET /search?q='+OR+'1'='1 HTTP/1.1" 500 256 "-" "Burp/2024.12.1"

# Count Burp requests by source IP
grep "Burp/" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Example output:
# 287 192.168.1.100
# 45 192.168.1.101
# 12 192.168.1.102

# Count requests per minute (to detect high-rate scanning)
grep "Burp/" /var/log/apache2/access.log |
  awk '{print $4" "$5}' |
  sed 's/:.*//g' |
  uniq -c | sort -k3 -t: -n |
  awk '$1 > 10 {print $0}'  # Alert if > 10 req/minute
```

### Hunt #2: Rapid Sequential HTTP Requests from Single IP

**PowerShell (aggregate log analysis):**
```powershell
# Load IIS logs and group by source IP and 1-minute windows
$logs = Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\*.log" |
  Select-String -NotMatch "^#" |
  ForEach-Object {
    $parts = $_ -split " "
    [PSCustomObject]@{
      Timestamp = [datetime]::ParseExact(($parts[0] + " " + $parts[1]), "yyyy-MM-dd HH:mm:ss", $null)
      SourceIP = $parts[2]
      Method = $parts[3]
      URI = $parts[4]
      Status = $parts[8]
    }
  }

# Find IPs with > 100 requests in a 1-minute window
$logs |
  Group-Object -Property SourceIP, { $_.Timestamp.ToString("yyyy-MM-dd HH:mm") } |
  Where-Object { $_.Count -gt 100 } |
  Select-Object Name, Count |
  Format-Table

# Example output:
# Name                           Count
# ----                           -----
# 192.168.1.100, 2024-06-15 10:24  287
# 192.168.1.100, 2024-06-15 10:25  156
```

**Bash (real-time log monitoring):**
```bash
# Monitor Apache log in real-time, alert on > 10 req/sec from single IP
tail -f /var/log/apache2/access.log |
  awk '{print $1 " " $4}' |
  sed 's/:.*//g' |
  sort |
  uniq -c |
  awk '$1 > 10 {print "[ALERT] " $0 " requests in 1 minute window"}'

# Or analyze historical logs
awk '{
  split($4, time, ":");
  minute_key = $1 " " substr(time[1], 2) ":" time[2]
  count[minute_key]++
}
END {
  for (key in count) {
    if (count[key] > 100) print "[SCANNER] " key " had " count[key] " requests"
  }
}' /var/log/apache2/access.log | sort -t: -k3 -n
```

### Hunt #3: Scanner Payload Patterns in HTTP Requests

**PowerShell (pattern matching):**
```powershell
# Common SQL injection payloads
$sqli_patterns = @(
  "' OR '1'='1",
  "' UNION SELECT",
  "' AND 1=1",
  "' AND SLEEP",
  "' OR 1=1--",
  "'; DROP TABLE"
)

# Common XSS payloads
$xss_patterns = @(
  "<script",
  "<img.*onerror",
  "<svg.*onload",
  "<iframe.*src="
)

# Search IIS logs for patterns
$all_patterns = $sqli_patterns + $xss_patterns
$logs = Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\u_ex240615.log"

foreach ($pattern in $all_patterns) {
  $matches = $logs | Select-String -Pattern ([regex]::Escape($pattern))
  if ($matches) {
    Write-Host "[FOUND] Pattern '$pattern' found in logs:"
    $matches | Select-Object -First 3
  }
}
```

**Bash (regex search):**
```bash
# Search for SQL injection indicators
grep -E "OR\s+['\"]?1['\"]?=|\bUNION\b|SLEEP\(|WAITFOR|xp_|sp_|sysobjects|LOAD_FILE" /var/log/apache2/access.log |
  head -10

# Search for XSS indicators
grep -E "<script|<img|<svg|<iframe|<body|<embed|javascript:" /var/log/apache2/access.log |
  head -10

# Search for path traversal indicators
grep -E "\.\.\/|\.\.\%2F|\.\.\\\\|%2e%2e" /var/log/apache2/access.log |
  head -10

# Export all suspicious requests to a file for manual review
grep -E "OR\s+['\"]?1['\"]?=|<script|\.\.\/|\?.*=" /var/log/apache2/access.log > suspicious_requests.txt
```

### Hunt #4: WAF/IDS Alerts for Known Scanner Payloads

**Splunk Query (if using Splunk):**
```
sourcetype=waf OR sourcetype=ids "SQL Injection" OR "XSS" OR "Brute Force"
| search src_ip=* earliest=2024-06-15T10:00:00 latest=2024-06-15T15:00:00
| stats count, earliest(_time), latest(_time), values(msg), values(rule_id) by src_ip
| where count > 50
```

**ELK Stack / Elasticsearch Query:**
```json
{
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "waf.alert": "SQL Injection"
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": "2024-06-15T10:00:00Z",
              "lte": "2024-06-15T15:00:00Z"
            }
          }
        }
      ]
    }
  },
  "aggs": {
    "by_source_ip": {
      "terms": {
        "field": "source.ip"
      },
      "aggs": {
        "alert_count": {
          "value_count": {
            "field": "waf.alert_id"
          }
        }
      }
    }
  }
}
```

### Hunt #5: Failed Authentication Clustering (Credential Stuffing)

**PowerShell (Windows Event Log):**
```powershell
# Query Security event log for 4625 (failed logon) clusters
$fourSixTwoFive = Get-WinEvent -FilterHashtable @{
  LogName   = 'Security'
  ID        = 4625
  StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue |
  Where-Object { $_.Properties[19].Value -match "^192\.168\.1\." }  # Filter by source IP

# Group by source IP and count
$fourSixTwoFive |
  Group-Object { $_.Properties[19].Value } |
  Where-Object { $_.Count -gt 50 } |  # Alert if > 50 failures from single IP in 24h
  Select-Object Name, Count, @{
    Name       = 'FirstFailure'
    Expression = { ($_.Group | Sort-Object TimeCreated | Select-Object -First 1).TimeCreated }
  }, @{
    Name       = 'LastFailure'
    Expression = { ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated }
  }

# Example output:
# Name           Count  FirstFailure            LastFailure
# ----           -----  ----------------        ----------------
# 192.168.1.100  287    2024-06-15 10:35:20     2024-06-15 10:36:15
```

**Linux (via auditd or syslog):**
```bash
# Search syslog for failed SSH logins
grep "Failed password\|Invalid user" /var/log/auth.log |
  awk '{print $11}' |
  sort | uniq -c | sort -rn |
  awk '$1 > 50 {print "[ALERT] " $2 " failed " $1 " times (likely brute force)"}'

# Count by source IP
grep "from.*port" /var/log/auth.log |
  awk -F'from' '{print $2}' |
  awk '{print $1}' |
  sort | uniq -c | sort -rn |
  awk '$1 > 50 {print "[ALERT] " $2 " with " $1 " login attempts"}'
```

### Hunt #6: HTTP Status Code Anomalies

**PowerShell:**
```powershell
# Get baseline for normal 5xx error rate, then detect spikes
$logs = Get-Content "C:\inetpub\logs\LogFiles\W3SVC1\*.log" |
  Select-String -NotMatch "^#" |
  ForEach-Object {
    $parts = $_ -split " "
    [PSCustomObject]@{
      Timestamp = [datetime]::ParseExact(($parts[0] + " " + $parts[1]), "yyyy-MM-dd HH:mm:ss", $null)
      SourceIP = $parts[2]
      Status = [int]$parts[8]
    }
  }

# Count 5xx errors per hour
$logs |
  Where-Object { $_.Status -ge 500 } |
  Group-Object -Property SourceIP, { $_.Timestamp.ToString("yyyy-MM-dd HH:00:00") } |
  Where-Object { $_.Count -gt 10 } |  # Alert if > 10 server errors from single IP in 1 hour
  Select-Object Name, Count |
  Sort-Object Count -Descending

# Example output:
# 192.168.1.100, 2024-06-15 10:00:00    287  ← Likely Scanner hitting vulnerable code
```

**Bash:**
```bash
# Count HTTP status codes by source IP
awk '{print $1 " " $9}' /var/log/apache2/access.log |
  sort | uniq -c | sort -rn |
  awk '$3 >= 500 && $2 ~ /192\.168/ {print "[ALERT] " $2 " received " $1 " 5xx errors"}' |
  head -10
```

### Hunt #7: Network Packet Capture Analysis (Zeek/NetFlow)

**Zeek HTTP Log (JSON or TSV):**
```bash
# Search Zeek http.log for Burp User-Agent
jq '.[] | select(.user_agent | contains("Burp/"))' zeek_http.log |
  jq '{timestamp: .ts, src_ip: .id_orig_h, method: .method, host: .host, uri: .uri, user_agent: .user_agent}' |
  head -20

# Count unique URIs accessed by a single source IP
jq '.[] | select(.id_orig_h == "192.168.1.100")' zeek_http.log |
  jq '.uri' | sort | uniq -c | sort -rn
```

**NetFlow Analysis (via nfdump or Argus):**
```bash
# Export NetFlow data and analyze high-packet-count flows
nfdump -r nfcapd.202406151000 -c 'srcip=192.168.1.100' |
  grep -E "dstip=10\.0\.1\." |
  awk '{print $NF}' |  # Extract packet count
  awk '{sum+=$1} END {print "Total packets: " sum}'

# Expected finding: 287–300 packets from 192.168.1.100 to 10.0.1.50:443 in 2-minute window
```

---

## Fleet-Wide Sweep (Proactive Hunting)

**Objective:** Hunt across the entire network/infrastructure for signs of Burp activity.

### Splunk Enterprise-Wide Search

```spl
# Search all ingested logs for Burp User-Agent
index=* "Burp/" 
| stats count, earliest(_time), latest(_time), values(src_ip), values(dest_ip) by user_agent

# Find all failed logins followed by successful login from same IP (credential stuffing pattern)
index=security EventCode=4625 earliest=-7d@d latest=now
| stats count by src_ip
| where count > 100
| join src_ip [
    search index=security EventCode=4624 earliest=-7d@d latest=now
    | stats earliest(_time), latest(_time) by src_ip
  ]
| where (latest(_time) - earliest(_time)) < 300  # Success within 5 min of first failure
```

### Microsoft Sentinel (Azure)

```kusto
// Hunt for rapid failed logins followed by success
let FailureThreshold = 50;
let TimeWindow = 5m;

SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType != "0"  // Failed logins
| summarize FailureCount=count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1m)
| where FailureCount > FailureThreshold
| join (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == "0"  // Successful logins
    | project UserPrincipalName, IPAddress, TimeGenerated
  ) on UserPrincipalName, IPAddress
| where TimeGenerated > (TimeGenerated_1 - TimeWindow) and TimeGenerated < (TimeGenerated_1 + TimeWindow)
| project-away TimeGenerated_1
```

### Datadog Monitoring

```
# Create a Datadog monitor for high-rate scanning
@web.access.status:500 AND @http.useragent:*Burp* > 100 in last 10m by @network.client.ip
```

---

## Remediation (Preserve Evidence Before Acting)

**Do NOT immediately kill or block suspicious processes / IPs without evidence preservation.**

### Evidence Capture Checklist

```
BEFORE BLOCKING OR TERMINATING:

□ Capture full HTTP request/response pair (headers + body)
  - Command: Save the Burp request to a .txt file via browser developer tools or WAF capture
  - Example: curl -v [URL] > request_capture.txt 2>&1

□ Export relevant log entries (IIS, Apache, application logs)
  - Command: Get-Content + Select-String (PowerShell) or grep + awk (Linux)
  - Example: grep "Burp/" /var/log/apache2/access.log > burp_requests.log

□ Extract event log entries (Windows Security, Application logs)
  - Command: wevtexport or PowerShell Get-WinEvent
  - Example: Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625, 4624} -MaxEvents 500 | Export-Csv auth_events.csv

□ Capture packet data (if available)
  - Command: tcpdump, Wireshark, or retrieve from PCAP archive
  - Example: tcpdump -i eth0 -w burp_traffic.pcap 'src host 192.168.1.100'

□ Screenshot WAF/IDS alerts (for visual documentation)
  - Include: alert timestamp, rule name, severity, payload/evidence, source IP, destination URL

□ Record timeline (earliest request, latest request, total duration)
  - Document in a text file: first_request=2024-06-15T10:24:33Z, last_request=2024-06-15T10:45:00Z, duration=20m 27s

□ Preserve attacker's IP address and any user-agent strings for attribution
```

### Incident Response Actions

**1. Isolate and Contain (if active engagement detected):**
```powershell
# Block attacker IP at firewall (example using Windows Firewall)
netsh advfirewall firewall add rule name="Block Burp Scanner" dir=in action=block remoteip=192.168.1.100

# Or redirect to honeypot/isolated network (if desired for observation)
# (Requires network infrastructure changes — consult network team)
```

```bash
# Linux: Block IP using iptables
sudo iptables -I INPUT -s 192.168.1.100 -j DROP
sudo iptables -I FORWARD -s 192.168.1.100 -j DROP

# Persist across reboots (Debian/Ubuntu)
sudo apt-get install iptables-persistent
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**2. Disable Vulnerable Endpoints (if confirmed exploitation):**
```
- If SQL injection confirmed: temporarily disable the /search endpoint
- If authentication bypass found: force password reset for affected accounts
- If RCE confirmed: immediately isolate the compromised server from network
```

**3. Notify Security/Management:**
- Document findings in incident ticket with forensic evidence
- Include: attacker IP, affected endpoints, vulnerabilities found, duration of engagement
- Recommend: patch vulnerabilities, WAF tuning, network segmentation

**4. Long-Term Hardening (post-incident):**
```
□ Deploy WAF rules for Burp detection (ModSecurity CRS 3.2+)
□ Enable request logging (with full body capture) for audit trail
□ Configure rate-limiting (429 threshold at 100+ req/min from single IP)
□ Deploy EDR/XDR agent on critical web servers
□ Enable advanced authentication logging (Event ID 4624, 4625)
□ Implement IDS/IPS monitoring for OWASP Top 10 attack patterns
□ Conduct patch management (fix discovered vulnerabilities)
□ Review access controls and enforce least-privilege on application endpoints
```

---

## Detection Baseline and Tuning

**False Positive Prevention:**

| Legitimate Traffic Pattern | Why It Might Look Like Burp | How to Distinguish |
|---|---|---|
| Automated API client (CI/CD, monitoring agent) | Makes rapid sequential requests with generic User-Agent | Check User-Agent string (CI tools use identifiable names: `curl/7.x`, `Python-requests/2.x`, `ServiceNow-Agent/1.0`); Burp is nearly unique |
| Load testing tool (JMeter, Locust, LoadRunner) | High request rate from single IP | Load testers announce themselves in User-Agent or request headers (e.g., `ApacheBench`, `Locust`); Burp does not |
| Legitimate security team running approved assessment | Makes requests with attack payloads | Check approval ticket and compare IP to authorized testing range; coordinate with security team before blocking |
| Web crawler (Googlebot, Bingbot, search engine) | Makes many sequential requests | Check User-Agent (Googlebot, Bingbot, etc.); these follow `robots.txt` and don't send attack payloads |
| Real user with malicious intent (not Burp) | Sends SQL injection/XSS payloads | Typically slower, lower request rate, inconsistent User-Agent; Burp pattern is systematic and rapid |

**Tuning WAF Rules:**

```
# ModSecurity: Lower false-positive rate by adjusting anomaly score
SecMarker BEFORE_SESSION_ACCESS_PHASE_1

# If seeing 20+ Burp requests/minute and they're all confirmed attack traffic, raise alert threshold
SecAction "phase:3,id:1000,pass,msg:'Set Burp Detection Mode',setvar:'tx:burp_detection=1'"

# Correlate WAF alerts with User-Agent before blocking
SecRule RESPONSE_HEADERS:User-Agent "@contains Burp" \
    "id:2000,phase:3,pass,msg:'Burp Scanner Detected',tag:'burp',tag:'scanner'"
```

