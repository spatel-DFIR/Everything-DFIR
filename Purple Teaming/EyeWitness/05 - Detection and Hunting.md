# EyeWitness — Detection and Hunting

---

## Hunting on Source (Attacker's Host)

**Objective:** Identify indicators of EyeWitness use on a potentially compromised attacker machine (red-teamer's workstation, compromised internal asset used as a beachhead, etc.).

### File System Hunting

#### Search for output directory structure

```bash
# Find the distinctive EyeWitness output structure (report.html + ew.db + screens/ + source/)
find ~/ -type f -name "report.html" -newermt "2026-08-01" 2>/dev/null
find ~/ -type f -name "ew.db" 2>/dev/null
find ~/ -type d -name "screens" -o -type d -name "source" 2>/dev/null

# On Windows (PowerShell):
Get-ChildItem -Path $HOME -Recurse -Filter "report.html" -ErrorAction SilentlyContinue
Get-ChildItem -Path $HOME -Recurse -Filter "ew.db" -ErrorAction SilentlyContinue
```

**Confidence level:** High — the combination of report.html + ew.db + screens/ directory is highly specific to EyeWitness (other tools do not produce this exact structure).

#### Search for Python virtual environments

```bash
# Look for eyewitness-venv directory
find ~/ -type d -name "*eyewitness*venv*" 2>/dev/null
find ~/ -type d -name "eyewitness-venv" 2>/dev/null

# Or search for venv directories containing Selenium
find ~/ -type d -name "site-packages" -exec grep -l "selenium" {} \; 2>/dev/null
```

**Confidence level:** Medium-High — EyeWitness specifically creates a venv named eyewitness-venv, but other tools may also use Selenium.

#### Search for EyeWitness source code

```bash
# Find cloned EyeWitness repository
find ~/ -type f -name "EyeWitness.py" 2>/dev/null
find ~/ -type d -name "*EyeWitness*" 2>/dev/null

# Search for characteristic Python modules
find ~/ -path "*/Python/modules/*.py" -name "*selenium*" 2>/dev/null
```

**Confidence level:** High — if the full EyeWitness repository is found, attribution to EyeWitness is certain.

#### Search for screenshot PNG files

```bash
# Look for PNG files in bulk (suspicious for reconnaissance)
find ~/ -type f -name "*.png" -path "*/screens/*" -mtime -7 2>/dev/null

# Check file size distribution (EyeWitness screenshots typically 50–200 KB)
find ~/ -type f -name "*.png" -size +30k -size -300k -mtime -7 2>/dev/null | head -20
```

**Confidence level:** Medium — many applications generate screenshots, but bulk PNG directories named "screens/" with many files is suspicious.

#### Search for database files

```bash
# Look for SQLite databases with suspicious names
find ~/ -type f -name "ew.db" -o -name "*eyewitness*.db" 2>/dev/null

# Examine database structure
sqlite3 ~/path/to/ew.db ".schema" | grep -i "http_results"
sqlite3 ~/path/to/ew.db "SELECT COUNT(*) FROM http_results;"
```

**Confidence level:** High — ew.db with the exact schema described in 03 - Source Evidence is definitive.

### Process and Memory Hunting

#### Look for active ChromeDriver/Selenium processes

```bash
# Identify ChromeDriver processes (typically spawned by Selenium)
ps aux | grep -i "chromedriver"
ps aux | grep -i "chrome" | grep "headless"

# Look at process trees
pstree -p | grep -B5 -A5 "python"

# On Windows:
Get-Process | Where-Object {$_.Name -like "*chrome*" -or $_.Name -like "*chromedriver*"}
Get-Process -Name "python" | Get-Process -IncludeChildProcess
```

**Confidence level:** Medium — ChromeDriver indicates Selenium is running, but not definitively EyeWitness (other tools also use Selenium).

#### Check open file descriptors

```bash
# For a Python process suspected of running EyeWitness
lsof -p <PID> | grep -E "(\.png|\.html|ew\.db|screens|source)"

# Look for network connections from ChromeDriver
lsof -p <PID> -iTCP -sTCP:ESTABLISHED | tail -20
```

**Confidence level:** Medium — identifying open connections to many hosts over short time window is consistent with web reconnaissance.

### Command-Line History Hunting

#### Bash/Zsh history

```bash
# Search for EyeWitness in shell history
grep -r "EyeWitness" ~/.bash_history ~/.zsh_history ~/.bash_history_extended 2>/dev/null
grep -r "python.*EyeWitness.py" ~/.bash_history ~/.zsh_history 2>/dev/null

# Look for common EyeWitness flags
grep -r "\-\-threads\|\-\-timeout\|eyewitness-venv" ~/.bash_history 2>/dev/null

# Search for Nmap XML output paired with EyeWitness (common workflow)
grep -r "\-oX" ~/.bash_history | grep -i "nmap"
grep -r "^python.*\-x.*\.xml" ~/.bash_history
```

**Confidence level:** High — finding EyeWitness.py invocation in shell history is definitive.

#### PowerShell history

```powershell
# PowerShell history location
Get-Content $PROFILE | Select-String "EyeWitness"
Get-Content "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" | Select-String "EyeWitness"

# Search for setup script execution
Get-Content "$env:APPDATA\...\ConsoleHost_history.txt" | Select-String "setup\.ps1"
```

**Confidence level:** High — finding EyeWitness setup or invocation in PowerShell history is definitive.

#### Python REPL history

```bash
# Check Python REPL history (if Python scripts were run interactively)
cat ~/.python_history | grep -i "eyewitness\|selenium"

# Check Jupyter notebooks
find ~/ -name "*.ipynb" -exec grep -l "EyeWitness\|selenium" {} \;
```

**Confidence level:** Medium — suggests exploration or testing, not necessarily EyeWitness usage.

### Network Artifact Hunting

#### Check DNS resolver cache/history

```bash
# Linux: systemd-resolved cache
resolvectl statistics | grep -i "cache"
journalctl -u systemd-resolved | grep -E "intranet|corp|internal"

# macOS: mDNS cache
dns-sd -G v4v6 [target]

# Windows: DNS cache
ipconfig /displaydns | Select-String "intranet\|corp\|admin"
```

**Confidence level:** Low-Medium — DNS cache is ephemeral and may not persist long after scan.

#### Check browser history (if attacker used a GUI browser for any reason)

```bash
# Chrome/Chromium history database (SQLite)
sqlite3 ~/.config/google-chrome/Default/History "SELECT url, visit_time FROM urls WHERE url LIKE '%intranet%' OR url LIKE '%admin%';"

# Firefox history
sqlite3 ~/.mozilla/firefox/*.default/places.sqlite "SELECT url FROM moz_places WHERE url LIKE '%internal%';"

# Safari history
sqlite3 ~/Library/Safari/History.db "SELECT url FROM history_visits JOIN history_items ON history_items.id = history_visits.history_item WHERE url LIKE '%admin%';"
```

**Confidence level:** Medium — browsing history may indicate reconnaissance targets, but does not confirm EyeWitness specifically.

#### Check proxy/VPN logs (if applicable)

```bash
# If attacker used a proxy, logs may show bulk requests routed through it
grep -i "proxy" ~/.bash_history ~/.zsh_history
grep -r "proxy-ip\|proxy-port" ~/.bash_history

# Check VPN connection logs
cat /var/log/syslog | grep -i "vpn\|openvpn\|wireguard" | tail -20
```

**Confidence level:** Medium — proxy usage suggests operational security, but doesn't confirm EyeWitness.

### Temporary File Hunting

#### Check /tmp for orphaned artifacts

```bash
# Look for Chromium temporary directories (if process was killed)
ls -lah /tmp | grep -i "chromium\|chrome"

# Look for orphaned image or HTML files
find /tmp -type f \( -name "*.png" -o -name "*.html" \) -mtime -1 2>/dev/null

# Check for database files
find /tmp -type f -name "*.db" -mtime -1 2>/dev/null
```

**Confidence level:** Low — temporary files are cleaned up automatically, but if present, they're forensically valuable.

#### Check for deleted files (file carving)

```bash
# Use autopsy, Foremost, or similar tools to recover deleted files from unallocated space
foremost -i /dev/sda1 -o ./recovery/

# Look for PNG/SQLite signatures in unallocated blocks
strings /dev/sda1 | grep -E "PNG|SQLite" | head -20
```

**Confidence level:** Medium-High — recovered deleted files confirm historical EyeWitness use.

---

## Hunting on Target (Victim Network)

**Objective:** Identify indicators of web reconnaissance activity on a target network (web server logs, firewall logs, etc.) that may indicate an attacker has run EyeWitness or similar reconnaissance tool.

### Web Server Log Hunting

#### Search for Chrome User-Agent with anomalous patterns

```bash
# Apache/Nginx access logs: search for Chrome User-Agent in rapid-fire requests
grep "Mozilla.*Chrome" access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -20

# Output: IPs making the most Chrome-based requests
# Expected: legitimate traffic has distributed IPs; reconnaissance has single IP with high count
```

**Query:**
```bash
# Find IPs making 50+ requests within 5 minutes with Chrome User-Agent
awk -F'"' '/Mozilla.*Chrome/ {print $5}' access.log | sort | uniq -c | awk '$1 > 50 {print $2}'
```

**Confidence level:** Medium — Chrome User-Agent is common, but combined with other factors, it's suspicious.

#### Search for requests with missing Referer header

```bash
# Requests with no Referer are common in API usage, but combined with Chrome User-Agent + rapid rate = suspicious
grep -v "Referer:" access.log | grep "Mozilla.*Chrome" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

**Confidence level:** Medium-High — Missing Referer + Chrome User-Agent + high volume = headless browser indicator.

#### Search for error-code enumeration (401/403/404 patterns)

```bash
# Find IPs receiving mostly 401/403/404 responses (not 200)
awk '{print $1, $9}' access.log | grep -E " (401|403|404)" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Expected: legitimate users have mostly 200s; reconnaissance shows mostly errors (endpoints being probed)
```

**Confidence level:** Medium — High percentage of 401/403/404 from single IP indicates endpoint enumeration.

#### Search for HTTP/2 with single GET per URL pattern

```bash
# In Nginx logs with HTTP/2 indicators
grep " HTTP/2.0 " access.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Combined with Chrome User-Agent
grep " HTTP/2.0 " access.log | grep "Chrome" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

**Confidence level:** High — HTTP/2 + Chrome User-Agent + bulk requests = browser-based reconnaissance.

#### Create a hunting query (ELK/Splunk)

```
# Elasticsearch/Kibana or Splunk query to find reconnaissance activity
user_agent:"Mozilla*Chrome" 
AND (http.response.status_code:(401 OR 403 OR 404) OR http.response.status_code:200) 
AND request_count:>20 
AND time_window:5m 
AND source_ip:[single IP]

# Returns: IPs making 20+ requests (mixed 200/401/403/404) within 5-minute window with Chrome User-Agent
```

**Confidence level:** High.

### Firewall and Network Log Hunting

#### Search for high connection counts from single IP

```bash
# Parse firewall logs for connection count by source IP
awk '{print $source_ip}' firewall.log | sort | uniq -c | sort -rn | head -20

# Expected: reconnaissance shows 50+ connections within 5 minutes to different destinations
# Baseline: normal traffic shows 5–10 connections per IP per hour
```

**Query (iptables log):**
```bash
grep -E "SYN|ESTABLISHED" iptables.log | awk '{print $source_ip}' | uniq -c | sort -rn
```

**Confidence level:** High — bulk connections from single IP is suspicious regardless of tool.

#### Search for rapid sequential connections to different ports

```bash
# Find IPs connecting to multiple destination ports within short time window
awk '{print $source_ip, $dest_ip, $dest_port, $timestamp}' firewall.log | \
  awk -F' ' '{ip=$1; key=ip "_" int($4/300); count[key]++; dest[key]=dest[key] "|" $2 ":" $3} \
  END {for (k in count) if (count[k] > 20) print k, count[k], dest[k]}'

# Returns: IPs making 20+ connections within 5-minute window to multiple destinations
```

**Confidence level:** High.

#### Search for TLS handshakes to multiple destinations

```bash
# Parse firewall or IDS logs for TLS ClientHello events
grep -i "tls\|ssl\|handshake" firewall.log | awk '{print $source_ip, $dest_ip, $dest_port}' | \
  awk '{key=$1; dest[key]=dest[key] " " $2 ":" $3} \
  END {for (k in dest) { split(dest[k], arr, " "); unique=length(arr); if (unique > 20) print k, unique " destinations"}}'

# Returns: IPs with TLS handshakes to 20+ unique destination IPs/ports
```

**Confidence level:** High.

### DNS Log Hunting

#### Search for bulk DNS queries from single IP

```bash
# Parse DNS query logs
awk '{print $source_ip, $query_name}' dns.log | \
  awk '{ip=$1; query_count[ip]++; queries[ip]=queries[ip] " " $2} \
  END {for (ip in query_count) if (query_count[ip] > 50) print ip, query_count[ip] " queries", queries[ip]}'

# Returns: IPs with 50+ DNS queries within scan timeframe
```

**Confidence level:** Medium-High — bulk DNS queries to internal hostnames from external IP is suspicious.

#### Search for DNS queries to uncommon hostnames

```bash
# Identify queries to hostnames that deviate from baseline
# (e.g., admin.*, internal.*, intranet.*, api.*, config.*)
grep -iE "admin|internal|intranet|api|config|debug|test" dns.log | awk '{print $source_ip}' | sort | uniq -c | sort -rn | head -10

# Returns: IPs querying many admin/internal/test hostnames
```

**Confidence level:** High — queries to admin/internal/test hostnames indicate targeted reconnaissance.

#### Create DNS hunting query (ELK/Splunk)

```
# Splunk query
index=dns sourcetype=dns 
| stats count by query, src_ip 
| where query like "admin" OR query like "internal" OR query like "test" 
| stats sum(count) as query_count by src_ip 
| where query_count > 50
```

**Confidence level:** High.

### IDS/Intrusion Detection Hunting

#### Snort/Suricata alerts for web reconnaissance

```
# Alert for suspicious User-Agent + high connection rate
alert http $HOME_NET any → $EXTERNAL_NET any 
  (
    msg:"Possible Web Application Reconnaissance";
    content:"Mozilla"; http_user_agent;
    content:"Chrome"; http_user_agent;
    flow:established; direction:to_server;
    threshold: type both, track by_src, count 20, seconds 300;
    sid:1000001; rev:1;
  )
```

**Confidence level:** High — if alert fires for 20+ requests from single IP within 300 seconds.

#### Zeek notice detection

```
# Zeek notice log for:
# - Too Many HTTP Requests (Zeek HTTP module tracks request rate)
# - Scanner Detection (Zeek detects patterns consistent with scanners)
# - SSL Certificate Validation Errors (if target uses self-signed cert)

grep "HTTP::Too_Many_Requests\|SSL::Certificate_Error" notice.log | awk '{print $12}' | sort | uniq -c
```

**Confidence level:** Medium-High — Zeek's built-in heuristics for scanner detection.

### Application Log Hunting

#### Search for stateless request patterns

```bash
# Application logs showing repeated 401 (Unauthorized) without session establishment
grep " 401 " app.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Expected: legitimate users receive 401 once, then authenticate; reconnaissance shows multiple 401s from same IP
awk '/401/ {ip=$1; unauthorized[ip]++} END {for (ip in unauthorized) if (unauthorized[ip] > 10) print ip, unauthorized[ip] " 401s"}' app.log
```

**Confidence level:** Medium-High — bulk 401s from single IP suggests endpoint enumeration.

#### Search for requests to uncommon endpoints

```bash
# Application logs showing requests to /admin, /config, /debug, /internal paths
grep -iE "GET.*/admin|GET.*/config|GET.*/debug|GET.*/api/internal" app.log | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# Returns: IPs probing administrative/internal endpoints
```

**Confidence level:** High — probing admin/internal endpoints indicates reconnaissance intent.

#### Search for lack of session persistence

```bash
# Users with multiple GET requests but no session cookie reuse
awk '$request ~ /GET/ && $session_id == "-" {print $1}' app.log | sort | uniq -c | sort -rn | head -10

# Expected: legitimate users establish a session (cookie) and reuse it; reconnaissance shows stateless requests
```

**Confidence level:** Medium-High.

### WAF/Security Appliance Log Hunting

#### Search for bot/scanner detection alerts

```bash
# WAF rules that commonly fire on EyeWitness:
grep -i "bot\|scanner\|headless\|automation" waf.log | awk '{print $source_ip}' | sort | uniq -c | sort -rn | head -10

# Returns: IPs triggering bot/scanner detection rules
```

**Confidence level:** High — WAF bot/scanner rules are trained on reconnaissance patterns.

#### Search for rate-limit events

```bash
# WAF rate-limiting events
grep -i "rate.limit\|too.many.request" waf.log | awk '{print $source_ip}' | sort | uniq -c | sort -rn | head -10

# Returns: IPs hitting rate limits (consistent with bulk reconnaissance)
```

**Confidence level:** High.

---

## Behavioral Indicators Summary

### Red Flag Combination (Attacker's Host)

- **report.html + ew.db + screens/ + source/ directory structure** present ✓
- **eyewitness-venv** or similar Python virtual environment present ✓
- **EyeWitness.py or RedSiege/EyeWitness repository** found ✓
- **Recent shell history containing EyeWitness invocation** ✓
- **Multiple screenshot PNG files in bulk** ✓
- **SQLite database with http_results schema** ✓

**Confidence:** Very High (any 2+ of above = definitive EyeWitness use)

### Red Flag Combination (Victim Network)

- **Single IP making 50+ HTTP requests within 5 minutes** ✓
- **Chrome User-Agent in all requests** ✓
- **Missing Referer header** ✓
- **High percentage of 401/403/404 responses** ✓
- **HTTP/2 protocol negotiated** ✓
- **Bulk DNS queries to internal hostnames from same IP** ✓
- **Rapid TLS handshakes to multiple destination IPs** ✓
- **WAF bot/scanner detection alerts for same IP** ✓

**Confidence:** High (any 4+ of above = likely web reconnaissance activity)

---

## Tuning False Positives

### False Positive Scenarios

**Legitimate Chrome Users:**
- Normal users browse with Chrome; would show Chrome User-Agent
- **Distinguish:** Legitimate users show asset requests (CSS, JS, images), longer inter-request intervals, referrer headers
- **Filter:** Set minimum request count threshold (50+ requests in 5 min) to eliminate single-user browsing

**Automated Testing (Selenium, Puppeteer):**
- Other testing frameworks also use Selenium/Chromium
- **Distinguish:** Filter by source IP (known test infrastructure IPs are approved)
- **Filter:** Whitelist internal QA/testing systems known to run Selenium

**API Clients (Headless):**
- Modern API clients sometimes use Chrome User-Agent for compatibility
- **Distinguish:** API clients typically use specific paths (/api/, /v1/, /v2/), not root paths
- **Filter:** Whitelist known API clients and their IP ranges

### Tuning Alerts

**Recommended thresholds:**
- **Request count:** 50+ requests from single IP within 5-minute window
- **Response-code mix:** 30%+ 401/403/404 responses (indicates errors, not normal browsing)
- **DNS query rate:** 50+ unique DNS queries within 1-minute window
- **Connection rate:** 20+ TLS handshakes to unique destination IPs within 5 minutes

**Exclusion lists:**
- Whitelist internal QA/testing IPs
- Whitelist known bug-bounty/pen-test ranges (if applicable)
- Whitelist corporate proxy IPs (if proxies generate legitimate bulk requests)

---

## Recommended Detection Rules (SIEM/Splunk/ELK)

### Rule 1: Bulk Chrome Requests with Missing Referer

```
Name: Bulk Chrome User-Agent with Missing Referer (Reconnaissance)
Criteria:
  - User-Agent contains "Chrome" or "Chromium"
  - Referer header is missing or empty
  - Request count from same source IP > 50 within 5 minutes
  - HTTP status includes 401/403/404 (>30%)
Action: Alert (Medium severity)
Response: Block IP, alert SOC, correlate with other indicators
```

### Rule 2: Rapid TLS Handshakes to Multiple Destinations

```
Name: Rapid TLS Handshakes to Multiple Destinations (Network Reconnaissance)
Criteria:
  - TLS ClientHello from single source IP
  - Destination count > 20 unique IPs within 5 minutes
  - Single GET request per destination (no asset follow-ups)
Action: Alert (High severity)
Response: Block IP, capture TLS handshake details, correlate with DNS queries
```

### Rule 3: Bulk DNS Queries for Admin/Internal Hostnames

```
Name: Bulk DNS Queries for Admin/Internal Hostnames (DNS Reconnaissance)
Criteria:
  - Query names contain "admin", "internal", "intranet", "api", "config", "debug"
  - Query count from same source IP > 50 within 1 minute
  - Queries to internal domain suffixes (.corp, .local, .internal, etc.)
Action: Alert (Medium severity)
Response: Log queries, correlate with HTTP requests from same IP
```

### Rule 4: Single Source IP Accessing Multiple Uncommon Endpoints

```
Name: Enumeration of Admin/Internal Endpoints
Criteria:
  - HTTP requests to paths: /admin*, /debug*, /config*, /internal*, /api/internal*
  - Source IP count > 10 requests to such paths within 5 minutes
  - Response codes 401/403 (authentication/permission denied)
Action: Alert (Medium severity)
Response: Alert SOC, enable detailed logging for source IP
```

---

## Incident Response Playbook (EyeWitness Reconnaissance Detected)

### Step 1: Confirm and Scope
- [ ] Confirm alert from 2+ sources (HTTP logs + DNS + Firewall + IDS)
- [ ] Identify source IP address and any correlated users/systems
- [ ] Determine timeframe of activity (scan start/end times)
- [ ] Estimate number of targets scanned (unique destination IPs)

### Step 2: Preserve Evidence
- [ ] Capture firewall logs for source IP (full session data)
- [ ] Export web server access logs for affected targets
- [ ] Capture DNS query logs from affected timeframe
- [ ] Preserve WAF/IDS alerts and rule hits
- [ ] Take screenshot of real-time monitoring dashboards

### Step 3: Contain
- [ ] Block source IP at firewall level (if external)
- [ ] Alert SOC to monitor for follow-up exploitation attempts
- [ ] If source is internal, isolate/quarantine source host from network
- [ ] Notify affected applications/business units of reconnaissance

### Step 4: Investigate
- [ ] Determine if reconnaissance led to any successful exploitation
- [ ] Check for any suspicious logins to identified applications using default credentials
- [ ] Review application logs for any POST requests (data exfiltration) following reconnaissance
- [ ] Correlate with other threat intelligence (known threat actors, threat feeds)

### Step 5: Remediate
- [ ] If source is attacker-controlled (external), no remediation needed on source
- [ ] If source is compromised internal system, conduct forensics and reimaging
- [ ] Patch/update any identified vulnerable applications
- [ ] Disable or change default credentials on affected systems
- [ ] Update WAF/IDS signatures to better detect future reconnaissance

### Step 6: Improve Detection
- [ ] Tune false positives based on Rule Tuning section above
- [ ] Update baselines for normal network traffic
- [ ] Implement additional monitoring for identified targets/applications
- [ ] Consider implementing network segmentation to limit reconnaissance impact

---

## IOC (Indicator of Compromise) Summary

### File-Based IOCs
```
filename: report.html
filename: ew.db
filepath: */screens/*.png
filepath: */source/*.html
directory: *eyewitness*venv
directory: *Purple\ Teaming/EyeWitness*
```

### Network IOCs
```
user_agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 ... Chrome/*
protocol: HTTP/2.0
behavior: 50+ requests from single IP within 5 minutes
behavior: bulk DNS queries to internal hostnames
behavior: rapid TLS handshakes to 20+ unique IPs within 5 minutes
```

### Process IOCs
```
process_name: chromedriver
process_name: python (parent: EyeWitness.py)
command_line: "python*/EyeWitness.py"
command_line: "--threads*--timeout"
```
