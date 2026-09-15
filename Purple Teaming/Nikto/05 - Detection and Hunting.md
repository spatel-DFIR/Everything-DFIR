# Nikto — Detection and Hunting

## Hunting Priority Table

The following table ranks Nikto detection signals by **invariant strength** — which survive which evasion techniques. Evasion flags (`-evasion 1–8,A,B`, `-useragent custom`, `-Pause delays`) can defeat signal 2–4 but **cannot hide** signals 1, 5, and 6:

| Rank | Signal | What It Detects | Survives `-evasion` | Survives `-useragent` | Survives `-Pause` | Difficulty to Spoof |
|---|---|---|---|---|---|---|
| **1** | **Rapid HTTP request clustering** | 50–500+ requests from one IP to one target within 1–10 minutes, exhaustive path enumeration | ❌ No | ✅ Yes | ❌ No | **Very Hard** |
| **2** | **db_tests path signatures** | Requests to `/admin/`, `/.env`, `/backup/`, `/config.php`, etc. — predictable, database-driven patterns | ⚠️ Partial (evasion 1–8 encode URI, but db_tests paths are still requested) | ✅ Yes | ✅ Yes | **Hard** |
| **3** | **User-Agent rotation** | Multiple different User-Agent strings from same source IP in short time window | ✅ Yes (if `-useragent custom` used) | ❌ No (randomized db_useragents is the default) | ✅ Yes | **Moderate** |
| **4** | **HTTP method diversity** | GET, HEAD, OPTIONS, (optional PUT/DELETE) in sequence — not all from same browsing session | ⚠️ Partial | ✅ Yes | ✅ Yes | **Moderate** |
| **5** | **Missing Referer header pattern** | All or most requests have Referer: `-` (no referer) — unusual for normal web browsing | ⚠️ Partial (`-Add-header` can inject Referer) | ✅ Yes | ✅ Yes | **Hard** |
| **6** | **HTTP/1.0 usage** | Some requests use HTTP/1.0 instead of HTTP/1.1 — older protocol version, rare in modern browsing | ❌ No | ✅ Yes | ✅ Yes | **Very Hard** (requires modifying LW2.pm internals) |
| **7** | **Optional: specific error patterns** | Server errors (5xx) triggered by Nikto's probes (e.g., `/app/secret/config.php` triggers 500 on broken app) | ⚠️ Partial | ✅ Yes | ✅ Yes | **Hard** (app-specific) |

**Recommended detection strategy:** Focus on **Rank 1** (clustering detection), **Rank 2** (db_tests path patterns), and **Rank 5** (Referer absence) as the core triad. Combine with log aggregation (SIEMs) to correlate across multiple detection mechanisms.

---

## Hunting on Source

### PowerShell: Find Nikto Binary and Script

```powershell
# Find nikto.pl on Windows (if attacker cloned repo)
Get-ChildItem -Path C:\, D:\, E:\ -Recurse -Filter nikto.pl -ErrorAction SilentlyContinue

# Find on Linux/Mac (common locations)
sudo find / -name "nikto.pl" 2>/dev/null
locate nikto.pl

# Check for nikto in PATH
which nikto
```

### Bash: Check Shell History for Nikto Invocations

```bash
# Search bash history for nikto
cat ~/.bash_history | grep nikto
cat ~/.zsh_history | grep nikto  # zsh

# Search all users' history (if you have access):
sudo grep -r "nikto" /home/*/.bash_history /root/.bash_history 2>/dev/null

# Check for Nikto in command-line audit logs (if auditd is enabled):
sudo ausearch -k nikto 2>/dev/null
sudo ausearch -x nikto 2>/dev/null

# Real-time monitoring for Nikto execution (auditd):
sudo auditctl -w /usr/local/bin/nikto -p x -k nikto_exec
sudo auditctl -w /opt/nikto/program/nikto.pl -p x -k nikto_exec
```

### Find Nikto Output Files

```bash
# Search for common Nikto output extensions
find ~ -type f \( -name "*nikto*.txt" -o -name "*nikto*.html" -o -name "*nikto*.json" -o -name "*nikto*.csv" \) 2>/dev/null

# Search by modification time (recent scans):
find ~ -type f -name "*nikto*" -mtime -7 2>/dev/null  # Modified in last 7 days

# Search entire filesystem (if root):
sudo find / -name "*nikto*" -type f 2>/dev/null

# Search for scan reports by extension pattern:
find ~ -type f \( -name "nikto_scan_*.txt" -o -name "scan_*.html" \) 2>/dev/null

# Check /tmp for temporary files:
ls -la /tmp/*nikto* 2>/dev/null
ls -la /tmp/results* /tmp/findings* 2>/dev/null  # Common output directories
```

### Examine Process and Network State

```bash
# If Nikto is actively running, find its process:
ps aux | grep nikto
ps aux | grep perl  # Nikto runs as perl

# Check network connections from the process:
sudo netstat -tnp | grep perl
sudo ss -tnp | grep perl

# Find established connections (if scan is in progress):
lsof -p $(pgrep -f nikto.pl) | grep -i tcp

# Check for listening ports (unusual for Nikto, but check anyway):
sudo netstat -tnlp | grep perl
```

### Check System Logs for Perl/Nikto Execution

```bash
# Linux: check syslog, auth log, or systemd journal
sudo tail -f /var/log/auth.log | grep perl
sudo journalctl -b | grep nikto
sudo journalctl -b | grep perl

# macOS: check system.log and install.log
log show --predicate 'process contains "perl"' --last 24h
log show --predicate 'message contains "nikto"' --last 24h

# Windows PowerShell: check event logs
Get-EventLog -LogName Application | Where-Object { $_.Message -like "*nikto*" }
Get-EventLog -LogName Security | Where-Object { $_.Message -like "*perl*" }
```

### Check Installed Packages and Downloads

```bash
# Check if Nikto was installed via package manager (Linux):
dpkg -l | grep nikto
rpm -qa | grep nikto
pacman -Q nikto

# Check for git repositories (if cloned):
find ~ -type d -name ".git" -path "*/nikto/.git" 2>/dev/null

# Check Downloads folder:
ls -la ~/Downloads/*nikto* 2>/dev/null

# Check for archives (zip, tar.gz):
find ~ -name "*nikto*.zip" -o -name "*nikto*.tar.gz" 2>/dev/null
```

### Check Cron Jobs or Scheduled Tasks

```bash
# Check crontab (user and system):
crontab -l
sudo crontab -l
sudo cat /etc/crontab
sudo ls -la /etc/cron.d/

# Search cron jobs for nikto:
sudo grep -r "nikto" /etc/cron* /var/spool/cron 2>/dev/null

# Windows: check Task Scheduler:
tasklist /v | findstr perl
schtasks /query /fo list | findstr nikto
```

### Check Configuration Files

```bash
# Look for custom nikto.conf:
find ~ -name "nikto.conf" -o -name ".niktorc" 2>/dev/null

# Check if ~/.niktorc exists:
cat ~/.niktorc 2>/dev/null

# Check for Nikto in common paths:
cat /usr/local/etc/nikto.conf 2>/dev/null
cat /etc/nikto.conf 2>/dev/null
```

---

## Hunting on Target

### HTTP Access Log Analysis (Core Hunting)

**Most reliable detection:** Parse web server access logs for Nikto's distinctive patterns.

```bash
# Search for rapid sequential requests (Apache/Nginx):
grep "192.168.1.101" /var/log/apache2/access.log | wc -l
# High count (50+) in short time window = suspicious

# Extract requests from a source IP:
grep "192.168.1.101" /var/log/apache2/access.log | cut -d' ' -f7 | sort | uniq -c | sort -rn

# Find requests to Nikto-typical paths:
grep -E "(admin|backup|config\.php|\.env|wp-login|cgi-bin)" /var/log/apache2/access.log | grep "192.168.1.101"

# Count requests per 5-minute window (to detect clustering):
awk '{print $4}' /var/log/apache2/access.log | cut -d: -f1-2 | sort | uniq -c | sort -rn
# If any 5-min window has 20+ requests from same IP → likely scan
```

### Detect HTTP/1.0 Requests (Nikto Signature)

```bash
# Look for HTTP/1.0 in access logs (rare in modern browsing):
grep -E "HTTP/1\.0" /var/log/apache2/access.log | head -20

# Extract User-Agent and HTTP version together:
grep -oE '".*" HTTP/1\.[01]' /var/log/apache2/access.log | grep HTTP/1.0

# Nikto often mixes HTTP/1.0 and HTTP/1.1 requests:
grep "192.168.1.101" /var/log/apache2/access.log | grep "HTTP/1.0" | wc -l
grep "192.168.1.101" /var/log/apache2/access.log | grep "HTTP/1.1" | wc -l
# Both present = suspicious
```

### Detect OPTIONS Method Requests

```bash
# Find OPTIONS requests (often a Nikto signature):
grep "OPTIONS" /var/log/apache2/access.log

# OPTIONS requests to / root (common Nikto check):
grep "OPTIONS /" /var/log/apache2/access.log

# Correlate source IP with OPTIONS requests:
grep "OPTIONS" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c
```

### Detect User-Agent Rotation

```bash
# Extract User-Agents for a source IP and count unique values:
grep "192.168.1.101" /var/log/apache2/access.log | awk -F'"' '{print $6}' | sort | uniq -c | sort -rn

# High count of unique User-Agents from one IP in short time = suspicious
# (Nikto's db_useragents rotation is a key signature)

# Filter for requests with "Mozilla" variations (common db_useragents):
grep "192.168.1.101" /var/log/apache2/access.log | grep "Mozilla"
```

### Detect Referer Header Absence

```bash
# Find requests with Referer: - (no referer):
grep ' "-" ' /var/log/apache2/access.log | head -20

# Count Referer-less requests from a source IP:
grep "192.168.1.101" /var/log/apache2/access.log | grep -c ' "-" '

# If >80% of requests from an IP have no Referer = suspicious
# (Normal browsing has Referers in most requests)
```

### IDS/WAF Detection (if available)

```bash
# Check Suricata alerts:
grep -i "nikto\|scanner" /var/log/suricata/eve.json | jq '.alert.signature' | sort | uniq -c

# Check Zeek HTTP logs for high request volume per source:
zeek http.log | awk '{print $5}' | sort | uniq -c | sort -rn
# (High counts = scanning)

# Check ModSecurity logs (Apache):
grep -i "nikto\|scanner" /var/log/apache2/modsec_audit.log

# Check WAF logs (cloud):
# AWS WAF → CloudWatch Logs
# Cloudflare → Logs → Threats
# F5/Imperva → WAF logs
```

### Nginx-Specific Access Logs

```bash
# Nginx common log format:
tail -f /var/log/nginx/access.log

# Find rapid requests:
awk '{print $1, $4}' /var/log/nginx/access.log | sort | uniq -c | sort -rn

# Find Nikto-typical paths:
grep -E "(admin|backup|config|\.env|wp-login|cgi-bin)" /var/log/nginx/access.log
```

### IIS Logs (Windows)

```powershell
# Read IIS logs:
Get-Content C:\inetpub\logs\LogFiles\W3SVC1\u_ex260812.log | Select-String "192.168.1.101"

# Find rapid requests:
$logs = Get-Content C:\inetpub\logs\LogFiles\W3SVC1\*.log
$logs | Where-Object { $_ -match "192.168.1.101" } | Measure-Object | Select-Object -ExpandProperty Count

# Find requests to Nikto-typical paths:
$logs | Where-Object { $_ -match "(admin|backup|config\.php|\.env)" }
```

### Fleet-Wide Scanning (Multiple Targets Detected)

**If Nikto scanned multiple targets, correlation across targets becomes evidence:**

```bash
# Scenario: Nikto scanned 5 targets from source 192.168.1.101
# Evidence:
# - Target1 logs: 192.168.1.101 probing /admin/, /.env, etc. (T=14:30–14:35)
# - Target2 logs: 192.168.1.101 probing /admin/, /.env, etc. (T=14:35–14:40)
# - Target3 logs: 192.168.1.101 probing /admin/, /.env, etc. (T=14:40–14:45)
# ... (same IP, same patterns, sequential timing)

# Correlation query (if using ELK/Splunk):
source_ip=192.168.1.101 AND (uri IN [/admin/, /.env, /backup/]) 
| stats count by target_host, source_ip, time | sort time
# Output: Same IP hitting multiple targets with Nikto pattern = high confidence
```

### Check for Response Size Anomalies

```bash
# Nikto generates requests to non-existent paths (mostly 404s with small responses)
# Followed by found paths (200s with variable sizes)

# Extract response sizes for a source IP:
grep "192.168.1.101" /var/log/apache2/access.log | awk '{print $10}' | sort | uniq -c | sort -rn

# Bimodal distribution (many small 404s + some larger 200s) = scanning signature
```

### Check for Evasion Encoding

```bash
# Look for URI-encoded requests (evasion technique 1):
grep "%2F\|%2E\|%5C" /var/log/apache2/access.log | head -20

# Look for requests with unusual encoding patterns:
grep -E "%00|%0d|%0a" /var/log/apache2/access.log

# Nikto's evasion techniques will be visible as encoded URIs in logs
```

---

## Remediation and Prevention

### Immediate Containment

1. **Block source IP** (if identified):
   ```bash
   # UFW (Ubuntu):
   sudo ufw deny from 192.168.1.101
   
   # iptables:
   sudo iptables -I INPUT -s 192.168.1.101 -j DROP
   
   # Windows Firewall:
   netsh advfirewall firewall add rule name="Block Nikto" dir=in action=block remoteip=192.168.1.101
   ```

2. **Preserve evidence** before blocking:
   ```bash
   # Archive access logs:
   cp /var/log/apache2/access.log /tmp/access_log_backup_$(date +%s)
   
   # Export IDS alerts:
   suricata-update-etpro; cp /var/log/suricata/eve.json /tmp/eve_backup
   ```

3. **Revoke or change credentials** for any accounts found during scan:
   - Change passwords for accounts in found files (/.env, /config.php, etc.)
   - Revoke API keys if found
   - Review access logs for any successful exploitation

### Long-Term Hardening

1. **Web Application Firewall (WAF):**
   - Deploy ModSecurity (Apache), NAXSI (Nginx), or cloud WAF (Cloudflare, AWS WAF)
   - Enable rules for scanner detection (OWASP ModSecurity Core Rule Set includes Nikto signatures)
   - Example ModSecurity rule:
   ```
   SecRule REQUEST_URI "@rx /(?:admin|backup|config|\.env|wp-login|cgi-bin)/" \
     "id:1000,phase:2,deny,log,msg:'Potential Nikto scan detected'"
   ```

2. **Disable Directory Listing:**
   - Apache: `Options -Indexes` in `.htaccess` or VirtualHost
   - Nginx: `autoindex off` in `nginx.conf`
   - IIS: Disable "Directory Browsing" in Feature View

3. **Remove Dangerous HTTP Methods:**
   - Disable PUT/DELETE/TRACE if not needed:
   ```apache
   # Apache:
   <Limit PUT DELETE TRACE CONNECT>
     Deny from all
   </Limit>
   ```
   - Nginx: Remove methods from `if ($request_method...)` blocks

4. **Delete/Protect Dangerous Files:**
   - Remove `install.php`, `test.php`, `config.php` (move to secure location if needed)
   - Protect `.env` files (should not be web-accessible):
   ```apache
   <Files .env>
     Deny from all
   </Files>
   ```
   - Protect `.git`, `.github`, `.gitlab-ci.yml` directories

5. **Implement Rate Limiting:**
   ```nginx
   # Nginx rate limiting:
   limit_req_zone $binary_remote_addr zone=nikto_zone:10m rate=5r/s;
   limit_req zone=nikto_zone burst=10 nodelay;
   ```

6. **Monitor and Alert:**
   - Configure SIEM (Splunk, ELK, Sentinel) to alert on:
     - >50 requests from one IP in 5 minutes
     - Requests to /admin/, /.env, /backup/ paths
     - OPTIONS method requests
     - Multiple HTTP/1.0 requests
   - Example Splunk search:
   ```
   sourcetype=apache_common | stats count by src_ip | where count > 50
   ```

7. **Security Headers:**
   - Add HTTP security headers (doesn't stop Nikto, but hardens application):
   ```apache
   Header set X-Frame-Options "DENY"
   Header set X-Content-Type-Options "nosniff"
   Header set Strict-Transport-Security "max-age=31536000; includeSubDomains"
   ```

8. **Baseline Logging:**
   - Ensure web server logging is enabled and centralized (not just local)
   - Use immutable log destinations (e.g., syslog server, S3 with object lock)
   - Implement log retention policy (90+ days for forensics)

9. **Network Segmentation:**
   - Place web servers in isolated DMZ
   - Restrict outbound connections from web servers (no C2 callbacks post-compromise)
   - Monitor north-south and east-west traffic

10. **Keep Software Updated:**
    - Regularly update Apache/Nginx/IIS
    - Keep PHP, .NET, and application frameworks current
    - Use Nikto itself to identify outdated software (as a defensive measure)

---

## Evidence Collection Best Practices

Before taking containment actions, ensure you've captured:

1. **Web server access logs** (full path, status, User-Agent, timestamp)
2. **IDS/WAF alerts** (if available)
3. **Network flow data** (NetFlow, sFlow, Zeek data)
4. **Process forensics** (if attacker was on the same host)
5. **Disk forensics** (any dropped files, backdoors)
6. **Memory forensics** (if incident response was immediate)
7. **DNS queries** (if attacker resolved hostnames)
8. **Firewall logs** (inbound connections, geolocation if available)

**Do NOT:**
- Delete logs immediately
- Reset firewall rules without documenting
- Restore from backups without forensic analysis
- Assume single attack is isolated (check for lateral movement)

**Do:**
- Collect evidence in forensically sound manner
- Preserve chain of custody
- Correlate evidence across multiple sources
- Document investigation process
- Report to incident response team

