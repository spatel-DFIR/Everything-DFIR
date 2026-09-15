# ffuf — Detection and Hunting

## Hunting on Source (Attacker's Host)

### Shell History Analysis

**Objective:** Identify ffuf invocations in shell history.

```bash
# Grep for ffuf in bash history
grep -r "ffuf" ~/.bash_history

# Search zsh history
grep "ffuf" ~/.zsh_history

# Search all shell history across all users
sudo grep -r "ffuf" /home/*/.*_history /root/.*_history 2>/dev/null

# Search for ffuf with common flags
grep -E "ffuf.*(-w|-u|--wordlist)" ~/.bash_history
```

**Expected output:**
```
ffuf -u https://target.com/FUZZ -w /usr/share/SecLists/Discovery/Web-Content/common.txt -mc 200
ffuf -u https://internal-api.company.com/FUZZ -w /home/attacker/wordlists/api-endpoints.txt
```

**Evasion resistance:** **Very High** — ffuf invocations in shell history are almost always captured unless the attacker explicitly clears history (`history -c`, `rm ~/.bash_history`, `export HISTFILE=/dev/null`).

---

### Wordlist File Discovery

**Objective:** Locate wordlist files that indicate ffuf staging.

```bash
# Find common SecLists directories
find /home -name "SecLists" 2>/dev/null
find /tmp -name "*wordlist*" -o -name "*common*" 2>/dev/null

# Find files with suspicious names matching fuzzing wordlists
find /home -name "directories.txt" -o -name "paths.txt" -o -name "subdomains.txt" 2>/dev/null

# Check modification times (recent wordlist staging)
find /home -type f -name "*.txt" -mtime -7  # Modified within last 7 days
ls -lah ~/wordlists/ ~/SecLists/ /tmp/*wordlist* 2>/dev/null

# Content inspection: does the file contain common fuzz words?
grep -l "admin\|config\|backup\|api" /home/attacker/*.txt 2>/dev/null
```

**Expected output:**
```
/home/attacker/SecLists/Discovery/Web-Content/common.txt
/home/attacker/wordlists/api-endpoints.txt
/tmp/subdomains.txt (recently modified)
```

**Evasion resistance:** **High** — Files are only deleted if the attacker actively cleans them. Deleted files may still be recoverable via file-system forensics.

---

### Process and Network State (Live System)

**Objective:** Detect ffuf running in real-time.

```bash
# Check running processes for ffuf
ps aux | grep ffuf
pgrep -a ffuf

# Monitor active network connections from ffuf
netstat -tpn | grep ffuf
ss -tpn | grep ffuf

# Count active connections from ffuf to a specific target
netstat -tpn | grep -c "203.0.113.50.*443"
```

**Expected output:**
```
attacker 12345 25.3 15.2 123456 1024000 ?  Sl  14:32   0:45 ffuf -u https://target.com/FUZZ ...
tcp  0  0 192.168.1.100:54321 203.0.113.50:443 ESTABLISHED 12345/ffuf
(38 active connections)
```

**Evasion resistance:** **Moderate** — Only detectable while ffuf is running. Once terminated, only shell history remains.

---

### Output File Recovery

**Objective:** Locate saved ffuf results.

```bash
# Find JSON/CSV output files
find /home -name "*.json" -exec grep -l "ffuf\|status\|length" {} \;
find /tmp -name "*fuzz*" -o -name "results*" 2>/dev/null

# Search for recently-modified output files
find /home -type f \( -name "*.json" -o -name "*.csv" -o -name "*.html" \) -mtime -1

# Content check: does JSON contain web-fuzz results?
grep -l '"status".*"length".*"words"' /home/attacker/*.json 2>/dev/null
```

**Expected output:**
```
/home/attacker/results.json  (contains ffuf JSON schema)
/tmp/target_com_fuzz.csv     (recently modified)
```

**Forensic value:** **Extremely high** — Output files directly show which paths were discovered.

**Evasion resistance:** **Low** — If output files are saved, they're very strong indicators (require `-o` flag to create).

---

## Hunting on Target (Victim's Host)

### Access Log Analysis

**Objective:** Identify ffuf activity in web server logs.

```bash
# Search for ffuf User-Agent
grep -r "ffuf" /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access.log

# Alternatively, search for multiple requests to non-existent paths from single IP
grep -E '(admin|backup|config|api|test|upload)' /var/log/apache2/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn | awk '$1 > 50'
# Output: IPs with >50 requests to common fuzz-words

# Time-based burst detection: 100+ requests within 10 seconds
awk -F'[ []' '{print $4}' /var/log/apache2/access.log | \
  sort | uniq -c | awk '$1 > 100'
```

**Expected output:**
```
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /backup HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /api HTTP/1.1" 200 3240 "-" "ffuf/2.1.0"
```

**Evasion resistance:** **Very High** — Access logs are a mandatory part of web-server configuration and difficult to bypass (even with log rotation/purging, recent logs are usually available).

---

### Status Code Distribution Analysis

**Objective:** Identify abnormal HTTP response patterns.

```bash
# Analyze response codes per source IP
awk '{print $1, $(NF-1)}' /var/log/apache2/access.log | sort | uniq | \
  awk '{ip=$1; status=$2; count[ip][status]++} \
       END {for (ip in count) print ip, length(count[ip]), "unique statuses"}'

# Find IPs returning >90% 404s with 100+ total requests
awk '{print $1, $(NF-1)}' /var/log/apache2/access.log | \
  awk '{count[$1]++; if($2==404) notfound[$1]++} \
       END {for (ip in count) if (count[ip]>100 && notfound[ip]/count[ip]>0.9) \
            print ip, notfound[ip], "/", count[ip]}'
```

**Expected output:**
```
203.0.113.50 4950 / 5000  (99% 404 rate)
192.168.1.100 50 / 50     (100% 404 rate, smaller volume)
```

**Evasion resistance:** **High** — This pattern is inherent to ffuf's operation (overwhelming majority of paths don't exist).

---

### Rate-Limiter and WAF Alerts

**Objective:** Check WAF and rate-limiting logs.

```bash
# Check ModSecurity audit logs
grep -i "scanner\|brute.force\|directory.traversal" /var/log/apache2/modsec_audit.log

# Check Cloudflare WAF logs (if target is behind Cloudflare)
curl -s "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/events?filter=action=challenge&filter=action=block" \
  -H "Authorization: Bearer {api_token}" | jq '.result[] | select(.client.ip=="203.0.113.50")'

# Check rate-limiter logs (if implemented)
grep -E "429|503|rate.limit|too.many" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c
```

**Expected output:**
```
203.0.113.50 sent 5000 requests in 120 seconds (rate limited)
Challenge issued to 203.0.113.50 (suspicious scanner activity)
```

**Evasion resistance:** **Very High** (if WAF/rate-limiter is active) — The target-side triggering is unavoidable at scale.

---

### Firewall and IDS Alerts

**Objective:** Search network-level detection systems.

```bash
# Check Suricata/Snort IDS alerts
grep -r "ffuf\|Directory Brute Force\|Scanner" /var/log/suricata/eve.json | jq .

# Check iptables rate-limiting logs (if configured)
dmesg | grep "rate limit"

# Check fail2ban logs
grep "Ban\|Jail" /var/log/fail2ban.log
```

**Expected output:**
```
{"event_type":"alert","alert":{"action":"alert","gid":1,"signature_id":"2024028","rev":1,"signature":"ET SCAN Scanner Activity"}}
```

**Evasion resistance:** **Very High** — Network-level IDS/firewall detection is difficult to evade without custom headers/delays.

---

## Hunting Priority Rankings

### By Evasion Resistance (What Survives Evasion Attempts)

| Rank | Signal | Survives Custom User-Agent? | Survives Rate-Limiting Evasion? | Survives Delayed Requests? | Comments |
|---|---|---|---|---|---|
| **1** | Access log burst (200+ requests to unique paths) | ✓ Yes | ✗ No (spread over time) | ✗ No (defeats burst pattern) | Eliminated by `-t 1 -p 500` (1 thread, 500ms delay) |
| **2** | WAF alerts / Rate-limit 429 responses | ✓ Yes | ✗ No | ✗ No | Requires scale; evaded by slow fuzzing |
| **3** | Shell history / wordlist files | ✓ Yes | ✓ Yes | ✓ Yes | Strong if accessible; survives all runtime evasions |
| **4** | 404 response size fingerprinting | ✓ Yes | ✓ Yes | ✗ Sometimes (depends on filter strategy) | Survives delay; weak if target changes 404 pages |
| **5** | Output files (JSON/CSV) | ✓ Yes | ✓ Yes | ✓ Yes | Only present if `-o` flag used; very strong if found |
| **6** | User-Agent string (ffuf/2.1.0) | ✗ No | ✓ Yes | ✓ Yes | Trivially spoofed with `-H "User-Agent: ..."` |

---

## Detection Queries

### Splunk / ELK Queries

**Detecting ffuf User-Agent in access logs:**
```splunk
index=web_logs (http_user_agent="*ffuf*" OR http_user_agent="*ffuf/*")
| stats count by src_ip, http_user_agent
```

**Detecting rapid HTTP requests:**
```splunk
index=web_logs
| stats count as request_count by src_ip
| where request_count > 500 and _time < 10
| table src_ip, request_count
```

**Detecting high 404 rate:**
```splunk
index=web_logs
| stats count as total_reqs, sum(eval(if(status=404, 1, 0))) as not_found_count by src_ip
| eval pct_404=(not_found_count/total_reqs)*100
| where total_reqs > 100 and pct_404 > 90
```

---

### GreyLog / Sigma Rule

**YAML Sigma rule for ffuf detection:**
```yaml
title: Potential ffuf Web Fuzzing Activity
description: Detects possible ffuf directory/parameter fuzzing based on HTTP patterns
logsource:
  category: web_application_firewall
  product: generic_web_server
detection:
  selection_useragent:
    http.user_agent: '*ffuf*'
  selection_pattern:
    - http.request.uri: ['/admin', '/backup', '/config', '/api', '/login', '/test']
    - http.response.status: 404
    - source.ip: '*'  # Single source
  selection_burst:
    - 40+ unique request URIs per source IP within 60 seconds
  condition: selection_useragent OR (selection_pattern AND selection_burst)
severity: medium
```

---

## Remediation and Hardening

### Target-Side Mitigations

1. **Rate-limiting** — Implement aggressively (5–10 req/sec per IP, temporary 10-minute ban after threshold).
2. **Custom 404 pages** — Vary response size/content to defeat `-fs`/`-fw` filtering.
3. **Require authentication** — Sensitive paths require login; ffuf can't enumerate what requires auth.
4. **Log rotation** — Retain access logs for ≥90 days to detect post-incident.
5. **WAF rules** — Block requests with `ffuf` User-Agent; block high-rate path-fuzzing patterns.

### Source-Side (Attacker) Evasion

1. **Custom User-Agent:** `-H "User-Agent: Mozilla/5.0 ..."`
2. **Rate limiting:** `-t 1 -p 500` (1 thread, 500ms delay = ~2 requests/second)
3. **Proxy chaining:** Route through multiple proxies to distribute source IP.
4. **Wordlist modification:** Use smaller, targeted wordlists to reduce request volume.

