# Gobuster — Detection and Hunting

## Hunting on Source (Attacker's Host)

### Shell History Analysis

**Objective:** Identify gobuster invocations in command-line history.

```bash
# Search for gobuster in bash history
grep -r "gobuster" ~/.bash_history

# Search zsh history
grep "gobuster" ~/.zsh_history

# Search all users' shell histories
sudo grep -r "gobuster" /home/*/.*_history /root/.*_history 2>/dev/null

# Search for specific modes
grep -E "gobuster (dir|dns|vhost)" ~/.bash_history

# Search for gobuster with common wordlist paths
grep -E "gobuster.*(-w|--wordlist)" ~/.bash_history
```

**Expected output:**
```
gobuster dir -u https://target.com -w /usr/share/SecLists/Discovery/Web-Content/common.txt -sc 200
gobuster dns -d target.com -w /home/attacker/subdomains.txt -z
```

**Evasion resistance:** **Very High** — gobuster invocations in shell history are captured unless history is explicitly cleared.

---

### Wordlist and Output File Discovery

**Objective:** Locate wordlist and results files.

```bash
# Find wordlist files
find /home -name "*wordlist*" -o -name "*subdomains*" -o -name "*endpoints*" 2>/dev/null

# Find gobuster output files
find /home -name "*.txt" -exec grep -l "Status:" {} \; 2>/dev/null

# Find recently-modified wordlists
find /home -type f -name "*.txt" -mtime -7  # Modified within last 7 days

# Search for SecLists directories
find /home -name "SecLists" -type d 2>/dev/null

# Check for specific result filenames
ls -la /home/attacker/{results,dns-results,vhost-results}.txt 2>/dev/null
```

**Expected output:**
```
/home/attacker/wordlists/common-paths.txt
/home/attacker/results.txt (contains: https://target.com/admin (Status: 200))
/home/attacker/SecLists/Discovery/Web-Content/common.txt
```

**Evasion resistance:** **High** — Files persist unless actively deleted. Deleted files may be recoverable via file-system forensics.

---

### Process and Network State (Live)

**Objective:** Detect gobuster running in real-time.

```bash
# Check running gobuster processes
ps aux | grep gobuster
pgrep -a gobuster

# Monitor active network connections from gobuster
netstat -tpn | grep gobuster
ss -tpn | grep gobuster

# Monitor DNS queries from gobuster
tcpdump -i any 'udp port 53 and src 192.168.1.100' -n

# Count HTTP connections to a specific target
netstat -tpn | grep -c "203.0.113.50.*443"
```

**Expected output:**
```
attacker 12345 45.2 8.3 102400 524288 ?  Sl  14:32   2:15 gobuster dir -u https://target.com ...
tcp  0  0 192.168.1.100:54321 203.0.113.50:443 ESTABLISHED 12345/gobuster
udp  0  0 192.168.1.100:54321 8.8.8.8:53 ESTABLISHED 12345/gobuster
```

**Evasion resistance:** **Moderate** — Only detectable while running. Shell history survives process termination.

---

## Hunting on Target (Victim's Host)

### Access Log Analysis (HTTP modes: `dir`, `vhost`)

**Objective:** Identify gobuster activity via web server logs.

```bash
# Search for gobuster User-Agent
grep -r "gobuster" /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access.log

# Find rapid sequences of requests from single IP
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | awk '$1 > 100' | sort -rn

# Identify high-velocity path enumeration (100+ requests in 10 seconds)
awk -F'[ []' '{
  ip=$1; time=$4;
  count[ip,time]++;
}
END {
  for (key in count) if (count[key] > 100) print key, count[key]
}' /var/log/apache2/access.log

# Find 404 response bursts (>90% 404 rate)
awk '{
  ip=$1; status=$(NF-1);
  count[ip]++;
  if (status == 404) notfound[ip]++;
}
END {
  for (ip in count) {
    pct = (notfound[ip] / count[ip]) * 100;
    if (count[ip] > 100 && pct > 90) 
      print ip, pct"% 404s (" notfound[ip] "/" count[ip] ")"
  }
}' /var/log/apache2/access.log
```

**Expected output:**
```
gobuster/3.5.0 found in 500+ entries
203.0.113.50 9950 404s (99.5% 404 rate, 10,000 total requests)
```

**Evasion resistance:** **Very High** — Access logs are a mandatory component of web-server configuration.

---

### DNS Query Analysis (DNS mode)

**Objective:** Identify gobuster DNS subdomain enumeration via DNS logs.

```bash
# Search BIND query logs
grep "target.com" /var/log/bind/query.log | wc -l

# Identify burst DNS queries from single IP
awk '{
  client = substr($NF, 1, index($NF, "#") - 1);
  count[client]++;
}
END {
  for (ip in count) if (count[ip] > 500) print ip, count[ip], "queries"
}' /var/log/bind/query.log

# Find NXDOMAIN responses (non-existent subdomains)
grep "NXDOMAIN\|NODATA" /var/log/bind/query.log | \
  awk '{print $NF}' | sort | uniq -c | sort -rn | head -20

# Detect wildcard DNS probes (random subdomains)
grep -E '[a-z0-9]{8}\.target\.com' /var/log/bind/query.log
```

**Expected output:**
```
500+ queries for target.com subdomains from 203.0.113.50
Query: admin.target.com (NXDOMAIN)
Query: api.target.com (NXDOMAIN)
Query: abcd1234.target.com (NXDOMAIN, wildcard probe)
```

**Evasion resistance:** **Very High** — DNS logs are mandatory on DNS servers.

---

### WAF and Rate-Limiter Alerts

**Objective:** Search WAF and rate-limiting logs for gobuster detections.

```bash
# ModSecurity audit logs
grep -i "scanner\|brute.force\|rate.limit" /var/log/apache2/modsec_audit.log

# Check rate-limiter logs
grep -E "429|503|rate.limit" /var/log/apache2/access.log | \
  awk '{print $1}' | sort | uniq -c | sort -rn

# Cloudflare WAF logs (via API)
curl -s "https://api.cloudflare.com/client/v4/zones/{zone_id}/firewall/events" \
  -H "Authorization: Bearer {token}" | jq '.result[] | select(.action=="challenge")'

# Suricata/Snort alerts
grep -r "gobuster\|Directory Brute\|Scanner" /var/log/suricata/eve.json | jq .
```

**Expected output:**
```
ModSecurity Alert: Potential directory brute-force from 203.0.113.50
429 Too Many Requests: 203.0.113.50 sent 500+ requests in 50 seconds
Cloudflare: Challenge issued to 203.0.113.50 (scanner activity)
```

**Evasion resistance:** **Very High** (if WAF/rate-limiter active) — Detection is unavoidable at scale.

---

## Hunting Priority Rankings

### By Evasion Resistance

| Rank | Signal | Survives Custom User-Agent? | Survives Rate-Limiting Evasion? | Survives DNS Mode? | Comments |
|---|---|---|---|---|---|
| **1** | Shell history / Output files | ✓ Yes | ✓ Yes | ✓ Yes | Strongest; survives all runtime evasions |
| **2** | User-Agent (gobuster/3.5.0) | ✗ No | ✓ Yes | ✓ Yes | Trivially spoofed with `-U` flag; weak if evaded |
| **3** | Access log burst (HTTP modes) | ✓ Yes | ✗ No | N/A | Eliminated by `--delay` and reduced concurrency |
| **4** | DNS query burst (DNS mode) | ✓ Yes | ✗ No | ✓ Yes | Unavoidable in `dns` mode at scale; beaten by slow fuzzing |
| **5** | WAF/Rate-limit alerts | ✓ Yes | ✗ No | ✗ No | Requires scale; evaded by slow fuzzing |
| **6** | 404 rate fingerprint | ✓ Yes | ✓ Yes | ✗ No | HTTP-only; survives all HTTP-level evasions |

---

## Detection Queries and Rules

### Splunk / ELK

**Detecting gobuster User-Agent:**
```splunk
index=web_logs http_user_agent="*gobuster*"
| stats count by src_ip, http_user_agent
```

**Detecting HTTP request bursts:**
```splunk
index=web_logs
| stats count as request_count by src_ip, _time
| where request_count > 100 and _time < 10  # >100 requests in <10 seconds
| table src_ip, request_count, _time
```

**Detecting 404 rate anomalies:**
```splunk
index=web_logs
| stats count as total_reqs, sum(eval(if(status=404, 1, 0))) as not_found_count by src_ip
| eval pct_404=(not_found_count/total_reqs)*100
| where total_reqs > 500 and pct_404 > 90
```

### DNS Log Analysis (Splunk)

**Detecting DNS brute-force (gobuster `dns` mode):**
```splunk
index=dns
| stats count as query_count by src_ip, query_time
| where query_count > 500 and query_time < 60  # >500 queries in <60 seconds
```

---

### Sigma Rule

**YAML Sigma rule for gobuster detection:**
```yaml
title: Gobuster Web Fuzzing Activity Detection
description: Detects gobuster directory/DNS enumeration via HTTP patterns or DNS logs
logsource:
  category: web_application_firewall
  product: generic_web_server
detection:
  selection_useragent:
    http.user_agent: '*gobuster*'
  selection_burst:
    - 100+ unique HTTP request URIs per source IP within 60 seconds
    - http.response.status: 404
  selection_dns_burst:
    - 500+ DNS queries from single IP within 60 seconds
    - dns.response.code: NXDOMAIN
  condition: selection_useragent OR (selection_burst) OR (selection_dns_burst)
severity: medium
```

---

## Target-Side Remediations

1. **Rate-limiting** — Cap requests per IP (5–10 req/sec); temporary ban after threshold.
2. **Custom 404 pages** — Vary response size and content to reduce blind filtering.
3. **Authentication** — Sensitive paths require login; gobuster can't enumerate what requires auth.
4. **Log retention** — Retain access logs for ≥90 days to detect post-incident.
5. **WAF rules** — Block `gobuster` User-Agent; block high-rate path-fuzzing patterns.
6. **DNS hardening** — Limit DNS queries per IP; implement rate-limiting on DNS server.

---

## Source-Side (Attacker) Evasion

1. **Custom User-Agent:** `-U "Mozilla/5.0 ..."`
2. **Reduced concurrency:** `-t 1` (1 thread instead of 10)
3. **Added delay:** `--delay 1000` (1000ms = 1 second between requests)
4. **Slow combined:** `-t 1 --delay 1000` = ~1 request per second (very slow)
5. **Custom resolver (DNS mode):** `-r internal.dns.server:53` (use internal resolver)
6. **Output suppression:** `-o /dev/null` (discard results, reduce forensic trail)

---

## Comparison: gobuster vs. ffuf Detection Difficulty

| Aspect | gobuster | ffuf | Detectability | Notes |
|---|---|---|---|---|
| **Default User-Agent** | `gobuster/3.5.0` | `ffuf/2.1.0` | Equal | Both identifiable; both easily spoofed |
| **Default concurrency** | 10 threads | 40 threads | gobuster less obvious | ffuf's 40-thread default creates larger burst |
| **Status-code filtering** | Single match (`-sc`) | Flexible chains (`-mc, -fs, -fw, -fr`) | ffuf more sophisticated | ffuf's filters are more complex to detect |
| **Response-size filtering** | None built-in | `-fs` flag | ffuf leaves fingerprint | ffuf's uniform-size filtering is detectable |
| **DNS mode** | Dedicated (`dns` mode) | None (HTTP Host header only) | gobuster's DNS mode is distinctive | DNS burst is unambiguous indicator |
| **Output format** | Plain text | JSON (default) | Equal | Both leave result files if `-o` used |

**Bottom line:** gobuster's `dns` mode is more detectable than ffuf (dedicated DNS mode vs. Host-header fuzzing), but both are equally identifiable via User-Agent and burst patterns unless evasion flags are used.

