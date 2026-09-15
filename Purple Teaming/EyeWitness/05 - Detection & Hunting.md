# EyeWitness: Detection & Hunting

## Detection Framework

Detecting EyeWitness reconnaissance requires a layered approach across web logs, network traffic, endpoint behavior, and system artifacts. This guide covers proactive hunting signatures and response procedures.

---

## Web Application Log Signatures

### Signature 1: HeadlessChrome + Rapid Sequential Requests

**Pattern:** Single source IP makes 50+ requests within 60 seconds, all with HeadlessChrome User-Agent.

**SIEM Rule (Pseudocode):**
```
User-Agent CONTAINS "HeadlessChrome"
  AND request_count > 50
  AND time_window = 60s
  AND distinct_paths > 30
  THEN alert
```

**False Positives:** Legitimate headless browser automation (Selenium tests, Chrome Extensions). Requires whitelist of known CI/CD IPs.

**Confidence:** HIGH (70–90%)

---

### Signature 2: Favicon + Robots.txt + Sitemap.xml Probing

**Pattern:** Three "404 Not Found" requests for common reconnaissance files from single IP within 3 seconds.

**Regex Pattern:**
```
(favicon\.ico|robots\.txt|sitemap\.xml|wp-admin|\.env|config\.php|web\.config).*404
```

**Log Entry Example:**
```
192.0.2.100 GET /favicon.ico 404
192.0.2.100 GET /robots.txt 404
192.0.2.100 GET /sitemap.xml 404
```

**False Positives:** Standard browser behavior; mitigated by combining with User-Agent or request clustering.

**Confidence:** MEDIUM (50–70%) as standalone; HIGH if paired with HeadlessChrome

---

### Signature 3: Rapid Port Enumeration (Web Logs)

**Pattern:** Same source IP connects to 5+ non-standard web ports (8080, 8443, 9000, 5000, 3000) within 30 seconds.

**Detection Query:**
```
src_ip = X.X.X.X
  AND dest_port IN (8080, 8443, 9000, 5000, 3000, 8888)
  AND time_window = 30s
  THEN tally port_count
```

**False Positives:** Internal security scanners, penetration testers, load balancer health checks.

**Confidence:** MEDIUM-HIGH (65–85%) with context (e.g., repeated across multiple targets)

---

## Network Detection

### Signature 4: TLS Handshake Burst without Data Transfer

**Indicator:** Firewall sees multiple TLS CONNECT attempts from single IP, each completing handshake but transmitting <1 KB of application data (screenshot capture timing out or fast).

**Network Signature:**
```
Protocol: TLS/SSL
Source: X.X.X.X
Destinations: multiple (10+)
Duration: <5 seconds per connection
Data Transferred: <1 KB
Time Cluster: <60 seconds
```

**Tool:** Zeek/Suricata can flag this as bot fingerprinting or CVSS automated scanning.

**Confidence:** MEDIUM-HIGH (60–80%)

---

### Signature 5: DNS Burst + Web Requests Correlation

**Pattern:** Spike in DNS A-record lookups from single IP correlated with HTTP requests to same domains within 5 seconds.

**Hunt Query (DNS + HTTP Logs):**
```
dns_query.src_ip = http_request.src_ip
  AND dns_query.domain = http_request.host
  AND TIME(http_request) - TIME(dns_query) < 5s
  THEN stats count by src_ip
```

**Example Timeline:**
```
14:23:40 DNS Query: app1.target.com → 192.168.1.10
14:23:41 HTTP GET http://192.168.1.10/ User-Agent: HeadlessChrome
14:23:42 DNS Query: app2.target.com → 192.168.1.11
14:23:43 HTTP GET http://192.168.1.11/ User-Agent: HeadlessChrome
```

**Confidence:** HIGH (75–90%)

---

## Endpoint Indicators

### Signature 6: EyeWitness Process Execution

**Process Name:** `python3` or `python.exe`

**Command Line Contains:**
```
EyeWitness.py
-f targets.txt
-x scan.xml
--web
--threads
```

**Detection (EDR/SIEM):**
```
process.name = "python*"
  AND process.command_line CONTAINS ("EyeWitness" OR "eyewitness")
  THEN alert with severity: MEDIUM
```

**False Positives:** Legitimate penetration testers (authorized by IR team).

**Confidence:** VERY HIGH (95%+) if EyeWitness is not part of authorized toolset

---

### Signature 7: Report Directory Creation

**Files Created:**
```
*EyeWitness-Results-[timestamp]/
├── index.html
├── report.csv
├── screenshots/ (many .png files)
├── source/ (many .html files)
└── log.txt
```

**Detection (File Integrity Monitoring / FIM):**
```
New directory CONTAINS "EyeWitness-Results"
  AND (index.html EXISTS
       AND report.csv EXISTS
       AND count(*.png) > 20)
  THEN alert
```

**Filesystem Locations (Context):**
- Windows: `C:\Users\[User]\AppData\Local\Temp\`, `C:\Users\[User]\Desktop\`
- Linux: `/tmp/`, `/home/[user]/reports/`, `/root/`

**Confidence:** VERY HIGH (90%+) if discovered on compromised system

---

### Signature 8: Browser Cache Artifacts

**Forensic Artifacts:** Temporary PNG/HTML files in browser cache (Chrome, Firefox, Edge) with rapid sequential timestamps.

**Browser Cache Locations:**
- Windows: `%APPDATA%\Local\Google\Chrome\User Data\Default\Cache`
- Linux: `~/.cache/google-chrome/Default/Cache`

**Indicator:** 100+ files added within 2-minute window, all image/HTML MIME types, no user-initiated browsing (check history).

**Confidence:** HIGH (70–85%) if combined with process execution detection

---

## Threat Hunting Workflows

### Hunt 1: Identify Compromised Workstations Running Reconnaissance

**Steps:**
1. Query EDR logs for `python.exe`/`python3` process execution
2. Filter command line for `--web`, `-f`, `-x` flags
3. Correlate with network outbound connections (large data transfers to external IPs)
4. Review timeline: when was Python installed? Is it standard for that user role?
5. Acquire host and carve `/tmp/` or `%APPDATA%\Local\Temp\` for EyeWitness reports

**Key Questions:**
- Is the user supposed to be running penetration testing tools?
- What network ranges/IP addresses are in the targets file?
- Are targets internal infrastructure, external, or both?

---

### Hunt 2: Identify External Reconnaissance Against Your Infrastructure

**Steps:**
1. Query web server logs for `HeadlessChrome` User-Agent
2. Aggregate by `src_ip`; filter for count > 20 requests per IP in 24h
3. Cross-reference firewall logs: is this IP on allowlist? (Likely no = adversary)
4. Check if requests follow pattern (ports 80, 443, 8080, 8443 in sequence)
5. Contact incident response: is IP affiliated with authorized security assessment?

**Key Questions:**
- Are requests coming from outside your network (WAN) or inside (LAN)?
- Do logs show failed login attempts correlated with EyeWitness requests?
- Did requests precede any malicious events (exploitation, data exfil)?

**Response Actions:**
- Block IP at firewall/WAF
- Review compromised application logs for account creation or data access during reconnaissance window
- Assume compromise if reconnaissance preceded unauthorized activity

---

### Hunt 3: Identify Internal Lateral Reconnaissance

**Steps:**
1. Query web server logs for non-user agents (HeadlessChrome, curl, wget) accessing internal administrative interfaces
2. Correlate with source IP: is this a standard user workstation or known attacker pivot?
3. Check network logs for large outbound data transfer from reconnaissance host (exfiltration of reports)
4. Timeline: when did user/system last authenticate to web applications? Compare with reconnaissance timing.

**Key Questions:**
- Can you trace the reconnaissance source IP to a specific employee/system?
- Does the attacker's targeted applications match their normal access patterns?
- Were there failed login attempts in application logs during reconnaissance?

---

## Response & Containment

### Immediate Actions (Tier 1)

1. **Isolate the reconnaissance source IP** (network segment or block at core firewall)
2. **Preserve logs:** Copy web server access logs, firewall logs for past 48 hours to evidence repository
3. **Preserve host:** If detected on endpoint, isolate host from network; do not shut down (preserve volatile memory and temp files)

### Investigation (Tier 2)

1. **Acquire forensic image** of compromised workstation
2. **Parse browser cache** for EyeWitness artifacts
3. **Review user activity logs** (logon times, process execution history)
4. **Correlate reconnaissance targets** with business criticality; identify likely attack vectors

### Long-Term Detection (Tier 3)

1. **Deploy YARA rules** for EyeWitness binary/Python script detection on endpoints
2. **Update WAF** to block HeadlessChrome User-Agent (if not critical for legitimate services)
3. **Implement EDR alerting** for Python process spawning with reconnaissance-like command lines
4. **Enable HTTP header inspection** to flag rapid multi-port scanning patterns

---

## Detection Blind Spots & Mitigations

| Blind Spot | Cause | Mitigation |
|-----------|-------|-----------|
| **HTTPS Proxy Tunnel** | Attacker routes through corporate proxy; logs encrypted | Monitor proxy logs for large data volumes; block HeadlessChrome at proxy level |
| **Default Python Installation** | Attacker runs EyeWitness on macOS/Linux where Python is standard | Whitelist known legitimate Python scripts; alert on unfamiliar Python processes |
| **Report Deletion** | Attacker deletes temp files after exfiltration | Monitor `/tmp/` directory changes; use FIM to alert on large file deletions |
| **Custom User-Agent** | Attacker modifies EyeWitness User-Agent string | Monitor for any headless browser indicators (e.g., "Headless", absence of typical browser plugins) |
| **Slow Scanning** | Attacker throttles --threads to 1–2 to evade rate-based detection | Implement long-term baseline; alert on anomalous outbound connection patterns per IP |

