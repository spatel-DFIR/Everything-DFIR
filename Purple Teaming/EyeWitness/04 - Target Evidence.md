# EyeWitness: Target Evidence

## Artifacts Left on Target Systems / Web Servers

When EyeWitness reconnaissance is performed against web applications, specific traces are left in logs, network traffic, and server state. This evidence is discoverable through web log analysis, firewall logs, and network detection systems.

---

## HTTP/HTTPS Access Logs

### Web Server Log Entries (Apache/Nginx/IIS)

**Apache (access.log):**
```
192.0.2.100 - - [29/Aug/2024:14:23:45 +0000] "GET / HTTP/1.1" 200 5432 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
192.0.2.100 - - [29/Aug/2024:14:23:46 +0000] "GET /favicon.ico HTTP/1.1" 404 612 "http://target.com/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
192.0.2.100 - - [29/Aug/2024:14:23:47 +0000] "GET /robots.txt HTTP/1.1" 404 612 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36"
```

**Key Indicators:**
- **User-Agent:** `HeadlessChrome`, `Chrome/[version] Safari` (headless browser signature)
- **Favicon/Robots.txt Requests:** Automated scanning behavior (humans rarely request both in sequence)
- **No Referer:** Requests with no referer header or synthetic referer patterns
- **Rapid Sequential Requests:** Multiple requests within 1-2 seconds from single IP
- **Request Pattern:** Follows common reconnaissance sequence: `/`, `/admin`, `/api`, `/config`, etc.

**IIS (LogFiles directory):**
```
2024-08-29 14:23:45 192.0.2.100 GET / - 80 - Mozilla/5.0+(X11;+Linux+x86_64)+AppleWebKit/537.36 200 0 0 1205
```

---

## Network-Level Indicators

### TLS/SSL Handshake Patterns

**Behavioral Signature:**
- **Certificate Enumeration:** EyeWitness tests HTTPS on multiple ports (443, 8443, 8080-8090) sequentially
- **No Client Certificates:** Most EyeWitness runs do not present client certificates (unless explicitly configured)
- **Default TLS Versions:** Often uses TLS 1.2/1.3; older versions may indicate legacy EyeWitness or proxy
- **No SNI Variations:** EyeWitness sends consistent SNI hostname; lack of rotation indicates automated tool

**Detection:** Firewall/IDS rules can flag rapid TLS handshakes from single source without data transfer (no full HTTP request).

### DNS Queries

**Pattern:**
```
192.0.2.100 → DNS Query for target1.com (A record)
192.0.2.100 → DNS Query for target2.com (A record)
192.0.2.100 → DNS Query for target3.com (A record)
[repeated x100+ in short timespan]
```

**Indicator:** Burst of forward DNS lookups from single IP (especially with sequential subdomain queries) suggests automated reconnaissance tool.

---

## HTTP Response Header Analysis

### Server Detection via Headers

**Passive Information Leakage:**
```
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
X-AspNet-Version: 4.0.30319
X-Powered-By: JSP/2.2
Date: Wed, 29 Aug 2024 14:23:45 GMT
```

**Forensic Significance:**
- EyeWitness captures these headers; presence in report.csv confirms server version was fingerprinted
- Multiple requests from same IP harvesting server headers indicates reconnaissance
- Absence of expected headers (stripped by WAF/reverse proxy) visible in logs

---

## WAF/Load Balancer Logs

### Rate Limiting & Blocking

**ModSecurity/WAF Logs:**
```
[id "910101"] [msg "HTTP Header Injection Attack"] [data "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko) HeadlessChrome/120.0.0.0"]
[rule matched] [client IP: 192.0.2.100] [uri: "/"] [timestamp: 2024-08-29T14:23:45Z]

[Rule Triggered: Multiple Requests in Short Time] [Client IP: 192.0.2.100] [Requests: 87] [Time Window: 30s]
```

**Detection Indicators:**
- **HeadlessChrome Detection:** WAF rules can flag this User-Agent as bot/scanner
- **Rate Spike:** Sudden surge of requests from single IP (EyeWitness --threads flag)
- **Reconnaissance Patterns:** Sequential scanning of known paths (/admin, /config, /backup)

---

## Application-Level Evidence

### Session Logs & Database Audit Trails

**Login Failures (if credentials attempted):**
```
[2024-08-29 14:23:50] Failed login attempt for user 'admin' from 192.0.2.100
[2024-08-29 14:23:51] Failed login attempt for user 'root' from 192.0.2.100
[2024-08-29 14:23:52] Account lockout triggered: admin (192.0.2.100)
```

**API Request Logs:**
```
POST /api/v1/auth HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36
Authorization: Basic YWRtaW46YWRtaW4=  [base64: admin:admin default credential attempt]
```

---

## Timing & Correlation Evidence

### Temporal Clustering

| Source IP | Time Cluster | Request Count | Ports Scanned | Likely Activity |
|-----------|--------------|----------------|---------------|-----------------|
| 192.0.2.100 | 14:23:40–14:25:12 | 432 | 80,443,8080,8443,9000,5000 | EyeWitness CIDR scan |
| 192.0.2.100 | 14:25:15–14:26:30 | 87 | 443 | HTTPS enumeration |
| 192.0.2.100 | 14:30:00–15:15:00 | 1 | 80 | Follow-up verification |

**Analysis:** Rapid burst (time cluster 1) followed by refinement (cluster 2) followed by verification (cluster 3) = high-confidence reconnaissance.

---

## Data Exfiltration Indicators

### HTTPS Tunnel Usage

**Scenario:** Attacker routes EyeWitness through HTTPS proxy to hide reconnaissance from inspection.

**Observable Signs:**
- **TLS Tunnel Establishment:** Persistent CONNECT tunnel to external proxy (detectable in firewall logs)
- **Envelope Size Anomalies:** Encrypted traffic carries EyeWitness report (binary PNG data) and CSV files (~1–50 MB exfiltration)
- **No HTTP POST:** Unusual absence of POST requests to external destinations (attacker avoids logging)

**Detection:** Monitor for large outbound encrypted traffic from internal reconnaissance scanning host.

---

## Analyst Hunt Queries

### Splunk / ELK Query Examples

**Find HeadlessChrome Requests (Web Logs):**
```
sourcetype=access_logs user_agent=*HeadlessChrome* | stats count by src_ip, dest_host | where count > 50
```

**Detect Rapid Port Scanning Behavior (Firewall Logs):**
```
sourcetype=firewall action=allow proto=tcp src_ip=* dest_port IN (80,443,8080,8443,9000) | stats dc(dest_port) as ports by src_ip | where ports > 5
```

**Identify Favicon Scraping Pattern (Web Logs):**
```
sourcetype=access_logs uri=/favicon.ico user_agent=*HeadlessChrome* | stats count by src_ip
```

