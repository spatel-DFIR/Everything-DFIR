# Gobuster — Target Evidence

## HTTP Access Logs (for `dir` and `vhost` modes)

### Web Server Access Logs

The primary evidence of gobuster's HTTP-based activity (`dir` and `vhost` modes) appears in web server logs:

```
# Apache access log (/var/log/apache2/access.log)
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "gobuster/3.5.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /api HTTP/1.1" 404 5242 "-" "gobuster/3.5.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /backup HTTP/1.1" 200 3240 "-" "gobuster/3.5.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /config HTTP/1.1" 200 1524 "-" "gobuster/3.5.0"

# Nginx access log (/var/log/nginx/access.log)
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "gobuster/3.5.0"

# IIS access log (W3C format, %SYSTEMROOT%\System32\LogFiles\W3SVC1\)
2026-08-12 14:32:45 203.0.113.50 GET /admin - 80 - HTTP/1.1 gobuster/3.5.0 - 404 5242 0
```

**Forensic characteristics:**
- **User-Agent:** `gobuster/3.x.x` (identifies the tool unambiguously, includes version)
- **Request pattern:** Sequential GET requests to various paths, typically 10–50 requests per second (default 10 threads)
- **Source IP:** All requests from a single source
- **Response variance:** Majority 404s (non-existent paths), interspersed with 200s/301s/403s
- **Timing:** Requests clustered within seconds (500+ requests in 10 seconds = 50 req/sec)

**Timeline correlation:** Access log timestamps allow precise timing of enumeration activity.

---

## HTTP Status Code Distribution

A typical gobuster `dir` run produces characteristic HTTP status patterns:

```
Total requests: 10,000
Response breakdown:
- 404 (Not Found): 9,900 (~99%)
- 200 (OK): 80 (~0.8%)
- 301 (Moved Permanently): 15
- 403 (Forbidden): 5
```

**Detection angle:** The overwhelming preponderance of 404s to random-seeming paths (rather than real user browsing) is a strong indicator of automated fuzzing.

---

## 404 Baseline Fingerprint

gobuster automatically establishes a 404-page baseline by requesting a path with random characters. This creates a specific artifact:

```bash
# Target server receives request for random path (gobuster's baseline probe)
[14:32:44] GET /<random-8-chars> HTTP/1.1 → 404, 5242 bytes

# Attacker's gobuster filter uses this baseline
# Subsequent requests matching this signature are silently filtered

# Access log shows baseline attempt:
203.0.113.50 - - [12/Aug/2026:14:32:44 +0000] "GET /abcd1234 HTTP/1.1" 404 5242 "-" "gobuster/3.5.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "gobuster/3.5.0"
```

**Forensic value:** A single random-path 404 followed by rapid sequential known-wordlist requests is a strong gobuster fingerprint.

---

## DNS Query Logs (for `dns` mode)

If the attacker uses gobuster's `dns` mode, the target's DNS server (or a forwarder) logs queries:

```
# DNS query log (BIND format)
12-Aug-2026 14:32:45.123 queries: client 203.0.113.50#54321 (admin.target.com): query: admin.target.com A +E (203.0.113.50)
12-Aug-2026 14:32:45.125 queries: client 203.0.113.50#54321 (api.target.com): query: api.target.com A +E (203.0.113.50)
12-Aug-2026 14:32:45.127 queries: client 203.0.113.50#54321 (backup.target.com): query: backup.target.com A +E (203.0.113.50)
```

**Characteristics:**
- **Burst pattern:** 50–100+ queries per second from single IP (depending on `-t` concurrency)
- **Timing:** Rapid-fire queries clustered in seconds
- **Wildcard queries:** If `-z` (wildcard detection) is used, `<random>.target.com` queries appear
- **NXDOMAIN responses:** Majority of responses are NXDOMAIN (no such domain)

**Forensic value:** DNS logs directly reveal which subdomains were probed, even if they don't exist.

---

## Wildcard DNS Fingerprint (from `-z` flag)

If gobuster was run with the `-z` (wildcard detection) flag:

```bash
# gobuster dns -d target.com -w subdomains.txt -z

# DNS queries include a wildcard probe
12-Aug-2026 14:32:44.001 queries: client 203.0.113.50#54321 (abcd1234.target.com): query: abcd1234.target.com A +E (203.0.113.50)
# This random-subdomain probe is logged FIRST
```

**Forensic value:** The appearance of random-subdomain queries (e.g., `abcd1234.target.com` NXDOMAIN) followed by known-wordlist queries is a gobuster `-z` wildcard-detection fingerprint.

---

## Rate-Limiting Reactions

### Target Defense Mechanisms

If the target has rate-limiting enabled:

```
# Attacker runs gobuster with default 10 threads
gobuster dir -u https://target.com -w wordlist.txt

# Target rate-limiter reacts after 500 requests (50 seconds at 10 req/sec)
[14:32:45] Requests 1-500: Status 200, 404, 301, 403 (normal)
[14:32:50] Requests 501+: All status 429 (Too Many Requests)
[14:32:55] Status 503 (Service Unavailable) or connection resets

# Access log cliff:
203.0.113.50 - - [12/Aug/2026:14:32:50 +0000] "GET /path501 HTTP/1.1" 429 ...
203.0.113.50 - - [12/Aug/2026:14:32:50 +0000] "GET /path502 HTTP/1.1" 429 ...
```

**Forensic value:** The timing of the 429/503 cliff reveals when automated scanning exceeded rate limits (specific fingerprint of gobuster vs. human browsing).

---

## WAF and IDS Alerts

### Web Application Firewall Signatures

WAF products flag gobuster activity:

```
# ModSecurity rule match
Rule ID: 930100 - Potential Directory Brute-Force Attack
Evidence: 30+ requests in 3 seconds to non-existent paths, single source IP, User-Agent: gobuster/3.5.0

# Cloudflare WAF
Alert: Suspected Scanner/Bot Activity
Action: CAPTCHA challenge or IP throttling

# Custom WAF patterns
Alert: High-velocity path fuzzing (40+ unique paths in 10 seconds)
Pattern: /admin, /api, /backup, /config, etc., all 404
```

**Artifacts:**
- WAF logs (if accessible)
- IDS/IPS alerts (Suricata, Snort)
- Bot-management platform detections

---

## Connection-Level Indicators

### TCP/IP Behavior Patterns

The target's network stack observes:

```
# Connection pattern during gobuster dns mode (10 concurrent queries)
- Source: 203.0.113.50
- Destination: DNS server (port 53)
- Pattern: 100+ UDP packets in 10 seconds to port 53
- Packet size: ~50–100 bytes (typical DNS query size)

# Connection pattern during gobuster dir mode (10 threads)
- Source: 203.0.113.50
- Destination: 192.0.2.1:443 (target web server)
- Pattern: 10 concurrent TCP connections, each sends 1 HTTP request, waits for response, closes
- Timing: New connection every ~100ms (10 threads × 10 requests/sec = 100ms per thread)
```

**Indicators:**
- **Burst DNS queries:** 50+ UDP packets to port 53 in <5 seconds from single IP
- **Rapid HTTP connections:** 10+ TCP connections to port 80/443 in rapid succession from single IP
- **Asymmetric traffic:** Many small requests, varied response sizes (404s are uniform size; 200s vary)

---

## Application-Level Logs

If the target application logs HTTP requests:

```python
# Flask/Python application log
[2026-08-12 14:32:45] GET /admin - 404 - 45ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /api - 404 - 42ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /backup - 200 - 124ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /config - 200 - 118ms (from 203.0.113.50)
```

**Detection:** Application logs capture User-Agent (`gobuster/3.5.0`) and request patterns.

---

## Timeline Analysis: Attack Walkthrough (HTTP `dir` mode)

```
14:32:44 - [Access Log] First GET / HTTP/1.1 (baseline 404 probe) from 203.0.113.50, "gobuster/3.5.0"
14:32:44 - [WAF] Alert: Scanner activity detected (high-rate HTTP requests from single IP)
14:32:45 - [Access Log] 100 GET requests to paths (admin, api, backup, ...), all 404, size 5242 bytes
14:32:46 - [Rate-Limiter] Threshold exceeded (~500 requests in 2 seconds)
14:32:46 - [Access Log] Status 429 returned for request 501+
14:32:47 - [Attacker adjusts] Adds --delay 100 (100ms between requests)
14:32:50 - [Access Log] Request rate drops to ~10 req/sec
14:35:00 - [Access Log] Last GET to discovered resource (/backup HTTP/1.1, 200)
14:35:00 - [Complete] Attack ends
```

---

## Summary: Strongest Target-Side Signals

**Tier 1 (Definitive):**
1. **User-Agent string:** `gobuster/3.x.x` in access logs (unambiguous identifier).
2. **Access log burst:** 500+ requests from single IP within 10 seconds, all to unique paths, mix of 404/200.
3. **404 rate:** >90% of requests return 404 (characteristic of fuzzing vs. legitimate browsing).

**Tier 2:**
4. **DNS query burst:** (if `dns` mode) 50+ queries in <5 seconds to non-existent subdomains.
5. **Rate-limiter activation:** 429/503 responses following normal traffic (cliff pattern).
6. **WAF alerts:** Suspected scanner/bot detection rules triggered.

**Tier 3:**
7. **Connection pattern:** Multiple rapid TCP/UDP connections from single IP.
8. **Random-path baseline probe:** Single request to `/<8-random>` followed by wordlist enumeration.

