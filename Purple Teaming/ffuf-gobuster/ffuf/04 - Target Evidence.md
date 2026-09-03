# ffuf — Target Evidence

## HTTP Access Logs

### Web Server Access Logs

The primary evidence of ffuf activity on the target is the web server's HTTP access log:

```
# Apache access log (/var/log/apache2/access.log)
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /api HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /backup HTTP/1.1" 200 3240 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:46 +0000] "GET /config HTTP/1.1" 200 1524 "-" "ffuf/2.1.0"

# Nginx access log (/var/log/nginx/access.log)
203.0.113.50 - - [12/Aug/2026:14:32:45 +0000] "GET /admin HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"

# IIS access log (W3C format, %SYSTEMROOT%\System32\LogFiles\W3SVC1\)
2026-08-12 14:32:45 203.0.113.50 GET /admin - 80 - HTTP/1.1 ffuf/2.1.0 - 404 5242 0
2026-08-12 14:32:45 203.0.113.50 GET /backup - 80 - HTTP/1.1 ffuf/2.1.0 - 200 3240 0
```

**Forensic characteristics:**
- **User-Agent:** `ffuf/2.1.0` or similar version string (identifies the tool unambiguously).
- **Request pattern:** Rapid sequence of GET requests to a variety of path names (hundreds to thousands in quick succession).
- **Source IP:** All requests from a single source IP.
- **Response variance:** Mix of 404s (non-existent paths) and 200s (discovered resources).
- **Timing:** Clustered requests within seconds (40+ requests per second at default concurrency).

**Timeline correlation:** Access log entries include timestamps; clustering of 50–100 requests within a 5-second window is a strong indicator of automated fuzzing.

---

## HTTP Status Codes and Response Fingerprinting

### Status Code Distribution

A typical ffuf run produces a characteristic distribution:

```
Total requests: 50,000
Responses by status:
- 404 (Not Found): 49,500 (~99%)
- 200 (OK): 450 (~0.9%)
- 301 (Moved Permanently): 30
- 403 (Forbidden): 20
```

**Detection angle:** The overwhelming majority of 404s from a single source, interspersed with occasional 200s, is anomalous. Legitimate browsing produces a mix heavily skewed toward 200s.

### Response Size Fingerprinting

ffuf's `-fs` (filter-size) option relies on 404 pages having a consistent size. Once the 404 baseline is established, all responses of that size are filtered out. This creates a **specific artifact on the target side:**

1. If the target has a **custom 404 page** (e.g., 5,242 bytes):
   - ffuf sees this baseline and filters it out.
   - The access log shows 5,000+ requests, but most are 404s the attacker filtered.
   - Blue team sees a burst of 404s of uniform size.

2. If the target has **dynamic 404 pages** (each 404 is different):
   - ffuf can't establish a stable baseline.
   - More false positives occur.
   - The attacker may adjust filters mid-run.

**Forensic value:** A burst of requests with identical response sizes (all 5,242 bytes) indicates an attacker is using ffuf's size-based filtering.

---

## Network-Level Indicators

### TCP/IP Behavior

While ffuf is running, the target observes:

```
# Inbound connection pattern
- Source: Single IP (203.0.113.50)
- Destination port: 80 or 443
- Timing: 40+ connections per second (default `-t 40`)
- Connection state: Many in ESTABLISHED, then transition to TIME-WAIT
- Bytes sent per connection: Small (HTTP request ~500 bytes)
- Bytes received per connection: Variable (404 responses ~5,242 bytes; 200 responses ~4,000 bytes)
```

**Indicators:**
- **Connection velocity:** 40+ TLS handshakes/second from a single IP is anomalous.
- **Termination pattern:** Rapid connection teardowns (FIN/RST) after receiving responses.
- **No keepalive:** ffuf by default does NOT reuse connections across requests (each request opens a new socket).

**Packet-level signature:**
```
TLS Client Hello → TLS Server Hello/Cert/Key Exchange → TLS Finished
  (TLS handshake: ~5-10 milliseconds per connection)
GET /admin → GET /backup → GET /config
  (HTTP requests on newly established connections, <1 ms apart)
FIN/ACK → RST
  (Connection teardown)
```

---

## Rate-Limiting Reactions

### Target Defense Mechanisms

Modern targets implement rate-limiting. ffuf's unconstrained default triggers it:

```
# Attacker runs ffuf at default concurrency
ffuf -u https://target.com/FUZZ -w wordlist.txt  # 40 threads, ~40 req/sec

# Target rate-limiter reacts after ~500 requests (5 seconds of burst)
# Response 1-500: Mix of 200s, 404s
# Response 501+: All 429 (Too Many Requests) or 503 (Service Unavailable)
# Target-side behavior: Connection resets, timeout delays, IP throttling

# Access log shows the cliff:
[14:32:45] Request 1-500: Status 200, 404, 301 (normal)
[14:32:50] Request 501+: Status 429, 429, 429, ... (rate limit triggered)
```

**Forensic value:** The timing of the 429/503 cliff reveals when ffuf's concurrency exceeded the target's threshold. This is a **specific fingerprint of automated scanning.**

---

## WAF/IDS Alerts

### Web Application Firewall Signatures

WAF products (ModSecurity, Cloudflare, AWS WAF, Imperva) flag ffuf activity:

```
# ModSecurity rule match (OWASP CRS 3.3.2)
Rule ID: 930100 "HTTP Request Smuggling Attack"
Alert: Potential directory traversal or brute-force scanning detected
Evidence: 40+ requests per second from 203.0.113.50, path-like patterns

# Cloudflare WAF
Challenge issued to 203.0.113.50
Reason: Suspected Scanner Activity
Action: CAPTCHA challenge (if not automated); block if bot-score too low

# Custom WAF patterns (specific to target)
Alert: Rapid 404s followed by 200 on variant paths
Pattern: /RANDOM1, /RANDOM2, /RANDOM3, ... /admin (200), /backup (200)
```

**Artifacts:**
- WAF logs (if accessible)
- IDS/IPS alerts (Suricata, Snort)
- Bot-management platform scores (Cloudflare Bot Score, Imperva Incapsula)

---

## Prefetch and Caching Artifacts

### Browser Cache (if target is accessed via browser)

Not applicable to ffuf (it's a command-line tool, not a browser). However, if an analyst views discovered resources in a browser afterward, browser artifacts accumulate.

---

## Application-Level Logs

### Web Application Logs

If the target has application-level logging (e.g., Python Flask, Node.js Express, Java):

```python
# Flask application log
[2026-08-12 14:32:45] GET /admin - 404 - 45ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /api - 404 - 42ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /backup - 200 - 124ms (from 203.0.113.50)
[2026-08-12 14:32:45] GET /config - 200 - 118ms (from 203.0.113.50)
...
```

**Detection:** Application logs often capture request headers (User-Agent, Host header modifications). The `ffuf/[VERSION]` User-Agent is a direct identifier.

---

## DNS Queries (for VHOST/Subdomain Fuzzing)

If the attacker fuzzes via Host header (e.g., `-H "Host: FUZZ.target.com"`):

### DNS Recursive Query Pattern

```
# Target's DNS server (if the attacker resolves subdomains)
Query: admin.target.com (A record)
Query: api.target.com (A record)
Query: backup.target.com (A record)
...
Query: xyzabc.target.com (A record)
```

**Forensic value:** DNS query logs show the attacker probed for specific subdomains. Even if no DNS results were returned (NXDOMAIN), the attempt is logged.

**Caveat:** If the attacker uses `-H "Host: FUZZ.target.com"` **without** resolving the domain (e.g., target's IP is 192.168.1.100, attacker sends Host header directly to the IP), then **no DNS queries occur** on the target side.

---

## Timeline Analysis: Attack Walkthrough

**Scenario:** ffuf fuzzes `target.com` for directories and file extensions.

```
14:32:45 - [Access Log] First GET /admin HTTP/1.1 from 203.0.113.50, 404, ffuf/2.1.0
14:32:45 - [WAF] Alert: Potential scanner activity (40+ req/sec from single IP)
14:32:45 - [IDS] Alert: High-rate HTTP requests, possible DoS/scanning
14:32:46 - [Access Log] 500 requests logged in 1 second (all 404, mostly)
14:32:47 - [Rate-Limiter] Threshold exceeded (1000 requests in 2 seconds)
14:32:47 - [Access Log] Status 429 returned for request 501+
14:32:50 - [Attacker adjusts] Reduces concurrency: -t 10 -p 100 (delays by 100ms per request)
14:32:50 - [Access Log] Request rate drops to ~10 req/sec, 429s drop, mix of 404/200 resumes
14:35:00 - [Access Log] Last GET /backup.php HTTP/1.1, 200 response
14:35:00 - [Complete] ffuf exits; attack ends
```

---

## Summary: Strongest Target-Side Signals

**Tier 1 (Definitive):**
1. **Access log burst:** 200+ requests from single IP within 10 seconds, all to unique paths, mixed 404/200 statuses.
2. **User-Agent:** `ffuf/[VERSION]` string in access logs (unambiguous identifier).
3. **Rate-limiter activation:** Sudden 429/503 responses to single IP, preceding access-log cliff.

**Tier 2:**
4. **WAF alerts:** Suspicious scanner detection rules triggered.
5. **Response size fingerprinting:** Consistent 404 sizes filtered out by attacker.
6. **IDS/IPS alerts:** High-rate connection pattern, port-scanning signature.

**Tier 3:**
7. **DNS query pattern:** (if VHOST/subdomain fuzzing with resolution).
8. **Application-level logs:** `ffuf/2.1.0` in User-Agent field.

