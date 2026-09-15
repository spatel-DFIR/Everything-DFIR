# Nikto — Target Evidence

## Web Server Access Logs

**Locations (typical):**
- Apache: `/var/log/apache2/access.log`, `/var/log/apache2/other_vhosts_access.log`
- Nginx: `/var/log/nginx/access.log`
- IIS: `C:\inetpub\logs\LogFiles\W3SVC1\` (one file per day)
- Apache on Windows (WAMPServer): `C:\wamp64\logs\apache_access.log`

### Log Format and Nikto Signature

**Apache Common Log Format:**
```
192.168.1.101 - - [12/Aug/2026:14:30:15 +0000] "GET / HTTP/1.1" 200 234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.101 - - [12/Aug/2026:14:30:15 +0000] "HEAD /admin/ HTTP/1.0" 404 0 "-" "Mozilla/5.0 (X11; Linux x86_64)"
192.168.1.101 - - [12/Aug/2026:14:30:16 +0000] "GET /.env HTTP/1.1" 200 145 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X)"
192.168.1.101 - - [12/Aug/2026:14:30:16 +0000] "GET /backup/ HTTP/1.1" 404 512 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.101 - - [12/Aug/2026:14:30:17 +0000] "OPTIONS / HTTP/1.0" 200 0 "-" "Mozilla/5.0 (X11; Linux x86_64)"
192.168.1.101 - - [12/Aug/2026:14:30:17 +0000] "GET /wp-login.php HTTP/1.0" 200 1234 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS)"
```

### Nikto-Specific Log Signatures

**Distinctive patterns:**

| Pattern | What it indicates |
|---|---|
| **Rapid sequential requests from one IP** | Multiple requests (50–500+) within seconds/minutes from a single source IP |
| **Mixed HTTP methods** (GET, HEAD, OPTIONS) | Nikto tests multiple HTTP methods; normal browsing is mostly GET/POST |
| **Requests to obviously non-existent paths** | `/admin/`, `/backup/`, `/.env`, `/.git/`, `/config.php` — paths Nikto probes regardless of app type |
| **Requests with varied User-Agents** | Each request may have a different User-Agent (db_useragents rotation), unless `-useragent custom` is used |
| **Requests to `/cgi-bin/` variants** | Nikto probes `/cgi-bin/`, `/cgi/`, `/cgi-asp/`, `/cgi-sh/` — the plugin's CGI scanning signature |
| **HTTP/1.0 requests** | Nikto sometimes sends HTTP/1.0 (line: `GET /path HTTP/1.0`), while most modern browsers use HTTP/1.1 |
| **Missing Referer header** | Nikto often sends `Referer: -` (no referrer) for every request, unusual for normal browsing |
| **Quick 404 probe at start** | Nikto begins with a GET to a random, non-existent path to establish baseline 404 response |

**Combined example (highly suspicious):**
```
14:30:15 192.168.1.101 GET /nikto_random_abc123xyz (404)  - Mozilla/5.0 Windows
14:30:16 192.168.1.101 HEAD /admin/ (404)  - Mozilla/5.0 Linux
14:30:16 192.168.1.101 GET /backup/ (404)  - Mozilla/5.0 Mac
14:30:17 192.168.1.101 GET /.env (200)  - Mozilla/5.0 iPhone
14:30:17 192.168.1.101 GET /wp-login.php (200)  - Mozilla/5.0 Android
14:30:18 192.168.1.101 OPTIONS / (200 Allow: GET, POST, OPTIONS, PUT, DELETE)  - ...
14:30:18 192.168.1.101 GET /config.php (200)  - ...
14:30:19 192.168.1.101 GET /cgi-bin/test-cgi (404)  - ...
14:30:20 192.168.1.101 GET /cgi-bin/formmail.pl (404)  - ...
```

This pattern is **unmistakable** as Nikto scanning.

**Evidentiary value:** Very High. Access logs are the single best artifact for identifying Nikto activity on the target server.

---

## IIS Web Server Logs

**Location:** `C:\inetpub\logs\LogFiles\W3SVC1\yyyyMMdd.log` (one file per day per site)

**Extended Log File Format (IIS):**
```
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-08-12
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-08-12 14:30:15 192.168.1.100 GET / - 80 - 192.168.1.101 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 23
2026-08-12 14:30:16 192.168.1.100 HEAD /admin/ - 80 - 192.168.1.101 Mozilla/5.0+(X11;+Linux+x86_64) - 404 0 2 15
2026-08-12 14:30:16 192.168.1.100 GET /.env - 80 - 192.168.1.101 Mozilla/5.0+(Macintosh;+Intel+Mac+OS+X) - 200 0 0 34
2026-08-12 14:30:17 192.168.1.100 OPTIONS / - 80 - 192.168.1.101 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64) - 200 0 0 8
```

**Same Nikto signatures apply** as Apache logs (rapid sequential requests, predictable paths, varied User-Agents, etc.).

---

## HTTP Status Code Distribution

**Nikto scan signature via status codes:**

```
Total requests: 427
  - 200 (OK): 45 requests (found files/vulnerable paths)
  - 404 (Not Found): 312 requests (expected probes for non-existent files)
  - 403 (Forbidden): 28 requests (access denied, but different from 404)
  - 302/301 (Redirect): 12 requests (follow-redirects flag may be set)
  - 500 (Server Error): 18 requests (path triggered server error, possibly vulnerable)
  - 401 (Unauthorized): 6 requests (authentication required)
  - 405 (Method Not Allowed): 6 requests (OPTIONS tests, PUT/DELETE rejections)
```

**Detection heuristic:** If a single source IP makes 50+ requests in under 5 minutes with this distribution, it's almost certainly a vulnerability scanner.

**Evidentiary value:** High. Aggregated status code patterns uniquely identify Nikto's scanning footprint.

---

## HTTP OPTIONS Method Responses

Nikto tests the OPTIONS method to discover allowed HTTP methods. The response's `Allow` header reveals permitted methods:

**Request:**
```
OPTIONS / HTTP/1.0
Host: target.local
Connection: close
```

**Response (normal server):**
```
HTTP/1.1 200 OK
Allow: GET, POST, HEAD, OPTIONS
Content-Length: 0
```

**Response (vulnerable to method abuse):**
```
HTTP/1.1 200 OK
Allow: GET, POST, HEAD, OPTIONS, PUT, DELETE, TRACE, CONNECT
Content-Length: 0
```

**Evidentiary value:** Moderate-to-High. The OPTIONS request itself is distinctive (not all scanners perform this check), and the response reveals the server's method configuration.

---

## Error Page Analysis

### 404 Baseline Detection Artifact

Nikto's first action is to request a deliberately non-existent URI to establish a baseline 404 response. This request appears in logs:

```
14:30:15 192.168.1.101 GET /nikto_random_abc123xyz HTTP/1.0 (404)
```

**Indicator:** Any log entry with "nikto" in the URI is a direct Nikto fingerprint. (Though attackers using custom evasion may randomize this.)

### Server Error Pages (5xx)

Nikto probes may trigger server errors if paths don't exist or if the application has bugs:

```
14:30:18 192.168.1.101 GET /app/secret/config.php HTTP/1.0 (500 Internal Server Error)
```

**Evidentiary value:** If the target logs request URIs (not just status codes), 500 errors reveal which paths Nikto probed.

---

## Request Path Enumeration from Logs

**Full list of paths Nikto probes** (partial — db_tests has thousands of entries):

Common probed paths:
```
/
/.env
/.git/
/.gitignore
/.github/
/.gitlab-ci.yml
/admin/
/admin/admin.php
/admin/login.php
/admins/
/administrator/
/backup/
/backup.sql
/backup.zip
/backup.tar.gz
/config/
/config.php
/config.json
/database/
/database.yml
/db/
/.htaccess
/.htpasswd
/install/
/install.php
/installer/
/web.config
/wp-admin/
/wp-login.php
/wp-config.php
/cgi-bin/
/cgi-bin/test-cgi
/cgi-bin/printenv
/cgi-bin/formmail.pl
/api/
/REST/
/services/
/v1/
/v2/
/soap/
/webservice/
```

**Evidentiary value:** Moderate. The specific paths probed indicate which Nikto database(s) were loaded (e.g., CMS detection, CGI scanning, API discovery).

---

## Prefetch Files (Windows Target)

**Location:** `C:\Windows\Prefetch\` (if Prefetch is enabled)

If web server runs on Windows (e.g., IIS), there may be prefetch records for tools used to view/analyze scan results:

```
notepad.exe.log
notepad++-5.9.2.log (if admin opened log files)
```

However, **Prefetch doesn't directly track Nikto** since Nikto runs on the attacker's host (source), not the target. Prefetch would only be relevant if the attacker uses Windows-based tools to analyze local target logs post-breach.

**Evidentiary value:** Low for Nikto specifically.

---

## Registry Keys (Windows Target, IIS)

**IIS logging configuration:** `HKLM\Software\Microsoft\InetStp\`

May indicate logging state (enabled/disabled), but doesn't directly show Nikto activity. However, if logs are disabled or were cleared around the time of scanning, that's suspicious.

**Evidentiary value:** Low.

---

## Firewall/IDS Alerts

**WAF/IDS sensor observations:**

Modern web firewalls (ModSecurity, F5, Imperva, Cloudflare) may detect Nikto signatures:

```
[2026-08-12 14:30:15] ALERT: Scanner signature detected (Nikto v2.6.1)
  Source: 192.168.1.101
  Reason: Rapid sequential requests to non-existent paths
  Actions: [Log] [Block] [Alert]

[2026-08-12 14:30:16] ALERT: SQLi pattern detected
  URI: /admin/?id=1' OR '1'='1
  Source: 192.168.1.101
  Match: SQL Injection (Nikto test probe)

[2026-08-12 14:30:17] ALERT: Command Execution pattern
  URI: /test.php?cmd=whoami
  Source: 192.168.1.101
  Match: Command execution testing (Nikto probe)
```

**Evidentiary value:** Very High. IDS/WAF logs directly name Nikto and provide timestamps, source IP, and specific probes.

---

## Syslog and Network Monitoring

**Network-based (if Zeek, Suricata, or similar NSM is running):**

```
2026-08-12T14:30:15.234Z conn ID 192.168.1.101:51234 192.168.1.100:80
  proto=tcp service=http
  orig_bytes=15234 resp_bytes=45123
  duration=327.892s state=SF (successful connection)
  
2026-08-12T14:30:15.456Z http ID 192.168.1.101:51234 192.168.1.100:80
  uri=/admin/ method=GET status_code=404 user_agent=Mozilla/5.0
  
2026-08-12T14:30:15.678Z http ID 192.168.1.101:51234 192.168.1.100:80
  uri=/.env method=GET status_code=200 resp_size=145
```

**Evidentiary value:** High. NSM logs show exact request/response details, URIs, status codes, and response sizes — perfect for correlating with Nikto behavior.

---

## Timeline of a Nikto Scan (Target-Side)

**Step-by-step what the target observes:**

```
Time      Event
──────────────────────────────────────────────────────────────────
14:30:15  Connection from 192.168.1.101 (SYN)
14:30:15  GET /nikto_random_abc123 HTTP/1.0 → 404 (baseline detection)
14:30:15  GET / HTTP/1.1 → 200 OK (root page)
14:30:16  HEAD /admin/ HTTP/1.0 → 404 (CGI probe)
14:30:16  GET /.env HTTP/1.1 → 200 OK (env file found) ⚠️ ALERT
14:30:16  GET /backup/ HTTP/1.1 → 404
14:30:17  GET /backup.zip HTTP/1.1 → 404
14:30:17  OPTIONS / HTTP/1.0 → 200 OK Allow: GET, POST, OPTIONS, PUT
14:30:18  GET /wp-login.php HTTP/1.0 → 404 (not WordPress)
14:30:18  GET /admin/login.php HTTP/1.0 → 404
14:30:18  GET /wp-config.php HTTP/1.0 → 404
14:30:19  GET /config.php HTTP/1.1 → 200 OK (config found) ⚠️ ALERT
14:30:20  GET /cgi-bin/test-cgi HTTP/1.0 → 404
14:30:20  GET /cgi-bin/printenv HTTP/1.0 → 404
... (400+ more requests in 5-10 minutes) ...
14:35:22  Connection closed (scan complete)
```

**Total footprint:** 
- Duration: ~5–10 minutes
- HTTP requests: 50–500+
- Response sizes: KB–MB (depending on what was found)
- Distinct HTTP methods: GET, HEAD, OPTIONS (sometimes PUT/DELETE tests)
- Source IP: Single IP address (rarely changes during scan)

---

## Distinguishing Nikto from other Scanners

| Scanner | Signature |
|---|---|
| **Nikto** | Perl-based, predictable db_tests paths, rapid sequential requests, mixed User-Agents (if not customized), HTTP/1.0 in some requests |
| **Nmap** | Port-scanning focus (SYN/ACN/etc.), HTTP service detection via NSE, fewer sequential requests per port |
| **Burp Suite** | Slower (by design), often follows redirects, XML/UI-heavy requests, consistent User-Agent |
| **ZAP** | Similar to Burp; sequential crawling, respects robots.txt (by default), persistent session handling |
| **w3af** | Web app fuzzer; more random path generation, heavier POST requests, longer scan duration |
| **Masscan** | Port-scanning only, not HTTP-level scanning |
| **Custom scripts** | Variable — depends entirely on what the script does |

**Nikto's distinctive marker:** **The combination of predictable db_tests paths + rapid sequential requests + mixed User-Agents (unless overridden)** is the clearest fingerprint.

---

## Correlating Target Evidence with Source Evidence

**Investigator's workflow:**

1. **Observe target logs:** Identify rapid sequential HTTP requests from source IP X during time window T
2. **Identify paths probed:** `/admin/`, `/.env`, `/backup/`, `/config.php` — matches Nikto's db_tests
3. **Check source host (if accessible):** Look for `nikto.pl` binary, shell history, output files (matches `03 - Source Evidence.md`)
4. **Correlate timestamps:** Source shell history shows `./nikto.pl -host target.com` at time T matches target-side requests at time T
5. **Confirm scope:** Source output file names targets; target access logs show those same targets scanned
6. **Attribute:** Conclude that source host engaged in Nikto-based reconnaissance against target

**Stronger evidence if:**
- Source IP is linked to attacker identity (VPN, ISP records, etc.)
- Output files found on source host contain findings from target
- Shell history directly shows target IP + Nikto command
- Target-side logs show response of found files (e.g., /.env 200 OK) with content matching what attacker accessed later

