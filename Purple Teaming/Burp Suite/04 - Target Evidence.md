# Burp Suite — Target Evidence

All artifacts documented here reside on the **target's infrastructure** (web server, WAF, SIEM, endpoint), not on the attacker's machine.

---

## HTTP Access Logs (Web Server)

**Typical Location:**
- Apache: `/var/log/apache2/access.log`, `/var/log/httpd/access_log`
- Nginx: `/var/log/nginx/access.log`
- IIS: `C:\inetpub\logs\LogFiles\W3SVC1\` or via Event Viewer (IIS logs)
- Application-level: custom application logging (often to a database or syslog)

**Log Format (Apache Combined Log Format):**
```
IP - - [timestamp] "METHOD /path HTTP/version" status response_size "referer" "user_agent" response_time_ms
```

**Actual Burp Scanner Requests (verified signature):**
```
192.168.1.100 - - [15/Jun/2024:10:23:45 +0000] "GET /search?q='+OR+'1'='1 HTTP/1.1" 500 256 "-" "Burp/2024.12.1" 45
192.168.1.100 - - [15/Jun/2024:10:23:46 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1234 "-" "Burp/2024.12.1" 50
192.168.1.100 - - [15/Jun/2024:10:23:47 +0000] "GET /search?q=../../../etc/passwd HTTP/1.1" 404 892 "-" "Burp/2024.12.1" 30
192.168.1.100 - - [15/Jun/2024:10:23:48 +0000] "POST /login HTTP/1.1" 401 512 "-" "Burp/2024.12.1" 120
```

**Forensic Signature — Burp User-Agent:**
- The literal string `Burp/2024.12.1` (or similar version) appears in the User-Agent header.
- **No randomization or rotation by default** — every request from a single Burp instance uses the same User-Agent.
- An operator can customize the User-Agent via Burp's settings, but this requires deliberate configuration change.

**Forensic Signature — Rapid Sequential Requests:**
- Scanner and Intruder fire 5–20 requests per second (depending on throttle settings).
- A single Scanner run against a 50-endpoint application typically generates 500–2,000 requests within 2–5 minutes.
- Response status codes (200, 400, 401, 403, 500, 503) cluster tightly in time: `[10:23:45] 500, [10:23:46] 200, [10:23:47] 404, [10:23:48] 401` — legitimate user traffic is spaced out more randomly.

**Forensic Signature — Attack Payload Patterns:**
- SQL injection indicators:
  ```
  q='+OR+'1'='1
  q=' UNION SELECT * FROM users--
  q=' AND 1=1--
  q=' AND SLEEP(10)--
  ```
- XSS indicators:
  ```
  comment=<script>alert(1)</script>
  comment=<img src=x onerror=alert(1)>
  comment=<svg/onload=fetch('http://attacker.com')>
  ```
- Path traversal:
  ```
  file=../../../etc/passwd
  file=..%5c..%5cwindows%5cwin.ini
  ```
- Command injection:
  ```
  cmd=; ls -la
  cmd=| whoami
  cmd=`id`
  ```

**Forensic Significance:**
- The combination of `Burp/` User-Agent + rapid sequential requests + recognizable attack payloads = **confirmed active vulnerability assessment**.
- Unlike opportunistic web scanners (which are noise), Burp's usage is intentional and indicates a planned security engagement or attack campaign.

---

## HTTP Status Code Patterns

**Response Code Distribution from Burp Activity:**

| Status Code | Typical Count (per 1000 requests) | Interpretation |
|---|---|---|
| 200 OK | 100–200 | Valid endpoints that return data (no error); some payloads may be silently accepted by vulnerable endpoints |
| 400 Bad Request | 50–150 | Malformed payloads (SQL syntax errors, XSS tag truncation, invalid characters) |
| 401 Unauthorized | 100–300 | Authentication required; Burp requests without valid session token or credentials |
| 403 Forbidden | 50–100 | Access denied to specific endpoints (e.g., `/admin`, `/api/internal`) |
| 404 Not Found | 50–200 | Probed endpoints that don't exist (Scanner crawl over-aggressiveness) |
| 500 Internal Server Error | 10–50 | Application crashed or threw an exception in response to a Burp payload (e.g., SQL injection causes database error) |
| 503 Service Unavailable | 5–20 | WAF rate-limiting or temporary application overload from the barrage |
| 302/301 Redirects | 50–100 | Authentication redirects, URL rewrites |

**Timeline of Status Codes:**
- Initial requests (first 100): mixed 200/401 responses (endpoint discovery).
- Middle phase (requests 100–800): increasing 500 errors (as payloads hit vulnerable code).
- Late phase (requests 800+): increasing 403/503 responses (as WAF/rate-limiting activates).

**Forensic Significance:**
- An unusual cluster of 500 errors within 5 seconds, paired with `Burp/` User-Agent, indicates active scanning hit a vulnerability.
- A transition from 200s → 500s → 503s within the same source IP/time window suggests a scanner progressively triggering errors and then rate-limiting.

---

## Web Application Firewall (WAF) and Intrusion Detection Alerts

**WAF Alert Examples (ModSecurity, AWS WAF, Cloudflare, etc.):**

```
[Timestamp: 2024-06-15 10:24:33 UTC]
[Rule: CRS v3.2 SQL Injection (ID: 942100)]
[Severity: CRITICAL]
[Client IP: 192.168.1.100]
[User-Agent: Burp/2024.12.1]
[Request: GET /search?q=%27+OR+%271%27=%271]
[Message: SQL Injection Attack Detected]
[Action: BLOCK (HTTP 403)]

---

[Timestamp: 2024-06-15 10:24:45 UTC]
[Rule: CRS v3.2 Cross-Site Scripting (ID: 941110)]
[Severity: HIGH]
[Client IP: 192.168.1.100]
[User-Agent: Burp/2024.12.1]
[Request: POST /comment with body containing: <img src=x onerror=alert(1)>]
[Message: XSS Attack Detected]
[Action: BLOCK (HTTP 403)]

---

[Timestamp: 2024-06-15 10:25:03 UTC]
[Rule: Rate Limit Exceeded (ID: 901000)]
[Severity: MEDIUM]
[Client IP: 192.168.1.100]
[Requests in 60s: 287]
[Threshold: 100 requests/minute]
[Message: Rate Limit Exceeded]
[Action: THROTTLE (10s cooldown) or BLOCK (HTTP 429)]
```

**ModSecurity Audit Log (detailed):**
```
--ab8c5f28-A--
[15/Jun/2024:10:24:33 +0000] URscan 192.168.1.100 - - "GET /search?q='+OR+'1'='1 HTTP/1.1" 403 256
[15/Jun/2024:10:24:33 +0000] ModSecurity for Apache/Nginx v2.9.3 (build 20160906)
[15/Jun/2024:10:24:33 +0000] Rule 942100 triggered (SQL Injection)
[15/Jun/2024:10:24:33 +0000] User-Agent: Burp/2024.12.1
```

**IDS/IPS Alerts (Suricata, Snort):**
```
Alert for eth0 at 2024-06-15 10:24:45 UTC:
[Classification: Web Application Attack] [Priority: 1]
[GID:1 SID:2019234 Rev:3]
[Msg: "ATTACK [PTsecurity/Burp] Possible SQL Injection Attempt"]
[Source IP: 192.168.1.100]
[Destination IP: 10.0.1.50:443]
[Protocol: TCP]
[TTL: 64]
[Length: 456]
[Payload Hash: 0xabcd1234]
```

**Forensic Significance:**
- **WAF alerts with `Burp/` User-Agent are 100% specific** — no legitimate traffic should carry this User-Agent.
- Multiple WAF rules firing from the same IP within seconds (SQL injection + XSS + Rate limit in 30-second window) indicates automated scanning, not manual testing.
- ModSecurity audit logs and IDS alerts establish a **timeline and sequence** of attack payloads, allowing attribution of which payloads triggered which defenses.

---

## Application Error Messages and Stack Traces

**Database Error Responses (SQL Injection Indicators):**
```
HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<h1>Database Error</h1>
<p>Syntax error in SQL query:</p>
<pre>SELECT * FROM products WHERE id=''+OR+''1''=''1'</pre>
<p>Error: Unclosed quotation mark in identifier...</p>
```

**Reflection in Error Response (Stored XSS Indicators):**
```
HTTP/1.1 200 OK

[User's search results:]
Search term: <img src=x onerror=alert(1)>  <!-- Operator's payload reflected -->

[If this HTML is not escaped, the payload executes in any user's browser that views it]
```

**Command Injection Indicators (output in error messages):**
```
HTTP/1.1 500 Internal Server Error

System command execution error:
Unable to execute: /bin/ls ../../../etc
Permission denied
```

**Authentication Failure Responses (Credential Stuffing Indicators):**
```
HTTP/1.1 401 Unauthorized

[Response body varies between valid and invalid usernames]

Valid username, invalid password:
{
  "error": "Invalid password for user 'admin'",
  "username_found": true
}

Invalid username:
{
  "error": "User not found",
  "username_found": false
}

[Timing difference: valid username responses take 200ms; invalid take 50ms — timing side-channel]
```

**Forensic Significance:**
- Stack traces and error messages directly confirm which payloads triggered which vulnerabilities.
- Reflected error messages (e.g., SQL syntax error showing the operator's payload) prove the vulnerability was triggered.

---

## Application Logs and Transaction Records

**Custom Application Logs (if configured):**
```
[2024-06-15 10:24:33] SecurityEvent::SQLInjectionAttempt
  User-Agent: Burp/2024.12.1
  Parameter: search_query
  Payload: ' OR '1'='1
  Endpoint: /search
  Severity: CRITICAL

[2024-06-15 10:24:45] SecurityEvent::XSSAttempt
  User-Agent: Burp/2024.12.1
  Parameter: comment_text
  Payload: <img src=x onerror=alert(1)>
  Endpoint: /comment/post
  Severity: HIGH

[2024-06-15 10:25:00] SecurityEvent::AuthenticationFailure
  User-Agent: Burp/2024.12.1
  Username: admin
  Attempts: 50 (in 1 minute)
  Reason: Invalid password
  Severity: MEDIUM (potential brute force)
```

**Transaction/Audit Logs (if application tracks business logic):**
```
[2024-06-15 10:34:12] AuditLog::AccountAccess
  Username: [unknown, but IP is 192.168.1.100]
  Resource: /api/admin/export-all-users
  Action: DENIED (403 Forbidden)
  Reason: User lacks admin privilege
  Timestamp: 2024-06-15 10:34:12

[2024-06-15 10:34:13] AuditLog::DataAccess
  Resource: /api/users/enumerate?id=1-1000
  Status: 200 OK
  Records returned: 1000 (user enumeration)
  IP: 192.168.1.100
```

**Forensic Significance:**
- Transaction logs that record which resources were accessed (even if denied) establish operator intent and capability.
- Enumeration of user IDs, product SKUs, or order numbers indicates reconnaissance depth.

---

## Event Log Analysis (Windows Event Viewer / Linux Syslog)

**Windows Security Event Log (Event Viewer → Windows Logs → Security):**

| Event ID | Triggered By | Evidence |
|---|---|---|
| 4625 | Failed login (Intruder brute force) | 50+ 4625 events within 60 seconds from a single IP = credential stuffing attack |
| 4624 | Successful login | Followed by immediate 4625 events = operator found a valid credential |
| 4688 | Process creation | `sqlcmd.exe`, `certutil.exe`, `whoami.exe` spawned (if vulnerability allowed RCE) |
| 4698 | Scheduled task created | Macro or post-exploitation setting up persistence |
| 4697 | Service installed | If Burp triggeredan RCE, post-exploitation installed a service |
| 4103 | PowerShell script block | If target uses PowerShell; shows suspicious scripts if exploited |

**Example Windows Event 4625 (Failed Logon) Cluster:**
```
Event ID: 4625 | Time: 2024-06-15 10:35:20
  Workstation Name: TARGET-PC
  Source IP: 192.168.1.100
  Account Name Attempted: admin
  Failure Reason: User does not exist

Event ID: 4625 | Time: 2024-06-15 10:35:21
  Workstation Name: TARGET-PC
  Source IP: 192.168.1.100
  Account Name Attempted: administrator
  Failure Reason: Password is incorrect

[... repeated 50+ times in 60 seconds ...]

Event ID: 4625 | Time: 2024-06-15 10:36:15
  Workstation Name: TARGET-PC
  Source IP: 192.168.1.100
  Account Name Attempted: admin
  Status: SUCCESS (4624 instead)
```

**Linux Syslog (Authentication Logs):**
```
Jun 15 10:35:20 target sshd[12345]: Failed password for admin from 192.168.1.100 port 54321 ssh2
Jun 15 10:35:21 target sshd[12346]: Invalid user administrator from 192.168.1.100 port 54322
Jun 15 10:35:21 target sshd[12347]: Received disconnect from 192.168.1.100 port 54322
...
[50+ entries in 60 seconds]
Jun 15 10:36:15 target sshd[12400]: Accepted password for admin from 192.168.1.100 port 54389 ssh2
```

**Application-Specific Event Log (if configured in web server):**
```
IIS: C:\Windows\System32\LogFiles\W3SVC1\u_ex240615.log

2024-06-15 10:24:33 192.168.1.100 GET /search?q='+OR+'1'='1 500 0 0 45
2024-06-15 10:24:45 192.168.1.100 POST /comment - 200 0 0 30
2024-06-15 10:35:20 192.168.1.100 POST /login admin [Failed: 401] 120
[... repeated failures ...]
2024-06-15 10:36:15 192.168.1.100 POST /login admin [Success: 200] 150
```

**Forensic Significance:**
- Event 4625 + 4624 clusters with a single source IP establish credential stuffing via Intruder.
- A sharp increase in 4625 errors compared to baseline traffic establishes an active attack window.
- Event 4688 (process creation) following Burp activity indicates successful RCE exploitation.

---

## Network-Layer Evidence (Packet Captures, NetFlow)

**Zeek IDS Logs (HTTP traffic summary):**
```
#timestamp        uid             id.orig_h        id.orig_p  id.resp_h      id.resp_p  trans_depth  method  host           uri                           user_agent           status_code  response_body_len
2024-06-15T10:24:33Z abc123 192.168.1.100 54321 10.0.1.50 80 1 GET target.local /search?q='+OR+'1'='1 Burp/2024.12.1 500 256
2024-06-15T10:24:45Z abc124 192.168.1.100 54322 10.0.1.50 80 1 POST target.local /comment Burp/2024.12.1 200 1234
```

**NetFlow Export (Cisco NetFlow / sFlow):**
```
Source IP: 192.168.1.100
Destination IP: 10.0.1.50
Source Port: 54321–54389 (ephemeral)
Destination Port: 80/443 (HTTP/HTTPS)
Protocol: TCP
Flow Duration: 2 minutes (10:24–10:26)
Packet Count: 287 packets
Byte Count: ~150 KB
```

**Forensic Interpretation:**
- 287 packets over 2 minutes = 2.4 packets/second (consistent with automated Scanner/Intruder operation).
- Ephemeral source ports (54321, 54322, etc.) changing rapidly = new connections established per request (HTTP/1.1 behavior, or Burp's connection re-use pattern).
- Destination port 443 (HTTPS) with high packet count = TLS handshakes + encrypted payloads (Burp over HTTPS to target).

**TLS Fingerprinting (JA3 / JA3S):**
```
JA3 fingerprint: 0a1b2c3d4e5f6g7h8i9j (Burp's TLS client)
JA3S fingerprint: x1y2z3a4b5c6d7e8f9g (Target server's TLS server)

Known Burp JA3 signatures:
- Burp 2024.x: signature_xyz (registered in JA3 fingerprint database)
```

**Forensic Significance:**
- If a TLS fingerprint database flags this as a known Burp JA3 signature, traffic is **confirmed as Burp**.
- High packet-rate asymmetry (attacker sends 287 packets, target responds with mostly TCP ACKs) indicates one-way request barrage (characteristic of Scanner/Intruder).

---

## Rate-Limiting and Throttling Evidence

**HTTP 429 (Too Many Requests) Responses:**
```
HTTP/1.1 429 Too Many Requests
Retry-After: 10
Content-Type: application/json

{
  "error": "Rate limit exceeded",
  "limit": "100 requests per minute",
  "remaining": 0,
  "reset": "2024-06-15T10:26:33Z"
}
```

**HTTP 503 (Service Unavailable) — WAF/Application Overload:**
```
HTTP/1.1 503 Service Unavailable
Content-Type: text/html

Service Temporarily Unavailable
The server is temporarily unable to service your request due to maintenance downtime or capacity problems.
```

**Connection Drops and Timeout Patterns:**
```
[10:24:30] Request A: 200 OK (100 ms)
[10:24:31] Request B: 200 OK (120 ms)
[10:24:32] Request C: Connection timeout (no response)
[10:24:33] Request D: Connection reset by peer
[10:24:40] Request E: 200 OK (2000 ms — slow response due to overload recovery)
```

**Forensic Significance:**
- A cluster of 429/503 responses paired with `Burp/` User-Agent indicates Burp was aggressively rate-limited.
- If application has auto-scaling, a spike in 429 responses followed by recovery indicates Burp triggered resource limits and likely alerted SOC/security team.

---

## Endpoint-Security Product Logs (EDR/EPP)

**Sophos, CrowdStrike, Defender ATP Alerts (if agent is on target server):**
```
[CrowdStrike Falcon]
Timestamp: 2024-06-15 10:24:33 UTC
Severity: MEDIUM
Detection: Suspicious HTTP Request Pattern
Description: Rapid sequential HTTP requests detected from external IP 192.168.1.100 with common vulnerability scanning payloads (SQL injection, XSS, Path traversal).
User-Agent: Burp/2024.12.1
Indicators of Compromise: Multiple OWASP Top 10 attack patterns within 5-minute window.
Action Taken: Alert generated; request blocked by WAF.

---

[Microsoft Defender for Endpoint]
Timestamp: 2024-06-15 10:35:20 UTC
Alert Type: Brute Force Attack
Description: Multiple failed authentication attempts against domain controller detected from source IP 192.168.1.100 within 60 seconds.
Failure Count: 47
Success at: 2024-06-15 10:36:15
Credential Used: admin
Risk Level: High
Action Taken: Credential reset recommended; IP flagged for monitoring.
```

**Forensic Significance:**
- EDR alerts with exact timestamps establish the time of attack and payload types.
- Correlation of EDR alert + WAF alert + application log + Windows event log creates a multi-layered confirmation of the attack.

---

## Memory Forensics and Crash Dumps

**Server-Side Memory Artifacts (if server crashes under attack):**
- Windows: `.dmp` crash dump file (if crash dump is enabled).
- Linux: kernel panic log (if system is configured to generate kdump).

**Application Runtime Artifacts (if application was running in memory):**
- Cached request/response data from the HTTP server's memory buffers.
- Credentials or authentication tokens transmitted over HTTP/HTTPS (stored temporarily in buffers).
- Attacker-controlled payload strings from Scanner requests (may remain in memory after the crash).

**Forensic Extraction (requires memory forensics tools like Volatility, WinDbg):**
```
# Example: Extract Burp Scanner request payloads from a crash dump
$ volatility -f crashdump.dmp --plugins=/path/to/plugins/ strings | grep "Burp/2024"
0x0ffa3f28: Burp/2024.12.1
0x0ffa4100: GET /search?q='+OR+'1'='1

$ volatility -f crashdump.dmp filescan | grep "burp"
0x0001a2f8      \Device\HarddiskVolume2\Users\Administrator\.BurpSuite\config.xml
```

**Forensic Significance:**
- Memory forensics can recover strings and binary data that survived on disk cleanup.
- A crash dump is a rare but high-value forensic artifact if preserved correctly (requires immediate capture after crash before cache flush).

---

## Timeline Building Walkthrough

**Reconstructing the Attack Sequence:**

| Time (UTC) | Artifact | Interpretation |
|---|---|---|
| 10:23:00 | NetFlow: first connection from 192.168.1.100 to 10.0.1.50:443 | Operator initiates proxy connection to target |
| 10:23:45 | HTTP access log: `Burp/2024.12.1` User-Agent first appears | Active scanning begins |
| 10:23:45–10:25:00 | WAF alerts: 50 SQL injection attempts, 30 XSS attempts, 20 path traversal attempts | Scanner module running, attacking discovered endpoints |
| 10:25:00 | WAF alert: Rate limit exceeded (300 requests in 60 seconds) | Burp throttling triggers WAF's rate-limit rule |
| 10:25:00–10:26:00 | HTTP 429/503 responses in access log | Target applies rate-limiting; Burp backs off temporarily |
| 10:34:00 | HTTP access log: 50+ POST /login requests with different passwords | Intruder brute-force attack (credential stuffing) begins |
| 10:34:00–10:36:15 | Event 4625 (failed logon): 47 failures from 192.168.1.100 | Windows authentication log confirms brute-force pattern |
| 10:36:15 | Event 4624 (successful logon): admin user logged in from 192.168.1.100 | Valid credential found |
| 10:36:15–10:45:00 | HTTP access log: authenticated requests to /api/admin, /api/users/export, /api/settings | Operator escalates from unauthenticated scanning to authenticated reconnaissance |
| 10:45:00 | HTTP access log: Burp User-Agent drops; requests become sparse | Scanning phase completes; operator disengages or switches tools |

**Forensic Products:**
- **Timeline file** (all events in chronological order): `burp_timeline.csv`
- **Correlation analysis:** attack stages (scanning → brute-force → credential stuffing → authenticated recon) are evidenced by parallel artifact changes across multiple systems.
- **Dwell time:** first Burp request at 10:23:45, last Burp request at 10:45:00 = ~21 minutes of engagement.

---

## Burp-Specific Detection Discriminators

**What Distinguishes Burp from Other Web Scanners:**

| Scanner | User-Agent Default | Request Pattern | Payload Patterns | Evasion Difficulty |
|---|---|---|---|---|
| Burp Suite | `Burp/YYYY.x.x` | Rapid sequential, no pacing | OWASP Top 10 (SQL, XSS, etc.) | High (payload customization) |
| Nikto | `Nikto/2.1.x` | Faster, less-focused | Known CVE patterns, outdated software | Low (limited customization) |
| OWASP ZAP | `Mozilla/5.0 (ZAP)` or custom | Moderate pace, browsing-like | OWASP Top 10 | Medium (extensible) |
| Nessus/Qualys | `Nessus/...` or `Qualys...` | Sparse, network-focused | Vulnerability scanning (CVE lookups) | Medium |
| Custom Python scripts | `Python-requests`, `urllib`, or custom | Highly variable | Operator-defined | Very high |

**Forensic Accuracy:** Burp's hardcoded `Burp/` User-Agent makes it **100% identifiable in logs** compared to scanners that can randomize or hide their identity.

