# Application and Database Logs

For internet-facing Linux, the web server and database logs are the front line — most compromises of these hosts begin with an HTTP request or a SQL statement, and the logs capture it. The move that makes or breaks a web-intrusion case is **correlating access-log timestamps with web-root file mtimes**: the request that uploaded a webshell and the file it created share a moment in time, and lining them up proves the chain. Database logs, when the general query log is on, are a similar goldmine — they record account creation, privilege grants, and the `INTO OUTFILE`/`LOAD_FILE` calls that turn SQL access into file read/write.

> 🔴 The classic webshell signature is a **POST returning 200 to a newly-created `.php`, then GETs to that same file carrying a command parameter** (`cmd=`, `c=`, `x=`) — all from one IP. Find the shell by its recent mtime under the web root, then pull that filename from the access log to recover the attacker's commands.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Web Server Log Locations](#web-server-log-locations)
- [Suspicious Requests](#suspicious-requests)
- [User Agent Analysis](#user-agent-analysis)
- [IP Analysis](#ip-analysis)
- [Webshell Detection](#webshell-detection)
- [Log Poisoning to RCE](#log-poisoning-to-rce)
- [Server Config Inspection](#server-config-inspection)
- [MySQL and MariaDB](#mysql-and-mariadb)
- [Other Databases](#other-databases)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Suspicious HTTP methods / endpoints
grep -Ei "POST|PUT|DELETE|CONNECT|cmd=|shell|upload|eval|base64|/bin/bash" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null

# Recently modified web content (possible webshell / defacement)
find /var/www -type f -mtime -3 -ls 2>/dev/null

# PHP files calling dangerous functions
find /var/www -type f -name "*.php" -exec grep -lE "shell_exec|system|passthru|\bexec\b|eval|base64_decode" {} \; 2>/dev/null

# Scanner user-agents
grep -Ei "sqlmap|nikto|nmap|acunetix|dirsearch|gobuster|feroxbuster" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Was a webshell uploaded, and when? | `find /var/www -name '*.php' -mtime -7`; match mtime to access-log 200 |
| What commands did the shell run? | pull the shell filename from the access log (`cmd=`/`c=` params) |
| Who attacked (source IP)? | `awk '{print $1}' access.log \| sort \| uniq -c \| sort -nr` |
| Recon tool used? | rare user-agents (`cut -d'"' -f6 … \| sort \| uniq -c \| sort -n`) |
| SQLi / DB backdoor / SQL file I/O? | `grep -Ei "UNION\|INTO OUTFILE\|CREATE USER\|GRANT" general.log*` |
| PostgreSQL command execution? | `grep -Ei "COPY .*(TO\|FROM) PROGRAM" /var/log/postgresql/*.log` |
| Data exfil (bulk pull)? | large response bytes to one IP (`awk '$10>1000000'`) |
| LFI log-poisoning RCE? | `grep -a '<?php' /var/log/apache2/*.log /var/log/nginx/*.log` |
| Every vhost/docroot a shell could live in? | `apachectl -S`; `nginx -T` |

## Web Server Log Locations

Access logs record every request (IP, method, URL, status, bytes, user-agent); error logs capture what failed — and exploitation that succeeded silently in the access log often leaves a trace in the error log (a PHP fatal, a permission-denied on an attacker write).

| Server | Access | Error |
|--------|--------|-------|
| Apache (Debian) | `/var/log/apache2/access.log` | `/var/log/apache2/error.log` |
| Apache (RHEL) | `/var/log/httpd/access_log` | `/var/log/httpd/error_log` |
| Apache vhosts | `/var/log/apache2/other_vhost_access.log` | per-vhost |
| Apache SSL (RHEL) | `/var/log/httpd/ssl_access_log` | `/var/log/httpd/ssl_error_log` |
| nginx | `/var/log/nginx/access.log` | `/var/log/nginx/error.log` |
| cPanel / Plesk | `/usr/local/apache/logs/access_log`, `/var/www/vhosts/*/logs/` | — |

Web roots to inspect: `/var/www`, `/var/www/html`, `/srv/www`, `/usr/share/nginx/html`, `/opt/*/www`, plus any per-vhost roots from the server config.

## Suspicious Requests

```bash
# High-risk methods
grep -Ei "POST|PUT|DELETE|CONNECT" /var/log/apache2/access.log

# Common attack patterns in the URL
grep -Ei "cmd=|shell|upload|eval|base64|/bin/bash|\.\./|passwd|wp-admin|phpmyadmin|xmlrpc" /var/log/apache2/access.log

# Abnormally large responses (field 10 = bytes; potential data pull)
awk '{if($10 > 1000000) print $0}' /var/log/apache2/access.log

# POSTs to upload/admin endpoints
grep -Ei "POST .*(upload|admin|shell|\.php)" /var/log/apache2/access.log
```

Large response sizes to a single IP can indicate bulk data pull (exfil); `../` sequences indicate path traversal; `wp-admin`/`xmlrpc`/`phpmyadmin` hits indicate CMS/admin-panel targeting. Read these in context of the source IP.

## User Agent Analysis

```bash
# Most common user agents (field 6 between quotes in combined log)
cut -d'"' -f6 /var/log/apache2/access.log | sort | uniq -c | sort -nr | head -20

# Rarest user agents (tools, custom clients, one-offs)
cut -d'"' -f6 /var/log/apache2/access.log | sort | uniq -c | sort -n | head -20
```

The interesting traffic is usually at the *tail* of the frequency distribution — the rare user-agents: `curl`, `python-requests`, `Go-http-client`, an empty UA, or named scanners. A tool user-agent hitting an upload or admin endpoint is worth following.

## IP Analysis

```bash
# Unique client count
awk '{print $1}' /var/log/apache2/access.log | sort -u | wc -l

# Most active IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr | head

# Everything from one suspect IP
grep "203.0.113.5" /var/log/apache2/access.log

# Requests from an IP that got a 200 on a POST
awk '$1=="203.0.113.5" && $6 ~ /POST/ && $9==200' /var/log/apache2/access.log
```

Once you have a suspect IP (from a webshell hit or a scanner UA), pull its full request history — it reconstructs the attacker's reconnaissance, exploitation, and use of whatever they dropped.

## Webshell Detection

Webshells hide as obfuscated PHP/JSP, sometimes inside files that look like images. These finds combine "recently modified" with "contains a dangerous function."

```bash
# PHP dangerous-function usage
find /var/www -type f -name "*.php" -exec grep -lE "shell_exec|system|passthru|\bexec\b|eval|assert|base64_decode|str_rot13|gzinflate|preg_replace.*/e" {} \; 2>/dev/null

# Recently created/modified web files
find /var/www -type f -mtime -2 -ls 2>/dev/null

# Hidden files in the web root
find /var/www -type f -name ".*" -ls 2>/dev/null

# World-writable web files (persistence risk)
find /var/www -type f -perm -o+w -ls 2>/dev/null

# Files whose extension doesn't match a normal web asset (e.g. image with PHP inside)
find /var/www -type f \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" \) -exec grep -lE "<\?php|eval|base64_decode" {} \; 2>/dev/null
```

🔴 The obfuscation signatures — `eval(base64_decode(...))`, `gzinflate`, `str_rot13`, `preg_replace` with the `/e` modifier — are hallmark webshell constructs, as are one-line "file managers" and PHP payloads hidden inside image files (polyglots). Any of these under a web root, especially with a recent mtime, is a shell until proven otherwise.

## Log Poisoning to RCE

🔴 An overlooked technique: an attacker with a Local File Inclusion (LFI) bug injects PHP into a value that gets **logged** (User-Agent, a bad URL, a failed username), then includes the *log file itself* — the server parses the injected `<?php … ?>` and executes it. The tell is PHP tags living inside a log that should only contain text.

```bash
# PHP tags injected into the logs themselves (poisoning payload)
grep -a '<?php' /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/*.log 2>/dev/null

# System commands smuggled through the User-Agent or URL
grep -aEi 'User-Agent.*(system|passthru|shell_exec|base64_decode)|<\?php' /var/log/apache2/access.log 2>/dev/null

# LFI attempts including a log or /proc path (the include target)
grep -aEi '(access\.log|error\.log|/proc/self/environ|php://|data://|expect://)' /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null
```

The same `php://`, `data://`, `expect://` wrappers and `/proc/self/environ` inclusion in a URL are LFI/RCE fingerprints — a request combining one of those with a payload is an attempt to turn file read into code execution.

## Server Config Inspection

```bash
# Apache vhost + module layout
apachectl -S

apache2ctl -M

# nginx full effective config
nginx -T

# Error log review
grep -i "error" /var/log/apache2/error.log

grep -i "permission denied" /var/log/nginx/error.log
```

The config tells you every vhost and document root (so you know all the places a shell could live), and the error log frequently reveals exploitation the access log alone doesn't — a broken webshell throwing PHP errors, or a `permission denied` on the attacker's write attempt.

## MySQL and MariaDB

The general query log is off by default, but when present it records every statement — a complete transcript of database activity. Even without it, the error and binary logs carry signal.

```bash
# General query log (if enabled)
cat /var/log/mysql/general.log

zcat /var/log/mysql/general.log* 2>/dev/null

# Auth: connects, denials
grep -Ei "Connect|Access denied|authentication|login" /var/log/mysql/general.log*

grep -Ei "Access denied for user" /var/log/mysql/general.log*

# App-login queries, excluding the admin account (find abused app creds)
grep 'WHERE user_login =' /var/log/mysql/general.log* | grep -v admin

# Account changes / privilege escalation
grep -Ei "CREATE USER|GRANT|WITH GRANT OPTION|INSERT INTO mysql.user" /var/log/mysql/general.log*

# File read/write via SQL (exfil / webshell drop)
grep -Ei "INTO OUTFILE|LOAD_FILE|LOAD DATA" /var/log/mysql/general.log*

# Injection indicators
grep -Ei "UNION|SELECT.*FROM|sleep\(|benchmark\(|information_schema" /var/log/mysql/general.log*

# CMS abuse (WordPress example)
grep -Ei "wp_users|wp_options|INSERT INTO.*wp_posts" /var/log/mysql/general.log*

# Destructive statements
grep -Ei "DROP|DELETE|TRUNCATE|ALTER|UPDATE" /var/log/mysql/general.log*

# Successful connections, and non-admin logins (focus on abused app creds)
grep -Ei "Connect.*as" /var/log/mysql/general.log*

grep -Ei "Connect" /var/log/mysql/general.log* | grep -vi "root\|admin"

# Most active users / most common query shapes
grep -Ei "Connect" /var/log/mysql/general.log* | awk '{print $NF}' | sort | uniq -c | sort -nr

awk '{print $5,$6,$7,$8,$9}' /var/log/mysql/general.log* | sort | uniq -c | sort -nr | head

# Date coverage of the log (both modern and older timestamp formats)
grep -E "^202[0-9]-" /var/log/mysql/general.log* | cut -d' ' -f1 | sort -u

grep -E "^2[0-9]{5}" /var/log/mysql/general.log* | awk '{print $1}' | sort -u
```

🔴 `INTO OUTFILE`/`LOAD_FILE` is the pivot from "database access" to "filesystem access" — it's how an attacker writes a webshell into the web root or reads `/etc/passwd` through SQL. `CREATE USER`/`GRANT` is a database-level backdoor account. `sleep(`/`benchmark(` and `UNION SELECT` are SQL-injection fingerprints. Also check the binary log (`mysqlbinlog`), error log (`/var/log/mysql/error.log`), and slow-query log.

## Other Databases

| DB | Log / evidence |
|----|----------------|
| PostgreSQL | `/var/log/postgresql/*.log`; `log_statement=all`; `pg_hba.conf` auth rules |
| Redis | `/var/log/redis/redis-server.log`; 🔴 unauth Redis → `CONFIG SET dir`/`dbfilename` writes an SSH key or cron file |
| MongoDB | `/var/log/mongodb/mongod.log`; auth + connection source IPs |
| Elasticsearch | `/var/log/elasticsearch/*.log`; exposed cluster = data exfil |

🔴 The Redis case is a common real-world foothold: an unauthenticated Redis instance can be told to write its dump file to `~/.ssh/authorized_keys` or a cron directory, converting a cache server into remote code execution.

## Deep Threat Hunts

The web/DB intrusion sweep. *(seasoned-DFIR; the webshell timestamp correlation is the money move)*

```bash
# 1. Webshell drop: list recent .php by mtime, then pull each from the access log
find /var/www -type f -name '*.php' -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM  %p\n' 2>/dev/null | sort
#   for a suspect file, recover the request that created/used it:
grep -F "shell.php" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null

# 2. Upload-and-use pattern: 200 POST to a .php, then command-param GETs, one IP
grep -E 'POST .*\.php' /var/log/nginx/access.log | awk '$9==200'

grep -aEi '\.php\?(cmd|c|x|q|exec|shell)=' /var/log/nginx/access.log 2>/dev/null

# 3. Recon-then-exploit: status distribution per IP (many 404s then a 200 POST = scanner that hit)
awk '{print $1, $9}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head -30

# 4. Reverse-shell / downloader one-liners URL-encoded in requests
grep -aEi "%2Fbin%2Fbash|bash%20-i|%2Fdev%2Ftcp|wget%20|curl%20|nc%20-e" /var/log/nginx/access.log 2>/dev/null

# 5. Log poisoning -> LFI RCE
grep -a '<?php' /var/log/apache2/*.log /var/log/nginx/*.log 2>/dev/null

# 6. PostgreSQL command execution + trust auth (passwordless DB)
grep -Ei "COPY .*(FROM|TO) PROGRAM|CREATE .*(plperlu|plpythonu)" /var/log/postgresql/*.log 2>/dev/null

grep -Ei "^[[:space:]]*(local|host).*trust" /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf 2>/dev/null

# 7. MySQL: file I/O + backdoor account + injection, consolidated
grep -Ei "INTO OUTFILE|LOAD_FILE|LOAD DATA|CREATE USER|GRANT|UNION SELECT|sleep\(|benchmark\(" /var/log/mysql/general.log* 2>/dev/null

# 8. Redis / Mongo unauth RCE writes
grep -Ei "CONFIG SET (dir|dbfilename)|SLAVEOF|MODULE LOAD" /var/log/redis/redis-server.log 2>/dev/null
```

**Hunt ideas:**

- **The webshell proof is the timestamp match** — the access-log request that returned `200` and created the file shares its minute with the file's mtime. Line them up to prove the chain.
- **Status distribution per IP** separates the noisy scanner (lots of 404) from the single request that actually landed (a `200` on a POST/upload).
- **Log poisoning is sneaky** — grep the log *files themselves* for `<?php`; an LFI that includes the log then executes it.
- **PostgreSQL `COPY … TO/FROM PROGRAM`** and untrusted PL languages are direct RCE; a `trust` line in `pg_hba.conf` is passwordless DB access.
- **Exposed Redis/Elasticsearch/Mongo without auth** are common footholds — the log shows the `CONFIG SET`/write that converted a data store into code execution.

## Getting Max Value

- **Correlate three ways for every web hit:** access-log IP+time ↔ web-root file mtime ↔ the process tree (`nginx`→`bash`) and `auth.log` (did they also SSH?).
- **The general query log is off by default** — if present it's a full transcript; otherwise mine the binlog (`mysqlbinlog`), slow-query log, and error log.
- **Read the log files for injected `<?php`** — the poisoning payload lives in the log, not the web root.
- **Rebuild across rotations** with `zcat -f access.log*`; on a mounted image everything works with the `/mnt/evidence/...` prefix.
- **Preserve the web root + logs before touching** — a webshell's own mtime is evidence; reading it can bump `atime`.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Did the web attacker get an interactive shell? | **Process Trees** (10b — `nginx`→`bash`), **Live Response** (10) |
| Did they also SSH in / pivot? | **Authentication and Login Records** |
| The dropped webshell as a file / persistence | **Persistence**, **Temp and Staging**, **Permissions** (mtime/timestomp) |
| The C2 the shell called out to | **Network and PCAP Forensics** (10c) |
| A DB backdoor account's privileges | **Users Groups and Authentication** (03) |
| Malware triage of the dropped payload | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| Full attack chain narrative | **Web Exploitation and Webshell Playbook** (15) |

## Scenarios

- **Webshell upload-and-use:** a `200` POST to a newly created `.php`, then GETs with `cmd=`, all from one IP.
- **Log poisoning → LFI RCE:** `<?php` injected via the User-Agent, then the access log included and executed.
- **SQLi to file write:** `INTO OUTFILE` drops a shell into the web root through the database.
- **DB backdoor:** `CREATE USER`/`GRANT` in the query log creates a database-level persistence account.
- **PostgreSQL RCE:** `COPY … TO PROGRAM` (or an untrusted PL function) runs OS commands from SQL.
- **Redis foothold:** `CONFIG SET dir` + `SAVE` writes `authorized_keys` or a cron file — cache server to RCE.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| POST to a new `.php` then GETs with `cmd=`/`c=` | Upload-and-use webshell |
| Recently modified file in `/var/www` with dangerous PHP funcs | Webshell |
| Scanner user-agents (sqlmap/nikto/…) | Active reconnaissance/exploitation |
| `INTO OUTFILE`/`LOAD_FILE` in DB logs | File write/read via SQL |
| `CREATE USER`/`GRANT` in DB logs | Database backdoor account |
| Redis `CONFIG SET dir` + `SAVE` | SSH-key / cron injection via Redis |
| Large response bytes to one IP | Data exfil |
| `<?php` inside an access/error log | Log-poisoning payload for LFI RCE |
| `php://`/`data://`/`/proc/self/environ` in a URL | LFI/RCE wrapper attempt |
| PostgreSQL `COPY … TO/FROM PROGRAM` | OS command execution via SQL |
| `trust` line in `pg_hba.conf` | Passwordless database access |

## Resources

- OWASP web-shell detection guidance — https://owasp.org/www-community/attacks/Web_Shell
- MySQL general query log & `mysqlbinlog` — https://dev.mysql.com/doc/refman/8.0/en/query-log.html
- PostgreSQL `COPY` / `pg_hba.conf` — https://www.postgresql.org/docs/current/sql-copy.html
- MITRE ATT&CK: T1505.003 (Web Shell), T1190 (Exploit Public-Facing App), T1059 (Command & Scripting), T1136 (Create Account), T1213 (Data from Information Repositories), T1041 (Exfil over C2)
