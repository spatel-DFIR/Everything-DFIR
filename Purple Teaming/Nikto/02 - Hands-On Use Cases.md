# Nikto — Hands-On Use Cases

## Basic Web Server Reconnaissance

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information — Active Scanning)

Run Nikto against a web server target with default settings. This performs a complete vulnerability scan using all enabled plugins and databases.

```bash
perl nikto.pl -host http://www.example.com

# Or using the shebang (if nikto.pl has execute permissions):
./nikto.pl -host http://example.com

# Save output to HTML report:
./nikto.pl -host http://example.com -output scan_report.html

# Save output in multiple formats:
./nikto.pl -host http://example.com -Format html,json,csv -output scan_report
# Generates: scan_report.html, scan_report.json, scan_report.csv
```

The scanner will:
1. Detect the target's 404 response pattern (baseline)
2. Run all plugins (cgi, headers, paths, outdated, auth, favicon, etc.)
3. Generate 50–200+ HTTP requests (depending on target size and database)
4. Output findings to stdout and optionally save to file

---

## Outdated Software and Version Detection

**MITRE ATT&CK IDs:** T1592.004 (Gather Victim Host Information — Software Versions)

Detect outdated Apache, IIS, OpenSSL, PHP, and other web-server software versions. Nikto's `nikto_outdated` plugin fingerprints the `Server` header and other version-revealing headers.

```bash
# Scan with verbose output to see version details:
./nikto.pl -host http://example.com -Display V

# Focus on software identification (Tuning category 'b' = software identification):
./nikto.pl -host http://example.com -Tuning b

# Scan an HTTPS server (auto-detects port 443, or force with -ssl):
./nikto.pl -host https://example.com -ssl

# Scan non-standard port (e.g., 8080):
./nikto.pl -host http://example.com:8080
```

Example output snippet:
```
+ Server: Apache/2.4.1 (Ubuntu)
  > This Apache version is outdated (2.4.1 released 2012, current: 2.4.X)
+ OpenSSL/1.0.1e
  > OpenSSL 1.0.1 end-of-life; vulnerable to Heartbleed (CVE-2014-0160)
```

---

## Dangerous HTTP Methods Discovery

**MITRE ATT&CK IDs:** T1595.002 (Active Scanning), T1046 (Network Service Scanning)

Test for dangerous HTTP methods (PUT, DELETE, TRACE, CONNECT) that could enable file write/delete or information disclosure. The `nikto_options` plugin checks the HTTP `Allow` header returned by OPTIONS requests.

```bash
# Run full scan (OPTIONS plugin is enabled by default):
./nikto.pl -host http://example.com

# Focus on OPTIONS method testing via the options plugin:
./nikto.pl -host http://example.com -Plugins @NONE;@options

# Test a specific directory for methods:
./nikto.pl -host http://example.com -root /webdav/

# Test PUT/DELETE methods specifically (Tuning 0 = file upload):
./nikto.pl -host http://example.com -Tuning 0
```

Example finding:
```
+ HTTP method OPTIONS allowed (potentially risky)
  > Response shows: Allow: GET, POST, PUT, DELETE, TRACE, CONNECT
  > PUT/DELETE/TRACE are dangerous (potential RCE/data loss/info disclosure)
```

---

## CGI Script Detection

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information), T1046 (Network Service Scanning)

Scan for CGI scripts in common directories (/cgi-bin/, /cgi/, /cgi-sh/, etc.). The `nikto_cgi` plugin loads tests specifically targeting CGI directories.

```bash
# Default CGI scanning (scans /cgi-bin/ and common variants):
./nikto.pl -host http://example.com

# Specify custom CGI directories:
./nikto.pl -host http://example.com -Cgidirs "/admin/cgi,/scripts/"

# Scan all possible CGI directories (exhaustive):
./nikto.pl -host http://example.com -Cgidirs all

# Disable CGI scanning:
./nikto.pl -host http://example.com -Cgidirs none

# Focus only on CGI plugin:
./nikto.pl -host http://example.com -Plugins @NONE;@cgi
```

Expected findings for an accessible CGI directory:
```
+ /cgi-bin/test-cgi is executable
+ /cgi-bin/formmail.pl found (potentially vulnerable script)
+ /cgi-bin/nph-test-cgi found (test script left on server)
```

---

## SSL/TLS Certificate and Security Header Analysis

**MITRE ATT&CK IDs:** T1592.003 (Gather Victim Host Information — Firmware, T1046 (Network Service Scanning)

Analyze SSL/TLS configuration and HTTP security headers (strict-transport-security, X-Frame-Options, CSP, etc.). The `nikto_headers` plugin tests for missing/weak security headers.

```bash
# Scan HTTPS with header analysis:
./nikto.pl -host https://example.com -ssl

# Or (Nikto auto-detects HTTPS via https:// scheme):
./nikto.pl -host https://example.com

# Focus only on headers plugin:
./nikto.pl -host https://example.com -Plugins @NONE;@headers

# Verbose output to see all headers:
./nikto.pl -host https://example.com -Display V
```

Example findings:
```
+ Server does not set Strict-Transport-Security header (HSTS)
  > No protection against MITM downgrade attacks
+ Missing X-Frame-Options header
  > Vulnerable to clickjacking (X-Frame-Options: DENY recommended)
+ Missing Content-Security-Policy header
  > No XSS protection via CSP
+ Server: nginx/1.14.0 (Ubuntu)
  > Outdated nginx version (current: 1.20+)
```

---

## Authentication Realm Enumeration

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Discover web server authentication realms (Basic, Digest, NTLM, SPNEGO) by analyzing WWW-Authenticate headers. The `nikto_auth` plugin detects and logs any authentication challenges.

```bash
# Basic scan (auth detection is automatic):
./nikto.pl -host http://example.com

# Access a protected path with credentials:
./nikto.pl -host http://example.com -id admin:password

# Access a path requiring a specific realm:
./nikto.pl -host http://example.com -id admin:password:Confidential

# Focus on auth plugin:
./nikto.pl -host http://example.com -Plugins @NONE;@auth

# Look for pages requiring authentication (Tuning 4):
./nikto.pl -host http://example.com -Tuning 4
```

Example output:
```
+ /admin/ requires HTTP authentication (WWW-Authenticate: Basic realm="admin area")
+ /api/ requires Digest authentication (realm="API Access")
+ /secure/ requires NTLM authentication
```

---

## Virtual Host Scanning

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Scan a virtual host (e.g., `internal.company.local`) by providing a custom Host header. Useful when DNS doesn't resolve but you have IP+hostname.

```bash
# Scan with custom Host header:
./nikto.pl -host http://192.168.1.100 -vhost internal.company.local

# Scan virtual host on non-standard port:
./nikto.pl -host http://192.168.1.100:8080 -vhost staging.company.local

# Combined with HTTPS:
./nikto.pl -host https://192.168.1.100 -vhost internal.company.local -ssl

# Multiple hosts via -Add-header (custom Host manipulation):
./nikto.pl -host http://192.168.1.100 -Add-header "Host: internal.company.local"
```

---

## Evasion Against IDS/WAF

**MITRE ATT&CK IDs:** T1027 (Obfuscation/Encoding), T1036 (Masquerading)

Test IDS/WAF detection coverage by using Nikto's built-in evasion techniques. Combine multiple evasion methods (`-evasion`) to defeat simple string-matching signatures.

```bash
# Basic scan without evasion (baseline):
./nikto.pl -host http://example.com -output baseline.txt

# Apply random URI encoding evasion:
./nikto.pl -host http://example.com -evasion 1 -output evasion1.txt

# Apply multiple evasion techniques (1,2,7):
./nikto.pl -host http://example.com -evasion 1,2,7 -output evasion_multi.txt

# Use directory self-reference and case-folding (techniques 2,7):
./nikto.pl -host http://example.com -evasion 2,7

# Combine evasion with custom User-Agent:
./nikto.pl -host http://example.com -evasion 1,2,3 -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

# Slow scan with pauses (evasion via timing):
./nikto.pl -host http://example.com -Pause 2 -evasion 1,6,8 -timeout 15
```

**Caveat:** Evasion techniques work against **string/signature-based** IDS/WAF rules. They do **NOT hide** the fundamental scanning pattern (rapid-fire sequential requests to predictable paths from a single IP). Log-based detection (counting requests per IP per minute) will still catch it.

---

## Post-Exploitation: Compromised Server Assessment

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information), T1046 (Network Service Scanning)

After compromising a web server, scan it locally or from the attacker's network to assess the current state (installed apps, loaded modules, dangerous configurations) without leaving a trail of suspicious requests from a compromised machine.

```bash
# Quick local assessment (127.0.0.1 or hostname):
./nikto.pl -host http://127.0.0.1

# Assume target is Linux (-Platform nix helps filter some tests):
./nikto.pl -host http://127.0.0.1 -Platform nix

# Scan with custom root directory (e.g., application installed at /app/web/):
./nikto.pl -host http://127.0.0.1 -root /app/web/

# Detailed output, save positive findings:
./nikto.pl -host http://127.0.0.1 -Display V -Save /tmp/findings

# Disable dangerous operations (no PUT/DELETE tests):
./nikto.pl -host http://127.0.0.1 -Tuning x0
```

---

## CMS Detection (WordPress, Drupal, Joomla, etc.)

**MITRE ATT&CK IDs:** T1592.004 (Gather Victim Host Information — Software Versions)

Detect CMS platforms and versions via plugin fingerprinting, favicon hashes, and signature-based detection. Nikto's `nikto_favicon` plugin uses favicon.ico hash matching; `nikto_outdated` detects CMS headers.

```bash
# Standard scan (will detect CMS via headers, files, signatures):
./nikto.pl -host http://example.com

# Enable verbose to see CMS-specific findings:
./nikto.pl -host http://example.com -Display V

# Focus on favicon detection (Tuning b = software identification):
./nikto.pl -host http://example.com -Tuning b

# Look for interesting files like wp-config, composer.json, etc.:
./nikto.pl -host http://example.com -Tuning 1

# Scan a site you suspect is WordPress:
./nikto.pl -host http://wordpress-site.example.com -root /wp-content/ -Tuning 1,b
```

Example findings:
```
+ WordPress wp-login.php detected at /wp-login.php
+ WordPress version 6.1 detected (from wp-includes/version.php)
+ Plugins directory /wp-content/plugins/ found
  > Vulnerable plugins may be present
```

---

## Default/Sample File and Backup Detection

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information), T1040 (Traffic Mirroring)

Discover default/installation files, backups, and admin panels left on web servers. Nikto's db_tests includes thousands of known-vulnerable or dangerous file paths.

```bash
# Standard scan detects many default files:
./nikto.pl -host http://example.com

# Focus on misconfiguration and default files (Tuning 2):
./nikto.pl -host http://example.com -Tuning 2

# Save all positive responses to a directory:
./nikto.pl -host http://example.com -Save /tmp/nikto_findings

# Look for admin/backup files (Tuning 1 = interesting files seen in logs):
./nikto.pl -host http://example.com -Tuning 1

# Display all 200/OK responses (some servers return 200 for everything):
./nikto.pl -host http://example.com -Display 3
```

Common findings:
```
+ /admin/ found
+ /backup/ found (backup directory accessible)
+ /config.php found (application config file)
+ /.env found (environment variables file, may contain credentials)
+ /install.php found (installer left on server)
+ /test.txt found
```

---

## WebDAV and File Write/Delete Capability Testing

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Test for WebDAV support and dangerous file operations. Nikto's `nikto_options` and `nikto_put_del_test` plugins identify hosts allowing PUT, DELETE, or WebDAV operations.

```bash
# Scan with full plugin suite (includes options/PUT-DELETE tests):
./nikto.pl -host http://example.com

# Focus only on OPTIONS/PUT/DELETE methods:
./nikto.pl -host http://example.com -Plugins @NONE;@options;@put_del

# Scan a WebDAV share (usually on /webdav or /dav):
./nikto.pl -host http://example.com -root /webdav/

# Enable Tuning 0 (file upload tests):
./nikto.pl -host http://example.com -Tuning 0
```

High-risk findings:
```
+ HTTP method PUT allowed — could allow file upload
+ HTTP method DELETE allowed — could allow file deletion
+ WebDAV enabled (seen via Allow: PROPFIND, COPY, MOVE, LOCK)
```

---

## API Endpoint and Path Enumeration

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information), T1046 (Network Service Scanning)

Enumerate API paths (/api/, /REST/, /v1/, /services/, etc.) to identify service endpoints and available operations. Nikto's path enumeration naturally discovers these.

```bash
# Standard scan (includes API paths in db_tests):
./nikto.pl -host http://api.example.com

# Scan with a specific root directory for APIs:
./nikto.pl -host http://example.com -root /api/v2/

# Enumerate custom paths (Tuning 1 = interesting files):
./nikto.pl -host http://example.com -Tuning 1

# Use mutation to guess additional paths (Tuning 6 = dict brute-force):
./nikto.pl -host http://api.example.com -mutate 6

# Save all found endpoints:
./nikto.pl -host http://api.example.com -Save /tmp/api_endpoints
```

---

## Time-Bound and Slow Scanning

**MITRE ATT&CK IDs:** T1027 (Obfuscation/Encoding)

Perform a time-limited scan or slow scan to reduce detection and impact on production systems. Use `-maxtime` to limit total scan duration and `-Pause` to add delays between requests.

```bash
# Limit scan to 5 minutes (e.g., for quick assessment):
./nikto.pl -host http://example.com -maxtime 5m

# Add 2-second pause between requests (reduce server load + detection):
./nikto.pl -host http://example.com -Pause 2

# Combine: limited time + slow requests:
./nikto.pl -host http://example.com -maxtime 10m -Pause 1

# Increase timeout per request (for slow servers):
./nikto.pl -host http://example.com -timeout 20
```

---

## Tuning Scans (Selective Test Execution)

**MITRE ATT&CK IDs:** N/A (Operational Optimization)

Run Nikto with specific tuning categories to focus on particular test types. Categories include file uploads (0), interesting files (1), misconfigurations (2), XSS (4), SQL injection (9), auth bypass (a), etc.

```bash
# Run only file upload tests (Tuning 0):
./nikto.pl -host http://example.com -Tuning 0

# Run multiple categories (1, 2, 3 = files, misconfigs, disclosure):
./nikto.pl -host http://example.com -Tuning 1,2,3

# Run all tests EXCEPT file uploads (x = reverse, so x0 excludes 0):
./nikto.pl -host http://example.com -Tuning x0

# Run security-focused tests (authentication, XSS, SQL injection, command exec):
./nikto.pl -host http://example.com -Tuning a,4,9,8

# Run only command-execution/shell checks (Tuning 8):
./nikto.pl -host http://example.com -Tuning 8
```

---

## Custom User-Agent and Header Injection

**MITRE ATT&CK IDs:** T1036 (Masquerading), T1027 (Obfuscation)

Scan using a custom User-Agent or inject HTTP headers to test application behavior or bypass WAF rules.

```bash
# Custom User-Agent (override random selection):
./nikto.pl -host http://example.com -useragent "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"

# Add custom HTTP header:
./nikto.pl -host http://example.com -Add-header "X-Forwarded-For: 127.0.0.1"

# Add multiple headers:
./nikto.pl -host http://example.com -Add-header "X-Forwarded-For: 127.0.0.1" -Add-header "X-Custom-Header: test"

# Add authentication header (in addition to -id):
./nikto.pl -host http://example.com -Add-header "Authorization: Bearer token123"

# Bypass WAF with custom User-Agent + evasion:
./nikto.pl -host http://example.com -useragent "curl/7.64.1" -evasion 1,2
```

---

## Follow Redirects and Multi-Stage Scanning

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Follow HTTP redirects (3xx responses) to scan through redirects, useful for applications that redirect to different pages/domains.

```bash
# Default: don't follow redirects:
./nikto.pl -host http://example.com

# Follow redirects (3xx responses):
./nikto.pl -host http://example.com -followredirects

# Follow redirects + display them (Display 1 = show redirects):
./nikto.pl -host http://example.com -followredirects -Display 1,V

# Scan through a redirect to a different host:
./nikto.pl -host http://old-server.com -followredirects
# (If old-server.com redirects to new-server.com, Nikto will scan new-server.com)
```

---

## Output Analysis and Report Generation

**MITRE ATT&CK IDs:** N/A (Post-Scan Analysis)

Generate Nikto reports in various formats for documentation, team review, or SIEM integration.

```bash
# Generate HTML report (human-readable, suitable for client delivery):
./nikto.pl -host http://example.com -output nikto_report.html

# Generate JSON report (parseable by scripts/tools):
./nikto.pl -host http://example.com -output nikto_report.json

# Generate CSV report (easy import into spreadsheets):
./nikto.pl -host http://example.com -output nikto_report.csv

# Generate multiple formats at once:
./nikto.pl -host http://example.com -Format html,json,csv -output nikto_scan

# Generate SQL insert statements (for database archival):
./nikto.pl -host http://example.com -output nikto_report.sql

# Auto-name output file:
./nikto.pl -host http://example.com -output .
# Generates: nikto_scan_timestamp.txt
```

---

## Batch Scanning Multiple Hosts

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Scan multiple targets in a single Nikto invocation. The `-host` parameter accepts a comma-separated list or a file containing one host per line.

```bash
# Comma-separated hosts:
./nikto.pl -host "http://site1.com,http://site2.com,https://site3.com:8443"

# Read hosts from a file (one per line):
./nikto.pl -host http://example.com < hosts.txt

# Or via xargs:
cat hosts.txt | xargs -I {} ./nikto.pl -host {}

# Scan a range of ports on a single host:
./nikto.pl -host http://example.com -port 80,443,8080,8443

# Batch scan with custom output directory:
for host in $(cat targets.txt); do
  ./nikto.pl -host "$host" -output "results/${host//\//_}.html"
done
```

---

## Shellshock and Specific Vulnerability Testing

**MITRE ATT&CK IDs:** T1595.002 (Gather Victim Web Application Information)

Run specific plugin-based vulnerability tests (e.g., Shellshock/CVE-2014-6271, MS10-070 SMB Relay, OptionBleed/CVE-2017-9798).

```bash
# Full scan (includes Shellshock, OptionBleed, MS10-070 plugins):
./nikto.pl -host http://example.com

# Focus only on Shellshock testing:
./nikto.pl -host http://example.com -Plugins @NONE;@shellshock

# Focus on Apache OptionBleed (CVE-2017-9798):
./nikto.pl -host http://example.com -Plugins @NONE;@optionsbleed

# Run MS10-070 SMB Relay check (specific for Windows servers):
./nikto.pl -host http://example.com -Plugins @NONE;@ms10_070

# Full scan with verbose to see all plugin findings:
./nikto.pl -host http://example.com -Display V
```

---

## Database Validation and Configuration Testing

**MITRE ATT&CK IDs:** N/A (Admin/Maintenance)

Validate Nikto's databases and configuration files for syntax errors before running scans.

```bash
# Check databases and config for syntax errors:
./nikto.pl -dbcheck

# Print Nikto and plugin versions:
./nikto.pl -Version

# List all available plugins:
./nikto.pl -list-plugins

# Use custom config file:
./nikto.pl -config /path/to/nikto.conf -host http://example.com

# Load only user-defined databases:
./nikto.pl -host http://example.com -Userdbs all
# (Loads udb_* instead of db_* from databases/)
```

---

## IPv6 Scanning and Network-Specific Options

**MITRE ATT&CK IDs:** T1046 (Network Service Scanning), T1595.002 (Gather Victim Web Application Information)

Scan IPv6-enabled web servers or force specific IP protocols.

```bash
# Force IPv4 only (useful on dual-stack hosts):
./nikto.pl -host http://example.com -ipv4

# Force IPv6 only:
./nikto.pl -host http://[::1] -ipv6

# Disable DNS lookups (useful for systems without DNS):
./nikto.pl -host 192.168.1.100 -nolookup

# Check if IPv6 is working:
./nikto.pl -check6
```
