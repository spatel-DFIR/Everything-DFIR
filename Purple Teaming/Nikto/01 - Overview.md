# Nikto — Overview

> 🔴 **Red Flag Principle:** Nikto performs exhaustive, sequential HTTP checks against a **single target** in rapid succession — each plugin/database entry generates a specific HTTP request (GET to a web path, HEAD request, specific headers, etc.) with highly distinctive patterns. The combination of (1) **Nikto's User-Agent string** (if not randomized), (2) **rapid-fire, sequential vulnerability-signature checks** to predictable paths (e.g. `/admin/`, `/backup/`, `/config/`), and (3) **specific HTTP methods** (HEAD for quick checks, OPTIONS for allowed-methods scanning) generates an **unmistakable scanning footprint** visible in web server logs — a single Nikto scan produces 50–500+ HTTP requests from one IP/logon session within minutes, with a distinctive signature pattern that's hard to obscure without completely randomizing the check order and User-Agent per request.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`sullo/nikto`](https://github.com/sullo/nikto), README.md, and source code:

- **Primary author:** [Chris Sullo](https://cirt.net/) — sole author and maintainer since the project's inception. Nikto has been actively developed for **25 years** (2001–2026) with continuous updates.
- **License:** GNU General Public License v3.0 (GPLv3-only); database files are proprietary and may only be distributed as part of the official Nikto package.
- **Repository:** [`sullo/nikto`](https://github.com/sullo/nikto) on GitHub, default branch `main`. Last pushed **2026-07-31**, same day the latest release (2.6.1) was published.
- **Current release:** **Nikto 2.6.1** (released 2026-07-31), just days before this write-up. Prior stable: 2.6.0 (2026-02-11), 2.5.0 (2023-12-03).
- **Implementation language:** Perl (`nikto.pl` entry point in `program/` directory). No compiled binary — executed via shebang or explicit perl invocation. Depends on Perl 5.x and the `LW2.pm` Perl HTTP library (bundled, LibWhisker2 lineage).
- **Purpose:** Nikto is an **open-source web server vulnerability scanner** — a post-discovery tool that **assumes network access to a running web service** and performs **automated scanning against a single target** to detect outdated software, dangerous HTTP methods, insecure configurations, and known vulnerabilities. Distinct from Nmap/Masscan (network-layer host discovery) or Shodan (passive OSINT); Nikto actively probes a known/pre-identified web server.

## How It Works

Nikto operates on a **single-target, plugin + database-driven architecture**:

```
1. Operator specifies target (-host, -port, -ssl, optional root dir)
2. Nikto loads plugins (nikto_core, nikto_cgi, nikto_headers, etc.)
3. Nikto loads test databases:
   - db_tests         (main vulnerability/misconfiguration signatures)
   - db_outdated      (outdated software fingerprints)
   - db_404_strings   (404 response patterns for accurate false-positive filtering)
   - db_headers_*     (HTTP header analysis)
   - db_favicon       (favicon hash matching, e.g., for IIS detection)
   - db_useragents    (User-Agent rotation)
4. For each test entry in db_tests:
   a. Construct HTTP request (GET, HEAD, OPTIONS, etc.)
   b. Send to target web server
   c. Match response using DSL syntax (CODE:xxx, BODY:pattern, HEADER:value, COOKIE:value)
   d. Log any matches as "findings"
5. Generate report (text, HTML, CSV, JSON, XML, SQL, or SQL direct insert)
```

### The Plugin System

Nikto's scanning behavior is entirely plugin-driven. Each `.plugin` file (e.g., `nikto_cgi.plugin`, `nikto_headers.plugin`, `nikto_outdated.plugin`) is a Perl module that either:
- **Runs database-driven tests** — loads entries from `db_tests` and/or plugin-specific databases, constructs requests, matches responses
- **Runs inline checks** — hardcoded logic for complex checks (e.g., `nikto_auth.plugin` for authentication realm detection, `nikto_negotiate.plugin` for HTTP Negotiate/SPNEGO challenges)
- **Produces reports** — `nikto_report_*.plugin` files format output in various formats

**Key plugins (default enabled unless explicitly disabled with `-Plugins`):**

| Plugin | Purpose |
|---|---|
| `nikto_core` | Core scanning: 404 detection, initial reconnaissance, status output |
| `nikto_paths` | Path enumeration from db_tests (the largest, most tests come from here) |
| `nikto_cgi` | CGI script detection; tests `/cgi-bin/`, `/cgi/` and variants; honors `-Cgidirs` |
| `nikto_headers` | HTTP header analysis (Server, X-Powered-By, security headers) |
| `nikto_outdated` | Software version fingerprinting (Apache, IIS, OpenSSL, PHP, etc.) |
| `nikto_auth` | Authentication realm enumeration (`WWW-Authenticate` header parsing) |
| `nikto_favicon` | Favicon favicon.ico hash matching (identifies popular platforms/CMS by hash) |
| `nikto_robots` | robots.txt and sitemap.xml parsing |
| `nikto_ms10_070` | SMB Relay vulnerability (specific check) |
| `nikto_shellshock` | Shellshock (CVE-2014-6271) testing via custom HTTP headers |
| `nikto_optionsbleed` | Apache OPTIONS method information disclosure (CVE-2017-9798) |
| `nikto_apacheusers` | Apache ~user directory enumeration (if enabled with `-mutate 3`) |
| `nikto_sitefiles` | Common site configuration files (.htaccess, .git, .env, etc.) |
| `nikto_cookies` | Cookie-based detection rules |
| `nikto_content_search` | Content/string matching in response bodies from db_content_search |
| `nikto_multiple_index` | Multiple index file detection (index.html, index.php, index.asp, etc.) |
| `nikto_options` | HTTP OPTIONS method analysis (WebDAV, allowed methods) |
| `nikto_put_del_test` | PUT/DELETE method testing (dangerous methods) |

### 404 Detection and Response Filtering

**Critical to Nikto's accuracy:** Every scan begins with a **404 (Not Found) baseline detection** phase:
1. Request a deliberately non-existent URI (e.g., `/nikto_random_<timestamp>/`)
2. Store the response code, body, and headers
3. **All subsequent responses are compared** against this baseline to avoid false positives
4. Default assumption: any response that matches the 404 baseline is a negative/false-positive
5. Operator can override with `-no404` (disable baseline detection) or `-404code` / `-404string` (ignore specific codes/strings)

Without this step, a web server misconfigured to return a 200/OK for all missing pages would generate thousands of false positives.

### Scan Execution Pattern

```
For each URI in db_tests (default: thousands of entries):
  1. Choose HTTP method (GET for most, HEAD for efficiency checks, OPTIONS for method checks)
  2. Build request: GET /path HTTP/1.0 + headers (Host, User-Agent, custom headers, etc.)
  3. Send request (TCP 80 or 443 if -ssl)
  4. Receive response
  5. Match against DSL (CODE:, BODY:, HEADER:, COOKIE: matchers with && / | logic)
  6. If matched: log as finding + optionally save response to -Save directory
  7. Pause (if -Pause is set, default 0 — no pause, fire requests as fast as possible)
  8. Next test
```

**No waiting between requests by default** — a full scan can generate 50–500+ HTTP requests within seconds to minutes, making it highly visible in logs.

### Evasion Encoding Techniques

Nikto includes **8 built-in evasion techniques** (plus 2 variants) accessible via `-evasion`:

| Technique | What it does | Stealth value |
|---|---|---|
| `1` | Random URI encoding (non-UTF8) | Encoder-based, bypasses string-matching |
| `2` | Directory self-reference (`/./`) | `./ directory normalization` bypass |
| `3` | Premature URL ending | Server-parsing bypass (tricky encoding) |
| `4` | Prepend long random string | Path traversal/encoding bypass |
| `5` | Fake parameter | Parameter injection (e.g., `?param=value` appended) |
| `6` | TAB as request spacer | HTTP whitespace variation |
| `7` | Change case of URL | Case-folding bypass (e.g., `/ADMIN/` vs `/admin/`) |
| `8` | Windows directory separator (`\`) | Server-parsing bypass (IIS, etc.) |
| `A` | Carriage return (0x0d) as spacer | HTTP protocol variation |
| `B` | Binary 0x0b as spacer | HTTP protocol variation |

These can be **combined** (e.g., `-evasion 1,2,3`) and help defeat simple IDS/WAF string-matching rules, but they do **not change the fundamental scanning pattern** — requests still arrive in the same order, at the same rate, to the same paths.

### Output Formats and Reporting

Nikto supports **7 output formats** (specifiable via `-Format` and/or `-output` file extension):
- **csv** — Comma-separated values (parseable by scripts)
- **json** — JSON object array (machine-readable)
- **txt** — Plain text (human-readable console output)
- **html** — HTML report (viewable in browser)
- **xml** — XML (SIEM/tool ingestion)
- **sql** — SQL INSERT statements (for database import)
- **sqld** — SQL direct (live insert into MySQL/PostgreSQL via credentials in nikto.conf and env vars)

Default (if no `-Format` specified): output format is inferred from the `-output` filename extension.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| HTTP/HTTPS | Scan target is always HTTP(S) (TCP 80 or 443) — can probe alternate ports via `-port` |
| HTTP methods | GET (default), HEAD (efficiency), OPTIONS (method discovery), PUT/DELETE (dangerous-method testing) |
| HTTP headers | Sends standard headers (Host, User-Agent, Accept-Encoding, Connection); can add custom headers via `-Add-header` |
| SSL/TLS | Supports SSL/TLS (automatic on 443, forced with `-ssl`); can disable with `-nossl` |
| DNS | Uses system resolver unless `-nolookup` is set; supports IPv4 and IPv6 (selectable with `-ipv4`/`-ipv6`) |
| Virtual hosting | Virtual host support via `-vhost` (modifies Host header) |
| Authentication | Basic authentication via `-id user:pass:realm` or `-id user:pass` (default realm `http://target/`) |
| Proxy | Supports HTTP proxy via `-useproxy` (value: `http://proxyhost:port` or uses nikto.conf `PROXYIP`/`PROXYPORT`) |
| Client certificates | TLS client cert + key via `-RSAcert` / `-key` |
| Cookies | Stored/handled automatically (can disable with `-nocookies`); matches/tests via `COOKIE:` DSL |
| DSL matchers | Custom response-matching language (see Quick Reference, section Command-Line Switches) |

## Command-Line Switches — Quick Reference

Verified live against [`sullo/nikto` README.md](https://github.com/sullo/nikto#readme) and help output.

| Switch | Value | Purpose |
|---|---|---|
| `-host` | URL/IP | **Required** — target host or full URL (http://host or http://host:port). Alias: `-url` |
| `-port` | number | Port to scan (default 80); can specify multiple (e.g., `80,443,8080`) |
| `-ssl` | *none* | Force SSL/TLS on the specified port (default: SSL on 443) |
| `-nossl` | *none* | Disable SSL/TLS entirely |
| `-root` | /path | Prepend this path to all requests (e.g., `-root /app` turns `/admin/` into `/app/admin/`) |
| `-vhost` | hostname | Set Host header to this value (virtual host scanning) |
| `-id` | user:pass OR user:pass:realm | HTTP Basic authentication credentials |
| `-RSAcert` | /path/cert.pem | TLS client certificate file |
| `-key` | /path/key.pem | TLS client certificate key file |
| `-Add-header` | "Name: Value" | Add custom HTTP header (can use multiple times) |
| `-timeout` | seconds | Timeout per request (default 10) |
| `-maxtime` | 1h/60m/3600s | Maximum time for entire scan (will stop scanning once reached) |
| `-Pause` | seconds | Pause between requests (default 0 — no pause, rapid fire) |
| `-Cgidirs` | /cgi/,/bin/ OR all/none | CGI directories to scan (default: /cgi-bin/ + common variants) |
| `-mutate` | 1–6 | Guess additional file names: (1) all files in all dirs, (2) password files, (3) Apache ~user, (4) cgiwrap ~user, (5) subdomain brute-force, (6) dictionary brute-force |
| `-evasion` | 1–8,A,B | Encoding techniques for IDS/WAF evasion (can combine: `-evasion 1,2,3`) |
| `-config` | /path | Use alternate nikto.conf instead of default |
| `-Plugins` | name | Comma-separated plugin list to load (default: ALL); can use `@NONE` to disable all, then `@name` to enable specific ones (e.g., `-Plugins @NONE;@headers` loads only headers plugin) |
| `-list-plugins` | *none* | List all available plugins and exit (no scanning) |
| `-Tuning` | 0–f,a–e,x | Filter tests by tuning category (default: all). Examples: `-Tuning 0` (only file uploads), `-Tuning 1,2,3` (files, misconfigs, disclosure), `-Tuning x0,x1` (exclude file uploads and misconfigs). Categories: 0–9 (file upload, interesting file, misconfiguration, XSS, RFI, DoS, remote file, command exec, SQL injection), a–e (auth bypass, software ID, remote source inclusion, webservice, admin console) |
| `-Display` | 1–9,D,E,P,S,V | Display/output modifiers (can combine): 1=redirects, 2=cookies, 3=all 200/OK, 4=auth-required pages, D=debug, E=errors, P=progress, S=scrub IPs/hostnames, V=verbose |
| `-output` | filename | Write report to file; format inferred from extension (.html, .txt, .csv, .json, .xml, .sql) or use `-Format` |
| `-Format` | csv/json/html/txt/xml/sql/sqld | Specify output format (can use multiple separated by commas) |
| `-Save` | /path | Save positive responses (matching tests) to this directory; use '.' for auto-named subdirectory |
| `-followredirects` | *none* | Follow 3xx redirects to new locations (default: don't follow) |
| `-noslash` | *none* | Strip trailing slashes from URLs (e.g., `/admin/` → `/admin`) |
| `-no404` | *none* | Disable 404 baseline detection (dangerous — will increase false positives) |
| `-404code` | 302,301 | Treat these HTTP codes as negative responses (ignore them) |
| `-404string` | pattern | Treat responses containing this string/regex as negative (ignore them) |
| `-nocookies` | *none* | Do not store/use cookies from responses |
| `-useragent` | string | Custom User-Agent string (overrides random db_useragents selection) |
| `-ipv4` | *none* | Force IPv4 only |
| `-ipv6` | *none* | Force IPv6 only |
| `-nolookup` | *none* | Disable DNS lookups |
| `-nointeractive` | *none* | Disable interactive features (e.g., prompts) |
| `-nocheck` | *none* | Don't check for updates on startup |
| `-Platform` | nix/win/all | Assume target platform (filters some tests); default: all |
| `-check6` | *none* | Check if IPv6 is working (connects to ipv6.google.com or configured host) |
| `-dbcheck` | *none* | Validate database and config files for syntax errors, exit |
| `-Version` | *none* | Print plugin and database versions and exit |
| `-Help` | *none* | Print full help and exit |
| `-Userdbs` | all/tests | Load only user databases (udb_*, udbtests) instead of standard ones |

## Quick Use-Case List

- Basic web server reconnaissance (quick scan with default checks)
- Comprehensive vulnerability scan against a known web service
- Outdated software detection (Apache, IIS, OpenSSL, PHP versions)
- Dangerous HTTP method discovery (PUT, DELETE, TRACE, CONNECT)
- SSL/TLS certificate and configuration analysis (via -ssl flag and header plugins)
- Authentication realm enumeration (detecting Basic/Digest/NTLM/SPNEGO realms)
- CGI script detection in common directories (/cgi-bin/, /cgi-asp/, /cgi-sh/)
- Virtual host enumeration (scanning different Host header values)
- Backdoor/malware signature detection (web shells, known compromises via db_tests patterns)
- Default/sample file detection (admin panels, installation files, backup files)
- API endpoint discovery (scanning for common API paths: /api/, /REST/, /v1/)
- Evasion testing against IDS/WAF (using `-evasion` techniques to test detection coverage)
- Post-exploitation web-server analysis (assessing a compromised server's surface)
- CMS detection (Drupal, WordPress, Joomla, etc. via plugin/theme fingerprinting)
- WebDAV/dangerous method enumeration (testing for file write/delete capabilities)
- Custom database scanning (loading user-defined vulnerability signatures via -Userdbs)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Perl 5.x runtime | Nikto is a Perl script — requires Perl with basic modules (LW2/LibWhisker2 bundled). No compilation needed. |
| Network access to target | TCP 80 (HTTP) or 443 (HTTPS) to the target web server. Can specify alternate ports. |
| Target web service | Must be running and listening on the specified port. If the service is behind a WAF/proxy, Nikto will scan through that layer. |
| Disk space | Minimal — script and databases are ~2–5 MB. Output files can be large if `-Save` is used (one file per matching test). |
| Permissions (source host) | No privilege escalation needed. Can run as any user. |
| Permissions (target) | No special permissions on target needed — just network access to HTTP(S) service. |
| Configuration (optional) | `nikto.conf` allows default options; see program/nikto.conf.default for all settings (PROXYIP, PROXYPORT, RFIURL for Remote File Inclusion tests, etc.) |
| Virtual host resolution | If scanning a virtual host, ensure DNS resolves the hostname to the target, or use `-vhost` + an IP address directly |
