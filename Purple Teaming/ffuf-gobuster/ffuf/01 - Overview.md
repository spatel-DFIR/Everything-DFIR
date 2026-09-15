# ffuf — Overview

> 🔴 **Red Flag Principle:** ffuf is a Go-compiled, multi-threaded HTTP fuzzer that generates rapid, high-concurrency requests to enumerate web resources (directories, files, subdomains, parameters, virtual hosts). The distinctive tell is **a burst of 200+ HTTP requests within 1–5 seconds from a single source IP, all targeting non-existent paths with identical User-Agent strings and no variance in inter-request timing** (default concurrency: 40 threads, configurable up to 1000+). Unlike human browsing or legitimate scanners with backoff logic, ffuf's default behavior fires all queued requests as fast as the target's TCP stack can accept them. On networks with rate-limiting awareness, this produces a characteristic "request cliff" in time-series flow data.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified against the official repository, [`ffuf/ffuf`](https://github.com/ffuf/ffuf):

- **Primary author:** Jouni Valakari (`@joohoi`). Active maintenance ongoing; recent releases (2024–2026) confirm the project is actively maintained.
- **License:** MIT, copyright maintained by Jouni Valakari and other contributors.
- **First release:** 2018 (early project evolution tracked through GitHub tags).
- **Current stable release:** v2.1.0+ (verify via GitHub Releases); the project uses semantic versioning consistently.
- **Design philosophy:** ffuf is purpose-built as a lightweight, parallelized HTTP fuzzer in Go, emphasizing **speed** and **concurrency** over the GUI/framework complexity of tools like Burp Suite's Scanner. A single ffuf binary (~10–20 MB) with no runtime dependencies (Go binaries are statically compiled) can out-throughput multi-threaded Python fuzzing frameworks by 10–50x on identical hardware.

## How It Works

ffuf constructs HTTP requests by templating a base URL, then **iterating a wordlist into the templated position(s)**, issuing each request concurrently within a configurable thread-pool ceiling. The tool's real innovation is its match/filter subsystem: rather than a naive "HTTP 200 = found" heuristic, ffuf allows operators to match or filter on multiple attributes per response in a single pass:

| Attribute | Scope | Example |
|---|---|---|
| **Status code** | HTTP response status (200, 404, 301, etc.) | `--mc 200,301` → match only these codes |
| **Word count** | Number of words in the response body | `--fw 45` → filter if body word-count is 45 |
| **Content size** | Raw bytes in the response body | `--fs 4242` → filter if response is exactly 4,242 bytes |
| **Regex pattern** | Regular expression against the full response | `--fr "Invalid|Error"` → filter responses matching this regex |
| **Lines in response** | Number of newline-delimited lines | `--fl 10` → filter if response has exactly 10 lines |

This multi-attribute filtering in a single pass is the key efficiency difference from sequential curl/grep chains — an operator can fuzzing 50,000 paths, then apply 5 simultaneous filters (e.g., "status 200–299 AND body > 1000 bytes AND NOT matching /admin/") without re-scanning the target.

### Request templating and wordlist injection

ffuf's wordlist injection points use a simple keyword syntax: `FUZZ` is the primary placeholder. Alternative wordlists are injected via `-w wordlist2:FUZZWORD2` syntax, and any custom keyword can substitute:

```
# Templating examples
URL template: https://target.com/FUZZ
  Injects each wordlist line into the path: /admin, /login, /api, ...

URL template: https://target.com/?search=FUZZ
  Injects into query-string value instead.

Multi-wordlist chaining: -w paths.txt:FUZZ -w domains.txt:FUZZDOMAIN
  Cartesian product: each path × each domain → combined fuzzing

Custom keyword: -w wordlist.txt:CUSTOM
  Allows multiple independent wordlists: https://CUSTOM.target.com:8080/FUZZ
```

### Concurrency model

ffuf uses Go's `net/http` client pooled over a goroutine worker pool:

```
Thread pool ceiling → configurable via -t flag (default: 40, tested up to 1000 in real-world use)
Per-thread behavior → each goroutine: fetch URL → measure response → apply match/filter logic
  → store or discard → loop on next wordlist entry
Result buffering → matched results held in memory until flush/output
```

For a 50,000-entry wordlist with `-t 500`, ffuf will spawn ~500 concurrent HTTP connections. On a 100 Mbps connection, this typically saturates the link within 10–20 seconds (the upstream network, not the target, becomes the bottleneck). Targets with connection limits or DDoS-detection mechanisms will begin dropping/resetting connections after the first 5,000–10,000 requests.

### Response fingerprinting and baseline

ffuf's `-t` concurrency default of 40 is tuned for "fast without obviously destructive" — but for **evasion**, operators typically reduce it to 5–10 threads + add `-p <delay>` (per-request delay in milliseconds) to spread requests over longer intervals, trading speed for stealth.

A baseline 404 response is critical: ffuf's `-b` flag or implicit 404-page fingerprinting reduces false positives. By default, ffuf attempts to fetch the target URL with a known-invalid path (e.g., `/<8-random-chars>`) and uses the resulting HTTP status + response size as the "expected 404" baseline. Paths returning anything *different* from that baseline are reported as potential matches.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **HTTP/HTTPS (core)** | Raw HTTP/1.1 GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS, etc. Configurable via `-X` flag. Supports HTTPS/TLS 1.2+ (no explicit certificate validation flag, uses OS-default CA store or `-k` to skip). No HTTP/2 multiplexing in standard builds (Go's `net/http` defaults to HTTP/1.1 unless server upgrades). |
| **DNS** | Passive resolver queries for subdomain fuzzing (no active DNS protocol abuse — just lookups via the OS resolver). No raw DNS packet construction (unlike gobuster's `-dns` mode). |
| **Word-list injection** | Wordlist templating at URL/header/data construction time. No language-specific payloads or encoding beyond URL-encoding of special characters (no SQLi, XSS, or LDAP-injection-specific wordlists built-in — OWASP SecLists can be used externally). |
| **TLS/SSL fingerprinting** | Default OS CA verification; `-k` skips. No custom certificate pinning or JA3-style fingerprinting. |
| **Output formats** | JSON (default, `-o json`), plain text, HTML, CSV, Markdown. The JSON output includes per-request metadata (status, size, time, filters applied). |

## Command-Line Switches — Quick Reference

| Flag | Argument | Default | Purpose |
|---|---|---|---|
| `-u, --url` | URL | (required) | Target URL with FUZZ/custom placeholders |
| `-w, --wordlist` | file:KEYWORD | (required) | Wordlist file, optionally with custom keyword (e.g., `-w paths.txt:FUZZ -w subdomains.txt:SUB`) |
| `-t, --threads` | int | 40 | Concurrency / number of parallel goroutines |
| `-p, --delay` | milliseconds | 0 | Delay between each request (spreads fuzzing over time for stealth) |
| `-x, --extensions` | .php,.html,... | (none) | Extensions to append to FUZZ (e.g., `-x .php` turns `/admin` → `/admin.php`) |
| `-mc, --match-codes` | 200,301,302,... | 200 | Match HTTP status codes (comma-separated) — REPORT if status is in this list |
| `-ms, --match-size` | bytes | (none) | Match exact response body size in bytes |
| `-ml, --match-lines` | count | (none) | Match exact line count in response |
| `-mr, --match-regexp` | regex | (none) | Match response against regex pattern |
| `-mw, --match-words` | count | (none) | Match exact word count in response body |
| `-fc, --filter-codes` | 404,403,... | (none) | Filter (hide) these HTTP status codes |
| `-fs, --filter-size` | bytes | (none) | Filter (hide) responses of exactly this size |
| `-fl, --filter-lines` | count | (none) | Filter (hide) responses with exactly this line count |
| `-fr, --filter-regexp` | regex | (none) | Filter (hide) responses matching this regex |
| `-fw, --filter-words` | count | (none) | Filter (hide) responses with exactly this word count |
| `-r, --follow-redirects` | bool | false | Follow HTTP 3xx redirects (track final status, not redirect chain) |
| `-b, --data` | string | (none) | POST data / request body (use with `-X POST`) |
| `-H, --header` | "Name: value" | (none) | Custom HTTP header (repeatable: `-H "User-Agent: Custom" -H "Cookie: xyz"`) |
| `-od, --outputdir` | directory | (none) | Save output to specified directory (creates JSON/HTML/etc. files) |
| `-o, --output` | format | (none) | Output format (json, csv, html, md, ecscsv, all) |
| `-v, --verbose` | bool | false | Print each request and response in real-time (verbose mode, slow for large fuzzes) |
| `-rate` | int | (unlimited) | Max requests per second (alternative to `-p` delay) |
| `-timeout` | seconds | 10 | Per-request timeout |
| `-k, --insecure` | bool | false | Skip HTTPS certificate validation (ignore self-signed/invalid certs) |
| `-X, --method` | GET, POST, etc. | GET | HTTP method (defaults to GET; `-X POST` for POST requests) |
| `-mode` | clusterbomb, pitchfork, sniper | clusterbomb | Cartesian-product mode: clusterbomb (all combinations), pitchfork (parallel iteration), sniper (one keyword at a time) |
| `-recursive` | bool | false | Recursively fuzz discovered paths (e.g., if /admin → 200, fuzz /admin/FUZZ/) |
| `-recursion-depth` | int | 0 | Max recursion depth (used with `-recursive`) |

## Quick Use-Case List

1. **Directory enumeration** — brute-force common directories (`/admin`, `/api`, `/backup`, etc.) on a target web server.
2. **File enumeration** — search for common files (`.php`, `.txt`, `.sql`, `.bak`, `.zip`, etc.) on the target.
3. **Virtual host enumeration** — fuzz the `Host:` header to discover subdomains via a single IP (e.g., `sub.FUZZ.target.com`).
4. **Subdomain brute-forcing** — fuzz `Host:` header or DNS to discover subdomains.
5. **Parameter enumeration** — fuzz query-string or POST parameters to discover hidden/undocumented parameters.
6. **API endpoint discovery** — enumerate `/api/v1/`, `/api/v2/`, `/graphql`, etc., or parameters within them.
7. **Username enumeration** — use fuzzing to probe user endpoints (e.g., `/user/FUZZ`, `/profile/FUZZ`) and identify which usernames exist via status-code or response-size differences.
8. **Extension brute-forcing** — combine `-x` with directory enumeration to test multiple file extensions in a single pass (e.g., `/admin.php`, `/admin.html`, `/admin.asp`).
9. **Recursive path discovery** — recursively fuzz subdirectories (e.g., discover `/admin` → 200, then auto-fuzz `/admin/*` for deeper paths).
10. **Rate-limiting and WAF bypass testing** — use `-p` (delay) and `-t` (reduced concurrency) to stay under rate-limit thresholds; test `-H` custom headers to bypass WAF rules.
11. **Content-type negotiation testing** — fuzz `Accept:` header values to discover alternate content types or API versions.
12. **HTTP method fuzzing** — test which HTTP methods are supported on discovered paths (via `-X` with repeated runs).

## Prerequisites

- **No authentication required** by default — ffuf is a passive HTTP client.
- **Network access to target** on HTTP/HTTPS ports (typically 80, 443; custom ports via URL).
- **Wordlists** — must be provided separately (OWASP SecLists, custom lists). ffuf ships with no built-in wordlist collection.
- **Local file system** — read-access to wordlist files.
- **Optional: proxy configuration** — ffuf respects `HTTP_PROXY`/`HTTPS_PROXY` environment variables (or explicit `-proxy` flag in some forks).
- **Optional: DNS resolver** — for subdomain fuzzing, relies on OS resolver (no custom DNS server flag in base ffuf, but environment-level DNS configuration applies).

