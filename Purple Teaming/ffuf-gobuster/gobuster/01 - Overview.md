# Gobuster — Overview

> 🔴 **Red Flag Principle:** gobuster is a Go-compiled, multi-threaded utility for directory brute-forcing, DNS subdomain enumeration, and virtual-host discovery. Unlike ffuf's URL-template flexibility, gobuster operates in three distinct **modes** (`dir`, `dns`, `vhost`), each with different protocol targets and evasion signatures. The characteristic tell is **a sequential, methodical flood of HTTP requests (or DNS queries) from a single source, often with visible CLI-derived patterns in User-Agent and request timing** — gobuster's default concurrency (10 threads) is more conservative than ffuf (40), but the underlying pattern remains: 50+ requests/sec to a single target, overwhelming 404s, and rapid-fire connection establishment. Unlike ffuf's flexible filter chains, gobuster uses a single `-sc` (status-code match) or implicit 404-baseline filtering, making it less flexible for complex response-analysis scenarios.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified against the official repository, [`OJ/gobuster`](https://github.com/OJ/gobuster):

- **Primary author:** OJ Reeves (`@TheColonial`), GitHub handle OJ. Active development and maintenance ongoing; recent commits confirm active project status (2024–2026).
- **License:** Apache 2.0, copyright originally held by OJ Reeves.
- **First release:** ~2015 (early Go-based directory brute-forcing tool, pre-dating ffuf by ~2 years).
- **Current stable release:** v3.x (v3.5.0+; verify via GitHub Releases); uses semantic versioning. Note: v3.0 was a major rewrite (2020), abandoning the earlier Python version.
- **Design philosophy:** gobuster prioritizes **speed** and **simplicity** — a single binary (~10–15 MB), no dependencies, with three focused modes (dir, dns, vhost). Less flexible than ffuf's URL templating, but faster at pure directory brute-forcing due to Go's concurrency model and minimal overhead.

---

## How It Works

gobuster operates in three independent modes, each with its own protocol and wordlist-injection strategy:

### 1. Directory Enumeration Mode (`dir`)

The default mode, functionally similar to ffuf's directory fuzzing:

```
Base URL → Append wordlist entries → Issue HTTP request
https://target.com/ → wordlist (admin, backup, api, ...) 
  → https://target.com/admin, https://target.com/backup, https://target.com/api, ...
```

**HTTP request construction:**
- Default method: **GET**
- Default User-Agent: **gobuster/3.x** (version-specific; identifiable)
- Header behavior: No custom header injection flags (unlike ffuf's `-H`), but `-U` allows User-Agent override
- Concurrency: Default **10 threads** (configurable via `-t`), conservative compared to ffuf's 40

**404-baseline establishment:**
- gobuster automatically requests the root URL with a known-invalid path (e.g., `/<8-random>`) to establish the 404 signature
- All responses matching the baseline are filtered out by default
- No explicit baseline configuration flag (unlike some tools)

**Response matching:**
- Match HTTP status codes via `-sc` (e.g., `-sc 200,301,302`)
- **No response-size or word-count filtering** — unlike ffuf, gobuster lacks `-fs`, `-fw`, `-fr` equivalents
- Default behavior: report everything that doesn't match the 404 baseline

### 2. DNS Subdomain Enumeration Mode (`dns`)

A **parallel DNS resolver**, not HTTP-based:

```
Wordlist entry → DNS A/AAAA record query
admin, api, backup, ... → Resolve admin.target.com, api.target.com, backup.target.com, ...
```

**DNS-specific behavior:**
- Queries the OS resolver by default (or custom resolver via `-r` flag)
- Concurrency: Up to **16 simultaneous DNS queries** (default, configurable via `-t`)
- **No baseline establishment** — all successful resolutions (non-NXDOMAIN) are reported
- Output: discovered hostname + IP address (if resolved)
- Wildcard detection: `-z` flag enables wildcard-DNS detection (queries `<8-random>.target.com` and filters matched IPs)

**DNS query types:**
- Default: A/AAAA records (hostname → IPv4/IPv6)
- Customizable (if fork supports): NS, MX, TXT, SRV records

### 3. Virtual-Host Enumeration Mode (`vhost`)

**HTTP Host header fuzzing** — similar to ffuf's `-H "Host: FUZZ.target.com"`, but dedicated:

```
Base URL (resolved IP or domain) → Inject Host header wordlist entries
https://192.168.1.100 + Host: admin.target.com, api.target.com, backup.target.com
```

**Mechanics:**
- Requests use the **target's IP address** (not domain), but vary the `Host:` header
- 404-baseline same as `dir` mode (request with random Host header value)
- Useful for discovering subdomains on shared IP hosting (virtual hosting)
- Concurrency: Default **10 threads** (same as `dir`)

---

## Request Construction and Concurrency

gobuster's concurrency model is similar to ffuf but uses a **fixed thread-pool ceiling** (default 10, not 40):

```
Thread pool: 10 goroutines (default, configurable via -t)
Per-thread loop: fetch URL → measure response → match/filter → loop on next wordlist entry
Connection pooling: Go's http.Client reuses TCP connections via Keep-Alive (more efficient than ffuf's default)
Result buffering: In-memory results, flushed to stdout or file on completion
```

**Timing characteristics:**
- At 10 threads × 1000-entry wordlist on a 100 Mbps link ≈ **~500 requests/sec at peak**
- Default `--delay` is 0 milliseconds; evasion variants use `--delay` or `--timeout` to spread requests over time
- Default `--timeout` is 10 seconds per request (configurable)

---

## Modes Comparison

| Feature | `dir` (HTTP) | `dns` (DNS) | `vhost` (HTTP Host header) |
|---|---|---|---|
| **Protocol** | HTTP/HTTPS GET | DNS A/AAAA queries | HTTP GET with Host header |
| **Concurrency default** | 10 threads | 16 queries | 10 threads |
| **Wordlist injection** | Path appending | Domain name | Host header |
| **404-baseline** | Implicit (random path) | N/A (all NXDOMAIN filtered) | Implicit (random Host header) |
| **Output** | HTTP status + size | Hostname + IP | HTTP status + size |
| **Network signature** | HTTP request burst | DNS query burst | HTTP request burst (Host header variant) |

---

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **HTTP/HTTPS (dir, vhost)** | Raw HTTP/1.1 GET requests over TCP/TLS. Default User-Agent: `gobuster/3.x`. HTTPS uses Go's default TLS 1.2+ (configurable cipher suite via OS-level TLS settings). No HTTP/2 support in base gobuster (HTTP/1.1 only). Keep-Alive connection reuse (default). |
| **DNS (dns mode)** | DNS A/AAAA record queries over UDP/53 (or custom resolver via `-r`). **No DNSSEC validation** by default. Wildcard detection via `<8-random>` query pattern and result-IP filtering. No raw DNS packet construction — uses Go's `net.LookupHost()` API. |
| **Word-list injection** | Direct string concatenation (no templating engine like ffuf). Wordlist format: one entry per line. No multi-wordlist chaining. |
| **TLS/SSL** | Default Go TLS client with OS CA store. `-k` flag skips HTTPS certificate validation. No JA3 fingerprinting. |
| **Output formats** | Plain text (stdout), plain text file (default for `-o`), no JSON/CSV/HTML variants built-in (unlike ffuf). |

---

## Command-Line Switches — Quick Reference

| Flag | Argument | Default | Mode(s) | Purpose |
|---|---|---|---|---|
| `-m, --mode` | dir\|dns\|vhost | dir | All | Select operating mode (directory, DNS, or virtual-host) |
| `-u, --url` | URL | (required for dir, vhost) | dir, vhost | Base URL (for `dir` mode, appends wordlist entries; for `vhost`, uses domain/IP) |
| `-w, --wordlist` | file | (required) | All | Wordlist file path (one entry per line) |
| `-t, --threads` | int | 10 (dir, vhost), 16 (dns) | All | Number of concurrent threads/queries |
| `--delay` | milliseconds | 0 | All | Delay between requests (spreads fuzzing for stealth) |
| `--timeout` | seconds | 10 | All | Per-request timeout |
| `-x, --extensions` | .php,.html,... | (none) | dir | Extensions to append to wordlist entries |
| `-sc, --status-codes` | 200,301,302,... | 200 | dir, vhost | Match (report) these HTTP status codes |
| `-k, --insecure` | bool | false | dir, vhost | Skip HTTPS certificate validation |
| `-U, --useragent` | string | gobuster/3.x | dir, vhost | Custom User-Agent (default is `gobuster/[version]`) |
| `-o, --output` | file | (none) | All | Write results to file (plain text, one result per line) |
| `-v, --verbose` | bool | false | All | Verbose output (print each request/response in real-time) |
| `-r, --resolver` | IP:port | (OS resolver) | dns | Custom DNS resolver (e.g., `8.8.8.8:53`) |
| `-z, --wildcards` | bool | false | dns | Detect and filter wildcard DNS responses |
| `-b, --body` | bool | false | dir, vhost | Print response body (verbose only) |
| `--follow-redirect` | bool | false | dir, vhost | Follow HTTP 3xx redirects |
| `--skip-ssl-verification` | bool | false | dir, vhost | Alias for `-k` (skip HTTPS cert validation) |

---

## Quick Use-Case List

1. **Directory enumeration** — brute-force common directories (`/admin`, `/api`, `/backup`, etc.) — classic use case, primary value proposition.
2. **File enumeration** — search for files (`.php`, `.txt`, `.config`, `.bak`, etc.) via `-x` extension appending.
3. **Subdomain discovery via DNS** — use `dns` mode to enumerate subdomains (faster than HTTP vhost fuzzing at scale).
4. **Virtual-host enumeration** — use `vhost` mode to discover subdomains via Host header injection (alternative to ffuf's `-H`).
5. **API endpoint discovery** — fuzz `/api/v1/`, `/api/v2/`, etc., on targets with known API structures.
6. **Recursive directory discovery** — older gobuster versions supported `-r` (recursive); v3.x requires manual chaining or external scripting.
7. **Wildcard DNS filtering** — use `dns` mode with `-z` to ignore wildcard-DNS catch-all responses.
8. **Custom resolver usage** — fuzz with non-standard DNS servers (e.g., internal corporate DNS) via `-r`.
9. **Rate-limited target fuzzing** — use `--delay` and `-t` to slow down fuzzing for stealth.
10. **Authentication-free reconnaissance** — no pre-authentication required (unlike some API scanners).
11. **Lightweight scanning** — single ~10 MB binary with no runtime dependencies (contrast with Python/Node frameworks).
12. **Competitive scanning** — compare gobuster's `dir` mode speed vs. ffuf's speed to establish performance baselines.

---

## Prerequisites

- **No authentication required** by default — gobuster is a passive HTTP client (for `dir`/`vhost` modes) or DNS client (for `dns` mode).
- **Network access to target** — HTTP/HTTPS ports (typically 80, 443) for `dir`/`vhost`; DNS port 53 for `dns` mode.
- **Wordlists** — must be provided separately (OWASP SecLists or custom). gobuster ships with no built-in wordlist.
- **Local file system** — read-access to wordlist files.
- **Optional: custom DNS resolver** — for `dns` mode, can specify via `-r` (e.g., internal corporate DNS server).
- **Optional: proxy configuration** — `dir`/`vhost` modes respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables (requires Go 1.8+).

