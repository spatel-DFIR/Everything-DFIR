# ffuf & Gobuster — Suite Overview

> **Purpose of this folder:** Two modern, Go-compiled web fuzzing tools optimized for directory and subdomain enumeration. Both are **same-purpose alternatives** — operators choose between them based on speed, flexibility, and feature depth rather than distinct operational contexts. This overview compares them and provides shared reconnaissance tactics applicable to both.

## Quick Table of Contents

1. **[Tool Comparison](#tool-comparison)** — Speed, features, modes, use-case fit
2. **[Shared Reconnaissance Workflow](#shared-reconnaissance-workflow)** — Typical attack chain combining both or either tool
3. **[Wordlist Resources](#wordlist-resources)** — Common wordlists for both tools
4. **[Rate-Limiting and Evasion](#rate-limiting-and-evasion)** — Shared stealth tactics
5. **[Red-Flag Detection Signal](#red-flag-detection-signal)** — The single most distinctive shared indicator

---

## Tool Comparison

| Aspect | ffuf | gobuster | Winner | Notes |
|---|---|---|---|---|
| **Language** | Go (statically compiled) | Go (statically compiled) | Equal | Both ~10–20 MB, no dependencies |
| **Default User-Agent** | `ffuf/2.1.0` | `gobuster/3.5.0` | Equal | Both identifiable; both easily spoofed |
| **Primary modes** | Single URL-template mode | Three modes: `dir`, `dns`, `vhost` | **gobuster** | gobuster's dedicated `dns` mode is faster than HTTP vhost fuzzing |
| **Default concurrency** | 40 threads | 10 threads | **ffuf** | ffuf's higher default = faster enumeration (but noisier) |
| **Flexibility** | High (URL templating, multi-wordlist chaining, `-mode` variants) | Low (single URL appending, no multi-wordlist mixing) | **ffuf** | ffuf's `-mode clusterbomb` and wordlist chaining enable complex scenarios |
| **Response filtering** | High (status, size, words, lines, regex: `-mc/-fs/-fw/-fr`) | Low (status only: `-sc`) | **ffuf** | ffuf's filter chains beat gobuster's single `-sc` flag |
| **Speed (dir mode)** | ~200 req/sec (40 threads, keep-alive) | ~50 req/sec (10 threads) | **ffuf** | ffuf is 4–5x faster on identical hardware due to concurrency |
| **Speed (DNS mode)** | N/A (HTTP only) | ~1000 queries/sec (16 threads) | **gobuster** | gobuster's `dns` mode is dedicated and optimized for DNS |
| **Evasion options** | `-t` (threads), `-p` (delay), `-H` (headers), `-r` (follow redirects) | `-t` (threads), `--delay`, `-U` (User-Agent) | **ffuf** | ffuf's `-H` custom headers give more control |
| **Output formats** | JSON, CSV, HTML, Markdown (multiple via `-of`) | Plain text only | **ffuf** | JSON/CSV output is better for automation and integration |
| **Recursion** | `-recursive` flag with `-recursion-depth` | None (v3.x removed recursive mode) | **ffuf** | ffuf's built-in recursion is a major feature; gobuster requires external scripting |
| **Learning curve** | Moderate (many flags, URL templating syntax) | Shallow (three modes, simple flags) | **gobuster** | gobuster is simpler for beginners; ffuf for advanced scenarios |
| **Maintenance status** | Active (2024–2026 commits) | Active (2024–2026 commits) | Equal | Both projects are maintained |

---

## Shared Reconnaissance Workflow

### Typical Enumeration Chain (Multi-Stage)

**Stage 1: Initial Information Gathering (both tools, minimal noise)**

```bash
# 1a. Passive DNS reconnaissance (external, not against target)
# Use DNS/OSINT tools like massdns, public DNS databases

# 1b. Gentle HTTP probing (low concurrency, check what's listening)
ffuf -u https://target.com/FUZZ -w /path/to/small-wordlist.txt -t 5 -p 100 --mc 200,301
gobuster dir -u https://target.com -w /path/to/small-wordlist.txt -t 5 --delay 100
```

**Stage 2: Subdomain Discovery (choose gobuster `dns` mode if possible, or ffuf vhost)**

```bash
# 2a. Fast DNS enumeration (gobuster's strength)
gobuster dns -d target.com -w /path/to/subdomains.txt -t 16 -z
# Discovers: admin.target.com, api.target.com, staging.target.com, ...

# 2b. Alternative: HTTP virtual-host fuzzing (if DNS is blocked/unreliable)
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt -t 10

# 2c. Resolve discovered subdomains
for sub in $(cat dns-results.txt | cut -d: -f1); do
  echo "$sub: $(dig +short $sub A)"
done
```

**Stage 3: Directory Enumeration on Each Subdomain (heavy scanning, higher concurrency)**

```bash
# 3a. Fast directory enumeration with ffuf (flexible filtering)
ffuf -u https://admin.target.com/FUZZ -w /path/to/common-dirs.txt -mc 200,301 -fs 5242 -v

# 3b. Alternative: gobuster dir with aggressive settings
gobuster dir -u https://admin.target.com -w /path/to/common-dirs.txt -t 50 -sc 200,301

# 3c. Add file extensions for deeper coverage
ffuf -u https://admin.target.com/FUZZ -w /path/to/common-files.txt -x .php,.html,.config -mc 200
```

**Stage 4: API Endpoint Discovery (target `/api/v1/`, `/api/v2/`, etc.)**

```bash
# 4a. Parameter fuzzing on discovered API endpoints
ffuf -u "https://api.target.com/v1/FUZZ" -w /path/to/api-endpoints.txt -mc 200,400

# 4b. Deep API path enumeration
gobuster dir -u https://api.target.com/v1 -w /path/to/api-paths.txt -sc 200,400,401,403

# 4c. Multi-stage API chaining
ffuf -u "https://api.target.com/v1/users/FUZZ" -w /path/to/user-endpoints.txt -recursive
```

**Stage 5: Post-Processing (convert results for targeting)**

```bash
# Consolidate results
cat ffuf-results.json | jq '.results[] | .url' | sort -u > all-discovered-paths.txt
cat gobuster-results.txt | sort -u >> all-discovered-paths.txt

# Feed into next-stage tools (vulnerability scanners, exploitation frameworks)
```

---

## Wordlist Resources

Both ffuf and gobuster accept standard wordlist formats (one entry per line, UTF-8 encoding).

### Recommended Wordlist Sources

| Purpose | Wordlist Source | Size | Notes |
|---|---|---|---|
| **Directory enumeration** | OWASP SecLists `/Discovery/Web-Content/common.txt` | ~7,000 paths | Industry standard; covers /admin, /api, /backup, /config, etc. |
| **Directory enumeration (large)** | `raft-large-directories.txt` | ~62,000 paths | More comprehensive; slower but catches obscure directories |
| **File enumeration** | `common.txt` or `raft-large-files.txt` | ~7,000–185,000 files | Extensions: .php, .html, .asp, .jsp, .txt, .sql, .config |
| **Subdomain discovery** | `subdomains-top1million-5000.txt` or `subdomains-10000.txt` | ~5,000–10,000 | Common subdomains (api, admin, mail, ftp, vpn, etc.) |
| **Subdomain (comprehensive)** | `subdomains-1000000.txt` | ~1 million entries | Very slow; used only on high-concurrency networks |
| **API endpoints** | Custom wordlists or `api-endpoints.txt` (community-maintained) | Variable | API-specific: /users, /posts, /payments, /search, etc. |
| **Virtual hosts** | `subdomains-*.txt` (same as subdomain lists, applied via Host header) | Variable | Same wordlist, different injection method |

**Wordlist location (if installed):**
```
/usr/share/SecLists/Discovery/Web-Content/
/opt/SecLists/Discovery/Web-Content/
~/.local/share/SecLists/
```

**Custom wordlist generation:**
```bash
# Extract from live source (web archives, past scans, code repositories)
cat wayback_urls.txt | sed 's|.*/||' | cut -d? -f1 | sort -u > custom-paths.txt

# Generate from known structures
echo -e "/admin\n/api\n/backup\n/config\n/users\n/posts" > simple-wordlist.txt
```

---

## Rate-Limiting and Evasion

### Common Target Defenses

| Defense | Indicator | Evasion Strategy | Tool Flag |
|---|---|---|---|
| **HTTP rate-limiting (429 Too Many Requests)** | 429 status code after N requests | Reduce concurrency, add delays | `-t 1 --delay 1000` (gobuster) or `-t 1 -p 1000` (ffuf) |
| **Connection throttling** | TCP RST/connection resets after N connections | Reduce threads, increase timeout | `-t 5 --timeout 30s` (gobuster) or `-t 5 --timeout 30` (ffuf) |
| **IP-based blocking** | Blocking by source IP after detection | Use proxy/VPN, rotate IPs, proxy chaining | `HTTP_PROXY` environment or firewall reroute |
| **Custom 404 pages** | All responses return 200 with "not found" text | Use response-size/word-count filtering | `--fw 45` or `--fs 5242` (ffuf only; gobuster lacks this) |
| **WAF rules** | Cloudflare, ModSecurity, AWS WAF blocks | Vary User-Agent, slow down, avoid signatures | `-U` (gobuster/ffuf) or custom `-H` headers (ffuf) |
| **DNS rate-limiting** | DNS server returns REFUSED after N queries | Use alternate DNS resolver | `-r custom.dns.server:53` (gobuster `dns` mode only) |

### Stealth Configuration (Both Tools)

**For low-noise, long-duration enumeration:**

```bash
# ffuf stealth mode
ffuf -u https://target.com/FUZZ -w wordlist.txt \
  -t 2 -p 2000 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Cookie: fake_session=xyz" \
  --timeout 30

# gobuster stealth mode
gobuster dir -u https://target.com -w wordlist.txt \
  -t 2 --delay 2000 \
  -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

**Speed expectations:**
- Default (40/10 threads, 0 delay): ~100–200 requests/sec per tool
- Stealth (2 threads, 2000ms delay): ~0.5 requests/sec per tool
- Trade-off: 4–5x slower, but significantly less detectable

---

## Red-Flag Detection Signal

### The Single Most Distinctive Indicator (Shared Across Both Tools)

**Rapid sequential HTTP requests (or DNS queries) to non-existent paths from a single source IP, with high 404 rate, within a compressed time window.**

**Characteristics:**
- **Volume:** 100+ unique requests within 10 seconds
- **Pattern:** Systematic path enumeration (e.g., `/admin`, `/api`, `/backup`, `/config`, then `/admin.php`, `/api.php`, etc.) — not random or user-browsing-like
- **Status distribution:** >90% 404s, occasional 200s/301s/403s (opposite of legitimate browsing)
- **Source:** Single IP address
- **User-Agent:** Either `ffuf/[VERSION]` or `gobuster/[VERSION]` (or spoofed, but same for all requests)
- **Timing:** Bursts of 10–50 requests per second (varies by tool concurrency setting)

**Examples of distinctive sequences in access logs:**

```
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /admin HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /api HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /backup HTTP/1.1" 200 3240 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /config HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /admin.php HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
203.0.113.50 - - [12/Aug/2026:14:32:45] "GET /api.php HTTP/1.1" 404 5242 "-" "ffuf/2.1.0"
...
(500 more in similar fashion)
```

**Why this signal survives most evasion:**
- Changing the User-Agent (via `-U` flag) only hides tool identity, not the pattern
- Adding delays (via `--delay` or `-p`) spreads the pattern over time but doesn't eliminate it
- The systematic enumeration of a wordlist is the core behavior; it's what the tool *does*
- Evasion is possible (very slow fuzzing, randomized paths, proxy rotation) but requires operational discipline most attackers lack

**Detection is hard to evade completely, but easy to make slower and less obvious** — the trade-off between speed and stealth is inherent to enumeration tooling.

---

## Inline Cross-References

- **[ffuf/ — All files]** — Deep technical details, per-file structure
- **[gobuster/ — All files]** — Deep technical details, per-file structure
- **[Windows/12 - Lateral Movement]** — Lateral movement context for discovered resources
- **[Windows/23 - Special Services/IIS - Web Server Forensics]** — IIS-specific log analysis
- **[Linux/06 - Logs/Authentication and Login Records]** — Logging on Linux web servers
- **[Cloud/Microsoft/Entra ID/]** — Cloud API discovery context
- **[NetExec/]** — Credential validation at scale (often follows enumeration)
- **[Hydra/]** — Credential spraying (often paired with discovered endpoints)

---

## Summary: Choosing Between ffuf and Gobuster

| Scenario | Recommended | Why |
|---|---|---|
| **DNS subdomain enumeration** | **gobuster dns** | Dedicated mode, 1000s queries/sec, purpose-built |
| **HTTP directory enumeration with complex filtering** | **ffuf** | Flexible filter chains (-mc, -fs, -fw, -fr, -mr) |
| **Fast directory enumeration, simple criteria** | **gobuster dir** | Simpler interface, 10 threads (less noisy) |
| **Recursive path discovery** | **ffuf** | `-recursive` flag; gobuster v3.x doesn't support it |
| **Multi-wordlist cartesian-product fuzzing** | **ffuf** | `-w wordlist1:FUZZ1 -w wordlist2:FUZZ2` syntax |
| **Large-scale recon with rate-limit evasion** | **Either** | Use stealth flags (--delay, -t, -U) on both |
| **JSON output for automation/integration** | **ffuf** | Native JSON; gobuster outputs plain text |
| **Lightweight tool for quick checks** | **gobuster** | Simpler, fewer options, smaller learning curve |
| **Parameter fuzzing (query strings)** | **ffuf** | Supports URL templating in any position |
| **Post-exploitation, quick internal scan** | **gobuster dir** | Fast with default settings, minimal overhead |

**Bottom line:** ffuf for **flexibility and power**; gobuster for **simplicity and speed** in specific modes (especially `dns`). Both are actively maintained. Operators typically use both interchangeably depending on the specific task.

