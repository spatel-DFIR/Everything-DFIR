# Gobuster — Hands-On Use Cases

## Directory Enumeration Mode (`dir`) — HTTP Path Brute-Forcing (T1526)

**Objective:** Discover common directories on a target web server using HTTP requests.

```bash
# Basic directory fuzzing
gobuster dir -u https://target.com -w /path/to/common-paths.txt

# Match only 200 responses (default behavior)
gobuster dir -u https://target.com -w /path/to/common-paths.txt -sc 200

# Match multiple status codes (200, 301, 302)
gobuster dir -u https://target.com -w /path/to/common-paths.txt -sc 200,301,302

# Append file extensions (.php, .html, .asp)
gobuster dir -u https://target.com -w /path/to/files.txt -x .php,.html,.asp

# Verbose output to see each request
gobuster dir -u https://target.com -w /path/to/common-paths.txt -v

# Skip HTTPS certificate validation
gobuster dir -u https://target.com -w /path/to/common-paths.txt -k

# Save results to file
gobuster dir -u https://target.com -w /path/to/common-paths.txt -o results.txt

# Increase concurrency (use 50 threads instead of default 10)
gobuster dir -u https://target.com -w /path/to/common-paths.txt -t 50

# Add delay between requests (100ms) for stealth
gobuster dir -u https://target.com -w /path/to/common-paths.txt --delay 100

# Reduce concurrency AND add delay for stealth
gobuster dir -u https://target.com -w /path/to/common-paths.txt -t 5 --delay 200

# Custom User-Agent
gobuster dir -u https://target.com -w /path/to/common-paths.txt -U "Mozilla/5.0"
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery (active information gathering).
- **T1595.002** — Vulnerability Scanning (active scanning to identify resources).

---

## DNS Subdomain Enumeration Mode (`dns`) — DNS Brute-Forcing (T1589.001)

**Objective:** Discover subdomains via DNS queries (faster than HTTP-based virtual-host fuzzing at scale).

```bash
# Basic DNS subdomain enumeration
gobuster dns -d target.com -w /path/to/subdomains.txt

# Verbose output to see each query
gobuster dns -d target.com -w /path/to/subdomains.txt -v

# Use custom DNS resolver (e.g., Google DNS)
gobuster dns -d target.com -w /path/to/subdomains.txt -r 8.8.8.8:53

# Use internal corporate DNS resolver
gobuster dns -d target.com -w /path/to/subdomains.txt -r 10.0.0.1:53

# Enable wildcard DNS detection (filter out catch-all responses)
gobuster dns -d target.com -w /path/to/subdomains.txt -z

# Wildcard detection with verbose output
gobuster dns -d target.com -w /path/to/subdomains.txt -z -v

# Increase DNS query concurrency (default 16)
gobuster dns -d target.com -w /path/to/subdomains.txt -t 32

# Increase timeout for slow DNS servers
gobuster dns -d target.com -w /path/to/subdomains.txt --timeout 30s

# Save DNS results to file
gobuster dns -d target.com -w /path/to/subdomains.txt -o dns-results.txt

# Slow DNS fuzzing with delays
gobuster dns -d target.com -w /path/to/subdomains.txt -t 5 --delay 100
```

**MITRE ATT&CK mappings:**
- **T1589.001** — Gather Victim Identity Information: Credentials (discovering subdomains for targeting).
- **T1590.002** — Gather Victim Network Information: DNS.

---

## Virtual-Host Enumeration Mode (`vhost`) — Host Header Fuzzing (T1590.002)

**Objective:** Discover subdomains/virtual hosts via `Host:` header injection (alternative to ffuf's `-H` flag).

```bash
# Basic virtual-host enumeration (requires target's IP or domain)
gobuster vhost -u https://target.com -w /path/to/subdomains.txt

# Virtual-host enumeration against a specific IP (bypasses DNS resolution)
gobuster vhost -u https://192.168.1.100 -w /path/to/subdomains.txt

# Match multiple status codes
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -sc 200,301,302

# Verbose output
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -v

# Skip HTTPS certificate validation
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -k

# Custom User-Agent
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -U "Mozilla/5.0"

# Save results
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -o vhost-results.txt

# Stealth virtual-host enumeration (low concurrency + delay)
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -t 3 --delay 500
```

**MITRE ATT&CK mappings:**
- **T1590.002** — Gather Victim Network Information: DNS / Network Topology.

---

## File Enumeration with Extensions (T1526)

**Objective:** Discover specific file types (.php, .config, .sql, .bak) on the target.

```bash
# Search for PHP files
gobuster dir -u https://target.com -w /path/to/files.txt -x .php

# Search for backup files
gobuster dir -u https://target.com -w /path/to/files.txt -x .bak,.backup,.old

# Search for configuration files
gobuster dir -u https://target.com -w /path/to/files.txt -x .conf,.config,.xml

# Search for multiple extensions at once
gobuster dir -u https://target.com -w /path/to/common.txt -x .php,.html,.js,.css,.asp

# Combine directory and file extension enumeration
gobuster dir -u https://target.com -w /path/to/dirs.txt -x .php --delay 100
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery.

---

## API Endpoint Discovery (T1526)

**Objective:** Discover API endpoints (e.g., `/api/v1/`, `/api/v2/`, etc.).

```bash
# Basic API path enumeration
gobuster dir -u https://api.target.com -w /path/to/api-endpoints.txt

# Match 200 and 400-level responses (some APIs return 401/403 for existing endpoints)
gobuster dir -u https://api.target.com/v1 -w /path/to/api-endpoints.txt -sc 200,400,401,403

# Verbose mode to see all responses
gobuster dir -u https://api.target.com -w /path/to/api-endpoints.txt -v

# Search for common API structure patterns
gobuster dir -u https://target.com/api/v1 -w /path/to/users_endpoints.txt
gobuster dir -u https://target.com/api/v2 -w /path/to/users_endpoints.txt
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery (discovering API infrastructure).

---

## Rate-Limited / Stealthy Fuzzing (T1087)

**Objective:** Enumerate targets with rate-limiting or WAF protections using reduced concurrency and delays.

```bash
# Reduce concurrency to 1 thread
gobuster dir -u https://target.com -w /path/to/wordlist.txt -t 1

# Add 500ms delay between requests
gobuster dir -u https://target.com -w /path/to/wordlist.txt --delay 500

# Combine: 1 thread + 500ms delay (very slow, ~2 requests per second)
gobuster dir -u https://target.com -w /path/to/wordlist.txt -t 1 --delay 500

# Custom User-Agent (avoid "gobuster" fingerprint)
gobuster dir -u https://target.com -w /path/to/wordlist.txt \
  -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Increase timeout for slow responses
gobuster dir -u https://target.com -w /path/to/wordlist.txt --timeout 30s

# Combined stealth approach
gobuster dir -u https://target.com -w /path/to/wordlist.txt \
  -t 2 --delay 1000 --timeout 30s \
  -U "Mozilla/5.0 (X11; Linux x86_64)"
```

**MITRE ATT&CK mappings:**
- **T1087** — Account Discovery (enumerating accounts despite rate-limiting).
- **T1518.001** — Software Discovery: Security Software Discovery (detecting WAF/IPS via response analysis).

---

## Comparison: gobuster `dir` vs. ffuf for Similar Tasks

**Same objective: enumerate `/admin`, `/api`, `/backup` on target.com**

```bash
# gobuster approach (10 threads, default 404-baseline filtering)
gobuster dir -u https://target.com -w /path/to/common.txt -sc 200 -v

# ffuf approach (40 threads, explicit filter chains)
ffuf -u https://target.com/FUZZ -w /path/to/common.txt -mc 200 -v

# Difference:
# - gobuster: ~10-50 requests/sec (default 10 threads)
# - ffuf: ~40-200 requests/sec (default 40 threads)
# - gobuster: single status-code matching (-sc)
# - ffuf: flexible chained filters (-mc, -fs, -fw, -fr)
# - gobuster: simpler, faster for basic directory enumeration
# - ffuf: slower but more flexible for complex filtering scenarios
```

**Speed comparison (on same wordlist, same target):**
```bash
time gobuster dir -u https://target.com -w /path/to/10k-entries.txt -t 20
# Completed in ~45 seconds

time ffuf -u https://target.com/FUZZ -w /path/to/10k-entries.txt -t 20
# Completed in ~30 seconds (faster due to keep-alive reuse)
```

---

## Output and Reporting

**Objective:** Save enumeration results for analysis and documentation.

```bash
# Save results to plain text file
gobuster dir -u https://target.com -w /path/to/wordlist.txt -o results.txt

# View results
cat results.txt
# Output:
# https://target.com/admin (Status: 200)
# https://target.com/api (Status: 301)
# https://target.com/backup (Status: 200)

# Save DNS results
gobuster dns -d target.com -w /path/to/subdomains.txt -o dns-results.txt

# Save vhost results
gobuster vhost -u https://target.com -w /path/to/subdomains.txt -o vhost-results.txt
```

**MITRE ATT&CK mappings:**
- **T1123** — Capture artifacts for logging/documentation.

