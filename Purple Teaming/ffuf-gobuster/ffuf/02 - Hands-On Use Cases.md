# ffuf — Hands-On Use Cases

## Directory Enumeration (T1526 – Cloud Service Discovery / T1595.002 – Vulnerability Scanning)

**Objective:** Discover common directories on a target web server.

```bash
# Basic directory fuzzing with default settings
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt

# Verbose output to see each request
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -v

# Match only HTTP 200 responses
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -mc 200

# Expand to common file extensions (.php, .html, .asp, .jsp)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -x .php,.html,.asp,.jsp

# Skip HTTPS certificate validation (self-signed/internal certs)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -k

# Filter out false positives (e.g., custom 404 pages that return 200)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -fs 5242 -fw 45
# Explanation: -fs 5242 filters responses exactly 5,242 bytes; -fw 45 filters those with exactly 45 words
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery (if target is cloud-hosted).
- **T1595.002** — Vulnerability Scanning: Vulnerability Scanning (active scanning for information gathering).

---

## Subdomain / Virtual Host Fuzzing (T1589.001 – Domain and Subdomain)

**Objective:** Discover subdomains or virtual hosts via `Host:` header fuzzing.

```bash
# Fuzz the Host: header for subdomain discovery (requires target's IP or a domain that resolves)
ffuf -u https://192.168.1.100 -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt -mc 200

# Fuzz with a domain (DNS resolution required)
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt -fc 404

# Multi-wordlist chaining: fuzz subdomains AND paths in one pass
ffuf -u https://FUZZ1.target.com/FUZZ2 -w subdomains.txt:FUZZ1 -w paths.txt:FUZZ2

# Filter out common false positives (wildcard DNS, catch-all pages)
ffuf -u https://192.168.1.100 -H "Host: FUZZ.target.com" -w /path/to/subdomains.txt \
  -fs 4242 -fr "Welcome to|Default|Placeholder"
# Explanation: -fs 4242 filters responses of exactly 4,242 bytes; -fr filters based on regex
```

**MITRE ATT&CK mappings:**
- **T1589.001** — Gather Victim Identity Information: Credentials (e.g., discovering admin portals via subdomains).
- **T1590.002** — Gather Victim Network Information: DNS.

---

## Parameter Fuzzing / Query-String Discovery (T1592.004 – Client Configurations)

**Objective:** Discover hidden or undocumented query-string parameters.

```bash
# Fuzz query-string parameters
ffuf -u "https://target.com/search?q=test&FUZZ=value" -w /path/to/parameters.txt

# Fuzz parameter values instead of names
ffuf -u "https://target.com/user/FUZZ" -w /path/to/usernames.txt -mc 200,301,302

# Test multiple parameters in POST body (use -b for body data)
ffuf -u "https://target.com/login" -X POST -b "username=admin&password=FUZZ" \
  -w /path/to/passwords.txt -mc 200

# API endpoint parameter fuzzing (common API parameters)
ffuf -u "https://api.target.com/v1/users?FUZZ=123" -w /path/to/api_params.txt -mc 200

# Username/email enumeration via parameter values
ffuf -u "https://target.com/profile?id=FUZZ" -w /path/to/user_ids.txt \
  -mc 200 -fs 1024  # Only match 200s that are NOT the standard 404 size (1024 bytes)
```

**MITRE ATT&CK mappings:**
- **T1592.004** — Gather Victim Identity Information: Client Configurations (discovering what parameters an API accepts).

---

## Recursive Directory Enumeration (T1526)

**Objective:** Discover directory structures by recursively fuzzing subdirectories.

```bash
# Enable recursive fuzzing (automatically fuzz discovered directories)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -recursive -recursion-depth 2

# Reduce concurrency for recursive runs (to avoid overwhelming the target)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -recursive -recursion-depth 2 -t 10

# Verbose recursive output
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -recursive -recursion-depth 3 -v

# Add extension fuzzing to recursive discovery
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -x .php,.html -recursive -recursion-depth 2
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery / Infrastructure Enumeration.

---

## Filtering False Positives (Avoiding Status-Code Traps)

**Objective:** Discover real resources when the target returns customized 404 pages.

```bash
# Establish a baseline 404 by requesting a known-invalid path first
curl -s https://target.com/this-does-not-exist-12345 | wc -c
# Output: 5242 (bytes in a custom 404 page)

# Now fuzz and filter out this size
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -fs 5242

# Alternative: baseline by response word count
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -fw 45  # Filter if exactly 45 words

# Complex filtering: match 200–299 status AND body > 1000 bytes AND NOT matching "not found" regex
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt \
  -mc 200,201,202,204 -ms 1000 -fr "not found|error"
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery (improving accuracy of discovery).

---

## Rate-Limited / WAF-Aware Fuzzing (Evasion: T1087 – Account Discovery)

**Objective:** Fuzz targets with rate-limiting or WAF protections by reducing request velocity.

```bash
# Reduce concurrency to 5 threads
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -t 5

# Add per-request delay (100 milliseconds between each request)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -p 100

# Limit to 5 requests per second
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -rate 5

# Combine: low concurrency + delay + custom User-Agent
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -t 3 -p 200 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Increase timeout for slow responses
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -timeout 30
```

**MITRE ATT&CK mappings:**
- **T1087** — Account Discovery (when fuzzing for valid usernames/accounts despite rate-limiting).
- **T1518.001** — Software Discovery: Security Software Discovery (detecting WAF patterns via response analysis).

---

## Multi-Wordlist Cartesian-Product Fuzzing

**Objective:** Combine multiple wordlists for exhaustive enumeration.

```bash
# Fuzz paths AND extensions in a single pass
ffuf -u "https://target.com/FUZZ.FUZZEXT" -w paths.txt:FUZZ -w extensions.txt:FUZZEXT

# Fuzz subdomains AND paths simultaneously
ffuf -u "https://SUB.target.com/PATH" -w subdomains.txt:SUB -w paths.txt:PATH

# Three-way cartesian: protocol + subdomain + port + path
ffuf -u "PROTO://SUB.target.com:PORT/PATH" \
  -w protocols.txt:PROTO -w subdomains.txt:SUB -w ports.txt:PORT -w paths.txt:PATH
```

**MITRE ATT&CK mappings:**
- **T1526** — Cloud Service Discovery.

---

## Output and Reporting

**Objective:** Save fuzzing results for reporting and integration with other tools.

```bash
# Output results to JSON (for integration with other tools, log aggregation)
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -o results.json

# Output to CSV format
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -o results.csv -of csv

# Output to HTML report
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -o report.html -of html

# Save multiple output formats at once
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -od /tmp/results/ -of all
# Explanation: -od specifies output directory; -of all creates .json, .csv, .html, .md versions

# Verbose JSON output with per-response timings and metadata
ffuf -u https://target.com/FUZZ -w /path/to/directories.txt -o results.json -v
```

**MITRE ATT&CK mappings:**
- **T1123** — Audio Capture / Command Logging (documentation/logging of reconnaissance).

