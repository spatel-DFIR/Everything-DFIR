# DNSDumpster — Source Evidence

Artifacts left on the **attacker/source host** during DNSDumpster reconnaissance. Unlike DNSRecon, which leaves shell history and process traces, DNSDumpster's main traces are **browser history, output files, and network connections to the web service**.

## Contents
- [Browser History & Cookies](#browser-history--cookies)
- [Outbound Network Connections](#outbound-network-connections)
- [Shell History (if API-driven)](#shell-history-if-api-driven)
- [Output Files & Exports](#output-files--exports)
- [API Key Storage](#api-key-storage)
- [Python Script Artifacts](#python-script-artifacts)
- [C2 Integration Traces](#c2-integration-traces)
- [Timeline Correlation](#timeline-correlation)

---

## Browser History & Cookies

### Browser History (Web Form Usage)

**Firefox/Chrome/Edge History:**

- **Path:** 
  - Chrome: `~/.config/google-chrome/Default/History` (SQLite database)
  - Firefox: `~/.mozilla/firefox/*/places.sqlite` (SQLite database)
  - Safari: `~/Library/Safari/History.db` (SQLite)
  - Edge: `~/.config/microsoft-edge/Default/History` (SQLite)

**Query Browser History for DNSDumpster Visits:**

```bash
# Chrome/Chromium (on Linux)
sqlite3 ~/.config/google-chrome/Default/History "SELECT url, title, last_visit_time FROM urls WHERE url LIKE '%dnsdumpster%';"

# Firefox (on Linux)
sqlite3 ~/.mozilla/firefox/*/places.sqlite "SELECT url, title, visit_date FROM moz_places WHERE url LIKE '%dnsdumpster%';"
```

**Expected Output:**
```
https://dnsdumpster.com/?q=example.com | DNSDumpster | example.com | [timestamp]
https://api.dnsdumpster.com/domain/example.com | ... | ...
```

**Forensic Value:** High. Browser history directly shows:
- Exact domain names queried
- Timestamp of each query
- Number of queries performed
- Whether API or web form was used (different URLs)

### Browser Cookies & Session Storage

**Path:** Same as browser history (SQLite), stored in separate `cookies` table.

**Query for DNSDumpster Cookies:**

```bash
# Chrome
sqlite3 ~/.config/google-chrome/Default/Cookies "SELECT host_key, name, value, expires_utc FROM cookies WHERE host_key LIKE '%dnsdumpster%';"

# Firefox
sqlite3 ~/.mozilla/firefox/*/storage/default/https+++dnsdumpster.com/ls/data.sqlite "SELECT * FROM data;" 2>/dev/null
```

**Expected Content:**
```
Session cookies, no sensitive data (DNSDumpster free tier doesn't require authentication)
```

**Forensic Value:** Low. Cookies typically contain only session IDs, not reconnaissance data. However, the presence of a cookie confirms the user visited the site.

### Cached Website Content

**Path:**
- Chrome cache: `~/.config/google-chrome/Default/Cache/Cache_Data/`
- Firefox cache: `~/.cache/firefox/*/cache2/`

**Contents:** Compressed HTML, CSS, JavaScript from dnsdumpster.com pages, and previously-viewed domain-search results.

**Forensic Value:** Medium. Cached page content may contain DNS enumeration results if the results were cached (though dynamic API results typically are not cached).

---

## Outbound Network Connections

### DNS Queries

**Target:** `dnsdumpster.com` and `api.dnsdumpster.com` only (not the target domains themselves).

**Netstat View (during active usage):**
```
TCP  127.0.0.1:54321  -->  dnsdumpster.com:443   (HTTPS connection)
TCP  127.0.0.1:54322  -->  api.dnsdumpster.com:443 (API connection)
```

**Packet Capture (tcpdump/Wireshark):**
```
Source IP: 192.168.1.100 (attacker)
Dest IP: dnsdumpster.com's IP address (resolves to HackerTarget infrastructure)
Port: 443 (HTTPS/TLS)
Data: Encrypted (TLS prevents reading query strings)
```

**Forensic Value:** Medium. Network logs show the attacker connected to dnsdumpster.com, but the TLS encryption means query contents are not visible in plain network logs. However, **DNS lookups for dnsdumpster.com itself** may be logged if the network monitors DNS queries.

### TLS Fingerprinting

If a network monitor (Zeek, Suricata, etc.) captures TLS handshakes:

**JA3/JARM Fingerprint:**
- dnsdumpster.com uses standard HTTPS with a commercial certificate (Cloudflare, AWS, or similar).
- The TLS fingerprint identifies the web service, not the query contents.

**Forensic Value:** Low to Medium. TLS fingerprint confirms connection to dnsdumpster.com infrastructure but not what was queried.

---

## Shell History (if API-driven)

If the operator used `curl` or a Python script to query the API:

**Bash/Zsh History:**

```bash
curl "https://api.dnsdumpster.com/domain/example.com"
curl "https://api.dnsdumpster.com/domain/example.com?api_key=abc123"
python dnsdumpster_bulk.py
```

**Forensic Value:** High (if API calls were made from CLI). The command line names the target domains and may expose the API key if passed on the CLI.

**Mitigation:** Operators often use environment variables (`DNSDUMPSTER_API_KEY`) instead of CLI arguments to avoid history exposure, but the env var itself is still accessible via memory/process-environment reads.

---

## Output Files & Exports

### JSON API Results

**Path:** Operator-chosen (e.g., `~/Downloads/example_com_results.json`)

**Content:**
```json
{
  "domain": "example.com",
  "dns_records": [
    {"type": "A", "name": "example.com", "value": "93.184.216.34", "asn": "AS15169"},
    {"type": "MX", "name": "example.com", "value": "mail1.example.com"}
  ],
  "banners": [
    {"ip": "93.184.216.34", "http_title": "Example Domain", "web_server": "Apache/2.4.41"}
  ]
}
```

**Forensic Value:** High. The JSON file contains the full reconnaissance results — every discovered host, IP, and service banner.

### Excel Reports (callDumpster)

**Path:** Operator-chosen (e.g., `./dnsdumpster_report.xlsx`)

**Content:** Three sheets:
- **Summary:** Domain count, record counts per domain
- **Hosts:** FQDN, IP, geolocation, ASN, banner data
- **TXT:** Raw DNS TXT records (SPF, DMARC, DKIM)

**Forensic Value:** High. Comprehensive report of discovered infrastructure.

### Exported Browser Output

**Formats:** HTML (full web page saved), CSV (copy/paste from table), Screenshots

**Path:** Browser Downloads folder (typically `~/Downloads/`)

**Forensic Value:** Medium to High. Content varies; HTML exports capture the full page including results.

---

## API Key Storage

### Environment Variables

**Detection:**

```bash
env | grep -i dnsdumpster
printenv DNSDUMPSTER_API_KEY
```

**Forensic Value:** Critical (if API key is stored). The key identifies the operator's account and can be used to query HackerTarget's abuse logs.

### Configuration Files

**Paths:**
- `~/.config/callDumpster/config.ini` (if using callDumpster wrapper)
- `~/.bashrc`, `~/.zshrc` (if key is sourced from a startup script)
- Python script source code (if key is hardcoded in script)

**Forensic Value:** Critical. Configuration files may contain plaintext API keys.

---

## Python Script Artifacts

### Python Bytecode Cache

**Path:** `~/.cache/dnsrecon/__pycache__/` or `__pycache__/` directories within script folders

**Forensic Value:** Very Low. Bytecode doesn't contain query results or keys.

### Installed Packages

**Check if DNSDumpster CLI tools were installed:**

```bash
pip list | grep -i dnsdumpster
pip show callDumpster
```

**Forensic Value:** Low. Confirms the tool was installed but not when or how it was used.

---

## C2 Integration Traces

If DNSDumpster queries were embedded in a C2 agent:

### Agent Binary Artifacts

**Reverse Engineering:**
- The C2 agent binary contains hardcoded strings: `api.dnsdumpster.com`, HTTPS endpoints
- Strings are visible in IDA Pro, Ghidra, or `strings` utility

**Forensic Value:** High (if agent binary is recovered). Confirms DNSDumpster capability exists in the malware.

### C2 Callback Logs

**Location:** C2 server logs (not on the source host)

**Content:**
```
[2026-08-11 10:23:45] Agent <ID> executed: recon.dnsdumpster example.com
[2026-08-11 10:23:46] Agent <ID> results: 487 hosts found
```

**Forensic Value:** Critical (if C2 server is captured). Logs show reconnaissance activities attributed to specific agents.

### Memory Forensics (Volatility)

**If the agent process is still running in memory:**

```bash
strings -a <agent_process_memory_dump> | grep -i dnsdumpster
```

**Forensic Value:** Medium. Strings may reveal configuration or API keys, but requires live/recent memory capture.

---

## Timeline Correlation

**Key Artifacts for Timeline Building:**

1. **Browser history entry for dnsdumpster.com** → First reconnaissance visit
2. **Shell history entries** (if API-driven) → Exact timestamp of each API query
3. **Output file modification time** → When results were saved/processed
4. **Network connection logs** (if available) → TLS handshake timestamp with dnsdumpster.com
5. **API key exposure** (shell history, config) → May correlate to HackerTarget's abuse logs (external)

**Example Timeline:**

```
2026-08-11 10:15:23  - Browser history: Visit to dnsdumpster.com/?q=example.com
2026-08-11 10:15:47  - Browser history: Visit to dnsdumpster.com/?q=example.co.uk
2026-08-11 10:20:00  - Shell history: "curl https://api.dnsdumpster.com/domain/partner.com"
2026-08-11 10:20:15  - Results file created: /home/attacker/dns_results.json (3.2 KB)
2026-08-11 10:22:00  - Shell history: "python dnsdumpster_bulk.py" (bulk enumeration script)
2026-08-11 10:25:30  - Excel report created: dnsdumpster_report.xlsx (125 KB)
```

This timeline shows a progression from interactive reconnaissance (web form) → API queries → bulk script execution, painting a clear picture of escalating reconnaissance scope.

---

## Cross-Reference

For comparison to DNSRecon source evidence, refer to `DNSRecon/03 - Source Evidence.md`. Key differences:
- **DNSRecon:** Shell history, process execution, output files (similar to DNSDumpster)
- **DNSRecon unique:** Shodan API key exposure risk, REST API server process
- **DNSDumpster unique:** Browser history, cookies, TLS connections to web service, less process/CLI exposure
