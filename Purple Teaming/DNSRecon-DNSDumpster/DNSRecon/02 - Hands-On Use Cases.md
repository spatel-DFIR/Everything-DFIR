# DNSRecon — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with full command sequences and MITRE ATT&CK IDs.

## Contents
- [Passive Domain-Enumeration Baseline](#passive-domain-enumeration-baseline)
- [Zone-Transfer Exploitation](#zone-transfer-exploitation)
- [Subdomain Brute-Force Discovery](#subdomain-brute-force-discovery)
- [Combined Full-Suite Enumeration](#combined-full-suite-enumeration)
- [Reverse-DNS Enumeration of a CIDR Block](#reverse-dns-enumeration-of-a-cidr-block)
- [Shodan Netblock Enrichment](#shodan-netblock-enrichment)
- [Active Shodan Re-Validation](#active-shodan-re-validation)
- [Bulk Enumeration Across Multiple Domains](#bulk-enumeration-across-multiple-domains)
- [REST API Mode for C2 Integration](#rest-api-mode-for-c2-integration)
- [Custom Resolver Targeting](#custom-resolver-targeting)
- [Wildcard Detection Before Brute-Forcing](#wildcard-detection-before-brute-forcing)
- [Zone Enumeration Pipeline](#zone-enumeration-pipeline)

---

## Passive Domain-Enumeration Baseline

**MITRE ATT&CK:** T1589.002 (Gather Victim Network Information: DNS Records), T1590.002 (Gather Victim Infrastructure Information: DNS Records)

```bash
cd ~/dnsrecon
uv run dnsrecon -d example.com -t std -f example_dns.txt
```

Queries the target domain's nameservers for standard records (A, AAAA, MX, SOA, NS, SPF, TXT). No wordlist queries, no AXFR attempts — the fastest, least-noisy reconnaissance baseline. Output saved to `example_dns.txt` (or printed to stdout if `-f` omitted).

## Zone-Transfer Exploitation

**MITRE ATT&CK:** T1589.002, T1595.002 (Active Scanning: Scanning IP Blocks — zone transfer is active scanning)

```bash
uv run dnsrecon -d example.com -t axfr
```

Attempts AXFR (full zone transfer) against every NS record discovered for the target. If the target's DNS is misconfigured to allow zone transfer to any querier (common on legacy or misconfigured servers, but rare on modern DNS), the entire zone database is returned — an operator learns **every subdomain, every A/AAAA/CNAME/MX record, and every internal naming convention** in one query. Failure (REFUSED/NXDOMAIN) is normal on modern DNS; success is a high-confidence infrastructure find.

## Subdomain Brute-Force Discovery

**MITRE ATT&CK:** T1589.002, T1595.002, T1595.003 (Active Scanning: Scanning DNS Records)

```bash
# Using default bundled wordlist
uv run dnsrecon -d example.com -t brt -f example_subdomains.txt

# Using a custom wordlist
uv run dnsrecon -d example.com -t brt --wordlist /path/to/wordlist.txt --threads 20 -f results.xml
```

Queries a wordlist of common subdomain names against the target domain (e.g., `www.example.com`, `mail.example.com`, `api.example.com`, etc.). Each query is DNS, not HTTP/HTTPS — the tool learns which subdomains have **A/AAAA records**, not which are HTTP-accessible. Parallel threads (`--threads`) speed up the enumeration; higher thread counts risk DNS rate-limiting from the target or upstream resolver. Default bundled wordlist (~10K entries) is reasonable for a quick scan; larger wordlists or custom company-specific lists can uncover more obscure infrastructure.

## Combined Full-Suite Enumeration

**MITRE ATT&CK:** T1589.002, T1590.002, T1590.006 (Mail Server Identification), T1595.002

```bash
uv run dnsrecon -d example.com -a -f example_full.txt
```

Runs every enumeration type: standard records, AXFR, brute-forcing, SRV records, TLD expansion, and wildcard detection. Slower than individual technique runs (minutes for large wordlists), but yields a **complete infrastructure picture** in one command. Useful for target prioritization or the initial recon phase when time allows.

## Reverse-DNS Enumeration of a CIDR Block

**MITRE ATT&CK:** T1590.002, T1595.002

```bash
# Single CIDR block
uv run dnsrecon -r 192.168.0.0/24 -f internal_ips.txt

# Multiple ranges (loop)
for range in 192.168.0.0/24 192.168.1.0/24 10.0.0.0/24; do
  uv run dnsrecon -r "$range" -f "results_${range////_}.txt"
done
```

Queries the in-addr.arpa (or ip6.arpa for IPv6) reverse-DNS zone for every IP in a CIDR block. Returns reverse-DNS names for any IP with a PTR record, helping an operator build a hostname→IP map **without touching the hosts themselves** (purely DNS). Useful for mapping infrastructure after discovering a netblock via SPF records or WHOIS. Large blocks (e.g., /16) can take significant time due to query volume.

## Shodan Netblock Enrichment

**MITRE ATT&CK:** T1589.002, T1590.002, T1590.005 (Gather Victim Infrastructure Information: IP Addresses), T1595.002 (via Shodan's own index scanning)

```bash
# Set Shodan API key via environment variable
export SHODAN_API_KEY="<your_key>"

# Enumerate domain, parse SPF/WHOIS, search Shodan
uv run dnsrecon -d example.com -t std -s -w -f example_shodan.txt

# Alternative: supply key on command line
uv run dnsrecon -d example.com -t std -s -w --shodan-key "$SHODAN_API_KEY" -f example_shodan.txt

# Combine with brute-forcing for larger surface
uv run dnsrecon -d example.com -t brt -s -w --shodan-key "$SHODAN_API_KEY" -f example_shodan_full.txt
```

Discovers the target domain's infrastructure (standard enumeration), parses SPF records and WHOIS data for CIDR blocks, then queries Shodan's **pre-built index** for every discovered netblock — converting passive reconnaissance into a passive-index lookup. No fresh port scans originate from the operator's IP; all scanning is Shodan's own ongoing crawl. Output includes discovered hosts, Shodan-indexed services, and geolocation data if available.

## Active Shodan Re-Validation

**MITRE ATT&CK:** T1589.002, T1590.002, T1595.001 (Active Scanning: Scanning IP Blocks)

```bash
uv run dnsrecon -d example.com -t std --shodan --shodan-active --shodan-key "$SHODAN_API_KEY" -f results.txt
```

Same as above, but with `--shodan-active` flag: DNSRecon **re-resolves each discovered IP** (a fresh DNS query) to confirm it's still live before returning it. Slower, but more current — useful if the target's infrastructure changes frequently or if operator confidence in Shodan index currency is low.

## Bulk Enumeration Across Multiple Domains

**MITRE ATT&CK:** T1589.002, T1590.002

```bash
#!/bin/bash
# bulk_dns_recon.sh — enumerate a list of target domains

DOMAINS=("example.com" "example.co.uk" "partner-domain.com")
OUTPUT_DIR="./dns_results"
mkdir -p "$OUTPUT_DIR"

for domain in "${DOMAINS[@]}"; do
  echo "[*] Enumerating $domain..."
  uv run dnsrecon -d "$domain" -t std -f "$OUTPUT_DIR/${domain}_std.txt"
  uv run dnsrecon -d "$domain" -t brt -f "$OUTPUT_DIR/${domain}_brt.txt" --threads 15
done

echo "[+] Results saved to $OUTPUT_DIR"
```

Automates enumeration across a target's entire domain portfolio (main domain + acquired subsidiaries, sister brands, etc.). Useful in large-scale assessments or when the operator has discovered multiple domains to enumerate in one campaign.

## REST API Mode for C2 Integration

**MITRE ATT&CK:** T1589.002, T1590.002 (reconnaissance via C2 agent, avoiding CLI process spawn)

```bash
# On a compromised host (or inside a C2 agent environment)
# Start the REST API server
uv run restdnsrecon

# In another terminal or from a C2 agent, query it
curl "http://127.0.0.1:5000/general_enum?domain=example.com&do_spf=true&do_whois=true&do_shodan=false"

# Or with Shodan enabled
curl "http://127.0.0.1:5000/general_enum?domain=example.com&do_spf=true&do_whois=true&do_shodan=true&api_key=$SHODAN_API_KEY"
```

Launches a headless HTTP server on `localhost:5000`, accepting enumeration requests without spawning new CLI processes. Useful for post-exploitation reconnaissance when process-creation (Sysmon 1, Windows Event 1) is being logged — an agent can call the REST API endpoint directly without invoking `dnsrecon` CLI, leaving a smaller forensic footprint. Server runs on `127.0.0.1` only (no remote access by default).

## Custom Resolver Targeting

**MITRE ATT&CK:** T1589.002, T1590.002

```bash
# Query the target's authoritative nameserver directly (not the public resolver)
uv run dnsrecon -d example.com -n ns1.example.com -t std -f results.txt

# Query Google DNS instead
uv run dnsrecon -d example.com -n 8.8.8.8 -t std -f results.txt

# Query a compromised/internal DNS server
uv run dnsrecon -d example.com -n 10.0.0.10 -t std -f results.txt
```

Overrides the default system resolver and queries a specific nameserver directly. Useful for:
- **Split-DNS scenarios:** targeting's internal DNS may resolve different names than public DNS
- **DNS poisoning detection:** querying different resolvers to compare responses
- **Enumerating internal domains:** from a host bridged into the target's internal network, querying internal DNS reveals internal infrastructure names

## Wildcard Detection Before Brute-Forcing

**MITRE ATT&CK:** T1589.002 (implied — subdomain enumeration may be less reliable if wildcards are present)

```bash
# Check for wildcard DNS
uv run dnsrecon -d example.com -t std -f std_records.txt

# If output shows that a random non-existent subdomain resolves to an IP,
# the zone has wildcard DNS enabled. Proceed with brute-forcing but expect
# lower signal-to-noise (false positives from wildcard matches).

# Proceed with brute-forcing if confident
uv run dnsrecon -d example.com -t brt -f subdomains.txt --threads 20
```

DNSRecon's wildcard detection (as part of the `std` enumeration) queries a random non-existent name (e.g., `nonexist-<uuid>.example.com`). If it resolves, wildcard DNS is enabled — meaning **every** brute-force query will return a positive result (the wildcard A record) rather than NXDOMAIN, requiring the operator to filter results by IP (keeping only unique IPs, or manually reviewing what the wildcard points to). Wildcard detection upfront saves time by warning of this scenario.

## Zone Enumeration Pipeline

**MITRE ATT&CK:** T1589.002, T1590.002, T1595.002

```bash
#!/bin/bash
# Intelligent zone-enumeration pipeline: try AXFR first, fall back to brute-force

DOMAIN="example.com"

# Try zone transfer first (fastest if it succeeds)
echo "[*] Attempting AXFR against $DOMAIN..."
if uv run dnsrecon -d "$DOMAIN" -t axfr -f "${DOMAIN}_axfr.txt" 2>&1 | grep -q "Addresses found"; then
  echo "[+] AXFR succeeded! Zone data saved to ${DOMAIN}_axfr.txt"
  exit 0
fi

# AXFR failed; proceed to brute-forcing
echo "[-] AXFR failed. Falling back to brute-force..."
uv run dnsrecon -d "$DOMAIN" -t brt -f "${DOMAIN}_brt.txt" --wordlist /path/to/wordlist.txt --threads 25

echo "[+] Brute-force enumeration complete. Results in ${DOMAIN}_brt.txt"
```

Combines multiple techniques intelligently: attempt AXFR first (if it works, complete enumeration in seconds); if AXFR fails, fall back to standard records + brute-forcing. This pipeline maximizes coverage while avoiding wasted effort on redundant techniques.
