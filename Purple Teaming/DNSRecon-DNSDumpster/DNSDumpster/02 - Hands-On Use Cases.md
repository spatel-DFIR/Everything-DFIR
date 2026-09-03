# DNSDumpster — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with full commands/steps and MITRE ATT&CK IDs.

## Contents
- [Web Form Query (Interactive)](#web-form-query-interactive)
- [API Query (Headless)](#api-query-headless)
- [API Query with Authentication](#api-query-with-authentication)
- [Bulk Domain Enumeration](#bulk-domain-enumeration)
- [Network Banner Search](#network-banner-search)
- [C2 Integration](#c2-integration)
- [Python Script Automation](#python-script-automation)
- [callDumpster CLI Wrapper](#calldumpster-cli-wrapper)
- [Filtered Result Extraction](#filtered-result-extraction)
- [Passive Reconnaissance Before Active Scan](#passive-reconnaissance-before-active-scan)

---

## Web Form Query (Interactive)

**MITRE ATT&CK:** T1589.002 (Gather Victim Network Information: DNS Records), T1590.002 (Gather Victim Infrastructure Information: DNS Records)

1. Open browser, navigate to `https://dnsdumpster.com`
2. Enter target domain name in the search box (e.g., `example.com`)
3. Click **Search**
4. Results display as a table: discovered hosts, IPs, geolocation, ASN, banner data
5. Optional: Click **Map** tab to view a visual domain-map (if available for the domain)
6. Optional: Export results by copying/pasting table or using browser "Save As" to capture HTML

**Advantages:**
- No technical setup required
- Visual domain map shows infrastructure relationships
- Easy for one-off reconnaissance

**Disadvantages:**
- Not scriptable
- Results not machine-parseable (manual copy/paste)
- No batch processing

---

## API Query (Headless)

**MITRE ATT&CK:** T1589.002, T1590.002 (reconnaissance via programmatic API)

```bash
# Single domain query
curl "https://api.dnsdumpster.com/domain/example.com"

# Save results to file
curl "https://api.dnsdumpster.com/domain/example.com" > example_com_results.json

# Pretty-print JSON
curl "https://api.dnsdumpster.com/domain/example.com" | jq .

# Extract just the discovered hosts
curl -s "https://api.dnsdumpster.com/domain/example.com" | jq '.dns_records[] | select(.type == "A") | .value'
```

**Expected Output:**
```json
{
  "domain": "example.com",
  "dns_records": [
    {"type": "A", "name": "example.com", "value": "93.184.216.34", "asn": "AS15169"},
    {"type": "A", "name": "www.example.com", "value": "93.184.216.35", "asn": "AS15169"}
  ],
  "banners": [
    {"ip": "93.184.216.34", "http_title": "Example Domain", "web_server": "Apache"}
  ]
}
```

**Note:** Free tier allows **1 request per 2 seconds** — add delays between queries:
```bash
for domain in example.com example.co.uk example.org; do
  curl "https://api.dnsdumpster.com/domain/$domain" > "${domain}_results.json"
  sleep 2  # Rate-limiting compliance
done
```

---

## API Query with Authentication

**MITRE ATT&CK:** T1589.002, T1590.002 (Plus tier allows higher query volume)

```bash
# With API key (for Plus/paid accounts with higher limits)
API_KEY="your_api_key_here"
curl "https://api.dnsdumpster.com/domain/example.com?api_key=$API_KEY"

# With pagination (Plus membership only)
curl "https://api.dnsdumpster.com/domain/example.com?api_key=$API_KEY&page=2"

# Store API key in environment variable to avoid shell history exposure
export DNSDUMPSTER_API_KEY="your_api_key"
curl "https://api.dnsdumpster.com/domain/example.com?api_key=$DNSDUMPSTER_API_KEY"
```

**Advantages:**
- Higher rate limits (Plus tier)
- Multi-page results (200+ records per domain)
- Access to domain-map visualization data

**API Key Security Note:** If the key is passed on the CLI, it appears in shell history. Use environment variables instead.

---

## Bulk Domain Enumeration

**MITRE ATT&CK:** T1589.002, T1590.002

```bash
#!/bin/bash
# bulk_dnsdumpster.sh — query multiple domains via API

DOMAINS=("example.com" "example.co.uk" "partner-domain.com")
OUTPUT_DIR="./dnsdumpster_results"
API_KEY="${DNSDUMPSTER_API_KEY:-}"

mkdir -p "$OUTPUT_DIR"

for domain in "${DOMAINS[@]}"; do
  echo "[*] Querying $domain..."
  
  if [ -n "$API_KEY" ]; then
    curl -s "https://api.dnsdumpster.com/domain/$domain?api_key=$API_KEY" > "$OUTPUT_DIR/${domain}_results.json"
  else
    curl -s "https://api.dnsdumpster.com/domain/$domain" > "$OUTPUT_DIR/${domain}_results.json"
  fi
  
  sleep 2  # Rate-limiting compliance
done

echo "[+] Results saved to $OUTPUT_DIR"
```

**Execution:**
```bash
chmod +x bulk_dnsdumpster.sh
./bulk_dnsdumpster.sh
```

**Output Structure:**
```
./dnsdumpster_results/
├── example.com_results.json
├── example.co.uk_results.json
└── partner-domain.com_results.json
```

---

## Network Banner Search

**MITRE ATT&CK:** T1590.002, T1595.002 (reconnaissance of discovered infrastructure)

```bash
# Query for discovered services in a CIDR range
curl "https://api.dnsdumpster.com/banners/192.168.1.0/24"

# Extract unique services
curl -s "https://api.dnsdumpster.com/banners/192.168.1.0/24" | jq '.banners[] | {ip, port, web_server}'

# Filter for specific service types (e.g., HTTP web servers only)
curl -s "https://api.dnsdumpster.com/banners/192.168.1.0/24" | jq '.banners[] | select(.web_server != null)'
```

**Expected Output:**
```json
{
  "banners": [
    {
      "ip": "192.168.1.1",
      "port": 80,
      "http_title": "Router Admin Panel",
      "web_server": "Cisco IOS"
    },
    {
      "ip": "192.168.1.100",
      "port": 443,
      "http_title": "Printer Web UI",
      "web_server": "HP LaserJet"
    }
  ]
}
```

**Useful for:** Post-discovery infrastructure enumeration — after discovering a CIDR block via DNS records, query the banner API to learn what services are running.

---

## C2 Integration

**MITRE ATT&CK:** T1589.002, T1590.002 (reconnaissance via C2 agent, no CLI logging)

**Pseudo-code (agent-side reconnaissance module):**

```python
# Inside a C2 agent (e.g., Sliver, Beacon)
import requests
import json

def dnsdumpster_recon(domain):
    """Query DNSDumpster API for domain reconnaissance, return results"""
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            results = response.json()
            return {
                "status": "success",
                "domain": domain,
                "hosts_found": len(results.get("dns_records", [])),
                "banners_found": len(results.get("banners", []))
            }
        else:
            return {"status": "error", "code": response.status_code}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# Agent command: recon.dnsdumpster example.com
result = dnsdumpster_recon("example.com")
agent.log(json.dumps(result))
```

**Advantages:**
- No CLI process spawn → No Sysmon/auditd execution log
- No shell history exposure
- Embedded in agent memory → Minimal forensic footprint
- Uses standard HTTPS (blends into normal traffic)

**Disadvantages:**
- Requires agent already compromised on internal host
- Target domain knowledge must be previously obtained
- Results transmitted through C2 (potential interception if C2 comms unencrypted)

---

## Python Script Automation

**MITRE ATT&CK:** T1589.002, T1590.002

```python
#!/usr/bin/env python3
# dnsdumpster_bulk.py — query multiple domains, generate Excel report

import requests
import json
import time
from openpyxl import Workbook
from openpyxl.styles import Font

def query_dnsdumpster(domain, api_key=None):
    """Query DNSDumpster API for a domain"""
    url = f"https://api.dnsdumpster.com/domain/{domain}"
    params = {"api_key": api_key} if api_key else {}
    
    try:
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error querying {domain}: {e}")
        return None

def main():
    domains = ["example.com", "example.co.uk", "partner-domain.com"]
    api_key = None  # Leave as None for free tier, or set to your API key
    
    # Create Excel workbook
    wb = Workbook()
    summary_sheet = wb.active
    summary_sheet.title = "Summary"
    
    # Headers
    summary_sheet.append(["Domain", "Hosts Found", "Banners Found", "IPs"])
    
    for domain in domains:
        print(f"[*] Querying {domain}...")
        results = query_dnsdumpster(domain, api_key)
        
        if results:
            hosts_found = len(results.get("dns_records", []))
            banners_found = len(results.get("banners", []))
            ips = list(set([r.get("value") for r in results.get("dns_records", []) if r.get("type") == "A"]))
            
            summary_sheet.append([domain, hosts_found, banners_found, "; ".join(ips)])
            
            # Create sheet for domain details
            detail_sheet = wb.create_sheet(domain)
            detail_sheet.append(["Type", "Name", "Value", "ASN", "Geolocation"])
            
            for record in results.get("dns_records", []):
                detail_sheet.append([
                    record.get("type"),
                    record.get("name"),
                    record.get("value"),
                    record.get("asn", "N/A"),
                    record.get("geolocation", "N/A")
                ])
        
        time.sleep(2)  # Rate-limiting
    
    # Save workbook
    output_file = "dnsdumpster_report.xlsx"
    wb.save(output_file)
    print(f"[+] Report saved to {output_file}")

if __name__ == "__main__":
    main()
```

**Execution:**
```bash
python3 dnsdumpster_bulk.py
# Output: dnsdumpster_report.xlsx
```

---

## callDumpster CLI Wrapper

**MITRE ATT&CK:** T1589.002, T1590.002

[callDumpster](https://github.com/cred0core/callDumpster) is a community CLI wrapper for DNSDumpster API, pre-built for convenience:

```bash
# Install (requires Python 3 and pip)
git clone https://github.com/cred0core/callDumpster
cd callDumpster
pip install -r requirements.txt

# Query single domain
python callDumpster.py -k "$DNSDUMPSTER_API_KEY" -d example.com

# Query multiple domains from file
echo -e "example.com\nexample.co.uk" > domains.txt
python callDumpster.py -k "$DNSDUMPSTER_API_KEY" -f domains.txt

# Generate Excel report
python callDumpster.py -k "$DNSDUMPSTER_API_KEY" -f domains.txt -o report.xlsx

# Use corporate proxy (if network-restricted)
python callDumpster.py -k "$DNSDUMPSTER_API_KEY" -d example.com -p "http://proxy.corp.local:8080"
```

**Output (Excel Report):**
```
Sheets:
  - Summary: Record counts per domain
  - Hosts: FQDN, IPv4, geolocation, ASN, PTR, banners, page titles
  - TXT: Raw DNS TXT records (SPF, DMARC, DKIM)
```

**Advantages:** Pre-built, production-ready, minimal setup.

---

## Filtered Result Extraction

**MITRE ATT&CK:** T1589.002, T1590.002 (filtered reconnaissance for targeted prioritization)

```bash
# Extract only US-based IPs
curl -s "https://api.dnsdumpster.com/domain/example.com" | jq '.dns_records[] | select(.geolocation == "United States") | {name, value, asn}'

# Extract only cloud-hosted infrastructure (AWS, Azure, Google Cloud)
curl -s "https://api.dnsdumpster.com/domain/example.com" | jq '.dns_records[] | select(.asn | test("AWS|AZURE|GOOGLE|DIGITAL|LINODE")) | {name, value, asn}'

# Extract only mail servers
curl -s "https://api.dnsdumpster.com/domain/example.com" | jq '.dns_records[] | select(.type == "MX") | .value'

# Create a target IP list for follow-up Shodan queries
curl -s "https://api.dnsdumpster.com/domain/example.com" | jq -r '.dns_records[] | select(.type == "A") | .value' | sort -u > target_ips.txt
```

**Use Case:** After DNSDumpster enumeration, extract specific IP ranges or services for targeted follow-up (Shodan queries, port scans, etc.).

---

## Passive Reconnaissance Before Active Scan

**MITRE ATT&CK:** T1589.002, T1590.002, T1595.002 (combined passive + active)

```bash
#!/bin/bash
# Strategy: DNSDumpster first (passive), then Nmap on discovered IPs (active)

DOMAIN="example.com"
API_KEY="${DNSDUMPSTER_API_KEY:-}"

echo "[*] Phase 1: Passive reconnaissance via DNSDumpster"
if [ -n "$API_KEY" ]; then
  RESULTS=$(curl -s "https://api.dnsdumpster.com/domain/$DOMAIN?api_key=$API_KEY")
else
  RESULTS=$(curl -s "https://api.dnsdumpster.com/domain/$DOMAIN")
fi

# Extract unique IP addresses
IPS=$(echo "$RESULTS" | jq -r '.dns_records[] | select(.type == "A") | .value' | sort -u)

echo "[+] Discovered IPs:"
echo "$IPS"

echo ""
echo "[*] Phase 2: Active reconnaissance via Nmap (on discovered IPs only)"
echo "$IPS" | nmap -iL - -p 22,80,443,3306,5432 -sV

echo "[+] Reconnaissance complete"
```

**Execution:**
```bash
chmod +x dnsdumpster_to_nmap.sh
./dnsdumpster_to_nmap.sh
```

**Advantages:**
- Passive DNSDumpster eliminates risk of triggering IDS before discovering targets
- Active Nmap is then targeted only to discovered IPs (reduces noise and survey time)
- Combines two tools for a complete reconnaissance pipeline
