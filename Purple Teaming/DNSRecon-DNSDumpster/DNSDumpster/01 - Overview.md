# DNSDumpster — Overview

> 🔴 **Red Flag Principle:** DNSDumpster is a **web-based, account-free DNS reconnaissance service** (dnsdumpster.com) hosted by HackerTarget.com that performs DNS enumeration via a **pre-built internet-wide database and passive crawling**, not fresh scanning from the operator's IP. An operator visits the site, enters a domain name, and receives a **pre-computed reconnaissance report** including discovered hosts, IP addresses, ASN/geolocation data, and HTTP/HTTPS banner information — **zero new scanning originates from the operator's IP**, which is why it's a favorite reconnaissance choice for operators inside highly-restrictive networks with no outbound DNS/scanning capability. The only network trace left on the target is the operator's own IP visiting `dnsdumpster.com`, not the reconnaissance activity itself. Combined with the REST API (`api.dnsdumpster.com`), DNSDumpster becomes a **passive-reconnaissance pipeline** suitable for headless/API-driven workflows and C2 integration, and the free tier requires no authentication — making this the path-of-least-resistance OSINT for rapid domain reconnaissance at scale.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [API Reference](#api-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **Origin:** DNSDumpster is a project of **HackerTarget.com**, a commercial internet-scanning and vulnerability-scanning infrastructure company founded in **2007**. HackerTarget performs continuous, internet-wide port scanning and banner grabbing across millions of IP addresses annually, maintaining a **pre-built database** of discovered infrastructure (IP addresses, DNS records, geolocation, service banners).
- **Public Service:** DNSDumpster is HackerTarget's **free public interface** to this scanning database, launched to enable security professionals and penetration testers to query DNS reconnaissance data without re-scanning targets themselves. The site and API tier remain **free and account-optional** — no registration required for basic queries.
- **Paid Tiers:** HackerTarget offers premium membership ("Plus" tier) for higher query limits (200 records/domain vs. 50 free) and additional features (base64-encoded domain maps, additional result pages).
- **No Dedicated MITRE ATT&CK Software Entry:** Verified directly against the live ATT&CK Software list — DNSDumpster has no S-number. It appears only as a **procedure example** under reconnaissance techniques (**T1589.002** Gather Victim Network Information: DNS Records, **T1590.002** Gather Victim Infrastructure Information: DNS Records, **T1595.001** Active Scanning: Scanning IP Blocks — the last via Shodan integration with Shodan, not DNSDumpster's own scanning).
- **Operator Adoption:** Widely cited in bug-bounty reconnaissance workflows (HackerOne, Bugcrowd), SANS pen-test courses (SEC560, SEC588), and threat-intelligence toolkits for rapid passive domain enumeration without raising active-scanning alerts.

## How It Works

### Passive Database Lookup

DNSDumpster is **not a scanner**. Instead, it:

1. **Operator queries the site or API** with a domain name (e.g., `dnsdumpster.com/?q=example.com`)
2. **HackerTarget's database is searched** for any previous scans/crawling results for that domain
3. **Pre-computed results are returned** — discovered hosts, IP addresses, ASN/geolocation, HTTP/HTTPS banner data
4. **Zero new network traffic originates from the operator's IP** toward the target domain

The reconnaissance data returned is **passive** — it reflects HackerTarget's own continuous internet-wide crawling, not a fresh scan initiated by the operator's query.

### Continuous Internet-Wide Crawling

Behind the scenes, HackerTarget runs **its own network of scanners** that continuously scan IP ranges and crawl the internet for:
- DNS records (via queries to public resolvers)
- Open ports (via port scanning)
- HTTP/HTTPS banners (via web-server fingerprinting)
- Reverse-DNS (PTR records)
- ASN and geolocation data (via WHOIS and IP-geolocation databases)

This crawling happens on HackerTarget's own infrastructure **independent of user queries**. When a user queries DNSDumpster, they're querying the results of this pre-existing crawl.

### Query Interface: Web and API

**Web Interface (dnsdumpster.com):**
- Browser-based form: enter a domain name, click "Search"
- Results displayed as a searchable table and optional domain-map visualization

**API Interface (api.dnsdumpster.com):**
```
GET https://api.dnsdumpster.com/domain/{domain}?api_key={key}
```
Returns JSON with DNS records, ASN details, geolocation, and banner data.

### API Response Structure

The API returns JSON-formatted records:
```json
{
  "domain": "example.com",
  "records": [
    {
      "type": "A",
      "name": "example.com",
      "value": "93.184.216.34",
      "geolocation": "United States",
      "asn": "AS15169 GOOGLE"
    },
    {
      "type": "A",
      "name": "www.example.com",
      "value": "93.184.216.35",
      "geolocation": "United States",
      "asn": "AS15169 GOOGLE"
    },
    {
      "type": "MX",
      "name": "example.com",
      "value": "mail1.example.com (priority 10)"
    }
  ],
  "banners": [
    {
      "ip": "93.184.216.34",
      "http_title": "Example Domain",
      "web_server": "Apache/2.4.41"
    }
  ]
}
```

### No Authentication Required (Free Tier)

The free tier accepts queries **without an API key** — the operator can query the web form or make API requests without registration. Rate-limiting is enforced (1 request per 2 seconds per the API docs), but queries are otherwise unrestricted.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Query transport | HTTPS (TLS) to `dnsdumpster.com` (web) or `api.dnsdumpster.com` (API) |
| Database backend | HackerTarget's proprietary scanning database (not a real-time DNS query engine) |
| DNS data source | HackerTarget's own DNS crawling + public WHOIS/ASN databases |
| Banner data | Results of HTTP/HTTPS banner grabbing performed by HackerTarget's scanners |
| Geolocation | IP-geolocation database lookups (vendor-supplied, likely MaxMind GeoIP) |
| Caching | HackerTarget caches results; updates are periodic (weekly for full re-crawl, daily for monitored assets) |
| Result format | HTML (web), JSON (API), optional base64-encoded domain map (Plus tier) |

## API Reference

Verified against the official `dnsdumpster.com/developer/` documentation.

### Endpoint: Domain DNS Lookup

**URL:**
```
GET https://api.dnsdumpster.com/domain/{domain}[?api_key={key}][&page={page}]
```

**Parameters:**

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `domain` | String (URL path) | Yes | Target domain (e.g., `example.com`) |
| `api_key` | String (query param) | No (free tier only) | API key from your account dashboard (free tier works without key) |
| `page` | Integer (query param) | No | Page number for results (Plus membership required for page 2+) |

**Example Request:**
```bash
curl "https://api.dnsdumpster.com/domain/example.com"
curl "https://api.dnsdumpster.com/domain/example.com?api_key=abc123"
curl "https://api.dnsdumpster.com/domain/example.com?page=2"
```

**Response (200 OK):**
```json
{
  "domain": "example.com",
  "dns_records": [
    {"type": "A", "name": "example.com", "value": "93.184.216.34", ...},
    ...
  ],
  "banners": [...],
  "map": "base64_encoded_visualization_data"  // Only if map=1 requested and Plus member
}
```

**Response (429 Rate-Limited):**
```json
{
  "error": "Rate limit exceeded. 1 request per 2 seconds."
}
```

### Endpoint: Network Banner Search

**URL:**
```
GET https://api.dnsdumpster.com/banners/{cidr}[?api_key={key}]
```

**Parameters:**

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `cidr` | String (URL path) | Yes | CIDR range for banner search (e.g., `192.168.0.0/24`) |
| `api_key` | String (query param) | No | API key (free tier limited queries) |

**Example Request:**
```bash
curl "https://api.dnsdumpster.com/banners/192.168.1.0/24"
```

**Response (200 OK):**
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
      "http_title": "Example Corp Login",
      "web_server": "Apache/2.4.41"
    }
  ]
}
```

### Rate Limiting

- **Free tier:** 1 request per 2 seconds per IP (enforced by API)
- **Plus tier:** Higher limits (specifics not documented; contact HackerTarget sales)

Exceeding limits returns HTTP 429 (Too Many Requests) with an error message.

## Quick Use-Case List

- Web form query (interactive): Visit dnsdumpster.com, enter domain, view results in browser
- API query (headless): `curl https://api.dnsdumpster.com/domain/example.com`
- API query with authentication: `curl "https://api.dnsdumpster.com/domain/example.com?api_key=<key>"`
- Bulk domain enumeration: Loop over domain list, query API for each, parse JSON results
- Network banner search: Query CIDR range for discovered IP addresses and service banners
- C2 integration: Embed API calls into a post-exploitation agent to retrieve reconnaissance data
- Python script automation: Use `requests` library to query API, parse results into XLSX/CSV for reporting
- Integration with `callDumpster` CLI wrapper: Automate multi-domain enumeration and Excel report generation
- Filtered result extraction: Query API, filter results by geolocation/ASN, feed to Shodan for further enrichment
- Passive reconnaissance before active scan: Enumerate domain passively via DNSDumpster, then target specific discovered hosts

## Prerequisites

| Requirement | Notes |
|---|---|
| Internet connectivity | Outbound HTTPS (443) to `dnsdumpster.com` or `api.dnsdumpster.com`. Web proxy required if internal network blocks direct HTTPS. |
| Browser (for web form) or HTTP client (for API) | curl, Python `requests`, or any REST client. |
| DNSDumpster API key (optional) | Free tier works without key; paid tier requires key from account dashboard. |
| No scanning capability required | DNSDumpster does not scan from your IP — it queries a pre-built database. Useful when active scanning is blocked. |
| Rate-limiting tolerance | Free tier: 1 request/2 seconds. Bulk operations must respect this limit. |
