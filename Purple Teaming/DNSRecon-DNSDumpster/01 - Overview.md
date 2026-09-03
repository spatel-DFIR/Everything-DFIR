# DNSRecon-DNSDumpster — Overview

> 🔴 **Red Flag Principle:** DNS reconnaissance is the quiet reconnaissance of choice — neither tool requires sophisticated network infrastructure to run, both generate trivial network footprints compared to active port scanning, and both reliably surface the network architecture that every subsequent phase of an intrusion leverages. **DNSRecon's active DNS queries land in plaintext DNS query logs on recursive resolvers and authoritative nameservers** (if the domain is configured to log); **DNSDumpster's passive queries vanish entirely from the target's perspective** — the entire attacker footprint lives on the source host's browser history or in API call logs to `dnsdumpster.com`. The threat-modeling implication is asymmetric: DNSRecon is louder on the wire but can be blocked at the perimeter; DNSDumpster is silent on the target but leaves browser artifacts on the source that persist indefinitely.

## Contents
- [Tool Overview & Comparison](#tool-overview--comparison)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Threat Actor Use](#threat-actor-use)
- [How Each Tool Works](#how-each-tool-works)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## Tool Overview & Comparison

| Aspect | DNSRecon | DNSDumpster |
|---|---|---|
| **Type** | Active DNS client (Python CLI) | Passive web service query (web + REST API) |
| **Execution** | Operator's machine sends fresh DNS queries | Queries pre-built HackerTarget database |
| **Query Source IP** | Operator's IP (visible to target) | HackerTarget infrastructure (invisible to target) |
| **Data Age** | Real-time (current) | Historic (days/weeks old) |
| **Installation** | Python 3.12+, `pip install dnsrecon` | None (web browser or curl) |
| **Enum Types** | Standard DNS queries, zone transfer attempts, brute force, reverse DNS, Shodan/WHOIS | DNS A/AAAA/MX/TXT/NS records from cached database |
| **Target Evidence** | **High** (DNS logs, IDS alerts, query patterns) | **Minimal** (zero target-side footprint) |
| **Source Evidence** | Shell history, process logs, files | Browser history (permanent), HTTP logs |
| **Detection Difficulty (Target)** | Easy (DNS log analysis) | Impossible (no target evidence) |
| **Detection Difficulty (Source)** | Medium (process/shell history can be cleared) | High (browser history persists) |

## MITRE ATT&CK Mapping

| Technique | Tool | ID | Description |
|---|---|---|---|
| Gather Victim Network Information | DNSRecon | [T1590.002](https://attack.mitre.org/techniques/T1590/002/) | Active DNS enumeration (A, MX, NS, SOA records) |
| Phishing for Information | DNSDumpster | [T1598.003](https://attack.mitre.org/techniques/T1598/003/) | Search public DNS repositories (passive) |
| Gather Victim Identity Information | Both | [T1589.001](https://attack.mitre.org/techniques/T1589/001/) | Email addresses, subdomains embedded in DNS/WHOIS |

## Threat Actor Use

**DNSRecon** appears consistently in reconnaissance phases across ransomware and APT intrusions — the DFIR Report's "LockBit 3.0 affiliate" report (2023) documents DNSRecon runs in early passive-reconnaissance batches alongside whois, nslookup, and Shodan queries, extracting mail server configurations and subdomain inventories to identify high-value targets. Its Python-based nature makes it trivial to wrap into post-exploitation automation or C2 implant task-runner callbacks.

**DNSDumpster** shows up in environments where active DNS scanning is blocked at the perimeter — operators query the web form from a foothold machine or simply browse the site to extract cached DNS results, avoiding direct query logs on the target. The HackerTarget database is indexed by search engines and sometimes cached by Wayback Machine, making past DNSDumpster results for a domain recoverable even after the operator's own browser history is wiped.

## How Each Tool Works

### DNSRecon (Active)

DNSRecon is a Python REPL-style DNS client that systematically queries a target domain's authoritative nameservers (or a recursive resolver if configured) for records in multiple categories:

- **Standard queries** (`A`, `AAAA`, `MX`, `NS`, `SOA`, `TXT`) — basic DNS enumeration
- **Zone transfers** (`AXFR`) — full zone dump if the nameserver is misconfigured to allow unauthenticated transfers
- **Subdomain brute force** — test thousands of likely subdomain names (mail, ftp, www, api, admin, etc.) against the authoritative nameserver
- **Reverse DNS** — queries PTR records for an IP range to find hostnames
- **Shodan integration** — optional; hand off IPs found in A records to the Shodan API for open-port information

Every query translates to a DNS wire-protocol packet visible in plaintext on the network (unless DNSSEC or DNS-over-HTTPS is in use) and logged by DNS servers configured with query logging enabled.

### DNSDumpster (Passive)

DNSDumpster (owned by HackerTarget.com) maintains a pre-built database of DNS records scraped from passive DNS feeds — it does **not** query the target domain's authoritative nameservers at all. Instead, it returns cached/historical A/AAAA/MX/TXT/NS/CNAME records observed in the past by either HackerTarget's own crawlers or contributed passive DNS feed partners. The operator's request goes to `dnsdumpster.com` (or its API, `api.dnsdumpster.com`), not to the target domain's infrastructure — the target sees nothing unless the operator was already on the target's network.

## Quick Use-Case List

- **Subdomain enumeration** (DNSRecon brute force or DNSDumpster cached results)
- **Zone file capture** (DNSRecon zone transfer if misconfigured)
- **Mail server inventory** (MX record enumeration — identifies targets for phishing)
- **Network topology mapping** (IP-to-hostname correlation via reverse DNS)
- **Shodan pivot** (DNSRecon + optional Shodan integration — active IPs → open ports)
- **Passive reconnaissance in restricted networks** (DNSDumpster web form access from compromised host; bypasses perimeter DNS filtering)
- **Historical DNS resolution** (DNSDumpster cached records show old/decommissioned infrastructure)
- **Precursor to credential-stuffing or brute-force attack** (subdomain/mail enumeration feeds into phishing/password-spray targets)

Full walkthroughs live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | DNSRecon | DNSDumpster |
|---|---|---|
| **Execution host** | Any Linux/macOS/Windows with Python 3.12+ | Web browser, or CLI tool (curl/wget) |
| **Network reachability** | Outbound DNS (port 53) to authoritative nameservers **or** to a recursive resolver configured at the source; optional Shodan API access (requires API key) | Outbound HTTPS (port 443) to `dnsdumpster.com` / `api.dnsdumpster.com` |
| **Installation** | `pip install dnsrecon` or `git clone` + manual setup | None (web-based) |
| **API key required?** | Optional (Shodan integration only) | No (free tier; optional Plus account for advanced features) |
| **Authentication** | None for standard DNS queries; Shodan API credentials if using `-s` switch | None required |
| **Permissions** | None (DNS queries are normal application-layer traffic) | None (HTTPS client request) |

---

**Each tool is documented separately in the subfolders:**

- **`DNSRecon/`** — Active DNS enumeration (01–05 suite)
- **`DNSDumpster/`** — Passive DNS queries (01–05 suite)

This file (`01 - Overview.md` at the parent level) serves as the bridge explaining the threat-modeling asymmetry and the shared reconnaissance purpose.
