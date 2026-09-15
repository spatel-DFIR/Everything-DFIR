# DNSRecon & DNSDumpster — Overview

Two distinct DNS reconnaissance approaches bundled as one module: **DNSRecon** (active, command-line DNS scanner) and **DNSDumpster** (passive, web-based database query). While both enumerate DNS records for a target domain, their **mechanics, footprint, and detection signatures are fundamentally different**.

## Contents
- [Quick Comparison](#quick-comparison)
- [How to Use This Module](#how-to-use-this-module)
- [Tool Selection Guide](#tool-selection-guide)
- [Shared Reconnaissance Concepts](#shared-reconnaissance-concepts)

---

## Quick Comparison

| Aspect | DNSRecon | DNSDumpster |
|---|---|---|
| **Type** | Active DNS client (command-line) | Passive web service (HackerTarget database) |
| **Execution Model** | CLI tool; sends fresh DNS queries from operator's IP | Web form or REST API; queries pre-built database |
| **Query Source** | Operator's machine (IP visible to target) | HackerTarget's infrastructure (operator's IP not visible to target) |
| **Data Currency** | Current (queries run at operator's choice) | Historic (days/weeks old; HackerTarget's crawl schedule) |
| **Install Required?** | Yes (Python 3.12+, uv package manager) | No (web form or curl/API client) |
| **Requires Credentials?** | No (free tier) | No (free tier; optional Plus account) |
| **Requires API Key?** | Optional (Shodan integration) | Optional (Plus tier; free tier works without) |
| **Target-Side Evidence** | High (DNS server query logs, network IDS alerts) | Minimal (passive queries don't originate from operator's IP) |
| **Source-Side Evidence** | Shell history, process logs, output files | Browser history, output files, network logs to dnsdumpster.com |
| **Detection Ease (on Target)** | Easy (DNS log analysis) | Difficult/Impossible (no target-side evidence) |
| **Detection Ease (on Source)** | Medium (shell history, process logs) | High (browser history is permanent) |
| **Typical Use Case** | Operator needs current DNS data; target network is open to scanning | Operator inside restricted network; wants to avoid active scanning |
| **Speed** | Slow (seconds to minutes, depending on wordlist size) | Fast (< 1 second; database lookup) |
| **Customization** | High (wordlist, threads, enum types) | Low (domain only; database is fixed) |
| **Risk Profile** | Higher (active scanning may trigger IDS) | Lower (passive, no target-side detection) |

---

## How to Use This Module

**Each tool is documented as a separate subfolder:**

- **`DNSRecon/`** — Active DNS enumeration tool
  - `01 - Overview.md` — History, mechanics, command reference, prerequisites
  - `02 - Hands-On Use Cases.md` — Operational workflows with MITRE ATT&CK IDs
  - `03 - Source Evidence.md` — Artifacts on attacker's host
  - `04 - Target Evidence.md` — Artifacts visible to target's DNS infrastructure
  - `05 - Detection and Hunting.md` — Hunting signals and evasion-resistant indicators

- **`DNSDumpster/`** — Passive web-based DNS reconnaissance
  - `01 - Overview.md` — History, mechanics, API reference, prerequisites
  - `02 - Hands-On Use Cases.md` — Operational workflows (web form, API, scripting)
  - `03 - Source Evidence.md` — Artifacts on attacker's host
  - `04 - Target Evidence.md` — Minimal; explains why target sees no evidence
  - `05 - Detection and Hunting.md` — Source-focused hunting (target-side is sparse)

**Usage Pattern:**

1. **For pentesting:** Read both tools' `01 - Overview.md` and `02 - Hands-On Use Cases.md` to decide which fits your network posture (can you run active DNS scans, or must you be passive?).
2. **For blue-team/incident response:** Focus on `03 - Source Evidence.md` and `05 - Detection and Hunting.md` to understand what the tool leaves behind.
3. **For threat intelligence:** Cross-reference both tools' `04 - Target Evidence.md` to understand detection gaps (DNSRecon is visible; DNSDumpster is not).

---

## Tool Selection Guide

### Use DNSRecon if:

- Your target network **allows outbound DNS traffic** (UDP/TCP 53) from your position
- You need **current DNS data** (queries run at your exact time)
- You want **fine-grained control** (wordlists, thread count, enumeration types)
- You're performing a **time-limited assessment** and speed is critical (active scanning is faster for bulk enumeration)
- The target's **DNS resolver is unreliable or split-DNS** requires testing against the authoritative nameserver specifically
- You have **Shodan API key** and want to enrich results with internet-wide service data
- You're willing to **accept DNS log alerts** on the target (active scanning triggers alerts if monitored)

### Use DNSDumpster if:

- Your network **blocks outbound DNS or has restrictive egress filtering** (only allows HTTPS/443)
- You want **low-risk reconnaissance** (passive database query, no target-side detection)
- You're **already inside a restricted network** and want to avoid raising alerts
- You need **fast results** (database lookup is sub-second vs. seconds/minutes for active scanning)
- You're doing **initial reconnaissance** before committing to active scanning
- You want to **minimize operational security risks** (low footprint, no active scanning)
- You **don't need current data** (historic data from HackerTarget's crawl is acceptable)
- You want **zero target-side evidence** of your reconnaissance

### Combine Both if:

- Your assessment scope is **large or multi-stage** (DNSDumpster for initial passive recon → DNSRecon for deeper active enumeration if needed)
- You want **data correlation** (compare DNSDumpster's historic results with DNSRecon's current queries to detect infrastructure changes)
- You're **testing IDS/DNS monitoring** (DNSRecon's queries will trigger alerts; DNSDumpster's won't)

---

## Shared Reconnaissance Concepts

Both tools enumerate the same DNS record types and discover the same target infrastructure. Concepts shared across both:

### DNS Record Types Discovered

| Record Type | Purpose | Both Tools? |
|---|---|---|
| **A** | IPv4 address | Yes |
| **AAAA** | IPv6 address | Yes |
| **MX** | Mail server | Yes |
| **NS** | Nameserver | Yes |
| **SOA** | Start of Authority (DNS admin, serial, etc.) | Yes |
| **TXT** / **SPF** | Arbitrary text; usually SPF/DMARC policies | Yes |
| **CNAME** | Alias | Yes |
| **SRV** | Service (Kerberos, LDAP, etc.) | DNSRecon only (DNSDumpster may include if HackerTarget crawled) |
| **PTR** | Reverse DNS | DNSRecon only (reverse-DNS enumeration via IP ranges) |

### Common Discovery Signals

Both tools flag:
- **Wildcard DNS** (zone configured to respond to any subdomain)
- **Zone configuration issues** (open SPF, DMARC policies; weak DNSSEC)
- **Infrastructure map** (web servers, mail servers, nameservers, geolocation)
- **ASN/WHOIS ownership** (who owns the IP blocks, geolocation)
- **Service banners** (HTTP/HTTPS titles, web server versions) — DNSDumpster includes this; DNSRecon only if Shodan integration is used

### MITRE ATT&CK Mapping

Both tools map to the same reconnaissance techniques:

- **T1589.002** — Gather Victim Network Information: DNS Records
- **T1590.002** — Gather Victim Infrastructure Information: DNS Records
- **T1590.005** — Gather Victim Infrastructure Information: IP Addresses
- **T1590.006** — Gather Victim Infrastructure Information: Mail Server Identification
- **T1595.002** — Active Scanning: Scanning IP Blocks (DNSRecon only; DNSDumpster is passive)

---

## Cross-Reference to Broader DFIR Repository

DNS reconnaissance is foundational to the larger attack chain. For deeper context, refer to:

- **`Windows/15 - Network Communications/DNS Forensics.md`** — Windows DNS server logging, Event IDs, query log analysis
- **`Linux/10 - Network Services/DNS and BIND.md`** — BIND logging configuration, query.log format, troubleshooting
- **`Windows/12 - Lateral Movement.md`** — Post-reconnaissance lateral-movement techniques (after infrastructure is discovered)
- **`Purple Teaming/Impacket/`** — Post-reconnaissance exploitation (SMB/RPC attacks on discovered infrastructure)
- **`Purple Teaming/Shodan/`** — External reconnaissance enrichment (internet-wide index, often chained with DNS enumeration)
- **`Purple Teaming/Masscan/` & `Nmap/`** — Active network scanning (next step after DNS enumeration)

---

## Summary

**DNSRecon and DNSDumpster are complementary tools, not alternatives.** They serve different operational contexts:

- **DNSRecon** is for operators with network access and time to perform active reconnaissance.
- **DNSDumpster** is for operators in restricted networks or seeking low-risk, fast results.

An experienced operator might use **both** in sequence: DNSDumpster first (passive, low-risk), then DNSRecon if deeper or current data is needed. A blue-teamer should monitor for both patterns: DNSRecon's distinctive DNS query bursts and DNSDumpster's browser-history footprint.
