# Shodan — Hands-On Use Cases

Every command below is a real, verified `shodan` CLI invocation or a documented Shodan query pattern (`01 - Overview.md`'s switch/filter tables). Because Shodan's core mechanism is a **read against a pre-built index** rather than an action against the target, most of these map to MITRE's reconnaissance tactic — specifically **T1596.005 (Search Open Technical Databases: Scan Databases)**, which MITRE's own technique page names Shodan as an example service of, and which the **Volt Typhoon** and **APT41** procedure examples on that page both cite (APT41 via the Shodan-like `fofa.su`, Volt Typhoon using Shodan directly alongside FOFA and Censys). Where a use case crosses into Shodan actually re-scanning a target on request, it's flagged separately below.

## Contents
- [Initial Setup and Account Verification](#initial-setup-and-account-verification)
- [Attack-Surface Discovery for a Target Organization](#attack-surface-discovery-for-a-target-organization)
- [Exposed Remote-Access Service Discovery](#exposed-remote-access-service-discovery)
- [Exposed Database Discovery](#exposed-database-discovery)
- [ICS/SCADA/OT Exposure Discovery](#icsscadaot-exposure-discovery)
- [CVE-Tagged Vulnerability Hunting](#cve-tagged-vulnerability-hunting)
- [Single-Host Deep Dive](#single-host-deep-dive)
- [Domain-to-IP Enumeration](#domain-to-ip-enumeration)
- [Bulk Download and Offline Analysis](#bulk-download-and-offline-analysis)
- [Faceted Summary Statistics](#faceted-summary-statistics)
- [Historical Trend Analysis](#historical-trend-analysis)
- [Honeypot Triage](#honeypot-triage)
- [Key-Less Spot-Checks via InternetDB](#key-less-spot-checks-via-internetdb)
- [Monitoring Your Own Organization Continuously](#monitoring-your-own-organization-continuously)
- [Real-Time Firehose Monitoring](#real-time-firehose-monitoring)
- [On-Demand Rescanning of a Specific Target](#on-demand-rescanning-of-a-specific-target)
- [Chained Workflow — Passive Recon Into Active Follow-Up](#chained-workflow--passive-recon-into-active-follow-up)

---

## Initial Setup and Account Verification

**MITRE ATT&CK:** Not a distinct technique — tooling setup

```bash
pip install shodan
shodan init YOUR_API_KEY_HERE
shodan info
shodan myip
```

`init` validates the key live against the API before writing it to disk — an invalid key fails immediately rather than silently. `info` confirms remaining query/scan credits before running anything that spends them; `myip` confirms which egress IP Shodan's own API sees the caller as (relevant if the operator is routing through a VPN/proxy for the query traffic itself, separate from anything about the target).

## Attack-Surface Discovery for a Target Organization

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/) (Search Open Technical Databases: Scan Databases), feeding [T1590](https://attack.mitre.org/techniques/T1590/) (Gather Victim Network Information)

```bash
# Everything Shodan has indexed for a named organization
shodan search --fields ip_str,port,org,hostnames 'org:"Acme Corp"'

# Narrow to a known netblock instead of a fuzzy org-name match
shodan search --fields ip_str,port,hostnames,data 'net:198.20.69.0/24'

# Cheap pre-check: how large is this result set before spending credits on it?
shodan count 'org:"Acme Corp"'
```

`org:` matches Shodan's own WHOIS/BGP-derived organization attribution for an IP — it can be noisy (cloud-hosted assets often attribute to the cloud provider, not the tenant), so `net:` against a confirmed netblock is the more precise variant once one is known. `count` never consumes query credits, making it the right first step before a `search` or `download` that will.

## Exposed Remote-Access Service Discovery

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/), feeding [T1133](https://attack.mitre.org/techniques/T1133/) (External Remote Services) targeting

```bash
# RDP exposed to the internet within a known netblock
shodan search 'port:3389 net:198.20.69.0/24'

# VNC — RFB protocol, optionally cross-referenced with a captured screenshot
shodan search 'has_screenshot:true rfb net:198.20.69.0/24'

# SSH running on a non-standard port (evades a naive port:22-only sweep)
shodan search 'ssh -port:22 net:198.20.69.0/24'
```

`has_screenshot:true` combined with a protocol keyword is Shodan's own documented pattern for screen-scraped services (VNC/RDP-style) — the screenshot itself, where present, is retrievable through the web UI or the API's image data and can immediately show what's on the exposed desktop without a single connection attempt of the operator's own.

## Exposed Database Discovery

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/), feeding [T1213](https://attack.mitre.org/techniques/T1213/) (Data from Information Repositories) if a discovered database turns out to be unauthenticated

```bash
shodan search 'product:MongoDB net:198.20.69.0/24'
shodan search 'product:"Elasticsearch" net:198.20.69.0/24'
shodan search 'port:6379 net:198.20.69.0/24'   # Redis, commonly deployed with no auth
```

`product:` matches Shodan's own service-fingerprinting result — a real identification derived from the banner content Shodan's crawler captured, not a port-number guess. This is the exact search pattern behind the December 2015 MongoDB/MacKeeper exposure research cited in `01 - Overview.md`'s History section.

## ICS/SCADA/OT Exposure Discovery

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/), feeding [T0846](https://attack.mitre.org/techniques/T0846/) (Remote System Discovery) in the ICS ATT&CK matrix where the follow-on activity is OT-specific

```bash
# Requires Corporate plan or higher (tag: filter)
shodan search 'tag:ics net:198.20.69.0/24'

# Free-tier alternative: Shodan's own ML-labeled screenshot category
shodan search 'screenshot.label:ics'

# Free-text banner match for a specific device family (Shodan's own documented example)
shodan search 'Moxa NPort'
```

`tag:ics` is Shodan's own pre-computed industrial-control-system classification and is plan-gated; `screenshot.label:ics` is a documented free-tier-accessible alternative that relies on Shodan's own machine-learning image classification of captured screenshots rather than the protocol-based tag. Free-text banner search (no filter prefix) works against `data` regardless of plan — useful when a specific vendor/product family (Moxa serial gateways, Siemens S7, Schneider Modicon, etc.) is the actual target rather than the broad ICS category.

## CVE-Tagged Vulnerability Hunting

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/), directly informing exploit selection (no single ID — the technique used against the discovered CVE depends on which one it is)

```bash
# Requires Small Business plan or higher (vuln: filter)
shodan search 'vuln:CVE-2014-0160'                          # Heartbleed
shodan search 'vuln:CVE-2019-19781 country:DE,CH,FR'        # Citrix ADC, geo-scoped

# Any known CVE at all, without naming one specifically
shodan search 'has_vuln:true net:198.20.69.0/24'
```

Both `vuln:CVE-2014-0160` and the country-scoped `vuln:CVE-2019-19781` example are Shodan's own [published example queries](https://www.shodan.io/search/examples) — not invented for this note. This is a direct, zero-packets-sent way to answer "who is still vulnerable to a specific disclosed CVE" at internet scale, which is exactly why `vuln:` sits behind a paid tier rather than the free one.

## Single-Host Deep Dive

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/)

```bash
shodan host 203.0.113.10
shodan host 203.0.113.10 --history          # every banner Shodan has ever recorded for this IP
shodan host 203.0.113.10 --format tsv       # grep-friendly output
shodan host 203.0.113.10 --save             # writes 203.0.113.10.json.gz locally
```

`--history` is the single highest-value flag here for an analyst, not just an operator — it shows what changed on a host over time (new ports opened, software upgraded/downgraded, certificates rotated), which is exactly the kind of longitudinal view a live scan can never give you in one shot.

## Domain-to-IP Enumeration

**MITRE ATT&CK:** [T1590.005](https://attack.mitre.org/techniques/T1590/005/) (Gather Victim Network Information: IP Addresses)

```bash
shodan domain acme-corp.example
shodan domain acme-corp.example --details   # also pulls Shodan host data for each resolved IP
shodan domain acme-corp.example --history --save
```

`--details` chains a `shodan domain` DNS lookup directly into a per-IP `shodan host` lookup for every A/AAAA record found, in one command — a fast way to go from "what subdomains exist" to "what does Shodan already know is running on each of them."

## Bulk Download and Offline Analysis

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/)

```bash
# Pull up to 5,000 full banners for a query into a compressed file (spends query credits)
shodan download acme_recon.json.gz 'org:"Acme Corp"' --limit 5000

# Later, extract just specific fields, offline, no further API calls
shodan parse --fields ip_str,port,org,hostnames acme_recon.json.gz

# Filtered extraction — only records where a vulns field is present
shodan parse --fields ip_str,port,vulns --filters vulns:CVE-2021-44228 acme_recon.json.gz

# Convert to other formats for downstream tooling
shodan convert acme_recon.json.gz csv
shodan convert acme_recon.json.gz kml     # for mapping tools
shodan convert acme_recon.json.gz images  # extracts embedded screenshots to a directory
```

The download-once/parse-repeatedly pattern is deliberate: `shodan parse` and `shodan convert` never touch the API, so an operator can re-slice a single downloaded dataset as many times as needed without spending additional query credits.

## Faceted Summary Statistics

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/)

```bash
shodan stats --facets country,org,port 'net:198.20.69.0/24'
shodan stats --facets product --limit 20 'vuln:CVE-2021-44228'   # top 20 products affected by Log4Shell
```

Facets give an aggregate breakdown (top countries, orgs, ports, products, etc.) without listing every individual matching host — the fast way to characterize a large result set's shape before deciding whether to drill into individual records with `search`/`download`.

## Historical Trend Analysis

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/)

```bash
shodan trends 'product:"Apache httpd"'
shodan trends --facets os 'net:198.20.69.0/24'
```

Queries Shodan's separate historical-trends database (`trends.shodan.io`) rather than the live index — useful for tracking exposure or patch-adoption trends over time (e.g., how many Log4Shell-vulnerable hosts existed month over month after disclosure) rather than a single point-in-time count.

## Honeypot Triage

**MITRE ATT&CK:** Not a distinct technique — a triage/verification step layered on prior discovery

```bash
shodan honeyscore 203.0.113.10
```

Before investing operator effort exploiting or further investigating a promising-looking host discovered via any of the above, a quick honeyscore check flags whether it's likely a deliberately-planted decoy — cheap insurance against burning a real technique against a monitored trap.

## Key-Less Spot-Checks via InternetDB

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/) — same technique, zero-credential path

```bash
curl -s https://internetdb.shodan.io/203.0.113.10 | python3 -m json.tool
```

No `shodan init`, no account, no API key file on disk at all — the single lowest-footprint way to check what Shodan already knows about a specific IP (open ports, CPEs, known CVEs). Weekly-updated and banner-free, so it's a triage/pre-check step, not a substitute for a full `shodan host` lookup once a target IP is confirmed interesting.

## Monitoring Your Own Organization Continuously

**MITRE ATT&CK:** Defensive analog of T1596.005 — the organization running the same technique against itself

```bash
# Create a monitor covering your own external netblocks
shodan alert create "Acme External" 198.20.69.0/24 203.0.113.0/24

# Or derive the IP set automatically from a domain
shodan alert domain acme-corp.example --triggers new_service,vulnerable,malware,open_database

# See what's currently enabled
shodan alert list
shodan alert info <alert_id>
shodan alert triggers

# Faceted exposure summary across everything currently monitored
shodan alert stats country,port,vuln
```

This is the single highest-value defensive use of Shodan covered in this note: any netblock added via `shodan alert create` gets rescanned **at least daily** (vs. the ~weekly baseline crawl), and enabling triggers like `new_service`/`vulnerable`/`open_database` turns Shodan's own third-party scanning into an early-warning system for the organization's own accidental exposure — effectively running the attacker's own recon technique defensively, continuously, before an actual attacker's manual query catches it first.

## Real-Time Firehose Monitoring

**MITRE ATT&CK:** [T1596.005](https://attack.mitre.org/techniques/T1596/005/)

```bash
# Newly-discovered banners on a specific port, as Shodan's crawlers find them
shodan stream --ports 3389 --datadir ./rdp_stream

# Scoped to an existing alert instead of a raw filter
shodan stream --alert <alert_id>

# Scoped to a CVE
shodan stream --vulns CVE-2021-44228
```

Only one scoping dimension (`--ports`/`--countries`/`--asn`/`--alert`/`--tags`/`--vulns`/`--custom-filters`) may be active per invocation — the CLI enforces this and errors out if more than one is supplied. This is the mechanism behind both offensive continuous-target-discovery and defensive continuous-self-monitoring; the only difference is what's being watched.

## On-Demand Rescanning of a Specific Target

**MITRE ATT&CK:** [T1595](https://attack.mitre.org/techniques/T1595/) (Active Scanning) — this is the one Shodan use case where fresh, request-triggered probing actually occurs, sourced from Shodan's own infrastructure rather than the operator's

```bash
shodan scan submit 198.20.69.0/24 --wait 30 --filename fresh_scan.json.gz
shodan scan status <scan_id>
shodan scan list
```

Unlike every other use case in this file, this one causes **new** crawler-sourced traffic to hit the target shortly after the command runs — see `04 - Target Evidence.md` for what that looks like from the target's side, and note the default 24-hour no-rescan-within-a-day restriction (Enterprise `--force` bypasses it) that limits how often this can be repeated against the same target.

## Chained Workflow — Passive Recon Into Active Follow-Up

**MITRE ATT&CK:** Composite — [T1596.005](https://attack.mitre.org/techniques/T1596/005/) for the Shodan phase, then [T1595.001](https://attack.mitre.org/techniques/T1595/001/)/[T1595.002](https://attack.mitre.org/techniques/T1595/002/) (Active Scanning: Scanning IP Blocks / Vulnerability Scanning) once the operator's own tools take over

```bash
# Phase 1 — passive: build a target list with zero packets sent to the org
shodan download acme_recon.json.gz 'org:"Acme Corp"' --limit -1
shodan parse --fields ip_str,port acme_recon.json.gz --separator ' ' > acme_ip_port.txt
awk '{print $1}' acme_ip_port.txt | sort -u > acme_ips.txt

# Phase 2 — active: now that the target list is narrowed, hand it to a real
# scanner for current, first-hand verification (see ../Masscan/ and ../Nmap/
# for full switch/technique coverage of both)
masscan -iL acme_ips.txt -p3389,22,443,3306 --rate 1000

nmap -sV -p3389,22,443,3306 -iL acme_ips.txt -oA acme_verify
```

This is the realistic shape of how Shodan actually gets used in a real engagement or a real intrusion: it narrows an internet-scale target space down to a short list **before** any active tool ever touches the target directly, and the active-scanning phase that follows is genuinely a separate technique with its own, much richer target-side evidence trail — see `../Masscan/04 - Target Evidence.md` and `../Nmap/04 - Target Evidence.md` for that half of the story, which this note deliberately does not re-derive.
