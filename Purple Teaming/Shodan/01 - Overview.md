# Shodan — Overview

> 🔴 **Red Flag Principle:** Shodan doesn't scan when an operator queries it — **it already scanned, days or weeks ago, and the operator is only reading a pre-built index.** A `shodan search`/`shodan host` lookup is an HTTPS API call from the operator's machine to `api.shodan.io`; it never touches the target at all. That means **the only network traffic a target will ever see from "Shodan reconnaissance" is Shodan's own continuous internet-wide crawling** — recurring, unauthenticated banner-grab connections from Shodan's own scanner infrastructure, arriving on a schedule that has nothing to do with when any specific operator decided to look. Detection has to invert accordingly: there is no operator-side event to catch on the target, only Shodan's own recon fingerprint to recognize and, if desired, respond to — and the actual attacker who used the results shows up later, if at all, as a completely ordinary connection with zero Shodan-specific signature.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Search Filters — Quick Reference](#search-filters--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Shodan was created by **John Matherly**, who first had the idea in 2003 and publicly debuted the search engine at **DEFCON 17 in 2009** — verified against [Wikipedia's Shodan entry](https://en.wikipedia.org/wiki/Shodan_(website)) and corroborated independently by contemporary security-industry reporting. The name is a reference to SHODAN, the antagonist AI from the *System Shock* video game series.

- **Canonical sources:** [shodan.io](https://www.shodan.io) (the service itself), [book.shodan.io](https://book.shodan.io) (Matherly's own official documentation/book covering crawler internals, the API, and the CLI), [developer.shodan.io](https://developer.shodan.io) (REST API reference), and the **official Python client/CLI repository**, [`achillean/shodan-python`](https://github.com/achillean/shodan-python) — `achillean` is confirmed (via the GitHub API) to be John Matherly's own account, company field `Shodan`, based in Austin, TX.
- **License:** MIT (the `shodan-python` package, which is the source of the `shodan` command-line tool this note covers). Current PyPI release is **1.31.0** (published 2023-12-17); the GitHub repo itself last received commits 2024-08-05 — actively usable and still the maintained CLI, just not under frequent version churn.
- **Growth into an IoT/ICS/OT visibility tool, not just a "hacker search engine":** Shodan's own reputation shifted from an obscure port-banner curiosity to mainstream security relevance through a string of well-documented findings — Forbes (September 2013) documented Shodan surfacing exposed heating/security-control systems at banks and universities and vulnerable TRENDnet cameras; researchers used it in December 2015 to identify exposed MongoDB instances tied to a MacKeeper data exposure; AT&T publicly used it for IoT-malware detection in November 2021; and as recently as September 2025, Cisco researchers used Shodan to enumerate over 1,100 publicly exposed Ollama LLM servers. The throughline across all of these: Shodan didn't "hack" anything in any of them — it simply made pre-existing, already-exposed misconfiguration searchable.
- **Company:** Shodan is developed and operated by Matherly's own company (also referred to as Shodan, Inc.), not a research-lab or open-source-community project — the CLI/Python library is open source (MIT), but the crawling infrastructure, index, and paid API tiers are Shodan's proprietary commercial product.

## How It Works

**Shodan is architecturally inverted compared to every scanning tool already in this module (`Masscan/`, `Nmap/`).** Those tools are things an operator runs, pointed at a target, at the moment of the engagement. Shodan is the opposite: **Shodan itself is a continuously-running, third-party-operated scanner**, and what an operator (or an analyst) actually interacts with is a **read-only search index** built from years of that scanning — the operator's own machine never sends a single packet toward the target.

### Phase 1 — Shodan's own crawling (continuous, target-facing, not operator-controlled)

Per Matherly's own documented crawler design (`book.shodan.io`'s [Crawler Algorithm](https://book.shodan.io/behind-the-scenes/crawler-algorithm/) page):

- **Random, not sequential, coverage.** The crawler generates a random IPv4 address, picks a random port from Shodan's known-port list, connects, and repeats — "completely random to ensure a uniform coverage of the Internet and prevent bias." This is a deliberate design choice, not an implementation detail: sequential/methodical scanning would create geographic and ISP-level blind spots that a defender could exploit to predict when they'd be revisited.
- **Protocol auto-detection on banner grab.** If a crawler connects to port 80 and the response looks like SSH rather than HTTP, it automatically switches to the SSH banner grabber for that connection — Shodan indexes what's actually listening, not what "should" be listening on a given port by convention.
- **Cascading scans.** When a banner reveals a peer or related service (e.g., a response referencing another host), the crawler can launch a secondary, related scan — tracked internally via the `_shodan.options.referrer` and `_shodan.id` banner properties. This is how Shodan sometimes surfaces infrastructure an operator never explicitly searched for.
- **Geographically distributed crawlers.** Multiple crawlers run from different regions specifically so that country-level IP blocking doesn't blind Shodan to a given network — each banner records which regional crawler collected it (`_shodan.region`).
- **Cadence:** the stated baseline is a **full random re-crawl of the internet roughly once a week**; any asset explicitly added to **Shodan Monitor** (the paid continuous-monitoring product, exposed via `shodan alert`) is rescanned **at least once a day** instead.

None of this activity is triggered by, or attributable to, any individual operator — it happens whether or not anyone ever searches the resulting data.

### Phase 2 — Querying the index (what an operator actually does)

```
Operator's machine                              Shodan's infrastructure
───────────────────                             ────────────────────────
shodan search "port:3389"                        api.shodan.io (HTTPS/443)
        │
        ├─ 1. Read ~/.shodan/api_key or   ──▶
        │      ~/.config/shodan/api_key
        │      (written by `shodan init`)
        │
        ├─ 2. HTTPS GET/POST to                ──▶  Shodan authenticates the
        │      api.shodan.io/shodan/host/search      request via the `key=`
        │      carrying the query string as a         query-string parameter,
        │      URL parameter, plus `key=<API key>`     deducts query credits
        │
        ◀── 3. JSON results streamed back ───────┘   (pre-computed banners —
        │      from the EXISTING index —              no packet is sent
        │      no live probe of the target             toward the target IP
        │      occurs as part of this call             named in the query)
        │
        └─ 4. CLI formats/prints/saves the
               result set locally (.json.gz,
               CSV, etc.)

    Target host, at some point in the past
    ────────────────────────────────────────
    (Phase 1, above) received a real, unrelated
    banner-grab connection from a Shodan crawler
    IP — the ONLY network event the target itself
    will ever see, and it has no fixed relationship
    in time to when any operator runs a query
```

The one deliberate exception to "querying never touches the target" is **on-demand scanning** (`shodan scan submit <ip/CIDR>`) and the **`stream`/`scan internet`** family: these submit a request to Shodan's own platform, and Shodan's own crawler infrastructure (not the operator's IP) performs a fresh probe against the requested target shortly afterward. The traffic the target sees is still a Shodan-crawler-sourced connection, not an operator-sourced one — but it is a genuinely fresh, request-triggered probe rather than a read against old data. This distinction matters directly for `04 - Target Evidence.md`.

### A free, no-API-key path worth knowing about: InternetDB

Shodan also exposes **`internetdb.shodan.io`**, a free, unauthenticated JSON lookup (`curl https://internetdb.shodan.io/<ip>`) that returns just open ports, CPEs, hostnames, tags, and known CVEs for an IP — no `shodan init`, no account, no API key at all (confirmed live and in Shodan's own [InternetDB documentation](https://internetdb.shodan.io/)). It updates weekly rather than in real time and carries no banner data, but it's the single lowest-friction way to check "what does Shodan already know about me/this IP" — including for a blue team auditing its own exposure with zero credential footprint to manage.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Query transport | HTTPS (443) from the operator's machine to `api.shodan.io` (search/host/count/scan/alert/etc.), `exploits.shodan.io` (Exploits archive, library-only — no CLI subcommand), `trends.shodan.io` (historical search), `stream.shodan.io` (real-time firehose), and the unauthenticated `internetdb.shodan.io` |
| Authentication | A single opaque API key, sent as a `key=` URL query-string parameter on every REST call — not a header, not OAuth, not a session cookie |
| Crawler transport (Shodan → target, not operator-controlled) | Whatever protocol/port Shodan's crawler is probing at that moment — effectively every commonly-scanned TCP/UDP service (HTTP/S, SSH, FTP, Telnet, RDP, SMB, industrial protocols like Modbus/S7, SNMP, NTP, Bitcoin, etc.) |
| Underlying index model | Passive lookup against a continuously-updated, third-party-maintained database — architecturally distinct from active scanning tools in this module (`Masscan/`, `Nmap/`), which the operator runs directly against the target |
| Streaming | A persistent HTTPS connection to `stream.shodan.io` delivering banners as Shodan's crawlers discover them, filterable by port/ASN/country/tag/vuln/custom-filter/alert ID |

## Command-Line Switches — Quick Reference

Verified directly against the live `shodan-python` CLI source (`shodan/__main__.py` and the `shodan/cli/*.py` submodules in [`achillean/shodan-python`](https://github.com/achillean/shodan-python)). The `shodan` command is a `click`-based command group; every row below is a real top-level command or option, not a guess.

| Command | Plain-English meaning |
|---|---|
| `shodan init <api key>` | Validates the key against the API and writes it to `~/.shodan/api_key` (or `~/.config/shodan/api_key` if `~/.shodan` doesn't already exist), `chmod 600`. Required before any other command works |
| `shodan myip [--ipv6]` | Prints the IP address Shodan's own API sees the caller as — useful to confirm what egress IP/proxy an operator's queries are actually leaving from |
| `shodan count <query>` | Returns just the total number of matching results — **does not consume query credits**, the cheap way to gauge how big a result set is before downloading it |
| `shodan search <query> [--fields] [--limit] [--separator] [--color/--no-color]` | Runs a search and prints matches to the terminal (paged). `--limit` caps at 1,000 per invocation; `--fields` controls which banner properties print (default `ip_str,port,hostnames,data`) |
| `shodan download <filename> <query> [--fields] [--limit]` | Same query, but streams full result banners into a compressed `<filename>.json.gz` file instead of printing — the bulk-export path, `--limit -1` pulls everything the query matches |
| `shodan parse <filenames...> [--fields] [--filters] [--filename] [--separator] [--color/--no-color]` | Reads back a previously downloaded `.json.gz` file and extracts/filters specific fields offline, without hitting the API again |
| `shodan convert <input> <format> [--fields]` | Converts a downloaded `.json.gz` into `kml`, `csv`, `geo.json`, `images` (extracts embedded screenshots to a directory), or `xlsx` |
| `shodan host <ip> [--history] [--format pretty\|tsv] [--filename/-O] [--save/-S]` | Full detail on one IP — every open port Shodan has banners for, org/location/OS, and any tagged vulnerabilities. `--history` shows every banner Shodan has ever recorded for that IP, not just the latest |
| `shodan stats <query> [--facets] [--limit] [--filename/-O]` | Aggregate/summary counts for a query, broken down by one or more facets (default `country,org`) — e.g., "how many results per country" without listing every individual host |
| `shodan trends <query> [--facets] [--filename/-O] [--save/-S]` | Queries Shodan's **historical** database — total-matches-over-time (or faceted breakdowns over time) for a query, month by month |
| `shodan scan submit <ip/CIDR...> [--wait] [--filename] [--force] [--verbose]` | Submits target(s) for a **fresh, Shodan-infrastructure-driven** on-demand scan (consumes scan credits, 1 per IP) and optionally waits and streams back results as they arrive. `--force` (Enterprise-only) bypasses the default 24-hour no-rescan-within-a-day restriction |
| `shodan scan internet <port> <protocol> [--quiet]` | Requests an **internet-wide** scan for a specific port/protocol combination using Shodan's own crawling infrastructure — a materially higher-impact request than scanning a single IP/CIDR |
| `shodan scan status <scan_id>` | Checks the status (`SUBMITTING`/`PROCESSING`/`DONE`, etc.) of a previously submitted on-demand scan |
| `shodan scan list` | Lists the operator's account's own recent on-demand scan jobs |
| `shodan scan protocols` | Lists the protocol names Shodan's on-demand scanning infrastructure supports |
| `shodan alert create <name> <netblocks...>` | Creates a **Shodan Monitor** network alert — the continuous-monitoring mechanism: any IP/CIDR added here gets rescanned at least daily instead of the weekly baseline |
| `shodan alert domain <domain> [--triggers]` | Resolves a domain's current A/AAAA records and creates a monitor alert covering the resulting external IPs in one step |
| `shodan alert list [--expired]` / `alert info <id>` / `alert remove <id>` / `alert clear` | Manage existing alerts — list, inspect one, delete one, or delete all |
| `shodan alert triggers` | Lists the notification trigger types available (`malware`, `vulnerable`, `open_database`, `new_service`, `iot`, `industrial_control_system`, `ssl_expired`, `internet_scanner`, and more) |
| `shodan alert enable <alert id> <trigger>` / `alert disable <alert id> <trigger>` | Turns a specific trigger on/off for a given alert — this is what actually generates notifications, creating the alert alone does not |
| `shodan alert stats <facets...> [--limit] [--filename]` | Aggregate facet stats across everything the operator's account currently monitors |
| `shodan alert export <filename>` / `alert import <filename>` | Back up/restore an account's full alert configuration to/from a local `.json.gz` file |
| `shodan alert download <filename> [--alert-id]` | Pulls full current banner data for every IP/network across all (or one) monitored alert |
| `shodan stream [--ports] [--countries] [--asn] [--alert] [--tags] [--vulns] [--custom-filters] [--datadir] [--limit] [--timeout]` | Subscribes to Shodan's real-time firehose of newly-discovered banners, optionally scoped to one filter dimension at a time (only one of ports/countries/asn/alert/tags/vulns/custom-filters may be set per invocation) |
| `shodan info` | Shows the current account's remaining query credits and scan credits |
| `shodan domain <domain> [--details/-D] [--save/-S] [--history/-H] [--type/-T]` | DNS/subdomain enumeration for a domain via Shodan's own DNS database, optionally cross-referencing each resulting IP against Shodan's host index |
| `shodan honeyscore <ip>` | Runs Shodan's honeypot-probability classifier against a single IP and prints a 0.0–1.0 score plus a plain-English verdict |
| `shodan radar` | Launches a terminal-based real-time visualization of banners as Shodan's crawlers find them |
| `shodan data list [--dataset]` / `data download <dataset> <file>` | Lists/downloads Shodan's curated bulk datasets (large pre-packaged result sets for specific research use cases) |
| `shodan org info` / `org add <user>` / `org remove <user>` | Organization/team account management — view members, add/remove seats (Corporate+ plans) |
| `shodan version` | Prints the installed `shodan` package version |
| `-h` / `--help` | Available on every command (the CLI explicitly maps `-h` to `--help`) |

## Search Filters — Quick Reference

Shodan's query language is `filtername:value` (no space around the colon; quote values containing spaces, e.g. `org:"SingTel Mobile"`), combinable in one query, with a leading `-` to negate a filter and a comma inside one filter's value to OR multiple values — all confirmed against Shodan's own [search-filter reference](https://www.shodan.io/search/filters) and [query fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals) documentation. A handful of the most operationally relevant filters:

| Filter | Plain-English meaning |
|---|---|
| `port:<n>` | Restrict to a specific port (or comma-separated list) |
| `net:<CIDR>` | Restrict to an IP range, e.g. `net:198.20.69.0/24` |
| `country:<XX>` / `city:<name>` | Geographic restriction by ISO country code or city name |
| `org:<name>` / `isp:<name>` | Restrict by the organization or ISP Shodan associates with the IP (WHOIS/BGP-derived, quote if it contains spaces) |
| `hostname:<domain>` | Restrict to banners with a matching (sub)domain in reverse-DNS/SSL cert data |
| `os:<name>` | Restrict by detected operating system |
| `product:<name>` / `version:<n>` | Restrict by the identified software product (and optionally version) behind a banner |
| `vuln:<CVE-ID>` | Restrict to hosts Shodan has flagged as vulnerable to a specific CVE — **requires Small Business plan or higher** |
| `tag:<name>` | Restrict by Shodan's own pre-computed category tags, e.g. `tag:ics`, `tag:database`, `tag:honeypot` — **requires Corporate plan or higher** |
| `has_vuln:true` | Any host with at least one known CVE tagged, without naming a specific one |
| `has_screenshot:true` / `screenshot.label:<name>` | Restrict to banners with a captured screenshot (RDP/VNC/webcam-style services), optionally by an ML-assigned label such as `ics` |
| `ssl.cert.subject.cn:<name>` / `ssl.version:<name>` | Restrict by TLS certificate subject CN or negotiated SSL/TLS version |
| `http.title:<text>` / `http.html:<text>` / `http.status:<code>` | Restrict by HTTP response title, page body content, or status code |
| `before:<dd/mm/yyyy>` / `after:<dd/mm/yyyy>` | Restrict to banners last seen before/after a given date |

Free-text terms with no `filtername:` prefix search the banner's `data` field only (raw service-response text) — e.g. `Moxa NPort` (Shodan's own documented example) finds Moxa serial-to-Ethernet gateways by matching text in their banners, not a dedicated `product:` entry.

## Quick Use-Case List

- Attack-surface discovery — enumerate every internet-facing service Shodan has already indexed for a target org (`org:`, `net:`, `hostname:`), without sending the org a single packet
- Exposed remote-access service discovery — RDP (`port:3389`), VNC (`port:5900` / `has_screenshot:true rfb`), SSH on non-standard ports (`ssh -port:22`)
- Exposed database discovery — MongoDB, Elasticsearch, Redis and similar services left open with no auth
- ICS/SCADA/OT exposure discovery — `tag:ics`, `screenshot.label:ics`, or protocol-specific searches (Modbus, S7, BACnet)
- CVE-tagged vulnerability hunting via `vuln:<CVE-ID>` — find every host Shodan believes is still vulnerable to a named, disclosed CVE
- Monitoring your own organization's external exposure continuously via `shodan alert` / Shodan Monitor, with trigger-based notification on new/risky findings
- Free, key-less exposure spot-checks via InternetDB (`curl https://internetdb.shodan.io/<ip>`) for a quick ports/CVE read with no account setup at all
- Domain/subdomain-to-IP enumeration via `shodan domain`, cross-referenced against Shodan's own host data
- Historical trend analysis (`shodan trends`) — how a query's result count (e.g. a specific vulnerable product) has changed month over month
- Honeypot triage (`shodan honeyscore`) before investing further effort investigating a promising-looking host
- Real-time firehose monitoring (`shodan stream`) scoped to a port, ASN, country, tag, or CVE — catching newly-exposed matching hosts as Shodan's crawlers find them, not after the fact
- Bulk offline analysis — `shodan download` a large result set once, then `shodan parse`/`shodan convert` it repeatedly without spending further query credits
- On-demand rescanning of a specific target (`shodan scan submit`) when an operator needs current data faster than Shodan's normal crawl cadence would provide
- Chaining Shodan-sourced IP/port lists into active follow-up recon with `Masscan/` or `Nmap/` once a target list has been narrowed down passively — see `02 - Hands-On Use Cases.md`'s chained-workflow example

## Prerequisites

| Requirement | Notes |
|---|---|
| Shodan account + API key | Free registration gets a `Membership`-eligible key with limited query credits and most filters; some filters are plan-gated (below). No account/key at all is needed for `internetdb.shodan.io` lookups |
| `shodan init <api key>` already run | Required once per machine before any other CLI command works — validates the key live against the API and writes it to disk |
| Account plan, if `vuln:`/`tag:` or bulk monitoring is needed | Verified against Shodan's own [platform overview](https://book.shodan.io/getting-started/platform/) and current published pricing: **Membership** (one-time $49, individual, most filters) → **Freelancer** ($69/mo, ~10,000 query credits, up to ~5,120 monitored IPs, `vuln`/`tag` still **not** included) → **Small Business** ($359/mo, unlocks `vuln:`) → **Corporate** ($1,099/mo, unlocks `tag:` and org/team features) → **Enterprise** (contact `sales@shodan.io`, bulk data access / full-internet on-demand scanning). Academic-email signups get an automatic free Membership upgrade |
| Network egress | Outbound HTTPS (443) to `api.shodan.io` and, depending on the command used, `exploits.shodan.io` / `trends.shodan.io` / `stream.shodan.io` / `internetdb.shodan.io` — no inbound access, no access to the target network at all for a plain query |
| For on-demand scanning specifically | Scan credits (separate pool from query credits) and, for `scan internet`, an Enterprise-tier plan |
| Python + `pip install shodan` | The CLI ships as part of the `shodan` PyPI package (MIT-licensed, `achillean/shodan-python`) — no separate binary distribution |
