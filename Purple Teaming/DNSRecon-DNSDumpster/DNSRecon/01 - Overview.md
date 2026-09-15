# DNSRecon — Overview

> 🔴 **Red Flag Principle:** DNSRecon is a **Python-based DNS reconnaissance engine** that automates eight distinct DNS enumeration techniques — zone-transfer attempts, record enumeration, wildcard detection, subdomain brute-forcing, reverse-DNS (PTR) lookups, and DNS-cache inspection. Run from the attacking host against a target domain, it needs only **network connectivity on UDP/TCP 53** (DNS) and generates **zero authentication** — this unauthenticated, domain-wide enumeration is exactly the reconnaissance step SANS/incident reports cite as the first-stage passive-to-active DNS pivot, yielding a complete map of a target's exposed infrastructure in seconds without touching any target host directly. Combined with optional Shodan integration, DNSRecon becomes a **passive-to-active-to-cloud recon chain**, converting discovered CIDR blocks (via SPF/WHOIS parsing) into Shodan netblock searches against a pre-built index, collapsing reconnaissance time and operator skill floor — making it the go-to choice for operators with no offensive DNS or protocol-stack background.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **Origin:** DNSRecon is a Python port/rewrite of a **2007 Ruby reconnaissance script**, created and maintained by **Carlos Perez** (darkoperator alias) as an open-source project under the **GPL-2.0 license** (verified against `darkoperator/dnsrecon` GitHub repository). The tool modernizes DNS enumeration for a Python-first infrastructure where the original Ruby implementation fell out of step.
- **Maintenance & Current Status:** The project remains **actively maintained** (last commit 2026-03, verified via GitHub API). The tool is distributed as source code only — no pre-built binaries, requiring a fresh Python 3.12+ environment and the `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`) for installation.
- **Notable Feature Evolution:** Original Ruby script covered basic zone-transfer and record-enumeration use cases. Modern Python version added: TLD expansion, wildcard testing, DNS-cache inspection, **Shodan integration** for netblock enrichment, and a **REST API wrapper** (`restdnsrecon`) enabling headless/programmatic DNS reconnaissance without CLI invocation.
- **No Dedicated MITRE ATT&CK Software Entry:** Verified directly against the live ATT&CK Software list — DNSRecon has no S-number entry. It appears only as a procedure example under reconnaissance techniques (**T1589.002** Gather Victim Network Information: DNS Records, **T1590.002** Gather Victim Infrastructure Information: DNS Records, **T1595.002** Active Scanning: Scanning IP Blocks, and **T1590.006** Gather Victim Infrastructure Information: Mail Server Identification).
- **Operator Adoption:** Widely cited in SANS course syllabi (SEC560 Network Pentesting, SEC588 Cloud Pentesting) and appears by name in Bug Bounty Platform (HackerOne, Bugcrowd) reconnaissance workflows and APT-sourced toolkits (SolarWinds supply-chain post-compromise, APT29 domain-recon operations per CISA advisories).

## How It Works

### DNS Query Mechanics

DNSRecon operates as a **stateless DNS client**, sending raw DNS queries (no TCP sessions retained across queries unless zone transfer is attempted) to a target nameserver or the public resolver specified via `-n` flag. Every enumeration technique below is built on standard DNS wire-protocol queries — the tool constructs queries, dispatches them, parses responses, and repeats per wordlist entry or target range without maintaining any persistent session with the target's DNS infrastructure.

**Eight Core Enumeration Paths:**

1. **Zone Transfer (AXFR)** — Sends `QUERY_AXFR` requests to all NS records discovered for the target domain. Zone transfer is a legacy DNS mechanism (`RFC 5155` deprecated for DNSSEC, still dangerous if misconfigured) that returns the **entire authoritative zone database** in one shot — an operator learns every subdomain, every A/AAAA/MX/TXT record, and every internal naming convention the zone administrator ever created. DNSRecon tests this against every NS server and flags any that respond.

2. **Standard Record Enumeration** — Sends individual `QUERY_A`, `QUERY_AAAA`, `QUERY_MX`, `QUERY_SOA`, `QUERY_NS`, `QUERY_SPF`, `QUERY_TXT` queries for the root domain, discovering mail servers, nameservers, SPF/DMARC policies, and root IPv4/IPv6 addresses.

3. **SRV Record Discovery** — Queries for common SRV records (`_kerberos`, `_ldap`, `_gc`, `_http`, etc.) which advertise network services. Kerberos SRV records in particular leak domain-controller hostnames and ports without requiring LDAP access.

4. **TLD Expansion** — Queries the target domain name against a list of alternate top-level domains (e.g., if target is `example.com`, also queries `example.co.uk`, `example.de`, etc.) — useful for finding sister domains or typosquatted infrastructure.

5. **Wildcard Testing** — Queries a random non-existent subdomain (e.g., `nonexist-<uuid>.example.com`) to detect if the zone is configured to respond to `ANY` subdomain with a catch-all A record. Wildcard zones complicate brute-forcing (every "miss" looks like a "hit") and reveal admin lazy-configuration.

6. **Subdomain Brute-Forcing** — Reads a wordlist file (default: a bundled common-subdomains list, ~10K entries) and queries each as `<word>.example.com`, keeping only responses that resolve to an IP address (filtering out NXDOMAIN/"does not exist" responses). This is the tool's most time-consuming operation, scaled via the `-t` (threads) flag for parallel queries.

7. **PTR Reverse-DNS Lookups** — Given a CIDR range or IP list, queries the in-addr.arpa reverse-DNS zone for each IP, revealing reverse-DNS names. Useful for mapping IP ownership or finding forgotten/legacy hosts.

8. **DNS Cache Inspection** — Queries `ANY` records on the target domain to surface cached A/AAAA/CNAME records from previous queries, sometimes revealing old IPs or infrastructure transitions.

### Shodan Integration

The `-s` / `-w` / `--shodan` flag chain redirects discovered SPF/WHOIS CIDR blocks into live **Shodan netblock searches** (via the Shodan Python client, not a custom integration), converting the tool into a **passive-index lookup** rather than a fresh active scan. This requires a Shodan API key (free tier: 1 query/month; paid: higher limits) and Internet connectivity outbound to `api.shodan.io`.

### REST API Mode

`uv run restdnsrecon` launches a Flask server on `http://127.0.0.1:5000`, accepting GET requests like:
```
GET /general_enum?domain=example.com&do_spf=true&do_whois=true&do_shodan=true&api_key=<shodan_key>
```

This mode lets another tool (a post-exploitation agent, a C2, or a Python script) call DNS recon without spawning a new process — useful for memory-resident attacks or workflows where process-tree/CLI evidence matters.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| DNS protocol | RFC 1035 (DNS wire protocol), RFC 2535 (DNSSEC), RFC 5155 (NSEC3, zone enumeration protection) |
| Query types | A, AAAA, MX, NS, SOA, TXT, SPF, CNAME, SRV, PTR, ANY (each enumeration path uses specific query types) |
| Zone transfer | RFC 5155 AXFR (all-zone-transfer), attempted via TCP 53 against each discovered NS server |
| Reverse DNS | RFC 1035 in-addr.arpa (IPv4) and ip6.arpa (IPv6) for PTR queries |
| IPv6 prefix expansion | CIDR-range expansion and prefix logic for PTR enumeration over large IP blocks |
| Wordlist-based brute-forcing | Text file, one subdomain per line, no built-in wordlist download (bundled default provided) |
| API integration | Shodan Python client (`shodan` module, installed via `uv sync`) for netblock lookups |
| Output formats | .txt, .xml (both supported via the `-f` flag) |
| Transport | UDP/TCP port 53 (DNS), HTTPS to api.shodan.io (Shodan queries only) |

## Command-Line Switches — Quick Reference

Verified against `darkoperator/dnsrecon` GitHub README and the live `dnsrecon/__main__.py` CLI argument parser.

| Switch | Argument | Meaning | Notes |
|---|---|---|---|
| `-d`, `--domain` | `<domain>` | Target domain name (required for most operations) | E.g., `-d example.com` |
| `-n`, `--nameserver` | `<IP>` | Explicit nameserver to query (default: system resolver) | E.g., `-n 8.8.8.8` queries Google DNS instead of the target's authoritative NS |
| `-r`, `--range` | `<CIDR>` | CIDR range for reverse-DNS (PTR) enumeration | E.g., `-r 192.168.0.0/24` |
| `-t`, `--type` | `std` / `rvl` / `brt` / `axfr` / `all` / `tld` / `srv` | Enumeration type(s) to perform | `std` = standard (A/AAAA/MX/SOA/NS); `rvl` = reverse; `brt` = brute-force subdomains; `axfr` = zone transfer only; `all` = every method; `tld` = TLD expansion; `srv` = SRV records |
| `-a` | — | Perform all enumeration types (alias for `-t all`) | Runs the full suite sequentially |
| `-s` | — | Enable Shodan netblock search (requires API key) | Requires `-w` (WHOIS parsing) or SPF data to work |
| `-w` | — | Parse WHOIS/SPF for CIDR blocks, then search Shodan | Complements `-s` for passive-to-active chain |
| `--shodan` | — | Shorthand for `-s -w` combined | Enables the full Shodan integration |
| `--shodan-key` | `<key>` | Shodan API key (can also use `SHODAN_API_KEY` env var) | Required if `-s`/`--shodan` is used |
| `--shodan-active` | — | Validate discovered IPs against Shodan (active re-resolve) | Slower, confirms Shodan index currency vs. passive check |
| `-D` | — | DNSSEC validation (attempted, may fail on misconfigured zones) | Rarely needed for pentesting |
| `-f` | `<file>` | Output file path (.txt or .xml) | If omitted, results print to stdout |
| `-w` / `--wordlist` | `<file>` | Subdomain wordlist file for brute-forcing (one per line) | Default: bundled wordlist if `-t brt` is used and `-w` is omitted |
| `--threads` | `<count>` | Number of parallel DNS queries (default: 10) | Higher = faster brute-forcing, risk of network saturation / rate-limiting |
| `-v`, `--verbose` | — | Verbose output (more detail on each query) | Useful for debugging failed queries |

## Quick Use-Case List

- Passive domain-enumeration baseline: `-d example.com -t std` (find MX, NS, SOA, A/AAAA records)
- Zone-transfer exploitation: `-d example.com -t axfr` (attempt AXFR against all NS servers)
- Subdomain brute-force discovery: `-d example.com -t brt` (wordlist-based enumeration)
- Combined enumeration sprint: `-d example.com -t all` (zone transfer, standard records, SRV, TLD, brute-force)
- Reverse-DNS enumeration of a CIDR block: `-r 192.168.1.0/24` (map IP-to-hostname)
- Shodan netblock enrichment: `-d example.com -t std -s -w --shodan-key <key>` (discover IPs, parse SPF, search Shodan index)
- Active Shodan re-validation: `-d example.com -t std --shodan --shodan-active` (discover, then confirm in Shodan)
- Bulk enumeration across multiple domains: Create a loop script, iterating `-d example1.com`, `-d example2.com`, etc., feeding output to a results aggregator
- REST API mode for C2 integration: `uv run restdnsrecon` launches a listener, allows programmatic DNS recon without CLI spawning
- Custom resolver targeting: `-d example.com -n <authoritative_ns> -t std` (query a specific nameserver directly, useful if the target has split-DNS or custom internal resolvers)
- Wildcard detection before brute-forcing: `-d example.com -t std` followed by `-d example.com -t brt` after confirming wildcard status
- Zone enumeration pipeline: `-d example.com -t axfr` → if AXFR succeeds, skip brute-forcing; if it fails, `-d example.com -t brt` with a large wordlist

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.12+ | Modern Python (3.12 minimum per `dnsrecon`'s `setup.py`). Older Python will not work. |
| `uv` package manager | Install via the official curl script: `curl -LsSf https://astral.sh/uv/install.sh \| sh` (not `pip`). The tool's own build is tightly tied to `uv`. |
| Network connectivity to UDP/TCP 53 | Outbound DNS queries to the target's authoritative nameservers or a public resolver. No inbound listener needed. |
| Shodan API key (optional) | Only required if using `-s`/`--shodan` flags. Free tier has minimal query limits; paid accounts needed for scale. Can be stored as `SHODAN_API_KEY` env var rather than passed on CLI. |
| Resolver/nameserver access | The target domain's nameservers must be reachable from the attacker's network (usually true since nameservers are public). Custom internal resolvers require network vantage (VPN, compromised host, etc.). |
| WHOIS lookups (optional, for Shodan integration) | `-w`/WHOIS parsing is optional, but often included to extract CIDR blocks from domain registrant records — useful to feed Shodan searches. No credential required. |
| Wordlist file (for brute-forcing) | `-t brt` requires a wordlist. Default bundled list is included; custom wordlists can be supplied via `--wordlist <file>`. |
