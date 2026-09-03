# DNSRecon-DNSDumpster — Hands-On Use Cases

Real-world reconnaissance workflows draw on **both** tools depending on network restrictions: DNSRecon when direct query access is available, DNSDumpster when the target network filters outbound DNS or the operator wants to avoid active-scanning detection signals.

## Contents
- [Standard DNS Enumeration (All Record Types)](#standard-dns-enumeration-all-record-types)
- [Zone Transfer Attempt](#zone-transfer-attempt)
- [Subdomain Brute Force](#subdomain-brute-force)
- [Reverse DNS (IP-to-Hostname Mapping)](#reverse-dns-ip-to-hostname-mapping)
- [Shodan Pivot (Active IPs → Open Ports)](#shodan-pivot-active-ips--open-ports)
- [Passive DNS via DNSDumpster Web Form](#passive-dns-via-dnsdumpster-web-form)
- [DNSDumpster REST API Batch Query](#dnsdumpster-rest-api-batch-query)
- [Chained Workflow — Passive Subdomain Discovery](#chained-workflow--passive-subdomain-discovery)

---

## Standard DNS Enumeration (All Record Types)

**MITRE ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/) (Gather Victim Network Information — DNS)

```bash
dnsrecon -d target.com -t std
```

Queries A, AAAA, MX, NS, SOA, and TXT records for `target.com` from the target's authoritative nameserver (discovered via NS lookup). Each query is a separate DNS wire packet logged on the nameserver if query logging is enabled. The `-t std` ("standard") type is the reconnaissance default — low noise, high signal, appears on virtually every DNS enumeration batch.

## Zone Transfer Attempt

**MITRE ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/)

```bash
dnsrecon -d target.com -t axfr
```

Attempts an AXFR (zone transfer) request against the target's authoritative nameserver — essentially asking for a complete DNS zone file export. Modern nameservers reject AXFR from unauthenticated sources by default, but misconfigured or legacy servers still allow it. A successful AXFR dumps every DNS record in the zone, revealing internal hostnames, IP ranges, and infrastructure layout in a single query — far more data than any individual A/MX query. This is a textbook early-stage reconnaissance signal: an AXFR attempt against a domain you don't own is almost never legitimate.

## Subdomain Brute Force

**MITRE ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/)

```bash
# Default wordlist (built-in dictionary of ~1000 common subdomains)
dnsrecon -d target.com -t brt

# Custom wordlist
dnsrecon -d target.com -t brt -D /path/to/wordlist.txt

# With threading (faster, noisier)
dnsrecon -d target.com -t brt -t 16
```

Tests thousands of probable subdomain names (mail, ftp, www, vpn, api, admin, dev, test, staging, etc.) against the target's authoritative nameserver. Each successful match is a DNS query — visible in query logs and triggerable in IDS/IPS rules for high-volume "negative" DNS responses (many NXDOMAIN replies in a short window). Threads (`-t 16`) speed up enumeration proportionally but increase detectability. Real-world campaigns reserve this for networks with light DNS monitoring or run it offline against cached DNS snapshots (e.g., via DNSDumpster or Censys).

## Reverse DNS (IP-to-Hostname Mapping)

**MITRE ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/)

```bash
# Single IP
dnsrecon -d target.com -t ipv4range -r 192.168.1.0/24

# Multiple IP ranges
dnsrecon -d target.com -t ipv4range -r 10.0.0.0/16,172.16.0.0/12
```

Queries reverse DNS (PTR records) for every IP in a given CIDR range to resolve IP → hostname. Organizations often name hostnames semantically (e.g., `corp-mail-01.internal.target.com`, `dc-philly-01.internal.target.com`), leaking internal naming conventions and infrastructure hints. This is network reconnaissance with minimal noise in logs (one PTR lookup per IP) but high information yield.

## Shodan Pivot (Active IPs → Open Ports)

**MITRE ATT&CK:** [T1590.002](https://attack.mitre.org/techniques/T1590/002/) → [T1595.002](https://attack.mitre.org/techniques/T1595/002/) (Active Scanning → Network Service Scanning)

```bash
dnsrecon -d target.com -t std -s SHODAN_API_KEY
```

Runs standard DNS enumeration, extracts all A records (IPs), then hands each IP to the Shodan API (indexed open-port database). Returns which ports are open on each discovered IP without the attacker's own port scanner ever touching the target network. This is a data-synthesis attack — DNS + Shodan are individually legitimate but chained together become active reconnaissance that avoids triggering port-scan IDS alerts.

## Passive DNS via DNSDumpster Web Form

**MITRE ATT&CK:** [T1598.003](https://attack.mitre.org/techniques/T1598/003/) (Phishing for Information — Search Open Websites)

```bash
# Web form: https://dnsdumpster.com
# Enter domain in search box, click "Search"
# Results: cached A/AAAA/MX/TXT/NS records from HackerTarget database
```

Point a web browser at `dnsdumpster.com`, type the target domain, and receive a cached DNS record snapshot. No active queries against the target; the target's DNS infrastructure sees nothing. Operator's browser makes a single HTTPS request to `dnsdumpster.com`, leaving an HTTP access log and browser history entry. This is the path chosen when the target network blocks outbound DNS on port 53 or when the operator is inside the target network and wants to avoid any sign of active DNS queries.

## DNSDumpster REST API Batch Query

**MITRE ATT&CK:** [T1598.003](https://attack.mitre.org/techniques/T1598/003/)

```bash
# Single domain query
curl -s "https://api.dnsdumpster.com/v2/dns-lookup/target.com" | jq '.data.dns'

# In a script (batch domains)
for domain in $(cat domains.txt); do
  curl -s "https://api.dnsdumpster.com/v2/dns-lookup/$domain" | \
    jq '.data.dns[] | "\(.a), \(.mx), \(.txt)"'
done
```

Programmatic query of the DNSDumpster API returns the same cached DNS records as the web form but in structured JSON. Batch processing multiple domains is fast (sub-second per domain, database lookup only) and leaves no DNS query traces on the target. The operator's HTTP logs show outbound HTTPS requests to `api.dnsdumpster.com`, not to the target domain.

## Chained Workflow — Passive Subdomain Discovery

**MITRE ATT&CK:** [T1598.003](https://attack.mitre.org/techniques/T1598/003/) → [T1590.002](https://attack.mitre.org/techniques/T1590/002/) (passive DNS yields subdomain list, feeds into brute-force scope)

```bash
# Step 1: Query DNSDumpster for cached records (passive)
curl -s "https://api.dnsdumpster.com/v2/dns-lookup/target.com" | \
  jq -r '.data.dns[] | select(.type=="A") | .host' > cached_subdomains.txt

# Step 2: Augment with targeted brute force (active, only if perimeter permits)
dnsrecon -d target.com -t brt -D cached_subdomains.txt

# Step 3: Output format — one per line, ready for follow-on tools (nmap, nuclei, etc.)
cat active_results.txt
```

Demonstrates the **practical division of labor**: DNSDumpster provides a passive baseline of subdomains (known from cache), then a targeted brute force against only those bases saves time and reduces noise compared to a full wordlist scan. The passive step is detection-invisible to the target; the active brute force is concentrated enough to appear as legitimate traffic if DNS logging is sparse.
