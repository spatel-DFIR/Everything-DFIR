# DNSRecon-DNSDumpster — Target Evidence

## Contents
- [The Asymmetry](#the-asymmetry)
- [DNSRecon Target-Side Evidence](#dnsrecon-target-side-evidence)
- [DNSDumpster Target-Side Evidence](#dnsdumpster-target-side-evidence)
- [Building a Timeline from Target Logs](#building-a-timeline-from-target-logs)

---

## The Asymmetry

**Set expectations clearly:** DNSRecon and DNSDumpster create a profound asymmetry in target-side visibility. DNSRecon sends active DNS queries from the operator's IP to the target's authoritative nameservers — visible in DNS query logs and network monitoring if it's enabled. DNSDumpster queries a third-party database and **leaves zero evidence on the target** — the target's DNS infrastructure has no way to know a reconnaissance query ever happened. This makes the two tools fundamentally different from a defense perspective: one is detectable if you log DNS, the other isn't detectable at all on the target side.

---

## DNSRecon Target-Side Evidence

Active DNS enumeration creates observable artifacts wherever DNS is logged or monitored.

### Authoritative Nameserver Query Logs

| Log Source | What it captures | Caveats |
|---|---|---|
| **BIND9 query log** (`querylog` enabled) | Full DNS query text (QNAME, QTYPE), source IP, timestamp, response (ANSWER/NXDOMAIN) | Not enabled by default; requires explicit `querylog yes` in named.conf; can be very verbose (hundreds of queries/sec at scale) |
| **Windows DNS Server Event Log** (Event Viewer > DNS > Analytic) | Query names, source IPs, query types, response codes | Requires "Analytic" event channel to be enabled (Event ID 258+ for queries); not on by default |
| **Cloudflare / hosted DNS provider logs** | Query name, source IP, timestamp, response code | Cloudflare and other hosted providers can enable per-zone query logging; pricing/retention varies |
| **Recursive resolver logs** (if operator queries against 8.8.8.8, 1.1.1.1, etc.) | Query logged by the public resolver, source IP is the operator's IP | Most public resolvers don't retain or expose per-query logs; only local/organizational recursive resolvers have this visibility |

**The signal:** High-volume DNS queries for many subdomains within a short window from a single source IP — especially many NXDOMAIN (non-existent) responses (brute-force signature) — is a direct brute-force enumeration signal.

### Network-Layer Detection (Firewall / IDS / NSM)

| Detection Point | Signal |
|---|---|
| **Firewall / WAF logs** | Inbound UDP/TCP port 53 traffic from an unexpected/external source IP to the organization's nameservers (if nameservers are internet-facing) |
| **Zeek DNS logs** (if passive DNS monitoring is deployed) | High-volume DNS requests from a single source IP for domains under the target zone; `query.resp_codes == "NXDOMAIN"` (non-existent domain) for brute-force enumeration; AXFR request attempt (zone transfer) is an extremely distinctive anomaly signal |
| **Suricata IDS** | Preconfigured rules detect high-volume DNS requests and AXFR attempts; e.g., Suricata rule `alert dns $HOME_NET any -> $EXTERNAL_NET any (msg:"ET DNS Brute Force"; ...)` |
| **NetFlow / sFlow** | Source IP → destination NS IP on port 53, high packet count (many queries), short duration (reconnaissance is fast) |

### Recursive Resolver Logs (Organization-Hosted)

If the target organization runs a recursive resolver (common in enterprise DNS architecture), queries from external sources hitting that resolver show up:

```
# BIND9 query log example
12-Aug-2025 14:23:45.123 queries: client 192.0.2.100#54321 (target.com): query: mail.target.com A +ED
12-Aug-2025 14:23:45.200 queries: client 192.0.2.100#54324 (target.com): query: ftp.target.com A +ED
12-Aug-2025 14:23:45.275 queries: client 192.0.2.100#54327 (target.com): query: vpn.target.com A +ED
[... hundreds of queries in rapid succession ...]
```

The query names are **fully visible** in the log, revealing exactly which subdomains the operator probed for.

### AXFR Attempt Detection

An AXFR (zone transfer) request is immediately suspicious:

```
# BIND9 log of rejected AXFR
12-Aug-2025 14:25:12.456 client 192.0.2.100#53210: query (cache) 'target.com/AXFR/IN' denied
12-Aug-2025 14:25:12.457 transfer of 'target.com/IN': AXFR query from 192.0.2.100#53210 denied
```

Attempting an AXFR against a domain you don't own is nearly always malicious — most organizations have it blocked and will generate alerts.

---

## DNSDumpster Target-Side Evidence

**Spoiler: there is none.**

DNSDumpster is a **passive query against a third-party database**. The target domain's authoritative nameservers are never queried. The target's DNS infrastructure sees nothing — no queries from the operator's IP, no AXFR attempts, no brute-force patterns, nothing.

The operator's HTTP request goes to `dnsdumpster.com` (HackerTarget's infrastructure), not to the target domain's nameservers. HackerTarget's crawlers may have scraped the target's DNS records in the past (weeks/months ago), cached them in their database, and that cached data is what the operator retrieves. The **only** way the target could know a DNSDumpster query happened is if:

1. The operator was already on the target's network and made the HTTPS request from inside — in which case the target's proxy/firewall logs show outbound HTTPS to `dnsdumpster.com`, but not the specific domain queried (it's in the encrypted HTTPS body)
2. The target somehow inspected HackerTarget's infrastructure (out of scope for typical incident response)

**For practical purposes: assume zero target-side evidence for DNSDumpster queries.** The reconnaissance is invisible to the target's own DNS/network monitoring.

---

## Building a Timeline from Target Logs

**For DNSRecon:**

```
[DNS query log on authoritative NS for target.com]
2025-08-12 14:23:45 UTC  Query from 192.0.2.100:54321  subdomain: mail.target.com  QTYPE: A  RESPONSE: ANSWER
2025-08-12 14:23:46 UTC  Query from 192.0.2.100:54322  subdomain: ftp.target.com   QTYPE: A  RESPONSE: NXDOMAIN
2025-08-12 14:23:47 UTC  Query from 192.0.2.100:54323  subdomain: www.target.com   QTYPE: A  RESPONSE: ANSWER
[... 997 more queries in next 30 seconds ...]
2025-08-12 14:24:15 UTC  Query from 192.0.2.100:54520  subdomain: admin.target.com QTYPE: A  RESPONSE: NXDOMAIN

→ Signal: High-volume DNS enumeration pattern from source 192.0.2.100, 1000+ queries in 30 seconds, many NXDOMAIN (brute-force signature)
→ Timeline: 14:23:45–14:24:15 UTC
→ Source IP: 192.0.2.100 (correlate to network device logs, firewall logs, compromised host, etc.)
```

**For DNSDumpster:**

```
[Target's DNS query logs]
← (nothing; no queries from any source for target.com in this time window)

[Target's network firewall logs]
← (if operator was on the target network and made HTTPS request from inside:
   Outbound HTTPS from 10.0.1.50 → 104.21.x.x (HackerTarget IP) port 443
   But the domain queried and search parameters are invisible at the network layer)
```

**Correlation strategy:** If you only have network-layer evidence (firewall logs showing HTTPS to `dnsdumpster.com`), you know an operator on that host made *some* external web request but can't determine what DNS domain was looked up without access to the operator's browser history or HTTP proxy logs that decrypt HTTPS (man-in-the-middle TLS inspection, which is invasive and rare in practice).
