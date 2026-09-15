# DNSRecon — Target Evidence

What the **target host(s), DNS servers, and network infrastructure** see when DNSRecon reconnaissance occurs. Since DNSRecon uses only standard DNS queries (no special protocols or exploitation techniques), target-side evidence is purely **network-layer DNS query logs and patterns**.

## Contents
- [DNS Server Query Logs](#dns-server-query-logs)
- [Query Pattern Anomalies](#query-pattern-anomalies)
- [Zone Transfer Attempts](#zone-transfer-attempts)
- [Rate-Limiting and Blacklisting](#rate-limiting-and-blacklisting)
- [DNS Security (DNSSEC) Impacts](#dns-security-dnssec-impacts)
- [External Resolver Exposure](#external-resolver-exposure)
- [Network-Layer Detection](#network-layer-detection)
- [Cross-Link to DNS Logging Reference](#cross-link-to-dns-logging-reference)

---

## DNS Server Query Logs

### Authoritative Nameserver Logs

The **target domain's authoritative nameservers** log every DNS query received. Standard logging includes:
- Query timestamp
- Source IP (the attacker's host)
- Query type (A, AAAA, MX, NS, TXT, AXFR, etc.)
- Query name (the domain/subdomain being queried)
- Response code (NOERROR, NXDOMAIN, REFUSED, etc.)

**Example DNS Server Log (BIND named.log):**
```
[client 192.168.1.100#54321] query (cache) 'example.com' '' A IN
[client 192.168.1.100#54322] query (cache) 'www.example.com' '' A IN
[client 192.168.1.100#54323] query (cache) 'mail.example.com' '' A IN
[client 192.168.1.100#54324] query (cache) 'nonexist-uuid.example.com' '' A IN
[client 192.168.1.100#54325] client 192.168.1.100#54326 (example.com): zone transfer (AXFR) from 192.168.1.100 denied
```

**Forensic Value:** High. Each DNS query is timestamped and attributed to the source IP. An analyst can reconstruct:
- **Timing:** First query → Last query → Duration
- **Target scope:** Every subdomain attempted
- **Technique:** AXFR attempts vs. standard queries vs. brute-force patterns
- **Source IP:** Attacker's network address

### Resolver/Forwarder Logs (Intermediate DNS)

If the target organization uses a **recursive resolver** or DNS forwarder (common in enterprise networks), intermediate logging may capture:
- Queries forwarded to the authoritative NS servers
- Caching behavior
- Query counts per client IP

**Example (Unbound resolver log):**
```
info: 192.168.1.100: query for example.com. A in
info: 192.168.1.100: query for www.example.com. A in
info: 192.168.1.100: query for mail.example.com. A in
```

**Forensic Value:** Medium. Provides broader context if the target monitors recursive resolver traffic.

---

## Query Pattern Anomalies

### Brute-Force Query Bursts

DNSRecon's brute-forcing generates a **rapid sequence of queries** for non-existent subdomains:

**Pattern (from target DNS logs):**
```
10:23:45.123 api.example.com A → NXDOMAIN
10:23:45.134 admin.example.com A → NXDOMAIN
10:23:45.145 backup.example.com A → NXDOMAIN
10:23:45.156 blog.example.com A → NXDOMAIN
...
10:23:45.999 test.example.com A → NXDOMAIN
```

Hundreds of queries in rapid succession (typically <1 second apart, depending on the `--threads` parameter), almost entirely **NXDOMAIN** responses (non-existent domains), is a clear indicator of DNS brute-forcing.

**Detection Signal:** A single IP source generating >100 NXDOMAIN responses in <1 minute for a single domain = highly suspicious DNS enumeration.

**Forensic Value:** Critical. Clear indicator of intentional subdomain brute-forcing.

### Non-Existent Subdomain Queries

DNSRecon's wildcard-detection step queries a random non-existent name:

```
10:23:45.050 nonexist-a7f3e2b1.example.com A → NXDOMAIN (or match if wildcard enabled)
```

A single query for a domain with a long random UUID or timestamp-like suffix is a signature of wildcard detection — human operators almost never guess random UUIDs, but automated tools do routinely.

**Forensic Value:** Medium. Suggests automated tooling rather than manual reconnaissance.

### TLD Expansion Pattern

DNSRecon's TLD expansion tests the domain name across alternate TLDs:

```
10:23:50.100 example.co.uk A → Resolves
10:23:50.150 example.de A → NXDOMAIN
10:23:50.200 example.fr A → NXDOMAIN
10:23:50.250 example.org A → Resolves
```

Sequential queries for the same base name across multiple TLDs in rapid succession is a signature of TLD expansion — rare for manual recon, common for automated tools.

**Forensic Value:** Medium. Suggests automated DNS enumeration.

### Query Type Diversity

DNSRecon queries multiple record types in a single enumeration:

```
10:23:45.010 example.com A
10:23:45.020 example.com AAAA
10:23:45.030 example.com MX
10:23:45.040 example.com NS
10:23:45.050 example.com SOA
10:23:45.060 example.com TXT
10:23:45.070 example.com SPF
10:23:45.080 example.com SRV
```

A single source IP querying multiple record types (A, AAAA, MX, NS, SOA, TXT, SRV) for the same domain in <1 second is a signature of automated standard enumeration — manual reconnaissance typically queries only A/MX records.

**Forensic Value:** Medium. Suggests automated tooling, possibly DNSRecon or a similar scanner.

---

## Zone Transfer Attempts

### AXFR Query Responses

An AXFR (All-Zone-Transfer) request sent to an authoritative NS server:

**Attacker's Query:**
```
QUERY AXFR example.com class IN
```

**Target DNS Server Response (if transfer is denied):**
```
REFUSED (most common on modern DNS)
```

Or, if the server is misconfigured to allow zone transfer:

```
[Complete zone file: every A, AAAA, CNAME, MX, TXT record in the zone, one per response packet]
```

**DNS Server Log Entry (BIND named.log, if transfer is attempted):**
```
[client 192.168.1.100#54321] zone transfer (AXFR) from 192.168.1.100 denied
```

Or, if transfer succeeds (rare, critical vulnerability):

```
[client 192.168.1.100#54321] zone transfer (AXFR) from 192.168.1.100 approved; 256 records transferred
```

**Forensic Value:** Critical. Zone transfer attempts are a **direct attack indicator** — legitimate DNS clients almost never request zone transfers. A single AXFR REFUSED response is a strong indicator of DNS reconnaissance.

---

## Rate-Limiting and Blacklisting

### DNS Rate-Limiting Responses

Modern DNS servers implement **rate-limiting** to slow down aggressive queries:

**Behavior:**
- First 100 queries/second: Responded normally
- Queries 101–500/second: Server rate-limits, returning SERVFAIL or silently dropping packets
- Queries 501+/second: Server temporarily blocks the source IP (common on public DNS like Google 8.8.8.8)

**Evidence (as seen by the attacker):**
```
[+] Query 1–50: Responses received
[+] Query 51–100: Responses received (slower)
[-] Query 101–150: Timeouts, no responses (rate-limited)
```

**Forensic Value on Target:** Low (rate-limiting doesn't generate detailed logs by design — it's a silent throttle). However, a sudden drop in query volume from a single source IP is a signature event.

### IP Blacklisting

If DNSRecon runs with aggressive threading (`--threads 100`), the source IP may be blacklisted by:
- Public DNS resolvers (Google, Cloudflare, Quad9) for abuse
- The target's own firewall or DDoS mitigation

**Evidence:**
- Subsequent DNS queries from the blocked IP return REFUSED or timeout
- The IP may appear in public DNS blacklists (SURBL, etc.) temporarily

**Forensic Value on Target:** Medium. An IP being blacklisted is visible in firewall/resolver logs and suggests aggressive DNS scanning.

---

## DNS Security (DNSSEC) Impacts

### DNSSEC Validation Failures

If DNSRecon queries a DNSSEC-signed zone and the queried nameserver performs strict validation, queries with malformed DNSSEC signatures may fail:

**Log Entry (BIND with DNSSEC enabled):**
```
validation failure reason: NXDOMAIN example.com A IN
```

DNSRecon does not deliberately break DNSSEC signatures, but its rapid-fire queries and brute-forcing of non-existent domains will trigger NXDOMAIN validation if the zone uses NSEC3 (hashed NSEC records for privacy). Each NXDOMAIN response validates the non-existence of the queried name, which is cryptographically sound but heavy on validation CPU.

**Forensic Value:** Low. DNSSEC validation failures are a byproduct of legitimate brute-forcing, not a specific indicator of DNSRecon.

---

## External Resolver Exposure

### Public Resolver Logs (Google DNS, Cloudflare DNS, etc.)

If the attacker uses a public resolver (e.g., `uv run dnsrecon -n 8.8.8.8 -d example.com`) instead of the target's authoritative NS, the target **does not see the queries directly**. However:

1. **Google/Cloudflare DNS records the queries** (with the attacker's IP) and may share logs with the target upon request (via GDPR/legal process).
2. **The target's NS servers eventually see the recursive query** if the public resolver's cache is empty (cache hit = no query to the target NS).

**Forensic Value on Target DNS:** Low if the attacker uses a public resolver (queries bypass target NS logging). However, external logs (Google, Cloudflare) become the evidence source — not on the target's own infrastructure.

---

## Network-Layer Detection

### Packet-Level Signatures (tcpdump, Wireshark, Zeek)

On a network monitoring tool (IDS, network TAP, etc.) between the attacker and the target DNS server:

**Raw DNS packet pattern (Zeek/Suricata alert):**
```
alert dns $HOME_NET any -> $EXTERNAL_NET 53 
  (msg: "Possible DNS zone enumeration"; content:"example.com"; http_client_body; 
   threshold:type both, track by_src, count 100, seconds 60; 
   reference:url,en.wikipedia.org/wiki/DNS_zone_transfer; classtype:attempted_recon; sid:1000001;)
```

**Observable Indicators:**
- High volume of DNS queries from a single source IP (>100 queries/min to a single domain)
- Queries for non-existent subdomains (NXDOMAIN bulk)
- AXFR attempts (zone transfer queries)
- Rapid query-type diversity (A, AAAA, MX, NS, TXT all in sequence)

**Forensic Value:** High. Network IDS/monitoring will flag rapid DNS queries as suspicious.

---

## Cross-Link to DNS Logging Reference

For comprehensive DNS query logging, event ID mappings, and DNSSEC validation details, refer to:
- `Windows/15 - Network Communications/DNS Forensics.md` (Windows DNS server logging, Event IDs, query logs structure)
- `Linux/10 - Network Services/DNS and BIND.md` (BIND named.log format, query logging configuration)

DNS enumeration via DNSRecon generates the same query patterns as any other DNS scanner — the evidence is in the **volume, timing, and pattern of queries**, not in tool-specific artifacts.
