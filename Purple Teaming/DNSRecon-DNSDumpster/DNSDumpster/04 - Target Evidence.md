# DNSDumpster — Target Evidence

What the **target host(s) and DNS servers** see when DNSDumpster reconnaissance occurs. Since DNSDumpster queries a **pre-built database owned by HackerTarget** rather than the target's own DNS servers, target-side evidence is **minimal to nonexistent** — the reconnaissance activity does not originate from the operator's IP address.

## Contents
- [No DNS Server Logs (Critical Distinction)](#no-dns-server-logs-critical-distinction)
- [No Network-Layer Evidence on Target](#no-network-layer-evidence-on-target)
- [Target Sees Only HackerTarget's Crawling](#target-sees-only-hackertargets-crawling)
- [External Service Logs (HackerTarget)](#external-service-logs-hackertarget)
- [Comparison to DNSRecon](#comparison-to-dnsrecon)

---

## No DNS Server Logs (Critical Distinction)

**Critical Finding:** When an operator queries DNSDumpster, **zero new DNS queries originate from the operator's IP address** toward the target domain's nameservers.

**Why?** DNSDumpster doesn't perform fresh DNS queries — it returns results from HackerTarget's **pre-built database** of internet-wide scanning. The reconnaissance data is passive historical data, not live queries against the target.

**Consequence for Target DNS Logs:**
```
Target's BIND named.log, Windows DNS logs, or ISP DNS server logs
will show NO queries from the operator's IP for the target domain.
```

The target's DNS servers are **completely unaware** that DNSDumpster reconnaissance has occurred.

---

## No Network-Layer Evidence on Target

### No Inbound Connections

The operator's IP never connects to the target's infrastructure:
- No DNS queries (UDP/TCP 53)
- No HTTP/HTTPS connections to the target's web servers
- No network packets arriving at the target's network perimeter

**Network IDS/Firewall Logs:** Silent. No evidence of the DNSDumpster query.

### No Outbound Detection Points

The target has no way to observe the operator visiting `dnsdumpster.com`:
- The operator's ISP sees the TLS connection to dnsdumpster.com (encrypted)
- The target's network sees nothing

**Forensic Value on Target:** Zero. The target has no direct evidence from its own network infrastructure.

---

## Target Sees Only HackerTarget's Crawling

### Continuous Background Crawling

HackerTarget runs its own network of scanners that perform **independent, continuous internet-wide reconnaissance**. These scans occur **regardless of whether any operator queries DNSDumpster** — they're just part of HackerTarget's infrastructure monitoring.

**What the Target Sees (if monitoring DNS queries):**
```
[Occasional queries from HackerTarget's crawler IPs]
[Reverse-DNS from HackerTarget's scanners]
[Port scans from known HackerTarget/Shodan scanning ranges]

(These would appear in DNS logs/firewall logs, but are NOT specific to the operator's DNSDumpster query)
```

**Forensic Value on Target:** Low. The target may see HackerTarget's own scanning, but cannot distinguish between:
- A random operator querying DNSDumpster for the domain
- HackerTarget's routine crawling
- Any other internet-wide scanning activity

### Historic Scanning Data

The reconnaissance data returned by DNSDumpster is **weeks/days old** — from HackerTarget's last crawl of the target domain. If a target administrator discovers suspicious DNSDumpster data in their infrastructure, they still don't know **when the operator queried it**, because the data itself is historic.

---

## External Service Logs (HackerTarget)

### HackerTarget API Logs (Not on Target's Infrastructure)

HackerTarget (dnsdumpster.com's host) records every API query:
- Operator's source IP
- Domain queried
- Timestamp
- API key used (if Plus tier)
- Response size

**Location:** HackerTarget's own servers (external to the target's infrastructure)

**Forensic Value on Target:** Zero (the logs don't exist on the target's infrastructure). However, if law enforcement or the target organization contacts HackerTarget during an investigation, they may request logs for the operator's IP.

### Web Form Visit Logs

If the operator visited the web form (dnsdumpster.com/?q=example.com), HackerTarget logs:
- Operator's source IP and User-Agent
- Timestamp
- Domain queried (encoded in URL)
- Session ID (cookie)

**Forensic Value on Target:** Zero (not on target's infrastructure). External only.

---

## Comparison to DNSRecon

| Aspect | DNSRecon | DNSDumpster |
|---|---|---|
| **DNS Queries from Operator's IP** | YES — operator's IP queries target's nameservers | NO — queries go to HackerTarget, not target |
| **Target DNS Server Logs** | High evidence (query volume, pattern, source IP) | Zero evidence (target never sees queries) |
| **Target Network IDS Alerts** | Possible (high query volume, AXFR attempts) | No alerts (no queries to target) |
| **Firewall Logs on Target** | Possible (inbound UDP/TCP 53 traffic) | No logs (target never receives traffic) |
| **Historical/Cached Data** | Current (queries run at operator's choice) | Historic (days/weeks old, HackerTarget's crawl) |
| **Operator IP Exposure** | Direct (source IP appears in target's logs) | Indirect (IP only visible to HackerTarget, not target) |
| **Detection Ease (on Target)** | Easy (DNS log analysis) | Difficult/Impossible (no target-side evidence) |

---

## Summary

**For Target Detection Purposes:**

DNSDumpster reconnaissance leaves **zero forensic evidence on the target's own infrastructure** — no DNS server logs, no network IDS alerts, no firewall records. The target is completely unaware of the reconnaissance unless:

1. **Law enforcement or incident responders contact HackerTarget** and request query logs for a suspicious IP
2. **The operator mistakes DNSDumpster for DNSRecon** and also runs active DNS queries (creating target-side logs)
3. **The operator visits dnsdumpster.com from a traced IP** (e.g., from the target's own network while already compromised), making the browser history the discovery vector (not DNSDumpster itself)

This is precisely why DNSDumpster is a favorite tool in restrictive network environments where active scanning triggers immediate alerts — the reconnaissance is **invisible to the target**.

---

## Cross-Reference

For comparison to DNSRecon's extensive target-side evidence, refer to `DNSRecon/04 - Target Evidence.md`. DNSRecon leaves **high-value target-side DNS logs** due to its active query pattern, while DNSDumpster's passive, database-backed approach leaves **no target-side evidence whatsoever**.
