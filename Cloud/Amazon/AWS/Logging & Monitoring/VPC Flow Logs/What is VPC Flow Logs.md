# What is VPC Flow Logs?

**VPC Flow Logs** record **network connections** inside your VPC — source, destination, port, protocol, bytes, and whether traffic was accepted or rejected. They are the **NetFlow of AWS**: no packet contents, but a complete map of *who talked to whom*.

When a finding says "this instance is talking to a mining pool" or "beaconing to C2," Flow Logs are where you **confirm it and find every other host doing the same.**

## Contents

- [How It Works](#how-it-works)
- [What's In a Flow Record](#whats-in-a-flow-record)
- [Reading the Default Format](#reading-the-default-format)
- [What Flow Logs Can and Can't Tell You](#what-flow-logs-can-and-cant-tell-you)
- [How to Identify Flow Logs in Evidence](#how-to-identify-flow-logs-in-evidence)
- [Where They Live](#where-they-live)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

You enable Flow Logs on a **VPC**, a **subnet**, or a single **network interface (ENI)**. AWS then samples the connection metadata and delivers records to **CloudWatch Logs**, **S3**, or **Kinesis Data Firehose**.

```
Traffic through an ENI  →  Flow Logs capture the 5-tuple + bytes + action
                        →  aggregated into ~1–10 min windows
                        →  delivered to S3 / CloudWatch Logs
```

Three facts that shape an investigation:

- 🔴 **Off by default.** Flow Logs must be enabled *before* the incident. No flow logs = no network evidence.
- **Metadata only.** You get the connection facts, **not** payload — no URLs, no packet contents (that's Traffic Mirroring).
- **Aggregated + slightly delayed.** Records cover a capture window (default ~10 min, or ~1 min); allow a few minutes' latency.

## What's In a Flow Record

The **5-tuple** plus volume and verdict:

| Field | Meaning |
|-------|---------|
| `srcaddr` / `dstaddr` | Source / destination IP |
| `srcport` / `dstport` | Source / destination port |
| `protocol` | IANA protocol number (6=TCP, 17=UDP, 1=ICMP) |
| `packets` / `bytes` | Volume — 🔴 large `bytes` outbound = possible exfil |
| `action` | **ACCEPT** or **REJECT** (by security group / NACL) |
| `start` / `end` | Capture window (epoch seconds) |
| `log-status` | OK / NODATA / SKIPDATA |

**Custom fields worth adding** (v3+): `vpc-id`, `subnet-id`, `instance-id`, `tcp-flags`, `pkt-srcaddr`/`pkt-dstaddr` (the *real* endpoints behind NAT), `flow-direction`, `traffic-path`.

> 🔴 **Enable `pkt-srcaddr` / `pkt-dstaddr`.** Behind a NAT gateway, `srcaddr` shows the NAT's IP, hiding which instance actually talked. The `pkt-` fields reveal the true origin — essential for attribution.

## Reading the Default Format

A default record is space-separated:

```
2 123456789012 eni-0abc123 10.0.1.15 203.0.113.9 49152 443 6 22 4500 1720533600 1720533660 ACCEPT OK
│ │            │           │         │           │     │  │ │  │    │          │          │      │
│ │            │           src       dst         sp    dp p pk byte start      end       action status
│ account      eni
version
```

Read it as: *account 12345… on `eni-0abc123`: `10.0.1.15:49152 → 203.0.113.9:443` TCP, 22 packets / 4500 bytes, **ACCEPTED**, in that minute.*

> **`REJECT` records are gold for recon detection:** many REJECTs from one source across many ports/hosts = a **port/host scan** blocked by your SGs/NACLs. Many ACCEPTs to one external IP on a fixed port at a steady interval = **beaconing/C2**.

## What Flow Logs Can and Can't Tell You

| ✅ Can | ❌ Can't |
|-------|---------|
| Who connected to whom, when, how much | The payload / URL / DNS name |
| Accepted vs rejected (SG/NACL verdict) | Whether data was actually stolen (only volume) |
| Port scans, beaconing, large egress | The process/user on the host |
| Lateral movement between instances | Encrypted-content details |
| The real endpoint behind NAT (`pkt-` fields) | Anything if it wasn't enabled |

> Pair Flow Logs with **DNS query logs** (Route 53 Resolver) to turn an IP into a domain, and with **CloudTrail** to tie the host to an identity. Flow Logs = the *network*; you supply the *name* and the *who* from elsewhere.

## How to Identify Flow Logs in Evidence

- **In S3:** `AWSLogs/<acct>/vpcflowlogs/<region>/YYYY/MM/DD/…` (gzipped).
- **In CloudWatch Logs:** a log group like `/aws/vpc/flow-logs` with a stream per ENI.
- **Config (CloudTrail):** `CreateFlowLogs` / `DeleteFlowLogs` events on `ec2.amazonaws.com`.

## Where They Live

| Destination | Query with | Best for |
|-------------|-----------|----------|
| **S3** | **Athena** (SQL) | Long retention, big historical hunts |
| **CloudWatch Logs** | **Logs Insights** | Near-real-time, alarms, quick pivots |
| **Kinesis Firehose** | Downstream (SecOps, etc.) | Streaming to a SIEM |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| VPC Flow Logs | NSG Flow Logs / VNet Flow Logs | VPC Flow Logs |
| Traffic Mirroring (payload) | Virtual Network TAP / packet capture | Packet Mirroring |
| Route 53 Resolver query logs | Azure DNS analytics | Cloud DNS logging |

## Common Use Cases

Your "normal":

- **Network monitoring / troubleshooting** — is traffic reaching a service?
- **Security analytics** — feed GuardDuty; hunt C2/exfil/scans.
- **Compliance** — evidence of network activity.
- **Baseline egress** — knowing normal outbound helps spot the abnormal.

## Key Terminology

| Term | Meaning |
|------|---------|
| **ENI** | Elastic Network Interface — a virtual NIC; the finest capture point |
| **5-tuple** | src IP, dst IP, src port, dst port, protocol |
| **ACCEPT / REJECT** | Allowed or blocked by SG/NACL |
| **Capture window** | The ~1–10 min interval a record aggregates |
| **Security group (SG)** | Stateful per-ENI firewall |
| **NACL** | Stateless per-subnet firewall |
| **NAT gateway** | Shared egress IP — hides instance IPs unless `pkt-` fields on |
| **Traffic Mirroring** | Separate feature that *does* capture payload |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Hunting C2/exfil/scans in Flow Logs | **VPC Flow Logs → VPC Flow Logs for DFIR** |
| The network findings that point here | **AWS → Security & Detection → GuardDuty** |
| The instances involved | **AWS → Compute → EC2** |
| The VPC/SG/NACL structure | **AWS → Networking → VPC** |
| Tying an IP to an identity | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- VPC Flow Logs — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html
- Flow log record fields — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records
- Query flow logs with Athena — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-athena.html
- Route 53 Resolver query logging — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html
