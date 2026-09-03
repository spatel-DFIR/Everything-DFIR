# What is Route 53?

**Route 53** is AWS's **DNS**. It hosts your domains (public and private), answers DNS queries, and does health-checked routing. Its DFIR relevance is threefold: **DNS query logs** (a rich source for C2/exfil detection), **domain/record hijacking** (attackers repointing your names), and **subdomain takeover** (dangling records pointing at reclaimable resources).

## Contents

- [How It Works](#how-it-works)
- [The Pieces](#the-pieces)
- [Three Ways It Shows Up in a Case](#three-ways-it-shows-up-in-a-case)
- [DNS Query Logging](#dns-query-logging)
- [How to Identify Route 53 in Evidence](#how-to-identify-route-53-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Hosted zone (example.com) → Records (A, CNAME, MX, TXT, NS…) → answers to DNS queries
Route 53 Resolver → what your VPC's instances resolve (and can log)
```

- **Global** service (records answer worldwide); events log to **`us-east-1`**.
- **Public hosted zones** serve the internet; **private hosted zones** serve inside a VPC.
- The **Resolver** is the VPC-side DNS that your instances use — and where **query logging** happens.

## The Pieces

| Piece | What it is | 🔴 DFIR relevance |
|-------|-----------|-------------------|
| **Hosted zone** | A domain's record container | 🔴 control of the zone = control of the name |
| **Record set** | A DNS entry (A/CNAME/MX/TXT/NS) | 🔴 repointed record = hijack/phishing/MITM |
| **Resolver query logging** | Logs what instances resolve | 🎯 C2/DGA/DNS-exfil detection |
| **Domain registration** | The registrar side (if bought via Route 53) | 🔴 nameserver change = full hijack |
| **Health checks / routing policies** | Failover/geo/weighted routing | Traffic steering |

## Three Ways It Shows Up in a Case

| Scenario | What happens | Signature |
|----------|--------------|-----------|
| **DNS as detection** | Instances resolving malware/C2/DGA domains | Resolver query logs → bad domains |
| **Record/domain hijack** | Attacker edits records (or NS) to repoint your name | `ChangeResourceRecordSets` / NS change to attacker infra |
| **Subdomain takeover** | A dangling CNAME points at a deleted/reclaimable resource; attacker claims it | A record pointing to a non-existent S3 site/ELB/etc. |

> 🔴 **Subdomain takeover** is subtle: `blog.example.com` CNAMEs to an S3 website bucket that was later deleted. An attacker recreates a bucket with that name and now *owns* `blog.example.com` for phishing. Hunt for dangling records pointing at removed resources.

## DNS Query Logging

🔴 **Off by default**, but one of the most valuable network-side sources when on:

- Logs every domain your VPC's instances resolve → catches **C2 beacons**, **DGA** patterns, and **DNS-tunnel exfil** that Flow Logs (IP-only) can't name.
- Pairs perfectly with **VPC Flow Logs**: Flow gives the IP + volume, DNS query logs give the *name*.

## How to Identify Route 53 in Evidence

- **`eventSource`:** `route53.amazonaws.com` (zones/records), `route53resolver.amazonaws.com` (Resolver), `route53domains.amazonaws.com` (registration).
- **ARNs / IDs:** hosted zone `/hostedzone/Z…`; records identified by name+type.
- **Query logs:** delivered to CloudWatch Logs / S3.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `ChangeResourceRecordSets` | Add/edit/delete DNS records | 🔴 repointing a name (hijack/phishing) |
| `CreateHostedZone` / `DeleteHostedZone` | Add/remove a zone | 🔴 zone tampering |
| `UpdateDomainNameservers` (domains) | Change NS delegation | 🔴 full domain hijack |
| `DisableDomainTransferLock` | Remove transfer protection | 🔴 domain theft prep |
| `CreateResolverRule` / `AssociateResolverRule` | Redirect DNS resolution | 🔴 DNS interception |
| `DeleteResolverQueryLogConfig` | Stop DNS logging | 🔴 blinding DNS evidence |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Route 53 | Azure DNS | Cloud DNS |
| Resolver query logging | Azure DNS analytics | Cloud DNS logging |
| Hosted zone | DNS zone | Managed zone |
| Route 53 Domains | App Service Domains | Cloud Domains |

## Common Use Cases

Your "normal":

- **Public DNS** for your domains/apps.
- **Private DNS** inside VPCs (service discovery).
- **Health-checked failover / geo routing.**
- **Domain registration + management.**

## Key Terminology

| Term | Meaning |
|------|---------|
| **Hosted zone** | Container for a domain's records |
| **Record set** | A DNS entry (A/CNAME/MX/TXT/NS) |
| **Resolver** | The VPC-side DNS instances use |
| **Query logging** | Logs of resolved domains |
| **Nameserver (NS)** | The authoritative servers for a domain |
| **Transfer lock** | Registrar protection against domain theft |
| **Subdomain takeover** | Claiming a dangling record's target |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating DNS hijack/exfil | **Route 53 → Route 53 for DFIR** |
| The network traffic behind the DNS | **AWS → Logging & Monitoring → VPC Flow Logs** |
| C2/DGA findings | **AWS → Security & Detection → GuardDuty** |
| Buckets behind subdomain takeover | **AWS → Storage → S3** |

## Resources

- What is Route 53 — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/Welcome.html
- Resolver query logging — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html
- Logging Route 53 API calls — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/integrating-with-cloudtrail.html
