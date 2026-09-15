# Route 53 for DFIR

Route 53 shows up two ways: as a **detection source** (DNS query logs revealing C2/exfil) and as a **target** (record/domain hijack, subdomain takeover). This note covers hunting in DNS logs and investigating tampering with your names.

New to the service? Read **What is Route 53** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Hunting Subdomain Takeover](#hunting-subdomain-takeover)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Route 53 answers **"what are our hosts resolving (C2/exfil?), and did someone repoint or steal our names?"** DNS is both a great sensor and a high-impact hijack target.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **Resolver query logs** | Every domain instances resolved | 🔴 Off — enable |
| CloudTrail `route53*.*` | Record/zone/NS/resolver changes + actor | ✅ On (us-east-1) |
| Current records | The live DNS config to compare against known-good | Live pull |
| Domain settings | NS, transfer lock (if registered here) | Live pull |

## Collect It

```bash
# The zones + records (compare to your known-good baseline)
aws route53 list-hosted-zones
aws route53 list-resource-record-sets --hosted-zone-id Z0ABC123 > records.json

# Who changed DNS? (logs to us-east-1)
aws cloudtrail lookup-events --region us-east-1 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ChangeResourceRecordSets --max-results 50

# Domain-level protection (if registered via Route 53)
aws route53domains get-domain-detail --domain-name example.com \
  --query '{NS:Nameservers,Lock:StatusList}'
```

> **Console:** Route 53 → **Hosted zones** (records) → *Change history*. **Resolver → Query logging**. **Registered domains** (NS + transfer lock).

## Investigate

| Step | Do this |
|------|---------|
| 1. DNS-as-sensor | Query the Resolver logs for the window: malware/C2/DGA domains, high port-53 volume (tunneling) |
| 2. Record integrity | Diff current records vs known-good; look for repointed A/CNAME/MX/NS/TXT |
| 3. Change timeline | CloudTrail `ChangeResourceRecordSets` / NS changes — who, when |
| 4. Domain hijack | NS changed? transfer lock disabled? (registrar-side theft) |
| 5. Takeover hunt | Dangling records pointing at deleted resources (below) |

## Hunting Subdomain Takeover

```bash
# For each CNAME target, does the resource still exist?
# e.g. a CNAME to <name>.s3-website-us-east-1.amazonaws.com whose bucket was deleted
aws route53 list-resource-record-sets --hosted-zone-id Z0ABC123 \
  --query "ResourceRecordSets[?Type=='CNAME'].{Name:Name,Target:ResourceRecords[0].Value}"
```

Then check each target: a CNAME pointing to a **non-existent** S3 website, ELB, CloudFront, or third-party SaaS = 🔴 **takeover-able**. An attacker recreates the target and owns that subdomain for phishing/cookie theft.

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `ChangeResourceRecordSets`, `UpdateDomainNameservers`, `DisableDomainTransferLock` |
| `requestParameters.changeBatch` | The record change (before→after) | 🔴 name repointed to attacker IP/host |
| `userIdentity` | Who changed DNS | Unexpected identity |
| `sourceIPAddress` | From where | External/new |

## Hunt at Scale

**In-platform — Athena over Resolver query logs + CloudTrail:**

```sql
-- Instances resolving suspicious/rare domains (C2/DGA hunt)
SELECT query_name, srcaddr, count(*) AS n
FROM resolver_query_logs
WHERE query_timestamp > '2026-07-09'
GROUP BY query_name, srcaddr
ORDER BY n DESC;   -- then triage rare/random-looking names + known-bad
```

**At the end — SecOps UDM (optional):** DNS query logs ingest as a DNS log type — use it to correlate resolved domains across the fleet, then confirm the host in EC2/Flow.

## Respond

| Goal | Action |
|------|--------|
| Revert a hijacked record | Restore the correct record; verify propagation |
| Recover a stolen domain | Re-enable transfer lock; restore correct NS; work the registrar |
| Fix a takeover | Delete the dangling record (or reclaim the target yourself) |
| Block C2 domain | Route 53 Resolver DNS Firewall rule to block the domain; NACL/WAF as backup |
| Preserve | Snapshot the zone records + query logs |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Resolver query logging** (all VPCs) | DNS-side C2/exfil visibility |
| **Route 53 Resolver DNS Firewall** with threat-intel domain lists | Block known-bad resolution |
| **Domain transfer lock ON**; registrar MFA | Prevents domain theft |
| **Audit dangling records** regularly | Kills subdomain-takeover exposure |
| **Alert** on `ChangeResourceRecordSets`, NS changes, `DeleteResolverQueryLogConfig` | Catch hijack/blinding |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Instances resolving DGA/random or known-bad domains | C2 / malware |
| High port-53 volume from a host | DNS tunneling/exfil |
| A record/CNAME repointed to unknown infra | DNS hijack / phishing / MITM |
| NS change or transfer lock disabled | Domain hijack in progress |
| Dangling CNAME to a deleted resource | Subdomain-takeover exposure |
| `DeleteResolverQueryLogConfig` | DNS evidence turned off |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Route 53 is | **Route 53 → What is Route 53** |
| The traffic behind the DNS | **AWS → Logging & Monitoring → VPC Flow Logs** |
| C2/DGA findings | **AWS → Security & Detection → GuardDuty** |
| Buckets behind takeover | **AWS → Storage → S3** |

## Resources

- Resolver query logging — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html
- Route 53 Resolver DNS Firewall — https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html
- MITRE ATT&CK: Dynamic Resolution / DNS (T1568) — https://attack.mitre.org/techniques/T1568/
- MITRE ATT&CK: Domain Hijacking (T1584.001) — https://attack.mitre.org/techniques/T1584/001/
