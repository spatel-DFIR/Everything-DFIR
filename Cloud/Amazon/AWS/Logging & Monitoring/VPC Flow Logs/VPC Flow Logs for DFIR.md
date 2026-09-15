# VPC Flow Logs for DFIR

Flow Logs are how you answer the **network** questions: *is this box beaconing? how much data left? what else did the attacker touch inside the VPC?* This note is the hunting playbook for that metadata.

New to the service? Read **What is VPC Flow Logs** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — The Network Questions](#investigate--the-network-questions)
- [Attack Patterns in Flow Data](#attack-patterns-in-flow-data)
- [Athena Queries That Earn Their Keep](#athena-queries-that-earn-their-keep)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Flow Logs answer **"what did this host talk to, how much left, and what else is compromised?"** They confirm C2/exfil/scan findings and, crucially, reveal *lateral movement inside the VPC* that identity logs never see.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| Flow records | 5-tuple + bytes + ACCEPT/REJECT per connection | S3 / CloudWatch Logs |
| `pkt-srcaddr`/`pkt-dstaddr` (if enabled) | True instance behind NAT | Same |
| DNS resolver query logs | IP → domain resolution | Route 53 Resolver logs |
| `CreateFlowLogs`/`DeleteFlowLogs` | Config tamper | CloudTrail |

## Collect It

```bash
# Are flow logs even on, and where do they go?
aws ec2 describe-flow-logs \
  --query 'FlowLogs[].{Id:FlowLogId,Dest:LogDestination,Group:LogGroupName,State:FlowLogStatus}' --output table

# CloudWatch Logs Insights (fast pivot on a suspect instance's ENI)
aws logs start-query --log-group-name /aws/vpc/flow-logs \
  --start-time $(date -d '2026-07-09' +%s) --end-time $(date +%s) \
  --query-string 'fields @timestamp, srcAddr, dstAddr, dstPort, bytes, action
                  | filter srcAddr = "10.0.1.15" | sort bytes desc | limit 100'
```

> **Console:** VPC → **Flow logs** (is it on? destination?). CloudWatch → **Logs Insights** (pick the flow-log group). For S3-delivered logs, use **Athena** (below).
>
> 🔴 If `describe-flow-logs` returns nothing for the VPC/subnet in scope, **there is no network evidence** — note it as a hardening gap and lean on GuardDuty/DNS.

## Investigate — The Network Questions

| Question | How Flow Logs answer it |
|----------|-------------------------|
| Is this host **beaconing** to C2? | Repeated ACCEPTs to one external IP:port at a steady interval |
| Was data **exfiltrated**? | Large outbound `bytes` to an external/unusual destination |
| Is someone **scanning**? | One source → many dst IPs/ports, mostly REJECT |
| **Lateral movement**? | Internal `10.x → 10.x` on admin ports (22/3389/5985) that's abnormal |
| What's the **true origin** behind NAT? | `pkt-srcaddr` — the actual instance |
| Did my **SG/NACL block it**? | `action = REJECT` (blocked) vs ACCEPT (allowed through) |

## Attack Patterns in Flow Data

| Pattern | Flow signature |
|---------|----------------|
| **C2 / beaconing** | Steady, low-byte ACCEPTs to a fixed external IP:port; periodicity |
| **Data exfiltration** | Sustained high outbound `bytes` to an external IP; often port 443/22/53 |
| **Crypto-mining** | ACCEPTs to mining-pool IPs/ports (3333, 4444, 5555, 14444…); pair with GuardDuty `CryptoCurrency` |
| **Port/host scan** | Fan-out REJECTs from one source across many ports/hosts |
| **DNS tunneling** | High volume to port 53 (UDP/TCP); pair with DNS query logs |
| **Reverse shell** | Outbound ACCEPT from a server to an odd external high port, long-lived |
| **Lateral movement** | Internal-to-internal on 22/3389/445/5985 outside normal admin patterns |

## Athena Queries That Earn Their Keep

Assuming an `vpc_flow_logs` table over the S3 logs:

```sql
-- Top external egress talkers (exfil hunt): who sent the most bytes out?
SELECT srcaddr, dstaddr, dstport, sum(bytes) AS total_bytes, count(*) AS flows
FROM vpc_flow_logs
WHERE action = 'ACCEPT'
  AND regexp_like(srcaddr, '^10\.')          -- internal source
  AND NOT regexp_like(dstaddr, '^10\.')      -- external dest
  AND date >= '2026/07/09'
GROUP BY srcaddr, dstaddr, dstport
ORDER BY total_bytes DESC LIMIT 50;

-- Scan detection: sources hitting many distinct ports (mostly rejected)
SELECT srcaddr, count(DISTINCT dstport) AS ports, count(DISTINCT dstaddr) AS hosts
FROM vpc_flow_logs
WHERE action = 'REJECT' AND date >= '2026/07/09'
GROUP BY srcaddr
HAVING count(DISTINCT dstport) > 20
ORDER BY ports DESC;

-- Beaconing: connections to a suspect IP, bucketed by minute (look for regularity)
SELECT date_trunc('minute', from_unixtime(start)) AS minute, count(*) AS conns, sum(bytes) AS b
FROM vpc_flow_logs
WHERE dstaddr = '203.0.113.9'
GROUP BY 1 ORDER BY 1;
```

## Hunt at Scale

Athena (above) is the primary tool for S3-delivered logs; CloudWatch Logs Insights for the CloudWatch destination.

**At the end — SecOps UDM (optional):** Flow Logs ingest as a network-event log type; use it to correlate the external IP across accounts, then return to Athena/Insights for the full connection set.

## Respond

Flow Logs don't have their own "response" — they **direct** it. What you found determines the action:

| Finding | Action (in the linked note) |
|---------|-----------------------------|
| Beaconing / C2 from an instance | Isolate the instance (SG lockdown) → **EC2 for DFIR** |
| Large egress / exfil | Isolate + capture; block the destination; assess data → **EC2**, **S3** |
| Scan source inside VPC | Isolate the scanning host; check how it was compromised |
| Lateral movement | Scope every host it reached; isolate the chain |
| Attacker IP identified | Add NACL deny; feed to WAF/edge blocks |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Flow Logs on every VPC** (S3 + long retention) | No blind network |
| Use **custom format** with `pkt-srcaddr`/`pkt-dstaddr`, `instance-id`, `tcp-flags` | Attribution behind NAT + richer analysis |
| **Enable Route 53 Resolver DNS query logs** | Turns IPs into domains; catches DNS exfil |
| **SCP/alert** on `DeleteFlowLogs` | Attacker can't quietly kill network evidence |
| Tighten **SGs/NACLs**; default-deny egress | Fewer paths for C2/exfil; more REJECT signal |
| Consider **Traffic Mirroring** on crown-jewel subnets | Payload when metadata isn't enough |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Steady low-byte ACCEPTs to one external IP:port | Beaconing / C2 |
| Sustained high outbound bytes to an external dest | Data exfiltration |
| Fan-out REJECTs across ports/hosts from one source | Scanning / recon |
| Internal traffic on 22/3389/445/5985 that's abnormal | Lateral movement |
| Traffic to mining-pool ports (3333/4444/5555/14444) | Crypto-mining |
| Heavy port-53 volume | DNS tunneling/exfil |
| `DeleteFlowLogs` during the incident | Network evidence being destroyed |
| No flow logs at all on the affected VPC | Blind spot — hardening finding |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Flow Logs are + record format | **VPC Flow Logs → What is VPC Flow Logs** |
| The findings that point here | **AWS → Security & Detection → GuardDuty** |
| The compromised instance | **AWS → Compute → EC2** |
| The VPC/SG/NACL you'll harden | **AWS → Networking → VPC** |
| Tying the IP to an identity | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- Query flow logs with Athena — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-athena.html
- Flow log record fields — https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-log-records
- CloudWatch Logs Insights query syntax — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
- MITRE ATT&CK: Exfiltration Over C2 Channel (T1041) — https://attack.mitre.org/techniques/T1041/
