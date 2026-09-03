# ELB for DFIR

When a web app is compromised, the load balancer usually saw the attack request first. ELB DFIR is mostly about **reading ALB access logs** to reconstruct the web attack, and checking that nobody quietly redirected traffic or stripped the WAF.

New to the service? Read **What is ELB** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Reconstruct the Web Attack](#investigate--reconstruct-the-web-attack)
- [Athena Queries for ALB Logs](#athena-queries-for-alb-logs)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

ELB answers **"what web requests hit the app, from whom, and did they succeed?"** — plus "did someone tamper with the front door (routing/WAF/logging)?"

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **ALB access logs** | Per-request: client IP, URL, method, status, UA | 🔴 Off — enable to S3 |
| CloudTrail `elasticloadbalancing.*` | LB/listener/target/WAF/logging changes + actor | ✅ On |
| WAF logs (if attached) | Blocked/allowed L7 requests | If WAF logging on |
| Connection logs (NLB) | L4 connection records | If enabled |

## Collect It

```bash
# Is access logging on, and where?
aws elbv2 describe-load-balancer-attributes --load-balancer-arn <arn> \
  --query "Attributes[?Key=='access_logs.s3.enabled' || Key=='access_logs.s3.bucket']"

# Listeners, rules, targets, WAF
aws elbv2 describe-listeners --load-balancer-arn <arn>
aws elbv2 describe-rules --listener-arn <listener-arn>
aws elbv2 describe-target-health --target-group-arn <tg-arn>

# Config-change history
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyListener --max-results 30
```

> **Console:** EC2 → **Load Balancers** → *Attributes* (access logs), *Listeners*, *Rules*, *Integrated services* (WAF). Access logs live in the S3 bucket → query with **Athena**.

## Investigate — Reconstruct the Web Attack

| Step | Do this |
|------|---------|
| 1 | Pull ALB access logs for the window; filter to the affected host/path |
| 2 | Find the **attacker requests** — malicious URLs (traversal, SQLi, `169.254.169.254`, webshell paths), odd user-agents |
| 3 | Read **status codes** — 200 on a suspicious path = likely success; 4xx walls = scanning |
| 4 | Get the **real client IP(s)** and pivot: same IP elsewhere? (Flow Logs, CloudTrail) |
| 5 | Correlate to the **backend** — the request that hit the ALB → what the app/instance did (→ EC2) |
| 6 | Check **tamper**: WAF detached, routing changed, access logs disabled during the window |

## Athena Queries for ALB Logs

Assuming an `alb_logs` table:

```sql
-- Suspicious request patterns (SSRF / traversal / webshell)
SELECT time, client_ip, request_verb, request_url, elb_status_code, user_agent
FROM alb_logs
WHERE (request_url LIKE '%169.254.169.254%'   -- IMDS SSRF attempt
    OR request_url LIKE '%../%'                -- path traversal
    OR request_url LIKE '%.php%' OR request_url LIKE '%cmd=%')
  AND parse_datetime(time,'yyyy-MM-dd''T''HH:mm:ss.SSSSSS''Z') > timestamp '2026-07-09'
ORDER BY time;

-- Top client IPs by request volume (scan/brute detection)
SELECT client_ip, count(*) AS reqs, count_if(elb_status_code >= 400) AS errors
FROM alb_logs GROUP BY client_ip ORDER BY reqs DESC LIMIT 50;
```

## Respond

| Goal | Action |
|------|--------|
| Block the attacker | WAF rule / IP set to block the client IP(s); NACL deny at the subnet edge |
| Restore protection | Re-attach the WAF Web ACL if it was removed |
| Fix hijacked routing | Revert malicious listener rules / target registrations |
| Re-enable logging | Turn access logs back on |
| Contain the backend | Isolate the compromised instance (→ EC2 for DFIR) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable ALB access logs** to a locked S3 bucket | Web-request evidence exists next time |
| **Attach AWS WAF** with managed rule groups (SSRF/SQLi/LFI) | Blocks common web attacks at the edge |
| **TLS-only listeners**, modern ciphers | No plaintext/downgrade |
| **Alert** on `SetWebAcl` (detach), `ModifyListener`, access-log disable | Catch front-door tampering |
| **Restrict who can register targets** | No attacker backends |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| ALB log request to `169.254.169.254` | IMDS SSRF attempt (→ EC2 role theft) |
| 200 on traversal/webshell/`cmd=` URLs | Successful web exploit |
| WAF Web ACL detached during the window | Protection stripped |
| Listener rule / target changed to a rogue backend | Traffic hijack |
| Access logging disabled mid-incident | Evidence turned off |
| One IP with high 4xx then a 200 | Scan that found a hit |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What ELB is + log format | **ELB → What is ELB** |
| The compromised backend | **AWS → Compute → EC2** |
| Network exposure | **AWS → Networking → VPC** |
| The SSRF→role-theft chain | **AWS → Playbooks → IMDS SSRF to Role Theft** |

## Resources

- ALB access logs — https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
- Query ALB logs with Athena — https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html
- AWS WAF — https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html
- MITRE ATT&CK: Exploit Public-Facing Application (T1190) — https://attack.mitre.org/techniques/T1190/
