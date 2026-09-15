# VPC for DFIR

VPC investigations answer the **network-structure** questions: *how was this exposed, what firewall let it through, what could move laterally, and did someone change the network to enable the attack?* Pair this with **VPC Flow Logs** (the traffic) — this note is the map you read the traffic against.

New to the service? Read **What is VPC** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Exposure and Lateral Paths](#investigate--exposure-and-lateral-paths)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond — Contain at the Network Layer](#respond--contain-at-the-network-layer)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

The VPC answers **"was this internet-reachable, which firewall rule allowed it, and does the network give the attacker a path onward?"** Network changes are also an attack step — opening an SG or adding a route is how exposure often begins.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| CloudTrail `ec2.*` (SG/route/IGW/peering) | Network config changes + actor | CloudTrail |
| Live network config | Current SGs, NACLs, routes, endpoints | `describe-*` APIs |
| **Config timeline** | When an SG/route changed, before/after | → Config for DFIR |
| **VPC Flow Logs** | The actual traffic (confirm/scope) | → VPC Flow Logs |

## Collect It

```bash
# What's open? Security groups allowing the world
aws ec2 describe-security-groups \
  --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].{Id:GroupId,Name:GroupName}"

# Full detail on a suspect SG
aws ec2 describe-security-groups --group-ids sg-0abc123

# Routing, gateways, peering (exposure + lateral paths)
aws ec2 describe-route-tables --query 'RouteTables[].{Id:RouteTableId,Routes:Routes}'
aws ec2 describe-internet-gateways
aws ec2 describe-vpc-peering-connections
aws ec2 describe-vpc-endpoints

# Who changed the firewall/routing?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress --max-results 50
```

> **Console:** VPC → **Security groups** (Inbound/Outbound rules), **Network ACLs**, **Route tables**, **Internet/NAT gateways**, **Peering**, **Endpoints**. EC2 → instance → *Security* tab for its effective SGs.

## Investigate — Exposure and Lateral Paths

| Question | How to answer |
|----------|---------------|
| Was the host **internet-reachable**? | Public IP + route to IGW + SG allowing the port — all three |
| Which **rule** allowed the attacker in? | The SG ingress rule matching their IP/port (cross-ref Flow Logs ACCEPTs) |
| Did someone **open** it during the incident? | CloudTrail `AuthorizeSecurityGroupIngress` / Config timeline on the SG |
| What can move **laterally**? | SGs referencing other SGs; peering/TGW routes; flat subnets |
| Did routing get **changed**? | `CreateRoute`/`ReplaceRoute` — traffic redirected to a rogue NAT/instance |
| New **egress path**? | New NAT/IGW or widened egress SG (exfil route) |

> **The technique:** Config/CloudTrail tells you *the network change and who made it*; Flow Logs tells you *what traffic then flowed*. Together they turn "the box was reachable" into "this rule, added by this identity at this time, let this IP in — and here's the traffic."

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The network action | `AuthorizeSecurityGroupIngress`, `CreateRoute`, `AttachInternetGateway` |
| `requestParameters.ipPermissions` | The rule (port + CIDR) | 🔴 `0.0.0.0/0` on 22/3389/DB ports |
| `requestParameters.groupId` | Which SG | Map to the affected hosts |
| `userIdentity` | Who changed it | Unexpected identity |
| `requestParameters.destinationCidrBlock` (routes) | New route target | 🔴 redirect |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
-- Firewall openings to the world
SELECT eventtime, useridentity.arn,
       json_extract_scalar(requestparameters,'$.groupId') AS sg,
       requestparameters
FROM cloudtrail_logs
WHERE eventname IN ('AuthorizeSecurityGroupIngress','AuthorizeSecurityGroupEgress')
  AND requestparameters LIKE '%0.0.0.0/0%'
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "AuthorizeSecurityGroupIngress"
```

## Respond — Contain at the Network Layer

| Goal | Action |
|------|--------|
| Isolate a host (keep it alive) | Swap it to an empty **quarantine SG** — stateful SGs drop return traffic, cutting C2 |
| Block an attacker IP/CIDR fast | Add a **NACL deny** at the subnet edge (stateless, blocks broadly) |
| Close the entry rule | `revoke-security-group-ingress` on the offending rule |
| Cut a bad route/egress | Remove the rogue route; tighten egress SG; detach the rogue gateway |
| Cut lateral path | Remove/limit peering; segment with tighter SGs |
| Preserve | Snapshot SG/NACL/route state (Config already has the timeline) before changes |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **No `0.0.0.0/0` on 22/3389/DB ports**; use SSM/bastion + SG references | Removes the classic exposure |
| **Default-deny egress**; only allow needed destinations | Fewer C2/exfil paths; more Flow signal |
| **Segment** with per-tier subnets + SG-to-SG rules | Limits lateral movement |
| **VPC Endpoints** for AWS services; endpoint policies | Data stays off the internet |
| **Config rules**: `restricted-ssh`, `vpc-sg-open-only-to-authorized-ports` | Continuous exposure checks |
| **SCP/alert** on `AuthorizeSecurityGroupIngress` (world), `CreateRoute`, `DeleteFlowLogs`, IGW attach | Catch exposure changes live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| SG opened `0.0.0.0/0` on 22/3389/DB ports | Direct exposure of admin/data ports |
| `AuthorizeSecurityGroupIngress` during the incident | Attacker opening their own way in |
| New route redirecting traffic (`ReplaceRoute`) | Traffic interception/redirect |
| New IGW/NAT or widened egress | New in/out path for exfil/C2 |
| New/accepted VPC peering to an unknown VPC | Lateral-movement bridge |
| `DeleteFlowLogs` | Network evidence destroyed |
| Flat network, everything in one SG | Free lateral movement |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What a VPC is (SG vs NACL, routing) | **VPC → What is VPC** |
| The traffic records | **AWS → Logging & Monitoring → VPC Flow Logs** |
| The hosts you'll isolate | **AWS → Compute → EC2** |
| When a rule changed | **AWS → Security & Detection → Config** |
| Public entry via a load balancer | **AWS → Networking → ELB** |

## Resources

- Security groups — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
- Network ACLs — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
- Control traffic to your resources — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security.html
- MITRE ATT&CK: Modify Cloud Compute Infrastructure (T1578) — https://attack.mitre.org/techniques/T1578/
