# What is VPC?

A **VPC (Virtual Private Cloud)** is your **private network in AWS** — the subnets, routing, and firewalls that decide what can talk to what. Every EC2 instance, RDS database, and Lambda-in-a-VPC lives inside one.

For DFIR, the VPC is where you answer the **network** questions that aren't about identity: *how was this reachable from the internet? what could move laterally to what? which firewall let it through?* The traffic itself is in **VPC Flow Logs**; this note is the **structure** you reason over.

## Contents

- [How It Works](#how-it-works)
- [The Building Blocks](#the-building-blocks)
- [Security Groups vs NACLs](#security-groups-vs-nacls)
- [How Traffic Reaches the Internet (and Back)](#how-traffic-reaches-the-internet-and-back)
- [How to Identify VPC in Evidence](#how-to-identify-vpc-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
VPC (a private IP range, e.g. 10.0.0.0/16)
├── Subnets (per-AZ IP ranges) — "public" (route to IGW) or "private"
├── Route tables — where traffic goes
├── Internet Gateway (IGW) / NAT Gateway — in/out to the internet
├── Security Groups (per-ENI stateful firewall)
├── NACLs (per-subnet stateless firewall)
├── VPC Endpoints — private access to AWS services (no internet)
└── Peering / Transit Gateway — connect VPCs together
```

- A VPC is **regional**; subnets are per-AZ.
- "Public subnet" just means its route table sends `0.0.0.0/0` to an **Internet Gateway**.
- Firewalling is layered: **NACLs** at the subnet edge, **security groups** at each interface.

## The Building Blocks

| Block | What it is | 🔴 DFIR relevance |
|-------|-----------|-------------------|
| **Subnet** | A per-AZ slice of the VPC's IP range | Public vs private = internet-reachable or not |
| **Route table** | Where traffic for a destination goes | 🔴 a route to a rogue NAT/instance = redirect/exfil |
| **Internet Gateway** | Door to the internet (in + out for public IPs) | Presence = public exposure possible |
| **NAT Gateway** | Outbound-only internet for private subnets | Where private-host egress (C2/exfil) exits |
| **Security Group** | Stateful firewall per ENI | 🔴 the main "what port is open" control |
| **NACL** | Stateless firewall per subnet | Secondary allow/deny; blocks broadly |
| **VPC Endpoint** | Private path to AWS services (S3, etc.) | 🔴 an endpoint policy can restrict/enable data paths |
| **Peering / Transit Gateway** | VPC-to-VPC connectivity | 🔴 lateral-movement paths between networks |

## Security Groups vs NACLs

The distinction you must know cold:

| | **Security Group (SG)** | **NACL** |
|-|-------------------------|----------|
| Scope | Per **ENI/instance** | Per **subnet** |
| State | **Stateful** (return traffic auto-allowed) | **Stateless** (must allow both directions) |
| Rules | **Allow only** | **Allow and Deny** |
| Order | All rules evaluated together | Numbered, first-match |
| DFIR use | The primary "who can reach this host" + **isolation** tool | Broad subnet-level block (e.g. block an attacker CIDR) |

> 🔴 Because SGs are **stateful**, swapping an instance to an empty "quarantine SG" cuts established connections' return traffic — the core **isolation** move (see EC2 for DFIR). NACLs are how you **deny an attacker IP/CIDR at the subnet edge** quickly.

## How Traffic Reaches the Internet (and Back)

Trace exposure by following the route:

| Scenario | Path |
|----------|------|
| **Inbound from internet** | IGW → public subnet route → SG allows → instance with a public IP |
| **Outbound from private host** | Private subnet → NAT Gateway → IGW → internet (this is where C2/exfil exits) |
| **Private AWS access** | VPC Endpoint → the AWS service, **without** touching the internet |

> 🔴 "Is this instance reachable from the internet?" = does it have a **public IP** *and* a route to an **IGW** *and* an **SG** that allows the port. All three must be true. Kill any one to contain.

## How to Identify VPC in Evidence

- **`eventSource`:** `ec2.amazonaws.com` (VPC lives under the EC2 API).
- **ARNs / IDs:** VPC `vpc-…`, subnet `subnet-…`, SG `sg-…`, NACL `acl-…`, route table `rtb-…`, IGW `igw-…`, ENI `eni-…`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `AuthorizeSecurityGroupIngress` | Open an inbound port | 🔴 `0.0.0.0/0` on 22/3389/DB ports |
| `AuthorizeSecurityGroupEgress` | Open outbound | 🔴 widening egress for exfil |
| `CreateSecurityGroup` / `RevokeSecurityGroup*` | Add/change firewall | Config change |
| `CreateRoute` / `ReplaceRoute` | Change routing | 🔴 redirect traffic |
| `CreateInternetGateway` / `AttachInternetGateway` | Add internet access | 🔴 new public exposure |
| `CreateNatGateway` | Add outbound internet | 🔴 egress path for private hosts |
| `CreateVpcPeeringConnection` / `AcceptVpcPeeringConnection` | Link VPCs | 🔴 lateral path |
| `ModifyVpcEndpoint` | Change private service access | Endpoint-policy change |
| `CreateFlowLogs` / `DeleteFlowLogs` | Network logging | 🔴 delete = blind the network |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| VPC | Virtual Network (VNet) | VPC network |
| Subnet | Subnet | Subnet |
| Security Group | Network Security Group (NSG) | Firewall rules |
| NACL | NSG (subnet-associated) | Hierarchical firewall |
| Internet Gateway | (implicit) / Public IP | Internet gateway (implicit) |
| NAT Gateway | NAT Gateway | Cloud NAT |
| VPC Endpoint | Private Endpoint / Service Endpoint | Private Service Connect |
| Peering / TGW | VNet peering / Virtual WAN | VPC peering / Network Connectivity Center |

## Common Use Cases

Your "normal":

- **Network segmentation** — public/private subnet tiers, per-app SGs.
- **Private connectivity** — endpoints to reach S3/DynamoDB without the internet.
- **Hybrid** — VPN/Direct Connect to on-prem.
- **Multi-VPC** — peering / Transit Gateway for shared services.

## Key Terminology

| Term | Meaning |
|------|---------|
| **VPC** | Your isolated virtual network (an IP range) |
| **Subnet** | A per-AZ IP slice; public or private |
| **Route table** | Rules for where traffic goes |
| **IGW / NAT GW** | Internet in-out / outbound-only |
| **Security Group** | Stateful per-ENI firewall |
| **NACL** | Stateless per-subnet firewall |
| **ENI** | Elastic Network Interface (a virtual NIC) |
| **VPC Endpoint** | Private path to an AWS service |
| **Peering / Transit Gateway** | VPC-to-VPC connectivity |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating exposure/lateral paths | **VPC → VPC for DFIR** |
| The traffic records | **AWS → Logging & Monitoring → VPC Flow Logs** |
| The instances inside it | **AWS → Compute → EC2** |
| When a rule changed (timeline) | **AWS → Security & Detection → Config** |
| Load balancers in front | **AWS → Networking → ELB** |

## Resources

- What is Amazon VPC — https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html
- Security groups — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html
- Network ACLs — https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html
- VPC endpoints — https://docs.aws.amazon.com/vpc/latest/privatelink/concepts.html
