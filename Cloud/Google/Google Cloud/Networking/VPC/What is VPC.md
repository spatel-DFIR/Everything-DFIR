# What is VPC (Virtual Private Cloud)?

**VPC** is GCP's software-defined network — the networks, **subnets**, **firewall rules**, routes, and perimeters your resources live in. For DFIR it matters as the **exposure and exfil boundary**: an attacker opens a firewall to reach a VM, peers a network to move data, or weakens **VPC Service Controls** to exfiltrate.

## Contents

- [How It Works](#how-it-works)
- [Firewall Rules — The Exposure Control](#firewall-rules--the-exposure-control)
- [VPC Service Controls — The Exfil Boundary](#vpc-service-controls--the-exfil-boundary)
- [How to Identify VPC in Evidence](#how-to-identify-vpc-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **VPC network** is global; **subnets** are regional. Resources (VMs, GKE, etc.) attach to subnets.
- **Firewall rules** control ingress/egress by priority, direction, source/target, ports.
- **Cloud NAT**, **VPC peering**, **Shared VPC**, **Private Google Access**, and **VPC Service Controls** shape connectivity and data-egress boundaries.

## Firewall Rules — The Exposure Control

| Concept | Detail |
|---------|--------|
| **Direction** | Ingress (in) / egress (out) |
| **Action** | Allow / deny |
| **Priority** | Lower number wins |
| **Source/target** | IP ranges, tags, service accounts |

🔴 The classic exposure: an **ingress allow from `0.0.0.0/0`** to SSH/RDP/a database port. Watch `compute.firewalls.insert/patch`. **Firewall Rules Logging** shows what each rule allowed/denied.

## VPC Service Controls — The Exfil Boundary

**VPC Service Controls (VPC-SC)** draws a **perimeter** around GCP services (e.g. GCS, BigQuery) so data can't be copied to projects/identities outside it — a strong anti-exfil control.

- Requests blocked by a perimeter appear in **Policy Denied** logs (recon/exfil attempts).
- 🔴 An attacker who can modify the perimeter (`accesscontextmanager` / VPC-SC changes) to **add their project** or **weaken** it is enabling exfil — a defense-evasion signal.

## How to Identify VPC in Evidence

- **Resource names:** `//compute.googleapis.com/projects/<p>/global/networks/<net>`, `.../firewalls/<rule>`.
- **Config events:** `compute.firewalls.insert/patch/delete`, `compute.networks.*`, peering, VPC-SC/`accesscontextmanager` changes.
- **Flow evidence:** VPC Flow Logs (separate note); **Firewall Rules Logging**.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `compute.firewalls.insert/patch` | Add/change a firewall rule | 🔴 open `0.0.0.0/0` ingress |
| `compute.networks.addPeering` | Peer to another VPC | 🔴 exfil/lateral path |
| VPC-SC / access-level change | Modify the exfil perimeter | 🔴 defense evasion |
| `compute.routes.insert` | Add a route | 🔴 redirect traffic |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| VPC network | VPC | VNet |
| Subnet | Subnet | Subnet |
| Firewall rule | Security group / NACL | NSG rule |
| VPC Service Controls | (no direct equal) / SCP + endpoints | Private Link + policy |
| VPC peering | VPC peering | VNet peering |
| Cloud NAT | NAT gateway | NAT gateway |

## Common Use Cases

Your "normal": tiered networks, allowlisted ingress, egress via NAT, perimeters around sensitive data. The job is to spot **new exposure** (open firewall), **new connectivity** (peering), or a **weakened perimeter**.

## Key Terminology

| Term | Meaning |
|------|---------|
| **VPC network / subnet** | The network / regional segment |
| **Firewall rule** | Ingress/egress allow/deny |
| **VPC Service Controls** | Data-exfil perimeter |
| **Peering** | Network-to-network connection |
| **Shared VPC** | One VPC shared across projects |
| **Private Google Access** | Reach Google APIs without external IP |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating VPC changes in a case | **VPC → for DFIR** |
| The flow evidence | **GCP → VPC Flow Logs** |
| The VM behind a firewall change | **GCP → Compute Engine** |
| Load-balanced ingress | **GCP → Cloud Load Balancing** |

## Resources

- VPC overview — https://cloud.google.com/vpc/docs/vpc
- Firewall rules — https://cloud.google.com/firewall/docs/firewalls
- VPC Service Controls — https://cloud.google.com/vpc-service-controls/docs/overview
