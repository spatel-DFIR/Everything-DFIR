# What is Lightsail?

**Lightsail** is AWS's **simplified VPS product** — a bundled instance + block storage + static IP + basic firewall + DNS, sold at a flat monthly price. It runs on the same underlying Nitro/EC2 infrastructure as EC2, but it is a **distinct AWS service** with its own console, its own API namespace, and its own CloudTrail event source. Think "DigitalOcean droplet, but it's AWS."

🔴 **The reason this matters for DFIR:** Lightsail instances are **invisible to the tooling analysts normally sweep with.** They do not show up in VPC Flow Logs, they do not appear in the EC2 console or EC2 Global View, and a `describe-instances` sweep across regions returns nothing for them. If you don't know Lightsail exists as a separate product, you will conclude an account has no compute when it actually does.

## Contents

- [How It Works](#how-it-works)
- [Why It Looks Like EC2 but Isn't](#why-it-looks-like-ec2-but-isnt)
- [The Networking Model](#the-networking-model)
- [Snapshots and Backups](#snapshots-and-backups)
- [How to Identify Lightsail in Evidence](#how-to-identify-lightsail-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
"Bundle" (fixed instance size + SSD + data transfer allowance)
   + Blueprint (OS or app image)
   + Static IP (optional, free while attached)
   + Lightsail firewall (per-instance, not a Security Group)
        →  launched as a LIGHTSAIL INSTANCE, in its own Lightsail-managed VPC
```

- A **bundle** is the plan — a fixed combination of vCPU/RAM/SSD/transfer for a flat monthly price (no separate EBS/EIP/data-transfer billing to reason about).
- A **blueprint** is the image — an OS (Linux/Windows) or a pre-built app stack (WordPress, Node.js, etc.).
- Instances live in an **AWS-managed VPC that customers don't see or configure** — there's no subnet/route-table/NACL model exposed to you the way EC2's VPC is.
- Lightsail also offers **managed databases, container services, and object storage (buckets)** as separate but similarly bundled products — this note focuses on compute instances, the part that maps to EC2.

## Why It Looks Like EC2 but Isn't

Lightsail instances **run on the same Nitro hypervisor as EC2** — under the hood it's the same virtualization stack. But operationally it is walled off:

| | EC2 | Lightsail |
|---|---|---|
| Console | EC2 console | **Separate Lightsail console** (`lightsail.aws.amazon.com`) |
| API / CLI namespace | `ec2.*` (`aws ec2 ...`) | **`lightsail.*`** (`aws lightsail ...`) |
| CloudTrail `eventSource` | `ec2.amazonaws.com` | `lightsail.amazonaws.com` |
| Appears in EC2 Global View / `describe-instances`? | ✅ Yes | 🔴 **No** |
| Appears in VPC Flow Logs? | ✅ Yes (customer VPC) | 🔴 **No** (Lightsail-managed VPC, not exposed) |
| Firewall construct | Security Group (stateful, VPC-attached) | **Lightsail firewall** (per-instance, simpler rule list — see below) |
| IAM model | Full IAM policy control over EC2 actions | IAM can allow/deny `lightsail:*` actions, but there's no equivalent to Security Group / NACL layering |

🔴 An analyst who runs the standard "enumerate every EC2 instance across every region" sweep (`describe-instances`, EC2 Global View, or a VPC Flow Log review) **will not see Lightsail instances at all.** They are a genuinely separate inventory that has to be checked on its own.

## The Networking Model

- **Static IP:** Lightsail instances can be assigned a **static IP** (Lightsail's equivalent of an Elastic IP) — free as long as it's attached to a running instance.
- **Lightsail firewall:** each instance has its own firewall — a flat list of allowed inbound rules (port/protocol/source), configured per-instance or per-instance-snapshot. It is **not** a Security Group and does not live in the EC2/VPC security-group namespace — `aws ec2 describe-security-groups` will not show it.
- **No customer-visible VPC/subnet/NACL/route-table.** You cannot attach a Lightsail instance to your own VPC directly; **VPC peering** is available to bridge a Lightsail-managed network to an existing AWS VPC if you need one, but by default Lightsail traffic never touches your VPC and therefore never generates VPC Flow Log records.
- **DNS:** Lightsail includes its own simple DNS zone management, separate from Route 53 (though Route 53 can still be used to point a domain at a Lightsail static IP).

## Snapshots and Backups

- **Manual instance snapshots** — a full image (OS + attached disk) you can create on demand or restore from, similar in spirit to an EC2 AMI but scoped to Lightsail.
- **Automatic snapshots** — an optional daily-snapshot schedule per instance, retained for a configurable number of days (up to 7), with no separate EBS-snapshot billing model to track — it's part of the bundle price.
- Snapshots can be **exported to EC2** (converted into an AMI) — a useful pivot for forensics: if you need full EC2-grade tooling (create-volume, attach to a forensic instance, mount read-only), export the Lightsail snapshot to an EC2 AMI first, then investigate it the same way you would an `EC2 for DFIR` snapshot.

## How to Identify Lightsail in Evidence

- **`eventSource`:** `lightsail.amazonaws.com` — this is the tell in CloudTrail. If you see this, you're looking at a Lightsail action, not EC2.
- **ARNs:** `arn:aws:lightsail:<region>:<acct>:Instance/<instance-name>` (Lightsail instances are named, not `i-…` IDs).
- **Console:** only visible in the dedicated Lightsail console, not the EC2 console.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateInstances` | Launch one or more Lightsail instances | 🔴 unexpected compute an EC2 sweep would miss |
| `DeleteInstance` | Terminate an instance | 🔴 evidence destruction |
| `OpenInstancePublicPorts` / `PutInstancePublicPorts` | Change the Lightsail firewall rules | 🔴 opening SSH/RDP/app ports to `0.0.0.0/0` |
| `CreateInstancesFromSnapshot` | Restore/clone from a snapshot | Persistence via re-deploy |
| `CreateInstanceSnapshot` / `ExportSnapshot` | Snapshot / export a disk image | Export = pivot point to EC2 AMI for exfil or forensics |
| `AllocateStaticIp` / `AttachStaticIp` | Assign a static IP | Track network identity of the instance |
| `DownloadDefaultKeyPair` / `GetInstanceAccessDetails` | Retrieve SSH access material | 🔴 credential access |
| `UpdateInstanceMetadataOptions` | Change instance metadata service behavior | Same IMDS logic as EC2 — check `HttpTokens` |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| **Lightsail instance** | Azure VM (via simplified "quickstart" templates — no exact 1:1 product) | Google Cloud's simplified VM offerings (no exact 1:1 product) |
| Lightsail firewall | NSG (simplified) | Firewall rule (simplified) |
| Lightsail static IP | Azure Public IP | GCE static external IP |

There isn't a clean 1:1 "simplified VPS" product on the other major clouds the way Lightsail is on AWS — the closest analogy is a managed/simplified hosting provider (DigitalOcean, Linode) bolted onto AWS's own infrastructure.

## Common Use Cases

Why organizations run Lightsail (your baseline for "normal"):

- **Small websites/blogs, dev/test boxes, internal tools** — workloads too small to justify full EC2/VPC design.
- **Quick prototypes** by developers who want a box without touching IAM/VPC/Security Groups.
- **Shadow IT** — because it's cheap, simple, and separate from the "real" EC2 estate, it's also a common place for **unsanctioned instances** to live unnoticed.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Instance** | A Lightsail VM, identified by name (not `i-…`) |
| **Bundle** | The fixed size/price plan (vCPU/RAM/SSD/transfer) |
| **Blueprint** | The OS or app image an instance boots from |
| **Lightsail firewall** | Per-instance inbound port rule list — distinct from Security Groups |
| **Static IP** | Lightsail's Elastic-IP equivalent |
| **Instance snapshot** | Lightsail's AMI/EBS-snapshot equivalent |
| **Snapshot export** | Converts a Lightsail snapshot into a standard EC2 AMI |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a Lightsail instance in a case | **Lightsail → Lightsail for DFIR** |
| EC2's own model (for comparison, and for exported snapshots) | **AWS → Compute → EC2 → What is EC2** |
| Every AWS action's audit trail | **AWS → Logging & Monitoring → CloudTrail** |
| Why VPC Flow Logs won't show this traffic | **AWS → Logging & Monitoring → VPC Flow Logs** |

## Resources

- Lightsail overview — https://docs.aws.amazon.com/lightsail/latest/userguide/what-is-amazon-lightsail.html
- Lightsail instance snapshots — https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-configuring-automatic-instance-and-attached-disk-snapshots.html
- Export a Lightsail snapshot to EC2 — https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-export-snapshot-to-amazon-ec2.html
- Lightsail firewall — https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-editing-instance-firewall-rules.html
