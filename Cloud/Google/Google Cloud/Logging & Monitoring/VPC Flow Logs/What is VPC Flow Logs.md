# What is VPC Flow Logs?

**VPC Flow Logs** record a sampled log of **network connections** to and from VM instances in a subnet — source/destination IP and port, protocol, bytes, and which instances/VPCs were involved. They are GCP's answer to "what talked to what," used to find C2, lateral movement, mining-pool traffic, and exfil volume.

## Contents

- [How It Works](#how-it-works)
- [What a Flow Record Contains](#what-a-flow-record-contains)
- [How to Identify Flow Logs in Evidence](#how-to-identify-flow-logs-in-evidence)
- [What You Can and Can't See](#what-you-can-and-cant-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- Enabled **per subnet** (VPC → subnet → Flow logs: on). Off by default.
- Samples flows (configurable sample rate) and aggregates them into records.
- Records land in **Cloud Logging** (`compute.googleapis.com/vpc_flows`) → can route to **BigQuery** for analysis.
- Captures VM↔VM, VM↔internet, and VM↔Google-API traffic that traverses the VPC.

## What a Flow Record Contains

| Field | Tells you |
|-------|-----------|
| `connection.src_ip` / `dest_ip` + ports | The 5-tuple |
| `connection.protocol` | TCP/UDP/… |
| `bytes_sent` / `packets_sent` | 🔴 Volume — exfil sizing |
| `src_instance` / `dest_instance` | Which VMs (project/zone/name) |
| `src_vpc` / `dest_vpc` | Which networks |
| `reporter` | SRC or DEST side |
| `src_location` / `dest_location` | Geo (for internet endpoints) |
| `start_time` / `end_time` | Flow window |

## How to Identify Flow Logs in Evidence

- **Console:** Logging → Logs Explorer → `logName=~"vpc_flows"`; or VPC → subnet → Flow logs.
- **CLI:** `gcloud logging read 'logName:"vpc_flows"'`.
- **BigQuery:** the flow-logs sink dataset (best for volume/aggregation).

## What You Can and Can't See

| ✅ You can | 🔴 You can't |
|-----------|-------------|
| Who connected to whom, ports, bytes | Packet **contents** (no payload) |
| Exfil **volume** and destination IP/geo | Application-layer detail (use app logs) |
| Mining-pool / C2 IP connections | Anything on a subnet without flow logs enabled |
| Lateral movement between VMs | Flows fully within a single host |

> 🔴 Like all flow logs, this is **metadata, not content** — and it's **sampled** and **per-subnet opt-in**. Enable it on sensitive subnets *before* an incident, or the network evidence won't exist.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| VPC Flow Logs | VPC Flow Logs | NSG Flow Logs |
| `bytes_sent` | `bytes` | `bytesSent` |
| `src_instance`/`dest_instance` | ENI / instance | NIC / VM |
| Flow logs → BigQuery | Flow logs → S3/CloudWatch | NSG logs → Log Analytics |

## Common Use Cases

Your "normal" baseline: app-tier traffic, health checks, egress to known SaaS/Google APIs. On a case: spot a VM beaconing to a rare external IP, a mining pool, or a large egress transfer.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Flow log** | A sampled record of a network connection |
| **5-tuple** | src IP/port, dest IP/port, protocol |
| **Sample rate** | Fraction of flows logged |
| **Reporter** | Which side (src/dest) recorded the flow |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with flow logs | **VPC Flow Logs → for DFIR** |
| The VM at the endpoint | **GCP → Compute Engine** |
| The network itself | **GCP → VPC** |
| Mining / C2 scenarios | **GCP → Playbooks → Cryptomining Incident** |

## Resources

- VPC Flow Logs — https://cloud.google.com/vpc/docs/flow-logs
- Flow log record format — https://cloud.google.com/vpc/docs/flow-logs#record_format
- Using flow logs — https://cloud.google.com/vpc/docs/using-flow-logs
