# What is NSG Flow Logs?

**NSG Flow Logs** (and their successor **VNet Flow Logs**) record the **network connections** allowed or denied by a **Network Security Group** — the firewall on Azure subnets/NICs. They are Azure's **VPC Flow Logs equivalent**: the `who-talked-to-whom` at the packet-flow level, without payload.

For DFIR they answer questions no identity log can: *did the compromised VM beacon to a C2? scan internally? exfiltrate over the network?*

## Contents

- [How It Works](#how-it-works)
- [What a Flow Record Contains](#what-a-flow-record-contains)
- [NSG Flow Logs vs VNet Flow Logs](#nsg-flow-logs-vs-vnet-flow-logs)
- [What They Do and Don't Tell You](#what-they-do-and-dont-tell-you)
- [How to Identify Flow Data](#how-to-identify-flow-data)
- [How to Identify Flow Data in Raw Storage](#how-to-identify-flow-data-in-raw-storage)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

An NSG has allow/deny rules. When flow logging is enabled (via **Network Watcher**), each connection evaluated by the NSG is written as a record to a **storage account** (and optionally Log Analytics / **Traffic Analytics**).

🔴 **Off by default** — like VPC Flow Logs, someone must have enabled it before the incident.

## What a Flow Record Contains

| Field | Meaning |
|-------|---------|
| Source / dest **IP** | The two endpoints |
| Source / dest **port** + protocol | The service |
| **Direction** | Inbound / outbound |
| **Decision** | Allowed (`A`) or Denied (`D`) |
| **Flow state** (v2) | Begin / continue / end |
| **Bytes / packets** (v2) | Volume — for exfil sizing |

## NSG Flow Logs vs VNet Flow Logs

| | **NSG Flow Logs** | **VNet Flow Logs** (newer) |
|-|-------------------|-----------------------------|
| Scope | Per-NSG | Per-VNet (broader, simpler) |
| Status | Being retired | The forward path |
| Data | Same core fields | Same + improvements |

> Microsoft is moving to **VNet Flow Logs**; on a modern tenant check there first. The forensic use is identical.

## What They Do and Don't Tell You

| ✅ They tell you | 🔴 They don't |
|------------------|---------------|
| Which IPs/ports talked, direction, allow/deny | Packet **contents** (no payload) |
| Volume (v2) — exfil sizing | The **identity** behind the traffic |
| Denied attempts (scanning/brute force) | DNS names (just IPs) |

> Pair flow logs with the **Activity Log** (who changed the NSG), **identity logs** (who the actor is), and **guest/EDR** (what process) for the full picture.

## How to Identify Flow Data

- **Portal:** Network Watcher → **Flow logs**; **Traffic Analytics** for a visual view.
- **Storage:** JSON blobs under the flow-log storage account.
- **KQL:** `AzureNetworkAnalytics_CL` (Traffic Analytics) or the raw storage.

## How to Identify Flow Data in Raw Storage

If you're pulling flow logs directly from the **storage account** (no Traffic Analytics, no Sentinel) — for example during an offline/archive review — the blobs are written in an **hourly-bucketed** path, one JSON file per hour per flow-enabled resource:

```
https://<storageaccount>.blob.core.windows.net/insights-logs-networksecuritygroupflowevent/
  resourceId=/SUBSCRIPTIONS/<sub-id>/RESOURCEGROUPS/<rg>/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/<nsg-name>/
  y=2026/m=07/d=17/h=14/m=00/
  macAddress=<mac-without-colons>/
  PT1H.json
```

| Path segment | Meaning |
|--------------|---------|
| `resourceId=` | The NSG (or VNet, for VNet Flow Logs) the flows belong to — always **uppercase** |
| `y=YYYY/m=MM/d=DD/h=HH/m=00` | The hour bucket, UTC — `m=00` is fixed, not the log's minute |
| `macAddress=` | The NIC's MAC address (no separators), one folder per interface |
| **`PT1H.json`** | The actual log file — ISO 8601 duration notation for "one hour"; every hour writes a *new* `PT1H.json` in its own `h=HH` folder, it isn't one growing file |

> 🔴 Each `PT1H.json` contains a `records` array of flow-log entries for that resource/interface/hour — pull the whole hour range you need and concatenate. If you're scripting a bulk pull (`az storage blob download-batch` or AzCopy), match on the `PT1H.json` filename and walk the `y=/m=/d=/h=` tree rather than guessing blob names.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| NSG / VNet Flow Logs | VPC Flow Logs | VPC Flow Logs |
| Network Watcher | (VPC/CloudWatch) | Network Intelligence |
| Traffic Analytics | (Athena over flow logs) | Flow analytics |

## Common Use Cases

Your "normal" baseline:

- Traffic auditing + troubleshooting.
- Detecting exposed ports / unexpected egress.
- Confirming segmentation.

## Key Terminology

| Term | Meaning |
|------|---------|
| **NSG** | Network Security Group (firewall) |
| **Flow log** | Record of a connection's allow/deny |
| **Network Watcher** | The service that enables flow logs |
| **Traffic Analytics** | Analyzed/visualized flow data |
| **VNet Flow Logs** | The newer per-VNet flow logging |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating network activity | **NSG Flow Logs → for DFIR** |
| Who changed the firewall | **Azure → Activity Log** |
| The compromised host | **Azure → Virtual Machines** |
| C2/mining network patterns | **Azure → Playbooks → Cryptomining Incident** |

## Resources

- NSG flow logs — https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview
- VNet flow logs — https://learn.microsoft.com/azure/network-watcher/vnet-flow-logs-overview
- Traffic Analytics — https://learn.microsoft.com/azure/network-watcher/traffic-analytics
