# NSG Flow Logs for DFIR

When you need to know what a compromised Azure host talked to — C2, internal scanning, exfil volume — flow logs are the evidence. This note is how you pull and read them.

New to the service? Read **What is NSG Flow Logs** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Needs |
|--------|--------------|-------|
| **Traffic Analytics** (`AzureNetworkAnalytics_CL`) | Analyzed flows in Log Analytics | Enabled + LA workspace |
| **Raw flow-log storage** | JSON flow blobs | Flow logging enabled |
| **Network Watcher** | Config + connection troubleshoot | — |

## Collect It

**Confirm flow logging is even on:**

```bash
az network watcher flow-log list --location <region> -o table
```

> **Console:** Network Watcher → **Flow logs** (is it enabled for the relevant NSG/VNet?) → **Traffic Analytics** for the visual view.

**If it's off / for older traffic:** you may only have Activity Log (NSG changes) + guest/EDR. Note the gap.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Scope the host IP | The compromised VM's private/public IP |
| 2. Outbound anomalies | New external IPs/ports, beaconing intervals, high egress volume |
| 3. Internal movement | The host scanning/connecting to peers it shouldn't |
| 4. Denied traffic | Bursts of denies = scanning / brute force |
| 5. Correlate | Times ↔ Activity Log (NSG change), identity logs, guest process |

## Hunt at Scale

**Top outbound talkers from a host (exfil/C2):**

```kql
AzureNetworkAnalytics_CL
| where FlowDirection_s == "O" and SrcIP_s == "<vm-ip>"
| summarize bytes=sum(OutboundBytes_d) by DestIP_s, DestPort_d
| order by bytes desc
```

**Beaconing shape (regular small connections to one dest):**

```kql
AzureNetworkAnalytics_CL
| where SrcIP_s == "<vm-ip>"
| summarize conns=count() by DestIP_s, bin(TimeGenerated, 5m)
| order by DestIP_s, TimeGenerated asc
```

**Denied inbound (scanning/brute force):**

```kql
AzureNetworkAnalytics_CL
| where FlowStatus_s == "D" and FlowDirection_s == "I"
| summarize attempts=count(), ports=dcount(DestPort_d) by SrcIP_s
| where ports > 20
```

## Respond

| Goal | Action |
|------|--------|
| Cut the traffic | NSG deny-all on the host's NIC (isolation) |
| Block the C2 | Deny the external IP/range at the NSG / Azure Firewall |
| Preserve | Export the flow logs for the window |
| Pivot | Feed the external IPs to threat intel; check other hosts talking to them |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable VNet/NSG flow logs + Traffic Analytics** | No network blind spot |
| **Restrict egress** (Azure Firewall / UDRs) | Blocks C2/exfil paths |
| **No public RDP/SSH**; least-open NSGs | Cuts inbound attack surface |
| **Alert** on high egress + beaconing | Catch exfil/C2 |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| High outbound volume to an unknown external IP | Exfil |
| Regular small connections to one dest | C2 beaconing |
| Host scanning internal peers | Lateral movement |
| Denied-inbound bursts across many ports | Scanning / brute force |
| Egress to mining pool IPs/ports | Cryptomining |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What flow logs are | **NSG Flow Logs → What is** |
| Who changed the firewall | **Azure → Activity Log** |
| The compromised host | **Azure → Virtual Machines** |
| Cryptomining chain | **Azure → Playbooks → Cryptomining Incident** |

## Resources

- NSG flow logs — https://learn.microsoft.com/azure/network-watcher/network-watcher-nsg-flow-logging-overview
- Traffic Analytics — https://learn.microsoft.com/azure/network-watcher/traffic-analytics
- MITRE ATT&CK: T1071 Application Layer Protocol / T1041 Exfiltration Over C2 — https://attack.mitre.org/techniques/T1071/
