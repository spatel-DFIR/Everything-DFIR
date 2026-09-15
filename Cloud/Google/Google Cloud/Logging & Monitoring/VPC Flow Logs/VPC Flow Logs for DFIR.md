# VPC Flow Logs for DFIR

Flow logs answer the network questions of a GCP case: **did this VM beacon to C2, connect to a mining pool, or move a lot of data out — and to where?**

New to it? Read **What is VPC Flow Logs** first.

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

| Source | What's there | Best for |
|--------|--------------|----------|
| **Logs Explorer** (`vpc_flows`) | Individual flow records | Targeted look |
| **BigQuery sink** | Aggregatable flows | Volume/exfil hunting |
| **Firewall Rules Logging** | Allow/deny decisions | What was permitted/blocked |

## Collect It

```bash
# All flows for a suspect VM's IP in the window
gcloud logging read \
  'logName:"vpc_flows" AND (jsonPayload.connection.src_ip="10.0.1.5" OR jsonPayload.connection.dest_ip="10.0.1.5")' \
  --freshness=7d --format=json > flows.json
```

> **Console:** Logging → Logs Explorer → filter `logName:"vpc_flows"`. For volume analysis, query the **BigQuery** flow-logs table.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Flow logs enabled on the subnet? Sample rate? |
| 2. Anchor the VM | The suspect instance's internal IP + interface |
| 3. Egress review | External destinations, ports, geo — rare/hostile IPs, mining pools |
| 4. Volume review | Large `bytes_sent` to external = exfil |
| 5. Lateral review | VM↔VM flows the app shouldn't make |

## Hunt at Scale

**BigQuery — top external egress by VM (exfil):**

```sql
SELECT jsonPayload.src_instance.vm_name AS vm,
       jsonPayload.connection.dest_ip AS dest,
       SUM(CAST(jsonPayload.bytes_sent AS INT64)) AS bytes
FROM `contoso.vpcflows.compute_googleapis_com_vpc_flows_*`
WHERE jsonPayload.dest_location.country IS NOT NULL          -- external
GROUP BY vm, dest
ORDER BY bytes DESC
LIMIT 50;
```

**Connections to a known mining-pool / C2 IP set:**

```sql
SELECT jsonPayload.src_instance.vm_name, jsonPayload.connection.dest_ip, COUNT(*) c
FROM `contoso.vpcflows.compute_googleapis_com_vpc_flows_*`
WHERE jsonPayload.connection.dest_ip IN UNNEST(@bad_ips)
GROUP BY 1,2 ORDER BY c DESC;
```

> **At the very end — SecOps UDM (optional):** land egress flows to correlate destination IPs across VMs/projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut C2 / exfil egress | Firewall rule denying the destination; isolate the VM's tags/network |
| Isolate the VM | Move to a quarantine network / remove external IP; snapshot the disk (→ Compute Engine) |
| Preserve | Export the flow window (Logs Explorer / BigQuery) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable flow logs** on sensitive subnets | The evidence must pre-exist |
| **Firewall Rules Logging** on | See allow/deny decisions |
| **Egress firewall / Cloud NAT allowlist** | Limit where VMs can talk |
| **Route flow logs → BigQuery** | Volume hunting + retention |
| **Alert** on large egress + rare-destination connections | Early exfil/C2 detection |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| VM egress to a mining pool / rare hostile IP | C2 / cryptomining |
| Large `bytes_sent` to an external destination | Data exfil |
| VM↔VM flows outside the app's design | Lateral movement |
| Egress to a new country/ASN after a compromise | Attacker channel |
| Beaconing pattern (regular small flows to one IP) | C2 |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The flow-log format + limits | **VPC Flow Logs → What is** |
| The VM endpoint + host forensics | **GCP → Compute Engine** |
| The network + firewall | **GCP → VPC** |
| Cryptomining end to end | **GCP → Playbooks → Cryptomining Incident** |

## Resources

- VPC Flow Logs — https://cloud.google.com/vpc/docs/flow-logs
- Firewall Rules Logging — https://cloud.google.com/firewall/docs/firewall-rules-logging
- Analyzing flow logs in BigQuery — https://cloud.google.com/vpc/docs/using-flow-logs#analyzing_the_logs
- MITRE ATT&CK: T1041 Exfil Over C2 / T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1041/
