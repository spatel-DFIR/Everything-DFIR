# Lightsail for DFIR

🔴 **Lightsail is a blind spot.** It does not appear in VPC Flow Logs, does not appear in the EC2 console or EC2 Global View, and a `describe-instances` sweep across every region returns nothing for it. If your standard "enumerate all compute" process is EC2-only, you will miss any Lightsail instance in the account — including one an attacker stood up on purpose *because* it's not where anyone looks. Every AWS account inventory step in this repo should include a Lightsail check alongside the EC2 one.

New to the service? Read **What is Lightsail** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [The Blind Spot, in Practice](#the-blind-spot-in-practice)
- [Collect It — Cloud Side](#collect-it--cloud-side)
- [Collect It — Host Side (Snapshot Forensics)](#collect-it--host-side-snapshot-forensics)
- [Investigate](#investigate)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Lightsail answers **"is there compute in this account that my EC2-centric sweep never found?"** It's a live product, running real workloads (or attacker-planted ones), on the same infrastructure as EC2, but outside every tool an analyst reaches for by default. It matters to IR in two ways: as a genuine blind spot to close during scoping, and — once found — as an instance to investigate with a parallel-but-different toolset from EC2.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| CloudTrail `lightsail.*` | Create/delete/firewall/snapshot changes + actor | CloudTrail — filter `eventSource = lightsail.amazonaws.com` |
| **Instance snapshot** | The disk — export to EC2 AMI for full host forensics | You create it |
| **In-guest logs** | OS/application logs *if you can reach the box* | SSH / Lightsail browser-based SSH, or exported AMI |
| **Lightsail firewall config** | What was open, and when it changed | `get-instance-port-states` / console |
| Console/API metrics | CPU/network utilization graphs | Lightsail console → *Metrics* tab |

🔴 What's **missing** compared to EC2: no VPC Flow Logs (Lightsail's managed network isn't yours to flow-log), no GuardDuty EC2-specific findings, no EC2 Global View entry, and — unless the instance was VPC-peered into a real VPC — nothing shows up in your normal network telemetry at all. CloudTrail and the instance's own disk are, practically speaking, your only cloud-side evidence.

## The Blind Spot, in Practice

| Tool an analyst normally runs | Does it show Lightsail? |
|---|---|
| `aws ec2 describe-instances` (any region) | 🔴 No |
| EC2 console / EC2 Global View | 🔴 No |
| VPC Flow Logs | 🔴 No (Lightsail-managed network, not your VPC — unless peered) |
| GuardDuty EC2 findings | 🔴 Generally no — Lightsail isn't a covered resource type the way EC2 is |
| Lightsail console | ✅ Yes |
| CloudTrail, filtered to `eventSource = lightsail.amazonaws.com` | ✅ Yes |
| `aws lightsail get-instances` (per region) | ✅ Yes |

> **Rule of thumb:** if a scoping question is "does this account have any compute I haven't accounted for," always run the Lightsail check alongside EC2 — they are two separate inventories and neither implies the other.

## Collect It — Cloud Side

```bash
# Lightsail instances are per-region — check every region you check for EC2
aws lightsail get-instances --region us-east-1 \
  --query 'instances[].{Name:name,State:state.name,PublicIp:publicIpAddress,Blueprint:blueprintId,Bundle:bundleId}'

# Loop every region (Lightsail is region-scoped like EC2, not a global service)
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="
  aws lightsail get-instances --region "$r" --query 'instances[].name' --output text
done

# Full state of one instance, including the attached static IP and firewall
aws lightsail get-instance --instance-name <name> --region us-east-1

# 🔴 What ports does the Lightsail firewall (not a Security Group) actually allow?
aws lightsail get-instance-port-states --instance-name <name> --region us-east-1

# Read the instance's access details (public key, username) — note who requested this
aws lightsail get-instance-access-details --instance-name <name> --region us-east-1

# What did this instance's actions look like in CloudTrail?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=lightsail.amazonaws.com --max-results 50
```

> **Console:** the **Lightsail console** (separate URL/nav from EC2) → *Instances* tab lists everything per region. There is no cross-region "global view" — you must check each region, same as the CLI loop above.

## Collect It — Host Side (Snapshot Forensics)

Lightsail doesn't give you EBS-style volume manipulation directly — the path is: **snapshot in Lightsail, then export to EC2** to get full forensic tooling.

```bash
# 1. Snapshot the instance FIRST — before any isolation/termination
aws lightsail create-instance-snapshot \
  --instance-name <name> --instance-snapshot-name "IR-<case>-$(date -u +%FT%TZ)"

# 2. Export the snapshot into an EC2-compatible AMI
aws lightsail export-snapshot --source-snapshot-name "IR-<case>-<timestamp>"

# 3. Find the resulting AMI/EBS snapshot in the linked EC2 account/region
aws lightsail get-export-snapshot-records

# 4. From here, treat it exactly like an EC2 disk: create-volume from the exported
#    snapshot, attach read-only to a clean forensic instance, and analyze.
#    (see EC2 for DFIR → Collect It — Host Side)
```

> 🔴 **Memory capture is not native to Lightsail** the way SSM run-command is for EC2 — if the box is live and you can reach it (SSH or the Lightsail browser-based terminal), you'll need to run a memory-acquisition tool manually (e.g. LiME/AVML) before you stop or delete the instance. There's no agent-brokered equivalent of SSM here.

## Investigate

| Step | Do this |
|------|---------|
| 1. Confirm you found it | Lightsail is region-scoped — loop every region, don't assume one hit means you've found them all |
| 2. Cloud provenance | `CreateInstances` — who created it, from what blueprint, when? Legit workload or attacker-planted? |
| 3. Firewall review | `get-instance-port-states` — what's exposed, and does CloudTrail show a `PutInstancePublicPorts`/`OpenInstancePublicPorts` call that opened it? |
| 4. Network identity | Static IP assigned? When? Correlate against any external threat intel/abuse reports tied to that IP |
| 5. Access material | Was `GetInstanceAccessDetails` or `DownloadDefaultKeyPair` called by someone unexpected? |
| 6. Snapshot/export activity | Any `CreateInstanceSnapshot`/`ExportSnapshot` you didn't expect — could be exfil of the whole disk |
| 7. Host forensics | Export snapshot → EC2 AMI → mount read-only → standard host triage (webshells, cron, bash history, added SSH keys) |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventSource` | Confirms it's Lightsail, not EC2 | `lightsail.amazonaws.com` |
| `eventName` | The Lightsail action | `CreateInstances`, `OpenInstancePublicPorts`, `ExportSnapshot` |
| `userIdentity` | Who did it | Unexpected identity creating/modifying instances |
| `requestParameters.instanceNames` / `.blueprintId` | What was launched, from what image | Unknown blueprint = unvetted image |
| `awsRegion` | Where | 🔴 an unused region is as suspicious here as it is for EC2 |

## Hunt at Scale

**In-platform — Athena / Lake (once you have Lightsail events flowing into the same CloudTrail S3/Lake source as everything else):**

```sql
-- Every Lightsail action, across regions — start here on any scoping question
SELECT eventtime, useridentity.arn, awsregion, eventname
FROM cloudtrail_logs
WHERE eventsource = 'lightsail.amazonaws.com'
  AND eventtime > '2026-07-01'
ORDER BY eventtime;

-- Firewall-opening events — did anyone expose a Lightsail instance to the world?
SELECT eventtime, useridentity.arn, awsregion,
       json_extract_scalar(requestparameters,'$.instanceName') AS instance
FROM cloudtrail_logs
WHERE eventname IN ('OpenInstancePublicPorts','PutInstancePublicPorts')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "CreateInstances" OR metadata.product_event_type = "ExportSnapshot"
```

## Respond

| Step | Action |
|------|--------|
| 1. Capture | Snapshot the instance (and grab memory manually if live) **before** touching state |
| 2. Isolate (don't delete) | Tighten the Lightsail firewall to deny all inbound — there's no "swap Security Group" pattern here, so edit/replace the firewall rules directly |
| 3. Cut access | Revoke/rotate any downloaded key pair; disable public IP if not needed for continued access |
| 4. Preserve | Keep the snapshot; note the export-to-EC2 record so it isn't cleaned up before analysis |
| 5. Eradicate | Rebuild from a known-good blueprint/snapshot; remove attacker-added keys/cron found on disk |
| 6. Close the blind spot | Confirm no other Lightsail instances exist in any region before closing the case |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Include Lightsail in every account-wide compute inventory** (script or checklist, every region) | Closes the blind spot — this is the #1 fix |
| **Alert on `lightsail.amazonaws.com` CloudTrail activity** via EventBridge, especially in accounts where Lightsail isn't an expected/sanctioned service | Catches shadow-IT or attacker-planted instances early |
| Restrict IAM so only specific principals can call `lightsail:CreateInstances` | Prevents unsanctioned instance sprawl |
| Keep Lightsail firewall rules least-privilege (no 22/3389 open to `0.0.0.0/0`) | Same exposure risk as an open Security Group |
| Enable **automatic snapshots** on any Lightsail instance running real workloads | Ensures a recovery/forensic point exists before an incident |
| If a Lightsail instance needs to talk to your real VPC, use **VPC peering** deliberately (and document it) — don't let it become an unmonitored bridge | Keeps network visibility intact |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Any Lightsail instance existing that wasn't in your EC2-based inventory | The blind spot realized — investigate why it's there |
| `CreateInstances` in a region with no other legitimate compute footprint | Attacker choosing an unwatched region/service on purpose |
| `OpenInstancePublicPorts` exposing SSH/RDP/app ports to `0.0.0.0/0` | Exposing entry, same as an open Security Group |
| `ExportSnapshot` you can't attribute to a legitimate migration | Whole-disk exfil path |
| `GetInstanceAccessDetails` / `DownloadDefaultKeyPair` by an unexpected identity | Credential access |
| A Lightsail instance's static IP tied to known-bad infrastructure | C2/hosting for an external campaign, run cheaply and quietly inside a legitimate AWS account |
| `DeleteInstance` before you captured a snapshot | Evidence destruction |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Lightsail is + terminology | **Lightsail → What is Lightsail** |
| The EC2 model your exported snapshot lands in | **AWS → Compute → EC2 → EC2 for DFIR** |
| Every AWS action's audit trail | **AWS → Logging & Monitoring → CloudTrail → CloudTrail for DFIR** |
| Why VPC Flow Logs don't cover this traffic | **AWS → Logging & Monitoring → VPC Flow Logs** |
| Full account inventory / scoping approach | **AWS → 00 Overview & Terminology** |

## Resources

- Lightsail overview — https://docs.aws.amazon.com/lightsail/latest/userguide/what-is-amazon-lightsail.html
- Lightsail API reference (CLI actions, `lightsail.*`) — https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/Welcome.html
- Export a Lightsail snapshot to EC2 — https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-export-snapshot-to-amazon-ec2.html
- Lightsail firewall / instance ports — https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-editing-instance-firewall-rules.html
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
