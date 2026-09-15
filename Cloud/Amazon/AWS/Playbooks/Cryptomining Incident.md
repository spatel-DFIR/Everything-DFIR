# Playbook — Cryptomining Incident

The **most common "impact" outcome** of an AWS compromise. Once an attacker has credentials (leaked key, IMDS theft, exposed service), the easiest way to monetize is to **spin up compute and mine cryptocurrency** on your bill. It's loud on the invoice but easy to miss if you're not watching regions.

> **Tier 2 (cross-service).** Touches EC2, VPC Flow Logs, GuardDuty, CloudWatch/Billing, IAM. Read **EC2 for DFIR**, **VPC Flow Logs for DFIR**, **GuardDuty for DFIR**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Stolen creds / exposed service
   → RunInstances (many, large/GPU types) — often in UNUSED regions to hide
   → new instances pull mining software, join a mining pool
   → outbound to pool IPs/ports (3333/4444/5555/14444…) — GuardDuty CryptoCurrency finding
   → sometimes: raise service quotas / delete on a timer to evade
   → your bill spikes
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **Billing alarm** | 🔴 `EstimatedCharges` spike — the classic tell |
| **GuardDuty** | `CryptoCurrency:EC2/BitcoinTool.B!DNS`, `Backdoor:EC2/C&CActivity` |
| **CloudWatch** | `CPUUtilization` pegged at ~100% on new instances |
| **Service quota / limit emails** | Attacker requested more compute |
| **New instances nobody launched** | In the EC2 console (check all regions) |

## Hypothesis

An attacker with credentials is running compute for mining. Confirm the rogue instances, find *how they got in* (the creds are the real problem), scope every region, and stop the bleed.

## Step-by-Step Investigation

**1. Find the rogue compute — every region.**

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r =="; aws ec2 describe-instances --region $r \
    --filters Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,Launched:LaunchTime}' --output text
done
```

🔴 Look for **large/GPU types** (`p3`, `g4`, `c5.24xlarge`…), **unusual regions**, and **recent launch times** in a burst.

**2. Who launched them?**

```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances --max-results 50
```

Note the identity, IP, and user-agent — this is your entry-point lead.

**3. Confirm mining traffic.** VPC Flow Logs for the rogue instances' ENIs: sustained ACCEPTs to mining-pool IPs/ports (→ VPC Flow Logs for DFIR). Pair with the GuardDuty finding's remote IP.

**4. Trace the entry.** The identity that ran `RunInstances` — is it a leaked key (→ Leaked Access Key), a stolen role, an over-broad CI role? *This* is what you must fix; the instances are just the symptom.

**5. Check for more.** Auto Scaling groups / launch templates / Spot fleets the attacker created to **re-launch** instances after you kill them; raised **service quotas**.

## Decision Points

| Question | If yes → |
|----------|----------|
| Rogue instances in multiple regions? | Sweep and kill *all* — don't stop at the first region |
| Auto Scaling / launch template involved? | Delete those first, or terminated instances respawn |
| How did they get in? | Fix the credential/entry, or it recurs immediately |
| Need evidence from an instance? | Snapshot before terminating (usually low value for pure mining) |
| Data touched too? | Treat as a fuller intrusion, not just mining |

## Contain

```bash
# 1. Stop the respawn source FIRST (or instances come back)
#    Delete attacker Auto Scaling groups / launch templates / spot fleets

# 2. Kill the entry credential (deactivate leaked key / revoke role sessions)

# 3. Terminate the rogue instances (all regions)
aws ec2 terminate-instances --region <r> --instance-ids i-xxxx i-yyyy
```

## Eradicate

- Remove **all** attacker-created compute infra: instances, ASGs, launch templates, spot requests, AMIs they made.
- Fix the **entry**: rotate/kill the leaked key, revoke role sessions, fix the SSRF/exposed service (→ the relevant playbook).
- Remove any **persistence** planted alongside (new IAM users/keys, EventBridge/Lambda that re-launches — → IAM, CloudWatch).
- Lower any **raised quotas** back to normal.

## Recover

- Contact **AWS Support** about fraudulent charges — mining from a compromised account is often eligible for credit; open a case with the timeline.
- Restore normal quotas and guardrails.
- Preserve: the `RunInstances` events, GuardDuty findings, Flow Logs showing pool traffic.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Billing / `EstimatedCharges` spike, no business reason | Resource abuse (usually mining) |
| `RunInstances` of large/GPU types in unused regions | Mining compute |
| `CPUUtilization` pegged on new instances | Mining load |
| Flow Logs to pool ports (3333/4444/5555/14444) | Confirmed mining traffic |
| GuardDuty `CryptoCurrency:EC2/...` | Managed confirmation |
| New Auto Scaling group / launch template | Respawn persistence |

## References

- Related notes: **EC2 for DFIR**, **VPC Flow Logs for DFIR**, **GuardDuty for DFIR**, **Leaked Access Key**
- Remediating a compromised account — https://repost.aws/knowledge-center/potential-account-compromise
- MITRE ATT&CK: Resource Hijacking (T1496) — https://attack.mitre.org/techniques/T1496/
