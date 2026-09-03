# What is AWS Config?

**AWS Config** records the **configuration of your resources over time** — every setting, and every change to it, as a timeline. Where CloudTrail says *"someone called `PutBucketPolicy`,"* Config says *"here is exactly what the bucket policy looked like before and after."*

For DFIR, Config answers the question CloudTrail can't: **"what state was this resource in at 14:32, and what changed it?"** It's your **point-in-time snapshot machine** and drift detector.

## Contents

- [How It Works](#how-it-works)
- [Config vs CloudTrail — The Key Difference](#config-vs-cloudtrail--the-key-difference)
- [What It Records](#what-it-records)
- [Config Rules and Conformance](#config-rules-and-conformance)
- [How to Identify Config in Evidence](#how-to-identify-config-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Resource changes  →  Config records a CONFIGURATION ITEM (full state snapshot)
                  →  builds a per-resource TIMELINE (state at every point)
                  →  optionally evaluates RULES (compliant / non-compliant)
                  →  delivers to S3 + notifies via SNS/EventBridge
```

- A **configuration item (CI)** is a full snapshot of a resource's state at a moment, with relationships to other resources.
- Config keeps a **configuration timeline** per resource — you can scrub to any point and diff.
- It's **regional**, can be **aggregated org-wide**, and (like everything else) is **opt-in** — must be recording *before* the incident.

## Config vs CloudTrail — The Key Difference

| | CloudTrail | AWS Config |
|-|-----------|------------|
| Records | **API calls** (the verb) | **Resource state** (the noun) |
| Answers | "Who did what action, when?" | "What did this resource look like, and when did it change?" |
| Granularity | Per-event | Per-resource-state |
| Best for | Attribution, the action timeline | Drift, before/after diffs, point-in-time state |
| Together | *Who* made the change | *Exactly what* the change was |

> 🔴 Use them as a pair: CloudTrail names the actor and the API; Config shows you the **precise before/after** of the affected resource. "Who opened this SG to 0.0.0.0/0 and what was it before?" needs both.

## What It Records

Supported resource types across most services — the ones that matter most in IR:

| Resource | Why the timeline matters |
|----------|--------------------------|
| **Security groups / NACLs** | 🔴 When did a port open to the world? |
| **S3 bucket policy / ACL / public-access block** | 🔴 When did the bucket go public? |
| **IAM roles/policies** | Permission changes over time |
| **EC2 instances / ENIs** | State, SGs, IPs at a point in time |
| **VPC / route tables / IGW** | Network path changes |
| **KMS keys** | Key policy changes |
| **RDS / EBS** | Encryption, public accessibility, snapshots |

## Config Rules and Conformance

Config **rules** continuously check resources against a desired state and mark them **compliant / non-compliant**:

- **Managed rules** (AWS-provided): `s3-bucket-public-read-prohibited`, `restricted-ssh` (no 0.0.0.0/0 on 22), `iam-user-mfa-enabled`, `cloudtrail-enabled`, `encrypted-volumes`, etc.
- **Custom rules** (Lambda / Guard): your own policy-as-code.
- **Conformance packs**: bundles of rules mapped to a framework (CIS, PCI).

> On a case, the **non-compliant list is a fast lead**: "which buckets are public right now?", "which SGs allow world-SSH?", "is CloudTrail enabled everywhere?" — answered instantly instead of enumerated by hand.

## How to Identify Config in Evidence

- **`eventSource`:** `config.amazonaws.com`.
- **In S3:** `AWSLogs/<acct>/Config/<region>/.../ConfigHistory/` and `ConfigSnapshot/`.
- **Config items** carry a `configurationItemCaptureTime`, `resourceType`, `resourceId`, and `relationships`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `StopConfigurationRecorder` | 🔴 Stop recording changes | Evasion — blinds the drift record |
| `DeleteConfigurationRecorder` / `DeleteDeliveryChannel` | Tear down Config | 🔴 evidence destruction |
| `PutConfigRule` / `DeleteConfigRule` | Add/remove a compliance rule | 🔴 removing a guardrail check |
| `GetResourceConfigHistory` | Read a resource's timeline | Normal analyst use |
| `SelectResourceConfig` | SQL-like query over current config | Normal (great for hunting) |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| AWS Config | Azure Resource Graph + Policy | Cloud Asset Inventory |
| Config timeline | Resource change history | Asset Inventory feed/history |
| Config rules | Azure Policy | Organization Policy / Security Health Analytics |

## Common Use Cases

Your "normal":

- **Compliance** — continuous CIS/PCI conformance.
- **Change management** — "what changed, when, by relationship."
- **Drift detection** — resources deviating from a secure baseline.
- **Incident support** — point-in-time state + before/after diffs.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Configuration item (CI)** | A full snapshot of a resource's state at a time |
| **Configuration timeline** | The ordered history of a resource's CIs |
| **Configuration recorder** | The thing that captures CIs (must be running) |
| **Delivery channel** | Where snapshots/history go (S3/SNS) |
| **Config rule** | A compliance check (managed/custom) |
| **Conformance pack** | A bundle of rules for a framework |
| **Aggregator** | Combines Config across accounts/regions |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using Config in an investigation | **Config → Config for DFIR** |
| Who made the change (the actor) | **AWS → Logging & Monitoring → CloudTrail** |
| Public-bucket / policy drift | **AWS → Storage → S3** |
| SG/NACL exposure | **AWS → Networking → VPC** |
| Posture aggregation | **AWS → Security & Detection → Security Hub** |

## Resources

- What is AWS Config — https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html
- Viewing configuration timelines — https://docs.aws.amazon.com/config/latest/developerguide/view-manage-resource.html
- Managed Config rules — https://docs.aws.amazon.com/config/latest/developerguide/managed-rules-by-aws-config.html
- Querying current config (`SelectResourceConfig`) — https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html
