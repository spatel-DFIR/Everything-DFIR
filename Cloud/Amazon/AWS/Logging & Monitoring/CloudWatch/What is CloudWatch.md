# What is CloudWatch?

**CloudWatch** is AWS's **monitoring and observability** service. It's really four things under one name:

- **Logs** — a place applications, OS agents, Lambda, and VPC Flow Logs send text logs.
- **Metrics** — numeric time-series (CPU, network, billing, custom app metrics).
- **Alarms** — thresholds on metrics that fire notifications/actions.
- **EventBridge** (formerly CloudWatch Events) — an event bus that routes events to actions.

For DFIR, CloudWatch is two things: a **rich evidence store** (the OS/app logs CloudTrail can't see) and a **tripwire** (metrics/alarms that reveal impact like mining or exfil). It's also an attacker **persistence and evasion** surface.

## Contents

- [How It Works](#how-it-works)
- [The Four Faces of CloudWatch](#the-four-faces-of-cloudwatch)
- [Logs — What Actually Lands Here](#logs--what-actually-lands-here)
- [Metrics as Incident Signal](#metrics-as-incident-signal)
- [EventBridge — Automation and Its Abuse](#eventbridge--automation-and-its-abuse)
- [How to Identify CloudWatch in Evidence](#how-to-identify-cloudwatch-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Sources (EC2 agent, Lambda, VPC Flow, app code, AWS services)
   │
   ├── Logs      → Log groups → Log streams   (query with Logs Insights)
   ├── Metrics   → Namespaces/dimensions      (graph, alarm)
   ├── Alarms    → threshold on a metric       → SNS / action
   └── EventBridge → rules match events         → Lambda / SSM / SNS / etc.
```

CloudWatch is **regional**. Logs cost by ingest + storage; retention is per-log-group (default: never expire, but often set).

## The Four Faces of CloudWatch

| Face | What it is | DFIR value |
|------|-----------|------------|
| **Logs** | Central log store (OS/app/Lambda/Flow) | The evidence CloudTrail can't produce — in-guest activity |
| **Metrics** | Numeric time-series | Impact signal: CPU (mining), NetworkOut (exfil), billing (cost spike) |
| **Alarms** | Thresholds → actions | Tripwires; can also auto-respond |
| **EventBridge** | Event bus + rules | Wiring detections to response — and an attacker persistence surface |

## Logs — What Actually Lands Here

CloudTrail tells you the *control plane*. CloudWatch Logs is where you get **inside the resource** — *if* logging was configured:

| Log group (typical) | Contains |
|---------------------|----------|
| `/var/log/...` via **CloudWatch Agent** | EC2 OS logs: auth, syslog, app logs |
| `/aws/lambda/<fn>` | Lambda function stdout/stderr + `START/END/REPORT` |
| `/aws/rds/...` | RDS engine/audit/error logs |
| `/aws/vpc/flow-logs` | VPC Flow Logs (if CloudWatch destination) |
| `/aws/eks/<cluster>/...` | EKS control-plane / audit logs |
| Custom app groups | Whatever the app writes |

> 🔴 **The CloudWatch Agent is opt-in.** Without it, an EC2 instance sends **no OS logs** here — so "what ran on the box?" may be unanswerable from the cloud side (pull it from the disk/snapshot instead — see **EC2 for DFIR**). Confirm whether the agent was installed *before* you assume logs exist.

## Metrics as Incident Signal

Metrics often reveal impact **before** anyone reads a log:

| Metric | Spike means |
|--------|-------------|
| `CPUUtilization` (EC2) | 🔴 pegged CPU → crypto-mining |
| `NetworkOut` / `NetworkPacketsOut` | 🔴 large egress → exfil |
| `EstimatedCharges` (Billing) | 🔴 cost spike → mining / resource abuse |
| `Invocations` / `ConcurrentExecutions` (Lambda) | 🔴 abused function |
| `NumberOfObjects` / `BucketSizeBytes` (S3) | Mass writes (ransomware) or deletes |
| Failed-login / 4xx custom metrics | Brute force / probing |

> A **billing or CPU spike with no business reason** is one of the most reliable "you've been popped" signals in AWS — mining shows up on the bill.

## EventBridge — Automation and Its Abuse

EventBridge routes events (a GuardDuty finding, an API call, a schedule) to targets (Lambda, SSM, SNS). Defenders use it for **auto-response**. Attackers abuse it for **persistence and evasion**:

| Abuse | How |
|-------|-----|
| **Persistence** | A scheduled rule re-creates a backdoor user/key periodically |
| **Trigger-based backdoor** | A rule fires a malicious Lambda on a specific event |
| **Evasion** | Deleting/disabling defender rules that auto-respond |
| **Exfil pipeline** | A rule ships data to an attacker-controlled target |

> 🔴 On a persistence hunt, **enumerate EventBridge rules** (and their targets) alongside IAM and Lambda — a scheduled rule + Lambda is a favorite "self-healing" foothold that survives you deleting the obvious backdoor.

## How to Identify CloudWatch in Evidence

- **`eventSource`:** `logs.amazonaws.com` (Logs), `monitoring.amazonaws.com` (Metrics/Alarms), `events.amazonaws.com` (EventBridge).
- **ARNs:** log group `arn:aws:logs:<region>:<acct>:log-group:<name>`; rule `arn:aws:events:<region>:<acct>:rule/<name>`.

## Common Operations You Will See

| Operation | Service | Watch? |
|-----------|---------|--------|
| `DeleteLogGroup` / `DeleteLogStream` | Logs | 🔴 evidence destruction |
| `PutRetentionPolicy` (lowering) | Logs | 🔴 shrinking look-back |
| `StartQuery` / `GetLogEvents` | Logs | Normal analyst use |
| `PutRule` / `PutTargets` | EventBridge | 🔴 persistence / backdoor wiring |
| `DeleteRule` / `DisableRule` / `RemoveTargets` | EventBridge | 🔴 disabling defender automation |
| `DeleteAlarms` / `DisableAlarmActions` | Alarms | 🔴 silencing tripwires |
| `PutMetricAlarm` | Alarms | Config change |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| CloudWatch Logs | Azure Monitor Logs / Log Analytics | Cloud Logging |
| CloudWatch Metrics | Azure Monitor Metrics | Cloud Monitoring |
| CloudWatch Alarms | Azure Monitor Alerts | Alerting policies |
| EventBridge | Event Grid | Eventarc / Pub-Sub |
| Logs Insights | KQL (Log Analytics) | Logs Explorer / Log Analytics |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Log group / stream** | Container / sub-stream of log events |
| **CloudWatch Agent** | The opt-in agent that ships EC2 OS logs & metrics |
| **Metric** | A numeric time-series |
| **Namespace / dimension** | How metrics are grouped/filtered |
| **Alarm** | A threshold on a metric that triggers actions |
| **Metric filter** | Turns matching log lines into a metric (→ alarm) |
| **EventBridge rule / target** | Match events → route to an action |
| **Logs Insights** | The query language for CloudWatch Logs |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Hunting in CloudWatch during a case | **CloudWatch → CloudWatch for DFIR** |
| The control-plane audit log | **AWS → Logging & Monitoring → CloudTrail** |
| In-guest evidence when no agent | **AWS → Compute → EC2** |
| Lambda logs & abuse | **AWS → Compute → Lambda** |
| Network logs | **AWS → Logging & Monitoring → VPC Flow Logs** |

## Resources

- What is CloudWatch — https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/WhatIsCloudWatch.html
- CloudWatch Logs — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/WhatIsCloudWatchLogs.html
- Logs Insights query syntax — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
- EventBridge — https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html
