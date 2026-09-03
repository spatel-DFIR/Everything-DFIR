# CloudWatch for DFIR

CloudWatch is where you go for the evidence **inside** the resources — OS/app/Lambda logs — and for the **impact signal** (CPU, egress, billing) that reveals mining and exfil. It's also a place attackers hide persistence (EventBridge) and destroy evidence (log-group deletion).

New to the service? Read **What is CloudWatch** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Three Jobs](#investigate--three-jobs)
- [Logs Insights Queries](#logs-insights-queries)
- [Hunting EventBridge Persistence](#hunting-eventbridge-persistence)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

CloudWatch answers **"what happened inside the host/function, did impact metrics spike, and did the attacker wire in automation or delete logs?"**

## Evidence It Produces

| Evidence | Gives you | Notes |
|----------|-----------|-------|
| **Log groups** (`/aws/lambda/*`, OS agent, RDS, EKS) | In-resource activity | Only if the source was configured to ship logs |
| **Metrics** | CPU/network/billing/invocation time-series | Always on for AWS-native metrics |
| **Alarms** | What tripwires existed and fired (or were disabled) | Config + history |
| **EventBridge rules/targets** | Automation — defensive *and* malicious | Persistence hunt surface |
| CloudTrail `logs.*`/`events.*`/`monitoring.*` | Who deleted/added/disabled the above | Evasion/persistence signal |

## Collect It

```bash
# What log groups exist (and their retention)?
aws logs describe-log-groups \
  --query 'logGroups[].{Name:logGroupName,RetentionDays:retentionInDays,Bytes:storedBytes}' --output table

# Impact check: CPU on a suspect instance (mining tell)
aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name CPUUtilization \
  --dimensions Name=InstanceId,Value=i-0abc123 \
  --start-time 2026-07-09T00:00:00Z --end-time 2026-07-10T00:00:00Z \
  --period 3600 --statistics Average Maximum

# 🔴 Persistence/automation surface
aws events list-rules --query 'Rules[].{Name:Name,State:State,Schedule:ScheduleExpression}' --output table
aws events list-targets-by-rule --rule <rule-name>
```

> **Console:** CloudWatch → **Log groups** (search/insights) · **Metrics** (graph CPU/NetworkOut/Billing) · **Alarms** · EventBridge → **Rules**.

## Investigate — Three Jobs

| Job | Do this |
|-----|---------|
| **1. Read in-resource logs** | Query the relevant log group (Lambda/OS/RDS) with Logs Insights for the incident window |
| **2. Check impact metrics** | Graph `CPUUtilization`, `NetworkOut`, `EstimatedCharges`, Lambda `Invocations` — spikes = mining/exfil/abuse |
| **3. Hunt automation & tamper** | Enumerate EventBridge rules/targets (persistence) and `DeleteLogGroup`/`DeleteAlarms` (evasion) |

## Logs Insights Queries

```sql
-- Errors/anomalies in a Lambda function during the window
fields @timestamp, @message
| filter @message like /error|Exception|Denied|curl|/tmp\// 
| sort @timestamp desc | limit 100

-- Find the biggest talkers / most frequent sources in an app log
fields @timestamp, @message
| filter @message like /Failed password|Accepted|sudo/
| stats count(*) as n by bin(5m)
| sort n desc
```

> **Console:** CloudWatch → **Logs Insights** → select the log group → paste → *Run query*. Use the time-range picker to bound to the incident window.

## Hunting EventBridge Persistence

EventBridge is a favorite "self-healing" backdoor. Check every rule:

| Look for | 🔴 Why |
|----------|--------|
| A **scheduled** rule (`rate(...)` / `cron(...)`) you don't recognize | Periodically re-creates a backdoor identity/key |
| A rule whose **target is a suspicious Lambda** | Trigger-based backdoor |
| A rule targeting an **SNS/SQS/Firehose to an external/attacker place** | Exfil pipeline |
| **Disabled/deleted defender rules** (e.g. GuardDuty→isolate) | Evasion — auto-response removed |
| A rule created **during the incident window** | Fresh persistence |

> Pair this with the IAM and Lambda persistence hunts — the classic combo is *EventBridge schedule → Lambda → CreateAccessKey*, which regenerates access every hour.

## Hunt at Scale

**In-platform — Athena / Lake for the config-tamper CloudTrail:**

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource IN ('logs.amazonaws.com','events.amazonaws.com','monitoring.amazonaws.com')
  AND eventname IN ('DeleteLogGroup','PutRetentionPolicy','PutRule','PutTargets',
                    'DeleteRule','DisableRule','DeleteAlarms')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** if OS/app logs are forwarded to SecOps, correlate host activity with the AWS control plane there.

## Respond

| Goal | Action |
|------|--------|
| Kill an EventBridge persistence loop | `disable-rule` / `remove-targets` / `delete-rule` (collect first); delete the paired Lambda |
| Preserve logs before they expire | Export the log group to S3; raise retention |
| Restore a disabled tripwire | Re-enable alarms / defender EventBridge rules |
| Re-enable in-guest logging | (Re)install the CloudWatch Agent on affected instances |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **CloudWatch Agent standard** on all EC2 (auth/syslog → CW Logs) | In-guest evidence exists next time |
| **Retention policies** + export critical groups to locked S3 | Logs survive deletion attempts |
| **Alarms** on `CPUUtilization`, `NetworkOut`, `EstimatedCharges` | Catch mining/exfil early |
| **SCP/alert** on `DeleteLogGroup`, `PutRule`, `DeleteRule` | Protect evidence + catch persistence |
| **Review EventBridge rules** periodically; least-privilege targets | No hidden automation |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `DeleteLogGroup` / retention lowered mid-incident | Evidence destruction |
| Unknown scheduled EventBridge rule → Lambda | Self-healing persistence |
| Defender EventBridge rule disabled/deleted | Auto-response removed |
| `CPUUtilization` pegged with no business reason | Crypto-mining |
| `NetworkOut` / `EstimatedCharges` spike | Exfil / resource abuse |
| Alarms deleted or actions disabled | Tripwires silenced |
| No CloudWatch Agent on a breached instance | No OS evidence — hardening gap |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What CloudWatch is | **CloudWatch → What is CloudWatch** |
| The control-plane audit log | **AWS → Logging & Monitoring → CloudTrail** |
| Disk/memory when no agent logs | **AWS → Compute → EC2** |
| Lambda abuse & function logs | **AWS → Compute → Lambda** |
| Network evidence | **AWS → Logging & Monitoring → VPC Flow Logs** |

## Resources

- Logs Insights query syntax — https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html
- CloudWatch Agent — https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html
- EventBridge rules — https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html
- MITRE ATT&CK: Event Triggered Execution (T1546) — https://attack.mitre.org/techniques/T1546/
