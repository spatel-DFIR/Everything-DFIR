# Config for DFIR

Config is your **time machine for resource state.** When you need to know *exactly* what a security group, bucket policy, or IAM role looked like at the moment of the incident — and what changed it — Config has the before/after that CloudTrail's API events only imply.

New to the service? Read **What is Config** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Point-in-Time and Diff](#investigate--point-in-time-and-diff)
- [Fast Wins with Config Queries](#fast-wins-with-config-queries)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Config answers **"what state was this resource in when it happened, what changed, and what's non-compliant right now?"** It turns a vague "the bucket got exposed" into a precise before/after with a timestamp.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| **Configuration timeline** | A resource's exact state at any point + every change | Config console / `get-resource-config-history` |
| **Config items** | Full snapshots with relationships | S3 delivery / API |
| **Compliance state** | What's non-compliant *now* | `describe-compliance-*` / console |
| `config.*` CloudTrail | Who tampered with Config (🔴 stop-recording) | CloudTrail |

## Collect It

```bash
# The change timeline for a specific resource (e.g. a security group)
aws configservice get-resource-config-history \
  --resource-type AWS::EC2::SecurityGroup --resource-id sg-0abc123 \
  --query 'configurationItems[].{When:configurationItemCaptureTime,Status:configurationItemStatus}'

# 🔴 Is Config even recording? (was it stopped during the incident?)
aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[].{Recording:recording,LastStatus:lastStatus}'

# What's non-compliant right now?
aws configservice describe-compliance-by-config-rule \
  --query 'ComplianceByConfigRules[?Compliance.ComplianceType==`NON_COMPLIANT`].ConfigRuleName'
```

> **Console:** Config → **Resources** → pick a resource → **Configuration timeline** (scrub + diff between versions). Config → **Rules** → filter *Non-compliant*.

## Investigate — Point-in-Time and Diff

The core moves:

| Step | Do this |
|------|---------|
| 1. Confirm recording | Was the recorder running across your window? A `StopConfigurationRecorder` = a gap |
| 2. Open the timeline | For the affected resource, scrub to the incident time — see its exact state |
| 3. Diff | Compare the CI just before vs just after — the precise change (e.g. SG rule `0.0.0.0/0:22` added) |
| 4. Attribute | Take the change time to **CloudTrail** and find *who* made the API call |
| 5. Sweep compliance | Use the non-compliant list to find *other* resources in the same bad state |

> **The Config→CloudTrail handoff is the technique:** Config gives you the *exact change and its timestamp*; you carry that timestamp to CloudTrail to name the actor. Neither alone is as strong.

## Fast Wins with Config Queries

`SelectResourceConfig` runs SQL over *current* config — great for instant scoping:

```sql
-- Every security group open to the world on SSH/RDP, right now
SELECT resourceId, configuration.ipPermissions
WHERE resourceType = 'AWS::EC2::SecurityGroup'
  AND configuration.ipPermissions.ipRanges = '0.0.0.0/0'

-- All S3 buckets and their public-access-block state
SELECT resourceId, supplementaryConfiguration.PublicAccessBlockConfiguration
WHERE resourceType = 'AWS::S3::Bucket'
```

> **Console:** Config → **Advanced query** → paste → *Run*. This answers "how widespread is this misconfig?" in seconds.

## Hunt at Scale

**In-platform — Config advanced query (current) + CloudTrail (who changed it):**

```sql
-- Athena/Lake: who tampered with Config itself?
SELECT eventtime, useridentity.arn, eventname, awsregion
FROM cloudtrail_logs
WHERE eventsource = 'config.amazonaws.com'
  AND eventname IN ('StopConfigurationRecorder','DeleteConfigurationRecorder',
                    'DeleteConfigRule','DeleteDeliveryChannel')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** Config findings/compliance can feed Security Hub → SecOps; use it for cross-account posture, then pivot back to the timeline for detail.

## Respond

Config is investigative; response happens on the affected resource. But:

| Goal | Action |
|------|--------|
| Re-enable recording | `start-configuration-recorder`; verify status |
| Restore the pre-incident state | Use the Config diff as the exact spec to revert (SG rule, bucket policy) |
| Re-add removed compliance checks | Re-create deleted Config rules |
| Auto-remediate future drift | Wire Config rules → SSM Automation remediation |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Config org-wide, all regions**, aggregated to an audit account | Complete change history |
| **Deploy a conformance pack** (CIS) with auto-remediation | Drift fixes itself |
| **SCP/alert** on `StopConfigurationRecorder`/`DeleteConfigRule` | Attacker can't blind the drift record |
| **Key rules on:** public-S3, restricted-SSH, cloudtrail-enabled, encrypted-volumes, iam-user-mfa | Continuous coverage of the classics |
| **Alert** on new non-compliant resources | Catch exposure as it happens |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `StopConfigurationRecorder` in the incident window | Drift record blinded |
| A resource CI showing world-exposure appearing at the incident time | The exposure moment, precisely dated |
| Config rule for a control deleted | Guardrail check removed |
| Wide non-compliance in the affected account | Poor baseline; likely more exposure |
| `DeleteDeliveryChannel` / `DeleteConfigurationRecorder` | Config evidence destroyed |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Config is + rules | **Config → What is Config** |
| Who made the change | **AWS → Logging & Monitoring → CloudTrail** |
| Public bucket investigations | **AWS → Storage → S3** |
| SG/NACL exposure | **AWS → Networking → VPC** |
| Posture aggregation across tools | **AWS → Security & Detection → Security Hub** |

## Resources

- Viewing configuration timelines — https://docs.aws.amazon.com/config/latest/developerguide/view-manage-resource.html
- Advanced queries (`SelectResourceConfig`) — https://docs.aws.amazon.com/config/latest/developerguide/querying-AWS-resources.html
- Remediating non-compliant resources — https://docs.aws.amazon.com/config/latest/developerguide/remediation.html
- MITRE ATT&CK: Impair Defenses (T1562) — https://attack.mitre.org/techniques/T1562/
