# Playbook — Defense Evasion: Logging Disabled

A capable attacker turns off the lights before they work. When CloudTrail, GuardDuty, Config, or Flow Logs get **disabled, deleted, or suppressed**, you have both a **red flag** (someone's hiding) and a **problem** (a gap in your evidence). This playbook handles both.

> **Tier 2 (cross-service).** Touches CloudTrail, GuardDuty, Config, CloudWatch, Organizations. Read **CloudTrail for DFIR**, **GuardDuty for DFIR**, **Config for DFIR**.

## Contents

- [Attack Chain](#attack-chain)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [The Evasion Actions to Hunt](#the-evasion-actions-to-hunt)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Working Around the Gap](#working-around-the-gap)
- [Contain and Restore](#contain-and-restore)
- [Decision Points](#decision-points)
- [Red Flags](#red-flags)
- [References](#references)

## Attack Chain

```
Attacker with control-plane access
   → StopLogging / DeleteTrail / PutEventSelectors (narrow scope)   ← CloudTrail
   → DeleteDetector / suppression rule / trusted-IP whitelist       ← GuardDuty
   → StopConfigurationRecorder                                       ← Config
   → DeleteFlowLogs                                                  ← VPC
   → DeleteLogGroup / DisableRule                                    ← CloudWatch/EventBridge
   → does the "real" work in the resulting blind window
   → (sometimes) re-enables logging afterward to look clean
```

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **GuardDuty** | `Stealth:IAMUser/CloudTrailLoggingDisabled`, `Stealth:IAMUser/PasswordPolicyChange` |
| **EventBridge alert** | You wired an alert on `StopLogging`/`DeleteTrail` (best case) |
| **A gap** | `get-trail-status` shows a stop inside your incident window |
| **Findings vanished** | Expected GuardDuty findings are archived/absent |
| **Config timeline holes** | Recorder stopped |

## Hypothesis

An attacker blinded one or more logging/detection controls to hide activity. Two goals: (1) find what happened *during the blind window* using surviving evidence, and (2) restore + prove the tamper.

## The Evasion Actions to Hunt

| Service | Actions |
|---------|---------|
| **CloudTrail** | `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` |
| **GuardDuty** | `DeleteDetector`, `UpdateDetector`, `CreateFilter`, `CreateSuppressionRule`, `CreateIPSet`, `DeleteMembers` |
| **Config** | `StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `DeleteConfigRule`, `DeleteDeliveryChannel` |
| **VPC** | `DeleteFlowLogs` |
| **CloudWatch** | `DeleteLogGroup`, `PutRetentionPolicy` (lower), `DeleteAlarms`, `DisableRule`, `DeleteRule` |
| **Security Hub** | `DisableSecurityHub`, `BatchUpdateFindings` (mass suppress) |
| **Org/SCP** | `DetachPolicy`/`UpdatePolicy` weakening a logging guardrail |

## Step-by-Step Investigation

**1. Establish the blind window.** When did logging stop and (if ever) restart?

```bash
aws cloudtrail get-trail-status --name <trail> \
  --query '{Logging:IsLogging,Stopped:TimeLoggingStopped,Started:TimeLoggingStarted}'
```

The interval `[Stopped, Started]` is your evidence gap.

**2. Attribute the tamper.** Find the actual `StopLogging`/`DeleteDetector`/etc. event — who, from where, with what creds. (Ironically, the *act of disabling* is usually still logged — it's the events *after* that are lost.)

**3. Check every control, every region/account.** Sweep the evasion actions above across regions and (in an Org) the org trail. Attackers often disable several controls at once.

**4. Hunt suppression, not just deletion.** GuardDuty **suppression rules** and **trusted-IP lists** silently archive findings without deleting the detector — read `list-filters` / `list-ip-sets` for anything created in the window.

## Working Around the Gap

The blind window isn't a dead end — use evidence the attacker **didn't** control:

| Surviving source | Why it helps |
|------------------|--------------|
| **GuardDuty** (if only CloudTrail was stopped) | Reads the CloudTrail event *stream* directly; may still have findings |
| **Config timeline** | If Config kept running, before/after resource state during the gap |
| **VPC Flow Logs / DNS logs** | Network activity independent of CloudTrail |
| **S3 server access logs / ALB logs** | Data/web activity outside CloudTrail |
| **The org trail** | If a member-account trail was stopped, the org trail may still have it |
| **Resource current state** | What exists now vs before implies what happened |
| **Billing** | Cost changes during the gap (mining/resources) |

> 🔴 **Redundant, tamper-resistant logging is what saves you here.** An org trail in a locked logging account + GuardDuty + Config means one `StopLogging` doesn't blind you. If it *did* fully blind you, that's the top hardening finding.

## Contain and Restore

```bash
# Re-enable the controls
aws cloudtrail start-logging --name <trail>
aws guardduty create-detector --enable                      # or update-detector to re-enable
aws configservice start-configuration-recorder --configuration-recorder-name <name>
# Remove attacker suppression: delete rogue GuardDuty filters / trusted-IP entries; re-open findings
```

Then cut the actor (deactivate key / revoke sessions) and work the underlying compromise.

## Decision Points

| Question | If yes → |
|----------|----------|
| Was logging fully blind, or partially? | Partial → reconstruct from surviving sources; full → assume worst case in the gap |
| Suppression rules created? | Un-suppress and re-review archived findings |
| Multiple controls disabled together? | Sophisticated actor — widen scope |
| Re-enabled afterward to look clean? | The `Stop`+`Start` pair dates the exact blind window |
| Org guardrail weakened? | Escalate to org-wide (→ Organizations) |

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `StopLogging` / `DeleteTrail` / `PutEventSelectors` | CloudTrail blinding |
| `DeleteDetector` / GuardDuty suppression rule / trusted-IP add | Detection blinding |
| `StopConfigurationRecorder` / `DeleteFlowLogs` | Config/network blinding |
| A stop→start pair around suspicious inactivity | A deliberately-created blind window |
| SCP weakened to allow the above | Org-wide guardrail removed |
| Expected findings mysteriously archived | Suppression in play |

## References

- Related notes: **CloudTrail for DFIR**, **GuardDuty for DFIR**, **Config for DFIR**, **Organizations for DFIR**
- CloudTrail log file integrity validation — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
- MITRE ATT&CK: Impair Defenses (T1562) — https://attack.mitre.org/techniques/T1562/
