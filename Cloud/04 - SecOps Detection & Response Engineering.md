# SecOps Detection & Response Engineering

The one place in this guide where we step back from a single incident and think about **fleet-wide detection**: landing all three clouds' logs into a SIEM/SecOps platform, normalizing them so one query spans providers, and writing a modest set of high-value cross-cloud detections. This guide is **native-platform first** — SecOps is the *"has this happened elsewhere / before?"* layer on top, not the centerpiece.

> Scope note: this chapter is deliberately compact. The depth of each detection lives in the provider `for DFIR` notes; here we cover the **cross-cloud plumbing and the handful of detections that matter most.**

## Contents

- [Where SecOps Fits](#where-secops-fits)
- [Getting the Logs In](#getting-the-logs-in)
- [Normalize to One Schema (UDM)](#normalize-to-one-schema-udm)
- [The Cross-Cloud Field Map](#the-cross-cloud-field-map)
- [High-Value Cross-Cloud Detections](#high-value-cross-cloud-detections)
- [Detection Engineering Principles](#detection-engineering-principles)
- [Response Automation Basics](#response-automation-basics)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Where SecOps Fits

| Layer | Tool | Use for |
|-------|------|---------|
| **Investigate now** | Native console + CLI + native query (Athena/KQL/Log Explorer) | The live case — where this guide spends its weight |
| **Detect broadly** | SecOps / SIEM (UDM) | Standing detections across all accounts/clouds |
| **Answer "elsewhere/before?"** | SecOps search | Pivot a single-case IOC across the whole estate + history |

Use SecOps to **scale and correlate**, not to replace hands-on platform work.

## Getting the Logs In

The ingestion path per provider (land these three and you can see the whole estate):

| Provider | Ship what | How |
|----------|-----------|-----|
| **AWS** | CloudTrail (all-region, org trail), GuardDuty, VPC Flow | S3 → SecOps feed / Data export |
| **Azure/Entra/M365** | Activity Log, **Entra Sign-in & Audit**, Unified Audit Log, Defender | Event Hub / Graph API / native feed |
| **Google** | Cloud Audit Logs, Workspace audit, SCC | **Log Router sink** → SecOps / Pub/Sub |

> 🔴 Ingestion gaps are detection gaps. Confirm **all regions, all accounts/subscriptions/projects**, and both **control- and data-plane** where it matters, are actually flowing — and alarm on feed silence.

## Normalize to One Schema (UDM)

The value of SecOps is a **single schema** across providers. Google SecOps uses **UDM (Unified Data Model)**; the principle is universal — reduce every event to *who / what / where / when / outcome* (the model from **00**). Once normalized, one detection covers AWS + Azure + GCP.

| UDM field | Meaning |
|-----------|---------|
| `metadata.event_type` / `product_event_type` | The action (normalized / raw) |
| `principal.user.userid` | Who |
| `principal.ip` | From where |
| `target.resource.name` | On what |
| `security_result.action` | Allow/deny/outcome |
| `metadata.log_type` | `AWS_CLOUDTRAIL` / `AZURE_AD` / `GCP_CLOUDAUDIT` … |

## The Cross-Cloud Field Map

Map each provider's raw fields into the common shape (same table used for manual correlation in **03**):

| Common | AWS CloudTrail | Azure/Entra | Google Cloud Audit | UDM |
|--------|----------------|-------------|--------------------|-----|
| who | `userIdentity.arn` | `identity`/`appId` | `principalEmail` | `principal.user.userid` |
| what | `eventName` | `operationName` | `methodName` | `metadata.product_event_type` |
| resource | resource ARN | `targetResources` | `resourceName` | `target.resource.name` |
| ip | `sourceIPAddress` | `ipAddress` | `callerIp` | `principal.ip` |
| when | `eventTime` | `activityDateTime` | `timestamp` | `metadata.event_timestamp` |
| outcome | `errorCode` | `resultType` | `status.code` | `security_result.action` |

## High-Value Cross-Cloud Detections

A modest, high-signal set that works across providers once normalized. (Examples in UDM-style syntax; adapt to your platform.)

**1. Logging/detection disabled** — the near-universal early evasion move:
```
metadata.product_event_type IN ("StopLogging","DeleteTrail","DeleteDetector",
   "microsoft.insights/diagnosticSettings/delete","google.logging.config.disable")
```

**2. Impossible travel / new-ASN privileged sign-in** — identity compromise:
```
// same principal.user.userid, two principal.ip in distant geos within a short window
// scope to admin/privileged roles
```

**3. Mass secret / key access** — credential harvesting:
```
metadata.product_event_type IN ("GetSecretValue","BatchGetSecretValue","SecretGet","AccessSecretVersion")
| group by principal.user.userid | count > threshold
```

**4. Key/data destruction** — impact:
```
metadata.product_event_type IN ("ScheduleKeyDeletion","DisableKey","VaultPurge","DestroyCryptoKeyVersion")
```

**5. Cloud admin command execution** — SSH-less exec:
```
metadata.product_event_type IN ("SendCommand","StartSession","runCommand")
principal.ip NOT IN known_admin_ranges
```

**6. New credential / consent persistence:**
```
metadata.product_event_type IN ("CreateAccessKey","Add service principal credentials",
   "Consent to application","CreateServiceAccountKey")
```

## Detection Engineering Principles

A detection idea only has value once it's running and tuned. Walk it through the same lifecycle regardless of cloud — the stages are universal, only the native plumbing that carries each stage changes per provider.

**1. Hypothesize.** State the tactic, not the IOC — "logging gets disabled before impact," "a service account starts calling APIs outside its normal set," not one specific event name. Ground the hypothesis in what's normal: every `for DFIR` note in this guide has a "what's normal" section per service, and **00b ATT&CK Cloud to Evidence Map** gives the technique-to-log mapping to find coverage gaps.

**2. Build.** Turn the hypothesis into a rule that runs on its own, using each provider's native event-driven building blocks:

| Provider | Native trigger | Native compute/action |
|----------|-----------------|------------------------|
| **AWS** | EventBridge rule (CloudTrail event pattern, GuardDuty finding, scheduled) | Lambda (evaluate/enrich/alert), Step Functions for multi-stage logic |
| **Azure** | Logic Apps trigger / Azure Monitor alert rule on a Log Analytics query | Logic Apps or Azure Automation runbook (evaluate/enrich/alert) |
| **Google Cloud** | Log Router sink → Pub/Sub topic, or Cloud Monitoring alert policy | Cloud Functions subscribed to the Pub/Sub topic (evaluate/enrich/alert) |

The detection logic itself (the query/condition) still belongs in the provider's native query surface — Athena/CloudTrail Lake, KQL/Log Analytics, Log Explorer/BigQuery — the trigger+compute pair above is just what turns "a query that finds bad things" into "a rule that fires without a human running it."

**3. Test.** Fire the exact behavior the hypothesis targets and confirm the rule catches it — the provider playbooks in this guide (each service's "Hunt at Scale"/attack-simulation content) double as red-team scripts for this. Test against a case that should trip it and a case that shouldn't, to catch both false negatives and obvious false positives before deploy.

**4. Tune.** Narrow the condition against real traffic: scope to the workload identity (service accounts/roles have tight, predictable behavior, so deviations are high-signal); exclude known-noisy legitimate callers; adjust thresholds (e.g., "mass secret read" needs a count/time window, not a single call). Re-test after every tuning pass.

**5. Deploy.** Promote the tuned rule from a manual/test invocation to standing coverage — the EventBridge rule, Logic App, or Log Router sink stays live, and its own health becomes something to monitor (see "alarm on absence" below).

**6. Maintain.** Detections rot as the environment and adversary tradecraft change:
- **Alarm on absence.** Feed silence, a trail stopping, a sudden drop in event volume — a detection that depends on a log source can't fire if the source goes dark.
- **Re-baseline periodically.** "Normal" drifts as services and staff change; a rule tuned six months ago may be noisy or blind today.
- **Revisit after every incident.** Confirm the rule that should have caught it did (or update it so next time it will).

## Response Automation Basics

Keep automation **reversible and evidence-preserving**:

| Trigger | Safe automated response |
|---------|-------------------------|
| Instance-credential exfil finding | Tag + isolate SG (not terminate); snapshot; page |
| Public bucket/blob detected | Re-apply Block-Public-Access; snapshot policy first |
| Impossible-travel admin | Revoke sessions / require re-auth; page |
| Logging disabled | Re-enable trail/sink; alert; preserve who did it |
| Key scheduled for deletion | Alert loudly (deletion has a window — human cancels) |

> 🔴 Auto-remediation must **capture before it changes** and be undoable. Automatically terminating an instance can destroy the evidence you needed (→ **02**).

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The shared model behind normalization | **00 Cloud Fundamentals** |
| Manual cross-cloud correlation | **03 Cross-Cloud Correlation** |
| Technique coverage to detect | **00b ATT&CK Cloud to Evidence Map** |
| Per-service detections + "what's normal" | each service **for DFIR** (Hunt at Scale) |
| Native queries per provider | **AWS** Athena/Lake · **Azure** KQL · **Google** Log Explorer |

## Resources

- Google SecOps UDM field list — https://cloud.google.com/chronicle/docs/reference/udm-field-list
- Sigma (cloud detection rules) — https://github.com/SigmaHQ/sigma
- MITRE ATT&CK Cloud — https://attack.mitre.org/matrices/enterprise/cloud/
- AWS CloudTrail → SIEM / Azure Sentinel / Google SecOps feeds — provider ingestion docs
