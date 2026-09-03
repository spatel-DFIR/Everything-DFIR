# Cloud Logging for DFIR

Two jobs on a case: **preserve and query** the evidence, and **verify the attacker didn't blind the logs**. This note covers both.

New to it? Read **What is Cloud Logging** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Confirm Logging Wasn't Tampered](#confirm-logging-wasnt-tampered)
- [Collect and Preserve](#collect-and-preserve)
- [Query for the Investigation](#query-for-the-investigation)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Logs Explorer** | All logs (audit/platform/app) | Query |
| **Log Router config** | Sinks + exclusions (and their change history) | Tamper check |
| **Admin Activity audit** | `ConfigServiceV2.*` — logging changes | Who touched logging |
| **BigQuery / GCS sink** | Exported copies | Long retention |

## Confirm Logging Wasn't Tampered

🔴 Early in any GCP case, verify the logs you're about to trust are intact:

```bash
gcloud logging sinks list --project=<p>           # any deleted/redirected recently?
gcloud logging buckets list --location=global      # retention shortened? bucket deleted?
# Who changed logging config?
gcloud logging read \
  'protoPayload.serviceName="logging.googleapis.com"
   AND protoPayload.methodName:("ConfigServiceV2" OR "sinks" OR "buckets" OR "exclusions")' \
  --freshness=30d
```

| Finding | Meaning |
|---------|---------|
| Sink deleted / redirected | Export to SIEM/BigQuery cut |
| Exclusion filter added | Selective log dropping |
| `_Default` retention shortened | Evidence aging out |
| Log bucket deleted | Destruction (blocked if locked) |

## Collect and Preserve

```bash
# Export a scoped window to a preservation dataset/bucket (or download from Logs Explorer)
gcloud logging read '<filter>' --freshness=30d --format=json > evidence.json
```

- If a **BigQuery/GCS sink** exists, prefer it — it's the durable copy.
- Put the preservation bucket under a **retention lock** so nothing rotates out mid-case.

## Query for the Investigation

Cloud Logging is where you run the queries the other notes reference — audit methods, VM logs, GKE audit, load-balancer logs. Use **Logs Explorer** (query language) or **Log Analytics / BigQuery** (SQL). Examples live in **Cloud Audit Logs for DFIR** and each service note.

## Respond

| Goal | Action |
|------|--------|
| Restore blinded logging | Recreate deleted sinks; remove malicious exclusions |
| Lock down evidence | Apply bucket retention locks; route to a separate logging project |
| Preserve | Export the case window before retention rotates |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Org-level aggregated sink → locked logging project** | Central, tamper-resistant evidence |
| **Bucket retention locks** on the security bucket | Logs can't be deleted early |
| **Restrict `logging.*` admin** (sinks/buckets/exclusions) | Fewer people can blind logs |
| **Alert** on sink/exclusion/bucket changes | Catch anti-forensics live |
| **Enable Data Access logging** + route it | Reads become visible |
| **Ops Agent** on VMs → guest logs to Cloud Logging | Host-level evidence exists |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Sink deleted or redirected | SIEM/lake export cut |
| Exclusion filter added mid-incident | Selective blindness |
| `_Default` retention shortened | Evidence destruction |
| Log bucket delete attempt | Destruction |
| `logging.*` config change by an unexpected principal | Attacker anti-forensics |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The routing model + buckets | **Cloud Logging → What is** |
| The audit logs you're querying | **GCP → Cloud Audit Logs** |
| Network evidence | **GCP → VPC Flow Logs** |
| Threat detections | **GCP → Security Command Center** |

## Resources

- Log Router / sinks — https://cloud.google.com/logging/docs/routing/overview
- Bucket retention & locks — https://cloud.google.com/logging/docs/buckets#retention
- Aggregated sinks — https://cloud.google.com/logging/docs/export/aggregated_sinks
- MITRE ATT&CK: T1562.008 Disable Cloud Logs — https://attack.mitre.org/techniques/T1562/008/
