# What is Cloud Logging?

**Cloud Logging** is GCP's central log-management service — where **audit logs, platform logs, and your app logs all land**, and where the **Log Router** decides what is kept, for how long, and copied where. For DFIR it matters twice: it's how you **preserve and query** evidence, and it's a prime target for attackers who want to **blind the logs**.

## Contents

- [How It Works](#how-it-works)
- [The Log Router and Sinks](#the-log-router-and-sinks)
- [Log Buckets and Retention](#log-buckets-and-retention)
- [Why Attackers Target It](#why-attackers-target-it)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Log sources (Audit logs · VM Ops Agent · GKE · load balancers · your app)
   → Cloud Logging API
   → Log Router (sinks decide destination + inclusion/exclusion filters)
      ├── _Required bucket   (audit admin/system — 400 days, can't disable)
      ├── _Default bucket    (everything else — 30 days default)
      ├── Custom buckets     (your retention, optional Log Analytics)
      └── Sinks → BigQuery / GCS / Pub/Sub / another project / SIEM
```

- Every project has a Log Router. **Sinks** are the mechanism for long retention and SIEM/lake export.
- **Log Analytics** turns a bucket into a BigQuery-queryable surface.

## The Log Router and Sinks

| Sink destination | Use |
|------------------|-----|
| **BigQuery** | SQL hunting + long retention |
| **Cloud Storage (GCS)** | Cheap cold archive |
| **Pub/Sub** | Stream to a SIEM / SecOps / Chronicle |
| **Another project** | 🔴 Tamper-resistant central logging project |

> 🔴 An **org-level aggregated sink** into a **locked, separate logging project** is the gold standard — it collects every project's logs where a project-level attacker can't delete them.

## Log Buckets and Retention

| Bucket | Holds | Default retention |
|--------|-------|-------------------|
| `_Required` | Admin Activity + System Event audit logs | **400 days** (fixed) |
| `_Default` | All other logs (Data Access, platform, app) | **30 days** (adjustable) |
| Custom | Whatever you route | You choose (up to 3650 days) |

**Bucket locks** make retention immutable — evidence can't be deleted early, even by an admin.

## Why Attackers Target It

| Action | Effect | 🔴 |
|--------|--------|----|
| **Delete/disable a sink** | Stops export to BigQuery/SIEM | Blinds long-retention hunting |
| **Add an exclusion filter** | Drops matching logs before storage | Selective blindness |
| **Shorten `_Default` retention** | Evidence ages out fast | Anti-forensics |
| **Delete a log bucket** | Destroys stored logs | Destruction (blocked by lock) |

> Admin Activity logs the config changes to logging itself (`google.logging.v2.ConfigServiceV2.*`) — so a **sink deletion or exclusion added** shows in the audit log. 🔴 Watch for it.

## How to Identify It in Evidence

- **Console:** Logging → **Logs Explorer** (query), **Logs Storage** (buckets/retention), **Log Router** (sinks/exclusions).
- **CLI:** `gcloud logging sinks list`, `gcloud logging buckets list`.
- Logging config changes are in the **Admin Activity** audit stream.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Logging | CloudWatch Logs | Azure Monitor Logs |
| Log Router / sink | CloudTrail → S3/CloudWatch; subscription filters | Diagnostic settings |
| Log bucket + lock | CloudWatch log group / S3 Object Lock | Log Analytics workspace / immutable storage |
| Log Analytics | CloudWatch Logs Insights | Log Analytics (KQL) |
| Aggregated sink | Organization trail | Central Log Analytics workspace |

## Common Use Cases

Your "normal" baseline: platform + app logs for ops; a sink to BigQuery/SecOps for security; retention tuned per bucket. On a case, Cloud Logging is *where you query and preserve* — and where you check whether the attacker tampered with logging.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Log Router** | Routes incoming logs per sinks/filters |
| **Sink** | A rule sending matching logs to a destination |
| **Exclusion filter** | Drops matching logs before storage |
| **Log bucket** | Storage container for logs |
| **Bucket lock** | Immutable retention |
| **Log Analytics** | BigQuery-backed query over a bucket |
| **Ops Agent** | The VM agent that ships guest OS/app logs |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with / preserving logs | **Cloud Logging → for DFIR** |
| The audit logs themselves | **GCP → Cloud Audit Logs** |
| Network flow evidence | **GCP → VPC Flow Logs** |
| Logging tamper as evidence destruction | **GCP → Playbooks → Data Exfiltration** (and defense-evasion notes) |

## Resources

- Cloud Logging overview — https://cloud.google.com/logging/docs/overview
- Log Router / sinks — https://cloud.google.com/logging/docs/routing/overview
- Log buckets & retention — https://cloud.google.com/logging/docs/buckets
- Log Analytics — https://cloud.google.com/logging/docs/analyze/query-and-view
