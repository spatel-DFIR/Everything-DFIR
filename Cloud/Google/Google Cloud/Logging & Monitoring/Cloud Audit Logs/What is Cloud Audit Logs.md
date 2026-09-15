# What is Cloud Audit Logs?

**Cloud Audit Logs** are GCP's master audit trail — the record of **who did what, where, and when** across every Google Cloud service. They are to GCP what CloudTrail is to AWS and the Activity Log is to Azure. Almost every GCP investigation starts here.

The one thing to internalize up front: there are **four streams** (plus a fifth, Access Transparency, for Google-side access), and the most valuable one for proving data theft — **Data Access** — is **off by default.**

## Contents

- [How It Works](#how-it-works)
- [The Four Streams](#the-four-streams)
- [Where the Logs Live](#where-the-logs-live)
- [Reading an Audit Entry](#reading-an-audit-entry)
- [The methodNames That Matter](#the-methodnames-that-matter)
- [How to Identify Cloud Audit Logs in Evidence](#how-to-identify-cloud-audit-logs-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Any call to a Google Cloud API (console / gcloud / SDK / Terraform)
   → an AuditLog entry is written to Cloud Logging
   → routed by the Log Router: kept in the _Required/_Default buckets,
     and (if you configure a SINK) copied to BigQuery / GCS / Pub/Sub / another project
```

- Every entry has a **caller** (`authenticationInfo.principalEmail`), a **method** (`methodName`), a **resource** (`resourceName`), and an **authorization decision** (`authorizationInfo`).
- Logs are **per-project** by default; an **org-level aggregated sink** collects them centrally.
- 🔴 Admin Activity is free and permanent-ish; **Data Access** you must turn on and it can be voluminous.

## The Four Streams

| Stream | Records | Default | Analogy |
|--------|---------|---------|---------|
| **Admin Activity** | Config/write actions: create/modify/delete, `SetIamPolicy`, key creation | ✅ **Always on, free, can't disable** | CloudTrail management events |
| **Data Access** | Data-plane reads/writes: object reads, dataset queries, secret access | 🔴 **Off** (except BigQuery) — enable per service | CloudTrail data events |
| **System Event** | Google-initiated actions (maintenance, auto-actions) | ✅ On | Non-human events |
| **Policy Denied** | Requests **denied** by IAM / VPC Service Controls / org policy | ✅ On (when denials occur) | 🔴 Recon/probing evidence |
| **Access Transparency** | Google support engineer access to *your* data (distinct from your own tenant's activity) | 🔴 Off — requires **Gold/Platinum/Enterprise** support tier | Proving/disproving a Google-side-access theory; ruling out Google insider risk |

> 🔴 **The Data Access gap is the single biggest GCP forensics limitation.** By default you can prove *who changed config* but **not who read your data**. Enabling Data Access logging (at least `DATA_READ` for GCS and critical services) is the difference between "we know exactly what was read" and "we assume worst case." See **Cloud Audit Logs for DFIR → Harden**.

## Where the Logs Live

| Log | logName suffix |
|-----|----------------|
| Admin Activity | `cloudaudit.googleapis.com%2Factivity` |
| Data Access | `cloudaudit.googleapis.com%2Fdata_access` |
| System Event | `cloudaudit.googleapis.com%2Fsystem_event` |
| Policy Denied | `cloudaudit.googleapis.com%2Fpolicy` |
| Access Transparency | `cloudaudit.googleapis.com%2Faccess_transparency` |

- **Retention:** `_Required` bucket (Admin Activity/System Event) = **400 days**; `_Default` (everything else) = **30 days**, unless you extend it or route to a sink.
- **Read them in:** Console → **Logging → Logs Explorer**; CLI `gcloud logging read`; or **BigQuery** if a sink exists.

## Reading an Audit Entry

```jsonc
"protoPayload": {
  "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
  "serviceName": "iam.googleapis.com",
  "methodName": "google.iam.admin.v1.CreateServiceAccountKey",   // 🔴 what happened
  "resourceName": "projects/contoso-prod/serviceAccounts/sa-app@contoso-prod.iam.gserviceaccount.com",
  "authenticationInfo": { "principalEmail": "attacker@contoso.com" },  // 🔴 who
  "authorizationInfo": [ { "permission": "iam.serviceAccountKeys.create", "granted": true } ],
  "requestMetadata": { "callerIp": "203.0.113.10", "callerSuppliedUserAgent": "gcloud/..." }
}
```

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `authenticationInfo.principalEmail` | **Who** | SA vs human; external domain |
| `methodName` | **What** | `SetIamPolicy`, `CreateServiceAccountKey`, `generateAccessToken` |
| `resourceName` | **Where** | Which project/resource |
| `authorizationInfo.granted` | Allowed/denied | Bursts of `false` = probing |
| `requestMetadata.callerIp` | **From where** | New geo/ASN |
| `serviceAccountKeyName` / `serviceAccountDelegationInfo` | Key vs impersonation (see 01) | 🔴 long-lived key / impersonation chain |

## The methodNames That Matter

🔴 The high-value actions to filter for:

| methodName | What it does | Watch |
|-----------|--------------|-------|
| `SetIamPolicy` | Change who has a role on a resource | 🔴 privilege escalation |
| `google.iam.admin.v1.CreateServiceAccountKey` | Mint an SA key | 🔴 persistence |
| `google.iam.credentials.v1.GenerateAccessToken` | Impersonate an SA | 🔴 lateral movement |
| `google.iam.admin.v1.CreateServiceAccount` | New SA | 🔴 backdoor identity |
| `*.compute.instances.insert` / `setMetadata` | New VM / metadata change | 🔴 mining / SSH-key injection |
| `storage.setIamPermissions` / `storage.buckets.update` | Bucket IAM/ACL change | 🔴 public exposure |
| `SetOrgPolicy` / delete constraints | Weaken guardrails | 🔴 defense evasion |
| `google.logging.v2.ConfigServiceV2.*` (sink delete) | Disable/redirect logging | 🔴 anti-forensics |

## How to Identify Cloud Audit Logs in Evidence

- **Console:** Logging → **Logs Explorer** (filter by `logName`, `protoPayload.methodName`, `principalEmail`).
- **CLI:** `gcloud logging read '<filter>' --project=<p> --freshness=30d`.
- **BigQuery:** query the sink's dataset if configured.
- **Entry type:** `protoPayload.@type = ...audit.AuditLog`.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud Audit Logs | CloudTrail | Azure Activity Log + resource logs |
| Admin Activity | Management events | Activity Log |
| Data Access | Data events | Diagnostic/resource logs |
| Policy Denied | (AccessDenied entries) | (denied by policy) |
| Log Router sink | CloudTrail → S3/CloudWatch | Diagnostic settings → Log Analytics |
| Logs Explorer | CloudTrail Lake / Athena | Log Analytics (KQL) |

## Common Use Cases

Your "normal" baseline: everyday deploys (Terraform/CI service accounts), autoscaling, automated maintenance (System Event). The job is to separate routine automation from attacker actions — check *principal*, *method*, *source IP*, and whether it's a **human** or a **service account** doing it.

## Key Terminology

| Term | Meaning |
|------|---------|
| **AuditLog** | The audit entry payload type |
| **Admin Activity / Data Access / System Event / Policy Denied** | The four streams |
| **Log Router / sink** | Routes logs to BigQuery/GCS/Pub-Sub/another project |
| **Log bucket** | Where logs are stored (`_Required`, `_Default`, custom) |
| **Logs Explorer** | The console log-query UI |
| **methodName** | The API action recorded |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with the audit logs | **Cloud Audit Logs → for DFIR** |
| Who the principals are (SA/key/impersonation) | **Google → 01 Google Identities** |
| Routing/sinks + long retention | **GCP → Cloud Logging** |
| IAM changes in depth | **GCP → Cloud IAM** |
| Managed threat detection | **GCP → Security Command Center** |

## Resources

- Cloud Audit Logs overview — https://cloud.google.com/logging/docs/audit
- Audit log entry structure — https://cloud.google.com/logging/docs/audit#audit_log_entry_structure
- Enable Data Access logs — https://cloud.google.com/logging/docs/audit/configure-data-access
- Logs Explorer / query language — https://cloud.google.com/logging/docs/view/logging-query-language
