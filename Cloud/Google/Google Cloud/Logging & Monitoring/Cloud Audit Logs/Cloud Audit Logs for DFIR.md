# Cloud Audit Logs for DFIR

The audit logs are the **first place you look** in almost every GCP case — they tell you what an identity did across compute, storage, IAM, and more. This note is the *how*: collect, read, and hunt.

New to it? Read **What is Cloud Audit Logs** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Reading Identity in the Log](#reading-identity-in-the-log)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Logs Explorer** | All four streams | `_Required` 400d / `_Default` 30d | Fast first look |
| **`gcloud logging read`** | Same, scriptable | Same | Bulk pulls |
| **BigQuery sink** (if configured) | Exported copy, SQL | Your retention | Hunting + long retention |
| **Data Access logs** | Reads (if enabled) | Config | Proving data theft |

**In SecOps (optional):** lands as GCP audit; actor → `principal.user.email_addresses`, method → `metadata.product_event_type`, resource → `target.resource.name`.

## Collect It

**Step 1 — Confirm coverage (do this first):**

```bash
gcloud projects get-iam-policy <project> --format=json | jq '.auditConfigs'  # is Data Access on?
gcloud logging sinks list --project=<project>                                 # long-retention sink?
```

**Step 2 — Pull an identity's activity:**

```bash
gcloud logging read \
  'logName="projects/<p>/logs/cloudaudit.googleapis.com%2Factivity"
   AND protoPayload.authenticationInfo.principalEmail="attacker@contoso.com"' \
  --project=<p> --freshness=30d --format=json > actor.json
```

**Step 3 — Target the high-value methods:**

```bash
gcloud logging read \
  'protoPayload.methodName=("SetIamPolicy" OR "google.iam.admin.v1.CreateServiceAccountKey"
    OR "google.iam.credentials.v1.GenerateAccessToken")' --freshness=30d
```

> **Console:** Logging → **Logs Explorer** → filter by `logName`, `protoPayload.methodName`, `principalEmail`, resource, time.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Data Access on? Sink for old events? Note blind spots |
| 2. Scope the principal | Full timeline; note `callerIp`, projects touched |
| 3. Classify credential | Human vs SA; **key** (`serviceAccountKeyName`) vs **impersonation** (`serviceAccountDelegationInfo`) |
| 4. Bucket by phase | IAM changes, new SAs/keys, compute, exfil (table below) |
| 5. Follow the pivot | Impersonation chains, metadata-token use, cross-project moves |

## What to Look For, by Phase

| Phase | Telltale methods |
|-------|------------------|
| **Initial access** | First action from a new IP; `GetCallerIdentity`-style enumeration; `compute.instances.list` recon |
| **Privilege escalation** | `SetIamPolicy` granting Owner/Editor; `CreateServiceAccountKey`; `GenerateAccessToken`; role update |
| **Persistence** | New SA + key; new IAM binding to an external account; new DWD client (Workspace admin log) |
| **Defense evasion** | Log sink delete/redirect; `SetOrgPolicy` weakening constraints; disabling SCC |
| **Collection/exfil** | `storage.objects.get` at volume (needs Data Access); BigQuery large extracts; bucket made public |
| **Impact** | Mass delete of resources/buckets; crypto VMs (`instances.insert` bursts) |

🔴 A **burst of `authorizationInfo.granted=false` then a sudden success** is privilege escalation in progress.

## Reading Identity in the Log

| You see… | It's… |
|----------|-------|
| `principalEmail` = `…iam.gserviceaccount.com`, `gcloud` agent | A service account |
| `serviceAccountKeyName` present | A **long-lived JSON key** was used 🔴 |
| `serviceAccountDelegationInfo` present | An **impersonation** — read the chain |
| `principalEmail` = `…-compute@developer…` | Compute **default SA** (often a compromised VM) 🔴 |
| `principalSubject` (not an email) | A **federated** external workload |
| `principalEmail` at `@gmail.com`/foreign domain | External identity 🔴 |

See **Google → 01 Google Identities** for the full decoder.

## Hunt at Scale

**BigQuery (audit sink) — IAM grants of broad roles:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.resourceName AS resource
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'SetIamPolicy'
ORDER BY timestamp DESC;
```

**New service-account keys (persistence):**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail, resource.labels.project_id
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'google.iam.admin.v1.CreateServiceAccountKey';
```

**Logs Explorer — impersonation:**

```
protoPayload.authenticationInfo.serviceAccountDelegationInfo:*
```

> **At the very end — SecOps UDM (optional):** land IAM-change + key-creation events to answer "did this principal/IP appear elsewhere/before?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut a compromised identity | Disable the SA + delete keys, or reset the user (see 02) |
| Reverse a rogue grant | Remove the IAM binding; review what it reached |
| Stop exfil | Re-privatize buckets; revoke external grants |
| Re-secure logging | Restore deleted sinks; lock the log bucket |
| Preserve | Export the audit window (Logs Explorer → download / BigQuery) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Data Access logging** (`DATA_READ` for GCS + critical services) | Closes the "who read data" blind spot |
| **Org-level aggregated sink → BigQuery** (locked bucket) | Long retention + central hunting + tamper-resistance |
| **Log bucket locks / separate project** for logs | Attacker can't delete evidence |
| **Alert** on `SetIamPolicy`, key creation, sink deletes, org-policy changes | Catch privesc/evasion live |
| **VPC Service Controls** around sensitive data | Denials show in Policy Denied |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `SetIamPolicy` granting Owner/Editor or org-admin | Privilege escalation |
| `CreateServiceAccountKey` on an existing SA | Persistence |
| `GenerateAccessToken` by an unexpected principal | Impersonation abuse |
| Log sink deleted/redirected | Anti-forensics |
| Org policy / SCC disabled | Defense evasion |
| Actions by the Compute default SA from a new IP | VM compromise / metadata theft |
| IAM binding to an external/consumer account | Backdoor access |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The streams + entry structure | **Cloud Audit Logs → What is** |
| Who the principals are | **Google → 01 Google Identities** |
| Routing / sinks / retention | **GCP → Cloud Logging** |
| IAM privilege escalation | **GCP → Cloud IAM** · **Playbooks → IAM Privilege Escalation** |
| SA key / impersonation abuse | **GCP → Service Accounts** |

## Resources

- Cloud Audit Logs — https://cloud.google.com/logging/docs/audit
- Logging query language — https://cloud.google.com/logging/docs/view/logging-query-language
- Enable Data Access logs — https://cloud.google.com/logging/docs/audit/configure-data-access
- Aggregated sinks — https://cloud.google.com/logging/docs/export/aggregated_sinks
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/
