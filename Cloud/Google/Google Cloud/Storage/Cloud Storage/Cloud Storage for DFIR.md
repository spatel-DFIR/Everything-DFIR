# Cloud Storage for DFIR

GCS cases answer: **was data exposed or stolen — what, by whom, when, and can I prove reads?** You read the config events (exposure) and, if enabled, the Data Access events (reads).

New to it? Read **What is Cloud Storage** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Bucket-Level Privilege Escalation](#bucket-level-privilege-escalation)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Default | Best for |
|--------|--------------|---------|----------|
| **Admin Activity** | IAM/config changes on buckets | ✅ On | Exposure event |
| **Data Access** | `objects.get/list/create` | 🔴 Off | Proving reads |
| **`get-iam-policy` / bucket metadata** | Current access + PAP state | Live | Present exposure |

## Collect It

```bash
# Is it public now? PAP on?
gcloud storage buckets get-iam-policy gs://<bucket>        # allUsers/allAuthenticatedUsers?
gcloud storage buckets describe gs://<bucket> --format='value(public_access_prevention)'

# When/who exposed it (config events)
gcloud logging read \
 'resource.type="gcs_bucket" AND protoPayload.methodName=("storage.setIamPermissions" OR "storage.buckets.update")
  AND resource.labels.bucket_name="<bucket>"' --freshness=30d --format=json

# Reads while exposed (only if Data Access logging was on)
gcloud logging read \
 'logName:"data_access" AND resource.labels.bucket_name="<bucket>" AND protoPayload.methodName="storage.objects.get"' \
 --freshness=30d
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm exposure | `allUsers`/`allAuthenticatedUsers` in the IAM policy or an object ACL |
| 2. When did it go public? | The `setIamPermissions` / `buckets.update` event |
| 3. Who exposed it? | The `principalEmail` on that event — accident (IaC/admin) vs attacker |
| 4. What's in the bucket? | Inventory + sensitivity (PII, secrets, backups) |
| 5. What was read? | Data Access logs (if on) → next section |

## Did Data Actually Leave?

| If you had… | You can determine |
|-------------|-------------------|
| **Data Access logs** on the bucket | Exactly which objects were read, by whom (incl. anonymous), from where 🎯 |
| **Neither** (default) | 🔴 Only that it *was* reachable during `[went-public, re-privatized]`. Scope by content; assume worst case |

🔴 `principalEmail` anonymous / `allUsers` reads, or an external identity, on data events = **confirmed** internet reads.

## Bucket-Level Privilege Escalation

A principal holding `storage.buckets.setIamPolicy` on a bucket can grant **themselves** broader access to that bucket — e.g. self-grant `roles/storage.objectAdmin` or add `allUsers`/`allAuthenticatedUsers`. It's a bucket-scoped privesc path, distinct from the general IAM privesc permissions table in **Cloud IAM → What is Cloud IAM**: it doesn't require project/org-level IAM permissions, only the one bucket-level binding.

- **Abuse pattern:** a principal with limited project IAM but `setIamPolicy` on a specific bucket uses it to reach objects they otherwise couldn't — their own storage-level "backdoor" scoped to that bucket.
- **Find it:** `storage.setIamPermissions` / `SetIamPolicy` events on the bucket where the grantor's own identity is the member added, or where the added role exceeds what the grantor holds elsewhere.
- 🔴 Watch for a principal with only `roles/storage.admin` on one bucket (not project-wide) suddenly appearing with broader access on that same bucket.

## Hunt at Scale

**BigQuery — buckets made public:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       resource.labels.bucket_name AS bucket
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName='storage.setIamPermissions'
  -- inspect request bindings for allUsers/allAuthenticatedUsers
ORDER BY timestamp DESC;
```

**Anonymous / high-volume object reads (if Data Access on):**

```sql
SELECT resource.labels.bucket_name, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       COUNT(*) reads
FROM `contoso.audit.cloudaudit_googleapis_com_data_access`
WHERE protopayload_auditlog.methodName='storage.objects.get'
GROUP BY 1,2 HAVING reads > 1000 ORDER BY reads DESC;
```

> **At the very end — SecOps UDM (optional):** land public-exposure + anonymous-read events to correlate the actor/IP. Keep it light.

## Respond

```bash
# Re-privatize: remove public members + turn ON Public Access Prevention
gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allUsers --role=roles/storage.objectViewer
gcloud storage buckets update gs://<bucket> --public-access-prevention
```

| Goal | Action |
|------|--------|
| Kill exposure | Remove `allUsers`/`allAuthenticatedUsers`; enable PAP |
| If attacker exposed it | Cut their identity (SA/user); hunt persistence |
| Rotate | Any secrets that sat in the exposed bucket |
| Enable reads logging | Turn on Data Access so the next event is answerable |
| Preserve | Export the exposure event + any read evidence |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Org Policy `storage.publicAccessPrevention`** (enforced) | Buckets can't be made public at all |
| **Uniform bucket-level access** | Kills fine-grained ACL mis-shares |
| **Enable Data Access (`DATA_READ`)** on sensitive buckets | Prove reads next time |
| **Alert** on `setIamPermissions` adding public members | Catch exposure live |
| **VPC Service Controls** around sensitive buckets | Blocks exfil outside the perimeter |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `setIamPermissions` adding `allUsers`/`allAuthenticatedUsers` | Public exposure |
| PAP disabled then bucket exposed | Deliberate exposure |
| Anonymous / external object reads | Confirmed data left |
| `objects.list` + bulk `objects.get` by one identity | Exfil |
| `objects.delete` at volume / bucket delete | Destruction / ransomware |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| GCS access model + logging gap | **Cloud Storage → What is** |
| The public-bucket scenario | **Cloud Storage → Playbooks → Public GCS Bucket** |
| Who exposed/read it | **GCP → Cloud Audit Logs** · **Google → 01 Identities** |
| Broader data theft | **GCP → Playbooks → Data Exfiltration** |
| The guardrail | **GCP → Organization Policy** |
| General IAM privesc primitives | **GCP → Cloud IAM → What is Cloud IAM** |

## Resources

- Storage audit logging — https://cloud.google.com/storage/docs/audit-logging
- Public access prevention — https://cloud.google.com/storage/docs/public-access-prevention
- Making data public (what to avoid) — https://cloud.google.com/storage/docs/access-control/making-data-public
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
