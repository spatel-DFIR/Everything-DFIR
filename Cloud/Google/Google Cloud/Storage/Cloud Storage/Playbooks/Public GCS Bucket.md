# Playbook — Public GCS Bucket

The classic "leaky bucket," GCP edition. A bucket becomes **publicly readable** (`allUsers`/`allAuthenticatedUsers`) — by accident or by an attacker — and sensitive data is exposed. This playbook determines **when it went public, who did it, what was readable, whether reads happened, and how to lock it down.**

> **Tier 1 (single-service).** GCS-focused; pulls in Cloud Audit Logs + Org Policy. Read **Cloud Storage for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **SCC** | `Public bucket ACL` / Security Health Analytics finding |
| **External report** | A researcher/customer found your data online |
| **Audit log** | `storage.setIamPermissions` adding `allUsers` |
| **Org Policy** | `publicAccessPrevention` disabled then a bucket exposed |

## Hypothesis

A bucket was exposed publicly — by accident or attacker. Establish the exposure window, attribute the change, quantify what was accessible and what was read, then re-privatize.

## Step-by-Step Investigation

**1. Confirm current exposure.**

```bash
gcloud storage buckets get-iam-policy gs://<bucket>    # allUsers / allAuthenticatedUsers?
gcloud storage buckets describe gs://<bucket> --format='value(public_access_prevention)'
```

**2. When did it go public?**

```bash
gcloud logging read \
 'resource.labels.bucket_name="<bucket>" AND protoPayload.methodName=("storage.setIamPermissions" OR "storage.buckets.update")' \
 --freshness=90d --format=json
```

**3. Who exposed it?** The `principalEmail` on that event. Accident (a known admin/Terraform run) vs attacker (unexpected identity/IP) changes your response. 🔴 Check if `publicAccessPrevention` was **disabled** first (org-policy event) — that's deliberate.

**4. What was in the bucket?** Inventory + sensitivity (PII, secrets, backups). This bounds impact even without read proof.

**5. What was read while public?** → next section.

## Did Data Actually Leave?

| If you had… | You can determine |
|-------------|-------------------|
| **Data Access logs** on the bucket | Exactly which objects were read, by whom (incl. anonymous), from where 🎯 |
| **Neither** (default) | 🔴 Only that it was reachable during `[went-public, re-privatized]`. Scope by sensitivity; assume worst |

🔴 Anonymous / external reads on data events = **confirmed** internet access.

## Decision Points

| Question | If yes → |
|----------|----------|
| Accident or attacker? | Attacker → full compromise workflow; accident → fix + process review |
| Data Access logs available? | Prove exactly what was read; else assume worst |
| Sensitive data in the bucket? | Treat as data breach; notify per policy/legal |
| PAP disabled first? | Deliberate — check who and hunt other actions |

## Contain

```bash
gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allUsers --role=roles/storage.objectViewer
gcloud storage buckets remove-iam-policy-binding gs://<bucket> --member=allAuthenticatedUsers --role=roles/storage.objectViewer
gcloud storage buckets update gs://<bucket> --public-access-prevention
```

## Eradicate

- Remove every public grant (IAM + any object ACLs).
- If an **attacker** exposed it: cut their identity (→ Service Account Key Abuse / IAM) and hunt persistence.
- Turn on **Data Access logging** now so the next event is answerable.

## Recover

- Re-privatize + verify (SCC finding clears; PAP enforced).
- Rotate any **secrets** that sat in the exposed bucket (assume leaked).
- Enforce **org-policy `publicAccessPrevention`** so it can't recur.
- Data-breach handling: legal/comms/regulatory if PII was exposed.
- Preserve: the exposure event, window, and any read evidence.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `setIamPermissions` adding `allUsers`/`allAuthenticatedUsers` | Bucket made public |
| `publicAccessPrevention` disabled before exposure | Deliberate |
| Anonymous / external reads on data events | Confirmed access |
| Sensitive content + no Data Access logs | Unprovable loss — assume worst |
| Exposure by an unexpected identity/IP | Attacker, not accident |

## References

- Related notes: **Cloud Storage for DFIR** (see also its **Bucket-Level Privilege Escalation** section — a principal can self-grant broader bucket access via `storage.buckets.setIamPolicy`, a distinct path from public exposure), **Cloud Audit Logs**, **Organization Policy**, **Service Account Key Abuse**
- Public access prevention — https://cloud.google.com/storage/docs/public-access-prevention
- Storage audit logging — https://cloud.google.com/storage/docs/audit-logging
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
