# Playbook — Service Account Key Abuse

A **service-account JSON key** — leaked in git/a laptop/CI, or minted by an attacker for persistence — is used to authenticate as the SA and act across GCP. Because a user-managed key **never expires**, it's the GCP leaked-credential classic. This playbook reconstructs the key's use, measures the blast radius, kills it, and hunts for the copies.

> **Tier 2 (cross-service).** Spans Cloud Audit Logs + IAM + Service Accounts. Read **GCP → Service Accounts** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Measure the Blast Radius](#measure-the-blast-radius)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **SCC** | Anomalous SA activity / key finding |
| **Audit log** | `serviceAccountKeyName` on actions from a new IP |
| **Secret scanner** | An SA key found in a public repo |
| **Persistence** | `CreateServiceAccountKey` on a privileged SA |

## Hypothesis

An SA key is being used by an attacker. Establish where the key came from (leaked vs attacker-minted), what the SA did with it, how far that reaches, delete the key, and find other copies/keys.

## Step-by-Step Investigation

**1. Confirm key-based use.** Filter audit logs for the SA with `serviceAccountKeyName` present:

```bash
gcloud logging read \
 'protoPayload.authenticationInfo.principalEmail="<sa>@<p>.iam.gserviceaccount.com"
  AND protoPayload.authenticationInfo.serviceAccountKeyName:*' --freshness=30d --format=json
```

**2. Where did the key come from?** `CreateServiceAccountKey` event (attacker-minted, note who) vs a pre-existing key (leaked). Cross-check `keys list --managed-by=user`.

**3. What did the SA do?** All actions in the window — IAM changes, storage reads, new SAs/keys, resource creation.

**4. From where?** `callerIp` — off-corp IP / new geo confirms external abuse.

## Measure the Blast Radius

| Question | Evidence |
|----------|----------|
| What roles does the SA hold? | `get-iam-policy` across org/folder/project (+ inheritance) |
| Can it impersonate other SAs? | `TokenCreator` bindings it holds |
| Does it have domain-wide delegation? | 🔴 The Workspace bridge — check the DWD list |
| What did it actually touch? | Its audit-log activity |

## Decision Points

| Question | If yes → |
|----------|----------|
| Key was attacker-minted? | Persistence — hunt for other new keys/SAs |
| SA has Owner/Editor or org roles? | Treat as project/org compromise |
| Has domain-wide delegation? | Workspace data reachable — run **Illicit OAuth / BEC** checks |
| Used from external IP? | Confirmed external actor — full IR |

## Contain

```bash
# Delete the key(s) and freeze the SA
gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<sa>
gcloud iam service-accounts disable <sa>
# Remove any impersonation grant the SA relied on
gcloud iam service-accounts remove-iam-policy-binding <target-sa> \
  --member='serviceAccount:<sa>' --role='roles/iam.serviceAccountTokenCreator'
```

## Eradicate

- Delete **all** user-managed keys on the SA; hunt other SAs the attacker created keys on.
- Revert IAM changes the SA made (rogue bindings, new SAs, new keys).
- If DWD was involved, remove the client from the Workspace DWD list.
- Rotate secrets the SA could reach (Secret Manager, KMS-wrapped data).

## Recover

- Enforce **org policy `disableServiceAccountKeyCreation`**; migrate workloads to **keyless** (impersonation / Workload Identity Federation).
- Alert on `CreateServiceAccountKey` + impersonation of privileged SAs.
- Rotate the SA (or replace it) and re-issue least-privilege access.
- Preserve: key-use events, the key-creation event, the SA's activity, and blast-radius snapshot.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `serviceAccountKeyName` on actions from a new IP | Key-based external abuse |
| `CreateServiceAccountKey` on a privileged SA | Attacker persistence |
| Multiple new keys across SAs | Backdoor spread |
| Key-authenticated SA granting itself roles | Privilege escalation |
| SA with DWD used off-corp | Workspace bridge abuse |

## References

- Related notes: **Service Accounts**, **Cloud IAM**, **Cloud Audit Logs**, **01 Google Identities**, **Metadata SSRF to SA Token Theft**
- Best practices for SAs — https://cloud.google.com/iam/docs/best-practices-service-accounts
- Restrict key creation — https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
- MITRE ATT&CK: T1098.001 Additional Cloud Credentials — https://attack.mitre.org/techniques/T1098/001/
