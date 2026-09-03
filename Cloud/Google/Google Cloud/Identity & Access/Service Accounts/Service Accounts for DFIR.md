# Service Accounts for DFIR

SA cases hinge on one question: **was this a key, an impersonation, or an attached workload — and how do I cut it?** Get that right and containment follows.

New to it? Read **What is a Service Account** first (and **01 - Google Identities** for the credential decoder).

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Classify How the SA Was Used](#classify-how-the-sa-was-used)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Admin Activity audit** | SA create/enable/key/impersonation events | The actions |
| **`serviceAccountKeyName`** | A user-managed key was used | Key-based abuse |
| **`serviceAccountDelegationInfo`** | Impersonation chain | Impersonation abuse |
| **`keys list`** | All keys on an SA (+ user vs Google-managed) | Backdoor keys |
| **SA IAM policy** | Who can impersonate/attach it | Blast radius |

## Collect It

```bash
# Enumerate SAs and their keys (user-managed keys are the risk)
gcloud iam service-accounts list --project=<p>
gcloud iam service-accounts keys list --iam-account=<sa> --managed-by=user

# Who can impersonate / attach this SA?
gcloud iam service-accounts get-iam-policy <sa>

# Key creation + impersonation events in the window
gcloud logging read \
 'protoPayload.methodName=("google.iam.admin.v1.CreateServiceAccountKey"
   OR "google.iam.credentials.v1.GenerateAccessToken"
   OR "google.iam.admin.v1.CreateServiceAccount")' --freshness=30d --format=json
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Anchor the SA | Which SA, what roles, what it can reach |
| 2. Classify usage | Key / impersonation / attachment (below) |
| 3. Find the origin | Who created the key or holds TokenCreator; who attached it |
| 4. Trace actions | Everything the SA did in the window (its `principalEmail`) |
| 5. Measure reach | The SA's roles + inheritance = blast radius |

## Classify How the SA Was Used

| You see… | It was used via… | Cut it by… |
|----------|------------------|-----------|
| `serviceAccountKeyName` present | A **user-managed key** | **Delete that key** |
| `serviceAccountDelegationInfo` present | **Impersonation** | **Remove TokenCreator** from the caller |
| SA email = default Compute SA, from a VM IP | **Attachment** (likely a compromised VM) | Fix/rebuild the **VM**; rotate SA |
| `principalSubject` federated | **Workload Identity Federation** | Fix the WIF pool/condition |

🔴 If it was a **key**, also assume the key is copyable and may be used again — rotate and hunt for other copies.

## Hunt at Scale

**BigQuery — all user-managed key creations:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS actor,
       protopayload_auditlog.resourceName AS sa
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'google.iam.admin.v1.CreateServiceAccountKey'
ORDER BY timestamp DESC;
```

**Impersonation of privileged SAs:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS caller,
       protopayload_auditlog.resourceName AS impersonated_sa
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'GenerateAccessToken'
ORDER BY timestamp DESC;
```

**Standing risk sweep (from state, not logs):** list every SA with **user-managed keys** and every SA with **domain-wide delegation** — both are backdoors waiting to happen.

> **At the very end — SecOps UDM (optional):** land key-creation + impersonation events to correlate the actor across projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Kill a leaked key | `keys delete <KEY_ID> --iam-account=<sa>` |
| Stop impersonation | Remove `TokenCreator`/`serviceAccountUser` from the attacker |
| Freeze the SA | `service-accounts disable <sa>` (then investigate before delete) |
| Rotate | Re-issue creds to legit workloads via keyless methods |
| Preserve | Export key/impersonation events + the SA IAM policy |

```bash
gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<sa>
gcloud iam service-accounts remove-iam-policy-binding <sa> \
  --member='user:attacker@...' --role='roles/iam.serviceAccountTokenCreator'
gcloud iam service-accounts disable <sa>
```

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Org Policy: disable SA key creation** (`iam.disableServiceAccountKeyCreation`) | No downloadable keys = no leaked-key risk |
| **Keyless** — attachment / impersonation / Workload Identity Federation | Removes the long-lived secret |
| **Least-privilege SAs**; no Basic **Editor**; disable default-SA auto-grant | Small blast radius |
| **Restrict TokenCreator / actAs** to specific principals | No easy impersonation |
| **Review DWD list** quarterly | Closes the Workspace bridge |
| **Alert** on `CreateServiceAccountKey`, impersonation of privileged SAs | Catch persistence live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `CreateServiceAccountKey` on a privileged SA | Persistence — long-lived key |
| Any user-managed key in a keyless environment | Standing backdoor |
| `GenerateAccessToken` by an unexpected principal | Impersonation abuse |
| TokenCreator/actAs granted to a foothold | Privesc setup |
| Default Compute SA acting from a new IP | VM compromise / metadata theft |
| New DWD authorization | Workspace-wide key |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The SA model + keys/impersonation | **Service Accounts → What is** |
| The credential decoder | **Google → 01 Google Identities** |
| IAM roles + privesc | **GCP → Cloud IAM** |
| Metadata token theft | **GCP → Compute Engine** · **Playbooks → Metadata SSRF to SA Token Theft** |
| Key-abuse intrusion | **GCP → Playbooks → Service Account Key Abuse** |
| Impersonation abuse | **GCP → Playbooks → Service Account Impersonation & Token Abuse** |

## Resources

- Best practices for SAs — https://cloud.google.com/iam/docs/best-practices-service-accounts
- Keys create/delete — https://cloud.google.com/iam/docs/keys-create-delete
- Restrict SA key creation (org policy) — https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
- Impersonation — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- MITRE ATT&CK: T1098.001 Additional Cloud Credentials / T1550 Use Alternate Auth Material — https://attack.mitre.org/techniques/T1098/001/
