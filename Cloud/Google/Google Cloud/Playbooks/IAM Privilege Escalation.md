# Playbook — IAM Privilege Escalation

An attacker with a foothold identity uses one of GCP's well-known **privesc primitives** — minting a key on a privileged SA, impersonating it, editing a custom role, or `SetIamPolicy`-ing themselves Owner — to climb toward project or **organization** control. This playbook reconstructs the escalation path and rolls it back.

> **Tier 2 (cross-service).** Spans Cloud IAM + Service Accounts + Cloud Audit Logs. Read **GCP → Cloud IAM** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [The Escalation Primitives](#the-escalation-primitives)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **SCC** | `IAM Anomalous Grant` / external member on a privileged role |
| **Audit log** | `SetIamPolicy` granting Owner/Editor/org-admin |
| **Burst pattern** | Many `granted=false` then a sudden success |
| **Foothold** | A low-priv identity suddenly doing high-priv actions |

## Hypothesis

A foothold identity escalated privileges. Establish the primitive used, the resulting access, how far it reaches (esp. org level), and revert every step.

## The Escalation Primitives

🔴 Watch for the foothold **using** or **granting itself** these:

| Primitive | The move |
|-----------|----------|
| `iam.serviceAccountKeys.create` | Mint a key on a more-privileged SA |
| `iam.serviceAccounts.getAccessToken` (TokenCreator) | Impersonate a privileged SA |
| `iam.serviceAccounts.actAs` + deploy | Run code as a privileged SA (VM/Function/Run) |
| `iam.roles.update` | Add permissions to a custom role you hold |
| `resourcemanager.projects.setIamPolicy` | Grant yourself Owner on a project |
| `resourcemanager.organizations.setIamPolicy` → `organizationAdmin` | 🔴 Own the whole org |
| `cloudfunctions/run ... create` + `actAs` | Execute as a privileged SA |

## Step-by-Step Investigation

**1. Find the grant/primitive.**

```bash
gcloud logging read \
 'protoPayload.methodName=("SetIamPolicy" OR "google.iam.admin.v1.CreateServiceAccountKey"
   OR "GenerateAccessToken" OR "google.iam.admin.v1.UpdateRole")' --freshness=30d --format=json
```

**2. Read the before/after.** For `SetIamPolicy`, compare bindings — what member+role was added, **at what scope** (resource/project/folder/**org**).

**3. Trace the foothold.** The first suspicious action → the primitive → the new powers → what they did next.

**4. Check org level.** 🔴 Any `SetIamPolicy` at the organization node, or `organizationAdmin` grant — the Super-Admin→GCP or top-tier escalation.

## Decision Points

| Question | If yes → |
|----------|----------|
| Reached org-level Owner/admin? | 🔴 Org compromise — all projects at risk |
| Via SA key/impersonation? | Run **SA Key Abuse** / **Impersonation & Token Abuse** |
| External member granted? | Backdoor account — remove + hunt |
| Custom role widened? | Read the new permissions; revert |

## Contain

```bash
# Remove the rogue binding at the exact scope it was granted
gcloud projects remove-iam-policy-binding <p> --member='<attacker>' --role='roles/owner'
gcloud organizations remove-iam-policy-binding <org> --member='<attacker>' --role='roles/resourcemanager.organizationAdmin'
# Kill key/impersonation paths (see those playbooks)
```

## Eradicate

- Revert **every** binding/role change in the chain (work backward from the highest privilege).
- Delete attacker-created SAs/keys and rogue custom-role versions.
- Remove `actAs`-attached resources running as privileged SAs.
- Reset the original foothold credential (user/SA).

## Recover

- **Ban Basic roles**; least-privilege predefined/custom roles; **IAM Conditions**.
- **Org Policy**: domain-restricted sharing, disable SA key creation.
- Restrict `setIamPolicy`, `TokenCreator`, `actAs`, `roles.update` to few, monitored principals.
- Alert on Owner/org grants, external members, key creation, impersonation.
- Preserve: the full `SetIamPolicy` history + the escalation chain.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `SetIamPolicy` granting Owner/Editor/org-admin | Escalation |
| Org/folder-level grant | Wide blast radius |
| `granted=false` burst then success | Escalation in progress |
| Custom role widened | Quiet privilege gain |
| Key/impersonation/`actAs` by a foothold | Primitive in use |

## References

- Related notes: **Cloud IAM**, **Service Accounts**, **Cloud Audit Logs**, **SA Key Abuse**, **SA Impersonation & Token Abuse**, **00 Overview (two admin worlds)**
- IAM best practices — https://cloud.google.com/iam/docs/using-iam-securely
- Restrict SA usage (org policy) — https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
- MITRE ATT&CK: T1098 Account Manipulation / T1548 Abuse Elevation Control — https://attack.mitre.org/techniques/T1098/
