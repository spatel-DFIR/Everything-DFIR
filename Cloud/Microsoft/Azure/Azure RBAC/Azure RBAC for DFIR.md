# Azure RBAC for DFIR

Privilege escalation in Azure means **a role assignment was made** — Owner, User Access Administrator, or a custom role hiding Owner-like power — often ending with `elevateAccess`. This note is how you find the grant, judge it, and pull it back.

New to this? Read **What is Azure RBAC** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Judging a Role Assignment](#judging-a-role-assignment)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **Activity Log** | `roleAssignments/write`, `elevateAccess/action` |
| **Current assignments** | Who holds what, at what scope, now |
| **Role definitions** | Custom roles + their actions |
| **PIM (Azure)** | Eligible/active Azure role activations |

## Collect It

**Every role assignment (sweep all scopes):**

```bash
az role assignment list --all --include-inherited \
  --query "[].{principal:principalName,type:principalType,role:roleDefinitionName,scope:scope}" -o table
```

**Read custom roles for hidden power:**

```bash
az role definition list --custom-role-only true \
  --query "[].{name:roleName,actions:permissions[0].actions}" -o json
```

**Role-grant events + the bridge (Activity Log):**

```bash
az monitor activity-log list --offset 30d \
  --query "[?contains(operationName.value,'roleAssignments/write') || contains(operationName.value,'elevateAccess')]"
```

> **Console:** subscription/mgmt group → **Access control (IAM)** → *Role assignments* (filter to Owner/UAA); PIM → **Azure resources** → activation history.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Find the grant | Which role, to whom, at what scope, by whom, when |
| 2. Judge legitimacy | Expected IaC/admin, or attacker? (table below) |
| 3. Check scope | Management-group/subscription = catastrophic; resource = contained |
| 4. Check the bridge | `elevateAccess` if a GA is involved |
| 5. Enumerate follow-on | After the grant: VM commands, key/secret access, deletions? |
| 6. Note SP/MI grants | Roles granted to service principals / managed identities (easy to miss) |

## Judging a Role Assignment

| Question | Attacker-leaning answer |
|----------|-------------------------|
| Principal? | A **new SP/managed identity**, a guest, or a fresh account |
| Role? | Owner / User Access Administrator / custom w/ `Authorization/*/write` |
| Scope? | Subscription or **management group** |
| Grantor? | A compromised account or an app |
| Correlation | Right after a suspicious sign-in; outside change windows |
| Via IaC? | No matching pipeline/deployment |

## Hunt at Scale

**Owner / UAA grants:**

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, Properties
```

**The GA→Azure bridge:**

```kql
AzureActivity
| where OperationNameValue has "elevateAccess"
| project TimeGenerated, Caller, CallerIpAddress
```

**Roles granted to service principals / managed identities:** filter the assignment list where `principalType in ("ServicePrincipal","ManagedIdentity")` and role is privileged.

## Respond

| Goal | Action |
|------|--------|
| Remove the rogue grant | `az role assignment delete --assignee <id> --role <role> --scope <scope>` |
| Revoke the bridge | Remove the root-scope UAA assignment created by `elevateAccess` |
| Contain the principal | Disable user/SP + revoke tokens (Entra); deallocate a compromised MI's resource |
| Sweep follow-on | Undo what the role did (VM commands, key access, deletions) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **PIM for Azure resources** (JIT Owner/UAA) | No standing privileged assignments |
| **Minimize Owners**; avoid subscription/mgmt-group Owner where possible | Small blast radius |
| **Alert** on `roleAssignments/write` (Owner/UAA) + `elevateAccess` | Catch escalation live |
| **Review custom roles** for `Authorization/*/write` | Kill hidden Owner-equivalents |
| **Deny-assignments / Azure Policy** on sensitive scopes | Guardrails |
| **Access reviews** on privileged assignments | Prune stale grants |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Owner/UAA granted at subscription/mgmt-group scope | Takeover |
| `elevateAccess` by a Global Admin | Owns all subscriptions |
| Role granted to a new SP/managed identity | Workload-based persistence |
| Custom role with `Authorization/*/write` | Hidden escalation |
| Grant right after a suspicious sign-in | Compromise-driven |
| Follow-on VM `runCommand` / `listKeys` | Using the new power |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Azure RBAC is + the two worlds | **Azure RBAC → What is** |
| The control-plane log | **Azure → Activity Log** |
| The Entra-roles side + `elevateAccess` | **Entra → Roles & PIM** |
| Who the principal is | **Microsoft → 01 Entra ID & Identities** |
| A cross-world escalation chain | **Entra → Playbooks → Privileged Role Escalation** |

## Resources

- Azure RBAC — https://learn.microsoft.com/azure/role-based-access-control/overview
- List/manage assignments — https://learn.microsoft.com/azure/role-based-access-control/role-assignments-list-cli
- PIM for Azure resources — https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-resource-roles-configure-role-settings
- MITRE ATT&CK: T1098.003 Additional Cloud Roles — https://attack.mitre.org/techniques/T1098/003/
