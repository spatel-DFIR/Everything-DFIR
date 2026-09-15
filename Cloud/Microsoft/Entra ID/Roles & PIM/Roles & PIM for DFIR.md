# Entra Roles & PIM for DFIR

Privilege escalation in Microsoft almost always means **a directory role was granted** — permanently, or via a PIM eligibility the attacker planted. This note is how you find the grant, judge whether it was legitimate, and pull it back.

New to this? Read **What is Entra Roles & PIM** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Judging a Role Grant](#judging-a-role-grant)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Where |
|--------|--------------|-------|
| **Audit logs** | Role grants, eligibilities, PIM activations, PIM setting changes | Entra / `AuditLogs` |
| **Current assignments** | Who holds/eligible for each role now | Entra → Roles / Graph |
| **PIM activation history** | Who activated what, when, justification, approver | Entra → PIM / Graph |
| **Activity Log** | 🔴 `elevateAccess` (the GA→Azure bridge) | Azure Activity Log |

## Collect It

**Who holds privileged roles right now:**

```powershell
# Members of Global Administrator (repeat per sensitive role)
$role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id

# PIM: eligible assignments (the persistence hiding spot)
Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
```

> **Console:** Entra ID → **Roles and administrators** → open a role → **Assignments** (Active + Eligible). PIM → **Entra roles** → *Assignments* / *Activation history*.

**Every role change in the window:**

```powershell
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Add member to role' or activityDisplayName eq 'Add eligible member to role'" -Top 200
```

**Check the Azure bridge (Activity Log):**

```bash
az monitor activity-log list --offset 30d \
  --query "[?contains(operationName.value,'elevateAccess')]"
```

## Investigate on the Platform

The flow:

| Step | Do this |
|------|---------|
| 1. Find the grant | Which role, to whom, by whom, when (audit log) |
| 2. Judge legitimacy | Expected admin action, or attacker? (table below) |
| 3. Check for eligibility persistence | Did they plant a **PIM eligibility** (quieter than a permanent grant)? |
| 4. Check PIM weakening | `Update role setting` removing MFA/approval? |
| 5. Check the Azure bridge | `elevateAccess` in the Activity Log if a GA is involved |
| 6. Enumerate what they did with it | Role activated → what actions followed (further grants, app creds, CA changes) |

## Judging a Role Grant

| Question | Attacker-leaning answer |
|----------|-------------------------|
| Who was granted? | A **fresh** account, a guest (`#EXT#`), or a service principal |
| Who granted it? | A compromised account, or an **app** (SP) |
| Which role? | Global Admin, Priv Role Admin, Priv Auth Admin, Hybrid Identity Admin |
| Permanent or PIM-JIT? | **Permanent**, bypassing the org's PIM model |
| Time of day / correlation | Outside change windows; right after a suspicious sign-in |
| Was PIM approval/MFA present? | Missing / setting recently weakened |

## Hunt at Scale

**Privileged role grants:**

```kql
AuditLogs
| where OperationName in ("Add member to role","Add eligible member to role")
| extend Role = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where Role has_any ("Global Administrator","Privileged Role Administrator","Privileged Authentication Administrator","Hybrid Identity Administrator","Application Administrator")
| project TimeGenerated, Actor=InitiatedBy, Role, Target=TargetResources
```

**PIM settings weakened:**

```kql
AuditLogs
| where OperationName has "Update role setting"
| project TimeGenerated, InitiatedBy, TargetResources
```

**The Azure bridge (in Sentinel with AzureActivity):**

```kql
AzureActivity
| where OperationNameValue has "elevateAccess"
| project TimeGenerated, Caller, CallerIpAddress, ActivityStatusValue
```

## Respond

| Goal | Action |
|------|--------|
| Remove the rogue role | `Remove-MgDirectoryRoleMemberByRef` (permanent) or remove the PIM eligibility |
| Undo PIM weakening | Restore MFA-on-activation + approval on the role settings |
| Revoke the Azure bridge | Remove the root-scope User Access Administrator grant from `elevateAccess` |
| Contain the identity | Disable + revoke tokens for the granted account and the granting account |
| Sweep for co-persistence | Check for backdoor users, app credential adds, CA changes made with the role |

> 🔴 Pulling the role back is not enough — an attacker who *had* Global Admin likely **also** created a backdoor account, added an app secret, or weakened CA. Run the **Privileged Role Escalation** playbook to sweep.

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **PIM for every privileged role** (JIT, approval, MFA, time-boxed) | No standing admins to abuse |
| **Minimize permanent Global Admins** (target ≤ 5, break-glass excluded) | Small, watched attack surface |
| **Alert** on any Global Admin / Priv Role Admin grant + `elevateAccess` | Catch escalation instantly |
| **Access reviews** on privileged roles | Prune stale grants + eligibilities |
| **Separate admin accounts** (no mail/browsing) + phishing-resistant MFA | Harder to compromise |
| **Restrict who can consent/assign roles** | Fewer escalation paths |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `Add member to role` → Global Administrator | Takeover |
| **Permanent** privileged grant bypassing PIM | Standing backdoor privilege |
| New **eligible** assignment to a fresh/guest account | Quiet persistence |
| `Update role setting` removing MFA/approval | PIM weakening (evasion) |
| Role granted by a **service principal** | App-driven escalation |
| `elevateAccess` by a Global Admin | Bridge to owning all Azure |
| Priv Auth Admin resetting an admin's MFA | Admin account takeover |
| Hybrid Identity Admin / federation change | Golden SAML path |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the roles are + PIM | **Roles & PIM → What is** |
| Who the actor is | **Microsoft → 01 Entra ID & Identities** |
| Role-grant events | **Entra → Audit Logs** |
| App-credential escalation | **Entra → Applications & Service Principals** |
| The Azure side + `elevateAccess` | **Azure → Azure RBAC** |
| The full chain | **Entra → Playbooks → Privileged Role Escalation** |

## Resources

- PIM — https://learn.microsoft.com/entra/id-governance/privileged-identity-management/pim-configure
- Securing privileged access — https://learn.microsoft.com/entra/identity/role-based-access-control/security-planning
- Emergency access accounts — https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
- MITRE ATT&CK: Account Manipulation: Additional Cloud Roles (T1098.003) — https://attack.mitre.org/techniques/T1098/003/
