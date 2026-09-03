# Azure Activity Log for DFIR

The Activity Log is the **first place you look** in almost every Azure investigation. It tells you what an identity did to your infrastructure — role grants, VM commands, firewall changes, deletions.

New to the service? Read **What is the Azure Activity Log** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading an Activity Log Entry](#reading-an-activity-log-entry)
- [What to Look For, by Phase](#what-to-look-for-by-phase)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention |
|--------|--------------|-----------|
| **Portal Activity log** | Control-plane ops | 90 days |
| **`az monitor activity-log`** | Same, scriptable | 90 days |
| **`AzureActivity`** (Sentinel) | Exported copy, KQL | Your retention |

**In SecOps (optional):** lands as Azure activity; caller → `principal.user.userid`, op → `metadata.product_event_type`, IP → `principal.ip`, resource → `target.resource.name`.

## Collect It

**Step 1 — Confirm export exists (retention > 90 days?).**

```bash
az monitor diagnostic-settings subscription list --subscription <sub-id> -o table
```

**Step 2 — Pull the window (per subscription — sweep all).**

```bash
az monitor activity-log list --subscription <sub-id> \
  --start-time 2026-07-01T00:00:00Z --end-time 2026-07-11T00:00:00Z \
  --query "[].{time:eventTimestamp,caller:caller,op:operationName.value,resource:resourceId,ip:callerIpAddress,status:status.value}" -o table
```

> **Console:** the subscription → **Activity log** → filter by *Operation*, *Caller*, *Resource*, timespan → **Export/Download**.

> 🔴 CSV export can render local time while JSON stays UTC — see the export-timezone callout in **Microsoft → 00 Overview & Terminology → Where Evidence Lives** before mixing exports into one timeline.

**Step 3 — Target a caller or resource.**

```bash
az monitor activity-log list --caller alice@contoso.com --offset 30d
az monitor activity-log list --resource-id <resourceId> --offset 30d
```

## Investigate on the Platform

The flow — five steps:

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Export set up? Which subscriptions? Note gaps (no data-plane logs) |
| 2. Scope the caller | Full timeline for the identity/app; note `callerIpAddress` |
| 3. Classify each op | Bucket into phases (table below) |
| 4. Follow the identity | User → managed identity/SP pivots; role grants → what they did next |
| 5. Cross to identity logs | Caller IP/time → Entra sign-in (interactive/SP/managed-identity) |

## Reading an Activity Log Entry

| Field | Answers | Notes |
|-------|---------|-------|
| `caller` | **Who** | UPN / SP objectId / managed identity |
| `operationName.value` | **What** | `Microsoft.<provider>/<type>/<action>` |
| `resourceId` | **On what** | sub / RG / resource |
| `callerIpAddress` | **From where** | Correlate with sign-in logs |
| `status.value` | **Did it work** | Succeeded / Failed |
| `claims` | Token claims | oid, appid, MFA state |

## What to Look For, by Phase

| Phase | Telltale operations |
|-------|---------------------|
| **Recon** | Bursts of `read`/`list` across providers; `Microsoft.Authorization/*/read` |
| **Privilege escalation** | `roleAssignments/write` (Owner/UAA); 🔴 `elevateAccess/action` |
| **Execution** | `virtualMachines/runCommand`, `runbooks`, `vmss` custom scripts |
| **Credential access** | `storageAccounts/listKeys`, `KeyVault/.../accessPolicies/write` |
| **Persistence** | New SP/managed identity + role; automation accounts; new admin |
| **Defense evasion** | `diagnosticSettings/delete`, disabling Defender, `activityLogAlerts/delete` |
| **Impact** | `resourceGroups/delete`, mass `delete`, disk/snapshot deletion |

🔴 A **burst of failed authorization** entries then a success is Azure permission enumeration finding a path.

## Hunt at Scale

KQL over `AzureActivity`:

**Role assignments (Owner/User Access Admin):**

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| project TimeGenerated, Caller, CallerIpAddress, Properties=parse_json(Properties_d), _ResourceId
```

**The GA→Azure bridge:**

```kql
AzureActivity
| where OperationNameValue has "elevateAccess"
| project TimeGenerated, Caller, CallerIpAddress, ActivityStatusValue
```

**Run Command execution:**

```kql
AzureActivity
| where OperationNameValue has "runCommand"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId
```

**Logging/Defender being disabled (evasion):**

```kql
AzureActivity
| where OperationNameValue has_any ("diagnosticSettings/delete","microsoft.security/pricings/write","activityLogAlerts/delete")
| project TimeGenerated, Caller, OperationNameValue, _ResourceId
```

> **At the very end — SecOps UDM (optional):** land role-grant / runCommand / delete events to answer "did this actor act elsewhere?" Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Undo a rogue role grant | `az role assignment delete --assignee <id> --role Owner --scope <scope>` |
| Revoke the GA→Azure bridge | Remove the root-scope User Access Administrator (from `elevateAccess`) |
| Contain a caller | Disable the user/SP; revoke tokens (Entra) |
| Stop a compromised VM/workload | Deallocate/isolate the VM; the managed identity dies with it (system-assigned) |
| Restore logging | Recreate deleted diagnostic settings; re-enable Defender |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Export Activity Log → Sentinel/Log Analytics** (2+ yrs) | Beats 90-day retention |
| **Enable resource/diagnostic logs** on storage, Key Vault, NSG | Closes the data-plane blind spot |
| **Azure Policy** denying dangerous ops / requiring logging | Guardrails an attacker can't easily dodge |
| **Alert** on `roleAssignments/write`, `elevateAccess`, `runCommand`, mass delete, `diagnosticSettings/delete` | Catch escalation/evasion/impact live |
| **PIM for Azure resources** | No standing Owners |
| **Resource locks + soft-delete/backup** | Blunt destruction |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `elevateAccess` | GA now owns all subscriptions |
| `roleAssignments/write` granting Owner to a new/guest/SP | Takeover / persistence |
| `runCommand` on a VM | Remote code execution |
| `storageAccounts/listKeys` / Key Vault access-policy self-grant | Credential/data access |
| `diagnosticSettings/delete` / Defender disabled | Defense evasion |
| `resourceGroups/delete` / mass delete | Ransomware / destruction |
| Managed identity / SP doing unusual resource ops | Compromised workload |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the log is + operations | **Activity Log → What is** |
| Who the caller is | **Microsoft → 01 Entra ID & Identities** |
| Azure resource RBAC + `elevateAccess` | **Azure → Azure RBAC** |
| A compromised workload's identity | **Azure → Managed Identities** |
| VM code execution | **Azure → Virtual Machines** |
| Managed threat findings | **Azure → Microsoft Defender for Cloud** |

## Resources

- Azure Activity Log — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log
- Activity log insights — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log-insights
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
