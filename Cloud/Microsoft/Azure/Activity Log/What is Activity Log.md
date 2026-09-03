# What is the Azure Activity Log?

The **Azure Activity Log** is Azure's **control-plane audit log** — it records every management operation against your resources: who created a VM, changed a network rule, assigned a role, deleted a storage account, or read a Key Vault's *config*. It answers *who did what to which Azure resource, from where, and whether it worked.*

Think of it as **CloudTrail for Azure infrastructure** — but note the split: it covers the **control plane** (managing resources), not the **data plane** (reading a blob's *contents*). That's a separate log you must enable.

## Contents

- [How It Works](#how-it-works)
- [Control Plane vs Data Plane — The Big Split](#control-plane-vs-data-plane--the-big-split)
- [Where the Log Lives and How You Query It](#where-the-log-lives-and-how-you-query-it)
- [How to Identify an Activity Log Entry](#how-to-identify-an-activity-log-entry)
- [The Eight Categories](#the-eight-categories)
- [The Fields That Carry the Investigation](#the-fields-that-carry-the-investigation)
- [The Operations That Matter Most](#the-operations-that-matter-most)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Every management action goes through **Azure Resource Manager (ARM)** — the control plane — and ARM writes an **Activity Log** entry. One entry per operation, with the caller, the resource, the operation, and the result.

```
Action (portal / az CLI / ARM API)  →  Azure Resource Manager  →  Activity Log entry
```

Two facts for a live case:

- **Retention is 90 days** in the platform. 🔴 Beyond that you need a **diagnostic setting** exporting to Log Analytics / storage / Event Hub. Confirm export early.
- It's **subscription-scoped** — each subscription has its own Activity Log. Sweep all subscriptions.

## Control Plane vs Data Plane — The Big Split

🔴 The distinction that explains most "why can't I see it?" gaps in Azure — same idea as AWS management vs data events:

| Plane | What it is | Logged where | Example |
|-------|-----------|--------------|---------|
| **Control plane** | Managing the resource | ✅ **Activity Log** (default on) | Create VM, assign role, change firewall, `elevateAccess` |
| **Data plane** | Using the resource's contents | 🔴 **Resource/diagnostic logs** (OFF by default) | Read a **blob**, retrieve a **secret**, run a **query** |

> 🔴 The classic Azure blind spot: the Activity Log shows someone changed a storage account's config (control plane) but **not which blobs they downloaded** (data plane). To see blob reads or Key Vault secret retrievals you must have **turned on diagnostic logging** for that resource. See **Azure → Storage** / **Key Vault**.

## Where the Log Lives and How You Query It

| Destination | What it is | Look-back | Query with | Best for |
|-------------|-----------|-----------|-----------|----------|
| **Azure portal → Activity log** | The built-in blade | 90 days | Filters | Fast first look |
| **`az monitor activity-log`** | CLI | 90 days | CLI queries | Scripted pulls |
| **Log Analytics / Sentinel** (`AzureActivity`) | Exported copy | Your retention | **KQL** | Hunting + long retention |
| **Storage / Event Hub** | Archived export | Your policy | Offline tooling | Cheap long archive |

> **Rule of thumb:** recent → portal/CLI. Older / hunt / correlate → `AzureActivity` in Sentinel. No export set up + incident > 90 days = 🔴 evidence gap.

## How to Identify an Activity Log Entry

- **Portal:** the subscription (or resource) → **Activity log**.
- **CLI:** `az monitor activity-log list --offset 30d`.
- **KQL:** table `AzureActivity`.
- Each entry: a `caller`, an `operationName` (like `Microsoft.Compute/virtualMachines/write`), a `resourceId`, a `callerIpAddress`, and a `status`.

## The Eight Categories

Every Activity Log entry belongs to one of eight fixed categories:

| Category | What it covers |
|----------|-----------------|
| **Administrative** | Control-plane resource operations — create/update/delete/act-on any resource, role assignments |
| **Service Health** | Microsoft-side incidents/outages affecting Azure services |
| **Resource Health** | Health state changes for your specific resources |
| **Alert** | Azure Monitor alerts firing/resolving |
| **Autoscale** | Autoscale engine scale-in/scale-out events |
| **Recommendation** | Azure Advisor recommendations |
| **Security** | Legacy Microsoft Defender for Cloud alerts (mirrored here) |
| **Policy** | Azure Policy evaluation results (compliant/non-compliant/deny) |

> 🔴 **Only `Administrative` matters for IR.** It's the control-plane record of *who did what* — every other category is operational/health telemetry, not an audit trail of actions taken. When you query or filter the Activity Log for an investigation, scope to `category eq 'Administrative'` and ignore the rest.

## The Fields That Carry the Investigation

| Field | Answers | Notes |
|-------|---------|-------|
| `caller` | **Who** | UPN, or an app/SP objectId, or a managed identity |
| `operationName` | **What** | `Microsoft.<provider>/<type>/<action>` |
| `resourceId` | **On what** | The full resource path (sub/RG/resource) |
| `callerIpAddress` | **From where** | Correlate with Entra sign-in IPs |
| `status` / `subStatus` | **Did it work** | Succeeded / Failed |
| `authorization` (evidence) | The RBAC scope/role used | Ties to a role assignment |
| `claims` | Token claims of the caller | oid / appid / MFA |

> 🔴 A `caller` that's a **managed identity or service principal** doing unusual resource actions can mean a compromised workload — cross to the **service-principal / managed-identity sign-in logs**.

## The Operations That Matter Most

| Operation | 🔴 Why |
|-----------|--------|
| `Microsoft.Authorization/roleAssignments/write` | Azure RBAC grant (Owner = takeover) |
| `Microsoft.Authorization/elevateAccess/action` | 🔴 GA → owns all subscriptions |
| `Microsoft.Compute/virtualMachines/runCommand/action` | Run code on a VM (RCE-as-a-service) |
| `Microsoft.Compute/virtualMachines/write` | New/modified VM (mining) |
| `Microsoft.KeyVault/vaults/write` / `accessPolicies/write` | Grant self access to secrets |
| `Microsoft.Storage/storageAccounts/listKeys/action` | Grab storage account keys |
| `Microsoft.Network/networkSecurityGroups/write` | Open a firewall |
| `Microsoft.Resources/subscriptions/resourceGroups/delete` | 🔴 Mass deletion (ransomware) |
| `Microsoft.Insights/diagnosticSettings/delete` | Defense evasion — killing logging |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Azure Activity Log | CloudTrail (management events) | Cloud Audit Logs (Admin Activity) |
| Diagnostic/resource logs | CloudTrail data events | Data Access logs |
| `roleAssignments/write` | `AttachRolePolicy` | `setIamPolicy` |
| `runCommand` | SSM `SendCommand` | `startupScript` / OS patch |

## Common Use Cases

Your "normal" baseline:

- **Change auditing** — who created/deleted a resource.
- **Compliance** — record of infrastructure changes.
- **Ops troubleshooting** — "what changed before the outage?"

## Key Terminology

| Term | Meaning |
|------|---------|
| **Activity Log** | The Azure control-plane audit log |
| **ARM** | Azure Resource Manager — the control plane |
| **operationName** | The `provider/type/action` of an entry |
| **Control plane** | Managing resources (logged by default) |
| **Data plane** | Using resource contents (needs diagnostic logs) |
| **Diagnostic setting** | Config that exports/enables extra logs |
| **AzureActivity** | The Sentinel/Log Analytics table |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with the Activity Log | **Activity Log → for DFIR** |
| Who the caller is | **Microsoft → 01 Entra ID & Identities** |
| Azure resource permissions | **Azure → Azure RBAC** |
| The layout (subs/RGs/mgmt groups) | **Microsoft → 00 Overview & Terminology** |
| Data-plane logs (blob/secret reads) | **Azure → Storage** · **Key Vault** |

## Resources

- Azure Activity Log — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log
- Activity log schema — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log-schema
- Control vs data plane — https://learn.microsoft.com/azure/azure-resource-manager/management/control-plane-and-data-plane
- Export the Activity Log — https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log#send-to-log-analytics-workspace
