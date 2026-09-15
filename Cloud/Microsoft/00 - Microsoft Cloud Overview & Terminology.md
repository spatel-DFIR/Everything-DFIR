# Microsoft Cloud Overview & Terminology

Before you investigate anything Microsoft, you need the map: **how a Microsoft environment is laid out, what the pieces are called, and where each piece writes its logs.**

The single most important idea: **one company = one tenant = one Entra ID directory**, and **two different clouds** — **Microsoft 365** (the SaaS: email, files, chat) and **Azure** (the infrastructure: VMs, storage, networks) — **both trust that same directory to say who you are.** Get that triangle straight and every log makes sense.

## Contents

- [The One-Paragraph Mental Model](#the-one-paragraph-mental-model)
- [The Three Worlds: Entra ID, M365, Azure](#the-three-worlds-entra-id-m365-azure)
- [The Tenant Is the Identity Boundary](#the-tenant-is-the-identity-boundary)
- [The Azure Resource Hierarchy](#the-azure-resource-hierarchy)
- [The Two RBAC Worlds — The Concept Everyone Confuses](#the-two-rbac-worlds--the-concept-everyone-confuses)
- [Resource IDs — How to Read Any Azure Resource Name](#resource-ids--how-to-read-any-azure-resource-name)
- [Where Evidence Lives — The Three Master Logs](#where-evidence-lives--the-three-master-logs)
- [How People and Code Reach Microsoft Cloud](#how-people-and-code-reach-microsoft-cloud)
- [The Shared Responsibility Model](#the-shared-responsibility-model)
- [Cross-Provider Terminology](#cross-provider-terminology)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The One-Paragraph Mental Model

A Microsoft environment is a **tenant** — one directory of identities, run by **Entra ID** (formerly Azure AD). Every user, guest, app, and service in the company lives in that one directory. On top of it sit **two clouds**: **Microsoft 365** (Exchange, SharePoint, OneDrive, Teams — productivity SaaS) and **Azure** (subscriptions full of VMs, storage, databases — infrastructure). A person signs in **once** to Entra and gets a **token**; that token lets them into Outlook *and* the Azure portal. So the investigative triangle is always: **an identity (Entra) did an action against a resource (M365 or Azure), and it was logged (in one of three master logs).** Learn those three words — *identity, resource, log* — and every Microsoft case reads the same way.

## The Three Worlds: Entra ID, M365, Azure

| World | What it is | What you investigate here | Master log |
|-------|-----------|---------------------------|-----------|
| **Entra ID** | The **identity directory** — every user, guest, app, sign-in, MFA, role | *Who* signed in, from where, was MFA satisfied, who got a role | **Entra sign-in + audit logs** |
| **Microsoft 365** | The **SaaS productivity suite** — Exchange Online, SharePoint, OneDrive, Teams | Email theft, inbox rules, file exfil, OAuth consent | **Unified Audit Log (UAL)** |
| **Azure** | The **infrastructure cloud** — subscriptions, VMs, storage, Key Vault, AKS | VM compromise, storage exposure, managed-identity theft | **Azure Activity Log** (+ resource logs) |

> **The one thing to internalize:** Entra is the *front door* to both other worlds. A compromised Entra identity is a compromise of **everything** — mailbox *and* infrastructure — because the same token opens both. This is why almost every Microsoft investigation **starts in Entra sign-in logs.**

**A note on names.** Entra ID = the product formerly called **Azure Active Directory (Azure AD / AAD)**. You will still see "Azure AD" everywhere — in older docs, log field names (`aad`), and PowerShell modules. Treat them as the same thing.

## The Tenant Is the Identity Boundary

A **tenant** is the top-level container — one dedicated Entra ID directory instance for one organization.

- Identified by a **tenant ID** (a GUID, e.g. `72f988bf-86f1-41af-91ab-2d7cd011db47`) and one or more **domains** (`contoso.onmicrosoft.com`, `contoso.com`).
- It is the **identity and security boundary**: users, groups, apps, and roles are scoped to it.
- **One tenant can own many Azure subscriptions and one M365 org.** The tenant is *not* the billing unit — that's the subscription (Azure) or the licensing (M365).

> 🔴 On a case, the **tenant ID is your first anchor** for identity questions, just as the AWS account ID anchors an AWS case. **Cross-tenant** activity (a guest from another tenant, a B2B invite, an app from a foreign tenant) is a major investigative signal — see **01 - Entra ID & Identities**.

**Guests and B2B.** A tenant can contain **guest users** — identities that actually live in *another* tenant but were invited in (external partners, contractors). A guest's home is elsewhere; you'll see `#EXT#` in their UPN. 🔴 Guest accounts are a common, under-watched foothold.

## The Azure Resource Hierarchy

Azure (only — M365 doesn't use this) nests resources in a strict tree. Know it cold; it tells you **where a role applies** and **where to look**.

```
Tenant (one Entra directory)
└── Management Group        ← optional folder grouping subscriptions (e.g. "Production")
    └── Subscription        ← the billing + isolation unit (has its own ID/GUID)
        └── Resource Group   ← a folder of related resources (deployed/deleted together)
            └── Resource     ← a VM, storage account, key vault, AKS cluster…
```

| Layer | What it is | Why the analyst cares |
|-------|-----------|-----------------------|
| **Management group** | A folder grouping subscriptions for policy/RBAC at scale | Azure RBAC or Azure Policy assigned here **inherits down to every subscription** — huge blast radius |
| **Subscription** | The billing + isolation boundary; identified by a **subscription ID** (GUID) | The normal blast-radius unit; "which subscription?" scopes an Azure case |
| **Resource group (RG)** | A logical folder; resources in it share a lifecycle | Deleting an RG deletes everything in it 🔴 (impact/ransomware) |
| **Resource** | The actual thing (VM, storage account, key vault) | What the attacker touched |

> **Inheritance is the key idea:** an RBAC role or policy assigned at a higher level **flows down** to everything beneath it. An attacker who gets **Owner** at the *management-group* or *subscription* level owns every resource under it. Always check *what scope* a role grant was made at.

## The Two RBAC Worlds — The Concept Everyone Confuses

This is the Microsoft equivalent of the EKS "two identity worlds," and it is the **single most common point of confusion.** There are **two completely separate permission systems**, and an attacker can abuse either:

| | **Entra roles** (directory roles) | **Azure RBAC** (resource roles) |
|-|-----------------------------------|----------------------------------|
| **Governs** | The **directory + M365** — users, groups, apps, Exchange, SharePoint, Conditional Access | **Azure resources** — VMs, storage, key vaults, subscriptions |
| **Example roles** | **Global Administrator**, Privileged Role Admin, User Admin, Exchange Admin | **Owner**, Contributor, Reader, Storage Blob Data Contributor |
| **Scope** | The **whole tenant** (some are admin-unit-scoped) | Management group / subscription / RG / single resource |
| **Assigned via** | Entra roles / **PIM** | Azure **role assignments** |
| **Logged in** | **Entra audit log** (`Add member to role`) | **Azure Activity Log** (`Microsoft.Authorization/roleAssignments/write`) |
| **The crown jewel** | 🔴 **Global Administrator** — owns the entire identity plane | 🔴 **Owner at management-group/root** — owns all infrastructure |

**Two facts that trip up every responder:**

1. **Global Administrator ≠ Azure Owner.** A Global Admin controls identity and M365 but does **not** automatically have access to Azure resources — *until* they use the one switch below.
2. 🔴 **The "elevate access" pivot.** A Global Admin can flip a tenant toggle (`Microsoft.Authorization/elevateAccess`) that grants themselves **User Access Administrator over every Azure subscription**. This is the bridge from "identity admin" to "owns all infrastructure." **Watch for `elevateAccess` in the Activity Log** — it's a top-tier red flag and a classic escalation step. See **Azure → Azure RBAC**.

> When you read "admin" in a Microsoft case, always ask: **admin of *what* — the directory, or the resources?** They are different worlds with different logs.

## Resource IDs — How to Read Any Azure Resource Name

Azure's equivalent of an ARN is the **resource ID** — a URL-like path that encodes the entire hierarchy. Learn the shape once:

```
/subscriptions/{sub-id}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
     │              │           │              │           │        │
     │              │           │              │           │        └─ the resource's name
     │              │           │              │           └─ virtualMachines, storageAccounts…
     │              │           │              └─ Microsoft.Compute, Microsoft.Storage…
     │              │           └─ the resource group
     │              └─ the subscription GUID
     └─ always starts here
```

Worked examples — memorize the shapes:

| Resource ID | What it is |
|-------------|-----------|
| `/subscriptions/<sub>/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/web01` | The VM **web01** in RG **prod** |
| `/subscriptions/<sub>/resourceGroups/data/providers/Microsoft.Storage/storageAccounts/contosologs` | A storage account |
| `/subscriptions/<sub>/resourceGroups/sec/providers/Microsoft.KeyVault/vaults/contoso-kv` | A Key Vault |
| `/providers/Microsoft.Management/managementGroups/Production` | A management group (tenant-level, no subscription) |

Identities, by contrast, are **GUIDs** (object IDs), not ARNs — see **01 - Entra ID & Identities**.

> 🔴 The resource-provider prefix (`Microsoft.Compute`, `Microsoft.Storage`, `Microsoft.KeyVault`) tells you at a glance *what kind* of resource an Activity Log entry touched. `Microsoft.Authorization` = a permission change — always read those.

## Where Evidence Lives — The Three Master Logs

Unlike AWS's single CloudTrail, Microsoft splits its audit trail across **three** master logs. Knowing which one answers which question is half the battle:

| Master log | Covers | Where you read it | Default retention |
|-----------|--------|-------------------|-------------------|
| **Entra sign-in logs** | *Authentications* — every sign-in, MFA result, Conditional Access decision, token issuance | Entra portal · Graph API · Log Analytics | **30 days** (7 for some SKUs) 🔴 short |
| **Entra audit logs** | *Directory changes* — user/group/app/role edits, consent grants | Entra portal · Graph API · Log Analytics | **30 days** 🔴 short |
| **Unified Audit Log (UAL)** | *M365 activity* — Exchange, SharePoint/OneDrive, Teams, plus Entra events too | Purview portal · `Search-UnifiedAuditLog` · Graph | **180 days** (E3) / **1 yr** (E5) |
| **Azure Activity Log** | *Azure control-plane* — resource create/modify/delete, role assignments | Azure portal · `az monitor activity-log` | **90 days** 🔴 short |
| **Azure resource / diagnostic logs** | *Data-plane* — storage reads, Key Vault access, NSG flow (must be **turned on**) | Log Analytics · storage · Event Hub | Only if configured |

> 🔴 **The retention trap.** Entra and Activity logs keep only **30 / 90 days** by default — far shorter than CloudTrail's typical years. If an incident is older than that and nobody exported logs to **Log Analytics / Sentinel / a storage account**, the evidence may be **gone**. Confirm the retention/export setup *first*. This is the Microsoft version of "cloud forensics is pre-decided by what you turned on."

> The UAL and Entra logs **overlap** (some Entra events appear in both). Prefer the UAL for long look-back on identity+M365; use the native Entra sign-in log for the richest authentication detail. See **02 - Investigating Microsoft**.

> 🔴 **The UTC-vs-local-time export trap.** Native Entra and Activity Log timestamps are always **UTC**. But the **portal's CSV export** can render those same timestamps in the **viewer's local time zone**, while the **JSON export stays UTC**. If you build a timeline by mixing a CSV pull from one analyst's machine with a JSON pull from another's — or with KQL output (also UTC) — the CSV rows can silently drift by whole hours. Always check (and normalize) the export format's time zone before merging timelines; when in doubt, re-export as JSON or query via KQL/Graph instead of trusting a CSV's displayed time.

## How People and Code Reach Microsoft Cloud

Every action arrives through one of these front doors. The tooling shows up in the **user agent / client app** field and separates a human from a script.

| Access path | What it is | Tell |
|-------------|-----------|------|
| **Web portals** | `portal.azure.com`, `admin.microsoft.com`, `entra.microsoft.com`, Outlook/Teams web | Browser user-agent; interactive sign-in |
| **Azure CLI** | The `az` command | `AzureCLI` in user agent |
| **Azure PowerShell** | `Az` module | `Az.*` / PowerShell user agent |
| **Microsoft Graph** | The unified REST API for identity + M365 (`graph.microsoft.com`) | Graph SDK / app-specific user agent |
| **Graph PowerShell / Exchange Online PowerShell** | `Microsoft.Graph`, `ExchangeOnlineManagement` modules | PowerShell user agents 🔴 common attacker tooling |
| **Legacy / EWS / IMAP** | Old mail protocols | 🔴 Legacy auth **bypasses MFA** — a classic attack path |

> **Human vs script is a core triage question**, exactly as in AWS. An interactive browser sign-in then portal clicks = a person. A burst of Graph calls at machine speed = automation (legit CI/CD or an attacker's script). See **Entra → Sign-in Logs**.

## The Shared Responsibility Model

Microsoft splits security by service model — and it tells you **what evidence even exists**.

| Model | Microsoft secures | You secure | You get logs for… |
|-------|-------------------|-----------|-------------------|
| **SaaS (M365)** | The app + infra | Your **data, identities, sharing, config** | UAL, Entra logs |
| **PaaS (e.g. Storage, Key Vault)** | The platform | Your data, access policy, network | Activity + resource logs (if enabled) |
| **IaaS (VMs)** | Host/hypervisor | **Guest OS, apps, patching** + Azure config | Activity log + **guest OS logs you enable** |

> 🔴 The hard lesson, same as AWS: for a **VM**, Microsoft gives you the control-plane (who created/started it) but the **inside of the OS is yours** — you only have guest logs if you deployed the agent. For **storage/Key Vault data access**, you only know "which blobs/secrets were read" if **diagnostic logging was on**. Harden = make sure future-you has evidence.

## Cross-Provider Terminology

If you know AWS, this ports your instinct.

| Concept | Microsoft | AWS | Google Cloud |
|---------|-----------|-----|--------------|
| Top of the tree | **Tenant** / Management Group | Organization | Organization |
| Grouping folder | **Management Group** | Organizational Unit (OU) | Folder |
| Billing/isolation unit | **Subscription** (Azure) | Account | Project |
| Identity directory | **Entra ID** (per tenant) | IAM (per account) | Cloud Identity + IAM |
| Human identity | **User / guest** | IAM user | Google user |
| App/workload identity | **Service principal / managed identity** | IAM role / instance profile | Service account |
| Temp credentials | **OAuth access token** | STS assumed-role (`ASIA`) | Short-lived SA token |
| Directory guardrail | **Entra roles / admin units** | (IAM) | (IAM) |
| Resource guardrail | **Azure Policy / RBAC** | SCP + IAM | Org Policy + IAM |
| Identity audit log | **Entra audit + sign-in logs** | CloudTrail (IAM events) | Cloud Audit Logs |
| SaaS audit log | **Unified Audit Log** | — | Workspace audit logs |
| Infra audit log | **Azure Activity Log** | CloudTrail | Cloud Audit Logs (Admin Activity) |
| Data-access log | **Diagnostic / resource logs** | CloudTrail data events | Data Access logs |
| Network flow log | **NSG Flow Logs** | VPC Flow Logs | VPC Flow Logs |
| Managed threat detection | **Defender for Cloud / XDR** | GuardDuty | Security Command Center |
| Object storage | **Blob Storage** | S3 | Cloud Storage |
| Virtual machine | **Azure VM** | EC2 | Compute Engine |
| Serverless function | **Azure Functions** | Lambda | Cloud Functions |
| Managed Kubernetes | **AKS** | EKS | GKE |
| Resource name | **Resource ID** | ARN | Resource name |

> Full detail lives in **Cloud → 06 Cloud Service Equivalents**. This is the quick-glance version.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Tenant** | One organization's dedicated Entra directory; the identity boundary |
| **Tenant ID** | GUID identifying the tenant |
| **Entra ID** | The identity directory (formerly Azure AD / AAD) |
| **Microsoft 365 (M365)** | The SaaS suite: Exchange, SharePoint, OneDrive, Teams |
| **Azure** | The infrastructure cloud: subscriptions, VMs, storage… |
| **Management group** | A folder grouping subscriptions for policy/RBAC |
| **Subscription** | Azure billing + isolation boundary (has a GUID) |
| **Resource group (RG)** | A folder of related Azure resources sharing a lifecycle |
| **Resource ID** | The full path identifying an Azure resource |
| **Entra role** | Directory/M365 permission (e.g. Global Administrator) |
| **Azure RBAC role** | Azure-resource permission (e.g. Owner) |
| **Global Administrator** | The most powerful Entra role (🔴 owns the identity plane) |
| **Guest / B2B user** | An external identity invited into the tenant (`#EXT#`) |
| **Service principal** | An app's identity in the tenant (see 01) |
| **Managed identity** | An Azure-managed identity for a resource (see 01) |
| **Unified Audit Log (UAL)** | The M365 master audit log |
| **Activity Log** | The Azure control-plane master log |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Who the identities are (user vs guest vs SP vs managed identity, and tokens) | **Microsoft → 01 Entra ID & Identities** |
| Where to start a case + the triage flow | **Microsoft → 02 Investigating Microsoft (start here)** |
| The M365 master audit log | **M365 → Unified Audit Log** |
| The Azure control-plane log | **Azure → Activity Log** |
| The two RBAC worlds in depth | **Azure → Azure RBAC** · **Entra → Roles & PIM** |
| The equivalents in other clouds | **Cloud → 06 Cloud Service Equivalents** |

## Resources

- What is Entra ID — https://learn.microsoft.com/entra/fundamentals/whatis
- Azure management groups / subscriptions / resource groups — https://learn.microsoft.com/azure/governance/management-groups/overview
- Azure resource ID format — https://learn.microsoft.com/azure/azure-resource-manager/management/resource-name-rules
- Entra roles vs Azure roles — https://learn.microsoft.com/entra/identity/role-based-access-control/custom-overview
- Elevate access to manage all subscriptions — https://learn.microsoft.com/azure/role-based-access-control/elevate-access-global-admin
- Audit log retention / where logs live — https://learn.microsoft.com/purview/audit-log-retention-policies
