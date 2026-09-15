# Google Cloud & Workspace Overview & Terminology

Before you investigate anything Google, you need the map: **how a Google environment is laid out, what the pieces are called, and where each piece writes its logs.**

The single most important idea: **one company = one Cloud Identity directory = one set of accounts**, and **two different clouds** — **Google Workspace** (the SaaS: Gmail, Drive, Docs, Meet) and **Google Cloud / GCP** (the infrastructure: VMs, storage, GKE) — **both trust that same directory to say who you are.** Get that triangle straight and every log makes sense.

## Contents

- [The One-Paragraph Mental Model](#the-one-paragraph-mental-model)
- [The Two Clouds: Workspace and Google Cloud](#the-two-clouds-workspace-and-google-cloud)
- [Cloud Identity Is the Identity Boundary](#cloud-identity-is-the-identity-boundary)
- [The GCP Resource Hierarchy](#the-gcp-resource-hierarchy)
- [The Two Admin Worlds — The Concept Everyone Confuses](#the-two-admin-worlds--the-concept-everyone-confuses)
- [Resource Names — How to Read Any GCP Resource](#resource-names--how-to-read-any-gcp-resource)
- [Where Evidence Lives — The Master Logs](#where-evidence-lives--the-master-logs)
- [How People and Code Reach Google](#how-people-and-code-reach-google)
- [The Shared Responsibility Model](#the-shared-responsibility-model)
- [Cross-Provider Terminology](#cross-provider-terminology)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The One-Paragraph Mental Model

A Google environment starts with a **Cloud Identity** (or **Workspace**) account — one directory of identities, tied to your **domain** (`contoso.com`). Every user, group, and service account lives there. On top of it sit **two clouds**: **Google Workspace** (Gmail, Drive, Docs, Meet, Calendar — productivity SaaS) and **Google Cloud / GCP** (an **Organization** full of projects with VMs, storage, databases — infrastructure). A person signs in **once** to their Google account and gets a **token**; that token lets them into Gmail *and* the Cloud Console. So the investigative triangle is always: **an identity (a Google account or service account) did an action against a resource (Workspace or GCP), and it was logged.** Learn those three words — *identity, resource, log* — and every Google case reads the same way.

## The Two Clouds: Workspace and Google Cloud

| Cloud | What it is | What you investigate here | Master log |
|-------|-----------|---------------------------|-----------|
| **Google Workspace** | The **SaaS productivity suite** — Gmail, Drive/Docs, Meet, Calendar, Chat | Email theft, forwarding/filters, file exfil, OAuth consent | **Workspace audit logs** (Admin, Login, Drive, Gmail, Token…) |
| **Google Cloud (GCP)** | The **infrastructure cloud** — an Organization of projects: Compute Engine, GCS, GKE, BigQuery | VM compromise, bucket exposure, service-account theft | **Cloud Audit Logs** (Admin Activity / Data Access…) |

Both are bound together by one identity layer:

| Layer | What it is |
|-------|-----------|
| **Cloud Identity** | The **free identity directory** — users, groups, security policies, MFA. The floor both clouds stand on. |
| **Google Workspace** | Cloud Identity **plus** the paid productivity apps (Gmail, Drive…). A Workspace account *is* a Cloud Identity account with apps added. |

> **The one thing to internalize:** the Google account is the *front door* to both clouds. A compromised account is a compromise of **everything** — mailbox *and* infrastructure — because the same identity opens both. This is why almost every Google investigation **starts with the Login/auth audit and Cloud Audit Logs for that principal.**

**A note on names.** "Cloud Identity" and "Workspace" both manage the same kind of account in the same **Admin console** (`admin.google.com`). The difference is licensing (does the account have Gmail/Drive?). For IR, treat the **domain** as the org's identity anchor.

## Cloud Identity Is the Identity Boundary

Your **domain + Cloud Identity account** is the top-level identity container — one directory of Google accounts for one organization.

- Identified by a **primary domain** (`contoso.com`) and a **customer ID** (e.g. `C01abc234`).
- It is the **identity boundary**: users, groups, and admin roles are scoped to it, managed in the **Admin console**.
- **One Cloud Identity/Workspace account maps to one GCP Organization** (the org node is created *from* the identity account). The identity directory and the GCP Organization are two faces of the same company.

> 🔴 On a case, the **domain / customer ID is your first anchor** for identity questions, just as the AWS account ID or Azure tenant ID anchors those clouds. **External accounts** (a `@gmail.com` consumer account, or a user from another domain granted access) are a major investigative signal — see **01 - Google Identities**.

**External and consumer accounts.** GCP IAM can grant access to **any Google identity** — including personal `@gmail.com` accounts and users in *other* domains. 🔴 An IAM binding to an external/consumer account is a classic under-watched foothold (there's no "guest" object to disable — the account lives entirely outside your directory).

## The GCP Resource Hierarchy

Google Cloud (only — Workspace doesn't use this) nests resources in a strict tree. Know it cold; it tells you **where a role applies** and **where to look**.

```
Organization            ← the root node, tied 1:1 to your Cloud Identity/Workspace domain
└── Folder               ← optional folders (can nest) grouping projects, e.g. "Production"
    └── Project          ← the core unit: billing + isolation + API enablement (has ID + number)
        └── Resource     ← a VM, GCS bucket, GKE cluster, BigQuery dataset…
```

| Layer | What it is | Why the analyst cares |
|-------|-----------|-----------------------|
| **Organization** | The root of the GCP tree, created from your Cloud Identity domain | An IAM role granted **at the org** inherits to **every project** — maximum blast radius |
| **Folder** | An optional folder grouping projects for policy/IAM at scale (can nest) | IAM/Org Policy set here **inherits down** to every project beneath it |
| **Project** | The fundamental unit: billing, isolation, API enablement; has a **project ID** (string, globally unique) + **project number** (numeric) | The normal blast-radius unit; "which project?" scopes a GCP case |
| **Resource** | The actual thing (VM, bucket, cluster) | What the attacker touched |

> **Inheritance is the key idea:** an IAM binding or Org Policy set at a higher level **flows down** to everything beneath it. An attacker who gets a broad role (e.g. **Owner** or **Editor**) at the *organization* or *folder* level owns every project under it. Always check **what level** a role grant was made at — see **GCP → Cloud IAM**.

> 🔴 **Project ID vs project number.** The **project ID** is the human-readable globally-unique string (`contoso-prod-01`); the **project number** is a numeric ID Google uses internally (and in default service-account emails and some log fields). You'll see both — learn to match them.

## The Two Admin Worlds — The Concept Everyone Confuses

This is the Google equivalent of Azure's "two RBAC worlds," and it is the **single most common point of confusion.** There are **two separate permission systems**, and an attacker can abuse either:

| | **Workspace / Cloud Identity admin** | **GCP IAM** (resource roles) |
|-|--------------------------------------|-------------------------------|
| **Governs** | The **directory + Workspace** — users, groups, Gmail, Drive, security settings, MFA | **Google Cloud resources** — projects, VMs, buckets, datasets |
| **Example roles** | **Super Admin**, User Management Admin, Groups Admin, Help Desk Admin | **Owner**, Editor, Viewer, `roles/iam.securityAdmin`, `roles/storage.admin` |
| **Scope** | The **whole domain** (some are org-unit-scoped) | Organization / folder / project / single resource |
| **Managed in** | **Admin console** (`admin.google.com`) | **Cloud Console / `gcloud` / IAM** |
| **Logged in** | **Workspace Admin audit log** | **Cloud Audit Logs — Admin Activity** (`SetIamPolicy`) |
| **The crown jewel** | 🔴 **Super Admin** — owns the entire identity + Workspace plane | 🔴 **Organization Owner / Org Admin** — owns all infrastructure |

**Two facts that trip up every responder:**

1. **Super Admin ≠ Organization Owner.** A Workspace **Super Admin** controls identity and Gmail/Drive but does **not** automatically have access to GCP resources — the two worlds are separate.
2. 🔴 **The Super-Admin → GCP pivot.** A Super Admin can **grant themselves (or anyone) the Organization Administrator IAM role** at the GCP org node — because control of the identity domain lets you manage the organization resource it's bound to. This is the Google analog of Azure's `elevateAccess`: the bridge from "identity admin" to "owns all infrastructure." 🔴 Watch for **`SetIamPolicy` at the organization level granting `roles/resourcemanager.organizationAdmin`** — a top-tier escalation. See **GCP → Cloud IAM**.

> When you read "admin" in a Google case, always ask: **admin of *what* — the directory (Workspace), or the cloud resources (GCP)?** Different worlds, different consoles, different logs.

## Resource Names — How to Read Any GCP Resource

Google's equivalent of an ARN is the **resource name** — a path that encodes the hierarchy. You'll see two forms:

```
Relative:  projects/{project-id}/zones/{zone}/instances/{name}
Full URL:  //compute.googleapis.com/projects/{project-id}/zones/{zone}/instances/{name}
                     │                    │             │            │
                     │                    │             │            └─ the resource's name
                     │                    │             └─ zone/region (or "global")
                     │                    └─ the project
                     └─ the API/service that owns the resource
```

Worked examples — memorize the shapes:

| Resource name | What it is |
|---------------|-----------|
| `//compute.googleapis.com/projects/contoso-prod/zones/us-central1-a/instances/web01` | The VM **web01** in project **contoso-prod** |
| `//storage.googleapis.com/projects/_/buckets/contoso-logs` | A **GCS bucket** (buckets are globally named, hence `_`) |
| `//cloudresourcemanager.googleapis.com/projects/contoso-prod` | The **project** resource itself |
| `//iam.googleapis.com/projects/contoso-prod/serviceAccounts/sa-app@contoso-prod.iam.gserviceaccount.com` | A **service account** |

Identities are **email addresses** (`principalEmail`), not paths — see **01 - Google Identities**.

> 🔴 The **service prefix** (`compute.googleapis.com`, `storage.googleapis.com`, `iam.googleapis.com`) tells you at a glance *what kind* of resource an audit entry touched. `iam.googleapis.com` / a `SetIamPolicy` method = a **permission change** — always read those.

## Where Evidence Lives — The Master Logs

Google splits its audit trail across the **two clouds**. Knowing which log answers which question is half the battle.

**GCP — Cloud Audit Logs** (four streams, all land in **Cloud Logging**):

| Stream | Covers | Default | Note |
|--------|--------|---------|------|
| **Admin Activity** | *Config/write actions* — create/modify/delete, `SetIamPolicy`, role grants | ✅ **Always on, free, cannot disable** | The CloudTrail-management-events equivalent |
| **Data Access** | *Data-plane reads/writes* — object reads, dataset queries | 🔴 **Off by default** (except BigQuery) — must enable per service | Can be huge; the CloudTrail-data-events equivalent |
| **System Event** | *Google-initiated* actions (e.g. automatic maintenance) | ✅ On | Non-human |
| **Policy Denied** | Requests **denied** by IAM / VPC Service Controls / org policy | ✅ On (when denials happen) | 🔴 Recon / probing shows here |

**Workspace — audit logs** (separate, in the **Admin console** / **Reports API**, one per app):

| Log | Covers |
|-----|--------|
| **Admin** | Admin-console changes (users, roles, settings) |
| **Login** | Sign-ins, MFA, suspicious-login, SAML |
| **Drive** | File create/view/download/share (Enterprise/Business+) |
| **Gmail** | Email Log Search + Gmail log events (BigQuery) |
| **Token** | OAuth authorizations to third-party apps |
| **Groups / Calendar / Chat / Meet** | Per-app activity |

> 🔴 **Retention & routing.** Cloud Audit Logs' **`_Default`** bucket keeps logs **30 days**; the **`_Required`** bucket (Admin Activity/System Event) keeps **400 days**. Workspace audit data retains **~6 months** in-console (varies by log). For anything longer, someone must have **routed logs via a sink** to **BigQuery / GCS / another project** (GCP) or **exported Workspace logs to BigQuery / Cloud Logging**. 🔴 If an incident is older than the retention window and no sink/export exists, the evidence may be **gone** — confirm routing **first**. This is the Google version of "cloud forensics is pre-decided by what you turned on."

> **Data Access logs are the sharpest gap.** By default you can prove *who changed config* (Admin Activity) but **not who read your data** (Data Access is off). Turning Data Access logging on — at least for GCS/critical services — is the difference between "we know exactly what was read" and "we assume worst case." See **GCP → Cloud Audit Logs**.

## How People and Code Reach Google

Every action arrives through one of these front doors. The tooling shows up in the **user agent / caller** and separates a human from a script.

| Access path | What it is | Tell |
|-------------|-----------|------|
| **Cloud Console** | `console.cloud.google.com` (GCP web UI) | Browser user-agent; interactive |
| **Admin console** | `admin.google.com` (Workspace/identity UI) | Browser; where Super Admin acts |
| **`gcloud` / `gsutil` / `bq`** | The Cloud SDK CLIs | `google-cloud-sdk` in `callerSuppliedUserAgent` |
| **REST APIs / client libraries** | Direct API calls (`*.googleapis.com`) | SDK/app-specific user agent |
| **Terraform / IaC** | Automated deploys | Terraform user agent; a CI service account |
| **Legacy / IMAP / POP (Gmail)** | Old mail protocols | 🔴 Can **bypass modern MFA** — a classic attack path |

> **Human vs script is a core triage question**, exactly as in AWS/Azure. An interactive browser sign-in then console clicks = a person. A burst of API calls at machine speed under a **service account** = automation (legit CI/CD or an attacker's stolen SA). See **01 - Google Identities**.

## The Shared Responsibility Model

Google splits security by service model — and it tells you **what evidence even exists**.

| Model | Google secures | You secure | You get logs for… |
|-------|----------------|-----------|-------------------|
| **SaaS (Workspace)** | The app + infra | Your **data, identities, sharing, config** | Workspace audit logs |
| **PaaS (e.g. GCS, BigQuery, Cloud Run)** | The platform | Your data, IAM, network | Admin Activity + **Data Access (if enabled)** |
| **IaaS (Compute Engine)** | Host/hypervisor | **Guest OS, apps, patching** + GCP config | Admin Activity + **guest OS logs you enable (Ops Agent)** |

> 🔴 The hard lesson, same as AWS/Azure: for a **VM**, Google gives you the control-plane (who created/started it) but the **inside of the OS is yours** — you only have guest logs if you installed the **Ops Agent**. For **GCS/BigQuery data access**, you only know "which objects/rows were read" if **Data Access logging was on**. Harden = make sure future-you has evidence.

## Cross-Provider Terminology

If you know AWS or Azure, this ports your instinct.

| Concept | Google | AWS | Microsoft |
|---------|--------|-----|-----------|
| Top of the tree | **Organization** | Organization | Tenant / Management Group |
| Grouping folder | **Folder** | Organizational Unit (OU) | Management Group |
| Billing/isolation unit | **Project** | Account | Subscription (Azure) |
| Identity directory | **Cloud Identity** | IAM (per account) | Entra ID (per tenant) |
| Human identity | **Google user** | IAM user | User / guest |
| App/workload identity | **Service account** | IAM role / instance profile | Service principal / managed identity |
| Long-term key | **SA key (JSON)** | Access key (`AKIA`) | Client secret / certificate |
| Temp credentials | **Short-lived SA token** (impersonation) | STS assumed-role (`ASIA`) | OAuth access token |
| Federation | **Workload Identity Federation** | `AssumeRoleWithWebIdentity` (OIDC) | Federated credential |
| Resource guardrail | **Organization Policy + IAM** | SCP + IAM | Azure Policy + RBAC |
| Infra audit log | **Cloud Audit Logs (Admin Activity)** | CloudTrail | Azure Activity Log |
| Data-access log | **Data Access logs** | CloudTrail data events | Diagnostic / resource logs |
| Identity/SaaS audit log | **Workspace audit logs** | (CloudTrail IAM) / — | Entra logs / Unified Audit Log |
| Network flow log | **VPC Flow Logs** | VPC Flow Logs | NSG Flow Logs |
| Managed threat detection | **Security Command Center** | GuardDuty | Defender for Cloud / XDR |
| Object storage | **Cloud Storage (GCS)** | S3 | Blob Storage |
| Virtual machine | **Compute Engine** | EC2 | Azure VM |
| Serverless function | **Cloud Functions** | Lambda | Azure Functions |
| Managed Kubernetes | **GKE** | EKS | AKS |
| Resource name | **Resource name** | ARN | Resource ID |

> Full detail lives in **Cloud → 06 Cloud Service Equivalents**. This is the quick-glance version.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Cloud Identity** | The free identity directory (users, groups); the floor both clouds stand on |
| **Google Workspace** | Cloud Identity + productivity apps (Gmail, Drive, Meet…) |
| **Google Cloud / GCP** | The infrastructure cloud (Organization of projects) |
| **Organization** | The root of the GCP resource tree, tied to your domain |
| **Folder** | An optional folder grouping projects (can nest) |
| **Project** | The core GCP unit: billing + isolation + APIs (has ID + number) |
| **Project ID / number** | Globally-unique string / internal numeric identifier for a project |
| **Resource name** | The full path identifying a GCP resource |
| **Super Admin** | The most powerful Workspace/Cloud Identity role (🔴 owns identity) |
| **Organization Admin** | The most powerful GCP IAM role (🔴 owns infrastructure) |
| **Service account (SA)** | An app/workload identity (`…@…iam.gserviceaccount.com`) — see 01 |
| **Cloud Audit Logs** | The GCP master audit logs (Admin Activity / Data Access / System Event / Policy Denied) |
| **Workspace audit logs** | The per-app SaaS logs (Admin, Login, Drive, Gmail, Token…) |
| **Cloud Logging** | Where GCP logs land; routes via **sinks** to BigQuery/GCS/Pub-Sub |
| **Admin console** | `admin.google.com` — where Workspace/identity is managed |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Who the identities are (user vs SA vs SA-key vs impersonation vs federation) | **Google → 01 Google Identities** |
| Where to start a case + the triage flow | **Google → 02 Investigating Google (start here)** |
| The GCP master audit log | **GCP → Cloud Audit Logs** |
| Workspace admin/login evidence | **Workspace → Admin Audit Log** · **Login & Auth Audit** |
| IAM, roles, and the two-worlds pivot in depth | **GCP → Cloud IAM** |
| The equivalents in other clouds | **Cloud → 06 Cloud Service Equivalents** |

## Resources

- Google Cloud resource hierarchy — https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy
- Cloud Identity overview — https://cloud.google.com/identity/docs/overview
- Cloud Audit Logs overview — https://cloud.google.com/logging/docs/audit
- Workspace audit logs & reports — https://support.google.com/a/answer/9725452
- Log retention & routing (sinks) — https://cloud.google.com/logging/docs/routing/overview
- Resource names — https://cloud.google.com/apis/design/resource_names
- IAM overview — https://cloud.google.com/iam/docs/overview
