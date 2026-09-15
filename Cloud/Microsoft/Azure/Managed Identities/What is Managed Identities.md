# What is Managed Identities?

A **managed identity** is an identity that **Azure creates and manages for a resource** — a VM, Function, App Service, Logic App, or AKS pod — so the resource's code can call Azure and Graph APIs **without a stored secret**. Azure handles the credentials; you never see them.

For DFIR this is one of the most important concepts in Azure: it's the **exact analog of the AWS instance role / IMDS problem.** Compromise the resource, and you can steal its token and act as it — no password, no MFA.

## Contents

- [How It Works](#how-it-works)
- [System-Assigned vs User-Assigned](#system-assigned-vs-user-assigned)
- [How a Resource Gets a Token — IMDS](#how-a-resource-gets-a-token--imds)
- [Why This Is the SSRF / RCE Prize](#why-this-is-the-ssrf--rce-prize)
- [How a Managed Identity Appears in Logs](#how-a-managed-identity-appears-in-logs)
- [How to Identify Managed Identities](#how-to-identify-managed-identities)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A managed identity is a **special kind of service principal** in Entra, tied to an Azure resource. Code on the resource asks Azure's local metadata endpoint for a **token**, then calls APIs with it. Azure rotates the underlying credential automatically.

```
Resource (VM/Function/AKS) → asks IMDS for a token → gets an Entra access token
                           → calls Azure ARM / Key Vault / Storage / Graph with it
```

The identity's **permissions** are whatever **Azure RBAC roles** (or Graph app permissions) you granted it.

## System-Assigned vs User-Assigned

| | **System-assigned** | **User-assigned** |
|-|---------------------|-------------------|
| Lifecycle | Created with the resource; **deleted with it** | Standalone; **outlives** any one resource |
| Sharing | 1:1 — one resource only | Attachable to **many** resources |
| 🔴 Risk | Compromise the resource → its token | 🔴 One identity shared across many resources → **one compromise reaches all their rights** |
| In Entra | An SP that appears/disappears with the resource | A persistent SP object |

> 🔴 A widely-shared **user-assigned** identity with broad rights is a big blast radius: compromise *any* resource it's attached to and you get the whole identity's access.

## How a Resource Gets a Token — IMDS

The mechanism is the **Instance Metadata Service (IMDS)** at the link-local address **`169.254.169.254`** — the same magic IP as AWS. Code requests:

```
GET http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
Metadata: true
```

…and gets an Entra **access token** for the managed identity. No secret is stored on disk; the token is fetched on demand.

> 🔴 Anything that can make that HTTP request from the resource — the app, a script, **an SSRF vulnerability**, or an attacker with **RCE** — can obtain the token. This is the crux of managed-identity theft.

## Why This Is the SSRF / RCE Prize

Identical to the AWS IMDS/SSRF story:

| Attack | Result |
|--------|--------|
| **SSRF** in a web app on the VM | Attacker makes the app fetch the IMDS token → gets the managed identity's access |
| **RCE / webshell** on the resource | Attacker runs the IMDS request directly |
| **AKS pod → node IMDS** | A pod reaching the node's IMDS steals the **node's** managed identity (often broad) |

Once they hold the token, the attacker has whatever the identity's **Azure RBAC roles** allow — read Key Vault secrets, list storage keys, create resources, even assign roles if it's over-permissioned.

> 🔴 **Investigate the identity's role assignments** the moment you suspect theft — that *is* the blast radius. And treat the **resource as compromised.** See **Azure → Playbooks → Managed Identity Theft via SSRF**.

## How a Managed Identity Appears in Logs

| Log | What you see |
|-----|--------------|
| **Managed-identity sign-in log** (`AADManagedIdentitySignInLogs`) | The identity getting a token — resource it accessed, but 🔴 **not a source IP** you can always trust |
| **Activity Log** | The managed identity as `caller` doing resource operations |
| **Key Vault / Storage diagnostic logs** | The identity reading secrets/blobs (if enabled) |

> 🔴 The tricky part: a stolen managed-identity token used *from the resource's own network* looks normal. The tells are **unusual actions** (a web-app identity suddenly listing all storage keys or assigning roles) and correlation with an **SSRF/RCE** on the resource — not the source IP.

## How to Identify Managed Identities

- **Portal:** the resource → **Identity** blade (system/user-assigned on/off); Entra → **Enterprise applications** → filter type = *Managed Identity*.
- **CLI:** `az identity list`; `az vm identity show --name <vm> -g <rg>`.
- **Sign-in log:** the **Managed identity** tab.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Managed identity | IAM role via instance profile | Attached service account |
| IMDS `169.254.169.254` | EC2 IMDS `169.254.169.254` | GCE metadata `169.254.169.254` |
| System-assigned | Instance role | Default SA |
| User-assigned | Shared instance profile | User-managed SA |

## Common Use Cases

Your "normal" baseline:

- A VM/Function reading secrets from **Key Vault** without embedding credentials.
- An app writing to **Storage** via its identity.
- AKS workloads using **Workload Identity**.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Managed identity** | Azure-managed identity for a resource |
| **System-assigned** | Tied to one resource's lifecycle |
| **User-assigned** | Standalone, attachable to many |
| **IMDS** | Instance Metadata Service (`169.254.169.254`) |
| **Access token** | The Entra token IMDS hands out |
| **Workload Identity** | AKS's federated pod-to-identity mechanism |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating identity theft | **Managed Identities → for DFIR** |
| What the identity can reach | **Azure → Azure RBAC** |
| The control-plane actions it took | **Azure → Activity Log** |
| The resource it lives on | **Azure → Virtual Machines** · **AKS** |
| The SSRF/RCE theft scenario | **Azure → Playbooks → Managed Identity Theft via SSRF** |

## Resources

- Managed identities overview — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview
- Get a token via IMDS — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/how-to-use-vm-token
- Managed identity best practices — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations
- AKS Workload Identity — https://learn.microsoft.com/azure/aks/workload-identity-overview
