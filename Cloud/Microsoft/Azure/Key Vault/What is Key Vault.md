# What is Azure Key Vault?

**Azure Key Vault** is Azure's **secrets store** — it holds **secrets** (passwords, connection strings, API keys), **keys** (crypto keys), and **certificates**. Applications and managed identities read from it instead of embedding credentials in code.

For DFIR it's a **high-value target**: whoever reads the vault gets the crown-jewel credentials for everything downstream. And the crucial catch — **reading a secret is a *data-plane* action that is NOT logged unless you enabled diagnostic logging.**

## Contents

- [How It Works](#how-it-works)
- [The Two Ways In — Access Policies vs RBAC](#the-two-ways-in--access-policies-vs-rbac)
- [The Logging Catch — Secret Reads Aren't Free](#the-logging-catch--secret-reads-arent-free)
- [How Attackers Reach a Vault](#how-attackers-reach-a-vault)
- [Evidence Key Vault Produces](#evidence-key-vault-produces)
- [How to Identify Key Vault Activity](#how-to-identify-key-vault-activity)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A vault stores secrets/keys/certs. A principal (user, app, or **managed identity**) with permission calls the vault's data plane (`https://<vault>.vault.azure.net`) to read them.

```
Principal → (has access via RBAC or access policy) → GET https://<vault>.vault.azure.net/secrets/<name>
```

## The Two Ways In — Access Policies vs RBAC

🔴 A vault uses **one of two** permission models — know which, because they log and grant differently:

| Model | How access is granted | Where changes log |
|-------|----------------------|-------------------|
| **Access policies** (legacy) | Per-principal lists of allowed operations on the vault | Activity Log: `vaults/accessPolicies/write` |
| **Azure RBAC** (recommended) | Data roles like *Key Vault Secrets User/Administrator* | Activity Log: `roleAssignments/write` |

> 🔴 An attacker granting **themselves** an access policy (`accessPolicies/write`) or a **Key Vault Secrets User** role is the "give me the keys" move — a control-plane event you *can* see even when the reads aren't logged. Watch it.

## The Logging Catch — Secret Reads Aren't Free

The most important Key Vault DFIR fact:

| Action | Plane | Logged by default? |
|--------|-------|--------------------|
| Grant access (policy/role) | Control | ✅ Activity Log |
| Change vault config | Control | ✅ Activity Log |
| **Read a secret** (`SecretGet`) | **Data** | 🔴 **NO** — needs diagnostic logging |

> 🔴 Without **Key Vault diagnostic logging** (`AuditEvent` → Log Analytics) enabled, you can see the attacker *granted themselves access* but **not which secrets they read**. Enable it on every vault — it's the only way to answer "what did they take?"

## How Attackers Reach a Vault

| Path | How |
|------|-----|
| **Stolen managed identity** | Compromised VM/app whose identity has vault access → read secrets |
| **Self-granted access** | Owner/Contributor grants themselves a data role / access policy |
| **Leaked app credential** | An app with vault access is compromised |
| **Network exposure** | Vault reachable from the internet (no firewall/Private Endpoint) |

> 🔴 Key Vault is usually **step 2** of an intrusion: get a foothold (VM/app/identity), then loot the vault for the credentials that unlock databases, storage, and other systems. Whatever's in the vault is now compromised — **rotate it all.**

## Evidence Key Vault Produces

| Evidence | Where | Needs |
|----------|-------|-------|
| Access grants / config changes | Activity Log | Default on |
| **Secret/key reads** | `AzureDiagnostics` / `AKVAuditLogs` | 🔴 Diagnostic logging |
| Current access model + policies/roles | Portal / CLI | — |
| Defender for Key Vault alerts | Defender for Cloud | If enabled |

## How to Identify Key Vault Activity

- **Resource ID:** `.../providers/Microsoft.KeyVault/vaults/<name>`.
- **Data-plane URL:** `https://<vault>.vault.azure.net/`.
- **Activity Log:** `Microsoft.KeyVault/vaults/*`.
- **Data-plane logs:** `AzureDiagnostics | where ResourceType == "VAULTS"` (or `AKVAuditLogs`).

## Common Operations You Will See

| Operation | Plane | 🔴 Watch |
|-----------|-------|---------|
| `vaults/accessPolicies/write` | Control | Self-granting access |
| `roleAssignments/write` (KV data role) | Control | Self-granting access |
| `SecretGet` / `SecretList` | Data | 🔴 Reading secrets (if logged) |
| `KeyGet` / `Decrypt` / `Sign` | Data | Key use |
| `vaults/write` (networkAcls) | Control | Opening the vault to the internet |
| `vaults/delete` / purge | Control | Destruction |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Key Vault | Secrets Manager / KMS | Secret Manager / Cloud KMS |
| SecretGet | `GetSecretValue` | `AccessSecretVersion` |
| Access policy / KV RBAC | Resource policy / IAM | IAM binding |
| Diagnostic AuditEvent | CloudTrail data events | Data Access logs |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Vault** | The container for secrets/keys/certs |
| **Secret** | A stored credential/string |
| **Key** | A crypto key (often non-exportable) |
| **Access policy** | Legacy per-principal permission list |
| **KV RBAC data role** | Azure-RBAC way to grant vault access |
| **AuditEvent** | The diagnostic log category for data-plane |
| **Private Endpoint** | Private network access to the vault |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating vault access | **Key Vault → for DFIR** |
| Grants (control plane) | **Azure → Activity Log** · **Azure RBAC** |
| The identity that read it | **Azure → Managed Identities** · **Microsoft → 01 Identities** |
| A stolen-identity chain | **Azure → Playbooks → Managed Identity Theft via SSRF** |

## Resources

- Key Vault overview — https://learn.microsoft.com/azure/key-vault/general/overview
- Key Vault logging — https://learn.microsoft.com/azure/key-vault/general/logging
- RBAC vs access policies — https://learn.microsoft.com/azure/key-vault/general/rbac-access-policy
- Defender for Key Vault — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-key-vault-introduction
