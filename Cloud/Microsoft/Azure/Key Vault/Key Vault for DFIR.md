# Azure Key Vault for DFIR

When an attacker reaches a Key Vault, the credentials inside unlock everything downstream. This note is how you determine **who got access, what they read (if you can), and what you must now rotate.**

New to the service? Read **What is Azure Key Vault** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [What Did They Read?](#what-did-they-read)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Needs |
|--------|--------------|-------|
| **Activity Log** | Access grants, config/network changes | Default on |
| **Diagnostic AuditEvent** (`AKVAuditLogs`/`AzureDiagnostics`) | 🔴 Secret/key **reads** | Diagnostic logging |
| **Current access** | Policies/roles, network rules | Portal / CLI |
| **Defender for Key Vault** | Anomalous-access alerts | If enabled |

## Collect It

**Who can access the vault (and how it grants):**

```bash
az keyvault show -n <vault> --query "{model:properties.enableRbacAuthorization,net:properties.networkAcls.defaultAction}"
# If access policies:
az keyvault show -n <vault> --query "properties.accessPolicies[].{oid:objectId,secrets:permissions.secrets}"
# If RBAC:
az role assignment list --scope <vault-resource-id> --query "[].{p:principalName,role:roleDefinitionName}" -o table
```

**Access-grant events (control plane):**

```bash
az monitor activity-log list --resource-id <vault-resource-id> --offset 30d \
  --query "[?contains(operationName.value,'accessPolicies/write') || contains(operationName.value,'roleAssignments/write')]"
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm the access model | RBAC or access policies? Who was granted, when, by whom |
| 2. Find the self-grant | `accessPolicies/write` or KV data-role assignment by a suspect |
| 3. Identify the reader | A user, an app, or a **stolen managed identity**? |
| 4. Prove the reads | Diagnostic `SecretGet` logs — if enabled (below) |
| 5. Rotate everything reachable | Assume every secret they could reach is compromised |

## What Did They Read?

| If you had… | You can determine |
|-------------|-------------------|
| **Diagnostic AuditEvent logging** | Exactly which secrets/keys were read, by which identity, from where 🎯 |
| Only Activity Log | Who *gained access* but 🔴 **not** what they read — assume all reachable secrets taken |

```kql
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName in ("SecretGet","KeyGet","CertificateGet","SecretList")
| project TimeGenerated, identity_claim_upn_s, CallerIPAddress, id_s, OperationName
```

## Hunt at Scale

**Self-granted vault access:**

```kql
AzureActivity
| where OperationNameValue has_any ("vaults/accessPolicies/write","roleAssignments/write") and _ResourceId has "Microsoft.KeyVault"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId
```

**Bulk secret reads (looting):**

```kql
AzureDiagnostics
| where ResourceType == "VAULTS" and OperationName == "SecretGet"
| summarize secrets=dcount(id_s) by identity_claim_upn_s, CallerIPAddress, bin(TimeGenerated, 1h)
| where secrets > 10
```

## Respond

| Goal | Action |
|------|--------|
| 🔴 Rotate the secrets | **Rotate every secret/key/cert the attacker could reach** — this is the point |
| Remove the access | Delete the rogue access policy / KV role assignment |
| Contain the reader | Disable the user/SP; treat a compromised managed identity's resource as owned |
| Lock the network | `networkAcls.defaultAction=Deny` + Private Endpoint |
| Preserve | Capture grants + any read logs before changes |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable diagnostic AuditEvent logging** → Sentinel | The only way to prove reads |
| **Use KV RBAC** (not access policies) + least privilege | Cleaner, auditable grants |
| **Private Endpoint / firewall** (`Deny` default) | No internet exposure |
| **Purge protection + soft delete** | Blocks destruction |
| **Defender for Key Vault** | Anomalous-access alerts |
| **Alert** on access grants + bulk reads | Catch looting |
| **Rotate secrets regularly**; prefer references over copies | Limits leak value |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Self-granted access policy / KV role | "Give me the keys" move |
| Bulk `SecretGet` from a new IP/identity | Vault being looted |
| Managed identity reading many secrets after VM compromise | Token-theft pivot |
| Network rules opened to the internet | Exposure |
| `vaults/delete` / purge | Destruction |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Key Vault is + the logging catch | **Key Vault → What is** |
| The grant (control plane) | **Azure → Activity Log** · **Azure RBAC** |
| The identity that read it | **Azure → Managed Identities** |
| A stolen-identity chain | **Azure → Playbooks → Managed Identity Theft via SSRF** |

## Resources

- Key Vault logging — https://learn.microsoft.com/azure/key-vault/general/logging
- Secure your vault — https://learn.microsoft.com/azure/key-vault/general/security-features
- MITRE ATT&CK: T1555.006 Cloud Secrets Management Stores — https://attack.mitre.org/techniques/T1555/006/
