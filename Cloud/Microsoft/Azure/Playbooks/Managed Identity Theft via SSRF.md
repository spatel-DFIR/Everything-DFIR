# Playbook — Managed Identity Theft via SSRF

The Azure version of the AWS IMDS/SSRF classic. A web app on an Azure resource (VM, App Service, Function, AKS pod) has an **SSRF** (or RCE) flaw. The attacker makes it fetch the **Instance Metadata Service** token at **`169.254.169.254`**, steals the resource's **managed identity** token, and pivots into Azure with whatever RBAC that identity holds. This playbook proves the theft, scopes the blast radius, and cuts it off.

> **Tier 2 (cross-service).** Spans the resource + Managed Identities + Activity Log + downstream (Key Vault/Storage). Read **Azure → Managed Identities** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Scoping the Blast Radius](#scoping-the-blast-radius)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender for Cloud** | Anomalous managed-identity / resource-manager activity |
| **App logs / WAF** | Requests to `169.254.169.254/metadata/identity/...` |
| **Activity Log** | The resource's managed identity doing unusual Azure ops |
| **Key Vault logs** | Secret reads by the managed identity from a new context |

## Hypothesis

An attacker exploited SSRF/RCE on a resource to steal its managed-identity token and is acting as the identity in Azure. Prove the theft, enumerate what the identity can reach, and contain both the resource and the downstream secrets.

## Step-by-Step Investigation

**1. Confirm the SSRF/RCE vector.** App/WAF logs showing outbound fetches to `169.254.169.254/metadata/identity/oauth2/token` (often with a `resource=` for ARM, Key Vault, or Storage).

**2. Identify the resource's managed identity.**

```bash
az vm identity show --name <vm> -g <rg>        # or the App Service/Function/AKS identity
az identity show --name <mi> -g <rg> --query principalId
```

**3. Map its Azure RBAC (the blast radius).**

```bash
az role assignment list --assignee <principalId> --all --query "[].{role:roleDefinitionName,scope:scope}" -o table
```

**4. Prove misuse.** The identity as `caller` doing out-of-character actions:

```kql
AzureActivity
| where Caller has "<mi-name-or-principalId>"
| where OperationNameValue has_any ("listKeys","vaults","roleAssignments/write","runCommand","storageAccounts")
| project TimeGenerated, OperationNameValue, _ResourceId, CallerIpAddress
```

**5. Prove data access.** Key Vault / Storage diagnostic logs — did the identity read secrets/blobs?

## Scoping the Blast Radius

The identity's **RBAC roles + Graph app permissions = what the attacker now has.** Prioritize:

| The identity has… | Attacker got… |
|-------------------|---------------|
| Key Vault Secrets User | Every secret in the vault → downstream creds |
| Storage Blob Data Contributor | Blob data read/write |
| Contributor / Owner | Resource creation/deletion, VM run-commands, more identities |
| User Access Administrator | 🔴 Can assign roles → escalate further |

🔴 Everything the identity could reach is now compromised — **rotate all of it.**

## Decision Points

| Question | If yes → |
|----------|----------|
| Identity over-permissioned (Contributor/Owner)? | Broad blast radius — full subscription review |
| Key Vault/Storage reachable? | Rotate every reachable secret/key |
| Identity assigned roles? | Undo the grants; hunt further escalation |
| Multiple resources share a user-assigned identity? | All are in scope |

## Contain

- **Isolate the resource** (NSG deny-all / stop the App Service/Function; cordon the AKS node).
- Treat the **managed identity as compromised** — a system-assigned one dies when you stop/delete the resource; for user-assigned, **remove its role assignments**.
- Revoke/rotate downstream: **Key Vault secrets, storage keys**, any credential the identity could read.

## Eradicate

- Patch the SSRF/RCE (input validation, block metadata egress, IMDS restrictions).
- Rebuild the compromised resource from a clean image.
- Remove any persistence the attacker established with the identity (new roles/identities/resources).

## Recover

- **Least-privilege** the managed identity (narrow role + scope).
- **Block SSRF paths to `169.254.169.254`** at the app and network layers.
- For AKS: **Workload Identity** + block pod→node IMDS.
- Enable Key Vault/Storage diagnostic logs.
- Preserve: SSRF evidence, the identity's RBAC, its Activity-Log actions, and downstream read logs.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| App fetching `169.254.169.254/metadata/identity` | IMDS token theft |
| Managed identity doing infra/secret actions | Token misuse |
| Web-app identity reading Key Vault / listing storage keys | Pivot underway |
| Identity assigning roles | Self-escalation |
| Over-permissioned identity (Contributor/Owner) | Large blast radius |

## References

- Related notes: **Managed Identities**, **Activity Log**, **Key Vault**, **Virtual Machines**, **AKS**
- IMDS security — https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service
- Managed identity best practices — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations
- MITRE ATT&CK: T1552.005 Cloud Instance Metadata API — https://attack.mitre.org/techniques/T1552/005/
