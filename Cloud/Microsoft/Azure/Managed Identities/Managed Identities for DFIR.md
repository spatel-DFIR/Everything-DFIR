# Managed Identities for DFIR

When an Azure workload is compromised, its **managed identity** is the pivot into the rest of Azure. This note is how you determine what a stolen identity could reach, prove what it did, and cut it off.

New to this? Read **What is Managed Identities** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Scoping the Blast Radius](#scoping-the-blast-radius)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **Managed-identity sign-in log** | The identity acquiring tokens (resources accessed) |
| **Activity Log** | The identity as `caller` doing control-plane ops |
| **Key Vault / Storage diagnostic logs** | Data-plane reads by the identity (if enabled) |
| **RBAC assignments** | What the identity is allowed to do (the blast radius) |

## Collect It

**What is this identity allowed to do? (the blast radius):**

```bash
# Find the managed identity's principal (objectId), then its role assignments
az identity show --name <mi-name> -g <rg> --query "{oid:principalId,client:clientId}"
az role assignment list --assignee <principalId> --all \
  --query "[].{role:roleDefinitionName,scope:scope}" -o table
```

**What did it do? (control plane):**

```kql
AzureActivity
| where Caller == "<managed-identity-principalId-or-name>"
| project TimeGenerated, OperationNameValue, _ResourceId, ActivityStatusValue
```

**Token acquisitions:**

```kql
AADManagedIdentitySignInLogs
| where ServicePrincipalName == "<mi-name>"
| project TimeGenerated, ResourceDisplayName, ResultType
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Identify the identity + its resource | System- vs user-assigned; which VM/Function/AKS |
| 2. Map its permissions | RBAC roles + Graph app perms = what it can reach |
| 3. Suspect the vector | SSRF or RCE on the resource? Check the app/VM |
| 4. Prove misuse | Unusual actions in Activity Log (listKeys, role grants, new resources) |
| 5. Prove data access | Key Vault/Storage diagnostic logs — did it read secrets/blobs? |
| 6. Treat resource as compromised | The token came *from* the resource — it's owned |

## Scoping the Blast Radius

The identity's **role assignments are the blast radius.** Ask:

| The identity has… | Attacker can… |
|-------------------|---------------|
| **Key Vault Secrets User** | Read every secret in the vault (creds, connection strings) |
| **Storage Blob Data Contributor** | Read/write blob data |
| **Contributor** on a sub/RG | Create/delete resources, run VM commands |
| **Owner / User Access Administrator** | 🔴 Escalate — assign roles to itself/others |
| **Graph app perms** (`Directory.ReadWrite`) | Act on the directory |

🔴 An over-permissioned managed identity (Contributor/Owner at subscription scope) turns one SSRF into full-subscription compromise.

## Hunt at Scale

**Managed identities with privileged roles (pre-position risk):**

```bash
az role assignment list --all \
  --query "[?principalType=='ServicePrincipal' && (roleDefinitionName=='Owner' || roleDefinitionName=='Contributor' || roleDefinitionName=='User Access Administrator')].{p:principalName,role:roleDefinitionName,scope:scope}" -o table
```

**Managed identity doing out-of-character actions:**

```kql
AzureActivity
| where Caller has "<mi-name>"
| where OperationNameValue has_any ("listKeys","roleAssignments/write","runCommand","vaults/secrets")
| project TimeGenerated, OperationNameValue, _ResourceId
```

## Respond

| Goal | Action |
|------|--------|
| Cut the token source | Stop/isolate/deallocate the compromised resource |
| Kill a system-assigned identity | Deleting/disabling the resource removes it |
| Contain a user-assigned identity | Remove its role assignments; detach it from resources |
| Rotate downstream | Rotate any Key Vault secrets / storage keys it could read |
| Fix the vector | Patch the SSRF/RCE; enforce IMDSv2-equivalent protections |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege roles** for every managed identity (narrow scope) | Shrinks blast radius |
| **Prefer system-assigned** or tightly-scoped user-assigned | Less sharing/persistence |
| **Block SSRF paths** to `169.254.169.254` (app + network) | Stops token theft via SSRF |
| **AKS: use Workload Identity, block pod→node IMDS** | Pods never touch node creds |
| **Enable Key Vault / Storage diagnostic logs** | Prove/deny data access |
| **Alert** on managed identities doing `listKeys`/`roleAssignments/write` | Catch misuse |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Managed identity listing all storage keys / reading all secrets | Token theft / over-privilege abuse |
| Managed identity assigning roles | Self-escalation |
| Web-app identity doing infra actions | SSRF-driven misuse |
| User-assigned identity on many resources w/ broad rights | Large blast radius |
| Identity token acquisitions spiking / new resources targeted | Compromise in progress |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What managed identities are + IMDS | **Managed Identities → What is** |
| What the identity can reach | **Azure → Azure RBAC** |
| The actions it took | **Azure → Activity Log** |
| The resource it lives on | **Azure → Virtual Machines** · **AKS** |
| The theft scenario end-to-end | **Azure → Playbooks → Managed Identity Theft via SSRF** |

## Resources

- Managed identities — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview
- Best practices — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations
- MITRE ATT&CK: T1552.005 Cloud Instance Metadata API — https://attack.mitre.org/techniques/T1552/005/
