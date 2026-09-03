# Azure Storage for DFIR

When data leaves Azure, it often leaves via storage — a public container, a leaked SAS token, or stolen account keys. This note is how you **find the exposure, prove what was read, and lock it down.**

New to the service? Read **What is Azure Storage** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Needs |
|--------|--------------|-------|
| **Activity Log** | Public-access changes, `listKeys`, key regen | Default on |
| **Storage diagnostic logs** (`StorageBlobLogs`) | 🔴 Blob reads/writes, incl. **anonymous** + SAS | Must be enabled |
| **Current config** | Public access, network rules, key/SAS policy | Portal / CLI |
| **Defender for Storage** | Malware + anomalous-access alerts | If enabled |

## Collect It

**Check current exposure:**

```bash
# Account-level public-access switch + network rules
az storage account show -n <acct> -g <rg> \
  --query "{publicBlob:allowBlobPublicAccess,network:networkRuleSet.defaultAction,sharedKey:allowSharedKeyAccess}"

# Per-container public level
az storage container list --account-name <acct> --auth-mode login \
  --query "[].{name:name,public:properties.publicAccess}" -o table
```

**Who changed public access / grabbed keys (Activity Log):**

```bash
az monitor activity-log list --offset 30d \
  --query "[?contains(operationName.value,'listKeys') || contains(operationName.value,'storageAccounts/write')]"
```

> **Console:** storage account → **Configuration** (public access switch) + **Networking**; each **Container → Change access level**; **Activity log** for changes.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm exposure | Public switch on? Which containers public? SAS policy? |
| 2. When + who | Activity Log for the `write`/public-access change → actor + IP + time |
| 3. Accident or attacker? | Known IaC/admin vs unexpected identity/IP |
| 4. What's in it? | Inventory container contents + sensitivity |
| 5. What was read? | Data-plane logs (below) — the key question |

## Did Data Actually Leave?

| If you had… | You can determine |
|-------------|-------------------|
| **Storage diagnostic logs** (`StorageBlobLogs`) | Exactly which blobs were read, by whom (incl. `AnonymousAuthentication` + SAS), from where 🎯 |
| **Defender for Storage** alerts | Anomalous/anonymous access flagged |
| **Neither** | 🔴 Only that it *was* reachable during the exposure window — scope by content sensitivity, assume worst |

```kql
// Blob reads while exposed — anonymous or SAS
StorageBlobLogs
| where OperationName == "GetBlob"
| where AuthenticationType in ("Anonymous","SAS")
| project TimeGenerated, AccountName, Uri, CallerIpAddress, AuthenticationType
```

🔴 `AuthenticationType == "Anonymous"` reads = **confirmed** internet downloads.

## Hunt at Scale

**Public access enabled across accounts:**

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Storage/storageAccounts/write"
| where Properties has "allowBlobPublicAccess"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId
```

**Account-key theft:**

```kql
AzureActivity
| where OperationNameValue has "storageAccounts/listKeys"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId
```

## Respond

```bash
# Re-privatize: kill account-level public access + set container private
az storage account update -n <acct> -g <rg> --allow-blob-public-access false
az storage container set-permission -n <container> --account-name <acct> --public-access off --auth-mode login
# Rotate BOTH keys (kills all account-key-signed SAS tokens)
az storage account keys renew -n <acct> -g <rg> --key primary
az storage account keys renew -n <acct> -g <rg> --key secondary
```

| Goal | Action |
|------|--------|
| Kill public exposure | Disable account public switch + set containers private |
| Revoke leaked SAS | 🔴 **Rotate account keys** (only way to kill key-signed SAS) |
| Lock network | Set `defaultAction=Deny` + allowlist |
| Contain an actor | Disable the identity that exposed it; revoke tokens |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Disable `allowBlobPublicAccess`** at the account (tenant policy) | Neutralizes leaky containers |
| **Disable shared-key access**; prefer **Entra RBAC data roles** | Auditable, revocable access; no standing keys |
| **Use user-delegation SAS** (Entra-signed, revocable) not account-key SAS | Revocable, scoped |
| **Enable storage diagnostic logs** → Sentinel | Prove reads; no exfil blind spot |
| **Defender for Storage** | Malware + anomalous-access detection |
| **Network rules / Private Endpoint** | No open internet exposure |
| **Alert** on public-access changes + `listKeys` | Catch exposure fast |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Container/account public access enabled | Leaky-container exposure |
| `listKeys` by an unexpected identity | Account-key theft = full access |
| Anonymous `GetBlob` reads | Confirmed internet download |
| Long-lived, account-wide SAS in use | Un-revocable broad access |
| `regenerateKey` you didn't do | Attacker locking you out / covering tracks |
| Network rules changed to `Allow all` | Exposure widened |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What storage is + access methods | **Storage → What is** |
| The control-plane log | **Azure → Activity Log** |
| Who accessed it | **Microsoft → 01 Entra ID & Identities** |
| The exposed-container scenario | **Storage → Playbooks → Exposed Blob Container** |
| A stolen key/SAS from a workload | **Azure → Managed Identities** · **Key Vault** |

## Resources

- Prevent anonymous access — https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent
- Monitor blob storage — https://learn.microsoft.com/azure/storage/blobs/monitor-blob-storage
- Defender for Storage — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
