# Playbook — Exposed Blob Container

The Azure "leaky bucket." A blob container becomes **publicly readable** (or a broad SAS token leaks), and data is exposed to the internet. This playbook determines **when it went public, who made it public, what was read while open, and how to lock it down.**

> **Tier 1 (single-service).** Storage-focused; pulls in Activity Log (actor) + storage diagnostic logs (reads). Read **Azure → Storage for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Did Data Actually Leave?](#did-data-actually-leave)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender for Cloud** | Storage account allows public access / anonymous access alert |
| **Defender for Storage** | Access from a suspicious/anonymous source |
| **External report** | A researcher/customer found your data online |
| **Azure Policy** | "Storage accounts should restrict public access" non-compliant |
| **Activity Log** | `allowBlobPublicAccess` set true / container public level changed |

## Hypothesis

A container was exposed publicly (or via a leaked SAS) — by accident or attacker. Establish the exposure window, attribute the change, quantify what was accessible and read, then re-privatize.

## Step-by-Step Investigation

**1. Confirm current exposure.**

```bash
az storage account show -n <acct> -g <rg> --query "{public:allowBlobPublicAccess,net:networkRuleSet.defaultAction}"
az storage container list --account-name <acct> --auth-mode login --query "[?properties.publicAccess!=null]"
```

**2. When + who?** Activity Log for the exposure change:

```bash
az monitor activity-log list --offset 30d \
  --query "[?contains(operationName.value,'storageAccounts/write') || contains(operationName.value,'containers/write')].{t:eventTimestamp,who:caller,ip:callerIpAddress,op:operationName.value}"
```

**3. Accident or attacker?** Known admin/IaC change vs unexpected identity/IP → sets your response path.

**4. What's in the container?** Inventory contents + sensitivity (PII, secrets, backups) — bounds impact even without read logs.

**5. What was read?** → next section.

## Did Data Actually Leave?

| If you had… | You can determine |
|-------------|-------------------|
| **Storage diagnostic logs** | Exactly which blobs were read, by whom (incl. `Anonymous`/SAS), from where 🎯 |
| **Defender for Storage** | Anomalous/anonymous access flagged |
| **Neither** | 🔴 Only that it *was* reachable during `[went-public, re-privatized]` — assume worst for sensitive content |

```kql
StorageBlobLogs
| where OperationName == "GetBlob" and AuthenticationType == "Anonymous"
| summarize reads=count(), blobs=dcount(Uri) by CallerIpAddress
```

🔴 Anonymous reads from external IPs = **confirmed** exfil.

## Decision Points

| Question | If yes → |
|----------|----------|
| Accident or attacker? | Attacker → full compromise workflow; accident → fix + process review |
| Diagnostic logs available? | Prove exactly what was read; else assume worst |
| Sensitive data present? | Data-breach handling; legal/regulatory notification |
| SAS leaked (not public)? | Rotate account keys to revoke; find where the SAS leaked |
| Secrets in the container? | Rotate them — assume leaked |

## Contain

```bash
az storage account update -n <acct> -g <rg> --allow-blob-public-access false
az storage container set-permission -n <container> --account-name <acct> --public-access off --auth-mode login
# If a SAS may have leaked, rotate both keys to revoke all key-signed SAS
az storage account keys renew -n <acct> -g <rg> --key primary
az storage account keys renew -n <acct> -g <rg> --key secondary
```

## Eradicate

- Remove every public setting (account switch + per-container).
- If an **attacker** exposed it: cut their identity, hunt persistence (roles/apps).
- Enable **storage diagnostic logs** now so the next event is answerable.

## Recover

- Re-privatize + verify with Azure Policy / Defender.
- Rotate any **secrets** that were in the container.
- Data-breach handling if PII/regulated data was exposed.
- Preserve: the exposure-change event, the exposure window, and any read evidence.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `allowBlobPublicAccess=true` / container public | Public exposure |
| Anonymous `GetBlob` reads | Confirmed internet access |
| Exposure change by an unexpected identity/IP | Attacker-driven |
| Leaked long-lived account-wide SAS | Un-revocable broad access |
| Sensitive content + no data-plane logs | Unprovable loss — assume worst |

## References

- Related notes: **Storage for DFIR**, **Activity Log**, **Managed Identities**, **Defender for Cloud**
- Prevent anonymous access — https://learn.microsoft.com/azure/storage/blobs/anonymous-read-access-prevent
- Defender for Storage — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-storage-introduction
- MITRE ATT&CK: T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1530/
