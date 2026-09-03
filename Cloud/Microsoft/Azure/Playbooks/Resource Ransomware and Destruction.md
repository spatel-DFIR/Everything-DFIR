# Playbook — Resource Ransomware and Destruction

The impact-stage nightmare. An attacker with broad Azure rights **destroys or encrypts** to extort or sabotage: deletes resource groups, wipes storage/disks, encrypts data with their own keys, or removes backups. This playbook establishes the scope, contains the identity, recovers what's recoverable, and preserves evidence.

> **Tier 2 (cross-service).** Spans Activity Log + Storage + Key Vault + backups + identity. Read **Azure → Activity Log** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [What Can Be Recovered?](#what-can-be-recovered)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Outage** | Resources/apps suddenly gone |
| **Ransom note** | A message in a storage container / left in the tenant |
| **Activity Log** | Mass `delete`, `resourceGroups/delete`, key regen, backup deletion |
| **Defender for Cloud** | Mass-deletion / suspicious-key alerts |

## Hypothesis

An attacker with high privilege is destroying or encrypting resources. Establish exactly what was deleted/encrypted, when, by whom, whether backups survive, and contain before more is lost.

## Step-by-Step Investigation

**1. Scope the destruction (Activity Log).**

```kql
AzureActivity
| where OperationNameValue has_any ("delete","regenerateKey","encryptionSettings")
| where ActivityStatusValue == "Success"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
| order by TimeGenerated asc
```

**2. Identify the actor + how privileged.** A compromised Owner? A stolen managed identity? `elevateAccess` beforehand? Cross to identity + RBAC logs.

**3. Enumerate what's gone vs recoverable.** Soft-delete? Backups? Resource locks that held?

**4. Encryption vs deletion.** Storage/disk encrypted with an **attacker-controlled key** (double extortion) vs outright deleted — different recovery paths.

## What Can Be Recovered?

| Protection | Recovers |
|-----------|----------|
| **Soft delete** (storage/Key Vault/blobs) | Deleted items within the retention window |
| **Azure Backup / snapshots** | Point-in-time restores — 🔴 *if the attacker didn't delete them* |
| **Resource locks** | May have *blocked* deletion entirely |
| **Geo-redundancy** | Not a backup — won't help against deletion |
| **Nothing** | 🔴 Permanent loss — scope by inventory, engage IR/legal |

🔴 Sophisticated actors **delete backups first.** Check the backup vault's own activity log.

## Decision Points

| Question | If yes → |
|----------|----------|
| Backups intact? | Restore; prioritize crown jewels |
| Attacker-key encryption? | Extortion — engage legal/IR/law enforcement; do **not** assume decryption |
| `elevateAccess` / Owner compromise? | Full-tenant response; assume everything reachable |
| Still in progress? | Contain the identity **immediately** — every minute costs resources |

## Contain

- **Immediately** disable the actor identity + revoke tokens; remove its role assignments.
- Revoke the **GA→Azure bridge** if `elevateAccess` was used.
- Apply **resource locks** / tighten RBAC to stop further deletion.
- Isolate any resource the attacker still controls.

## Eradicate

- Remove the attacker's access, backdoor accounts, apps, and identities.
- Rotate all credentials the actor could reach (Key Vault, storage keys).
- Rebuild from clean backups/images; verify integrity.

## Recover

- Restore from **backups/snapshots/soft-delete** (validate against tampering).
- Re-establish resource locks + backup protection + **immutable backups**.
- **PIM** for Owner/UAA; **alert** on mass delete + backup deletion.
- Data-breach/legal process; preserve: the destruction events, the actor, and the pre-incident inventory.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `resourceGroups/delete` / mass `delete` | Destruction |
| Backup vault items deleted | Anti-recovery move |
| Storage/disk re-encrypted with a new key | Extortion |
| `elevateAccess` before the destruction | GA-driven takeover |
| `regenerateKey` locking you out of storage | Denial |
| Resource locks removed just before deletes | Guardrail defeat |

## References

- Related notes: **Activity Log**, **Storage**, **Key Vault**, **Azure RBAC**, **Entra → Privileged Role Escalation**
- Azure Backup security / immutability — https://learn.microsoft.com/azure/backup/backup-azure-security-feature
- Resource locks — https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources
- MITRE ATT&CK: T1485 Data Destruction / T1486 Data Encrypted for Impact — https://attack.mitre.org/techniques/T1486/
