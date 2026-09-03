# Playbook — Cryptomining Incident

The most common financially-motivated Azure incident. An attacker with resource-creation rights (a compromised identity, a stolen managed identity, or an exposed cluster) spins up **compute to mine cryptocurrency** — new VMs, oversized VM scale sets, or pods in AKS — and you find out via a **cost/CPU spike**. This playbook confirms the mining, scopes it across the tenant, contains it, and finds how they got in.

> **Tier 2 (cross-service).** Spans Activity Log + VMs/AKS + identity + network. Read **Azure → Activity Log** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [How Did They Get the Rights?](#how-did-they-get-the-rights)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Cost Management** | Sudden spend spike (compute) |
| **Defender for Cloud** | Crypto-mining / suspicious-compute alert |
| **Activity Log** | Bursts of `virtualMachines/write` / `vmss` / new pods |
| **Network** | Egress to mining-pool IPs/ports |

## Hypothesis

An attacker is using your compute to mine. Confirm the mining resources, identify the identity that created them, scope across **all regions and subscriptions**, contain, and remediate the access.

## Step-by-Step Investigation

**1. Find the created compute + the creator.**

```kql
AzureActivity
| where OperationNameValue in ("Microsoft.Compute/virtualMachines/write","Microsoft.Compute/virtualMachineScaleSets/write")
| where ActivityStatusValue == "Success"
| summarize count() by Caller, CallerIpAddress, bin(TimeGenerated, 1h)
| where count_ > 3
```

**2. Sweep all regions + subscriptions.** 🔴 Attackers hide mining in **unused regions**. Enumerate compute everywhere:

```bash
az vm list -d --query "[].{name:name,rg:resourceGroup,size:hardwareProfile.vmSize,location:location,state:powerState}" -o table
az account list --query "[].id" -o tsv   # then loop per subscription
```

**3. Confirm mining.** Oversized GPU/CPU SKUs, egress to mining pools (NSG flow logs), miner process (Defender/guest), or a mining container image (AKS kube-audit).

**4. Identify the identity.** User, service principal, or **stolen managed identity**? Cross to Entra sign-in / MI logs.

## How Did They Get the Rights?

| Vector | Evidence |
|--------|----------|
| Compromised user/SP with Contributor | Sign-in anomaly + role |
| **Stolen managed identity** (SSRF/RCE) | MI creating VMs → **Managed Identity Theft** |
| Exposed AKS / API | `listClusterAdminCredential` + mining pods |
| Leaked credential in a repo/pipeline | CI SP creating compute |

## Decision Points

| Question | If yes → |
|----------|----------|
| Multiple subscriptions/regions? | Full-tenant sweep |
| Stolen managed identity? | Run **Managed Identity Theft** |
| AKS-based? | Run **Malicious Pod and Cryptomining** |
| Persistence beyond the compute? | Hunt roles/apps/identities the actor added |

## Contain

- **Stop/deallocate** the mining VMs/VMSS; delete mining pods.
- **Cut the identity** — disable user/SP, revoke tokens; for a stolen MI, isolate its resource.
- **Block mining-pool egress** (Azure Firewall / NSG).
- Preserve a disk snapshot of one mining host before deleting (evidence).

## Eradicate

- Delete all attacker-created compute across every subscription/region.
- Remove persistence: rogue role assignments, apps, identities.
- Rotate any credentials the entry identity/MI could reach.
- Patch the entry vector (SSRF/RCE/exposed API/leaked key).

## Recover

- **Azure Policy** limiting VM SKUs/regions; **budgets + alerts** on spend.
- **PIM** for Contributor/Owner; least-privilege managed identities.
- **Defender for Cloud** plans + alerts on compute bursts.
- Preserve: the create events, creator identity, mining evidence, and the entry vector.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Burst of VM/VMSS creation | Mining spin-up |
| Compute in an **unused region** | Hidden mining |
| Oversized GPU/CPU SKUs | Mining hardware |
| Egress to mining-pool IPs/ports | Active mining |
| Managed identity creating VMs | Stolen-identity abuse |
| Mining container image in AKS | Container mining |

## References

- Related notes: **Activity Log**, **Virtual Machines**, **AKS**, **Managed Identities**, **NSG Flow Logs**
- Respond to crypto-mining (Defender) — https://learn.microsoft.com/azure/defender-for-cloud/alerts-reference
- Azure Policy for compute — https://learn.microsoft.com/azure/governance/policy/overview
- MITRE ATT&CK: T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1496/
