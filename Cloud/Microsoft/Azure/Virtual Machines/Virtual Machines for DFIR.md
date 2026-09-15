# Azure Virtual Machines for DFIR

A compromised VM is both a foothold and a pivot — code runs in the guest, its managed identity gets stolen, its disks hold the evidence. This note is how you **investigate the control-plane abuse, acquire the guest for forensics, and contain the box.**

New to the service? Read **What is Azure Virtual Machines** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Acquiring the Guest OS](#acquiring-the-guest-os)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Needs |
|--------|--------------|-------|
| **Activity Log** | runCommand, extensions, VM/NSG changes | Default on |
| **Guest-OS logs** | Auth, process, security events | AMA / your collection |
| **Disk snapshot** | Full offline forensic image | You create it |
| **Boot diagnostics** | Console screenshot/serial log | If enabled |
| **Defender for Servers** | Guest-level alerts | If enabled |
| **WAD Windows Event Logs (legacy)** | Windows Event Logs, but stored in a **NoSQL Azure Storage Table**, not Log Analytics | Legacy Azure Diagnostics (WAD) extension |

> 🔴 **Legacy WAD vs modern AMA — a real false-negative risk.** The **Azure Monitor Agent (AMA)** is the current agent and ships Windows Event Logs into Log Analytics, where KQL can query them. Many still-running/legacy VMs instead have the older **Azure Diagnostics (WAD)** extension installed, which writes Windows Event Logs into a **NoSQL Azure Storage Table** named `WADWindowsEventLogsTable` — a completely different storage mechanism. That table is **not visible in Log Analytics at all**; you can only read it via **Storage Explorer** or the **Table API/SDK**. An analyst who checks `Event`/`SecurityEvent` in Log Analytics and finds nothing may simply be looking at a VM running WAD, not AMA — check which extension is installed (`az vm extension list`) before concluding guest-OS logging doesn't exist.


## Collect It

**Control-plane actions on the VM:**

```bash
az monitor activity-log list --resource-id <vm-resource-id> --offset 30d \
  --query "[].{t:eventTimestamp,who:caller,op:operationName.value,ip:callerIpAddress}" -o table
```

**Current extensions + run-command history (the code that ran):**

```bash
az vm extension list --vm-name <vm> -g <rg> -o table
az vm run-command list --vm-name <vm> -g <rg>          # managed run-commands
```

> **Console:** the VM → **Activity log**; **Extensions + applications**; **Run command** history.

## Acquiring the Guest OS

🔴 For a real intrusion, image the disk offline — don't trust the running box.

```bash
# 1. Snapshot the OS disk (point-in-time, immutable)
az snapshot create -g <rg> -n <vm>-ir-snap --source <osDiskId>
# 2. Copy the snapshot to a forensic/storage account (isolated subscription ideally)
# 3. Create a disk from the snapshot and attach to an analysis VM, or export a SAS to download
az snapshot grant-access -g <rg> -n <vm>-ir-snap --duration-in-seconds 3600
```

| Step | Why |
|------|-----|
| Snapshot **before** you stop the VM | Preserve disk state; capture memory separately if possible |
| Work from the snapshot, not the live disk | Integrity |
| Isolate first (NSG deny-all) | Stop attacker activity without tipping cleanup |

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Find the code execution | `runCommand` / `extensions/write` events → what ran, by whom |
| 2. Suspect identity theft | VM has a managed identity? Scope its RBAC (assume stolen) |
| 3. Check network exposure | NSG opening RDP/SSH? Brute force in flow logs? |
| 4. Acquire the guest | Snapshot + image for OS-level forensics |
| 5. Correlate | Caller IP/time → Entra sign-in; managed-identity actions → Activity Log |

## Hunt at Scale

**Run Command / extension execution:**

```kql
AzureActivity
| where OperationNameValue has_any ("runCommand","virtualMachines/extensions/write")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, OperationNameValue
```

**New VMs (possible mining):**

```kql
AzureActivity
| where OperationNameValue == "Microsoft.Compute/virtualMachines/write"
| where ActivityStatusValue == "Success"
| summarize count() by Caller, bin(TimeGenerated, 1h)
| where count_ > 3
```

## Respond

| Goal | Action |
|------|--------|
| Isolate | NSG deny-all on the NIC (network isolation) |
| Preserve | Snapshot disks before stopping |
| Stop the box | Deallocate the VM |
| Kill the stolen identity | Treat the managed identity as compromised; rotate downstream secrets |
| Remove persistence | Delete attacker extensions/run-commands; rebuild from clean image |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict `runCommand`/`extensions/write`** via custom roles / Azure Policy | Removes RCE-as-a-service for non-admins |
| **No public RDP/SSH**; use **Bastion** / just-in-time VM access | Cuts brute force |
| **Least-privilege managed identity** | Shrinks pivot blast radius |
| **Deploy AMA + Defender for Servers** | Real guest-OS telemetry + alerts |
| **Alert** on runCommand/extensions + new VMs | Catch execution/mining |
| **Disk encryption + backup** | Protects + enables recovery |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `runCommand` / custom-script extension | Guest code execution |
| VMAccess extension resetting local admin | Credential persistence |
| NSG opening 3389/22 to `0.0.0.0/0` | Exposure / brute force |
| Managed identity doing infra actions after VM compromise | Token theft pivot |
| Burst of new/oversized VMs | Cryptomining |
| Snapshot exported / SAS on a disk | Data theft |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What VMs are + code execution | **Virtual Machines → What is** |
| The control-plane log | **Azure → Activity Log** |
| The stolen identity | **Azure → Managed Identities** |
| Network exposure | **Azure → NSG Flow Logs** |
| Run Command abuse scenario | **Virtual Machines → Playbooks → Run Command Abuse** |
| Cryptomining chain | **Azure → Playbooks → Cryptomining Incident** |

## Resources

- Run Command — https://learn.microsoft.com/azure/virtual-machines/run-command-overview
- Snapshot for forensics — https://learn.microsoft.com/azure/virtual-machines/snapshot-copy-managed-disk
- JIT VM access — https://learn.microsoft.com/azure/defender-for-cloud/just-in-time-access-usage
- MITRE ATT&CK: T1059 Command and Scripting / T1078.004 Cloud Accounts — https://attack.mitre.org/techniques/T1059/
