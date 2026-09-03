# Playbook — Run Command Abuse

Azure lets a control-plane caller **run arbitrary code inside a VM's guest OS** — no SSH/RDP, no OS password, no firewall change — via **Run Command** or the **Custom Script Extension**. An attacker with Contributor (or a custom role granting it) turns Azure RBAC into RCE on every VM in scope. This playbook finds what ran, contains it, and closes the path.

> **Tier 1 (single-service).** VM-focused; pulls in Activity Log + guest forensics. Read **Azure → Virtual Machines for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [What Did the Command Do?](#what-did-the-command-do)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender for Servers** | Suspicious script execution / process alert on a VM |
| **Activity Log** | `runCommand/action` or `extensions/write` from an unusual caller |
| **Guest EDR** | A script/process spawned by the Azure guest agent |
| **Cost/perf** | Mining or beaconing after a control-plane action |

## Hypothesis

An attacker with resource-management rights executed code in one or more VMs' guest OS. Establish who, on which VMs, what the script did, whether the VM's managed identity was stolen, and eradicate.

## Step-by-Step Investigation

**1. Find the execution events.**

```kql
AzureActivity
| where OperationNameValue has_any ("runCommand","virtualMachines/extensions/write")
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, OperationNameValue, ActivityStatusValue
| order by TimeGenerated asc
```

**2. Identify the caller + scope.** A user? A service principal/managed identity? What role let them (Contributor / custom w/ `runCommand`)? How many VMs?

**3. Recover the script.** Run Command/extension settings may hold the command; correlate with **guest-OS logs** (process creation) and **EDR** for what actually executed.

**4. Check the managed identity.** If the VM has one, assume the script **stole its IMDS token** → scope its RBAC. See **Managed Identities**.

**5. Acquire the guest.** Snapshot the disk for offline analysis of dropped files/persistence.

## What Did the Command Do?

| Look for | Evidence |
|----------|----------|
| Reverse shell / C2 | Guest network conns; NSG flow logs |
| Mining | High CPU; miner process; pool connections |
| Credential theft | IMDS token pull; local credential access |
| Persistence | New services/tasks/users in the guest |
| Lateral movement | Auth to other hosts; the identity's Azure actions |

## Decision Points

| Question | If yes → |
|----------|----------|
| Multiple VMs targeted? | Broad campaign — sweep all VMs the caller could reach |
| Managed identity present? | Assume token theft → run **Managed Identity Theft** |
| Mining? | Run **Cryptomining Incident** |
| Persistence in guest? | Rebuild from clean image, don't just clean |

## Contain

- **Isolate** affected VMs (NSG deny-all on the NIC).
- **Cut the caller** — disable the user/SP; revoke tokens; remove the role that allowed runCommand.
- **Snapshot** disks before stopping (preserve evidence).

## Eradicate

- Remove attacker Run Commands / extensions.
- Rebuild compromised VMs from a known-good image (guest persistence is easy to miss).
- Rotate any secrets the stolen managed identity could reach.

## Recover

- **Restrict `runCommand`/`extensions/write`** to break-glass admins via custom roles + Azure Policy.
- Deploy Defender for Servers + EDR; alert on runCommand.
- Preserve: the execution events, recovered scripts, guest images, and identity-abuse evidence.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `runCommand`/`extensions/write` from an unusual caller | Control-plane RCE |
| Same caller executing across many VMs | Fleet-wide compromise |
| Managed-identity token pulled after execution | Pivot into Azure |
| Miner/C2 process spawned by the guest agent | Impact / beaconing |
| VMAccess extension resetting local admin | Credential persistence |

## References

- Related notes: **Virtual Machines**, **Activity Log**, **Managed Identities**, **Cryptomining Incident**
- Run Command — https://learn.microsoft.com/azure/virtual-machines/run-command-overview
- Defender for Servers — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-servers-introduction
- MITRE ATT&CK: T1059 Command and Scripting Interpreter — https://attack.mitre.org/techniques/T1059/
