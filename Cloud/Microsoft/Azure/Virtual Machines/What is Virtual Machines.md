# What is Azure Virtual Machines?

**Azure Virtual Machines (VMs)** are Azure's **infrastructure-as-a-service compute** — the EC2 equivalent. For DFIR they matter three ways: attackers **run code on them** (Run Command, extensions), **steal their managed-identity token** (IMDS), and you **acquire their disks** for guest-OS forensics.

The key Azure-specific twist: the **control plane can execute code inside the guest OS** without any OS credentials — via Run Command and VM extensions. That's the move to watch.

## Contents

- [How It Works](#how-it-works)
- [Running Code Without OS Credentials](#running-code-without-os-credentials)
- [The VM Attack Surface](#the-vm-attack-surface)
- [The Managed Identity / IMDS Angle](#the-managed-identity--imds-angle)
- [Evidence a VM Produces](#evidence-a-vm-produces)
- [How to Identify VM Activity](#how-to-identify-vm-activity)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

A VM lives in a resource group, attached to a **NIC** (in a VNet/subnet with an **NSG** firewall), one or more **disks** (managed disks you can snapshot), and often a **managed identity**. Azure's **guest agent** runs inside the OS and executes control-plane instructions (extensions, Run Command).

## Running Code Without OS Credentials

🔴 The single most important VM-DFIR fact — Azure gives control-plane callers **code execution inside the guest**:

| Mechanism | What it does | Log |
|-----------|--------------|-----|
| **Run Command** | Runs an arbitrary script in the guest OS (as SYSTEM/root) | `virtualMachines/runCommand/action` |
| **Custom Script Extension** | Installs/runs a script via the agent | `extensions/write` |
| **Other extensions** (e.g. VMAccess) | Reset local admin password / SSH key | `extensions/write` |
| **Serial Console** | Direct OS console access | Boot diagnostics / Activity Log |

> 🔴 An attacker with **Contributor** (or a custom role with `.../runCommand/action` or `.../extensions/write`) can run code on **every VM in scope** — no SSH/RDP, no OS password, no inbound firewall change. It's RCE-as-a-service. This is the Azure analog of AWS **SSM SendCommand**. **Watch `runCommand` and `extensions/write` closely.**

## The VM Attack Surface

| Vector | What it looks like |
|--------|--------------------|
| **Run Command / extensions** | Control-plane code execution (above) |
| **Exposed RDP/SSH** | NSG opening 3389/22 to the internet → brute force |
| **Managed-identity theft** | SSRF/RCE → IMDS token (see below) |
| **Password reset extension** | VMAccess resets local admin creds |
| **Cryptomining** | New/oversized VMs, or mining deployed via Run Command |
| **Disk/snapshot theft** | Copy a disk snapshot out to read its data |

## The Managed Identity / IMDS Angle

If the VM has a **managed identity**, anything that runs on it (Run Command, a webshell, or an **SSRF**) can hit **IMDS `169.254.169.254`** and steal the identity's token — pivoting into whatever Azure RBAC the identity holds.

> 🔴 A compromised VM ⇒ suspect its **managed identity is stolen**. Scope the identity's roles immediately. See **Azure → Managed Identities**.

## Evidence a VM Produces

| Evidence | Where | Needs |
|----------|-------|-------|
| Control-plane ops (create, runCommand, extensions) | Activity Log | Default on |
| Guest-OS logs (auth, process, security) | Inside the OS | 🔴 Agent + collection you set up |
| Boot diagnostics / screenshot | Storage | If enabled |
| **Disk snapshot** (full forensic image) | Managed disks | You create it |
| Managed-identity token use | MI sign-in + Activity Log | — |

> 🔴 As in AWS: the **inside of the guest is yours.** You only have OS-level logs if you deployed the **Azure Monitor Agent / AMA** or forwarded them. For a real intrusion, **snapshot the disk** and image it offline.

## How to Identify VM Activity

- **Resource ID:** `.../providers/Microsoft.Compute/virtualMachines/<name>`.
- **Activity Log:** `Microsoft.Compute/virtualMachines/*`.
- **CLI:** `az vm list`, `az vm run-command`, `az vm extension list`.

## Common Operations You Will See

| Operation | 🔴 Watch |
|-----------|---------|
| `virtualMachines/runCommand/action` | Guest code execution |
| `virtualMachines/extensions/write` | Custom script / VMAccess |
| `virtualMachines/write` | New/modified VM (mining) |
| `disks/beginGetAccess` / snapshot export | Disk/data theft |
| `networkSecurityGroups/write` | Opening RDP/SSH |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Azure VM | EC2 | Compute Engine |
| Run Command | SSM `SendCommand` | `gcloud compute ssh` / startup script |
| Custom Script Extension | User data / SSM | Startup script |
| Managed disk snapshot | EBS snapshot | Persistent disk snapshot |
| IMDS `169.254.169.254` | EC2 IMDS | GCE metadata |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Run Command** | Control-plane guest script execution |
| **VM extension** | An add-on the guest agent runs |
| **VMAccess** | Extension to reset local creds |
| **Managed disk** | The VM's disk (snapshottable) |
| **NSG** | Network Security Group (firewall) |
| **Guest agent** | The in-OS agent that runs extensions |
| **Serial console** | Direct OS console access |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a VM compromise | **Virtual Machines → for DFIR** |
| The control-plane log | **Azure → Activity Log** |
| The VM's stolen identity | **Azure → Managed Identities** |
| Network exposure/flow | **Azure → NSG Flow Logs** |
| The Run Command abuse scenario | **Virtual Machines → Playbooks → Run Command Abuse** |
| Core host forensics | **(Unix/Windows host-forensics notes)** |

## Resources

- Azure VMs — https://learn.microsoft.com/azure/virtual-machines/overview
- Run Command — https://learn.microsoft.com/azure/virtual-machines/run-command-overview
- Snapshot a disk — https://learn.microsoft.com/azure/virtual-machines/snapshot-copy-managed-disk
- VM IMDS — https://learn.microsoft.com/azure/virtual-machines/instance-metadata-service
