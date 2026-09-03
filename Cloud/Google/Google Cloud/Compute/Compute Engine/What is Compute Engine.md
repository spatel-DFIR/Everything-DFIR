# What is Compute Engine?

**Compute Engine** is GCP's virtual machines — the equivalent of AWS EC2 and Azure VMs. For DFIR it carries three recurring problems: the **metadata server** (steal the attached service account's token via SSRF), **metadata-based SSH keys and startup scripts** (code execution + persistence), and **disk snapshots** (your acquisition method).

## Contents

- [How It Works](#how-it-works)
- [The Metadata Server — Token Theft Target](#the-metadata-server--token-theft-target)
- [SSH Keys and Startup Scripts in Metadata](#ssh-keys-and-startup-scripts-in-metadata)
- [Disk Snapshots — Your Acquisition Method](#disk-snapshots--your-acquisition-method)
- [How to Identify Compute Engine in Evidence](#how-to-identify-compute-engine-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **VM instance** runs in a **zone**, boots from an **image**, uses **persistent disks**, and (usually) has an **attached service account** for its GCP access.
- Config (create/start/stop/metadata) is **Admin Activity** logged; the **guest OS** is yours (logs only if you install the **Ops Agent**).
- The VM reads its identity + config from the **metadata server**.

## The Metadata Server — Token Theft Target

🔴 Every VM can reach an internal metadata server that hands out the **attached service account's OAuth token** — no secret needed. This is the exact GCP analog of the **AWS IMDS / SSRF role-theft** problem.

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
   (also at 169.254.169.254; requires header: Metadata-Flavor: Google)
   → returns the attached SA's access token
```

| Fact | Detail |
|------|--------|
| **Header required** | `Metadata-Flavor: Google` (a small hurdle, easily set) |
| **What leaks** | The attached SA's **access token** (its full GCP reach) |
| **Attack** | **SSRF or RCE** on the VM → fetch the token → act as the SA |
| **Worst case** | The VM runs the **Compute default SA** with **Editor** → project-wide compromise |

> 🔴 In audit logs, the stolen token's use appears as the **VM's service account** (`…-compute@developer…` for the default SA) acting — often **from the VM's IP but doing unexpected things**, or from a new IP if the token was exfiltrated. See **GCP → Playbooks → Metadata SSRF to SA Token Theft**.

## SSH Keys and Startup Scripts in Metadata

Instance/project **metadata** is a persistence and execution surface:

| Metadata key | What it does | 🔴 |
|--------------|--------------|----|
| **`ssh-keys`** | Public keys allowed to SSH in | 🔴 Attacker adds their key (`setMetadata`) = persistent SSH |
| **`startup-script`** | Runs on every boot (as root) | 🔴 Code execution + persistence |
| **`enable-oslogin`** | Use **OS Login** (IAM-based SSH) instead | Preferred — auditable, no metadata keys |

> 🔴 **OS Login vs metadata SSH keys:** OS Login ties SSH to IAM + Cloud Audit Logs (who logged in). Metadata `ssh-keys` bypasses that. A `setMetadata` adding an `ssh-keys` entry, or a new `startup-script`, is classic persistence — watch for it.

## Disk Snapshots — Your Acquisition Method

To forensically acquire a VM's disk without touching the live guest:

```bash
gcloud compute disks snapshot <disk> --snapshot-names=ir-<case>-$(date +%s) --zone=<z>
# create a disk from the snapshot, attach read-only to an analysis VM
```

- Snapshots are point-in-time copies — the GCP equivalent of an EBS snapshot.
- Take one **before** you stop/reset the VM (memory is lost on stop; consider live capture first).

## How to Identify Compute Engine in Evidence

- **Resource name:** `//compute.googleapis.com/projects/<p>/zones/<z>/instances/<name>`.
- **Config events:** `v1.compute.instances.insert/delete/setMetadata/reset`.
- **Attached SA:** the instance's `serviceAccounts`.
- **Guest logs:** only if the **Ops Agent** ships them to Cloud Logging.

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `compute.instances.insert` | Create a VM | 🔴 bursts = cryptomining |
| `compute.instances.setMetadata` | Change metadata | 🔴 SSH key / startup-script injection |
| `compute.instances.reset` / `stop` | Reboot/stop | Evidence-affecting |
| `compute.instances.setServiceAccount` | Change attached SA | 🔴 privilege change |
| `compute.disks.createSnapshot` | Snapshot a disk | IR (or attacker copying data) |
| `compute.firewalls.insert` | Open a firewall | 🔴 expose the VM |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Compute Engine | EC2 | Azure VM |
| Metadata server (`metadata.google.internal`) | IMDS `169.254.169.254` | IMDS `169.254.169.254` |
| Attached service account | Instance role (profile) | Managed identity |
| Metadata `ssh-keys` / startup-script | Key pair / user-data | SSH keys / custom-data / Run Command |
| Disk snapshot | EBS snapshot | Managed-disk snapshot |
| OS Login | (SSM / IAM) | Azure AD login |
| Ops Agent | CloudWatch Agent | Azure Monitor Agent |

## Common Use Cases

Your "normal": app servers, batch/ML nodes, autoscaling groups (MIGs). The job is to spot a **compromised VM** (metadata token abused, injected SSH key/startup-script) or **attacker-created VMs** (mining).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Instance** | A VM |
| **Metadata server** | Internal endpoint serving instance config + SA tokens |
| **Attached service account** | The VM's GCP identity |
| **Startup script** | Boot-time code (metadata) |
| **OS Login** | IAM-based, auditable SSH |
| **Snapshot** | Point-in-time disk copy |
| **Ops Agent** | Guest OS/app log shipper |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a VM compromise | **Compute Engine → for DFIR** |
| The attached SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Metadata token theft end to end | **GCP → Playbooks → Metadata SSRF to SA Token Theft** |
| Network evidence for the VM | **GCP → VPC Flow Logs** |
| Cryptomining | **GCP → Playbooks → Cryptomining Incident** |

## Resources

- Compute Engine — https://cloud.google.com/compute/docs
- VM metadata / SA tokens — https://cloud.google.com/compute/docs/metadata/overview
- OS Login — https://cloud.google.com/compute/docs/oslogin
- Create/use snapshots — https://cloud.google.com/compute/docs/disks/create-snapshots
