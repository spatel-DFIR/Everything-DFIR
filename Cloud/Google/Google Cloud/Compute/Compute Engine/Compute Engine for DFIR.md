# Compute Engine for DFIR

A VM case has two halves: the **GCP control plane** (who created/changed it, was the metadata token abused, was an SSH key/startup-script injected) and the **guest OS** (host forensics — only if you have logs/a snapshot).

New to it? Read **What is Compute Engine** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Was the Metadata Token Stolen?](#was-the-metadata-token-stolen)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **Admin Activity** (`compute.*`) | Create/metadata/SA/firewall changes + actor | ✅ On |
| **Attached SA activity** | What the VM's identity did (its `principalEmail`) | ✅ On |
| **VPC Flow Logs** | The VM's network (C2/exfil/mining) | Per-subnet opt-in |
| **Guest OS logs** | In-VM activity | 🔴 Only with Ops Agent |
| **Disk snapshot** | Full host forensics | You take it |

## Collect It

```bash
# VM config, attached SA, and metadata (ssh-keys / startup-script)
gcloud compute instances describe <vm> --zone=<z> --format=json

# Control-plane events for the VM
gcloud logging read 'resource.type="gce_instance" AND resource.labels.instance_id="<id>"' --freshness=30d

# What the attached SA did (token abuse shows here)
gcloud logging read \
 'protoPayload.authenticationInfo.principalEmail="<num>-compute@developer.gserviceaccount.com"' --freshness=30d

# Acquire the disk
gcloud compute disks snapshot <disk> --snapshot-names=ir-<case> --zone=<z>
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Config review | `setMetadata` (ssh-keys/startup-script), `setServiceAccount`, firewall opens |
| 2. Metadata token | Did the attached SA act unexpectedly / from a new IP? (next section) |
| 3. Network | VPC Flow Logs: C2, mining pools, large egress |
| 4. Guest | If Ops Agent / snapshot: host triage (→ Linux/Container notes) |
| 5. Blast radius | The attached SA's roles = what the VM compromise reached |

## Was the Metadata Token Stolen?

🔴 The signature of metadata/SSRF token theft:

| Signal | Meaning |
|--------|---------|
| Attached SA doing **unexpected API calls** (IAM, storage, new keys) | Token abused for lateral movement |
| Attached SA acting **from an IP that isn't the VM** | Token **exfiltrated** off-box |
| The VM had an **SSRF-able app** or RCE | The delivery mechanism |
| Compute **default SA** (Editor) attached | 🔴 Worst case — project-wide reach |

Trace the SA's actions in Cloud Audit Logs after the suspected theft; that's the blast radius. See **GCP → Playbooks → Metadata SSRF to SA Token Theft**.

## Hunt at Scale

**Metadata changes (SSH key / startup-script injection):**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       resource.labels.instance_id AS vm
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'v1.compute.instances.setMetadata'
ORDER BY timestamp DESC;
```

**VM creation bursts (mining):**

```sql
SELECT protopayload_auditlog.authenticationInfo.principalEmail AS who, COUNT(*) vms
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName='v1.compute.instances.insert'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 DAY)
GROUP BY who HAVING vms > 10 ORDER BY vms DESC;
```

> **At the very end — SecOps UDM (optional):** land metadata-change + instance-insert events to correlate the actor across projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Preserve first | **Snapshot the disk** (and live-capture memory if possible) before stop |
| Isolate | Firewall-deny the VM / move to quarantine network / remove external IP |
| Cut token abuse | **Disable/rotate the attached SA**; remove injected SSH keys/startup-script |
| Rebuild | Recreate the VM from a clean image (don't trust a compromised host) |
| Preserve | Export control-plane events + the SA's activity |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege attached SA** (never default Editor) | Small blast radius if token stolen |
| **Enforce OS Login** (`compute.requireOsLogin`) | Auditable SSH; no metadata keys |
| **Block metadata SSH keys** (`block-project-ssh-keys`) | Kills key-injection persistence |
| **No external IPs** (`compute.vmExternalIpAccess`) + IAP for SSH | Reduce exposure/SSRF impact |
| **Ops Agent** on VMs | Guest-level evidence exists |
| **Alert** on `setMetadata`, `setServiceAccount`, instance-insert bursts | Catch persistence/mining live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Attached SA acting from a non-VM IP | Metadata token exfiltrated |
| `setMetadata` adding `ssh-keys`/`startup-script` | Persistence / code execution |
| Default Compute SA (Editor) abused | Project-wide compromise |
| Instance-insert bursts | Cryptomining |
| Firewall opened to `0.0.0.0/0` | VM exposure |
| `setServiceAccount` to a more-privileged SA | Privilege change |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| VM fundamentals + metadata | **Compute Engine → What is** |
| The attached SA's reach | **GCP → Service Accounts** · **Cloud IAM** |
| Metadata token theft | **GCP → Playbooks → Metadata SSRF to SA Token Theft** |
| Network evidence | **GCP → VPC Flow Logs** |
| Cryptomining | **GCP → Playbooks → Cryptomining Incident** |
| Guest OS forensics | **Linux / Container notes** |

## Resources

- VM metadata — https://cloud.google.com/compute/docs/metadata/overview
- OS Login — https://cloud.google.com/compute/docs/oslogin
- Snapshots — https://cloud.google.com/compute/docs/disks/create-snapshots
- MITRE ATT&CK: T1552.005 Cloud Instance Metadata API / T1078.004 Cloud Accounts — https://attack.mitre.org/techniques/T1552/005/
