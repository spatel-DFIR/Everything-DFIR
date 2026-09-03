# Playbook — Cryptomining Incident

The most common financially-motivated GCP incident: an attacker with a stolen credential or exposed resource **spins up compute** (VMs, GKE pods, sometimes Cloud Run) to **mine cryptocurrency**, running up a huge bill. This playbook confirms mining, finds every miner, traces the access, contains, and prevents recurrence.

> **Tier 2 (cross-service).** Spans Compute Engine + GKE + VPC Flow + IAM. Read **GCP → Compute Engine** and **GKE for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Find Every Miner](#find-every-miner)
- [How Did They Get In?](#how-did-they-get-in)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Billing** | Sudden compute cost spike (often in a new region) |
| **SCC (VM Threat Detection)** | Cryptomining detected on a VM/pod |
| **Audit log** | Bursts of `instances.insert` / `pods.create` |
| **VPC Flow** | Egress to mining-pool IPs / ports |

## Hypothesis

An attacker is using your compute to mine. Establish the access vector (stolen key, exposed API, compromised VM), find every miner (VMs, pods, jobs), stop the spend, and close the door.

## Step-by-Step Investigation

**1. Confirm mining.** SCC VM/Container Threat Detection; VPC Flow Logs egress to a **mining pool**; pinned CPU on the resources; the image/binary name.

**2. Scope the spend.** Billing by project/region/SKU — where's the cost, when did it start?

**3. Identify the compute.** New VMs, GKE pods/daemonsets, Cloud Run jobs created in the window.

## Find Every Miner

```sql
-- VM creation bursts
SELECT protopayload_auditlog.authenticationInfo.principalEmail AS who, COUNT(*) vms
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName='v1.compute.instances.insert'
  AND timestamp > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 DAY)
GROUP BY who ORDER BY vms DESC;
```
```bash
# GKE pods/daemonsets (miners often use daemonsets to spread)
kubectl get pods,daemonsets -A -o wide
```

## How Did They Get In?

| Vector | Evidence |
|--------|----------|
| **Stolen SA key** | `serviceAccountKeyName` on the `instances.insert` calls |
| **Exposed/compromised VM** | Metadata-token abuse (→ Metadata SSRF playbook) |
| **Exposed GKE API** | `getCredentials` / `system:anonymous` pod creates |
| **Compromised CI/CD** | A pipeline SA creating compute |
| **Leaked user creds** | New human login then compute spin-up |

## Decision Points

| Question | If yes → |
|----------|----------|
| Stolen SA key? | Run **Service Account Key Abuse** |
| Via a VM metadata token? | Run **Metadata SSRF to SA Token Theft** |
| GKE pods? | Run **GKE Malicious Pod and Cryptomining** |
| Spread across projects? | Org-wide sweep; check org-level IAM |

## Contain

```bash
# Stop/delete miner VMs; delete miner pods; cordon nodes
gcloud compute instances delete <vm> --zone=<z>          # snapshot first if needed as evidence
kubectl delete daemonset <ds> -n <ns>; kubectl delete pod <p> -n <ns>
# Cut the identity that created them
gcloud iam service-accounts disable <sa>                 # or reset the user
# Block mining-pool egress
gcloud compute firewall-rules create deny-mining --direction=EGRESS --action=DENY ...
```

## Eradicate

- Delete **all** miner compute (VMs, pods, daemonsets, Cloud Run jobs) — they self-respawn if you miss one.
- Cut the access vector: delete leaked keys, fix SSRF/RCE, remove rogue IAM, tighten the GKE API.
- Rebuild any compromised hosts/nodes from clean images.
- Revert IAM/quota changes the attacker made.

## Recover

- **Budget alerts + quota limits** so the next spike is caught fast.
- Least-privilege SAs; no default Editor; **org policy** restricting external IPs + regions.
- SCC VM/Container Threat Detection enabled; alert on `instances.insert` bursts.
- Preserve: billing evidence, the creation events, the access vector, VPC Flow to pools.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Compute-cost spike (new region) | Mining |
| `instances.insert` / `pods.create` bursts | Miner deployment |
| Egress to mining-pool IPs/ports | Mining traffic |
| Daemonsets spreading miners | Cluster-wide mining |
| Compute created by a stolen key / metadata token | Attacker-driven spend |

## References

- Related notes: **Compute Engine**, **GKE for DFIR**, **VPC Flow Logs**, **Service Account Key Abuse**, **Metadata SSRF to SA Token Theft**, **GKE → Malicious Pod and Cryptomining**
- Cryptomining detection — https://cloud.google.com/security-command-center/docs/concepts-vm-threat-detection-overview
- Best practices to avoid cryptomining — https://cloud.google.com/architecture/prevention-detection-cryptomining-attacks
- MITRE ATT&CK: T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1496/
