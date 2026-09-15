# Playbook — Metadata SSRF to SA Token Theft

An attacker with **SSRF or RCE on a Compute Engine VM (or a GKE pod)** reaches the **metadata server** (`169.254.169.254` / `metadata.google.internal`) and pulls the **attached service account's access token** — then acts as that SA across GCP. It's the GCP twin of the AWS IMDS/SSRF role-theft chain, and the Compute default SA (Editor) makes it devastating.

> **Tier 2 (cross-service).** Spans Compute Engine + Cloud Audit Logs + IAM. Read **GCP → Compute Engine** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Confirm the Token Was Stolen](#confirm-the-token-was-stolen)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **LB / Cloud Armor** | SSRF-looking request (URL pointing at metadata/internal) |
| **Audit log** | The VM's attached SA doing unexpected API calls |
| **SCC** | Anomalous SA activity from a VM |
| **VPC Flow / app logs** | The VM fetching `metadata.google.internal` then egress |

## Hypothesis

A VM/pod was made to fetch its SA token via the metadata server, and the attacker is using it. Establish the delivery (SSRF/RCE), confirm token theft, trace the SA's actions, and cut it.

## Step-by-Step Investigation

**1. Find the delivery.** LB/app logs: a request with a URL/param pointing at `169.254.169.254` / `metadata.google.internal` / `/computeMetadata/v1/.../token`. Or an RCE on the app.

**2. Identify the attached SA.** `gcloud compute instances describe <vm>` → `serviceAccounts`. 🔴 Is it the **Compute default SA** (Editor)?

**3. Trace the SA's actions.**

```bash
gcloud logging read \
 'protoPayload.authenticationInfo.principalEmail="<vm-sa>"' --freshness=7d --format=json
```

## Confirm the Token Was Stolen

| Signal | Meaning |
|--------|---------|
| SA doing **unexpected API calls** (IAM, storage, new keys) | Token abused for lateral movement |
| SA acting **from an IP that isn't the VM** | 🔴 Token **exfiltrated** off-box (strongest proof) |
| Actions **inconsistent** with the app's normal behavior | Token misuse in place |
| App had an SSRF/RCE vuln | The delivery mechanism confirmed |

## Decision Points

| Question | If yes → |
|----------|----------|
| Default Compute SA (Editor)? | Assume project-wide compromise |
| Token used off-box? | Confirmed theft — rotate SA + full IR |
| SA created keys / granted IAM? | Escalation/persistence — run **SA Key Abuse** / **IAM Privesc** |
| GKE pod (not VM)? | Check Workload Identity + node SA; run **GKE Malicious Pod** |

## Contain

```bash
# Isolate the VM and cut the token's identity
gcloud compute instances add-metadata <vm> --metadata=... # (or firewall-isolate)
gcloud iam service-accounts disable <vm-sa>               # stops the SA acting
# Snapshot for forensics BEFORE stopping
gcloud compute disks snapshot <disk> --snapshot-names=ir-<case> --zone=<z>
```

## Eradicate

- Fix the **SSRF/RCE** vulnerability in the app.
- Rebuild the VM from a clean image (don't trust a compromised host).
- Revert anything the stolen-token SA changed (IAM, new SAs/keys, resources).
- Rotate secrets the SA could reach.

## Recover

- Attach a **least-privilege SA** (never default Editor) to VMs.
- Enforce **IMDSv2-equivalent hardening**: for GKE use **Workload Identity + Metadata Concealment**; require the `Metadata-Flavor` header is already default but restrict app egress to metadata.
- No public IPs (`compute.vmExternalIpAccess`) + WAF in front of apps.
- Alert on the attached SA acting from non-VM IPs.
- Preserve: the SSRF request, the SA's activity, the disk snapshot.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| Request pointing at `metadata.google.internal` / `169.254.169.254` | SSRF attempt |
| Attached SA acting from a non-VM IP | Token exfiltrated |
| Default Compute SA (Editor) abused | Project-wide reach |
| SA minting keys / granting IAM after the SSRF | Escalation/persistence |

## References

- Related notes: **Compute Engine**, **Service Accounts**, **Cloud Load Balancing**, **GKE**, **Service Account Key Abuse**, **IAM Privilege Escalation**
- VM metadata / SA tokens — https://cloud.google.com/compute/docs/metadata/overview
- Protect against SSRF — https://cloud.google.com/compute/docs/metadata/overview#querying
- MITRE ATT&CK: T1552.005 Cloud Instance Metadata API — https://attack.mitre.org/techniques/T1552/005/
