# Playbook — Data Exfiltration

An attacker (or insider) pulls sensitive data out of GCP — from **Cloud Storage**, **BigQuery**, or **Cloud SQL** — by reading it, exporting it to a bucket/project they control, or sharing it externally. This playbook establishes what left, by whom, how, and whether the exfil perimeter held.

> **Tier 2 (cross-service).** Spans GCS + BigQuery + Cloud SQL + VPC-SC. Read the relevant service note first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Quantify What Left](#quantify-what-left)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **SCC** | `Exfiltration: BigQuery Data Extraction` / anomalous access |
| **Audit log** | Extract/copy jobs, bulk object reads, dataset shared externally |
| **VPC-SC** | Policy Denied spikes (blocked exfil attempts) |
| **DLP** | Sensitive-data movement |

## Hypothesis

Sensitive data was accessed and moved out. Identify the source (GCS/BigQuery/Cloud SQL), the actor and method, the destination, the volume/sensitivity, and whether the perimeter contained it.

## Step-by-Step Investigation

**1. Identify the source + method.**

| Source | Exfil method | Evidence |
|--------|--------------|----------|
| **GCS** | Bucket made public / bulk `objects.get` / external grant | `setIamPermissions`, Data Access reads |
| **BigQuery** | Extract job → GCS, copy to external project, dataset shared | jobChange/extract, dataset `SetIamPolicy` |
| **Cloud SQL** | `instances.export` / `clone` | Admin Activity export events |

**2. Attribute.** The `principalEmail` (user or SA), `callerIp`, and credential type (key/impersonation).

**3. Find the destination.** The GCS URI of an extract/export; the external project of a copy; the external member on a share.

## Quantify What Left

| Question | Evidence |
|----------|----------|
| Which data? | Resource names in the read/extract/export events |
| How much? | BigQuery `total_bytes_processed`; GCS object counts; export sizes |
| To where? | Extract/export destinations; external grantees |
| Was it sensitive? | DLP labels / policy tags / content classification |
| Did the perimeter block it? | VPC-SC Policy Denied entries |

## Decision Points

| Question | If yes → |
|----------|----------|
| Sensitive/regulated data confirmed out? | Data breach — legal/comms/regulatory |
| Via a stolen SA/key? | Run **SA Key Abuse** / **Impersonation** |
| Insider? | HR/legal; preserve for litigation |
| External destination project? | Attempt provider takedown; identify the account |

## Contain

- **GCS:** re-privatize; enable PAP; revoke external grants (→ Public GCS Bucket).
- **BigQuery:** remove dataset shares; disable rogue scheduled queries; cut the principal's access.
- **Cloud SQL:** close public IP; reset DB users.
- Cut the identity (disable SA / delete keys / reset user); block the destination where possible.

## Eradicate

- Remove all attacker access paths (IAM, shares, exports, scheduled jobs).
- Rotate secrets/keys that were in exposed data.
- Fix the vector (stolen cred, over-broad IAM, missing perimeter).

## Recover

- **VPC Service Controls** around GCS/BigQuery (blocks exfil outside the perimeter).
- Least-privilege data IAM; authorized views; column-level security.
- Enable **Data Access logging** on sensitive services (GCS especially).
- Alert on extracts/copies/external shares + Policy Denied spikes.
- Preserve: the access + movement events, destinations, volumes, and DLP evidence.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| BigQuery extract/copy to an external project/bucket | Exfil |
| GCS bucket made public / bulk anonymous reads | Exposure/theft |
| Dataset shared with an external principal | External access |
| Cloud SQL `export`/`clone` to an unfamiliar target | DB exfil |
| VPC-SC Policy Denied spike | Blocked exfil attempts (or probing) |

## References

- Related notes: **Cloud Storage**, **BigQuery**, **Cloud SQL**, **VPC (VPC-SC)**, **Cloud Audit Logs**, **Public GCS Bucket**
- VPC Service Controls — https://cloud.google.com/vpc-service-controls/docs/overview
- BigQuery data exfiltration detection — https://cloud.google.com/security-command-center/docs/how-to-investigate-threats
- MITRE ATT&CK: T1537 Transfer to Cloud Account / T1530 Data from Cloud Storage — https://attack.mitre.org/techniques/T1537/
