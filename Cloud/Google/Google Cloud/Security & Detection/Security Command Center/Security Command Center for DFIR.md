# Security Command Center for DFIR

SCC is often the **entry point and the scoping tool** of a GCP case: triage the finding, pull its evidence, then pivot to the audit logs for the full story.

New to it? Read **What is Security Command Center** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Triage a Finding](#triage-a-finding)
- [Collect It](#collect-it)
- [Scope with SCC](#scope-with-scc)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **SCC Findings** | Threats + misconfig, with linked resource + evidence | Triage entry |
| **SCC API / BigQuery export** | Findings programmatically | Hunting/automation |
| **ETD findings** | Log-derived threats | Fast pointer to the audit event |

## Triage a Finding

| Step | Do this |
|------|---------|
| 1. Read the finding | Category, severity, resource, principal, timestamp |
| 2. Pull the evidence | The linked audit-log entry / resource state |
| 3. Confirm true positive | Cross the audit log for the underlying action |
| 4. Scope | Other findings on the same principal/resource/IP |
| 5. Pivot | To the service note for the affected resource |

## Collect It

```bash
# Active findings for the org (or filtered)
gcloud scc findings list <ORG_ID> --filter='state="ACTIVE" AND category="IAM Anomalous Grant"'

# Findings tied to one resource / principal
gcloud scc findings list <ORG_ID> --filter='resourceName:"//compute.googleapis.com/.../web01"'
```

> **Console:** Security Command Center → **Findings** → filter by category/severity/resource → open → follow the evidence link.

## Scope with SCC

| Use SCC to answer | How |
|-------------------|-----|
| What else did this principal trigger? | Filter findings by principal |
| Which projects are affected? | Group findings by project |
| Is this a campaign? | Same category/IP across resources |
| What's the posture gap? | Security Health Analytics on the resource type |

## Respond

| Goal | Action |
|------|--------|
| Act on the threat | Follow the matching service/playbook note (contain the SA/VM/bucket) |
| Suppress noise | Mute rules for known-benign findings (carefully) |
| Track | Set finding state; export to SIEM/ticketing |
| Preserve | Export findings + linked evidence |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable SCC Premium/Enterprise** (ETD, Container/VM TD) | Real threat detection, not just posture |
| **Export findings → Pub/Sub → SIEM/SOAR** | Central triage + automation |
| **Turn on Security Health Analytics** org-wide | Continuous misconfig detection |
| **Tune mute rules** narrowly | Signal without alert fatigue |
| **Alert** on high-severity ETD categories | Fast response |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `IAM Anomalous Grant` (external member) | Privesc/backdoor |
| `BigQuery Data Extraction` (large/unusual) | Exfil |
| VM/Container mining detection | Resource hijack |
| `Modify VPC Service Control` / disabled logging | Defense evasion |
| `Account Disabled Password Leak` login | Takeover |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| SCC services + finding types | **Security Command Center → What is** |
| The audit logs behind findings | **GCP → Cloud Audit Logs** |
| Workspace-side detection | **Workspace → Alert Center & SIT** |
| Cryptomining end to end | **GCP → Playbooks → Cryptomining Incident** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- Investigate threats — https://cloud.google.com/security-command-center/docs/how-to-investigate-threats
- SCC findings API — https://cloud.google.com/security-command-center/docs/reference/rest
- Export findings — https://cloud.google.com/security-command-center/docs/how-to-export-data
- MITRE ATT&CK Cloud — https://attack.mitre.org/matrices/enterprise/cloud/
