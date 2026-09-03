# What is Security Command Center?

**Security Command Center (SCC)** is GCP's built-in security platform — **misconfiguration scanning + threat detection + findings**, spanning the whole org. It's the GCP counterpart to AWS GuardDuty + Security Hub and Microsoft Defender for Cloud. In IR it's often *where the case starts* (a finding) and a fast way to scope posture across projects.

## Contents

- [How It Works](#how-it-works)
- [The Detection Services](#the-detection-services)
- [Findings You'll See](#findings-youll-see)
- [How to Identify SCC in Evidence](#how-to-identify-scc-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- SCC watches your org's resources + logs and raises **findings** (misconfig or active threat).
- Tiers: **Standard** (basic + Security Health Analytics), **Premium**, **Enterprise** (adds Mandiant + more detectors + SIEM/SOAR).
- Findings appear in the **SCC console** and export to **Pub/Sub / BigQuery / the SCC API** for SIEM/SOAR.
- **Event Threat Detection (ETD)** is the key one for DFIR — it turns **Cloud Audit Logs** into threat findings (anomalous grants, exfil, disabled logging).

## The Detection Services

| Service | Detects |
|---------|---------|
| **Security Health Analytics** | Misconfigurations (public buckets, open firewall, no MFA, over-broad IAM) |
| **Event Threat Detection (ETD)** | Log-based threats: anomalous IAM grant, data exfil, disabled logging, brute force, malware IPs |
| **Container Threat Detection** | Runtime threats in GKE (suspicious binary, reverse shell) |
| **VM Threat Detection** | 🔴 Cryptomining on VMs (hypervisor-level) |
| **Web Security Scanner** | App vulns |
| **Sensitive Data Protection** | Where sensitive data (PII) lives |
| **Mandiant** (Enterprise) | Threat intel + attack-surface + IR |

## Findings You'll See

| Finding category (examples) | Means | 🔴 |
|-----------------------------|-------|----|
| `Persistence: IAM Anomalous Grant` | Unusual role grant (esp. external) | Privesc/backdoor |
| `Credential Access: External Member Added To Privileged Group` | External identity gained privilege | Backdoor |
| `Exfiltration: BigQuery Data Extraction` | Large/unusual BigQuery export | Data theft |
| `Malware: Cryptomining Bad IP` / VM TD mining | VM talking to mining pool / mining | Resource hijack |
| `Defense Evasion: Modify VPC Service Control` / disabled logging | Guardrail/logging tamper | Anti-forensics |
| `Discovery: Service Account Self-Investigation` | SA enumerating its own perms | Recon after landing |
| `Initial Access: Account Disabled Password Leak` | Leaked-credential login | Takeover |

## How to Identify SCC in Evidence

- **Console:** Security → **Security Command Center → Findings**.
- **API/CLI:** `gcloud scc findings list <org-id>`; export to BigQuery/Pub-Sub.
- Each finding links to the **source resource** + the underlying log/evidence.

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Security Command Center | GuardDuty + Security Hub + Inspector | Defender for Cloud |
| Event Threat Detection | GuardDuty (log-based) | Defender alerts |
| Security Health Analytics | Security Hub / Config | Defender CSPM / Secure Score |
| VM/Container Threat Detection | GuardDuty Runtime / Malware | Defender for Servers/Containers |
| Mandiant (Enterprise) | — | Defender XDR + TI |

## Common Use Cases

Your "normal": SCC findings triaged into a queue; posture dashboards for misconfig; ETD feeding the SIEM. On a case, SCC often provides the **first alert** and a fast **scope** (which projects/resources are affected).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Finding** | A detected issue (misconfig or threat) |
| **Source** | The detector that raised it |
| **Event Threat Detection** | Log-based threat detection |
| **Security Health Analytics** | Misconfig scanning |
| **Mute rule** | Suppress known-benign findings |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using SCC in a case | **Security Command Center → for DFIR** |
| The logs behind ETD findings | **GCP → Cloud Audit Logs** |
| Workspace-side detection | **Workspace → Alert Center & SIT** |
| Cryptomining findings end to end | **GCP → Playbooks → Cryptomining Incident** |

## Resources

- Security Command Center — https://cloud.google.com/security-command-center/docs/security-command-center-overview
- Event Threat Detection — https://cloud.google.com/security-command-center/docs/concepts-event-threat-detection-overview
- Findings & categories — https://cloud.google.com/security-command-center/docs/how-to-investigate-threats
