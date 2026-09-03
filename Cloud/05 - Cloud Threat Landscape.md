# Cloud Threat Landscape

Who attacks cloud environments, what they're after, and the handful of kill chains that recur across nearly every case. This is the **threat-informed** backdrop for the whole guide: read it to know what you're most likely walking into, so your triage starts with the right hypotheses.

## Contents

- [What Attackers Are After](#what-attackers-are-after)
- [The Actor Archetypes](#the-actor-archetypes)
- [The Recurring Kill Chain](#the-recurring-kill-chain)
- [Top Entry Points](#top-entry-points)
- [Top Techniques by Provider](#top-techniques-by-provider)
- [Notable Real-World Patterns](#notable-real-world-patterns)
- [Where the Money Goes (Impact)](#where-the-money-goes-impact)
- [What This Means for Triage](#what-this-means-for-triage)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## What Attackers Are After

| Goal | Looks like | Most-hit services |
|------|-----------|-------------------|
| **Free compute (cryptomining)** | Sudden GPU/large instances, cost spike, mining pool traffic | EC2/Compute Engine/VMs, EKS/AKS/GKE, Lambda |
| **Data theft** | Bulk reads, snapshot/DB share-outs, storage enumeration | S3/GCS/Blob, RDS/Cloud SQL/BigQuery, secrets |
| **Credential harvesting** | Secret-store reads, key creation, token minting | Secrets Manager/Key Vault/Secret Manager, KMS, IAM |
| **Extortion (ransom/destruction)** | Key deletion, mass delete, re-encryption, backup wipe | KMS, S3/GCS, snapshots, databases |
| **Business Email Compromise** | Mail rules, forwarding, OAuth grants, fraud | M365 Exchange, Google Workspace Gmail |
| **Foothold for resale (access brokers)** | Persistence, new creds/identities, quiet recon | IAM/Entra/Cloud IAM, federation |

## The Actor Archetypes

| Archetype | Motivation | Signature moves |
|-----------|-----------|-----------------|
| **Opportunistic cryptojackers** | Money via stolen compute | Scan for leaked keys/exposed creds → spin big instances → mine. Fast, noisy, automated. |
| **Financially-motivated intrusion crews** | Ransom/extortion, data theft | Identity compromise → recon → privesc → exfil → destroy backups & keys → extort. |
| **Identity-focused crews (e.g. "Scattered Spider"-style)** | Access + extortion | Social-engineer help desk/MFA, hijack SSO/IdP, ride federation into cloud, disable logging. |
| **Access brokers** | Sell the foothold | Establish quiet persistence + fresh creds, minimize noise, then hand off. |
| **Nation-state** | Espionage, long dwell | Stealthy token/consent abuse, service-principal/OAuth persistence, careful log evasion. |
| **Insiders** | Data/sabotage | Use legitimate access outside normal pattern; hardest to spot without baselines. |

## The Recurring Kill Chain

Across archetypes, most cloud intrusions walk the same path — map your evidence to it:

```
1. Initial Access   leaked key / phish+MFA-bypass / exposed service / SSRF to metadata
2. Recon            enumerate identities, permissions, resources (ListRoles, describe*, Get-IAM)
3. Priv Esc         attach admin policy, edit trust policy, consent grant, impersonate SA
4. Persistence      new keys/users/SP creds, OAuth app, SSM association, mail rule, federation
5. Defense Evasion  disable logging/detection, delete findings, unused regions
6. Collection/Exfil bulk storage/db reads, snapshot/secret export, replication out
7. Impact           mine, ransom (delete/encrypt keys & backups), fraud (BEC)
```

> The value of the chain on a live case: whichever stage the alert caught, you know to **look backward** (how did they get here?) and **forward** (what's the next stage — did they persist? exfil? destroy?).

## Top Entry Points

Ranked by how often they start real cloud cases:

1. **Leaked long-lived credentials** — keys/secrets in git, laptops, CI logs, public repos. `AKIA`/SA-JSON/SP-secret harvested by scanners in *minutes*.
2. **Identity attacks on humans** — phishing with **MFA-bypass (AiTM)**, MFA fatigue, password spray, help-desk social engineering.
3. **Exposed resources** — public buckets, open management ports, exposed dashboards/APIs, unauthenticated services.
4. **SSRF to the metadata service** — app flaw → `169.254.169.254` → instance role creds (the Capital One pattern).
5. **OAuth / consent abuse** — illicit app consent grants that persist without a password.
6. **Over-broad federation/OIDC trust** — CI pipelines or WIF pools trusting too much.

## Top Techniques by Provider

| Technique | AWS | Azure/Entra/M365 | Google |
|-----------|-----|------------------|--------|
| Metadata SSRF → creds | IMDSv1 SSRF | Azure IMDS SSRF | GCE metadata SSRF |
| Priv-esc via policy | `AttachUserPolicy`, `PassRole` | Directory-role / RBAC add, PIM abuse | IAM binding, `actAs`, SA impersonation |
| Persistence via identity | New access key, OIDC provider | **OAuth app / SP credential**, federated cred | **SA key**, domain-wide delegation |
| SSH-less execution | **SSM Run Command** | **Run Command** | startup scripts / IAP |
| Log evasion | `StopLogging`, `DeleteTrail` | disable diagnostic settings, purge | disable sink / audit config |
| Data destruction | KMS `ScheduleKeyDeletion`, S3 delete | Key Vault purge, blob delete | KMS destroy, GCS delete |
| Mail/BEC | (n/a) | inbox rules, forwarding, consent | filters, forwarding, delegation |

## Notable Real-World Patterns

*(Patterns, not a case archive — recognize the shape.)*

- **SSRF → metadata → S3 (Capital One class).** App SSRF steals the instance role; role reads storage from outside AWS. → **AWS IMDS SSRF to Role Theft**.
- **Identity/SSO takeover crews.** Help-desk social engineering + MFA reset → hijack SSO → ride federation into cloud → disable EDR/logging → extort. → identity-first triage, IdP logs.
- **Illicit OAuth consent.** A malicious app gets a user (or admin) to consent; the app token persists mailbox/Drive access with no password and survives password resets. → **Entra Illicit Consent Grant**, **Workspace Illicit OAuth Grant**.
- **Leaked-key cryptojacking.** Scanner finds a committed key → mass large/GPU instances across unused regions within minutes. → **AWS Cryptomining Incident**.
- **Cloud ransomware.** Attacker deletes/disables KMS keys and wipes snapshots/backups, then extorts — no host malware needed. → **Ransomware and Data Destruction**.

## Where the Money Goes (Impact)

- **Cryptomining** — direct cloud-bill theft; often the *only* goal for opportunists.
- **Data extortion** — steal then threaten to leak; storage + DB + secrets.
- **Ransom by denial** — destroy keys/backups so *you* can't read your own data.
- **Fraud** — BEC wire fraud, gift-card/invoice scams from a trusted mailbox.

## What This Means for Triage

- **Start with identity.** Most cases begin with a credential or a human — decode the "who" first (→ 01).
- **Assume the chain continues.** An alert is one stage; check persistence, evasion, and exfil around it.
- **Sweep all regions/accounts.** Opportunists and evasion both hide in the unwatched ones.
- **Confirm logging integrity** across your window — evasion is early and common.
- **Follow the value** — compute (mining), storage/db (data), secrets/keys (pivot + destruction).

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The shared model & where evidence lives | **00 Cloud Fundamentals** |
| Technique → evidence per provider | **00b ATT&CK Cloud to Evidence Map** |
| One actor across clouds | **03 Cross-Cloud Correlation** |
| A full multi-cloud intrusion | **Cross-Cloud Investigations → Multi-Cloud Intrusion Playbook** |
| Provider playbooks for each pattern | **AWS/Microsoft/Google → Playbooks** |

## Resources

- MITRE ATT&CK Cloud matrix — https://attack.mitre.org/matrices/enterprise/cloud/
- CISA — Cloud security guidance — https://www.cisa.gov/topics/cybersecurity-best-practices/cloud-security
- Mandiant / Google Cloud Threat Intelligence — https://cloud.google.com/security/resources/threat-intelligence
- The DFIR Report — https://thedfirreport.com/
