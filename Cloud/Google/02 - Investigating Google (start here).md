# Investigating Google (start here)

You've got an alert in a Google environment — a suspicious login, a mail-forwarding rule, a new service-account key, a VM doing something odd. This note is the **first-hour triage flow**: what to establish, in what order, and which note to open next.

The golden rule for Google: **start in identity.** Because one Google account (or one stolen service-account key) opens both Workspace and GCP, almost every case begins with "whose identity, and what did it touch?"

## Contents

- [The First Five Questions](#the-first-five-questions)
- [Which Cloud Am I In?](#which-cloud-am-i-in)
- [The Master Logs — Which One Answers What](#the-master-logs--which-one-answers-what)
- [Confirm You Even Have Evidence](#confirm-you-even-have-evidence)
- [The Triage Flow](#the-triage-flow)
- [Situation → Open This](#situation--open-this)
- [First-Hour Containment Checklist](#first-hour-containment-checklist)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The First Five Questions

Answer these before you go deep. They scope everything:

| # | Question | Where to look |
|---|----------|---------------|
| 1 | **Which identity?** A user, a service account, an impersonation, or a federated workload? | Cloud Audit Logs · **01 - Google Identities** |
| 2 | **Which cloud?** Workspace (mail/files), GCP (infra), or the directory itself? | The resource in the alert (see below) |
| 3 | **From where?** IP, geo, ASN, user-agent — known or new? | `requestMetadata.callerIp` / Login audit |
| 4 | **Was it a key, an impersonation, or a human login?** | `serviceAccountKeyName` / `serviceAccountDelegationInfo` / Login audit MFA |
| 5 | **Do I even have the logs?** Data Access on? Sinks/exports configured? | **Confirm evidence** below — do this early |

## Which Cloud Am I In?

The resource in the alert tells you which cloud — and which log — to work:

| If the alert is about… | You're in… | Master log | Start note |
|------------------------|-----------|-----------|-----------|
| A sign-in, MFA, suspicious login, a Workspace admin change | **Workspace** | Login / Admin audit | **Workspace → Login & Auth Audit** / **Admin Audit Log** |
| An email, forwarding rule, filter, Drive file/share | **Workspace** | Gmail / Drive audit | **Workspace → Gmail** / **Drive & Docs Audit** |
| A VM, GCS bucket, GKE cluster, IAM/role grant, an SA key | **GCP** | Cloud Audit Logs | **GCP → Cloud Audit Logs** |

> Many real cases span **both** (phished user → mail rules → then a stolen SA key into GCP). Work them in identity → Workspace → GCP order, following the credential.

## The Master Logs — Which One Answers What

Google splits its audit trail across the two clouds. Point the right question at the right log:

| Question | Log | Read it with |
|----------|-----|-------------|
| "Who signed in, from where, MFA how?" | **Workspace Login audit** | Admin console → Reporting → Audit → Login · Reports API |
| "Who changed a user/role/setting in Workspace?" | **Workspace Admin audit** | Admin console → Audit → Admin |
| "What happened in mail / Drive?" | **Gmail / Drive audit** | Admin console → Audit (Drive) · Email Log Search / Gmail logs in BigQuery |
| "What GCP resource was created/changed, or role granted?" | **Cloud Audit Logs — Admin Activity** | Console → Logging · `gcloud logging read` |
| "Which object/row was actually read?" | **Cloud Audit Logs — Data Access** | Logging — *only if enabled* |

> 🔴 Don't fight one log for an answer it doesn't hold. The Login audit won't tell you what a GCS object read did; Admin Activity won't show data reads unless **Data Access logging** is on. Match the question to the log.

## Confirm You Even Have Evidence

Google's defaults have real gaps: **Data Access logging is OFF**, and retention is bounded (`_Default` 30 days; Workspace ~6 months). **Do this first** — an older or read-only incident may have no native logs left:

```bash
# GCP: is Data Access logging enabled anywhere? (look in the org/project IAM audit config)
gcloud projects get-iam-policy <project-id> --format=json | jq '.auditConfigs'

# GCP: are logs routed anywhere long-term? (sinks to BigQuery / GCS / another project)
gcloud logging sinks list --project=<project-id>

# GCP: what log buckets/retention exist?
gcloud logging buckets list --location=global --project=<project-id>
```

> **Console:** GCP → **Logging → Logs Storage** (buckets/retention) and **Log Router** (sinks). Workspace → Admin console → **Reporting → Audit** (and any **BigQuery export** / Cloud Logging sharing). If a **security data lake / SIEM sink** exists (BigQuery, Chronicle/SecOps), that's usually your long-retention gold mine — check it early. 🔴 No sink + Data Access off + incident older than the window = evidence gap; document it and pivot to whatever remains (mail contents, endpoint, backups).

## The Triage Flow

| Step | Do this | Note |
|------|---------|------|
| 1. **Confirm logging** | Check Data Access + retention/sinks before anything ages out | *Confirm evidence* above |
| 2. **Anchor the identity** | Pull the full timeline for the principal. User, SA, or impersonation? | **01 - Google Identities** |
| 3. **Classify the credential** | Human login (Login audit) vs SA **key** (`serviceAccountKeyName`) vs **impersonation** (`serviceAccountDelegationInfo`) | **01 - Google Identities** |
| 4. **Read the IAM/admin changes** | Any `SetIamPolicy`, new SA key, role grant, DWD grant, admin change in the window? | **GCP → Cloud IAM** · **Workspace → Admin Audit Log** |
| 5. **Follow into Workspace** | Forwarding, filters, mass Drive download, OAuth grants? | **Workspace → Gmail** / **Drive** / **OAuth & Third-Party Apps** |
| 6. **Follow into GCP** | New resource, SA impersonation, metadata-token use, GKE pod? | **GCP → Cloud Audit Logs** |
| 7. **Split human vs workload** | Human+MFA login = person; SA key / impersonation = workload/automation | **01 - Google Identities** |
| 8. **Contain the credential, not just the account** | Revoke sessions + delete SA keys + remove impersonation grants | *Checklist* below |

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A suspicious / impossible-travel login | **[Workspace → Login & Auth Audit](Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)** |
| MFA bypass / token / session-cookie theft | **[Account Takeover](Google%20Workspace/Playbooks/Account%20Takeover.md)** |
| A new/consented third-party app reading mail or Drive | **[Illicit OAuth Grant](Google%20Workspace/Playbooks/Illicit%20OAuth%20Grant.md)** · **[OAuth & Third-Party Apps](Google%20Workspace/OAuth%20%26%20Third-Party%20Apps/OAuth%20%26%20Third-Party%20Apps%20for%20DFIR.md)** |
| A compromised mailbox / forwarding / filters | **[BEC and Mail Forwarding](Google%20Workspace/Playbooks/BEC%20and%20Mail%20Forwarding.md)** · **[Gmail for DFIR](Google%20Workspace/Gmail/Gmail%20for%20DFIR.md)** |
| Mass file download / external Drive sharing | **[Mass Drive Exfiltration](Google%20Workspace/Playbooks/Mass%20Drive%20Exfiltration.md)** |
| A new service-account key / stolen SA credential | **[Service Account Key Abuse](Google%20Cloud/Playbooks/Service%20Account%20Key%20Abuse.md)** · **[Service Accounts](Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)** |
| A metadata/SSRF token stolen from a VM | **[Metadata SSRF to SA Token Theft](Google%20Cloud/Playbooks/Metadata%20SSRF%20to%20SA%20Token%20Theft.md)** |
| Someone got Owner / org-admin / escalated IAM | **[IAM Privilege Escalation](Google%20Cloud/Playbooks/IAM%20Privilege%20Escalation.md)** · **[Cloud IAM](Google%20Cloud/Identity%20%26%20Access/Cloud%20IAM/Cloud%20IAM%20for%20DFIR.md)** |
| A publicly exposed GCS bucket | **[Public GCS Bucket](Google%20Cloud/Storage/Cloud%20Storage/Playbooks/Public%20GCS%20Bucket.md)** |
| A VM mining / a cost spike | **[Cryptomining Incident](Google%20Cloud/Playbooks/Cryptomining%20Incident.md)** |
| A new/crypto pod in GKE | **[Malicious Pod and Cryptomining](Google%20Cloud/Serverless%20%26%20Containers/GKE/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** |
| Data pulled from GCS / BigQuery | **[Data Exfiltration](Google%20Cloud/Playbooks/Data%20Exfiltration.md)** |

## First-Hour Containment Checklist

Do these to actually cut a compromised identity — **remember tokens and keys outlive passwords**:

```bash
# --- If a USER account is compromised (Workspace) ---
# 1. Reset password AND sign the user out everywhere (revokes sessions/tokens)
#    Admin console → Users → (user) → Reset password + "Sign out"
gcloud identity ... # or via Admin SDK; console is fastest here
# 2. Revoke OAuth tokens/app grants the attacker may hold
#    Admin console → Users → (user) → Security → Connected applications → remove

# --- If a SERVICE ACCOUNT is compromised (GCP) ---
# 3. Disable the SA (stops it acting) then delete leaked keys
gcloud iam service-accounts disable sa@proj.iam.gserviceaccount.com
gcloud iam service-accounts keys list --iam-account=sa@proj.iam.gserviceaccount.com
gcloud iam service-accounts keys delete <KEY_ID> --iam-account=sa@proj.iam.gserviceaccount.com
# 4. Remove any impersonation grant (TokenCreator) the attacker abused
gcloud iam service-accounts remove-iam-policy-binding sa@proj.iam.gserviceaccount.com \
  --member='user:attacker@...' --role='roles/iam.serviceAccountTokenCreator'
```

| Goal | Action |
|------|--------|
| Kill a user's silent re-auth | **Reset password + "Sign out" everywhere** (revokes sessions) — *and* remove OAuth app grants |
| Stop a compromised SA | **Disable the SA**, **delete its keys**, **remove impersonation grants** |
| Kill a stolen metadata token | Treat the **VM** as compromised; stop/isolate it, rotate its SA |
| Neutralize a rogue app | Remove the **OAuth grant** / block the app in the Admin console |
| Close the gap | Enable **Data Access logging** + a long-retention **sink** before more ages out |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The layout: org, projects, two admin worlds | **Google → 00 Overview & Terminology** |
| Who the identities are + keys/impersonation/tokens | **Google → 01 Google Identities** |
| The GCP master log | **GCP → Cloud Audit Logs** |
| Workspace login/admin evidence | **Workspace → Login & Auth Audit** / **Admin Audit Log** |
| The same actor across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Cloud Audit Logs overview — https://cloud.google.com/logging/docs/audit
- Enable Data Access audit logs — https://cloud.google.com/logging/docs/audit/configure-data-access
- Workspace audit & investigation — https://support.google.com/a/answer/9725452
- Revoke user access / sign-out — https://support.google.com/a/answer/33314
- MITRE ATT&CK Cloud (Google Workspace / IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/
