# Google Workspace — DFIR

The **SaaS** half of Google: Gmail, Drive/Docs, Meet, Calendar, Chat — all riding on **Cloud Identity**. This is the #1 target for **account takeover, BEC, illicit OAuth grants, and data exfil**. Master log family: the **Workspace audit logs** (Admin, Login, Drive, Gmail, Token…), read in the **Admin console → Reporting → Audit and investigation** or the **Reports API**.

> Start with the platform foundation notes: **[00 Overview & Terminology](../00%20-%20Google%20Cloud%20%26%20Workspace%20Overview%20%26%20Terminology.md)** · **[01 Google Identities](../01%20-%20Google%20Identities.md)** · **[02 Investigating Google](../02%20-%20Investigating%20Google%20(start%20here).md)**.

## Services

| Service | What it covers | Open |
|---------|----------------|------|
| **Admin Audit Log** | Who changed the org (admins, 2SV, DWD, routing) | [What is](Admin%20Audit%20Log/What%20is%20the%20Admin%20Audit%20Log.md) · [for DFIR](Admin%20Audit%20Log/Admin%20Audit%20Log%20for%20DFIR.md) |
| **Login & Auth Audit** | Sign-ins, MFA, suspicious/leaked-password | [What is](Login%20%26%20Auth%20Audit/What%20is%20the%20Login%20%26%20Auth%20Audit.md) · [for DFIR](Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md) |
| **Gmail** | Mail evidence + mailbox persistence (filters/forwarding) | [What is](Gmail/What%20is%20Gmail%20(for%20DFIR).md) · [for DFIR](Gmail/Gmail%20for%20DFIR.md) |
| **Drive & Docs Audit** | File access, sharing, exfil | [What is](Drive%20%26%20Docs%20Audit/What%20is%20the%20Drive%20Audit.md) · [for DFIR](Drive%20%26%20Docs%20Audit/Drive%20Audit%20for%20DFIR.md) |
| **OAuth & Third-Party Apps** | Consent grants + domain-wide delegation | [What is](OAuth%20%26%20Third-Party%20Apps/What%20is%20OAuth%20%26%20Third-Party%20Apps.md) · [for DFIR](OAuth%20%26%20Third-Party%20Apps/OAuth%20%26%20Third-Party%20Apps%20for%20DFIR.md) |
| **Alert Center & SIT** | Detection + bulk remediation | [What is](Alert%20Center%20%26%20Security%20Investigation%20Tool/What%20is%20Alert%20Center%20%26%20SIT.md) · [for DFIR](Alert%20Center%20%26%20Security%20Investigation%20Tool/Alert%20Center%20%26%20SIT%20for%20DFIR.md) |

## Playbooks

| Scenario | Open |
|----------|------|
| A phished OAuth app reading mail/Drive | [Illicit OAuth Grant](Playbooks/Illicit%20OAuth%20Grant.md) |
| A compromised mailbox / payment fraud | [BEC and Mail Forwarding](Playbooks/BEC%20and%20Mail%20Forwarding.md) |
| Bulk download / external sharing exfil | [Mass Drive Exfiltration](Playbooks/Mass%20Drive%20Exfiltration.md) |
| A compromised account (phish/spray/token) | [Account Takeover](Playbooks/Account%20Takeover.md) |

## Recurring Themes

1. **Start in identity** — the Login audit is the first hour; one account opens Workspace *and* GCP.
2. **Tokens/grants outlive passwords** — revoke **sessions + OAuth grants**, not just the password.
3. **Mail persistence isn't in the audit log** — pull filters/forwarding/delegation from **Gmail settings** (Gmail API / GAM).
4. **Domain-wide delegation** is a GCP service account holding a **Workspace-wide** key — audit it.
5. **Retention ~6 months** — export logs to **BigQuery** before evidence ages out.

## Related

- **[Google Cloud (GCP)](../Google%20Cloud/README.md)** — the infrastructure half (same identity fabric)
- **[Google → 01 Google Identities](../01%20-%20Google%20Identities.md)** — service accounts, DWD, tokens
- **[Microsoft → M365](../../Microsoft/M365/README.md)** — the equivalent SaaS field guide
