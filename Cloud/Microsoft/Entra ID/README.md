# Entra ID DFIR Field Guide

**Entra ID** (formerly Azure AD) is the **identity backbone** of the whole Microsoft cloud — the directory both **M365** and **Azure** trust to say who you are. Because one Entra token opens both, **almost every Microsoft investigation starts here.**

Written for the full range from associate analyst to principal DFIR consultant: plain enough to onboard a junior, deep enough that a principal finds nothing hand-waved. Primary lens = hands-on the platform (Entra portal, Graph/PowerShell, KQL in Log Analytics/Sentinel); SecOps UDM appears only as a small end-of-note aid.

## How to Use This Guide

**New to Entra DFIR?** Start with the Microsoft-level foundation notes:

1. **[00 - Microsoft Cloud Overview & Terminology](../00%20-%20Microsoft%20Cloud%20Overview%20%26%20Terminology.md)** — tenant, subscriptions, the two RBAC worlds, where each log lives.
2. **[01 - Entra ID & Identities](../01%20-%20Entra%20ID%20%26%20Identities.md)** — the decoder ring: user vs guest vs service principal vs managed identity, and tokens.
3. **[02 - Investigating Microsoft (start here)](../02%20-%20Investigating%20Microsoft%20(start%20here).md)** — the first-hour triage flow.

**Working an incident?** Jump from the router below.

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A risky / impossible-travel sign-in | **[Sign-in Logs for DFIR](Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| MFA bypass / token replay / AiTM | **[Token Theft and AiTM](Playbooks/Token%20Theft%20and%20AiTM.md)** |
| A new/consented app reading mail or files | **[Illicit Consent Grant](Playbooks/Illicit%20Consent%20Grant.md)** · **[Applications & Service Principals](Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| A secret/cert added to an app | **[Service Principal Credential Abuse](Playbooks/Service%20Principal%20Credential%20Abuse.md)** |
| A burst of failed sign-ins | **[Password Spray](Playbooks/Password%20Spray.md)** |
| Someone got Global Admin / a privileged role | **[Privileged Role Escalation](Playbooks/Privileged%20Role%20Escalation.md)** · **[Roles & PIM](Roles%20%26%20PIM/Roles%20%26%20PIM%20for%20DFIR.md)** |
| A directory change (user/app/role/consent) | **[Audit Logs for DFIR](Audit%20Logs/Audit%20Logs%20for%20DFIR.md)** |
| "Why didn't MFA/CA stop this?" | **[Conditional Access & MFA for DFIR](Conditional%20Access%20%26%20MFA/Conditional%20Access%20%26%20MFA%20for%20DFIR.md)** |
| A risky-user / leaked-credential alert | **[Identity Protection for DFIR](Identity%20Protection/Identity%20Protection%20for%20DFIR.md)** |

## Structure

```
Microsoft/Entra ID/
├── Sign-in Logs/                  ← authentications (the front-door log)
├── Audit Logs/                    ← directory changes (roles, apps, consent)
├── Conditional Access & MFA/      ← the gate every token passes
├── Applications & Service Principals/ ← the non-human "who" (apps, consent, credentials)
├── Roles & PIM/                   ← directory roles + just-in-time privilege
├── Identity Protection/           ← the managed risk engine
└── Playbooks/                     ← Illicit Consent · Token Theft/AiTM · Password Spray
                                      · SP Credential Abuse · Privileged Role Escalation
```

Each service folder holds **What is `<svc>`** + **`<svc>` for DFIR**.

## Coverage

| Service | Answers |
|---------|---------|
| **Sign-in Logs** | Who authenticated, from where, MFA/CA outcome (4 logs: interactive/non-interactive/SP/managed-identity) |
| **Audit Logs** | What changed in the directory (roles, apps, consent, credentials) |
| **Conditional Access & MFA** | Whether a sign-in should have been stopped, and why it wasn't |
| **Applications & Service Principals** | App vs SP objects, delegated vs application permissions, consent, credentials |
| **Roles & PIM** | Directory roles (Global Admin), PIM eligible vs active, the `elevateAccess` bridge |
| **Identity Protection** | Managed risk detections (leaked creds, anomalous token, impossible travel) |

## The Recurring Themes

1. **Identity is the front door** — one token opens both M365 and Azure; start every case here.
2. **Check all four sign-in logs** — attackers hide in non-interactive / service-principal / managed-identity.
3. **Tokens outlive passwords** — you must **revoke refresh tokens**, not just reset the password.
4. **Apps are the stealthy "who"** — no user, no MFA, a separate log; consent + credential adds are the quiet takeover.
5. **Two RBAC worlds** — Global Admin (directory) ≠ Owner (Azure); the bridge is `elevateAccess`.

## Related

- **[Microsoft → 00 Overview](../00%20-%20Microsoft%20Cloud%20Overview%20%26%20Terminology.md)** · **[01 Identities](../01%20-%20Entra%20ID%20%26%20Identities.md)** · **[02 Investigating](../02%20-%20Investigating%20Microsoft%20(start%20here).md)**
- **[M365](../M365/)** and **[Azure](../Azure/)** — the two clouds Entra fronts
- **External:** [Entra monitoring & health](https://learn.microsoft.com/entra/identity/monitoring-health/) · [MITRE ATT&CK Cloud](https://attack.mitre.org/matrices/enterprise/cloud/)
