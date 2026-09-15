# Playbook — Token Theft and AiTM

The modern MFA bypass. In an **adversary-in-the-middle (AiTM)** phish, the victim lands on a proxy of the real login page, types their password, **and completes MFA** — and the attacker captures the resulting **token**, MFA already baked in. They replay it, no password reuse, no MFA prompt. This playbook detects the theft, proves the replay, and cuts the session.

> **Tier 2 (cross-service).** Spans sign-in logs + Identity Protection + M365. Read **Entra → 01 Identities** (tokens) and **Sign-in Logs** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Proving Token Replay](#proving-token-replay)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Identity Protection** | `anomalousToken`, `tokenIssuerAnomaly`, impossible travel |
| **Sign-in logs** | MFA "satisfied by claim in token" from a new device/IP |
| **User report** | Clicked a link, entered creds + approved MFA, "site looked normal" |
| **Mailbox activity** | New inbox rules / sends right after a sign-in from a new ASN |

## Hypothesis

The attacker holds a **stolen access + refresh token** (not the password). They're operating as the user with MFA already satisfied. Establish the theft time, what they did with the session, and revoke the tokens.

## Step-by-Step Investigation

**1. Find the suspicious sign-in.** Success from a **new IP/ASN/country**, `AuthenticationDetails` showing MFA **satisfied by a prior token/claim** rather than freshly performed.

```kql
SigninLogs
| where UserPrincipalName == "alice@contoso.com"
| where TimeGenerated > ago(14d)
| project TimeGenerated, IPAddress, Location, AuthenticationRequirement, AuthenticationDetails, DeviceDetail
| order by TimeGenerated asc
```

**2. Check the non-interactive log.** 🔴 Replayed tokens generate **non-interactive** sign-ins with no interactive parent.

```kql
AADNonInteractiveUserSignInLogs
| where UserPrincipalName == "alice@contoso.com" and TimeGenerated > ago(14d)
| project TimeGenerated, IPAddress, AppDisplayName, ResourceDisplayName
```

**3. Identify the phish.** The delivering email (Defender / message trace) and the AiTM domain.

**4. Follow the session's actions.** Everything the attacker did with the token: inbox rules, forwarding, file access, app consents, sends. Correlate the **attacker IP/ASN** across UAL + sign-in logs.

## Proving Token Replay

| Signal | Why it's replay |
|--------|-----------------|
| MFA "satisfied by claim in the token" from a **new device** | The MFA happened elsewhere (the proxy), not here |
| Non-interactive sign-in from the attacker IP with **no** interactive login | The attacker never authenticated interactively — they replayed |
| Same session/token used from two far-apart geos | Token used by victim *and* attacker |
| Identity Protection `anomalousToken` | Microsoft's own token-theft signal |

## Decision Points

| Question | If yes → |
|----------|----------|
| Did they establish persistence? | Inbox rules, app consent, new MFA method → eradicate each |
| Business email compromise? | Forwarding/BEC → run the **BEC** playbook |
| Admin account? | Check for role grants + `elevateAccess` → **Privileged Role Escalation** |
| Multiple users hit? | AiTM campaign — hunt the phishing domain tenant-wide |

## Contain

```powershell
Revoke-MgUserSignInSession -UserId alice@contoso.com   # invalidate refresh tokens
Update-MgUser -UserId alice@contoso.com -AccountEnabled:$false
```
Then force password reset **after** revocation, and block the AiTM domain/IP.

> 🔴 **Revoke tokens BEFORE resetting the password** — a valid refresh token mints a new session right through a password change. Enable **CAE** for near-real-time enforcement.

## Eradicate

- Remove attacker persistence: inbox rules, forwarding, consented apps, added MFA methods.
- Re-register MFA from a trusted device.
- Sweep other users who clicked the same phish.

## Recover

- Re-enable the account with fresh creds + MFA.
- Harden: **phishing-resistant MFA** (FIDO2), **token protection / CAE**, require compliant device for sensitive apps.
- Preserve: the phishing email, the suspicious sign-ins (interactive + non-interactive), and the session's actions.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| MFA "satisfied by token" from a new device | Token replay |
| Non-interactive sign-in, no interactive parent | Replayed/stolen token |
| Identity Protection `anomalousToken` | Token theft |
| Session actions (rules/consent) from a new ASN | Hands-on-keyboard with a stolen token |
| Password reset without token revoke → session survives | Containment failure |

## References

- Related notes: **Sign-in Logs**, **01 Entra ID & Identities**, **Conditional Access & MFA**, **BEC**
- Token theft playbook — https://learn.microsoft.com/security/operations/token-theft-playbook
- Token protection / CAE — https://learn.microsoft.com/entra/identity/conditional-access/concept-token-protection
- MITRE ATT&CK: T1550.001 Application Access Token / T1539 Steal Web Session Cookie — https://attack.mitre.org/techniques/T1539/
