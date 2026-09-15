# What is Entra Identity Protection?

**Identity Protection** is Entra's **risk engine** — it scores sign-ins and users for signs of compromise (leaked credentials, impossible travel, anonymous IPs, token anomalies) and can automatically **block, require MFA, or force a password reset**. It's the pre-triage layer: it tells you *which* identities Microsoft already thinks are compromised.

Think of it as **GuardDuty for identity** — managed detections that turn raw sign-ins into risk verdicts.

## Contents

- [How It Works](#how-it-works)
- [Risk: Sign-in vs User](#risk-sign-in-vs-user)
- [The Detections That Matter](#the-detections-that-matter)
- [Risk Levels and States](#risk-levels-and-states)
- [How to Identify Risk in Evidence](#how-to-identify-risk-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Identity Protection evaluates every sign-in against Microsoft's threat intelligence and behavioral models, producing a **risk level**. Policies (risk-based Conditional Access) can then act automatically.

```
Sign-in signals + Microsoft TI  →  risk detection  →  sign-in risk / user risk
                                 →  optional auto-response (block / MFA / password reset)
```

> Requires **Entra ID P2** for the full feature set (P1/free surface a subset). On a case, confirm the licensing — it decides what detections you even have.

## Risk: Sign-in vs User

Two kinds of risk, and they mean different things:

| | **Sign-in risk** | **User risk** |
|-|------------------|---------------|
| Scores | A single **authentication** | The **account** overall |
| Example | Impossible travel on *this* login | Leaked credentials found for the user |
| Acts via | Sign-in risk policy (block / MFA now) | User risk policy (force secure password reset) |
| On a case | "Was *this* sign-in suspicious?" | "Is this *account* likely compromised?" |

## The Detections That Matter

| Detection | Means |
|-----------|-------|
| **Leaked credentials** | The user's password appeared in a breach dump 🔴 |
| **Impossible travel** | Two sign-ins too far apart in time/geography |
| **Anonymous IP** | Sign-in from Tor / anonymizing proxy |
| **Malicious IP / password spray** | Source tied to known attack infrastructure or spray patterns |
| **Unfamiliar sign-in properties** | New device/location/ASN pattern for the user |
| **Token anomalies / anomalous token** | 🔴 Signs of **token theft / replay** (AiTM) |
| **Suspicious inbox manipulation rules** | Detected via Defender — links identity to BEC |
| **Verified threat actor IP** | Microsoft-attributed adversary source |

## Risk Levels and States

| Level | Meaning |
|-------|---------|
| **High** | Strong evidence of compromise 🔴 |
| **Medium** | Notable anomaly |
| **Low** | Minor deviation |

| Risk state | Meaning |
|-----------|---------|
| **At risk** | Active, unremediated risk |
| **Confirmed compromised** | You (or automation) marked it a true positive — feeds the model |
| **Remediated / Dismissed** | Password reset / MFA cleared it, or judged benign |
| **Confirmed safe** | Marked false positive |

> 🔴 Marking a user **Confirmed compromised** or **Confirmed safe** trains the model *and* documents your verdict — use it during IR.

## How to Identify Risk in Evidence

- **Portal:** Entra ID → **Protection → Identity Protection** → *Risky users*, *Risky sign-ins*, *Risk detections*.
- **Graph:** `identityProtection/riskyUsers`, `riskDetections`, `servicePrincipalRiskDetections`.
- **Sign-in log fields:** `riskLevelDuringSignIn`, `riskState`, `riskEventTypes`.
- **KQL:** `AADRiskyUsers`, `AADUserRiskEvents`, `AADRiskyServicePrincipals`.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Identity Protection | GuardDuty (IAM/anomaly findings) | reCAPTCHA/Identity risk + SCC |
| Risky sign-in | GuardDuty `UnauthorizedAccess:IAMUser/*` | Suspicious login |
| Leaked credentials | (no direct equal) | Password checkup |

## Common Use Cases

- **Auto-remediation** — block/MFA/reset on risk without human delay.
- **Prioritization** — triage the riskiest identities first.
- **Feeding SIEM/XDR** — risk events into Sentinel/Defender.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Sign-in risk** | Risk of a single authentication |
| **User risk** | Risk of the account overall |
| **Risk detection** | A specific signal (leaked creds, impossible travel…) |
| **Risk level** | High / Medium / Low |
| **Risk state** | At risk / confirmed compromised / remediated / dismissed |
| **Risk-based CA** | Conditional Access driven by risk |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating risky identities | **Identity Protection → for DFIR** |
| The sign-ins behind the risk | **Entra → Sign-in Logs** |
| The policy that acts on risk | **Entra → Conditional Access & MFA** |
| Token-theft risk detections | **Entra → Playbooks → Token Theft and AiTM** |

## Resources

- Identity Protection overview — https://learn.microsoft.com/entra/id-protection/overview-identity-protection
- Risk detections reference — https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks
- Risk-based Conditional Access — https://learn.microsoft.com/entra/id-protection/concept-identity-protection-policies
