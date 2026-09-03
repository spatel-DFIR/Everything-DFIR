# Entra Identity Protection for DFIR

Identity Protection is often **where the alert came from** — a risky user, a leaked-credential hit, an anomalous-token detection. This note is how you read those verdicts, confirm or clear them, and use them to scope a compromise.

New to this? Read **What is Entra Identity Protection** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Where |
|--------|--------------|-------|
| **Risky users** | Per-account risk level + state + history | Entra / `AADRiskyUsers` |
| **Risky sign-ins** | Which sign-ins were risky + why | Entra / `SigninLogs` (risk fields) |
| **Risk detections** | The individual signals | Entra / `AADUserRiskEvents` |
| **Risky service principals** | Risk on apps (P2) | Entra / `AADRiskyServicePrincipals` |

## Collect It

```powershell
# All currently at-risk users
Get-MgRiskyUser -Filter "riskState eq 'atRisk'" -All

# Risk detections for one user
Get-MgRiskDetection -Filter "userPrincipalName eq 'alice@contoso.com'" -All
```

> **Console:** Entra ID → Protection → **Identity Protection** → *Risky users* → pick the user → **Detections** + timeline. Export via Graph or the portal.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Read the risk detections | What fired — leaked creds, impossible travel, anomalous token? |
| 2. Pull the underlying sign-ins | Cross to the sign-in log for IP/app/MFA detail |
| 3. Confirm or clear | Real? mark **Confirmed compromised**. Benign? **Confirmed safe** (document why) |
| 4. Scope the blast radius | If compromised, follow into audit logs (role/app/consent), M365, Azure |
| 5. Note anomalous-token detections | These point at **AiTM/token theft** — pivot to non-interactive sign-ins |

## Hunt at Scale

**High-risk users with token anomalies (token theft):**

```kql
AADUserRiskEvents
| where RiskLevel == "high"
| where RiskEventType has_any ("anomalousToken","tokenIssuerAnomaly","mcasSuspiciousInboxManipulationRules")
| project TimeGenerated, UserPrincipalName, RiskEventType, IpAddress, Source
```

**Leaked-credential hits still at risk:**

```kql
AADUserRiskEvents
| where RiskEventType == "leakedCredentials"
| join kind=inner (AADRiskyUsers | where RiskState == "atRisk") on $left.UserPrincipalName == $right.UserPrincipalName
```

## Respond

| Goal | Action |
|------|--------|
| Force account remediation | Require secure password change (user-risk policy) + revoke tokens |
| Cut the session | `Revoke-MgUserSignInSession` + disable if actively abused |
| Record the verdict | Mark **Confirmed compromised** — feeds the model + documents IR |
| Automate next time | Enable risk-based CA to block/MFA high risk automatically |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Risk-based Conditional Access** (block high sign-in risk; reset on high user risk) | Automated, instant response |
| **Entra ID P2** where feasible | Full detection + auto-remediation |
| **Export risk events → Sentinel** | Correlation + retention |
| **Investigate every "leaked credentials" hit** | Known-bad passwords must be rotated |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| **Anomalous token** / token issuer anomaly | Token theft / AiTM |
| **Leaked credentials** high | Known-compromised password in use |
| **Impossible travel** + success | Account compromise |
| High-risk user still **at risk** (not remediated) | Active exposure |
| Risky **service principal** | Rogue/hijacked app |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the risk engine is | **Identity Protection → What is** |
| The sign-ins behind the risk | **Entra → Sign-in Logs** |
| Auto-response policy | **Entra → Conditional Access & MFA** |
| Token-theft follow-through | **Entra → Playbooks → Token Theft and AiTM** |

## Resources

- Investigate risk — https://learn.microsoft.com/entra/id-protection/howto-identity-protection-investigate-risk
- Remediate & unblock — https://learn.microsoft.com/entra/id-protection/howto-identity-protection-remediate-unblock
- Risk detections — https://learn.microsoft.com/entra/id-protection/concept-identity-protection-risks
