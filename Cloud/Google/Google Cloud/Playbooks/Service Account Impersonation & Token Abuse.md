# Playbook — Service Account Impersonation & Token Abuse

An attacker with `roles/iam.serviceAccountTokenCreator` (or `actAs`) **impersonates a more-privileged service account** — minting short-lived tokens (`generateAccessToken`/`signJwt`) or attaching the SA to a resource — to escalate without ever holding a key. It's the GCP lateral-movement engine (the `AssumeRole`/token analog). This playbook reconstructs the impersonation chain and cuts the grant.

> **Tier 2 (cross-service).** Spans Cloud Audit Logs + IAM + Service Accounts. Read **GCP → Service Accounts** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Reconstruct the Chain](#reconstruct-the-chain)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Audit log** | `GenerateAccessToken` by an unexpected principal |
| **SCC** | Anomalous impersonation |
| **IAM change** | `TokenCreator`/`serviceAccountUser` granted to a foothold |
| **Downstream** | A privileged SA acting via `serviceAccountDelegationInfo` |

## Hypothesis

An attacker is impersonating a privileged SA to act beyond their own rights. Establish who impersonated what, what the target SA did, how the grant was obtained, and remove the impersonation path.

## Step-by-Step Investigation

**1. Find the impersonations.**

```bash
gcloud logging read \
 'protoPayload.methodName="GenerateAccessToken" OR protoPayload.methodName="SignJwt"' \
 --freshness=30d --format=json
```

**2. Read the delegation chain.** In actions by the target SA, `authenticationInfo.serviceAccountDelegationInfo` lists **who impersonated whom** — the chain back to the human/foothold.

**3. How did they get TokenCreator?** Look for the `SetIamPolicy` that granted `TokenCreator`/`serviceAccountUser` to the attacker — and who made it.

## Reconstruct the Chain

| Step | Field |
|------|-------|
| The original foothold identity | First `principalEmail` in the chain |
| The impersonation grant | `SetIamPolicy` adding `TokenCreator` |
| The token mint | `GenerateAccessToken` on the target SA |
| What the target SA did | Later actions with `serviceAccountDelegationInfo` |
| Any further hop | The target SA impersonating *another* SA (chains multi-hop) |

## Decision Points

| Question | If yes → |
|----------|----------|
| Target SA has Owner/org roles? | Treat as project/org compromise |
| Chain is multi-hop? | Follow every hop; contain the whole chain |
| `actAs` used to attach the SA to a VM/Function/Run? | Check that resource for attacker code |
| Grant made by a compromised admin? | Also run **IAM Privilege Escalation** |

## Contain

```bash
# Remove the impersonation grant (tokens then expire on their own)
gcloud iam service-accounts remove-iam-policy-binding <target-sa> \
  --member='<attacker-principal>' --role='roles/iam.serviceAccountTokenCreator'
gcloud iam service-accounts remove-iam-policy-binding <target-sa> \
  --member='<attacker-principal>' --role='roles/iam.serviceAccountUser'
# Disable the target SA if it did damage
gcloud iam service-accounts disable <target-sa>
```

> 🔴 Removing `TokenCreator` stops new tokens; existing short-lived tokens **expire in ~1 hour**. Disable the SA if you need an immediate hard stop.

## Eradicate

- Remove every attacker impersonation grant across the chain.
- Revert what the impersonated SAs changed (IAM, keys, resources).
- Check for **`actAs`-attached** resources running as the SA (VMs/Functions/Run) and clean them.

## Recover

- Restrict `TokenCreator`/`serviceAccountUser` to specific, monitored principals.
- Prefer **direct resource attachment** over broad impersonation grants.
- Alert on `GenerateAccessToken` for privileged SAs + new `TokenCreator` grants.
- Preserve: the delegation chains, the grant events, and the SAs' activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| `GenerateAccessToken` by an unexpected principal | Impersonation abuse |
| New `TokenCreator`/`serviceAccountUser` grant to a foothold | Privesc setup |
| Multi-hop `serviceAccountDelegationInfo` chains | Lateral movement |
| Impersonated SA granting itself roles | Escalation |
| `actAs` + a compute deploy | Run code as the SA |

## References

- Related notes: **Service Accounts**, **Cloud IAM**, **Cloud Audit Logs**, **Metadata SSRF to SA Token Theft**, **IAM Privilege Escalation**
- Short-lived credentials — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Best practices for SAs — https://cloud.google.com/iam/docs/best-practices-service-accounts
- MITRE ATT&CK: T1550 Use Alternate Auth Material / T1078.004 — https://attack.mitre.org/techniques/T1550/
