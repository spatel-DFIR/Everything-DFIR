# Organization Policy for DFIR

Two jobs: **check whether a guardrail was weakened** during the incident, and **use guardrails to contain and prevent recurrence.**

New to it? Read **What is Organization Policy** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Was a Guardrail Weakened?](#investigate--was-a-guardrail-weakened)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Admin Activity audit** | `SetOrgPolicy` changes | Guardrail edits |
| **`org-policies list`** | Current constraints per node | Present posture |
| **Policy Denied logs** | Blocked requests | Attacker attempts |

## Collect It

```bash
# Current guardrails at each level
gcloud org-policies list --organization=<org-id>
gcloud org-policies list --project=<project>

# Guardrail changes in the window
gcloud logging read 'protoPayload.methodName="SetOrgPolicy"' --freshness=30d --format=json
```

## Investigate — Was a Guardrail Weakened?

| Step | Do this |
|------|---------|
| 1. List `SetOrgPolicy` events | In the incident window |
| 2. Compare before/after | Which constraint was disabled/loosened, at what scope |
| 3. Match to the next action | Did a public bucket / SA key / external-IP VM follow it? |
| 4. Attribute | Who changed it, with what creds |
| 5. Check Policy Denied | Attempts the guardrail blocked before it was removed |

🔴 The pattern to catch: **disable `storage.publicAccessPrevention` → make a bucket public**, or **disable `iam.disableServiceAccountKeyCreation` → create an SA key**. The guardrail change is the tell.

## Hunt at Scale

**Guardrail weakenings:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.resourceName AS scope
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName = 'SetOrgPolicy'
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land `SetOrgPolicy` events to correlate defense-evasion across projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Restore the guardrail | Re-apply the constraint at the org node |
| Undo the enabled action | Re-privatize the bucket / delete the SA key / remove external IP |
| Lock scope | Enforce constraints at the org so projects can't override |
| Preserve | Export the `SetOrgPolicy` history |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Set security constraints at the org** (public-access, key-creation, domain-restriction, external-IP, OS Login) | Baseline that inherits everywhere |
| **Restrict `orgpolicy.*` admin** | Fewer people can weaken guardrails |
| **Alert** on `SetOrgPolicy` (esp. disabling security constraints) | Catch evasion live |
| **Deny org-policy overrides** at lower levels for critical constraints | Projects can't loosen |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `SetOrgPolicy` disabling `publicAccessPrevention` | Bucket exposure enabled |
| Disabling `disableServiceAccountKeyCreation` | Key persistence enabled |
| Disabling `vmExternalIpAccess` / `requireOsLogin` | Attacker VM / SSH-injection enabled |
| Constraint deleted right before a matching action | Defense evasion → next step |
| Guardrail change by an unexpected principal | Attacker anti-guardrail |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The constraint model | **Organization Policy → What is** |
| Grants (the other half) | **GCP → Cloud IAM** |
| The bucket-exposure it enables | **GCP → Cloud Storage → Playbooks → Public GCS Bucket** |
| SA-key persistence it enables | **GCP → Service Accounts** |

## Resources

- Organization Policy Service — https://cloud.google.com/resource-manager/docs/organization-policy/overview
- Constraints reference — https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- MITRE ATT&CK: T1562 Impair Defenses — https://attack.mitre.org/techniques/T1562/
