# Workload Identity Federation for DFIR

WIF cases are trust-condition cases: **did an external identity that shouldn't have been trusted impersonate a GCP SA?** You read the token-exchange events, find the federated subject, and check the pool provider's condition.

New to it? Read **What is Workload Identity Federation** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Auditing the Trust Condition](#auditing-the-trust-condition)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Admin Activity audit** | STS exchange + SA impersonation by federated subjects | The exchanges |
| **`principalSubject`** | The external identity that acted | Attribution |
| **Pool provider config** | The attribute condition (trust gate) | Root-cause |

## Collect It

```bash
# Pools + providers (read the attribute conditions)
gcloud iam workload-identity-pools list --location=global --project=<p>
gcloud iam workload-identity-pools providers describe <prov> \
  --workload-identity-pool=<pool> --location=global

# Federated impersonation events
gcloud logging read \
 'protoPayload.authenticationInfo.principalSubject:"workloadIdentityPools"' \
 --freshness=30d --format=json
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Find the exchange | STS/impersonation events with a `principalSubject` |
| 2. Identify the external subject | The repo/branch/AWS role/OIDC sub that mapped in |
| 3. Read the condition | Does the provider actually restrict to that subject? |
| 4. Trace the SA actions | What the impersonated SA did after the exchange |
| 5. Judge legitimacy | Is that external subject an approved pipeline/workload? |

## Auditing the Trust Condition

| Provider | Tight condition should pin… |
|----------|-----------------------------|
| **GitHub Actions** | `attribute.repository == 'org/repo'` (and branch/environment) |
| **AWS** | The specific role ARN, not the whole account |
| **Generic OIDC** | `google.subject`/`aud` to specific values |

🔴 If the condition is missing or matches broadly, treat every federated impersonation as suspect.

## Hunt at Scale

**Federated subjects impersonating privileged SAs:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalSubject AS ext_subject,
       protopayload_auditlog.resourceName AS impersonated_sa
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalSubject LIKE '%workloadIdentityPools%'
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land federated impersonations to spot unexpected external subjects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut the abuse | Tighten/replace the provider **attribute condition**; or disable the provider |
| Remove the grant | Revoke `workloadIdentityUser` on the SA for the pool |
| Contain the SA | Disable/rotate the impersonated SA if it did damage |
| Preserve | Export the exchange events + provider config |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Pin attribute conditions** to specific repo/branch/role | Only the intended workload can exchange |
| **Least-privilege SA** per pipeline | Small blast radius |
| **Prefer WIF over keys** for CI/CD | No downloadable secrets |
| **Alert** on new pools/providers + condition changes | Catch loosening live |
| **Review providers** periodically | Catch drift |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Provider with no/broad attribute condition | Anyone's pipeline can impersonate |
| Federated impersonation from an unexpected subject | OIDC trust abuse |
| New pool/provider created outside change control | Backdoor federation |
| Condition loosened (`SetOrgPolicy`/provider update) | Defense evasion |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The WIF model + trust conditions | **Workload Identity Federation → What is** |
| The impersonated SA | **GCP → Service Accounts** |
| The identity decoder | **Google → 01 Google Identities** |
| IAM privesc | **GCP → Cloud IAM** |

## Resources

- Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
- Best practices — https://cloud.google.com/iam/docs/best-practices-for-using-workload-identity-federation
- MITRE ATT&CK: T1199 Trusted Relationship / T1550 Use Alternate Auth Material — https://attack.mitre.org/techniques/T1199/
