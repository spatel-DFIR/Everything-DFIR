# Cloud IAM for DFIR

IAM cases are about **who gained what access, when, and how far it reaches.** You read `SetIamPolicy` events, reconstruct the grant, and measure the blast radius via inheritance.

New to it? Read **What is Cloud IAM** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading a SetIamPolicy Event](#reading-a-setiampolicy-event)
- [Measuring the Blast Radius](#measuring-the-blast-radius)
- [Policy Troubleshooter](#policy-troubleshooter)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Best for |
|--------|--------------|----------|
| **Admin Activity audit** | Every `SetIamPolicy` (before/after bindings) | The grant events |
| **`get-iam-policy`** | Current bindings on a resource | Present state |
| **Policy Analyzer** | "Who can access what" across the org | Blast radius |
| **Recommender** | Over-privileged grants | Excess to clean |

## Collect It

```bash
# Current bindings on a project/folder/org
gcloud projects get-iam-policy <project> --format=json
gcloud organizations get-iam-policy <org-id> --format=json

# Every IAM change in the window
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' --project=<p> --freshness=30d --format=json

# Who can act as / impersonate a sensitive SA (blast radius) — Policy Analyzer's CLI backend
gcloud asset analyze-iam-policy --organization=<org-id> \
  --identity="serviceAccount:prod-admin@<p>.iam.gserviceaccount.com"
```

> **Console:** IAM & Admin → **IAM** (bindings), **Policy Analyzer**, **Recommender**; Logging → Logs Explorer for `SetIamPolicy`.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Find the grant | `SetIamPolicy` events in the window; who/what/where |
| 2. Read before/after | Compare `request.policy.bindings` vs prior — what member+role was added |
| 3. Check the scope | Was it at resource / project / folder / **org**? Inheritance = blast radius |
| 4. Trace the grantor | Who made the grant, with what creds (key/impersonation) |
| 5. Look for privesc chains | Key creation → impersonation → self-grant Owner |

## Reading a SetIamPolicy Event

| Field | Answers | 🔴 |
|-------|---------|----|
| `authenticationInfo.principalEmail` | Who granted | Unexpected grantor |
| `resourceName` | Where (scope) | 🔴 org/folder = wide |
| `request.policy.bindings[]` | The new member+role | 🔴 Owner/Editor; external member |
| `serviceData`/delta | What changed | The added binding |
| `callerIp` | From where | New geo |

## Measuring the Blast Radius

| Grant | Reaches |
|-------|---------|
| Owner/Editor at **project** | All resources in the project |
| Any role at **folder** | All projects under the folder |
| Owner/`organizationAdmin` at **org** | 🔴 Everything |
| TokenCreator on an SA | The SA's full access (impersonation) |
| `actAs` + deploy service | Whatever the attached SA can do |

## Policy Troubleshooter

Answers a narrower question than Policy Analyzer: **"why did this specific access get allowed or denied?"** — useful for confirming whether a permission an attacker used was actually granted (and by which binding), or for validating that a fix closed the gap.

```bash
gcloud policy-troubleshoot iam <resource> --principal-email=<email> --permission=<permission>
```

> **Console:** IAM & Admin → **Policy Troubleshooter**.

## Hunt at Scale

**BigQuery — external members added to IAM:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS grantor,
       protopayload_auditlog.resourceName AS resource, b.role, m AS member
FROM `contoso.audit.cloudaudit_googleapis_com_activity`,
     UNNEST(protopayload_auditlog.servicedata_v1_iam.policyDelta.bindingDeltas) b,
     UNNEST([b.member]) m
WHERE protopayload_auditlog.methodName='SetIamPolicy' AND b.action='ADD'
  AND (m LIKE '%@gmail.com' OR m NOT LIKE '%@contoso.com')
ORDER BY timestamp DESC;
```

**Owner/Editor grants:**

```sql
-- same source; filter b.role IN ('roles/owner','roles/editor')
```

> **At the very end — SecOps UDM (optional):** land IAM `ADD` bindings to correlate the grantor/member across projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Reverse a rogue grant | Remove the binding (`remove-iam-policy-binding`) |
| Cut an external member | Remove it from every resource it was added to |
| Contain privesc | Disable the SA / delete keys / remove TokenCreator (see Service Accounts) |
| Preserve | Export the `SetIamPolicy` events + policy snapshots |

```bash
gcloud projects remove-iam-policy-binding <p> \
  --member='user:attacker@...' --role='roles/owner'
```

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Ban Basic roles**; use predefined/custom least-privilege | Smaller blast radius |
| **Org Policy: restrict external members / domain-restricted sharing** | No `@gmail.com` grants |
| **IAM Conditions** (time/resource-bound) on sensitive roles | Limits standing access |
| **Recommender** to remove over-grants | Shrinks attack surface |
| **Alert** on Owner/Editor grants, external members, org/folder-level changes | Catch privesc live |
| **Separate break-glass** Owner, tightly monitored | Controlled emergency access |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `SetIamPolicy` granting Owner/Editor | Privilege escalation |
| Grant at org/folder level | Wide blast radius |
| External / `@gmail.com` member added | Backdoor access |
| Custom role widened (`iam.roles.update`) | Quiet privilege gain |
| Burst of `granted=false` then success | Escalation in progress |
| TokenCreator / `actAs` granted to a foothold | Impersonation setup |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The IAM model + privesc primitives | **Cloud IAM → What is** |
| Who the principals are | **Google → 01 Google Identities** |
| SA keys + impersonation | **GCP → Service Accounts** |
| The audit stream | **GCP → Cloud Audit Logs** |
| Privilege escalation end to end | **GCP → Playbooks → IAM Privilege Escalation** |

## Resources

- IAM audit logging — https://cloud.google.com/iam/docs/audit-logging
- Policy Analyzer — https://cloud.google.com/policy-intelligence/docs/analyze-iam-policies
- Restrict identities by domain (org policy) — https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains
- IAM Recommender — https://cloud.google.com/iam/docs/recommender-overview
- MITRE ATT&CK: T1098 Account Manipulation / T1078.004 Cloud Accounts — https://attack.mitre.org/techniques/T1098/
