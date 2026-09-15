# What is Organization Policy?

**Organization Policy** is GCP's **guardrail** system — org-wide (or folder/project) **constraints** that cap what *anyone* can do, regardless of their IAM roles. It's the GCP analog of AWS SCPs and Azure Policy. For DFIR it matters because attackers **weaken or remove** these guardrails to enable their next move (make a bucket public, create SA keys, spin up external-IP VMs), and those changes are a defense-evasion signal.

## Contents

- [How It Works](#how-it-works)
- [Constraints That Matter for Security](#constraints-that-matter-for-security)
- [IAM vs Org Policy](#iam-vs-org-policy)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **constraint** is a named restriction (e.g. `storage.publicAccessPrevention`).
- A **policy** sets that constraint at the **org / folder / project** level and **inherits down**.
- Constraints are **boolean** (on/off) or **list** (allow/deny values).
- Unlike IAM (which grants), Org Policy **restricts** — it can block even an Owner.

## Constraints That Matter for Security

| Constraint | Restricts | 🔴 If removed |
|-----------|-----------|---------------|
| `iam.disableServiceAccountKeyCreation` | No user-managed SA keys | Attackers can mint long-lived keys |
| `iam.allowedPolicyMemberDomains` | Domain-restricted IAM sharing | External `@gmail.com` grants become possible |
| `storage.publicAccessPrevention` | No public buckets | Buckets can be exposed to the internet |
| `compute.vmExternalIpAccess` | No external IPs on VMs | Attacker VMs get public IPs (C2/mining) |
| `compute.requireOsLogin` | Enforce OS Login (auditable SSH) | SSH-key injection via metadata |
| `gcp.resourceLocations` | Restrict regions | Resources spun up in odd regions |
| `iam.disableCrossProjectServiceAccountUsage` | Contain SA use | Cross-project SA abuse |

> 🔴 A `SetOrgPolicy` that **disables** one of these — or **deletes** the constraint — right before a matching action (public bucket, SA key, external-IP VM) is defense evasion enabling the next step.

## IAM vs Org Policy

| | IAM | Organization Policy |
|-|-----|---------------------|
| **Answers** | *Who can do what* (grants) | *What is allowed at all* (caps) |
| **Effect** | Additive permissions | Restrictions/guardrails |
| **Beats an Owner?** | No | ✅ Yes — caps even Owners |
| **Logged as** | `SetIamPolicy` | `SetOrgPolicy` |

## How to Identify It in Evidence

- **`SetOrgPolicy`** in Admin Activity = a guardrail changed.
- **Config:** `gcloud org-policies list --organization=<org>` / `describe <constraint>`.
- **Policy Denied logs** show requests these constraints blocked (recon/attempts).

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Organization Policy | Service Control Policy (SCP) | Azure Policy |
| Constraint | SCP statement | Policy definition |
| `publicAccessPrevention` | S3 Block Public Access (org) | Storage public-access policy |
| `allowedPolicyMemberDomains` | (no direct equal) | External collaboration restrictions |

## Common Use Cases

Your "normal": security baseline guardrails set at the org, inherited everywhere; occasional scoped exceptions per project. On a case, check **whether a guardrail was changed** in the incident window.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Constraint** | A named restriction |
| **Boolean/List constraint** | On-off / allow-deny values |
| **Org policy** | A constraint applied at a node |
| **Inheritance** | Policy flows down org→folder→project |
| **Policy Denied log** | Records requests a constraint blocked |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating guardrail changes | **Organization Policy → for DFIR** |
| Grants (the other half) | **GCP → Cloud IAM** |
| The audit stream | **GCP → Cloud Audit Logs** |
| SA-key guardrail | **GCP → Service Accounts** |

## Resources

- Organization Policy Service — https://cloud.google.com/resource-manager/docs/organization-policy/overview
- All constraints — https://cloud.google.com/resource-manager/docs/organization-policy/org-policy-constraints
- Public access prevention — https://cloud.google.com/storage/docs/public-access-prevention
