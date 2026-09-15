# Cross-Cloud Investigations

Deep, pair-specific investigation of an actor moving from one cloud into another. Where **[03 - Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** gives the general method (anchors, log normalization, building one timeline), this folder gives the **per-pair technical depth**: every real bridge mechanism between AWS, Azure, and GCP, worked from both sides — what it looks like leaving the source cloud, and what it looks like arriving in the destination cloud.

Written for the same range as the rest of this repo: plain enough to onboard a junior, deep enough that a principal finds nothing hand-waved.

## How to Use This Guide

**New to cross-cloud bridges?** Start with **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** — the map of every mechanism, organized by which cloud an actor starts in.

**Working a case right now?** Jump straight to the directional note for the pair you're chasing, from the router below.

### Each directional note has the same shape

| Section | Answers |
|---------|---------|
| **The Bridges** | Every mechanism specific to this pair, numbered, with how common each is |
| **Source-Side Investigation** | What "leaving" looks like — per bridge, with field tables and example values |
| **Destination-Side Investigation** | What "arriving" looks like — per bridge, same treatment |
| **Correlation** | The exact fields that prove it's the same actor on both sides |
| **Hunt at Scale** | Native queries (CloudTrail Lake SQL / KQL / GCP Log Explorer & BigQuery) + a small SecOps/UDM landing point |
| **Red Flags** | The tells, independent of confirmed abuse |

## Situation → Open This

| The lead is… | Open |
|---------------|------|
| "I don't know yet which cloud this reaches, or how" | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| An Entra/Azure identity compromised, need to check **AWS** | **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** |
| An Entra/Azure identity compromised, need to check **GCP** | **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** |
| An AWS identity/credential compromised, need to check **Azure** | **[AWS → Azure](AWS%20%E2%86%92%20Azure.md)** |
| An AWS identity/credential compromised, need to check **GCP** | **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** |
| A GCP identity/service account compromised, need to check **AWS** | **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** |
| A GCP identity/service account compromised, need to check **Azure** | **[GCP → Azure](GCP%20%E2%86%92%20Azure.md)** |
| I need the general anchors/normalization/timeline method, not a specific pair | **[03 - Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| I have a full multi-cloud scenario to run end to end | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Frictionless vs Deliberate — A Quick Cheat Sheet

Not every pair requires the same amount of setup, and that changes what "normal" looks like on a case. Verified per-note, not assumed:

| Pair | Shortcut? | Why |
|------|-----------|-----|
| **GCP → AWS** | 🔴 Frictionless | AWS ships `accounts.google.com` as a **built-in** federated provider — no IAM OIDC provider resource to create |
| **AWS → GCP** | 🔴 Frictionless | GCP Workload Identity Federation has a **native AWS provider type** — trusts AWS role ARNs directly, no AWS-side config |
| **Azure → AWS** | Deliberate | SSO/SAML via Identity Center is common, but always a customer-configured trust — no native shortcut |
| **Azure → GCP** | Deliberate | GCP has no native Azure provider type — every trust is a hand-configured generic OIDC/SAML object |
| **GCP → Azure** | Deliberate | Azure treats Google as any standards-compliant external OIDC issuer — the customer must explicitly register the issuer and subject |
| **AWS → Azure** | Deliberate, and the least common direction | AWS is almost never the identity *source* for Azure; every bridge here (stored secret, custom OIDC issuer) had to be hand-built |

**GCP ↔ AWS is the only pair where both vendors pre-wired the trust themselves.** Everywhere else, a bridge existing at all means someone in the organization built it on purpose — which makes it worth inventorying even before an incident.

## Structure

```
Cross-Cloud Investigations/
├── README.md
├── 00 - Cross-Cloud Bridges Overview.md   ← the map: every bridge, by source cloud
├── Azure → AWS.md                         ← golden template for this folder
├── Azure → GCP.md
├── AWS → Azure.md
├── AWS → GCP.md
├── GCP → AWS.md
├── GCP → Azure.md
└── Multi-Cloud Intrusion Playbook.md      ← tier 3: a full scenario spanning multiple bridges
```

## Related

- **[01 - Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** — the identity-shape vocabulary used throughout this folder
- **[03 - Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** — the general correlation method this folder goes pair-specific on
- **[06 - Cloud Service Equivalents](../06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** — cross-provider terminology
- **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** — a full scenario spanning multiple bridges in one case
- **External:** [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
