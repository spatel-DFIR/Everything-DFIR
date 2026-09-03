# What is Security Hub?

**Security Hub** is the **single pane of glass** for AWS security. It aggregates findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, Config, and partner tools into **one normalized format**, and it runs **posture checks** (CIS, AWS Foundational, PCI) against your accounts.

For an analyst, Security Hub is **where you triage across tools and accounts** — one prioritized list instead of six consoles — and where you see your **misconfiguration debt** at a glance.

## Contents

- [How It Works](#how-it-works)
- [Two Jobs — Aggregation and Posture](#two-jobs--aggregation-and-posture)
- [The ASFF — One Finding Format](#the-asff--one-finding-format)
- [How to Identify Security Hub in Evidence](#how-to-identify-security-hub-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
GuardDuty · Inspector · Macie · Access Analyzer · Config · partners
        │  all send findings in the ASFF format
        ▼
   SECURITY HUB  ── normalizes · dedups · scores · runs posture standards ──►
        │
        └── one prioritized list  →  EventBridge  →  SecOps / ticketing / auto-response
```

- **Regional**, with **org-wide aggregation** to a delegated admin/audit account (and cross-region aggregation).
- Everything is normalized to the **AWS Security Finding Format (ASFF)** — so a GuardDuty finding and an Inspector CVE look structurally the same.

## Two Jobs — Aggregation and Posture

| Job | What it does | DFIR use |
|-----|--------------|----------|
| **Finding aggregation** | Collects + normalizes findings from all sources | One triage queue across tools/accounts |
| **Security standards (posture)** | Continuous checks (CIS, AWS FSBP, PCI, NIST) → pass/fail controls | Your misconfiguration debt; hardening backlog |

> Security Hub **doesn't detect threats itself** (that's GuardDuty/Inspector) and it isn't raw evidence — it's the **aggregator + scorekeeper**. For the deep evidence you still pivot to the source tool and to CloudTrail.

## The ASFF — One Finding Format

Every finding, whatever the source, shares a structure:

| ASFF field | Meaning |
|------------|---------|
| `Title` / `Description` | What the finding is |
| `ProductName` | Which tool raised it (GuardDuty, Inspector…) |
| `Severity.Label` | INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL |
| `Resources[]` | Affected resource ARNs |
| `Types[]` | Normalized finding taxonomy |
| `Compliance.Status` | PASSED / FAILED (for posture controls) |
| `Workflow.Status` | NEW / NOTIFIED / SUPPRESSED / RESOLVED |
| `RecordState` | ACTIVE / ARCHIVED |

> The normalized `Severity` + `Workflow.Status` is what lets you run one queue. 🔴 Watch for findings **mass-set to `SUPPRESSED`/`RESOLVED`** during an incident — that's someone clearing the board.

## How to Identify Security Hub in Evidence

- **`eventSource`:** `securityhub.amazonaws.com`.
- Findings flow out via **EventBridge** (`source: aws.securityhub`, `detail-type: Security Hub Findings - Imported`).
- **ARNs:** `arn:aws:securityhub:<region>:<acct>:...`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `BatchUpdateFindings` | Change workflow/severity of findings | 🔴 mass-suppress/resolve |
| `UpdateFindings` (legacy) | Update findings | 🔴 same |
| `DisableSecurityHub` | Turn it off | 🔴 blinding the aggregator |
| `DisableImportFindingsForProduct` | Stop ingesting a source | 🔴 dropping a tool's findings |
| `CreateInsight` / `GetFindings` | Analyst use | Normal |
| `BatchDisableStandards` | Turn off a posture standard | 🔴 hiding compliance debt |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Security Hub | Defender for Cloud (Secure Score + alerts) | Security Command Center |
| ASFF | Defender alert schema | SCC finding schema |
| Security standards (CIS/FSBP) | Regulatory compliance dashboard | SCC compliance / posture |

## Common Use Cases

Your "normal":

- **Central triage** of all security findings, org-wide.
- **Continuous compliance** scoring (CIS/FSBP/PCI).
- **Routing** findings to SecOps/ticketing/auto-response via EventBridge.
- **Prioritization** — one severity scale across many tools.

## Key Terminology

| Term | Meaning |
|------|---------|
| **ASFF** | AWS Security Finding Format — the normalized schema |
| **Security standard** | A posture framework (CIS, FSBP, PCI) |
| **Control** | One check within a standard (pass/fail) |
| **Insight** | A saved grouping/query of findings |
| **Workflow status** | NEW / NOTIFIED / SUPPRESSED / RESOLVED |
| **Delegated admin** | The account running Security Hub org-wide |
| **Finding aggregation** | Cross-region/-account collection |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using Security Hub in a case | **Security Hub → Security Hub for DFIR** |
| The threat findings it aggregates | **AWS → Security & Detection → GuardDuty** |
| The config/compliance side | **AWS → Security & Detection → Config** |
| Graph-based deep dives | **AWS → Security & Detection → Detective** |
| The raw actor evidence | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- What is Security Hub — https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html
- ASFF — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
- Security standards — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html
