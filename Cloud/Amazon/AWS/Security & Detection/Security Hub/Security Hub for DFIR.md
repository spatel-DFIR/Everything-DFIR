# Security Hub for DFIR

Security Hub is where you **triage the whole board at once** — every tool's findings, every account, one prioritized queue — and where you read your **misconfiguration debt** during hardening. It's an aggregator, so the deep evidence always lives one pivot away.

New to the service? Read **What is Security Hub** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Triage Across Tools](#investigate--triage-across-tools)
- [Reading a Finding and Pivoting](#reading-a-finding-and-pivoting)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Security Hub answers **"across all my tools and accounts, what's on fire, and how bad is my posture?"** It's your **first-pane triage**, not your evidence — you confirm each finding in the source tool + CloudTrail.

## Evidence It Produces

| Evidence | Gives you | Where |
|----------|-----------|-------|
| Aggregated findings (ASFF) | Normalized, scored, cross-account list | Security Hub console / `get-findings` |
| Posture control status | Pass/fail against CIS/FSBP/PCI | Console / `describe-standards-controls` |
| `securityhub.*` CloudTrail | Who suppressed/disabled things | CloudTrail |

## Collect It

```bash
# Active high/critical findings across the org
aws securityhub get-findings \
  --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"},
                                {"Value":"HIGH","Comparison":"EQUALS"}],
              "RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --max-results 100 > sechub_findings.json

# Failing posture controls (your hardening backlog)
aws securityhub describe-standards-controls \
  --standards-subscription-arn <arn> \
  --query 'Controls[?ControlStatus==`ENABLED`]'
```

> **Console:** Security Hub → **Findings** (filter severity/product/account/workflow) · **Security standards** → open a standard → *Failed* controls · **Insights** for saved groupings.

## Investigate — Triage Across Tools

| Step | Do this |
|------|---------|
| 1 | Pull ACTIVE HIGH/CRITICAL findings for the affected account(s), sorted by severity + last-observed |
| 2 | Group by resource — one compromised instance/identity often lights up several findings |
| 3 | For each, note `ProductName` (which tool) and pivot to that tool + CloudTrail to **confirm** |
| 4 | Check `Workflow.Status` history — anything mass-suppressed/resolved during the window? |
| 5 | Use failing posture controls to understand *how* the resource was exposed (the misconfig) |

## Reading a Finding and Pivoting

| `ProductName` | Pivot to |
|---------------|----------|
| **GuardDuty** | **GuardDuty for DFIR** → CloudTrail / VPC Flow |
| **Inspector** | Vulnerability/CVE on the resource → patch + assess exploit |
| **Macie** | Sensitive-data exposure in S3 → **AWS → Security & Detection → Macie for DFIR**, then **S3 for DFIR** |
| **IAM Access Analyzer** | External/cross-account access → **IAM** |
| **AWS Config** | Failed posture control → **Config for DFIR** |
| **Firewall Manager / partners** | The partner console |

> Security Hub tells you *that* and *how severe*; the source tool + CloudTrail tell you *the evidence and the actor*. Never close a finding from the aggregator alone.

## Hunt at Scale

**In-platform — `get-findings` filters** are the native hunt. For tamper:

```sql
-- Athena/Lake: who suppressed or disabled Security Hub?
SELECT eventtime, useridentity.arn, eventname
FROM cloudtrail_logs
WHERE eventsource = 'securityhub.amazonaws.com'
  AND eventname IN ('BatchUpdateFindings','DisableSecurityHub',
                    'DisableImportFindingsForProduct','BatchDisableStandards')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** Security Hub commonly forwards findings to SecOps; use it as the cross-account queue, then pivot back to the source tool for depth.

## Respond

| Goal | Action |
|------|--------|
| Work the real incident | Respond in the *source* domain (EC2/IAM/S3), not in the aggregator |
| Track state | Set `Workflow.Status` (NOTIFIED/RESOLVED) as you work — but only after confirming |
| Undo attacker suppression | Re-open findings mass-set to SUPPRESSED/RESOLVED; re-enable disabled products/standards |
| Automate | EventBridge: CRITICAL finding → ticket + auto-response |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Security Hub org-wide**, delegated admin, cross-region aggregation | One board for everything |
| **Turn on FSBP + CIS standards**; drive failed controls to zero | Your hardening backlog, quantified |
| **SCP/alert** on `DisableSecurityHub` / `BatchUpdateFindings` (mass) | Catch board-clearing |
| **Route findings** to SecOps/ticketing via EventBridge | Nothing sits unseen |
| **Suppress with rules, not mass-updates**, and log why | Auditable noise reduction |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Mass `BatchUpdateFindings` to SUPPRESSED/RESOLVED in the window | Attacker clearing the board |
| `DisableSecurityHub` / product import disabled | Aggregator blinded |
| A single resource lighting up many product findings | Real, active compromise |
| Posture score cratering in an account | Widespread exposure |
| Standards disabled (`BatchDisableStandards`) | Compliance debt hidden |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Security Hub is + ASFF | **Security Hub → What is Security Hub** |
| Threat findings it aggregates | **AWS → Security & Detection → GuardDuty** |
| Config/compliance detail | **AWS → Security & Detection → Config** |
| Graph investigation | **AWS → Security & Detection → Detective** |
| The raw actor evidence | **AWS → Logging & Monitoring → CloudTrail** |

## Resources

- Managing findings — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings.html
- ASFF — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
- Security standards & controls — https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html
- MITRE ATT&CK: Impair Defenses (T1562) — https://attack.mitre.org/techniques/T1562/
