# Detective for DFIR

Detective is the **scoping accelerator.** When you have one lead — an IP, a role, a GuardDuty finding — Detective shows you its entire connected footprint and flags what's abnormal, in clicks instead of queries. Use it to *scope fast*, then confirm and act in the underlying services.

New to the service? Read **What is Detective** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Access It](#access-it)
- [Investigate — The Pivot Workflow](#investigate--the-pivot-workflow)
- [Questions Detective Answers Fast](#questions-detective-answers-fast)
- [Respond](#respond)
- [Fix the Setup and Harden](#fix-the-setup-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

Detective answers **"what is this lead connected to, and is any of it abnormal?"** without you hand-joining CloudTrail, Flow Logs, and findings. It compresses scoping from hours to minutes — then you verify the specifics elsewhere.

## Evidence It Produces

| Evidence | Gives you | Notes |
|----------|-----------|-------|
| Entity profiles | Full activity for an IP/role/session/instance | Up to ~1 year, baselined |
| Finding overviews | A GuardDuty finding expanded into related entities | The "Investigate in Detective" landing |
| Baseline deviations | New geo / new user-agent / unusual API volume | Auto-computed |
| `detective.*` CloudTrail | Who disabled Detective / dropped members | Evasion signal |

## Access It

Detective is a **console-first** tool — the value is the interactive graph.

> **Console:** GuardDuty finding → **Investigate in Detective**, or Detective console → search an **IP / role / instance / finding** → open its profile → scrub the timeframe.

```bash
# Confirm Detective is enabled and covering the accounts
aws detective list-graphs
aws detective list-members --graph-arn <arn> \
  --query 'MemberDetails[].{Account:AccountId,Status:Status}'
```

## Investigate — The Pivot Workflow

| Step | Do this |
|------|---------|
| 1. Start from the lead | Open the GuardDuty finding in Detective, or search the IP/role directly |
| 2. Read the profile | Activity volume over time, geolocations, user-agents, connected resources |
| 3. Spot the deviation | Detective highlights *new* geo/UA/volume vs baseline — those are your leads |
| 4. Expand outward | Pivot to connected entities (the role's other sessions, the IP's other targets) |
| 5. Bound the timeframe | Scrub to the incident window to isolate the relevant activity |
| 6. Confirm + act | Take the scoped entities to CloudTrail/VPC Flow to verify; respond in the resource's domain |

## Questions Detective Answers Fast

| Question | How Detective shows it |
|----------|------------------------|
| Is this IP new for this role? | Baseline flag on the role's IP history |
| What *else* did this IP touch? | The IP entity's connected roles/instances |
| Is this API volume abnormal? | Deviation-from-baseline graph |
| What did this `ASIA` session do? | The role-session profile, end to end |
| Did activity come from a new country/tool? | Geolocation + user-agent panels |
| How far back does this go? | Timeframe scrub across ~1 year |

## Respond

Detective is investigative — you act elsewhere:

| Goal | Action |
|------|--------|
| Scope confirmed | Take the entity list to CloudTrail/VPC Flow to lock the timeline |
| Contain the identity | **IAM / STS for DFIR** (deactivate key, revoke sessions) |
| Contain the instance | **EC2 for DFIR** (isolate + snapshot) |
| Preserve | Detective retains ~1 year, but export the confirming CloudTrail from S3 for the record |

## Fix the Setup and Harden

| Fix | Why |
|-----|-----|
| **Enable Detective org-wide**, delegated admin | Scoping works across all accounts |
| **Enable it in every active region** | Attackers hide in unused regions |
| **SCP/alert** on `DeleteGraph` / `DisassociateMembership` | Keep the investigation graph intact |
| **Train responders** on the GuardDuty→Detective pivot | Faster scoping under pressure |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| A role suddenly active from a **new country/ASN** | Likely stolen creds |
| A **new user-agent** on a normally-scripted role | Different tooling = different operator |
| **Abnormal API volume** spike for an identity | Automated attacker activity |
| One IP connected to **many roles/instances** | Broad compromise footprint |
| `DeleteGraph` / Detective disabled in the window | Investigation capability removed |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Detective is | **Detective → What is Detective** |
| The findings you pivot from | **AWS → Security & Detection → GuardDuty** |
| Confirming the raw API detail | **AWS → Logging & Monitoring → CloudTrail** |
| The identity/session behind it | **AWS → Identity & Access → STS**, **01 Identities** |
| The network side | **AWS → Logging & Monitoring → VPC Flow Logs** |

## Resources

- Analyzing findings with Detective — https://docs.aws.amazon.com/detective/latest/userguide/detective-investigation-about.html
- Detective + GuardDuty integration — https://docs.aws.amazon.com/detective/latest/userguide/detective-integration-guardduty.html
- Profile panels reference — https://docs.aws.amazon.com/detective/latest/userguide/profile-panels.html
- MITRE ATT&CK: N/A — Detective is an investigative/scoping tool, not an attacker technique. It's most often used to pivot into findings mapped to **Discovery** and **Initial Access** tactics — see the finding's own ATT&CK mapping in **GuardDuty for DFIR**.
