# What is Detective?

**Amazon Detective** automatically builds a **behavior graph** from your CloudTrail, VPC Flow Logs, and GuardDuty findings — then lets you **click through relationships** instead of writing queries. Given a suspicious IP, role, or finding, it shows you *everything connected to it* and how activity deviates from baseline.

For an analyst, Detective is the **"pivot and scope fast"** tool: it does the join-across-logs work for you and visualizes it. It doesn't replace reading raw CloudTrail — it accelerates getting to the right slice.

## Contents

- [How It Works](#how-it-works)
- [What It's Good At (and Not)](#what-its-good-at-and-not)
- [The Core Entities](#the-core-entities)
- [How to Identify Detective in Evidence](#how-to-identify-detective-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
CloudTrail + VPC Flow + GuardDuty findings  (auto-ingested, no setup)
        │  Detective builds a linked BEHAVIOR GRAPH + baselines
        ▼
   Analyst starts from a finding / IP / role / account
        →  sees connected entities, activity over time, deviations from normal
```

- **No data plumbing** — Detective pulls the sources itself once enabled; it retains up to **~1 year** of linked activity.
- **Regional**, org-aggregatable, and tightly integrated with GuardDuty ("**Investigate in Detective**" from any finding).
- It computes **baselines**, so it can highlight *unusual* API volume, new geolocations, and new user-agents automatically.

## What It's Good At (and Not)

| ✅ Strong | ❌ Not for |
|----------|-----------|
| Fast scoping of an IP/role/finding's full footprint | Being the system of record (that's raw CloudTrail/S3) |
| Visual pivoting across CloudTrail + Flow + GuardDuty | Custom detections (that's GuardDuty/SecOps) |
| Spotting deviation from baseline (new geo/UA/volume) | Payload-level or in-guest detail |
| Timeframe scrubbing on an entity's activity | Long-term/legal retention beyond ~1 year |

> Think of Detective as the **investigation accelerator**: it answers "what else is this connected to and is it abnormal?" in clicks. You still confirm specifics in CloudTrail and act in the resource's own domain.

## The Core Entities

Detective's graph is made of entities you pivot between:

| Entity | You learn |
|--------|-----------|
| **IP address** | Everything that IP touched; new-IP-for-this-role signal |
| **AWS role / user** | Every session, action, and resource for that identity |
| **Role session** | The `ASIA` session's full activity (great with STS cases) |
| **EC2 instance** | The instance's API + network behavior |
| **Finding (GuardDuty)** | The finding expanded into all related entities |
| **User agent / geolocation** | New tooling / new country for an identity |

## How to Identify Detective in Evidence

- **`eventSource`:** `detective.amazonaws.com` (admin actions).
- Reached mostly via console (the graph UI) or the "Investigate in Detective" link on a GuardDuty finding.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateGraph` / `DeleteGraph` | Enable/disable Detective | 🔴 `DeleteGraph` drops the investigation graph |
| `CreateMembers` / `DisassociateMembership` | Org membership | 🔴 dropping coverage |
| `StartMonitoringMember` | Begin ingesting an account | Config |
| `ListGraphs` / `Get*` | Analyst use | Normal |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| Detective | Defender / Sentinel investigation graph | SCC + Chronicle investigation |
| Behavior graph | Sentinel entity graph | Chronicle entity graph |

## Common Use Cases

Your "normal":

- **Triage a GuardDuty finding** — one click to its full context.
- **Scope a compromised identity/IP** — see everything connected, fast.
- **Baseline deviation** — "is this login geo/UA new for this role?"
- **Timeframe analysis** — scrub an entity's activity around the incident.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Behavior graph** | The linked model of entities + activity |
| **Entity** | An IP, role, session, instance, finding, etc. |
| **Profile panel** | Detective's per-entity activity view |
| **Baseline** | Learned normal for volume/geo/UA |
| **Finding overview** | A GuardDuty finding expanded in the graph |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Using Detective in a case | **Detective → Detective for DFIR** |
| The findings you'll pivot from | **AWS → Security & Detection → GuardDuty** |
| Confirming the API detail | **AWS → Logging & Monitoring → CloudTrail** |
| The identity/session behind it | **AWS → Identity & Access → STS**, **01 Identities** |

## Resources

- What is Detective — https://docs.aws.amazon.com/detective/latest/userguide/what-is-detective.html
- Analyzing findings with Detective — https://docs.aws.amazon.com/detective/latest/userguide/detective-investigation-about.html
- Integration with GuardDuty — https://docs.aws.amazon.com/detective/latest/userguide/detective-integration-guardduty.html
