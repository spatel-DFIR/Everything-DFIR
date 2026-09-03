# What is a Log Analytics Workspace?

A **Log Analytics Workspace** is Azure's central **log data store** — a container that holds structured log/telemetry data as a set of queryable tables, plus the query engine (**KQL**) that reads them. Every "for DFIR" note in this module that says "query `AzureActivity`" or "query `SigninLogs`" is telling you to run a **KQL** query against a workspace.

Think of it as **the S3-bucket-plus-Athena of Azure/Entra logging** — a durable store *and* a query surface in one resource, except here the query language is built in rather than bolted on.

🔴 A workspace is not a log source itself — it's *where* other services (Activity Log, Entra sign-in/audit logs, VM agents, NSG Flow Logs, App Service, etc.) send data once you've configured a **diagnostic setting** to export to it. If nothing was ever exported, the workspace exists but is empty for that source.

## Contents

- [How It Works](#how-it-works)
- [Region-Scoping and Data Residency](#region-scoping-and-data-residency)
- [Retention Configuration](#retention-configuration)
- [Workspace vs Sentinel — The Relationship](#workspace-vs-sentinel--the-relationship)
- [KQL Fundamentals](#kql-fundamentals)
- [How to Identify a Workspace in Evidence](#how-to-identify-a-workspace-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Source (Activity Log / Entra logs / VM agent / NSG / App Service / custom)
   → Diagnostic setting (the export config)
   → Log Analytics Workspace (ingestion → table)
   → KQL query (portal Logs blade / CLI / REST / Sentinel)
```

A workspace is an **Azure resource** like any other — it has a resource group, a subscription, a region, and RBAC. Data lands in it as rows in **tables** (`SigninLogs`, `AzureActivity`, `AuditLogs`, `Syslog`, custom tables, etc.), each row timestamped by an ingestion-side field called `TimeGenerated`.

A tenant or subscription can have **multiple workspaces** — teams often split by environment (prod/dev), by business unit, or centralize into one for security. 🔴 Before you query, confirm you're looking at *every* workspace a source might have exported to. A query that returns nothing can mean "nothing happened" or "wrong workspace."

## Region-Scoping and Data Residency

A workspace is created **in a specific Azure region** and its data is stored there — this is a data-residency commitment, not just a performance setting.

- Resources being logged **do not need to be in the same region** as the workspace they export to — a diagnostic setting can ship a West Europe VM's logs to an East US workspace.
- 🔴 **Investigation implication:** if the organization operates under data-residency requirements (GDPR, sovereign-cloud, regulatory), the workspace's region tells you *which jurisdiction's legal process applies to that evidence* — not the resource's region. Note the workspace region explicitly when documenting evidence provenance.
- Cross-region query is possible (a Sentinel/KQL query can reach across workspaces with **cross-workspace queries**, see below), but each workspace's data still physically resides in its own region.

## Retention Configuration

Retention is a **per-workspace setting**, and it's the single most important thing to check before you assume evidence exists.

| Setting | Default | Range | Notes |
|---------|---------|-------|-------|
| **Interactive retention** | **30 days** | 30–730 days (2 years) | How far back a normal KQL query searches |
| **Total retention (with Archive)** | — | Up to **12 years** | Older data moves to lower-cost **Archived Logs** — queryable, but needs a **search job** or **restore** first, not instant KQL |
| **Per-table retention override** | Inherits workspace default | Configurable per table | Some tables (e.g. security-relevant ones) are often set longer than the workspace default |

🔴 **Why this matters for how far back you can hunt:** the workspace default is only **30 days** unless someone explicitly extended it. An incident that predates the configured retention has **no data in the workspace to query** — full stop, regardless of how good your KQL is. Confirm the retention setting (and whether Archive tiers exist) *before* concluding "nothing happened" from an empty query result.

```bash
# Check a workspace's configured retention
az monitor log-analytics workspace show \
  --resource-group <rg> --workspace-name <workspace> \
  --query "{retentionInDays:retentionInDays}"
```

## Workspace vs Sentinel — The Relationship

🔴 The distinction that trips up new readers: **Microsoft Sentinel is not a separate log store — it's a SIEM/SOAR layer that sits on top of a Log Analytics Workspace.**

| | Log Analytics Workspace | Microsoft Sentinel |
|---|---|---|
| **What it is** | The data store + KQL query engine | A SIEM/SOAR product *enabled onto* a workspace |
| **Can exist without the other?** | ✅ Yes — a workspace works standalone, no Sentinel required | ❌ No — Sentinel always requires an underlying workspace |
| **What it adds** | Nothing extra — raw tables + KQL | Incidents, analytics rules, UEBA, threat intelligence, workbooks, playbooks |
| **Data location** | The tables live here either way | Same tables — Sentinel just reads and correlates them |

**The practical takeaway:** you do **not** need Sentinel enabled to investigate with KQL. If an organization exported Activity Log / sign-in logs / VM logs to a workspace but never turned on Sentinel, every KQL query in this module's "for DFIR" notes still works exactly the same way — you're just running them from the workspace's own **Logs** blade instead of Sentinel's. Sentinel's value-add (correlation rules, incident queues, automated response) is a separate, additional layer on top — and this repo's Azure/Entra coverage is deliberately scoped to **investigation with the workspace/KQL itself**, not to Sentinel's detection-rule authoring.

## KQL Fundamentals

**KQL (Kusto Query Language)** is Microsoft's native query language for Log Analytics/Sentinel/Application Insights/Azure Data Explorer. It is **unrelated to Kibana's query language** despite the similar-sounding name — this is Azure's own built-in query surface, the same role Athena/SQL plays for CloudTrail.

A KQL query is a **pipeline**: start with a table, then chain operators with `|`, each one filtering or transforming the output of the one before it.

```kql
TableName
| where <condition>
| project <columns>
| order by <column>
```

**The core operators you'll see everywhere:**

| Operator | Does | Example |
|----------|------|---------|
| `where` | Filters rows | `where ResultType == 0` |
| `project` | Picks/renames columns (like `SELECT`) | `project TimeGenerated, UserPrincipalName` |
| `extend` | Adds a computed column | `extend Hour = bin(TimeGenerated, 1h)` |
| `summarize` | Aggregates rows into groups | `summarize count() by UserPrincipalName` |
| `order by` / `sort by` | Sorts results | `order by TimeGenerated desc` |
| `take` / `limit` | Caps row count | `take 50` |
| `distinct` | Unique values | `distinct IPAddress` |

**`summarize` — the aggregation workhorse:**

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize FailCount = count() by UserPrincipalName, IPAddress
| where FailCount > 10
```

This groups rows by `UserPrincipalName` + `IPAddress` and counts them — the shape behind almost every "hunt at scale" query in this module (spray detection, enumeration bursts, etc.).

**`mv-expand` — unpacking arrays/dynamic fields:**

Many Azure/Entra log fields are JSON arrays or objects packed into a single column (e.g. a sign-in's `AuthenticationDetails`, or an Activity Log entry's `Properties`). `mv-expand` turns each array element into its own row so you can filter/aggregate on it:

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| mv-expand AuthDetail = parse_json(AuthenticationDetails)
| where AuthDetail.succeeded == false
```

**Joins — combining two tables:**

```kql
SigninLogs
| where ResultType == 0
| join kind=inner (
    AuditLogs
    | where OperationName == "Add member to role"
  ) on $left.UserId == $right.InitiatedBy.user.id
```

`kind=inner` keeps only matching rows; `kind=leftouter` keeps all left-side rows even without a match. Joins are how you tie a sign-in to what the identity did next (e.g. a successful sign-in followed by a role grant).

**Time-range filtering — always do this first:**

Every table has a `TimeGenerated` column (ingestion timestamp). Filtering on it early keeps queries fast and scoped:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-01) .. datetime(2026-07-11))
```

```kql
SigninLogs
| where TimeGenerated > ago(7d)
```

`ago(7d)` means "7 days before now" — common units are `d` (days), `h` (hours), `m` (minutes). 🔴 Put the time filter as the **first** `where` clause — KQL evaluates top to bottom, and filtering on time first means every later operator works on a smaller, cheaper set of rows.

**Cross-workspace queries** — if evidence is split across workspaces, reach into another one without switching context:

```kql
workspace("other-workspace-name").SigninLogs
| where TimeGenerated > ago(7d)
```

## How to Identify a Workspace in Evidence

- **Resource ID shape:** `/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>`
- **Portal:** Log Analytics workspaces (its own resource blade) — or reached indirectly via **Microsoft Sentinel → Logs**, which points at the same underlying workspace.
- **Workspace ID (GUID)** — used when querying via API/CLI instead of by name.
- Query results reference the source table name directly (`SigninLogs`, `AzureActivity`, `AuditLogs`, `Syslog`) — that table name is your clue to which diagnostic setting fed it.

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Log Analytics Workspace (store) | S3 bucket (a trail's target) / CloudTrail Lake | Cloud Logging bucket |
| KQL (query engine) | Athena SQL / CloudTrail Lake SQL | BigQuery SQL / Logs Explorer |
| Diagnostic setting (the export config) | Trail (delivers events to S3/CloudWatch/Lake) | Log sink (routes to a destination) |
| Sentinel (SIEM layer on top) | Security Lake + Detective (analysis layer) | Chronicle/Google SecOps (SIEM layer) |

If you know Athena-over-S3 or CloudTrail Lake, you already understand the shape here: a durable store, plus a SQL-like language to query it, with an optional SIEM product built on top.

## Common Use Cases

- **Investigation/hunting** — the primary use in this module: KQL queries against `SigninLogs`, `AzureActivity`, `AuditLogs`, VM/NSG data.
- **Operational monitoring** — dashboards, workbooks, alerting on infrastructure health.
- **Long-term log retention** — the answer to Activity Log's and Entra's short native retention windows.
- **Centralized cross-resource correlation** — one place to join sign-in data against resource changes.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Log Analytics Workspace** | The Azure resource holding queryable log tables |
| **KQL (Kusto Query Language)** | The native query language for the workspace |
| **Table** | One log type's rows (`SigninLogs`, `AzureActivity`, etc.) |
| **`TimeGenerated`** | The ingestion timestamp column present on every table |
| **Diagnostic setting** | The export config that routes a source's logs into a workspace |
| **Interactive retention** | The default queryable window (30–730 days) |
| **Archive tier** | Lower-cost, longer-term storage (up to 12 years); needs a search job/restore to query |
| **Sentinel** | The SIEM/SOAR layer optionally enabled on top of a workspace |
| **Cross-workspace query** | A KQL query reaching into another workspace via `workspace("name")` |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating with a workspace day-to-day | **Log Analytics Workspace → for DFIR** |
| The tables this powers | **Azure → Activity Log**, **Entra ID → Sign-in Logs**, **Entra ID → Audit Logs** |
| Where evidence lives + retention traps generally | **Microsoft → 00 Overview & Terminology → Where Evidence Lives** |
| Identity types behind query results | **Microsoft → 01 Entra ID & Identities** |

## Resources

- Log Analytics workspace overview — https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
- Data retention and archive — https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-archive
- KQL quick reference — https://learn.microsoft.com/kusto/query/kql-quick-reference
- KQL tutorial — https://learn.microsoft.com/azure/data-explorer/kusto/query/tutorials/learn-common-operators
- Microsoft Sentinel overview — https://learn.microsoft.com/azure/sentinel/overview
