# Log Analytics Workspace for DFIR

The workspace is **where you actually run the KQL** that every other Azure/Entra "for DFIR" note points you toward. This note is the *how*: accessing it, scoping a query correctly, and the gotchas that make an otherwise-correct query return the wrong answer.

New to the concept? Read **What is a Log Analytics Workspace** first — it covers region-scoping, retention, the Sentinel relationship, and KQL fundamentals (`summarize`, `mv-expand`, joins, `ago()`).

🔴 **Scope note:** this note covers *running queries interactively during an investigation*. It does not cover turning a KQL query into a scheduled/near-real-time **Sentinel analytics rule** — that's detection engineering, a separate topic and explicitly out of scope here.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Access It](#access-it)
- [Scoping a Query Correctly](#scoping-a-query-correctly)
- [Common Gotchas](#common-gotchas)
- [Worked Example](#worked-example)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

The workspace itself doesn't generate evidence — it **stores and serves** whatever other services exported to it.

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Structured tables** (`SigninLogs`, `AzureActivity`, `AuditLogs`, `NSGFlowLogs`, etc.) | Schema'd, service-specific columns | Workspace's configured retention (default 30 days, up to 730 with interactive tier) | Field-level KQL queries |
| **Free-text tables** (`Syslog`, custom text-based log ingestion) | Raw text lines, minimal schema | Same as above | Grep-style `search`/`has` queries — no rich field structure to `project` |
| **Archived Logs** | Older data past interactive retention | Up to 12 years total | Long-look-back, but needs a **search job** or **table restore** first — not instant KQL |

🔴 A **structured table** and a **free-text table** are not interchangeable in how you query them — see Gotchas below.

## Access It

Three ways in, same underlying data:

**1. Azure Portal — Logs blade.**

> **Console:** the workspace resource → **Logs**, or (if Sentinel is enabled on it) **Microsoft Sentinel → Logs** — both point at the same tables. Paste KQL, set the time-range picker, run.

**2. CLI — `az monitor log-analytics query`.**

```bash
az monitor log-analytics query \
  --workspace <workspace-id> \
  --analytics-query "SigninLogs | where TimeGenerated > ago(1d) | take 20" \
  --output table
```

> Use the **workspace GUID** (not the resource name) for `--workspace`. Get it with:
> ```bash
> az monitor log-analytics workspace show \
>   --resource-group <rg> --workspace-name <name> --query customerId -o tsv
> ```

**3. REST API** — for scripted/automated pulls outside the CLI:

```bash
curl -X POST \
  "https://api.loganalytics.io/v1/workspaces/<workspace-id>/query" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"query": "SigninLogs | where TimeGenerated > ago(1d) | take 20"}'
```

All three run the **same KQL** — pick portal for exploration, CLI/REST for scripted or repeatable pulls (e.g. feeding a timeline export).

## Scoping a Query Correctly

Two things to get right before trusting a result:

**1. The right workspace.** A tenant/subscription can have multiple workspaces (see What is → How It Works). Confirm which workspace(s) the source you care about actually exports to — check the source's **diagnostic settings**, not just "the workspace I know about":

```bash
az monitor diagnostic-settings list --resource <resource-id> -o table
```

**2. The right time range.** Every table query should filter `TimeGenerated` explicitly and early — both for correctness and because an unscoped query over months of data is slow and can hit result-size limits.

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-01T00:00:00Z) .. datetime(2026-07-11T00:00:00Z))
| where UserPrincipalName == "alice@contoso.com"
```

> **Portal:** the time-range picker at the top of the Logs blade sets an *implicit* filter — but an explicit `TimeGenerated` `where` in the query itself is what travels correctly if the query is saved, shared, or run via CLI/REST where there's no picker.

## Common Gotchas

| Gotcha | What it means for you |
|--------|------------------------|
| 🔴 **Ingestion delay** | Data isn't queryable the instant it happens — allow a **few minutes to ~15+ minutes** depending on the table/source (Entra/Activity Log tables are typically fast; some diagnostic-log tables lag more). A query that returns nothing for "just now" may just be too soon — re-run before concluding a gap. |
| 🔴 **Structured vs free-text table schema** | Structured tables (`SigninLogs`, `AzureActivity`) have real columns you `project`/`where` on directly. Free-text tables (`Syslog`, custom text ingestion) are closer to raw log lines — use `search`/`has`/`parse` instead of assuming named fields exist. Copy-pasting a `project ColumnName` query written for `SigninLogs` onto a free-text table will error or return nothing. |
| **Wrong workspace, silent empty result** | An empty result set looks identical whether "nothing happened" or "you're querying the wrong workspace." Always confirm the diagnostic-setting target before trusting a zero-row answer. |
| **Retention gap** | A query with no time-range error but zero rows for an old incident may mean the data aged out — check the workspace's retention setting (see What is → Retention Configuration) before concluding absence of evidence. |
| **Case sensitivity** | KQL string operators (`==`, `has`, `contains`) have case-sensitive and case-insensitive variants (e.g. `==` is case-sensitive; `=~` is not). A query that "should" match but doesn't is often a case mismatch. |
| **CSV export local time, JSON stays UTC** | Same trap as the raw Entra/Activity Log portal exports — see the callout in **Microsoft → 00 Overview & Terminology → Where Evidence Lives**. KQL's own `TimeGenerated` is UTC; don't let a downstream CSV export quietly shift it. |

## Worked Example

Grounding the fundamentals in a table you'll recognize from elsewhere in this module — pulling a specific user's sign-ins over a bounded window, the same pattern used in **Entra ID → Sign-in Logs for DFIR**:

```kql
SigninLogs
| where TimeGenerated between (datetime(2026-07-01T00:00:00Z) .. datetime(2026-07-11T00:00:00Z))
| where UserPrincipalName == "alice@contoso.com"
| summarize Attempts = count(), Failures = countif(ResultType != 0), IPs = make_set(IPAddress) by bin(TimeGenerated, 1h)
| where Failures > 0
| order by TimeGenerated asc
```

What this does, operator by operator: scope to the window (`where TimeGenerated between`) → scope to the identity (`where UserPrincipalName`) → group into hourly buckets and count total vs failed attempts plus the distinct IPs seen (`summarize ... by bin(...)`) → keep only hours with at least one failure (`where Failures > 0`) → sort oldest-first for a readable timeline (`order by`).

Swap the table for `AzureActivity` and the field names for `Caller`/`OperationNameValue`/`CallerIpAddress` to run the equivalent pull against infrastructure changes instead of sign-ins — see **Azure → Activity Log for DFIR → Hunt at Scale** for that table's own worked queries.

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Identify the workspace(s) | Check the source's diagnostic settings — don't assume there's only one |
| 2. Check retention | Confirm the incident window falls inside the configured retention (or that Archive/search-job access is needed) |
| 3. Scope the query | Time range first, then identity/resource/IP — see above |
| 4. Pick the right table shape | Structured (`project`/`where` on named columns) vs free-text (`search`/`parse`) |
| 5. Build outward with `summarize`/`join` | Aggregate to spot volume anomalies; join across tables (e.g. sign-in → role grant) to build a chain of events |
| 6. Account for ingestion delay | Don't conclude "nothing happened" from a query run seconds after the suspected event |

## Respond

The workspace itself isn't something you "respond to" in the sense of containing an attacker — but its **configuration** is part of the evidence trail and worth protecting mid-incident:

| Goal | Action |
|------|--------|
| Preserve evidence before retention/lifecycle changes | Note the current retention setting; export/save query results for the case file rather than relying on being able to re-run the query later |
| Confirm no one shortened retention or deleted diagnostic settings mid-incident | See Red Flags below — check `AzureActivity` for changes to the workspace resource itself |
| Widen visibility if a source was never exported | Stand up the missing diagnostic setting going forward (doesn't backfill history, but closes the gap for the rest of the incident) |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Set interactive retention deliberately** (not left at the 30-day default) for security-relevant tables | Matches how far back your org expects to be able to investigate |
| **Confirm diagnostic settings exist** for every source this module documents (Activity Log, sign-in/audit logs, NSG Flow Logs, VM agent logs) | A workspace with nothing exported to it is a false sense of coverage |
| **RBAC-scope workspace access** (`Log Analytics Reader` vs `Contributor`) | Query access shouldn't require the ability to change retention or delete data |
| **Alert on retention shortening or diagnostic-setting deletion** (via `AzureActivity` itself) | Catches an attacker narrowing the evidence window |
| **Consider Archive tier** for long-term/compliance retention instead of just extending interactive retention | Cheaper for data you rarely query but must keep |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Workspace retention shortened mid-incident | Defense evasion — narrowing the window an investigator can query |
| Diagnostic setting deleted or scope narrowed on a source | Blinding — the source stops feeding the workspace going forward |
| A source you expected to see in the workspace has zero rows for the whole window | Either never exported, or evasion — confirm the diagnostic setting, don't assume "nothing happened" |
| Query results stop abruptly mid-incident with no corresponding drop in source activity | Possible ingestion/export interruption — verify via the source's own native retention (e.g. Activity Log's 90-day portal view) as a cross-check |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What a workspace is, retention, region-scoping, KQL fundamentals | **Log Analytics Workspace → What is Log Analytics Workspace** |
| Querying Activity Log data specifically | **Azure → Activity Log for DFIR → Hunt at Scale** |
| Querying sign-in data specifically | **Entra ID → Sign-in Logs for DFIR → Hunt at Scale** |
| Querying directory-change data specifically | **Entra ID → Audit Logs for DFIR** |
| Retention traps across the Microsoft module generally | **Microsoft → 00 Overview & Terminology → Where Evidence Lives** |
| Where Sentinel fits if it's enabled | **Log Analytics Workspace → What is Log Analytics Workspace → Workspace vs Sentinel** |

## Resources

- Log Analytics workspace overview — https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview
- `az monitor log-analytics query` reference — https://learn.microsoft.com/cli/azure/monitor/log-analytics
- Log Analytics REST API — https://learn.microsoft.com/rest/api/loganalytics/
- KQL quick reference — https://learn.microsoft.com/kusto/query/kql-quick-reference
- Data retention and archive — https://learn.microsoft.com/azure/azure-monitor/logs/data-retention-archive
- MITRE ATT&CK: N/A — a Log Analytics Workspace is an investigative query surface, not an attacker technique. It's most often used to confirm/expand events already mapped to ATT&CK by the source table's own "for DFIR" note (e.g. **Sign-in Logs**, **Activity Log**).
