# Security Lake for DFIR

Security Lake is where you go when a single-source hunt (CloudTrail alone, Flow Logs alone) isn't enough — you need one identity or one IP traced **across** API calls, network traffic, DNS, and managed findings **in one query**, without hand-joining differently-shaped tables.

New to the service? Read **What is Security Lake** first. This note is the *how*.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Reading an OCSF Event](#reading-an-ocsf-event)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Retention | Best for |
|--------|--------------|-----------|----------|
| **Security Lake S3 (Parquet)** | Every enabled source, normalized to OCSF | Your configured lifecycle (often years) | Cross-source correlation, long look-back |
| **Athena over Security Lake tables** | SQL access to the same Parquet data | Same as above | The main way you'll actually query it |
| **Subscriber feed** (if configured) | A copy/stream sent to a SIEM | Depends on the subscriber | Cross-account retro-hunt outside AWS |

**In SecOps:** if a subscriber feeds Security Lake's OCSF data into Google SecOps, it lands *already* close to UDM shape — OCSF and UDM are both normalized schemas, so field mapping is thinner than mapping raw CloudTrail JSON. Confirm the actual parser/mapping in use; don't assume 1:1.

## Collect It

**Step 1 — Confirm Security Lake is actually enabled, and for which sources/regions.** Do this before assuming any data exists.

```bash
# Is Security Lake set up at all, and where
aws securitylake list-data-lakes --region us-east-1

# Which sources are configured (CloudTrail, VPC Flow, Route 53, GuardDuty, EKS audit...)
aws securitylake list-log-sources --region us-east-1
```

> **Console:** Security Lake → Summary → check regions and enabled sources.

🔴 A source not listed here means **no normalized data for it** — you'll need to fall back to that source's own native evidence (raw CloudTrail, raw Flow Logs) for the gap.

**Step 2 — Find the Athena database and tables.**

```bash
aws glue get-databases --query "DatabaseList[?starts_with(Name,'amazon_security_lake')].Name"
aws glue get-tables --database-name amazon_security_lake_glue_db_us_east_1 \
  --query "TableList[].Name"
```

> **Console:** Athena → Data source → the `amazon_security_lake_glue_db_<region>` database lists a table per source (e.g. `..._cloud_trail_mgmt_2_0`, `..._vpc_flow_2_0`, `..._route53_2_0`, `..._sh_findings_2_0`).

**Step 3 — Confirm Lake Formation grants.** Athena queries against Security Lake fail silently with permission errors if your IR role lacks a Lake Formation grant on the table, even with normal IAM S3/Glue/Athena permissions.

```bash
aws lakeformation list-permissions \
  --resource '{"Table":{"DatabaseName":"amazon_security_lake_glue_db_us_east_1","Name":"amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0"}}'
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Confirm coverage | Which sources/accounts/regions actually feed the lake for your incident window? Gaps = fall back to the native source |
| 2. Pick the anchor | An identity, IP, or hostname — OCSF's common fields (`actor.user`, `src_endpoint.ip`) let you pivot the *same* value across every source table |
| 3. Query one source at a time first | Confirm the shape/volume before writing a cross-source join |
| 4. Join across OCSF event classes | e.g. `API Activity` (CloudTrail) JOIN `Network Activity` (Flow Logs) on IP/time window |
| 5. Cross-check against native evidence | For anything load-bearing, verify against the raw CloudTrail/Flow Logs/GuardDuty source — Security Lake is a normalized *copy*, not the original |

## Reading an OCSF Event

Fields that carry most Security Lake investigations, common across event classes:

| Field | Answers | Notes |
|-------|---------|-------|
| `time` | **When** | Unix epoch; sort by this across sources |
| `actor.user.uid` / `actor.user.name` | **Who** | Mapped from CloudTrail `userIdentity` |
| `src_endpoint.ip` / `dst_endpoint.ip` | **Network who-talked-to-whom** | Mapped from Flow Logs 5-tuple |
| `api.operation` | **What API call** | Mapped from CloudTrail `eventName` |
| `severity_id` | **How bad** | Populated on `Security Finding` (GuardDuty) events |
| `status_id` / `status` | **Did it work** | Success/Failure, mapped from `errorCode` |
| `metadata.product.name` | **Which source** | `"Cloudtrail"`, `"Amazon VPC"`, `"Amazon GuardDuty"`, `"Amazon Route 53"` |
| `cloud.account.uid` / `cloud.region` | **Which account/region** | Present on every event — this is what makes org-wide queries possible |

## Hunt at Scale

**In-platform — Athena over Security Lake OCSF tables:**

```sql
-- Every action from a suspect IP, across BOTH API calls and network traffic, in one query
SELECT time, actor.user.name, api.operation, src_endpoint.ip, metadata.product.name
FROM amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0
WHERE src_endpoint.ip = '203.0.113.10'
  AND eventDay BETWEEN '20260701' AND '20260717'

UNION ALL

SELECT time, actor.user.name, CAST(NULL AS varchar) AS api_operation, src_endpoint.ip, metadata.product.name
FROM amazon_security_lake_table_us_east_1_vpc_flow_2_0
WHERE src_endpoint.ip = '203.0.113.10'
  AND eventDay BETWEEN '20260701' AND '20260717'
ORDER BY time DESC;
```

```sql
-- Cross-source correlation: tie a GuardDuty finding's IP to the API calls that IP made
SELECT ct.time, ct.actor.user.name, ct.api.operation, gd.finding_info.title
FROM amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0 ct
JOIN amazon_security_lake_table_us_east_1_sh_findings_2_0 gd
  ON ct.src_endpoint.ip = gd.resources[1].ip
 AND ct.eventDay = gd.eventDay
WHERE gd.eventDay = '20260716'
ORDER BY ct.time DESC;
```

> **Partitioning matters here too:** Security Lake tables are partitioned by `region`, `accountid`, and `eventDay` — always filter on those, or a query scans every account/region/day in the lake.

**At the very end — SecOps UDM (optional, for cross-account/cross-cloud retro-hunt):**

```text
metadata.log_type = "AWS_SECURITY_LAKE"
principal.ip = "203.0.113.10"
```

Keep SecOps light — it answers "has this IP/identity shown up elsewhere, in another cloud?" The deep, source-preserving read stays on Athena over Security Lake.

## Respond

Security Lake itself isn't the thing you contain — the identity/resource it surfaced is. Act on what you found, then confirm the lake kept recording.

| Goal | Action |
|------|--------|
| Confirm the lake wasn't blinded mid-incident | `aws securitylake list-log-sources` — check nothing was disabled during your window |
| Act on a compromised identity/IP found via correlation | Follow the source note (**CloudTrail for DFIR → Respond**, **GuardDuty for DFIR → Respond**) |
| Preserve the correlation for the case file | Export the Athena query + results (CTAS to a case-specific S3 prefix) before any lifecycle rule ages out the source data |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| Enable Security Lake **org-wide**, delegated admin in the security-tooling account | No account left un-normalized |
| Enable **all relevant sources** (CloudTrail, VPC Flow, Route 53 Resolver, GuardDuty/Security Hub, EKS audit) | Partial sources = partial correlation |
| Lock down **Lake Formation grants** to the IR role + explicit subscribers only | Prevents the lake itself from becoming an over-broad read surface |
| Set a **rollup Region** for org-wide single-pane querying | Avoids per-region Athena queries during a fast-moving case |
| Wire `DeleteDataLake` / `DeleteAwsLogSource` → **EventBridge** alert | Catch someone turning off normalization mid-incident |
| Keep the **native sources' own retention** intact (don't rely on Security Lake alone) | Security Lake is a normalized copy; native CloudTrail/Flow Logs remain your ground truth |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| A source/account/region missing from `list-log-sources` mid-investigation | Correlation gap — that slice never got normalized; fall back to the native source |
| `DeleteDataLake` / `DeleteAwsLogSource` / `DeleteSubscriber` in CloudTrail | Attacker (or panicked admin) turning off cross-source visibility |
| Lake Formation permission denied for the IR role | Access misconfigured — you have IAM rights but no data-level grant |
| A correlated identity/IP appears in `Network Activity` but never in `API Activity` for the same window | Traffic without a matching AWS API call — could be a compromised on-box process, not console/API activity |
| OCSF event counts far lower than the native source's own event count | Ingestion lag or a silently disabled source — verify against the raw log |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What the service is + OCSF/subscriber model | **Security Lake → What is Security Lake** |
| The raw CloudTrail evidence behind the `API Activity` class | **AWS → Logging & Monitoring → CloudTrail** |
| The raw Flow Logs evidence behind the `Network Activity` class | **AWS → Logging & Monitoring → VPC Flow Logs** |
| The raw GuardDuty findings behind the `Security Finding` class | **AWS → Security & Detection → GuardDuty** |
| Where this fits your first-hour toolkit | **AWS → 02 Investigating AWS (start here)** |
| Same identity pivoting to Azure/GCP | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Security Lake overview — https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html
- Querying data with Athena — https://docs.aws.amazon.com/security-lake/latest/userguide/query-data.html
- OCSF schema browser — https://schema.ocsf.io/
- Managing Lake Formation permissions for Security Lake — https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-data-access.html
- MITRE ATT&CK Cloud (IaaS) — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
