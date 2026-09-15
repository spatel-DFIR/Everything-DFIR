# What is Security Lake?

**Amazon Security Lake** is a managed data lake that pulls your security telemetry — CloudTrail, VPC Flow Logs, Route 53 Resolver query logs, GuardDuty findings, and more — out of their native formats and into **one normalized schema (OCSF)**, stored in **S3**, queryable with **Athena**.

Think of it as **CloudTrail Lake's bigger sibling**: instead of one source (management events) in one shape, Security Lake takes *many* sources and reshapes them all to look the same, so you can join a network event to an API call to a GuardDuty finding without hand-mapping field names first.

## Contents

- [How It Works](#how-it-works)
- [OCSF — the Normalized Schema](#ocsf--the-normalized-schema)
- [What Feeds It](#what-feeds-it)
- [Security Lake vs CloudTrail Lake vs Raw-Log Athena](#security-lake-vs-cloudtrail-lake-vs-raw-log-athena)
- [The Subscriber Model](#the-subscriber-model)
- [How to Identify Security Lake in Evidence](#how-to-identify-security-lake-in-evidence)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Security Lake is opt-in per account/region and typically set up **org-wide** from a delegated administrator account.

```
Source logs (CloudTrail, VPC Flow, Route 53 Resolver, GuardDuty, Security Hub, custom)
        │
        ▼
Security Lake normalizes each event to OCSF and writes Parquet files to S3
        │  (one S3 bucket per region, owned by the Security Lake admin account)
        ▼
Query with Athena over Lake Formation-governed tables  ── or ──  hand off to a subscriber (SIEM)
```

Key mechanics:

- **Multi-account, multi-region aggregation.** Point every member account and every region at one central S3-backed lake instead of stitching together per-account trails yourself.
- **Storage format is Apache Parquet**, partitioned by source, region, account, and date — built for large-scale SQL scans, not line-by-line `jq`.
- **Access is governed by AWS Lake Formation**, not plain S3 bucket policies — permissions are grant-based per table/source.
- 🔴 **Off by default and not free.** Like Flow Logs and CloudTrail data events, nothing lands here until Security Lake is enabled for a source/region — check before you assume it exists.

## OCSF — the Normalized Schema

**OCSF (Open Cybersecurity Schema Framework)** is an open, vendor-neutral event schema. Every source Security Lake ingests gets mapped into OCSF **event classes** — e.g. `API Activity` (from CloudTrail), `Network Activity` (from VPC Flow Logs), `DNS Activity` (from Route 53 Resolver logs), `Security Finding` (from GuardDuty/Security Hub).

Every OCSF event shares a common backbone regardless of source:

| OCSF field | Answers | Source-specific example |
|-----------|---------|--------------------------|
| `time` | When | Same shape whether it came from CloudTrail or Flow Logs |
| `actor.user` | Who | CloudTrail `userIdentity` mapped in |
| `src_endpoint` / `dst_endpoint` | Network who-talked-to-whom | Flow Logs 5-tuple mapped in |
| `api.operation` | The API call | CloudTrail `eventName` mapped in |
| `severity_id` / `status_id` | Outcome | GuardDuty severity, CloudTrail `errorCode` |
| `metadata.product.name` | Which source produced it | `"Cloudtrail"`, `"Amazon VPC"`, `"Amazon GuardDuty"` |

🔴 This is the whole point: without OCSF, correlating "this IP called `AssumeRole`" (CloudTrail) with "this IP had a rejected connection" (Flow Logs) with "GuardDuty already flagged this IP" (findings) means three differently-shaped tables and three sets of field names. In OCSF they're the same shape — one `WHERE src_endpoint.ip = '...'` clause spans all three.

## What Feeds It

**Native AWS sources** (no per-service setup beyond enabling the source in Security Lake):

| Source | OCSF class | What it adds |
|--------|-----------|---------------|
| **CloudTrail** (management events) | API Activity | Who did what, from where |
| **VPC Flow Logs** | Network Activity | Who talked to whom on the network |
| **Route 53 Resolver query logs** | DNS Activity | Domain names behind an IP |
| **GuardDuty findings** | Security Finding | Pre-triaged managed detections |
| **Security Hub findings** | Security Finding | Aggregated findings from other services |
| **EKS audit logs** | API Activity (Kubernetes) | Control-plane actions inside a cluster |
| **S3 data events** (via CloudTrail) | API Activity | Object-level S3 access |

**Custom sources:** third-party or in-house tools can write their own OCSF-formatted data into the lake via the Security Lake custom-source API — out of scope here since this repo stays native-AWS-tooling-focused, but worth knowing it's not limited to the built-in sources above.

## Security Lake vs CloudTrail Lake vs Raw-Log Athena

Three ways to run SQL over AWS security data — know which one you're looking at:

| | **Athena over raw S3 logs** | **CloudTrail Lake** | **Security Lake** |
|---|---|---|---|
| Sources | Whatever you point Athena at (usually just CloudTrail) | CloudTrail events only | CloudTrail **+ VPC Flow + DNS + GuardDuty + more**, one schema |
| Schema | Each source's native JSON shape | CloudTrail's native shape | **OCSF** — normalized across sources |
| Scope | One bucket/table you build | One account or org, CloudTrail-only | **Multi-account, multi-region**, all enabled sources |
| Setup | You define the DDL/partitions | Enable Lake, done | Enable Security Lake per source/region; Athena tables provided |
| Best for | One-off queries on one source | Long CloudTrail-only retro-hunt | **Cross-source correlation** in a single query |

> If the question is "what did this CloudTrail identity do," Lake or raw Athena is enough. If the question is "correlate this identity's API calls with the network traffic and the GuardDuty finding, in one query," that's what Security Lake exists for.

## The Subscriber Model

Security Lake data doesn't have to stay in Athena. A **subscriber** is a consumer registered against the lake:

- **Data access subscriber** — gets direct query access (Lake Formation permissions) or an S3 notification feed, for pulling normalized data into a SIEM, a notebook, or a custom pipeline.
- **Query access subscriber** — queries the lake in place via Athena/Lake Formation without a copy of the data leaving AWS.

This is how Security Lake acts as the **normalization layer in front of** a downstream SIEM: instead of the SIEM ingesting and reshaping five raw AWS log formats itself, it subscribes to one already-normalized OCSF feed.

## How to Identify Security Lake in Evidence

- **S3 path shape:** `s3://aws-security-data-lake-<region>-<hash>/<source>/region=<region>/accountid=<acct>/eventDay=<YYYYMMDD>/` — Parquet files, not `.json.gz`.
- **Glue/Athena database:** named `amazon_security_lake_glue_db_<region>`, with per-source tables like `amazon_security_lake_table_<region>_cloud_trail_mgmt_2_0`.
- **CloudTrail tell:** Security Lake's own control-plane actions (`CreateDataLake`, `CreateAwsLogSource`, `CreateSubscriber`) appear as `securitylake.amazonaws.com` events in CloudTrail.

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| **Security Lake** (OCSF-normalized multi-source lake) | Sentinel data lake / Log Analytics workspace (KQL, not OCSF) | Chronicle / Google SecOps (UDM-normalized) |
| OCSF event classes | Sentinel tables (native schema per source) | UDM (Unified Data Model) |

Security Lake's role is closest conceptually to what **UDM does inside Google SecOps** — a normalized schema across heterogeneous sources — except Security Lake keeps the data natively in your own S3, queryable with Athena, rather than in a separate SIEM platform.

## Common Use Cases

- **Cross-source correlation** — one query spanning CloudTrail + Flow Logs + DNS + GuardDuty.
- **Centralizing multi-account, multi-region telemetry** without building per-account Athena tables by hand.
- **Feeding a SIEM a pre-normalized stream** via the subscriber model, instead of the SIEM doing the normalization.
- **Long-term, cost-efficient retention** — Parquet + S3 lifecycle rules scale further than raw JSON.

## Key Terminology

| Term | Meaning |
|------|---------|
| **OCSF** | Open Cybersecurity Schema Framework — the normalized event schema Security Lake writes to |
| **Event class** | An OCSF category (API Activity, Network Activity, DNS Activity, Security Finding, …) |
| **Rollup Region** | A region you designate to also receive a copy of data from other regions |
| **Delegated administrator** | The account that manages Security Lake org-wide |
| **Custom source** | A non-native feed written into the lake in OCSF format |
| **Subscriber** | A consumer (query access or data access) registered against the lake |
| **Lake Formation** | The permissions layer governing who can query which Security Lake tables |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating Security Lake in a case | **Security Lake → Security Lake for DFIR** |
| The raw CloudTrail source it normalizes | **AWS → Logging & Monitoring → CloudTrail** |
| The raw VPC Flow Logs source it normalizes | **AWS → Logging & Monitoring → VPC Flow Logs** |
| The GuardDuty findings it normalizes | **AWS → Security & Detection → GuardDuty** |
| Where this fits your first-hour toolkit | **AWS → 02 Investigating AWS (start here)** |

## Resources

- Security Lake overview — https://docs.aws.amazon.com/security-lake/latest/userguide/what-is-security-lake.html
- OCSF schema — https://schema.ocsf.io/
- Security Lake source-to-OCSF mapping — https://docs.aws.amazon.com/security-lake/latest/userguide/source-management.html
- Querying data with Athena — https://docs.aws.amazon.com/security-lake/latest/userguide/query-data.html
