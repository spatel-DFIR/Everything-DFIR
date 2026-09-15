# What is CloudTrail?

CloudTrail is AWS's **audit log**. It records every action taken in an account as a JSON *event* — who did it, what they did, when, and from where.

Think of it as **CCTV for API calls**. Almost every attacker step shows up here first.

## Contents

- [How It Works](#how-it-works)
- [The Three Event Types](#the-three-event-types)
- [Where Events Live and How You Query Each](#where-events-live-and-how-you-query-each)
- [Proving Logs Weren't Tampered With](#proving-logs-werent-tampered-with)
- [How to Identify CloudTrail in Evidence](#how-to-identify-cloudtrail-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

Everything you do in AWS is an API call. CloudTrail writes **one JSON event per call**.

A **trail** is the thing that saves those events somewhere durable.

The pipeline:

| Step | What happens |
|------|--------------|
| 1. Action | Someone clicks in the console, or runs `aws`, an SDK, or another AWS service |
| 2. API call | That action becomes an API call (e.g. `CreateUser`) |
| 3. Event | CloudTrail records the call as a JSON event |
| 4. Trail | The trail delivers the event to storage |
| 5. Storage | Lands in **S3** (always), and optionally **CloudWatch Logs** and **CloudTrail Lake** |

Two timing facts to remember on a live case:

- Events are **not instant** — allow up to ~15 minutes from action to log file in S3.
- Order is **not guaranteed** — always sort by `eventTime`.

## The Three Event Types

| Type | Records | On by default? |
|------|---------|----------------|
| **Management events** | Control-plane actions: `RunInstances`, `CreateUser`, `AssumeRole`, `ConsoleLogin` | ✅ Yes (90-day history); saved long-term only if a trail exists |
| **Data events** | Data-plane actions: S3 `GetObject`, Lambda `Invoke`, DynamoDB item reads | 🔴 **No** — must be turned on (high volume, extra cost) |
| **Insights events** | CloudTrail's own alerts on unusual API *rates* | ❌ No — opt-in per trail |

🔴 The default blind spot: without **data events**, you see that someone *called* `GetObject`, but not *which objects* they read. Enable data events on your crown-jewel buckets.

## Where Events Live and How You Query Each

The **same events** can land in up to four places. Each has a different look-back, cost, and query language — and on a case you'll use different ones for different questions.

| Destination | What it is | Look-back | How you query it | Best for |
|-------------|-----------|-----------|------------------|----------|
| **Event history** | Free, always-on console view of the last 90 days of **management** events. No trail needed. | 90 days | Console filters · `aws cloudtrail lookup-events` | The fast first look; "what did this user do lately?" |
| **S3 bucket** (a trail's delivery target) | The durable, raw `.json.gz` files | Bucket lifecycle — often **years** | Download + `jq`, or **Athena** SQL | The real evidence; long look-back; offline timeline |
| **CloudTrail Lake** | A managed store you query with SQL; no S3 plumbing | Up to **7–10 years** | **CloudTrail Lake SQL** (`StartQuery`) | Retro-hunt across accounts/regions without building Athena |
| **CloudWatch Logs** (optional trail target) | Near-real-time stream of events | Log-group retention | **Logs Insights** queries; metric filters + alarms | Alerting (e.g. fire on `StopLogging`) |

> **Rule of thumb:** *last 90 days, quick* → Event history. *Older / court-grade* → S3 + Athena. *Multi-year hunt* → Lake. *Real-time alert* → CloudWatch Logs.

**Athena vs Lake — the practical difference:** Athena runs SQL directly over the `.json.gz` files already in S3 (you pay per-TB scanned; you define the table). Lake is a managed copy with SQL built in (you pay to ingest + store; nothing to set up). Most mature orgs have one or the other — check which exists before you build anything.

## Proving Logs Weren't Tampered With

If **log file integrity validation** was enabled on the trail, CloudTrail also writes a **digest file** every hour to S3.

- Each digest is **signed** and lists the hash of every log file delivered that hour, chained to the previous digest.
- You verify the chain with `aws cloudtrail validate-logs`. If a log file was altered or deleted, validation **fails** — that's your tamper proof.
- 🔴 Digest files themselves can be a target: a missing digest, or a validation failure, is itself evidence of tampering.

> This is what makes CloudTrail **court-defensible**. Turn it on *before* you need it — you can't retroactively sign old logs. See **CloudTrail for DFIR → Collect It**.

## How to Identify CloudTrail in Evidence

**In S3, the log file path looks like this:**

```
s3://<bucket>/AWSLogs/<accountId>/CloudTrail/<region>/YYYY/MM/DD/
     <account>_CloudTrail_<region>_<timestamp>_<random>.json.gz
```

**The event JSON is an array of records:**

```jsonc
{ "Records": [ { "eventName": "...", "userIdentity": { ... } } ] }
```

**ARNs you will see:**

| Thing | ARN shape |
|-------|-----------|
| A trail | `arn:aws:cloudtrail:<region>:<acct>:trail/<name>` |
| A Lake data store | `arn:aws:cloudtrail:<region>:<acct>:eventdatastore/<id>` |

**Quick tells that you're looking at CloudTrail:** a `Records[]` array, an `eventSource` ending in `.amazonaws.com`, and a `userIdentity` block on every event.

## Common Operations You Will See

These are CloudTrail's **own** API actions — the ones you audit to check nobody tampered with logging:

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `CreateTrail` / `UpdateTrail` | Create or change a trail | 🔴 `UpdateTrail` can narrow scope |
| `StartLogging` / `StopLogging` | Turn delivery on / off | 🔴 `StopLogging` = blinding |
| `DeleteTrail` | Remove a trail | 🔴 evidence destruction |
| `PutEventSelectors` | Choose which events are captured | 🔴 can silently drop data events |
| `LookupEvents` | Search the 90-day history | Normal analyst/tool use |
| `GetTrailStatus` | Check if a trail is logging | Normal |
| `StartQuery` | Run a CloudTrail Lake SQL query | Normal |

> CloudTrail also *records* the operations of **every other service** — that's what you actually investigate. See **CloudTrail for DFIR**.

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud | Microsoft 365 | Google Workspace |
|-----|-------|--------------|---------------|------------------|
| **CloudTrail** (management events) | **Azure Activity Log** | **Cloud Audit Logs** — Admin Activity | **Unified Audit Log (UAL)** | **Admin audit log** |
| CloudTrail **data events** | Azure **resource / diagnostic logs** | Cloud Audit Logs — **Data Access** | UAL (per-workload) | Drive/Gmail audit logs |

If you know CloudTrail, you already understand the *shape* of the others: an identity, an action, a source, an outcome.

## Common Use Cases

Why organizations run CloudTrail (this is your baseline for "normal"):

- **Security monitoring** — feed detections and investigations.
- **Compliance** — an auditable record of every change.
- **Operational troubleshooting** — "who deleted that resource?"
- **Change tracking** — reconstruct how the environment got to its current state.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Event** | One recorded API call (JSON) |
| **Trail** | Config that delivers events to S3 / CloudWatch / Lake |
| **Management event** | Control-plane action (default on) |
| **Data event** | Data-plane action (off by default) |
| **Insights event** | Anomaly on API *rate* |
| **Event history** | Free, searchable last-90-days of management events (no trail needed) |
| **CloudTrail Lake** | Managed store you query with SQL; long retention |
| **Event data store** | The container Lake queries run against |
| **Digest file** | Signed file used to prove logs weren't tampered with |
| **Organization trail** | One trail capturing every account in the AWS Org |
| **Multi-region trail** | One trail capturing all regions |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating CloudTrail in a case | **CloudTrail → CloudTrail for DFIR** |
| Who the identities are (user vs role vs token) | **AWS → 01 IAM & Identities** |
| How AWS accounts/Orgs/regions fit together | **AWS → 00 Overview & Terminology** |
| The equivalents in other clouds | **Cloud → 06 Cloud Service Equivalents** |

## Resources

- CloudTrail concepts — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html
- Record contents — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- CloudTrail Lake — https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html
