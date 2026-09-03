# DynamoDB for DFIR

DynamoDB has no network to firewall and no host to image — a breach is an **IAM + data-event** story: who read/exported the table, and did anyone widen access or wire an exfil pipeline.

New to the service? Read **What is DynamoDB** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate](#investigate)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

DynamoDB answers **"who read or exported this table, and did access get widened?"** — with the caveat that item-level reads are only visible if data events were on.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| CloudTrail `dynamodb.*` (mgmt) | Table/backup/export/policy/stream changes + actor | ✅ On |
| **Data events** | `Scan`/`Query`/`GetItem`/`PutItem` + identity | 🔴 Off — enable |
| Table config | Resource policy, streams, PITR, export history | Live pull |
| The S3 export destination | What a table export dumped | → S3 |

## Collect It

```bash
# Tables + their config (resource policy, streams, PITR)
aws dynamodb list-tables
aws dynamodb describe-table --table-name <t> \
  --query '{Stream:LatestStreamArn,SSE:SSEDescription}'
aws dynamodb get-resource-policy --resource-arn <table-arn> 2>/dev/null   # cross-account?
aws dynamodb describe-continuous-backups --table-name <t>                 # PITR state
aws dynamodb list-exports --table-arn <table-arn>                         # 🔴 exports to S3

# Who exported / changed access?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ExportTableToPointInTime --max-results 20
```

> **Console:** DynamoDB → table → **Exports and streams**, **Backups** (PITR), **Resource-based policy**, **Additional settings** (encryption).

## Investigate

| Step | Do this |
|------|---------|
| 1. Exfil-by-export | Any `ExportTableToPointInTime`? To which S3 bucket? Is that bucket yours? (→ S3) |
| 2. Exfil-by-scan | With data events: bulk/repeated `Scan` by an unusual identity/IP |
| 3. Access widening | `PutResourcePolicy` (cross-account), over-broad IAM roles reaching the table |
| 4. Exfil pipeline | New Streams / Kinesis destination → attacker Lambda/target |
| 5. Destruction | Mass `DeleteItem`, `DeleteTable`, or backup deletion |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `ExportTableToPointInTime`, `Scan`, `PutResourcePolicy`, `DeleteTable` |
| `requestParameters.tableName` | Which table | The crown-jewel table |
| `requestParameters.s3Bucket` (export) | Export destination | 🔴 unfamiliar/attacker bucket |
| `userIdentity` | Who | Unexpected identity/role |
| `sourceIPAddress` | From where | External/new |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
-- Table exports + access-policy changes
SELECT eventtime, useridentity.arn, eventname,
       json_extract_scalar(requestparameters,'$.tableName') AS tbl,
       json_extract_scalar(requestparameters,'$.s3Bucket') AS dest
FROM cloudtrail_logs
WHERE eventsource = 'dynamodb.amazonaws.com'
  AND eventname IN ('ExportTableToPointInTime','PutResourcePolicy','CreateBackup','DeleteTable')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "ExportTableToPointInTime"
```

## Respond

| Goal | Action |
|------|--------|
| Cut cross-account access | Remove the offending resource-policy statements |
| Stop an exfil pipeline | Disable the new stream / Kinesis destination + its target |
| Scope the loss | Where the export landed (S3) → who could read it; with data events, which items were scanned |
| Contain the identity | Deactivate key / revoke sessions; scope the role down (→ IAM/STS) |
| Recover | Restore from PITR/backup if items were destroyed |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege IAM** on tables (no `dynamodb:*` on `*`) | Limits who can Scan/Export |
| **Enable data events** on sensitive tables | See reads/exfil next time |
| **Encrypt with KMS** (CMK) + tight key policy | Confidentiality + limits shared restores |
| **PITR + backups**; deletion protection | Recover from destruction |
| **VPC endpoints** + endpoint policy | Keep access private and scoped |
| **Alert** on `ExportTableToPointInTime`, `PutResourcePolicy`, stream changes | Catch exfil live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `ExportTableToPointInTime` to an unfamiliar bucket | Whole-table exfil |
| Bulk `Scan` by an unusual identity/IP | Data exfiltration |
| `PutResourcePolicy` granting external account | Cross-account access |
| New stream/Kinesis destination → external target | Exfil pipeline |
| Mass `DeleteItem` / `DeleteTable` | Destruction |
| Data events not enabled on a sensitive table | Can't scope reads — hardening gap |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What DynamoDB is | **DynamoDB → What is DynamoDB** |
| The S3 bucket an export lands in | **AWS → Storage → S3** |
| The roles that reach the table | **AWS → Identity & Access → IAM** |
| The Lambda querying it | **AWS → Compute → Lambda** |

## Resources

- Logging DynamoDB data events — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
- Export to S3 — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DataExport.html
- Resource-based policies — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-resource-based.html
- MITRE ATT&CK: Data from Cloud Storage (T1530) — https://attack.mitre.org/techniques/T1530/
