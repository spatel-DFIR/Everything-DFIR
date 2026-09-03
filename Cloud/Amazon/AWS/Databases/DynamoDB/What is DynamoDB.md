# What is DynamoDB?

**DynamoDB** is AWS's fully-managed **NoSQL key-value / document database** — serverless tables that scale automatically. It's a common backend for apps that store user data, sessions, and metadata, which makes it a **data-exfiltration target**.

For DFIR, the key facts are: access is **IAM-controlled** (no network endpoint to firewall), object-level reads (**`Scan`/`GetItem`**) are **data events that are off by default**, and whole tables can be exfiltrated via **`ExportTableToPointInTime`** or shared backups.

## Contents

- [How It Works](#how-it-works)
- [How Data Leaves DynamoDB](#how-data-leaves-dynamodb)
- [The Logging Gotcha](#the-logging-gotcha)
- [How to Identify DynamoDB in Evidence](#how-to-identify-dynamodb-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
Table → Items (rows) identified by a partition key (+ optional sort key)
   access is 100% IAM-controlled (no VPC/SG unless via a VPC endpoint)
   Read: GetItem / Query / Scan   Write: PutItem / UpdateItem / DeleteItem
   Backups: PITR + on-demand; Export to S3; Streams for change capture
```

- **Regional**, serverless — **no instance, no network exposure** to misconfigure; access is purely IAM + resource policy.
- Reads range from a single `GetItem` to a full-table `Scan` (the exfil primitive).
- **Streams** capture every change; **PITR/export** can dump a whole table to S3.

## How Data Leaves DynamoDB

| Vector | What happens | Signature |
|--------|--------------|-----------|
| **Full-table `Scan`** | Attacker reads the entire table | 🔴 large/repeated `Scan` by an unusual identity (data event) |
| **Export to S3** | `ExportTableToPointInTime` dumps the table to a bucket | 🔴 export to an attacker-controlled/opened bucket |
| **Backup share / restore** | Backup restored elsewhere | Backup + cross-account restore |
| **Streams redirect** | A new stream/trigger ships changes out | 🔴 new stream → attacker Lambda |
| **Over-broad IAM** | An app/role with `dynamodb:*` on `*` | Broad grants = broad reach |

> 🔴 **`ExportTableToPointInTime` is the clean whole-table exfil:** it writes the entire table to S3 in one call. Watch for exports to unfamiliar buckets — pair with the **S3** investigation of the destination.

## The Logging Gotcha

Same pattern as S3: item-level access needs data events.

| Event class | Example | Default |
|-------------|---------|---------|
| **Management** | `CreateTable`, `UpdateTable`, `CreateBackup` | ✅ On |
| **Data** | `GetItem`, `Query`, `Scan`, `PutItem`, `DeleteItem` | 🔴 Off — enable data events |

> 🔴 Without DynamoDB **data events**, you can't see the `Scan` that read the table — only management changes. Enable data events on tables holding sensitive data.

## How to Identify DynamoDB in Evidence

- **`eventSource`:** `dynamodb.amazonaws.com`.
- **ARNs:** `arn:aws:dynamodb:<region>:<acct>:table/<name>`.
- **In a data event:** the table is in `requestParameters.tableName`.

## Common Operations You Will See

| Operation | Class | What it does | Watch? |
|-----------|-------|--------------|--------|
| `Scan` / `Query` / `GetItem` | Data | Read items | 🔴 bulk `Scan` = exfil |
| `PutItem` / `UpdateItem` / `DeleteItem` | Data | Write/delete items | 🔴 mass delete/overwrite = destruction |
| `ExportTableToPointInTime` | Mgmt | Dump table to S3 | 🔴 whole-table exfil |
| `CreateBackup` / `RestoreTableFromBackup` | Mgmt | Backup / restore | 🔴 restore elsewhere = exfil |
| `UpdateTable` (streams) / `EnableKinesisStreamingDestination` | Mgmt | Change change-capture | 🔴 exfil pipeline |
| `PutResourcePolicy` | Mgmt | Table resource policy | 🔴 cross-account access |
| `DeleteTable` | Mgmt | Destroy the table | 🔴 destruction |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| DynamoDB | Cosmos DB | Firestore / Bigtable |
| Scan/Query | Cosmos query | Firestore query |
| Export to S3 | Cosmos data export | Firestore export |
| Streams | Cosmos change feed | Firestore triggers |

## Common Use Cases

Your "normal":

- **App backends** — user profiles, sessions, metadata, carts.
- **High-scale key-value** — gaming, IoT, ad-tech.
- **Serverless data** — paired with Lambda.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Table / item / attribute** | The DB / row / field |
| **Partition (+ sort) key** | The primary key |
| **Scan** | Read the whole table |
| **PITR** | Point-in-time recovery |
| **Export to S3** | Dump a table to a bucket |
| **Streams** | Change-data-capture feed |
| **Resource policy** | Table-level (cross-account) access policy |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating DynamoDB exfil | **DynamoDB → DynamoDB for DFIR** |
| The S3 bucket an export lands in | **AWS → Storage → S3** |
| The IAM roles that reach the table | **AWS → Identity & Access → IAM** |
| The Lambda that queries it | **AWS → Compute → Lambda** |

## Resources

- What is DynamoDB — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Introduction.html
- Logging data events — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html
- Export to S3 — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DataExport.html
- Resource-based policies — https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-resource-based.html
