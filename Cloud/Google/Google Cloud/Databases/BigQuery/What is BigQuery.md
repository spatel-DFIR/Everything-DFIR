# What is BigQuery?

**BigQuery** is GCP's serverless data warehouse — petabyte-scale analytics over **datasets** and **tables**. It's the crown-jewels **data-exfiltration target** in many GCP environments. One helpful quirk for responders: **BigQuery Data Access logging is ON by default**, so queries and extracts are usually visible.

## Contents

- [How It Works](#how-it-works)
- [The Good News — Data Access Logging Is On](#the-good-news--data-access-logging-is-on)
- [How Data Leaves BigQuery](#how-data-leaves-bigquery)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- **Datasets** hold **tables/views**; access is via IAM (dataset/table level) and authorized views.
- Users run **query jobs**; **extract jobs** export to GCS; **copy jobs** duplicate datasets.
- Jobs and data reads are logged in Cloud Audit Logs (Data Access).

## The Good News — Data Access Logging Is On

🔴 Unlike GCS and most services, **BigQuery emits Data Access audit logs by default** — query jobs, `tabledata.list`, and extracts are recorded (`serviceName="bigquery.googleapis.com"`, `metadata.jobChange`/`tableDataRead`). So you can usually reconstruct **exactly what was queried and extracted, by whom.** Confirm it wasn't disabled.

## How Data Leaves BigQuery

| Path | Evidence | 🔴 |
|------|----------|----|
| **Large query + result download** | `jobservice.jobcompleted` / `jobChange`, bytes billed/processed | Bulk read |
| **Extract job → GCS** | `extract` job with a GCS destination | Exfil to a bucket |
| **Copy dataset/table** | `copy` job to another dataset/project | Exfil via copy |
| **Dataset shared externally** | `SetIamPolicy` adding an external principal | External access |
| **Scheduled query / transfer** | A recurring exfil job | Persistence |

## How to Identify It in Evidence

- **Resource name:** `//bigquery.googleapis.com/projects/<p>/datasets/<ds>/tables/<t>`.
- **Job events:** `google.cloud.bigquery.v2.JobService.InsertJob` / `jobcompleted`; `tabledata.list`.
- **Access changes:** `SetIamPolicy` on datasets; `datasets.update` (ACLs).

## Common Operations You Will See

| Operation | What it does | 🔴 |
|-----------|--------------|----|
| Query job (`jobChange`) | Run SQL | 🔴 huge scans / sensitive tables |
| `tableDataRead` | Read table data | 🔴 volume |
| Extract job → GCS | Export data | 🔴 exfil |
| Copy job | Duplicate data | 🔴 exfil |
| `SetIamPolicy` (dataset) | Share dataset | 🔴 external grantee |
| Scheduled query created | Recurring job | 🔴 persistence/exfil |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| BigQuery | Redshift / Athena | Synapse / Azure SQL DW |
| Dataset / table | Schema / table | Database / table |
| Extract job → GCS | UNLOAD → S3 | Export to Blob |
| Data Access logs (on) | Redshift/Athena logs | Diagnostic logs |
| SCC BigQuery Exfil finding | GuardDuty exfil | Defender data alert |

## Common Use Cases

Your "normal": analytics, dashboards, ETL, ML feature stores. High-volume querying is normal — the job is to spot **abnormal** access: a user/SA suddenly scanning sensitive tables, extracting to an unfamiliar bucket, or a dataset shared externally.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Dataset / table / view** | Data containers |
| **Query job** | A SQL execution |
| **Extract job** | Export to GCS |
| **Authorized view** | A view granting scoped access |
| **Scheduled query** | A recurring job |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating BigQuery exfil | **BigQuery → for DFIR** |
| Who queried/extracted | **GCP → Cloud Audit Logs** |
| Where an extract landed | **GCP → Cloud Storage** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- BigQuery — https://cloud.google.com/bigquery/docs
- BigQuery audit logs — https://cloud.google.com/bigquery/docs/reference/auditlogs
- Controlling access to datasets — https://cloud.google.com/bigquery/docs/dataset-access-controls
