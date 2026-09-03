# BigQuery for DFIR

BigQuery cases are exfil cases — and the good news is the evidence usually exists: **who queried what, how much they read, and where they extracted it.**

New to it? Read **What is BigQuery** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Quantify the Exfil](#quantify-the-exfil)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Default |
|--------|--------------|---------|
| **Data Access (jobChange/tableDataRead)** | Queries + reads + bytes | ✅ **On** |
| **Admin Activity** | Dataset IAM changes, scheduled queries | ✅ On |
| **INFORMATION_SCHEMA.JOBS** | Query job history (SQL text, bytes) | In-BQ |

## Collect It

```bash
# Extract (exfil) + copy jobs in the window
gcloud logging read \
 'resource.type="bigquery_resource" AND protoPayload.methodName="google.cloud.bigquery.v2.JobService.InsertJob"
  AND protoPayload.serviceData.jobInsertResponse.resource.jobConfiguration.extract:*' --freshness=30d
```

```sql
-- Query jobs by a suspect principal (SQL text + bytes) from INFORMATION_SCHEMA
SELECT creation_time, user_email, statement_type, total_bytes_processed, query
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE user_email = 'attacker@contoso.com'
ORDER BY total_bytes_processed DESC;
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Anchor the principal | User or SA; from where |
| 2. Review query jobs | SQL text, tables touched, bytes processed (volume) |
| 3. Find extracts/copies | Export to GCS / copy to another dataset/project |
| 4. Check sharing | Dataset `SetIamPolicy` adding external principals |
| 5. Check persistence | New scheduled queries / transfers |

## Quantify the Exfil

| Question | Evidence |
|----------|----------|
| Which tables were read? | jobChange / tableDataRead resourceNames |
| How much data? | `total_bytes_processed` / bytes read |
| Was it exported? | Extract job destination (GCS URI) |
| Shared externally? | Dataset IAM adding external members |

## Hunt at Scale

**Large extracts / high-volume readers:**

```sql
SELECT user_email, SUM(total_bytes_processed)/POW(10,12) AS tb, COUNT(*) jobs
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY user_email ORDER BY tb DESC LIMIT 25;
```

> **At the very end — SecOps UDM (optional):** land extract/copy jobs + dataset-share events to correlate the actor. Keep it light. (SCC's `BigQuery Data Extraction` finding also flags this.)

## Respond

| Goal | Action |
|------|--------|
| Cut access | Remove the principal's dataset/table IAM; disable a rogue SA |
| Kill persistence | Delete rogue scheduled queries/transfers |
| Contain exfil | Identify the destination bucket/project; treat as breach |
| Revoke sharing | Remove external dataset grants |
| Preserve | Export the job history + Data Access logs |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Least-privilege dataset IAM**; authorized views | No broad `bigquery.dataViewer` on sensitive data |
| **VPC Service Controls** around BigQuery | Blocks extract/copy outside the perimeter |
| **Restrict export** / disable to external buckets | Fewer exfil paths |
| **Column-level security + policy tags** | Protect sensitive columns |
| **Alert** on large extracts, external dataset shares, new scheduled queries | Catch exfil live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Extract job to an unfamiliar/external bucket | Data exfil |
| Copy of a sensitive dataset to another project | Exfil via copy |
| Huge `total_bytes_processed` by one principal | Bulk read |
| Dataset shared with an external principal | External access |
| New scheduled query pulling sensitive data | Persistence/exfil |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| BigQuery fundamentals | **BigQuery → What is** |
| Who queried/extracted | **GCP → Cloud Audit Logs** |
| Where an extract landed | **GCP → Cloud Storage** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- BigQuery audit logs — https://cloud.google.com/bigquery/docs/reference/auditlogs
- INFORMATION_SCHEMA.JOBS — https://cloud.google.com/bigquery/docs/information-schema-jobs
- VPC Service Controls for BigQuery — https://cloud.google.com/bigquery/docs/vpc-sc
- MITRE ATT&CK: T1530 Data from Cloud Storage / T1213 — https://attack.mitre.org/techniques/T1530/
