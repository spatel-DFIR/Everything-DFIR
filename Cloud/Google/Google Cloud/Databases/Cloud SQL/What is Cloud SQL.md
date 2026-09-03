# What is Cloud SQL?

**Cloud SQL** is GCP's managed relational database (MySQL, PostgreSQL, SQL Server) — the equivalent of AWS RDS and Azure SQL. For DFIR the recurring issues are **public exposure** (a public IP + open authorized networks), **weak credentials**, and **exfil via export** to a bucket.

## Contents

- [How It Works](#how-it-works)
- [How Instances Get Exposed](#how-instances-get-exposed)
- [The Evidence Layers](#the-evidence-layers)
- [How to Identify It in Evidence](#how-to-identify-it-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

- A **Cloud SQL instance** hosts databases + users. It has a **public IP** and/or **private IP**.
- Access is gated by **authorized networks** (IP allowlist), the **Cloud SQL Auth Proxy**, and/or **IAM database authentication**.
- Config is Admin Activity logged; **connections/queries** need Data Access or DB audit logging.

## How Instances Get Exposed

🔴 A Cloud SQL instance is exposed when:

| Setting | Result |
|---------|--------|
| **Public IP** + authorized network `0.0.0.0/0` | Internet-reachable database |
| **Weak/default DB user password** | Brute-forceable |
| **No SSL/Auth Proxy required** | Plaintext / unauthenticated paths |
| **Broad IAM** (`cloudsql.instances.*`) | Attacker can export/clone data |

## The Evidence Layers

| Layer | Log | Default |
|-------|-----|---------|
| **Control plane** (create/config/export) | Admin Activity | ✅ On |
| **Connections** | Data Access | 🔴 Off |
| **Database queries** | DB audit logs (pgAudit / MySQL/SQL Server audit) | 🔴 Off — enable in-DB |

🔴 Without DB audit logging you can prove config changes and exports, but **not the SQL an attacker ran** inside the DB.

## How to Identify It in Evidence

- **Resource name:** `//cloudsql.googleapis.com/projects/<p>/instances/<name>`.
- **Config events:** `cloudsql.instances.create/update/export/clone`, `cloudsql.users.*`.
- **Exposure:** the instance's `ipConfiguration` (public IP + authorized networks).

## Common Operations You Will See

| methodName | What it does | 🔴 |
|-----------|--------------|----|
| `cloudsql.instances.update` | Change config (IP/networks/flags) | 🔴 open to `0.0.0.0/0` |
| `cloudsql.instances.export` | Export DB to GCS | 🔴 exfil |
| `cloudsql.instances.clone` / `restoreBackup` | Copy the data | 🔴 exfil via copy |
| `cloudsql.users.create/update` | DB user changes | 🔴 backdoor user / password |
| `cloudsql.instances.delete` | Delete instance | 🔴 destruction |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| Cloud SQL | RDS | Azure SQL Database |
| Authorized networks | Security group | Firewall rules |
| Cloud SQL Auth Proxy | RDS Proxy / IAM auth | Private endpoint |
| `instances.export` | RDS snapshot/export | Export/BACPAC |
| IAM database auth | IAM DB auth | Entra auth |

## Common Use Cases

Your "normal": app backends behind private IP + Auth Proxy. 🔴 A **public IP with `0.0.0.0/0`** is almost never right. The job is to spot exposure, backdoor DB users, and exports to unexpected buckets.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Instance** | The managed DB server |
| **Authorized networks** | IP allowlist for public IP |
| **Auth Proxy** | Secure connection helper |
| **IAM database authentication** | Log in with a Google identity |
| **Export** | Dump DB to GCS |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a Cloud SQL case | **Cloud SQL → for DFIR** |
| Who changed/exported it | **GCP → Cloud Audit Logs** |
| Where an export landed | **GCP → Cloud Storage** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- Cloud SQL — https://cloud.google.com/sql/docs
- Authorized networks / IP config — https://cloud.google.com/sql/docs/mysql/configure-ip
- Database auditing — https://cloud.google.com/sql/docs/postgres/pg-audit
