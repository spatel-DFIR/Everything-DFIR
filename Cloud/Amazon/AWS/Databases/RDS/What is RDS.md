# What is RDS?

**RDS (Relational Database Service)** is AWS's **managed relational databases** — MySQL, PostgreSQL, MariaDB, Oracle, SQL Server, and **Aurora**. AWS runs the engine, patching, and backups; you own the data and access.

For DFIR, RDS is a **crown-jewel data store**, and it gets breached in cloud-specific ways: a **publicly-accessible** instance, a **shared DB snapshot** (whole-database exfil, exactly like EBS), or stolen DB credentials. There's no host to log into — you investigate via the **cloud API, DB engine logs, and network reachability**.

## Contents

- [How It Works](#how-it-works)
- [The Cloud-Specific Attack Surface](#the-cloud-specific-attack-surface)
- [Snapshots — Whole-Database Exfil](#snapshots--whole-database-exfil)
- [Logging](#logging)
- [How to Identify RDS in Evidence](#how-to-identify-rds-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

```
DB instance (or Aurora cluster) in a VPC subnet group
   ├── reached over the DB port (3306/5432/1433…), gated by a Security Group
   ├── auth: master user + DB users (or IAM auth)
   ├── automated + manual SNAPSHOTS (shareable, like EBS)
   └── engine logs (audit/error/slow/general) → CloudWatch Logs (if enabled)
```

- **Regional**, in a VPC; reachability is a **security-group + public-accessibility** question.
- Managed engine → you get **API events** (control plane) and **engine logs** (if exported), but **no OS**.
- **Snapshots** work like EBS: point-in-time DB copies that can be **shared or made public**.

## The Cloud-Specific Attack Surface

| Vector | What happens | Signature |
|--------|--------------|-----------|
| **Public accessibility** | Instance set `PubliclyAccessible=true` + SG open | 🔴 `ModifyDBInstance` publicly-accessible; SG `0.0.0.0/0:3306` |
| **Snapshot sharing** | Snapshot shared to attacker account / made public | 🔴 `ModifyDBSnapshotAttribute` add external/`all` |
| **Stolen DB creds** | Master/DB user creds reused | DB engine auth logs; app-side |
| **Master password reset** | Attacker resets the master user | 🔴 `ModifyDBInstance` master password |
| **Delete + no backups** | Instance/snapshots deleted | 🔴 `DeleteDBInstance` (skip final snapshot) |

## Snapshots — Whole-Database Exfil

The RDS version of the EBS snapshot-share attack:

```
CreateDBSnapshot  →  ModifyDBSnapshotAttribute (restore-permission: add attacker accountId / all)
   → [attacker account] RestoreDBInstanceFromDBSnapshot → full database, read at leisure
```

> 🔴 **A DB snapshot shared to an external account (or public) is a whole-database breach** — no query logs needed, the attacker just restores your data in their account. Encryption (KMS) helps: sharing an encrypted snapshot also requires sharing the key. Watch `ModifyDBSnapshotAttribute` and `ModifyDBClusterSnapshotAttribute`.

## Logging

| Log | Contains | Default |
|-----|----------|---------|
| CloudTrail `rds.*` | Instance/snapshot/parameter changes + actor | ✅ On (mgmt) |
| **DB engine logs** (audit/general/error/slow) | Connections + queries (engine-dependent) | 🔴 Off — export to CloudWatch |
| **Database Activity Streams** (Aurora) | Near-real-time SQL activity | Opt-in |
| **RDS in GuardDuty** | Anomalous logins | Add-on |

> 🔴 Query-level evidence (what SQL ran, which rows) requires **engine audit logs** or **Activity Streams** enabled beforehand. Without them, you can prove *access was possible* but not *what was read* — mirror of the S3 data-events gap.

## How to Identify RDS in Evidence

- **`eventSource`:** `rds.amazonaws.com`.
- **ARNs:** `arn:aws:rds:<region>:<acct>:db:<instance>` / `:cluster:<name>` / `:snapshot:<id>`.
- **Endpoints:** `<name>.<id>.<region>.rds.amazonaws.com`.

## Common Operations You Will See

| Operation | What it does | Watch? |
|-----------|--------------|--------|
| `ModifyDBInstance` (PubliclyAccessible) | Expose to internet | 🔴 public DB |
| `ModifyDBInstance` (master password) | Reset master creds | 🔴 credential takeover |
| `CreateDBSnapshot` | Snapshot the DB | Normal — 🔴 if followed by a share |
| `ModifyDBSnapshotAttribute` | Share a snapshot | 🔴 external/public = exfil |
| `RestoreDBInstanceFromDBSnapshot` | Restore a snapshot | Attacker restoring stolen data (in their acct) |
| `DeleteDBInstance` (skip final snapshot) | Destroy the DB | 🔴 destruction |
| `ModifyDBClusterSnapshotAttribute` | Aurora snapshot share | 🔴 exfil |
| `AuthorizeDBSecurityGroupIngress` / SG change | Open DB port | 🔴 exposure |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| RDS / Aurora | Azure SQL / DB for MySQL/Postgres | Cloud SQL / AlloyDB |
| DB snapshot | DB backup/export | Cloud SQL backup/export |
| Publicly accessible | Public network access | Public IP + authorized networks |
| Database Activity Streams | SQL audit logs | Cloud SQL audit logs |

## Common Use Cases

Your "normal":

- **App backends** — the primary datastore.
- **Managed HA/replicas** — Multi-AZ, read replicas.
- **Backups/DR** — automated snapshots, cross-region copies.

## Key Terminology

| Term | Meaning |
|------|---------|
| **DB instance / cluster** | The database server / Aurora cluster |
| **Master user** | The admin DB account |
| **Snapshot** | A point-in-time DB copy (shareable) |
| **Publicly accessible** | Whether it has a public endpoint |
| **Subnet group / SG** | Where it lives / what can reach it |
| **Parameter/option group** | Engine config (incl. audit logging) |
| **Database Activity Streams** | Near-real-time SQL activity (Aurora) |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating RDS breach/exfil | **RDS → RDS for DFIR** |
| The snapshot-share pattern (EBS analog) | **AWS → Storage → EBS** |
| Network reachability | **AWS → Networking → VPC** |
| Who did it | **AWS → 01 IAM & Identities** |

## Resources

- What is RDS — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Welcome.html
- Sharing a DB snapshot — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
- RDS database logs — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html
- Database Activity Streams — https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/DBActivityStreams.html
