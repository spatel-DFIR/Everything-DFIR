# RDS for DFIR

An RDS breach is usually one of three things: **the DB got exposed to the internet**, **a snapshot was shared out**, or **credentials were abused**. Because there's no OS, you work the **cloud API, network reachability, and engine logs**.

New to the service? Read **What is RDS** first.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — The Three Scenarios](#investigate--the-three-scenarios)
- [Reading the Events](#reading-the-events)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

RDS answers **"was the database exposed or copied out, and by whom?"** The data is the prize; the cloud-plane moves (public toggle, snapshot share) are how it leaves.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| CloudTrail `rds.*` | Public toggle, snapshot share, password reset, delete + actor | ✅ On |
| **Engine audit/general logs** | Connections + SQL (engine-dependent) | 🔴 Off — export to CloudWatch |
| **Activity Streams** (Aurora) | Near-real-time SQL | Opt-in |
| Snapshot attributes | Who a snapshot is shared with | Live pull |
| Instance config | Public accessibility, SG, encryption | Live pull |

## Collect It

```bash
# Posture: is anything public? what can reach it?
aws rds describe-db-instances \
  --query 'DBInstances[].{Id:DBInstanceIdentifier,Public:PubliclyAccessible,Enc:StorageEncrypted,SGs:VpcSecurityGroups}'

# 🔴 Snapshots shared externally / public?
aws rds describe-db-snapshots --snapshot-type manual \
  --query 'DBSnapshots[].DBSnapshotIdentifier' --output text
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <snap>   # look for 'all' or external acct

# Who toggled public / shared snapshots / reset the master?
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ModifyDBSnapshotAttribute --max-results 30
```

> **Console:** RDS → databases → *Connectivity & security* (Publicly accessible, SG), *Maintenance & backups*. RDS → **Snapshots** → *Share snapshot* (who it's shared with). CloudWatch for exported engine logs.

## Investigate — The Three Scenarios

**1. Public exposure:**

| Step | Do this |
|------|---------|
| 1 | Is `PubliclyAccessible=true` and the SG open to `0.0.0.0/0` on the DB port? |
| 2 | When did it change? CloudTrail `ModifyDBInstance` / Config timeline |
| 3 | Who from the internet connected? Engine logs (if on) + VPC Flow Logs to the DB ENI |

**2. Snapshot exfil:**

| Step | Do this |
|------|---------|
| 1 | Any manual snapshot shared to an external account or public? |
| 2 | Correlate `CreateDBSnapshot` → `ModifyDBSnapshotAttribute` (share) in the timeline |
| 3 | Was it encrypted? If not, assume the recipient restored + read the whole DB |

**3. Credential / data abuse:**

| Step | Do this |
|------|---------|
| 1 | Master password reset (`ModifyDBInstance`)? New DB users? |
| 2 | Engine audit logs: unusual logins, bulk `SELECT`/dump queries, off-hours access |
| 3 | App-side logs for the DB creds' origin (leaked in code/config?) |

## Reading the Events

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `eventName` | The action | `ModifyDBInstance` (public/password), `ModifyDBSnapshotAttribute`, `DeleteDBInstance` |
| `requestParameters.publiclyAccessible` | Exposure toggle | 🔴 `true` |
| `requestParameters` (snapshot attr) | Share targets | 🔴 external acct / `all` |
| `userIdentity` | Who | Unexpected identity |
| `requestParameters.skipFinalSnapshot` | On delete | 🔴 `true` = destroy with no backup |

## Hunt at Scale

**In-platform — Athena / Lake:**

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'rds.amazonaws.com'
  AND eventname IN ('ModifyDBSnapshotAttribute','ModifyDBClusterSnapshotAttribute','ModifyDBInstance','DeleteDBInstance')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):**

```text
metadata.log_type = "AWS_CLOUDTRAIL"
metadata.product_event_type = "ModifyDBSnapshotAttribute"
```

## Respond

| Goal | Action |
|------|--------|
| Re-privatize | Set `PubliclyAccessible=false`; tighten the SG to app subnets only |
| Cut snapshot exfil | `modify-db-snapshot-attribute --values-to-remove` (unshare); make private |
| Rotate creds | Reset the master + all DB users; rotate app secrets |
| Assess loss | With engine logs: which queries ran. Without: scope by data sensitivity |
| Preserve | Take a controlled snapshot for evidence; export engine logs |
| Recover | Restore from a clean automated snapshot if destroyed |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Never `PubliclyAccessible`**; DB in private subnets, SG to app only | No internet-reachable DB |
| **Encrypt at rest (KMS)** + tight key policies | Shared snapshots are useless without the key |
| **SCP/alert** on `ModifyDBSnapshotAttribute`(share), `PubliclyAccessible=true` | Catch exposure/exfil live |
| **Enable engine audit logs** / Aurora Activity Streams | Query-level evidence next time |
| **IAM database auth** where possible; rotate master; Secrets Manager | Fewer standing DB creds |
| **Deletion protection** + final snapshots | No easy destruction |
| **GuardDuty RDS Protection** | Anomalous-login detection |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `PubliclyAccessible` toggled true + open SG | Internet-exposed database |
| DB snapshot shared to external account / public | Whole-database exfil |
| `CreateDBSnapshot` → share, back to back | Deliberate DB theft |
| Master password reset by an unexpected identity | DB credential takeover |
| `DeleteDBInstance` with `skipFinalSnapshot: true` | Destruction, no recovery |
| Bulk `SELECT`/dump in engine logs off-hours | Data exfiltration |
| Unencrypted snapshots of sensitive DBs | Nothing stopping share-read |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What RDS is | **RDS → What is RDS** |
| The EBS snapshot-share analog | **AWS → Storage → EBS** |
| Network reachability | **AWS → Networking → VPC**, **VPC Flow Logs** |
| Who did it | **AWS → 01 IAM & Identities**, **IAM for DFIR** |

## Resources

- Sharing a DB snapshot — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html
- RDS log access — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.html
- RDS security best practices — https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_BestPractices.Security.html
- MITRE ATT&CK: Data from Cloud Storage / Transfer to Cloud Account (T1530 / T1537) — https://attack.mitre.org/techniques/T1537/
