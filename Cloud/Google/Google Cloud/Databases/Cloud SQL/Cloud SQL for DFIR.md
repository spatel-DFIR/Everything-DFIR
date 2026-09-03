# Cloud SQL for DFIR

Cloud SQL cases answer: **was the DB exposed, was a backdoor user made, and was data exported?** You read config events (exposure/export) and, where enabled, connection/DB audit logs.

New to it? Read **What is Cloud SQL** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Default |
|--------|--------------|---------|
| **Admin Activity** | Config/export/user changes | ✅ On |
| **Data Access** | Connections | 🔴 Off |
| **DB audit logs** | The SQL run | 🔴 Off (enable in-DB) |
| **Instance metadata** | Public IP + authorized networks | Live |

## Collect It

```bash
# Exposure + config
gcloud sql instances describe <inst> --format='value(ipConfiguration)'

# Config/export/user events in the window
gcloud logging read \
 'protoPayload.methodName:("cloudsql.instances.update" OR "cloudsql.instances.export"
   OR "cloudsql.instances.clone" OR "cloudsql.users")' --freshness=30d --format=json
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Exposure check | Public IP + `0.0.0.0/0` authorized network? SSL/Auth Proxy required? |
| 2. User changes | New/modified DB users (backdoor / password reset) |
| 3. Export/clone | `export` to a bucket / `clone` = data copied out |
| 4. Attribute | Who made each change, from where |
| 5. Query trail | DB audit logs (if on) for the SQL executed |

## Hunt at Scale

**Exports (exfil) + instances opened to the internet:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.methodName AS method, protopayload_auditlog.resourceName AS inst
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName IN
      ('cloudsql.instances.export','cloudsql.instances.clone','cloudsql.instances.update')
ORDER BY timestamp DESC;
```

> **At the very end — SecOps UDM (optional):** land export + config-open events to correlate the actor. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Close exposure | Remove `0.0.0.0/0`; require SSL/Auth Proxy; use private IP |
| Kill backdoor access | Reset/remove rogue DB users; rotate passwords |
| Contain exfil | Identify the export bucket; treat as data breach |
| Preserve | Export config/user/export events; snapshot/backup the instance |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Private IP + Auth Proxy**; no public IP | No internet exposure |
| **IAM database authentication** | No standing DB passwords |
| **Enable DB audit logging** (pgAudit / audit) | Prove the SQL run |
| **Restrict `cloudsql.instances.export`** | Fewer exfil paths |
| **Alert** on export/clone + `0.0.0.0/0` config | Catch exfil/exposure live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Public IP + `0.0.0.0/0` authorized network | Exposed database |
| New DB user / password reset | Backdoor access |
| `instances.export` to an unfamiliar bucket | Data exfil |
| `clone`/`restoreBackup` to another project | Data copied out |
| Instance deleted | Destruction |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Cloud SQL fundamentals | **Cloud SQL → What is** |
| Who changed/exported it | **GCP → Cloud Audit Logs** |
| Where an export landed | **GCP → Cloud Storage** |
| Data exfil end to end | **GCP → Playbooks → Data Exfiltration** |

## Resources

- Cloud SQL auditing — https://cloud.google.com/sql/docs/postgres/pg-audit
- Configure IP / private IP — https://cloud.google.com/sql/docs/mysql/configure-private-ip
- MITRE ATT&CK: T1213 Data from Information Repositories / T1530 — https://attack.mitre.org/techniques/T1213/
