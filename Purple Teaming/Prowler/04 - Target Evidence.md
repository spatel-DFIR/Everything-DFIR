# Prowler — Target Evidence (Cloud Account)

Evidence left on the **target/destination** cloud account when Prowler enumerates and audits resources. Prowler is read-only, so no resources are modified — only queried and logged.

---

## Cloud Audit Logs (Primary Signal)

### AWS CloudTrail

Prowler makes API calls via boto3 to AWS; each call is logged in CloudTrail.

#### Event Log Structure
```json
{
  "EventVersion": "1.08",
  "UserIdentity": {
    "Type": "IAMUser",
    "PrincipalId": "AIDACKCEVSQ6C2EXAMPLE",
    "Arn": "arn:aws:iam::123456789012:user/security-audit",
    "AccountId": "123456789012",
    "AccessKeyId": "AKIA...[REDACTED]"
  },
  "EventTime": "2026-08-11T14:32:15Z",
  "EventSource": "iam.amazonaws.com",
  "EventName": "ListUsers",
  "AwsRegion": "us-east-1",
  "SourceIPAddress": "192.168.1.100",
  "UserAgent": "python-requests/2.28.0",
  "RequestParameters": null,
  "ResponseElements": null,
  "ReadOnly": true,
  "EventID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "EventCategory": "Management"
}
```

#### Common Prowler API Calls (Partial List)

| Service | Event Name | Prowler Check(s) | Frequency |
|---|---|---|---|
| **IAM** | `ListUsers`, `ListRoles`, `ListPolicies`, `ListAccessKeys`, `GetUser`, `GetRole` | CIS 1.x (Access Control) | 1-2 per check |
| **EC2** | `DescribeInstances`, `DescribeSecurityGroups`, `DescribeNetworkInterfaces`, `DescribeImages`, `DescribeSnapshots` | CIS 2.x, 4.x (Networking) | Many (once per region) |
| **S3** | `ListBuckets`, `GetBucketVersioning`, `GetBucketEncryption`, `GetBucketPolicy`, `GetBucketTagging`, `GetBucketLogging` | CIS 2.3, 2.4 (Storage) | 5-10 per bucket |
| **RDS** | `DescribeDBInstances`, `DescribeDBClusters`, `DescribeDBParameterGroups` | CIS 2.2 (Database) | 3-5 per RDS resource |
| **KMS** | `DescribeKey`, `GetKeyPolicy`, `GetKeyRotationStatus` | CIS 2.7 (Encryption) | 2-3 per key |
| **CloudTrail** | `DescribeTrails`, `GetTrailStatus`, `ListTrails` | CIS 2.1 (Logging) | 3-5 |
| **CloudWatch** | `DescribeAlarms`, `GetMetricAlarms` | PCI/HIPAA (Monitoring) | 1-2 |
| **Secrets Manager** | `ListSecrets`, `DescribeSecret` | HIPAA (Credential Management) | 1+ per secret |

**Timestamp**: Each event is timestamped; Prowler scan leaves a **contiguous sequence of API calls** in CloudTrail from start to end time.

**Volume**: A typical full CIS audit makes **500-2000 API calls** depending on account resource count.

#### CloudTrail Search & Analysis

```bash
# Query CloudTrail for Prowler API calls (AWS CLI)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=security-audit \
  --max-results 100 \
  --region us-east-1 \
  --query 'Events[?ReadOnly==`true`]'

# Or via Athena (if CloudTrail logs are in S3)
SELECT eventTime, eventName, sourceIPAddress, userIdentity.principalId
FROM cloudtrail_logs
WHERE eventSource LIKE '%iam.%' OR eventSource LIKE '%ec2.%'
  AND eventTime > '2026-08-11T14:00:00Z'
  AND eventTime < '2026-08-11T14:45:00Z'
  AND readOnly = true
ORDER BY eventTime;
```

### Azure Activity Log

Prowler on Azure makes calls via Azure SDK; logged in the Activity Log (Azure Monitor).

#### Event Log Structure
```json
{
  "time": "2026-08-11T14:32:15.1234567Z",
  "resourceId": "/subscriptions/sub-id/resourceGroups/rg-name/providers/Microsoft.Compute/virtualMachines/vm-name",
  "operationName": {
    "value": "Microsoft.Compute/virtualMachines/read",
    "localizedValue": "Get Virtual Machine"
  },
  "category": {
    "value": "Administrative",
    "localizedValue": "Administrative"
  },
  "level": "Informational",
  "authorization": {
    "action": "Microsoft.Compute/virtualMachines/read",
    "scope": "/subscriptions/sub-id"
  },
  "caller": "security-audit-app@tenant.onmicrosoft.com",
  "correlationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "status": {
    "value": "Succeeded",
    "localizedValue": "Succeeded"
  }
}
```

#### Common Prowler Azure API Calls

| Service | Operation | Prowler Check(s) |
|---|---|---|
| **Subscriptions** | `Microsoft.Subscription/subscriptions/read` | Enumeration |
| **Virtual Machines** | `Microsoft.Compute/virtualMachines/read`, `listKeys` | CIS 2.x, 5.x |
| **Storage Accounts** | `Microsoft.Storage/storageAccounts/read`, `listKeys` | CIS 2.1, Encryption |
| **Network Security Groups** | `Microsoft.Network/networkSecurityGroups/read` | CIS 2.x, 3.x |
| **Key Vault** | `Microsoft.KeyVault/vaults/read`, `listSecrets` | HIPAA (Secrets) |
| **App Services** | `Microsoft.Web/sites/read` | Web Security |
| **Databases** | `Microsoft.Sql/servers/read`, `databases/read` | CIS 2.2 |
| **Access Control (IAM)** | `Microsoft.Authorization/roleAssignments/read` | CIS 1.x |

**Note:** Azure Resource Manager (ARM) API is read-heavy; Prowler's calls are tagged as `Informational` (not `Warning` or `Error`).

### GCP Cloud Audit Logs

Prowler on GCP makes calls via Google Cloud SDK; logged in Cloud Audit Logs.

#### Event Log Structure
```json
{
  "protoPayload": {
    "methodName": "storage.buckets.list",
    "resourceName": "projects/_/buckets",
    "request": {}
  },
  "insertId": "a1b2c3d4-e5f6-7890-abcd-ef",
  "resource": {
    "type": "gce_project",
    "labels": {
      "project_id": "my-gcp-project"
    }
  },
  "timestamp": "2026-08-11T14:32:15.123456Z",
  "severity": "NOTICE",
  "logName": "projects/my-gcp-project/logs/activity",
  "authenticationInfo": {
    "principalEmail": "prowler-sa@my-project.iam.gserviceaccount.com"
  },
  "requestMetadata": {
    "callerIp": "192.168.1.100",
    "userAgent": "gcloud-python/2.50.0"
  }
}
```

#### Common Prowler GCP API Calls

| Service | API Call | Prowler Check(s) |
|---|---|---|
| **Compute** | `instances.list`, `firewalls.list`, `disks.list` | CIS 2.x (Networking) |
| **Storage** | `buckets.list`, `buckets.getIamPolicy` | CIS 2.1, Encryption |
| **Cloud SQL** | `instances.list`, `backups.list` | Database Security |
| **IAM** | `roles.list`, `serviceAccounts.list`, `bindings.list` | CIS 1.x (Access) |
| **Logging** | `logSinks.list`, `auditConfigs.get` | CIS 2.6 (Logging) |
| **VPC** | `networks.list`, `routes.list` | CIS 2.x (Networking) |

**Note:** GCP logs are in `projects/{project}/logs/activity` or `cloudaudit.googleapis.com` depending on log type.

---

## Resource Enumeration Timeline

Prowler queries follow a predictable sequence; timeline reconstruction reveals scan scope.

### Example: CIS Audit Timeline

```
14:32:15.001 - iam.ListUsers() → 5 users returned
14:32:15.234 - iam.ListRoles() → 50 roles returned
14:32:15.567 - iam.ListAccessKeys() → check for old keys
14:32:16.012 - ec2.DescribeInstances(region=us-east-1) → 20 instances
14:32:16.234 - ec2.DescribeSecurityGroups(region=us-east-1) → 15 SGs
14:32:16.567 - ec2.DescribeInstances(region=us-west-2) → 5 instances
14:32:16.789 - ec2.DescribeSecurityGroups(region=us-west-2) → 8 SGs
14:32:17.012 - s3.ListBuckets() → 30 buckets
14:32:17.500 - s3.GetBucketEncryption(bucket=prod-data) → not encrypted ❌
14:32:17.750 - s3.GetBucketEncryption(bucket=backup-storage) → encrypted ✓
... [continues for all resources]
14:32:42.999 - kms.DescribeKey() → last API call
```

**Forensic value:**
- **Start time**: First API call (`14:32:15.001`)
- **End time**: Last API call (`14:32:42.999`)
- **Scan duration**: ~27 seconds
- **Services scanned**: IAM, EC2, S3, KMS (reveals which frameworks targeted)
- **Regions covered**: us-east-1, us-west-2 (implies full audit or specific region focus)

---

## No Resource Modifications (Read-Only Signature)

Prowler **never** modifies resources. Every API call has `ReadOnly: true` in CloudTrail.

### Evidence Pattern
```json
[
  {"EventName": "ListUsers", "ReadOnly": true},
  {"EventName": "GetBucketEncryption", "ReadOnly": true},
  {"EventName": "DescribeInstances", "ReadOnly": true},
  {"EventName": "ListPolicies", "ReadOnly": true}
]
```

**This distinguishes Prowler from:**
- **Pacu** (Wave 4 #13): exploitation tool that **modifies** resources (PutBucketPolicy, CreateAccessKey, etc.)
- **ScoutSuite** (Wave 4 #14): also read-only, same signature pattern

### Contrast: Exploitation vs. Assessment

| Tool | API Pattern | CloudTrail Signature |
|---|---|---|
| **Prowler** | Read, read, read... | `ReadOnly: true` on every event |
| **Pacu (Exploitation)** | Read → analyze → modify | Mix of `ReadOnly: true` and `ReadOnly: false` |
| **Example:** Prowler finds S3 bucket public | N/A (assessment only) | — |
| **Example:** Pacu exploits same bucket | `PutBucketPolicy`, `DeleteBucketPolicy` | `ReadOnly: false` |

---

## Endpoint Security (EDR) Signals

If account has AWS GuardDuty, Azure Defender, or GCP Security Command Center enabled:

### GuardDuty (AWS)
Prowler's bulk API queries **may** trigger low-confidence findings:
- **`Recon:IAMUser/Anomalous`** — if API calls from unusual IP/time
- **`Discovery/UnauthorizedAccess`** — not applicable (Prowler is authorized)

**False positive risk:** High. GuardDuty may flag bulk read-only API calls as reconnaissance.

### Azure Defender
- **`Anomalous activity`** — bulk Resource Manager queries flagged as enumeration
- **`Suspicious Activity Detection`** — may correlate with service principal sudden activity spike

### GCP Security Command Center
- **`Suspicious bulk activity`** — many API calls in short timeframe may trigger

**Note:** Read-only API calls have lower alert priority than modification/exploitation patterns, but volume still matters.

---

## Resource State Snapshots

After Prowler completes, no **persistent state changes** exist in resources. However, operational history is available:

### CloudTrail Event History (Available ~90 days via console, indefinite via S3 export)
```bash
# Query CloudTrail for Prowler's scan window
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[*].[EventTime, EventName, ReadOnly]'
```

### Config Snapshots (AWS Config)
If AWS Config is enabled, it captures resource snapshots independently of Prowler:
- Snapshots are taken on schedule (every 6 hours, daily, etc.)
- Prowler's scan does **not** trigger Config snapshots
- But timestamps of resource snapshots can be correlated with Prowler scan times

### Cloud Security Posture Management (CSPM) Baselines
If org uses Prisma Cloud, CloudSploit, or native cloud-vendor CSPM tools:
- These tools run on schedule (daily, weekly)
- Prowler scan is independent
- But findings from Prowler may align with CSPM findings (same misconfigs)

---

## Network & DNS Traces

### AWS VPC Flow Logs
If enabled, flow logs capture outbound connections from EC2/Lambda to AWS API endpoints:

```
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
2 123456789012 eni-1a2b3c4d 10.0.1.100 52.89.213.45 54321 443 6 45 34521 1391349000 1391349060 ACCEPT OK
```

**Forensic value:**
- Destination IP is AWS API endpoint
- Port 443 (HTTPS encrypted)
- Direction: outbound to AWS (not from internet)
- No source IP visible (flow logs only show VPC traffic, not external internet)

### DNS Query Logs (Route53/CloudWatch Logs)
If Route53 query logging enabled:

```
{ "version" : "1.0", "account_id" : "123456789012", "region" : "us-east-1",
  "vpc_id" : "vpc-1a2b3c4d", "query_timestamp" : "2026-08-11T14:32:15Z",
  "query_name" : "ec2.us-east-1.amazonaws.com", "query_type" : "A",
  "query_class" : "IN", "response_code" : "NOERROR", "query_region" : "us-east-1" }
```

**Forensic value:**
- DNS queries to AWS API domains (ec2, iam, s3, etc.)
- Query frequency during scan window

---

## Account-Level Anomalies

### IAM Login Activity
```bash
# Check for unusual login patterns (if MFA enabled, login events appear in CloudTrail)
aws cloudtrail lookup-events --event-names "ConsoleLogin" --max-results 50
```

**Expected:** Operator's usual IP/time zone
**Red flag:** Prowler API calls from unexpected IP (differs from console login IP)

### Service Principal / API Key Age
```bash
# Azure: check when service principal was last used
az ad sp credential list --id <app-id> --query '[*].[customKeyIdentifier, notAfter]'
```

**Forensic value:**
- API key/secret created shortly before Prowler scan indicates prep activity
- Credentials not used before scan suggests purpose-built for this audit

---

## Compliance Artifact Recovery

### Prowler Output in S3 (if uploaded)
If Prowler uploads results to S3 (`-b my-bucket` flag):

```bash
aws s3 ls s3://my-bucket/ --recursive
# 2026-08-11 14:35:12        1234567 cis-123456789012-report.json
# 2026-08-11 14:35:13        5678901 cis-123456789012-report.html
```

**Forensic value:**
- S3 object creation time (when Prowler completed)
- Object name encodes account ID, framework, timestamp
- Prowler's own report is the strongest evidence of what was scanned

### Security Hub Integration (if enabled)
```bash
aws securityhub get-findings --filters '{"Title": {"Value": "Prowler"}}'
```

**Forensic value:**
- Security Hub archives all Prowler findings
- Provides centralized SIEM view of all scans across accounts

---

## Timeline Reconstruction Walkthrough

**Scenario:** Blue team finds that Prowler was run against production AWS account. Reconstruct the event.

```bash
# Step 1: Find the scan window
aws cloudtrail lookup-events \
  --event-names ListUsers,DescribeInstances,GetBucketEncryption \
  --max-results 100 \
  --query 'Events[*].[EventTime, EventName, ReadOnly]' \
  --output table

# Output:
# 2026-08-11T14:32:15.001Z | ListUsers | true
# 2026-08-11T14:32:15.234Z | ListRoles | true
# ...
# 2026-08-11T14:32:42.999Z | GetKeyRotationStatus | true

# Step 2: Identify the operator
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
  --max-results 1 \
  --query 'Events[0].Username'
# Output: arn:aws:iam::123456789012:user/security-audit

# Step 3: Identify source IP
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ListUsers \
  --max-results 1 \
  --query 'Events[0].CloudTrailEvent' | jq '.sourceIPAddress'
# Output: "192.168.1.100"

# Step 4: Extract framework used
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[*].EventName' | grep -E 'ListUsers|DescribeInstances|GetBucket' \
  # Many IAM + EC2 + S3 calls = likely CIS audit

# Step 5: Estimate account coverage
# Count unique regions in EC2 API calls
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[?EventName==`DescribeInstances`].[AwsRegion]' | sort | uniq
# Output: us-east-1, us-west-2, eu-west-1 = multi-region scan
```

**Blue Team Interpretation:**
- Scan started: `2026-08-11T14:32:15Z`
- Scan ended: `2026-08-11T14:32:42Z` (~27 seconds)
- Operator: security-audit user
- Source IP: 192.168.1.100 (corporate network)
- Scope: All regions, likely CIS framework (based on API mix)
- Verdict: **Authorized security audit** (or unauthorized insider threat)

---

## Anomaly Detection in Baseline Behavior

### Distinguishing Authorized vs. Unauthorized Prowler Scans

Even if Prowler is commonly run in your organization, unauthorized scans (by insider threats or attackers with compromised credentials) have **behavioral signatures** that differ from baseline:

#### Expected Patterns (Authorized Audits)
- **Scheduled timing:** Same time each day/week (e.g., Mondays at 2 AM UTC, Friday compliance audits)
- **Consistent duration:** ~30–120 seconds for full CIS audit (predictable per account size)
- **Known principals:** Service account owned by security team (e.g., `compliance-automation@domain`)
- **Source IP consistency:** Always from corporate VPN range or specific office
- **Regional consistency:** Audits same regions every time (or documented cross-region expansion)
- **Framework consistency:** Same compliance framework each run (CIS), or rotation on schedule (CIS Monday, PCI Wednesday)

#### Red Flags (Unauthorized Scans)
- **Anomalous timing:** 3 AM UTC, Friday night, holiday weekends (outside business hours)
- **Unusual principal:** User account flagged as "test", "admin", "temp" — vs. dedicated service account
- **Source IP anomaly:** Scan from public IP, Tor exit node, or IP geolocation mismatches (claiming US but connecting from EU)
- **Unusual framework:** Scan restricted to single service (e.g., only IAM, only S3), suggests targeted reconnaissance not full audit
- **Rapid re-scans:** Multiple scans within 24 hours (probing for configuration changes post-compromise)
- **Post-incident correlation:** Scan occurs immediately after:
  - Initial access indicator (suspicious login attempt)
  - Credential compromise (exposed API key)
  - Network anomaly (unusual egress traffic)

### Timeline Anomaly Detection

Construct a **baseline timeline** of authorized Prowler scans:

```
Baseline Pattern (Security Team, Authorized):
- Every Monday, 02:00 UTC, ~45 seconds, principal=compliance-sa@corp.local, IP=10.0.1.50
- Every Friday, 14:00 UTC, ~60 seconds, principal=compliance-sa@corp.local, IP=10.0.1.50

Anomaly Detection:
- Wednesday 03:15 UTC: Scan from principal=auditor@corp.local, IP=198.51.100.44 (public IP)
  → Red flag: outside baseline (different time, different principal, external IP)
  
- Tuesday 02:05 UTC: Scan is identical to Monday baseline
  → Not necessarily suspicious (could be emergency post-incident audit)
  → But if no incident ticket exists, investigate
```

**Blue team tactic:** Use ML-based SIEM alerting (e.g., Elastic anomaly detection, Splunk Unusual Activity) to flag deviations from learned baseline.

---

## Resource-Level Evidence Trails

### Specific Resource Findings Mapped to Attack Intent

By analyzing which resources Prowler checks fail on, defenders can infer attacker's likely next move:

| Finding Pattern | Likely Attacker Intent | Risk Level |
|---|---|---|
| All **IAM checks** failed (overpermissioned roles, old keys) | Privilege escalation, lateral movement | ⚠️ Critical |
| **S3 public access** (buckets, snapshots) | Data exfiltration | ⚠️ Critical |
| **Logging disabled** (CloudTrail, VPC Flow Logs, RDS audit) | Post-exploitation cover-up | ⚠️ Critical |
| **Encryption missing** (EBS, RDS, S3) | Credential theft, data theft | ⚠️ High |
| **Security groups open** (0.0.0.0/0 inbound) | Network pivot, lateral movement | ⚠️ High |
| **KMS key policies weak** | Break encryption, access encrypted secrets | ⚠️ High |
| **MFA disabled** (root, admins) | Account takeover | ⚠️ High |
| **Database backups public** | Backup data theft, restore to attacker account | ⚠️ High |
| **Secrets Manager no rotation** | Credential compromise, no refresh cycle | ⚠️ Medium |
| **Cost optimization only** (no security findings) | Likely authorized audit, low threat | ✅ Low |

**Forensic use:** If Prowler scan is cross-referenced with subsequent compromise (attacker exfiltrated S3 data 2 hours after scan), timeline shows:
1. Scan identified public S3 bucket (ThreatScore 9.5)
2. Attacker reviewed findings
3. Attacker exfiltrated S3 data
→ Confirms **reconnaissance → exploitation** chain

---

## Resource Modification Absence (Gold Standard)

### Why "ReadOnly: true" Matters

Prowler's defining characteristic is **no resource modifications**. Every API call has `ReadOnly: true` in CloudTrail. This is forensically valuable because:

1. **Eliminates accidental damage theory** — if Prowler was running and account was compromised, Prowler didn't cause the compromise (it's read-only)
2. **Differentiates from exploitation tools** — Pacu (wave 4 #13) modifies resources (creates keys, changes policies); ScoutSuite also read-only but less comprehensive
3. **Supports authorization hypothesis** — if only read-only calls, likely an authorized security audit (not an attack) — though this doesn't rule out insider threat using authorized tool

### Contrast: Exploitation Tool Footprint

If `ReadOnly: false` appears in CloudTrail during same timeframe:
```json
{
  "EventName": "PutBucketPolicy",
  "ReadOnly": false,
  "RequestParameters": {"bucketName": "prod-data", "policyText": "..."},
  "UserIdentity": {"principalId": "AIDACKCEVSQ6C2EXAMPLE"}
}
```

This indicates **Pacu or similar exploitation tool**, not Prowler. Prowler would never generate this event.

---

## Cross-Link: Similar Tools

- **ScoutSuite** (Wave 4 #14): Similar cloud-auditing tool, also read-only, nearly identical CloudTrail signature but focuses on "what can be exploited" rather than compliance
- **Pacu** (Wave 4 #13): AWS exploitation framework; creates `ReadOnly: false` events when it *modifies* resources (key difference from Prowler)

