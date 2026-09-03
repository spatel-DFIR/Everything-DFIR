# ScoutSuite — Target Evidence

**Scope:** Artifacts and forensic indicators **on the target cloud environment** (AWS account, Azure subscription, GCP project). This covers what cloud security teams, SOC analysts, and forensic investigators should look for when investigating a potential cloud reconnaissance incident using ScoutSuite.

---

## Cloud Provider Audit Logs

### AWS CloudTrail Logs

**Log storage:** CloudTrail writes logs to S3 bucket (configurable) and CloudWatch Logs (optional)

**Log format:** JSON events with detailed metadata:
```json
{
  "eventVersion": "1.09",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAI234567890ABCDEF0",
    "arn": "arn:aws:iam::123456789012:user/attacker-user",
    "accountId": "123456789012",
    "accessKeyId": "AKIA...[REDACTED]"
  },
  "eventTime": "2026-08-11T10:30:15Z",
  "eventSource": "ec2.amazonaws.com",
  "eventName": "DescribeInstances",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.42",
  "userAgent": "python-requests/2.28.0",
  "requestParameters": {
    "instancesSet": {},
    "filterSet": [],
    "maxResults": null
  },
  "responseElements": null,
  "requestId": "12345678-1234-1234-1234-123456789012",
  "eventID": "abcdef01-2345-6789-abcd-ef0123456789",
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

**Forensic indicators of ScoutSuite reconnaissance:**

| Event Name | Forensic Significance | Expected Pattern |
|---|---|---|
| **DescribeInstances** | Enumerating EC2 instances | 10–50+ calls within 1–5 minute window per region |
| **DescribeSecurityGroups** | Enumerating security groups | 5–20+ calls in quick succession |
| **DescribeImages** | Enumerating AMIs | 10–50+ calls per region |
| **DescribeSubnets, DescribeVpcs** | Enumerating network configuration | 5–20+ calls per region |
| **ListBuckets, GetBucketAcl, GetBucketPolicy** | Enumerating S3 buckets and permissions | 50–200+ calls (one ListBuckets + one per bucket) |
| **ListUsers, GetUserPolicy, GetUser** | Enumerating IAM users and policies | 20–100+ calls per user |
| **ListRoles, GetRolePolicy, GetRole** | Enumerating IAM roles | 20–100+ calls per role |
| **DescribeLoadBalancers** | Enumerating load balancers | 5–20+ calls |
| **DescribeDBInstances** | Enumerating RDS databases | 5–20+ calls per region |
| **DescribeSnapshots, DescribeVolumes** | Enumerating EBS snapshots/volumes | 20–100+ calls |
| **GetTrailStatus, DescribeTrails** | Checking CloudTrail configuration | 1–5+ calls (reconnaissance of logging) |
| **GetBucketLogging, GetBucketVersioning** | Checking S3 bucket logging/versioning | 50–200+ calls (one per bucket) |

**Pattern characteristics of ScoutSuite activity:**

1. **Read-only API calls:** CloudTrail `readOnlyEvents: true` (no DeleteBucket, PutBucketPolicy, TerminateInstances, etc.)

2. **Rapid-fire API calls:** 50–500+ API calls within a 5–30 minute timeframe from a single source IP

3. **Single source IP:** All reconnaissance traffic originates from the attacker's IP address (no internal reconnaissance from multiple IPs)

4. **User-Agent string:** Often contains "python-requests", "boto3", or similar SDK indicators (not typical web browser User-Agent)

5. **Regional enumeration:** If the attacker scans all regions, there will be separate API call bursts for each region (us-east-1, us-west-2, eu-west-1, ap-northeast-1, etc.)

6. **Comprehensive scope:** Attacker enumerates EC2, S3, IAM, VPC, RDS, Lambda, CloudFormation, etc. (not just one or two services)

**Query to detect ScoutSuite-like activity in CloudTrail:**

```sql
SELECT
  eventTime,
  eventName,
  sourceIPAddress,
  userIdentity.principalId,
  awsRegion,
  COUNT(*) as count
FROM cloudtrail_logs
WHERE
  eventTime > timestamp('2026-08-11T10:00:00Z')
  AND eventTime < timestamp('2026-08-11T12:00:00Z')
  AND sourceIPAddress NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')  -- Filter internal IPs
  AND readOnlyEvents = true
GROUP BY
  eventTime,
  eventName,
  sourceIPAddress,
  userIdentity.principalId,
  awsRegion
HAVING count > 5
ORDER BY eventTime;
```

**CloudTrail limitations:**
- Logs are typically delayed 5–15 minutes (not real-time)
- If CloudTrail is not enabled, no logs will be generated
- Logs can be deleted if attacker gains permissions (critical finding)

### Azure Activity Log (Azure Monitor)

**Log storage:** Stored in Azure Monitor; queryable via Azure Portal, Log Analytics Workspace, or Azure SDK

**Log format:** JSON events with detailed metadata:
```json
{
  "eventDataId": "12345678-1234-1234-1234-123456789012",
  "eventName": {
    "value": "ListVirtualMachines",
    "localizedValue": "List Virtual Machines"
  },
  "category": {
    "value": "Administrative",
    "localizedValue": "Administrative"
  },
  "eventTimestamp": "2026-08-11T10:30:15.000Z",
  "id": "/subscriptions/12345678-1234-1234-1234-123456789012/providers/microsoft.insights/eventtypes/management/events/...",
  "level": "Informational",
  "operationId": "12345678-1234-1234-1234-123456789012",
  "operationName": {
    "value": "Microsoft.Compute/virtualMachines/read",
    "localizedValue": "List Virtual Machines"
  },
  "resourceGroupName": "prod-rg",
  "resourceProviderName": {
    "value": "Microsoft.Compute",
    "localizedValue": "Microsoft Compute"
  },
  "resourceType": {
    "value": "Microsoft.Compute/virtualMachines",
    "localizedValue": "Virtual Machines"
  },
  "resourceId": "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-prod-01",
  "status": {
    "value": "Succeeded",
    "localizedValue": "Succeeded"
  },
  "subStatus": {
    "value": "",
    "localizedValue": ""
  },
  "submissionTimestamp": "2026-08-11T10:30:16.000Z",
  "subscriptionId": "12345678-1234-1234-1234-123456789012",
  "callerIpAddress": "203.0.113.42",
  "correlationId": "12345678-1234-1234-1234-123456789012",
  "description": null,
  "eventSource": {
    "value": "Administrative",
    "localizedValue": "Administrative"
  },
  "claims": {
    "aud": "https://management.azure.com/",
    "iss": "https://sts.windows.net/.../",
    "iat": "1660218615",
    "nbf": "1660218615",
    "exp": "1660222515",
    "aio": "E2Zp...",
    "appid": "abcdef01-2345-6789-abcd-ef0123456789",
    "appidacr": "2",
    "oid": "12345678-1234-1234-1234-123456789012",
    "sub": "12345678-1234-1234-1234-123456789012",
    "tid": "abcdef01-2345-6789-abcd-ef0123456789",
    "uti": "...",
    "ver": "1.0"
  },
  "authorization": {
    "action": "Microsoft.Compute/virtualMachines/read",
    "scope": "/subscriptions/12345678-1234-1234-1234-123456789012"
  }
}
```

**Forensic indicators of ScoutSuite reconnaissance:**

| Operation Name | Forensic Significance | Expected Pattern |
|---|---|---|
| **Microsoft.Compute/virtualMachines/read** | Enumerating VMs | 10–50+ calls within 1–5 minute window |
| **Microsoft.Compute/disks/read** | Enumerating managed disks | 20–100+ calls |
| **Microsoft.Network/networkSecurityGroups/read** | Enumerating NSGs | 10–50+ calls |
| **Microsoft.Network/networkInterfaces/read** | Enumerating NICs | 20–100+ calls |
| **Microsoft.Storage/storageAccounts/read** | Enumerating storage accounts | 20–100+ calls per account |
| **Microsoft.Storage/storageAccounts/blobServices/containers/read** | Enumerating blob containers | 50–200+ calls |
| **Microsoft.Authorization/roleAssignments/read** | Enumerating IAM role assignments | 20–100+ calls |
| **Microsoft.Authorization/roleDefinitions/read** | Enumerating role definitions | 50+ calls |
| **Microsoft.KeyVault/vaults/read** | Enumerating Key Vaults | 10–50+ calls |
| **Microsoft.Sql/servers/read** | Enumerating SQL servers | 5–20+ calls |
| **Microsoft.Insights/diagnosticSettings/read** | Checking logging configuration | 50–200+ calls (one per resource) |

**Pattern characteristics of ScoutSuite activity:**

1. **Batch read operations:** Typically Microsoft.Compute/*/read, Microsoft.Storage/*/read, etc. in rapid succession

2. **Single service principal or user identity:** All operations attributed to one identity (e.g., service principal "automation-app")

3. **Rapid-fire operations:** 100–500+ operations within 5–30 minute window

4. **Cross-subscription enumeration:** If `--all-subscriptions` flag is used, activity will span multiple subscriptions

5. **Diagnostic settings checks:** ScoutSuite often checks Azure Monitor diagnostic settings (Microsoft.Insights/diagnosticSettings/read) for logging validation

6. **High caller IP consistency:** All operations from the same source IP address

**KQL query to detect ScoutSuite-like activity in Log Analytics:**

```kusto
AzureActivity
| where TimeGenerated > ago(2h)
| where ActivityStatus == "Succeeded" and Level == "Informational"
| where ResourceProvider in ("Microsoft.Compute", "Microsoft.Storage", "Microsoft.Network", "Microsoft.Authorization", "Microsoft.Insights")
| where OperationName endswith "/read"
| summarize count() by CallerIpAddress, OperationName, TimeWindow=bin(TimeGenerated, 1m)
| where count_ > 5
| order by TimeGenerated desc
```

**Azure Activity Log limitations:**
- Logs are typically available within 10–15 minutes
- Only 90 days of history retained by default (older logs require long-term retention)
- If activity logging is disabled, no reconnaissance will be recorded

### Google Cloud Platform (GCP) Cloud Audit Logs

**Log storage:** Stored in Cloud Logging (Cloud Audit Logs); queryable via Cloud Console or Log Analytics

**Log format:** JSON events with detailed metadata:
```json
{
  "insertId": "1a2b3c4d5e6f7g8h9i0j",
  "logName": "projects/prod-project-123/logs/cloudaudit.googleapis.com%2Factivity",
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "status": {},
    "authenticationInfo": {
      "principalEmail": "attacker-sa@prod-project-123.iam.gserviceaccount.com",
      "serviceAccountKeyName": "projects/prod-project-123/serviceAccounts/.../keys/...",
      "principalId": "1234567890"
    },
    "requestMetadata": {
      "callerIp": "203.0.113.42",
      "userAgent": "google-cloud-python/2.12.0 gcloud/...",
      "requestAttributes": {
        "time": "2026-08-11T10:30:15.000Z",
        "auth": {}
      },
      "destinationAttributes": {}
    },
    "serviceName": "compute.googleapis.com",
    "methodName": "compute.instances.list",
    "resourceName": "projects/prod-project-123",
    "request": {
      "@type": "type.googleapis.com/compute.instances.list",
      "project": "prod-project-123",
      "zone": "us-central1-a"
    },
    "response": {
      "@type": "type.googleapis.com/compute.instances.listResponse",
      "instances": [...],
      "nextPageToken": null
    }
  },
  "severity": "NOTICE",
  "timestamp": "2026-08-11T10:30:15.000Z",
  "receiveTimestamp": "2026-08-11T10:30:15.123Z"
}
```

**Forensic indicators of ScoutSuite reconnaissance:**

| Method Name | Forensic Significance | Expected Pattern |
|---|---|---|
| **compute.instances.list** | Enumerating GCE instances | 10–50+ calls within 1–5 minute window |
| **storage.buckets.list** | Enumerating GCS buckets | 1–5+ calls (lists all buckets) |
| **storage.buckets.getIamPolicy** | Enumerating bucket permissions | 50–200+ calls (one per bucket) |
| **compute.networks.list** | Enumerating VPCs | 5–10+ calls |
| **compute.firewalls.list** | Enumerating firewall rules | 5–10+ calls |
| **iam.roles.list** | Enumerating roles | 10–50+ calls |
| **iam.serviceAccounts.list** | Enumerating service accounts | 5–20+ calls |
| **iam.serviceAccounts.getIamPolicy** | Enumerating service account IAM bindings | 50–200+ calls (one per SA) |
| **cloudresourcemanager.projects.getIamPolicy** | Enumerating project-level IAM | 1–5+ calls |
| **logging.logEntries.list** | Checking logging configuration | 50+ calls |
| **compute.disks.list** | Enumerating persistent disks | 20–100+ calls |

**Pattern characteristics of ScoutSuite activity:**

1. **Rapid-fire .list() calls:** GCP audit logs will show many compute.*.list, storage.*.list, iam.*.list operations

2. **getIamPolicy calls:** ScoutSuite checks permissions on every resource; bulk .getIamPolicy calls are characteristic

3. **Service account authentication:** If ScoutSuite is run with a service account (not user account), all operations attributed to service account identity

4. **Single source IP:** All operations from the attacker's IP address

5. **Zone enumeration (for GCE):** If the attacker scans all zones, there will be separate list calls per zone (us-central1-a, us-central1-b, us-west1-b, etc.)

6. **Logging inspection:** ScoutSuite checks if logging is enabled (logging.logEntries.list, logging.logSinks.list)

**Cloud Logging query to detect ScoutSuite-like activity:**

```sql
resource.type = "gce_project"
protoPayload.methodName =~ "compute\..*\.list|storage\..*\.list|iam\..*\.list"
protoPayload.status.code = 0
protoPayload.requestMetadata.callerIp = "203.0.113.42"
timestamp >= "2026-08-11T10:00:00Z" AND timestamp <= "2026-08-11T12:00:00Z"
```

**GCP Cloud Audit Logs limitations:**
- Logs are typically available within 2–5 minutes
- Admin activity logs retained for 400 days; data access logs shorter (if enabled)
- If Cloud Audit Logs are not enabled, no reconnaissance will be recorded

---

## Resource Access Patterns

### Enumeration signatures by cloud provider

**AWS:**
- **Rapid Describe* calls:** DescribeInstances, DescribeSecurityGroups, DescribeImages, DescribeSubnets in quick succession (< 5 seconds apart)
- **Cross-region enumeration:** If attacker scans all regions, CloudTrail will show API calls for each region in sequence (us-east-1, us-west-2, etc.)
- **Bucket permissions check:** ListBuckets followed by GetBucketAcl/GetBucketPolicy for each bucket (50–200+ sequential calls)
- **IAM full enumeration:** ListUsers, GetUserPolicy for each user; ListRoles, GetRolePolicy for each role

**Azure:**
- **Read operation floods:** Microsoft.Compute/*/read, Microsoft.Storage/*/read operations in high volume
- **Subscription-level scope:** Operations across multiple subscriptions if --all-subscriptions is used
- **IAM role discovery:** Burst of Microsoft.Authorization/roleAssignments/read calls
- **Diagnostic settings inspection:** Microsoft.Insights/diagnosticSettings/read calls for each resource

**GCP:**
- **List operation patterns:** compute.instances.list, storage.buckets.list, iam.serviceAccounts.list in rapid succession
- **getIamPolicy bulk calls:** After .list() calls, bulk getIamPolicy calls for every resource (service account, bucket, etc.)
- **Zone-based enumeration:** If all zones scanned, separate calls per zone visible in logs

---

## Absence of Modification Events

**Key indicator: ScoutSuite leaves no modification footprint**

CloudTrail/Activity Logs/Audit Logs will NOT show:
- CreateInstance, RunInstances, TerminateInstances (no EC2 creation/deletion)
- CreateBucket, DeleteBucket, PutBucketPolicy (no S3 bucket modification)
- CreateUser, DeleteUser, AttachUserPolicy (no IAM user creation/deletion)
- ModifyDBInstance, CreateDBInstance (no RDS modification)
- UpdateSecurityGroup (no security group rule changes)

**Absence of these write events is itself a forensic indicator:** If there is a burst of read-only API calls from an unusual IP but no corresponding write operations, it strongly suggests automated reconnaissance (not manual exploration or adversarial attack).

---

## Resource Enumeration Completion Markers

### Timing signatures

**AWS enumeration timing (typical):**
- 1–2 minutes: Initial authentication + IAM enumeration (Users, Roles, Policies)
- 3–5 minutes: EC2 enumeration across all regions
- 5–10 minutes: S3 bucket enumeration (slow due to GetBucketPolicy calls)
- 10–15 minutes: RDS, VPC, Lambda, CloudFormation enumeration
- 15–25 minutes: Full scan completion for typical account (500–1000 resources)

**Azure enumeration timing (typical):**
- 1–2 minutes: Authentication + Subscription enumeration
- 2–5 minutes: Virtual machine enumeration
- 5–10 minutes: Storage account enumeration
- 10–15 minutes: Network + IAM enumeration
- 15–25 minutes: Full scan completion for typical subscription

**GCP enumeration timing (typical):**
- 1–2 minutes: Authentication + Project enumeration
- 2–5 minutes: Compute instance enumeration
- 5–10 minutes: Storage bucket enumeration + getIamPolicy calls
- 10–15 minutes: Network + IAM enumeration
- 15–25 minutes: Full scan completion for typical project

**Forensic observation:** ScoutSuite completion is marked by:
1. Sudden drop in API request volume (from 50+ req/min to near zero)
2. Last API call typically a logging/configuration check (CloudTrail, Activity Log, Cloud Audit Logs status)
3. Gap of 30+ seconds before any new API calls (indicating attacker is processing/analyzing results locally)

---

## Summary of Cloud-Side Forensic Indicators

| Indicator | Cloud Provider | Forensic Weight | Detection Method |
|---|---|---|---|
| Burst of Describe* / List / .read operations | AWS / Azure / GCP | **CRITICAL** | CloudTrail / Activity Log / Audit Logs query |
| Single source IP, high request volume (5–30 min) | All | **CRITICAL** | Aggregated log query (sourceIPAddress/callerIp) |
| Read-only API calls only (no writes) | All | **HIGH** | Filter for read operations; absence of write operations |
| Comprehensive service enumeration (EC2, S3, IAM, VPC, etc.) | AWS | **HIGH** | Describe*/List operations across multiple services |
| Cross-region/subscription enumeration | AWS / Azure | **HIGH** | Unique regions/subscriptions in API logs |
| Rapid GetBucketPolicy/getIamPolicy calls | AWS / GCP | **HIGH** | Bulk permission checks in short timeframe |
| Service principal / unusual user identity | All | **MEDIUM** | User identity anomaly detection |
| User-Agent contains SDK keywords (boto3, requests, google-cloud) | All | **MEDIUM** | User-Agent pattern analysis |
| Logging configuration inspection | All | **MEDIUM** | CloudTrail/Activity Log/Audit Logs read operations |
| Absence of resource modifications | All | **MEDIUM** | No CreateInstance, PutBucketPolicy, etc. |

