# Pacu — Target Evidence

**Scope:** This page documents artifacts left in the **target AWS account** — what Pacu's exploitation activities leave behind in CloudTrail, GuardDuty, resource states, and AWS audit logs.

---

## CloudTrail Audit Logging (Primary Evidence Source)

**Critical Point:** By default, AWS CloudTrail logs **every API call** made by any principal (user, role, application) in an AWS account. Pacu operations are completely transparent to CloudTrail — every `aws:` API action appears as a distinct event.

### CloudTrail Event Structure

Every Pacu module execution generates a stream of CloudTrail events:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDACKCEVSQ6C2EXAMPLE",
    "arn": "arn:aws:iam::123456789012:user/compromised-dev",
    "accountId": "123456789012",
    "invokeSource": "aws.amazonaws.com",
    "accessKeyId": "AKIA...[REDACTED]",
    "sessionContext": {
      "sessionIssueTime": "2026-08-11T14:31:00Z"
    }
  },
  "eventTime": "2026-08-11T14:31:45Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "ListUsers",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.5",  ← Attacker's IP
  "userAgent": "aws-cli/1.18.69 Python/3.8.2",
  "requestParameters": null,
  "responseElements": null,
  "requestId": "12345678-1234-1234-1234-123456789012",
  "eventID": "12345678-1234-1234-1234-123456789012",
  "eventName": "ListUsers",
  "readOnly": false,
  "resources": [],
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

### Observable CloudTrail Event Patterns for Pacu Modules

| Module | API Calls (CloudTrail Events) | Detection Difficulty | Notes |
|---|---|---|---|
| `iam__enum_users` | `ListUsers`, `GetUser`, `ListUserTags` | Very easy | Read-only operations; no "suspicious" action names |
| `iam__enum_roles` | `ListRoles`, `GetRole`, `ListRoleTags`, `ListAttachedRolePolicies` | Easy | Read-only; high volume |
| `iam__enum_permissions` | `SimulateCustomPolicy` (600+ API calls) | Medium | **Highly suspicious action** — testing 600 permissions in sequence |
| `iam__privesc_scan` | `GetPolicy`, `GetPolicyVersion`, `GetRolePolicy`, `ListAttachedUserPolicies` | Easy | High-volume policy enumeration |
| `s3__download_bucket` | `ListBuckets`, `GetBucketLocation`, `ListObjects`, `GetObject` (per object) | Medium | High-volume `GetObject` calls; exfiltration-sized download |
| `ec2__download_userdata` | `DescribeInstances`, `DescribeInstanceAttribute` (UserData) | Easy | Direct user-data retrieval; often contains secrets |
| `ec2__backdoor_ec2_sec_groups` | `DescribeSecurityGroups`, `AuthorizeSecurityGroupIngress` | Medium | **Suspicious action** — security-group modification |
| `iam__backdoor_users_keys` | `CreateAccessKey` | Very easy | **Highly suspicious** — new persistent credential created |
| `iam__backdoor_assume_role` | `CreateRole`, `PutRolePolicy`, `UpdateAssumeRolePolicy` | Very easy | **Suspicious** — new IAM role with broad permissions created |
| `lambda__backdoor_new_users` | `CreateFunction`, `CreateRole`, `AttachRolePolicy`, `UpdateFunctionConfiguration` | Easy | **Suspicious** — new Lambda function + role created |
| `ecs__backdoor_task_def` | `RegisterTaskDefinition`, `UpdateService` | Medium | **Suspicious** — task definition modified with new container |
| `cfn__resource_injection` | `GetTemplate`, `UpdateStack`, `CreateStack` | Medium | **Suspicious** — CloudFormation stack modified to inject resources |
| `cloudtrail__csv_injection` | `ListTrails`, `GetEventSelectors`, `GetTrailStatus`, `ListObjects` (S3), `PutObject` | Medium | **Malicious action** — CloudTrail logs themselves are modified |
| `guardduty__whitelist_ip` | `CreateIPSet`, `UpdateDetector`, `UpdateFindingsFeedback` | Medium | **Malicious action** — detection suppression |
| `detection__disruption` | `UpdateDetector`, `DisassociateMembers` | Medium | **Malicious** — security service disabled |
| `organizations__assume_role` | `AssumeRole` + subsequent calls under the new role's identity | Medium | **Suspicious** — cross-account role assumption; all subsequent events show assumed-role principal |

### Signature CloudTrail Patterns

**High-Confidence Pacu Reconnaissance Pattern:**
```
Time: 14:31:00 - 14:32:30 (90 seconds)
Event sequence:
  1. ListUsers (IAM)
  2. GetUser × 42 (one per user)
  3. ListRoles (IAM)
  4. GetRole × 15 (one per role)
  5. DescribeInstances (EC2)
  6. ListBuckets (S3)
  7. GetBucketLocation × 8
  8. ListObjects × 8
  9. DescribeSecurityGroups (EC2)
  10. ListSecrets (Secrets Manager)
  
Pattern indicators:
  - All from single source IP (attacker's IP)
  - All from single principal (compromised user/role)
  - Rapid-fire sequence (bulk enumeration, not interactive)
  - Services touched: IAM, EC2, S3, Secrets Manager (classic "cloud recon")
```

**High-Confidence Pacu Exploitation Pattern:**
```
Time: 14:35:00 - 14:36:00
Event sequence:
  1. CreateAccessKey (suspicious — new credential)
  2. CreateRole (suspicious — new role)
  3. PutRolePolicy (suspicious — attaching admin policy)
  4. CreateFunction (suspicious — new Lambda)
  5. AttachRolePolicy (suspicious — privilege escalation setup)
  6. UpdateAssumeRolePolicy (suspicious — cross-account trust modification)

Pattern indicators:
  - Rapid sequence of create/modify actions (typical of backdooring)
  - Multiple "create" actions (CreateAccessKey, CreateRole, CreateFunction)
  - Policy attachment/modification immediately following creation
  - No legitimate use case for this sequence
```

**High-Confidence Pacu Cover-Up Pattern:**
```
Time: 14:50:00 - 14:52:00
Event sequence:
  1. ListTrails (CloudTrail enumeration)
  2. GetEventSelectors (checking what's logged)
  3. ListObjects (finding log S3 bucket)
  4. GetObject × 500 (downloading logs)
  5. PutObject × 500 (rewriting logs with CSV injection)
  6. CreateIPSet (GuardDuty IP whitelist)
  7. UpdateDetector (disabling findings)

Pattern indicators:
  - Targeted attacks on logging systems and detection services
  - Modification of logs themselves (destructive)
  - Detection service configuration changes
```

---

## CloudTrail Query Examples

**Detective Controls for Pacu Activity:**

### Find all API calls by the compromised credential

```
# Using AWS CloudTrail console filter or AWS CLI:
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-dev \
  --start-time 2026-08-11T14:00:00Z \
  --end-time 2026-08-11T15:00:00Z \
  --query 'Events[*].[EventTime, EventName, SourceIPAddress, RequestParameters]'

Output:
2026-08-11T14:31:00Z  ListUsers         203.0.113.5         null
2026-08-11T14:31:05Z  GetUser           203.0.113.5         {"userName": "ci-deploy"}
...
2026-08-11T14:35:00Z  CreateAccessKey   203.0.113.5         {"userName": "ci-deploy"}
...
```

### Find all suspicious actions (CreateUser, CreateAccessKey, etc.)

```
# CloudTrail filter for persistence indicators
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time 2026-08-01T00:00:00Z

# Also check:
#  CreateUser, CreateRole, PutUserPolicy, AttachUserPolicy, 
#  UpdateAssumeRolePolicy, CreateFunction, RegisterTaskDefinition, etc.
```

### Find EnumPermissions pattern (SimulateCustomPolicy bulk calls)

```
# Pacu's iam__enum_permissions makes 600+ SimulateCustomPolicy calls
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SimulateCustomPolicy \
  --max-results 100
# If >100 events in a short time from single IP → likely Pacu enumeration
```

### Find exfiltration patterns (high-volume GetObject calls)

```
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time 2026-08-11T14:30:00Z \
  --end-time 2026-08-11T15:00:00Z \
  --query 'Events[*].CloudTrailEvent' | jq '.[] | select(.sourceIPAddress == "203.0.113.5")'
  
# If single IP makes 1000+ GetObject calls in 30 minutes → likely bucket exfiltration
```

---

## GuardDuty Alerts

**AWS GuardDuty** is an AWS-native threat detection service that generates alerts for suspicious AWS API activity.

### Triggered GuardDuty Finding Types

| Pacu Activity | GuardDuty Finding Type | Severity | Description |
|---|---|---|---|
| Enumeration (high-volume API calls) | `UnauthorizedAccess:IAM/MaliciousIPCaller` | High | Suspicious IP calling IAM APIs |
| Enumeration (permission testing) | `UnauthorizedAccess:IAM/MaliciousIPCaller.Custom` | High | IP testing IAM permissions |
| Cross-account role assumption | `DefenseEvasion:IAM/AnomalousBehavior` | Medium | Unusual IAM activity pattern |
| Credential exfiltration (CreateAccessKey) | `PersistenceIA M/ExternallyTriggeredPolicyChange` | High | New persistent credentials |
| Lambda backdooring | `CryptoCurrency:Lambda/BitcoinTool` (false positive) OR `Trojan:EC2/DGADomainRequest` | Medium-High | Unusual compute activity |
| CloudTrail log deletion | `UnauthorizedAccess:IAM/UnauthorizedOperation` | High | Attempt to delete/modify logs |
| Cross-account access | `DefenseEvasion:IAM/AnomalousAssumeRole` | High | Unusual cross-account role assumption |

**Example GuardDuty Alert JSON:**
```json
{
  "type": "UnauthorizedAccess:IAM/MaliciousIPCaller",
  "severity": 7.5,
  "accountId": "123456789012",
  "region": "us-east-1",
  "title": "An API call was made from a known malicious IP address",
  "description": "User compromised-dev called ListUsers from IP address 203.0.113.5 which is known to be a malicious IP.",
  "resourceType": "IAM",
  "service": {
    "serviceName": "guardduty",
    "detectionDetail": {
      "eventFirstSeen": "2026-08-11T14:31:00Z",
      "eventLastSeen": "2026-08-11T14:35:00Z",
      "count": 147
    }
  },
  "sourceIPAddress": "203.0.113.5"
}
```

**Note:** GuardDuty's effectiveness depends on:
- Whether GuardDuty is **enabled** in the account (not enabled by default; must be explicitly activated)
- Whether findings are reviewed by the security team (often findings pile up unreviewed)
- Attacker's sophistication — whitelisting their IP in GuardDuty (`guardduty__whitelist_ip`) disables future alerts

---

## AWS Resource State Changes

### New IAM Users & Access Keys

When Pacu creates backdoor users or adds keys:

```
# List IAM users and their creation dates
aws iam list-users

Output:
{
  "Users": [
    {
      "UserName": "pacu-backdoor-user",
      "CreateDate": "2026-08-11T14:35:00Z",  ← Suspiciously recent
      "Arn": "arn:aws:iam::123456789012:user/pacu-backdoor-user"
    },
    ...
  ]
}

# List access keys for a user
aws iam list-access-keys --user-name ci-deploy

Output:
{
  "AccessKeyMetadata": [
    {
      "AccessKeyId": "AKIAIOSFODNN7ORIGINAL",
      "CreateDate": "2025-01-01T08:00:00Z"  ← Original key
    },
    {
      "AccessKeyId": "AKIAIOSFODNN7BACKDOOR",
      "CreateDate": "2026-08-11T14:35:00Z"  ← Suspicious new key!
    }
  ]
}
```

**Observable:** Users/keys created outside normal change-management windows.

### Modified IAM Policies

```
# Get inline policies for a user
aws iam list-user-policies --user-name ci-deploy

Output:
{
  "PolicyNames": [
    "original-inline-policy",
    "pacu-escalation-policy"  ← New policy added by Pacu
  ]
}

# Retrieve the policy document
aws iam get-user-policy --user-name ci-deploy --policy-name pacu-escalation-policy

Output:
{
  "UserName": "ci-deploy",
  "PolicyName": "pacu-escalation-policy",
  "PolicyDocument": "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"
}
```

**Observable:** Overly permissive policies added to users/roles.

### New Lambda Functions

```
aws lambda list-functions

Output:
{
  "Functions": [
    {
      "FunctionName": "pacu-backdoor-function",
      "Runtime": "python3.11",
      "LastModified": "2026-08-11T14:35:00Z",  ← Suspicious
      "CodeSize": 5242880,
      "Role": "arn:aws:iam::123456789012:role/pacu-backdoor-role"  ← Suspicious
    }
  ]
}
```

**Observable:** New functions with suspicious names or created outside normal deployment windows.

### Modified Security Groups

```
aws ec2 describe-security-groups --group-ids sg-12345678

Output:
{
  "SecurityGroups": [
    {
      "GroupId": "sg-12345678",
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 3306,
          "ToPort": 3306,
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0",  ← Suspicious: entire internet can access MySQL
              "Description": "Added 2026-08-11T14:35:00Z"
            }
          ]
        }
      ]
    }
  ]
}
```

**Observable:** Security groups modified to allow inbound from 0.0.0.0/0.

---

## AWS Config (Configuration Tracking)

**AWS Config** records changes to AWS resources and can highlight suspicious modifications:

```
# Query AWS Config for IAM policy changes
aws configservice get-resource-config-history \
  --resource-type AWS::IAM::User \
  --resource-ids ci-deploy

Output:
{
  "configurationItems": [
    {
      "resourceName": "ci-deploy",
      "configurationItemCaptureTime": "2026-08-11T14:30:00Z",
      "configuration": {
        "path": "/",
        "createDate": "2025-01-01T08:00:00Z"
      }
    },
    {
      "resourceName": "ci-deploy",
      "configurationItemCaptureTime": "2026-08-11T14:35:00Z",
      "configuration": {
        "userPolicyList": [
          "pacu-escalation-policy"  ← NEW
        ]
      }
    }
  ]
}
```

**Observable:** Resource configuration changes with timestamps.

---

## SecurityHub Aggregated Findings

**AWS SecurityHub** aggregates findings from GuardDuty, Config, Inspector, and other sources:

```
aws securityhub get-findings \
  --filters '{"CreatedAt": [{"Value": "2026-08-11T14:00:00Z", "Comparison": "GREATER_THAN_OR_EQUAL"}]}'

Output:
{
  "Findings": [
    {
      "Title": "User compromised-dev created a new access key",
      "Description": "A new long-term access key was created for user compromised-dev at 2026-08-11T14:35:00Z",
      "Severity": "HIGH",
      "ResourceType": "IAM:User",
      "RecordState": "ACTIVE",
      "FirstObservedAt": "2026-08-11T14:35:00Z"
    },
    ...
  ]
}
```

---

## CloudWatch Logs (Application-Level)

If the attacker's actions trigger application or service logs:

### Lambda Function Logs

```
aws logs get-log-events \
  --log-group-name /aws/lambda/pacu-backdoor-function \
  --log-stream-name '2026/08/11/[$LATEST]abcd1234'

Output (if function was invoked):
START RequestId: 12345678-1234-1234-1234-123456789012 Version: $LATEST
END RequestId: 12345678-1234-1234-1234-123456789012
REPORT RequestId: 12345678-1234-1234-1234-123456789012 Duration: 150.00 ms
```

### ECS Task Logs

```
aws logs describe-log-streams --log-group-name /ecs/prod-app

Output:
{
  "logStreams": [
    {
      "logStreamName": "ecs/prod-app/container-id",
      "lastIngestionTime": 1660210500000,
      "firstEventTimestamp": 1660210200000,
      "lastEventTimestamp": 1660210500000
    }
  ]
}
```

---

## Timeline Reconstruction (Target-Side)

**Attacker's AWS activities timeline (based on CloudTrail):**

```
2026-08-11 14:31:00  Enumeration phase begins
  - ListUsers (IAM)
  - GetUser × 42
  - ListRoles, GetRole × 15
  - DescribeInstances (EC2)
  - ListBuckets (S3)
  - ListSecrets (Secrets Manager)

2026-08-11 14:35:00  Exploitation phase begins
  - CreateAccessKey (ci-deploy user) ← NEW CREDENTIAL
  - CreateRole (pacu-backdoor-role)
  - PutRolePolicy (Admin access)
  - CreateFunction (pacu-backdoor-function)

2026-08-11 14:40:00  Data exfiltration
  - ListObjects (s3://acme-prod-backups)
  - GetObject × 500 (18.5 GB total)

2026-08-11 14:50:00  Cover-up phase
  - ListTrails (CloudTrail enumeration)
  - GetObject × 500 (downloading logs)
  - PutObject × 500 (rewriting logs)
  - UpdateDetector (GuardDuty disabled)
  - CreateIPSet (Attacker's IP whitelisted)
```

---

## 🔗 Cross-References

- **Cloud/Amazon/AWS/02 - Investigating AWS.md** — Step-by-step CloudTrail querying and analysis.
- **Cloud/Amazon/AWS/Logging & Monitoring/CloudTrail.md** — Detailed CloudTrail event ID reference and forensic techniques.
- **Cloud/Amazon/AWS/Logging & Monitoring/GuardDuty.md** — GuardDuty finding types and interpretation.
- **Cloud/Amazon/AWS/Logging & Monitoring/CloudWatch.md** — CloudWatch Logs forensic collection.

---

