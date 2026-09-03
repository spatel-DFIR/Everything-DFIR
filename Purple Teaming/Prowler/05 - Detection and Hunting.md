# Prowler — Detection and Hunting

Prowler is a read-only cloud security auditor. Every execution leaves traces in cloud audit logs (primary signal) and source-host artifacts (shell history, credential files, output directories). Unlike exploitation tools (Pacu, ScoutSuite), Prowler's API pattern is purely enumeration — no resource modifications — making it distinguishable but not always easy to attribute (multiple blue teams run Prowler legitimately daily).

---

## Contents
- [Hunting Priority — Ranked by Evasion Survivability](#hunting-priority--ranked-by-evasion-survivability)
- [Hunting on Source Host](#hunting-on-source-host)
- [Hunting on Target (Cloud Logs)](#hunting-on-target-cloud-logs)
- [Cross-Cloud Hunting (Multi-Cloud Scans)](#cross-cloud-hunting-multi-cloud-scans)
- [Timeline Reconstruction Playbook](#timeline-reconstruction-playbook)
- [Fleet-Wide Detection (Cloud-Native Alerting)](#fleet-wide-detection-cloud-native-alerting)
- [False Positive Context](#false-positive-context)

---

## Hunting Priority — Ranked by Evasion Survivability

Below are detection signals ranked by how robust they are against operator evasion/cleanup tactics.

| Priority | Signal | Evasion Difficulty | Cloud-Side Permanent | Detection Method |
|---|---|---|---|---|
| **1 (Highest)** | CloudTrail/Activity Log/Audit Log read-heavy API sequence (ListUsers → DescribeInstances → ListBuckets...) | **Very hard** — operator cannot delete cloud logs without account compromise | ✅ **Yes, 90+ days** | See "Cloud Audit Log Analysis" below |
| **2** | Bulk API calls all from same `userIdentity.principalId` (IAM user, role, or service principal) within short timeframe | **Hard** — requires log modification or account deletion | ✅ **Yes, archived** | CloudTrail filter by principal + time window |
| **3** | Cross-account/cross-tenant scan pattern (STS AssumeRole or Azure cross-subscription calls) | **Hard** — both accounts log the activity | ✅ **Yes, separate logs** | Query both source + target account CloudTrail |
| **4** | Source IP address + time correlation (Prowler runs at `14:32Z`, CloudTrail events from same IP at `14:32:15Z` to `14:32:42Z`) | **Medium** — operator can use proxy/VPN, but VPC Flow Logs (if enabled) capture internal traffic | ⚠️ **Yes if Flow Logs enabled** | CloudTrail SourceIPAddress + VPC Flow Logs |
| **5** | User-Agent string signature (`python-requests`, `boto3`, `azure-identity`, `google-cloud-*`) | **Medium** — operator can spoof User-Agent, but legitimate cloud SDKs are hard to fake perfectly | ✅ **Yes** | CloudTrail UserAgent field analysis |
| **6** | Shell history on source host (`~/.bash_history`, `~/.zsh_history`) containing `prowler` command | **Easy** — operator can delete history, disable history, or clear in-memory buffer | ❌ **No (local only)** | Live host forensics or EDR history capture |
| **7** | Prowler binary/package presence on source host (`~/.local/lib/python3.x/site-packages/prowler/`) | **Easy** — operator can uninstall package | ❌ **No (local only)** | EDR package inventory, sysmon process lineage |
| **8** | Output files in local directory (`.json`, `.csv`, `.html` reports) | **Easy** — operator can delete output files | ❌ **No (local only)** | EDR file monitoring, undelete recovery |
| **9** | Credential file access (`~/.aws/credentials`, `~/.azure/credentials` read at scan time) | **Medium** — files persist, but can be deleted; IAM key rotation harder to conceal | ✅ **Yes (credential age traceable)** | auditd watch rules on credential files; IAM key age query |
| **10 (Lowest)** | Process memory dump (credentials/API responses in RAM) | **Very easy** — operator can kill process, reboot system | ❌ **No (ephemeral)** | Live memory forensics (requires immediate response) |

**Takeaway:** Cloud audit logs (signals 1–2) are the most resilient detection sources. Source-host artifacts require live-system access and rapid response.

---

## Hunting on Source Host

### Shell History Analysis

#### Bash/Zsh History Search
```bash
# On compromised/suspected host, search for Prowler invocations
grep -r prowler ~/.bash_history ~/.zsh_history /home/*/.bash_history 2>/dev/null

# OR search for specific Prowler flags
grep -E 'prowler|aws -f (cis|pci|nist)|--assume-role' ~/.bash_history

# Example output:
# prowler aws -f cis -o json -d ./audit-output
# prowler azure -f cis --client-id abc123 --tenant-id xyz789
```

**Timeline correlation:**
```bash
# Get the modification time of history file
stat ~/.bash_history
# Change: 2026-08-11 14:35:42.123456789 +0000

# Compare with Prowler scan timestamp (from cloud logs)
# If history mtime aligns with cloud API start time, confirms correlation
```

#### Shell History With Credential Leaks
```bash
# Search for hardcoded credentials in history
grep -E 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET' ~/.bash_history

# Example (bad OPSEC):
# AWS_ACCESS_KEY_ID=AKIA...[REDACTED] AWS_SECRET_ACCESS_KEY=... prowler aws -f cis

# Recover credentials directly from shell history
cat ~/.bash_history | grep -oP '(AKIA[A-Z0-9]{16}|[A-Za-z0-9/+=]{40})'
```

**Evasion indicators:**
```bash
# Operator ran Prowler with history disabled
HISTFILE=/dev/null prowler aws -f cis

# Check for presence of /dev/null in history (reveals evasion attempt)
grep '/dev/null' ~/.bash_history

# Operator cleared history in-memory (history -c) but not on disk
# Recent history file is suspiciously short or has gaps
wc -l ~/.bash_history  # Should be 1000+ lines in active user; if <100, suspicious
```

### Credential File Analysis

#### AWS Credentials File Inspection
```bash
# Check for cloud credential files
ls -la ~/.aws/

# Content analysis
cat ~/.aws/credentials
# [default]
# aws_access_key_id=AKIA...[REDACTED]
# aws_secret_access_key=...
# 
# [audit-profile]
# aws_access_key_id=AKIA...

# Timestamp of credential file
stat ~/.aws/credentials
# Access: 2026-08-11 14:32:00 (aligns with Prowler scan time!)
```

**Forensic value:**
- Multiple profiles = multiple cloud accounts targeted
- Profile name (e.g., `audit-profile`, `cross-account-prod`) hints at scope
- File access time (atime) matches Prowler execution start

#### Azure Credentials
```bash
# Service principal credentials (if stored locally)
cat ~/.azure/credentials

# msal_token_cache (MSAL Python library cache, used by Prowler)
file ~/.azure/msal_token_cache.bin
# Binary cache; timestamps show last login

# Check environment variables in current shell
env | grep -E 'AZURE_CLIENT'
```

#### GCP Service Account Key
```bash
# Find service account JSON key (Prowler -a flag points to it)
find ~ -name "*.json" -path "*/gcp/*" 2>/dev/null
find ~ -name "*service*account*.json" 2>/dev/null

# Content analysis
jq '.project_id, .client_email, .key_id' /path/to/key.json
# Reveals GCP project, service account email (attacker identity)

# Check atime (access time)
stat /path/to/key.json
# If accessed at Prowler scan time, confirms usage
```

### Prowler Package & Binary Analysis

#### Python Package Detection
```bash
# Check for installed Prowler package
pip list | grep prowler

# Find package directory
python3 -c "import prowler; print(prowler.__file__)"
# /usr/local/lib/python3.10/site-packages/prowler/__init__.py

# Check version
pip show prowler-cloud
# Name: prowler-cloud
# Version: 5.25.0
# Location: /usr/local/lib/python3.10/site-packages
# Installed-Date: 2026-08-10 13:45:32

# Timeline: installation date before scan date?
```

#### Git Clone Detection (Source Installation)
```bash
# Check for source directory
ls -la ~/prowler/.git 2>/dev/null

# Git history
cd ~/prowler && git log --oneline | head -5
# Recent commits show repo was actively used

# Timestamps on .git/objects (commit times)
stat ~/prowler/.git/objects/pack/*.pack | grep -E 'Modify|Change'
```

#### Docker Container Usage
```bash
# Check for cached Prowler image
docker images | grep prowler
# prowler-cloud/prowler:latest | 5.25.0 | 2026-08-10

# Container execution history
docker ps -a | grep prowler
# Container ID, creation time, exit time

# Inspect container logs (if still present)
docker logs <container-id> 2>&1 | grep -E 'Prowler|AWS|Azure|GCP'
```

### Local Output File Analysis

#### Output Directory Search
```bash
# Search for typical Prowler output directories
find ~ -type d -name "output" -o -name "*audit*" 2>/dev/null | head -20

# Look for output files with timestamps
find ~ -name "*prowler*.json" -o -name "*.html" -path "*/cis/*" 2>/dev/null

# Timeline of output files
ls -lt ~/output/ 2>/dev/null | head -10
# Most recent files are scan results
```

#### JSON Report Analysis (If Still Present)
```bash
# Extract metadata from JSON report
jq '.Metadata' ./output/json/cis-123456789012-report.json
# {
#   "Provider": "aws",
#   "Checks Passed": 187,
#   "Checks Failed": 43,
#   "Scan Date": "2026-08-11T14:32:00Z",
#   "Prowler Version": "5.25.0"
# }

# Extract high-threat findings
jq '.findings[] | select(.ThreatScore > 8)' ./output.json | head -20

# Correlate with cloud audit logs
# Scan date: 2026-08-11T14:32:00Z → match against CloudTrail start time
```

### Process & Memory Artifacts

#### Live Process Inspection (During Scan)
```bash
# While Prowler is running, capture command-line args
ps aux | grep prowler
# python /usr/local/bin/prowler aws -f cis -o json -d ./output

# Extract environment variables (if process still live)
cat /proc/<PID>/environ | tr '\0' '\n' | grep -E 'AWS|AZURE|GCP'
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_DEFAULT_REGION=us-east-1

# Full process tree (parent → child processes)
pstree -p <PID>
# Shows if Prowler spawned subprocesses (unusual if using SDK)
```

#### Memory Dump (Post-Incident)
```bash
# If system memory was captured (e.g., crash dump), search for credentials
strings memory.dump | grep -E 'AKIA|ASIA|prowler'

# Use Volatility to extract environment variables
volatility -f memory.dump linux.bash.bash_env
# May recover AWS_ACCESS_KEY_ID and scan parameters
```

### Evasion & Cleanup Detection

#### Indicators of History Cleanup
```bash
# Search for history-clearing commands
grep -E 'history -c|history -w|cat /dev/null|unset HISTFILE' ~/.bash_history

# Check for suspicious gaps in history (missing commands)
# If history jumps from 14:30 UTC to 14:40 UTC (10-min gap), investigate

# Check shell rc files for history disabling
grep -E 'HISTFILE=|unset HISTFILE|HISTSIZE=0' ~/.bashrc ~/.bash_profile ~/.zshrc

# Check for suspicious aliases (e.g., ls aliased to not show hidden files)
alias | grep -E 'ls=|history='
```

#### File Deletion Recovery
```bash
# On Linux, recover deleted files from unallocated space
sudo extundelete /dev/sdX --recover-all

# On macOS (if undelete tool available)
ls -l /path/to/deleted/files (if in Trash)

# EDR tools (Falcon, Defender, etc.) often retain file-deletion logs
# Query EDR event logs for file deletion patterns
```

---

## Hunting on Target (Cloud Logs)

### AWS CloudTrail Analysis

#### Query for Read-Only API Bulk Pattern
```bash
# Search CloudTrail for contiguous read-only API calls (Prowler signature)
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:30:00Z \
  --end-time 2026-08-11T14:35:00Z \
  --query 'Events[?ReadOnly==`true`].[EventTime, EventName, UserIdentity.principalId, SourceIPAddress]' \
  --output table
```

**Expected Prowler pattern:**
```
2026-08-11T14:32:15.001Z | ListUsers      | arn:aws:iam::123456789012:user/security-audit | 192.168.1.100
2026-08-11T14:32:15.234Z | ListRoles      | arn:aws:iam::123456789012:user/security-audit | 192.168.1.100
2026-08-11T14:32:15.567Z | ListAccessKeys | arn:aws:iam::123456789012:user/security-audit | 192.168.1.100
... [dozens more API calls within 30-second window]
2026-08-11T14:32:42.999Z | GetKeyPolicy   | arn:aws:iam::123456789012:user/security-audit | 192.168.1.100
```

**Detection:** Burst of 100+ read-only API calls from single principal in < 60 seconds = strong Prowler signature.

#### Athena Query (if CloudTrail logs in S3)
```sql
SELECT
  eventTime,
  eventName,
  userIdentity.principalId,
  sourceIPAddress,
  COUNT(*) as call_count
FROM cloudtrail_logs
WHERE eventTime BETWEEN '2026-08-11T14:30:00Z' AND '2026-08-11T14:35:00Z'
  AND readOnly = true
  AND eventSource IN ('iam.amazonaws.com', 'ec2.amazonaws.com', 's3.amazonaws.com', 'rds.amazonaws.com', 'kms.amazonaws.com')
GROUP BY eventTime, eventName, userIdentity.principalId, sourceIPAddress
ORDER BY eventTime;
```

#### Identify Framework Used (from API Call Mix)
```bash
# Extract unique event names in time window
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[*].EventName' \
  | jq -s 'group_by(.) | map({event: .[0], count: length}) | sort_by(.count) | reverse'

# Output:
# [
#   { "event": "ListUsers", "count": 2 },
#   { "event": "ListRoles", "count": 2 },
#   { "event": "DescribeInstances", "count": 8 },
#   { "event": "GetBucketEncryption", "count": 15 }
# ]

# Interpretation:
# - Many IAM calls (ListUsers, ListRoles) = CIS 1.x (Access Control)
# - Many EC2 calls = CIS 2.x (Networking)
# - Many S3 calls = CIS 2.3/2.4 (Storage)
# Conclusion: CIS audit, likely framework = cis
```

#### Cross-Account Scan Detection
```bash
# Look for STS AssumeRole calls preceding bulk API activity from another account
aws cloudtrail lookup-events \
  --event-names 'AssumeRole' \
  --query 'Events[0]' --output json | jq '.'

# Check if source principal (in account A) assumed role in account B
# Then subsequent API calls in account B from that role = cross-account Prowler scan
```

### Azure Activity Log Analysis

#### Query for Read Operations Burst
```bash
# Use Azure CLI to query Activity Log
az monitor activity-log list \
  --start-time 2026-08-11T14:30:00Z \
  --end-time 2026-08-11T14:35:00Z \
  --query "[?operationName.value | contains('/read')].{Time: eventTimestamp, Operation: operationName.value, Caller: caller, Status: status.value}" \
  --output table

# Expected output (Prowler signature):
# Time                          | Operation                            | Caller                              | Status
# 2026-08-11T14:32:15.001Z      | Microsoft.Compute/virtualMachines/read | prowler-audit@tenant.onmicrosoft.com | Succeeded
# 2026-08-11T14:32:15.234Z      | Microsoft.Storage/storageAccounts/read | prowler-audit@tenant.onmicrosoft.com | Succeeded
# ... [dozens more /read operations]
```

#### KQL Query (if using Azure Log Analytics)
```kusto
AzureActivity
| where TimeGenerated between (datetime(2026-08-11T14:30:00Z) .. datetime(2026-08-11T14:35:00Z))
| where OperationName contains "/read"
| where Caller has "prowler"
| summarize APICallCount = count() by bin(TimeGenerated, 1m), OperationName
| sort by TimeGenerated desc
```

#### Cross-Tenant Audit Detection
```bash
# Check if managed identity or service principal spans multiple subscriptions
az role assignment list --query "[?principalName | contains('prowler')].{Principal: principalName, Scope: scope}"

# Multiple scopes = multi-tenant/multi-subscription scan
```

### GCP Cloud Audit Logs Analysis

#### Query Audit Logs
```bash
gcloud logging read 'protoPayload.methodName=~".*list|.*get"' \
  --start-time=2026-08-11T14:30:00Z \
  --end-time=2026-08-11T14:35:00Z \
  --format=json | jq '.[] | {time: .timestamp, method: .protoPayload.methodName, principal: .authenticationInfo.principalEmail}'

# Expected Prowler pattern:
# {
#   "time": "2026-08-11T14:32:15.001Z",
#   "method": "storage.buckets.list",
#   "principal": "prowler-sa@my-project.iam.gserviceaccount.com"
# }
# ... [dozens more list/get operations]
```

#### Detect Service Account Abuse
```bash
# Check for unusual activity by service account
gcloud iam service-accounts describe prowler-sa@my-project.iam.gserviceaccount.com

# List all actions this service account took recently
gcloud logging read 'authenticationInfo.principalEmail="prowler-sa@my-project.iam.gserviceaccount.com"' \
  --start-time=2026-08-11 \
  --limit=100

# Timeline: if service account was created yesterday, then suddenly active today = suspicious
```

---

## Cross-Cloud Hunting (Multi-Cloud Scans)

### Detecting AWS + Azure + GCP Scans from Same Source

#### Scenario: Attacker runs Prowler against all three clouds
```bash
# Timestamp correlation across clouds

# AWS CloudTrail
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[0].[EventTime, UserIdentity.principalId, SourceIPAddress]'
# 2026-08-11T14:32:15Z | arn:aws:iam::111111111111:user/attacker | 192.168.1.100

# Azure Activity Log
az monitor activity-log list --start-time 2026-08-11T14:32:00Z --end-time 2026-08-11T14:33:00Z \
  --query '[0].[eventTimestamp, caller]'
# 2026-08-11T14:32:14Z | prowler-audit@tenant.onmicrosoft.com

# GCP Audit Logs
gcloud logging read 'timestamp>="2026-08-11T14:32:00Z" AND timestamp<="2026-08-11T14:33:00Z"' \
  --limit=1 --format=json | jq '.[0].{time: .timestamp, principal: .authenticationInfo.principalEmail}'
# {
#   "time": "2026-08-11T14:32:14Z",
#   "principal": "prowler-sa@project-id.iam.gserviceaccount.com"
# }

# Correlation:
# All three clouds show similar start time (~14:32:14Z), suggesting:
# 1. Single attacker with multi-cloud access
# 2. Possible scripted multi-cloud scan (e.g., for-loop over three environments)
# 3. Attacker is mapping full cloud portfolio for exploitation/lateral movement
```

#### Cross-Cloud IP Correlation
```bash
# Extract source IPs from all three cloud audit logs
# AWS: 192.168.1.100 (CloudTrail SourceIPAddress)
# Azure: 192.168.1.100 (Activity Log callerIPAddress)
# GCP: 192.168.1.100 (requestMetadata.callerIp)

# If all three show SAME IP, very strong indicator of coordinated scan
# If different IPs, suggests federated authentication (different gateways per cloud)
```

---

## Timeline Reconstruction Playbook

### Step-by-Step Incident Investigation

**Scenario:** Blue team detects bulk API calls to AWS account; suspects Prowler or similar enumeration tool.

#### Phase 1: Establish Scan Window

```bash
# Query CloudTrail for burst of read-only calls
aws cloudtrail lookup-events \
  --query 'Events[*].[EventTime]' \
  --output text | sort | uniq -c
# Count events per second; big spike = scan window

# Get exact start/end times
aws cloudtrail lookup-events \
  --query 'Events[] | [min_by(@, &EventTime).EventTime, max_by(@, &EventTime).EventTime]'
# ["2026-08-11T14:32:15.001Z", "2026-08-11T14:32:42.999Z"]

# Scan duration: 28 seconds (typical for Prowler full CIS audit)
```

#### Phase 2: Identify Principal (Attacker)

```bash
# Query for unique principals in scan window
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[*].UserIdentity.principalId' \
  | jq -s 'unique'
# ["arn:aws:iam::123456789012:user/security-audit"]

# Single principal = single attacker identity or service principal
# Multiple principals = team activity or cross-account assume-role

# Query IAM user details
aws iam get-user --user-name security-audit
# { "User": { "UserName": "security-audit", "Arn": "...", "CreateDate": "2026-08-10..." } }

# User created recently? = red flag (purpose-built for audit)
```

#### Phase 3: Determine Scope (Framework & Resources Scanned)

```bash
# Enumerate API calls per service
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:32:00Z \
  --end-time 2026-08-11T14:33:00Z \
  --query 'Events[*].EventSource' \
  | jq -s 'group_by(.) | map({service: .[0], count: length}) | sort_by(.count) | reverse'

# Output:
# [
#   {"service": "iam.amazonaws.com", "count": 12},
#   {"service": "ec2.amazonaws.com", "count": 45},
#   {"service": "s3.amazonaws.com", "count": 20},
#   ...
# ]

# API mix matches CIS Benchmark checks = likely Prowler running CIS audit
```

#### Phase 4: Correlate with Source Host (if accessible)

```bash
# On suspected source host, check shell history
grep prowler ~/.bash_history

# Extract the exact command run
grep "prowler aws -f cis" ~/.bash_history

# Compare command flags with cloud behavior:
# If history shows: prowler aws -f cis -r us-east-1,us-west-2
# And CloudTrail shows API calls only in us-east-1, us-west-2
# = Strong confirmation of correlation
```

#### Phase 5: Attribution

```bash
# Check if operator is internal (authorized) or external (threat)

# Internal signals (legitimate audit):
# - User created by security team (check IAM user CreateDate + description)
# - Run during business hours (check EventTime timestamps)
# - Account is "security-audit" or similar (naming convention)
# - Scan includes remediation notes (if HTML report found on host)

# External signals (unauthorized threat):
# - User created recently (within hours of scan)
# - Run outside business hours (2 AM UTC)
# - Source IP is public/external (not corporate VPN)
# - Account is generic/suspicious (e.g., "admin", "test")
# - Scan results exfiltrated to S3 (if -b flag used)

# Query for suspicious follow-up activity
aws cloudtrail lookup-events \
  --start-time 2026-08-11T14:33:00Z \
  --end-time 2026-08-11T15:00:00Z \
  --query 'Events[?UserIdentity.principalId==`arn:aws:iam::123456789012:user/security-audit`]'
# If attacker used same identity for exploitation (CreateAccessKey, PutBucketPolicy), = red flag
```

---

## Fleet-Wide Detection (Cloud-Native Alerting)

### AWS GuardDuty

#### Prowler-Specific Findings
```bash
# List GuardDuty findings that may correlate with Prowler
aws guardduty list-findings --detector-id <detector-id> --finding-criteria '{"Criterion": {"type": {"Eq": ["Recon:IAMUser/Anomalous"]}}}'

# Expected finding (false positive if authorized scan):
# {
#   "FindingId": "12abc34d567e8f9g0h1i2j3k4l5m6n7o",
#   "Type": "Recon:IAMUser/Anomalous",
#   "Severity": 4.0,
#   "CreatedAt": 1628692335000,
#   "UpdatedAt": 1628692335000,
#   "Resource": { "ResourceType": "AccessKey", "AccessKeyDetails": { "PrincipalId": "AIDACKCEVSQ6C2EXAMPLE", "UserName": "security-audit" } },
#   "ServiceDetails": { "EventFirstSeen": 1628692310000, "EventLastSeen": 1628692410000, "Evidence": "Made 150 API calls in 100 seconds" }
# }

# **Interpretation:** Bulk API calls from single IAM user = Prowler signature, but could be authorized.
# **Response:** Whitelist the `security-audit` user in GuardDuty suppression rules if scan is authorized.

# Suppress finding (if authorized)
aws guardduty update-findings-feedback --detector-id <detector-id> --finding-ids "12abc34d567e8f9g0h1i2j3k4l5m6n7o" --feedback ARCHIVED
```

### Azure Defender

#### Anomalous Activity Detection
```bash
# Check for "Anomalous activity from a Service Principal" alert
az security alert list --query "[?AlertDisplayName contains 'Anomalous']"

# Alert structure:
# {
#   "AlertDisplayName": "Anomalous activity from a Service Principal",
#   "AlertType": "ServicePrincipalAnomalousActivity",
#   "ReportedSeverity": "Informational",
#   "CreatedAt": "2026-08-11T14:32:15Z",
#   "Description": "Service principal 'prowler-audit' made 120 API calls in 30 seconds"
# }

# Suppress alert (if authorized)
az security alert dismiss --name "12abc34d567e8f9g0h1i2j3k4l5m6n7o"
```

### GCP Security Command Center

#### Bulk Activity Detection
```bash
# Query Security Command Center findings
gcloud scc findings list <org-id> --source <source-id> --query "findings[resource.name contains 'anomalous']"

# Check for reconnaissance patterns
gcloud scc findings list <org-id> --source <source-id> \
  --filter "category='Anomalous bulk activity' AND severity='HIGH'"
```

### SIEM Correlation (Splunk, ELK, Sentinel)

#### Detection Rule (Splunk SPL)
```splunk
sourcetype=cloudtrail (eventSource=iam.amazonaws.com OR eventSource=ec2.amazonaws.com OR eventSource=s3.amazonaws.com)
| stats count as api_call_count dc(eventName) as unique_events by userIdentity.principalId, sourceIPAddress, date_hour
| where api_call_count > 100 AND unique_events > 20
| rename userIdentity.principalId as Principal
| eval alert_type="Potential Prowler Scan"
```

#### Detection Rule (Azure Sentinel KQL)
```kusto
AzureActivity
| where TimeGenerated > ago(1h)
| where OperationName contains "/read"
| summarize APICallCount = count(), UniqueOperations = dcount(OperationName) by Caller, bin(TimeGenerated, 1m)
| where APICallCount > 50 and UniqueOperations > 10
| extend AlertName = "Bulk Read-Only API Activity (Possible Cloud Enumeration)"
```

---

## False Positive Context

### Legitimate Prowler Use Cases (Not a Threat)

1. **Security/Compliance Team Running Authorized Audits**
   - Scheduled weekly/daily CIS audits
   - User account is owned by security team
   - Source IP is corporate network (VPN/office)
   - Findings documented in compliance system (Jira, ServiceNow)

2. **Incident Response Investigation**
   - Blue team running Prowler post-breach to assess compromise scope
   - User is IR-team member (documented in incident ticket)
   - Scan limited to specific account/region (not full portfolio)

3. **Third-Party Assessor/Auditor**
   - External security firm running Prowler for SOC 2/ISO/FedRAMP audit
   - Service principal created for vendor access (with expiration date)
   - Scan is logged in audit ticket/contract

4. **Automated Compliance Monitoring (Prowler SaaS/Commercial)
   - Prowler service principal running on schedule (daily/weekly)
   - Service principal is "prowler" or "compliance-automation"
   - API calls are consistent time-of-day (no randomization = likely automation, not attacker)

### Red Flags vs. Benign Indicators

| Indicator | Benign (Authorized) | Red Flag (Threat) |
|---|---|---|
| **Scan Duration** | 30-120 seconds (predictable) | Repeats multiple times in 24h (probing) |
| **User Account Age** | Created weeks/months ago | Created within 24h of scan (prep) |
| **Time of Day** | Business hours (9-5) | Off-hours (2-4 AM) |
| **Source IP** | Corporate network, VPN | Public IP, rotating IPs, Tor |
| **Scan Scope** | Full account (routine audit) | Single service (targeted reconnaissance) |
| **Follow-Up Activity** | None (read-only) | Exploitation attempt (CreateAccessKey, PutBucketPolicy) |
| **Output Handling** | Local review, no exfil | Uploaded to attacker-controlled S3 (`-b` flag) |
| **Cloud Credential Age** | Rotated monthly | Never rotated (static creds for persistence) |

### Whitelisting & Suppression

#### AWS CloudTrail Suppression (Quiet Authorized Scans)
```bash
# Create event selectors to exclude known audit accounts from detailed logging
aws cloudtrail put-event-selectors \
  --trail-name my-trail \
  --event-selectors '[{
    "ReadWriteType": "ReadOnly",
    "IncludeManagementEvents": true,
    "DataResources": [],
    "ExcludeManagementEventSources": ["security-audit@example.com"]
  }]'
```

#### Azure Sentinel Automation Rule
```yaml
name: "Whitelist Authorized Prowler Audits"
triggers:
  - type: "Alert"
    alert_type: "Bulk Read-Only API Activity"
conditions:
  - field: "Caller"
    operator: "equals"
    value: ["prowler-audit@tenant.onmicrosoft.com", "security-team@tenant.onmicrosoft.com"]
  - field: "TimeGenerated"
    operator: "between"
    value: ["08:00", "18:00"]  # Business hours only
actions:
  - action: "Close Alert"
  - action: "Add Tag"
    tag: "authorized-compliance-scan"
```

---

## Cross-Link: Similar Tools

- **ScoutSuite** (Wave 4 #14): Also performs cloud enumeration via read-only API calls; nearly identical CloudTrail signature to Prowler. Differentiation: ScoutSuite focuses on "what's exploitable" vs. Prowler's "compliance framework mapping." Both are read-only; both leave similar audit-log traces.
- **Pacu** (Wave 4 #13): AWS-only exploitation framework; **not read-only**. CloudTrail will show `ReadOnly: false` when Pacu modifies resources (e.g., PutBucketPolicy, CreateAccessKey). This is the key differentiator.

---

## Detection Command Reference

### Quick Hunt Commands (One-Liners)

```bash
# AWS: Find bulk API calls in last hour
aws cloudtrail lookup-events --max-results 100 --query 'Events[?ReadOnly==`true`].[EventTime, EventName, UserIdentity.principalId]' | tail -20

# Azure: Find service principal activity
az monitor activity-log list --offset 1h --query "[?operationName.value contains '/read'].{Time: eventTimestamp, Operation: operationName.value, Caller: caller}"

# GCP: Find bulk list/get operations
gcloud logging read 'protoPayload.methodName=~".*list|.*get"' --limit 50 --format json | jq '.[] | {method: .protoPayload.methodName, time: .timestamp}'

# Source host: Check for Prowler in history
grep -r prowler ~/.bash_history ~/.zsh_history /var/log/auth.log 2>/dev/null

# Source host: Find recent credential access
stat ~/.aws/credentials ~/.azure/credentials ~/.config/gcloud/ 2>/dev/null | grep -E 'Access|Modify'
```

