# ScoutSuite — Detection and Hunting

---

## Detection Strategies

### 1. Cloud Audit Log Anomaly Detection

**Baseline approach:** Establish normal API request patterns, then alert on deviations.

**Implementation:**

**AWS CloudTrail anomaly detection:**

```python
# Pseudo-code: Detect rapid API calls from unusual IP
import json
import collections
from datetime import datetime, timedelta

def detect_scout_suite_activity(cloudtrail_logs, threshold_api_calls=50, time_window_minutes=15):
    """
    Detect potential ScoutSuite reconnaissance activity in CloudTrail logs.
    """
    # Aggregate API calls by source IP and time window
    ip_activity = collections.defaultdict(lambda: {'calls': [], 'services': set()})
    
    for event in cloudtrail_logs:
        if event['eventType'] != 'AwsApiCall':
            continue
        
        source_ip = event.get('sourceIPAddress', 'unknown')
        event_time = datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
        event_name = event['eventName']
        service = event['eventSource'].split('.')[0]  # ec2, s3, iam, etc.
        
        ip_activity[source_ip]['calls'].append({
            'time': event_time,
            'event': event_name,
            'service': service
        })
        ip_activity[source_ip]['services'].add(service)
    
    # Analyze patterns
    suspicious_activity = []
    
    for source_ip, activity in ip_activity.items():
        # Skip internal IPs and AWS-internal operations
        if source_ip.startswith(('10.', '172.16.', '192.168.')) or source_ip == 'AWS Internal':
            continue
        
        # Count API calls in each time window
        calls = sorted(activity['calls'], key=lambda x: x['time'])
        for i in range(len(calls)):
            window_start = calls[i]['time']
            window_end = window_start + timedelta(minutes=time_window_minutes)
            
            calls_in_window = [c for c in calls 
                              if window_start <= c['time'] <= window_end]
            
            if len(calls_in_window) >= threshold_api_calls:
                suspicious_activity.append({
                    'source_ip': source_ip,
                    'api_calls': len(calls_in_window),
                    'time_window': (window_start, window_end),
                    'services': activity['services'],
                    'confidence': 'HIGH' if len(activity['services']) >= 3 else 'MEDIUM'
                })
    
    return suspicious_activity
```

**Scoring criteria:**
- **50–100 API calls in 15 minutes:** MEDIUM confidence (could be CI/CD pipeline)
- **100–300 API calls in 15 minutes:** HIGH confidence (likely reconnaissance)
- **300+ API calls in 15 minutes:** CRITICAL confidence (definite automated scan)
- **Enumeration of 4+ services (EC2, S3, IAM, VPC):** HIGH confidence (broad reconnaissance scope)
- **Source IP outside organization:** HIGH confidence (external reconnaissance)

---

### 2. Behavioral Detection Using Machine Learning

**Approach:** Train a model on normal cloud API usage patterns; flag outliers.

**Features to extract:**

1. **API call velocity:** Requests per minute from a given user/IP
2. **Service diversity:** Number of distinct cloud services accessed
3. **Geographic anomaly:** API calls from unexpected geographic region
4. **Time-of-day anomaly:** API calls outside normal business hours
5. **Comprehensive enumeration pattern:** Sequential calls to Describe*/List* methods (signature of automated scanning)
6. **User-Agent anomaly:** SDK-style user agents (boto3, azure-cli) instead of human web client

**Example detection rule (Sigma format):**

```yaml
title: ScoutSuite-like Cloud Reconnaissance Activity
id: a1b2c3d4e5f6g7h8i9j0
description: Detects potential ScoutSuite automated cloud resource enumeration
status: experimental
logsource:
  product: cloud
  service: cloudtrail  # or azure activity log, gcp audit logs
detection:
  selection:
    eventType: AwsApiCall
    eventName|startswith:
      - Describe
      - List
      - Get
    readOnlyEvent: true
  filter_internal:
    sourceIPAddress|startswith:
      - 10.
      - 172.16.
      - 192.168.
  filter_aws_internal:
    sourceIPAddress: AWS Internal
  timeframe:
    - field: eventTime
      window: 15m
      aggregate: count
      operator: '>='
      value: 50
  condition: selection and not filter_internal and not filter_aws_internal and timeframe
falsepositives:
  - CI/CD pipelines performing infrastructure validation
  - Legitimate cloud security scanning tools
  - Cloud management console bulk operations
level: medium
```

---

### 3. Network-Based Detection

**Approach:** Monitor outbound HTTPS traffic to cloud provider API endpoints.

**Detection signatures:**

**AWS API endpoint access pattern:**
```
Destination: *.amazonaws.com (wildcard)
Destination IPs: AWS IP ranges (https://ip-ranges.amazonaws.com/ip-ranges.json)
Protocol: HTTPS (TCP 443)
Characteristic pattern:
  - High request volume (50+ TLS connections in 15 minutes)
  - Rapid connection cycling (new connection every 1–5 seconds)
  - Consistent SNI hostname pattern (api.aws.amazon.com, ec2.amazonaws.com, etc.)
```

**Azure API endpoint access pattern:**
```
Destination: management.azure.com, graph.microsoft.com, login.microsoftonline.com
Protocol: HTTPS (TCP 443)
Characteristic pattern:
  - Rapid-fire POST/GET requests to management.azure.com
  - Multiple distinct resource groups accessed in short timeframe
  - User-Agent contains "Azure SDK", "python-requests", or "azure-cli"
```

**GCP API endpoint access pattern:**
```
Destination: cloudresourcemanager.googleapis.com, compute.googleapis.com, storage.googleapis.com
Protocol: HTTPS (TCP 443)
Characteristic pattern:
  - High-volume LIST, GET requests to GCP API endpoints
  - Multiple distinct projects enumerated
  - User-Agent contains "google-cloud", "gcloud", or "Python"
```

**IDS/IPS rule example (Suricata):**

```
alert http any any -> any any (
  msg:"Possible ScoutSuite AWS Reconnaissance";
  flow:to_server,established;
  content:"GET|20|";
  http_uri:"/";
  content:"Host|3a|";
  http_host:"*.amazonaws.com";
  threshold:type both,track by_src,count 50,seconds 900;
  classtype:attempted-recon;
  sid:4000001;
  rev:1;
)
```

---

### 4. Host-Based Detection

**Approach:** Monitor for ScoutSuite installation and execution on internal machines.

**File-based detection:**

```bash
# Alert if ScoutSuite repository exists
find / -name "ScoutSuite" -type d 2>/dev/null

# Alert if scout.py or scoutsuite package exists
find / -name "scout.py" 2>/dev/null
find / -name "scoutsuite" -type d 2>/dev/null

# Alert if cloud SDK binaries are recently executed
lastused scout
lastused gcloud
lastused az
lastused aws
```

**Process-based detection:**

```bash
# Monitor for Python interpreters running scout or cloud SDK tools
ps aux | grep -E "scout\.py|scout aws|scout azure|scout gcp"

# Monitor for uncommon python module imports
strace -e openat python 2>&1 | grep -E "boto3|azure|google.cloud"
```

**Log-based detection (Auditd on Linux):**

```
# Alert on execution of scout.py
-w /opt/scoutsuite/scout.py -p x -k scout_execution

# Alert on access to .aws/credentials
-w ~/.aws/credentials -p r -k aws_credentials_access

# Alert on access to .azure directory
-w ~/.azure -p r -k azure_credentials_access
```

---

## Hunting Techniques

### 1. CloudTrail Log Hunting

**Query 1: Bulk Describe* calls within a short timeframe**

```sql
-- AWS Athena query
SELECT
  eventTime,
  sourceIPAddress,
  eventName,
  userIdentity.principalId,
  COUNT(*) as api_count
FROM cloudtrail_logs
WHERE
  eventTime >= date_format(current_timestamp - interval '24' hour, '%Y-%m-%dT%H:%i:%SZ')
  AND eventName LIKE 'Describe%'
  AND eventType = 'AwsApiCall'
  AND sourceIPAddress NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'AWS Internal')
GROUP BY
  eventTime,
  sourceIPAddress,
  eventName,
  userIdentity.principalId
HAVING api_count >= 10
ORDER BY api_count DESC
LIMIT 100;
```

**Query 2: Cross-service enumeration (indicator of automated scanning)**

```sql
SELECT
  sourceIPAddress,
  eventTime,
  COUNT(DISTINCT eventSource) as unique_services,
  COUNT(*) as total_calls
FROM cloudtrail_logs
WHERE
  eventTime >= date_format(current_timestamp - interval '24' hour, '%Y-%m-%dT%H:%i:%SZ')
  AND eventType = 'AwsApiCall'
  AND sourceIPAddress NOT IN ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
GROUP BY
  sourceIPAddress,
  eventTime
HAVING unique_services >= 4 AND total_calls >= 50
ORDER BY total_calls DESC;
```

**Query 3: Rapid S3 bucket enumeration (ListBuckets + GetBucketPolicy calls)**

```sql
SELECT
  sourceIPAddress,
  eventTime,
  userIdentity.principalId,
  COUNT(CASE WHEN eventName = 'ListBuckets' THEN 1 END) as list_calls,
  COUNT(CASE WHEN eventName = 'GetBucketPolicy' THEN 1 END) as policy_calls,
  COUNT(CASE WHEN eventName = 'GetBucketAcl' THEN 1 END) as acl_calls
FROM cloudtrail_logs
WHERE
  eventTime >= date_format(current_timestamp - interval '24' hour, '%Y-%m-%dT%H:%i:%SZ')
  AND eventName IN ('ListBuckets', 'GetBucketPolicy', 'GetBucketAcl')
  AND eventType = 'AwsApiCall'
GROUP BY
  sourceIPAddress,
  eventTime,
  userIdentity.principalId
HAVING (policy_calls + acl_calls) >= 20
ORDER BY (policy_calls + acl_calls) DESC;
```

---

### 2. Azure Activity Log Hunting

**KQL Query 1: Rapid-fire read operations across resources**

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatus == "Succeeded"
| where OperationName endswith "/read" or OperationName endswith "/list"
| where CallerIpAddress !in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')
| extend ServiceName = tostring(split(ResourceProvider, "/")[0])
| summarize
    ReadCount = count(),
    DistinctOperations = dcount(OperationName),
    DistinctServices = dcount(ServiceName)
  by CallerIpAddress, Caller, bin(TimeGenerated, 15m)
| where ReadCount >= 50 and DistinctServices >= 3
| order by ReadCount desc
```

**KQL Query 2: Service principal IAM enumeration**

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where Caller contains "service principal" or Caller contains "app"
| where OperationName in (
    "List role assignments",
    "Get role assignments",
    "List service principals",
    "Get service principal"
  )
| summarize
    EnumerationCount = count(),
    DistinctResources = dcount(ResourceId)
  by Caller, CallerIpAddress, bin(TimeGenerated, 15m)
| where EnumerationCount >= 20
| order by EnumerationCount desc
```

---

### 3. GCP Cloud Audit Logs Hunting

**Cloud Logging query 1: Bulk list operations**

```sql
resource.type = "gce_project"
AND protoPayload.methodName =~ "compute\..*\.list|storage\..*\.list|iam\..*\.list"
AND protoPayload.status.code = 0
AND protoPayload.requestMetadata.callerIp != "127.0.0.1"
AND protoPayload.requestMetadata.callerIp !~ "^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)"
| GROUP BY protoPayload.requestMetadata.callerIp
| COUNT()
| HAVING COUNT() >= 50
| SORT(COUNT, DESC)
```

**Cloud Logging query 2: getIamPolicy bulk operations (permission enumeration)**

```sql
resource.type = "gce_project"
AND protoPayload.methodName = "*.getIamPolicy"
AND protoPayload.status.code = 0
| GROUP BY protoPayload.requestMetadata.callerIp, protoPayload.request.resource
| COUNT()
| HAVING COUNT() >= 20
| SORT(COUNT, DESC)
```

---

### 4. File System Hunting

**Search for ScoutSuite artifacts on compromised machines:**

```bash
# Find ScoutSuite reports
find / -name "scoutsuite-report.html" -o -name "scoutsuite-findings.json" 2>/dev/null

# Find cloud SDK credentials
find / -name "credentials" -path "*/.aws/*" 2>/dev/null
find / -path "*/.azure/accessTokens/*" 2>/dev/null
find / -name "*service-account*.json" 2>/dev/null

# Find ScoutSuite source code
find / -path "*/ScoutSuite/scout.py" 2>/dev/null
find / -path "*/scoutsuite-venv/*" 2>/dev/null

# Find cloud SDK configuration
find / -path "*/.aws/config" 2>/dev/null
find / -path "*/.config/gcloud/properties" 2>/dev/null
```

**Search for evidence in shell history:**

```bash
# Bash history
grep -i "scout\|scoutsuite" ~/.bash_history
grep -i "aws configure\|az login\|gcloud auth" ~/.bash_history

# Zsh history
grep -i "scout\|scoutsuite" ~/.zsh_history

# All users' histories (as root)
for user in $(cut -d: -f1 /etc/passwd); do
  echo "=== $user ==="
  grep -i "scout\|aws\|azure\|gcp" /home/$user/.bash_history 2>/dev/null
done
```

---

### 5. Database Hunting (if logs are centralized)

**SIEM query (Elasticsearch/Splunk) for ScoutSuite patterns:**

```
source=cloudtrail_logs eventType=AwsApiCall
| stats count by eventName, sourceIPAddress
| where count > 10 and eventName LIKE "Describe%" OR eventName LIKE "Get%" OR eventName LIKE "List%"
| timechart count by sourceIPAddress
```

**SQL query (if logs are in database):**

```sql
SELECT
  source_ip,
  COUNT(*) as api_calls,
  COUNT(DISTINCT event_name) as distinct_events,
  COUNT(DISTINCT service) as distinct_services,
  MIN(event_time) as first_call,
  MAX(event_time) as last_call,
  (JULIANDAY(MAX(event_time)) - JULIANDAY(MIN(event_time))) * 24 * 60 as duration_minutes
FROM cloud_audit_logs
WHERE
  event_time > datetime('now', '-24 hours')
  AND event_type = 'API_CALL'
  AND read_only = 1
  AND source_ip NOT LIKE '10.%' AND source_ip NOT LIKE '172.16.%' AND source_ip NOT LIKE '192.168.%'
GROUP BY source_ip
HAVING
  api_calls >= 50
  AND distinct_services >= 3
  AND duration_minutes <= 30
ORDER BY api_calls DESC;
```

---

## Incident Response Playbook

### Phase 1: Confirmation (0–30 minutes)

1. **Alert triggered** — Automated detection detects bulk API calls from external IP
2. **Verify in logs** — Query CloudTrail/Activity Logs/Audit Logs for confirmed activity
3. **Identify scope:**
   - How many API calls? (50–100 = limited; 300+ = aggressive)
   - Which services enumerated? (EC2, S3, IAM, VPC = full scope)
   - How long did it last? (5–10 min = fast automated scan; 30+ min = slower or exploratory)
   - Which AWS/Azure/GCP account(s) targeted?
4. **Identify user identity:**
   - Who authorized the reconnaissance? (which user/role/service principal?)
   - Is this identity compromised or intentional (authorized penetration test)?

### Phase 2: Containment (30–60 minutes)

1. **Revoke compromised credentials immediately** (if not authorized penetration test):
   - AWS: Disable IAM user access keys; assume-role blocked for compromised principal
   - Azure: Reset service principal password; disable if suspicious
   - GCP: Revoke service account key; disable if suspicious
2. **Block source IP** in firewall/security group (cloud provider and network perimeter)
3. **Enable Enhanced logging:**
   - Enable CloudTrail data events (for detailed read access logging)
   - Enable Azure Monitor diagnostic settings for affected resources
   - Enable GCP Cloud Audit Logs data access tier (if not already enabled)
4. **Activate incident response team** — notify security, compliance, legal

### Phase 3: Investigation (1–4 hours)

1. **Determine attacker intent:**
   - Which resources were queried? (storage buckets, databases, IAM users?)
   - What configuration was discovered? (public S3 buckets, overpermissioned roles, etc.?)
   - Did attacker attempt exploitation after reconnaissance? (check for write operations or lateral movement)
2. **Timeline reconstruction:**
   - When was access obtained? (when did compromised credentials first appear in logs?)
   - How long was reconnaissance in progress?
   - Any activity before the bulk API calls? (credential enumeration, privilege escalation?)
3. **Scope of exposure:**
   - How much cloud configuration was exposed? (all regions? all subscriptions?)
   - Are cloud audit logs themselves intact/unmodified?
   - Any evidence of data exfiltration? (downloads from S3, database dumps?)

### Phase 4: Recovery & Hardening (4–24 hours)

1. **Reset all affected user/service principal credentials**
2. **Change cloud account root access keys** (AWS)
3. **Enable MFA on all admin accounts**
4. **Implement cloud access controls:**
   - Require IP whitelist for API access (restrict to corporate IPs)
   - Enable STS session duration limits
   - Enable resource-based policies to restrict API access
5. **Implement detection improvements:**
   - Deploy cloud-native SIEM rules for future ScoutSuite activity
   - Enable CloudTrail data events (detailed logging of resource access)
   - Set up alerts on bulk List/Describe operations

### Phase 5: Post-Incident Review (24–48 hours)

1. **Document findings** — CIRT report on attack, exposure, and root cause
2. **Review cloud configuration** for security gaps (use ScoutSuite internally to audit)
3. **Share IoCs** with security team — IP addresses, user agents, timestamps

---

## Evasion Techniques (What Defenders Should Watch For)

ScoutSuite operators may attempt to evade detection using these techniques:

1. **Rate limiting / slow enumeration:**
   - Spread API calls over longer time period (1 API call per 5–10 seconds)
   - Reduces API call velocity; harder to detect as anomaly
   - **Defense:** Look for sequential API calls in ordered patterns (Describe* calls all in sequence), not just bulk velocity

2. **Credential rotation:**
   - Use multiple AWS profiles or Azure service principals
   - Each identity enumerates a subset of resources
   - Distributed across time (days/weeks)
   - **Defense:** Track enumeration patterns cross-identity; flag any identity rapidly calling List/Describe operations

3. **VPN/proxy tunneling:**
   - Route reconnaissance traffic through VPN to hide source IP
   - **Defense:** Analyze User-Agent and API patterns (even with different IPs, API call patterns are similar)

4. **Timing attacks during maintenance windows:**
   - Run ScoutSuite during scheduled maintenance or known high-API-call periods
   - **Defense:** Maintain baseline per time-of-day; flag outliers even during busy periods

5. **Custom rule modifications:**
   - Modify ScoutSuite rules to skip certain checks (reduce API call volume)
   - **Defense:** Complete enumeration is still visible (even reduced set of rules requires broad API calls)

---

## Summary: Detection Checklist

| Detection Method | Ease | Effectiveness | False Positive Rate |
|---|---|---|---|
| **CloudTrail/Activity Log queries** | Easy | High | Low (if tuned) |
| **Network-based (IDS/firewall logs)** | Medium | Medium | Medium (many API calls are legitimate) |
| **Automated ML-based anomaly detection** | Hard | High | Low (if model well-trained) |
| **File system/process monitoring** | Easy | Low | Low |
| **SIEM correlation** | Medium | High | Medium |
| **User behavior analytics (UBA)** | Hard | High | Low |

**Recommended layered approach:**
1. **Layer 1 (Detection):** CloudTrail queries for rapid bulk API calls
2. **Layer 2 (Enrichment):** Cross-reference with known IP reputation, threat intelligence
3. **Layer 3 (Investigation):** Manual review of affected resources; determine if authorized testing
4. **Layer 4 (Response):** If unauthorized, revoke credentials immediately; enable enhanced logging

