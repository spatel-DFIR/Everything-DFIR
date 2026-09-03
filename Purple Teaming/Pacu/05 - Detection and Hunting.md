# Pacu — Detection & Hunting

---

## Hunting Priority — Signal Ranking by Evasion Resistance

Not all detection signals are equally resilient to evasion. Pacu operators can obscure some evidence but not others. This table ranks detection signals from **hardest to evade** (rank 1) to **easiest to defeat** (rank 5):

| Rank | Signal | Evasion Resistance | Why | Mitigation |
|---|---|---|---|---|
| **1** | **CloudTrail events (CreateAccessKey, CreateRole, CreateFunction)** | Impossible to evade | These API calls are **logged by AWS** before the attacker's code executes; operator cannot disable CloudTrail logging retroactively without AWS API access (which itself logs). Even if attacker deletes logs, CloudTrail → S3 MFA-protected log bucket prevents retroactive deletion. | MFA-protect CloudTrail S3 bucket; enable CloudTrail log integrity; set up CloudTrail → CloudWatch Logs forwarding (immutable). |
| **2** | **GuardDuty findings (anomalous privilege escalation, cross-account assumption)** | Very difficult | GuardDuty findings are **generated and stored by AWS** in a managed database. Operator can suppress findings (`guardduty__whitelist_ip`) but this action is itself logged and leaves a suspicious "finding suppression" event. | Baseline GuardDuty alert patterns; monitor for suppression activity; forward findings to external SIEM. |
| **3** | **High-volume API calls from single IP (enumeration pattern)** | Very difficult | Even if the compromised credential is later deleted, the IP address and CloudTrail events correlate back to enumeration. Attacker's IP is embedded in CloudTrail. | Monitor for bulk ListUsers, DescribeInstances, GetBucketLocation sequences; geo-location blocking (if attacker IP is out-of-country). |
| **4** | **Suspicious resource creation (new IAM user, new Lambda function)** | Difficult | Attacker can delete resources post-exploitation, but deletion is itself logged. AWS Config change history may survive deletion. CloudTrail → S3 archive enables log reconstruction even if on-premise logs are deleted. | AWS Config MFA-protected; immutable archive to external storage; alerting on Create+Delete sequences. |
| **5** | **Attacker's source IP** | Difficult | Attacker can use VPN/proxy, but most don't. If attacker IP is known, it can be blocked and added to threat intelligence. | Geolocation-based blocking; IP reputation services; alert on unexpected geographic access. |
| **6** | **Local session files (~/.pacu/sessions/main.db)** | Easy to evade | Attacker can delete session directory (`rm -rf ~/.pacu/`). However, recovery is possible via forensic imaging if attacker's machine is seized. | Forensic acquisition of attacker's machine (requires law enforcement or physical access). |
| **7** | **Shell history** | Very easy to evade | `history -c`, `rm ~/.bash_history`, `unset HISTFILE` — all trivial commands. | Monitor for history-clearing commands; collect shell history via EDR if deployed on attacker's machine. |
| **8** | **Pacu process visibility** | Easy to evade | Attacker can run Pacu via SSH/C2 on a compromised instance (process runs on AWS side, not attacker's machine). Or run via Docker, which obscures Python binary. | Monitor for Python processes with boto3 network calls; network-level monitoring for AWS API calls. |

---

## Hunting on Source (Attacker's Machine)

### Search for Pacu Session Files

**Goal:** Locate the `~/.pacu/sessions/` directory and recover credentials + enumeration history.

**Filesystem Search (Linux/macOS):**
```bash
# Find all Pacu session directories
find ~ -type d -name "pacu" 2>/dev/null
# Output: /home/attacker/.pacu
# Output: /Users/attacker/.pacu

# List all session folders
ls -la ~/.pacu/sessions/
# Output: prod-aws, staging-aws, dev-aws, ... (one folder per AWS account accessed)

# Dump the SQLite database (credentials)
sqlite3 ~/.pacu/sessions/prod-aws/main.db "SELECT * FROM credentials;"
# Output:
# key_alias|access_key_id|secret_access_key|session_token|account_id|user_arn
# compromised-dev|AKIA...[REDACTED]|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY||123456789012|arn:aws:iam::123456789012:user/compromised-dev

# Extract all enumerated IAM users
sqlite3 ~/.pacu/sessions/prod-aws/main.db "SELECT username FROM iam_users;"
# Output: ci-deploy, lambda-service, backup-admin, ...

# Extract all discovered S3 buckets
sqlite3 ~/.pacu/sessions/prod-aws/main.db "SELECT bucket_name FROM s3_buckets;"
```

**Windows (if WSL or native Python is used):**
```powershell
# Find Pacu directories
Get-ChildItem -Path $env:USERPROFILE -Filter ".pacu" -Recurse -Force

# Access SQLite database
C:\> sqlite3 "C:\Users\attacker\.pacu\sessions\prod-aws\main.db" "SELECT * FROM credentials;"
```

### Search Shell History

**Goal:** Recover commands showing Pacu was run and what modules were executed.

```bash
# Check bash history
cat ~/.bash_history | grep -i pacu

# Output examples:
# pacu
# set_keys
# set_regions all
# run iam__enum_users
# run s3__download_bucket --bucket-name acme-prod-backups
# export_data S3 csv
# run lambda__backdoor_new_users

# Check zsh history (if zsh is the shell)
cat ~/.zsh_history | grep pacu

# Check for history-clearing commands (sign of evasion)
grep -E "history -c|rm.*bash_history|unset HISTFILE" ~/.bash_history
# If found, history was deliberately cleared → suspicious
```

**Detection Note:** If `.bash_history` is suspiciously empty or truncated while other shell configuration files exist, an attacker cleared history.

### Search for Pacu Process Artifacts

**Goal:** Find evidence that Pacu ran (process trees, running processes).

```bash
# Check for running Pacu process
ps aux | grep -i pacu
# Output: attacker 12345  0.5  2.1  152000 87456 pts/0  S+  14:31  0:15 python3 -m pacu --session prod-aws

# Check process parent/child tree (if still running)
pstree -p $PID

# Check Python process command lines (may reveal Pacu module being run)
cat /proc/12345/cmdline | tr '\0' '\n'
# Output: python3, -m, pacu, --session, prod-aws

# Check network connections from Pacu process
lsof -p $PID | grep AWS
# Output: python3 12345 attacker 123u  IPv4 987654  0t0  TCP attacker.local:50123->iam.us-east-1.amazonaws.com:443 (ESTABLISHED)

# Look for any boto3-related Python processes
ps aux | grep python | grep -E "boto|aws"
```

**Windows:**
```powershell
# Check for Pacu-related processes
Get-Process | Where-Object { $_.ProcessName -like "*pacu*" -or $_.ProcessName -like "*python*" } | Select-Object ProcessName, Id, StartTime, CommandLine

# Check network connections from Python processes
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -like "*.amazonaws.com" } | Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess

# Use Get-WmiObject to retrieve detailed command line
Get-WmiObject Win32_Process -Filter "name like '%python%'" | Select-Object ProcessId, CommandLine, CreationTime
```

### Search for Downloaded AWS Data

**Goal:** Find bulk-downloaded AWS data (databases, backups, configuration files).

```bash
# Look for S3 downloads directory
find ~ -type d -name "*s3_download*" -o -name "*bucket*" 2>/dev/null

# Look for recently-modified large files (exfiltrated data)
find ~ -type f -size +100M -newermt "2026-08-11 14:00" 2>/dev/null

# Check for database files
find ~ -name "*.sql*" -o -name "*.rdb" -o -name "*.db" -mtime -1 2>/dev/null

# Check temp directories for temporary files
ls -lah /tmp/pacu* /tmp/aws* 2>/dev/null
ls -lah $TMPDIR/*pacu* 2>/dev/null
```

### Search for AWS Credentials in Environment & Memory

**Goal:** Extract AWS credentials from the attacker's machine (environment, shell configuration, memory dumps).

```bash
# Check environment variables (if process is still running)
cat /proc/$PID/environ | tr '\0' '\n' | grep AWS

# Check shell configuration files for hardcoded credentials
grep -r "AWS_ACCESS_KEY" ~/.bashrc ~/.bash_profile ~/.zshrc ~/.profile

# Search for credential patterns in files
grep -r "AKIA[0-9A-Z]\{16\}" ~/ 2>/dev/null  # AWS access key ID pattern

# Memory forensics (if attacker's machine is live)
# Use volatility or Rekall to search process memory for credential strings
volatility -f memory.dump pslist
volatility -f memory.dump memdump -p $PID -D /tmp/
strings /tmp/$PID.dmp | grep -E "AKIA|wJalr"  # AWS patterns
```

### Search for Event Logs (Windows)

**Goal:** Find PowerShell history, command execution logs, process tracking logs.

```powershell
# Check PowerShell history (if Pacu was run via PowerShell or Python called from PS)
Get-Content $PROFILE -ErrorAction SilentlyContinue
Get-Content "C:\Users\attacker\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"

# Check Windows Event Log for process creation events
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Where-Object { $_.Message -like "*pacu*" -or $_.Message -like "*python*" } | Select-Object TimeCreated, Message

# Check for file creation events (Pacu session files)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} | Where-Object { $_.Message -like "*pacu*" } | Select-Object TimeCreated, Message
```

---

## Hunting on Target (AWS Account)

### CloudTrail Query for Suspicious API Calls

**Goal:** Find API calls indicating Pacu enumeration, exploitation, or cover-up.

**AWS CLI (Local Investigation):**

```bash
# 1. Find all API calls by a specific credential (suspected compromised user)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-dev \
  --start-time 2026-08-11T14:00:00Z \
  --end-time 2026-08-11T15:00:00Z \
  --query 'Events[*].[EventTime, EventName, SourceIPAddress, RequestParameters]' \
  --output table

# 2. Find all CreateAccessKey actions (new backdoor credentials)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --query 'Events[*].[EventTime, UserIdentity.principalId, SourceIPAddress, RequestParameters]'

# 3. Find all CreateRole actions in a time window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateRole \
  --start-time 2026-08-11T14:00:00Z \
  --query 'Events[*].[EventTime, UserIdentity.arn, RequestParameters]'

# 4. Find all SimulateCustomPolicy calls (Pacu's iam__enum_permissions)
# High volume from single IP = enumeration
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=SimulateCustomPolicy \
  --query 'Events[*].[EventTime, SourceIPAddress]' | sort | uniq -c

# 5. Find all S3 GetObject calls in a time window (exfiltration pattern)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time 2026-08-11T14:30:00Z \
  --end-time 2026-08-11T15:00:00Z \
  --query 'Events[*].[EventTime, SourceIPAddress]' | wc -l
# If > 500 GetObject calls in 30 min from single IP → likely exfiltration

# 6. Find backdoor resource creation (Lambda functions, IAM roles with suspicious names)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateFunction \
  --query 'Events[*].[EventTime, UserIdentity.principalId, RequestParameters]'

# 7. Find CloudTrail manipulation attempts
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=DeleteTrail \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --query 'Events[*].[EventTime, UserIdentity.arn, SourceIPAddress]'

# 8. Find cross-account role assumption (lateral movement)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --query 'Events[*].[EventTime, UserIdentity.principalId, RequestParameters]'
```

### CloudTrail Insights Query (Athena SQL)

If CloudTrail logs are exported to S3 and queried via Athena:

```sql
-- Find all API calls by a specific user in 1 hour
SELECT eventtime, eventname, sourceipaddress, awsregion, useragent
FROM cloudtrail_logs
WHERE useridentity.principalid LIKE '%compromised-dev%'
  AND eventtime BETWEEN '2026-08-11T14:00:00Z' AND '2026-08-11T15:00:00Z'
ORDER BY eventtime;

-- Find all CreateAccessKey, CreateRole, CreateFunction in a day
SELECT eventtime, useridentity.arn, eventname, sourceipaddress
FROM cloudtrail_logs
WHERE eventname IN ('CreateAccessKey', 'CreateRole', 'CreateFunction', 'CreateUser')
  AND eventtime > '2026-08-10T00:00:00Z'
ORDER BY eventtime;

-- Find all GetObject calls from a specific IP (exfiltration detection)
SELECT eventtime, COUNT(*) as call_count, sourceipaddress
FROM cloudtrail_logs
WHERE eventname = 'GetObject'
  AND eventtime > '2026-08-11T14:00:00Z'
GROUP BY sourceipaddress
HAVING COUNT(*) > 100
ORDER BY call_count DESC;

-- Find EnumPermissions pattern (600+ SimulateCustomPolicy calls in short time)
SELECT sourceipaddress, COUNT(*) as call_count, MIN(eventtime) as first_call, MAX(eventtime) as last_call
FROM cloudtrail_logs
WHERE eventname = 'SimulateCustomPolicy'
  AND eventtime > '2026-08-11T14:00:00Z'
GROUP BY sourceipaddress
HAVING COUNT(*) > 100;
```

### GuardDuty Finding Search

```bash
# Query GuardDuty findings
aws guardduty list-findings \
  --detector-id <detector-id> \
  --finding-criteria '{"Criterion": {"severity": {"Gte": 7}}}' \
  --query 'FindingIds'

# Get details on specific finding
aws guardduty get-findings \
  --detector-id <detector-id> \
  --finding-ids <finding-id> \
  --query 'Findings[*].[Type, Severity, CreatedAt, Title]'

# Export findings to CSV for analysis
aws guardduty list-findings --detector-id <id> --query 'FindingIds' \
  | xargs -I {} aws guardduty get-findings --detector-id <id> --finding-ids {} \
  | jq '.Findings[] | [.CreatedAt, .Type, .Severity, .Title]' > guardduty_findings.csv
```

### Detect Newly Created IAM Users & Access Keys

```bash
# List all IAM users and sort by creation date
aws iam list-users \
  --query 'Users[*].[CreateDate, UserName]' \
  --output text | sort -r | head -20

# List all access keys for all users (find recently-added keys)
for user in $(aws iam list-users --query 'Users[*].UserName' --output text); do
  aws iam list-access-keys --user-name $user \
    --query "AccessKeyMetadata[*].[CreateDate, AccessKeyId]" \
    --output text
done | sort -r | head -20

# Detect access keys created in specific time window
aws iam list-users --query 'Users[*].UserName' --output text | while read user; do
  aws iam list-access-keys --user-name $user \
    --query "AccessKeyMetadata[?CreateDate > '2026-08-11T14:00:00'] | [*].[AccessKeyId, CreateDate]"
done
```

### Detect New Lambda Functions & Roles

```bash
# List Lambda functions sorted by creation date
aws lambda list-functions \
  --query 'Functions[*].[LastModified, FunctionName, Runtime]' \
  --output text | sort -r | head -20

# Check recently-created IAM roles
aws iam list-roles \
  --query "Roles[?CreateDate > '2026-08-11T14:00:00'].{Name:RoleName, Created:CreateDate, Arn:Arn}" \
  --output text

# List all inline policies for recently-created roles
for role in $(aws iam list-roles --query 'Roles[*].RoleName' --output text); do
  echo "=== $role ==="
  aws iam list-role-policies --role-name $role --query 'PolicyNames' --output text
done
```

### Detect Modified Security Groups

```bash
# List all security groups and their ingress rules
aws ec2 describe-security-groups \
  --query 'SecurityGroups[*].[GroupId, GroupName, IpPermissions[?FromPort==`0` && IpRanges[?CidrIp==`0.0.0.0/0`]]]' \
  --output text

# Detect overly-permissive rules (0.0.0.0/0 access to common ports)
aws ec2 describe-security-groups \
  --query "SecurityGroups[*].[GroupId, GroupName, IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']].[FromPort, ToPort]]" \
  --output text

# Get security group modification history (via AWS Config)
aws configservice get-resource-config-history \
  --resource-type AWS::EC2::SecurityGroup \
  --resource-ids sg-12345678 \
  --query 'ConfigurationItems[*].[ConfigurationItemCaptureTime, Configuration.GroupId]'
```

### Detect GuardDuty Suppression

```bash
# List IP sets (whitelists) in GuardDuty
aws guardduty list-ip-sets --detector-id <detector-id>

# Get details on IP set (should only contain known/trusted IPs)
aws guardduty get-ip-set --detector-id <detector-id> --ip-set-id <set-id>

# Monitor for UpdateDetector actions (detector configuration changes)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=UpdateDetector \
  --query 'Events[*].[EventTime, UserIdentity.principalId, RequestParameters]'
```

### Detect Exfiltration (High-Volume Data Download)

```bash
# Find S3 buckets with unusual access patterns
aws s3api list-objects --bucket acme-prod-backups --max-items 1000000 | wc -l
# If bucket typically has N objects but suddenly thousands accessed → exfiltration

# Check CloudTrail for GetObject requests targeting specific bucket
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=RequestParameters,AttributeValue=acme-prod-backups \
  --query 'Events[*].[EventTime, EventName, UserIdentity.principalId, SourceIPAddress]' \
  | grep GetObject | wc -l
# If > 500 GetObject requests in short time → exfiltration in progress
```

---

## Fleet-Wide Sweep Commands

Use these commands to hunt across all AWS accounts in an organization:

```bash
# Scan all accounts for recently-created IAM users
for account in $(aws organizations list-accounts --query 'Accounts[*].Id' --output text); do
  echo "=== Account $account ==="
  aws iam list-users --query "Users[?CreateDate > '2026-08-01T00:00:00Z'].UserName" \
    --output text 2>/dev/null || echo "Access denied"
done

# Scan all regions for new Lambda functions
for region in us-east-1 us-west-2 eu-west-1 eu-central-1; do
  echo "=== Region $region ==="
  aws lambda list-functions --region $region \
    --query 'Functions[*].[LastModified, FunctionName]' \
    --output text | sort -r | head -5
done

# Scan all regions for modified security groups
for region in us-east-1 us-west-2 eu-west-1; do
  aws ec2 describe-security-groups --region $region \
    --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].{Id:GroupId, Name:GroupName}" \
    --output text
done
```

---

## Remediation & Response

### Immediate Actions (First Hour)

1. **Rotate compromised credentials**
   ```bash
   # Disable all access keys for the compromised user
   aws iam update-access-key-status --user-name compromised-dev \
     --access-key-id AKIAIOSFODNN7ORIGINAL --status Inactive
   
   # Create new access key for legitimate operations
   aws iam create-access-key --user-name compromised-dev
   ```

2. **Delete backdoor resources**
   ```bash
   # Delete backdoor Lambda function
   aws lambda delete-function --function-name pacu-backdoor-function
   
   # Delete backdoor IAM user/role
   aws iam delete-user --user-name pacu-backdoor-user
   aws iam delete-role --role-name pacu-backdoor-role
   
   # Revert security group changes
   aws ec2 revoke-security-group-ingress --group-id sg-12345678 \
     --ip-permissions IpProtocol=tcp,FromPort=3306,ToPort=3306,IpRanges="[{CidrIp=0.0.0.0/0}]"
   ```

3. **Disable GuardDuty suppression**
   ```bash
   # Remove IP set (whitelist)
   aws guardduty delete-ip-set --detector-id <detector-id> --ip-set-id <set-id>
   ```

### Follow-Up (Hours 2-24)

1. **Preserve evidence** — Export all CloudTrail logs to immutable S3 bucket with MFA delete enabled.

2. **Scope the compromise** — Determine:
   - What data was exfiltrated?
   - What credentials were exposed?
   - What cross-account accounts were accessed?

3. **Notify affected parties** — Customers, partners, regulatory bodies (if required).

4. **Implement preventive controls**:
   - Enable MFA for all IAM users
   - Enable CloudTrail log integrity
   - Deploy AWS Config rules for detecting configuration changes
   - Deploy GuardDuty in all accounts + regions
   - Implement least-privilege IAM policies (remove overly-broad permissions)

---

## 🔗 Cross-References

- **Cloud/Amazon/AWS/02 - Investigating AWS.md** — CloudTrail querying methodology.
- **Cloud/Amazon/AWS/Logging & Monitoring/CloudTrail.md** — Event ID reference and forensic reconstruction.
- **Cloud/Amazon/AWS/Logging & Monitoring/GuardDuty.md** — Finding types and alert interpretation.
- **Purple Teaming/NetExec/** — Similar AWS credential-abuse tool; parallel detection strategies.

---

