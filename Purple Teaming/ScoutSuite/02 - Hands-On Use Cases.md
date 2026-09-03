# ScoutSuite — Hands-On Use Cases

## Use Case 1: Baseline AWS Security Configuration Audit (T1526.003)

**Scenario:** Red teamer has AWS credentials (from phishing, credential stuffing, or EC2 instance role) and wants to assess the baseline security posture of the target AWS account. Goal is to identify configuration gaps vs. CIS Benchmarks for inclusion in the final red-team report.

**MITRE ATT&CK mapping:**
- **T1526.003 — Gather System Network Configuration Information / Cloud Infrastructure Discovery**
- **T1652 — Gather Victim Cloud Infrastructure Information** (external assessment)

### Step-by-step walkthrough

**1. Verify AWS CLI is configured with the target account credentials:**
```bash
aws sts get-caller-identity
# Expected output: AWS account ID, ARN of the authenticated identity
```

**2. Run ScoutSuite against AWS:**
```bash
scout aws --report-dir ./aws-audit-results
```

**What this does:**
- Authenticates to AWS using the configured CLI credentials
- Enumerates all EC2 instances, S3 buckets, IAM users/roles, security groups, RDS databases, load balancers, CloudTrail settings, etc. across all AWS regions
- Evaluates each resource against CIS AWS Foundations Benchmark rules (500+ checks)
- Generates an interactive HTML report and JSON findings file

**3. Review the report:**
```bash
open ./aws-audit-results/scoutsuite-report.html  # macOS
# OR
firefox ./aws-audit-results/scoutsuite-report.html  # Linux
# OR
start ./aws-audit-results/scoutsuite-report.html  # Windows
```

**Expected findings (example output):**
- **Critical:** 3 S3 buckets with public-read ACL
- **High:** EC2 security group allows 0.0.0.0/0 on port 3306 (MySQL)
- **High:** CloudTrail not enabled on primary account
- **Medium:** RDS instance not encrypted at rest
- **Medium:** 5 IAM users have inactive access keys (30+ days old)
- **Low:** VPC Flow Logs not enabled

**4. Export findings to JSON for programmatic processing:**
```bash
cat ./aws-audit-results/scoutsuite-findings.json | \
  jq '.findings | map(select(.severity == "CRITICAL"))' > critical-findings.json
```

**Attacker's next step:** Use identified public S3 buckets for data exfiltration; attempt to assume overpermissioned IAM roles via STS AssumeRole; or exploit weak security group rules for network lateral movement.

**Detection angle:** CloudTrail will log GetUser, ListUsers, DescribeInstances, DescribeBuckets, GetBucketPolicy API calls in rapid succession from a single source IP (the attacker's machine).

---

## Use Case 2: Azure IAM Overpermissioning Discovery (T1526.003)

**Scenario:** Red teamer has Azure tenant credentials and wants to identify overpermissioned service principals, users with excessive roles, and misconfigured access policies. Goal is to find privilege escalation paths.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**
- **T1087.004 — Account Discovery / Cloud Account** (discovering high-privilege identities)

### Step-by-step walkthrough

**1. Authenticate to Azure (using browser MFA):**
```bash
scout azure --user-account-browser --report-dir ./azure-iam-audit
```

**What this does:**
- Opens browser for interactive MFA login
- Authenticates to the default subscription
- Enumerates Azure AD users, groups, service principals, and their IAM role assignments
- Checks for overpermissioning patterns (e.g., Owner role on subscription, Directory admin roles, etc.)

**2. Focus on service principals (high-value compromise targets):**
```bash
cat ./azure-iam-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_id | contains("service_principal")))'
```

**Expected findings:**
- **Critical:** Service principal "app-automation-prod" has Owner role on subscription
- **High:** Service principal "third-party-api" has Directory.Read.All and Directory.Write.All permissions
- **High:** 10 service principals with secret credentials expiring in <30 days
- **Medium:** User "admin-acc" has Directory admin role but hasn't logged in for 90+ days

**3. Export IAM role assignments for analysis:**
```bash
cat ./azure-iam-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_name | contains("Owner")))'
```

**Attacker's next step:** Compromise identified service principal via its stored credentials (often in configuration files, environment variables, or Key Vault); assume Owner role on subscription to escalate privileges; or exploit Directory admin role to add new admin accounts or reset user passwords.

**Detection angle:** Azure Activity Log will show a burst of List, Get, and Read operations on Azure AD (users, groups, applications) and Azure Resource Manager (role assignments, permissions) from the attacker's IP.

---

## Use Case 3: Multi-Cloud Comparison (AWS + Azure + GCP)

**Scenario:** Target organization uses multiple cloud providers. Red teamer wants to benchmark security posture across all three clouds and identify which cloud has the weakest configuration (for targeted exploitation).

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**
- **T1652 — Gather Victim Cloud Infrastructure Information**

### Step-by-step walkthrough

**1. Run ScoutSuite against all three clouds in sequence:**
```bash
# AWS
scout aws --report-dir ./multi-cloud-audit/aws

# Azure (with specific subscription)
scout azure --cli --subscriptions "Production" \
  --report-dir ./multi-cloud-audit/azure

# GCP
scout gcp --user-account --projects "prod-project-123" \
  --report-dir ./multi-cloud-audit/gcp
```

**2. Compare findings across clouds:**
```bash
for cloud in aws azure gcp; do
  echo "=== $cloud ===" 
  cat ./multi-cloud-audit/$cloud/scoutsuite-findings.json | \
    jq '.findings | length' | \
    xargs echo "Total findings:"
  cat ./multi-cloud-audit/$cloud/scoutsuite-findings.json | \
    jq '.findings | map(.severity) | group_by(.) | map({(.[0]): length}) | add'
done
```

**Expected output (example):**
```
=== aws ===
Total findings: 47
{"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 22}

=== azure ===
Total findings: 23
{"CRITICAL": 0, "HIGH": 3, "MEDIUM": 12, "LOW": 8}

=== gcp ===
Total findings: 61
{"CRITICAL": 5, "HIGH": 18, "MEDIUM": 28, "LOW": 10}
```

**3. Identify the "weakest link" (GCP in this example) for targeted exploitation:**
```bash
cat ./multi-cloud-audit/gcp/scoutsuite-findings.json | \
  jq '.findings | sort_by(.severity) | reverse | .[0:10]'
```

**Attacker's next step:** Focus exploitation efforts on GCP (highest risk); attempt to escalate from identified critical/high-severity findings.

**Detection angle:** Three simultaneous cloud audit log investigations (CloudTrail for AWS, Activity Log for Azure, Cloud Audit Logs for GCP) will show correlated burst of reconnaissance API calls.

---

## Use Case 4: Exposed Storage Detection (S3, Azure Blob, GCS)

**Scenario:** Attacker wants to identify publicly-accessible cloud storage buckets that may contain sensitive data (backups, configuration files, private keys, etc.).

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**
- **T1526.005 — Cloud Infrastructure Discovery / Obtain Sensitive Data** (if data is exfiltrated from exposed buckets)

### Step-by-step walkthrough

**1. Run ScoutSuite specifically targeting storage audit rules:**
```bash
scout aws --report-dir ./storage-audit
```

**2. Filter findings for public storage buckets:**
```bash
cat ./storage-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_id | test("public|acl")))' > public-storage.json
```

**3. List publicly-accessible bucket names:**
```bash
jq '.[] | {bucket_name: .resource_id, acl: .description}' public-storage.json
```

**Expected output (example):**
```json
{
  "bucket_name": "backup-prod-2024",
  "acl": "S3 bucket is publicly readable"
}
{
  "bucket_name": "logs-analytics-2024",
  "acl": "S3 bucket is publicly readable and writable"
}
```

**4. Verify accessibility and enumerate contents:**
```bash
aws s3 ls s3://backup-prod-2024 --no-sign-request
# If successful, attacker can download objects
aws s3 cp s3://backup-prod-2024/prod-db-backup.sql.gz . --no-sign-request
```

**Attacker's impact:** Download sensitive data from exposed buckets; if bucket is writable, inject malicious files (e.g., backdoored application binary, malicious script).

**Detection angle:** S3 access logs (if enabled) will show GET requests from non-authenticated principals; CloudTrail will show describe/list bucket operations from the reconnaissance phase.

---

## Use Case 5: Insecure Network Configuration Auditing

**Scenario:** Attacker wants to identify network misconfigurations that allow lateral movement or external access to databases, admin panels, or other sensitive services.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**
- **T1526.001 — Cloud Infrastructure Discovery / Compute Instances** (with focus on network exposure)

### Step-by-step walkthrough

**1. Run ScoutSuite and filter for network-related findings:**
```bash
scout aws --report-dir ./network-audit
```

**2. Extract security group rules allowing dangerous inbound traffic:**
```bash
cat ./network-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_name | contains("security") or contains("ingress")))' \
  > network-findings.json
```

**Expected findings:**
- **High:** Security group "prod-db-sg" allows 0.0.0.0/0 inbound on port 3306 (MySQL from entire internet)
- **High:** Security group "admin-bastion" allows 0.0.0.0/0 on port 22 (SSH from entire internet)
- **Medium:** VPC has no flow logs enabled (cannot audit network traffic)
- **Medium:** Network ACLs overly permissive (allow-all ingress/egress)

**3. Identify resources using those misconfigured security groups:**
```bash
aws ec2 describe-instances \
  --filters "Name=instance.group-id,Values=sg-xxxxxxxx" \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,Tags[0].Value]' \
  --output table
```

**Attacker's next step:** Attempt to connect to identified RDS databases or bastion hosts via the exposed ports; enumerate further from those systems.

**Detection angle:** VPC Flow Logs (if enabled) will show inbound connections on unusual ports (3306, 5432, 27017) from external IPs; security group access logs will show "allowed" entries for those connections.

---

## Use Case 6: Post-Compromise Assessment

**Scenario:** Blue team has detected and contained a breach; red team is tasked with assessing what attacker had access to based on cloud configuration at time of compromise. Goal is to identify exposed secrets, exported data, or compromised identities.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery** (post-incident inventory)

### Step-by-step walkthrough

**1. Take a "snapshot" of cloud configuration immediately after incident:**
```bash
scout aws --report-dir ./incident-snapshot-$(date +%s)
```

**2. Compare snapshot to baseline (if baseline exists from before compromise):**
```bash
# Using jq to diff findings
diff <(jq '.findings | sort_by(.resource_id)' baseline-findings.json) \
     <(jq '.findings | sort_by(.resource_id)' incident-findings.json) \
     > config-changes.diff
```

**3. Check for evidence of attacker activity (new IAM users, modified policies, etc.):**
```bash
cat incident-findings.json | jq '.findings | map(select(.rule_name | contains("iam") or contains("policy")))'
```

**Expected findings (example):**
- **Critical:** New IAM user "backup-automation" created 2 hours before incident detection
- **High:** S3 bucket policy modified to allow public-read on "prod-backups" bucket
- **High:** CloudTrail logging disabled on primary account (2 hours ago)
- **Medium:** EC2 instance security group modified to allow 0.0.0.0/0 on port 22 (SSH)

**4. Export a detailed CSV of exposed resources for incident response team:**
```bash
jq -r '.findings[] | [.resource_id, .rule_name, .severity] | @csv' incident-findings.json \
  > incident-exposure-summary.csv
```

**Incident response use:** Identify what was exposed; verify if attacker exfiltrated data; assess whether backup/recovery procedures can be executed safely.

**Detection angle:** CloudTrail API logs will show timestamps of policy changes, security group modifications, and user creations; correlate with other indicators of compromise (malware execution, network anomalies).

---

## Use Case 7: Logging and Monitoring Gap Identification

**Scenario:** Auditor wants to ensure that all AWS/Azure/GCP resources are generating audit logs (for compliance, forensics, and detection). Goal is to find resources without CloudTrail, Activity Log, or Cloud Audit Logs enabled.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**

### Step-by-step walkthrough

**1. Run ScoutSuite and filter for logging-related findings:**
```bash
scout aws --report-dir ./logging-audit
cat ./logging-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_name | contains("logging") or contains("trail") or contains("audit")))'
```

**Expected findings:**
- **Critical:** CloudTrail is not enabled on the account
- **High:** S3 bucket does not have access logging enabled
- **High:** RDS instance does not have enhanced monitoring enabled
- **Medium:** VPC Flow Logs not enabled
- **Medium:** Lambda function does not have CloudWatch logs

**2. Check which services lack logging configuration:**
```bash
jq -r '.findings[] | select(.severity == "HIGH" or .severity == "CRITICAL") | 
  .resource_type + ": " + .description' ./logging-audit/scoutsuite-findings.json | sort | uniq -c
```

**3. Create remediation plan (enable CloudTrail, S3 access logging, VPC Flow Logs, etc.)**

**Attacker's perspective:** Absence of logging means attacker activity will not be recorded; this is an ideal target for data exfiltration or persistence.

**Detection angle:** Blue team will discover the logging gaps via vulnerability assessments or compliance audits; this informs incident response prioritization.

---

## Use Case 8: Encryption Misconfiguration Detection

**Scenario:** Compliance auditor wants to ensure that all storage buckets, databases, and disks are encrypted at rest with customer-managed keys (not AWS-managed keys).

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**

### Step-by-step walkthrough

**1. Run ScoutSuite with encryption-focused rules:**
```bash
scout aws --report-dir ./encryption-audit
cat ./encryption-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_name | contains("encrypt") or contains("kms")))'
```

**Expected findings:**
- **High:** S3 bucket does not have default encryption enabled
- **High:** RDS database encryption is disabled
- **High:** EBS volumes not encrypted
- **Medium:** S3 bucket uses AWS-managed key (not customer-managed KMS key)
- **Medium:** EBS snapshots are public

**2. Identify resources with weak encryption:**
```bash
jq -r '.findings[] | 
  select(.rule_name | contains("aws-managed")) | 
  .resource_id' ./encryption-audit/scoutsuite-findings.json | head -20
```

**3. Report to infrastructure team for remediation:**

**Attacker's perspective:** Weak encryption means data at rest is either unencrypted or uses AWS-managed keys (attacker with access to the account can decrypt it).

**Detection angle:** Encryption configuration changes can be tracked via CloudTrail; this is a blue-team control.

---

## Use Case 9: Service-Principal Overpermissioning (Azure-specific)

**Scenario:** Red teamer has compromised an Azure tenant and wants to identify service principals with excessive permissions that can be escalated into full tenant compromise.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery**
- **T1098.003 — Account Manipulation / Modify Cloud Account** (if service principal is compromised and used for escalation)

### Step-by-step walkthrough

**1. Run ScoutSuite against Azure with focus on service principals:**
```bash
scout azure --cli --all-subscriptions --report-dir ./azure-sp-audit
```

**2. Filter for service principals with critical permissions:**
```bash
cat ./azure-sp-audit/scoutsuite-findings.json | \
  jq '.findings | map(select(.rule_name | contains("Owner") or contains("admin")))' \
  > critical-sp-findings.json
```

**Expected findings:**
- **Critical:** Service principal "automation-prod" has Owner role on all subscriptions
- **High:** Service principal "third-party-api" has Directory.Write.All permission
- **High:** Service principal has been inactive for 180+ days (orphaned account)
- **Medium:** Service principal with multiple credential secrets (high key compromise risk)

**3. Identify service principal credentials location (often exposed in code repositories, configuration files):**
```bash
# Attacker perspective: search for service principal credentials in GitHub, CI/CD pipelines
git log --all -S "tenant_id" --source --remotes --oneline | head -20
```

**4. Attempt to authenticate as identified service principal:**
```bash
# If credentials found in config file
az login --service-principal \
  -u <client_id> \
  -p <client_secret> \
  --tenant <tenant_id>

# Verify permissions
az role assignment list --include-inherited --output table
```

**Attacker's next step:** Use compromised service principal to add new admin accounts, create backdoor apps, or extract secrets from Key Vault.

**Detection angle:** Azure Activity Log will show unusual API calls (user/group/app modifications) from the service principal's identity; anomaly detection can flag service principals making atypical API calls.

---

## Use Case 10: CIS Benchmark Compliance Scoring

**Scenario:** Organization wants to track compliance with CIS Benchmarks over time. Red team provides monthly security posture assessments.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery** (ongoing monitoring)

### Step-by-step walkthrough

**1. Run ScoutSuite monthly and save results with timestamp:**
```bash
for month in $(seq 1 12); do
  scout aws --report-dir ./cis-compliance/aws-$(date +%Y-%m)
  sleep 1  # Avoid throttling
done
```

**2. Parse compliance score from findings:**
```bash
for report in ./cis-compliance/*/scoutsuite-findings.json; do
  month=$(dirname "$report" | xargs basename)
  total=$(jq '.findings | length' "$report")
  critical=$(jq '.findings | map(select(.severity == "CRITICAL")) | length' "$report")
  high=$(jq '.findings | map(select(.severity == "HIGH")) | length' "$report")
  echo "$month: $total findings (CRITICAL: $critical, HIGH: $high)"
done
```

**Expected output:**
```
2026-01: 53 findings (CRITICAL: 3, HIGH: 12)
2026-02: 48 findings (CRITICAL: 2, HIGH: 11)
2026-03: 42 findings (CRITICAL: 1, HIGH: 8)
```

**3. Visualize compliance drift over time (for management reporting):**

This data feeds into compliance dashboards, executive summaries, and remediation tracking.

**Blue-team use:** Track progress toward compliance; identify remediation backlogs; prioritize security hardening efforts.

---

## Use Case 11: Continuous Compliance Monitoring (Scheduled)

**Scenario:** Red team wants to run ScoutSuite on a daily basis to detect configuration drift (misconfigurations that were hardened but regressed).

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery** (continuous)

### Step-by-step walkthrough

**1. Create a cron job to run ScoutSuite daily:**
```bash
# Add to crontab
0 2 * * * /usr/local/bin/scout aws --report-dir /var/scoutsuite/aws-$(date +\%Y-\%m-\%d)
```

**2. Compare today's findings to yesterday's (drift detection):**
```bash
#!/bin/bash
today=$(date +%Y-%m-%d)
yesterday=$(date -d "1 day ago" +%Y-%m-%d)

new_findings=$(diff <(jq '.findings | sort_by(.resource_id)' /var/scoutsuite/aws-$yesterday/scoutsuite-findings.json) \
                   <(jq '.findings | sort_by(.resource_id)' /var/scoutsuite/aws-$today/scoutsuite-findings.json) | \
  grep "^>" | wc -l)

echo "New findings in $today: $new_findings"
```

**3. Alert on regression (new critical/high findings):**
```bash
critical_today=$(jq '.findings | map(select(.severity == "CRITICAL")) | length' \
  /var/scoutsuite/aws-$today/scoutsuite-findings.json)
critical_yesterday=$(jq '.findings | map(select(.severity == "CRITICAL")) | length' \
  /var/scoutsuite/aws-$yesterday/scoutsuite-findings.json)

if [ $critical_today -gt $critical_yesterday ]; then
  # Send alert email / Slack message
  echo "ALERT: New critical findings detected"
fi
```

**Blue-team use:** Continuous monitoring detects configuration drift immediately; incident response can react before damage occurs.

---

## Use Case 12: Onboarding New Cloud Environment

**Scenario:** Organization provisions a new AWS account for a new business unit. Before workloads are deployed, red team runs ScoutSuite baseline to ensure the account is hardened to company standards.

**MITRE ATT&CK mapping:**
- **T1526.003 — Cloud Infrastructure Discovery** (initial assessment)

### Step-by-step walkthrough

**1. Create new AWS account and establish baseline:**
```bash
# Assume role in new account
aws sts assume-role --role-arn arn:aws:iam::NEW_ACCOUNT:role/ScoutSuiteAudit \
  --role-session-name scoutsuite-onboarding

# Temporarily set AWS credentials to new account

scout aws --report-dir ./new-account-baseline
```

**2. Compare to company security baseline (from golden-image account):**
```bash
diff <(jq '.findings | sort' ./baseline/scoutsuite-findings.json) \
     <(jq '.findings | sort' ./new-account-baseline/scoutsuite-findings.json) \
     > onboarding-gap-analysis.diff
```

**Expected findings:**
- **High:** No CloudTrail enabled (needs to be enabled immediately)
- **High:** No VPC Flow Logs
- **Medium:** Default VPC still exists (should be deleted)
- **Low:** S3 bucket versioning not enabled

**3. Document remediation items before production workloads are deployed:**

This ensures the account starts in a secure state, reducing the attack surface from day one.

