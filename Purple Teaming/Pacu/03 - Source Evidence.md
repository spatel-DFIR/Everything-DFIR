# Pacu — Source Evidence

**Scope:** This page documents artifacts left on the **attacker's/operator's machine** (not the target AWS account). Source evidence includes Pacu's own session files, process artifacts, credential storage, shell history, and network-layer traces of AWS API communication.

---

## Pacu Session Files (Critical)

**Location:** `~/.pacu/sessions/<session_name>/`

Every Pacu session is stored on-disk in a dedicated directory structure:

```
~/.pacu/
├── sessions/
│   ├── prod-aws/
│   │   ├── main.db                          ← CRITICAL: SQLite database (credentials + enumeration data)
│   │   ├── logs/
│   │   │   ├── module_output.log            ← All module output (enumeration results)
│   │   │   ├── errors.log                   ← Module execution errors
│   │   │   └── command_log.txt              ← Command history (all `run` commands with args)
│   │   └── exported_data/
│   │       ├── IAM.csv
│   │       ├── EC2.csv
│   │       └── S3.csv
│   ├── staging-aws/
│   └── dev-aws/
│
└── errors.log                               ← Global error log (shared across sessions)
```

### main.db — The Critical Artifact

The `main.db` SQLite database is the **single most damaging artifact** — it contains:

1. **AWS Credentials (Plaintext)**
   - Access Key ID
   - Secret Access Key
   - STS session tokens (if used)
   - All key aliases and associated credentials
   - Plaintext readable via `sqlite3 main.db` CLI or any SQL tool

2. **Complete Enumeration History**
   - All discovered IAM users, roles, policies
   - All EC2 instances, security groups, VPC configs
   - All S3 bucket names, EBS snapshots, RDS snapshots
   - All Lambda functions, ECS tasks, Secrets Manager entries
   - Database connection strings, API endpoints, passwords extracted from user-data/environment variables
   - Every secret retrieved from Secrets Manager / Parameter Store

3. **Forensic Timeline**
   - Timestamps for every module execution
   - When credentials were added to the session
   - Regional scope changes, module parameters used

**Threat:** If an analyst acquires an attacker's `main.db` file (e.g., from a forensic image of the attacker's machine), they can:
- Extract AWS credentials immediately and assume the attacker's identity
- Replay the attacker's exact workflow (modules run, what was discovered, what was exfiltrated)
- Pivot to any AWS account the attacker reached
- Access all secrets/credentials the attacker retrieved

**Indicator:** SQLite database file with specific table structure:

```sql
-- Query to verify this is a Pacu session database
sqlite3 ~/.pacu/sessions/prod-aws/main.db

-- List tables
.tables
-- Expected output: aws_accounts, credentials, iam_roles, iam_users, 
--                  ec2_instances, s3_buckets, lambda_functions, etc.

-- Extract credentials
SELECT * FROM credentials;
-- Output: key_alias, access_key, secret_key, session_token, account_id, ...
```

---

## Process Execution & Command-Line Evidence

### Pacu Startup & Interactive Shell

When Pacu is launched interactively, the process tree is:

```
bash (or zsh, sh)
  └─ python (or python3)
       └─ pacu
            └─ cli.py (main entry point)
            └─ Main() class (interactive shell)
```

**Process Command Line:**
```
python3 -m pacu --session prod-aws
```

Or via pipx:
```
~/.local/venvs/pacu/bin/pacu --session prod-aws
```

**Observable:**
- Process name: `pacu` or `python` (depending on launch method)
- Parent: shell (bash, zsh, PowerShell on Windows if running WSL/Cygwin)
- Arguments: session name (if passed via CLI)
- Working directory: Usually user's home or current directory (no constraint)

### Module Execution via CLI

When modules are run non-interactively:
```bash
pacu --session prod-aws --module-name iam__enum_users --exec
```

This spawns:
```
pacu --session prod-aws --module-name iam__enum_users --exec
  └─ python (subprocess, module loader)
       └─ iam__enum_users.py (actual module code)
            └─ boto3.client('iam')  (AWS API calls)
```

**Observable:** CLI arguments include the module name and session; module name is also visible as an argument or subprocess name.

---

## Shell History & Command Artifacts

### Interactive Shell History

If Pacu is run from an interactive terminal, commands are logged to shell history:

**Bash/Zsh (`~/.bash_history` or `~/.zsh_history`):**
```bash
pacu
# Inside Pacu shell:
set_keys
set_regions all
run iam__enum_users
run s3__download_bucket --bucket-name acme-prod-backups
export_data S3 csv
run lambda__backdoor_new_users
exit
```

Or if run via CLI:
```bash
pacu --session prod-aws --list-modules
pacu --session prod-aws --module-name iam__enum_users --exec
pacu --session prod-aws --module-name ec2__download_userdata --exec
```

**Observable:** Command history reveals:
- Pacu was run
- Which AWS services were enumerated
- Which backdoor modules were executed
- Session names (account identifiers)

### Clearing History

An aware attacker will clear shell history:
```bash
history -c                  # Clear current session
rm ~/.bash_history
rm ~/.zsh_history
unset HISTFILE              # Disable logging for new commands
```

**Indicator:** If shell history is missing or truncated while other .bash/zsh files exist, it's suspicious.

---

## Pacu Logging Output

### Module Output Log (`logs/module_output.log`)

Every module execution writes output to the session's log file:

```
[*] Running iam__enum_users...
[+] Found 42 IAM users
[*] Downloading user policies...
[+] User: ci-deploy, Policy: AmazonEC2FullAccess
[+] User: lambda-service, Policy: custom-lambda-policy
...
[*] Module completed, results stored in database
```

**Location:** `~/.pacu/sessions/<session_name>/logs/module_output.log`

**Observable:** Complete log of module executions and discovered resources.

### Error Log (`logs/errors.log`)

Failed module runs are logged:

```
2026-08-11 14:32:15 - ERROR - iam__enum_permissions: Access Denied for action ec2:ModifyImageAttribute
2026-08-11 14:33:02 - ERROR - lambda__backdoor_new_users: Unable to create role (insufficient permissions)
```

**Observable:** Which attacks failed (often due to missing IAM permissions).

### Command History Log (`logs/command_log.txt`)

Every interactive command is logged:

```
2026-08-11 14:30:00 - set_keys (key_alias: compromised-dev)
2026-08-11 14:30:15 - set_regions (regions: all)
2026-08-11 14:31:00 - run iam__enum_users
2026-08-11 14:32:00 - run ec2__enum
2026-08-11 14:33:00 - run s3__download_bucket --bucket-name acme-prod-backups
2026-08-11 14:34:00 - export_data S3 csv
```

**Observable:** Exact timeline of attacker's reconnaissance and exploitation steps.

---

## AWS Credentials in Memory & Environment

### Process Memory

While Pacu is running, AWS credentials are held in memory:

- **Python process memory** (`/proc/<pid>/maps` on Linux, or via memory dump tools like `volatility`, `WinDbg` on Windows)
- **Boto3 session object** stores credentials
- **Command-line arguments** if credentials were passed via CLI

**Memory Forensics Indicators:**
- Access Key ID (AKIA... pattern, 20 characters)
- Secret Access Key (40 characters, mixed alphanumeric)
- Session tokens (AQoD... pattern, variable length)

### Environment Variables

If credentials were set via environment:

```bash
echo $AWS_ACCESS_KEY_ID
# Output: AKIA...[REDACTED]

echo $AWS_SECRET_ACCESS_KEY
# Output: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

echo $AWS_SESSION_TOKEN
# Output: AQoDYXdzEJr...
```

**Observable:** `env` output or `/proc/<pid>/environ` on Linux.

---

## Network Evidence — AWS API Calls

### HTTPS Connections to AWS API Endpoints

Pacu uses boto3, which makes HTTPS calls to AWS API endpoints:

```
Source: attacker's machine (e.g., 192.168.1.100)
Destination: api.us-east-1.amazonaws.com, iam.amazonaws.com, s3.amazonaws.com, etc.
Port: 443 (HTTPS)
```

### Observable Network Artifacts

**Packet Capture (tcpdump, Wireshark):**
```
TLS handshake to *.amazonaws.com
  ├─ SNI: iam.amazonaws.com
  ├─ Certificate: AWS Certificate issued to *.amazonaws.com
  └─ Cipher: TLS 1.2/1.3

TLS encrypted data
  (AWS API request body is encrypted, not visible in plaintext)
```

**No plaintext credentials are sent over the wire** — all AWS API communication is signed with the access key and encrypted via TLS. The signature itself does not leak the secret key (it's a one-way hash).

### AWS API Call Patterns

Pacu's network behavior is distinctive:

1. **High-volume API calls to multiple services in rapid succession**
   - 50-500 API calls within a few minutes (depending on module)
   - Calls to iam.amazonaws.com, ec2.amazonaws.com, s3.amazonaws.com in a burst

2. **Enumeration patterns** (CloudTrail will show this):
   - `ListUsers`, `GetUser` (repeated for each user)
   - `ListRoles`, `GetRole` (repeated for each role)
   - `ListInstances`, `DescribeInstances` (repeated for each instance)

3. **Suspicious action sequences**:
   - `DescribeInstances` → `GetUserData` (extracting secrets)
   - `ListBuckets` → `ListObjects` → `GetObject` (bucket exfiltration)
   - `CreateAccessKey` → `PutUserPolicy` (IAM backdooring)

**Observable:** Network-level detection focuses on:
- High-frequency API calls from a single source IP
- Calls to services the attacker's role shouldn't need
- `CreateUser`, `CreateRole`, `CreateAccessKey` actions followed by policy modifications (persistence)

---

## Downloaded Data & Temporary Files

### S3 Bucket Downloads

When `s3__download_bucket` runs, files are saved locally:

```
~/.pacu/sessions/prod-aws/s3_downloads/
├── acme-prod-backups/
│   ├── backups/2026-08-10/database.sql.bz2 (5.2 GB)
│   ├── backups/2026-08-10/redis-dump.rdb (2.1 GB)
│   └── backups/2026-08-09/... (previous backups)
└── terraform-state/
    ├── main.tfstate (contains AWS resource definitions + secrets)
    └── terraform.tfvars (API keys, database passwords)
```

**Observable:** Large directories with S3-like structure, containing business data, databases, configuration files.

### Temporary Files

Pacu may create temporary files during module execution:

```
/tmp/pacu_*.tmp
/tmp/aws_snapshot_*.img
/tmp/exported_data_*.json
```

**Observable:** Temporary files with `pacu` in the name, or large unencrypted data files in `/tmp`.

---

## Credential Reuse & Cross-Account Access

### Session Chaining

If an attacker uses Pacu to assume a cross-account role, they create a new session with the assumed role's credentials:

```
pacu (prod-aws) > run organizations__assume_role --role-name CrossAccountOrgRole --account 123456789999
[+] New credentials generated (STS temporary credentials)

pacu (staging-aws) > run iam__enum_users
(Now running against a different AWS account with assumed-role credentials)
```

**Observable:**
- Multiple Pacu sessions created (`prod-aws`, `staging-aws`, etc.)
- Each session's `main.db` contains different AWS credentials
- Session metadata (timestamps) shows progression from one account to the next

### Credential Pivoting (Lateral Movement)

Credentials extracted via Pacu (e.g., from environment variables, Secrets Manager) are often re-used in other tools:

```bash
# Attacker extracts credentials from Lambda environment
export AWS_ACCESS_KEY_ID=AKIA... (from Pacu)
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# Then uses CLI tools
aws s3 ls
aws ec2 describe-instances
# Or: ScoutSuite, Prowler, other cloud-recon tools
```

**Observable:** Same credentials appear in multiple tool execution contexts.

---

## Timeline Reconstruction

**Evidence Chain for Timeline:**

1. **Session creation** (`~/.pacu/sessions/<session_name>/` directory ctime)
2. **Credential import** (first `set_keys` command in command_log.txt)
3. **Enumeration phase** (module_output.log shows `enum_*` modules first)
4. **Exploitation phase** (backdoor modules like `*__backdoor_*`, `*__create_*` appear next)
5. **Persistence phase** (IAM backdoor, Lambda backdoor, CloudFormation injection)
6. **Data exfiltration** (s3__download_bucket, ebs__download_snapshots, etc.)
7. **Cover-up** (cloudtrail__download_event_history, cloudtrail__csv_injection, guardduty__whitelist_ip)

**Example Timeline:**
```
2026-08-11 14:30:00  Session created: prod-aws
2026-08-11 14:30:15  Credentials set (access_key: AKIA...)
2026-08-11 14:31:00  iam__enum_users (discovery)
2026-08-11 14:32:00  ec2__enum (discovery)
2026-08-11 14:33:00  iam__privesc_scan (privilege assessment)
2026-08-11 14:34:00  s3__download_bucket (data exfiltration) ← 18.5 GB downloaded
2026-08-11 14:45:00  iam__backdoor_users_keys (persistence) ← new access key created
2026-08-11 14:50:00  cloudtrail__csv_injection (cover-up) ← logs corrupted
2026-08-11 14:52:00  guardduty__whitelist_ip (detection evasion) ← attacker IP whitelisted
2026-08-11 14:55:00  Session terminated
```

---

## 🔗 Cross-References

- **Windows/05 - Users, Groups & Authentication.md** — AWS credential formats (AKIA prefix, Base64 encoding).
- **Linux/06 - Logs/Bash & Shell History.md** — Shell history forensics, clearing techniques.
- **Cloud/Amazon/AWS/02 - Investigating AWS.md** — CloudTrail audit logs (these capture every API call Pacu makes).
- **Cloud/Amazon/AWS/Logging & Monitoring/CloudTrail.md** — Detailed CloudTrail event structure and targeted event IDs for Pacu exploitation.

---

