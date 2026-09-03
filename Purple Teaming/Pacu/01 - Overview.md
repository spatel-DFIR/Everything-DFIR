# Pacu — AWS Exploitation Framework

🔴 **Red Flag:** Pacu stores all AWS credentials (access key ID, secret access key, STS tokens) in plaintext within session files, which survive across shell sessions and are trivially recoverable from disk. Any attacker foothold enabling file-system access can extract full sets of credentials for immediate lateral movement to other AWS accounts or credential re-use attacks.

## History

**Pacu** is an open-source AWS exploitation framework created and maintained by Rhino Security Labs, first released in June 2018 (v0.1 / 2018-06-13). The framework was designed from the ground up as an offensive security testing tool for cloud environments — functionally analogous to Metasploit, but purpose-built for AWS attack surfaces instead of network services.

**Current Release:** v1.7.0 (March 2026). The project remains actively maintained with regular security and functionality updates. Licensed under BSD 3-Clause.

**Official Repository:** [`RhinoSecurityLabs/pacu`](https://github.com/RhinoSecurityLabs/pacu) (Python, 27,897 KB, 5,300+ stars)

**Current Language Support:** Python 3.7+ (confirmed via `pyproject.toml`)

## How It Works

Pacu is an **interactive exploitation framework** operating on a session-based architecture. An operator launches Pacu, creates a named session, imports AWS credentials, and then runs a series of modular attack workflows. The framework manages credential storage, regional scope, data enumeration, and attack execution — eliminating the need to manually call AWS APIs or manage boto3 credentials for each separate attack.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     Pacu Interactive CLI                │
│                   (pacu.main.Main class)                │
└────────────┬────────────────────────────────────────────┘
             │
             ├─ Session Management
             │  ├─ Create/Resume named session
             │  ├─ SQLite database (~/.pacu/sessions/<session>/)
             │  └─ Credential storage (plaintext)
             │
             ├─ Credential Input (set_keys command)
             │  ├─ Access Key ID + Secret Access Key
             │  ├─ Optional: STS session token
             │  └─ Optional: Import from AWS CLI default/profile
             │
             ├─ Boto3 Session Layer
             │  ├─ Transparently initialize boto3.Session
             │  ├─ Auto-detect default AWS credentials (env, ~/.aws/credentials)
             │  └─ Populate key fields on startup if not explicitly set
             │
             ├─ Regional Scope Management
             │  ├─ set-regions: define AWS regions for module execution
             │  └─ Module auto-filters to specified regions
             │
             ├─ Module Discovery & Execution (pacu/modules/)
             │  ├─ 76 available modules across ~30 AWS services
             │  ├─ Common syntax: <service>__<action> (e.g., ec2__enum)
             │  └─ Per-module option/argument parsing
             │
             ├─ Local Data Storage (SQLAlchemy + SQLite)
             │  ├─ Store enumerated results (hosts, services, credentials)
             │  ├─ Minimize API calls via caching
             │  ├─ Reduce CloudTrail audit footprint
             │  └─ Enable offline analysis / reporting
             │
             └─ Output & Reporting
                ├─ Interactive shell result display
                ├─ Export enumeration to CSV/JSON
                └─ Command logging per-session (all run() calls recorded)
```

### Credential Discovery & Storage

When Pacu starts, it attempts to auto-populate AWS credentials from three sources (in order):
1. **Environment variables** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. **AWS CLI default credential file** (`~/.aws/credentials`, default profile)
3. **Operator input** (interactive `set_keys` command, manually entered or pasted)

Once set, credentials are **stored in plaintext** in the session's SQLite database file at `~/.pacu/sessions/<session_name>/main.db`. The session file is readable by any process running under the same user context and survives across shell sessions, restarts, and container instance lifecycle events.

**Credential Access Methods:**
- **Access Key ID + Secret Access Key** (long-term, no expiration)
- **STS Session Token** (temporary, with expiration — but Pacu stores it as-is without tracking expiration time)
- **Assumed Role Credentials** (via `organizations__assume_role`, `iam__backdoor_assume_role` modules, stores in same plaintext session database)

### Module Discovery & Execution Model

Pacu's 76 modules are organized by AWS service and attack pattern:

| Service Family | Module Count | Key Modules |
|---|---|---|
| **IAM/Access** | 13 | `iam__enum_users`, `iam__privesc_scan`, `iam__backdoor_*` (assume-role, keys, password) |
| **EC2/Compute** | 6 | `ec2__enum`, `ec2__download_userdata`, `ec2__backdoor_ec2_sec_groups`, `ec2__startup_shell_script` |
| **S3/Storage** | 2 | `s3__download_bucket`, (enumeration integrated into general enum modules) |
| **Lambda/Serverless** | 5 | `lambda__enum`, `lambda__backdoor_new_*` (roles, security groups, users) |
| **RDS/Databases** | 3 | `rds__enum`, `rds__enum_snapshots`, `rds__explore_snapshots` |
| **EBS/Snapshots** | 5 | `ebs__enum_snapshots_unauth`, `ebs__download_snapshots`, `ebs__explore_snapshots` |
| **Networking** | 3 | `vpc__enum_lateral_movement`, `elb__enum_logging`, `route53__enum` |
| **Containers** | 5 | `ecs__enum`, `ecs__backdoor_task_def`, `eks__enum`, `eks__collect_tokens` |
| **Secrets/Config** | 4 | `secrets__enum`, `systemsmanager__download_parameters`, `cognito__enum`, `cognito__attack` |
| **Logging/Detection** | 4 | `cloudtrail__download_event_history`, `cloudtrail__csv_injection`, `cloudwatch__download_logs`, `detection__*` |
| **Other** | 26 | CloudFormation, CodeBuild, Elastic Beanstalk, MQ, Organizations, Transfer Family, WAF, Lightsail, etc. |

**Module Execution Flow:**
```
list
  ├─ Display available modules for current regions
  │
help <module_name>
  ├─ Display module parameters and required permissions
  │
run <module_name> [--regions r1,r2] [--<arg> <value>]
  ├─ Execute module with optional regional/argument overrides
  ├─ Module queries AWS API via boto3
  ├─ Results stored in SQLite database
  └─ Results displayed to console
```

Each module declares its AWS service dependencies and required IAM permissions. The framework does NOT validate permissions before execution — modules will fail gracefully if credentials lack required permissions.

### Session File Structure

```
~/.pacu/
├── sessions/
│   └── <session_name>/
│       ├── main.db                    # SQLite database (contains creds + enumeration data)
│       ├── logs/
│       │   ├── module_output.log      # All module execution output
│       │   ├── errors.log              # Module errors
│       │   └── command_log.txt         # All commands run (command history)
│       └── exported_data/              # CSV/JSON exports (on-demand via export command)
│
└── errors.log                           # Global error log (out-of-session errors)
```

The **`main.db`** file is the critical artifact — it contains AWS credentials in plaintext (readable via `sqlite3` CLI or any SQL tool) plus a complete enumeration history of everything the framework discovered.

---

## Techniques & Protocols

| Protocol / Layer | How Pacu Uses It | Notes |
|---|---|---|
| **AWS Signature v4** | Boto3 handles transparently; Pacu supplies credentials | All calls signed with provided access key + secret key |
| **HTTPS** | Boto3 default; all communication to AWS API endpoints | Standard AWS API transport layer |
| **STS (Security Token Service)** | Assumed-role credential retrieval, session-token usage | Modules like `organizations__assume_role` explicitly call STS `AssumeRole` |
| **IAM API** | Direct enumeration of users, roles, policies, permissions | Bulk of Pacu's reconnaissance is IAM-focused |
| **EC2 Instance Metadata Service** | `ec2__download_userdata` + lambda backdooring uses metadata endpoint | IMDSv1 (unsecured) vs. IMDSv2 (token-required) distinction |
| **S3** | Direct S3 API calls for bucket enumeration and object download | `s3__download_bucket` fully downloads accessible buckets |
| **Secrets Manager / Parameter Store** | `secrets__enum` enumerates and retrieves stored secrets | Retrieved secrets stored in session database |
| **Lambda** | API calls to enumerate functions, update environment variables, add layers | Backdooring adds malicious IAM role/security group to new Lambda functions |
| **CloudFormation** | `cfn__resource_injection` edits CloudFormation stacks to inject resources | New compute resources (EC2, Lambda) inserted into existing stacks |
| **CloudTrail / CloudWatch** | Direct API access to query/download logs | `cloudtrail__csv_injection` exploits CSV parsers in log exports |
| **Organizations** | `organizations__assume_role` cross-account role assumption | Chains into compromised cross-account IAM roles |

---

## Command-Line Switches — Quick Reference

### Interactive Commands (Within Pacu Shell)

| Command | Arguments | Blue-Team Plain English | Evasion Notes |
|---|---|---|---|
| `help` | `[module_name]` | List all available commands OR display help for a specific module. | None — pure information gathering. |
| `list` | `[service_filter]` | Display all modules available for the current region set. | Shows operator what exploits are available; no API calls yet. |
| `run` | `<module_name> [--regions r1,r2] [--<arg> <value>]` | Execute a specific module with optional region override and module-specific arguments. | Actual exploitation happens here; triggers CloudTrail, GuardDuty, anomaly detection. |
| `set_keys` | None | Prompt for AWS access key ID, secret access key, and optional STS session token. | Credentials stored in plaintext in session database. |
| `set_regions` | `<region1 region2 ... \| all>` | Set which AWS regions this session will scan. Overrides per-module `--regions` if not specified. | Limits module execution scope; no security benefit. |
| `export_data` | `[service_name \| all] [csv\|json]` | Export enumerated data from the session database to CSV or JSON files. | Export is local-only; does not leak data to AWS. |
| `import_keys` | None (prompts) | Load AWS credentials from `~/.aws/credentials` (AWS CLI default) or environment. | Alternative to manual `set_keys`; leverages existing AWS CLI setup. |
| `database` | `<service_name \| all>` | Query the local SQLite database to view previously enumerated data without re-running modules. | Database queries are entirely local; no new AWS API traffic. |
| `exit` / `quit` | None | Exit the Pacu shell. Session data persists on disk. | Clean exit; session is preserved for later resumption. |

### CLI (Direct Command-Line Execution)

Pacu can also be run non-interactively via command-line arguments:

| Flag | Example | Blue-Team Plain English |
|---|---|---|
| `--session <session_name>` | `pacu --session prod-test` | Specify which session to load/use for the following command. |
| `--list-modules` | `pacu --list-modules` | Show all 76 available modules (doesn't require a session or credentials). |
| `--module-name <name>` | `pacu --module-name iam__enum_users` | Specify a module to operate on. |
| `--exec` | `pacu --session prod --module-name iam__enum_users --exec` | Execute the specified module non-interactively. |
| `--module-info` | `pacu --module-name iam__enum_users --module-info` | Display help/parameters for a module without executing. |
| `--module-args "<arg1> <val> <arg2> <val>"` | `pacu --module-args "account_id 123456789012"` | Pass module-specific arguments via command line. |
| `--set-regions <region_list>` | `pacu --set-regions us-east-1 eu-west-1` | Set active regions for this execution. |
| `--data <service \| all>` | `pacu --data EC2` | Query local database without opening interactive shell. |
| `--whoami` | `pacu --whoami` | Display current AWS account ID and identity for the active session/credentials. |
| `--pacu-help` | `pacu --pacu-help` | Display main Pacu help (doesn't require session). |
| `--help` | `pacu --help` | Display system help for the Pacu CLI itself. |
| `--version` | `pacu --version` | Display Pacu version (fixed in v1.7.0 to return actual version, not "unknown"). |

### Module-Specific Flags (Examples)

Most modules accept `--regions` to override the session-level region setting. Selected modules expose additional options:

| Module | Flags | Example |
|---|---|---|
| `iam__enum_permissions` | `--account-id <id>` | Discover which IAM actions the current credential can execute. |
| `s3__download_bucket` | `--bucket-name <name>` | Download all objects from a specific S3 bucket (if readable). |
| `ec2__download_userdata` | `--instance-id <id>` | Retrieve EC2 user-data from a specific instance. |
| `lambda__backdoor_new_roles` | `--username <name>` | Create a new Lambda function with a backdoored IAM role. |
| `organizations__assume_role` | `--role-name <name> --account <id>` | Assume a cross-account IAM role. |
| `secrets__enum` | None | Enumerate Secrets Manager + Parameter Store (returns names + values if readable). |
| `cloudtrail__csv_injection` | `--bucket <name>` | Download CloudTrail logs and inject CSV formulas to exploit log-reader parsers. |
| `detection__enum_services` | None | Probe GuardDuty, SecurityHub, Macie, etc. to discover what detections are enabled. |

---

## Quick Use-Case List

1. **Initial AWS Account Enumeration** — Post-compromise, discover what services exist, what buckets/databases/functions are available.
2. **IAM Privilege-Escalation Scanning** — Identify users/roles that can assume more-privileged roles, edit policies, or access unintended resources.
3. **S3 Bucket Discovery & Exfiltration** — Enumerate accessible S3 buckets and download sensitive files in bulk.
4. **EC2 Metadata & User-Data Harvesting** — Retrieve user-data scripts (often containing credentials, API keys, deployment secrets).
5. **Lambda Environment-Variable Extraction** — Access Lambda environment variables (source of database credentials, third-party API keys, secrets).
6. **RDS/Database Snapshot Exfiltration** — Enumerate and download RDS snapshots to offline-attack database credentials/data.
7. **EBS Snapshot Theft** — Enumerate unprotected EBS snapshots and download them for offline analysis.
8. **Secrets Manager / Parameter Store Enumeration** — Discover and retrieve stored secrets (database passwords, API keys, tokens).
9. **Cross-Account Role Assumption** — Use discovered IAM roles to pivot into other AWS accounts within the same organization.
10. **CloudFormation Stack Injection** — Inject malicious compute resources (EC2, Lambda, containers) into existing CloudFormation stacks to establish persistence or escalate access.
11. **IAM Credential Backdooring** — Create new IAM users, attach permissive policies, or add access keys to existing users for persistent access.
12. **Lambda Backdooring** — Create new Lambda functions with malicious code and attach them to existing VPC/security groups for code execution.
13. **ECS Task Definition Backdooring** — Modify ECS task definitions to inject malicious container images or add persistence mechanisms.
14. **CloudTrail Log Deletion / Manipulation** — Delete or inject CSV-formula payloads into CloudTrail logs to evade detection.
15. **GuardDuty / SecurityHub Suppression** — Enumerate and suppress GuardDuty findings to disable active detection/alerting.

---

## Prerequisites

| Use Case | Required AWS Credential Type | Minimum IAM Permissions | Notes |
|---|---|---|---|
| **General Enumeration** | Access Key ID + Secret Access Key (long-term) | `iam:GetUser`, `iam:ListUsers`, `ec2:DescribeInstances`, etc. | Read-only; attacker often compromises a developer/service account with broad permissions. |
| **STS Token Usage** | Session token (`AWS_SESSION_TOKEN`) | Inherited from assumed role; varies per use case | Token expires after N hours; Pacu stores but doesn't auto-refresh. |
| **S3 Bucket Download** | Long-term access key or session token | `s3:GetObject`, `s3:ListBucket` | Requires bucket + object-level permissions. |
| **Secrets Retrieval** | Long-term key or session token | `secretsmanager:GetSecretValue` + `ssm:GetParameter(s)` | Often restricted to specific secret ARNs; unrestricted access is a privilege-escalation path. |
| **IAM Backdooring** | Long-term key | `iam:CreateUser`, `iam:PutUserPolicy`, `iam:CreateAccessKey` | Equivalent to Domain Admin in AWS; enables persistent access. |
| **Lambda/ECS Backdooring** | Long-term key | `lambda:CreateFunction`, `iam:CreateRole`, `ec2:DescribeSecurityGroups`, `ecs:UpdateTaskDefinition` | Requires cross-service permissions; creates suspicious new resources. |
| **Cross-Account Assumption** | Long-term key | Trust relationship in target account's role + `sts:AssumeRole` permission | Requires prior reconnaissance (e.g., via Organizations API) to discover target account ID. |
| **CloudFormation Injection** | Long-term key | `cloudformation:UpdateStack`, `iam:CreateRole`, `ec2:RunInstances` | Must already have permissions to modify stacks; injects new compute resources. |
| **CloudTrail Manipulation** | Long-term key | `cloudtrail:DeleteTrail`, `s3:DeleteObject` (for log bucket) | Destructive; triggers GuardDuty `UnauthorizedAPI_PrincipalCloudTrailEventSelector` alert if enabled. |

---

## 🔗 Cross-References

- **Cloud/Amazon/AWS/** — Pacu operates entirely within AWS; reference the Cloud module for service fundamentals (IAM, EC2, S3, Lambda, RDS), CloudTrail audit logging, and GuardDuty/SecurityHub detection.
- **Cloud/Amazon/AWS/01 - IAM & Identities.md** — Pacu's privilege-escalation scanning directly maps to IAM policy evaluation; cross-referenced for permission model details.
- **Cloud/Amazon/AWS/Logging & Monitoring/** — CloudTrail, CloudWatch, GuardDuty source of detection signals; Pacu's modules trigger logging that detection systems query.
- **SEC588/Cloud Penetration Testing** (SANS syllabus) — Pacu aligns with SEC588 post-compromise AWS exploitation module topics.

---

