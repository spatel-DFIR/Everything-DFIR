# ScoutSuite — Overview

> 🔴 **Red Flag Principle:** ScoutSuite's defining strength is **API-based configuration discovery without exploitation**. Every finding is the result of **read-only API calls to enumerate cloud resources and their configurations** — no payload injection, no credential stuffing, no account takeover attempts. The tool compares discovered configurations against a **ruleset of security best practices** (CIS Benchmarks, custom policy rules) and reports **misconfigurations and policy violations as a structured HTML report with JSON findings**. The reconnaissance and audit footprint is **read-only API calls from a single attacker source IP** (no network scanning, no lateral movement via the tool itself, no persistence mechanisms). The output artifacts — **HTML reports, JSON findings, and the ScoutSuite database** — are the highest-fidelity indicators of the tool's use; cloud provider audit logs will show a burst of **configuration-reading API calls** from a single identity in a compressed time window (minutes to hours, depending on cloud size and rule count).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line / Usage Quick Reference](#command-line--usage-quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`nccgroup/ScoutSuite`](https://github.com/nccgroup/ScoutSuite), its README.md, wiki documentation, and published source code:

- **Author:** **NCC Group** — a multinational cybersecurity consulting firm with OSINT and offensive security expertise. The repository was **created in 2015** (11+ years old at this writing, August 2026), making it one of the longest-running cloud security auditing tools in the red-team ecosystem.
- **License:** GNU General Public License v2.0 (GPL-2.0) — verified via the GitHub repository's LICENSE file.
- **Distribution:** ScoutSuite ships as **pure Python source code** — no pre-compiled binaries in the repository itself. Operators install via **PyPI (`pip install scoutsuite`)** or **clone the repository** and run `pip install -r requirements.txt`. Installation creates an isolated environment with **boto3 (AWS SDK), azure-cli-core (Azure authentication), google-cloud-* (GCP SDK)** and supporting libraries. **PyPI is the recommended distribution path**; installation is straightforward and dependency-managed.
- **Current version:** The repository's master branch is actively maintained. No formal semantic versioning; releases tracked via commit tags and `CHANGELOG.md`.
- **Python versions supported:** Python 3.9, 3.10, and 3.11 — verified against official setup documentation and requirements.txt.
- **Purpose, in NCC Group's own words** (from README): *"ScoutSuite is an open source multi-cloud security-auditing tool which enables security posture assessment of cloud environments."* The tool's core value is **speed and comprehensiveness** — scanning all resources across AWS, Azure, or GCP in a single run, checking each resource against hundreds of security rules (CIS Benchmarks, custom policies), and generating a beautiful, searchable HTML report with findings. Unlike manual assessment or point-in-time compliance audits, ScoutSuite provides **repeatable, automated cloud security posture evaluation** across large, complex cloud environments.
- **Maintained actively.** NCC Group continues to update ScoutSuite with new cloud provider support, new rules, and dependency updates. This is a production-grade tool, not a research prototype.
- **GitHub stars:** 3,800+ stars (as of August 2026) — evidence of adoption in both red-team and blue-team communities (penetration testing, cloud security assessments, compliance auditing).
- **MITRE ATT&CK mapping:** ScoutSuite does not have a dedicated Software entry, but its **techniques** map directly to **T1526 (Gather System Network Configuration Information)** — specifically **T1526.003 (Cloud Infrastructure Discovery)** and **T1538 (Cloud Service Discovery)**. The findings it generates can inform **T1652 (Gather Victim Cloud Infrastructure Information)** for external cloud assessments.
- **Distinguishing characteristic vs. Pacu (Wave 4 #13):** ScoutSuite is **configuration auditing** (read-only, best-practices checking); Pacu is **exploitation and privilege escalation** (write operations, credential abuse). ScoutSuite finds the gaps; Pacu exploits them.

## How It Works

ScoutSuite is a **Python orchestration tool** built around **five core subsystems**, each handling a distinct phase of multi-cloud security assessment:

```
Authentication     Resource enumeration   Configuration   Rule evaluation    Report generation
──────────────     ────────────────────   ─────────────   ───────────────    ─────────────────
1. Cloud CLI       2. API calls           3. JSON/dict    4. Custom          5. HTML + JSON
   (AWS/Azure/        per cloud           structure       rulesets           findings report
   GCP) or service    provider            of all          (CIS, custom)
   principal          (DescribeInstances, resources
                      GetPolicies, etc.)
```

### Authentication layer

ScoutSuite leverages the cloud provider's native CLI or SDK for credentials:

**AWS:**
- Default: Uses existing AWS CLI configuration (IAM access key in `~/.aws/credentials` or EC2 instance role)
- Command: `scout aws` (or `python scout.py aws`)
- Flag for specific profile: `--profile <name>`

**Azure:**
- Six authentication methods:
  - **Azure CLI:** `--cli` flag; expects `az login` to have already been executed
  - **User account interactive:** `--user-account` flag; prompts for credentials
  - **User account browser (MFA):** `--user-account-browser` flag; opens browser for MFA login
  - **Service Principal:** `--service-principal` flag; requires client ID, tenant ID, secret
  - **File-based:** `--file-auth` flag; reads credentials from a JSON file (generated via `az ad sp create-for-rbac --sdk-auth`)
  - **Managed Service Identity (MSI):** `--msi` flag; uses managed identity from within Azure VM or app
- Subscription selection: `--subscriptions <names>` for specific subscriptions; `--all-subscriptions` to scan all accessible subscriptions
- Required permissions: **Reader** and **Security Reader** roles; additional API permissions for v6+ (Directory.Read.All, Policy.Read.All)

**Google Cloud Platform:**
- Default: Uses existing GCP CLI configuration (via `gcloud auth login`)
- Command: `scout gcp --user-account`
- Project selection: `--projects <project-ids>` to specify which GCP projects to audit; default scans the current project

**Authentication principle:** ScoutSuite does not store credentials itself. It relies on pre-configured CLI authentication, service principals, or environment variables — a design choice that reduces credential exposure on the attacker's machine but requires the CLI to be pre-configured.

### Resource enumeration layer

Once authenticated, ScoutSuite calls **cloud provider APIs** to fetch configuration data. For each service (EC2, S3, IAM, security groups, firewalls, storage accounts, etc.), it:

1. **Enumerates all resources** — calls APIs like:
   - AWS: `describe_instances()`, `describe_buckets()`, `get_user_policy()`, `describe_security_groups()`
   - Azure: `list_virtual_machines()`, `list_storage_accounts()`, `get_authorization_rules()`, `list_diagnostics_settings()`
   - GCP: `list_instances()`, `list_buckets()`, `get_iam_policy()`, `list_firewall_rules()`

2. **Fetches detailed configuration** — reads each resource's properties:
   - Security group rules (inbound/outbound CIDR blocks, protocols)
   - IAM policies (who has what permissions)
   - Storage bucket/blob container access control lists (public vs. private)
   - Encryption settings (at-rest encryption, key management)
   - Logging and monitoring configuration

3. **Stores results in a structured format** — Python dictionary, later serialized to JSON:
   ```json
   {
     "aws": {
       "regions": {
         "us-east-1": {
           "ec2": [
             {
               "id": "i-1234567890abcdef0",
               "type": "t2.micro",
               "vpc": "vpc-12345678",
               "security_groups": [{"id": "sg-123456", "name": "allow-web"}],
               "public_ip": "203.0.113.5"
             }
           ],
           "s3": [
             {
               "name": "my-app-backups-prod",
               "region": "us-east-1",
               "acl": "public-read",
               "logging_enabled": false
             }
           ]
         }
       }
     }
   }
   ```

**Key characteristic:** All API calls are **read-only** — they fetch configuration state but do not modify, delete, or create any resources. The attacker identity needs only **read permissions** on cloud resources, not admin or write privileges.

### Rule evaluation layer

ScoutSuite maintains a **ruleset database** — hundreds of security best-practice checks:

**Rule structure:**
```
Rule ID: "s3-bucket-public-read"
Condition: If S3 bucket ACL == "public-read" OR bucket policy allows GetObject for "*"
Severity: HIGH
Description: "S3 bucket is publicly readable; sensitive data exposure risk"
Remediation: "Set ACL to private; restrict bucket policy"
```

**Rulesets supported:**
- **CIS Benchmarks** — AWS Foundations Benchmark, Azure Foundations Benchmark, GCP Foundations Benchmark (specific versions)
- **Custom rulesets** — operators can define their own rules in YAML format and apply them
- **Default recommendations** — NCC Group's own best practices

**Rule evaluation process:**
1. For each resource in the enumerated data, ScoutSuite checks all applicable rules
2. Rules are written in Python (or YAML for custom rules) and evaluated against the resource configuration
3. If a rule condition is met, a **finding** is generated with:
   - Rule ID and name
   - Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
   - Description
   - Affected resource(s)
   - Remediation steps

**Example rule evaluation:**
```
For each S3 bucket:
  If bucket_acl == "public-read" OR "public-read-write":
    Generate finding "S3 Bucket Public Read"
    Severity: HIGH
    Details: bucket_name, current_acl, recommended_acl
```

### Report generation layer

ScoutSuite generates **two output formats**:

**1. HTML Report (Interactive Web Dashboard)**
- Filename: `scoutsuite-report.html` (or custom via `--report-dir`)
- Self-contained: All CSS, JavaScript, data embedded; no external dependencies
- Structure:
  - **Dashboard tab:** Summary of findings by severity (pie chart of CRITICAL/HIGH/MEDIUM/LOW/INFO findings)
  - **Findings list:** Searchable, sortable table of all violations with:
    - Rule name and ID
    - Severity level
    - Affected resource(s)
    - Description
    - Remediation steps
  - **Services tab:** Per-cloud-service breakdown (EC2, S3, IAM, etc.) with findings per service
  - **Configuration tab:** Raw enumerated configuration data (searchable)
  - **Navigation:** Cloud provider selector (AWS/Azure/GCP) at the top; findings filtered by severity and service

**2. JSON Findings File (Programmatic Access)**
- Filename: `scoutsuite-findings.json` (or custom)
- Schema: Machine-readable findings array:
  ```json
  {
    "cloud": "aws",
    "findings": [
      {
        "rule_id": "s3-bucket-public-read",
        "rule_name": "S3 Bucket Public Read",
        "severity": "HIGH",
        "resource_id": "my-app-backups-prod",
        "resource_type": "s3_bucket",
        "description": "S3 bucket is publicly readable",
        "remediation": "Set ACL to private",
        "service": "s3"
      }
    ]
  }
  ```
- Use case: Parsing and feeding findings into downstream tools (SIEM ingestion, ticketing systems, automated remediation)

**Database (Optional):**
- ScoutSuite can store enumerated data and findings in a local database (SQLite or cloud database) for historical tracking and trend analysis

---

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **Cloud APIs** | AWS API (boto3 SDK), Azure Resource Manager API (Azure SDK), Google Cloud API (google-cloud SDK) — all using HTTPS (TCP 443) with OAuth2/mutual TLS authentication |
| **Authentication protocols** | OAuth2 (Azure/GCP), IAM access keys (AWS), service principals (Azure), managed identities (Azure) |
| **Data format (input)** | None required; ScoutSuite fetches data directly from cloud APIs |
| **Data format (output)** | JSON (findings), HTML (interactive report), optional SQLite database |
| **Rule definition** | Python code (built-in rules) or YAML (custom rules) |
| **Encryption in transit** | TLS 1.2+ (all cloud provider APIs use HTTPS) |
| **Encryption at rest** | N/A — ScoutSuite itself does not store secrets; credentials come from pre-configured CLI or environment variables |
| **Concurrency** | Multi-threaded enumeration; can be configured to throttle API calls to avoid rate-limiting |
| **Error handling** | Graceful handling of insufficient permissions (reports findings only for resources accessible to the authenticated identity) |

---

## Command-Line / Usage Quick Reference

Verified against the official ScoutSuite source code (`scout.py` and CLI argument parser) and wiki documentation:

### Global options

| Flag | Argument | Purpose |
|---|---|---|
| `--profile` | `<name>` | AWS profile to use (if multiple AWS credentials configured) |
| `--report-dir` | `<directory>` | Output directory for HTML report and JSON findings; default: `./scoutsuite-report/` |
| `--logfile` | `<path>` | Write debug log to file |
| `--debug` | — | Enable debug output (verbose logging) |
| `--quiet` | — | Suppress non-essential output |
| `--no-banner` | — | Skip startup banner |

### AWS-specific options

| Flag | Argument | Purpose |
|---|---|---|
| `--profile` | `<name>` | AWS profile (if multiple credentials) |
| `--regions` | `<regions>` | Comma-separated regions to scan; default: all |
| `--max-retries` | `<number>` | API retry count on transient failures |

### Azure-specific options

| Flag | Argument | Purpose |
|---|---|---|
| `--cli` | — | Use Azure CLI for authentication (default) |
| `--user-account` | — | Interactive user credentials (prompts) |
| `--user-account-browser` | — | Browser-based login (supports MFA) |
| `--service-principal` | — | Service principal authentication |
| `--file-auth` | `<file>` | Read service principal credentials from JSON file |
| `--msi` | — | Use Azure Managed Service Identity (from within Azure) |
| `--subscriptions` | `<names>` | Comma-separated subscription names to scan; default: first accessible |
| `--all-subscriptions` | — | Scan all accessible subscriptions |
| `--tenant-id` | `<id>` | Azure tenant ID (for service principal) |
| `--client-id` | `<id>` | Service principal client ID |

### GCP-specific options

| Flag | Argument | Purpose |
|---|---|---|
| `--user-account` | — | Use gcloud CLI authentication (default) |
| `--projects` | `<ids>` | Comma-separated GCP project IDs to scan; default: current project |

### Custom rules and reporting

| Flag | Argument | Purpose |
|---|---|---|
| `--custom-rules` | `<directory>` | Directory containing custom YAML rule files |
| `--skip-default-rules` | — | Do not apply built-in CIS Benchmark rules |
| `--findings-only` | — | Output only findings; omit configuration details in report |

---

## Quick Use-Case List

1. **Baseline security configuration audit (CIS Benchmarks)** — Run ScoutSuite against AWS/Azure/GCP to get a snapshot of current security posture vs. CIS Benchmarks
2. **IAM permission discovery and overpermissioning detection** — Identify users/roles with excessive privileges
3. **Exposed storage bucket/blob container detection** — Find public S3 buckets, Azure Blob containers, or GCS buckets accessible to anonymous users
4. **Public API endpoint discovery** — Identify APIs, load balancers, or application gateways exposed to the internet
5. **Insecure network configuration auditing** — Find security groups, firewalls, and network policies that permit unnecessary inbound/outbound traffic
6. **Logging and monitoring gap identification** — Detect resources without CloudTrail/Azure Activity Log/Cloud Audit Logs enabled
7. **Encryption misconfiguration** — Find databases, storage buckets, or VMs without at-rest encryption; identify resources using weak encryption keys
8. **Service-principal overpermissioning (Azure-specific)** — Identify service principals with Directory admin or excessive API permissions
9. **Cross-cloud comparison** — Run ScoutSuite against AWS, Azure, and GCP in sequence; compare security postures across multiple cloud providers
10. **Post-compromise assessment** — After an incident, run ScoutSuite to verify what configuration was exposed before remediation
11. **Continuous compliance monitoring** — Schedule ScoutSuite to run on a daily/weekly basis; track compliance drift over time
12. **Onboarding a new cloud environment** — Baseline audit of a newly-provisioned AWS/Azure/GCP account before production workloads are deployed

---

## Prerequisites

**On the attacker's machine:**
1. **Python 3.9, 3.10, or 3.11** — installed and accessible via `python3` or `python`
2. **pip** — Python package manager (included with modern Python installations)
3. **Cloud provider CLI pre-configured:**
   - **AWS:** AWS CLI v2 installed; `aws configure` run with valid IAM credentials (access key + secret key), or EC2 instance role configured
   - **Azure:** Azure CLI installed; `az login` executed to establish authenticated session
   - **GCP:** gcloud CLI installed; `gcloud auth login` executed with valid Google account
4. **Network access to cloud provider APIs** — ScoutSuite must reach AWS API endpoints, Azure Resource Manager, or GCP API servers (typically port 443/HTTPS from the attacker's network)
5. **Appropriate IAM/RBAC permissions on the cloud account:**
   - **AWS:** ReadOnly IAM policy on the account being audited (at minimum: EC2:Describe*, S3:GetBucket*, IAM:GetUser, IAM:ListUsers, etc.) — specific permissions depend on rules being evaluated
   - **Azure:** Reader + Security Reader roles on the subscription(s) being audited
   - **GCP:** Viewer or Security Reader role on the project(s) being audited
6. **Optional — For custom rules:** YAML knowledge (to write custom rule definitions)

**Legal / Compliance note:**
- **AWS:** No special permission form required (ScoutSuite performs only read-only API calls)
- **Azure:** Comply with Microsoft Cloud Unified Penetration Testing Rules of Engagement
- **GCP:** Comply with Google Cloud Platform's Acceptable Use Policy and Terms of Service

---

## Installation Quick Start

```bash
# Via PyPI (recommended)
pip install scoutsuite

# Verify installation
scout --version

# OR via Git (for development / latest source)
git clone https://github.com/nccgroup/ScoutSuite.git
cd ScoutSuite
pip install -r requirements.txt
python scout.py --help
```

