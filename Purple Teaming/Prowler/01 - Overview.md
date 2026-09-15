# Prowler — Cloud Security Compliance Assessment

🔴 **Red Flag:** Unlike multi-cloud vulnerability scanners, Prowler's defining capability is **compliance framework automation** — it identifies cloud misconfigurations against CIS/PCI-DSS/NIST/ISO standards as pre-built checks, not ad-hoc scans, making it the tool of choice for both operators (to find exploitable compliance gaps) and blue teams (to audit controls). Output includes a **ThreatScore** risk-weighted prioritization, making it actionable for incident-response triage.

---

## History

**Prowler** is a cloud security assessment platform built and maintained by **Prowler Cloud Security** (prowler.io). The open-source project lives at `prowler-cloud/prowler` on GitHub.

- **First release:** 2016, originally AWS-only
- **Current stable version:** v5.25+ (as of August 2026)
- **Language:** Python ≥3.10, <3.13
- **License:** Open source (Apache 2.0 for core; commercial licensing for enterprise features)
- **Maintainer:** Cloud-native organization (founded 2020), split between open-source core and commercial Prowler SaaS platform
- **Multi-cloud expansion:** AWS (primary, 2016+) → Azure (2021) → GCP (2022) → Kubernetes (2023) → other cloud/SaaS platforms (GitHub, M365, Okta, OCI, Alibaba, CloudFlare, MongoDB Atlas, etc.)

**Current scope (v5.25+):**
- **AWS:** 639 checks across 86 services
- **Azure:** 191 checks across 22 services
- **GCP:** 109 checks across 20 services
- **Kubernetes:** 92 checks across 7 services
- **Supported compliance frameworks:** CIS Benchmarks (AWS/Azure/GCP/Kubernetes), NIST 800-53, NIST Cybersecurity Framework, CISA, MITRE ATT&CK, PCI-DSS, HIPAA, GDPR, ISO 27001, FedRAMP, RBI, NIS2, FFIEC, and custom/third-party frameworks

**GitHub:** https://github.com/prowler-cloud/prowler

---

## How It Works

Prowler operates as a **read-only compliance auditor** that connects to cloud provider APIs (AWS/Azure/GCP) using the operator's own cloud credentials, enumerates cloud resources, and evaluates them against pre-built security checks organized by compliance framework.

### Execution Flow

1. **Authentication:** Operator provides cloud credentials (AWS: IAM role, STS token, or access-key pair; Azure: managed identity, service principal, or app registration; GCP: service account JSON key)
2. **Resource Enumeration:** Prowler queries cloud APIs for all resources in the target account(s). **Enumeration is service-aware:** first queries IAM to determine what's available in the account, then enumerates services in parallel (e.g., all EC2 instances across all regions simultaneously).
3. **Check Execution:** Each check (a Python module in `prowler/providers/{aws|azure|gcp}/services/`) queries specific resource types and evaluates them against a pre-defined security rule. Checks are **tagged by framework** (CIS, NIST, PCI, etc.) so only relevant checks run when a framework is specified.
4. **Compliance Mapping:** Results are mapped to compliance framework controls (CIS requirement 2.1.1, PCI 2.2.3, etc.). **Single finding can map to multiple frameworks** (e.g., "Root MFA disabled" is CIS 1.1 AND NIST IA-2 AND PCI 2.1).
5. **Reporting:** Output formatted as JSON, HTML, CSV, or SARIF; includes **ThreatScore** (weighted risk prioritization). **Multiple output files generated** simultaneously (e.g., `-o json` writes `findings.json`, `summary.json`, `metadata.json` to same directory)

### Authentication Methods per Provider

| Provider | Auth Methods | Notes |
|---|---|---|
| **AWS** | - Access key + secret key<br>- STS temporary token<br>- IAM role (from EC2/Lambda)<br>- Federated (SAML/OIDC)<br>- AWS SSO | Default: env var or `~/.aws/credentials`. Role assumption (`-a <role>`) for cross-account audit. |
| **Azure** | - Service principal (app registration) with secret<br>- Managed identity (from VM/function)<br>- User delegation (device flow) | Client ID/secret or certificate. Azure CLI cache also works. |
| **GCP** | - Service account JSON key (`-a` flag)<br>- Application Default Credentials | JSON key most common for automation. |

### Core Protocols & Techniques

- **Cloud Provider APIs:** AWS (boto3), Azure (azure-identity/azure-mgmt), GCP (google-cloud-*) — all READ-ONLY, no modifications
- **Authentication:** OAuth 2.0 / bearer tokens / API key authentication (provider-specific)
- **Data Collection:** Describe/List/Get API calls (no put/delete/modify actions)
- **Compliance Mapping:** Internal ruleset per framework (CIS, NIST, etc.); checks are idempotent Python modules
- **Output:** JSON (machine-parseable), HTML (human-readable), CSV (tabular), SARIF (IDE integration)

### Check Architecture & Execution Model

Prowler's core is a **service-oriented check system** (verified against `prowler-cloud/prowler`'s source structure, `prowler/providers/{aws|azure|gcp}/services/`):

1. **Service modules** — One Python module per cloud service (e.g., `iam.py`, `ec2.py`, `s3.py`). Each service module defines:
   - API calls to enumerate resources (e.g., `list_users()`, `describe_instances()`)
   - Data models to store responses (e.g., User, Instance, Bucket objects)
   - Cache mechanism to avoid re-querying the same API (speeds up multi-check runs)

2. **Check modules** — One Python file per individual check (e.g., `cis_1_1.py` for "Ensure MFA is enabled on the root account"). Each check:
   - Calls one or more service modules to fetch data
   - Applies a logical rule (e.g., "root account has MFA enabled?" → PASSED/FAILED)
   - Returns a finding object with resource ARN, status, remediation hint, and framework mapping

3. **Framework mapping** — Check results are tagged with multiple framework IDs:
   ```
   Check: aws_iam_root_mfa_enabled
   Maps to:
   - CIS 1.1 (Ensure root account has MFA enabled)
   - NIST AC-2 (Account Management)
   - PCI-DSS 2.1 (Restrict access to systems by business need)
   - ISO 27001 A.9.4.2 (Access management)
   ```
   When operator runs `-f cis`, only checks tagged with CIS mappings execute.

4. **Parallelization** — Prowler spawns worker threads per region/account to query APIs in parallel (speeds up regional enumeration for EC2, S3, etc.). Single region = single API call per service; multi-region = parallel calls.

5. **Caching & Optimization** — API responses cached in memory during scan; subsequent checks reuse results. Example: `ListUsers` API call made once, reused by CIS 1.2 (access keys), 1.3 (credentials), 1.5 (root inactive), etc.

### What Makes a Finding "PASSED" vs. "FAILED"

For each check, Prowler evaluates a resource against a rule. Rule logic is often simple but security-critical:

**Example: CIS 1.1 (MFA on Root Account)**
```python
# Pseudocode of check logic
def cis_1_1_root_mfa():
    root_user = iam.get_account_summary()
    if root_user.has_mfa_enabled:
        return PASSED  # Green light
    else:
        return FAILED  # Red light (remediation: enable MFA)
```

**Example: CIS 2.1.2 (S3 Block Public Access)**
```python
# Pseudocode
def cis_2_1_2_s3_block_public_access():
    s3_settings = s3.get_public_access_block()
    if s3_settings.block_public_acls and \
       s3_settings.block_public_policies and \
       s3_settings.ignore_public_acls and \
       s3_settings.restrict_public_buckets:
        return PASSED
    else:
        return FAILED  # All four settings required
```

**Example: AWS-Specific Check (Unrelated to CIS)**
```python
# Not mapped to CIS, but still useful
def aws_ec2_imdsv2_enabled():
    for instance in ec2.describe_instances():
        if instance.imds_version == 'v2':
            return PASSED
        else:
            return FAILED  # IMDSv2 mitigates SSRF attacks
```

### ThreatScore Calculation

Each finding gets a **ThreatScore** (1–10 scale) for incident-response triage. Calculation considers:

1. **Severity** — how damaging is the misconfiguration if exploited?
   - Critical (10): root account no MFA, public S3 with secrets, overpermissioned IAM
   - High (8–9): unencrypted databases, disabled CloudTrail, open security groups
   - Medium (5–7): old access keys, no bucket versioning, missing MFA on users (non-root)
   - Low (1–4): missing tags, no cost-optimization settings

2. **Scope** — how many resources affected?
   - Blast radius: single resource = lower score; account-wide setting = higher score
   - Example: "VPC Flow Logs not enabled" is account-wide, high blast radius

3. **Exploitability** — how easily can an attacker abuse this?
   - Low hanging fruit: public S3 bucket (direct data access)
   - Medium: overpermissioned IAM (requires compromised credential)
   - High: missing logging (post-exploitation, hard to detect attacker)

**Example Scoring:**
- Root account no MFA: ThreatScore 9.5 (high severity + high scope + high exploitability)
- Single EC2 instance with open RDP: ThreatScore 7 (high exploitability, single resource)
- Old IAM access key (>90 days): ThreatScore 4 (medium risk, single key)

Findings sorted by ThreatScore in output (highest first), so IR team triages critical issues first.

---

## AWS Service Coverage (639 Checks, 86 Services)

Prowler's AWS check suite is comprehensive. Major services covered:

| Service | Check Count | Example Checks | Frameworks Mapped |
|---|---|---|---|
| **IAM** | 60+ | MFA on root, access key age, overpermissioned policies, unused roles | CIS 1.x, NIST AC-2, PCI 2.1 |
| **EC2** | 45+ | Security group rules, IMDSv2, EBS encryption, VPC flow logs | CIS 2.x, NIST SC-7 |
| **S3** | 50+ | Public access, encryption, versioning, access logging, bucket policies | CIS 2.3/2.4, PCI 1.3, HIPAA |
| **RDS** | 35+ | Encryption at rest/transit, backup retention, enhanced monitoring, master username | CIS 2.2, HIPAA, PCI 3.4 |
| **CloudTrail** | 25+ | Multi-region logging, log file validation, S3 protection, KMS encryption | CIS 2.1, NIST AU-2 |
| **CloudWatch** | 15+ | Log groups, alarms for management events, unauthorized API calls | CIS 2.1, NIST AU-6 |
| **KMS** | 20+ | Key rotation, key policies, key deletion protection | CIS 2.7, PCI 3.6, HIPAA |
| **Lambda** | 20+ | Public access, runtime versions, environment variable encryption, concurrency limits | CIS 2.x, NIST SI-3 |
| **SNS/SQS** | 15+ | Queue policies, encryption, dead-letter queues | HIPAA, PCI |
| **DynamoDB** | 12+ | Encryption, point-in-time recovery, TTL | PCI 3.2 |
| **Secrets Manager** | 18+ | Automatic rotation, encryption, access policies | HIPAA, PCI |
| **VPC** | 40+ | Flow logs, network ACLs, route tables, VPN/Direct Connect, security groups | CIS 2.x, NIST SC-7 |
| **Networking (Route53, ELB, ALB/NLB)** | 30+ | HTTPS/TLS versions, WAF rules, health checks, logging | CIS 2.x, PCI |
| **Backup/Disaster Recovery** | 15+ | Backup vault policies, cross-account backup, encryption | HIPAA, ISO 27001 |
| **X-Ray, Config, GuardDuty, SecurityHub** | 25+ | Enable/disabled status, rule compliance, log retention | CIS 2.1 |
| **Organizations, SCP, Access Analyzer** | 20+ | SCPs enforcing standards, cross-account access validation | CIS 1.x |
| **Other** (Cognito, DocumentDB, Kinesis, etc.) | 100+ | Service-specific encryption, logging, access control | Framework-specific |

**Total:** 639 checks = high coverage but not exhaustive (AWS has 200+ services; Prowler prioritizes security-critical ones).

### Azure Service Coverage (191 Checks, 22 Services)

| Service | Check Count | Example Checks | Frameworks Mapped |
|---|---|---|---|
| **Active Directory (Entra ID)** | 30+ | MFA enforcement, conditional access, guest access, privileged roles | CIS 5.x, NIST IA-2 |
| **Virtual Machines** | 25+ | Encryption, network isolation, OS hardening, guest attestation | CIS 2.x, NIST SI-2 |
| **Storage Accounts** | 25+ | Encryption, access keys, public access, network rules | CIS 2.1, PCI 3.4 |
| **SQL Database** | 18+ | Encryption, auditing, threat detection, firewall rules | CIS 2.2, PCI 3.4 |
| **Key Vault** | 20+ | Access policies, key rotation, purge protection | HIPAA, PCI |
| **App Services** | 18+ | HTTPS only, authentication, backup | CIS 2.x |
| **Network Security Groups** | 20+ | Inbound rules, NSG flow logging | CIS 2.x |
| **Azure Monitor** | 15+ | Diagnostic logs, alerts, workspace retention | NIST AU-2 |
| **Policies & Governance** | 15+ | Azure Policy enforcement, blueprints, RBAC assignments | CIS 1.x |
| **Other** (Logic Apps, API Management, Cosmos DB, etc.) | 5+ | Service-specific settings | Varies |

### GCP Service Coverage (109 Checks, 20 Services)

| Service | Check Count | Example Checks | Frameworks Mapped |
|---|---|---|---|
| **IAM** | 20+ | Service account keys, project-level roles, user access review | CIS 1.x, NIST AC-2 |
| **Compute Engine** | 25+ | VM disk encryption, OS login, firewall rules, serial port access | CIS 2.x |
| **Cloud Storage** | 20+ | Public buckets, encryption, access logging, retention policies | CIS 2.1, PCI 1.3 |
| **Cloud SQL** | 15+ | Encryption, backups, SSL/TLS, root user deactivation | CIS 2.2, PCI 3.4 |
| **Cloud IAM** | 18+ | Service account key rotation, workload identity, org policy | CIS 1.x |
| **VPC & Networking** | 15+ | Firewall rules, flow logs, DNS security | CIS 2.x |
| **Logging & Monitoring** | 12+ | Cloud Audit Logs, monitoring alerts, retention | NIST AU-2 |
| **Cloud Armor** | 8+ | DDoS protection, security policies | CIS 2.x |
| **Other** (Kubernetes, Cloud Run, DataProc, etc.) | 5+ | Container/serverless security | Varies |

---

## Design Philosophy: Compliance ≠ Security

**Important distinction:** Prowler passes/fails checks **against compliance frameworks**, not against absolute security best practices. A resource can pass CIS 1.2 but still be exploitable.

**Example:**
- **CIS 1.2:** "Ensure that all expired SSH public keys for IAM users have been removed"
- Prowler check: Lists all IAM users, counts active SSH keys, checks key age
- **Pass logic:** If all SSH keys are ≤2 years old (arbitrary baseline)
- **Reality:** A 1-year-old SSH key may still be in the attacker's hands (compromise date unknown)

**Recommendation:** Use Prowler output as a **baseline starting point**, not a compliance ceiling. Findings flagged "PASSED" may still require deeper investigation by security team (e.g., "Is this S3 bucket truly necessary to be accessible by this IAM role?").

---

## Distinctive Features vs. Similar Tools

| Feature | Prowler | ScoutSuite (Wave 4 #14) | Pacu (Wave 4 #13) | Manual AWS Audit |
|---|---|---|---|---|
| **Multi-cloud** | ✅ AWS/Azure/GCP/K8s | ✅ AWS/Azure/GCP/Alibaba/Oracle | ❌ AWS only | — |
| **Compliance frameworks** | ✅✅ CIS/NIST/PCI/ISO/HIPAA/GDPR/FedRAMP | ❌ No framework mapping | ❌ No | — |
| **Read-only checks** | ✅ 100% read-only | ✅ 100% read-only | ❌ Exploits misconfigs | — |
| **Check modification** | ✅ Can add custom checks (JSON/YAML) | ✅ Extensible | ✅ Modular code | — |
| **ThreatScore prioritization** | ✅ Risk-weighted findings | ⚠️ Basic severity | ⚠️ No prioritization | — |
| **HTML report** | ✅ Interactive, sortable | ✅ Interactive HTML | ❌ N/A | — |
| **SARIF export** | ✅ For IDE integration | ❌ No | ❌ No | — |
| **Container/serverless** | ✅ K8s, Lambda, Cloud Run | ✅ Some serverless | ❌ Limited | — |
| **SaaS platform** | ✅ Commercial version | ❌ Open-source only | ❌ Open-source only | — |
| **Speed** | ✅ Fast (30-120s per account) | ✅ Fast | ⚠️ Depends on exploits attempted | ❌ Slow, manual |

**Prowler's niche:** Blue team / compliance-focused auditing with risk prioritization and framework mapping. Attackers use it for **post-compromise reconnaissance** when inside a cloud account already.

---

## Not In Scope (Prowler Limitations)

Prowler does **not** cover:

1. **Application-layer security** — Prowler checks cloud platform configuration, not application code (no SAST/DAST integration)
2. **Compliance frameworks outside its mappings** — e.g., SOX, HIPAA Accounting & Reporting, granular GDPR Article-by-Article audits require additional tools
3. **Cost optimization** — RI recommendations, reserved capacity, spot pricing (see AWS Compute Optimizer instead)
4. **On-premises infrastructure** — AWS Outposts, hybrid cloud (not in scope for Prowler)
5. **Hard-coded secrets detection** — Prowler doesn't scan source code repos for leaked credentials (see Trufflehog, Gitleaks — Wave 4 #4)
6. **Third-party SaaS tenants** — GitHub Enterprise, Okta, Slack security posture (Prowler has experimental GitHub/M365 support, but not feature-complete)
7. **Penetration testing** — Prowler doesn't attempt to exploit misconfigs; it reports them. Use Pacu for that.

### Compliance Frameworks Covered

| Framework | Type | Coverage | Notes |
|---|---|---|---|
| **CIS AWS Foundations Benchmark** | Security baseline | AWS only, ~500+ controls | De facto standard for AWS hardening |
| **CIS Azure Foundations Benchmark** | Security baseline | Azure only, ~200+ controls | Default for Azure audits |
| **CIS Kubernetes Benchmark** | Container security | Kubernetes, ~170+ controls | Network policy, RBAC, pod security |
| **NIST 800-53** | Regulatory framework | AC, AU, CA, CM, CP, IA, IR, MA, MP, PS, RA, SA, SC, SI families | Maps individual checks to SP 800-53 control IDs |
| **NIST Cybersecurity Framework** | Risk framework | Identify, Protect, Detect, Respond, Recover | High-level risk categorization |
| **PCI-DSS 3.2.1** | Payment-card compliance | AWS/Azure/GCP | Requirement-level controls |
| **ISO 27001:2022** | Information security | All cloud providers | Annex A control mapping |
| **HIPAA** | Healthcare privacy | AWS/Azure | 49 controls for PHI handling |
| **GDPR** | Data-protection regulation | All providers | Article-level controls |
| **FedRAMP (High)** | U.S. federal compliance | AWS, GCP | Moderate/High baselines |
| **Custom frameworks** | User-defined | All providers | Via JSON/YAML ruleset |

---

## Command-Line Switches — Quick Reference

```
prowler [OPTIONS] [PROVIDER]
```

### Global Options

| Flag | Argument | Purpose |
|---|---|---|
| `-l, --list-checks` | None | List all available checks and their IDs (for use with `-c`) |
| `-c, --checks` | `CHECK_ID[,CHECK_ID,...]` | Run only specified checks (comma-separated); e.g., `-c cis_1_1,cis_1_2` |
| `-e, --excluded-checks` | `CHECK_ID[,...]` | Exclude specific checks from the scan |
| `-f, --framework` | `FRAMEWORK_NAME` | Run only checks mapped to a specific framework; e.g., `-f cis` or `-f pci_dss` |
| `--compliance` | `FRAMEWORK` | Same as `-f` (alternate flag) |
| `-s, --services` | `SERVICE[,SERVICE,...]` | Audit only specified services; e.g., `-s iam,ec2` (AWS), `-s subscriptions,vm` (Azure) |
| `-r, --regions` | `REGION[,REGION,...]` | Audit only specified regions; e.g., `-r us-east-1,eu-west-1` (AWS) |
| `-g, --groups` | `GROUP[,GROUP,...]` | Run checks belonging to specific groups (tags) |
| `-o, --output` | Format | Output format: `json` (default), `csv`, `html`, `sarif`, `json-ocsf` |
| `-d, --output-directory` | Path | Write output files to specified directory (default: `./output`) |
| `--quiet` | None | Suppress non-critical logging (quiet mode) |
| `--verbose` | None | Enable debug-level logging |
| `--version` | None | Display version and exit |

### Provider-Specific Options

#### AWS
| Flag | Argument | Purpose |
|---|---|---|
| `aws` | None | Target AWS (default if no provider specified) |
| `-a, --assume-role` | `ROLE_ARN` | Assume an IAM role in the same or cross-account for auditing; e.g., `-a arn:aws:iam::123456789012:role/CrossAccountAuditRole` |
| `--profile` | `PROFILE_NAME` | Use a named profile from `~/.aws/config` (instead of default) |
| `-b, --bucket` | `S3_BUCKET` | Upload JSON/HTML output to an S3 bucket after scan |
| `--security-hub` | None | Send findings to AWS Security Hub (if enabled in account) |
| `--send-to-aws-s3` | `S3_BUCKET` | Upload findings to S3 automatically |
| `--send-to-security-hub` | None | Publish findings to AWS Security Hub (requires IAM permission) |

#### Azure
| Flag | Argument | Purpose |
|---|---|---|
| `azure` | None | Target Azure |
| `--client-id` | Client ID | Service principal client ID (alternative to env var) |
| `--client-secret` | Secret | Service principal secret (alternative to env var) |
| `--tenant-id` | Tenant ID | Azure tenant ID (if not using managed identity) |

#### GCP
| Flag | Argument | Purpose |
|---|---|---|
| `gcp` | None | Target Google Cloud Platform |
| `-a, --asset-inventory` | None | Use GCP Cloud Asset Inventory (instead of real-time API calls) for faster scanning of large environments |

### Additional Options

| Flag | Argument | Purpose |
|---|---|---|
| `--log-level` | `DEBUG\|INFO\|WARNING\|ERROR` | Set logging level (default: INFO) |
| `--log-file` | Path | Write logs to file (in addition to stdout) |
| `--no-banner` | None | Suppress Prowler banner/header output |
| `--no-inputs` | None | Run in non-interactive mode (no prompts) |
| `--remediation` | None | Include remediation steps in HTML/JSON output (if applicable to framework) |

---

## Quick Use-Case List

Prowler's main operational modes:

1. **Baseline Security Audit (CIS Benchmark)** — scan all AWS/Azure/GCP resources against CIS baseline; output CIS requirement-level findings
2. **PCI-DSS Compliance Validation** — audit cloud payment-card environment against PCI 3.2.1 requirements; auto-map findings to requirement IDs for compliance documentation
3. **NIST 800-53 Control Verification** — evaluate controls against NIST SP 800-53 (FedRAMP/government contracts); categorize by control family (AC, AU, CM, etc.)
4. **ISO 27001 Control Audit** — verify information-security controls per ISO 27001:2022 Annex A; map findings to control-objective mappings
5. **Multi-Cloud Comparison** — run identical compliance checks across AWS/Azure/GCP; identify control gaps across cloud platforms
6. **Post-Remediation Verification** — re-scan cloud environment after security team remediates findings; confirm fixes in output
7. **Continuous Compliance Monitoring** — schedule recurring Prowler scans; track compliance score over time; identify drift
8. **Risk-Weighted Prioritization (ThreatScore)** — scan entire account but focus incident-response efforts on highest-risk findings (ThreatScore ranking)
9. **Custom Compliance Framework** — define organization-specific security checks via JSON/YAML; map to internal policy/standards
10. **Cross-Account AWS Audit** — use STS role assumption to audit multiple AWS accounts in a single Prowler run
11. **Misconfig Discovery (Deep Dive)** — scan for common cloud misconfigurations (open S3 buckets, public RDS, overpermissioned IAM, unencrypted data, etc.)
12. **Exfiltration Risk Assessment** — identify resources that could facilitate data theft (public storage, misconfigured data-lake ACLs, logging gaps)
13. **HIPAA/GDPR Readiness Check** — audit AWS/Azure for healthcare/privacy regulatory alignment (encryption, audit logging, access controls)
14. **Lateral Movement Enumeration** — map IAM trust relationships, role chaining, and permission paths that attackers could exploit after initial compromise

---

## Prerequisites

### For Operator (Attack/Assessment)
- **Python ≥3.10, <3.13** installed and accessible via `python3`
- **Cloud credentials** (AWS key pair, Azure service principal, GCP service account) with READ-ONLY permissions on target account(s)
- **Network access** to cloud provider APIs (usually HTTPS outbound to `*.amazonaws.com`, `*.microsoft.com`, `*.googleapis.com` endpoints)
- **Prowler installed:** `pip install prowler-cloud` or git clone + `pip install -e .` from source
- **Optional:** AWS CLI v2 (`aws` command for profile selection), Azure CLI (`az login` for token cache)

### For Blue Team (Detection/Audit)
- **Access to cloud audit logs** (CloudTrail for AWS, Activity Log for Azure, Cloud Audit Logs for GCP) to detect Prowler's resource-enumeration API calls
- **CloudTrail/Activity Log retention** of at least 7 days (to correlate back to scan timestamps)
- **IAM audit trail** to identify which user/role executed Prowler (via `userIdentity` in CloudTrail, `Initiator` in Azure Activity Log)

### Privilege Requirements

| Provider | Minimum IAM Permissions | Notes |
|---|---|---|
| **AWS** | `iam:Get*`, `iam:List*`, `s3:Get*`, `s3:List*`, `ec2:Describe*`, `kms:Describe*`, `logs:Describe*`, ... (1000+ list/get/describe actions) | Use a custom policy or AWS-managed `SecurityAudit` role (doesn't include everything Prowler needs; custom policy recommended). Cross-account: `sts:AssumeRole` + role must exist in target account with same permission set. |
| **Azure** | `Reader` role on subscription(s) + `Storage Blob Data Reader` for compliance-log scanning | OR: custom role with read-only permissions on storage, compute, networking, identity resources |
| **GCP** | `Viewer` role (project-level) + `roles/iam.securityReviewer` for IAM analysis | Compute, Storage, VPC, Logging APIs must be enabled |

---

## Check Discovery & Selection

### Listing Available Checks

Prowler includes a **check catalog** that can be queried without running a scan:

```bash
# List all AWS checks (hundreds of output lines)
prowler aws -l

# List checks for specific framework
prowler aws -l -f cis

# List checks for specific service
prowler aws -l -s iam

# Find a specific check
prowler aws -l | grep "root_mfa"
# Output: aws_iam_root_mfa_enabled [CIS 1.1] Ensure root account MFA enabled
```

Each check listing includes:
- **Check ID** (e.g., `aws_iam_root_mfa_enabled`)
- **Framework mappings** (e.g., `[CIS 1.1, NIST IA-2, PCI 2.1]`)
- **One-line description** (what it audits)

### Running Specific Checks

Operators can cherry-pick checks instead of running full frameworks:

```bash
# Run only CIS 1.x (IAM controls)
prowler aws -c cis_1_1,cis_1_2,cis_1_3,cis_1_4,cis_1_5

# Run only encryption-related checks
prowler aws -c aws_rds_instance_encryption_enabled,aws_s3_bucket_encryption_enabled,aws_ebs_volume_encryption_enabled

# Exclude specific checks
prowler aws -f cis -e cis_2_1,cis_2_2  # Run CIS but skip logging checks
```

**Use case for operators:** Run only high-risk checks first to prioritize, then full framework later (saves time during initial assessment).

---

## Version History & Active Development

Prowler is actively maintained (verified via GitHub commits, issues, pull requests):

- **v5.x line (current):** Unified codebase for AWS/Azure/GCP (major refactor from v4)
- **Release cadence:** Every 2–4 weeks (new checks, bug fixes, framework updates)
- **Python compatibility:** v5.25+ requires Python 3.10–3.12 (3.13+ not supported due to dependency incompatibilities)
- **Container images:** `prowler-cloud/prowler:latest` updated with each release; can pin to specific version (e.g., `:5.25.0`)

**Stability:** v5.x is production-ready but may have breaking changes (e.g., new flag names, check ID renames). Auditors should pin version if running scheduled compliance scans (to maintain check consistency year-over-year).

---

## Cross-Links (No Re-Derivation)

- **Compliance frameworks:** CIS Benchmarks (official site: cisecurity.org), NIST 800-53 (nvlpubs.nist.gov), PCI-DSS (pcisecuritystandards.org) — Prowler maps findings to these official control IDs; refer to official documentation for control details
- **Cloud audit logs:** Cross-link to `Cloud/AWS/CloudTrail/`, `Cloud/Azure/Activity Logs/`, `Cloud/Google Cloud/Audit Logs/` for how to analyze Prowler's own API-call traces
- **Similar tools (multi-cloud auditing):**
  - **ScoutSuite** (Wave 4 #14): similar multi-cloud scope, but **detection-focused** (what's exposed, what's exploitable?) vs. **compliance-focused** (does it meet CIS/PCI/NIST?)
  - **Pacu** (Wave 4 #13): AWS-only exploitation framework (finds misconfigs AND exploits them) vs. Prowler's assessment-only posture
- **Incident response:** If Prowler scan triggers a security investigation, refer to `Cloud/AWS/Incident Response/`, `Cloud/Azure/Incident Response/` for playbooks on who ran it, what resources were scanned, and whether it's part of an active attack

