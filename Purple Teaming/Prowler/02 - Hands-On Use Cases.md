# Prowler — Hands-On Use Cases

Each scenario includes full commands and MITRE ATT&CK mapping. Prowler is a **read-only assessment tool** — it enumerates and evaluates, but does not modify or exploit resources.

---

## 1. Baseline AWS Security Audit (CIS Benchmark)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Scan an AWS account against CIS Foundations Benchmark v1.4.0 to identify compliance gaps.

```bash
# Install Prowler (first time only)
pip install prowler-cloud

# Run full AWS CIS audit against current AWS account
prowler aws -f cis -o json -d ./cis-audit-$(date +%Y%m%d)

# Or specify a profile
prowler aws --profile my-audit-profile -f cis

# Run only specific CIS section (e.g., Identity and Access Management = section 1)
prowler aws -c cis_1_1,cis_1_2,cis_1_3,cis_1_4,cis_1_5,cis_1_6,cis_1_7,cis_1_8,cis_1_9,cis_1_10,cis_1_11,cis_1_12 -o html -d ./cis-iam-audit
```

**What to look for:**
- MFA not enabled on root account
- Overpermissioned IAM policies (e.g., `"Action": "*"`)
- Access keys older than 90 days
- CloudTrail not enabled or multi-region coverage gaps
- Default VPC not deleted

**Output interpretation:**
- `PASSED`: Control is satisfied (e.g., root MFA enabled)
- `FAILED`: Control is not satisfied (e.g., root MFA disabled) — flagged for remediation
- `MUTED`: Finding suppressed (usually for false positives or accepted risks)

---

## 2. PCI-DSS Compliance Validation

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Scan AWS payment-card environment against PCI-DSS v3.2.1 requirements; correlate findings with PCI requirement IDs for audit documentation.

```bash
# Scan for PCI-DSS compliance
prowler aws -f pci_dss -o json -d ./pci-audit-$(date +%Y%m%d)

# Combine PCI audit with remediation steps
prowler aws -f pci_dss --remediation -o html -d ./pci-audit-remediation

# Run only PCI Requirement 2 (access control) checks
prowler aws -f pci_dss -c pci_2_1,pci_2_1_1,pci_2_2,pci_2_2_1,pci_2_2_2,pci_2_2_3,pci_2_2_4 -o json
```

**What to look for:**
- Public S3 buckets (PCI 1.3: deny direct access to cardholder data)
- EC2 security groups allowing unrestricted inbound (PCI 1.2)
- Unencrypted RDS databases (PCI 3.2.1: encryption at rest)
- Missing VPC Flow Logs (PCI 10.1: logging and monitoring)
- IAM policies allowing overprivileged actions on payment systems

**Key PCI controls mapped in Prowler:**
- **PCI 1.x:** Firewall configuration (security groups, NACLs)
- **PCI 2.x:** Default configurations, administrative access
- **PCI 3.x:** Encryption and cryptography
- **PCI 10.x:** Logging and monitoring

---

## 3. NIST 800-53 Control Verification (FedRAMP-Ready)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Audit cloud infrastructure against NIST SP 800-53 control families for government/FedRAMP compliance.

```bash
# Full NIST 800-53 audit
prowler aws -f nist_800_53 -o html -d ./nist-audit-$(date +%Y%m%d)

# Focus on specific control family: Access Control (AC)
prowler aws -f nist_800_53 -g access_control -o json

# Export findings mapped to NIST control IDs
prowler aws -f nist_800_53 -o csv -d ./nist-controls-mapping

# FedRAMP High baseline (stricter than AWS)
prowler aws -f nist_800_53 -c nist_ac_2_1,nist_ac_3_1,nist_ac_4_1,nist_au_2_1,nist_ia_2_1 -o json
```

**What to look for:**
- **AC-2** (Account Management): root/service accounts not properly managed
- **AC-3** (Access Enforcement): IAM policies not properly restricting access
- **AU-2** (Audit Events): CloudTrail gaps, logs not being sent to centralized repository
- **IA-2** (Authentication): MFA not enforced, no conditional access policies
- **SC-7** (Boundary Protection): Security groups allowing unnecessary inbound

**Output example:**
```json
{
  "control_id": "ac_2_1",
  "control_name": "Account Management",
  "resource": "arn:aws:iam::123456789012:root",
  "status": "FAILED",
  "finding": "Root account does not have MFA enabled"
}
```

---

## 4. ISO 27001:2022 Control Audit

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Verify information-security controls per ISO 27001 Annex A for certification readiness.

```bash
# ISO 27001 full audit
prowler aws -f iso27001 -o html -d ./iso27001-audit-$(date +%Y%m%d)

# ISO 27001 + Azure (multi-cloud compliance)
prowler aws -f iso27001 -o json -d ./iso-aws
prowler azure -f iso27001 -o json -d ./iso-azure

# Remediation-focused report
prowler aws -f iso27001 --remediation -o html
```

**What to look for (Annex A control objectives):**
- **A.5.1** (Policies for information security): No written security policies in account
- **A.6** (Organization): No segregation of duties (everyone admin)
- **A.9** (Access Control): Overpermissioned IAM, no MFA, no password policy
- **A.10** (Cryptography): No KMS encryption, unencrypted EBS/RDS
- **A.12** (Operations Security): No encryption in transit (HTTPS), no logging
- **A.13** (Communications Security): No VPC isolation, public storage

---

## 5. Multi-Cloud Comparison (AWS + Azure + GCP)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Run identical CIS checks across three cloud platforms; identify which cloud has the strictest/loosest compliance posture.

```bash
# AWS CIS audit
prowler aws -f cis -o json -d ./cis-aws-$(date +%Y%m%d)

# Azure CIS audit
prowler azure -f cis -o json -d ./cis-azure-$(date +%Y%m%d)

# GCP CIS audit (requires service account key)
prowler gcp -a /path/to/service-account-key.json -f cis -o json -d ./cis-gcp-$(date +%Y%m%d)

# Compare findings across clouds in a single HTML report
prowler aws azure gcp -f cis -o html -d ./multi-cloud-audit
```

**Analysis:**
- Identify which cloud has the most failures (highest risk)
- Map same control across clouds (e.g., CIS 1.1 across all three = MFA on root/admin)
- Prioritize remediation on the most-exposed platform

---

## 6. Post-Remediation Verification

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

After security team remediates findings (e.g., enables MFA, encrypts storage), re-run Prowler to confirm fixes.

```bash
# Initial baseline scan (store results)
prowler aws -f cis -o json -d ./baseline-scan-$(date +%Y%m%d)

# [Security team remediates findings]

# Re-run scan one week later
prowler aws -f cis -o json -d ./remediation-verification-$(date +%Y%m%d)

# Compare: look for FAILED → PASSED status changes
# Generate a "before/after" report highlighting improvements
prowler aws -f cis --remediation -o html -d ./remediation-summary
```

**Success metrics:**
- Number of FAILED → PASSED transitions
- CIS compliance score improvement (e.g., 65% → 85%)
- Critical/high-severity findings reduced to zero

---

## 7. Continuous Compliance Monitoring (Scheduled Scans)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Deploy Prowler on a schedule (daily/weekly) to track compliance drift; send alerts when scores drop.

```bash
# Run daily via cron
# Add to crontab -e:
0 2 * * * prowler aws -f cis -o json -d /compliance-reports/$(date +\%Y\%m\%d) >> /var/log/prowler.log 2>&1

# Or use a container/Lambda:
# Docker: prowler-cloud/prowler:latest
docker run --rm \
  -e AWS_ACCESS_KEY_ID=$AWS_KEY \
  -e AWS_SECRET_ACCESS_KEY=$AWS_SECRET \
  -v /reports:/output \
  prowler-cloud/prowler:latest \
  prowler aws -f cis -o json -d /output/$(date +%Y%m%d)

# AWS Lambda (serverless scheduling):
# Create Lambda function that invokes prowler, store results in S3
prowler aws -f cis -o json -b my-compliance-bucket
```

**Monitoring/Alerting:**
- Track CIS score over time (trend analysis)
- Alert if score drops >5% week-over-week (compliance drift)
- Aggregate findings across all scheduled scans

---

## 8. Risk-Weighted Prioritization Using ThreatScore

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Prowler's ThreatScore ranks findings by weighted risk; use this for incident-response prioritization when audit queue is deep.

```bash
# Full audit with ThreatScore output
prowler aws -f cis -o json -d ./threat-scored-audit

# Extract and rank findings by ThreatScore (JSON)
cat output.json | jq '.findings[] | select(.threat_score != null) | sort_by(.threat_score) | reverse'

# HTML report auto-sorts by ThreatScore (highest first)
prowler aws -f cis -o html -d ./threat-prioritized
```

**Threat scoring methodology:**
- Framework (CIS vs. PCI vs. NIST): different severity weightings
- Resource type (root account > IAM user > database > storage): sensitivity
- Control scope (affects entire account vs. single resource): blast radius
- Example: "Root account MFA disabled" = highest ThreatScore (all three factors)

**Response workflow:**
1. Review findings in ThreatScore order (highest first)
2. Remediate high/critical findings within 24 hours
3. Re-scan to confirm fix
4. Move to next highest finding

---

## 9. Custom Compliance Framework Definition

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Define organization-specific security checks (e.g., "all production RDS must be in us-east-1") via JSON ruleset.

```bash
# Create custom ruleset (my-policy.json)
cat > my-custom-policy.json << 'EOF'
{
  "framework": "my_org_policy",
  "version": "1.0",
  "checks": [
    {
      "id": "org_1_1",
      "title": "All production RDS in us-east-1",
      "service": "rds",
      "checks": [
        {
          "id": "rds_prod_region",
          "description": "Production RDS instances must be in us-east-1",
          "conditions": {
            "tags": {"Environment": "Production"},
            "region": "us-east-1"
          }
        }
      ]
    }
  ]
}
EOF

# Apply custom framework
prowler aws -f my_org_policy -o json -d ./custom-audit
```

**Use cases:**
- Enforce geographic data residency (GDPR: data in EU only)
- Require specific tags on all resources (cost allocation)
- Mandate encryption key rotation schedule (HSM/KMS policies)
- Enforce network isolation (VPC, subnet) requirements

---

## 10. Cross-Account AWS Audit (STS Role Assumption)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1087 (Account Discovery)

Audit multiple AWS accounts in a single Prowler run; operator has role assumption rights to all target accounts.

```bash
# Assume role in secondary account
prowler aws \
  -a arn:aws:iam::999999999999:role/ProwlerAuditRole \
  -f cis -o json -d ./cross-account-audit-$(date +%Y%m%d)

# Audit multiple accounts sequentially
for ACCOUNT in 111111111111 222222222222 333333333333; do
  prowler aws \
    -a arn:aws:iam::${ACCOUNT}:role/ProwlerAuditRole \
    -f cis -o json -d ./audit-${ACCOUNT}
done

# Combine results into single report
# (Manual step: merge JSON files or use Prowler SaaS for consolidated view)
```

**Prerequisites (in each target account):**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::OPERATOR-ACCOUNT:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "unique-external-id-123"
        }
      }
    }
  ]
}
```

**Consolidated reporting:**
- Aggregate findings across all accounts
- Identify account-level compliance gaps (some accounts pass CIS 1.1, others fail)
- Track remediation across org

---

## 11. Misconfig Discovery & Exploitation Risk Assessment

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1530 (Data from Cloud Storage)

Deep scan for attackable misconfigurations (open storage, overpermissioned roles, trust-relationship chains).

```bash
# Run all checks (not limited to single framework)
prowler aws -o json -d ./full-misconfig-scan

# Focus on high-risk services
prowler aws -s s3,iam,ec2,rds,kms,secretsmanager -o json -d ./high-risk-scan

# Check for specific misconfig patterns
prowler aws -c \
  aws_s3_bucket_public_access_enabled,\
  aws_iam_policy_allows_actions_without_resource_restrictions,\
  aws_ec2_securitygroup_allows_unrestricted_inbound,\
  aws_rds_instance_encryption_enabled,\
  aws_secretsmanager_secret_exposed_in_logs \
  -o html -d ./misconfig-focus

# Hunt for data-exfiltration paths
prowler aws -s s3,dynamodb,glacier,ebs -o json -d ./data-exfil-risk
```

**High-risk misconfigs Prowler finds:**
- **S3 Public Buckets:** `aws_s3_bucket_public_access_enabled` → data exfiltration
- **Overpermissioned IAM:** `aws_iam_policy_allows_*_without_resource_restrictions` → lateral movement
- **Open Security Groups:** `aws_ec2_securitygroup_allows_unrestricted_inbound` → network pivot
- **Unencrypted Databases:** `aws_rds_instance_encryption_enabled` → credential theft
- **Exposed Secrets:** `aws_secretsmanager_secret_exposed_in_logs` → credential compromise

---

## 12. Exfiltration Risk Assessment

**MITRE ATT&CK:** T1537 (Transfer Data to Cloud Account), T1530 (Data from Cloud Storage)

Identify cloud resources that could facilitate data theft (public storage, overpermissioned read access, missing logging).

```bash
# Scan for storage exposure
prowler aws -s s3,glacier,ebs,efs,backup -o json -d ./storage-risk-scan

# Specifically: public S3 buckets, public snapshots, public backups
prowler aws -c \
  aws_s3_bucket_public_access_enabled,\
  aws_ec2_snapshot_public,\
  aws_ec2_ami_public,\
  aws_backup_recovery_point_public \
  -o html

# Check logging for data-access trails (detecting exfiltration)
prowler aws -c \
  aws_cloudtrail_enabled,\
  aws_s3_bucket_access_logging_enabled,\
  aws_rds_instance_enhanced_monitoring_enabled \
  -o json -d ./logging-for-exfil-detection

# Identify credential-store exposure
prowler aws -s secretsmanager,ssm -c \
  aws_secretsmanager_secret_encrypted_with_kms,\
  aws_secretsmanager_secret_rotation_enabled,\
  aws_ssm_parameter_encrypted \
  -o json
```

**Attack chain Prowler detects:**
1. Open S3 bucket (publicly readable)
2. No logging on bucket (no access trail)
3. IAM policy allows `s3:GetObject` on `*` resource (any identity)
4. Attacker: upload exfil script, download sensitive data

---

## 13. HIPAA/GDPR Readiness Check

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Audit AWS/Azure for healthcare/privacy regulatory requirements (encryption at rest/transit, audit logging, access controls, data retention).

```bash
# HIPAA compliance scan (AWS)
prowler aws -f hipaa -o html -d ./hipaa-audit-$(date +%Y%m%d)

# GDPR compliance scan
prowler aws -f gdpr -o json -d ./gdpr-audit-$(date +%Y%m%d)

# Both frameworks (intersection of controls)
prowler aws -f hipaa -f gdpr -o html

# Focus on encryption (core HIPAA/GDPR requirement)
prowler aws -c \
  aws_rds_instance_encryption_enabled,\
  aws_s3_bucket_encryption_enabled,\
  aws_ebs_volume_encryption_enabled,\
  aws_secretsmanager_secret_encrypted_with_kms \
  -o json

# Audit data retention/deletion policies
prowler aws -c aws_s3_bucket_versioning_mfa_delete_enabled,aws_rds_backup_retention_period -o json
```

**Key controls:**
- **Encryption at rest:** RDS, S3, EBS must use KMS/managed keys
- **Encryption in transit:** TLS 1.2+ for all data flows
- **Access logging:** CloudTrail, VPC Flow Logs, bucket/RDS audit logs
- **Data retention:** Configured delete policies, versioning locks
- **Segregation:** Data classified by sensitivity; access controls enforce least privilege

---

## 14. Lateral Movement & Trust-Path Enumeration

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1087 (Account Discovery), T1098 (Account Manipulation)

Map IAM trust relationships, role chaining, and permission paths that attackers could exploit for lateral movement post-initial compromise.

```bash
# Enumerate all IAM roles, trusts, and permissions
prowler aws -s iam -o json -d ./iam-trust-mapping

# Specifically: check for roles with assume-role trust to external principals
prowler aws -c \
  aws_iam_role_cross_account_access_trusted,\
  aws_iam_role_assumed_by_external_identity,\
  aws_iam_role_allows_sts_assume_role_without_conditions \
  -o json

# Find roles that can assume other roles (privilege escalation chains)
prowler aws -c aws_iam_policy_allows_sts_assume_role_without_resource_restrictions -o json

# Enumerate service-linked roles (often overpermissioned)
prowler aws -s iam -c aws_iam_service_linked_role_permissions -o json

# Map EC2 instance profiles (what roles can EC2 assume?)
prowler aws -s ec2,iam -c aws_ec2_instance_profile_attached,aws_iam_instance_profile_role_permissions -o json
```

**Exploitation workflow Prowler reveals:**
1. Initial compromise: attacker gains access to EC2 instance with attached role
2. `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` → retrieve role credentials
3. Prowler scan shows that role can assume another role (`sts:AssumeRole` on `arn:aws:iam::*:role/*`)
4. Attacker uses `sts:AssumeRole` to assume cross-account admin role
5. Attacker now has access to production account

**Blue team use:**
- Map all trust relationships before breach (know the attack surface)
- Audit for unnecessary cross-account trusts
- Implement `StringEquals` conditions on `sts:AssumeRole` to restrict lateral movement
- Enable CloudTrail logging of `AssumeRole` calls to detect exploitation

---

## Output Format Examples

### JSON Output
```bash
prowler aws -f cis -o json -d ./output
cat output/json/cis-123456789012-report.json | jq '.findings[] | {id, status, resource}'
```

### CSV Output (Easy Import to Sheets/Splunk)
```bash
prowler aws -f cis -o csv -d ./output
# Columns: FindingID, Resource, Status, Framework, Requirement, Remediation
```

### HTML Report (Human-Readable)
```bash
prowler aws -f cis -o html -d ./output
# Opens in browser; interactive, sortable by status/severity
```

### SARIF Output (IDE Integration)
```bash
prowler aws -f cis -o sarif -d ./output
# Import into VS Code, IntelliJ, GitHub Actions for code-review workflows
```

---

## Chained Workflow Example: Post-Breach Threat Assessment

**Scenario:** Attacker compromised an EC2 instance; blue team wants to understand what data/resources are at risk.

```bash
# Step 1: Scan full AWS account
prowler aws -o json -d ./full-audit

# Step 2: Extract only FAILED findings (things are wrong)
cat output.json | jq '.findings[] | select(.status == "FAILED")'

# Step 3: Focus on attackable misconfigs (high ThreatScore)
cat output.json | jq '.findings[] | select(.threat_score > 8) | sort_by(.threat_score)'

# Step 4: Identify data exfiltration paths
cat output.json | jq '.findings[] | select(.finding | contains("public") or contains("exposed")) | .resource'

# Step 5: Generate executive summary
prowler aws -f cis -o html --remediation -d ./incident-response-summary
```

This gives incident response a prioritized list of what to secure/monitor next.

