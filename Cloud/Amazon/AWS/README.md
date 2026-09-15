# AWS DFIR Field Reference

Hands-on reference for investigating, detecting, and responding to attacks on Amazon Web Services. Covers IAM identity and access control, audit logging (CloudTrail), compute (EC2, Lambda, Systems Manager), storage (S3, EBS), databases (RDS, DynamoDB), and security services (GuardDuty, Config). Primary lens: native AWS console, AWS CLI, and native log queries (CloudTrail Lake, Athena).

> Part of the [Cloud / Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../../../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Read the three foundation notes in order, then navigate to services by scenario:

1. **[00 - AWS Overview & Terminology](00%20-%20AWS%20Overview%20%26%20Terminology.md)** — Mental model: accounts, Organizations, regions, ARNs, control/data plane
2. **[01 - IAM & Identities](01%20-%20IAM%20%26%20Identities.md)** — Identity types, roles, policies, and the "who" decoder for any log
3. **[02 - Investigating AWS (start here)](02%20-%20Investigating%20AWS%20(start%20here).md)** — First-hour triage workflow, CloudTrail queries, multi-account collection

**Responding to an incident now?** Use the scenario router below to jump straight to your situation.

---

## Module Status

- ✅ **Complete:** 50+ investigation notes covering 15 service categories (IAM, CloudTrail, EC2, S3, Lambda, RDS, DynamoDB, KMS, Secrets Manager, GuardDuty, Config, VPC, ECS, EKS, Fargate); 20+ playbooks for cross-service attack scenarios
- Coverage includes account-level triage, identity compromise, data exfiltration, cryptojacking, ransomware, privilege escalation, and persistence/backdoor hunting
- All MITRE ATT&CK Cloud techniques referenced; cross-linked to Linux/Windows notes for compute-side investigation

---

### Each service has the same three note types

| Note | Answers | Template |
|------|---------|----------|
| **What is `<service>`** | Identify & understand — architecture, logs, terminology, "what's normal" | A |
| **`<service>` for DFIR** | Investigate → respond → harden — the hands-on core | B |
| **Playbooks/** | Scenario walk-throughs (attack chain → contain → eradicate → recover) | C |

## Situation → Open This

| The alert / symptom is about… | Start here |
|-------------------------------|-----------|
| A suspicious API-call timeline / "who did X" | **[CloudTrail for DFIR](Logging%20%26%20Monitoring/CloudTrail/CloudTrail%20for%20DFIR.md)** |
| A leaked / abused access key | **[Playbooks → Leaked Access Key](Playbooks/Leaked%20Access%20Key.md)** |
| An IAM user/role/policy change or privesc | **[IAM for DFIR](Identity%20%26%20Access/IAM/IAM%20for%20DFIR.md)** · **[Privilege Escalation to Admin](Playbooks/Privilege%20Escalation%20to%20Admin.md)** |
| A temporary session (`ASIA`) / role assumption | **[STS for DFIR](Identity%20%26%20Access/STS/STS%20for%20DFIR.md)** |
| SSO / permission-set login | **[IAM Identity Center for DFIR](Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)** · **[SSO Compromise](Playbooks/Identity%20Center%20SSO%20Compromise.md)** |
| A public or exfiltrated S3 bucket | **[S3 for DFIR](Storage/S3/S3%20for%20DFIR.md)** · **[Exposed Bucket](Storage/S3/Playbooks/Exposed%20S3%20Bucket.md)** · **[Data Exfiltration](Storage/S3/Playbooks/S3%20Data%20Exfiltration.md)** |
| An EC2 box mining / SSRF / odd behavior | **[EC2 for DFIR](Compute/EC2/EC2%20for%20DFIR.md)** · **[IMDS SSRF to Role Theft](Playbooks/IMDS%20SSRF%20to%20Role%20Theft.md)** |
| Commands run on a host with **no SSH** / SSH-less shell | **[Systems Manager (SSM) for DFIR](Compute/Systems%20Manager%20(SSM)/Systems%20Manager%20(SSM)%20for%20DFIR.md)** · **[SSM Run Command & Session Abuse](Compute/Systems%20Manager%20(SSM)/Playbooks/SSM%20Run%20Command%20and%20Session%20Abuse.md)** |
| A cost / CPU spike | **[Cryptomining Incident](Playbooks/Cryptomining%20Incident.md)** |
| A GuardDuty finding | **[GuardDuty for DFIR](Security%20%26%20Detection/GuardDuty/GuardDuty%20for%20DFIR.md)** |
| Strange network traffic / C2 / scanning | **[VPC Flow Logs for DFIR](Logging%20%26%20Monitoring/VPC%20Flow%20Logs/VPC%20Flow%20Logs%20for%20DFIR.md)** |
| A Lambda doing something odd | **[Lambda for DFIR](Compute/Lambda/Lambda%20for%20DFIR.md)** |
| A database accessed / dumped / shared | **[RDS for DFIR](Databases/RDS/RDS%20for%20DFIR.md)** · **[DynamoDB for DFIR](Databases/DynamoDB/DynamoDB%20for%20DFIR.md)** |
| A disk snapshot shared out | **[EBS for DFIR](Storage/EBS/EBS%20for%20DFIR.md)** |
| "When did this resource change?" | **[Config for DFIR](Security%20%26%20Detection/Config/Config%20for%20DFIR.md)** |
| Logging turned off / findings vanished | **[Defense Evasion](Playbooks/Defense%20Evasion%20-%20Logging%20Disabled.md)** |
| Data deleted / encrypted / ransom note | **[Ransomware & Data Destruction](Playbooks/Ransomware%20and%20Data%20Destruction.md)** |
| A KMS key deleted/disabled / data suddenly unreadable | **[KMS for DFIR](Data%20Protection/KMS/KMS%20for%20DFIR.md)** |
| Secrets / credential store read or shared out | **[Secrets Manager for DFIR](Data%20Protection/Secrets%20Manager/Secrets%20Manager%20for%20DFIR.md)** |
| Root / console login from a new place | **[Root & Console Takeover](Playbooks/Root%20and%20Console%20Account%20Takeover.md)** |
| A CI/CD pipeline / OIDC role | **[CI/CD OIDC Trust Abuse](Playbooks/CICD%20OIDC%20Trust%20Abuse.md)** |
| "Did they leave a way back in?" | **[Persistence & Backdoor Hunt](Playbooks/Persistence%20and%20Backdoor%20Hunt.md)** |
| A container / EKS / ECS compromise | **[ECS](Serverless%20%26%20Containers/ECS/ECS%20for%20DFIR.md)** · **[EKS](Serverless%20%26%20Containers/EKS/EKS%20for%20DFIR.md)** · **[Fargate](Serverless%20%26%20Containers/Fargate/Fargate%20for%20DFIR.md)** |
| A new / crypto pod in EKS | **[Malicious Pod & Cryptomining](Serverless%20%26%20Containers/EKS/Playbooks/Malicious%20Pod%20and%20Cryptomining.md)** |

## Structure

```
Amazon/AWS/
├── 00 - AWS Overview & Terminology.md       ← accounts, Orgs, regions, ARNs, planes
├── 01 - IAM & Identities.md                 ← the "who" decoder ring
├── 02 - Investigating AWS (start here).md   ← first-hour triage flow
├── Playbooks/                               ← tier-2 cross-service attack chains
│   ├── Leaked Access Key.md
│   ├── IMDS SSRF to Role Theft.md
│   ├── Cryptomining Incident.md
│   ├── Ransomware and Data Destruction.md
│   ├── Privilege Escalation to Admin.md
│   ├── Persistence and Backdoor Hunt.md
│   ├── Defense Evasion - Logging Disabled.md
│   ├── Root and Console Account Takeover.md
│   ├── CICD OIDC Trust Abuse.md
│   └── Identity Center SSO Compromise.md
├── Identity & Access/   { IAM · STS · IAM Identity Center (SSO) · Organizations · Cognito }
├── Logging & Monitoring/{ CloudTrail · VPC Flow Logs · CloudWatch }
├── Security & Detection/{ GuardDuty · Config · Security Hub · Detective }
├── Data Protection/     { KMS · Secrets Manager }
├── Storage/             { S3 (+Playbooks) · EBS · EFS }
├── Compute/             { EC2 · Lambda · Systems Manager (SSM) (+Playbook) }
├── Networking/          { VPC · ELB · Route 53 · API Gateway }
├── Databases/           { RDS · DynamoDB }
└── Serverless & Containers/ { ECS · EKS (+Playbook) · Fargate }
```

Each service folder holds **What is `<svc>`** + **`<svc>` for DFIR** (and **Playbooks/** where a single-service scenario warrants it).

## Coverage

| Category | Services |
|----------|----------|
| **Identity & Access** | IAM, STS, IAM Identity Center (SSO), Organizations, Cognito |
| **Logging & Monitoring** | CloudTrail, VPC Flow Logs, CloudWatch |
| **Security & Detection** | GuardDuty, Config, Security Hub, Detective |
| **Data Protection** | KMS, Secrets Manager |
| **Storage** | S3, EBS, EFS |
| **Compute** | EC2 (+IMDS), Lambda, Systems Manager (SSM) |
| **Networking** | VPC, ELB, Route 53, API Gateway |
| **Databases** | RDS/Aurora, DynamoDB |
| **Serverless & Containers** | ECS, EKS, Fargate |

## The Five Recurring Themes

Patterns that show up across nearly every AWS case — internalize these:

1. **Identity, action, resource, account, region** — every log reads the same way once you see these five (→ 00).
2. **The `AKIA → AssumeRole → ASIA` pivot** — long-term key to temporary role session; follow it (→ 01, STS).
3. **The data-plane blind spot** — control-plane is logged by default; *object/data access needs data events* (→ CloudTrail, S3, DynamoDB).
4. **Attackers blind logging** — always confirm CloudTrail/GuardDuty/Config were intact across your window (→ Defense Evasion).
5. **Contain the credential *and* the persistence** — killing the entry key without hunting backdoors is the #1 IR failure (→ Persistence Hunt).

## Related

- **[Cloud → 00 Cloud Fundamentals](../../00%20-%20Cloud%20Fundamentals.md)** · **[06 Cloud Service Equivalents](../../06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** — cross-cloud context
- **[Cloud → 03 Cross-Cloud Correlation](../../03%20-%20Cross-Cloud%20Correlation.md)** — the same actor pivoting across providers
- **Container →** the core Kubernetes/Docker forensics notes (cross-linked from EKS/ECS/Fargate)
- **External:** [AWS Security Incident Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.html) · [MITRE ATT&CK Cloud (IaaS)](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
