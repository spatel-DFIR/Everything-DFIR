# ATT&CK Cloud to Evidence Map

Reverse lookup: given a MITRE ATT&CK **Cloud/IaaS** technique, where does the evidence live in each provider and which note covers it. Techniques evolve — verify IDs against the current ATT&CK Cloud matrix. Evidence names are the **event/log to pull**; the note is where the depth is.

## Contents

- [Initial Access](#initial-access)
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery](#discovery)
- [Lateral Movement](#lateral-movement)
- [Collection & Exfiltration](#collection--exfiltration)
- [Impact](#impact)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Initial Access

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Valid Accounts: Cloud | T1078.004 | CloudTrail `ConsoleLogin`, STS sessions | Entra Sign-in logs | Login/Auth audit, Cloud Audit |
| Trusted Relationship / Federation | T1199 | `AssumeRoleWithSAML/WebIdentity` | Federated sign-in, B2B guest | SAML login, WIF |
| Phishing (to cloud) | T1566 | (via SSO) | M365 UAL, Entra Sign-in (AiTM) | Gmail audit, Login audit |
| Exploit Public-Facing App | T1190 | ALB/app logs, GuardDuty | App Gateway/WAF logs | Cloud LB / Cloud Armor logs |
| Cloud Instance Metadata API (SSRF) | T1552.005 | IMDS SSRF → EC2 role; GuardDuty exfil | Azure IMDS SSRF → MI | GCE metadata SSRF → SA |

## Execution

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Cloud Administration Command | T1651 | **SSM `SendCommand`/`StartSession`** | **Run Command** | startup scripts, IAP exec |
| Serverless Execution | T1648 | Lambda `Invoke` (data event) | Functions invocation logs | Cloud Functions/Run logs |
| Container Admin Command | T1609 | EKS kube-audit (CloudWatch) | AKS diagnostic audit | GKE audit logs |
| Deploy Container | T1610 | ECS/EKS run-task, `CreatePod` | AKS pod create | GKE pod create |

## Persistence

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Additional Cloud Credentials | T1098.001 | `CreateAccessKey`, SP-style keys | SP secret/cert add | **SA key create** |
| Additional Cloud Roles | T1098.003 | `AttachUserPolicy` admin | Directory-role / RBAC add | IAM binding add |
| Additional Email Delegate / Rules | T1098.002/.003 | (n/a) | Exchange inbox rules, forwarding | Gmail filters/forwarding, delegation |
| Create Cloud Account | T1136.003 | `CreateUser` | Entra user/guest create | Workspace user create |
| Office/OAuth Application | T1098 / T1550 | OIDC provider create | **Illicit OAuth consent**, SP creds | **OAuth app grant, DWD** |
| Scheduled/Config persistence | T1053 | **SSM State Manager association**, EventBridge rule | Automation, Guest Config | OS Config, scheduler |
| Modify Federation/Trust | T1484.002 | `UpdateAssumeRolePolicy`, IdP | **Domain federation change** | Federation/WIF change |

## Privilege Escalation

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Valid Accounts abuse | T1078.004 | Policy attach, `PassRole` | PIM activation, role add | `actAs`, SA impersonation |
| Domain/Tenant Policy Mod | T1484 | SCP edit | **Conditional Access / policy mod** | Org Policy edit |
| Additional Roles/Bindings | T1098.003 | `PutUserPolicy` admin | Global Admin add | IAM binding to owner |
| Temporary Elevated Access | T1548 | `AssumeRole` to admin | PIM eligible→active | impersonation chain |

## Defense Evasion

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Disable Cloud Logs | T1562.008 | `StopLogging`, `DeleteTrail`, event-selector edit | disable diagnostic settings; UAL audit-off | disable sink / audit config |
| Impair Defenses | T1562 | GuardDuty disable, `DeleteDetector` | Defender/alert disable | SCC / ETD disable |
| Delete Findings/Logs | T1070 | delete GuardDuty findings, S3 log delete | purge logs | delete log entries/sink |
| Unused Region/Location | T1535 | activity in unused region | unused region | unused region |
| Revert/rollback | T1578 | restore snapshot, `CancelKeyDeletion` (dual-use) | restore | restore |

## Credential Access

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Cloud Instance Metadata | T1552.005 | IMDS role creds | Azure IMDS MI token | GCE metadata SA token |
| Credentials in Files/Stores | T1552.001/.006 | **Secrets Manager `GetSecretValue`**, SSM Param | **Key Vault secret get** | **Secret Manager access** |
| Unsecured Cloud Credentials | T1552 | access keys in git/user-data | SP secret leak | SA key leak |
| Steal Application Access Token | T1528 | OIDC token abuse | **OAuth token theft**, PRT | OAuth token theft |
| Brute Force / Spray | T1110 | `ConsoleLogin` failures | Entra Sign-in (spray) | Login audit failures |
| MFA/AiTM bypass | T1621 / T1556.006 | (SSO) | **Token Theft & AiTM**, MFA fatigue | 2SV bypass |

## Discovery

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Cloud Infrastructure Discovery | T1580 | `Describe*`, `List*` bursts | Resource Graph, `List*` | `list`/`get` bursts |
| Cloud Service Discovery | T1526 | `ListBuckets`, `GetCallerIdentity` | tenant/service enum | asset inventory reads |
| Permission Groups Discovery | T1069.003 | `ListRoles`, `GetAccountAuthorizationDetails` | directory role enum | IAM policy reads |
| Account Discovery | T1087.004 | `ListUsers` | Entra user enum | Workspace user list |

## Lateral Movement

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Use Alternate Auth Material | T1550 | assume role chain, token | OAuth/PRT reuse | impersonation chain |
| Internal SSRF / metadata pivot | T1552.005 | instance role → other services | MI → resources | SA → resources |
| Remote Services (cloud exec) | T1021 / T1651 | **SSM** to other instances | **Run Command** fan-out | IAP / SSH keys |
| Cross-account/tenant/project | T1078 | cross-account `AssumeRole` | cross-tenant B2B | cross-project impersonation |

## Collection & Exfiltration

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Data from Cloud Storage | T1530 | S3 `GetObject`/`ListBucket` (data events) | Blob read logs | GCS `objects.get/list` |
| Data from Cloud Database | T1213 | RDS/DynamoDB reads | Azure SQL/Cosmos | **BigQuery extract**, Cloud SQL |
| Transfer to Cloud Account | T1537 | snapshot/AMI **share to external acct**, S3 replication | disk/blob copy out | disk snapshot / GCS transfer |
| Email Collection | T1114 | (n/a) | Exchange export, eDiscovery abuse | Gmail export, Vault |
| Automated Exfil | T1020 | replication rules | export jobs | transfer jobs |

## Impact

| Technique | ID | AWS | Azure / M365 | Google |
|-----------|----|-----|--------------|--------|
| Data Encrypted for Impact | T1486 | S3 re-encrypt (SSE-C/foreign KMS) | blob re-encrypt | GCS re-encrypt |
| Data Destruction | T1485 | S3/snapshot delete | blob/disk delete | GCS/disk delete |
| Account/Key Removal | T1531 / T1485 | **KMS `ScheduleKeyDeletion`/`DisableKey`** | **Key Vault purge** | **KMS destroy version** |
| Resource Hijacking (mining) | T1496 | large/GPU `RunInstances` | large VM deploy | large GCE deploy |
| Financial Theft (BEC) | T1657 | (n/a) | inbox-rule fraud, wire | Gmail fraud |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The shared model & planes | **00 Cloud Fundamentals** |
| Who uses these techniques | **05 Cloud Threat Landscape** |
| The identity techniques in depth | **01 Cloud Identity and Federation** |
| The service map (equivalents) | **06 Cloud Service Equivalents** |
| Provider ATT&CK depth | each service **for DFIR** note's Red Flags |

## Resources

- MITRE ATT&CK Cloud matrix — https://attack.mitre.org/matrices/enterprise/cloud/
- MITRE ATT&CK IaaS matrix — https://attack.mitre.org/matrices/enterprise/cloud/iaas/
- MITRE ATT&CK Office 365 / Entra — https://attack.mitre.org/matrices/enterprise/cloud/
