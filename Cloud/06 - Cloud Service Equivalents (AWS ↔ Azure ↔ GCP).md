# Cloud Service Equivalents (AWS ↔ Azure ↔ GCP)

A translation dictionary for the analyst who knows one cloud and is handed another. Find the service you know, read across, and jump to the matching note. Equivalents are **approximate** — they line up on *purpose and evidence*, not feature-for-feature — which is exactly what you need mid-incident.

> Use this with **00 Cloud Fundamentals** (the shared model) and each provider's `00 Overview` (the quick table). This is the full, categorized version.

## Contents

- [Identity & Access](#identity--access)
- [Credentials, Keys & Tokens — Side by Side](#credentials-keys--tokens--side-by-side)
- [Authentication Methods](#authentication-methods)
- [Identifiers & Prefixes — Telling Them Apart](#identifiers--prefixes--telling-them-apart)
- [Logging & Audit](#logging--audit)
- [Threat Detection & Posture](#threat-detection--posture)
- [Storage](#storage)
- [Compute](#compute)
- [Containers & Serverless](#containers--serverless)
- [Networking](#networking)
- [Databases](#databases)
- [Keys & Secrets](#keys--secrets)
- [Management & Execution](#management--execution)
- [Productivity / Collaboration (SaaS)](#productivity--collaboration-saas)
- [Terminology Quick-Map](#terminology-quick-map)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Identity & Access

| Purpose | AWS | Azure / Entra | Google |
|---------|-----|---------------|--------|
| Identity directory | IAM + Identity Center | **Entra ID** | **Cloud Identity** |
| Human identity | IAM user | Entra user | Google user |
| Workload identity | IAM **role** (assumed) | **Service principal** / **managed identity** | **Service account** |
| Temp credential | STS **assumed-role session** (`ASIA`) | OAuth **access token** | Short-lived **SA token** |
| Get temp creds | `sts:AssumeRole` | token request / OBO | `generateAccessToken` (impersonation) |
| Long-lived secret cred | Access key (`AKIA`) | SP **client secret / certificate** | **SA key** (JSON) |
| Enterprise SSO | IAM Identity Center | Entra SSO / SAML apps | Workspace SSO |
| Workload federation | OIDC/SAML → `AssumeRoleWith*` | **Federated credentials** | **Workload Identity Federation** |
| RBAC | IAM policies | **Entra roles** *and* **Azure RBAC** (two worlds) | Cloud IAM roles/bindings |
| Guardrail | Service Control Policy (SCP) | Azure Policy | Organization Policy |
| Priv access mgmt | (IAM + boundaries) | **PIM** (eligible/just-in-time) | (IAM Conditions / privileged access) |

→ AWS **01 IAM & Identities**, **STS**, **IAM Identity Center** · Microsoft **01 Entra ID & Identities**, **Managed Identities**, **Roles & PIM** · Google **01 Google Identities**, **Service Accounts**, **Workload Identity Federation**

## Credentials, Keys & Tokens — Side by Side

The single most-requested cross-cloud comparison: **which credential in AWS equals which in Azure and GCP.** Every cloud boils down to *one long-lived secret type* and *one short-lived token type* per identity — the names just differ.

| Credential type | AWS | Azure / Entra | Google | Notes |
|-----------------|-----|---------------|--------|-------|
| **Long-lived programmatic key** | **Access key** (`AKIA…` + secret) | **SP client secret** / certificate | **SA key** (JSON) | ♾ Never expires until deleted — the "leaks in git" class |
| **Short-lived session/token** | **STS session** (`ASIA…` + session token) | **OAuth access token** | **Short-lived SA token** | Expires (mins–hours); minted *from* something else |
| **Refresh material** | (none — re-assume the role) | **Refresh token** / **PRT** | (re-mint via impersonation) | Azure's refresh/PRT is a prime theft target |
| **The temp-cred broker** | **STS** (`AssumeRole`, `GetSessionToken`) | **token endpoint** (OAuth2 / OBO) | **`generateAccessToken`** (IAM Credentials API) | *"What is the STS equivalent?"* → this row |
| **Human interactive login** | Console password + MFA | Entra sign-in (password/MFA/passwordless) | Google sign-in + 2SV | Produces a session, not a signed request |
| **Superuser credential** | Root email + password | Global Admin | Super Admin | Should be near-silent in logs |
| **Second factor** | MFA device/code | Entra MFA / passwordless | Google 2SV / passkey | |
| **OS-level key (not cloud API)** | EC2 key pair (`.pem`) | VM SSH key / password | OS Login / SSH key | Auths to the guest OS, **not** the cloud API |
| **Pre-signed / delegated URL** | S3 pre-signed URL | **SAS token** | Signed URL | Time-limited embedded credential |
| **Federated assertion** | SAML / OIDC → `AssumeRoleWith*` | Federated credential / SAML token | WIF token | Exchanged for a short-lived token |
| **Metadata-served workload cred** | IMDS instance-role creds | IMDS managed-identity token | metadata SA token | 🔴 the SSRF-theft target in every cloud |
| **Domain-wide delegation** | (n/a) | (app-only Graph consent) | **DWD** (SA acts as any user) | Google-specific Workspace bridge |

> 🔴 **The universal rule:** the **long-lived key** (`AKIA` / SP secret / SA key) is contained by **deleting/rotating it**; the **short-lived token** (`ASIA` / OAuth token / SA token) keeps working until it **expires or you revoke the session** — deleting the source key does *not* stop an already-minted token. Same trap, three clouds.

## Authentication Methods

How a caller proves identity — and the log signature each leaves:

| Method | AWS | Azure / Entra | Google |
|--------|-----|---------------|--------|
| Interactive human | Console `ConsoleLogin` + MFA | Entra interactive sign-in | Google login + 2SV |
| Programmatic (signed request) | SigV4-signed API call w/ access key | Bearer token in header | Bearer token / signed request |
| Assume/exchange for temp creds | `sts:AssumeRole` | OAuth2 token grant / OBO | SA impersonation (`generateAccessToken`) |
| Enterprise SSO | IAM Identity Center (SAML/OIDC) | Entra SSO | Workspace SSO / SAML |
| Workload (no stored secret) | IMDS role / OIDC WIF | Managed identity / federated cred | metadata SA / WIF |
| Non-interactive / service | Service principal event (`invokedBy`) | Non-interactive sign-in / SP | SA principal in audit log |

## Identifiers & Prefixes — Telling Them Apart

The strings that tell you *what kind of thing* you're looking at, at a glance:

| Purpose | AWS | Azure / Entra | Google |
|---------|-----|---------------|--------|
| User principal ID | `AIDA…` (`principalId`) | Object ID (GUID) + **UPN** (`user@dom`) | email (`user@dom`) + unique ID |
| Role / workload ID | `AROA…` (role), `assumed-role/<role>/<session>` | **App ID** (client ID) + SP Object ID | SA email `…@…gserviceaccount.com` |
| Long-term key | `AKIA…` | client secret (opaque) / cert thumbprint | SA key ID |
| Temp session key | `ASIA…` (+ session token) | token `oid`/`appid` claims | token (opaque) |
| Resource name | **ARN** `arn:aws:svc:region:acct:…` | **Resource ID** `/subscriptions/…/providers/…` | **full name** `//svc.googleapis.com/projects/…` |
| Account/tenant/project | 12-digit account ID | Tenant ID + Subscription ID (GUIDs) | Project ID (string) + number |
| SSO/federated marker | `AWSReservedSSO_<permset>_<hash>` | `#EXT#` (guest); federated issuer | SAML/WIF pool provider |

> On a case: an `AKIA` vs `ASIA` prefix (AWS), a UPN vs an App ID (Azure), or a `user@` vs `…gserviceaccount.com` (Google) instantly tells you **human vs workload** and **long-term vs temporary** — the first fork in any identity investigation.

## Logging & Audit

| Purpose | AWS | Azure / M365 | Google |
|---------|-----|--------------|--------|
| Control-plane audit | **CloudTrail** (mgmt events) | **Activity Log** (Azure) | **Cloud Audit Logs — Admin Activity** |
| Data-plane audit | CloudTrail **data events** | **Diagnostic/resource logs** | Cloud Audit Logs — **Data Access** |
| Identity/sign-in audit | Console + Identity Center logs | **Entra Sign-in & Audit logs** | **Login/Auth audit** (Workspace) |
| SaaS/user activity | (n/a) | **Unified Audit Log** (M365) | **Admin/Drive/Gmail audit** |
| Log store / query | CloudTrail Lake / **Athena** | Log Analytics / **KQL** | **Log Explorer** / **BigQuery** |
| Network flow | **VPC Flow Logs** | **NSG Flow Logs** | **VPC Flow Logs** |
| Log routing/export | CloudWatch Logs / S3 | Diagnostic settings / Event Hub | **Log Router / sinks** |

→ AWS **CloudTrail**, **CloudWatch**, **VPC Flow Logs** · Microsoft **Activity Log**, **Unified Audit Log**, **Sign-in/Audit Logs**, **NSG Flow Logs** · Google **Cloud Audit Logs**, **Cloud Logging**, **VPC Flow Logs**

## Threat Detection & Posture

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Managed threat detection | **GuardDuty** | **Defender for Cloud** (+ Defender XDR) | **Security Command Center** (Event Threat Detection) |
| Config/compliance drift | **Config** | Defender for Cloud posture / Azure Policy | SCC posture |
| Findings aggregation | **Security Hub** | Defender / Sentinel | SCC |
| Investigation graph | **Detective** | Sentinel / XDR incidents | SCC / Chronicle |
| Identity risk | (GuardDuty IAM findings) | **Entra Identity Protection** | (SCC / Google identity alerts) |

→ AWS **GuardDuty**, **Config**, **Security Hub**, **Detective** · Microsoft **Defender for Cloud**, **Identity Protection** · Google **Security Command Center**

## Storage

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Object storage | **S3** | **Blob Storage** | **Cloud Storage (GCS)** |
| Block/disk | **EBS** | **Managed Disks** | **Persistent Disk** |
| File share | **EFS** | **Azure Files** | **Filestore** |
| Archive / cold tier | S3 Glacier / Deep Archive | Archive Blob tier | GCS Coldline / Archive |
| CDN (edge cache) | **CloudFront** | Azure CDN / Front Door | **Cloud CDN** |
| Backup service | AWS Backup | Azure Backup | Backup & DR |
| Public-exposure risk | Bucket policy / ACL / Block Public Access | Container public access / anonymous | IAM `allUsers` / `allAuthenticatedUsers` |

→ AWS **S3 (+playbooks)**, **EBS**, **EFS** · Microsoft **Storage (+Exposed Blob)** · Google **Cloud Storage (+Public GCS)**

## Compute

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Virtual machine | **EC2** | **Virtual Machines** | **Compute Engine** |
| Metadata service (SSRF target) | **IMDS** `169.254.169.254` | **IMDS** `169.254.169.254` | metadata `169.254.169.254` / `metadata.google.internal` |
| SSH-less admin/exec | **SSM Session Manager / Run Command** | **Run Command** / Bastion / Serial Console | **IAP** / OS Login / startup scripts |
| Guest agent | SSM Agent | Azure VM Guest Agent (WAAgent) | Guest / OS Config agent |
| Machine image | **AMI** | Managed Image / VM Image | Custom Image |
| Auto-scaling group | **Auto Scaling Group** | VM Scale Set | Managed Instance Group |

→ AWS **EC2**, **Systems Manager (SSM)** · Microsoft **Virtual Machines (+Run Command)** · Google **Compute Engine**

## Containers & Serverless

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Managed Kubernetes | **EKS** | **AKS** | **GKE** |
| Container tasks | **ECS** / **Fargate** | Container Apps / ACI | **Cloud Run** |
| Functions (FaaS) | **Lambda** | **Azure Functions** | **Cloud Functions** |
| K8s audit log | EKS control-plane logs → CloudWatch | AKS diagnostic logs (kube-audit) → `AzureDiagnostics` | GKE audit → Cloud Audit Logs |

**K8s logging implementation, per cloud** — the audit log above is the control-plane record; each cloud also has its own additional log source(s) worth knowing by name:

| Log category | AWS (EKS) | Azure (AKS) | Google (GKE) |
|---|---|---|---|
| IAM↔K8s identity resolution | **authenticator log** (🔴 off by default — enable) | *(kube-audit `user.username` carries the resolved Entra/local identity — no separate log)* | *(kube-audit `authenticationInfo.principalEmail` carries the resolved identity — no separate log)* |
| Container/workload stdout-stderr | CloudWatch Container Insights | **Container Insights** (🔴 not on by default — enable the monitoring add-on) | **Workload logs** (`k8s_container`) — on by default |
| Scheduler / pod-placement | *(not separately called out)* | *(not separately called out)* | **Scheduler logs** (`k8s_control_plane_component`, `component="scheduler"`) — on by default |
| Sidecar/mesh data plane | — | **Dapr sidecar logs** (`daprd` container), if Dapr is deployed | — |

→ AWS **EKS (+playbook)** — see "Evidence It Produces" for the authenticator log · Microsoft **AKS (+playbook)** — see "Evidence It Produces" for Container Insights and Dapr sidecar logs · Google **GKE (+playbook)** — see "Evidence It Produces" for workload/scheduler logs · Google **Cloud Run**, **Cloud Functions**

## Networking

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Virtual network | **VPC** | **VNet** | **VPC** |
| Firewall rules | Security Groups / NACLs | **NSGs** | Firewall rules |
| Load balancer | **ELB/ALB** | Azure Load Balancer / App Gateway | **Cloud Load Balancing** |
| WAF | AWS WAF | Azure WAF | **Cloud Armor** |
| DNS | **Route 53** | Azure DNS | Cloud DNS |
| API front door | **API Gateway** | API Management | API Gateway / Apigee |
| Site-to-site VPN | Site-to-Site VPN | VPN Gateway | Cloud VPN |
| Private connectivity | **PrivateLink** / VPC endpoint | Private Link | Private Service Connect |
| Network peering | VPC Peering | VNet Peering | VPC Network Peering |
| Dedicated interconnect | Direct Connect | ExpressRoute | Cloud Interconnect |

→ AWS **VPC**, **ELB**, **Route 53**, **API Gateway** · Microsoft **NSG Flow Logs** · Google **VPC**, **Cloud Load Balancing**

## Databases

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Managed relational | **RDS / Aurora** | Azure SQL / DB for PostgreSQL | **Cloud SQL** |
| NoSQL | **DynamoDB** | Cosmos DB | Firestore / Bigtable |
| In-memory cache | **ElastiCache** (Redis/Memcached) | Azure Cache for Redis | Memorystore |
| Analytics warehouse | Redshift / Athena | Synapse | **BigQuery** |
| Message queue / pub-sub | SQS / SNS | Service Bus / Event Grid | Pub/Sub |
| Event streaming | Kinesis / MSK | Event Hubs | Pub/Sub / Dataflow |

→ AWS **RDS**, **DynamoDB** · Google **Cloud SQL**, **BigQuery**

## Keys & Secrets

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Managed keys (KMS) | **KMS** | **Key Vault (keys)** / Managed HSM | **Cloud KMS** |
| Secret store | **Secrets Manager** / SSM Parameter Store | **Key Vault (secrets)** | **Secret Manager** |
| Destroy-a-key impact | `ScheduleKeyDeletion` | soft-delete + purge | `destroyCryptoKeyVersion` |

→ AWS **KMS**, **Secrets Manager** · Microsoft **Key Vault**

## Management & Execution

| Purpose | AWS | Azure | Google |
|---------|-----|-------|--------|
| Fleet command execution | **SSM Run Command** | **Run Command** | startup scripts / OS Config |
| Automation/runbooks | SSM **Automation** | Azure Automation | Workflows |
| Scheduled config | State Manager | Guest Configuration / DSC | OS Config |
| Org account factory | Organizations / Control Tower | Management Groups | Folders / Org |

→ AWS **Systems Manager (SSM)**, **Organizations**

## Productivity / Collaboration (SaaS)

| Purpose | Microsoft 365 | Google Workspace |
|---------|---------------|------------------|
| Email | **Exchange Online** | **Gmail** |
| Files | **SharePoint / OneDrive** | **Drive** |
| Chat | **Teams** | Chat/Meet |
| Consent/OAuth apps | **App consent** (Entra) | **OAuth & Third-Party Apps** |
| Master activity log | **Unified Audit Log** | **Admin Audit Log** |

→ Microsoft **M365** (Exchange, SharePoint, Teams, UAL) · Google **Workspace** (Gmail, Drive, OAuth, Admin Audit)

*(AWS has no first-party productivity SaaS suite — this row is Microsoft ↔ Google.)*

## Terminology Quick-Map

| Concept | AWS | Azure | Google |
|---------|-----|-------|--------|
| Resource name | ARN | Resource ID | Resource full name |
| Isolation unit | Account | Subscription | Project |
| Tenant/org | Organization | Tenant | Organization |
| Assume-identity | AssumeRole | (token / MI) | impersonate SA |
| "Root"/superuser | Root user | Global Administrator | Super Admin / Org Admin |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Why the shapes match (the shared model) | **00 Cloud Fundamentals** |
| The identity equivalents in depth | **01 Cloud Identity and Federation** |
| Technique → evidence per provider | **00b ATT&CK Cloud to Evidence Map** |
| One actor across these services | **03 Cross-Cloud Correlation** |
| Each provider's own overview | **Amazon/AWS → 00** · **Microsoft → 00** · **Google → 00** |

## Resources

- AWS ↔ Azure service comparison — https://learn.microsoft.com/en-us/azure/architecture/aws-professional/services
- Google Cloud ↔ AWS/Azure comparison — https://cloud.google.com/docs/compare/aws
- MITRE ATT&CK Cloud matrix — https://attack.mitre.org/matrices/enterprise/cloud/
