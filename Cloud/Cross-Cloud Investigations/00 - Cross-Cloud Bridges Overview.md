# Cross-Cloud Bridges Overview

By default, AWS doesn't know Azure exists. Azure doesn't know GCP exists. GCP doesn't know AWS exists. Each is a separate account, a separate login, a separate trust boundary — an identity that works in one means literally nothing in either of the other two. Nobody walks from one cloud into another unless somebody **built a bridge**, almost always for a normal business reason: a human wants one login instead of three (SSO), a pipeline needs to deploy into a second cloud without storing a password (keyless federation), a backup tool needs to replicate data into a second cloud's storage, or two clouds' networks got wired together so traffic can move between them privately.

That bridge is exactly what an actor rides across once they have a foothold in one cloud. This note is the **map of every bridge shape**, organized by which cloud the actor starts in — so you can look up "I'm inside AWS, where could this actor be headed, and how" (or Azure, or GCP) and get the realistic inventory. It is **not** the deep investigation of any one bridge — each mechanism below points forward to a **directional note** (`AWS → Azure`, `AWS → GCP`, `Azure → AWS`, `Azure → GCP`, `GCP → AWS`, `GCP → Azure`) that works that specific pair end-to-end: source-side evidence, destination-side evidence, and the fields that prove it's the same actor on both sides.

Two things worth knowing before you scan the tables:

- **Bridges aren't only identity.** A federated login or a stolen access key is the obvious kind, but two clouds can also be wired together at the *infrastructure* layer — a private network circuit, a hybrid-management agent that lets one cloud's console reach into another's virtual machines, a backup/DR tool holding a foreign credential, an ETL pipeline reading data out of a second cloud's storage, or a security platform's cross-account connector. None of those need a "login" to become a path across, and some of them leave **no identity trail at all** — pure network or job-history evidence.
- **The three clouds are not mirror images of each other.** A mechanism that's native and effortless in one direction can require a fully custom setup — or not exist at all — in reverse. Where that's true, this note says so explicitly rather than forcing a tidy three-way symmetry that doesn't reflect how these platforms actually work.

Read this with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity-shape vocabulary used throughout) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method for stitching logs across clouds once you know which bridge you're dealing with).

## Contents

- [AWS's Outbound Bridges](#awss-outbound-bridges)
- [Azure's Outbound Bridges](#azures-outbound-bridges)
- [GCP's Outbound Bridges](#gcps-outbound-bridges)
- [Infrastructure Bridges That Cut Across Every Pair](#infrastructure-bridges-that-cut-across-every-pair)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## AWS's Outbound Bridges

What a compromise of AWS can be used to reach. AWS is more often the *destination* than the *source* in cross-cloud federation (see the asymmetry callout below) — its strongest outbound paths are stored credentials, CI/CD, and workload federation into GCP.

| # | Mechanism | How it works | How common | Reaches | Depth |
|---|-----------|---------------|-------------|---------|-------|
| 1 | **Stored/leaked Azure or GCP credential in AWS** | An Azure SP client secret/certificate or a GCP service-account key (JSON) sits in Secrets Manager (`arn:aws:secretsmanager:us-east-1:123456789012:secret:azure-prod-deploy-sp-secret-Ab12Cd`), SSM Parameter Store (`/prod/gcp/etl-sa-key`, SecureString), or a Lambda/ECS/CodeBuild environment variable — read and used directly, no trust relationship involved | 🔴 Very common — the "boring" bridge | Azure, GCP | → `AWS → Azure.md` / `AWS → GCP.md` |
| 2 | **AWS-hosted CI/CD deploying cross-cloud** | A CodeBuild project (`codebuild-deploy-to-azure`) or a self-hosted GitHub Actions/GitLab runner on EC2 holds a stored key or a federated identity and pushes changes into Azure or GCP | Common in shops using AWS as the CI/CD hub | Azure, GCP | → both notes |
| 3 | **GCP Workload Identity Federation — native AWS provider** | A GCP workload identity pool provider is created with `gcloud iam workload-identity-pools providers create-aws`, mapping `google.subject=assertion.arn`. It trusts AWS IAM role ARNs *directly* — the AWS-side caller signs a normal `sts:GetCallerIdentity` request with its own AWS credentials, and GCP's STS verifies that signature against AWS to hand back a short-lived Google token. No IAM OIDC provider, no thumbprint, no AWS-side config at all | 🔴 Growing fast — the modern default for AWS workloads reaching GCP | GCP only | → `AWS → GCP.md` |
| 4 | **IAM Identity Center as an external SAML IdP** | Identity Center can be configured as the identity source for a custom external SAML application (Entity ID like `https://portal.sso.us-east-1.amazonaws.com/saml/metadata/AbCdEf123`), in principle including a GCP Workforce Identity Federation SAML provider or an Entra External ID guest source | Rare / atypical direction — AWS is almost always the *relying party* in cross-cloud federation, not the identity source | Azure, GCP (uncommon) | → both notes |
| 5 | **AWS Systems Manager hybrid/multicloud activations** | An SSM managed-instance activation (Activation Code + Activation ID `a-1234567890abcdef0`) lets the SSM Agent, installed on an Azure VM or a GCP Compute Engine instance, register as an AWS-managed instance (`mi-0a1b2c3d4e5f6g7h8`) under an IAM role (`arn:aws:iam::123456789012:role/SSMHybridInstanceRole`) — AWS can then run commands, patch, and open sessions on that non-AWS machine | Common where Systems Manager is the fleet-management standard | Azure, GCP (compute reach, not console/API access) | → [Infrastructure Bridges](#infrastructure-bridges-that-cut-across-every-pair) |
| 6 | **Security Hub cross-account aggregation / Security Lake** | Security Hub's finding aggregator (`arn:aws:securityhub:us-east-1:123456789012:finding-aggregator/1a2b3c4d`) is **AWS-Organization-scoped only** — it does not itself reach Azure or GCP. Security Lake (OCSF-normalized) is the piece that *can* ingest custom third-party sources, occasionally including data pulled from another cloud | Common for the aggregation itself; genuinely cross-cloud only if a custom Security Lake source was built | Visibility only — not a credential/access path | n/a — awareness item |

## Azure's Outbound Bridges

Entra is the most common central-IdP choice in the enterprises this repo covers, which makes Azure the most frequent *source* cloud in real intrusions — the richest outbound catalog of the three. Full AWS-direction depth already exists in `Azure → AWS.md`; the GCP-direction rows below are the mirror image, not yet in their own note.

| # | Mechanism | How it works | How common | Reaches | Depth |
|---|-----------|---------------|-------------|---------|-------|
| 1 | **Federated SSO (Entra as external IdP)** | A human signs into Entra; Entra vouches for them over SAML to AWS IAM Identity Center / a direct IAM SAML provider, or to a GCP Workforce Identity Federation SAML/OIDC pool | 🔴 Very common — the default enterprise pattern | AWS, GCP | → `Azure → AWS.md` (full depth) / `Azure → GCP.md` |
| 2 | **Workload identity federation (Entra federated credentials)** | An Entra App Registration presents an Entra-issued token (issuer `https://login.microsoftonline.com/72f988bf-.../v2.0`) to an AWS IAM OIDC provider or a GCP workload identity pool's generic OIDC provider — keyless, no password stored anywhere | Growing — the modern CI/CD pattern | AWS, GCP | → both notes |
| 3 | **Azure DevOps OIDC service connection** | Azure DevOps itself (not Entra) is the OIDC issuer (`vstoken.dev.azure.com/<org-id>`); an AWS role trust policy or a GCP pool provider trusts a specific org/project/pipeline subject | Common in shops using Azure DevOps against AWS or GCP infra | AWS, GCP | → both notes |
| 4 | **Stored/leaked AWS or GCP credential in Azure** | An `AKIA` key or a GCP SA key (JSON) sits in Key Vault (`https://corp-kv.vault.azure.net/secrets/gcp-prod-sa-key/`), App Service application settings, an Automation Account variable, or an Azure DevOps pipeline variable | 🔴 Very common — the "boring" bridge | AWS, GCP | → both notes |
| 5 | **Microsoft Defender for Cloud / Sentinel multicloud connectors** | The **AWS connector** deploys a cross-account IAM role (`arn:aws:iam::123456789012:role/DefenderForCloudAWSConnector`) trusted via web-identity federation (historically with an `sts:ExternalId` condition); the **GCP connector** instead uses GCP Workload Identity Federation + service-account impersonation (`mdc-gcp-connector@project.iam.gserviceaccount.com`) — genuinely keyless, no stored secret on either side | Common — the standard multicloud CSPM onboarding path | AWS, GCP | → `Azure → AWS.md` (AWS side) / `Azure → GCP.md` |
| 6 | **Azure Arc multicloud connector** | Discovers and onboards AWS EC2 instances and GCP Compute Engine VMs into Azure's management plane via the Connected Machine agent, over API calls with no agent required just for inventory | Established for AWS; **GCP support in public preview** as of mid-2026 | AWS, GCP | → [Infrastructure Bridges](#infrastructure-bridges-that-cut-across-every-pair) |
| 7 | **Azure Data Factory / Synapse linked service** | A linked service (`ls_aws_s3_prod`) holds an AWS access key or a GCP SA key, stored in Key Vault or ADF's own credential store, to read/write S3 or Cloud Storage | Common in data-engineering estates | AWS, GCP | → [Infrastructure Bridges](#infrastructure-bridges-that-cut-across-every-pair) |

## GCP's Outbound Bridges

GCP's Workload Identity Federation is the most actively developed keyless-federation product of the three, and it shows in the outbound catalog: GCP has native, purpose-built federation into AWS that neither AWS nor Azure mirrors, plus a cross-cloud analytics engine (BigQuery Omni) with no equivalent elsewhere.

| # | Mechanism | How it works | How common | Reaches | Depth |
|---|-----------|---------------|-------------|---------|-------|
| 1 | **Stored/leaked AWS or Azure credential in GCP** | An `AKIA` key or an Azure SP client secret sits in Secret Manager (`projects/987654321000/secrets/azure-sp-secret/versions/latest`), a Cloud Functions environment variable, or a Cloud Build substitution variable | 🔴 Very common — the "boring" bridge | AWS, Azure | → `GCP → AWS.md` / `GCP → Azure.md` |
| 2 | **GCP service-account identity token → AWS's built-in Google provider** | A GCP service account mints an OIDC ID token (`generateIdToken`, issuer `https://accounts.google.com`, `sub` = the SA's numeric unique ID, e.g. `103547991597142817347`). AWS **already has `accounts.google.com` registered as a built-in federated identity provider** — no customer-created IAM OIDC provider resource needed, only a role trust-policy condition on `accounts.google.com:aud`/`:sub` | 🔴 Growing — one of the lowest-friction cross-cloud federation setups that exists | AWS | → `GCP → AWS.md` |
| 3 | **GCP service-account identity token → Azure federated credential** | The same SA identity token (issuer `https://accounts.google.com`) is trusted by an Entra App Registration's federated credential — Azure treats Google as any standards-compliant OIDC issuer, but (unlike AWS) still requires the customer to explicitly register the issuer/subject | Less common, but documented and supported | Azure | → `GCP → Azure.md` |
| 4 | **Google Workspace / Cloud Identity as external SAML IdP for AWS** | Workspace is registered as the external identity source for AWS IAM Identity Center over SAML 2.0 (`Google SSO URL` + `Google Issuer URL` pasted into the Identity Center IdP config) | Common in Workspace-centric orgs | AWS | → `GCP → AWS.md` |
| 5 | **Google as a federation source for Entra guest sign-in** | Entra External ID accepts Google as a direct federation source for B2B guest invitations — the inverse of the usual "Entra is the central IdP" pattern | Uncommon — an inversion pattern, but real | Azure | → `GCP → Azure.md` |
| 6 | **BigQuery Omni** | GCP's cross-cloud analytics engine queries data directly in S3 or Azure Blob Storage; query compute runs in GCP-managed infrastructure inside the target cloud's region, authenticating via a GCP-controlled `accounts.google.com` identity trusted by a customer-created AWS IAM role (`arn:aws:iam::123456789012:role/bigquery-omni-role`) — no cross-cloud data movement required, and Google never holds an AWS/Azure credential | 🔴 Growing in data-engineering shops, unique to GCP | AWS, Azure (data-plane reach) | → [Infrastructure Bridges](#infrastructure-bridges-that-cut-across-every-pair) |
| 7 | **GKE attached clusters (Fleet, formerly Anthos)** | GCP's fleet-management layer registers an existing AWS EKS or Azure AKS cluster (`projects/my-project/locations/global/memberships/eks-prod-cluster`) via a Connect Agent pod running inside that cluster, using a GCP-issued credential and a Kubernetes RBAC binding — GCP's console/API can then reach into the attached cluster | Native multicloud GKE (GKE on AWS/Azure) was deprecated March 2025; the attached-clusters/Fleet registration pattern that replaced it is current | AWS, Azure (Kubernetes reach) | → [Infrastructure Bridges](#infrastructure-bridges-that-cut-across-every-pair) |

> 🔴 **The three clouds are not symmetric on federation.** GCP ↔ AWS is close to frictionless in both directions: GCP has a purpose-built native AWS provider type in Workload Identity Federation (AWS table, row 3), and AWS has Google's issuer pre-registered as a built-in federated provider (GCP table, row 2) — neither side needs to stand up a generic OIDC-provider resource. Azure sits outside that shortcut: federating either direction between Azure and AWS, or Azure and GCP, always requires an explicitly customer-created OIDC/SAML trust object (an IAM OIDC provider, a GCP pool provider, an Entra federated credential). When auditing what trust exists, check the frictionless shortcut paths first — they're easy to set up and easy to forget about — before assuming every federation path required deliberate, documented setup.

## Infrastructure Bridges That Cut Across Every Pair

These aren't identity mechanisms — they're **wiring**. Which two clouds are connected this way has more to do with which vendor an org picked for backup/ETL/hybrid-management than with which cloud got compromised first. Investigate them by asking "is this pair wired together at all," not "which side is the source."

### Network Interconnects

| Pair | AWS side | Azure side | GCP side | Notes |
|------|----------|------------|----------|-------|
| AWS ↔ Azure | Direct Connect | ExpressRoute | — | Usually bridged via a colo/partner exchange (Megaport, Equinix) |
| AWS ↔ GCP | Direct Connect / **AWS Interconnect – Multicloud** | — | Cloud Interconnect / **Cross-Cloud Interconnect** | AWS and Google announced a joint direct-peering partnership (public preview, December 2025) that removes the third-party colo from the picture |
| Azure ↔ GCP | — | ExpressRoute | Cloud Interconnect | Still colo-brokered as of this writing; Azure is expected to join the AWS↔GCP direct-peering model in 2026 |

🔴 No identity event exists on either side of any of these. An actor who reaches a second cloud's resources over a private interconnect leaves **network evidence only** — VPC Flow Logs / NSG Flow Logs on the addresses in the peered range, and the interconnect gateway's own connection logs. State this gap explicitly in a timeline; don't expect an IAM trail to confirm or deny it.

### Hybrid Management Agents

Each cloud has its own version of "reach into a machine or cluster that physically runs somewhere else":

| Tool | Owning cloud | Reaches | What it plants on the target |
|------|--------------|---------|-------------------------------|
| Azure Arc (multicloud connector) | Azure | AWS EC2, GCP Compute Engine (preview) | The **Connected Machine agent** + an Arc-enabled-server resource with its own Azure identity |
| AWS Systems Manager hybrid activations | AWS | Azure VMs, GCP Compute Engine | The **SSM Agent**, registered as a managed instance under an IAM role |
| GKE attached clusters (Fleet) | GCP | AWS EKS, Azure AKS | A **Connect Agent** pod + a Kubernetes RBAC binding trusting a GCP-issued credential |

The investigative shape is the same for all three: find the agent/credential planted on the target cloud's compute, then check whether the **managing cloud's console/API** was used to run anything through it — that's the actual lateral-movement moment, not the onboarding itself.

### Backup / DR Replication

A backup or DR tool running in one cloud holds a stored (occasionally federated) credential for a second cloud so it can replicate data there. Investigate it exactly like the stored-credential bridge (per-source tables above), corroborated against **the tool's own job/run history** — a burst of cross-cloud read/write activity that lines up with a scheduled backup job is expected; one that doesn't is the anomaly.

| Tool | Typically runs in | Holds a credential for |
|------|--------------------|--------------------------|
| AWS Backup (cross-account/cross-Region copy) | AWS | Another AWS account/Region — not natively cross-cloud, but a common on-ramp when paired with a stored foreign-cloud secret |
| Azure Backup | Azure | Azure-native; cross-cloud replication is usually third-party (below) |
| Google Backup and DR Service | GCP | GCP-native; same caveat |
| Veeam / Commvault / Rubrik / Cohesity (third-party) | Wherever the agent/VM is deployed | Whichever cloud's storage it's configured to replicate into — identify direction by where the agent actually runs, not by the product name |

### ETL / Data Pipeline Tooling

Same shape as backup/DR — a stored credential, not a trust relationship, in the common case:

| Tool | Owning cloud | Typically reaches |
|------|--------------|---------------------|
| Azure Data Factory / Synapse (linked service) | Azure | AWS S3, GCP Cloud Storage |
| AWS Glue / Database Migration Service | AWS | Azure Blob/SQL, GCP Cloud Storage/BigQuery |
| GCP Dataflow / Datastream | GCP | AWS S3, Azure Blob |
| BigQuery Omni | GCP | AWS S3, Azure Blob — 🔴 the one exception that's federated, not a stored key (see GCP's table above) |

### Security-Tooling Connectors

| Connector | Owning cloud | Reaches | Auth mechanism |
|-----------|--------------|---------|------------------|
| Microsoft Defender for Cloud — AWS connector | Azure | AWS | Cross-account IAM role, web-identity federation trust |
| Microsoft Defender for Cloud — GCP connector | Azure | GCP | Workload Identity Federation + SA impersonation (fully keyless) |
| Google Security Command Center (Enterprise tier) | GCP | AWS, Azure | Newer/less established than Defender for Cloud's connectors; reads AWS IAM and Entra ID identity data for cross-cloud identity visibility |
| AWS Security Hub cross-account aggregation | AWS | Other AWS accounts only | **Not cross-cloud** — listed to be explicit that AWS has no direct equivalent to the other rows; AWS Security Lake (OCSF) is the closer analog if a custom cross-cloud source was built |

## Red Flags

| 🔴 | Meaning |
|----|---------|
| An OIDC/WIF trust condition missing a scoped `aud`/`sub`/attribute condition (any AWS role trust policy, GCP pool-provider attribute condition, or Entra federated-credential subject) | Any external tenant/account/repo can mint credentials through it — audit regardless of confirmed abuse |
| A new federated identity credential, WIF pool provider, or IAM OIDC provider nobody on the team recognizes | Persistence — an attacker who can create their own trust doesn't need to steal a token |
| A long-lived foreign-cloud credential (`AKIA`, SP client secret, SA key JSON) sitting in a secret store, pipeline variable, or app config | The "boring" bridge — assume it's usable the moment it's found; treat it as burned |
| A federation event (`AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity`, a GCP STS token exchange, an Entra federated sign-in) with no matching sign-in/mint event on the source side | Token minted or replayed outside the expected flow, or a logging-scope/retention gap |
| A cross-account/cross-cloud connector role (Defender for Cloud, Security Command Center, Azure Arc, a backup/ETL agent) assumed from outside its documented owner ranges | The standing trust is being abused, not the tool itself compromised |
| A hybrid-management agent (Arc Connected Machine agent, SSM Agent, GKE Connect Agent) newly installed on a machine, or a managed-instance/fleet-membership registration nobody requested | A new remote-control path into that compute, planted as persistence |
| Traffic to a second cloud's resources over a private interconnect with no matching IAM/audit trail on either side | Expected — this bridge is invisible to identity logging; widen to Flow Logs instead of expecting a login story |
| An externally-issued identity token (Entra, GCP SA, or any OIDC issuer) presented from an unexpected source IP/ASN relative to where that workload normally runs | Token theft/replay, not the workload's normal presentation path |
| A GCP service account minting identity tokens (`generateIdToken`) outside its normal pipeline schedule, especially with an external cloud as the intended audience | GCP table row 2/3 being exercised — the account may be reaching AWS or Azure right now |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes referenced throughout (human vs workload, long-lived vs temporary, federation) | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method — anchors, log normalization, unified timeline | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| Cross-provider service-name equivalents | **[Cloud Service Equivalents](../06%20-%20Cloud%20Service%20Equivalents%20(AWS%20%E2%86%94%20Azure%20%E2%86%94%20GCP).md)** |
| A full multi-cloud intrusion, worked step by step | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |
| AWS as the source cloud, full depth | **[AWS → Azure](AWS%20%E2%86%92%20Azure.md)** · **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** |
| Azure as the source cloud, full depth | **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** · **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** |
| GCP as the source cloud, full depth | **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** · **[GCP → Azure](GCP%20%E2%86%92%20Azure.md)** |

## Resources

- AWS: Creating an OIDC identity provider for IAM — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html
- AWS Security Blog: Access AWS using a Google Cloud Platform native workload identity — https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/
- Google Cloud: Configure Workload Identity Federation with AWS or Azure VMs — https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds
- Microsoft: Workload identity federation (federated credentials) — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Microsoft: What is the multicloud connector enabled by Azure Arc — https://learn.microsoft.com/en-us/azure/azure-arc/multicloud-connector/overview
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004) — https://attack.mitre.org/matrices/enterprise/cloud/
