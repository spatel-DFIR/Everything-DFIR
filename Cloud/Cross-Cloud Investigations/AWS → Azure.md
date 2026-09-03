# AWS → Azure

## Why This Happens

AWS and Azure are separate accounts with separate logins. By default, an AWS identity means **nothing** to Azure, and an Azure identity means nothing to AWS. Nobody walks from one into the other unless someone **deliberately built a bridge**, almost always for an ordinary reason: a script needs to write to Azure Storage, a pipeline that lives in AWS needs to deploy into an Azure resource group, or two clouds' management tooling got wired together.

This direction is real, but it's the less common one, and it's worth saying so plainly before the bridge catalog: **AWS is far more often the destination of cross-cloud federation than the source.** Entra is the identity provider most enterprises centralize on (that traffic runs the other way — see **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)**), and GCP's Workload Identity Federation has a purpose-built provider type for AWS role ARNs. Azure has no equivalent pointed *at* AWS. Every bridge below required someone to deliberately configure a trust relationship or store a credential somewhere reachable — there's no frictionless, native "just works" path from AWS into Azure the way there is from AWS into GCP (see **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** for that contrast).

An actor with a foothold in AWS crosses into Azure using one of these mechanisms:

- **A plain leaked Azure credential in an AWS secret store** — an Entra App Registration's client secret or certificate sitting in Secrets Manager, SSM Parameter Store, or a Lambda/CodeBuild environment variable. No trust relationship exists on either side, and no event connects the two clouds — whoever reads the secret just uses it directly against Azure AD's token endpoint, from wherever they happen to be calling from. This is the "boring" bridge and, as in every direction, the easiest one to miss.
- **AWS registered as a custom OIDC issuer for an Entra federated credential** — the keyless pattern, but hand-built. Entra's federated credentials will trust *any* standards-compliant OIDC issuer, and AWS has a few services that can act as one: a Cognito User Pool minting ID tokens, an EKS cluster's own per-cluster OIDC issuer (normally used only for AWS-internal IRSA), or a fully self-hosted token-vending service backed by AWS STS. Unlike GCP, though, Azure has no native "just trust an AWS IAM role ARN" provider type — someone had to explicitly stand this up and point Entra at it.
- **The Azure Arc identity that Defender for Cloud plants on the AWS side, stolen from the AWS side.** Microsoft Defender for Cloud's AWS connector — the same standing trust the Azure→AWS note covers from the other angle — doesn't just read AWS's inventory. If the Defender for Servers plan is enabled, it auto-installs the Azure Connected Machine agent onto the EC2 instances it discovers, and that agent carries its own Azure identity, cached locally on the AWS-side host. Compromise the EC2 instance and you've compromised something that authenticates directly to Azure Resource Manager — this is the reverse angle of the connector, riding the agent it planted rather than the connector's own AWS-side role.

**The bridge determines what evidence exists on both sides**, and here more than usual that cuts sharply: a stored secret leaves nothing connecting it back to AWS except timing and IP, and the custom-OIDC path can leave close to *nothing* on the AWS side at all if the issuer never touches an AWS API to mint its token. Knowing which bridge you're dealing with tells you which evidence to go looking for — and, more than once in this note, that the honest answer on the AWS side is "there isn't any."

This note works the investigation from the AWS side first (what does "leaving" look like, per bridge), then the Azure side (what does "arriving" look like, per bridge), then ties the two together with the fields that prove it was the same actor both times.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method). See **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** for how this pair sits relative to the other five directional notes.

## Contents

- [The Bridges — AWS → Azure](#the-bridges--aws--azure)
- [Source-Side Investigation — AWS Logs](#source-side-investigation--aws-logs)
- [Destination-Side Investigation — Azure Logs](#destination-side-investigation--azure-logs)
- [Correlation — Tying the AWS Identity to the Azure Session](#correlation--tying-the-aws-identity-to-the-azure-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — AWS → Azure

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|------------|---------------------|
| 1 | **Stored/leaked Azure credential in AWS** | An Entra App Registration's client secret or certificate sits in Secrets Manager (`arn:aws:secretsmanager:us-east-1:123456789012:secret:azure-prod-deploy-sp-secret-Ab12Cd`), SSM Parameter Store (`/prod/azure/sp-client-secret`, SecureString), or a Lambda/CodeBuild environment variable — read and used directly against Azure AD's token endpoint | 🔴 Very common — the "boring" bridge | The secret object itself; no cloud-native trust relationship to find |
| 2 | **AWS as a custom OIDC issuer (Entra federated credential)** | A Cognito User Pool, an EKS cluster's built-in per-cluster OIDC issuer, or a self-hosted token-vending service issues an OIDC-compliant token; an Entra App Registration's federated credential is configured to trust that issuer's URL + subject claim | Uncommon — requires deliberate setup on both ends; no AWS-native "trust an IAM role ARN" provider type exists in Entra | The federated credential's `issuer` / `subject` / `audiences` config on the Entra App Registration |
| 3 | **AWS-hosted CI/CD deploying into Azure** | A CodeBuild project (`codebuild-deploy-to-azure`) or a self-hosted GitHub Actions/GitLab runner on EC2 holds a stored secret (bridge 1) or a federated identity (bridge 2) and pushes changes into Azure via ARM/Bicep/Terraform | Common in shops using AWS as the CI/CD hub even for Azure-hosted workloads | The build project's environment/role config; whichever of bridge 1 or 2 the pipeline actually uses |
| 4 | **Azure Arc agent identity, planted via the Defender for Cloud AWS connector** | Defender for Cloud's Defender for Servers plan auto-provisions the Azure Connected Machine agent onto discovered EC2 instances; the agent authenticates to Azure using a locally-cached certificate served by the Hybrid Instance Metadata Service (HIMDS), bound to an Arc-enabled-server resource in the Azure tenant that owns the connector | Uncommon as a *confirmed* abuse path, but a real standing identity sits on every Arc-onboarded EC2 host whether anyone's abused it yet or not | The Arc agent's local credential material on the compromised EC2 instance + the Arc-enabled-server resource's RBAC role assignments in Azure |
| 5 | **AWS Systems Manager hybrid activations reaching an Azure VM** | An SSM managed-instance activation lets the SSM Agent, installed on an Azure VM, register as an AWS-managed instance under an IAM role — AWS can then run commands on that Azure-hosted machine | Common where Systems Manager is the fleet-management standard | Compute reach only, no Azure identity involved — see **[00 - Cross-Cloud Bridges Overview → Infrastructure Bridges](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair)** for the full treatment |

> Note on scope: AWS Security Hub's cross-account aggregation (and Security Lake, unless a custom cross-cloud source was built) is **not** a credential bridge into Azure — it doesn't appear in the table above on purpose. See the overview note's AWS table, row 6, for why it's excluded rather than assumed missing.

## Source-Side Investigation — AWS Logs

All of this lives in **CloudTrail**. Work the stored-credential bridge first (it's the common case), then the OIDC-issuer bridge (where the honest answer is often "little to nothing"), then the Arc-agent angle.

### Bridge #1 — Secrets Manager / Parameter Store — the stored-credential bridge

| Field | What it tells you | Example value | Read it as |
|-------|--------------------|----------------|------------|
| `eventName` | The retrieval action | `GetSecretValue` / `GetParameter` / `GetParametersByPath` | 🔴 The pivot moment — the secret was read |
| `requestParameters.secretId` (Secrets Manager) or `.name`/`.path` (SSM) | Which secret | `azure-prod-deploy-sp-secret` / `/prod/azure/sp-client-secret` | Confirm it's the one holding the Azure credential |
| `requestParameters.withDecryption` (SSM) | Was the SecureString decrypted | `true` | A `false` read only fetches ciphertext — not yet usable |
| `userIdentity` | Who read it | `arn:aws:iam::123456789012:role/app-server` | 🔴 A human/role that isn't the owning app |
| `sourceIPAddress` / `userAgent` | From where / with what | `203.0.113.45` / `aws-cli/2.15.0` | New IP/geo, or a tool that isn't the app's normal runtime |

```bash
# Inventory secrets that look Azure-related
aws secretsmanager list-secrets --query "SecretList[?contains(Name, 'azure') || contains(Name, 'sp-')]"

# Every read of a specific secret in the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue \
  --start-time 2026-07-01 --end-time 2026-07-16
```

Console path: **Secrets Manager → Secrets** (inventory) or **CloudTrail → Event history** filtered on `GetSecretValue`/`GetParameter`. Full field detail: AWS **[Secrets Manager for DFIR](../Amazon/AWS/Data%20Protection/Secrets%20Manager/Secrets%20Manager%20for%20DFIR.md)**.

### Bridge #2 — AWS as the OIDC issuer

The evidence here depends entirely on *which* AWS service played issuer — and one of the three leaves almost nothing:

| Issuer used | AWS-side signal | Example value | Notes |
|-------------|------------------|----------------|-------|
| **Cognito User Pool** | `eventName = InitiateAuth` / `AdminInitiateAuth`, `eventSource = cognito-idp.amazonaws.com` | `userPoolId: us-east-1_AbCdEfGhI`, `clientId: 1a2b3c4d5e6f7g8h9i0j` | The clearest of the three — a normal, CloudTrail-visible sign-in that happens to mint a reusable OIDC ID token |
| **EKS cluster's built-in OIDC issuer** | 🔴 **None in CloudTrail.** The token is signed locally by the EKS control plane using the cluster's own key and served from the cluster's OIDC discovery/JWKS endpoint — no AWS API call is made to mint it | `https://oidc.eks.us-east-1.amazonaws.com/id/A1B2C3D4E5F6789EXAMPLE` | If this is the issuer, pivot to **EKS/Kubernetes audit logs** for which pod/service account requested a projected token, not CloudTrail |
| **Self-hosted token-vending service** | Whatever the service itself logs — commonly a `GetCallerIdentity` or `AssumeRole` call embedded in its verification logic, plus the Lambda invocation | `eventName: GetCallerIdentity`, `requestParameters: null` | 🔴 `GetCallerIdentity` takes **no input parameters** — CloudTrail's `requestParameters` (and usually `responseElements`) are empty for this call whether it's a routine self-identification check or the exact call a vending service uses to verify a caller before minting a token. **You cannot tell from CloudTrail alone which one it was.** |

> 🔴 **The gap to state explicitly on this bridge:** unless Cognito is the issuer, AWS-side evidence for the token *mint* is thin-to-nonexistent. Don't spend the investigation looking for an AWS-side "federation event" that may not exist — the arrival on the Azure side (below) is often the only place this bridge shows up at all.

```bash
# Cognito: sign-ins to a specific user pool in the window
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventSource,AttributeValue=cognito-idp.amazonaws.com \
  --start-time 2026-07-01 --end-time 2026-07-16

# If a self-hosted vending service is suspected, check its own invocation history
aws lambda get-function --function-name <vending-function-name>
```

Console path: **Cognito → User pools → (pool) → Sign-in experience / App integration** for config; **CloudTrail → Event history** for `cognito-idp.amazonaws.com` events. For a suspected EKS issuer: **EKS console → Cluster → Overview → OpenID Connect provider URL**, then pivot to the cluster's own audit logging (outside CloudTrail's scope).

### Bridge #3 — AWS-hosted CI/CD

Same investigative shape as bridges 1 and 2 — the pipeline is just the actor. The tell is in the build config: a CodeBuild `buildspec.yml` resolving a `secrets-manager:` or `parameter-store:` prefixed environment variable (bridge 1), or a self-hosted runner on EC2/EKS presenting a federated token at deploy time (bridge 2). Pull the **CodeBuild build history** (`aws codebuild batch-get-builds`) or the runner's own job logs alongside the CloudTrail events above — an off-schedule build, or one triggered by an unexpected commit/PR source, is the abuse signature.

### Bridge #4 — Arc agent local credential (via the Defender for Cloud connector)

The interesting evidence here is **on the host**, not in CloudTrail — but CloudTrail shows how the agent got there in the first place: Defender for Cloud's auto-provisioning installs the Connected Machine agent via **SSM Run Command or a State Manager association**, so a `SendCommand`/`CreateAssociation` event referencing an Azure-Arc-related document is the install moment.

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `eventName` | The install mechanism | `SendCommand` / `CreateAssociation` | Look for `documentName` referencing Arc/`AzureConnectedMachineAgent` |
| `requestParameters.documentName` | Which SSM document ran | `AWS-ConfigureAWSPackage` or a custom onboarding doc | Confirms Defender for Cloud's provisioning, not a manual install |
| `requestParameters.instanceIds` / `targets` | Which EC2 instances got the agent | `i-0abc123` | Your inventory of Arc-onboarded AWS hosts |

Once installed, the agent's identity material lives locally on the instance, served over the Hybrid Instance Metadata Service (an IMDS-style local endpoint the agent uses to fetch tokens for itself, analogous to EC2's own IMDS but for the Arc identity). An attacker with root/admin on that EC2 instance can query it, or steal the underlying certificate, to mint Azure Resource Manager tokens for the Arc-enabled-server resource — no AWS credential involved at all from that point forward.

```bash
# Find every EC2 instance the Defender for Cloud connector's provisioning touched
aws ssm list-command-invocations --details \
  --filter "key=DocumentName,value=AWS-ConfigureAWSPackage"
```

Console path: **Systems Manager → Run Command → Command history**, filter by document; on the host itself, confirm the agent's presence (`azcmagent show` if the CLI is present) before assuming compromise. Full SSM field detail: AWS **[Systems Manager (SSM) for DFIR](../Amazon/AWS/Compute/Systems%20Manager%20(SSM)/Systems%20Manager%20(SSM)%20for%20DFIR.md)**.

### Bridge #5 — SSM hybrid activation reaching an Azure VM

This is compute reach, not an Azure identity — AWS runs commands on an Azure-hosted machine via the SSM Agent, exactly as it would against any hybrid-activated on-prem box. Investigate it exactly like any other SSM `SendCommand`/`StartSession` case (see AWS **[Systems Manager (SSM) for DFIR](../Amazon/AWS/Compute/Systems%20Manager%20(SSM)/Systems%20Manager%20(SSM)%20for%20DFIR.md)**); the only cross-cloud-specific step is confirming the target instance's `PlatformName`/tags identify it as Azure-hosted. Full treatment of this mechanism lives in the overview note — don't re-derive it here.

## Destination-Side Investigation — Azure Logs

The `AADServicePrincipalSignInLogs` table is the anchor for bridges 1–3 (an app, not a human, is authenticating); the Activity Log is the anchor for bridge 4 (a resource identity taking action). See Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** and **[Activity Log for DFIR](../Microsoft/Azure/Activity%20Log/Activity%20Log%20for%20DFIR.md)** for the full field references this section applies to each bridge.

### Bridge #1 — Stolen client secret/certificate, used directly

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The SP sign-in itself | `AADServicePrincipalSignInLogs` row | — | No human sign-in exists for this bridge — go straight to the SP tab |
| Which app authenticated | `ServicePrincipalName`, `AppId` | `aws-prod-deploy-sp`, `8f14e45f-ceea-467e-...` | Confirm it's the app whose secret you suspect is burned |
| Where the call came from | `IPAddress` | `52.94.xx.xx` | 🔴 Cross-reference against AWS's published [IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) — a client-secret sign-in that's *only* ever come from your known office/VPN egress suddenly authenticating from an AWS IP/ASN is the tell |
| What it was issued a token for | `ResourceDisplayName` | `Windows Azure Service Management API` | Confirms scope of what the stolen secret can reach |
| Which credential was used | `KeyId` (on the SP object, cross-referenced) | `3fa85f64-5717-4562-b3fc-2c963f66afa6` | Ties the sign-in to a *specific* secret/cert — useful when the app has several |

```kql
// Service-principal sign-ins for a suspect app, all IPs seen
AADServicePrincipalSignInLogs
| where AppId == "8f14e45f-ceea-467e-0000-000000000000"
| project TimeGenerated, ServicePrincipalName, IPAddress, ResourceDisplayName, ResultType
| order by TimeGenerated desc
```

Console path: **Entra admin center → Identity → Monitoring & health → Sign-in logs → Service principal** tab, filter by App ID.

### Bridge #2 — Federated-credential sign-in

The sign-in log shows the same SP-tab evidence as bridge 1 — `AppId`, `ServicePrincipalName`, `IPAddress`, `ResourceDisplayName` — because from Entra's perspective a federated-credential-based token request and a client-secret-based one both land as a service-principal sign-in. **The sign-in log alone won't tell you which one it was.** To confirm federated-credential auth specifically, and to see which AWS-side issuer is trusted, read the App Registration's trust config directly:

```powershell
# List federated credentials on the app — the issuer field names the AWS-side OIDC provider
Get-MgApplicationFederatedIdentityCredential -ApplicationId <app-object-id>
```

| Field (federated credential object) | What it tells you | Example value |
|--------------------------------------|--------------------|-----------------|
| `issuer` | The AWS-side OIDC issuer trusted | `https://cognito-idp.us-east-1.amazonaws.com/us-east-1_AbCdEfGhI` or `https://oidc.eks.us-east-1.amazonaws.com/id/A1B2C3D4E5F6789EXAMPLE` |
| `subject` | The exact external identity trusted | A Cognito `sub` claim (a GUID) or an EKS `system:serviceaccount:<namespace>:<sa-name>` |
| `audiences` | The intended audience | `api://AzureADTokenExchange` (Entra's documented default audience for this pattern) |

🔴 An `issuer`/`subject` pair that's broader than intended — e.g. a `subject` pattern that isn't pinned to the one Cognito user or one Kubernetes service account it should be — is this bridge's version of the over-broad-trust misconfig common to every OIDC pattern in this repo.

Console path: **Entra admin center → App registrations → (app) → Certificates & secrets → Federated credentials.**

### Bridge #3 — CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline used; the distinguishing signal is the source IP falling in AWS's published CodeBuild/EC2 ranges and the sign-in cadence matching a build schedule rather than a human's working hours.

### Bridge #4 — Arc-enabled-server identity acting in Azure

| Field (Azure Activity Log) | What it tells you | Example value | Notes |
|------------------------------|--------------------|-----------------|-------|
| `caller` | The Arc machine's identity | A system-assigned managed identity object ID, e.g. `9c3d1a2b-4c5e-4f6a-9b7c-1e2f3a4b5c6d` | Not a UPN — this is a resource identity, not a human |
| `resourceId` | The Arc-enabled-server resource | `/subscriptions/.../resourceGroups/rg-hybrid/providers/Microsoft.HybridCompute/machines/aws-ec2-i-0abc123` | Naming conventions that embed the EC2 instance ID make this correlation trivial when present |
| `operationName.value` | What it did | `Microsoft.Authorization/roleAssignments/write` | 🔴 The identity gaining or using privilege, not just existing |
| `callerIpAddress` | Where the call came from | `52.94.xx.xx` | Should be the compromised EC2 instance's outbound IP — a strong cross-cloud anchor |

```kql
// Actions taken by Arc-enabled-server identities (system-assigned MI naming is inconsistent —
// filter by resource type on the target instead)
AzureActivity
| where _ResourceId has "Microsoft.HybridCompute/machines"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
| order by TimeGenerated desc
```

Console path: **Azure portal → Azure Arc → Machines** (inventory + per-machine identity/role assignments); **Activity log**, filtered by resource, for what the identity actually did.

### Bridge #5 — SSM hybrid reaching an Azure VM

No Azure identity evidence exists for this bridge — it's guest-OS command execution, invisible to Entra and the Activity Log alike. Work it from the VM's own guest-level artifacts (shell/PowerShell history, the SSM Agent's local logs) exactly as you would any other host-level compromise; the cross-cloud angle is establishing *why* an AWS-issued command reached an Azure VM in the first place (the hybrid activation itself, on the AWS side).

## Correlation — Tying the AWS Identity to the Azure Session

| Anchor | AWS side | Azure side | Example match | Strength |
|--------|----------|------------|-----------------|----------|
| Source IP | `sourceIPAddress` (Secrets Manager/SSM read, or the vending service's caller) | `IPAddress` (SP sign-in) / `callerIpAddress` (Activity Log) | `52.94.xx.xx` ↔ `52.94.xx.xx` | Medium–High — strong when the same host does the read *and* the sign-in; weaker if a build system relays through a different egress |
| Timing | `eventTime` of the secret read or `GetCallerIdentity` call | `TimeGenerated` of the SP sign-in | A read at `14:22:01Z`, a sign-in at `14:22:04Z` | High when within seconds — the credential is used immediately after being read |
| The credential's `KeyId` | Not visible on the AWS side | `KeyId` on the sign-in, cross-referenced to the App Registration's `Certificates & secrets` | A specific secret/cert's key ID matches what was stored where it was leaked | High — ties a *specific* stored credential to a *specific* sign-in |
| The OIDC issuer/subject (bridge 2) | The issuer's own identifier (Cognito pool ID, EKS cluster's OIDC URL) | `issuer`/`subject` on the federated credential | `us-east-1_AbCdEfGhI` ↔ the same pool ID in the `issuer` URL | High — a direct claim-to-claim match, when the AWS side is visible at all |
| Resource naming convention | The EC2 instance ID | The Arc-enabled-server resource name (bridge 4) | `i-0abc123` ↔ `aws-ec2-i-0abc123` | Medium — depends entirely on whether your onboarding tagged/named things predictably |

## Hunt at Scale

```sql
-- CloudTrail Lake SQL: reads of secrets/parameters with Azure-sounding names, by principals
-- outside a known allowlist, last 7 days
SELECT eventTime, userIdentity.arn, sourceIPAddress,
       eventName, requestParameters
FROM cloudtrail_lake_event_table
WHERE eventName IN ('GetSecretValue','GetParameter','GetParametersByPath')
  AND (element_at(requestParameters, 'secretId') LIKE '%azure%'
       OR element_at(requestParameters, 'name') LIKE '%azure%')
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC
```

```kql
// KQL: service-principal sign-ins whose IP falls outside your known ranges, joined against
// a watchlist of AWS-published CIDR blocks (maintain the watchlist from ip-ranges.amazonaws.com)
AADServicePrincipalSignInLogs
| where IPAddress in (AWS_IPRanges_Watchlist)   // KQL watchlist populated from AWS's ip-ranges.json
| project TimeGenerated, ServicePrincipalName, AppId, IPAddress, ResourceDisplayName
| order by TimeGenerated desc
```

```kql
// KQL: Arc-enabled-server identities performing role assignments or other write ops
AzureActivity
| where _ResourceId has "Microsoft.HybridCompute/machines"
| where OperationNameValue has "write"
| project TimeGenerated, Caller, CallerIpAddress, OperationNameValue, _ResourceId
```

A modest cross-cloud SecOps/UDM landing point: normalize the AWS-side secret read (`target.resource.name` = secret ARN) and the Azure-side SP sign-in (`target.application` = `AppId`) to a shared `principal.asset.ip`, and alert when the same IP touches an AWS secret matching an Azure-naming pattern and an Azure SP sign-in within a tight window — the two-sided version of the same "arriving from nowhere" pattern the other directional notes use.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A service-principal sign-in from an AWS IP/ASN with no known AWS-side integration | Bridge #1 or #3 in progress — a stolen secret being used from AWS-hosted infrastructure |
| A federated credential's `issuer`/`subject` you don't recognize on an App Registration | Bridge #2 freshly created — likely persistence, not legitimate use |
| `GetCallerIdentity` calls from a principal that has no reason to self-identify | Possibly the token-vending half of bridge #2 — thin signal, but worth a look given how little else this bridge leaves |
| An Arc-enabled-server resource (`Microsoft.HybridCompute/machines`) with an RBAC role assignment broader than "report inventory" | Bridge #4's blast radius — the agent has more reach in Azure than onboarding required |
| `SendCommand`/`CreateAssociation` installing an Arc-related package on an EC2 instance nobody remembers onboarding | New standing Azure identity being planted on AWS-side compute |
| A Secrets Manager/Parameter Store entry matching an Azure-credential naming pattern read by an unexpected principal | Bridge #1 in progress — pivot to Azure immediately, assume the credential is burned |
| Cognito User Pool `InitiateAuth` activity from a principal/IP with no legitimate reason to authenticate end users | Possible abuse of Cognito as an OIDC-issuer bridge |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| The full bridge inventory across all six directional pairs | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| AWS identity types and access-key decoding | AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** |
| AWS secret-store investigation in depth | AWS **[Secrets Manager for DFIR](../Amazon/AWS/Data%20Protection/Secrets%20Manager/Secrets%20Manager%20for%20DFIR.md)** |
| AWS Systems Manager (SSM) investigation in depth | AWS **[Systems Manager (SSM) for DFIR](../Amazon/AWS/Compute/Systems%20Manager%20(SSM)/Systems%20Manager%20(SSM)%20for%20DFIR.md)** |
| Entra sign-in log deep dive | Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| App Registrations, service principals, federated credentials | Microsoft **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| Azure Activity Log deep dive (Arc-identity actions) | Microsoft **[Activity Log for DFIR](../Microsoft/Azure/Activity%20Log/Activity%20Log%20for%20DFIR.md)** |
| The Defender for Cloud multicloud connector | Microsoft **[Microsoft Defender for Cloud for DFIR](../Microsoft/Azure/Microsoft%20Defender%20for%20Cloud/Microsoft%20Defender%20for%20Cloud%20for%20DFIR.md)** |
| This pair from the other direction | **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- AWS: `GetCallerIdentity` API reference (note the empty request/response shape) — https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- AWS: IP address ranges (JSON feed) — https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
- AWS: Cognito user pool JWTs — https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
- AWS: IAM roles for service accounts (IRSA) / EKS OIDC issuer — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- Microsoft: Configure an app to trust an external identity provider (federated credentials) — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- Microsoft: Workload identity federation overview — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Microsoft: Azure Arc-enabled servers agent security overview (HIMDS) — https://learn.microsoft.com/en-us/azure/azure-arc/servers/security-overview
- Microsoft: Onboard AWS accounts to Microsoft Defender for Cloud — https://learn.microsoft.com/en-us/azure/defender-for-cloud/quickstart-onboard-aws
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
