# Azure → AWS

## Why This Happens

Azure and AWS are separate accounts with separate logins. By default, an Azure identity means **nothing** to AWS, and an AWS identity means nothing to Azure — the two clouds don't know each other exist. Nobody can walk from one into the other unless someone **deliberately built a bridge** between them, almost always for a normal business reason: single sign-on so employees don't need a second password, a CI/CD pipeline that needs to deploy into AWS, or a script that needs to read a file out of an S3 bucket.

That bridge is exactly what an attacker rides across. An actor with a foothold in Azure/Entra crosses into AWS using one of three technical mechanisms — this note calls them "bridges," and which one was used determines what an investigator can and can't find:

- **Federated SSO** — a *human* logs into Entra, and Entra vouches for them to AWS over SAML (or, with IAM Identity Center, an SSO-brokered version of the same idea). If a phished employee's Entra account has SSO access into AWS, whoever now controls that Entra account has that same AWS access — no separate "AWS hack" needed, just the trust relationship the organization already configured. This leaves a sign-in event on the Azure side and a distinct federation API call on the AWS side.
- **A keyless OIDC trust (workload identity federation)** — the same idea as SSO, but for a *machine* (a CI/CD pipeline, an app) instead of a human, and with no password or long-lived secret stored anywhere. The workload proves who it is with a short-lived, cryptographically signed token instead of a credential. "Keyless" is the important word here: there's no secret for an attacker to steal, and no secret for you to find in a scan — the abuse instead targets the *trust configuration itself* (a role trust policy that's scoped too loosely lets tokens from an unintended source in).
- **A plain leaked AWS credential in an Azure secret store** — an AWS access key sitting in Key Vault, an app's config settings, or a pipeline variable. No trust relationship at all, and no login event either — whoever reads that secret can just use it directly against AWS, from anywhere. This is the "boring" bridge and the easiest one to miss, because neither side logs anything that says "federation happened."

**The bridge determines what evidence exists on both sides.** SSO and OIDC bridges leave a trust configuration to audit *and* a matching pair of events (one leaving Azure, one arriving in AWS). The leaked-credential bridge leaves neither — just a key being used from a new place, with no story connecting it back to Azure except timing and IP. Knowing which bridge you're dealing with tells you which evidence to go looking for, and which evidence's *absence* is itself information (no matching Entra sign-in doesn't mean nothing happened — it can mean it's a stolen key, not a federation abuse).

This note works the investigation from the Azure/Entra side first (what does "leaving" look like, per bridge), then the AWS side (what does "arriving" look like, per bridge), then ties the two together with the specific fields that prove it was the same actor both times.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method — anchors, normalization, timeline). This note is the pair-specific depth those two stay generic about.

## Contents

- [The Bridges — Azure → AWS](#the-bridges--azure--aws)
- [Source-Side Investigation — Azure/Entra Logs](#source-side-investigation--azureentra-logs)
- [Destination-Side Investigation — AWS Logs](#destination-side-investigation--aws-logs)
- [Correlation — Tying the Azure Identity to the AWS Session](#correlation--tying-the-azure-identity-to-the-aws-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — Azure → AWS

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|------------|---------------------|
| 1 | **IAM Identity Center SSO (Entra as external IdP)** | Entra ID is registered as the SAML IdP for AWS IAM Identity Center; the human signs into Entra, gets redirected into AWS SSO with a permission-set role. | 🔴 Very common — the default enterprise pattern. | The Entra **Enterprise Application** for AWS SSO + the Identity Center's IdP config. |
| 2 | **Direct SAML federation (no Identity Center)** | An IAM SAML identity provider is configured straight in IAM (`aws:samlprovider`); Entra issues the SAML assertion; the caller does `sts:AssumeRoleWithSAML` directly. | Less common now (Identity Center is the modern default) but still seen in older estates. | The IAM SAML provider resource + the role's trust policy. |
| 3 | **OIDC / Workload Identity Federation (Entra as token issuer)** | An AWS IAM OIDC identity provider is registered pointing at Entra's issuer (`https://login.microsoftonline.com/<tenant>/v2.0`); an Entra App Registration (with a federated credential or its own token) presents an Entra-issued token to `sts:AssumeRoleWithWebIdentity`. | Growing — the "keyless" pattern for cross-cloud CI/CD and workloads. | The AWS OIDC provider (issuer URL + thumbprint/audience) + the role's trust policy `Condition` on `aud`/`sub`. |
| 4 | **Azure DevOps OIDC service connection → AWS** | Azure DevOps itself (not Entra) acts as the OIDC issuer; an AWS role trust policy trusts Azure DevOps's issuer for a specific organization/project/pipeline subject. | Common in shops using Azure DevOps as CI/CD against AWS infra. | The AWS role trust policy's `token.actions.githubusercontent.com`-style condition, but for `vstoken.dev.azure.com`. |
| 5 | **Stored/leaked AWS credentials in Azure** | A long-term `AKIA` key or an `ASIA` session sits in Azure Key Vault, App Service application settings, an Automation Account variable, a Logic App connection, or an Azure DevOps pipeline variable — read by the actor and used directly against AWS. | 🔴 Very common — the "boring" bridge, easy to miss. | The secret object itself; no cloud-native trust relationship to find. |
| 6 | **Microsoft Defender for Cloud / Sentinel multicloud connector** | Onboarding AWS to Defender for Cloud or Sentinel deploys a cross-account IAM role in AWS, trusted by a Microsoft-owned AWS account (with an external ID). Compromising the Azure tenant that owns the connector can, in theory, ride that trust. | Rare as an abuse path, but a real standing trust edge worth knowing about. | The AWS cross-account role's trust policy — principal is a Microsoft AWS account, condition is the external ID. |
| 7 | **Data pipeline / ETL tooling (Azure Data Factory, Synapse)** | A Data Factory linked service holds an AWS access key (or, less often, assumes a role via a configured connection) to read/write S3. | Common in data-engineering estates. | The linked-service credential (stored in Key Vault or ADF's own credential store). |
| 8 | **Backup/DR & third-party agents** | Third-party backup/replication software (Veeam, Commvault, Rubrik, etc.) running in Azure holds AWS credentials to replicate into S3/Glacier. | Common in hybrid backup architectures. | The agent's stored AWS credential, usually outside any cloud-native audit trail. |
| 9 | **Network interconnect (ExpressRoute ↔ AWS Direct Connect)** | A colo/partner exchange (Megaport, Equinix, etc.) bridges an Azure VNet and an AWS VPC at the network layer — no identity crosses, but an actor on an Azure VM can reach AWS-hosted resources directly over the private link. | Uncommon, but seen in large enterprises with dual-cloud data centers. | The interconnect/gateway config; **no IAM trail on either side** — this is the one bridge that's purely network evidence. |

## Source-Side Investigation — Azure/Entra Logs

Work these in order: sign-in evidence first (who authenticated and into what), then the audit trail for anything that *created or changed* a bridge (new federated credential, new Key Vault access policy), then the secret-access logs for the "boring" bridge.

### Entra Sign-In Logs — the SSO/SAML/OIDC bridges (1, 2, 3, 4)

Table: `SigninLogs` (interactive) and `AADServicePrincipalSignInLogs` / `AADNonInteractiveUserSignInLogs` (workload/OIDC).

| Field | What it tells you | Example value | Read it as |
|-------|--------------------|----------------|------------|
| `AppDisplayName` / `AppId` | The Entra Enterprise Application used | `"AWS IAM Identity Center"` / `8b8b1cf9-...-...` | For bridge #1/#2, this is the AWS SSO / AWS SAML app registered in your tenant — confirm it's the one you expect, not a lookalike |
| `ResourceDisplayName` | What the token was issued *for* | `"Amazon Web Services"` | Should read as the AWS-facing app/API; a token issued to an unexpected resource from the same flow is a red flag |
| `UserPrincipalName` / `ServicePrincipalName` | The human or workload identity | `alice@corp.com` / `sp-aws-federation-deploy` | The anchor you carry into AWS |
| `IPAddress` + `Location` | Where the sign-in came from | `203.0.113.45` / `Seattle, WA, US` | Compare against the AWS-side `sourceIPAddress` on the resulting `AssumeRoleWithSAML`/`AssumeRoleWithWebIdentity` — they should be the same address (browser posts the SAML assertion; token exchange happens from the same caller) or land within seconds of each other |
| `ConditionalAccessStatus` | Whether CA policy applied | `success` / `notApplied` / `failure` | 🔴 `notApplied`/`failure` on a sign-in into the AWS app is a controls gap an actor may be exploiting |
| `RiskLevelDuringSignIn` / `RiskState` | Identity Protection's verdict | `high` / `atRisk` | 🔴 `high`/`medium` risk feeding straight into an AWS federation event is a strong lead |
| `CorrelationId` | Ties every event in one sign-in flow together | `4b1f6e2a-9c3d-4a7e-8f21-6d5c9a0b1e33` | Pull every `SigninLogs` row with the same `CorrelationId` to see the full MFA/CA/token-issuance sequence before the AWS hop |
| `ClientAppUsed` / `AppDisplayName` on the SP sign-in | For OIDC (#3/#4): which app/pipeline actually requested the token | `"Browser"` (interactive) / the pipeline's app name (workload) | A workload identity requesting a token outside its normal schedule/pipeline run is the tell |

```kql
// Sign-ins into the AWS SSO / SAML Enterprise Application
SigninLogs
| where AppDisplayName has "AWS" or ResourceDisplayName has "Amazon"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ConditionalAccessStatus, RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated desc
```

```kql
// Service-principal sign-ins requesting tokens for the AWS OIDC app registration (bridge #3)
AADServicePrincipalSignInLogs
| where AppId == "<app-registration-guid>"
| project TimeGenerated, ServicePrincipalName, IPAddress, ResourceDisplayName, ResultType
```

Console path: **Entra admin center → Identity → Monitoring & health → Sign-in logs**, filter by Application = the AWS-facing Enterprise App.

### Entra Audit Logs — bridge creation/modification (3, 4)

A brand-new federation trust is itself an event, and it's often the *actual* persistence mechanism (an attacker doesn't need to steal a token if they can mint their own trust).

| What to look for | `ActivityDisplayName` (approximate — verify against your tenant's audit taxonomy) | Example record shape | Why it matters |
|-------------------|--------------------------------------------------------------------------------|------------------------|-----------------|
| A federated identity credential added to an App Registration | *Add federated identity credential for application* / *Update application – Certificates and secrets management* | `TargetResources: [{"displayName":"aws-prod-deploy","type":"Application"}]`, `InitiatedBy: {"user":{"userPrincipalName":"alice@corp.com"}}` | 🔴 This is how bridge #3 gets created — an attacker with `Application.ReadWrite.All` or ownership of the app can add a federated credential trusting an *external* subject they control, then mint tokens for it |
| New Enterprise Application (service principal) matching an AWS-sounding name | *Add service principal* | `TargetResources: [{"displayName":"AWS-SSO-Backup","appId":"..."}]` | Could be a lookalike app set up to phish/harvest, or a legitimate new SSO integration — confirm with the requester |
| Changes to the AWS SSO Enterprise App's SAML config | *Update application* on the app object | `ModifiedProperties: [{"displayName":"AppAddress","newValue":"https://attacker.example/saml"}]` | Certificate rotation is normal; a changed **reply URL**/**Entity ID** is not |
| App Registration owner or credential added by an unexpected actor | *Add owner to application* / *Add password* / *Add key* | `InitiatedBy` UPN doesn't match the app's normal owning team | Classic app-hijack persistence pattern |

Console path: **Entra admin center → Identity → Monitoring & health → Audit logs**, filter Category = `ApplicationManagement`.

### Key Vault Diagnostic Logs — the stored-credential bridge (5)

If bridge #5 is in play, the AWS credential lived in a Key Vault secret. The read of that secret is the pivot moment.

| Field (Key Vault diagnostic / `AzureDiagnostics`) | What it shows | Example value |
|----------------------------------------------------|----------------|-----------------|
| `OperationName = SecretGet` | The secret was read | `SecretGet` |
| `identity_claim_upn_s` / `identity_claim_appid_g` | Who or what read it | `alice@corp.com` / `3fa85f64-5717-4562-b3fc-2c963f66afa6` |
| `CallerIPAddress` | Where from | `203.0.113.45` |
| `requestUri_s` | Which secret (confirm it's the one holding the AWS key) | `https://corp-kv.vault.azure.net/secrets/aws-prod-deploy-key/` |
| `ResultType` / `ResultSignature` | Success vs denied | `Success` / `OK` |

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| where requestUri_s has "aws" or requestUri_s has "s3"   // name the secret meaningfully in your own vault
| project TimeGenerated, identity_claim_upn_s, identity_claim_appid_g, CallerIPAddress, requestUri_s, ResultType
```

Console path: **Key Vault → Monitoring → Diagnostic settings** (must be enabled ahead of time) or **Key Vault → Access policies/RBAC + activity log** for coarser access-grant history.

Also check **App Service configuration reads** (`Microsoft.Web/sites/config/list/action` in the Activity Log — this is the API that dumps application settings, including any inline AWS keys) and **Automation Account variable reads** (`Microsoft.Automation/automationAccounts/variables/read`) as the equivalent for bridges #7/#8 when the credential sits there instead of Key Vault.

### Azure DevOps Audit Log — bridge #4

Azure DevOps keeps its own audit trail, separate from Entra. Look for **service connection** creation/edits (an OIDC service connection to AWS is a DevOps object, not an Entra object) and **pipeline run history** for the pipeline that uses it — an off-schedule run, or a run triggered by a fork/PR from an untrusted branch, is the classic abuse of an over-broad OIDC trust.

Console path: **Azure DevOps → Organization settings → Auditing**; pipeline runs under **Pipelines → Runs** for the specific pipeline.

## Destination-Side Investigation — AWS Logs

All of this lives in **CloudTrail**. The `userIdentity` block is the anchor — see AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** for the full type table; this section applies it to each bridge.

### Bridge #1 — IAM Identity Center SSO

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The permission-set role assumption | `eventName = AssumeRole`, role ARN contains `AWSReservedSSO_<permission-set>_<hash>` | `arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@corp.com` | This is the CloudTrail-visible moment; everything upstream (the Entra sign-in) is invisible here |
| `userIdentity.type` on subsequent actions | `AssumedRole` | `AssumedRole` | Session name inside the ARN often encodes the human's identifier — confirm your Identity Center config sets this meaningfully |
| The human, if you need to prove it | Not in CloudTrail — pivot to **IAM Identity Center's own sign-in/access history** (Identity Center console) or the upstream Entra sign-in log | — | 🔴 CloudTrail alone **stops at the permission-set role** — this is the single most important gotcha for this bridge |
| `sourceIdentity` (if your org sets it) | Propagates through any further role chain | `alice@corp.com` | The best field for tying a deep role chain back to the original Entra identity — see AWS **STS** hardening guidance |

Console path: **AWS IAM Identity Center console → Users → (user) → Account access**, or **CloudTrail Lake / Athena** for the `AssumeRole` events themselves.

### Bridge #2 — Direct SAML federation

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The federation event itself | `eventName = AssumeRoleWithSAML` | `AssumeRoleWithSAML` | Distinct API call from Identity Center's internal role-assumption flow |
| Identity type | `userIdentity.type = SAMLUser` | `SAMLUser` | Per the repo's established AWS type table |
| The SAML assertion's claims, as AWS saw them | `responseElements.subject`, `responseElements.subjectType`, `responseElements.issuer`, `responseElements.nameQualifier`, `responseElements.audience` | `subject: alice@corp.com`, `subjectType: persistent`, `issuer: https://sts.windows.net/<tenant-id>/`, `audience: https://signin.aws.amazon.com/saml` | `subject` is the SAML NameID Entra sent — this is your strongest cross-cloud anchor back to the Entra user |
| Which IAM SAML provider was used | `requestParameters.principalArn` | `arn:aws:iam::123456789012:saml-provider/EntraID` | Confirms which trust relationship (if more than one SAML IdP is configured) |
| `sourceIdentity` | Same as above | `alice@corp.com` | If configured on the role, survives the chain |

### Bridge #3/#4 — OIDC / Workload Identity Federation

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The federation event | `eventName = AssumeRoleWithWebIdentity` | `AssumeRoleWithWebIdentity` | |
| Identity type | `userIdentity.type = WebIdentityUser` | `WebIdentityUser` | |
| The token's claims, as AWS saw them | `responseElements.subjectFromWebIdentityToken`, `responseElements.audience`, `responseElements.provider` | `subjectFromWebIdentityToken: 3fa85f64-5717-4562-b3fc-2c963f66afa6`, `audience: api://AwsFederation`, `provider: login.microsoftonline.com/72f988bf-.../v2.0` | `provider` names the OIDC issuer (Entra's `login.microsoftonline.com/<tenant>/v2.0`, or `vstoken.dev.azure.com/<org-id>` for Azure DevOps/bridge #4) — confirms which of the two OIDC bridges fired |
| The trust condition that let it through | Not in the event — check the role's **trust policy** directly | `"Condition":{"StringEquals":{"login.microsoftonline.com/72f988bf-.../v2.0:aud":"api://AwsFederation"}}` | 🔴 An over-broad `Condition` (missing `aud`/`sub` scoping, or a wildcard subject) is what makes this bridge exploitable by *any* Entra tenant/app, not just yours — audit the trust policy itself, not just the events |
| Role used, first-use timing | `requestParameters.roleArn`, `eventTime` | `arn:aws:iam::123456789012:role/gh-style-deploy-role`, `2026-07-16T14:22:03Z` | A first-ever `AssumeRoleWithWebIdentity` on a role that's existed for months is itself a signal |

```bash
# CLI: pull the trust policy to check the OIDC condition scoping
aws iam get-role --role-name <role-name> --query 'Role.AssumeRolePolicyDocument'
```

Console path: **IAM → Roles → (role) → Trust relationships** to read the condition; **CloudTrail event history** filtered on `AssumeRoleWithWebIdentity` for the events.

### Bridge #5 — Stored/leaked AWS credential

No federation event exists — this is a plain key. Work it like any leaked-credential case (see AWS **[01 - IAM & Identities → Access Keys](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md#access-keys--akia-vs-asia)**), with one extra angle: **prove the Azure origin**.

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The key type | `userIdentity.accessKeyId` prefix | `AKIAIOSFODNN7EXAMPLE` (long-term) / `ASIAJEXAMPLE...` (temporary) | `AKIA` = long-term (matches a static secret sitting in Key Vault/App Service); `ASIA` = temporary (matches a *generated* AWS session stored briefly, less common for this bridge) |
| Source IP falling in Azure's published ranges | `sourceIPAddress` | `20.150.34.12` | Cross-reference against Microsoft's published [Azure IP ranges](https://www.microsoft.com/en-us/download/details.aspx?id=56519) (updated weekly) — a key that's *only* ever been used from your own known egress suddenly calling from an Azure Data Center IP/ASN is the tell |
| Tooling fingerprint | `userAgent` | `aws-sdk-dotnet-core/3.7.x .NET_Core/8.0 os/Microsoft-Windows-Azure` | AWS SDK calls originating from an Azure Function/App Service/Automation Account runbook often carry a distinctive default `userAgent` (language-runtime + SDK version) that's easy to baseline |
| GuardDuty | Finding types like `Recon:IAMUser/*`, `UnauthorizedAccess:IAMUser/*`, or an anomalous-ASN finding | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty's ML baselines "usual" ASNs for a given key — a first-time Azure ASN can trip it |

### Bridge #6 — Defender for Cloud / Sentinel connector

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The connector's own `AssumeRole` traffic | `eventName = AssumeRole`, `requestParameters.roleArn` = the connector role | `arn:aws:iam::123456789012:role/DefenderForCloudAWSConnector` | Should **only ever** originate from Microsoft's documented connector AWS account/IP ranges — anything else assuming that role is the trust being abused |
| The external ID | Not visible in CloudTrail directly; verify against the role's trust policy `Condition.StringEquals.sts:ExternalId` | `d3f8b2a1-4c5e-4f6a-9b7c-1e2f3a4b5c6d` | A leaked/guessable external ID lets anyone with the Microsoft account ARN (public knowledge) assume the role |

### Bridge #7/#8 — ETL / backup credential

Same investigative shape as bridge #5 (it's still a stored key), but corroborate against **Azure Data Factory pipeline-run logs** or the **backup agent's own job history** on the source side — a `GetObject`/`PutObject`/`s3:*` burst on the AWS side that lines up exactly with a pipeline/job run window is expected; one that *doesn't* line up with any scheduled run is the anomaly.

### Bridge #9 — Network interconnect

No IAM event exists on either side — this bridge is invisible in CloudTrail and Entra logs entirely. Work it from **VPC Flow Logs** (destination/source in the peered RFC1918 range that maps to the Azure VNet's address space) and the interconnect gateway's own connection logs. State this gap explicitly in your timeline — a resource reached this way leaves **no identity trail**, only network evidence.

## Correlation — Tying the Azure Identity to the AWS Session

| Anchor | Azure/Entra side | AWS side | Example match | Strength |
|--------|-------------------|----------|-----------------|----------|
| The human/workload identity | `UserPrincipalName` / `ServicePrincipalName` | SAML `responseElements.subject` (bridge #2) or OIDC `subjectFromWebIdentityToken` (bridge #3/#4) | `alice@corp.com` ↔ `subject: alice@corp.com` | High — this is the direct claim-to-claim match |
| Timing | Entra `CorrelationId` sign-in timestamp | `AssumeRoleWithSAML`/`AssumeRoleWithWebIdentity` `eventTime` | `14:22:01Z` (Entra) ↔ `14:22:03Z` (AWS) | High when within seconds; the browser/workload posts the assertion/token immediately after issuance |
| Source IP | Entra `IPAddress` | CloudTrail `sourceIPAddress` | `203.0.113.45` ↔ `203.0.113.45` | Medium–High — matches for interactive SSO (same browser); may legitimately differ for workload OIDC (token minted in one place, presented from a build agent's IP) |
| Application identity | Entra `AppId` of the federated app | AWS OIDC provider config / SAML provider ARN (which app/audience it trusts) | `AppId: 8b8b1cf9-...` ↔ `saml-provider/EntraID` | High — ties a specific Entra app registration to a specific AWS trust |
| `sourceIdentity` propagation | N/A (set on the AWS side) | `sourceIdentity` on the `AssumeRole*` event and every subsequent chained session | `sourceIdentity: alice@corp.com` on every hop | High if your org enables it — survives role chaining, the single best "prove it's the same actor three roles deep" field |
| Session-name conventions (SSO) | N/A | The session-name portion of `AWSReservedSSO_*` ARNs, if Identity Center is configured to populate it meaningfully | `.../AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@corp.com` | Medium — depends on your Identity Center config |

## Hunt at Scale

```sql
-- CloudTrail Lake SQL: federation events with no matching sourceIdentity, last 7 days
SELECT eventTime, eventName, userIdentity.type, sourceIPAddress,
       responseElements.subjectFromWebIdentityToken, responseElements.subject
FROM cloudtrail_lake_event_table
WHERE eventName IN ('AssumeRoleWithSAML', 'AssumeRoleWithWebIdentity')
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC
```

```kql
// KQL: sign-ins to the AWS-facing app outside business hours or from new ASNs
SigninLogs
| where AppDisplayName has "AWS"
| where hourofday(TimeGenerated) !between (6 .. 20)
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```

A modest cross-cloud SecOps/UDM landing point: normalize both sides to `target.user.email_addresses` / `principal.asset.ip` and alert on a UDM event where a `target.resource.type = "AWS_ROLE"` assumption has a `principal.user.email_addresses` value with **no prior sign-in event** to that same principal in the Azure/Entra UDM stream in the preceding 5 minutes — a federation "arriving from nowhere."

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A new federated identity credential added to an App Registration you don't recognize | Bridge #3 being freshly created — likely persistence, not legitimate use |
| `AssumeRoleWithWebIdentity`/`AssumeRoleWithSAML` with no corresponding Entra sign-in in the window | Token minted/replayed outside the expected flow, or your Entra log retention/scope has a gap |
| Entra sign-in IP and AWS `sourceIPAddress` far apart with no explainable relay (e.g. not a build agent) | Session/token replay from a different location |
| OIDC role trust policy missing a scoped `aud`/`sub` condition | Any external Entra tenant/app can assume the role — audit immediately regardless of whether abuse is confirmed |
| `AKIA`/`ASIA` key first-used from an Azure IP/ASN with no known Azure integration | Leaked credential surfacing from Azure-side compromise |
| Defender for Cloud/Sentinel connector role assumed from outside Microsoft's documented ranges | Cross-account trust abuse — verify the external ID hasn't leaked |
| A Key Vault secret matching an AWS-credential naming pattern read by an unexpected principal | Bridge #5 in progress — pivot to AWS immediately, assume the key is burned |
| Traffic to AWS-hosted resources over a private interconnect with no matching IAM trail on either side | Bridge #9 — pure network pivot; widen to Flow Logs, don't expect an identity story |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method (anchors, normalization, timeline) | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| AWS identity types and access-key decoding | AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** |
| AWS Identity Center investigation in depth | AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)** |
| AWS role-chaining and `sourceIdentity` hardening | AWS **[STS for DFIR](../Amazon/AWS/Identity%20%26%20Access/STS/STS%20for%20DFIR.md)** |
| Entra sign-in log deep dive | Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| App Registrations, service principals, federated credentials | Microsoft **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| Azure Key Vault secret-access investigation | Microsoft **[Key Vault](../Microsoft/Azure/Key%20Vault/)** |
| The Defender for Cloud multicloud connector | Microsoft **[Microsoft Defender for Cloud for DFIR](../Microsoft/Azure/Microsoft%20Defender%20for%20Cloud/Microsoft%20Defender%20for%20Cloud%20for%20DFIR.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- AWS: AssumeRoleWithSAML — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
- AWS: AssumeRoleWithWebIdentity — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- Microsoft: Workload identity federation — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Microsoft: Configure AWS IAM Identity Center as an Entra-federated app — https://learn.microsoft.com/en-us/entra/identity/saas-apps/aws-single-sign-on-tutorial
- Microsoft: Azure IP Ranges and Service Tags — https://www.microsoft.com/en-us/download/details.aspx?id=56519
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
