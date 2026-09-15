# Azure → GCP

## Why This Happens

Azure and GCP are separate accounts with separate logins. By default, an Azure identity means **nothing** to GCP, and a GCP identity means nothing to Azure — the two clouds don't know each other exist. Nobody walks from one into the other unless someone **deliberately built a bridge**, almost always for a normal business reason: single sign-on so employees don't need a second password, a pipeline that needs to deploy into GCP, or a script that needs to read a Cloud Storage bucket.

This pairing has a real asymmetry worth naming up front, because it changes what "normal" looks like here. GCP built a purpose-made, near-frictionless Workload Identity Federation provider *specifically* for AWS role ARNs (see **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)**) — no such native Azure provider type exists. Every Azure-to-GCP federation trust, keyless or not, is a **generic, customer-configured OIDC or SAML object** on the GCP side. That's not a gap in this note; it's a gap in the platform. The closest thing to a frictionless, purpose-built bridge in this direction isn't a general workload-federation pattern at all — it's Microsoft's own **Defender for Cloud GCP connector**, a narrow product feature, not something a developer reaches for in everyday CI/CD.

An actor with a foothold in Azure/Entra crosses into GCP using one of these mechanisms:

- **Federated SSO** — a *human* logs into Entra, and Entra vouches for them to a GCP **Workforce Identity Federation** pool (typically over SAML, the same Enterprise Application gallery pattern used for any other SSO integration). If a phished employee's Entra account has this SSO path into GCP, whoever now controls that Entra account has that same GCP access — no separate "GCP hack" needed.
- **Workload identity federation (the deliberate one)** — the same idea as SSO, but for a *machine*, and with no password stored anywhere. An Entra App Registration (or a managed identity, which needs no stored secret at all) requests an Entra-issued OIDC token scoped to whatever audience the GCP side expects, then presents that token to a GCP Workload Identity Federation pool provider configured, by hand, as a **generic OIDC provider** trusting Entra's issuer (`https://login.microsoftonline.com/<tenant>/v2.0`). Nobody clicked "add Azure" the way AWS's native provider works — someone had to type the issuer URL in.
- **Azure DevOps OIDC service connection** — a close cousin of the above, except Azure DevOps itself (not Entra) is the token issuer, and the GCP-side provider is configured to trust DevOps's issuer instead.
- **A plain leaked GCP service-account key in an Azure secret store** — a GCP SA key (a JSON file that never expires until deleted) sitting in Key Vault, an App Service's application settings, an Automation Account variable, or a Data Factory linked service. No trust relationship, no login event — whoever reads it just uses it directly against GCP's APIs. This is the "boring" bridge, and it's the one most likely already sitting in your environment.
- **Microsoft Defender for Cloud's GCP connector** — onboarding a GCP project to Defender for Cloud provisions a GCP Workload Identity Federation pool and a dedicated service account the connector impersonates. This is genuinely keyless on both ends, and it's a meaningfully different mechanism from Defender's **AWS** connector, which trusts a cross-account IAM role instead (see **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)**, bridge #6).

**The bridge determines what evidence exists on both sides.** SSO and OIDC bridges leave a trust configuration to audit *and* a matching pair of events (one leaving Azure, one arriving in GCP). The leaked-key bridge leaves neither — just a key being used from a new place. Knowing which bridge you're dealing with tells you which evidence to go looking for, and which evidence's *absence* is itself information.

This note works the investigation from the Azure/Entra side first, then the GCP side, then ties the two together with the specific fields that prove it was the same actor both times.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method). See also **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** for the contrast — the same starting cloud, but a destination with a native, one-command federation shortcut waiting for it — and **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** for the same destination, reached from a different, far more frictionless source.

## Contents

- [The Bridges — Azure → GCP](#the-bridges--azure--gcp)
- [Source-Side Investigation — Azure/Entra Logs](#source-side-investigation--azureentra-logs)
- [Destination-Side Investigation — GCP Logs](#destination-side-investigation--gcp-logs)
- [Correlation — Tying the Azure Identity to the GCP Session](#correlation--tying-the-azure-identity-to-the-gcp-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — Azure → GCP

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|-------------|---------------------|
| 1 | **Federated SSO (Entra as external IdP for GCP Workforce Identity Federation)** | A human signs into Entra; Entra issues a SAML assertion (the standard Enterprise App gallery pattern) accepted by a GCP **Workforce Identity Federation** pool, which maps it to a Google principal | 🔴 Very common — the default enterprise pattern wherever GCP is the secondary cloud | The Entra **Enterprise Application** for the GCP pool + the Workforce pool's SAML provider config |
| 2 | **Workload identity federation — Entra token → GCP generic OIDC provider** | An Entra App Registration (or managed identity) gets an Entra-issued token, then presents it to a GCP Workload Identity Pool provider configured by hand as a **generic OIDC provider** trusting `login.microsoftonline.com/<tenant>/v2.0` | Growing — the deliberate, "had to be built" keyless pattern for cross-cloud CI/CD | The GCP pool provider's issuer URI + allowed audience + attribute condition — all customer-typed, none of it native |
| 3 | **Azure DevOps OIDC service connection → GCP** | Azure DevOps itself is the OIDC issuer (`vstoken.dev.azure.com/<org-id>`); a GCP pool provider trusts DevOps's issuer for a specific org/project/service-connection subject | Common in shops using Azure DevOps as CI/CD against GCP infra | The GCP pool provider's issuer + subject condition, scoped to a `sc://` subject |
| 4 | **Stored/leaked GCP SA key in Azure** | A GCP service-account key (JSON, never expires) sits in Key Vault, App Service application settings, an Automation Account variable, or an Azure DevOps pipeline variable | 🔴 Very common — the "boring" bridge, easy to miss | The secret object itself; no cloud-native trust relationship to find |
| 5 | **Microsoft Defender for Cloud — GCP connector** | Onboarding provisions a GCP Workload Identity Federation pool + provider and a dedicated service account (`mdc-gcp-connector@<project>.iam.gserviceaccount.com`) the connector impersonates — genuinely keyless, unlike the AWS connector's IAM-role-trust model | Common — the standard multicloud CSPM onboarding path | The GCP-side WIF pool/provider provisioned for the connector + the connector's `securityConnectors` resource in Azure |
| 6 | **Azure Arc — GCP Compute Engine support (public preview)** | The Connected Machine agent is installed on a GCE VM, giving it its own Azure managed identity; reaches the VM's compute, not GCP's control plane | Newer — GCP support is in public preview as of mid-2026 | The Arc-enabled-server resource (`Microsoft.HybridCompute/machines`) + its own managed identity |
| 7 | **Azure Data Factory / Synapse linked service** | A linked service holds a GCP SA key (stored in Key Vault or ADF's own credential store) to read/write Cloud Storage or BigQuery | Common in data-engineering estates | The linked-service credential — same shape as bridge #4, just a different consumer |
| 8 | **Network interconnect (ExpressRoute ↔ Cloud Interconnect)** | A colo/partner exchange bridges an Azure VNet and a GCP VPC at the network layer — no identity crosses | Uncommon, and still colo-brokered as of this writing; Azure is expected to join the AWS↔GCP direct-peering model in 2026 | The interconnect/gateway config; **no IAM trail on either side** |

## Source-Side Investigation — Azure/Entra Logs

Work these in order: sign-in evidence first (who authenticated and into what), then the audit trail for anything that *created or changed* a bridge, then the secret-access logs for the "boring" bridge.

### Entra Sign-In Logs — the SSO/WIF/DevOps OIDC bridges (1, 2, 3)

Table: `SigninLogs` (interactive) and `AADServicePrincipalSignInLogs` / `AADNonInteractiveUserSignInLogs` (workload/OIDC).

| Field | What it tells you | Example value | Read it as |
|-------|--------------------|----------------|------------|
| `AppDisplayName` / `AppId` | The Entra Enterprise Application used | `"GCP Workforce Identity Federation"` / `a2b3c4d5-6e7f-4a8b-9c0d-1e2f3a4b5c6d` | For bridge #1, this is the SAML app registered for the GCP Workforce pool sign-in — confirm it's the one you expect, not a lookalike |
| `ResourceDisplayName` | What the token was issued *for* | `"Google Cloud"` | Should read as the GCP-facing app/audience; anything else from the same flow is a red flag |
| `UserPrincipalName` / `ServicePrincipalName` | The human or workload identity | `alice@corp.com` / `sp-gcp-federation-deploy` | The anchor you carry into GCP |
| `IPAddress` + `Location` | Where the sign-in came from | `203.0.113.45` / `Seattle, WA, US` | Compare against the GCP-side `requestMetadata.callerIp` — should match for interactive SSO, may legitimately differ for a workload minting its own token |
| `ConditionalAccessStatus` | Whether CA policy applied | `success` / `notApplied` | 🔴 `notApplied`/`failure` on a sign-in into the GCP-facing app is a controls gap |
| `RiskLevelDuringSignIn` / `RiskState` | Identity Protection's verdict | `high` / `atRisk` | 🔴 High/medium risk feeding straight into a GCP federation event is a strong lead |
| `CorrelationId` | Ties every event in one sign-in flow together | `5c2f7e3b-8a1d-4f6e-b3c2-9d0e1f2a3b4c` | Pull every `SigninLogs` row sharing this id to see the full MFA/CA/token-issuance sequence before the GCP hop |
| `ClientAppUsed` / SP `AppDisplayName` | For bridges #2/#3: which app/pipeline actually requested the token | `"Browser"` (interactive) / the pipeline's app name (workload) | A workload requesting a token outside its normal schedule/pipeline run is the tell |

```kql
// Sign-ins into the GCP-facing Enterprise Application
SigninLogs
| where AppDisplayName has "GCP" or AppDisplayName has "Google" or ResourceDisplayName has "Google"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, ConditionalAccessStatus, RiskLevelDuringSignIn, CorrelationId
| order by TimeGenerated desc
```

```kql
// Service-principal sign-ins requesting tokens under the App Registration used for GCP WIF (bridge #2)
AADServicePrincipalSignInLogs
| where AppId == "<app-registration-guid>"
| project TimeGenerated, ServicePrincipalName, IPAddress, ResourceDisplayName, ResultType
```

Console path: **Entra admin center → Identity → Monitoring & health → Sign-in logs**, filter by Application = the GCP-facing Enterprise App.

### Entra Audit Logs — bridge creation/modification (2, 3)

A brand-new federation path into GCP is itself an event, and it's often the *actual* persistence mechanism.

| What to look for | `ActivityDisplayName` (approximate — verify against your tenant's audit taxonomy) | Example record shape | Why it matters |
|-------------------|--------------------------------------------------------------------------------|------------------------|-----------------|
| A client secret or certificate added to the App Registration used for GCP federation | *Add password* / *Add key* / *Update application – Certificates and secrets management* | `TargetResources: [{"displayName":"gcp-prod-deploy","type":"Application"}]` | If the app isn't a managed identity, this credential is what lets it request the Entra-issued token it presents to GCP in the first place — an attacker-added secret means they can request that token too |
| A federated identity credential added to the App Registration | *Add federated identity credential for application* | `TargetResources: [{"displayName":"gcp-prod-deploy","type":"Application"}]`, `InitiatedBy: {"user":{"userPrincipalName":"alice@corp.com"}}` | 🔴 Relevant when the Azure app is itself federated **in** from a third party (GitHub Actions, Kubernetes) before turning around and requesting a GCP-audience token — a chained trust an attacker can plant at either hop |
| New Enterprise Application / App Registration with a GCP-sounding name | *Add service principal* / *Add application* | `TargetResources: [{"displayName":"GCP-WIF-Backup","appId":"..."}]` | Could be a lookalike set up to blend in, or a legitimate new integration — confirm with the requester |
| App Registration owner added by an unexpected actor | *Add owner to application* | `InitiatedBy` UPN doesn't match the app's normal owning team | Classic app-hijack persistence pattern |

Console path: **Entra admin center → Identity → Monitoring & health → Audit logs**, filter Category = `ApplicationManagement`.

### Azure DevOps Audit Log — bridge #3

Azure DevOps keeps its own audit trail, separate from Entra. Look for **service connection** creation/edits to a GCP-facing OIDC service connection, and **pipeline run history** for the pipeline that uses it — an off-schedule run, or a run triggered by a fork/PR from an untrusted branch, is the classic abuse of an over-broad OIDC trust.

Console path: **Azure DevOps → Organization settings → Auditing**; pipeline runs under **Pipelines → Runs** for the specific pipeline.

### Key Vault Diagnostic Logs — the stored-credential bridge (4, 7)

If bridge #4 (or the underlying credential behind bridge #7) is in play, the GCP SA key JSON lived in a Key Vault secret. The read of that secret is the pivot moment.

| Field (Key Vault diagnostic / `AzureDiagnostics`) | What it shows | Example value |
|----------------------------------------------------|----------------|-----------------|
| `OperationName = SecretGet` | The secret was read | `SecretGet` |
| `identity_claim_upn_s` / `identity_claim_appid_g` | Who or what read it | `alice@corp.com` / `3fa85f64-5717-4562-b3fc-2c963f66afa6` |
| `CallerIPAddress` | Where from | `203.0.113.45` |
| `requestUri_s` | Which secret (confirm it's the one holding the GCP key) | `https://corp-kv.vault.azure.net/secrets/gcp-etl-sa-key/` |
| `ResultType` / `ResultSignature` | Success vs denied | `Success` / `OK` |

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT" and OperationName == "SecretGet"
| where requestUri_s has "gcp" or requestUri_s has "gcs" or requestUri_s has "bigquery"   // name the secret meaningfully in your own vault
| project TimeGenerated, identity_claim_upn_s, identity_claim_appid_g, CallerIPAddress, requestUri_s, ResultType
```

Console path: **Key Vault → Monitoring → Diagnostic settings** (must be enabled ahead of time) or **Key Vault → Access policies/RBAC + activity log** for coarser access-grant history.

Also check **App Service configuration reads** (`Microsoft.Web/sites/config/list/action` in the Activity Log) and **Automation Account variable reads** (`Microsoft.Automation/automationAccounts/variables/read`) as the equivalent when the credential sits there instead of Key Vault — and **Azure Data Factory pipeline-run logs** for bridge #7, corroborating a `GetObject`/`insert`/BigQuery-job burst on the GCP side against a scheduled pipeline run window.

### Microsoft Defender for Cloud — GCP connector onboarding (bridge #5)

Onboarding a GCP project creates a **security connector** resource in Azure and, on the GCP side, provisions the WIF pool/provider and dedicated service account the connector impersonates. The Azure-side artifact worth checking is the connector's own configuration and who last touched it — the actual keyless exchange happens entirely on the GCP side (see below).

| Signal | Field (Activity Log) | Example value | Notes |
|--------|-----------------------|-----------------|-------|
| Connector created/modified | `operationName = Microsoft.Security/securityConnectors/write` | `resourceId: /subscriptions/3fa85f64-5717-4562-b3fc-2c963f66afa6/resourceGroups/security/providers/Microsoft.Security/securityConnectors/gcp-prod-connector` | Confirms which GCP project(s) the connector is scoped to |
| Who touched it | `caller` | `alice@corp.com` | Should be a small, known set of security-team admins |
| The connector's GCP-side scope | Not in Activity Log — read from the connector resource's `properties.gcpProjectDetails` | `projectId: contoso-prod` | A connector scoped wider than the intended project set is worth auditing |

```bash
az resource show --ids /subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.Security/securityConnectors/gcp-prod-connector
```

Console path: **Defender for Cloud → Environment settings → the GCP connector** → review its onboarding scope and last-modified history.

### Azure Arc — GCP Compute Engine onboarding (bridge #6)

Compute reach, not a GCP identity — the Connected Machine agent gets its own Azure identity, but that identity lives *in Azure*, not GCP.

| Signal | Field (Activity Log) | Example value | Notes |
|--------|-----------------------|-----------------|-------|
| Arc-enabled server resource created | `operationName = Microsoft.HybridCompute/machines/write` | `resourceId: .../Microsoft.HybridCompute/machines/gce-web01-arc` | One per onboarded GCE VM |
| The Connected Machine agent's own identity | The machine resource's system-assigned managed identity | `principalId: 6f1e2d3c-4b5a-4c6d-8e9f-0a1b2c3d4e5f` | A real Azure identity now reachable from that GCP-hosted VM — treat it like any other managed identity in scope |
| Who ran the onboarding | `caller` | `alice@corp.com` | Onboarding requires Azure Connected Machine Onboarding rights, run from a script on the target VM |

Console path: **Azure Arc → Machines**, filter by a GCP-hosted tag. CLI: `az connectedmachine list --resource-group <rg> -o table`.

### Network Interconnect — bridge #8

No Azure identity event exists — this bridge is invisible in Entra/Activity Log entirely. Work it from **NSG Flow Logs** (destination in the peered range mapping to the GCP VPC's address space) and the interconnect gateway's own connection logs. State this gap explicitly in your timeline. Full treatment in **[00 - Cross-Cloud Bridges Overview → Infrastructure Bridges](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair)**.

## Destination-Side Investigation — GCP Logs

All of this lives in **Cloud Audit Logs**. See Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** for the full field reference this section applies to each bridge.

### Bridge #1 — Workforce Identity Federation (SSO)

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalSubject` | The federated Workforce Identity principal | `principal://iam.googleapis.com/locations/global/workforcePools/azure-sso-pool/subject/alice@corp.com` | Note the path — **`workforcePools`**, not `workloadIdentityPools`; this is the human-SSO variant of the same underlying STS mechanism |
| `protoPayload.requestMetadata.callerIp` | Where the human's console/CLI session originated | `203.0.113.45` | Compare against the Entra sign-in IP for the same user |
| `protoPayload.methodName` | The actual GCP action taken next | `storage.objects.list`, or `google.iam.credentials.v1.GenerateAccessToken` if the human next impersonates a service account | The federated identity itself may hold a direct binding, or use it to impersonate an SA — check both |

Console path: **IAM & Admin → Workforce Identity Federation**, for the pool/provider config trusting Entra's SAML metadata; **Logging → Logs Explorer**, filtered on `principalSubject:"workforcePools"`.

### Bridge #2 — Workload Identity Federation — generic OIDC trusting Entra

This is the note's headline mechanic, and it's worth being precise about it: unlike AWS's native provider, someone had to type Entra's issuer URL into a GCP pool provider by hand.

**If the federated identity impersonates a GCP service account** (the common pattern — a `roles/iam.workloadIdentityUser` binding on the target SA):

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.methodName` | The impersonation call | `google.iam.credentials.v1.GenerateAccessToken` | The moment the federated identity becomes usable as the GCP SA |
| `protoPayload.authenticationInfo.principalSubject` | The federated Azure identity, exactly as GCP mapped it | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/azure-prod-pool/subject/a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d` | 🔴 The embedded string is the **Entra App Registration's Object ID (the token's `sub` claim)** — a bare GUID, not a self-describing string like an AWS role ARN. You cannot tell which app this is from the GUID alone; cross-reference it against the App Registration's Object ID in Entra to identify the app |
| `protoPayload.resourceName` | The SA being impersonated | `projects/contoso-prod/serviceAccounts/gcp-deploy-sa@contoso-prod.iam.gserviceaccount.com` | What the Azure identity can now act as |
| `protoPayload.requestMetadata.callerIp` | Where the exchange call came from | `20.150.34.12` | Should fall in Azure's published IP ranges if this is a legitimate Azure-hosted workload |

**If the federated identity is granted a direct IAM binding instead** (no SA impersonation):

| Field | What it tells you | Example value |
|-------|--------------------|-----------------|
| `protoPayload.methodName` | The bound resource's own API call | `storage.objects.get`, or `SetIamPolicy` if you're looking at the binding itself |
| `protoPayload.authenticationInfo.principalSubject` | Same shape as above | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/azure-prod-pool/subject/a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d` |
| The IAM binding itself | `request.policy.bindings[]` member, on the `SetIamPolicy` event that created it | `member: "principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/azure-prod-pool/subject/a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d"`, `role: "roles/storage.objectViewer"` |

> 🔴 **Read the provider's allowed audience and issuer before trusting any single event.** `gcloud iam workload-identity-pools providers describe` shows exactly what audience/issuer was configured — an issuer pinned to your specific tenant GUID (`login.microsoftonline.com/72f988bf-.../v2.0`) and an audience scoped to a value only your app requests is the tight setup; an issuer with no tenant restriction, or an audience left at a generic default, means **any** Entra tenant that knows the provider's resource name can attempt to federate in.

```bash
# Read the pool provider's issuer, audience, and attribute condition
gcloud iam workload-identity-pools providers describe entra-provider \
  --workload-identity-pool=azure-prod-pool --location=global --project=contoso-prod

# Federated impersonation events for this pool
gcloud logging read \
 'protoPayload.authenticationInfo.principalSubject:"workloadIdentityPools/azure-prod-pool"' \
 --project=contoso-prod --freshness=30d --format=json
```

```sql
-- BigQuery (audit sink): every federated Entra principal that acted, and what it did
SELECT timestamp,
       protopayload_auditlog.authenticationInfo.principalSubject AS entra_subject,
       protopayload_auditlog.methodName AS action,
       protopayload_auditlog.resourceName AS resource
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalSubject LIKE '%workloadIdentityPools/azure%'
ORDER BY timestamp DESC;
```

Console path: **IAM & Admin → Workload Identity Federation** (pool/provider config, including issuer and audience); **Logging → Logs Explorer**, filtered on `principalSubject:"workloadIdentityPools"`.

### Bridge #3 — Azure DevOps OIDC

Same mechanics as bridge #2, but the trusted issuer and embedded subject are Azure DevOps's, not Entra's.

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalSubject` | The federated Azure DevOps pipeline identity | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/ado-prod-pool/subject/sc://contoso-org/contoso-project/gcp-deploy-connection` | The `sc://<org>/<project>/<service-connection>` subject shape is distinctive to Azure DevOps OIDC — pin the provider's condition to this exact string, not a wildcard |
| The pool provider's issuer | Config, not a per-event field | `vstoken.dev.azure.com/<org-id>` | Confirms it's DevOps, not Entra, that's trusted |

Console path: **IAM & Admin → Workload Identity Federation**, for the `ado-prod-pool` provider config. This bridge doesn't warrant its own deep destination-side breakdown beyond the table above — correlate the timing against Azure DevOps's own pipeline-run history (source side, above) rather than expecting a separate GCP-side "this was a pipeline" marker.

### Bridge #4/#7 — Stored/leaked GCP SA key

No federation event exists — this is a plain key. Work it like any leaked-credential case (see Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)**), with one extra angle: **prove the Azure origin**.

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalEmail` | The SA identity | `gcp-etl-sa@contoso-prod.iam.gserviceaccount.com` | Confirms which SA the leaked key belongs to |
| `protoPayload.authenticationInfo.serviceAccountKeyName` | 🔴 A user-managed key was used | `projects/contoso-prod/serviceAccounts/gcp-etl-sa@contoso-prod.iam.gserviceaccount.com/keys/a1b2c3d4e5f6...` | Present = key-based auth, not impersonation or WIF — confirms this bridge specifically |
| `protoPayload.requestMetadata.callerIp` | Where the key was used from | `20.150.34.12` | 🔴 Cross-reference against Microsoft's published [Azure IP ranges](https://www.microsoft.com/en-us/download/details.aspx?id=56519) — a key that's only ever been used from a GCP-side pipeline suddenly calling from an Azure IP/ASN is the tell |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | Tooling fingerprint | `google-api-dotnet-client/1.68.0 (gzip)` | An SDK/runtime signature consistent with an Azure Function/App Service/Automation Account runbook rather than the SA's expected environment |

```bash
gcloud logging read \
 'protoPayload.authenticationInfo.serviceAccountKeyName:"gcp-etl-sa"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Logging → Logs Explorer**, filtered on `serviceAccountKeyName`; **IAM & Admin → Service Accounts → (SA) → Keys** to inventory every key that exists and when it was created.

### Bridge #5 — Defender for Cloud GCP connector

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalSubject` | The connector's own federated identity | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/mdc-gcp-connector-pool/subject/...` | Provisioned during onboarding — should be the *only* subject exchanging through this specific pool |
| `protoPayload.methodName` | The impersonation call | `google.iam.credentials.v1.GenerateAccessToken` | Impersonating the connector's own SA |
| `protoPayload.resourceName` | The SA being impersonated | `projects/contoso-prod/serviceAccounts/mdc-gcp-connector@contoso-prod.iam.gserviceaccount.com` | The dedicated connector SA — should only ever act within the scan/assessment scopes Defender grants it |
| `protoPayload.requestMetadata.callerIp` | Where the exchange call came from | — | Should **only ever** originate from Microsoft's documented connector infrastructure — anything else exchanging through this pool is the trust being abused, not the tool compromised |

Console path: **IAM & Admin → Workload Identity Federation**, for the connector's dedicated pool/provider; **IAM & Admin → Service Accounts**, for the `mdc-gcp-connector` SA's own activity.

### Bridge #6 — Azure Arc reaching a GCP Compute Engine instance

No GCP identity evidence exists for this bridge — it's guest-OS command execution via the Connected Machine agent, invisible to Cloud Audit Logs. Work it from the VM's own guest-level artifacts exactly as you would any host-level compromise, and confirm whether the **Azure-side** managed identity (source-side section, above) was used to push anything through it.

### Bridge #8 — Network interconnect

No GCP identity evidence exists — pure network pivot. Work it from **VPC Flow Logs** on the addresses in the peered range and the interconnect gateway's own connection logs.

## Correlation — Tying the Azure Identity to the GCP Session

| Anchor | Azure/Entra side | GCP side | Example match | Strength |
|--------|-------------------|----------|-----------------|----------|
| The human identity (bridge #1) | `UserPrincipalName` | `principalSubject`'s embedded subject, `workforcePools` path | `alice@corp.com` ↔ `subject/alice@corp.com` | High — direct claim-to-claim match |
| The workload identity (bridges #2/#3) | App Registration/service principal **Object ID** (the token's `sub` claim) | `principalSubject`'s embedded GUID or `sc://` string, `workloadIdentityPools` path | `a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d` ↔ same GUID inside `principal://.../subject/a1b2c3d4-...` | 🔴 High, but **not self-describing** — unlike an AWS ARN, the raw GUID tells you nothing on its own; you must look it up against Entra's App Registration Object IDs to know which app it is |
| Timing | Entra sign-in/token-request timestamp | `timestamp` of the first `principalSubject`-bearing GCP event | `14:22:01Z` (Entra) ↔ `14:22:03Z` (GCP) | High when within seconds |
| Source IP | Entra `IPAddress` | `requestMetadata.callerIp` | `203.0.113.45` ↔ `203.0.113.45` | High for interactive SSO (same browser); may legitimately differ for a workload minting its token in one Azure-hosted environment |
| The pool/provider's issuer + audience | The custom audience the app requested (config, not a per-event field) | Same, read via `gcloud iam workload-identity-pools providers describe` | `api://gcp-federation-prod` bound in the provider's allowed audience | High — confirms which Azure app is even eligible to federate, independent of any single event |
| SA key identity (bridge #4/#7) | Key Vault secret name/version | `serviceAccountKeyName` on the GCP side | The key ID in `serviceAccountKeyName` matches the JSON key that was in the burned Key Vault secret | High — ties a specific leaked key to specific GCP-side usage |

## Hunt at Scale

```kql
// KQL: sign-ins to the GCP-facing app outside business hours or from new ASNs
SigninLogs
| where AppDisplayName has "GCP" or AppDisplayName has "Google" or ResourceDisplayName has "Google"
| where hourofday(TimeGenerated) !between (6 .. 20)
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```

```kql
// KQL: federated-credential and app-secret additions in the last 7 days (persistence sweep)
AuditLogs
| where OperationName in ("Add federated identity credential for application","Add password","Add key")
| where TimeGenerated > ago(7d)
| project TimeGenerated, InitiatedBy, TargetResources
```

```sql
-- BigQuery (GCP audit sink): every federated Entra subject seen in the last 7 days,
-- and how many distinct actions it performed
SELECT
  REGEXP_EXTRACT(protopayload_auditlog.authenticationInfo.principalSubject,
                 r'subject/([^"]+)') AS entra_subject,
  COUNT(*) AS actions
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalSubject LIKE '%workloadIdentityPools%'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
GROUP BY entra_subject
ORDER BY actions DESC;
```

**Log Explorer, for a fast first look:**

```
protoPayload.authenticationInfo.principalSubject:"workloadIdentityPools"
protoPayload.authenticationInfo.principalSubject:"workforcePools"
```

A modest cross-cloud SecOps/UDM landing point: normalize the Entra-side sign-in/token-request (`principal.user.userid` = `UserPrincipalName` or the App Registration Object ID) and the GCP-side federated action (`target.resource.name` = `resourceName`, `principal.asset.ip` = `callerIp`) to a shared timeline, and alert on a `principalSubject` containing `workloadIdentityPools` or `workforcePools` with no prior Entra sign-in/token-request event from the matching identity in the preceding few minutes — the same "arriving from nowhere" pattern used elsewhere in this repo. Keep it light; the deep read stays in the native queries above.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A GCP WIF pool provider's issuer with no tenant restriction, or an audience left at a generic/default value | Any Entra tenant that discovers the provider's resource name can attempt to federate in — audit immediately regardless of confirmed abuse |
| A new federated identity credential, app secret, or cert added to an App Registration you don't recognize | Persistence — an attacker who can request the token themselves doesn't need to steal one |
| A `principalSubject` containing `workloadIdentityPools` or `workforcePools` with an Entra identity you don't recognize | New/unexpected federated identity acting in GCP |
| A GCP SA key (`serviceAccountKeyName`) used from an Azure IP/ASN with no known Azure-side integration | Bridge #4/#7 surfacing — leaked key, assume it's burned |
| `GenerateAccessToken` impersonating a privileged SA, called by a federated Entra principal outside its normal schedule | Lateral movement via the impersonation hop |
| A direct IAM binding (`SetIamPolicy`) granting a role straight to a `principal://.../workloadIdentityPools/...` member | Confirm the bound role is least-privilege, not broad |
| Defender for Cloud's GCP connector pool exchanged from outside Microsoft's documented connector infrastructure | The standing trust is being abused, not the tool compromised |
| An Azure Arc Connected Machine agent installed on a GCE VM nobody requested | A new remote-control path into that compute, planted as persistence |
| Traffic to GCP-hosted resources over a private interconnect with no matching IAM trail on either side | Expected — this bridge is invisible to identity logging; widen to Flow Logs, don't expect a login story |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method (anchors, normalization, timeline) | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| The full bridge inventory across all six directional pairs | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| This pair from the other Azure-outbound direction | **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** |
| The same destination, a different source | **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** |
| Entra sign-in log deep dive | Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| App Registrations, service principals, federated credentials | Microsoft **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| Azure Key Vault secret-access investigation | Microsoft **[Key Vault](../Microsoft/Azure/Key%20Vault/)** |
| The Defender for Cloud GCP connector | Microsoft **[Microsoft Defender for Cloud for DFIR](../Microsoft/Azure/Microsoft%20Defender%20for%20Cloud/Microsoft%20Defender%20for%20Cloud%20for%20DFIR.md)** |
| GCP Workload Identity Federation in depth | Google **[Workload Identity Federation for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Workload%20Identity%20Federation/Workload%20Identity%20Federation%20for%20DFIR.md)** |
| GCP Cloud Audit Logs deep dive | Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** |
| GCP service-account keys, impersonation, delegation chains | Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)** |
| GCP IAM bindings and privilege escalation | Google **[Cloud IAM for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Cloud%20IAM/Cloud%20IAM%20for%20DFIR.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- Google Cloud: Workload Identity Federation overview — https://cloud.google.com/iam/docs/workload-identity-federation
- Google Cloud: Manage workload identity pools and providers (generic OIDC setup) — https://cloud.google.com/iam/docs/manage-workload-identity-pools-providers
- Google Cloud: Workforce Identity Federation overview — https://cloud.google.com/iam/docs/workforce-identity-federation
- Microsoft: Workload identity federation (federated credentials) — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Microsoft: Connect AWS, GCP, and Azure with the multicloud connector — https://learn.microsoft.com/en-us/azure/azure-arc/multicloud-connector/overview
- Microsoft: Onboard your GCP project to Microsoft Defender for Cloud — https://learn.microsoft.com/en-us/azure/defender-for-cloud/quickstart-onboard-gcp
- Microsoft: Azure IP Ranges and Service Tags — https://www.microsoft.com/en-us/download/details.aspx?id=56519
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
