# GCP → Azure

## Why This Happens

GCP and Azure are separate accounts with separate logins. By default, a GCP identity means **nothing** to Azure, and an Azure identity means nothing to GCP — the two clouds don't know each other exist. Nobody walks from one into the other unless someone **deliberately built a bridge**, almost always for a normal business reason: single sign-on, a pipeline that needs to write into Azure Storage, a script that needs to read a Blob container.

This pairing has a real asymmetry worth naming up front, because it changes what "normal" looks like here. GCP↔AWS is the most frictionless federation pair in this repo — both vendors ship native, purpose-built trust for each other (see **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** and **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)**'s asymmetry callout). Azure sits outside that shortcut. Every GCP-to-Azure federation trust, keyless or not, requires the customer to **explicitly register Google as an issuer** — Azure treats `accounts.google.com` as any other standards-compliant external OIDC issuer, with no special-case trust the way AWS provides. Nobody at Microsoft or Google pre-wired this pair the way AWS and GCP wired themselves to each other.

An actor with a foothold in GCP crosses into Azure using one of these mechanisms:

- **A GCP service account's identity token, presented to an Entra federated credential (the deliberate one)** — a GCP service account mints its own OIDC identity token (`generateIdToken`, issuer `https://accounts.google.com`, `sub` = the SA's numeric unique ID) and exchanges it for an Entra access token via `client_credentials` + `client_assertion`. Unlike the AWS direction, someone had to **explicitly type Google's issuer URL and the SA's subject** into an Entra App Registration's federated credential — this trust doesn't exist until a human deliberately builds it.
- **A plain leaked Azure credential in a GCP secret store** — an Entra App Registration's client secret sits in Secret Manager (`projects/987654321000/secrets/azure-sp-secret/versions/latest`), a Cloud Functions environment variable, or a Cloud Build substitution variable. No trust relationship, no federation, no login event — whoever reads it just uses it directly against Azure. The "boring" bridge, and still the one most likely to already be sitting in your environment.
- **GCP-hosted CI/CD deploying into Azure** — a Cloud Build trigger or a self-hosted GitHub Actions/GitLab runner on Compute Engine uses either of the two mechanisms above to push changes into Azure.
- **Google as a federation source for Entra guest sign-in (an inversion)** — a *human's* Google account (personal Gmail or Workspace-managed) is registered as an accepted external identity provider for Entra External ID, and the human is invited as a B2B guest. This is a fundamentally different mechanism from the SA token bridge above: it's a **human interactive OAuth sign-in**, not a machine-to-machine token exchange, and it inverts the usual pattern of Entra being the central IdP everyone else trusts.
- **BigQuery Omni** — GCP's cross-cloud analytics engine queries Azure Blob Storage directly, authenticating as a GCP-controlled identity trusted by a customer-created Entra App/service principal with Storage RBAC access. No data ever moves between clouds and Google never holds an Azure credential — but the trust is a real, standing bridge.
- **GKE attached clusters (Fleet)** — GCP's fleet-management layer registers an existing Azure AKS cluster via a Connect Agent pod running inside it, using a GCP-issued credential and a Kubernetes RBAC binding. Compute/Kubernetes reach, not an Entra identity bridge.

**The bridge determines what evidence exists on both sides**, and bridge #1 is the sharpest illustration of the asymmetry named above: on the AWS side of this same GCP SA mechanism, the federated subject (the SA's numeric ID) is embedded **directly in the response of the live federation event** (`responseElements.subjectFromWebIdentityToken`). On the Azure side, it is not. Entra's service-principal sign-in log shows that *the app* authenticated and requested a token — it does not surface which external `sub` claim satisfied the federated credential. To find out which GCP SA is trusted, you have to read the federated credential's **static configuration**, not a live event. Keep this distinction in your head throughout the destination-side section below.

This note works the investigation from the GCP side first, then the Azure side, then ties the two together with the fields that prove it was the same actor both times.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method). See also **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** for the contrast — the same starting cloud, a destination with native trust waiting for it on both ends — and **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** for this exact pairing worked from the other direction.

## Contents

- [The Bridges — GCP → Azure](#the-bridges--gcp--azure)
- [Source-Side Investigation — GCP Logs](#source-side-investigation--gcp-logs)
- [Destination-Side Investigation — Azure/Entra Logs](#destination-side-investigation--azureentra-logs)
- [Correlation — Tying the GCP Identity to the Azure Session](#correlation--tying-the-gcp-identity-to-the-azure-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — GCP → Azure

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|-------------|---------------------|
| 1 | **GCP SA identity token → Entra federated credential** | A GCP service account calls `generateIdToken` (issuer `https://accounts.google.com`, `sub` = the SA's numeric unique ID), then exchanges it at Entra's token endpoint for an access token. Unlike AWS, the customer must **explicitly register** Google's issuer + the SA's subject on the App Registration's federated credential | Less common than the AWS direction, but documented and supported | The Entra App Registration's **federated credential** (issuer, subject, audience) — a fully customer-typed object |
| 2 | **Stored/leaked Azure credential in GCP** | An Entra App Registration's client secret sits in Secret Manager (`projects/987654321000/secrets/azure-sp-secret/versions/latest`), a Cloud Functions environment variable, or a Cloud Build substitution variable | 🔴 Very common — the "boring" bridge | The secret object itself; no cloud-native trust relationship to find |
| 3 | **GCP-hosted CI/CD deploying into Azure** | A Cloud Build trigger or a self-hosted GitHub Actions/GitLab runner on Compute Engine uses bridge 1 (preferred, keyless) or bridge 2 (stored key, often legacy) to deploy | Common — federated credentials are increasingly the recommended pattern here | Whichever of bridge 1 or 2 the pipeline actually uses |
| 4 | **Google as a federation source for Entra guest sign-in** | Entra External ID accepts Google as a direct federation source for B2B guest invitations (Entra admin center → External Identities → All identity providers → Google, backed by a Google Cloud OAuth 2.0 client). A human authenticates with their own Google credentials, not a Microsoft account | Uncommon — an inversion of the usual "Entra is the central IdP" pattern, but real | The Entra **identity provider** config (Google OAuth Client ID/secret) + the guest invitation itself |
| 5 | **BigQuery Omni** | GCP's cross-cloud analytics engine queries Azure Blob Storage directly; query compute runs in GCP-managed infrastructure, authenticating as a GCP-controlled identity trusted by a customer-created Entra App/SP holding Storage RBAC on the target account | Growing in data-engineering shops, unique to GCP | The Entra App/SP's role assignment on the Storage Account (`Storage Blob Data Reader` or similar) |
| 6 | **GKE attached clusters (Fleet)** | GCP's fleet-management layer registers an existing Azure AKS cluster (`projects/contoso-prod/locations/global/memberships/aks-prod-cluster`) via a Connect Agent pod running inside that cluster, using a GCP-issued credential and a Kubernetes RBAC binding | Native multicloud GKE was deprecated March 2025; attached-clusters/Fleet registration is current | The Fleet membership resource + the Connect Agent's RBAC binding inside AKS |

## Source-Side Investigation — GCP Logs

Work these in order: the identity-token mint (bridge #1) and secret reads (bridge #2) live in **Cloud Audit Logs**; the human sign-in behind bridge #4 lives in **Workspace's Login & Auth Audit** — and for personal (non-Workspace) Gmail guests, GCP-side evidence may not exist at all. See Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** for the full field reference this section applies to each bridge.

### Bridge #1 — GCP SA identity token → Entra federated credential

Same underlying GCP mechanic as the AWS direction — the difference is entirely on the Azure side (below). GCP's own evidence shape doesn't change based on which cloud the token is headed for.

**Path A — minted via the IAM Credentials API** (a principal holding `roles/iam.serviceAccountTokenCreator` on the target SA calls `generateIdToken` explicitly):

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The mint call | `google.iam.credentials.v1.GenerateIdToken` | Admin Activity — always logged when called through the API |
| `protoPayload.authenticationInfo.principalEmail` | Who actually called it | `ci-pipeline@contoso-prod.iam.gserviceaccount.com` | May differ from the SA the token is *for* — check `serviceAccountDelegationInfo` |
| `protoPayload.resourceName` | The SA the token was minted for | `projects/contoso-prod/serviceAccounts/gcp-azure-deploy@contoso-prod.iam.gserviceaccount.com` | The identity that must match the Entra federated credential's registered subject |
| `protoPayload.request.audience` | The requested `aud` claim | `api://AzureADTokenExchange` | 🔴 Microsoft's documented required audience value for federated credentials — a token minted with any other audience won't validate at Entra's token endpoint |
| `protoPayload.requestMetadata.callerIp` | Where the mint call came from | `35.190.x.x` | Compare against the Azure-side sign-in IP |

**Path B — minted locally via the attached-resource metadata server** (the SA is attached to a Compute Engine VM, Cloud Run service, Cloud Function, or GKE pod):

> 🔴 Same gap as the AWS direction, stated again because it applies identically here: this path calls the local metadata server (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<sa>/identity?audience=api://AzureADTokenExchange`) directly, on-instance — **no Cloud Audit Log entry is produced.** If Azure shows a service-principal sign-in but GCP shows no matching `GenerateIdToken` event, that's the expected shape of this path, not a logging gap to widen.

```bash
gcloud logging read \
 'protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"
  AND protoPayload.request.audience="api://AzureADTokenExchange"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Logging → Logs Explorer**, filtered on `protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"`; **IAM & Admin → Service Accounts → (SA) → Permissions** for TokenCreator holders (Path A) or the resource's own config for SA attachment (Path B).

### Bridge #2 — Stored/leaked Azure credential in GCP

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The retrieval action | `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` | 🔴 Data Access — confirm it's enabled for `secretmanager.googleapis.com`, or this read is invisible |
| `protoPayload.resourceName` | Which secret | `projects/987654321000/secrets/azure-sp-secret/versions/latest` | Confirm it's the one holding the Entra SP client secret |
| `protoPayload.authenticationInfo.principalEmail` | Who read it | `attacker@contoso.com` | 🔴 A human/SA that isn't the owning pipeline |
| `protoPayload.requestMetadata.callerIp` | From where | `203.0.113.77` | New IP/geo relative to the pipeline's normal host |

```bash
gcloud logging read \
 'protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
  AND protoPayload.resourceName:"azure"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Secret Manager → Secrets** (inventory) or **Logging → Logs Explorer** filtered on `AccessSecretVersion`.

### Bridge #3 — GCP-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline uses — the distinguishing signal is the *actor*: a Cloud Build service account or a self-hosted runner's attached SA calling `generateIdToken`/using the metadata server (bridge 1) or reading a stored secret (bridge 2) on a build schedule rather than ad hoc. Pull **Cloud Build build history** (`gcloud builds list`) alongside the Cloud Audit Log events above.

### Bridge #4 — Google as a federation source for Entra guest sign-in

This is a **human, interactive OAuth sign-in** — not the machine token exchange in bridge #1. Keep the two separate in your notes; they leave completely different evidence.

| Field (Login & Auth Audit, Workspace-managed guests only) | What it tells you | Example value | Notes |
|----------------------------------------------------------|--------------------|----------------|-------|
| `actor.email` | The Google account used | `alice@contoso.com` | Only present if the guest's Google account is Workspace-managed |
| `events[].name` | The sign-in result | `login_success` | The guest's real authentication happens here, at Google |
| `login_type` | How they authenticated | `google_password` | Google's log has **no field indicating this login satisfied an Entra guest sign-in** — it looks identical to any other Google login |
| `ipAddress` | Where from | `203.0.113.45` | Compare against the Entra-side sign-in IP |

> 🔴 **For a personal Gmail guest (not Workspace-managed), there is no enterprise-visible Google-side log at all.** Google's consumer account activity isn't something your org can pull. If the guest used a personal Gmail address, the GCP/Workspace side of this bridge is a dead end by design — the entire evidentiary burden falls on the Azure side below. State this explicitly rather than searching for evidence that structurally cannot exist.

Console path (Workspace-managed guests only): **Admin console → Reporting → Audit and investigation → Login events**, filtered by user. Full field detail: Google **[Login & Auth Audit for DFIR](../Google/Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)**.

### Bridge #5 — BigQuery Omni

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The connection resource being created | `google.cloud.bigquery.connection.v1.ConnectionService.CreateConnection` | One-time setup event |
| `protoPayload.resourceName` | The Omni connection | `projects/contoso-prod/locations/azure-eastus/connections/blob-omni-conn` | Names the region and connection |
| BigQuery job events referencing the connection | The actual queries against Blob Storage | `INFORMATION_SCHEMA.JOBS_BY_PROJECT`, `query` referencing the Omni connection and an `azure://` external table | Same job-history evidence as any BigQuery query — see **BigQuery for DFIR** |

```sql
-- Query jobs that used the Azure Omni connection, with volume
SELECT creation_time, user_email, total_bytes_processed, query
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE query LIKE '%blob-omni-conn%'
ORDER BY total_bytes_processed DESC;
```

Console path: **BigQuery → Connections** (inventory the Omni connections + their target Entra App/SP); **BigQuery → Job history** for the queries. Full field detail: Google **[BigQuery for DFIR](../Google/Google%20Cloud/Databases/BigQuery/BigQuery%20for%20DFIR.md)**.

### Bridge #6 — GKE attached clusters (Fleet) reaching AKS

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The Fleet membership registration | `google.cloud.gkehub.v1.GkeHubMembershipService.CreateMembership` | One-time onboarding event |
| `protoPayload.resourceName` | The registered cluster | `projects/contoso-prod/locations/global/memberships/aks-prod-cluster` | Confirms which AKS cluster GCP can now reach |
| `protoPayload.authenticationInfo.principalEmail` | Who registered it | `alice@contoso.com` | Should be a small, known set of platform admins |

This bridge is compute/Kubernetes reach, not an Entra identity — the actual lateral-movement moment is whether the GCP console/API was used to push anything through the Connect Agent afterward. Full treatment: Google **[GKE for DFIR](../Google/Google%20Cloud/Serverless%20%26%20Containers/GKE/GKE%20for%20DFIR.md)** and **[00 - Cross-Cloud Bridges Overview → Infrastructure Bridges](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair)**.

## Destination-Side Investigation — Azure/Entra Logs

All of this lives in **Entra Sign-in and Audit logs**. See Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** and **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** for the full field reference this section applies to each bridge.

### Bridge #1 — Entra federated credential trusting a GCP SA

This is the note's headline mechanic, and the asymmetry from **Why This Happens** matters most right here.

| Field (Service-principal sign-in) | What it tells you | Example value | Notes |
|------------------------------------|--------------------|----------------|-------|
| `AppId` / `ServicePrincipalName` | Which Entra app authenticated | `a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d` / `gcp-azure-federation-app` | Confirms *which* app — but not which external identity presented the credential |
| `ResourceDisplayName` | What the token was requested for | `"Azure Storage"` / `"Windows Azure Service Management API"` | The Azure resource the SA can now act against |
| `IPAddress` | Where the token exchange call came from | `35.190.x.x` | Should fall in GCP's published IP ranges for a legitimate GCP-hosted workload |
| `ResultType` | Success vs failure | `0` | |

> 🔴 **The gap this bridge is built around:** the sign-in event above proves the **app** authenticated. It does **not** show which GCP SA's `sub` claim satisfied the federated credential — unlike AWS's `responseElements.subjectFromWebIdentityToken`, Entra's sign-in log carries no equivalent field. To find out which SA is trusted, you must read the **federated credential's static configuration**, not a live event:

```bash
# Read the federated credential's configured issuer, subject, and audience — the actual trust gate
az ad app federated-credential list --id <app-id>
```

Example configuration (not a per-event log line):

```jsonc
{
  "name": "gcp-sa-trust",
  "issuer": "https://accounts.google.com",
  "subject": "103547991597142817347",
  "audiences": ["api://AzureADTokenExchange"]
}
```

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `issuer` | The trusted OIDC issuer | `https://accounts.google.com` | Confirms the app trusts Google at all |
| `subject` | The exact GCP SA subject trusted | `103547991597142817347` | 🔴 The SA's numeric unique ID — a bare number, same as the AWS direction, but here it's a **standing config value**, not something embedded in every event |
| `audiences` | The required `aud` claim | `["api://AzureADTokenExchange"]` | A token minted with any other audience is rejected before it ever reaches the sign-in log |

Also check the **Entra Audit Log** for when this trust was created — `Add federated identity credential for application` — with `TargetResources` naming the app; parameter detail on issuer/subject varies by tenant audit taxonomy, so don't assume it will always show the subject inline.

Console path: **Entra admin center → App registrations → (app) → Certificates & secrets → Federated credentials**, for the configuration; **Entra admin center → Enterprise applications → (app) → Sign-in logs**, for the exchange events.

### Bridge #2 — Stored/leaked Azure credential

No federation event exists — this is a plain client secret. Work it like any leaked-credential case (see Microsoft **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)**), with one extra angle: **prove the GCP origin**.

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The credential type | The app's `PasswordCredentials`/`KeyCredentials` entry used | A client secret, not a federated credential | Confirms bridge #2, not #1 |
| Source IP falling in GCP's published ranges | Service-principal sign-in `IPAddress` | `35.190.x.x` | Cross-reference against Google's published [Cloud IP ranges](https://www.gstatic.com/ipranges/cloud.json) — a secret that's only ever used from your own known egress suddenly calling from a GCP-owned range is the tell |
| Tooling fingerprint | Sign-in log client/user-agent detail | A Python/Go Azure SDK signature consistent with a Cloud Function/Cloud Run/Compute Engine runtime | An SDK signature inconsistent with the app's expected environment |

### Bridge #3 — GCP-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline used — the distinguishing signal is cadence (build-triggered, not ad hoc) and `IPAddress` falling in Cloud Build's/Compute Engine's ranges rather than a developer's known egress.

### Bridge #4 — Google as a federation source for Entra guest sign-in

| Field (Entra Sign-in Logs) | What it tells you | Example value | Notes |
|------------------------------|--------------------|----------------|-------|
| `UserPrincipalName` | The guest's identity in your tenant | `alice_gmail.com#EXT#@contoso.onmicrosoft.com` | The `#EXT#` shape marks a B2B guest — the local part encodes the external email |
| `UserType` | Confirms guest status | `Guest` | |
| `IPAddress` + `Location` | Where the sign-in came from | `203.0.113.45` / `Mountain View, CA, US` | Compare against Workspace's Login & Auth Audit **only if** the guest's Google account is Workspace-managed (bridge #4 GCP-side section, above) |
| `ResourceDisplayName` / `AppDisplayName` | What the guest signed into | The resource the invitation grants access to | Confirm it matches the scope of the original invitation |

> 🔴 If the guest used a **personal Gmail address**, this Entra sign-in event may be the **only** evidence that exists anywhere for this authentication — there is no enterprise Google-side log to pivot to. Treat the Entra sign-in log as the sole source of truth for this bridge in that case, and say so explicitly in your timeline rather than implying a corroborating GCP-side record exists.

Console path: **Entra admin center → Identity → External Identities → All identity providers** (confirm Google is configured, and since when); **Entra admin center → Identity → Monitoring & health → Sign-in logs**, filtered to `UserType = Guest`.

### Bridge #5 — BigQuery Omni

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| The RBAC role assignment | Azure Activity Log, `Microsoft.Authorization/roleAssignments/write` | Assigns `Storage Blob Data Reader` to the Entra App/SP registered for Omni | One-time setup event — confirm scope is the intended Storage Account only |
| Service-principal sign-ins | Same shape as bridge #1 | `IPAddress` should fall in GCP's published ranges — this is Google's Omni compute plane, not a customer SA | Don't expect this identity to match any GCP SA you can enumerate in your own project |
| Resulting Blob activity | Storage Account diagnostic logs, `GetBlob` at volume | A burst against the target container | Corroborate against the BigQuery job history on the GCP side — a burst lining up with a scheduled query is expected; one that doesn't is the anomaly |

Console path: **Storage Account → Access Control (IAM)**, to confirm the RBAC assignment; **Storage Account → Monitoring → Diagnostic settings**, for the Blob access logs.

### Bridge #6 — GKE attached clusters (Fleet) reaching AKS

No Entra identity evidence exists on the Azure side for the registration itself — the Connect Agent runs as a pod *inside* the AKS cluster, using a GCP-issued credential validated against Kubernetes RBAC, not against Entra. Work it from the **AKS cluster's own Kubernetes control-plane audit log** (via Azure Monitor / Container Insights, not the Entra sign-in logs) for the Connect Agent's service account and what it did inside the cluster.

## Correlation — Tying the GCP Identity to the Azure Session

| Anchor | GCP side | Azure side | Example match | Strength |
|--------|----------|------------|-----------------|----------|
| The SA's numeric unique ID | `gcloud iam service-accounts describe <sa> --format='value(uniqueId)'` (config, or `GenerateIdToken`'s `resourceName` if Path A applies) | The federated credential's configured `subject` (`az ad app federated-credential list`) — **not** a per-event field | `103547991597142817347` ↔ `103547991597142817347` | 🔴 High as a config-to-config match, but weaker as a per-event anchor than the AWS direction — you're matching two static configurations, not two live events |
| Timing | `eventTime` of `GenerateIdToken` (Path A only) | Service-principal sign-in `TimeGenerated` | `14:22:01Z` (GCP) ↔ `14:22:03Z` (Azure) | High when Path A applies and within seconds; N/A for Path B |
| Source IP | `requestMetadata.callerIp` (Path A only) | Sign-in `IPAddress` | `35.190.x.x` ↔ `35.190.x.x` | High for Path A; not available for Path B |
| The federated credential's audience | The requested `aud` claim (Path A: `protoPayload.request.audience`) | The federated credential's configured `audiences` | `api://AzureADTokenExchange` ↔ same | High — confirms the token was even eligible to validate at Entra's token endpoint |
| The Google human (bridge #4) | `actor.email` in Login & Auth Audit, **Workspace-managed guests only** | `UserPrincipalName`'s `#EXT#`-encoded local part | `alice@contoso.com` ↔ `alice_contoso.com#EXT#@...` | High when the GCP side exists at all; **absent entirely** for personal Gmail guests — state the gap rather than forcing a match |
| Secret identity (bridge #2) | Which secret was read, and by whom | The client secret's `keyId`/thumbprint used at sign-in | The credential ID in the burned Secret Manager secret matches the one used at the Azure sign-in | High — ties a specific leaked secret to specific Azure-side usage |

## Hunt at Scale

```bash
# gcloud: every GenerateIdToken call targeting the Azure audience, last 7 days
gcloud logging read \
 'protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"
  AND protoPayload.request.audience="api://AzureADTokenExchange"' \
 --project=contoso-prod --freshness=7d --format='table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName)'
```

```kql
// KQL: service-principal sign-ins from GCP-owned IP ranges, cross-referenced against
// known federated apps — replace the IP prefix with Google's current published ranges
AADServicePrincipalSignInLogs
| where IPAddress startswith "35.190." or IPAddress startswith "34."
| summarize count(), make_set(ResourceDisplayName) by ServicePrincipalName, AppId
| order by count_ desc
```

```kql
// KQL: new federated identity credentials added in the last 7 days (persistence sweep)
AuditLogs
| where OperationName == "Add federated identity credential for application"
| where TimeGenerated > ago(7d)
| project TimeGenerated, InitiatedBy, TargetResources
```

```kql
// KQL: guest sign-ins where the UPN's #EXT# domain suggests a consumer Google account
SigninLogs
| where UserType == "Guest"
| where UserPrincipalName has "gmail.com#EXT#"
| project TimeGenerated, UserPrincipalName, IPAddress, ResourceDisplayName
```

A modest cross-cloud SecOps/UDM landing point: normalize the Azure-side service-principal sign-in (`target.resource.name` = `ResourceDisplayName`, `principal.asset.ip` = `IPAddress`) and, where Path A applies, the GCP-side `GenerateIdToken` mint (`principal.user.email_addresses` = `principalEmail`) to a shared timeline, and alert on a service-principal sign-in whose app has a federated credential trusting `accounts.google.com` when no corresponding GCP-side mint event exists in the preceding few minutes — remembering, as with the AWS note, that this is expected for Path B (attached-workload minting) and not automatically a finding. Keep it light; the deep read stays in the native queries above.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A federated credential with `issuer: https://accounts.google.com` and no `subject` restriction, or an `audiences` value left at a generic/default string | Any GCP SA that discovers the app can attempt to federate in — audit immediately regardless of confirmed abuse |
| A new federated identity credential added to an app you don't recognize | Persistence — an attacker who can request the token themselves doesn't need to steal one |
| A service-principal sign-in from an IP outside GCP's published ranges, on an app with a Google-trusting federated credential | Token replay from somewhere other than the expected GCP workload |
| Google configured as an Entra External ID identity provider, and nobody on the team can explain when or why | Bridge #4 set up as a backdoor guest path, not a legitimate integration |
| A guest sign-in with a `#EXT#` UPN mapping to a personal Gmail address, accessing anything sensitive | No corroborating Google-side log will ever exist for this — treat the Entra sign-in log as the sole evidence and weigh it accordingly |
| An Entra App/SP holding `Storage Blob Data Reader` (or broader) with no known BigQuery Omni connection referencing it | The trust is being abused by something other than Omni itself |
| `AKIA`-style Azure client-secret use (a client secret sign-in, not a federated credential) from a GCP IP/ASN with no known GCP-side integration | Bridge #2 surfacing — leaked secret, assume it's burned |
| A GKE Fleet membership registering an AKS cluster nobody requested | A new remote-control path into that cluster, planted as persistence |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| The full bridge inventory across all six directional pairs | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| This pair from the other direction | **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** |
| The same starting cloud, a far more frictionless destination | **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** |
| GCP reached as a destination, for contrast | **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** |
| Entra sign-in log deep dive | Microsoft **[Sign-in Logs for DFIR](../Microsoft/Entra%20ID/Sign-in%20Logs/Sign-in%20Logs%20for%20DFIR.md)** |
| App Registrations, service principals, federated credentials | Microsoft **[Applications & Service Principals for DFIR](../Microsoft/Entra%20ID/Applications%20%26%20Service%20Principals/Applications%20%26%20Service%20Principals%20for%20DFIR.md)** |
| GCP Cloud Audit Logs deep dive | Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** |
| GCP service accounts, keys, impersonation | Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)** |
| GCP Workload Identity Federation (the inbound direction) | Google **[Workload Identity Federation for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Workload%20Identity%20Federation/Workload%20Identity%20Federation%20for%20DFIR.md)** |
| Workspace login/takeover investigation | Google **[Login & Auth Audit for DFIR](../Google/Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)** |
| Workspace admin-level persistence (DWD, new admins) | Google **[Admin Audit Log for DFIR](../Google/Google%20Workspace/Admin%20Audit%20Log/Admin%20Audit%20Log%20for%20DFIR.md)** |
| BigQuery exfil/Omni investigation | Google **[BigQuery for DFIR](../Google/Google%20Cloud/Databases/BigQuery/BigQuery%20for%20DFIR.md)** |
| GKE and the Fleet/attached-clusters bridge | Google **[GKE for DFIR](../Google/Google%20Cloud/Serverless%20%26%20Containers/GKE/GKE%20for%20DFIR.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- Microsoft: Workload identity federation (federated credentials) — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Microsoft: Configure an app to trust a Google Cloud service account — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation-create-trust
- Microsoft: Add Google as an identity provider for External ID — https://learn.microsoft.com/en-us/entra/external-id/google-federation
- Google Cloud: Create short-lived credentials (identity tokens, `generateIdToken`) — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Google Cloud: BigQuery Omni overview — https://cloud.google.com/bigquery/docs/omni-introduction
- Google Cloud: GKE attached clusters / Fleet — https://cloud.google.com/kubernetes-engine/multi-cloud/docs/aws/how-to/attached-clusters-create
- Google Cloud: IP address ranges (JSON feed) — https://www.gstatic.com/ipranges/cloud.json
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
