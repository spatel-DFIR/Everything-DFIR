# GCP → AWS

## Why This Happens

GCP and AWS are separate accounts with separate logins. By default, a GCP identity means **nothing** to AWS, and an AWS identity means nothing to GCP — the two clouds don't know each other exist. Nobody walks from one into the other unless someone **deliberately built a bridge**. But this particular direction has something no other pairing in this repo has: **both ends already trust each other natively.** AWS ships Google's OIDC issuer (`accounts.google.com`) as a built-in federated provider — no IAM OIDC provider resource to create. GCP, from the other direction, ships a purpose-built AWS provider type in Workload Identity Federation (see **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)**). Nowhere else in this repo do both sides show up with the trust relationship already half-built by the vendors themselves.

An actor with a foothold in GCP crosses into AWS using one of these mechanisms:

- **A GCP service account's identity token, presented to AWS's built-in Google provider (the headline bridge)** — a GCP service account mints its own OIDC identity token (`generateIdToken`, issuer `https://accounts.google.com`, `sub` = the SA's numeric unique ID) and hands it straight to `sts:AssumeRoleWithWebIdentity`. AWS already trusts `accounts.google.com` as an issuer — the only thing a customer configures is the **role's trust policy**, not a provider resource. This is about as close to frictionless as cross-cloud federation gets anywhere in this repo, and it means an attacker doesn't need to find a *misconfigured* trust to abuse — a *correctly configured, intentional* one is already doing exactly what both vendors designed it to do. The only question is whether the trust policy's condition is scoped tightly enough.
- **A plain leaked AWS credential in a GCP secret store** — an `AKIA` key sitting in Secret Manager, a Cloud Functions environment variable, or a Cloud Build substitution variable. No trust relationship, no federation, no login event — whoever reads it just uses it directly against AWS. The "boring" bridge, same shape as every other cloud pair in this repo, and still the one most likely to already be sitting in your environment.
- **GCP-hosted CI/CD deploying into AWS** — a Cloud Build trigger or a self-hosted GitHub Actions/GitLab runner on Compute Engine uses either of the two mechanisms above to push changes into AWS. Not a distinct trust mechanism on its own — just a distinct *actor* riding one of the first two.
- **Google Workspace / Cloud Identity as the external SAML IdP for AWS IAM Identity Center** — a *human* signs into Workspace with their normal Google credentials, and Workspace vouches for them to AWS Identity Center over SAML. If a phished Workspace account has this SSO path into AWS, whoever now controls that account has that same AWS access — no separate "AWS hack" needed.
- **BigQuery Omni** — GCP's cross-cloud analytics engine queries S3 directly; compute runs in GCP-managed infrastructure inside AWS's region, authenticating as a GCP-controlled `accounts.google.com` identity trusted by a customer-created AWS IAM role. No data ever moves between clouds and Google never holds an AWS credential — but the IAM role's trust is a real, standing bridge worth knowing about.
- **GKE attached clusters (Fleet)** — GCP's fleet-management layer registers an existing AWS EKS cluster via a Connect Agent pod running inside it, using a GCP-issued credential and a Kubernetes RBAC binding. Not an identity bridge in the SSO/OIDC sense — it's compute/Kubernetes reach, planted as a pod.

**The bridge determines what evidence exists on both sides**, and bridge #1 illustrates a gap worth stating up front: when a GCP service account is *attached* to a resource (a Compute Engine VM, a Cloud Function, a GKE pod) it can mint its own identity token straight from the **local metadata server** — a call that never reaches Google's API surface and so **never appears in Cloud Audit Logs at all**. On this bridge, more than almost any other pairing this repo covers, the AWS side may hold the only record that the exchange happened.

This note works the investigation from the GCP side first, then the AWS side, then ties the two together with the fields that prove it was the same actor both times.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method). See also **[GCP → Azure](GCP%20%E2%86%92%20Azure.md)** for the contrast — the same starting cloud, a destination that requires deliberate issuer registration instead of native trust — and **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** for this exact pairing worked from the other direction.

## Contents

- [The Bridges — GCP → AWS](#the-bridges--gcp--aws)
- [Source-Side Investigation — GCP Logs](#source-side-investigation--gcp-logs)
- [Destination-Side Investigation — AWS Logs](#destination-side-investigation--aws-logs)
- [Correlation — Tying the GCP Identity to the AWS Session](#correlation--tying-the-gcp-identity-to-the-aws-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — GCP → AWS

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|------------|---------------------|
| 1 | **GCP SA identity token → AWS's built-in Google provider** | A GCP service account calls `generateIdToken` (issuer `https://accounts.google.com`, `sub` = the SA's numeric unique ID) and presents the token to `sts:AssumeRoleWithWebIdentity`. AWS already trusts `accounts.google.com` natively — no IAM OIDC provider resource exists to find | 🔴 Growing — one of the lowest-friction cross-cloud federation setups in this repo | The role's trust policy **`Condition`** on `accounts.google.com:aud`/`:sub` — there is no provider resource to audit |
| 2 | **Stored/leaked AWS credential in GCP** | An `AKIA` key sits in Secret Manager (`projects/987654321000/secrets/aws-prod-deploy-key/versions/latest`), a Cloud Functions environment variable, or a Cloud Build substitution variable | 🔴 Very common — the "boring" bridge | The secret object itself; no cloud-native trust relationship to find |
| 3 | **GCP-hosted CI/CD deploying into AWS** | A Cloud Build trigger or a self-hosted GitHub Actions/GitLab runner on Compute Engine uses bridge 1 (preferred, keyless) or bridge 2 (stored key, often legacy) to deploy | Common — WIF is increasingly the recommended pattern here, displacing stored keys | Whichever of bridge 1 or 2 the pipeline actually uses |
| 4 | **Google Workspace/Cloud Identity as external SAML IdP for AWS IAM Identity Center** | Workspace is registered as the external identity source for Identity Center over SAML 2.0 (Google SSO URL + Google Issuer URL pasted into the Identity Center IdP config); the human signs into Workspace, gets redirected into AWS with a permission-set role | Common in Workspace-centric orgs | The Identity Center external-IdP config + the Workspace SAML app |
| 5 | **BigQuery Omni** | GCP's cross-cloud analytics engine queries S3 directly; query compute runs in GCP-managed infrastructure inside AWS's region, authenticating as a GCP-controlled `accounts.google.com` identity trusted by a customer-created AWS IAM role | 🔴 Growing in data-engineering shops, unique to GCP | The AWS IAM role's trust policy (`arn:aws:iam::123456789012:role/bigquery-omni-role`) — no cross-cloud data movement |
| 6 | **GKE attached clusters (Fleet)** | GCP's fleet-management layer registers an existing AWS EKS cluster (`projects/contoso-prod/locations/global/memberships/eks-prod-cluster`) via a Connect Agent pod running inside that cluster, using a GCP-issued credential and a Kubernetes RBAC binding | Native multicloud GKE was deprecated March 2025; attached-clusters/Fleet registration is current | The Fleet membership resource + the Connect Agent's RBAC binding inside EKS |

## Source-Side Investigation — GCP Logs

Work these in order: the identity-token mint (bridge #1) and secret reads (bridge #2) live in **Cloud Audit Logs**; the human sign-in behind bridge #4 lives in **Workspace's Login & Auth Audit**. See Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** for the full field reference this section applies to each bridge.

### Bridge #1 — GCP SA identity token → AWS's built-in Google provider

The mechanics, precisely, because getting this right changes what you go looking for: an identity token isn't a permissions grant, it's a signed claim of *who the caller is* — GCP hands it out through two different paths, and only one of them is logged.

**Path A — minted via the IAM Credentials API** (a principal holding `roles/iam.serviceAccountTokenCreator` on the target SA calls `generateIdToken` explicitly — common when a human, another SA, or a CI/CD pipeline impersonates the SA rather than running as it):

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The mint call | `google.iam.credentials.v1.GenerateIdToken` | Admin Activity — always logged when called through the API |
| `protoPayload.authenticationInfo.principalEmail` | Who actually called it | `ci-pipeline@contoso-prod.iam.gserviceaccount.com` | May differ from the SA the token is *for* — check `serviceAccountDelegationInfo` for the impersonation chain |
| `protoPayload.resourceName` | The SA the token was minted for | `projects/contoso-prod/serviceAccounts/gcp-aws-deploy@contoso-prod.iam.gserviceaccount.com` | The identity that shows up on the AWS side |
| `protoPayload.request.audience` | The requested `aud` claim | `arn:aws:iam::123456789012:role/gcp-workload-federation-role` | 🔴 Should match exactly what the AWS role's trust policy condition expects — a mismatch here means the token won't validate on the AWS side, a *match* means it will |
| `protoPayload.requestMetadata.callerIp` | Where the mint call came from | `35.190.x.x` | Compare against the AWS-side `sourceIPAddress` |

**Path B — minted locally via the attached-resource metadata server** (the default, common path when the SA is attached to a Compute Engine VM, Cloud Run service, Cloud Function, or GKE pod running *as* that SA):

> 🔴 **The gap to state explicitly on this bridge, every time:** this path never calls `iamcredentials.googleapis.com` — the workload asks its own local metadata server (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<sa>/identity?audience=...`) directly, entirely on-instance. **No Cloud Audit Log entry is produced.** If the AWS side shows a federation event carrying this SA's `sub`, but you can't find a matching `GenerateIdToken` event in Cloud Audit Logs, that's not a logging gap to widen — it's the expected shape of this exact path. Pivot to the compute resource itself (VM guest logs, Cloud Run/Function invocation logs, GKE pod events) for corroboration instead.

```bash
# Confirm which SA is attached to a resource — the workload identity that can mint its own token locally
gcloud compute instances describe <instance> --zone=<zone> --format='value(serviceAccounts)'

# If minted via the API instead, pull the GenerateIdToken events directly
gcloud logging read \
 'protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Logging → Logs Explorer**, filtered on `protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"`; **IAM & Admin → Service Accounts → (SA) → Permissions** to see who holds `TokenCreator` on it (Path A) or **Compute Engine/Cloud Run/Cloud Functions/GKE → the resource** to confirm SA attachment (Path B).

### Bridge #2 — Stored/leaked AWS credential in GCP

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The retrieval action | `google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion` | 🔴 Data Access — confirm it's enabled for `secretmanager.googleapis.com`, or this read is invisible (see Cloud Audit Logs' Data Access gap) |
| `protoPayload.resourceName` | Which secret | `projects/987654321000/secrets/aws-prod-deploy-key/versions/latest` | Confirm it's the one holding the AWS key |
| `protoPayload.authenticationInfo.principalEmail` | Who read it | `attacker@contoso.com` | 🔴 A human/SA that isn't the owning pipeline |
| `protoPayload.requestMetadata.callerIp` | From where | `203.0.113.77` | New IP/geo relative to the pipeline's normal host |

```bash
gcloud logging read \
 'protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"
  AND protoPayload.resourceName:"aws"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Secret Manager → Secrets** (inventory) or **Logging → Logs Explorer** filtered on `AccessSecretVersion`.

### Bridge #3 — GCP-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline uses — the distinguishing signal is the *actor*: a Cloud Build service account or a self-hosted runner's attached SA calling `generateIdToken`/using the metadata server (bridge 1) or reading a stored key (bridge 2) on a build schedule rather than ad hoc. Pull the **Cloud Build build history** (`gcloud builds list`) alongside the Cloud Audit Log events above; an off-schedule build, or one triggered by an unexpected commit source, is the abuse signature.

### Bridge #4 — Google Workspace as external SAML IdP for AWS Identity Center

Here Workspace *is* the identity provider — the human's real authentication happens at Google, not AWS. Workspace's own audit trail has no separate "SAML assertion issued to AWS" event; the login itself is the evidence.

| Field (Login & Auth Audit) | What it tells you | Example value | Notes |
|------------------------------|--------------------|----------------|-------|
| `actor.email` | The Workspace user | `alice@contoso.com` | The anchor you carry into AWS |
| `events[].name` | The sign-in result | `login_success` | This *is* the authentication — Workspace doesn't log a distinct "assertion sent" event |
| `login_type` | How they authenticated | `google_password` | Normal for this bridge — Workspace is the IdP, not a relying party, so you won't see `saml` here |
| `ipAddress` | Where from | `203.0.113.45` | Compare against the AWS-side `sourceIPAddress` on the resulting role assumption |
| `is_suspicious` | Google's verdict | `false` / `true` | 🔴 `true` feeding straight into an AWS federation event is a strong lead |

```bash
# API (Admin SDK Reports): the user's logins in the window
GET https://admin.googleapis.com/admin/reports/v1/activity/users/alice@contoso.com/applications/login \
  ?startTime=2026-07-01T00:00:00Z&endTime=2026-07-16T00:00:00Z
```

Console path: **Admin console → Reporting → Audit and investigation → Login events**, filtered by user. Full field detail: Google **[Login & Auth Audit for DFIR](../Google/Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)**.

### Bridge #5 — BigQuery Omni

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The connection resource being created | `google.cloud.bigquery.connection.v1.ConnectionService.CreateConnection` | One-time setup event — confirm who created it and when |
| `protoPayload.resourceName` | The Omni connection | `projects/contoso-prod/locations/aws-us-east-1/connections/s3-omni-conn` | Names the region and connection |
| BigQuery job events referencing the connection | The actual queries against S3 | `INFORMATION_SCHEMA.JOBS_BY_PROJECT`, `query` referencing `s3://contoso-omni-data/...` via the external connection | Same job-history evidence as any BigQuery query — see **BigQuery for DFIR** |

```sql
-- Query jobs that used the Omni connection, with volume
SELECT creation_time, user_email, total_bytes_processed, query
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE query LIKE '%s3-omni-conn%'
ORDER BY total_bytes_processed DESC;
```

Console path: **BigQuery → Connections** (inventory the Omni connections + their target IAM role); **BigQuery → Job history** for the queries themselves. Full field detail: Google **[BigQuery for DFIR](../Google/Google%20Cloud/Databases/BigQuery/BigQuery%20for%20DFIR.md)**.

### Bridge #6 — GKE attached clusters (Fleet) reaching EKS

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The Fleet membership registration | `google.cloud.gkehub.v1.GkeHubMembershipService.CreateMembership` | One-time onboarding event |
| `protoPayload.resourceName` | The registered cluster | `projects/contoso-prod/locations/global/memberships/eks-prod-cluster` | Confirms which EKS cluster GCP can now reach |
| `protoPayload.authenticationInfo.principalEmail` | Who registered it | `alice@contoso.com` | Should be a small, known set of platform admins |

This bridge is compute/Kubernetes reach, not an AWS IAM identity — the actual lateral-movement moment is whether the GCP console/API was used to push anything through the Connect Agent afterward. Full treatment: Google **[GKE for DFIR](../Google/Google%20Cloud/Serverless%20%26%20Containers/GKE/GKE%20for%20DFIR.md)** and **[00 - Cross-Cloud Bridges Overview → Infrastructure Bridges](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair)**.

## Destination-Side Investigation — AWS Logs

All of this lives in **CloudTrail** (and IAM Identity Center's own console for bridge #4). The `userIdentity` block is the anchor — see AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** for the full type table; this section applies it to each bridge.

### Bridge #1 — AWS's built-in Google provider

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `eventName` | The federation call | `AssumeRoleWithWebIdentity` | Same STS API every other OIDC bridge in this repo uses |
| `userIdentity.type` | Identity type | `WebIdentityUser` | |
| `responseElements.subjectFromWebIdentityToken` | The GCP SA's numeric unique ID, exactly as AWS extracted it from the token's `sub` claim | `103547991597142817347` | 🔴 **Not self-describing** — a bare number. Cross-reference against `gcloud iam service-accounts describe <sa> --format='value(uniqueId)'` to know which SA it is |
| `responseElements.audience` | The `aud` claim | `arn:aws:iam::123456789012:role/gcp-workload-federation-role` | |
| `responseElements.provider` | The OIDC issuer AWS matched | `accounts.google.com` | Confirms this specific bridge fired, not some other OIDC provider on the same role |
| `requestParameters.roleArn` | The role assumed | `arn:aws:iam::123456789012:role/gcp-workload-federation-role` | |

> 🔴 **The distinction that matters most on this bridge:** there is **no IAM OIDC provider resource** to find. Run `aws iam list-open-id-connect-providers` and `accounts.google.com` will not appear — AWS ships this trust built-in. The only customer-configured artifact is the **role's trust policy**:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "accounts.google.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "accounts.google.com:aud": "arn:aws:iam::123456789012:role/gcp-workload-federation-role",
          "accounts.google.com:sub": "103547991597142817347"
        }
      }
    }
  ]
}
```

```bash
# Confirm there is no customer-created OIDC provider for this issuer (there won't be one)
aws iam list-open-id-connect-providers

# Read the role's trust policy — the only customer-configured piece for this bridge
aws iam get-role --role-name gcp-workload-federation-role --query 'Role.AssumeRolePolicyDocument'
```

Console path: **IAM → Roles → (role) → Trust relationships** to read the condition; **CloudTrail → Event history**, filtered on `AssumeRoleWithWebIdentity`.

### Bridge #2 — Stored/leaked AWS credential

No federation event exists — this is a plain key. Work it like any leaked-credential case (see AWS **[01 - IAM & Identities → Access Keys](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md#access-keys--akia-vs-asia)**), with one extra angle: **prove the GCP origin**.

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The key type | `userIdentity.accessKeyId` prefix | `AKIAIOSFODNN7EXAMPLE` | `AKIA` = long-term, matches a static secret sitting in Secret Manager |
| Source IP falling in GCP's published ranges | `sourceIPAddress` | `35.190.x.x` | Cross-reference against Google's published [Cloud IP ranges](https://www.gstatic.com/ipranges/cloud.json) — a key that's only ever used from your own known egress suddenly calling from a GCP-owned range is the tell |
| Tooling fingerprint | `userAgent` | `aws-sdk-go-v2/1.30.0 exec-env/GoogleCloudFunctions` | AWS SDK calls from a Cloud Function/Cloud Run/Compute Engine instance often carry a distinctive `exec-env` or runtime marker |
| GuardDuty | Finding types like `UnauthorizedAccess:IAMUser/*` or an anomalous-ASN finding | `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | GuardDuty baselines "usual" ASNs for a given key — a first-time GCP ASN can trip it |

### Bridge #3 — GCP-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline used — the distinguishing signal is cadence (build-triggered, not ad hoc) and `sourceIPAddress` falling in Cloud Build's/Compute Engine's ranges rather than a developer's known egress.

### Bridge #4 — Identity Center with Workspace as external IdP

| Signal | Field | Example value | Notes |
|--------|-------|-----------------|-------|
| The permission-set role assumption | `eventName = AssumeRole`, role ARN contains `AWSReservedSSO_<permission-set>_<hash>` | `arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@contoso.com` | The CloudTrail-visible moment; the Workspace login upstream is invisible here |
| `userIdentity.type` on subsequent actions | `AssumedRole` | `AssumedRole` | |
| The human, if you need to prove it | Not in CloudTrail — pivot to **IAM Identity Center's own sign-in history** or the upstream Workspace Login & Auth Audit | — | 🔴 CloudTrail alone **stops at the permission-set role** — pivot to Identity Center's console or Workspace's Login audit for the real authentication |
| `sourceIdentity` (if your org sets it) | Propagates through any further role chain | `alice@contoso.com` | The best field for tying a deep role chain back to the original Workspace identity |

Console path: **AWS IAM Identity Center console → Users → (user) → Account access**, or **CloudTrail Lake / Athena** for the `AssumeRole` events. Full field-level treatment: AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)**.

### Bridge #5 — BigQuery Omni

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `eventName` | Same federation call as bridge #1 | `AssumeRoleWithWebIdentity` | Distinguish from bridge #1 by the identity and the resource pattern, not the API |
| `responseElements.subjectFromWebIdentityToken` | A GCP-managed Omni-specific identity — **not** a customer SA's unique ID | (opaque, Google-controlled) | Don't expect this to match any SA you can enumerate in your own project — it belongs to Google's Omni compute plane |
| `requestParameters.roleArn` | The role Omni assumes | `arn:aws:iam::123456789012:role/bigquery-omni-role` | Should be assumed **only** by Omni traffic — any other caller assuming it is the trust being abused |
| Resulting S3 activity | `eventName = GetObject`, bucket | `s3://contoso-omni-data/*` at volume | Corroborate against the BigQuery job history on the GCP side — a burst that lines up with a scheduled query is expected; one that doesn't is the anomaly |

Console path: **IAM → Roles → bigquery-omni-role → Trust relationships**; **CloudTrail → Event history** filtered on `AssumeRoleWithWebIdentity` for that role ARN, cross-referenced with S3 server access logs or CloudTrail data events on the bucket.

### Bridge #6 — GKE attached clusters (Fleet) reaching EKS

No IAM identity evidence exists on the AWS side for the registration itself — the Connect Agent runs as a pod *inside* the EKS cluster, using a GCP-issued credential validated against Kubernetes RBAC, not against AWS IAM. Work it from the **EKS cluster's own Kubernetes control-plane audit log** (not CloudTrail) for the Connect Agent's service account and what it did inside the cluster. State this split explicitly: CloudTrail shows nothing for this bridge; the evidence is entirely inside the cluster.

## Correlation — Tying the GCP Identity to the AWS Session

| Anchor | GCP side | AWS side | Example match | Strength |
|--------|----------|----------|-----------------|----------|
| The SA's numeric unique ID | `gcloud iam service-accounts describe <sa> --format='value(uniqueId)'` (config lookup, not always a per-event field — see Path A/B above) | `responseElements.subjectFromWebIdentityToken` | `103547991597142817347` ↔ `103547991597142817347` | 🔴 High, but **not self-describing** — unlike an AWS role ARN, a bare number tells you nothing on its own; you must look it up |
| Timing | `eventTime` of the `GenerateIdToken` call (Path A only — Path B has no timestamp on the GCP side) | `eventTime` of `AssumeRoleWithWebIdentity` | `14:22:01Z` (GCP, Path A) ↔ `14:22:03Z` (AWS) | High when Path A applies and within seconds; N/A for Path B — state the gap rather than forcing a match |
| Source IP | `requestMetadata.callerIp` (Path A only) | `sourceIPAddress` | `35.190.x.x` ↔ `35.190.x.x` | High for Path A; not available for Path B |
| The role's trust condition | The SA's `aud`/`sub` values (config, not a per-event field) | Same, read via `aws iam get-role` | `accounts.google.com:sub: 103547991597142817347` bound in the role's `Condition` | High — confirms which SA is even eligible to federate, independent of any single event |
| The Workspace human (bridge #4) | `actor.email` in Login & Auth Audit | `AWSReservedSSO_*` session-name portion of the assumed-role ARN | `alice@contoso.com` ↔ `.../AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@contoso.com` | High — direct email match, if Identity Center is configured to populate the session name meaningfully |
| Secret identity (bridge #2) | Which secret was read, and by whom | `AKIA` key ID first-used | The AWS key ID in the burned Secret Manager secret matches the `accessKeyId` on the AWS side | High — ties a specific leaked key to specific AWS-side usage |

## Hunt at Scale

```bash
# gcloud: every GenerateIdToken call in the last 7 days, by SA — look for cadence,
# and for an audience pointing at an AWS role ARN specifically
gcloud logging read \
 'protoPayload.methodName="google.iam.credentials.v1.GenerateIdToken"' \
 --project=contoso-prod --freshness=7d --format='table(timestamp,protoPayload.authenticationInfo.principalEmail,protoPayload.resourceName,protoPayload.request.audience)'
```

```sql
-- CloudTrail Lake SQL: every AssumeRoleWithWebIdentity via Google's built-in provider, last 7 days
SELECT eventTime, requestParameters.roleArn AS role_assumed,
       responseElements.subjectFromWebIdentityToken AS gcp_sa_unique_id,
       responseElements.audience, sourceIPAddress
FROM cloudtrail_lake_event_table
WHERE eventName = 'AssumeRoleWithWebIdentity'
  AND responseElements.provider = 'accounts.google.com'
  AND eventTime > date_add('day', -7, now())
ORDER BY eventTime DESC
```

```sql
-- CloudTrail Lake SQL: roles trusting accounts.google.com with a condition scoped to a whole
-- project rather than one SA sub — audit these regardless of confirmed abuse
-- (read via `aws iam get-role` per role; not a single queryable CloudTrail field)
```

A modest cross-cloud SecOps/UDM landing point: normalize the AWS-side `AssumeRoleWithWebIdentity` (`target.resource.name` = `roleArn`, `principal.user.userid` = `subjectFromWebIdentityToken`) and, where Path A applies, the GCP-side `GenerateIdToken` mint (`principal.asset.ip` = `callerIp`) to a shared timeline, and alert on an AWS-side event carrying `provider: accounts.google.com` with **no matching GCP-side mint event** in the preceding few minutes — remembering that this is the *expected* shape for Path B (attached-workload minting), not automatically a finding. Keep it light; the deep read stays in the native queries above.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A role trust policy `Condition` on `accounts.google.com:sub` missing entirely, or scoped to a project rather than one SA | Any SA in that GCP project can federate in — audit immediately regardless of confirmed abuse |
| `AssumeRoleWithWebIdentity` with `provider: accounts.google.com` and a `subjectFromWebIdentityToken` you don't recognize | New/unexpected GCP SA acting in AWS |
| `GenerateIdToken` called by a principal other than the SA itself, with no legitimate TokenCreator reason | Impersonation being used to mint federated tokens |
| An `AssumeRoleWithWebIdentity` event with no discoverable GCP-side `GenerateIdToken` | Expected if the SA is attached to a resource (Path B) — **not** automatically suspicious; confirm attachment before treating it as a gap |
| `AKIA`/`ASIA` key first-used from a GCP IP/ASN with no known GCP-side integration | Bridge #2 surfacing — leaked key, assume it's burned |
| Workspace `suspicious_login` or `is_suspicious: true` feeding directly into an `AWSReservedSSO_*` role assumption | Bridge #4 — SSO account compromise |
| The `bigquery-omni-role` assumed by a `subjectFromWebIdentityToken` that doesn't match Omni's known pattern | The trust is being abused by something other than Omni itself |
| A GKE Fleet membership registering an EKS cluster nobody requested | A new remote-control path into that cluster, planted as persistence |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| The full bridge inventory across all six directional pairs | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| This pair from the other direction | **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** |
| The same starting cloud, a much less frictionless destination | **[GCP → Azure](GCP%20%E2%86%92%20Azure.md)** |
| GCP reached as a destination, for contrast | **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** |
| AWS identity types and access-key decoding | AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** |
| AWS STS mechanics and role-chaining | AWS **[STS for DFIR](../Amazon/AWS/Identity%20%26%20Access/STS/STS%20for%20DFIR.md)** |
| AWS Identity Center investigation in depth | AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)** |
| GCP Cloud Audit Logs deep dive | Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** |
| GCP service accounts, keys, impersonation | Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)** |
| GCP Workload Identity Federation (the inbound direction) | Google **[Workload Identity Federation for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Workload%20Identity%20Federation/Workload%20Identity%20Federation%20for%20DFIR.md)** |
| Workspace login/takeover investigation | Google **[Login & Auth Audit for DFIR](../Google/Google%20Workspace/Login%20%26%20Auth%20Audit/Login%20%26%20Auth%20Audit%20for%20DFIR.md)** |
| BigQuery exfil/Omni investigation | Google **[BigQuery for DFIR](../Google/Google%20Cloud/Databases/BigQuery/BigQuery%20for%20DFIR.md)** |
| GKE and the Fleet/attached-clusters bridge | Google **[GKE for DFIR](../Google/Google%20Cloud/Serverless%20%26%20Containers/GKE/GKE%20for%20DFIR.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- AWS: `AssumeRoleWithWebIdentity` API reference — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
- AWS Security Blog: Access AWS using a Google Cloud Platform native workload identity — https://aws.amazon.com/blogs/security/access-aws-using-a-google-cloud-platform-native-workload-identity/
- Google Cloud: Create short-lived credentials (identity tokens, `generateIdToken`) — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Google Cloud: BigQuery Omni overview — https://cloud.google.com/bigquery/docs/omni-introduction
- Google Cloud: GKE attached clusters / Fleet — https://cloud.google.com/kubernetes-engine/multi-cloud/docs/aws/how-to/attached-clusters-create
- Google Workspace: Set up Google as your IdP for AWS SSO — https://support.google.com/a/answer/6262987
- Google Cloud: IP address ranges (JSON feed) — https://www.gstatic.com/ipranges/cloud.json
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
