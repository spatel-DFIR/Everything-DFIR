# AWS → GCP

## Why This Happens

AWS and GCP are separate accounts with separate logins. By default, an AWS identity means **nothing** to GCP, and a GCP identity means nothing to AWS. Nobody walks from one into the other unless someone **deliberately built a bridge** — but unlike the AWS↔Azure pair, this direction has a bridge that was *purpose-built* by Google to require almost no setup at all. That changes the shape of this whole note.

An actor with a foothold in AWS crosses into GCP using one of these mechanisms:

- **GCP Workload Identity Federation's native AWS provider (the headline bridge)** — GCP has a provider type built specifically to trust AWS IAM role ARNs, directly, with no AWS-side configuration whatsoever. No IAM OIDC provider to create, no thumbprint, no certificate. The AWS-side caller signs an ordinary `sts:GetCallerIdentity` request with its own AWS credentials; GCP's Security Token Service verifies that signature and hands back a short-lived Google token mapped to the AWS role's ARN. This is about as close to frictionless as cross-cloud federation gets anywhere in this repo, and it means an attacker doesn't need to find a *misconfigured* trust to abuse — a *correctly configured, intentional* one is already doing exactly what GCP designed it to do. The only question is whether its attribute condition is scoped tightly enough.
- **A plain leaked GCP service-account key in an AWS secret store** — a GCP SA key (a JSON file, never expires until deleted) sitting in Secrets Manager, SSM Parameter Store, or a Lambda environment variable. No trust relationship, no federation, no login event — whoever reads it just uses it directly against GCP's APIs. The "boring" bridge, same shape as every other cloud pair in this repo, and still the one most likely to be sitting in your environment right now.
- **AWS-hosted CI/CD deploying into GCP** — a CodeBuild project or a self-hosted GitHub Actions/GitLab runner on EC2 uses either of the two mechanisms above to push changes into GCP. Not a distinct trust mechanism on its own — just a distinct *actor* riding one of the first two.
- **IAM Identity Center as an atypical external SAML IdP for GCP Workforce Identity Federation** — rare, and going the "wrong way" for AWS (AWS is almost always the *relying party* in cross-cloud federation, not the identity source), but real: Identity Center can be configured as the SAML identity source behind a GCP Workforce Identity Federation pool, letting AWS SSO users sign into the GCP console/`gcloud` with their AWS SSO identity.

**The bridge determines what evidence exists on both sides**, and the WIF bridge is the sharpest illustration of that rule in this repo: its AWS-side "mint" event is `sts:GetCallerIdentity` — an API call that takes **no input parameters** and typically logs no response either, so CloudTrail looks *identical* whether that call was a routine self-identification check or the exact signed request a workload used to authenticate into GCP a moment later. On this bridge, more than almost any other pairing this repo covers, the GCP side is where the real story lives.

This note works the investigation from the AWS side first, then the GCP side, then ties the two together with the fields that prove it was the same actor both times. It also flags, once, what this note *isn't* about: AWS Security Hub's cross-account aggregation (and Security Lake, absent a custom cross-cloud source) doesn't reach GCP — see **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)**, AWS table row 6, for why it's excluded rather than overlooked.

Read with **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes) and **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the general method). See also **[AWS → Azure](AWS%20%E2%86%92%20Azure.md)** for the contrast — the same starting cloud, a much less frictionless destination.

## Contents

- [The Bridges — AWS → GCP](#the-bridges--aws--gcp)
- [Source-Side Investigation — AWS Logs](#source-side-investigation--aws-logs)
- [Destination-Side Investigation — GCP Logs](#destination-side-investigation--gcp-logs)
- [Correlation — Tying the AWS Identity to the GCP Session](#correlation--tying-the-aws-identity-to-the-gcp-session)
- [Hunt at Scale](#hunt-at-scale)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Bridges — AWS → GCP

| # | Bridge | How it works | How common | Key trust artifact |
|---|--------|--------------|------------|---------------------|
| 1 | **GCP Workload Identity Federation — native AWS provider** | A pool provider is created with `gcloud iam workload-identity-pools providers create-aws`, mapping `google.subject=assertion.arn`. The AWS-side caller signs a normal `sts:GetCallerIdentity` request with its own AWS SigV4 credentials; GCP's STS verifies that signature (via `subject_token_type=urn:ietf:params:aws:token-type:aws4_request`) and exchanges it for a short-lived Google federated token — no AWS IAM OIDC provider, no thumbprint, no AWS-side config at all | 🔴 Growing fast — the modern default for AWS workloads reaching GCP | The pool provider's **attribute condition** — the only thing standing between "your AWS account" and "your one specific role" |
| 2 | **Stored/leaked GCP SA key in AWS** | A GCP service-account key (JSON, never expires) sits in Secrets Manager (`arn:aws:secretsmanager:us-east-1:123456789012:secret:gcp-etl-sa-key-Xy9Zab`), SSM Parameter Store (`/prod/gcp/etl-sa-key`, SecureString), or a Lambda/CodeBuild environment variable | 🔴 Very common — the "boring" bridge | The key file itself; no cloud-native trust relationship to find |
| 3 | **AWS-hosted CI/CD deploying into GCP** | A CodeBuild project (`codebuild-deploy-to-gcp`) or a self-hosted GitHub Actions/GitLab runner on EC2 uses bridge 1 (preferred, keyless) or bridge 2 (stored key, often legacy) to deploy | Common — WIF is increasingly the recommended pattern here, displacing stored keys | Whichever of bridge 1 or 2 the pipeline actually uses |
| 4 | **IAM Identity Center as an external SAML IdP for GCP Workforce Identity Federation** | Identity Center is configured as a custom external SAML application; a GCP Workforce Identity Federation pool trusts Identity Center's SAML assertions, letting AWS SSO users sign into the GCP console/`gcloud` | Rare / atypical direction — see **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)**, AWS table row 4 | The Workforce Identity Federation SAML provider config + the Identity Center external-app registration |
| 5 | **AWS Systems Manager hybrid activations reaching a GCP Compute Engine instance** | An SSM managed-instance activation lets the SSM Agent, installed on a GCE VM, register under an IAM role — AWS can then run commands on that GCP-hosted machine | Common where Systems Manager is the fleet-management standard | Compute reach only, no GCP identity — see **[00 - Cross-Cloud Bridges Overview → Infrastructure Bridges](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair)** |

## Source-Side Investigation — AWS Logs

All of this lives in **CloudTrail**. The `userIdentity` block is the anchor for every bridge here — see AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** for the full type table.

### Bridge #1 — GCP WIF native AWS provider

The mechanics, precisely, because getting this right changes what you go looking for: an AWS role or user's own credentials sign a `GetCallerIdentity` request. That signed request — headers, signature, and all — is passed to Google's STS token endpoint (`sts.googleapis.com/v1/token`) as the `subject_token`. Google's backend validates the AWS signature and extracts the caller's ARN from it. **The AWS side never calls a Google API to do this** — it only ever calls its own `sts.amazonaws.com`, and the call it makes is one it might make for entirely unrelated, benign reasons.

| Field | What it tells you | Example value | Read it as |
|-------|--------------------|----------------|------------|
| `eventName` | The call that (may) precede a WIF exchange | `GetCallerIdentity` | 🔴 Not diagnostic on its own — see the gap below |
| `eventSource` | Confirms it's an STS call | `sts.amazonaws.com` | |
| `userIdentity` | Who/what signed the request | `arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123` | This ARN is exactly what shows up on the GCP side as the federated subject — the single strongest correlation field this bridge has |
| `requestParameters` | The call's inputs | `null` / `{}` | 🔴 `GetCallerIdentity` takes **no parameters** — this field is empty on *every* call, WIF-related or not |
| `responseElements` | The call's outputs | typically not logged | Confirms nothing further; don't expect to find a "this went to GCP" marker here |
| `sourceIPAddress` / `userAgent` | Origin & tooling | `10.0.4.22` (private, if called from inside a VPC) / `aws-sdk-go-v2/1.30.0` | Google's own client libraries make this call automatically when configured for AWS-based WIF — a distinctive SDK `userAgent` making frequent, regular `GetCallerIdentity` calls is a stronger tell than any single call |

> 🔴 **The gap to state explicitly on this bridge, every time:** CloudTrail cannot distinguish a `GetCallerIdentity` call made for routine self-identification (a script confirming which role it's running as) from the exact same call crafted and signed for a GCP WIF token exchange. If you need to *prove* the AWS side initiated a WIF exchange, don't look for a special AWS-side event — there isn't one. Corroborate with **volume and cadence** (WIF exchanges tend to repeat on a schedule matching the workload's token-refresh interval, roughly hourly) and pivot to the GCP-side arrival evidence below, which is unambiguous.

```bash
# GetCallerIdentity calls by a specific role in the window — look for cadence, not a single event
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetCallerIdentity \
  --start-time 2026-07-01 --end-time 2026-07-16
```

Console path: **CloudTrail → Event history**, filtered on `GetCallerIdentity`, then cross-reference the calling role's other activity for context — this event alone won't tell the story.

### Bridge #2 — Stored/leaked GCP SA key

| Field | What it tells you | Example value | Read it as |
|-------|--------------------|----------------|------------|
| `eventName` | The retrieval action | `GetSecretValue` / `GetParameter` | 🔴 The pivot moment |
| `requestParameters.secretId` / `.name` | Which secret | `gcp-etl-sa-key` / `/prod/gcp/etl-sa-key` | Confirm it's the one holding the SA key JSON |
| `userIdentity` | Who read it | `arn:aws:iam::123456789012:user/data-eng-alice` | 🔴 A human/role that isn't the owning pipeline |
| `sourceIPAddress` / `userAgent` | From where / with what | `203.0.113.77` | New IP/geo relative to the pipeline's normal host |

```bash
aws secretsmanager list-secrets --query "SecretList[?contains(Name, 'gcp') || contains(Name, 'sa-key')]"
```

Console path: **Secrets Manager → Secrets** (inventory) or **CloudTrail → Event history** filtered on `GetSecretValue`. Full field detail: AWS **[Secrets Manager for DFIR](../Amazon/AWS/Data%20Protection/Secrets%20Manager/Secrets%20Manager%20for%20DFIR.md)**.

### Bridge #3 — AWS-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline uses — the distinguishing signal is the *actor*: a CodeBuild service role or a self-hosted runner's instance role calling `GetCallerIdentity` (bridge 1) or reading a stored key (bridge 2) on a build schedule rather than ad hoc. Pull the **CodeBuild build history** (`aws codebuild batch-get-builds`) or the runner's own job logs alongside the CloudTrail events above; an off-schedule build, or one triggered by an unexpected commit source, is the abuse signature.

### Bridge #4 — Identity Center as external SAML IdP

Investigate the AWS side exactly as you would any Identity Center external-app configuration: confirm the custom SAML application registered in Identity Center actually points at the GCP Workforce Identity Federation pool you expect, and pull Identity Center's own sign-in history for the users who authenticated through it. Full field-level treatment of Identity Center itself: AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)**. This bridge is atypical enough that it doesn't warrant its own deep destination-side breakdown below — see the GCP-side note in that section instead.

### Bridge #5 — SSM hybrid activation reaching a GCP Compute Engine instance

Compute reach, not a GCP identity. Investigate exactly like any other SSM `SendCommand`/`StartSession` case (AWS **[Systems Manager (SSM) for DFIR](../Amazon/AWS/Compute/Systems%20Manager%20(SSM)/Systems%20Manager%20(SSM)%20for%20DFIR.md)**); confirm the target instance is GCE-hosted via its tags/platform info. Full cross-cloud treatment lives in the overview note.

## Destination-Side Investigation — GCP Logs

All of this lives in **Cloud Audit Logs**. See Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** for the full field reference this section applies to each bridge.

### Bridge #1 — GCP WIF native AWS provider

This is where the bridge actually becomes visible. Two things happen after the token exchange, and you may see either or both depending on how the pool was configured:

**If the federated identity impersonates a GCP service account** (the common pattern — a `roles/iam.workloadIdentityUser` binding on the target SA):

| Field | What it tells you | Example value | Notes |
|-------|--------------------|----------------|-------|
| `protoPayload.methodName` | The impersonation call | `google.iam.credentials.v1.GenerateAccessToken` | The moment the federated identity becomes usable as the GCP SA |
| `protoPayload.authenticationInfo.principalSubject` | The federated AWS identity, exactly as GCP mapped it | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/aws-prod-pool/subject/arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123` | 🔴 The AWS role ARN (with session name) is embedded verbatim here — your strongest cross-cloud anchor, and it's a direct copy of the AWS-side `userIdentity.arn` |
| `protoPayload.resourceName` | The SA being impersonated | `projects/contoso-prod/serviceAccounts/gcp-deploy-sa@contoso-prod.iam.gserviceaccount.com` | What the AWS identity can now act as |
| `protoPayload.requestMetadata.callerIp` | Where the exchange call came from | `52.94.xx.xx` | Should fall in AWS's published IP ranges if this is a legitimate AWS-hosted workload |
| Subsequent calls by the impersonated SA | `authenticationInfo.principalEmail` + `authenticationInfo.serviceAccountDelegationInfo` | `principalEmail: gcp-deploy-sa@contoso-prod.iam.gserviceaccount.com`, delegation info naming the same `principalSubject` above | The full chain: AWS role → federated principal → impersonated SA → the actual action taken |

**If the federated identity is granted a direct IAM binding instead** (no SA impersonation — the newer, more direct WIF pattern):

| Field | What it tells you | Example value |
|-------|--------------------|-----------------|
| `protoPayload.methodName` | The bound resource's own API call | `storage.objects.get`, or `SetIamPolicy` if you're looking at the binding itself |
| `protoPayload.authenticationInfo.principalSubject` | Same shape as above — the federated identity acting directly | `principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/aws-prod-pool/subject/arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123` |
| The IAM binding itself | `request.policy.bindings[]` member, on the `SetIamPolicy` event that created it | `member: "principal://iam.googleapis.com/projects/987654321000/locations/global/workloadIdentityPools/aws-prod-pool/subject/arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123"`, `role: "roles/storage.objectViewer"` |

> 🔴 **This is the note's headline gap-filler, not the golden template's:** unlike a role trust *policy* on the AWS side (which you can `get-role` and read directly), the WIF exchange itself may not produce its own distinct audit-log line — the first artifact you'll actually find is whichever API call the federated identity (or the SA it impersonated) makes *next*. Don't go looking for a single "here's the federation event" line the way you would for `AssumeRoleWithSAML`; go looking for the first `principalSubject` containing `workloadIdentityPools`, in whichever log stream the resulting action landed in.

```bash
# Read the pool provider's attribute condition — the actual trust gate
gcloud iam workload-identity-pools providers describe aws-provider \
  --workload-identity-pool=aws-prod-pool --location=global --project=contoso-prod

# Federated impersonation events for this pool
gcloud logging read \
 'protoPayload.authenticationInfo.principalSubject:"workloadIdentityPools/aws-prod-pool"' \
 --project=contoso-prod --freshness=30d --format=json
```

```sql
-- BigQuery (audit sink): every federated AWS principal that acted, and what it did
SELECT timestamp,
       protopayload_auditlog.authenticationInfo.principalSubject AS aws_identity,
       protopayload_auditlog.methodName AS action,
       protopayload_auditlog.resourceName AS resource
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalSubject LIKE '%workloadIdentityPools%'
  AND protopayload_auditlog.authenticationInfo.principalSubject LIKE '%arn:aws%'
ORDER BY timestamp DESC;
```

Console path: **IAM & Admin → Workload Identity Federation** (pool/provider config, including the attribute condition); **Logging → Logs Explorer**, filtered on `principalSubject:"workloadIdentityPools"`, for the exchanges themselves.

### Bridge #2 — Stored/leaked GCP SA key

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalEmail` | The SA identity | `gcp-etl-sa@contoso-prod.iam.gserviceaccount.com` | Confirms which SA the leaked key belongs to |
| `protoPayload.authenticationInfo.serviceAccountKeyName` | 🔴 A user-managed key was used | `projects/contoso-prod/serviceAccounts/gcp-etl-sa@contoso-prod.iam.gserviceaccount.com/keys/a1b2c3d4e5f6...` | Present = key-based auth, not impersonation or WIF — this is the field that confirms bridge #2 specifically |
| `protoPayload.requestMetadata.callerIp` | Where the key was used from | `52.94.xx.xx` | 🔴 Cross-reference against AWS's published [IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) — a key that's only ever been used from your GCP-side pipeline suddenly calling from an AWS IP/ASN is the tell |
| `protoPayload.requestMetadata.callerSuppliedUserAgent` | Tooling fingerprint | `google-api-python-client/2.100.0 (gzip)` | An SDK/runtime signature consistent with AWS Lambda/CodeBuild/EC2 rather than the SA's expected environment |

```bash
gcloud logging read \
 'protoPayload.authenticationInfo.serviceAccountKeyName:"gcp-etl-sa"' \
 --project=contoso-prod --freshness=30d --format=json
```

Console path: **Logging → Logs Explorer**, filtered on `serviceAccountKeyName`; **IAM & Admin → Service Accounts → (SA) → Keys** to inventory every key that exists and when it was created. Full field detail: Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)**.

### Bridge #3 — AWS-hosted CI/CD

Same evidence shape as whichever of bridge 1 or 2 the pipeline used — the distinguishing signal is cadence (build-triggered, not ad hoc) and the `callerIp` falling in AWS's CodeBuild/EC2 ranges rather than a developer's known egress.

### Bridge #4 — Identity Center as external SAML IdP for Workforce Identity Federation

| Field | What it tells you | Example value | Notes |
|-------|--------------------|-----------------|-------|
| `protoPayload.authenticationInfo.principalSubject` | The federated Workforce Identity principal | `principal://iam.googleapis.com/locations/global/workforcePools/aws-sso-pool/subject/alice@corp.com` | Note the path — `workforcePools`, not `workloadIdentityPools`; this is the human-SSO variant of the same underlying STS mechanism |
| `protoPayload.requestMetadata.callerIp` | Where the human's console/CLI session originated | `203.0.113.45` | Compare against Identity Center's own sign-in IP for the same user |

Console path: **IAM & Admin → Workforce Identity Federation**, for the pool/provider config trusting Identity Center's SAML metadata. This bridge is rare enough that the field shape above is the extent of dedicated coverage here — cross-reference AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)** for the AWS-side half.

### Bridge #5 — SSM hybrid reaching a GCP Compute Engine instance

No GCP identity evidence exists for this bridge — it's guest-OS command execution, invisible to Cloud Audit Logs. Work it from the VM's own guest-level artifacts exactly as you would any host-level compromise.

## Correlation — Tying the AWS Identity to the GCP Session

| Anchor | AWS side | GCP side | Example match | Strength |
|--------|----------|----------|-----------------|----------|
| The AWS role ARN | `userIdentity.arn` on the `GetCallerIdentity` call (or on whatever call held the credentials used) | `principalSubject`'s embedded ARN | `arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123` ↔ the same string inside `principal://.../subject/arn:aws:sts::123456789012:assumed-role/gcp-federation-deploy-role/i-0abc123` | 🔴 High — an exact, verbatim string match, the strongest anchor in this entire note |
| Timing | `eventTime` of the `GetCallerIdentity` call | `timestamp` of the first `principalSubject`-bearing GCP event | `14:22:01Z` (AWS) ↔ `14:22:03Z` (GCP) | High when within seconds — the exchange happens immediately after signing |
| Source IP | `sourceIPAddress` on the AWS-side call | `requestMetadata.callerIp` on the GCP-side event | `52.94.xx.xx` ↔ `52.94.xx.xx` | High — the same process typically makes both calls in sequence, unlike SSO where a browser and a backend token exchange can differ |
| The pool/provider's attribute condition | The AWS account ID / role ARN it's scoped to (config, not a per-event field) | Same, read via `gcloud iam workload-identity-pools providers describe` | `aws.accountId: 123456789012` bound in the provider's attribute condition | High — confirms which AWS account is *even eligible* to federate, independent of any single event |
| SA key identity (bridge 2) | Not visible on the AWS side beyond the secret read | `serviceAccountKeyName` on the GCP side, cross-referenced to where the key was stored in AWS | The key ID in `serviceAccountKeyName` matches the JSON key that was in the burned secret | High — ties a specific leaked key to specific GCP-side usage |

## Hunt at Scale

```sql
-- CloudTrail Lake SQL: GetCallerIdentity cadence by role, last 7 days — look for the
-- hourly-ish repeating pattern typical of WIF token refresh, not a single anomalous call
SELECT userIdentity.arn AS who, COUNT(*) AS calls,
       MIN(eventTime) AS first_seen, MAX(eventTime) AS last_seen
FROM cloudtrail_lake_event_table
WHERE eventName = 'GetCallerIdentity'
  AND eventTime > date_add('day', -7, now())
GROUP BY userIdentity.arn
ORDER BY calls DESC
```

```sql
-- BigQuery (GCP audit sink): every federated AWS principal seen in the last 7 days,
-- and whether its condition is scoped to a role or an entire account
SELECT DISTINCT
  REGEXP_EXTRACT(protopayload_auditlog.authenticationInfo.principalSubject,
                 r'subject/(arn:aws:sts::\d+:assumed-role/[^/]+)') AS aws_role,
  COUNT(*) AS actions
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalSubject LIKE '%workloadIdentityPools%'
  AND DATE(timestamp) >= DATE_SUB(CURRENT_DATE(), INTERVAL 7 DAY)
GROUP BY aws_role
ORDER BY actions DESC;
```

**Log Explorer, for a fast first look:**

```
protoPayload.authenticationInfo.principalSubject:"workloadIdentityPools"
protoPayload.authenticationInfo.principalSubject:"arn:aws"
```

A modest cross-cloud SecOps/UDM landing point: normalize the AWS-side `GetCallerIdentity` caller (`principal.user.userid` = `userIdentity.arn`) and the GCP-side federated action (`target.resource.name` = `resourceName`, `principal.asset.ip` = `callerIp`) to a shared timeline, and alert on a `principalSubject` containing `workloadIdentityPools` with no prior `GetCallerIdentity` from the matching ARN in the preceding few minutes in the AWS UDM stream — the WIF-specific version of the "arriving from nowhere" pattern used elsewhere in this repo. Keep it light; the deep read stays in the native queries above.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| A WIF pool provider's attribute condition trusting a whole AWS account rather than a specific role ARN | Any principal in that AWS account can federate in — audit immediately regardless of confirmed abuse |
| A `principalSubject` containing `workloadIdentityPools` with an AWS role you don't recognize | New/unexpected federated identity acting in GCP |
| `GetCallerIdentity` calls from a principal/role with no legitimate reason to check its own identity, especially on a regular cadence | Likely the AWS-side half of a WIF exchange — corroborate on the GCP side, since AWS alone won't confirm it |
| A GCP SA key (`serviceAccountKeyName`) used from an AWS IP/ASN with no known AWS-side integration | Bridge #2 surfacing — leaked key, assume it's burned |
| `GenerateAccessToken` impersonating a privileged SA, called by a federated AWS principal outside its normal schedule | Lateral movement via the impersonation hop |
| A direct IAM binding (`SetIamPolicy`) granting a role straight to a `principal://.../workloadIdentityPools/...` member | Newer direct-access WIF pattern — confirm the bound role is least-privilege, not broad |
| A Workforce Identity Federation `principalSubject` (`workforcePools`, not `workloadIdentityPools`) you weren't expecting | Bridge #4 — an AWS SSO identity signing into the GCP console/CLI |

## Correlate With

| To go deeper on… | Open |
|-------------------|------|
| The identity shapes involved | **[Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| The general correlation method | **[Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |
| The full bridge inventory across all six directional pairs | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** |
| AWS identity types and access-key decoding | AWS **[01 - IAM & Identities](../Amazon/AWS/01%20-%20IAM%20%26%20Identities.md)** |
| AWS secret-store investigation in depth | AWS **[Secrets Manager for DFIR](../Amazon/AWS/Data%20Protection/Secrets%20Manager/Secrets%20Manager%20for%20DFIR.md)** |
| AWS Identity Center investigation in depth | AWS **[IAM Identity Center for DFIR](../Amazon/AWS/Identity%20%26%20Access/IAM%20Identity%20Center%20(SSO)/IAM%20Identity%20Center%20for%20DFIR.md)** |
| GCP Workload Identity Federation in depth | Google **[Workload Identity Federation for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Workload%20Identity%20Federation/Workload%20Identity%20Federation%20for%20DFIR.md)** |
| GCP Cloud Audit Logs deep dive | Google **[Cloud Audit Logs for DFIR](../Google/Google%20Cloud/Logging%20%26%20Monitoring/Cloud%20Audit%20Logs/Cloud%20Audit%20Logs%20for%20DFIR.md)** |
| GCP service-account keys, impersonation, delegation chains | Google **[Service Accounts for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Service%20Accounts/Service%20Accounts%20for%20DFIR.md)** |
| GCP IAM bindings and privilege escalation | Google **[Cloud IAM for DFIR](../Google/Google%20Cloud/Identity%20%26%20Access/Cloud%20IAM/Cloud%20IAM%20for%20DFIR.md)** |
| This pair from the other direction | **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** |
| The much less frictionless AWS-outbound pairing | **[AWS → Azure](AWS%20%E2%86%92%20Azure.md)** |
| A full multi-cloud scenario walkthrough | **[Multi-Cloud Intrusion Playbook](Multi-Cloud%20Intrusion%20Playbook.md)** |

## Resources

- Google Cloud: Workload Identity Federation with AWS or Azure VMs — https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds
- Google Cloud: Workload Identity Federation overview — https://cloud.google.com/iam/docs/workload-identity-federation
- Google Cloud: `gcloud iam workload-identity-pools providers create-aws` reference — https://cloud.google.com/sdk/gcloud/reference/iam/workload-identity-pools/providers/create-aws
- Google Cloud: Workforce Identity Federation overview — https://cloud.google.com/iam/docs/workforce-identity-federation
- AWS: `GetCallerIdentity` API reference (note the empty request/response shape) — https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- AWS: IP address ranges (JSON feed) — https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
- MITRE ATT&CK: Trusted Relationship (T1199), Valid Accounts – Cloud Accounts (T1078.004), Use Alternate Authentication Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
