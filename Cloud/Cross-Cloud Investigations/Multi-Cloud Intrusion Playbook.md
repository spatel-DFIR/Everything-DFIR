# Playbook — Multi-Cloud Intrusion

The tier-3 scenario: **one actor, multiple clouds.** By default no cloud knows another exists — an identity that works in AWS means nothing in Azure or GCP. So whenever an investigation in one cloud turns out to involve a second (or third), the actor rode a **bridge**: a federated login, a secret holding a foreign credential, a hybrid-management agent, a private network circuit. This playbook is how you run that case as a *single* investigation instead of several disconnected ones — regardless of which clouds are involved or which bridge they used.

It's built as a **framework**, not a script for one scenario: [The Bridge Framework](#the-bridge-framework--building-any-chain) below shows how to identify your actual chain from the full bridge catalog, and every step in [Step-by-Step Investigation](#step-by-step-investigation) is written to swap in whichever directional note matches your case. Threaded through both is one fully-worked, field-level example — **Entra → AWS → GCP** — so the abstract steps always have a concrete illustration next to them.

> **Tier 3 (multi-cloud).** Sits above the provider playbooks. Read with **[03 Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** (the method), **[01 Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** (the identity shapes), and **[02 Evidence Acquisition](../02%20-%20Evidence%20Acquisition%20in%20the%20Cloud.md)** (collecting from each). For the map of every bridge and the field-level depth on any one pair, see **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** and the rest of **[Cross-Cloud Investigations/](README.md)**.

## Contents

- [The Bridge Framework — Building Any Chain](#the-bridge-framework--building-any-chain)
- [Attack Chain — Worked Example: Entra → AWS → GCP](#attack-chain--worked-example-entra--aws--gcp)
- [Trigger / How You Find Out](#trigger--how-you-find-out)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [Hunt at Scale](#hunt-at-scale)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## The Bridge Framework — Building Any Chain

Every multi-cloud case has the same shape, no matter which clouds or bridges are actually involved:

```
entry cloud + identity  →  bridge  →  next cloud  →  (bridge → next cloud, repeat)
```

Work it as a lookup, not a memorized scenario:

| Step | Ask | Where to look it up |
|------|-----|----------------------|
| 1. Where did the actor land? | Which cloud fired the first alert, and who/what is the identity? | Your entry cloud's own playbooks + **[01 - Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)** |
| 2. What could that identity reach? | Which bridge mechanisms exist *from* this cloud — federation, a readable secret, CI/CD, an infrastructure connector? | **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** — organized by source cloud, every mechanism numbered |
| 3. Did they use one? | For each candidate bridge, what does "used" look like on the source side? | The matching directional note's **Source-Side Investigation** section |
| 4. Where did it land them? | What does "arrived" look like on the destination side, and what did they do next? | The same note's **Destination-Side Investigation** section — then repeat from step 2 in the new cloud |
| 5. Prove it's one actor. | What fields survive the hop and tie both sides together? | The note's **Correlation** section, or the general method in **[03 - Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)** |

> Bridge numbers aren't universal — **00** numbers each source cloud's mechanisms across *all* its destinations, while each directional note numbers only the bridges relevant to *its one pair*. The same mechanism can carry two different numbers depending which document you're reading. Cite whichever note you're currently in; don't assume the numbers line up across documents.

**Six directional notes cover every ordered pair** among AWS, Azure, and GCP — `Azure → AWS`, `Azure → GCP`, `AWS → Azure`, `AWS → GCP`, `GCP → AWS`, `GCP → Azure` — plus [00's infrastructure-bridges section](00%20-%20Cross-Cloud%20Bridges%20Overview.md#infrastructure-bridges-that-cut-across-every-pair) for network interconnects, hybrid-management agents, backup/DR, and ETL tooling that don't require an identity event at all. A chain through three clouds is just two of these legs run back-to-back; four clouds is three legs. There's no separate method for longer chains — repeat steps 2–5 at each new cloud until the trail stops growing.

**Not every leg is equally likely.** Before you go hunting for a custom trust object, check whether the pair is one of the two **frictionless** ones — both vendors pre-wired the trust themselves, so a bridge can exist with zero setup on either side:

| Pair | Shortcut? | What that means for you |
|------|-----------|---------------------------|
| **GCP → AWS** | 🔴 Frictionless | AWS ships `accounts.google.com` as a built-in federated provider — no IAM OIDC provider resource was ever created. Don't rule this leg out just because you find no custom trust object. |
| **AWS → GCP** | 🔴 Frictionless | GCP Workload Identity Federation has a native AWS provider type — trusts AWS role ARNs directly. Same caveat: no AWS-side config to find. |
| Every other pair | Deliberate | Azure↔AWS, Azure↔GCP, and GCP→Azure all require a customer-built OIDC/SAML trust object, a stored credential, or an infrastructure connector — something to actually find and attribute. |

(Full table with the *why* per pair: **[Cross-Cloud Investigations/README.md](README.md#frictionless-vs-deliberate--a-quick-cheat-sheet)**.)

## Attack Chain — Worked Example: Entra → AWS → GCP

One instance of the framework above, worked concretely from a real-shaped case: a phished Microsoft 365 user becomes an Entra token, federates into AWS over a **deliberate** bridge (Identity Center SSO), reads a secret holding a Google service-account key — the "boring," near-universal bridge — and ends up exfiltrating from BigQuery. Chosen as the worked example because it chains one bridge of each flavor (deliberate SSO, then a stored-credential bridge that's frictionless in the sense that *no trust object exists to find at all*) into one story.

```
1. Entry (Microsoft)   phish + AiTM MFA-bypass → M365 user token (alice@corp.com)
                       → mailbox rule + illicit OAuth consent (persistence, no password)

2. Bridge → AWS         Federated SSO (Entra as external IdP) — Azure → AWS bridge #1
                        Entra vouches over SAML to IAM Identity Center
                       → AssumeRole into AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6
                         (same human upstream, same source IP)

3. Loot (AWS)           recon (List*/Describe*/Get*, mostly AccessDenied)
                       → Secrets Manager GetSecretValue on
                         arn:aws:secretsmanager:us-east-1:123456789012:secret:gcp-etl-sa-key-Xy9Zab
                       → creates an extra IAM access key (AWS-side persistence)

4. Bridge → GCP         Stored/leaked GCP credential in AWS — AWS → GCP bridge #2
                        the SA key from the burned secret is used directly — no federation,
                        no login event, just the JSON key presented to GCP's APIs

5. Impact (GCP)          gcp-etl-sa@contoso-prod.iam.gserviceaccount.com used from the same
                          ASN as steps 1–3 → storage.objects.list, then a large BigQuery extract
                        → serviceAccountKeys.create (GCP-side persistence)
                        → a log sink disabled (evasion)
```

### Step 1 — Entry (Microsoft): The Phish + OAuth + Federation Entry Point

**The attack:**

1. **AiTM phishing to steal an Entra token** — The attacker sends a phishing link that routes alice through a **reverse proxy sitting between her and the real M365 login page**. She sees what looks like the genuine sign-in flow, enters her password, and completes MFA — but every request actually transits the proxy, which relays it to Microsoft's real endpoint and captures the resulting session artifacts (the token/session cookie) as they come back. Because the proxy relays a *real* authentication, MFA is genuinely satisfied — there's nothing to "bypass" in the sense of tricking Microsoft; the attacker simply captures what a legitimate session produces and reuses it from their own infrastructure. Result: a valid **Entra refresh token** for alice@corp.com, MFA claim already attached, usable from anywhere.

   **What this produces in the logs — two sign-ins that don't match:**

   *The phish itself, at the proxy* (`SigninLogs`, interactive): looks almost indistinguishable from a normal sign-in, because it *is* one — alice really authenticated, MFA really ran. The only anomaly available at this stage is the destination: if you have the phishing domain (from the delivering email), the `SigninLogs` entry's redirect/referrer chain or the user's own report is what flags it, not the auth fields themselves.

   *The replay — the actual tell* (`AADNonInteractiveUserSignInLogs`): when the attacker later uses the captured token from their own device/script, it generates a **non-interactive** sign-in with **no interactive parent** — because the attacker never went through an interactive login themselves; they inherited a token that already carries a satisfied-MFA claim.

   | Field | Victim's real sign-in (`SigninLogs`) | Attacker's replay (`AADNonInteractiveUserSignInLogs`) |
   |-------|----------------------------------------|----------------------------------------------------------|
   | `IPAddress` | Alice's real IP (or the proxy's, if she's mid-phish) | 🔴 Different — the attacker's own infrastructure, e.g. `185.220.101.47` |
   | `AuthenticationDetails` / MFA | MFA freshly performed | `"authenticationStepResultDetail": "MFA requirement satisfied by claim in the token"` — 🔴 satisfied by a *prior* token, not performed here |
   | Interactive parent | Is itself interactive | 🔴 **None within the token's lifetime from this IP** — the single strongest replay signal |
   | Identity Protection | Usually clean at the time | `anomalousToken` — Microsoft's backend often flags this **retroactively**, once telemetry correlates the reuse |

   Pull the pivot directly:
   ```kql
   AADNonInteractiveUserSignInLogs
   | where UserPrincipalName == "alice@corp.com" and TimeGenerated > ago(14d)
   | project TimeGenerated, IPAddress, AppDisplayName, ResourceDisplayName
   ```
   (→ full replay-proof methodology, `CorrelationId` handling, and containment: **Microsoft Token Theft & AiTM**.)

2. **Illicit OAuth consent to establish no-password persistence** — Rather than risk the stolen token expiring or being noticed, the attacker uses the token to navigate to the OAuth consent flow for a malicious multi-tenant app (often hosted by the attacker or a phishing-as-a-service provider). The flow typically looks like:
   - The app requests `Mail.Read`, `Files.ReadWrite.All`, or `Directory.Read.All` (or all three).
   - The user (alice) sees a consent prompt claiming the app needs these scopes — the prompt mimics Microsoft's UI.
   - Alice's token is used to grant the app **delegated permissions** — the app gets a **service principal** in the tenant with the right to access alice's mail and files *on her behalf*.
   - Importantly, the app never learns alice's password. It only gets tokens (via OAuth refresh grants) as long as the consent grant exists.

   **What this produces in the logs — two events, in that order:**

   *First, a sign-in event for the consent redirect itself* (Entra **sign-in logs** / `signInLogs`): the OAuth authorize request (`/oauth2/v2.0/authorize?...&scope=Mail.Read+Files.ReadWrite.All+offline_access...`) shows up as an interactive sign-in with `appDisplayName` set to the **malicious app's registered name** — often a lookalike ("Office365 Enhanced Security", "SharePoint Online Connector") — and `resourceDisplayName = "Microsoft Graph"`. This is the earliest tell: alice authenticating *to an app she's never used before*, moments after the AiTM sign-in.

   *Then the grant itself lands as a directory audit event* (`directoryAudits` / Entra **audit logs**), `activityDisplayName = "Consent to application"`:

   ```json
   {
     "activityDisplayName": "Consent to application",
     "category": "ApplicationManagement",
     "activityDateTime": "2026-07-16T14:22:03Z",
     "result": "success",
     "initiatedBy": {
       "user": {
         "userPrincipalName": "alice@corp.com",
         "ipAddress": "185.220.101.47"
       }
     },
     "targetResources": [
       {
         "type": "ServicePrincipal",
         "displayName": "Office365 Enhanced Security",
         "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
         "modifiedProperties": [
           {
             "displayName": "ConsentAction.Permissions",
             "oldValue": "[]",
             "newValue": "[\"Mail.Read\",\"Files.ReadWrite.All\",\"offline_access\"]"
           }
         ]
       }
     ]
   }
   ```

   | Field | Read it as |
   |-------|------------|
   | `initiatedBy.user.userPrincipalName` | The victim who clicked "Accept" — `alice@corp.com` |
   | `initiatedBy.user.ipAddress` | 🔴 Often the **attacker's** infra, not alice's — the AiTM proxy can complete the redirect from wherever it sits, not from alice's real device |
   | `targetResources[].displayName` | The app name shown to alice — check against your tenant's known-app inventory |
   | `targetResources[].modifiedProperties[].newValue` (key = `ConsentAction.Permissions`) | 🔴 The exact scopes granted, old→new — this is what defines blast radius |
   | `result` | `success` confirms the grant went through (a `failure` here means consent was blocked, not attempted) |

   Pull it directly:
   ```powershell
   Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Consent to application'" -Top 50
   ```
   (→ general schema for every field above: **Entra Audit Logs for DFIR**; full response/eradication workflow once you've found this event: **Illicit Consent Grant**.)

   Why this persistence mechanism? The attacker can now:
   - Exfiltrate alice's mail and files directly via the app's Graph API calls (visible in `AADServicePrincipalSignInLogs` and UAL).
   - Delete or rotate the app grant at will without needing alice's password (the phished token will eventually expire; the grant persists).
   - Operate the app from attacker infrastructure, not from alice's device (detection evasion).
   
   The attacker can also request **admin consent** during this flow (if alice is a Global Admin or if the tenant has overly permissive admin-consent policies), granting the app **application permissions** across *all* tenants — but delegated permissions are sufficient for this case.

3. **Why this enables cross-cloud federation** — alice's compromised Entra identity is now persistent (via the OAuth consent grant) and has:
   - Full interactive tokens (refresh tokens good for months without re-auth).
   - Access to alice's own mailbox and files (tactical goal achieved).
   - But more importantly, alice's Entra identity is *enrolled in the tenant's federated SSO setup* (Azure Identity Center / Entra app).
   
   The attacker can now use alice's compromised Entra token to **authenticate to AWS via the federated SAML bridge**. Entra ID (as an external IdP) can issue SAML assertions for alice, attesting to her identity and group membership. AWS's Identity Center reads this SAML assertion and issues an `AssumeRoleWithSAML` call, minting an STS temporary credential set (`ASIA*` key and secret). These STS credentials are short-lived (1–12 hours, configurable) but grant full access to the AWS role that alice's Entra group is mapped to (often AdministratorAccess if alice is a sysadmin).
   
   **The bridge mechanism:** Entra → AWS federation relies on SAML metadata exchange and trust configuration that was set up when the tenant enrolled Identity Center. No new trust object is created; the attacker simply re-uses the pre-wired path using alice's compromised Entra token. The cross-cloud link is **alice's persistent Entra identity + the pre-configured trust relationship** — not a new credential type or secret stored in Entra.

### Mailbox Rules and Inbox Forwarding — Secondary Persistence

While the OAuth grant persists alice's data access, the attacker may also install **mailbox rules** (via OWA or Graph API) to:
- Forward all incoming mail to an attacker-controlled mailbox.
- Delete or move sensitive mail to a hidden folder.
- Suppress notifications of external forwarding.

This is visible in **Unified Audit Log** (UAL) as `New-InboxRule` or `Set-Mailbox` events and requires **Write** access to alice's mailbox — which the phished token provides. Rules survive the phished token's expiration (they're stored server-side in Exchange) and continue operating until discovered.

### Step 2 — Bridge → AWS: Federated SSO Turns the Entra Identity into an AWS Session

With alice's Entra identity persistently held (via the OAuth grant, and while her phished tokens remain valid), the attacker rides the tenant's **pre-existing** IAM Identity Center SSO trust (Azure → AWS bridge #1 — no new trust object to create; just the one the organization already built for legitimate SSO). Using alice's session, the attacker requests the AWS access portal / the AWS SSO tile in Entra's My Apps. Because the session already satisfies Conditional Access and MFA, **no fresh challenge fires** — the same mechanism that made the OAuth consent possible is reused here for a different resource.

**Mechanically:** Entra issues a **SAML assertion** for alice (her `NameID`, typically her email, plus any group/role claims mapped for AWS). AWS IAM Identity Center consumes the assertion, resolves it to a **permission set** assigned to alice (or her group), and performs the underlying role assumption into a reserved SSO role — minting an STS session.

**What this produces — one event on each side:**

*Entra side* (`SigninLogs`, interactive):

| Field | Example value | Read it as |
|-------|-----------------|------------|
| `AppDisplayName` | `"AWS IAM Identity Center"` | Confirms the sign-in targeted the AWS SSO app |
| `ResourceDisplayName` | `"Amazon Web Services"` | The token's intended audience |
| `IPAddress` | `185.220.101.47` | Compare against AWS's `sourceIPAddress` below — should match or land within seconds |
| `ConditionalAccessStatus` | `notApplied` on a token-derived session | 🔴 CA satisfied by an inherited claim, not freshly evaluated |
| `CorrelationId` | `4b1f6e2a-9c3d-4a7e-8f21-6d5c9a0b1e33` | Pulls every row in this one sign-in flow |

*AWS side* (CloudTrail, visible in the target account as `AssumeRole`):

```json
{
  "eventName": "AssumeRole",
  "eventTime": "2026-07-16T14:24:11Z",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@corp.com"
  },
  "sourceIPAddress": "185.220.101.47",
  "requestParameters": {
    "roleArn": "arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6"
  },
  "responseElements": {
    "credentials": { "accessKeyId": "ASIAJEXAMPLE...", "sessionToken": "..." }
  }
}
```

| Field | Read it as |
|-------|------------|
| `userIdentity.arn` (session name) | Identity Center usually stamps the SSO username/email here — `.../alice@corp.com` already names the human, *if* your config sets this meaningfully |
| `sourceIPAddress` | 🔴 Match against Entra's `IPAddress` — a mismatch means the token was relayed from different infrastructure, not used live |
| `responseElements.credentials.accessKeyId` | The `ASIA*` session key — the pivot for every action this session takes next |

> 🔴 **The gotcha to know cold:** CloudTrail alone stops at the permission-set role. An attacker with SSO-admin rights *can* forge `roleSessionName`. Don't take the ARN's session name at face value — pivot to **IAM Identity Center's own sign-in history** or back to Entra by `CorrelationId`/timestamp to corroborate the human (→ AWS **IAM Identity Center for DFIR**).

Pull it directly:
```bash
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time 2026-07-16T14:00:00Z --end-time 2026-07-16T15:00:00Z
```
(→ full bridge mechanics: **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)**, Bridge #1; role-back-to-human procedure: AWS **IAM Identity Center for DFIR**.)

### Step 3 — Loot (AWS): Recon, the Secrets Manager Read, and a Backdoor Access Key

Operating as `AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6`, the attacker's first moves are reconnaissance, and a lot of it fails.

**Recon (`List*`/`Describe*`/`Get*`, mostly `AccessDenied`):** calls into services outside the account's normal footprint, other regions, or gated by SCPs will bounce — expected and diagnostic.

| Field | Read it as |
|-------|------------|
| `eventName` | `ListBuckets`, `DescribeInstances`, `ListSecrets`, `GetCallerIdentity` — broad, untargeted enumeration |
| `errorCode` | 🔴 A **burst of `AccessDenied`** interspersed with successes is the recon signature — a legitimate admin's calls are targeted, not exploratory |
| `userIdentity.arn` | The same SSO session from step 2 on every call in this phase |

**The pivot — Secrets Manager `GetSecretValue`:**

```json
{
  "eventName": "GetSecretValue",
  "eventTime": "2026-07-16T14:31:47Z",
  "userIdentity": {
    "type": "AssumedRole",
    "arn": "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_a1b2c3d4e5f6/alice@corp.com"
  },
  "sourceIPAddress": "185.220.101.47",
  "requestParameters": {
    "secretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:gcp-etl-sa-key-Xy9Zab"
  }
}
```

| Field | Read it as |
|-------|------------|
| `requestParameters.secretId` | 🔴 A secret *named* for a foreign cloud is the multi-cloud tell (→ **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)**) |
| `userIdentity.arn` | Confirms the same SSO session read it — no separate compromise needed |
| Preceding events | A `ListSecrets`/`DescribeSecret` immediately before this read is the harvest signature, not routine app behavior (→ AWS **Secrets Manager for DFIR**) |

**AWS-side persistence — a backdoor access key.** The SSO session expires in 1–12 hours and requires re-authenticating through Entra every time, so the attacker mints a credential that survives independent of the federation path entirely:

```
CreateUser (e.g. "svc-monitoring-backup")  →  CreateAccessKey  →  AttachUserPolicy (AdministratorAccess)
```

| Pattern | Signature | Notes |
|---------|-----------|-------|
| New backdoor user | `CreateUser` → `CreateAccessKey` → `AttachUserPolicy`, tight together in time | The classic pattern |
| Extra key on a real user | `CreateAccessKey` on an existing user that already had one | 🔴 **A second active key** on an account that only ever used one — the tell when no new user was created |

(→ full backdoor-identity hunt patterns: AWS **IAM for DFIR**, *Finding Persistence — Backdoor Identities*.)

### Step 4 — Bridge → GCP: The Stored Credential, Used Directly

The secret from step 3 isn't a pointer — it's the **raw GCP service-account key file** (JSON: `type`, `project_id`, `private_key_id`, `private_key`, `client_email`). The attacker downloads it once and from then on authenticates to any Google API **directly**: no federation step, no trust object, and — critically — **no login event on the GCP side that names AWS at all**. This is the "boring" bridge: the evidence is a credential being *used*, not an arrival.

```bash
export GOOGLE_APPLICATION_CREDENTIALS=gcp-etl-sa-key.json
gcloud auth activate-service-account --key-file=gcp-etl-sa-key.json
```

**What this produces — every subsequent GCP call, not one "arrival" event:**

```json
{
  "protoPayload": {
    "authenticationInfo": {
      "principalEmail": "gcp-etl-sa@contoso-prod.iam.gserviceaccount.com",
      "serviceAccountKeyName": "projects/contoso-prod/serviceAccounts/gcp-etl-sa@contoso-prod.iam.gserviceaccount.com/keys/a1b2c3d4e5f6..."
    },
    "requestMetadata": {
      "callerIp": "185.220.101.47",
      "callerSuppliedUserAgent": "google-api-python-client/2.100.0 (gzip)"
    },
    "methodName": "storage.objects.list"
  }
}
```

| Field | Read it as |
|-------|------------|
| `serviceAccountKeyName` | 🔴 **Present** = key-based auth — this is what confirms the stored-key bridge specifically, not a keyless one |
| `principalEmail` | Confirms which SA the burned key belongs to — matches the secret name from step 3 |
| `callerIp` | 🔴 Cross-reference against [AWS's published IP ranges](https://ip-ranges.amazonaws.com/ip-ranges.json) — and note it's the **same IP** as steps 1–3, tying the whole chain to one actor |
| `callerSuppliedUserAgent` | An SDK fingerprint inconsistent with the SA's normal execution environment |

Pull it directly:
```bash
gcloud logging read \
 'protoPayload.authenticationInfo.serviceAccountKeyName:"gcp-etl-sa"' \
 --project=contoso-prod --freshness=30d --format=json
```
(→ full field reference and the alternate keyless bridge: **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)**, Bridge #2; SA key inventory: Google **Service Accounts for DFIR**.)

### Step 5 — Impact (GCP): Recon, the BigQuery Extract, and Covering Tracks

Operating as `gcp-etl-sa@contoso-prod.iam.gserviceaccount.com` from the same ASN as every prior step, the attacker moves fast — the goal is now directly reachable.

**Recon:** `storage.objects.list` across every bucket the SA can reach — cheap, low-noise, tells the attacker what's worth pulling.

**The extract:**

```json
{
  "protoPayload": {
    "authenticationInfo": { "principalEmail": "gcp-etl-sa@contoso-prod.iam.gserviceaccount.com" },
    "methodName": "google.cloud.bigquery.v2.JobService.InsertJob",
    "serviceData": {
      "jobInsertResponse": {
        "resource": {
          "jobConfiguration": { "extract": { "destinationUris": ["gs://staging-exfil-tmp/export-*.csv"] } },
          "jobStatistics": { "totalBytesProcessed": "48318374912" }
        }
      }
    }
  }
}
```

| Field | Read it as |
|-------|------------|
| `jobConfiguration.extract.destinationUris` | 🔴 A destination outside the normal ETL bucket is the exfil tell |
| `jobStatistics.totalBytesProcessed` | Quantifies the pull — compare against the table's normal query-volume baseline |

Fast volume check:
```sql
SELECT creation_time, user_email, statement_type, total_bytes_processed, query
FROM `region-us`.INFORMATION_SCHEMA.JOBS_BY_PROJECT
WHERE user_email = 'gcp-etl-sa@contoso-prod.iam.gserviceaccount.com'
ORDER BY total_bytes_processed DESC;
```

**GCP-side persistence:** rather than depend on the *original* key surviving rotation, the attacker mints their own — `google.iam.admin.v1.CreateServiceAccountKey` on the same SA. A second active key the pipeline owner never created (the same "extra credential" pattern as the AWS backdoor key in step 3; ATT&CK **Additional Cloud Credentials**, T1098.001).

**Evasion — the log sink:** to blind whatever exports Cloud Audit Logs to a SIEM/BigQuery sink before the extract is noticed:

| Field | Read it as |
|-------|------------|
| `protoPayload.methodName` | `google.logging.v2.ConfigServiceV2.DeleteSink` / `...UpdateSink` — logged in **Admin Activity**, which is much harder to tamper with than the sink itself (→ Google **What is Cloud Logging**) |
| `authenticationInfo.principalEmail` | The same burned SA — confirms it wasn't a separate compromise |
| Timing | 🔴 A sink change **immediately before or during** a large extract is evasion, not routine maintenance |

(→ exfil quantification and containment: Google **Data Exfiltration**, **BigQuery for DFIR**; sink-tamper detail: Google **What is Cloud Logging**.)

The connective tissue: **federation** (Entra→AWS, a deliberate bridge you can find a trust object for), **a secret holding a foreign credential** (AWS→GCP, a bridge with no trust object to find — just the key itself), and **one set of infrastructure** (the same source IP/ASN across every hop) tying all three legs to one actor.

> This is one instance, not the template. A case that starts in GCP and ends in AWS uses the *same* five-step framework above, just with `GCP → AWS` (frictionless — check for `accounts.google.com` federated-token use before assuming a custom trust) as its single leg instead of these two. Swap the legs; keep the method.

## Trigger / How You Find Out

| Source | What you see |
|--------|--------------|
| **Entry cloud's own detections** | Risky sign-in / AiTM (Entra), GuardDuty finding (AWS), SCC finding (GCP) — whatever fired first |
| **A single-cloud playbook that "doesn't end"** | The trail points *out* of the cloud you started in — a secret named for another provider, a federated identity, persistence that doesn't explain everything the actor did |
| **The destination cloud, independently** | A credential/token first-used from an IP/ASN you don't associate with that cloud — before you even knew the source cloud was compromised |
| **Cross-cloud SecOps detection** | Same principal/IP across two or more providers' normalized logs (→ [Hunt at Scale](#hunt-at-scale), and **04**) |

**Worked example, concretely:**

| Source | What you see |
|--------|--------------|
| Entra Identity Protection / M365 | Risky sign-in, AiTM, new inbox rule, OAuth consent |
| AWS GuardDuty / CloudTrail | SSO role used from a new ASN; `GetSecretValue`; new access key |
| GCP SCC / Cloud Audit | SA key first-use from an odd IP; large BigQuery extract; sink disabled |

> 🔴 The tell that this is multi-cloud: an investigation in one provider **points at another** — a secret named for a second cloud, a federated login, a credential first-seen from the same IP in a different provider's log. Don't wait for all three clouds to alert independently; one clear pointer is enough to open this playbook.

## Hypothesis

A single actor has moved across two or more clouds using one or more of the bridges cataloged in **00**. Establish the **full identity graph and one timeline** across every cloud touched, find persistence and the objective in *each*, and contain everywhere **at once** — a partial containment lets them walk back in through a cloud you haven't closed yet.

## Step-by-Step Investigation

**1. Anchor the entry.** Start where the first alert fired and decode the identity (→ **01**). Capture the entry artifacts fully before moving on — you'll need them as correlation anchors at every later hop.

> *Worked example:* the AiTM sign-in, the mailbox rule, the OAuth grant → Microsoft **Token Theft & AiTM**, **Illicit Consent Grant**. Anchor identity: `alice@corp.com`, source ASN, `CorrelationId` of the sign-in flow.

**2. Identify the candidate bridges.** Open **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)** for your entry cloud's outbound table and check each mechanism against what this identity could actually do: Does it federate elsewhere? Could it read a secret naming another cloud? Does it run CI/CD with cross-cloud trust? Is it wired to another cloud at the infrastructure layer? Don't skip the frictionless pairs (GCP↔AWS) just because you find no custom trust object — for those two, none is expected to exist.

> *Worked example:* entry identity is Entra — check Azure's Outbound Bridges table in **00**. Row 1, **Federated SSO**, is the candidate: this tenant has IAM Identity Center configured as a SAML relying party.

**3. Follow the bridge into the next cloud.** Open the matching directional note (`{source} → {destination}.md`) and work its **Destination-Side Investigation** section: what "arrived" looks like, field by field, with example values to match against your own logs.

> *Worked example:* → **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)**, destination side, bridge #1 (IAM Identity Center SSO). Trace `AssumeRoleWithSAML` → the resulting `AWSReservedSSO_*` session → everything that role did: recon, the `GetSecretValue` on `gcp-etl-sa-key-Xy9Zab`, the new access key (→ AWS **Identity Center SSO Compromise**, **Leaked Access Key**, **Secrets Manager for DFIR**).

**4. Repeat from step 2 in the new cloud.** The identity/credential you just followed in is your new entry point — check *its* outbound bridges in **00** before assuming the trail ends here.

> *Worked example:* the burned secret names a GCP service-account key — check AWS's Outbound Bridges table in **00**. Row 1, **stored/leaked credential**, is the candidate. → **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)**, destination side, bridge #2. Trace the SA key's first use (`serviceAccountKeyName` on the impersonation events) → `storage.objects.list` → the BigQuery extract (→ Google **Service Account Key Abuse**, **Data Exfiltration**). No further outbound bridge found from this GCP footprint — the trail stops here.

**5. Build ONE timeline.** Normalize every cloud's log to *who/what/where/when/outcome* (→ **03**), merge on UTC, and stitch with the anchors that survive each hop: email/UPN, ASN, tooling fingerprint, timing, the secret read, the credential's first use.

**6. Enumerate persistence in every cloud touched.** Each cloud needs its own sweep — a bridge followed once doesn't mean the actor only touched that one cloud's persistence surface:

| Cloud | Sweep for |
|-------|-----------|
| Microsoft | Mailbox rules, illicit OAuth app consents, new federated credentials on App Registrations |
| AWS | Extra access keys, new users/roles, `AttachUserPolicy`/trust-policy edits, new OIDC/SAML providers (→ AWS **Persistence & Backdoor Hunt**) |
| GCP | New/rotated SA keys, domain-wide delegation grants, new IAM bindings |

**7. Scope the data loss and confirm evidence integrity.** Data-plane reads per cloud (S3/GCS/BigQuery, if enabled), and whether **logging was disabled** anywhere in your window — a gap in one cloud's evidence means you assume worse, not less, happened there.

## Hunt at Scale

The pairwise directional notes each show a 2-hop correlation. What none of them can show on their own is a **single pattern that fires on a 3+-hop chain across all providers at once** — exactly the shape of the worked example above. Normalize to UDM (→ **04**) and look for one identity anchor appearing in a tight sequence across three distinct `metadata.log_type` values:

```
// Conceptual UDM sequence — adapt to your platform's multi-event/join syntax
// (e.g. a Chronicle YARA-L multi-event rule or a scheduled correlation job;
// most SIEMs need an explicit sequence/join construct for this, not a single filter)

sequence, ordered, within 30m, keyed on a shared identity anchor:

  event1  metadata.log_type = "AZURE_AD"
          metadata.product_event_type IN ("Sign-in activity", "Add service principal credentials")
          → capture: principal.user.userid, principal.ip, metadata.event_timestamp

  event2  metadata.log_type = "AWS_CLOUDTRAIL"
          metadata.product_event_type IN ("AssumeRoleWithSAML", "AssumeRoleWithWebIdentity")
          → same principal.ip as event1 (or sourceIdentity carrying event1's identity)
          followed within the window by:
          metadata.product_event_type IN ("GetSecretValue", "BatchGetSecretValue")
          → capture: the secret/resource name touched

  event3  metadata.log_type = "GCP_CLOUDAUDIT"
          metadata.product_event_type IN ("google.iam.credentials.v1.GenerateAccessToken",
             "storage.objects.get", "storage.objects.list", "jobs.create" /* BigQuery */)
          → serviceAccountKeyName or impersonated-SA identity traceable to the secret named in event2
          → principal.ip in the same ASN as event1/event2

alert: all three events present, in order, within the window, sharing the identity/IP anchor
```

This is intentionally a **modest, single pattern** (per this repo's cross-cloud detection philosophy in **04**), not an exhaustive rule pack — one high-signal sequence that catches the shape of "one identity, three clouds, minutes apart" regardless of which specific bridges it used. Tune the `metadata.product_event_type` lists to the bridges relevant to your environment using **00**'s catalog.

## Decision Points

| Question | If yes → |
|----------|----------|
| Does the entry identity have any outbound bridge in **00**'s table for its cloud? | Follow it — treat as multi-cloud now, even before you've confirmed abuse |
| Is the candidate bridge one of the two frictionless pairs (GCP↔AWS)? | Don't wait to find a custom trust object — none is expected; go straight to the destination-side evidence |
| Was a secret/credential holding a foreign cloud's access read? | Assume the second cloud is compromised the moment the read is confirmed |
| Same IP/ASN/tooling across providers? | One actor — correlate, contain everywhere |
| Persistence found in one cloud only? | Sweep every other cloud touched before closing — they re-enter otherwise |
| Was a log sink/trail disabled in any cloud? | Evidence gap — widen sources, assume more happened than you can currently prove |

## Contain

Contain **across all clouds together** — a staggered containment lets the actor pivot back through whichever cloud you haven't closed yet:

```
Microsoft:  revoke sessions/refresh tokens; disable the user; remove mailbox rule;
            revoke the illicit OAuth app's grant.               (→ Entra playbooks)
AWS:        revoke the SSO permission-set sessions; disable the extra access key;
            rotate the secret that was read.                    (→ STS Respond, Secrets Manager)
GCP:        disable the SA + delete rogue SA keys; revoke short-lived tokens;
            remove illicit IAM bindings; re-enable the sink.    (→ Service Accounts, Cloud Logging)
```

Generalize this per cloud actually involved in your case, using each destination-side note's own evidence to know exactly what to revoke.

> 🔴 **Rotate every credential that crossed a boundary.** A secret that held a foreign-cloud key is burned; so is anything that key could reach. Contain the *bridge*, not just the endpoints.

## Eradicate

- **Remove persistence in each cloud** (rules, OAuth apps, keys, roles, SA keys, DWD, federation edits).
- **Fix the entry:** enforce phishing-resistant MFA / Conditional Access to close the initial-access path.
- **Fix the bridges:** scope federation/SSO trust conditions tightly (`aud`/`sub`/attribute conditions per **00**'s red flags); stop storing long-lived foreign credentials in secrets — prefer keyless workload federation (WIF, federated credentials) where the pair supports it; tighten every OIDC/WIF subject condition you find.
- **Rebuild** any compromised host/workload from known-good.

## Recover

- Re-enable and verify logging/detection in **every** cloud touched; land the [Hunt at Scale](#hunt-at-scale) pattern (and **04**'s broader set) so the same chain shape is caught earlier next time.
- Reset the affected users; re-issue clean credentials.
- Preserve the **unified timeline** and each cloud's evidence export (→ **02**) with chain of custody.
- Debrief on the specific bridges that made the case multi-cloud — those are the systemic fixes, not the entry vector alone.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| An investigation that points *out* of its cloud | Multi-cloud in progress — open **00** for that cloud's outbound bridges |
| A GCP↔AWS pivot with no custom trust object found | Expected — this pair is frictionless; the absence of a trust object is not evidence the bridge wasn't used |
| Secret named for another provider, then read | Cross-cloud credential bridge — assume the named cloud is burned |
| Foreign credential first-used from the same infra as the entry compromise | The actor crossed the boundary |
| Same email/ASN/tooling in two or more providers' logs | One actor, multiple clouds |
| Federated/SSO login → immediate privileged action | IdP-ride into the cloud |
| Logging disabled in any one cloud | Evasion; expand scope, assume worse |
| Persistence in one cloud but not swept in others | Re-entry path left open |

## References

- Method & depth: **[03 Cross-Cloud Correlation](../03%20-%20Cross-Cloud%20Correlation.md)**, **[01 Cloud Identity and Federation](../01%20-%20Cloud%20Identity%20and%20Federation.md)**, **[02 Evidence Acquisition](../02%20-%20Evidence%20Acquisition%20in%20the%20Cloud.md)**, **[04 SecOps Detection & Response Engineering](../04%20-%20SecOps%20Detection%20%26%20Response%20Engineering.md)**, **[05 Cloud Threat Landscape](../05%20-%20Cloud%20Threat%20Landscape.md)**
- The bridge catalog: **[00 - Cross-Cloud Bridges Overview](00%20-%20Cross-Cloud%20Bridges%20Overview.md)**
- Per-pair field-level depth: **[Azure → AWS](Azure%20%E2%86%92%20AWS.md)** · **[Azure → GCP](Azure%20%E2%86%92%20GCP.md)** · **[AWS → Azure](AWS%20%E2%86%92%20Azure.md)** · **[AWS → GCP](AWS%20%E2%86%92%20GCP.md)** · **[GCP → AWS](GCP%20%E2%86%92%20AWS.md)** · **[GCP → Azure](GCP%20%E2%86%92%20Azure.md)**
- Provider playbooks: Microsoft **Token Theft & AiTM**, **Illicit Consent Grant** · AWS **Identity Center SSO Compromise**, **Leaked Access Key**, **Persistence & Backdoor Hunt** · Google **Service Account Key Abuse**, **Data Exfiltration**
- MITRE ATT&CK: Valid Accounts – Cloud (T1078.004), Trusted Relationship (T1199), Use Alternate Auth Material (T1550) — https://attack.mitre.org/matrices/enterprise/cloud/
