# Google Identities

Every Google event answers one question first: **who did this?** And in Google, "who" is subtle — the same access can come from a person, a **service account** acting *as itself*, a service account someone **impersonated**, a VM that carries an attached identity, or an **external** workload federated in. Each looks different in the logs.

This note is the **decoder ring for the `who`.** It teaches you to look at a Cloud Audit Log entry and instantly say: *a user, a service account, an impersonation, or a federated workload* — and to tell a long-lived **service-account key** from a short-lived **impersonation token**. Get this right and the rest of the investigation falls into place.

## Contents

- [Why This Note Exists](#why-this-note-exists)
- [The Identity Types at a Glance](#the-identity-types-at-a-glance)
- [How You Authenticate to Google](#how-you-authenticate-to-google)
- [Users vs Service Accounts — The Core Distinction](#users-vs-service-accounts--the-core-distinction)
- [SA Keys vs Impersonation — Long-Term vs Short-Term](#sa-keys-vs-impersonation--long-term-vs-short-term)
- [Default and Google-Managed Service Accounts](#default-and-google-managed-service-accounts)
- [Domain-Wide Delegation — The Workspace Bridge](#domain-wide-delegation--the-workspace-bridge)
- [Workload Identity Federation and GKE Workload Identity](#workload-identity-federation-and-gke-workload-identity)
- [The Identifiers — Email, Unique ID, Project](#the-identifiers--email-unique-id-project)
- [Tokens — The Credentials of the Cloud](#tokens--the-credentials-of-the-cloud)
- [Reading an Audit Log Entry](#reading-an-audit-log-entry)
- [How Each Identity Appears in the Logs](#how-each-identity-appears-in-the-logs)
- [Permissions — How Access Is Decided](#permissions--how-access-is-decided)
- [Red Flags](#red-flags)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why This Note Exists

An attacker rarely stays one identity. A typical modern Google chain looks like:

```
phished user  →  steal a service-account key (JSON)  →  impersonate a more powerful SA
              →  SA has domain-wide delegation  →  read every mailbox in Workspace, no user, no MFA
```

If you can't tell a **user** from a **service account** from an **impersonation**, you can't follow that chain — and you can't answer "who is the human, or what is the workload, behind this?" This note makes that chain readable.

## The Identity Types at a Glance

| Identity type | What it is | Authenticates with | Where it lives | 🔴 In logs (`principalEmail`) |
|---------------|-----------|--------------------|----------------|------------------------------|
| **User** | A normal employee Google account | Password + MFA, or SAML/SSO | Your Cloud Identity/Workspace | `alice@contoso.com` |
| **Google group** | A group used in IAM bindings | (not a login — a container) | Your directory | `admins@contoso.com` |
| **Service account (SA)** | A **workload's identity** | A **JSON key**, impersonation, or attached to a resource | A GCP project | `sa-app@contoso-prod.iam.gserviceaccount.com` |
| **Default SA** | An SA auto-created for Compute/App Engine | Attached to the resource | The project | `…-compute@developer.gserviceaccount.com` |
| **Google-managed service agent** | An SA Google uses to act on your project | Google-managed | Google | `service-<num>@gcp-sa-<svc>.iam.gserviceaccount.com` |
| **Federated / external identity** | An outside workload (AWS/Azure/OIDC/GitHub) or a consumer account | Workload Identity Federation, or its own creds | Outside your directory | `principalSubject`; a `@gmail.com` or foreign domain |

> The two you'll spend most time on: a **user** (the phished human — the *first* thing compromised) and a **service account** (a workload — what attackers *pivot into* for stealthy, MFA-less access, especially one with a long-lived key or domain-wide delegation).

## How You Authenticate to Google

Before the identity types make sense, understand the **doors** — the ways a person or a workload proves who it is. In Google the tell is in **`authenticationInfo`** in the Cloud Audit Log, and each door leaves a different field:

| Method | Who uses it | What they present | How to spot it in `authenticationInfo` |
|--------|-------------|-------------------|----------------------------------------|
| **Interactive user login** | A human | Password / 2SV / SAML SSO | `principalEmail` = `user@domain`; login itself is in the Workspace **Login audit** |
| **SA key (JSON)** | A workload with a downloaded key | The **long-lived JSON key** signs a token request | 🔴 `serviceAccountKeyName` present (`…/keys/<id>`) |
| **SA impersonation** | A principal allowed to act as an SA | Calls `generateAccessToken` → **short-lived token** | 🔴 `serviceAccountDelegationInfo` present (the *real* caller) |
| **Attached SA (metadata)** | Code on a VM / GKE / Cloud Run | The **metadata server** hands it a token, no key | `principalEmail` = `…gserviceaccount.com`, **no** `serviceAccountKeyName` |
| **Workload Identity Federation** | External workload (AWS/Azure/OIDC/GitHub) | An OIDC/SAML token exchanged for a Google token | `principalSubject` / external subject |
| **Domain-wide delegation** | An SA acting *as a user* in Workspace | An assertion authorizing the SA to impersonate the user | `principalEmail` = the **user**, with `serviceAccountDelegationInfo` = the SA 🔴 |
| **OAuth third-party app** | An app a user consented to | An OAuth token with granted scopes | App in the **OAuth/Token audit**; token grant |

Two things to lock in, because they drive every Google investigation:

- **The `authenticationInfo` fields are how you tell the doors apart.** `serviceAccountKeyName` = a **long-lived key** was used (the "leaks in git" class). `serviceAccountDelegationInfo` = an **impersonation** (find the *real* caller inside it). Neither present on an SA principal = an **attached** SA (metadata). This trio is the Google equivalent of AWS's `AKIA`-vs-`ASIA` tell.
- **No MFA on workloads.** Service accounts, keys, and impersonation carry **no MFA** — so a leaked key or an over-broad `actAs` is game-over-quiet. Containment = disable the SA / delete the key / remove the impersonation grant (short-lived tokens then expire).

## Users vs Service Accounts — The Core Distinction

This is the concept people get wrong. Burn it in:

| | **User** | **Service account** |
|-|----------|----------------------|
| **Represents** | A human | An application / workload / VM |
| **Authenticates with** | Password + **MFA**, SSO applies | A **JSON key**, an **impersonation** token, or **attachment** to a resource — 🔴 **no MFA** |
| **Appears in** | **Login audit** (Workspace) + Cloud Audit Logs | **Cloud Audit Logs** only (SAs don't sign into Workspace) |
| **Permissions via** | IAM bindings on its email + its groups | IAM bindings on the **SA's email** (+ what it can impersonate) |
| **Lifecycle** | Managed in the Admin console | Created/deleted via IAM in a project |
| **Analogy** | A named employee badge | A **robot with its own keycard** — no face, no MFA prompt |

> 🔴 **Why attackers love service accounts:** an SA authenticates with **no MFA and no human interaction**, its activity blends into normal automation, and a **user-managed JSON key never expires**. An SA with the **Editor** role (the default!) or **domain-wide delegation** is a tenant-wide skeleton key. Creating a key on an existing SA (`google.iam.admin.v1.CreateServiceAccountKey`) is a top persistence technique. See **GCP → Service Accounts**.

## SA Keys vs Impersonation — Long-Term vs Short-Term

This is the **Google equivalent of AWS `AKIA` vs `ASIA`**, and it is the single most important distinction for both attribution and containment. A service account can be *used* two fundamentally different ways:

| | **Service-account key (JSON)** | **Impersonation (short-lived token)** |
|-|--------------------------------|----------------------------------------|
| **What it is** | A downloaded **private key file** the workload signs with | A **short-lived OAuth token** minted for the SA on demand |
| **Lifetime** | 🔴 **Never expires** — valid until the key is deleted | ✅ Short — **~1 hour** (up to 12h if configured) |
| **How it's obtained** | `CreateServiceAccountKey` → a `.json` file | `generateAccessToken` / `signJwt` (needs `roles/iam.serviceAccountTokenCreator`) |
| **The log tell** | 🔴 `authenticationInfo.serviceAccountKeyName` is present | 🔴 `authenticationInfo.serviceAccountDelegationInfo` lists the impersonation chain |
| **How you kill it** | **Delete the key** (`DeleteServiceAccountKey`) | **Remove the `TokenCreator` binding**; the token expires on its own |
| **🔴 Risk** | Leaks and lives **forever** in code/git/laptops/CI — the leaked-in-git classic | Short-lived but minted *from* something — find the caller who could impersonate |

> 🔴 **Containment differs — this is the key operational fact.** Deleting a stolen **JSON key** stops that path. But if the attacker used it to **impersonate** another SA, they hold a short-lived token that **keeps working until it expires** — and they can re-mint it as long as they retain the `TokenCreator` permission. You must **remove the impersonation grant**, not just delete the key. This is the Google version of "the `ASIA` session keeps working after you kill the `AKIA` key." See **GCP → Service Accounts → Respond**.

> **Modern best practice is *keyless*.** Google recommends **no downloaded keys at all** — use attachment (`actAs`), impersonation, or Workload Identity Federation instead. So a **newly created user-managed SA key is itself a red flag** in a mature environment.

## Default and Google-Managed Service Accounts

Not all SAs are equal — know which is which:

| SA kind | Email shape | Why the analyst cares |
|---------|-------------|-----------------------|
| **User-managed SA** | `<name>@<project-id>.iam.gserviceaccount.com` | The ones you create for apps; check their roles + keys |
| **Compute Engine default SA** | `<project-number>-compute@developer.gserviceaccount.com` | 🔴 Historically granted **Editor** on the whole project and **attached to every VM** by default — a huge blast radius if a VM is compromised (see metadata SSRF) |
| **App Engine / Cloud Functions default SA** | `<project-id>@appspot.gserviceaccount.com` | Similar over-privilege risk |
| **Google-managed service agent** | `service-<project-number>@gcp-sa-<service>.iam.gserviceaccount.com` | Google acting on your project (e.g. `gcp-sa-storage`) — usually benign, but confirm the action fits the service |

> 🔴 The **Compute Engine default SA** is the single most abused Google identity: default **Editor**, attached to VMs, reachable via the **metadata server**. A compromised VM → its token → project-wide write. See **GCP → Compute Engine** and **GCP → Playbooks → Metadata SSRF to SA Token Theft**.

## Domain-Wide Delegation — The Workspace Bridge

**Domain-Wide Delegation (DWD)** is the most dangerous bridge between the two clouds. A **GCP service account** can be authorized (in the **Admin console**, by a Super Admin) to **impersonate Workspace users** for specific OAuth scopes — so the SA can read *any* user's Gmail, Drive, or Calendar **without that user's consent**.

| Fact | Detail |
|------|--------|
| **Set where** | Admin console → Security → API controls → **Domain-wide delegation** (SA's OAuth client ID + scopes) |
| **What it grants** | The SA can call Workspace APIs **as any user** in the domain, within the granted scopes |
| **🔴 The attack** | Steal the SA's **key** (or impersonate the SA) → read the CEO's mailbox, exfil all of Drive — silently, no user, no MFA |
| **The log tell** | Gmail/Drive API calls where the SA acts on a user's data; a new client ID added to the DWD list (Admin audit) |

> 🔴 **DWD is a GCP identity holding a Workspace master key.** Enumerate every SA with domain-wide delegation as a standing risk; a **new DWD grant** is a top-tier alert. This is *the* GCP↔Workspace lateral-movement path. See **GCP → Service Accounts** and **Workspace → OAuth & Third-Party Apps**.

## Workload Identity Federation and GKE Workload Identity

Two keyless ways an *external or in-cluster* workload becomes a Google identity:

| Mechanism | What it is | 🔴 Risk |
|-----------|-----------|---------|
| **Workload Identity Federation** | An external IdP (AWS, Azure, OIDC, GitHub Actions, SAML) exchanges its token for a Google SA token — **no key** | A **loose attribute/audience condition** lets the wrong external identity impersonate your SA — the OIDC-trust-abuse pattern |
| **GKE Workload Identity** | A Kubernetes service account maps to a GCP SA, so pods get Google tokens | A compromised pod gets the SA's token — investigate its IAM reach, like a stolen SA |

> 🔴 In logs, federated callers show a **`principalSubject`** (e.g. the external subject) rather than a normal SA email, and the exchange appears via the **Security Token Service** (`sts.googleapis.com`). An unexpected external subject minting SA tokens = federation abuse. See **GCP → Workload Identity Federation**.

## The Identifiers — Email, Unique ID, Project

Google identities are **email addresses** (not ARNs, not GUIDs). Know the pieces:

| Identifier | Belongs to | Shape | Use on a case |
|-----------|-----------|-------|---------------|
| **Principal email** | Any identity (user or SA) | `alice@contoso.com` / `sa@proj.iam.gserviceaccount.com` | The main key — `principalEmail` ties events to one identity |
| **Unique ID** | A user or SA | A numeric string | Stable even if the email is deleted/reused — pivot on this for deleted identities |
| **Project ID / number** | The project an SA belongs to | `contoso-prod` / `729...` | Which project owns the SA; default-SA emails embed the **number** |
| **OAuth client ID** | An app / SA (for consent + DWD) | A numeric client ID | Ties an OAuth grant or DWD entry to an app |
| **Customer ID** | The whole directory | `C01abc234` | Which org |

> 🔴 **The pivot in one line:** `principalEmail` tells you *who*, and for a service account the domain (`…iam.gserviceaccount.com`) tells you it's a workload, not a person. When an email was deleted and recreated, pivot on the **unique ID** to avoid confusing two different identities that shared a name.

## Tokens — The Credentials of the Cloud

Google is **OAuth 2.0 / OpenID Connect**. Access is granted with **tokens**. Knowing the token types is the Google equivalent of knowing `AKIA` vs `ASIA` — it tells you what was stolen and how you contain it.

| Token | What it is | Lifetime | 🔴 If stolen |
|-------|-----------|----------|-------------|
| **SA key (JSON)** | A downloaded private key that *signs* to get tokens | 🔴 **Never expires** | Long-lived skeleton key — the leaked-in-git classic |
| **OAuth access token** | The bearer key that **calls an API** | **~1 hour** | Works until expiry; MFA already satisfied inside it |
| **Refresh token** | Used to **silently mint new access tokens** | Long-lived (rolling) | 🔴 Persistence — `gcloud` login + OAuth apps hold these; mint fresh tokens without re-auth |
| **ID token** | Proof of *who* the user/workload is (OIDC) | Short | Low value alone — not used to call most APIs |
| **Impersonation token** | A short-lived token minted **for another SA** | **~1 hour** (up to 12h) | Works until expiry; find who could impersonate |

**The containment consequence — this is the key operational fact:**

> 🔴 **Disabling an account or resetting a password does NOT kill existing tokens.** An **OAuth access token** keeps working until it expires (~1 hr); a **refresh token** or **OAuth app grant** keeps minting new ones; a **user-managed SA key** works **forever** until deleted. To actually cut a compromised session you must: **revoke the user's sessions** (Admin console → reset + "sign out"), **revoke OAuth tokens/app grants**, **delete SA keys**, and **remove impersonation grants**. This is the Google equivalent of "the `ASIA` session keeps working after you kill the `AKIA` key." See **Workspace → Login & Auth Audit → Respond** and **GCP → Service Accounts → Respond**.

**Token theft is the modern attack.** AiTM phishing proxies the real Google login, the victim completes MFA, and the attacker captures the resulting **token/session cookie** — MFA already baked in. See **Workspace → Playbooks → Account Takeover**.

## Reading an Audit Log Entry

Every Cloud Audit Log entry carries an `authenticationInfo` / `authorizationInfo` block. Here's a real-ish one for an **impersonated service account** action:

```jsonc
"protoPayload": {
  "authenticationInfo": {
    "principalEmail": "pipeline@contoso-ci.iam.gserviceaccount.com",   // who acted
    "serviceAccountKeyName": "//iam.googleapis.com/projects/contoso-ci/serviceAccounts/pipeline@contoso-ci.iam.gserviceaccount.com/keys/abc123",  // 🔴 a LONG-LIVED key was used
    "serviceAccountDelegationInfo": [                                   // 🔴 impersonation chain
      { "firstPartyPrincipal": { "principalEmail": "alice@contoso.com" } }
    ]
  },
  "authorizationInfo": [
    { "permission": "storage.objects.get", "granted": true,
      "resource": "projects/_/buckets/crown-jewels" }
  ],
  "requestMetadata": {
    "callerIp": "203.0.113.10",
    "callerSuppliedUserAgent": "google-cloud-sdk gcloud/..." }
}
```

**The fields that carry the investigation:**

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `authenticationInfo.principalEmail` | The identity that acted | 🔴 an SA where you expect a human, or vice-versa |
| `authenticationInfo.serviceAccountKeyName` | A **user-managed key** was used | 🔴 present at all in a keyless environment |
| `authenticationInfo.serviceAccountDelegationInfo` | The **impersonation chain** (who → who) | 🔴 an unexpected human/SA impersonating a privileged SA |
| `authenticationInfo.principalSubject` | A **federated** external subject | 🔴 Workload Identity Federation abuse |
| `authorizationInfo[].permission` / `.granted` | What was attempted + allow/deny | Bursts of `granted:false` = probing |
| `requestMetadata.callerIp` | Source IP | 🔴 new geo/ASN; Tor/VPN |
| `requestMetadata.callerSuppliedUserAgent` | Tooling | Human browser vs `gcloud`/script |
| `methodName` | The API action | 🔴 `SetIamPolicy`, `CreateServiceAccountKey`, `generateAccessToken` |

## How Each Identity Appears in the Logs

Quick recognition guide — what you actually see:

| You see… | It's… |
|----------|-------|
| Login-audit sign-in, a `@contoso.com` email, MFA, a browser | A **member user** (a person) |
| `principalEmail` at a `@gmail.com` or foreign domain in an IAM binding | An **external / consumer** account 🔴 |
| `principalEmail` ending `…iam.gserviceaccount.com`, no MFA, `gcloud`/SDK agent | A **service account** (a workload) |
| `serviceAccountKeyName` present | The SA authenticated with a **long-lived JSON key** 🔴 |
| `serviceAccountDelegationInfo` present | An **impersonation** — read the chain to find the human/SA behind it |
| `principalSubject` (not an email) | A **federated external** workload |
| `principalEmail` = `…-compute@developer.gserviceaccount.com` | The **Compute default SA** (often a compromised VM) 🔴 |
| `CreateServiceAccountKey` on an existing SA | Someone **minted a key** 🔴 persistence |
| `SetIamPolicy` granting a role | An **IAM change** 🔴 possible privesc |
| A **new domain-wide-delegation** client ID (Admin audit) | An SA granted a **Workspace master key** 🔴 |

## Permissions — How Access Is Decided

You don't need to author policy, but you must understand *why an action succeeded* — it tells you what the attacker could reach.

**The IAM model, simply:**

| Piece | What it is |
|-------|-----------|
| **Member / principal** | Who: a user, group, SA, or federated identity |
| **Role** | A bundle of permissions — **Basic** (Owner/Editor/Viewer 🔴 broad), **Predefined** (`roles/storage.admin`), or **Custom** |
| **Binding** | A `member → role` grant **on a resource** (org / folder / project / resource) |
| **Policy** | The set of bindings on a resource; edited by **`SetIamPolicy`** |

**The rules that matter on a case:**

- Access is **additive** — a principal's effective access is the **union** of every binding that applies, **inherited down** the hierarchy (org → folder → project → resource). There is no AWS-style explicit-deny by default; **IAM Deny policies** exist but are separate and less common.
- 🔴 The **Basic roles** — **Owner**, **Editor**, **Viewer** — are dangerously broad. **Editor** (the default SA role!) can modify almost everything in a project.
- 🔴 **Privilege-escalation permissions to watch:** `iam.serviceAccountKeys.create` (mint a key), `iam.serviceAccounts.getAccessToken`/`actAs` (impersonate), `iam.roles.update` (rewrite a custom role), `resourcemanager.*.setIamPolicy` (grant yourself a role), `iam.serviceAccounts.getOpenIdToken`.

> 🔴 A **burst of `granted:false` then a sudden success** — or a `SetIamPolicy` adding `roles/owner` right before sensitive actions — is privilege escalation in progress. See **GCP → Cloud IAM** and **GCP → Playbooks → IAM Privilege Escalation**.

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `CreateServiceAccountKey` on an existing SA | **Persistence** — attacker minted a long-lived key |
| Any user-managed SA key in a "keyless" environment | Standing risk / possible backdoor |
| `serviceAccountDelegationInfo` showing an unexpected impersonator | Impersonation abuse / privesc |
| `SetIamPolicy` granting **Owner/Editor** or org-level admin | Privilege escalation |
| `SetIamPolicy` at the **organization** level granting `organizationAdmin` | 🔴 Super-Admin → GCP takeover pivot |
| A new **domain-wide-delegation** client ID | SA granted a Workspace-wide mailbox/Drive key |
| IAM binding to a `@gmail.com` / external domain | External foothold |
| Compute default SA acting from an unexpected IP | Metadata SSRF / VM compromise |
| `principalSubject` (federation) minting SA tokens unexpectedly | Workload Identity Federation abuse |
| Token/OAuth grant to an unfamiliar third-party app | Illicit consent grant |
| Refresh-token use / `gcloud` login from a new geo | Session/token theft |

## Cross-Provider Equivalent

| Google | AWS | Microsoft |
|--------|-----|-----------|
| User | IAM user | Member user |
| Google group | IAM group | Entra group |
| Service account | IAM role (assumed by app) | Service principal / managed identity |
| SA key (JSON) | Access key (`AKIA`) | Client secret / certificate |
| Impersonation token | STS session (`ASIA`) | OAuth access token |
| `generateAccessToken` | `AssumeRole` | Token request / OBO |
| Workload Identity Federation | `AssumeRoleWithWebIdentity` | Federated credential |
| Attached/default SA | Instance profile / instance role | Managed identity |
| Domain-wide delegation | (no direct equal) | App-only Graph permissions (`Mail.Read` app) |
| Basic role (Owner/Editor) | `AdministratorAccess` / broad policy | Owner / Global Admin |
| `SetIamPolicy` | `AttachRolePolicy` / trust edit | Role assignment |
| Revoke keys / impersonation | Revoke role sessions | Revoke refresh tokens |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| How the org/projects/two-admin-worlds fit together | **Google → 00 Overview & Terminology** |
| Where these identities show up (the master audit log) | **GCP → Cloud Audit Logs** |
| Service accounts, keys, impersonation in depth | **GCP → Service Accounts** |
| IAM roles, bindings, and the privesc paths | **GCP → Cloud IAM** |
| Federated external workloads | **GCP → Workload Identity Federation** |
| Human sign-ins, MFA, suspicious login | **Workspace → Login & Auth Audit** |
| A key-theft / impersonation intrusion | **GCP → Playbooks → Service Account Key Abuse** |
| Same human pivoting across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Service accounts overview — https://cloud.google.com/iam/docs/service-account-overview
- Service account keys — https://cloud.google.com/iam/docs/keys-create-delete
- Create short-lived credentials (impersonation) — https://cloud.google.com/iam/docs/create-short-lived-credentials-direct
- Domain-wide delegation — https://support.google.com/a/answer/162106
- Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
- Audit log entry structure (`AuthenticationInfo`) — https://cloud.google.com/logging/docs/audit#audit_log_entry_structure
- IAM roles & permissions — https://cloud.google.com/iam/docs/roles-overview
