# What is Applications & Service Principals?

In Entra, an **application** is any piece of software that signs in and calls APIs — a SaaS product, an internal tool, a script. A **service principal** is that application's **identity in your tenant**. This pair is one of the most abused and least understood areas of Microsoft security, so this note makes it concrete.

If **01 - Entra ID & Identities** is the decoder ring for *who*, this is the deep-dive on the **non-human "who"** — the apps that read your mail and data with no user and no MFA.

## Contents

- [How It Works](#how-it-works)
- [App Registration vs Enterprise App — The Two Objects](#app-registration-vs-enterprise-app--the-two-objects)
- [How an App Gets Permissions — Consent](#how-an-app-gets-permissions--consent)
- [Delegated vs Application Permissions](#delegated-vs-application-permissions)
- [How an App Proves Itself — Credentials](#how-an-app-proves-itself--credentials)
- [The High-Risk Permissions](#the-high-risk-permissions)
- [How to Identify Apps in Evidence](#how-to-identify-apps-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## How It Works

An app authenticates to Entra with a **credential** (a client secret, a certificate, or a federated credential), gets a **token**, and calls APIs (usually **Microsoft Graph**) with whatever **permissions** it was granted.

```
App → authenticate with secret/cert → get token → call Graph with its granted scopes
                                                     (delegated = with a user, or application = app-only)
```

The three things you always establish about a suspect app:

1. **Which object** — the app registration and its service principal(s).
2. **What it can do** — its consented permissions (delegated vs application).
3. **How it authenticates** — its credentials (and 🔴 any *recently added* ones).

## App Registration vs Enterprise App — The Two Objects

The universal confusion. An "app" is **two objects**:

| Object | Graph type | What it is | Lives in |
|--------|-----------|-----------|----------|
| **App registration** | `application` | The app's **blueprint** — its App ID, allowed credentials, requested permissions, redirect URIs | The tenant that *built* it |
| **Enterprise app** | `servicePrincipal` | The app's **instance in your tenant** — how it signs in and what it's granted here | **Every** tenant that uses it |

- Building an app in your tenant creates **both**.
- Consenting to a **third-party / multi-tenant** app creates only a **service principal** (enterprise app) in your tenant — the registration lives in the vendor's (or attacker's) tenant.

> 🔴 **This is the crux of the illicit-consent attack:** an attacker registers a multi-tenant app in *their* tenant, tricks a user or admin into consenting, and gets a **service principal in your tenant** holding permissions to your data. You can't delete their registration — but you **can** disable/delete the **service principal** in your tenant to cut it off.

## How an App Gets Permissions — Consent

An app only gets access after someone **consents**:

| Consent type | Who does it | Scope |
|--------------|-------------|-------|
| **User consent** | A regular user | Only *that user's* data (delegated), if the tenant allows user consent |
| **Admin consent** | A privileged admin | 🔴 **Tenant-wide** — grants for *all* users, and any **application** permission |

> 🔴 **Application permissions always require admin consent** — so an admin-consent event granting app-only `Mail.Read`/`.All` is the single most dangerous consent to see. Tenants that allow unrestricted **user consent** are exposed to consent-phishing at scale.

## Delegated vs Application Permissions

*How* the app acts decides its blast radius:

| | **Delegated** (with a user) | **Application** (app-only) |
|-|------------------------------|-----------------------------|
| **Acts as** | The signed-in user + the app | **The app alone — no user, no MFA** |
| **Ceiling** | Lesser of app grant and user's own rights | Exactly the grant, **tenant-wide** |
| **Consent** | User (or admin) | 🔴 **Admin only** |
| **Example** | Read *this* user's mail | Read *everyone's* mail, silently |

> The scary combination is **application permission + high-value scope** (below). That's an app that reads or writes the whole tenant's mail/files/directory, with no user and no MFA, and whose sign-ins land in the rarely-watched **service-principal** log.

## How an App Proves Itself — Credentials

An app authenticates with one of:

| Credential | What it is | 🔴 Risk |
|-----------|-----------|---------|
| **Client secret** | A password-like string | Leaks in code/config; easy to add as persistence |
| **Certificate** | A public/private keypair | Stronger, but a rogue cert = stealthy persistence |
| **Federated credential** | Trust to an external IdP/OIDC (e.g. GitHub, another cloud) | 🔴 Loose trust = external workload can authenticate as the app |

> 🔴 **`Add service principal credentials` / adding a secret or cert to an existing app** is a top persistence technique: the attacker plants their own key in a **trusted, over-permissioned app** and returns any time — no user, no MFA, quiet. Always inventory an app's credentials and their **creation dates**.

## The High-Risk Permissions

Memorize these — as **application** permissions they effectively own the tenant:

| Permission | Grants |
|-----------|--------|
| `Mail.Read` / `Mail.ReadWrite` | Read/modify **all mailboxes** |
| `Files.ReadWrite.All` / `Sites.ReadWrite.All` | Read/write **all SharePoint/OneDrive** |
| `Directory.ReadWrite.All` | Modify the **directory** (users, groups) |
| `RoleManagement.ReadWrite.Directory` | 🔴 **Grant roles** — become Global Admin via the app |
| `Application.ReadWrite.All` | Create/modify apps + **add credentials** (persistence) |
| `User.ReadWrite.All` | Reset passwords, edit users |
| `full_access_as_app` (EWS) | Full mailbox access as the app |

## How to Identify Apps in Evidence

- **Portal:** Entra ID → **Enterprise applications** (service principals) and **App registrations**.
- **Graph:** `/servicePrincipals`, `/applications`, `/oauth2PermissionGrants` (delegated), `/servicePrincipals/{id}/appRoleAssignments` (application).
- **Audit log:** `Add service principal`, `Consent to application`, `Add app role assignment to service principal`, `Add service principal credentials`.
- **Sign-in log:** the **service-principal** tab.

## Common Operations You Will See

| Operation (audit log) | What it does | Watch? |
|-----------------------|--------------|--------|
| `Add service principal` | An app added to the tenant | 🔴 unexpected multi-tenant app |
| `Consent to application` | Permissions granted to an app | 🔴 high-risk scopes / admin consent |
| `Add app role assignment to service principal` | Application-permission grant | 🔴 `*.All` app perms |
| `Add service principal credentials` | Secret/cert added | 🔴 persistence |
| `Add owner to service principal/application` | New app owner | 🔴 persistence (owner can add creds) |
| `Update application` | App config change | Redirect URI / cred changes |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| App registration | OAuth client / IAM role def | OAuth client |
| Service principal (enterprise app) | IAM role assumed by an app | Service account |
| Application permission | Role attached to a service | Domain-wide delegation |
| Client secret / cert | Access key / cert | SA key |
| Federated credential | OIDC/web-identity trust | Workload Identity Federation |

## Common Use Cases

Your "normal" baseline:

- **SaaS integrations** consented by users/admins (Salesforce, Zoom, backup tools).
- **Internal apps/automation** using app-only Graph.
- **CI/CD** using federated credentials.
- **Managed identities** for Azure workloads (a special SP type).

## Key Terminology

| Term | Meaning |
|------|---------|
| **Application (app registration)** | The app's blueprint/definition |
| **Service principal (enterprise app)** | The app's identity/instance in a tenant |
| **App ID (client ID)** | GUID identifying the app registration |
| **Consent** | Granting an app permission to data |
| **Delegated permission** | App acts with a signed-in user |
| **Application permission** | App acts app-only, tenant-wide |
| **Client secret / certificate** | The app's authentication credential |
| **Federated credential** | Trust from an external IdP to the app |
| **OAuth2PermissionGrant** | A delegated-permission grant record |
| **AppRoleAssignment** | An application-permission grant record |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a rogue app | **Applications & Service Principals → for DFIR** |
| Identity types + tokens | **Microsoft → 01 Entra ID & Identities** |
| Consent / credential events | **Entra → Audit Logs** |
| App sign-ins | **Entra → Sign-in Logs** |
| A consent-phishing intrusion | **Entra → Playbooks → Illicit Consent Grant** |
| A credential-add persistence chain | **Entra → Playbooks → Service Principal Credential Abuse** |
| Managed identities (a special SP) | **Azure → Managed Identities** |

## Resources

- Apps & service principals — https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals
- Permissions & consent — https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview
- Consent framework / illicit consent — https://learn.microsoft.com/defender-office-365/detect-and-remediate-illicit-consent-grants
- Microsoft Graph permissions reference — https://learn.microsoft.com/graph/permissions-reference
