# Entra ID & Identities

Every Microsoft event answers one question first: **who did this?** And in Entra, "who" is subtle — the same access can come from a person, a guest from another company, an app acting *as itself*, or a VM that carries its own identity. Each looks different in the logs.

This note is the **decoder ring for the `who`.** It teaches you to look at a sign-in or audit event and instantly say: *a user, a guest, a service principal, or a managed identity* — and to tell an **access token** from a **refresh token** from a stolen **primary refresh token**. Get this right and the rest of the investigation falls into place.

## Contents

- [Why This Note Exists](#why-this-note-exists)
- [The Identity Types at a Glance](#the-identity-types-at-a-glance)
- [How You Authenticate to Microsoft](#how-you-authenticate-to-microsoft)
- [Users vs Service Principals — The Core Distinction](#users-vs-service-principals--the-core-distinction)
- [App Registration vs Enterprise App (Service Principal)](#app-registration-vs-enterprise-app-service-principal)
- [Managed Identities — Identities for Azure Resources](#managed-identities--identities-for-azure-resources)
- [The Identifiers — Object ID vs App ID vs UPN](#the-identifiers--object-id-vs-app-id-vs-upn)
- [Tokens — The Credentials of the Cloud](#tokens--the-credentials-of-the-cloud)
- [Delegated vs Application Permissions](#delegated-vs-application-permissions)
- [Reading a Sign-in Event](#reading-a-sign-in-event)
- [Interactive vs Non-Interactive Sign-ins](#interactive-vs-non-interactive-sign-ins)
- [How Each Identity Appears in the Logs](#how-each-identity-appears-in-the-logs)
- [Red Flags](#red-flags)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why This Note Exists

An attacker rarely stays one identity. A typical modern Entra chain looks like:

```
phished user  →  steal token (AiTM)  →  add credential to an app (service principal)
              →  grant the app app-only Graph permissions  →  app reads all mailboxes, no user, no MFA
```

If you can't tell a **user** from a **service principal** from a **managed identity**, you can't follow that chain — and you can't answer "who is the human, or what is the app, behind this?" This note makes that chain readable.

## The Identity Types at a Glance

| Identity type | What it is | Signs in with | Where it lives | 🔴 In logs |
|---------------|-----------|---------------|----------------|-----------|
| **Member user** | A normal employee identity | Password + MFA, or federated | Your tenant | UPN `alice@contoso.com` |
| **Guest user (B2B)** | An external person invited in | Their home tenant's creds | *Another* tenant, referenced in yours | UPN with `#EXT#`, `userType=Guest` |
| **Service principal (enterprise app)** | An **app's identity** in your tenant | Client secret / certificate / federated cred | Your tenant | App display name; `appId` (GUID) |
| **Managed identity** | An identity **Azure gives a resource** (VM, Function, AKS) | Azure-managed, no secret you hold | Your tenant, tied to a resource | Service principal of type `ManagedIdentity` |
| **On-prem synced user** | An AD user synced up via Entra Connect | AD password (hash-synced or federated) | On-prem AD → synced to Entra | `onPremisesSyncEnabled=true` |

> The two you'll spend most time on: a **user** (the phished human — the *first* thing compromised) and a **service principal** (an app — what attackers *pivot into* for stealthy, MFA-less, app-only access to email and data).

## How You Authenticate to Microsoft

Before the identity types make sense, understand the **doors** — the ways a person or an app proves who it is to Entra. Each door lands in a **different log**, and that split is the single biggest Microsoft blind spot:

| Method | Who uses it | What they present | Which log it lands in |
|--------|-------------|-------------------|-----------------------|
| **Interactive sign-in** | A human, at a prompt | Password / passwordless / passkey **+ MFA**; Conditional Access applies | Entra **Interactive** sign-in log |
| **Non-interactive sign-in** | A human's client, silently | A cached/refresh token (no prompt) | Entra **Non-interactive** sign-in log 🔴 (separate) |
| **Service principal** | An app as *itself* | A **client secret or certificate** — 🔴 **no MFA, most CA does not apply** | **Service principal** sign-in log 🔴 (separate, often unwatched) |
| **Managed identity** | An Azure resource (VM/Function/AKS) | Azure-issued token, **no secret you hold** (via IMDS) | **Managed identity** sign-in log 🔴 (separate) |
| **Federated** | On-prem/ADFS or external IdP users | A SAML/WS-Fed assertion from the IdP | Interactive sign-in w/ federated details |
| **Device / PRT** | A joined device's user | A **Primary Refresh Token** bound to the device | Sign-in w/ device + PRT details |
| **Legacy auth** | Old clients/protocols | Basic auth (username+password, **no MFA possible**) | 🔴 Sign-in w/ legacy `clientApp` (IMAP/POP/SMTP) |

Two things to lock in, because they drive every Microsoft investigation:

- **Sign-ins are split across four logs** (interactive, non-interactive, **service principal**, **managed identity**). An investigation that only reads the interactive log **misses app and workload activity entirely** — where stealthy attackers live. Always pull all four.
- **Microsoft is bearer-token based.** Once issued, an **access token** works from anywhere until it expires; a stolen **refresh token / PRT** re-mints access tokens. So containment = **revoke the tokens**, not just reset the password (see *Tokens* below).

## Users vs Service Principals — The Core Distinction

This is the concept people get wrong. Burn it in:

| | **User** | **Service principal** (app) |
|-|----------|------------------------------|
| **Represents** | A human | An application / workload |
| **Signs in with** | Password + **MFA**, Conditional Access applies | A **client secret or certificate** — 🔴 **MFA and most Conditional Access do NOT apply** |
| **Appears in** | **Interactive** + non-interactive sign-in logs | **Service principal sign-in logs** (a *separate* log 🔴 often not monitored) |
| **Permissions via** | Its roles + group memberships | **App role assignments** (app-only) or delegated (on behalf of a user) |
| **Analogy** | A named employee badge | A **robot with its own keycard** — no face, no MFA prompt |

> 🔴 **Why attackers love service principals:** an app with a client secret authenticates with **no MFA and no user interaction**, and its sign-ins land in a **different log** most teams never watch. Granting an app **application permissions** (e.g. `Mail.Read` app-only) lets it read *every* mailbox in the tenant silently. Adding a secret to an existing app (`Add service principal credentials` in the audit log) is a top persistence technique. See **Entra → Applications & Service Principals**.

## App Registration vs Enterprise App (Service Principal)

Another universal point of confusion. An "app" in Entra is **two objects**:

| Object | What it is | Analogy | Lives |
|--------|-----------|---------|-------|
| **App registration** (`application`) | The app's **definition / blueprint** — its ID, its allowed credentials, its requested permissions | The *class* | In the tenant that *built* the app (home tenant) |
| **Enterprise app** (`servicePrincipal`) | The **instance** of that app **in your tenant** — how it actually signs in and is granted access here | The *object* | In **every** tenant that uses the app |

- When someone **consents** to a third-party app, Entra creates a **service principal** (enterprise app) for it in your tenant. That's the object that then holds permissions.
- 🔴 A **multi-tenant** app registered in an attacker's tenant, once consented in yours, gets a **service principal in your tenant** with whatever permissions were granted — the **illicit consent grant** attack. See **Entra → Playbooks → Illicit Consent Grant**.

> **On a case:** credentials and permission grants attach to the **service principal / enterprise app**. That's the object you disable to contain a rogue app.

## Managed Identities — Identities for Azure Resources

A **managed identity** is an identity Azure creates and manages for a **resource** (a VM, Function, App Service, AKS pod) so it can call Azure/Graph **without a stored secret**. It is the Azure equivalent of an AWS instance role.

| Type | What it is | 🔴 Risk |
|------|-----------|---------|
| **System-assigned** | Tied 1:1 to one resource; dies with it | Compromise the resource → get its token via IMDS |
| **User-assigned** | A standalone identity attachable to many resources | Over-shared → one compromise reaches many resources' rights |

**How it gets a token:** code on the resource calls the **Instance Metadata Service (IMDS)** at **`169.254.169.254`** and receives an **access token** — no secret involved. 🔴 This is the **exact Azure analog of the AWS IMDS/SSRF role-theft problem**: an SSRF or RCE on the resource lets an attacker pull the managed-identity token and act as the resource. See **Azure → Managed Identities** and **Azure → Playbooks → Managed Identity Theft via SSRF**.

> In sign-in logs a managed identity appears as a **service principal sign-in** whose app is of type **Managed Identity**. If you see one authenticating from an unexpected IP or doing unexpected Graph/Azure calls, treat the underlying resource as compromised.

## The Identifiers — Object ID vs App ID vs UPN

Microsoft identities are **GUIDs**, not ARNs. Know which GUID is which:

| Identifier | Belongs to | Shape | Use on a case |
|-----------|-----------|-------|---------------|
| **Object ID (OID)** | Any directory object (user, group, SP) | GUID | The stable, unique key — ties events to one identity even if the name changes |
| **Application (client) ID** | An app registration | GUID | Identifies *which app*; shared across tenants for multi-tenant apps |
| **Service principal object ID** | The enterprise app in *your* tenant | GUID (different from App ID) | The object you disable/audit for a rogue app |
| **Tenant ID** | The whole directory | GUID | Which org; `#EXT#`/foreign tenant = cross-tenant |
| **UPN** | A user | `alice@contoso.com` | Human-readable; 🔴 `#EXT#` = guest |

> 🔴 **The pivot in one line:** a token's `oid` (object ID) and `appid` claims tell you *exactly* which identity and which app made a call — even when display names are ambiguous or reused. Pivot on the **object ID**, not the display name.

## Tokens — The Credentials of the Cloud

Entra is **OAuth/OpenID Connect**. Access is granted with **tokens**, not passwords. Knowing the token types is the Microsoft equivalent of knowing `AKIA` vs `ASIA` in AWS — it tells you what was stolen and how you contain it.

| Token | What it is | Lifetime | 🔴 If stolen |
|-------|-----------|----------|-------------|
| **ID token** | Proof of *who* the user is (for the app to read) | Short | Low value alone — not used to call APIs |
| **Access token** | The bearer key that **calls an API** (Graph, Azure ARM) | **~60–90 min** | Works until expiry; **MFA already satisfied inside it** — replaying it bypasses MFA |
| **Refresh token** | Used to **silently get new access tokens** | **Up to 90 days** (rolling) | 🔴 Long-lived persistence — mint fresh access tokens without re-auth |
| **Primary Refresh Token (PRT)** | A device-bound super-refresh-token on Entra-joined machines | Long | 🔴 **Crown jewel** — SSO to everything; theft = full impersonation |
| **SAML token** | Federated sign-in assertion (from ADFS/IdP) | Short | 🔴 **Golden SAML** — forge tokens if the signing key is stolen |

> Physically, an access token is a **JWT (JSON Web Token)**: **Base64URL**-encoded, **three dot-separated segments** (`header.payload.signature`). The fastest "is this string a token?" tell — it visually starts with **`ey`**, the Base64 encoding of `{"` (the opening of the JSON header).

**The containment consequence — this is the key operational fact:**

> 🔴 **Disabling the account or resetting the password does NOT kill existing tokens.** An **access token** keeps working until it expires (~1 hr); a **refresh token** keeps minting new ones for up to 90 days. To actually cut a compromised session you must **revoke the user's refresh tokens** (`Revoke-MgUserSignInSession` / "Revoke sessions") **and** disable the account **and** (for a device) revoke/disable the device. This is the Microsoft equivalent of "the `ASIA` session keeps working after you kill the `AKIA` key." See **Entra → Sign-in Logs → Respond**.

**Token theft is the modern attack.** **AiTM (adversary-in-the-middle) phishing** proxies the real login page, so the victim completes MFA — and the attacker **captures the resulting token**, MFA already baked in. No password reuse, no MFA prompt on replay. See **Entra → Playbooks → Token Theft and AiTM**.

## Delegated vs Application Permissions

*How* an app is allowed to act decides how much damage it can do — and whether a user was even involved.

| | **Delegated** (on behalf of a user) | **Application** (app-only) |
|-|--------------------------------------|-----------------------------|
| **Acts as** | The signed-in user (app + user together) | **The app itself — no user** |
| **Ceiling** | The **lesser** of the app's grant and the user's own rights | Exactly what was granted, tenant-wide |
| **Consent** | User can consent (unless restricted) | 🔴 Requires **admin consent** |
| **Example** | App reads *this user's* mail (`Mail.Read` delegated) | App reads *everyone's* mail (`Mail.Read` application) |
| **🔴 Risk** | Phished consent to one user's data | **Admin-consented app = tenant-wide, MFA-less, silent access** |

> 🔴 **`Mail.Read`, `Mail.ReadWrite`, `Files.ReadWrite.All`, `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` granted as *application* permissions** are the ones that let an app own the tenant. Any **`Add app role assignment`** / **`Consent to application`** audit event granting these deserves immediate scrutiny.

## Reading a Sign-in Event

Every Entra sign-in carries these fields. They carry the investigation:

| Field | Tells you | Watch for |
|-------|-----------|-----------|
| `userPrincipalName` / `userType` | Who, and member vs guest | 🔴 `#EXT#` guest doing sensitive things |
| `appDisplayName` / `appId` | Which app they signed into | 🔴 unexpected app; legacy clients |
| `ipAddress` + location | From where | 🔴 impossible travel / new geo/ASN |
| `clientAppUsed` | Modern vs **legacy** auth | 🔴 `IMAP`, `POP`, `SMTP`, "Other clients" = **MFA-bypassing legacy auth** |
| `authenticationRequirement` | Was MFA required | 🔴 `singleFactorAuthentication` on sensitive access |
| `mfaDetail` / `authenticationDetails` | Was MFA satisfied, and how | 🔴 MFA "satisfied by claim in token" = possible token replay |
| `conditionalAccessStatus` | CA outcome | 🔴 `failure` / `notApplied` where it should apply |
| `status.errorCode` | Success (`0`) or why it failed | Bursts of `50126` = password spray; `50053` = smart-lockout |
| `riskState` / `riskLevel` | Identity Protection's verdict | 🔴 `atRisk`, `high` |
| `resourceDisplayName` | What they accessed (Graph, ARM, Exchange) | 🔴 `Microsoft Graph` from odd tooling |

## Interactive vs Non-Interactive Sign-ins

A crucial distinction Microsoft splits into **separate logs** — miss it and you miss half the attacker's activity:

| Log | What it records | Why it matters |
|-----|-----------------|----------------|
| **Interactive** | A **human** authenticating (typed password, did MFA) | The obvious sign-ins; what most people look at |
| **Non-interactive** | **Silent** re-auth using an existing token/refresh token (background app/client) | 🔴 Where **token replay** hides — a stolen token shows up here, not interactive |
| **Service principal** | An **app** signing in with its own secret/cert | 🔴 App-only attacks; a separate tab most teams never open |
| **Managed identity** | A **resource** getting a token | Managed-identity abuse |

> 🔴 **All four are separate views in the Entra portal (and separate Log Analytics tables: `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`).** A token-theft or app-abuse case that looks "quiet" in the interactive log is often loud in the non-interactive / SP logs. **Always check all four.**

## How Each Identity Appears in the Logs

Quick recognition guide — what you actually see:

| You see… | It's… |
|----------|-------|
| Interactive sign-in, UPN, MFA prompt, a browser | A **member user** (a person) |
| UPN containing `#EXT#`, `userType=Guest` | A **guest** from another tenant |
| Non-interactive sign-in, no MFA, an app name, from a token | A **user's app/session** (🔴 or a replayed token) |
| **Service principal** sign-in, an `appId`, secret/cert auth, no user | A **service principal** (an app acting as itself) |
| Service principal sign-in where app type = **Managed Identity** | A **managed identity** (an Azure resource) |
| Audit event `Add service principal credentials` | Someone **added a secret/cert to an app** 🔴 persistence |
| Audit event `Consent to application` / `Add app role assignment` | An **app was granted permissions** 🔴 possible illicit consent |
| Audit event `Add member to role` (Global Administrator) | A **role was granted** 🔴 privilege escalation |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Sign-in with `clientAppUsed` = IMAP/POP/SMTP/"Other clients" | **Legacy auth** — bypasses MFA |
| MFA "satisfied by claim in the token" from a new device/IP | Possible **token replay** (AiTM) |
| Service-principal sign-in from a new IP or doing new Graph calls | App credential theft / rogue app |
| `Add service principal credentials` on an existing app | **Persistence** — attacker's secret added to a trusted app |
| `Consent to application` / admin-consent to `Mail.Read`/`.All` app perms | **Illicit consent grant** — tenant-wide silent access |
| `Add member to role` → Global Administrator (esp. via a fresh account) | **Privilege escalation** |
| `Add member to role` outside PIM / without approval | Standing privilege / PIM bypass |
| A **guest** (`#EXT#`) granted a privileged role or app consent | External foothold escalating |
| Burst of failed sign-ins (`50126`) across many users | **Password spray** |
| Managed-identity token used from an unexpected IP | **IMDS/SSRF theft** — resource compromised |
| New **federated domain** / **Golden SAML** signing activity | Token forgery / federation backdoor |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| Member user | IAM user | Google user |
| Guest / B2B user | Cross-account principal | External identity |
| Service principal (enterprise app) | IAM role (assumed by app) | Service account |
| App registration | (app + IAM role) | OAuth client + SA |
| Managed identity | Instance profile / instance role | Attached service account |
| Access token (OAuth) | STS session (`ASIA`) | Short-lived SA token |
| Refresh token | (no direct equal) — long-lived SSO | Refresh token |
| Primary Refresh Token (PRT) | (no equal) | (no equal) |
| Application permission (app-only) | Role attached to a service | SA with domain-wide delegation |
| Entra role (Global Admin) | IAM admin / Org management acct | Org Admin |
| Revoke refresh tokens | Revoke role sessions | Revoke SA keys / sessions |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| How the tenant / subscriptions / two-RBAC-worlds fit together | **Microsoft → 00 Overview & Terminology** |
| Where these identities show up when they authenticate | **Entra → Sign-in Logs** |
| Directory changes (roles, apps, consent) | **Entra → Audit Logs** |
| Apps, service principals, OAuth consent in depth | **Entra → Applications & Service Principals** |
| Directory roles + PIM | **Entra → Roles & PIM** |
| Managed identities + IMDS token theft | **Azure → Managed Identities** |
| A phished-token intrusion | **Entra → Playbooks → Token Theft and AiTM** |
| A rogue-app intrusion | **Entra → Playbooks → Illicit Consent Grant** |
| Same human pivoting across clouds | **Cloud → 03 Cross-Cloud Correlation** |

## Resources

- Entra ID identity fundamentals — https://learn.microsoft.com/entra/fundamentals/whatis
- App vs service principal objects — https://learn.microsoft.com/entra/identity-platform/app-objects-and-service-principals
- Managed identities overview — https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/overview
- Access tokens / refresh tokens / lifetimes — https://learn.microsoft.com/entra/identity-platform/access-tokens
- Primary Refresh Token (PRT) — https://learn.microsoft.com/entra/identity/devices/concept-primary-refresh-token
- Delegated vs application permissions — https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview
- Sign-in logs schema — https://learn.microsoft.com/entra/identity/monitoring-health/concept-sign-ins
- Revoke user access / sessions — https://learn.microsoft.com/entra/identity/users/users-revoke-access
