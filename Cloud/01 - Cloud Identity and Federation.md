# Cloud Identity and Federation

The first question in any cloud incident is **"who did this?"** — and in every cloud the answer is subtler than a username. This note is the **cross-provider decoder ring**: it lines up the identity types across AWS, Entra/Azure, and Google so that once you can read a `userIdentity` block, a `SignInLog`, and a `principalEmail` field, you can read all three. It then covers **federation** — the wiring that lets one identity span clouds — which is where modern intrusions live.

For the provider specifics, use each platform's `01`: **AWS 01 IAM & Identities**, **Microsoft 01 Entra ID & Identities**, **Google 01 Google Identities**. This note is the layer that connects them.

## Contents

- [The Identity Types, Lined Up](#the-identity-types-lined-up)
- [Human vs Workload — The Core Split](#human-vs-workload--the-core-split)
- [Long-Lived vs Temporary Credentials](#long-lived-vs-temporary-credentials)
- [How Each Reads in the Logs](#how-each-reads-in-the-logs)
- [Federation — One Identity, Many Clouds](#federation--one-identity-many-clouds)
- [Workload Identity Federation (Keyless)](#workload-identity-federation-keyless)
- [Following an Identity Across the Boundary](#following-an-identity-across-the-boundary)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Identity Types, Lined Up

Every cloud has the same four categories. Learn the row, not the cell:

| Category | AWS | Entra / Azure | Google |
|----------|-----|---------------|--------|
| **Superuser** | Root user | Global Administrator | Super Admin / Org Admin |
| **Human** | IAM user (or federated user) | Entra user (member/guest) | Google user |
| **Workload (app/service)** | IAM role / instance profile | Service principal / **managed identity** | Service account |
| **Temporary session** | Assumed-role session (`ASIA`) | OAuth access token | Short-lived SA token |

> The two you spend most time on everywhere: the **human that got phished/leaked** (entry) and the **workload identity they pivot into** (blast radius). Cloud attacks are a chain *between* these.

## Human vs Workload — The Core Split

| | Human identity | Workload identity |
|-|----------------|-------------------|
| **Who authenticates** | A person (password + MFA, or SSO) | Code/a machine (a role, SP, MI, or SA) |
| **Credential** | Password/MFA, or a federated token | A role to assume, a client secret/cert, or an SA key/impersonation |
| **In logs** | Interactive sign-in; a named user | Non-interactive; a role/SP/SA principal, often with a service `userAgent` |
| **Attacker interest** | The way *in* (phish, spray, token theft) | The way *up and across* (privileged, often over-permissioned) |

> 🔴 A **workload identity acting like a human** (a service account doing interactive-looking console actions, an app role enumerating IAM) — or a **human credential used by automation** — is one of the most reliable anomaly signals in any cloud.

## Long-Lived vs Temporary Credentials

The credential *lifetime* decides how you contain it — and it's the same idea in each cloud:

| | Long-lived | Temporary |
|-|-----------|-----------|
| **AWS** | Access key `AKIA…` (never expires) | STS `ASIA…` session (15 min–36 h) |
| **Azure** | SP client secret / certificate | OAuth access token (~1 h) + refresh token |
| **Google** | SA key (JSON, never expires) | Impersonation / short-lived token (~1 h) |
| **Contain by** | Delete/rotate the key/secret | **Revoke the session** — deleting the source key doesn't stop an already-minted token |

> 🔴 **The universal containment trap:** disabling the long-lived credential does **not** kill a temporary session already minted from it. AWS: revoke the role's sessions. Azure: revoke refresh tokens / sign-ins. Google: the short-lived token runs until expiry — remove the grant and disable the SA. Always contain *both*.

## How Each Reads in the Logs

The field that carries "who" in each provider — memorize these three shapes:

| Provider | Log | The "who" field | Tells you |
|----------|-----|-----------------|-----------|
| **AWS** | CloudTrail | `userIdentity.type` + `.arn` | `Root` / `IAMUser` / `AssumedRole`; `assumed-role/<role>/<session>` |
| **Entra/Azure** | Sign-in & Audit logs | `identity` / `appId` / `servicePrincipalId` | user UPN vs app/SP; interactive vs non-interactive |
| **Google** | Cloud Audit Logs | `authenticationInfo.principalEmail` | user@ vs `...@...gserviceaccount.com`; `serviceAccountKeyName`, `serviceAccountDelegationInfo` |

**Twin tells worth knowing across clouds:**

- **AWS `AKIA` vs `ASIA`** (long-term key vs temp session) ≈ **Google SA-key vs impersonation token** ≈ **Azure SP-secret vs OAuth token**. Same distinction, three vocabularies.
- **A service acting on its own:** AWS `invokedBy: *.amazonaws.com` ≈ Google `principalEmail` = a service agent ≈ Azure a first-party/managed-identity principal.
- **MFA satisfied?** AWS `sessionContext.attributes.mfaAuthenticated` ≈ Entra `authenticationDetails` / MFA result ≈ Google login `is_second_factor`.

## Federation — One Identity, Many Clouds

Federation lets an identity in one directory authenticate to another system. It's why "who?" often crosses a boundary — and why an IdP compromise is catastrophic.

| Pattern | What it bridges | How it appears |
|---------|-----------------|----------------|
| **SAML/OIDC SSO to a cloud** | An IdP (Entra, Okta, Google, Ping) → AWS/Azure/GCP | AWS `AssumeRoleWithSAML`/`WebIdentity`, `AWSReservedSSO_*` roles; Entra federated sign-in; Google SAML login |
| **Entra as IdP for AWS** | Entra users → AWS via IAM Identity Center | AWS SSO sign-in maps to an Entra user upstream |
| **Google Workspace as IdP** | Google users → SAML apps / GCP | Workspace login audit → downstream app |
| **Cross-tenant / guest (B2B)** | External users into a tenant | Entra **guest** (`#EXT#`) principals |

> 🔴 **The investigative consequence:** the cloud log often stops at the *federated role/permission-set* (e.g. `AWSReservedSSO_Admin_abc`). To find the **actual human**, pivot to the **IdP sign-in log** (Entra Sign-in, Okta System Log, Google Login audit). CloudTrail alone can't name them.

## Workload Identity Federation (Keyless)

The modern, keyless way for external workloads (CI/CD, other clouds) to get cloud credentials **without a stored secret** — by presenting an OIDC token. Powerful and increasingly abused:

| Provider | Mechanism | Trust is defined by |
|----------|-----------|---------------------|
| **AWS** | `AssumeRoleWithWebIdentity` (IAM OIDC provider) | The role's **trust policy** (issuer + subject conditions) |
| **Azure** | **Federated credentials** on an app/MI | The app's federated-credential subject/issuer |
| **Google** | **Workload Identity Federation** (pool + provider) | The pool provider's **attribute conditions** |

> 🔴 **The classic misconfig, in every cloud:** an over-broad trust condition — e.g. a GitHub OIDC role that trusts *any* repo instead of `repo:org/name:ref:...`. That lets **anyone's pipeline** mint your cloud credentials. This is a live, common attack path (see AWS **CI/CD OIDC Trust Abuse**). When you see `AssumeRoleWithWebIdentity` / federated-credential use, **read the subject claim** and confirm it's scoped to your workload.

## Following an Identity Across the Boundary

When an actor crosses from one identity/cloud to the next, tie the hops together with fields that **survive** the jump:

| Anchor | Use it to link |
|--------|----------------|
| **Email / UPN / principalEmail** | The same human across IdP and each cloud |
| **IdP session / correlation ID** | An SSO login to the downstream cloud actions |
| **Source IP + ASN** | Same actor across providers within a window |
| **`userAgent` / tooling** | A distinctive SDK/tool string reused across clouds |
| **Timing** | Tight sequences (login → assume → act) across logs |
| **`sourceIdentity` (AWS)** | Propagates through role chains — best single anchor when set |

→ The full method is **03 Cross-Cloud Correlation**.

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Superuser (Root / Global Admin / Super Admin) doing anything | Should be near-silent; top-tier signal |
| Workload identity performing human-style/privileged actions | Stolen SA/role/SP creds in use |
| Temp session with no matching mint event you can find | Minted outside your logging scope — widen window/region/IdP |
| Federated sign-in from new geo/IP into a privileged role | SSO/IdP compromise |
| `AssumeRoleWithWebIdentity` / federated credential with an unexpected subject | Over-broad workload-federation trust abused |
| New long-lived credential on an identity that shouldn't need one | Persistence (extra key/secret/SA key) |
| MFA `false` on a sensitive action | MFA bypass or gap |
| Guest/external (`#EXT#`) principal with elevated access | B2B abuse path |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| The shared model these identities live in | **00 Cloud Fundamentals** |
| Correlating one actor across clouds | **03 Cross-Cloud Correlation** |
| AWS specifics (AKIA/ASIA, role chains) | **Amazon/AWS → 01 IAM & Identities** · **STS** |
| Microsoft specifics (tokens, PRT, SP vs MI) | **Microsoft → 01 Entra ID & Identities** · **Managed Identities** |
| Google specifics (SA key vs impersonation, DWD) | **Google → 01 Google Identities** · **Service Accounts** |
| CI/CD OIDC trust abuse in practice | **Amazon/AWS → Playbooks → CICD OIDC Trust Abuse** |
| The service-name equivalents | **06 Cloud Service Equivalents** |

## Resources

- MITRE ATT&CK: Valid Accounts – Cloud Accounts (T1078.004) — https://attack.mitre.org/techniques/T1078/004/
- AWS federation & AssumeRole — https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers.html
- Entra workload identity federation — https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation
- Google Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
