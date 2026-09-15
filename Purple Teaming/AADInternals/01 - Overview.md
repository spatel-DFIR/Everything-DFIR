# AADInternals — Overview

> 🔴 **Red Flag Principle:** AADInternals' federation-backdoor technique (`ConvertTo-Backdoor`) doesn't generate a fresh signing certificate at attack time — it reuses one literal, hardcoded self-signed certificate (`any_sts.pfx`, subject/issuer `CN=hack.o365domain.org, O=Gerenios`, **SHA-1 `4B56E1F1B800243 59E34010D9AAB3CED9C67FF5E`**) that has shipped byte-identical inside every copy of the module's source since February 2018. Any Entra ID domain whose federation `SigningCertificate`/`NextSigningCertificate` matches that exact thumbprint has been backdoored by this specific tool — a 100%-specific IOC with zero false-positive risk, and the strongest single artifact in this whole page. It matters more than usual here because almost everything *else* AADInternals does authenticates as one of Microsoft's own first-party client apps ("Azure Active Directory PowerShell", "Microsoft Office"), so this certificate is one of the only truly tool-specific fingerprints available.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line / Cmdlet Quick Reference](#command-line--cmdlet-quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`Gerenios/AADInternals`](https://github.com/Gerenios/AADInternals), its `README.md`/`AADInternals.psd1` manifest, the GitHub API, the PowerShell Gallery listing, and the companion site [aadinternals.com](https://aadinternals.com/aadinternals/):

- **Author:** Dr. **Nestori Syynimaa** (`@DrAzureAD`), publishing under **Gerenios Ltd** (a Finnish company — repo metadata lists `C=fi, ST=Pirkanmaa`). The repo was created **October 25, 2018**. Syynimaa has a PhD and spent 20+ years as a researcher/CIO/consultant/university lecturer before the tool existed — the module's own description frames it as the output of "hours of reverse-engineering and debugging of Microsoft tools related to Entra ID," not a from-scratch attack framework.
- **License:** MIT (verified via the GitHub API's `license` field and `LICENSE.md`).
- **Distribution:** AADInternals ships **no compiled binaries and no GitHub Releases** (`gh api repos/Gerenios/AADInternals/releases` returns an empty array) — it is pure PowerShell source plus three bundled managed DLLs (`BouncyCastle.Crypto.dll` for crypto primitives, and Microsoft's own `Microsoft.Identity.Client.dll`/`Microsoft.IdentityModel.Abstractions.dll` for MSAL support). The supported install path is `Install-Module AADInternals` from the **PowerShell Gallery** (current published version `0.9.8`, matching the repo's `AADInternals.psd1`) or a plain `git clone`.
- **Current version:** `0.9.8`, last pushed to `master` **September 30, 2025**. The module's own copyright string reads `(c) 2018 - 2025 Nestori Syynimaa`.
- **A genuinely dual-use, disclaimed tool.** The module manifest's own `Description` field states it plainly: *"AADInternals allows you to export ADFS certificates, Azure AD Connect passwords, and modify numerous Azure AD / Office 365 settings not otherwise possible. DISCLAIMER: Functionality provided through this module are not supported by Microsoft and thus should not be used in a production environment. Use on your own risk!"* Legitimate uses documented on aadinternals.com include ADFS certificate export for disaster-recovery/migration scenarios and Azure AD Connect configuration troubleshooting — the same primitives that make it an attack tool also make it one of the few ways to recover from certain hybrid-identity misconfigurations without Microsoft support.
- **Naming convention:** the module manifest sets `DefaultCommandPrefix = 'AADInt'`. Every function is written internally without a prefix (`Get-AccessToken`, `Invoke-ReconAsOutsider`) but is *imported* with `AADInt` automatically inserted (`Get-AADIntAccessToken`, `Invoke-AADIntReconAsOutsider`) — this is a standard PowerShell manifest mechanism, not per-function renaming, and every cmdlet name in this repo's AADInternals pages uses the real, as-imported `AADInt`-prefixed form.
- **Tracked as a named threat-actor tool.** AADInternals has its own MITRE ATT&CK Software entry, **[S0677](https://attack.mitre.org/software/S0677/)**, mapped to 22 distinct techniques. MITRE's page cites two tracked intrusion sets using it: **APT29** (per Microsoft threat intelligence) and **Storm-0501**, which Microsoft's own reporting describes using AADInternals specifically "to create a back door within the victim tenant, thus allowing for the impersonation of any user in the organization and bypassing MFA" during a September 2024 hybrid-cloud ransomware campaign — a description that matches the `ConvertTo-Backdoor` federation-backdoor mechanic covered below almost verbatim.
- **The author now works for the vendor whose product the tool attacks.** Per Syynimaa's own conference bio (HIP Conference speaker profile, corroborated by his Sessionize/LinkedIn profiles), he **joined Microsoft in early 2024 as a Principal Identity Security Researcher on the Microsoft Threat Intelligence Center**, while continuing to maintain AADInternals as a personal/independent project. This is worth flagging for an analyst: the same MITRE ATT&CK page that credits Microsoft's own threat intel with attributing AADInternals to APT29 and Storm-0501 is, functionally, reporting on a tool its author now helps track professionally.
- **Foundational research posts** (aadinternals.com), cited throughout this and the following files: ["How to create a backdoor to Azure AD - part 2: Seamless SSO and Kerberos"](https://aadinternals.com/post/kerberos/) and ["Azure AD Seamless SSO allows enumerating tenant users"](https://aadinternals.com/post/desktopsso/) — the two posts that originated the Desktop SSO abuse chain this page's red flag is built on.

## How It Works

AADInternals is not one client talking to one API — it's roughly **230 functions** spread across ~35 script files, each one a thin, source-verified wrapper around a *different* Microsoft backend, several of them entirely undocumented by Microsoft. The unifying mechanic is OAuth2's classic `resource` parameter: one access token is only valid for one audience, so the module's `AccessToken.ps1` file alone defines **30 separate `Get-AccessTokenFor*` functions**, each requesting a token for a different resource/client-ID pair against the same `https://login.microsoftonline.com/<tenant>/oauth2/token` endpoint. Whichever resource the token is minted for determines which backend will accept it:

| Resource (token audience) | Backend it unlocks | Documented by Microsoft? |
|---|---|---|
| `https://graph.windows.net` | **Azure AD Graph** — the legacy directory API (`GraphAPI.ps1`, 15 functions) | Yes, historically — but Microsoft's own retirement notice states Azure AD Graph was **fully retired August 31, 2025**. Whether `graph.windows.net`-audienced tokens still mint/work as of this writing is an **open question this research could not confirm live** — flagged rather than asserted either way. |
| `https://graph.windows.net` (same audience, different physical endpoint) | The legacy **SOAP "Provisioning API"** at `provisioningapi.microsoftonline.com/provisioningwebservice.svc` — the same backend the retired `MSOnline` PowerShell module used. This is `ProvisioningAPI.ps1`, at **133 functions the single largest file in the module** (`Get-Users`, `Set-User`, `Reset-UserPasswordByUpn`, `Set-CompanyDirSyncFeature`, etc.) | No — this is an internal SOAP service with no public REST documentation; reverse-engineered from the legacy Office 365 admin center's own network traffic. |
| `https://graph.microsoft.com` | Modern **Microsoft Graph** (`MSGraphAPI.ps1`, 31 functions — `Get-AzureSignInLog`, `Get-AzureAuditLog`, rollout-policy manipulation, etc.) | Yes, current and fully documented. |
| `https://proxy.cloudwebappproxy.net/registerapp` | The **Application Proxy / Pass-through Authentication / Desktop SSO registration API** at `https://<tenantId>.registration.msappproxy.net/register/*` — used by `Get/Set-DesktopSSO`, `Set-PassThroughAuthenticationEnabled` | No — reverse-engineered from the Azure AD Connect agent's own registration traffic. |
| (n/a — binary WCF, not REST) | The **Azure AD Connect sync engine's own web service** (`AzureADConnectAPI.ps1`, 24 functions incl. `Reset-ServiceAccount`, `Set-UserPassword`, `Get-SyncObjects`) — a binary, WCF-framed protocol (`Create-SyncEnvelope`/`Call-ADSyncAPI`/`BinaryToXml`) talking to an `aadsync`-branded server hostname | No — this is the on-prem Azure AD Connect server's own internal sync protocol. |

This "undocumented internal API" angle is the tool's own stated reason for existing — the module description literally says it "utilises several internal features of Azure Active Directory, Office 365, and related admin tools" not otherwise exposed by `Az`, `AzureAD`, or `Microsoft.Graph`.

**Token handling is centralized in one function, `Get-AccessToken`,** which every `Get-AccessTokenFor*` wrapper ultimately calls. It supports interactive/MSAL, username+password (ROPC, `-Credentials`), device-code flow, refresh-token reuse, and three attack-specific exchange modes: `-PRTToken` (trade a forged Primary Refresh Token for a resource-scoped access token), `-KerberosTicket` (trade a forged Desktop SSO Kerberos ticket for a token — see below), and `-SAMLToken` (trade a forged federation SAML assertion for a token). Tokens can be cached to AADInternals' own on-disk cache **or**, via `-SaveToMgCache`, written directly into the real Microsoft Graph PowerShell SDK's own token cache — letting a stolen/forged token hide inside a legitimate tool's persisted state rather than a bespoke AADInternals artifact.

**Client-ID reuse is a deliberate blending mechanic, not an oversight.** Nearly the entire `AccessToken.ps1` file authenticates using one of two of Microsoft's own genuine first-party application IDs rather than a custom AADInternals app registration:

| Client ID | Real Microsoft app it impersonates | Used for |
|---|---|---|
| `1b730954-1685-4b74-9bfd-dac224a7b894` | **"Azure Active Directory PowerShell"** | Azure AD Graph, MS Graph, Office Apps, AAD device-join tokens — the majority of the module |
| `d3590ed6-52b3-4102-aeff-aad2292ab01c` | **"Microsoft Office"** | Admin portal / AAD IAM API tokens |
| `cb1056e2-e479-49de-ae31-7812af012ed8` | Application Proxy registration client | PTA/Desktop SSO enable-disable, registration API |

Because Entra sign-in logs record `AppDisplayName` from the **client ID**, not the calling tool, a tenant that already tolerates any legitimate Azure AD PowerShell or Office 365 desktop usage will see AADInternals traffic labeled identically to that legitimate traffic — see `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`, whose own "new/unusual tooling in `AppDisplayName`" red flag is specifically the signal this client-ID reuse is built to defeat.

### Unauthenticated tenant recon (`Invoke-ReconAsOutsider`)

Before any credential is ever supplied, `Invoke-AADIntReconAsOutsider -DomainName company.com` chains three public, **unauthenticated** endpoints to build a detailed tenant profile with zero logged sign-in attempts:

```
Attacker (no credentials at all)                         Microsoft public endpoints
─────────────────────────────────                         ───────────────────────────
1. GET  login.microsoftonline.com/<domain>/       ──────▶  Confirms the domain is a real
        .well-known/openid-configuration                    Entra tenant; returns tenant ID,
                                                              region, issuer, MS Graph host

2. POST login.microsoftonline.com/common/         ──────▶  GetCredentialType (the same call
        GetCredentialType   {"username":"nn@domain"}         the O365 login page itself makes)
                                                    ◀──────  EstsProperties.DesktopSsoEnabled,
                                                              Credentials.HasCertAuth (CBA),
                                                              per-domain federation/managed type

3. POST login.microsoftonline.com/GetUserRealm.srf ─────▶  Legacy realm lookup — federation
        (Get-UserRealmV2)                                   brand name, ADFS STS hostname
                                                    ◀──────  (if federated: sts.company.com)

4. (optional -GetRelayingParties) GET the ADFS      ──────▶ idpinitiatedsignon.aspx page,
   server's idpinitiatedsignon.aspx                          parsed for every trusting-party
                                                               name registered on that ADFS —
                                                               a same-org application inventory
                                                               with no auth at all
```

The output includes the tenant ID/brand/region, per-domain DNS/MX/SPF/DMARC/DKIM/MTA-STS posture, whether Desktop SSO is enabled, whether the domain uses **Microsoft Defender for Identity** (a separate helper, `GetMDIInstance`, probes for the tenant's MDI sensor hostname), whether Azure AD cloud sync is in use (probed by checking if the well-known `ADToAADSyncServiceAccount@<tenant>` account exists), and whether Certificate-Based Authentication is enabled — **all before a single authentication attempt occurs.** This matters directly for `04 - Target Evidence.md`: none of steps 1–4 produce an Entra sign-in log or audit log entry, because none of them is a sign-in.

### Desktop SSO / Kerberos ticket forging — the mechanic behind the red flag

`AZUREADSSOACC$` is a real computer account Azure AD Connect creates in **on-prem Active Directory** when Desktop SSO (Seamless SSO) is enabled. Its Kerberos key is also registered with Azure AD, so a domain-joined Windows client can silently authenticate to Azure AD by presenting a Kerberos service ticket for `HTTP/autologon.microsoftazuread-sso.com`, encrypted with that shared secret — Azure AD trusts the ticket because only a real on-prem DC (or the holder of that one shared secret) could have produced it.

AADInternals implements the **entire Kerberos PAC and ticket structure itself, in pure PowerShell byte arrays** (`Kerberos.ps1`'s `New-PAC`/`New-KerberosTicket`, ~960 lines) rather than calling any Windows Kerberos API — it needs no domain membership, no `klist`, and no LSASS interaction of any kind:

```
Attacker (anywhere, no on-prem or cloud session)          Azure AD (autologon.microsoftazuread-sso.com)
──────────────────────────────────────────────            ───────────────────────────────────────────────
New-AADIntKerberosTicket -Hash <AZUREADSSOACC$ NTHash>
                          -Sid <target user's SID>
   1. Hand-builds a MS-PAC LOGON_INFO structure
      naming the target user's SID, no group
      membership validation performed
   2. Encrypts/signs it as a KRB-CRED with the
      supplied AZUREADSSOACC$ key material          ─────▶  Decrypts with its own copy of the
                                                               same AZUREADSSOACC$ key — cannot
                                                               distinguish this from a genuine
                                                               on-prem-issued ticket
                                                       ◀─────  Full authenticated session for the
                                                               named user, MFA/Conditional-Access
                                                               posture applied as if this were a
                                                               real Seamless SSO sign-in
```

The `-Hash` (AZUREADSSOACC$'s NT hash) is normally obtained **entirely on-prem**, via a DCSync-capable tool against the `AZUREADSSOACC$` computer object (this repo's `Mimikatz/lsadump (DCSync)/` covers the mechanics) — meaning the whole chain, from credential theft to a working cloud session for *any* user, never needs Global Administrator or any cloud-side access at all. A second, cloud-side path exists too: with a Global Admin token, `Set-AADIntDesktopSSO -Password X` pushes a **new, attacker-chosen** password into Azure AD's registered copy of AZUREADSSOACC$'s key (the function separately prompts whether to also sync it into on-prem AD — declining leaves the two sides desynced, which is itself a detectable state). Both paths converge on the same `New-KerberosTicket` forging primitive.

### The federation backdoor (`ConvertTo-Backdoor`) — this page's red flag, in detail

`ConvertTo-AADIntBackdoor -DomainName company.com` (Global Admin token required) either converts a Managed domain to Federated, or — if already Federated — adds a **`NextSigningCertificate`** to the domain's federation settings via `Set-DomainFederationSettings`. In both cases the certificate used is `$any_sts`, a **hardcoded X.509 certificate literal embedded directly in `FederatedIdentityTools.ps1`'s source** (self-signed, `CN=hack.o365domain.org, O=Gerenios`, valid Feb 2018–Feb 2028), whose matching private key ships as `any_sts.pfx` (password-less) alongside the module. Once Azure AD trusts that certificate for the domain, `New-SAMLToken`/`Open-Office365Portal` can forge a SAML assertion for **any user in the tenant**, sign it with the shipped private key, and log in — a Golden-SAML-equivalent backdoor that survives password resets and doesn't touch MFA at all, because federated sign-in bypasses Entra's own MFA/Conditional Access enforcement by design (the IdP — now the attacker — is trusted to have already done it). The `IssuerUri` is randomized per run (`http://any.sts/<8-hex>`), but the **signing certificate itself is not** — it is the exact same file, and therefore the exact same thumbprint, in every install of AADInternals since 2018.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| OAuth 2.0 / Azure AD v1 endpoint | `login.microsoftonline.com/<tenant-or-common>/oauth2/token` — ROPC, device code, refresh-token, and three forged-credential exchange modes (PRT, Kerberos ticket, SAML token) |
| Azure AD Graph (legacy) | `graph.windows.net` REST API — **officially retired by Microsoft August 31, 2025**; current functional status of AADInternals' Azure-AD-Graph-dependent functions is unverified as of this research |
| Microsoft Graph (modern) | `graph.microsoft.com` — documented, current, used for read-heavy recon (`MSGraphAPI.ps1`) |
| Legacy Provisioning API (SOAP) | `provisioningapi.microsoftonline.com/provisioningwebservice.svc` — the same backend the retired `MSOnline` module used; 133 functions, audienced with a `graph.windows.net` token despite hitting a different host |
| Application Proxy / PTA / Desktop SSO registration | `https://<tenantId>.registration.msappproxy.net/register/*` — undocumented, reverse-engineered from the Azure AD Connect agent |
| Azure AD Connect sync engine API | Binary WCF protocol against the on-prem sync server (`Reset-ServiceAccount`, `Set-UserPassword`, `Get-SyncObjects`) |
| Kerberos (hand-built, not a real KDC exchange) | Raw PAC/KRB-CRED construction and RC4/AES encryption for Desktop SSO ticket forging (`Kerberos.ps1`) — no AS-REQ/TGS-REQ ever touches a real KDC |
| SAML 1.1/2.0 and WS-Federation | Federation-backdoor SAML token forging (`New-SAMLToken`/`New-SAML2Token`/`New-WSFedResponse`) against a domain converted to Federated auth |
| Certificate-Based Authentication (CBA) | `CBA.ps1` — portal access-token retrieval using a client certificate instead of a password |
| Exchange Online / SharePoint Online / Teams / OneDrive / OneNote | Resource-specific token acquisition + light REST/CSOM calls for each service's own API surface |

## Command-Line / Cmdlet Quick Reference

All names below are the real, **`AADInt`-prefixed** exported cmdlet names (per `DefaultCommandPrefix` in the manifest), verified against source. This is a representative slice of ~230 functions, grouped by role — see `02 - Hands-On Use Cases.md` for full runnable examples of each.

**Recon (no or minimal credentials)**

| Cmdlet | Plain-English meaning |
|---|---|
| `Invoke-AADIntReconAsOutsider -DomainName <domain>` | Unauthenticated tenant profile: tenant ID/brand/region, DNS posture, Desktop SSO/MDI/cloud-sync/CBA status |
| `Invoke-AADIntUserEnumerationAsOutsider -UserName <list>` | Bulk-check which usernames exist in the tenant via `GetCredentialType` |
| `Invoke-AADIntReconAsGuest` / `Invoke-AADIntReconAsInsider` | Deeper recon once authenticated as a guest or a normal member user (MS Graph reads) |
| `Invoke-AADIntPhishing` | Sends a device-code or OAuth consent-phishing email to a target list |

**Access tokens**

| Cmdlet | Plain-English meaning |
|---|---|
| `Get-AADIntAccessToken -ClientId <id> -Resource <uri>` | General-purpose token request for an arbitrary client/resource pair |
| `Get-AADIntAccessTokenForAADGraph` / `-ForMSGraph` / `-ForEXO` / `-ForSPO` / `-ForTeams` / `-ForOneDrive` / etc. | Pre-built wrappers requesting a token for one specific Microsoft service (30 total) |
| `Get-AADIntAccessTokenUsingDeviceCode` | Device-code flow — no password prompt, phishable via `Invoke-Phishing` |
| `Get-AADIntAccessTokenWithRefreshToken` | Mint a fresh access token from a previously stolen/saved refresh token |
| `Get-AADIntAccessTokenUsingIMDS` | Steal a managed-identity token from Azure IMDS (`169.254.169.254`) on a compromised Azure VM/resource |
| `Get-ESTSAUTHCookie` / `Unprotect-EstsAuthPersistentCookie` | Extract/decrypt the browser's persistent Entra sign-in session cookie |

**PRT / device identity**

| Cmdlet | Plain-English meaning |
|---|---|
| `Join-AADIntDeviceToAzureAD` | Register a fake/rogue device object in Azure AD, obtaining a device certificate |
| `Get-AADIntUserPRTKeys` | Derive a Primary Refresh Token + session key for a (real or newly joined) device |
| `New-AADIntUserPRTToken` | Forge a signed PRT JWT from stolen/derived refresh-token+session-key material |
| `New-AADIntBulkPRTToken` | Forge a Bulk PRT (BPRT) — used for mass/kiosk device provisioning, a DoS/abuse vector of its own |
| `Set-AADIntDeviceTransportKey` / `Set-AADIntDeviceWHfBKey` | Overwrite a device's transport key or Windows Hello for Business key material |

**Desktop SSO / Kerberos**

| Cmdlet | Plain-English meaning |
|---|---|
| `Get-AADIntDesktopSSO` | Check whether Desktop SSO is enabled and for which domains (Global Admin token) |
| `Set-AADIntDesktopSSO -Password <p>` | Push a new AZUREADSSOACC$ password into Azure AD's registered copy (cloud-side backdoor path) |
| `New-AADIntKerberosTicket -Hash <NT hash> -Sid <target SID>` | Forge a Desktop SSO Kerberos ticket for any user, given the AZUREADSSOACC$ key |
| `Reset-AADIntServiceAccount -ServiceAccount <name>` | Create or reset the Azure AD Connect **sync** service account's password (a distinct, DirectorySynchronizationAccount-privileged backdoor) |

**Federation / SAML backdoor**

| Cmdlet | Plain-English meaning |
|---|---|
| `ConvertTo-AADIntBackdoor -DomainName <domain>` | Convert/extend a domain's federation trust to accept AADInternals' hardcoded signing certificate |
| `New-AADIntSAMLToken` / `New-AADIntSAML2Token` | Forge a SAML assertion for an arbitrary user, signed with the backdoor (or a stolen ADFS) certificate |
| `Open-AADIntOffice365Portal` | Launch a browser session authenticated with a forged SAML token |
| `Find-AADIntBackdoor` | Check a domain's current federation settings for a known backdoor certificate |
| `Export-AADIntADFSCertificates` (`ADFS.ps1`) | Export ADFS token-signing/decryption certificates from a compromised ADFS server |

**Admin/directory manipulation (legacy Provisioning API)**

| Cmdlet | Plain-English meaning |
|---|---|
| `Set-AADIntUserMFA -UserPrincipalName <upn> -State Disabled` | Directly disable legacy **per-user** MFA (not Conditional-Access MFA) via the SOAP Provisioning API |
| `Reset-AADIntUserPasswordByUpn` | Reset an arbitrary user's password |
| `Add-AADIntRoleMembers` / `Add-AADIntRoleScopedMembers` | Grant a directory role (incl. Global Administrator) to an account |
| `Set-AADIntCompanySettings` / `Set-AADIntPasswordPolicy` | Tenant-wide configuration changes |

## Quick Use-Case List

- Fully unauthenticated tenant recon — tenant ID/brand/region, DNS/mail-security posture, Desktop SSO/MDI/cloud-sync/CBA status, all with zero logged sign-ins
- Bulk username/tenant-membership enumeration (internal and guest accounts) via `GetCredentialType`
- Reading an ADFS server's public relaying-party list (application inventory) with no authentication
- Acquiring access tokens via ROPC, device code (phishable), interactive MSAL, or refresh-token replay, for any of ~30 different Microsoft services
- Extracting and decrypting a browser's persistent ESTSAUTH sign-in cookie
- Stealing an Azure managed-identity token from IMDS on a compromised Azure resource
- Registering a rogue/fake device object in Azure AD and deriving a usable PRT for it
- Forging a Primary Refresh Token (PRT) JWT from stolen refresh-token + session-key material
- Forging a Bulk PRT (BPRT) for mass-provisioning abuse
- Overwriting a device's transport key or Windows Hello for Business key
- Extracting the AZUREADSSOACC$ Kerberos key on-prem (via a DCSync-capable tool) and forging a Desktop SSO ticket to log in as **any** cloud user — full MFA bypass, no cloud access ever required
- Pushing a new, attacker-known AZUREADSSOACC$ password into Azure AD directly from a Global Admin session (cloud-side Desktop SSO backdoor path)
- Resetting/creating the Azure AD Connect **sync service account** password from the cloud side — a separate, DirectorySynchronizationAccount-privileged backdoor
- Converting a domain to Federated auth (or extending an existing federation trust) with AADInternals' hardcoded signing certificate, then forging SAML tokens to impersonate any user indefinitely
- Exporting ADFS token-signing/decryption certificates from a compromised on-prem ADFS server for offline SAML forging
- Disabling a specific user's legacy per-user MFA directly via the SOAP Provisioning API
- Resetting an arbitrary user's password or granting directory roles (incl. Global Administrator) via the legacy Provisioning API
- Dumping Azure AD Connect sync configuration and credentials from a compromised AAD Connect server
- Sending device-code or OAuth-consent phishing emails to a target list
- A chained on-prem-to-cloud pivot workflow: Mimikatz DCSync on-prem → AZUREADSSOACC$ hash → AADInternals ticket forge → full cloud tenant access, all without ever touching a cloud credential

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell (Windows PowerShell 5.1 or PowerShell 7+) | Installed via `Install-Module AADInternals` (PowerShell Gallery) or `git clone` — no compiled binary exists |
| No credential at all | Sufficient for `Invoke-ReconAsOutsider`, user enumeration, and ADFS relaying-party discovery |
| Any valid user credential (no special role) | Sufficient for `Invoke-ReconAsGuest`/`-AsInsider` (MS Graph reads), most `Get-AccessTokenFor*` calls |
| A domain-joined AD account with DCSync rights (on-prem, not cloud) | Sufficient to obtain AZUREADSSOACC$'s NT hash and forge Desktop SSO tickets for **any** cloud user — this path needs no cloud credential whatsoever |
| Global Administrator (cloud) | Required for `Set-AADIntDesktopSSO`, `ConvertTo-AADIntBackdoor`, `Reset-AADIntServiceAccount`, and most legacy Provisioning API write functions (`Set-UserMFA`, `Reset-UserPasswordByUpn`, `Add-RoleMembers`) |
| Local admin/console access to an on-prem ADFS server | Required for `Export-ADFSCertificates` |
| Code execution on a compromised Azure resource with a managed identity | Required for `Get-AccessTokenUsingIMDS` |
| Domain-joined device or a registerable device identity | Required for the PRT-derivation family (`Get-UserPRTKeys`, `Join-DeviceToAzureAD`) |
