# GraphRunner — Overview

🔴 **Red Flag:** A PowerShell post-compromise toolkit that uses stolen or compromised Microsoft Graph access tokens to enumerate, exfiltrate, and modify tenant data (email, SharePoint, Teams, user attributes, applications) — zero network calls to the victim organization, all traffic appears as legitimate Microsoft Graph API queries from the authenticated user's own account.

## History

**GraphRunner** is a PowerShell-based post-exploitation toolkit for abusing the Microsoft Graph API, authored by Justin Busk (dafthack) and maintained on GitHub at [`dafthack/GraphRunner`](https://github.com/dafthack/GraphRunner). 

- **First release:** August 15, 2023.
- **Current status:** Actively maintained (last commit April 9, 2026).
- **Language:** PowerShell (no external library dependencies).
- **License:** Not explicitly stated in repo; examination of source suggests research/educational use model.

GraphRunner emerged as a result of increased operator interest in Graph API abuse for post-compromise operations — it packages a comprehensive set of modules for token acquisition, tenant reconnaissance, data exfiltration (email, Teams, SharePoint, OneDrive), and persistence (application registration, security group cloning, conditional access policy dumping). It explicitly assumes the operator has already broken in and holds valid (stolen/phished/forged) credentials or tokens; it is **not** an initial-access tool.

## How It Works

GraphRunner operates across three delivery/interaction modes, all centered on the Microsoft Graph API (OAuth 2.0 / OpenID Connect):

### Core Architecture

1. **PowerShell module** (`GraphRunner.ps1`, ~3000 lines) — the operational engine
   - Imports as a single PowerShell module; no external dependency installation required
   - ~85 distinct functions covering token management, reconnaissance, data pillaging, and persistence
   - All Graph API calls made via `Invoke-RestMethod` over HTTPS to `https://graph.microsoft.com/v1.0` and `https://graph.microsoft.com/beta`

2. **HTML GUI** (`index.html`, ~900 lines) — browser-based interface
   - Accepts a valid access token from the PowerShell module
   - Provides point-and-click enumeration/exfiltration of email, Teams, SharePoint, files, users, apps
   - Runs client-side only (no server-side component); requires the token to be supplied by the operator

3. **PHP redirector** (`redirect.php`) — OAuth flow harvesting
   - Accepts authorization codes from a victim's OAuth consent flow
   - Designed to be hosted on an operator-controlled domain during a consent-grant attack (T1528)

### Token Acquisition Paths

GraphRunner supports multiple methods for obtaining valid Microsoft Graph access tokens:

- **Device Code Flow** (`Invoke-CAPSDeviceCodeAuth`) — interactive, asks user to visit and sign in on `microsoft.com/devicelogin`
- **Refresh Token Abuse** (`Invoke-CAPSRefreshTokenAuth`) — reuses a captured/exfiltrated refresh token to obtain a fresh access token
- **Compromised Credentials** (`Get-GraphTokens`) — prompts for username/password, performs ROPC (Resource Owner Password Credential) flow via Azure AD token endpoint
- **Delegated Token from Another User** (via the PowerShell module's graph functions) — if the current user has mailbox access to another user, their Graph token can enumerate that user's data

### API Endpoints and Data Access

Once the operator holds a valid access token, GraphRunner's modules make requests to these core Microsoft Graph endpoints (and many others):

| Endpoint | Purpose | Capability |
|----------|---------|-----------|
| `/v1.0/me` | Get current user info | Identity + mailbox address |
| `/v1.0/me/mailFolders` | List user's mail folders | Enumerate all mail organization |
| `/v1.0/me/messages` | Search/export email | Exfiltrate all messages + attachments |
| `/v1.0/me/drive` | OneDrive access | Enumerate files; download via `/content` |
| `/v1.0/me/drive/root/children` | OneDrive directory listing | File names, sizes, modification dates |
| `/v1.0/me/chats` | User's chat conversations | Personal/group chats in Teams |
| `/v1.0/teams/{teamId}/channels` | Teams channel enumeration | Channel list + member details |
| `/v1.0/teams/{teamId}/channels/{channelId}/messages` | Teams message export | Exfiltrate all visible messages |
| `/v1.0/me/memberOf` | Group membership | User's groups + roles |
| `/v1.0/groups` | Organization groups | All security + Office 365 groups |
| `/v1.0/applications` | Application registration inventory | App IDs, permissions, reply URLs |
| `/v1.0/servicePrincipals` | Service principal enumeration | Delegated + application permissions |
| `/v1.0/deviceAppManagement/conditionalAccessPolicies` | Conditional Access policies | Security posture reconnaissance |
| `/v1.0/me/deviceManagementTroubleshootingEvents` | Device enrollment status | Intune/MDM details |
| `/v1.0/directoryObjects` | Tenant-wide object resolution | User/group/app GUID lookups |

### Key Attack Mechanics

1. **Tokenless Reconnaissance** — Many Graph endpoints return data visible only to an authenticated user (no "list all users" endpoint exists for low-privilege accounts); GraphRunner's reconnaissance is therefore **per-user limited** by that user's own access rights, not administrative.

2. **Data Exfiltration** — Email/Teams/SharePoint/OneDrive are queried via Graph's `/messages`, `/chats`, and `/drive` endpoints; results are exported as JSON, CSV, or HTML by the PowerShell module or HTML GUI.

3. **Mailbox Access Inheritance** — If the compromised user has mailbox access rights to another user (e.g., a manager's mailbox granted to their assistant), GraphRunner can enumerate and exfiltrate that delegated mailbox as well (`Get-DelegatedMailboxAccess`, `Search-MailboxForKeywords`).

4. **Application Deployment Persistence** — The `Invoke-InjectOAuthApp` function registers a malicious multi-tenant OAuth application and grants it delegated permissions to the tenant, allowing the operator to obtain tokens for that app in future sessions even if the original compromised user's credentials are rotated.

5. **Security Group Manipulation** — `Invoke-SecurityGroupCloner` duplicates an existing security group (often a privileged group like "Domain Admins" equivalent in Azure AD), allowing the operator to:
   - Join the cloned group to themselves
   - Use the cloned group for lateral movement / privilege escalation (if group membership is used for resource authorization)
   - Avoid immediate detection (the clone is a real group, not a suspicious addition to the original)

6. **Token Refresh Management** — `Invoke-AutoTokenRefresh` periodically refreshes the operator's tokens using the refresh token, keeping the access token valid for days/weeks without re-authentication.

## Techniques/Protocols Used

| Protocol/Technique | GraphRunner Use | Reference |
|---|---|---|
| **OAuth 2.0 / OpenID Connect** | Token acquisition, refresh-token abuse, consent-grant attacks | T1528, T1528 (OAuth 2.0 Scopes) |
| **Microsoft Graph API (REST/HTTPS)** | All data access and manipulation | Microsoft Graph overview |
| **Device Code Flow** | Interactive device-login authentication | RFC 8628, Microsoft identity platform |
| **Resource Owner Password Credential (ROPC)** | Direct username/password → token exchange | OAuth 2.0 Resource Owner Password Credentials Grant |
| **Delegated Permissions** | Acting on behalf of an authenticated user | Microsoft identity scopes/permissions model |
| **Application Permissions** | Service principal / application-to-tenant access (some GraphRunner functions) | Microsoft Entra ID application permissions |
| **Azure AD Token Endpoint** | `https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token` | Entra ID authentication |

## Command-Line Switches — Quick Reference

GraphRunner is invoked as a PowerShell module; it has **no command-line switches** per se. Instead, the operator imports the module and calls individual functions with parameters. Below are the key functions and their primary parameters:

### Authentication & Token Management

| Function | Key Parameters | Purpose |
|----------|---|---|
| `Get-GraphTokens` | `-username <UPN>` `-password <SecureString>` `-tenantId <GUID>` | Acquire tokens via ROPC flow (prompts for credentials if not provided) |
| `Invoke-CAPSDeviceCodeAuth` | `-clientId <GUID>` | Device-code flow; user must authenticate at `microsoft.com/devicelogin` |
| `Invoke-CAPSRefreshTokenAuth` | `-refreshToken <string>` `-clientId <GUID>` `-tenantId <GUID>` | Use captured refresh token to obtain new access token |
| `Invoke-AutoTokenRefresh` | `-refreshToken <string>` `-clientId <GUID>` `-headers <hashtable>` | Continuously refresh tokens in a loop every N hours |
| `Get-TenantID` | `-username <UPN>` | Resolve tenant GUID from a user's UPN (no auth required) |

### Reconnaissance & Enumeration

| Function | Key Parameters | Purpose |
|----------|---|---|
| `Invoke-GraphRecon` | `-headers <hashtable>` `-outfile <path>` | Quick tenant survey (user info, groups, roles, apps) |
| `List-GraphRunnerModules` | (none) | Display all available functions and their descriptions |
| `Get-DumpAppsTenantInfo` | `-headers <hashtable>` | Enumerate all registered applications and service principals |
| `Get-DumpAppsApplicationInventory` | `-headers <hashtable>` | List all app registrations (client ID, redirect URIs, owner, permissions) |
| `Get-DumpAppsServicePrincipalInventory` | `-headers <hashtable>` | Enumerate service principals + delegated permission grants |
| `Get-SecurityGroups` | `-headers <hashtable>` `-selectall` | List all security and Office 365 groups |
| `Get-DirectoryRoles` | `-headers <hashtable>` | Enumerate all directory roles + current members |
| `Get-SharePointSiteURLs` | `-headers <hashtable>` | Discover accessible SharePoint site collections |
| `Get-CAPSTenantInfo` | `-headers <hashtable>` `-outfile <path>` | Dump conditional access policies + legacy policies |
| `Invoke-GraphRunner` | (HTML GUI launcher) | Launch browser-based GUI for token pillaging |

### Data Exfiltration

| Function | Key Parameters | Purpose |
|----------|---|---|
| `Invoke-SearchUserAttributes` | `-query <string>` `-headers <hashtable>` | Search user attributes (email, phone, description, etc.) for keywords |
| `Invoke-SearchSharePointAndOneDrive` | `-query <string>` `-headers <hashtable>` `-outfile <path>` | Search all accessible SharePoint + OneDrive files |
| `Invoke-DriveFileDownload` | `-driveId <GUID>` `-itemId <GUID>` `-outfile <path>` | Download a specific file from OneDrive/SharePoint |
| `Invoke-SearchTeams` | `-query <string>` `-headers <hashtable>` `-outfile <path>` | Search Teams chats + channels for messages/files |
| `Get-TeamsChat` | `-headers <hashtable>` | List all user's Teams chats and export messages |
| `Get-ChannelEmails` | `-teamId <GUID>` `-channelId <GUID>` `-headers <hashtable>` | Export email linked to a Teams channel |

### Persistence & Post-Compromise

| Function | Key Parameters | Purpose |
|----------|---|---|
| `Invoke-InjectOAuthApp` | `-displayName <string>` `-tenantId <GUID>` `-clientId <string>` | Register malicious OAuth app + assign delegated permissions |
| `Invoke-DeleteOAuthApp` | `-appId <GUID>` `-headers <hashtable>` | Delete a previously registered OAuth app (cleanup) |
| `Invoke-SecurityGroupCloner` | `-groupId <GUID>` `-headers <hashtable>` `-groupName <string>` | Clone a security group (often used to clone high-privilege groups) |
| `Invoke-AddGroupMember` | `-groupId <GUID>` `-userId <GUID>` `-headers <hashtable>` | Add user to a group |
| `Invoke-RemoveGroupMember` | `-groupId <GUID>` `-userId <GUID>` `-headers <hashtable>` | Remove user from a group |
| `Create-Webhook` | `-resource <string>` `-changeType <string>` `-notificationUrl <URL>` | Create Graph API webhook for event notifications |
| `Create-SecurityGroupWithMembers` | `-displayName <string>` `-members <array>` `-headers <hashtable>` | Create new security group + pre-populate membership |

### Credential Attack & Token Manipulation

| Function | Key Parameters | Purpose |
|----------|---|---|
| `Invoke-BruteClientIDAccess` | `-username <UPN>` `-password <string>` `-clientIds <array>` | Try multiple OAuth client IDs against user credentials (consent-grant enumeration) |
| `Invoke-ImportTokens` | `-file <path>` | Parse and import tokens from stolen/exfiltrated token cache files (e.g., `TokenCache.dat`) |

## Quick Use-Case List

The following 15+ post-compromise scenarios are realistic and well-documented in the wild:

1. **Application Inventory Enumeration** — Map all OAuth apps in the tenant, their permissions, and which users have granted consent (identify planted malicious apps or overprivileged integrations).
2. **User Enumeration & Attribute Harvesting** — Extract all user attributes (email, phone, description, job title, manager, etc.) searchable by keyword, to identify high-value targets for lateral movement.
3. **Email Exfiltration — Full Mailbox Dump** — Export all messages, attachments, and folder structure from the compromised user's mailbox.
4. **Email Exfiltration — Keyword Search** — Search across all accessible mailboxes (own + delegated) for specific terms (e.g., "password", "server", "VPN", "keys") to prioritize sensitive messages.
5. **Delegated Mailbox Access Discovery** — Identify which other users' mailboxes the compromised account has been granted access to, then exfiltrate those as well.
6. **OneDrive & SharePoint File Discovery** — Enumerate all files accessible to the user across SharePoint sites and OneDrive, export file metadata (names, sizes, modification dates).
7. **OneDrive & SharePoint File Exfiltration** — Download sensitive files (documents, spreadsheets, archives) from SharePoint/OneDrive visible to the compromised user.
8. **Teams Enumeration & Exfiltration** — Export all Teams channels visible to the user, including full message history and attachments from each channel.
9. **Teams Direct Chat Exfiltration** — Extract all direct/group chats from Teams, including message history.
10. **Conditional Access Policy Reconnaissance** — Dump all Conditional Access policies + legacy policies to identify security controls and potential bypass vectors.
11. **Privilege Escalation — Security Group Cloning** — Clone a high-privilege group (e.g., "Azure AD Global Admin" group equivalent), add self to the clone, use cloned group membership for escalation.
12. **Privilege Escalation — Group Membership Manipulation** — If group membership controls resource access, add the compromised user (or the operator's own Azure AD account) to administrative groups.
13. **Persistence — Malicious OAuth App Registration** — Register a multi-tenant OAuth app with delegated permissions (Mail.Read, Files.Read, etc.), grant it permissions in the target tenant, and use it to obtain tokens for future sessions.
14. **Persistence — Webhook Creation** — Set up Graph API webhooks to receive notifications of future tenant events (new user creation, group changes, email received by specific users), maintaining awareness without re-authentication.
15. **Consent Grant Attack Reconnaissance** — Use `Invoke-BruteClientIDAccess` to enumerate which OAuth client IDs have been provisioned in the tenant, and attempt password-spray against them to identify which ones the victim has pre-consented to.
16. **Cross-Tenant Enumeration** (if applicable) — If the compromised user is a guest/federation account in another tenant, enumerate and pillage that tenant's resources as well.
17. **Intune/MDM Device Enumeration** — Query `/deviceAppManagement/` endpoints to enumerate enrolled devices, their compliance status, and management policies.
18. **Dynamic Group Membership Abuse** — Find dynamic groups whose membership rules can be exploited, or find groups with simple membership rules, to add the operator's account dynamically.

## Cross-References to Related Tools & Modules

- **AADInternals (Wave 3 #6)** — For Azure AD enumeration and attack context beyond Graph API; GraphRunner complements AADInternals but operates via Graph API rather than direct AD LDAP
- **TrevorSpray + Spray365 (Wave 3 #7)** — Initial Entra ID password-spray/credential-stuffing that **precedes** GraphRunner deployment; password spray gives the operator valid credentials needed for `Get-GraphTokens`
- **Cloud/Microsoft/Entra ID/** — Foundational reference for Microsoft Graph API scopes, permissions models (delegated vs. application), sign-in logs, audit logs, Conditional Access
- **Incident Response Guides in Cloud/** — Post-compromise investigation using Graph API activity logs, Entra ID sign-in analysis, and audit correlation

---

## Prerequisites

GraphRunner operations require **all** of the following conditions:

| Prerequisite | Details |
|---|---|
| **Initial Compromise** | The operator must already have access to a user's credentials, refresh token, or access token — GraphRunner is strictly post-exploitation, not initial-access |
| **Valid Microsoft Entra ID Account** | The credentials/tokens must belong to an active Entra ID (Azure AD) user or service principal in the target tenant |
| **Microsoft Graph API Access** | The user/application must have been granted (or previously consented to) permissions to read/write the targeted resources (Mail, Files, Teams, etc.) — Entra ID conditional access or policy restrictions may block access even with valid credentials |
| **Network Access to Microsoft Graph** | Outbound HTTPS access to `https://graph.microsoft.com` and `https://login.microsoftonline.com` — no proxying or network restrictions from the operator's position that would block these endpoints |
| **PowerShell** (for module mode) | PowerShell 5.0+ on Windows, or PowerShell Core on Linux/macOS — no admin privileges required for the PowerShell module itself, but some enumeration/exfiltration may be scoped by the user's own permissions |
| **Browser** (for GUI mode) | Modern browser (Chrome, Edge, Firefox) to host the HTML GUI — requires the PowerShell module to provide an access token |
| **Operator Knowledge of Microsoft Graph API** | Familiarity with OAuth 2.0, access tokens, and Graph API endpoints — the tool does not abstract away this complexity |

**Permissions Model Caveat:** GraphRunner's actual capabilities depend entirely on the **user's own permissions in Entra ID**. A low-privilege user can only read/enumerate resources they personally have access to; if the tenant has restricted Entra roles or conditional access policies that block token acquisition, GraphRunner will fail at token-acquisition time, not later.
