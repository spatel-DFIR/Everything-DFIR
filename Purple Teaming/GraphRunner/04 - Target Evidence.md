# GraphRunner — Target Evidence

## Overview

GraphRunner's target-side evidence is almost entirely **cloud-based**: Microsoft Graph API audit logs, Entra ID sign-in logs, Azure audit logs, and per-application event logs (Exchange Online, SharePoint, Teams). There are **no filesystem or local-registry artifacts** on the victim's machine, since all operations go through cloud APIs.

The key audit logs are:

1. **Azure Entra ID Sign-in Logs** — captures token acquisition (authentication events)
2. **Azure Audit Logs** (Activity Log) — tracks changes to Azure resources
3. **Microsoft Graph API Activity Logs** (via `audit.azure.com` or unified audit log) — per-API-call visibility
4. **Exchange Audit Log** — email access, mailbox enumeration
5. **SharePoint/OneDrive Audit Log** — file access, enumeration
6. **Teams Audit Log** — chat/channel access, message retrieval
7. **Azure AD Conditional Access** — sign-in alerts if policies trigger

## Azure Entra ID Sign-In Logs

### Initial Token Acquisition

Every time GraphRunner calls `Get-GraphTokens` or `Invoke-CAPSDeviceCodeAuth`, an Entra ID sign-in event is logged.

**Log Location:** Azure Portal → Azure AD → Sign-in logs → [Filter by user/app]

**Key Event Fields:**

| Field | Value | GraphRunner Indicator |
|-------|-------|---|
| **User** | `user@target.onmicrosoft.com` | The compromised account |
| **Application** | "Azure Mobile Application" or "Microsoft Office" (default client IDs) | Default multi-tenant app; suggests password spray or credential reuse |
| **Client App** | PowerShell (if via ROPC flow) | Direct ROPC = password spray suspect |
| **Sign-in Status** | Success | Valid credentials or tokens |
| **IP Address** | Operator's IP (VPN, proxy, residential) | Geolocation anomaly if operator is in unusual location |
| **Device Info** | PowerShell.exe, Windows 10/11 | Non-browser authentication = automated attack |
| **Conditional Access** | May show "Block" or "Challenge" if MFA/CA policies trigger | High-confidence indicator of attack if CA blocks it |
| **Risk Level** | May be flagged as "High" if sign-in from new location | Azure AD Identity Protection evaluation |

### Example Sign-In Log Entry

```json
{
  "id": "66c8e3f1-...",
  "createdDateTime": "2024-01-15T14:35:50Z",
  "userPrincipalName": "user@target.onmicrosoft.com",
  "userId": "12345678-...",
  "appId": "1b730954-1685-4b74-9bda-3b3b6a7366c9",
  "appDisplayName": "Azure Mobile Application",
  "ipAddress": "203.0.113.45",  // Attacker's IP
  "clientAppUsed": "Modern authentication clients",
  "deviceInfo": {
    "displayName": "DESKTOP-ATTACKER",
    "operatingSystem": "Windows",
    "browser": "PowerShell"
  },
  "riskDetail": "tokenIssuerAnomaly",
  "conditionalAccessStatus": "success",
  "resourceDisplayName": "Microsoft Graph"
}
```

**Detection Opportunity:** Token issuers from unusual geographies, impossible-travel scenarios (e.g., login from US at 14:35, then from China at 14:45), or repeated failed auth followed by success within seconds (password spray pattern).

### Refresh Token Abuse

If the operator uses `Invoke-CAPSRefreshTokenAuth` with a captured refresh token, a new sign-in event is created **without requiring a password**. This is called a **"Refresh token flow"** and appears in sign-in logs with:

- **Authentication Requirement:** "Single-factor authentication"
- **MFA Requirement:** "Not satisfied" (no MFA on refresh)
- **Device Registration:** May not match the original device
- **Risk Level:** Often flagged as "tokenIssuerAnomaly" or "atypicalSignInProperties"

**Example Refresh Token Sign-In:**

```
Sign-in: 2024-01-15 14:36:15 UTC
User: user@target.onmicrosoft.com
Authentication Method: Refresh Token (OAuth 2.0)
Device: NEW-DEVICE-123
Risk: Atypical Sign-in Properties
```

## Azure AD Audit Logs (Activity Log)

If the operator modifies Entra ID resources (groups, apps, policies), those changes are logged.

### Group Cloning / Group Membership Changes

If `Invoke-SecurityGroupCloner` is used:

**Audit Log Event:** "Add member to group" OR "Create group"

| Field | Value |
|-------|-------|
| **Activity** | "Add member to group" OR "Create group" |
| **Category** | Group Management |
| **DateTime** | Timestamp of the change |
| **Modified By** | The compromised user's account (or service principal if app-based) |
| **Target** | The cloned group (new group name) + the added member (operator's account) |
| **Resource** | Azure AD |

**Example Log:**

```
Event: Create group
DateTime: 2024-01-15T14:37:00Z
Modified By: user@target.onmicrosoft.com
Target: "Global Admins - Operations Team" (new group ID: 87654321-...)
Result: Success
```

Followed immediately by:

```
Event: Add member to group
DateTime: 2024-01-15T14:37:05Z
Modified By: user@target.onmicrosoft.com
Group: "Global Admins - Operations Team"
Member Added: attacker@attacker-domain.com or operator-compromised-account
Result: Success
```

### Application Registration

If `Invoke-InjectOAuthApp` is used:

**Audit Log Events:**
1. "Register application" (creation of the app)
2. "Add application" (if it's a service principal)
3. "Grant admin consent for application" (if permissions are pre-consented)

**Example Log:**

```
Event: Register application
DateTime: 2024-01-15T14:38:00Z
Modified By: user@target.onmicrosoft.com
Application: "Microsoft Teams Sync Service" (fake app)
Application ID: attacker-app-id
Result: Success

Event: Grant admin consent for application
DateTime: 2024-01-15T14:38:05Z
Application: "Microsoft Teams Sync Service"
Permissions Granted: Mail.Read, Files.Read.All, Teams.Read
Result: Success
```

## Microsoft Graph API Activity Logs (Unified Audit Log)

The **Unified Audit Log** (if enabled) records all Graph API calls made on behalf of the user.

**Log Location:** Microsoft 365 Security & Compliance → Audit → Unified Audit Log

**Key Activities Logged:**

| GraphRunner Function | Audit Activity | Log Name | Notes |
|---|---|---|---|
| Invoke-SearchUserAttributes | User viewed/searched directory | AzureActiveDirectoryAccountLogon / Add user | LDAP-style query |
| Invoke-SearchSharePointAndOneDrive | FileAccessed / FileDownloaded | SharePoint | File enumeration + download |
| Invoke-SearchTeams | TeamsSearch / MessageRead | Teams | Teams message exfiltration |
| Invoke-SearchUserAttributes (email) | Search-MailboxAuditLog / UserLoggedIn | Exchange | Mailbox access |
| Invoke-DumpAppsTenantInfo | Application accessed / SP accessed | AzureActiveDirectory | App enumeration |
| Invoke-SecurityGroupCloner | Group modified / Member added | AzureActiveDirectory | Group manipulation |
| Invoke-InjectOAuthApp | Application registered / Consent granted | AzureActiveDirectory | Persistence mechanism |

### Example Unified Audit Log Entries

#### Email Search/Exfiltration

```json
{
  "Timestamp": "2024-01-15T14:36:10Z",
  "UserIds": "user@target.onmicrosoft.com",
  "RecordType": "ExchangeItem",
  "Operations": "Search-MailboxAuditLog",
  "AuditData": {
    "Mailbox": "user@target.onmicrosoft.com",
    "MailboxOwner": "user@target.onmicrosoft.com",
    "LogonType": "Admin",  // Or "Delegate" if accessing delegated mailbox
    "SearchTerms": "*",  // Broad search / export of all messages
    "ResultSize": 4853
  }
}
```

#### File Access / Exfiltration (SharePoint/OneDrive)

```json
{
  "Timestamp": "2024-01-15T14:36:30Z",
  "UserIds": "user@target.onmicrosoft.com",
  "RecordType": "SharePoint",
  "Operations": "FileAccessed",
  "AuditData": {
    "Site": "https://target-tenant.sharepoint.com/sites/SensitiveProject",
    "ItemType": "File",
    "ItemName": "Q4_Budget_Forecast.xlsx",
    "EventSource": "SharePoint",
    "SourceFileExtension": "xlsx",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; ...) / or PowerShell User-Agent"
  }
}
```

#### Teams Messages Accessed

```json
{
  "Timestamp": "2024-01-15T14:36:45Z",
  "UserIds": "user@target.onmicrosoft.com",
  "RecordType": "Teams",
  "Operations": "MessageRead",
  "AuditData": {
    "TeamName": "Executive Communication",
    "ChannelName": "General",
    "MessageCount": 2847,
    "SearchTerms": "*"  // Broad export
  }
}
```

#### Application Enumeration

```json
{
  "Timestamp": "2024-01-15T14:37:30Z",
  "UserIds": "user@target.onmicrosoft.com",
  "RecordType": "AzureActiveDirectory",
  "Operations": "List applications / Get service principal",
  "AuditData": {
    "Target": [
      {
        "ID": "application ID",
        "Type": "ServicePrincipal"
      }
    ],
    "ResultSize": 247  // Number of apps enumerated
  }
}
```

## Microsoft Entra ID Risk Detection & Conditional Access Alerts

### Identity Protection Risk Detections

If Entra ID's **Identity Protection** service is enabled, GraphRunner's token reuse/refresh token abuse may trigger risk detections:

| Risk Detection | Trigger | Severity |
|---|---|---|
| **Token Issuer Anomaly** | Refresh token used from unusual IP/location | Medium |
| **Atypical Sign-in Properties** | Sign-in pattern differs from baseline (time, geography, device) | Low |
| **Impossible Travel** | Sign-in from two geographies in impossible timeframe | High |
| **Malware Detection** | PowerShell-based attack patterns (signature match) | High |
| **Anonymous IP** | Sign-in from known VPN/proxy IP | Low |
| **Suspicious API Traffic** | Bulk/unusual Graph API calls to multiple resources | High |
| **Risky Sign-in** | Composite risk score above threshold | Variable |

**Example Risk Detection Alert:**

```
Risk Type: Token Issuer Anomaly
Severity: Medium
User: user@target.onmicrosoft.com
Sign-in Time: 2024-01-15T14:35:50Z
Risk State: Detected
Remediation: User flagged for manual review; may trigger MFA re-authentication requirement
```

### Conditional Access Policy Triggers

If the tenant has Conditional Access policies enforced:

- **MFA Challenge** — User prompted for second factor (if policy requires MFA for unusual sign-ins)
- **Session Time-Out** — Token valid for reduced duration (e.g., 1 hour instead of 24 hours)
- **Access Denied** — Policy blocks sign-in entirely (if operator's IP is on blocklist, or device is unmanaged, etc.)

**Example CA Log:**

```
Sign-in: user@target.onmicrosoft.com
Time: 2024-01-15T14:35:50Z
IP: 203.0.113.45
Device: Unmanaged
Conditional Access Policy: "Require MFA for External Access"
Result: Challenge (MFA prompt sent)
Outcome: User failed MFA / User passed MFA after N attempts
```

## Exchange Online Audit Logs

If the operator exfiltrates email via GraphRunner's `Invoke-RestMethod` calls to the `/me/messages` endpoint:

**Audit Events:** mailbox access is logged, but the **granularity depends on mailbox audit policy settings**.

### Default Mailbox Audit Logging

By default, Exchange Online logs:

- **Search-MailboxAuditLog** — When a user's mailbox is searched (via E-discovery, compliance search, etc.)
- **HardDelete** — When emails are permanently deleted
- **SoftDelete** — When emails are moved to Deleted Items folder
- **MoveToDeletedItems** — Emails moved to trash

**GraphRunner's graph API calls** to `/me/messages` do **NOT** by default generate a "message read" audit event (message reading is not logged by default in Exchange). However:

1. If the mailbox audit policy has **custom auditing enabled** for "Read" action, those events appear
2. **Admin/delegate mailbox access** is always logged with higher fidelity

### Exchange Audit Log Example

```
Mailbox: user@target.onmicrosoft.com
Action: MailboxLogin (via Graph API)
DateTime: 2024-01-15T14:36:10Z
ClientInfo: PowerShell/Graph API (User-Agent: Microsoft Graph Client Library)
LogonType: Delegate (if accessing another user's mailbox)
LogonUser: user@target.onmicrosoft.com (the compromised account performing the access)
```

## SharePoint & OneDrive Audit Logs

### Accessed Files / Enumeration

**Audit Events:**
- **FileAccessed** — When a file is downloaded or opened
- **FileModified** — When a file is edited
- **FileDeleted** — When a file is deleted
- **FileCheckedOut** / **FileCheckedIn** — Version control actions
- **FolderAccessed** — When a folder listing is accessed (enumeration)

**GraphRunner-Specific Pattern:**

```
Site: https://target-tenant.sharepoint.com/sites/Executive
Item: /Executive/Q1_Revenue_Report.xlsx
Action: FileAccessed
DateTime: 2024-01-15T14:36:35Z
UserAgent: PowerShell
UserPrincipalName: user@target.onmicrosoft.com
ClientIPAddress: 203.0.113.45
```

### Mass Enumeration Indicator

If `Invoke-SearchSharePointAndOneDrive` is run with a broad query, the audit log shows:

```
Multiple FileAccessed events in quick succession (seconds apart)
Site: [Multiple SharePoint sites]
Folder: [Multiple folders]
Item: [Hundreds of files]
Pattern: Systematic enumeration (not typical user browsing)
```

This is **highly suspicious** and indicates programmatic file discovery.

## Teams Audit Logs

### Message Access

**Audit Events:**
- **TeamsChatCreated** — New chat created
- **TeamsChannelCreated** — New channel created
- **ChatMessageCreated** / **ChatMessageRead** — Chat activity
- **ChannelMessagePosted** — Channel message activity

**GraphRunner-Specific Pattern:**

```
Team: "Executive Communication"
Channel: "General"
Action: ChatMessageRead / ExportedData
DateTime: 2024-01-15T14:36:50Z
User: user@target.onmicrosoft.com
MessageCount: 2847
Pattern: Bulk export (not typical chat reading)
```

## Network-Layer Evidence

### TLS/SSL Certificate Inspection

All traffic to `graph.microsoft.com` uses **TLS 1.2+** with **Microsoft's legitimate certificates**. This means:

1. **Network signature-based detection is impossible** — traffic is encrypted with real Microsoft certs
2. **Certificate pinning** (if enabled on the client) will succeed (GraphRunner uses legitimate HTTPS)
3. **Proxy/firewall content inspection** may be able to see the **Host header** (`graph.microsoft.com`) but not the request body

### DNS Logging

Queries for `graph.microsoft.com` and `login.microsoftonline.com` are logged:

- **From the victim's network:** If DNS logging is enabled
- **By the ISP:** If the victim's network uses ISP DNS
- **Correlation with activity:** No correlation possible — these resolutions are normal for any cloud user

### NetFlow / Network Traffic Analysis

#### Indicators

1. **High volume of HTTPS traffic to `graph.microsoft.com`** — bulk data exfiltration may show elevated HTTPS traffic volume
2. **Outbound HTTPS on port 443** — normal for any cloud app, not suspicious alone
3. **Repeated DNS queries for `graph.microsoft.com`** — normal for long-lived GraphRunner sessions with periodic API calls
4. **Multiple concurrent HTTPS connections** — not typical for human-paced activity

**Evasion:** The operator can spread requests over time or run GraphRunner at scheduled intervals to avoid volume-based detection.

## Timeline Building: Source to Target Evidence Correlation

Here's how to correlate source-side indicators (from **03 - Source Evidence.md**) with target-side logs:

### Example Attack Timeline

| Timestamp (UTC) | Source Indicator | Target Indicator | Correlation |
|---|---|---|---|
| 14:35:22 | PSReadline: `Import-Module .\GraphRunner.ps1` | — | Prep (no target activity yet) |
| 14:35:47 | PSReadline: `$headers = Get-GraphTokens -username ...` | Entra ID Sign-in: Token issued to "Azure Mobile App" | Token acquisition |
| 14:35:50 | Network: POST to login.microsoftonline.com/.../token | Entra ID: Sign-in event + possible CA/Risk detection | Same event, ±3 sec |
| 14:36:05 | PSReadline: `Invoke-SearchSharePointAndOneDrive ...` | SharePoint Audit: Multiple FileAccessed events | File exfil starts |
| 14:36:30 | PSReadline: `Invoke-DumpAppsTenantInfo ...` | Entra ID Audit: Application list accessed via Graph API | App enumeration |
| 14:37:00 | PSReadline: `Invoke-SecurityGroupCloner ...` | Entra ID Audit: Group created + member added | Group cloning |
| 14:37:30 | File: `C:\Exfil\AppsInventory.html` created (filesystem timestamp) | Unified Audit Log: Activity logged 2-5 min after the actual operation | Slight time lag (log delivery) |

**Key Insight:** The **greatest fidelity is between source PSReadline timestamps and target-side Entra ID/Exchange/SharePoint audit log timestamps — usually within 5 seconds**. This correlation is forensically reliable and forms the basis of attack timeline reconstruction.

## Summary of Strongest Target-Side Indicators

1. **Entra ID Sign-in Logs** — Token acquisition events; risk detections from unusual IP/location
2. **Entra ID Audit Logs** — Group creation, application registration, permission grants
3. **Unified Audit Log** — Broad enumeration activity (multiple resources accessed in quick succession)
4. **Exchange Audit** — Mailbox access, delegated mailbox activity, bulk message access
5. **SharePoint/OneDrive Audit** — File access patterns (bulk enumeration vs. normal browsing)
6. **Teams Audit** — Chat/channel message access, bulk export patterns
7. **Identity Protection Alerts** — Token issuer anomalies, atypical sign-in properties, impossible travel
8. **Conditional Access Logs** — CA policy blocks, MFA challenges triggered
9. **Temporal Correlation** — Source-side timestamps ↔ target-side audit log timestamps (±5 sec = match)
