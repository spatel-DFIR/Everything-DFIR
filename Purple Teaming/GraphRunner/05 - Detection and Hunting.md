# GraphRunner — Detection and Hunting

## Hunting Priority Table

The following hunting signals are ranked by **invariant strength** — which ones survive operator evasion attempts (running from memory, disabling PSReadline history, using proxy/VPN, etc.).

| Priority | Signal | Survives Source Opsec | Survives Network Opsec | Survives Cloud-Config Evasion | Reliability | Query/Command |
|---|---|---|---|---|---|---|
| **🔴 1** | **Entra ID sign-in from unusual IP/location + token issuer anomaly risk detection** | Yes (target-side) | Yes (Azure tenant-side) | No | High | Azure AD → Sign-in logs + Identity Protection |
| **🔴 2** | **Bulk graph.microsoft.com API calls within seconds (>100 endpoints in <60s)** | Yes (target-side) | Yes (telemetry) | No | High | Audit logs (Unified/Exchange/SharePoint) or Log Analytics |
| **🟠 3** | **Entra ID Audit Logs: Group created + member added within seconds** | Yes (target-side) | Yes | No | High | Entra ID → Audit activity logs |
| **🟠 4** | **Entra ID Audit Logs: Application registered + permissions granted in rapid sequence** | Yes (target-side) | Yes | No | High | Entra ID → Audit activity logs |
| **🟡 5** | **PSReadline history file contains GraphRunner function calls** | No (can be cleared) | Yes | Yes | Medium | Source: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| **🟡 6** | **Event 4104 (Script Block Logging): GraphRunner module import + function calls** | No (can be disabled) | Yes | Yes | Medium | Source: Event Viewer → Windows Logs → Application |
| **🟡 7** | **Delegated mailbox access: Mailbox accessed by user != mailbox owner within seconds of abnormal sign-in** | Yes (target-side) | Yes | Partially | High | Exchange audit: Search-MailboxAuditLog + MailboxLogin |
| **🟡 8** | **FileAccessed events from same user across multiple SharePoint sites within seconds** | Yes (target-side) | Yes | Partially | Medium | SharePoint audit: FolderAccessed + FileAccessed in rapid sequence |
| **🟢 9** | **GraphRunner.ps1 file on disk** | No (can be run in-memory) | Yes | Yes | Low | Source: File system search for `GraphRunner.ps1` |
| **🟢 10** | **Exfiltrated data files (AppsInventory.json, Teams_*.json, etc.) on disk** | No (can be deleted/moved) | Yes | Yes | Low | Source: File system search for `.json`/`.csv` export files in suspicious paths |
| **🟢 11** | **DNS query for graph.microsoft.com from unusual client** | No (can use proxy DNS) | Partially (can randomize via VPN) | Yes | Low | Source: DNS logs; too common for reliable detection alone |
| **🟢 12** | **Refresh token captured in memory dump or token cache file** | No (can be cleared) | Yes | Yes | Low | Source: Memory forensics or `%LOCALAPPDATA%\...TokenCache.dat` |

**Legend:** 🔴 = Highest priority (near-certain indicator); 🟠 = High priority; 🟡 = Medium priority; 🟢 = Low priority (context-dependent)

---

## Hunting on Source

### 1. PowerShell Command History (PSReadline)

**Attacker Opsec Risk:** Operator can delete the history file or disable PSReadline before running GraphRunner.

**Command (PowerShell):**

```powershell
# Read PSReadline history file
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $historyPath) {
    Get-Content $historyPath | Select-String -Pattern "Get-GraphTokens|Invoke-Graph|Invoke-Search|Invoke-Dump|GraphRunner|Graph API"
}
```

**On Linux/macOS:**

```bash
cat ~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt | grep -iE "graphrunner|get-graphtokens|invoke-graph"
```

**Key Indicators:**
- `Import-Module .\GraphRunner.ps1`
- `Get-GraphTokens` (password spray / credential reuse)
- `Invoke-SearchSharePointAndOneDrive`, `Invoke-SearchTeams`, `Invoke-SearchUserAttributes` (data exfil)
- `Invoke-DumpAppsTenantInfo`, `Invoke-DumpAppsTenantInfo` (app enumeration)
- `Invoke-SecurityGroupCloner` (privilege escalation)
- `Invoke-InjectOAuthApp` (persistence)
- `Invoke-RestMethod -Uri "https://graph.microsoft.com"` (direct Graph API calls)

---

### 2. PowerShell Script Block Logging (Event ID 4104)

**Attacker Opsec Risk:** Requires Script Block Logging to be enabled (not by default on non-SYSTEM accounts).

**Command (PowerShell):**

```powershell
# Query Event Viewer for Script Block events containing GraphRunner
Get-WinEvent -FilterHashtable @{
    LogName = "Windows PowerShell"
    Id = 4104
} -ErrorAction SilentlyContinue | Where-Object {
    $_.Message -match "GraphRunner|Get-GraphTokens|Invoke-Graph|Invoke-Dump|oauth2PermissionGrants|graph.microsoft.com"
}

# Or filter for events in the past 24 hours:
Get-WinEvent -FilterHashtable @{
    LogName = "Windows PowerShell"
    Id = 4104
    StartTime = (Get-Date).AddHours(-24)
} | Where-Object {
    $_.Message -match "Get-GraphTokens|Invoke-Security"
} | Format-Table TimeCreated, Message
```

**Key Indicators in Script Block Content:**
- Function calls with suspicious parameter patterns (e.g., `-outfile "C:\Exfil\..."`)
- Direct Invoke-RestMethod calls to `https://graph.microsoft.com/v1.0/oauth2PermissionGrants` (app enumeration)
- OAuth token handling variables (`$headers`, `$bearer`, `$token`)

---

### 3. GraphRunner.ps1 File Presence

**Command (PowerShell):**

```powershell
# Find GraphRunner.ps1 anywhere on disk
Get-ChildItem -Path C:\ -Recurse -Name "GraphRunner.ps1" -ErrorAction SilentlyContinue

# Alternative: search for files modified in the past 24 hours in common temp paths
Get-ChildItem -Path C:\Users\*\AppData\Local\Temp, C:\Temp, C:\Windows\Temp -Filter "GraphRunner*" -Recurse -ErrorAction SilentlyContinue
```

**File Signature (if analyzing offline):**
- Hash the file and compare to known GraphRunner GitHub repo versions
- Look for the string `"Import-Module .\GraphRunner.ps1"` in any parent scripts

---

### 4. Exfiltrated Data Files

**Command (PowerShell):**

```powershell
# Search for exfiltrated data files (JSON/CSV exports with telltale names)
Get-ChildItem -Path C:\Users\*\AppData\*, C:\Temp, C:\Exfil -Recurse -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "AppsInventory|AdminUsers|Teams_|SensitiveFiles|CondAccess|AdminGroups" } |
    Select-Object FullName, CreationTime, LastWriteTime, Length

# Or search for any recently-created .json/.csv files in unusual paths:
Get-ChildItem -Path C:\Exfil, C:\Temp -Recurse -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddHours(-24) }
```

**File Contents to Review:**
- `AppsInventory.html` / `.csv` — Contains application IDs and permissions
- `Email.csv` / `Mailbox.json` — Exfiltrated email messages
- `Teams_*.json` — Teams chat/channel content
- `CondAccessPolicies.html` — Conditional Access policy definitions

---

### 5. Access Token / Refresh Token in Memory

**Command (PowerShell - Memory Forensics):**

```powershell
# Dump a specific process's memory (requires admin)
# This requires a tool like `procdump.exe` (SysInternals) or `windbg`
procdump.exe -accepteula -ma powershell.exe C:\Temp\powershell_dump.dmp

# Then search the dump for Bearer token patterns:
# Tokens typically start with "eyJhbGci" (base64 for JWT header)
# Use strings tool or hex editor to search
strings.exe C:\Temp\powershell_dump.dmp | Select-String -Pattern "^eyJhbGci|Bearer.*eyJhbGci"
```

**Alternative (Token Cache Files):**

```powershell
# Search for Azure AD token cache files
Get-ChildItem -Path $env:LOCALAPPDATA -Recurse -Name "*TokenCache*" -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:APPDATA -Recurse -Name "*msal*" -ErrorAction SilentlyContinue

# Check for Azure SDK cache:
Get-ChildItem -Path "$env:USERPROFILE\.azure\*" -Recurse -ErrorAction SilentlyContinue
```

---

### 6. Proxy / Firewall Logs (Source Network Analysis)

**Search Terms:**

```
POST to login.microsoftonline.com/.../oauth2/v2.0/token (token acquisition)
GET/POST to graph.microsoft.com/v1.0/... (API calls)
User-Agent: PowerShell (authenticator for source-side identity)
Authorization: Bearer (OAuth 2.0 Bearer token in request headers)
```

**Command (If logs are available as logs):**

```bash
# Example: searching proxy logs for graph.microsoft.com access from a specific IP/user
grep -E "graph.microsoft.com|login.microsoftonline.com" /var/log/proxy.log | grep "203.0.113.*" | head -20
```

**Indicator Pattern:**
- Multiple HTTPS connections to `graph.microsoft.com` in a short time window (seconds)
- POST to `login.microsoftonline.com` token endpoint followed by rapid GET/POST bursts to Graph endpoints
- PowerShell User-Agent (not typical for human-interactive browser activity)

---

## Hunting on Target (Cloud/Azure)

### 1. Entra ID Sign-In Logs: Unusual Token Acquisition

**Portal Path:** Azure AD → Sign-in logs

**Query (PowerShell / MS Graph API):**

```powershell
# Query sign-in logs via Graph API
$headers = @{
    "Authorization" = "Bearer YOUR-ADMIN-TOKEN"
    "Content-Type" = "application/json"
}

# Search for sign-ins from unusual IPs using Azure AD default client IDs
$uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=appId eq '1b730954-1685-4b74-9bda-3b3b6a7366c9' and createdDateTime gt $(Get-Date -Format 'yyyy-MM-ddT00:00:00Z')"

$signInLogs = Invoke-RestMethod -Uri $uri -Headers $headers
$signInLogs.value | Where-Object {
    $_.riskLevel -eq "High" -or $_.riskDetail -match "tokenIssuerAnomaly|atypicalSignInProperties"
} | Select-Object userPrincipalName, ipAddress, deviceInfo, createdDateTime
```

**Key Filters:**
- **Risk Level:** "High" (impossible travel, token issuer anomaly)
- **Authentication Method:** "Single-factor" (no MFA) — unusual for modern tenants
- **Device Info:** "PowerShell", "Modern authentication clients" (not a browser)
- **IP Geolocation:** Mismatched with user's typical location

---

### 2. Entra ID Audit Logs: Suspicious Activity

**Portal Path:** Azure AD → Audit logs

**PowerShell Query:**

```powershell
# Query for group creation + membership changes (group cloning indicator)
Get-AuditLog -Filter "activityDisplayName eq 'Create group' or activityDisplayName eq 'Add member to group'" -ResultSize unlimited |
    Where-Object { $_.CreatedDateTime -gt (Get-Date).AddHours(-24) } |
    Select-Object CreatedDateTime, InitiatedByUser, Activity, TargetResources

# Query for application registration + permission grants
Get-AuditLog -Filter "activityDisplayName eq 'Register application' or activityDisplayName eq 'Grant admin consent for application'" -ResultSize unlimited |
    Where-Object { $_.CreatedDateTime -gt (Get-Date).AddHours(-24) } |
    Select-Object CreatedDateTime, InitiatedByUser, Activity, TargetResources
```

**Indicators:**
- Group creation + rapid member add (within seconds, same user performing both)
- Application registered with suspicious names (e.g., "Microsoft Teams Sync", "Azure Admin", "Office 365 Helper")
- Permission grants for sensitive scopes (Mail.Read, Files.Read.All, Teams.Read.All) by non-admin users

---

### 3. Unified Audit Log: Bulk Data Access

**Portal Path:** Microsoft 365 Compliance → Audit

**Query (PowerShell):**

```powershell
# Search for bulk file access in SharePoint/OneDrive
Search-UnifiedAuditLog -Operations FileAccessed -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) |
    Where-Object { $_.CreationDate -gt (Get-Date).AddSeconds(-10) } |
    Group-Object UserIds | Where-Object { $_.Count -gt 50 } |
    Select-Object Name, @{ n="AccessCount"; e={ $_.Count } }

# Search for Teams message access / export
Search-UnifiedAuditLog -Operations TeamsSearch -StartDate (Get-Date).AddDays(-1) -EndDate (Get-Date) |
    Select-Object UserIds, Operation, CreationDate, AuditData
```

**Bulk Activity Pattern:**
- Same user accessing 50+ files within 10 seconds (programmatic enumeration)
- Multiple Teams channels accessed in rapid succession (bulk export)
- SharePoint sites accessed by user who rarely uses them

---

### 4. Exchange Online Audit: Delegated Mailbox Access

**Query (PowerShell):**

```powershell
# Search for mailbox accessed by user != mailbox owner
Search-MailboxAuditLog -Mailbox "target@tenant.com" -LogonTypes Delegate -ResultSize unlimited |
    Where-Object { $_.LastAccessed -gt (Get-Date).AddHours(-24) } |
    Select-Object UserIds, MailboxOwner, LogonType, LastAccessed, Operations
```

**Indicator:**
- MailboxOwner != UserIds (delegate access)
- Operations = Search-MailboxAuditLog (programmatic search, not manual email reading)
- Large ResultSize (bulk exfiltration)

---

### 5. Identity Protection Risk Detections

**Portal Path:** Azure AD → Security → Identity Protection → Risky users / Risk detections

**PowerShell Query:**

```powershell
# Get current risk detections
Get-AzureADRiskyUser -All $true | Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-1) } |
    Select-Object UserPrincipalName, RiskState, RiskLastUpdatedDateTime

# Drill into a specific user's risk detections
Get-AzureADUserRiskDetection -UserId "user@tenant.com" -All $true |
    Where-Object { $_.RiskDetectionType -match "tokenIssuerAnomaly|atypicalSignInProperties" }
```

**High-Fidelity Alerts:**
- "Token Issuer Anomaly" — Refresh token used from unusual IP/device
- "Impossible Travel" — Sign-in from two geographies in impossible timeframe
- "Atypical Sign-in Properties" — Bulk enumeration / API access pattern unusual for this user

---

### 6. Conditional Access Logs: Policy Blocks / MFA Challenges

**Query (PowerShell):**

```powershell
# Query sign-in logs for Conditional Access blocks
Get-AuditLog -Filter "activityDisplayName eq 'Conditional Access'" -ResultSize unlimited |
    Where-Object { $_.CreatedDateTime -gt (Get-Date).AddDays(-1) } |
    Select-Object CreatedDateTime, UserIds, AuditData

# Or via Graph API (Conditional Access policy changes):
$uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
$policies = Invoke-RestMethod -Uri $uri -Headers $headers
$policies.value | Select-Object displayName, state, conditions, grantControls
```

**Indicators:**
- CA policy applied / block triggered on high-risk sign-in
- MFA challenged but user failed (or passed after multiple attempts, suggesting credential reuse/spray)

---

## Remediation (Before Acting)

**Before disabling accounts, rotating tokens, or removing groups, capture the following for forensic evidence:**

1. **Full Entra ID Sign-in Log Export** — Export to CSV for investigation timeline
   ```powershell
   Get-AuditLog -Filter "signInActivityEvents" -ResultSize unlimited | Export-Csv "SignInLogs.csv"
   ```

2. **Full Audit Log Export** — All audit events from the past 7 days
   ```powershell
   Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -ResultSize unlimited |
       Export-Csv "AuditLogs.csv"
   ```

3. **Memory Dump of Suspected PowerShell Process** — Preserve access tokens
   ```powershell
   # If the GraphRunner session is still active:
   procdump.exe -accepteula -ma powershell.exe C:\Forensics\powershell_dump.dmp
   ```

4. **Preserve PSReadline History File** — Copy before clearing
   ```powershell
   Copy-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "C:\Forensics\history.txt"
   ```

5. **Snapshot Entra ID Applications & Service Principals** — Identify backdoored apps registered during attack
   ```powershell
   Get-AzureADApplication -All $true | Export-Csv "Applications.csv"
   Get-AzureADServicePrincipal -All $true | Export-Csv "ServicePrincipals.csv"
   ```

**Then Take Remediation Actions:**

- Revoke all active sessions for the compromised user
  ```powershell
  Revoke-AzureADUserAllRefreshToken -ObjectId "user-object-id"
  ```

- Disable/delete backdoored OAuth applications
  ```powershell
  Remove-AzureADApplication -ObjectId "app-object-id"
  ```

- Reset passwords for compromised accounts
  
- Remove cloned/suspicious security groups
  ```powershell
  Remove-AzureADGroup -ObjectId "group-object-id"
  ```

- Review and remove suspicious delegated mailbox access
  ```powershell
  Remove-MailboxPermission -Identity "mailbox@tenant.com" -User "suspicious-user" -AccessRights FullAccess
  ```

- Enable/strengthen Conditional Access policies to prevent re-exploitation

---

## Evasion Techniques & Detection Bypass

The following evasion techniques may allow GraphRunner to evade detection; counter-measures are listed:

| Evasion Technique | How It Works | Counter-Measure |
|---|---|---|
| **Run from Memory (Invoke-Expression)** | PowerShell script fetched via WebClient, never written to disk | Event 4104 (Script Block Logging) captures function calls if enabled; Unified Audit Logs capture API calls; source-side proxy logs capture the download |
| **Disable PSReadline History** | `Remove-Item (Get-PSReadLineOption).HistorySavePath` before session | Event logs (4104) still capture if enabled; cloud-side Audit Logs are unaffected |
| **Use Proxy/VPN** | Operator requests routed through proxy to obscure source IP | Cloud-side audit logs show the proxy IP as the source, not the operator's real IP; temporal correlation with source-side commands still works |
| **Use Built-in Graph API Calls** | Operator calls `Invoke-RestMethod` directly instead of using GraphRunner functions | Audit logs still capture the API calls; the pattern (bulk enumeration, rapid app access) is still detectable |
| **Blend into Normal User Activity** | Spread requests over hours/days; mix with legitimate user activity | Harder to detect in noisy environments; risk/anomaly detection still flags impossible-travel or unusual resource access |
| **Use Refresh Token Abuse Instead of Password Reuse** | Refresh token obtained from token cache, no password needed | Identity Protection may still flag "tokenIssuerAnomaly" if token used from unusual IP; Entra audit logs still capture app access |
| **Clean Up Exfiltration Files** | Delete local `.json`/`.csv` files, PSReadline history | Unified Audit Logs on target are unchanged; file recovery may retrieve deleted files |

**Key Insight:** GraphRunner's strongest defense against evasion is **cloud-side audit logging**, which is tenant-controlled and much harder for the attacker to tamper with than local host artifacts.

---

## Fleet-Wide Detection

If hunting across an entire organization:

```powershell
# PowerShell (Entra ID / Office 365 Admin)

# 1. Find all tenants with risky sign-ins from the past 7 days
$signInLogs = Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -Operations UserLoggedIn -ResultSize unlimited
$riskyLogins = $signInLogs | Where-Object { $_.AuditData | ConvertFrom-Json | Select-Object -ExpandProperty RiskLevel -eq "High" }
$riskyLogins | Group-Object { ($_.AuditData | ConvertFrom-Json).UserPrincipalName } | Select-Object Name, Count

# 2. Find all application registrations from the past 7 days
Search-UnifiedAuditLog -Operations "Add application" -StartDate (Get-Date).AddDays(-7) -ResultSize unlimited |
    Select-Object UserIds, CreationDate, AuditData

# 3. Find all group manipulations (cloning indicator)
Search-UnifiedAuditLog -Operations @("Add member to group", "Create group") -StartDate (Get-Date).AddDays(-7) -ResultSize unlimited |
    Where-Object { $_.CreatedDateTime -gt $_.ModifiedDateTime } | # Same user creating + modifying rapidly
    Group-Object UserIds

# 4. Export high-value results to CSV
$results | Export-Csv "GraphRunner_Indicators.csv" -NoTypeInformation
```

**Correlation Across All Indicators:**
- If the same user appears in multiple log types (sign-in + group creation + app registration) within minutes, it's high-confidence GraphRunner usage
- Temporal proximity (within 5 seconds) between source-side PSReadline history and target-side audit logs is forensically strong

---

## Summary of Detection Approach

1. **Start with cloud-side indicators** (Entra ID sign-in logs, Audit Logs, Identity Protection) — these are attacker-hostile and tamper-proof
2. **Correlate with source-side artifacts** (PSReadline history, Event 4104) if available
3. **Use temporal proximity** (±5 seconds) to link source commands to target API calls
4. **Escalate on bulk activity patterns** (>50 file accesses, >100 API calls, rapid group/app modifications in seconds)
5. **Review for known evasion patterns** (memory-only runs, proxy use, token reuse) and apply specific detection rules
