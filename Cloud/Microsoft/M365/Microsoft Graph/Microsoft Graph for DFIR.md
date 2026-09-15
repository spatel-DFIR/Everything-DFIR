# Microsoft Graph for DFIR

Graph is both your collection engine and the attacker's data-access path. This note is how you **spot Graph abuse, prove what an app/token pulled, and use Graph safely for your own collection.**

New to the service? Read **What is Microsoft Graph** first.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [Proving What Graph Accessed](#proving-what-graph-accessed)
- [How to Spot Graph-Mediated Access in the UAL](#how-to-spot-graph-mediated-access-in-the-ual)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there |
|--------|--------------|
| **Sign-in logs** | User + **service-principal** sign-ins with `ResourceDisplayName = Microsoft Graph` |
| **Permission grants** | What an app was allowed (`appRoleAssignments`/`oauth2PermissionGrants`) |
| **UAL** | The data-plane result (which mail/files were read) |
| **MDCA / app governance** | App behavior anomalies |

## Collect It

**Who/what is calling Graph, and with what:**

```kql
// App (service-principal) calls to Graph
AADServicePrincipalSignInLogs
| where ResourceDisplayName == "Microsoft Graph"
| summarize calls=count(), IPs=make_set(IPAddress) by ServicePrincipalName, AppId
| order by calls desc
```

```powershell
# What an app is allowed to do via Graph
$sp = Get-MgServicePrincipal -Filter "appId eq '<guid>'"
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id
```

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Identify the caller | User or app? Delegated or app-only? |
| 2. Read its permissions | High-value `*.All` scopes? |
| 3. Baseline the behavior | New Graph resources/volume vs the app's history |
| 4. Prove the data reach | Cross to UAL for `MailItemsAccessed`/`FileAccessed` by the identity |
| 5. Tie to access | Consent event or credential add that granted it (audit log) |

## Proving What Graph Accessed

🔴 Graph sign-ins tell you *who/what/when*; the **UAL** tells you *which data*. Correlate:

```powershell
# Did the app read mail? (needs advanced audit)
Search-UnifiedAuditLog -StartDate .. -EndDate .. -Operations "MailItemsAccessed" |
  Where-Object { $_.UserIds -eq "<app-or-upn>" }
```

If workload auditing was off, you can only bound the exposure by the app's **permissions** — assume it read what it could.

## How to Spot Graph-Mediated Access in the UAL

A UAL record for a file/mail access doesn't always mean the user's client touched it directly — it may have been pulled through Graph on the user's behalf. Three tells that a UAL record is **Graph-mediated**, not a direct client action:

| Tell | What it looks like | Why it matters |
|------|--------------------|-----------------|
| `ClientAppID` populated | A GUID (the calling app's App ID) present on the record | Direct Outlook/OWA/OneDrive-client actions usually leave this blank; a populated `ClientAppID` points at a specific app pulling the data |
| `ClientInfoString` contains `client=REST` | Literal substring in the field | Marks the call as coming through the Graph REST API rather than a native Office client protocol |
| `ClientIP` is a Microsoft datacenter IP | IP resolves to Microsoft/Azure infrastructure, not an ISP/residential/corporate range | 🔴 **Correlation gotcha:** if the app runs server-side (Azure Function, background job, another tenant's infra), Graph makes the call *on the app's behalf* — the logged `ClientIP` is Microsoft's, not the actor's real IP. Pivoting off `ClientIP` alone can miss or misattribute the true source |

🔴 When you see all three together, stop trusting `ClientIP` as "where the attacker was." Pivot instead to the **service-principal sign-in** (`AADServicePrincipalSignInLogs`) and the app's own network footprint (its hosting provider, deployment region) to find the real access point.

## Hunt at Scale

**Apps calling Graph from new IPs (possible stolen secret):**

```kql
AADServicePrincipalSignInLogs
| where ResourceDisplayName == "Microsoft Graph"
| summarize IPs=make_set(IPAddress), first=min(TimeGenerated) by AppId, ServicePrincipalName
| where array_length(IPs) > 1
```

**High-privilege Graph grants (from audit log):**

```kql
AuditLogs
| where OperationName == "Add app role assignment to service principal"
| where tostring(TargetResources) has_any ("Mail.Read","Directory.ReadWrite.All","Files.ReadWrite.All","RoleManagement.ReadWrite.Directory")
| project TimeGenerated, InitiatedBy, TargetResources
```

## Respond

| Goal | Action |
|------|--------|
| Cut a rogue app's Graph access | Disable the SP; remove app-role assignments |
| Cut a user's stolen-token Graph use | Revoke refresh tokens + disable |
| Remove persistence | Delete attacker-added app credentials/owners |
| Preserve | Capture the app's permissions, SP sign-ins, and UAL data-access before deleting |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Restrict user consent**; admin-consent workflow | Stops apps getting Graph scopes via phishing |
| **App governance / Workload ID Protection** | Detects anomalous Graph behavior + credential adds |
| **Least-privilege app permissions**; review `*.All` grants | Shrinks blast radius |
| **CA for workload identities** (P2) | Gate app sign-ins by IP/risk |
| **Enable advanced audit** | Prove Graph data access |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| App-only Graph with `Mail.Read`/`.All` scopes | Tenant-wide silent access |
| SP calling Graph from a new/hosting IP | Stolen secret / rogue app |
| New Graph resources/volume vs baseline | App behavior change (compromise) |
| `RoleManagement.ReadWrite.Directory` via Graph | Self-escalation to Global Admin |
| Consent/credential grant right before Graph spike | Access → action chain |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What Graph is + permissions | **Microsoft Graph → What is** |
| Apps / consent / credentials | **Entra → Applications & Service Principals** |
| App sign-ins | **Entra → Sign-in Logs** |
| Which data was read | **M365 → Unified Audit Log** |
| The illicit-consent chain | **Entra → Playbooks → Illicit Consent Grant** |

## Resources

- Graph permissions reference — https://learn.microsoft.com/graph/permissions-reference
- App governance — https://learn.microsoft.com/defender-cloud-apps/app-governance-manage-app-governance
- Investigate compromised/malicious apps — https://learn.microsoft.com/security/operations/incident-response-playbook-compromised-malicious-app
- MITRE ATT&CK: T1114 Email Collection / T1213 Data from Information Repositories — https://attack.mitre.org/techniques/T1213/
