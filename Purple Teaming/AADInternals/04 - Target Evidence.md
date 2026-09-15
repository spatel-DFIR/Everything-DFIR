# AADInternals — Target Evidence

This is a cloud-attack tool, so "target evidence" is overwhelmingly **Entra ID / Microsoft 365 log data**, not Windows Event Viewer — the exception is the two on-prem-server use cases (Azure AD Connect, ADFS), covered separately below. `Cloud/Microsoft/Entra ID/` already documents this repo's full Entra logging architecture in depth; this file gives the AADInternals-specific values within that architecture and cross-links rather than re-deriving field-by-field mechanics.

## Contents
- [The One Thing to Check First: Nothing Logs the Unauthenticated Recon](#the-one-thing-to-check-first-nothing-logs-the-unauthenticated-recon)
- [Entra ID Sign-in Logs](#entra-id-sign-in-logs)
- [Entra ID Audit Logs](#entra-id-audit-logs)
- [Identity Protection Risk Detections](#identity-protection-risk-detections)
- [The Backdoor Certificate as a Standing, Queryable Artifact](#the-backdoor-certificate-as-a-standing-queryable-artifact)
- [Microsoft 365 Unified Audit Log](#microsoft-365-unified-audit-log)
- [On-Prem Target Artifacts — Azure AD Connect and ADFS Servers](#on-prem-target-artifacts--azure-ad-connect-and-adfs-servers)
- [Building a Timeline](#building-a-timeline)

---

## The One Thing to Check First: Nothing Logs the Unauthenticated Recon

`Invoke-AADIntReconAsOutsider`, `Invoke-AADIntUserEnumerationAsOutsider`, and the ADFS relaying-party read all hit **public, unauthenticated Microsoft endpoints** — `.well-known/openid-configuration`, `common/GetCredentialType`, `GetUserRealm.srf`, and a public ADFS page — none of which is a sign-in attempt. **None of them produces an Entra ID Sign-in Log or Audit Log entry**, because both logs are scoped to authenticated activity against the tenant's own directory, not to anonymous requests against Microsoft's shared, tenant-agnostic front-end. An analyst working purely from tenant-side logs will never see this phase — it has to be caught upstream (source-host network egress, or a WAF/CDN in front of a custom login page that happens to also front these Microsoft-hosted endpoints, which is rare). This is the direct cloud-native analog of `NetExec/`'s null-session finding: the richest recon happens below the logging floor by design, not by evasion.

## Entra ID Sign-in Logs

Full field-by-field mechanics, retention, and collection commands live in `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md` — this section gives the AADInternals-specific values within that structure.

- **`AppDisplayName` will almost never say "AADInternals."** As covered in `01 - Overview.md`, the module authenticates using Microsoft's own first-party client IDs — expect **"Azure Active Directory PowerShell"** (`1b730954-1685-4b74-9bfd-dac224a7b894`, the large majority of calls) or **"Microsoft Office"** (`d3590ed6-52b3-4102-aeff-aad2292ab01c`). Neither name is inherently suspicious in a tenant with any legitimate AAD PowerShell or Office desktop usage — this directly defeats the "new/unusual tooling in AppDisplayName" red flag the Sign-in Logs page itself calls out, so don't rely on `AppDisplayName` alone.
- **Forged Kerberos/SAML/PRT sign-ins appear as fully successful, ordinary sign-ins** (`ResultType == 0`) — Azure AD has no way to distinguish a validly-signed forged credential from a genuine one at sign-in time. The signal is in the **surrounding context**, not the sign-in event's success/failure field:
  - A Desktop-SSO-forged sign-in (`New-KerberosTicket` → `-KerberosTicket`) shows `AuthenticationDetails` consistent with Seamless SSO, but from a source IP/ASN/device that has never previously performed Seamless SSO for that user, or from a location inconsistent with the organization's actual network egress — cross-reference against `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`'s "impossible travel"/"new country" red flags.
  - A federation-backdoor SAML sign-in (`Open-Office365Portal` after `ConvertTo-Backdoor`) shows a **non-interactive-looking sign-in with an unusually short chain back to any interactive MFA event** — the whole point of the technique is that the (now attacker-controlled) IdP is trusted to have already satisfied MFA, so `ConditionalAccessStatus` may show as **satisfied** despite no real MFA challenge ever having occurred for that session.
  - A PRT-forged token exchange (`New-UserPRTToken` → `-PRTToken`) surfaces primarily in **non-interactive sign-ins** — the Sign-in Logs page's own red flag "non-interactive sign-in with no interactive parent" applies directly.
- **New/rogue device registration** (`Join-AADIntDeviceToAzureAD`) produces its own device-join sign-in event distinguishable by `ClientAppUsed` and the device-registration resource — cross-reference the resulting device object's `deviceId`/registration timestamp against the Audit Log entry below.

## Entra ID Audit Logs

Full mechanics and collection commands live in `Cloud/Microsoft/Entra ID/Audit Logs/Audit Logs for DFIR.md`. AADInternals' write operations map to that page's existing phase table as follows:

| AADInternals action | Expected `activityDisplayName` | Notes |
|---|---|---|
| `Join-AADIntDeviceToAzureAD` | `Register device` | Matches the Audit Logs page's own "Device persistence" row exactly — check `initiatedBy` for a user context inconsistent with that user's normal devices |
| `ConvertTo-AADIntBackdoor` | `Set domain authentication` (Managed→Federated) or `Set federation settings on domain` (adding `NextSigningCertificate`) | The page's own "Federation backdoor" red flag row — **open `modifiedProperties` and diff the `SigningCertificate`/`NextSigningCertificate` value against the known thumbprint below** |
| `Set-AADIntDesktopSSO` | Uncertain / possibly absent | `Set-DesktopSSO` calls `<tenantId>.registration.msappproxy.net/register/EnableDesktopSso` directly — an Application Proxy registration endpoint, not a Microsoft Graph directory-write call. Whether Microsoft internally emits a corresponding `directoryAudits` entry for this specific endpoint **could not be confirmed from source or public documentation** — flagged as an open question rather than asserted either way; do not assume audit-log coverage here without validating against a live tenant. |
| `Reset-AADIntServiceAccount` | Uncertain / possibly absent | Same caveat — this hits the Azure AD Connect sync engine's binary WCF API, not a documented Graph write path |
| `Set-AADIntUserMFA -State Disabled` | `Disable Strong Authentication` | Matches the Audit Logs page's own "Defense evasion" row |
| `Reset-AADIntUserPasswordByUpn` | `Reset user password` / `Change user password` | Standard password-reset audit action |
| `Add-AADIntRoleMembers` (Global Admin grant) | `Add member to role` | Matches the Audit Logs page's own "Privilege escalation" row — filter for `Global Administrator`/`Company Administrator` as the target role |
| `Set-AADIntCompanySettings` / tenant policy writes | `Update company settings` / policy-specific action names | Broad tenant-configuration bucket |

**The two "uncertain" rows above are the most important finding in this file.** Several of AADInternals' most powerful backdoor primitives (Desktop SSO password overwrite, AAD Connect sync-account reset) deliberately route through Microsoft's own **undocumented internal APIs** rather than the standard Microsoft Graph write path that `directoryAudits`/Audit Logs are built to capture — the same "internal features not otherwise possible" positioning from `01 - Overview.md`'s History section may also mean these specific actions escape the audit trail an analyst would normally expect for any tenant-configuration change. Treat this as a real, unresolved coverage gap to validate empirically against a test tenant rather than a documented Microsoft guarantee either way.

## Identity Protection Risk Detections

Full mechanics live in `Cloud/Microsoft/Entra ID/Identity Protection/Identity Protection for DFIR.md`; the values below (verified live against Microsoft Learn's current risk-detection reference, updated April 2026) are the ones most likely to fire against specific AADInternals techniques — **all require Microsoft Entra ID P2** unless noted:

| Risk detection | `riskEventType` | Fires against |
|---|---|---|
| **Token issuer anomaly** | `tokenIssuerAnomaly` | The federation-backdoor SAML technique specifically — Microsoft's own description is "the SAML token issuer for the associated SAML token is potentially compromised... claims included in the token are unusual or match known attacker patterns," a close, direct match for `ConvertTo-Backdoor`/`New-SAMLToken` |
| **Anomalous Token** (sign-in and user) | `anomalousToken` | PRT-forged and refresh-token-replayed sessions — "unusual lifetime or a token played from an unfamiliar location" |
| **Suspicious API Traffic** (user risk) | `suspiciousAPITraffic` | Bulk Provisioning API/Graph API calls — "abnormal GraphAPI traffic or directory enumeration," a strong match for `Invoke-ReconAsInsider`/`Get-Users`/`Get-SyncObjects`-scale enumeration once authenticated |
| **Unfamiliar sign-in properties** | `unfamiliarFeatures` | Any forged sign-in (Kerberos, PRT, SAML) from an ASN/device/browser the target user hasn't used before — real-time, does **not** require Defender for Cloud Apps |
| **Possible attempt to access Primary Refresh Token (PRT)** | `attemptedPrtAccess` | Only fires if **Microsoft Defender for Endpoint** is deployed on the device `Get-AADIntUserPRTKeys` runs against — an endpoint-side detection, not a cloud-log one; irrelevant to PRT forging done entirely off a stolen device certificate away from any monitored endpoint |

**All of these are offline/near-real-time and Premium (P2)-gated except Unfamiliar sign-in properties (real-time).** A tenant on Entra ID Free or P1 sees only a generic "Additional risk detected" entry with no technique-specific detail for the P2-gated rows — a real, license-dependent visibility gap worth confirming before assuming any of these will fire.

## The Backdoor Certificate as a Standing, Queryable Artifact

Unlike almost everything else in this file, the federation-backdoor certificate from `01 - Overview.md`'s red flag is a **persistent tenant configuration artifact**, not a transient log entry — it remains in the domain's federation settings until explicitly removed, and is queryable at any time, not just during the incident window:

```powershell
Connect-MgGraph -Scopes "Domain.Read.All"
Get-MgDomainFederationConfiguration -DomainId "victim.com" |
    Select-Object IssuerUri, SigningCertificate, NextSigningCertificate
```

or, using AADInternals' own read-only detection helper against a domain you're authorized to check:

```powershell
Find-AADIntBackdoor -AccessToken $pt -DomainName "victim.com"
```

Compare any returned `SigningCertificate`/`NextSigningCertificate` value's thumbprint against the known-hardcoded value from `01 - Overview.md`: **SHA-1 `4B56E1F1B800243 59E34010D9AAB3CED9C67FF5E`**, subject `CN=hack.o365domain.org, O=Gerenios`. A match is definitive — see `05 - Detection and Hunting.md` for the fleet-wide sweep version of this query.

## Microsoft 365 Unified Audit Log

`Cloud/Microsoft/M365/Unified Audit Log/Unified Audit Log for DFIR.md` covers the UAL in full — it's worth checking here specifically because its **retention (180 days–1 year) is longer than the Entra Sign-in/Audit Log portal default (~30 days)**, and it independently captures many `AzureActiveDirectory` `RecordType` events that overlap the Entra Audit Log rows above, giving a second, longer-lived copy of the same evidence if the incident is discovered outside the 30-day portal window.

## On-Prem Target Artifacts — Azure AD Connect and ADFS Servers

Two AADInternals workflows target genuine on-prem Windows servers rather than the cloud tenant directly — for these, standard Windows target-evidence practice from `Windows/` applies in full:

- **Azure AD Connect server** (`Get-AADIntSyncConfiguration`, `Get-AADIntSyncObjects`, `Export-ADSyncToolsAADPassword`-equivalent reads): the operator needs an authenticated token, but once obtained, `Reset-ServiceAccount` and `Get-SyncObjects` calls hit the sync engine's own binary WCF API — this generates **no distinctive Windows Event Log signature of its own** beyond normal PowerShell/network activity on the AAD Connect box; treat this as a case where the source-evidence half of the equation (attacking-host command history/Script Block Logging, `03 - Source Evidence.md`) carries more weight than anything the AAD Connect server itself logs.
- **ADFS server** (`Export-AADIntADFSCertificates`): reading the token-signing/decryption certificates out of ADFS's configuration database/DKM container from an already-elevated session on the server doesn't require exploiting ADFS itself, so it produces no ADFS-specific event beyond ordinary local admin activity — the value here is almost entirely in local host forensics (process creation, PowerShell logging) rather than ADFS's own event log.

## Building a Timeline

1. **Anchor on the persistent artifact first if present** — the backdoor certificate (above) or a newly-registered device object don't expire, so start there regardless of when the incident was reported.
2. **Pull the Entra Audit Log for the suspected actor/timeframe**, filtering for the `activityDisplayName` values in the table above, especially `Set domain authentication`/`Set federation settings on domain` and `Register device`.
3. **Cross-reference each Audit Log hit against the Sign-in Log** for the same `initiatedBy` principal in the surrounding minutes — establishes the session/IP/device that performed the change, per `Cloud/Microsoft/Entra ID/Audit Logs/Audit Logs for DFIR.md`'s own "tie to the sign-in" step.
4. **Check Identity Protection's risk-detection history** for the same principal/timeframe — `Token issuer anomaly` or `Suspicious API Traffic` hits materially strengthen a timeline built otherwise from ordinary-looking successful sign-ins.
5. **Pull the Unified Audit Log for the same window** as a longer-retention cross-check, and to catch any Exchange Online/SharePoint/Teams activity performed with a token AADInternals acquired for those services.
6. **If an on-prem pivot is suspected** (AZUREADSSOACC$ hash theft), correlate backward into `Mimikatz/lsadump (DCSync)/`'s own target-evidence guidance for the on-prem DC — the cloud-side forged sign-in's timestamp should follow the on-prem DCSync event by minutes to hours, not days, in most real intrusions.
