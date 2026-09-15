# AADInternals — Detection and Hunting

## Contents
- [Hunting Priority](#hunting-priority)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority

Ranked by which AADInternals operator choices/evasion factors each signal survives — strongest (hardest to avoid) first.

| Rank | Signal | Survives | Defeated by |
|---|---|---|---|
| 1 | **Federation `SigningCertificate`/`NextSigningCertificate` thumbprint match** against the hardcoded `any_sts` certificate (SHA-1 `4B56E1F1B800243 59E34010D9AAB3CED9C67FF5E`) | Every operator, every version since 2018, any client-ID or IP/ASN evasion — the certificate itself never changes | Only defeated if an operator hand-modifies AADInternals' source to swap in a self-generated certificate before running `ConvertTo-Backdoor` — possible, but not the tool's default behavior, and not observed in Microsoft's own APT29/Storm-0501 reporting cited in `01 - Overview.md` |
| 2 | **`Token issuer anomaly` (`tokenIssuerAnomaly`) Identity Protection risk detection** | Any client-ID blending, any IP/ASN choice — this is a content-based detection on the SAML assertion itself, not on how it was delivered | Requires Microsoft Entra ID **P2** licensing; a P1/Free tenant only sees a generic "Additional risk detected" with no technique detail |
| 3 | **`Register device` Entra Audit Log entry** for an unexpected device/context | Client-ID blending (this is a directory write, not a sign-in) | Not defeated by any documented AADInternals flag — device registration always writes this audit entry |
| 4 | **`Suspicious API Traffic` (`suspiciousAPITraffic`) risk detection** on bulk enumeration | Client-ID blending | Requires P2 licensing; low-volume/targeted enumeration may stay under the detection's threshold |
| 5 | **`Unfamiliar sign-in properties`/`Anomalous Token` risk detections** on forged Kerberos/PRT/SAML sign-ins | Client-ID blending, works in real-time | Requires P2 licensing (Unfamiliar sign-in properties itself is real-time but still P2-gated); a "learning mode" period on new/low-activity accounts suppresses it; an operator who reuses a previously-seen IP/ASN/device fingerprint for the target avoids it entirely |
| 6 | **Source-host Script Block Logging (4104)** capturing full `Invoke-AADInt*`/`New-AADInt*` command lines | Nothing about the module itself — this is Windows/PowerShell logging posture | **Off by default** (see `LOLBins/powershell/`) — the single most common reason this signal is absent, not an AADInternals evasion at all |
| 7 | **Entra `AppDisplayName`/client-ID sign-in matching** ("Azure Active Directory PowerShell", "Microsoft Office") | Nothing — this is the *weakest* signal in this table by design | Deliberately blended with legitimate high-volume traffic; only useful layered with an anomaly (new device/ASN/geography), never alone |
| — | **Undocumented-API write actions** (`Set-DesktopSSO`, `Reset-ServiceAccount`) generating an Entra Audit Log entry | Unconfirmed | Flagged in `04 - Target Evidence.md` as an **open coverage question**, not ranked — validate empirically against a test tenant before relying on it |

## Hunting on Source

Standard PowerShell-host hunting applies in full — see `LOLBins/powershell/05 - Detection and Hunting.md` for the general technique. AADInternals-specific angles:

```powershell
# If Script Block Logging (4104) is enabled: search for the module's
# distinctive function-name vocabulary
Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -FilterXPath '*[System[(EventID=4104)]]' |
    Where-Object { $_.Message -match 'AADInt|ConvertTo-Backdoor|New-KerberosTicket|Reset-ServiceAccount|any_sts' }

# PSReadLine history — survives even with logging disabled
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" `
    -Pattern 'AADInt|ConvertTo-Backdoor|New-KerberosTicket|Join-DeviceToAzureAD'

# Look for the module itself staged on disk (Gallery install or git clone)
Get-ChildItem -Path "$env:USERPROFILE\Documents\*\Modules\AADInternals*", `
                     "$env:ProgramFiles\*\Modules\AADInternals*" -Recurse -ErrorAction SilentlyContinue

# Look for the tell-tale password-less device-registration PFX left in a
# working directory (see 03 - Source Evidence.md)
Get-ChildItem -Path C:\ -Recurse -Filter *.pfx -ErrorAction SilentlyContinue |
    ForEach-Object {
        try { $c = [Security.Cryptography.X509Certificates.X509Certificate2]::new($_.FullName)
              if ($c.HasPrivateKey) { $_ } } catch {}
    }
```

## Hunting on Target

**Rank-1 signal — the backdoor certificate, checked directly via Microsoft Graph:**

```powershell
Connect-MgGraph -Scopes "Domain.Read.All"

$knownBadThumbprint = "4B56E1F1B80024359E34010D9AAB3CED9C67FF5E"

Get-MgDomain -All | ForEach-Object {
    $fed = Get-MgDomainFederationConfiguration -DomainId $_.Id -ErrorAction SilentlyContinue
    foreach ($f in $fed) {
        foreach ($certProp in @($f.SigningCertificate, $f.NextSigningCertificate)) {
            if ($certProp) {
                $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($certProp))
                if ($cert.Thumbprint -eq $knownBadThumbprint) {
                    Write-Warning "AADInternals backdoor certificate found on domain $($_.Id)"
                }
            }
        }
    }
}
```

**KQL (Sentinel/Log Analytics) — Token issuer anomaly and Anomalous Token risk detections:**

```kql
AADUserRiskEvents
| where RiskEventType in ("tokenIssuerAnomaly", "anomalousToken", "suspiciousAPITraffic")
| project TimeGenerated, UserPrincipalName, RiskEventType, RiskLevel, DetectionTimingType, AdditionalInfo
| order by TimeGenerated desc
```

**KQL — sign-ins from the two blended-in client IDs, layered with an anomaly (per Rank-7's caveat, never alone):**

```kql
SigninLogs
| where AppId in ("1b730954-1685-4b74-9bfd-dac224a7b894", "d3590ed6-52b3-4102-aeff-aad2292ab01c")
| where ResultType == 0
| summarize IPs = make_set(IPAddress), ASNs = make_set(AutonomousSystemNumber), Count = count()
    by UserPrincipalName, bin(TimeGenerated, 1d)
| where array_length(IPs) > 3   // an ordinary admin's real AAD PowerShell usage is typically far more concentrated
```

**KQL — `Register device` and federation-settings audit events (Rank 3 / the backdoor's own write action):**

```kql
AuditLogs
| where OperationName in ("Register device", "Set domain authentication", "Set federation settings on domain")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
| order by TimeGenerated desc
```

Both queries above are direct applications of `Cloud/Microsoft/Entra ID/Audit Logs/Audit Logs for DFIR.md`'s and `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`'s own "Hunt at Scale" sections — nothing here re-derives those pages' general Entra hunting mechanics, only the AADInternals-specific filter values.

## Fleet-Wide Sweep

The certificate check above is already fleet-wide by construction (`Get-MgDomain -All`) — run it as a **standing scheduled hunt**, not just an incident-response step, since the certificate is a durable configuration artifact independent of any specific incident window. Pair it with:

```kql
// Every tenant domain whose federation config changed in the lookback window,
// regardless of which account/session made the change
AuditLogs
| where TimeGenerated > ago(90d)
| where OperationName has_any ("federation", "domain authentication")
| project TimeGenerated, InitiatedBy, OperationName, TargetResources
| order by TimeGenerated desc
```

```kql
// Every account whose device-registration count spiked in a single day —
// catches BPRT-style bulk device registration abuse
AuditLogs
| where OperationName == "Register device"
| summarize Devices = count() by InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName), bin(TimeGenerated, 1d)
| where Devices > 5
```

## Remediation

🔴 **Capture evidence before acting** — pulling the federation certificate value, the Audit Log entries, and any Identity Protection risk-detection records first preserves the case; several of the actions below (removing a federation trust, resetting AZUREADSSOACC$) are themselves disruptive to legitimate SSO and should be sequenced deliberately, not fired reflexively.

| Finding | Action |
|---|---|
| Backdoor certificate present on a domain's federation config | Remove it via `Update-MgDomainFederationConfiguration` (drop the `NextSigningCertificate`, or convert the domain back to Managed if it was never legitimately federated); rotate the *real* signing certificate afterward if the domain remains federated |
| AZUREADSSOACC$ hash confirmed stolen (on-prem DCSync) | Reset the AZUREADSSOACC$ password **both on-prem and in Azure AD together** (unlike `Set-AADIntDesktopSSO`'s optional on-prem sync, do both sides in the same maintenance window) and restart the Kerberos Key Distribution Center service on every DC — a stale KDC can serve tickets encrypted with the old key for up to its ticket lifetime |
| Unexpected device object(s) registered | Remove the device from Entra ID (`Remove-MgDevice`), and separately revoke any PRT/session derived from it (`Revoke-MgUserSignInSession` for the associated user, per `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`'s own respond guidance) |
| Rogue Global Administrator grant found | Remove the role assignment immediately; treat the granting account and any account it touched as compromised until proven otherwise, per `Cloud/Microsoft/Entra ID/Playbooks/Privileged Role Escalation.md` |
| Legacy per-user MFA disabled on an account | Re-enable it, and separately confirm Conditional-Access-based MFA is also enforced for that account — don't rely on the legacy control alone going forward |
| AAD Connect sync service account reset/created | Rotate its password again and review `DirectorySynchronizationAccount`-role membership for any account that shouldn't hold it |
| ADFS certificates exported from a compromised ADFS server | Rotate the ADFS token-signing/decryption certificates; every relying party (including Azure AD) needs the new certificate before the rotation completes, so this is a planned-maintenance action, not an instant fix |
| Order matters, per the existing Entra guidance | **Revoke sessions/tokens and disable the account before resetting its password** — a still-valid refresh token or forged PRT simply mints a new session after a password-only reset, per `Cloud/Microsoft/Entra ID/Sign-in Logs/Sign-in Logs for DFIR.md`'s own red flag on this exact failure mode |
