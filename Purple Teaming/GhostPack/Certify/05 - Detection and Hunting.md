# Certify — Detection and Hunting

**The single most important caveat on this page**: meaningful hunting for Certify's actual exploitation activity (as opposed to recon) requires **Certificate Services auditing to be explicitly enabled on the CA** — verified in `04 - Target Evidence.md`, this is off by default and needs both `certutil -setreg CA\AuditFilter 127` (plus a `CertSvc` restart) and the Object Access → "Audit Certification Services" subcategory turned on. **Without it, the CA's Security event log produces zero events for any Certify request/exploitation activity** — the CA's own request database (`certutil -view`) still has the record regardless, but that requires an active, deliberate query; it isn't something that lands in a SIEM on its own.

## Hunting Priority

Ranked by which signals survive Certify's own evasion/customization surface — a `Disarm`-built binary, `--skip-web-checks`, `--out-file` redirection, alternate-credential binds, reflective/`execute-assembly` delivery, and the fundamental fact that `forge` never touches a CA at all:

| Rank | Signal | Survives `Disarm` build? | Survives no CA auditing? | Survives `forge` (offline)? | Notes |
|---|---|---|---|---|---|
| 1 | CA's own request database (`certutil -view`) | N/A (only weaponized builds submit requests) | ✅ **Yes** — this is the point | ❌ No — `forge` never contacts a CA | The one signal that doesn't depend on Windows auditing configuration at all; always query this first for any `request`/`request-agent`/`request-download`/`request-renew` activity |
| 2 | DC-side PKINIT redemption evidence (4768, cross-linked to `Rubeus/04`) | N/A | ✅ Yes (DC-side, separate audit surface) | ✅ Yes — a forged cert is still redeemed via the same PKINIT path | Catches the *use* of any Certify-minted certificate regardless of how it was minted, but only once redemption actually happens |
| 3 | Forged-certificate 5-EKU fingerprint (`Any Purpose`+`Client Authentication`+`PKINIT Client Authentication`+`Smartcard Logon`+`Certificate Request Agent` together) | N/A (`forge` is compiled out of `Disarm`) | ✅ Yes — static cert inspection, no logging needed | ✅ **This is specifically the `forge`-produced signature** | Hardcoded in source (`CertForge.cs`), not configurable by the operator — the single strongest static indicator this page has for identifying a forged cert specifically |
| 4 | CA-wide config registry baseline diff (`EditFlags`/`InterfaceFlags`/`DisableExtensionList`) | N/A | ✅ Yes — direct registry read, not log-dependent | ❌ N/A — `forge` doesn't touch CA config | Detects `manage-ca`'s ESC6/ESC11/ESC16 backdoor toggles even with zero auditing |
| 5 | Template attribute/ACL baseline diff (LDAP) | N/A | ✅ Yes — direct LDAP read | ❌ N/A | Detects `manage-template`/ESC4 self-escalation even with zero Directory Service Changes auditing |
| 6 | CA Security-log events (4886–4889, 4868/4870/4880-4882/4891-4892) | N/A | ❌ **No** — this is the entire caveat above | ❌ N/A | Highest-fidelity signal when available, but conditional on non-default configuration most environments haven't done |
| 7 | Source-host process/network correlation (Sysmon 1/3, DCOM/LDAP/HTTP(S) connections) | ✅ Survives (enumeration still generates this) | ✅ Yes (source-side, independent of CA config) | ✅ Yes (the local key-generation step still runs) | Weakened by reflective loading/`execute-assembly` (no distinct `Certify.exe` process image) and by `--out-file` hiding output from console scrollback |
| 8 | Command-line switch/target-identity matching (`enum-templates`, `request`, `--upn`, etc.) | ✅ Survives | ✅ Yes | ✅ Yes | **Fully defeated** if invoked via `[Certify.Program]::MainString(...)` from a PowerShell reflection wrapper — only the wrapper's own, much less distinctive command line is visible then |
| 9 | PE metadata / static filename / binary hash | ❌ No | N/A | N/A | No official binary is ever released — no canonical signature exists, weakest signal by construction |

## Hunting on Source

**Process/network correlation for enumeration and weaponization verbs (rank 7):**

```powershell
# Sysmon Event ID 1, filtered for Certify's own verb vocabulary
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
    Where-Object { $_.Id -eq 1 -and $_.Message -match '(enum-templates|enum-cas|enum-pkiobjects|request-agent|request-download|request-renew|\brequest\b|\bforge\b|manage-ca|manage-template|manage-self)' }
```

```powershell
# Correlate with outbound LDAP/SMB/HTTP(S) connections from the same process (Sysmon Event ID 3)
Get-NetTCPConnection -RemotePort 389,636,445 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{ Process = $proc.ProcessName; PID = $proc.Id; Path = $proc.Path; RemotePort = $_.RemotePort; RemoteAddress = $_.RemoteAddress }
    } | Where-Object { $_.Process -notin @('lsass','svchost','System') }
```

**Local certificate store sweep — exportable certs and the forged-cert EKU fingerprint (rank 3):**

```powershell
# Every exportable private key in the current user's/machine's My store is worth a manual look --
# Certify's own CertEnrollment.cs marks every key it generates as exportable by default
Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.HasPrivateKey -and $_.PrivateKey.CspKeyContainerInfo.Exportable } |
    Select-Object Subject, Thumbprint, NotBefore, NotAfter, EnhancedKeyUsageList

# The specific forge() fingerprint: all five EKUs present together on one certificate
Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My | Where-Object {
    $ekus = $_.EnhancedKeyUsageList.ObjectId
    ($ekus -contains '2.5.29.37.0') -and ($ekus -contains '1.3.6.1.5.5.7.3.2') -and
    ($ekus -contains '1.3.6.1.5.2.3.4') -and ($ekus -contains '1.3.6.1.4.1.311.20.2.2') -and
    ($ekus -contains '1.3.6.1.4.1.311.20.2.1')
}
```

**Filesystem sweep for dropped `.pfx`/`.p12` files (`forge --output-path`, or manually-redirected `request` output):**

```powershell
Get-ChildItem -Path C:\ -Recurse -Include *.pfx,*.p12 -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\Windows\\System32\\|\\Program Files' }
```

**Redirected `--out-file` content sweep — anomalous text files carrying certificate/key material:**

```powershell
Get-ChildItem -Path C:\Users,C:\Temp,C:\ProgramData -Recurse -Include *.txt,*.log -ErrorAction SilentlyContinue |
    Select-String -Pattern 'BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY|Certify completed in' -List |
    Select-Object Path
```

## Hunting on Target

**CA request database — the always-available signal (rank 1), run regardless of audit configuration:**

```
:: On the CA server (or against it remotely with rights)
certutil -view -restrict "Request.RequesterName=*,Disposition=20" -out "RequesterName,CertificateTemplate,SubjectAltName2,NotBefore" | more

:: Narrow to a specific ESC1-shaped anomaly: a low-privileged requester naming a
:: privileged UPN in the SAN of an issued cert
certutil -view -restrict "Request.RequesterName=*,Disposition=20" -out "RequesterName,CertificateTemplate,SubjectAltName2" |
    findstr /i "administrator domain admins enterprise admins"
```

**CA-wide config baseline diff (rank 4) — compare against a known-good snapshot:**

```powershell
# Run periodically and diff against a stored baseline per CA
$ca = "ca01.ghostpack.local"; $caName = "GHOSTPACK-CA"
$key = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ca)
$policy = $key.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy")
[PSCustomObject]@{
    EditFlags            = $policy.GetValue("EditFlags")             # ESC6 if 0x00040000 bit set
    DisableExtensionList = $policy.GetValue("DisableExtensionList")  # ESC16 if szOID_NTDS_CA_SECURITY_EXT (1.3.6.1.4.1.311.25.2) present
}
```

**Template attribute/ACL baseline diff (rank 5) — flag ESC1/ESC9/ESC4-shaped drift:**

```powershell
# Requires the PSPKI module (or equivalent LDAP query) -- flags any template that now
# allows enrollee-supplied subjects with a client-auth-capable EKU and no approval gate
Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, pKIExtendedKeyUsage |
    Where-Object { ([int]$_."msPKI-Certificate-Name-Flag" -band 0x1) -and (-not $_.pKIExtendedKeyUsage -or $_.pKIExtendedKeyUsage -match '1\.3\.6\.1\.5\.5\.7\.3\.2') }
```

**CA Security-log events (rank 6 — only if auditing is confirmed enabled):**

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4886,4887,4888,4889} |
    Group-Object { ($_.Message -split "`n" | Select-String 'Requester Name:').ToString() } |
    Sort-Object Count -Descending
```

```powershell
# The loud CertSvc restart pair every manage-ca flag toggle produces
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4880,4881}
```

**PKINIT redemption on the DC — cross-linked, not re-derived:**

Apply `Rubeus/05 - Detection and Hunting.md`'s Event 4768 hunting queries directly against the DC(s) the certificate would authenticate to — a Certify-minted certificate redeemed via `Rubeus asktgt /certificate:` produces DC-side evidence with no Certify-specific shape of its own.

## Fleet-Wide Sweep

```powershell
# Every enterprise CA in the forest -- run the request-database query against each
$cas = Get-ADObject -LDAPFilter "(objectClass=pKIEnrollmentService)" `
    -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties dNSHostName, cn
foreach ($ca in $cas) {
    Write-Host "=== $($ca.dNSHostName)\$($ca.cn) ==="
    certutil -config "$($ca.dNSHostName)\$($ca.cn)" -view -restrict "Disposition=20" -out "RequesterName,CertificateTemplate,SubjectAltName2,NotBefore"
}
```

```powershell
# Every certificate template in the forest -- compare against a stored known-good
# baseline in one pass (build the baseline once, on a confirmed-clean domain state)
Get-ADObject -LDAPFilter "(objectClass=pKICertificateTemplate)" `
    -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,$((Get-ADRootDSE).configurationNamingContext)" `
    -Properties * | Export-Clixml -Path "\\fileshare\baselines\adcs-templates-$(Get-Date -f yyyyMMdd).xml"
```

## Remediation

**Capture the CA's own request-database record, any recovered `.pfx`/private key material, and the full event-log window (where available) before revoking certificates or resetting CA configuration** — revoking a certificate before its full scope of use is understood can burn evidence needed to determine what it was already used to access.

- **Harden ESC1-class templates**: remove `ENROLLEE_SUPPLIES_SUBJECT` wherever the template doesn't genuinely need enrollee-supplied subjects, or narrow the Enroll-rights group down from broad defaults (`Domain Users`/`Authenticated Users`) to the specific principals that actually need to enroll. Where enrollee-supplied subjects are genuinely required, require manager approval (`PEND_ALL_REQUESTS`) or authorized RA signatures instead of leaving both at zero.
- **Restrict Certificate Request Agent (ESC3) issuance**: limit which templates carry the Certificate Request Agent EKU, and restrict enrollment on those templates to a small, monitored set of principals — an Enrollment Agent certificate is functionally a skeleton key for requesting certificates as anyone else.
- **Tighten template ACLs (ESC4)**: audit every template for low-privileged or unexpected `WriteOwner`/`WriteDacl`/`GenericAll`/unrestricted `WriteProperty` grants — GhostPack's own [`PSPKIAudit`](https://github.com/GhostPack/PSPKIAudit) (released alongside Certify's original whitepaper) is purpose-built for this sweep.
- **Disable CA-wide backdoor flags (ESC6/ESC11/ESC16)**: confirm `EDITF_ATTRIBUTESUBJECTALTNAME2` is unset, `IF_ENFORCEENCRYPTICERTREQUEST` is set (enforce RPC packet-privacy on certificate requests), and `DisableExtensionList` does not contain `szOID_NTDS_CA_SECURITY_EXT` — restart `CertSvc` after any correction, matching the same mechanism `manage-ca` itself uses.
- **Restrict CA role delegation (ESC7)**: audit `ManageCA`/`ManageCertificates` role grants on every CA the same way template ACLs are audited — these roles let a holder approve/deny/reissue requests and, in some configurations, escalate further.
- **Enable NTLM relay protections for web enrollment (ESC8)**: require Extended Protection for Authentication (channel binding) on any `certsrv`/CES/CEP endpoint, or disable HTTP(S) web enrollment entirely where not needed.
- **Rotate the CA's own signing key if a `forge`-class compromise is confirmed** — a stolen CA private key invalidates trust in every certificate that CA has ever issued or ever will issue until re-keyed; this is the AD CS equivalent of a `krbtgt` double-reset and should be treated with the same urgency and blast-radius awareness.
- **Enable the auditing this page's target-side hunts depend on**: `certutil -setreg CA\AuditFilter 127` plus a `CertSvc` restart, the Object Access → "Audit Certification Services" subcategory, "Audit: Force audit policy subcategory settings" (so a legacy basic policy can't silently override it back off), and Directory Service Changes auditing with a SACL on the Certificate Templates container (for 5136-based ESC4/`manage-template` detection) — none of these are default, and every one of them is a real detection gap until explicitly configured.
