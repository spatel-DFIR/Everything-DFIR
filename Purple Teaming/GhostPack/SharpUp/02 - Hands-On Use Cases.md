# SharpUp — Hands-On Use Cases

Every command below is verified against [`GhostPack/SharpUp`](https://github.com/GhostPack/SharpUp)'s `README.md` and source (`SharpUp/Program.cs`, every file under `SharpUp/Checks/`). Check names use the actual reflected class names, not the README's own (in one case incorrect — see `01 - Overview.md`) hand-typed list.

## Contents
- [Full Unattended Audit Sweep](#full-unattended-audit-sweep)
- [Default Gated Run — Letting the Built-In Check Do the Triage](#default-gated-run--letting-the-built-in-check-do-the-triage)
- [Discovering Unquoted Service Paths](#discovering-unquoted-service-paths)
- [Discovering Modifiable Services — Service DACL Abuse](#discovering-modifiable-services--service-dacl-abuse)
- [Discovering Modifiable Service Binaries](#discovering-modifiable-service-binaries)
- [Discovering Modifiable Service Registry Keys](#discovering-modifiable-service-registry-keys)
- [Discovering AlwaysInstallElevated](#discovering-alwaysinstallelevated)
- [Discovering Hijackable %PATH% Directories](#discovering-hijackable-path-directories)
- [Discovering Hijackable DLLs in Running Processes](#discovering-hijackable-dlls-in-running-processes)
- [Discovering Modifiable Scheduled Task Files](#discovering-modifiable-scheduled-task-files)
- [Harvesting Cached GPP Passwords (Local Cache)](#harvesting-cached-gpp-passwords-local-cache)
- [Harvesting GPP Passwords From Domain SYSVOL](#harvesting-gpp-passwords-from-domain-sysvol)
- [Harvesting McAfee SiteList.xml Credentials](#harvesting-mcafee-sitelistxml-credentials)
- [Harvesting Unattended-Install Answer Files](#harvesting-unattended-install-answer-files)
- [Harvesting Registry Autologon Credentials](#harvesting-registry-autologon-credentials)
- [Enumerating Modifiable Registry AutoRun Targets](#enumerating-modifiable-registry-autorun-targets)
- [Enumerating Abusable Token Privileges](#enumerating-abusable-token-privileges)
- [In-Memory Execution via a C2 Loader](#in-memory-execution-via-a-c2-loader)
- [Chained Workflow — Recon to Privesc Enumeration to Abuse](#chained-workflow--recon-to-privesc-enumeration-to-abuse)

---

## Full Unattended Audit Sweep

**MITRE ATT&CK:** No single ID — this runs every check below, each individually tagged.

```
SharpUp.exe audit
```

Runs all 15 checks regardless of the caller's current integrity level or local-admin group membership — the explicit override of `PrivescChecks()`'s default gate (see `01`'s dispatch diagram). This is the realistic "run everything and see what comes back" invocation an operator uses on a fresh, not-yet-elevated foothold, and is also the only way to get thorough results on a host where the caller is *already* a local administrator but wants the full picture anyway (SharpUp's own console output warns explicitly in this case: *"Note: Running audit mode in high integrity will yield a large number of false positives"*, since checks like `ModifiableServices` will trivially show every service as writable once already running with admin rights).

## Default Gated Run — Letting the Built-In Check Do the Triage

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery) for the integrity/admin check itself

```
SharpUp.exe
```

With **no** `audit` argument and no check names, `Program.Main()` prints usage and exits (identical to `-h`) — SharpUp requires at least one argument to do anything. The realistic "gated" invocation always names at least `audit` or a specific check; there is no bare "run everything if I'm not elevated yet" mode without explicitly typing `audit`. Operators who want the gate's protection (skip the run entirely if already elevated) but still want the full sweep when it *does* run should use exactly `SharpUp.exe audit` — the gate only fires when `audit` is present at all, so this "gated-but-full" behavior is really just `audit`'s own quit-early logic, not a separate mode.

## Discovering Unquoted Service Paths

**MITRE ATT&CK:** [T1574.009](https://attack.mitre.org/techniques/T1574/009/) (Hijack Execution Flow: Path Interception by Unquoted Path)

```
SharpUp.exe audit UnquotedServicePath
```

Reads `ImagePath` directly from every subkey of `HKLM\SYSTEM\CurrentControlSet\Services` (no WMI, no `sc qc`), finds any value with an unquoted path containing a space before the `.exe` token, then checks whether the current principal can write into any of the resulting ambiguous parent-folder candidates (e.g. `C:\Program Files\My`, if the real target is `C:\Program Files\My App\svc.exe`). Reports the service name, its configured start type (`Automatic`/`Manual`/`Disabled`), the full path, and the specific writable sub-path.

## Discovering Modifiable Services — Service DACL Abuse

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) (Create or Modify System Process: Windows Service)

```
SharpUp.exe audit ModifiableServices
```

For every service returned by `ServiceController.GetServices()`, obtains a raw SCM handle via reflection into `ServiceController`'s own private `GetServiceHandle()` method, then P/Invokes `QueryServiceObjectSecurity()` against that handle and walks the resulting DACL for any `AccessAllowed` ACE granting the current principal (by direct SID or group membership) `ChangeConfig`, `WriteDac`, `WriteOwner`, `GenericAll`, `GenericWrite`, or `AllAccess`. This is the SCM-API-level check — a positive hit means the operator can legitimately call `ChangeServiceConfig`/`sc config` against that service without needing filesystem or registry write access at all.

## Discovering Modifiable Service Binaries

**MITRE ATT&CK:** [T1574.010](https://attack.mitre.org/techniques/T1574/010/) (Hijack Execution Flow: Services File Permissions Weakness)

```
SharpUp.exe audit ModifiableServiceBinaries
```

Queries `Win32_Service` over WMI (`root\cimv2`), regex-extracts the binary path from each service's `PathName`, and runs `CheckModifiableAccess()` (filesystem ACL check) against that specific EXE/DLL/SYS file. A hit means the service's own security is irrelevant — the operator can overwrite the binary on disk directly and let the service (or a reboot) execute it with whatever privilege the service account holds.

## Discovering Modifiable Service Registry Keys

**MITRE ATT&CK:** [T1574.011](https://attack.mitre.org/techniques/T1574/011/) (Hijack Execution Flow: Services Registry Permissions Weakness)

```
SharpUp.exe audit ModifiableServiceRegistryKeys
```

For every service, opens `HKLM\SYSTEM\CurrentControlSet\Services\<name>` directly and checks the registry key's own ACL (`ChangePermissions`/`FullControl`/`TakeOwnership`/`SetValue`/`WriteKey`) — a distinct check from `ModifiableServices` above, because a misconfigured **registry** ACL bypasses the Service Control Manager's own access model entirely: an operator with `SetValue` on the key can overwrite `ImagePath` directly with `reg.exe`/`Set-ItemProperty` without ever calling `ChangeServiceConfig` or touching the SCM API at all, which is exactly why this is its own MITRE sub-technique rather than a variant of T1543.003.

## Discovering AlwaysInstallElevated

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Abuse Elevation Control Mechanism: Bypass User Account Control)

```
SharpUp.exe audit AlwaysInstallElevated
```

Reads `AlwaysInstallElevated` under `Software\Policies\Microsoft\Windows\Installer` in both `HKCU` and `HKLM`. **The real-world exploitable condition requires the value to be `1` in *both* hives** — Windows Installer only grants SYSTEM-level MSI installs when both policies agree. **SharpUp's own check does not verify this**: `RegistryUtils.GetRegValue()` returns an empty string only when the value is entirely absent, so a value that exists but is literally `0` (policy explicitly disabled) still reads back as the non-empty string `"0"` and flips `_isVulnerable = true`. Treat any `AlwaysInstallElevated` hit from SharpUp as **"a value exists — go verify it's actually `1` in both hives before treating this as exploitable"**, not as a pre-verified finding; this is a real, source-confirmed false-positive path, distinct from PowerUp's PowerShell original which explicitly checks both keys equal `1`.

## Discovering Hijackable %PATH% Directories

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (Hijack Execution Flow: DLL), [T1574.007](https://attack.mitre.org/techniques/T1574/007/) (Path Interception by PATH Environment Variable)

```
SharpUp.exe audit HijackablePaths
```

Reads the **system-wide** `%PATH%` from `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` (not the per-user `HKCU` `Path`, and not the process's own resolved runtime environment variable), splits on `;`, and runs a filesystem ACL check against each folder. A writable directory earlier in `%PATH%` than the legitimate copy of a commonly-invoked binary is a classic search-order-hijack primitive — drop a same-named malicious EXE/DLL there and wait for anything that resolves the binary by name alone.

## Discovering Hijackable DLLs in Running Processes

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (Hijack Execution Flow: DLL)

```
SharpUp.exe audit ProcessDLLHijack
```

A structurally different check from `HijackablePaths` above: instead of searching static `%PATH%` directories, this enumerates **every currently running process** (`Process.GetProcesses()`) and walks each one's already-loaded `.Modules` collection, flagging any `.dll` that (a) isn't in the `KnownDlls` registry list, (b) isn't rooted under `C:\Windows`, and (c) the current principal can write to. Because this touches every reachable PID on the host to read its module list, it's the single noisiest check in the tool from a process-interaction standpoint — see `03 - Source Evidence.md`. Findings under `C:\Program Files` are explicitly flagged by the tool's own console output as more likely to be false positives requiring manual verification.

## Discovering Modifiable Scheduled Task Files

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task)

```
SharpUp.exe audit ModifiableScheduledTaskFile
```

**Note the exact name** — the README's own usage text says `ModifiableScheduledTask`; the real class (and the only name the argument parser actually matches) is `ModifiableScheduledTaskFile`, confirmed in `01`'s discrepancy note. Iterates every XML file under `%SystemRoot%\System32\Tasks` (or `SysWOW64\Tasks` on a 32-bit process), checks whether the task's own XML file is writable and/or whether the `<Command>` element's target binary is writable, and reports both permission states per task alongside the task's own name/path.

## Harvesting Cached GPP Passwords (Local Cache)

**MITRE ATT&CK:** [T1552.006](https://attack.mitre.org/techniques/T1552/006/) (Unsecured Credentials: Group Policy Preferences)

```
SharpUp.exe audit CachedGPPPassword
```

Recursively searches `%ALLUSERSPROFILE%\Microsoft\Group Policy\History` for `Groups.xml`/`Services.xml`/`Scheduledtasks.xml`/`DataSources.xml`/`Printers.xml`/`Drives.xml`/`Registry.xml`, parses out any `cpassword` attribute, and decrypts it with the static AES key Microsoft published as part of MS14-025 — see [`Windows/GPO/02 - GPO Content Deep Dive`](<../../../Windows/GPO/02%20-%20GPO%20Content%20Deep%20Dive%20%28Registry.pol%2C%20GPP%2C%20Scripts%2C%20Security%20Templates%29.md>) for the shared decryption mechanics, not re-derived here. This searches the **local machine's own cached copy** of policy files it has already applied — no network access required.

## Harvesting GPP Passwords From Domain SYSVOL

**MITRE ATT&CK:** [T1552.006](https://attack.mitre.org/techniques/T1552/006/) (Unsecured Credentials: Group Policy Preferences)

```
SharpUp.exe audit DomainGPPPassword
```

The network-reaching sibling of the check above: walks `\\<USERDNSDOMAIN>\SYSVOL` directly (a live, authenticated SMB read under the caller's own token — no separate credential switch exists) rather than relying on a local cache copy, so it finds GPP passwords in policies that exist on the DC even if this specific host never applied them. Exits immediately with `"Error: Machine is not a domain member or User is not a member of the domain"` if `USERDNSDOMAIN` isn't set — this is the **one check in SharpUp that generates network traffic to another host**, covered in full in `04 - Target Evidence.md`.

## Harvesting McAfee SiteList.xml Credentials

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)

```
SharpUp.exe audit McAfeeSitelistFiles
```

Recursively searches `Program Files`, `Program Files (x86)`, `Documents and Settings`, and `Users` for any file literally named `SiteList.xml` — the legacy McAfee ePolicy Orchestrator repository-configuration file, historically shipping with a reversibly-encrypted (3DES, static key) repository credential. SharpUp only locates the file; it does not decrypt the credential itself.

## Harvesting Unattended-Install Answer Files

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)

```
SharpUp.exe audit UnattendedInstallFiles
```

Checks nine hardcoded, well-known paths (`sysprep.xml`, `sysprep.inf`, `Panther\Unattend.xml`, `System32\Sysprep\unattend.xml`, and variants) for plain existence — no ACL check, no content parsing. A hit simply means one of these legacy answer files, which historically embed a local Administrator password, is still present on disk.

## Harvesting Registry Autologon Credentials

**MITRE ATT&CK:** [T1552.002](https://attack.mitre.org/techniques/T1552/002/) (Unsecured Credentials: Credentials in Registry)

```
SharpUp.exe audit RegistryAutoLogons
```

Reads `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`. Only reports a finding if `AutoAdminLogon` is literally `"1"` **and** either `DefaultUserName` or `AltDefaultUserName` is non-empty — at that point it dumps `DefaultDomainName`/`DefaultUserName`/`DefaultPassword`/`AltDefaultDomainName`/`AltDefaultUserName`/`AltDefaultPassword` verbatim, since Windows itself stores this credential in plaintext for the autologon feature to work.

## Enumerating Modifiable Registry AutoRun Targets

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder)

```
SharpUp.exe audit RegistryAutoruns
```

Reads all eight `Run`/`RunOnce`/`RunService`/`RunOnceService` locations (native and `Wow6432Node`) under `HKLM`, regex-extracts each value's target binary path (`.exe`/`.bat`/`.ps1`/`.vbs`), and checks write access on it. Because these run keys execute at every logon/boot as whichever user logs on, a writable target here is a direct route from "current low-priv write access" to "code execution as the next admin who logs into this box" — not necessarily an immediate SYSTEM primitive the way the service checks are.

## Enumerating Abusable Token Privileges

**MITRE ATT&CK:** [T1134](https://attack.mitre.org/techniques/T1134/) (Access Token Manipulation) — enumeration only; SharpUp does not itself perform token duplication/impersonation or exploit any privilege found

```
SharpUp.exe audit TokenPrivileges
```

Walks the current token's full privilege set via `GetTokenInformation(TokenPrivileges)` and flags any of 9 named high-value privileges present (`SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, `SeSystemEnvironmentPrivilege`, `SeImpersonatePrivilege`, `SeTcbPrivilege`), reporting each one's current attribute state (`SE_PRIVILEGE_ENABLED`/`DISABLED`/`ENABLED_BY_DEFAULT`). **A privilege reported here is one the token already holds** — SharpUp has no `Enable-Privilege` equivalent to actually turn a disabled-but-assigned privilege on; that step, and any follow-on exploitation (e.g. a `SeImpersonatePrivilege` potato-family exploit, or `SeBackupPrivilege`-based file read of `SAM`/`NTDS.dit`), is a separate tool entirely.

## In-Memory Execution via a C2 Loader

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) for the hosting mechanism itself; the check(s) run inside carry whatever ID is listed above

```
execute-assembly C:\Tools\SharpUp.exe audit
```

Same reflective-.NET-assembly loading pattern already documented for `Rubeus/` and `Seatbelt/` — Cobalt Strike's `execute-assembly`, Covenant's equivalent, or Sliver's `execute-assembly` all host a CLR inside an existing beacon/implant process and invoke `SharpUp.Program.Main()` directly, with no `SharpUp.exe` ever touching disk on the target. Because SharpUp targets .NET Framework 3.5 (one generation older than Rubeus/Seatbelt's 4.0+/4.8 range), whether AMSI's CLR-level hook applies depends entirely on the **loader's own hosted CLR version**, not SharpUp's declared target framework — see `03 - Source Evidence.md` for the detail.

## Chained Workflow — Recon to Privesc Enumeration to Abuse

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/), [T1574.011](https://attack.mitre.org/techniques/T1574/011/), [T1543.003](https://attack.mitre.org/techniques/T1543/003/)

```
# 1. General host recon on initial foothold
Seatbelt.exe -group=all -q

# 2. Privesc-specific enumeration once general recon is done
SharpUp.exe audit

# 3. SharpUp reports "Services with Modifiable Registry Keys" -> WeirdSvc is hit
#    Confirm and abuse directly against the registry (bypasses the SCM ACL entirely)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WeirdSvc" /v ImagePath /t REG_EXPAND_SZ /d "C:\Windows\Temp\evil.exe" /f
sc.exe start WeirdSvc

# 4. Alternatively, if SharpUp instead reports "Modifiable Services" (SCM DACL, not registry) -
#    use PowerUp's in-process API call rather than a raw registry write:
#    see Purple Teaming/PowerSploit/PowerUp/02 for Set-ServiceBinaryPath's ChangeServiceConfig path
```

This is the realistic division of labor between the tools already built in this repo: **`Seatbelt`** answers "what does this host look like in general" (AV/EDR, browsers, cloud creds, persistence surface); **`SharpUp`** narrows specifically to the local-privesc surface `Seatbelt` doesn't dig into as deeply; and the actual abuse step is handed off to whichever tool fits the specific finding — a raw `reg`/`sc` command for a registry-ACL or SCM-ACL hit, or `PowerSploit/PowerUp/`'s `Write-ServiceBinary`/`Set-ServiceBinaryPath` for the weaponization SharpUp itself deliberately doesn't implement.
