# SharpUp — Overview

> 🔴 **Red Flag Principle:** SharpUp is a **pure read-only enumeration binary — "no weaponization functions have yet been implemented," in the project's own README** — and every requested check runs as its **own `Thread`** spawned in a tight loop and joined at the end, not sequentially like Seatbelt's dispatcher. The result is a sub-second burst of WMI, registry, and file-ACL queries across a dozen-plus unrelated artifact classes (services, scheduled tasks, `%PATH%`, every running process's loaded modules, SYSVOL) landing **concurrently** rather than one after another. Layer on top of that the tool's own default behavior: `Program.cs`'s `PrivescChecks()` checks the caller's integrity/admin status **first** and, unless the literal argument `audit` is supplied, silently **exits without running a single check** if the process is already high-integrity or is a medium-integrity local administrator — meaning the single most common real-world SharpUp invocation on an already-elevated foothold produces almost no check-related evidence at all, just a two-line console message.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/SharpUp`](https://github.com/GhostPack/SharpUp), its `README.md`, and the live commit/release/tag history via the GitHub API:

- **Primary author:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`), the same GhostPack author behind `Rubeus/` and `Seatbelt/` (both already built in this repo). **License:** BSD 3-Clause, copyright 2018 Will Schroeder.
- **Lineage — explicitly stated, not inferred.** The README's opening line: *"SharpUp is a C# port of various [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) functionality. Currently, only the most common checks have been ported; **no weaponization functions have yet been implemented.**"* This is the single fact that shapes this entire page — SharpUp is PowerUp's **discovery half only**. See [`PowerSploit/PowerUp/01 - Overview.md`](<../../PowerSploit/PowerUp/01%20-%20Overview.md>) for the full function inventory this was ported from and exactly what SharpUp leaves out (below).
- **First commit:** 2018-07-24. **Releases/tags:** verified live via the GitHub API — **zero, ever** (`gh api repos/GhostPack/SharpUp/releases` and `/tags` both return empty arrays). Same "we are not planning on releasing binaries" posture as Rubeus and Seatbelt, and the README says so explicitly under Compile Instructions: *"We are not planning on releasing binaries for SharpUp, so you will have to compile yourself :)"* — every real-world `SharpUp.exe` is a custom operator compile; there is no canonical hash or PE-metadata fingerprint to check a suspect binary against.
- **Build target:** .NET Framework **3.5**, confirmed directly in `SharpUp.csproj` (`<TargetFrameworkVersion>v3.5</TargetFrameworkVersion>`), built against Visual Studio 2015 per the README — one full Framework generation older than Rubeus/Seatbelt's 3.5/4.0/4.8 range, which matters for the AMSI discussion in `03 - Source Evidence.md`.
- **Development activity, verified against the live commit log:** the last functionally meaningful commits landed **2022-05-10/11** — community contributor `IceMoonHSV` added the `ModifiableScheduledTaskFile` and `ProcessDLLHijack` checks (two of the tool's 15 total), and `JohnLaTwC` patched a `TokenPrivileges` memory leak (missing `Marshal.FreeHGlobal`). The only commit since (2023-10-16) is a one-line `.csproj` housekeeping edit. The project is not archived, but it is effectively feature-frozen at 15 checks.
- **Acknowledged contributors** (per the README): Igor Korkhov (token-group/logon-SID code), JGU (file/folder ACL comparison), Rod Stephens (recursive file-enumeration pattern), SwDevMan81 (token-privilege enumeration), Nikki Locke (service security-descriptor querying), `Raikia` (unquoted-service-path search), `RemiEscourrou` (ACE-checking / modifiable service registry key code), `Coder666` (ACE filtering), `vysecurity` (Registry Auto Logon / Domain GPP Password), `djhohnstein` (merged outdated PRs, refactored the codebase).

## How It Works

SharpUp shares Seatbelt's reflection-driven plugin architecture — `GetAvailableChecks()` calls `Assembly.GetExecutingAssembly().GetTypes().Where(t => t.Namespace == "SharpUp.Checks")`, so every class dropped into the `Checks/` namespace is automatically discovered with no static registry to maintain — but it **diverges from Seatbelt in two structural ways worth knowing before reading any evidence page**:

1. **A check's entire enumeration logic runs inside its own constructor**, not a separate `Execute()` method. `Activator.CreateInstance(t)` in `Program.cs` is the line that actually *does the work* — `IsVulnerable()` and `Details()` (defined on the shared abstract `VulnerabilityCheck` base class) just return fields (`_isVulnerable`, `_details`) the constructor already populated. Seatbelt's `CommandBase.Execute()` pattern separates "instantiate" from "run"; SharpUp collapses them into one step.
2. **Every requested check gets its own `Thread`, not a sequential loop.** `PrivescChecks()` builds one `Thread` per `Type` in the requested-checks array, `.Start()`s all of them in a tight `foreach`, then `.Join()`s them all — a shared `Mutex` protects the results list from concurrent writes. Seatbelt runs checks **sequentially** (with an optional `-DelayCommands` throttle between them); SharpUp has no equivalent throttle and runs everything **at once**. This is the mechanical basis for the red-flag callout above.

### The integrity/admin gate — the actual default behavior

```
SharpUp.exe [audit] [check1] [check2]...
        │
        ▼
Program.Main() → GetChecksFromArgumentString(args)
        │  "audit" present?  → auditMode = true
        │  no check names after "audit"? → run ALL 15 checks
        │  otherwise → run only the named checks (still gated below)
        ▼
Program.PrivescChecks(checks)
        │
        ├─ IsHighIntegrity()  → WindowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator)
        │                        (a token-role check standing in for a true integrity-level
        │                         read — not GetTokenInformation(TokenIntegrityLevel))
        ├─ IsLocalAdmin()     → does the current token's group SID set contain S-1-5-32-544?
        │
        ├─ IF already high integrity:
        │     print "Already in high integrity, no need to privesc!"
        │     IF NOT auditMode → RETURN. Zero checks run. Zero evidence beyond this message.
        ├─ ELIF medium integrity but token is in Administrators:
        │     print "...UAC can be bypassed."
        │     IF NOT auditMode → RETURN. Same zero-check outcome.
        │
        ▼ (only reached if low-priv, OR audit mode forced past the gate above)
For each requested check type:
   spawn Thread → Activator.CreateInstance(t)   ← constructor IS the check logic
        │            (WMI / registry / file-ACL / Win32 P/Invoke, per check — see below)
        └─ mutex.WaitOne() → add to vulnerableChecks list if _isVulnerable → mutex.Release()
        ▼
All threads .Join()'d → console report: "=== <CheckName> ===" + Details() per vulnerable check
```

**No check ever shells out to `sc.exe`, `wmic.exe`, `schtasks.exe`, `icacls.exe`, or any other external process.** Every check reaches its target artifact through an in-process .NET API call — this is a genuine, source-verified parallel to `PowerSploit/PowerUp/`'s own finding that `Set-ServiceBinaryPath` calls `Advapi32::ChangeServiceConfig` directly rather than shelling `sc config`: SharpUp's `ModifiableServices` check does the same thing one layer deeper, using **.NET reflection to call `ServiceController`'s own private `GetServiceHandle()` method** (`BindingFlags.NonPublic`) to obtain a raw SCM handle, then P/Invokes `QueryServiceObjectSecurity()` against that handle directly — SharpUp never calls `OpenSCManager`/`OpenService` itself; it borrows .NET's own internal handle.

### The 15 checks, by underlying mechanism

| Mechanism | Checks |
|---|---|
| Direct registry read (`Microsoft.Win32.Registry*`, no P/Invoke) | `AlwaysInstallElevated`, `RegistryAutoLogons`, `RegistryAutoruns`, `HijackablePaths` (reads the system `%PATH%` from `HKLM\...\Environment`), `ProcessDLLHijack` (reads `KnownDlls`) |
| Registry read + `ImagePath` string parsing (no WMI) | `UnquotedServicePath` — reads every subkey of `HKLM\SYSTEM\CurrentControlSet\Services` directly, unlike `ModifiableServiceBinaries` (below), which goes through WMI |
| WMI (`System.Management`, `root\cimv2`, `Win32_Service`) | `ModifiableServiceBinaries` (enumeration); `ModifiableServices`/`ModifiableServiceRegistryKeys` (metadata lookup only, after `ServiceController.GetServices()` does the actual enumeration) |
| Filesystem ACL check (`System.Security.AccessControl`, `Directory`/`File.GetAccessControl`) | `HijackablePaths`, `ModifiableServiceBinaries`, `RegistryAutoruns` (target-path check), `UnquotedServicePath` (directory-write check), `ModifiableScheduledTaskFile`, `ProcessDLLHijack` |
| Recursive filesystem search, no ACL check (existence/content only) | `CachedGPPPassword`, `DomainGPPPassword`, `McAfeeSitelistFiles`, `UnattendedInstallFiles` |
| Win32 P/Invoke via `SharpUp.Native.Win32` (`advapi32.dll`) | `TokenPrivileges` (`GetTokenInformation`/`LookupPrivilegeName`), `ModifiableServices` (`QueryServiceObjectSecurity`, reached via the reflection trick above) |
| Static-key AES decryption | `CachedGPPPassword`/`DomainGPPPassword` — the well-known, Microsoft-published GPP `cpassword` AES key; see [`Windows/GPO/02 - GPO Content Deep Dive`](<../../../Windows/GPO/02%20-%20GPO%20Content%20Deep%20Dive%20%28Registry.pol%2C%20GPP%2C%20Scripts%2C%20Security%20Templates%29.md>) for the full mechanics and MS14-025 history — not re-derived here |
| Live process module enumeration (`Process.GetProcesses()` → `.Modules`) | `ProcessDLLHijack` — the one check that touches **every running process on the box**, not just services/registry/files |

### What SharpUp does *not* port from PowerUp

Per the README's own framing ("only the most common checks... no weaponization functions"), the following PowerUp capabilities have **no SharpUp equivalent** at all: `Write-ServiceBinary`/`Install-ServiceBinary` (the pre-compiled-blob service-binary drop), `Write-HijackDll`, `Write-UserAddMSI` (`AlwaysInstallElevated` exploitation, as opposed to detection), `Add-ServiceDacl`, `Enable-Privilege` (SharpUp's `TokenPrivileges` only *reports* assigned-but-disabled privileges — it never enables one), `Get-ApplicationHost`/`Get-WebConfig` (IIS/ASP.NET config-file credential harvesting), and `Invoke-EventVwrBypass` (UAC bypass). SharpUp also **adds** one check PowerUp's own function list doesn't split out separately: `DomainGPPPassword` walks the live domain SYSVOL share as a distinct check from `CachedGPPPassword`'s local `%ALLUSERSPROFILE%\Microsoft\Group Policy\History` search.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Local registry API | `Microsoft.Win32.Registry` (`HKLM`/`HKCU`/`HKU` reads) — no remote-registry protocol involved anywhere |
| WMI | `System.Management.ManagementObjectSearcher` against local `root\cimv2` (`Win32_Service`) — always local; SharpUp has **no** `-computername`-style remote-targeting flag anywhere in `Program.cs`'s argument parser |
| Service Control Manager API | `QueryServiceObjectSecurity` via P/Invoke on a handle obtained through .NET reflection into `ServiceController.GetServiceHandle()` — never `OpenSCManager`/`OpenService` directly, never `sc.exe` |
| Windows Token APIs | `GetTokenInformation`/`LookupPrivilegeName` (P/Invoke, `TokenPrivileges`); `WindowsPrincipal.IsInRole()`/`WindowsIdentity.GetCurrent().Groups` (managed APIs, the integrity/admin gate and `IsLocalAdmin()`) |
| Filesystem ACL API | `System.Security.AccessControl` (`Directory.GetAccessControl`/`File.GetAccessControl`, `FileSystemRights`) |
| SMB | `DomainGPPPassword`'s `\\<USERDNSDOMAIN>\SYSVOL` walk — a normal authenticated UNC file read under the caller's own token, not a distinct protocol client |
| Cryptography | AES-256-ECB-equivalent decryption of GPP `cpassword` using Microsoft's own published static key (`4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8 f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b`) |
| Process/module enumeration | `System.Diagnostics.Process.GetProcesses()` + `.Modules` — implicitly opens every reachable process on the host to walk its loaded-module list (`ProcessDLLHijack`) |

## Command-Line Switches — Quick Reference

SharpUp takes **positional arguments only** — there is no `-flag`/`/flag` syntax anywhere. Verified directly against `Program.cs`'s `GetChecksFromArgumentString()`/`Usage()`.

| Argument | Plain-English meaning |
|---|---|
| *(none)* | Prints usage and exits — no checks run |
| `-h` / `--help` | Prints usage (the check-name list here is generated live via reflection, so it's always accurate — unlike the README's own hand-typed usage block, see the correction below) |
| `audit` | **Disables the integrity/admin gate.** Without this literal argument, SharpUp checks the caller's own integrity level first and silently exits if already elevated or a medium-integrity local admin — see the diagram above. With `audit` and no other arguments, runs **all 15 checks** regardless of privilege level |
| `audit <check1> [check2]...` | Forces the named check(s) to run past the gate |
| `<check1> [check2]...` (no `audit`) | Runs only the named check(s) — **but still subject to the same integrity gate**: if the process is already elevated, none of the named checks run either, since the gate check happens before the check list is ever consulted |

**The 15 check names** (case-insensitive exact match against the reflected class name — verified against every file in `SharpUp/Checks/`):

| Check | What it looks for |
|---|---|
| `AlwaysInstallElevated` | The `AlwaysInstallElevated` MSI-installer policy value under `HKLM`/`HKCU\Software\Policies\Microsoft\Windows\Installer` |
| `CachedGPPPassword` | Legacy Group Policy Preferences `cpassword` values in the local `%ALLUSERSPROFILE%\Microsoft\Group Policy\History` cache |
| `DomainGPPPassword` | The same `cpassword` values, but walking the live domain's `\\<domain>\SYSVOL` share directly |
| `HijackablePaths` | Directories on the system-wide `%PATH%` (`HKLM\...\Environment`) the current principal can write to |
| `McAfeeSitelistFiles` | McAfee ePO `SiteList.xml` files (historically embed a reversible-encryption credential) under common install/profile roots |
| `ModifiableScheduledTaskFile` | Scheduled-task XML files (or their target command binary) under `%SystemRoot%\System32\Tasks` that the current principal can write |
| `ModifiableServiceBinaries` | Service `PathName` targets (via WMI `Win32_Service`) whose on-disk binary the current principal can overwrite |
| `ModifiableServiceRegistryKeys` | `HKLM\SYSTEM\CurrentControlSet\Services\<name>` keys the current principal can write to directly — bypasses the SCM ACL entirely |
| `ModifiableServices` | Services whose own security descriptor (queried via `QueryServiceObjectSecurity`) grants the current principal `ChangeConfig`/`WriteDac`/`WriteOwner`/`GenericAll`/`GenericWrite`/`AllAccess` |
| `ProcessDLLHijack` | Writable, non-`KnownDlls`, non-`C:\Windows`-rooted DLLs already loaded by any currently running process |
| `RegistryAutoLogons` | Plaintext `DefaultPassword`/`AltDefaultPassword` values under `HKLM\...\Winlogon` when `AutoAdminLogon=1` |
| `RegistryAutoruns` | Writable target binaries referenced by `Run`/`RunOnce`/`RunService`/`RunOnceService` autorun registry keys (both native and `Wow6432Node`) |
| `TokenPrivileges` | Whether the current token holds any of 9 named high-value privileges (`SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeSecurityPrivilege`, `SeSystemEnvironmentPrivilege`, `SeTcbPrivilege`) — **detection only, SharpUp never enables a disabled one** |
| `UnattendedInstallFiles` | Presence of known unattended-Windows-install answer files (`sysprep.xml`/`sysprep.inf`/`Unattend.xml`, several path variants) that may embed a local-admin password |
| `UnquotedServicePath` | Services whose registry `ImagePath` has a space in an unquoted path, and whether any of the resulting ambiguous sub-paths is writable |

**A real, verified discrepancy worth knowing before scripting against this tool:** the README's hand-typed usage block lists the eleventh check as **`ModifiableScheduledTask`** — but the actual class (`SharpUp/Checks/ModifiableScheduledTaskFile.cs`) is named **`ModifiableScheduledTaskFile`**, confirmed both in source and by the live `-h` output (which is generated by reflecting over `GetAvailableChecks()`, not copied from the README). Running `SharpUp.exe ModifiableScheduledTask` — copy-pasted straight from the README — silently matches **zero** checks and produces `"Not vulnerable to any of the 0 checked modules."` with no error. Use `ModifiableScheduledTaskFile` (the real class name) instead.

## Quick Use-Case List

- Full unattended audit sweep post-foothold (`audit`), overriding the built-in integrity gate to get every finding regardless of current privilege
- A default, non-`audit` run — deliberately relying on the built-in gate so the tool self-terminates immediately if the foothold is already elevated (saves time/noise on hosts that don't need privesc)
- Targeted single-check runs for a specific technique class (`UnquotedServicePath`, `ModifiableServices`, `AlwaysInstallElevated`, etc.) rather than the full sweep
- Discovering unquoted service paths as a precursor to a manual or `PowerUp`-driven binary drop
- Discovering a service's own weak DACL (`ModifiableServices`) as a precursor to `sc config`/`PowerUp`'s `Set-ServiceBinaryPath` binPath hijack
- Discovering a writable service binary file (`ModifiableServiceBinaries`) as a precursor to overwriting the EXE/DLL in place
- Discovering a writable service registry key (`ModifiableServiceRegistryKeys`) — a path that bypasses the SCM's own ACL model entirely
- Discovering writable `%PATH%` directories (`HijackablePaths`) for a classic DLL/EXE search-order hijack
- Discovering hijackable DLLs already loaded by a **running** process (`ProcessDLLHijack`) — a live-process variant distinct from the static `%PATH%` check above
- `AlwaysInstallElevated` discovery as a precursor to an MSI-based SYSTEM-level install (weaponization itself is `PowerUp`'s `Write-UserAddMSI`, not SharpUp's)
- Discovering modifiable scheduled-task action files for a task-hijack persistence/privesc chain
- Harvesting cached GPP passwords from the local Group Policy History cache
- Harvesting GPP passwords by walking the live domain SYSVOL share directly
- Harvesting McAfee ePO `SiteList.xml` and unattended-install answer-file credentials in the same sweep
- Harvesting plaintext registry autologon credentials
- Enumerating writable autorun-key targets for follow-on persistence/privesc
- Enumerating abusable-but-disabled token privileges as a precursor to a separate exploitation tool (a named-pipe/potato-family exploit for `SeImpersonatePrivilege`, `SeBackupPrivilege`-based file access, etc. — SharpUp itself does not weaponize any of these)
- In-memory execution via a C2 loader's "execute .NET assembly" capability (Cobalt Strike `execute-assembly`, Covenant, Sliver `execute-assembly`) — same pattern documented for Rubeus/Seatbelt
- A chained workflow: `Seatbelt`/`BloodHound` general recon → `SharpUp audit` for the privesc-specific surface → `PowerSploit/PowerUp` or manual `sc`/registry abuse of whichever finding SharpUp surfaced

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are ever released — every deployment is a custom Visual Studio (.NET 3.5) build, run standalone or reflectively loaded (`execute-assembly`, `[Assembly]::Load()`) |
| Execution privileges | **Not required to run any individual check's underlying API calls** — but the tool's own default behavior gates on integrity/admin status first; pass `audit` explicitly to bypass that gate and force checks to run regardless of current privilege |
| Target OS | Windows only — every check is built on Win32 registry/token/service APIs and WMI; no cross-platform build exists |
| Domain membership (`DomainGPPPassword` only) | Requires `USERDNSDOMAIN` to be set (domain-joined host) and read access to the target DC's `SYSVOL` share — all 14 other checks are entirely local and need no network reachability at all |
| No remote-targeting capability | Unlike `Seatbelt/` (`-computername=`), SharpUp has no flag anywhere to run its checks against a second host — every check (`DomainGPPPassword` included) executes from, and enumerates, the local host SharpUp itself is running on |
