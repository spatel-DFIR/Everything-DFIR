# PowerUp — Overview

> 🔴 **Red Flag Principle:** PowerUp does not compile anything at run time. Its service-abuse payload (`Write-ServiceBinary`) is a **pre-compiled C# service executable stored as a hardcoded Base64 blob inside the script itself** — verified directly in the live source (a literal `$B64Binary = "TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAA..."`, a valid MZ/PE header once decoded). Every service binary PowerUp ever drops is a byte-for-byte match to every other PowerUp-dropped binary except for the one attacker-supplied command string patched into it — making file-hash/PE-metadata matching against this known-constant template one of the strongest, most durable signals in this entire module, independent of what command the operator patched in.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Function Reference — Quick Reference](#function-reference--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

PowerUp was written by **Will Schroeder (`@harmj0y`)**, originally as part of the **Veil-Framework's `PowerTools`** project, then merged into **`PowerShellMafia/PowerSploit`**'s `Privesc/` directory alongside PowerView. License: **BSD 3-Clause**.

**Archived-upstream status, verified live (2026-08-04):** same repo as PowerView — `PowerShellMafia/PowerSploit` shows `"archived": true` via the GitHub API, last real push `2020-08-17`, `master`/`dev` branches byte-identical.

**A real internal rename happened here too, and the alias story is the interesting part.** A December 2016 commit (`eae4695b`, message verified live: *"Renamed Invoke-AllChecks to Invoke-PrivescAudit, added alias mapping"*) renamed the flagship "run everything" command and several helper functions for consistency (`Get-ServiceUnquoted`→`Get-UnquotedService`, `Set-ServiceBinPath`→`Set-ServiceBinaryPath`, `Get-CurrentUserTokenGroupSid`→`Get-ProcessTokenGroup`). Critically, that same commit **added backward-compatible aliases** — confirmed directly in the live file's final two lines: `Set-Alias Invoke-AllChecks Invoke-PrivescAudit` and `Set-Alias Get-CurrentUserTokenGroupSid Get-ProcessTokenGroup`. **`Invoke-AllChecks` — the name almost every OSCP guide, HTB walkthrough, and pentest cheat sheet still cites — has worked as an alias for `Invoke-PrivescAudit` since 2016**, not as the tool's real function name. Both names run identically; an analyst hunting for the literal string `Invoke-AllChecks` in a 4104 event is hunting the alias invocation, not the underlying function definition, which matters if a detection rule tries to match the function's *definition* text rather than its call site.

**The canonical-source question — and a genuine, verified divergence from PowerView's story.** PowerView's actively-maintained superset lives embedded inside `BC-SECURITY/Empire` and is substantially *ahead* of the archived original (see `PowerView/01 - Overview.md`). PowerUp's Empire-embedded copy (`empire/server/data/module_source/privesc/PowerUp.ps1`) is the **opposite** case, verified live:

| | PowerShellMafia (archived, final state) | BC-SECURITY/Empire's copy (verified live) |
|---|---|---|
| Lines | 4,989 | 4,013 |
| Function naming | Post-2016 rename: `Invoke-PrivescAudit`, `Get-UnquotedService`, `Set-ServiceBinaryPath`, `Get-ProcessTokenGroup`/`Get-ProcessTokenPrivilege`/`Get-ProcessTokenType`, plus `Enable-Privilege` and `Invoke-EventVwrBypass` (UAC bypass) | **Pre-2016-rename naming**: `Invoke-AllChecks` as the literal function (not an alias), `Get-ServiceUnquoted`, `Set-ServiceBinPath`, `Get-CurrentUserTokenGroupSid` — none of the 2016 additions/renames present |
| `Set-Alias` block | Present (2 aliases) | **Absent entirely** |
| Empire's own file history | — | Vendored in Feb 2021 ("move files part 2," `995a22d8`), touched only by a 2025 YAML/pre-commit formatting pass since — never resynced to upstream's later state |

**This module's established practice is to flag a genuine fork/version discrepancy rather than silently pick one** (see `PLANNING.md` §9's Sliver port-default and ProcDump privilege-requirement precedents). Here it is: **BC-SECURITY's actively-maintained Empire ships an older, pre-rename snapshot of PowerUp that predates the archived original's own final state.** This page documents the **archived PowerShellMafia/PowerSploit `master` branch as the primary reference** (it is the more complete, more recently-authored, alias-preserving version, even though the repo hosting it is archived) and calls out every place BC-SECURITY's bundled copy uses different (older) function names.

**What actually superseded PowerUp in practice, worth knowing even though it's out of this page's scope:** two tools now do more of what operators reach for PowerUp for. `PrivescCheck.ps1` (by **itm4n**) ships **bundled alongside PowerUp** in Empire's own `privesc/` module-source directory (verified live in the same repo tree) and is a broader, more actively-developed enumeration script with a substantially larger check inventory than PowerUp's original set. And **SharpUp** — a direct C# reimplementation by the same GhostPack author family as Seatbelt and Rubeus (see `Purple Teaming/GhostPack/`, Wave 3 #4, not yet built at time of writing) — is the modern compiled successor for the enumeration side of PowerUp's job. This page covers PowerUp itself as originally specified, not its successors.

## How It Works

PowerUp, like PowerView, is a pure-PowerShell `.ps1` script — no compiled component of its own, loaded the same way (dot-source, `Import-Module`, or `IEX`-download-cradle). Its mechanics split cleanly into two families:

**1. Reflective Win32 API calls for privilege/token/service introspection — no `sc.exe`, no `whoami`.** Every check and abuse primitive that touches the Service Control Manager or a process token uses the same **`New-InMemoryModule`/`Add-Win32Type` reflective-P/Invoke pattern** PowerView uses for SAMR (see `PowerView/01 - Overview.md`). Verified directly in source: `Set-ServiceBinaryPath` calls `Advapi32::ChangeServiceConfig` via a dynamically-defined P/Invoke wrapper — **not** a shelled-out `sc config` call. This is a meaningful, checkable distinction from `LOLBins/sc/`'s own abuse primitive: both ultimately call the identical underlying SCM API, but PowerUp's version never spawns an `sc.exe` child process at all — from a process-tree perspective, the service reconfiguration happens entirely inside the PowerShell host process. `Add-ServiceDacl`/`Test-ServiceDaclPermission` similarly call `QueryServiceObjectSecurity` directly rather than `sc sdshow`. See `LOLBins/sc/01 - Overview.md` for the shared SCM/MS-SCMR mechanics and the already-documented finding that reconfiguring an *existing* service's `binPath` fires neither Event 4697 nor 7045 — that gap applies identically here, since it's the same Win32 API either way.

**2. A hardcoded, pre-compiled payload blob for the service-binary and MSI abuse paths.** `Write-ServiceBinary` doesn't compile C# at run time the way many PowerShell offensive tools do (no `Add-Type`/`csc.exe` invocation — confirmed via an explicit source comment: *"using reflection (i.e. csc.exe is never called like with Add-Type)"*). Instead it holds a **pre-compiled .NET service executable as a literal Base64 string**, decodes it, patches the operator's chosen command (or default user/group-add behavior) into a placeholder inside the decoded bytes, and writes the result to disk (or, via `Install-ServiceBinary`, directly overwrites an existing service's binary in place). `Write-UserAddMSI` follows the identical pattern with a pre-compiled MSI installer instead of an EXE.

```
PowerUp session                              Target service / registry
────────────────                             ─────────────────────────
Get-ModifiableService              ──SAMR/local──▶  enumerate services this
                                                       principal can reconfigure
Set-ServiceBinaryPath -Name X                 ──ChangeServiceConfig (Advapi32,
  -Path "C:\Windows\Temp\svc.exe"                P/Invoke, no sc.exe child)──▶
                                                     HKLM\SYSTEM\...\Services\X\
                                                     ImagePath overwritten
Write-ServiceBinary -Name X                   ──decode $B64Binary, patch
  -UserName evil -Password ...                   command, write PE to disk──▶
sc.exe start X  (or a reboot)                 ──service starts as SYSTEM──▶
                                                     new local admin created
```

## Techniques / Protocols Used

| Mechanism | Used by |
|---|---|
| Service Control Manager (SCM) API — `ChangeServiceConfig`, `QueryServiceObjectSecurity`, reached via reflective P/Invoke into `advapi32.dll` | Every service-abuse function — same underlying API `sc.exe`, PsExec, and Impacket's `psexec.py`/`smbexec.py` all ultimately call |
| Filesystem/registry ACL enumeration (`System.Security.AccessControl`) | `Get-ModifiablePath`, `Get-ModifiableRegistryAutoRun`, `Get-ModifiableScheduledTaskFile`, `Get-ModifiableServiceFile` |
| Windows Access Token APIs (`OpenProcessToken`, `GetTokenInformation`), reflective P/Invoke | `Get-ProcessTokenGroup`, `Get-ProcessTokenPrivilege`, `Get-ProcessTokenType`, `Enable-Privilege` |
| Registry reads for known misconfiguration classes (no API beyond `Get-ItemProperty`) | `Get-RegistryAlwaysInstallElevated`, `Get-RegistryAutoLogon`, `Get-CachedGPPPassword` (decrypts the well-known static AES key used for Group Policy Preferences passwords) |
| Filesystem search for known-sensitive file classes | `Get-UnattendedInstallFile`, `Get-ApplicationHost` (IIS `applicationHost.config`), `Get-WebConfig` (ASP.NET `web.config` connection strings), `Get-SiteListPassword` (McAfee ePO `SiteList.xml`) |
| Pre-compiled binary patching (no live compilation) | `Write-ServiceBinary`, `Write-UserAddMSI` |

## Function Reference — Quick Reference

| Category | Key Functions | What they do |
|---|---|---|
| **Master Check** | `Invoke-PrivescAudit` (alias: `Invoke-AllChecks`) `-Format Object/List/HTML` | Runs every check function below and reports every positive finding in one pass |
| **Service Discovery** | `Get-ModifiableService`, `Get-UnquotedService` (alias-equivalent in BC's older copy: `Get-ServiceUnquoted`), `Get-ModifiableServiceFile`, `Get-ServiceDetail` | Find services the current principal can reconfigure, unquoted-path services with a space in the name, and services whose binary file itself is writable |
| **Service Abuse** | `Set-ServiceBinaryPath` (BC: `Set-ServiceBinPath`), `Install-ServiceBinary`, `Write-ServiceBinary`, `Restore-ServiceBinary`, `Invoke-ServiceAbuse` | Actually reconfigure/replace a service binary to execute an attacker command as the service's own account (default `LocalSystem`) |
| **Service DACL** | `Add-ServiceDacl`, `Test-ServiceDaclPermission` | Read/test a service's own security descriptor (separate from filesystem/registry ACLs) for reconfiguration rights |
| **DLL Hijacking** | `Find-PathDLLHijack`, `Find-ProcessDLLHijack`, `Write-HijackDll`, `Get-ModifiablePath` | Find writable directories on `%PATH%` or in a running process's DLL search order, and write a hijack DLL there |
| **AlwaysInstallElevated** | `Get-RegistryAlwaysInstallElevated`, `Write-UserAddMSI` | Check the two `AlwaysInstallElevated` registry policy values (`HKLM`/`HKCU`, both must be `1`) and, if set, drop a pre-compiled MSI that adds a user via an elevated `msiexec` install |
| **Registry/Credential Exposure** | `Get-RegistryAutoLogon`, `Get-ModifiableRegistryAutoRun`, `Get-CachedGPPPassword` | Plaintext autologon credentials, writable autorun-key targets, and cached GPP passwords (reversed via the long-published static GPP AES key) |
| **Scheduled Tasks** | `Get-ModifiableScheduledTaskFile` | Scheduled tasks whose action target file the current principal can overwrite |
| **Unattended/Config Files** | `Get-UnattendedInstallFile`, `Get-ApplicationHost`, `Get-WebConfig`, `Get-SiteListPassword` | Search for known plaintext-credential-bearing file classes left behind by imaging/deployment/app-config processes |
| **Token/Privilege** | `Get-ProcessTokenGroup` (BC: `Get-CurrentUserTokenGroupSid`), `Get-ProcessTokenPrivilege`, `Get-ProcessTokenType`, `Enable-Privilege` | Inspect and, where already assigned but disabled, enable a process token's special privileges (`SeImpersonatePrivilege`, `SeBackupPrivilege`, etc.) |
| **UAC Bypass** | `Invoke-EventVwrBypass` | `eventvwr.exe`-based UAC bypass (credited to `@enigma0x3`) — **archived-original-only**, not present in BC's older bundled copy |

## Quick Use-Case List

- Full-surface triage via `Invoke-PrivescAudit`/`Invoke-AllChecks`
- Discovering and abusing unquoted service paths
- Discovering and abusing weak service-file/service-ACL permissions (`binPath` hijack)
- Discovering and abusing a modifiable existing service's DACL for future reconfiguration rights
- DLL hijacking via a writable `%PATH%` directory or process DLL search order
- AlwaysInstallElevated abuse via a pre-compiled MSI
- Scheduled-task action-file hijacking
- Harvesting cached GPP passwords
- Harvesting plaintext registry autologon credentials
- Harvesting credentials from IIS `applicationHost.config`/`web.config`
- Harvesting McAfee ePO SiteList.xml credentials
- Harvesting unattended-install answer-file credentials
- Enumerating and enabling disabled-but-assigned special token privileges
- UAC bypass via `Invoke-EventVwrBypass` (archived-original only)

## Prerequisites

| Use case | Requirement |
|---|---|
| Any discovery/check function (`Get-Modifiable*`, `Get-Unquoted*`, `Get-Registry*`) | Local code execution as the current low-privilege user — no special rights needed to *find* a misconfiguration |
| Service-abuse functions (`Set-ServiceBinaryPath`, `Install-ServiceBinary`, `Write-ServiceBinary`) | The current principal must already hold write access to the specific service's config/binary/registry key that `Get-ModifiableService`/`Get-ModifiableServiceFile` identified — PowerUp does not grant rights it doesn't already have |
| `Write-UserAddMSI` | `AlwaysInstallElevated` already set to `1` in both `HKLM` and `HKCU` — a pre-existing environment misconfiguration, not something PowerUp creates |
| `Get-CachedGPPPassword` | Read access to SYSVOL and a still-present cached GPP XML file (Microsoft's 2014 patch, MS14-025, stopped *new* GPP-password creation but does not retroactively remove old cached files) |
| `Enable-Privilege` | The target privilege must already be **assigned** to the token (visible but disabled) — this function cannot grant a privilege the token was never issued |
