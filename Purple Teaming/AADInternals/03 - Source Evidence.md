# AADInternals — Source Evidence

Everything here is what an operation leaves on the **attacking host** — the machine running the AADInternals PowerShell module. This is a cloud-attack tool, so unlike most of this repo's Windows-targeting entries, the richer half of the evidence picture is `04 - Target Evidence.md` (Entra ID's own logs); this file is comparatively thin by design, matching the precedent set in `AnyDesk/03 - Source Evidence.md` for the same reason.

## Contents
- [PowerShell Host Artifacts](#powershell-host-artifacts)
- [Module Installation and File-System Artifacts](#module-installation-and-file-system-artifacts)
- [Device-Registration Artifacts — The PFX That Gets Left Behind](#device-registration-artifacts--the-pfx-that-gets-left-behind)
- [Network State on the Source Host](#network-state-on-the-source-host)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## PowerShell Host Artifacts

AADInternals is pure PowerShell — every command is a script-level function invocation, so **every source-host detection angle already documented for `powershell.exe` in this repo applies directly and isn't re-derived here.** See `LOLBins/powershell/` for the full picture, in particular:

- **Module and Script Block logging (Event IDs 4103/4104)** are the primary source-host artifacts, but **both are off by default** in Windows (confirmed in `LOLBins/powershell/01 - Overview.md`) — an analyst should not assume they're present unless the environment specifically enabled them.
- If Script Block Logging (4104) is enabled, `Import-Module AADInternals` and every subsequent `Invoke-AADInt*`/`Get-AADInt*`/`New-AADInt*` call is logged **in full**, including literal parameter values — credentials passed via `-Credentials`/`-Password`, forged SIDs, hashes, and target domain names all land in plaintext in the Security or `Microsoft-Windows-PowerShell/Operational` channel (channel depends on PS5.1 vs. PS7, also covered in the `powershell/` page).
- **PSReadLine command history** (`(Get-PSReadLineOption).HistorySavePath`, typically `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`) captures every interactively-typed AADInternals command verbatim, surviving process exit — a persistent, unencrypted artifact independent of any Windows event-log configuration.
- **`$Error`/transcript files**, if `Start-Transcript` was active, capture full command *and* console output — including any printed access tokens, PRT material, or the `ConvertTo-Backdoor` confirmation prompt/output.

## Module Installation and File-System Artifacts

- **Install path.** `Install-Module AADInternals -Scope CurrentUser` lands the module (all ~35 `.ps1` files plus the three bundled DLLs) under `%USERPROFILE%\Documents\{WindowsPowerShell|PowerShell}\Modules\AADInternals\<version>\`; `-Scope AllUsers` lands it under `%ProgramFiles%\{WindowsPowerShell|PowerShell}\Modules\AADInternals\<version>\` instead — this split is standard PowerShell Gallery behavior, not AADInternals-specific, but the resulting directory tree (dozens of `.ps1` files with names like `PRT.ps1`, `Kerberos.ps1`, `FederatedIdentityTools.ps1`) is itself a strong, plainly-labeled artifact if disk forensics reaches the source host.
- **`config.json`** lives directly inside the installed module folder (`Configuration.ps1`'s `Read-/Save-Configuration` read/write `"$PSScriptRoot\config.json"`) and persists any settings changed via `Set-AADIntSettings` (e.g. a custom `User-Agent` string) across sessions — a small but durable, version-specific artifact.
- **A `git clone` install** (the alternative to PowerShell Gallery) leaves the full repository history, including the literal `any_sts.pfx`/`any_sts.der`-equivalent embedded certificate and every other source file, on disk with normal `.git` metadata (commit timestamps, remote URL) — useful for establishing when the tool was first staged on a host.
- **PowerShell Gallery telemetry.** `Install-Module` itself, if PowerShell's own module-logging/AMSI/Defender for Endpoint script-content scanning is active on the source host, generates its own independent trail (package download from `psg-prod-eastus.azureedge.net`, `nuget.org`-style package metadata) separate from anything AADInternals itself does — this is standard `PowerShellGet` behavior worth checking regardless of which tool was installed.

## Device-Registration Artifacts — The PFX That Gets Left Behind

`Join-AADIntDeviceToAzureAD` and the related PRT-derivation functions are the one part of the module that reliably writes **sensitive, reusable credential material to disk** rather than keeping it in memory. Verified directly in `PRT.ps1`: the function exports the newly-registered device's certificate with `Set-BinaryContent -Path "$deviceId.pfx" -Value $deviceCert.Export([...]::Pfx)` — a **single-argument `.Export()` call, which produces a password-less PFX** — written to whatever directory the operator's PowerShell session had as its current working directory at the time, named after the device's own new GUID (e.g. `d03994c9-24f8-41ba-a156-1805998d6dc7.pfx`). Because the export carries no password, anyone who later finds this file (backup, shadow copy, `$Recycle.Bin`, temp-directory sweep) has the full device private key with no cracking required — this is the single strongest recoverable source-host artifact the tool produces, and it survives long after the PowerShell process that created it has exited.

## Network State on the Source Host

- Every AADInternals HTTP(S) call goes out over TLS to a small, predictable set of Microsoft hostnames — `login.microsoftonline.com`, `graph.windows.net` (see the open retirement question in `01 - Overview.md`), `graph.microsoft.com`, `<tenant-id>.registration.msappproxy.net`, `provisioningapi.microsoftonline.com` — all legitimate Microsoft-owned domains, so DNS/proxy logs on the source host won't show anything inherently suspicious by hostname alone.
- `netstat -ano` / `Get-NetTCPConnection` during an active session shows outbound TCP 443 connections to Microsoft IP ranges from the hosting `powershell.exe`/`pwsh.exe` process — unremarkable on its own, but correlatable against the process's command line/parent if Sysmon Event ID 3 (Network Connection) is enabled with process-image logging.
- No custom User-Agent is set by default (`Configuration.ps1`'s default is a plain string), but it's operator-configurable via `Set-AADIntSettings` — if the operator hasn't customized it, a proxy/TLS-inspection device that logs User-Agent strings may show the module's default value across many requests, a coarse but real fleet-wide correlator across a single operator's activity against multiple tenants.

## Memory-Forensics Angle

Access tokens, refresh tokens, and PRT material acquired during a session are held in a **PowerShell script-scope in-memory hashtable** (`$Script:tokens`, `$Script:refresh_tokens` in `AccessToken_utils.ps1`) — **not written to disk unless the operator explicitly does so** (`-SaveToCache`, `-SaveToMgCache`, or a manual `Out-File`/`ConvertTo-Json` export). This means:

- A live or hibernated memory capture of the hosting `powershell.exe`/`pwsh.exe` process is the only reliable way to recover tokens from a session that never persisted them — the same "memory is the artifact, not disk" pattern this repo documents for `PowerShell Empire/` and `PowerSploit/`'s in-memory tradecraft.
- If `-SaveToMgCache` was used, the token additionally lands in the **real Microsoft Graph PowerShell SDK's own on-disk token cache** (a legitimate, expected artifact location for that SDK) — meaning a forensic review of "why does this host have a cached Graph token for a Global Admin" needs to consider AADInternals as one possible source, not just genuine `Connect-MgGraph` usage.

## Timeline Correlation Value

Source-host evidence is weakest for this tool relative to most others in this repo — much of what AADInternals does (recon, token acquisition, ticket/SAML forging) happens **entirely client-side**, producing no network round-trip signature distinct from ordinary HTTPS to Microsoft, and no disk artifact unless the operator opts in. Where source evidence *does* exist (PSReadLine history, Script Block Logging if enabled, the device-registration `.pfx`), its primary value is establishing **when and by whom** a given tenant-side event (a role grant, a federation-settings change, a new device object — see `04`) was actually triggered, since the target-side Entra logs record the resulting change but not the tool that made it. Correlate the source-host command timestamp against the corresponding Entra Audit Log `activityDateTime` (typically within seconds, allowing for clock skew) to tie a specific operator action to a specific tenant-side artifact.
