# PowerUp — Target Evidence

As noted in `03 - Source Evidence.md`, PowerUp's "target" is the **same host** it runs on — this page covers what's recoverable from that host's own filesystem, registry, and event logs after the fact, distinct from the live/volatile view `03` covers.

## Contents
- [Default-Credential Signature](#default-credential-signature)
- [Registry — Service Configuration Changes](#registry--service-configuration-changes)
- [Event Log Gap — Reconfiguring vs. Creating a Service](#event-log-gap--reconfiguring-vs-creating-a-service)
- [Filesystem — The Dropped Service Binary](#filesystem--the-dropped-service-binary)
- [AlwaysInstallElevated — MSI Installation Evidence](#alwaysinstallelevated--msi-installation-evidence)
- [Scheduled-Task Action-File Overwrite](#scheduled-task-action-file-overwrite)
- [The Discovery/Harvesting Functions Leave No Write-Side Evidence](#the-discoveryharvesting-functions-leave-no-write-side-evidence)
- [PowerShell-Logging-Driven Evidence — Cross-Linked](#powershell-logging-driven-evidence--cross-linked)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Building a Timeline](#building-a-timeline)

---

## Default-Credential Signature

Verified directly in source: **`Write-ServiceBinary`/`Install-ServiceBinary` default to creating a local user named `john` with password `Password123!`** if the operator doesn't override `-UserName`/`-Password`. This is a strong, narrow, highly citable signature: a newly-created local account literally named `john` (or added to `Administrators` via the default `-LocalGroup` value) with that specific password is disproportionately likely to be a PowerUp default-configuration run rather than a real administrative action — check `Get-LocalUser`/`net user`/Event 4720 (user account created) for exactly this pattern before assuming a more sophisticated explanation.

## Registry — Service Configuration Changes

`Set-ServiceBinaryPath`/`Install-ServiceBinary` overwrite `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>\ImagePath` via `ChangeServiceConfig` (see `01 - Overview.md`). This is the exact same registry value `LOLBins/sc/`'s own `sc config` abuse modifies — same underlying write, different calling mechanism. Comparing the value's `LastWriteTime` against the service's original install timestamp (if known/baselined) is a direct, if manual, tamper indicator.

## Event Log Gap — Reconfiguring vs. Creating a Service

Directly inheriting `LOLBins/sc/04 - Target Evidence.md`'s already-verified finding, which applies unchanged here because both tools call the identical `ChangeServiceConfig` Win32 API:

| Action | Event 4697 (Security) | Event 7045 (System) | Event 7040 (System) |
|---|---|---|---|
| **New** service (`Install-ServiceBinary` targeting a non-existent service — not PowerUp's primary path, but structurally possible) | Fires (if audited) | Fires | N/A |
| **Reconfigured** existing service's `binPath` (`Set-ServiceBinaryPath`/`Install-ServiceBinary` on an already-installed service — the realistic PowerUp use case) | **Does not fire** — install-only | **Does not fire** — install-only | Only if the **start type** itself also changed |

**A pure `ImagePath` swap on an already-installed, already-`Auto`-start service — PowerUp's typical real-world target, since `Get-ModifiableService` specifically discovers already-installed services — leaves no native Windows Event Log record of the reconfiguration at all.** This is precisely why `05 - Detection and Hunting.md`'s Hunting Priority table ranks raw registry-value inspection above event-log monitoring, mirroring `LOLBins/sc/`'s own established ranking.

## Filesystem — The Dropped Service Binary

Per `01 - Overview.md`'s red-flag callout, the dropped/replaced binary is a **decoded copy of a hardcoded, constant Base64 PE template** with only the operator's command/credential string patched in:

- **File hash of the decoded template region is stable across every PowerUp deployment** — an analyst with one known-bad PowerUp-dropped binary can extract the constant byte regions (everything outside the patched command string) and match them against any other suspected drop, even from a different campaign or operator, without needing YARA-authored signature research first.
- PE metadata (compile timestamp, internal fields) reflects **whenever the PowerUp author last recompiled the embedded template**, not when the operator ran the tool — a static, non-time-correlated compile timestamp across every sample is itself a tell distinguishing this from a tool that compiles per-run (like many `Add-Type`-based PowerShell payloads, which get a fresh, run-time-correlated compile timestamp each time).
- Default output path, if not overridden: current working directory (`service.exe`) for `Write-ServiceBinary`'s standalone use; `Install-ServiceBinary` writes directly over the existing service's already-configured `ImagePath` target, so the "drop location" in that case is wherever the victim service's original binary already lived.
- Prefetch/Amcache/ShimCache record execution of whatever the patched binary was named — low standalone uniqueness (same caveat as any executable), useful for corroborating a specific execution timestamp once a suspect binary is already identified by hash.

## AlwaysInstallElevated — MSI Installation Evidence

`Write-UserAddMSI`'s output, once run via `msiexec /i`, generates the **standard Windows Installer event trail** — Application log Event **1033**/**11707** (MSI install success) and MSI-specific verbose logging if enabled — same as any legitimate MSI install, since `msiexec.exe` itself doesn't distinguish an AlwaysInstallElevated-triggered elevated install from an ordinary one at the logging level. The distinguishing signal is contextual: an MSI installing with **no accompanying interactive UAC consent prompt** (visible via the absence of a corresponding consent.exe/UAC-related event, where applicable) from a non-administrator's session is what actually indicates AlwaysInstallElevated abuse rather than a legitimate elevated install.

## Scheduled-Task Action-File Overwrite

Where `Get-ModifiableScheduledTaskFile`'s finding was acted on (the file itself replaced, not through PowerUp directly — PowerUp only *discovers* this condition, it has no dedicated "hijack this task" abuse function of its own), see `Purple Teaming/LOLBins/schtasks/04 - Target Evidence.md` and `Windows/10 - Persistence Mechanisms/Scheduled Tasks.md` for the full XML/TaskCache/event-ID artifact set that condition feeds into — not re-derived here.

## The Discovery/Harvesting Functions Leave No Write-Side Evidence

Every `Get-*` check/discovery function (`Get-ModifiableService`, `Get-UnquotedService`, `Get-RegistryAlwaysInstallElevated`, `Get-CachedGPPPassword`, `Get-RegistryAutoLogon`, `Get-ApplicationHost`, `Get-WebConfig`, `Get-SiteListPassword`, `Get-UnattendedInstallFile`, `Get-ModifiableRegistryAutoRun`, `Get-ModifiableScheduledTaskFile`) is **read-only** — it inspects existing registry/filesystem/service state and returns findings, without writing anything to the target host. **`Invoke-PrivescAudit` itself, run with default parameters, leaves no target-side write artifact at all** — only the individual abuse functions an operator runs *afterward*, based on the audit's findings, create the registry/filesystem changes documented above.

## PowerShell-Logging-Driven Evidence — Cross-Linked

Identical mechanics to `PowerView/04 - Target Evidence.md`'s cross-link to `LOLBins/powershell/04 - Target Evidence.md` — 4103/4104 off by default, the narrow Warning-level 4104 heuristic (more likely to trip for PowerUp's reflective P/Invoke code than PowerView's LDAP-only code, per `03 - Source Evidence.md`), Event 400 on the classic channel on by default with the full invocation command line. Not re-derived here.

## Endpoint Security Product Behavior

- **AMSI** applies identically to PowerUp's script content as any PowerShell script (see `LOLBins/powershell/04 - Target Evidence.md`).
- Most mainstream EDR products carry a **static-signature detection specifically for PowerUp's known Base64 payload template** — because that template is a widely-published, unchanging constant (the same blob has circulated since the original PowerSploit commits), it is one of the easier offensive-PowerShell payloads for a signature-based product to catch outright, independent of any behavioral detection. An operator who hasn't re-patched or re-encoded the template before use is relying entirely on evading whatever inspects the script's *text* (obfuscation/encoding of the PowerShell source itself), not the payload.

## Building a Timeline

For the realistic service-abuse path: `[ConsoleHost_history.txt / Event 400, source-side]` → `[HKLM\...\Services\<name>\ImagePath registry write, no 4697/7045 companion — see the gap above]` → `[service stop/start or reboot]` → `[new process spawned by services.exe as the service's configured account — Sysmon 1, parent services.exe]` → `[if the default user-add path was used: Event 4720/4732, account "john" created and added to a local group]`. The registry write is the anchor event; everything else either has a companion log entry or doesn't, per the tables above.
