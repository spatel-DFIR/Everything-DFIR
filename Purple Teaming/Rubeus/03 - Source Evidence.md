# Rubeus — Source Evidence

What the **host running Rubeus** (whether that's `Rubeus.exe` on disk, a reflectively-loaded assembly inside another process, or Rubeus compiled as a library and invoked from PowerShell/Covenant/Cobalt Strike) leaves behind. Because Rubeus never touches LSASS memory (see `01 - Overview.md`), the evidentiary picture here is fundamentally different from Mimikatz's `sekurlsa::*` commands — there's no `MiniDumpWriteDump`-style handle-to-LSASS event to hunt for. What replaces it is a mix of process/network artifacts and, for elevated operations specifically, a well-known token-theft pattern.

## Weaponization and Delivery Artifacts

**No official Rubeus binary exists to fingerprint against.** The project's README states plainly it releases no compiled binaries — every real-world sample is a custom Visual Studio build. This has concrete forensic consequences:

- **PE metadata is not a reliable static indicator.** `AssemblyTitle`, `AssemblyProduct`, `AssemblyCompany`, and the on-disk filename are all whatever the operator set at compile time (or left at Visual Studio's project-template defaults, which themselves vary). Unlike Sysinternals PsExec or AdFind — vendor-shipped binaries with a stable, checkable identity — there is no canonical "real Rubeus.exe" to compare a suspect binary's metadata against.
- **Compiled-to-disk EXE**: standard AV signature scanning applies; the README notes this is *part of why the project deliberately withholds compiled releases* — "brittle signatures are silly."
- **PowerShell-hosted (base64-reflection loader)**: the operator base64-encodes the compiled assembly and loads it via `[System.Reflection.Assembly]::Load()`, then invokes `[Rubeus.Program]::Main()`. Standard PowerShell v5 protections apply in full here — AMSI, Script Block Logging (Event 4104), Module Logging (4103) — see `LOLBins/powershell/` for the underlying logging-subsystem mechanics this repo already documents in depth.
- **Unmanaged assembly execution (Cobalt Strike `execute-assembly`, Covenant, etc.)**: the CLR gets loaded into a process that may not normally host .NET at all — a strong anomaly signal independent of anything Rubeus-specific, since it's the same signature any reflectively-loaded .NET tradecraft produces.
- **AMSI**: added to .NET 4.8 itself (not just PowerShell) — a Rubeus assembly targeting .NET 4.8 and invoked through a scanning-aware loader is subject to AMSI inspection at the CLR level, independent of how it was delivered.

## Command-Line / Shell History

- If invoked as a standalone EXE from `cmd.exe`/PowerShell interactively, the full switch string lands in `ConsoleHost_history.txt` (PowerShell) or is visible via Sysmon Event ID 1's `CommandLine` field (see `04 - Target Evidence.md` for the equivalent target-side capture when Rubeus is run *against* a remote host it's not local to — most Rubeus actions are run locally against a remote KDC, so "target" for command-line logging purposes is usually the same host as "source" here).
- **Credential material appears in plaintext on the command line** for nearly every command: `/rc4:HASH`, `/aes256:HASH`, `/password:X`, `/krbkey:HASH`, `/new:PASSWORD` (changepw) are all literal arguments — any command-line-capturing telemetry (Sysmon 1, Security 4688 with command-line auditing enabled, EDR process-creation events) captures the secret material itself, not just the fact that Rubeus ran.
- Base64 `.kirbi` ticket blobs passed via `/ticket:BASE64` are long, high-entropy strings that stand out clearly in raw command-line logs even without any signature matching — a useful heuristic hunt independent of matching specific switch names.

## Process and Handle Artifacts — the winlogon.exe Token-Duplication Signal

This is the single strongest source-side artifact for **any elevated, all-users Rubeus operation** — `triage`, `klist`, `dump`, `monitor`, `harvest`, `purge`/`ptt` targeting a `/luid` other than the current session. Verified directly against `Rubeus/lib/Helpers.cs`'s `GetSystem()` and `Rubeus/lib/LSA.cs`'s `GetLsaHandle()`:

1. The process must already be **high-integrity** (elevated) but not yet SYSTEM.
2. `GetSystem()` calls `Process.GetProcessesByName("winlogon")`, then `OpenProcessToken(handle, TOKEN_DUPLICATE, ...)` against it.
3. `DuplicateToken()` copies `winlogon.exe`'s SYSTEM token (`SecurityImpersonation` level).
4. `ImpersonateLoggedOnUser()` applies the duplicated token to the current thread.
5. Only **then** does Rubeus call `LsaConnectUntrusted()` — the same untrusted LSA connection used by the non-elevated path — to enumerate/extract tickets for all logon sessions.

**Correction to the tool's own documentation:** Rubeus's README describes this step as registering "a fake logon application... with the `LsaRegisterLogonProcess()` API call." That is not what the current source does — there is no `LsaRegisterLogonProcess` P/Invoke declaration anywhere in `Interop.cs`, and every call site in `LSA.cs` uses `LsaConnectUntrusted()`. The actual, verifiable artifact is:

- A **process handle opened to `winlogon.exe`** by a non-`winlogon`/non-LSA-related process — `OpenProcessToken` requires first calling `OpenProcess`/using the process handle from `Process.GetProcessesByName`, which itself requires a handle with sufficient access rights to `winlogon.exe` (PID 1-ish, a Session 0/interactive-session-critical process).
- That process then **carrying a SYSTEM-impersonation token** for the remainder of its elevated ticket-extraction call.

This is the same token-theft pattern ("steal winlogon's/lsass's token") that EDR products specifically watch for as a `getsystem`-style technique — it is **not unique to Rubeus** (the same `Helpers.GetSystem()` pattern exists across the GhostPack tool family, e.g. `Seatbelt/`'s own elevation helper), but any occurrence of it immediately preceding Kerberos-ticket-cache API calls is a strong compound signal.

## Network Connection State

- Any live-protocol command (`asktgt`, `asktgs`, `renew`, `brute`/`spray`, `preauthscan`, `s4u`, `kerberoast` in its default/`/aes` modes, `asreproast`, `changepw`) opens an outbound TCP/UDP connection to **port 88** on a domain controller (or **464** for `changepw`) sourced from the Rubeus process itself — visible in `netstat`/`Get-NetTCPConnection` output on the source host as a non-`lsass.exe` process holding a port-88 socket, which is the exact anomaly the tool's own author calls out as its hardest-to-avoid tell.
- `golden`/`silver /ldap` additionally opens LDAP/LDAPS (389/636) connections for PAC-field population, and briefly mounts (`net use`-equivalent) then unmounts a target DC's `\\<dc>\SYSVOL` share — this leaves a transient SMB session and, depending on host configuration, a **recently-mounted-share MRU artifact** even after the unmount completes (the mount/unmount pair is logged in the README's own example console output as two explicit, separate steps).
- `/proxyurl:URL` routes Kerberos traffic over HTTPS to an MS-KKDCP proxy instead of a direct port-88 connection — defeats a pure port/protocol-based network hunt entirely, since the traffic is indistinguishable at the transport layer from ordinary HTTPS unless the proxy endpoint itself is known-bad or TLS inspection decodes the KKDCP payload.

## Memory Forensics

- Rubeus performs **no LSASS memory access of any kind** by design — this is worth stating explicitly for negative-evidence purposes: a memory-forensics sweep looking for handles opened to `lsass.exe` (the standard Mimikatz-hunting playbook) will find **nothing** from genuine Rubeus activity. Don't let a clean LSASS-handle sweep on a host be read as "no credential-access tooling ran here."
- If loaded reflectively (`execute-assembly`, `[Assembly]::Load()`), the Rubeus CLR module exists **in memory only**, with no corresponding on-disk PE — the standard "unbacked executable memory region" / PE-without-a-file-handle signature that tools like Moneta, PE-sieve, or `Get-InjectedThread`-style EDR heuristics are built to catch, independent of anything Rubeus-specific.
- Decrypted ticket material (session keys, PAC contents) exists in process memory for the duration of a run — a live memory capture of the Rubeus process itself (not LSASS) during or shortly after execution can recover cleartext key material the same way any process handling secrets in memory would expose it.

## OS-Level Audit Trail

- **Sysmon Event ID 1** (process creation): the compiled Rubeus binary's `CommandLine` field carries the full switch string including credential material (see above); `OriginalFileName`/`Company`/`Product` PE fields are only useful if the operator didn't bother clearing them at compile time — treat as supplementary, not primary.
- **Sysmon Event ID 3** (network connection): the outbound port-88/464 connection sourced from a non-`lsass.exe` process is the network-layer half of the same core signal described above.
- **Sysmon Event ID 7** (image/DLL load) if Rubeus is compiled and invoked as a library DLL rather than a standalone EXE.
- **PowerShell 4104/4103**: only relevant when a PowerShell reflection wrapper is the delivery vector — captures the *loader* script's content (the base64 blob and the `[Assembly]::Load()`/`[Rubeus.Program]::Main()` invocation lines), not Rubeus's own C# source, since the loaded assembly executes as compiled managed code outside the script-block-logging boundary.
- **Security 4688** (process creation, if command-line auditing is enabled) is the non-Sysmon equivalent of the Event ID 1 signal above — check both are enabled before assuming coverage.

## Local Persistence of Harvested Output

`monitor`/`harvest`'s `/registry:SOFTWARE\PATH` flag writes captured ticket output under `HKLM` **on the host Rubeus is running on** (not the target) — the README's own cleanup instructions (`Get-Item HKLM:\SOFTWARE\<PATH>\ | Remove-Item -Recurse -Force`) confirm this is local, operator-managed storage. A non-standard `HKLM\SOFTWARE\` subkey containing base64-blob-shaped string values is a durable, easily-missed source-host artifact if the operator forgets the cleanup step — check `HKLM\SOFTWARE\` for anomalous keys whenever `monitor`/`harvest` activity is suspected, independent of process/network evidence, since it survives the Rubeus process exiting.

## Timeline Correlation Value

Source-side artifacts here are most useful for establishing **intent and staging** — which specific account/key an operator targeted, in what sequence, and from which specific host process — while the *consequence* of that activity (a forged/injected ticket actually being used) is what shows up in `04 - Target Evidence.md`'s domain-controller and target-service logs. The winlogon.exe token-duplication signal in particular is a strong **pivot point**: correlating "Rubeus process opens a handle to `winlogon.exe` and begins impersonating SYSTEM" against "that same process's LUID subsequently appears associated with a newly-cached ticket for a *different* user" ties the elevation step directly to the specific ticket-extraction or injection that followed it, which is exactly the kind of causal chain a DFIR timeline needs to distinguish "an admin ran `klist` out of curiosity" from "an operator used Rubeus to harvest every cached TGT on the box."
