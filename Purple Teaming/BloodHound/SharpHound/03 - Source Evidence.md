# BloodHound — SharpHound — Source Evidence

Evidence left on the **collecting host** — the machine SharpHound itself runs from. This is a meaningful departure from the Linux-operator-box baseline used throughout this repo's Impacket coverage: SharpHound is a **.NET assembly**, so its collecting host is a **Windows machine** (a compromised domain-joined workstation, an attacker-controlled VM joined or reachable to the domain, or a jump box) — everything below is a Windows-host artifact set, not a shell-history/Linux one.

## Contents
- [The Binary and Its Loading Mechanism](#the-binary-and-its-loading-mechanism)
- [Local Output Files — The Loot Itself](#local-output-files--the-loot-itself)
- [The Object-Resolution Cache File](#the-object-resolution-cache-file)
- [Command-Line and Console History](#command-line-and-console-history)
- [Live Process State](#live-process-state)
- [OS-Level Audit Trail on the Collecting Host](#os-level-audit-trail-on-the-collecting-host)
- [Network Evidence, Source Side](#network-evidence-source-side)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Binary and Its Loading Mechanism

SharpHound reaches a collecting host one of two ways, and which one materially changes the disk-forensics story:

| Delivery | Disk footprint | Notes |
|---|---|---|
| `SharpHound.exe` dropped and run directly | Full standard on-disk-executable footprint: file itself, Prefetch, Amcache/ShimCache entry, Sysmon 1/Security 4688 process-creation event with the complete command line | The default, and by far the more common path in practice — most public tradecraft guidance and the official docs assume this delivery |
| Reflectively loaded via `Invoke-BloodHound` (the `Template.ps1` PowerShell wrapper, still shipped in current `SpecterOps/SharpHound` source under `src/PowerShell/`) | **No `SharpHound.exe` file ever touches disk** — the compiled assembly is embedded base64-encoded inside the `.ps1` script and loaded at runtime via `System.Reflection.Assembly.Load` | Confirmed still present and functional in current CE source, not a Legacy-only technique. See **Memory Forensics** below for what this shifts the evidence burden onto |

Either way, the file/module itself carries a distinctive PE identity — public AV telemetry catalogs it generically as a hack-tool signature family (Microsoft's own signature naming for the BloodHound/SharpHound assembly family is `HackTool:Win32/BloodHound` and its variants) — so a still-quarantined or logged detection event on the collecting host, even without a surviving file, is itself a durable artifact (AV/EDR quarantine logs, Windows Defender's `MpCmdRun`/Operational log).

## Local Output Files — The Loot Itself

The single highest-value artifact class here, structurally identical in concept to `Impacket/secretsdump/03 - Source Evidence.md`'s "Local Output Files" section, but with SharpHound's own naming convention (verified against `BaseContext.ResolveFileName` and `Runtime/OutputWriter.cs` in source):

| File | Naming pattern | Notes |
|---|---|---|
| Per-object-type JSON | `<timestamp>_<type>.json` (e.g. `20260802101530_users.json`) | One file per object type — `users`, `computers`, `groups`, `domains`, `gpos`, `ous`, `containers`, `rootcas`, `aiacas`, `ntauthstores`, `enterprisecas`, `certtemplates`, `issuancepolicies` (13 types in current CE schema). Each contains a JSON `data` array plus a `meta` object recording `count`, `type`, the `CollectionMethods` bitmask actually used, the JSON schema `version` (currently `6`), and the collector version string — **the `meta` block on a surviving JSON file tells an analyst exactly what collection methods produced it, even without the original command line** |
| Output zip | `<timestamp>_BloodHound.zip` by default, or `<timestamp>_<ZipFileName>.zip` if `--ZipFileName` was set | DEFLATE level 9 via SharpZipLib; `--ZipPassword` AES/ZipCrypto-protects it; `--NoZip` skips this step entirely, leaving the raw JSON files as the only output artifact |
| Randomized-name variant | Random 8-character filenames (`Path.GetRandomFileName()`) for both the JSON files and the zip | Only when `--RandomFileNames` is set — defeats a naming-pattern-based file hunt, but the JSON `meta` block inside each file (and its Newtonsoft-JSON structure/keys) still fingerprints it as SharpHound output regardless of filename |
| Computer-call tracking CSV | Written alongside the other output when `--TrackComputerCalls` is set | Logs the outcome (success/error code) of every per-computer connection attempt during Phase 2 — itself a target list, useful for reconstructing exactly which hosts were touched even if the main output was deleted |

**All of these land in `--OutputDirectory` (current directory by default)** — an unusually complete, self-documenting loot trail compared to most credential-dumping tools, since the JSON itself carries provenance metadata.

## The Object-Resolution Cache File

**`<Base64(MachineGuid)>.bin`** by default (verified against `BaseContext.GetCachePath()` and `ClientHelpers.GetBase64MachineID()` in source) — SharpHound base64-encodes the **collecting host's own `MachineGuid`** (read from `HKLM\SOFTWARE\Microsoft\Cryptography`, falling back to the base64'd computer name if that key is unreadable) to name a persistent SID/object-resolution cache, written to `--OutputDirectory` unless `--MemCache` is set. This file:

- **Survives between separate SharpHound invocations** on the same host — its mere presence is evidence SharpHound ran here before, independent of whether any JSON/zip output from that run still exists
- Is trivially reversible: decoding the base64 filename recovers the collecting host's own `MachineGuid`, directly tying the cache file to a specific machine identity even if it's later copied elsewhere
- Gets discarded and rebuilt if `--RebuildCache` was passed on a given run — an unusually large or old cache file relative to a short engagement window can itself suggest reuse across multiple prior collection sessions

## Command-Line and Console History

| Source | Detail |
|---|---|
| PowerShell console history | `(Get-PSReadlineOption).HistorySavePath` — typically `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` — persists the full `SharpHound.exe -c ...` or `Invoke-BloodHound -CollectionMethods ...` invocation, including every flag, across sessions |
| `cmd.exe` command history | **Not persisted by default** — Doskey's history buffer is in-memory only and lost when the `cmd.exe` process exits, unlike bash/zsh's file-backed history. A `SharpHound.exe` run launched from `cmd.exe` and then closed leaves **no command-line-history artifact** for the invocation itself, only whatever process-creation logging (below) captured it |
| PowerShell ScriptBlock Logging (Event ID 4104) | If enabled, captures the **entire decoded script block** — for `Invoke-BloodHound`, this includes the full embedded base64 assembly blob inside `Template.ps1`, making 4104 one of the very few artifacts that can recover the actual SharpHound binary bytes from a fileless run |
| PowerShell Module/Transcription Logging | If enabled, an equivalent durable transcript of the same invocation |

## Live Process State

```powershell
Get-Process -Name SharpHound -ErrorAction SilentlyContinue
Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'SharpHound|CollectionMethod' }
```
Full command line — every flag including `-LdapUsername`/`-LdapPassword`/`-ZipPassword` if supplied inline — is visible via `Win32_Process.CommandLine` or `Get-Process`'s `.Path`/`MainModule` for the process's lifetime, same general exposure principle as any Windows process to a co-resident analyst/EDR agent.

## OS-Level Audit Trail on the Collecting Host

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'SharpHound' }
```
Sysmon Event ID 1 (or Security 4688 if process-creation command-line auditing is enabled) is the **single richest artifact on this host** for an `.exe`-delivered run — it captures the complete command line, meaning every `-c`/`--CollectionMethods` value, every scoping flag (`--DistinguishedName`, `--LDAPFilter`, `--ComputerFile`), and every OPSEC flag (`--Stealth`, `--Throttle`, `--Jitter`) an operator chose. **This is itself intent evidence** — a `-c DCOnly --Stealth` invocation reads very differently from `-c All`, the same way `Impacket/secretsdump/`'s flag choices reveal operator intent in that folder's Source Evidence file. For a fileless `Invoke-BloodHound` run, this event only ever shows `powershell.exe` with the wrapper's own arguments — the SharpHound-specific flags only surface if ScriptBlock Logging (4104, above) is also enabled.

## Network Evidence, Source Side

| Artifact | Detail |
|---|---|
| Outbound LDAP/LDAPS (389/636) | A burst of connections to a DC, sustained for the LDAP-sweep duration — visible in the collecting host's own connection state (`Get-NetTCPConnection`) and any network-layer sensor on its egress path |
| Outbound SMB (445) + RPC (135 + dynamic) | Fans out to **every live computer object** in scope during Phase 2 — for a `Default`/`All` run against a domain of any real size, this looks nothing like normal host-to-host traffic in both volume and destination spread. `DCOnly`/`--Stealth` runs meaningfully suppress this leg (see `01 - Overview.md`) |
| DNS resolution burst | Resolving every computer object's hostname ahead of the per-host connection attempts — a spike in outbound DNS queries from one host, correlated with the SMB/RPC fan-out above, is a useful corroborating signal even where host-based logging on the collecting machine itself is thin |

## Endpoint Security Product Signatures

Most modern AV/EDR products carry both a **static signature** for the SharpHound/BloodHound assembly family (Microsoft's own naming: `HackTool:Win32/BloodHound` and variants) and a **behavioral** detection for the LDAP-query-pattern + SAMR/SRVSVC-fan-out combination this tool produces regardless of build/obfuscation — a custom-recompiled or renamed SharpHound binary defeats the static signature but not the behavioral one, since the underlying API call pattern is unchanged. A quarantine/detection event on the collecting host that doesn't correlate with a surviving binary is consistent with a detected-and-blocked run — check AV operational logs even when `find`-style file hunts turn up nothing.

## Memory Forensics

- **For an `.exe`-delivered run:** standard process-memory capture (a full dump, or a targeted minidump) can recover in-flight LDAP query buffers, resolved SID/object mappings from the cache, and any inline credentials passed via `-LdapPassword`/`-ZipPassword`/`-LocalAdminPassword` — these exist as live .NET string/byte objects for the process's lifetime, the same general principle as `Impacket/secretsdump/03 - Source Evidence.md`'s memory-forensics note for credential material in flight.
- **For a fileless `Invoke-BloodHound` run, memory *is* the primary evidence source, not a supplement.** Since the compiled assembly is reflectively loaded via `Assembly.Load` and never written as a standalone PE to disk, there is no `SharpHound.exe` file to recover post-execution — the loaded module only exists as an **unbacked/anonymously-mapped memory region inside `powershell.exe`'s process space**. Tooling built to detect exactly this pattern (PE-sieve, Moneta, or any "unbacked executable memory" / "reflectively loaded .NET assembly" EDR heuristic) is the relevant detection and recovery angle — a live memory capture of the `powershell.exe` process while `Invoke-BloodHound` is running (or shortly after) can recover the full assembly bytes for static analysis, confirming both that SharpHound ran and which build/version.
- .NET's AMSI integration for `Assembly.Load` (available since .NET Framework 4.8 on hosts with it configured) can additionally surface the reflectively-loaded assembly's content to AMSI-aware AV/EDR at load time — a detection opportunity that doesn't exist for pre-4.8 targets or AMSI-bypassed sessions.

## Timeline Correlation Value

The collecting-host artifacts above are most valuable **paired against target-side evidence** (`04 - Target Evidence.md`): a Sysmon 1 process-creation event for `SharpHound.exe -c All`, timestamped, correlated against the target DC's Event 1644 LDAP-query-logging burst and the fan-out of SAMR/SRVSVC calls across member computers in the same window turns "a SharpHound run happened somewhere" into a provable, fully-scoped collection event — and the flag values recovered from the command line tell an analyst **exactly which target-side artifacts to expect** (a `DCOnly` run's command line predicts *zero* per-computer SAMR/SRVSVC evidence, so its absence isn't a detection gap to chase). Where the collecting host shows only a fileless `Invoke-BloodHound` invocation and no `SharpHound.exe`, expect the corresponding target-side evidence to look identical regardless — the loading mechanism only changes the *source*-side story, not what the DC/member computers observe.
