# ProcDump / comsvcs.dll MiniDump — Target Evidence

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Event Logs](#event-logs)
- [Sysmon](#sysmon)
- [The Shared dbghelp.dll Load — The Defining Finding](#the-shared-dbghelpdll-load--the-defining-finding)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint-Security-Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | ProcDump | comsvcs.dll |
|---|---|---|
| Dropped tool binary | `procdump.exe`/`procdump64.exe` (or renamed), wherever the operator staged it — often `C:\Windows\Temp\`, `C:\ProgramData\`, or a user-writable path | **None** — `comsvcs.dll` is already present in `C:\Windows\System32\` |
| Output dump file | `.dmp` at the operator-chosen path, default filename `PROCESSNAME_YYMMDD_HHMMSS.dmp` if unspecified | `.dmp`/`.bin` at the operator-chosen path (LOLBAS's own example uses `dump.bin`) |
| Zone.Identifier ADS | On the dropped binary, if downloaded rather than copied via SMB/PsExec | N/A |
| WER queue artifact | If `-wer` used, a copy routed through the Windows Error Reporting pipeline (`%ProgramData%\Microsoft\Windows\WER\`) | N/A |

A `.dmp`/`.bin` file naming `lsass` in its path, or any large (typically tens to low-hundreds of MB) dump file at all sitting in a non-standard location like `C:\Windows\Temp\`, is itself worth flagging regardless of which tool produced it — legitimate LSASS crash dumps are rare and normally land under `%WINDIR%\Minidump\` or `%LOCALAPPDATA%\CrashDumps\`, not an operator-chosen path.

## Registry

| Key | Meaning |
|---|---|
| `HKCU:\Software\Sysinternals\ProcDump\EulaAccepted` (or shared `HKCU:\Software\Sysinternals`) | ProcDump-specific — proves the tool ran interactively or with `-accepteula` under this profile at least once. No equivalent exists for `comsvcs.dll` |
| `HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | Not written *by* either technique, but its **absence or a recent value change** is directly relevant — see `02`'s PPL-disabling use case and the WinInit Event 12 signal below |

## Event Logs

| Event ID | Log | What it shows | Caveat |
|---|---|---|---|
| **4656** / **4663** | Security | A handle was requested/granted against an object — would name `lsass.exe` as the target object if it fired | **Requires a SACL configured on the `lsass.exe` process object**, which is non-default and rarely deployed in practice — same caveat pattern as this repo's DCSync (Event 4662) and Kerberoasting (Event 5136) findings elsewhere. Don't rely on this being present; Sysmon 10 below is the practical primary signal |
| **12** | System (WinInit) | `"LSASS.exe was started as a protected process with level: 4"` — confirms PPL was active for a given boot | Only tells you PPL state *at boot*; a `RunAsPPL` registry change doesn't take effect until the next restart, so correlate this against registry-modification timestamps, not just presence/absence |
| **7040** | System | Service start-type change — relevant only if the operator's remote-execution vector (e.g. `../PsExec/`) itself installed a service; not produced by ProcDump/`comsvcs.dll` directly | Cross-link to whichever delivery tool's own `04` file for its service-related event coverage |

## Sysmon

| Event ID | What it shows | ProcDump | comsvcs.dll |
|---|---|---|---|
| **1** (Process Create) | Command-line and image for the invocation itself | `procdump.exe`/`procdump64.exe -ma lsass.exe ...` (or renamed image + surviving command-line syntax) | `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump ...` (or `,#24 ...` ordinal form) |
| **7** (Image Load) | `dbghelp.dll` loading into the calling process | Loads into `procdump.exe`/`procdump64.exe` | Loads into `rundll32.exe` — see the dedicated section below, this is the strongest shared signal on this page |
| **10** (Process Access) | `OpenProcess()` call against `lsass.exe`, with `GrantedAccess` mask | Fires with `SourceImage` = `procdump.exe`/`procdump64.exe` | Fires with `SourceImage` = `rundll32.exe` — an unusual `SourceImage` for a `TargetImage` of `lsass.exe` on its own, independent of the mask value |
| **11** (File Create) | The `.dmp` output file being written | Fires for the chosen output path | Same |

**GrantedAccess mask detail:** both techniques request the access rights `MiniDumpWriteDump()` needs (at minimum `PROCESS_QUERY_INFORMATION \| PROCESS_VM_READ`, commonly observed alongside `PROCESS_DUP_HANDLE`). This falls in the same mask family already documented in depth in `../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md` (`0x1010`/`0x1400`/`0x1410`/`0x1038`) — cross-linked rather than re-derived, since the underlying `OpenProcess()` request against `lsass.exe` is the same kernel-level event regardless of which user-mode tool issued it.

## The Shared dbghelp.dll Load — The Defining Finding

Because both `procdump.exe -ma` and `comsvcs.dll`'s `MiniDump` export bottom out in the identical `DbgHelp!MiniDumpWriteDump()` API call (`01`), **both must load `dbghelp.dll` into their own process to make that call.** This produces a Sysmon 7 (Image Load) event that is unusual in two different, tool-specific ways:

- For ProcDump: `dbghelp.dll` loading into `procdump.exe`/`procdump64.exe` is *expected* for the tool's legitimate purpose (it's a debugging utility) — the anomaly here is contextual (why is a debugging tool present and targeting `lsass.exe` specifically), not the load itself.
- For `comsvcs.dll`: `dbghelp.dll` loading into **`rundll32.exe`** is genuinely unusual — `rundll32.exe` has no legitimate reason to load the Debug Help Library in virtually any normal admin workflow. This is the single strongest behavioral signal on this entire page, precisely because it survives every command-line-level evasion (renaming, ordinal-vs-name invocation, output-path choice) covered in `02` — none of those change which DLL gets loaded to make the underlying API call.

## Network-Layer Evidence

Neither technique has a network component of its own (`01`). Any network evidence belongs entirely to whichever remote-execution vector delivered the command and/or whichever exfil tool moved the resulting `.dmp` off the host — see `../PsExec/04 - Target Evidence.md`, `../Impacket/wmiexec/04 - Target Evidence.md`, and `../Rclone/04 - Target Evidence.md` for those respective network-layer artifacts.

## Endpoint-Security-Product Behavior

Most modern EDR/AV products carry a **behavioral** detection for any process opening a read-capable handle to `lsass.exe` and subsequently calling a dump-capable API, independent of the calling binary's identity or signature — this is the direct product-side analog of the shared-mechanic finding above, and it's why Microsoft Defender's dedicated Attack Surface Reduction rule (`../Mimikatz/sekurlsa (Credential Dumping)/05 - Detection and Hunting.md`'s `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`, "Block credential stealing from lsass.exe") catches ProcDump and `comsvcs.dll` invocations alike, not just Mimikatz — cross-linked rather than re-derived.

## Memory Forensics

A live or hibernated memory capture of the target host taken shortly after either technique ran may still hold: the resolved LSASS PID lookup in the invoking process's memory, the open handle itself (if the process hasn't exited), or — for `comsvcs.dll` — `rundll32.exe`'s in-memory module list showing `comsvcs.dll` and `dbghelp.dll` both loaded together, a distinctive pairing for that particular launcher process.

## Building a Timeline

1. **Sysmon 1** — the invocation itself (command line, image, parent process) — establishes T0.
2. **Sysmon 7** — `dbghelp.dll` load into the calling process, milliseconds after T0 — confirms the API-call path actually executed, not just that the command line was typed/scripted.
3. **Sysmon 10** — `OpenProcess()` against `lsass.exe`, `GrantedAccess` mask — confirms the handle was actually obtained (if PPL blocked it, this either won't fire or will show a failed/denied access depending on Sysmon's own logging behavior for failed calls — treat a *missing* Sysmon 10 hit alongside a Sysmon 1 invocation as a signal the attempt likely failed against a protected LSASS, not proof nothing happened).
4. **Sysmon 11** — the `.dmp` file's creation — confirms a dump was actually written to disk, closing the loop from "attempted" to "succeeded."
5. **Source-side correlation** — the `03`-documented `EulaAccepted` write (ProcDump) or command-log entry (`comsvcs.dll`) on the originating host, to tie the target-side sequence back to a specific operator session.
6. **Network/exfil correlation** — whichever delivery and exfil tools were used, per their own `04` files, to bracket the whole operation from initial access through data leaving the environment.
