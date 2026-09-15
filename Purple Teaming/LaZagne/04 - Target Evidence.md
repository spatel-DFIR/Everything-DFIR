# LaZagne — Target Evidence

This is where the real evidence lives for this tool — per `03`, the host LaZagne runs on is, in the common case, the same host being harvested. Set expectations by privilege level first: an **elevated** run touches the registry, spawns child processes, and performs token operations across every logged-on user; an **unprivileged** run leaves almost nothing beyond the binary's own execution trace and whatever output file the operator chose to write. Every subsection below flags which privilege level it requires.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Process Creation — Security 4688 / Sysmon 1](#process-creation--security-4688--sysmon-1)
- [Process Access — Sysmon 10 (the Token-Theft Signal)](#process-access--sysmon-10-the-token-theft-signal)
- [Security Log — Privilege Use and Logon Events](#security-log--privilege-use-and-logon-events)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Distinguishing From Legitimate Administrative Activity](#distinguishing-from-legitimate-administrative-activity)
- [Building a Timeline](#building-a-timeline)

---

## Filesystem

| Artifact | Detail |
|---|---|
| The binary itself | If run as a standalone PyInstaller `.exe` (the common case per `01`), it lands wherever the operator placed it — no fixed default path. Its own PE carries a distinctive trailer signature regardless of filename: PyInstaller's `CArchive` cookie magic bytes `MEI\x0c\x0b\x0a\x0b\x0e`, appended near the end of the file (`struct` format `'!8sIIii64s'` for the trailer, per PyInstaller's own `archive/readers.py`). This survives renaming completely and identifies the file as **some** PyInstaller-frozen Python application even before any content-specific signature matches — a useful first-pass carving target on a disk image for "is this LaZagne (or any other PyInstaller-built tool)" even against a renamed, unknown binary |
| SAM/SECURITY/SYSTEM hive copies (admin only, transient) | `%TEMP%\<6-12 random lowercase letters, no extension>` — three files, one per hive, created by `save_hives()` and removed by `delete_hives()` in a `finally` block once the `windows` system-module pass completes. **A crash, kill, or forced termination mid-run can leave one or more of these behind** — an unnamed, extensionless, small-to-medium binary file in `%TEMP%` with no legitimate reason to exist is a strong indicator if found during live response before it's cleaned up or the temp directory is otherwise cycled |
| Output file (if `-oN`/`-oJ`/`-oA` used) | `credentials_<DDMMYYYY_HHMMSS>.txt`/`.json` in the working directory or the `-output` path — filename is timestamp-derived, not fixed, per `01`. The embedded timestamp is itself forensically useful: it dates the run to the second independent of the file's own filesystem metadata |
| Working-directory clutter | None beyond the above by default — LaZagne doesn't stage or cache application-specific data to disk as an intermediate step; each module reads its target application's existing on-disk store directly (browser profile SQLite DBs, `%APPDATA%\Microsoft\Credentials\`, `%LOCALAPPDATA%\Microsoft\Vault\`, etc.) and holds the decrypted result in memory only |

## Registry

| Key/Value | What LaZagne does with it |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (`AutoAdminLogon`, `DefaultUserName`, `DefaultPassword`, `Alt*` equivalents) | **Read-only** — the `autologon` module queries these values, it doesn't write anything |
| `HKLM\SAM`, `HKLM\SECURITY`, `HKLM\SYSTEM` | Not read live via a registry handle at all for the hash/secrets/mscache modules — exported to a flat file via `reg.exe save` first (see Filesystem above and `01`), then parsed offline. No `RegSaveKeyEx` API call from LaZagne's own process; the export is entirely `reg.exe`'s doing as a child process |
| Everything else LaZagne touches (browser profile paths, application config locations) | Read-only, application-specific, no meaningful registry-write footprint |

**LaZagne writes essentially nothing to the registry.** This is a real, useful negative finding — a registry-modification-centric hunt (the kind that works well for, say, `sc.exe`'s service hijacking or `schtasks`'s persistence) has nothing to find here.

## Process Creation — Security 4688 / Sysmon 1

The clearest, least ambiguous target-side signal this tool produces, and it's independent of which specific software category the operator targeted:

| Child process | When it fires | Command-line pattern |
|---|---|---|
| `cmd.exe` → `reg.exe` (x3) | Admin-only, once per run of any `windows` system-module (`-hashdump`, `-lsa_secrets`, `-mscache`, or the bare `windows` category / `all`) — **all three fire together even if only one specific module was requested**, since `save_hives()` exports every hive up front regardless | `cmd.exe /c reg.exe save hklm\sam <6-12 random lowercase letters>` (and `hklm\security`, `hklm\system`, same pattern) — each spawned hidden (`SW_HIDE`), each targeting a **randomly-named, extensionless file in `%TEMP%`** |
| `netsh.exe` | No-admin fallback path for the `wifi` module only, when the SYSTEM-DPAPI path isn't available | `netsh.exe wlan show profile "<SSID>" key=clear` |

Both patterns are essentially unique to LaZagne's own execution — legitimate hive backups via `reg.exe save` are rare enough on an endpoint (vs. a domain controller, where NTDS/hive backup tooling has a real operational reason to exist) that this pairing (three simultaneous randomly-named hive exports, immediate deletion, from a non-backup-software parent) is a strong signal on its own, before even considering the parent process's own identity.

## Process Access — Sysmon 10 (the Token-Theft Signal)

Phase 3's `OpenProcess(PROCESS_QUERY_INFORMATION, ...)` loop (per `01`) against **every running PID** on the box, followed by `OpenProcessToken`, is exactly the kind of activity Sysmon Event ID 10 (ProcessAccess) exists to capture — LaZagne's process shows up as the `SourceImage`, dozens of unrelated processes as `TargetImage`, all within a tight time window.

**A real, important caveat on this signal's actual coverage:** `PROCESS_QUERY_INFORMATION` (access mask `0x400`) is the *only* access right LaZagne requests for the initial `OpenProcess` call — verified directly in `change_privileges.py`. This is one of the lowest, most commonly-triggered access masks in normal Windows operation (AV engines, monitoring agents, and Task Manager itself request it constantly), and **many published/default Sysmon configurations deliberately exclude ProcessAccess events with a `GrantedAccess` of `0x400` specifically to cut this noise down**. Treat this signal as **config-dependent, not guaranteed** — verify what your specific Sysmon deployment's `ProcessAccess` rule actually excludes before relying on it, and don't assume coverage exists just because Sysmon is deployed. Where it *is* logged, the tell isn't any single event — it's the **volume and breadth** (one source process opening dozens of distinct target processes across multiple distinct owning users, in a short window) that distinguishes it from routine monitoring-tool noise.

## Security Log — Privilege Use and Logon Events

- **What does *not* fire:** `DuplicateTokenEx` + `ImpersonateLoggedOnUser` against an **already-existing** logon session (the case here — LaZagne duplicates a token from a process that's already running, it doesn't establish a new logon) does **not** generate a new Security 4624 logon event. There is no new logon session being created; the duplicated token rides the target user's existing session ID. Don't expect to find a fresh 4624/Logon-Type-9 pattern here the way you would for a `RunAs /netonly`-style credential use.
- **What may fire, environment-dependent:** Security 4673/4674 (Sensitive Privilege Use) can fire when `SeDebugPrivilege` is exercised against an audited object, but this is gated by non-default "Audit Sensitive Privilege Use" policy and is inconsistent in practice — treat it as a bonus signal if already enabled for other reasons, not something to enable purely for this tool.
- **Bottom line:** the Security log's native logon/privilege-use events are a weak signal for the impersonation phase specifically — Sysmon process-creation/process-access coverage (above) and the filesystem trail (above) carry the real evidentiary weight.

## Network-Layer Evidence

None. LaZagne has no network client of its own (per `01`'s Prerequisites) — every module operates against local files, the local registry, or local process tokens. There is no C2 beacon, no outbound connection, and no target-side network signature to look for from LaZagne itself. Any network activity around a LaZagne run belongs to whatever delivered the binary or later exfiltrated its output — see `03`.

## Endpoint Security Product Behavior

- The standalone PyInstaller `.exe` is a **well-known, heavily signatured file** across commercial AV/EDR products — the tool's public GitHub presence and long history (since 2015) mean static signature detection is generally effective against an unmodified download, which is exactly why real-world operators are commonly observed renaming, repacking, or compiling from source with modifications.
- Both memory-reading modules (`ppypykatz`, `memorydump`) were **removed by the project itself** specifically because AV/EDR detection made them unreliable/risky to ship (per `01`) — meaning current-release LaZagne presents **no LSASS-memory-access behavior at all** for a behavioral EDR rule to catch, unlike Mimikatz. The `reg.exe save`/token-impersonation/`netsh.exe` behaviors documented above are what's left to catch behaviorally.
- A source-compiled or repacked build defeats static/hash-based detection entirely, same as any open-source tool — the process-creation and process-access *behaviors* described above are unaffected by recompilation and are the more durable detection surface (see `05`'s Hunting Priority table).

## Memory Forensics

- A live memory capture of a running LaZagne process can recover the current run's in-progress `constant.finalResults`/`constant.stdout_result` structures (Python objects holding already-decrypted plaintext credentials) directly from the process's own heap — standard Python-process memory-forensics approach (string/heap carving), no LaZagne-specific structure to look for.
- If a PyInstaller-frozen `.exe` was used, the process's memory also contains the unpacked embedded Python interpreter and bytecode archive — of secondary forensic interest (confirms the specific build/version in memory) but not where the actual credential material shows up.
- No LSASS-specific memory forensics angle applies (see Endpoint Security Product Behavior above) — this tool's current release doesn't touch LSASS.

## Distinguishing From Legitimate Administrative Activity

`reg.exe save hklm\sam`/`hklm\security`/`hklm\system` is also exactly what a legitimate backup process, AD/system-state-backup tooling, or a security team's own credential-hygiene audit would run. The differentiators:

- **Destination path** — a random 6-12-character extensionless filename in `%TEMP%` has no legitimate backup naming convention behind it; genuine backup tooling uses a predictable, documented path and filename.
- **Immediate deletion** — legitimate hive backups are retained; LaZagne's are deleted within the same run (`delete_hives()`'s `finally` block).
- **Parent process** — `cmd.exe /c reg.exe save ...` spawned from a Python/PyInstaller-bootloader process with no prior backup-software identity is a mismatch worth flagging even before the path/lifetime signals above.
- **The `netsh.exe wlan show profile ... key=clear`** command is one a help-desk technician might genuinely run once, interactively, to troubleshoot a WiFi issue — a single instance isn't inherently suspicious. Repeated invocations across multiple distinct SSIDs in quick succession, or paired with the `reg.exe` pattern above in the same session, is the differentiator.

## Building a Timeline

For an elevated `all -oA` run, the expected sequence on the executing host:

```
[T+0]     Binary execution begins (Prefetch/Amcache/Sysmon 1 for the LaZagne
          process itself, if it's a dropped standalone .exe — see 03 for
          the in-memory-execution case where this step is absent)
[T+0.1s]  IsUserAnAdmin() check passes → save_hives() →
          3x cmd.exe/reg.exe child processes (Sysmon 1 / Security 4688) →
          3x transient random-named files appear in %TEMP%
[T+~1s]   windows system-module pass runs (hashdump/lsa_secrets/mscache/
          autologon) → delete_hives() removes the 3 temp files
[T+~1-2s] Current-user pass — CryptUnprotectData/DPAPI reads against the
          operator's own session, no distinct new artifact class
[T+~2s+]  Phase 3 begins — mass OpenProcess/OpenProcessToken across every
          running PID (Sysmon 10, config-dependent per above), followed by
          DuplicateTokenEx/ImpersonateLoggedOnUser for each distinct SID
          found, re-running the module set per impersonated user
[T+var]   wifi module, if in scope and non-admin path taken → netsh.exe
          child process(es)
[T+end]   Output file written, if -oN/-oJ/-oA specified — its own filename
          timestamp should match this window's end almost exactly
```

Anchor an investigation on the `reg.exe save` child-process cluster first — it's the tightest, most distinctive timestamp group, and everything else in the run falls within a few seconds of it either side.
