# ProcDump / comsvcs.dll MiniDump — Overview

> 🔴 **Red Flag Principle:** These are two different launchers converging on the **exact same Win32 API call** — `MiniDumpWriteDump()`, exported by `dbghelp.dll`. `procdump.exe -ma lsass.exe` calls it directly; `rundll32.exe comsvcs.dll, MiniDump` calls it indirectly through an internal COM+ Services helper function that does nothing but wrap the identical call. Mechanically they are the same technique wearing two different front-end binaries. The forensic split that actually matters isn't "which tool" — it's that **ProcDump has to be delivered to the target** (a real, signed, but non-native binary landing on disk) while **`comsvcs.dll` is already sitting in `C:\Windows\System32\` on every Windows host that has ever existed**, needing nothing dropped at all. Anchor hunts on the shared `dbghelp.dll` load and the `OpenProcess()` access mask against `lsass.exe` — not on which binary name shows up in a process-creation log.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [ProcDump vs. comsvcs.dll — At a Glance](#procdump-vs-comsvcsdll--at-a-glance)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

This folder covers two mechanically related but provenance-distinct techniques toward the same goal: pulling `lsass.exe`'s process memory to disk for offline credential extraction. Both are **stealthier alternatives to Mimikatz's own direct LSASS read** (`sekurlsa::minidump`/`sekurlsa::logonpasswords` against a live handle) — see `../Mimikatz/sekurlsa (Credential Dumping)/` for the shared LSASS-internals/credential-structure mechanics, cross-linked throughout rather than re-derived here.

### ProcDump (Sysinternals)

- **Authors: Mark Russinovich and Andrew Richards.** ProcDump is part of the Sysinternals suite Russinovich began building in the 1990s; its original purpose is entirely legitimate — capturing crash/hang dumps of misbehaving applications for developers to triage CPU spikes, hung windows, and unhandled exceptions. Nothing about its design targets credential theft.
- **Microsoft acquired Sysinternals in July 2006** (same acquisition that brought in PsExec — see `../PsExec/01 - Overview.md`), and has maintained/redistributed ProcDump directly ever since under the Sysinternals brand.
- Verified live against the official page, [learn.microsoft.com/sysinternals/downloads/procdump](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) (byline: "By Mark Russinovich and Andrew Richards," live page dated 2026-07-09). **Open item:** unlike the PsExec Learn page (which states an explicit `v2.43`), the current ProcDump Learn page does not display an explicit version number in its front matter — treat the exact shipping version as unverified this session and re-check `Procdump.zip`'s own file properties at time of use.
- Companion open-source ports exist on GitHub — [microsoft/ProcDump-for-Linux](https://github.com/microsoft/ProcDump-for-Linux) and [microsoft/ProcDump-for-Mac](https://github.com/microsoft/ProcDump-for-Mac) — but the classic Windows `procdump.exe`/`procdump64.exe` binary itself is distributed only via the Sysinternals Live/download channel, not as buildable open source.
- **Genuine, Authenticode-signed Microsoft binary** — the same provenance story as PsExec: the signature isn't suspicious, its presence/context on a host that shouldn't have diagnostic tooling installed is.

### comsvcs.dll MiniDump

- `comsvcs.dll` is a core Windows library shipping with **COM+ Services** (Component Services), present in `C:\Windows\System32\` on every Windows install since COM+ was introduced with Windows 2000 — it is not a downloadable tool, has no version history of its own to track, and was never intended to be invoked this way.
- The `MiniDump` export is an **internal, undocumented helper function** (not a supported public API contract) that itself just calls the same `MiniDumpWriteDump()` function ProcDump calls directly. Its public discovery and documentation as a credential-dumping technique is credited by the LOLBAS Project to security researcher **modexp**, in a 2019 blog post: [MiniDumpWriteDump via COM+ Services DLL](https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/) — verified live against the LOLBAS Project's own [`Comsvcs` entry](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/), which cites the same credit and the same blog post.
- **Catalogued under MITRE ATT&CK [T1003.001](https://attack.mitre.org/techniques/T1003/001/)** (OS Credential Dumping: LSASS Memory) per LOLBAS's own entry, verified live.
- **A genuinely surprising finding from verifying LOLBAS's catalog directly:** ProcDump *also* has its own LOLBAS entry — [`Procdump` under `OtherMSBinaries`](https://lolbas-project.github.io/lolbas/OtherMSBinaries/Procdump/) — but it documents an entirely **different** abuse primitive: `procdump.exe -md <path.dll> explorer.exe` executes an arbitrary **unsigned DLL** through ProcDump's own `-md` (custom dump-callback DLL) mechanism, mapped to **[T1202](https://attack.mitre.org/techniques/T1202/)** (Indirect Command Execution), credited to Alfie Champion (@ajpc500) — **not** the LSASS-dumping use this page centers on. LOLBAS's own catalog does not document `-ma lsass.exe` as an entry at all; that usage is instead sourced from MITRE ATT&CK's T1003.001 procedure-example library (below). Don't conflate the two ProcDump abuse stories — this page covers the LSASS-dump one as its primary subject and the `-md` DLL-execution one as a secondary use case in `02`.
- **Real-world procedure examples naming both tools, verified live against MITRE ATT&CK T1003.001:** APT28, APT33, APT39, APT41, Earth Lusca, HAFNIUM, and Indrik Spider are all documented using ProcDump for LSASS dumping; Sandworm Team, Magic Hound, and VOID MANTICORE are documented using `comsvcs.dll` specifically. Both techniques are established, actively-used threat-actor tradecraft, not theoretical.

## How It Works

### The mechanical convergence

```
PROCDUMP PATH                                   COMSVCS.DLL PATH
──────────────                                   ────────────────
Operator resolves LSASS PID                      Operator resolves LSASS PID
(tasklist / Get-Process / wmic)                  (tasklist / Get-Process / wmic)
        │                                                 │
        ▼                                                 ▼
procdump.exe -ma <PID> lsass.dmp                 rundll32.exe comsvcs.dll, MiniDump
   (or procdump64.exe)                                <PID> lsass.dmp full
        │                                                 │
   [First run only, unless -accepteula:]           rundll32.exe LOADS comsvcs.dll into
   EULA dialog → writes HKCU\Software\             ITS OWN process space, then calls
   Sysinternals\ProcDump\EulaAccepted              the DLL's exported "MiniDump" function
        │                                                 │
        ▼                                                 ▼
procdump.exe calls OpenProcess() against          comsvcs.dll's MiniDump export calls
lsass.exe directly, requesting the access          OpenProcess() against lsass.exe —
rights DbgHelp needs (PROCESS_QUERY_              same access-rights request, just
INFORMATION | PROCESS_VM_READ |                    issued from inside rundll32.exe's
PROCESS_DUP_HANDLE at minimum)                     process instead of procdump.exe's
        │                                                 │
        └───────────────────┬─────────────────────────────┘
                             ▼
              Both call DbgHelp!MiniDumpWriteDump()
              (dbghelp.dll — Microsoft's own documented
              debug-dump API) against the opened LSASS
              handle, writing the .dmp file to disk
                             │
                             ▼
              If LSASS is running as a Protected Process
              Light (RunAsPPL=1): OpenProcess() fails with
              Access Denied for BOTH paths — a normal
              (non-protected) caller cannot open a PPL
              process for read access regardless of
              SeDebugPrivilege or admin/SYSTEM token
```

**The defining forensic insight:** because both techniques bottom out in the identical `dbghelp.dll!MiniDumpWriteDump()` call against `lsass.exe`, a detection strategy built around *that shared mechanic* (DLL image-load into an unexpected process, `OpenProcess()` access-mask against `lsass.exe`) catches both — and any future third launcher that reaches the same API — while a detection strategy built around either binary's literal name or command-line string catches neither once an operator renames the file or (for `comsvcs.dll`) calls the export by ordinal number instead of by name (see `05`'s Hunting Priority table).

### PPL as the actual gate on both techniques

Windows 8.1+ supports running `lsass.exe` as a **Protected Process (Light)** via the `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` registry value (verified live against [Microsoft Learn's "Configure added LSA protection"](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) page). When enabled, `WinInit` Event 12 logs `"LSASS.exe was started as a protected process with level: 4"` at boot. A non-protected caller — which both `procdump.exe` and `rundll32.exe` are, by default — cannot obtain a read-capable handle on a PPL process no matter what privilege level it runs at; both techniques fail outright with Access Denied. The only ways past this are (a) an administrator disabling `RunAsPPL` outright (a documented, auditable, reboot-required configuration change — Microsoft's own page shows exactly how, which is also exactly what a hunt should watch for: a `RunAsPPL` value change followed by a reboot followed by a dump attempt) or (b) a Bring-Your-Own-Vulnerable-Driver (BYOVD) kernel-level bypass. **Open item:** no specific BYOVD driver/tool is verified against a primary source in this pass — flagged rather than asserted, per this note's narrowed research footprint; if deeper BYOVD-bypass coverage is wanted, that's a follow-up.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Execution | Both are **local** techniques by design — neither ProcDump nor `comsvcs.dll` has any network client of its own. Remote use rides entirely on whatever lateral-movement/remote-execution tool delivers the command (`../PsExec/`, `../Impacket/psexec/`, `../Impacket/wmiexec/`, `../LOLBins/wmic/`, a C2 framework's own shell) |
| Target API | `DbgHelp!MiniDumpWriteDump()` (`dbghelp.dll`) — Microsoft's own documented debug/dump API, called by both techniques against a handle opened via `OpenProcess()` |
| Access control gate | Windows Protected Process Light (PPL) via `RunAsPPL` — governs whether the `OpenProcess()` call in either technique can succeed at all |
| MITRE ATT&CK | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory) for the LSASS-dump use of both tools; [T1202](https://attack.mitre.org/techniques/T1202/) (Indirect Command Execution) for ProcDump's separate `-md` unsigned-DLL-execution primitive (LOLBAS-catalogued, not LSASS-related) |
| Offline follow-on | The resulting `.dmp` is parsed offline (Mimikatz `sekurlsa::minidump`, pypykatz, or similar) — the dump *file* is the deliverable, not a live session; see `../Mimikatz/sekurlsa (Credential Dumping)/` |

## Command-Line Switches — Quick Reference

Verified verbatim against the official [Microsoft Learn ProcDump page](https://learn.microsoft.com/en-us/sysinternals/downloads/procdump) and the LOLBAS Project's live [`Comsvcs`](https://lolbas-project.github.io/lolbas/Libraries/comsvcs/) entry.

### ProcDump — Dump Types (the flags that matter most for this page)

| Flag | Plain-English meaning |
|---|---|
| `-mm` | **Mini** dump (default if no type flag given) — stacks + referenced memory + metadata only. Rarely useful for credential extraction; too shallow to contain decrypted secrets reliably |
| `-ma` | **Full** dump — all process memory (Image, Mapped, Private) + all metadata. **This is the flag used in essentially every real-world LSASS-dump procedure example** (`procdump.exe -ma lsass.exe lsass.dmp`) — it's the only type guaranteed to contain the memory regions Mimikatz-style parsers need |
| `-mt` | **Triage** dump — stacks only, limited metadata, with an *attempted* (not guaranteed) scrub of sensitive data. A smaller, less useful dump for this purpose |
| `-mp` | **MiniPlus** dump — all Private memory + Read/Write Image/Mapped memory, excludes the single largest >512MB private region. 10–75% the size of a Full dump while retaining most of what a Full dump has — a genuine stealth/size tradeoff an operator might choose over `-ma` |
| `-mc <Mask>` | **Custom** dump defined by a raw `MINIDUMP_TYPE` bitmask (hex) — full manual control over what's included |
| `-md <Callback_DLL>` | **Callback** dump — memory selection is delegated to a `MiniDumpCallbackRoutine` inside an operator-supplied DLL. **This is the flag LOLBAS's own `Procdump` entry documents for unsigned-DLL execution (T1202)** — a completely separate abuse path from LSASS dumping, see `02` |
| `-mk` | Also capture a kernel-mode dump alongside the user-mode one |

### ProcDump — Other flags relevant to this page

| Flag | Plain-English meaning |
|---|---|
| `-accepteula` | Silently accepts the Sysinternals EULA — required for unattended/scripted use, since a first run without it blocks on an interactive dialog. Still writes the `EulaAccepted` registry value (see `03`) — doesn't suppress the artifact, only the popup |
| `-r [1..5] [-a]` | Dump using a **clone** of the target process rather than suspending the live process directly — reduces the outage window on the target. Windows 7/8.0 uses Reflection; 8.1+ uses Page-file-backed Snapshots (PSS). `-a` skips the trigger entirely if concurrency limits would cause a prolonged suspend |
| `-o` | Overwrite an existing dump file at the destination path |
| `-n <Count>` | Number of dumps to write before exiting — relevant for a `-c`/`-p` triggered-monitoring use, less so for a one-shot LSASS pull |
| `-s <Seconds>` | Consecutive seconds a trigger condition must hold before dumping (default 10) — again, monitoring-trigger-specific |
| `-w` | Wait for the named process to launch if it isn't running yet |
| `-64` | Force a 64-bit dump of a 32-bit process running under WOW64 (irrelevant for `lsass.exe`, which is always native-bit) |
| `-wer` | Queue the dump to **Windows Error Reporting** instead of (or alongside) writing it directly — an alternate delivery path worth knowing exists, see `02` |
| `-i [Dump_Folder]` / `-u` | **Install**/**uninstall** ProcDump as the system's AeDebug postmortem debugger — persistence-adjacent, out of scope for a one-shot LSASS pull but worth knowing the tool supports it |
| `<Process_Name> \| <PID>` | The target — `lsass.exe` by name (only works if exactly one match exists) or an explicit PID (unambiguous, the pattern real-world procedure examples favor) |
| `<Dump_File> \| <Dump_Folder>` | Output path. Default filename pattern if omitted: `PROCESSNAME_YYMMDD_HHMMSS.dmp` |

### comsvcs.dll — MiniDump Syntax

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> <Dump_File> full
```

| Component | Plain-English meaning |
|---|---|
| `rundll32.exe` | The genuine, signed Windows LOLBIN that loads an arbitrary DLL and calls a named export inside it — the actual "front-end" binary here, not `comsvcs.dll` itself |
| `C:\Windows\System32\comsvcs.dll` | The target library — already present on every Windows host, nothing to deliver |
| `MiniDump` | The exported function name being called. **Can also be invoked by ordinal number (`#24`) instead of the literal string `"MiniDump"`** — commonly cited across third-party write-ups as a command-line-string-matching evasion, though this specific ordinal isn't independently confirmed against a primary Microsoft source in this pass; treat as commonly-reported, not primary-source-verified |
| `<PID>` | Target process ID — `lsass.exe`'s PID, resolved beforehand |
| `<Dump_File>` | Output path for the `.dmp`/`.bin` file |
| `full` | Dump-type flag — per LOLBAS's own documented syntax, produces a full memory dump equivalent in purpose to ProcDump's `-ma` |

## ProcDump vs. comsvcs.dll — At a Glance

| | ProcDump | comsvcs.dll |
|---|---|---|
| Native to Windows? | **No** — must be delivered to the target | **Yes** — ships in every Windows install |
| Binary dropped on target? | Yes — `procdump.exe`/`procdump64.exe` lands on disk (Zone.Identifier ADS if downloaded) | **No** — only the output `.dmp` file is new |
| Authenticode-signed? | Yes, by Microsoft | N/A — no new binary, `rundll32.exe` itself is the (also Microsoft-signed) launcher |
| LOLBAS-catalogued for LSASS dumping? | **No** — LOLBAS's `Procdump` entry documents `-md` unsigned-DLL execution (T1202), not `-ma` LSASS dumping | **Yes** — LOLBAS's `Comsvcs` entry documents exactly this (T1003.001) |
| Stated privilege requirement | Local admin + `SeDebugPrivilege` (or equivalent) to open a handle on `lsass.exe` | LOLBAS's own entry states **SYSTEM** — broader community write-ups more often describe local-admin + `SeDebugPrivilege` as sufficient, matching ProcDump's requirement; this is a real discrepancy between sources, flagged rather than silently resolved |
| Blocked by PPL (`RunAsPPL`)? | Yes | Yes — both call the identical `OpenProcess()`+`MiniDumpWriteDump()` sequence |
| Needs a remote-execution vector to use against another host? | Yes — no network client of its own | Yes — same, no network client of its own |
| EULA/first-run artifact? | Yes — `EulaAccepted` registry value | No — no license gate on a built-in DLL |

## Quick Use-Case List

- Baseline full-memory LSASS dump via `procdump.exe -ma`
- Reduced-size MiniPlus dump (`-mp`) as a stealth/size tradeoff over a Full dump
- Triage dump (`-mt`) for a smaller, more limited capture
- Clone-based capture (`-r`) to shrink the target-process outage window and blend into legitimate crash-monitoring behavior
- Queuing the dump through Windows Error Reporting (`-wer`) instead of a direct file write
- Renaming `procdump.exe`/`procdump64.exe` on disk to defeat filename-based detection (PE metadata survives — mirrors the `../PsExec/` and `../Rclone/` precedent)
- Fully unattended/scripted invocation (`-accepteula`)
- ProcDump's separate `-md` callback-DLL mechanism for unsigned-DLL execution (T1202) — a distinct capability from LSASS dumping, included because it's the technique LOLBAS actually catalogs under ProcDump's name
- Baseline `comsvcs.dll` MiniDump via `rundll32.exe`, invoked by name
- `comsvcs.dll` MiniDump invoked by export ordinal (`#24`) instead of the literal string, to evade command-line-string detection
- Checking/disabling `RunAsPPL` before attempting either technique against a protected `lsass.exe` — a detection-relevant, Microsoft-documented, reboot-gated administrative action, not a silent bypass
- Fleet-wide/chained deployment: pushing `procdump.exe` and triggering the dump via an already-built remote-execution tool (`../PsExec/`, `../Impacket/wmiexec/`, `../LOLBins/wmic/`)
- Post-collection exfiltration of the `.dmp` file via an already-built exfil tool (`../Rclone/`)
- Offline parsing of the resulting `.dmp` via Mimikatz `sekurlsa::minidump` (cross-linked, not re-derived — see `../Mimikatz/sekurlsa (Credential Dumping)/`)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | ProcDump | comsvcs.dll |
|---|---|---|
| Delivery to target | Must be copied/staged (any remote-execution/lateral-movement vector already in this repo) | None — already present |
| Privilege on target | Local admin + `SeDebugPrivilege` (or equivalent) to open a read-capable handle on `lsass.exe` | Same, per most community reporting — though LOLBAS's own entry states SYSTEM (see comparison table above) |
| `lsass.exe` PID | Resolved beforehand (`tasklist`, `Get-Process`, `wmic process where name='lsass.exe'`) | Same |
| LSASS not running as PPL, or `RunAsPPL` disabled | Required — otherwise `OpenProcess()` fails outright | Required — identical gate |
| EULA acceptance | First interactive run, or `-accepteula` for scripted use | N/A |
| Remote execution vector, if targeting another host | Required — no network client of its own | Required — same |
