# hunt_persistence.ps1

Read-only triage sweep of Windows persistence mechanisms (MITRE ATT&CK **TA0003**) across 32
technique families. Built for live response — including CrowdStrike RTR — on hosts that may
already be compromised.

The tool answers one question per artifact: *does this entry point somewhere it shouldn't?*
It never assumes a location is malicious because it exists, and it never assumes a location is
clean because nothing flagged — anything it could not read is named in the coverage report.

- **Script:** `hunt_persistence.ps1` (v2.0)
- **Author:** Suvas Patel
- **Predecessor:** `archive/hunt_persistence_v1.ps1` (superseded; this is a from-scratch rewrite)
- **Technique references:** `Windows/10 - Persistence Mechanisms/*.md` in this repo

## Contents

- [Safety contract](#safety-contract)
- [Usage](#usage)
- [RTR deployment](#rtr-deployment-real-time-response)
- [Run modes](#run-modes)
- [Optional switches](#optional-switches)
- [Time handling](#time-handling)
- [Output layout](#output-layout)
- [Scoring model](#scoring-model)
- [Absolute vs Scored](#absolute-vs-scored)
- [Module reference](#module-reference)
- [False-positive controls](#false-positive-controls)
- [Known limitations](#known-limitations)
- [Verified baseline](#verified-baseline)

## Safety contract

| Property | Guarantee |
|---|---|
| Read-only | Every registry and WMI access is a read. No `Set-`, `New-`, `Remove-`, `Stop-` or `reg load` call exists anywhere in the script. |
| No hive loading | Unloaded user hives are **reported, not mounted** — loading a hive is a write to the registry namespace. |
| Console-only | No export path, no `-OutFile`. Redirect the console stream if you need a file. |
| Non-interactive | No `Read-Host`, no confirmation prompts. Safe for RTR, which has no stdin. |
| Degrades without elevation | Runs to completion unelevated; every access-denied target is listed in the coverage report, never silently reported clean. |
| No truncation | Output columns size themselves to the live console and wrap. A truncated `ImagePath` is the one thing an analyst cannot afford to lose. |
| Host-agnostic | No hardcoded user names, host names, hashes, or per-host allowlists. Every FP control derives from path trust, signature verification, or an OS-documented default. |

**Minimum version:** PowerShell 3.0+ (`#Requires -Version 3.0` — the script uses ordered
hashtables, which do not exist in PowerShell 2.0). Developed and verified against PowerShell
5.1 on Windows 10/Server 2016+; not tested against PowerShell 7/`pwsh`. Below 3.0 the script
refuses to run and PowerShell prints its own version error rather than an in-script one.

**64-bit only, for full coverage.** If launched as a 32-bit `powershell.exe`/`pwsh.exe` process
on a 64-bit OS, WOW64 transparently redirects `System32` filesystem access and non-`WOW6432Node`
registry access to the 32-bit view with no error — the native-vs-32-bit model this tool relies
on (see [False-positive controls](#false-positive-controls)) would silently be wrong. The script
detects this mismatch and prints a loud warning; it does not attempt to force the 64-bit view.

## Usage

```powershell
.\hunt_persistence.ps1                                   # Quick sweep (default)
.\hunt_persistence.ps1 -Deep                             # all 32 modules
.\hunt_persistence.ps1 -Deep -AnomaliesOnly              # only what scored
.\hunt_persistence.ps1 -AnomaliesOnly -MinSeverity High  # HIGH only
.\hunt_persistence.ps1 -Modules scheduledtasks,wmi       # targeted re-run
.\hunt_persistence.ps1 -Modules runkeys -Verbose         # every column
.\hunt_persistence.ps1 -Days 14 -AnomaliesOnly           # narrow to an incident window
.\hunt_persistence.ps1 -ListModules                      # module catalog
.\hunt_persistence.ps1 -Help
```

Run elevated for full coverage. Unelevated runs work but cannot read `SYSTEM\CurrentControlSet`
in full, other users' hives, or other profiles' files.

All switches and module tokens are **case-insensitive** (`-modules RUNKEYS` is valid).
Module tokens accept both PowerShell array syntax and a comma string, so both of these work —
the second is how RTR invokes scripts:

```powershell
.\hunt_persistence.ps1 -Modules RunKeys,WMI
powershell -File hunt_persistence.ps1 -Modules RunKeys,WMI
```

## RTR deployment (Real Time Response)

**For Falcon Insight or endpoint response platforms with size constraints**, use
`hunt_persistence_loader.ps1`:

```powershell
# The loader is ~33KB (fits RTR's 40KB limit)
powershell -File hunt_persistence_loader.ps1 -Deep -MinSeverity High
powershell -File hunt_persistence_loader.ps1 -Modules RunKeys,WMI
```

The loader embeds a gzip+base64-compressed copy of `hunt_persistence.ps1` (117KB → 33KB),
decompressed and run entirely in memory — nothing is written to disk. **All arguments and modes
work identically** — pass the same arguments as you would to `hunt_persistence.ps1` directly.
`-Help` is the one exception: run the full script directly, or read this README, for complete
help text.

Rebuild the loader after any change to `hunt_persistence.ps1`: `.\build_loader.ps1`. It strips
comments (via the PowerShell tokenizer, so string content is never touched), compresses, and
fails loudly if the result would exceed 40KB.

## Run modes

Mutually exclusive. If none is given, **Quick** runs silently — no error, no usage prompt.

| Mode | Modules | Notes |
|---|---|---|
| `-Quick` | 25 | Default. ~15 s on a typical workstation. |
| `-Deep` | 32 | Quick **plus** the 7 Deep modules — Deep adds to Quick, it does not replace it. ~35 s. |
| `-Modules <tokens>` | exact set | Any tier, for targeted re-runs. |

## Optional switches

All four work identically regardless of run mode.

| Switch | Behavior |
|---|---|
| `-Verbose` | Appends `More`, `Target`, `Trust`, `Signature`, `Score` columns to every table, and un-suppresses quiet rows (confirmed-stock values, static rosters). Evidence codes are always in the `Tag` column, in every mode. |
| `-InventoryOnly` | Raw enumeration on its own: no scoring, no tiering, no suppression of any kind (confirmed-stock rows included). **Verification still runs**, so trust/signature columns hold real data. Cannot combine with `-AnomaliesOnly` or `-MinSeverity` — the script errors rather than silently ignoring a flag. |
| `-AnomaliesOnly` | Narrows displayed rows to the scored tiers; modules with nothing flagged are skipped entirely rather than printed empty. |
| `-MinSeverity High\|Notable` | Alone, controls which rows carry an inline `[TIER]` tag. With `-AnomaliesOnly`, it is the filter threshold. Default `Notable`. (`Low` is deliberately absent: LOW never surfaces at any setting.) |

## Time handling

Two independent mechanisms that v1 conflated:

**RECENCY scoring** is always on, fixed at a 14-day-from-now lookback, and is not configurable.
It contributes +1 to the score. It is deliberately **withheld** when the resolved target is
Microsoft-signed in a trusted path — Windows rewrites its own task XML and registry keys
constantly during servicing, so recency there carries no investigative signal and would push
stock entries over the threshold on a freshly patched host.

**`-Since` / `-Days` / `-Until`** are a pure *display* filter, entirely decoupled from scoring.

> ⚠️ **The time filter applies uniformly to everything, including tagged HIGH/NOTABLE findings.**
> A real finding whose registry key or file was last written before the `-Since` cutoff will
> **not display** while the filter is active. Narrowing to an incident window is a deliberate
> scope decision, not a "reduce noise" button. The summary line always reports how many items
> the window hid.

Items with **no resolvable timestamp** (WMI subscriptions, TaskCache orphans) are
**filter-exempt** — always shown. "Unknown" cannot be proven to fall outside the window, and
excluding on an absence of evidence is a different failure mode than excluding a known-old
timestamp.

If both `-Since` and `-Days` are given, `-Since` wins and `-Days` is ignored — they set the same
boundary, so there is nothing to combine. An inverted window (`-Since` later than `-Until`) is
rejected with an explicit error rather than silently displaying zero dated items.

## Output layout

Four sections, in this order:

1. **Banner** — script/version/author, UTC run time, hostname, user, elevation state, OS, mode,
   module count, active time window, and the exact arguments the script was invoked with. A
   yellow warning block follows when not elevated.
2. **Findings** — one condensed table per module: `Item | Scope | Modified | Detail | Tag`
   (plus `More | Target | Trust | Signature | Score` under `-Verbose`). `RunKeys` rows are
   grouped under the full registry path they live in, with the owning account resolved, so a
   key can be reviewed and remediated as a unit. Each module ends with a
   `[N row(s) suppressed -- reason]` line whenever anything was hidden.
3. **Tag legend** — every tag that appeared in this run and what it means. Only tags that
   actually fired are listed.
4. **Summary** — one labelled block rather than a run of banner sections:

   | Line | Shown when | Carries |
   |---|---|---|
   | `Findings` | always | HIGH/NOTABLE counts, items enumerated, modules run |
   | `Window` | a time filter is active | how many items it hid, scored ones included |
   | `Coverage` | always | `complete`, or each unreadable target and why, with a run-wide `re-run elevated` suffix appended whenever the run itself is unelevated (not computed per gap — a gap's own `Reason` text separately says "(re-run elevated)" when that specific target was the cause) |
   | `Failed` | a module threw | which modules were skipped |
   | `Hives` | a profile hive is unloaded | each profile whose per-user registry could not be read |

   Unreadable targets are the honesty of the report: they are the places the run could not
   speak for, and they are never folded into a clean result. Profiles whose `NTUSER.DAT` is
   not mounted are out of reach by design — loading a hive is a write — but their **on-disk**
   artifacts (Startup folders, PowerShell profiles, Office startup folders) were still swept.

### The Tag column

The `Tag` column carries the tier (when the row is at or above `-MinSeverity`) followed by the
evidence codes that produced it — for example `HIGH,UNTRUSTED-PATH,TARGET-MISSING,RECENCY`.

A tier suffixed with `*` (`HIGH*`, `NOTABLE*`) means an **Absolute** rule fired: the module
concluded HIGH/NOTABLE from presence or deviation alone, not from accumulated evidence weight —
see [Absolute vs Scored](#absolute-vs-scored). A tier with no `*` was reached by summing the
listed evidence tags' weights against the [Scoring model](#scoring-model) table. This is the
only place the distinction is visible; without it, an Absolute-HIGH and a Scored-HIGH render
identically. The tag legend spells out the `*` meaning whenever it appears in a run.

**Worked example:** a row tagged `HIGH,UNTRUSTED-PATH,TARGET-MISSING,RECENCY` (no `*`) is
`RunKeys`, a Scored module — `UNTRUSTED-PATH` (2) + `TARGET-MISSING` (2) + `RECENCY` (1) = 5,
which crosses the HIGH threshold on accumulated evidence. A row tagged `HIGH*,NON-DEFAULT-VALUE`
from `Winlogon` is HIGH because `Shell` did not equal `explorer.exe` — an Absolute rule — not
because `NON-DEFAULT-VALUE`'s own weight (2) reached the threshold; the evidence tag is present
for context, but the tier came from the module's own presence check.

There is deliberately **no separate anomaly-queue section**. The tag column plus the legend
already carry the tier, the evidence and its meaning, so restating each finding as its own card
was duplicated output and duplicated code. A row scoring below `-MinSeverity` still shows its
evidence codes, which is what keeps a LOW-but-interesting row (an OS-signed `LOLBIN`, say)
readable at a glance.

The `More`/`Extra` column (`-Verbose` only) carries free-text, per-module context that doesn't
fit any other column — scheduled-task triggers and last-run time, a `FileAssoc` ProgID, `ComFull`
CLSIDs, a `Services` `DisplayName`, a signature census line. What it holds is module-specific;
treat it as supplementary detail, not a fixed schema.

Column widths are computed from the data and the live console width, then shrunk widest-first
until the row fits; cells wrap at spaces or path separators. Verified to wrap cleanly at 80
columns with zero truncation.

## Scoring model

Weighted evidence tags accumulate into a score; the score maps to a tier. Thresholds match the
sibling tools in this repo, so a tier means the same thing across `hunt_lnk.ps1` and this script.

| Tier | Score |
|---|---|
| **HIGH** | ≥ 5 |
| **NOTABLE** | ≥ 3 |
| LOW | < 3 (enumerated as context, never surfaced in the anomaly queue) |

| Evidence tag | Weight | Meaning |
|---|---|---|
| `ENCODED-COMMAND` | 4 | Encoded/base64 payload in the command line |
| `DOWNLOAD-CRADLE` | 4 | Downloads and executes remote content |
| `SIGNATURE-INVALID` | 3 | Authenticode hash mismatch |
| `USER-WRITABLE-PATH` | 3 | Target in Temp/AppData/Downloads/profile |
| `SUSPICIOUS-CONTENT` | 3 | Script file content matches download/execute patterns |
| `TARGET-MISSING` | 2 | Registered target does not exist on disk |
| `UNTRUSTED-PATH` | 2 | Target outside Windows and Program Files |
| `UNSIGNED` | 2 | Target not Authenticode-signed |
| `LOLBIN` | 2 | Resolves to an interpreter / living-off-the-land binary |
| `REGISTRATION-ORPHAN` | 2 | Artifacts that should agree, don't |
| `PER-USER-OVERRIDE` | 2 | HKCU registration shadows the machine-wide definition |
| `HIDDEN` | 2 | Configured to stay out of the default UI view |
| `NON-DEFAULT-VALUE` | 2 | Deviates from the documented Windows default |
| `REMOTE-URL` | 2 | Command line fetches from an `http`/`https`/`ftp` URL |
| `USER-WRITABLE-ARG` | 2 | A LOLBIN is handed a file from a user-writable location |
| `HANDLER-CHAIN` | 3 | Command runs something extra and then chains to the real handler |
| `USERCHOICE-OVERRIDE` | 2 | Explorer's effective handler for this user differs from the machine default |
| `PRECEDES-SMB` | 1 | A non-OS-vendor network provider is ordered ahead of `LanmanWorkstation` |
| `OBFUSCATION-FLAGS` | 1 | Hidden-window / policy-bypass flags |
| `RECENCY` | 1 | Written in the last 14 days (never sufficient alone) |

Weak obfuscation flags promote to `ENCODED-COMMAND` only when stacked with a URL or a base64
blob, so a stock `-NoProfile` launcher stays quiet.

`USER-WRITABLE-ARG` is gated on `LOLBIN` deliberately: an ordinary application reading its own
config out of `AppData` is normal, whereas an interpreter being pointed at a script there is
the drop-and-persist pattern. It exists because the resolved target alone cannot show this —
`wscript.exe C:\Users\Public\x.vbs` resolves to `wscript.exe`, which is a signed Microsoft
binary in `System32`. Both tags were measured at **zero** occurrences across every command line
on a clean reference host before being given weight.

A regression harness for this scoring lives at `lolbin_suppression_test.ps1` in the output
folder: it drives the script's own `Add-Finding` and suppression predicate with synthetic
LOLBIN persistence entries (`cmd /c`, encoded PowerShell, `certutil`, `rundll32`, `mshta`,
`wscript`, `regsvr32`, `bitsadmin`) plus benign Microsoft controls, and asserts that every
abuse case displays while the controls suppress. Re-run it after changing any weight.

## Absolute vs Scored

The distinction a contributor needs to know before adding an evidence tag.

**Absolute** — presence or deviation is conclusive on its own; the score is irrelevant and the
tier is fixed by the module.

| Module | Absolute condition | Tier |
|---|---|---|
| Winlogon | `Shell` ≠ `explorer.exe` | HIGH |
| Winlogon | `Userinit` has more than one comma-separated entry | HIGH |
| Winlogon | Any per-user `Shell` override exists | HIGH |
| Winlogon | Any `Notify` subkey on Vista+ | NOTABLE |
| IFEO | `Debugger` set on any of the 7 accessibility binaries | HIGH |
| IFEO | `GlobalFlag` 0x200 + `SilentProcessExit\MonitorProcess` | NOTABLE |
| OfficeTest | `Office test\Special\Perf` exists at all | HIGH |
| ComWatchlist | Per-user override of a watchlist CLSID | HIGH |
| BootExecute | Any deviation from `autocheck autochk *` | HIGH |
| SafeBoot | `AlternateShell` ≠ `cmd.exe` | HIGH |
| AppInitCerts | `AppInit_DLLs` populated **and** `LoadAppInit_DLLs=1` | NOTABLE |
| AppInitCerts | Any `AppCertDLLs` entry | NOTABLE |
| CommandProcessorAutoRun | Any non-empty `AutoRun` | NOTABLE |
| EnvHijack | Any watched variable populated | NOTABLE |
| DllSearchOrder | `SafeDllSearchMode = 0` | NOTABLE |
| LSAPackages | `OSConfig` mirror out of sync with the primary key | NOTABLE |
| BootLogonScripts | `UserInitMprLogonScript` populated | NOTABLE |
| ScheduledTasks | TaskCache entry with no task XML on disk | NOTABLE |
| FullSignaturePass | `HashMismatch` on re-verification | HIGH |
| FullSignaturePass | Unsigned binary inside a Windows directory | NOTABLE |
| NetworkProviderOrder | `ProviderOrder` and the parallel `HwOrder` copy disagree | NOTABLE |
| DllSearchOrder | `DllDirectory`/`DllDirectory32` deviates from the documented default | HIGH |
| DllSearchOrder | A `KnownDLLs` roster entry contains a path separator (not a bare file name) | HIGH |
| DllSearchOrder | A `KnownDLLs` roster entry exists on disk but is not OS-vendor-signed | HIGH |

`NetworkProviderOrder` is a mix: the `Order`/`HwOrder` mismatch above is Absolute, its
per-provider ordering/registration rows are Scored (see the bucket below) — same pattern as
`IFEO`, `LSAPackages`, `BootLogonScripts`, `SafeBoot`, `EnvHijack`. `DllSearchOrder` has no
Scored rows at all: every finding it reports is one of the four Absolute rules above, or a
zero-evidence inventory row (an architecture-specific `KnownDLLs` entry with no file on disk).

**Scored** — everything else. These need corroborating weak signals (path trust, signature,
command shape, recency) to separate attacker-controlled from benign: `RunKeys`,
`StartupFolders`, `ShellFolderRedir`, `Services`, `ServiceDll`, `ScheduledTasks` (normal
actions), `WMI`, `ActiveSetup`, `BootLogonScripts` (GPO scripts), `NetshHelpers`, `PSProfiles`,
`SafeBoot`, `NetworkProviderOrder` (provider ordering/registration), `FileAssoc`, `Screensaver`,
`ComFull`, `OfficeAddins`, `SysvolGpo`, `BitsJobs`, `CredentialProviders`, `ShellExt`, `IFEO`
(non-accessibility targets), `LSAPackages` (individual entries), `EnvHijack` (the PATH-ahead-of-
System32 check only — watched-variable population is the Absolute row above).

## Module reference

### Quick tier (25)

| Token | ATT&CK | What it reads | What makes it a finding |
|---|---|---|---|
| `RunKeys` | T1547.001 | `Run`, `RunOnce`, `RunOnceEx`, `Policies\Explorer\Run` under HKLM + WOW6432Node + every loaded user hive; `RunServices`/`RunServicesOnce` under HKLM + WOW6432Node only (no per-user equivalent exists); legacy `Windows NT\CurrentVersion\Windows` `load`/`run` | Target resolves outside Windows/Program Files, is missing, unsigned, or the command line is encoded/a download cradle. Legacy `load`/`run` are non-default on their own. |
| `StartupFolders` | T1547.001 | All-users and per-profile Startup folders **on disk**; `.lnk` targets resolved via COM | Same target-trust logic. Filesystem-side by design so a profile with no loaded hive is still swept. |
| `ShellFolderRedir` | T1547.001 | `User Shell Folders` / `Shell Folders` `Startup` and `Common Startup` per user hive | Configured path differs from the stock per-profile Startup path — a redirect relocates the sweep above without touching a Run key. Confirmed-stock rows are quiet. |
| `Services` | T1543.003 | Every `Services\*\ImagePath`, `Start`, `ObjectName`; `DisplayName` is carried into the `-Verbose`-only `More` column, not used for verification | Target trust/signature. svchost-hosted services are skipped here — see `ServiceDll`. |
| `ServiceDll` | T1543.003 | `Services\*\Parameters\ServiceDll` and the `-k` group | Only the loaded DLL is evaluated, never svchost.exe. The process tree looks normal; this registry value is the only tell. |
| `ScheduledTasks` | T1053.005 | Task XML under `System32\Tasks` + `SysWOW64\Tasks` (actions, triggers, principal, `Hidden`), `TaskCache\Tasks`, live `Get-ScheduledTask`/`Get-ScheduledTaskInfo` | Target trust/signature per action; `Hidden`; and triad inconsistency — an entry in any one of filesystem / TaskCache / live scheduler but not the others. `ComHandler` actions resolve the CLSID and flag per-user overrides. |
| `WMI` | T1546.003 | `root\subscription` filters, consumers, bindings | Only a **bound** triad scores. Orphaned halves are inert and shown as quiet context. `ActiveScriptEventConsumer` script text is pattern-matched since it never touches disk. |
| `Winlogon` | T1547.004 | `Shell`, `Userinit`, `Notify\*`, per-user `Shell` | Absolute — see table above. `Userinit` is judged on entry *count*, not string equality: the stock value legitimately ends in a trailing comma. |
| `LSAPackages` | T1547.005 | `Lsa` Authentication/Notification/Security Packages + `OSConfig` mirror | Each bare name resolved to `System32\<name>.dll` and verified individually — no assumed-safe skip list, because password-filter software legitimately populates Notification Packages. Malformed/path-shaped entries are caught before naive resolution. |
| `IFEO` | T1546.012 / .008 | IFEO `Debugger` and `GlobalFlag`/`SilentProcessExit` under both registry views | Accessibility-binary `Debugger` is absolute regardless of what the debugger is. Everything else is scored normally. |
| `AppInitCerts` | T1546.010 / .009 | `AppInit_DLLs` + `LoadAppInit_DLLs` (both views), `AppCertDLLs` | Populated-vs-active is surfaced explicitly; a dormant `AppInit_DLLs` is reported but not treated as live. |
| `ActiveSetup` | T1547.014 | `Installed Components\*` `StubPath`, `Version`, `IsInstalled`, plus each user's HKCU version | StubPath trust/command shape. The HKLM↔HKCU version delta is zero-weight context — it is normal after any legitimate update. |
| `BootLogonScripts` | T1037.001 / .003 | `UserInitMprLogonScript`, GPO `Scripts\Startup\Shutdown` registry cache, local GPO script folders on disk | `UserInitMprLogonScript` is absolute. Only the **on-disk local GPO script-cache files** are content-scanned; the registry-cache entries (which point at scripts by path) get target/trust/signature verification but not a content scan. No-ops quietly on a standalone host. |
| `NetshHelpers` | T1546.007 | `SOFTWARE\Microsoft\Netsh` (both views) | Helper value names are opaque vendor identifiers, so path/signature verification is the only usable filter. |
| `PSProfiles` | T1546.013 | All profile paths for both engines, AllUsers and per-profile, including OneDrive-redirected `Documents` | None exist on a stock install, so existence is context (LOW); **content** matching download/execute patterns is the finding. Trust/signature verification is deliberately skipped — a per-user `.ps1` is user-writable and unsigned by definition. |
| `CommandProcessorAutoRun` | Unmapped | `Command Processor\AutoRun`, machine and per-user | Any non-empty value is NOTABLE; a LOLBIN or encoded payload promotes it. Some enterprises legitimately use this for environment setup. |
| `EnvHijack` | T1574.012 / .007 | `COR_PROFILER` family, `windir`, and `PATH` in both the machine and per-user `Environment` keys | Watched variables have no benign default population. `windir` only flags when it is not the real Windows directory. PATH entries are only flagged when positioned ahead of System32 **within the same list**. |
| `SafeBoot` | Unmapped | `SafeBoot\Minimal` / `Network` roster, `AlternateShell`, and the binary behind every listed service | `AlternateShell` deviation is absolute. Each roster entry is **resolved to the service binary it permits in Safe Mode and verified** — the question the technique turns on is whose code still runs when an analyst boots to Safe Mode to remediate, and the answer should be the OS vendor's. Baseline suppression hides the stock set (135 entries on the reference host — this count is host- and build-specific, not a fixed contract) and leaves any third-party entry visible. Orphans are reported only for entries whose own type value is `Service`; `Driver Group` entries and device setup classes (`Mouse`, `Volume`, class GUIDs) never have a service key, so demanding one reported most of a stock roster as orphaned. |
| `NetworkProviderOrder` | T1556.008 | `ProviderOrder`, the parallel `HwOrder` copy, each provider's `NetworkProvider\ProviderPath`, and every service registering a provider | Every name cross-referenced against its own registration — a name with nothing behind it is the setup half of credential interception via `NPLogonNotify()`. Also checks the reverse: a provider DLL registered under a service but **absent from `ProviderOrder`** is staged rather than live and is invisible to a sweep that only walks the order string. `Order` and `HwOrder` are compared, since the two normally agree. Position matters — every provider ahead of `LanmanWorkstation` is offered the logon notification first — so a **non-OS-vendor** provider in that position carries `PRECEDES-SMB`. Windows itself ships `RDPNP` and `P9NP` ahead of SMB, so those are not tagged. No provider-name allowlist. |
| `BootExecute` | Unmapped | `Session Manager\BootExecute` | Any deviation from the single documented stock value. Runs earlier than anything else in user mode. |
| `FileAssoc` | T1546.001 | A narrow watchlist of script/executable extensions, resolved through the ProgID indirection to the actual `shell\open\command`, machine-wide and per user. Also reads `Explorer\FileExts\<ext>\UserChoice`, which is what Explorer actually honours on a double-click and overrides the Classes association entirely. | The **command is the output** — what really runs when this file type is opened — with the ProgID shown as context under `-Verbose`. A `HKCU\Software\Classes` override is a registry hijack and carries `PER-USER-OVERRIDE`; a `UserChoice` entry is what Windows itself writes when a user picks an app, so it is reported but not treated as evidence. The resolved handler is then judged normally (trust, signature, `LOLBIN`, `HANDLER-CHAIN`). Deliberately narrower than the document-handler space. |
| `Screensaver` | T1546.002 | `Control Panel\Desktop` `SCRNSAVE.EXE`, `ScreenSaveActive`, `ScreenSaveTimeOut` per user hive | Target trust/signature, but only verified when `ScreenSaveActive=1`. A dormant hijack is still displayed, just not scored as live. |
| `OfficeTest` | T1137.002 | `Office test\Special\Perf`, HKLM and per-user | Existence alone. Not created by any Office install or update. |
| `DllSearchOrder` | T1574.001 | `SafeDllSearchMode`, the `KnownDLLs` roster, and `DllDirectory`/`DllDirectory32` | A DLL-hijacking **posture** check rather than a persistence finder. `SafeDllSearchMode=0` makes the current directory outrank System32, which is what enables classic search-order hijacking. `DllDirectory` is where every pre-mapped KnownDLL is loaded from, so repointing it redirects the whole set at once — validated against the documented default. Each roster entry is resolved and verified: one carrying a path separator instead of a bare file name, or one that exists but is not OS-vendor-signed, is a replaced pre-mapped system DLL. Entries with no file on disk are inventory, not findings — architecture-specific entries (ARM emulation on an x64 host) legitimately have none. |
| `ComWatchlist` | T1546.015 | A small, explicitly non-exhaustive set of stable, documented-abused shell CLSIDs, HKCU only | Any per-user override at all. These CLSIDs have no normal HKCU counterpart. |

### Deep tier (7)

| Token | ATT&CK | What it reads | Notes |
|---|---|---|---|
| `ComFull` | T1546.015 | Every per-user `Software\Classes\CLSID\*\InprocServer32` | HKLM excluded by design — COM hijacking is inherently a per-user-override technique. **Rows are collapsed per (user, target DLL)**: one application can register thousands of CLSIDs that all resolve to a single DLL (Java registers ~2 900 per profile), and the forensic question is which DLL loads, not which CLSID reached it. Collapsing loses nothing and makes an outlier easier to spot — a hijack pointing elsewhere is its own target and gets its own row. CLSIDs that shadow an HKLM class carry `PER-USER-OVERRIDE`. |
| `FullSignaturePass` | Unmapped | Re-derives signature/trust across every service and scheduled-task target | Uses the shared signature cache, so it adds no verification cost after `Services`/`ScheduledTasks`. Emits only failures plus a quiet census line. Task XML timestamps are wired through so rows participate in time-narrowing. |
| `OfficeAddins` | T1137.006 | `Office\<ver>\<app>\Addins\*` across every installed version, HKLM + per-user, ProgID→CLSID→DLL; plus Word `STARTUP` / Excel `XLSTART` files | Office versions walked dynamically — a host upgraded across versions can carry a stale-but-launchable registration. `.wll`/`.xla` files load by presence alone and have no registry footprint. |
| `SysvolGpo` | T1037.003 | `\\<domain>\SYSVOL\<domain>\Policies\*\{Machine,User}\Scripts` | Gated on a real domain-joined check; a clean no-op on workgroup hosts. An unreachable DC degrades into the coverage report. |
| `BitsJobs` | T1197 | `Get-BitsTransfer -AllUsers` + BITS COM for `NotifyCmdLine`; captures `CreationTime` | `NotifyCmdLine` is the execution primitive and the module cmdlet does not expose it. A job without one is quiet inventory. Upload-type jobs are flagged. |
| `CredentialProviders` | Unmapped | `Authentication\Credential Providers` and `Credential Provider Filters`, resolved to their DLLs | Every provider verified; no assumed-safe list. This is a logon-time plaintext-capture surface, not just persistence. |
| `ShellExt` | Unmapped | Context-menu handler roots, icon-overlay identifiers, machine and per-user | Deliberately scoped to well-known roots rather than a full CLSID sweep — `ComFull` covers the broad case. The `Approved` list is shown as context only; it is not an enforcement boundary on modern builds. |

## False-positive controls

Every control below is derived generically. There is no per-host, per-vendor, or per-hash
allowlist anywhere in the script.

- **Path trust** is computed from where Windows itself installs code: `System` (under
  `%SystemRoot%`), `Program` (under either Program Files), `UserWritable`
  (AppData/Temp/Downloads/Public/PerfLogs or any user profile), `Untrusted` (anything else).
  User-writable patterns are tested *first*, so `Windows\Temp` is never classified as System.
- **Signature verification** is cached per path — the same binary is referenced by dozens of
  entries, and verification is the most expensive operation in the tool.
- **Command-line target extraction** handles quoted paths, unquoted paths containing spaces
  (non-greedy to the first extension, so `C:\Program Files\App\x.exe -flag` does not truncate
  to `C:\Program`), trailing commas (`userinit.exe,`), and drills `rundll32.exe x.dll,Entry`
  down to `x.dll` — the DLL is the code that actually runs.
- **Path resolution** follows the real `CreateProcess` search order (System32, then the Windows
  directory, then PATH). `SysWOW64` is only a last resort: it is not in a 64-bit process's
  search order, and putting it earlier resolves bare `explorer.exe` to the wrong file.
- **Per-user variables** resolve against the **owning** profile, never the running account, so
  a value read from another user's hive is not silently mis-resolved.
- **Recency suppression** for Microsoft-signed targets in trusted paths (see
  [Time handling](#time-handling)).
- **Quiet rows**: confirmed-stock values and static rosters are suppressed from the default
  view — but a quiet row that actually scored is *never* suppressed. Suppression only ever
  applies to confirmed-clean, zero-evidence rows.
- **Windows-baseline suppression** (every module): a binary signed by an **OS vendor** *and*
  sitting on an expected path *and* carrying **no evidence tag at all** is the Windows
  baseline, and is hidden unless `-InventoryOnly` is given.

  The zero-evidence bar is what makes this safe, and it is deliberately stricter than "below
  NOTABLE". A Run key running `cmd.exe /c evil.bat` resolves to a Microsoft-signed System32
  binary, so a naive rule would hide it — but it also earns a `LOLBIN` tag, so it survives.
  On the test host this keeps visible, among others, the `.js` / `.jse` / `.vbs` / `.vbe` /
  `.wsf` / `.hta` association handlers (all Microsoft-signed, all score 2, all LOW tier) —
  exactly the handlers an attacker hijacks.

  OS vendors are a deliberately tiny, explicit list —
  `Microsoft Corporation` and `Intel Corporation` — because they publish the inbox OS
  components. **Every other vendor still appears**, so third-party services and drivers stay
  visible for review.

  The important exception: Microsoft also signs *other vendors'* drivers under
  `CN=Microsoft Windows Hardware Compatibility Publisher` as a WHQL attestation. That is
  third-party code wearing a Microsoft signature, and WHQL-signed malicious drivers are a
  documented attack path, so those are **never** treated as OS-vendor binaries. They display
  with the signature label `WHQL 3rd-party`. On the reference host this distinction kept 13
  VMware drivers visible (host-specific — depends on what WHQL-signed third-party drivers are
  installed) that a naive "signed by Microsoft" rule would have hidden.

  Every suppression is announced per module — `[399 row(s) suppressed -- Windows baseline:
  OS-vendor-signed binaries on expected paths; re-run with -InventoryOnly to include]` (the row
  count is a reference-host measurement, not a fixed contract) — so nothing disappears silently.
- **Signature labels name the vendor.** A valid signature displays as the signing
  organisation (`Microsoft`, `Adobe`, `Broadcom`, `voidtools`, `WHQL 3rd-party`) rather than a
  generic "signed", so the publisher is visible without switching to `-Verbose`.

## Known limitations

- **Unloaded hives.** Registry-side per-user persistence in an unmounted profile is out of
  reach by design (mounting is a write). Those profiles are named in their own report section,
  and their on-disk artifacts are still swept.
- **Catalog-signed binaries — measured, not assumed.** Most Windows drivers carry no embedded
  Authenticode signature and are signed via a system catalog instead. `Get-AuthenticodeSignature`
  on PowerShell 5.1 already resolves those against the catalog store, so they report `Valid`
  and this tool does **not** need its own `wintrust` catalog lookup. Verified by measurement on
  Windows 10 19041: across 618 resolved service and driver targets on that reference host (this
count will differ on other builds/installs), the number reporting
  `NotSigned` while a matching catalog existed was **zero**. A `NotSigned` row from
  `FullSignaturePass` therefore means the file has neither an embedded signature nor catalog
  coverage — treat it as a real finding, not a tooling artifact. (Cross-check with
  `Get-AuthenticodeSignature` and `sigcheck` before acting, and re-measure if you ever run this
  on a much older build where the cmdlet's catalog behaviour may differ.)
- **`PSProfiles` content scan** matches download/execute patterns only. It is not a script
  analyser, and an obfuscated profile can evade it.
- **`BootLogonScripts`** is a best-effort registry/local-cache walk, not a full GPO parser.
- **`ShellExt`** covers well-known handler roots, not every possible shell-extension
  registration point.
- **No baseline diff.** This tool judges each host on its own merits. Cross-host outlier
  analysis (the strongest signal for `Services`, `DllSearchOrder`, `SafeBoot`) still requires
  collecting these results across an estate and diffing them yourself.
- **No event-log correlation.** Registry/filesystem state only; pair with `hunt_eventlogs.ps1`
  for 7045 / 106 / 4698 / 5859-5861 correlation.

## Verified baseline

Tested on Windows 10 Enterprise (build 19041), elevated and non-elevated. **The `Items` column
is a per-host measurement, not a fixed contract** — it is dominated by `ComFull`'s per-user CLSID
sweep, which tracks installed third-party software (a second reference run with a lighter COM
footprint measured 1 288 `-Deep` items in 22 s against the same 32 modules). The HIGH/NOTABLE
*tier counts* are the more stable signal across hosts of similar build/software mix.

| Run | Modules | Time | Items | Result |
|---|---|---|---|---|
| `-Quick` (elevated) | 25 | 15 s | 1 219 | 1 HIGH, 5 NOTABLE, 0 module failures |
| `-Deep` (elevated) | 32 | 35 s | 4 227 | 1 HIGH, 6 NOTABLE, 0 module failures |
| `-Deep -AnomaliesOnly` | 32 | 21 s | — | 131 lines of output |
| `-Quick` (non-elevated) | 25 | — | 984 | Same HIGH surfaced; 22 coverage gaps named; 0 leaked errors |

Every anomaly on the clean test host was genuine and explainable: a Run key and a scheduled task
pointing at a dangling UNC share, two stock Windows tasks invoking PowerShell with
hidden-window/bypass flags, an unsigned third-party autorun binary, and a TaskCache entry with
no task XML behind it.

Rendering was verified at an 80-column console: longest emitted line exactly 80 characters,
zero truncation. Every label line in the Summary block, and grouped-module headers (`RunKeys`),
route through the same wrap logic as the findings tables.

## Changelog

**v2.1** — Hardening pass from an independent three-track review (static code audit, live
functional testing, README-vs-code accuracy audit). Highlights: the registry P/Invoke helper no
longer crashes the whole run if `Add-Type` is blocked (Constrained Language Mode/WDAC) — it
degrades to no `LastWrite` instead; hive enumeration and report rendering are now guarded so a
failure dumps whatever findings were already gathered instead of losing them; `Test-Content`,
`FullSignaturePass`'s task-XML read, and `BitsJobs`'s per-job `NotifyCmdLine` read now log a
coverage gap on failure instead of silently reporting clean; a failed `Get-ScheduledTask` no
longer mass-tags every on-disk task as an orphan; `-InventoryOnly` alone now gives true raw
output (previously needed `-Verbose` too); a `*` suffix on the tier tag now marks an Absolute
finding so it's distinguishable from a Scored one in the output itself; `-Since`/`-Until` parse
with an invariant-culture exact format instead of a locale-dependent one; a negative `-Days` and
an inverted `-Since`/`-Until` window now error explicitly instead of silently no-opping; a
WOW64 bitness mismatch (32-bit process on a 64-bit OS) is now detected and warned on; `ClassId`
values from task XML are validated as GUID-shaped before being used in a registry path;
`$B64Rx` now requires the matched run to contain 3+ characters outside the hex alphabet
(`g`-`z`/`G`-`Z`/`+`/`/`) before it can flag `ENCODED-COMMAND`, so a coincidental 40+ char pure-hex
run (a concatenated hash or a GUID chain with hyphens stripped) no longer false-positives — a
real base64 blob still does; `Services` now surfaces `DisplayName`; two `Write-Host` sites that
bypassed the wrap helper (the `RunKeys` group header, the Summary `Hives` line) now wrap like
everything else; `FullSignaturePass` no longer double-lists the `UNSIGNED` tag on the same row.
`#Requires -Version 3.0` added (placed after the comment-based help block, not before it — before
it silently suppresses `Get-Help -Full`/`-Help` down to a bare syntax line on PowerShell 5.1). See
the code review, functional test, and README audit reports for the full finding list, including
the handful of reported items evaluated and intentionally left as-is (documented in this
changelog's companion review, not restated here).

**v2.0** — Complete rewrite from scratch. 42 → 32 modules (dropped Port Monitors, Print
Processors, Time Providers, Terminal Services, PSModulePath, AppShim, Office Trusted Locations,
Outlook Home Page, BHO, Winsock LSP as rare, retired, or non-actionable). Three mutually
exclusive run modes replace the old fast-default/`-Deep`-adds/`-Modules`-override scheme.
`-Since`/`-Days`/`-Until` became a display filter decoupled from RECENCY scoring. Registry
access moved to the .NET API with native `RegQueryInfoKey` timestamps. Dynamic wrapping output
replaces fixed-width tables. v1 is preserved under `archive/`.

