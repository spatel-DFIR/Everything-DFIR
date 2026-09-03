# Application Shimming

The Windows Application Compatibility infrastructure exists to keep older software running correctly as the underlying OS changes underneath it — a "shim" is a small compatibility layer, packaged into a shim database (`.sdb`) file, that intercepts a targeted executable's API calls and transparently alters, redirects, or fakes their behavior so the older program keeps working against a newer Windows version. Microsoft ships thousands of these shims for known-problematic legacy software as part of the OS itself, applied automatically and invisibly. The same infrastructure also lets an administrator — or an attacker — register a **custom** shim database against an arbitrary executable using the native `sdbinst.exe` tool, and some shim types are powerful enough to inject a DLL into the shimmed process or redirect its execution entirely to a different binary.

That combination — a native installation path, a legitimate and common underlying framework, and shim types capable of DLL injection or execution redirection — is what makes Application Shimming a real persistence and privilege-escalation primitive rather than just a compatibility curiosity. A custom shim database applies its behavior every time the targeted executable launches, which means shimming a frequently-run legitimate binary (or a startup/logon program already covered elsewhere in this family) gives an attacker code execution that re-triggers on a schedule they don't have to maintain themselves, and that looks — to a defender skimming a process list — like nothing more than the original, expected program running normally.

This note is part of the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table comparing Application Shimming against Run keys, Services, Scheduled Tasks, and WMI Event Consumers.

🔴 **A critical naming distinction before going further: Application Shimming (this note) is not ShimCache/AppCompatCache.** The names are related for a reason — ShimCache is part of the same Application Compatibility infrastructure — but they are functionally opposite artifacts. ShimCache (AppCompatCache).md (note 06) documents a **passive, forensic execution-evidence artifact**: a cache Windows maintains of metadata about executables that have run or simply been touched by the OS, useful for proving something ran or existed. Application Shimming, covered here, is an **active persistence/injection technique**: an attacker deliberately installing a custom `.sdb` file to make chosen code run automatically. An analyst who finds "shim" in two different contexts on the same engagement should not assume they're looking at the same thing twice.

> 🔴 **A custom shim database is only as suspicious as its target executable and its shim types.** Legitimate custom shims exist — enterprises commonly ship their own `.sdb` files to keep internal line-of-business software running on a newer Windows version, and Microsoft's own compatibility fixes apply constantly and invisibly in the background. The finding is never "a custom shim database exists," it's "this database targets an unexpected executable, uses a shim type capable of code injection or execution redirection, or was installed via `sdbinst.exe` with no accompanying legitimate change record."

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Where Custom Shims Live — Registry & Filesystem](#where-custom-shims-live--registry--filesystem)
- [Shim Types Relevant to Abuse](#shim-types-relevant-to-abuse)
- [`sdbinst.exe` as the Native Installation Tool](#sdbinstexe-as-the-native-installation-tool)
- [Event Log Evidence](#event-log-evidence)
- [Red Flags Specific to Application Shimming](#red-flags-specific-to-application-shimming)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native registry- and filesystem-only triage — the shim infrastructure has no dedicated PowerShell module, so these read the `AppCompatFlags` registry keys and the on-disk `.sdb` files directly.

```powershell
# Every custom shim database registered under Custom, with its target executable and GUID
Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.PSPath | ForEach-Object { [PSCustomObject]@{ TargetExecutable = $_.PSChildName; SubValues = (Get-ItemProperty $_.PSPath).PSObject.Properties.Name -join '; ' } }
}

# Every installed SDB tracked under InstalledSDB, cross-referenced to its file on disk
Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.PSPath | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        [PSCustomObject]@{ GUID = $_.PSChildName; DatabasePath = $p.DatabasePath; DatabaseDescription = $p.DatabaseDescription }
    }
}

# .sdb files under AppPatch\Custom whose registry entry targets an executable outside Program Files/Windows
Get-ChildItem 'C:\Windows\apppatch\Custom' -Filter *.sdb -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, CreationTime, LastWriteTime

# .sdb files present anywhere on disk that are NOT registered under InstalledSDB - orphaned or manually-copied databases
$registered = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB' -ErrorAction SilentlyContinue |
    ForEach-Object { (Get-ItemProperty $_.PSPath).DatabasePath })
Get-ChildItem 'C:\Windows\apppatch' -Filter *.sdb -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notin $registered } | Select-Object FullName

# Recently modified/created files under AppPatch\Custom - the install-time proxy for a planted shim
Get-ChildItem 'C:\Windows\apppatch\Custom' -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) } | Select-Object FullName, CreationTime

# sdbinst.exe execution evidence via Prefetch, if present - direct confirmation the native install tool actually ran
Get-ChildItem "$env:SystemRoot\Prefetch\SDBINST.EXE*" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime
```

## Where Custom Shims Live — Registry & Filesystem

Custom shim databases installed via `sdbinst.exe` register in two parallel registry locations plus an on-disk `.sdb` file:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom\<TargetExecutableName>
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB\<DatabaseGUID>
```

| Location | Structure | Forensic relevance |
|---|---|---|
| `AppCompatFlags\Custom\<TargetExecutableName>` | One subkey per **targeted executable name** (not per database) — each holds a value named after the database's internal GUID, referencing which shim(s) apply to that executable | 🔴 The **application-centric view** — walk this key to answer "what's shimmed on this host," which is the more useful starting point for hunting since it surfaces the target executable directly |
| `AppCompatFlags\InstalledSDB\<DatabaseGUID>` | One subkey per **installed database**, keyed by GUID, holding `DatabasePath` (the `.sdb` file's location on disk) and `DatabaseDescription` | The **database-centric view** — the definitive record of every `.sdb` file `sdbinst.exe` has ever registered on this host, with its actual file path; cross-reference this against `Custom` to confirm every registered database has a live, findable file |
| `%WINDIR%\AppPatch\Custom\` (and `\Custom\Custom64\` for 64-bit-targeting databases) | Default on-disk location for the `.sdb` file itself, typically named `<GUID>.sdb` | The database file is not required to live here — `DatabasePath` can point anywhere the installing account could write, including a UNC path — but the default location is what `sdbinst.exe` uses absent an explicit alternate target, so a `DatabasePath` pointing elsewhere is itself worth noting |

The `.sdb` file is a binary format (compiled by the Application Compatibility Toolkit or manually crafted) containing the actual shim logic — which API calls to intercept, what to substitute, and which executable(s) it applies to. Reading its contents in detail typically requires a compatibility-database-aware tool rather than a plain text editor, unlike the XML task files or plain-text registry values covered elsewhere in this family.

### PowerShell

Walk the `Custom` key to get the application-centric view — every executable name that has at least one shim applied, which is the fastest way to answer "is anything shimmed on this host at all":

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom' -ErrorAction SilentlyContinue |
    Select-Object PSChildName
```

Cross-reference the `InstalledSDB` key against actual files on disk to catch a registered database whose `.sdb` file has since been moved, deleted, or was never actually written to the expected location:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\InstalledSDB' -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{ GUID = $_.PSChildName; DatabasePath = $p.DatabasePath; Exists = Test-Path $p.DatabasePath }
}
```

## Shim Types Relevant to Abuse

Not every shim type is meaningful from an attacker's perspective — most of Microsoft's built-in shim library exists for narrow, benign compatibility fixes (window-sizing quirks, version-string spoofing for picky installers). A small number of shim types, however, are directly relevant to code execution and are the ones worth recognizing by name when parsing a suspect `.sdb`:

| Shim Type | Behavior | Abuse relevance |
|---|---|---|
| `InjectDll` | Loads an attacker-specified DLL into the target process's address space when it starts | 🔴 The most direct persistence/injection primitive this framework offers — functionally equivalent to a DLL side-load, but triggered by the compatibility layer rather than the loader's own search order |
| `RedirectEXE` | Redirects execution from the targeted executable to a different executable entirely | Used historically (and documented publicly) as a UAC-bypass primitive as well as a straightforward persistence mechanism — the user or system launches what they believe is the original program, and a different binary runs instead |
| `GetProcAddress` | Intercepts and can alter the return value of `GetProcAddress` calls, effectively letting the shim substitute which function a program actually calls | Lower-level and more surgical than `InjectDll`/`RedirectEXE`; less commonly the headline technique but documented as part of the same abuse surface |
| `DisableNX` / `DisableSEH` | Disable Data Execution Prevention / Structured Exception Handling for the targeted process | Not code-execution primitives on their own, but weaken exploit mitigations for the targeted process — relevant when a shim is paired with a separate exploitation attempt against that same executable |

Documented incident reporting (Mandiant's account of FIN7's use of this technique is the most widely cited) describes a shim injecting a malicious in-memory patch into a core Windows process to spawn a backdoor — illustrating that these shim types are not theoretical; they have been used in real intrusions specifically for the persistence and injection properties described above, not as an incidental side effect of legitimate compatibility work.

## `sdbinst.exe` as the Native Installation Tool

`sdbinst.exe`, present by default under `%WINDIR%\System32`, is the native command-line tool for both installing and removing custom shim databases:

```
sdbinst.exe /q C:\path\to\custom.sdb
```

The `/q` flag suppresses the installation UI, making this a fully silent, one-line install suitable for a script or a remote-execution payload — a live host's `sdbinst.exe /q <file>.sdb` invocation is the typical infection vector for this technique, whether run interactively by an attacker with local access or pushed and executed as part of a broader intrusion. Removal follows the same tool: `sdbinst.exe /u <file>.sdb` unregisters a database, which is worth checking for in command-line history when a shim appears to have been present at one point in an investigation timeline but is absent from current registry state.

🔴 Prior to the fix shipped in security update KB3045645, `sdbinst.exe` carried an auto-elevate manifest flag, meaning it could install a shim database without triggering a UAC consent prompt even when run by a standard user — a UAC-bypass angle worth being aware of on any host that hasn't received that update, though on any currently-patched and supported Windows version this specific bypass path is closed and the technique should be evaluated purely as a persistence/injection primitive requiring the privilege level normally needed to write to `HKLM`.

## Event Log Evidence

`sdbinst.exe` execution and the resulting registry writes are the two evidence chains this mechanism leaves; neither has a dedicated always-on event ID of its own.

| Source | Event ID | Meaning | Notes |
|---|---|---|---|
| Security log | 4688 (if command-line auditing enabled) | Process creation | Shows `sdbinst.exe` launching along with its full command line, including the `.sdb` file path — the single most direct piece of evidence this technique leaves, contingent on command-line auditing being turned on |
| Security log | 4657 | Registry value modified | 🔴 Requires **non-default auditing** with a SACL on the `AppCompatFlags\Custom`/`InstalledSDB` keys — not enabled by default |
| Sysmon (if deployed) | 1 | Process creation | Same evidence as 4688, with richer default fields (hash, parent process) if Sysmon is installed and configured |
| Sysmon (if deployed) | 11/13 | File create / Registry value set | Fires for `.sdb` file writes under `AppPatch\Custom` and for the corresponding `AppCompatFlags` registry writes, if Sysmon's config includes these paths |
| Prefetch | N/A (not an event log) | `SDBINST.EXE-<hash>.pf` | Confirms `sdbinst.exe` ran on this host at least once, with run count and last-run timestamp, independent of any event log being enabled at all — see Prefetch.md (note 06) |

Because neither the registry write nor the shim-application event itself is reliably logged by default, this note leans on `sdbinst.exe` process-creation evidence (4688/Sysmon 1, or Prefetch as a fallback with no auditing dependency at all) as the primary "was this technique used" signal, then pivots to the registry-state enumeration above to identify exactly what was installed and against which target.

### PowerShell

Pull `sdbinst.exe` process-creation events where command-line auditing is enabled, to recover the exact `.sdb` file path used at install time:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'sdbinst\.exe' } |
    Select-Object TimeCreated, @{N='CommandLine';E={($_.Message -split "`n" | Select-String 'Process Command Line').ToString()}}
```

Fall back to Prefetch alone when no relevant event log or auditing was enabled — this at least confirms `sdbinst.exe` ran, with the timestamp to anchor further investigation against registry state and file-system timestamps under `AppPatch\Custom`:

```powershell
Get-Item "$env:SystemRoot\Prefetch\SDBINST.EXE*" -ErrorAction SilentlyContinue | Select-Object Name, LastWriteTime, @{N='RunCount';E={ (Get-ItemProperty $_.FullName).RunCount }}
```

## Red Flags Specific to Application Shimming

- **A custom shim database targeting an executable with no plausible legitimate compatibility need.** Legitimate custom shims almost always target older, specifically-known-problematic line-of-business software; a shim applied to a core Windows utility, a security tool, or a frequently-run legitimate binary with no compatibility history has no obvious legitimate explanation.
- **A shim database whose type includes `InjectDll` or `RedirectEXE`.** These are the two shim types capable of directly delivering or redirecting to attacker code — their presence in a custom `.sdb`, once parsed, is a strong signal regardless of what the targeted executable is.
- **`DatabasePath` pointing outside the default `AppPatch\Custom` location, especially to a user-writable directory or a UNC path.** A legitimately packaged enterprise shim is typically deployed to the standard location by its own installer; a database pointing at `%TEMP%` or a network share is atypical.
- **`sdbinst.exe` execution evidence (4688, Sysmon 1, or Prefetch) with no corresponding change-management record for a legitimate compatibility deployment.** Because this tool has essentially one purpose, any unexplained invocation is worth investigating on its own.
- **A registered `InstalledSDB` entry with no corresponding file on disk, or a `.sdb` file present under `AppPatch\Custom` with no registry entry referencing it.** Mirrors the orphan-check pattern used elsewhere in this family (`TaskCache` GUIDs with no XML, services with no matching file) — either half of the artifact pair surviving without the other suggests incomplete cleanup or a mechanism other than `sdbinst.exe`'s normal registration path.
- **A shim targeting an executable that is itself already covered by another persistence mechanism in this family — a Run-key target, a service binary, a scheduled-task action.** Shimming an executable that already launches automatically compounds the attacker's persistence: the shim doesn't need its own trigger at all, it rides whatever trigger already exists for the target binary.

## Tooling

| Tool | Use |
|---|---|
| **`sdbinst.exe`** | The native install/uninstall tool itself — its presence in Prefetch, process-creation logs, or command-line history is the primary "was this used" signal covered above |
| **Application Compatibility Toolkit / Compatibility Administrator** (`sdbinst`/`compatadmin`, part of the Windows ADK) | Microsoft's own tool for creating and inspecting `.sdb` files — the practical way to open a suspect `.sdb` and read its target executable(s) and shim type(s) in a structured view rather than raw binary |
| **Registry Explorer** / **RECmd** (Eric Zimmerman) | Offline hive inspection of `AppCompatFlags\Custom` and `AppCompatFlags\InstalledSDB` under an acquired `SOFTWARE` hive — see Registry Forensics Fundamentals (note 04) |
| **Autoruns** (Sysinternals) | Includes a Known DLLs / compatibility-shim view on recent versions; cross-check against the registry paths above since coverage of custom shim databases specifically can be less complete than Autoruns' coverage of Run keys and services |
| **PECmd** / Prefetch parsing (Eric Zimmerman) | Confirms `sdbinst.exe` execution history when no event-log evidence is available — see Prefetch.md (note 06) |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Custom shim targets an executable with no plausible compatibility need | Legitimate custom shims target known-problematic legacy software, not core utilities or security tools |
| Shim type includes `InjectDll` or `RedirectEXE` | The two shim types directly capable of delivering or redirecting to attacker code |
| `DatabasePath` outside the default `AppPatch\Custom` location, especially user-writable paths or UNC shares | Atypical of a legitimately packaged and deployed enterprise shim |
| `sdbinst.exe` execution evidence with no change-management record | This tool has essentially one purpose — any unexplained invocation warrants investigation |
| `InstalledSDB` entry with no matching file on disk, or vice versa | Incomplete cleanup, or installation via a path other than `sdbinst.exe`'s normal flow |
| Shimmed target is also a Run-key/service/scheduled-task target elsewhere in this family | Compounded persistence — the shim rides an existing autostart trigger rather than needing its own |
| Confused with ShimCache/AppCompatCache during analysis | Different artifact entirely — ShimCache is passive execution evidence, Application Shimming is an active persistence technique; see ShimCache (AppCompatCache).md |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry hive structure and offline `SOFTWARE` hive access mechanics | Registry Forensics Fundamentals (note 04) |
| The passive execution-evidence artifact that shares this technique's name but is functionally unrelated | ShimCache (AppCompatCache).md (note 06) |
| Confirming `sdbinst.exe` (or a shimmed target executable) actually ran | Prefetch.md (note 06), Amcache.md (note 06) |
| Run-key, service, or scheduled-task targets that a custom shim might be layered onto for compounded persistence | Autostart (Run/RunOnce) Keys, Services, Scheduled Tasks |
| Other DLL-injection-capable persistence mechanisms in this family | DLL Hijacking, Provider & Helper DLL Hijacking (Time Providers, Netsh, Winsock LSP) |

## Resources

- MITRE ATT&CK T1546.011 (Event Triggered Execution: Application Shimming) — https://attack.mitre.org/techniques/T1546/011/
- Mandiant/Google Cloud Blog, "FIN7 Spear Phishing Campaign Targets Personnel Involved in SEC Filings" / FIN7 shim database persistence writeup — https://cloud.google.com/blog/topics/threat-intelligence/fin7-shim-databases-persistence
- Black Hat EU 2015, Sean Pierce, "Defending Against Malicious Application Compatibility Shims" — https://blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims.pdf
- Microsoft, Application Compatibility Toolkit / Compatibility Administrator documentation — https://learn.microsoft.com/windows/deployment/planning/compatibility-administrator-users-guide
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Eric Zimmerman's tools (Registry Explorer, RECmd, PECmd) — https://ericzimmerman.github.io/
- Atomic Red Team, T1546.011 — https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.011/T1546.011.md
