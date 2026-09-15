# Seatbelt — Overview

> 🔴 **Red Flag Principle:** Seatbelt is a **read-only enumeration tool** — it queries WMI, reads the registry, checks file existence/metadata, and reads event logs, but by design it doesn't create files, write registry values, or install anything (a standalone drop of `Seatbelt.exe` itself is the one exception — the checks it *runs* are read-only). That means classic "file created" / "registry modified" hunting doesn't apply here. The single most distinctive signal is **behavioral and volume-based**: one process making a tight-window burst of WMI queries against `root\SecurityCenter2` (AntiVirusProduct), dozens of registry reads across unrelated hives (LSA settings, Run keys, Defender exclusions), and file-existence checks across every local user's profile (browser stores, cloud credential files, KeePass/Putty/FileZilla configs) — no legitimate single process touches that many unrelated artifact classes in seconds. Hunt the **pattern of access**, not a dropped artifact.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Seatbelt is a C# project maintained under the **[GhostPack](https://github.com/GhostPack)** organization on GitHub — the same author family/publisher as Rubeus (Wave 2 of this repo's build list) and the future `GhostPack/` folder covering SharpUp, SharpDump, SafetyKatz, SharpWMI, and Certify (Wave 3) — though Seatbelt itself is treated as its own top-level folder here per this repo's Wave 1 build order, not nested under `GhostPack/`.

Verified against the canonical upstream repository, [`github.com/GhostPack/Seatbelt`](https://github.com/GhostPack/Seatbelt):

- **License:** BSD 3-Clause.
- **Credited authors (per the repo's own README):** `@harmj0y` and `@tifkin_` are named as the primary authors of the implementation. `@andrewchiles`'s [`HostEnum.ps1`](https://github.com/threatexpress/red-team-scripts/blob/master/HostEnum.ps1) and `@tifkin_`'s [`Get-HostProfile.ps1`](https://github.com/leechristensen/Random/blob/master/PowerShellScripts/Get-HostProfile.ps1) are credited as inspiration for many of the artifacts Seatbelt collects.
- **Purpose, in the project's own words:** "a C# project that performs a number of security oriented host-survey 'safety checks' relevant from both offensive and defensive security perspectives" — the dual-audience framing is the project's own, not an add-on for this wiki.
- **Version:** the compiled `Seatbelt.cs`'s `Version` constant (verified directly in source) is `"1.2.2"`, while the ASCII banner text embedded in the README's usage example still shows `v1.2.1` — a minor documentation/source drift, not a meaningful discrepancy, but worth knowing if you're trying to fingerprint a build from banner text alone.
- **Build target:** .NET 3.5 and 4.0, using C# 8.0 language features. No prebuilt binaries are distributed by the project — "We are not planning on releasing binaries for Seatbelt, so you will have to compile yourself" (README, Compile Instructions) — meaning almost every real-world `Seatbelt.exe` in the wild is either operator-compiled from source or redistributed by a C2/tooling framework (e.g. bundled with Cobalt Strike Aggressor scripts, Covenant, or similar), which matters for hash-based detection: there is no single canonical hash to blocklist.
- **No dedicated commercial/marketing site** — the GitHub repository is the sole authoritative source for this tool; this note is verified against it directly rather than secondary write-ups.

## How It Works

Seatbelt's entire design is a plugin-style dispatcher over a large library of independent "check" classes, each implementing a common `CommandBase` abstract class (`Command`, `Description`, `Group[]`, `SupportRemote`, `Execute()`). At startup, `Runtime.InitializeCommands()` uses .NET reflection (`Assembly.GetExecutingAssembly().GetTypes()`) to find and instantiate every class that subclasses `CommandBase` — there is no static registry of checks to maintain; adding a new check is dropping a new class into the `Commands/` tree and rebuilding.

### Command dispatch flow (verified against `Runtime.cs` / `Seatbelt.cs` / `SeatbeltArgumentParser.cs`)

```
Seatbelt.exe -group=all -Full
        │
        ▼
SeatbeltArgumentParser.Parse()
  strips -q / -Full / -RandomizeOrder / -Group= / -OutputFile= /
         -ComputerName= / -Username= / -Password= / -DelayCommands=
  from argv; everything left over is treated as a bare command name
        │
        ▼
Seatbelt / Runtime constructor
  ├─ if -ComputerName set → ManagementScope(\\<host>\root\cimv2, creds).Connect()
  │                          (fail-fast validation of the remote WMI connection
  │                           before any check runs)
  └─ InitializeCommands()  → reflection over every CommandBase subclass,
                              sorted alphabetically into Runtime.AllCommands
        │
        ▼
Runtime.Execute()
  ├─ ProcessGroup(group) for each -Group value:
  │     • "all"     → every command
  │     • otherwise → commands whose Group[] contains the matching
  │                    CommandGroup enum value
  │     • any bare "-CommandName" argument is treated as an EXCLUSION,
  │       not a new check, e.g. "-group=all -AuditPolicies"
  │     • RandomizeOrder (if set) shuffles execution order via
  │       RNGCryptoServiceProvider
  └─ ProcessCommand(command) for each bare command name:
        • exact, case-insensitive match against AllCommands
        • per-command quoted arguments parsed via Shell32.CommandLineToArgs
        │
        ▼
ExecuteCommand(command, args)
  ├─ Thread.Sleep(DelayCommands) if set — throttles the burst
  ├─ command.Execute(args) → WMI query (System.Management), registry read
  │     (Microsoft.Win32.Registry* locally, or WMI's StdRegProv remotely),
  │     Win32 P/Invoke (LSA policy, token privileges, security packages),
  │     EventLogReader (Security/PowerShell/Sysmon channels), or plain
  │     System.IO file-existence/metadata checks — the technique varies
  │     per check, this is the actual "safety check" logic
  └─ OutputSink.WriteOutput(result) → Console (default) / flat .txt file /
        structured .json file / in-memory JSON string ("jsonstring")
```

### Remote enumeration mechanics (verified against `Runtime.cs`)

Checks marked `+` in the tool's own help output (`SupportRemote == true`) can run against a second host via `-ComputerName=`. This is **WMI over DCOM/RPC**, not the classic SMB/Remote-Registry path other tools in this repo use for remote access:

```
Operator/foothold host                              Target host (-ComputerName=TARGET)
(Seatbelt.exe running here)
────────────────────────────                         ─────────────────────────────────
1. ManagementScope(\\TARGET\root\cimv2, creds)
   .Connect() — RPC bind, TCP 135 (Endpoint Mapper) ▶  RPC Endpoint Mapper resolves the
                                                         WinMgmt (WMI) DCOM interface
2.                 ◀── dynamic RPC/DCOM port returned ──
   (typically in the high/ephemeral range; exact
    range is host/policy dependent, not fixed by
    Seatbelt itself)
3. Authenticated DCOM call over that dynamic port ──▶  WinMgmt service services the call
                                                         against root\cimv2 /
                                                         root\SecurityCenter2
4. Per "+"-flagged check:
     • WMI class query (AntiVirusProduct,
       Win32_UserAccount, Win32_ScheduledJob, ...) or
     • StdRegProv method call for a remote registry
       read — NOT the legacy Remote Registry service ─▶  Query/read answered by the
                                                         target's local WMI provider
5.                 ◀── Result set (property bag) ───────
6. Result rendered to the OPERATOR host's output sink
   (console / file) — nothing is written on the target
```

The StdRegProv detail matters: Seatbelt's remote registry checks do **not** require the target's `RemoteRegistry` service to be running (that service is disabled by default on modern Windows) — they ride the same WMI/DCOM channel as everything else, so a host with Remote Registry disabled but WMI reachable is still fully enumerable.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Local enumeration | Direct in-process calls: .NET registry APIs, Win32 P/Invoke (LSA policy queries, token privilege enumeration, `EnumerateSecurityPackagesA`), `System.Management` (WMI) against local `root\cimv2`/`root\SecurityCenter2`, `EventLogReader` against Security/PowerShell/Sysmon channels, `System.IO` for file existence, timestamps, and size |
| Remote enumeration | WMI over DCOM/RPC (TCP 135 endpoint mapper + a dynamic high port); registry reads ride WMI's `StdRegProv` class rather than the legacy Remote Registry service/port 445 |
| Output | Console (default), flat text file, structured JSON file, or an in-memory JSON string with no file ever touching disk (`-outputfile=jsonstring`) — built specifically for loader-hosted/in-memory use, where the caller wants JSON back through its own C2 channel instead of a file it then has to retrieve |
| Execution surface | Standalone `Seatbelt.exe`, or reflectively loaded in-memory by a C2 loader's "execute .NET assembly" capability (Cobalt Strike's `execute-assembly`, Meterpreter's `post/windows/manage/execute_dotnet_assembly`, Sliver's `execute-assembly` — see the dedicated use case in `02 - Hands-On Use Cases.md` for verified specifics on each) |

## Command-Line Switches — Quick Reference

Verified directly against `SeatbeltArgumentParser.cs`, `SeatbeltOptions.cs`, `Runtime.cs`, and `Seatbelt.cs` in the current `GhostPack/Seatbelt` `master` branch — not just the README, since one flag below (`-DelayCommands`) exists in source but is **not documented in the README at all**.

| Switch | Plain-English meaning |
|---|---|
| `<Command> [Command2] ...` | Run one or more specific checks by name, e.g. `Seatbelt.exe AntiVirus WindowsDefender` |
| `-group=<name>` | Run a named command group instead of individual checks. Valid values (case-insensitive, matches the `CommandGroup` enum): `all`, `user`, `system`, `slack`, `chromium`, `remote`, `misc` |
| `-group=all -CommandName` | Run a group but **exclude** specific checks — any bare argument starting with `-` that matches a real command name is treated as an exclusion, e.g. `-group=all -AuditPolicies -LOLBAS` |
| `-full` (parsed case-insensitively as `-Full`) | Return **complete, unfiltered** results — many individual checks filter/trim by default (e.g. `Processes`/`Services` hide anything with a "Microsoft" company name; `LocalGroups` hides empty groups) |
| `-q` | Quiet mode — suppresses the startup ASCII-art banner and the "completed collection in N seconds" trailer |
| `-outputfile=<path>` | Redirect output to a file. `.txt` extension → flat text; `.json` extension → structured JSON file; the literal value `jsonstring` → JSON returned as an in-memory string through the output sink with **no file ever written to disk** |
| `-computername=<host>` | Run applicable ("+"-flagged) checks against a remote host over WMI instead of locally |
| `-username=<DOMAIN\user>` | Alternate credential (username) for the WMI connection to `-computername` |
| `-password=<pass>` | Alternate credential (password) for the WMI connection — **passed and stored as plaintext on the command line**, a significant OPSEC/detection point covered in `03 - Source Evidence.md` |
| `-randomizeorder` | Randomize a group's check execution order (`RNGCryptoServiceProvider`) — evasion against detections keyed on a fixed, predictable check sequence |
| `-delaycommands=<ms>` | **Undocumented in the README — verified only in source.** Sleeps the given number of milliseconds before each individual check runs, spreading out the WMI/registry/file-access burst that otherwise fires back-to-back — evasion against volume/behavioral heuristics |
| `"<Command> [arg]"` | Pass an argument to a single check that supports one; must be quoted as one string, e.g. `Seatbelt.exe "LogonEvents 30"` or `Seatbelt.exe "reg \"HKLM\SOFTWARE\Microsoft\Windows Defender\" 3 .*defini.* true"` |

**Note on scope-by-privilege:** per the tool's own README, "searches that target users will run for the current user if not-elevated and for ALL users if elevated" — the same command line produces a narrower or broader result set purely based on the token Seatbelt is running under, with no separate flag to control it.

## Quick Use-Case List

- Full local survey after initial foothold (`-group=all`)
- Quiet, filtered baseline recon that skips the banner/trailer noise (`-group=all -q`)
- Targeted AV/EDR-only check before dropping a second-stage payload (`AntiVirus`, `WindowsDefender`, `AMSIProviders`, `InterestingProcesses`, `AppLocker`)
- Browser credential/history harvesting across Chromium-family and non-Chromium browsers (`-group=chromium`, `FirefoxHistory`, `WindowsVault`, `IEUrls`/`IEFavorites`)
- Cloud credential file harvesting — AWS/Google/Azure/Bluemix cached credential files (`CloudCredentials`, plus `CloudSyncProviders`, `DpapiMasterKeys`)
- Persistence-mechanism discovery for follow-on implantation (`AutoRuns`, `ScheduledTasks`, the `WMIEventConsumer`/`WMIEventFilter`/`WMIFilterBinding` trio, `WindowsAutoLogon`, `LocalGPOs`)
- Remote/lateral enumeration of a second host over WMI, no agent required on the target (`-group=remote -computername=`)
- User-context recon vs. elevated all-user recon — same command line, privilege-dependent scope (`-group=user`)
- Slack workspace/download artifact harvesting (`-group=slack`)
- Excluding noisy or slow checks from a broad sweep (`-group=all -InterestingFiles -LOLBAS -SearchIndex`)
- Single targeted check with a per-command argument (`"LogonEvents 30"`, `"reg ..."`, `"dir ..."`)
- Structured JSON output for tooling ingestion or exfil over an existing C2 channel (`-outputfile=out.json` or `-outputfile=jsonstring`)
- Randomized check order plus inter-command delay for behavioral/volume-based EDR evasion (`-randomizeorder -delaycommands=`)
- In-memory execution via a C2 loader's "execute .NET assembly in-memory" capability — Cobalt Strike's `execute-assembly`, Meterpreter's `post/windows/manage/execute_dotnet_assembly`, or Sliver's `execute-assembly` (see `../Metasploit/Meterpreter/` for the Meterpreter-session side of this repo; Sliver's own folder does not exist yet in this repo, referenced by name only)
- Chained workflow — Seatbelt's findings directly informing the next tool choice (AV/EDR findings → payload/encoder selection; persistence findings → deeper implantation; credential findings → offline cracking or DCSync)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Target OS | Windows only — every check is built on Win32 P/Invoke, .NET Framework registry APIs, and WMI; there is no Linux/macOS build |
| Compatible .NET Framework/CLR on the host process | Seatbelt targets .NET 3.5/4.0 with C# 8 language features. A standalone `Seatbelt.exe` needs the matching Framework installed; in-memory/loader-hosted execution needs the loader's hosted CLR to satisfy the same version requirement |
| Execution privileges | Runs unprivileged — but scope changes with the token: user-scoped checks (`-group=user`) enumerate only the current user when non-elevated, and expand to **every** local user when elevated (verified in the README, not just inferred) |
| `root\SecurityCenter2` WMI namespace (the `AntiVirus` check specifically) | **Only present on Windows client/workstation SKUs.** Verified directly in `AntiVirusCommand.cs`: the check detects Windows Server via `Shlwapi.IsWindowsServer()` and skips with an explicit warning rather than querying a namespace that doesn't exist there |
| For remote enumeration (`-computername=`) | Target must accept inbound WMI/DCOM (RPC Endpoint Mapper TCP 135 + a dynamic high port — not blocked by host or network firewall); operator needs sufficient rights on the target for the WMI/registry queries the "+"-flagged checks make, either via the current token or explicit `-username=`/`-password=` |
| For in-memory / loader-hosted use | The loader must be able to host a CLR of a compatible version inside the target process — see the specific per-loader options (e.g. Meterpreter's `TECHNIQUE`, `AMSIBYPASS`, `ETWBYPASS` datastore options) in `02 - Hands-On Use Cases.md` |
