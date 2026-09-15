# Atomic Red Team — Overview

> 🔴 **Red Flag Principle:** Atomic Red Team's execution framework is **self-incriminating by design, and that's the point.** Unless an operator explicitly passes `-NoExecutionLog`, every single `Invoke-AtomicTest` run that actually fires a test (not `-ShowDetails`/`-CheckPrereqs`/`-GetPrereqs`) appends a row to `$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv` (`/tmp/...` on Linux/macOS) containing the **exact MITRE ATT&CK technique ID, test number, test name, and test GUID** — verified directly in `Public/Default-ExecutionLogger.psm1`. This is a gift for purple-team validation (you get a ground-truth, timestamped "what ran and when" to correlate against EDR/SIEM alerts) and a liability for anyone who repurposes the library adversarially without stripping it: the tool that makes detection engineering easy also makes attacker attribution easy, because the artifact it leaves behind literally names the technique it just executed. See `05 - Detection and Hunting.md` for how to hunt this log and the optional Windows-Event-Log/syslog loggers that make it even louder.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Atomic Red Team is actually **two separate GitHub projects** that this repo treats as one tool because they're used together in practice — worth being precise about, since they have different creation dates, different licenses (both MIT, but separately declared), and different maintainers listed:

- **[`redcanaryco/atomic-red-team`](https://github.com/redcanaryco/atomic-red-team)** — the atomics **library**: a folder-per-ATT&CK-technique tree of YAML test definitions (`atomics/T1003.001/T1003.001.yaml`, etc.), no execution logic at all. Verified directly against the repo: created 2017-10-11, MIT License (Copyright 2018 Red Canary, Inc.), maintained under the **Red Canary** (`redcanaryco`) GitHub org. The repo's own README badge (checked at build time of this note) shows **1,817 individual atomic tests** across roughly 340 technique/sub-technique folders. In the project's own words: "a library of tests mapped to the MITRE ATT&CK framework. Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments." The top historical contributor is `clr2of8` (Casey Smith, `@subTee`), publicly credited elsewhere as the tool's creator while at Red Canary; the project has since grown into a community-contributed library maintained by Red Canary.
- **[`redcanaryco/invoke-atomicredteam`](https://github.com/redcanaryco/invoke-atomicredteam)** — the **execution framework**: a PowerShell module (works on Windows natively, and on Linux/macOS via PowerShell Core) that parses the atomics YAML and actually runs the tests. Verified directly against the repo: created 2020-02-07, MIT License, also under the `redcanaryco` org. This is a genuinely separate, later project — the atomics library shipped and was usable (via manual copy/paste of each test's command) for over two years before this framework existed to automate it. The wiki's own framing still holds: "For a more robust testing experience, consider using an execution framework like Invoke-Atomic" — the atomics folder is documentation-as-code, `Invoke-AtomicTest` is the runner.
- **Distribution:** `invoke-atomicredteam` ships on the PowerShell Gallery (`Install-Module -Name invoke-atomicredteam,powershell-yaml`) and, separately, as a direct install script fetched over `IEX (IWR ...)` — the project's own documented "no PowerShell Gallery" installation path is itself a classic download-cradle pattern (see `03 - Source Evidence.md`). Installing the framework does **not** download the atomics library by default — the project's own wiki states this is deliberate, "because the atomics folder contains many files likely to trigger AV alerts on the endpoint."
- No single canonical binary or version number to fingerprint — this is a scripted YAML+PowerShell toolchain, actively developed, with tests added/removed continuously as ATT&CK itself evolves.

## How It Works

### The YAML test schema

Every technique folder (`atomics/<TechniqueID>/<TechniqueID>.yaml`) is one `AtomicTechnique` document: `attack_technique` (the ATT&CK ID), `display_name`, and an `atomic_tests` array. Each entry is one `AtomicTest`, schema verified directly against `Private/AtomicClassSchema.ps1` and a live example (`atomics/T1003.001/T1003.001.yaml`):

| Field | Purpose |
|---|---|
| `name` | Human-readable test name — this is what shows up in `-ShowDetails` output and the execution log, **not** a "Use Case N" label |
| `auto_generated_guid` | A stable UUID per test, usable with `-TestGuids` to target one exact test regardless of its position in the file |
| `description` | Free text, often including expected output/artifact paths and source attribution (credits the original researcher/tool) |
| `supported_platforms` | Array of `windows` / `macos` / `linux`, or cloud-only values (`office-365`, `azure-ad`, `google-workspace`, `saas`, `iaas`, `containers`, `iaas:aws`, `iaas:azure`, `iaas:gcp` — verified in the framework's own `Platform-IncludesCloud` function) |
| `input_arguments` | A map of `argname` → `{description, type, default}`. `type` is one of `path` / `url` / `string` / `integer` / `float` (lowercase in YAML; the authoring cmdlet's `-Type` parameter uses the same values PascalCased) |
| `dependency_executor_name` | Overrides which shell runs the `dependencies` prereq commands, independent of the test's own `executor.name` |
| `dependencies` | Array of `{description, prereq_command, get_prereq_command}` — `prereq_command` exits 0 if the dependency is already satisfied; `get_prereq_command` fetches/installs it |
| `executor` | `{name, elevation_required, command, cleanup_command}` for automated executors, or `{name: manual, steps, cleanup_command}` for human-driven tests |

### Executor types (verified against `Private/Invoke-ExecuteCommand.ps1`)

Five executor names exist. Four are automated; the fifth is deliberately **not**:

| Executor | What actually runs the command |
|---|---|
| `command_prompt` | `cmd.exe /c "<command, newlines joined with ' & '>"` |
| `powershell` | `powershell.exe` on Windows (local) with the command wrapped as `& {<command>}` — **not** invoked with `-Command`, `-NoProfile`, `-ExecutionPolicy Bypass`, or `-WindowStyle Hidden**`; `pwsh -Command <command>` when running inside a `-Session` or on Linux/macOS |
| `sh` / `bash` | `/bin/sh -c "<command>"` / `/bin/bash -c "<command>"`, with `\` and `"` escaped and newlines joined with `; ` |
| `manual` | **Not executed at all.** `Invoke-AtomicTest` checks `$test.executor.name.Contains('manual')` and skips the test with `continue` *before* it ever reaches the `-ShowDetails`/`-ShowDetailsBrief` code path — meaning `-ShowDetails` cannot even print a manual test's `steps` field. An operator has to read the test's own `.md`/`.yaml` directly for GUI-driven or otherwise non-scriptable procedures (e.g. "open Task Manager, right-click lsass.exe, Create Dump File") |

### Command dispatch flow

```
Invoke-AtomicTest T1003.001 -TestNumbers 2
        │
        ▼
Resolve -PathToAtomicsFolder, load T1003.001.yaml, walk atomic_tests[]
        │
        ▼
Per matching test:
  ├─ platform filter (supported_platforms vs. host OS; cmd.exe tests skipped
  │   on non-Windows, sh/bash tests skipped on Windows, unless -anyOS)
  ├─ manual executor?  → skip unconditionally, cannot be shown or run
  ├─ -ShowDetailsBrief → print "<AT>-<n> <test name>", continue
  ├─ -PromptForInputArgs → interactively collect each input_argument value
  ├─ -ShowDetails      → print technique/test/GUID/executor/elevation/
  │                       command (raw + #{arg}-substituted)/cleanup/
  │                       dependencies, continue (no execution)
  ├─ -CheckPrereqs     → run each dependency's prereq_command only, report
  │                       pass/fail, no execution
  ├─ -GetPrereqs       → run prereq_command; on failure, run
  │                       get_prereq_command, then re-check
  ├─ -Cleanup          → run executor.cleanup_command only
  └─ (default)         → Merge-InputArgs substitutes every #{argname} with
                          the -InputArgs override or the YAML default,
                          then Invoke-ExecuteCommand spawns the mapped
                          shell (cmd.exe/powershell.exe/pwsh/sh/bash) with
                          a 120-second default timeout (-TimeoutSeconds),
                          killing the process tree on timeout
        │
        ▼
Unless -NoExecutionLog: append one row (technique, test #, name, GUID,
hostname, IP, user, PID, exit code) to the configured logger
```

### Input-argument substitution

`Merge-InputArgs` (verified in `Private/Replace-InputArgs.ps1`) does simple literal find/replace of `#{argname}` tokens in `executor.command`, `executor.cleanup_command`, and every `dependencies[].prereq_command`/`get_prereq_command` — operator-supplied `-InputArgs` values override the YAML's own `default` per key; any key not recognized by the test is silently ignored. The literal strings `$PathToAtomicsFolder` and `PathToAtomicsFolder` are also replaced with the resolved atomics-folder path, which is how tests reference bundled payloads under `atomics/<ID>/src/` or the shared `ExternalPayloads/` staging directory without hardcoding an absolute path.

### Prereqs and cleanup are opt-in, separate invocations — not automatic

`-GetPrereqs` and `-CheckPrereqs` never run the attack command itself. `-Cleanup` runs *only* `executor.cleanup_command` and nothing else. A normal (no-flag) run does **not** clean up after itself automatically — cleanup is always a second, explicit `Invoke-AtomicTest ... -Cleanup` call. Not every test defines a `cleanup_command` at all (e.g. read-only discovery tests), so `-Cleanup` against those is a no-op.

### Remote execution

`-Session` accepts one or more `PSSession` objects (standard PowerShell Remoting / WinRM). When set, `Invoke-ExecuteCommand` stages `Invoke-Process.ps1` and `Invoke-KillProcessTree.ps1` into the remote session via `Invoke-Command -Session ... -FilePath`, then runs the actual test command *inside* that session — meaning the target host, not the operator's box, does the real work, and standard WinRM/PSRemoting evidence applies on top of whatever the test itself does (see `03`/`04 - Source/Target Evidence.md`).

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Local process execution | Direct child-process spawn of `cmd.exe`, `powershell.exe`/`pwsh`, `/bin/sh`, or `/bin/bash` via .NET `System.Diagnostics.Process` (`Private/Invoke-Process.ps1`) — no injection, no in-memory tradecraft in the framework itself; whatever evasion exists is whatever the *individual atomic test's own command* does |
| Remote execution | PowerShell Remoting (WinRM) via `-Session` — the framework's only built-in remote-execution path; it is not a C2 and has no listener/implant of its own |
| Distribution | PowerShell Gallery (`Install-Module`) or an `IEX (IWR ...)` download-cradle installer script; the atomics library itself is a separate `git clone`/zip download |
| Logging/telemetry | CSV file (default), Windows Event Log channel `Atomic Red Team` (Event ID 3001, opt-in), syslog (opt-in or auto-selected if configured), or the community `Attire-ExecutionLogger` JSON format (opt-in) — all four ship in the framework itself, see `05 - Detection and Hunting.md` |
| Coverage breadth | Every ATT&CK Enterprise tactic has atomics — Initial Access through Impact, plus cloud-platform-tagged tests for Office 365/Azure AD/Google Workspace/AWS/GCP — the framework itself performs no exploitation; it is a **dispatcher for other people's/tools' commands** (many tests literally shell out to Mimikatz, Rubeus, PsExec, or download-cradle a PowerSploit/Empire module — cross-linked per use case in `02 - Hands-On Use Cases.md`) |

## Command-Line Switches — Quick Reference

`Invoke-AtomicTest` parameters, verified directly against `Public/Invoke-AtomicTest.ps1` in the current `redcanaryco/invoke-atomicredteam` `master` branch:

| Switch | Plain-English meaning |
|---|---|
| `<AtomicTechnique>` (positional) | The ATT&CK ID to run, e.g. `T1003.001`. Also accepts the literal value `All` (every technique folder found under `-PathToAtomicsFolder`), and a short combined form `T1003.001-1,3` (technique + comma-separated test numbers, parsed by splitting on `-` and folded into `-TestNumbers`) |
| `-ShowDetails` | Print full test detail (name, GUID, executor, elevation requirement, raw and argument-substituted command, cleanup command, dependencies) without executing anything |
| `-ShowDetailsBrief` | Print just `<AT>-<test#> <test name>` per matching test — a one-line inventory |
| `-anyOS` | Skip the platform filter — run/show a test even if its `supported_platforms` doesn't list the current OS (useful for reading a Linux test's command on a Windows analysis box, for example) |
| `-TestNumbers <int[]>` | Restrict to specific test numbers within the technique (1-indexed, matching file order) |
| `-TestNames <string[]>` | Restrict by exact `name` field match |
| `-TestGuids <string[]>` | Restrict by exact `auto_generated_guid` match — the most precise selector, immune to file reordering |
| `-PathToAtomicsFolder <path>` | Where to look for `<Technique>/<Technique>.yaml`. Defaults to `C:\AtomicRedTeam\atomics` (Windows) or `~/AtomicRedTeam/atomics` (Linux/macOS) |
| `-CheckPrereqs` | Run each dependency's `prereq_command` only; report pass/fail. No attack command runs |
| `-PromptForInputArgs` | Interactively prompt for each `input_arguments` value instead of silently using YAML defaults |
| `-GetPrereqs` | Run `prereq_command`; on failure, run `get_prereq_command` to fetch/install the dependency, then re-check. No attack command runs |
| `-Cleanup` | Run only `executor.cleanup_command` for the matching test(s) |
| `-NoExecutionLog` | Disable the execution logger entirely — the direct evasion flag against the CSV/EventLog/syslog artifact described in the red-flag callout above |
| `-ExecutionLogPath <path>` | Override the default log file location (`$env:TEMP\Invoke-AtomicTest-ExecutionLog.csv` / `/tmp/Invoke-AtomicTest-ExecutionLog.csv`) |
| `-Force` | Suppress the interactive confirmation prompt (relevant to `-AtomicTechnique All`'s "Highway to the danger zone" prompt) |
| `-InputArgs <hashtable>` | Override one or more `input_arguments` defaults, e.g. `@{output_file = "C:\Temp\out.dmp"}` |
| `-TimeoutSeconds <int>` | Per-test execution timeout; default **120**. Process tree is killed on timeout |
| `-Session <PSSession[]>` | Run against one or more remote hosts over PowerShell Remoting/WinRM instead of locally |
| `-Interactive` | Let stdout/stderr flow live to the console instead of being captured — required for tests containing interactive prompts |
| `-KeepStdOutStdErrFiles` | Retain the timeout-marker output files (see `03 - Source Evidence.md` — these are **only** written on a timeout, not on every run) |
| `-LoggingModule <name>` | Choose the execution logger: `Default-ExecutionLogger` (CSV, the default), `WinEvent-ExecutionLogger` (Windows Event Log, ID 3001), `Syslog-ExecutionLogger`, or `Attire-ExecutionLogger` (JSON, ATTIRE v1.1 format) |
| `-SupressPathToAtomicsFolder` | **Sic — misspelled in source, not "Suppress."** Silences the informational "PathToAtomicsFolder = ..." banner line printed at the start of every run |

## Quick Use-Case List

- Full-fidelity, single-technique validation with `-ShowDetails` reviewed before ever executing (understand exactly what will run and what it claims to leave behind)
- Firing a single numbered test to test-fire a specific detection rule (`-TestNumbers`, or the short form `T1003.001-2`)
- Sweeping an entire technique — every test in one `T####` folder in one call
- Sweeping a tactic or credential-access/lateral-movement/persistence chain across multiple technique IDs in a loop
- `-CheckPrereqs` / `-GetPrereqs` workflow — confirming and then fetching a test's payload dependency (e.g. downloading ProcDump/Mimikatz/PsExec into `ExternalPayloads/`) before ever running the attack command
- `-Cleanup` as its own explicit second pass, since normal execution does not self-clean
- SOC tabletop rehearsal — walking analysts through `-ShowDetails` output as a "what would this look like" briefing without ever touching a live host
- Detection-engineering test-firing — run a labeled, known-answer test, then confirm the paired EDR/SIEM rule actually alerted
- CI/CD-integrated continuous validation — `Invoke-AtomicTest`/`Invoke-AtomicRunner` invoked from a pipeline job or the framework's own scheduled-runner service, results shipped to a syslog/SIEM sink automatically
- Remote execution against a second host over PowerShell Remoting (`-Session`) instead of locally
- Overriding default input arguments to point a test at a non-default drop path or target value (`-InputArgs`)
- Interactive/manual-test walkthrough for GUI-only procedures the framework can't script
- Adversarial reuse by an actual attacker — pulling a single, already-weaponized, known-working command for a specific ATT&CK ID straight out of the library instead of writing custom tradecraft (see the explicit callout in `02 - Hands-On Use Cases.md`)
- Chaining multiple atomics end-to-end into a realistic attack path (discovery → credential access → lateral movement), each step a separate `Invoke-AtomicTest` call
- Authoring and testing a custom, private atomic test with `New-AtomicTechnique`/`New-AtomicTest`/`New-AtomicTestInputArgument`, without contributing it to the public library
- Exporting execution history for after-action reporting via `-LoggingModule Attire-ExecutionLogger` (structured JSON) or `-ExecutionLogPath` pointed at a shared analysis location

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| PowerShell | Windows PowerShell 5.0+ natively, or PowerShell Core (`pwsh`) on Linux/macOS — the framework is genuinely cross-platform, the atomics library is not (individual tests are platform-tagged via `supported_platforms`) |
| `powershell-yaml` module | Required alongside `invoke-atomicredteam` to parse the YAML test definitions — the project's own install command bundles both (`Install-Module -Name invoke-atomicredteam,powershell-yaml`) |
| The atomics folder itself | Not installed automatically with the framework — must be separately fetched (`Install-AtomicsFolder`, or a manual clone of `redcanaryco/atomic-red-team`'s `atomics/` directory). The project explicitly does not bundle it by default because of AV/EDR quarantine risk on the payload-heavy `src`/`ExternalPayloads` content |
| Execution privileges | Varies per test — `executor.elevation_required` is a per-test boolean. **Not enforced by the framework**: `Invoke-AtomicTest` does not block a non-elevated run of an elevation-required test; it only warns during `-GetPrereqs`. The test simply fails (access-denied) at execution time if the required privilege isn't present |
| Test-specific dependencies | Whatever the test's own `dependencies[]` declares — anything from "must be domain-joined" (checked via `Get-CimInstance Win32_ComputerSystem`) to a specific tool binary (ProcDump, Mimikatz, PsExec, Rubeus, etc.) fetched by `-GetPrereqs` into `ExternalPayloads/` or a per-technique `src/` folder |
| For remote execution (`-Session`) | Target must accept inbound WinRM/PowerShell Remoting; operator needs sufficient rights on the target for both the WinRM connection and whatever the test itself requires |
| For cloud-platform tests | Depends entirely on the test — typically an authenticated session/API token for the relevant cloud platform (Azure AD, Office 365, AWS, GCP), outside the scope of the local-host prerequisite model above |
