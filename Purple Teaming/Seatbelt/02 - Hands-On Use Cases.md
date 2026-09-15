# Seatbelt — Hands-On Use Cases

Every scenario below is a variation on the same dispatch mechanism documented in `01 - Overview.md`: a `-group=` value, one or more bare command names, or both, optionally scoped by `-full`, `-computername=`, or the evasion flags. MITRE ATT&CK ID(s) are tagged per scenario; most Seatbelt checks map to a **Discovery**-tactic technique, since the tool itself performs no exploitation or lateral movement — the follow-on action it enables (a second payload, a relay, a credential-store parse) carries its own separate techniques where relevant.

## Contents
- [Full Local Survey After Initial Foothold](#full-local-survey-after-initial-foothold)
- [Quiet, Filtered Baseline Recon](#quiet-filtered-baseline-recon)
- [Targeted AV/EDR Check Before a Second-Stage Payload](#targeted-avedr-check-before-a-second-stage-payload)
- [Browser Credential/History Harvesting](#browser-credentialhistory-harvesting)
- [Cloud Credential File Harvesting](#cloud-credential-file-harvesting)
- [Persistence-Mechanism Discovery](#persistence-mechanism-discovery)
- [Remote/Lateral Enumeration of a Second Host](#remotelateral-enumeration-of-a-second-host)
- [User-Context Recon vs. Elevated All-User Recon](#user-context-recon-vs-elevated-all-user-recon)
- [Slack Workspace/Download Artifact Harvesting](#slack-workspacedownload-artifact-harvesting)
- [Excluding Noisy or Slow Checks from a Broad Sweep](#excluding-noisy-or-slow-checks-from-a-broad-sweep)
- [Single Targeted Check With an Argument](#single-targeted-check-with-an-argument)
- [Structured JSON Output for Tooling or C2 Ingestion](#structured-json-output-for-tooling-or-c2-ingestion)
- [Randomized Order Plus Inter-Command Delay for Evasion](#randomized-order-plus-inter-command-delay-for-evasion)
- [In-Memory Execution via a C2 Loader](#in-memory-execution-via-a-c2-loader)
- [Chained Workflow — Seatbelt Findings Driving the Next Tool](#chained-workflow--seatbelt-findings-driving-the-next-tool)

---

## Full Local Survey After Initial Foothold

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery), [T1087](https://attack.mitre.org/techniques/T1087/) (Account Discovery), [T1518](https://attack.mitre.org/techniques/T1518/) (Software Discovery) — a broad-spectrum Discovery run, not one specific technique

```
Seatbelt.exe -group=all

# Unfiltered — every check returns its complete result set, not the
# default-trimmed view
Seatbelt.exe -group=all -full
```

The baseline case. Every check across every group runs once, in alphabetical order (`Runtime.AllCommands` is sorted at load time). This is the highest-noise, highest-yield option — appropriate immediately after landing on a new host, when the operator wants the fullest possible picture before deciding what to do next, and detection risk is a secondary concern to speed of situational awareness.

## Quiet, Filtered Baseline Recon

**MITRE ATT&CK:** Same as above — T1082/T1087/T1518, presentation-layer variant only

```
Seatbelt.exe -group=all -q
```

`-q` suppresses the ASCII-art startup banner and the "Completed collection in N seconds" trailer — cosmetic on a full standalone run, but relevant when output is being captured through a size- or line-limited C2 console/log and every extra line of banner noise pushes real findings further down (or off) the visible buffer.

## Targeted AV/EDR Check Before a Second-Stage Payload

**MITRE ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Software Discovery: Security Software Discovery)

```
Seatbelt.exe AntiVirus WindowsDefender AMSIProviders InterestingProcesses AppLocker
```

Runs only the checks relevant to deciding whether/how to stage a second payload: `AntiVirus` (queries `root\SecurityCenter2`'s `AntiVirusProduct` WMI class — client SKUs only, see `01 - Overview.md`'s Prerequisites), `WindowsDefender` (Defender-specific settings including configured exclusion paths — directly useful for choosing a drop location Defender is already told to ignore), `AMSIProviders` (which AMSI providers are registered — relevant to script-based delivery), `InterestingProcesses` (matches running process names against a hardcoded list of AV/EDR/security-tooling process signatures — e.g. `csfalconservice`/CrowdStrike Falcon, `cylancesvc`/Cylance, `repux`/Carbon Black Defense, `savservice`/Sophos, drawn from the `threatexpress/red-team-scripts` `HostEnum.ps1` list this project credits as inspiration), and `AppLocker` (whether AppLocker is configured, which constrains what can even execute). This is the narrowest, fastest, and lowest-noise realistic Seatbelt invocation — five checks instead of dozens.

## Browser Credential/History Harvesting

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003/) (Credentials from Password Stores: Credentials from Web Browsers)

```
# Chrome/Edge/Brave/Opera — bookmarks, history, and a lightweight
# presence-only check
Seatbelt.exe -group=chromium

# Non-Chromium and OS-native stores
Seatbelt.exe FirefoxHistory FirefoxPresence WindowsVault IEUrls IEFavorites IETabs
```

`-group=chromium` runs every command whose name starts with `Chromium*` (`ChromiumBookmarks`, `ChromiumHistory`, `ChromiumPresence`) against any installed Chrome/Edge/Brave/Opera profile found. `WindowsVault` pulls credentials saved in the Windows Vault (the store behind Internet Explorer/Edge saved logins) — note this is a genuine credential-material check, distinct from `ChromiumHistory`/`FirefoxHistory`, which only recover browsing history/URLs, not stored passwords. `ChromiumPresence`/`FirefoxPresence` are cheap existence-only checks (no parsing) worth running first on a fleet-wide sweep to triage which hosts are worth the heavier history/bookmark parse.

## Cloud Credential File Harvesting

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001/) (Unsecured Credentials: Credentials In Files)

```
Seatbelt.exe CloudCredentials CloudSyncProviders DpapiMasterKeys
```

`CloudCredentials` (verified directly in `CloudCredentialsCommand.cs`) walks every user profile under `C:\Users\` and checks for the **presence** of known cloud CLI/SDK credential-cache files — it reports filename, last-accessed time, last-modified time, and size, but does **not** parse or exfiltrate the file's contents itself:

| Provider | Path(s) checked, relative to each user's profile |
|---|---|
| AWS | `\.aws\credentials` |
| Google Cloud | `\AppData\Roaming\gcloud\credentials.db`, `\AppData\Roaming\gcloud\legacy_credentials`, `\AppData\Roaming\gcloud\access_tokens.db` |
| Azure | `\.azure\azureProfile.json`, `\.azure\TokenCache.dat`, `\.azure\AzureRMContext.json`, `\AppData\Roaming\Windows Azure Powershell\TokenCache.dat`, `\AppData\Roaming\Windows Azure Powershell\AzureRMContext.json` |
| IBM Bluemix | `\.bluemix\config.json`, `\.bluemix\.cf\config.json` |

Because this check only calls `File.Exists()` and reads file metadata (not content), the operator still needs a second step — manually pulling the flagged file, or a follow-on tool — to actually extract usable cloud credential material; Seatbelt's role here is **discovery and triage**, telling the operator which of these files exist and how recently they were touched, not extraction. `DpapiMasterKeys` lists DPAPI master key files present, relevant because several of the credential stores above (and `WindowsVault`/`WindowsCredentialFiles`) are themselves DPAPI-protected.

## Persistence-Mechanism Discovery

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder), [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task/Job: Scheduled Task), [T1546.003](https://attack.mitre.org/techniques/T1546/003/) (Event Triggered Execution: WMI Event Subscription)

```
Seatbelt.exe AutoRuns ScheduledTasks WMIEventConsumer WMIEventFilter WMIFilterBinding WindowsAutoLogon LocalGPOs
```

`AutoRuns` (verified in `AutoRunsCommand.cs`) checks exactly eight `HKLM` registry paths — `...\CurrentVersion\Run`, `RunOnce`, `RunService`, `RunOnceService`, and their `Wow6432Node` equivalents. This is narrower than Sysinternals Autoruns: it does **not** check `HKCU` per-user Run keys, the Startup folder, services, scheduled tasks, or browser extensions — those are covered by separate checks (`ScheduledTasks`, `Services`) or not covered at all. `ScheduledTasks` (via WMI) excludes tasks authored by 'Microsoft' by default, `-full` (as a per-invocation `-Full` global flag) dumps everything including Microsoft-authored tasks. The `WMIEventConsumer`/`WMIEventFilter`/`WMIFilterBinding` trio enumerates WMI-based persistence (event filter → consumer → filter-to-consumer binding), a mechanism that survives conventional Run-key/scheduled-task sweeps entirely. An operator planning follow-on implantation runs this set first specifically to find a persistence slot the existing environment already uses/tolerates, or to confirm a chosen technique won't collide with something already present.

## Remote/Lateral Enumeration of a Second Host

**MITRE ATT&CK:** [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery), [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation) for the access mechanism itself

```
# Full remote-capable group
Seatbelt.exe -group=remote -computername=SQL01.CORP.LOCAL

# Explicit alternate credentials
Seatbelt.exe -group=remote -computername=SQL01.CORP.LOCAL -username=CORP\svc-backup -password="P@ssw0rd!"

# A single targeted remote check
Seatbelt.exe LocalUsers -computername=SQL01.CORP.LOCAL
```

`-group=remote` runs a curated subset of the "+"-flagged checks specifically chosen for remote applicability (`AMSIProviders`, `AntiVirus`, `AuditPolicyRegistry`, `ChromiumPresence`, `CloudCredentials`, `DNSCache`, `DotNet`, `DpapiMasterKeys`, `EnvironmentVariables`, `ExplicitLogonEvents`, `ExplorerRunCommands`, `FileZilla`, `Hotfixes`, `InterestingProcesses`, `KeePass`, `LastShutdown`, `LocalGroups`, `LocalUsers`, `LogonEvents`, `LogonSessions`, `LSASettings`, `MappedDrives`, `NetworkProfiles`, `NetworkShares`, `NTLMSettings`, `OptionalFeatures`, `OSInfo`, `PoweredOnEvents`, `PowerShell`, `ProcessOwners`, `PSSessionSettings`, `PuttyHostKeys`, `PuttySessions`, `RDPSavedConnections`, `RDPSessions`, `RDPsettings`, `SecureBoot`, `Sysmon`, `WindowsDefender`, `WindowsEventForwarding`, `WindowsFirewall` — full list verified against the README's own enumeration). Without explicit `-username=`/`-password=`, the connection uses the operator's **current token** — meaning this only works if that token already has sufficient rights on the target. This is the tool's own equivalent of lateral-movement recon: identify a second reachable host, confirm what's running there and who's logged in, before deciding whether to actually move to it with a separate tool.

## User-Context Recon vs. Elevated All-User Recon

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) (Account Discovery: Local Account)

```
Seatbelt.exe -group=user
```

The exact same command line behaves differently depending on the calling token — per the project's own README: "searches that target users will run for the current user if not-elevated and for ALL users if elevated." An operator running this from a non-elevated context gets a single-user picture (their own browser history, their own PuTTY sessions, their own KeePass configs); the same command from an elevated/SYSTEM context walks every local user profile. Worth running once early (non-elevated, to confirm current-user footprint) and again after any privilege escalation (to see what newly becomes visible).

## Slack Workspace/Download Artifact Harvesting

**MITRE ATT&CK:** [T1213](https://attack.mitre.org/techniques/T1213/) (Data from Information Repositories) for the downstream value of anything recovered; [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery) for the check itself

```
Seatbelt.exe -group=slack
```

Runs every command starting with `Slack*` — `SlackDownloads` (parses any found `slack-downloads` files), `SlackPresence` (checks whether interesting Slack files exist at all), `SlackWorkspaces` (parses `slack-workspaces` files). Slack's local cache/config files can reveal internal workspace names, channel structures, and download history that map directly to organizational structure — useful reconnaissance value distinct from credential material.

## Excluding Noisy or Slow Checks from a Broad Sweep

**MITRE ATT&CK:** Same as [Full Local Survey](#full-local-survey-after-initial-foothold) — this is a scoping variant, not a distinct technique

```
Seatbelt.exe -group=all -InterestingFiles -LOLBAS -SearchIndex
```

Any bare `-CommandName` argument present alongside a `-group=` value is treated as an **exclusion** from that group, not a new check to add (verified in `Runtime.ProcessGroup`). `InterestingFiles` and `LOLBAS` are both explicitly flagged in their own README descriptions as taking "non-trivial time" — excluding them from an `all` sweep is a common operational choice when the operator wants breadth without the multi-minute runtime those two specific checks add.

## Single Targeted Check With an Argument

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012/) (Query Registry) for the `reg` example; [T1070](https://attack.mitre.org/techniques/T1070/) doesn't apply — Seatbelt only reads logs, it doesn't clear them; general Discovery otherwise

```
# 4624 logon events for the last 30 days instead of the 10-day default
Seatbelt.exe "LogonEvents 30"

# Registry query: HKLM\SOFTWARE\Microsoft\Windows Defender, 3 levels deep,
# only keys/values/valueNames matching the regex, ignoring read errors
Seatbelt.exe "reg \"HKLM\SOFTWARE\Microsoft\Windows Defender\" 3 .*defini.* true"

# List a specific directory 2 levels deep, filtered to a file-extension regex
Seatbelt.exe "dir C:\Users 2 .*\.kdbx$ true"
```

Commands that accept an argument must be passed as a single quoted string (the whole `"Command arg1 arg2"` block, parsed internally via `Shell32.CommandLineToArgs` so it behaves like a normal Windows command line inside the quotes). This is how an operator narrows a check's default window/depth/filter instead of accepting Seatbelt's built-in defaults (e.g. `LogonEvents`' default of 10 days, `ExplorerMRUs`'/`IEUrls`' default of 7 days).

## Structured JSON Output for Tooling or C2 Ingestion

**MITRE ATT&CK:** Not a distinct technique — an output-format/exfil-preparation choice layered on whichever checks are run

```
# Structured JSON file
Seatbelt.exe -group=user -q -outputfile="C:\Temp\out.json"

# JSON returned as an in-memory string — no file ever touches disk
Seatbelt.exe -group=system -outputfile=jsonstring
```

Verified in `Seatbelt.cs`'s `OutputSinkFromArgs`: any `-outputfile=` value ending in `.json` produces a `JsonFileOutputSink`; the **literal string** `jsonstring` (not a filename, an exact keyword match) produces a `JsonStringOutputSink` that returns the JSON as an in-memory string instead of writing anything to disk. This second form exists specifically for loader-hosted/in-memory use — a C2 operator capturing Seatbelt's stdout through `execute-assembly`-style output piping gets structured JSON back through the existing C2 channel without ever staging a file on the target that then has to be separately retrieved and cleaned up.

## Randomized Order Plus Inter-Command Delay for Evasion

**MITRE ATT&CK:** [T1622](https://attack.mitre.org/techniques/T1622/) (Debugger Evasion) doesn't apply; this is better framed as a general Defense Evasion posture layered on Discovery — no single dedicated ATT&CK ID covers "randomize/throttle a recon tool's own check order," it's an operational choice rather than a technique

```
Seatbelt.exe -group=all -randomizeorder -delaycommands=750
```

`-randomizeorder` shuffles the group's check execution order via `RNGCryptoServiceProvider` before running them. `-delaycommands=<ms>` — **verified only in source, not documented in the official README** — sleeps for the given number of milliseconds before each individual check executes, spreading a burst of dozens of WMI queries/registry reads/file-existence checks that would otherwise fire in well under a second across a much longer window. Both exist specifically to defeat detections keyed on Seatbelt's default behavior: a fixed, alphabetically-ordered check sequence executing as fast as the CLR can run it.

## In-Memory Execution via a C2 Loader

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) for the loader's own injection technique, layered under whatever Discovery ID applies to the checks actually run

Seatbelt is commonly never dropped as a standalone binary at all — it's reflectively loaded and executed in-memory by a C2 framework's ".NET assembly execution" capability, with Seatbelt's own stdout captured back through the C2 channel. Verified specifics per loader:

**Cobalt Strike** (Wave 2 of this repo, not yet built — syntax below is from Cobalt Strike's own public documentation/community usage, not verified against source in this session since the product is closed-source):

```
beacon> execute-assembly /path/to/Seatbelt.exe -group=all -full
```

**Meterpreter** — verified directly against `rapid7/metasploit-framework`'s `modules/post/windows/manage/execute_dotnet_assembly.rb` (there is no built-in Meterpreter *console command* called `execute-assembly`; the equivalent is this post-exploitation module, authored by `b4rtik`, credited with an AMSI bypass from Rastamouse). It reflectively injects a bundled `HostingCLRx64.dll`/`HostingCLRWin32.dll` to host the CLR inside a target process, copies the assembly into that process's memory over an allocated buffer, and streams output back through a named pipe:

```
use post/windows/manage/execute_dotnet_assembly
set SESSION <id>
set DOTNET_EXE /path/to/Seatbelt.exe
set ARGUMENTS -group=all -full
set TECHNIQUE SELF              # or INJECT (existing PID) / SPAWN_AND_INJECT (new process)
set AMSIBYPASS true
set ETWBYPASS true
run
```

`TECHNIQUE SELF` runs inside Meterpreter's own process; `SPAWN_AND_INJECT` launches a new host process (the module's own default is `notepad.exe` via the `PROCESS` datastore option) purely to host the CLR — an unexpected process like `notepad.exe` loading the CLR and hosting inbound named-pipe I/O is itself a strong target-side signal, covered in `04 - Target Evidence.md`. See `../Metasploit/Meterpreter/` for this repo's coverage of the Meterpreter session side of this workflow.

**Sliver** (folder not yet built in this repo — referenced by name only, no cross-link) — verified directly against `bishopfox/sliver`'s `client/command/exec/execute-assembly.go`. Sliver's console exposes a native `execute-assembly` command taking flags including `--process` (host process for injection), `--in-process` (run inside the current implant process instead of spawning one), `--amsi-bypass`, `--etw-bypass`, `--arch`, and `--ppid`:

```
sliver > execute-assembly /path/to/Seatbelt.exe -group=all -full
```

## Chained Workflow — Seatbelt Findings Driving the Next Tool

**MITRE ATT&CK:** Varies by follow-on action — see below

This is the realistic end-to-end pattern: Seatbelt is rarely the payoff step, it's the situational-awareness step that tells the operator what to do next.

```
# 1. Targeted AV/EDR check informs payload/encoder choice for the next stage
Seatbelt.exe AntiVirus WindowsDefender AMSIProviders
# -> finding: Windows Defender active, no third-party EDR process match
# -> informs choice of msfvenom encoder / evasion approach
# (see ../Metasploit/msfvenom/ and ../Metasploit/Encoders and Evasion/)

# 2. Persistence discovery informs which mechanism is safe/available to reuse
Seatbelt.exe AutoRuns ScheduledTasks WMIEventConsumer
# -> finding: a Run-key slot with no existing occupant discovered
# -> operator implants there rather than adding a new, more visible key

# 3. Credential-store discovery informs the next credential-access tool
Seatbelt.exe WindowsVault CredEnum DpapiMasterKeys
# -> finding: DPAPI master keys present, current-user Vault entries exist
# -> hand off to Mimikatz's sekurlsa/dpapi commands for actual extraction
# (see ../Mimikatz/)
```

Recognizing this chain in target-side telemetry — a burst of Seatbelt-shaped Discovery activity followed within minutes by a second, distinctly different tool's activity on the same host — is a stronger detection story than either step viewed in isolation; see `05 - Detection and Hunting.md`.