# SharpWMI — Overview

> 🔴 **Red Flag Principle:** SharpWMI is not one execution fingerprint but three, and applying the `Impacket/wmiexec.py`/`LOLBins/wmic.exe` playbook wholesale will miss two of them. Its `exec` (alias `create`) action rides the familiar `Win32_Process.Create()` path — `WmiPrvSE.exe` spawns the command as an unexpected child, same as `wmiexec.py`/`wmic` — but `result=true` output capture never touches a share or writes a file at all; per the README, it works "by storing command's output in an instance of arbitrary WMI object" and reads it back over the **same** WMI connection, so the `__<timestamp>`-style file hunt that catches `wmiexec.py` finds nothing here. Its `executevbs` action bypasses `Win32_Process.Create()` entirely: it registers a transient `__EventFilter`/`ActiveScriptEventConsumer`/`__FilterToConsumerBinding` triad — the same WMI persistence primitive documented in [`Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`](<../../../Windows/10%20-%20Persistence%20Mechanisms/WMI%20Event%20Consumers.md>) — to trigger VBScript execution. That makes `executevbs` the one SharpWMI action that legitimately fires WMI-Activity **5859/5860/5861** (filter/consumer/binding registration) — the exact three event IDs `Impacket/wmiexec/04 - Target Evidence.md` explicitly rules out as inapplicable to `Win32_Process.Create()`-based execution. And because the registered consumer type is `ActiveScriptEventConsumer`, the resulting process tree runs through `scrcons.exe` (the WMI ActiveScript event-consumer host) as an intermediate hop — not `WmiPrvSE.exe` spawning the payload directly.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`GhostPack/SharpWMI`](https://github.com/GhostPack/SharpWMI), its `README.md`, its `LICENSE` file, and the live commit/release/tag history via the GitHub API:

- **Primary author:** [Will Schroeder](https://twitter.com/harmj0y) (`@harmj0y`), the same GhostPack author behind `Rubeus/`, `Seatbelt/`, and `SharpUp/` (all already built in this repo). **License:** BSD 3-Clause, `Copyright (c) 2018, Will Schroeder` (verified directly from the `LICENSE` file text, not just the README's one-line mention).
- **The README's own description, verbatim:** *"SharpWMI is a C# implementation of various WMI functionality. This includes local/remote WMI queries, remote WMI process creation through win32_process, and remote execution of arbitrary VBS through WMI event subscriptions. Alternate credentials are also supported for remote methods."*
- **No explicit lineage statement — a real discrepancy from `SharpUp`'s README worth flagging before writing anything else.** `SharpUp/README.md` opens with an explicit "C# port of PowerUp" sentence; `SharpWMI/README.md` carries no equivalent line naming PowerSploit's `Invoke-WmiCommand` or any other tool as a direct port source. SharpWMI is commonly described in community write-ups as conceptually related to PowerSploit's WMI-based lateral-movement functions, but that lineage is **not asserted by the project's own README**, so it isn't stated as verified fact here.
- **First commit:** 2018-07-24 (`"initial commit"`, 18:47:32 UTC) — the same day the repository was created (`created_at: 2018-07-24T17:44:35Z`) and the same day `GhostPack/SharpUp` was created, consistent with a coordinated multi-tool GhostPack launch. **Releases/tags:** verified live via the GitHub API — **zero, ever** (`gh api repos/GhostPack/SharpWMI/releases` and `/tags` both return empty arrays). Same "compile yourself" posture as every other GhostPack tool already in this repo, and the README says so explicitly under Compile Instructions: *"We are not planning on releasing binaries for SharpWMI, so you will have to compile yourself :)"*
- **Build target:** .NET Framework **3.5**, per the README text directly: *"SharpWMI has been built against .NET 3.5 and is compatible with Visual Studio 2015 Community Edition."* Identical target to `SharpUp` — one full Framework generation older than `Rubeus`/`Seatbelt`'s 3.5/4.0/4.8 range.
- **Development activity, verified against the live commit log (20 commits total):** the most recent commit landed **2021-01-15** (`"Merge pull request #5 from slyd0g/master: Added the ability to execute MSI installers"`) — the addition of `action=install`. The repository is not archived, but it has been feature-frozen for over five years as of this writing. Notable intermediate milestones from the same commit log: `action=firewall`, `action=ps`/`terminate`, and the environment-variable actions (`getenv`/`setenv`/`delenv`) all landed in a burst between 2020-03-30 and 2020-05-19; the `executevbs` action's script-specification flexibility, WMI file upload, and AMSI-disable support landed 2020-05-06 in a single commit titled *"Added WMI file upload, executevbs script specification variations, AMSI disabling and some minor enhancements."* A 2019-07-03 commit message reads simply `"回显"` (Chinese for "echo"/"reflect output") — consistent with the Authors table's own credit for "WMI code-exec output idea" to a Chinese-handle contributor (below), and it's the commit that introduced the `result=true` WMI-object output-capture mechanism this page's red-flag callout centers on.
- **Acknowledged contributors** (per the README's own Authors table): **harmj0y** (original SharpWMI implementation), **Ridter** (Evi1cg — WMI code-exec output idea, i.e. the `result=true` mechanism), **0xthirteen** (Steven Flores — AMSI evasion code taken from `SharpMove`), **mgeeky** (Mariusz B. — enhancements, VBS flexibility, file upload; the README states `executevbs` "was reworked as compared to the original version of SharpWMI" under this contribution), **slyd0g** (Justin Bui — MSI file installation, the tool's final feature addition).

## How It Works

Every action shares the same WMI/DCOM connection bootstrap already documented in [`Impacket/wmiexec/01 - Overview.md`](<../../Impacket/wmiexec/01%20-%20Overview.md>)'s How It Works — `IWbemLocator`/`IWbemServices` bound to a namespace (default `root\cimv2`), reached in-process for local targets or over DCOM/RPC (TCP 135 + a dynamically negotiated high port, NTLM or Kerberos) for remote ones. That shared mechanic isn't re-derived here. What's specific to SharpWMI is that a single binary exposes **three structurally different WMI usage patterns** behind one `action=` argument, each with its own evidentiary footprint:

```
SharpWMI.exe action=<verb> [computername=HOST[,HOST2,...]] [username=DOMAIN\user password=Pass123!]
        │
        ▼
Shared WMI/DCOM connection bootstrap (see Impacket/wmiexec/01 - Overview.md — not re-derived here):
  IWbemLocator.ConnectServer() → IWbemServices bound to root\cimv2 (or namespace=)
  local: in-process call, no network hop · remote: DCOM/RPC, TCP 135 + dynamic port
        │
        ├── QUERY / ENUMERATION FAMILY — query, loggedon, firewall, ps, getenv
        │     IWbemServices.ExecQuery(WQL) against Win32_Service / Win32_Process /
        │     Win32_Environment / the firewall provider / etc. — read-only, no
        │     process creation, no event subscription, no registry/service write
        │
        ├── METHOD-CALL FAMILY — exec (alias create), terminate, setenv, delenv, install
        │     IWbemServices.ExecMethod() against a target class's own method:
        │       exec/create   → Win32_Process.Create(command) ────▶ WmiPrvSE.exe
        │                                                              └─▶ <command>
        │       result=true   → command output stashed as a property value on an
        │                       ad hoc WMI object instance, read back over the SAME
        │                       WMI connection — no share write, no output file
        │       terminate     → Win32_Process.Terminate() against the matched PID/name
        │       setenv/delenv → Win32_Environment Create()/Delete()
        │       install       → MSI install path — the README does not state whether
        │                       this calls Win32_Product's own WMI Install() method
        │                       or launches msiexec.exe via Win32_Process.Create();
        │                       unconfirmed, see the note below
        │
        └── EVENT-SUBSCRIPTION FAMILY — executevbs — bypasses Win32_Process.Create() entirely
              PutInstance() registers a transient triad in the WMI repository:
                __EventFilter             (timer-based trigger, per `trigger=N` seconds)
                ActiveScriptEventConsumer (VBScript text, from one of 8 script-
                                            specification methods A-H — see below)
                __FilterToConsumerBinding (binds the two into a live subscription)
                        │
                        ▼  fires after `trigger` seconds
              WmiPrvSE.exe ──▶ scrcons.exe (WMI ActiveScript event-consumer host)
                                  └─▶ VBScript executes → spawns the real payload
                        │
                        ▼  after `timeout` seconds
              Subscription objects presumably torn down — cleanup-on-every-code-path
              not independently confirmed against source for this note (README-only
              research scope); treat any surviving triad with the same full-triad
              review discipline as genuine WMI persistence
```

**Two things worth being precise about, both flagged rather than guessed at:**

1. **The `install` action's exact WMI method call is not stated in the README.** MSI installation via WMI can mean either `Win32_Product.Install()` (a genuine, if notoriously slow, WMI class method that talks to the Windows Installer service directly) or a `Win32_Process.Create()` call that simply launches `msiexec.exe /i <path>` — the two leave meaningfully different evidence (the former touches the Windows Installer service and its own MSI event log directly with no `WmiPrvSE.exe → msiexec.exe` process-tree entry; the latter produces exactly that process-tree entry, identical in shape to the `exec` action's). This wasn't independently verified against source for this note — see `04 - Target Evidence.md` for how to disambiguate live.
2. **`executevbs`'s `trigger=`/`timeout=` parameters are framed by the README purely as execution timing** ("script trigger and wait timeouts"), not as a persistence on/off switch — there is no visible flag in the usage block for "install this subscription and leave it running." That framing, plus the presence of both a trigger delay and a wait timeout, reads as a self-cleaning one-shot execution primitive built on top of the WMI permanent-event-subscription mechanism, not a dedicated persistence installer. If an operator's build is modified to skip cleanup (or a run is interrupted before it completes), the leftover triad would be indistinguishable from genuine `T1546.003` persistence — which is exactly why `04 - Target Evidence.md` treats a found triad as needing full review regardless of the tool's own intent.

**All eight `executevbs` script-specification methods only change what ends up in the registered consumer's `ScriptText` property** — the subscription mechanism itself (filter, consumer, binding, trigger/timeout) is identical across all eight:

| Method | What it puts in `ScriptText` |
|---|---|
| A | A preset VBS wrapper that runs an OS command given via `command=` |
| B | VBS that downloads a PowerShell script from a URL and feeds it to `powershell.exe` via stdin |
| C | VBS that downloads a binary from a URL to a target path and executes it |
| D | Same as C, plus executes an arbitrary follow-on `command=` after the download |
| E | The literal contents of a local `.vbs` file (`script=`) |
| F | A VBS script given literally inline on the command line (`script=`) |
| G | A base64-encoded VBS script given literally (`scriptb64=`) |
| H | A base64-encoded VBS script read from a local `.vbs.b64` file (`scriptb64=`) |

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Transport (remote) | DCOM/RPC — TCP 135 (RPC endpoint mapper) + a dynamically negotiated high port, identical channel to `Impacket/wmiexec.py` and `LOLBins/wmic.exe /node:` |
| Transport (local) | None — `computername` omitted targets the local host entirely in-process, no network hop for any action |
| Authentication | NTLM or Kerberos, using either the calling process's current token or explicit `username=`/`password=` alternate credentials on any remote action |
| Query/enumeration | `IWbemServices.ExecQuery()` (WQL) against `Win32_Service`, `Win32_Process`, `Win32_Environment`, firewall-related classes, `MSFT_NetTCPConnection`, or any class the operator names in a raw `query=` string |
| Remote process creation | `Win32_Process.Create()` method call — same primitive as `wmiexec.py`/`wmic.exe process call create` |
| Output-capture covert channel | A distinctive SharpWMI mechanism: command output is written into a property of an ad hoc WMI class instance and read back over the same `IWbemServices` connection — no SMB share write, unlike `wmiexec.py`'s loopback-SMB output relay |
| Persistence-primitive-as-execution | `__EventFilter` / `ActiveScriptEventConsumer` / `__FilterToConsumerBinding` — the standing WMI permanent-event-subscription mechanism, used here as a transient (trigger/timeout-bounded) execution vector rather than as a persistence installer — see `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` for the general mechanics this note doesn't re-derive |
| File transfer | `action=upload`, mechanism not detailed beyond "via WMI" in the README — plausibly rides the same ad hoc WMI-object channel as `result=true`, not independently confirmed |
| Defense evasion | `amsi=disable` — AMSI-bypass code the Authors table credits as "taken from `SharpMove`," available on `exec`, `executevbs`, `upload`, and `install` |
| Execution context | The authenticating user's token (impersonation) for remote calls — same as `wmiexec.py`, never SYSTEM |
| Process host | `WmiPrvSE.exe` for `Win32_Process.Create()`-based actions; `WmiPrvSE.exe` → `scrcons.exe` for `executevbs` |

## Command-Line Switches — Quick Reference

SharpWMI takes `key=value` arguments only — no `-flag`/`/flag` syntax. Verified directly against the README's `Usage` block, written for a reader with no offensive background.

| Argument | Applies to | Plain-English meaning |
|---|---|---|
| `action=<verb>` | All | **Required.** Selects the operation: `query`, `loggedon`, `exec` (alias `create`), `executevbs`, `upload`, `firewall`, `ps`, `terminate`, `getenv`, `setenv`, `delenv`, `install` |
| `computername=HOST[,HOST2,...]` | All remote-capable actions | Target host(s) — comma-separated for multiple. **Omit entirely to target localhost** |
| `username=DOMAIN\user` / `password=Pass123!` | Any remote action | Alternate credentials — optional; without them, the call rides the caller's current token |
| `namespace=BLAH` | `query` | WMI namespace override (e.g. `root\SecurityCenter2`, `ROOT\StandardCIMV2`) — defaults to `root\cimv2` if omitted |
| `query="WQL text"` | `query` | The raw WQL query string to execute |
| `command="..."` | `exec`, `executevbs` (method A) | The command line to run |
| `result=true` | `exec`/`create` | Retrieve the executed command's output via the WMI-object covert channel described in How It Works, instead of fire-and-forget |
| `amsi=disable` | `exec`, `executevbs`, `upload`, `install` | Disables AMSI before the action runs (code credited to `SharpMove`) |
| `script="path.vbs"` | `executevbs` (method E/F) | Path to a local `.vbs` file, or a literal inline VBS string |
| `scriptb64="..."` | `executevbs` (method G/H) | A base64-encoded VBS script, given literally or as a path to a `.vbs.b64` file |
| `url="URL"` or `url="URL,PATH"` | `executevbs` (methods B/C/D) | A URL to a PowerShell script (stdin execution) or a `SOURCE_URL,TARGET_PATH` pair to download-and-run a binary |
| `eventname=blah` | `executevbs` | Name assigned to the registered `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` triad |
| `trigger=N` | `executevbs` | Seconds to wait before the registered event fires |
| `timeout=N` | `executevbs` | Seconds to wait after firing — the README frames this as a wait timeout, not an explicit cleanup toggle |
| `source="..."` / `dest="..."` | `upload` | Local source path / remote destination path |
| `process=PID|name` | `terminate` | Target to kill — terminates the **first matching** process by PID or by name |
| `name=VariableName` | `getenv` (optional — all vars if omitted), `setenv`, `delenv` | Environment variable name |
| `value=VariableValue` | `setenv` | Environment variable value to set |
| `path="C:\...\installer.msi"` | `install` | Local or remote path to the MSI file to install |

## Quick Use-Case List

- Local WMI query enumeration — no credentials, no network hop at all
- Remote WMI query enumeration against one or more hosts (`computername=`, comma-separated)
- Remote logged-on user enumeration (`action=loggedon`)
- Remote process creation, fire-and-forget (`action=exec`)
- Remote process creation with output retrieved via the WMI-object covert channel (`result=true`)
- Remote process creation with AMSI disabled first (`amsi=disable`)
- VBS execution via a transient WMI event subscription, running a preset OS command (method A)
- VBS execution downloading and running a PowerShell one-liner via stdin (method B)
- VBS execution downloading a binary and executing it, optionally with a follow-on command (methods C/D)
- VBS execution from a local file or a literal inline script (methods E/F)
- VBS execution from a base64-encoded script or script file (methods G/H)
- File upload via WMI — no SMB share access involved
- Remote firewall rule enumeration (`action=firewall`)
- Remote process listing and targeted termination (`action=ps` / `action=terminate`)
- Remote environment variable get/set/delete (`getenv`/`setenv`/`delenv`)
- Remote MSI installation (`action=install`)
- Alternate-credential use layered onto any of the above remote actions
- Fleet-wide use via a comma-separated `computername=` list against many hosts in one invocation
- In-memory execution via a C2 loader's `execute-assembly` capability, same pattern as every other GhostPack tool already built in this repo
- Choosing SharpWMI over `Impacket/wmiexec.py` or `LOLBins/wmic.exe` specifically for its output-capture and VBS-execution capabilities those tools don't have natively

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Compiled binary or in-memory host | No official binaries are ever released — every deployment is a custom Visual Studio (.NET 3.5) build, run standalone or reflectively loaded (`execute-assembly`, `[Assembly]::Load()`) |
| Privilege on target (remote actions) | The authenticating account must be a **local administrator** on the target for `Win32_Process.Create()`-based actions and for registering an `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` triad in `root\subscription` — identical gating requirement to `wmiexec.py`/`wmic.exe` |
| Network reachability (remote actions) | TCP 135 (RPC endpoint mapper) plus a dynamically negotiated high port for DCOM/WMI — **not required at all** for local-only invocations (`computername` omitted) |
| Credential material (optional) | Explicit `username=`/`password=` for alternate-credential use, or none at all to ride the caller's current token |
| Target OS | Windows only — every action is built on WMI/DCOM and Win32 APIs; no cross-platform build exists |
| VBS/scripting host on target | `executevbs` depends on the target's WMI ActiveScript event-consumer provider (`scrcons.exe`) being available to run VBScript — present by default on Windows but a genuinely separate dependency from the `Win32_Process.Create()` path the other actions use |
