# LOLBins — wmic.exe — Overview

> 🔴 **Red Flag Principle:** Every meaningful abuse of `wmic.exe` — local, remote via `/node:`, or the XSL-transform variant — ends the same way: **`WmiPrvSE.exe` (the WMI Provider Host) appears as the parent of an unexpected child process**, because `Win32_Process.Create()` is a WMI method call that Windows always services out-of-process in a provider host, never inside `wmic.exe` itself, even for a purely local, non-`/node:` command. `wmic.exe` itself is typically gone from the process tree by the time anyone looks — it's a thin CLI client, not the process doing the work. The second, rarer but far stronger tell is specific to the XSL-transform ("SquiblyTwo") technique: `wmic.exe` loading the .NET CLR to process an XSL stylesheet leaves a **`wmic.exe.log` file under `%LOCALAPPDATA%\Microsoft\CLR_v4.0[_32]\UsageLogs\`** — a `.NET CLR usage log entry for a process that has no legitimate reason to ever load the CLR at all, verified across multiple independent detection-engineering sources. That combination — `WmiPrvSE.exe` as an unexplained parent, plus (for the XSL variant specifically) a CLR usage-log entry for `wmic.exe` — is this tool's signature.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`wmic.exe` (Windows Management Instrumentation Command-line) is a first-party Windows OS component — a command-line front-end for WMI, not a third-party or offensive-security-authored tool. It shipped with **Windows XP Professional and Windows Server 2003** (excluded from XP Home), per Microsoft's own legacy documentation set (["Using Windows Management Instrumentation command-line"](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc779482(v=ws.10)), Windows Server 2003 vintage). Note a documentation discrepancy worth flagging rather than silently resolving: the current [Win32 API reference page for WMIC](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) lists "Minimum supported client: Windows Vista; Minimum supported server: Windows Server 2008" in its Requirements table — almost certainly reflecting when that specific *documentation page* was normalized into the modern Win32 SDK doc set, not the utility's actual ship date, since Microsoft's own older Server 2003-era pages document it running there. The [LOLBAS Project](https://lolbas-project.github.io/lolbas/Binaries/Wmic/)'s verified OS floor for the abuse techniques in this note is **Windows Vista through Windows 11** — treat Vista as this note's verified abuse-technique floor, XP/2003 as the tool's actual (but abuse-technique-unverified-that-far-back) origin.

**`wmic.exe`'s abuse as a LOLBIN was catalogued by the LOLBAS Project on 2018-05-25**, authored by **Oddvar Moe** (`@oddvarmoe`), with acknowledgement credited to **Casey Smith** (`@subTee`) and **Avihay Eldad** (`@AvihayEldad`) — verified directly against LOLBAS's current [`Wmic.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Wmic.yml) source. Casey Smith's own credit matters historically: the XSL-transform execution technique this note calls **"SquiblyTwo"** (a name echoing the `regsvr32.exe` "Squiblydoo" technique) was first published on his blog in April 2018 (["WMIC.exe Whitelisting Bypass – Hacking with Native Windows Applications"](https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html)), weeks before LOLBAS formally catalogued the binary.

**Deprecation timeline — get this right, it's commonly stated stale.** There are two distinct, verified milestones, not one:

1. **Original deprecation announcement: Windows 10, version 21H1, and the 21H1 semi-annual/General Availability Channel release of Windows Server** (2021). Microsoft's [WMIC Win32 reference page](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) and its [Windows Commands reference page](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic) both carry the identical banner: *"WMIC is deprecated as of Windows 10, version 21H1... This utility is superseded by Windows PowerShell for WMI... This deprecation applies only to the WMIC utility. Windows Management Instrumentation (WMI) itself is not affected."* This is a **deprecation announcement, not a removal** — the binary kept shipping.
2. **A January 2024 update, verified against Microsoft's own [Deprecated features in the Windows client](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features) page:** *"Currently, WMIC is a Feature on Demand (FoD) that's preinstalled by default in Windows 11, versions 23H2 and 22H2. In the next release of Windows, the WMIC FoD will be disabled by default."* In plain terms: as of this update, `wmic.exe` **still ships and is still installed by default** on the two most current Windows 11 releases named — it just isn't guaranteed to stay that way, and Microsoft explicitly frames the *next* release (not a specific already-shipped one) as the point where the Feature-on-Demand flips to disabled-by-default. MITRE ATT&CK's own T1047 page paraphrases this as *"`wmic.exe` is deprecated as of January of 2024, with the WMIC feature being 'disabled by default' on Windows 11+"* — treat that as MITRE's compressed summary of the same January 2024 milestone above, **not** confirmation that `wmic.exe` is already gone from current Windows 11 builds. **Bottom line for an analyst: do not assume a Windows 11 host lacks `wmic.exe` — verify presence (`Get-WindowsCapability -Online -Name "WMIC*"` or simply checking for the binary) rather than ruling it out as a possible attack surface or hunting target by version alone.**

`wmic.exe` is superseded by [Windows PowerShell for WMI](https://learn.microsoft.com/en-us/powershell/scripting/learn/ps101/07-working-with-wmi) (the `Get-WmiObject`/`Get-CimInstance`/`Invoke-CimMethod` cmdlet family) as the actively-developed path — but as long as the binary is present, every technique in this note works unchanged.

## How It Works

`wmic.exe` is a command-line client over the same underlying WMI/COM architecture that PowerShell's `Get-CimInstance`, VBScript's `GetObject("winmgmts:...")`, and Impacket's [`wmiexec.py`](<../../Impacket/wmiexec/01 - Overview.md>) all use — the difference between them is which client talks to the WMI infrastructure, not the infrastructure itself.

**1. The namespace/class/provider model.** WMI organizes everything Windows can report or act on into **classes** (e.g. `Win32_Process`, `Win32_OperatingSystem`, `Win32_ShadowCopy`) inside **namespaces** (`root\cimv2` is the default and by far the most commonly used; `root\SecurityCenter2` holds AV/firewall product state; `root\subscription` holds permanent event-subscription objects). A **provider** — a DLL registered with the WMI service — actually implements each class's behavior. `wmic.exe` defaults to `root\cimv2` unless `/namespace:` overrides it.

**2. Every call is serviced out-of-process, even locally.** WMI providers do not run inside the calling client's process. Whether `wmic.exe` is querying `Win32_Process` on the local machine or calling `Win32_Process.Create()` against a remote `/node:`, the actual work happens inside **`WmiPrvSE.exe`** (WMI Provider Host), a separate process spawned on demand by the WMI service (`Winmgmt`, hosted in a shared `svchost.exe`). This is fundamental to WMI's COM-based architecture, not a quirk specific to remote use — **a local `wmic.exe process call create` produces a child process under `WmiPrvSE.exe`, not under `wmic.exe` directly**, exactly like the remote case.

**3. Local vs. `/node:` remote — same method call, different transport.** For a purely local command, the client-to-service call stays on-box (local COM activation). For `/node:<target>`, `wmic.exe` connects over **DCOM/RPC** — TCP 135 (RPC endpoint mapper) followed by a dynamically negotiated high port — authenticates (NTLM by default, using either the current user's token or explicit `/user:`/`/password:` credentials), and issues the identical `Win32_Process.Create()` (or whichever alias/verb was used) against the remote host's WMI service. This is architecturally the same DCOM/RPC path [Impacket's `wmiexec.py`](<../../Impacket/wmiexec/01 - Overview.md>) uses, and the same one documented in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`'s "Remote WMI as a Lateral-Movement Primitive" section — **`wmic.exe` is Microsoft's own native, built-in equivalent of what `wmiexec.py` reimplements in Python**, not a separate mechanism. The key operational difference from `wmiexec.py`: `wmic.exe` has no built-in output-relay mechanism of its own (no loopback-SMB `__<timestamp>` file) — `process call create` returns only a `ReturnValue`/`ProcessId` pair to the console, not the spawned process's stdout/stderr. An operator who wants output back must either redirect the remote command to a file on a share it can reach, or use `wmic`'s `/format:` output-shaping switches against data WMI itself already returns (e.g. `get` queries), not against an arbitrary command's console output.

```
Attacker box (wmic.exe /node:"10.10.10.5" ...)          Target (10.10.10.5)
────────────────────────────────────────────            ────────────────────
1. DCOM/RPC bind — TCP 135 (endpoint mapper) ─────────▶  Authenticate (NTLM by
   + dynamically negotiated high port                      default, or explicit
                                                             /user:/password:)
2. IWbemServices bound to root\cimv2 (or                 svchost.exe (Winmgmt)
   whatever /namespace: specifies)                             │
                                                                └─▶ WmiPrvSE.exe
3. ExecMethod: Win32_Process.Create(commandline) ───────▶         (WMI Provider Host)
                                                                      │
                                                                      └─▶ cmd.exe /c <cmd>
                                                                            (as the
                                                                             AUTHENTICATED
                                                                             USER)
4. wmic.exe prints only ReturnValue + ProcessId          No output relay exists —
   to the console — NOT the command's own output           command output is not
                                                             returned unless the
                                                             command itself writes
                                                             it somewhere reachable
```

**4. Execution context — the authenticating user, not SYSTEM.** Like `wmiexec.py`, a process spawned via `Win32_Process.Create()` runs impersonating whichever account authenticated the WMI call — never SYSTEM by default. This is the same execution-context behavior documented in [`Impacket/wmiexec/01 - Overview.md`](<../../Impacket/wmiexec/01 - Overview.md>) and is a direct consequence of both tools calling the identical underlying WMI method.

**5. The XSL-transform ("SquiblyTwo") execution path is architecturally distinct.** `wmic.exe process get brief /format:"<path-or-URL>.xsl"` doesn't call `Win32_Process.Create()` at all — it hands the query's output to an **XSL stylesheet processor** for formatting, and a malicious `.xsl` file can embed JScript or VBScript inside a `<msxsl:script>` block that the processor executes as part of "formatting" the output. Per LOLBAS, the stylesheet can be sourced from a **remote URL** or an **SMB path** — either way `wmic.exe` itself, not a spawned child, is what loads the .NET Common Language Runtime (CLR) to run the embedded script, because the XSL/scripting engine used here is CLR-hosted. That CLR load is what produces the `wmic.exe.log` usage-log artifact called out in the red-flag callout above — `wmic.exe` has no legitimate reason to ever load the .NET CLR outside of this technique.

**6. `wmic.exe` can also register WMI permanent-event-subscription persistence, but that is a *different* technique/artifact family from everything above.** `wmic /namespace:"\\root\subscription" path __EventFilter create ...` (and the matching `__EventConsumer`/`__FilterToConsumerBinding` creates) use `wmic.exe` purely as a **CREATE-verb client against the WMI repository** — no `Win32_Process.Create()` call, no `WmiPrvSE.exe` child-process signature at execution time. The resulting persistence mechanism, its repository storage, and its own distinct event trail (Sysmon 19/20/21, WMI-Activity 5859/5860/5861) are already covered in full depth in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` — this note does not re-derive that content, only flags that `wmic.exe` is one of several clients (alongside PowerShell's `Get-CimInstance`/`New-CimInstance` and raw `mofcomp.exe`) capable of creating that triad. **Do not conflate this note's `Win32_Process.Create()` execution mechanic with that separate persistence technique** — they share a binary but not an event signature.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique (umbrella) | [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) |
| Related technique classes | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/) (LOLBAS's own mapping for the local/remote/XSL execute verbs — no dedicated T1218 sub-technique number exists for `wmic.exe` the way regsvr32/mshta/msiexec each have one), [T1564.004 — Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/) (ADS execution), [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) (file copy), [T1518.001 — Security Software Discovery](https://attack.mitre.org/techniques/T1518/001/) (AV/EDR enumeration), [T1490 — Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/) (shadow copy deletion), [T1546.003 — Event Triggered Execution: WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/) (persistence use, distinct mechanic — see How It Works §6) |
| Transport (execution, local) | Local COM activation — no network transport, still routed through `WmiPrvSE.exe` out-of-process |
| Transport (execution, remote/`/node:`) | DCOM/RPC — TCP 135 (RPC endpoint mapper) + a dynamically negotiated high port |
| Authentication | NTLM by default (current user's token, or explicit `/user:`/`/password:` credentials); Kerberos where the environment/target negotiates it |
| Remote execution method | WMI `Win32_Process.Create()`, reached through `IWbemServices` bound to whichever namespace is in effect (default `root\cimv2`) |
| XSL execution mechanism | `.NET CLR`-hosted XSL/script processing of a `/format:` stylesheet — loads JScript/VBScript embedded in a `<msxsl:script>` block, sourced from a remote URL or SMB path |
| Execution context | The authenticating user's token (impersonation), **not** SYSTEM |
| Process host | `WmiPrvSE.exe` (WMI Provider Host), spawned under a shared `svchost.exe` hosting the `Winmgmt` service |
| Binary location | `C:\Windows\System32\wbem\wmic.exe` and `C:\Windows\SysWOW64\wbem\wmic.exe` — note the `\wbem\` subdirectory, unlike several sibling LOLBins in this module that sit directly under `System32`/`SysWOW64` |

## Command-Line Switches — Quick Reference

Verified against Microsoft's [WMIC Win32 API reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) and [Windows Commands reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic), plus the [LOLBAS Project's `Wmic.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Wmic.yml). WMIC's syntax model is **alias + verb + global switches**, not a flat flag list — this table groups accordingly.

**Verbs (used after an alias, e.g. `process call create`, `process get name`)**

| Verb | Plain-English meaning |
|---|---|
| `LIST [BRIEF\|FULL\|INSTANCE\|STATUS\|SYSTEM]` | Shows data. **Default verb** if none is specified. `FULL` (all properties) is the default adverb; `BRIEF` shows a core property subset |
| `GET <property1,property2,...>` | Retrieves specific property values only, rather than the full object |
| `CALL <method>` | Executes a method on the alias's underlying class — this is what makes `process call create` work; `Win32_Process` exposes a `Create` method |
| `CREATE <property=value,...>` | Creates a new instance of the class and sets its property values — used for the WMI-subscription-persistence use case (`__EventFilter create`, etc.) |
| `SET <property=value,...>` | Assigns values to properties on an existing instance |
| `DELETE` | Deletes the current instance or set of matched instances |
| `ASSOC` | Returns objects associated with the matched instance(s) via a `WMI Associators of` query |

**Global switches (set context for the whole invocation)**

| Switch | Plain-English meaning |
|---|---|
| `/NODE:<computer[,computer2,...]>` | **The remote-targeting switch.** Runs every subsequent command against each listed computer instead of (or in addition to) the local machine — comma-delimited for multiple targets, or `/NODE:@<file>` to read a target list from a file. **This is the switch that turns `wmic.exe` into a lateral-movement/fleet-execution tool** |
| `/NAMESPACE:<path>` | Which WMI namespace the alias/class resolves against. Default `root\cimv2`. Set to `\root\SecurityCenter2` for AV/firewall product enumeration, or `\root\subscription` for the event-subscription-persistence use case |
| `/USER:<name>` / `/PASSWORD:<pw>` | Explicit alternate credentials for the `/NODE:` target(s) — prompts for the password interactively if `/PASSWORD:` is omitted. **A password supplied via `/PASSWORD:` is visible on the command line/console and in process-creation logging**, unlike wmiexec.py's `-A authfile` option, which has no wmic.exe equivalent |
| `/FORMAT:<keyword-or-.xsl-path-or-URL>` | Formats query output using a built-in keyword (`table`, `list`, `htable`, `csv`, etc.) **or an XSL stylesheet path/URL** — this second form is the abuse-relevant one (SquiblyTwo) |
| `/IMPLEVEL:<level>` | COM impersonation level for the connection (e.g. `Anonymous`, `Identify`, `Impersonate`) |
| `/AUTHLEVEL:<level>` | COM authentication level (e.g. `Pkt`, `PktPrivacy`) |
| `/OUTPUT:<STDOUT\|CLIPBOARD\|file>` / `/APPEND:<...>` | Redirect all output to a file or the clipboard instead of the console — `/APPEND` doesn't clear the destination first |
| `/RECORD:<file.xml>` | Additionally records all output to an XML file, alongside normal console display |
| `/INTERACTIVE:ON\|OFF` | Whether `DELETE` commands prompt for confirmation — `OFF` is the quiet, script-friendly, scriptable-abuse-friendly setting |
| `/FAILFAST:ON\|OFF\|<ms>` | If `ON`, pings each `/NODE:` target first and skips any that don't respond, rather than hanging on an unreachable host — relevant to fleet-wide use at scale |
| `/AGGREGATE:ON\|OFF` | For multi-`/NODE:` `LIST`/`GET` calls: wait for all targets to respond/timeout before displaying results (`ON`, default) vs. streaming results in as each target answers (`OFF`) |
| `/LOCALE:<id>` | Output language/locale (e.g. `ms_409` for English) |
| `/PRIVILEGES:ENABLE\|DISABLE` | Enable or disable all optional Windows privileges for the WMIC session |
| `/TRACE:ON\|OFF` | Prints success/failure of each internal function call — troubleshooting the tool itself |
| `/ROLE:<namespace>` | Where WMIC looks up alias definitions — rarely changed from the default |

**Commands (top-level, not tied to an alias)**

| Command | Plain-English meaning |
|---|---|
| `CLASS <ClassName>` | Escapes alias mode to query a WMI class directly by name — needed for classes with no built-in alias (e.g. `AntiVirusProduct`, `ShadowCopy`, `__EventFilter`) |
| `PATH <ClassName>` | Same class-direct escape as `CLASS`, oriented toward instance-path operations |
| `CONTEXT` | Prints the current value of every global switch — useful for confirming what a script's preceding `/NODE:`/`/NAMESPACE:` etc. actually set |
| `QUIT` / `EXIT` | Leaves the WMIC interactive shell |

## Quick Use-Case List

- Local process execution (`process call create`) — the baseline code-execution primitive
- Alternate Data Stream (ADS) execution — running a `.exe` payload stored as an NTFS ADS
- Remote process execution via `/node:` — single-target lateral movement
- Fleet-wide / mass remote execution — the same `process call create` issued against many `/node:` targets at once
- XSL-transform remote-URL execution ("SquiblyTwo") — fetching and executing embedded JScript/VBScript from a remote `.xsl` stylesheet, a documented AppLocker/whitelisting bypass
- XSL-transform SMB-sourced execution — same technique, stylesheet pulled from an internal share instead of a URL
- Antivirus/EDR product discovery via `root\SecurityCenter2`
- Installed-software/patch enumeration (`product get`, `qfe get`) for recon/targeting
- User account and local-group enumeration (`useraccount get`, `group get`) for recon
- OS/hardware/process enumeration (`os get`, `computersystem get`, `process list`) for situational awareness
- File copy via `datafile ... call Copy` — a WMI-native alternative to `copy`/`xcopy` for staging or exfil prep
- Volume shadow copy deletion (`shadowcopy delete`) — anti-forensics / ransomware pre-encryption step
- WMI permanent-event-subscription persistence creation (`__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` via `/namespace:\\root\subscription`) — a distinct technique family from every execution use case above, covered by cross-link rather than re-derivation
- Renamed or relocated binary to dodge simple image-name detections

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the source host | Any existing foothold that can run a command line. `wmic.exe` is not itself an initial-access vector |
| Privilege level (execution use cases) | LOLBAS lists every `process call create`/ADS/XSL/copy technique as requiring only `User` privilege on the account running `wmic.exe` — but per Microsoft's own WMI security model, the **target** account authenticating the `Win32_Process.Create()` call typically needs local administrator rights on the target for that call to succeed, matching `wmiexec.py`'s documented requirement |
| Privilege level (AV discovery) | LOLBAS documents `root\SecurityCenter2` enumeration as `User`-level — no admin rights needed for local recon use |
| Network reachability (`/node:` remote use) | TCP 135 (RPC endpoint mapper) plus a dynamically negotiated high port — identical requirement to [`wmiexec.py`](<../../Impacket/wmiexec/01 - Overview.md>), and the same DCOM/firewall constraint documented in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` |
| Credential material (`/node:` remote use) | Current user's token (if it already has rights on the target), or explicit `/user:`/`/password:` — no pass-the-hash or Kerberos-ticket input mode built into `wmic.exe` itself, unlike `wmiexec.py`'s `-hashes`/`-k`/`-aesKey` options |
| XSL stylesheet reachability | An HTTP(S) URL or SMB path the target/operator machine can resolve and read, hosting the malicious `.xsl` file |
| OS version / binary presence | Windows Vista through Windows 11 for LOLBAS's verified abuse-technique floor — but **verify `wmic.exe` is actually present** on any Windows 11 target rather than assuming either its presence or its absence, per the deprecation-timeline caveat in History above |
| WMI service running | `Winmgmt` starts automatically on virtually all Windows installations by default — no precondition to check in practice |
