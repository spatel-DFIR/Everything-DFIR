# LOLBins — sc.exe — Overview

> 🔴 **Red Flag Principle:** `sc.exe` has **no `/user` or `/password` switch of its own** — it is not an authentication client, it is a thin CLI wrapper over the Service Control Manager Remote Protocol (MS-SCMR). `obj=`/`password=` on `create`/`config` set the account the **service** will run as; they say nothing about who the **caller** is. Every `sc \\target ...` invocation therefore rides on a session the operator already holds — an existing domain token, a prior `net use \\target\IPC$ /user:...`, or an interactively-elevated `runas` — which means the command line alone never proves how the attacker authenticated. The second, equally important tell is evidentiary asymmetry between **create** and **config**: a brand-new service (`sc create` + `sc start`) reliably fires System-log **7045** (and, if audited, Security **4697**); **hijacking an already-installed service's `binPath` via `sc config` fires neither** — those two events are install-only. Unless the operator also flips the start type (which fires 7040, a commonly-deprioritized event), a pure `binPath=` swap on an existing service leaves no native Windows Event Log record at all. Hunt the `config` path differently than the `create` path — see `05 - Detection and Hunting.md`.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`sc.exe` (Service Control) is a first-party Windows component, not a third-party or offensive-security-authored tool. Per [Wikipedia's "Sc (command)"](https://en.wikipedia.org/wiki/Sc_(command)) article and Microsoft's own historical documentation, it originated as a **Windows NT Resource Kit** utility — shipped alongside `SrvAny.exe` for Windows NT 3.51, Windows NT 4.0, and Windows 2000 as a way to install, start, stop, and uninstall services from the command line. It became an **inbox, no-download-required command starting with Windows XP**, and Windows Server 2003 is documented as the point where `sc.exe` gained full parity with the Services MMC snap-in, including install/uninstall — not just query/start/stop. It has shipped in every Windows release since, with no deprecation history (unlike `wmic.exe` — see [`LOLBins/wmic/01 - Overview.md`](<../wmic/01 - Overview.md>)).

**LOLBAS's coverage of `sc.exe` is narrower than most operators assume.** Verified directly against the live [`Sc.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Sc.yml) source (author **Oddvar Moe**, `@oddvarmoe`, catalogued **2018-05-25**) and cross-checked against the rendered [LOLBAS Sc.exe page](https://lolbas-project.github.io/lolbas/Binaries/Sc/): the file documents exactly **two** commands, and both are the same technique applied to `create` and `config` respectively — pointing a service's `binPath` at a file hidden inside an **NTFS Alternate Data Stream** (`c:\ADS\file.txt:cmd.exe`), mapped to [T1564.004 — Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/), credited to Oddvar Moe's own [ADS execution research](https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/). **LOLBAS does not catalogue the classic "create a service pointing at an attacker binary and start it" remote-execution technique at all** — the one most pentest and red-team material treats as `sc.exe`'s primary abuse. That mainstream technique isn't a LOLBAS gap so much as a scoping one: it's simply normal, documented Windows administration (`sc.exe` doing exactly what Microsoft built it to do), which doesn't fit LOLBAS's "unexpected functionality" bar the way an ADS-hidden binary path does. This note covers both — the LOLBAS-catalogued ADS trick and the much more consequential remote-service-creation/hijack primitive, the latter sourced from [MITRE ATT&CK T1543.003](https://attack.mitre.org/techniques/T1543/003/)'s procedure-example library (see Techniques/Protocols Used below).

## How It Works

`sc.exe` is a command-line client over the same **Service Control Manager (SCM)** infrastructure that `services.msc`, PowerShell's `New-Service`/`Set-Service`/`Get-Service` cmdlets, and every third-party service-installer ultimately call through `advapi32.dll`'s service-control API (`OpenSCManagerW`, `CreateServiceW`, `ChangeServiceConfigW`, `StartServiceW`, `ControlService`, `DeleteService`, `QueryServiceConfigW`). `sc.exe` adds no capability the API doesn't already expose — it is a raw, scriptable front door onto the exact same primitive every SCM-based lateral-movement tool (PsExec, Impacket's `psexec.py`/`smbexec.py`) wraps and automates.

**1. Local vs. remote — same API, different RPC transport.** For a purely local command, `sc.exe` talks to `services.exe` over local RPC (ALPC) with no network transport at all. For `sc \\target ...`, the target name is a leading positional argument in **UNC format**, and the connection is serviced by **MS-SCMR (Service Control Manager Remote Protocol)** — per the [MS-SCMR specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/705b624a-13de-43cc-b8a2-99573da3635f), the well-known RPC endpoint is `\PIPE\svcctl` (also reachable via the equivalent `\PIPE\ntsvcs` alias), and the server accepts either **RPC over SMB named pipe** (`ncacn_np`, TCP 445) or **RPC over TCP** (`ncacn_ip_tcp`, TCP 135 endpoint mapper + a dynamically negotiated high port) — Windows Vista and later default the client side to RPC/TCP. This is the identical transport family [Impacket's `wmiexec.py`](<../../Impacket/wmiexec/01 - Overview.md>) and `wmic.exe`'s `/node:` (see [`LOLBins/wmic/01 - Overview.md`](<../wmic/01 - Overview.md>)) use for their own RPC calls — different interface UUID and pipe name, same DCOM/RPC transport model.

**2. `sc.exe` authenticates nothing itself.** There is no `-hashes`, `-k`, `/user:`, or `/password:` equivalent anywhere in `sc.exe`'s syntax for the RPC/SMB session. The call rides whatever security context the calling process already holds — the current interactive/service token, or a session explicitly established beforehand (most commonly `net use \\target\IPC$ /user:<domain>\<user> <password>`, which negotiates the SMB session `sc.exe` then reuses, or an interactively-elevated `runas /netonly`). This is a meaningful, easily-missed contrast with `wmic.exe`'s built-in `/user:`/`/password:` and with `wmiexec.py`'s `-hashes`/`-k`/`-aesKey` — an analyst looking for credential material on an `sc.exe \\target` command line will never find it there; the credential submission event lives on a **separate** command or logon a moment earlier (see `03 - Source Evidence.md`).

**3. Create → start is a two-call sequence, not one.** `sc create` alone only writes the service's registry footprint (`HKLM\SYSTEM\CurrentControlSet\Services\<Name>`) and registers it with the SCM database — nothing executes yet. A second, explicit `sc start` (or a reboot, for `start= auto`/`delayed-auto`) is required to actually launch `binPath`. This two-step model is exactly what `sc \\host create` + `sc \\host start` automates in tools built on top of it, and it's why `Windows/10 - Persistence Mechanisms/Services.md`'s "Remote Service Creation for Lateral Movement" section already documents this pattern at the general-services level — this note adds `sc.exe`'s own operator-facing syntax and command-line-specific evidence on top of that existing material rather than re-deriving the registry/event-ID structure.

**4. `sc.exe` delivers no payload of its own.** Unlike PsExec or `psexec.py`, which upload a service binary over `ADMIN$` as part of the same operation, `sc create`'s `binpath=` value must already point at something the target can execute at start time — a binary staged there by a separate mechanism (a prior SMB copy, `certutil`/`bitsadmin` download, an ADS-embedded stream), a UNC path reachable from the target, or a living-off-the-land command line (`cmd.exe /c ...`, `powershell.exe -enc ...`) with no dropped file at all. **The right first hunting question for `sc.exe` is "what does `binPath` actually point to," not "what got dropped" — because `sc.exe` itself never drops anything.**

**5. `sc config` reuses trust, `sc create` builds it from zero.** Hijacking an already-installed, already-trusted service's `binPath` (`sc config <existing> binPath= "..."`) inherits whatever the SCM install event's absence implies — see the red-flag callout above — and, if the target service was already `Auto`-start and already excluded from an analyst's mental "new services" watchlist, blends into steady-state noise far better than a freshly-created service ever can.

**6. Execution context is whatever `obj=` says — default `LocalSystem`.** If `obj=` is omitted, the service runs as `LocalSystem` (SYSTEM), matching PsExec/`psexec.py`'s always-SYSTEM behavior. Unlike those tools, `sc.exe` lets the operator explicitly target a **different** account (`obj= DOMAIN\svc_account password= ...`) — useful for blending a malicious service in among legitimate service accounts, or for a lower-privilege persistence foothold that doesn't trip SYSTEM-execution-focused detections.

**7. `sc failure` is a separate, trigger-based persistence hook.** `sc failure <name> command= "<path>"` sets a command line the SCM runs if — and only if — the service later **crashes or stops unexpectedly**, independent of `binPath`. This is its own artifact family (see `04 - Target Evidence.md`), not a variant of the `binPath` hijack.

**8. `sc sdset`/`sdshow` operate on the service's own security descriptor, not the file/registry ACLs analysts usually think of.** Every service object has a discretionary access-control list (DACL), expressed in SDDL, controlling who may query, start, stop, reconfigure, or delete it — separate from filesystem or registry-key permissions. `sc sdshow <name>` reads the current SDDL; `sc sdset <name> <SDDL>` overwrites it. Two distinct abuse patterns follow from this, both documented by SANS's ["Red Team Tactics: Hiding Windows Services"](https://www.sans.org/blog/red-team-tactics-hiding-windows-services) and mirrored by dedicated [SigmaHQ](https://github.com/SigmaHQ/sigma) detection rules: **hiding** a service from enumeration (deny ACEs stripping the `LC`/List-Contents right from ordinary trustees, so `services.exe`, `Get-Service`, and `sc query` alike simply never see it — confirmed by the SANS author directly), and **backdooring** a service by granting a normally-unprivileged account rights to reconfigure/start/stop a SYSTEM-context service it otherwise has no business touching.

```
Attacker box                                          Target (10.10.10.5)
──────────────                                         ────────────────────
0. (pre-req) net use \\10.10.10.5\IPC$                Authenticate — NTLM/Kerberos.
   /user:CONTOSO\admin <password>          ──────────▶  sc.exe itself supplies NO
   (or an already-held token/session)                    credential of its own — see
                                                            How It Works §2
1. sc \\10.10.10.5 create SvcName                      MS-SCMR bind — \PIPE\svcctl
   binPath= "C:\Windows\Temp\evil.exe"     ──────────▶  (TCP 445 SMB, or TCP 135 +
   start= demand                                          dynamic high port)
                                                              │
                                                              └─▶ OpenSCManagerW()
                                                                    └─▶ CreateServiceW()
                                                                          (writes
                                                                     HKLM\...\Services\
                                                                     SvcName — fires
                                                                     System 7045, and
                                                                     Security 4697 if
                                                                     audited)

2. sc \\10.10.10.5 start SvcName          ──────────▶  StartServiceW() ──▶ services.exe
                                                                              └─▶ evil.exe
                                                                                    (as
                                                                                    obj=
                                                                                    account,
                                                                                    default
                                                                                    SYSTEM)

3. sc \\10.10.10.5 delete SvcName         ──────────▶  DeleteService() — registry key
   (cleanup, if the operator bothers)                   removed, no dedicated "service
                                                          deleted" event — see 04
```

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique (persistence/priv-esc — create/config/failure) | [T1543.003 — Create or Modify System Process: Windows Service](https://attack.mitre.org/techniques/T1543/003/) |
| MITRE technique (execution — the start step) | [T1569.002 — System Services: Service Execution](https://attack.mitre.org/techniques/T1569/002/) — MITRE's own page names both PsExec and `sc.exe` as tools that "accept remote servers as arguments and may be used to conduct remote execution" via this sub-technique |
| MITRE technique (ADS binPath, LOLBAS-catalogued) | [T1564.004 — Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/) |
| Related technique class (remote-session prerequisite) | [T1021.002 — Remote Services: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002/) — covers the `net use \\target\IPC$`/`ADMIN$` session `sc.exe` rides on when no token already exists |
| Service DACL manipulation (`sdset`/`sdshow`) | No dedicated MITRE sub-technique ID exists for service security-descriptor tampering specifically — closest umbrella remains T1543.003 (it's still modifying "the service") with a defense-evasion (hiding) or persistence (backdoor-grant) intent layered on top, not a separately numbered technique |
| Transport (local) | Local RPC (ALPC) to `services.exe` — no network transport |
| Transport (remote) | MS-SCMR over `\PIPE\svcctl` — RPC/SMB (`ncacn_np`, TCP 445) or RPC/TCP (`ncacn_ip_tcp`, TCP 135 endpoint mapper + dynamic high port); Vista+ clients default to RPC/TCP |
| Authentication | **None of `sc.exe`'s own** — reuses whatever token/session already exists (current logon, prior `net use`, `runas`) |
| Underlying API | `advapi32.dll` service-control functions: `OpenSCManagerW`, `CreateServiceW`, `ChangeServiceConfigW`, `StartServiceW`, `ControlService`, `DeleteService`, `QueryServiceConfigW`, `SetServiceObjectSecurity`/`QueryServiceObjectSecurity` (`sdset`/`sdshow`) |
| Execution context | Whatever `obj=` specifies — `LocalSystem` (SYSTEM) if omitted |
| Registry footprint | `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` (config) and its `\Security` subkey (SDDL security descriptor) |
| Binary location | `C:\Windows\System32\sc.exe` and `C:\Windows\SysWOW64\sc.exe` |

## Command-Line Switches — Quick Reference

`sc.exe`'s syntax model is **`[\\servername] <command> [servicename] [options...]`**, verified against the official Microsoft "[Sc](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754599(v=ws.11))" command index and the individual per-command reference pages ([`sc create`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create), [`sc config`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config), [`sc query`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query)). **Every `option=` requires the trailing `=` and a following space before its value** — `binpath= C:\svc.exe`, never `binpath=C:\svc.exe` — omitting the space is a documented failure mode, not a style choice.

**`\\servername`** — leading, optional, UNC-format (`\\10.10.10.5`) target for every command below. Omit entirely to run locally.

**Primary commands (the ones this note's use cases center on)**

| Command | Plain-English meaning |
|---|---|
| `create <name> binpath= <path> [type=] [start=] [error=] [group=] [tag=] [depend=] [obj=] [displayname=] [password=]` | Registers a **new** service. `binpath=` has no default and must be supplied. `type=` defaults to `own`; `start=` defaults to `demand` (does **not** auto-run); `obj=` defaults to `LocalSystem`. Fires System 7045 (and Security 4697 if audited) |
| `config <name> [binpath=] [type=] [start=] [error=] [group=] [tag=] [depend=] [obj=] [displayname=] [password=]` | Modifies an **existing** service's registry entries — same option set as `create`, any omitted option is left unchanged. **Does not fire 7045/4697** — see red-flag callout |
| `start <name> [args...]` | Starts the service (`StartServiceW`) |
| `stop <name>` | Sends a STOP control request |
| `delete <name>` | Removes the service's registry subkey — reverses `create` |
| `query [name] [type=] [state=] [bufsize=] [ri=] [group=]` | Enumerates services/drivers and their live state (`SERVICE_NAME`, `TYPE`, `STATE`, etc.). Default `state=` is `active` only — add `state= all` to see stopped/disabled services too |
| `queryex [name] [same options as query]` | Same as `query`, adds the owning **process ID** for running services |
| `qc <name> [bufsize=]` | Queries **configuration**: `SERVICE_NAME`, `TYPE`, `ERROR_CONTROL`, `BINARY_PATH_NAME`, `LOAD_ORDER_GROUP`, `TAG`, `DISPLAY_NAME`, `DEPENDENCIES`, `SERVICE_START_NAME` — the fastest way to read a service's current `binPath`/run-as account from a live host |
| `failure <name> [reset=] [reboot=] [command=] [actions=]` | Sets recovery/failure actions: `reset=<seconds>` — how long with no failures before the failure counter resets; `reboot=<message>` — broadcast message before a reboot action; `command=<commandline>` — **run this command** if the service fails; `actions={run\|restart\|reboot}/<ms>[/...]` — the ordered action list and per-action delay |
| `sdshow <name>` | Displays the service's security descriptor in SDDL |
| `sdset <name> <SDDL>` | **Overwrites** the service's security descriptor — used both to lock a service down legitimately and, per the red-flag callout, to hide or backdoor it |

**Secondary commands** (verified against the same official Microsoft index, less central to this note's abuse cases but included for completeness)

| Command | Plain-English meaning |
|---|---|
| `pause <name>` | Sends a PAUSE control request |
| `continue <name>` | Sends a CONTINUE control request to a paused service |
| `interrogate <name>` | Sends an INTERROGATE control request (asks the service to report its current status) |
| `control <name> <control#>` | Sends an arbitrary numbered control code to a service |
| `description <name> <text>` | Sets the service's description string |
| `qdescription <name>` | Displays the service's description string |
| `qfailure <name>` | Displays the currently-configured failure actions |
| `failureflag <name> <flag>` | Sets whether failure actions trigger on a non-crash stop as well as a crash |
| `getdisplayname <name>` | Resolves a service's key name to its display name |
| `getkeyname <displayname>` | Resolves a display name back to its registry key/service name |
| `enumdepend <name>` | Lists services that depend on (won't start without) the named service |
| `boot {yes\|no}` | Marks whether the most recent boot should be saved as the last-known-good configuration |
| `lock` | Locks the SCM database (blocks other service-config changes while held) |
| `querylock` | Displays whether the SCM database is currently locked, and by whom |

## Quick Use-Case List

- Local service creation + start — baseline SYSTEM code-execution primitive (`sc create` + `sc start`)
- Remote service creation over `\\target` — raw SCM-based lateral movement, the primitive PsExec/`psexec.py` automate
- Fleet-wide / mass remote creation-and-start across a target list
- `binPath` hijack of an already-installed, trusted service (`sc config`) — reuses trust, avoids the 7045/4697 install-event trail
- Delayed-auto persistence (`start= delayed-auto`) — blends with the batch of legitimate services Windows itself starts a few seconds after boot
- Failure-action persistence hook (`sc failure ... command=`) — fires only if/when the target service crashes, a separate trigger from `binPath`
- ADS-embedded `binPath` execution (LOLBAS-documented, both `create` and `config` variants) — an AWL/whitelisting-bypass technique
- Custom run-as account (`obj=`/`password=`) — execute as a specific domain/local account instead of SYSTEM, for blending or scoped persistence
- Service DACL hiding (`sc sdset` with deny ACEs) — removes the service from `services.exe`/`Get-Service`/`sc query` enumeration entirely
- Service DACL backdoor grant (`sc sdset` with an allow ACE for a low-privilege trustee) — lets a non-admin account reconfigure/start/stop a SYSTEM-context service later, without re-elevating
- Recon/situational awareness (`sc query`, `sc qc`, `sc queryex`) — enumerate installed services, their `binPath`/run-as account, and running PIDs for targeting
- Cleanup / anti-forensics (`sc stop` + `sc delete`) after a completed operation
- Renamed or relocated binary to dodge simple image-name-keyed detections
- Chained use immediately after a separate credential-harvesting or session-establishment step (e.g. `secretsdump.py` → `net use` → `sc.exe`) — `sc.exe` as the "last mile" execution step once a session already exists

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on the source host | Any existing foothold that can run a command line. `sc.exe` is not itself an initial-access vector |
| An already-authenticated session or token for the target (`\\target` use) | `sc.exe` has no credential switches of its own — see How It Works §2. Requires a prior `net use \\target\IPC$ /user:...`, an already-privileged current token, or `runas` |
| Privilege on target | `SC_MANAGER_CREATE_SERVICE` (create) or the relevant service-specific right (config/start/stop/delete/sdset) — in practice this means local-Administrator-equivalent rights on the target for the create/config/sdset use cases; `sc query`/`sc qc` read access can be broader depending on the service's own DACL |
| Network reachability (`\\target` remote use) | TCP 445 (SMB, `\PIPE\svcctl`) or TCP 135 (RPC endpoint mapper) + a dynamically negotiated high port |
| A reachable `binPath` target | `sc.exe` delivers no payload itself — the executable/command `binPath` points at must already be staged (separate file drop, UNC path, ADS stream, or a living-off-the-land command line) |
| SDDL syntax knowledge (`sdset` use case) | Required to construct a valid, syntactically-correct security descriptor string — a malformed SDDL argument fails the call outright |
| OS version / binary presence | Present, unmodified, and un-deprecated on every supported Windows version — no removal/FoD caveat the way `wmic.exe` and (soon) other legacy CLI tools carry |
