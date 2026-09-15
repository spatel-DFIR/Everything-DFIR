# Mimikatz — lsadump (DCSync) — Source Evidence

Evidence left on the **attacking/operator** host. This is a sharply different evidentiary shape from `sekurlsa/`: DCSync is a **network-protocol** operation — the operator's own machine is the one making outbound RPC calls, which means source-side network evidence carries real weight here in a way it never did for a local LSASS memory read. `sam`/`secrets`/`cache`/`trust` (default paths) are local-only and leave the same thin, generic trail sekurlsa's source evidence describes. `netsync` sits in between — a targeted RPC call, but a much smaller one than DCSync.

## Contents
- [Shell History](#shell-history)
- [Dropped Binary / Loader Script Artifacts](#dropped-binary--loader-script-artifacts)
- [Live Process State](#live-process-state)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| `cmd.exe` on the operator host | No native history file | Same limitation as `sekurlsa/03 - Source Evidence.md` — nothing persists without a separate console-logging mechanism |
| PowerShell | `PSReadLine` history — `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | If mimikatz was launched or scripted from a PowerShell console, the full command text lands here — for `dcsync`, this includes the exact `/user:`/`/domain:` targets requested, which is itself valuable scoping information (what did the operator actually go after?) |
| bash/zsh (Linux operator box) | `~/.bash_history` / `~/.zsh_history` | Relevant when the operator used Impacket's `secretsdump.py -just-dc` or a similar Linux-native DCSync-equivalent instead of mimikatz itself — same underlying MS-DRSR technique, different tool, same target-side signature (see `04 - Target Evidence.md`) |

## Dropped Binary / Loader Script Artifacts

| Loading method | What's left on the operator's own staging infrastructure |
|---|---|
| Dropped `mimikatz.exe`/`.dll` | Same as `sekurlsa/03 - Source Evidence.md` — the binary itself, wherever staged |
| Reflective load (`Invoke-Mimikatz`, Beacon `execute-assembly`, Meterpreter `kiwi`) | No file — `lsadump::dcsync` runs identically whether mimikatz is on disk or reflectively loaded, since DCSync's evidentiary weight sits almost entirely on the *target* DC's side, not in how the calling code was loaded |
| Non-mimikatz DCSync-capable tooling | Impacket's `secretsdump.py` (`-just-dc`/`-just-dc-ntlm`), PowerShell's `DCSync.ps1`/Empire modules, and DSInternals' `Get-ADReplAccount` all implement the identical `IDL_DRSGetNCChanges` call — a `.py` script, `.ps1` file, or a PowerShell-module installation on the operator's staging box is the equivalent artifact for those toolchains |
| Exported `.csv`/output redirected to a file | If `/csv` output (`02 - Hands-On Use Cases.md`) was redirected to a file rather than left on-console, that file is a durable, high-value artifact on the operator's own box — it contains the actual recovered credential material, not just evidence that an operation occurred |

## Live Process State

```powershell
Get-Process | Where-Object { $_.ProcessName -match 'mimikatz|secretsdump' }
```
Same caveat as `sekurlsa/03 - Source Evidence.md` — a reflectively-loaded instance shows only as its host process (`powershell.exe`, the C2 agent binary), never as `mimikatz.exe` itself.

## Network Evidence

**The single most valuable source-side evidence category for this module — unlike sekurlsa, DCSync's core mechanic *is* a network operation from this host.**

```powershell
# Active/recent outbound connections to a Domain Controller's RPC endpoint mapper and
# whatever dynamic high port it handed back
Get-NetTCPConnection | Where-Object { $_.RemotePort -eq 135 -or ($_.RemotePort -ge 49152 -and $_.RemotePort -le 65535) }
```

| Artifact | Notes |
|---|---|
| `netstat`/`Get-NetTCPConnection` output, or a firewall/EDR connection log, at the time of the operation | Shows the operator's own machine establishing an outbound connection to a DC's TCP/135 (endpoint mapper) followed immediately by a connection to a dynamic high port — this two-step pattern (mapper query, then the actual DRSUAPI session) is characteristic of any `ncacn_ip_tcp` RPC call, not unique to DCSync, but combined with the destination being a DC and the timing matching a known operational window, it's strong corroborating evidence |
| Kerberos ticket cache (`klist`), if the operator authenticated via Kerberos (the default, absent `/authntlm`) | A TGS for a service principal tied to the target DC's computer account will be present in the operator's own ticket cache around the time of the DCSync call — recoverable via `klist` if the operator's own machine is examined live, or from a memory capture otherwise |
| DNS query log/cache for the target domain's `_ldap._tcp.dc._msdcs.<domain>` SRV record | If `/dc:` wasn't explicitly specified, mimikatz performs a DC-locator DNS lookup first — visible in the operator machine's own DNS resolver cache/query log, timestamped just before the RPC connection |
| Operator infrastructure's own web/file-server logs (if a reflective loader was used) | Same as `sekurlsa/03 - Source Evidence.md` — durable, target-independent record on operator-controlled infrastructure |

## OS-Level Audit Trail

If the operator's own pivot/staging box has command-line process-creation auditing enabled (Security 4688 with command-line logging, or Sysmon Event 1):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'mimikatz|lsadump|dcsync|secretsdump' }
```
On a Windows operator box with Sysmon deployed, **Sysmon Event 3 (Network Connection)** for the process that ran mimikatz/`secretsdump.py`, showing the destination IP/port matching a DC, is a stronger and more specific artifact here than it was for sekurlsa — because for DCSync, that network connection *is* the technique, not an incidental side effect of a loader.

## Memory Forensics

- Same dynamic as `sekurlsa/03 - Source Evidence.md` for reflectively-loaded instances: a still-resident DLL in `powershell.exe`/a C2 agent's memory is recoverable only via a live memory capture of that process, never from disk.
- **DCSync-specific:** the recovered credential material (NTLM hashes, Kerberos keys, cleartext trust passwords) exists in the calling process's memory the moment the `IDL_DRSGetNCChanges` reply is parsed — before it's ever printed to console or written to a `/csv` file. A memory capture of the operator's process can recover this even if console output was never logged and no output file was ever written, exactly as `sekurlsa/03 - Source Evidence.md` notes for its own recovered material.

## Timeline Correlation Value

Source-side evidence here is materially more useful for building a provable chain than it was for sekurlsa, precisely because the operation itself crosses the network. A `Get-NetTCPConnection`/firewall-log entry showing the operator's machine connecting to a DC's RPC ports, a Kerberos TGS for that DC in the operator's ticket cache, and a PSReadLine history line naming the target account — matched in time against the **target-side Event 4662 replication-rights signature** documented in `04 - Target Evidence.md` — is what turns "a DCSync-style replication happened somewhere in the domain" into a provable chain tying a specific operator host to a specific DC and a specific set of harvested accounts. This correlation is stronger and easier to establish here than for a local LSASS read, since both ends of the connection generate independent, cross-checkable evidence.
