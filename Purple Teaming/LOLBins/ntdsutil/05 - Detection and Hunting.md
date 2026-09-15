# LOLBins — ntdsutil.exe — Detection and Hunting

## Contents
- [Hunting Priority — Which Signal to Trust Most](#hunting-priority--which-signal-to-trust-most)
- [Hunting on Source](#hunting-on-source)
- [Hunting on Target](#hunting-on-target)
- [Fleet-Wide Sweep](#fleet-wide-sweep)
- [Remediation](#remediation)

---

## Hunting Priority — Which Signal to Trust Most

This tool's evasion surface is unusual for this module: the operator doesn't need a flag to blend in — the **published detection indicators themselves are narrow enough to blend in on their own**. LOLBAS's own listed IOC is *"ntdsutil.exe with command line including 'ifm'"*, and the community Sigma rule (ID `2afafd61-6aae-4df4-baed-139fa1f4c345`, author Thomas Patzke, "Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)") matches on the **process image name alone** — it fires on every `ntdsutil.exe` execution, full stop, with no command-line content check at all. Rank hunts by what actually survives an operator switching to the raw-VSS bypass (`vssadmin` instead of `ntdsutil`, `02`'s evasion use case) or simply not typing the literal word `ifm`:

| Rank | Signal | Survives raw `vssadmin` bypass (never invokes `ntdsutil.exe`)? | Survives avoiding the literal `"ifm"` substring? | Notes |
|---|---|---|---|---|
| 1 (strongest) | Process-tree/context: `ntdsutil.exe` **or** `vssadmin.exe` on a DC, with a parent that isn't a recognized backup service, outside a documented backup window | ✅ Yes — explicitly covers both binaries | ✅ Yes — doesn't depend on command-line content at all | This is `Windows/23 - Special Services/Domain Controller — Role-Specific Forensics.md` Step 7's own flowchart — the load-bearing detection in this whole note, not re-derived here |
| 2 | Sysmon 11 file-create of `ntds.dit` at a non-default path, correlated to the `ntdsutil.exe`/`vssadmin.exe` process | ❌ No, if the operator renames the copied file immediately (MITRE CAR's own "Low" coverage rating for this exact analytic, cited below) | ✅ Yes — filename-based, not command-line-based | Strong corroboration, weak as a sole trigger |
| 3 | Unexpected VSC creation event on a DC outside a backup window | ✅ Yes — both `ifm` and the raw bypass use VSS under the hood | ✅ Yes | The one signal genuinely common to every extraction variant in `02` |
| 4 | Security 4688/Sysmon 1 full command line matching `"ifm"`/`"create full"` | ❌ No — defeated entirely by the raw-VSS bypass | ❌ No — defeated by not typing the word | This is what LOLBAS's and the Sigma rule's published indicators actually check — treat as enrichment only |
| 5 (weakest) | Process image name `ntdsutil.exe` alone (the Sigma rule as published) | ❌ No | N/A — fires on **any** ntdsutil use, including 100% legitimate DC administration | High false-positive rate on its own; the rule's own documented false-positives note is "legitimate NTDS database maintenance activities" |

**Build hunts on ranks 1 and 3 as primary detections — they're the only two that survive the raw-VSS bypass. Treat ranks 2, 4, and 5 as enrichment/corroboration once a rank-1/3 hit already exists, not as standalone triggers.**

## Hunting on Source

Because this tool has no genuine "source" host of its own (`03 - Source Evidence.md`), source-side hunting means hunting the **access vector**, not `ntdsutil` itself:

```bash
# If the access vector was Impacket wmiexec.py/psexec.py — reuse those notes' own
# Hunting on Source sections directly (Impacket/wmiexec/05, Impacket/psexec/05)
grep -iE "wmiexec|psexec|impacket" ~/.bash_history ~/.zsh_history 2>/dev/null
```

```powershell
# If the access vector was PowerShell Remoting from another Windows host,
# check that host's own PSReadLine history for the ntdsutil invocation
Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String 'ntdsutil|ifm|create full'
```

## Hunting on Target

```powershell
# 1. HIGHEST-CONFIDENCE: ntdsutil.exe / vssadmin.exe execution on a DC, context-checked
#    against a documented backup window. Full decision logic (parent process, account
#    context, off-hours timing) lives in Windows/23's Step 7 flowchart — this pulls the
#    raw event set that flowchart is built on.
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 1000 |
  Where-Object { $_.Message -match 'ntdsutil\.exe|vssadmin\.exe' } |
  Select-Object TimeCreated,
    @{n='Account';e={($_.Message -split "`n" | Select-String 'Account Name:').ToString()}},
    @{n='ParentProcess';e={($_.Message -split "`n" | Select-String 'Creator Process Name:').ToString()}},
    @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'Process Command Line:').ToString()}}

# 2. Sysmon equivalent, with full command line and parent image captured natively
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object { $_.Message -match 'ntdsutil\.exe|vssadmin\.exe' } |
  Select-Object TimeCreated, Message

# 3. Sysmon file-create of ntds.dit at a NON-default path — MITRE CAR-2019-08-002's own
#    analytic (rated "Low" coverage: misses a renamed/moved copy, and misses the raw-VSS
#    bypass entirely, so use only as corroboration, never standalone)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11} |
  Where-Object { $_.Message -match 'ntds\.dit' -and $_.Message -notmatch 'Windows\\NTDS\\ntds\.dit' }

# 4. Unexpected Volume Shadow Copy creation on a DC — survives BOTH the ifm-vs-raw-vssadmin
#    variant and the "avoid the word ifm" evasion, since every extraction path in 02 uses VSS
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='VSS'} -MaxEvents 200 |
  Select-Object TimeCreated, Id, Message
vssadmin list shadows

# 5. DSRM persistence variant — registry value + the account-manipulation event around it
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4657} |
  Where-Object { $_.Message -match 'DsrmAdminLogonBehavior' }

# 6. Command-line audit trail for the metadata-cleanup / DSRM-password-reset submenus,
#    if either secondary use case from 02 is suspected
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} |
  Where-Object { $_.Message -match 'metadata cleanup|set dsrm password|reset password on server' }
```

## Fleet-Wide Sweep

```powershell
# Run against every known DC — the fleet-level signal here is a burst of ntdsutil.exe/
# vssadmin.exe execution across multiple DCs in a tight window, matching 02's Multi-DC/
# Forest-Wide Domain-Dominance Sweep scenario, rather than any single host's file artifact
$dcs = (Get-ADDomainController -Filter *).HostName

$results = Invoke-Command -ComputerName $dcs -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 500 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'ntdsutil\.exe|vssadmin\.exe' } |
        Select-Object @{n='DC';e={$env:COMPUTERNAME}}, TimeCreated,
            @{n='CommandLine';e={($_.Message -split "`n" | Select-String 'Process Command Line:').ToString()}}
} -ErrorAction SilentlyContinue

$results | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd HH:mm') } |
  Sort-Object Count -Descending | Select-Object -First 10 Count, Name

$results | Export-Csv -Path .\ntdsutil_sweep_results.csv -NoTypeInformation
```

Cross-link: `Windows/Threat Landscape and Playbooks/Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook.md`'s Quick Triage section runs this exact `4688`/`ntdsutil.exe|vssadmin.exe` check (its "Path B") in parallel with the DCSync-specific `4662` check ("Path A") as the very first move in that playbook — this sweep is that check, scaled to every DC rather than one.

## Remediation

**Capture evidence first** — export the 4688/Sysmon 1 process-creation records, the VSS creation events, and (if the operator's output folder is still present) hash the exported `ntds.dit`/`SYSTEM`/`SAM` files before touching anything. If a confirmed NTDS.dit extraction is in scope, hand off immediately to `Windows/Threat Landscape and Playbooks/Domain Credential Compromise (DCSync and NTDS.dit Theft) Playbook.md` — the response from this point (double `krbtgt` reset, domain-wide password rotation, DSRM password reset on every DC, treating the entire domain as exposed rather than attempting to scope it narrower) is that playbook's job, not re-derived here.

```powershell
# If caught live, remove the operator's exported output (does not undo the theft —
# the data is already presumed exfiltrated the moment ifm/vssadmin completed)
Remove-Item 'C:\path\to\operator\output' -Recurse -Force -ErrorAction SilentlyContinue

# Revert a DSRM persistence backdoor if the registry variant from 02 was used
Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue
# then reset the DSRM password itself — see the playbook's Credential Reset step 3
```

Real hardening — beyond evidence capture:

- **Enable command-line process auditing** (Security 4688 with command-line logging) and, ideally, Sysmon on every DC specifically — this tool's entire detection story depends on process-tree/context, which is unrecoverable after the fact without this logging already enabled.
- **Restrict and monitor who can log on interactively or via WinRM to Domain Controllers** — since `ntdsutil` requires local code execution on the DC, shrinking that population (tiered administration, PAWs/jump-hosts for DC administration) directly shrinks this technique's reachable attack surface, the same lever `Windows/23`'s own hardening guidance and the general lateral-movement notes in this module already emphasize.
- **Establish and document actual backup windows/tooling** for every DC, and alert on any `ntdsutil.exe`/`vssadmin.exe` execution outside them — this is the single highest-leverage control, since it's the one dimension (context, not command syntax) that survives every evasion variant covered in this note.
- **Set `DsrmAdminLogonBehavior` explicitly and monitor for drift** — leaving it at an undocumented/default state on every DC, with no monitoring on the key itself, is what makes the persistence variant viable in the first place.
- **Treat DSRM account passwords as Tier-0 credential material** — rotate them on the same cadence and with the same rigor as `krbtgt` and Domain/Enterprise Admin credentials, not as a one-time promotion-time setting nobody revisits.
