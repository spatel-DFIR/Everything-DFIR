# GPO-Based Mass Deployment Playbook

The scenario this playbook owns: **the lead you're working is the GPO, not the payload.** You've found (or suspect) a malicious or tampered Group Policy Object — not a ransom note, not a pegged-CPU host — and need to work outward from "what does this GPO push, and to how much of the estate" toward full scoping and eradication. [`GPO/05 - GPO Abuse, Hunting and Detection`](<../GPO/05 - GPO Abuse, Hunting and Detection.md>) owns the technique mechanics (T1484.001 walkthrough, payload types, the consolidated detection workflow) and is not re-derived here. The [`Ransomware Playbook`](<Ransomware Playbook.md>) owns the full ransomware IR sequence once an encryptor is confirmed as the payload, with GPO as one of its four deployment-mechanism branches (§4). This note is what you run when the entry point is the *mechanism* itself, and it forks into whichever *payload* turns up — ransomware, a cryptominer, or generic persistence-at-scale.

> 🔴 **The GPO is the delivery truck, not the cargo — don't stop investigating once you've identified what's in the trailer.** A GPO that pushed a cryptominer to 400 workstations used the exact same privilege (Domain Admin, or delegated GPO-edit rights on a broad OU) that could just as easily have pushed a ransomware encryptor. Treat a confirmed GPO-based miner deployment as a near-miss on ransomware, not a lesser incident — the attacker had the access; the payload choice was theirs, not a limitation you can rely on next time.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Identify the Payload](#identify-the-payload)
- [Scope the Deployment](#scope-the-deployment)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Attack Chain

Domain privilege obtained (full Domain Admin, or narrower delegated GPO-edit rights on a specific OU — GPO/00's delegation model, GPO/05's §"the path defenders underestimate") → new GPO created or an existing one edited, populated with a payload (scheduled task, Run-key value via `Registry.pol`, startup/logon script, or Restricted-Groups/`GptTmpl.inf` tampering — GPO/05's Payload Types table) → GPO linked to a broad scope (domain root or a large OU, maximizing blast radius from one edit) → every computer/user object in scope pulls the change at next background refresh or an operator-forced `gpupdate /force` → payload detonates fleet-wide, near-simultaneously → **terminal payload branches here**: a ransomware encryptor (destructive, immediately loud), a cryptominer (quiet, resource-theft, meant to persist undetected), or bare persistence (a foothold for a later, separate objective). The GPO mechanism doesn't care which — that choice is the attacker's, made after they already had the access this whole chain required.

## Quick Triage

No third-party tooling required — native `GroupPolicy`/`ActiveDirectory` modules only. Run this the moment a GPO-abuse lead surfaces, before you know which payload branch you're in.

```powershell
# GPOs created or modified in the last 7 days - the standing triage query for an active incident window
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-7) } |
    Sort-Object ModificationTime -Descending | Select-Object DisplayName, Id, ModificationTime, Owner

# What does the flagged GPO actually push - full settings report before chasing further
Get-GPOReport -Guid <GPOGuid> -ReportType Html -Path .\flagged_gpo_report.html

# Where is it linked - domain-root/broad-OU is the blast-radius red flag
Get-ADObject -Filter "gPLink -like '*<GPOGuid>*'" -Properties gPLink | Select-Object DistinguishedName, gPLink

# On a single affected host right now: top CPU consumers (miner candidate) and any unrecognized
# scheduled task / Run-key value matching what the GPOReport above showed
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, Path
Get-ScheduledTask | Where-Object State -eq Ready | Select-Object TaskName, TaskPath
```

If the GPOReport shows a scheduled task or script whose action is an unrecognized binary or a base64/download-cradle command line, treat that as the payload lead and move to the next section immediately — don't wait for a second signal.

## Identify the Payload

GPO/05's Payload Types table already covers *how* each payload type is delivered (scheduled task, Run key, script, security tampering). What differs by payload is what you check *next*, once you know a GPO pushed something:

### If ransomware

Full identification, encryptor-hash workflow, and IOC extraction are the **Ransomware Playbook's** territory — its §7 (Encryptor Binary Identification) and §5 (Shadow-Copy/Backup Destruction) are the authoritative sequence. The one check specific to *this* playbook's job — confirming GPO as the vector before handing off — is already in GPO/05's Mass-Deployment Ransomware Pattern section: a fleet-wide, near-simultaneous first-execution timestamp cluster (Prefetch/Amcache, note 06) immediately following the flagged GPO's modification time.

```powershell
# Fast confirm: does the GPO-pushed task/script's target binary match the encryptor's name/hash
# already recovered from an affected host (Ransomware Playbook §7)?
Get-GPOReport -Guid <GPOGuid> -ReportType Xml | Select-String -Pattern '<Command>|<Arguments>'
```

If this comes back positive, **stop working this playbook and move to the Ransomware Playbook** — its full response sequence (triage → scope → shadow-copy confirmation → credential reconstruction → eradication) supersedes the generic steps below for a confirmed encryptor.

### If a cryptominer

No dedicated Windows cryptojacking playbook exists in this repo yet (see the Linux equivalent, [`Linux/15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md`](<../../Linux/15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md>), for the same payload on a different OS) — so this section carries the Windows/GPO-specific identification steps directly rather than pointing elsewhere.

```powershell
# Confirm the suspect process: CPU pinned near 100% sustained, path under an unusual/writable location
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 Name, Id, CPU, Path, StartTime

# Known miner binary names / staging paths - not exhaustive, but covers the commodity families seen via GPO drops
Get-Process | Where-Object { $_.ProcessName -match 'xmrig|xmr-stak|nheqminer|ccminer|cpuminer|lolminer' }
Get-Process | Where-Object { $_.Path -match '\\ProgramData\\|\\Public\\|\\Temp\\|\\AppData\\Local\\Temp' } |
    Select-Object ProcessName, Path, Id

# Outbound connections to mining-pool ports (stratum protocol) - the network tell
Get-NetTCPConnection -State Established | Where-Object { $_.RemotePort -in 3333,4444,5555,7777,14444,14433 } |
    Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess

# Command line for a suspect PID - pool address/wallet/donate-level are usually visible in cleartext
Get-CimInstance Win32_Process -Filter "ProcessId=<PID>" | Select-Object CommandLine
```

🔴 A GPO-deployed miner is commonly the payload of a `ScheduledTasks.xml` entry (GPO/05's Payload Types table) whose `<Command>` points at a downloader (`certutil`, `bitsadmin`, `Invoke-WebRequest`) rather than the miner binary directly — check the task's actual command line via the GPOReport pull above, not just the process you can see running now, since the GPO itself may stage a fetch-and-execute rather than embedding the binary.

**Key evidence artifact to check first:** the GPOReport's `<ScheduledTasks>` or Run-key XML for a download-cradle or unrecognized binary path, corroborated by sustained near-100% CPU and a stratum-port connection on affected hosts.

**What a positive finding looks like in practice:** a GPO-pushed scheduled task running as SYSTEM on a broad OU, its command line resolving to a miner binary (or a downloader for one) staged under `%ProgramData%`, `%Public%`, or a temp path, with multiple affected hosts showing the same process pinned near 100% CPU and an outbound connection to the same mining-pool IP/domain.

### If generic persistence (no destructive or resource-theft payload yet)

A Run-key value or scheduled task pushed fleet-wide with no immediately obvious malicious action is persistence-at-scale in its own right (GPO/05's framing) — don't dismiss it as a false positive just because nothing is visibly "happening" yet. Cross-reference the pushed binary/script against [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>) for the specific mechanism, and treat the standing access (Domain Admin or the delegated GPO-edit rights that enabled this) as the real finding — the payload may simply not have detonated yet.

## Scope the Deployment

```powershell
# Full link scope for the flagged GPO - every OU/domain-root object it applies to
(Get-ADObject -Filter "gPLink -like '*<GPOGuid>*'" -Properties gPLink, distinguishedName).DistinguishedName

# Resolve that scope down to an actual computer list to hunt/triage against
$scopeOUs = (Get-ADObject -Filter "gPLink -like '*<GPOGuid>*'").DistinguishedName
$scopeOUs | ForEach-Object { Get-ADComputer -SearchBase $_ -Filter * } | Select-Object Name, DistinguishedName |
    Export-Csv C:\hunt\affected_hosts.csv -NoTypeInformation

# Security-filtering check - is the GPO scoped further by group membership, not just OU link?
Get-GPPermissions -Guid <GPOGuid> -All
```

A GPO linked at the domain root or a large parent OU, with no security-filtering narrowing it further, is the maximum-blast-radius case — assume every computer object under that scope received the payload at its next refresh until `gpresult` evidence (GPO/04) says otherwise for a given host.

## Timeline

```powershell
# GPO creation/modification time, GPT.INI SYSVOL version, and GPC AD-object version in one pull -
# desync between the two is the raw-SYSVOL-edit tell (GPO/01)
$gpo = Get-GPO -Guid <GPOGuid>
$gptVersion = (Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\GPT.INI" |
    Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
[PSCustomObject]@{ Name = $gpo.DisplayName; Created = $gpo.CreationTime; Modified = $gpo.ModificationTime; GPC_Version = $gpo.Computer.DsVersion; GPT_Version = $gptVersion }

# Attribute-level provenance - which DC, which attribute, exact write time (GPO/03, 05b)
repadmin /showobjmeta <DC_FQDN> "CN={<GPOGuid>},CN=Policies,CN=System,DC=<domain>,DC=com"
```

Bracket the incident window as: GPO creation/modification timestamp → SYSVOL script/task file write time → first fleet-wide execution timestamp cluster (Prefetch/Amcache per note 06, or the process-start evidence gathered in Identify the Payload above). A tight cluster of first-execution times across many hosts, immediately after the GPO's modification time, is the mass-deployment signature — a wide spread suggests staggered manual deployment instead (Ransomware Playbook §4's PsExec/WMI/scheduled-task alternatives), which changes what else you should be looking for.

## Eradication

Disable-before-delete, per note 21's containment discipline — capture evidence before removing anything.

```powershell
# 1. Disable the malicious GPO's link first - reversible, preserves the GPO object and its evidentiary value
Set-GPLink -Name '<Malicious-GPO-Name>' -Target '<Scope-DN-from-above>' -LinkEnabled No

# 2. Once evidence is captured (GPOReport already pulled, SYSVOL folder copied for evidence) and disabling
#    is confirmed sufficient, remove the GPO entirely
Remove-GPO -Name '<Malicious-GPO-Name>'

# 3. Force every affected host to re-pull policy immediately, rather than waiting on the background refresh interval
Get-Content C:\hunt\affected_hosts.csv | ForEach-Object { Invoke-GPUpdate -Computer $_ -Force -RandomDelayInMinutes 0 }

# 4. Kill the live payload process on each affected host and remove the dropped binary/staged files
Invoke-Command -ComputerName (Get-Content C:\hunt\affected_hosts.csv) -ScriptBlock {
    Get-Process -Name '<miner_or_payload_name>' -ErrorAction SilentlyContinue | Stop-Process -Force
    Remove-Item '<staged_binary_path>' -Force -ErrorAction SilentlyContinue
}

# 5. Confirm the fleet actually landed on the restored baseline - verification, not assumption
Invoke-Command -ComputerName (Get-Content C:\hunt\affected_hosts.csv) -ScriptBlock { gpresult /r /scope:computer }
```

If the payload branch was ransomware, stop here and hand off fully to the Ransomware Playbook's own eradication/recovery sequence — this playbook's eradication steps are sufficient for the miner/persistence branches but are not a substitute for that playbook's shadow-copy and recovery workflow.

## Credential Reset

The privilege that enabled this — full Domain Admin, or the delegated GPO-edit rights on the affected OU — is itself compromised and must be addressed, not just the payload:

```powershell
# Identify who/what actually made the change, from the provenance pulled in Timeline above,
# and force a credential reset on that account
Set-ADAccountPassword -Identity '<compromised_admin_or_delegated_account>' -Reset

# If GPP cpassword was the entry point or was found alongside this GPO (GPO/02, GPO/05's hunting workflow),
# rotate every account it exposed - treat as compromised regardless of proven active abuse
Invoke-Command -ComputerName (Get-Content C:\hunt\affected_hosts.csv) -ScriptBlock {
    Set-LocalUser -Name '<ExposedAccountName>' -Password (ConvertTo-SecureString '<NewComplexPassword>' -AsPlainText -Force)
}
```

Also review the delegation itself: if the access path was delegated GPO-edit rights rather than full Domain Admin, that delegation is the standing exposure — narrow or revoke it, don't just reset the compromised account's password and leave the same over-broad delegation in place for the next attacker to reuse (GPO/05's delegation red flag).

## Fleet Hunt

Scope IOCs across the estate, independent of the OU the flagged GPO was linked to — a Domain Admin-level compromise may have touched more than one GPO.

```powershell
# Any other GPO modified in the same window by the same account
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-14) } | ForEach-Object {
    [PSCustomObject]@{ Name = $_.DisplayName; Modified = $_.ModificationTime; Owner = $_.Owner }
} | Where-Object Owner -eq '<compromised_account>'

# Fleet-wide sweep for the same miner process/pool IOC or payload binary hash, beyond the confirmed scope
Invoke-Command -ComputerName (Get-Content C:\hunt\all_hosts.csv) -ScriptBlock {
    Get-Process | Where-Object { $_.ProcessName -eq '<payload_name>' }
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object RemotePort -eq <pool_port>
}

# GPP cpassword standing sweep - independent check, doesn't require this incident to justify running it
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -ErrorAction SilentlyContinue -Include Groups.xml,Drives.xml,Services.xml,ScheduledTasks.xml,Printers.xml,DataSources.xml |
    Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Matches.Value -ne 'cpassword=""' }
```

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full T1484.001 technique walkthrough, payload types, consolidated detection workflow, cpassword hunting mechanics | [`GPO/05 - GPO Abuse, Hunting and Detection`](<../GPO/05 - GPO Abuse, Hunting and Detection.md>) |
| GPT/GPC duality, LSDOU/inheritance, delegated GPO-edit rights model | [`GPO/00 - GPO Fundamentals and Architecture`](<../GPO/00 - GPO Fundamentals and Architecture.md>) |
| GPT.INI/GPC version-desync mechanics, SYSVOL replication | [`GPO/01 - Storage, Replication and Version Synchronization`](<../GPO/01 - Storage, Replication and Version Synchronization.md>) |
| `Registry.pol`, GPP XML family, cpassword/MS14-025 flaw, `GptTmpl.inf`/Restricted Groups | [`GPO/02 - GPO Content Deep Dive`](<../GPO/02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |
| DC-side enumeration, event 5136, `repadmin /showobjmeta`, GPO backup/restore | [`GPO/03 - Domain Controller GPO Investigation`](<../GPO/03 - Domain Controller GPO Investigation.md>) |
| `gpresult`/RSOP, local GPO cache, GroupPolicy operational log | [`GPO/04 - Domain-Joined Host GPO Investigation`](<../GPO/04 - Domain-Joined Host GPO Investigation.md>) |
| Full ransomware IR sequence once an encryptor is the confirmed payload | [`Ransomware Playbook`](<Ransomware Playbook.md>) |
| The same cryptomining payload/behavior on Linux hosts | [`Linux/15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md`](<../../Linux/15 - Threat Landscape and Playbooks/Cryptojacking Playbook.md>) |
| Prefetch/Amcache/ShimCache execution-evidence mechanics for timestamp clustering | [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) |
| Scheduled task and Run-key persistence-artifact mechanics once landed on a host | [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>) |
| Manual PsExec/WMI/scheduled-task loop as the slower, per-host alternative to GPO-based deployment | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) |
| Disable-before-delete containment discipline | [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>) |
| Fleet-wide baselining and post-fix return-to-known-good-state | [`22 - Enterprise Management and Baseline`](<../22 - Enterprise Management and Baseline.md>) |

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| Unexpected new GPO, or modification of an existing GPO, in or before the incident window | The core lead this playbook is built around — pull its GPOReport immediately |
| GPO linked at domain root or a broad OU with no security-filtering narrowing it | Maximum blast radius from one edit — assume estate-wide reach until proven otherwise |
| GPT.INI/GPC version desync | Raw SYSVOL file edit bypassing normal GPO-editing tooling |
| Scheduled task/Run-key/script pushed via the GPO resolving to an unrecognized binary or download cradle | The payload-delivery signature — identify which branch (ransomware/miner/persistence) before proceeding |
| Sustained near-100% CPU on multiple hosts with an outbound stratum-port connection | Cryptominer branch — commodity resource-theft, quiet by design |
| Fleet-wide, near-simultaneous file-encryption or mass-rename activity | Ransomware branch — hand off to the Ransomware Playbook immediately |
| Tight fleet-wide first-execution timestamp cluster (Prefetch/Amcache) right after the GPO's modification time | Confirms mass, near-simultaneous detonation rather than a staggered manual push |
| Delegated GPO-edit rights broadly granted on an OU with no documented justification | The narrower, easier-to-obtain privilege path — a standing exposure independent of this incident |
| `cpassword` present in any GPP XML in SYSVOL | Decryptable credential exposure — treat as compromised regardless of proven active abuse |
| Same account modified multiple unrelated GPOs in the same window | Domain-Admin-level compromise, not a single scoped delegation abuse |

## Resources

- MITRE ATT&CK **T1484.001** (Domain Policy Modification: Group Policy Modification) — https://attack.mitre.org/techniques/T1484/001/
- MITRE ATT&CK **T1496** (Resource Hijacking) — https://attack.mitre.org/techniques/T1496/
- MITRE ATT&CK **T1486** (Data Encrypted for Impact) — https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK **T1053.005** (Scheduled Task/Job: Scheduled Task) — https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK **T1547.001** (Boot or Logon Autostart Execution: Registry Run Keys) — https://attack.mitre.org/techniques/T1547/001/
