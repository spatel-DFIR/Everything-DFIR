# GPO Abuse, Hunting and Detection

This is the capstone note for the `GPO/` folder — it does not re-derive artifact mechanics that the four notes before it already own. **[`00 - GPO Fundamentals and Architecture`](<00 - GPO Fundamentals and Architecture.md>)** owns the conceptual model (GPT/GPC duality, LSDOU/inheritance, local vs domain GPO, refresh mechanics); **[`01 - Storage, Replication and Version Synchronization`](<01 - Storage, Replication and Version Synchronization.md>)** owns SYSVOL/GPT structure and FRS/DFSR replication; **[`02 - GPO Content Deep Dive`](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>)** owns `Registry.pol`, GPP file internals, and the cpassword flaw's mechanics; **[`03 - Domain Controller GPO Investigation`](<03 - Domain Controller GPO Investigation.md>)** owns the DC-side enumeration/`gpLink`/event-5136/`repadmin` workflow; **[`04 - Domain-Joined Host GPO Investigation`](<04 - Domain-Joined Host GPO Investigation.md>)** owns `gpresult`/RSOP and local-cache mechanics. This note's job is different: it tells the attack-technique story end to end, and it sequences those four notes' mechanics into a single hunt an analyst can actually run start to finish.

Group Policy's forensic value and its danger come from the same property — a single edit fans out to every computer and user object in its linked scope. That makes T1484.001 (Group Policy Modification) one of the highest-leverage techniques available to an attacker who has reached the right level of domain privilege, and it is the reason a ransomware crew that has escalated to Domain Admin reaches for a new GPO rather than a host-by-host PsExec loop. Everything below — the technique walkthrough, the payload types, the mass-deployment pattern, the consolidated detection sequence, and the cpassword hunting workflow — builds toward one outcome: an analyst who suspects GPO abuse can open this note and work the case top to bottom without guessing which sibling note to open next.

> 🔴 **Group Policy is simultaneously the defender's baseline-enforcement tool and the attacker's highest-leverage mass-deployment weapon — and it is the same mechanism in both cases, just pointed the other way.** An attacker holding Domain Admin, or merely delegated GPO-edit rights on the right OU, can push a malicious scheduled task, Run-key value, or logon script to every computer in that scope with a single edit. Mass-deploying a ransomware encryptor via a freshly created domain-linked GPO is a well-documented, real-world deployment pattern, not a theoretical risk. Treat unexpected GPO creation or modification with the same urgency as a new Domain Admin account.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [T1484.001 — The Full Technique Walkthrough](#t1484001--the-full-technique-walkthrough)
- [Payload Types — What Gets Deployed and How](#payload-types--what-gets-deployed-and-how)
- [The Mass-Deployment Ransomware Pattern](#the-mass-deployment-ransomware-pattern)
- [Consolidated Detection Workflow — End to End](#consolidated-detection-workflow--end-to-end)
- [GPP cpassword Hunting Workflow](#gpp-cpassword-hunting-workflow)
- [PowerShell](#powershell)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [MITRE ATT&CK Techniques Covered](#mitre-attck-techniques-covered)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

This is the most comprehensive Hunt Evil block in the `GPO/` folder — several of these one-liners deliberately cross into a sibling note's territory (recent-modification triage is GPO/03's, scope resolution is GPO/03's, effective-policy comparison is GPO/04's) because a real hunt runs all of them together, not one at a time. No third-party tooling required; native `GroupPolicy`/`ActiveDirectory` modules only.

```powershell
# GPOs modified in the last 7 days, sorted newest-first - the standing triage query for an active incident window (GPO/03's territory)
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-7) } |
    Sort-Object ModificationTime -Descending | Select-Object DisplayName, Id, ModificationTime, Owner

# GPT.INI (SYSVOL) vs GPC (AD object) version desync across every GPO - a raw file edit that bypassed normal tooling (GPO/01's territory)
Get-GPO -All | ForEach-Object {
    $gptVersion = (Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($_.Id)}\GPT.INI" -ErrorAction SilentlyContinue |
        Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
    [PSCustomObject]@{ Name = $_.DisplayName; GPC_Version = $_.Computer.DsVersion; GPT_Version = $gptVersion }
}

# Where a specific GPO is actually linked - domain-root/broad-OU scope is the blast-radius red flag (GPO/03's territory)
Get-ADObject -Filter "gPLink -like '*<GPOGuid>*'" -Properties gPLink | Select-Object DistinguishedName, gPLink

# Effective policy across a batch of hosts in one pass - estate-wide gpresult without touching each box by hand (GPO/04's territory)
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock { gpresult /r /scope:computer }

# Fleet-wide sweep of every GPO's GPP XML for a live cpassword attribute - this note's own hunting workflow (mechanics owned by GPO/02)
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -ErrorAction SilentlyContinue -Include Groups.xml,Drives.xml,Services.xml,ScheduledTasks.xml,Printers.xml,DataSources.xml |
    Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Matches.Value -ne 'cpassword=""' } | Select-Object Path, LineNumber

# The consolidated pipeline: recently modified GPOs, their actual link scope, AND cpassword presence, in one pass -
# this is what makes this note's Hunt Evil block different from any single sibling note's
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-14) } | ForEach-Object {
    $gpo = $_
    $scope = (Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink).DistinguishedName -join '; '
    $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}"
    $cpass = Get-ChildItem $gpoPath -Recurse -ErrorAction SilentlyContinue -Include Groups.xml,Drives.xml,Services.xml,ScheduledTasks.xml |
        Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Matches.Value -ne 'cpassword=""' }
    [PSCustomObject]@{ Name = $gpo.DisplayName; Modified = $gpo.ModificationTime; LinkedTo = $scope; CpasswordHit = [bool]$cpass }
}

# GroupPolicy operational log entries across a batch of hosts - who processed what and whether it failed (GPO/04's territory)
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 50
}
```

## T1484.001 — The Full Technique Walkthrough

Because a GPO's effect fans out to every computer/user object in its linked scope, a single malicious GPO creation or edit is one of the highest-leverage techniques available to an attacker who has reached the right level of domain privilege. There are two distinct paths to that privilege, and the second is the one defenders consistently underestimate:

1. **Full Domain Admin** — the obvious path. An attacker who has already escalated this far can create, edit, or delete any GPO in the domain.
2. **Delegated GPO-edit rights on a specific OU** — a narrower, meaningfully easier-to-obtain permission that is **frequently over-granted in real environments**. An IT team delegating "manage GPOs for the Sales OU" to a junior admin or a helpdesk group, without narrowing that delegation further, hands out exactly the privilege this whole technique needs — scoped to one OU, but that OU can still contain hundreds of machines. Flag broad, undocumented GPO-edit delegation the same way you'd flag an over-privileged service account: as a standing exposure, not just a post-incident finding.

Once either privilege level is held, the mechanics of *how* the GPO is created, linked, and populated are GPO/00's territory (LSDOU, inheritance, security filtering) and GPO/02's territory (what actually lands in `Registry.pol`/GPP/scripts) — not re-derived here. What this note owns is the attacker's *decision*: a single GPO edit, applied once, is functionally equivalent to manually touching every computer in scope — and it does so without needing valid credentials on each target host, without triggering per-host lateral-movement telemetry (note 12), and with a blast radius the attacker controls directly via link placement.

## Payload Types — What Gets Deployed and How

Four payload types account for nearly all documented GPO-abuse cases. Each is a legitimate GPO capability turned against the environment — the mechanics of each file/format are owned by the cross-linked notes, not repeated here.

| Payload type | Mechanism | Where the mechanics live |
|---|---|---|
| **Scheduled task** | Deployed via GPO Preferences — a `ScheduledTasks.xml` entry under the GPO's SYSVOL folder, runs on every targeted computer at its configured trigger | `ScheduledTasks.xml` structure — [GPO/02](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>); once landed on a host, task-artifact mechanics — [`10 - Persistence Mechanisms/Scheduled Tasks.md`](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |
| **Run-key registry value** | Pushed via `Registry.pol`, lands as an ordinary autostart entry on every targeted computer at next refresh | `Registry.pol` binary format — [GPO/02](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>); Run-key artifact mechanics once landed — [`10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md`](<../10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md>) |
| **Startup/logon script** | Placed under `Machine\Scripts\Startup\` or `User\Scripts\Logon\` in the GPO's SYSVOL folder, executes on every boot or logon within scope | Script placement and CSE processing — [GPO/02](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |
| **Security-settings tampering** | Restricted Groups / `GptTmpl.inf` — adding an account to local Administrators fleet-wide, weakening audit or password policy domain-wide | `GptTmpl.inf`/Restricted Groups/SecEdit mechanics — [GPO/02](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |

Any one of these, pushed via a single GPO edit, reaches the entire linked scope at the next refresh (background interval or `gpupdate /force`) — see GPO/00 for refresh timing.

## The Mass-Deployment Ransomware Pattern

This is a well-documented, real-world ransomware-deployment pattern, not a theoretical risk. Rather than manually pushing an encryptor to each host via PsExec or WMI (see [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) for that slower, per-host alternative), an attacker who has escalated to Domain Admin — or obtained the delegated GPO-edit rights described above — creates a new domain-linked GPO that deploys the payload, via a scheduled task or logon script, to every reachable computer in a single action. The result is near-simultaneous mass detonation across the estate, rather than a staggered host-by-host rollout that gives defenders time to react between hosts.

The same mechanism works equally well short of a destructive payload — a Run key or scheduled task pushed everywhere at once is persistence-at-scale, not just a ransomware precursor. But ransomware is where this pattern is most consequential and most documented: **[`Threat Landscape and Playbooks/Ransomware Playbook.md`](<../Threat Landscape and Playbooks/Ransomware Playbook.md>)** already treats GPO-based deployment as one of four primary mass-deployment mechanisms (alongside PsExec/`sc create`, WMI, and scheduled-task loops) in its own §4, with a practical investigation sequence for confirming it. This note and that playbook describe the same attack pattern from two angles — this note is the GPO-technique deep dive; the Ransomware Playbook is the full incident-response sequence (triage → scope determination → deployment-mechanism investigation → shadow-copy confirmation → credential/lateral-movement reconstruction → remediation) that this technique feeds into as one of its four deployment-mechanism branches. If you are actively working a ransomware incident, that playbook is the sequencing document; this note is what you open when its §4 GPO-Based Deployment section tells you to dig into the GPO angle specifically.

## Consolidated Detection Workflow — End to End

This is the unique value of this note — the full chain a hunter actually follows, in order, citing which sibling note owns each step's mechanics. No step below re-derives artifact detail; each one sequences and cross-links.

```
1. Unexpected new GPO creation, or modification of an existing GPO,
   in or before the suspected incident window
        │   → GPO/03 (DC-side enumeration: Get-GPO -All by ModificationTime)
        ▼
2. GPT (SYSVOL) / GPC (AD object) version desynchronization check
        │   → GPO/01 (GPT.INI vs GPC versionNumber)
        ▼
3. Event 5136 ("a directory service object was modified"),
   if Advanced Auditing / directory-service-changes auditing is enabled
        │   → GPO/03
        ▼
4. repadmin /showobjmeta - attribute-level provenance: which
   attribute changed, the originating DC, the exact timestamp
        │   → GPO/03 / 05b
        ▼
5. gpLink scope check - is this GPO applying to an unusually
   broad or unexpected scope (domain root instead of a narrow OU)?
        │   → GPO/03
        ▼
6. Effective-policy divergence check - does gpresult on an
   affected endpoint disagree with the GPO's current state in AD?
        │   → GPO/04
        ▼
7. GPP cpassword sweep - fleet-wide SYSVOL search for exposed
   credentials, independent of whether this GPO is the flagged one
        │   → GPO/02 (mechanics) + this note's hunting workflow below
```

Walking this in order matters: step 1 narrows a domain's worth of GPOs down to a handful worth chasing; steps 2-4 establish *whether and how* a flagged GPO was actually tampered with, from the AD/DC side; step 5 establishes *how much damage* it could do based on scope; step 6 confirms whether any endpoint actually *received* the tampered state (a GPO can be reverted in AD before every endpoint refreshes, leaving residue only `gpresult` will show); step 7 is a standing, independent check that should run regardless of whether anything else in this sequence flagged — cpassword exposure doesn't require an active incident to be a finding.

Not every investigation needs all seven steps — a hunt triggered by a single suspicious `gpresult` finding on one endpoint (step 6) naturally works backward through steps 5→1, while a hunt triggered by a SIEM alert on event 5136 (step 3) works forward through steps 4-7. The sequence above is the full chain; where you enter it depends on which lead you start with.

## GPP cpassword Hunting Workflow

Group Policy Preferences' legacy `cpassword` flaw — the AES key used to "encrypt" the credential was published by Microsoft itself, so any authenticated user who can read SYSVOL (everyone, by default) can decrypt it — is covered for its mechanics in [GPO/02](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) and its Red Flags entry in [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md#the-gpp-cpassword-vulnerability-legacy>). What follows here is the **hunting activity itself** — the fleet-wide workflow to actually find and remediate exposed credentials, since that's an investigative action, not an artifact-format explanation.

1. **Sweep every GPO's SYSVOL folder for a live `cpassword` attribute** across the five GPP XML files that carry one: `Groups.xml`, `Drives.xml`, `ScheduledTasks.xml`, `Services.xml`, `DataSources.xml` (add `Printers.xml` for completeness — some tooling includes it). An empty `cpassword=""` is not a hit; only a populated value is.
2. **Decode any hit found.** Don't hand-roll the AES decryption — the published key is well-known and already implemented in **`Get-GPPPassword`** (PowerSploit) and the Metasploit **`smb_enum_gpp`** module (see Tooling below). Either tool turns a raw `cpassword` value into the plaintext credential in one step.
3. **Identify what account the credential belongs to** — GPP entries typically create or modify a **local** account (Groups.xml is the most common carrier), so the same username/password pair may be valid across every host the GPO was linked to, not just one.
4. **Treat the credential as compromised the moment it's found, regardless of whether you can prove active abuse.** MS14-025 (2014) stops GPMC from letting an admin *create new* GPP entries containing a `cpassword`, but does **not** retroactively strip existing ones — a hit found today could be a decade old and still valid on every host it was ever pushed to.
5. **Rotate the credential fleet-wide**, and **remove or replace the GPP entry itself** — deleting the XML attribute without also rotating the password leaves the same compromised credential live under a different discovery mechanism.

## PowerShell

Pull the GPO list sorted by modification and a full settings report for one flagged GPO, confirming exactly what it pushes before chasing further:

```powershell
Get-GPO -All -Domain $env:USERDNSDOMAIN | Sort-Object ModificationTime -Descending |
    Select-Object DisplayName, Id, GpoStatus, ModificationTime, Owner | Select-Object -First 25

Get-GPOReport -Guid <GPOGuid> -ReportType Html -Path .\flagged_gpo_report.html
```

Run the consolidated pipeline this note is built to provide: recently modified GPOs, their actual link scope, AND whether any of their GPP XML carries a live `cpassword`, in a single pass:

```powershell
$recent = Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date).AddDays(-14) }
foreach ($gpo in $recent) {
    $links = (Get-ADObject -Filter "gPLink -like '*$($gpo.Id)*'" -Properties gPLink).DistinguishedName
    $gpoPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}"
    $cpass = Get-ChildItem $gpoPath -Recurse -ErrorAction SilentlyContinue -Include Groups.xml,Drives.xml,Services.xml,ScheduledTasks.xml,Printers.xml,DataSources.xml |
        Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Matches.Value -ne 'cpassword=""' }
    [PSCustomObject]@{
        Name                        = $gpo.DisplayName
        ModifiedOn                  = $gpo.ModificationTime
        LinkedTo                    = ($links -join '; ')
        LinkedAtDomainRootOrBroadOU = [bool]($links | Where-Object { $_ -notmatch 'OU=' -and $_ -match ',DC=' })
        CpasswordFound              = [bool]$cpass
    }
}
```

Cross-reference DC-side GPO state (GPO/03's territory) against a batch of endpoints' actual last-applied state (GPO/04's territory) — the estate-wide version of the `gpresult`-vs-AD divergence check that step 6 of the detection workflow above names:

```powershell
$hosts = Get-Content C:\hunt\hosts.txt
$currentGpos = Get-GPO -All | Select-Object DisplayName, Id, ModificationTime
Invoke-Command -ComputerName $hosts -ScriptBlock { gpresult /r /scope:computer } |
    Select-Object PSComputerName, ToString
# Diff each host's "Applied Group Policy Objects" list/version against $currentGpos - a host still showing
# a GPO version older than the current AD-side ModificationTime has a stale or divergent cache (GPO/04)
```

Remove a confirmed-malicious GPO's influence, rotate exposed cpassword credentials, and force the fleet back to compliant state. Capture evidence (GPO/03's export/backup workflow, this note's cpassword-hit list) before touching anything, per note 21's disable-before-delete principle:

```powershell
# 1. Disable the malicious GPO's link first - reversible, does not destroy the GPO object or its evidentiary value
Set-GPLink -Name '<Malicious-GPO-Name>' -Target 'OU=Workstations,DC=corp,DC=example,DC=com' -LinkEnabled No

# 2. Once evidence is captured and disabling is confirmed sufficient, remove the GPO entirely
Remove-GPO -Name '<Malicious-GPO-Name>'

# 3. Force every affected host to re-pull policy immediately, rather than waiting on the background refresh interval
Get-Content C:\hunt\affected_hosts.txt | ForEach-Object { Invoke-GPUpdate -Computer $_ -Force -RandomDelayInMinutes 0 }

# 4. Rotate every local account exposed via a confirmed GPP cpassword hit - the credential is compromised
# regardless of proven active abuse (per the cpassword hunting workflow above)
Invoke-Command -ComputerName $hosts -ScriptBlock {
    $newPass = ConvertTo-SecureString '<NewComplexPassword>' -AsPlainText -Force
    Set-LocalUser -Name '<ExposedAccountName>' -Password $newPass
}

# 5. Confirm the fleet actually landed on the restored baseline - verification, not assumption
Invoke-Command -ComputerName $hosts -ScriptBlock { gpresult /r /scope:computer }
```

For a host that needs to be returned to its full documented baseline (not just this one GPO's remediation), see [`22 - Enterprise Management and Baseline`](<../22 - Enterprise Management and Baseline.md>)'s baseline-restoration workflow; for general containment sequencing (isolate, disable-and-document, verify), see [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>).

## Red Flags

The most complete Red Flags table in the `GPO/` folder — aggregating the technique-specific findings this note owns alongside the ones scattered across its four sibling notes, each cross-linked rather than re-derived.

| 🔴 Finding | Why it matters | Where the mechanics live |
|---|---|---|
| Unexpected new GPO creation, or modification of an existing GPO, in or before a suspected incident window | The mass-deployment abuse pattern this note is built around — check what the GPO pushes and to what scope immediately | GPO/03 |
| GPT (`GPT.INI`) version and GPC (AD object) version desynchronized | A raw SYSVOL file edit that bypassed normal GPO-editing tooling can change policy content while leaving the AD object's version looking unchanged | GPO/01 |
| A GPO applying to an unusually broad or unexpected scope (e.g., linked at the domain root when it should be OU-scoped) | Maximizes an attacker's blast radius from one edit — also worth checking as a legitimate misconfiguration absent an incident | GPO/03 |
| `gpresult`-shown effective policy inconsistent with what the GPO object in AD currently specifies | Either a stale local cache, or the residue of a since-reverted attacker modification the endpoint picked up before rollback | GPO/04 |
| Event 5136 for a GPO object/`gpLink`/version attribute, with no matching change-management record | Directory-service-level confirmation of tampering — requires Advanced Auditing to be enabled | GPO/03 |
| `repadmin /showobjmeta` shows a GPO attribute's last write from an unexpected DC or a time inconsistent with the incident narrative | Corroborates or contradicts a claimed timeline for when/by whom a GPO was actually modified | GPO/03, 05b |
| `cpassword` attribute present in any GPP XML file anywhere in SYSVOL | Decryptable, clear-text-equivalent credential; MS14-025 gap — treat as compromised regardless of proven active abuse | GPO/02, this note |
| Delegated GPO-edit rights granted broadly on an OU with no documented business justification | The narrower, easier-to-obtain privilege path to this entire attack chain — frequently over-granted and under-audited | GPO/00 |
| A scheduled task, Run-key value, or logon/startup script pushed via a newly created or modified GPO, running as SYSTEM or a high-privilege account, deployed to a broad OU | The payload-delivery signature itself — see Payload Types above | This note |
| Fleet-wide, near-simultaneous first-execution timestamp cluster (Prefetch/Amcache) for an unrecognized binary immediately following a GPO modification | The mass-deployment ransomware detonation pattern | This note, Ransomware Playbook |
| A host's local GPO cache reflecting a setting/script that the current AD-side GPO no longer contains | Residue of a since-reverted attacker change the endpoint picked up before rollback | GPO/04 |
| A host's Autoruns/persistence-mechanism inventory deviating from the established fleet baseline with no legitimate change-management explanation | The anomaly-based-hunting signal a GPO-pushed persistence mechanism ultimately produces on each endpoint | 22 |

## Tooling

| Tool | Use |
|---|---|
| **`Get-GPPPassword`** (PowerSploit) | Automates finding and decrypting `cpassword` values from GPP XML across SYSVOL — the standard tool for the cpassword hunting workflow above |
| **Metasploit `smb_enum_gpp` module** | Equivalent automated cpassword discovery/decryption — common in both offensive tooling and red-team-informed defensive hunts |
| **Group Policy Management Console (`gpmc.msc`)** | Standard GUI for GPO administration and investigation — browsing links, scope, settings, version history, backup/restore |
| **`GroupPolicy` PowerShell module** | Native `Get-GPO`/`Get-GPOReport`/`Set-GPLink`/`Remove-GPO`/`Invoke-GPUpdate` — this note's primary native toolset throughout |
| **`ActiveDirectory` PowerShell module** | `gpLink`/`gPCFileSysPath` resolution, `Get-ADReplicationAttributeMetadata` (GPO/03, 05b) |
| **`repadmin`** | Attribute-level replication provenance for a GPO's AD object (GPO/03, 05b) |
| **Autoruns / `autorunsc.exe`** (Sysinternals) | Persistence-mechanism fleet baselining — confirms whether a GPO-pushed Run key or scheduled task shows up as an outlier against a known-good baseline (22) |

## MITRE ATT&CK Techniques Covered

| Technique | ID | Where it shows up |
|---|---|---|
| Domain Policy Modification: Group Policy Modification | T1484.001 | Primary technique — full walkthrough, payload types, ransomware pattern, and the consolidated detection workflow all live in this note; config/mechanics owned by GPO/00-02 |
| Scheduled Task/Job: Scheduled Task | T1053.005 | Secondary — the GPP-scheduled-task payload delivery mechanism (Payload Types above); full task-artifact mechanics owned by `10 - Persistence Mechanisms/Scheduled Tasks.md` |
| Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | Secondary — the `Registry.pol`-pushed Run-key payload (Payload Types above); full Run-key mechanics owned by `10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md` |
| Unsecured Credentials: Group Policy Preferences | T1552.006 | The GPP cpassword hunting workflow (this note); flaw mechanics owned by GPO/02 |
| Data Encrypted for Impact | T1486 | Referenced — the mass-deployment ransomware pattern's terminal stage; full incident-response sequence owned by the Ransomware Playbook |

## Correlate With

| To go deeper on… | Open |
|---|---|
| GPT/GPC two-halves model, local vs domain GPO, LSDOU/inheritance, refresh mechanics, delegated GPO-edit rights model | [`GPO/00 - GPO Fundamentals and Architecture`](<00 - GPO Fundamentals and Architecture.md>) |
| Full SYSVOL/GPT folder tree, GPC AD-object attributes, FRS/DFSR replication mechanics, GPT/GPC version-desync detail | [`GPO/01 - Storage, Replication and Version Synchronization`](<01 - Storage, Replication and Version Synchronization.md>) |
| `Registry.pol` binary format, Client-Side Extensions, GPP file family + cpassword/MS14-025 flaw mechanics, `GptTmpl.inf`/Restricted Groups, ADMX/ADML | [`GPO/02 - GPO Content Deep Dive`](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |
| DC-side enumeration workflow, `gpLink` resolution, event 5136 full detail, `repadmin /showobjmeta`, GPO backup/restore | [`GPO/03 - Domain Controller GPO Investigation`](<03 - Domain Controller GPO Investigation.md>) |
| `gpresult`/RSOP mechanics, local GPO cache artifacts, `Microsoft-Windows-GroupPolicy/Operational` event table, staleness detection | [`GPO/04 - Domain-Joined Host GPO Investigation`](<04 - Domain-Joined Host GPO Investigation.md>) |
| AD replication metadata corroboration, Kerberos/DCSync context for the domain compromise that often precedes this abuse | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md>) |
| The full ransomware incident-response sequence this technique feeds into, mass-deployment scoping | [`Threat Landscape and Playbooks/Ransomware Playbook`](<../Threat Landscape and Playbooks/Ransomware Playbook.md>) |
| Manual PsExec/WMI/scheduled-task lateral movement as the slower, per-host alternative this technique replaces at scale | [`12 - Lateral Movement`](<../12 - Lateral Movement.md>) |
| Disable-before-delete containment discipline, credential-reset sequencing, verification of successful remediation | [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md>) |
| Fleet-wide baselining and post-fix return-to-known-good-state | [`22 - Enterprise Management and Baseline`](<../22 - Enterprise Management and Baseline.md>) |
| Run-key and scheduled-task persistence mechanics once a GPO-pushed payload lands on an endpoint | [`10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md`](<../10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md>), [`10 - Persistence Mechanisms/Scheduled Tasks.md`](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |

## Resources

- MITRE ATT&CK **T1484.001** (Domain Policy Modification: Group Policy Modification) — https://attack.mitre.org/techniques/T1484/001/
- MITRE ATT&CK **T1053.005** (Scheduled Task/Job: Scheduled Task) — https://attack.mitre.org/techniques/T1053/005/
- MITRE ATT&CK **T1547.001** (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder) — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK **T1552.006** (Unsecured Credentials: Group Policy Preferences) — https://attack.mitre.org/techniques/T1552/006/
- MITRE ATT&CK **T1486** (Data Encrypted for Impact) — https://attack.mitre.org/techniques/T1486/
- Microsoft MS14-025 (Group Policy Preferences cpassword) advisory — https://learn.microsoft.com/security-updates/securitybulletins/2014/ms14-025
- Microsoft Learn — Group Policy overview and administration — consulted generically for architecture/behavior, not fabricated to a specific sub-page
- SANS FOR508 poster/index — used as a coverage-checklist only for the GPO-abuse content this note synthesizes; no verbatim reproduction
