# Domain Controller GPO Investigation

A GPO tampering finding rarely starts on a Domain Controller — it usually starts with a suspicious scheduled task on an endpoint, a logon script nobody remembers authorizing, or a `whenChanged` timestamp that doesn't line up with a change ticket (the detection-angle bullets in [`GPO/05 - GPO Abuse, Hunting and Detection`](<05 - GPO Abuse, Hunting and Detection.md#-hunt-evil>)'s Hunt Evil block). This note is what happens next: once that suspicion exists, how do you actually work the case from the Domain Controller / directory-service side — enumerate every GPO in the domain, pin down exactly what a suspect GPO is linked to, confirm SYSVOL is telling you the truth before you trust it, pull the AD-object change trail, and use replication metadata and (where they exist) GPO backups to build a defensible who/what/when.

This is the DC/AD-object-side half of the investigation. It directly complements [`23 - Special Services/Domain Controller — Role-Specific Forensics`](<../23 - Special Services/Domain Controller — Role-Specific Forensics.md#step-3--sysvoldfsr-replication-health>)'s Step 3, which now hands SYSVOL/DFSR replication-health findings off to this note for the GPO-content investigation built on top of them. For the conceptual model this note assumes you already have — LSDOU processing order, inheritance/Block Inheritance/Enforced, security filtering, WMI filters, loopback — see [`GPO/00 - GPO Fundamentals and Architecture`](<00 - GPO Fundamentals and Architecture.md>). For the actual `dfsrdiag`/`dfsrmig` replication mechanics this note leans on but does not re-derive, see [`GPO/01 - Storage, Replication and Version Synchronization`](<01 - Storage, Replication and Version Synchronization.md>). For what each artifact type inside a GPO *is* (`Registry.pol` format, GPP file internals and the `cpassword` flaw, CSEs, ADMX/ADML), see [`GPO/02 - GPO Content Deep Dive`](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>). General `repadmin` per-attribute replication-metadata mechanics, Kerberos ticket abuse, and DCSync are [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md#ad-replication-metadata-for-timeline-corroboration>)'s territory, not this note's — here `repadmin` is applied specifically to a GPO object, not re-explained from scratch.

> 🔴 **The AD object and the raw SYSVOL file don't always move together, and a raw file edit is the quieter attack.** Every legitimate GPO edit made through GPMC or the `GroupPolicy` module bumps both halves — the GPC's `versionNumber` attribute in AD and the `GPT.INI` version on SYSVOL — together. An attacker (or a careless admin) who edits a `Registry.pol`, a GPP XML file, or `GptTmpl.inf` directly on the SYSVOL share, bypassing the GPO editing tools entirely, leaves the AD object's `versionNumber` and `whenChanged` looking completely normal while the actual applied content has changed. If your investigation only checks the AD object (event 5136, `repadmin /showobjmeta`) and never diffs the SYSVOL file content itself, this kind of change is invisible to you. Treat the two halves as independent witnesses that must corroborate each other, not one signal.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Enumerating GPOs in the Domain](#enumerating-gpos-in-the-domain)
- [Resolving Scope: gpLink and Get-GPOReport](#resolving-scope-gplink-and-get-gporeport)
- [SYSVOL/DFSR Replication Health as an Investigative Prerequisite](#sysvoldfsr-replication-health-as-an-investigative-prerequisite)
- [Malicious GPO Content Detection from the DC Side](#malicious-gpo-content-detection-from-the-dc-side)
- [Event ID 5136 — A Directory Service Object Was Modified](#event-id-5136--a-directory-service-object-was-modified)
- [repadmin /showobjmeta Applied to a GPO Object](#repadmin-showobjmeta-applied-to-a-gpo-object)
- [GPO Backup/Restore as Forensic Evidence](#gpobackuprestore-as-forensic-evidence)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Like `05b`, this note is **not purely native**: it assumes the `GroupPolicy` and `ActiveDirectory` PowerShell modules (RSAT features, not shipped on a workstation by default, but present on every Domain Controller). Where a no-module fallback exists — friendly-name↔GUID resolution via raw LDAP/ADSI — it's called out below.

```powershell
# GPOs sorted by most recently modified - the fastest single query for "what changed lately"
Get-GPO -All | Sort-Object ModificationTime -Descending | Select-Object DisplayName,Id,ModificationTime,Owner

# GPOs linked at the domain root - the scope-abuse pattern (a change that should be OU-scoped, applied everywhere instead)
$domainDN = (Get-ADDomain).DistinguishedName
Get-ADObject -Identity $domainDN -Properties gPLink | Select-Object -ExpandProperty gPLink

# Event 5136 (directory service object modified) scoped to GPO container changes - requires DS Changes auditing, see below
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136} | Where-Object { $_.Message -match 'groupPolicyContainer' }

# repadmin per-attribute replication metadata applied to one GPO's AD object - originating DC + timestamp for its last write
repadmin /showobjmeta * "CN={<GPO-GUID>},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)"

# Friendly name <-> GUID resolution with no RSAT module at all - raw LDAP/ADSI fallback, works from any domain-joined host
$domainDN = ([ADSI]'LDAP://RootDSE').defaultNamingContext
$searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Policies,CN=System,$domainDN")
$searcher.Filter = '(objectClass=groupPolicyContainer)'
$searcher.FindAll() | ForEach-Object { '{0}  {1}  whenChanged={2}' -f $_.Properties['displayname'][0], $_.Properties['cn'][0], $_.Properties['whenchanged'][0] }

# GPO backups on hand for a suspect GPO - a routine backup regime turns "what changed" into a direct diff, see below
Get-GPOReport -Guid <GPO-GUID> -ReportType Xml -Path .\suspect-gpo-now.xml
```

## Enumerating GPOs in the Domain

The first move in any suspected-GPO-tampering case is a full domain inventory, sorted by recency — most malicious edits are recent relative to when the case opened, and an unfamiliar GPO or an old one with a suddenly-bumped modification time both jump out immediately once the whole list is in front of you.

```powershell
Import-Module GroupPolicy
Get-GPO -All | Select-Object DisplayName,Id,GpoStatus,Owner,ModificationTime | Sort-Object ModificationTime -Descending
```

A GPO's SYSVOL folder name is always its GUID, never its friendly name, so any investigation that starts from a file path or an AD distinguished name needs to resolve back to the name an admin would actually recognize — and vice versa. Two methods cover this, and only one of them requires RSAT:

- **No RSAT required — raw LDAP/ADSI against the GPO container.** Every GPO's AD object (a `groupPolicyContainer`) lives under `CN=Policies,CN=System,<domain DN>`, and its `cn` attribute *is* the GUID that also names the SYSVOL folder. This works from any domain-joined host, RSAT or not:

```powershell
$domainDN = ([ADSI]'LDAP://RootDSE').defaultNamingContext
$searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Policies,CN=System,$domainDN")
$searcher.Filter = '(objectClass=groupPolicyContainer)'
$searcher.FindAll() | ForEach-Object { '{0}  {1}' -f $_.Properties['displayname'][0], $_.Properties['cn'][0] }
```

- **`GroupPolicy` module — friendly reporting without hand-parsing anything.** A separate RSAT feature from `ActiveDirectory`, and the one this whole note leans on for everything past basic name/GUID resolution:

```powershell
Get-GPO -All | Select-Object DisplayName,Id,ModificationTime
Get-GPO -Guid <GPO-GUID>   # resolve one specific GUID back to its DisplayName and metadata
```

To retrieve the full inventory using PowerShell, with no filtering:

```powershell
Get-GPO -All
```

To narrow to GPOs modified using PowerShell inside a specific incident window, the standing query once you have a suspected timeframe:

```powershell
Get-GPO -All | Where-Object { $_.ModificationTime -gt (Get-Date '2026-07-01') -and $_.ModificationTime -lt (Get-Date '2026-07-22') } |
    Select-Object DisplayName,Id,ModificationTime,Owner
```

To cross-reference the GUID list using PowerShell from `Get-GPO -All` against the raw AD container directly, catching any `groupPolicyContainer` object the `GroupPolicy` module's own cache might not reflect (e.g., a very recent replication-in-progress state):

```powershell
$viaModule = (Get-GPO -All).Id.Guid
$domainDN = ([ADSI]'LDAP://RootDSE').defaultNamingContext
$searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://CN=Policies,CN=System,$domainDN")
$searcher.Filter = '(objectClass=groupPolicyContainer)'
$viaLdap = $searcher.FindAll() | ForEach-Object { $_.Properties['cn'][0].Trim('{','}') }
Compare-Object $viaModule $viaLdap
```

## Resolving Scope: gpLink and Get-GPOReport

A GPO existing is not the same as a GPO applying anywhere — a GPO with a genuinely malicious payload sitting unlinked in the console is a lower-priority finding than the same content linked to an OU full of domain controllers or servers. `gpLink` is the attribute that turns a GPO from "defined" into "applied," and it lives on the *container* (an OU, the domain object, or a site), not on the GPO itself — so answering "where does this GPO actually apply" means searching every container for a `gpLink` value that references the GPO's GUID:

```powershell
Get-ADObject -Filter {gPLink -like '*<GPO-GUID>*'} -Properties gPLink,DistinguishedName |
    Select-Object DistinguishedName,gPLink
```

The single highest-value scope check is whether a GPO is linked at the **domain root** rather than a narrowly justified OU — the scope-abuse pattern flagged in [`GPO/05`'s T1484.001 walkthrough](<05 - GPO Abuse, Hunting and Detection.md#t1484001--the-full-technique-walkthrough>): a link at the domain object itself fans a change out to every computer/user in the domain at the next refresh, which is exactly the leverage a mass-deployment attack (ransomware staging, a domain-wide backdoor scheduled task) is built to exploit.

```powershell
$domainDN = (Get-ADDomain).DistinguishedName
(Get-ADObject -Identity $domainDN -Properties gPLink).gPLink
```

For the full per-setting content of what a GPO actually does once you've confirmed where it's linked, `Get-GPOReport` produces a complete export — the starting point for the content-level detection work in the next section, and for the backup/diff workflow later in this note:

```powershell
Get-GPOReport -Guid <GPO-GUID> -ReportType Html -Path .\gpo_report.html
Get-GPOReport -Guid <GPO-GUID> -ReportType Xml  -Path .\gpo_report.xml   # XML is easier to diff/script against
```

To find every gpLink for one GPO using PowerShell across the whole domain:

```powershell
Get-ADObject -Filter {gPLink -like '*<GPO-GUID>*'} -Properties gPLink | Select-Object DistinguishedName,gPLink
```

To parse the `gpLink` string using PowerShell (an ordered, semicolon-separated list of `[LDAP://<GPO DN>;<link options bitmask>]` entries) — pull it apart to see link order and whether the suspect GPO is Enforced (bit value `2`) at that particular link, which changes how much you should weight it relative to other links in the chain (the LSDOU precedence mechanics themselves are `GPO/00`'s territory):

```powershell
$link = (Get-ADObject -Identity $domainDN -Properties gPLink).gPLink
$link -split '\]\[' -replace '[\[\]]',''
```

To build a scope-abuse report using PowerShell across every GPO in the domain in one pass — which ones are linked at the domain root vs. OU-scoped, sorted so domain-root links surface first:

```powershell
$domainDN = (Get-ADDomain).DistinguishedName
Get-ADObject -Filter * -SearchBase $domainDN -SearchScope Base -Properties gPLink |
    Select-Object -ExpandProperty gPLink |
    Select-String -Pattern '\{[0-9A-F-]+\}' -AllMatches |
    ForEach-Object { $_.Matches.Value } |
    ForEach-Object { Get-GPO -Guid $_ | Select-Object DisplayName,Id,@{N='LinkedAt';E={'Domain Root'}} }
```

## SYSVOL/DFSR Replication Health as an Investigative Prerequisite

Before trusting any single DC's SYSVOL copy of a GPO as authoritative — before diffing content, before pulling `GPT.INI`, before concluding "the malicious script isn't there" — confirm SYSVOL replication is actually healthy across the DCs you're comparing. A stale or lagging DFSR replica can mask a malicious GPO change on some DCs while it's already fully visible on others: if you happen to query the lagging DC first, you can walk away concluding a change never happened when it's sitting in plain sight one replication hop away. This is precisely the scenario [`23`'s DC note](<../23 - Special Services/Domain Controller — Role-Specific Forensics.md#persistence-patterns-specific-to-this-role>) flags in its Persistence Patterns table: the GPO-tampering mechanism itself is this note's territory, but a stuck or backlogged replica complicating "when did this actually apply domain-wide" is a replication-health question first.

The actual mechanics — `dfsrdiag replicationstate`, `dfsrdiag backlog`, and the FRS→DFSR migration-state gotcha (`dfsrmig /getmigrationstate`) — are fully covered in [`GPO/01 - Storage, Replication and Version Synchronization`](<01 - Storage, Replication and Version Synchronization.md>); this note only adds the investigator's-eye view: run that health check *first*, on every DC whose SYSVOL copy you intend to rely on, before drawing any conclusion from what you find (or don't find) in the next section. If backlog is non-zero and growing between the DCs you're comparing, treat any content discrepancy between them as expected until replication catches up — not as evidence either way.

## Malicious GPO Content Detection from the DC Side

Once scope is confirmed and replication is known to be healthy, the actual content-level detection work happens against the GPO's SYSVOL folder and its AD object side by side. The table below is the DC-investigator's checklist — *where* each kind of malicious change shows up and *what to pull* to confirm it; what each artifact type fundamentally *is* (the `Registry.pol` binary format, GPP XML internals, CSEs, `GptTmpl.inf`/Restricted Groups semantics) is [`GPO/02`](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>)'s job.

| Malicious change | Where it shows up | DC-side detection workflow |
|---|---|---|
| New/modified **logon script** | `Machine\Scripts\Logon\` or `User\Scripts\Logon\` under the GPO's SYSVOL folder, referenced from `Registry.pol` | Diff the script file's own timestamp against the GPO's `GPT.INI` version-history and the GPC's `whenChanged` — a script file newer than the GPO's last "official" edit is the tell of a raw SYSVOL edit that bypassed GPMC |
| **Scheduled task pushed via GPO Preferences (GPP)** | `Machine\Preferences\ScheduledTasks\ScheduledTasks.xml` under the GPO's SYSVOL folder | Pull the XML directly and read the task's command/binary and run-as account; cross-reference the GPO's scope (previous section) — a broad OU/domain-root link plus a task running as SYSTEM is the combination worth escalating on immediately |
| **Modified startup/shutdown script** | `Machine\Scripts\Startup\` (or `Shutdown\`) | Same workflow as logon scripts — file timestamp vs. `GPT.INI`/`whenChanged`, both compared against the org's documented change-management calendar |
| **Security-settings tampering** (Restricted Groups, weakened audit/password policy) | `Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf` under the GPO's SYSVOL folder | Pull `GptTmpl.inf` and diff its `[Group Membership]`/policy sections against the last known-good version (a scheduled backup, if one exists — see below) |

Two DC-side pulls anchor every row above:

- **`GPT.INI` version history** — `GPT.INI` at the root of the GPO's SYSVOL folder carries a version number that increments on every legitimate GPMC/`GroupPolicy`-module edit. There's no built-in history of *past* versions on a live system, so "history" in practice means comparing the current version against whatever your evidence trail preserved — a prior `Get-GPOReport` export, a formal backup (below), or a VSS snapshot of SYSVOL.
- **`whenChanged` on the GPC object** — the AD-object side's coarse, object-level "something changed" signal, checked directly:

```powershell
Get-ADObject -Filter {objectClass -eq 'groupPolicyContainer' -and Name -eq '{<GPO-GUID>}'} -Properties whenChanged,whenCreated,versionNumber
```

The critical thing to internalize from the red-flag callout at the top of this note: `whenChanged`/`versionNumber` only move when a change goes through the GPO object itself. A raw SYSVOL file edit — someone with file-share write access editing `ScheduledTasks.xml` or `GptTmpl.inf` directly rather than through GPMC — never touches the AD object at all. If the table above and the AD-object metadata disagree (file evidence of a recent change, but a stale `whenChanged`), that disagreement *is* the finding.

## Event ID 5136 — A Directory Service Object Was Modified

Event **5136** ("A directory service object was modified") fires on the DC that processed the write, for changes to any AD object — including GPO objects (`groupPolicyContainer`) and, critically, their `gPLink` and `versionNumber` attributes. This is the DC-side audit trail for exactly the kind of change GPMC or the `GroupPolicy` module makes when an admin (or an attacker with sufficient rights) edits a GPO or re-links it to a different container.

It is **not enabled by default**. Generating it requires the **"Audit Directory Service Changes"** Advanced Audit Policy subcategory (under DS Access) to be turned on — a setting many environments never explicitly configure. Before treating an absence of 5136 events as "nothing was changed," confirm the subcategory was actually enabled for the window in question:

```powershell
auditpol /get /subcategory:"Directory Service Changes"
```

When it's enabled and fires, 5136 gives you:

- the **modifying account** (the security principal that made the change),
- the **object's distinguished name** (which GPO, which OU's `gpLink`, etc.),
- and — with sufficient audit detail configured — the **specific attribute changed** and its **old and new values**.

That's a complete who/what/when for the AD-object side of a change, on its own. The full picture comes from pairing it with two other data points this note already covers:

1. **SYSVOL file-level timestamps** (previous section) — confirms the file content actually changed and roughly when, independent of whether 5136 was even auditing at the time.
2. **`repadmin /showobjmeta`** (next section) — confirms the *originating DC* for the attribute-level AD write, corroborating (or contradicting) both the 5136 event and the claimed timeline.

The scenario worth internalizing explicitly: an attacker who edits a GPO through normal tooling (GPMC, `Set-GPRegistryValue`) generates a clean, complete trail across all three — 5136 fires, `versionNumber`/`gPLink` change, and the SYSVOL file timestamp moves in lockstep. An attacker who edits the raw SYSVOL file directly generates **no 5136 event at all for the content change** (nothing touched the AD object), and `versionNumber` stays put — the file-timestamp evidence from the previous section is the *only* trail that scenario leaves on the DC side, which is exactly why this note treats the AD-object trail and the SYSVOL file trail as two independent witnesses rather than one.

To pull raw 5136 events using PowerShell from the DC's Security log:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136}
```

To narrow using PowerShell to GPO-related object changes specifically, since 5136 fires for every AD object type:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5136} |
    Where-Object { $_.Message -match 'groupPolicyContainer|gPLink' } |
    Select-Object TimeCreated,@{N='Account';E={$_.Properties[4].Value}},@{N='ObjectDN';E={$_.Properties[6].Value}}
```

To sweep using PowerShell every DC (a client's writes/reads don't always hit the same DC, and 5136 is logged only by the DC that accepted the change) and correlate hits against the GPO GUID list from the enumeration step:

```powershell
$guidPattern = ((Get-GPO -All).Id.Guid -join '|')
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName='Security'; Id=5136} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match $guidPattern } |
        Select-Object @{N='DC';E={$dc}},TimeCreated,Message
}
```

## repadmin /showobjmeta Applied to a GPO Object

`05b` already covers `repadmin /showobjmeta`'s general per-attribute replication-metadata mechanics and why it's useful for timeline corroboration generally — that concept isn't repeated here. What's specific to this note is pointing it at a GPO's AD object (or the `gPLink` attribute on the OU it's linked to) to get an authoritative answer to "which DC actually accepted this write, and when":

```powershell
repadmin /showobjmeta * "CN={<GPO-GUID>},CN=Policies,CN=System,DC=<domain>,DC=<tld>"
```

This is the step that closes the loop on the previous two sections: if 5136 gave you a modifying account and a rough time, and the SYSVOL file timestamp gave you file-level confirmation, `/showobjmeta` gives you the **originating DC** and the **authoritative last-write timestamp** for that specific attribute (`versionNumber`, `gPLink`, whichever is in question) — which either corroborates the timeline you've built so far or directly contradicts it, independent of whether Security-log auditing was even enabled at the time of the change. The `Get-ADReplicationAttributeMetadata` PowerShell equivalent (also `05b`'s territory) works identically here, substituting the GPO's distinguished name as the target object:

```powershell
Get-ADReplicationAttributeMetadata -Object "CN={<GPO-GUID>},CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Server (Get-ADDomainController).HostName |
    Where-Object AttributeName -in 'versionNumber','gPCFileSysPath' |
    Select-Object AttributeName,LastOriginatingChangeTime,LastOriginatingChangeDirectoryServerIdentity,Version
```

For a `gPLink` change specifically (a re-scoping rather than a content edit), run the same query against the *linked container's* distinguished name rather than the GPO object itself — `gPLink` lives on the OU/domain/site, not on the GPO.

## GPO Backup/Restore as Forensic Evidence

Independent of whatever Security-log auditing was or wasn't enabled at the time of a change, a GPO backup taken *before* the incident is direct, evidentiary-quality proof of what a GPO looked like at that point in time. If the organization runs scheduled or routine GPO backups (a common change-management practice, whether via GPMC's built-in backup feature or a script wrapping `Backup-GPO`), comparing a suspect GPO's *current* state against its most recent legitimate backup can reveal exactly what changed — settings added, removed, or modified — with no dependency on 5136, `whenChanged`, or any Security-log evidence existing at all.

```powershell
# Point-in-time backup of every GPO in the domain, to a share reviewed periodically for drift
Backup-GPO -All -Path \\<server>\GPOBackups\$(Get-Date -Format 'yyyy-MM-dd')

# Pull the metadata for backups already on hand for a specific GPO
Get-GPOReport -Guid <GPO-GUID> -ReportType Xml -Path .\backup-manifest-check.xml
```

Where a formal backup regime exists, the investigative move is a direct diff: export the suspect GPO's current state with `Get-GPOReport` (XML, since it diffs cleanly), and compare it against the equivalent report generated from the most recent pre-incident backup:

```powershell
Get-GPOReport -Guid <GPO-GUID> -ReportType Xml -Path .\suspect-now.xml
# ... restore the backed-up GPO to a scratch/lab location, or extract its XML from the backup manifest directly, then:
Compare-Object (Get-Content .\suspect-now.xml) (Get-Content .\suspect-backup.xml)
```

Where no formal backup regime exists, a lighter-weight version of the same idea still works if you happened to pull `Get-GPOReport` at any earlier point (a prior audit, a change-management record, even an analyst's own earlier-in-the-case export) — diffing two `Get-GPOReport` snapshots from different points in time is strictly less authoritative than a real backup (it only proves what you happened to capture, not a guaranteed clean state) but is far better than no independent record of the GPO's prior content at all.

To restore a specific GPO backup using PowerShell to confirm/inspect its content without touching the live GPO:

```powershell
Get-GPOReport -Guid <GPO-GUID> -ReportType Html -Path .\restored-check.html
```

To restore the GPO using PowerShell to its last known-good backed-up state once a change is confirmed malicious (via the sections above) and the evidence has been captured:

```powershell
Restore-GPO -Guid <GPO-GUID> -Path \\<server>\GPOBackups\<backup-date-folder>
```

Capture the current (malicious) state — a `Get-GPOReport` export at minimum, ideally a full `Backup-GPO` of the suspect GPO as it currently stands — *before* restoring, so the compromised version itself remains available as evidence rather than being overwritten with no record.

## Investigative Sequence Summary

```
1. Enumerate every GPO in the domain, sorted by ModificationTime
   Get-GPO -All  (+ raw LDAP/ADSI fallback if no RSAT)
                    │
2. Resolve scope for any GPO of interest
   gpLink lookup on candidate containers · Get-GPOReport for full content
   → flag domain-root links as the scope-abuse red flag
                    │
3. Confirm SYSVOL replication health BEFORE trusting any one DC's copy
   → hand off to GPO/01 for dfsrdiag/dfsrmig mechanics
                    │
4. Content-level detection: logon/startup scripts, GPP scheduled tasks, GptTmpl.inf
   GPT.INI version vs. whenChanged on the GPC object
   → hand off to GPO/02 for what each artifact type IS
                    │
5. Pull event 5136 (confirm DS Changes auditing was on first)
   → modifying account, object DN, attribute, old/new value
                    │
6. repadmin /showobjmeta on the GPO object / gpLink container
   → originating DC + authoritative timestamp, corroborate or contradict the timeline
                    │
7. Check for a prior GPO backup (or an earlier Get-GPOReport export)
   → diff current state against last known-good, independent of whether auditing was ever on
                    │
8. Remediate: capture current state as evidence, then Restore-GPO from known-good backup
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| GPO linked at the domain root rather than a narrowly scoped OU, with no documented justification | Scope-abuse pattern — maximizes blast radius of a single edit |
| SYSVOL file content (script, GPP XML, `GptTmpl.inf`) newer than the GPC object's `whenChanged`/`versionNumber` | Likely a raw SYSVOL edit that bypassed GPMC/`GroupPolicy` tooling entirely — the AD-object trail will be clean because nothing touched the AD object |
| "Audit Directory Service Changes" not enabled on the DC(s) in question | 5136 cannot have fired — absence of the event proves nothing about whether a change occurred |
| Event 5136 for a GPO object with a modifying account outside the expected change-management group | Unauthorized or credential-abuse-driven GPO edit |
| `repadmin /showobjmeta` shows an originating DC or timestamp inconsistent with the claimed change window | Corroborates or contradicts the timeline independent of Security-log auditing state |
| DFSR backlog non-zero between the DCs being compared, discovered mid-investigation | Any content discrepancy found so far is provisional until replication catches up — see `GPO/01` |
| No GPO backup and no prior `Get-GPOReport` export exists for the suspect GPO | No independent point-in-time record of pre-incident state — the diff-based detection in this note's last section is unavailable |
| Investigation limited to the AD-object side (5136, `whenChanged`, `repadmin`) with no SYSVOL file-content review | Structurally blind to the raw-file-edit scenario this note's opening red flag describes |

## Tooling

| Tool | Use |
|---|---|
| **GPMC** (Group Policy Management Console) | GUI equivalent of most commands in this note — GPO enumeration, `gpLink` scope review, backup/restore, report generation |
| **`GroupPolicy` PowerShell module** (`Get-GPO`, `Get-GPOReport`, `Backup-GPO`, `Restore-GPO`) | This note's primary tooling — RSAT feature, present on every DC |
| **`ActiveDirectory` PowerShell module** (`Get-ADObject`, `Get-ADReplicationAttributeMetadata`) | `gpLink`/GPC object queries, replication-metadata equivalent to `repadmin` |
| **`repadmin`** | `/showobjmeta` for authoritative per-attribute replication provenance — general mechanics owned by `05b`, applied here to GPO objects specifically |
| **Raw LDAP/ADSI (`[ADSI]`, `DirectorySearcher`)** | No-RSAT-required fallback for friendly-name↔GUID resolution and GPC object queries |
| **`auditpol`** | Confirm "Audit Directory Service Changes" is actually enabled before trusting an absence of 5136 events |

## Correlate With

| To go deeper on… | Open |
|---|---|
| GPO fundamentals — LSDOU, inheritance, WMI filters, loopback, local vs. domain GPO | [`GPO/00 - GPO Fundamentals and Architecture`](<00 - GPO Fundamentals and Architecture.md>) |
| SYSVOL/GPT folder structure, `dfsrdiag`/`dfsrmig` mechanics, GPT/GPC version-desync detection | [`GPO/01 - Storage, Replication and Version Synchronization`](<01 - Storage, Replication and Version Synchronization.md>) |
| `Registry.pol` format, GPP file internals and the `cpassword`/MS14-025 flaw, CSEs, ADMX/ADML | [`GPO/02 - GPO Content Deep Dive`](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |
| T1484.001 full attack narrative, mass-deployment ransomware pattern, consolidated folder-wide hunting/detection | [`GPO/05 - GPO Abuse, Hunting and Detection`](<05 - GPO Abuse, Hunting and Detection.md>) |
| `repadmin` general per-attribute replication-metadata mechanics, Kerberos ticket abuse, DCSync, AD replication metadata generally | [`05b - Active Directory & Domain Forensic Artifacts`](<../05b - Active Directory & Domain Forensic Artifacts.md#ad-replication-metadata-for-timeline-corroboration>) |
| DC-as-a-host operational forensics — NTDS.dit acquisition, rogue DC detection, DC-side log-volume triage | [`23 - Special Services/Domain Controller — Role-Specific Forensics`](<../23 - Special Services/Domain Controller — Role-Specific Forensics.md>) |
| Event 5136's place in the general log taxonomy, audit-policy prerequisites, log rollover/retention | [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md>) |
| Domain-joined-host side of a GPO investigation — `gpresult`, RSOP, local GPO cache, `Microsoft-Windows-GroupPolicy/Operational` | [`GPO/04 - Domain-Joined Host GPO Investigation`](<04 - Domain-Joined Host GPO Investigation.md>) |

## Resources

- Microsoft Learn — `Backup-GPO`: https://learn.microsoft.com/powershell/module/grouppolicy/backup-gpo
- Microsoft Learn — `Restore-GPO`: https://learn.microsoft.com/powershell/module/grouppolicy/restore-gpo
- Microsoft Learn — `Get-GPOReport`: https://learn.microsoft.com/powershell/module/grouppolicy/get-gporeport
- Microsoft Learn — Event 5136 description (Audit Directory Service Changes): https://learn.microsoft.com/windows/security/threat-protection/auditing/event-5136
- Microsoft Learn — `repadmin` command reference: https://learn.microsoft.com/windows-server/administration/windows-commands/repadmin
- MITRE ATT&CK **T1484.001** (Domain Policy Modification: Group Policy Modification): https://attack.mitre.org/techniques/T1484/001/
