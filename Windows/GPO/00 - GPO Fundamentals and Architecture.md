# GPO Fundamentals and Architecture

This is the orientation note for the `GPO/` folder — read it first. Group Policy shows up throughout this repo (`05b`'s AD-object angle, `22`'s baselining angle, `23`'s Domain Controller role notes) but none of those notes teach the mechanism itself end to end: what a GPO actually *is*, how its two on-disk/AD halves relate, why a machine that has never joined a domain can still have a malicious Group Policy applied to it, and — the piece most investigators under-appreciate — the precedence logic (LSDOU, inheritance, enforcement, filtering) that decides which of a dozen possibly-conflicting GPOs actually wins on a given endpoint. That precedence logic is exactly where an attacker with limited GPO-edit rights hides scope, and it's the conceptual foundation every other note in this folder assumes you already have. Once you've read this note, `01 - Storage, Replication and Version Synchronization` goes deep on the SYSVOL/AD-object plumbing this note only introduces, `02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates)` covers what's actually inside a GPO, `03 - Domain Controller GPO Investigation` and `04 - Domain-Joined Host GPO Investigation` cover the two investigation vantage points, and `05 - GPO Abuse, Hunting and Detection` covers the T1484.001 attack technique and a consolidated hunt/red-flags reference across the whole folder.

> 🔴 **An analyst who only thinks "pull the GPOs from the domain controller" will miss a whole class of malicious Group Policy.** Every Windows machine — domain-joined or not, even a machine that has never touched a domain in its life — has its own **Local Group Policy Object**, processed and enforced with exactly the same engine as a domain GPO. A standalone or workgroup box compromised by an attacker can have a malicious local GPO setting (a logon script, a disabled Defender policy, a Restricted-Groups-equivalent local security setting) sitting entirely outside AD and SYSVOL, invisible to any investigation that starts and ends at the DC. Separately, on a domain-joined machine, the *combination* of LSDOU ordering, Block Inheritance, Enforced links, security filtering, and WMI filters is complex enough that it is a genuinely effective place for an attacker to hide a narrowly-scoped malicious GPO in plain sight — the GPO itself can look completely unremarkable until you check what's actually gating who it applies to.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [What GPO Is — Centralized Configuration and Its Forensic Duality](#what-gpo-is--centralized-configuration-and-its-forensic-duality)
- [The GPT/GPC Two-Halves Model](#the-gptgpc-two-halves-model)
- [Local GPO vs Domain GPO](#local-gpo-vs-domain-gpo)
  - [Multiple Local Group Policy Objects (MLGPO)](#multiple-local-group-policy-objects-mlgpo)
- [Processing Order — LSDOU and Precedence](#processing-order--lsdou-and-precedence)
  - [The LSDOU Order](#the-lsdou-order)
  - [Block Inheritance and Enforced (No Override)](#block-inheritance-and-enforced-no-override)
  - [Security Filtering](#security-filtering)
  - [WMI Filters](#wmi-filters)
  - [Loopback Processing (Merge vs Replace)](#loopback-processing-merge-vs-replace)
- [Refresh Mechanics](#refresh-mechanics)
- [Friendly Name ↔ GUID Resolution](#friendly-name--guid-resolution)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native triage via the in-box `GroupPolicy` module (RSAT, ships on every DC and any admin workstation with RSAT installed) plus `ActiveDirectory` for the OU-side checks. No third-party tooling required.

```powershell
# Every GPO sorted by last-modified, with its GUID shown alongside the display name - reinforces that the GUID, not the name, is the real identity
Get-GPO -All | Sort-Object ModificationTime -Descending | Select-Object DisplayName, Id, GpoStatus, ModificationTime | Select-Object -First 25

# Resolve a friendly name to its GUID, and a GUID back to its friendly name - the two-way lookup every other note in this folder assumes you can do
Get-GPO -Name 'Default Domain Policy' | Select-Object DisplayName, Id
Get-GPO -Guid '31B2F340-016D-11D2-945F-00C04FB984F9' | Select-Object DisplayName, Id

# Every GPO carrying a WMI filter - the narrow/stealthy-targeting check, since a filter can scope an otherwise broad-looking GPO down to almost nothing
Get-GPO -All | Where-Object { $_.WmiFilter } | Select-Object DisplayName, @{N='WmiFilter'; E={ $_.WmiFilter.Name }}

# Every OU with Block Inheritance set, and whether any GPO linked there is Enforced anyway - the interaction this note's LSDOU section covers
Get-ADOrganizationalUnit -Filter * | ForEach-Object {
    $inh = Get-GPInheritance -Target $_.DistinguishedName
    if ($inh.GpoInheritanceBlocked) {
        [PSCustomObject]@{ OU = $_.DistinguishedName; EnforcedLinksPresent = ($inh.GpoLinks | Where-Object Enforced -eq 'Enforced').Count -gt 0 }
    }
}

# GPOs whose reports mention loopback processing - the shared/kiosk/RDS-machine tell that's easy to miss if you only check the logged-on user's own OU
Get-GPO -All | ForEach-Object { if ((Get-GPOReport -Guid $_.Id -ReportType Xml) -match 'Loopback') { $_.DisplayName } }

# Local GPO Registry.pol presence on this host - the artifact an analyst who only thinks "domain" will never look for
Test-Path 'C:\Windows\System32\GroupPolicy\Machine\Registry.pol', 'C:\Windows\System32\GroupPolicy\User\Registry.pol'

# Security filtering on a specific GPO - who can actually apply it, versus who it merely looks like it's linked to
Get-GPPermissions -Guid '<GPOGuid>' -All | Where-Object Permission -eq 'GpoApply' | Select-Object Trustee, Permission

# Background refresh interval currently configured (absent = OS default applies) - flags a tampered/extended refresh window
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name GroupPolicyRefreshTime, GroupPolicyRefreshTimeOffset -ErrorAction SilentlyContinue
```

## What GPO Is — Centralized Configuration and Its Forensic Duality

Group Policy is Active Directory's native mechanism for centralized configuration management: an administrator defines a set of settings once — security policy, software deployment, logon/startup scripts, registry values, Restricted Groups membership, and hundreds of other configurable areas — links that definition to a site, domain, or Organizational Unit, and every computer or user object within that scope picks the settings up automatically at the next refresh. It is the single most common way an enterprise Windows environment enforces a consistent configuration baseline across hundreds or thousands of endpoints without an administrator ever touching each one by hand.

That same centralization is exactly what gives GPO its forensic duality:

| Angle | What it means |
|---|---|
| **Defender's tool** | GPO is how an organization *establishes and enforces* "normal" — audit policy, password/lockout policy, software restriction policy, Restricted Groups, and pushed security baselines typically flow through it. Anomaly-based hunting that depends on a known baseline is frequently comparing against a baseline GPO built. |
| **Attacker target** | An attacker with sufficient domain privilege — full Domain Admin, or merely delegated GPO-edit rights on the right OU, a narrower and more commonly over-granted permission — can abuse GPO as a mass-deployment mechanism: a single edit fans out a malicious scheduled task, Run-key registry value, or logon script to every computer in the linked scope at next refresh. MITRE ATT&CK tracks this as **T1484.001 (Group Policy Modification)**; this is also a well-documented real-world ransomware mass-deployment pattern. The full attack-technique walkthrough is `05 - GPO Abuse, Hunting and Detection`'s job — this note's contribution is the conceptual "why GPO is such high-leverage abuse surface in the first place": one edit, one link, thousands of endpoints. |

The rest of this note builds the vocabulary that duality depends on: where a GPO's content and identity actually live, how a machine without any domain at all still has one, and the precedence logic that decides which of several competing GPOs actually wins on a given endpoint.

## The GPT/GPC Two-Halves Model

A GPO is not a single object — it is two halves that have to stay in sync, and a surprising amount of forensic value comes from noticing when they don't.

| Half | What it is | Where it conceptually lives |
|---|---|---|
| **GPT — Group Policy Template** | The actual policy *content*: the registry-based settings, scripts, security templates, and Group Policy Preferences that a GPO pushes | Replicated files on **SYSVOL**, one folder per GPO, named by the GPO's GUID |
| **GPC — Group Policy Container** | The AD *object* representing the GPO's identity and metadata — its GUID, version number, and link information (which sites/domains/OUs it's actually applied to) | An Active Directory object under the domain's Group Policy Objects container |

Both halves carry their own version number, and normal GPO-editing tools (GPMC, the `GroupPolicy` PowerShell module) move both together whenever a GPO is edited. A raw SYSVOL file edit that bypasses that tooling can change policy *content* while leaving the AD object's version looking unchanged — a GPT/GPC desync that is itself a lead worth chasing. That is as deep as this note goes: the full SYSVOL folder tree, the GPC's AD attributes, replication mechanics (FRS vs. DFSR), and the version-desync detection workflow all belong to **`01 - Storage, Replication and Version Synchronization`** — this note's job is only to establish that the two-halves model exists and why it matters conceptually.

## Local GPO vs Domain GPO

Every Windows machine has a **Local Group Policy Object**, edited via `gpedit.msc` — and this is true regardless of whether the machine has ever joined a domain. A brand-new, never-networked, workgroup-only laptop still has a functioning Local GPO the moment Windows is installed; it's processed by the exact same client-side Group Policy engine that processes domain GPOs, just with nothing above it in the hierarchy to layer on top.

🔴 **`gpedit.msc`'s availability varies by SKU** (historically absent on Windows *Home* editions), but the absence of the *editor GUI* is not the same as the absence of *local policy processing* — the underlying engine still reads and applies whatever local policy is present on any SKU, and tools like Microsoft's `LGPO.exe` (Security Compliance Toolkit) or direct registry/`Registry.pol` manipulation can still set local policy even where `gpedit.msc` itself isn't installed. Don't assume "Home edition, so no local GPO risk."

This matters forensically because a **compromised standalone or workgroup machine can still have malicious local GPO settings** — a logon script, a disabled security control, a Restricted-Groups-equivalent local security policy change — persisted entirely through the Local GPO mechanism, with zero footprint in AD or SYSVOL. An investigation of that machine that only thinks in domain-GPO terms (pull SYSVOL, check `gpLink`, query the GPC) will never find it; the evidence is purely local, under `C:\Windows\System32\GroupPolicy\`.

### Multiple Local Group Policy Objects (MLGPO)

Starting with Windows Vista, workstation SKUs support **Multiple Local Group Policy Objects** — more than one local policy layer, processed in order, each one able to override the one before it for users that fall into its scope:

| Layer | Applies to | Precedence |
|---|---|---|
| **Local Group Policy** | Every user of the machine | Applied first, lowest precedence among the local layers |
| **Administrators / Non-Administrators GPO** | Split by whether the logging-on user is a member of the local `Administrators` group | Applied after the base Local GPO, overriding it for the matching user category |
| **User-specific Local GPO** | One specific local user account, by name | Applied last among the local layers, highest local-tier precedence |

The forensic point: MLGPO means a single machine can carry *several* distinct local policy layers simultaneously, targeted differently — e.g. a malicious setting scoped only to the local `Administrators` GPO layer, invisible when checking the base Local GPO alone. When a machine is domain-joined, these local layers still process first in LSDOU order (below); anything a domain-level GPO actually configures overrides the corresponding local setting, but anything the domain GPO leaves **Not Configured** falls through to whatever the local layer already set — local policy is superseded per-setting, not wiped wholesale.

## Processing Order — LSDOU and Precedence

### The LSDOU Order

Group Policy processes in a fixed order — **Local → Site → Domain → OU** — and, on conflict, **later-applied wins**:

```
Local GPO(s)  (see MLGPO above)
     │
     ▼
Site GPO(s)               ← linked to the AD Site object; uncommon outside multi-site orgs
     │
     ▼
Domain GPO(s)              ← linked at the domain root (e.g. Default Domain Policy)
     │
     ▼
OU GPO(s) — outermost OU first
     │
     ▼
OU GPO(s) — innermost OU (the one actually containing the object)   ◀── applied LAST, wins ties
```

Two refinements worth carrying forward, since they're where actual precedence questions get answered:

- **Multiple GPOs linked to the same container** process in **reverse link order** — the GPO with **link order 1** is applied *last* at that container, and so wins any conflict among GPOs linked at that same level.
- **Inheritance flows down the OU tree** by default — a GPO linked at the domain root or a parent OU applies to every child OU below it unless something interrupts that flow, which is exactly what the next two mechanisms do.

Full resolution of *which* GPOs are actually linked where (`gpLink` attribute parsing, AD-side enumeration) is `03 - Domain Controller GPO Investigation`'s job — this section's job is only the ordering logic itself.

### Block Inheritance and Enforced (No Override)

Two settings interrupt or override the default LSDOU/inheritance flow, and they can directly conflict with each other:

| Setting | Set on | Effect | When both are present |
|---|---|---|---|
| **Block Inheritance** | An OU (or the domain) | Stops GPOs linked at *parent* containers (the domain, or any OU further up the tree) from applying to this container by default | — |
| **Enforced** (also called **No Override**) | A specific GPO *link*, at any level | Forces that GPO's settings to apply to the entire subtree below the link, and prevents any GPO closer to the object from overriding *its* settings on conflict | **Enforced wins** — an Enforced link's settings apply even through a Block Inheritance set further down the tree |

Worked example: a GPO linked at the domain root is marked **Enforced**. An OU three levels down sets **Block Inheritance**. That OU's Block Inheritance stops every *other* non-Enforced parent GPO from reaching it — but the Enforced domain GPO still applies anyway, because Enforced overrides Block Inheritance specifically.

🔴 **Forensic angle:** an attacker who secures an Enforced link on a GPO they control guarantees that setting can't be locally overridden or blocked by an OU admin further down the tree trying to remediate it — a durable way to make a malicious setting "win" no matter what a defender does at a lower OU, short of removing the Enforced link itself or the GPO's link entirely.

### Security Filtering

By default, a linked GPO applies to the **Authenticated Users** security principal within its scope — every computer/user object in that container gets it. An administrator can narrow that down via **security filtering**: the GPO's own ACL controls who actually receives it, gated on the **Apply Group Policy** permission (an ACE, not a GPO setting) rather than the link itself.

- **Allow — Apply Group Policy**, granted to a specific security group instead of Authenticated Users, scopes the GPO to only that group's members.
- **Deny — Apply Group Policy**, added for a specific group, explicitly excludes that group even if it would otherwise be in scope via Authenticated Users or another Allow entry.

🔴 **The "deny wins" gotcha:** this is ordinary Windows ACL evaluation, not a GPO-specific rule — if a principal is covered by both an Allow and a Deny entry for Apply Group Policy (e.g. a member of both an allowed group and a denied group), **the explicit Deny always wins**, regardless of group nesting or evaluation order. An analyst reading a GPO's permissions needs to check for Deny entries specifically, not just confirm an Allow entry exists.

Forensic angle: security filtering lets an attacker scope a malicious GPO down to a single computer or a small group rather than an entire OU — the GPO's link can look broad (linked at a large OU or even the domain root) while its actual effective scope, once security filtering is accounted for, is a handful of targeted machines. Read the GPO's permissions, not just its link location, before concluding how broadly it actually applies.

### WMI Filters

A **WMI filter** is a separate AD object holding a WMI query; when attached to a GPO, that GPO only applies to a target machine if the query evaluates true against it at processing time. Typical legitimate uses: scoping a GPO to a specific OS version (`SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.%'`), a specific hardware class, or a specific installed-software condition.

🔴 **Forensic angle:** a WMI filter can scope an otherwise broad-looking GPO down to an oddly narrow condition — a single hostname, a single OS build, the *absence* of a specific security product — without that narrowing being visible anywhere in the GPO's link location or security filtering. It's a separate object entirely, and it's the piece of the puzzle most easily missed: the GPO looks like it's linked domain-wide, security filtering looks like Authenticated Users, and the actual effective scope is nonetheless one machine, because the WMI filter query only matches one machine. Always check whether a GPO of interest carries a WMI filter, and read the query itself.

### Loopback Processing (Merge vs Replace)

Normally, **user-side** policy settings are computed from the GPOs linked to the OU containing the **user object** that logged on — the computer is irrelevant to which user policies apply. **Loopback processing** changes this: when enabled (a Computer Configuration setting on the target computer's own GPO), the user's effective policy is instead computed from the GPOs linked to the OU containing the **computer object**, not the user's own OU.

| Mode | Behavior |
|---|---|
| **Merge** | The user's own normal GPOs still apply, *and* the computer-OU's GPOs are applied afterward — computer-OU settings win any conflict, but nothing from the user's normal GPO set is skipped |
| **Replace** | The user's own normal GPO set is skipped entirely — only the GPOs linked to the computer's OU determine the user's effective policy |

This exists for **shared, kiosk, or terminal-server/RDS-style machines**, where the administrator wants a consistent user experience driven by which machine someone logged onto, regardless of which user account did the logging on. Forensic angle: on a machine like this, an investigator who checks only the logged-on user's own OU GPOs is looking in the wrong place — the policy that actually took effect is sitting on the *computer's* OU instead, and missing that is a common source of "the GPO I found doesn't match what I'm seeing on the box."

## Refresh Mechanics

| Mechanism | What it does |
|---|---|
| **Background refresh interval** | Windows refreshes Group Policy automatically on a periodic cycle, historically in the range of roughly 90–120 minutes with a randomized offset (to avoid every endpoint hitting a DC simultaneously) — hedge on the exact current default for a specific OS/build, since it's policy-tunable via `GroupPolicyRefreshTime`/`GroupPolicyRefreshTimeOffset` and has had minor variation historically; confirm against the live host's effective settings rather than assuming a fixed number. Domain Controllers themselves have historically defaulted to a much shorter refresh cycle (on the order of a few minutes) given their higher security sensitivity — again, confirm the live value rather than assuming. |
| **Foreground refresh** | Occurs at boot (computer policy) and logon (user policy); certain settings (notably Software Installation and Folder Redirection) require a **synchronous** foreground application to work correctly, which can add to boot/logon time — the exact synchronous/asynchronous default has shifted across OS versions, so confirm rather than assume for a specific build |
| **Background refresh** | The periodic refresh above, applied silently while the user is already logged on — most setting categories process this way without requiring a logoff/reboot |
| **`gpupdate`** | Manually triggers a refresh, but only reapplies settings whose GPO version has actually changed since the endpoint's last successful refresh (the same version-check logic that underlies the GPT/GPC sync concept above) |
| **`gpupdate /force`** | Reapplies **all** settings from every linked GPO regardless of version — useful for troubleshooting, and for confirming a setting is genuinely being pushed rather than merely unchanged since last refresh |
| **Slow-link detection** | The GPO client estimates the throughput of its connection to a Domain Controller (historically ICMP-ping-based estimation, more recently informed by Network Location Awareness) and, if below a configurable threshold, treats the connection as a "slow link" — some Client-Side Extensions (Software Installation, Folder Redirection) skip processing over a slow link by default, while core Security settings always process regardless of link speed. Threshold and per-CSE slow-link behavior are both tunable; treat this as a brief orientation point rather than a full mechanism, since it rarely changes an investigation's conclusions on its own. |

To read the currently configured refresh-interval values on a host using PowerShell (absent = the OS default applies):

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name GroupPolicyRefreshTime, GroupPolicyRefreshTimeOffset -ErrorAction SilentlyContinue
```

To force a refresh and confirm it actually happened using PowerShell, the fastest way to distinguish "nothing to reapply" from "refresh isn't working":

```powershell
gpupdate /force
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 5 | Select-Object TimeCreated, Id, Message
```

To sweep a hunt list of hosts using PowerShell for a refresh interval that's been tampered with to an unusually long value (a way to delay legitimate policy re-application after a local override):

```powershell
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name GroupPolicyRefreshTime -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, GroupPolicyRefreshTime
}
```

## Friendly Name ↔ GUID Resolution

Every GPO's real identity — its SYSVOL folder name, and its AD object's `CN` — is a **GUID**, never its display name. The display name is just a friendly attribute for humans; two different GPOs can even share the identical display name (a known source of confusion when an admin duplicates a GPO for testing and forgets to rename the copy). Any investigation that matters — confirming which GPO a `gpLink` entry actually points to, matching a SYSVOL folder back to the GPMC-displayed name — ultimately has to resolve through the GUID, not the name.

At the basic level, resolution is a one-line lookup in either direction via the `GroupPolicy` module:

```powershell
Get-GPO -Name 'Default Domain Policy' | Select-Object DisplayName, Id
Get-GPO -Guid '31B2F340-016D-11D2-945F-00C04FB984F9' | Select-Object DisplayName, Id
```

Deeper resolution paths — raw ADSI/LDAP enumeration with no `GroupPolicy` module dependency, matching a `gpLink` GUID back to a linked object, and cross-checking a SYSVOL folder name against the AD object — are `03 - Domain Controller GPO Investigation`'s territory; this note's job is only to establish that the GUID, not the name, is the thing to trust.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| A GPO link marked **Enforced** at an unexpectedly high level (domain root) or on a narrow, unexpected OU | Guarantees the GPO's settings can't be overridden by anything closer to the object, including a defender's attempted local remediation further down the tree |
| A WMI filter attached to a GPO with a query narrower than the GPO's stated purpose or its link location would suggest | Classic narrow/stealthy-targeting pattern — the GPO looks broadly linked but its WMI filter actually restricts it to a small, specific set of machines |
| Security filtering that scopes a GPO down to a single computer or user object rather than the expected group | Same narrowing pattern as a WMI filter, achieved through the GPO's own ACL instead of a filter object — check permissions, not just the link |
| Loopback processing (Merge or Replace) configured on a GPO linked to an OU that isn't an obviously shared-use/kiosk/RDS context | Redirects user-policy evaluation to the computer's OU instead of the user's — an investigator checking only the user's own OU will miss the actual effective policy |
| Populated `Registry.pol` under `C:\Windows\System32\GroupPolicy\` on a standalone or workgroup machine with no domain to explain it | Local GPO settings persisting entirely outside AD/SYSVOL — invisible to any investigation that starts and ends at the Domain Controller |
| Two GPOs sharing an identical display name | A friendly-name collision — forces GUID-level verification before trusting which GPO a reference actually points to |
| `GroupPolicyRefreshTime`/`GroupPolicyRefreshTimeOffset` set to an unusually long interval, inconsistent with the environment's normal configuration | Possible deliberate delay of legitimate policy re-application, buying time for a local override or malicious setting to persist longer between refreshes |

## Tooling

| Tool | Use |
|---|---|
| **`GroupPolicy` PowerShell module** (RSAT) | `Get-GPO`, `Get-GPOReport`, `Get-GPInheritance`, `Get-GPPermissions`, `Get-GPResultantSetOfPolicy` — the native toolkit this note's Hunt Evil and PowerShell sections lean on throughout |
| **`ActiveDirectory` PowerShell module** (RSAT) | Resolving OU/domain/site objects that GPOs link to, and the WMI filter objects a GPO may carry |
| **Group Policy Management Console (`gpmc.msc`)** | The standard GUI for browsing links, inheritance (including Block Inheritance/Enforced flags visually), security filtering, and WMI filters without dropping to raw AD/SYSVOL inspection |
| **Local Group Policy Editor (`gpedit.msc`)** | GUI for editing the Local GPO and, where present, the Administrators/Non-Administrators/user-specific MLGPO layers — availability varies by Windows SKU |
| **`LGPO.exe`** (Microsoft Security Compliance Toolkit) | Command-line local-policy export/import/backup — works even on SKUs where `gpedit.msc` isn't installed |
| **`rsop.msc`** | GUI Resultant Set of Policy viewer — effective-policy depth is `04 - Domain-Joined Host GPO Investigation`'s territory, but the tool itself belongs on this note's roster as foundational |
| **`gpresult` / `gpupdate`** | Native CLI tools for effective-policy reporting and manual refresh — depth on `gpresult` output interpretation lives in `04` |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Full SYSVOL folder structure, GPC AD attributes, FRS/DFSR replication, GPT/GPC version-desync detection | [01 - Storage, Replication and Version Synchronization](<01 - Storage, Replication and Version Synchronization.md>) |
| `Registry.pol` binary format, GPP and the legacy `cpassword` flaw, Client-Side Extensions, ADMX/ADML templates | [02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates)](<02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>) |
| DC-side investigation workflow, `gpLink` resolution, event 5136, `repadmin`-based provenance | [03 - Domain Controller GPO Investigation](<03 - Domain Controller GPO Investigation.md>) |
| Domain-joined-host investigation: `gpresult`/RSOP depth, local GPO cache artifacts, GroupPolicy operational event IDs, last-applied history | [04 - Domain-Joined Host GPO Investigation](<04 - Domain-Joined Host GPO Investigation.md>) |
| The T1484.001 attack technique in full, mass-deployment abuse patterns, and this folder's consolidated hunt/red-flags reference | [05 - GPO Abuse, Hunting and Detection](<05 - GPO Abuse, Hunting and Detection.md>) |
| AD object/Kerberos/domain-controller forensic fundamentals this folder builds on top of | [Active Directory & Domain Forensic Artifacts](<../05b - Active Directory & Domain Forensic Artifacts.md>) |
| GPO as the mechanism that establishes a fleet-wide configuration baseline | [Enterprise Management and Baseline](<../22 - Enterprise Management and Baseline.md>) |
| What's different about GPO/SYSVOL because the box under investigation *is* a Domain Controller | [Domain Controller — Role-Specific Forensics](<../23 - Special Services/Domain Controller — Role-Specific Forensics.md>) |
| Registry hive mechanics behind a GPO-pushed local setting's actual on-disk footprint | [Registry Forensics Fundamentals](<../04 - Registry Forensics Fundamentals.md>) |
| Scheduled tasks, Run keys, and services pushed via GPO as a persistence mechanism, once landed on an endpoint | [Persistence Mechanisms](<../10 - Persistence Mechanisms>) |

## Resources

- Microsoft Learn — Group Policy overview and core concepts: https://learn.microsoft.com/windows/win32/group-policy/group-policy-start-page
- Microsoft Learn — Group Policy processing and precedence (inheritance, blocking, enforcement, loopback, filtering): https://learn.microsoft.com/windows/win32/group-policy/group-policy-processing
- Microsoft Learn — Group Policy security filtering and WMI filtering concepts, consulted rather than copied verbatim
- MITRE ATT&CK — T1484.001 (Group Policy Modification): https://attack.mitre.org/techniques/T1484/001/
