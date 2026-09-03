# GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates)

A GPO is not one thing — it's a container for at least six structurally different content types, each processed by its own client-side mechanism and each leaving its own file-level footprint in the GPT. **GPO/00** covers what GPO *is* and how it's applied (LSDOU, inheritance, local vs domain GPO); **GPO/01** covers *where* all of the files below physically sit inside the SYSVOL/GPT folder tree and how that tree stays in sync with its AD-side twin. This note assumes both and goes one layer deeper: what's actually *inside* those files — `Registry.pol`'s binary layout, the Client-Side Extensions that process each content type, the full Group Policy Preferences (GPP) file family and its legacy `cpassword` flaw, logon/startup/shutdown scripts, `GptTmpl.inf` security templates, and ADMX/ADML Administrative Templates. For the attack-technique narrative that ties all of this content back to T1484.001 and the consolidated hunting/detection workflow, see **GPO/05**.

The throughline across every content type below is the same: a GPO's payload is only as trustworthy as the SYSVOL file it's read from, and several of these formats were designed decades apart with wildly different security assumptions — a binary registry format meant to be opaque, an XML preference format that shipped with a **published** decryption key, and a template-definition format (ADMX) that a Central Store will load and display as legitimate regardless of who dropped it there.

> 🔴 **Any `cpassword` attribute found in a SYSVOL GPP XML file (`Groups.xml`, `Drives.xml`, `ScheduledTasks.xml`, `Services.xml`, `DataSources.xml`) is a decryptable, clear-text-equivalent credential — treat it as compromised the moment you find it, regardless of whether you can prove active abuse.** Microsoft had to publish the AES key used to "encrypt" `cpassword` so client-side extensions could decrypt it to apply the setting, which means any authenticated domain user who can read SYSVOL — everyone, by default, since SYSVOL is a world-readable share — can decrypt it just as easily. MS14-025 (2014) stopped GPMC from creating *new* `cpassword` entries; it did not strip existing ones, which is why this is still routinely found in legacy or neglected AD environments over a decade later.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Registry.pol — The Binary Format Behind Registry-Based Settings](#registrypol--the-binary-format-behind-registry-based-settings)
- [Client-Side Extensions (CSEs) — What Actually Processes Each Content Type](#client-side-extensions-cses--what-actually-processes-each-content-type)
- [Group Policy Preferences (GPP) — The File Family](#group-policy-preferences-gpp--the-file-family)
  - [The cpassword / MS14-025 Vulnerability](#the-cpassword--ms14-025-vulnerability)
- [Logon, Startup, and Shutdown Scripts](#logon-startup-and-shutdown-scripts)
- [Security Templates — GptTmpl.inf](#security-templates--gpttmplinf)
- [Administrative Templates (ADMX/ADML)](#administrative-templates-admxadml)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, content-level triage — every command below reads directly from SYSVOL or a GPO's own attributes, no third-party parser required for the initial sweep.

```powershell
# Any SYSVOL GPP XML file still carrying a cpassword attribute - the single highest-confidence finding in this note
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter *.xml -ErrorAction SilentlyContinue |
    Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Line -notmatch 'cpassword=""' }

# Read one specific registry-based setting straight out of a GPO's Registry.pol without a standalone parser
Get-GPRegistryValue -Guid <GPOGuid> -Key 'HKLM\Software\Policies\<Vendor>\<Product>' -ValueName '<ValueName>'

# Every GPP ScheduledTasks.xml across every GPO in SYSVOL - inventory pass for the scheduled-task-via-GPO abuse pattern
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter ScheduledTasks.xml -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime

# Every GptTmpl.inf security template modified in the last 30 days - the Restricted Groups / audit-policy tampering angle
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter GptTmpl.inf -ErrorAction SilentlyContinue |
    Where-Object LastWriteTime -gt (Get-Date).AddDays(-30) | Select-Object FullName, LastWriteTime

# ADMX files in the Central Store - eyeball against a known-good baseline for anything unexpected/custom
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\PolicyDefinitions" -Filter *.admx -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime, Length

# CSE GUIDs a specific GPO actually references - tells you what TYPES of settings it pushes without opening the full GPO report
Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer' -and cn -eq '{$GpoGuid}'" -Properties gPCMachineExtensionNames, gPCUserExtensionNames |
    Select-Object gPCMachineExtensionNames, gPCUserExtensionNames

# Logon/startup/shutdown script files across all GPOs, most recently written first - a timestamp outside the change-management calendar is the tell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.ps1, *.bat, *.vbs, *.cmd -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\Scripts\\(Startup|Shutdown|Logon|Logoff)\\' } | Sort-Object LastWriteTime -Descending

# Full GPP file-family inventory across SYSVOL - broader than just the cpassword hits above
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include Groups.xml, Drives.xml, Services.xml, ScheduledTasks.xml, Printers.xml, DataSources.xml, Registry.xml -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime
```

## Registry.pol — The Binary Format Behind Registry-Based Settings

`Registry.pol` is the file that encodes every Administrative-Template registry-key/value setting a GPO is configured to push. It sits under `Machine\` or `User\` inside a GPO's GPT structure — see **GPO/01** for the full folder tree; this note only cares about what's *inside* the file, not where the folder sits.

It is a **binary format**, not human-readable in a text editor. Conceptually, the layout is simple even though it isn't plain text:

| Section | What it holds |
|---|---|
| Signature | A fixed 4-byte magic value that reads as the ASCII characters `PReg` — the first thing any parser checks to confirm it's looking at a real `.pol` file |
| Version | A 4-byte version field (the format has stayed at version 1 since introduction) |
| Records (repeated) | A sequence of bracketed entries, each shaped roughly as `[key;value;type;size;data]` — the registry key path and value name as null-terminated Unicode strings, a 4-byte code identifying the `REG_*` data type (`REG_SZ`, `REG_DWORD`, `REG_BINARY`, `REG_MULTI_SZ`, etc.), a 4-byte length, and the raw data bytes themselves |

That's deliberately a conceptual description, not a byte-offset map — this isn't a hex-editor-driven note the way `NTFS/` is, and the practical point holds either way: reading `Registry.pol` directly requires a purpose-built parser. Hedge on the exact current name/version of that parser rather than asserting one; tooling in this space has shifted over the years, so confirm what's current at investigation time.

**The practical investigative workflow runs backward, not forward.** An analyst rarely opens `Registry.pol` as a starting point. The far more common sequence is:

1. Notice an anomalous registry value on an endpoint (via note 04's registry-forensics mechanics — hive structure, transaction logs, last-write timestamps).
2. Confirm it traces back to a GPO — via `gpresult`/RSOP on the endpoint (**GPO/04**'s territory) or by reviewing SYSVOL directly.
3. Only then open that GPO's `Registry.pol` to confirm the setting was pushed *deliberately*, and pair it with the GPC's version/modification metadata (**GPO/03**) to establish when and by whom.

Treat `Registry.pol` as the **confirmation step at the end of that chain**, not the starting point — the practical effect of any GPO-pushed registry setting shows up on the endpoint as an ordinary registry write once the policy applies, indistinguishable from any other registry change until you go looking for its source.

To read a specific registry-based setting using PowerShell straight out of a GPO's `Registry.pol` without a standalone parser, via the native `GroupPolicy` module:

```powershell
Get-GPRegistryValue -Guid <GPOGuid> -Key 'HKLM\Software\Policies\<Vendor>\<Product>' -ValueName '<ValueName>'
```

## Client-Side Extensions (CSEs) — What Actually Processes Each Content Type

Every content type in this note — Registry settings, Scripts, Security Templates, Software Installation, Folder Redirection, and each individual GPP preference area — is applied on the client by its own **Client-Side Extension (CSE)**: a DLL that knows how to read one specific slice of GPT content and turn it into an actual change on the machine. A GPO's report can list dozens of configured settings, but nothing happens on the endpoint until the corresponding CSE runs during a policy refresh.

Each CSE is identified by a **GUID pair** — a client-side extension GUID (which DLL processes the content) and a tool-extension GUID (which GPMC/editor snap-in was used to author it). Both GUIDs for every CSE actually configured in a GPO are recorded on the GPC AD object, in the `gPCMachineExtensionNames` and `gPCUserExtensionNames` attributes — the two attributes **GPO/01** introduces structurally as part of the GPC object layout. This note is where those attributes' *meaning* lives: they're a curly-braced, semicolon-delimited list of GUID pairs, and Windows consults them at refresh time to decide which CSEs even need to run for a given GPO, skipping the rest for performance.

**The forensic angle:** reading the CSE GUID list off a GPO's GPC object tells you what *types* of settings it actually pushes without opening the full `Get-GPOReport` output. A GPO whose `gPCMachineExtensionNames` includes the GPP Scheduled Tasks CSE is worth a closer look before you've read a single setting inside it — the presence of that GUID alone confirms the GPO is capable of dropping a scheduled task on every computer in its scope.

A handful of the most well-documented CSE GUIDs, useful as recognition anchors — verify against current Microsoft Learn documentation before relying on any of these in a report, since the authoritative, complete list (including every individual GPP preference-area CSE) is maintained there, not reproduced exhaustively here:

| CSE | Client-side extension GUID (commonly cited) |
|---|---|
| Registry | `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` |
| Scripts | `{42B5FAAE-6536-11D2-AE5A-0000F87571E3}` |
| Security | `{827D319E-6EAC-11D2-A4EA-00C04F79F83A}` |
| Software Installation | `{C6DC5466-785A-11D2-84D0-00C04FB169F7}` |
| Folder Redirection | `{25537BA6-77A8-11D2-9B6C-0000F8080861}` |

GPP's individual preference areas (Scheduled Tasks, Drive Maps, Local Users and Groups, etc.) each register their own separate CSE beyond the core five above — Microsoft Learn's client-side extension reference is the place to confirm those exact GUIDs rather than working from memory here.

## Group Policy Preferences (GPP) — The File Family

GPP, introduced with Server 2008, extended GPO beyond enforced policy settings into **preferences** — items an administrator configures once that get pushed and applied on the client, covering local account/group management, drive mappings, scheduled tasks, services, data sources, and printers. Each preference area is its own XML file, living under `Machine\Preferences\<Area>\` or `User\Preferences\<Area>\` in the GPT (see **GPO/01** for the folder tree itself).

| File | Preference area | What it configures |
|---|---|---|
| `Groups.xml` | Local Users and Groups | Local group membership changes, and local user account creation/modification — **including setting that account's password**, historically via the `cpassword` mechanism below |
| `Drives.xml` | Drive Maps | Mapped network drives, including credentials for connecting under an alternate account when the mapping requires one |
| `ScheduledTasks.xml` | Scheduled Tasks (Preferences) | Scheduled task definitions pushed via GPP — distinct from a task created directly through Task Scheduler, though the end result on disk is the same task-engine footprint covered in [10/Scheduled Tasks](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |
| `Services.xml` | Services | Service startup-type and logon-account changes, including stored service-account credentials |
| `DataSources.xml` | Data Sources | ODBC data source definitions, including stored connection credentials |
| `Printers.xml` | Printers | Printer connection deployment |
| `Registry.xml` | Registry (Preferences) | GPP's **own, separate** registry-preference mechanism — see the distinction below |

🔴 **`Registry.xml` (GPP) and `Registry.pol` (GPO-native) are two different mechanisms and a common point of confusion.** Both end up writing registry values, but they get there through entirely different code paths with different behavior once the GPO stops applying:

| | `Registry.pol` | `Registry.xml` (GPP) |
|---|---|---|
| Mechanism | Native Administrative Templates registry policy | GPP's own registry preference extension |
| Format | Binary | XML (plain text, human-readable) |
| Location in GPT | `Machine\` or `User\` root | `Machine\Preferences\Registry\` or `User\Preferences\Registry\` |
| CSE | Registry CSE (see above) | A separate GPP Registry CSE |
| Behavior when the GPO no longer applies | Values under a `Policies` registry path are non-tattooing — they're removed/reverted automatically | GPP preferences **tattoo** by default — the value stays on the machine after the GPO is unlinked, unless "Remove this item when it is no longer applied" was explicitly configured |
| Editing tool in GPMC | Computer/User Configuration → **Policies** → Administrative Templates | Computer/User Configuration → **Preferences** → Windows Settings → Registry |

That tattooing behavior is worth carrying into an investigation on its own: a registry value written by a GPP `Registry.xml` preference can persist on a host long after the responsible GPO was deleted or unlinked, which makes "what GPO caused this" harder to answer from the current GPO list alone — the GPO that pushed it may no longer exist.

### The cpassword / MS14-025 Vulnerability

Several GPP files above carry a credential field for the account they configure — a local account's password in `Groups.xml`, a drive-mapping account's password in `Drives.xml`, a service or scheduled-task run-as account's password in `Services.xml`/`ScheduledTasks.xml`, and a data-source connection's password in `DataSources.xml`. That credential is stored in an XML attribute named **`cpassword`**, nominally protected with AES-256 encryption.

The flaw is structural, not implementation error: the client-side extensions applying these settings need to decrypt `cpassword` to actually use the credential, which means the decryption key has to exist somewhere those extensions can reach it. Microsoft's solution was to **publish the AES key** in the GPP documentation — meaning the "encryption" provides no real protection at all. Any authenticated domain user who can read a `cpassword`-bearing XML file — which is any user, since SYSVOL is a world-readable share by default — can decrypt the credential in a single offline step with publicly known key material.

The single riskiest instance of this is `Groups.xml`'s local-account-creation scenario: an administrator configures GPP to *create* a new local account on every targeted computer and set its initial password via `cpassword`. Any attacker who can read that GPO's SYSVOL folder now has a decrypted, working credential for a local account that may exist, unattended, on every machine that GPO ever applied to.

- **Patched via MS14-025** (2014) — after the patch, GPMC refuses to let an administrator create a *new* GPP entry containing a `cpassword` value. It does **not** retroactively strip `cpassword` from entries that already existed before the patch was applied.
- 🔴 **Still routinely found in legacy or neglected AD environments** — domains that predate the patch and were never cleaned up, or where an admin recreated an old GPP entry by copy-pasting pre-patch XML. Tools like **Get-GPPPassword** (part of PowerSploit) and the **Metasploit `smb_enum_gpp`** module automate finding and decrypting every `cpassword` in a domain's SYSVOL in seconds — meaning any attacker with ordinary domain read access and standard, freely available tooling would find the same thing an analyst does.

To search every GPP XML file in SYSVOL using PowerShell for a live `cpassword` attribute, natively, no third-party module:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include Groups.xml, Drives.xml, Services.xml, ScheduledTasks.xml, DataSources.xml -ErrorAction SilentlyContinue |
    Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Line -notmatch 'cpassword=""' } |
    Select-Object Path, LineNumber, Line
```

To pull the account name using PowerShell each hit is tied to, alongside the file it came from, so a finding maps directly to "which account needs rotating":

```powershell
Select-String -Path "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\*\*\Preferences\*\*.xml" -Pattern 'cpassword="[^"]+"' |
    ForEach-Object {
        $userName = if ($_.Line -match 'userName="([^"]+)"') { $Matches[1] } else { '(unresolved)' }
        [PSCustomObject]@{ Path = $_.Path; Account = $userName }
    }
```

To sweep every DC's SYSVOL replica using PowerShell (in case of an FRS/DFSR replication gap, per **GPO/01**), not just the one nearest the analyst's workstation:

```powershell
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    Get-ChildItem "\\$dc\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.xml -ErrorAction SilentlyContinue |
        Select-String -Pattern 'cpassword="[^"]+"' | Where-Object { $_.Line -notmatch 'cpassword=""' } |
        Select-Object @{N='DC'; E={$dc}}, Path
}
```

To capture evidence and rotate the compromised credential using PowerShell (the raw XML, the resolved account name, before touching anything) — if the account is domain-based use `Set-ADAccountPassword`, if it's local to each target machine, rotate it host-by-host:

```powershell
# Evidence capture, before any remediation step
Copy-Item '\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\Machine\Preferences\Groups\Groups.xml' -Destination 'C:\hunt\evidence\Groups_GPOGUID.xml'

# Domain account: rotate via ActiveDirectory module
Set-ADAccountPassword -Identity <CompromisedAccountName> -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New password')

# Local account, fleet-wide: rotate the same local account across every host it may have been pushed to
$newPassword = Read-Host -AsSecureString -Prompt 'New password for compromised local account'
Invoke-Command -ComputerName (Get-Content C:\hunt\hosts.txt) -ScriptBlock {
    param($NewPassword) Set-LocalUser -Name '<CompromisedAccountName>' -Password $NewPassword
} -ArgumentList $newPassword
```

Removing the `cpassword`-bearing GPP entry itself is best done through GPMC's Preferences editor rather than a raw SYSVOL file edit — a direct file edit bypasses the GPC version-increment that normal tooling performs, producing exactly the GPT/GPC desync **GPO/01** flags as its own red flag.

## Logon, Startup, and Shutdown Scripts

Script-based settings live under fixed subfolders of the GPT, split by scope and trigger:

| Location | Scope | Trigger |
|---|---|---|
| `Machine\Scripts\Startup\` | Computer | System boot |
| `Machine\Scripts\Shutdown\` | Computer | System shutdown |
| `User\Scripts\Logon\` | User | User logon |
| `User\Scripts\Logoff\` | User | User logoff |

Because these fire on every boot or logon within a GPO's scope, they're one of the plainest mass-deployment mechanisms available — a single script drop reaches every targeted computer or user at the next trigger, no interaction required.

**What a malicious deployment looks like:**

- Script content that's a downloader (pulls and executes a second-stage payload) or a credential harvester, rather than anything resembling ordinary logon housekeeping (mapping a drive, launching a login banner, syncing a config file).
- File timestamps on the script itself inconsistent with the organization's documented change-management calendar — a script added or modified outside any known maintenance window.
- A script referencing an unusual binary, LOLBAS command, or encoded PowerShell, mirroring the same red flags note 10's persistence-mechanism notes already train an analyst to spot in a Run key or scheduled task — here, just distributed via GPO instead of planted host-by-host.

To list every script file under any GPO's script subfolders using PowerShell, across all four locations:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.ps1, *.bat, *.vbs, *.cmd -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\Scripts\\(Startup|Shutdown|Logon|Logoff)\\' } |
    Select-Object FullName, LastWriteTime
```

To pull the actual content of every discovered script using PowerShell for eyeball review, flagging anything that references a download cmdlet or an encoded command:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.ps1, *.bat, *.vbs, *.cmd -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\Scripts\\(Startup|Shutdown|Logon|Logoff)\\' } |
    ForEach-Object {
        $content = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue
        if ($content -match 'Invoke-WebRequest|DownloadString|-[Ee]nc(odedCommand)?\s') {
            [PSCustomObject]@{ Path = $_.FullName; LastWriteTime = $_.LastWriteTime; Flagged = $true }
        }
    }
```

To preserve the script and its metadata using PowerShell for the case file, then remove it — remove the file itself and its reference within the GPO's script assignment via GPMC (a raw SYSVOL deletion alone can leave a dangling reference in the GPO's script configuration):

```powershell
Copy-Item '\\<domain>\SYSVOL\<domain>\Policies\{<GPO-GUID>}\Machine\Scripts\Startup\suspicious.ps1' -Destination 'C:\hunt\evidence\suspicious_startup.ps1'
```

## Security Templates — GptTmpl.inf

`GptTmpl.inf` lives under `Machine\Microsoft\Windows NT\SecEdit\` in the GPT and encodes a GPO's security-template settings — the same INF-style format the standalone Security Configuration and Analysis tooling uses, just deployed via GPO instead of applied locally.

| Section (as it appears in the file) | What it encodes |
|---|---|
| `[Group Membership]` | **Restricted Groups** — which accounts/groups are forced into (or out of) a target local group, such as local Administrators, on every computer in scope |
| `[System Access]` | Password policy (length, complexity, age) and account lockout policy |
| `[Event Audit]` | Legacy (non-Advanced) audit policy categories |
| `[Privilege Rights]` | User rights assignments — who can log on locally, log on as a service, act as part of the operating system, etc. |

**The security-tampering angle:** because Restricted Groups is enforced fleet-wide at every refresh, adding an account to the `[Group Membership]` section's local Administrators entry is a single-edit way to grant persistent local-admin rights across every computer a GPO touches — functionally identical in effect to note 10's Run-key/scheduled-task abuse, just aimed at the privilege layer instead of the execution layer. Weakening `[Event Audit]` domain-wide (dropping audit categories that would otherwise generate the event IDs the rest of this module depends on) is the corresponding "turn off the cameras" move, and is worth checking any time an investigation is coming up unexpectedly quiet on event coverage that should be there.

To locate and read a specific GPO's security template using PowerShell directly from SYSVOL:

```powershell
Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{<GPO-GUID>}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf" -Raw
```

To pull just the Restricted Groups section using PowerShell across every GPO in the domain, the fastest way to see who's been granted local-group membership fleet-wide:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Filter GptTmpl.inf -ErrorAction SilentlyContinue | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -match '(?s)\[Group Membership\](.*?)\r?\n\[') {
        [PSCustomObject]@{ Path = $_.FullName; RestrictedGroups = $Matches[1].Trim() }
    }
}
```

## Administrative Templates (ADMX/ADML)

ADMX/ADML define what a policy setting even *is* and what it looks like in the GPO editor — they're the schema layer sitting above `Registry.pol`, not a content type an endpoint applies directly.

| File type | Role |
|---|---|
| **ADMX** | Language-neutral policy *definition* — the setting's name, its registry key/value target, valid data types/ranges, and supported OS versions |
| **ADML** | Language-specific *display strings* for that same definition — the friendly name and explanatory text shown in the GPO editor UI for a given locale |

Together they determine what shows up as an editable setting in GPMC/`gpedit.msc` — an ADMX with no matching ADML for the admin's locale won't render properly, and a setting with no ADMX at all can't be configured through the GUI regardless of whether the underlying registry value exists.

**Central Store vs local definitions:**

| Source | Location | Behavior |
|---|---|---|
| **Central Store** | `SYSVOL\<domain>\Policies\PolicyDefinitions\` | If present, GPMC and `gpedit.msc` on any domain-joined admin workstation read definitions from here instead of the local machine — ensures every administrator sees the same, consistent setting catalog regardless of which workstation they're editing from |
| **Local definitions** | `%SystemRoot%\PolicyDefinitions\` | Used only when no Central Store exists; each admin workstation's local ADMX/ADML set could in principle drift from another's |

🔴 **A custom or third-party ADMX file dropped into the Central Store looks completely legitimate in GPMC.** It renders in the GPO editor exactly like any Microsoft-authored policy — a friendly name, a description, a configurable value — while actually targeting a registry key of the attacker's or vendor's choosing, one that standard Microsoft documentation says nothing about. Because the Central Store is just a SYSVOL file share, anyone with write access to it (the same access level needed to tamper with any other content in this note) can add or modify an ADMX file there. A modified or unexpected ADMX file in the Central Store — one that doesn't match a known-good baseline or a legitimate vendor's published template — is itself worth investigating, independent of anything it appears to configure.

To inventory every ADMX file currently in the Central Store using PowerShell:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\PolicyDefinitions" -Filter *.admx -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime, Length
```

To flag ADMX files using PowerShell whose name doesn't match Microsoft's shipped baseline set, as a first-pass filter for anything custom/third-party (adjust the known-set list to the organization's actual baseline before trusting this as exhaustive):

```powershell
$knownMicrosoftAdmx = @('WindowsUpdate.admx', 'GroupPolicy.admx', 'AppCompat.admx') # illustrative subset only - build a real baseline from a known-good Central Store snapshot
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\PolicyDefinitions" -Filter *.admx -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notin $knownMicrosoftAdmx } | Select-Object Name, LastWriteTime
```

To hash every ADMX file using PowerShell for comparison against a known-good Central Store snapshot from before the suspected incident window:

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\PolicyDefinitions" -Filter *.admx -ErrorAction SilentlyContinue |
    Get-FileHash -Algorithm SHA256 | Select-Object Path, Hash
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `cpassword` attribute present in any SYSVOL GPP XML file | Decryptable, clear-text-equivalent credential — MS14-025 doesn't retroactively strip it; treat as compromised regardless of proof of active abuse |
| Unexpected or unsigned ADMX file in the Central Store not matching a known baseline | Can define a policy setting that looks legitimate in GPMC while pushing a vendor- or attacker-defined registry value undocumented by Microsoft |
| Logon/startup/shutdown script content resembling a downloader/credential harvester, or a script timestamp outside the change-management calendar | Mass-deployment persistence or payload delivery via a mechanism that fires on every boot/logon in scope |
| GPP `ScheduledTasks.xml` entry running an unusual binary/LOLBAS command as SYSTEM or a high-privilege account | The GPP scheduled-task abuse pattern — fans out to every computer in the GPO's scope at next refresh |
| Restricted Groups (`GptTmpl.inf` `[Group Membership]`) adding an unexpected account to local Administrators | Domain-wide privilege-escalation push via a single security-template edit |
| `GptTmpl.inf` `[Event Audit]` section weakened relative to the organization's documented baseline | "Turn off the cameras" — check whenever event-log coverage is unexpectedly thin during an investigation |
| A GPP `Registry.xml` value present with no corresponding entry the organization's Administrative-Template baseline would explain | Pushed via the lesser-scrutinized preference path rather than native Administrative Templates — also remember GPP preferences tattoo and can outlive the GPO that set them |

## Tooling

| Tool | Use |
|---|---|
| **Get-GPPPassword** (PowerSploit) | Automates finding and decrypting `cpassword` values across a domain's SYSVOL in one pass |
| **Metasploit `smb_enum_gpp` module** | Same discovery/decryption workflow against SYSVOL over SMB, run from within Metasploit |
| **A `Registry.pol` parser** | Needed to read `Registry.pol` content directly, beyond what `Get-GPRegistryValue` retrieves one setting at a time; hedge on the exact current tool name/version — confirm what's current at investigation time |
| **Group Policy Management Console (`gpmc.msc`)** | Standard GUI for browsing and safely editing every content type in this note — GPP preference nodes, Administrative Templates, and security settings — without the GPC/GPT desync risk of a raw SYSVOL file edit |

## Correlate With

| To go deeper on… | Open |
|---|---|
| GPO fundamentals, LSDOU/inheritance, local vs domain GPO | [GPO/00 - GPO Fundamentals and Architecture](<00 - GPO Fundamentals and Architecture.md>) |
| SYSVOL/GPT folder structure, GPC attributes, GPT/GPC version sync — where all the content in this note physically lives | [GPO/01 - Storage, Replication and Version Synchronization](<01 - Storage, Replication and Version Synchronization.md>) |
| DC-side GPO investigation workflow, event 5136 | [GPO/03 - Domain Controller GPO Investigation](<03 - Domain Controller GPO Investigation.md>) |
| `gpresult`/RSOP, local GPO cache artifacts on a workstation | [GPO/04 - Domain-Joined Host GPO Investigation](<04 - Domain-Joined Host GPO Investigation.md>) |
| Full T1484.001 attack narrative, consolidated cross-folder hunting/detection, remediation | [GPO/05 - GPO Abuse, Hunting and Detection](<05 - GPO Abuse, Hunting and Detection.md>) |
| Registry mechanics behind a pushed setting's actual on-disk footprint | [04 - Registry Forensics Fundamentals](<../04 - Registry Forensics Fundamentals.md>) |
| Scheduled-task persistence mechanics, independent of the GPP delivery mechanism | [Scheduled Tasks](<../10 - Persistence Mechanisms/Scheduled Tasks.md>) |
| Run/RunOnce autostart persistence pushed via Registry.pol | [Autostart (Run/RunOnce) Keys](<../10 - Persistence Mechanisms/Autostart (Run-RunOnce) Keys.md>) |

## Resources

- Microsoft MS14-025 (Group Policy Preferences cpassword) advisory: https://learn.microsoft.com/security-updates/securitybulletins/2014/ms14-025
- Microsoft Learn — Group Policy Preferences overview and each preference extension's documentation, consulted rather than fabricated to a specific URL for every file type
- Microsoft Learn — Client-side extension GUID reference (the authoritative, complete CSE GUID list, including per-GPP-area CSEs not enumerated in full here)
- Microsoft Learn — Administrative Templates (ADMX/ADML) and the Central Store
- PowerSploit — `Get-GPPPassword`: https://github.com/PowerShellMafia/PowerSploit
- Rapid7 Metasploit — `smb_enum_gpp` module documentation
