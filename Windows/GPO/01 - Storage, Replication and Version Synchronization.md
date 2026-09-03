# Storage, Replication and Version Synchronization

A Group Policy Object is not one thing sitting in one place — it is two independently-stored halves that a mountain of tooling (GPMC, the `GroupPolicy` PowerShell module, background replication) works continuously to keep in lockstep, and forensic value routinely shows up precisely where that lockstep breaks. **[00 - GPO Fundamentals and Architecture](00%20-%20GPO%20Fundamentals%20and%20Architecture.md)** already introduced the GPT/GPC split at a conceptual level — this note is the full structural depth behind it: the exact folder tree on disk, the exact AD attributes that make the two halves point at each other, how SYSVOL actually gets copied between Domain Controllers, and the version-tracking mechanics that let an analyst prove (or disprove) that a GPO's two halves currently agree.

This note is deliberately about **mechanics and plumbing**, not content or workflow. What's actually inside `Registry.pol`, the GPP file family, and `GptTmpl.inf` is **[02 - GPO Content Deep Dive](02%20-%20GPO%20Content%20Deep%20Dive%20%28Registry.pol%2C%20GPP%2C%20Scripts%2C%20Security%20Templates%29.md)**'s job — this note only tells you where those files live and what folder to go looking in. The narrative of investigating a specific DC during an incident, including what a malicious GPO change looks like from the AD-object side, is **[03 - Domain Controller GPO Investigation](03%20-%20Domain%20Controller%20GPO%20Investigation.md)**'s job — that note consumes the replication-health commands built here rather than re-deriving them.

> 🔴 **GPT (SYSVOL) version and GPC (AD object) version are supposed to move together, and a mismatch is a lead, not a footnote.** Every GPO edit made through normal tooling — GPMC, `Set-GPRegistryValue`, `Set-GPPrefRegistryValue` — bumps both halves' version counters in the same operation. A raw file edit on the SYSVOL share that bypasses that tooling (hand-editing `Registry.pol` or a GPP XML file directly, or restoring an old file over a current one) changes policy *content* while leaving the AD object's `versionNumber` looking untouched. Anywhere the two can be compared — one GPO, or the whole domain in one pass — a desync is one of the highest-signal indicators in this entire folder that a GPO was tampered with outside the audited path.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [GPT — the SYSVOL Folder-Tree Structure](#gpt--the-sysvol-folder-tree-structure)
- [GPT.INI — the Version File](#gptini--the-version-file)
- [GPC — the AD-Side Object](#gpc--the-ad-side-object)
- [GPT vs GPC — Two Halves, One GPO](#gpt-vs-gpc--two-halves-one-gpo)
- [gpLink — Applying a GPO to a Scope](#gplink--applying-a-gpo-to-a-scope)
- [Replication: FRS vs DFSR](#replication-frs-vs-dfsr)
- [GPT/GPC Version Desynchronization — Detection Workflow](#gptgpc-version-desynchronization--detection-workflow)
- [Replication Health Checking](#replication-health-checking)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native tooling first: the `GroupPolicy` module (RSAT, same tier as `ActiveDirectory` elsewhere in this repo) for the AD/GPC side, plain file reads for the SYSVOL/GPT side, and `dfsrdiag`/`dfsrmig` — DC-specific binaries with no PowerShell-cmdlet replacement — for replication health.

```powershell
# GPT.INI vs GPC version across every GPO in the domain in one pass - the top red flag in this note, in one line
Get-GPO -All | ForEach-Object {
    $gptIni = Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($_.Id)}\GPT.INI" -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Name = $_.DisplayName; GPC_Raw = $_.User.DSVersion + $_.Computer.DSVersion; GPT_Raw = ($gptIni | Select-String '^Version=(\d+)').Matches.Value -replace 'Version=' }
}

# gPCFileSysPath / flags / CSE extension GUIDs for every GPO, straight off the AD object - the raw GPC attributes this note builds on
Get-ADObject -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Filter {objectClass -eq 'groupPolicyContainer'} -Properties displayName,versionNumber,gPCFileSysPath,flags,gPCMachineExtensionNames,gPCUserExtensionNames |
    Select-Object displayName,versionNumber,gPCFileSysPath,flags

# gpLink dump for a specific container - which GPOs are actually linked here, and in what raw order
Get-ADObject -Identity 'OU=Workstations,DC=example,DC=com' -Properties gPLink | Select-Object -ExpandProperty gPLink

# DFSR replication state for SYSVOL - confirms replication is actively happening, not stalled
dfsrdiag replicationstate

# FRS -> DFSR migration state - the real-world "stuck mid-migration" gotcha
dfsrmig /getmigrationstate

# DFSR backlog between two specific DCs for the SYSVOL replication group - non-zero/growing means one side is stale
dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:DC01 /rmem:DC02

# Every DC's own copy of a GPO's GPT.INI, read directly - the cross-DC consistency check, one GPO at a time
(Get-ADDomainController -Filter *).HostName | ForEach-Object {
    Get-Content "\\$_\SYSVOL\$env:USERDNSDOMAIN\Policies\{<GPOGuid>}\GPT.INI" -ErrorAction SilentlyContinue |
        Select-String '^Version=' | ForEach-Object { [PSCustomObject]@{ DC = $_; Version = $_ } }
}
```

## GPT — the SYSVOL Folder-Tree Structure

The **GPT (Group Policy Template)** is the content half of a GPO — a folder tree living on the SYSVOL share, replicated identically to every Domain Controller servicing the domain. The folder's name is always the GPO's GUID, never its friendly display name; friendly-name resolution happens on the GPC side (below) or via `Get-GPO`/GPMC.

```
\\<domain>\SYSVOL\<domain>\Policies\
│
├── {31B2F340-016D-11D2-945F-00C04FB984F9}\        ← Default Domain Policy's GUID (well-known, built-in)
│   ├── GPT.INI                                     version tracking — see below
│   ├── Machine\                                     ← computer-side settings
│   │   ├── Registry.pol                             registry-based settings, binary format — full depth: GPO/02
│   │   ├── Scripts\
│   │   │   ├── Startup\                              scripts run at machine boot
│   │   │   └── Shutdown\                             scripts run at machine shutdown
│   │   ├── Preferences\                              GPP XML (Groups.xml, Drives.xml, ScheduledTasks.xml, ...) — full depth: GPO/02
│   │   └── Microsoft\Windows NT\SecEdit\
│   │       └── GptTmpl.inf                           security template (Restricted Groups, audit/password policy) — full depth: GPO/02
│   └── User\                                        ← user-side settings, mirrors Machine\'s shape
│       ├── Registry.pol                             HKCU-targeted registry settings
│       ├── Scripts\
│       │   └── Logon\                                scripts run at user logon
│       └── Preferences\                              user-context GPP XML
│
├── {6AC1786C-016F-11D2-945F-00C04FB984F9}\        ← Default Domain Controllers Policy's GUID (well-known, built-in)
│   └── ... (same shape as above)
│
└── {<GUID>}\                                        ← one folder per additional GPO created in the domain
    └── ...
```

A few structural notes worth calling out explicitly:

- Not every subfolder exists for every GPO — a GPO that has never had a startup script configured has no `Scripts\Startup\` folder at all. GPMC creates folders on demand as settings are configured, not up front.
- `Machine\` and `User\` are independently populated and independently versioned (see [GPT.INI](#gptini--the-version-file) below) — a GPO can have computer-side settings only, user-side settings only, or both, and the `flags` attribute on the GPC side (below) records which half is actually enabled.
- The two well-known GUIDs above (Default Domain Policy, Default Domain Controllers Policy) are created automatically when a domain is provisioned and are the same across every domain — recognizing them by GUID is a useful sanity check that you're looking at the built-in policies and not a lookalike.

To list every GPO folder actually present on SYSVOL and its last-write time using PowerShell, independent of what the AD side claims exists (catches an orphaned SYSVOL folder with no matching GPC object, or vice versa):

```powershell
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\" -Directory |
    Where-Object Name -match '^\{.*\}$' | Select-Object Name, LastWriteTime
```

To cross-reference that SYSVOL folder listing using PowerShell against the GPC objects in AD, surfacing either side missing the other (an orphaned SYSVOL folder with no AD object is a real-world artifact of an incompletely deleted GPO, and worth investigating on its own):

```powershell
$sysvolGuids = (Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\" -Directory |
    Where-Object Name -match '^\{.*\}$').Name
$gpcGuids = (Get-GPO -All).Id.Guid | ForEach-Object { "{$_}" }
Compare-Object -ReferenceObject $sysvolGuids -DifferenceObject $gpcGuids
```

## GPT.INI — the Version File

`GPT.INI` sits at the root of each GPO's SYSVOL folder and is the on-disk version record for that GPO's content:

```ini
[General]
Version=131233
displayName=New Group Policy Object
```

The `Version=` value is not a simple incrementing counter — it is a single 32-bit integer that packs **two independent 16-bit version numbers** into one field: the high-order 16 bits are the **User** version, the low-order 16 bits are the **Computer** version. This is exactly why `Get-GPO`'s output exposes `Computer.DSVersion` and `User.DSVersion` as two separate values even though `GPT.INI` shows one raw number — both the GPT-side `GPT.INI` and the GPC-side `versionNumber` AD attribute (below) use this identical packed encoding, which matters directly for the desync check later in this note: editing only computer-side settings bumps only the low 16 bits, so a naive "did the raw number change" comparison can miss a real edit if you're not decomposing the value.

| Field | Meaning |
|---|---|
| `Version=` | Packed 32-bit value: high word = User version, low word = Computer version |
| `displayName=` | The GPO's friendly name as of last GPMC save — cosmetic, not authoritative (the AD object's `displayName` attribute is authoritative; this is a convenience copy) |

To read one GPO's raw `GPT.INI` using PowerShell and decompose the packed version into its Computer/User halves without relying on `Get-GPO` at all (useful when working directly from a SYSVOL copy with no AD connectivity, e.g. a forensic image):

```powershell
$raw = (Get-Content '\\<domain>\SYSVOL\<domain>\Policies\{<GPOGuid>}\GPT.INI' | Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
$packed = [uint32]$raw
[PSCustomObject]@{
    Raw             = $packed
    ComputerVersion = $packed -band 0xFFFF
    UserVersion     = ($packed -shr 16) -band 0xFFFF
}
```

## GPC — the AD-Side Object

The **GPC (Group Policy Container)** is the AD object representing the GPO — it does not hold policy content itself, only metadata and the pointer back to the GPT.

| Fact | Detail |
|---|---|
| Location | `CN={GUID},CN=Policies,CN=System,DC=<domain>,DC=<tld>` — every GPC lives under the domain's **Group Policy Objects** container, one object per GPO |
| Object class | `groupPolicyContainer` |
| GUID | Matches the SYSVOL folder name for the same GPO exactly — this GUID is the join key between the two halves |

Key attributes:

| Attribute | What it holds |
|---|---|
| `versionNumber` | The GPC's own version counter — same packed-DWORD encoding as `GPT.INI`'s `Version=` field (high word = User, low word = Computer). This is the AD-side half of the desync check. |
| `gPCFileSysPath` | The literal UNC path pointer back to the GPT — e.g. `\\<domain>\SYSVOL\<domain>\Policies\{<GUID>}`. This attribute is the actual link between the two halves; everything else (matching GUIDs) is convention, but this is the pointer AD-aware tooling actually follows. |
| `gPCMachineExtensionNames` / `gPCUserExtensionNames` | Multi-valued strings listing the **Client-Side Extension (CSE)** GUID pairs relevant to this GPO's computer-side and user-side settings, respectively — this is the forward pointer that tells a client which CSE DLLs need to process this GPO at refresh time. What a CSE is and how it processes settings is fully **[02](02%20-%20GPO%20Content%20Deep%20Dive%20%28Registry.pol%2C%20GPP%2C%20Scripts%2C%20Security%20Templates%29.md)**'s territory — this note only notes that the pointer exists and lives here. |
| `flags` | A small bitmask recording which half of the GPO is enabled (below) |
| `displayName` | The GPO's authoritative friendly name |
| `whenChanged` | Coarse, object-level last-modification timestamp — see **[05b](../05b%20-%20Active%20Directory%20%26%20Domain%20Forensic%20Artifacts.md#ad-replication-metadata-for-timeline-corroboration)** for `repadmin /showobjmeta`'s per-attribute alternative, which is the tool of choice when `whenChanged` alone isn't granular enough |

The `flags` bitmask values:

| Value | Meaning |
|---|---|
| `0` | Both Computer and User settings enabled |
| `1` | User settings disabled |
| `2` | Computer settings disabled |
| `3` | Both Computer and User settings disabled |

To pull the GPC's key attributes for one GPO by GUID using PowerShell natively via ADSI (no `ActiveDirectory` or `GroupPolicy` module required — works even without RSAT):

```powershell
$domainDN = ([ADSI]'LDAP://RootDSE').defaultNamingContext
$gpo = [ADSI]"LDAP://CN={<GPOGuid>},CN=Policies,CN=System,$domainDN"
$gpo.Properties['displayName'], $gpo.Properties['versionNumber'], $gpo.Properties['gPCFileSysPath'], $gpo.Properties['flags']
```

To retrieve the same attributes using PowerShell modules (`GroupPolicy`/`ActiveDirectory`) for every GPO in the domain at once, with the `flags` bitmask decoded into plain text:

```powershell
$flagsMap = @{0='Both Enabled'; 1='User Disabled'; 2='Computer Disabled'; 3='All Disabled'}
Get-ADObject -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Filter {objectClass -eq 'groupPolicyContainer'} -Properties displayName,versionNumber,gPCFileSysPath,flags |
    Select-Object displayName, versionNumber, gPCFileSysPath, @{N='FlagsMeaning';E={$flagsMap[[int]$_.flags]}}
```

To resolve `gPCFileSysPath` using PowerShell against the live SYSVOL folder listing to confirm the pointer is actually valid (a GPC whose `gPCFileSysPath` points at a folder that doesn't exist, or points somewhere other than the expected `Policies\{same-GUID}` path, is itself an anomaly):

```powershell
Get-ADObject -SearchBase "CN=Policies,CN=System,$((Get-ADDomain).DistinguishedName)" -Filter {objectClass -eq 'groupPolicyContainer'} -Properties displayName,gPCFileSysPath |
    ForEach-Object {
        [PSCustomObject]@{
            Name          = $_.displayName
            FileSysPath   = $_.gPCFileSysPath
            PathResolves  = Test-Path $_.gPCFileSysPath
        }
    } | Where-Object { -not $_.PathResolves }
```

## GPT vs GPC — Two Halves, One GPO

| | GPT (Group Policy Template) | GPC (Group Policy Container) |
|---|---|---|
| What it is | The policy *content* | The policy's AD *metadata object* |
| Where it lives | `SYSVOL\<domain>\Policies\{GUID}\` on every DC | `CN={GUID},CN=Policies,CN=System,DC=...` |
| Replicated by | FRS or DFSR (file-based replication) | Standard AD replication (object-based, multi-master) |
| Version tracked in | `GPT.INI`'s `Version=` field | `versionNumber` attribute |
| Version encoding | Packed 32-bit: high word = User, low word = Computer | Identical packed 32-bit encoding |
| Points to the other half via | GUID matches the GPC's GUID (convention) | `gPCFileSysPath` (literal UNC pointer — the authoritative link) |
| What it holds | `Registry.pol`, scripts, GPP XML, `GptTmpl.inf` | `displayName`, `flags`, CSE extension-GUID lists, link/permission metadata |
| Forensic role | "What does the policy actually say to do" | "Is this GPO enabled, what does AD think its version is, where does AD think the content lives" |

## gpLink — Applying a GPO to a Scope

A GPO having a GPC and GPT does not, by itself, apply that GPO to anything — a GPO only takes effect once it is *linked* to a scope. That link is **not** an attribute on the GPO itself; it is the **`gpLink`** attribute set on the target container — an OU, a domain object, or a site object.

`gpLink` is a multi-valued string listing every GPO linked at that container, in the form:

```
[LDAP://cn={GUID1},cn=policies,cn=system,DC=example,DC=com;0][LDAP://cn={GUID2},cn=policies,cn=system,DC=example,DC=com;2]
```

Each bracketed entry is one link: the LDAP distinguished-name path to the GPC being linked, followed by a semicolon and a small options integer:

| Options value | Meaning |
|---|---|
| `0` | Link enabled, not enforced |
| `1` | Link disabled |
| `2` | Link enabled, enforced (No Override) |
| `3` | Link disabled, enforced |

The order links appear in this string reflects precedence at that single container — but hand-parsing that order to determine which GPO wins a setting conflict is exactly the kind of raw-string inference this repo prefers to avoid: `Get-GPInheritance` (below) returns the same links already resolved into GPMC's authoritative **Link Order** (1 = highest precedence at that container), so treat that cmdlet's output as ground truth rather than re-deriving order from the raw `gpLink` string by hand.

This is link-order precedence **within a single container only**. How that combines with inheritance from parent containers, Block Inheritance, Enforced links overriding Block Inheritance, security filtering, WMI filters, and loopback processing — the full **LSDOU** precedence chain across levels — is **[00](00%20-%20GPO%20Fundamentals%20and%20Architecture.md)**'s territory; this note stops at "here is the attribute and its raw format."

To read the raw `gpLink` value on a specific container using PowerShell natively (no module required):

```powershell
([ADSI]'LDAP://OU=Workstations,DC=example,DC=com').Properties['gPLink']
```

To retrieve the same information using PowerShell, resolved into GPMC's authoritative precedence order and enforcement state, via the native `GroupPolicy` module (preferred over hand-parsing the raw string above):

```powershell
Get-GPInheritance -Target 'OU=Workstations,DC=example,DC=com' |
    Select-Object -ExpandProperty GpoLinks | Select-Object DisplayName, Order, Enabled, Enforced
```

To find every container using PowerShell in the domain linking a specific GPO, useful for scoping-abuse triage (a GPO unexpectedly linked at the domain root instead of a narrow OU):

```powershell
Get-ADObject -Filter {gPLink -like "*<GPOGuid>*"} -Properties gPLink, distinguishedName |
    Select-Object distinguishedName, gPLink
```

## Replication: FRS vs DFSR

SYSVOL's file content — every GPO's GPT folder tree, plus logon scripts stored outside any specific GPO — has to be replicated identically to every Domain Controller servicing the domain. Two different replication engines have serviced this over the life of Windows Server:

| | FRS (File Replication Service, legacy) | DFSR (DFS Replication, modern) |
|---|---|---|
| Hosting process | `ntfrs.exe` | `dfsrs.exe` |
| Era | Pre-2008 domain functional level; the original SYSVOL replication mechanism | 2008+ domain functional level; Microsoft's supported replacement for years now |
| Replication group name (SYSVOL) | N/A (FRS predates the DFSR replication-group concept) | **"Domain System Volume"** — the standard DFSR replication group name for SYSVOL, referenced directly in `dfsrdiag` syntax below |
| Current status | Deprecated; still occasionally found on older or never-migrated domains — hedge on which one any given environment actually runs rather than assuming DFSR by default | The modern default; assume DFSR going forward, but verify |

The practical forensic point is the same regardless of which engine is running: **SYSVOL is replicated, multi-DC content, so a GPO's on-disk state should be identical across every DC servicing that domain.** A discrepancy between two DCs' copies of the same GPO's SYSVOL folder is itself worth investigating — either as a replication-health problem (see below) or, in the worst case, as evidence that an attacker modified SYSVOL directly on one DC and replication simply hasn't caught up (or was deliberately targeted) yet.

**Migration states** — `dfsrmig /getmigrationstate` reports which of four states a domain is in on its FRS→DFSR migration path:

| State | Meaning |
|---|---|
| `Start` | Still on legacy FRS; migration not yet begun |
| `Prepared` | DFSR is staged and replicating a copy of SYSVOL content alongside FRS, but FRS is still authoritative |
| `Redirected` | DFSR is now authoritative for SYSVOL; FRS is being phased out |
| `Eliminated` | Migration complete — FRS is fully retired, DFSR is the sole SYSVOL replication mechanism |

🔴 **A domain stuck at `Prepared` or `Redirected` rather than fully `Eliminated` is itself worth flagging, even absent any sign of compromise.** It usually signals a domain that was upgraded rather than rebuilt and never had its migration finished — a real-world gotcha that correlates with weaker general patching/auditing posture, and it means SYSVOL troubleshooting commands and expectations differ from what a fully-migrated domain would show.

## GPT/GPC Version Desynchronization — Detection Workflow

This is the callout at the top of this note made concrete: a full workflow for proving whether a GPO's GPT and GPC halves currently agree.

The reasoning: normal GPO edits — through GPMC, `Set-GPRegistryValue`, `Set-GPPrefRegistryValue`, or any other tooling that goes through the proper GPO-editing APIs — bump **both** the SYSVOL-side `GPT.INI` version and the AD-side `versionNumber` attribute in the same logical operation. A raw SYSVOL file edit (opening `Registry.pol` or a GPP XML file directly on the file share, or restoring an old backup copy over a current file) changes the *content* on disk without going through that API, and can leave the GPC's `versionNumber` completely unchanged. Comparing the two, decomposed into their Computer/User halves, is how you catch that gap.

To perform the single-GPO check using PowerShell, read both versions and compare directly:

```powershell
$gpo = Get-GPO -Guid '<GPOGuid>'
$gptIni = Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\GPT.INI" -ErrorAction SilentlyContinue
$gptVersion = ($gptIni | Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
[PSCustomObject]@{
    Name              = $gpo.DisplayName
    GPC_ComputerVer   = $gpo.Computer.DSVersion
    GPC_UserVer       = $gpo.User.DSVersion
    GPT_Raw           = $gptVersion
    GPT_ComputerVer   = [uint32]$gptVersion -band 0xFFFF
    GPT_UserVer       = ([uint32]$gptVersion -shr 16) -band 0xFFFF
}
```

To perform the domain-wide audit using PowerShell, decomposed into Computer/User halves independently (catches a computer-only or user-only edit that a naive raw-number comparison would miss) and flagging any mismatch:

```powershell
Get-GPO -All | ForEach-Object {
    $gptIni = Get-Content "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($_.Id)}\GPT.INI" -ErrorAction SilentlyContinue
    $raw = ($gptIni | Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
    $gptComputer = if ($raw) { [uint32]$raw -band 0xFFFF } else { $null }
    $gptUser     = if ($raw) { ([uint32]$raw -shr 16) -band 0xFFFF } else { $null }
    [PSCustomObject]@{
        Name          = $_.DisplayName
        GPC_Computer  = $_.Computer.DSVersion
        GPT_Computer  = $gptComputer
        GPC_User      = $_.User.DSVersion
        GPT_User      = $gptUser
        Mismatch      = ($_.Computer.DSVersion -ne $gptComputer) -or ($_.User.DSVersion -ne $gptUser)
    }
} | Where-Object Mismatch
```

To run the same check using PowerShell against **every DC's own copy** of SYSVOL rather than whichever DC the client happens to resolve `\\<domain>\SYSVOL\` to — a mismatch that only appears on one specific DC points at that DC specifically, rather than a domain-wide tampering event:

```powershell
$gpoList = Get-GPO -All
foreach ($dc in (Get-ADDomainController -Filter *).HostName) {
    foreach ($gpo in $gpoList) {
        $gptIni = Get-Content "\\$dc\SYSVOL\$env:USERDNSDOMAIN\Policies\{$($gpo.Id)}\GPT.INI" -ErrorAction SilentlyContinue
        $raw = ($gptIni | Select-String '^Version=(\d+)').Matches.Value -replace 'Version='
        [PSCustomObject]@{
            DC       = $dc
            Name     = $gpo.DisplayName
            GPT_Raw  = $raw
            GPC_Raw  = ($gpo.User.DSVersion -shl 16) -bor $gpo.Computer.DSVersion
        }
    }
} | Group-Object Name | Where-Object { ($_.Group.GPT_Raw | Select-Object -Unique).Count -gt 1 }
```

## Replication Health Checking

Before treating any single DC's SYSVOL copy as authoritative during an investigation — including before trusting the version-desync checks above as domain-wide truth — confirm replication is actually healthy between the DCs being compared.

| Command | Purpose |
|---|---|
| `dfsrdiag replicationstate` | Confirms DFSR replication is actively occurring on the local DC, not stalled |
| `dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:<SourceDC> /rmem:<DestDC>` | Reports the outstanding, not-yet-replicated update count between two specific DCs for the SYSVOL replication group |
| `dfsrmig /getmigrationstate` | Reports the FRS→DFSR migration state — see [above](#replication-frs-vs-dfsr) |

🔴 **A non-zero, and especially a growing, backlog between two DCs means one of them is serving stale SYSVOL content — don't trust a single DC's copy as authoritative until backlog is confirmed at or near zero.** An analyst comparing GPO state across DCs mid-incident who doesn't check backlog first risks treating a perfectly normal replication-lag artifact as evidence of tampering, or conversely, missing genuine tampering on a DC that legitimate replication hasn't reached yet.

Neither `dfsrdiag` nor `dfsrmig` has a PowerShell-cmdlet replacement — like `repadmin` (see **[05b](../05b%20-%20Active%20Directory%20%26%20Domain%20Forensic%20Artifacts.md)**), they are standalone native binaries. `Invoke-Command` wraps them for remote/fleet-wide execution the same way it wraps any other console tool.

To check replication state and migration state using native commands on the local DC:

```powershell
dfsrdiag replicationstate
dfsrmig /getmigrationstate
```

To check backlog using native commands between two named DCs for the SYSVOL replication group specifically, run from either DC:

```powershell
dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:DC01 /rmem:DC02
```

To check backlog using PowerShell across every DC pair in the domain in one pass, the fleet-wide equivalent of checking one pair at a time:

```powershell
$dcs = (Get-ADDomainController -Filter *).HostName
foreach ($source in $dcs) {
    foreach ($dest in $dcs | Where-Object { $_ -ne $source }) {
        Invoke-Command -ComputerName $source -ScriptBlock {
            param($rmem) dfsrdiag backlog /rgname:"Domain System Volume" /rfname:"SYSVOL Share" /smem:$env:COMPUTERNAME /rmem:$rmem
        } -ArgumentList $dest
    }
}
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| GPT (`GPT.INI`) version and GPC (`versionNumber`) desynchronized, for either the Computer or User half | A raw SYSVOL file edit that bypassed normal GPO-editing tooling can change content while leaving the AD object's version looking unchanged |
| A GPC's `gPCFileSysPath` pointing at a SYSVOL path that doesn't exist, or doesn't match `Policies\{same-GUID}` | The AD object and its supposed content have become disconnected — investigate both halves independently |
| An orphaned SYSVOL GUID folder with no matching GPC object in AD, or vice versa | An incompletely deleted or incompletely created GPO — worth confirming which side is authoritative before assuming either is safe to remove |
| A domain stuck at `Prepared` or `Redirected` (rather than `Eliminated`) in `dfsrmig /getmigrationstate` | Signals an incomplete FRS→DFSR migration — correlates with weaker general patching/auditing posture, and changes what "normal" SYSVOL troubleshooting looks like |
| Non-zero or growing `dfsrdiag backlog` between two DCs | One DC is serving stale SYSVOL content — don't trust that DC's copy as authoritative until backlog clears |
| The same GPO's `GPT.INI` version differing across two DCs' own SYSVOL copies, with backlog confirmed at zero | Genuinely inconsistent SYSVOL state despite healthy replication — a stronger finding than a desync explained by ordinary replication lag |
| A GPO applying to an unusually broad scope via `gpLink` (e.g. domain root instead of a narrow OU) | Scope-abuse red flag — full detection-angle depth is **[05 - GPO Abuse, Hunting and Detection](05%20-%20GPO%20Abuse%2C%20Hunting%20and%20Detection.md)**'s territory; this note only supplies the `gpLink`-reading mechanics |

## Tooling

| Tool | Use |
|---|---|
| **`dfsrdiag`** | DFSR replication-state and backlog checking — no PowerShell-cmdlet equivalent |
| **`dfsrmig`** | FRS→DFSR migration-state reporting — no PowerShell-cmdlet equivalent |
| **Group Policy Management Console (`gpmc.msc`)** | The standard GUI for browsing GPOs, their links, versions, and settings without hand-inspecting raw SYSVOL/AD objects |
| **`GroupPolicy` PowerShell module** | `Get-GPO`, `Get-GPInheritance`, `Get-GPOReport` — the native, RSAT-shipped module this note's PowerShell examples lean on |
| **`ActiveDirectory` PowerShell module / raw ADSI** | Direct GPC attribute access (`versionNumber`, `gPCFileSysPath`, `flags`, `gpLink`) when `GroupPolicy`-module cmdlets don't expose a specific attribute directly |

## Correlate With

| To go deeper on… | Open |
|---|---|
| GPO fundamentals, GPT/GPC concept at a high level, LSDOU precedence across levels, security filtering, WMI filters, loopback processing | **[00 - GPO Fundamentals and Architecture](00%20-%20GPO%20Fundamentals%20and%20Architecture.md)** |
| `Registry.pol` binary format, GPP file contents and the `cpassword` flaw, Client-Side Extensions, ADMX/ADML templates, `GptTmpl.inf` detail | **[02 - GPO Content Deep Dive](02%20-%20GPO%20Content%20Deep%20Dive%20%28Registry.pol%2C%20GPP%2C%20Scripts%2C%20Security%20Templates%29.md)** |
| DC-side GPO investigation workflow, malicious-GPO-change detection, event 5136 full detail, GPO backup/restore evidence | **[03 - Domain Controller GPO Investigation](03%20-%20Domain%20Controller%20GPO%20Investigation.md)** |
| T1484.001 attack-technique depth and consolidated GPO hunting/detection commands | **[05 - GPO Abuse, Hunting and Detection](05%20-%20GPO%20Abuse%2C%20Hunting%20and%20Detection.md)** |
| AD replication metadata (`repadmin /showobjmeta`) general mechanics, applied to any AD object including a GPC | **[05b - Active Directory & Domain Forensic Artifacts](../05b%20-%20Active%20Directory%20%26%20Domain%20Forensic%20Artifacts.md#ad-replication-metadata-for-timeline-corroboration)** |
| DC-role context this note's replication-health checks are consumed by (SYSVOL/DFSR as one of several DC-specific services) | **[Domain Controller — Role-Specific Forensics](../23%20-%20Special%20Services/Domain%20Controller%20%E2%80%94%20Role-Specific%20Forensics.md#step-3--sysvoldfsr-replication-health)** |

## Resources

- Microsoft Learn — Group Policy architecture and the GPT/GPC model, consulted rather than fabricated to a specific URL
- Microsoft Learn — DFS Replication and the legacy File Replication Service, including SYSVOL migration guidance
- `dfsrmig` command reference — Microsoft Learn
- `dfsrdiag` command reference — Microsoft Learn
- MS-GPOL (Group Policy: Core Protocol) — the underlying protocol document describing `GPT.INI`'s and `versionNumber`'s packed version-DWORD encoding
