# Domain-Joined Host GPO Investigation

Every other note in this folder investigates GPO from the top down — the SYSVOL/AD object pair (**GPO/01**), the content inside a GPO (**GPO/02**), and the Domain Controller's own view of what's linked and to whom (**GPO/03**). This note flips the vantage point: an analyst is standing at (or holds an image of) a single domain-joined workstation or member server, and the question is no longer "what does the domain say should apply here" but **"what actually applied to *this* host, when, and what's the disk-level proof?"** That is a genuinely different investigation — the host's own local cache, its own registry history, and its own event log are the primary evidence, and none of them require touching a Domain Controller at all.

This is the endpoint-side complement to **GPO/03**'s DC-side workflow, and the two should be read together on a real case: GPO/03 tells you what the DC currently thinks is linked and enforced; this note tells you what the endpoint actually received and when. **GPO/00** is the prerequisite for the concepts this note leans on without re-deriving them — the local-vs-domain-GPO distinction, and LSDOU processing order/precedence. **GPO/01** owns the SYSVOL/GPC storage model this note's local cache is compared against for staleness. **GPO/02** owns `Registry.pol`'s binary format — this note covers only the *location* of the host's locally cached copy, not how to parse it.

> 🔴 **A host's `gpresult` output tells you what it last successfully pulled down — not what the GPO object in AD currently specifies, and the two can disagree.** If a GPO has been edited, reverted by an admin, or modified and rolled back by an attacker since this host's last refresh, the endpoint's effective policy (what `gpresult`/RSOP show, and what the local cache on disk actually contains) will diverge from the live SYSVOL/AD state that **GPO/03**'s DC-side workflow reports. That divergence does not tell you which side is "wrong" by itself — it tells you there's a timing question to chase: is this host simply stale (hasn't refreshed since a legitimate change), or are you looking at the on-disk residue of a since-reverted attacker modification the endpoint picked up before it was rolled back? Never treat a single host's `gpresult` output as proof of the GPO's current, real-time content in AD — cross-check against **GPO/03** before concluding anything about intent.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Finding Which GPOs Applied to This Host](#finding-which-gpos-applied-to-this-host)
  - [gpresult /r and gpresult /h](#gpresult-r-and-gpresult-h)
  - [rsop.msc — the GUI Alternative](#rsopmsc--the-gui-alternative)
  - [Get-GPResultantSetOfPolicy — the PowerShell-Native Equivalent](#get-gpresultantsetofpolicy--the-powershell-native-equivalent)
  - [Effective Policy vs Currently-Configured Policy](#effective-policy-vs-currently-configured-policy)
- [Local GPO Artifacts — the Disk-Level Cache](#local-gpo-artifacts--the-disk-level-cache)
  - [C:\Windows\System32\GroupPolicy\\](#cwindowssystem32grouppolicy)
  - [C:\Windows\System32\GroupPolicyUsers\\\<SID\>\\](#cwindowssystem32grouppolicyuserssid)
  - [The Local GPO Itself](#the-local-gpo-itself)
  - [Staleness Detection — Local Cache vs Current SYSVOL/AD State](#staleness-detection--local-cache-vs-current-sysvolad-state)
- [Event Logs](#event-logs)
  - [Microsoft-Windows-GroupPolicy/Operational](#microsoft-windows-grouppolicyoperational)
  - [Legacy Userenv Events (Application Log)](#legacy-userenv-events-application-log)
- [Last Changes — When Was GPO Last Applied on This Host](#last-changes--when-was-gpo-last-applied-on-this-host)
  - [The Group Policy History Registry Key](#the-group-policy-history-registry-key)
  - [Key LastWrite Timestamps](#key-lastwrite-timestamps)
- [Forcing a Refresh](#forcing-a-refresh)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, single-host triage — everything below runs from an elevated PowerShell/cmd session on the box itself (or via `/s`/`-ComputerName` where noted), no RSAT/`GroupPolicy` module required unless flagged.

```powershell
# Quick effective-policy summary for this host - the fastest "what applied here" answer, no report file needed
gpresult /r /scope:computer
gpresult /r /scope:user

# Full HTML resultant-set-of-policy report - the gold-standard artifact for "what policy state was this host actually in"
gpresult /h C:\triage\gpresult.html /f

# Every GPO this host has EVER applied, per the local registry history - independent of the current live cache
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -Recurse -ErrorAction SilentlyContinue |
    Select-Object Name, @{N='LastWrite'; E={ (Get-Item $_.PSPath).LastWriteTime }}

# Local GroupPolicy client-side cache folder timestamps - when did this host last actually write new cached policy content
Get-ChildItem C:\Windows\System32\GroupPolicy -Recurse -ErrorAction SilentlyContinue |
    Select-Object FullName, LastWriteTime | Sort-Object LastWriteTime -Descending | Select-Object -First 20

# Recent GroupPolicy Operational log entries filtered to anything that didn't succeed
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object LevelDisplayName -in @('Warning','Error') |
    Select-Object TimeCreated, Id, LevelDisplayName, Message

# Confirm the channel actually exists and is enabled before concluding "no GPO errors" from an empty result
Get-WinEvent -ListLog 'Microsoft-Windows-GroupPolicy/Operational'

# Local gpt.ini version for the client-side cache - compare against the GPO's current SYSVOL version (GPO/01/03) for staleness
Get-Content C:\Windows\System32\GroupPolicy\gpt.ini -ErrorAction SilentlyContinue

# Group Policy Client service state and start type - a stopped/disabled service is itself a reason GPOs stop applying
Get-Service gpsvc | Select-Object Status, StartType
```

## Finding Which GPOs Applied to This Host

This is the core "how do I even answer this" question on a domain-joined endpoint, and there are three tools that answer it at increasing depth, plus one critical framing point that applies to all three.

### gpresult /r and gpresult /h

| Command | What it gives you |
|---|---|
| **`gpresult /r`** | A quick, text-summary dump of the effective (actually-applied) policy on the target — which GPOs applied, which were denied and why, a short settings summary. Fast triage before pulling the full report |
| **`gpresult /h <file>`** | The full HTML resultant-set-of-policy (RSoP) report — the single most information-dense artifact for "what policy state was this host actually in." Includes every applied GPO with its link order, every denied GPO with the denial reason (security filtering, WMI filter, disabled link, etc.), and a full settings-by-category breakdown for both Computer and User configuration |

**Syntax:**

```
gpresult [/s <computer> [/u <domain\user> /p <password>]] [/scope {user | computer}] {/r | /v | /z}
gpresult [/s <computer> [/u <domain\user> /p <password>]] [/scope {user | computer}] /h <filename> [/f]
```

| Flag | Meaning |
|---|---|
| `/s <computer>` | Target a **remote** host instead of the local machine — requires the querying account to have appropriate remote-admin rights and Remote Registry/RPC connectivity to the target |
| `/u` / `/p` | Alternate credentials for the remote query |
| `/scope:computer` | Restrict the report to Computer Configuration only |
| `/scope:user` | Restrict the report to User Configuration only (defaults to the currently logged-on user unless a specific `/user` is supplied) |
| `/r` | Text summary (RSoP data) |
| `/v` | Verbose text output — more setting-level detail than `/r` |
| `/z` | Super-verbose text output (the deepest text-mode detail level) |
| `/h <filename>` | HTML report to the given path |
| `/f` | Force-overwrite an existing report file at that path |

Because `gpresult` can target a remote computer via `/s`, a single analyst workstation with the right rights can pull effective-policy reports for a hunt list of hosts without physically touching each one — the estate-wide version of this workflow (batch `/s` sweeps across a hunt list) belongs to **GPO/05**; this note covers the single-host mechanics that workflow is built on.

### rsop.msc — the GUI Alternative

`rsop.msc` launches the **Resultant Set of Policy** MMC snap-in — the interactive, browsable equivalent of a `gpresult /h` report. It's slower to produce a shareable artifact than `gpresult /h` (there's no one-command HTML export from the snap-in itself), but it earns its place when you need to **interactively walk one specific setting** to see exactly which GPO won and why: right-click any setting in the RSoP tree and its Properties dialog shows the **precedence order** of every GPO that attempted to configure that setting, with the winning one at the top. This is the fastest way to answer "which of these five linked GPOs actually set this specific registry value" without re-deriving the whole LSDOU precedence chain by hand — see **GPO/00** for the LSDOU/inheritance/security-filtering model this precedence is built on; this note does not re-derive it.

🔴 `rsop.msc` reads the same underlying RSoP data `gpresult` does — it is not a live, real-time query of AD. Launching it does **not** force a fresh policy pull; it's showing you the same last-applied effective state, just interactively.

### Get-GPResultantSetOfPolicy — the PowerShell-Native Equivalent

Part of the `GroupPolicy` PowerShell module (RSAT feature — present on Domain Controllers and any admin workstation with RSAT installed, not shipped by default on a plain member workstation). It produces the same RSoP data as `gpresult /h`, scriptable:

```powershell
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\triage\rsop-report.html
Get-GPResultantSetOfPolicy -ReportType Html -Path C:\triage\rsop-report.html -Computer 'HOSTNAME' -User 'DOMAIN\username'
```

Prefer `gpresult /h` on a plain workstation where the `GroupPolicy` module isn't installed — it needs no extra features and produces the same underlying report; reach for `Get-GPResultantSetOfPolicy` when you're already scripting a multi-host sweep from an RSAT-equipped admin workstation and want the output folded into a larger PowerShell pipeline rather than shelled out to a separate binary.

### Effective Policy vs Currently-Configured Policy

This is the distinction the 🔴 callout at the top of this note names, and it's worth restating precisely because it governs how you should read every one of the three tools above:

- **Effective policy** (`gpresult`, RSoP, the local cache under `C:\Windows\System32\GroupPolicy\`) reflects whatever the host **last successfully pulled and applied** — a point-in-time snapshot from its last refresh, not a live query of the current GPO objects.
- **Currently-configured policy** is what the GPO object actually specifies **right now** in AD/SYSVOL — that's **GPO/03**'s territory, queried directly from the DC side (`Get-GPO`, `Get-GPOReport`, raw SYSVOL/AD object inspection).

A host that hasn't refreshed since a GPO was last modified will show effective policy that no longer matches the GPO's current content — and that's true whether the modification was a legitimate admin change the host simply hasn't picked up yet, or the surviving evidence of an attacker's edit that was later reverted before anyone thought to check the endpoint. Either way, the divergence itself is the finding worth chasing, and confirming *which* explanation applies means comparing this note's host-side evidence against **GPO/03**'s DC-side confirmation of the GPO's current state and modification history.

## Local GPO Artifacts — the Disk-Level Cache

Everything in this section answers a different question than the tools above: not "what did the host report as applied" but **"what does the raw disk-level cache actually contain, independent of any tool's interpretation of it."** This is the artifact **05b**'s "Where GPOs Live" table only flagged in one line (the "Client-side" row) — full depth on it lives here.

### C:\Windows\System32\GroupPolicy\

This is the **local, cached copy** of whatever policy content the host pulled from SYSVOL (or its own Local GPO — see below), maintained by the Group Policy Client service (`gpsvc`).

| Path | Contents |
|---|---|
| `C:\Windows\System32\GroupPolicy\Machine\Registry.pol` | The **merged** registry-based Computer Configuration settings — every applicable GPO's registry-based settings, resolved through LSDOU precedence, combined into one file |
| `C:\Windows\System32\GroupPolicy\User\Registry.pol` | Same, for the currently/most-recently processed user's User Configuration |
| `C:\Windows\System32\GroupPolicy\gpt.ini` | A local `gpt.ini`, tracking a version number for the cached content as a whole |
| `C:\Windows\System32\GroupPolicy\Machine\Scripts\`, `User\Scripts\` | Cached copies of any logon/startup/logoff/shutdown scripts referenced by applicable GPOs |
| `C:\Windows\System32\GroupPolicy\Machine\Preferences\` (and `User\Preferences\`) | Cached GPP content (scheduled tasks, drive mappings, etc.) — see **GPO/02** for the GPP file family's own format/content depth |

🔴 **This is not a mirror of SYSVOL's per-GPO folder structure.** SYSVOL (**GPO/01**'s territory) keeps one folder per GPO GUID, each with its own `Registry.pol`. The local client-side cache under `System32\GroupPolicy\` is **flattened and merged** — a single `Machine\Registry.pol` and single `User\Registry.pol` representing the net *effective* result after every applicable GPO (domain-linked and local) has been resolved through LSDOU precedence. You cannot look at this cache and tell which individual GPO contributed which setting — that's exactly what `gpresult`/RSoP (above) are for. Do not re-derive `Registry.pol`'s internal binary format here — see **GPO/02** for that; this section covers only where the cached copy lives and what its scope actually represents.

To list the cache using PowerShell and read the local `gpt.ini`:

```powershell
Get-ChildItem C:\Windows\System32\GroupPolicy -Recurse | Select-Object FullName, Length, LastWriteTime
Get-Content C:\Windows\System32\GroupPolicy\gpt.ini
```

To pull just the version line using PowerShell out of the local `gpt.ini` for direct comparison against a specific GPO's current SYSVOL version (from **GPO/01**/**GPO/03**'s workflow):

```powershell
(Get-Content C:\Windows\System32\GroupPolicy\gpt.ini | Select-String '^Version=').ToString() -replace 'Version='
```

### C:\Windows\System32\GroupPolicyUsers\\<SID\>\

A parallel, per-user-SID structure alongside the machine-wide cache above — same `Machine`/`User`-style split, but keyed to a specific local user SID rather than the single flat Machine/User cache. This is the mechanism Windows uses to keep per-user policy application state distinct when more than one local profile is in play on the same box, and it is also where **Multiple Local Group Policy Objects (MLGPO)** — a Vista-and-later feature letting an administrator configure a *different* local policy for the local Administrators group versus non-administrator users — actually live on disk, each keyed by that group's well-known SID (`S-1-5-32-544` for local Administrators, `S-1-5-32-545` for the non-Administrators/Users group).

```powershell
Get-ChildItem C:\Windows\System32\GroupPolicyUsers -ErrorAction SilentlyContinue |
    Select-Object Name, LastWriteTime
```

A folder here named `S-1-5-32-544` is strong evidence that MLGPO's "different policy for Administrators" configuration is in use on this specific host — worth flagging on a domain-joined machine, since a divergent local policy layered underneath domain policy is an easy way to quietly carve out an exception for the local Administrators group that doesn't show up in any domain-side GPO review.

### The Local GPO Itself

Every Windows machine — domain-joined or not — has exactly one **Local Group Policy Object**, editable via `gpedit.msc` (not present on Home editions). Per LSDOU (see **GPO/00** for the full precedence model — not re-derived here), the Local GPO is applied **first**, before Site, Domain, and OU-linked GPOs, meaning any domain-linked GPO can override a Local GPO setting unless that domain GPO is itself blocked/filtered out.

On disk, the Local GPO's own settings live in **exactly the same path structure** described above — `C:\Windows\System32\GroupPolicy\Machine\` and `\User\`, with the same `gpt.ini`. On a domain-joined host that also receives domain GPOs, this means the client-side cache described in the previous section represents the **merged result of the Local GPO plus every applicable domain GPO** — there is no separate, distinguishable "Local GPO folder" sitting apart from the domain cache. The only way to isolate what the Local GPO itself is contributing (versus a domain-linked GPO) is, again, `gpresult`/RSoP's per-setting precedence view, or directly opening `gpedit.msc` and reading its configured settings (which reads the Local GPO specifically, not the merged effective result).

🔴 On a domain-joined production host, a **non-default Local GPO configuration** is itself worth flagging — it's an easy way for someone with local admin rights to establish settings that persist regardless of what domain policy says, right up until a domain GPO happens to override the same setting. Compare `gpedit.msc`'s configured Local GPO settings against a known-clean baseline for that host role.

### Staleness Detection — Local Cache vs Current SYSVOL/AD State

The local cache's content and timestamps are a **third data point**, independent of both `gpresult`'s interpreted output and the DC-side SYSVOL/AD state **GPO/03** queries directly: what does the raw cache on disk actually say, and when was it last written.

Practical staleness check:

1. Pull the local `gpt.ini` version and the `Machine\Registry.pol`/`User\Registry.pol` `LastWriteTime` from this host.
2. Pull the specific GPO's **current** SYSVOL `GPT.ini` version and GPC `versionNumber` via **GPO/01**/**GPO/03**'s workflow (`Get-GPO`, or a direct SYSVOL read).
3. If the host's registry-recorded applied version (see the History key, next section) is behind the GPO's current version, and the local cache's `LastWriteTime` predates the GPO's last-modified timestamp, that host has **not refreshed since the GPO changed** — a legitimate lag if it's within one background-refresh interval, a genuine finding if it's been far longer.

```powershell
# Local cache timestamp vs a specific GPO's SYSVOL last-write - flags a host that has not refreshed since that GPO last changed
$localCache = Get-Item 'C:\Windows\System32\GroupPolicy\Machine\Registry.pol' -ErrorAction SilentlyContinue
$sysvolGpt  = Get-Item "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies\{<GPO-GUID>}\GPT.INI" -ErrorAction SilentlyContinue
[PSCustomObject]@{
    LocalCacheLastWrite = $localCache.LastWriteTime
    SysvolGptLastWrite  = $sysvolGpt.LastWriteTime
    Stale               = if ($localCache -and $sysvolGpt) { $localCache.LastWriteTime -lt $sysvolGpt.LastWriteTime } else { 'unknown' }
}
```

## Event Logs

### Microsoft-Windows-GroupPolicy/Operational

`Microsoft-Windows-GroupPolicy/Operational` (under **Applications and Services Logs**) is the primary, modern (Vista+) channel for Group Policy processing events on the endpoint — recorded directly on the host, no DC access required. It records the client-side pipeline: when a refresh started, which extensions/CSEs processed, whether processing succeeded, and any failures along the way.

🔴 **Accuracy note — do not treat any specific event ID below as gospel without live verification.** This channel's exact numbering has shifted across OS releases and Microsoft's own published guidance is inconsistent about citing precise IDs for every event in it. What is safe to state:

- The channel records **processing-start** and **processing-succeeded/completed** events for both Computer and User policy application, and **error-level events for a failed Client-Side Extension (CSE)** — e.g., a specific extension (Registry, Security, Scripts, Folder Redirection, etc.) that failed to apply.
- Commonly cited IDs in published Group Policy troubleshooting material fall in the **4000s/5000s/8000s ranges** for start/success-type events, with distinct, higher-numbered events for warnings and CSE-specific failures — treat this as a directional pointer, **not** a confirmed exact number, until you verify it against the live host in front of you.
- Before relying on any specific ID in a report, run `Get-WinEvent -ListLog 'Microsoft-Windows-GroupPolicy/Operational'` to confirm the channel exists and is enabled, then `Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' | Group-Object Id | Sort-Object Count -Descending` to see the actual ID distribution on that specific host/OS build before citing a number as fact.

| What you're looking for | How to find it without a hardcoded ID |
|---|---|
| Was a refresh attempted at all in the window of interest | Any events present in the channel with `TimeCreated` in that window |
| Did it succeed | `LevelDisplayName -eq 'Information'` entries whose `Message` text references successful completion |
| Did a specific CSE fail | `LevelDisplayName -in @('Warning','Error')` entries — the `Message` text names the specific extension/GPO that failed, even without memorizing the numeric ID |
| A gap where processing should have occurred but didn't | Absence of any event in the channel spanning more than one full background-refresh interval — itself a finding, see Red Flags |

To confirm the channel exists using PowerShell and pull recent raw entries:

```powershell
Get-WinEvent -ListLog 'Microsoft-Windows-GroupPolicy/Operational'
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 100
```

To filter using PowerShell to anything that didn't succeed, and see the actual ID distribution on this specific host/build rather than assuming one from a reference table:

```powershell
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 500 |
    Where-Object LevelDisplayName -in @('Warning','Error') |
    Select-Object TimeCreated, Id, LevelDisplayName, Message

Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 500 |
    Group-Object Id | Sort-Object Count -Descending |
    Select-Object Count, Name, @{N='SampleMessage'; E={ $_.Group[0].Message.Substring(0, [Math]::Min(80, $_.Group[0].Message.Length)) }}
```

To narrow using PowerShell to a specific suspected incident window, and cross-reference against the History key's last-write time (below) to see whether the event log and the registry agree on when the last refresh actually happened:

```powershell
$windowStart = (Get-Date).AddHours(-24)
Get-WinEvent -LogName 'Microsoft-Windows-GroupPolicy/Operational' -MaxEvents 1000 |
    Where-Object TimeCreated -ge $windowStart |
    Sort-Object TimeCreated
```

### Legacy Userenv Events (Application Log)

On systems that predate the dedicated Operational channel — Windows XP/Server 2003, and as a legacy compatibility fallback that persisted into some later OS versions — Group Policy processing errors were logged to the classic **`Application` log**, source **`Userenv`**, rather than a specialized channel. The two most widely cited and well-documented legacy Userenv IDs, seen across two decades of sysadmin troubleshooting, are:

| Event ID | Source | Meaning |
|---|---|---|
| **1030** | Userenv | Windows cannot access the specified `gpt.ini`/network path for a GPO — typically a SYSVOL access or connectivity failure preventing that GPO from being read at all |
| **1058** | Userenv | Windows cannot access the specified file for a GPO on SYSVOL (e.g., a corrupted/inaccessible GPT folder) — closely related to 1030 and commonly seen alongside it |

These two are confidently citable — they are among the most well-documented legacy Group Policy failure signatures in existence. Beyond them, hedge: Userenv logged a broader family of processing events on legacy systems, but exact IDs beyond 1030/1058 should be verified against the specific OS build rather than asserted here. On any modern (Vista+) host, check the Operational channel first — Userenv/Application-log entries are the exception, not the norm, on current OS versions.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Userenv'} -MaxEvents 100 -ErrorAction SilentlyContinue
```

## Last Changes — When Was GPO Last Applied on This Host

### The Group Policy History Registry Key

`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History\` is the definitive **"did this host ever receive GPO X"** artifact, independent of whatever the live client-side cache currently shows — it accumulates a record of GPOs actually applied to this specific machine over time, not just the most recent refresh.

- **Computer-side history**: subkeys directly under `...\Group Policy\History\`, named by **GPO GUID** — one subkey per GPO this host has applied Computer Configuration settings from.
- **User-side history**: because the Group Policy Client service processes user policy in the SYSTEM context (not the logged-on user's own context), user-side history is **also stored under HKLM**, not `HKCU` — look under `...\Group Policy\History\<user-SID>\{GPO-GUID}` for a record of which GPOs applied to a specific user's session on this machine, keyed by that user's SID. This matters practically: you can recover which GPOs a user's session received **even without access to that user's own profile/hive**, since it's all sitting under the machine-wide `SOFTWARE` hive.

Each GPO subkey typically carries version and path metadata (the specific GPO's display name and a version value tracked at the time it was last applied) — treat the presence of specific value names as something to confirm against the live host rather than assumed verbatim, since the exact value-name set has some variation across OS versions; the key's *existence and GUID-keyed structure* is the reliable, well-documented part.

A related location sometimes cited in Group Policy internals references is `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine\Extension-List\` — reportedly tracking per-Client-Side-Extension processing state/timing. This path is **less universally documented** than the History key above — verify its presence and exact subkey layout on the specific host/OS build in front of you before relying on it in a report, rather than assuming it's there.

```powershell
# Every GPO GUID this host's computer account has ever applied
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction SilentlyContinue |
    Select-Object PSChildName, @{N='LastWrite'; E={ (Get-Item $_.PSPath).LastWriteTime }}

# Per-user GPO application history - works even without access to that user's own NTUSER.DAT
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History' -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^S-1-5-21-' } |
    ForEach-Object {
        $userSid = $_.PSChildName
        Get-ChildItem $_.PSPath | Select-Object @{N='UserSID'; E={ $userSid }}, PSChildName,
            @{N='LastWrite'; E={ (Get-Item $_.PSPath).LastWriteTime }}
    }
```

🔴 **A GPO this host was supposed to receive (per its OU membership and the domain's linked-GPO list — confirm via GPO/03) that has NO corresponding subkey under the History key** is a genuine finding: either the host never actually successfully processed that GPO (worth checking the Operational log around the expected timeframe for a processing failure), or the subkey has been deliberately removed — registry key deletion here is a plausible, low-effort way to erase local evidence that a specific GPO ever applied, the same class of anti-forensic move Prefetch-deletion represents for execution evidence.

### Key LastWrite Timestamps

Every registry key carries its own last-write timestamp (see **Registry Forensics Fundamentals (04)** for the general mechanics and the "one timestamp per key, not per value" gotcha — not re-derived here). Applied to the History key specifically: a GPO subkey's own `LastWriteTime` is a direct, registry-native answer to **"when did this host last apply this specific GPO"** — a timestamp source that exists independent of both the client-side file cache's timestamps and the Operational event log, and one more corroborating (or contradicting) data point when the other two disagree or are unavailable (log rolled over, cache overwritten by a subsequent refresh of a *different* GPO).

Cross-reference all three "last refresh" sources against each other before settling on a timeline:

| Source | What it tells you | Caveat |
|---|---|---|
| History key subkey `LastWriteTime` | Last time this specific GPO's application was recorded on this host | Per-key, not per-value — see note 04's general LastWrite caveat |
| `Microsoft-Windows-GroupPolicy/Operational` event timestamps | Last time a processing cycle ran (success or failure) | Log may have rolled over past the window of interest |
| Local cache file `LastWriteTime` (`Machine\Registry.pol`, `User\Registry.pol`) | Last time the merged cache was rewritten | Reflects the *most recent* refresh of the merged result — doesn't tell you which specific GPO's content changed within it |

## Forcing a Refresh

Single-host mechanics only — the estate-wide/remote-hunting angle (batch-forcing an entire hunt list) belongs to **GPO/05**.

| Command | Effect |
|---|---|
| `gpupdate` | Triggers a policy refresh, applying only settings whose GPO version has changed since the last refresh |
| `gpupdate /force` | Re-applies **all** settings from every applicable GPO regardless of version — useful for troubleshooting, and for pushing a tampered/drifted host back to policy-compliant state |
| `Invoke-GPUpdate` | The native `GroupPolicy`-module PowerShell equivalent, RPC-based (works against a remote target without a WinRM session) |

To force a refresh using native commands on the local host, then immediately re-check effective policy to confirm it landed:

```powershell
gpupdate /force
gpresult /r /scope:computer
```

To bring a host using PowerShell that was found to have drifted (stale cache, missing History subkey, tampered local settings) back in line with current domain policy, and verify the correction actually took:

```powershell
Invoke-GPUpdate -Computer 'HOSTNAME' -Force -RandomDelayInMinutes 0
Start-Sleep -Seconds 30
Invoke-Command -ComputerName 'HOSTNAME' -ScriptBlock { gpresult /r /scope:computer }
```

🔴 Capture the evidence covered in this note — the History key, the local cache's pre-refresh state, the Operational log entries — **before** forcing a refresh on a host under active investigation. A forced `gpupdate` overwrites the merged local cache and can push a new entry into the History key, destroying the exact "what did this host have before you touched it" snapshot you may need to prove what an attacker's GPO tampering actually looked like on the endpoint.

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `gpresult`/RSoP effective policy inconsistent with the GPO's current state in AD (per GPO/03) | Either a stale host that hasn't refreshed since a legitimate change, or the surviving residue of a since-reverted attacker modification — chase the timing before concluding either way |
| Local cache (`C:\Windows\System32\GroupPolicy\`) unexpectedly stale relative to the background refresh interval and the GPO's known last-modified time | The host isn't picking up current policy — could be a broken Group Policy Client service, network/SYSVOL access failure, or a host deliberately kept isolated from a legitimate remediation push |
| Group Policy History registry key missing or empty for a GPO this host should have received per its OU/link scope | Either the GPO never actually successfully applied (check the Operational log for a processing failure around the expected time) or the evidence was deliberately removed |
| Gaps or clustered errors in `Microsoft-Windows-GroupPolicy/Operational` around a suspicious time window | Corroborates tampering with policy processing itself, or a host taken offline/isolated during the window an attacker needed to operate without a policy refresh interfering |
| Non-default Local GPO (`gpedit.msc`) configuration on a domain-joined production host | An easy way to establish settings that persist locally regardless of domain policy, until a domain GPO happens to override the same setting |
| `C:\Windows\System32\GroupPolicyUsers\S-1-5-32-544\` (or other MLGPO per-SID folder) present unexpectedly | A distinct local policy carved out for the local Administrators group (or another local principal) that won't show up in any domain-side GPO review |
| Group Policy Client service (`gpsvc`) stopped or disabled | GPOs silently stop refreshing on this host entirely — a simple, low-effort way to freeze a host's policy state while everything else in the domain moves on |

## Tooling

| Tool | Use |
|---|---|
| **`gpresult /r` / `gpresult /h`** | The primary tools for confirming effective, actually-applied policy on a live endpoint — text summary vs full HTML report |
| **`rsop.msc`** | GUI Resultant Set of Policy snap-in — best for interactively walking one specific setting's winning-GPO precedence |
| **`Get-GPResultantSetOfPolicy`** | PowerShell-native RSoP equivalent (`GroupPolicy` module, RSAT) — scriptable, folds into a larger automation pipeline |
| **`Invoke-GPUpdate`** | Native PowerShell force-refresh, RPC-based, works against a remote single host without a WinRM session |
| **Registry Explorer / RECmd** (Eric Zimmerman) | Offline parsing of the History key and local cache registry values from an acquired `SOFTWARE` hive, with transaction-log replay — see note 04 |
| **Group Policy Management Console (`gpmc.msc`)** | GUI browsing of GPO scope/settings/version history when you have DC-side access — see GPO/03 |

## Correlate With

| To go deeper on… | Open |
|---|---|
| GPO fundamentals, forensic duality, local-vs-domain GPO concept, LSDOU/inheritance/security filtering/WMI filters/loopback | **GPO/00 — GPO Fundamentals and Architecture** |
| SYSVOL/GPT structure, GPC AD object attributes, FRS/DFSR, GPT/GPC version-desync detection | **GPO/01 — Storage, Replication and Version Synchronization** |
| `Registry.pol`'s binary format, GPP file family, `cpassword`/MS14-025, ADMX/ADML | **GPO/02 — GPO Content Deep Dive** |
| DC-side enumeration, `gpLink` resolution, event 5136, malicious-GPO-change detection from the AD-object side | **GPO/03 — Domain Controller GPO Investigation** |
| T1484.001 full technique narrative, consolidated cross-folder hunting, estate-wide GPP cpassword sweep | **GPO/05 — GPO Abuse, Hunting and Detection** |
| Registry hive structure, key LastWrite mechanics, offline hive parsing | **Registry Forensics Fundamentals (04)** |
| Full event-log taxonomy, `Get-WinEvent` methodology, where the Operational channel fits alongside the rest of the module's logging coverage | **Event Log Analysis (11)** |

## Resources

- Microsoft Learn — `gpresult` command reference: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult
- Microsoft Learn — `GroupPolicy` PowerShell module reference (`Get-GPResultantSetOfPolicy`, `Invoke-GPUpdate`): https://learn.microsoft.com/en-us/powershell/module/grouppolicy/
- Microsoft's own Group Policy troubleshooting documentation (Microsoft Learn) — generic reference for the `Microsoft-Windows-GroupPolicy/Operational` channel and RSoP behavior, consulted rather than fabricated to a specific event-ID-by-ID URL; verify exact event IDs against `Get-WinEvent -ListLog` on the live host/OS build in front of you
- SANS FOR508 course syllabus (public) — GPO forensics coverage checklist
