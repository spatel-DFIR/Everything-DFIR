# Event Log Analysis

Windows records almost everything an investigator cares about somewhere in its event logs — but "somewhere" is the problem. A single intrusion can leave fingerprints across `Security.evtx` (logons, privilege use, account changes), `System.evtx` (service installs, time changes, boot events), `Application.evtx` (crash artifacts), and a sprawling family of specialized operational logs (PowerShell, WinRM, Terminal Services, Task Scheduler, WMI-Activity) that most first responders never open. This note is the mechanics hub the rest of the module builds on: how `.evtx` files are structured, retained, and tampered with; the dense event-ID reference tables for the three core logs; and full coverage of every specialized log this repo's persistence, authentication, and lateral-movement notes forward-reference rather than re-explain.

Five sibling notes point here rather than duplicating this content: **Users, Groups & Authentication (05)** owns logon-*type interpretation* for 4624/4625/4634/4647/4672/4648/4768/4769/4776/4800/4801 but defers the Security log's own mechanics to this note; **Services**, **Scheduled Tasks**, and **WMI Event Consumers** (all in Persistence Mechanisms, note 10) each promise "full event mechanics in Event Log Analysis" for their respective System/Security/operational-log event IDs. Where those notes already own the *interpretation* of a specific event in a specific investigative context, this note cross-links rather than repeats — but every event ID they cite gets its full mechanical treatment here.

> 🔴 **Before trusting any event ID's absence as "nothing happened," check three things: retention (did the log roll past that time window?), audit policy (was the category that generates this event even enabled?), and log integrity (was the log cleared?).** The single most common event-log mistake in DFIR is reading a missing event as evidence of absence rather than as one of these three far more common explanations.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Why It Matters to IR](#why-it-matters-to-ir)
- [EVTX Mechanics](#evtx-mechanics)
  - [File Format \& Default Locations](#file-format--default-locations)
  - [Retention \& Rollover Behavior](#retention--rollover-behavior)
  - [Record Structure](#record-structure)
  - [Log Clearing \& Tampering Detection](#log-clearing--tampering-detection)
  - [OS-Version Delta: Legacy .evt vs .evtx](#os-version-delta-legacy-evt-vs-evtx)
- [Get-WinEvent — Native Query Methodology](#get-winevent--native-query-methodology)
- [Audit Policy Fundamentals](#audit-policy-fundamentals)
- [Security Log — Core Event ID Reference](#security-log--core-event-id-reference)
  - [Account Logon / Logoff](#account-logon--logoff)
  - [Object Access](#object-access)
  - [Privilege Use](#privilege-use)
  - [Process Creation — 4688](#process-creation--4688)
  - [Audit Policy Change — 4719](#audit-policy-change--4719)
  - [Service \& Scheduled-Task Related](#service--scheduled-task-related)
  - [Account Management](#account-management)
  - [Log Clearing — 1102](#log-clearing--1102)
- [System Log — Key Event IDs](#system-log--key-event-ids)
  - [Service Control Manager Events](#service-control-manager-events)
  - [Time-Change Events — 1 and 4616](#time-change-events--1-and-4616)
  - [Boot \& Shutdown Events](#boot--shutdown-events)
- [Application Log](#application-log)
- [Specialized Operational Logs](#specialized-operational-logs)
  - [PowerShell](#powershell)
  - [WinRM / PowerShell Remoting](#winrm--powershell-remoting)
  - [Terminal Services / RDP](#terminal-services--rdp)
  - [TaskScheduler/Operational](#taskscheduleroperational)
  - [WMI-Activity/Operational](#wmi-activityoperational)
  - [OAlerts (Office Alerts)](#oalerts-office-alerts)
- [WLAN / Geo-Location Events](#wlan--geo-location-events)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage across the logs this note owns — no third-party modules required. `-FilterHashtable`/`-FilterXPath` (not `Where-Object`) is what makes these fast enough for live-response use against multi-hundred-MB logs; see the Get-WinEvent Fundamentals section below for why.

```powershell
# Script Block Logging (4104) content matching classic obfuscation/download-and-execute markers
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match '-enc|EncodedCommand|IEX|Invoke-Expression|DownloadString|DownloadFile|FromBase64String' } |
    Select-Object TimeCreated, @{N='ScriptBlock';E={$_.Message}}

# Fast multi-ID sweep of the Security log's highest-value event IDs in one pass - runs in the log engine, not in the pipeline
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4672,4688,4720,4728,4732,1102} -MaxEvents 500

# Either log-clear event (Security 1102 or System 104) present at all - a hit here demands immediate priority triage
Get-WinEvent -FilterHashtable @{LogName='Security','System'; Id=1102,104} -ErrorAction SilentlyContinue

# System time changed (System log ID 1) and who changed it (Security 4616) - classic anti-forensics timeline skew
Get-WinEvent -FilterHashtable @{LogName='System'; Id=1} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4616} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[1].Value}}

# Last 24 hours across the three core logs plus PowerShell/Operational, sorted into one timeline - fast triage baseline
Get-WinEvent -FilterHashtable @{LogName='Security','System','Application','Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | Select-Object TimeCreated, LogName, Id, @{N='Summary';E={$_.Message.Split("`n")[0]}}

# RDP session reconstruction: Logon Type 10 successes paired with the destination-host session-manager events (21/22/23/24/25)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 10 } | Select-Object TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, @{N='Detail';E={$_.Message}}
```

## Why It Matters to IR

Every other note in this module that mentions a Windows event ID assumes this note exists underneath it. Event logs are the one artifact family that spans the entire kill chain on a single host — initial access (logon events), execution (process creation, PowerShell script blocks), persistence (service/task/WMI creation), lateral movement (RDP, WinRM, remote service/task creation), and anti-forensics (log clearing, time manipulation) all leave a record here, *if* the right log exists, hasn't rolled past the window, and the right audit policy was enabled when the event fired. Getting good at this note's mechanics — knowing what's on by default vs. what requires configuration, knowing how to tell a cleared log from a quiet one, knowing which of six PowerShell-adjacent logs actually has the content you need — is what separates "I checked the Security log" from an investigation that actually reconstructs what happened.

## EVTX Mechanics

### File Format & Default Locations

Windows Vista and later store event logs in the **`.evtx`** format — an XML-structured binary container, distinct from the flat binary `.evt` format used pre-Vista (see the OS-version delta section below). All `.evtx` files live under:

```
%SystemRoot%\System32\winevt\Logs\
```

| Log | Filename | What it holds |
|---|---|---|
| **Security** | `Security.evtx` | Logon/logoff, object access, privilege use, account management, audit policy changes — the single most-queried log in an intrusion |
| **System** | `System.evtx` | OS/driver/service-level events — service control manager, boot/shutdown, time changes, hardware/PnP |
| **Application** | `Application.evtx` | Third-party and Microsoft application-level errors, warnings, and info events — least structured of the three core logs |

Beyond the three core logs, Windows Vista+ ships dozens of **specialized operational and analytic channels**, one per provider/feature area, following a consistent naming pattern:

```
Microsoft-Windows-<Provider>%4<Channel>.evtx
```

The `%4` is a literal encoded slash (`/`) — the channel's logical name is `Microsoft-Windows-<Provider>/<Channel>` (e.g. `Microsoft-Windows-PowerShell/Operational`), and Windows encodes that slash into `%4` when naming the backing file on disk. Every specialized log covered later in this note (PowerShell, WinRM, Terminal Services, TaskScheduler, WMI-Activity, WLAN-AutoConfig) follows this pattern. Most operational channels are **enabled and visible by default** in Event Viewer; some richer **Analytic** and **Debug** channels (a step up in verbosity from Operational) are hidden and disabled by default and must be explicitly enabled (`wevtutil sl <channel> /e:true`) before they start recording — PowerShell's Script Block Logging (4104) is the highest-value example of an entire channel's richest content being opt-in.

### Retention & Rollover Behavior

Each log has a configurable **maximum size** and a configurable **behavior when full**:

| Setting | Behavior | Forensic implication |
|---|---|---|
| **Overwrite events as needed (circular)** | Oldest records are silently overwritten once the log hits its max size — the default for most logs out of the box | Retention window is a function of event *volume*, not calendar time — a busy server can roll its Security log over in hours, a quiet workstation might retain months |
| **Archive the log when full** | Full log is archived to a new file and a fresh log starts | Preserves history but requires someone to have configured it — check for `Archive-Security-*.evtx`-style files if the live log looks unusually short |
| **Do not overwrite events (clear log manually)** | Log simply stops recording new events once full, until manually cleared | Rare in practice — a full, non-recording log with a very old oldest-record timestamp is itself worth investigating |

🔴 **A suspiciously small Security log on a busy Domain Controller is itself a finding, not just an inconvenience.** DCs generate enormous event volume (every Kerberos ticket request, every logon from every domain-joined host). A small default max size on a high-volume DC means rapid circular overwrite — history measured in hours or days, not weeks. This is frequently a genuine, pre-existing misconfiguration rather than attacker action, but the effect (loss of history right when you need it) is identical either way, and it's worth explicitly flagging in a report as a finding about the *environment's* logging posture, separate from anything the attacker did. Always check the oldest-record timestamp in a log before concluding "no evidence of X" — a Security log whose oldest record postdates your intrusion window has told you nothing about that window at all.

Default max size varies significantly by log, OS version, and GPO configuration — do not assume a specific number; always check the live/acquired log's actual configured max size (`wevtutil gl Security`) rather than relying on a remembered default.

### Record Structure

Every `.evtx` record shares a common structure worth knowing field-by-field:

| Field | What it holds | Forensic relevance |
|---|---|---|
| **Event Record ID** | A sequential integer, unique *per log file* (not global across logs) | 🔴 **Gaps in the Record ID sequence are a tampering-detection method independent of the log-clearing event itself.** If Record ID 40,201 is immediately followed by 40,350, records 40,202–40,349 existed and are gone — this can reveal selective record deletion (via a repository-level edit rather than a full log clear) that wouldn't otherwise show up as an obvious "log was cleared" event |
| **EventData** | Structured, named field/value pairs specific to the event's schema — the normal case for most modern providers | This is what most parsers surface as clean columns (e.g. 4624's `TargetUserName`, `IpAddress`, `LogonType`) |
| **UserData** | An alternative, less-common payload structure some providers use instead of EventData — same purpose, different XML shape | Some parsers handle UserData less gracefully than EventData; if a field you expect is missing from a tool's default view, check whether the raw XML uses UserData |
| **Provider GUID / Name** | Identifies which component logged the event (e.g. `Microsoft-Windows-Security-Auditing` for Security-log events) | Useful for confirming an event's true source when the channel name alone is ambiguous, and for hunting across all events from a specific provider regardless of channel |
| **Keywords** | Bitmask flags categorizing the event (e.g. Audit Success, Audit Failure) | Filterable at the log level — most log-viewing tools surface these as the Success/Failure icon on Security events |
| **Task / Opcode** | Sub-categorization within a provider (Task) and a lifecycle marker like Start/Stop/Info (Opcode) | Useful for correlating paired events from the same provider (e.g. an Opcode "Start" and "Stop" pair bounding a single operation) |

### Log Clearing & Tampering Detection

A cleared event log is one of the single strongest findings available in an intrusion — it directly signals someone with sufficient privilege deliberately destroyed evidence, and it usually happens close in time to the activity the attacker most wanted hidden.

| Event ID | Log | Meaning | Notes |
|---|---|---|---|
| **1102** | Security | "The audit log was cleared." | The canonical Security-log-clear event — logged by the security auditing subsystem itself, which is precisely why it's so hard for an attacker to suppress: the act of clearing the log is what generates this record, and it's written as part of the clear operation |
| **104** | System | Event log service recorded a log being cleared (naming which log) | Fires in the System log when a log is cleared via Event Viewer's "Clear Log" action or `wevtutil cl <log>` — treat this as corroborating, secondary evidence alongside 1102 rather than the primary signal for a *Security*-log clear; verify the exact event text/log name field for the specific log named before asserting which log was cleared in a given case |

🔴 **The meta-signal matters more than the event ID itself: 1102 becomes the most recent, or near-most-recent, record in a suspiciously short log.** An attacker who clears the Security log to hide their tracks cannot avoid the clear operation itself generating a new 1102 record immediately afterward — the log is never truly "empty," it's a log whose oldest record is the clear event (or very close to it) and whose subsequent records only cover the time *after* the clear. A log with an oldest-record timestamp that suspiciously coincides with a 1102 event, on a host that should have weeks or months of history, is one of the highest-confidence "something was actively hidden here" findings an analyst can report — pursue what happened in the window immediately before that 1102 with priority.

Also watch for: `wevtutil cl <log>` and `Clear-EventLog`/`Clear-WinEventLog` (PowerShell) as the command-line mechanisms behind a manual clear — if command-line auditing (4688, see below) was enabled and survived the clear (i.e., logged to a *different*, unaffected log or exported before the clear), the clearing command itself may be recoverable as direct proof of intent.

### PowerShell

To check for the presence of 1102/104 and, if found, confirm the meta-signal (oldest remaining record close to the clear):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='System'; Id=104} -ErrorAction SilentlyContinue

# Oldest surviving record in the Security log vs. the 1102 event's own timestamp - a near-match confirms the "log is never truly empty" pattern
$clear = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 1 -ErrorAction SilentlyContinue
$oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
[PSCustomObject]@{ ClearTime = $clear.TimeCreated; OldestSurvivingRecord = $oldest.TimeCreated }
```

To perform Event Record ID gap detection (a repository-level selective-deletion tell independent of 1102/104, per the Record Structure field notes above):

```powershell
$ids = (Get-WinEvent -LogName Security -MaxEvents 5000).RecordId | Sort-Object
$gaps = for ($i = 1; $i -lt $ids.Count; $i++) { if ($ids[$i] - $ids[$i-1] -gt 1) { "Gap: $($ids[$i-1]) -> $($ids[$i])" } }
$gaps
```

🔴 This only inspects Record IDs among events still present after any filtering/retention — a genuine circular-overwrite rollover produces the same *symptom* (IDs missing from the visible range) as selective deletion. Corroborate a suspected gap against the log's configured max size and current record count (`wevtutil gl Security`) before concluding tampering rather than ordinary rollover.

### OS-Version Delta: Legacy .evt vs .evtx

| | Pre-Vista (`.evt`) | Vista and later (`.evtx`) |
|---|---|---|
| Format | Flat binary, fixed-size records | XML-structured binary |
| Default max size | Much smaller (commonly 512 KB–16 MB depending on log and OS) | Larger defaults, GPO-configurable |
| Channel model | Three fixed logs only (Security/System/Application) | Three core logs plus the full specialized operational/analytic channel ecosystem covered later in this note |
| Query tooling | Legacy `eventvwr`, `Get-EventLog` | `Get-WinEvent`, modern Event Viewer, `wevtutil` |

Flag this explicitly on any pre-Vista (XP/Server 2003) image: the specialized operational logs this note spends most of its length on (PowerShell/Operational, WinRM/Operational, TaskScheduler/Operational, WMI-Activity/Operational) **do not exist** on those systems in any meaningful form — most of those providers/features postdate Vista entirely. An XP/2003 investigation is effectively limited to the three core `.evt` logs and whatever third-party logging was in place.

## Get-WinEvent — Native Query Methodology

Every other note in this module that shows a `Get-WinEvent` one-liner for a specific event ID is borrowing from this section's methodology rather than re-deriving it — this is the note's home turf for *how* to query event logs at scale natively, not just which IDs to look for.

### PowerShell

Three ways to ask `Get-WinEvent` for the same events, in increasing order of performance:

```powershell
# -LogName alone: pulls every event in the log, filters happen client-side afterward - fine for small/quiet logs only
Get-WinEvent -LogName Security | Where-Object Id -eq 4624

# -FilterHashtable: filtering happens inside the log-reading engine itself, before events are even deserialized to objects
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624}

# -FilterXPath: same engine-level filtering, expressed as raw XPath against the event's XML - needed for filters -FilterHashtable can't express
Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4624) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
```

🔴 **`-FilterHashtable`/`-FilterXPath` vs. piping to `Where-Object` is not a stylistic choice — it's the difference between minutes and seconds on a large `.evtx`.** `Get-WinEvent -LogName X | Where-Object {...}` reads and deserializes *every* record in the log into a full object before the filter ever runs. `-FilterHashtable` and `-FilterXPath` push the filter down into the underlying Windows Event Log query engine (the same engine `wevtutil` and Event Viewer's custom-filter XML use) — only matching records are ever materialized as PowerShell objects. On a multi-hundred-thousand-record Security log from a busy server, this is routinely the difference between a query that returns instantly and one that takes minutes; default to `-FilterHashtable` (or `-FilterXPath` when you need boolean logic, time-delta math, or suppression conditions the hashtable syntax can't express) and reserve `Where-Object` for narrowing an already-small, already-filtered result set.

Useful `-FilterHashtable` keys beyond `LogName`/`Id`: `StartTime`/`EndTime` (both accept `DateTime` objects, e.g. `(Get-Date).AddDays(-7)`), `ProviderName` (filter by the logging provider rather than the channel, useful when one provider writes to multiple channels), `Data` (match a specific EventData field value), `UserID` (filter by the security principal that logged the event, distinct from the event's *TargetUserName* field).

For parsing `.Message` vs. indexing `.Properties[]`:

```powershell
# .Message: pre-rendered, human-readable text - convenient for eyeballing, fragile for scripting
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1).Message

# .Properties[]: the same event's raw, ordered EventData values - index into it directly rather than regexing Message
$event = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
$event.Properties[5].Value   # TargetUserName
$event.Properties[8].Value   # LogonType
$event.Properties[18].Value  # IpAddress
```

🔴 **`.Properties[]` indexing is more reliable for scripting than regex-parsing `.Message`, and the reason is locale.** `.Message` is rendered from a localized string template baked into the provider's manifest — on a non-English-language Windows install, the same 4624 event's `.Message` text is in that install's display language, silently breaking any regex written against English field labels like `Account Name:` or `Logon Type:`. `.Properties[]` is the raw, ordered, language-independent EventData array the manifest defines regardless of display-language — the index positions are stable across locales even though the rendered `.Message` text isn't. The tradeoff: you need to know (or look up via `EvtxECmd`'s Event ID Maps, or `Get-WinEvent -ListProvider`/the provider's manifest) which index corresponds to which named field for each event ID, since `Properties[]` carries no field names of its own — only positional values.

For remote collection, export to CSV/EVTX for a case file, and combining multiple logs/hosts into one timeline-ready set:

```powershell
# Remote collection via Invoke-Command - runs the filtered query on each remote host, only matching events cross the wire
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625; StartTime=(Get-Date).AddDays(-1)} -ErrorAction SilentlyContinue
} | Select-Object PSComputerName, TimeCreated, Id, @{N='TargetUser';E={$_.Properties[5].Value}} |
    Export-Csv C:\hunt\logon_sweep.csv -NoTypeInformation

# Same query directly against a remote log without a full session, via -ComputerName (requires WinRM/remote-registry access to the target)
Get-WinEvent -ComputerName DC01 -FilterHashtable @{LogName='Security'; Id=4768,4769} -Credential (Get-Credential)

# Export matched events to a standalone .evtx for the case file - preserves full original XML, not just the flattened columns
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102,4719} |
    Export-Csv C:\hunt\case1234_logclears.csv -NoTypeInformation
wevtutil epl Security C:\hunt\case1234_security_filtered.evtx /q:"*[System[(EventID=1102 or EventID=4719)]]"

# Combine multiple logs and multiple hosts into one sorted, timeline-ready export
$computers | ForEach-Object {
    $c = $_
    Get-WinEvent -ComputerName $c -FilterHashtable @{LogName='Security','System','Microsoft-Windows-PowerShell/Operational'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$c}}, TimeCreated, LogName, Id, Message
} | Sort-Object TimeCreated | Export-Csv C:\hunt\multihost_timeline.csv -NoTypeInformation
```

`Export-Csv` flattens events to the columns you select; `wevtutil epl` with a `/q:` XPath query preserves the full original `.evtx` structure (every field, untouched) when the case requires the original record format rather than a derived spreadsheet — pick based on what the case file needs, not habit.

## Audit Policy Fundamentals

A large fraction of the event IDs in this note **do not fire unless the relevant audit subcategory is enabled** — this is the single most common reason an expected event is missing, and it's a separate question from retention.

| | Basic Audit Policy | Advanced Audit Policy |
|---|---|---|
| Where configured | `Local Security Policy` (`secpol.msc`) → `Local Policies` → `Audit Policy` | `Local Security Policy` → `Advanced Audit Policy Configuration` (also settable via Group Policy) |
| Granularity | 9 broad categories (e.g. "Audit account logon events," "Audit object access") — on/off at the category level | Dozens of fine-grained **subcategories** nested under each of the 9 legacy categories (e.g. "Audit object access" splits into File System, Registry, Removable Storage, Kernel Object, and more) |
| OS availability | All supported Windows versions | Windows 7 / Server 2008 R2 and later |
| Practical effect | Coarse — enabling "object access" auditing at the basic level floods the log with every object type | Lets an analyst/admin enable *just* the subcategories that matter (e.g. Removable Storage auditing for 4663, without turning on every other object-access subtype) |

Why this matters for nearly every table in this note: 4688 (process creation with command line), 4697/4698 (service/task creation), 4656/4663 (object access), and several others are conditional on the corresponding advanced-audit subcategory being turned on — none of them are universally on by default in a stock, unhardened install. Before concluding "this event never fired," check current audit policy on a live host with:

```
auditpol /get /category:*
```

Against an offline image, audit policy configuration is recoverable from the `SECURITY` hive (`PolAdtEv` and related keys) and from applied GPO settings — a more involved offline check than the live command above, but worth pursuing when the case turns on whether a specific event *should* have been logged.

## Security Log — Core Event ID Reference

All events below are logged to `Security.evtx`. Where note **05 (Users, Groups & Authentication)** already owns full interpretive depth for an event (logon-type meaning, triage patterns), this table stays at the mechanics/audit-policy layer and cross-links rather than repeats.

### Account Logon / Logoff

| Event ID | Name | Audit subcategory required | Full interpretation |
|---|---|---|---|
| 4624 | Logon success | Logon/Logoff — Audit Logon (on by default in most modern baselines) | **Users, Groups & Authentication (05)** — Logon Types table |
| 4625 | Logon failure | Same as 4624 | **05** |
| 4634 | Logoff | Logon/Logoff — Audit Logoff | **05** |
| 4647 | User-initiated logoff | Same as 4634 | **05** |
| 4648 | Logon with explicit credentials | Logon/Logoff — Audit Logon | **05** — dedicated section, the lateral-movement tell |
| 4672 | Special privileges assigned to new logon | Fires automatically alongside a privileged 4624 | **05** |
| 4768 | Kerberos TGT request | Account Logon — Audit Kerberos Authentication Service (Domain Controller only) | **05b (Active Directory & Domain Forensic Artifacts)** |
| 4769 | Kerberos service ticket request | Account Logon — Audit Kerberos Service Ticket Operations (DC only) | **05b** |
| 4776 | NTLM credential validation | Account Logon — Audit Credential Validation | **05** |
| 4800 / 4801 | Workstation locked / unlocked | Logon/Logoff — Audit Other Logon/Logoff Events | **05** |

The mechanics point worth adding here that 05 doesn't cover: this entire family lives under the **Logon/Logoff** and **Account Logon** advanced-audit categories, both of which are enabled by default in Windows' out-of-box audit baseline on modern client and server builds — meaning 4624/4625/4634/4647/4672 are among the more reliable Security-log events an analyst can count on being present without first confirming policy, in contrast to the object-access and process-creation events below.

### Object Access

| Event ID | Name | Audit subcategory required | Notes |
|---|---|---|---|
| **4656** | A handle to an object was requested | Object Access (specific subtype — File System, Registry, Removable Storage, etc.) — **not on by default** | Precedes 4663/4660 — records the *request* for access, including the requested access rights, before any actual read/write occurs |
| **4663** | An attempt was made to access an object | Same subcategory as 4656 — **not on by default** | The event that actually shows *what was done* to the object (read/write/delete) — see **Removable Device (USB) Forensics (09)** for this event ID's specific use tracking file-level access on removable storage |
| **4660** | An object was deleted | Object Access — File System subcategory — **not on by default** | Pairs with 4663 when the specific access type was delete |

🔴 **This entire family is off by default.** Unlike the logon/logoff family above, none of 4656/4663/4660 fire without explicitly enabling the relevant Object Access subcategory *and* configuring a System Access Control List (SACL) on the specific object(s) of interest — auditing "object access" as a category alone isn't sufficient; Windows also needs to be told, object by object, which files/keys/devices to audit. Their absence on a host tells you nothing about whether access occurred unless you've independently confirmed both the audit subcategory and the object's SACL were configured beforehand.

### Privilege Use

| Event ID | Name | Notes |
|---|---|---|
| 4672 | Special privileges assigned to new logon | Covered under Account Logon/Logoff above — repeated here for the Privilege Use family's completeness |
| 4673 | A privileged service was called | Records use of a specific sensitive privilege (e.g. `SeDebugPrivilege`) during a service call — requires Privilege Use auditing, **not on by default**, and historically noisy enough that many environments deliberately leave it off |
| 4674 | An operation was attempted on a privileged object | Companion to 4673 for privileged-object operations rather than service calls — same audit-policy and noise caveats |

### Process Creation — 4688

🔴 **4688 is one of the single highest-value forensic events in this entire note — and it is functionally two different events depending on one GPO setting.**

| State | What 4688 records |
|---|---|
| Default (Command Line auditing **disabled**) | New process name, PID, parent process, creator's Logon ID — useful for a process tree, but with no visibility into *what arguments were passed* |
| **Command Line auditing enabled** | Everything above **plus the full command line** the process was launched with — argument by argument, exactly as typed or scripted |

The GPO that enables the richer form: **`Administrative Templates → System → Audit Process Creation → Include command line in process creation events`** (also settable directly via the registry value `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled`). This is layered on top of the base **Detailed Tracking — Audit Process Creation** subcategory, which itself must also be enabled for 4688 to fire at all — two separate switches, both non-default, both required for the fully useful version of this event.

Why it's worth flagging this prominently: with command-line auditing on, 4688 captures the exact invocation of `powershell.exe -enc <base64>`, `rundll32.exe` LOLBIN abuse, or a service/task's actual launch arguments — evidence that otherwise requires a live EDR agent or Sysmon to obtain. With it off, 4688 tells you *that* `powershell.exe` ran, and nothing about what it was told to do — near-useless for distinguishing a legitimate admin script from an attacker's obfuscated one-liner. Always check whether this GPO was active before treating a lack of suspicious 4688 command-line content as evidence of nothing happening.

### Audit Policy Change — 4719

🔴 **An attacker disabling auditing to hide their tracks is itself a critical finding, and 4719 is how you catch it.** Event ID 4719 fires whenever the system's audit policy itself is changed — including an attacker (with sufficient privilege) *turning off* the very categories that would otherwise log their subsequent activity. A 4719 event immediately preceding a gap in expected logging, or preceding activity that goes suspiciously unlogged despite policy supposedly requiring it, should be treated with the same urgency as a 1102 log-clear event — both are the attacker directly attacking the evidence trail rather than merely acting within it.

### Service & Scheduled-Task Related

| Event ID | Name | Full mechanics/interpretation |
|---|---|---|
| 4697 | A service was installed on the system | **Services.md (10)** — requires non-default auditing; System log 7045 (below) is the more reliable baseline |
| 4698 | A scheduled task was created | **Scheduled Tasks.md (10)** — requires non-default auditing; TaskScheduler/Operational 106 (below) is the more reliable baseline |
| 4699 | A scheduled task was deleted | **Scheduled Tasks.md** |
| 4700 | A scheduled task was enabled | **Scheduled Tasks.md** |
| 4701 | A scheduled task was disabled | **Scheduled Tasks.md** |
| 4702 | A scheduled task was updated | **Scheduled Tasks.md** |

All six require the **Object Access — Audit Other Object Access Events** (4698–4702) or equivalent (4697) subcategory, none on by default — this is the same detection-gap pattern that runs through the whole Object Access family above, and it's why both sibling notes lean on their respective operational-log baseline (7045, TaskScheduler/Operational 106) instead.

### Account Management

| Event ID | Name | Analyst value |
|---|---|---|
| **4720** | A user account was created | Same-day-as-intrusion account creation is one of the strongest persistence indicators available — cross-reference against the SAM-hive creation timestamp covered in **05** |
| 4722 | A user account was enabled | A previously disabled account (e.g. a stale service or ex-employee account) being re-enabled mid-incident is a strong re-activation-for-persistence signal |
| 4724 | An attempt was made to reset an account's password | Attacker locking out the legitimate user, or seizing an account for continued access |
| 4725 | A user account was disabled | Can indicate an attacker disabling a competing/monitoring account, or legitimate IR containment already in motion — context-dependent |
| **4726** | A user account was deleted | Cleanup — an attacker removing an account they created once it's no longer needed, or legitimate account lifecycle management |
| **4728** | A member was added to a security-enabled global group | Privilege-escalation/persistence — adding an account to a privileged group (e.g. Domain Admins) is a core technique |
| 4732 | A member was added to a security-enabled local group | Same pattern as 4728, scoped to a local group (e.g. local Administrators) rather than a domain group |
| 4738 | A user account was changed | Broad "something about this account object changed" event — check the specific changed attributes in the event data before drawing conclusions |

This family is logged under the **Account Management** audit category, which is enabled by default in most modern baselines for the account-level events (4720/4722/4725/4726/4738) — more reliably present than the Object Access family above, though group-membership events (4728/4732) depend on the specific group-management subcategories being active.

### Log Clearing — 1102

| Event ID | Name | Notes |
|---|---|---|
| **1102** | The audit log was cleared | See the full [Log Clearing & Tampering Detection](#log-clearing--tampering-detection) section above — repeated here for reference-table completeness. This event cannot be disabled by normal audit-policy configuration; it fires as an inherent part of the Security auditing subsystem's own clear operation |

## System Log — Key Event IDs

### Service Control Manager Events

| Event ID | Name | Notes |
|---|---|---|
| **7045** | A service was installed on the system | **Primary, default-on detection signal for new services** (Windows Server 2008 R2 / Windows 7 onward) — full mechanics/red-flag depth in **Services.md (10)**, which treats this as the reliable baseline over the audited-only Security 4697 |
| 7034 | A service crashed unexpectedly | Useful for confirming a service actually ran (and failed) rather than just being installed |
| 7035 | A start/stop control was sent to a service | Records the control-request side of a state transition — pairs with 7036 |
| 7036 | A service entered the running or stopped state | Confirms the service actually transitioned state, not just that a control was sent |
| 7040 | A service's start type was changed | E.g. Manual → Auto-start, or Auto-start → Disabled — a start-type change toward Auto-start on a service with no legitimate reason to persist that way is worth chasing |

### Time-Change Events — 1 and 4616

🔴 **An attacker changing system time to muddy a timeline is a classic anti-forensics move, and it's recorded in two independent places — cross-reference both.**

| Event ID | Log | Provider | Notes |
|---|---|---|---|
| **1** | System | `Microsoft-Windows-Kernel-General` | "The system time was changed" — kernel-level record of the change, including old and new time values |
| **4616** | Security | `Microsoft-Windows-Security-Auditing` | "The system time was changed" — the Security-log equivalent, additionally recording *who* (which account/process) made the change, under the **System — Audit Security State Change** subcategory (on by default in most modern baselines) |

Because these are two independent providers recording the same underlying event, use them together: System-log ID 1 confirms the change occurred and gives the old/new time delta; Security-log 4616 attributes it to a specific account and process. A time change with no plausible administrative justification (NTP drift correction, timezone/DST adjustment, legitimate sync) — especially one immediately preceding or following other suspicious activity, or one that shifts the clock backward — is a strong indicator the attacker was deliberately trying to skew file timestamps, event-log timestamps, or both ahead of an anticipated forensic timeline reconstruction. Full anti-forensics-technique depth (how a skewed clock propagates into filesystem MACB timestamps and other event timestamps, and how to detect/correct for it during timeline analysis) belongs in the forthcoming **Anti-Forensics and Evidence Destruction** note; this note owns the two source events themselves.

### PowerShell

To pull both events and join them by timestamp so the old/new time delta (ID 1) and the responsible account (4616) sit in one row:

```powershell
$sys1 = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-Kernel-General'; Id=1} -ErrorAction SilentlyContinue
$sec4616 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4616} -ErrorAction SilentlyContinue

$sys1 | Select-Object TimeCreated, @{N='NewTime';E={$_.Properties[0].Value}}, @{N='PreviousTime';E={$_.Properties[1].Value}}
$sec4616 | Select-Object TimeCreated, @{N='Account';E={$_.Properties[1].Value}}, @{N='NewTime';E={$_.Properties[4].Value}}, @{N='PreviousTime';E={$_.Properties[5].Value}}
```

To perform a quick backward-shift flag across an estate: any time change where the new time is earlier than the previous time is a stronger anti-forensics signal than a forward drift correction:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4616} -ErrorAction SilentlyContinue |
        Where-Object { [datetime]$_.Properties[4].Value -lt [datetime]$_.Properties[5].Value } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, @{N='Account';E={$_.Properties[1].Value}}
} | Export-Csv C:\hunt\backward_time_shifts.csv -NoTypeInformation
```

### Boot & Shutdown Events

| Event ID | Name | Notes |
|---|---|---|
| 6005 | The Event log service was started | Logged near boot — a reasonable, indirect boot-time marker when a more direct one isn't available |
| 6006 | The Event log service was stopped | Logged during a clean, orderly shutdown |
| **6008** | The previous system shutdown was unexpected | Records an *ungraceful* shutdown (power loss, crash, forced power-off) detected on the *next* boot — useful for spotting an attacker forcibly powering off a host to disrupt live response, or simply a genuine crash worth ruling out before assuming malicious intent |
| 6013 | System uptime | Reports current uptime in seconds, logged periodically (roughly daily) by the EventLog source — useful for confirming a host's actual running time against its expected patch/reboot cadence |

## Application Log

The Application log is the least forensically dense of the three core logs — it's a catch-all for third-party and Microsoft application-level errors, warnings, and informational events, with far less standardized structure across providers than Security or System (every application vendor logs however it chooses). It's rarely the first place to look, but two event families are worth knowing:

| Event ID | Name | Notes |
|---|---|---|
| 11707 | Product installation completed successfully | MSI installer event — useful corroboration for when a piece of software (legitimate or attacker-delivered via a signed/unsigned MSI) was installed |
| 11724 | Product removed | MSI installer event — the uninstall-side counterpart to 11707 |
| **1000** | Application error | Application crash event — records the crashing process, faulting module, and exception code; useful when a foothold or injected payload destabilizes its host process |
| 1001 | Windows Error Reporting event | Fires alongside 1000 for crashes WER processed — carries a bucket ID that can sometimes be pivoted into Microsoft's own crash-report data if the environment permits WER upload |

## Specialized Operational Logs

### PowerShell

PowerShell forensics spans **three** distinct logging surfaces, each richer than the last, and — critically — the richest one is not on by default.

| Log / Event ID | Channel | Default state | What it captures |
|---|---|---|---|
| 400 / 403 | `Windows PowerShell.evtx` (the older, classic log — predates the Operational channel's richer content) | On by default | Engine lifecycle — 400 = engine state started, 403 = engine state stopped. Minimal detail; largely superseded by the Operational channel's events on systems that have them, but still the only PowerShell-adjacent log on older OS versions/PowerShell versions that predate the Operational channel |
| 800 | `Windows PowerShell.evtx` | On by default | Pipeline execution details — records that a pipeline ran, with some detail, but not the full script content the way 4104 does |
| 4103 | `Microsoft-Windows-PowerShell/Operational` | On by default (module logging itself is more configurable, but the channel/event exists by default) | Module logging — records pipeline execution details for specific modules, including parameter values, when Module Logging is configured for the relevant modules |
| **4104** | `Microsoft-Windows-PowerShell/Operational` | **Off by default — must be explicitly enabled** | **Script Block Logging — the single highest-value PowerShell forensic event.** Captures the actual **deobfuscated script block content** as PowerShell's engine sees it after decoding/deobfuscation — meaning even a heavily obfuscated one-liner shows up here in its executed, readable form |
| 4105 / 4106 | `Microsoft-Windows-PowerShell/Operational` | Tied to the same logging configuration as 4103/4104 | Command invocation start (4105) / stop (4106) — bounds individual command execution within a broader script-block session |

🔴 **Enable via Group Policy or registry — this is the PowerShell equivalent of 4688's command-line-auditing GPO, and just as consequential.** GPO path: `Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`. Registry equivalent: `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging = 1`. With this off, an attacker's obfuscated `-EncodedCommand` payload is invisible at the script-content level anywhere in the event log; with it on, 4104 shows you the payload after PowerShell itself has already done the work of decoding it.

Classic ScriptBlock content markers worth grep'ing for once 4104 events are in hand:

| Marker | Why it's suspicious |
|---|---|
| `-EncodedCommand` / `-enc` | Base64-encoded script passed on the command line — a common evasion of naive command-line string matching, though not of 4104 itself since 4104 logs the *decoded* content |
| `IEX` / `Invoke-Expression` | Executes a string as code — a staple of fileless/download-and-execute PowerShell payloads |
| `DownloadString` / `DownloadFile` / `Net.WebClient` | Remote payload retrieval — the download half of a download-and-execute chain |
| `-WindowStyle Hidden` / `-NoProfile` | Suppresses the visible console window and skips profile-load noise — common in scripted/automated attacker use, less common in interactive admin use |
| `FromBase64String` | Manual decode of an embedded payload — often paired with `-EncodedCommand` at the outer layer or used to decode a second-stage payload |

To confirm whether Script Block Logging is actually enabled before concluding 4104 has (or should have) content:

```powershell
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4103,4104,4105,4106} -MaxEvents 20
```

To pull 4104 content and flag the classic markers from the table above in one pass:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} |
    Where-Object { $_.Message -match '-enc|EncodedCommand|IEX|Invoke-Expression|DownloadString|DownloadFile|Net\.WebClient|WindowStyle Hidden|NoProfile|FromBase64String' } |
    Select-Object TimeCreated, @{N='MatchedMarkers';E={ ($Matches.Values -join ', ') }}, @{N='ScriptBlock';E={$_.Message}}
```

To sweep an estate for 4104 hits, since Script Block Logging is opt-in per host and coverage gaps are common:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        ScriptBlockLoggingEnabled = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        FourOneOhFourCount = (Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104} -ErrorAction SilentlyContinue | Measure-Object).Count
    }
} | Export-Csv C:\hunt\4104_coverage_sweep.csv -NoTypeInformation
```

### WinRM / PowerShell Remoting

`Microsoft-Windows-WinRM/Operational` is the native log for WS-Management (WinRM) activity — the transport underlying PowerShell Remoting (`Enter-PSSession`, `Invoke-Command`), `winrs.exe`, and CIM-over-WSMan calls (see **WMI Event Consumers'** remote-execution section for the CIM/WSMan angle specifically). This note owns the **log and channel mechanics**; the full lateral-movement evidence chain — source/destination pairing, session establishment semantics, how WinRM remoting compares to `sc create`/`schtasks /s`/WMI as a remote-execution primitive — belongs in the forthcoming **Lateral Movement** note.

At the mechanics level: WinRM listens on TCP 5985 (HTTP) / 5986 (HTTPS) by default, and both a client-side and server-side `WinRM/Operational` log exist — the destination host's log is generally the more useful of the two for confirming an inbound remoting session actually occurred. Corroborate WinRM/Operational entries against Security-log 4624 (Logon Type 3, since PowerShell Remoting authenticates as a network logon) on the destination host for a fuller picture of who connected and when.

### PowerShell

To list `WinRM/Operational` events on the destination host:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'} -MaxEvents 50
```

To correlate WinRM session activity against the corresponding Security-log Logon Type 3 (network logon) entries around the same time window, since WinRM/Operational itself doesn't carry the authenticating account in an easily-indexed field:

```powershell
$winrm = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue
$logons3 = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-24)} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -eq 3 }
$winrm + $logons3 | Sort-Object TimeCreated | Select-Object TimeCreated, LogName, Id, Message
```

To sweep an estate's destination-host `WinRM/Operational` logs in one pass, useful when hunting for a specific attacker technique known to use `Invoke-Command`/`winrs.exe`:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WinRM/Operational'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Id, Message
} | Export-Csv C:\hunt\winrm_sweep.csv -NoTypeInformation
```

### Terminal Services / RDP

RDP evidence splits across **three** independent sources that, read together, form one coherent evidence chain — each answers a different piece of "who connected, when, and did the session actually establish."

| Source | Event ID(s) | What it shows |
|---|---|---|
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | **21** | Session logon succeeded — a full RDP session actually started |
| Same channel | **22** | Shell start — the user's desktop/shell finished loading within the session |
| Same channel | **23** | Session logoff |
| Same channel | **24** | Session disconnect — session left in a disconnected-but-not-logged-off state |
| Same channel | **25** | Session reconnect — a disconnected session was resumed |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | **1149** | Network-level RDP connection, including source IP — see caveat below |
| `Security.evtx` | **4624**, Logon Type **10** | RemoteInteractive logon success — the authentication half of the session, tied together with the above by timestamp/account |
| `Security.evtx` | **4624**, Logon Type **7** | Reconnect to an existing disconnected session (unlock-family logon type, reused for RDP reconnect) |

🔴 **1149 is logged even on connections that never complete authentication or get cancelled — treat it as "a network-level RDP connection attempt reached this host," not "a session was established."** This is the most important caveat in this section: an analyst who sees a 1149 event and reports it as a successful logon is overstating the evidence. Always pair 1149 with LocalSessionManager 21 (session logon succeeded) and/or Security 4624 Type 10 before concluding a session actually established — 1149 alone only proves the connection reached the RDP listener and network authentication was attempted, which is still useful (confirms source IP even for failed/aborted attempts) but is a different claim than "this account logged on."

Full client-side RDP artifact depth (`Terminal Server Client\Servers` registry connection history, bitmap cache reconstruction, jump-list evidence of RDP client use) — the *outbound*, source-host half of the picture — is covered in **Users, Groups & Authentication (05)**'s RDP Usage Tracking section and the forthcoming **Lateral Movement** note; this note owns the destination-host log/event mechanics only.

### PowerShell

To pull the LocalSessionManager and RemoteConnectionManager operational logs:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25} -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -MaxEvents 50
```

To reconstruct one coherent RDP session timeline by merging all three sources (session-manager events, 1149 network-connection events, and Security 4624 Type 10/7) sorted by time, so the "connection reached the host" claim (1149) and the "session actually established" claim (21/4624 Type 10) sit side by side rather than being read in isolation:

```powershell
$sessionEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23,24,25} -ErrorAction SilentlyContinue
$netEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -ErrorAction SilentlyContinue
$logonEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
    Where-Object { $_.Properties[8].Value -in 10,7 }

$sessionEvents + $netEvents + $logonEvents | Sort-Object TimeCreated |
    Select-Object TimeCreated, LogName, Id, @{N='Summary';E={$_.Message.Split("`n")[0]}}
```

🔴 Confirm any 1149 hit has a matching 21 or 4624 Type 10 nearby before reporting it as a completed logon — see the caveat above.

To sweep an estate's destination hosts for RDP sessions from a specific source IP of interest:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -eq 10 } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, @{N='User';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
} | Export-Csv C:\hunt\rdp_type10_sweep.csv -NoTypeInformation
```

### TaskScheduler/Operational

`Microsoft-Windows-TaskScheduler/Operational` (events 106/140/141/200/201) plus the corresponding Security-log family (4698–4702) are covered in full — channel mechanics, audit-policy dependency, and the reliable-baseline argument for leading with 106/200/201 over the audited-only 4698 — in **Scheduled Tasks.md (10)**. See that note rather than duplicating the table here.

### WMI-Activity/Operational

`Microsoft-Windows-WMI-Activity/Operational` (events 5857–5861) and the parallel Sysmon 19/20/21 events for WMI permanent-subscription creation are covered in full — including the Windows-10-centric reliability caveat for the native log versus Sysmon's more consistent coverage — in **WMI Event Consumers.md (10)**. See that note rather than duplicating the table here.

### OAlerts (Office Alerts)

The `OAlerts` channel (surfaced as `OAlerts.evtx`, generally filed under Application-adjacent logs rather than one of the three core channels) records Microsoft Office's own security-relevant alerts — Protected View warnings, blocked macros, and similar Office-generated security prompts.

| Event ID | Notes |
|---|---|
| **300** | The general-purpose Office alert entry — records the alert text/description Office itself generated (e.g. a blocked-macro or Protected View warning); confirm the exact alert text in the event data rather than assuming a specific meaning from the ID alone, since this channel logs a fairly wide variety of Office-generated alert content under a small number of event IDs |

This is intentionally thin coverage — OAlerts is a genuinely low-volume, narrow-purpose log compared to everything else in this note, and its main investigative value is corroborating that a user was shown (and how they responded to) an Office macro/security warning around the time of a suspected malicious-document delivery, cross-referenced against **Email Forensics** (forthcoming) and **Web Browser Forensics** for the delivery vector itself.

### PowerShell

To pull OAlerts events around a suspected document-delivery window; low volume means this is usually a quick, full-log read rather than a filtered sweep:

```powershell
Get-WinEvent -FilterHashtable @{LogName='OAlerts'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, Message
```

## WLAN / Geo-Location Events

`Microsoft-Windows-WLAN-AutoConfig/Operational` records wireless network connection activity — useful, on a laptop or any Wi-Fi-capable host, for reconstructing a rough physical-movement timeline from SSID connect/disconnect history alone, without needing GPS or any dedicated location-service artifact.

| Event ID | Meaning |
|---|---|
| **8001** | Successfully connected to a wireless network — records the SSID and connection timestamp |
| **8002** | Failed to connect to a wireless network |
| **8003** | Disconnected from a wireless network |
| **11004** | Wireless network association/connection attempt detail (profile- or DHCP-adjacent stage of the connection sequence) |
| **11005** | Wireless network connection completed successfully (companion detail event to 8001 in the same connection sequence) |

This is deliberately kept brief — coverage here is thinner in the source posters than the rest of this note's material, per this module's planning decision to fold WLAN/geo-location content into this note rather than dedicate a standalone note to it. Practical use: a sequence of 8001 events with different SSIDs across a timeline gives a coarse "this laptop was physically at location A, then location B" reconstruction — useful for corroborating or contradicting a suspect/witness's claimed whereabouts, or for confirming a stolen/exfiltrated laptop's movement after the fact. Cross-reference against Windows OS Fundamentals & Versions' session/boot timeline data and any available Timeline Analysis (forthcoming) super-timeline for the fullest picture.

### PowerShell

To pull the connect/disconnect sequence and build a coarse SSID-by-SSID movement timeline:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001,8002,8003,11004,11005} -ErrorAction SilentlyContinue |
    Sort-Object TimeCreated | Select-Object TimeCreated, Id, Message
```

To sweep a laptop fleet for connections to a specific SSID of interest (e.g. an unexpected/unauthorized network named in a physical-security incident):

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; Id=8001} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'SUSPECT-SSID' } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Message
} | Export-Csv C:\hunt\wlan_ssid_sweep.csv -NoTypeInformation
```

## Tooling

| Tool | Use |
|---|---|
| **`wevtutil.exe`** | Native, built-in CLI — query (`wevtutil qe`), export (`wevtutil epl`), and enumerate log configuration (`wevtutil gl <log>`, `wevtutil el`) directly from the command line, live or against an offline-mounted log; the fastest no-install option on a live host or within a remote shell |
| **Event Viewer (`eventvwr.msc`)** | Built-in GUI — adequate for ad hoc single-host review and applying XPath-based custom filters, but not built for cross-host or bulk analysis |
| **`Get-WinEvent`** (PowerShell) | The modern, XML/XPath-capable query cmdlet — works against live channels and offline `.evtx` files alike, supports structured filtering (`-FilterHashtable`) far more efficiently than `Get-EventLog` |
| **`Get-EventLog`** (PowerShell) | 🔴 **Legacy/deprecated** — limited to the three core classic logs, cannot query most specialized operational channels, and is markedly slower than `Get-WinEvent` on large logs; prefer `Get-WinEvent` for all new work |
| **EvtxECmd** (Eric Zimmerman) | The primary offline `.evtx` parser in this ecosystem — bulk-parses `.evtx` files to CSV/JSON, and ships with a maintained set of **Event ID Maps** that translate raw, sparse EVTX field names into human-readable, per-event-type descriptions (e.g. mapping 4624's raw fields into clearly labeled Logon Type/Account/Source IP columns) — the standard tool for turning a KAPE collection's worth of `.evtx` files into an analyzable dataset |
| **Event Log Explorer / EZ timeline tooling** | Companion GUI review layer for EvtxECmd output, part of the broader Eric Zimmerman/KAPE ecosystem workflow already established elsewhere in this module |
| **Hayabusa** | Rust-based EVTX threat-hunting and Sigma-rule scanning tool — named here as existing and worth knowing about; deep Sigma-rule-hunting depth is explicitly out of scope for this pass (FOR608 territory, deferred per this module's planning decisions) |
| **Chainsaw** | Similar niche to Hayabusa (fast EVTX triage/Sigma-rule scanning) — same brief, name-only treatment as Hayabusa here |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Security-log 1102 present, with the log's oldest record timestamp suspiciously close to the clear event | Strong evidence of deliberate evidence destruction — investigate the window immediately before the clear with priority |
| System-log 104 recording a log clear with no corresponding, explainable administrative action | Corroborating evidence alongside 1102, or evidence a non-Security log was cleared |
| 4688 process-creation events present but command-line auditing was never enabled | The event exists but tells you almost nothing about intent — confirm the GPO state before concluding a process's purpose from 4688 alone |
| 4104 Script Block Logging content containing `-EncodedCommand`, `IEX`, `DownloadString`, or `FromBase64String` with no legitimate administrative explanation | Classic obfuscated/download-and-execute PowerShell pattern |
| 4719 (audit policy change) immediately preceding a gap in expected logging | Attacker directly disabling auditing to hide subsequent activity — treat with the same urgency as a log clear |
| System-log time-change event (ID 1) or Security 4616 with no administrative justification, especially a backward time shift | Classic anti-forensics timeline manipulation |
| RDP Logon Type 10 (4624) success from an unfamiliar source IP or outside business hours, especially following a 4625 cluster | Possible brute-force-then-success RDP compromise — see **05**'s Logon-Type Triage table for the full pattern |
| 1149 (RDP network connection) present with no corresponding LocalSessionManager 21 or 4624 Type 10 | Connection attempt reached the host but never established a session — don't overstate this as a successful logon |
| 4720 (account created) or 4728/4732 (added to privileged group) inside a known intrusion window, outside documented change-management | Core persistence/privilege-escalation indicator |
| Event Record ID sequence gaps in a log with no corresponding clear event | Possible selective record deletion at the repository level, distinct from and more surgical than a full log clear |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Logon-type interpretation and full field-level depth for 4624/4625/4634/4647/4648/4672/4768/4769/4776/4800/4801 | **Users, Groups \& Authentication (05)** |
| Domain-only Kerberos event depth (4768/4769/4771 fields, delegation abuse) | **Active Directory \& Domain Forensic Artifacts (05b)** |
| Service-creation event mechanics in investigative context (7045/4697) | **Persistence Mechanisms → Services** |
| Scheduled-task event mechanics in investigative context (106/140/141/200/201, 4698–4702) | **Persistence Mechanisms → Scheduled Tasks** |
| WMI permanent-subscription event mechanics in investigative context (5857–5861, Sysmon 19/20/21) | **Persistence Mechanisms → WMI Event Consumers** |
| File/object-level access auditing on removable storage (4663/4656/6416) | **Removable Device (USB) Forensics (09)** |
| Normal process-tree baseline for judging 4688/WmiPrvSE-style process-creation anomalies | **Windows OS Fundamentals \& Versions (01)** |
| Hive/SACL mechanics underlying audit-policy configuration recovery from an offline `SECURITY` hive | **Registry Forensics Fundamentals (04)** |
| Full RDP/WinRM/remote-service/remote-task lateral-movement evidence chains (source/destination pairing) | **Lateral Movement** (forthcoming) |
| How time-manipulation and log-clearing findings feed a broader anti-forensics assessment, and how a skewed clock propagates into filesystem timestamps | **Anti-Forensics and Evidence Destruction** (forthcoming) |
| Building a cross-artifact super-timeline that incorporates event-log timestamps alongside filesystem/registry timestamps | **Timeline Analysis** (forthcoming) |
| Sigma-rule-driven hunting and enterprise-scale EVTX triage with Hayabusa/Chainsaw at full depth | **Threat Hunting Methodology and Intelligence** (forthcoming) |

## Resources

- SANS FOR508 "Hunt Evil" poster — Windows Event Log panel and Malware Persistence panel's event-ID coverage — used as a coverage checklist, rewritten in this note's own words
- SANS FOR500 poster — event log fundamentals coverage checklist
- Microsoft Learn — Windows security event IDs reference (auditing/threat-protection documentation)
- Microsoft Learn — Advanced Audit Policy Configuration documentation (subcategory reference, recommended baseline settings)
- Eric Zimmerman's tools (EvtxECmd, Event Log Explorer) — https://ericzimmerman.github.io/
- Hayabusa — https://github.com/Yamato-Security/hayabusa
- Chainsaw — https://github.com/WithSecureLabs/chainsaw
- MITRE ATT&CK T1070.001 (Indicator Removal: Clear Windows Event Logs) — https://attack.mitre.org/techniques/T1070/001/
- MITRE ATT&CK T1562.002 (Impair Defenses: Disable Windows Event Logging) — https://attack.mitre.org/techniques/T1562/002/
- MITRE ATT&CK T1070.006 (Indicator Removal: Timestomp) — https://attack.mitre.org/techniques/T1070/006/ (System Time manipulation is a closely related technique, covered here as 1/4616; full anti-forensics depth in the forthcoming dedicated note)
