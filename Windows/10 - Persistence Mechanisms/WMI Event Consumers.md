# WMI Event Consumers

Windows Management Instrumentation (WMI) permanent event subscriptions let an attacker wire up "when X happens, run Y" entirely inside the WMI repository — a database file most first responders never open, using a persistence mechanism that leaves no Run key, no service, no scheduled task, and in its most evasive form no file on disk at all. Where every other note in this family points you at a registry key or a filesystem path, this one points you at a purpose-built database that requires its own parser to read. That single fact is why WMI event subscriptions carry the highest stealth rating of any mechanism in the Persistence Mechanisms family (see the orientation table in Autostart (Run/RunOnce) Keys) and why analyst familiarity with them, historically, lags far behind Run keys, services, and scheduled tasks.

WMI also does double duty this note has to cover, the same duality Services.md covers for `sc create`/PsExec: it is simultaneously a **persistence** mechanism (the permanent-subscription triad covered in depth below) and a **remote-execution/lateral-movement** primitive (`wmic process call create`, `Invoke-CimMethod -ClassName Win32_Process -MethodName Create`) attackers use to run code on other hosts without dropping a service or task there at all. This note covers both angles from the host-evidence side; full lateral-movement depth — source/destination session semantics, how WMI compares to PsExec/PowerShell Remoting/remote scheduled tasks — belongs in Lateral Movement (note 12) and is only summarized here.

This is the third note in the Persistence Mechanisms family — see Autostart (Run/RunOnce) Keys for the family-wide orientation table.

> 🔴 **A lone `__EventFilter` or a lone `__EventConsumer` is inert.** Neither one does anything by itself — an event filter with no consumer bound to it never triggers an action, and a consumer with no filter bound to it never fires. The thing that actually persists and executes is the **bound triad**: filter + consumer + `__FilterToConsumerBinding`. Hunt for complete, bound triads, not isolated filter or consumer instances — flagging every standalone `__EventFilter` on a host will bury you in noise from legitimate monitoring software.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [WMI Architecture Primer](#wmi-architecture-primer)
- [Where This Family's Persistence Lives, Contrasted](#where-this-familys-persistence-lives-contrasted)
- [The Permanent-Subscription Triad](#the-permanent-subscription-triad)
- [How to Interpret the Triad](#how-to-interpret-the-triad)
- [Live-Host Enumeration](#live-host-enumeration)
- [Event Log Evidence](#event-log-evidence)
- [Remote WMI as a Lateral-Movement Primitive](#remote-wmi-as-a-lateral-movement-primitive)
- [Why Attackers Prize This Technique](#why-attackers-prize-this-technique)
- [Red Flags Specific to WMI Event Consumers](#red-flags-specific-to-wmi-event-consumers)
- [Tooling](#tooling)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage against `root\subscription` before any repository parser (or even a live-host deep dive) comes out — no third-party tooling required. This is the quintessential native WMI persistence hunt: everything below runs directly through `Get-CimInstance` on a live host with execution access.

```powershell
# Every __EventFilter, __EventConsumer, and __FilterToConsumerBinding on the host, in one pass each
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Select-Object Name, Query
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Select-Object Name, __CLASS
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Select-Object Filter, Consumer

# CommandLineEventConsumer payloads - the single most common malicious-consumer location
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate

# ActiveScriptEventConsumer payloads - the fully-fileless option, script text lives only in the repository
Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | Select-Object Name, ScriptingEngine, ScriptText

# Resolve every binding to the filter and consumer names it actually links - trigger -> action, at a glance
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
    [PSCustomObject]@{
        FilterName   = ($_.Filter -replace '.*Name="(.*)"', '$1')
        ConsumerName = ($_.Consumer -replace '.*Name="(.*)"', '$1')
    }
}

# Flag command lines invoking the classic living-off-the-land payload droppers
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer |
    Where-Object { $_.CommandLineTemplate -match 'powershell.*-enc|certutil|mshta|regsvr32|rundll32' } |
    Select-Object Name, CommandLineTemplate

# Every namespace under ROOT - permanent subscriptions belong in root\subscription only;
# an unfamiliar custom namespace anywhere else on the host is worth a second look
Get-CimInstance -Namespace root -ClassName __Namespace | Select-Object Name
```

## WMI Architecture Primer

Just enough to ground the rest of this note — full WMI internals are out of scope.

WMI is Windows' management/scripting object model: everything from process lists to disk volumes to installed software is exposed as a **class** with **instances**, queryable with **WQL** (WMI Query Language, a SQL-like syntax). Classes are organized into **namespaces**, and two matter for this note:

| Namespace | What lives there |
|---|---|
| `root\cimv2` | The vast majority of everyday WMI activity — `Win32_Process`, `Win32_Service`, `Win32_LogonSession`, hardware/OS inventory classes, and the classes most WQL filter queries reference as their trigger source |
| `root\subscription` | Where **permanent event subscriptions** — the filter/consumer/binding triad this note is about — actually live and persist |

All of this is stored on disk under `%SystemRoot%\System32\wbem\Repository\`, in a small set of files that make up the **WMI repository**:

| File | Role |
|---|---|
| `OBJECTS.DATA` | The actual object store — class definitions and instances, including every `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` instance on the host |
| `INDEX.BTR` | B-tree index into `OBJECTS.DATA` for fast lookup |
| `MAPPING1.MAP` / `MAPPING2.MAP` / `MAPPING3.MAP` | Page-mapping files the repository engine uses to track which physical pages in `OBJECTS.DATA` are current — the repository rotates between them |

None of this is human-readable by opening the file in a hex editor and eyeballing strings the way you might skim a registry hive — it's a proprietary page-based object store. Extracting the filter/consumer/binding triad from an offline `OBJECTS.DATA` requires a WMI-repository-aware parser (see Tooling below), not manual inspection.

## Where This Family's Persistence Lives, Contrasted

Every other mechanism in this family leaves a registry or filesystem footprint you can point a general-purpose tool at. WMI is the outlier:

| Mechanism | Physical evidence location | Parser needed |
|---|---|---|
| Autostart (Run/RunOnce) keys | `SOFTWARE`/`NTUSER.DAT` registry values | Any registry viewer |
| Services | `SYSTEM\CurrentControlSet\Services\<Name>` registry key | Any registry viewer |
| Scheduled Tasks | Task Scheduler XML under `C:\Windows\System32\Tasks\` + `Schedule\TaskCache` registry | Any XML/registry viewer |
| **WMI event consumers** | **WMI repository (`OBJECTS.DATA`, `INDEX.BTR`, `MAPPING*.MAP`)** | **WMI-repository-specific parser required** — general registry/filesystem tools cannot read this data at all |
| DLL hijacking | Planted DLL on the filesystem, no dedicated config store | Any filesystem tool |

This is the single most important fact to internalize about this note: skipping WMI-repository parsing during triage means skipping this entire persistence mechanism, full stop — there is no registry key or file you can eyeball as a fallback the way you can for every other row in this table.

## The Permanent-Subscription Triad

Three WMI class instances, all created in `root\subscription`, work together to form a permanent event subscription. All three must exist and be correctly linked for the subscription to actually do anything.

### 1. Event Filter (`__EventFilter`)

Defines the **triggering condition** — a WQL query that WMI's event subsystem evaluates continuously (or on the interval the query itself specifies). Common trigger patterns:

| WQL pattern | Fires when |
|---|---|
| `SELECT * FROM __InstanceCreationEvent WITHIN <n> WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = '<processname>.exe'` | A specific process starts |
| `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = '<processname>.exe'` | A specific process starts (trace-event variant, lower-latency than the `__InstanceCreationEvent` polling form above) |
| `SELECT * FROM __InstanceCreationEvent WITHIN <n> WHERE TargetInstance ISA 'Win32_LogonSession'` | A user logon occurs |
| `SELECT * FROM __TimerEvent WHERE TimerID = '<id>'` (paired with a registered interval timer) | A fixed time interval elapses — used for beacon-style, time-based persistence |
| `SELECT * FROM __InstanceModificationEvent WITHIN <n> WHERE TargetInstance ISA 'Win32_OperatingSystem'` | A system-state change such as boot/uptime crossing a threshold — a common "run shortly after startup" pattern |

Key fields on an `__EventFilter` instance: `Name` (arbitrary label — attackers often pick something bland and plausible-sounding), `Query` (the WQL text above), `QueryLanguage` (always `WQL`), `EventNamespace` (which namespace the query watches, almost always `root\cimv2`).

### 2. Event Consumer

Defines the **action** taken when the bound filter fires. Four standard consumer classes ship with Windows:

| Consumer class | Action | Notes |
|---|---|---|
| **`CommandLineEventConsumer`** | Runs a command line (`CommandLineTemplate` property) | **Most common in malicious use** — directly equivalent to a Run-key command string, but triggered by an event instead of boot/logon |
| **`ActiveScriptEventConsumer`** | Executes embedded VBScript or JScript (`ScriptText` property, with `ScriptingEngine` set to `VBScript` or `JScript`) | The fully-fileless option — the script text lives as a property value inside the WMI repository itself and **never touches the filesystem**; this is the consumer type responsible for WMI persistence's reputation as the family's most evasive mechanism |
| **`SMTPEventConsumer`** | Sends an email via SMTP when the filter fires | Rare in the wild, but a real, standard consumer class — occasionally seen as an attacker's own crude alerting/exfil channel or, legitimately, in monitoring tooling |
| **`LogFileEventConsumer`** | Writes a line of text to a specified file | Least commonly abused for code execution directly, but can be a low-noise way to stage data or signal state |

`CommandLineEventConsumer` and `ActiveScriptEventConsumer` are the two that matter most operationally — the first because it's the most common, the second because it's the hardest to find with anything other than a repository parser.

### 3. Filter-to-Consumer Binding (`__FilterToConsumerBinding`)

The object that actually links one specific filter to one specific consumer — this is what turns two inert objects into a live, running subscription. Its two key properties, `Filter` and `Consumer`, are references (by path) to the `__EventFilter` and `__EventConsumer` instances it connects.

🔴 **Always resolve the full triad before concluding a subscription is malicious or benign.** A `CommandLineEventConsumer` sitting in the repository with no `__FilterToConsumerBinding` pointing at it will never execute — it's a dead object, possibly a leftover from an uninstalled tool or an incomplete attacker deployment. Conversely, don't stop at "I found a binding" — pull the actual `Filter` and `Consumer` it references and read their `Query`/`CommandLineTemplate`/`ScriptText` content before judging anything.

## How to Interpret the Triad

- **Read the WQL query, not just the filter name.** The `Name` property is an arbitrary label the creator chose — legitimate and malicious filters alike can be named anything. The `Query` property is where the actual trigger logic lives; that's what you evaluate for legitimacy.
- **Read the consumer's action content in full.** For `CommandLineEventConsumer`, that's `CommandLineTemplate` — treat it exactly like a Run-key value or a scheduled task's `Actions` element: does it point at a signed binary in an expected location, or at something in a user-writable path, or at `powershell.exe`/`cmd.exe` with encoded/obfuscated arguments? For `ActiveScriptEventConsumer`, that's the full `ScriptText` — read the script itself.
- **Baseline your environment before flagging every subscription as malicious.** System Center Configuration Manager (SCCM/MECM), several endpoint-monitoring agents, and some legitimate software packages register their own permanent WMI event subscriptions as part of normal operation. The finding is never "a permanent subscription exists," it's "this specific triad's trigger condition and action don't match any known legitimate product installed on this host" — the same "presence isn't automatically damning" caveat that runs through this entire family (compare Services.md's "a service is only as suspicious as its `ImagePath`").
- **A filter or consumer without a binding is inert** — see the callout above. Don't over-flag orphaned halves of a triad as active persistence; note them, but prioritize complete bound triads.
- **Namespace matters.** Permanent subscriptions in `root\subscription` persist across reboots by design. Transient/temporary event subscriptions (registered via `Register-WmiEvent`/`Register-CimIndicationEvent` in an active PowerShell session, not written to `root\subscription`) do not survive a reboot and are a different animal — this note is specifically about the permanent, repository-persisted form.

### PowerShell

Join all three classes into one readable trigger→action table instead of eyeballing filters, consumers, and bindings separately, and decode whichever of `CommandLineTemplate` or `ScriptText` the consumer type actually populates:

```powershell
$filters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
$consumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
$bindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding

$bindings | ForEach-Object {
    $filterName   = ($_.Filter -replace '.*Name="(.*)"', '$1')
    $consumerName = ($_.Consumer -replace '.*Name="(.*)"', '$1')
    $filter   = $filters | Where-Object Name -eq $filterName
    $consumer = $consumers | Where-Object Name -eq $consumerName
    [PSCustomObject]@{
        Filter       = $filterName
        Trigger      = $filter.Query
        Consumer     = $consumerName
        ConsumerType = $consumer.CimClass.CimClassName
        Action       = if ($consumer.CommandLineTemplate) { $consumer.CommandLineTemplate } else { $consumer.ScriptText }
    }
} | Format-Table -Wrap
```

Sweep the triad across an entire estate rather than one host at a time — permanent WMI subscriptions are a classic lateral-movement-adjacent technique, so a single-host check is rarely sufficient once one malicious triad is confirmed:

```powershell
$computers = Get-Content C:\hunt\hosts.txt
Invoke-Command -ComputerName $computers -ScriptBlock {
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | ForEach-Object {
        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Filter       = $_.Filter
            Consumer     = $_.Consumer
        }
    }
} | Export-Csv C:\hunt\wmi_subscriptions_sweep.csv -NoTypeInformation
```

Baseline diff against a known-clean host — anything present only on the suspect host is the lead to chase:

```powershell
$known   = Import-Csv C:\hunt\known_clean_baseline.csv
$current = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Select-Object Filter, Consumer
Compare-Object -ReferenceObject $known -DifferenceObject $current -Property Filter, Consumer
```

Export the full triad with `Export-Clixml` before touching anything, then remove the `__FilterToConsumerBinding` first so the trigger→action link is severed before deleting the filter and consumer it referenced:

```powershell
# Evidence-first: capture the full objects before removal
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Export-Clixml C:\evidence\eventfilters.xml
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Export-Clixml C:\evidence\eventconsumers.xml
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Export-Clixml C:\evidence\bindings.xml

# Remove the binding FIRST, then the filter and consumer it referenced - avoids dangling references
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding |
    Where-Object { $_.Consumer -match '<ConsumerName>' } | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -Filter "Name='<FilterName>'" | Remove-CimInstance
Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Filter "Name='<ConsumerName>'" | Remove-CimInstance
```

## Live-Host Enumeration

On a live system, the triad can be queried directly through WMI itself — no repository parser needed if you have interactive access:

### PowerShell

Enumerate all three core classes directly, live, with no `Select-Object` filtering — the fastest possible first look:

```powershell
# Legacy WMI cmdlets (deprecated but still present through Windows 10/11, absent by default on newer builds)
Get-WmiObject -Namespace root\subscription -Class __EventFilter
Get-WmiObject -Namespace root\subscription -Class __EventConsumer
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding

# CIM cmdlet equivalents (current, work over WSMan for remote use too)
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding
```

`__EventConsumer` is the base class — querying it surfaces instances of all four concrete consumer types (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `SMTPEventConsumer`, `LogFileEventConsumer`) in one pass; query the concrete class name directly (e.g. `-Class CommandLineEventConsumer`) to see only that type with its type-specific properties populated.

🔴 **Live enumeration only works if the host is up and you have execution rights on it.** For dead-box/offline analysis — an acquired image, a triage collection that pulled the repository files but not a live shell — you're back to needing a WMI-repository parser against the extracted `OBJECTS.DATA`/`INDEX.BTR`/`MAPPING*.MAP` set (see Tooling below).

## Event Log Evidence

`Microsoft-Windows-WMI-Activity/Operational` is the primary native log for WMI subscription activity:

| Event ID | Meaning | Notes |
|---|---|---|
| 5857 | A WMI provider started | Can indicate a consumer's action executing (e.g. the provider hosting `CommandLineEventConsumer`/`ActiveScriptEventConsumer` spinning up) — a useful timing anchor, but not exclusively tied to malicious activity |
| 5858 | A WMI provider encountered an error | Worth checking when a suspected subscription appears to have failed to fire as expected |
| 5859 | An `__EventFilter` was registered | Direct signal — "someone created a WMI event filter," right down to the WQL query text in the event data |
| 5860 | An `__EventConsumer` was registered | Direct signal — "someone created a WMI event consumer," with the consumer type and its action content in the event data |
| 5861 | A `__FilterToConsumerBinding` was registered | Direct signal — "someone bound a filter to a consumer," completing an active triad |

🔴 **5859/5860/5861 are the strongest native "someone just created a permanent subscription" signal this log offers, but their reliability is Windows 10+ centric** — coverage and consistency on Windows 7/8.1 and Server 2012 R2-and-earlier is materially weaker. Don't assume these three event IDs will be present and complete on an older host; corroborate with a repository parse instead of relying on the operational log alone when working an older OS build.

**Sysmon**, if deployed, is often the *better* evidence source for this specific technique — it was purpose-built with WMI persistence detection in mind:

| Sysmon Event ID | Meaning |
|---|---|
| 19 (WmiEvent: WmiEventFilter) | An `__EventFilter` was registered — includes the filter name, event namespace, and full WQL query |
| 20 (WmiEvent: WmiEventConsumer) | An `__EventConsumer` was registered — includes the consumer name, type, and destination (command line / script text, depending on type) |
| 21 (WmiEvent: WmiEventConsumerToFilter) | A `__FilterToConsumerBinding` was registered — links a specific consumer name to a specific filter name |

If Sysmon 19/20/21 are available for the window in question, prefer them over the native WMI-Activity log — they're consistently populated across supported OS versions in a way the native operational log's 5859-5861 triad is not guaranteed to be.

## Remote WMI as a Lateral-Movement Primitive

WMI accepts remote connections (over DCOM/RPC by default, or over WSMan when using the CIM cmdlets with a `-ComputerName`/`-CimSession` pointed at WSMan) and can be used to start a process on a remote host directly — no service to install, no task to register there, parallel to `sc \\host create` covered in Services.md:

```
wmic /node:<host> process call create "cmd.exe /c <command>"
```

```powershell
Invoke-WmiMethod -ComputerName <host> -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c <command>"
Invoke-CimMethod -ComputerName <host> -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd.exe /c <command>"}
```

This is a lateral-movement technique from the source host's perspective and, if the attacker also registers a permanent subscription while they're connected, a fresh instance of the persistence mechanism covered above on the destination host. Full source/destination lateral-movement depth (session semantics, credential requirements, how this compares to PsExec/PowerShell Remoting/remote scheduled tasks) belongs in Lateral Movement (note 12); the table below is the destination-host evidence chain this technique leaves behind.

| Evidence Source | What It Shows | Notes |
|---|---|---|
| Network — TCP 135 + dynamic RPC high port range | DCOM/RPC connection to the WMI service (`wmic`, `Invoke-WmiMethod`, legacy `Invoke-CimMethod` without `-CimSession`/WSMan) | Classic RPC endpoint-mapper-then-dynamic-port pattern; the specific high port varies per connection, 135 is the only fixed anchor to filter on |
| Network — TCP 5985 (HTTP) / 5986 (HTTPS) | CIM-over-WSMan connection (`Invoke-CimMethod` with an explicit `-CimSession` built over WSMan, or `New-CimSession`) | Same ports WinRM/PowerShell Remoting use — see Lateral Movement (note 12) for the full WinRM evidence chain |
| Security log 4624 (Logon Type 3) | Network logon from the source host, on the destination | Establishes who connected and from where |
| Security log 4672 | Admin-equivalent privileges assigned at logon | WMI process creation and permanent-subscription registration both require local admin rights on the target by default |
| `Microsoft-Windows-WMI-Activity/Operational` on the destination | Provider start/error events (5857/5858) around the time of the remote call, and 5859/5860/5861 if a permanent subscription was also registered during the same connection | See Event Log Evidence above for the same OS-version reliability caveat |
| Prefetch / ShimCache / Amcache | Execution/presence evidence for whatever the remote command line launched | See Prefetch.md, ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Process tree — `WmiPrvSE.exe` as parent | The WMI Provider Host process (`WmiPrvSE.exe`) is what actually spawns the child process requested via remote (or local event-triggered) WMI execution | 🔴 A child process with `WmiPrvSE.exe` as its parent is itself worth flagging in a process-tree review — see Windows OS Fundamentals & Versions (note 01) for what a normal process tree/parent-child lineage looks like and why an unexpected `WmiPrvSE.exe` parent is a signal worth chasing, whether the trigger was a remote lateral-movement call or a local permanent-subscription firing |

## Why Attackers Prize This Technique

- **Survives reboot.** The WMI repository is a persistent on-disk store — a registered permanent subscription is still there and still armed after every restart, exactly like a Run key or an auto-start service, but without either of those mechanisms' footprint.
- **Can be entirely fileless.** `ActiveScriptEventConsumer` stores its VBScript/JScript payload as a property value inside the repository itself — the script text never exists as a standalone file on disk for antivirus/EDR file-scanning or filesystem timeline analysis to catch.
- **No process footprint at rest.** Unlike a Run key, service, or scheduled task, there is no corresponding registry autostart value or Task Scheduler entry sitting idle waiting to be enumerated by a general-purpose tool — the only place the persistence "lives" is inside a purpose-built database that requires purpose-built tooling to read.
- **Historically low analyst familiarity.** Run keys, services, and scheduled tasks are the first three things most responders check; WMI permanent subscriptions are frequently the fourth thing, if they're checked at all — which is precisely why this technique remains effective years after it was first documented.

## Red Flags Specific to WMI Event Consumers

- **`CommandLineEventConsumer` or `ActiveScriptEventConsumer` with no legitimate explanation.** Cross-check against known monitoring/management software installed on the host (SCCM/MECM, endpoint agents) before flagging — legitimate tooling does use permanent subscriptions, so this is a baseline-your-environment finding, not an automatic "any subscription = malicious" rule.
- **WQL filter queries targeting suspicious trigger conditions** — a filter keyed to a specific, unusual process name starting, a logon event, or a time-based interval engineered to look innocuous (e.g. an oddly specific recurring interval) all warrant a closer look at the paired consumer.
- **Consumer command lines invoking `powershell.exe`/`cmd.exe` with encoded or obfuscated arguments** — the same `-enc <base64>`, `-WindowStyle Hidden`, `-NoProfile` pattern flagged in Autostart (Run/RunOnce) Keys' Red Flags Specific section applies identically here, just delivered via `CommandLineTemplate` instead of a registry value.
- **Bindings connecting filters/consumers with mismatched or generic naming** that doesn't match any known legitimate product — a `__FilterToConsumerBinding` linking a bland-named filter to a bland-named consumer, neither of which corresponds to any installed software, is a strong signal once the full WQL/command-line/script content has also been reviewed.

## Tooling

| Tool | Use |
|---|---|
| **`Get-WmiObject`/`Get-CimInstance` against `root\subscription`** | Live enumeration of the filter/consumer/binding triad on a running host with execution access — see Live-Host Enumeration above |
| **`wbemtest.exe`** | Built-in Windows WMI test console — connects to any namespace (including `root\subscription`) and lets you browse/query classes and instances manually on a live host; useful for ad hoc inspection when you don't want to write PowerShell |
| **PyWMIPersistenceFinder.py** | Purpose-built, Countercept/FireEye-lineage Python tool that enumerates the filter/consumer/binding triad from a live system or an offline WMI repository — the closest thing to a dedicated "find WMI persistence" tool in common DFIR use |
| **Autoruns** (Sysinternals) | Already introduced in Autostart (Run/RunOnce) Keys — its WMI tab enumerates permanent event subscriptions alongside every other autostart mechanism, the same comprehensive-view role it plays for Services and Run keys; convenient for a live-host pass, though a dedicated repository parser is still preferable for deep offline work |
| **Community WMI-repository parsers** (`python-cim`-style tooling, and equivalents referenced within the KAPE/DFIR tooling ecosystem) | Parse an offline `OBJECTS.DATA`/`INDEX.BTR`/`MAPPING*.MAP` set extracted from a dead-box image or triage collection — this is the only path to the triad when you don't have live execution access on the host. Note: unlike most of the artifact families in this repo, there is no Eric Zimmerman tool dedicated to WMI repository parsing as of this writing — don't assume one exists in his suite the way RECmd/PECmd/etc. cover other artifacts |

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| `CommandLineEventConsumer`/`ActiveScriptEventConsumer` bound to an active filter, with no matching legitimate monitoring/management product on the host | Core malicious-subscription pattern — verify against an environment baseline before concluding, but this is the primary thing to hunt for |
| WQL query keyed to a specific process name, logon event, or engineered time interval with no plausible legitimate purpose | Trigger-condition tuning designed to fire unobtrusively — read the full `Query` text, not just the filter's `Name` |
| `CommandLineTemplate`/`ScriptText` containing encoded PowerShell or obfuscated command syntax | Same delivered-payload pattern flagged across every other mechanism in this family |
| `__EventFilter` or `__EventConsumer` instance with no corresponding `__FilterToConsumerBinding` | Inert by itself — note it, but don't treat it as active persistence until/unless a binding appears |
| Bland or generic filter/consumer naming with no match to any installed product | Masquerading — the naming convention doesn't correspond to any legitimate software on the host |
| WMI-Activity Operational log 5859/5860/5861 present around a time of interest | Direct native evidence a subscription was created — corroborate with the actual triad content pulled from `root\subscription` or the repository |
| Sysmon 19/20/21 present but native WMI-Activity 5859-5861 absent or sparse | Expected on pre-Windows 10 hosts or where native WMI logging reliability is weak — treat Sysmon as the stronger source when both exist |
| Unexpected `WmiPrvSE.exe` parent in a process tree | Indicates a process was spawned via WMI — either a local permanent-subscription firing or a remote WMI-based execution call; pivot to the triad and to remote-connection evidence respectively |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Family-wide orientation across all five persistence mechanisms | Autostart (Run/RunOnce) Keys |
| Registry-based persistence for comparison (Run keys survive in `SOFTWARE`/`NTUSER.DAT`, not the WMI repository) | Autostart (Run/RunOnce) Keys |
| Service-based persistence and its own remote-execution primitive (`sc create`/PsExec), the closest structural parallel to this note | Services |
| Task-based persistence and its own event/registry/filesystem evidence chain | Scheduled Tasks |
| Search-order/DLL side-loading persistence with no service, task, or WMI-repository footprint | DLL Hijacking |
| Registry hive structure and offline-parsing mechanics (referenced for contrast, not because WMI persistence lives in the registry) | Registry Forensics Fundamentals (note 04) |
| What a normal process tree looks like, to judge an unexpected `WmiPrvSE.exe` parent | Windows OS Fundamentals & Versions (note 01) |
| Execution/presence evidence for whatever a `CommandLineEventConsumer` or remote WMI call launched | Prefetch.md, ShimCache (AppCompatCache).md, Amcache.md (note 06) |
| Full lateral-movement depth — source/destination pairing for WMI/WMIC, PsExec, PowerShell Remoting, remote scheduled tasks, `net use` | Lateral Movement (note 12) |
| Full WMI-Activity Operational log mechanics, plus the rest of the specialized operational-log catalog | Event Log Analysis (note 11) |

## Resources

- SANS FOR508 poster, "Hunt Evil" — Malware Persistence panel, WMI subsection — coverage checklist for the filter/consumer/binding triad and its registry-adjacent repository location, rewritten in this note's own words
- SANS FOR508 poster — Lateral Movement panel, WMI/WMIC subsection — coverage checklist for the remote-execution evidence chain
- MITRE ATT&CK T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription) — https://attack.mitre.org/techniques/T1546/003/
- MITRE ATT&CK T1047 (Windows Management Instrumentation) — https://attack.mitre.org/techniques/T1047/
- PyWMIPersistenceFinder — https://github.com/davidpany/WMI_Forensics
- Sysinternals Autoruns — https://learn.microsoft.com/sysinternals/downloads/autoruns
- Sysmon (Sysinternals) — https://learn.microsoft.com/sysinternals/downloads/sysmon
