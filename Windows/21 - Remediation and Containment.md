# Remediation and Containment

Every note earlier in this module answers "what happened and how do I prove it." This note answers the question that comes after: **now that I've found it, what do I actually do about it, without destroying the case I just built or letting the attacker finish what they started?** It is deliberately a synthesis note, not a new detection methodology — the five Persistence Mechanisms notes (10), Lateral Movement (12), Live Response and Volatile Data (16), and Anti-Forensics and Evidence Destruction (19) already own the *finding* half of this problem in full depth. This note owns the *acting* half: how to disable a service, a task, a WMI subscription, or a Run key without destroying the evidence it represents; how to isolate a host without losing the volatile evidence that isolation itself can destroy; how to reset the credentials an attacker actually used; and how to confirm, afterward, that the threat is actually gone rather than just quiet.

It mirrors the Linux module's Remediation and Containment note (Linux/14) in shape and philosophy — evidence-preservation-first, disable-before-delete, verify-with-a-reboot — but every command, mechanism, and artifact below is Windows-specific.

> 🔴 **This note assumes containment/remediation decisions happen in the middle of an active investigation, not after it's closed.** Every action described below carries an evidentiary cost as well as a security benefit. The right call is rarely "do the most aggressive thing available" — it's "do the least destructive thing that actually stops the bleeding," and know when active damage overrides that default.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Core Tension: Containment vs. Evidence Preservation](#the-core-tension-containment-vs-evidence-preservation)
- [Network-Level Containment](#network-level-containment)
- [Host-Level Containment — Per Persistence Mechanism](#host-level-containment--per-persistence-mechanism)
  - [The General Principle: Disable and Document, Don't Delete](#the-general-principle-disable-and-document-dont-delete)
  - [Services](#services)
  - [Scheduled Tasks](#scheduled-tasks)
  - [WMI Event Consumers](#wmi-event-consumers)
  - [DLL Hijacking Remnants](#dll-hijacking-remnants)
  - [Autostart Run/RunOnce Keys](#autostart-runrunonce-keys)
- [Account and Credential Remediation](#account-and-credential-remediation)
- [Evidence Preservation Sequencing](#evidence-preservation-sequencing)
- [Verification of Successful Remediation](#verification-of-successful-remediation)
- [Red Flags](#red-flags)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner **pre-remediation verification** checks — this note's "Hunt Evil" is oriented toward confirming a containment/remediation action actually took effect, not toward first discovery (that's the job of the Persistence Mechanisms, Lateral Movement, and Event Log Analysis notes this file remediates against). Run the relevant check immediately after taking the corresponding action below.

```powershell
# Confirm network isolation actually took effect - adapter should show Disabled/Disconnected, not Up
Get-NetAdapter | Select-Object Name, Status, ifOperStatus

# Confirm a blocking firewall rule is active and enabled, not just created
Get-NetFirewallRule -DisplayName "*Containment*" | Select-Object DisplayName, Enabled, Direction, Action

# Confirm a local account is actually disabled after a credential-remediation action
Get-LocalUser -Name "<AccountName>" | Select-Object Name, Enabled

# Confirm a domain account is actually disabled (requires ActiveDirectory module - see note 05b)
Get-ADUser -Identity "<sAMAccountName>" -Properties Enabled | Select-Object SamAccountName, Enabled

# Confirm a process actually stopped, not just that Stop-Process returned without error
Get-Process -Name "<ProcessName>" -ErrorAction SilentlyContinue

# Confirm a service is both stopped and disabled, so it can't relaunch at next boot
Get-Service -Name "<ServiceName>" | Select-Object Name, Status, StartType

# Confirm a scheduled task is disabled, not just that the /disable command returned success
Get-ScheduledTask -TaskName "<TaskName>" | Select-Object TaskName, State

# Confirm no active logon session remains for a compromised account after remediation
Get-CimInstance Win32_LogonSession | Where-Object { (Get-CimAssociatedInstance -InputObject $_ -Association Win32_LoggedOnUser).Name -eq "<AccountName>" }
```

## The Core Tension: Containment vs. Evidence Preservation

Every containment action an analyst can take on a Windows host — pulling the network cable, powering it down, killing a process, disabling a service — buys security at the direct expense of evidence. This is the single most important framing in this note, and every subsequent section is a variation on managing it.

**Why aggressive containment destroys evidence:** Live Response and Volatile Data (note 16) establishes the order of volatility — RAM, network state, and running-process information sit at the top, and all three are gone the moment a host is powered off, and some of it is meaningfully degraded the moment a host is even network-isolated (an active C2 session's in-memory state may unwind or a beacon may terminate cleanly once it loses its connection, versus being caught mid-operation). Pull the plug before capturing memory and you have permanently lost the process table, the decrypted contents of whatever the attacker had in RAM, and any fileless payload that only ever existed in memory. This is not a hypothetical cost — it is the default outcome of "isolate first, ask questions later."

**Why delaying containment has its own real cost:** Anti-Forensics and Evidence Destruction (note 19) covers, in depth, how an attacker who realizes they've been detected rushes to destroy evidence themselves — `vssadmin delete shadows`, log clearing, timestomping, secure-wiping. An attacker actively encrypting files (ransomware), actively exfiltrating data, or actively pivoting to additional hosts (note 12) does not pause while the analyst carefully sequences evidence collection. Every minute of delay is a minute of continued damage or continued opportunity for the attacker to notice, react, and destroy the very evidence the analyst is trying to preserve by not acting yet.

**The standard resolution:** capture volatile evidence **first** — memory image, live-response snapshot, disk image if warranted (see Evidence Preservation Sequencing below) — **then** contain, in that order, wherever the situation allows it. This is the default posture this note assumes throughout the sections that follow.

**The exception, stated plainly:** active, ongoing damage can force immediate containment even at evidence-preservation cost. Ransomware actively encrypting files, an active large-scale exfiltration in progress, or an attacker with hands-on-keyboard access actively destroying evidence in real time are all situations where the calculus flips — the cost of *not* acting now exceeds the evidentiary value of a few more minutes of collection. This is a genuine judgment call, not a formula: weigh what's actually happening (confirmed active damage vs. suspected dormant persistence), how much volatile evidence has already been captured, and how reversible the damage in progress is. A dormant Run key sitting quietly on a host that shows no sign of active attacker interaction almost never justifies skipping evidence capture. Active encryption spreading across a file share does.

## Network-Level Containment

| Technique | Confidence | Live-evidence impact | Attacker visibility | When to use |
|---|---|---|---|---|
| **Full physical/network disconnection** (unplug, disable adapter, pull from switch) | Highest — attacker definitively loses the connection | **Total** — no further live collection possible after disconnection; any not-yet-captured volatile evidence beyond what's already collected is frozen in whatever state it was at, and further live enumeration of network/process state is no longer possible | High — an attacker with any monitoring of their own C2 channel (a beacon check-in, an active session) notices the loss immediately | Active, confirmed damage in progress (see the exception above) where stopping the attacker outweighs further live collection |
| **VLAN quarantine / network isolation** | High — attacker's C2 traffic is cut off | Host stays reachable for the analyst's **own** tooling (live response, further collection) while attacker traffic is blocked | Moderate — the attacker's C2 fails, but the host itself stays up and reachable, which can look like a network blip rather than a deliberate response depending on the attacker's own diagnostics | Generally preferred middle ground in an environment with the network infrastructure (managed switches, NAC, SDN) to support it — best balance of containment confidence and continued analyst access |
| **Firewall/ACL blocking of specific known-bad IPs/domains** | Lower — only blocks what's already been identified as bad | Minimal — host and its legitimate traffic are undisturbed | Low-moderate — the attacker's specific connection fails, but the host and its other traffic look untouched | Early triage, when full isolation isn't yet warranted, or when the investigation needs the host to keep functioning normally while specific known-bad indicators are shut down |
| **DNS sinkholing** (redirect known-bad domain resolution to a controlled/monitoring endpoint) | Lower for stopping a determined attacker with hardcoded IPs, but genuinely valuable for intel | Minimal — normal host operation continues | **Lowest** — the attacker's DNS resolution *succeeds*, their connection attempt goes somewhere, and nothing about the failure pattern necessarily signals detection | Investigation still gathering intelligence and wants to observe continued attacker connection *attempts* without those attempts actually succeeding — the sinkhole captures who's still trying to reach out and how often, without alerting the attacker that they've been caught |

🔴 **Full disconnection and DNS sinkholing sit at opposite ends of the attacker-visibility spectrum.** Disconnection is the loudest possible signal to an attacker with any awareness of their own C2 health; sinkholing is nearly silent and has real ongoing intelligence value. Choose based on where the investigation actually is — confirmed active damage justifies the loud option, early/uncertain triage often favors the quiet one.

Cross-reference **Lateral Movement (note 12)** for what network-side indicators (technique-hopping across a destination host, `ADMIN$`/`C$` access from an unexpected source, WMI/WinRM activity outside business hours) should trigger a containment decision in the first place — this section covers the *response* once note 12's indicators have fired.

### PowerShell

Enumerate adapters and their current state before deciding on an isolation approach:

```powershell
Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed
```

Pull the adapter's current IP configuration, since the right isolation approach depends on whether the host sits behind a VLAN-manageable switch or is effectively standalone:

```powershell
Get-NetIPConfiguration -InterfaceAlias "<AdapterName>"
```

DNS sinkhole a specific known-bad domain via the native Name Resolution Policy Table, redirecting resolution to a controlled/monitoring endpoint without touching the adapter at all — the PowerShell-native equivalent of the DNS sinkholing row above:

```powershell
Add-DnsClientNrptRule -Namespace ".evil-domain.com" -NameServers "10.0.0.53"
```

Full adapter-level disconnection, the native PowerShell equivalent of pulling the cable. 🔴 Capture volatile evidence (memory image, live-response snapshot — see Evidence Preservation Sequencing below) *before* running this; it is the loudest, most evidence-costly option in the table above:

```powershell
Disable-NetAdapter -Name "<AdapterName>" -Confirm:$false
```

Block a specific known-bad IP without full isolation, for the firewall/ACL-blocking middle ground in the table above; document the indicator before adding the block:

```powershell
New-NetFirewallRule -DisplayName "Containment-Block-<Indicator>" -Direction Outbound -RemoteAddress <IP> -Action Block
```

## Host-Level Containment — Per Persistence Mechanism

### The General Principle: Disable and Document, Don't Delete

The registry value, service key, task XML file, and WMI filter/consumer/binding objects covered across the five Persistence Mechanisms notes (10) are not just configuration — **they are themselves evidence.** Deleting a malicious persistence mechanism the moment it's found destroys that evidence permanently: the exact command line, the exact trigger condition, the exact account context the attacker chose all disappear with it. Registry Forensics Fundamentals (note 04) and this module's general evidence-preservation ethos both point the same direction — in an active investigation, **disabling** a discovered mechanism is almost always preferable to immediately deleting it, at least until the artifact has been documented.

The standard sequence, applied to every mechanism below:

1. **Document/export the artifact first** — `reg export` for a registry value or service key, a copy of the task XML file, a dump of the WMI filter/consumer/binding objects (via `Get-WmiObject`/`Get-CimInstance`, piped to a file or exported as XML/CIM-serialized text).
2. **Disable, don't delete** — a service gets its start type set to `Disabled` rather than the key deleted; a scheduled task gets disabled rather than removed; a Run key value gets renamed or exported-then-removed only after step 1 is complete.
3. **Neutralize, don't necessarily destroy** — the goal is stopping the mechanism from firing again, while preserving enough of it (on disk, in an export, or in a forensic image) that its full evidentiary value survives for the report and any legal process that follows.

This sequencing costs a small amount of time relative to outright deletion and buys back nearly all of the mechanism's evidentiary value — worth the trade in essentially every case that isn't an active-damage exception (see the core tension section above).

### Services

Detection depth — `ImagePath`/`Start`/`Type`/`ObjectName` interpretation, service DLL abuse, red flags — is fully owned by **Services (10)**; this section covers only the remediation action once a malicious service has been identified there.

```
# 1. Document first
reg export "HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>" C:\evidence\evil_service_export.reg

# 2. Disable without deleting
sc.exe config <ServiceName> start= disabled
```

```powershell
Set-Service -Name <ServiceName> -StartupType Disabled
Stop-Service -Name <ServiceName> -Force   # if currently running
```

Setting `Start` to `Disabled` (`0x04`) prevents the service from launching on the next boot without removing the `SYSTEM\CurrentControlSet\Services\<Name>` key itself — the `ImagePath`, `ObjectName`, and any `Parameters\ServiceDll` value (see Services.md's Service DLL Abuse section) remain intact for later analysis or a formal export. Stop the running instance separately if it's currently active; disabling the start type alone does not stop an already-running service.

### Scheduled Tasks

Detection depth — XML structure, `TaskCache` registry footprint, trigger-type analysis — is fully owned by **Scheduled Tasks (10)**; this section covers only the remediation action.

```
# 1. Document first — copy the XML file and export the TaskCache entry
copy "C:\Windows\System32\Tasks\<TaskName>" C:\evidence\evil_task.xml
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\<GUID>" C:\evidence\evil_task_taskcache.reg

# 2. Disable without deleting
schtasks /change /tn <TaskName> /disable
```

`schtasks /change /tn <TaskName> /disable` sets the task's `Enabled` state to false without removing the XML file from `C:\Windows\System32\Tasks\` or the corresponding `TaskCache` registry entry — the task stops firing on its configured trigger while its full `<Actions>`/`<Triggers>`/`<Principal>` content stays available for documentation. A disabled task is still visible with `schtasks /query` and in `taskschd.msc`, which is itself a useful confirmation that the disable took effect.

### WMI Event Consumers

Detection depth — the filter/consumer/binding triad, WMI-repository internals, live-host enumeration — is fully owned by **WMI Event Consumers (10)**; this section covers only the remediation action.

The remediation here is narrower and more surgical than the other mechanisms: rather than deleting the `__EventFilter` and `__EventConsumer` objects themselves (destroying the trigger condition and the action content — genuinely high-value evidence, especially for an `ActiveScriptEventConsumer` whose payload lives only as a property value inside the repository), remove the specific **`__FilterToConsumerBinding`** that links them. WMI Event Consumers.md is explicit that a filter or consumer with no binding pointing at it is inert — breaking the binding neutralizes the persistence while preserving the filter and consumer objects as evidence.

```powershell
# 1. Document first — pull the full triad before touching anything
Get-CimInstance -Namespace root\subscription -ClassName __EventFilter | Export-Clixml C:\evidence\evil_filter.xml
Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer | Export-Clixml C:\evidence\evil_consumer.xml
Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding | Export-Clixml C:\evidence\evil_binding.xml

# 2. Remove only the specific binding, not the filter or consumer objects
$binding = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding |
    Where-Object { $_.Filter -match '<FilterName>' -and $_.Consumer -match '<ConsumerName>' }
Remove-WmiObject -InputObject $binding
```

This is the WMI-specific application of the general disable-don't-delete principle above — instead of a start-type flag or an `/disable` switch, the equivalent "off switch" for a WMI permanent subscription is removing the one object (the binding) that actually connects the inert filter and consumer into a live, firing subscription.

### DLL Hijacking Remnants

Detection depth — search-order mechanics, sub-techniques, signature-verification triage — is fully owned by **DLL Hijacking (10)**; this section is more straightforward than the others because there is no registry toggle or scheduler flag to flip.

Once a planted DLL has been identified (via signature verification, an out-of-place filename, or a mismatched creation timestamp per DLL Hijacking.md's evidence tables), remediation is a file-level action:

1. **Hash and document the DLL first** — record its SHA-1/SHA-256, full path, and timestamps before touching it (Amcache may already carry this hash — see note 06 — but document it independently regardless).
2. **Quarantine or remove the file itself** — move it to an isolated evidence location rather than deleting outright where practical, preserving the binary for malware analysis.
3. **Address the launcher separately, if one exists.** DLL Hijacking.md's "layered on top" pattern — a legitimate Run key/service/task that unwittingly re-arms the payload on every trigger — means removing only the DLL breaks the immediate execution, but the underlying persistence entry (if one exists and is itself illegitimate) still needs its own remediation per the relevant subsection above. If the launching mechanism is itself entirely legitimate (a real, trusted application that's simply been side-loaded against), no separate persistence-mechanism remediation is needed — removing the planted DLL alone resolves it.

### Autostart Run/RunOnce Keys

Detection depth — the core key family, `WOW6432Node`/GPO-pushed variants, red flags — is fully owned by **Autostart (Run/RunOnce) Keys (10)**; this section covers only the remediation action.

```
# 1. Document first
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" C:\evidence\evil_run_key_export.reg
```

```powershell
# 2. Remove the specific value only, after export
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "<ValueName>"
```

Unlike services, tasks, and WMI subscriptions, a Run/RunOnce value has no native "disabled" state to toggle to — the value either exists (and fires at the next boot/logon) or doesn't. The disable-and-document principle here collapses to export-then-remove: export the full key (not just the single value, since the key's last-write timestamp reflects the most recent change across all its values — note 04's per-key-not-per-value caveat) before removing only the specific malicious value, leaving legitimate sibling entries untouched.

## Account and Credential Remediation

Full authentication/credential-theft detection depth — logon types, 4624/4648, Pass-the-Hash/Pass-the-Ticket indicators — is owned by **Users, Groups & Authentication (05)** and **Lateral Movement (12)**; this section covers the remediation actions those findings trigger.

| Action | Approach | Notes |
|---|---|---|
| **Password reset for compromised accounts** | Force a reset at the domain/IdP level, not just locally | Rotate any account confirmed or strongly suspected of being used by the attacker — see note 05's 4624/4648 evidence and note 12's Pass-the-Hash section for what establishes "used by the attacker" |
| **Disable (don't delete) compromised or attacker-created accounts** | Disable the account object pending investigation, mirroring the disable-don't-delete principle used throughout this note for persistence mechanisms | A deleted account loses its SID history, group memberships, and audit trail context; a disabled account preserves all of that for later review while immediately blocking further use |
| **Revoke active sessions/tokens** | Terminate any live logon sessions and Kerberos tickets tied to the compromised account | An attacker who authenticated once (especially via Pass-the-Hash/Pass-the-Ticket, note 12) may hold a still-valid session or ticket that a password reset alone does not invalidate |
| **`krbtgt` account password reset — TWICE** | If domain-wide compromise or Golden Ticket abuse is suspected, reset the `krbtgt` account's password **twice**, with the AD replication convergence between resets allowed to complete | 🔴 A single `krbtgt` reset is widely considered **insufficient** — Kerberos ticket-lifetime and replication considerations mean a single reset can leave a window where a previously-forged or previously-issued ticket signed with the old key remains usable; the double-reset (with replication convergence between the two) is the standard guidance for actually invalidating everything signed with the compromised key. Hedge: confirm exact timing/spacing guidance against current Microsoft documentation at the time of the incident rather than assuming a fixed interval — the "twice" requirement itself is the well-established, frequently-cited part of this guidance |

Disabling rather than deleting a compromised account follows the same evidence-preservation logic that runs through the rest of this note — the account object, its group memberships, and its logon history all remain queryable for the investigation.

### PowerShell

Confirm the account's current state and pull the group-membership/logon-history context worth documenting before acting:

```powershell
Get-LocalUser -Name "<AccountName>"
Get-ADUser -Identity "<sAMAccountName>" -Properties LastLogonDate, MemberOf
```

Disable rather than delete, preserving SID history and group-membership context per the table above:

```powershell
Disable-LocalUser -Name "<AccountName>"
Disable-ADAccount -Identity "<sAMAccountName>"
```

Force a password reset at the domain level for an account confirmed or strongly suspected of attacker use:

```powershell
Set-ADAccountPassword -Identity "<sAMAccountName>" -Reset -NewPassword (ConvertTo-SecureString "<TempPassword>" -AsPlainText -Force)
```

The `krbtgt` double reset described above. Run this command, allow AD replication to converge across all domain controllers, then run it again — a single run is insufficient per the caution above:

```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "<RandomPassword>" -AsPlainText -Force)
```

## Evidence Preservation Sequencing

This section ties together the tension framed at the top of this note with the concrete remediation actions above: before **any** host-level remediation action described in this note, capture, in this order —

1. **A memory image** — see **Memory Acquisition Fundamentals (note 17)** for full acquisition mechanics (WinPMEM, Magnet RAM Capture, physical vs. logical capture). RAM is the most volatile capturable evidence tier and is the first thing this note assumes is already preserved before any disabling, deleting, or account action below occurs.
2. **A live-response volatile-data snapshot** — see **Live Response and Volatile Data (note 16)** for the full order-of-volatility-driven collection sequence (processes, network state, autoruns snapshot, command history). Note 16's own Autoruns-snapshot step is directly relevant here: capturing the full persistence landscape *before* remediation gives the analyst a documented "before" state to compare against the post-remediation verification pass below.
3. **Disk imaging, if warranted** — see **Evidence Acquisition & Imaging (note 02)** for the live-vs-dead-box decision and imaging mechanics. Not every incident requires a full disk image before remediation, but where the investigation's scope or likely legal exposure warrants it, imaging belongs in this pre-remediation sequence too.

This note's remediation actions — service/task/WMI/Run-key disabling, DLL quarantine, account resets, network containment — are written throughout to happen **after** steps 1–3, except in the active-damage exception described in the core-tension section above. When that exception applies, capture whatever volatile evidence is practically achievable in the compressed window available (even a fast memory image and a brief live-response pass are far better than nothing) before falling back to immediate containment.

## Verification of Successful Remediation

Taking a remediation action is not the same as confirming the threat is neutralized — a sophisticated attacker who notices one persistence mechanism was removed may have already planted redundant persistence elsewhere, and superficial removal (killing a process without addressing what relaunches it, disabling one Run key while missing a second) leaves the intrusion effectively intact.

1. **Re-run the relevant detection technique from the Persistence Mechanisms notes.** Don't just trust that the disable action worked — re-check the specific artifact (the service's `Start` value, the task's `Enabled` state, the binding's absence, the Run key's contents) using the same methodology the originating note used to find it.
2. **Run Autoruns as a fast cross-cutting re-check.** Note 16 already establishes `autorunsc.exe` as the single fastest way to snapshot the entire persistence landscape in one pass — rerunning it post-remediation and diffing against the pre-remediation snapshot captured in step 2 of Evidence Preservation Sequencing above is the fastest way to confirm the specific mechanism is gone **and** to check for anything new that wasn't there before.
3. **Check for redundant persistence via a different mechanism.** 🔴 This is a genuinely important caution: an attacker who anticipates discovery frequently plants more than one persistence mechanism from the start, specifically so that removing the one an analyst finds first doesn't fully evict them. Clearing a malicious scheduled task does not confirm the absence of a WMI event consumer, a service, or a Run key planted at the same time — walk the full Persistence Mechanisms family (10), not just the mechanism that was originally found.
4. **Monitor network and EVTX activity post-remediation.** Cross-reference **Event Log Analysis (note 11)** for the specialized operational logs (TaskScheduler, WMI-Activity, PowerShell, WinRM) and **Lateral Movement (note 12)**'s network-indicator patterns — renewed C2 check-in attempts, a fresh technique-hopping pattern, or unexpected authentication activity in the period after remediation is the ultimate confirmation that the threat is actually gone rather than just quiet. A DNS-sinkhole containment choice (see Network-Level Containment above) is particularly useful here, since it lets the analyst directly observe whether the attacker's tooling is still trying to phone home.

### PowerShell

Confirming the malicious Run key value is actually gone rather than trusting the removal call succeeded requires verifying per step 1 above:

```powershell
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue
```

Diffing the pre-remediation WMI subscription export (captured per Evidence Preservation Sequencing above) against current live state confirms no binding was quietly re-created:

```powershell
Compare-Object (Import-Clixml C:\evidence\evil_binding.xml) (Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding)
```

A native fallback for the redundant-persistence check in step 3, without Sysinternals Autoruns, provides a basic verification (not a substitute for the real tool per note 16, but usable when it isn't available):

```powershell
Get-CimInstance Win32_Service | Where-Object StartMode -eq 'Auto' | Select-Object Name, PathName, StartName
Get-ScheduledTask | Where-Object State -ne 'Disabled' | Select-Object TaskName, TaskPath
```

## Red Flags

| 🔴 Finding | Why it matters |
|---|---|
| Network isolation or process termination performed before memory/volatile-data capture | Premature containment — the single most common process mistake this note exists to prevent; volatile evidence lost this way cannot be recovered afterward |
| Persistence mechanism deleted rather than disabled-and-documented | Destroys the registry value/service key/task XML/WMI object's own evidentiary value — export first, always |
| Single persistence mechanism remediated with no check for a second, different mechanism | A sophisticated attacker frequently plants redundant persistence — walk the full Persistence Mechanisms family (10) before declaring the host clean |
| `krbtgt` reset performed only once when domain-wide compromise/Golden Ticket abuse was suspected | A single reset is insufficient per the twice-reset guidance above — leaves a window where previously-forged tickets remain valid |
| Full network disconnection used when the investigation was still in early/uncertain triage | Tips off an attacker with any monitoring of their own C2 channel before evidence capture is complete — a quieter option (VLAN isolation, DNS sinkholing) preserves intelligence value and analyst access |
| Compromised account deleted rather than disabled | Loses SID history, group-membership context, and audit trail the investigation may still need |
| No post-remediation verification pass (re-run detection, Autoruns diff, EVTX/network monitoring) | "Removed it" is not the same as "confirmed gone" — see Verification of Successful Remediation above |
| Active, confirmed damage (ransomware encryption, active exfiltration) allowed to continue while evidence collection is completed in full | The active-damage exception exists precisely because delay has a real cost too — this is the mirror-image mistake of premature containment |

## Tooling

| Tool | Use |
|---|---|
| **`sc.exe config <name> start= disabled`** / **`Set-Service -StartupType Disabled`** | Disable a malicious service without deleting its registry key |
| **`schtasks.exe /change /tn <name> /disable`** | Disable a malicious scheduled task without deleting its XML file or `TaskCache` entry |
| **`Get-WmiObject`/`Get-CimInstance` + `Remove-WmiObject`** (`root\subscription`) | Enumerate and remove a specific `__FilterToConsumerBinding`, leaving the filter and consumer objects intact for evidence |
| **`reg export`** | Document/export a registry key (service, Run key, `TaskCache` entry) before any disabling or removal action |
| **Autoruns / `autorunsc.exe`** (Sysinternals) | Fast, cross-cutting persistence re-check across all five mechanisms in one pass — the primary post-remediation verification tool, per note 16 |
| **Network/firewall management tooling** (organization-specific — managed switch/NAC console, firewall management console, DNS sinkhole appliance) | VLAN quarantine, ACL blocking, and DNS sinkholing are implemented through whatever network infrastructure the organization has — kept generic here since the specific tooling varies by environment |
| **`Set-ADAccountPassword`** / **`Disable-ADAccount`** (Active Directory PowerShell module), or their GUI equivalents in Active Directory Users and Computers | Force a password reset or disable a compromised domain account without deleting the object |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Volatile-data capture and sequencing that must happen **before** containment | **Live Response and Volatile Data (16)** |
| Memory acquisition mechanics that must happen **before** containment | **Memory Acquisition Fundamentals (17)** |
| Disk imaging and the live-vs-dead-box decision, if imaging is warranted before remediation | **Evidence Acquisition & Imaging (02)** |
| Why an attacker may rush to destroy evidence once they realize they've been detected/contained | **Anti-Forensics and Evidence Destruction (19)** |
| Full detection depth this note's remediation actions build on | All five **Persistence Mechanisms** notes (10) |
| Authentication/credential context — logon types, 4648, what establishes an account as attacker-used | **Users, Groups & Authentication (05)** |
| Lateral-movement/credential-theft context driving network and account remediation decisions | **Lateral Movement (12)** |
| Post-remediation EVTX/operational-log monitoring for renewed activity | **Event Log Analysis (11)** |
| Where this note fits in the overall IR lifecycle — Containment/Eradication/Recovery stages | **Threat Hunting Methodology and Intelligence (20)** |
| Post-incident hardening and baseline restoration once remediation is verified | **Enterprise Management and Baseline (22)** |

## Resources

- SANS FOR508 poster/index — used as a coverage-checklist only for the containment/eradication content this note synthesizes; no verbatim reproduction
- Microsoft's own guidance on `krbtgt` password-reset procedures following suspected Kerberos ticket-forging attacks — consult current Microsoft Learn documentation for exact timing/spacing guidance at the time of the incident rather than a fixed interval asserted here
- MITRE ATT&CK Mitigations — https://attack.mitre.org/mitigations/ (the defensive-technique counterpart to the offensive technique IDs cited throughout this module's Persistence Mechanisms, Lateral Movement, and Anti-Forensics notes)
