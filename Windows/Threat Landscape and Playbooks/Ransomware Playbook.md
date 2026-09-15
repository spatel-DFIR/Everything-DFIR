# Ransomware Playbook

The phone rings. Someone says "everything has a `.txt` file next to it now" or just reads you the ransom note over the phone. This note is the tactical walkthrough for that moment forward: what to capture first, how to figure out how many hosts are actually affected, how the encryptor got pushed fleet-wide, whether recovery via shadow copies is even possible, how the attacker actually got domain-wide access, and how to pull IOCs off the encryptor itself — all sequenced as a single response, not a topic list. This note assumes the reader has this module's artifact notes open in other tabs; it does not re-explain artifact mechanics, it sequences and applies them to this one incident type.

> 🔴 If you remember one instruction from this note: **do not assume the first encrypted host you hear about is patient zero.** Modern ransomware detonates near-simultaneously across a fleet via a mass-deployment mechanism (§4) — the workstation someone happened to notice first is usually just the one an actual human was looking at when the lights went out, not the host the attacker actually started from.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Scenario Framing — The Full Attack Chain](#scenario-framing--the-full-attack-chain)
- [Immediate Triage Priorities](#immediate-triage-priorities)
- [Scope Determination — How Many Hosts Are Actually Affected](#scope-determination--how-many-hosts-are-actually-affected)
- [Investigating the Deployment Mechanism](#investigating-the-deployment-mechanism)
  - [GPO-Based Deployment](#gpo-based-deployment)
  - [PsExec / `sc create` Remote-Service Deployment](#psexec--sc-create-remote-service-deployment)
  - [WMI-Based Deployment](#wmi-based-deployment)
  - [Scheduled-Task Deployment](#scheduled-task-deployment)
- [Confirming Shadow-Copy / Backup Destruction](#confirming-shadow-copy--backup-destruction)
- [Credential-Theft and Lateral-Movement Reconstruction](#credential-theft-and-lateral-movement-reconstruction)
- [Encryptor Binary Identification and IOC Extraction](#encryptor-binary-identification-and-ioc-extraction)
- [Response Sequence — Summary](#response-sequence--summary)
- [Common Investigative Pitfalls](#common-investigative-pitfalls)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for "is this host actively or recently encrypting" — no third-party tooling required. These are fast-first checks for the §2 triage moment; the deep-dive sections below (§3–§7) supply the full deployment-mechanism, shadow-copy, and IOC evidence chains each of these hints at.

```powershell
# Files modified in the last 15 minutes across user profiles - a live encryption sweep leaves a tight timestamp cluster
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-15) } |
    Group-Object Extension | Sort-Object Count -Descending | Select-Object -First 20

# A single new extension suddenly appearing across many files in the last hour - the mass-rename tell
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) } |
    Group-Object Extension | Where-Object Count -gt 50

# Ransom-note-shaped files dropped in the last hour, across every user profile
Get-ChildItem C:\Users -Recurse -File -ErrorAction SilentlyContinue -Include *readme*,*decrypt*,*ransom*,*restore*,*how_to* |
    Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-1) } | Select-Object FullName, LastWriteTime

# Unsigned process currently burning CPU - the live-encryptor candidate (§2 step 4)
Get-Process | Where-Object CPU -gt 60 | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Name = $_.Name; Path = $_.Path; CPU = $_.CPU; Signature = $sig.Status }
} | Where-Object Signature -ne 'Valid'

# New service/task installs in the last hour, this host - the mass-deployment tell (§4); sweep the full host list, not just this one
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddHours(-1)} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}, @{N='ImagePath';E={$_.Properties[1].Value}}

# Shadow copies present right now on this host - an empty result where VSS should be enabled is itself the finding (full deletion-evidence chain in §5 / note 19)
Get-CimInstance Win32_ShadowCopy | Select-Object ID, VolumeName, InstallDate
```

## Scenario Framing — The Full Attack Chain

Modern "big-game hunting" ransomware is almost never a smash-and-grab against a single host — it's the terminal stage of an intrusion that has typically already had days to weeks of unhurried access before anything visibly breaks. The overview note in this folder already names this chain at survey depth; this playbook walks it in the depth and order an active response actually needs:

```
Initial access
   │  (phishing, exposed RDP, unpatched external service, purchased foothold)
   ▼
Credential harvesting / privilege escalation
   │  (LSASS dumping — note 17 Memory Analysis; Kerberoasting/DCSync — note 05b)
   ▼
Lateral movement / domain compromise
   │  (RDP, PsExec, WMI, PowerShell Remoting, remote services/tasks — note 12)
   ▼
Data exfiltration (double-extortion staging)
   │  (cloud-storage sync abuse — note 13; email/webmail exfil — note 15;
   │   this playbook does not go deep here — it's a parallel workstream, not
   │   a gate the encryption stage waits on)
   ▼
Shadow-copy / backup destruction
   │  (vssadmin delete shadows — note 19, THE canonical precursor)
   ▼
Mass encryptor deployment
   (GPO / PsExec / WMI / scheduled tasks pushed fleet-wide, near-simultaneous detonation)
```

**Why this matters for how you investigate:** by the time anyone notices encrypted files, the attacker is already at the *end* of this chain. The investigation runs in the opposite direction — you start where the damage is visible (mass encryption) and work backward through shadow-copy destruction, to the deployment mechanism, to lateral movement, to the original foothold — while simultaneously working forward on live triage to stop what's still happening. This playbook is organized around that backward reconstruction (§4 through §7), bracketed by the immediate-response steps that have to happen regardless of how far back the reconstruction eventually gets (§2, §3).

Exfiltration deserves one operational note even though this playbook doesn't carry its own evidence-chain depth for it: double-extortion means data theft frequently happens *before* encryption, using the same lateral-movement access described above to stage data via a cloud-sync client (note 13) or reach mailboxes (note 15). Treat "was data exfiltrated" as a parallel question to run alongside this playbook's encryption-focused sequence, not something to defer until after remediation — the answer materially changes notification obligations and is far harder to reconstruct after volatile evidence is gone.

## Immediate Triage Priorities

This is the "ransom note is on screen, is encryption still running" moment. Note 16's order-of-volatility methodology applies here directly, with one addition specific to this scenario: **active, confirmed encryption is exactly the exception case note 21's containment-vs-evidence-preservation tension names** — active damage in progress can justify earlier, more aggressive containment than the "capture everything volatile first" default. The judgment call is real, not a formula: is this host still actively encrypting, or is it already done and just sitting there with a ransom note? Those are different situations with different correct first moves.

```
1. Is this host STILL actively encrypting right now?
        │
   ┌────┴────┐
   │ YES     │ NO / UNSURE / ALREADY DONE
   ▼         ▼
Note 21's active-damage exception applies:      Default sequence applies (note 16):
weigh stopping the damage against lost           capture volatile evidence BEFORE
volatile evidence. A single host still           containing. Do not pull the network
visibly encrypting, spreading across a           cable or power off "to be safe" —
mapped share, generally justifies                that is the single most common
network isolation (prefer VLAN quarantine        process mistake this note exists
over full disconnection where the                to prevent (note 21's own framing).
infrastructure supports it — note 21)
before memory capture completes.                 │
   │                                              ▼
   └──────────────────┬───────────────────────────┘
                       ▼
        2. Capture memory FIRST, before extensive live-command
           interaction (note 16's Order of Volatility — RAM sits
           above network/process state). This is not optional even
           under time pressure: LSASS-derived credential material,
           the encryptor's in-memory state, and any fileless-stage
           tooling live ONLY here (note 17).
                       │
                       ▼
        3. Capture live network state (netstat -anob,
           Get-NetTCPConnection, arp -a) — confirms whether this
           host is still an active node in the encryptor's
           deployment/C2 activity, per note 16.
                       │
                       ▼
        4. Capture process/handle/DLL state (tasklist /v, handle.exe,
           listdlls.exe) — the encryptor process itself, if still
           running, is exactly what you want alive long enough to
           identify (see §7) before it's killed or exits on its own.
                       │
                       ▼
        5. THEN — and only then — move to the scoping and
           deployment-mechanism investigation below (§3, §4).
```

🔴 **The active-damage exception is a judgment call about scope, not a blanket license.** Isolating the one host actively encrypting a share does not mean skipping memory capture on every other host in the environment — it means accepting a compressed collection window on the specific host where damage is confirmed and ongoing, per note 21's own framing ("even a fast memory image and a brief live-response pass are far better than nothing").

To capture live network and process-state (steps 3–4 above), use PowerShell native equivalents to `netstat`/`tasklist`:

```powershell
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
Get-Process | Select-Object Id, ProcessName, Path, StartTime, CPU
```

Apply response actions for the "still actively encrypting" branch of the decision tree above. These are containment actions, not evidence collection: apply only after memory capture is complete, or deliberately compressed per note 21's active-damage exception. Document the target (process ID, adapter name) before acting:

```powershell
# Kill the confirmed encryptor process - if its handles/command line haven't already been captured (step 4 above), do that first
Stop-Process -Id <EncryptorProcessId> -Force

# Block outbound SMB to stop further share-to-share spread from this host, short of a full network disconnect
New-NetFirewallRule -DisplayName "Containment-Block-SMB-Out" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block

# Full adapter isolation - the local, host-side fallback; prefer VLAN quarantine (note 21) where the infrastructure supports it
Disable-NetAdapter -Name "<AdapterName>" -Confirm:$false
```

## Scope Determination — How Many Hosts Are Actually Affected

Before committing to a containment strategy, get a real number, not an impression from whoever called it in. The instinct to isolate "the affected host" and move on is exactly backward when the deployment mechanism was fleet-wide (§1's chain) — by the time one host is visibly encrypted, the mass-deployment step has typically already fired against every reachable target simultaneously, meaning most of the "affected" population is either already encrypted-and-quiet or about to be.

Practical blast-radius assessment, before deep-diving any single host:

1. **Check for the mass-deployment mechanisms (§4) across the fleet, not just the reporting host.** A quick sweep for fresh GPO changes (`GPT.INI` version jumps), new/renamed services (System 7045) or scheduled tasks (TaskScheduler/Operational 106) created in the same narrow time window across multiple hosts is far more diagnostic of true scope than walking host-by-host waiting for someone to report a ransom note.
2. **Pull a fleet-wide timestamp cluster.** If the deployment mechanism fired near-simultaneously (the whole point of mass deployment), the encryptor's first-execution evidence (Prefetch creation time, per note 06) should cluster tightly across affected hosts. A wide spread in "first encryption" timestamps across hosts is itself informative — it can mean staggered manual deployment (PsExec/WMI looped host-by-host) rather than a single GPO push, which changes what you look for in §4.
3. **Check domain-controller-level indicators early, not last.** Because ransomware operators specifically target the DC to push payloads via GPO or scripted logon actions (cross-ref note 05b), a domain-wide blast radius should be treated as the default assumption to disprove, not a worst case to rule in only after everything else is checked.
4. **Use the autoruns/persistence baseline (note 22) if one exists.** A pre-incident fleet-wide Autoruns snapshot or golden-image comparison turns "how many hosts got the malicious task/service/GPO" from a guess into a measurable diff.

The output of this step is a working host list — confirmed-encrypted, confirmed-touched-but-not-yet-encrypted (a live encryptor process or a fresh deployment artifact with no damage yet), and unconfirmed — that everything from here forward operates against, rather than a single-host investigation that happens to expand later.

To perform a fleet-wide sweep for service (7045) and scheduled-task (106) installs clustered in a tight window across a working host list (per point 1 above), use PowerShell:

```powershell
$hosts = Get-Content C:\hunt\scope_hosts.txt
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddHours(-6)} -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, @{N='ServiceName';E={$_.Properties[0].Value}}
} | Sort-Object TimeCreated
```

Check Prefetch first-execution-time clustering across the same host list to distinguish a single near-simultaneous push from a staggered manual loop (point 2 above). Full per-artifact Prefetch mechanics live in note 06:

```powershell
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-ChildItem "$env:SystemRoot\Prefetch\*.pf" -ErrorAction SilentlyContinue | Where-Object Name -match '<ENCRYPTOR_NAME>' |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, Name, LastWriteTime
}
```

## Investigating the Deployment Mechanism

Ransomware operators overwhelmingly reach for the enterprise's own management plane rather than manually touching every host — it's faster, and it detonates everything near-simultaneously, maximizing damage before defenders can react. Four mechanisms account for nearly all real-world mass deployment. Check all four in parallel where possible rather than stopping at the first one found — a sophisticated operator sometimes uses more than one, exactly the "technique-hopping" pattern note 12 already flags as a lateral-movement tell in its own right.

### GPO-Based Deployment

The highest-leverage single mechanism, because one edit fans out to every computer in scope — [`GPO/05 - GPO Abuse, Hunting and Detection`](<../GPO/05 - GPO Abuse, Hunting and Detection.md>) names this explicitly as "a well-documented, real-world ransomware-deployment pattern."

**Practical sequence:**
1. Check `GPT.INI` version numbers across SYSVOL for jumps inconsistent with normal administrative change cadence — [`GPO/01`](<../GPO/01 - Storage, Replication and Version Synchronization.md>)'s core GPO-abuse detection angle.
2. Check for **newly created GPOs**, or modification of existing GPOs, inside the incident window — a brand-new domain-linked GPO created shortly before mass detonation is the single strongest finding here ([`GPO/03`](<../GPO/03 - Domain Controller GPO Investigation.md>)).
3. Read what the GPO actually pushes: a `ScheduledTasks.xml` payload under GPO Preferences, a Run-key value via `Registry.pol`, or a startup/logon script under `Machine\Scripts\Startup\` — [`GPO/02`](<../GPO/02 - GPO Content Deep Dive (Registry.pol, GPP, Scripts, Security Templates).md>)'s three documented payload types.
4. Cross-reference the GPC's AD-object version against the GPT's SYSVOL-side version ([`GPO/01`](<../GPO/01 - Storage, Replication and Version Synchronization.md>)'s desynchronization red flag) — a raw SYSVOL file edit bypassing normal GPO tooling can leave the AD object looking unchanged. Pull attribute-level provenance via `repadmin /showobjmeta` ([`GPO/03`](<../GPO/03 - Domain Controller GPO Investigation.md>) applied to a GPO object; general mechanics in note 05b) rather than relying on the coarser `whenChanged`.
5. Check scope: a GPO linked at the domain root rather than a narrow OU is itself a red flag ([`GPO/03`](<../GPO/03 - Domain Controller GPO Investigation.md>)) — it's exactly how an attacker maximizes blast radius from one edit.

**Key evidence artifact to check first:** `GPT.INI` version + a fresh GPO creation/modification timestamp on SYSVOL.

**What a positive finding looks like in practice:** a GPO you don't recognize, linked at the domain or a broad OU, created or edited in a tight window immediately before the mass-encryption timestamp cluster identified in §3, pushing a scheduled task or logon script whose action is the encryptor binary (or a downloader for it).

For GPT.INI/GPC version-desync detection, GPO creation/modification-time sweeps, and `gpresult`/GroupPolicy-operational-log pulls (points 1, 2, and 4 above), use PowerShell — these are covered in full across the [`GPO/` folder](<../GPO/00 - GPO Fundamentals and Architecture.md>) and not repeated here. For point 5 (link scope), identify where a suspect GPO is actually linked using PowerShell. A domain-root or broad-OU link is the blast-radius red flag point 5 names:

```powershell
Get-GPInheritance -Target "DC=<domain>,DC=com"
```

### PsExec / `sc create` Remote-Service Deployment

The classic manual-loop mass-deployment method — an attacker with valid admin credentials scripts `sc \\host create` + `sc \\host start` (or PsExec, built on the same primitive) against a host list.

**Practical sequence across multiple hosts:**
1. Pull **System log 7045** (service installed) across every host in the working scope list from §3 — this is the reliable, default-on baseline; do not wait on the audited-only Security 4697 (note 10's Services.md, note 12).
2. Look for the same or a near-identical service name/`ImagePath` appearing across multiple hosts in a tight time window — that clustering is the tell of a scripted loop, distinct from a single legitimate service install.
3. If PsExec specifically: check for `EulaAccepted` under `NTUSER.DAT\Software\SysInternals\PsExec` on the source host used to launch the deployment, and `PSEXESVC` (or a `-r`-renamed equivalent) service creation on each destination — note 10's PsExec Special Case gives the full chain.
4. Cross-reference Security 4624 (Type 3) + 4672 on each destination to confirm the same source host/account pushed to all of them — this is what actually proves "one operator, one script, many hosts" rather than coincidence.

**Key evidence artifact to check first:** System 7045 across the fleet, clustered in time.

**What a positive finding looks like in practice:** the same service name (or `-r`-renamed variant) installed via 7045 across dozens of hosts within minutes of each other, all sourced from Security 4624 Type 3 logons from the same one or two source IPs/accounts.

To correlate 7045 service installs across the working host list against the source logon that pushed them (establishing "one operator, one script, many hosts" per point 4 above), use PowerShell. Single-host 7045 pulls and the PsExec-specific evidence chain are covered in note 10's Services.md, not repeated here:

```powershell
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-6)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Properties[8].Value -eq 3 } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}
} | Group-Object SourceIP, Account | Sort-Object Count -Descending
```

### WMI-Based Deployment

No service, no task, no file necessarily dropped beyond whatever the launched command line does — `wmic /node:<host> process call create` or `Invoke-CimMethod`/`Invoke-WmiMethod` against a host list.

**Practical sequence across multiple hosts:**
1. Look for `WmiPrvSE.exe` as an unexpected parent process across the fleet — note 10's WMI Event Consumers.md and note 12 both flag this as the destination-host tell that a process was spawned via WMI rather than a user or normal parent.
2. Pull `Microsoft-Windows-WMI-Activity/Operational` 5857/5858 clustered across hosts around the suspected detonation window — corroborate with Sysmon Event ID 19/20/21 if deployed, since Sysmon is materially more reliable pre-Windows 10 than the native operational log (note 10).
3. Check network evidence for the transport used: TCP 135 + dynamic RPC (DCOM path) or TCP 5985/5986 (WSMan/CIM-session path) — the choice of transport is itself diagnostic of which specific tooling the attacker used (note 12's comparative table).
4. If the attacker also registered a permanent WMI subscription while connected (rather than a one-shot remote process call), pull the full filter/consumer/binding triad per note 10 — this would represent WMI being used for *persistence* alongside deployment, not just a one-time push.

**Key evidence artifact to check first:** `WmiPrvSE.exe` as parent of the encryptor process, corroborated by WMI-Activity 5857/5858 or Sysmon 19-21.

**What a positive finding looks like in practice:** the encryptor's own process-tree evidence (from live triage, §2) or Prefetch (§7) shows `WmiPrvSE.exe` as its parent across multiple hosts, with 4624 Type 3 + 4672 logons from a common source clustered in the same window as the GPO/PsExec/task findings above.

To identify unexpected `WmiPrvSE.exe` parent-process relationships (the destination-host tell point 1 names) and corroborate with the WMI-Activity operational log (point 2), use PowerShell:

```powershell
Get-CimInstance Win32_Process | Where-Object { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name -eq 'WmiPrvSE.exe' } |
    Select-Object ProcessId, Name, ParentProcessId, CommandLine

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; Id=5857,5858} -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message
```

### Scheduled-Task Deployment

`schtasks /create /s <host>` + `schtasks /run /s <host>` — sits alongside `sc create` and WMI as one of the three classic native remote-execution primitives (note 12); functionally the RPC-based sibling of the PsExec mechanism above.

**Practical sequence across multiple hosts:**
1. Pull **`TaskScheduler/Operational` 106** (task registered) across the fleet — the reliable, default-on baseline; lead with this over the audited-only Security 4698 (note 10's Scheduled Tasks.md, note 12).
2. Look for the same or similarly-named task appearing across multiple hosts in a tight window, same clustering logic as the service-based check above.
3. Pull `TaskScheduler/Operational` 200/201 to confirm the pushed task actually executed, not just registered — note 12 flags that install-to-execution time is often measured in seconds for scripted lateral movement, which is itself a signal distinguishing automated deployment from a manually-created legitimate task.
4. Check the task's `<Actions><Exec><Command>` — does it point directly at a dropped encryptor path, or at a LOLBin/downloader staging it? Read the full `<Principal>`/`RunLevel` too — `SYSTEM` + `HighestAvailable` for a task with no plausible legitimate need is note 10's own escalation signal.
5. Also check for `ITaskService` COM-API creation (note 10) — a task fully present in `TaskCache`/the operational log with **no** corresponding `schtasks.exe` command-line evidence anywhere (4688, EDR) suggests the attacker registered it via the COM interface specifically to dodge command-line-based detection.

**Key evidence artifact to check first:** `TaskScheduler/Operational` 106, clustered in time across hosts.

**What a positive finding looks like in practice:** an identically-named task registered (106) and executed (200/201) within seconds of each other across many hosts, action pointing at the encryptor or a stager, all traced back to the same source session.

To check 200/201 (task actually executed, not just registered) across the working host list and confirm point 3's register-to-execution timing, use PowerShell. Fleet-wide 106 registration pulls are covered in note 10's Scheduled Tasks.md, not repeated here:

```powershell
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=200,201; StartTime=(Get-Date).AddHours(-6)} -ErrorAction SilentlyContinue |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Id, @{N='TaskName';E={$_.Properties[0].Value}}
} | Sort-Object TimeCreated
```

## Confirming Shadow-Copy / Backup Destruction

Once the deployment mechanism is understood, confirm the precursor that made the encryption unrecoverable-by-default: shadow-copy deletion. Note 19 covers this in full depth as THE canonical ransomware precursor — this section is the practical application sequence.

1. **Run `vssadmin list shadows` on every affected host.** An empty result on a host that would normally be expected to have shadow copies (VSS enabled, sufficient shadow storage allocated) is itself the confirmation — the absence is the finding, not a separate step. Also run `vssadmin list shadowstorage` to see whether shadow storage allocation itself was reduced/zeroed, which is a second, independent confirmation signal.
2. **If shadow copies ARE still present**, don't stop there — mount one (via `mklink`/`GLOBALROOT`, ShadowExplorer, or Arsenal Image Mounter against an image per note 19's Accessing Shadow Copies table) and check whether it predates the encryption event. A shadow copy that exists but postdates encryption is worthless for recovery; one that predates it is a genuine recovery path independent of backup infrastructure.
3. **Confirm execution evidence for the deletion tooling itself across affected hosts** — cross-reference note 06's execution-evidence family for `vssadmin.exe` or `wmic.exe` (with `shadowcopy delete` arguments):
   - **Prefetch** — strongest if present: proves the exact path ran, with a run-count and timestamp array (note 06's Prefetch.md).
   - **ShimCache/Amcache** — if Prefetch is absent (common on servers, where Prefetch is often disabled by default per Prefetch.md's version table) or was deliberately deleted, ShimCache or Amcache may still show `vssadmin.exe`/`wmic.exe` was present and evaluated — presence only, not execution proof on its own, but a lead worth corroborating against the timestamp cluster from §3.
4. **Check whether the deletion command line itself was captured**, if command-line auditing (Security 4688 with command-line logging) or Sysmon Event ID 1 was in place — this is the only source that shows the literal `/all` argument and target-volume detail (note 19's detection-evidence table).
5. **Do this across every host in the §3 scope list, not just the first one found.** Shadow-copy deletion typically fires as part of the same mass-deployment action as the encryptor itself (often the same task/service/script does both), so the fleet-wide pattern here should mirror the fleet-wide pattern found in §4.

🔴 Per note 19: execution evidence for `vssadmin delete shadows` (or its PowerShell/WMI equivalents — `Get-WmiObject Win32_ShadowCopy | Remove-WmiObject`, `wmic shadowcopy delete`) is one of the single strongest, most unambiguous anti-forensic/ransomware-precursor signals in Windows DFIR. It is rarely, if ever, something a legitimate user runs incidentally.

## Credential-Theft and Lateral-Movement Reconstruction

By this point you know *how* the encryptor was pushed (§4) and *that* recovery was sabotaged (§5). The remaining question — and the one that actually determines the true scope of compromise, not just the visible damage — is **how the attacker got from the original foothold to the domain-wide access needed to pull off §4 at all.**

**Practical reconstruction sequence:**

1. **Start from the account(s) used in §4's deployment evidence.** Every deployment mechanism in §4 left a 4624 (Type 3) + 4672 logon trail pointing at a source host and account — that account is your starting thread to pull.
2. **Establish whether that account's access was obtained via credential theft rather than legitimate use.** Pull LSASS handle-access evidence for the source host(s) per note 17's Credential Theft section: Sysmon Event ID 10 (ProcessAccess) targeting `lsass.exe` from an unexpected process, or an `lsass`-characteristic `.dmp` file anywhere on disk (from `procdump.exe -ma lsass.exe`, the `comsvcs.dll` MiniDump technique, or Task Manager's own dump option — all three named in note 17). Any of these findings on the source host is the credential-theft evidence explaining how the attacker obtained the account used in §4.
3. **Walk the logon-type evidence backward through the intrusion**, per note 05's logon-type table cross-referenced against note 12: Type 3 (network) logons chained across hosts, Type 9 (NewCredentials) suggesting pass-the-hash/pass-the-ticket use (note 12's Pass-the-Hash section), and a nearby Security 4648 (explicit credentials) corroborating a credential-theft-driven pivot rather than a legitimately-supplied password.
4. **Establish the order accounts were compromised, not just which accounts were involved.** The account used to deploy the encryptor (§4) is very rarely the account used for initial access — walk backward through each lateral hop's source/destination pairing (note 12's Source → Network → Destination framework) until you reach a host and account consistent with the initial-access vector (phishing, exposed RDP, etc.), reconstructing the full chain rather than stopping at the first credential-theft finding.
5. **Check for domain-wide indicators specifically** if the deployment mechanism was GPO-based (§4): Kerberoasting, Golden/Silver Ticket abuse, or DCSync activity per note 05b are the class of technique that turns a single compromised workstation account into Domain Admin — cross-reference note 05b's AD forensic artifacts and note 17's LSASS/Mimikatz depth for the specific evidence chain of each.

The output of this section is a timeline, not just a list of compromised accounts: initial foothold → first credential theft → first lateral hop → escalation → domain-wide access → §4's mass deployment. This timeline is what actually answers "what else could the attacker have touched" — which matters more than the encryptor itself for scoping legal/notification exposure (cross-ref the exfiltration note in §1).

For credential-theft and lateral-movement analysis using PowerShell:

pull the 4624 (Type 3) / 4648 / 4672 logon chain for a specific account across the working host list to walk the lateral-hop sequence backward per point 3 above; full logon-type interpretation lives in note 05:

```powershell
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4648,4672; StartTime=(Get-Date).AddDays(-3)} -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match '<AccountName>' } | Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, TimeCreated, Id
} | Sort-Object TimeCreated
```

- LSASS process-access events (Sysmon Event ID 10) targeting `lsass.exe` from an unexpected process, where Sysmon is deployed (point 2 above) — full LSASS/Mimikatz credential-theft depth lives in note 17:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'TargetImage:.*lsass\.exe' } | Select-Object TimeCreated, Message
```

## Encryptor Binary Identification and IOC Extraction

Once the chain above is reconstructed, positively identify the encryptor binary itself and extract IOCs usable both for the current response and for the threat-intel feedback loop (cross-ref note 20).

1. **Pull Amcache first for the hash.** Note 06's Amcache.md is explicit that Amcache's SHA-1 hash is the field that "turns a routine 'was this file here' question into a hash-based threat-intel pivot, even after the file itself has been deleted from disk" — and ransomware encryptors are frequently self-deleting or deleted by the operator's own cleanup script after detonation, making Amcache's persistence-independent-of-the-file-still-existing property directly relevant here.
2. **Corroborate with Prefetch where present** — the run-count and embedded timestamp array (note 06's Prefetch.md) confirm actual execution (not just presence) and give a tight first/last-run window per host, useful for building the detonation timeline referenced in §3.
3. **Corroborate with ShimCache on hosts where Prefetch is thin or absent** — particularly relevant for server-role hosts, where Prefetch is often disabled by default (note 06's Prefetch.md version table). ShimCache's path + last-modified time is weaker evidence but may be the only registry-resident trace left if the attacker deleted the encryptor and its Prefetch entry.
4. **Match the hash across every host in the §3 scope list.** Amcache's SHA-1 is portable in a way path strings aren't — a masquerading or renamed encryptor can't defeat a hash match, which is exactly what note 06 flags as Amcache's core value for exactly this cross-host-matching use case.
5. **Extract and document, at minimum:** SHA-1 (and SHA-256 if independently computed from a recovered sample), the ransom-note filename/text pattern, the file extension appended to encrypted files, the deployment path used, and the C2/callback indicators if any were captured in §2's live network-state collection or §6's lateral-movement reconstruction.
6. **Feed the confirmed hash and IOC set into the threat-intel loop** (cross-ref note 20) — both for internal fleet-wide hunting (sweep every host's Amcache/ShimCache for the same hash, independent of whether encryption visibly occurred there) and for external correlation against known campaign trackers where applicable.

🔴 Do not stop at "encryptor identified" and call the investigation done — an encryptor hash alone tells you almost nothing about what else the attacker accessed before deploying it. §6's credential/lateral-movement reconstruction is what actually answers the scope question; §7 is IOC hygiene, not a substitute for it.

For encryptor binary identification using PowerShell:

Compute SHA-1/SHA-256 directly from a recovered sample for cross-referencing against Amcache's stored SHA-1 (note 06) and for the threat-intel pivot in point 6 above; full Amcache hive-mount/parse mechanics live in note 06's Amcache.md, not repeated here:

```powershell
Get-FileHash -Path 'C:\evidence\encryptor_sample.exe' -Algorithm SHA1
Get-FileHash -Path 'C:\evidence\encryptor_sample.exe' -Algorithm SHA256
```

Sweep the working host list (§3) for the confirmed hash under common drop locations, independent of path/filename, per point 4 above:

```powershell
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-ChildItem -Path 'C:\Users','C:\ProgramData','C:\Windows\Temp' -Recurse -File -Include *.exe -ErrorAction SilentlyContinue |
        Where-Object { (Get-FileHash $_.FullName -Algorithm SHA1 -ErrorAction SilentlyContinue).Hash -eq '<CONFIRMED_SHA1>' } |
        Select-Object @{N='ComputerName';E={$env:COMPUTERNAME}}, FullName
}
```

## Response Sequence — Summary

The full playbook, tied together as a single ordered checklist. This is the single most valuable deliverable in this note — everything above is the depth behind each step.

```
 1. Confirm: is encryption STILL ACTIVE on the reporting host?
        │
        ├─ YES → apply note 21's active-damage exception: contain
        │        (prefer VLAN isolation over full disconnect) before
        │        or in parallel with a compressed volatile-evidence
        │        capture — don't skip capture, just compress it.
        │
        └─ NO/UNSURE → default sequence: capture BEFORE contain.
        │
        ▼
 2. Memory capture FIRST (note 16/17) — LSASS credential material and
    any fileless-stage tooling exist only here.
        │
        ▼
 3. Live network + process state capture (note 16) — confirms whether
    the host is still an active node in ongoing deployment/C2 activity.
        │
        ▼
 4. Scope determination (§3 of this note) — sweep the fleet for
    mass-deployment artifacts BEFORE committing to a containment
    strategy. Do not assume the first host found is patient zero.
        │
        ▼
 5. Identify the deployment mechanism (§4) — GPO / PsExec-sc / WMI /
    scheduled task — check all four, in parallel where possible.
        │
        ▼
 6. Confirm shadow-copy/backup destruction (§5) — vssadmin list
    shadows + execution evidence for the deletion tooling, across
    every affected host.
        │
        ▼
 7. Reconstruct credential theft and lateral movement (§6) — walk
    backward from the §5 deployment account to the original foothold;
    this is what actually determines true scope of compromise.
        │
        ▼
 8. Identify and hash the encryptor (§7) — Amcache SHA-1 first,
    corroborate with Prefetch/ShimCache; sweep the hash fleet-wide.
        │
        ▼
 9. Remediate per note 21 — disable-and-document every persistence/
    deployment mechanism found in steps 5-7 (don't delete first),
    reset every compromised account, krbtgt TWICE if domain-wide
    compromise is confirmed, verify with a post-remediation Autoruns
    diff and a redundant-persistence check before declaring done.
        │
        ▼
10. Restore from backups/shadow copies confirmed clean in step 6 —
    only after remediation is verified, not before.
```

## Common Investigative Pitfalls

| 🔴 Pitfall | Why It's a Trap |
|---|---|
| Treating the first encrypted host reported as patient zero | Mass deployment (§4) means the visibly-affected workstation is usually just the one someone happened to be looking at, not the origin — encryption often starts on a less-visible server and spreads outward via the deployment mechanism. Always run §3's scope sweep before accepting any single host's narrative as the starting point. |
| Containing or powering off hosts before memory capture | Destroys the exact evidence (LSASS credential material, in-memory encryptor state, fileless-stage tooling per note 17) needed to reconstruct §6's credential-theft chain. Note 21's active-damage exception is narrow and situational, not a general license to isolate first and ask questions later. |
| Focusing exclusively on the encryptor binary and stopping there | An encryptor hash (§7) alone tells you almost nothing about what else the attacker accessed, staged, or exfiltrated before detonating. §6's credential/lateral-movement reconstruction is what actually determines full scope of compromise — skipping it because "we found the ransomware" leaves the real intrusion timeline unwritten. |
| Treating shadow-copy absence as automatically meaning "no recovery possible" | §5's `vssadmin list shadows` check only covers the local host's own recovery points. Backup infrastructure outside the immediate host scope — offline/immutable backups, a separate backup server the attacker didn't reach, replicated data at another site — may still provide recovery even when every local shadow copy is confirmed deleted. Check backup infrastructure independently before declaring data unrecoverable. |
| Assuming the account used to deploy the encryptor (§4) is where initial access happened | The deployment account is almost always several lateral hops and a privilege escalation away from the original foothold. Walking only as far back as "found the admin account that ran the deployment" and stopping understates the compromise window and misses earlier persistence the attacker may have planted along the way. |
| Deleting a discovered persistence/deployment mechanism the moment it's found | Per note 21's disable-and-document principle — deletion destroys the exact command line, trigger condition, and account context that both this investigation and any later legal process needs. Export/document first, disable second, exactly as note 21 sequences it for every mechanism in §4. |

## Correlate With

| To go deeper on… | Open |
|---|---|
| Order-of-volatility triage methodology applied throughout §2 | **Live Response and Volatile Data (16)** |
| Memory acquisition priority and full acquisition mechanics | **Memory Forensics — Memory Acquisition Fundamentals (17)** |
| LSASS/Mimikatz credential-theft detection depth behind §6 | **Memory Forensics — Memory Analysis (Processes, Injection, Rootkits) (17)** |
| Containment-vs-evidence-preservation tension, the active-damage exception, disable-and-document remediation sequencing | **Remediation and Containment (21)** |
| Full VSS mechanics, shadow-copy access methods, the shadow-copy-deletion detection-evidence table behind §5 | **Anti-Forensics and Evidence Destruction (19)** |
| GPO structure, `Registry.pol`, `gpresult`/`gpupdate`, the GPO-abuse-as-mass-deployment pattern behind §4 | **[GPO/ folder](<../GPO/00 - GPO Fundamentals and Architecture.md>)**, starting at 00; T1484.001 depth in GPO/05 |
| Fleet-wide Autoruns/software-inventory baselining used to scope §4's deployment mechanisms | **Enterprise Management and Baseline (22)** |
| Full source/destination evidence tables for every technique in §4 and §6 (RDP, PsExec, WMI, PowerShell Remoting, remote tasks/services, Pass-the-Hash/Pass-the-Ticket) | **Lateral Movement (12)** |
| Full registry/event-log evidence chain for service-based deployment (§4) | **Persistence Mechanisms — Services (10)** |
| Full XML/`TaskCache`/event-log evidence chain for scheduled-task deployment (§4) | **Persistence Mechanisms — Scheduled Tasks (10)** |
| Full filter/consumer/binding triad and event-log evidence chain for WMI-based deployment (§4) | **Persistence Mechanisms — WMI Event Consumers (10)** |
| The full execution-evidence family (Prefetch/ShimCache/Amcache/BAM-DAM/etc.) behind §5's deletion-tooling check and §7's encryptor identification | **Evidence of Program Execution (06)** |
| Full logon-type interpretation and 4648 explicit-credentials depth behind §6 | **Users, Groups & Authentication (05)** |
| AD replication metadata, Kerberoasting/Golden-Silver-Ticket/DCSync evidence chains behind §6 for GPO-based domain compromise | **Active Directory & Domain Forensic Artifacts (05b)** |
| Threat-intel feedback loop for the hash/IOC set extracted in §7 | **Threat Hunting Methodology and Intelligence (20)** |
| Landscape-level survey of ransomware alongside the other threat categories this module covers | **Windows Malware and Threat Landscape** (this folder) |
| Local-evidence trail if exfiltration via cloud-storage sync is suspected alongside encryption (§1) | **Cloud Storage Artifacts (Local Evidence) (13)** |
| Local-evidence trail if exfiltration via mailbox/webmail is suspected alongside encryption (§1) | **Email Forensics (15)** |

## Resources

- MITRE ATT&CK **T1486** (Data Encrypted for Impact) — https://attack.mitre.org/techniques/T1486/
- MITRE ATT&CK **T1490** (Inhibit System Recovery) — https://attack.mitre.org/techniques/T1490/ — already the anchor technique cited in note 19's VSS-deletion section
- MITRE ATT&CK **T1484.001** (Group Policy Modification) — https://attack.mitre.org/techniques/T1484/001/ — already cited in `GPO/05` for the GPO-abuse deployment vector in §4
- MITRE ATT&CK Lateral Movement (TA0008) and its constituent T1021 sub-techniques — already cited in full in note 12; not re-listed here to avoid duplication
- SANS FOR508 poster/index (bundled in this module's root) — used as a coverage-checklist only for the general ransomware/lateral-movement/anti-forensics scope this playbook sequences; no verbatim content reproduced
- Ransomware-group leak-site tracking resources — a category of publicly maintained trackers useful for correlating a victim organization against known active campaigns during an active incident, per this folder's overview note; not naming a specific tool/URL since availability changes, treat as "a category worth knowing exists"
