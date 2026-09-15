# RDP Brute-Force and Foothold Playbook

Internet-exposed RDP gets hammered by automated credential-stuffing/brute-force tools around the clock — this is background radiation on the modern internet, not a targeted event by itself. Most attempts fail. The ones that succeed usually succeed against a weak, default-ish, or previously-breached-and-reused password, and the moment they do, a burst of noisy failed logons quietly becomes a genuine interactive foothold on the host. This playbook covers that transition: detecting the brute-force pattern, confirming the pivot to success, reconstructing what the attacker actually did once inside, and handing off cleanly to the broader lateral-movement/persistence/ransomware investigation this foothold may feed.

> 🔴 **Scope boundary.** This playbook stops at the **foothold** — establishing that RDP brute-force succeeded and scoping what the attacker did during that initial access window. It deliberately does not re-cover the full ransomware kill chain (credential harvesting for domain-wide movement, mass deployment, shadow-copy deletion, encryption) — that belongs to a dedicated Ransomware Playbook in this same folder. RDP brute-force is frequently just the **first stage**: initial-access brokers specifically hunt for and sell working RDP credentials, and a ransomware affiliate buying that access picks up exactly where this playbook leaves off.

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [Scenario Framing](#scenario-framing)
- [Step 1 — Detect the Brute-Force Pattern](#step-1--detect-the-brute-force-pattern)
- [Step 2 — Confirm Successful Compromise](#step-2--confirm-successful-compromise)
- [Step 3 — Reconstruct the Attacker's Session Timeline](#step-3--reconstruct-the-attackers-session-timeline)
- [Step 4 — Check Post-Foothold Activity](#step-4--check-post-foothold-activity)
- [Step 5 — Source-IP and External Context](#step-5--source-ip-and-external-context)
- [Investigative Sequence Summary](#investigative-sequence-summary)
- [Pitfalls](#pitfalls)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## 🎯 Hunt Evil

Native, one-liner triage for the brute-force-to-foothold pattern this playbook covers — no third-party tooling required. These are fast-first checks for Steps 1–3 below; the deep-dive sections supply the full evidentiary-chain reasoning and the deferrals to notes 05/11/12 each of these hints at.

```powershell
# 4625 volume per source IP, with unique-account count - distinguishes single-account brute-force from a spray pattern (Step 1)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-6)} |
    ForEach-Object { [PSCustomObject]@{ SourceIP = $_.Properties[19].Value; Account = $_.Properties[5].Value } } |
    Group-Object SourceIP | Sort-Object Count -Descending |
    Select-Object Count, @{N='UniqueAccounts';E={($_.Group.Account | Sort-Object -Unique).Count}}, Name

# 4624 Type 10 (RemoteInteractive) successes in the same window - the brute-force-then-success pivot (Step 2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-6)} |
    Where-Object { $_.Properties[8].Value -eq 10 } |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='SourceIP';E={$_.Properties[18].Value}}

# LocalSessionManager 21/22 - confirms a session actually started and the shell loaded, not just a bare 4624 (Step 2)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22} -MaxEvents 50 |
    Select-Object TimeCreated, Id, @{N='User';E={$_.Properties[0].Value}}, @{N='SourceIP';E={$_.Properties[2].Value}}

# Currently active Type 10 (RDP) sessions on this host right now - is the foothold still live (Step 3)
Get-CimInstance Win32_LogonSession | Where-Object LogonType -eq 10 |
    ForEach-Object { Get-CimAssociatedInstance -InputObject $_ -ResultClassName Win32_Account } | Select-Object Name, Domain

# RDP exposure and NLA state on this host - direct check for the Pitfalls-table concern about pre-auth attack surface
Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action
(Get-CimInstance -Namespace root/CIMV2/TerminalServices -ClassName Win32_TSGeneralSetting).UserAuthenticationRequired

# mstsc.exe connection history on the compromised host - fastest lead on an onward lateral hop (Step 3, note 12)
Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue | Select-Object PSChildName
```

## Scenario Framing

The pattern is mechanically simple and shows up constantly in real intrusions: a host has RDP reachable from the internet — either directly on TCP 3389, or forwarded to a non-standard external port. The non-standard port buys essentially nothing against automated attackers; credential-stuffing tooling routinely scans wide port ranges looking for the RDP protocol handshake rather than assuming 3389, so "we moved it to a weird port" should never be treated as a mitigating control on its own.

An automated tool — usually working from a previously-breached credential list (username/password pairs harvested from unrelated prior breaches, tried here on the chance of reuse) or a simple dictionary of common/default-ish usernames and passwords — throws a high volume of logon attempts at the host. The overwhelming majority fail. Eventually, if any local or domain account reachable via RDP has a weak, default, or reused password, one succeeds. From that moment the attacker has a genuine interactive Windows session — not just network reachability, an actual desktop, with whatever rights that account carries.

What happens next varies, but a common shape is: brief reconnaissance (who am I, what's on this box, what else is on the network), an attempt to establish more durable persistence or a secondary credential, and staging for lateral movement. Critically, **this is frequently not the end goal of the operation** — it is the *access*. Initial-access brokers exist specifically to find and sell working RDP credentials; a ransomware affiliate or other downstream operator buying that access can arrive hours, days, or weeks after the original brute-force succeeded and pick up the intrusion from there. That gap in time, and the fact that the brute-force operator and the eventual ransomware operator may be entirely different actors, is why this playbook's scope is deliberately bounded to the foothold itself rather than chasing the full downstream kill chain — see the (separate, possibly-still-in-progress) Ransomware Playbook in this folder for that continuation.

## Step 1 — Detect the Brute-Force Pattern

The signature is volume, not any single event: a burst of **4625** (logon failure) events against the same account, or against many different account names, from the same source IP in a short window. Full field-level meaning of 4625 (failure-reason codes, source workstation/IP fields, logon package) is owned by [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md#core-authentication--account-event-ids>); this step is purely about recognizing the volume pattern, not re-deriving what the event's fields mean.

Two shapes to watch for, and they imply different attacker tooling:

- **Same account, many failures** — a straightforward brute-force against one known/guessed username.
- **Many different accounts, same source IP, in a short window** — a spray/credential-stuffing pattern working through a username list rather than fixating on one account. Tally accounts-per-source-IP here, not just failures-per-account, or a spray pattern reads as noise instead of a signature — this exact framing is already called out in note 05's Logon-Type Triage table.

**Logon Type filter:** apply Type **10** (RemoteInteractive) or Type **3** (Network) depending on how the brute-force tool is hitting the host. Hedge here deliberately — different RDP brute-force tooling behaves differently at the protocol level, and depending on where in the RDP negotiation/authentication sequence the attempt fails, some tooling generates Type 10 failures directly while other tooling (or certain NLA pre-authentication rejection paths) can surface as Type 3-shaped network logon failures before the full RDP session negotiation even begins. Don't assume one type to the exclusion of the other — filter 4625 broadly first, then check which Logon Type the actual burst carries on this host before narrowing further.

Also pull `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` Event ID **1149** for the same window. 🔴 Note 11 carries an explicit caveat that is directly load-bearing here: **1149 fires even on connections that never complete authentication or get cancelled.** A 1149 record proves a network-level RDP connection reached the host and network authentication was attempted — it does **not** by itself prove a session was established, and during an active brute-force it will be firing constantly for attempts that go nowhere. Treat 1149 volume during this step as corroborating "yes, RDP is being hit hard from this source," not as evidence of compromise. Full mechanics: [`11 - Event Log Analysis` § Terminal Services / RDP](<../11 - Event Log Analysis.md#terminal-services--rdp>).

### PowerShell

Full field-level 4625 mechanics (failure-reason codes, logon package) live in note 05, not repeated here. Hunt Evil above gives the aggregated per-source-IP tally; these go one layer deeper.

Pull the raw, unaggregated 4625 events for the window under review:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-6)} |
    Select-Object TimeCreated, @{N='Account';E={$_.Properties[5].Value}}, @{N='LogonType';E={$_.Properties[10].Value}}, @{N='SourceIP';E={$_.Properties[19].Value}}
```

Tag each source IP with which of the two shapes this step names (same-account brute-force vs. multi-account spray):

```powershell
$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-6)} |
    ForEach-Object { [PSCustomObject]@{ SourceIP = $_.Properties[19].Value; Account = $_.Properties[5].Value } }
$events | Group-Object SourceIP | Select-Object Name, Count,
    @{N='UniqueAccounts';E={($_.Group.Account | Sort-Object -Unique).Count}},
    @{N='Shape';E={ if (($_.Group.Account | Sort-Object -Unique).Count -eq 1) {'Same-account'} else {'Spray'} }}
```

- 1149 volume for the same window — corroborating context only, per the caveat above, never proof of compromise on its own:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149; StartTime=(Get-Date).AddHours(-6)}
```

## Step 2 — Confirm Successful Compromise

The clearest positive signature: a **4624** (logon success), Logon Type **10**, for the target account, landing immediately after — or interleaved with the tail of — the 4625 burst identified in Step 1, from the same source IP. This is the brute-force-then-success pattern note 05's Logon-Type Triage table already names explicitly for Type 10.

Confirm session establishment, don't stop at the 4624 alone — cross-reference `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`:

| Event ID | What it confirms |
|---|---|
| **21** | Session logon succeeded — a full RDP session actually started |
| **22** | Shell start — the desktop/shell finished loading inside the session |
| **23** | Session logoff |
| **24** / **25** | Session disconnect / reconnect |

Full field depth for all of the above (and the 1149 caveat again, since it applies here too — don't let a 1149 substitute for this confirmation step) lives in [`11 - Event Log Analysis` § Terminal Services / RDP](<../11 - Event Log Analysis.md#terminal-services--rdp>). The evidentiary chain you want before calling this "confirmed compromise" is: 4625 burst → 4624 Type 10 success → LocalSessionManager 21 (session logon) → 22 (shell loaded) — four independent sources agreeing, not one event read in isolation. For interpreting exactly what Logon Type 10 (and the reconnect-flavored Type 7) mean at the field level, see note 05's [Logon Types table](<../05 - Users, Groups & Authentication.md#logon-types-event-id-4624--4625>).

### PowerShell

Assemble the four-source evidentiary chain above for one candidate account, rather than eyeballing each log in isolation:

```powershell
$account = '<TargetAccount>'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddHours(-6)} |
    Where-Object { $_.Properties[8].Value -eq 10 -and $_.Properties[5].Value -eq $account } |
    Select-Object TimeCreated, @{N='Event';E={'4624 Type 10'}}

Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'; Id=21,22,23; StartTime=(Get-Date).AddHours(-6)} |
    Where-Object { $_.Properties[0].Value -eq $account } |
    Select-Object TimeCreated, Id, @{N='Event';E={"LSM $($_.Id)"}}
```

## Step 3 — Reconstruct the Attacker's Session Timeline

Once compromise is confirmed, the goal shifts to answering "what did the attacker actually do during this session, and are they still in it."

**If the investigation is happening while access may still be live** — check for an active unauthorized session before anything else:

```
query user
quser
net session
```

These live-session-enumeration commands (full context and the rest of the live-response sequence in [`16 - Live Response and Volatile Data` § Logged-On Users and Sessions](<../16 - Live Response and Volatile Data.md#logged-on-users-and-sessions>)) tell you whether the compromised account (or any other unexpected account) is currently logged on via RDP right now — a materially different, more urgent situation than reconstructing a session that already ended. Note 16's live-response principles apply directly here: document every command run, since your own triage activity generates the same kind of execution/session evidence you're trying to distinguish from the attacker's.

**Reconstructing what was on screen** — the RDP bitmap cache is the single most valuable "what did the attacker actually see" artifact for this scenario, and it's already fully covered in [`12 - Lateral Movement` § RDP](<../12 - Lateral Movement.md#rdp>). Two caveats worth restating in this specific context:

- The bitmap cache (`%LocalAppData%\Microsoft\Terminal Server Client\Cache\`) lives on the **source** machine — the attacker's own box — not the victim host. In a brute-force-foothold scenario that source machine is the attacker's infrastructure, which is realistically out of collection scope. This artifact becomes genuinely useful for this playbook mainly in the **secondary-hop** case: once the attacker RDPs from the compromised host onward to a second internal host, the *first* compromised host's own bitmap cache can show fragments of what the attacker saw on that second hop, even if the second host's own logs are gone.
- The `mstsc.exe` connection-history key (`HKCU\Software\Microsoft\Terminal Server Client\Servers`) on the compromised host tells you **where the compromised account's session subsequently RDP'd to** — the fastest way to identify a lateral hop originating from the very foothold this playbook is investigating.

### PowerShell

Enumerate the `mstsc.exe` connection-history key with `UsernameHint`, since the account used on an onward hop isn't always the same as the compromised account (Hunt Evil above lists destinations only; this adds the account):

```powershell
Get-ChildItem 'HKCU:\Software\Microsoft\Terminal Server Client\Servers' -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ItemProperty $_.PSPath | Select-Object @{N='Destination';E={$_.PSChildName}}, UsernameHint
}
```

Response actions apply if the live-session check above (`query user`/`quser`/`net session`, or the Hunt Evil `Win32_LogonSession` equivalent) confirms access is still active right now. Capture evidence first: document that output and Step 2's evidentiary chain before acting. Full containment sequencing and the active-damage-exception tradeoff live in [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md#account-and-credential-remediation>), not repeated here — these are the RDP-specific mechanics that section's generic sequencing calls for.

```powershell
# Force logoff the active RDP session identified above - logoff.exe is still the native tool for this, no direct cmdlet exists in Windows PowerShell 5.1
logoff.exe <SessionID> /server:<HostName>

# Disable the compromised account - disable, don't delete, so it's still available for later review (local and domain variants)
Disable-LocalUser -Name '<CompromisedAccount>'
Disable-ADAccount -Identity '<CompromisedAccount>'

# Block inbound RDP at the host firewall - immediate local containment; broader network-level 3389 blocking belongs to note 21
New-NetFirewallRule -DisplayName 'Containment-Block-RDP-In' -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block

# Disable the RDP listener itself once evidence collection is complete - takes effect after a reboot or Terminal Services restart
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
```

**Execution evidence for whatever the attacker ran** once inside — Prefetch, ShimCache, Amcache, BAM/DAM, and the rest of the execution-evidence family, all timestamped and each with different guarantees/limitations, are covered in full in [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>). Pull this evidence bounded to the confirmed session window from Step 2 (LocalSessionManager 21 through 23/24) — anything executed inside that window under the compromised account's context is presumptively attacker activity until shown otherwise.

## Step 4 — Check Post-Foothold Activity

Once the foothold itself is confirmed and the session window is bounded, the investigation broadens outward from "did they get in" to "what did they set up while they were in." This is a pointer section, not a re-derivation — each of these is a full artifact family covered elsewhere in this module:

- **Persistence establishment** — did the attacker create a Run key, service, scheduled task, WMI subscription, or exploit DLL search order to survive a reboot or the compromised account being disabled? Full detection depth across all five mechanisms: [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>).
- **Credential harvesting for further lateral movement** — an attacker with an interactive foothold on one host frequently pursues LSASS memory access or other credential-dumping techniques to obtain material for reaching further hosts. Full detection depth: [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits)`](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>).
- **Reconnaissance commands** — what the attacker typed once at an interactive prompt is frequently recoverable from PowerShell's persistent command history. Full coverage (including the caveat that gaps in this history can themselves indicate selective clearing): [`16 - Live Response and Volatile Data` § Command History](<../16 - Live Response and Volatile Data.md#command-history>).

Treat this step as the launch point into the module's broader lateral-movement and persistence investigation, not something to fully resolve inside this playbook.

### PowerShell

Bound the persistence check to the confirmed session window from Step 2 (LSM 21 through 23/24), rather than an unscoped fleet-wide autoruns sweep; full per-mechanism detection depth (Run keys, services, scheduled tasks, WMI subscriptions, DLL hijacking) lives in [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>), not repeated here:

```powershell
$sessionStart = '<LSM21_Timestamp>'; $sessionEnd = '<LSM23_or_24_Timestamp>'
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=$sessionStart; EndTime=$sessionEnd} -ErrorAction SilentlyContinue
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime=$sessionStart; EndTime=$sessionEnd} -ErrorAction SilentlyContinue
```

## Step 5 — Source-IP and External Context

The source IP(s) behind the brute-force burst are worth correlating against whatever threat-intelligence/reputation context is available — known-malicious infrastructure, prior appearance in other incidents, or an existing internal indicator list. This is the same intel feedback-loop concept established generically in [`20 - Threat Hunting Methodology and Intelligence` § Threat Intelligence — The Feedback Loop](<../20 - Threat Hunting Methodology and Intelligence.md#threat-intelligence--the-feedback-loop>): this investigation's own finding (a source IP that successfully brute-forced RDP) is exactly the kind of output that should feed back into future hunts and detections, not just get used once and discarded.

Geolocation of the source IP is useful **triage context** — does the apparent origin match or wildly contradict where the legitimate account holder is expected to be — but it is not reliable attribution. Attackers routinely operate through VPNs, proxies, and compromised third-party infrastructure specifically to obscure true origin, so a geolocation result should inform your working hypothesis and prioritization, never stand alone as proof of who did this or where they actually are.

## Investigative Sequence Summary

```
1. Detect brute-force pattern
   4625 burst (same account, or many accounts/one source) + 1149 volume
   → apply Logon Type 10/3 filter, hedge on which per note 05/11
                    │
2. Confirm success
   4624 Type 10, immediately after the burst, same source
   → cross-reference LocalSessionManager 21 (session logon) + 22 (shell start)
                    │
3. Reconstruct session timeline
   query user / quser / net session (if possibly still active)
   → RDP bitmap cache + mstsc.exe connection history (note 12)
   → execution evidence bounded to the session window (note 06)
                    │
4. Check post-foothold activity
   Persistence (note 10) · Credential harvesting (note 17 Memory Analysis)
   · PowerShell history recon (note 16)
                    │
5. Correlate source-IP context
   Threat-intel/reputation feedback loop (note 20) · geolocation as
   triage-only context, not attribution
                    │
6. Hand off
   Broader lateral-movement investigation (note 12) if the account/session
   reached other hosts · account/credential remediation (note 21)
   · if downstream ransomware activity is suspected, continue into the
     Ransomware Playbook (this folder) from here
```

## Pitfalls

| 🔴 Pitfall | Why it matters |
|---|---|
| Reading a single 4624 after a 4625 burst as automatic proof of compromise without checking *who* actually logged in | A legitimate user who mistypes their own password several times before getting it right produces the exact same superficial 4625-then-4624 shape. Confirm the source IP/workstation is genuinely unfamiliar and the timing/context doesn't match the account holder's normal pattern before calling it compromise — this is the single highest-risk false positive in this whole playbook |
| Treating 1149 alone as proof of successful access | Note 11's own caveat applies directly: 1149 fires even on connections that never complete authentication. Always require LocalSessionManager 21 and/or Security 4624 Type 10 alongside it |
| Stopping the investigation at "found and disabled the compromised account" | RDP brute-force is frequently just the first stage. Skipping Step 4 (persistence, credential harvesting, recon-command review) means missing whatever the attacker actually did during their access window — the part that usually matters more than the initial access itself |
| Not checking whether Network Level Authentication (NLA) was enabled | NLA-disabled RDP exposes a larger pre-authentication attack surface than NLA-enabled RDP and can change what evidence is generated before a credential is even validated. Confirm NLA's configured state on the host as part of scoping the exposure, but hedge on asserting the *exact* evidentiary differences this produces — verify the specific pre-auth logging behavior against current documentation/testing for the OS build in question rather than assuming a fixed rule |
| Assuming a non-default listening port meaningfully reduced exposure | Automated brute-force/credential-stuffing tooling commonly scans for the RDP protocol handshake across a range of ports, not just 3389 — don't treat "we moved the port" as a mitigating factor when scoping how the host was found in the first place |

## Correlate With

| Note | Why |
|---|---|
| [`Windows Malware and Threat Landscape`](<Windows Malware and Threat Landscape.md>) | This folder's landing page — RDP brute-force sits under its Ransomware and Credential Theft threat categories as a common initial-access vector |
| [`05 - Users, Groups & Authentication`](<../05 - Users, Groups & Authentication.md>) | Full logon-type reference table, 4624/4625 field-level meaning, RDP usage tracking from the account/authentication angle |
| [`06 - Evidence of Program Execution`](<../06 - Evidence of Program Execution>) | Execution evidence for whatever the attacker ran once inside the session |
| [`10 - Persistence Mechanisms`](<../10 - Persistence Mechanisms>) | What the attacker may have planted to survive the account being disabled/reset |
| [`11 - Event Log Analysis`](<../11 - Event Log Analysis.md#terminal-services--rdp>) | Terminal Services/RDP operational-log mechanics — LocalSessionManager 21-25, RemoteConnectionManager 1149, and the 1149 false-confirmation caveat this playbook leans on directly |
| [`12 - Lateral Movement`](<../12 - Lateral Movement.md#rdp>) | RDP-specific source/destination artifact chain, bitmap cache, `mstsc.exe` connection history, and where this foothold feeds into onward lateral movement |
| [`16 - Live Response and Volatile Data`](<../16 - Live Response and Volatile Data.md>) | `query user`/`quser`/`net session` live-session enumeration, PowerShell command history collection |
| [`17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits)`](<../17 - Memory Forensics/Memory Analysis (Processes, Injection, Rootkits).md>) | Credential-harvesting detection if the attacker pursued further lateral movement from this foothold |
| [`20 - Threat Hunting Methodology and Intelligence`](<../20 - Threat Hunting Methodology and Intelligence.md#threat-intelligence--the-feedback-loop>) | The intel feedback-loop concept behind Step 5's source-IP correlation |
| [`21 - Remediation and Containment`](<../21 - Remediation and Containment.md#account-and-credential-remediation>) | Account/credential remediation once the compromised account is confirmed — password reset, disable-don't-delete, session/token revocation |
| Ransomware Playbook (this folder — check current contents, may not yet be written) | The likely next stage if this foothold was sold to or used by a ransomware affiliate; this playbook's Step 4/handoff is where that broader investigation begins |

## Resources

- MITRE ATT&CK **T1110 (Brute Force)** — the technique this playbook's Step 1/2 detects.
- MITRE ATT&CK **T1021.001 (Remote Services: Remote Desktop Protocol)** — already cited in full in [`12 - Lateral Movement`](<../12 - Lateral Movement.md>); not re-cited in depth here.
- SANS FOR508 poster/personal index — used as a coverage checklist only during this playbook's construction; no content reproduced verbatim. No RDP-brute-force-specific playbook content was found there beyond the Account Usage/logon-type and RDP session-event panels already reflected in notes 05 and 11.
- Microsoft Learn — Network Level Authentication for Remote Desktop Services (consult current documentation for exact pre-authentication evidentiary behavior referenced in the Pitfalls table above).
