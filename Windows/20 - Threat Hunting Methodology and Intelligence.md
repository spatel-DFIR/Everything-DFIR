# Threat Hunting Methodology and Intelligence

Every other note in this module answers "how do I find and read artifact X." This note answers a different question: **once you've found something, what do you do with it, and how do you decide where to look next?** It is the connective tissue that ties the module's ~35 artifact-specific notes into a single working investigation — the IR lifecycle that frames when each note gets used, the hunting disciplines that decide which notes to open first, the kill chain that turns a pile of individual findings into an attack narrative, and the ATT&CK framework that gives that narrative a shared vocabulary. This note deliberately does **not** re-derive artifact-level detail that already lives elsewhere — its job is to be the map, not the territory, and to explicitly feed the future **`00b - ATT&CK Windows to Evidence Map.md`** note, which will build the full granular ATT&CK-technique-to-evidence table this note only sets up conceptually.

> 🔴 **The single biggest process failure this note exists to prevent: finding an artifact and stopping.** An analyst who finds a suspicious scheduled task and writes "persistence confirmed" without asking *what kill-chain stage does this represent, what does it imply about earlier stages I haven't checked, and what does it imply the attacker still has access to* has done artifact-spotting, not threat hunting. Every section below is built around forcing that next question.

## 🎯 Hunt Evil

This note is methodology, not an artifact — so unlike the rest of the module, this block isn't "the values to key on for one artifact." It's the three hunting-discipline patterns (IOC-based, hypothesis-driven, anomaly-based) from the Threat Hunting as a Discipline section, expressed as reusable, native PowerShell scaffolding. Swap in the specific hash/path/technique for a given hunt; the artifact-level detail behind any specific hit belongs in that artifact's own note, not here.

```powershell
# IOC-based hunt: sweep a host list for known-bad file hashes (SHA1, matching Amcache's hash type) - the classic "vendor report gave us a hash" hunt
$hosts = Get-Content C:\hunt\hosts.txt
$badHashes = Get-Content C:\hunt\known_bad_sha1.txt
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-ChildItem C:\Users, C:\ProgramData, C:\Windows\Temp -Recurse -File -ErrorAction SilentlyContinue |
        Get-FileHash -Algorithm SHA1 |
        Where-Object Hash -in $using:badHashes
}

# IOC-based hunt: sweep a host list for a known-bad filename/path fragment, e.g. a tool named in a threat-intel report
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-ChildItem C:\Users, C:\ProgramData -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object Name -match 'evil\.exe|suspicioustool'
}

# Hypothesis-driven hunt: test a specific, falsifiable claim across the estate - here, "an attacker is using WMI for lateral movement"
# points directly at a bounded evidence set (see WMI Event Consumers, note 10, and Lateral Movement, note 12) rather than "look at everything"
Invoke-Command -ComputerName $hosts -ScriptBlock { Get-Process -Name WmiPrvSE | Select-Object Id, Parent }

# Anomaly-based hunt: baseline deviation - which hosts are running a process name that ISN'T present fleet-wide (outlier, not majority pattern)
$results = Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-Process | Select-Object @{N='ComputerName'; E={ $env:COMPUTERNAME }}, ProcessName
}
$results | Group-Object ProcessName | Where-Object Count -lt ($hosts.Count * 0.1) | Select-Object Name, Count

# Anomaly-based hunt: "Know Normal" process-tree check - unexpected parent for a process that should only ever be spawned by services.exe
Get-CimInstance Win32_Process -Filter "Name='svchost.exe'" |
    ForEach-Object { [PSCustomObject]@{ PID = $_.ProcessId; ParentPID = $_.ParentProcessId; ParentName = (Get-Process -Id $_.ParentProcessId -ErrorAction SilentlyContinue).ProcessName } } |
    Where-Object ParentName -ne 'services'

# Kill-chain timeline scaffold: pull a specific Event ID across the estate in parallel, for building the kill-chain-annotated
# timeline described in the Practical Walkthrough below - swap the LogName/Id for whatever the current hypothesis is checking
Invoke-Command -ComputerName $hosts -ScriptBlock {
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} -MaxEvents 100
} | Sort-Object TimeCreated
```

## Contents

- [🎯 Hunt Evil](#-hunt-evil)
- [The Incident Response Process](#the-incident-response-process)
- [Threat Hunting as a Discipline](#threat-hunting-as-a-discipline)
- [The Cyber Kill Chain](#the-cyber-kill-chain)
- [MITRE ATT&CK — The Framework Concept](#mitre-attck--the-framework-concept)
- [IR Team Roles (Brief)](#ir-team-roles-brief)
- [Threat Intelligence — The Feedback Loop](#threat-intelligence--the-feedback-loop)
- [Practical Walkthrough — How to Actually Use This Module](#practical-walkthrough--how-to-actually-use-this-module)
- [Red Flags — Process Pitfalls](#red-flags--process-pitfalls)
- [Tooling](#tooling)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## The Incident Response Process

The standard SANS/NIST-aligned IR lifecycle — six stages, cyclical rather than strictly linear (Lessons Learned feeds back into Preparation for the next incident). This note's job is to map **which parts of this module support which stage**, not to re-teach IR process theory.

| Stage | What happens | Where this module supports it |
|---|---|---|
| **Preparation** | Establishing baselines, logging/audit-policy configuration, tooling readiness, IR plan/playbooks *before* an incident happens | **Enterprise Management and Baseline (22, forthcoming)** owns baselining and GPO-driven logging configuration; note 11's Audit Policy Fundamentals section covers the logging prerequisites that must be *already on* for later stages to have evidence to work with |
| **Identification** | Confirming an incident is actually occurring, scoping which hosts/accounts are affected | Draws on nearly **every** artifact note in this module — this is the stage where notes 03 through 19 do their work: execution evidence (06), persistence (10), lateral movement (12), event logs (11), timeline construction (18), anti-forensics detection (19) |
| **Containment** | Isolating affected hosts/accounts to stop the bleeding without destroying evidence or tipping off the attacker prematurely | **Remediation and Containment (21, forthcoming)** owns this in full; this module's job during containment planning is supplying the *scope* (which hosts, which accounts, which persistence mechanisms) that containment decisions are based on |
| **Eradication** | Removing the attacker's access — killing persistence, resetting credentials, patching the entry vector | **Remediation and Containment (21, forthcoming)**; note 10's five Persistence Mechanisms notes are the direct input — you cannot eradicate what you haven't fully enumerated |
| **Recovery** | Restoring systems to normal operation, monitoring closely for reinfection | **Remediation and Containment (21, forthcoming)**; note 22 (forthcoming) baselining is what "normal" gets measured against post-recovery |
| **Lessons Learned** | Post-incident review, updating detections/playbooks/baselines for next time | Feeds the Threat Intelligence feedback loop below, and feeds **Enterprise Management and Baseline (22, forthcoming)** — this is where a completed investigation's findings become tomorrow's hunt hypotheses |

The **Identification** row is intentionally the widest — that's not an oversight, it's the reality that this module is overwhelmingly an Identification-stage reference. Containment/Eradication/Recovery are process and infrastructure decisions that lean on this module's findings but are executed elsewhere (note 21). Preparation leans on note 22. This note sits conceptually above all six stages as the reasoning framework that connects them.

## Threat Hunting as a Discipline

**Threat hunting is proactive; incident response is reactive.** IR responds to a known or suspected incident — an alert fired, a user reported something, a third party notified you. Threat hunting searches for evidence of compromise **without** a specific triggering alert, based on a hypothesis about what an attacker *might* be doing in the environment. The two disciplines use the exact same artifact notes in this module — the difference is entirely about what triggers the investigation, not what evidence gets pulled once it starts.

| | Incident Response | Threat Hunting |
|---|---|---|
| **Trigger** | A specific alert, report, or confirmed indicator | No specific trigger — a hypothesis, a threat-intel report, or scheduled proactive coverage |
| **Starting scope** | Usually narrow (one host, one account) and expands as findings warrant | Usually broad (fleet-wide sweep for a specific technique) and narrows as findings warrant |
| **Success looks like** | Incident contained, root cause identified, recovery complete | Either confirmation the environment is clean of the hunted-for behavior, or a new incident discovered before it was otherwise noticed |
| **This module's role** | Same artifact notes, applied to a scoped set of hosts already implicated | Same artifact notes, applied fleet-wide against a specific hypothesis |

Three hunting methodologies, not mutually exclusive — a mature hunting program runs all three:

**Hypothesis-driven hunting.** Start from a specific, falsifiable hypothesis about likely attacker behavior in *this* environment, then systematically check the relevant artifacts across hosts to confirm or refute it. The hypothesis should be specific enough to point at a concrete evidence set — "an attacker may be using WMI for lateral movement in our environment" is a good hypothesis because it points directly at **WMI Event Consumers (10)** and the WMI-specific evidence in **Lateral Movement (12)** (`WmiPrvSE.exe` parent processes, WMI-Activity/Operational 5857-5861, permanent-subscription triads) — a hunter can go pull exactly those artifacts fleet-wide and get a concrete yes/no answer. A vague hypothesis ("the attacker might be doing something with PowerShell") is much weaker — it doesn't point at a bounded evidence set, and the hunt risks becoming unfocused "look at everything" work (see Red Flags below).

**IOC-based hunting.** Search for specific known indicators — file hashes, IPs, domains, filenames — across the environment, usually seeded by external threat intel (a vendor report, an ISAC bulletin, a hash from a related incident). More reactive/intel-driven than hypothesis hunting: you're not reasoning about likely attacker behavior in the abstract, you're checking whether a *specific, already-known* artifact is present. Amcache/ShimCache hash values (note 06) and lateral-movement source/destination IPs (note 12) are the two most common IOC types this module's notes produce and consume — see the Threat Intel feedback loop below.

**Anomaly-based / baseline-deviation hunting.** Compare current environment state against an established "normal" baseline and investigate deviations. This is the hunting style with the steepest prerequisite: you cannot hunt for deviation from normal without first having established what normal *is*. Note 01's "Know Normal" process-tree material (the dozen legitimate system processes, their expected paths/parents/instance counts) is the host-level starting point for this — an unexpected `svchost.exe` parent or an out-of-place instance count is a baseline deviation caught this way. **Enterprise Management and Baseline (22, forthcoming)** is the fleet-wide extension of the same idea — GPO/configuration baselines, software inventory baselines — and is the explicit prerequisite this hunting style depends on at scale; note 01 gives you the single-host version, note 22 gives you the fleet version.

## The Cyber Kill Chain

The Lockheed Martin Cyber Kill Chain models an intrusion as a sequence of stages an attacker must progress through to achieve their objective. It predates ATT&CK, is coarser-grained, and is still valuable as a **high-level narrative structure** for an investigation report — "here's what stage the attacker reached, here's the evidence for each stage" reads far more clearly to a non-technical stakeholder than a flat list of ATT&CK technique IDs. This is the single most valuable table in this note: it turns the module's entire artifact catalog into a kill-chain-organized index.

| Kill Chain Stage | What it means | Windows evidence in this module |
|---|---|---|
| **Reconnaissance** | Attacker gathers information about the target before acting — often external to the host (OSINT, scanning) and largely invisible to host forensics | Rarely direct host evidence; `net view`/`net use` share enumeration and `Get-SmbShare` reconnaissance that *precedes* lateral movement is covered in **Lateral Movement (12)**'s `net use`/Share Mapping section — the one recon sub-type this module does have host-side visibility into |
| **Weaponization** | Attacker builds or obtains the malicious payload/deliverable — happens off-host, before delivery | No direct host evidence by definition; occasionally inferable from payload characteristics recovered in later stages (e.g., packing/obfuscation patterns seen in Memory Analysis) |
| **Delivery** | The payload reaches the target — phishing email, drive-by download, malicious attachment, watering-hole site | **Email Forensics (15)** (malicious attachment/link delivery), **Web Browser Forensics (14)** — especially the Chromium and Private Browsing/Anti-Forensic Recovery sub-notes — for drive-by/malvertising delivery; **Removable Device (USB) Forensics (09)** for physical-media delivery |
| **Exploitation** | The payload's vulnerability/exploit code executes, gaining the attacker initial code execution | **Evidence of Program Execution (06)** family (Prefetch/ShimCache/Amcache/BAM-DAM) for the exploited process's first-run evidence; **Event Log Analysis (11)** Application-log crash/fault events can sometimes mark the exploited process's failure point; browser-process crash artifacts in **Web Browser Forensics (14)** |
| **Installation** | Attacker establishes a durable foothold — this is where "gaining execution" becomes "staying" | All five **Persistence Mechanisms (10)** notes (Autostart/Run keys, Services, Scheduled Tasks, WMI Event Consumers, DLL Hijacking) plus **Evidence of Program Execution (06)** confirming the dropped persistence payload actually ran |
| **Command & Control (C2)** | Attacker establishes a communication channel back to infrastructure they control | **Event Log Analysis (11)** network-adjacent operational logs (WinRM/Operational, PowerShell/Operational 4104 for C2-delivered commands); Sysmon Event ID 3 if deployed (noted in note 12's Tooling section) is the strongest per-process network-connection evidence available, since native Windows logging has no equivalent by default |
| **Actions on Objectives** | The attacker's actual goal — lateral movement to reach a target, data staging/exfiltration, destructive impact, credential harvesting for further reach | **Lateral Movement (12)** in full (RDP, PsExec, WMI, WinRM, remote tasks/services, `net use`, pass-the-hash/pass-the-ticket); **Users, Groups & Authentication (05)** for credential-harvesting evidence (4648 explicit credentials, logon-type anomalies); **Anti-Forensics and Evidence Destruction (19)** for evidence the attacker tried to cover their tracks once objectives were reached |

A single intrusion typically shows evidence at multiple stages simultaneously across multiple hosts — the attacker may be in Installation on the initial foothold host while already in Actions on Objectives (lateral movement) against a second host. Building a kill-chain-annotated timeline (feeding **Timeline Analysis, note 18**) that plots findings against this table, per host, is the practical output of this section.

## MITRE ATT&CK — The Framework Concept

ATT&CK (attack.mitre.org) is the modern, far more granular complement to the kill chain — not a replacement for it. The two are typically used **together**: the kill chain gives the high-level narrative arc for a report or a stakeholder briefing ("the attacker reached the Installation stage on three hosts before containment"), while ATT&CK gives the technique-level precision needed for detection engineering, threat-intel sharing, and cross-incident comparison ("the attacker used T1053.005 Scheduled Task for persistence, matching TTPs seen in a prior incident").

ATT&CK's structure, three layers of increasing specificity:

| Layer | What it represents | Example |
|---|---|---|
| **Tactic** | The attacker's *why* — the goal a stage of the intrusion serves | Persistence (TA0003) |
| **Technique** | The *how* — a general method of achieving that tactic | T1053 Scheduled Task/Job |
| **Sub-technique** | A specific variant of the technique | T1053.005 Scheduled Task |

Tactics map loosely onto (but are more granular than, and not identical to) kill-chain stages — ATT&CK has 14 tactics versus the kill chain's 7 stages, because ATT&CK splits things like Privilege Escalation, Defense Evasion, Discovery, and Collection out as distinct tactics rather than folding them into a broader stage. This module's artifact notes already, individually, cite specific ATT&CK technique IDs where directly relevant (e.g., **Lateral Movement (12)**'s Resources section cites T1021.001/.002/.003/.006, T1570, T1550.002/.003). Building the **complete, systematic Windows-technique-to-evidence mapping table** — every relevant ATT&CK technique cross-referenced against exactly which note and which artifact proves it — is explicitly the job of the forthcoming **`00b - ATT&CK Windows to Evidence Map.md`** note, deferred to the end of this module's build. This section's scope stops at explaining the framework concept clearly enough to use the per-note technique citations that already exist throughout the module.

## IR Team Roles (Brief)

Kept intentionally brief and generic — this is organizational-process content, not artifact-specific technical depth, and engagement structure varies significantly by organization size and whether the response is internal or consultant-led. A typical formal IR engagement includes, at minimum:

| Role | Function |
|---|---|
| **Incident Commander / IR Lead** | Owns overall coordination and decision authority — containment timing, communication cadence, when to declare stages complete |
| **Forensic Analyst(s)** | The role this module is written for — artifact collection and interpretation, timeline construction, scope determination |
| **Threat Intelligence Analyst** | Correlates findings against known actor TTPs/IOCs, produces attribution assessments where possible — feeds and is fed by the loop in the next section |
| **Communications / Legal Liaison** | Manages internal stakeholder updates, regulatory/breach-notification obligations, external communication — keeps technical findings from leaking prematurely or being miscommunicated |

On smaller engagements one person frequently holds two or more of these roles simultaneously; the roles are worth naming even when the org chart doesn't reflect them, because each represents a distinct *type of decision* that needs to get made during a response.

## Threat Intelligence — The Feedback Loop

Threat intel and investigation findings feed each other in both directions — this is the loop that makes hunting programs improve over time rather than restarting from zero on every engagement.

**Intel shapes the hunt (intel → investigation):** existing threat intel — actor profiles, published TTP reports, IOC feeds — shapes which hypotheses a hunt starts from in the first place. A report describing a specific actor's known use of WMI permanent subscriptions is exactly what turns into the hypothesis-driven hunt example above.

**Findings become intel (investigation → intel):** an investigation's own findings become new threat intel that seeds future hunts and detections. This module's artifact notes are concrete producers of exactly this kind of IOC:

| Evidence source | IOC type produced |
|---|---|
| **Lateral Movement (12)** — destination-host authentication and technique-footprint evidence | Malicious source IPs, compromised account names, characteristic tool command-line patterns (e.g., Evil-WinRM's recognizable 4104 content) |
| **Evidence of Program Execution (06)** — Amcache/ShimCache | File hashes (SHA1 in Amcache) and full paths of attacker tooling — the most durable, portable IOC type this module produces, since a hash survives even when the file itself is gone |
| **Event Log Analysis (11)** | C2 infrastructure indicators from PowerShell/WinRM operational-log content, timestamps that anchor an actor's operational hours |

Feed these findings back into whatever IOC/TTP tracking your organization uses — a dedicated threat-intel platform (category note below) or, at minimum, a durable internal indicator list — so the next hunt starts from a stronger hypothesis than this one did. An investigation that produces findings but never feeds them back into future hunting or detection content has thrown away half its value.

### PowerShell

- Close the loop mechanically: export a durable indicator list from an investigation's findings — the minimum viable version of "feed intel back" when no dedicated TIP is in use. Populate the object from whatever artifact evidence the investigation actually produced (hashes from Amcache, per note 06; IPs/accounts from note 12):

```powershell
[PSCustomObject]@{ Date = Get-Date; Type = 'SHA1'; Value = '<hash>'; Source = 'Amcache'; Incident = 'INC-1234' } |
    Export-Csv C:\hunt\ioc_tracker.csv -Append -NoTypeInformation
```

## Practical Walkthrough — How to Actually Use This Module

A realistic scenario showing the module working as an integrated system, not a pile of independent artifact references:

```
1. ALERT: suspicious PowerShell activity on a workstation
        │
        ▼
2. Pull PowerShell Script Block Logging (Event ID 4104)
   → Event Log Analysis (11), Specialized Operational Logs section
        │
        ▼
3. Malicious? → pivot two directions in parallel:
        │
        ├─► Execution evidence: what else did this process run/spawn?
        │   → Evidence of Program Execution (06) — Prefetch/ShimCache/Amcache/BAM-DAM
        │
        └─► Persistence check: did it establish a foothold?
            → Persistence Mechanisms (10) — Autostart keys, Services,
              Scheduled Tasks, WMI Event Consumers, DLL Hijacking
        │
        ▼
4. Build a timeline correlating everything found so far
   → Timeline Analysis (18)
        │
        ▼
5. Check whether the attacker tried to cover tracks
   → Anti-Forensics and Evidence Destruction (19) — timestomping,
     log clearing, VSC/UsnJrnl deletion
        │
        ▼
6. Place every finding on the Kill Chain table above — what stage(s)
   does the evidence collectively represent? What does that imply
   about stages NOT yet found evidence for (e.g., found Installation +
   evidence pointing at Actions on Objectives — go look harder for
   Lateral Movement (12) evidence on other hosts before assuming
   containment is scoped correctly)
        │
        ▼
7. Scope determined → proceed to Remediation and Containment (21,
   forthcoming); feed IOCs/TTPs back into threat intel per the loop above
```

The step that separates a thorough analyst from a fast one is step 6 — resisting the urge to stop at "found persistence, ticket closed" and instead asking what the kill-chain placement implies is still unaccounted for. A host showing Installation-stage evidence almost never represents the full scope of a fleet intrusion; the kill-chain table exists specifically to prompt "what should I be looking for next, on which other hosts."

## Red Flags — Process Pitfalls

This note is process/methodology rather than artifact-specific, so its Red Flags table is reframed as **analyst-process mistakes** rather than host-evidence indicators — the mistakes most likely to produce an incomplete or wrong investigation even when every individual artifact was read correctly.

| 🔴 Pitfall | Why it matters |
|---|---|
| Concluding from a single artifact without corroboration | Every "evidence of execution" artifact in note 06 has known false-positive/absence modes (e.g., ShimCache presence ≠ execution) — see note 18's corroboration-pattern content for why a timeline needs multiple independently-sourced artifacts agreeing before a finding is treated as solid |
| Skipping hypothesis formation, doing unfocused "look at everything" hunting | Without a specific hypothesis pointing at a bounded evidence set, a hunt has no way to know when it's done, wastes time on low-yield artifacts, and — counterintuitively — is *more* likely to miss a real finding buried in noise than a focused hunt would be |
| Finding an artifact and not mapping it to a kill-chain/ATT&CK stage | Loses the strategic picture: what does the attacker still have access to, what's their likely next move, is the current containment scope even complete — see the Practical Walkthrough's step 6 |
| Treating containment as complete after finding one host's persistence mechanism | The kill-chain table's Actions on Objectives row (lateral movement) exists precisely because a single-host finding rarely represents full scope — always check note 12 evidence before declaring scope closed |
| Not feeding findings back into threat intel for future hunts | Throws away half the value of the investigation — the next hunt starts from zero instead of a stronger hypothesis (see the Threat Intel feedback loop above) |
| Treating the kill chain and ATT&CK as competing frameworks rather than complementary ones | Leads to either an under-detailed report (kill-chain-only, no technique specificity for detection engineering) or an over-detailed one that loses the narrative arc a stakeholder needs (ATT&CK-only) |

## Tooling

This note is conceptual/process rather than artifact-specific, so this table stays intentionally short — the real tooling for *executing* on this methodology lives in the artifact-specific notes already covered throughout this module (EvtxECmd, the Eric Zimmerman suite, KAPE, Sysmon, etc. — see each note's own Tooling section).

| Tool | Use |
|---|---|
| **MITRE ATT&CK Navigator** | Official web tool (attack.mitre.org/resources/navigator) for visualizing and tracking ATT&CK technique coverage — useful for marking which techniques an investigation has confirmed evidence for, and for planning hypothesis-driven hunts against technique gaps not yet checked |
| **Threat-intel platform (category)** | Organizations vary widely here — a dedicated TIP/MISP-style indicator-management platform, a SIEM's built-in threat-intel module, or a simple internal tracked indicator list all serve the same function described in the feedback-loop section: durable storage for IOCs/TTPs an investigation produces, queryable by future hunts |
| **Everything else** | See each artifact note's own Tooling section — EvtxECmd and the Eric Zimmerman suite (note 11 and throughout), KAPE (note 02), Sysmon (note 12's Tooling section) |

## Correlate With

This is one of the densest Correlate With tables in the module by design — this note's role is connective tissue across nearly everything else.

| To go deeper on… | Open |
|---|---|
| Single-host process-tree baseline ("Know Normal"), the prerequisite for anomaly-based hunting | **Windows OS Fundamentals & Versions (01)** |
| Execution evidence — the primary "Installation"/"Exploitation" kill-chain evidence family | **Evidence of Program Execution (06)** |
| Full persistence-mechanism evidence — the primary "Installation" kill-chain evidence | **Persistence Mechanisms (10)** — all five sub-notes |
| Broad kill-chain-stage evidence source (C2, credential use, session activity) | **Event Log Analysis (11)** |
| "Actions on Objectives" kill-chain evidence — lateral movement, pass-the-hash/ticket | **Lateral Movement (12)** |
| Likely initial-access / "Delivery" vectors | **Web Browser Forensics (14)**, **Email Forensics (15)** |
| Building the investigation narrative this note's kill-chain reasoning gets applied to | **Timeline Analysis (18)** |
| What the attacker is trying to hide — feeds this note's "what stage are they really at" reasoning | **Anti-Forensics and Evidence Destruction (19)** |
| Executing on containment/eradication/recovery once scope is determined here | **Remediation and Containment (21, forthcoming)** |
| Baselining — the prerequisite for anomaly-based hunting at fleet scale | **Enterprise Management and Baseline (22, forthcoming)** |
| Full, granular ATT&CK-technique-to-evidence mapping table (this note only explains the framework concept) | **ATT&CK Windows to Evidence Map (00b, forthcoming)** — this note explicitly feeds that one |

## Resources

- SANS FOR508 Section 1 (IR process, threat hunting concepts, kill chain, ATT&CK) — coverage checklist only, per the bundled `SANS_DFPS_FOR508_v4.11_0624.pdf` and `FOR508 Index Suvas Final.xlsx`; original prose throughout this note, no verbatim reproduction
- Lockheed Martin Cyber Kill Chain — https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html
- MITRE ATT&CK — https://attack.mitre.org/
- MITRE ATT&CK Navigator — https://attack.mitre.org/resources/navigator/
- SANS Incident Handler's Handbook and related SANS/NIST IR-lifecycle publications — generic reference for the Preparation → Identification → Containment → Eradication → Recovery → Lessons Learned model
