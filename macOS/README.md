# macOS DFIR Field Reference

Hands-on reference for macOS forensics and incident response — covers OS fundamentals, Unified Logs, filesystem/security mechanisms (TCC/SIP/FileVault), persistence, and artifacts. Every note opens with Quick Triage (native bash/log stream commands), then deepens through evidence interpretation and hunting.

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Start with [`00 - Cross-Artifact Correlation`](<00 - Cross-Artifact Correlation.md>) — pick your investigative goal (app execution, exfil, persistence, anti-forensics) and it tells you which notes to open in order. [`00b - ATT&CK to Evidence Map`](<00b - ATT&CK to Evidence Map.md>) is the reverse lookup (MITRE technique → evidence location).

**Common Scenarios — which notes to open:**

| Scenario | Start With | Then Read |
|----------|-----------|-----------|
| **Suspected persistence / backdoor** | [Persistence Mechanisms](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>) | LaunchDaemons/Agents, Cron, Login Items, System Extensions, [Unified Logs](<09 - Unified Logs/System and Kernel Events.md>) |
| **Application execution timeline** | [Program Execution Evidence](<11 - Artifacts/Program Execution Evidence.md>) | [Unified Logs](<09 - Unified Logs/System and Kernel Events.md>), [FSEvents](<11 - Artifacts/File System Events (FSEvents).md>), [knowledgeC.db](<11 - Artifacts/knowledgeC.db.md>) |
| **Malware / infostealer incident** | [ClickFix & Infostealer Playbook](<17 - Threat Landscape and Playbooks/ClickFix and Infostealer Playbook.md>) | [App & Container Data](<11 - Artifacts/Application and Container Data.md>), [Messages/Mail](<11 - Artifacts/Messages and Mail.md>), [Cloud Storage](<11 - Artifacts/Cloud Storage and Sync.md>) |
| **Supply-chain / trojanized app** | [DPRK Fake-Job Playbook](<17 - Threat Landscape and Playbooks/DPRK Fake-Job and Contagious Interview Playbook.md>) | [App Data](<11 - Artifacts/Application and Container Data.md>), [Install History](<11 - Artifacts/Install History and Receipts.md>), [Quarantine](<11 - Artifacts/Download Provenance and Quarantine.md>) |
| **Anti-forensics / evidence destruction** | [Unified Logs - System Events](<09 - Unified Logs/System and Kernel Events.md>) | [Trash](<11 - Artifacts/Trash.md>), [FSEvents](<11 - Artifacts/File System Events (FSEvents).md>), [Spotlight](<11 - Artifacts/Spotlight.md>) |
| **Timeline reconstruction** | [Program Execution Evidence](<11 - Artifacts/Program Execution Evidence.md>) | [Plaso/Log2Timeline](<14 - Timelining/Plaso (Log2Timeline).md>), [UAC & mactime](<14 - Timelining/UAC and mactime.md>) |

**Tip:** Use GitHub anchors to jump within notes; in Obsidian, use the **Outline** panel.

---

## How This Platform Is Organized

**Core Concepts (01–08):** macOS fundamentals, permissions, users, shells, and security mechanisms (SIP, TCC, XProtect, FileVault).

**Unified Logs (09):** The primary evidence source for macOS investigations — log architecture, subsystem navigation, and how to extract signals from high-volume logging.

**Filesystems (10):** HFS+, APFS, and exFAT internals — structure, deleted-file recovery, and forensic implications.

**Artifacts (11):** 14 distinct artifact families from .DS_Store to cloud storage, covering execution evidence, persistence indicators, user activity, and exfiltration footprints.

**Persistence Mechanisms (12):** 8 persistence families with hunting commands — LaunchDaemons/Agents, cron, login items, system extensions, SSH keys, dylib hijacking.

**Live Response & Timelining (13–14):** Evidence collection methodologies, memory acquisition, and super-timeline creation (UAC, Plaso).

**Remediation (16):** Enterprise IR eradication — persistence removal, MDM/profile handling, root CA cleanup, SSO/token revocation, fleet scoping.

**Threat Playbooks (17):** End-to-end scenarios (ClickFix infostealers, DPRK trojanized apps) synthesizing evidence from multiple sections.

**Enterprise Management (18):** MDM state, configuration profiles, managed preferences, and baseline artifacts.

---

## Module Status

- ✅ **In Depth:** 68 markdown files across 18 sections; persistence hunter script (v1.0); playbooks for ClickFix infostealer and DPRK trojanization; macOS package managers & .app bundle forensics
- 🟡 **Evolving:** Enterprise management baselines expanding; cloud-sync artifacts deepening
- ⏳ **Deferred:** Advanced EDR evasion detection, fuzzing-based vulnerability hunting

---

## Module Structure

```
macOS/ (68 files total)
├── README.md (182 lines) ⭐ START HERE
│   ├── Quick Navigation Table (6 scenarios)
│   ├── Scope Clarity (7 section categories)
│   └── Module Status & Contents
├── 00 - Cross-Artifact Correlation.md (293 lines) ⭐ ENTRY POINT
│   └── Goal-driven playbook & timestamp epochs
├── 00b - ATT&CK to Evidence Map.md (149 lines)
│   └── MITRE Technique → Evidence lookup
├── 01–08 - Core macOS Fundamentals (2–4 KB each)
│   └── Root structure, permissions, users, shells, SIP, TCC, XProtect, FileVault
├── 09 - Unified Logs/
│   ├── System and Kernel Events, Authentication, Firewalls, Wi-Fi, Bluetooth
│   ├── Gatekeeper, TCC, XProtect, Crash Reporting, Application-specific
│   └── Focus: Primary macOS evidence source
├── 10 - macOS File Systems/
│   └── HFS+, APFS, exFAT internals and forensic implications
├── 11 - Artifacts/
│   ├── .DS_Store, Trash, FSEvents, Spotlight, Quick Look, Recent Items
│   ├── knowledgeC.db, App Data, Messages, Mail, Cloud Storage
│   ├── Download Provenance, Install History, Package Managers, .app Bundle Structure
│   └── Focus: User activity & execution evidence
├── 12 - Persistence Mechanisms/
│   └── LaunchDaemons/Agents, Cron, Login Items, System Extensions, dylib Hijacking, SSH Keys
├── 13–14 - Live Response & Timelining/
│   └── Evidence collection, memory acquisition, Plaso, UAC, timeline creation
├── 16 - Remediation and Containment/ (1 file, 10+ KB)
│   └── Enterprise IR eradication workflow
├── 17 - Threat Landscape and Playbooks/
│   └── ClickFix Infostealer, DPRK Fake-Job, Threat Landscape
├── 18 - Enterprise Management/ (1 file, 8+ KB)
│   └── MDM state, profiles, managed preferences
├── macOS Posters/ (5 PDFs)
│   └── SANS & community reference materials (see README.md in folder)
└── Scripts/ (3 files)
    └── Persistence hunter, IR response scripts
```

---

## Contents

### Start Here
- [00 - Cross-Artifact Correlation](<00 - Cross-Artifact Correlation.md>) — timestamp epochs, volume-artifact checklist, ATT&CK matrix, and goal-driven case playbooks
- [00b - ATT&CK to Evidence Map](<00b - ATT&CK to Evidence Map.md>) — MITRE technique → evidence (reverse lookup)

### Core macOS
- [01 - macOS Root Directory Structure](<01 - macOS Root Directory Structure.md>)
- [02 - File and Directory Permissions](<02 - File and Directory Permissions.md>) — POSIX, BSD flags, ACLs, xattrs, `stat`, timestomping
- [03 - Users and Groups](<03 - Users and Groups.md>) — DSLocal, ShadowHashData, Keychain, Secure Token
- [04 - Shells and Command History](<04 - Shells and Command History.md>)
- [05 - System Integrity Protection (SIP)](<05 - System Integrity Protection (SIP).md>)
- [06 - Transparency, Consent, and Control (TCC)](<06 - Transparency Consent and Control (TCC).md>)
- [07 - XProtect](<07 - XProtect.md>)
- [08 - FileVault](<08 - FileVault.md>)

### 09 - Unified Logs
- [System and Kernel Events](<09 - Unified Logs/System and Kernel Events.md>) — `log` mechanics, kexts, AMFI, boot/power, anti-forensics
- [Authentication and Security](<09 - Unified Logs/Authentication and Security.md>)
- [Advanced Authentication and Security](<09 - Unified Logs/Advanced Authentication and Security.md>)
- [Firewalls and Proxies](<09 - Unified Logs/Firewalls and Proxies.md>)
- [Wi-Fi and Network](<09 - Unified Logs/Wi-Fi and Network.md>)
- [Bluetooth](<09 - Unified Logs/Bluetooth.md>)
- [Gatekeeper, TCC, and XProtect](<09 - Unified Logs/Gatekeeper, TCC, and XProtect.md>)
- [Crash Reporting](<09 - Unified Logs/Crash Reporting.md>)
- [Legacy Logs](<09 - Unified Logs/Legacy Logs.md>)
- [Application-specific Logs](<09 - Unified Logs/Application-specific Logs.md>)
- [Additional Topics and Tools](<09 - Unified Logs/Additional Topics and Tools.md>) — Spotlight, auditd/OpenBSM, GUI tools

### 10 - macOS File Systems
- [HFS+](<10 - macOS File Systems/HFS+.md>)
- [APFS](<10 - macOS File Systems/APFS.md>)
- [exFAT](<10 - macOS File Systems/exFAT.md>)

### 11 - Artifacts
- [.DS_Store](<11 - Artifacts/DS_Store.md>)
- [Trash](<11 - Artifacts/Trash.md>)
- [File System Events (FSEvents)](<11 - Artifacts/File System Events (FSEvents).md>)
- [Spotlight](<11 - Artifacts/Spotlight.md>)
- [Quick Look Thumbnails](<11 - Artifacts/Quick Look Thumbnails.md>)
- [Recent Items and SharedFileList](<11 - Artifacts/Recent Items and SharedFileList.md>)
- [knowledgeC.db](<11 - Artifacts/knowledgeC.db.md>)
- [Biome](<11 - Artifacts/Biome.md>)
- [Program Execution Evidence](<11 - Artifacts/Program Execution Evidence.md>)
- [Download Provenance and Quarantine](<11 - Artifacts/Download Provenance and Quarantine.md>) — `com.apple.quarantine` xattr + `QuarantineEventsV2` DB: where a file came from, what downloaded it, when (macOS Mark-of-the-Web)
- [Application and Container Data](<11 - Artifacts/Application and Container Data.md>) — the five app-data homes, sandbox Containers / Group Containers, saved state; where app tokens/recent files live
- [Application Bundle (.app) Structure and Forensic Analysis](<11 - Artifacts/Application Bundle (.app) Structure and Forensic Analysis.md>) — `.app` directory structure, Info.plist metadata, code signatures, entitlements, detecting tampered/malicious bundles; how to extract and analyze app contents
- [Messages and Mail](<11 - Artifacts/Messages and Mail.md>)
- [USB and External Device History](<11 - Artifacts/USB and External Device History.md>)
- [Install History and Receipts](<11 - Artifacts/Install History and Receipts.md>)
- [Package Managers and Installation Forensics](<11 - Artifacts/Package Managers and Installation Forensics.md>) — Homebrew, MacPorts, native `.pkg` installer forensics; installation timelines, dependency chains, supply-chain compromise detection, cross-platform correlation with Windows package managers
- [Cloud Storage and Sync](<11 - Artifacts/Cloud Storage and Sync.md>) — iCloud/OneDrive/Google Drive/Dropbox/Box local DBs, logs & `CloudStorage/` tree: exfil evidence + account/tenant identity
- [mac_apt Artifact Parser](<11 - Artifacts/mac_apt Artifact Parser.md>) — bulk parser; also covers Notifications, Accounts, iOS Backups, Document Revisions

### 12 - Persistence Mechanisms
- [Launch Daemons and Launch Agents](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>)
- [Privileged Helper Tools](<12 - Persistence Mechanisms/Privileged Helper Tools.md>)
- [Cron Jobs](<12 - Persistence Mechanisms/Cron Jobs.md>)
- [Login Items](<12 - Persistence Mechanisms/Login Items.md>)
- [System Extensions](<12 - Persistence Mechanisms/System Extensions.md>)
- [SSH Keys](<12 - Persistence Mechanisms/SSH Keys.md>)
- [Dylib Hijacking and Injection](<12 - Persistence Mechanisms/Dylib Hijacking and Injection.md>)
- [More Persistence Mechanisms](<12 - Persistence Mechanisms/More Persistence Mechanisms.md>) — emond, auth plugins, folder actions, at/periodic, profiles

### 13 - Evidence Collection
- [Unified Logs Collection](<13 - Evidence Collection/Unified Logs Collection.md>)
- [Fuji](<13 - Evidence Collection/Fuji.md>)
- [Unix-like Artifacts Collector (UAC)](<13 - Evidence Collection/Unix-like Artifacts Collector (UAC).md>)
- [Acquiring Memory](<13 - Evidence Collection/Acquiring Memory.md>)

### 14 - Timelining
- [UAC and mactime](<14 - Timelining/UAC and mactime.md>)
- [Plaso (Log2Timeline)](<14 - Timelining/Plaso (Log2Timeline).md>)

### 15 - Live Response
- [Live Response and Volatile Data](<15 - Live Response and Volatile Data.md>) — the run-first commands: processes, open files (`lsof`), network connections, loaded kernel/system extensions, logged-in users, mounts, and live software inventory (`brew list`, `pkgutil`, `system_profiler`)
- [15b - Process Trees and Execution Lineage](<15b - Process Trees and Execution Lineage.md>) — reference process trees for classifying an alerted process: LaunchDaemon vs LaunchAgent vs user-launched vs cron/SSH/macro/browser, why `PPID 1` is ambiguous on macOS, and how `launchctl procinfo` (domain + plist + responsible pid) settles it

### 16 - Remediation
- [Remediation and Containment](<16 - Remediation and Containment.md>) — complete enterprise IR eradication/recovery: killing a payload without `KeepAlive` re-spawn, step-by-step removal of every persistence foothold, **handling config profiles & MDM** (manual vs MDM-pushed vs rogue enrollment), **removing malicious root CAs & proxies**, account remediation, **SSO session/token revocation & MFA reset** at the IdP, EDR coordination + fleet IOC scoping, restoring SIP/Gatekeeper/firewall, verify-with-reboot, and network isolation as an EDR fallback

### 17 - Threat Landscape and Playbooks
- [macOS Malware and Threat Landscape](<17 - Threat Landscape and Playbooks/macOS Malware and Threat Landscape.md>) — the families you meet on enterprise Macs (infostealers/AMOS, adware, DPRK/Lazarus, ransomware), their delivery vectors and hiding spots, the shared LOLbin toolkit (`osascript`/`curl`/`security`/`xattr`) mapped to ATT&CK, and a hunting playbook
- [ClickFix and Infostealer Playbook](<17 - Threat Landscape and Playbooks/ClickFix and Infostealer Playbook.md>) — end-to-end scenario for the #1 macOS initial-access technique (fake CAPTCHA → paste-and-run → AMOS-class stealer): per-stage identification, scoping what was stolen, timeline, eradication, and the credential/session reset that actually ends it
- [DPRK Fake-Job and Contagious Interview Playbook](<17 - Threat Landscape and Playbooks/DPRK Fake-Job and Contagious Interview Playbook.md>) — North-Korea developer targeting (BeaverTail → InvisibleFerret, trojanized interview apps): identification, **dev-secret & supply-chain scoping**, eradication, credential/CI-CD reset, and org-wide hunt

### 18 - Enterprise Management
- [Enterprise Management Artifacts](<18 - Enterprise Management Artifacts.md>) — MDM enrollment state, configuration profiles & payloads (certs/proxies/PPPC/pushed daemons), managed preferences, management agents (Jamf/Intune/Munki/Kandji/…), enterprise SSO & AD binding, trust certs, FileVault key escrow — the "expected vs attacker-added" baseline

### Scripts
- [`scripts/`](scripts/README.md) — **usage guide** for the read-only triage scripts (modes, options, severity tiers, FLAGS + ATT&CK reference).
- [`scripts/hunt_persistence.sh`](scripts/hunt_persistence.sh) — all-in-one persistence hunter across every documented macOS persistence surface (13 modules) with severity-ranked (HIGH/NOTABLE/LOW) findings; `quick`/`deep` modes, opt-in Gatekeeper checks. Non-destructive, console-only, read-only.
- [`scripts/archived/hunt_launchd.sh`](scripts/archived/hunt_launchd.sh) — *(archived)* original focused Launch Agent/Daemon triage, now superseded by the `launchd` module of `hunt_persistence.sh`. See [`scripts/archived/`](scripts/archived/README.md).

### Reference Cheat Sheets (PDF)
- [macOS Core Forensic Artifacts](<macos_core_forensic_artifacts_cheat_sheet.pdf>)
- [macOS Extended Attributes](<macos_extended_attributes_cheat_sheet.pdf>)
- [macOS Unified Log](<macos_log_cheat_sheet.pdf>)
- [APFS CheatSheet](<SANS_DFPSFOR5180924.pdf>)

---

## Conventions & Voice

- **Quick Triage** block first — native bash/log commands for immediate hypothesis testing; deeper context follows
- 🔴 marks high-value / red-flag items — easily missed indicators or high-confidence evidence
- Commands are blank-line separated; tables explain what output means and how to interpret it
- MITRE ATT&CK technique IDs are tagged per note (verify against current macOS matrix)
- macOS version deltas (Big Sur / Monterey / Ventura / Sonoma) are called out where they change commands or artifact locations
- Named tools are first-class: Unified Log, mac_apt, UAC, Fuji, Plaso (Log2Timeline)

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify artifact behavior against the specific macOS version in front of you — paths, log formats, and security mechanisms evolve.
- **Built from macOS internals research and public DFIR sources.** Not affiliated with or endorsing any vendor or training provider.
- **Scope:** Host-level macOS forensics and IR. Mobile/iOS forensics are out of scope. Container forensics live in [Container/](../Container/README.md).

---

## License

The notes in this repository are released under the [MIT License](../LICENSE). Bundled third-party reference PDFs (SANS and community cheat sheets, posters) remain under their original authors' copyright and terms.
