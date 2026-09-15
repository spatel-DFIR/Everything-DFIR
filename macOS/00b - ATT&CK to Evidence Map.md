# ATT&CK to Evidence Map

Reverse lookup for incident response: given an adversary **technique** (from a threat report, EDR alert, or hypothesis), find **where the evidence lives in this vault**. Pairs with `00 - Cross-Artifact Correlation` (which goes the other way — goal → artifacts).

> ⚙️ **TRIAL (decide later):** this same matrix is also embedded inside `00 - Cross-Artifact Correlation.md` — on purpose, so you can compare keeping it **inline** (one master note) vs **standalone** (this file). Once you pick, delete the other copy. **Keep both in sync until then.**

> 🔴 Use it both directions: report says *"T1543.001"* → open the listed notes; you find a rogue LaunchAgent → tag the finding **T1543.001** in standard language. Verify IDs against current ATT&CK (macOS matrix); techniques evolve.

## Contents
- [Execution](#execution)
- [Persistence](#persistence)
- [Privilege Escalation](#privilege-escalation)
- [Defense Evasion](#defense-evasion)
- [Credential Access](#credential-access)
- [Discovery](#discovery)
- [Lateral Movement](#lateral-movement)
- [Collection](#collection)
- [Command and Control](#command-and-control)
- [Exfiltration](#exfiltration)

---

## Execution

| Technique (ID) | Evidence / notes |
|---|---|
| Unix Shell (T1059.004) | Shells and Command History; Unified Logs (process spawn) |
| AppleScript (T1059.002) | `osascript` in plists/shell history; Unified Logs |
| System Services: Launchctl (T1569.001) | launchd Unified Logs; Launch Daemons/Agents |
| User Execution: Malicious File (T1204.002) | Quarantine xattr; Gatekeeper logs; Program Execution Evidence |
| Native API (T1106) | Crash reports; Unified Logs |

---

## Persistence

| Technique (ID) | Evidence / notes |
|---|---|
| Launch Agent (T1543.001) | `~/Library` + `/Library/LaunchAgents`; launchd log; FSEvents (plist drop) |
| Launch Daemon (T1543.004) | `/Library/LaunchDaemons`; Privileged Helper Tools |
| Cron (T1053.003) / At (T1053.002) | `/usr/lib/cron/tabs`; `/var/at/jobs`; cron log |
| Login Items (T1547.015) | BTM `sfltool dumpbtm`; Login Items |
| Login Hook (T1037.002) | `com.apple.loginwindow LoginHook`; Login Items |
| SSH Authorized Keys (T1098.004) | `~/.ssh/authorized_keys` mtime; sshd Accepted |
| Emond (T1546.014) | `/etc/emond.d/rules`; More Persistence |
| Unix Shell Config Mod (T1546.004) | `~/.zshrc`/`.zshenv`/`.bash_profile`; Shells |
| Kernel Modules / Extensions (T1547.006) | `kextstat`; System Extensions |
| Dylib Hijacking (T1574.004) | `otool -l` weak/rpath; Dylib Hijacking and Injection |
| Dynamic Linker Hijacking (T1574.006) | `DYLD_INSERT_LIBRARIES` in plists/shell; Dylib note |
| Create Account (T1136.001) | DSLocal; Users and Groups; loginwindow |
| Compromise Host Software Binary (T1554) | `codesign --verify`; Install Receipts BOM |
| Modify Auth Process (T1556) | PAM; Authorization Plugins (More Persistence) |

---

## Privilege Escalation

| Technique (ID) | Evidence / notes |
|---|---|
| Sudo and Sudo Caching (T1548.003) | sudo Unified Logs; `/etc/sudoers` (Users and Groups) |
| Create/Modify System Process (T1543) | Privileged Helper Tools; LaunchDaemons |
| Exploitation for Priv Esc (T1068) | Crash/panic reports; Unified Logs (AMFI/sandbox) |

---

## Defense Evasion

| Technique (ID) | Evidence / notes |
|---|---|
| Gatekeeper Bypass (T1553.001) | quarantine removed; `syspolicyd` override (Gatekeeper-TCC-XProtect) |
| Disable or Modify Tools (T1562.001) | firewall/Gatekeeper off; AV silent (App-specific Logs) |
| Clear Mac System Logs (T1070.002) | `log erase` tell (System & Kernel); ASL/`system.log` gaps (Legacy Logs) |
| File Deletion (T1070.004) | Trash; FSEvents `Removed`; unallocated carving |
| Timestomp (T1070.006) | MACB `create>modify` (File Systems); FSEvents vs file times |
| Hidden Files/Dirs (T1564.001) | leading-dot; `chflags hidden`; `ls -laO` (Permissions) |
| Hidden Users (T1564.002) | UID<500 / `IsHidden` (Users and Groups) |
| File Perms Modification (T1222.002) | `chmod`/`chflags` (Permissions) |
| Masquerading (T1036) | `com.apple.*` plist outside `/System/Library`; signature mismatch |
| Obfuscation / Deobfuscate (T1027 / T1140) | base64/`osascript` in plists & history |

---

## Credential Access

| Technique (ID) | Evidence / notes |
|---|---|
| Credentials from Keychain (T1555.001) | `login.keychain-db`; securityd unlocks (Advanced Auth); Users and Groups |
| Brute Force (T1110) | loginwindow / opendirectoryd / sshd failure bursts |
| Modify Auth Process (T1556) | PAM modules; Authorization Plugins |
| Unsecured Credentials (T1552) | shell history; config files; `/etc/kcpassword` (Users) |

---

## Discovery

| Technique (ID) | Evidence / notes |
|---|---|
| File and Directory Discovery (T1083) | Shell history; `mdfind`/`mdls`; Unified Logs |
| Process Discovery (T1057) | Shell history (`ps`); Unified Logs |
| Security Software Discovery (T1518.001) | Shell history; process listing |
| System Owner/User Discovery (T1033) | Shell history (`whoami`/`id`); Users and Groups |
| Browser Information Discovery (T1217) | (your dedicated browser-forensics project) |

---

## Lateral Movement

| Technique (ID) | Evidence / notes |
|---|---|
| Remote Services: SSH (T1021.004) | sshd Accepted + source IP (Advanced Auth); authorized_keys |
| Remote Services: VNC (T1021.005) | `screensharingd` / ARD (Wi-Fi and Network) |
| Internal Spearphishing / Tools | Messages and Mail; App-specific Logs |

---

## Collection

| Technique (ID) | Evidence / notes |
|---|---|
| Data from Local System (T1005) | FSEvents; Program Execution Evidence; Messages and Mail |
| Input Capture: Keylogging (T1056.001) | TCC Accessibility grant (Gatekeeper-TCC-XProtect) |
| Screen Capture (T1113) | TCC Screen Recording grant |
| Audio Capture (T1123) | TCC Microphone grant |
| Clipboard Data (T1115) | (limited native artifact) |
| Archive Collected Data (T1560) | FSEvents (archive created); shell history (`zip`/`tar`) |

---

## Command and Control

| Technique (ID) | Evidence / notes |
|---|---|
| Application Layer Protocol (T1071) | Little Snitch/LuLu (App-specific); firewall; Wi-Fi/Network logs |
| Ingress Tool Transfer (T1105) | quarantine where-from; FSEvents `Created`; `curl` in history |
| Proxy (T1090) | `scutil --proxy`; configd proxy logs (Firewalls and Proxies) |

---

## Exfiltration

| Technique (ID) | Evidence / notes |
|---|---|
| Exfiltration Over USB (T1052.001) | USB & Device History; on-media `.fseventsd`/`.Trashes` |
| Exfiltration to Cloud Storage (T1567.002) | Wi-Fi/Network logs; App-specific; browser project |
| Email Collection / Exfil (T1114) | Messages and Mail (auto-forward rules, attachments) |

---

> This is the reverse index. For goal-driven playbooks (deleted file, app execution, exfil, etc.) and the timestamp-epoch reference, see `00 - Cross-Artifact Correlation`.
