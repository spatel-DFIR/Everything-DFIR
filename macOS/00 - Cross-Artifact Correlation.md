# Cross-Artifact Correlation

A **playbook** view of the vault: pick the investigative **goal** (or an attacker **technique**), get the **artifacts to pull and the order** to combine them. No single macOS artifact tells the whole story — deletion time comes from one, original path from another, "where it came from" from a third. This note maps goals → sources and **MITRE ATT&CK** techniques → evidence; the detailed commands live in each topic note.

> 🔴 Golden rule: **one artifact = a lead; corroborated artifacts = a finding.** Build every timeline from ≥2 independent sources, and watch the epochs (below) so times actually line up.

> ⚙️ **TRIAL (decide later):** the **ATT&CK Technique → Evidence** matrix below also exists standalone in **`00b - ATT&CK to Evidence Map.md`** — on purpose, so you can compare the *all-in-one* (this note) vs the *split* layout. Once you pick a layout, delete the other copy. **Keep the two matrices in sync until then.**

## Contents
- [Timestamp Epochs and Conversions](#timestamp-epochs-and-conversions)
- [Volume Artifacts to Always Collect](#volume-artifacts-to-always-collect)
- [ATT&CK Technique to Evidence](#attck-technique-to-evidence)
- [Deleted File Investigation](#deleted-file-investigation)
- [Application Execution Timeline](#application-execution-timeline)
- [User Presence at the Machine](#user-presence-at-the-machine)
- [Data Exfiltration to Removable Media](#data-exfiltration-to-removable-media)
- [Download to Execution Chain](#download-to-execution-chain)
- [Persistence Sweep](#persistence-sweep)
- [Remote Access and Lateral Movement](#remote-access-and-lateral-movement)
- [Dylib Hijacking and Injection](#dylib-hijacking-and-injection)
- [Trojanized or Cracked App](#trojanized-or-cracked-app)
- [Insider Data Theft](#insider-data-theft)
- [Living off the Land](#living-off-the-land)
- [Anti-Forensics and Tampering](#anti-forensics-and-tampering)

---

## Timestamp Epochs and Conversions

🔴 Different artifacts use different epochs — **convert everything to UTC** before correlating.

| Source | Epoch / format | Convert to Unix/UTC |
|---|---|---|
| **APFS**, Unix `stat`, FSEvents (file times) | 1970-01-01, nanosecond | native |
| **HFS+** catalog | 1904-01-01, 1-second | TSK/`stat` handle it (catalog=UTC, volume header=local) |
| **Cocoa / Mac Absolute** — knowledgeC, Safari, plists, `.DS_Store`, `chat.db` | 2001-01-01 | **`+ 978307200`** (chat.db: `date/1000000000 + 978307200`) |
| **exFAT** | local time + UTC-offset field; 2 s (10 ms create/mod) | verify the offset; beware Win vs Mac writers |
| **Unified Log** | stored UTC, shown local | `log show --timezone "UTC"` |
| **FSEvents** (timing) | **no per-event timestamp** | order by event ID; approx time = log-file window |

> The classic mistake: comparing a knowledgeC time (2001 epoch) against a `stat` time (1970 epoch) without converting — a 31-year skew.

---

## Volume Artifacts to Always Collect

Grab these from **every** volume (boot **and** each external/USB) — they're per-volume and prove what happened on that media:

| Artifact | Note | Gives |
|---|---|---|
| `.fseventsd/` (boot = `/System/Volumes/Data/.fseventsd/`) | FSEvents | File create/delete/rename history (incl. deleted paths) |
| `.DS_Store` (every folder) | .DS_Store | Folders browsed in Finder + item names |
| `.Trashes/<UID>/` | Trash | What a user deleted on that volume + deletion time |
| `._*` (AppleDouble) | exFAT / File Permissions | xattrs/quarantine on non-native FS |
| `.Spotlight-V100/` | Additional Topics | Metadata index |

---

## ATT&CK Technique to Evidence

🔴 Reverse lookup — adversary technique → **where the evidence lives in this vault**. (macOS-relevant subset; verify IDs against current ATT&CK.)

| Tactic | Technique (ID) | Evidence / notes |
|---|---|---|
| Execution | Unix Shell (T1059.004) | Shells & Command History; Unified Logs |
| Execution | AppleScript (T1059.002) | `osascript` in plists/history; Unified Logs |
| Execution | Launchctl (T1569.001) | launchd Unified Logs; Launch Daemons/Agents |
| Execution | Malicious File (T1204.002) | Quarantine xattr; Gatekeeper logs; Program Execution Evidence |
| Persistence | Launch Agent (T1543.001) | `~/Library` + `/Library/LaunchAgents`; launchd log; FSEvents |
| Persistence | Launch Daemon (T1543.004) | `/Library/LaunchDaemons`; Privileged Helper Tools |
| Persistence | Cron (T1053.003) / At (T1053.002) | `/usr/lib/cron/tabs`; `/var/at/jobs`; cron log |
| Persistence | Login Items (T1547.015) | BTM `sfltool dumpbtm`; Login Items |
| Persistence | Login Hook (T1037.002) | `com.apple.loginwindow LoginHook`; Login Items |
| Persistence | SSH Authorized Keys (T1098.004) | `~/.ssh/authorized_keys` mtime; sshd Accepted |
| Persistence | Emond (T1546.014) | `/etc/emond.d/rules`; More Persistence |
| Persistence | Shell Config Mod (T1546.004) | `~/.zshrc`/`.zshenv`; Shells |
| Persistence | Kernel Modules/Extensions (T1547.006) | `kextstat`; System Extensions |
| Persistence | Dylib Hijacking (T1574.004) / Dyld (T1574.006) | `otool -l`; `DYLD_*` in plists; Dylib note |
| Persistence | Create Account (T1136.001) | DSLocal; Users and Groups; loginwindow |
| Persistence | Compromise Host Binary (T1554) | `codesign --verify`; Install Receipts BOM |
| Priv Esc | Sudo / Caching (T1548.003) | sudo logs; sudoers (Users) |
| Defense Evasion | Gatekeeper Bypass (T1553.001) | quarantine removed; `syspolicyd` override |
| Defense Evasion | Disable/Modify Tools (T1562.001) | firewall/Gatekeeper off; AV silent (App-specific) |
| Defense Evasion | Clear Mac Logs (T1070.002) | `log erase` tell; ASL/`system.log` gaps |
| Defense Evasion | File Deletion (T1070.004) | Trash; FSEvents `Removed`; carving |
| Defense Evasion | Timestomp (T1070.006) | MACB `create>modify`; FSEvents vs file times |
| Defense Evasion | Hidden Files/Users (T1564.001/.002) | leading-dot/`chflags hidden`; UID<500/IsHidden |
| Defense Evasion | Modify Auth Process (T1556) | PAM; Authorization Plugins (More Persistence) |
| Credential Access | Keychain (T1555.001) | `login.keychain-db`; securityd unlocks; Users |
| Credential Access | Brute Force (T1110) | loginwindow/opendirectoryd/sshd fail bursts |
| Discovery | File/Dir, Security SW (T1083/T1518.001) | Shell history; process listing |
| Lateral Movement | SSH (T1021.004) | sshd Accepted; authorized_keys |
| Lateral Movement | VNC/Screen Sharing (T1021.005) | `screensharingd`/ARD (Wi-Fi and Network) |
| Collection | Local Data (T1005) | FSEvents; Program Execution; Messages and Mail |
| Collection | Keylog/Screen (T1056.001/T1113) | TCC Accessibility / Screen Recording grants |
| C2 | App Layer Protocol (T1071) | Little Snitch/LuLu; firewall; network logs |
| C2 | Ingress Tool Transfer (T1105) | quarantine where-from; FSEvents `Created` |
| Exfiltration | Over USB (T1052.001) | USB & Device History; on-media FSEvents |
| Exfiltration | To Cloud/Email (T1567/T1114) | network logs; Messages and Mail; App-specific |

---

## Deleted File Investigation

**ATT&CK:** File Deletion (T1070.004) · Indicator Removal

| Order | Source (note) | What it gives |
|---|---|---|
| 1 | **Trash** — `ctime` | **When** it was deleted |
| 2 | **Trash** — Put-Back `ptbL`/`ptbN` | **Original path + name** |
| 3 | **FSEvents** — `Removed`/`Renamed` | Corroborate the deletion event |
| 4 | **.DS_Store** of the source folder | Confirms the file was present |
| 5 | **quarantine / `kMDItemWhereFroms`** | Where the file came from |
| 6 | Unallocated carving (File Systems) | Recover content if Trash emptied |

---

## Application Execution Timeline

**ATT&CK:** Unix Shell (T1059.004) · Malicious File (T1204.002)

| Source (note) | What it gives |
|---|---|
| **Program Execution Evidence** | The consolidated map (start here) |
| **knowledgeC.db** / **Biome** | App usage + duration |
| **Spotlight** `kMDItemLastUsedDate`/`UseCount` | Last opened + run count |
| **Unified Logs** (launchd, AMFI) | Spawn + code-sign checks |
| **Gatekeeper/XProtect** logs | Allowed / flagged at launch |
| **TCC** + **crash reports** | Indirect proof it ran |

---

## User Presence at the Machine

🔴 "Was a human physically at the Mac at time T?"

| Source (note) | What it gives |
|---|---|
| **Unified Logs – Authentication** (loginwindow) | Login / logout / **screen unlock** |
| **knowledgeC.db** `/device/isLocked`,`/display/isBacklit` | Lock/unlock + screen on/off |
| **Unified Logs – Bluetooth** (`wirelessproxd`) | **Apple Watch auto-unlock** = owner present |
| **knowledgeC** `/media/nowPlaying` | Active media use |
| `last` / utmpx | Console vs remote session |

---

## Data Exfiltration to Removable Media

**ATT&CK:** Exfiltration Over USB (T1052.001)

| Source (note) | What it gives |
|---|---|
| **USB & External Device History** | Device attach + serial |
| **exFAT** artifacts (`._*`,`.DS_Store`,`.Trashes`,`.fseventsd`) on `/Volumes/USB` | A Mac wrote/browsed it |
| **FSEvents** of the USB | Files created/copied/deleted on it |
| **Unified Logs** (USB attach) | When plugged in |
| **quarantine / where-from** on copied files | On-Mac source |

---

## Download to Execution Chain

**ATT&CK:** Ingress Tool Transfer (T1105) · Malicious File (T1204.002) · Gatekeeper Bypass (T1553.001)

| Stage | Source (note) |
|---|---|
| Downloaded | **quarantine** + `kMDItemWhereFroms` → source URL |
| Allowed to run | **Gatekeeper** (`syspolicyd`) assess/deny/override |
| Known-bad? | **XProtect** detection/remediation |
| Dropped on disk | **FSEvents** `Created` (`/tmp`, `~/Library`) |
| Executed | **knowledgeC/Biome**, **Unified Logs** |
| Gained permissions | **TCC** grants (FDA/Accessibility/Screen) |
| Persisted | Launch Agents/Daemons, login items |

---

## Persistence Sweep

**ATT&CK:** T1543.001/.004 · T1053.003 · T1547.015 · T1098.004 · T1546.014 · T1574.004

| Mechanism | Note |
|---|---|
| Launch Agents/Daemons | Launch Daemons and Launch Agents |
| Privileged helpers | Privileged Helper Tools |
| Cron / at / periodic | Cron Jobs · More Persistence |
| Login items / hooks | Login Items |
| System extensions / kexts | System Extensions |
| SSH keys | SSH Keys |
| Emond / auth plugins / folder actions / profiles | More Persistence |
| Dylib hijack / DYLD injection | Dylib Hijacking and Injection |
| Shell config hooks | Shells and Command History |

> Corroborate any plist/job with **FSEvents** (when it was dropped) + **quarantine** + **Install Receipts** (was it package-installed or hand-dropped?).

---

## Remote Access and Lateral Movement

**ATT&CK:** SSH (T1021.004) · VNC (T1021.005) · SSH Authorized Keys (T1098.004)

| Source (note) | What it gives |
|---|---|
| **Advanced Auth** (`sshd`) | Accepted/Failed + **source IP** |
| `~/.ssh/authorized_keys` / `known_hosts` | Planted keys / outbound targets |
| **Auth** (`opendirectoryd`, sudo) | Credential verify + escalation |
| **Wi-Fi/Network** (Screen Sharing, VPN, `nehelper`) | Remote desktop / tunnels |
| **securityd** | Keychain unlocks (cred theft) |
| Firewalls / App-specific (LuLu) | Outbound C2 |

---

## Dylib Hijacking and Injection

**ATT&CK:** Dylib Hijacking (T1574.004) · Dyld Hijacking (T1574.006) · Process Injection (T1055)

| Source (note) | What it gives |
|---|---|
| **Dylib Hijacking and Injection** | The full method + detection |
| `codesign --verify` on suspect apps | Tampered bundle (broken seal) |
| `otool -l` load commands | Weak/rpath dylibs (hijack surface) |
| `DYLD_*` in LaunchAgents/Daemons/shell config | Injection persistence |
| **Unified Logs** AMFI / Library Validation | System blocked an attempt |
| **TCC** grants of the host app | Capability the injected code inherits |

---

## Trojanized or Cracked App

**ATT&CK:** Compromise Host Binary (T1554) · Supply Chain (T1195) · Malicious File (T1204.002)

| Source (note) | What it gives |
|---|---|
| **quarantine / where-from** | Came from a warez/cracked source? |
| `codesign --verify` / Team ID | Re-signed / ad-hoc / broken |
| **Install Receipts** BOM | Files not matching any package = hand-dropped |
| **FSEvents** | When the app/its payload was written |
| **Launch Agents/Daemons** | Persistence the trojan installed |
| **Unified Logs** (Gatekeeper/XProtect) | Was it flagged/overridden |

---

## Insider Data Theft

**ATT&CK:** Local Data (T1005) · Exfil over USB (T1052.001) / Cloud (T1567) / Email (T1114)

| Source (note) | What it gives |
|---|---|
| **.DS_Store** / **RecentItems** / Spotlight | Folders/files the user browsed |
| **USB & Device History** + on-media FSEvents | Copied to removable media |
| **Messages and Mail** | Sent out via chat/email + attachments |
| **Wi-Fi/Network** + App-specific | Cloud upload / VPN egress |
| **Trash** | What they deleted to cover tracks |
| **knowledgeC/Biome** | Apps used (archiver, browser, Finder) + timing |

---

## Living off the Land

**ATT&CK:** Unix Shell (T1059.004) · AppleScript (T1059.002) · Ingress Tool Transfer (T1105)

🔴 Built-in binaries (LOLBins) abused so nothing "malware" lands on disk:

| Binary | Abuse | Evidence |
|---|---|---|
| `osascript` | AppleScript payloads / UI phishing | Shell history; Unified Logs; plists |
| `curl` / `nscurl` | Download payloads | quarantine (or absence of it); FSEvents |
| `sqlite3` | Read protected DBs (chat.db, TCC) | Shell history; TCC |
| `mdfind` / `mdls` | Recon of files | Shell history |
| `launchctl` | Load persistence | launchd logs |
| `sudo`/`security` | Escalation / keychain | sudo + securityd logs |

> Pull **shell history** (Shells note) + **Unified Logs** together — LOLBin abuse shows in command lines and process spawns, not in quarantine/XProtect.

---

## Anti-Forensics and Tampering

**ATT&CK:** Clear Logs (T1070.002) · Timestomp (T1070.006) · Disable Tools (T1562.001) · Gatekeeper Bypass (T1553.001)

| Tell | Where to look (note) |
|---|---|
| Unified Logs wiped (`log erase`) | System & Kernel — oldest-entry check |
| FSEvents wiped / `fseventsd-uuid` changed | FSEvents — empty/short store |
| **Timestomping** | File Systems — `create>modify`, whole-second on APFS |
| Clock changed | System & Kernel — `settimeofday`, `timesync` |
| Trash emptied / `rm` used | Trash + FSEvents + carving |
| Security agent disabled | App-specific (AV silent); Firewalls off |
| Quarantine stripped to evade Gatekeeper | File Permissions; `syspolicyd` |
| Bulk same-`ctime` deletions | Trash / FSEvents |

---

> Detailed commands, parsers, and red flags for each source are in its own note. This page is the index that tells you **which notes to open** for the case in front of you.
