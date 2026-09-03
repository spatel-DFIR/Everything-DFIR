# More Persistence Mechanisms

Beyond the headline mechanisms (Launch Agents/Daemons, cron, login items, system extensions, SSH keys), macOS has a long tail of **less-common persistence spots** attackers use precisely because defenders rarely check them. Several are **deprecated but still functional** on older or upgraded systems — which makes them stealthy. This note rounds them up so nothing gets missed in a hunt.

> 🔴 The deprecated ones (**emond**, login/logout hooks, authorization plugins) are loud findings *because* almost nothing legitimate uses them anymore. Check them even on modern Macs — upgraded systems carry the old configs.

## Contents
- [Quick Triage](#quick-triage)
- [Emond Event Monitor](#emond-event-monitor)
- [Authorization Plugins](#authorization-plugins)
- [Folder Actions](#folder-actions)
- [At Jobs and Periodic](#at-jobs-and-periodic)
- [Spotlight Importers and Dock Plugins](#spotlight-importers-and-dock-plugins)
- [Reopened Apps and Saved State](#reopened-apps-and-saved-state)
- [Trojanized Binaries and Apps](#trojanized-binaries-and-apps)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Emond rules (should be EMPTY by default — any rule is suspect)
sudo ls -la /etc/emond.d/rules/ /private/var/db/emondClients 2>/dev/null

# Authorization plugins (credential-capture / login persistence)
ls -la /Library/Security/SecurityAgentPlugins/ 2>/dev/null

# Folder Actions (AppleScript triggered on folder changes)
defaults read com.apple.FolderActionsDispatcher 2>/dev/null

# at jobs
sudo ls -la /var/at/jobs/ 2>/dev/null

# Reopen-at-login app list
defaults read com.apple.loginwindow TALAppsToRelaunchAtLogin 2>/dev/null
```

---

## Emond Event Monitor

🔴 **emond** (Event Monitor Daemon) runs rules at startup/events — a classic persistence spot. **Empty by default**, so any rule is suspicious. Deprecated and removed around **Ventura**, but present on older/upgraded systems.

| Path | Holds |
|---|---|
| 🔴 `/etc/emond.d/rules/*.plist` | Rule definitions (commands to run on events) |
| `/private/var/db/emondClients` | Client marker files |
| `/System/Library/LaunchDaemons/com.apple.emond.plist` | The daemon |

```bash
sudo ls -la /etc/emond.d/rules/

sudo plutil -p /etc/emond.d/rules/*.plist 2>/dev/null
```

**ATT&CK:** Event Triggered Execution: Emond — **T1546.014**

---

## Authorization Plugins

🔴 Plugins loaded by **`authorizationd`/SecurityAgent** during login/authorization — they see credentials, so they're used for **credential theft** *and* persistence.

| Path | Holds |
|---|---|
| 🔴 `/Library/Security/SecurityAgentPlugins/` | Third-party auth plugins |
| `/System/Library/CoreServices/SecurityAgentPlugins/` | Apple's (baseline) |
| `/etc/authorization` / `authorizationdb` | Authorization policy DB (`security authorizationdb read …`) |

```bash
ls -la /Library/Security/SecurityAgentPlugins/

# Verify any non-Apple plugin's signature
codesign -dvvv /Library/Security/SecurityAgentPlugins/*.bundle 2>&1
```

**ATT&CK:** Modify Authentication Process — **T1556** · Boot/Logon Autostart — T1547

---

## Folder Actions

AppleScript scripts attached to a folder that **fire when items are added/removed** — persistence via `osascript`.

```bash
defaults read com.apple.FolderActionsDispatcher 2>/dev/null

ls -la ~/Library/Scripts/Folder\ Action\ Scripts/ 2>/dev/null

osascript -e 'tell application "System Events" to get every folder action' 2>/dev/null
```

**ATT&CK:** Event Triggered Execution — **T1546** · AppleScript — T1059.002

---

## At Jobs and Periodic

| Mechanism | Where | Note |
|---|---|---|
| `at` jobs | `/var/at/jobs/` | `atrun` (`com.apple.atrun`) is **disabled by default** — enabling it is itself a flag |
| periodic | `/etc/periodic/{daily,weekly,monthly}/`, `/usr/local/etc/periodic/` | Scripts hide among Apple maintenance (cross-ref Cron note) |

```bash
sudo ls -la /var/at/jobs/ 2>/dev/null

sudo launchctl print-disabled system | grep -i atrun

ls -la /etc/periodic/*/ /usr/local/etc/periodic/ 2>/dev/null
```

**ATT&CK:** Scheduled Task/Job: At — **T1053.002** · Cron — T1053.003

---

## Spotlight Importers and Dock Plugins

Rare but real — code loaded by system services:

| Path | Loaded by |
|---|---|
| `/Library/Spotlight/*.mdimporter` | `mdworker` (Spotlight indexing) |
| `~/Library/Spotlight/` | per-user importers |
| App `Contents/PlugIns/` Dock tile plugins | the Dock |

```bash
ls -la /Library/Spotlight/ ~/Library/Spotlight/ 2>/dev/null

codesign -dvvv /Library/Spotlight/*.mdimporter 2>&1
```

**ATT&CK:** Hijack Execution Flow / Boot-Logon Autostart — T1574 / T1547

---

## Reopened Apps and Saved State

The "**reopen windows when logging back in**" feature relaunches apps at login — abusable to auto-start a payload.

```bash
defaults read com.apple.loginwindow TALAppsToRelaunchAtLogin 2>/dev/null

ls -la ~/Library/Saved\ Application\ State/ 2>/dev/null
```

🔴 An attacker-controlled app in the relaunch list = login persistence that isn't a Login Item or LaunchAgent.

**ATT&CK:** Boot or Logon Autostart Execution — **T1547**

---

## Trojanized Binaries and Apps

Replacing or backdooring a **legitimate** binary/app keeps persistence *and* blends in.

```bash
# Verify a system/app binary hasn't been modified
codesign --verify --strict --verbose=4 /Applications/Some.app 2>&1

# Compare against the install receipt's file list (what shipped)
lsbom -p f /var/db/receipts/com.vendor.pkg.bom 2>/dev/null
```

🔴 A **broken signature** on a normally-signed app/binary, or files not matching the install receipt, = tampering.

**ATT&CK:** Compromise Host Software Binary — **T1554** · Masquerading — T1036

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| **Any** emond rule (non-empty) | Persistence (emond is empty by default) |
| Third-party **authorization plugin** | Credential theft + login persistence |
| Folder Action script attached to a watched folder | osascript persistence |
| `atrun` enabled / `at` jobs present | Scheduled persistence |
| Non-Apple `.mdimporter` / Dock plugin | Code loaded by a system service |
| Unknown app in the **relaunch-at-login** list | Stealth login persistence |
| **Broken signature** on a legit app/binary | Trojanized binary |
| Recently modified config in any of the above | Freshly planted (cross-ref FSEvents) |

---

## Resources

- `man emond` (where present) · `man at` · `man pkgutil`
- Cross-ref: Launch Daemons/Agents, Cron, Login Items, Dylib Hijacking and Injection
