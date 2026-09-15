# Login Items

**Login Items** launch apps/scripts automatically when a **user logs in** — clean **user-level persistence**. Modern macOS (Ventura+) manages them through **Background Task Management (BTM)**, but several **legacy** mechanisms (and deprecated **login/logout hooks**) still work, especially on upgraded systems. Attackers use them to silently start a payload at login.

> 🔴 Check **both** the modern BTM database (`sfltool dumpbtm`) and the legacy spots — especially the **deprecated `LoginHook`/`LogoutHook`**, which run a script at login/logout and survive on older or upgraded Macs. A `LoginHook` is almost always worth investigating.

## Contents
- [Quick Triage](#quick-triage)
- [Mechanisms Overview](#mechanisms-overview)
- [Background Task Management](#background-task-management)
- [Legacy Login Items](#legacy-login-items)
- [Login and Logout Hooks](#login-and-logout-hooks)
- [App-Bundled Login Item Helpers](#app-bundled-login-item-helpers)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Modern: dump Background Task Management (login items + agents/daemons), Ventura+
sudo sfltool dumpbtm

# Deprecated login/logout hooks (high-value — run scripts at login/logout)
sudo defaults read com.apple.loginwindow LoginHook 2>/dev/null

sudo defaults read com.apple.loginwindow LogoutHook 2>/dev/null

# Login items as the user sees them
osascript -e 'tell application "System Events" to get the name of every login item'
```

---

## Mechanisms Overview

| Mechanism | Era | Where |
|---|---|---|
| 🔴 **BTM** (Background Task Management) | Ventura 13+ | `BackgroundItems-v*.btm` (parsed by `sfltool dumpbtm`) |
| **SharedFileList** login items | 10.13+ | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` |
| Legacy `loginitems.plist` | Older | `~/Library/Preferences/com.apple.loginitems.plist` |
| 🔴 **Login/Logout Hooks** | Deprecated, still works | `com.apple.loginwindow` `LoginHook`/`LogoutHook` |
| **SMLoginItemSetEnabled** helpers | Modern | App bundle `Contents/Library/LoginItems/` |

---

## Background Task Management

BTM (Ventura+) tracks login items **and** Launch Agents/Daemons in one database.

```bash
# Dump everything BTM knows (items, their executables, enabled/disabled)
sudo sfltool dumpbtm

# The backing database on disk
ls -la /private/var/db/com.apple.backgroundtaskmanagement/

#   BackgroundItems-v*.btm   (parse with sfltool, mac_apt, or aftermath)
```

🔴 Look for items whose **executable** is in `~/Library/…`, `/tmp`, or a hidden path, items added **recently**, or items **disabled then re-enabled** (attacker toggling). BTM also logs add/remove events to the Unified Log.

---

## Legacy Login Items

```bash
# SharedFileList store (per-user login items)
ls -la ~/Library/Application\ Support/com.apple.backgroundtaskmanagementagent/ 2>/dev/null

# Older preferences plist
plutil -p ~/Library/Preferences/com.apple.loginitems.plist 2>/dev/null

# Via Apple Events (what's registered now)
osascript -e 'tell application "System Events" to get the path of every login item'
```

> SharedFileList (`.sfl`/`.sfl2`) files are serialized binary — parse with a tool (`mac_apt`, `sfltool`) rather than reading raw.

---

## Login and Logout Hooks

🔴 **Deprecated** but functional — a single script run as the user (LoginHook) or at logout (LogoutHook). Loud red flag because almost nothing legitimate uses them anymore.

```bash
# Read current hooks
sudo defaults read com.apple.loginwindow LoginHook 2>/dev/null

sudo defaults read com.apple.loginwindow LogoutHook 2>/dev/null

# The plist itself (system + per-user)
sudo plutil -p /var/root/Library/Preferences/com.apple.loginwindow.plist 2>/dev/null

plutil -p ~/Library/Preferences/com.apple.loginwindow.plist 2>/dev/null
```

> If `LoginHook` is set, **the path it points to runs at every login** — examine and preserve that script. (LoginHook runs as **root** when set at the system level.)

---

## App-Bundled Login Item Helpers

Modern apps register a helper inside the bundle via `SMLoginItemSetEnabled`:

```bash
# Helper apps shipped to auto-start with their parent
ls -la /Applications/*/Contents/Library/LoginItems/ 2>/dev/null

ls -la ~/Applications/*/Contents/Library/LoginItems/ 2>/dev/null

# Verify the helper's signature matches its parent app
codesign -dvvv "/Applications/Some.app/Contents/Library/LoginItems/Helper.app" 2>&1
```

🔴 A login-item helper whose **Team ID doesn't match** the parent app, or that lives in a sketchy app, is suspect.

---

## Logs

```bash
# BTM add/enable/disable events (Ventura+)
log show --predicate 'subsystem == "com.apple.backgroundtaskmanagement" OR process == "backgroundtaskmanagementd"' --info --last 30d

# loginwindow session activity (cross-ref Authentication note)
log show --predicate 'subsystem == "com.apple.loginwindow"' --info --last 7d
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `LoginHook`/`LogoutHook` set | Deprecated hook abused for persistence (run a script at login) |
| BTM/login item executable in `~/Library`, `/tmp`, hidden dir | Malware auto-start |
| Login item added **recently** / toggled disabled→enabled | Attacker activity |
| App-bundled helper with **mismatched Team ID** | Hijacked/fake helper |
| Login item with no visible/known parent app | Stealth persistence |
| Item runs a **script** (`.sh`/osascript/python) | Stager |
| BTM data wiped while items still run | Anti-forensics |

---

## Resources

- `man sfltool` · Background Task Management (Ventura+)
- Apple `SMLoginItemSetEnabled` / ServiceManagement: https://developer.apple.com/documentation/servicemanagement
