# Application and Container Data

Where an app's evidence actually lives. macOS splits app data across **preferences, application support, caches, logs, saved state**, and — for sandboxed apps — a redirected **Container**. Knowing the exact paths for a bundle ID turns "the user ran Slack/Teams/an installer" into recoverable artifacts: tokens, config, recent files, autosaved documents, and cached content. This is also where **infostealers shop** — session tokens and app secrets sit in these directories in plaintext.

> 🔴 First move for any app: get its **bundle identifier**, then enumerate its five data homes. Sandboxed apps redirect `~/Library` into `~/Library/Containers/<bundleID>/Data/` — looking only at the top-level `~/Library` misses everything an App Store / sandboxed app wrote.

## Contents
- [Quick Triage](#quick-triage)
- [The Five Data Homes](#the-five-data-homes)
- [Sandboxed Apps: Containers](#sandboxed-apps-containers)
- [Group Containers](#group-containers)
- [Preferences and cfprefsd](#preferences-and-cfprefsd)
- [Saved State and Autosave](#saved-state-and-autosave)
- [High-Value App Data](#high-value-app-data)
- [Mapping a Bundle ID to Everything](#mapping-a-bundle-id-to-everything)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
APP=/Applications/Suspect.app
BID=$(defaults read "$APP/Contents/Info" CFBundleIdentifier)
echo "bundle: $BID"

# All five data homes for this app (non-sandboxed)
ls -la ~/Library/Application\ Support/"$BID"* ~/Library/Preferences/"$BID"*.plist \
       ~/Library/Caches/"$BID"* ~/Library/Logs/"$BID"* \
       ~/Library/Saved\ Application\ State/"$BID".savedState 2>/dev/null

# Sandboxed home (redirected ~/Library) + shared group containers
ls -la ~/Library/Containers/"$BID"/Data 2>/dev/null
ls -d  ~/Library/Group\ Containers/*"$BID"* 2>/dev/null

# What did THIS app write recently (behavioral)
find ~/Library/Application\ Support/"$BID"* ~/Library/Containers/"$BID" -type f -mtime -7 2>/dev/null

# Ask LaunchServices where an installed bundle id lives
mdfind "kMDItemCFBundleIdentifier == '$BID'"
```

---

## The Five Data Homes

A traditional (non-sandboxed) app scatters data across these; check all five:

| Location | Holds | Notes |
|---|---|---|
| `~/Library/Application Support/<BID or Name>/` | Primary app data, DBs, **tokens/creds**, plugins | 🔴 richest; stealer target |
| `~/Library/Preferences/<BID>.plist` | Settings (binary plist) | `defaults read <BID>`; also `ByHost/` |
| `~/Library/Caches/<BID>/` | Cached content, thumbnails, network cache | Often has URLs, filenames, fragments |
| `~/Library/Logs/<BID or Name>/` | App logs | Timestamps of activity |
| `~/Library/Saved Application State/<BID>.savedState/` | Window/UI restoration | Can contain on-screen text/secrets |

System-wide equivalents live under `/Library/…` (all users) and Apple's under `/System/Library/…` (SIP).

---

## Sandboxed Apps: Containers

App Store apps and many notarized apps are **sandboxed**: their `$HOME` is transparently redirected into a container, so their "`~/Library/Preferences`" is really inside the container.

```
~/Library/Containers/<bundleID>/
├── Container.plist            # maps the container to its bundle id + metadata
└── Data/                      # the app's redirected HOME
    ├── Documents/
    ├── Library/
    │   ├── Preferences/<bundleID>.plist
    │   ├── Application Support/
    │   ├── Caches/
    │   └── Cookies/
    ├── Desktop/  Downloads/    # symlinks back to the real ones (if granted)
    └── tmp/
```

```bash
# Which app owns a container
defaults read ~/Library/Containers/<bundleID>/Container.plist | grep -i identifier
# Real preferences of a sandboxed app
defaults read ~/Library/Containers/<bundleID>/Data/Library/Preferences/<bundleID>
```

> A single app can have **multiple containers** (main app + each extension/XPC service). `com.apple.*` containers are Apple apps (Notes, Messages, Mail, Safari). A **non-Apple bundle id writing into a `com.apple.*` container**, or a container whose id doesn't match any installed app, is anomalous.

---

## Group Containers

Shared storage between an app and its extensions/helpers (and sometimes a suite). Keyed by an **App Group** id (often `<TeamID>.<name>`).

```bash
ls -la ~/Library/Group\ Containers/
```

| Example group container | Belongs to |
|---|---|
| `UBF8T346G9.Office` | Microsoft Office suite (shared license/state) |
| `group.com.apple.notes` | Apple Notes (the actual `NoteStore.sqlite` lives here) |
| `group.<TeamID>.<app>` | An app + its Share/Today/Notification extensions |

Group containers frequently hold the **real database** (e.g., Notes) and **shared auth state** — check them whenever the top-level container looks empty.

---

## Preferences and cfprefsd

Preferences are binary plists mediated by `cfprefsd` — **don't `cat` them, read them decoded**, and beware caching.

```bash
defaults read <bundleID>                       # current user
defaults read /Library/Preferences/<bundleID>  # system-wide
ls ~/Library/Preferences/ByHost/               # per-hardware-UUID prefs (<domain>.<UUID>.plist)
plutil -p ~/Library/Preferences/<bundleID>.plist
```

`ByHost/` prefs are tied to the machine's hardware UUID — useful to prove *which* Mac, and they hold things like screen-sharing and some login settings.

---

## Saved State and Autosave

```bash
# Window restoration blobs — can contain on-screen content / typed text
ls -la ~/Library/Saved\ Application\ State/*.savedState/
# Autosaved / unsaved documents (recover work an attacker never explicitly saved)
ls -la ~/Library/Autosave\ Information/ ~/Library/Containers/*/Data/Library/Autosave\ Information/ 2>/dev/null
# App "recent documents"
defaults read <bundleID> NSRecentDocumentRecords 2>/dev/null
```

Cross-reference [`Recent Items and SharedFileList`](<Recent Items and SharedFileList.md>) for the per-app recent-file lists.

---

## High-Value App Data

Common enterprise apps and the artifacts worth pulling (paths are `~/Library/Application Support/…` unless noted):

| App | Where | What |
|---|---|---|
| **Slack** | `Slack/` (or container) | Workspaces, `storage/`, local cache; **session tokens** in leveldb/cookies |
| **Microsoft Teams** | `Microsoft/Teams/` or `com.microsoft.teams` | Cache, logs, tokens |
| **Microsoft Office** | `UBF8T346G9.Office` group container | Recent files, autorecovery, MRU |
| **Discord** | `discord/` | leveldb, cache, tokens (classic stealer target) |
| **Zoom** | `zoom.us/` + `~/Documents/Zoom` | Meeting logs, recordings, config |
| **Terminal / iTerm2** | Prefs + `Saved Application State` | Scrollback, window state → [`04 - Shells`](<../04 - Shells and Command History.md>) |
| **Apple Notes** | `group.com.apple.notes/NoteStore.sqlite` | Note bodies (often creds/secrets) |
| **Messages** | `~/Library/Messages/chat.db` | → [`Messages and Mail`](<Messages and Mail.md>) |
| **VPN/SSH/cloud CLIs** | `~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube` | Keys/tokens → [`16 - Remediation`](<../16 - Remediation and Containment.md>) |

> 🔴 Chat/collab apps store **OAuth/session tokens** in their Application Support (leveldb, `Cookies`, `storage`). These are exactly what AMOS-class stealers exfiltrate — their presence in an exfil staging dir is a strong signal.

---

## Mapping a Bundle ID to Everything

```bash
BID=com.vendor.app
for base in "Application Support" "Preferences" "Caches" "Logs" "Saved Application State" "Containers" "Group Containers"; do
  echo "== $base =="; ls -d ~/Library/"$base"/*"$BID"* 2>/dev/null
done
mdfind "kMDItemCFBundleIdentifier == '$BID'"     # the installed bundle(s)
lsappinfo info -only bundlepath "$BID" 2>/dev/null # running app's path (if live)
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| A container/prefs domain not matching any installed app | Orphaned or planted app data |
| Non-Apple process writing into a `com.apple.*` container | Masquerade / data injection |
| App **tokens/cookies/leveldb copied** into `/tmp`, `/Users/Shared`, or an archive | Infostealer staging for exfil |
| App Support dir for a "system utility" holding a payload/script | Malware hiding in plain sight |
| Recently-created `Application Support/<random>/` with an executable | Adware/stealer working dir (pair with its LaunchAgent) |
| Saved State / Autosave with credentials or attacker notes | Recoverable operator artifacts |
| Group container modified by an unexpected Team ID | Suite/extension tampering |

---

## Resources
- `man` pages: `defaults(1)`, `plutil(1)`, `mdfind(1)`, `lsappinfo(8)`
- [`Recent Items and SharedFileList`](<Recent Items and SharedFileList.md>) — per-app recent files
- [`06 - Transparency Consent and Control (TCC)`](<../06 - Transparency Consent and Control (TCC).md>) — per-bundle permission grants
- [`15b - Process Trees and Execution Lineage`](<../15b - Process Trees and Execution Lineage.md>) — the macro tree points into an app's container
