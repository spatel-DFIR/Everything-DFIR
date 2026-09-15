# Process Trees and Execution Lineage

When an alert fires on a process, the first question is **"what started it, and as whom?"** The answer classifies the alert — a `curl` child of a shell in Terminal is a human (or a pasted one-liner); the same `curl` under a `com.apple.*` LaunchDaemon is persistence. This note is the **reference set of process trees** for the common ways code runs on an enterprise Mac, so you can place an alerted process fast and know where to look next.

> 🔴 **`launchd` is PID 1 and the parent of every launchd-managed job**, so a **`PPID` of 1 does NOT mean "daemon."** Daemons, Agents, login items, and even user-double-clicked apps can all show `PPID 1`. You disambiguate with **(1) effective UID**, **(2) the launchd domain + plist path from `launchctl procinfo`**, **(3) start time vs boot/login**, and **(4) the nearest *non-launchd* ancestor**. Parent alone is a trap.

## Contents
- [Quick Triage](#quick-triage)
- [The launchd Parenting Model](#the-launchd-parenting-model)
- [Pulling a Process's Lineage](#pulling-a-processs-lineage)
- [Reference Trees](#reference-trees)
  - [Launch Daemon (root service)](#launch-daemon-root-service)
  - [Launch Agent (per-user service)](#launch-agent-per-user-service)
  - [User double-clicked a GUI app](#user-double-clicked-a-gui-app)
  - [Interactive shell / pasted one-liner](#interactive-shell--pasted-one-liner)
  - [Cron and periodic](#cron-and-periodic)
  - [Login item / Background Task](#login-item--background-task)
  - [SSH remote execution](#ssh-remote-execution)
  - [AppleScript / osascript](#applescript--osascript)
  - [Office macro / app-spawned interpreter](#office-macro--app-spawned-interpreter)
  - [Browser drive-by / download-and-run](#browser-drive-by--download-and-run)
- [Fast Classification Table](#fast-classification-table)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
PID=<alerted-pid>

# 1. The one-liner lineage: walk parent → parent up to launchd (PID 1)
P=$PID; while [ "$P" -gt 1 ]; do ps -o pid=,ppid=,uid=,lstart=,command= -p "$P"; P=$(ps -o ppid= -p "$P" | tr -d ' '); done

# 2. AUTHORITATIVE "who launched me" (root): launchd domain, the plist path, responsible pid
sudo launchctl procinfo "$PID" | grep -iE 'program|domain|path|responsible|argument' | head

# 3. What the running image is + as whom
ps -o pid,ppid,uid,user,lstart,command -p "$PID"

# 4. launchd's own record of spawning it (label ↔ pid)
log show --last 1h --predicate 'process == "launchd"' 2>/dev/null | grep -i '<label-or-path>'

# Optional visual tree (needs: brew install pstree)
pstree -p "$PID" 2>/dev/null
```

The decisive field is usually in **`launchctl procinfo`**: it prints the launchd **domain** (`system` = daemon, `gui/<uid>` = agent/app) and, for a launchd job, the **originating plist path** — that single line tells you daemon vs agent vs app.

---

## The launchd Parenting Model

Unlike Linux (where a service's parent is `systemd`/`init` and interactive commands descend from a shell/`sshd`), macOS routes **almost everything** through `launchd`:

- A **LaunchDaemon** job → parent `launchd` (PID 1), domain `system`, **UID 0**.
- A **LaunchAgent** job → parent `launchd` (PID 1), domain `gui/<uid>`, **user UID**.
- A **double-clicked app** → launched by LaunchServices/RunningBoard, **reparented to `launchd`** (PID 1), domain `gui/<uid>`, user UID — *but it is not a launchd *job*, so `procinfo` shows no plist path.*
- Only things spawned by a **real running parent** keep that parent: a command in Terminal (parent = shell → Terminal), a macro payload (parent = Word), a remote command (parent = `sshd`), a cron job (parent = `cron`).

So the trick is: **find the nearest ancestor that is NOT `launchd`.** If there isn't one, fall back to **UID + procinfo domain + plist path** to separate daemon / agent / user-app.

---

## Pulling a Process's Lineage

| Source | Gives you | Note |
|---|---|---|
| `ps -o pid,ppid,uid,lstart,command` | Parent, owner, start time, argv | Start with this; `lstart` pins the timeline |
| `launchctl procinfo <pid>` (root) | launchd **domain**, **plist path**, **responsible pid**, env, argv | The authoritative "who launched me" |
| `log show --predicate 'process == "launchd"'` | launchd loading/spawning a label | Ties a running PID back to its plist label |
| `pstree -p` (brew) | Visual ancestry tree | Convenience only |
| **EDR / EndpointSecurity** `EXEC` events | Full parent **and responsible** chain, signing info | Best source when the agent is healthy — records lineage even after the process exits |

> **Responsible process** is macOS's "who is ultimately behind this" attribution (used by TCC for permission prompts). `launchctl procinfo` prints it. For an app-spawned helper it points back to the app; for an injected/abused process it can reveal the real driver.

---

## Reference Trees

Each tree shows `name (pid, uid)` and how to confirm the classification.

### Launch Daemon (root service)
```
launchd (1, uid 0)
└── com.vendor.helper (837, uid 0)        ← runs as ROOT, started at boot
```
- **UID 0**, `PPID 1`, alive since ~boot. `sudo launchctl procinfo 837` → `domain = system`, `path = /Library/LaunchDaemons/com.vendor.helper.plist`.
- **Verdict driver:** root + system domain + plist in `/Library/LaunchDaemons`. A `com.apple.*` label here that isn't under `/System/Library` = masquerade. → [`Launch Daemons and Launch Agents`](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>)

### Launch Agent (per-user service)
```
launchd (1, uid 0)
└── com.vendor.agent (1420, uid 501)      ← runs as the USER, started at login
```
- **User UID**, `PPID 1`, alive since ~login. `launchctl procinfo 1420` → `domain = gui/501`, `path = ~/Library/LaunchAgents/…` or `/Library/LaunchAgents/…`.
- **Verdict driver:** user UID + `gui/<uid>` domain + plist in a `LaunchAgents` dir. Same `PPID 1` as a daemon — **UID + plist path are what separate them.**

### User double-clicked a GUI app
```
launchd (1, uid 0)
└── Suspicious.app (2003, uid 501)        ← reparented to launchd, but NOT a launchd job
```
- **User UID**, `PPID 1`, but `launchctl procinfo 2003` shows **no LaunchDaemon/Agent plist** — it's a LaunchServices launch. Confirm human action via a **quarantine event** (download provenance) and Finder/LaunchServices log entries near the start time.
- **Verdict driver:** user UID + `PPID 1` + *no plist* = launched interactively (Finder/Dock/Spotlight), not persistence. If it also persists, you'll find a *separate* LaunchAgent.

### Interactive shell / pasted one-liner
```
Terminal (900, 501)  [or iTerm2]
└── zsh (901, 501)
    └── bash (1500, 501)                  ← curl … | bash
        └── curl / python / payload (1501, 501)
```
- Nearest non-launchd ancestor is **Terminal/iTerm2 via a shell**. This is a **human at a keyboard** or a **fileless one-liner** they pasted/ran.
- **Verdict driver:** ancestor chain ends in a terminal app. Pull the shell history ([`04 - Shells`](<04 - Shells and Command History.md>)) for the exact command. A `sh -c`/`base64 -d`/`curl|bash` here is hands-on-keyboard activity.

### Cron and periodic
```
launchd (1, 0)
└── cron (310, 0)                          [com.vix.cron LaunchDaemon]
    └── sh (5001, 501)                     ← the crontab command
        └── payload (5002, 501)
```
- Nearest non-launchd ancestor is **`cron`**. UID is whichever user's crontab fired it.
- **Verdict driver:** ancestor `cron` = scheduled execution → check `/usr/lib/cron/tabs/<user>` and `/etc/periodic`. → [`Cron Jobs`](<12 - Persistence Mechanisms/Cron Jobs.md>)

### Login item / Background Task
```
launchd (1, 0)
└── HelperApp (2110, 501)                  ← opened at login via BTM / SMLoginItem
```
- Looks like an Agent (`PPID 1`, user UID) but there's **no LaunchAgent plist**; instead it's registered in **Background Task Management**. Confirm with `sfltool dumpbtm` / the `loginitems` module.
- **Verdict driver:** user UID + `PPID 1` + no plist + present in BTM. → [`Login Items`](<12 - Persistence Mechanisms/Login Items.md>)

### SSH remote execution
```
launchd (1, 0)
└── sshd (450, 0)
    └── sshd (7001, 501)                   ← the authenticated user session
        └── zsh / remote command (7002, 501)
```
- Nearest non-launchd ancestor is **`sshd`** → the process came in over **SSH** (interactive or a remote command). Cross-ref `last`/`w` for the source host and time.
- **Verdict driver:** ancestor `sshd` = remote/lateral execution. → [`SSH Keys`](<12 - Persistence Mechanisms/SSH Keys.md>)

### AppleScript / osascript
```
<shell or app> 
└── osascript (3200, 501)                  ← e.g. `osascript -e 'display dialog …'`
    └── payload / prompt
```
- `osascript` is a top adware/stealer tool — **fake password prompts** (`display dialog … with hidden answer`) and app automation. Its parent tells you what drove it (a shell one-liner, a LaunchAgent, or an app).
- **Verdict driver:** any `osascript` running a `-e` string, especially spawning a credential dialog or reading Keychain, is suspicious regardless of parent.

### Office macro / app-spawned interpreter
```
Microsoft Word (4000, 501)  [or Excel / PowerPoint / a PDF viewer]
└── bash / osascript / python (4100, 501)  ← macro or document exploit
    └── curl / dropped payload (4101, 501)
```
- A **productivity/document app as the parent of a shell or interpreter** is the macOS equivalent of the classic "Word spawned cmd.exe." Very high signal.
- **Verdict driver:** parent is a document/productivity app (or a browser) and child is an interpreter/downloader → macro/exploit-driven execution. Check TCC prompts and the document in `~/Library/Containers/<app>`.

### Browser drive-by / download-and-run
```
launchd (1, 0)
└── Installer.app / payload (5300, 501)    ← ran shortly after a browser download
```
- Parent may just be `launchd` (Finder-launched), so lineage alone is thin — **the tell is correlation**: a **quarantine event** (download URL + agent + timestamp) or a browser download record immediately preceding first execution.
- **Verdict driver:** quarantine/download provenance + first-run timing. A browser (`Google Chrome Helper`, `Safari`) directly parenting a shell is an exploit; a downloaded app launched from Finder needs the quarantine correlation.

---

## Fast Classification Table

Find the **nearest non-`launchd` ancestor** (or fall back to UID + procinfo), then read across:

| Nearest ancestor / signal | UID | Classification | Where next |
|---|---|---|---|
| Terminal / iTerm2 → shell | user | Hands-on / pasted one-liner | shell history |
| Word / Excel / PowerPoint / PDF app → interpreter | user | **Macro or document exploit** | app container, TCC |
| Browser → shell/interpreter | user | Drive-by / exploit | quarantine, browser history |
| `sshd` | user | Remote / lateral execution | `last`, `w`, auth logs |
| `cron` | user/root | Scheduled | crontab, periodic |
| `launchd` only, **UID 0**, `/Library/LaunchDaemons` plist | root | **LaunchDaemon persistence** | persistence sweep |
| `launchd` only, user UID, `LaunchAgents` plist | user | **LaunchAgent persistence** | persistence sweep |
| `launchd` only, user UID, **no plist**, in BTM | user | Login item / background task | `sfltool dumpbtm` |
| `launchd` only, user UID, **no plist**, quarantine event | user | User launched it (Finder/Dock) | quarantine, LaunchServices |

---

## Red Flags

| 🔴 Lineage | Likely meaning |
|---|---|
| Document/productivity app is the parent of `bash`/`sh`/`python`/`osascript` | Macro or document-exploit execution |
| Browser process directly parents a shell/interpreter | Browser exploit / drive-by |
| `osascript -e` spawning a password **dialog** or reading Keychain | Credential-phishing stealer (AMOS-style) |
| A "service" process whose real ancestor is **Terminal** or an app (not `launchd`) | Not a service — interactive or injected |
| `PPID 1`, **UID 0**, plist in `~/Library` or `/Library` named `com.apple.*` | Masquerading root persistence |
| Long-lived `PPID 1` process from `/tmp`/`/Users/Shared`/hidden dir with a network socket | Implant/beacon (pair with [`15 - Live Response`](<15 - Live Response and Volatile Data.md>)) |
| Child interpreter with `curl\|bash` / `base64 -d` / `-e`/`-c` one-liner argv | Downloader / fileless stage |
| `responsible pid` (procinfo) points somewhere that doesn't match the visible parent | Injection / responsibility spoofing — dig deeper |
| Process running, but `launchctl procinfo` shows a plist you didn't expect | Persistence you haven't enumerated yet — sweep it |

---

## Resources

- `man` pages: `ps(1)`, `launchctl(1)` (`procinfo`, `print`), `log(1)`, `pstree(1)` (brew)
- [`15 - Live Response and Volatile Data`](<15 - Live Response and Volatile Data.md>) — pull the processes/sockets this note helps you interpret
- [`12 - Persistence Mechanisms`](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>) — the launch points each "persistence" verdict maps to
- [`11 - Artifacts/Program Execution Evidence`](<11 - Artifacts/Program Execution Evidence.md>) — proving a process *ran* (even after it exits)
- [`scripts/hunt_persistence.sh`](scripts/hunt_persistence.sh) — enumerate the launch points behind a suspicious process
