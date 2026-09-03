# Launch Daemons and Launch Agents

`launchd` (PID 1) starts and supervises every background service on macOS via **job definition plists**. **Launch Daemons** run **system-wide at boot as root** with no UI; **Launch Agents** run **in a user session at login** and can have a UI. This is the **#1 macOS persistence mechanism** — drop a plist with `RunAtLoad`/`KeepAlive` pointing at your binary and it runs automatically, forever.

> 🔴 Triage rule: enumerate every `LaunchDaemons`/`LaunchAgents` directory, then for each non-Apple plist check **where `ProgramArguments` points** and **whether the target is signed**. Malware lives in plists that launch scripts or binaries from `/tmp`, `/Users/Shared`, `~/Library/…`, or hidden dirs.

## Contents
- [Quick Triage](#quick-triage)
- [Daemons vs Agents](#daemons-vs-agents)
- [Locations](#locations)
- [The Plist Job Definition](#the-plist-job-definition)
- [Sample Plist](#sample-plist)
- [Key Persistence Keys](#key-persistence-keys)
- [Enumerating and Inspecting](#enumerating-and-inspecting)
- [Hunting Guidance](#hunting-guidance)
- [Automated Hunt Script](#automated-hunt-script)
- [Logs](#logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Enumerate every launchd location (system + all users)
ls -la /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents /Users/*/Library/LaunchAgents 2>/dev/null

# Non-Apple plists modified in the last 30 days
sudo find /Library/LaunchDaemons /Library/LaunchAgents /Users/*/Library/LaunchAgents -name '*.plist' -mtime -30 2>/dev/null

# What's actually loaded right now
sudo launchctl list | grep -v com.apple

# Inspect a suspect plist + verify its target binary
plutil -p /Library/LaunchDaemons/com.suspect.plist

codesign -dvvv "$(plutil -extract ProgramArguments.0 raw /Library/LaunchDaemons/com.suspect.plist 2>/dev/null)"
```

---

## Daemons vs Agents

| | Launch **Daemon** | Launch **Agent** |
|---|---|---|
| Runs | At **boot**, before/without login | At **user login**, in the user session |
| As | 🔴 **root** (system) | The **logged-in user** |
| UI | No (background only) | Can show UI (`Aqua` session) |
| Use for persistence | System-wide, root-level | Per-user, user-level |

---

## Locations

| Path | Type | Scope |
|---|---|---|
| `/System/Library/LaunchDaemons/` | Apple daemons | root — **SIP-protected** |
| 🔴 `/Library/LaunchDaemons/` | Third-party/admin daemons | root, all-boot — **prime persistence** |
| `/System/Library/LaunchAgents/` | Apple agents | user — SIP-protected |
| 🔴 `/Library/LaunchAgents/` | Third-party agents | every user's login |
| 🔴 `~/Library/LaunchAgents/` | Per-user agents | that user's login |

> Apple's own jobs live under **`/System/Library`** (SIP-protected). A `com.apple.*`-named plist sitting in **`/Library`** or **`~/Library`** is a **masquerade red flag** — Apple doesn't put its jobs there.

---

## The Plist Job Definition

An XML (or binary) property list describing **what** to run and **when**. Place it in a `LaunchDaemons` or `LaunchAgents` dir; `launchd` loads it at boot/login (or on `launchctl load`).

```bash
# Convert/view a binary plist as text
plutil -p /Library/LaunchAgents/com.example.plist

# Or with defaults (omit the .plist extension)
defaults read /Library/LaunchAgents/com.example
```

---

## Sample Plist

Place in `/Library/LaunchDaemons/` (system, root) **or** `~/Library/LaunchAgents/` / `/Library/LaunchAgents/` (user session, can show UI):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.example.persistence</string>

  <key>KeepAlive</key>
  <false/>

  <key>ProgramArguments</key>
  <array>
    <string>/path/to/binary</string>
    <string>run</string>
  </array>

  <key>RunAtLoad</key>
  <true/>

  <!-- 
    Optional (often used in Launch Agents):
    <key>LimitLoadToSessionType</key>
    <string>Aqua</string>
  -->
</dict>
</plist>
```

---

## Key Persistence Keys

| Key | Meaning / DFIR relevance |
|---|---|
| 🔴 `Label` | Reverse-DNS job name (often mimics a real vendor/Apple) |
| 🔴 `ProgramArguments` / `Program` | The binary/script + args that runs — **the payload** |
| 🔴 `RunAtLoad` | Run immediately on load (boot/login) |
| 🔴 `KeepAlive` | Respawn if it exits (resilient persistence) — `true` or conditions dict |
| `StartInterval` | Run every N seconds (beaconing) |
| `StartCalendarInterval` | Cron-like schedule |
| `WatchPaths` / `QueueDirectories` | Trigger when a path changes (event persistence) |
| `StartOnMount` | Run when a volume mounts |
| `LimitLoadToSessionType` | `Aqua` (GUI), `LoginWindow`, `Background`, `StandardIO`, `System` |
| `UserName` / `RootDirectory` | Run-as user / chroot |
| `EnvironmentVariables` | Can smuggle `DYLD_*` injection |

---

## Enumerating and Inspecting

```bash
# All locations, long listing with timestamps
ls -la@ /Library/LaunchDaemons /Library/LaunchAgents 2>/dev/null

ls -la@ ~/Library/LaunchAgents /Users/*/Library/LaunchAgents 2>/dev/null

# Loaded jobs (root + user context differ)
launchctl list

sudo launchctl list

# 🔴 Richer than `list` — full state, Program/args, endpoints, run-at-load, PID
sudo launchctl print system                 # every loaded DAEMON (system domain)
launchctl print gui/$(id -u)                 # every loaded AGENT (your GUI login session)
sudo launchctl print system/<label>          # deep-dive one job (state, program, args, MachServices)
launchctl print gui/$(id -u)/<label>         # deep-dive one agent

# What's DISABLED (attacker may disable a security agent)
sudo launchctl print-disabled system
launchctl print-disabled gui/$(id -u)

# Dump every plist's Program/ProgramArguments quickly
for p in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist ~/Library/LaunchAgents/*.plist; do
  echo "== $p =="; plutil -p "$p" 2>/dev/null | grep -A3 -iE 'Program|Label'
done

# Verify the target binary's signature
codesign -dvvv /path/to/target_binary 2>&1

spctl -a -vv /path/to/target_binary 2>&1
```

---

## Hunting Guidance

🔴 For each non-Apple plist, score these:

| Signal | Suspicious when… |
|---|---|
| `ProgramArguments` path | In `/tmp`, `/Users/Shared`, `~/Library/…`, `/private/var/…`, hidden dirs |
| Interpreter payload | `sh -c`, `bash`, `python`, `osascript`, `curl … | bash`, base64 blobs |
| Target signature | Unsigned, ad-hoc, revoked, or Team ID ≠ a known app |
| `Label` vs location | `com.apple.*` outside `/System/Library` (masquerade) |
| Timestamps | Plist **birth/mtime** recent vs system age (cross-ref FSEvents/quarantine) |
| `RunAtLoad` + `KeepAlive` | Both set = aggressive, resilient persistence |
| Orphan | Plist exists but the app/vendor it claims doesn't |

### 1. Unusual / unauthorized plists (orphans, masquerades)

```bash
# Every non-Apple plist (Apple's own live only in /System/Library)
ls -1 /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents /Users/*/Library/LaunchAgents 2>/dev/null

# 🔴 ORPHAN — target executable no longer exists (dangling/stale persistence, e.g. a half-removed product)
for p in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist ~/Library/LaunchAgents/*.plist; do
  b=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null || /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)
  [ -n "$b" ] && [ ! -e "$b" ] && echo "ORPHAN: $p -> $b (missing)"
done

# 🔴 MASQUERADE — com.apple.* label outside /System/Library (Apple never installs there)
grep -lE 'com\.apple\.' /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist ~/Library/LaunchAgents/*.plist 2>/dev/null

# Not backed by any install package (hand-dropped) — cross-ref Install History and Receipts (lsbom / pkgutil --files)
```

### 2. Suspicious payload / unexpected location / interpreter

```bash
# 🔴 Target in a temp / user / world-writable / hidden path
grep -rlE '/tmp/|/private/tmp/|/var/tmp/|/Users/Shared/|/private/var/folders/|/\.[A-Za-z]' \
  /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null

# 🔴 Interpreter / downloader / obfuscation / reverse-shell in the args
grep -rliE 'sh -c|bash|/bin/zsh|python|perl|ruby|osascript|curl|wget|nscurl|base64|eval|/dev/tcp|nc |ncat|xxd' \
  /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null

# 🔴 DYLD injection smuggled via EnvironmentVariables
grep -rl 'DYLD_INSERT_LIBRARIES' /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null

# Odd label/filename — not a normal reverse-DNS vendor prefix (random/gibberish)
ls /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents 2>/dev/null | grep -iE '\.plist$' | grep -vE '^(com|org|io|us|net|app|de)\.'
```

### 3. Timestamps — recently created / modified

```bash
# Plists modified in the last 14 days
find /Library/LaunchDaemons /Library/LaunchAgents ~/Library/LaunchAgents /Users/*/Library/LaunchAgents -name '*.plist' -mtime -14 2>/dev/null

# Birth + mtime for every plist, time-sorted (recent additions bubble up)
for p in /Library/LaunchDaemons/*.plist /Library/LaunchAgents/*.plist ~/Library/LaunchAgents/*.plist; do
  stat -f '%SB | %Sm | %N' "$p"
done 2>/dev/null | sort
```

🔴 A plist whose **birth time is far newer than the OS install** (see `/var/log/install.log`) = a recent implant. Corroborate the drop with **FSEvents** (`Created` on the plist path) and any **quarantine** xattr.

### 4. Verify the target (the decisive check)

```bash
# For a suspect plist's binary $B:
codesign -dvvv "$B" 2>&1 | grep -iE 'Authority|TeamIdentifier|Identifier'   # who signed it (Team ID)

codesign --verify --strict --verbose=4 "$B" 2>&1                            # tampered? ("sealed resource…" = broken)

spctl -a -vv "$B" 2>&1                                                       # notarization / Gatekeeper verdict
```

> ⚠️ **No built-in baseline** on macOS — this is pattern-matching + signature verification, not diffing against a gold image. Signature status (unsigned / ad-hoc / revoked / Team-ID mismatch / broken seal) is the strongest single signal; keep your own known-good plist inventory per fleet image if you want true diffing.

---

## Automated Hunt Script

The [`launchd` module of `scripts/hunt_persistence.sh`](../scripts/hunt_persistence.sh) runs all of the above in one **read-only** pass and flags the outliers (orphan, masquerade, suspicious path, interpreter/downloader, DYLD injection, unsigned/tampered, recently created), showing each target's **signer + notarization**. (The original standalone `hunt_launchd.sh` is kept in [`scripts/archived/`](../scripts/archived/README.md) — its logic was folded into this module.)

```bash
bash hunt_persistence.sh --modules launchd          # your session
sudo bash hunt_persistence.sh --modules launchd     # also reads root-only plists (shown as ??)
```

**Reading the output** — annotated sample:

```
  ok  com.microsoft.update.agent                     [signed: Microsoft Corporation]   # known vendor, nothing tripped
    ??  com.microsoft.teams.TeamsUpdaterDaemon         [unreadable — needs root]

[LOW] com.okta.authentication.service                 # BENIGN: real vendor — flagged only because it updated recently
   path : com.okta.authentication.service.plist
   sig  : signed: Okta, Inc.
   info : RunAtLoad=true KeepAlive=true
   FLAGS: RECENT<14d

[HIGH] com.apple.softwareupdate                        # MALICIOUS (illustrative): everything wrong at once
   path : ~/Library/LaunchAgents/com.apple.softwareupdate.plist
   exec : /Users/Shared/.cache/update
   sig  : unsigned
   info : RunAtLoad=true KeepAlive=true
   FLAGS: APPLE-MASQUERADE SUSPICIOUS-PATH UNSIGNED RECENT<14d
```

| Flag | Means |
|---|---|
| `ORPHAN` | plist points to a **missing** binary (dangling / half-removed product) |
| `APPLE-MASQUERADE` | `com.apple.*` label **outside** `/System/Library` (Apple never installs there) |
| `SUSPICIOUS-PATH` | target in `/tmp`, `/Users/Shared`, `/private/var/folders`, a hidden dir |
| `INTERP/DOWNLOAD` | args run a shell/interpreter/downloader (`sh -c`, `python`, `curl`, `base64`, `nc`, …) |
| `DYLD-INJECT` | `DYLD_INSERT_LIBRARIES` set (dylib injection into the launched process) |
| `UNSIGNED` / `SIG-INVALID` | target isn't signed / fails `codesign --verify` (tampered) |
| `RECENT<14d` | plist created/modified in the last 14 days (recent implant — **or** a legit update) |

> 🔴 One flag is a **lead, not a verdict**. `RECENT<14d` alone is usually a normal update; **stacked** flags (`APPLE-MASQUERADE + SUSPICIOUS-PATH + UNSIGNED`) is what a real implant looks like. The `sig` Team ID is the decisive check — cross it against the vendor you expect.

---

## Logs

```bash
# launchd activity (loads, spawns, throttle/respawn)
log show --predicate 'subsystem == "com.apple.launchd"' --info --last 7d

# A specific label being spawned
log show --predicate 'subsystem == "com.apple.launchd" AND eventMessage CONTAINS[c] "com.example.persistence"' --info --last 30d
```

> Cross-ref the Unified Logs – System & Kernel note (launchd) and FSEvents (when the plist was dropped).

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Non-Apple plist launching from `/tmp`/`~/Library`/hidden dir | Malware persistence |
| `com.apple.*` plist in `/Library` or `~/Library` | Masquerade |
| Target binary **unsigned / ad-hoc / revoked** | Untrusted payload |
| `RunAtLoad` + `KeepAlive` on an unknown job | Resilient auto-start |
| Plist created recently with `quarantine` xattr / FSEvents drop | Freshly planted |
| `ProgramArguments` running `curl|bash` / base64 / osascript | Stager/downloader |
| `EnvironmentVariables` with `DYLD_INSERT_LIBRARIES` | Dylib injection |
| Orphan plist (no matching app) | Leftover or hidden persistence |

---

## Resources

- go4launch.dmg (lesson demo): https://cdn.13cubed.com/downloads/go4launch.dmg
- Apple `launchd.plist` man page: `man launchd.plist`
