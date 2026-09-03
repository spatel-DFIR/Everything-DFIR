# DPRK Fake-Job and Contagious Interview Playbook

The end-to-end playbook for **North-Korea-attributed developer targeting** — fake recruiters lure engineers (crypto/web3/fintech especially) into running a "coding assessment" repo or an npm/pip package that ships **BeaverTail** (JS stealer/loader) → **InvisibleFerret** (Python backdoor), often with a trojanized "interview" video-call app. Sibling campaign **Operation Dream Job** (Lazarus) uses trojanized job PDFs/apps against defense/aerospace/crypto staff.

> 🔴 **This is a developer-credential and supply-chain incident.** The crown jewels aren't just the login Keychain — they're **cloud/CI-CD tokens, git & package-registry credentials, signing keys, source code, and crypto wallets**. Assume anything the developer could push, publish, or deploy is now attacker-reachable. Scope for **onward supply-chain compromise**, not just this endpoint.

## Contents
- [Attack Chain at a Glance](#attack-chain-at-a-glance)
- [Quick Triage (60-second confirm)](#quick-triage-60-second-confirm)
- [Stage 1 — The Lure (fake recruiter / assessment)](#stage-1--the-lure-fake-recruiter--assessment)
- [Stage 2 — Run the Project (BeaverTail)](#stage-2--run-the-project-beavertail)
- [Stage 3 — Second Stage (InvisibleFerret + remote access)](#stage-3--second-stage-invisibleferret--remote-access)
- [Identification: Evidence by Source](#identification-evidence-by-source)
- [Scoping: What Was Stolen (dev-secret priority)](#scoping-what-was-stolen-dev-secret-priority)
- [Build the Timeline](#build-the-timeline)
- [Containment and Eradication](#containment-and-eradication)
- [Credential and Supply-Chain Reset](#credential-and-supply-chain-reset)
- [Fleet / Org Hunt](#fleet--org-hunt)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Attack Chain at a Glance

| Stage | Action | Primary evidence |
|---|---|---|
| 1. Lure | Fake recruiter (LinkedIn/Telegram/email) → "clone this repo / install this package for the assessment" | Comms *(email/IM)*, browser hist *(separate repo)*, quarantine/where-froms, `git`/`npm` in history |
| 2. Run project | `npm install` / `npm start` runs **BeaverTail** hidden (obfuscated) in a server/config file → steals browser+wallets, pulls stage 2 | Shell history, `node` process lineage, `package.json`/`node_modules`, obfuscated blob |
| 3. Second stage | **InvisibleFerret** (Python) backdoor: C2, keylog, exfil, drops **AnyDesk** for hands-on access | `python` process, hidden `~/.` files, unexpected AnyDesk, C2 network |

MITRE: **T1566** (spearphishing/social) · **T1195.001** (compromised dev tooling / packages) · T1059.007 (JS) → T1059.006 (Python) · T1204.002 · T1555 (creds/wallets) · **T1219** (AnyDesk remote access) · T1041 (exfil).

---

## Quick Triage (60-second confirm)

```bash
# 1. Recently cloned "assessment" repos + when their deps were installed
find ~ -maxdepth 4 -name package.json -mtime -45 2>/dev/null | grep -viE 'node_modules|Library' 
ls -la ~/ | grep -iE 'demo|assessment|task|interview|test|challenge|assignment'

# 2. node/python running from a home/temp path, and their ancestry (Terminal → npm → node → python)
pgrep -fl 'node|python' | grep -viE '/Applications|/usr/'
#   → walk the tree with 15b - Process Trees and Execution Lineage

# 3. Obfuscated loader inside a project's server/config JS (BeaverTail signature)
grep -rElZ --include='*.js' 'eval\(|Buffer\.from\(|require\(.child_process.\)|_0x[0-9a-f]{4}' ~/ 2>/dev/null | tr '\0' '\n' | grep -viE 'node_modules/.*/(dist|min)' | head

# 4. Remote-access tooling the attacker drops for hands-on control
ls -la /Applications/AnyDesk.app ~/Applications/AnyDesk.app 2>/dev/null; pgrep -fl -i 'anydesk|rustdesk|osascript'

# 5. git clone / npm install of an unknown repo in shell history
grep -hriE 'git clone .*(github|gitlab|bitbucket)|npm (i|install|run|start)|pip[0-9]? install' /Users/*/.zsh_history /Users/*/.bash_history 2>/dev/null | tail -40
```

A `node`/`python` process descending from Terminal, spawned inside a freshly-cloned "assessment" repo, reaching out to a raw-IP C2 — with AnyDesk appearing — is a confirmed Contagious Interview.

---

## Stage 1 — The Lure (fake recruiter / assessment)

Contact comes via **LinkedIn/X recruiter DMs, Telegram, or email** — a lucrative role, then a "technical assessment": clone a repo (GitHub/GitLab/Bitbucket), an npm/pip package to run a "demo," or a trojanized **interview video-call app** (e.g., fake "MiroTalk"/"FCCCall"). Targets skew **crypto/web3/blockchain/fintech**.

```bash
# The downloaded repo/app + its origin (Mark-of-the-Web)  → ../11 - Artifacts/Download Provenance and Quarantine.md
sqlite3 ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2 \
 "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString
  FROM LSQuarantineEvent ORDER BY 1 DESC LIMIT 25;"

# The clone itself
grep -hriE 'git clone' /Users/*/.zsh_history /Users/*/.bash_history 2>/dev/null
```
Recruiter comms (LinkedIn message, email, Telegram) are the lure evidence — pull them from the mail/IM store and, for web LinkedIn, the **browser repo**. The repo URL and any npm package name are prime IOCs.

---

## Stage 2 — Run the Project (BeaverTail)

The malicious code is usually a **single heavily-obfuscated line** buried in a legitimate-looking `server/`, `config`, or middleware JS file — it runs on `npm install` (postinstall script) or `npm start`. BeaverTail steals browser data + crypto wallets and downloads the Python second stage.

```bash
# The project + its dependency manifest (look for a postinstall script + odd deps)
cat <repo>/package.json                            # scripts.postinstall / unknown deps = red flag
ls -la <repo>/node_modules/ | head

# Hunt the obfuscated loader across the repo (BeaverTail hides in server/config JS)
grep -rEn 'eval\(|Buffer\.from\([^)]*base64|require\(.child_process.\)|atob\(|_0x[0-9a-f]{4,}|https?:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}' <repo> 2>/dev/null | grep -v node_modules | head

# node running the project + child processes
pgrep -fl node
#   parent Terminal → npm → node → (curl/python) = 15b - Process Trees and Execution Lineage
```

| BeaverTail tell | Where |
|---|---|
| `scripts.postinstall` running a node/curl command | `package.json` |
| Obfuscated `_0x…` / `Buffer.from(…,'base64')` / `eval(atob(…))` blob | a `server`/`config`/middleware `.js` |
| Hardcoded raw-IP C2 URL in JS | same file |
| Browser profile + wallet-extension reads by `node` | unified log / `lsof -p <node-pid>` |

---

## Stage 3 — Second Stage (InvisibleFerret + remote access)

BeaverTail pulls **InvisibleFerret**, a multi-module **Python backdoor**: C2 tasking, keylogging, browser/creds exfil, and it often installs **AnyDesk** for interactive access. Persistence via LaunchAgent is common.

```bash
# Python second stage — often runs hidden scripts from home/temp
pgrep -fl python
find ~ /tmp /var/folders -maxdepth 3 -name '*.py' -mtime -45 2>/dev/null | head
ls -la ~/.n2 ~/.npl ~/.pyp ~/.cache/pip 2>/dev/null    # names vary — look for recent hidden dot-dirs

# Remote-access drop (hands-on-keyboard) — a strong DPRK-stage tell
ls -la /Applications/AnyDesk.app ~/Downloads/*AnyDesk* 2>/dev/null
sudo log show --last 7d --predicate 'process CONTAINS "AnyDesk"' 2>/dev/null | tail

# Persistence + live C2
sudo bash ../scripts/hunt_persistence.sh deep     # (run from macOS/ root: scripts/hunt_persistence.sh)
sudo lsof -nP -i | grep -E 'ESTABLISHED|SYN_SENT'
```

---

## Identification: Evidence by Source

| Source | What it proves | Note |
|---|---|---|
| Recruiter comms (mail/IM/LinkedIn) | Social-engineering lure + attacker identity | mail/IM store, **browser repo** |
| `git clone` / `npm install` in history | The developer ran the malicious project | [`../04 - Shells`](<../04 - Shells and Command History.md>) |
| `package.json` postinstall + obfuscated JS | BeaverTail loader | — |
| `node` → `python` process lineage | Stage-2 execution chain | [`../15b - Process Trees`](<../15b - Process Trees and Execution Lineage.md>) |
| Quarantine / where-froms | Repo/app download origin | [`../11 - Quarantine`](<../11 - Artifacts/Download Provenance and Quarantine.md>) |
| AnyDesk install / logs | Interactive remote access (T1219) | — |
| Hidden `~/.` python dirs | InvisibleFerret staging | — |
| Live network / logs | C2 endpoint | [`../15 - Live Response`](<../15 - Live Response and Volatile Data.md>) |
| LaunchAgents | Persistence | [`hunt_persistence.sh`](../scripts/hunt_persistence.sh) |

---

## Scoping: What Was Stolen (dev-secret priority)

Developer machines hold the keys to the kingdom — scope **outward** from the endpoint:

| Assume stolen | Where it lives | Impact |
|---|---|---|
| 🔴 **Cloud / CI-CD tokens** | `~/.aws`, `~/.config/gcloud`, `~/.azure`, `~/.kube`, CI env, `~/.netrc` | Pivot to prod/cloud, poison pipelines |
| 🔴 **Git & package-registry creds** | `~/.git-credentials`, `~/.config/gh`, `~/.npmrc`, `~/.pypirc`, keychain | Push malicious code / publish trojaned packages (**supply chain**) |
| 🔴 **Code-signing / notarization keys** | Keychain, provisioning profiles | Sign malware as your org |
| 🔴 **Crypto wallets / seeds** | Browser extensions, desktop wallets, files | Direct theft — move funds now |
| Source code + `.env` secrets | Repos, `.env`, config | IP theft + embedded secrets |
| SSH keys | `~/.ssh` | Lateral movement |
| Login Keychain + browser creds/cookies | as in any stealer | Session/identity theft |

---

## Build the Timeline

```
[recruiter comms]  lure / assessment sent                     (Stage 1)
[quarantine/hist]  repo cloned / package installed            (Stage 1→2)
[shell hist]       npm install|start  under Terminal          (Stage 2)  ← initial access
[node lineage]     node → curl/python                         (Stage 2→3)
[python + hidden]  InvisibleFerret staged                     (Stage 3)
[AnyDesk logs]     remote-access tool installed               (Stage 3)  ← hands-on-keyboard
[network]          C2 beacon / exfil                          (Stage 3)
```
Anchor with `knowledgeC` (Terminal/IDE usage), FSEvents (repo + hidden-dir writes), and `node_modules` install mtimes.

---

## Containment and Eradication

Full procedures in [`../16 - Remediation and Containment`](<../16 - Remediation and Containment.md>); the DPRK-specific short path:

```bash
# 1. Kill the chain (node, python, remote-access) and confirm C2 drops
sudo pkill -9 -f 'node|python|AnyDesk'
sudo lsof -nP -i | grep ESTABLISHED

# 2. Remove persistence (unload+disable+delete, then verify) — sweep:
sudo bash ../scripts/hunt_persistence.sh deep

# 3. Remove the malicious project + stages + remote-access tool
rm -rf <repo> <repo>/node_modules <hidden-python-dirs>
sudo rm -rf /Applications/AnyDesk.app ~/Applications/AnyDesk.app
```
Endpoint cleanup is necessary but **the supply-chain reset below is what contains the incident.**

---

## Credential and Supply-Chain Reset

This is where a developer-targeted case is actually resolved:

1. **Reset login password**; treat the **login Keychain as fully compromised** — rotate everything in it.
2. **Rotate all developer secrets** — cloud/CI-CD tokens, git creds, `~/.npmrc`/`~/.pypirc` registry tokens, SSH keys, code-signing keys — **revoke server-side**, don't just delete files.
3. **At the IdP:** revoke all sessions, reset MFA, reset password (stolen cookies bypass MFA).
4. **Crypto wallets:** move funds immediately if seeds/keys were on the box.
5. 🔴 **Supply-chain audit** — the real blast radius:
   - Review every **commit / branch / tag** the dev pushed and every **package version they published** during the exposure window for tampering.
   - **Rotate CI/CD pipeline secrets** and any deploy keys the machine held.
   - Check for **new/malicious releases** to internal or public registries under the dev's identity.
   - Invalidate and reissue any **signing identities** the box could use.

---

## Fleet / Org Hunt

DPRK runs these at scale — assume the "recruiter" hit more of your engineers:

```bash
# IOCs to hand to EDR/SIEM: repo URL, npm/pip package name, C2 host/IP, AnyDesk install, payload hashes
shasum -a 256 <stage-files> 2>/dev/null
echo '<repo-url>  <package-name>  <c2-host>  AnyDesk'
```
Hunt across dev endpoints for: the **repo URL / package name** in shell history & proxy logs, `node`/`python` **children of Terminal** reaching raw-IP C2, **AnyDesk** installs, and the obfuscated-JS pattern. Warn engineering about the recruiter lure; check package-registry audit logs for suspicious publishes org-wide. → [`macOS Malware and Threat Landscape ▸ DPRK`](<macOS Malware and Threat Landscape.md>).

---

## Red Flags

| 🔴 Finding | Meaning |
|---|---|
| `node`/`python` child of Terminal running from a cloned "assessment" repo | Contagious Interview execution |
| `package.json` **postinstall** running node/curl, or obfuscated `_0x…`/`Buffer.from(base64)` in a server JS | BeaverTail loader |
| Hidden `~/.` python dir created during a job "interview" | InvisibleFerret staging |
| **AnyDesk/RustDesk** appearing around the same time | DPRK hands-on remote access |
| `node`/`python` reading browser profiles + crypto-wallet paths | Wallet/cred theft |
| Outbound to a **raw IP** from `node`/`python` after an `npm install` | Stage-2 pull / C2 |
| Any of the above on a machine with **cloud/CI-CD/signing** access | Supply-chain emergency — scope outward |

---

## Resources
- [`macOS Malware and Threat Landscape`](<macOS Malware and Threat Landscape.md>) — DPRK/Lazarus cluster reference (RustBucket, KANDYKORN, 3CX, BeaverTail/InvisibleFerret)
- [`ClickFix and Infostealer Playbook`](<ClickFix and Infostealer Playbook.md>) — sibling social-engineering → stealer chain
- [`../16 - Remediation and Containment`](<../16 - Remediation and Containment.md>) · [`../15b - Process Trees and Execution Lineage`](<../15b - Process Trees and Execution Lineage.md>) · [`../15 - Live Response`](<../15 - Live Response and Volatile Data.md>)
- **Terms:** "Contagious Interview" / "DeceptiveDevelopment" / "Famous Chollima" / "Operation Dream Job"; **BeaverTail**, **InvisibleFerret**. Objective-See & vendor writeups for current hashes/IOCs.
