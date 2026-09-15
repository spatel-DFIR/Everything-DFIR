# hunt_persistence.sh

Read-only triage script for **live macOS investigations** — built to run on a host you can't disturb. It enumerates every documented macOS persistence surface (13 modules), scores each item from anomaly signals, and prints findings ranked by severity to give the analyst a short true-positive queue.

> Part of the [macOS DFIR Triage Scripts](../) → cross-ref [`12 - Persistence Mechanisms/`](<../../12 - Persistence Mechanisms/>).

## Safety contract

- **Read-only / non-destructive** — only read commands (`plutil`, `codesign`, `defaults`, `launchctl print`, `stat`, `find`, `ls`). Nothing is written, loaded, unloaded, or killed.
- **Console-only** — no report file, no temp files, no footprint left on the host.
- **`root`-optional** — run with system privileges (`sudo`) for full coverage; degrades gracefully otherwise — unreadable root-only items are shown as `??` and a warning banner prints if not run as root.

---

## RTR deployment (Real Time Response)

**For Falcon Insight or endpoint response platforms with size constraints**, use `hunt_persistence_loader.sh`:

```bash
# The loader is 27KB (fits RTR's 40KB limit)
bash hunt_persistence_loader.sh deep --min-severity notable
bash hunt_persistence_loader.sh quick
```

The loader script embeds a gzip+base64-compressed copy of `hunt_persistence.sh` (57KB → 27KB), making it deployable to endpoint response platforms with strict size limits. **All arguments and modes work identically** — pass the same arguments as you would to `hunt_persistence.sh` directly.

---

## Quick start

```bash
# Full sweep, but only show items worth acting on (the analyst's queue)
sudo bash hunt_persistence.sh deep --min-severity notable

# Fast triage of the core surfaces
sudo bash hunt_persistence.sh quick

# Re-check a single surface after a lead
sudo bash hunt_persistence.sh --modules ssh,cron

# Scope recency to the incident window
sudo bash hunt_persistence.sh deep --since 2026-06-01

# Add a full Gatekeeper/notarization pass (slower) — or just confirm unsigned items
sudo bash hunt_persistence.sh deep --gk
sudo bash hunt_persistence.sh quick --gk-unsigned
```

## Modes (one is required)

| Mode | Surfaces |
|---|---|
| `quick` | `launchd` `cron` `loginitems` `sysext` `helpers` `ssh` `authmods` `apps` |
| `deep` | quick **+** `dylib` `shell` `longtail` `trojan` `profiles` |
| `--modules a,b,c` | Run only the named modules (overrides mode) |

Every run also prints **host posture** (SIP + Gatekeeper) at the top and a **user-account inventory + last 5 logins** at the bottom, regardless of mode.

## Options

| Option | Effect |
|---|---|
| `--days N` | Recency window for the `RECENT` flag (default `14`) |
| `--since YYYY-MM-DD` | Flag items modified on/after this date (overrides `--days`) |
| `--min-severity T` | Only print findings `>= T` (`high`\|`notable`\|`low`; default `low`). Counts are still tallied. |
| `--verbose` | Show the full detail block for **every** item, including clean ones (not just the compact `ok` line) |
| `--gk` | Run `spctl` (Gatekeeper) on **every** item regardless of status → appends `[notarized]` / `[not notarized]`. Thorough but **slow** (~4–24s/app; may hang on network-restricted hosts). *(alias: `--gatekeeper-check`)* |
| `--gk-unsigned` | Run `spctl` **only** on unsigned items — confirms Gatekeeper would reject them; near-instant on a clean host. *(alias: `--gatekeeper-check-unverified`)* |
| `--modules a,b,c` | Restrict to specific modules |
| `--user NAME` | Limit per-user surfaces to one user (default: all of `/Users/*`) |
| `--suspect-only` | Hide the clean `ok` inventory lines |
| `-h`, `--help` | Usage |

**Coverage is always full** — every item on the host is scanned regardless of options, and every per-user artifact is checked for **all users plus root** (`/Users/*` + `/var/root`; needs `sudo` to read other users' files). The recency window (`--days`/`--since`) only adds a `RECENT` *highlight* flag to items changed inside it; it never limits what is checked. **All timestamps are shown in UTC.** Empty sections print a section-specific message (e.g. `No cron, at, or periodic jobs present`, else `Nothing present`) so you know a check ran and found nothing (vs. failed). A **flag legend** at the end explains every flag that fired.

The run opens with a compact header (version, author, UTC run time, hostname, the exact command) — so a saved copy of the output is self-documenting. If not run as root, a warning banner follows:

```
hunt_persistence.sh  v1.18    author: Suvas Patel
Ran at   : 2026-07-02 16:58:15 UTC
Hostname : MacBookPro
Command  : hunt_persistence.sh quick --min-severity notable

!! WARNING: not running as root. Root-only paths (other users, /var/at,
!! sfltool BTM, login/logout hooks, some plists) will be incomplete or shown as ??.
!! Re-run with system privileges (sudo) for full coverage.
```

## Severity tiers

Work top-down. `--min-severity notable` hides the `LOW` context tier.

| Tier | Meaning | Triage |
|---|---|---|
| 🔴 `[HIGH]` | Strong indicator (bad signature, DYLD inject, emond rule, login hook, staged dylib…) | **Act first** |
| 🟠 `[NOTABLE]` | Worth a look (interpreter/downloader, orphan, forced SSH options, ES/network extension…) | Review |
| 🟡 `[LOW]` | Context / expected-but-verify (signed third-party extension, recency alone…) | Confirm & move on |

---

## What it checks — full DFIR checklist

Every location the script enumerates and every signal it evaluates, by module. All checks are read-only.

### Host posture (always, top)
- **SIP** (`csrutil status`) — flags if System Integrity Protection is disabled/weakened.
- **Gatekeeper** (`spctl --status`) — flags if assessments are disabled (unsigned apps allowed).

### User accounts & logins (always, bottom) · `T1136`
- **Accounts** (table): `USER · UID · TYPE · ADMIN · LOGIN-SCRN · CREATED(UTC) · LAST-LOGIN(UTC) · SHELL`. Skips only `_`-prefixed Apple service accounts and non-login shells — **does not blindly skip low UIDs** (a non-`_` UID<500 account with an interactive shell is TA account-hiding → `LOW-UID-ACCOUNT`).
  - **ADMIN** = *effective* membership via `dsmemberutil checkmembership` — catches **AD-group-mapped admins** that reading the local `admin` group misses.
  - **TYPE** from `AuthenticationAuthority`: `local` / `mobile-AD` (cached) / `network`. On an **AD-bound** Mac (`dsconfigad -show`) a note flags that pure network accounts live in the AD node and aren't fully enumerable locally.
  - **LOGIN-SCRN** hidden if `IsHidden` **or** in loginwindow `HiddenUsersList` → `HIDDEN-ACCOUNT` (HIGH). Created inside recency window → `NEW-ACCOUNT` (NOTABLE).
- **Recent logins:** last 5 from `last` (UTC), printed **above** the summary tally.

### Signatures & verdicts — one consistent vocabulary
| Verdict | Meaning |
|---|---|
| `unsigned` | no code signature |
| `signed: <Vendor>` / `Apple` | valid Developer-ID / Apple signature (default check, `codesign -dvvv`) |
| `invalid (tampered)` | signature present but the on-disk seal is broken (bare binaries + `trojan`) |
| `[notarized]` (appended bracket) | Gatekeeper **accepted** it (only with `--gk` / `--gk-unsigned`) |
| `[not notarized]` (appended bracket) | Gatekeeper **rejected** it — unsigned/unnotarized/revoked (only with `--gk` / `--gk-unsigned`) |

**Default (fast, offline):** shows **who signed it** (`signed: Vendor`) from `codesign -dvvv` (~0.06s). We deliberately **do not run `spctl` (Gatekeeper)** by default: an assessment is **4–24s per app** (online notarization lookup, measured 2m28s for launchd alone) and can hang on network-restricted hosts.

**Opt-in Gatekeeper** (any mode) keeps the signer verdict and **appends the notarization status as its own separate bracket**: `[signed: Vendor] [notarized]` / `[signed: Vendor] [not notarized]`. Unsigned → `unsigned [not notarized]`.
- `--gk` → `spctl` runs on **every item, any status**. `spctl` only truly assesses `.app`/installer bundles; on a **bare binary** it returns *"rejected (the code is valid but does not seem to be an app)"* — that's **not** a notarization failure, so those keep their `signed: Vendor` verdict with **no bracket** (no false positive). Only a genuine rejection (no usable signature / unnotarized / revoked) becomes `[not notarized]`, and a *signed* item that genuinely fails also flags `SIG-INVALID`. Chrome PWAs / stubs that Gatekeeper can't assess get no bracket either.
- `--gk-unsigned` → `spctl` runs **only on unsigned items** (fast; confirms they'd be rejected → `[not notarized]`). Signed items stay bracket-free.

Team IDs appear under `--verbose`.

### `launchd` — Launch Agents & Daemons · `T1543.001/.004`
- **Locations:** `/Library/LaunchDaemons`, `/Library/LaunchAgents`, and every user's `~/Library/LaunchAgents`.
- **Per plist:** resolves `Program` / `ProgramArguments[0]` and checks —
  - target executable **missing** (`ORPHAN`)
  - `com.apple.*` label outside `/System` (`APPLE-MASQUERADE`)
  - target/args in `/tmp`, `/var/tmp`, `/Users/Shared`, `/private/var/folders`, hidden dir (`SUSPICIOUS-PATH`)
  - interpreter / downloader in args (`INTERP/DOWNLOAD`)
  - `DYLD_INSERT_LIBRARIES` in `EnvironmentVariables` (`DYLD-INJECT`)
  - code signature of the target (`UNSIGNED` / `SIG-INVALID` / signer verdict; `[not notarized]` bracket under `--gk`)
  - plist recency (`RECENT`)
- **Context surfaced** (not scored): `RunAtLoad`, `KeepAlive`, and trigger keys — `StartInterval` (beaconing), `StartCalendarInterval`, `WatchPaths` / `QueueDirectories` (event-triggered), `StartOnMount`, `LimitLoadToSessionType`.
- **Unreadable** plists (need root) are surfaced as `??`.

### `cron` — Cron / at / periodic · `T1053.003/.002`
- **Locations:** `/etc/crontab`, per-user `/usr/lib/cron/tabs/*`, `/etc/cron.d/*`, `/etc/periodic/{daily,weekly,monthly}/*`, `/usr/local/etc/periodic/*`, `/etc/{daily,weekly,monthly,periodic}.local`, `/var/at/jobs/*`.
- **Checks:** any user crontab present (`CRONTAB-PRESENT`); interpreter/downloader or suspicious path in a job line; non-standard/local periodic scripts (`NONSTANDARD-PERIODIC` / `LOCAL-PERIODIC-OVERRIDE`); queued `at` jobs (`AT-JOB-PRESENT`); `atrun` enabled — disabled by default (`ATRUN-ENABLED`); recency.

### `loginitems` — Login / Background Items · `T1547.015`
- **Modern BTM:** parses `sfltool dumpbtm` — each item's executable checked for orphan / suspicious path / signature, with its **disposition** (`[enabled]`/`[disabled]`) shown. **BTM = Background Task Management** (Ventura+): the full on-disk database of every registered login item, agent, and daemon (enabled *and* disabled) — a **superset** of System Settings > Login Items, which shows only the enabled, user-facing subset. That's why the CLI lists more than the Settings pane.
- **SMLoginItem helpers:** `/Applications/*/Contents/Library/LoginItems/*.app` and per-user `~/Applications/...` — path / signature / recency (`SMLOGINITEM-HELPER`).
- **Reopen-at-login:** resolves every `TALAppsToRelaunchAtLogin` entry and checks it (`RELAUNCH-AT-LOGIN`).
- **Legacy:** `~/Library/Preferences/com.apple.loginitems.plist` (`LEGACY-LOGINITEM`).
- **Login/Logout hooks:** `LoginHook` / `LogoutHook` in each user's + `/var/root`'s `com.apple.loginwindow.plist` — deprecated, run a script at login/logout, almost nothing legit uses them (`LOGIN-HOOK` / `LOGOUT-HOOK`, HIGH).

### `sysext` — System Extensions & Kexts · `T1547.006`
- **System extensions:** `systemextensionsctl list` — every non-Apple extension resolved to its **on-disk `/Library/SystemExtensions/<uuid>/…systemextension` bundle**, whose signature is verified directly (not just the Team ID from `list`). Category parsed; Endpoint Security / Network extensions (see all events / all traffic) risk-elevated (`HIGH-RISK-SYSEXT`).
- **Kexts (on disk):** `/Library/Extensions/*.kext` — third-party kext with signature + recency (`THIRD-PARTY-KEXT`).
- **Kexts (loaded):** `kextstat` — non-Apple kexts loaded in the kernel that may lack a `/Library/Extensions` bundle (`THIRD-PARTY-KEXT-LOADED`).

### `helpers` — Privileged Helper Tools · `T1543.004`
- **Location:** `/Library/PrivilegedHelperTools/*`.
- **Checks:** signature (broken = tampered helper), suspicious path, recency. **Helper↔daemon link** — a helper with no referencing LaunchDaemon is odd (`HELPER-NO-DAEMON`). **Trust link** — if an installed app declares the helper via `SMPrivilegedExecutables`, the Team ID it requires must match the helper's actual signing Team ID; a mismatch (`HELPER-TRUST-MISMATCH`, HIGH) = hijack/fake. (Modern `SMAppService` helpers have no such declaration — that's normal and never flagged.)

### `ssh` — SSH keys, config & activity · `T1098.004 / T1563.001`
Every SSH artifact is shown with its **last-modified time (UTC)** so you can tell when SSH was last used within your timeframe.
- **authorized_keys / authorized_keys2** (inbound backdoor keys): presence, forced options (`command=`/`no-pty`/`permitopen=`/`environment=` → `FORCED-OPTIONS`), key count, **last-modified**, recency. Keys on `root`/service accounts → `ROOT-SSH-KEY`.
- **known_hosts** (outbound = lateral movement): count of hosts this account SSH'd *to* + **last-modified** (last outbound SSH).
- **private keys** (`id_*`, `*.pem`): presence + **last-modified** — key material usable for lateral movement.
- **~/.ssh/config:** `LocalCommand` / `ProxyCommand` / `Match exec` / `PermitLocalCommand` (`SSH-CONFIG-EXEC`).
- **sshd_config + sshd_config.d/*:** `ForceCommand`, `AuthorizedKeysCommand`, `PermitRootLogin yes`, non-default (absolute) `AuthorizedKeysFile` (`SSHD-EXEC-DIRECTIVE`).
- **Remote Login:** best-effort check that `sshd` is enabled (`REMOTE-LOGIN-ON`).

### `authmods` — Sudoers · PAM · legacy rc · `T1548.003 / T1556.003 / T1037`
- **sudoers** (`/etc/sudoers`, `/etc/sudoers.d/*`): passwordless sudo (`NOPASSWD` → `SUDO-NOPASSWD`) and a specific non-root/non-`%group` user granted sudo (`SUDOERS-USER-GRANT`) — privilege backdoors. *(needs root to read)*
- **PAM** (`/etc/pam.d/*`): any module reference that isn't a standard `pam_*.so` — an absolute-path or planted `.so` = auth backdoor (`PAM-CUSTOM-MODULE`, HIGH); recency flags a TA editing `sshd`/`sudo`/`login` PAM config.
- **legacy rc** (`/etc/rc.local`, `/etc/rc.common`, `/etc/rc.server`): `rc.local` isn't present by default on macOS → its presence is flagged (`RC-LOCAL-PRESENT`); interpreter/downloader content and recency are checked too.

### `dylib` — Dylib injection / hijack · `T1574.006/.001/.004` *(deep)*
- **DYLD env:** global `launchctl getenv DYLD_INSERT_LIBRARIES` (`DYLD-GLOBAL`); `/etc/launchd.conf` and `~/.launchd.conf` `DYLD`/`setenv` lines.
- **Staged libraries:** unsigned `.dylib` / `.so` dropped in `/tmp`, `/private/tmp`, `/var/tmp`, `/Users/Shared` (`STAGED-DYLIB`).
- **Hijackable weak-dylib slots:** `otool` scan of third-party app main executables for `LC_LOAD_WEAK_DYLIB` whose target is **missing and in a writable (non-SIP) path** (`WEAK-DYLIB-HIJACKABLE`). SIP-protected paths (`/usr/lib`, `/System`) are excluded — an attacker can't plant there, so weak links to them are never hijackable. `@rpath` references are **resolved** against the binary's `LC_RPATH` list (including `@loader_path`/`@executable_path`); `@loader_path`/`@executable_path` direct refs are resolved too.
- *(DYLD in plists and shell rc is covered by the `launchd` and `shell` modules.)*

### `shell` — Shell & terminal init files · `T1546.004` *(deep)*
- **All shell families**, system-wide and per-user (all users + root): **zsh** (`.zshrc/.zprofile/.zshenv/.zlogin/.zlogout`, `/etc/z*`), **bash** (`.bash_profile/.bashrc/.bash_login/.bash_logout/.profile`, `/etc/bashrc`, `/etc/profile.d/*`), **sh**, **fish** (`~/.config/fish/config.fish`), **tcsh/csh** (`.tcshrc/.cshrc/.login/.logout`, `/etc/csh.*`), **ksh** (`.kshrc`).
- **iTerm2:** auto-launch scripts (`~/Library/Application Support/iTerm2/Scripts/AutoLaunch/*`), dynamic profiles, and profiles configured to run a command / send text at start.
- **Checks (tight, low-FP):** malicious one-liners only — `curl`/`wget`/`nscurl`, `base64`, `/dev/tcp//dev/udp`, `nc -e`/`ncat`, `bash -i`, `python -c`/`perl -e`/`ruby -e`/`osascript -e`, `unset HISTFILE`/`history -c` (`INTERP/DOWNLOAD`); `DYLD_INSERT_LIBRARIES`/`DYLD_LIBRARY_PATH` (`DYLD-IN-RC`). Benign `eval "$(brew shellenv)"`, interpreter names, and `~/.dotfile` paths are **not** flagged.

### `longtail` — emond / auth plugins / folder actions / spotlight · `T1546` *(deep)*
- **emond:** any rule in `/etc/emond.d/rules/*.plist` — empty by default, so any rule is suspect (`EMOND-RULE`, HIGH).
- **Authorization plugins:** `/Library/Security/SecurityAgentPlugins/*.bundle|*.plugin` — signature + recency (`AUTH-PLUGIN`; credential-theft surface).
- **Folder Action scripts:** `~/Library/Scripts/Folder Action Scripts/*` (`FOLDER-ACTION`).
- **Spotlight importers:** non-Apple `/Library/Spotlight/*.mdimporter` + per-user (`MDIMPORTER`).

### `trojan` — Trojanized binaries / apps · `T1554 / T1036` *(deep)*
- **All system binaries:** `codesign --verify` on **every** binary in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/libexec`. These dirs are on the **SIP/SSV-sealed system volume**, so every Mach-O in them is Apple-signed by construction — three swap/tamper cases are flagged (**HIGH**, near-zero FP on a healthy host):
  - `SIG-INVALID` — signed but **broken seal** (patched/tampered in place)
  - `UNSIGNED-SYSBIN` — **unsigned Mach-O** (swapped-in implant). Unsigned *scripts/text* are legitimate here and skipped (a `file` type check gates this — `/usr/bin` alone has ~260 legit unsigned scripts).
  - `NON-APPLE-SYSBIN` — valid signature but **not Apple's `Software Signing` leaf authority** (re-signed/replaced binary; catches the attacker who re-signs the trojaned binary so `--verify` passes). *Note: matching "Apple Root CA" would be wrong — Developer-ID certs chain to it too; the platform-binary leaf is `Software Signing`.*
- **Installed apps:** `codesign --verify` on every `/Applications/*.app` — reports **only genuine seal failures** (skips merely-unsigned apps and benign `__pycache__` drift to avoid noise).
- **Cost:** this fully hashes every bundle/binary — ~3 min on a typical host. It's the reason `trojan` is `deep`-only. No network, so it won't hang.

### `profiles` — Configuration Profiles · `T1478` *(deep)*
- **Installed profiles:** `profiles show -all` — every configuration profile (can install LaunchDaemons, trusted certs, proxies, restrictions) surfaced for review (`INSTALLED-PROFILE`).
- **MDM management:** `/Library/Managed Preferences` presence = device is under profile/MDM management.

### `apps` — Installed non-Apple apps inventory *(quick + deep)*
- `NAME · SHA-256(main executable) · SIGNATURE`, **grouped by location**: `/Applications`, `/Applications/Utilities`, `/opt`, and every user's `~/Applications` (skips `com.apple.*` bundle IDs). Pure inventory (not scored) for IOC matching. **Chrome/Chromium PWAs** are tagged — they share one `app_mode_loader` shim, so their hashes collide by design (identity is in `Info.plist`, not the binary).
- Signature is the **signer verdict** (`signed: <Vendor>` / `Apple` / `unsigned`) from `codesign -dvvv` — fast, no `spctl`, in **both** quick and deep. Gatekeeper notarization (`[notarized]` / `[not notarized]`) is appended only when you pass `--gk` / `--gk-unsigned` (independent of mode).
- **Package managers** (Homebrew, MacPorts, Fink, Nix, pkgsrc/pkgin, and conda/miniconda/miniforge — system *and* per-user installs) are probed at their documented install paths and listed separately with **version · install prefix · log dir**. Different hosts ship different managers, so all are probed and whichever are present get listed; version/prefix come from the tool itself (never hardcoded). Their casks (GUI apps) already appear above; their CLI packages live under the prefix.

> **On the `trojan` module and benign seal drift:** some legitimately-signed apps break `codesign --verify` without being tampered — e.g. LibreOffice writes Python bytecode caches (`__pycache__/*.pyc`) into its own bundle on first run. The module recognizes pyc-only drift and does **not** flag it; a real modification (changed files, missing resources, added dylibs/executables) still flags `SIG-INVALID`.

> **No baseline on macOS.** This is pattern-matching + signature verification, not diffing against a gold image. Signature status (unsigned / ad-hoc / broken seal / unexpected Team ID) is the single strongest signal — keep a per-fleet known-good inventory if you want true diffing.

---

## Reading a finding

```
[HIGH] com.apple.softwareupdate                 ← label / item name
   path : ~/Library/LaunchAgents/com.apple.softwareupdate.plist   ← where the persistence lives
   exec : /Users/Shared/.cache/update            ← target executable (omitted when it equals path)
   sig  : unsigned                               ← signer / signature verdict (+ Team ID under --verbose)
   info : RunAtLoad=true KeepAlive=true          ← context (trigger keys, disposition, mtime…)
   FLAGS: APPLE-MASQUERADE SUSPICIOUS-PATH UNSIGNED   ← why it fired (stacked flags drive the tier)
```

The `exec` line is printed only when it differs from `path`; the `sig` line is omitted for config-file items that have no signature. The run ends with a tally: `X HIGH · Y NOTABLE · Z LOW · N clean · M unreadable`.
`??` lines and the `unreadable` count mean **re-run with root** for full coverage.

## FLAGS reference

| Flag | Meaning |
|---|---|
| `SIG-INVALID` | Signed code fails `codesign --verify` (tampered) **or** a signed item is genuinely Gatekeeper-rejected under `--gk` |
| `UNSIGNED-SYSBIN` | Unsigned **Mach-O** in a SIP/SSV-sealed system dir (`/bin`,`/usr/bin`…) — every platform binary there is Apple-signed (swapped-in implant) |
| `NON-APPLE-SYSBIN` | System binary with a valid signature but **not Apple's `Software Signing` authority** — re-signed / replaced platform binary |
| `UNSIGNED` | Target has no code signature |
| `APPLE-MASQUERADE` | `com.apple.*` label living outside `/System` |
| `DYLD-INJECT` / `DYLD-GLOBAL` / `DYLD-IN-RC` | `DYLD_INSERT_LIBRARIES` in a plist / launchd env or launchd.conf / shell rc |
| `STAGED-DYLIB` | `.dylib`/`.so` sitting in a drop dir (`/tmp`, `/Users/Shared`…) |
| `SUSPICIOUS-PATH` | Target in `/tmp`, `/var/tmp`, `/Users/Shared`, `/private/var/folders`, hidden dir |
| `INTERP/DOWNLOAD` | Args/content call a downloader / decoder / inline interpreter |
| `ORPHAN` | Referenced target executable is missing (stale persistence) |
| `LOGIN-HOOK` / `LOGOUT-HOOK` | Deprecated loginwindow hook runs a script at login/logout |
| `HIDDEN-ACCOUNT` / `NEW-ACCOUNT` | Hidden real user account / account created inside the recency window |
| `WEAK-DYLIB-HIJACKABLE` | `LC_LOAD_WEAK_DYLIB` target missing in a writable (non-SIP) path |
| `INSTALLED-PROFILE` | Configuration profile installed / device under MDM management |
| `HELPER-NO-DAEMON` | Privileged helper with no referencing LaunchDaemon |
| `HELPER-TRUST-MISMATCH` | Helper's signing Team ID ≠ the Team ID its client app requires (hijack/fake) |
| `THIRD-PARTY-KEXT-LOADED` | Non-Apple kext loaded in the kernel (`kextstat`) |
| `EMOND-RULE` | Any emond rule (emond is empty by default — always suspect) |
| `ATRUN-ENABLED` / `AT-JOB-PRESENT` | `at` scheduling enabled / jobs queued (disabled by default) |
| `FORCED-OPTIONS` / `SSH-CONFIG-EXEC` / `SSHD-EXEC-DIRECTIVE` | SSH `command=`/forced opts, `ProxyCommand`/`LocalCommand`, `ForceCommand`/`AuthorizedKeysCommand`/redirected `AuthorizedKeysFile` |
| `ROOT-SSH-KEY` | `authorized_keys` on root / a service account |
| `SUDO-NOPASSWD` | sudoers grants passwordless sudo (`NOPASSWD`) — privilege backdoor |
| `SUDOERS-USER-GRANT` | a specific user (not root/`%admin`) granted sudo |
| `PAM-CUSTOM-MODULE` | PAM config references a non-standard / planted `.so` module — auth backdoor |
| `RC-LOCAL-PRESENT` | `/etc/rc.local` present (not default on macOS) — legacy boot execution |
| `REMOTE-LOGIN-ON` | sshd (Remote Login) is enabled — confirm expected |
| `AUTH-PLUGIN` | Third-party SecurityAgent authorization plugin (credential-theft surface) |
| `HIGH-RISK-SYSEXT` | Third-party Endpoint Security / Network system extension (sees all events / traffic) |
| `THIRD-PARTY-SYSEXT` / `THIRD-PARTY-KEXT` | Non-Apple system extension / kext |
| `SMLOGINITEM-HELPER` / `RELAUNCH-AT-LOGIN` / `LEGACY-LOGINITEM` | Login-item persistence variants |
| `FOLDER-ACTION` / `MDIMPORTER` | AppleScript folder action / Spotlight importer plugin |
| `NONSTANDARD-PERIODIC` / `LOCAL-PERIODIC-OVERRIDE` / `CRONTAB-PRESENT` | Cron/periodic persistence variants |
| `RECENT<Nd` | Config created/modified inside the recency window (cross-ref FSEvents) |

The run ends with a **legend** that spells out every flag that actually fired — so you never have to look flags up.

## Notes & limitations

- **One flag is a lead, not a verdict.** `RECENT` alone is usually a normal update; stacked flags (`APPLE-MASQUERADE + SUSPICIOUS-PATH + UNSIGNED`) is what an implant looks like. The signer Team ID is the decisive check — cross it against the vendor you expect.
- **Two review-worthy surfaces stay elevated on purpose:** authorization plugins and any signature-seal failure are `NOTABLE`/`HIGH` even when likely legitimate — for DFIR, err toward the analyst confirming them.
- The `trojan` module runs `codesign --verify` across `/Applications` (2 calls per app) — it is the **slow** part of a `deep` run.
- `dylib` intentionally does **not** scan whole home directories (avoids flooding on dev `.so`/venv files) — only classic drop dirs.
- A `codesign` "Permission denied" (e.g. setuid binaries when run non-root) is counted as `unreadable`, **never** as `SIG-INVALID`.

---