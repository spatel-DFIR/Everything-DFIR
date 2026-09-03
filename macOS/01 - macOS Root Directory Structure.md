# macOS Root Directory Structure

Map of the macOS filesystem for triage: where evidence lives, what each directory *is*, what it's used for, and what to pull from it. macOS is a single UNIX tree rooted at `/` (no drive letters) — every disk, external, network share, and mounted DMG hangs off `/`.

Two macOS-specific things to keep in mind throughout:
- **Library "domains"** — the name `Library` exists at 3 levels (System / all-users / one-user). Which one tells you the **scope** of an artifact (§4).
- **APFS split (Catalina 10.15+)** — what looks like one tree is a read-only **System** volume + writable **Data** volume joined by firmlinks. Evidence ≈ Data volume (§3).

## Contents
- [Quick Triage](#quick-triage)
- [Quick Triage Map](#quick-triage-map)
- [Top-Level `/` Directories](#top-level--directories)
- [`/private` Tree](#private-tree)
- [APFS Split-Volume Layout (Catalina 10.15+)](#apfs-split-volume-layout-catalina-1015)
- [The `/Library` Domains](#the-library-domains)
- [Red Flags](#red-flags)

---

## Quick Triage

Quick sweeps across the directory structure to surface malicious activity. Run read-only; on a dead-box, point paths at the mounted **Data volume**.

```bash
# --- PERSISTENCE: enumerate every launchd job location ---
ls -la /Library/LaunchDaemons /Library/LaunchAgents \
       /System/Library/LaunchDaemons /System/Library/LaunchAgents \
       /Users/*/Library/LaunchAgents 2>/dev/null

# Flag non-Apple-signed programs referenced by launchd plists
for p in /Library/Launch*/*.plist /Users/*/Library/LaunchAgents/*.plist; do
  bin=$(/usr/libexec/PlistBuddy -c 'Print :Program' "$p" 2>/dev/null \
     || /usr/libexec/PlistBuddy -c 'Print :ProgramArguments:0' "$p" 2>/dev/null)
  [ -n "$bin" ] && { codesign -dvv "$bin" 2>&1 | grep -qi 'Authority=Apple' \
     || echo "SUSPECT: $p -> $bin"; }

done

# --- DROPPERS / STAGING: executables in world-writable & temp dirs ---
find /tmp /private/var/tmp /Users/Shared /private/var/folders \
     -type f -perm +111 2>/dev/null

# Recently modified files in persistence & binary dirs (last 7 days)
find /Library/LaunchDaemons /Library/LaunchAgents /Users/*/Library/LaunchAgents \
     /usr/local/bin /Library/Application\ Support -type f -mtime -7 2>/dev/null

# --- NEW SOFTWARE: apps installed in the last 30 days ---
find /Applications /Users/*/Applications -maxdepth 3 -name Info.plist -mtime -30 2>/dev/null

# Software-install history (text log)
grep -Ei 'installed|PackageKit' /var/log/install.log 2>/dev/null | tail -50

# --- HIDDEN PAYLOADS: dotfiles in homes/shared (minus the usual) ---
find /Users -maxdepth 3 -name '.*' -type f 2>/dev/null \
  | grep -vE '/\.(DS_Store|localized|CFUserTextEncoding|Trash|zsh_history|bash_history|zprofile|zshrc)'

# --- EXTERNAL MEDIA / iOS PAIRING ---
ls -la /Volumes 2>/dev/null

ls -la /private/var/db/lockdown 2>/dev/null            # paired iPhones/iPads

# --- TAMPER: disabled launchd jobs (security tools turned off) ---
/usr/libexec/PlistBuddy -c Print /private/var/db/com.apple.xpc.launchd/disabled.plist 2>/dev/null

# --- PRIVILEGE USE: last sudo per user (ticket mtimes) ---
ls -la /private/var/db/sudo/ts/ 2>/dev/null
```

---

## Quick Triage Map

Hit these in roughly this order on a mounted image or live box:

1. 🔴 `/Users/<user>/Library` — user-attributable activity (the goldmine)
2. 🔴 `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `~/Library/LaunchAgents` — persistence
3. 🔴 `/private/var/db/diagnostics` (+ `uuidtext`) — Unified Log
4. 🔴 `/private/var/db/dslocal/.../users` — accounts + password hashes
5. `/.fseventsd`, `/.Spotlight-V100` — file activity + metadata
6. `/private/var/log` — plain-text logs (`install.log` = software history)
7. `/Volumes` + mount records — external media / DMGs

> On Catalina+, confirm System vs Data volume. User evidence = **Data volume** (`Macintosh HD - Data`, mounted at `/System/Volumes/Data`).

---

## Top-Level `/` Directories

| Path | What it is / used for | DFIR meaning |
|---|---|---|
| 🔴 `/Users` | Per-user home directories + shared spaces. Where all user-created data and per-user config lives. | Richest user-attributable evidence; each `~/Library` is the goldmine (§4). Details below. |
| 🔴 `/Library` | **Local domain** — system-wide app support, prefs, logs, and persistence applying to **every** user. Writable by admin. | LaunchDaemons/Agents here = prime persistence; system-wide configs and third-party support files. Details in §4. |
| 🔴 `/private` | Holds the *real* `etc`, `var`, `tmp`, `Cores`. Apple tucked the BSD mutable system dirs here. | System logs, databases, temp, and local accounts all live under here (§2). |
| `/System` | The OS itself — read-only, sealed System volume. Almost entirely `/System/Library` + `/System/Applications`. | Apple-signed; Apple's own Launch* live here; unexpected changes = integrity red flag. Details below. |
| `/Applications` | System-wide installed GUI apps (`.app` bundles) + `/Applications/Utilities`. Available to all users. | Installed-software inventory; compare vs download/quarantine history. Bundle anatomy below. |
| `/Volumes` | Mount points for **all non-boot volumes** — externals, DMGs, network shares, extra partitions. The boot volume is the exception (mounted at `/`). | What was mounted and when; folder names reveal external media and opened disk images. Often contains `.DS_Store`. |
| `/usr` | UNIX userland — binaries, libraries, helpers, and **`/usr/local`** for third-party. Read-only except `/usr/local`. | `/usr/local/bin` is a common home for third-party + attacker tooling. Sub-dirs below. |
| `/bin`, `/sbin` | Core CLI binaries needed at boot/single-user: shells (`bash`,`zsh`,`sh`), `ls`,`cp`,`mv`,`rm`,`cat` (`/bin`); admin/network tools `mount`,`fsck`,`ifconfig`,`route` (`/sbin`). | Baseline known-good, Apple-signed; any addition or modification here is suspicious. |
| `/opt` | "Optional" third-party software. **`/opt/homebrew`** = Homebrew default on Apple Silicon. | Primary third-party package location on Apple Silicon Macs (bins, formulae, logs). |
| `/cores` | Process core dumps (disabled by default; `ulimit -c`). | Memory-state evidence of a crashed/exploited process if enabled. |
| `/dev` | Virtual device files — disks (`disk0`,`disk1s1`), terminals (`ttys00x`), pseudo-devices (`null`,`random`). | Live-system only; maps disks/volumes; rarely a dead-box artifact source. |
| `/Network` | Legacy network-resource mount point. | Empty unless network resources/automounts configured. |
| `/net`, `/home` | autofs auto-mount triggers (`/net/<host>`, `/home/<user>` via automounter). | Empty by default; relevant only with automount maps configured. |

### 🔴 `/Users` — structure

| Item | Contents |
|---|---|
| `/Users/<user>/` | `Desktop`, `Documents`, `Downloads`, `Movies`, `Music`, `Pictures`, `Public`, `Library` (hidden), plus dotfiles (`.zsh_history`, `.ssh/`, `.zprofile`, `.viminfo`) |
| `/Users/Shared/` | Inter-user shared space; world-writable. Often abused for staging payloads/tools (no single-user attribution) |
| `/Users/Guest/` | Guest account home; wiped at logout but remnants may survive |
| `.localized` | Marker enabling localized folder display names |
| Deleted users | May leave a `.<user>.<UID>` shadow dir or a DMG under `/Users/Deleted Users/` |

### `/System` — what's inside

| Path | Contains / used for | DFIR meaning |
|---|---|---|
| `/System/Library/` | OS's own Library: kexts (`Extensions/`, `.kext`), frameworks, `CoreServices` (Finder, SystemUIServer, `SystemVersion.plist` = OS version/build), 🔴 `LaunchDaemons`/`LaunchAgents`, `PrivateFrameworks` | Apple's signed autostarts — establish a baseline; `SystemVersion.plist` confirms OS build |
| `/System/Applications/` | Apple's stock apps (Mail, Safari, Notes…) | Moved here from `/Applications` on Catalina+ |
| `/System/Volumes/` | Mount root exposing the split-volume layout: `Data`, `Preboot`, `Recovery`, `VM` (swap/sleepimage), `Update`, `Hardware`, `iSCPreboot`, `xarts` | `Data` = the writable Data volume where evidence lives (§3); `VM` holds swap/`sleepimage`; `Preboot`/`Recovery` hold boot + FileVault unlock material |

### `/usr` — sub-dirs

| Path | Used for | DFIR meaning |
|---|---|---|
| `/usr/bin` | Apple-shipped user binaries (`ssh`,`curl`,`python3`,`sqlite3`,`log`,`plutil`) | Signed baseline; your own analysis tools (`log`, `plutil`, `sqlite3`) live here |
| `/usr/sbin` | System admin binaries | Baseline admin tooling |
| `/usr/libexec` | Helper daemons launched by others (`trustd`, `secd`, `mdmclient`) | Persistence/abuse hide among helpers; verify signatures |
| 🔴 `/usr/local` | Third-party software (Homebrew on **Intel**, `bin/`, `sbin/`, `lib/`) | Common attacker/third-party drop zone (not Apple-signed) |
| `/usr/share` | Static data, man pages, **`/usr/share/firmlinks`** | Firmlink list (§3) |
| `/usr/standalone` | Boot/firmware support | Rarely relevant |

### `.app` bundle anatomy (a directory, not a file)

Everything lives under `App.app/Contents/`:

| Item | Contains / used for | DFIR meaning |
|---|---|---|
| 🔴 `Info.plist` | Bundle id (`CFBundleIdentifier`), version, executable name, URL schemes, entitlements refs | Identify the app; spoofed/odd bundle ids; declared capabilities |
| 🔴 `MacOS/<binary>` | The actual **Mach-O** executable | The thing that runs; analyze/hash, check architecture |
| `_CodeSignature/` | Code-signing data (`CodeResources`) | Verify signature/notarization; tampering = unsigned or broken seal |
| `Resources/` | Icons, nibs, localized strings, embedded assets | Bundled scripts/payloads sometimes hide here |
| `Frameworks/` | Bundled private frameworks/dylibs | Injected/malicious dylibs; dylib hijack targets |
| `Library/LaunchServices/` | Privileged helper tools (SMJobBless) | Root helper persistence path |

🔴 Always check: code signature validity, bundle id vs. real publisher, and the Mach-O itself.

### Hidden root items (`.`-prefixed, on the Data volume)

| Path | What it is / used for | DFIR meaning |
|---|---|---|
| 🔴 `/.fseventsd` | **FSEvents** daemon store — gzip'd logs (`0000000000xxxxxx`) of filesystem *changes* per directory, plus a `fseventsd-uuid` identifying the volume | Reconstruct create/modify/rename/delete activity even after files are gone; event IDs give ordering. Per-volume (also on externals) |
| 🔴 `/.Spotlight-V100` | **Spotlight** metadata index — `Store-V2/<UUID>/store.db` + `.store.db` | Filenames, timestamps, `kMDItem` attributes, traces of since-deleted files. Per-volume |
| `/.DocumentRevisions-V100` | Backing store for document **Versions** (auto-saved revisions) + `db-V1/` SQLite | Recover earlier versions of edited documents |
| `/.Trashes` | Per-volume trash, `/.Trashes/<UID>/`. Per-user trash is `~/.Trash` | Deleted files + deletion attribution by UID |
| `/.fseventsd`, `/.TemporaryItems`, `/.PKInstallSandboxManager` | Temp / installer scratch areas | Install/runtime remnants |
| `.DS_Store` | Per-folder Finder view state (everywhere, incl. removable media) | Proves a folder existed / was browsed; lists filenames once present even if deleted |

---

## `/private` Tree

`/etc`, `/var`, `/tmp` at root are **symlinks** → `/private/etc`, `/private/var`, `/private/tmp`. Always reason in real paths.

| Path | Contains / used for | DFIR meaning |
|---|---|---|
| 🔴 `/private/var/log` | Plain-text logs: `system.log`, `install.log`, `wifi.log`, `appfirewall.log`, `fsck_*`, `asl/` (legacy Apple System Log) | Human-readable activity. `install.log` = software/update history. Unified Log is NOT here → see `diagnostics` |
| 🔴 `/private/var/db` | System databases (key children below) | High-value system state |
| `…/db/diagnostics` | **Unified Log** `.tracev3` binaries + `timesync/`, `Special/`, `Persist/` | Primary modern log source (process exec, network, auth…). Decode with `uuidtext` |
| `…/db/uuidtext` | String/format catalog referenced by the unified log | Required to fully resolve `.tracev3` messages |
| 🔴 `…/db/dslocal/nodes/Default/users` | **Local accounts** — one `.plist` per user (UID, GID, home, shell, `ShadowHashData` = password hash) | Account enumeration, hash extraction, hidden/rogue/duplicate-UID accounts. Also `.../groups/` for admin membership |
| `…/db/ConfigurationProfiles` | Installed config profiles / MDM payloads + settings | Management context; attacker-installed profiles, restrictions |
| 🔴 `/private/var/folders` | Per-user DARWIN_USER dirs (two random-named levels): `0/` (temp `T/`), `C/` (caches), app scratch | Overlooked: app caches, LaunchServices DB, quarantined temp, provisioning, crash leftovers |
| `/private/var/root` | **root** user's home directory | Root's `~/Library`, `.bash_history`/`.zsh_history`, SSH config |
| `/private/var/vm` | Swap files + `sleepimage` (hibernation = RAM image) | `sleepimage` can yield memory artifacts |
| `/private/var/audit` | OpenBSM audit trail (BSM) if auditing enabled | Detailed kernel-level auth/exec records |
| `/private/etc` | `hosts`, `sudoers`, `ssh/`, `pam.d/`, `synthetic.conf`, `shells`, `paths` | Tampering with hosts/sudoers/SSH; `synthetic.conf` for custom root-level mounts |
| `/private/tmp` | World-writable temporary scratch (→ `/tmp`) | Payload/tool staging; cleared on reboot |

### Other high-value `/private/var/db` children

| Path | Contains | DFIR meaning |
|---|---|---|
| 🔴 `…/db/sudo/ts/<user>` | sudo **timestamp tickets** (one file per user) | mtime ≈ **last successful `sudo`** for that user — proof of privilege use + timing |
| 🔴 `…/db/lockdown/` | **iOS device pairing** records (`.plist` per paired iPhone/iPad, UDID) | A Mac that paired with iDevices; pairing enables backups/extraction |
| 🔴 `…/db/com.apple.xpc.launchd/disabled.plist` | launchd jobs explicitly **disabled** | Attackers disable security agents here; legit services force-disabled = tamper |
| `…/db/CoreDuet/` , `…/db/coreduetd/` | Knowledge/usage aggregation | App/device usage timeline source |
| `…/db/analyticsd/` , `…/db/diagnostics/` | Analytics + unified log | Activity corroboration |
| `…/db/Spotlight/` , `…/db/spindump/` | Index + perf dumps | Misc supporting metadata |

---

## APFS Split-Volume Layout (Catalina 10.15+)

> The boot disk = **two APFS volumes** in one container, presented as one seamless tree.

| Volume | Mode | Holds | DFIR meaning |
|---|---|---|---|
| **System** (`Macintosh HD`) | **read-only** | `/System`, `/bin`, `/usr`, `/sbin`. Big Sur 11+: sealed **Signed System Volume (SSV)** | Any change breaks the seal & won't boot → OS files trustworthy; mods = integrity finding |
| 🔴 **Data** (`Macintosh HD - Data`) | **read-write** | `/Users`, third-party `/Applications`, `/Library`, `/private/var`, hidden artifact dirs (`/.fseventsd`, `/.Spotlight-V100`) | **Where the evidence is** |

How they merge into one tree:
- Data volume mounted at **`/System/Volumes/Data`**.
- **Firmlinks** transparently graft Data-volume dirs into their expected locations (`/Users`, `/Applications`, `/Library`, `/private/var`…). The list: **`/usr/share/firmlinks`**.
- A **synthetic root** (driven by `/etc/synthetic.conf`) provides a writable `/` on top of the read-only system volume.

DFIR impact:
- Imaging/mounting may expose the volumes **separately** → real evidence is on the **Data** volume.
- `/Users/sek/Library` and `/System/Volumes/Data/Users/sek/Library` are the **same files** via firmlink → don't double-count.
- Sealed System volume → OS files trustworthy by default; unexpected modifications = serious integrity finding.

---

## The `/Library` Domains

`Library` exists at 3 levels — the domain = **scope** of the artifact (who it affects).

| Domain | Path | Scope |
|---|---|---|
| System | `/System/Library` | Apple OS only (sealed, read-only) |
| Local | `/Library` | All users on this Mac (admin-writable) |
| User | `~/Library` (`/Users/<user>/Library`) | One user (hidden by default) |

### Key subdirs (present in both `/Library` and `~/Library`)

| Subdir | Contains / used for | DFIR meaning |
|---|---|---|
| 🔴 `LaunchDaemons` | `.plist` job definitions for system services run as **root**, no login required | **Top persistence.** Malicious `.plist` = root-level autostart. Only `/Library` + `/System/Library`, never `~` |
| 🔴 `LaunchAgents` | `.plist` jobs run **per-user at login/GUI session**; exists in all 3 domains incl. `~` | **Top persistence.** `~/Library/LaunchAgents` = classic user foothold |
| 🔴 `Application Support` | Per-app working data, databases, embedded resources/state | App evidence; malware support dirs; browser-extension data |
| 🔴 `Preferences` | Settings as `.plist` (`com.vendor.app.plist`), incl. `ByHost/` (per-hardware) | Config, MRU/recent lists, last-used state, account identifiers |
| `Logs` | App/subsystem text logs + `DiagnosticReports/` (`.crash`, `.spin`, `.ips`) | App activity, crash context (crash reports show what ran + args) |
| `Caches` | Cached app/system data, incl. `com.apple.LaunchServices` | Thumbnails, partial downloads, leftover URLs/IDs |
| `Containers` / `Group Containers` | **Sandboxed app** data — each app gets a mini-`~/Library` at `Containers/<bundle-id>/Data/` | Look here when app data isn't where expected (Messages, Notes, Mail-attachments) |
| `Saved Application State` | Per-app window/session restore (`<bundle-id>.savedState/`) | Proof an app was open + what it had loaded |
| `Keychains` | (`~/Library` only) encrypted credential store `login.keychain-db` | Saved passwords, certs, secure notes (needs creds to decrypt) |
| `StartupItems` | Legacy pre-launchd autostart bundles | Rare/legacy persistence; still worth a glance |

### `~/Library` — user-specific highlights

| Group | Paths / artifacts |
|---|---|
| Comms / web | `Safari/` (`History.db`, `Downloads.plist`), `Mail/`, `Messages/` (`chat.db`), `Cookies/`, `HTTPStorages/` |
| Identity / creds | `Accounts/` (configured internet accounts), `Keychains/`, `IdentityServices/` (iMessage/FaceTime) |
| Activity / state | `Application Support/com.apple.sharedfilelist/` (recent items), `Application Support/Knowledge/knowledgeC.db` (device/app usage), `Suggestions/`, `Autosave Information/` |

### `~/` (home root) dotfiles

| File / dir | Used for | DFIR meaning |
|---|---|---|
| `.Trash` | User's deleted items | Recently deleted files |
| `.zsh_history` / `.bash_history` | Shell command history | Commands the user ran |
| `.ssh/` | Keys, `known_hosts`, `config` | Remote-access targets + lateral movement |
| `.zprofile` / `.zshrc` | Login/shell startup scripts | 🔴 Persistence via injected commands |
| `.viminfo`, `.lesshst` | Editor/pager history | Files viewed/edited |

> Files in `Downloads`/`Documents`/`Desktop` carry the **quarantine** xattr recording origin.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Non-Apple-signed program in `/Library/LaunchDaemons` or `~/Library/LaunchAgents` | Persistence |
| Executable in `/tmp`, `/var/tmp`, `/Users/Shared`, or `/var/folders` | Dropper / staging |
| Recently modified file in a system/persistence dir not matching an update | Tamper / implant |
| Modification (broken seal) on the **System volume** | Serious integrity finding |
| Entries in `com.apple.xpc.launchd/disabled.plist` for security agents | Defense evasion |
| Unexpected device in `/private/var/db/lockdown` | Undisclosed iOS pairing / data exfil path |
| App in `/Applications` with no matching `install.log` entry | Manually planted software |
| Hidden (`.`-prefixed) executable in a home or `/Users/Shared` | Concealed tooling |
