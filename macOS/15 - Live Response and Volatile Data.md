# Live Response and Volatile Data

The commands you run **first** on a live macOS host — the volatile state that vanishes on reboot: running processes, open files, network connections, loaded kernel/system extensions, logged-in users, mounted volumes, and the live software inventory. All **read-only**; capture in **order of volatility** (network + memory-resident state before disk-resident state). Run as **root** (`sudo`) for full visibility — many fields (other users' processes, `procinfo`, pf rules) are privileged.

> 🔴 A process is the one artifact an attacker can't fully hide from the kernel. Signature, path, parent, open sockets, and injected libraries of a *running* PID are ground truth — reconcile them against the persistence surfaces (LaunchAgents/Daemons, cron, login items) that started them. See [`12 - Persistence Mechanisms`](<12 - Persistence Mechanisms/Launch Daemons and Launch Agents.md>) and the [`hunt_persistence.sh`](scripts/hunt_persistence.sh) sweep.

## Contents
- [Quick Triage](#quick-triage)
- [Order of Volatility](#order-of-volatility)
- [Running Processes](#running-processes)
- [Single-Process Deep Dive](#single-process-deep-dive)
- [Open Files and Handles (lsof)](#open-files-and-handles-lsof)
- [Network Connections and Listeners](#network-connections-and-listeners)
- [Loaded Kernel and System Extensions](#loaded-kernel-and-system-extensions)
- [Logged-in Users and Sessions](#logged-in-users-and-sessions)
- [Mounted Volumes and Disks](#mounted-volumes-and-disks)
- [Installed Software and Package Managers](#installed-software-and-package-managers)
- [Injected Libraries and Signature of a Live Process](#injected-libraries-and-signature-of-a-live-process)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# --- NETWORK: established connections + listeners, with owning PID/user (most volatile) ---
sudo lsof -nP -i | grep -E 'LISTEN|ESTABLISHED'

sudo netstat -anv -p tcp; sudo netstat -anv -p udp

# --- PROCESSES: full tree with start time, parent, user, cpu/mem, full command ---
ps -Axo pid,ppid,user,%cpu,%mem,lstart,command

# --- PROCESSES RUNNING FROM SUSPICIOUS PATHS ---
ps -Axo pid,ppid,user,command | grep -Ei '/tmp/|/Users/Shared/|/private/var/folders/|/\.[A-Za-z]| /Users/[^/]+/(Public|Library/Caches)/' | grep -v grep

# --- DELETED-BUT-RUNNING binaries (classic fileless / self-deleting malware) ---
sudo lsof -nP +L1 | grep -i txt        # link count 0 = unlinked while executing

# --- launchd-managed jobs actually loaded right now ---
launchctl list | grep -v '^-\t0'       # non-zero PID or last-exit != 0

# --- LOADED non-Apple kernel + system extensions ---
kextstat 2>/dev/null | grep -vi com.apple; systemextensionsctl list

# --- WHO is on the box + boot time ---
who -a; w; last -5

# --- MOUNTS (look for RAM disks, DMGs, network shares) ---
mount; diskutil list

# --- LIVE SOFTWARE INVENTORY ---
brew list --versions 2>/dev/null; brew list --cask 2>/dev/null
pkgutil --pkgs | tail -40
system_profiler SPApplicationsDataType 2>/dev/null | grep -A4 -iE 'Obtained from: Unknown|Signed by: \(none\)'
```

---

## Order of Volatility

Capture from most-to-least ephemeral so an action of yours doesn't destroy earlier evidence.

| Order | State | Command family |
|---|---|---|
| 1 | Network connections / routing / ARP | `lsof -i`, `netstat`, `arp -a`, `nettop` |
| 2 | Running processes + their memory/env | `ps`, `launchctl procinfo`, `vmmap` |
| 3 | Open files / handles | `lsof` |
| 4 | Logged-in users / sessions | `who`, `w`, `last` |
| 5 | Loaded kernel/system extensions | `kextstat`, `kmutil`, `systemextensionsctl` |
| 6 | Mounts / removable media | `mount`, `diskutil` |
| 7 | Live software inventory (disk-backed but analyst-facing) | `brew`, `pkgutil`, `system_profiler` |

Then image memory (see [`13 - Evidence Collection/Acquiring Memory`](<13 - Evidence Collection/Acquiring Memory.md>)) and the disk.

---

## Running Processes

```bash
# Full listing: pid, parent, uid, start (absolute), elapsed, cpu, mem, FULL command
ps -Axo pid,ppid,uid,user,%cpu,%mem,lstart,etime,command

# Sort by CPU / memory (crypto-miners, beacons)
ps -Axo pid,ppid,user,%cpu,%mem,command -r | head -20      # -r = by cpu
top -l 1 -o cpu -n 20

# Process ancestry for one PID (walk ppid up to launchd=1)
ps -Ao pid,ppid,command | awk -v p=<PID> 'function up(x){while(x>1){for(i in P)if(pid[i]==x){print cmd[i];x=ppid[i];next}}} {pid[NR]=$1;ppid[NR]=$2;$1=$2="";cmd[NR]=$0} END{up(p)}'

# Everything launchd is supervising (label ↔ PID ↔ last exit code)
launchctl list
sudo launchctl print system            # rich: services, their state, paths, exit reasons
launchctl print gui/$(id -u)           # the console user's Aqua session agents
```

| `ps` column | Meaning / why it matters |
|---|---|
| `ppid` | Parent. `1` = launchd (daemon/orphaned); a shell/interpreter parent on a "service" is suspicious |
| `lstart` | Absolute start time — pivot into unified logs / FSEvents at that moment |
| `etime` | Elapsed run time — a "system" process alive only minutes is odd |
| `uid`/`user` | Ran-as identity; root processes launched by a user context deserve scrutiny |
| `command` | Full argv — look for `sh -c`, `base64 -d`, `curl`, `-e`/`-c` one-liners, odd paths |

`launchctl list` PID column: a number = running; `-` = loaded, not running. Third column is the **last exit status** (repeated non-zero = crash-looping payload).

---

## Single-Process Deep Dive

```bash
PID=<PID>

# Executable path on disk (resolve the running image)
ps -p "$PID" -o comm=; sudo lsof -nP -p "$PID" | awk '$4=="txt"{print $NF}' | head

# Environment of the running process (BSD 'e' flag) — look for DYLD_*, proxies, secrets
ps eww -p "$PID"

# Rich launchd view (root): argv, env, ports, sandbox, path, domain — best single command
sudo launchctl procinfo "$PID"

# Everything this PID has open: files, sockets, dylibs, cwd
sudo lsof -nP -p "$PID"

# Memory regions + mapped libraries (injected dylibs show here)
sudo vmmap "$PID" 2>/dev/null | grep -iE '\.dylib|__TEXT' | head -30
```

---

## Open Files and Handles (lsof)

```bash
sudo lsof -nP                       # everything (n=no DNS, P=no port-name lookup → fast)
sudo lsof -nP -p <PID>              # by process
sudo lsof -nP -u <user>            # by user
sudo lsof -nP /path                # who has THIS file/dir open
sudo lsof -nP +D /Users/Shared     # everything open under a dir
sudo lsof -nP +L1                  # UNLINKED files still open (link count < 1) — deleted-but-running
```

| `lsof` FD / TYPE | Meaning |
|---|---|
| `cwd` / `rtd` | Process working dir / root dir |
| `txt` | The executable image (and its linked libraries) |
| `REG` | Regular file — data/config/log the process touches |
| `IPv4`/`IPv6` | A socket — pair with the network section |
| `(deleted)` after path, or `+L1` link count `0` | File unlinked while in use — fileless / anti-forensics |

---

## Network Connections and Listeners

```bash
# Connections + listeners WITH owning process (macOS netstat lacks -p, so use lsof)
sudo lsof -nP -i                          # all
sudo lsof -nP -iTCP -sTCP:LISTEN          # listeners only
sudo lsof -nP -iTCP -sTCP:ESTABLISHED     # active sessions

# Kernel socket table (no PID, but authoritative state), routes, ARP cache
netstat -anv
netstat -rn                               # routing table — rogue default route / gateway
arp -a                                    # ARP cache — lateral movement / spoofing

# Per-process bandwidth (live) — good for spotting a quiet beacon
sudo nettop -P -l 1

# Host firewalls (both exist on macOS)
sudo pfctl -s rules 2>/dev/null; sudo pfctl -s nat 2>/dev/null          # packet filter (pf)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate --listapps   # app firewall

# DNS the box is currently using (rogue resolver / DoH redirection)
scutil --dns | grep 'nameserver\[' | sort -u
```

| Look for | Why |
|---|---|
| `LISTEN` on an unexpected high port owned by an unsigned/`/tmp` binary | Backdoor / implant C2 listener |
| `ESTABLISHED` to a raw IP (no reverse DNS), odd port | Beacon / exfil channel |
| A rogue entry in `netstat -rn` default route, or foreign `arp -a` | MITM / lateral movement |
| Non-Apple nameserver in `scutil --dns` | DNS hijack / DoH exfil |

Cross-reference network **events over time** in [`09 - Unified Logs/Firewalls and Proxies`](<09 - Unified Logs/Firewalls and Proxies.md>) and [`Wi-Fi and Network`](<09 - Unified Logs/Wi-Fi and Network.md>).

---

## Loaded Kernel and System Extensions

```bash
# Loaded kexts in the running kernel (legacy interface, still works)
kextstat | grep -vi com.apple             # non-Apple = review

# Modern kext interface (Big Sur+)
kmutil showloaded --list-only 2>/dev/null | grep -vi com.apple

# System Extensions (user-space replacements for kexts: ES, network, DriverKit)
systemextensionsctl list

# Kernel/AMFI/boot events over time
log show --last 1h --predicate 'sender == "kernel"' --info 2>/dev/null | tail -40
```

A non-Apple **Endpoint Security** or **Network** system extension sees all events / all traffic — legitimate for EDR/VPN, a rootkit-tier foothold otherwise. Verify signer and expected vendor. Detail in [`12 - Persistence Mechanisms/System Extensions`](<12 - Persistence Mechanisms/System Extensions.md>).

---

## Logged-in Users and Sessions

```bash
who -a            # all sessions incl. run-level, boot time, dead procs
w                 # who + what each is running now (idle, JCPU, WHAT)
users             # bare list of logged-in usernames
last -20          # login history (tty/console/ssh) newest first
last reboot       # boot history
who -b; uptime    # last boot time / how long up

# Console (GUI) vs remote — remote SSH sessions show a host in 'last'/'w'
last | grep -vE 'console|reboot|shutdown|wtmp' | head    # remote-ish logins
```

Pivot deeper on account artifacts (Secure Token, admin membership, hidden users) in [`03 - Users and Groups`](<03 - Users and Groups.md>).

---

## Mounted Volumes and Disks

```bash
mount                              # every mount + flags (nobrowse, nodev, read-only)
df -h                              # capacity per mount
diskutil list                     # physical + APFS containers/volumes
diskutil apfs list                # APFS detail (roles, encryption, snapshots)
diskutil info /Volumes/<name>     # a specific mount (filesystem, device, encryption)
hdiutil info                      # attached DMG/sparse images (staging / delivery)
```

| Look for | Why |
|---|---|
| A DMG/sparseimage in `hdiutil info` | Malware delivery/staging still attached |
| `nobrowse` mount in an odd path | Hidden mount used to conceal files |
| RAM disk / tmpfs holding executables | Anti-forensic staging (vanishes on reboot) |
| Unexpected network share (`smbfs`/`nfs`) in `mount` | Lateral movement / exfil target |

---

## Installed Software and Package Managers

Different hosts ship different managers — enumerate all that are present. All read-only.

```bash
# --- Homebrew (formulae = CLI, casks = GUI apps) ---
brew list --versions                 # installed formulae + versions
brew list --cask                     # installed casks (GUI apps)
brew leaves                          # top-level installs (not pulled in as deps)
brew outdated                        # stale = potential vulnerable software
brew services list                   # brew-managed background services (persistence!)
brew --prefix                        # install root (/opt/homebrew or /usr/local)

# --- Apple installer receipts (what .pkg installers put down) ---
pkgutil --pkgs                       # all package IDs with a receipt
pkgutil --pkg-info <pkg-id>          # install time, version, volume
pkgutil --files  <pkg-id>            # files a package delivered

# --- Installed .app inventory with signing + provenance (very useful) ---
system_profiler SPApplicationsDataType   # Name, Version, Obtained from, Signed by, Last Modified
system_profiler SPInstallHistoryDataType # software install history (updates, pkgs)
mdfind "kMDItemContentType == 'com.apple.application-bundle'"   # every app Spotlight knows

# --- Other managers (run whichever exist) ---
mas list                             # Mac App Store apps (if 'mas' installed)
port installed                       # MacPorts
conda list; conda env list           # Anaconda/Miniconda/Miniforge
pip3 list; npm ls -g --depth=0       # language ecosystems (often overlooked)
softwareupdate --history             # OS/security update history
```

| Source | Gives you |
|---|---|
| `brew leaves` / `brew list --cask` | What was *intentionally* installed vs pulled as a dependency |
| `brew services list` | Background services brew started — a persistence surface many miss |
| `pkgutil --pkg-info` | **Install timestamp** of a package — timeline pivot |
| `SPApplicationsDataType` "Obtained from" | `Mac App Store` / `Identified Developer` / **`Unknown`** ← unsigned/side-loaded |
| `SPApplicationsDataType` "Last Modified" | Bundle tamper / repackage indicator |
| `softwareupdate --history` | Whether the OS is patched; gaps around the incident window |

> The [`hunt_persistence.sh`](scripts/hunt_persistence.sh) `apps` module already prints **NAME · SHA-256 · SIGNATURE** for non-Apple apps and enumerates package managers (brew, MacPorts, Fink, Nix, pkgin, conda) with version/prefix — use it for the hash-level inventory, and the commands here for interactive follow-up.

---

## Injected Libraries and Signature of a Live Process

```bash
PID=<PID>; BIN=$(sudo lsof -nP -p "$PID" | awk '$4=="txt"{print $NF; exit}')

# Injection via environment (the #1 userland technique)
ps eww -p "$PID" | tr ' ' '\n' | grep -E 'DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH'

# Libraries actually mapped into the live process (non-system = suspect)
sudo vmmap "$PID" 2>/dev/null | grep -i '\.dylib' | grep -vE '/usr/lib/|/System/' 

# Static link table of the on-disk binary (compare to what's mapped live)
otool -L "$BIN"

# Signature + notarization + entitlements of the running binary
codesign -dv --verbose=4 "$BIN" 2>&1
codesign --verify --deep --strict "$BIN" 2>&1 && echo "seal OK" || echo "TAMPERED/UNSIGNED"
codesign -d --entitlements :- "$BIN" 2>/dev/null      # over-broad entitlements?
spctl -a -vv "$BIN" 2>&1                               # Gatekeeper assessment (.app; slow/online)
```

Deep dylib-hijack / injection theory (weak links, `@rpath`, DYLD variants) lives in [`12 - Persistence Mechanisms/Dylib Hijacking and Injection`](<12 - Persistence Mechanisms/Dylib Hijacking and Injection.md>).

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Process image in `/tmp`, `/Users/Shared`, `/private/var/folders`, or a dotted/hidden dir | Dropped payload running from a staging path |
| `lsof +L1` / path shows `(deleted)` for a live executable | Self-deleting / fileless malware still resident |
| Parent (`ppid`) is a shell/interpreter for a long-lived "service" | Injected or spawned implant, not a real daemon |
| `DYLD_INSERT_LIBRARIES` in a running process's env | Dylib injection into that process |
| Non-system `.dylib` mapped in `vmmap` but absent from the binary's `otool -L` | Library injected at runtime |
| `codesign --verify` fails, or binary is unsigned, on a network-listening process | Tampered / untrusted implant |
| `LISTEN` on an unexpected port owned by an unsigned/odd-path binary | Backdoor C2 listener |
| `ESTABLISHED` to a bare IP with no rDNS on an odd port, low bandwidth, periodic | Beaconing / exfil |
| Non-Apple **Endpoint Security**/**Network** system extension you can't attribute to known EDR/VPN | Rootkit-tier monitoring foothold |
| `brew services` running a service you don't recognize | Persistence via a package-manager service |
| App "Obtained from: **Unknown**" / "Signed by: (none)" in `system_profiler` | Side-loaded / unsigned software |
| DMG/sparseimage attached in `hdiutil info`, or `nobrowse` mount in an odd path | Malware staging / concealment |
| Rogue default route (`netstat -rn`) or non-Apple resolver (`scutil --dns`) | MITM / DNS hijack |

---

## Resources

- `man` pages: `ps(1)`, `lsof(8)`, `netstat(1)`, `nettop(1)`, `launchctl(1)`, `vmmap(1)`, `codesign(1)`, `diskutil(8)`, `pkgutil(1)`, `system_profiler(8)`
- [`13 - Evidence Collection/Acquiring Memory`](<13 - Evidence Collection/Acquiring Memory.md>) — capture RAM after volatile triage
- [`13 - Evidence Collection/Unix-like Artifacts Collector (UAC)`](<13 - Evidence Collection/Unix-like Artifacts Collector (UAC).md>) — automate the collection above
- [`scripts/hunt_persistence.sh`](scripts/hunt_persistence.sh) — read-only persistence sweep that reconciles these processes/sockets against their launch points
