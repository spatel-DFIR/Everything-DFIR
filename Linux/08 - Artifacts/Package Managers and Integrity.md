# Package Managers and Integrity

The package database is a quiet superpower in Linux DFIR, because it's a signed, complete inventory of what *should* be on the system and what those files' hashes *should* be. That gives you two fast, high-value checks that are hard to get any other way: **integrity verification** (`rpm -Va`/`debsums` flag trojaned system binaries like a replaced `sshd`, `ps`, or `ls`) and **install history** (when a package landed, and whether a compiler or `nc` appeared right around the incident). This note covers inventory, history, integrity, maintainer-script persistence, and repo/key tampering across dpkg/apt and rpm/dnf.

> 🔴 Run the integrity check early — it's cheap and it directly catches userland rootkits. A hash mismatch (`5` flag in `rpm -V`) on a core binary in `/bin`, `/sbin`, or `/usr/sbin` means the packaged file was replaced or patched, which is a hallmark of a trojaned system binary. Config files legitimately change; system binaries should not.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Investigation Order](#investigation-order)
- [Package Managers by Distro](#package-managers-by-distro)
- [Integrity Verification](#integrity-verification)
- [Installed Package Inventory](#installed-package-inventory)
- [Install History and Logs](#install-history-and-logs)
- [Package DB State and Backups](#package-db-state-and-backups)
- [File to Package Mapping](#file-to-package-mapping)
- [Inspecting a Package File](#inspecting-a-package-file)
- [Recover the Installed Package](#recover-the-installed-package)
- [Maintainer Scripts as Persistence](#maintainer-scripts-as-persistence)
- [Repositories and Signing Keys](#repositories-and-signing-keys)
- [Unowned Files](#unowned-files)
- [Snap Flatpak AppImage](#snap-flatpak-appimage)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Verify all packages - find modified system binaries (RHEL)
rpm -Va 2>/dev/null | grep -E '^..5|missing'

# Verify all packages (Debian - needs debsums)
debsums -c 2>/dev/null

# Recently installed packages (Debian)
grep " install " /var/log/dpkg.log | tail -30

# Recent transactions (RHEL)
dnf history 2>/dev/null | head; yum history 2>/dev/null | head

# Files not owned by any package (attacker drops)
rpm -qf /usr/bin/* 2>&1 | grep "not owned" 2>/dev/null
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Any trojaned system binary? | `rpm -Va \| grep '^..5'`; `dpkg --verify`; `debsums -c` |
| Privesc capability added to a binary? | `rpm -Va \| grep '^........P'` (the `P` flag) |
| Was the rpmdb rebuilt to hide a swap? | mtime of `/var/lib/rpm/*` vs last real transaction |
| What installed during the incident? | `rpm -qa --last`; `grep install /var/log/dpkg.log`; `dnf history` |
| Post-exploit toolkit added? | fresh `gcc`/`nmap`/`nc`/`socat` in the inventory |
| Who/what ran a transaction? | `dnf history info <ID>` (shows the command line) |
| Which manager is this distro? | Package Managers by Distro table (apt/rpm/apk/pacman/zypper) |
| Integrity on Arch / Alpine? | `pacman -Qkk` / `apk audit --system` |
| Does anything own this file? | `dpkg -S`/`rpm -qf`/`pacman -Qo`/`apk info -W` ("not owned" = drop) |
| Inspect a suspect `.deb`/`.rpm`/`.apk`/`.pkg.tar.zst`? | list files + **read the install scripts** (Inspecting a Package File) |
| Malicious install/remove script? | `rpm -q --scripts <pkg>`; `/var/lib/dpkg/info/*.postinst` |
| Repo / signing subverted? | `gpgcheck=0`, `http:` repos, unexpected GPG keys |
| Held or downgraded to vulnerable? | `apt-mark showhold`; `dnf history \| grep downgrade` |
| Software bypassing the system DB? | `snap/flatpak list`, AppImages, `pip/npm/gem list` |

## Investigation Order

The natural analyst sequence on a suspected-compromise host — cheapest, highest-yield first:

1. **Integrity first** (`rpm -Va` / `dpkg --verify` / `debsums`) — the cheap userland-rootkit / trojaned-binary catch. Do it before anything else.
2. **What changed in the window** — `rpm -qa --last` / `dnf history` / `dpkg.log` + `/var/backups/dpkg.status.*` — did a compiler, `nc`, or a local `.deb`/`.rpm` land near the incident?
3. **Attribute the drops** — unowned binaries + file→package mapping; recover the actual package from the cache.
4. **Supply-chain surface** — maintainer scripts, repos, signing keys, held/downgraded packages.
5. **Off-DB software** — Snap/Flatpak/AppImage and pip/npm/gem, which `rpm`/`dpkg` never see.

## Package Managers by Distro

Linux is not just apt/rpm — identify the distro's manager first (note 01), especially **apk on Alpine**, which is the default in most container images. The five you'll actually meet:

| Manager | Distros | Inventory | Integrity check | Owns a file | History | Repos / DB |
|---------|---------|-----------|-----------------|-------------|---------|------------|
| **dpkg/apt** | Debian, Ubuntu, Mint | `dpkg -l` | `dpkg --verify` / `debsums -c` | `dpkg -S <f>` | `/var/log/dpkg.log`, `apt/history.log` | `/etc/apt/`, `/var/lib/dpkg/status` |
| **rpm/dnf/yum** | RHEL, Fedora, CentOS, Rocky, Alma | `rpm -qa` | `rpm -Va` | `rpm -qf <f>` | `dnf history`, `/var/log/dnf.log` | `/etc/yum.repos.d/`, `/var/lib/rpm` |
| 🔴 **apk** | Alpine (**containers**) | `apk info` | `apk audit --system` | `apk info -W <f>` | file mtimes / DB (no rich log) | `/etc/apk/`, `/lib/apk/db/installed` |
| **pacman** | Arch, Manjaro | `pacman -Q` | `pacman -Qkk` | `pacman -Qo <f>` | `/var/log/pacman.log` | `/etc/pacman.conf`, `/var/lib/pacman/local/` |
| **zypper** (rpm-based) | openSUSE, SLES | `zypper se -i` | `rpm -Va` | `rpm -qf <f>` | `/var/log/zypp/history` | `/etc/zypp/repos.d/`, `/var/lib/rpm` |

🔴 **Alpine (apk) is the one to know for containers.** `apk audit --system` flags modified package files (the apk analog of `rpm -Va`), `apk info -L <pkg>` lists a package's files, and the DB is `/lib/apk/db/installed` (scripts in `/lib/apk/db/scripts.tar`). Alpine uses **musl libc + BusyBox**, so many "binaries" are symlinks to `/bin/busybox` — integrity and behaviour differ from glibc systems. **Arch:** `pacman -Qm` lists *foreign* packages (AUR / not from official repos) — a higher-risk set worth scrutinising. **SUSE** is rpm underneath, so `rpm -Va` and the rpm tooling apply. *(Niche but seen: Gentoo `portage`/`equery`, NixOS immutable `/nix/store`, Void `xbps`.)*

## Integrity Verification

The highest-value package check — the package DB stores each file's expected hash, size, mode, caps, and mtime, so verification flags anything altered after install. Run it **first**.

```bash
# RHEL: verify every installed file against the package DB
rpm -Va

# Focus on binaries; drop the noisy config-file (c) lines
rpm -Va | grep -E '/s?bin/'

rpm -Va | grep -E '^..5'                 # content/hash mismatch anywhere

# Verify one package + verify the package's own GPG signature (not just file hashes)
rpm -V openssh-server coreutils

rpmkeys -Kv openssh-server*.rpm          # signature check (stronger than --checksig)

# Debian: NATIVE integrity check — no debsums needed (dpkg >= 1.17)
dpkg --verify                            # or: dpkg -V

dpkg --verify openssh-server

# Debian: debsums (covers ONLY packages that shipped md5sums)
debsums -c                               # changed files
debsums -a                               # all, incl. config
debsums -l                               # 🔴 packages with NO md5sums = verification BLIND SPOTS

# Arch: verify every package's files (integrity)
pacman -Qkk 2>/dev/null | grep -iE 'warning|altered|missing'

# Alpine (containers): flag modified package files
apk audit --system 2>/dev/null; apk verify /path/*.apk 2>/dev/null

# SUSE = rpm underneath -> use rpm -Va (above)
```

`rpm -V` prints a 9-flag string, then a file-type marker, before each path:

| Flag | Meaning |
|------|---------|
| `S` | Size differs |
| `M` | Mode / permissions differ |
| `5` | 🔴 Digest (hash) differs — content replaced or patched |
| `D` | Device number mismatch |
| `L` | 🔴 Symlink target changed — retargeted to an attacker file |
| `U` / `G` | Owner / group differ |
| `T` | mtime differs |
| `P` | 🔴 Capabilities differ — a privesc primitive added to a binary |
| `.` / `?` | test passed / test could not be performed |

Marker after the flags: `c` = config (change is normal), `d` = doc, `g` = ghost, `l` = license, `r` = readme.

🔴 A `5` on a core binary (`/bin/ls`, `/usr/bin/ps`, `/usr/sbin/sshd`, `/bin/netstat`) is a trojaned binary. A **`P`** (capabilities) on a binary that shouldn't have one is a stealth privesc primitive (→ Permissions). Config files (`c`) change legitimately — filter them out. `debsums`'s blind spot is real: run `debsums -l` to see which packages it *can't* verify, and fall back to `dpkg --verify` or a clean-package hash for those.

> ⚠️ **Prelink false positives (older RHEL/CentOS 6–7):** `prelink` rewrites binaries in place, so `rpm -Va` reports spurious `5` mismatches on prelinked files. Un-prelink before trusting a hit — `prelink -y <binary>` to verify one, `prelink -ua` to undo system-wide — or compare against a freshly pulled package. Modern distros dropped prelink.

## Installed Package Inventory

The inventory is your baseline of legitimate software, and sorting it by install time floats the most recent additions — often the attacker's tooling — to the top.

```bash
# Debian / Ubuntu
dpkg -l

dpkg-query -W -f='${Package} ${Version} ${Status}\n'

apt list --installed 2>/dev/null

# Manually installed (not pulled in as dependencies)
apt-mark showmanual

# RHEL / CentOS / Fedora
rpm -qa

rpm -qa --last | head -40      # sorted by install time

# Arch (-Qm = foreign/AUR packages, not from official repos = higher risk)
pacman -Q; pacman -Qm

# Alpine (containers)
apk info; apk info -vv

# SUSE
zypper se --installed-only 2>/dev/null
```

`rpm -qa --last` is excellent triage — the most recently installed packages appear first, so a compiler, network tool, or random package installed during the incident window jumps out immediately. On Debian, `apt-mark showmanual` distinguishes deliberately-installed packages from dependency noise.

## Install History and Logs

```bash
# Debian: apt history has ATTRIBUTION — the command line + the user who ran it
cat /var/log/apt/history.log            # each block: Commandline:, Requested-By:, Install:/Remove:

grep -E 'Commandline:|Requested-By:' /var/log/apt/history.log*

# The actual terminal output of apt runs (maintainer-script output, download URLs)
cat /var/log/apt/term.log

# Lower-level dpkg action log
grep -E " install | remove | upgrade " /var/log/dpkg.log | tail -40

# RHEL: dnf/yum history
dnf history

dnf history info <ID>                    # what changed + the exact command that ran it

cat /var/log/dnf.log /var/log/yum.log 2>/dev/null

# Arch: full package action log
grep -E 'installed|upgraded|removed|reinstalled' /var/log/pacman.log | tail -40

# Alpine: no rich history — use install order + DB/file mtimes
ls -la /lib/apk/db/installed; tail -40 /var/log/apk.log 2>/dev/null

# SUSE
cat /var/log/zypp/history 2>/dev/null | tail -40
```

🔴 An install of `gcc`/`make` (to compile an exploit or rootkit), compression tools (to stage exfil), `nmap`/`nc`/`socat`, or a random local `.deb`/`.rpm` right around the incident is a strong lead. **Attribution is here:** apt's `history.log` records the full `Commandline:` and the `Requested-By:` user (who ran it via sudo), and `dnf history info <ID>` shows the transaction *and* its command line — scope plus who-did-it in one place. `term.log` even preserves the download URLs and maintainer-script output.

🔴 **A locally-installed `.deb`/`.rpm`** (`apt install ./x.deb`, `dpkg -i /tmp/x.deb`, `rpm -i`) shows a **file path** rather than a repo package name in the history — that bypasses repo signing entirely and is a classic attacker drop. Grep the history for `.deb`/`.rpm` paths outside `/var/cache`.

## Package DB State and Backups

🔴 The package databases themselves are evidence, and Debian keeps **rotated backups** you can diff to reconstruct package changes over time — the Debian analog of `dnf history` (which Debian otherwise lacks).

```bash
# The live package-state DBs (mtime = last package operation)
ls -la /var/lib/dpkg/status /var/lib/dpkg/status-old 2>/dev/null      # Debian
ls -la /var/lib/rpm/Packages* /var/lib/rpm/rpmdb.sqlite 2>/dev/null   # RHEL

# 🔴 Debian rotates the status DB daily to /var/backups — DIFF them to see what changed when
ls -la /var/backups/dpkg.status.* /var/backups/apt.extended_states.* 2>/dev/null

zdiff /var/backups/dpkg.status.1.gz /var/backups/dpkg.status.0.gz 2>/dev/null | grep -E '^[<>] Package:'

# Compare the installed-package set across days to surface a newly-added package
diff <(zgrep -a '^Package:' /var/backups/dpkg.status.1.gz | sort) \
     <(grep  -a '^Package:' /var/lib/dpkg/status | sort)
```

🔴 A package present in today's `status` but absent from yesterday's `/var/backups/dpkg.status.1.gz` was installed in that window — **even if `apt/history.log` was cleared.** The rpmdb equivalent: a recent `/var/lib/rpm` mtime with no matching `dnf history` transaction suggests a `--rebuilddb` cover-up (see Deep Hunts).

## File to Package Mapping

Answering "does anything own this file, and what else did that package bring" both attributes a suspicious file and lets you inspect a package before trusting it.

```bash
# Which package owns a file? (per manager)
dpkg -S /usr/bin/curl           # Debian
rpm -qf /usr/bin/curl           # RHEL/SUSE
pacman -Qo /usr/bin/curl        # Arch
apk info -W /usr/bin/curl       # Alpine

# What files does a package contain?
dpkg -L openssh-server; rpm -ql openssh-server; pacman -Ql openssh; apk info -L openssh
```

🔴 "Not owned by any package" from any of these = a **hand-dropped binary** in a system path — one of the fastest attacker-drop tells. On Alpine, remember most tools symlink to `/bin/busybox`, so `apk info -W` on them resolves to the busybox package.

## Inspecting a Package File

🔴 When you have a suspect **package file** (recovered from `/tmp`, the cache, or a capture), inspect it *without installing* — list its files, and above all **read its install/upgrade scripts**, which are where a malicious package runs code. Every manager's format is just an archive.

| Format | Manager | List / metadata | Extract + read scripts |
|--------|---------|-----------------|------------------------|
| `.deb` | dpkg/apt | `dpkg-deb -I` (meta), `-c` (files) | `dpkg-deb -e x.deb ./c` → `c/{pre,post}inst`; or `ar x` → `control.tar.*` |
| `.rpm` | rpm/dnf | `rpm -qip`, `-qlp`, `--checksig` | `rpm -qp --scripts x.rpm`; `rpm2cpio x.rpm \| cpio -idmv` |
| `.apk` | apk (Alpine) | `tar -tzf x.apk` (it's a gzip tar) | `tar -xzOf x.apk .PKGINFO`; `.pre-install`/`.post-install`/`.trigger` |
| `.pkg.tar.zst` | pacman (Arch) | `tar --zstd -tf x.pkg.tar.zst` | `tar --zstd -xOf x.pkg.tar.zst .INSTALL` (install/upgrade/remove hooks) |

```bash
# .deb — control.tar holds the maintainer scripts, data.tar the files
dpkg-deb -I x.deb; dpkg-deb -c x.deb; dpkg-deb -e x.deb ./ctrl && cat ./ctrl/postinst 2>/dev/null

# .rpm — metadata, files, and the %pre/%post scriptlets
rpm -qip x.rpm; rpm -qp --scripts x.rpm; rpm2cpio x.rpm | cpio -idmv

# .apk (Alpine) — gzipped tar with hidden dotfile metadata/scripts
tar -tzf x.apk; tar -xzOf x.apk .PKGINFO 2>/dev/null; tar -xzOf x.apk .post-install 2>/dev/null

# .pkg.tar.zst (Arch) — zstd tar; .INSTALL carries the hooks
tar --zstd -tf x.pkg.tar.zst; tar --zstd -xOf x.pkg.tar.zst .INSTALL 2>/dev/null

# Always: hash + identify for IOC/intel, then triage any ELF inside (ELF Triage note)
file x.*; sha256sum x.*
```

🔴 The install script (`.postinst` / `%post` / `.post-install` / `.INSTALL`) is the **supply-chain payload location across every manager** — a script there that fetches from the internet, adds a user, drops a cron/systemd unit, or writes an SSH key is malicious regardless of distro.

## Recover the Installed Package

🔴 The actual package that was installed is frequently still **on disk in the cache** — recover it and analyze the real payload (files + maintainer scripts), even after the install.

```bash
# Downloaded packages still in the cache (not cleared unless `apt clean`/`dnf clean`)
ls -la /var/cache/apt/archives/*.deb 2>/dev/null

ls -la /var/cache/dnf/*/packages/*.rpm /var/cache/yum/*/packages/*.rpm 2>/dev/null

# A partially-downloaded / interrupted install
ls -la /var/cache/apt/archives/partial/ 2>/dev/null

# Hunt a MANUAL local install (bypasses repo signing) — a .deb/.rpm dropped and installed by hand
find / -xdev \( -name '*.deb' -o -name '*.rpm' \) ! -path '/var/cache/*' -ls 2>/dev/null

grep -aE '\.(deb|rpm)' /var/log/apt/history.log* /var/log/dpkg.log* 2>/dev/null | grep -vE '/var/cache'

# Then triage the recovered package: list files, read scripts, hash it
dpkg-deb -c recovered.deb; dpkg-deb -e recovered.deb ./ctrl; cat ./ctrl/postinst 2>/dev/null

rpm -qlp recovered.rpm; rpm -qp --scripts recovered.rpm; sha256sum recovered.*
```

🔴 A `.deb`/`.rpm` in `/tmp`, a home dir, or `/var/cache/apt/archives` that maps to a **local file path** in the install history (not a repo package) is a hand-dropped package — extract it and read its maintainer scripts before trusting anything it installed (→ Maintainer Scripts, ELF Triage).

## Maintainer Scripts as Persistence

Packages can run scripts at install/remove time — a legitimate mechanism that doubles as a supply-chain and persistence vector when the package is malicious.

```bash
# Debian maintainer scripts on disk
ls -l /var/lib/dpkg/info/*.postinst /var/lib/dpkg/info/*.preinst /var/lib/dpkg/info/*.prerm

# Read a suspect one
cat /var/lib/dpkg/info/<pkg>.postinst

# RHEL: scriptlets embedded in a package
rpm -q --scripts <package>

rpm -qp --scripts suspicious.rpm
```

🔴 A `postinst`/`%post` that fetches from the internet, adds a user, drops a cron/systemd unit, or writes an SSH key is malicious — legitimate maintainer scripts do packaging housekeeping, not any of that.

## Repositories and Signing Keys

Package signing is what makes the whole trust model work, so subverting the repo list or trusted keys lets an attacker install malicious packages that appear legitimate.

```bash
# Debian sources — BOTH the classic one-line format AND the modern Deb822 (.sources) format
grep -rhE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null

grep -rhE '^(URIs|Types):' /etc/apt/sources.list.d/*.sources 2>/dev/null   # 🔴 Deb822 - the ^deb grep misses these

ls -l /etc/apt/sources.list.d/

# APT trusted keys — legacy (apt-key, deprecated) AND modern keyrings
apt-key list 2>/dev/null

ls -l /etc/apt/trusted.gpg.d/ /etc/apt/keyrings/ /usr/share/keyrings/ 2>/dev/null

grep -rhE 'signed-by' /etc/apt/sources.list.d/ 2>/dev/null       # which key each repo trusts

# RHEL repos (enabled + disabled) + GPG keys
ls -l /etc/yum.repos.d/

dnf repolist all 2>/dev/null; yum repolist all 2>/dev/null

rpm -qa gpg-pubkey* --qf '%{name}-%{version}-%{release}\n'

# Signature enforcement OFF, or plaintext-http repos (MITM / unsigned installs)
grep -rEn 'gpgcheck=0|sslverify=0|baseurl=http:' /etc/yum.repos.d/ 2>/dev/null

# Arch: repos, mirrors, signing keys
cat /etc/pacman.conf; grep -v '^#' /etc/pacman.d/mirrorlist 2>/dev/null; ls /etc/pacman.d/gnupg/ 2>/dev/null

grep -iE 'SigLevel *= *Never|TrustAll' /etc/pacman.conf 2>/dev/null    # signature checking disabled

# Alpine: repos + trusted keys
cat /etc/apk/repositories 2>/dev/null; ls /etc/apk/keys/ 2>/dev/null

# SUSE: repos (look for gpgcheck=0)
zypper lr -d 2>/dev/null; grep -rEn 'gpgcheck=0' /etc/zypp/repos.d/ 2>/dev/null
```

🔴 A rogue repo pointing at an attacker server, an unexpected imported GPG key, or a `.repo` file with `gpgcheck=0` (signature enforcement off) all let malicious packages install "cleanly." Compare the repo/key set to a known-good host of the same build.

## Unowned Files

```bash
# Debian: binaries in system paths not owned by any package
for f in /usr/bin/* /usr/sbin/* /bin/* /sbin/*; do dpkg -S "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; done

# RHEL
for f in /usr/bin/* /usr/sbin/*; do rpm -qf "$f" >/dev/null 2>&1 || echo "UNOWNED: $f"; done
```

An unowned binary in a system path is either a locally-compiled sysadmin tool (legitimate) or an attacker drop — triage each. Combined with the integrity check, this brackets the whole "what binaries don't belong here" question.

## Snap Flatpak AppImage

```bash
# Snap
snap list

ls -l /var/lib/snapd/snaps/

# Flatpak
flatpak list

ls -l /var/lib/flatpak/app/

# AppImage: self-contained; find them + their data dirs
find /home /opt -iname "*.AppImage" -ls 2>/dev/null
```

These modern packaging formats bypass the system package DB, so they won't show in `rpm`/`dpkg` — enumerate them separately, and remember an AppImage is a self-contained executable that can be dropped anywhere. Extract one with `./app.AppImage --appimage-extract`. **Language package managers** (`pip list`, `npm ls -g`, `gem list`) also install code the system DB never sees — check `~/.local/lib/python*/site-packages` for malicious PyPI packages.

## Deep Threat Hunts

Integrity + supply-chain sweep. *(seasoned-DFIR)*

```bash
# 1. Trojaned system binaries — the cheap userland-rootkit catch (RHEL + native Debian)
rpm -Va 2>/dev/null | grep -E '^..5.*bin/'

dpkg --verify 2>/dev/null                 # native Debian integrity, no debsums needed

debsums -c 2>/dev/null; debsums -l 2>/dev/null   # -l = packages debsums CAN'T verify (blind spots)

# 1b. Capabilities added to a binary (P flag) — a stealth privesc primitive
rpm -Va 2>/dev/null | grep -E '^........P'

# 2. rpmdb TAMPER: was the package DB rebuilt to hide a binary swap?
ls -la --time-style=long-iso /var/lib/rpm/Packages* /var/lib/rpm/rpmdb.sqlite 2>/dev/null
#   a recent rpmdb mtime with NO matching dnf/yum transaction => possible --rebuilddb cover-up

# 3. Debian manual verify (when debsums is unavailable)
find /usr/bin /usr/sbin -type f -exec md5sum {} \; 2>/dev/null > /tmp/now.md5
#   diff /tmp/now.md5 against the package .md5sums in /var/lib/dpkg/info/

# 4. What installed during the incident window (+ post-exploit toolkit)
rpm -qa --qf '%{installtime:date}\t%{name}-%{version}\n' 2>/dev/null | sort | tail -40

rpm -qa --last 2>/dev/null | grep -Ei 'gcc|make|nmap|netcat|ncat|socat|tcpdump|python|perl' | head

# 5. Held / downgraded packages (pinned-vulnerable or rolled back for exploitation)
apt-mark showhold 2>/dev/null

dnf history 2>/dev/null | grep -iE 'downgrade|reinstall'

# 6. Repo / signing subversion (Debian side)
grep -rhE '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -i 'http:'

# 7. Broken / partial installs (an interrupted malicious package)
dpkg --audit 2>/dev/null

# 8. Language-manager packages that bypass the system DB
pip list 2>/dev/null | tail -20; npm ls -g --depth 0 2>/dev/null; gem list 2>/dev/null | tail

# 9. Debian package-DB backup diff — what installed in a window even if history.log was cleared
diff <(zgrep -a '^Package:' /var/backups/dpkg.status.1.gz 2>/dev/null | sort) \
     <(grep  -a '^Package:' /var/lib/dpkg/status 2>/dev/null | sort) | grep '^>'

# 10. Recover the installed package from cache + find hand-dropped .deb/.rpm (repo-signing bypass)
ls -la /var/cache/apt/archives/*.deb /var/cache/dnf/*/packages/*.rpm 2>/dev/null

find / -xdev \( -name '*.deb' -o -name '*.rpm' \) ! -path '/var/cache/*' -ls 2>/dev/null

# 11. Attribution: who ran which package op (apt) + a dnf rollback/undo (patch re-introduced)
grep -E 'Commandline:|Requested-By:' /var/log/apt/history.log* 2>/dev/null

dnf history 2>/dev/null | grep -iE 'undo|rollback|downgrade'
```

**Hunt ideas:**

- **`rpm -Va` trusts `/var/lib/rpm`** — an attacker who swaps a binary then runs `rpm --rebuilddb` makes verification *pass*. Check the rpmdb mtime against the last real transaction; if suspicious, hash the binary against a clean same-version package.
- **`rpm -qa --last` / install times float the incident-window toolkit to the top** — a compiler, `nc`, or a random local package installed then is a strong lead.
- **`gpgcheck=0` or `http:` repos let malicious packages install cleanly** — a config-level backdoor; diff repo/key sets against a known-good build.
- **A downgrade in `dnf history`** can deliberately re-introduce a vulnerable version.
- **Language managers (pip/npm/gem) install code the system DB never sees** — enumerate them separately.
- **`debsums` has a blind spot; `dpkg --verify` doesn't** — `debsums -c` silently skips packages that shipped no md5sums (`debsums -l` lists them), so use `dpkg --verify` (native, complete) as the primary Debian integrity check.
- **The `/var/backups/dpkg.status.*` diff reconstructs installs even when `history.log` was cleared** — Debian's poor-man's transaction log.

## Getting Max Value

- **Run integrity first** (`rpm -Va` / `dpkg --verify` / `debsums`) — the cheapest userland-rootkit catch on the box; watch the `5` (content), `L` (symlink), and `P` (capabilities) flags.
- **Prefer `dpkg --verify` over `debsums` on Debian** — it's native and doesn't skip packages that lack md5sums.
- **Trust-but-verify the rpmdb** — if a rebuild is suspected, hash suspect binaries against a freshly pulled clean package; on old RHEL, un-prelink first to avoid false `5`s.
- **Recover the actual package from the cache** (`/var/cache/apt/archives`, `/var/cache/dnf`) — analyze the real files + maintainer scripts, not just the DB record.
- **Correlate install-history timestamps + attribution** — apt `history.log` `Requested-By:`/`Commandline:` and `dnf history info <ID>` give who-did-it plus scope.
- **Enumerate everything off the system DB** — Snap/Flatpak/AppImage and pip/npm/gem all sit outside `rpm`/`dpkg`.
- **On a mounted image:** `rpm --dbpath /mnt/evidence/var/lib/rpm -Va`, `dpkg --root /mnt/evidence --verify`, and read `dpkg.log`/`apt/history.log`/`/var/backups/dpkg.status.*` directly.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Maintainer-script persistence detail | **Persistence → More Persistence Mechanisms** (package hooks) |
| A trojaned binary's rootkit behavior | **Rootkit Detection Tooling** (11c), **ELF and Malware Triage** (11b) |
| Exactly when a package installed | **Timelining** (13) |
| Triage an unowned/dropped binary | **ELF and Malware Triage** (11b), **IOC and YARA Scanning** (11d) |
| A repo/key reached over the network | **Network and PCAP Forensics** (10c) |
| Packages baked into a container image | **Container → Malicious Images and Supply Chain** (04) |

## Scenarios

- **Trojaned `sshd`/`ls`:** `rpm -Va` shows a `5` (hash mismatch) on a core binary — userland rootkit or password-harvesting `sshd`.
- **Toolkit install:** `gcc`/`nmap`/`nc` appears in the inventory during the incident window.
- **Supply-chain persistence:** a malicious `postinst`/`%post` adds a user, key, or cron.
- **Repo backdoor:** a rogue repo or `gpgcheck=0` lets attacker packages install as "legitimate."
- **rpmdb cover-up:** a binary is swapped, then `rpm --rebuilddb` makes verification pass — caught by the rpmdb-mtime check.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `rpm -Va`/`debsums` flags a system binary (`5`) | Trojaned binary / userland rootkit |
| Package installed in the incident window | Attacker tooling |
| `postinst`/`%post` fetching or adding users/keys | Supply-chain persistence |
| Rogue repo or unexpected GPG key / `gpgcheck=0` | Malicious packages install cleanly |
| Unowned binary in `/usr/bin` etc. | Attacker drop |
| `nc`/`nmap`/compilers freshly installed | Post-exploitation toolkit |
| rpmdb rebuilt with no matching transaction | Integrity check subverted (`--rebuilddb` cover-up) |
| Package `apt-mark showhold` / `dnf` downgrade / `history undo` | Vulnerable version pinned/re-introduced |
| pip/npm/gem package installed off the system DB | Code outside package-manager visibility |
| `rpm -V` `P` flag on a binary (capabilities changed) | Stealth privesc primitive added |
| `rpm -V` `L` flag (symlink retargeted) | Trusted path repointed to attacker file |
| Local-file `.deb`/`.rpm` install in the history | Hand-dropped package (repo-signing bypass) |
| New package in `status` vs `/var/backups/dpkg.status.*` | Install even if `history.log` was cleared |
| `debsums -l` shows critical packages unverifiable | Integrity blind spot — use `dpkg --verify` |
| `pacman -Qkk`/`apk audit` flags a modified file | Trojaned binary on Arch/Alpine |
| `pacman -Qm` foreign/AUR package near the incident | Unofficial-source package (higher risk) |
| `SigLevel=Never` (pacman) / `gpgcheck=0` (zypper) | Signature checking disabled |
| Install script in a `.apk`/`.pkg.tar.zst` fetching/adding users | Supply-chain payload (any distro) |

## Resources

- `rpm(8)`, `rpm-verify(8)`, `rpmkeys(8)`, `dpkg(1)` (`--verify`), `dpkg-deb(1)`, `debsums(1)`, `apt(8)`, `dnf(8)`, `sources.list(5)` (Deb822) man pages
- `apk(8)` (Alpine — `audit`/`info -W`), `pacman(8)` (Arch — `-Qkk`/`-Qo`/`-Qm`), `zypper(8)` (SUSE) — the other top managers
- MITRE ATT&CK: T1195 (Supply Chain Compromise), T1546.016 (Installer Packages), T1554 (Compromise Host Software Binary), T1562.001 (Impair Defenses), T1195.001 (Compromise Software Dependencies), T1548.001 (Setuid/Setgid — capabilities)
