# Package Managers and Installation Forensics

macOS software installation happens three ways: **native `.pkg` installers** (receipts in `/var/db/receipts`), **third-party package managers** (Homebrew, MacPorts, Nix), and **app bundles dragged to `/Applications`**. Each leaves distinct forensic traces — install timestamps, dependency chains, whether the software came from official sources, and evidence of unauthorized or suspicious packages. Understanding these paths is critical for detecting supply-chain compromise, rogue software, and unauthorized configuration.

> 🔴 **Package managers are stealth installation vectors**: Homebrew runs user-level builds from source with minimal logging; MacPorts installs from ports trees; both can be abused to drop payloads. The trick is that they leave **installation timestamps, dependency metadata, and formula history** that native `.pkg` installers don't — and examining this tells you *what was built, when, from which sources*.

## Contents
- [Quick Triage](#quick-triage)
- [The Three Installation Paths](#the-three-installation-paths)
- [Native .pkg Installer Forensics](#native-pkg-installer-forensics)
- [Homebrew Forensics](#homebrew-forensics)
- [MacPorts Forensics](#macports-forensics)
- [Package Timeline Construction](#package-timeline-construction)
- [Detecting Suspicious Packages](#detecting-suspicious-packages)
- [Cross-Platform Correlation](#cross-platform-correlation)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Native .pkg installer timeline
system_profiler SPInstallHistoryDataType
tail -n 100 /var/log/install.log

# Homebrew installations (user-level)
ls -la ~/.brew* ~/.cache/Homebrew ~/Library/Homebrew ~/Library/Caches/Homebrew 2>/dev/null
brew list 2>/dev/null
brew info formula_name  # inspect a formula

# MacPorts installations
ls -la /opt/local/var/macports* /opt/local/var/db/receipts 2>/dev/null
port installed

# What was installed recently (all methods)
ls -lat /usr/local/Cellar 2>/dev/null | head -10
ls -lat /opt/local 2>/dev/null | head -10
sudo find /var/db/receipts -type f -mtime -30 -name '*.plist' 2>/dev/null
```

---

## The Three Installation Paths

| Method | Location(s) | Logs | Ownership | Ease of Detection |
|---|---|---|---|---|
| **Native .pkg** | `/Applications`, `/usr/local`, system dirs | `/var/db/receipts/*.plist+.bom`, `/var/log/install.log`, InstallHistory.plist | admin/installer | 🔴 **High** — receipts + BOM files |
| **Homebrew** | `~/Library/Homebrew`, `/usr/local/Cellar` (or custom) | Cache dir, `.git` history in Cellar, build logs | Current user | Medium — requires inspecting Cellar + cache |
| **MacPorts** | `/opt/local`, `/opt/local/var/macports` | `registry.db`, `receipts/`, `state/` | root (mostly) | Medium — registry DB + file metadata |

---

## Native .pkg Installer Forensics

**Starting point**: See [Install History and Receipts](<Install History and Receipts.md>) for comprehensive `.pkg` receipt analysis. This section covers the **forensic timeline and supply-chain questions**.

### Receipt Timeline

```bash
# List all installed packages
pkgutil --pkgs

# Installation metadata for a package
pkgutil --pkg-info com.vendor.product

# Parse InstallHistory.plist for chronological timeline
plutil -p /Library/Receipts/InstallHistory.plist | grep -A10 "CFBundleVersion\|installDate"
```

### Supply-Chain Forensics

```bash
# Determine the installation source
pkg_id="com.example.product"
receipt="/var/db/receipts/${pkg_id}.plist"

# Who installed it (from receipt metadata)
plutil -extract installer.0 raw "$receipt" 2>/dev/null  # e.g., "softwareupdated", "Installer", an MDM agent

# Where did it come from (source URL if captured)
plutil -p "$receipt" | grep -i source

# Verify what files the package claims to have installed
lsbom -p f "/var/db/receipts/${pkg_id}.bom" | head -20
```

### Suspicious Package Indicators

| Indicator | Concern |
|---|---|
| Package ID typo-squats a known vendor (e.g., `com.appl.update` vs `com.apple.update`) | Masquerade/trojanized package |
| Installation by an **unknown MDM agent** or unexpected process | Unauthorized deployment or rogue MDM |
| Package installs files into **unusual locations** (e.g., `/tmp`, hidden dirs) | Evasion |
| **No receipt** for an app in `/Applications` or system dir | Hand-dropped or removed |
| Install timestamp at **odd hours** or when user claims absence | Unauthorized installation |
| Binary in BOM but **not on disk** | Removed (anti-forensics?) |
| Binary **on disk but not in any BOM** | 🔴 **Highly suspicious** — hand-dropped, likely malware |

---

## Homebrew Forensics

Homebrew is a **user-level package manager** running without root (unless using Homebrew-Cask or `sudo`). It installs packages from GitHub-hosted formula repositories and stores binaries + metadata in the Cellar.

### Homebrew Locations and Artifacts

| Path | Contains | Forensic Value |
|---|---|---|
| `~/.brew_home`, `~/.cache/Homebrew` | Cache of downloaded packages + formula source | 🔴 Download timestamps, source URLs, formula versions |
| `/usr/local/Cellar/<package>/<version>` | Installed package + metadata | File timestamps = install time |
| `/usr/local/etc/Homebrew` | Configuration | Policy, logging level |
| `~/.local/share/homebrew/`, `.git/` in Cellar | **Version control history** | 🔴 All formula changes, pin history, uninstall logs |
| `/var/log/Homebrew/` (if logging enabled) | Build/install logs | Timestamps, errors, dependencies |

### Installation Timeline

```bash
# Installed packages
brew list

# Detailed info about a package (version, install date)
brew info package_name

# Show when each package was last updated
for pkg in $(brew list); do
  echo "=== $pkg ==="
  stat -f "%Sm" /usr/local/Cellar/$pkg/*/
done
```

### Forensic Questions and Answers

| Question | How to Answer |
|---|---|
| When was package X installed? | `stat` the `/usr/local/Cellar/<X>/` directory; cross-check with `.git` log if available |
| What version of package X was installed? | `ls /usr/local/Cellar/<X>/` (shows all versions ever installed) |
| Was package X installed from official Homebrew or a 3rd-party tap? | `brew tap list` + check formula source; look for taps pointing to GitHub accounts |
| What dependencies did X bring in? | `brew deps <X>` + check Cellar for dependent packages |
| What is the formula source (ruby code) for a package? | `brew cat <package_name>` or check formula repository |

### Suspicious Homebrew Patterns

| Pattern | Concern |
|---|---|
| 🔴 Formula from **untrusted GitHub account** (not `Homebrew/homebrew-*`) | Rogue formula, supply-chain risk |
| 🔴 Formula that **uses curl piping to shell** or `unsafe` scripts | Code execution risk in formula |
| Package pinned (prevented from updating) when **not installed by user** | Anti-remediation |
| **Build artifacts** (source tarballs, compiled objects) not cleaned up | Possible staging area |
| Formula cloning a **private/internal repo** (requires auth) | Insider access or credential theft |

---

## MacPorts Forensics

MacPorts is a **root-level package manager** (vs. Homebrew's user-level). It maintains a registry database and port definitions tree.

### MacPorts Locations and Artifacts

| Path | Contains |
|---|---|
| `/opt/local/var/macports/registry.db` | 🔴 **SQLite DB** — all installed ports, versions, install dates |
| `/opt/local/var/macports/receipts/` | Detailed port installation records |
| `/opt/local/var/macports/sources.conf` | Repository configuration |

### MacPorts Timeline

```bash
# Installed ports
port installed

# Port installation history (registry DB)
sqlite3 /opt/local/var/macports/registry.db ".mode line" "SELECT name, version, date FROM registry WHERE name='package_name';"
```

### Suspicious MacPorts Patterns

| Pattern | Concern |
|---|---|
| Port installation by **non-standard source** (not official MacPorts) | Rogue port, supply-chain risk |
| Ports from **custom local sources.conf entries** | Custom/internal port tree, possible malware injection |

---

## Package Timeline Construction

Build a complete installation history by stacking evidence:

```bash
# 1. Native .pkg timeline
echo "=== Native .pkg Installations ===" 
plutil -p /Library/Receipts/InstallHistory.plist | grep -E "installDate|displayName"

# 2. Homebrew timeline
echo "=== Homebrew Installations ==="
for pkg in $(brew list 2>/dev/null); do
  if [[ -d "/usr/local/Cellar/$pkg" ]]; then
    echo "$pkg: $(stat -f '%Sm' /usr/local/Cellar/$pkg/)"
  fi
done | sort
```

---

## Detecting Suspicious Packages

### Filename and ID Masquerade

```bash
# Check for typo-squats in package names
pkgutil --pkgs | grep -iE '^com\.appl\.|^com\.micro\.|^com\.mozil\.'  # typos
```

### Binary Signature and Notarization

```bash
# Verify code signature of a Homebrew-installed binary
codesign -dvvv /usr/local/Cellar/package/version/bin/binary

# Native .pkg signature verification
pkgutil --check-signature /path/to/package.pkg
```

---

## Cross-Platform Correlation

### macOS ↔ Windows Package Managers

For enterprise investigations spanning macOS and Windows:

| Aspect | macOS | Windows | Correlation |
|---|---|---|---|
| **User-level package manager** | Homebrew | winget | Check for unauthorized deployments |
| **3rd-party package manager** | MacPorts | Chocolatey, Scoop | Registry DB vs installer MSI/EXE |
| **Installation timeline** | InstallHistory.plist | Registry hives | Timeline should align for org deployments |

---

## Red Flags

| 🔴 Finding | Likely Meaning |
|---|---|
| Package **not in any official repository** (custom tap on GitHub) | Rogue package, supply-chain compromise |
| Homebrew formula that **uses `curl \| bash`** | Extremely high execution risk |
| Receipt for package **whose files are gone** | Installed then cleaned up (anti-forensics) |
| Installation at **odd time** / not by user | Unauthorized deployment |
| 🔴 **Binary on disk but not in any receipt/Cellar** | Hand-dropped malware |
| **Mismatched package versions** across databases | Rollback or tampering |
| 🔴 **Rapid, automated package installs** | Worm/malware deployment or bulk deployment |

---

## Resources

- Cross-ref: [Install History and Receipts](<Install History and Receipts.md>), [Program Execution Evidence](<Program Execution Evidence.md>)
- MITRE ATT&CK: T1195 (Supply Chain Compromise), T1546.015 (Login Item)
