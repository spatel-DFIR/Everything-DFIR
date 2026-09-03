# GUI and Desktop Artifacts

Most Linux *servers* are headless and this note won't apply to them — but on workstations and jump boxes the desktop environment leaves a rich trail of user activity that fills gaps the shell history and logs don't cover: which files were opened, what external drives and network shares were mounted, and which programs auto-start on login. These artifacts are the Linux analog of the "recent items" and "shell folder" evidence you'd chase on other platforms, and they're especially useful for reconstructing what an interactive user did in a GUI session.

> 🔴 On a headless server, skip most of this — but `~/.config/autostart/*.desktop` and `~/.config/systemd/user/` are per-user persistence vectors that apply even to lightly-used graphical sessions, so always check those. Browser artifacts are intentionally **out of scope** for this repo (maintained separately); don't pull browser histories here.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Recently Used Files](#recently-used-files)
- [Desktop Autostart](#desktop-autostart)
- [Trojan Desktop Launchers](#trojan-desktop-launchers)
- [Stored Secrets Keyrings and Wallets](#stored-secrets-keyrings-and-wallets)
- [Mounted Volumes and GVFS](#mounted-volumes-and-gvfs)
- [Application State](#application-state)
- [Remote Access Clients](#remote-access-clients)
- [Clipboard and Screenshots](#clipboard-and-screenshots)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Recently-opened files (GTK/GNOME)
cat /home/*/.local/share/recently-used.xbel 2>/dev/null

# Desktop autostart (per-user persistence)
ls -la /home/*/.config/autostart/ /etc/xdg/autostart/ 2>/dev/null

# Trash metadata (deletion evidence)
cat /home/*/.local/share/Trash/info/*.trashinfo 2>/dev/null

# GVFS recent mounts / network shares
ls -la /home/*/.config/gvfs* /run/user/*/gvfs 2>/dev/null
```

## What to Check for What

*(workstation/jump-box focus — headless servers: skip to autostart + `systemd/user`)*

| Investigative question | Command / source |
|------------------------|------------------|
| What files did the user open? | `recently-used.xbel`; Zeitgeist; LibreOffice recent |
| GUI-session persistence? | `~/.config/autostart/*.desktop` (`Exec=`); `~/.config/systemd/user/` |
| Trojan launcher in the menu? | `grep Exec= ~/.local/share/applications/*.desktop` |
| Saved credentials (wifi/VPN/app)? | GNOME Keyring, KDE Wallet |
| External media / network share attached? | GVFS, `udisks` in journal, GTK bookmarks |
| Did the workstation pivot outward? | Remmina/VNC/RDP client configs |
| Copied secrets? | clipboard-manager history |
| Command output from the GUI session? | `~/.xsession-errors` |

## Recently Used Files

The desktop keeps a registry of recently-opened documents — a per-user "what did they open" trail that survives even deletion of the file itself.

```bash
# GTK/GNOME recently-used registry (XML: URI + timestamps + application)
cat /home/*/.local/share/recently-used.xbel 2>/dev/null

# KDE recent documents
ls -la /home/*/.local/share/RecentDocuments/ 2>/dev/null

cat /home/*/.local/share/RecentDocuments/*.desktop 2>/dev/null
```

`recently-used.xbel` records each file's URI, the application that opened it, and added/modified/visited timestamps. That's a direct answer to "did this user open the sensitive document," complete with which app they used and when — and it persists after the file is gone.

## Desktop Autostart

This overlaps with the Persistence note (it *is* a persistence vector); here it's listed as an artifact to collect and interpret.

```bash
# Per-user autostart entries
ls -la /home/*/.config/autostart/ 2>/dev/null

cat /home/*/.config/autostart/*.desktop 2>/dev/null

# System-wide autostart
ls -la /etc/xdg/autostart/ 2>/dev/null
```

🔴 A `.desktop` file with an `Exec=` line pointing at a script in `/tmp`, `/home`, or `/dev/shm` — or a `.desktop` recently added with `Hidden=false` — is GUI-session persistence that fires on the next graphical login. Read the `Exec=` line of every entry. Also check KDE's `~/.config/autostart-scripts/` and `X-GNOME-Autostart-*` keys.

## Trojan Desktop Launchers

🔴 A `.desktop` file in the *applications menu* can spoof a legitimate app's **name and icon** while its `Exec=` runs a payload — the user clicks what looks like Firefox and launches malware. These live outside `autostart/`, so an autostart-only sweep misses them.

```bash
# Menu launchers whose Exec runs a script / shell / temp path
grep -REn 'Exec=.*(/tmp|/dev/shm|/home|curl|wget|bash -c|sh -c|base64)' \
  /home/*/.local/share/applications/ /usr/share/applications/ 2>/dev/null

# Recently added/modified launchers (spoofed icon + real-looking name)
find /home/*/.local/share/applications /usr/share/applications -name '*.desktop' -mtime -30 -ls 2>/dev/null
```

## Stored Secrets Keyrings and Wallets

🔴 The desktop credential stores are a goldmine: they hold saved **wifi passwords, VPN creds, and application passwords**. An attacker in an unlocked session (or with the user's login password) can dump them.

```bash
# GNOME Keyring (login.keyring holds the secrets; encrypted with the login password)
ls -la /home/*/.local/share/keyrings/ 2>/dev/null

# KDE Wallet
ls -la /home/*/.local/share/kwalletd/ 2>/dev/null

# NetworkManager stored connection secrets (wifi/VPN PSKs, often plaintext, root-readable)
grep -rEl 'psk=|password=' /etc/NetworkManager/system-connections/ 2>/dev/null
```

Even if you can't decrypt a keyring without the login password, its **presence and mtime** matter; `/etc/NetworkManager/system-connections/` frequently stores wifi/VPN secrets in plaintext (root-readable).

## Mounted Volumes and GVFS

External drives and network shares are ingress and exfil paths, and the desktop stack records them.

```bash
# GVFS - GNOME virtual filesystem (SMB/SFTP/MTP mounts, recent network shares)
ls -la /run/user/*/gvfs/ 2>/dev/null

# udisks mount history in the journal (USB / external drives)
journalctl | grep -Ei "udisks|mount|usb-storage|sd[b-z]"

# GNOME/KDE remembered network places
cat /home/*/.config/gtk-3.0/bookmarks 2>/dev/null
```

🔴 Mounted SMB/SFTP shares (in GVFS) and USB devices (in the journal via udisks) reconstruct *when external storage or network shares were attached* — directly relevant to data exfil (copying out to a USB drive) or ingress (pulling tools from a network share). The `bookmarks` file also reveals network locations the user saved.

## Application State

```bash
# General per-user app config/state
ls -la /home/*/.config/ 2>/dev/null

# Autostarting user services (systemd --user) - persistence
ls -la /home/*/.config/systemd/user/ 2>/dev/null

# Terminal emulator / file-manager state, editor sessions
ls -la /home/*/.local/share/ 2>/dev/null
```

🔴 `~/.config/systemd/user/` holds per-user systemd units that a normal user can install without root — a persistence spot that's easy to miss because it lives in a home directory rather than a system path.

Activity databases worth pulling:

```bash
# Zeitgeist activity log (GNOME) — detailed "what the user did" DB
ls -la /home/*/.local/share/zeitgeist/activity.sqlite 2>/dev/null

# LibreOffice recent-documents list
grep -a 'file://' /home/*/.config/libreoffice/*/user/registrymodifications.xcu 2>/dev/null

# GUI session stdout/stderr (captures command output/errors)
tail -50 /home/*/.xsession-errors 2>/dev/null
```

## Remote Access Clients

A workstation is often the pivot *into* the environment — its outbound remote-access client configs map where the user (or attacker on the user's session) connected.

```bash
# RDP (Remmina), VNC, and other saved remote sessions
ls -la /home/*/.config/remmina/ /home/*/.vnc/ /home/*/.config/*rdp* 2>/dev/null

grep -rhEi 'host|server|username' /home/*/.config/remmina/*.remmina 2>/dev/null
```

## Clipboard and Screenshots

```bash
# Clipboard managers persist copied data
ls -la /home/*/.config/clipit/ /home/*/.local/share/klipper/ 2>/dev/null

cat /home/*/.local/share/klipper/history* 2>/dev/null

# Default screenshot locations
ls -la /home/*/Pictures/Screenshots/ /home/*/Pictures/ 2>/dev/null
```

Clipboard-manager history can capture passwords or commands the user copied, and screenshots can show exactly what the user saw on screen — both occasionally decisive in an insider or account-misuse case.

## Deep Threat Hunts

*(seasoned-DFIR; workstation/interactive-user reconstruction)*

```bash
# 1. Autostart persistence across ALL desktop mechanisms
grep -REn 'Exec=|Hidden|X-GNOME-Autostart' /home/*/.config/autostart/ /etc/xdg/autostart/ 2>/dev/null

ls -la /home/*/.config/autostart-scripts/ /home/*/.config/systemd/user/ 2>/dev/null

# 2. Trojan menu launchers (spoofed name/icon, payload Exec)
grep -REn 'Exec=.*(/tmp|/dev/shm|/home|curl|bash -c|sh -c|base64)' \
  /home/*/.local/share/applications/ 2>/dev/null

# 3. Stored secrets: keyrings, wallets, NetworkManager PSKs
ls -la /home/*/.local/share/keyrings/ /home/*/.local/share/kwalletd/ 2>/dev/null

grep -rEl 'psk=|password=' /etc/NetworkManager/system-connections/ 2>/dev/null

# 4. Activity: recently-used + Zeitgeist + LibreOffice recent
cat /home/*/.local/share/recently-used.xbel 2>/dev/null

grep -a 'file://' /home/*/.config/libreoffice/*/user/registrymodifications.xcu 2>/dev/null

# 5. External media + network shares (exfil/ingress windows)
ls -la /run/user/*/gvfs/ 2>/dev/null

journalctl | grep -Ei 'udisks|usb-storage|Mounted|sd[b-z]:'

# 6. Remote-access-OUT clients (pivot)
ls -la /home/*/.config/remmina/ /home/*/.vnc/ 2>/dev/null

# 7. dconf/gsettings MRU dump
dconf dump / 2>/dev/null | grep -iE 'recent|mru|uri'
```

**Hunt ideas:**

- **Keyrings/wallets + NetworkManager PSKs are a credential trove** — wifi/VPN/app passwords an attacker in an unlocked session can dump.
- **Trojan `.desktop` launchers spoof a real app's name+icon** while the `Exec` runs a payload — they hide in the applications menu, not `autostart/`.
- **`recently-used.xbel` + Zeitgeist + LibreOffice recent triangulate** exactly which documents an interactive user opened and when — surviving file deletion.
- **GVFS + `udisks` journal reconstruct external-storage/network-share attach times** = the exfil/ingress window.
- **Remmina/VNC configs show the workstation pivoting outward** to other hosts.

## Getting Max Value

- **Headless server?** Skip most of this — but *always* check `~/.config/autostart/` and `~/.config/systemd/user/` (persistence regardless of GUI use).
- **Note keyrings/wallets even if you can't decrypt them** — presence + mtime matter, and NetworkManager secrets are often plaintext.
- **`recently-used.xbel`/Zeitgeist survive file deletion** — use them to prove a user accessed a document that's since gone.
- **Correlate GVFS/`udisks` mount times with the exfil window** — external storage attach + a spike of file access is a strong exfil signal.
- **Browser artifacts are intentionally out of scope** here — use the separate browser repo.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Autostart / `systemd --user` as persistence | **Persistence → More Persistence**, **Systemd Units** |
| USB/mount insertion times in depth | **Syslog and Rsyslog** (kernel USB), **Timelining** (13) |
| The deleted file an `xbel` entry references | **Trash and Deleted File Artifacts** (08) |
| Reuse of stolen keyring/wifi/VPN creds | **Users Groups and Authentication** (03), **Auth Records** |
| The workstation pivoting to other hosts | **Authentication and Login Records**, **Network and PCAP** (10c) |

## Scenarios

- **Interactive-user reconstruction:** `recently-used.xbel` + Zeitgeist show which documents were opened, by which app, when.
- **GUI persistence:** an autostart `.desktop` with `Exec=` to a `/tmp` script fires on next graphical login.
- **Trojan launcher:** a spoofed-icon `.desktop` in the applications menu runs a payload when clicked.
- **Credential trove:** GNOME Keyring / KDE Wallet / NetworkManager hold wifi/VPN/app passwords.
- **Exfil path:** a USB or SMB mount (GVFS/`udisks`) attached exactly at the exfil timeframe.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `.desktop` autostart with `Exec=` to a temp/home script | GUI persistence |
| `recently-used.xbel` referencing sensitive files an attacker touched | Access evidence |
| GVFS/udisks mounts of external or network storage near incident | Exfil / ingress path |
| `systemd --user` unit in a home directory | Per-user persistence |
| Clipboard history containing credentials/commands | Leaked secrets |
| Trojan `.desktop` launcher (spoofed icon, payload `Exec`) | GUI social-engineering execution |
| Keyring/wallet/NetworkManager secrets accessed | Credential theft |
| Remmina/VNC config to an unexpected host | Workstation pivot outward |

## Resources

- FreeDesktop recently-used, autostart & Desktop Entry specs — https://specifications.freedesktop.org
- MITRE ATT&CK: T1547.013 (XDG Autostart), T1204.002 (Malicious File / `.desktop`), T1555 (Credentials from Password Stores), T1080 (Taint Shared Content), T1021 (Remote Services)
