# Legacy Logs

Before the Unified Logging System (Sierra 10.12), macOS used **ASL (Apple System Log)** and plaintext logs under `/var/log`. Modern systems route almost everything through Unified Logs, but **legacy logs still matter**: some daemons and third-party tools still write here, and **upgraded systems** retain old ASL/`system.log` data predating the upgrade. These are plain files — read with standard CLI tools, no `log` command needed.

> 🔴 On an upgraded Mac, `/var/log` and `/var/log/asl/` can hold events from **before** the Unified Log buffer's window — sometimes the only record of older activity. Always check them.

## Contents
- [Quick Triage](#quick-triage)
- [Why Legacy Logs Still Matter](#why-legacy-logs-still-matter)
- [Key Files and Locations](#key-files-and-locations)
- [system.log](#systemlog)
- [ASL Databases](#asl-databases)
- [Other Legacy Logs](#other-legacy-logs)
- [ASL Configuration](#asl-configuration)
- [Preserving Legacy Logs](#preserving-legacy-logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
grep -i "fail\|error\|denied" /var/log/system.log

ls -lh /var/log/asl/ /var/log/system.log.*

syslog -r -f /var/log/asl/*.asl 2>/dev/null | tail -n 50

cat /etc/asl.conf                                                  # tampering check
```

---

## Why Legacy Logs Still Matter

- **Upgraded systems** keep pre-upgrade `system.log`/ASL data → events older than the Unified Log window.
- Some daemons and **third-party tools** still log to `/var/log` plaintext.
- Plaintext = easy to `grep`/`tail`, and **easy for an attacker to edit/delete** — gaps and truncation are themselves evidence.
- Rotated archives (`.gz`) extend the timeline backward.

---

## Key Files and Locations

| Path | Holds |
|---|---|
| 🔴 `/var/log/system.log` | Legacy main system log (plaintext) |
| `/var/log/system.log.*` (e.g. `system.log.0.gz`) | Rotated/compressed historical archives |
| 🔴 `/var/log/asl/` | ASL database files (`*.asl`) |
| `/var/log/DiagnosticMessages/` | Older ASL diagnostic data |
| `/var/log/wifi.log` | Wi-Fi association history (legacy) |
| `/var/log/racoon.log` | IPsec/IKE (VPN) negotiation (legacy) |
| `/var/log/ppp.log` | PPP / dial-up / some VPN |
| `/var/log/appfirewall.log` | ALF firewall (legacy plaintext — cross-ref Firewalls) |
| `/var/log/install.log` | Install/update history (still active, long retention) |
| `/etc/asl.conf` | ASL configuration (what gets logged/where/rotation) |

---

## system.log

```bash
# View
less /var/log/system.log

# Live tail (active logging)
tail -f /var/log/system.log

# Search for a keyword
grep "keyword" /var/log/system.log

# Suspicious terms (case-insensitive)
grep -i "error" /var/log/system.log

# Check rotation archives
ls -lh /var/log/system.log.*

# Search inside compressed archives
zgrep -i "keyword" /var/log/system.log.*.gz
```

🔴 Look for: auth failures, daemon errors, USB/mount events, and **time gaps** (a missing chunk = possible tampering).

---

## ASL Databases

ASL files are a binary format — read them with the **`syslog`** tool.

```bash
# List ASL databases
ls -lh /var/log/asl/

# Parse a specific .asl file (reverse-sorted)
syslog -r -f /var/log/asl/filename.asl

# Filter while parsing (example: only a sender/keyword)
syslog -f /var/log/asl/filename.asl -k Sender sshd
```

> Each `.asl` file is roughly a time slice. On upgraded systems these can predate the Unified Log — the only home for older events.

---

## Other Legacy Logs

```bash
# Wi-Fi association history (legacy)
less /var/log/wifi.log

# VPN / IPsec negotiation
less /var/log/racoon.log

# PPP / dial-up / some VPN
less /var/log/ppp.log
```

🔴 `wifi.log` corroborates SSID/movement (cross-ref Wi-Fi and Network); `racoon.log`/`ppp.log` reveal legacy VPN tunnels.

---

## ASL Configuration

```bash
# What ASL logs, where, and rotation policy
cat /etc/asl.conf

ls -l /etc/asl/                # module-specific configs
```

🔴 An attacker may edit `asl.conf` to **stop logging** a facility or shorten retention — compare against a known-good config; unexpected changes are tampering.

---

## Preserving Legacy Logs

```bash
# Copy before rotation overwrites them
cp /var/log/system.log /safe_location/

cp /var/log/system.log.0.gz /safe_location/

# Grab the whole ASL + log trees
cp -R /var/log/asl /safe_location/asl

cp -R /var/log /safe_location/var_log
```

> On a forensic image these are captured automatically; on a **live** triage, copy them early — rotation and attacker cleanup both destroy them.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| **Gaps / truncation** in `system.log` | Log tampering / selective deletion |
| `system.log` recently **emptied** or shrunk | Anti-forensics |
| `asl.conf` modified to disable a facility / shorten retention | Attacker quieting logs |
| Missing rotation archives (`.gz`) that should exist | Evidence destroyed |
| `wifi.log` SSIDs inconsistent with the user's account | Undisclosed movement |
| `racoon.log`/`ppp.log` showing unexpected VPN tunnels | Covert egress |
| Pre-upgrade ASL events contradicting the Unified Log timeline | Important older activity |

---

## Resources

- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
