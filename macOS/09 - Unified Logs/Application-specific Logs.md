# Application-specific Logs

Many security-relevant apps log **outside** the Unified Logs — in their own files or via dedicated subsystems. Third-party **firewalls** (Little Snitch, LuLu), **MDM/identity** tooling (Jamf Pro, Jamf Connect), AV/EDR, VPN clients, and browsers/chat apps each keep their own trails. These often capture what Apple's logs miss — notably **outbound** network decisions and policy deployments.

> 🔴 Little Snitch / LuLu logs are one of the few places you'll see **outbound** connection attempts (C2/exfil), since Apple's ALF only covers inbound. Jamf logs reveal **what was pushed** to the endpoint (scripts, profiles, policies) — a prime persistence/abuse vector in managed fleets.

## Contents
- [Quick Triage](#quick-triage)
- [Where Apps Log](#where-apps-log)
- [Little Snitch](#little-snitch)
- [LuLu](#lulu)
- [Jamf Connect](#jamf-connect)
- [Jamf Pro](#jamf-pro)
- [Antivirus and EDR](#antivirus-and-edr)
- [VPN Clients](#vpn-clients)
- [Browsers and Chat Apps](#browsers-and-chat-apps)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
littlesnitch log-traffic                                           # outbound (C2 / exfil)

log stream --predicate="subsystem=='com.objective-see.lulu'" --debug

sudo profiles list -all                                            # rogue MDM profiles

find /Library/Logs ~/Library/Logs -type f -mtime -7 2>/dev/null   # recent app logs
```

---

## Where Apps Log

| Location | Holds |
|---|---|
| 🔴 `/Library/Logs/` | System-wide app/daemon logs |
| 🔴 `~/Library/Logs/` | Per-user app logs |
| `~/Library/Application Support/<App>/` | App data, often incl. logs/state/history |
| `~/Library/Containers/<bundleid>/Data/Library/Logs/` | Sandboxed-app logs |
| `~/Library/Preferences/<bundleid>.plist` | App config (settings, sometimes recent activity) |
| Unified Log subsystem | Some apps log via ULS (`subsystem == "com.vendor.app"`) |

> Triage rule: for any app of interest, check **all** of `/Library/Logs`, `~/Library/Logs`, `~/Library/Application Support/<App>`, its prefs plist, and a ULS subsystem query on its bundle ID.

---

## Little Snitch

Third-party outbound/inbound application firewall (proprietary CLI).

```bash
# View Little Snitch logs
littlesnitch log

# Real-time traffic logs
littlesnitch log-traffic
```

🔴 Shows per-app **connection attempts** and allow/deny decisions — including **outbound** to C2/exfil hosts that ALF never sees. Note destination host/IP/port, the process, and the rule that matched.

---

## LuLu

Objective-See's free outbound firewall (logs to the Unified Log + on-disk).

```bash
# Stream LuLu events from the Unified Logs
log stream --predicate="subsystem=='com.objective-see.lulu'" --debug
```

On-disk (older versions / artifacts):

```
/Library/Objective-See/LuLu
/Library/Logs/LuLu
```

🔴 Records outbound connection alerts and the user's allow/block choices. The rules DB under `/Library/Objective-See/LuLu` shows what was **permitted** — an attacker-allowed rule for a malicious binary is a red flag.

---

## Jamf Connect

Identity / cloud-IdP sign-in (logs via Unified Log subsystem).

```bash
# Historical logs (last 30 min) → file on Desktop
log show --predicate 'subsystem == "com.jamf.connect"' --debug --last 30m > ~/Desktop/JamfConnect.log

# Stream in real time
log stream --predicate 'subsystem == "com.jamf.connect"' --debug
```

🔴 Shows IdP authentications, local-account/password sync, and sign-in events — auth activity that may not appear in `loginwindow`.

---

## Jamf Pro

MDM agent — **plaintext** logs.

| Path | Holds |
|---|---|
| 🔴 `/var/log/jamf.log` | Primary Jamf Pro log (check-ins, policies, scripts run) |
| `/Library/Logs/Jamf/` | Additional Jamf logs |
| `/usr/local/jamf/logs/` | Agent component logs |

```bash
less /var/log/jamf.log

grep -i "policy\|script\|install\|enroll" /var/log/jamf.log
```

🔴 Reveals **what the MDM pushed**: policies, scripts executed as root, package installs, enrollment changes. In a managed fleet this is a top **persistence/lateral** vector — a rogue or hijacked Jamf policy can run arbitrary code on every endpoint.

Configuration profiles installed by *any* MDM (high-value persistence/control check):

```bash
sudo profiles list -all                 # all installed config profiles

sudo profiles show -type enrollment     # MDM enrollment state (supervised? which server?)

ls -la /Library/Managed\ Preferences/   # MDM-enforced prefs in effect
```

> 🔴 An **unexpected MDM enrollment** or a config profile from an unknown server = full remote control of the endpoint. Profiles can silently set proxies, install certs, and deploy LaunchDaemons.

---

## Antivirus and EDR

```
/Library/Logs/<VendorName>/
```

🔴 Vendor AV/EDR (CrowdStrike, SentinelOne, Defender, Sophos, etc.) keep detection/quarantine logs here and often a richer console. Check for **detections, quarantines, and any agent tampering/disable** events. Absence of expected agent logs can itself indicate the agent was killed.

---

## VPN Clients

```
/Library/Logs/<Vendor>/
~/Library/Logs/<Vendor>/
```

🔴 Non-Apple VPNs (Cisco AnyConnect, GlobalProtect, OpenVPN, Tunnelblick, etc.) log connect/disconnect, gateways, and assigned IPs — establishes **egress paths** and remote-network access.

---

## Browsers and Chat Apps

```
~/Library/Application Support/<AppName>/
```

🔴 Browsers (history/downloads/extensions) and chat apps (Slack, Discord, Teams, Signal) store data and logs here — downloads of tooling, exfil via chat, malicious extensions. (Full browser/app forensics is its own discipline; here, know **where** to look.)

| App type | Typical path |
|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/` |
| Safari | `~/Library/Safari/` |
| Slack | `~/Library/Application Support/Slack/` |
| Discord | `~/Library/Application Support/discord/` |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Little Snitch/LuLu **allowed** an unknown binary outbound | Sanctioned C2/exfil path |
| Third-party firewall recently **disabled** / rules cleared | Tampering to enable exfil |
| `jamf.log` shows an **unexpected policy/script** run as root | Rogue/hijacked MDM → fleet-wide code exec |
| New/unknown **MDM enrollment** | Unauthorized management takeover |
| AV/EDR **detection** then agent goes silent | Malware found, then agent killed |
| Missing AV/EDR logs where the agent should be running | Agent disabled (anti-forensics) |
| VPN client connecting to an **unfamiliar gateway** | Covert egress / unauthorized remote access |
| Browser download logs for tooling / chat exfil of files | Ingress of malware / data theft |

---

## Resources

- The Eclectic Light Company – log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
- Objective-See (LuLu and free macOS security tools): https://objective-see.org/
