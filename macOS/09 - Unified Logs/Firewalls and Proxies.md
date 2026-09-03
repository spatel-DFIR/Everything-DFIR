# Unified Logs – Firewalls and Proxies

How macOS logs its built-in **Application Layer Firewall (ALF)** and **proxy** activity. ALF (`socketfilterfw`) is a *per-application* inbound firewall — it logs **incoming** connection decisions at a high level, **not** packet-level detail. Proxy settings flow through `configd`. For real packet visibility you drop down to **pf**, `tcpdump`, or Wireshark.

> 🔴 ALF only governs **incoming** connections per-app and logs sparsely. **Outbound** C2/exfil is *not* caught by ALF — third-party firewalls (Little Snitch/LuLu) or pf/packet capture are needed for that.

## Contents
- [Quick Triage](#quick-triage)
- [ALF Overview and Status](#alf-overview-and-status)
- [Querying Firewall Logs](#querying-firewall-logs)
- [What ALF Captures on Incoming Connections](#what-alf-captures-on-incoming-connections)
- [Proxies](#proxies)
- [Going Deeper Than ALF](#going-deeper-than-alf)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

log show --predicate '(process == "socketfilterfw") OR (subsystem == "com.apple.alf")' --last 24h

scutil --proxy                                                      # proxy / PAC set?

lsof -i -nP | grep -i listen                                       # unexpected listeners
```

---

## ALF Overview and Status

The Application Layer Firewall is configured via `/usr/libexec/ApplicationFirewall/socketfilterfw` and the plist `/Library/Preferences/com.apple.alf.plist`.

```bash
# Firewall global state (0=off, 1=on for specific services, 2=on/block-all)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Useful companions
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall      # block all incoming?

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode   # stealth (no ICMP/probe replies)?

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps         # per-app allow/block rules

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode   # is logging on?
```

| State | Meaning |
|---|---|
| `0` | 🔴 Firewall **off** |
| `1` | On — allow signed/explicitly-allowed apps |
| `2` | On — **block all** incoming (except essentials) |

> 🔴 Firewall **off** (or stealth disabled) on a sensitive host is a posture gap; a recent toggle in the log can indicate an attacker easing inbound access.

---

## Querying Firewall Logs

```bash
# ALF events from the last 24 hours
log show --predicate '(process == "socketfilterfw") OR (subsystem == "com.apple.alf")' --last 24h

# Real-time monitor on a live system (resource-intensive)
log stream --predicate '(process == "socketfilterfw") OR (subsystem == "com.apple.alf")'

# Preserve firewall logs to a file
log show --predicate '(process == "socketfilterfw") OR (subsystem == "com.apple.alf")' --last 24h > firewall_snapshot.txt
```

> Legacy plaintext firewall log may also exist at `/var/log/appfirewall.log` (cross-ref *Legacy Logs*).

---

## What ALF Captures on Incoming Connections

When something listens/accepts inbound, ALF logs the **app** and the **allow/deny** decision (e.g. *"… is listening from …"*, *"Deny … connecting from …"*). Example: an **nmap** scan against the host surfaces as inbound connection attempts being allowed/denied per service.

🔴 What to pull from ALF entries:

| Field in entry | DFIR value |
|---|---|
| Binary / app name accepting inbound | Is an **unexpected** process listening? (backdoor/bind shell) |
| Allow vs Deny decision | What got through vs blocked |
| Remote endpoint (when present) | Source of inbound activity |
| Timestamp | Correlate with logins / scans |

> ALF identifies by **application**, not port — a renamed/unsigned binary suddenly accepting inbound is the red flag. Cross-check listeners live with `lsof -i -nP | grep LISTEN` and `netstat -an`.

---

## Proxies

System proxy settings (HTTP/HTTPS/SOCKS, **PAC** auto-config URLs) are managed by `configd`. Malware/adware commonly sets a proxy or a malicious **PAC URL** to intercept traffic.

```bash
# Any proxy references (last 24 hours)
log show --predicate 'eventMessage CONTAINS "proxy"' --last 24h

# Narrow to the configuration daemon
log show --predicate 'process == "configd" AND eventMessage CONTAINS "proxy"' --last 24h
```

Live / on-disk proxy state:

```bash
scutil --proxy                                   # current resolved proxy config (incl. PAC URL)

networksetup -getwebproxy "Wi-Fi"                # per-service proxy

networksetup -getautoproxyurl "Wi-Fi"            # PAC auto-config URL
```

🔴 Proxy red flags:

| Finding | Meaning |
|---|---|
| 🔴 Unexpected **HTTP/HTTPS/SOCKS proxy** set | Traffic interception / MITM |
| 🔴 **PAC URL** pointing at an external/odd host | Adware/malware redirecting traffic |
| Proxy enabled only for some services | Targeted interception |
| Proxy set shortly after malware execution | Part of the infection chain |

---

## Going Deeper Than ALF

ALF's detail is limited. For packet/flow-level analysis:

| Tool | Use | Notes |
|---|---|---|
| **pf** (`pfctl`) | The real kernel packet filter | Rules in `/etc/pf.conf`; `sudo pfctl -s rules` / `-s info`; can log to `pflog` |
| **tcpdump** | Live capture / pcap | `sudo tcpdump -i en0 -w /evidence/cap.pcap` |
| **Wireshark / tshark** | Deep packet analysis | Offline analysis of captures |
| `lsof -i` / `netstat -an` | Current sockets/listeners | Spot live backdoor listeners & active C2 |
| `nettop` | Live per-process throughput | Find the process talking out |

> 🔴 ALF won't show **outbound** C2. If you suspect beaconing/exfil, go straight to `lsof -i`, `nettop`, a `tcpdump` capture, or third-party outbound firewall logs.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Firewall **off** (`--getglobalstate` = 0) on a sensitive host | Posture gap / attacker eased inbound |
| Firewall/stealth recently **toggled** in the log | Tampering to allow inbound access |
| **Unexpected app** accepting inbound in ALF logs | Backdoor / bind shell listening |
| Unsigned/renamed binary listening | Masqueraded malware |
| System **proxy** or **PAC URL** set to an odd host | Traffic interception / adware |
| Proxy change right after a suspicious process ran | Part of infection chain |
| Suspected C2 but ALF is silent | Outbound — pivot to pf/tcpdump/`lsof`/3rd-party FW |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
