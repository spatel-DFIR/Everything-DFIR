# Unified Logs – Wi-Fi and Network

How macOS logs **Wi-Fi association, network configuration, service discovery, device continuity (Handoff/AirDrop), and VPN**. These reconstruct **where a Mac has been** (which SSIDs it joined), what it talked to on the LAN, and what data moved via AirDrop.

> 🔴 Wi-Fi join history + DHCP leases place a device on specific networks at specific times (geolocation/movement). AirDrop and continuity logs reveal **data transfer** and **nearby paired devices**.

## Contents
- [Quick Triage](#quick-triage)
- [Processes and Subsystems](#processes-and-subsystems)
- [Wi-Fi with airportd](#wi-fi-with-airportd)
- [Network Configuration with configd](#network-configuration-with-configd)
- [Broader Network Events](#broader-network-events)
- [Service Discovery mDNSResponder](#service-discovery-mdnsresponder)
- [Continuity and AirDrop](#continuity-and-airdrop)
- [VPN and Network Extension](#vpn-and-network-extension)
- [On-Disk Network Artifacts](#on-disk-network-artifacts)
- [Preserving Network Logs](#preserving-network-logs)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate 'process == "airportd"' --last 24h            # SSIDs joined

log show --predicate 'process == "sharingd"' --last 24h            # AirDrop transfers

log show --predicate 'subsystem == "com.apple.networkextension"' --last 24h   # VPN / filters

arp -a; lsof -i -nP; scutil --dns                                  # live LAN + DNS
```

---

## Processes and Subsystems

| Area | process / subsystem |
|---|---|
| Wi-Fi association / scans | `process == "airportd"` |
| IP / DHCP / interface config | `process == "configd"` |
| Broader network stack (newer macOS) | `subsystem == "com.apple.network"` |
| Bonjour / local service discovery | `process == "mDNSResponder"` |
| Device continuity (Handoff/Universal Clipboard) | `process == "rapportd"` |
| AirDrop | `process == "sharingd"`; `subsystem == "com.apple.sharing"` |
| VPN / per-app VPN / content filters | `subsystem == "com.apple.networkextension"`; `process == "nehelper"` |

Live network state (snapshot at triage — none of this is in the log):
```bash
ifconfig                       # interfaces + current IPs/MACs

arp -a                         # devices recently seen on the LAN (IP↔MAC)

netstat -rn                    # routing table (default gateway, odd routes)

lsof -i -nP                    # all current sockets + owning process (C2/exfil)

nettop -P -L1                  # per-process throughput (who's talking out)

scutil --dns                   # active DNS resolvers (hijack check)
```

---

## Wi-Fi with airportd

```bash
# Wi-Fi logs (last 24 hours)
log show --predicate 'process == "airportd"' --last 24h

# Activity for a specific SSID
log show --predicate 'process == "airportd" AND eventMessage CONTAINS "SSID-NAME-HERE"' --last 24h

# Monitor Wi-Fi in real time (resource-intensive)
log stream --predicate 'process == "airportd"' --info
```

🔴 Extract: **SSIDs joined** + timestamps (movement/geolocation), association/auth failures, BSSID (AP MAC), and roaming. A Mac connecting to an **unexpected SSID** (rogue AP, phone hotspot, "evil twin") is a red flag.

> Current Wi-Fi state live: `networksetup -getairportnetwork en0`; older `airport -I` (the `airport` CLI is removed in recent macOS).

---

## Network Configuration with configd

`configd` (SystemConfiguration) handles IP assignment, DHCP, and interface up/down.

```bash
# Network configuration changes (last 24 hours)
log show --predicate 'process == "configd"' --last 24h
```

🔴 Watch for: interface up/down, **IP/DHCP** changes, new DNS servers (DNS hijack), and link changes that correlate with attaching to a new network. (Proxy-specific `configd` entries → *Firewalls and Proxies*.)

---

## Broader Network Events

```bash
# Newer macOS unified network subsystem
log show --predicate 'subsystem == "com.apple.network"' --last 24h
```

> Captures higher-level connectivity, path changes, and per-flow events on modern macOS — use alongside `configd`/`airportd`.

---

## Service Discovery mDNSResponder

Bonjour/mDNS — local-network service discovery and DNS resolution.

```bash
# Local service discovery / mDNS (last 24 hours)
log show --predicate 'process == "mDNSResponder"' --last 24h
```

🔴 Value: hostnames/services the Mac saw or advertised on the LAN (lateral-movement recon), and DNS queries. Unusual `_service._tcp` advertisements or resolution of odd internal hosts can indicate enumeration.

---

## Continuity and AirDrop

`rapportd` brokers Continuity (Handoff, Universal Clipboard, Instant Hotspot); `sharingd` handles **AirDrop**.

```bash
# Continuity events (Handoff, etc.)
log show --predicate 'process == "rapportd"' --last 24h

# AirDrop (subsystem + daemon)
log show --predicate 'subsystem == "com.apple.sharing"' --last 24h

log show --predicate 'process == "sharingd"' --last 24h
```

🔴 DFIR value:

| Signal | Meaning |
|---|---|
| 🔴 AirDrop **send/receive** events | Data transfer on/off the Mac (exfil or ingress of tooling) |
| Filenames / peer device names in `sharingd` | What moved and to/from whom |
| Continuity with an **unknown** device | Unexpected paired/nearby Apple device |
| AirDrop set to **"Everyone"** | Exposure / opportunistic receipt |

> AirDrop received files commonly land in `~/Downloads` with a quarantine xattr (cross-ref File Permissions → quarantine).

---

## VPN and Network Extension

The **NetworkExtension** framework backs VPNs, per-app VPN, DNS proxies, and content filters; `nehelper` services those requests.

```bash
# VPN / network-extension activity
log show --predicate 'subsystem == "com.apple.networkextension"' --last 24h

# nehelper (NE request broker)
log show --predicate 'process == "nehelper"' --last 24h
```

🔴 Watch for: a **new VPN/tunnel** coming up (data egress path), a **content filter / DNS proxy** being installed (traffic interception, e.g. a rogue NE), and VPN connections at odd times. Configs live in `/Library/Preferences/com.apple.networkextension*.plist`.

---

## On-Disk Network Artifacts

| Artifact | Path | Holds |
|---|---|---|
| 🔴 Known Wi-Fi networks | `/Library/Preferences/com.apple.wifi.known-networks.plist` (modern); older `…/SystemConfiguration/com.apple.airport.preferences.plist` | SSIDs, last-joined times, security type, BSSIDs |
| Network interfaces / locations | `/Library/Preferences/SystemConfiguration/preferences.plist` | Configured services/interfaces |
| Current network state | `/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist` | Interface inventory |
| 🔴 DHCP leases | `/var/db/dhcpclient/leases/` | IPs leased + which network/when |
| VPN / NE configs | `/Library/Preferences/com.apple.networkextension*.plist` | Configured tunnels/filters |

> The known-networks plist is gold for **movement timelines** even when logs have rolled.

---

## Preserving Network Logs

```bash
# Snapshot of key network events
log show --predicate '(process == "airportd" OR process == "configd" OR process == "rapportd" OR subsystem == "com.apple.network")' --last 24h > network_events_snapshot.txt

# Full store for evidence
sudo log collect --output /evidence/host.logarchive
```

> Pair with the **known-networks plist** and **DHCP leases** above — they survive log rollover.

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Join to an **unexpected SSID** (hotspot, "evil twin", rogue AP) | Off-network exfil path / MITM |
| New/changed **DNS server** in `configd` | DNS hijack |
| AirDrop **send/receive** of sensitive files | Data exfil or tooling ingress |
| Continuity/AirDrop with an **unknown** device | Unexpected nearby/paired device |
| New **VPN tunnel** or **content filter / DNS proxy** (NE) | Covert egress / traffic interception |
| mDNS enumeration of internal hosts/services | Lateral-movement recon |
| Known-networks plist shows SSIDs not matching user's story | Movement the user didn't disclose |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
