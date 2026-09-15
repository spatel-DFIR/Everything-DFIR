# Unified Logs – Bluetooth

How macOS logs **Bluetooth**: device discovery, **pairing**, connect/disconnect, Apple Watch **auto-unlock**, and proximity/continuity. These trace which peripherals and nearby devices interacted with the Mac — useful for spotting **unusual pairings** (rogue keyboards/HID, data-exfil peripherals) and placing devices near the host.

> 🔴 A new/unexpected **pairing** (especially HID — keyboard/mouse) can mean a physical attack (BadUSB-style HID injection) or an unauthorized peripheral. Pairing + connect timestamps also place a known device near the Mac.

## Contents
- [Quick Triage](#quick-triage)
- [Processes and Subsystems](#processes-and-subsystems)
- [Bluetooth Daemon Logs](#bluetooth-daemon-logs)
- [Pairing Events](#pairing-events)
- [Connect and Disconnect](#connect-and-disconnect)
- [Apple Watch Unlock and Proximity](#apple-watch-unlock-and-proximity)
- [Continuity over Bluetooth](#continuity-over-bluetooth)
- [Subsystem-Level Events](#subsystem-level-events)
- [On-Disk Bluetooth Artifacts](#on-disk-bluetooth-artifacts)
- [Live Streaming and Preserving](#live-streaming-and-preserving)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
log show --predicate '(process == "bluetoothd" OR process == "blued") AND eventMessage CONTAINS "Pairing"' --last 24h

log show --predicate 'process == "wirelessproxd"' --last 24h       # Apple Watch unlock

plutil -p /Library/Preferences/com.apple.Bluetooth.plist 2>/dev/null   # paired devices

system_profiler SPBluetoothDataType
```

---

## Processes and Subsystems

| Area | process / subsystem |
|---|---|
| Core Bluetooth daemon | `process == "bluetoothd"` (legacy `blued`) |
| Apple Watch unlock / proximity | `process == "wirelessproxd"` |
| Continuity over Bluetooth | `process == "rapportd"` |
| Subsystem-level events | `subsystem == "com.apple.Bluetooth"` |

> `blued` is the older daemon name (pre-modern macOS); query both for coverage on upgraded systems.

---

## Bluetooth Daemon Logs

```bash
# Bluetooth logs from bluetoothd or blued (last 24 hours)
log show --predicate 'process == "bluetoothd" OR process == "blued"' --last 24h
```

🔴 Extract device names, MAC addresses, device **class** (HID vs audio vs phone), and pairing/connection lifecycle.

---

## Pairing Events

```bash
# Pairing-related messages
log show --predicate '(process == "bluetoothd" OR process == "blued") AND eventMessage CONTAINS "Pairing"' --last 24h
```

🔴 A pairing event = a device was **bonded** to this Mac. Note the device name/MAC and **when**. New HID (keyboard/mouse) pairings are the highest-risk (input injection); unknown phones/peripherals may indicate data movement.

---

## Connect and Disconnect

```bash
# Connected / disconnected messages
log show --predicate '(process == "bluetoothd" OR process == "blued") AND (eventMessage CONTAINS "Connected" OR eventMessage CONTAINS "Disconnected")' --last 24h
```

🔴 Connect/disconnect timestamps place a **known** paired device physically near the Mac at specific times (presence timeline). Repeated brief connects from an unknown device = scanning/proximity probing.

---

## Apple Watch Unlock and Proximity

```bash
# wirelessproxd (Apple Watch auto-unlock, proximity features)
log show --predicate 'process == "wirelessproxd"' --last 24h
```

🔴 Apple Watch **auto-unlock** events show the owner (with their Watch) was physically present to unlock the Mac — strong evidence of who/when, and corroborates `loginwindow` unlock entries (cross-ref Authentication).

---

## Continuity over Bluetooth

```bash
# rapportd — continuity (Handoff, etc.) over Bluetooth
log show --predicate 'process == "rapportd"' --last 24h
```

> `rapportd` also appears in *Wi-Fi and Network* (continuity rides BLE + Wi-Fi). Here, focus on the **Bluetooth/proximity** side: which nearby Apple devices the Mac handed off to/from.

---

## Subsystem-Level Events

```bash
# Subsystem-level Bluetooth events
log show --predicate 'subsystem == "com.apple.Bluetooth"' --last 24h
```

> Broader framework-level events not tied to a single daemon; use alongside the `bluetoothd` queries.

---

## On-Disk Bluetooth Artifacts

| Artifact | Path | Holds |
|---|---|---|
| 🔴 Paired devices | `/Library/Preferences/com.apple.Bluetooth.plist` | Paired device list, names, MACs, last-seen/connect data |
| Per-user BT prefs | `~/Library/Preferences/ByHost/com.apple.Bluetooth.*.plist` | User-side device settings |
| Live state | `system_profiler SPBluetoothDataType` | Current paired/connected devices + addresses |

> The paired-devices plist survives log rollover — pull it for the full bonded-device history.

---

## Live Streaming and Preserving

```bash
# Stream Bluetooth in real time (resource-intensive)
log stream --predicate '(process == "bluetoothd" OR process == "blued" OR process == "wirelessproxd")' --info

# Preserve a snapshot of Bluetooth events
log show --predicate '(process == "bluetoothd" OR process == "blued" OR process == "wirelessproxd" OR subsystem == "com.apple.Bluetooth")' --last 24h > bluetooth_events_snapshot.txt
```

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| New **HID pairing** (keyboard/mouse) | Possible input-injection / BadUSB-style attack |
| Unknown device **paired** to the Mac | Unauthorized peripheral / data movement |
| Repeated brief connects from an unknown device | Proximity probing / scanning |
| Pairing event at an **odd time** / outside user presence | Unauthorized physical access |
| Apple Watch unlock when owner claims absence | Timeline contradiction |
| Paired-devices plist lists devices the user doesn't recognize | Rogue bonded peripheral |

---

## Resources

- Apple Developer – Logging: https://developer.apple.com/documentation/os/logging
- Apple Support – macOS Logs and Console: https://support.apple.com/en-ca/guide/console/welcome/mac
- The Eclectic Light Company – Consolation / Ulbow / log utilities: https://eclecticlight.co/consolation-t2m2-and-log-utilities/
