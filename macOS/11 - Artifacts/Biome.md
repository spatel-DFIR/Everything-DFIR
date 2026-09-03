# Biome

**Biome** is Apple's newer on-device activity framework that has **taken over much of the usage logging** once held by `knowledgeC.db` and **PowerLog**. On modern macOS (Ventura/Sonoma+) it's rapidly becoming a **must-check** artifact — app launches, focus, device state, notifications, and more flow into Biome. The catch: it stores data in **proprietary `SEGB` files** (protobuf-encoded records), and **open-source parsing is still immature** — expect to lean on commercial tools, `mac_apt` (as support lands), or early projects like `ccl-segb` / Dissectify.

> 🔴 The takeaway for triage: on a **recent** Mac, the user-activity timeline you used to get from `knowledgeC.db` increasingly lives in **Biome** — don't skip it just because parsing is harder. `knowledgeC.db` still matters on older systems; Biome is the modern equivalent.

## Contents
- [Quick Triage](#quick-triage)
- [What Biome Is](#what-biome-is)
- [Where It Lives](#where-it-lives)
- [SEGB File Format](#segb-file-format)
- [What It Records](#what-it-records)
- [knowledgeC vs Biome](#knowledgec-vs-biome)
- [Parsing Biome](#parsing-biome)
- [Why It Matters for DFIR](#why-it-matters-for-dfir)
- [Caveats](#caveats)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Locate Biome data (per-user)
find ~/Library/Biome -type f 2>/dev/null | head -50

ls -la ~/Library/Biome/streams/public/ 2>/dev/null

# System-level Biome
sudo find /private/var/db/biome -type f 2>/dev/null | head -50

# Identify SEGB containers, then parse with ccl-segb
python3 -m ccl_segb ~/Library/Biome/streams/public/<stream>/local/<file>
```

---

## What Biome Is

- A successor activity/“pattern of life” pipeline on macOS and iOS that **ingests events into per-stream files**, supplanting `knowledgeC.db` and `PowerLog` for many event types.
- Stores records in **SEGB** container files; the actual event payloads are **protobuf**-serialized (per-stream schemas).
- Designed for Apple's on-device intelligence (Siri suggestions, Spotlight, Focus), but the byproduct is a **detailed user-activity log** for forensics.

---

## Where It Lives

| Path | Scope |
|---|---|
| 🔴 `~/Library/Biome/` | **Per-user** Biome data |
| `~/Library/Biome/streams/public/<stream>/…` | Public event streams (SEGB files, often under `local/`) |
| `~/Library/Biome/streams/restricted/<stream>/…` | Restricted streams |
| `/private/var/db/biome/` | System-level Biome |

> Structure/stream names **vary by macOS version**. Enumerate with `find`; don't assume a fixed layout.

---

## SEGB File Format

**SEGB** is the proprietary **container/record** format Biome uses (also seen in other modern Apple artifacts).

- Two known generations — **SEGB v1** and **SEGB v2** — with different headers/record framing.
- A SEGB file is a sequence of **records**; each record's payload is usually a **protobuf** message specific to that stream.
- 🔴 Parsing is **two layers**: (1) decode the SEGB container into records (e.g. `ccl-segb`), then (2) decode each record's **protobuf** — which needs the per-stream definition (often reverse-engineered, not public).

---

## What It Records

Stream contents overlap with (and extend) the old knowledgeC streams:

| Activity | DFIR value |
|---|---|
| 🔴 App launches / foreground / focus | Application execution & usage timeline |
| Device state (lock/unlock, backlight, power) | User presence at the machine |
| Notifications | What was shown / interacted with |
| Web / Safari activity | Browsing behavior |
| Now-playing / media | Media usage |
| Location / routine (where present) | Movement / presence (privacy-sensitive) |
| Siri / suggestions / intents | User intent signals |

---

## knowledgeC vs Biome

| | knowledgeC.db | Biome |
|---|---|---|
| Era | Older macOS (still present) | Modern macOS (Ventura+) |
| Format | **SQLite** (easy: `sqlite3`) | **SEGB + protobuf** (hard) |
| Tooling | Mature (APOLLO, mac_apt) | **Immature** (ccl-segb, commercial, Dissectify) |
| Status | May be **sparse** on newest systems | The **growing** must-check source |

> 🔴 Check **both**: knowledgeC for history/older systems, Biome for current activity. On the newest macOS, Biome may be the only place an event exists.

---

## Parsing Biome

```bash
# Enumerate streams + files
find ~/Library/Biome -type f 2>/dev/null

ls -la ~/Library/Biome/streams/public/

# Decode SEGB records (CCL ccl-segb — SEGB v1 & v2)
python3 -m ccl_segb /path/to/segb_file

# Preserve for offline analysis
cp -R ~/Library/Biome /evidence/biome_user

sudo cp -R /private/var/db/biome /evidence/biome_system
```

| Option | Notes |
|---|---|
| 🔴 **Commercial** (Cellebrite, AXIOM, Recon) | Most complete Biome parsing today |
| **mac_apt** | Adding Biome support — check current version |
| **ccl-segb** (CCL) | Open-source SEGB v1/v2 record decoder (provided resource) — gets you records; protobuf decode still needed |
| **Dissectify** | Experimental open-source tool with Biome support (early, not widely vetted — try & give feedback) |

---

## Why It Matters for DFIR

- 🔴 On modern macOS, the **richest user-activity timeline** (app exec, presence, web, media) increasingly lives here — not in knowledgeC.
- Fills the gap when `knowledgeC.db` is sparse/empty on newer systems.
- Survives even when other logs (Unified Logs) have rolled — Biome retains history.
- Corroborates app execution / presence findings from knowledgeC, Unified Logs, and Spotlight.

---

## Caveats

- ⚠️ **Proprietary + protobuf** → no clean, complete open-source parser yet; results depend on the tool's reverse-engineered schemas.
- **SEGB v1 vs v2** and stream layouts **change across macOS versions** — verify your tool matches the OS version.
- Decoding the SEGB container is only half the job; the **protobuf payload** still needs per-stream definitions.
- Treat partial/early-tool output cautiously and **corroborate** before relying on it.

---

## Correlate With

| To answer | Pivot to |
|---|---|
| Older usage history | **knowledgeC.db** (pre-Biome) |
| App execution corroboration | **Unified Logs** (launchd) · Spotlight `kMDItemLastUsedDate` · **FSEvents** |
| Was an executed app trusted? | **Unified Logs – Gatekeeper, TCC, and XProtect** |
| Is the app persistent? | LaunchAgents/Daemons (persistence) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| Biome app-launch records for a suspicious app | Execution evidence on a modern Mac (where knowledgeC is empty) |
| Activity/presence at odd hours | User active when they claim absence |
| Web/media/location records contradicting the user's account | Behavior reconstruction |
| Biome data **wiped/missing** on a modern system | Anti-forensics — corroborate with Unified Logs/FSEvents |
| Events in Biome but **not** in knowledgeC | Normal on new macOS — Biome is now the source of truth |

---

## Resources

- ccl-segb — Python modules for parsing SEGB v1 and v2 (CCL): https://github.com/cclgroupltd/ccl-segb
- APOLLO (Apple Pattern of Life Lazy Output'er): https://github.com/mac4n6/APOLLO
- mac_apt (macOS Artifact Parsing Tool): https://github.com/ydkhatri/mac_apt
