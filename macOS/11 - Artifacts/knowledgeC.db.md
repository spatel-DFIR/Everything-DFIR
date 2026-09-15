# knowledgeC.db

`knowledgeC.db` is a SQLite database from Apple's **CoreDuet / "Knowledge"** framework that records **device and app usage events** — which apps ran and for how long, web usage, media playback, Bluetooth connections, device lock/unlock, and more. It's a **user-activity timeline goldmine**. On modern macOS much of this has migrated to **Biome**, but `knowledgeC.db` remains important on **older systems** (and often still holds data). You analyze it with the built-in **`sqlite3`**.

> 🔴 Everything hangs off the **`ZOBJECT`** table: each row is an event on a **stream** (`ZSTREAMNAME` like `/app/usage`, `/app/inFocus`, `/bluetooth/isConnected`), with start/end dates. Timestamps are **Mac absolute time** (seconds since **2001-01-01**) — add **978307200** to convert to Unix epoch.

## Contents
- [Quick Triage](#quick-triage)
- [Where It Lives](#where-it-lives)
- [Schema Essentials](#schema-essentials)
- [Timestamps](#timestamps)
- [Event Streams](#event-streams)
- [Core Queries](#core-queries)
- [App Usage with Duration](#app-usage-with-duration)
- [Why It Matters for DFIR](#why-it-matters-for-dfir)
- [Tools and Caveats](#tools-and-caveats)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

---

## Quick Triage

```bash
# Locate the DB (per-user; copy out before querying live)
ls -la ~/Library/Application\ Support/Knowledge/knowledgeC.db

cp ~/Library/Application\ Support/Knowledge/knowledgeC.db /evidence/

# What kinds of events are recorded?
sqlite3 /evidence/knowledgeC.db "SELECT DISTINCT ZSTREAMNAME FROM ZOBJECT ORDER BY ZSTREAMNAME;"

# Recent app usage (human-readable time)
sqlite3 /evidence/knowledgeC.db "SELECT ZSTREAMNAME, ZVALUESTRING, DATETIME(ZSTARTDATE + 978307200, 'unixepoch') FROM ZOBJECT WHERE ZSTREAMNAME LIKE '%app%' ORDER BY ZSTARTDATE DESC LIMIT 10;"
```

---

## Where It Lives

| Path | Scope |
|---|---|
| 🔴 `~/Library/Application Support/Knowledge/knowledgeC.db` | **Per-user** activity (primary) |
| `/private/var/db/CoreDuet/Knowledge/knowledgeC.db` | System/aggregate (older macOS) |

> Copy the DB (and its `-wal`/`-shm` sidecars) before querying so you don't alter evidence. On a dead-box image, pull all of the above.

---

## Schema Essentials

The table that matters is **`ZOBJECT`**:

| Column | Holds |
|---|---|
| 🔴 `ZSTREAMNAME` | The event type/stream (`/app/usage`, `/bluetooth/isConnected`, …) |
| `ZVALUESTRING` | String payload — usually the **app bundle ID** or URL/string for the event |
| `ZVALUEINTEGER` | Integer payload — e.g. Bluetooth connected = 1/0 |
| 🔴 `ZSTARTDATE` / `ZENDDATE` | Event start/end (Mac absolute time) → **duration** |
| `ZCREATIONDATE` | When the record was written |
| `ZSECONDSFROMGMT` | GMT offset → derive **local** time |
| `ZSOURCE` / `ZUUID` / `Z_PK` | Source, unique id, primary key |

Other tables: `ZSTRUCTUREDMETADATA` (extra typed metadata), `ZSOURCE`, `ZCUSTOMMETADATA`.

---

## Timestamps

🔴 Times are **Cocoa/Mac absolute time** = seconds since **2001-01-01 00:00:00 UTC**. Convert:

```sql
DATETIME(ZSTARTDATE + 978307200, 'unixepoch')                 -- UTC
DATETIME(ZSTARTDATE + 978307200, 'unixepoch', 'localtime')    -- analyst local
DATETIME(ZSTARTDATE + 978307200 - ZSECONDSFROMGMT, 'unixepoch') -- device local
```

The constant **978307200** is the seconds between 1970 and 2001 epochs.

---

## Event Streams

High-value `ZSTREAMNAME` values:

| Stream | What it tells you |
|---|---|
| 🔴 `/app/usage` | App used + start/end (execution timeline) |
| `/app/inFocus` | App brought to foreground (focus) |
| 🔴 `/app/webUsage` | Web/Safari usage |
| `/app/activity` | App activity |
| 🔴 `/bluetooth/isConnected` | BT device connect/disconnect (presence, exfil device) |
| `/media/nowPlaying` | Media playback |
| `/display/isBacklit` | Screen on/off |
| `/device/isLocked` | Device lock/unlock (presence at keyboard) |
| `/device/isPluggedIn` | Power state |
| `/notification/usage` | Notifications shown |
| `/siri/*` | Siri usage |

---

## Core Queries

All four lesson queries, verbatim:

```sql
-- Distinct event streams (overview of what's logged)
SELECT DISTINCT ZSTREAMNAME
FROM ZOBJECT
ORDER BY ZSTREAMNAME;
```

```sql
-- App usage (foreground apps + start time)
SELECT
ZSTREAMNAME,
ZVALUESTRING,
DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS LocalStartTime
FROM ZOBJECT
WHERE ZSTREAMNAME LIKE '%app%'
ORDER BY ZSTARTDATE DESC
LIMIT 10;
```

```sql
-- Bluetooth connection changes
SELECT
ZSTREAMNAME,
ZVALUEINTEGER,
DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS LocalStartTime
FROM ZOBJECT
WHERE ZSTREAMNAME = '/bluetooth/isConnected'
ORDER BY ZSTARTDATE DESC
LIMIT 10;
```

```sql
-- Web usage (Safari / web activity)
SELECT
ZSTREAMNAME,
ZVALUESTRING,
DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS LocalStartTime
FROM ZOBJECT
WHERE ZSTREAMNAME = '/app/webUsage'
ORDER BY ZSTARTDATE DESC
LIMIT 10;
```

```sql
-- Media playback (nowPlaying)
SELECT
ZSTREAMNAME,
ZVALUESTRING,
DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS LocalStartTime
FROM ZOBJECT
WHERE ZSTREAMNAME = '/media/nowPlaying'
ORDER BY ZSTARTDATE DESC
LIMIT 10;
```

Run any of them with:

```bash
sqlite3 /evidence/knowledgeC.db < query.sql
```

---

## App Usage with Duration

🔴 `ZSTARTDATE`→`ZENDDATE` gives how **long** an app was used — strong for "what was running when":

```sql
SELECT
  ZVALUESTRING AS App,
  DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS Start,
  DATETIME(ZENDDATE   + 978307200, 'unixepoch') AS End,
  (ZENDDATE - ZSTARTDATE) AS Seconds
FROM ZOBJECT
WHERE ZSTREAMNAME = '/app/usage'
ORDER BY ZSTARTDATE DESC
LIMIT 25;
```

```sql
-- Device lock/unlock (presence at the machine)
SELECT ZVALUEINTEGER AS Locked,
       DATETIME(ZSTARTDATE + 978307200, 'unixepoch') AS Time
FROM ZOBJECT
WHERE ZSTREAMNAME = '/device/isLocked'
ORDER BY ZSTARTDATE DESC LIMIT 25;
```

---

## Why It Matters for DFIR

- 🔴 **App execution timeline** — which apps ran, when, and for how long (incl. malware/tools).
- **Presence**: lock/unlock + backlight + nowPlaying show a human was actively using the Mac at given times.
- 🔴 **Bluetooth** connects/disconnects — a paired phone/exfil device near the machine, with timing.
- **Web usage** — browsing activity even when history is cleared.
- Corroborates Unified Logs, Spotlight `kMDItemLastUsedDate`, and Biome.

---

## Tools and Caveats

- **APOLLO** (Sarah Edwards) bundles ready-made knowledgeC queries across versions — fastest path.
- **mac_apt** parses knowledgeC in bulk during image processing.
- ⚠️ **Schema varies by macOS version** — column/stream names can differ; inspect with `.schema ZOBJECT` and `SELECT DISTINCT ZSTREAMNAME`.
- On modern macOS, much of this moved to **Biome** (see the Biome note) — knowledgeC may be sparse on the newest systems but is still gold on older ones.

```bash
sqlite3 /evidence/knowledgeC.db ".schema ZOBJECT"
```

---

## Correlate With

| To answer | Pivot to |
|---|---|
| App execution (modern macOS / fuller picture) | **Biome** · **Unified Logs** (launchd) · Spotlight `kMDItemLastUsedDate` |
| Is the app persistent? | LaunchAgents/Daemons (**Users and Groups** / persistence) |
| Bluetooth device presence | **Unified Logs – Bluetooth** |
| Presence at the machine (lock/unlock) | **Unified Logs – Authentication** (loginwindow) |

---

## Red Flags

| 🔴 Finding | Likely meaning |
|---|---|
| `/app/usage` for an unknown/suspicious app | Malware/tool execution with timing |
| App usage at **odd hours** | Activity when the user claims absence |
| `/bluetooth/isConnected` to an unknown device | Exfil/pairing device present, with time |
| `/app/webUsage` to suspicious domains | Browsing even if history cleared |
| Lock/unlock pattern contradicting an alibi | Someone physically using the Mac |
| knowledgeC.db **missing/emptied** | Anti-forensics (then pivot to Biome / Unified Logs) |

---

## Resources

- APOLLO (Apple Pattern of Life Lazy Output'er) — knowledgeC/Biome queries: https://github.com/mac4n6/APOLLO
- mac_apt (macOS Artifact Parsing Tool): https://github.com/ydkhatri/mac_apt
