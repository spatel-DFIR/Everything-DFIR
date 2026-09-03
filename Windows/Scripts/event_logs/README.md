# `hunt_eventlogs.ps1`

Read-only Windows Event Log inventory and timeframe-correct keyword/regex hunter — built to run
during **live EDR RTR (Real-Time Response) sessions** on a host you can't disturb.

- **Script:** [`hunt_eventlogs.ps1`](hunt_eventlogs.ps1) · **version:** 1.0 · **author:** Suvas Patel
- Part of the [`Windows/Scripts/`](../) collection of Windows DFIR scripts.
- Cross-ref: [`11 - Event Log Analysis`](<../../11 - Event Log Analysis.md>).

This is a professional rewrite/rebrand of an ad hoc one-off script. The rewrite exists for one
reason above all others: the original had a silent, timeframe-breaking bug in exactly the codepath
an analyst relies on most (see [§3](#3-the-bug-this-rewrite-fixes)).

---

## 1. Safety contract

This script is written under the assumption that it may be run against a live client host you have
no ability to remediate mistakes on. Every design decision follows from that:

- **Read-only / non-destructive.** Only calls `Get-WinEvent` (list + filtered query) and a
  read-only elevation check. Nothing is written, deleted, cleared, or configured.
- **Console-only, by design.** No file writes, no temp files, no CSV/JSON export. This is an
  explicit, permanent scope decision for RTR safety — not a "not implemented yet." If you need a
  structured export, pipe/copy the console transcript your RTR tooling already captures.
- **No elevation required to run.** The script checks whether it's running elevated and, if not,
  prints a warning banner and continues — logs it can't read (typically Security, and some
  provider/operational channels) land in the **unreadable logs** list at the end instead of
  crashing the run.
- **Single self-contained `.ps1`.** No external modules, no `Import-Module`, no dependency beyond
  what ships in-box with **Windows PowerShell 5.1** (not PowerShell 7 — no `??`, no ternary, no
  `&&`/`||`).

---

## 2. Quick start

```powershell
# Inventory: every event log with events on this host — record count + oldest/newest event (UTC)
.\hunt_eventlogs.ps1

# Keyword search: last 3 days, either substring, across every log
.\hunt_eventlogs.ps1 -Keywords '.msi','powershell.exe' -Days 3

# Regex search: scoped to one log, default 1-day lookback
.\hunt_eventlogs.ps1 -Pattern '\b(4104|4103)\b' -LogName 'Microsoft-Windows-PowerShell/Operational'

# Level + explicit timeframe, no keyword needed (a pure scoped dump)
.\hunt_eventlogs.ps1 -Level Error,Critical -Since '2026-07-27 08:00:00' -Until '2026-07-27 20:00:00' -LogName System

# -Help works even where Get-Help doesn't reliably invoke inside an RTR console
.\hunt_eventlogs.ps1 -Help
```

### Modes (Inventory is the default; Search auto-promotes)

| Mode | When it runs | What it does |
|---|---|---|
| `Inventory` | Default — no `-Keywords`/`-Pattern`/`-Level` given | Lists every log on the host with events: name, record count, oldest/newest event time (UTC) |
| `Search` | Auto-enabled by `-Keywords`, `-Pattern`, or `-Level` — or forced with `-Mode Search` | Timeframe-scoped per log, then keyword/regex/level filtered; prints full match blocks + a tally |

`-Mode Search` with none of `-Keywords`/`-Pattern`/`-Level` still runs — it dumps every event in
the scope you gave it (`-LogName`/`-Since`/`-Days`/`-Until`), tagged as a scope-only match. See
[§5](#5-choosing-good-keywords-and-narrowing-the-search).

---

## 3. The bug this rewrite fixes

The original script ran:

```powershell
Get-WinEvent -LogName $Log.LogName -MaxEvents 500 -ErrorAction SilentlyContinue |
    Where-Object {$_.TimeCreated -ge $StartDate}
```

**`-MaxEvents 500` is applied first, against the raw log, newest-record-first — the time filter
only runs afterward, against whatever 500 records happened to come back.** On a quiet log that's
harmless. On a busy log (Security, `Microsoft-Windows-Windows Defender/Operational`, PowerShell
operational) 500 raw records can span a few minutes of wall-clock time. If your requested window
was "last 24 hours," the query silently returned "the last few minutes," and **nothing told the
operator this happened** — the script just reported fewer (or zero) matches, indistinguishable
from a genuinely quiet window.

**The fix:** put the timeframe inside `-FilterHashtable`:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = $log; StartTime = $StartDate; EndTime = $EndDate } -MaxEvents $MaxEvents
```

`FilterHashtable`'s `StartTime`/`EndTime` are evaluated by the event log provider **before**
`-MaxEvents` trims the result set. So `-MaxEvents` now correctly means *"the most recent N events
**within the timeframe**,"* not *"the most recent N events, then hope they're in the timeframe."*
Nothing from your requested window is silently skipped; if a log's own `-MaxEvents` cap gets hit,
that's now a true statement about event density inside your window, not an artifact of query order.

---

## 4. Reading a match

Search-mode output is a full, un-clipped block per match — never `Format-Table -Wrap | Out-String`,
which clips exactly the wide `Message` text an analyst needs to read:

```
------------------------------------------------------------
Time     : 2026-07-28 14:22:05 UTC
Log      : Security
EventID  : 4624
Level    : Information
Source   : Microsoft-Windows-Security-Auditing
Matched  : keyword '127.0.0.1'
Message  :
An account was successfully logged on.

Subject:
	Security ID:		SYSTEM
	Account Name:		HOST$
	...
Network Information:
	Workstation Name:	HOST
	Source Network Address:	127.0.0.1
	Source Port:		52344
------------------------------------------------------------
```

`Matched` shows exactly why this event fired — which keyword(s), the regex, or (with no text
filter) `(scope filter only — no text match required)`. All timestamps are **UTC** — this is a
firm convention throughout the script (`.ToUniversalTime()` on every displayed time), so results
line up regardless of the host's local time-zone setting.

At the end of a run, a summary tallies **total matches**, a **breakdown by log**, a **breakdown by
keyword/pattern/scope**, and the **unreadable logs** list — logs that genuinely errored (need
elevation, disabled channel, a bad query) as opposed to logs that simply had nothing in the window
(which are skipped silently, since that's not an error).

---

## 5. Choosing good keywords (and narrowing the search)

The original script's default keyword list — `"127.0.0.1", ".msi"` — is a useful cautionary
example, not a template to copy. `.msi` in particular is a **floods-with-noise anti-pattern**:
software inventory, Windows Update, and every routine install/patch event mentions an `.msi` path
somewhere in its message text, so on a normally-patched host this keyword alone can return
hundreds of entirely benign matches per day and bury the one that matters. A keyword search is
only as good as how specific the substring is to what you're actually hunting.

How to narrow it, in order of preference:

1. **Be specific in the string itself.** A full or near-full path (`C:\Users\Public\update.msi`),
   a distinctive filename, a C2 domain, or a rare argument fragment beats a bare extension.
2. **Scope the log(s) with `-LogName`.** `-LogName 'Microsoft-Windows-PowerShell/Operational'` or
   `-LogName 'Microsoft-Windows-Windows Defender/Operational'` (wildcards supported, e.g.
   `-LogName 'Microsoft-Windows-*'`) turns a host-wide sweep into a targeted one.
3. **Use `-Level` to drop noise tiers.** `-Level Error,Critical` on `System`/`Application` skips
   the routine `Information` chatter that a keyword match would otherwise have to wade through.
4. **Tighten the timeframe.** `-Since`/`-Until` (or a small `-Days`) around the suspected incident
   window does more to cut noise than almost anything else — see [§3](#3-the-bug-this-rewrite-fixes)
   for why the timeframe filter is now trustworthy.
5. **Reach for `-Pattern` when a keyword can't express the shape you want** — e.g.
   `-Pattern '\b(4104|4103)\b'` for PowerShell script-block logging event IDs mentioned in message
   text, or `-Pattern '\\Users\\[^\\]+\\AppData\\Local\\Temp\\.*\.(exe|dll|ps1)$'` for an
   execution-from-temp shape. A single bad regex prints one warning and disables pattern matching
   for the run — it will not throw per event.

`-Keywords` and `-Pattern` are **OR'd together** when both are given: an event matches if *either*
fires. If you want AND-style narrowing, do it structurally instead — via `-LogName`, `-Level`, and
a tight `-Since`/`-Until` window, since a single substring/regex check against the whole `Message`
can't easily express "contains A AND B."

---

## 6. Options

| Option | Effect |
|---|---|
| `-Mode Inventory\|Search` | Force a mode. Default: `Inventory`, auto-promoted to `Search` by `-Keywords`/`-Pattern`/`-Level` |
| `-Keywords <string[]>` | Substring match against `Message` (OR logic across keywords). Case-insensitive by default. Plain `.Contains()`, not `-like` — a keyword containing `*`/`?`/`[` is matched literally, not as a wildcard |
| `-Pattern <regex>` | Single .NET regex matched against `Message` via `[Text.RegularExpressions.Regex]::IsMatch()`. Case-insensitive by default. Invalid regex → one warning, matching disabled for the run |
| `-CaseSensitive` | Makes both `-Keywords` and `-Pattern` matching case-sensitive |
| `-Level <string[]>` | `Critical`\|`Error`\|`Warning`\|`Information`\|`Verbose` (array). Maps to the native event Level filter. Given alone (no keyword/pattern), still promotes to `Search` and emits every event at that level in scope |
| `-LogName <string[]>` | Restrict which logs are used. Supports wildcards via `-like`, e.g. `'Microsoft-Windows-*'`. Does **not** by itself promote `Inventory` to `Search` |
| `-Since <datetime>` | Start of the timeframe, e.g. `'2026-07-28'` or `'2026-07-28 09:00:00'`. Interpreted in the **host's local time zone**. Wins over `-Days` if both are given |
| `-Days <int>` | Lookback window in days from now (default `1`, matching the original script). Ignored if `-Since` is given |
| `-Until <datetime>` | End of the timeframe, same format/time-zone rules as `-Since`. Default: now |
| `-MaxEvents <int>` | Per-log cap on returned events, applied **after** the timeframe filter (default `500`) |
| `-IncludeEmptyLogs` | Include/search logs with `RecordCount 0` too (default: skipped in both modes) |
| `-Help` | Print usage and exit immediately, before anything else runs |

`Get-Help .\hunt_eventlogs.ps1 -Full` also works — the script carries a full comment-based help
block — but `-Help` exists as a fallback since some RTR consoles don't invoke comment-based help
reliably.

---

## 7. Self-documenting runs

Every run (except `-Help`) opens with a banner so a saved RTR transcript is self-documenting on
its own, without needing the operator's scrollback:

```
hunt_eventlogs.ps1  v1.0    author: Suvas Patel
Ran at   : 2026-07-29 18:04:11 UTC
Hostname : WIN10-CLIENT01
Mode     : Search
Command  : .\hunt_eventlogs.ps1 -Keywords '.msi','powershell.exe' -Days 3

Timeframe: 2026-07-26 18:04:11 UTC  ->  2026-07-29 18:04:11 UTC
```

If not running elevated, a warning banner follows immediately, and the run continues (never a hard
failure):

```
!! WARNING: not running elevated. The Security log and some provider logs
!! (e.g. Microsoft-Windows-* channels requiring privileged read access) may be
!! inaccessible; they will appear in the unreadable-logs list below rather than
!! causing a failure. Re-run from an elevated PowerShell for full coverage.
```

---

## 8. Notes & limitations

- **Message text can be unavailable** for events whose provider/manifest isn't installed locally
  (common after a provider's uninstalled, or the log came from a different build) — those events
  print `(no message text available for this event)` rather than being silently skipped, and
  keyword/pattern matching against them naturally can't fire.
- **`-Since`/`-Until` are local-time strings** by design (an operator typing a time during live
  response reads their own clock); all *displayed* timestamps are UTC regardless.
- **Coverage depends on elevation.** Non-elevated runs will show `Security` and some provider logs
  in the unreadable-logs list rather than results from them — re-run elevated for full coverage.
- **No export, ever, on purpose.** If you need the output preserved, capture it the way your RTR
  tooling already captures console transcripts.

---

## 9. Changelog

- **v1.0** — Initial professional rewrite/rebrand of the original ad hoc keyword-search script.
  **Bug fixed:** the original applied `-MaxEvents 500` against the raw log *before* filtering by
  `-TimeCreated -ge $StartDate`, so on a busy log the newest 500 raw records could span only a few
  minutes and silently drop matches from earlier in the requested window with no indication to the
  operator (see [§3](#3-the-bug-this-rewrite-fixes)). Fixed by moving `StartTime`/`EndTime` into
  `-FilterHashtable`, which the provider evaluates before `-MaxEvents` trims results.
  **Features added:** `Inventory` mode (log roster + record count + oldest/newest event, UTC);
  regex search via `-Pattern` (validated once, not per event); `-Level` filter mapped to the native
  event Level; `-LogName` wildcard scoping; `-Since`/`-Until` explicit-window support alongside
  `-Days`; literal (non-`-like`) keyword matching so `*`/`?`/`[` in a keyword can't break the match;
  an elevation check that warns and degrades instead of failing; an unreadable-logs list that
  distinguishes a genuine query error from "nothing in this window" (which is not an error); a
  self-documenting banner (version, author, UTC run time, hostname, mode, effective command line);
  full, un-clipped per-match output instead of a clipped `Format-Table -Wrap`; a `-Help` switch and
  comment-based help block. Read-only, console-only, no CSV/JSON export by design (RTR safety).
