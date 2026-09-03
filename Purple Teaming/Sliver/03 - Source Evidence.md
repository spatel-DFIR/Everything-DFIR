# Sliver — Source Evidence

Evidence left on the **operator/server-side** infrastructure — the box (or boxes) running `sliver-server` and any `sliver-client` instances connecting to it. Like Responder, Sliver is a **long-running service**, but unlike Responder its footprint is split across two roles: the **server** (persistent database, listener jobs, all historical session/beacon state) and each **operator's client** (console history, imported operator config, local loot copies). A seized server gives DFIR far more than a seized client — the server is the single source of truth for everything the framework ever did.

## Contents
- [The Server Database](#the-server-database)
- [Server Configuration and Certificates](#server-configuration-and-certificates)
- [Console Logs](#console-logs)
- [Audit Log](#audit-log)
- [Loot Store](#loot-store)
- [Live Process and Socket State](#live-process-and-socket-state)
- [Operator Client Artifacts](#operator-client-artifacts)
- [Shell History](#shell-history)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## The Server Database

Sliver's server persists implant builds, profiles, session/beacon metadata, task history, and loot in a **SQLite database by default** (accessed via GORM — the server also supports MySQL/PostgreSQL as alternate backends, verified against the server's ORM driver dependencies in `go.mod`/release changelogs rather than the outdated "BoltDB" claim that circulates in some older third-party write-ups). The exact on-disk path is configuration-dependent (see `configs/server.json`, below) rather than a single fixed location — locate it via the running process's open file handles if the config file isn't available:

```bash
# Identify the DB file a running server process has open
lsof -p $(pgrep sliver-server) 2>/dev/null | grep -iE '\.db$|sqlite'
```

This database is the single most valuable artifact on the server host: every implant ever generated (with its embedded C2 config and per-binary key material), every session/beacon that ever checked in (with source IP, hostname, username, OS), and the full task/result history for every command an operator ever issued — including against beacons whose tasks may not yet have completed at time of seizure.

## Server Configuration and Certificates

| Artifact | Location pattern | Notes |
|---|---|---|
| Server config | `configs/server.json` (relative to the server's working directory, or `~/.sliver-server/configs/` in common install layouts) | Daemon-mode settings, multiplayer port, TLS/GRPC bind config |
| Certificate authority material | Server-managed CA used to sign both implant certs and operator `.cfg` mTLS certs (`certs.SetupCAs()` in `server/cli/operator.go`) | The CA private key on disk is what makes every operator config and every mTLS implant on that server trustable — its compromise/exfiltration is a full-framework-compromise event, not just a single-implant one |
| HTTP C2 profiles | Server-side profile store, referenced by `--c2profile` at generate time | Defines the procedural URL/header shaping used by that profile's implants — recovering this from the server tells you exactly what URL patterns to hunt for target-side, without needing to reverse a live implant |
| Website content (`websites` command) | Server-managed static content served alongside HTTP(S) listeners for decoy/staging purposes | Any files staged this way are directly recoverable from the server |

## Console Logs

Verified against the v1.6.0 changelog's addition of **"rotate and compress server-side console logs"** and **"console session asciicast recorder"** — the server retains a history of console activity independent of any individual operator's own terminal scrollback:

```bash
find / -iname "*.log" -path "*sliver*" 2>/dev/null
find / -iname "*.cast" 2>/dev/null   # asciicast session recordings, if enabled
```

Where enabled, the asciicast recorder is a **full session replay** — not just a command list but the literal terminal output an operator saw, which is uniquely valuable for reconstructing exactly what an operator did and saw during a specific window, including output they may not have explicitly saved/looted.

## Audit Log

Sliver ships a **built-in audit log** (verified against v1.6.0's changelog entry "Add additional details to audit log") that records operator actions server-side, independent of the console-session logs above and independent of the SQLite task-history table. Locate and review it as the most structured, purpose-built record of "who did what, when" on the server:

```bash
find / -iname "*audit*" -path "*sliver*" 2>/dev/null
```

## Loot Store

Files/output an operator explicitly saved via `--loot`/`-X` flags (available on `execute`, `execute-assembly`, `sideload`, `spawn-dll`, `procdump`, and others — see `01 - Overview.md`'s switches table) land in the server's loot store, queryable via the `loot` command. This is the most curated evidence source — it reflects what an operator considered worth keeping, not the full raw output of every command run, so its absence doesn't mean a technique wasn't used, only that the operator didn't loot the result.

## Live Process and Socket State

```bash
ps aux | grep -i sliver
sudo ss -tlnp | grep -E ':8888|:80|:443|:53|:1337|:9898'
```

A live server shows listener jobs bound to whichever ports its running `mtls`/`http`/`https`/`dns`/`wg`/pivot jobs configured — cross-reference against `jobs` output captured from a live console session (if access is available) rather than assuming default ports, since every listener's `-l/--lport` is operator-configurable.

## Operator Client Artifacts

| Artifact | Notes |
|---|---|
| Imported operator `.cfg` file | Contains the operator's mTLS client certificate and the server's connection details (`sliver-client import <file>.cfg`) — its presence on a machine is direct evidence that machine was provisioned as an operator client for a specific server |
| `sliver-client` local config/cache | Client-side connection profile storage, typically under a user config directory (`~/.sliver-client/` or platform-equivalent) |
| Local loot/downloaded artifacts | Files pulled via `download` or loot exports land on the operator's own filesystem, separate from the server-side loot store |

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash/zsh | `~/.bash_history` / `~/.zsh_history` | `sliver-server`/`sliver-client` invocation lines themselves carry little detail (the interesting activity happens *inside* the console, which has its own logging above) — but reveal the operator config generation command (`operator --name ... --permissions ...`), directly showing who was provisioned and with what permission level |

## Memory Forensics

Because the server is long-running and holds the CA private key, all active implant key material, and the full session/beacon task queue in memory continuously, a memory capture of a live `sliver-server` process is disproportionately valuable — it can expose in-flight beacon tasks not yet reflected in the database, decrypted C2 traffic content the on-disk DB may store differently, and (most sensitively) the server's CA private key material if it isn't otherwise protected/hardware-backed.

## Timeline Correlation Value

The server database's session/beacon check-in timestamps are the anchor for correlating against target-side evidence in `04 - Target Evidence.md` — a beacon's recorded check-in time against a specific target IP/hostname, matched to that host's own outbound-connection evidence (Sysmon Event ID 3, firewall/proxy logs) in the same window, is what turns "a Sliver server existed somewhere" into a provable, specific server-implant-victim chain. Because beacon check-ins are **interval-driven with jitter**, expect the target-side connection timestamp to fall within `[interval - jitter, interval + jitter]` of the previous check-in rather than at an exact fixed offset — don't discount a correlation candidate for missing an exact interval match.