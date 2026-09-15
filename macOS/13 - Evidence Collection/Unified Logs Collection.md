# Unified Logs Collection

Collecting the macOS Unified Logs as evidence means producing a **`.logarchive`** with **`log collect`** — a self-contained bundle in the native **`.tracev3`** format that preserves the **full event data, metadata, and format strings**. This is far richer than redirecting `log show` to a text file: the archive can be queried offline with the same predicates, **without touching the live system**, and it travels with everything needed to decode it.

> 🔴 Always prefer a **`.logarchive`** over a text dump. Target a **time window** to keep it manageable, write it to your **evidence volume** (not the subject disk), then **hash** it for chain of custody. Analyze it offline on your workstation.

## Contents
- [Quick Triage](#quick-triage)
- [Why a logarchive](#why-a-logarchive)
- [Collecting the Archive](#collecting-the-archive)
- [Targeting a Time Window](#targeting-a-time-window)
- [Offline Analysis](#offline-analysis)
- [Chain of Custody](#chain-of-custody)
- [Dead-Box Alternative](#dead-box-alternative)
- [Pitfalls](#pitfalls)
- [Resources](#resources)

---

## Quick Triage

```bash
# Collect the entire live log store to a logarchive on the EVIDENCE volume
sudo log collect --output /Volumes/EVIDENCE/host.logarchive

# Bounded to the last 7 days (smaller, focused)
sudo log collect --last 7d --output /Volumes/EVIDENCE/host_7d.logarchive

# Hash it for chain of custody (it's a bundle → tar first)
tar czf /Volumes/EVIDENCE/host.logarchive.tar.gz -C /Volumes/EVIDENCE host.logarchive

shasum -a 256 /Volumes/EVIDENCE/host.logarchive.tar.gz

# Analyze offline (no live system needed)
log show --archive /Volumes/EVIDENCE/host.logarchive --predicate 'process == "sshd"' --info
```

---

## Why a logarchive

| Method | What you get |
|---|---|
| `log show … > out.txt` | Flat text, **point-in-time**, loses structure/metadata, only what your predicate matched |
| 🔴 `log collect` → `.logarchive` | Full **`.tracev3`** store + **uuidtext** format strings + metadata — **re-queryable** offline with any predicate, `--info`/`--debug`, any style |

> The `.logarchive` is self-contained, so you don't need to also grab `/var/db/uuidtext` separately — the format strings travel inside it.

---

## Collecting the Archive

```bash
# Whole current store
sudo log collect --output /Volumes/EVIDENCE/host.logarchive

# (Optional) sysdiagnose also bundles a logarchive + lots more context
sudo sysdiagnose -f /Volumes/EVIDENCE/
```

- Requires **`sudo`** (the store is privileged).
- `--output` names the archive; write it to **external evidence media**, not the subject's own disk.
- `log collect` **reads** the store — it doesn't alter logged events — but document that you ran it (it is itself an action on the live system).

---

## Targeting a Time Window

```bash
# Last N (m/h/d) — fastest way to scope around an incident
sudo log collect --last 24h --output /Volumes/EVIDENCE/host_24h.logarchive

# Since a specific start time
sudo log collect --start "2026-06-01 00:00:00" --output /Volumes/EVIDENCE/host_since.logarchive

# Limit the archive size (oldest data trimmed to fit)
sudo log collect --size 500m --output /Volumes/EVIDENCE/host_capped.logarchive
```

🔴 Scope to the incident window to keep the archive small and analysis fast — but remember the buffer only holds **days-to-weeks**, so collect **early**.

---

## Offline Analysis

Query the archive exactly like the live log, but with `--archive`:

```bash
log show --archive /Volumes/EVIDENCE/host.logarchive --predicate 'process == "kernel"' --info

log show --archive host.logarchive --last 1d --style syslog

log show --archive host.logarchive --predicate 'subsystem == "com.apple.TCC"' --info --debug

# Stats / what's inside
log stats --archive host.logarchive
```

> Do this on your **analysis workstation** — the subject system is never touched again. GUI tools (Ulbow/Consolation) also open `.logarchive` bundles. Normalize times with `--timezone "UTC"`.

---

## Chain of Custody

| Step | Action |
|---|---|
| 🔴 Hash | `tar` the bundle, then `shasum -a 256` (record the hash) |
| Document | Collector name, date/time (with TZ), host, macOS version, command used |
| Storage | Write-once / read-only evidence media; note serials |
| Integrity | Re-hash before analysis; confirm it matches |
| Notes | Record that `log collect` ran on the live system (an action you took) |

```bash
# Capture host context alongside the archive
sw_vers > /Volumes/EVIDENCE/host_info.txt

date -u >> /Volumes/EVIDENCE/host_info.txt

scutil --get ComputerName >> /Volumes/EVIDENCE/host_info.txt
```

---

## Dead-Box Alternative

If you can't run `log collect` (no live access), copy the raw stores from the image:

```bash
# Need BOTH to decode offline
cp -R /Volumes/SUBJECT/private/var/db/diagnostics /evidence/diagnostics

cp -R /Volumes/SUBJECT/private/var/db/uuidtext   /evidence/uuidtext
```

> Then parse with `log show --archive` (after assembling), Ulbow, or Mandiant's `macos-UnifiedLogs`. Cross-ref the **Unified Logs – System and Kernel Events** note.

---

## Pitfalls

| 🔴 Pitfall | Avoid by |
|---|---|
| Writing the archive to the **subject disk** | Always target external evidence media |
| Text dump instead of `.logarchive` | Use `log collect` — keeps full structure/metadata |
| Forgetting it's a **bundle** when hashing | `tar` it first, then hash |
| Collecting too late (buffer rolled) | Collect **early**; scope a window |
| Time-zone confusion | Record host TZ; analyze with `--timezone "UTC"` |
| Not documenting the live action | Log that `log collect`/`sysdiagnose` was run |

---

## Resources

- `man log` (`log collect`, `log show --archive`)
- Cross-ref: **09 - Unified Logs** (querying & interpretation)
