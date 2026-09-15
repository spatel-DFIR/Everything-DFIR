# Linux DFIR Triage Scripts

Read-only triage scripts for **live Linux investigations** — built to run on a host you can't disturb. Two complementary hunters that share one engine and one doctrine (*flag on evidence, enumerate everything else*). **Each lives in its own folder with its own README.**

> Part of the [Linux DFIR Field Reference](../README.md) → cross-ref [`09 - Persistence Mechanisms/`](<../09 - Persistence Mechanisms/>).

| Script | Answers | Folder |
|---|---|---|
| **`hunt_persistence.sh`** | *What persists on disk?* Host triage · newest-first persistence timeline · what's armed (and running now) · the evidence-backed anomaly queue. | [`hunt_persistence/`](hunt_persistence/README.md) |
| **`hunt_intrusion.sh`** | *Is an intruder active right now, and is the box lying to me?* Process lineage (webshell/RCE) · network-backed shells · masquerade & fake kthreads · self-hiding · timestomp · log evasion. NDJSON for fleet stacking. | [`hunt_intrusion/`](hunt_intrusion/README.md) |

**Run them together:** persistence finds the foothold, intrusion finds the live hands-on-keyboard.

## Shared design

- **Flag on evidence, enumerate everything else.** A mechanism *existing* is never the signal — a behavioural payload or a hard tell is. On a clean host both scripts print an ~empty anomaly queue.
- **Package provenance is the trust anchor** (the Linux answer to code-signing), `usrmerge`-aware, and used as a *gate + modifier* — never a standalone "unowned = alert."
- **Read-only / non-destructive / console-only.** Nothing is written, enabled, loaded, or killed; no temp files, no host footprint. Run as `root` (via `sudo` / an EDR live-response shell) for full coverage; both degrade gracefully with a banner otherwise.
- **Same engine & flags:** weighted evidence → `[HIGH]` / `[NOTABLE]`, `--since`/`--days` incident window, `--deep`, `--modules`, `--min-severity`, `--inventory-only`, `--anomalies-only` (`hunt_intrusion.sh` adds `--json`).

## Quick start

```bash
# Persistence sweep (foothold hunt)
sudo bash hunt_persistence/hunt_persistence.sh

# Active-intrusion sweep (reverse shells, webshells, hiding, evasion)
sudo bash hunt_intrusion/hunt_intrusion.sh

# Scope both to an incident window
sudo bash hunt_persistence/hunt_persistence.sh --since 2026-07-01
sudo bash hunt_intrusion/hunt_intrusion.sh   --since 2026-07-01
```

See each folder's README for the full "what it checks" reference, module details, strengths & weaknesses, options, and validation checklists.

> **Validation status:** runtime-validated on a stock SANS SIFT (Ubuntu 20.04) — **both `0 HIGH · 0 NOTABLE`** on the clean host, as root with `--deep`. False-positive and performance work is done; what remains is **true-positive** confirmation — plant the artifacts in each README's checklist (reverse shell, fake kthread, webshell, hidden module, …) on a disposable VM to confirm the flagship detections fire.
