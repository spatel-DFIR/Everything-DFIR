# Unix-like Artifacts Collector (UAC)

**UAC** is a **live-response collection script** for incident response that automates artifact gathering on macOS (and Linux/other UNIX-likes) using **native binaries** — no install, no dependencies to drop on the subject. It respects the **order of volatility**, is driven by **YAML artifact definitions** and **profiles**, and produces a single comprehensive **output archive** for offline review.

> 🔴 UAC is the fast "grab everything that matters, in the right order, with one command" tool for a live Mac: `sudo ./uac -p ir_triage /path/to/output`. It collects volatile data first (memory-adjacent, process, network state) before disk artifacts, hashes its output, and logs exactly what it did.

## Contents
- [Quick Triage](#quick-triage)
- [What UAC Does](#what-uac-does)
- [Profiles and Artifacts](#profiles-and-artifacts)
- [Running a Collection](#running-a-collection)
- [Order of Volatility](#order-of-volatility)
- [Output](#output)
- [Pitfalls and Chain of Custody](#pitfalls-and-chain-of-custody)
- [Resources](#resources)

---

## Quick Triage

```bash
# Triage collection (run as root, output to external evidence media)
sudo ./uac -p ir_triage /path/to/output

# See available profiles / artifacts
./uac --profiles

./uac --artifacts
```

---

## What UAC Does

- A self-contained **shell script** — runs from a USB/evidence volume, uses the subject's **native tools** (no binaries to install).
- Collects across the **order of volatility**: live/volatile state → then on-disk artifacts.
- **YAML-defined** artifacts and **profiles** make collection **customizable and repeatable**.
- Outputs a compressed, **hashed** archive + a run log → review offline.
- Cross-platform (macOS, Linux, *BSD, Solaris, etc.) — handy for mixed environments.

> ⚠️ Actively developed — flags/profiles evolve. Check `./uac --help` for your version.

---

## Profiles and Artifacts

| Concept | What it is |
|---|---|
| 🔴 **Profile** (`-p`) | A named bundle of artifacts for a scenario (e.g. `ir_triage`, `full`) |
| **Artifact** (`-a`) | A YAML definition of *what to collect and how* (paths, commands) |
| YAML files | Live under `artifacts/` and `profiles/` in the UAC directory — readable/editable |

```bash
# List them
./uac --profiles

./uac --artifacts

# Collect specific artifacts instead of a whole profile
sudo ./uac -a 'live_response/*,artifacts/*' /path/to/output
```

---

## Running a Collection

```bash
# Standard triage (provided example)
sudo ./uac -p ir_triage /path/to/output

# Full collection
sudo ./uac -p full /path/to/output

# Add case metadata + run details
sudo ./uac -p ir_triage /path/to/output --hostname SUBJECT-MAC

# Help
./uac --help
```

- Run with **`sudo`** for complete access to system artifacts.
- Point output at **external evidence media**, not the subject disk.
- Provide a writable output directory; UAC creates the archive there.

---

## Order of Volatility

🔴 UAC collects **most-volatile first** so fragile evidence isn't lost:

| Order | Examples |
|---|---|
| 1 | Running processes, open files, network connections/sockets, loaded modules |
| 2 | Logged-in users, ARP/routing, mounts |
| 3 | Logs (Unified/legacy), launch items, persistence |
| 4 | File-system metadata, hashes, configs |

> This is why a scripted collector beats ad-hoc commands — it preserves the sequence and timestamps everything consistently.

---

## Output

| Item | Holds |
|---|---|
| 🔴 `uac-<host>-<os>-<timestamp>.tar.gz` | The collected artifacts archive |
| `.tar.gz.sha256` (and/or log) | Integrity hash of the archive |
| `uac.log` | What UAC ran, errors, timing (collection record) |

```bash
# Verify integrity after collection
shasum -a 256 -c uac-*.tar.gz.sha256

# Extract for review on the analysis workstation
tar xzf uac-*.tar.gz -C /cases/review/
```

---

## Pitfalls and Chain of Custody

| 🔴 Pitfall | Avoid by |
|---|---|
| Running without `sudo` | Use root for full coverage |
| Output to the **subject** disk | Write to external evidence media |
| Treating it as a disk image | UAC is **logical live-response**, not a full image |
| Skipping integrity check | UAC hashes output — verify it, keep `uac.log` |
| Version drift vs a guide | Trust `./uac --help` / current docs |
| Not recording the live action | Note that UAC ran, by whom, when (TZ) |

---

## Resources

- UAC (Unix-like Artifacts Collector): https://github.com/tclahr/uac
- UAC Documentation: https://tclahr.github.io/uac-docs/
