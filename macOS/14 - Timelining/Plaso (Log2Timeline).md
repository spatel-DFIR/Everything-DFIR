# Plaso (Log2Timeline)

**Plaso** builds **"super timelines"** — it ingests **many** data sources at once (file system, Unified/legacy logs, plists, SQLite DBs, browser history, persistence, etc.) and merges them into one time-sorted timeline. Where `mactime` gives you a *file-system* timeline, Plaso correlates **everything** into a single view. The toolset: **`log2timeline`** (collect → `.plaso` storage), **`psort`** (filter/output), **`psteal`** (one-shot collect+output), and **`pinfo`** (inspect a `.plaso`).

> 🔴 Pattern: `log2timeline … → timeline.plaso` (parse once, slow) → `psort … timeline.plaso` (filter/output many times, fast). Use **`--artifact-filters`** or a **`--file-filter` YAML** to scope collection, and `psort --slice` / date ranges to zoom the output.

## Contents
- [Quick Triage](#quick-triage)
- [The Tools](#the-tools)
- [Installation](#installation)
- [Kitchen Sink with psteal](#kitchen-sink-with-psteal)
- [Parsing a UAC Collection](#parsing-a-uac-collection)
- [Targeted Collection](#targeted-collection)
- [YAML Filter Files](#yaml-filter-files)
- [Filtering Output with psort](#filtering-output-with-psort)
- [Pitfalls](#pitfalls)
- [Resources](#resources)

---

## Quick Triage

```bash
# One-shot: image -> CSV super timeline
psteal --source image.dmg -w timeline.csv

# Or: parse once into storage, then filter repeatedly
log2timeline --storage-file timeline.plaso image.dmg

psort -o dynamic -w timeline.csv timeline.plaso "date > '2024-06-01 00:00:00' and date < '2024-07-01 00:00:00'"
```

---

## The Tools

| Tool | Role |
|---|---|
| 🔴 `log2timeline` | Parse sources → `.plaso` **storage** (do this once; it's the slow step) |
| 🔴 `psort` | **Filter / sort / output** the `.plaso` to CSV/JSON (run many times) |
| `psteal` | **One-shot** `log2timeline` + `psort` (quick "kitchen sink") |
| `pinfo` | Show what's inside a `.plaso` (sources, counts, errors) |

---

## Installation

```bash
# Download a Plaso release and extract
#   https://github.com/log2timeline/plaso/releases/tag/20260512
tar zxvf plaso-20xxxxxx.tar.gz

cd plaso-20xxxxxx

# System build tools (Homebrew)
brew install pkgconf autoconf automake libtool

# Python virtual environment
python3.13 -m venv ~/plaso_env

source ~/plaso_env/bin/activate

# Upgrade pip/setuptools, then install Plaso + deps
pip install --upgrade pip setuptools

python3 -m pip install .

# Verify (expect usage info + missing-arguments error)
log2timeline
```

As needed:

```bash
# Leave the venv
deactivate

# Return to it later
source ~/plaso_env/bin/activate
```

---

## Kitchen Sink with psteal

`psteal` runs the whole pipeline in one go — parse **everything** and write a timeline:

```bash
psteal --source image.dmg -w timeline.csv
```

> Easiest start; least control. For repeated filtering or scoping, use `log2timeline` + `psort` instead so you don't re-parse each time.

---

## Parsing a UAC Collection

Plaso can ingest a **UAC** archive directly (no disk image needed):

```bash
log2timeline --storage-file timeline.plaso uac-HOSTNAME.local-macos-xxxxxxxxxxxxxx.tar.gz
```

> Ties the two timelining workflows together — collect live with UAC, then build a super timeline from that archive. (Cross-ref the UAC note.)

---

## Targeted Collection

Scope what gets parsed so the `.plaso` stays focused and fast:

```bash
# Use the ForensicArtifacts "macos" artifact definitions
log2timeline --storage-file timeline.plaso image.dmg --artifact-filters macos

# Use a custom YAML path filter
log2timeline --storage-file timeline.plaso image.dmg --file-filter logs.yaml
```

> `--artifact-filters` references the **Digital Forensics Artifact Repository** definitions; `--file-filter` uses your own YAML include/exclude paths (below).

---

## YAML Filter Files

Example `logs.yaml` (include macOS log dirs, exclude Apache logs):

```yaml
description: Include common macOS log directories
type: include
path_separator: '/'
paths:
  - '/var/log/.+'
  - '/Library/Logs/.+'
  - '/private/var/log/.+'
---
description: Exclude Apache webserver logs
type: exclude
path_separator: '/'
paths:
  - '/var/log/apache2/.+'
```

> Precreated YAML filter files ship under:
> `/Users/<username>/plaso_env/lib/python3.xx/site-packages/artifacts/data`
> (when the `plaso_env` venv is created via the install steps above). Paths are **regex**.

---

## Filtering Output with psort

```bash
# Time slice around a pivot time (default window = 5 minutes)
psort -o dynamic -w timeline-filtered.csv timeline.plaso --slice 2024-06-09T22:00:00+00:00

# Wider slice window (minutes)
psort -o dynamic -w timeline-filtered.csv timeline.plaso --slice 2024-06-09T22:00:00+00:00 --slice-size 30

# Explicit date range
psort -o dynamic -w timeline-filtered2.csv timeline.plaso "date > '2023-12-31 23:59:59' and date < '2024-04-01 00:00:00'"
```

- 🔴 `--slice` default window is **5 minutes**; change with `--slice-size <minutes>`.
- Slice time must be **ISO 8601 with a timezone offset** (e.g. `+00:00`).
- `-o dynamic` = a flexible CSV output; other output modules exist (`-o l2tcsv`, `-o json`, …).

---

## Pitfalls

| 🔴 Pitfall | Avoid by |
|---|---|
| Re-parsing for every filter | Parse once to `.plaso`, then `psort` repeatedly |
| `--slice` time without TZ | Use full ISO 8601 + offset (`…+00:00`) |
| Timeline too huge to read | Scope with `--artifact-filters`/`--file-filter`; slice/date-range on output |
| Timezone confusion | Decide one TZ (UTC) and stay consistent |
| Version drift vs a guide | Plaso evolves — check `log2timeline -h` / docs |
| Trusting one source | Super timeline shines because sources **corroborate** each other |

---

## Resources

- Plaso Documentation: https://plaso.readthedocs.io/en/latest/
- Plaso releases: https://github.com/log2timeline/plaso/releases
- Digital Forensics Artifact Repository: https://github.com/ForensicArtifacts/artifacts
