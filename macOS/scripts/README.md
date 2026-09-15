# macOS DFIR Triage Scripts

Read-only triage scripts for **live macOS investigations** — built to run on a host you can't disturb. They enumerate persistence, rank findings by severity, and hand the analyst a short true-positive queue instead of a wall of output.

> Part of the [macOS DFIR Field Reference](../README.md) → cross-ref [`12 - Persistence Mechanisms/`](<../12 - Persistence Mechanisms/>).

## Scripts

- **[`hunt_persistence/`](hunt_persistence/)** — All-in-one triage. Scans every documented macOS persistence surface (13 modules), scores each item from anomaly signals, severity-ranked output. See [`hunt_persistence/README.md`](hunt_persistence/README.md) for full documentation.
