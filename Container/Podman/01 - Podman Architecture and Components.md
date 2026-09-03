# Podman Architecture and Components

The knowledge base for Podman — the **daemonless, rootless-first** container engine (Red Hat's Docker replacement, default on RHEL/Fedora). Podman speaks a Docker-compatible CLI but the internals differ in ways that change forensics: there is **no central daemon** (each container is a child of a `conmon` supervisor), it runs **rootless by default** (containers as a normal user via user namespaces, data under the user's home), and it integrates with **systemd** for persistence instead of its own daemon. This note maps its components and where each leaves evidence; the investigation flow is the next note.

> 🔴 Two Podman facts flip the usual assumptions. **No daemon:** "there's no dockerd running" doesn't mean no containers — Podman containers run as `conmon → <entrypoint>` under whichever *user* started them. **Rootless:** containers live under `~/.local/share/containers/` and "root inside" maps to an **unprivileged host UID** (via `/etc/subuid`/`/etc/subgid`), so a container footprint can hide entirely inside a service account's home and never touch `/var/lib`.

## Contents

- [The Podman Model](#the-podman-model)
- [Rootful vs Rootless](#rootful-vs-rootless)
- [Storage Layout](#storage-layout)
- [Logging](#logging)
- [Pods and systemd Integration](#pods-and-systemd-integration)
- [Differences from Docker](#differences-from-docker)
- [Where the Evidence Lives](#where-the-evidence-lives)
- [Resources](#resources)

## The Podman Model

Podman is a **fork-exec** engine — no long-running daemon mediates containers:

| Component | Role | Forensic relevance |
|-----------|------|--------------------|
| `podman` CLI | Docker-compatible command surface | Runs directly; no daemon to query for state |
| **conmon** | Per-container monitor (one per container) | The container's parent on the host process tree |
| **crun / runc** | OCI runtime that `clone()`s the namespaced process | The actual container process |
| **containers/storage** | Image + container layer store (overlay) | `.../storage/` under root or the user's home |
| **containers/image** | Pull/registry handling | `~/.config/containers/`, `/etc/containers/` config |

🔴 On the host process tree a Podman container is `conmon → <entrypoint>`, reparented and *not* under any daemon — so a running container can be missed if you only look for `dockerd`/`containerd`. There **is** an optional API socket (`podman system service`, the Docker-compat socket) — check for it, it's the Podman analog of `docker.sock`.

## Rootful vs Rootless

| | Rootful | Rootless (default) |
|-|---------|--------------------|
| Runs as | root | a normal user |
| Storage | `/var/lib/containers/storage` | `~/.local/share/containers/storage` |
| "root" inside maps to | real root | an **unprivileged host UID** via `/etc/subuid`/`/etc/subgid` |
| Networking | full | user-mode (slirp4netns / pasta) |
| Where to look | system paths | the **user's home** (easy to overlook) |

```bash
# Which users run rootless containers? (subuid/subgid maps + storage dirs)
cat /etc/subuid /etc/subgid
ls -la /home/*/.local/share/containers/storage /root/.local/share/containers/storage 2>/dev/null
```

🔴 Rootless is the overlooked footprint: a compromised web/service account can run containers entirely under its home. Enumerate `/etc/subuid` for users with mappings, and check each home's `.local/share/containers`.

## Storage Layout

`containers/storage` (overlay driver), under `/var/lib/containers/storage/` (root) or `~/.local/share/containers/storage/` (rootless):

| Path | Content |
|------|---------|
| `overlay/` | 🔴 Layer diffs — a container's writable layer (what it wrote) |
| `overlay-images/`, `overlay-layers/` | Image + layer metadata |
| `overlay-containers/<id>/userdata/config.json` | 🔴 OCI runtime config (mounts, caps, process, env) |
| `db.sql` / `bolt_state.db` / `containers.json` | Container/image state DB |
| `~/.config/containers/`, `/etc/containers/` | `registries.conf`, `storage.conf`, `policy.json` (signature policy) |

🔴 `overlay-containers/<id>/userdata/config.json` is the OCI spec for the container — the Podman equivalent of Docker's `config.v2.json`+`hostconfig.json`: it holds the mounts (escape surface), capabilities, and process/env. The overlay `diff` is the writable-layer changelog.

## Logging

Podman defaults to the **journald** log driver (not Docker's `json-file`):

```bash
# Container output via podman (reads journald or k8s-file)
podman logs <container>

# Straight from journald (rootful) — the container's stdout/stderr
journalctl CONTAINER_NAME=<name>
journalctl -u <systemd-unit>            # if run as a systemd/Quadlet service

# k8s-file driver logs (if configured), under the container's userdata
find ~/.local/share/containers /var/lib/containers -name '*.log' 2>/dev/null
```

🔴 Because logs default to journald, a Podman container's output lands in the systemd journal (subject to the journald volatility caveats — see Linux Logging). Check the `log-driver` in `containers.conf` if `podman logs` is empty.

## Pods and systemd Integration

- **Pods** — `podman pod` groups containers sharing namespaces (the same concept as a Kubernetes pod); an infra container (`k8s.gcr.io/pause`-style) holds the shared namespaces.
- **systemd integration is the persistence story** — `podman generate systemd` / **Quadlet** (`.container` files in `~/.config/containers/systemd/` or `/etc/containers/systemd/`) turn a container into a systemd unit. Combined with **user lingering** (`loginctl enable-linger`), a rootless container auto-starts at boot with no login. 🔴 That's the Podman persistence path — cross-ref Linux → Systemd Units (user linger) and Non-systemd notes.

```bash
# Quadlet / generated unit files that auto-run containers
ls -la /etc/containers/systemd/ /home/*/.config/containers/systemd/ 2>/dev/null
ls -la /home/*/.config/systemd/user/*.service 2>/dev/null   # generated container units
cat /var/lib/systemd/linger/* 2>/dev/null                   # users whose units run w/o login
```

## Differences from Docker

| Aspect | Docker | Podman |
|--------|--------|--------|
| Daemon | `dockerd` (+ containerd) | **none** (fork-exec `conmon`) |
| Default privilege | root | **rootless** |
| Container parent (host) | `containerd-shim` | `conmon` |
| Data root | `/var/lib/docker` | `/var/lib/containers` or `~/.local/share/containers` |
| Log driver default | `json-file` | **journald** |
| Persistence | systemd service running dockerd | **Quadlet / `generate systemd`** (user units + linger) |
| API socket | `docker.sock` (default on) | `podman.sock` (opt-in `podman system service`) |

## Where the Evidence Lives

| Question | Artifact |
|----------|----------|
| Rootless footprint under a user? | `/etc/subuid`; `~/.local/share/containers/storage` |
| How a container was configured? | `overlay-containers/<id>/userdata/config.json` |
| What it wrote at runtime? | `overlay/<layer>/diff/` |
| Its output/logs? | `journalctl CONTAINER_NAME=` / `podman logs` |
| Persistence? | Quadlet units + `generate systemd` + linger |
| Running now, no daemon to ask? | `conmon` processes; `podman ps` per user |

## Resources

- Podman architecture & rootless — https://docs.podman.io
- Quadlet (`podman generate systemd`) — https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html
- containers/storage — https://github.com/containers/storage
