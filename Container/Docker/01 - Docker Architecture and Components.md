# Docker Architecture and Components

The knowledge base for Docker — *how it actually works* so the investigation makes sense. Docker is a client/daemon system: the `docker` CLI sends API calls to the **dockerd** daemon, which delegates to **containerd** and **runc** to pull images from a registry, stack them as read-only layers under a writable layer, and run the result as namespaced host processes. This note walks every component — client, daemon, images/layers, the registry, containers, networking, volumes — and, crucially, **where each one leaves evidence on the host**. The *how-to-investigate* commands live in the next note; this one is the map.

> 🔴 Two facts drive all Docker forensics. First, **everything lives under `/var/lib/docker/`** — per-container config/logs, the overlay2 layer store, images, volumes, and network state all persist there on the host disk, surviving the container's deletion. Second, an **image is immutable and content-addressed** (identified by a SHA-256 digest), so you can prove exactly which image ran and diff a container's writable layer against it to isolate attacker changes.

## Contents

- [The Docker Stack](#the-docker-stack)
- [Images Layers and Digests](#images-layers-and-digests)
- [The Registry and docker pull](#the-registry-and-docker-pull)
- [Containers and the Writable Layer](#containers-and-the-writable-layer)
- [Networking](#networking)
- [Volumes and Mounts](#volumes-and-mounts)
- [On-Disk Layout var lib docker](#on-disk-layout-var-lib-docker)
- [Daemon Configuration](#daemon-configuration)
- [Where the Evidence Lives](#where-the-evidence-lives)
- [Resources](#resources)

## The Docker Stack

A single `docker run` flows through five components — each is a place to look:

| Component | What it does | Forensic relevance |
|-----------|--------------|--------------------|
| `docker` **client** | Sends REST calls to the daemon over `/var/run/docker.sock` | The socket is a **full-host-control API** — mounting it into a container = trivial escape |
| **dockerd** (daemon) | Manages images/containers/networks/volumes; exposes the API | Config in `/etc/docker/daemon.json`; logs to journald/syslog |
| **containerd** | Pulls images, manages snapshots + container lifecycle | State in `/var/lib/containerd`; used *directly* by Kubernetes |
| **containerd-shim** | One per container; keeps it running if containerd restarts | The `shim` is the container's parent on the host process tree |
| **runc** | `clone()`s the actual namespaced/cgrouped process, then exits | The container's real PID-1 process is what remains |

🔴 The container's process on the host is a child of a **`containerd-shim`**, *not* of `dockerd` — so on the process tree a container looks like `containerd-shim → <entrypoint>`, reparented away from the daemon. (See Process Trees, note 10b.) The `docker.sock` is the crown jewel: anything that can talk to it can start a privileged container and own the host.

## Images Layers and Digests

An **image** is a stack of read-only **layers** plus a JSON **config**, all content-addressed by SHA-256:

- Each **layer** is a tarball of filesystem changes (`ADD`, `RUN`, `COPY` from the Dockerfile). Layers are shared between images — pulling two images that share a base downloads the base once.
- The **image config** (`sha256:<digest>`) holds the entrypoint, env, exposed ports, and the **build history** (one entry per Dockerfile instruction).
- The **manifest** lists the config digest + the ordered layer digests. A **tag** (`nginx:latest`) is just a human name pointing at a manifest digest.

```
image  =  manifest ─┬─> config (sha256)      ← entrypoint, env, history
                    └─> layer1 (sha256)  \
                        layer2 (sha256)   } read-only, stacked (lowerdir)
                        layer3 (sha256)  /
```

🔴 Because layers and config are content-addressed, an image's identity is cryptographic — a tampered or backdoored layer changes the digest. `docker history <image>` shows every build step (and often the injected `RUN curl … | sh`); the Image and Layer Analysis note walks unpacking these.

## The Registry and docker pull

`docker pull nginx` connects to the default **registry** (Docker Hub, `registry-1.docker.io`, unless overridden) and downloads the image so it's ready to run:

1. Resolve the tag (`nginx:latest`) → the registry returns the **manifest**.
2. Download the **config** blob and any **layer** blobs not already cached.
3. Store them under `/var/lib/docker/image/` + `/var/lib/docker/overlay2/`.

The registry can be public (Docker Hub, GHCR, Quay), private/internal, or a rogue one an attacker points the daemon at. Registries and auth live in `~/.docker/config.json` (credentials/tokens) and `/etc/docker/daemon.json` (`insecure-registries`, `registry-mirrors`).

🔴 A pull from an **unexpected or `insecure` registry**, a typosquatted image name, or credentials in `~/.docker/config.json` are all supply-chain leads (→ Malicious images, in Image and Layer Analysis). A pull *is* an ingress-of-tooling event.

## Containers and the Writable Layer

A **container** = the image's read-only layers + a thin **writable layer** (the overlay `upperdir`) + runtime config, run as namespaced processes:

- Start: containerd creates an overlay mount (image layers as `lowerdir`, a fresh `upperdir` for writes) and runc launches the entrypoint inside new namespaces.
- Every file the container writes or changes lands in its **`upperdir` (`diff/`)** — the writable layer.
- Stop: the process exits but the container's `upperdir`, config, and logs **remain on disk** until `docker rm`.

🔴 The writable layer is the runtime changelog. `docker diff <container>` (or reading the `diff/` dir directly) shows exactly what the container added (`A`), changed (`C`), or deleted (`D`) versus its image — usually the fastest way to spot the dropped miner/webshell/key.

## Networking

Docker networking decides what a container can reach — and how much isolation an attacker had:

| Mode | Behaviour | Forensic note |
|------|-----------|---------------|
| **bridge** (default) | Private `docker0` bridge; NAT out; published ports via iptables | Normal; check published ports for exposed services |
| **host** | 🔴 Container shares the **host's** network stack — no isolation | Removes a security boundary; the container sees host interfaces/ports |
| **none** | No networking | Rare |
| **overlay** | Multi-host (Swarm/K8s) | Cross-node traffic |
| **container:<id>** | Shares another container's net namespace | Sidecar / sniffing |

Docker programs **iptables** (the `DOCKER` chains + NAT) to publish ports; `docker network ls`/`inspect` and the host's `iptables -t nat -L` show the mapping.

🔴 A container on **`host` network mode**, an unexpected **published port** (backdoor listener), or a container joined to another's network namespace are the network red flags.

## Volumes and Mounts

How data (and host access) crosses the container boundary:

- **Named volumes** — managed by Docker under `/var/lib/docker/volumes/<name>/_data`; persist after the container is removed (persistent attacker data lives here).
- **Bind mounts** — a host path mapped in (`-v /host:/path`). 🔴 A bind of **`/`**, **`/etc`**, or **`/var/run/docker.sock`** is an escape/host-access surface.
- **tmpfs mounts** — RAM-backed, gone on stop (volatile staging inside a container).

Every mount is recorded in the container's `hostconfig.json` (`.Binds`) and `config.v2.json` (`.MountPoints`).

🔴 `docker.sock` or `/` bind-mounted into a container is the #1 Docker escape primitive — a container with the socket can start a privileged sibling that owns the host.

## On-Disk Layout var lib docker

Everything Docker persists — readable directly on a live host or a mounted image (prefix `/mnt/evidence`):

| Path | Content |
|------|---------|
| 🔴 `/var/lib/docker/containers/<id>/config.v2.json` | Env, cmd, entrypoint, mounts, labels, created time |
| 🔴 `/var/lib/docker/containers/<id>/hostconfig.json` | Privileged, CapAdd, Binds, NetworkMode, PidMode, PortBindings |
| 🔴 `/var/lib/docker/containers/<id>/<id>-json.log` | Container stdout/stderr (default `json-file` driver) |
| 🔴 `/var/lib/docker/overlay2/<id>/diff/` | The **writable layer** — what the container changed |
| `/var/lib/docker/overlay2/l/` | Short symlink names for layers |
| `/var/lib/docker/image/overlay2/` | Image metadata, `imagedb`, layer DB, `repositories.json` |
| `/var/lib/docker/volumes/` | Named volumes (persistent data) + `metadata.db` |
| `/var/lib/docker/network/files/local-kv.db` | Network state (bolt DB) |
| `/etc/docker/daemon.json` | Daemon config (registries, log driver, insecure regs) |
| `~/.docker/config.json` | Client registry credentials / tokens |

## Daemon Configuration

`/etc/docker/daemon.json` governs daemon behaviour and can be tampered to aid an attacker or destroy evidence:

- `log-driver` — default `json-file`. 🔴 Changed to `none` = container output isn't recorded (evidence suppression); `journald`/remote = logs went elsewhere.
- `insecure-registries` — allows unsigned/HTTP registries (malicious-image vector).
- `data-root` — moves `/var/lib/docker` elsewhere (look there instead).
- `hosts` / exposing the API on `tcp://0.0.0.0:2375` — 🔴 the **unauthenticated Docker API** exposed to the network is a very common initial-access vector (cryptojacking crews scan for it).

## Where the Evidence Lives

A one-glance map from *question* → *artifact*, expanded in the investigation notes:

| Question | Artifact |
|----------|----------|
| What ran, how, privileged? | `config.v2.json` + `hostconfig.json` |
| What did the container do (output)? | `<id>-json.log` |
| What did it write at runtime? | overlay2 `diff/` (writable layer) |
| What image, built how? | `docker history` / image config + `repositories.json` |
| Host access / escape surface? | `hostconfig.json` `.Binds`/`.Privileged`/`.CapAdd` |
| Persistent attacker data? | `/var/lib/docker/volumes/` |
| Exposed backdoor port? | `hostconfig.json` `.PortBindings` + host iptables |

## Resources

- Docker architecture & storage (overlay2) — https://docs.docker.com/storage/storagedriver/
- OCI Image Specification — https://github.com/opencontainers/image-spec
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
