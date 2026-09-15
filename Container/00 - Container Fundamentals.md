# Container Fundamentals

The mental model that makes container DFIR work: **a container is just namespaced, cgroup-limited host processes with a layered filesystem — so you investigate it from the host.** This note is the cross-cutting groundwork for the whole Container section: the architecture, how a container process maps to a host PID, how the writable layer records attacker activity, and how to tell which runtime (Docker / Kubernetes / Podman) you're actually dealing with. The per-technology folders build on this.

> 🔴 There is no "container" object in the kernel — it's a process tree with its own namespaces + cgroup + overlay mount. Everything an attacker does *inside* a container is visible from the host: as a host process (via cgroup/PID mapping), as files in the overlay `upperdir`, and as config on disk that survives the container's deletion. Work from the host and you never depend on a possibly-tampered container runtime.

> ⚠️ Identify the **runtime first** (`docker` vs `containerd`/`crictl` vs `podman`) — the commands, data directories, and even whether there's a daemon differ. Kubernetes nodes usually have **no `docker`** at all; use `crictl`.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [Architecture](#architecture)
- [Namespaces and cgroups](#namespaces-and-cgroups)
- [OverlayFS the Layered Filesystem](#overlayfs-the-layered-filesystem)
- [Container PID to Host PID](#container-pid-to-host-pid)
- [Identify the Runtime](#identify-the-runtime)
- [Rootless and the Landscape](#rootless-and-the-landscape)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# 1. Which runtime(s) are here?
which docker podman ctr crictl nerdctl 2>/dev/null

systemctl status docker containerd crio 2>/dev/null | grep -E 'Active|Main PID'

# 2. Running containers (per runtime)
docker ps -a 2>/dev/null; crictl ps -a 2>/dev/null; podman ps -a 2>/dev/null

# 3. Container processes as seen FROM THE HOST (cgroup names them)
ps -eo pid,cgroup,cmd | grep -E 'docker|containerd|kubepods|libpod' | head

# 4. Overlay mounts — each is a container/image layer set
mount | grep overlay | head
```

## What to Check for What

| Investigative question | Command / source |
|------------------------|------------------|
| Which runtime is on this host? | `which docker podman ctr crictl`; `systemctl status …` |
| Is a suspect host process containerized? | `cat /proc/<PID>/cgroup` (`docker/…`, `kubepods/…`, `libpod-…`) |
| Which container does a host PID belong to? | the cgroup ID in `/proc/<PID>/cgroup` |
| A container process's host PID? | `docker top <c>` / `docker inspect -f '{{.State.Pid}}'` |
| What did a container write? | its overlay **`upperdir`** (`diff/`) |
| Inspect a container without its runtime? | `nsenter -t <host_pid> -m -p …`; read config JSON on disk |
| Rootless containers hiding under a user? | `~/.local/share/containers`, `~/.local/share/docker` |
| Did a process escape? | container cgroup but touching host paths / host namespaces |

## Architecture

The Docker/OCI stack, top to bottom — know it so you know *what to inspect and where it lives*:

| Layer | Role |
|-------|------|
| `docker` / `nerdctl` / `podman` / `crictl` CLI | User command interface |
| **dockerd** (Docker daemon) | Builds/runs/manages containers, images, networks, volumes |
| **containerd** | Core runtime — image pull, snapshots, container lifecycle (used *directly* by Kubernetes) |
| **containerd-shim** | Per-container supervisor; keeps the container alive independent of containerd |
| **runc** | The low-level OCI runtime that actually `clone()`s the namespaced process |
| **Kernel** | namespaces + cgroups + overlayfs do the *real* isolation |

🔴 Kubernetes talks to **containerd** (or CRI-O) via the CRI — not to `docker`. Podman is **daemonless** (no dockerd; `podman` forks `conmon`+`runc` directly). So "there's no Docker daemon" doesn't mean "no containers" — check `containerd`/`crictl`/`podman` too.

## Namespaces and cgroups

Isolation is a set of **kernel features**, not a VM. A container is a process (tree) with its own namespaces and cgroup limits.

| Namespace | Isolates |
|-----------|----------|
| `pid` | Process IDs (container sees its own PID 1) |
| `net` | Network stack (own interfaces, ports) |
| `mnt` | Mount points / filesystem view |
| `uts` | Hostname |
| `ipc` | Shared memory / semaphores |
| `user` | UID/GID mapping (rootless / userns) |
| `cgroup` | cgroup root view |

```bash
# The namespaces of a process (containers have their OWN; host procs share the host's)
ls -l /proc/<PID>/ns/

lsns

# The cgroup path carries the container ID
cat /proc/<PID>/cgroup

# cgroup v1 vs v2 layout
mount | grep cgroup; ls /sys/fs/cgroup/
```

🔴 A process whose `/proc/<PID>/cgroup` references `docker/<id>`, `kubepods/…`, or `libpod-<id>` is containerized. Cross-referencing a suspicious host PID's cgroup tells you **which container** it belongs to — the foundational pivot for the whole section.

## OverlayFS the Layered Filesystem

A container's filesystem is layered: read-only image layers (`lowerdir`) stacked under a single writable container layer (`upperdir`), presented as one view (`merged`).

```bash
# Overlay mounts show the layer directories
mount | grep overlay
#   lowerdir=<img layers>  upperdir=<.../diff>  workdir=<.../work>   merged at <.../merged>
```

🔴 The **`upperdir` (the `diff` directory)** is *everything the container wrote since it started* — a free, host-side changelog of attacker activity inside the container (dropped miner, webshell, added key, modified config). It persists on the host even after the container stops. The read-only `lowerdir` layers are the image; diffing `upperdir` against them isolates exactly what changed at runtime.

## Container PID to Host PID

The single most important skill: a container's processes are visible on the host with **different PIDs** — map between them and every Linux `/proc` technique works from the host.

```bash
# Host PIDs for a container (Docker)
docker top <container>

docker inspect -f '{{.State.Pid}}' <container>     # PID 1 of the container, as a host PID

# From a host PID -> which container (the cgroup carries the 64-hex ID)
grep -oE 'docker[-/][0-9a-f]{64}|[0-9a-f]{64}' /proc/<host_pid>/cgroup

# Container's own PID view vs the host view
grep -E '^NSpid|^Pid' /proc/<host_pid>/status

# Enter a container's namespaces read-only FROM THE HOST — no runtime needed
nsenter -t <host_pid> -m -p -- ls -la /
```

🔴 `NSpid: 4242 1` means host PID **4242** is PID **1** inside the container. This is the bridge: it lets you run every technique from the Linux **Live Response** note (`/proc/PID/exe`, `maps`, `environ`, fileless recovery) against a container process, from the host, even if the container runtime is compromised or the container is being hidden.

## Identify the Runtime

Commands, data roots, and daemon model all differ — establish which runtime you have before anything else:

| Runtime | CLI | Data root | Daemon? |
|---------|-----|-----------|---------|
| **Docker** | `docker` | `/var/lib/docker/` | yes (`dockerd`→`containerd`) |
| **containerd** (direct / K8s) | `ctr`, `crictl`, `nerdctl` | `/var/lib/containerd/`, `/run/containerd/` | yes (`containerd`) |
| **Podman** (daemonless) | `podman` | `/var/lib/containers/` (root) or `~/.local/share/containers/` (rootless) | **no** (`conmon`+`runc`) |
| **CRI-O** (K8s) | `crictl` | `/var/lib/containers/` | yes (`crio`) |
| **LXC/LXD** | `lxc` | `/var/lib/lxd/` | yes |

```bash
which docker podman ctr crictl nerdctl lxc 2>/dev/null

systemctl status docker containerd crio 2>/dev/null | grep -E 'Active|Main PID'

ls -d /var/lib/docker /var/lib/containerd /var/lib/containers 2>/dev/null
```

## Rootless and the Landscape

- **Rootless** (Podman, rootless Docker) runs containers as a normal user via user namespaces — data lives under `~/.local/share/containers` or `~/.local/share/docker`, and "root" inside maps to the unprivileged host user. Still fully investigable from the host, just under that user's home (easy to overlook).
- **Kubernetes** abstracts all of this — you mostly work at the pod/node level (see the Kubernetes folder) and drop to `crictl` / host `/proc` for a specific container.
- **Podman / LXC** are covered in their own places where they differ; the core techniques (host `/proc`, overlay `upperdir`, config JSON on disk) transfer across all of them.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| Docker specifics — components, on-disk layout | **Docker → Architecture and Components** |
| Investigating a live/stopped Docker container | **Docker → Investigating Docker** |
| Unpacking an image and hashing layer contents | **Docker → Image and Layer Analysis** |
| Kubernetes pods / control plane / audit | **Kubernetes** folder |
| Daemonless / rootless Podman | **Podman** folder |
| A process that broke out to the host | **Escapes and Privilege Abuse** |
| Runtime behavioral detection (Falco/Tracee) | **Runtime Detection and Logging** |
| The `/proc` workup of a container process | **Linux → Live Response** (10), **Process Trees** (10b) |

## Scenarios

- **Suspicious host process:** its `cgroup` names a `docker/<id>` — you've attributed it to a specific container without touching the runtime.
- **Deleted container:** the container is gone but `config.v2.json` + the overlay `diff/` on the host disk reconstruct what it was and what it wrote.
- **Hidden/rogue container:** an `NSpid` PID-1 process in a container you didn't expect, or a rootless container under a service account's home.
- **Escape:** a process with a container cgroup that is touching host paths or the host PID/mount namespace.
- **Compromised runtime:** the `docker` CLI lies, but host `/proc` + overlay dirs still show the truth.

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Host process with cgroup `docker/<id>` doing host-level things | Container process that may have escaped |
| `NSpid` shows a PID-1-in-container you didn't expect | Unknown / rogue container |
| Overlay `upperdir` with recent writes | Attacker activity captured inside the container |
| Runtime you didn't expect installed/running | Shadow container infrastructure |
| Rootless containers under a service account's home | Overlooked container footprint |

## Resources

- OCI Runtime Specification — https://opencontainers.org
- Docker / containerd architecture docs — https://docs.docker.com
- MITRE ATT&CK Containers matrix — https://attack.mitre.org/matrices/enterprise/containers/
