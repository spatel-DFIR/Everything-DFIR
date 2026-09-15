# Escapes and Privilege Abuse

The cross-cutting "did they get to the host?" note (ATT&CK **T1611 Escape to Host**) — it applies to Docker, Podman, and Kubernetes alike, because they all rely on the same kernel isolation. It covers the misconfigurations and exploits that break the container boundary, how to spot each in the container's config *from the host*, and how to confirm an escape actually happened. The through-line: a container escape almost always ends as ordinary **host persistence**, so once you confirm the surface, treat it as a host compromise and sweep with the Linux Persistence notes.

> 🔴 Most "escapes" aren't exploits at all — they're **configuration**: a `--privileged` container, a mounted `docker.sock`, or a host `/` bind mount hands over the host with no CVE required. Assess the escape *surface* from the container's on-disk config first (it survives the container's deletion); only then look at runtime/kernel CVEs.

## Contents

- [Quick Triage](#quick-triage)
- [The Escape Surfaces](#the-escape-surfaces)
- [Privileged Containers](#privileged-containers)
- [Mounted Docker Socket](#mounted-docker-socket)
- [Host Mounts](#host-mounts)
- [Dangerous Capabilities](#dangerous-capabilities)
- [cgroup release_agent](#cgroup-release_agent)
- [Runtime and Kernel Exploits](#runtime-and-kernel-exploits)
- [Confirming an Escape](#confirming-an-escape)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Privileged containers (biggest escape surface)
docker ps -q | xargs -r docker inspect -f '{{.Name}} priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' 2>/dev/null

# docker.sock mounted into a container = instant host root
grep -rl 'docker.sock' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null

# Host root mounted in
grep -rlE '"/:/|:/host' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null

# Host persistence appearing right after container activity (the tell of a successful escape)
find /etc/cron* /etc/systemd/system /root/.ssh /etc/ld.so.preload -newermt '3 hours ago' -ls 2>/dev/null
```

## The Escape Surfaces

| Surface | Why it breaks isolation |
|---------|-------------------------|
| `--privileged` | Disables most isolation; device access → mount the host disk |
| `/var/run/docker.sock` mounted in | Talk to dockerd → run a new privileged container on the host |
| Host path mounts (`-v /:/host`) | Direct read/write of the host filesystem |
| Dangerous capabilities | `SYS_ADMIN` (mount), `SYS_PTRACE` (host procs), `DAC_READ_SEARCH` (read any file) |
| `PidMode=host` / `NetworkMode=host` | See/attack host processes / network |
| cgroup v1 `release_agent` | Trick the kernel into running a host binary as root |
| Kernel / runtime CVEs | runc overwrite, Dirty Pipe, Leaky Vessels |

## Privileged Containers

```bash
# Which running containers are privileged
docker inspect -f '{{.Name}} {{.HostConfig.Privileged}}' $(docker ps -q) 2>/dev/null | grep true

# From on-disk config (container may be stopped) — Docker, Podman, K8s runtime
grep -l '"Privileged":true' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | .metadata.namespace+"/"+.metadata.name' 2>/dev/null
```

🔴 A privileged container can see host devices (`ls /dev`), mount the host disk (`mount /dev/sda1 /mnt`), and load kernel modules — full host compromise. Legitimate uses exist (some CI, storage/network plugins), so confirm intent, but treat it as escape-capable.

## Mounted Docker Socket

```bash
# The socket bind (in hostconfig .Binds or a -v mount)
grep -r 'docker.sock' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null

# Inside the container this yields host root:
#   docker -H unix:///var/run/docker.sock run -v /:/host --privileged image ...
```

🔴 `docker.sock` in a container is equivalent to root on the host — it can spawn a new container that mounts `/` and runs privileged. Extremely common in CI/CD and monitoring stacks, and a frequent real-world escape path.

## Host Mounts

```bash
# All bind mounts for a container
docker inspect -f '{{json .Mounts}}' <container> | python3 -m json.tool

# Dangerous ones: /, /etc, /root, /var/run, /proc, host cron/systemd dirs
grep -rE '"Source":"/(|etc|root|var/run|proc|home)' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null

# Kubernetes hostPath volumes
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.volumes[]?.hostPath) | .metadata.namespace+"/"+.metadata.name+" -> "+(.spec.volumes[]?.hostPath.path//"")' 2>/dev/null
```

A container that mounts the host `/`, `/etc`, cron dirs, or `/root/.ssh` can write persistence directly onto the host with no "exploit" at all.

## Dangerous Capabilities

```bash
# Capabilities added to running containers
docker inspect -f '{{.Name}} {{.HostConfig.CapAdd}}' $(docker ps -q) 2>/dev/null

# Inside a container, what caps do we actually have?
#   capsh --print   /   grep Cap /proc/self/status
```

| Capability | Escape use |
|------------|-----------|
| `SYS_ADMIN` | mount + many escape primitives |
| `SYS_PTRACE` (+ host PID) | inject into host processes |
| `DAC_READ_SEARCH` | "Shocker" — read arbitrary host files |
| `SYS_MODULE` | load a kernel module on the host |
| `NET_ADMIN` / `NET_RAW` | manipulate host network / sniff |

## cgroup release_agent

The classic cgroup **v1** privileged-container escape: set a `release_agent` that the kernel runs — as root, in the host namespace — when a cgroup empties.

```bash
# On the HOST: a release_agent pointing at an odd path = active escape attempt
find /sys/fs/cgroup -name release_agent -exec sh -c 'echo "== $1 =="; cat "$1"' _ {} \; 2>/dev/null

# notify_on_release enabled where it shouldn't be
grep -rl 1 /sys/fs/cgroup/*/notify_on_release 2>/dev/null
```

🔴 A `release_agent` referencing a script in a container's overlay path or `/tmp` is an active escape. Only works on cgroup v1 + privileged/`SYS_ADMIN`.

## Runtime and Kernel Exploits

Even a well-configured container can be escaped via runtime/kernel CVEs — check versions and look for the artifacts:

| CVE | Mechanism | Artifact |
|-----|-----------|----------|
| CVE-2019-5736 | Overwrite the host `runc` binary via `/proc/self/exe` | Modified `runc`; verify with package integrity |
| CVE-2024-21626 (Leaky Vessels) | runc fd leak → host fs access | runc version; odd `WORKDIR`/fd usage |
| CVE-2022-0847 (Dirty Pipe) | Kernel page-cache write → overwrite host files | Kernel version; unexpected root-file writes |

```bash
# Versions
runc --version; docker version; uname -r

# Integrity of the runc binary (overwrite attack)
which runc | xargs rpm -Vf 2>/dev/null; dpkg -V runc 2>/dev/null
```

## Confirming an Escape

The tell is host-level activity attributable to a container:

```bash
# Host persistence created in the container's activity window
find /etc/cron* /etc/systemd/system /root/.ssh /etc/ld.so.preload -newermt '<window_start>' ! -newermt '<window_end>' -ls 2>/dev/null

# A host process whose parent traces back to a container shim/runc
ps -eo pid,ppid,cmd --forest | grep -A3 -E 'containerd-shim|runc'

# Files owned by the container's mapped UID appearing OUTSIDE the container tree
```

🔴 A container escape almost always pivots into ordinary **host persistence** — once you confirm the escape surface, sweep the host with the Linux Persistence notes and treat it as a host compromise.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| The container's config that enabled the escape | **Docker → Investigating Docker**, **Kubernetes → Investigating** |
| Host persistence the escape planted | **Linux → Persistence Mechanisms** (all) |
| The `/proc`/lineage of the escaped process | **Linux → Live Response** (10), **Process Trees** (10b) |
| Verifying a modified `runc` binary | **Linux → Package Managers and Integrity** (08) |
| Runtime detection of the escape attempt | **Runtime Detection and Logging** |
| Remediation (rebuild the node?) | **Linux → Remediation and Containment** (14) |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Privileged container / `docker.sock` mounted | Trivial host root |
| Host `/`, `/etc`, cron, `/root/.ssh` mounted in | Direct host persistence |
| `SYS_ADMIN`/`SYS_PTRACE`/`DAC_READ_SEARCH` capabilities | Escape-capable |
| `release_agent` pointing at a container/temp path | Active cgroup escape |
| Modified `runc` binary | CVE-2019-5736 escape |
| Host persistence created during container activity | Escape succeeded → host compromise |

## Resources

- MITRE ATT&CK T1611 Escape to Host — https://attack.mitre.org/techniques/T1611/
- Docker security & capabilities — https://docs.docker.com/engine/security/
- Leaky Vessels (CVE-2024-21626) advisory — https://github.com/opencontainers/runc/security
