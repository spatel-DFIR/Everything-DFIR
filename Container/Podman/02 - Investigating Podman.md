# Investigating Podman

The step-by-step field flow for a Podman host — the same outside-in rhythm as the Docker note, but adapted to Podman's realities: **no daemon** (query per user, not a central engine), **rootless by default** (containers hide under user homes), **journald logs**, and **systemd/Quadlet persistence**. Read **Podman → Architecture and Components** first for the *why*.

> 🔴 The first question is always **who is running containers** — rootful (root) *and* every user with rootless containers. A rootless footprint lives under `~/.local/share/containers/` and won't show if you only run `podman` as root or look in `/var/lib`. Enumerate `/etc/subuid` and each user's storage dir.

## Contents

- [Quick Triage](#quick-triage)
- [Step 1 Orient Rootful and Rootless](#step-1-orient-rootful-and-rootless)
- [Step 2 Enumerate What Exists](#step-2-enumerate-what-exists)
- [Step 3 Inspect the Suspect Container](#step-3-inspect-the-suspect-container)
- [Step 4 Logs via journald](#step-4-logs-via-journald)
- [Step 5 What It Changed diff and cp](#step-5-what-it-changed-diff-and-cp)
- [Step 6 Image Analysis](#step-6-image-analysis)
- [Step 7 Persistence via systemd and Quadlet](#step-7-persistence-via-systemd-and-quadlet)
- [Host-Side Artifacts](#host-side-artifacts)
- [Correlate to the Host](#correlate-to-the-host)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Is Podman here, and who's running containers (rootful + rootless)?
which podman; cat /etc/subuid                    # users with UID-map ranges = rootless candidates

# Rootful containers
podman ps -a 2>/dev/null

# Rootless storage under user homes (the overlooked footprint)
ls -la /home/*/.local/share/containers/storage/overlay-containers /root/.local/share/containers 2>/dev/null

# conmon processes = running containers regardless of daemon
ps -eo pid,ppid,user,cmd | grep -E '[c]onmon'
```

## Step 1 Orient Rootful and Rootless

```bash
# Version + info (storage driver, root dir, rootless status)
podman version; podman info | grep -Ei 'rootless|graphRoot|runRoot|store'

# Rootful (as root)
podman ps -a; podman images

# Rootless — run AS the user, or point at their storage
sudo -u <user> XDG_RUNTIME_DIR=/run/user/$(id -u <user>) podman ps -a
#   or read on-disk: ls ~<user>/.local/share/containers/storage/overlay-containers/
```

🔴 Do this for **root and every user in `/etc/subuid`** — a compromised service account frequently runs its containers rootless under its own home.

## Step 2 Enumerate What Exists

```bash
# Images, containers (running + stopped), networks, volumes, pods
podman images; podman ps -a; podman network ls; podman volume ls; podman pod ps

# Anything privileged / host-namespaced / with dangerous mounts
podman ps -aq | xargs -r -I{} podman inspect {} --format '{{.Name}} priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} net={{.HostConfig.NetworkMode}}'
```

## Step 3 Inspect the Suspect Container

```bash
# Full definition (image, command, env, mounts, caps, privileged)
podman inspect <container>

# Processes running inside, with ps args (spot the miner/shell)
podman top <container>
podman top <container> aux

# Published ports (backdoor listener)
podman port <container>
```

🔴 On disk, the same data is in `overlay-containers/<id>/userdata/config.json` (the OCI spec) — mounts (escape surface), capabilities, and the process/env, readable even if `podman` can't be trusted.

## Step 4 Logs via journald

```bash
# Podman's default log driver is journald
podman logs <container>

# Straight from journald
journalctl CONTAINER_NAME=<name>
journalctl -u <unit>                    # if run as a systemd/Quadlet service

# k8s-file driver logs, if configured
find /home/*/.local/share/containers /var/lib/containers -name '*.log' 2>/dev/null
```

## Step 5 What It Changed diff and cp

```bash
# Files the container added/changed vs its image
podman diff <container>

# Copy a suspect file OUT for offline analysis (don't execute it)
podman cp <name>:/path/to/file /cases/podman/output/

# Read the writable layer directly on disk
find "$(podman inspect -f '{{.GraphDriver.Data.UpperDir}}' <container> 2>/dev/null)" -type f -ls 2>/dev/null
```

## Step 6 Image Analysis

```bash
# Build history (spot an injected RUN) + export for layer analysis
podman history <image>
podman save <image> -o /cases/podman/output/image.tar    # then unpack + hash layers (same as Docker note)
```

The full `save` → unpack → per-layer hash workflow is identical to **Docker → Image and Layer Analysis** — Podman produces OCI-format archives.

## Step 7 Persistence via systemd and Quadlet

🔴 Podman's persistence isn't a daemon — it's **systemd**. Check for generated units, Quadlet files, and lingering users.

```bash
# Quadlet .container files that auto-run containers
ls -la /etc/containers/systemd/ /home/*/.config/containers/systemd/ 2>/dev/null

# Generated container units (podman generate systemd)
ls -la /home/*/.config/systemd/user/*.service /etc/systemd/system/*container*.service 2>/dev/null
grep -rl 'podman' /etc/systemd/system /home/*/.config/systemd/user 2>/dev/null

# Lingering users — their rootless container units run with NO login
ls -la /var/lib/systemd/linger/ 2>/dev/null
```

🔴 A rootless container set to auto-start via a generated user unit + `enable-linger` runs on every boot with the user never logging in — the Podman equivalent of a persistence service (cross-ref Linux → Systemd Units, User Linger).

## Host-Side Artifacts

When `podman` can't be trusted or the container is gone — read the storage on disk (root or the user's home):

```bash
STORE=/var/lib/containers/storage            # or ~<user>/.local/share/containers/storage
cat "$STORE"/overlay-containers/<id>/userdata/config.json | python3 -m json.tool | less
find "$STORE"/overlay/*/diff/ -type f \( -perm -111 -o -name '*.sh' -o -name '*.so' \) -ls 2>/dev/null
```

## Correlate to the Host

```bash
# The container's parent is conmon; map its process to the host
ps -eo pid,ppid,user,cmd --forest | grep -A2 '[c]onmon'

# From a host PID -> its container cgroup (libpod)
grep -oE 'libpod[-/][0-9a-f]{64}|machine.slice|user.slice' /proc/<host_pid>/cgroup

# Rootless UID mapping: "root" inside = an unprivileged host UID (subuid range)
grep -E '^Uid|^Gid' /proc/<host_pid>/status; cat /etc/subuid
```

🔴 In rootless Podman, a process the container thinks is root shows on the host as a **high, unprivileged UID** from the user's subuid range — that mapping is how you attribute a container process to the host user.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| How Podman's rootless/daemonless model works | **Podman → Architecture and Components** |
| Unpack the image + hash layers | **Docker → Image and Layer Analysis** (same OCI format) |
| A container that broke out to the host | **Escapes and Privilege Abuse** |
| Rootless persistence via user systemd + linger | **Linux → Persistence → Systemd Units** (User Linger) |
| Triage a file you `podman cp`'d out | **Linux → ELF and Malware Triage** (11b) |
| journald log volatility / recovery | **Linux → Logs → Systemd Journal** |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Rootless containers under a service account's home | Overlooked / hidden footprint |
| `conmon` process with no expected container | Running container off the radar |
| `podman.sock` (`podman system service`) exposed | API-control equivalent of docker.sock |
| Privileged / host-mount / dangerous-cap container | Escape-capable |
| Quadlet/generated unit + linger for a container | Rootless boot persistence |
| Dropped binary/webshell in overlay `diff/` | Attacker activity captured on disk |

## Resources

- Podman CLI reference — https://docs.podman.io/en/latest/Commands.html
- Rootless containers — https://github.com/containers/podman/blob/main/docs/tutorials/rootless_tutorial.md
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
