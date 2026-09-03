# Evidence Collection

Preserving a container (and its cluster context) for analysis — the cross-cutting acquisition note. The core skills: knowing the difference between **`export`, `save`, and `commit`** (pick wrong and you lose evidence), capturing the **writable layer** and **process memory from the host**, and collecting **Kubernetes state**. Read-only, hash-everything, volatile-first — the same discipline as Linux → Evidence Collection, adapted to containers.

> 🔴 **Volatile first: capture the container's process memory from the host *before* you `docker stop`/`commit`** — stopping the container destroys the process, and `commit` changes it. A container process is a host process, so image it via `/proc/<host_pid>` exactly as in Linux → Memory Forensics.

## Contents

- [Quick Triage](#quick-triage)
- [Save vs Export vs Commit](#save-vs-export-vs-commit)
- [Capture the Writable Layer](#capture-the-writable-layer)
- [Container Process Memory](#container-process-memory)
- [Metadata and Logs](#metadata-and-logs)
- [Kubernetes Evidence](#kubernetes-evidence)
- [Order and Custody](#order-and-custody)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Snapshot a running container to an image (preserves fs state as a new layer)
docker commit <container> incident/<container>:evidence

# Save that image (with history/layers) to a portable tar
docker save incident/<container>:evidence -o /evidence/container.tar

# Preserve the per-container metadata + logs from the host
cp -a /var/lib/docker/containers/<id>/ /evidence/container_meta/

# Hash everything
find /evidence -type f -exec sha256sum {} \; > /evidence/hashes.txt
```

## Save vs Export vs Commit

Know what each captures — picking wrong loses evidence:

| Command | Captures | Loses |
|---------|----------|-------|
| `docker commit <ctr> img` | Current container fs as a new image layer (live state) | Running process memory |
| `docker save <img>` | Image **with all layers + history + metadata** (tar) | Not tied to a running container |
| `docker export <ctr>` | Flattened container filesystem (single tar) | **Layer history + image metadata** |

```bash
# Recommended flow: commit the live state, then save the resulting image
docker commit <container> incident/evi:$(date -u +%Y%m%dT%H%M%SZ)
docker save incident/evi:<tag> -o /evidence/container_image.tar

# Point-in-time flat filesystem (quick, but no history)
docker export <container> -o /evidence/container_rootfs.tar

# containerd / K8s / Podman
ctr -n k8s.io images export /evidence/image.tar <image-ref>
crictl inspect <container> > /evidence/crictl_inspect.json
podman commit <ctr> incident/evi:tag && podman save incident/evi:tag -o /evidence/podman_image.tar
```

🔴 Use `commit` + `save` to preserve a compromised container **with** its layer history, so you can diff it against the base image later (→ Docker → Image and Layer Analysis). `export` alone flattens everything and throws away which layer introduced what.

## Capture the Writable Layer

The overlay `diff` (upperdir) is the attacker's on-disk changes — collect it directly:

```bash
# Locate the writable layer, then archive it read-only
UPPER=$(docker inspect -f '{{.GraphDriver.Data.UpperDir}}' <container>)
tar -C "$UPPER" -cf /evidence/upperdir.tar .

# Or copy specific artifacts out of a running container (without executing them)
docker cp <container>:/tmp/payload /evidence/
```

## Container Process Memory

A container process is a host process — image its memory **from the host** (see Linux → Memory Forensics):

```bash
# Get the container's host PID
PID=$(docker inspect -f '{{.State.Pid}}' <container>)

# Recover the (possibly deleted) binary from memory
cp /proc/$PID/exe /evidence/container_$PID.bin

# Dump the process memory (or AVML for full RAM)
gcore -o /evidence/container_$PID $PID

# Environment + maps + open files
tr '\0' '\n' < /proc/$PID/environ > /evidence/env_$PID.txt
cat /proc/$PID/maps > /evidence/maps_$PID.txt
ls -l /proc/$PID/fd/ > /evidence/fd_$PID.txt
```

🔴 For fileless / `memfd` container malware, this host-side memory capture is the **only** way to recover the payload — and it's gone the instant you stop the container.

## Metadata and Logs

```bash
# The primary triad + everything about the container
cp -a /var/lib/docker/containers/<id>/ /evidence/meta_<id>/    # config.v2.json, hostconfig.json, <id>-json.log

docker inspect <container> > /evidence/inspect.json
docker logs <container> > /evidence/stdout.log 2>&1
docker diff <container> > /evidence/diff.txt

# Daemon events around the incident
docker events --since '<start>' --until '<end>' > /evidence/events.txt
```

## Kubernetes Evidence

For a cluster incident, collect control-plane + node + workload state:

```bash
# API audit log (the crown jewel) + etcd snapshot (all objects + secrets)
cp /var/log/kubernetes/audit/audit.log /evidence/
etcdctl snapshot save /evidence/etcd-snapshot.db          # with certs — see Kubernetes note

# Workload specs + events + RBAC
kubectl get all -A -o yaml > /evidence/all_objects.yaml
kubectl get events -A > /evidence/events.txt
kubectl get clusterrolebindings,rolebindings -A -o yaml > /evidence/rbac.yaml

# The suspect pod's logs (current + previous container)
kubectl logs <pod> -n <ns> --all-containers > /evidence/pod.log
kubectl logs <pod> -n <ns> --previous > /evidence/pod_prev.log 2>/dev/null

# Node-level container artifacts
cp -a /var/log/pods/ /evidence/pod_logs/
```

## Order and Custody

- **Volatile first:** container process memory + `/proc` state **before** stopping/committing (commit changes the container).
- **Don't `docker stop`** the container before capturing memory — you lose the process.
- **Preserve the node too** — an escape means the host is evidence (fall back to Linux → Evidence Collection).
- **Hash on collection**, store hashes separately, work on copies.
- **Record** container ID, image digest, node, cluster, and timestamps (UTC).

## Red Flags

| Situation | Action |
|-----------|--------|
| Container stopped before memory capture | Process memory lost — capture from `/proc` first next time |
| Only `docker export` taken | Layer history gone — also `commit`+`save` the image |
| Escape suspected | Collect the host/node as evidence too |
| etcd not snapshotted in a cluster case | Missing all cluster state + secrets |
| No hash / working on originals | Integrity/custody failure |

## Resources

- Docker `commit`/`save`/`export` — https://docs.docker.com/reference/cli/docker/
- Linux → Memory Forensics (AVML/LiME, `/proc`) — this repo
- `etcdctl` snapshot — https://etcd.io/docs/latest/op-guide/recovery/
