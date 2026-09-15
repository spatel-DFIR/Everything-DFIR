# Docker Image and Layer Analysis

Offline analysis of a Docker image: export it to a tarball, unpack it, walk its layers, and find (and hash) exactly what was baked in — a backdoor, a miner, a webshell, credentials, or a tampered base layer. Because an image is an ordered stack of content-addressed layers plus a config, you can reconstruct precisely *which build step introduced which file* and prove it cryptographically. This is where you go after the live investigation (previous note) points at a suspect image, and it's fully **offline** — no daemon required once you have the tar.

> 🔴 `docker save` exports the **image with all its layers, manifest, and config** (the build story). `docker export` exports a **flattened container filesystem** (no layers/history) — useful for a single snapshot but it loses the per-layer provenance. For image forensics, use `docker save`. Work on a **copy in a case directory**, never in-place.

## Contents

- [Two Ways to Export](#two-ways-to-export)
- [Unpack the Image](#unpack-the-image)
- [Image Tarball Layout](#image-tarball-layout)
- [Extract Every Layer](#extract-every-layer)
- [Find and Hash the Payload](#find-and-hash-the-payload)
- [Which Layer Introduced a File](#which-layer-introduced-a-file)
- [docker-explorer (Purpose-Built Offline Tool)](#docker-explorer-purpose-built-offline-tool)
- [skopeo (Registry-Side Inspection)](#skopeo-registry-side-inspection)
- [Structured Analysis with container-diff](#structured-analysis-with-container-diff)
- [Malicious Image Indicators](#malicious-image-indicators)
- [Base Image Comparison](#base-image-comparison)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Two Ways to Export

```bash
# IMAGE with layers + manifest + config (the build history) — preferred for forensics
docker save <image_or_id> > image.tar
docker save <image> -o image.tar

# FLATTENED container filesystem (single snapshot, no layer/history) — a whole-FS view
docker export <container> > rootfs.tar
```

🔴 Use `docker save` to keep the layer provenance (which step added what). Use `docker export` only when you want the final merged filesystem of one container as a single tree.

## Unpack the Image

The full workflow — set up a case dir, export (or import a provided archive), decompress if needed, and unpack:

```bash
# Set up the case output directory
mkdir -p /cases/docker/output/

# Export the image to a tar
docker save omnicorp_wpcontainer > /cases/docker/output/omnicorp_wpcontainer.tar

# --- or, if you were handed a prebuilt gzipped image archive ---
mkdir -p /cases/docker/output
cp /cases/docker/prebuilt/omnicorp_wpcontainer.tar.gz /cases/docker/output/omnicorp_wpcontainer.tar.gz
gunzip /cases/docker/output/omnicorp_wpcontainer.tar.gz

# Unpack the image tarball
tar xvf /cases/docker/output/omnicorp_wpcontainer.tar

ls /cases/docker/output/

# Read the manifest (which config + which layers, in order)
json_pp < /cases/docker/output/manifest.json
```

🔴 `manifest.json` is the index: it names the image **config** JSON (`Config`) and the ordered list of **layers** (`Layers`, each a `<hash>/layer.tar` or a `blobs/sha256/...`). Read it first so you know the layer order — a file added in a *later* layer overrides the same path in an earlier one.

## Image Tarball Layout

After `tar xvf`, a saved image expands to:

| Item | Content |
|------|---------|
| `manifest.json` | 🔴 Index: the config file + the ordered layer list + `RepoTags` |
| `repositories` | Tag → top-layer mapping (older format) |
| `<config-sha256>.json` | 🔴 Image **config**: `Cmd`, `Entrypoint`, `Env`, exposed ports, and the **`history`** (one entry per Dockerfile instruction) |
| `<layer-dir>/layer.tar` | 🔴 One layer's filesystem changes (a tar of added/changed files) |
| `<layer-dir>/json`, `VERSION` | Per-layer metadata |
| (newer format) `blobs/sha256/<digest>` | Config + layers stored by digest under `blobs/` |

```bash
# Read the image CONFIG (entrypoint, env, and the build history)
json_pp < /cases/docker/output/<config-sha256>.json | grep -A2 -iE '"cmd"|"entrypoint"|"env"|"created_by"'
```

🔴 The config's **`history`** array is `docker history` in raw form — each `created_by` is a Dockerfile step. A `RUN curl … | sh`, an `ADD http://…`, or a baked-in secret shows here.

## Extract Every Layer

Unpack each layer's `layer.tar` in place so you can browse the whole filesystem across layers:

```bash
cd /cases/docker/output

# Extract each layer directory's layer.tar into itself
for i in $(ls -al | grep ^d | grep -v "\." | awk '{ print $9 }'); do
  cd $i
  tar xvf layer.tar
  cd /cases/docker/output
done
```

After this, each `<layer-hash>/` directory contains that layer's slice of the filesystem — you can now `find`, `grep`, and hash across all of them.

## Find and Hash the Payload

With the layers extracted, hunt the suspect file and hash it for IOC/intel:

```bash
# Hash a specific file found inside a layer (e.g. a webshell in the WordPress app)
md5sum /cases/docker/output/4f79cf1d9c27921901617c89c4d1b05fcbf65686e64c032b918c71b39f151d4c/var/www/html/app/admin.php

# Hunt across ALL extracted layers for the usual suspects
find /cases/docker/output -type f -name '*.php' -exec grep -lE 'eval\(base64_decode|system\(|passthru\(' {} \; 2>/dev/null

find /cases/docker/output -type f \( -perm -111 -o -name '*.sh' -o -name '*.so' \) -ls 2>/dev/null

# SHA-256 everything of interest for the fleet hunt / threat intel
find /cases/docker/output -type f -newer /cases/docker/output/manifest.json -exec sha256sum {} + 2>/dev/null
```

🔴 Hashing the exact file (`md5sum`/`sha256sum`) both confirms identity against threat intel and gives you a fleet-hunt IOC — the same webshell/miner is likely baked into other images or dropped on other hosts.

## Which Layer Introduced a File

Provenance = attribution. Because layers are ordered, the layer that *contains* a file is the build step that added it — and Docker records **deletions** as special whiteout files.

```bash
# Which layer directory holds the suspect file? (that layer's build step added it)
find /cases/docker/output/*/ -path '*var/www/html/app/admin.php' 2>/dev/null

# Whiteout files mark deletions between layers (something removed to hide it)
find /cases/docker/output -name '.wh.*' -o -name '.wh..wh..opq' 2>/dev/null

# Map the layer hash back to its history entry in the config to see the Dockerfile step
json_pp < /cases/docker/output/<config-sha256>.json | grep -B1 -A1 created_by
```

🔴 A file that appears in a *late* layer (not the base) was added during the build after the base image — exactly where a backdoor is injected. A `.wh.` whiteout hiding a file is an attempt to remove evidence between build steps.

## docker-explorer (Purpose-Built Offline Tool)

The manual `docker save` → `tar` → walk-layers workflow above works anywhere, but Google's [`docker-explorer`](https://github.com/google/docker-explorer) is a purpose-built offline forensic tool for exactly this job — it understands the image/layer/overlay storage formats natively instead of requiring a manual unpack, and covers containerd storage too, not just Docker.

```bash
# List images/containers found in a mounted or copied Docker root (no daemon needed)
de.py -r /var/lib/docker list all_containers

# List a container's mount points / namespaced filesystem
de.py -r /var/lib/docker mount <container_id> /mnt/mount_point

# Show a container's history (layer-by-layer, as recorded by Docker)
de.py -r /var/lib/docker history <container_id>
```

🔴 Use `docker-explorer` when working against a **copied/mounted disk image** rather than a live daemon — it saves the manual layer-walking above and is purpose-built for the storage-driver internals (overlay2, etc.), reducing the chance of missing a layer or misreading the storage layout by hand.

## skopeo (Registry-Side Inspection)

`skopeo` inspects an image **directly against a registry** — no `docker pull`, no daemon, no local disk footprint. Useful for triaging a suspect image/tag before deciding whether to pull it at all.

```bash
# Full image metadata without pulling (works against a registry)
skopeo inspect docker://<registry>/<image>:<tag>

skopeo inspect --config docker://<image>:<tag>     # full config JSON
```

🔴 `skopeo inspect` is the fastest way to check what an image *is* — layers, digest, config — before you pull it onto a host and risk running it.

## Structured Analysis with container-diff

Google's `container-diff` gives a structured view without manual unpacking — history, files, packages, and image-to-image diffs:

```bash
# The image's build history (structured)
container-diff analyze -t history daemon://image_name

# Files + installed packages (apt/rpm/pip/npm) baked into the image
container-diff analyze -t file -t apt -t pip daemon://image_name

# Diff a suspect image against a known-good base to isolate what was added
container-diff diff daemon://suspect_image daemon://library/wordpress:latest -t file -t apt
```

🔴 `container-diff diff <suspect> <clean-base> -t file` is the fast way to isolate *only* the attacker's additions when you have a known-good reference image.

## Malicious Image Indicators

What to look for once the image is unpacked/analyzed:

| Indicator | Meaning |
|-----------|---------|
| `RUN curl/wget … | sh` in history | Build-time payload download |
| Baked-in `Env` secret, token, or key | Credential exposure / attacker access |
| Added `authorized_keys` / SSH key in a layer | Persistent access in the image |
| Miner / reverse-shell / webshell binary in a layer | Malicious tooling baked in |
| `ENTRYPOINT`/`CMD` pointing at a dropped script | Payload runs on every container start |
| A late layer modifying a base-image binary | Trojaned component |
| Image from an unexpected / typosquatted registry name | Supply-chain / poisoned image |

## Base Image Comparison

Establish the legitimate baseline and diff against it — the delta is the tampering.

```bash
# Pull the clean upstream base named in the Dockerfile/history, then container-diff
docker pull library/wordpress:6.4
container-diff diff daemon://suspect daemon://library/wordpress:6.4 -t file

# Or hash-compare a specific base binary in the suspect layer vs the clean image
sha256sum /cases/docker/output/<layer>/usr/local/bin/php
```

## Getting Max Value

- **`docker save` preserves provenance** — keep the layers so you can attribute a file to its build step; `docker export` only when you want the flattened FS.
- **Read `manifest.json` and the config `history` first** — they tell you layer order and the Dockerfile steps (where backdoors hide).
- **Hash the payload** (`md5sum`/`sha256sum`) for identity + fleet-hunt IOCs.
- **Late layers + whiteouts** are where added/removed evidence lives — check them specifically.
- **Diff against a clean base image** (`container-diff diff`) to isolate exactly what the attacker added.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| The live/stopped container that ran this image | **Docker → Investigating Docker** |
| How images/layers/registries work | **Docker → Architecture and Components** |
| Reverse/triage a binary pulled from a layer | **Linux → ELF and Malware Triage** (11b) |
| YARA-scan the extracted layers + fleet hunt | **Linux → IOC and YARA Scanning** (11d) |
| Registry/supply-chain + signing | **Runtime Detection and Logging**, **Linux → Package Managers** (08) |
| Preserve the image + layers as evidence | **Evidence Collection** |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `RUN curl … | sh` / `ADD http://…` in the config history | Build-time payload |
| Baked-in secret/token/SSH key in a layer or `Env` | Credential exposure / persistent access |
| Miner/webshell/reverse-shell binary in a layer | Malicious tooling in the image |
| `.wh.` whiteout hiding a file between layers | Evidence removed during build |
| Late layer modifying a base-image binary | Trojaned component |
| Image name typosquats a popular one / unexpected registry | Poisoned supply chain |

## Resources

- OCI Image Specification (manifest/config/layers) — https://github.com/opencontainers/image-spec
- container-diff — https://github.com/GoogleContainerTools/container-diff
- docker-explorer (Google, offline Docker/containerd storage forensics) — https://github.com/google/docker-explorer
- skopeo (registry-side image inspection) — https://github.com/containers/skopeo
- Docker `save`/`export` reference — https://docs.docker.com/reference/cli/docker/image/save/
- MITRE ATT&CK: T1610 (Deploy Container), T1612 (Build Image on Host), T1525 (Implant Internal Image)
