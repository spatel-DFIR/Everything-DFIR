# Runtime Detection and Logging

The cross-cutting telemetry that catches container attacks *in motion* — **Falco** and **Tracee** (eBPF/syscall level), host **auditd** correlated to containers, and the **Docker/Kubernetes control-plane logs**. Because so much container malice is fileless (in-memory, `memfd`, short-lived), this behavioral telemetry is frequently the *only* record. Applies across Docker, Podman, and Kubernetes.

> 🔴 The single most useful join in container DFIR: a host syscall event (from auditd/Falco/eBPF) carries the **host PID**, and `/proc/<host_pid>/cgroup` names the **container** it came from. Master that pivot and every host-level detection becomes container-attributable.

## Contents

- [Quick Triage](#quick-triage)
- [Falco](#falco)
- [Tracee and eBPF Tools](#tracee-and-ebpf-tools)
- [auditd for Containers](#auditd-for-containers)
- [Docker Daemon Logs](#docker-daemon-logs)
- [FluentBit (Log-Shipping Layer)](#fluentbit-log-shipping-layer)
- [Kubernetes Audit](#kubernetes-audit)
- [Attributing a Syscall to a Container](#attributing-a-syscall-to-a-container)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Is runtime security tooling present?
systemctl status falco 2>/dev/null | head -3; which tracee falco 2>/dev/null

# Falco alerts
journalctl -u falco --since "24 hours ago" 2>/dev/null; cat /var/log/falco/falco.log 2>/dev/null

# Docker daemon activity
journalctl -u docker --since "24 hours ago" | grep -Ei "exec|create|mount|error"

# Container process events via auditd (if keyed)
ausearch -k docker -i 2>/dev/null
```

## Falco

Falco watches kernel syscalls (via eBPF or a kernel module) and alerts on rule matches — shell-in-container, sensitive mounts, escapes, unexpected network.

```bash
# Service + config + where alerts go (file / syslog / journald / stdout)
systemctl status falco; grep -Ei 'json_output|file_output|syslog' /etc/falco/falco.yaml

cat /var/log/falco/falco.log 2>/dev/null; journalctl -u falco

# Rules in effect
ls /etc/falco/*.yaml /etc/falco/rules.d/ 2>/dev/null
```

High-value default rules to look for in the alert stream:

| Rule (paraphrased) | Catches |
|--------------------|---------|
| Terminal shell in container | 🔴 Interactive shell spawned in a container |
| Launch privileged container | Privileged container start |
| Sensitive mount / write below etc | Host-path mount, `/etc` writes |
| Change thread namespace | `nsenter` / escape attempt |
| Outbound connection to non-allowed host | C2 / exfil |
| Read sensitive file (shadow, ssh keys) | Credential access |

## Tracee and eBPF Tools

```bash
# Tracee (Aqua) — eBPF runtime tracing/detection
tracee --output json 2>/dev/null | head

# Other eBPF observability if deployed: sysdig, Cilium Tetragon
sysdig -c topprocs_cpu container.name!=host 2>/dev/null
```

🔴 eBPF-based tools see execution that never touches disk (fileless, `memfd`) — frequently the only trace of an in-memory container attack (cross-ref Linux → eBPF Tooling).

## auditd for Containers

Host auditd sees container syscalls too; correlate them by namespace/cgroup (see Linux → Auditd for the full command set).

```bash
# If a docker key was configured
ausearch -k docker -i

# Executions, then filter to container cgroups
ausearch -sc execve -i | grep -Ei "docker|containerd|kubepods|libpod"

# Defensive: watch the docker socket
# auditctl -w /var/run/docker.sock -p rwxa -k docker_sock
```

🔴 auditd records the syscall with the **host PID** — join that PID's `/proc/PID/cgroup` to attribute it to a container (below).

## Docker Daemon Logs

```bash
# dockerd log (journald on systemd hosts) or file-based
journalctl -u docker; cat /var/log/docker.log 2>/dev/null

# High-value events
journalctl -u docker | grep -Ei "exec|create|start|kill|mount|oom|error|unauthorized"

# The daemon event stream (structured lifecycle timeline)
docker events --since '2026-04-23' --until '2026-04-24'
```

🔴 `docker events` / the daemon log record `create`, `start`, `exec_create`/`exec_start` (**interactive access**), `mount`, `kill`, and image pulls — a container-lifecycle timeline. (Podman: `journalctl CONTAINER_NAME=`; the daemonless model has no central daemon log.)

## FluentBit (Log-Shipping Layer)

The sections above cover *where* container/K8s logs live (`docker logs`, `*-json.log`, the daemon log). **FluentBit** is the de facto standard agent that ships those logs off-host — typically stdout/stderr from every container, tailed and forwarded to a central store. It sits between the evidence and its long-term retention, which makes it a tamper target in its own right: an attacker (or a careless config change) doesn't need to touch the source logs if they can just stop shipping them.

```bash
# Is FluentBit running, and since when?
systemctl status fluent-bit 2>/dev/null; ps -ef | grep -i fluent-bit

# Its config — inputs (what it tails), filters, and outputs (where logs go)
cat /etc/fluent-bit/fluent-bit.conf 2>/dev/null

# In Kubernetes, FluentBit normally runs as a DaemonSet (one pod per node)
kubectl get daemonset -A | grep -i fluent-bit
kubectl get pods -A -l app.kubernetes.io/name=fluent-bit
```

🔴 If FluentBit was stopped, its config was edited to drop a source/output, or its DaemonSet is missing from nodes it should be running on, logs may still be generated locally but never reach the central store — a **log-tampering / retention gap** rather than a logging gap. Always cross-check the local on-host log (`docker logs`, `*-json.log`, journald) against what actually landed in the downstream log store; a mismatch or a hole in the timeline points at the shipping layer, not the source.

## Kubernetes Audit

The API-server audit log is the K8s equivalent — covered fully in **Kubernetes → Investigating**. In brief:

```bash
cat /var/log/kubernetes/audit/audit.log | jq 'select(.objectRef.subresource=="exec")'
```

## Attributing a Syscall to a Container

The join that ties host telemetry to a specific container:

```bash
# From a host PID (from auditd/Falco), find its container ID
grep -oE '[0-9a-f]{64}|docker-[0-9a-f]+|libpod-[0-9a-f]+' /proc/<host_pid>/cgroup

# Map that container ID back to a name / pod
docker ps --no-trunc | grep <container_id>
crictl ps -a | grep <shortid>

# Namespaces confirm the isolation boundary
ls -l /proc/<host_pid>/ns/
```

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| eBPF live tracing / malicious eBPF | **Linux → eBPF Tooling for DFIR** (10d) |
| The full auditd command set + record types | **Linux → Auditd** |
| The K8s audit log analysis in depth | **Kubernetes → Investigating** |
| Docker lifecycle events + inspect | **Docker → Investigating Docker** |
| The `/proc` workup of the container process | **Linux → Live Response** (10) |
| Preserving the telemetry as evidence | **Evidence Collection** |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| Falco "shell in container" alert | Interactive attacker in a container |
| Falco/Tracee namespace-change or sensitive-mount alert | Escape attempt |
| Docker `exec_start` at an odd time | Interactive container access |
| auditd/eBPF execution with no disk-backed binary | Fileless container malware |
| Runtime security tooling stopped/disabled | Evasion |
| FluentBit stopped, reconfigured, or its DaemonSet missing from a node | Log shipping tampered with / retention gap |
| Outbound connection from a container to an unknown host | C2 / exfil |

## Resources

- Falco — https://falco.org
- Tracee — https://github.com/aquasecurity/tracee
- FluentBit — https://fluentbit.io
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
