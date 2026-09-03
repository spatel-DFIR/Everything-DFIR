# peirates — Overview

> 🔴 **Red Flag Principle:** peirates is a **Kubernetes post-exploitation tool** designed to escalate privileges and pivot laterally once an attacker is **already inside a container** (either compromised or deliberately deployed). Unlike `kubectl` (API client from outside) or `kube-hunter` (automated external scanner), peirates' operational footprint is **container-internal**: filesystem manipulation, kernel exploitation, pod-to-pod lateral movement via shared namespaces or network access. Detection focuses on **in-container process behavior** (unexpected child processes, capability probing, privilege escalation attempts) and **node-level evidence** (container escape traces, modified kernel state, rogue processes with root context).

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

peirates is developed and maintained by **Aqua Security**, the same team behind kube-hunter. The canonical upstream repository is [`aquasecurity/peirates`](https://github.com/aquasecurity/peirates), licensed under **Apache License 2.0**. Verified against the repo and GitHub API:

- **Repository created 2018-06-15** — designed as a post-exploitation Kubernetes pivot tool.
- **v1.0.0 (March 2019)** — first stable release, formalized privilege escalation and container escape methodology.
- **Current (v1.1.x, 2024)** — active maintenance; recent additions include CVE-2024-21626 (runc escape) support, improved RBAC testing, and API server authentication bypass probes.
- **GitHub stars:** 2,000+; maintained regularly.

peirates is a **standalone binary** (Go-compiled) with no external dependencies, designed to fit in minimal container environments. It's typically installed inside a compromised container or deployed via kubectl as a multi-stage payload.

## How It Works

### Three exploitation stages

Verified against the source `peirates/` modules:

#### Stage 1: In-container information gathering
- List mounted ServiceAccount token path and read it.
- Enumerate container capabilities via `/proc/self/status` (CapEff, CapPrm, CapInh).
- Check for overly-permissive mounts (e.g., `hostPath: /` allowing full node filesystem access).
- Query the Kubernetes API server using the mounted ServiceAccount token.
- Test what RBAC permissions the Pod's ServiceAccount has.

#### Stage 2: Container escape and privilege escalation
- **Dirty COW (CVE-2016-5195)** — kernel vulnerability allowing write to read-only mappings; breaks out to root.
- **CVE-2021-22555** — netfilter/iptables vulnerability (Netfilter Local Privilege Escalation).
- **CVE-2024-21626 (runc escape)** — container runtime escape via `/sys/fs/cgroup` manipulation.
- **Capability escalation** — if `CAP_SYS_PTRACE` is set, ptrace into a process running as root and escalate.
- **SECCOMP bypass** — if seccomp is not enforced, use low-level system calls for escape.

#### Stage 3: Lateral movement and persistence
- **Mount the host filesystem** via `hostPath` volume or kernel exploit, then `chroot`.
- **Create backdoor Pods** — use the compromised ServiceAccount to spawn new Pods across namespaces.
- **Copy kubeconfig** from the host's `/root/.kube/config` or ETCD backup.
- **Modify RBAC** — if the ServiceAccount has permissions, create overly-permissive ClusterRoles/ClusterRoleBindings.

---

## Techniques / Protocols Used

- **Linux kernel exploitation** — CVE-2016-5195, CVE-2021-22555, CVE-2024-21626 (Netfilter, runc, cgroups)
- **Container runtime manipulation** — cgroups, namespaces, seccomp, AppArmor/SELinux bypass
- **ptrace/process injection** — if CAP_SYS_PTRACE is set
- **Kubernetes API** (via mounted ServiceAccount token)
- **Node filesystem access** — via `hostPath` or kernel exploit
- **Bash scripting** — peirates is heavily shell-based with embedded Go binary fallback

---

## Command-Line Switches — Quick Reference

| Flag | Description |
|---|---|
| (no args) | Enter interactive menu |
| `--pod` | Attempt to exploit and pivot from the current Pod |
| `--list` | List available exploits and modules |
| `--exploit <NAME>` | Run a specific exploit (e.g., `--exploit dirty-cow`) |
| `--all` | Attempt all available exploits (warning: destructive) |
| `--kubeconfig <PATH>` | Path to kubeconfig for post-exploitation API access |
| `--api <URL>` | Kubernetes API server URL (for direct API calls) |
| `--token <TOKEN>` | ServiceAccount token for API authentication |
| `--nohostfspath` | Disable hostPath exploitation attempts |
| `--nokernel` | Disable kernel CVE exploitation attempts |
| `--hostname <NAME>` | Target node hostname (for targeted exploitation) |

---

## Quick Use-Case List

1. **Initial reconnaissance** — read mounted ServiceAccount token, check capabilities.
2. **Privilege escalation via kernel CVE** — dirty cow, netfilter, runc vulnerabilities.
3. **RBAC escalation** — use compromised token to create admin-level Pods or modify RBAC.
4. **Lateral movement to another Pod** — exploit shared namespaces or network access.
5. **Node breakout via hostPath mount** — if a Pod has `hostPath: /` mounted, access the host filesystem.
6. **Persistence via CronJob creation** — create a CronJob that auto-revives a backdoor Pod.
7. **Copy kubeconfig from host** — escalate to node, extract admin credentials, use kubectl externally.
8. **Container escape to privileged Pod** — if one exists, compromise it and use its privileges.
9. **Credential harvesting from environment** — extract KUBECONFIG, cloud credentials, API keys from running Pods.
10. **ETCD backup theft** — if accessible, dump cluster state including secrets.

---

## Prerequisites

- **Execution context** — must be running **inside a container** (not external, unlike kube-hunter).
- **Kubernetes API server accessibility** — the mounted ServiceAccount token must be able to reach the in-cluster API server (usually `kubernetes.default.svc.cluster.local:443`).
- **Kernel vulnerabilities** (for escape) — the host kernel must be vulnerable to one of the documented CVEs (Dirty COW, Netfilter, runc).
- **Capability misconfiguration** — for non-kernel-based escalation, the container must be run with excess capabilities (CAP_SYS_PTRACE, CAP_SYS_ADMIN, etc.).
- **Overly-permissive ServiceAccount token** — preferably with `create`/`patch`/`delete` permissions on Pods, Deployments, or ClusterRoles.

---

## How peirates differs from kubectl

| Aspect | kubectl | peirates |
|--------|---------|----------|
| **Execution context** | External to cluster (attacker's machine) | Inside a container (already compromised) |
| **Credential requirement** | Requires kubeconfig or ServiceAccount token | Uses the Pod's pre-mounted token |
| **Escape capability** | None — pure API client | Focuses on kernel exploit + namespace escape |
| **Operational noise** | High — API audit logs every call | Mixed — kernel exploits leave subtle traces |
| **Evasion vector** | Audit logging, RBAC restrictions | Kernel vulnerability patching, capability restrictions |
