# kube-hunter — Overview

> 🔴 **Red Flag Principle:** kube-hunter is an **automated Kubernetes penetration testing tool** developed by Aqua Security that performs a standardized, repeatable attack chain: network reconnaissance, API server discovery, credential harvesting, and privilege escalation testing. Unlike `kubectl` (which is a manual API client), kube-hunter's operational footprint is **highly distinctive**: a rapid, sequential burst of probe attempts against well-known Kubernetes attack vectors, followed by evidence-gathering queries. Detection should focus on **anomalous access patterns** (rapid API calls, probing of default credentials, exploitation attempts) rather than individual API calls, since any single call by itself is legitimate.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

kube-hunter is developed and maintained by **[Aqua Security](https://www.aquasec.com/)**, a container and Kubernetes security company. The canonical upstream repository is [`aquasecurity/kube-hunter`](https://github.com/aquasecurity/kube-hunter), licensed under **Apache License 2.0**. Verified against the repo and GitHub API:

- **Repository created 2018-02-27** — born as an open-source offensive security tool for auditing Kubernetes clusters before most blue-team tooling existed.
- **`v1.0.0` (June 2019)** — first stable release, formalized the scanning methodology and attack chain.
- **`v0.6.x` (2021-2024)** — current active maintenance branch; recent additions include pod_exec_scanner, token_mounted_scanner, and improved CVE detection.
- **GitHub stars:** 3,500+; actively maintained (commits within the current month).

kube-hunter is **not a library** but a standalone **scanning tool** — it compiles to a single statically-linked binary or runs as a container image (`aquasec/kube-hunter:latest`). Unlike `kubectl`, kube-hunter is purpose-built for offensive testing and is rarely installed on workstations; instead, it's run as a container Pod inside the target cluster or executed once from an external scanning host.

## How It Works

### Scanning methodology — the kube-hunter attack chain

Verified against the source `kube_hunter/plugins/` and the project's own documentation:

kube-hunter operates in **two modes**:

#### Mode 1: External scanning (network reconnaissance)

When run outside the cluster, kube-hunter:
1. **Network reconnaissance** — probes a given IP range or Kubernetes API server endpoint for open ports (6443, 10250, 10255, 2379, etc.).
2. **Service identification** — identifies which Kubernetes components are present (API server, kubelet, ETCD, etc.).
3. **Vulnerability probing** — attempts known Kubernetes CVEs and misconfigurations:
   - Anonymous API server access (no credentials required).
   - Unauthenticated kubelet API (port 10250).
   - Unencrypted ETCD (port 2379).
   - Default credentials (e.g., `admin:admin` on some installers).
   - Kubernetes Dashboard (port 30000) with default authentication.
4. **Exploitation attempts** — tries container escape techniques and privilege escalation if vulnerabilities are found.

#### Mode 2: Internal scanning (from within the cluster)

When run **as a Pod inside the cluster**, kube-hunter gains access to:
1. **In-cluster service discovery** — automatically finds the API server at `kubernetes.default.svc.cluster.local:443`.
2. **ServiceAccount token access** — reads the Pod's mounted token at `/var/run/secrets/kubernetes.io/serviceaccount/token`.
3. **Node access** — probes the kubelet on each node (port 10250), which is typically only accessible from within the cluster.
4. **Container escape** — tests kernel vulnerabilities (e.g., CVE-2016-5195 "dirty cow", CVE-2021-22555).

### kube-hunter's plugin architecture

The tool is organized around **plugins** (attack modules), each testing a specific vector:

| Plugin | Tests | Requires |
|--------|-------|----------|
| **api_server** | Anonymous API server access, privilege checking | Network access to port 6443 |
| **kubelet** | Unauthenticated kubelet API, read nodes/pods/logs | Network access to port 10250 |
| **kubeproxy** | IPVS/iptables manipulation via kubeproxy API | Network access to port 10256 |
| **etcd** | Unencrypted ETCD access | Network access to port 2379 |
| **pod_exec_scanner** | Exploits to break out of containers (CVEs) | Execution inside a container |
| **token_mounted_scanner** | Tests if ServiceAccount token is mounted and usable | Execution inside a container |
| **capabilities_scanner** | Checks container capabilities (CAP_SYS_PTRACE, etc.) | Execution inside a container |
| **privilege_scanner** | Tests privilege escalation via RBAC, kernel CVEs | Execution inside a container |

---

## Techniques / Protocols Used

- **HTTPS (TLS 1.2+)** — API server connections.
- **HTTP (unencrypted)** — kubelet, kubeproxy, ETCD unauthenticated endpoints.
- **Kubernetes API (HTTP REST)** — enumeration and exploit delivery.
- **SSH (if configured)** — node access via SSH keys (if they're compromised).
- **Kernel exploitation** — CVE-based container escape (requires local execution).

---

## Command-Line Switches — Quick Reference

| Flag | Description |
|---|---|
| (no args) | Run internal scan (assumes running inside a Pod) |
| `--pod` | Run internal scan (explicitly set mode) |
| `--active` | Enable aggressive/destructive tests (use with caution) |
| `--remote <IP:PORT>` | Scan an external Kubernetes API server endpoint |
| `--service <NAMESPACE>/<SERVICE>` | Scan a specific Kubernetes service (internal mode) |
| `--port <PORT>` | Override default port for scanning |
| `--output json` | Output results in JSON format (default: text) |
| `--output yaml` | Output results in YAML format |
| `--output none` | Suppress output (useful for integration) |
| `--log` | Enable debug logging |
| `-v, --verbose` | Verbose output |

---

## Quick Use-Case List

1. **External cluster discovery** — find Kubernetes API servers on a network range.
2. **Unauthenticated API server access testing** — check if the cluster allows anonymous reads/writes.
3. **Kubelet API enumeration** — extract node information, pod specs, logs from port 10250.
4. **ETCD exploitation** — dump cluster state from unencrypted ETCD (port 2379).
5. **ServiceAccount token harvesting** — extract tokens from compromised Pods.
6. **Privilege escalation testing** — test RBAC misconfigurations via the extracted token.
7. **Container escape exploitation** — probe for kernel CVEs and test escapes.
8. **Default credential testing** — try common username/password combinations.
9. **Kubernetes Dashboard access** — test for unprotected dashboard instances.
10. **Supply-chain attack simulation** — test pull-secret credentials and registry access.

---

## Prerequisites

- **For external scanning:** Network access to the target cluster (API server, kubelet, ETCD ports).
- **For internal scanning:** A compromised container with the ability to run the kube-hunter binary or its Docker image.
- **Python 3.6+** (if running from source) or a container runtime (if running the Docker image).
- **No specific credentials required** for initial discovery (kube-hunter is specifically designed to work without credentials), though credentials accelerate exploitation.
