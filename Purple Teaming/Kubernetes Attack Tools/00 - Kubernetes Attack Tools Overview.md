# Kubernetes Attack Tools — Overview

The root page for the `Kubernetes Attack Tools/` folder. This page covers the Kubernetes architecture, the shared API patterns and authorization mechanisms that all three sub-tools exploit, a timeline of how attacks typically chain together, and a table of contents to the three specialized sub-tool folders.

## Contents
- [Kubernetes Architecture](#kubernetes-architecture)
- [Shared Attack Surface](#shared-attack-surface)
- [The Three-Tool Attack Chain](#the-three-tool-attack-chain)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## Kubernetes Architecture

Verified against the official [Kubernetes Architecture Documentation](https://kubernetes.io/docs/concepts/architecture/) and the current Kubernetes codebase (`kubernetes/kubernetes` v1.30+):

### Control Plane components

The **control plane** (or **master** in legacy terminology) manages the cluster's state:

- **kube-apiserver** — the central Kubernetes API server (port 6443 by default). Every resource read/write goes through here. All authentication and authorization (RBAC) is enforced at this component.
- **kube-controller-manager** — runs reconciliation loops that ensure desired state matches actual state (e.g., "if a Deployment wants 5 Pods, create them").
- **kube-scheduler** — assigns Pods to nodes.
- **etcd** — the distributed key-value store holding all cluster state (nodes, pods, secrets, roles, etc.). Unencrypted ETCD is a critical vulnerability.

### Worker node components

Each **node** (worker machine) runs:

- **kubelet** — the node-level Kubernetes agent; ensures Pods are running as configured. Exposes an HTTP API on port 10250 (kubelet API).
- **Container runtime** — Docker, containerd, or CRI-O; actually runs containers.
- **kube-proxy** — manages network routing for Services.

### Logical structure

```
Cluster
├── Namespace "default"
│   ├── Pod "web-app-1"
│   │   └── Container (running application)
│   ├── Pod "web-app-2"
│   ├── Service "web-svc" (routes traffic to Pods)
│   ├── Deployment "web-app" (manages Pods)
│   └── Secret "db-password" (encrypted credentials)
├── Namespace "kube-system" (system components)
│   ├── Pod "kube-apiserver-node1"
│   ├── Pod "coredns" (DNS)
│   └── Pod "etcd-node1" (state store)
└── Namespace "kube-public" (world-readable, rare)
```

- **Namespaces** — logical isolation within a cluster (not cryptographic; RBAC is the enforcement boundary).
- **Pods** — the smallest deployable unit; one or more containers sharing network namespace.
- **Deployments/StatefulSets/DaemonSets** — higher-level abstractions managing Pods.
- **Services** — network abstractions exposing Pods to internal/external traffic.
- **Secrets/ConfigMaps** — key-value stores for sensitive/non-sensitive configuration.
- **ServiceAccounts** — identity objects; each Pod gets a token for API server authentication.
- **ClusterRoles/ClusterRoleBindings** — RBAC policy; define who can do what.

---

## Shared Attack Surface

All three tools exploit the same core Kubernetes API and authorization layer:

### 1. Kubernetes API Server (port 6443)

The API server is the **single point of enforcement** for every cluster operation. Attackers target it in stages:

| Stage | Tool | Method | Signal |
|-------|------|--------|--------|
| **Discovery** | kubectl / kube-hunter | Network scan for port 6443; attempt anonymous access | Audit logs: `user: system:anonymous` with `403 Forbidden` |
| **Credential acquisition** | kubectl / peirates | Extract ServiceAccount tokens from `/var/run/secrets/.../token`; exfiltrate kubeconfig files | Audit logs: requests from Pod IPs (internal); process logs showing file reads |
| **Exploitation** | kubectl / peirates | Use token to call API (e.g., `kubectl get secrets`, `kubectl create pods`) | Audit logs: verb/resource matching the exploitation (get/list secrets, create pods) |

### 2. ServiceAccount tokens (JWT format)

Every Pod automatically receives a **ServiceAccount token** at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This token is a **JWT** signed by the API server and contains claims including the Pod's namespace and ServiceAccount name:

```
Header: { "alg": "RS256", "kid": "..." }
Payload: { "kubernetes.io/serviceaccount/namespace": "default", "kubernetes.io/serviceaccount/service-account.name": "default", ... }
Signature: <cryptographic signature from API server key>
```

Attackers targeting tokens:
- **kubectl** uses extracted tokens directly (via `--token` flag).
- **peirates** reads the in-cluster token automatically; uses it to make API calls.
- **kube-hunter** attempts to abuse the API server with anonymous access, but also probes for token misconfigurations.

### 3. RBAC (Role-Based Access Control)

RBAC is the **authorization layer**. Every API call is checked against the requestor's ClusterRole/Role bindings:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin
rules:
- apiGroups: [""]
  resources: ["*"]  # All resources
  verbs: ["*"]      # All verbs (GET, POST, PATCH, DELETE, etc.)
```

Common RBAC misconfigurations:
- **Default namespace has `cluster-admin` via rolebinding** — allows any Pod in that namespace to act as a superuser.
- **Overly-permissive ServiceAccount** — grants `create pods`, `create secrets`, or `patch clusterrolebindings` to a low-privilege identity.
- **`*` wildcards in ClusterRoles** — grants all permissions to a resource or verb.

Attackers exploiting RBAC:
- **kubectl** checks permissions via `kubectl auth can-i`; identifies privesc opportunities.
- **peirates** uses escalated tokens to create new admin Pods or modify ClusterRoleBindings.
- **kube-hunter** probes for overly-permissive roles.

### 4. Namespaces and isolation

**Namespaces are NOT security boundaries** — they're logical grouping. All Pods on the same node share the Linux kernel. If a Pod escapes its container, it has access to the node; if the node is compromised, all Pods on it are visible.

Attackers exploiting weak namespace isolation:
- **peirates** escalates from one namespace to system namespaces (kube-system) to compromise cluster-level components.
- **kubectl** uses RBAC to cross namespaces if overly-permissive rules exist.

---

## The Three-Tool Attack Chain

A realistic attack typically flows through all three tools in sequence:

```
┌─────────────────────────────────────────────────────────────────┐
│ Stage 1: External Reconnaissance (kube-hunter)                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ Attacker runs kube-hunter from external network:                │
│ - Network scan for Kubernetes ports (6443, 10250, 2379)        │
│ - Probe API server for anonymous access                        │
│ - Detect unencrypted ETCD or kubelet APIs                      │
│                                                                   │
│ Signal: A burst of API audit log 403 Forbidden responses        │
│ from external IP, user=system:anonymous                         │
│                                                                   │
│ Result: API server endpoint identified; may find vulnerability  │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 2: API Server Exploitation (kubectl)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ Attacker obtains credentials (via kube-hunter findings or       │
│ other means: leaked kubeconfig, intercepted token, etc.)        │
│                                                                   │
│ kubectl is used to:                                              │
│ - Enumerate Pods, Secrets, ConfigMaps, RBAC policy             │
│ - Create backdoor Pod with privileged: true or hostPath: /     │
│ - Read sensitive data (Secrets, ConfigMaps)                     │
│                                                                   │
│ Signal: Audit logs show API calls with valid credentials,       │
│ accessing secrets or creating Pods                              │
│                                                                   │
│ Result: Foothold inside cluster (running backdoor Pod)          │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 3: Container Escape & Privilege Escalation (peirates)     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ Attacker execs into the backdoor Pod (via kubectl exec)         │
│ and runs peirates to:                                           │
│                                                                   │
│ - Test kernel vulnerabilities (Dirty COW, Netfilter CVE)       │
│ - Exploit container escape to node root                         │
│ - Extract kubeconfig from /root/.kube/config                    │
│ - Use elevated token to create cluster-admin Pod               │
│                                                                   │
│ Signal: Root-owned processes spawning from non-root container;  │
│ kernel logs showing exploitation attempts (segfaults, oops)     │
│                                                                   │
│ Result: Cluster-admin access; ability to persist and expand      │
└──────────────────────┬──────────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│ Stage 4: Persistence & Lateral Movement                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│ With cluster-admin access:                                       │
│ - Create CronJobs that spawn persistent backdoor Pods          │
│ - Modify RBAC to create new admin accounts                     │
│ - Extract ETCD backups containing all Secrets/config           │
│ - Deploy malicious Deployments across multiple nodes           │
│                                                                   │
│ Signal: Unexpected Pods in kube-system; API audit showing       │
│ cluster-admin operations; Event objects showing bulk creation   │
└─────────────────────────────────────────────────────────────────┘
```

**Not all attacks follow this exact sequence:** An attacker might:
- Skip Stage 1 if they already have a credential (compromised laptop with kubeconfig).
- Skip Stage 2 if they're already inside a container (security incident triggered by supply-chain compromise).
- Use only kubectl if RBAC misconfiguration allows direct cluster-admin access without escape.

---

## Sub-Tool Table of Contents

| Sub-Tool | Purpose | Execution Context | Key Signal |
|----------|---------|---|---|
| [`kubectl/`](kubectl/01%20-%20Overview.md) | Kubernetes CLI — query/modify cluster state via API server | External to cluster (attacker's workstation) or inside a Pod | API audit log entries with legitimate-looking verbs/resources; kubeconfig file on attacker's machine |
| [`kube-hunter/`](kube-hunter/01%20-%20Overview.md) | Automated Kubernetes penetration tester — discovers API servers, probes vulnerabilities, tests default credentials | External to cluster; can run as Pod internally | Burst of 50+ API calls in 10 seconds with 403 Forbidden responses; port scanning for 6443/10250/2379 |
| [`peirates/`](peirates/01%20-%20Overview.md) | Post-exploitation tool — container escape, privilege escalation, lateral movement | Inside a container Pod (must be deployed first via kubectl or other means) | Root-owned child processes from non-root container; kernel logs showing exploitation attempts; unexpected API calls from Pod IPs |

---

## Most Distinctive Detection Signal (Across All Three)

The **single most reliable red-flag pattern** spanning all three tools:

1. **External burst of API calls (100+/sec)** from IP X to port 6443, mostly 403 Forbidden → **kube-hunter indicator**.
2. **Short pause** (seconds).
3. **Fewer but valid API calls** from IP X, accessing Secrets/Pods, creating new Pods → **kubectl indicator** (possibly compromised credential).
4. **Switch to internal Pod IP (10.x.x.x)** making API calls, creating Pods, modifying RBAC → **peirates indicator** (inside-cluster escalation).

When audit logging is enabled, this entire chain is captured sequentially in the audit log, making attribution and timeline reconstruction straightforward. **Disabling audit logging requires API server restart or cluster-admin access** — both of which are suspicious operations themselves.
