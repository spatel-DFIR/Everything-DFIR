# Kubernetes Architecture and Components

The knowledge base for Kubernetes (K8s) — *how a cluster is built* so cluster IR makes sense. Kubernetes orchestrates containers across many nodes: a **control plane** (API server, etcd, scheduler, controllers) decides *what* should run, and **nodes** (kubelet + container runtime) actually run it as pods. For DFIR this scale is the whole point — one compromised cluster puts every workload, secret, and often the cloud account within reach. This note maps every component and, crucially, **where each one leaves evidence**; the investigation flow is the next note.

> 🔴 The **API server audit log is the single most important Kubernetes artifact** — it records every authenticated API request (who, what, when, from where). **etcd** is the source of truth and holds every **Secret** (base64, *not* encrypted unless you configured it). And the **kubelet** on each node runs any pod manifest dropped in `/etc/kubernetes/manifests/` with **no API-server record** — a stealth node-persistence path. Know these three before you triage.

## Contents

- [The Control Plane](#the-control-plane)
- [The Nodes](#the-nodes)
- [Objects and Concepts](#objects-and-concepts)
- [RBAC and Service Accounts](#rbac-and-service-accounts)
- [The Evidence Map](#the-evidence-map)
- [Managed vs Self-Hosted](#managed-vs-self-hosted)
- [Where the Evidence Lives](#where-the-evidence-lives)
- [Resources](#resources)

## The Control Plane

The "brain" — decides desired state and serves the API:

| Component | Role | Forensic relevance |
|-----------|------|--------------------|
| 🔴 **kube-apiserver** | The single entry point; every action is an authenticated API call | The **audit log** = the whole attacker session at the API level |
| 🔴 **etcd** | Key-value store of *all* cluster state, incl. Secrets | Read etcd (or a snapshot) = every object + secret; base64 unless encrypted |
| **kube-scheduler** | Assigns pods to nodes | Control-plane logs |
| **kube-controller-manager** | Reconciles desired vs actual state | Control-plane logs |
| **cloud-controller-manager** | Ties the cluster to cloud APIs | The pivot into the cloud account |

🔴 Everything funnels through the API server, so its **audit log** is the master timeline. etcd is where the crown jewels (Secrets, ServiceAccount tokens, all config) live — an etcd snapshot or backup is a full-cluster compromise if encryption-at-rest isn't enabled.

## The Nodes

Where workloads actually run:

| Component | Role | Forensic relevance |
|-----------|------|--------------------|
| 🔴 **kubelet** | Node agent; runs/monitors pods; talks to the runtime | `/var/lib/kubelet`, kubelet logs, and **static pods** in `/etc/kubernetes/manifests/` |
| **container runtime** (containerd / CRI-O) | Actually runs containers (via CRI) | `crictl` (not `docker`); per-container artifacts (Fundamentals) |
| **kube-proxy** | Node networking / service routing | iptables/ipvs rules on the node |
| **Pods** | The scheduled unit (1+ containers) | `/var/log/pods/`, `/var/log/containers/` on the node |

🔴 **Static pods** are the trap: the kubelet runs any pod YAML dropped in `/etc/kubernetes/manifests/` directly, with no API-server involvement — so a malicious static pod (privileged, `hostPath: /`) is node (and often cluster) compromise that **won't appear in the audit log**.

## Objects and Concepts

The API objects an analyst reasons about:

- **Pod** — one or more containers sharing a network/IPC namespace; the smallest schedulable unit.
- **Deployment / DaemonSet / StatefulSet** — controllers that keep pods running (a DaemonSet runs a pod on *every* node — attacker-favoured for fleet persistence).
- **Job / CronJob** — one-shot / scheduled pods (container-world cron).
- **Namespace** — a logical partition (`kube-system` is the sensitive one).
- **Service / Ingress** — expose pods to the network.
- **ConfigMap / Secret** — config and credentials (Secrets are base64, not encrypted by default).
- **Admission webhooks** (Validating/Mutating) — 🔴 can inspect or *mutate* every object create — a mutating webhook can inject a sidecar/backdoor into every new pod cluster-wide.

## RBAC and Service Accounts

Authorization is **RBAC**: `Role`/`ClusterRole` (permissions) bound to subjects via `RoleBinding`/`ClusterRoleBinding`.

- A **ServiceAccount (SA)** is a pod's identity; every pod gets a mounted **JWT token** at `/var/run/secrets/kubernetes.io/serviceaccount/token` that authenticates to the API as that SA.
- **Escalation primitives** to know: a subject that can `create pods` (mount any SA/hostPath and escalate), `exec` into pods, `impersonate`, create `rolebindings`, or read `secrets` — any of these is a path to cluster-admin.
- `cluster-admin` / `system:masters` = full control; a new binding to either is a takeover.

🔴 A stolen SA token used **outside its pod** authenticates as that SA from anywhere — the container-world equivalent of a stolen credential, and the main lateral-movement mechanism inside a cluster.

## The Evidence Map

| Component | Where evidence lives |
|-----------|---------------------|
| kube-apiserver | 🔴 **Audit log** — all API activity (the entry point) |
| etcd | Cluster state DB (all objects + Secrets) |
| controller-manager / scheduler | Control-plane logs |
| kubelet (per node) | Node agent logs; `/var/lib/kubelet`; static pod manifests |
| kube-proxy | Node networking (iptables/ipvs) |
| container runtime | Per-container (`crictl`; see Fundamentals) |
| Pods | `/var/log/pods/`, `/var/log/containers/` on nodes |

## Managed vs Self-Hosted

- **Self-hosted / kubeadm** — control-plane components run as static pods on control-plane nodes; the **audit log is a file** (`/var/log/kubernetes/audit/audit.log`) and etcd is directly reachable.
- **Managed (EKS / GKE / AKS)** — the control plane is the provider's; you **don't** get shell on it. The audit log surfaces via **cloud logging** (CloudWatch / Cloud Logging / Azure Monitor) — pull it from there. You still own the nodes (and their kubelet/runtime/pod logs).

🔴 On managed clusters, the API audit trail lives in the cloud provider's logging, and cluster compromise frequently **pivots into the cloud account** (via node IAM roles / IRSA / Workload Identity) — flag that pivot.

## Where the Evidence Lives

| Question | Artifact |
|----------|----------|
| Who did what at the API? | kube-apiserver **audit log** |
| Full cluster state + secrets? | **etcd** (snapshot it) |
| What pods/workloads exist? | `kubectl get pods,deploy,ds,cronjobs -A` |
| Node persistence with no API record? | `/etc/kubernetes/manifests/` static pods |
| Who can escalate? | RBAC (`ClusterRoleBindings`, `auth can-i`) |
| A stolen identity? | ServiceAccount token used off-pod (audit log) |
| Cloud pivot? | node IAM role / IRSA / IMDS from a pod |

## Resources

- Kubernetes architecture — https://kubernetes.io/docs/concepts/architecture/
- Kubernetes auditing — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
