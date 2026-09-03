# What is GKE?

**GKE (Google Kubernetes Engine)** is Google's **managed Kubernetes** — Google runs the Kubernetes control plane; you run containerized workloads on **nodes**. Like EKS and AKS, it brings **two identity and audit worlds** together: **Kubernetes RBAC + audit logs** and **Google IAM + Cloud Audit Logs**. Understanding the bridge between them — and the Kubernetes building blocks — is the whole game.

This note first nails the **Kubernetes fundamentals** (cluster / node pool / node / pod), then the **GKE-specific** DFIR. For core Kubernetes forensics, cross-reference the **Container → Kubernetes** notes.

## Contents

- [Kubernetes Building Blocks — Cluster, Node, Pod](#kubernetes-building-blocks--cluster-node-pod)
- [How It Works](#how-it-works)
- [The Two Identity Worlds — and the Bridge](#the-two-identity-worlds--and-the-bridge)
- [Workload Identity — Pods That Hold GCP Rights](#workload-identity--pods-that-hold-gcp-rights)
- [The Audit Logs — Your Primary Evidence](#the-audit-logs--your-primary-evidence)
- [The Pod → Metadata Problem](#the-pod--metadata-problem)
- [How to Identify GKE in Evidence](#how-to-identify-gke-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Kubernetes Building Blocks — Cluster, Node, Pod

🔴 The fundamentals every responder must have straight before touching a Kubernetes case. From biggest to smallest:

| Building block | What it is | Analogy |
|----------------|-----------|---------|
| **Cluster** | The whole Kubernetes system: a **control plane** + all the nodes. One GKE resource = one cluster. | The whole datacenter |
| **Node pool** | A group of identical **nodes** managed together (same machine type/config). A GKE cluster has 1+ node pools (Standard mode). | A rack of identical servers |
| **Node** | A single **VM** that runs workloads. Has a **kubelet** (agent) + container runtime. In GKE, nodes are **Compute Engine VMs**. | One server |
| **Pod** | The smallest deployable unit: **one or more containers** sharing a network/storage context. Pods run **on** nodes. | An app instance |
| **Container** | The running image (your code + deps) inside a pod. | A process |

**How they assemble into a cluster:**

```
Cluster
├── Control plane (Google-managed: API server, etcd, scheduler)   ← you get its AUDIT LOGS
└── Node pool(s)   [Standard mode]   |   Autopilot = Google manages nodes for you
    └── Node (a Compute Engine VM, runs a kubelet)
        └── Pod (scheduled onto the node)
            └── Container(s) (your workload)
```

- You talk to the cluster through the **API server** (via `kubectl`). Every `kubectl` action = a Kubernetes API call → the **audit log**.
- The **scheduler** decides which node a pod runs on. An attacker who can **create a pod** chooses the image and can request privileges/host access.
- **Namespaces** partition a cluster logically (e.g. `kube-system`, `default`, app namespaces).
- **Autopilot vs Standard:** in **Autopilot**, Google manages nodes (no node access for you *or* the attacker); in **Standard**, nodes are your Compute Engine VMs.

> 🔴 Why this matters on a case: "a new pod appeared" means an attacker got the cluster to **run their container** (often mining or a foothold); "a node was reached" often means they escaped a pod onto the **Compute Engine VM** (and can steal the node SA via the metadata server); "the cluster was compromised" means the **API/control-plane** access was abused. Different blast radius, different evidence — see **GKE → Playbooks → Malicious Pod and Cryptomining**.

## How It Works

```
GKE control plane (Google-managed API server + etcd)
   ├── Node pools: Compute Engine VMs that run your pods  (Standard)  |  Autopilot: Google-managed
   ├── Auth: Google IAM identity → mapped to Kubernetes RBAC
   ├── Workload identity: pods federate to a GCP service account for GCP rights
   └── Audit: control-plane logs → Cloud Logging (Cloud Audit Logs)
```

- The **control plane** is Google-managed; you don't shell into it — you get its **audit logs**.
- **Nodes** are Compute Engine VMs (Standard); pods run there.
- Access is a **two-step**: authenticate with **Google IAM**, then authorize with **Kubernetes RBAC**.

## The Two Identity Worlds — and the Bridge

The concept that trips everyone up (same as EKS/AKS):

| World | Who/what | Controls | Logged in |
|-------|----------|----------|-----------|
| **Google IAM** | Identities calling the GCP API + authenticating to the cluster | GCP actions + *who can reach the cluster* | **Cloud Audit Logs** |
| **Kubernetes RBAC** | Subjects acting *inside* the cluster | What you can do to pods/secrets/etc. | **GKE audit logs** (Cloud Logging) |

**The bridge** = how a Google identity maps to Kubernetes permissions:

- **IAM roles** like `roles/container.admin` / `roles/container.developer` grant cluster access at the GCP level.
- **`container.clusters.getCredentials`** fetches a kubeconfig — then Kubernetes RBAC decides in-cluster rights.
- Google **users/groups** can be bound directly in Kubernetes `RoleBinding`/`ClusterRoleBinding`.

> 🔴 **`container.clusters.getCredentials`** in Cloud Audit Logs = someone pulled cluster credentials. Combined with a broad IAM role (`container.admin`) or a `cluster-admin` RBAC binding, it's cluster takeover. Watch both the IAM side (Cloud Audit Logs) and the RBAC side (GKE audit).

## Workload Identity — Pods That Hold GCP Rights

Pods get GCP permissions via **GKE Workload Identity**: a Kubernetes service account maps to a **GCP service account**, so the pod gets GCP tokens **without a key**.

> 🔴 A compromised pod with Workload Identity gets that GCP SA's token → investigate its **IAM reach** (Storage? BigQuery? more SAs?), just like a stolen SA. A **loose mapping** lets the wrong pod impersonate the SA. See **GCP → Service Accounts**.

## The Audit Logs — Your Primary Evidence

GKE control-plane logging routes to **Cloud Logging**:

| Log | Contains |
|-----|----------|
| **Kubernetes API audit (Data Access)** | Every kube API call: who, verb, resource, decision |
| **Admin Activity (`container.*`)** | Cluster lifecycle/config + `getCredentials` (GCP side) |
| **Node/system logs** | Via the node's logging agent |

The **Kubernetes audit log** is your kube-side Cloud Audit Log: `exec` into pods, secret reads, RBAC changes, pod creation — attributed to the mapped identity.

## The Pod → Metadata Problem

Same as EKS/AKS: on **Standard** node pools, a pod that can reach the **metadata server** (`169.254.169.254` / `metadata.google.internal`) can steal the **node's service account** token — usually the Compute default SA (often broad), and a classic GKE escalation.

> 🔴 **GKE Workload Identity + Metadata Concealment** block pod access to the node SA. Use them so pods never need node creds. Autopilot enforces this. See **GCP → Compute Engine** (metadata) and **GCP → Playbooks → Metadata SSRF to SA Token Theft**.

## How to Identify GKE in Evidence

- **Resource name:** `//container.googleapis.com/projects/<p>/locations/<l>/clusters/<name>`.
- **Nodes:** Compute Engine VMs in a Google-managed node-pool instance group.
- **Admin Activity:** `container.clusters.create/update`, `getCredentials`.
- **Kube audit:** Cloud Logging `resource.type="k8s_cluster"`.

## Common Operations You Will See

| Operation | Where | 🔴 |
|-----------|-------|----|
| `container.clusters.getCredentials` | Cloud Audit Logs | Cluster credential grab |
| `container.clusters.update` | Cloud Audit Logs | Disable audit / enable legacy metadata |
| `create pod` / `create deployment` | Kube audit | 🔴 Attacker running a container (mining/foothold) |
| `exec`/`attach` into a pod | Kube audit | Hands-on-keyboard |
| `get secrets` | Kube audit | Credential access |
| `create clusterrolebinding` | Kube audit | RBAC escalation |
| Workload Identity token use | Cloud Audit Logs | Pod assumes a GCP SA |

## Cross-Provider Equivalent

| Google Cloud | AWS | Microsoft |
|--------------|-----|-----------|
| GKE | EKS | AKS |
| Workload Identity | IRSA / Pod Identity | Workload Identity |
| IAM + K8s RBAC | aws-auth / access entries | Entra + K8s RBAC |
| Kube audit logs | EKS control-plane audit | kube-audit |
| `getCredentials` | EKS get-token / update-kubeconfig | `listClusterAdminCredential` |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Cluster** | Control plane + nodes (one GKE resource) |
| **Node pool** | A group of identical nodes |
| **Node** | A Compute Engine VM running pods; has a kubelet |
| **Pod** | The smallest unit — 1+ containers |
| **Namespace** | A logical partition of a cluster |
| **Autopilot / Standard** | Google-managed nodes vs your nodes |
| **Workload Identity** | Pod-to-GCP-SA federation |
| **Metadata Concealment** | Blocks pod→node-SA metadata access |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating a GKE compromise | **GKE → GKE for DFIR** |
| The malicious/crypto-pod scenario | **GKE → Playbooks → Malicious Pod and Cryptomining** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| The pod/node metadata theft | **GCP → Compute Engine** |
| The Workload Identity SA's reach | **GCP → Service Accounts** · **Cloud IAM** |

## Resources

- GKE overview — https://cloud.google.com/kubernetes-engine/docs/concepts/kubernetes-engine-overview
- Cluster concepts — https://cloud.google.com/kubernetes-engine/docs/concepts/cluster-architecture
- GKE audit logging — https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- Workload Identity — https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- GKE hardening guide — https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
