# What is AKS?

**AKS (Azure Kubernetes Service)** is Azure's **managed Kubernetes** — Azure runs the Kubernetes control plane; you run containerized workloads on **nodes**. Like EKS, it brings **two identity and audit worlds** together: **Kubernetes RBAC + audit logs** and **Entra + Azure RBAC + Activity Log**. Understanding the bridge between them — and the Kubernetes building blocks — is the whole game.

This note first nails the **Kubernetes fundamentals** (cluster / node pool / node / pod — what they are and how they fit), then the **AKS-specific** DFIR. For core Kubernetes forensics, cross-reference the **Container → Kubernetes** notes.

## Contents

- [Kubernetes Building Blocks — Cluster, Node, Pod](#kubernetes-building-blocks--cluster-node-pod)
- [How It Works](#how-it-works)
- [The Two Identity Worlds — and the Bridge](#the-two-identity-worlds--and-the-bridge)
- [Workload Identity — Pods That Hold Azure Rights](#workload-identity--pods-that-hold-azure-rights)
- [The Audit Logs — Your Primary Evidence](#the-audit-logs--your-primary-evidence)
- [The Pod → IMDS Problem](#the-pod--imds-problem)
- [How to Identify AKS in Evidence](#how-to-identify-aks-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Kubernetes Building Blocks — Cluster, Node, Pod

🔴 The fundamentals every responder must have straight before touching a Kubernetes case. From biggest to smallest:

| Building block | What it is | Analogy |
|----------------|-----------|---------|
| **Cluster** | The whole Kubernetes system: a **control plane** + all the nodes. One AKS resource = one cluster. | The whole datacenter |
| **Node pool** | A group of identical **nodes** managed together (same VM size/config). AKS has 1+ node pools. | A rack of identical servers |
| **Node** | A single **VM** that runs workloads. Has a **kubelet** (agent) + container runtime. In AKS, nodes are Azure VMs (in a managed resource group). | One server |
| **Pod** | The smallest deployable unit: **one or more containers** that share a network/storage context. Pods run **on** nodes. | An app instance |
| **Container** | The running image (your code + deps) inside a pod. | A process |

**How they assemble into a cluster:**

```
Cluster
├── Control plane (Azure-managed: API server, etcd, scheduler)   ← you get its AUDIT LOGS
└── Node pool(s)
    └── Node (an Azure VM, runs a kubelet)
        └── Pod (scheduled onto the node)
            └── Container(s) (your workload)
```

- You talk to the cluster through the **API server** (via `kubectl`). Every `kubectl` action = a Kubernetes API call → the **audit log**.
- The **scheduler** decides which node a pod runs on. An attacker who can **create a pod** chooses the image and can request privileges/host access.
- **Namespaces** partition a cluster logically (e.g. `kube-system`, `default`, app namespaces).

> 🔴 Why this matters on a case: "a new pod appeared" means an attacker got the cluster to **run their container** (often mining or a foothold); "a node was reached" often means they escaped a pod onto the **VM**; "the cluster was compromised" means the **API/control plane** access was abused. Different blast radius, different evidence.

## How It Works

```
AKS control plane (Azure-managed API server + etcd)
   ├── Node pools: Azure VMs (in a managed "MC_" resource group) that run your pods
   ├── Auth: Entra identity → mapped to Kubernetes RBAC (Entra integration / local accounts)
   ├── Workload identity: pods federate to a managed identity / Entra app for Azure rights
   └── Audit: control-plane logs → Azure Monitor / Log Analytics
```

- The **control plane** is Azure-managed; you don't shell into it — you get its **audit logs**.
- **Nodes** are Azure VMs you (partly) own; pods run there.
- Access is a **two-step**: authenticate with **Entra**, then authorize with **Kubernetes RBAC**.

## The Two Identity Worlds — and the Bridge

The concept that trips everyone up (same as EKS):

| World | Who/what | Controls | Logged in |
|-------|----------|----------|-----------|
| **Entra + Azure RBAC** | Identities calling the Azure API + authenticating to the cluster | Azure actions + *who can reach the cluster* | **Activity Log** |
| **Kubernetes RBAC** | Subjects acting *inside* the cluster | What you can do to pods/secrets/etc. | **AKS audit logs** |

**The bridge** = how an Entra identity maps to Kubernetes permissions:

- **Entra + Kubernetes RBAC** integration (recommended): Entra users/groups → `ClusterRoleBinding`/`RoleBinding`.
- **Azure RBAC for Kubernetes Authorization**: Azure roles (e.g. *AKS RBAC Cluster Admin*) grant in-cluster access — an **Azure** role that gives **cluster** power.
- 🔴 **Local accounts / the admin kubeconfig** (`--admin`): a static cluster-admin credential that **bypasses Entra entirely**. Grabbing it (`listClusterAdminCredential`) is full cluster takeover.

> 🔴 **`Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action`** in the Activity Log = someone pulled the **admin kubeconfig** — cluster-admin, no Entra, no MFA. Top-tier red flag. Disable local accounts to remove it.

## Workload Identity — Pods That Hold Azure Rights

Pods get Azure permissions via **Workload Identity** (OIDC federation): a Kubernetes service account federates to an **Entra app / managed identity**, so the pod gets Azure tokens.

> 🔴 A compromised pod with Workload Identity gets that identity's Azure token → investigate its **Azure RBAC** reach (Key Vault? storage?), just like a stolen managed identity. A **loose federation** (wrong subject/audience) lets the wrong pod assume the identity.

## The Audit Logs — Your Primary Evidence

🔴 AKS control-plane logging is **off by default.** Turn on the **kube-audit** category — it's the single most important AKS evidence:

| Log category | Contains |
|--------------|----------|
| **kube-audit** | Every Kubernetes API call: who, verb, resource, decision |
| **kube-audit-admin** | Same, minus noisy read events (lighter) |
| **kube-apiserver / kube-controller-manager / cluster-autoscaler** | Control-plane component logs |
| **guard** | Entra ↔ Kubernetes auth (the bridge in action) |

The **kube-audit** log is your kube-side Activity Log: it shows `exec` into pods, secret reads, RBAC changes, and pod creation — attributed to the mapped identity.

## The Pod → IMDS Problem

Same as EKS/VMs: on standard node pools, a pod that can reach **`169.254.169.254`** can steal the **node's managed identity** — usually broader than the pod's own rights, and a classic AKS escalation.

> 🔴 **Block pod access to the node IMDS** and use **Workload Identity** so pods never need node creds. See **Azure → Managed Identities**.

## How to Identify AKS in Evidence

- **Resource ID:** `.../providers/Microsoft.ContainerService/managedClusters/<name>`.
- **Nodes:** Azure VMs in a **`MC_<rg>_<cluster>_<region>`** managed resource group.
- **Activity Log:** `Microsoft.ContainerService/managedClusters/*`.
- **Audit logs:** Log Analytics `AzureDiagnostics | where Category has "kube-audit"`.

## Common Operations You Will See

| Operation | Where | 🔴 Why |
|-----------|-------|--------|
| `listClusterAdminCredential/action` | Activity Log | Full cluster-admin kubeconfig grab |
| `managedClusters/write` | Activity Log | Cluster config change (disable audit, enable local accounts) |
| `create pod` / `create deployment` | kube-audit | 🔴 Attacker running a container (mining/foothold) |
| `exec`/`attach` into a pod | kube-audit | Hands-on-keyboard |
| `get secrets` | kube-audit | Credential access |
| `create clusterrolebinding` | kube-audit | RBAC escalation |
| Workload Identity token federation | Entra sign-in | Pod assumes Azure identity |

## Cross-Provider Equivalent

| Microsoft | AWS | Google Cloud |
|-----------|-----|--------------|
| AKS | EKS | GKE |
| Workload Identity | IRSA / Pod Identity | Workload Identity |
| Entra + K8s RBAC / local accounts | aws-auth / access entries | GKE IAM + RBAC |
| kube-audit logs | EKS control-plane audit | GKE audit logs |
| `listClusterAdminCredential` | EKS admin access | GKE get-credentials |

## Key Terminology

| Term | Meaning |
|------|---------|
| **Cluster** | Control plane + nodes (one AKS resource) |
| **Node pool** | A group of identical nodes |
| **Node** | A VM running pods (has a kubelet) |
| **Pod** | The smallest unit — 1+ containers |
| **Namespace** | A logical partition of a cluster |
| **kube-audit** | The Kubernetes API-call log |
| **Workload Identity** | Pod-to-Entra federation |
| **Local accounts / admin kubeconfig** | Entra-bypassing cluster-admin creds |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating an AKS compromise | **AKS → AKS for DFIR** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| The pod/node IMDS theft | **Azure → Managed Identities** |
| The workload identity's Azure reach | **Azure → Azure RBAC** · **Key Vault** |
| The malicious-pod scenario | **AKS → Playbooks → Malicious Pod and Cryptomining** |

## Resources

- What is AKS — https://learn.microsoft.com/azure/aks/what-is-aks
- Kubernetes core concepts — https://learn.microsoft.com/azure/aks/concepts-clusters-workloads
- AKS control-plane/audit logs — https://learn.microsoft.com/azure/aks/monitor-aks
- Workload Identity — https://learn.microsoft.com/azure/aks/workload-identity-overview
- AKS security best practices — https://learn.microsoft.com/azure/aks/operator-best-practices-cluster-security
