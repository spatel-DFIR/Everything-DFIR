# What is EKS?

**EKS (Elastic Kubernetes Service)** is AWS's **managed Kubernetes** — AWS runs the Kubernetes control plane; you run workloads on **EC2 nodes** or **Fargate**. It brings *two* identity and audit worlds together: **Kubernetes RBAC + audit logs** and **AWS IAM + CloudTrail**. Understanding the bridge between them — and the Kubernetes building blocks — is the whole game.

This note first nails the **Kubernetes fundamentals** (cluster / node group / node / pod — what they are and how they fit), then the **AWS-specific** side of EKS DFIR. For core Kubernetes forensics (RBAC, etcd, kubelet, container escape), cross-reference the **Container → Kubernetes** notes.

## Contents

- [Kubernetes Building Blocks — Cluster, Node, Pod](#kubernetes-building-blocks--cluster-node-pod)
- [How It Works](#how-it-works)
- [The Two Identity Worlds — and the Bridge](#the-two-identity-worlds--and-the-bridge)
- [IRSA and Pod Identity — Pods That Hold IAM](#irsa-and-pod-identity--pods-that-hold-iam)
- [The Audit Logs — Your Primary Evidence](#the-audit-logs--your-primary-evidence)
- [The Pod → IMDS Problem](#the-pod--imds-problem)
- [How to Identify EKS in Evidence](#how-to-identify-eks-in-evidence)
- [Common Operations You Will See](#common-operations-you-will-see)
- [Cross-Provider Equivalent](#cross-provider-equivalent)
- [Common Use Cases](#common-use-cases)
- [Key Terminology](#key-terminology)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Kubernetes Building Blocks — Cluster, Node, Pod

🔴 The fundamentals every responder must have straight before touching a Kubernetes case. From biggest to smallest:

| Building block | What it is | Analogy |
|----------------|-----------|---------|
| **Cluster** | The whole Kubernetes system: a **control plane** + all the nodes. One EKS resource = one cluster. | The whole datacenter |
| **Node group** | A group of identical **nodes** managed together (same instance type/config). An EKS cluster has 0+ managed node groups (or Fargate profiles). | A rack of identical servers |
| **Node** | A single **machine** that runs workloads. Has a **kubelet** (agent) + container runtime. In EKS, nodes are **EC2 instances** (or serverless **Fargate** micro-VMs). | One server |
| **Pod** | The smallest deployable unit: **one or more containers** that share a network/storage context. Pods run **on** nodes. | An app instance |
| **Container** | The running image (your code + deps) inside a pod. | A process |

**How they assemble into a cluster:**

```
Cluster
├── Control plane (AWS-managed: API server, etcd, scheduler)   ← you get its AUDIT LOGS
└── Node group(s)  /  Fargate profile(s)
    └── Node (an EC2 instance, runs a kubelet)   |  Fargate = one micro-VM per pod
        └── Pod (scheduled onto the node)
            └── Container(s) (your workload)
```

- You talk to the cluster through the **API server** (via `kubectl` or the EKS API). Every `kubectl` action = a Kubernetes API call → the **audit log**.
- The **scheduler** decides which node a pod runs on. An attacker who can **create a pod** chooses the image and can request privileges/host access.
- **Namespaces** partition a cluster logically (e.g. `kube-system`, `default`, app namespaces).

> 🔴 Why this matters on a case: "a new pod appeared" means an attacker got the cluster to **run their container** (often mining or a foothold); "a node was reached" often means they escaped a pod onto the **EC2 host** (and can steal the node role via IMDS); "the cluster was compromised" means the **API/control-plane** access was abused. Different blast radius, different evidence — see **EKS → Playbooks → Malicious Pod and Cryptomining**.

## How It Works

```
EKS control plane (AWS-managed API server + etcd)
   ├── Nodes: EC2 node groups  OR  Fargate  (run your pods)
   ├── Auth: IAM identity → mapped to Kubernetes RBAC (aws-auth / access entries)
   ├── Workload identity: IRSA / EKS Pod Identity → pods get IAM roles
   └── Audit: control-plane logs → CloudWatch Logs
```

- The **control plane** (API server, etcd, scheduler) is AWS-managed; you don't get shell on it — you get its **audit logs**.
- **Nodes** are yours (EC2) or serverless (Fargate); pods run there.
- Access is a **two-step**: authenticate with **IAM**, then authorize with **Kubernetes RBAC**.

## The Two Identity Worlds — and the Bridge

This is the concept that trips everyone up:

| World | Who/what | Controls | Logged in |
|-------|----------|----------|-----------|
| **AWS IAM** | Users/roles calling the AWS API and authenticating to the cluster | AWS actions + *who can reach the cluster* | CloudTrail |
| **Kubernetes RBAC** | Subjects acting *inside* the cluster | What you can do to pods/secrets/etc. | EKS **audit logs** |

**The bridge** = the mapping of an IAM identity to a Kubernetes group/role:

- Legacy: the **`aws-auth` ConfigMap** (maps IAM ARNs → K8s users/groups).
- Newer: **EKS Access Entries** (`CreateAccessEntry` / access policies) — an AWS-API way to grant cluster access.

> 🔴 **Editing `aws-auth` / creating an access entry that grants `system:masters` is cluster-admin persistence.** It's the EKS equivalent of `AttachUserPolicy AdministratorAccess`. Watch both the ConfigMap (audit logs) and the access-entry API (CloudTrail).

## IRSA and Pod Identity — Pods That Hold IAM

Pods get AWS permissions two ways — both mean **a pod carries an IAM role**:

| Mechanism | How | 🔴 Risk |
|-----------|-----|---------|
| **IRSA** (IAM Roles for Service Accounts) | An OIDC-federated service account assumes an IAM role | Over-broad role, or a **loose OIDC trust** an outside pod can abuse |
| **EKS Pod Identity** | An agent hands roles to pods (newer, simpler) | Over-broad association |

> 🔴 A compromised pod with IRSA gets that role's `ASIA` creds — investigate what the role could reach (its AWS blast radius), just like a container task role. A **too-permissive IRSA trust policy** (wrong `sub`/audience conditions) lets the wrong pod assume the role.

## The Audit Logs — Your Primary Evidence

EKS **control-plane logging is off by default.** 🔴 Turn on the **audit** and **authenticator** logs — they are the single most important EKS evidence:

| Log type | Contains |
|----------|----------|
| **audit** | Every Kubernetes API call: who, verb, resource, decision (`allow`/`forbid`) |
| **authenticator** | IAM→Kubernetes identity resolution (the bridge in action) |
| **api / controllerManager / scheduler** | Control-plane component logs |

The **audit log** is your kube-side CloudTrail: it shows `exec` into pods, secret reads, RBAC changes, and privilege use — attributed to the mapped identity.

## The Pod → IMDS Problem

Same as ECS/EC2: on **EC2 node groups**, a pod that can reach **`169.254.169.254`** can steal the **node instance role** — usually far more powerful than the pod's own role, and a classic EKS escalation.

> 🔴 **Block pod access to the node IMDS** (IMDSv2 + hop limit 1, or a network policy denying `169.254.169.254`). Prefer **IRSA/Pod Identity** so pods never need node creds. Fargate pods have no node IMDS.

## How to Identify EKS in Evidence

- **`eventSource`:** `eks.amazonaws.com` (cluster API); `sts.amazonaws.com` for IRSA `AssumeRoleWithWebIdentity`.
- **ARNs:** `arn:aws:eks:<region>:<acct>:cluster/<name>`.
- **Audit logs:** CloudWatch group `/aws/eks/<cluster>/cluster`.
- **IRSA sessions:** `AssumeRoleWithWebIdentity` with the cluster's OIDC provider; sessions named per service account.

## Common Operations You Will See

| Operation | Where | What it does | Watch? |
|-----------|-------|--------------|--------|
| `CreateCluster` / `UpdateClusterConfig` | CloudTrail | Cluster lifecycle/config | 🔴 disabling audit logging |
| `CreateAccessEntry` / `AssociateAccessPolicy` | CloudTrail | Grant IAM→cluster access | 🔴 granting cluster-admin |
| `aws-auth` ConfigMap edit | Audit log | Map IAM→RBAC | 🔴 self-grant `system:masters` |
| `exec` / `attach` into a pod | Audit log | Shell in a container | 🔴 hands-on-keyboard |
| `get secrets` | Audit log | Read Kubernetes secrets | 🔴 credential access |
| `create clusterrolebinding` | Audit log | RBAC escalation | 🔴 privesc |
| `AssumeRoleWithWebIdentity` (IRSA) | CloudTrail | Pod assumes an IAM role | Normal — 🔴 unexpected subject |

## Cross-Provider Equivalent

| AWS | Azure | Google Cloud |
|-----|-------|--------------|
| EKS | AKS | GKE |
| IRSA / Pod Identity | Workload Identity (AKS) | Workload Identity (GKE) |
| aws-auth / access entries | AKS Azure AD integration | GKE IAM + RBAC |
| Control-plane audit logs | AKS diagnostic logs | GKE audit logs |

## Common Use Cases

Your "normal":

- **Microservices platforms** at scale.
- **Regulated/hybrid** Kubernetes with AWS integration.
- **ML/batch** on Kubernetes.

## Key Terminology

| Term | Meaning |
|------|---------|
| **Cluster** | Control plane + nodes (one EKS resource) |
| **Control plane** | The AWS-managed Kubernetes API/etcd |
| **Node group / Fargate profile** | A group of identical nodes / serverless pods — where pods run |
| **Node** | An EC2 instance (or Fargate micro-VM) running pods; has a kubelet |
| **Pod** | The smallest unit — 1+ containers sharing a network/storage context |
| **Namespace** | A logical partition of a cluster |
| **aws-auth ConfigMap** | Legacy IAM→RBAC mapping |
| **Access entry** | AWS-API IAM→cluster access grant |
| **IRSA** | IAM Roles for Service Accounts (OIDC) |
| **EKS Pod Identity** | Newer pod-to-IAM mechanism |
| **RBAC** | Kubernetes' own authorization |
| **Audit log** | Kubernetes API-call log |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| Investigating an EKS compromise | **EKS → EKS for DFIR** |
| The malicious/crypto-pod scenario | **EKS → Playbooks → Malicious Pod and Cryptomining** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| The pod/node IMDS theft | **AWS → Compute → EC2** |
| The IRSA role's AWS reach | **AWS → Identity & Access → IAM / STS** |
| Serverless nodes | **AWS → Serverless & Containers → Fargate** |

## Resources

- What is EKS — https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html
- Control-plane logging — https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- IAM roles for service accounts (IRSA) — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- Cluster access (access entries / aws-auth) — https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html
- EKS best practices — security — https://aws.github.io/aws-eks-best-practices/security/docs/
