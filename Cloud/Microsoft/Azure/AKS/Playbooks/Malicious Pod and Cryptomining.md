# Playbook — Malicious Pod and Cryptomining

The most common Kubernetes incident: an attacker gets cluster access (exposed API, stolen kubeconfig, a compromised CI token, or a vulnerable app) and **deploys a pod** — usually a **cryptominer**, sometimes a foothold that escapes to the node and pivots into Azure. This playbook finds the pod, traces how it got there, contains the cluster, and stops the pivot.

> **Tier 1 (single-service).** AKS-focused; pulls in Activity Log + Managed Identities. Read **Azure → AKS for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [How Did the Pod Get There?](#how-did-the-pod-get-there)
- [Did It Pivot Into Azure?](#did-it-pivot-into-azure)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **Defender for Containers** | Crypto-mining container / suspicious pod alert |
| **Cost/perf** | Node CPU pinned; cluster autoscaling up unexpectedly |
| **kube-audit** | `create pod` with an unknown image / privileged spec |
| **Activity Log** | `listClusterAdminCredential` before the pod appeared |

## Hypothesis

An attacker deployed one or more malicious pods (likely mining). Establish how they reached the cluster, what the pod does, whether it escaped to the node or pivoted into Azure via a workload/node identity, and eradicate.

## Step-by-Step Investigation

**1. Find the pod(s).**

```kql
AzureDiagnostics
| where Category == "kube-audit"
| extend d = parse_json(log_s)
| where d.verb == "create" and d.objectRef.resource == "pods"
| project TimeGenerated, user=d.user.username, ns=d.objectRef.namespace, name=d.objectRef.name, image=d.requestObject.spec.containers
```
Note the **image** (mining pool/known-bad?), **namespace**, **privileged/hostPath**, and the **user** that created it.

**2. Confirm mining.** Node CPU spike; pod connecting to a **mining pool** (NSG flow logs / Defender); the image name.

**3. Check privileges + host access.** `privileged: true`, `hostPID`, `hostNetwork`, or `hostPath` mounts = node-escape intent.

## How Did the Pod Get There?

| Access vector | Evidence |
|---------------|----------|
| **Admin kubeconfig grabbed** | Activity Log `listClusterAdminCredential` |
| **Exposed/insecure API** | Public API server + weak auth |
| **Compromised CI/CD token** | A pipeline SP creating workloads |
| **RBAC escalation** | New `clusterrolebinding` before the pod |
| **Vulnerable app in a pod** | RCE → `kubectl`/API from inside |

## Did It Pivot Into Azure?

🔴 The dangerous escalation — check whether the pod reached an identity:

- Pod → **node IMDS** (`169.254.169.254`) → **node managed identity** token.
- Pod using **Workload Identity** → its Entra app / managed identity.
- Then Azure RBAC actions (Key Vault reads, storage, role grants) in the **Activity Log** by that identity.

See **Azure → Managed Identities**.

## Decision Points

| Question | If yes → |
|----------|----------|
| Privileged / hostPath pod? | Assume node compromise — snapshot + rebuild the node |
| Pivoted into Azure? | Run **Managed Identity Theft**; rotate reachable secrets |
| Admin kubeconfig grabbed? | Full cluster takeover — rotate certs, disable local accounts |
| Multiple clusters/nodes? | Broader campaign — sweep the subscription |

## Contain

```bash
kubectl get pod <pod> -o yaml > evidence-pod.yaml     # capture first
kubectl delete pod <pod>                              # or the deployment
kubectl cordon <node> && kubectl drain <node>         # isolate the node
```
- Rotate cluster credentials; **disable local accounts**.
- NSG/network-policy to block mining-pool egress + isolate the cluster.

## Eradicate

- Delete all malicious pods/deployments/daemonsets (miners often use daemonsets to spread).
- Remove attacker RBAC bindings + rogue service accounts.
- Rebuild compromised **nodes** from clean images (node escape is easy to miss).
- Rotate any secrets a stolen workload/node identity could reach.

## Recover

- Enable **Defender for Containers** + kube-audit logging.
- Enforce **Pod Security / admission control** (no privileged, no hostPath).
- Use **Workload Identity**; block pod→node IMDS.
- Preserve: pod manifests, kube-audit trail, the access-vector evidence, and any Azure pivot activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| New pod pulling a mining image | Cryptomining |
| Privileged / hostPath / hostNetwork pod | Node-escape setup |
| `listClusterAdminCredential` before the pod | Cluster takeover |
| New cluster-admin rolebinding | RBAC escalation |
| Pod reaching node IMDS | Identity theft pivot |
| Node CPU pinned / autoscaler spiking | Mining impact |

## References

- Related notes: **AKS for DFIR**, **Managed Identities**, **Activity Log**, **NSG Flow Logs**, **Defender for Cloud**
- Defender for Containers — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction
- AKS security best practices — https://learn.microsoft.com/azure/aks/operator-best-practices-cluster-security
- MITRE ATT&CK: T1610 Deploy Container / T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1496/
