# AKS for DFIR

An AKS compromise spans two worlds: the Kubernetes API (pods, RBAC, secrets) and Azure (the cluster resource, node VMs, workload identities). This note is how you work both — find the malicious pod or RBAC change, trace the identity, and contain the cluster.

New to the service? Read **What is AKS** first — especially the cluster/node/pod fundamentals.

## Contents

- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate on the Platform](#investigate-on-the-platform)
- [The Two-Sided Timeline](#the-two-sided-timeline)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Evidence It Produces

| Source | What's there | Needs |
|--------|--------------|-------|
| **Activity Log** | Cluster ops: `listClusterAdminCredential`, `managedClusters/write` | Default on |
| **kube-audit** (`AzureDiagnostics`) | Every K8s API call (pods, exec, secrets, RBAC) | 🔴 Enable diagnostic logging |
| **Container Insights** (Azure Monitor) | Container stdout/stderr, pod/node inventory, perf metrics (`ContainerLog`/`ContainerLogV2`, `KubePodInventory`, `KubeEvents`) | 🔴 Not on by default — enable the monitoring add-on |
| **Dapr sidecar logs** (`daprd` container) | Service-invocation, pub/sub, and binding calls made *through* Dapr — a second data plane distinct from kube-audit | Only if Dapr is deployed |
| **Entra sign-in / MI logs** | Workload-identity token use | — |
| **Defender for Containers** | Crypto-pod / exec / API-abuse alerts | If enabled |
| **Node VM / guest** | Node-level forensics | Snapshot the node VM |

## Collect It

**Confirm audit logging is on; pull cluster ops:**

```bash
az monitor activity-log list --resource-id <aks-resource-id> --offset 30d \
  --query "[?contains(operationName.value,'listClusterAdminCredential') || contains(operationName.value,'managedClusters/write')]"
```

**Kubernetes API activity (kube-audit):**

```kql
AzureDiagnostics
| where Category == "kube-audit"
| extend d = parse_json(log_s)
| project TimeGenerated, user=d.user.username, verb=d.verb, resource=d.objectRef.resource, name=d.objectRef.name, ns=d.objectRef.namespace, decision=d.annotations.["authorization.k8s.io/decision"]
| order by TimeGenerated asc
```

**Container Insights — is it on, and what did a pod log/do:**

```bash
# Is the monitoring add-on enabled?
az aks show --name <c> --resource-group <rg> --query "addonProfiles.omsagent"
```

```kql
// Container stdout/stderr for a suspect pod
ContainerLogV2
| where PodName == "<pod>"
| order by TimeGenerated asc

// Pod/container inventory (image, node, namespace) at time of interest
KubePodInventory
| where TimeGenerated between (datetime(<start>) .. datetime(<end>))
| project TimeGenerated, Name, Namespace, ContainerImage, Node = ComputerName
```

**Dapr sidecar logs — service-invocation/pub-sub calls the `daprd` container made:**

```bash
kubectl logs <pod> -c daprd -n <namespace>          # sidecar's own log stream
```

```kql
// If Dapr's log output is also routed to Container Insights
ContainerLogV2
| where ContainerName == "daprd"
| order by TimeGenerated asc
```

> **Console:** the cluster → **Diagnostic settings** (is kube-audit exported?); **Insights** for workload view (Container Insights); `az aks get-credentials` + `kubectl get pods,clusterrolebindings -A` for current state (read-only).

## Investigate on the Platform

| Step | Do this |
|------|---------|
| 1. Which layer? | Cluster/API abuse, a rogue **pod**, a **node** escape, or a **workload-identity** pivot? |
| 2. Cluster access | Was the admin kubeconfig pulled (`listClusterAdminCredential`)? Local accounts on? |
| 3. Rogue pods | New pods/deployments — image, namespace, privileges, host mounts |
| 4. RBAC changes | New `clusterrolebindings` granting cluster-admin |
| 5. Secrets read | `get secrets` in kube-audit |
| 6. Identity pivot | Workload identity / node managed identity used against Azure? |
| 7. App-layer trace (if Dapr) | Did the workload use Dapr for service invocation/pub-sub? Check the `daprd` sidecar log alongside kube-audit — it's a separate data plane kube-audit won't show |

## The Two-Sided Timeline

Reconstruct across both logs — this is the AKS-specific skill:

```
Activity Log:  listClusterAdminCredential  →  (attacker now has cluster-admin, no Entra)
kube-audit:    create clusterrolebinding    →  create pod (miner image, privileged, hostPath)
kube-audit:    exec into pod / get secrets   →  pod reaches node IMDS
Entra/MI:      node/workload identity token   →  Azure RBAC actions (Key Vault, storage)
```

## Hunt at Scale

**Admin kubeconfig grabs:**

```kql
AzureActivity
| where OperationNameValue has "listClusterAdminCredential"
| project TimeGenerated, Caller, CallerIpAddress, _ResourceId
```

**New pods with suspicious images / privileges (kube-audit):**

```kql
AzureDiagnostics
| where Category == "kube-audit"
| extend d = parse_json(log_s)
| where d.verb == "create" and d.objectRef.resource == "pods"
| project TimeGenerated, user=d.user.username, ns=d.objectRef.namespace, name=d.objectRef.name, req=d.requestObject
```

**RBAC escalation (cluster-admin bindings):**

```kql
AzureDiagnostics
| where Category == "kube-audit"
| extend d = parse_json(log_s)
| where d.verb == "create" and d.objectRef.resource == "clusterrolebindings"
| project TimeGenerated, user=d.user.username, name=d.objectRef.name
```

## Respond

| Goal | Action |
|------|--------|
| Kill the rogue workload | `kubectl delete pod/deployment <name>` (capture manifest first) |
| Cut cluster access | Rotate cluster certs; **disable local accounts**; remove rogue rolebindings |
| Contain the node | Cordon/drain; snapshot the node VM for forensics |
| Kill the identity pivot | Treat the workload/node managed identity as stolen; rotate downstream secrets |
| Isolate | Network policy / NSG to contain the cluster |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable kube-audit diagnostic logging** → Sentinel | The primary AKS evidence |
| **Enable Container Insights** (the monitoring add-on) | Container stdout/stderr, pod inventory, and events — otherwise unavailable |
| **Disable local accounts**; use **Entra + K8s RBAC** | Removes the Entra-bypass admin creds |
| **Defender for Containers** | Crypto-pod / exec / API-abuse detection |
| **Workload Identity** + block pod→node IMDS | Pods never hold node creds |
| **Pod Security / admission control** (no privileged, no hostPath) | Stops privileged rogue pods |
| **Private cluster / API allowlist** | Limits API exposure |
| **Alert** on `listClusterAdminCredential`, new cluster-admin bindings, crypto images | Catch takeover/mining |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `listClusterAdminCredential` | Cluster-admin, Entra-bypassing |
| New **privileged** pod / hostPath mount | Foothold / node-escape setup |
| New pod pulling a **mining image** | Cryptomining |
| New `clusterrolebinding` to cluster-admin | RBAC escalation |
| `get secrets` at volume | Credential access |
| Pod reaching `169.254.169.254` | Node identity theft |
| Workload/node identity acting on Azure | Pivot into the subscription |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What AKS is + K8s fundamentals | **AKS → What is** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| The stolen node/workload identity | **Azure → Managed Identities** |
| The control-plane log | **Azure → Activity Log** |
| The malicious-pod scenario | **AKS → Playbooks → Malicious Pod and Cryptomining** |

## Resources

- Monitor AKS / control-plane logs — https://learn.microsoft.com/azure/aks/monitor-aks
- Container Insights for AKS — https://learn.microsoft.com/azure/azure-monitor/containers/container-insights-enable-aks
- Dapr on AKS — https://learn.microsoft.com/azure/aks/dapr
- AKS security best practices — https://learn.microsoft.com/azure/aks/operator-best-practices-cluster-security
- Defender for Containers — https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction
- MITRE ATT&CK: Containers matrix — https://attack.mitre.org/matrices/enterprise/containers/
