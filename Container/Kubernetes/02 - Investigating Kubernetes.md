# Investigating Kubernetes

The step-by-step field flow for a Kubernetes incident — *what to run first, then next*. You orient to the cluster, enumerate workloads and permissions, then mine the **API server audit log** (the master timeline), snapshot **etcd**, check the **nodes** (kubelet + static pods), and hunt the specific abuses: RBAC escalation, ServiceAccount-token theft, malicious workloads, and the cloud pivot. Read **Kubernetes → Architecture and Components** first for the *why*; this is the *how*.

> 🔴 Order of operations: **orient → enumerate → audit log → etcd → nodes → RBAC/token/workload hunts → cloud pivot.** The audit log is where the whole attacker session lives — get to it early, and on managed clusters (EKS/GKE/AKS) pull it from the cloud provider's logging, not a file.

## Contents

- [Quick Triage](#quick-triage)
- [Step 1 Orient to the Cluster](#step-1-orient-to-the-cluster)
- [Step 2 Enumerate Workloads and Permissions](#step-2-enumerate-workloads-and-permissions)
- [Step 3 Mine the API Server Audit Log](#step-3-mine-the-api-server-audit-log)
- [Step 4 Snapshot etcd](#step-4-snapshot-etcd)
- [Step 5 Check the Nodes and Static Pods](#step-5-check-the-nodes-and-static-pods)
- [Step 6 RBAC Abuse](#step-6-rbac-abuse)
- [Step 7 Service Account Token Theft](#step-7-service-account-token-theft)
- [Step 8 Malicious Workloads](#step-8-malicious-workloads)
- [Step 9 Cloud Pivot](#step-9-cloud-pivot)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Red Flags](#red-flags)
- [Resources](#resources)

## Quick Triage

```bash
# Cluster-wide pod view (odd images, hostPath, privileged)
kubectl get pods -A -o wide

# Recent cluster events
kubectl get events -A --sort-by=.lastTimestamp | tail -40

# Overly-powerful bindings (privilege escalation / takeover)
kubectl get clusterrolebindings -o wide | grep -Ei 'cluster-admin|system:masters'

# Privileged / hostPath / hostNetwork / hostPID pods (escape surface)
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork or .spec.hostPID or (.spec.containers[].securityContext.privileged==true) or (.spec.volumes[]?.hostPath)) | .metadata.namespace+"/"+.metadata.name'
```

## Step 1 Orient to the Cluster

```bash
# What/where is this cluster, and am I on a managed provider?
kubectl cluster-info; kubectl version --short
kubectl get nodes -o wide                 # node OS/runtime; provider labels reveal EKS/GKE/AKS
kubectl config current-context
```

If it's **managed**, the API audit log lives in cloud logging (CloudWatch / Cloud Logging / Azure Monitor) — go there for Step 3. If **self-hosted**, work on the control-plane node.

## Step 2 Enumerate Workloads and Permissions

```bash
# All workload types across all namespaces
kubectl get pods,deploy,ds,statefulset,job,cronjobs -A

# Images in use — flag ones not from your registry
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -Ev '<your-registry>'

# Powerful bindings + admission webhooks (cluster-wide injection surface)
kubectl get clusterrolebindings -o wide | grep -Ei 'cluster-admin|system:masters'
kubectl get validatingwebhookconfigurations mutatingwebhookconfigurations
```

## Step 3 Mine the API Server Audit Log

🔴 The most important artifact — every authenticated API request with `user`, `verb`, `objectRef`, `sourceIPs`, `responseStatus`, `stage`. It reconstructs the whole attacker session.

```bash
# Self-hosted: the audit log on the control-plane node
cat /var/log/kubernetes/audit/audit.log | jq .

# What verbosity was captured? (Metadata / Request / RequestResponse)
cat /etc/kubernetes/audit-policy.yaml 2>/dev/null

# HUNT — exec/attach into pods (interactive attacker access)
jq 'select(.verb=="create" and (.objectRef.subresource=="exec" or .objectRef.subresource=="attach"))' audit.log

# HUNT — secret access
jq 'select(.objectRef.resource=="secrets" and .verb=="get")' audit.log

# HUNT — RBAC changes (privilege grants)
jq 'select(.objectRef.resource | test("roles|rolebindings"))' audit.log

# HUNT — anonymous / unauthenticated access
jq 'select(.user.username=="system:anonymous" or .user.username=="system:unauthenticated")' audit.log

# HUNT — by source IP or user
jq 'select(.sourceIPs[]=="203.0.113.5")' audit.log
```

## Step 4 Snapshot etcd

etcd is the source of truth — all objects, including **Secrets (base64, not encrypted by default)**.

```bash
# Snapshot etcd for offline analysis (from a control-plane node)
ETCDCTL_API=3 etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  snapshot save /evidence/etcd-snapshot.db

# Is encryption-at-rest configured? If not, every Secret is just base64
grep -i encryption-provider /etc/kubernetes/manifests/kube-apiserver.yaml 2>/dev/null
```

🔴 Without an `EncryptionConfiguration`, anyone who reads etcd — or an etcd snapshot/backup — gets **every Secret in the cluster in plaintext**.

## Step 5 Check the Nodes and Static Pods

```bash
# Kubelet config + logs (the node agent)
cat /var/lib/kubelet/config.yaml; journalctl -u kubelet | tail -50

# 🔴 Static pod manifests — the kubelet runs ANY pod dropped here, NO API record
ls -la /etc/kubernetes/manifests/; cat /etc/kubernetes/manifests/*.yaml

# Pod logs on the node + node-level container triage
ls -la /var/log/pods/ /var/log/containers/
crictl ps -a; crictl pods
```

🔴 `/etc/kubernetes/manifests/` is the node-persistence goldmine — a privileged static pod mounting `hostPath: /` gives node-and-cluster compromise with no audit-log trace.

## Step 6 RBAC Abuse

```bash
# What can a subject do? (run as the suspect SA/user)
kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# Who is bound to cluster-admin
kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name+" -> "+([.subjects[]?.kind+"/"+.subjects[]?.name]|join(","))'

# Who can create pods / exec / read secrets (escalation primitives)
kubectl get clusterroles -o json | jq -r '.items[] | select(.rules[]? | (.resources[]? | test("pods|secrets")) and (.verbs[]? | test("create|get|list|\\*"))) | .metadata.name'
```

🔴 Hunt subjects that can `create pods`, `exec`, `impersonate`, create `rolebindings`, or read `secrets` — each is an escalation path. A new binding to `cluster-admin`/`system:masters` near the incident is a takeover.

## Step 7 Service Account Token Theft

```bash
# Pods that auto-mount tokens (broad blast radius if compromised)
kubectl get pods -A -o json | jq -r '.items[] | select(.spec.automountServiceAccountToken != false) | .metadata.namespace+"/"+.metadata.name'

# In audit logs: a SA token used from an unexpected sourceIP (used outside its pod)
jq 'select(.user.username | test("system:serviceaccount")) | {user:.user.username, ip:.sourceIPs, verb:.verb, res:.objectRef.resource}' audit.log
```

🔴 A stolen SA token (mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`) used from **outside its pod's IP**, or a low-privilege SA suddenly doing high-privilege actions, is token theft → intra-cluster lateral movement.

## Step 8 Malicious Workloads

```bash
# Privileged / host-namespace / hostPath pods (escape surface)
kubectl get pods -A -o json | jq -r '.items[] | select((.spec.containers[].securityContext.privileged==true) or .spec.hostPID or .spec.hostNetwork or (.spec.volumes[]?.hostPath)) | .metadata.namespace+"/"+.metadata.name'

# DaemonSets (run on EVERY node - fleet persistence) + CronJobs (scheduled)
kubectl get ds,cronjobs -A

# Admission/mutating webhooks that can inject into every pod
kubectl get mutatingwebhookconfigurations -o yaml | grep -A3 clientConfig
```

## Step 9 Cloud Pivot

Kubernetes compromise often continues in the cloud account:

- **IRSA / Workload Identity** — a pod's SA maps to a cloud IAM role; stealing the token yields cloud credentials.
- **IMDS (169.254.169.254)** — a pod (or SSRF in a pod) reaching node metadata grabs the **node's** cloud role credentials. 🔴

```bash
# From a suspect pod's perspective, can it reach IMDS?
kubectl exec <pod> -- curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null
```

🔴 A pod reaching IMDS, or a workload-identity token used in the cloud control plane, means the incident has pivoted out of the cluster — hand off to cloud IR and rotate the node/pod IAM roles at the provider.

## Getting Max Value

- **Audit log first** — it's the master timeline; on managed clusters pull it from cloud logging.
- **Snapshot etcd** early (it holds every secret) and check encryption-at-rest.
- **Never skip static pods** — `/etc/kubernetes/manifests/` persistence leaves no API trace.
- **Follow the token** — a SA token used off-pod is the lateral-movement mechanism; correlate sourceIPs in the audit log.
- **Flag the cloud pivot** — IRSA/IMDS turns a cluster breach into a cloud-account breach; rotate at the provider.

## Correlate With

| To go deeper on… | Pivot to |
|------------------|----------|
| How the cluster/components work | **Kubernetes → Architecture and Components** |
| A single node's container | **Container Fundamentals**, `crictl` (runtime) |
| A pod that broke out to the node | **Escapes and Privilege Abuse** |
| Runtime behavioral detection in pods | **Runtime Detection and Logging** |
| The cloud-account side of the pivot | **Linux → Enterprise Management and Baseline** (16, IMDS) |
| Proper acquisition (etcd, audit, node) | **Evidence Collection** |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `exec`/`attach` into pods from odd sourceIPs | Interactive attacker access |
| New binding to `cluster-admin` / `system:masters` | Cluster takeover |
| Anonymous/unauthenticated API access | Misconfigured API server |
| SA token used from outside its pod | Token theft → lateral movement |
| Privileged / hostPath / hostPID pod | Escape to node |
| Static pod in `/etc/kubernetes/manifests/` | Node persistence, no API record |
| Mutating webhook injecting into pods | Cluster-wide backdoor |
| etcd unencrypted / snapshot exfiltrated | All secrets exposed |
| Pod reaching IMDS (169.254.169.254) | Cloud-credential theft pivot |

## Resources

- Kubernetes auditing — https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- `etcdctl` snapshot — https://etcd.io/docs/latest/op-guide/recovery/
- MITRE ATT&CK Containers — https://attack.mitre.org/matrices/enterprise/containers/
