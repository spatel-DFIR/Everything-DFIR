# Playbook — Malicious Pod and Cryptomining

The most common Kubernetes incident: an attacker gets cluster access (exposed API, stolen kubeconfig/`getCredentials`, a compromised CI token, or a vulnerable app) and **deploys a pod** — usually a **cryptominer**, sometimes a foothold that escapes to the node and pivots into GCP. This playbook finds the pod, traces how it got there, contains the cluster, and stops the pivot.

> **Tier 1 (single-service).** GKE-focused; pulls in Cloud Audit Logs + Service Accounts. Read **GKE → What is GKE** (cluster/node/pod fundamentals) and **GKE for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [How Did the Pod Get There?](#how-did-the-pod-get-there)
- [Did It Pivot Into GCP?](#did-it-pivot-into-gcp)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **SCC (Container/VM Threat Detection)** | Cryptomining / suspicious binary / reverse shell in a pod |
| **Cost/perf** | Node CPU pinned; cluster autoscaling up unexpectedly; surprise bill |
| **Kube audit** | `create pod` with an unknown image / privileged spec / `system:anonymous` |
| **Cloud Audit Logs** | `getCredentials` before the pod appeared |

## Hypothesis

An attacker deployed one or more malicious pods (likely mining). Establish how they reached the cluster, what the pod does, whether it escaped to the node or pivoted into GCP via a workload/node SA, and eradicate.

## Step-by-Step Investigation

**1. Find the pod(s).** In Logs Explorer (kube audit) or live:

```
resource.type="k8s_cluster"
protoPayload.methodName="io.k8s.core.v1.pods.create"
```
```bash
kubectl get pods -A -o wide     # note image, namespace, node
kubectl get pod <p> -n <ns> -o yaml | grep -iE 'image|privileged|hostPath|hostPID|hostNetwork'
```
Note the **image** (mining pool / known-bad?), **namespace**, **privileged/hostPath**, and the **user** that created it.

**2. Confirm mining.** Node CPU spike (Compute metrics); pod egress to a **mining pool** (VPC Flow Logs / SCC); the image name.

**3. Check privileges + host access.** `privileged: true`, `hostPID`, `hostNetwork`, or `hostPath` mounts = node-escape intent.

## How Did the Pod Get There?

| Access vector | Evidence |
|---------------|----------|
| **Credentials grabbed** | Cloud Audit Logs `container.clusters.getCredentials` |
| **Exposed/public API server** | Public endpoint + weak auth; `system:anonymous` in kube audit |
| **Compromised CI/CD token** | A pipeline SA creating workloads |
| **RBAC escalation** | New `clusterrolebinding` before the pod |
| **Vulnerable app in a pod** | RCE → `kubectl`/API from inside |

## Did It Pivot Into GCP?

🔴 The dangerous escalation — check whether the pod reached a GCP identity:

- Pod → **node metadata** (`169.254.169.254`) → **node service account** token (often the Compute default SA / Editor).
- Pod using **Workload Identity** → its mapped **GCP service account**.
- Then GCP actions (Storage reads, new SA keys, IAM grants) in **Cloud Audit Logs** by that SA.

```sql
SELECT timestamp, protopayload_auditlog.methodName, protopayload_auditlog.requestMetadata.callerIp
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.authenticationInfo.principalEmail LIKE '%-compute@developer.gserviceaccount.com'
ORDER BY timestamp DESC;
```
See **GCP → Playbooks → Metadata SSRF to SA Token Theft** and **Service Accounts**.

## Decision Points

| Question | If yes → |
|----------|----------|
| Privileged / hostPath pod? | Assume **node compromise** — snapshot + rebuild the node VM |
| Pivoted into GCP? | Run **Metadata SSRF / Service Account Key Abuse**; rotate reachable secrets |
| `getCredentials` / `cluster-admin` self-grant? | Full cluster takeover — rotate access, tighten RBAC/IAM |
| Multiple clusters/projects? | Broader campaign — sweep the org |

## Contain

```bash
kubectl get pod <pod> -n <ns> -o yaml > evidence-pod.yaml   # capture first
kubectl delete pod <pod> -n <ns>                            # or the deployment/daemonset
kubectl cordon <node> && kubectl drain <node>               # isolate the node
```
- Remove attacker IAM `container.*` grants + rogue clusterrolebindings.
- Rotate/disable the **node SA / Workload Identity SA** if GCP creds were reachable.
- Firewall/network-policy block on mining-pool egress; isolate the cluster.

## Eradicate

- Delete all malicious pods/deployments/daemonsets (miners often use **daemonsets** to respawn on every node).
- Remove attacker RBAC bindings + rogue Kubernetes service accounts; fix Workload Identity mappings.
- **Rebuild** compromised node VMs from clean images (node escape is easy to miss).
- Rotate any secrets a stolen workload/node SA could reach.

## Recover

- Enable **Workload Identity + Metadata Concealment** (or move to **Autopilot**); block pod→node metadata.
- Enforce **Pod Security / Policy Controller** (no privileged, no hostPath) + **Binary Authorization**.
- Private cluster + master authorized networks; least-privilege node SA.
- Enable **SCC Container Threat Detection** + kube audit logging.
- Preserve: pod manifests, kube-audit trail, access-vector evidence, and any GCP pivot activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| New pod pulling a mining image / unknown registry | Cryptomining |
| Privileged / hostPath / hostNetwork pod | Node-escape setup |
| `system:anonymous` creating resources | Public/unauth API server |
| `getCredentials` before the pod / new `cluster-admin` binding | Cluster takeover / RBAC escalation |
| Pod reaching node metadata | Node SA theft pivot |
| Node CPU pinned / autoscaler spiking | Mining impact |

## References

- Related notes: **GKE for DFIR**, **What is GKE**, **Service Accounts**, **Compute Engine**, **VPC Flow Logs**, **Metadata SSRF to SA Token Theft**
- GKE hardening — https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
- Container Threat Detection — https://cloud.google.com/security-command-center/docs/concepts-container-threat-detection-overview
- MITRE ATT&CK: T1610 Deploy Container / T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1496/
