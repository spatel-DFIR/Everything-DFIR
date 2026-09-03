# GKE for DFIR

A GKE investigation lives in **two log streams at once**: the **Kubernetes audit log** (what happened *inside* the cluster) and **Cloud Audit Logs** (the GCP-side access grants and Workload Identity use). You constantly cross the bridge between Google IAM and Kubernetes RBAC.

New to it? Read **What is GKE** first (cluster/node/pod fundamentals). For core Kubernetes forensics, use the **Container → Kubernetes** notes alongside this.

## Contents

- [Why It Matters to IR](#why-it-matters-to-ir)
- [Evidence It Produces](#evidence-it-produces)
- [Collect It](#collect-it)
- [Investigate — Both Sides of the Bridge](#investigate--both-sides-of-the-bridge)
- [Reading the Audit Log](#reading-the-audit-log)
- [Hunt at Scale](#hunt-at-scale)
- [Respond](#respond)
- [Fix the Misconfig and Harden](#fix-the-misconfig-and-harden)
- [Red Flags](#red-flags)
- [Correlate With](#correlate-with)
- [Resources](#resources)

## Why It Matters to IR

GKE answers **"who reached the cluster, what did they do inside it (exec, read secrets, escalate RBAC, deploy pods), and did a pod's GCP identity get abused?"** Miss either log stream and you miss half the attack.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **Kubernetes audit log** | Every kube API call: subject, verb, resource, decision | ✅ On (routes to Cloud Logging) |
| **Admin Activity (`container.*`)** | Cluster config + `getCredentials` + actor | ✅ On |
| **Workload Identity SA use** | Pod-assumed GCP SA actions | ✅ On (Cloud Audit Logs) |
| **Workload logs** (`k8s_container` resource type) | Container stdout/stderr, distinct from the API-call audit log | ✅ On (routes to Cloud Logging) |
| **Scheduler logs** (`k8s_control_plane_component`, `component="scheduler"`) | Pod-placement decisions — which node a pod landed on and why | ✅ On (routes to Cloud Logging) |
| **Node (Compute Engine) evidence** | Host/container forensics on the node | Snapshot (→ Compute Engine) |
| **SCC Container Threat Detection** | Runtime threat findings | Add-on |

## Collect It

```bash
# Cluster posture: audit logging, Workload Identity, endpoint exposure
gcloud container clusters describe <c> --location=<l> \
  --format='value(loggingConfig,workloadIdentityConfig,privateClusterConfig,masterAuthorizedNetworksConfig)'

# GCP-side: who fetched credentials / changed the cluster
gcloud logging read \
 'protoPayload.methodName:("getCredentials" OR "container.clusters.update")' --freshness=30d

# Kubernetes side (needs cluster access)
kubectl get clusterrolebindings -o wide          # who has cluster-admin?
kubectl get pods -A -o wide                       # unexpected pods/images
kubectl get serviceaccounts -A                    # Workload Identity mappings
```

> **Console:** Kubernetes Engine → cluster → **Security/Logging**; Logging → Logs Explorer (`resource.type="k8s_cluster"`).

## Investigate — Both Sides of the Bridge

| Step | Do this |
|------|---------|
| 1. GCP side | Cloud Audit Logs `container.*`: `getCredentials`, IAM grants of `container.admin`; `clusters.update` disabling audit |
| 2. The bridge | Which Google identity/group maps to which K8s role; any self-grant to `cluster-admin` |
| 3. Kube side | Audit log: `exec`/`attach`, `get secrets`, `create clusterrolebinding`, `create pod` (privileged) |
| 4. Pod identity | Workload Identity SA use — unexpected pods assuming GCP SAs; what those SAs did |
| 5. Node/host | If Standard nodes: pod→node metadata theft; snapshot the node VM (→ Compute Engine) |
| 6. Workload | Malicious images / privileged pods / hostPath mounts (→ Container Kubernetes notes) |

## Reading the Audit Log

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `authenticationInfo.principalEmail` / user | The (mapped) subject | `system:anonymous`; an IAM identity you don't expect |
| `verb` + `objectRef.resource` | What was done to what | `create` on `clusterrolebindings`; `get` on `secrets` |
| `objectRef.subresource` | e.g. `exec` / `attach` | 🔴 shell into a pod |
| `responseStatus.code` | Allowed vs forbidden | Bursts of `403` = RBAC probing |
| `sourceIPs` | Where the call came from | External / new |

## Hunt at Scale

**GCP-side cluster credential grabs + config changes:**

```sql
SELECT timestamp, protopayload_auditlog.authenticationInfo.principalEmail AS who,
       protopayload_auditlog.methodName AS method
FROM `contoso.audit.cloudaudit_googleapis_com_activity`
WHERE protopayload_auditlog.methodName LIKE '%getCredentials%'
   OR protopayload_auditlog.methodName LIKE '%clusters.update%'
ORDER BY timestamp DESC;
```

**Kube audit — pod creation / exec / secret reads (Logs Explorer):**

```
resource.type="k8s_cluster"
protoPayload.methodName=("io.k8s.core.v1.pods.create" OR "io.k8s.core.v1.pods.exec")
```

> **At the very end — SecOps UDM (optional):** land pod-create + getCredentials events to correlate cluster activity across projects. Keep it light.

## Respond

| Goal | Action |
|------|--------|
| Cut attacker cluster access | Remove IAM `container.*` grants; delete malicious clusterrolebindings |
| Kill a malicious/priv pod | `kubectl delete pod`; cordon/drain the node; scale the workload down |
| Kill stolen Workload Identity | Rotate/disable the mapped GCP SA; fix the WI mapping |
| Contain a node | Cordon + isolate + snapshot the Compute Engine node VM |
| Rotate secrets | Any Kubernetes secret the attacker could read |
| Re-enable logging | Turn control-plane/audit logging back on |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable Workload Identity + Metadata Concealment** (or Autopilot) | Pods can't steal the node SA |
| **Private cluster + master authorized networks** | No public control plane |
| **Least-privilege RBAC**; no broad `cluster-admin`; scoped IAM | Limits in-cluster power |
| **Least-privilege node SA** (not default Editor) | Small blast radius on node compromise |
| **Pod Security / Policy Controller** (no privileged/hostPath) | No easy escapes |
| **SCC Container Threat Detection + Binary Authorization** | Runtime detection + trusted images |
| **Alert** on `getCredentials`, audit `exec`/secret-reads/RBAC changes | Catch persistence/privesc live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| `getCredentials` by an unexpected identity | Cluster-access grab |
| New clusterrolebinding to `cluster-admin` | RBAC escalation |
| Audit `exec`/`attach` by an unexpected subject | Hands-on-keyboard |
| Audit `get secrets` at volume | Credential harvesting |
| Pod reaching node metadata (Standard nodes) | Pod→node SA theft |
| Privileged / hostPath pods deployed | Container escape setup |
| `clusters.update` disabling audit logging | Evidence blinded |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What GKE is + the fundamentals + bridge | **GKE → What is GKE** |
| The malicious/crypto-pod scenario | **GKE → Playbooks → Malicious Pod and Cryptomining** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| Pod/node metadata theft | **GCP → Compute Engine** |
| Workload Identity SA reach | **GCP → Service Accounts** · **Cloud IAM** |

## Resources

- GKE audit logging — https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
- Hardening your cluster — https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster
- Workload Identity — https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity
- MITRE ATT&CK: Containers matrix — https://attack.mitre.org/matrices/enterprise/containers/
