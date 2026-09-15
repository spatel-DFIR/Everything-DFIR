# Playbook — Malicious Pod and Cryptomining

The most common Kubernetes incident: an attacker gets cluster access (exposed API server, a stolen/leaked kubeconfig, a compromised CI token, an over-broad access entry, or a vulnerable app in a pod) and **deploys a pod** — usually a **cryptominer**, sometimes a foothold that escapes to the EC2 node and pivots into AWS. This playbook finds the pod, traces how it got there, contains the cluster, and stops the pivot.

> **Tier 1 (single-service).** EKS-focused; pulls in CloudTrail + IAM/STS. Read **EKS → What is EKS** (cluster/node/pod fundamentals) and **EKS for DFIR** first.

## Contents

- [Scenario & Trigger](#scenario--trigger)
- [Hypothesis](#hypothesis)
- [Step-by-Step Investigation](#step-by-step-investigation)
- [How Did the Pod Get There?](#how-did-the-pod-get-there)
- [Did It Pivot Into AWS?](#did-it-pivot-into-aws)
- [Decision Points](#decision-points)
- [Contain](#contain)
- [Eradicate](#eradicate)
- [Recover](#recover)
- [Red Flags](#red-flags)
- [References](#references)

## Scenario & Trigger

| Source | What you see |
|--------|--------------|
| **GuardDuty (EKS Protection / Runtime Monitoring)** | `CryptoCurrency:EC2/BitcoinTool`, `Execution:Kubernetes/...`, malicious-pod / anonymous-access findings |
| **Cost / performance** | Node CPU pinned; cluster autoscaler adding nodes unexpectedly; a surprise EC2 bill |
| **Kubernetes audit log** | `create pod` with an unknown image / privileged spec / `system:anonymous` |
| **CloudTrail** | New `CreateAccessEntry` (admin) or `aws-auth` edit before the pod appeared |

## Hypothesis

An attacker deployed one or more malicious pods (likely mining). Establish how they reached the cluster, what the pod does, whether it escaped to the EC2 node or pivoted into AWS via an IRSA/node role, and eradicate.

## Step-by-Step Investigation

**1. Find the pod(s).** In CloudWatch Logs Insights on the `/aws/eks/<cluster>/cluster` group:

```
fields @timestamp, user.username, objectRef.namespace, objectRef.name, requestObject.spec.containers.0.image
| filter verb = "create" and objectRef.resource = "pods"
| sort @timestamp desc
```
Note the **image** (mining pool / known-bad?), **namespace**, **privileged/hostPath** spec, and the **user** (mapped IAM identity or `system:anonymous`) that created it.

> **Console:** CloudWatch → Log groups → `/aws/eks/<cluster>/cluster` → **Logs Insights**. Live cluster: `kubectl get pods -A -o wide`.

**2. Confirm mining.** Node CPU spike (CloudWatch EC2 metrics); pod egress to a **mining pool** (VPC Flow Logs / GuardDuty); the image name/registry.

**3. Check privileges + host access.** `privileged: true`, `hostPID`, `hostNetwork`, or `hostPath` mounts in the pod spec = **node-escape intent**.

```bash
kubectl get pod <pod> -n <ns> -o yaml | grep -iE 'privileged|hostPath|hostPID|hostNetwork|securityContext'
```

## How Did the Pod Get There?

| Access vector | Evidence |
|---------------|----------|
| **Access entry / `aws-auth` abused** | CloudTrail `CreateAccessEntry`/`AssociateAccessPolicy` (admin); audit-log edit of the `aws-auth` ConfigMap |
| **Exposed/public API server** | `endpointPublicAccess=true` + weak auth; `system:anonymous` in the audit log |
| **Compromised CI/CD token** | An IRSA/pipeline role creating workloads (`AssumeRoleWithWebIdentity` → `create pod`) |
| **RBAC escalation** | New `clusterrolebinding` to a broad role before the pod |
| **Vulnerable app in a pod** | RCE → `kubectl`/API calls from inside the cluster |
| **Leaked kubeconfig / long-term key** | `AKIA` key or stale kubeconfig used from a new IP/geo |

## Did It Pivot Into AWS?

🔴 The dangerous escalation — check whether the pod reached AWS credentials:

- Pod → **node IMDS** (`169.254.169.254`) → the **EC2 node instance role** token (`ASIA…`), usually broader than the pod's own role.
- Pod using **IRSA / EKS Pod Identity** → `AssumeRoleWithWebIdentity` → its own IAM role.
- Then AWS API actions (S3 reads, Secrets Manager, KMS, new IAM users/keys) in **CloudTrail** by that role's `ASIA` session.

```sql
SELECT eventtime, eventname, sourceipaddress, requestparameters
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%assumed-role/<node-or-irsa-role>/%'
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```
See **AWS → 01 IAM & Identities** (tie the `ASIA` session back to the role) and **AWS → Compute → EC2** (node IMDS theft).

## Decision Points

| Question | If yes → |
|----------|----------|
| Privileged / hostPath pod? | Assume **node compromise** — snapshot + rebuild the EC2 node |
| Pivoted into AWS? | Run **IMDS SSRF to Role Theft** / **Leaked Access Key**; rotate reachable secrets |
| Admin access entry / `system:masters` self-grant? | Full cluster takeover — rotate access, tighten entries |
| Multiple clusters/accounts? | Broader campaign — sweep the org (CloudTrail `eks.*` across accounts) |

## Contain

```bash
kubectl get pod <pod> -n <ns> -o yaml > evidence-pod.yaml   # capture first
kubectl delete pod <pod> -n <ns>                            # or the deployment/daemonset
kubectl cordon <node> && kubectl drain <node>               # isolate the EC2 node
```
- Remove rogue **access entries** / fix `aws-auth`; delete malicious `clusterrolebindings`.
- Revoke the **IRSA / node role** sessions (deny by `aws:TokenIssueTime`) if AWS creds were reachable.
- Security-group / network-policy block on mining-pool egress; isolate the node's ENI.

## Eradicate

- Delete all malicious pods/deployments/daemonsets (miners often use **daemonsets** to respawn on every node).
- Remove attacker RBAC bindings + rogue service accounts; tighten the IRSA **OIDC trust** (`sub`/`aud`).
- **Rebuild** compromised EC2 nodes from clean AMIs (node escape is easy to miss).
- Rotate any secrets a stolen IRSA/node role could reach (Secrets Manager, KMS-wrapped data, Kubernetes secrets).

## Recover

- Enable **GuardDuty EKS Protection + Runtime Monitoring** and **control-plane audit + authenticator logs**.
- Enforce **Pod Security Standards** (restricted) / admission control — no privileged, no hostPath.
- Use **IRSA/Pod Identity**; **block pod→node IMDS** (IMDSv2 hop-limit 1 or a network policy denying `169.254.169.254`).
- Make the API endpoint **private** (or tight CIDR allowlist); scope access entries to least privilege.
- Preserve: pod manifests, the kube-audit trail, the access-vector evidence, and any AWS-pivot CloudTrail activity.

## Red Flags

| 🔴 | Meaning |
|----|---------|
| New pod pulling a mining image / from an unknown registry | Cryptomining |
| Privileged / hostPath / hostNetwork pod | Node-escape setup |
| `system:anonymous` creating resources | Public/unauthenticated API server |
| New admin access entry / `system:masters` self-grant | Cluster takeover |
| New cluster-admin `clusterrolebinding` | RBAC escalation |
| Pod reaching `169.254.169.254` (EC2 nodes) | Node IAM role theft pivot |
| `AssumeRoleWithWebIdentity` from an unexpected IRSA subject | Loose OIDC trust abused |
| Node CPU pinned / autoscaler spiking | Mining impact |

## References

- Related notes: **EKS for DFIR**, **What is EKS**, **01 IAM & Identities**, **EC2 for DFIR**, **GuardDuty for DFIR**, **VPC Flow Logs for DFIR**, **Playbooks → IMDS SSRF to Role Theft**
- EKS security best practices — https://aws.github.io/aws-eks-best-practices/security/docs/
- GuardDuty EKS Protection — https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html
- EKS control-plane logging — https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- MITRE ATT&CK: T1610 Deploy Container / T1496 Resource Hijacking — https://attack.mitre.org/techniques/T1496/
