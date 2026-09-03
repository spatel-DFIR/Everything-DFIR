# EKS for DFIR

An EKS investigation lives in **two log streams at once**: the **Kubernetes audit log** (what happened *inside* the cluster) and **CloudTrail** (the AWS-side access grants and IRSA assumes). You constantly cross the bridge between IAM identity and Kubernetes RBAC.

New to the service? Read **What is EKS** first. For core Kubernetes forensics, use the **Container → Kubernetes** notes alongside this.

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

EKS answers **"who reached the cluster, what did they do inside it (exec, read secrets, escalate RBAC), and did a pod's IAM role get abused?"** Miss either log stream and you miss half the attack.

## Evidence It Produces

| Evidence | Gives you | Default |
|----------|-----------|---------|
| **Kubernetes audit log** | Every kube API call: subject, verb, resource, decision | 🔴 Off — enable control-plane logging |
| **authenticator log** | IAM→Kubernetes identity resolution | 🔴 Off — enable |
| CloudTrail `eks.*` | Cluster/config/access-entry changes + actor | ✅ On |
| CloudTrail `AssumeRoleWithWebIdentity` | IRSA pod-role assumes | ✅ On |
| Node (EC2) evidence | Host/container forensics on the node | Snapshot (→ EC2) |
| GuardDuty EKS Protection | Managed K8s threat findings | Add-on |

## Collect It

```bash
# Cluster posture: is audit logging on? what's the access model?
aws eks describe-cluster --name <c> \
  --query 'cluster.{Logging:logging,Endpoint:resourcesVpcConfig.endpointPublicAccess,OIDC:identity.oidc.issuer}'
aws eks list-access-entries --cluster-name <c>                 # IAM→cluster grants
aws eks list-associated-access-policies --cluster-name <c> --principal-arn <arn>

# Kubernetes side (needs cluster access)
kubectl get configmap aws-auth -n kube-system -o yaml          # 🔴 IAM→RBAC mapping
kubectl get clusterrolebindings -o wide                        # who has cluster-admin?
kubectl get serviceaccounts -A -o yaml | grep -i role-arn      # IRSA associations

# Audit log query (CloudWatch Logs Insights on /aws/eks/<c>/cluster)
#   filter for exec / secret reads / rbac changes (below)
```

> **Console:** EKS → cluster → **Logging** (control-plane logs), **Access** (entries/policies). CloudWatch → the `/aws/eks/<cluster>/cluster` group → **Logs Insights**.

## Investigate — Both Sides of the Bridge

| Step | Do this |
|------|---------|
| 1. AWS side | CloudTrail `eks.*`: new/changed **access entries** granting cluster-admin; `UpdateClusterConfig` disabling audit logs |
| 2. The bridge | authenticator log + `aws-auth`: which IAM identity maps to which K8s group; any self-grant to `system:masters` |
| 3. Kube side | Audit log: `exec`/`attach` into pods, `get secrets`, `create clusterrolebinding`, `create pod` (privileged) |
| 4. Pod IAM | CloudTrail `AssumeRoleWithWebIdentity` — unexpected IRSA subjects; what those roles did |
| 5. Node/host | If EC2 nodes: check for pod→node IMDS theft; snapshot the node (→ EC2) |
| 6. Workload | Malicious images / privileged pods / hostPath mounts (→ Container Kubernetes notes) |

## Reading the Audit Log

Key fields in a Kubernetes audit event:

| Field | Answers | 🔴 Watch |
|-------|---------|----------|
| `user.username` / `user.groups` | The (mapped) subject | `system:masters`; an IAM role you don't expect |
| `verb` + `objectRef.resource` | What was done to what | `create` on `clusterrolebindings`; `get` on `secrets` |
| `objectRef.subresource` | e.g. `exec` / `attach` | 🔴 shell into a pod |
| `responseStatus.code` | Allowed vs forbidden | Bursts of `403` = RBAC probing |
| `sourceIPs` | Where the call came from | External / new |

Insights query pattern:

```
fields @timestamp, user.username, verb, objectRef.resource, objectRef.subresource, responseStatus.code
| filter objectRef.subresource = "exec" or objectRef.resource = "secrets" or objectRef.resource = "clusterrolebindings"
| sort @timestamp desc
```

## Hunt at Scale

**In-platform — CloudTrail for the AWS-side grants:**

```sql
SELECT eventtime, useridentity.arn, eventname, requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'eks.amazonaws.com'
  AND eventname IN ('CreateAccessEntry','AssociateAccessPolicy','UpdateClusterConfig')
  AND eventtime > '2026-07-01'
ORDER BY eventtime;
```

**At the end — SecOps UDM (optional):** EKS audit logs + GuardDuty EKS findings can feed SecOps; use it to correlate cluster activity across accounts, then pivot to the audit log for detail.

## Respond

| Goal | Action |
|------|--------|
| Cut attacker cluster access | Remove rogue access entries / fix `aws-auth`; delete malicious clusterrolebindings |
| Kill a malicious/priv pod | `kubectl delete pod`; cordon/drain the node; scale the workload down |
| Kill stolen IRSA creds | Revoke the pod role's sessions; tighten the OIDC trust (`sub`/`aud`) |
| Contain a node | Cordon + isolate + snapshot the EC2 node (→ EC2) |
| Rotate secrets | Any Kubernetes secret the attacker could read |
| Re-enable logging | Turn control-plane audit logs back on |

## Fix the Misconfig and Harden

| Fix | Why |
|-----|-----|
| **Enable audit + authenticator logs** to CloudWatch | The primary EKS evidence |
| **Private API endpoint** (or tight CIDR allowlist) | No public control plane |
| **Least-privilege RBAC**; no broad `system:masters`; scoped access entries | Limits in-cluster power |
| **IRSA/Pod Identity** with tight OIDC trust (sub/aud) | Pods get scoped IAM, no node creds |
| **Block pod→node IMDS** (IMDSv2 hop-limit 1 / network policy) | Stops pod→node role theft |
| **Network policies + Pod Security Standards** (restricted) | No privileged/hostPath pods |
| **GuardDuty EKS Protection**; ECR image scanning | Managed detection + clean images |
| **Alert** on `CreateAccessEntry`(admin), audit `exec`/secret-reads/RBAC changes | Catch persistence/privesc live |

## Red Flags

| 🔴 Finding | Why it matters |
|-----------|----------------|
| New access entry / `aws-auth` edit granting cluster-admin | Cluster-admin persistence |
| Audit `exec`/`attach` into pods by an unexpected subject | Hands-on-keyboard |
| Audit `get secrets` at volume | Credential harvesting |
| New `clusterrolebinding` to a broad role | RBAC privilege escalation |
| Pod reaching `169.254.169.254` (EC2 nodes) | Pod→node IAM role theft |
| `AssumeRoleWithWebIdentity` from an unexpected IRSA subject | Loose OIDC trust abused |
| `UpdateClusterConfig` disabling audit logging | Evidence blinded |
| Privileged / hostPath pods deployed | Container escape setup |

## Correlate With

| To go deeper on… | Open |
|------------------|------|
| What EKS is + the identity bridge | **EKS → What is EKS** |
| The malicious/crypto-pod scenario | **EKS → Playbooks → Malicious Pod and Cryptomining** |
| Core Kubernetes forensics | **Container → (Kubernetes notes)** |
| Pod/node IMDS theft + host forensics | **AWS → Compute → EC2** |
| IRSA role reach | **AWS → Identity & Access → IAM / STS** |
| Serverless nodes | **AWS → Serverless & Containers → Fargate** |

## Resources

- Control-plane logging — https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html
- IRSA — https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html
- Cluster access management — https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html
- EKS security best practices — https://aws.github.io/aws-eks-best-practices/security/docs/
- MITRE ATT&CK: Containers matrix — https://attack.mitre.org/matrices/enterprise/containers/
