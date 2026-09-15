# Kubernetes Cluster Compromise Playbook

A pod is compromised (app RCE, malicious image), its service-account token is stolen, and the attacker escalates through RBAC to deploy workloads cluster-wide. The API-server audit log is the spine of this investigation.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Reconstruct from the Audit Log](#reconstruct-from-the-audit-log)
- [Trace the Token and RBAC Path](#trace-the-token-and-rbac-path)
- [Find Attacker Workloads and Node Persistence](#find-attacker-workloads-and-node-persistence)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Red Flags](#red-flags)

## Attack Chain

Initial foothold in a pod (app vulnerability / poisoned image) → read the mounted SA token → call the API server as that SA → enumerate RBAC (`can-i --list`) → escalate (create privileged pod, exec into pods, create a rolebinding, read secrets) → deploy workloads cluster-wide → optionally drop a static pod on a node → pivot to cloud via IMDS/IRSA.

## Quick Triage

```bash
# Powerful bindings (takeover indicator)
kubectl get clusterrolebindings -o wide | grep -Ei "cluster-admin|system:masters"

# Privileged / hostPath / host-namespace pods (escape surface)
kubectl get pods -A -o json | jq -r '.items[] | select((.spec.containers[].securityContext.privileged==true) or .spec.hostPID or .spec.hostNetwork or (.spec.volumes[]?.hostPath)) | .metadata.namespace+"/"+.metadata.name'

# Recent cluster events + exec activity
kubectl get events -A --sort-by=.lastTimestamp | tail -30

jq 'select(.objectRef.subresource=="exec")' /var/log/kubernetes/audit/audit.log 2>/dev/null | tail
```

## Reconstruct from the Audit Log

🔴 The audit log records every API action with user, verb, object, sourceIP, and result — this is the whole attacker session.

```bash
AUDIT=/var/log/kubernetes/audit/audit.log     # or the cloud logging sink

# Everything a suspect SA/user did
jq --arg u "system:serviceaccount:<ns>:<sa>" 'select(.user.username==$u) | {t:.requestReceivedTimestamp, verb, res:.objectRef.resource, name:.objectRef.name, ip:.sourceIPs, status:.responseStatus.code}' $AUDIT

# Interactive access (exec/attach into pods)
jq 'select(.objectRef.subresource=="exec" or .objectRef.subresource=="attach")' $AUDIT

# Secret reads
jq 'select(.objectRef.resource=="secrets" and (.verb=="get" or .verb=="list"))' $AUDIT

# RBAC changes (escalation)
jq 'select(.objectRef.resource | test("rolebindings|clusterrolebindings|roles|clusterroles")) | select(.verb=="create" or .verb=="update")' $AUDIT

# Workload creation
jq 'select(.objectRef.resource | test("pods|deployments|daemonsets|cronjobs")) | select(.verb=="create")' $AUDIT

# Anonymous / unauthenticated
jq 'select(.user.username | test("anonymous|unauthenticated"))' $AUDIT
```

## Trace the Token and RBAC Path

```bash
# Which SA did the compromised pod use, and what could it do?
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.serviceAccountName}'

kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>

# Token used from OUTSIDE its pod IP = theft
jq --arg u "system:serviceaccount:<ns>:<sa>" 'select(.user.username==$u) | .sourceIPs[]' $AUDIT | sort -u

# The bindings that granted the escalation
kubectl get clusterrolebindings,rolebindings -A -o json | jq -r '.items[] | select(.subjects[]?.name=="<sa>") | .metadata.name+" -> "+.roleRef.name'
```

🔴 A SA token appearing from a sourceIP that isn't its pod, or a low-privilege SA that suddenly reads secrets / creates pods, is the theft-and-escalation core of the incident.

## Find Attacker Workloads and Node Persistence

```bash
# Rogue workloads
kubectl get pods,deploy,ds,cronjobs -A | grep -Ei "<suspect>|miner|<unknown-image>"

# Suspicious images
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}' | grep -Ev "<your-registry>"

# Static pods dropped on nodes (no API record) - check each node
ls -la /etc/kubernetes/manifests/

# Malicious admission webhooks (inject into every pod)
kubectl get mutatingwebhookconfigurations validatingwebhookconfigurations
```

## Timeline

```bash
# Order the attacker's audit actions
jq -r --arg u "system:serviceaccount:<ns>:<sa>" 'select(.user.username==$u) | .requestReceivedTimestamp+" "+.verb+" "+(.objectRef.resource//"")+" "+(.objectRef.name//"")' $AUDIT | sort

# Correlate pod creation times + node static-pod mtimes
```

## Eradication

```bash
# Delete attacker workloads (controllers, not just pods)
kubectl delete deployment/<x> daemonset/<x> cronjob/<x> pod/<x> -n <ns>

# Remove malicious RBAC
kubectl delete clusterrolebinding <evil>; kubectl delete rolebinding <evil> -n <ns>

# Remove static pods on nodes
sudo rm /etc/kubernetes/manifests/<evil>.yaml

# Remove malicious webhooks
kubectl delete mutatingwebhookconfiguration <evil>

# Cordon/drain and rebuild any node with confirmed node-level compromise
kubectl cordon <node>; kubectl drain <node> --ignore-daemonsets
```

## Credential Reset

🔴 Token/secret rotation is the only thing that actually ends cluster access:

```bash
# Rotate the compromised SA's tokens (delete the SA's token secrets / rotate)
kubectl delete secret <sa-token-secret> -n <ns>      # forces reissue (older K8s)

# Rotate ALL secrets the attacker could read (they're compromised)
# Rotate kubeconfig credentials / client certs used by the attacker
# If etcd was accessed: assume ALL cluster secrets are exposed -> rotate everything
# Rotate cloud IAM creds if IMDS/IRSA pivot is possible
```

## Fleet Hunt

IOCs: attacker sourceIPs, malicious image digests, the SA/token, webhook/binding names, node static-pod content.

```bash
# Same image across clusters/namespaces
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | grep -i <image>

# Attacker sourceIP across the audit log
jq 'select(.sourceIPs[]=="<attacker_ip>")' $AUDIT | jq -r '.user.username' | sort -u
```

## Red Flags

| Finding | Meaning |
|---------|---------|
| SA token used from outside its pod IP | Token theft |
| New binding to cluster-admin/system:masters | Privilege escalation → takeover |
| exec/attach into pods from odd sourceIPs | Interactive attacker |
| Secret get/list burst by one SA | Credential harvesting |
| Static pod on a node / malicious webhook | Persistence |
| Anonymous API access | Misconfigured API server |
| Pod reaching IMDS 169.254.169.254 | Cloud pivot |
