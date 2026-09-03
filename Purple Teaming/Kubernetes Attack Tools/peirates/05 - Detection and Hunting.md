# peirates — Detection and Hunting

## Hunting on Source

### Find peirates binary or source code

```bash
find / -name "peirates" -o -name "*peirates*" 2>/dev/null
find ~/.cache ~/.local ~/.config -name "*peirates*" 2>/dev/null
git log --all --source --remotes | grep peirates
```

### Check for compiled Go binary artifacts

```bash
strings $(find / -name "peirates") | grep -i "aquasec\|peirates\|escape" 2>/dev/null
```

### Search shell history

```bash
grep -n "peirates\|--exploit\|--pod" ~/.bash_history
grep -E "dirty.?cow|cve-2021|cve-2024" ~/.bash_history
```

---

## Hunting on Target

### 1. Monitor for privileged container creation

Peirates is most effective when deployed as a Pod with elevated privileges.

```bash
# Look for Pods with privileged: true or excess capabilities
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.securityContext.privileged}{"\n"}{end}' | grep -c "true"

# List Pods with suspicious capabilities
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}{end}'
```

### 2. Check for suspicious API calls from Pod IPs

```bash
# Query audit logs for API calls from in-cluster Pod IPs (10.x.x.x range)
kubectl logs -n kube-system -l component=kube-apiserver | \
  jq 'select(.sourceIPAddress | test("10\\.")) | select(.verb | test("create|patch"))'

# Focus on Pods creating other Pods
kubectl logs -n kube-system -l component=kube-apiserver | \
  jq 'select(.verb == "create") | select(.objectRef.resource == "pods")'
```

### 3. Hunt for kernel exploitation attempts

```bash
# Query kernel logs for exploitation signatures
dmesg | grep -i -E "segfault|oops|panic|kernel bug|protection fault"

# Check for Dirty COW or Netfilter CVE exploitation
dmesg | grep -i -E "cow|dirty|netfilter|privilege"
```

### 4. Monitor process tree for privilege escalation

```bash
# On compromised nodes, check for unexpected root processes from user containers
ps aux | grep -E "UID=0.*container-process|root.*peirates"

# Check cgroups for cross-container process execution
cat /proc/*/cgroup | grep -v "^[0-9]" | sort -u
```

### 5. Check for Pod creation bursts in kube-system

```bash
# Unexpected Pods in kube-system (system namespace) indicate compromise
kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\n"}{end}' | sort -k2 -r

# Filter for recently created Pods (last 1 hour)
kubectl get pods -n kube-system -o json | jq '.items[] | select(.metadata.creationTimestamp | split("T")[0] == "'$(date +%Y-%m-%d)'") | .metadata.name'
```

### 6. Look for modified RBAC or ClusterRoleBindings

```bash
# List recently created ClusterRoleBindings
kubectl get clusterrolebinding -o json | jq '.items[] | select(.metadata.creationTimestamp | startswith("2024")) | .metadata.name'

# Check for cluster-admin bindings to non-system ServiceAccounts
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.subjects[*].name}{"\n"}{end}' | grep -v "system:"
```

### 7. Hunt for kubeconfig theft

```bash
# Check node filesystem for suspicious kubeconfig copies
ssh <NODE_IP> sudo find / -name "*kubeconfig*" -o -name "*kube/config" 2>/dev/null

# Check for ETCD backup files
ssh <NODE_IP> sudo find / -name "*etcd*backup*" 2>/dev/null
```

### 8. Monitor container runtime for escape indicators

```bash
# containerd: Check for multiple OOMKill or exit events (indicator of exploit attempts)
ssh <NODE_IP> sudo journalctl -u containerd -n 1000 | grep -i "ooomkill\|exit.*137\|exit.*139"

# Docker: Similar
ssh <NODE_IP> sudo docker inspect <CONTAINER_ID> | jq '.State.OOMKilled, .State.ExitCode'
```

---

## Evasion Resistance: Signals Ranking

| Rank | Signal | Evasion Method | Resistance |
|------|--------|-----------------|-----------|
| 1 | **Kernel privilege escalation attempt** (CVE exploit in kernel logs) | Kernel patching; Linux kernel hardening (CONFIG_KPROBES=n, etc.) | Very high — kernel vulnerabilities are OS-level and hard to hide |
| 2 | **Root process from non-root container** (process tree anomaly) | Run container as root initially (but this is suspicious itself) | High — process UID is immutable at runtime without kernel exploit |
| 3 | **Unexpected API calls from Pod IP** (audit logs) | Disable audit logging (requires API server restart) | Very high — if enabled, audit logs capture all API calls |
| 4 | **peirates binary presence** | Delete binary or run from source; use in-memory execution | Medium — deletion doesn't erase process logs or audit trail |
| 5 | **CronJob/Pod creation in kube-system** (K8s event logs) | Use a non-system namespace; events are ephemeral (1-2 hour retention) | Medium — can evade by waiting for event expiration |

---

## Red-Flag Callout

**A root-owned bash/sh process spawning from a container Pod, followed by API calls from that Pod's IP attempting to create additional Pods or modify RBAC, combined with kernel logs showing exploitation attempts.**

This is:
- **Specific to privilege escalation:** peirates' core function is container escape + lateral movement.
- **Evasion-resistant:** Requires kernel patching or audit logging disablement to hide.
- **Multi-layer signal:** Process behavior + API audit + kernel logs converge on the same attack.

**Secondary callout:** Rapid creation of Pods with `privileged: true` in system namespaces, especially if paired with `hostPath: /` mounts.
