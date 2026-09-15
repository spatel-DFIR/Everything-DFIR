# kubectl — Detection and Hunting

## Hunting on Source (Attacker's Machine)

### Find kubeconfig files

```bash
# Search standard locations
find ~/.kube -type f -name "config" -o -name "*.conf" -o -name "*.yaml"

# Search for kubeconfigs anywhere on the filesystem (slow)
find / -name "*kubeconfig*" 2>/dev/null
find / -path "*/.kube/*" -type f 2>/dev/null

# Search temp directories
ls -la /tmp/*kube* 2>/dev/null
ls -la $TMPDIR/*kube* 2>/dev/null

# Check for kubeconfig in environment variables
env | grep -i KUBECONFIG
```

### Extract and validate found kubeconfigs

```bash
# Verify a file is a valid kubeconfig
kubectl config view --kubeconfig=/path/to/suspected/kubeconfig

# Decode embedded certificates/tokens (Base64-encoded in kubeconfig)
cat kubeconfig | grep client-certificate-data | awk '{print $2}' | base64 -d | openssl x509 -text -noout

# Extract authentication material
kubectl config view --kubeconfig=./config --flatten > decoded_config.yaml
# Now decoded_config.yaml contains base64-decoded certs/tokens (still in YAML but readable)
```

### Search shell history

```bash
# Bash history
grep -n "kubectl" ~/.bash_history
grep -E "kubeconfig|--token|--server" ~/.bash_history

# Zsh history
grep -n "kubectl" ~/.zsh_history

# All history files
for history_file in ~/.bash_history ~/.zsh_history ~/.history ~/.ksh_history; do
  [ -f "$history_file" ] && echo "=== $history_file ===" && grep "kubectl" "$history_file"
done
```

### Check process arguments and command line

```bash
# Current running processes
ps aux | grep kubectl

# Process command line (reads from /proc)
grep -a "kubectl" /proc/*/cmdline | tr '\0' ' '

# If auditd is available, search audit logs for kubectl invocation
ausearch -c kubectl 2>/dev/null
```

### Search for temporary kubeconfig artifacts

```bash
# Check /tmp for leftover kubeconfig files
find /tmp -type f \( -name "*kube*" -o -name "*.conf" \) -mtime -7  # Modified in last 7 days

# Check for kubectl cache
ls -la ~/.kube/cache/
du -sh ~/.kube/cache/

# Look for kubectl plugin directories
find ~/.kube/plugins/ -type f 2>/dev/null
```

### Timeline analysis: correlate tool usage with other events

```bash
# Combine kubeconfig file times, shell history, and process logs
stat ~/.kube/config  # File modification time
grep "kubectl" ~/.bash_history | head -1  # First kubectl command
ls -l ~/.bash_history  # Shell history modification time
```

### Evasion Resistance: Source Artifacts Ranking

| Rank | Signal | Evasion Method | Resistance |
|------|--------|-----------------|-----------|
| 1 | **kubeconfig file** (presence + content) | Delete or overwrite the file | File recovery via deleted-inode analysis; cloud metadata if kubeconfig was uploaded |
| 2 | **Decoded client certificates** (X.509 metadata) | Can't remove certificate metadata without regenerating | Very resistant; certificate issuer/subject/dates are intrinsic to the cert |
| 3 | **Process arguments** (/proc/*/cmdline or auditd) | Shell history can be cleared, but processes with kubectl in args are hard to hide | High resistance if auditd/process accounting is enabled |
| 4 | **Shell history** (.bash_history, .zsh_history) | `history -c` or `export HISTFILE=/dev/null` before kubectl commands, or delete history file | Low resistance; easy to clear, and many operators clear shell history routinely |
| 5 | **kubeconfig cache** (~/.kube/cache/) | Cache directories are small and often cleared | Medium resistance; cache presence may survive even if contents don't |

---

## Hunting on Target (Kubernetes Cluster)

### 1. Check if audit logging is enabled

```bash
# Query the kube-apiserver pod (usually in kube-system namespace)
kubectl get pod kube-apiserver-<NODE_NAME> -n kube-system -o yaml | grep -i audit

# Or check the apiserver's command-line arguments
kubectl describe pod kube-apiserver-<NODE_NAME> -n kube-system | grep -i audit

# Check for audit log file on the API server node (requires SSH to the node)
ssh <NODE_IP> sudo tail -f /var/log/kube-audit.log
```

If audit logging is **not** enabled, hunting becomes significantly harder — rely on event objects, kubelet logs, and container runtime logs.

### 2. Query audit logs for suspicious API calls

If audit logs are accessible (via kubectl exec to an API server pod, or SSH to the control plane):

```bash
# Get all pod creations in the cluster
kubectl exec -it kube-apiserver-<NODE_NAME> -n kube-system -- tail -f /var/log/kube-audit.log | \
  jq 'select(.verb=="create" and .objectRef.resource=="pods")'

# Get all secret reads
kubectl logs -n kube-system -l component=kube-apiserver --timestamps=true | \
  grep -i "verb: get.*secrets" 

# Use a custom log parser (if audit logs are exported to Splunk/ELK/etc.)
# Example Splunk query:
# index=kubernetes verb=create resource=pods
# | stats count by user, namespace, objectRef.name
# | sort - count
```

**Note:** Many clusters send audit logs to external logging backends (Splunk, Datadog, CloudWatch, etc.); check the cluster's logging configuration:

```bash
kubectl get configmap -n kube-system audit-policy -o yaml  # May contain the audit policy
```

### 3. Hunt for suspicious Pod creation patterns

```bash
# List all Pods created in the last 24 hours
kubectl get events -A --sort-by='.lastTimestamp' | grep -i "pod.*created\|deployment.*created"

# Look for Pods with suspicious image repositories (attacker-controlled registries)
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep -v 'docker.io\|gcr.io\|k8s.gcr.io\|quay.io'

# Look for Pods with hostPath mounts (potential privilege escalation)
kubectl get pods -A -o jsonpath='{range .items[*].spec.volumes[*]}{.hostPath.path}{"\n"}{end}' | sort -u

# List Pods running with privileged: true
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.securityContext.privileged}{"\n"}{end}' | grep -c "true"
```

### 4. Hunt for CronJobs (used for persistence)

```bash
# List all CronJobs
kubectl get cronjobs -A

# Find CronJobs created recently (within last 7 days)
kubectl get cronjobs -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\n"}{end}' | awk '{print $1, $2, $3}'

# Inspect a suspicious CronJob's command
kubectl get cronjob <CRONJOB_NAME> -n <NAMESPACE> -o yaml | grep -A 10 "command:"
```

### 5. Hunt for exec operations (kubectl exec into Pods)

```bash
# Query audit logs for exec operations (requires audit logs)
kubectl logs -n kube-system -l component=kube-apiserver --timestamps=true | \
  grep 'verb: create.*resource: pods/exec'

# Alternative: look for processes inside containers that shouldn't exist
# (requires SSH to the node and container inspection)
```

### 6. Check for ServiceAccount token exfiltration

```bash
# Look for recently-modified ServiceAccount tokens
find /var/run/secrets/kubernetes.io/serviceaccount/ -type f -mtime -7 2>/dev/null

# Check if token was read by comparing file access time
stat /var/run/secrets/kubernetes.io/serviceaccount/token | grep -i access
```

### 7. Hunt for RBAC privilege escalation

```bash
# List all ClusterRoles with wildcard permissions (admin-like)
kubectl get clusterrole -o jsonpath='{range .items[?(@.rules[*].verbs[*]=="*")]}{.metadata.name}{"\n"}{end}'

# Find ServiceAccounts with cluster-admin binding
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.subjects[*].name}{"\n"}{end}'

# Check who can impersonate users (potential privilege escalation)
kubectl get clusterrole -o jsonpath='{range .items[*].rules[?(@.resources[*]=="users")]}{.metadata.name}{"\t"}{.verbs}{"\n"}{end}' | grep impersonate
```

### 8. Check for deleted/modified resources

```bash
# Look at Kubernetes Events to see if Pods were deleted recently
kubectl get events -A --sort-by='.lastTimestamp' | grep -i "deleted\|removed"

# If using etcd, query for deleted resources (requires etcdctl access)
# etcdctl get "" --prefix | grep "deletionTimestamp"
```

### 9. Monitor API server performance (potential DoS/brute-force)

```bash
# Check API server request latency (may spike under brute-force)
kubectl top nodes  # Node resource usage
kubectl top pods -n kube-system  # Pod resource usage (including API server)

# Query logs for rate-limiting events
kubectl logs -n kube-system -l component=kube-apiserver | grep -i "rate limit\|too many"
```

### 10. Hunt for changes to critical resources

```bash
# Check for recent changes to RBAC resources
kubectl get clusterrole -A -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.managedFields[0].time}{"\n"}{end}' | sort -k2 -r | head -20

# Check for recent changes to Secrets (especially in kube-system)
kubectl get secrets -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\n"}{end}' | sort -k2 -r | head -20
```

### Evasion Resistance: Target Artifacts Ranking

| Rank | Signal | Evasion Method | Resistance |
|------|--------|-----------------|-----------|
| 1 | **Kubernetes API audit logs** (if enabled) | Requires cluster-admin + API server restart to disable; or delete audit log files (harder if they're in PersistentVolume) | **Very high** — if enabled, audit logs are comprehensive and difficult to tamper with |
| 2 | **Audit log entries** (if exported to external backend like Splunk) | Can't modify external logs without access to the external system | Extremely high if logs are immutable and centralized |
| 3 | **Kubelet logs** (events, pod startup/stop) | Kubelet logs are harder to delete; require node-level access | High resistance |
| 4 | **ETCD state** (deleted resources may still have `deletionTimestamp`) | Requires ETCD corruption or full cluster wipe | Very high |
| 5 | **Kubernetes Events** (Pod created/deleted, etc.) | Events are ephemeral (1-2 hour retention by default) | Medium resistance; easy to evade by waiting for event expiration or high event volume to flush cache |
| 6 | **Container filesystem artifacts** | Ephemeral; deleted when Pod is deleted | Low resistance — Pod deletion removes all filesystem traces |

---

## Red-Flag Callout

The **single most distinctive detection signal across all kubectl usage scenarios** is:

**A surge of API audit log entries with `verb: get` or `verb: list` against `resource: secrets`, `resource: configmaps`, or `resource: pods` from a single user/ServiceAccount, originating from an external IP (not a Pod), within a compressed timeframe (e.g., 100+ API calls in 10 seconds).**

This pattern is:
- **Specific to reconnaissance:** An attacker enumerating the cluster's state.
- **Difficult to mimic as legitimate:** Normal kubectl usage is interactive and human-paced, not bursting.
- **Evasion-resistant:** If audit logging is enabled, there's no way to hide this pattern.

**Secondary red flag:** Pod creation events (`verb: create`, `resource: pods`) with unusual image repositories (non-standard registries), hostPath mounts, or `privileged: true` in kube-system or kube-public namespaces (where application Pods shouldn't be).
