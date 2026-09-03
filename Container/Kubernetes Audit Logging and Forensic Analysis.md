# Kubernetes Audit Logging and Forensic Analysis

Advanced investigation of Kubernetes audit logs — the authoritative record of API server events, cluster-level actions, and RBAC decisions. Audit logs are your primary evidence source for cluster compromise, privilege escalation, data exfiltration, and persistence mechanisms deployed at the orchestration layer.

---

## Quick Triage

```bash
# Check audit log status on control plane
kubectl get configmap -n kube-system kube-apiserver-audit-policy -o yaml

# Export audit logs from etcd backup
etcdctl snapshot restore etcd-backup.db --data-dir=./snapshot
cat ./snapshot/audit.log | jq '.verb, .user, .resourceAttributes'

# Hunt suspicious API calls (live cluster)
kubectl logs -n kube-system -l component=kube-apiserver | grep -i "error\|forbidden\|unauthorized"

# Timeline correlation: when was a service account compromised?
grep '"user":{"username":"system:serviceaccount' audit.log | jq '.requestTimestamp, .user, .resourceAttributes'
```

---

## Kubernetes Audit Architecture

### Audit Log Pipeline

The Kubernetes API server generates audit events at several stages:

1. **Request Reception** — HTTP request hits the API server
2. **Authentication** — Client certificate, bearer token, or webhook validates identity
3. **Authorization** — RBAC rules (ClusterRole/Role/RoleBinding) determine if action is allowed
4. **Admission Control** — Webhooks (ValidatingAdmissionWebhook, MutatingAdmissionWebhook) approve/reject/modify
5. **Event Logging** — Audit backend (file, webhook, dynamic) records the event

**Forensic significance:** Each stage can be compromised; audit logs capture the decision at authorization boundary.

### Audit Log Levels

| Level | Content | Forensic Use |
|-------|---------|--------------|
| **None** | No logging | ❌ Destroyed evidence (red flag) |
| **Metadata** | Request/response headers, user, resource | Baseline investigation |
| **RequestResponse** | Full request/response bodies + metadata | Suspicious API args, data exfiltration |
| **RequestResponseWithWarnings** | RequestResponse + plugin warnings | Admission controller decisions |

**Investigation note:** Metadata level is common; RequestResponse generates 100–500 GB/day on busy clusters — retention is usually 7–30 days.

### Audit Log Format

Each event is a JSON object with these key fields:

```json
{
  "level": "RequestResponse",
  "auditID": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "stage": "ResponseComplete",
  "requestTimestamp": "2026-08-29T14:23:45.123456Z",
  "stageTimestamp": "2026-08-29T14:23:45.234567Z",
  "requestObject": {...},
  "responseObject": {...},
  "user": {
    "username": "alice@example.com",
    "uid": "1234567890",
    "groups": ["developers", "system:authenticated"]
  },
  "sourceIPs": ["10.0.1.100"],
  "userAgent": "kubectl/v1.25.0",
  "verb": "create",
  "apiVersion": "v1",
  "objectRef": {
    "resource": "pods",
    "namespace": "default",
    "name": "malicious-pod",
    "apiGroup": "core"
  },
  "requestURI": "/api/v1/namespaces/default/pods",
  "code": 201
}
```

**Forensic interpretation:**
- `stage`: RequestStart (before auth), RequestReceived (after auth), ResponseStarted (before response body), ResponseComplete
- `code`: HTTP status (200–299 = allowed, 4xx = error/unauthorized, 5xx = server error)
- `user`: Who performed the action (human, service account, webhook)
- `objectRef`: What resource was touched (pod, secret, node, rbac role, etc.)

---

## Advanced Hunting: DFIR Workflows

### Scenario 1: Privilege Escalation Detection

**Investigation Goal:** Find when attacker escalated from basic user to cluster-admin.

**Hunting query:**

```bash
# Step 1: Identify the compromised user
jq 'select(.user.username == "compromised-user") | .verb, .user, .resourceAttributes' audit.log

# Step 2: Hunt for RBAC modification (ClusterRoleBinding changes)
jq 'select(.verb == "create" or .verb == "patch") | 
    select(.objectRef.resource == "clusterrolebindings") | 
    {timestamp: .requestTimestamp, user: .user.username, binding: .objectRef.name, requestBody: .requestObject}' audit.log

# Step 3: Timeline — when did the compromise start?
jq 'select(.user.username == "compromised-user") | .requestTimestamp' audit.log | sort | head -1
```

**Red flags:**
- User creating/patching ClusterRoleBinding to cluster-admin
- Service account escalation (e.g., system:serviceaccount:default:webhook → cluster-admin)
- Verb: "create" or "patch" on RoleBinding/ClusterRoleBinding immediately before suspicious actions

### Scenario 2: Secret Exfiltration Detection

**Investigation Goal:** Identify if secrets were read and exfiltrated.

**Hunting query:**

```bash
# Step 1: Find all secret reads
jq 'select(.verb == "get" or .verb == "list") | 
    select(.objectRef.resource == "secrets") | 
    {timestamp: .requestTimestamp, user: .user.username, secret: .objectRef.name, namespace: .objectRef.namespace}' audit.log

# Step 2: Correlate with outbound connections
# (requires network logs from CNI plugin or packet capture)
# Look for: secret read → immediate network egress to external IP

# Step 3: Identify service accounts accessing secrets across namespaces
jq 'select(.verb == "get") | 
    select(.objectRef.resource == "secrets") | 
    select(.user.username | contains("system:serviceaccount")) | 
    {user: .user.username, namespace: .objectRef.namespace, secret: .objectRef.name}' audit.log | sort | uniq -c
```

**Red flags:**
- Service account (not human) reading secrets
- Secrets read from unexpected namespaces (cross-namespace access)
- High volume of secret reads in short time (data dump)
- Secret read followed by pod creation in different namespace (pivot)

### Scenario 3: Persistence Mechanism Detection

**Investigation Goal:** Find how attacker maintained access (e.g., webhook, sidecar injection, control plane backdoor).

**Hunting query — ValidatingAdmissionWebhook:**

```bash
# Hunt for webhook creation/modification
jq 'select(.verb == "create" or .verb == "patch") | 
    select(.objectRef.resource == "validatingwebhookconfigurations") | 
    {timestamp: .requestTimestamp, user: .user.username, webhook: .objectRef.name, config: .requestObject}' audit.log

# Extract webhook URLs (potential C2 callback)
jq 'select(.objectRef.resource == "validatingwebhookconfigurations") | 
    .requestObject.webhooks[].clientConfig.url' audit.log | sort | uniq
```

**Hunting for sidecar injection (mutating webhook):**

```bash
jq 'select(.verb == "create" or .verb == "patch") | 
    select(.objectRef.resource == "mutatingwebhookconfigurations") | 
    {timestamp: .requestTimestamp, user: .user.username, webhook: .objectRef.name}' audit.log
```

**Red flags:**
- Webhooks created by non-admin users
- Webhooks pointing to external URLs (C2 callbacks)
- Webhooks created immediately before pod anomalies
- Webhooks with `failurePolicy: Ignore` (keeps working even if server is down)

### Scenario 4: Lateral Movement Detection

**Investigation Goal:** Identify when attacker pivoted from one namespace to another or from worker to control plane.

**Hunting query:**

```bash
# Cross-namespace activity from service accounts
jq 'select(.user.username | contains("system:serviceaccount")) | 
    .user.username as $user | 
    select(.objectRef.namespace != (.user.username | split(":")[2])) |
    {user: $user, resource_namespace: .objectRef.namespace, action: .verb, resource: .objectRef.resource}' audit.log

# Service account access to cluster-wide resources (not namespace-scoped)
jq 'select(.user.username | contains("system:serviceaccount")) | 
    select(.objectRef.namespace == null) |
    {user: .user.username, resource: .objectRef.resource, verb: .verb}' audit.log
```

**Red flags:**
- Service account from namespace A accessing resources in namespace B
- Service account accessing cluster-scoped resources (nodes, clusterroles, network policies)
- Sudden change in service account activity pattern

---

## Log Acquisition and Analysis

### Acquiring Audit Logs from Running Cluster

**From control plane node:**

```bash
# SSH to control plane node
ssh user@control-plane-node

# Locate audit log file
find /var/log -name "*audit*" -o -name "*kube*"
# Typical path: /var/log/pods/kube-system_kube-apiserver-*/kube-apiserver/0.log

# Or via kubelet logs (if audit backend is configured)
journalctl -u kubelet -S "2026-08-28" | grep audit
```

**From Kubernetes API (live access required):**

```bash
# If audit logs are exposed via logs endpoint (rare, requires RBAC)
kubectl logs -n kube-system -l component=kube-apiserver

# Check if audit webhooks are configured (backend sends to remote server)
kubectl get configmap -n kube-system kube-apiserver-audit-policy -o yaml | grep -i webhook
```

### Acquiring Audit Logs from etcd Backup

**If control plane has failed:**

```bash
# Restore etcd snapshot
ETCDCTL_API=3 etcdctl snapshot restore etcd-backup.db --data-dir=./snapshot

# Audit logs may be stored as Kubernetes resources in etcd
find ./snapshot -name "*.db" -exec strings {} \; | grep -i "audit\|apiserver"
```

**If audit backend was webhook (logs shipped to remote server):**

```bash
# Check for audit logs on log aggregation system (ELK, Splunk, CloudWatch, etc.)
# Query by timestamp and keywords:
# - "verb": "create" + "resource": "secrets"
# - "user.username": "system:admin"
# - "code": "403" (forbidden, potential attack detection)
```

### File-Based Audit Logs

**Location and rotation:**

```bash
# Audit log file (configured in kube-apiserver manifest)
/var/log/kubernetes/audit.log

# Rotation (if configured)
ls -la /var/log/kubernetes/audit.log*
# Timestamp recovery: file mtime = when log was written
stat /var/log/kubernetes/audit.log
```

**Recovery from deleted audit logs:**

```bash
# If audit.log was deleted but file descriptor still open
# (common if logs rotated but process didn't restart):
ls -la /proc/[kube-apiserver-pid]/fd/ | grep audit

# Extract from memory/journal
journalctl -u kube-apiserver -S "2026-08-28" --no-pager > apiserver.log

# Search for log entries in etcd (if etcd backend was used)
strings /var/lib/etcd/member/wal/0.wal | grep -i audit
```

---

## SIEM Integration and Detection Rules

### Splunk Query: Detect RBAC Privilege Escalation

```spl
sourcetype="kubernetes:audit" verb IN ("create", "patch") objectRef.resource="clusterrolebindings"
| stats count by user.username, objectRef.name, requestTimestamp
| where count > 5
| alert
```

### ELK Query: Detect Secret Exfiltration

```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"verb": "get"}},
        {"match": {"objectRef.resource": "secrets"}},
        {"range": {"requestTimestamp": {"gte": "now-1h"}}}
      ],
      "should": [
        {"match": {"user.username": "system:serviceaccount"}}
      ]
    }
  },
  "size": 10000
}
```

### Falco Rules: Real-Time Audit Anomaly Detection

```yaml
- rule: Suspicious API Server Activity
  desc: Detect anomalous API server audit events
  condition: k8s_audit and (high_privilege_verb or cross_namespace_access)
  output: >
    Suspicious Kubernetes API activity detected
    (user=%user.username verb=%verb resource=%object.resource namespace=%object.namespace)
  priority: WARNING
  tags: [mitre_t1542]
```

---

## Forensic Artifacts and Correlation

### Timeline Building

**Audit log + system timeline correlation:**

```bash
# Extract audit events with precise timestamps
jq '.requestTimestamp' audit.log | sort | uniq

# Correlate with container runtime events (Docker/containerd logs)
grep "container started\|container created" /var/log/syslog | awk '{print $1, $2, $3}'

# Correlate with system-level RBAC changes (kubectl apply)
journalctl -u kubelet | grep "mounting\|unmounting\|creating"

# Build super-timeline
cat <(jq '{timestamp: .requestTimestamp, source: "audit", event}' audit.log) \
    <(journalctl -u kubelet -o json | jq '{timestamp: .__REALTIME_TIMESTAMP, source: "kubelet", MESSAGE}') \
    | jq -s 'sort_by(.timestamp)'
```

### Deletion and Anti-Forensics Detection

**Red flags in audit logs:**

```bash
# Deletion of audit logs themselves (if audit backend can be accessed)
jq 'select(.objectRef.resource == "audit") | select(.verb == "delete")' audit.log

# Kube-apiserver restarts (may indicate log rotation or tampering)
journalctl -u kube-apiserver | grep "Started\|Stopped"

# Audit policy changes (logging level downgraded from RequestResponse to Metadata)
jq 'select(.objectRef.resource == "configmaps") | 
    select(.objectRef.name == "kube-apiserver-audit-policy")' audit.log

# High-volume token generation + immediate token deletion (cover tracks)
jq 'select(.objectRef.resource == "secrets") | 
    select(.objectRef.name | contains("token")) | 
    select(.verb == "create" or .verb == "delete")' audit.log
```

---

## Limitations and Blind Spots

| Limitation | Impact | Mitigation |
|-----------|--------|-----------|
| **Audit logs stored on compromised control plane** | Attacker can delete/modify logs | Ship logs to external immutable store (syslog, webhook to off-cluster server) |
| **Metadata-only logging** | Request/response bodies not captured (can't see secret values) | Use RequestResponse level (performance cost) or correlate with etcd snapshots |
| **Kubelet logs not audited** | Container creation/process execution on workers not in audit log | Use Falco, auditd, or Sysmon for Linux on worker nodes |
| **Webhook audit backend may drop events** | High-load clusters may lose audit events if webhook is slow | Monitor webhook latency; use local file backup + remote webhook |
| **No built-in alerting** | Audit logs are passive; no real-time detection | Integrate with SIEM (Splunk, ELK) or use Falco for live monitoring |

---

## References

- **Kubernetes Audit Documentation:** https://kubernetes.io/docs/tasks/debug-application-cluster/audit/
- **MITRE ATT&CK Kubernetes Techniques:** https://attack.mitre.org/tactics/TA0040/ (Kubernetes)
- **Falco Kubernetes Auditing:** https://falco.org/docs/
- **Audit Policy Generator:** https://github.com/kubernetes/kubernetes/tree/master/cluster/gce/gci/configure-helper.sh

---

## Investigation Checklist

- [ ] Verify audit logging is enabled (check kube-apiserver flags: `--audit-log-path`, `--audit-policy-file`)
- [ ] Identify audit log retention (check log rotation, webhook destinations)
- [ ] Extract audit logs (file system or webhook backend)
- [ ] Parse JSON and identify incident timeline (`.requestTimestamp`)
- [ ] Hunt for privilege escalation (RBAC creation/modification by non-admin)
- [ ] Hunt for secret access (service accounts reading secrets across namespaces)
- [ ] Hunt for persistence (webhook configurations, control plane modifications)
- [ ] Correlate with system-level events (journalctl, container runtime logs)
- [ ] Identify log gaps (audit policy changes, restarts, deleted logs)
- [ ] Document evidence chain (audit events → timeline → attack sequence)
