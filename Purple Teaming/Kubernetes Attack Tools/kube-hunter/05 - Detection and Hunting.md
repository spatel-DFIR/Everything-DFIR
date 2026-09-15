# kube-hunter — Detection and Hunting

## Hunting on Source

### Find kube-hunter binary or Docker image

```bash
docker images | grep kube-hunter
find / -name "*kube-hunter*" -o -name "*kube_hunter*" 2>/dev/null
which kube-hunter
```

### Check for kube-hunter network connections

```bash
netstat -an | grep -E ":(6443|10250|2379|10255)" | grep ESTABLISHED
```

### Search shell history

```bash
grep -n "kube-hunter\|--remote\|aquasec" ~/.bash_history ~/.zsh_history
```

---

## Hunting on Target

### 1. Query audit logs for scanning patterns

```bash
# Look for burst of API calls from a single source in a short time window
kubectl logs -n kube-system -l component=kube-apiserver --timestamps=true | \
  jq 'select(.sourceIPAddress == "192.168.1.100")' | \
  wc -l  # Count: should be low for legitimate tools, high for kube-hunter

# Look for anonymous access attempts
kubectl logs -n kube-system -l component=kube-apiserver | \
  jq 'select(.user.username == "system:anonymous")'

# Look for rapid attempts to read resources across namespaces
kubectl logs -n kube-system -l component=kube-apiserver | \
  jq 'select(.verb | test("list|get")) | select(.objectRef.resource == "pods")' | \
  jq '.sourceIPAddress' | sort | uniq -c | sort -rn
```

### 2. Check for suspicious Pod deployments (kube-hunter as a Pod)

```bash
# Look for Pods with kube-hunter image
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.containers[*].image}{"\n"}{end}' | grep kube-hunter

# Look for recently created Pods in kube-system (suspicious)
kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.creationTimestamp}{"\n"}{end}' | sort -k2 -r | head -20
```

### 3. Monitor API server for scanning characteristics

```bash
# Count API calls per source IP (burst patterns)
kubectl logs -n kube-system -l component=kube-apiserver --tail=1000 | \
  jq -r '.sourceIPAddress' | sort | uniq -c | sort -rn | head -10
```

### 4. Check kubelet logs for connection attempts

```bash
# SSH to the node and check kubelet logs
ssh <NODE_IP> sudo journalctl -u kubelet -n 1000 | grep -i "unauthorized\|denied\|connection"
```

### 5. Hunt for ETCD access (port 2379)

```bash
# Query API server logs for port 2379 connection attempts
kubectl logs -n kube-system -l component=kube-apiserver | \
  jq 'select(.verb == "get") | select(.objectRef.resource == "nodes")'

# If ETCD is compromised, check for suspicious reads
ssh <CONTROL_PLANE_NODE> sudo etcdctl --endpoints=https://127.0.0.1:2379 get "" --prefix | \
  jq . | head -100
```

---

## Evasion Resistance: Signals Ranking

| Rank | Signal | Evasion Method | Resistance |
|------|--------|-----------------|-----------|
| 1 | **kube-hunter binary/image presence** | Delete the binary or uninstall the image | Medium — binary removal doesn't erase network logs or audit entries; image deletion on a registry-less node is possible but suspicious |
| 2 | **Burst of API audit log entries** (100+ in 10 seconds from anonymous user) | Disable audit logging (requires API server restart) | Very high — if enabled, burst is unmistakable; hard to fake or hide |
| 3 | **Rapid port scanning** (6443, 10250, 2379 in seconds from same IP) | Use slower scanning to blend in | High — but slower scanning takes longer and increases detection window |
| 4 | **Anonymous access attempts** (if cluster allows) | Use compromised credentials instead | Medium — but anonymous is often restricted; using creds is just kubectl |
| 5 | **Container image presence** (docker images \| grep kube-hunter) | Use a renamed image or run from source | Medium — source-based execution is slower and noisier |

---

## Red-Flag Callout

**A rapid sequence of API calls (50+ within 10 seconds) with HTTP 403 Forbidden responses, all from the same external IP, targeting `/api/v1/pods`, `/api/v1/secrets`, `/api/v1/nodes`, and port 10250 connection attempts.**

This is:
- **Specific to automated scanning:** kube-hunter's systematic, sequential testing.
- **Evasion-resistant:** Network rate-limiting and audit logging capture this pattern regardless of tool customization.
- **Low false-positive rate:** Legitimate tools rarely make this many failed attempts in such a short timeframe.
