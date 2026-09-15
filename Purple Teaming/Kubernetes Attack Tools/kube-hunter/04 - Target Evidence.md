# kube-hunter — Target Evidence

## Kubernetes API audit logs

When kube-hunter probes the API server, every probe is logged in the audit log if enabled:

```json
{
  "verb": "list",
  "resource": "pods",
  "namespace": "kube-system",
  "sourceIPAddress": "192.168.1.100",
  "user": {
    "username": "system:anonymous",
    "groups": ["system:unauthenticated"]
  },
  "responseStatus": {
    "code": 403
  }
}
```

**Pattern:** A burst of API calls with `user: system:anonymous` attempting to list/read resources in kube-system or kube-public, all within seconds, from an external IP.

## Kubelet logs

When kube-hunter probes port 10250, the kubelet logs connection attempts:

```
time="2024-08-01T10:30:00Z" level=warning msg="Attempted unauthorized kubelet access from 192.168.1.100:54321"
```

## Container runtime logs

If kube-hunter runs as a Pod inside the cluster, the container runtime logs Pod creation:

```bash
docker logs <CONTAINER_ID>  # Output of kube-hunter scan
```

---

## Strongest Target Evidence Signal

**A burst of API audit log entries (100+) within 10 seconds, all with `user: system:anonymous` or a low-privilege ServiceAccount, attempting to enumerate resources across namespaces.**

This is highly distinctive because:
1. Legitimate tools rarely make so many API calls per second.
2. Anonymous access itself is suspicious (most clusters require authentication).
3. The sequential, systematic nature (testing each plugin/attack) is machine-like, not human interactive.

**Secondary signal:** Multiple connection attempts to port 10250 (kubelet) and port 2379 (ETCD) from the same source IP within seconds.
