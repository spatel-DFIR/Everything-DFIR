# peirates — Target Evidence

## Container runtime logs

When peirates escapes from a container or creates new Pods, the container runtime (Docker, containerd, CRI-O) logs the events:

```bash
docker logs <CONTAINER_ID>
# Output: peirates binary execution, escape attempts, etc.

# On the node:
journalctl -u containerd  # containerd logs
journalctl -u docker      # Docker logs
```

## kubelet logs

When a new Pod is created by peirates (via API), the kubelet logs Pod scheduling and container startup:

```bash
journalctl -u kubelet -n 1000
# Shows: "Pod <namespace>/<name> created", "Container started"
```

## Kernel logs (dmesg)

If a kernel CVE is exploited, the kernel may log warnings or errors:

```bash
dmesg | tail -100  # Check for segfaults, oops, or security warnings

# Dirty COW may trigger:
# [ ] BUG: unable to handle kernel NULL pointer dereference

# Netfilter CVE-2021-22555 may trigger:
# [ ] kernel: netfilter: dropped packet from <PID> due to...
```

## API audit logs

When peirates uses the ServiceAccount token to make API calls:

```json
{
  "verb": "create",
  "resource": "pods",
  "namespace": "kube-system",
  "user": {
    "username": "system:serviceaccount:default:default",
    "uid": "12345..."
  },
  "sourceIPAddress": "10.0.0.50:12345"  # Pod IP
}
```

**Pattern:** API calls from a Pod IP (internal) rather than external IP, making API calls from inside the cluster.

## Process tree anomalies

On the compromised node, unexpected process hierarchies may appear:

```
containerd (PID 1234)
  └─ container-process (PID 5000)
      └─ peirates (PID 5001) [unexpected]
          └─ bash (PID 5002) [running as root, but container is non-root]
```

The presence of root-owned processes spawning from a non-root container is highly suspicious.

## File system modifications

On the node, if hostPath is mounted or escape is achieved:

- **Files written to /host/** — any files peirates creates in mounted host volumes.
- **Modified /etc/passwd or /etc/shadow** — if peirates tries to create a user account.
- **Kubeconfig copied** — if `/root/.kube/config` is accessed, it may show in file access logs.

---

## Strongest Target Evidence Signal

**A root-owned process spawning from a container that should be running as non-root, particularly if that process is an exploit binary (peirates, kernel exploit) or a child shell spawned by exploitation.**

This is:
- **Highly suspicious:** Containers should not arbitrarily escalate privileges without `privileged: true` or equivalent configuration.
- **Evasion-resistant:** Occurs at the kernel level; hard to hide from process accounting or container runtime logs.
- **Actionable:** Can be traced back to the specific Pod/container that spawned it via cgroup IDs or namespace analysis.
