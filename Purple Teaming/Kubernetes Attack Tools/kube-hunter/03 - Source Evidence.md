# kube-hunter — Source Evidence

## kube-hunter binary or container image

**Presence of the tool itself is the strongest signal:**

- **Docker image:** `aquasec/kube-hunter` or custom builds
- **Binary:** `/usr/local/bin/kube-hunter`, `/opt/kube-hunter`, or within a container
- **Container registry cache:** If `docker pull kube-hunter` was run, the image is cached locally

```bash
# Check for kube-hunter docker image
docker images | grep kube-hunter

# Check for kube-hunter binary
which kube-hunter
find / -name "*kube-hunter*" 2>/dev/null
```

## kube-hunter configuration files

- **Scan profiles:** `~/.kube-hunter/config` or environment variables
- **Output reports:** `kube-hunter-report.json`, `kube-hunter-report.txt`

## Network connections

If kube-hunter was run, the attacker's workstation will show outbound connections to:
- Port 6443 (Kubernetes API server)
- Port 10250 (kubelet)
- Port 2379 (ETCD)
- Port 10255 (kubelet read-only)

```bash
# Check netstat for these connections
netstat -an | grep -E "6443|10250|2379"

# Check packet capture
tcpdump -i any -w kube-hunter-traffic.pcap port 6443 or port 10250
```

## Shell history

Commands to run kube-hunter would appear in shell history:

```bash
grep "kube-hunter" ~/.bash_history
grep -E "kube-hunter|--remote" ~/.bash_history
```

## Process logs

If auditd or process accounting is enabled:

```bash
ausearch -c kube-hunter
```

---

## Strongest Source Evidence Signal

**The kube-hunter binary itself** — possession of the binary or a container image is highly suspicious and indicates intentional Kubernetes offensive testing. Paired with network connections to port 6443/10250/2379, the evidence is nearly definitive.
