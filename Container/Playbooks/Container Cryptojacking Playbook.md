# Container Cryptojacking Playbook

The most common container incident: an exposed orchestrator or runtime is abused to launch miner containers/pods that consume compute. Detection is easy (pegged CPU); the value is scoping *how* they got in and killing the automation that redeploys the miner.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Identify the Miner](#identify-the-miner)
- [Scope the Entry Point](#scope-the-entry-point)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Red Flags](#red-flags)

## Attack Chain

Exposed Docker API (2375) / exposed Kubernetes API / compromised registry or CI → attacker launches a miner container or pod (often from a public image) → miner pins CPU and connects to a pool → a deployment/daemonset/cronjob (K8s) or a `--restart=always` container (Docker) redeploys it when killed.

## Quick Triage

```bash
# Docker: pegged-CPU containers
docker stats --no-stream | sort -k3 -hr | head

docker ps --format '{{.Names}}\t{{.Image}}' | grep -Ei "xmrig|miner|monero|nicehash|<unknown-registry>"

# Kubernetes: miner pods / high-CPU
kubectl top pods -A 2>/dev/null | sort -k3 -hr | head

kubectl get pods -A -o wide | grep -Ei "xmrig|miner|kdevtmpfsi"

# Host: the miner process under a container cgroup
ps -eo pid,%cpu,cgroup,cmd --sort=-%cpu | head
```

## Identify the Miner

```bash
# Docker: what is the container running + its host PID
docker top <container>; docker inspect -f '{{.State.Pid}} {{.Config.Image}} {{.Config.Cmd}}' <container>

# Recover the miner binary from the host (see Runtime Triage / Memory)
PID=$(docker inspect -f '{{.State.Pid}}' <container>); cp /proc/$PID/exe /evidence/miner.bin

# Pool connection + wallet
ss -tnp | grep $PID; tr '\0' '\n' < /proc/$PID/environ | grep -Ei "pool|wallet|stratum"

# K8s: the pod spec + image
kubectl get pod <pod> -n <ns> -o yaml | grep -Ei "image:|command|args"
```

🔴 Miner containers often run known images (`xmrig`, disguised base images) with the pool/wallet in the command args or env. Capture the wallet + pool before deleting the workload.

## Scope the Entry Point

The miner is the payload — find the exposed door.

```bash
# Docker: is the API exposed unauthenticated? (2375/2376)
ss -ltnp | grep -E ":2375|:2376"; grep -i "hosts" /etc/docker/daemon.json

docker events --since 48h | grep -Ei "create|start|pull"       # who launched it

# Kubernetes: how was it deployed + by whom
kubectl get deploy,daemonset,cronjob -A | grep -Ei "miner|<suspect>"

jq 'select(.objectRef.resource=="pods" and .verb=="create")' /var/log/kubernetes/audit/audit.log 2>/dev/null

# Anonymous API access?
jq 'select(.user.username | test("anonymous|unauthenticated"))' /var/log/kubernetes/audit/audit.log 2>/dev/null
```

🔴 Common entry points: Docker API bound to `0.0.0.0:2375` with no auth, an anonymously-accessible Kubelet/API server, a leaked kubeconfig/SA token, or a poisoned image from CI.

## Timeline

```bash
# Docker: creation time of the miner container
docker inspect -f '{{.Created}} {{.State.StartedAt}}' <container>

# K8s: pod creation + the audit entry that created it
kubectl get pod <pod> -n <ns> -o jsonpath='{.metadata.creationTimestamp}'

jq 'select(.objectRef.name=="<pod>")' /var/log/kubernetes/audit/audit.log 2>/dev/null | head
```

## Eradication

```bash
# Kill the AUTOMATION first so it can't redeploy
# Docker: remove the restart policy / the creating cron/script
docker update --restart=no <container>; docker rm -f <container>

# Kubernetes: delete the controller, not just the pod (pods respawn)
kubectl delete deployment/<name> daemonset/<name> cronjob/<name> -n <ns>

kubectl delete pod <pod> -n <ns>

# Close the entry point: bind Docker API to localhost + TLS, restrict API/RBAC
```

🔴 Deleting the pod/container alone fails — a Deployment/DaemonSet/CronJob (K8s) or a `restart=always` policy / cron on the host redeploys it. Remove the controller/automation first.

## Credential Reset

- Rotate any exposed Docker API / registry credentials.
- Rotate the compromised kubeconfig and service-account tokens (see Kubernetes note).
- If the miner image came from your registry, rotate registry creds and rebuild from a clean base.

## Fleet Hunt

IOCs: miner image name/digest, wallet, pool IP/domain, the deployment/pod naming pattern.

```bash
# Same image running elsewhere
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | grep -i <miner_image>

# Pool connection from any node/container
ss -tunap | grep -E "<pool_ip>|:3333|:14444"

# Exposed Docker APIs across hosts
for h in <hosts>; do ssh "$h" 'ss -ltn | grep -E ":2375|:2376"'; done
```

## Red Flags

| Finding | Meaning |
|---------|---------|
| Container/pod pegging CPU + pool connection | Active mining |
| Miner image from a public/unknown registry | Malicious workload |
| Docker API on `0.0.0.0:2375` unauthenticated | Wide-open entry point |
| Anonymous pod-create in K8s audit log | API-server misconfig |
| Deployment/DaemonSet redeploying the miner | Automation must be removed |
| Same wallet/pool across cluster | Campaign-wide |
