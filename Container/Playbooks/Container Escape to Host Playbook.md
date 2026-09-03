# Container Escape to Host Playbook

A process breaks out of its container to the underlying node — via a misconfiguration (privileged, docker.sock, host mount) or a runtime/kernel exploit. Once out, it's a normal Linux host compromise, so this playbook bridges into the Linux notes.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Determine the Escape Vector](#determine-the-escape-vector)
- [Confirm the Escape Happened](#confirm-the-escape-happened)
- [Scope the Host and Cluster](#scope-the-host-and-cluster)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Red Flags](#red-flags)

## Attack Chain

Attacker controls a container (app RCE, malicious image) → uses a misconfig (privileged, `docker.sock`, host mount, dangerous cap, cgroup `release_agent`) or a CVE (runc overwrite, Dirty Pipe, leaky vessels) → gains code execution on the **node** → establishes host persistence → on a K8s node, pivots to other pods / the kubelet / cluster credentials.

## Quick Triage

```bash
# Escape-capable containers on the host
docker ps -aq | xargs -r docker inspect -f '{{.Name}} priv={{.HostConfig.Privileged}} caps={{.HostConfig.CapAdd}} binds={{.HostConfig.Binds}} pid={{.HostConfig.PidMode}}' 2>/dev/null | grep -E "true|/:/|:/host|docker.sock|SYS_ADMIN|SYS_PTRACE|DAC_READ"

# Host persistence created in the incident window (the escape's footprint)
find /etc/cron* /etc/systemd/system /root/.ssh /etc/ld.so.preload -newermt "3 hours ago" -ls 2>/dev/null

# cgroup release_agent abuse
find /sys/fs/cgroup -name release_agent -exec cat {} \; 2>/dev/null

# runc integrity (CVE-2019-5736)
which runc | xargs -r dpkg -V 2>/dev/null; which runc | xargs -r rpm -Vf 2>/dev/null
```

## Determine the Escape Vector

```bash
# Config-based (the container was misconfigured) - see Escapes note
docker inspect -f '{{json .HostConfig}}' <container> | python3 -m json.tool | grep -Ei "privileged|capadd|binds|pidmode|networkmode"

# docker.sock mounted in?
grep -r "docker.sock" /var/lib/docker/containers/*/hostconfig.json 2>/dev/null

# Exploit-based - check versions against known CVEs
runc --version; docker version | grep -i version; uname -r
```

| Vector | Evidence |
|--------|----------|
| Privileged / host mount / docker.sock | `hostconfig.json` shows it |
| Dangerous capability | `CapAdd` has SYS_ADMIN/SYS_PTRACE/DAC_READ_SEARCH |
| cgroup release_agent | `release_agent` points at a container/temp path |
| runc overwrite (CVE-2019-5736) | `runc` binary fails package verification |
| Dirty Pipe / kernel | vulnerable kernel + unexpected root-file writes |

## Confirm the Escape Happened

🔴 The proof is host-level activity attributable to the container.

```bash
# Host files written during container activity, esp. from the container's mapped UID
find / -xdev -newermt "<container_start>" ! -newermt "now" -type f 2>/dev/null | grep -vE "/proc|/sys|/var/lib/docker" | head

# A host process parented by the container shim/runc doing host work
ps -eo pid,ppid,cmd --forest | grep -A5 -E "containerd-shim|runc"

# New host persistence (cron/systemd/ssh/ld.so.preload)
cat /etc/ld.so.preload 2>/dev/null
find /etc/cron* /etc/systemd/system -newermt "<container_start>" -ls 2>/dev/null
find / -name authorized_keys -newermt "<container_start>" -exec cat {} \; 2>/dev/null
```

## Scope the Host and Cluster

Once escaped, treat it as a full host compromise (Linux notes) and, on a K8s node, a potential cluster incident.

```bash
# Host: full persistence + volatile sweep (Linux Persistence + Live Response notes)
ps auxww | grep -Ei "/tmp|/dev/shm|memfd"; ss -tunap | grep -v 127.0.0.1; cat /proc/sys/kernel/tainted

# K8s node: was the kubelet / static-pod dir / node creds touched?
ls -la /etc/kubernetes/manifests/ /var/lib/kubelet/
cat /var/lib/kubelet/pki/kubelet-client-current.pem 2>/dev/null | head -1     # node cert (theft target)
```

## Timeline

```bash
# Container start -> escape artifact -> host persistence
docker inspect -f '{{.State.StartedAt}} {{.Name}}' <container>
# then align host file mtimes + daemon/audit events around it
```

## Eradication

```bash
# Remove the container + fix the misconfig (drop privileged, unmount docker.sock/host paths)
docker rm -f <container>

# Remove host persistence (Linux Remediation note) - chattr -i first if locked
sudo chattr -i <locked>; sudo rm <host_persistence>

# Patch runc/docker/kernel if an exploit was used
# If a kernel exploit or unknown scope: rebuild the node
```

🔴 If the escape used a kernel exploit, or scope is uncertain, **rebuild the node** — a node-level compromise can hide from in-place cleanup (see Linux Remediation).

## Credential Reset

- Rotate everything on the node: SSH keys, cloud creds, app secrets.
- On a K8s node: rotate the **kubelet client cert** and any node/SA credentials the attacker could read — a node compromise can become a cluster compromise (pivot to the Kubernetes Cluster Compromise playbook).

## Fleet Hunt

IOCs: the escape-capable image/config pattern, planted host persistence, dropped binary hash.

```bash
# Other hosts running privileged / docker.sock-mounting containers
for h in <hosts>; do ssh "$h" 'docker ps -q | xargs -r docker inspect -f "{{.Name}} {{.HostConfig.Privileged}} {{.HostConfig.Binds}}" 2>/dev/null | grep -E "true|docker.sock|/:/"'; done

# Same planted key / persistence elsewhere
grep -rl "<attacker_pubkey>" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys 2>/dev/null
```

## Red Flags

| Finding | Meaning |
|---------|---------|
| Escape-capable container (priv/docker.sock/host mount/cap) | Escape surface present |
| Host persistence created during container activity | Escape succeeded |
| `release_agent` pointing at a container/temp path | Active cgroup escape |
| Modified `runc` binary | CVE-2019-5736 |
| Host process parented by shim/runc doing host work | Break-out in progress |
| Kubelet cert / node creds accessed | Node → cluster pivot |
