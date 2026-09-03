# Exposed Docker API Playbook

The Docker daemon's remote API bound to the network without TLS/auth (typically `2375`) lets anyone create containers on the host — including one that mounts `/` and runs privileged, which is instant host root. A classic internet-wide mass-exploitation target.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Confirm the Exposure](#confirm-the-exposure)
- [Identify Attacker Containers](#identify-attacker-containers)
- [Scope the Host Compromise](#scope-the-host-compromise)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Red Flags](#red-flags)

## Attack Chain

Docker API exposed on `0.0.0.0:2375` (no TLS/auth) → attacker enumerates via the API → runs a container with `-v /:/host` (or `--privileged`) → writes host persistence (cron, SSH key, systemd) via the mount → escapes to full host control → drops a miner/backdoor and moves on.

## Quick Triage

```bash
# Is the API listening on the network unauthenticated?
ss -ltnp | grep -E ":2375|:2376"

grep -i "hosts" /etc/docker/daemon.json /lib/systemd/system/docker.service 2>/dev/null

# Recently created containers (attacker's)
docker ps -a --format '{{.CreatedAt}}\t{{.Names}}\t{{.Image}}\t{{.Command}}' | sort

# Containers mounting the host root / privileged
docker ps -aq | xargs -r docker inspect -f '{{.Name}} binds={{.HostConfig.Binds}} priv={{.HostConfig.Privileged}}' 2>/dev/null | grep -E "/:/|:/host|true"
```

## Confirm the Exposure

```bash
# API bound to a non-loopback address = exposed
ss -ltnp | grep dockerd

# The config that caused it (-H tcp://0.0.0.0:2375)
grep -rE "2375|tcp://0.0.0.0" /etc/docker/daemon.json /etc/systemd/system/docker.service.d/ /lib/systemd/system/docker.service 2>/dev/null

# Daemon log: remote API calls
journalctl -u docker | grep -Ei "api|remote|create|pull" | tail
```

🔴 `dockerd` listening on `0.0.0.0:2375` (or any non-localhost) without TLS = unauthenticated remote root-equivalent. `2376` is the TLS port; verify certs are actually enforced (`--tlsverify`).

## Identify Attacker Containers

```bash
# Newly created containers, sorted by time
docker ps -a --format '{{.CreatedAt}}\t{{.ID}}\t{{.Image}}\t{{.Command}}' | sort

# The dangerous ones: host mount / privileged / host namespaces
for c in $(docker ps -aq); do
  docker inspect -f '{{.Name}} priv={{.HostConfig.Privileged}} binds={{.HostConfig.Binds}} net={{.HostConfig.NetworkMode}} pid={{.HostConfig.PidMode}}' "$c"
done | grep -E "true|/:/|:/host|host"

# What each wrote (overlay diff) + its logs
docker diff <container>; docker logs <container>
```

## Scope the Host Compromise

An API-abuse container almost always writes to the host — treat the host as compromised.

```bash
# Persistence written via a host mount (see Linux Persistence note)
find /etc/cron* /etc/systemd/system /root/.ssh /home/*/.ssh /etc/ld.so.preload -newermt "<incident_start>" -ls 2>/dev/null

# Attacker SSH keys planted on the host
find / -name authorized_keys -newermt "<incident_start>" -exec cat {} \; 2>/dev/null

# Miner/backdoor dropped on the host
ps auxww | grep -Ei "/tmp|/dev/shm|xmrig|kinsing"; ss -tunap | grep -v 127.0.0.1
```

## Timeline

```bash
# Container create times vs host file changes
docker inspect -f '{{.Created}} {{.Name}}' $(docker ps -aq) | sort

# Correlate with host persistence mtimes and daemon log
journalctl -u docker --since "<incident_start>" | grep -i create
```

## Eradication

```bash
# Remove attacker containers + any images they pulled
docker rm -f <attacker_containers>; docker rmi <malicious_images>

# Remove host persistence they planted (see Linux Remediation note)

# Close the API: bind to localhost, require TLS client certs
#   daemon.json: "hosts": ["unix:///var/run/docker.sock"]  (no tcp), or tlsverify with certs
systemctl daemon-reload; systemctl restart docker
```

🔴 Because the host was reachable as root via the mount, remove **host** persistence too, not just the containers — follow the Linux Remediation note. If scope is unclear, rebuild the host.

## Credential Reset

- Rotate every credential/key that lived on the host (SSH host + user keys, cloud creds, app secrets).
- Rotate registry credentials in `~/.docker/config.json`.

## Fleet Hunt

IOCs: attacker image names/digests, planted SSH key, miner wallet/pool, source IPs in the daemon log.

```bash
# Any other host with the Docker API exposed
for h in <hosts>; do ssh "$h" 'ss -ltn | grep -E ":2375|:2376"'; done

# The attacker's container image / SSH key elsewhere
docker images | grep <malicious_image>
grep -rl "<attacker_pubkey>" /home/*/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null
```

## Red Flags

| Finding | Meaning |
|---------|---------|
| `dockerd` on `0.0.0.0:2375` no TLS | Unauthenticated remote root |
| Recently created container with `-v /:/host` or `--privileged` | Host-escape container |
| Host persistence written during container activity | Escape succeeded |
| Attacker container pulling a miner/backdoor image | Post-exploitation payload |
| Multiple hosts with the same exposure | Mass-scan campaign target |
