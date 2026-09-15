# Backdoored Image Playbook

A container image carries the malware — a poisoned public base image, a typosquat, or a trojaned build from compromised CI. The workload behaves maliciously from first run because the payload is baked in. Investigation centers on layer analysis and provenance.

## Contents

- [Attack Chain](#attack-chain)
- [Quick Triage](#quick-triage)
- [Confirm the Image Is Malicious](#confirm-the-image-is-malicious)
- [Find the Malicious Layer](#find-the-malicious-layer)
- [Trace Provenance](#trace-provenance)
- [Scope Runtime Impact](#scope-runtime-impact)
- [Timeline](#timeline)
- [Eradication](#eradication)
- [Credential Reset](#credential-reset)
- [Fleet Hunt](#fleet-hunt)
- [Red Flags](#red-flags)

## Attack Chain

A malicious image enters the environment (typosquatted/poisoned public image, or CI pushes a trojaned build) → it's pulled and run → the baked-in payload executes on start (miner in ENTRYPOINT, second-stage fetch, planted SSH key, in-image cron) → persistence/exfil/mining, often across every host that runs the image.

## Quick Triage

```bash
# What images are running + their digests (pin, don't trust tags)
docker ps --format '{{.Names}}\t{{.Image}}' ; docker images --digests

# Build history reveals baked-in payloads
docker history --no-trunc <image>

# Entrypoint / Cmd / Env that runs on start
docker inspect -f 'Entrypoint={{.Config.Entrypoint}} Cmd={{.Config.Cmd}} Env={{.Config.Env}}' <image>

# K8s
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort -u
```

## Confirm the Image Is Malicious

```bash
# Suspicious build steps (curl|bash, ADD of a binary, C2 in ENV)
docker history --no-trunc <image> | grep -Ei "curl|wget|base64|http|chmod|ADD|COPY"

# Behaviour on start: what did the running container write + say
docker diff <container>; docker logs <container> | grep -Ei "curl|wget|stratum|/dev/tcp|token"

# Scanner second opinion (then confirm by hand)
trivy image <image>; trivy image --scanners secret <image>
```

🔴 A `RUN curl … | bash`, an ENTRYPOINT that fetches a second stage, an added `authorized_keys`, or a miner binary in a layer confirms the image is the malware.

## Find the Malicious Layer

```bash
# Save + unpack to inspect layers offline
docker save <image> -o image.tar; mkdir img && tar -xf image.tar -C img

# dive shows exactly which layer added each file
dive <image>

# Flatten and hunt for backdoors
mkdir root && for l in img/*/layer.tar; do tar -xf "$l" -C root 2>/dev/null; done
find root -name authorized_keys -o -path "*cron*" -type f 2>/dev/null
grep -rEl "xmrig|stratum|/dev/tcp|base64 -d|curl.*sh" root/ 2>/dev/null
find root -type f -perm -4000 -ls 2>/dev/null      # SUID backdoor
cat root/entrypoint.sh root/*entrypoint* 2>/dev/null
```

## Trace Provenance

```bash
# Where was it pulled from? (registry + digest)
docker inspect -f '{{.RepoDigests}}' <image>

cat /var/lib/docker/image/overlay2/repositories.json | python3 -m json.tool

# Registry config + creds (was it your registry or a public/attacker one?)
cat ~/.docker/config.json 2>/dev/null; grep -Ei "registry|insecure" /etc/docker/daemon.json 2>/dev/null

# K8s: which image ref + pull secrets
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].image}'; kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.imagePullSecrets}'
```

🔴 Determine whether the image came from your trusted registry (→ CI/registry compromise) or a public/typosquatted source (→ someone pulled a bad image). That decides how far the supply-chain investigation goes.

## Scope Runtime Impact

```bash
# Every host/pod running the malicious image or digest
docker ps -a --filter ancestor=<image>

kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" "}{.spec.containers[*].image}{"\n"}{end}' | grep <image>

# Did the payload escape / write to the host? (see Escapes note)
find /etc/cron* /root/.ssh /etc/systemd/system -newermt "<incident>" -ls 2>/dev/null
```

## Timeline

```bash
# When the image was pulled + containers created
docker inspect -f '{{.Created}}' <image>; docker inspect -f '{{.Created}} {{.Name}}' $(docker ps -aq --filter ancestor=<image>)

# In CI, correlate the build/push time from pipeline logs
```

## Eradication

```bash
# Stop + remove every workload using the image, then delete the image
docker ps -aq --filter ancestor=<image> | xargs -r docker rm -f
docker rmi <image>

# K8s: delete the controllers running it, quarantine the image in the registry
kubectl delete deploy,ds -A -l <selector>

# Remove any host persistence the payload dropped (Linux Remediation note)
# Rebuild from a known-good base + pin to digests going forward
```

## Credential Reset

- Rotate registry credentials (esp. if a trojaned image was pushed to your registry → CI compromise).
- Rotate any secrets the running container could read (env vars, mounted secrets).
- If CI was the source, treat the CI/CD system as compromised and rotate its credentials/keys.

## Fleet Hunt

IOCs: image name + digest, baked-in payload hash, C2/pool, planted SSH key.

```bash
# The image digest anywhere in the fleet
kubectl get pods -A -o json | jq -r '.items[].status.containerStatuses[]?.imageID' | grep <digest>

for h in <hosts>; do ssh "$h" "docker images --digests | grep <digest>"; done
```

## Red Flags

| Finding | Meaning |
|---------|---------|
| `docker history` shows `curl\|bash` / ADD of a binary | Payload baked into image |
| ENTRYPOINT fetches a second stage on start | Image-borne dropper |
| authorized_keys / cron / SUID inside the image | Persistent backdoor in the image |
| Image from a public/typosquatted registry | Supply-chain deception |
| Trojaned image in your own registry | CI/CD compromise |
| Same malicious digest across many hosts | Wide blast radius |
