# Supply Chain Security and Image Scanning Forensics

Investigation of container image supply chain attacks, malicious image detection, artifact provenance, and forensic analysis of image signatures, vulnerability scanning, and build pipeline integrity. Covers detection of backdoored images, compromised registries, unsigned artifacts, and supply-chain lateral movement.

---

## Quick Triage

```bash
# List all images in use on cluster
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\n"}{end}' | sort | uniq

# Check image signatures and digests
docker inspect [image_name] | jq '.RepoDigests, .Layers'

# Scan image for vulnerabilities (using Trivy)
trivy image --severity HIGH,CRITICAL [image_name]

# Audit image registry access logs
cat /var/lib/docker/image/overlay2/repositories.json | jq '.repositories' | grep -i "pull\|push"

# Check for unsigned images (if Notary/Cosign configured)
cosign verify [image_name]

# Timeline: when was image pulled/pushed?
stat /var/lib/docker/overlay2/*/diff/manifest.json | grep Modify
```

---

## Container Image Architecture and Forensics

### Image Structure and Layers

A container image consists of:

1. **Configuration Blob (config.json)** — JSON metadata: environment variables, entrypoint, workdir, labels
2. **Layer Tarballs** — Filesystem changes stacked on top of each other
3. **Manifest (manifest.json)** — Pointer to config and layer digests, image metadata
4. **Image Index (optional)** — References multiple platform-specific manifests (ARM64, AMD64, etc.)

**Forensic implications:**
- Each layer is immutable; changes are additive layers
- Image digest (SHA256 of manifest) proves tampering (if digest doesn't match expected)
- Layer order matters; malicious layer can shadow legitimate files in earlier layers
- Entrypoint/CMD in config may trigger malicious code silently

### Image Digest and Immutability

```
Image ID (digest): sha256:1a2b3c4d5e6f7g8h...
  ├── Manifest Digest: sha256:a1b2c3d4e5f6g7h8...
  │   ├── Config Digest: sha256:cfg1cfg2cfg3...
  │   └── Layers: [sha256:layer1, sha256:layer2, ...]
  └── Tag: myregistry.com/myapp:v1.2.3 (points to above digest)
```

**Investigation note:** An attacker can push a malicious image with the same tag (tag overwriting); digest verification catches this because the new image has a different SHA256.

---

## Supply Chain Attack Vectors

### Vector 1: Compromised Registry

**Scenario:** Attacker gains access to container registry (Docker Hub, ECR, ACR, GCR) and pushes malicious images.

**Forensic evidence:**
- Registry audit logs (who pushed what, when)
- Image manifest history (older manifests may show legitimate vs malicious)
- Layer timeline (when were malicious layers added)
- Image signatures (missing or forged signatures = red flag)

**Investigation workflow:**

```bash
# Step 1: Query registry API for image history
curl -H "Authorization: Bearer [token]" \
  https://registry.example.com/v2/myapp/tags/list

# Step 2: Extract manifest of pushed image
curl -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
  https://registry.example.com/v2/myapp/manifests/v1.2.3

# Step 3: Verify image signature (if using Cosign/Notary)
cosign verify --key cosign.pub myregistry.com/myapp:v1.2.3

# Step 4: Compare digests
# If image was re-signed by attacker (new digest), you need to:
#  - Check image signing certificate (who signed it?)
#  - Correlate with CI/CD logs (was this version legitimately built?)

# Step 5: Timeline
# Pull audit logs: when did users/services pull the malicious image?
kubectl get events -A | grep "pulling image"
```

### Vector 2: Backdoored Base Image

**Scenario:** Attacker supplies a malicious base image (e.g., `library/ubuntu:latest`); developers unknowingly inherit the backdoor.

**Forensic evidence:**
- Dockerfile history (which base image was used?)
- Build cache (intermediate layers from base image)
- Base image manifest comparison (legitimate vs backdoored version)

**Investigation workflow:**

```dockerfile
# Vulnerable Dockerfile (unknowingly uses backdoored base)
FROM ubuntu:latest    # ← May be compromised
RUN apt-get install -y package1
COPY app /app
CMD ["/app/start.sh"]
```

**Detect:**

```bash
# Step 1: Extract Dockerfile from image
docker history myapp:latest

# Step 2: Verify base image digest
# Legitimate: sha256:abc123...
# Backdoored: sha256:def456...
docker inspect ubuntu:latest | jq '.RepoDigests'

# Step 3: Scan base image for known vulnerabilities
trivy image ubuntu:latest --list-all-pkgs

# Step 4: Extract base image layers and inspect
docker save ubuntu:latest | tar -x
strings layer.tar | grep -i "backdoor\|/etc/rc.local\|crontab"
```

### Vector 3: Sidecar Injection in Build Pipeline

**Scenario:** Attacker compromises build system (CI/CD platform) and injects malicious layer during build.

**Forensic evidence:**
- Build logs (what commands were run during build?)
- Dockerfile vs actual image (does the image match what Dockerfile specifies?)
- Layer content comparison (which layer contains the payload?)
- Build artifact storage (where are builds cached?)

**Investigation workflow:**

```bash
# Step 1: Get build logs from CI/CD system
# (GitHub Actions, GitLab CI, Jenkins, etc.)
# Look for: unusual docker build flags, extra RUN commands, secrets exposure

# Step 2: Rebuild image locally from source (reproducible build)
git clone https://github.com/myorg/myapp.git
docker build -t myapp:v1.2.3 .

# Step 3: Compare digests
# Legitimate (locally built): sha256:abc123...
# Deployed (CI/CD built): sha256:def456...
# If digests differ → build pipeline was compromised

# Step 4: Layer-by-layer comparison
docker inspect myapp:v1.2.3 | jq '.RootFS.Layers'
# Extract malicious layer:
docker save myapp:v1.2.3 | tar -x
# Find which layer differs from expected
sha256sum layer.tar >> compare.txt
```

### Vector 4: Configuration Tampering (Entrypoint/CMD)

**Scenario:** Attacker creates image that looks legitimate but executes malicious code via modified entrypoint.

**Forensic evidence:**
- Image config (CMD/ENTRYPOINT/ENV variables)
- Runtime behavior (what process actually runs?)
- Layer content (where does the payload live?)

**Investigation:**

```bash
# Step 1: Extract image config
docker inspect myapp:latest | jq '.Config.Cmd, .Config.Entrypoint, .Config.Env'

# Step 2: Compare with expected (check source Dockerfile)
cat Dockerfile | grep "ENTRYPOINT\|CMD"

# Step 3: If config differs → tampering detected
# Example:
# Legitimate: ENTRYPOINT ["python3", "app.py"]
# Backdoored: ENTRYPOINT ["bash", "-c", "/tmp/payload.sh && python3 app.py"]

# Step 4: Extract and analyze payload
docker create --name temp myapp:latest bash
docker cp temp:/tmp/payload.sh ./
# Analyze payload for C2, data theft, persistence, etc.
strings payload.sh | grep -i "curl\|wget\|nc\|bash"
```

---

## Advanced Image Forensics

### Extracting and Analyzing Image Layers

```bash
# Step 1: Save image to TAR
docker save myapp:latest -o myapp.tar

# Step 2: Extract and inspect
tar -xf myapp.tar
ls -la
# Output:
# blobs/ (layer content)
# index.json (manifest)
# repositories/ (tags)

# Step 3: Extract individual layers
cd blobs/sha256
tar -xzf [layer-digest] -C /tmp/layer-analysis

# Step 4: Search for red flags in each layer
strings /tmp/layer-analysis/etc/crontab | grep -i "curl\|sh\|nc"
find /tmp/layer-analysis -name "*.so" -o -name "*.o" -exec strings {} \; | grep -i "backdoor"

# Step 5: Verify file integrity (if legitimate image available for comparison)
ls -la /tmp/layer-analysis/usr/bin | wc -l
# Compare against known-good image layer count
```

### Container Filesystem Forensics

**Once a backdoored image is running, extract evidence from container:**

```bash
# Step 1: Identify running container from malicious image
docker ps --no-trunc | grep myapp

# Step 2: Export container filesystem
docker export [container_id] -o container_fs.tar

# Step 3: Extract and analyze
tar -xf container_fs.tar
cd .

# Step 4: Hunt for persistence mechanisms
find . -name "authorized_keys" -o -name ".ssh"
find . -name "crontab" -o -name "at.allow"
find . -name "rc.local" -o -name "systemd" -type d

# Step 5: Timeline analysis
stat . -c "%y %a %n" | sort -k1,2

# Step 6: Carving (find deleted files)
scalpel container_fs.tar
```

---

## Image Signature and Artifact Verification

### Cosign Image Signing

**Legitimate workflow:**

```bash
# Sign image during build
cosign sign --key cosign.key myregistry.com/myapp:v1.2.3

# Verify image signature before deployment
cosign verify --key cosign.pub myregistry.com/myapp:v1.2.3

# Check signature metadata
cosign verify --key cosign.pub --output json myregistry.com/myapp:v1.2.3 | jq '.critical'
```

**Forensic investigation:**

```bash
# Step 1: Verify signature matches expected signing key
cosign verify --key cosign.pub myapp:v1.2.3
# Output shows: was this signed by the legitimate key?

# Step 2: Check signature timestamp (when was it signed?)
cosign verify --key cosign.pub myapp:v1.2.3 | jq '.critical.image.docker-manifest-digest, .critical.timestamp'

# Step 3: Detect signature forgery
# If image signature verifies but digest doesn't match expected → key was compromised
Expected digest: sha256:abc123...
Actual digest: sha256:def456...
Signature valid: YES
→ Attacker has signing key

# Step 4: Check certificate chain
cosign verify-blob-attestation --blob-ref myapp:v1.2.3 --certificate cosign.crt
```

### Notary Delegation Forensics

```bash
# List all signed roles for image
notary delegation list myregistry.com/myapp

# Check delegation keys (who has authority to sign releases?)
notary key list

# Timeline: when was role compromised?
notary lookup myregistry.com/myapp v1.2.3
# Shows: signature timestamp, signer role, whether role was compromised
```

---

## Vulnerability Scanning and SBOM Forensics

### Trivy Vulnerability Scanning

```bash
# Scan image for vulnerabilities
trivy image --severity HIGH,CRITICAL --list-all-pkgs myapp:v1.2.3 > scan-result.json

# Export SBOM (Software Bill of Materials)
trivy image --format spdx myapp:v1.2.3 > sbom.spdx.json

# Check for known vulnerable packages
jq '.results[].target' scan-result.json | grep -i "openssl\|glibc\|curl"

# Timeline: when were vulnerable packages introduced?
# Compare SBOM from multiple image versions
diff <(jq '.packages' sbom-v1.2.2.json) <(jq '.packages' sbom-v1.2.3.json)
# If new vulnerable package in v1.2.3 → red flag
```

**Red flags in SBOM:**

```json
{
  "package": "openssl",
  "version": "1.0.2k",  // ← OLD, known vulnerable version
  "fixed_version": "1.1.1",
  "severity": "CRITICAL",
  "cve": ["CVE-2019-1547", "CVE-2019-1563"]
}
```

### Grype (Alternative Scanner)

```bash
# Scan with Grype (good for binary packages)
grype myapp:v1.2.3 -o json > grype-report.json

# Compare with Trivy
diff <(trivy image myapp:v1.2.3 -o json) <(grype myapp:v1.2.3 -o json)
# Look for discrepancies (one scanner may miss issues)
```

---

## Registry and Build System Forensics

### Container Registry Audit Logs

**Docker Registry v2 (Docker Hub, Private Registry):**

```bash
# Pull events from Docker Hub API
curl -H "Authorization: Bearer [token]" \
  https://hub.docker.com/v2/repositories/[org]/[repo]/tags/?page_size=100

# Check push/pull history (if available)
docker pull [image] --log-level debug 2>&1 | grep "Pulling\|Downloaded"

# Check registry database for push timestamps
# (If using private Docker Registry, check database directly)
sqlite3 /var/lib/docker-registry/registry.sqlite \
  "SELECT * FROM blobs WHERE digest LIKE 'sha256:%';"
```

**AWS ECR (Elastic Container Registry):**

```bash
# List image history
aws ecr describe-image-detail --repository-name myapp --region us-east-1

# Check image tags and push timestamps
aws ecr describe-images --repository-name myapp \
  --query 'imageDetails[*].[imageTags, imagePushedAt]' --output table

# Pull image scan results
aws ecr describe-image-scan-findings --repository-name myapp --image-id imageTag=v1.2.3
```

**Azure ACR (Container Registry):**

```bash
# List push history
az acr repository show --name myregistry --repository myapp

# Check image tags
az acr repository show-tags --name myregistry --repository myapp --output table

# Scan for vulnerabilities
az acr image scan --registry myregistry --image myapp:v1.2.3
```

### CI/CD Build Pipeline Forensics

**GitHub Actions workflow compromises:**

```bash
# Check Actions logs
gh run list -R org/repo --limit 100

# Export workflow run logs
gh run view [run-id] -R org/repo --log

# Analyze Dockerfile changes in pull requests
gh pr list -R org/repo --state merged --search "Dockerfile" | head -20

# Check for suspicious secrets exposure in logs
gh run view [run-id] -R org/repo --log | grep -i "password\|secret\|token"
```

**GitLab CI pipeline investigation:**

```bash
# Check pipeline history
gitlab pipeline list --project org/repo --all

# Export job logs
gitlab pipeline-job artifacts --project org/repo --job-id [id]

# Check for build artifact tampering
gitlab artifact list --project org/repo --pipeline-id [id]
```

**Jenkins build investigation:**

```bash
# Check build logs
curl -u user:token http://jenkins.example.com/job/myapp/[build_id]/consoleText

# Analyze Jenkinsfile changes
git log -p Jenkinsfile | grep -B5 -A5 "docker\|build"

# Check artifact storage
ls -la /var/lib/jenkins/jobs/myapp/builds/[build_id]/archive/
```

---

## Detection and Response

### Image Scanning Automation

**Falco Rules: Detect Malicious Image Execution**

```yaml
- rule: Suspicious Image Deployment
  desc: Detect deployment of unsigned or vulnerable images
  condition: |
    k8s_audit and 
    (verb == "create" or verb == "patch") and 
    objectRef.resource == "pods" and 
    image_unsigned
  output: Unsigned image deployed (image=%image signed=%signed vulnerability_count=%vuln_count)
  priority: CRITICAL
```

**Admission Controller: Block Unsigned Images**

```yaml
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: image-signature-verification
webhooks:
- name: verify-image-signatures.example.com
  clientConfig:
    service:
      name: image-verifier
      namespace: kube-system
      path: "/verify"
  rules:
  - operations: ["CREATE"]
    apiGroups: [""]
    apiVersions: ["v1"]
    resources: ["pods"]
  failurePolicy: Fail
```

### Incident Response Checklist

- [ ] Identify malicious image digest and tags
- [ ] Query registry logs: who pulled/pushed the malicious image?
- [ ] Timeline: when was image built/pushed? Correlation with CI/CD pipeline compromise
- [ ] List all clusters/pods running the malicious image
- [ ] Identify containers spawned from the malicious image (docker ps, kubectl get pods)
- [ ] Extract container filesystem and analyze for payload, persistence, exfiltration
- [ ] Check image signatures (was image legitimately signed? If yes, signing key is compromised)
- [ ] Audit RBAC in registries (who has write access? Who escalated recently?)
- [ ] Review CI/CD pipeline logs (when/how was malicious image built?)
- [ ] Revoke compromised registry credentials and rebuild CI/CD signing keys
- [ ] Update admission controller policies to enforce signature verification
- [ ] Scan all images in registries for known payload signatures (YARA)
- [ ] Correlate image push events with system events (lateral movement, data exfil)

---

## References

- **OCI Image Spec:** https://github.com/opencontainers/image-spec
- **Cosign Documentation:** https://docs.sigstore.dev/cosign/
- **Notary Project:** https://github.com/notaryproject/notary
- **Trivy Vulnerability Scanner:** https://github.com/aquasecurity/trivy
- **Falco Container Security:** https://falco.org/
- **SLSA Framework (Supply Chain Levels for Software Artifacts):** https://slsa.dev/

---

## Forensic Workflow: Complete Supply Chain Investigation

### Phase 1: Detection
- Alerts: unsigned image deployed, vulnerability scan fails, image signature verification fails

### Phase 2: Scope
- Query registry: all instances of malicious image tag
- Query Kubernetes: all pods running malicious image
- Query CI/CD: when/how was image built?

### Phase 3: Evidence Collection
- Export registry manifests and layer digests
- Export Kubernetes events (when pods were created/updated)
- Export CI/CD build logs and artifact metadata
- Export container filesystems from running pods
- Export registry audit logs

### Phase 4: Analysis
- Compare digests (legitimate vs malicious)
- Layer analysis (which layer contains payload?)
- Timeline correlation (build time → push time → deployment time)
- Signature verification (was image legitimately signed?)

### Phase 5: Attribution
- Identify who pushed malicious image (registry audit log)
- Identify when image was built (CI/CD timestamp)
- Identify if signing key was compromised (signature valid but digest wrong)

### Phase 6: Remediation
- Revoke compromised registry credentials
- Rebuild all images from known-good source
- Audit RBAC and signing key access
- Force pod re-deployment with verified images
