# kubectl — Overview

> 🔴 **Red Flag Principle:** `kubectl` is the **legitimate Kubernetes CLI** — the upstream, Microsoft/Google/Linux Foundation-blessed command-line interface to Kubernetes clusters. Every single kubectl command an attacker runs is an *expected* API call to the cluster's legitimate control plane. The only difference between a red-team operator and a platform engineer is the **authenticity of the credential** and the **authorization level** the attacker holds. Because legitimate operations are indistinguishable from offensive operations at the API layer, detection must pivot entirely to **credential chain forensics** (How did they get the kubeconfig/token? From where? When?) and **RBAC/audit-logging hygiene** (Does the environment log all API calls? Does RBAC bound credentials to their intended scope?) rather than attempting to blacklist "suspicious" kubectl subcommands.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

`kubectl` (Kubernetes Command-Line Tool) is the **official, upstream command-line interface to Kubernetes clusters**, developed and maintained by the **[Kubernetes Project](https://kubernetes.io/)** under the Linux Foundation. The canonical upstream repository is [`kubernetes/kubernetes`](https://github.com/kubernetes/kubernetes), licensed under **Apache License 2.0**. Verified against the repo and official release metadata:

- **Kubernetes v1.0 (July 2015)** — the first production-ready release of Kubernetes itself, bundled with an initial `kubectl` CLI.
- **Kubernetes v1.8+ (2017)** — RBAC (Role-Based Access Control) became the primary authorization model; Service Account tokens transitioned from legacy bearer tokens to JWT-format tokens (RFC 7519).
- **Kubernetes v1.19+ (August 2020)** — introduction of Audit Logging to the core API server (GA release), making API-call logging standardized across distributions.
- **Kubernetes v1.30+ (current, December 2024)** — ongoing refinement of API groups (`.apps`, `.batch`, `.policy`, `.storage`, `.networking.k8s.io`) and RBAC granularity.

`kubectl` is **not a separate project** — it is the CLI component of the Kubernetes repository itself, compiled directly from the `cmd/kubectl/` directory in the main Kubernetes codebase. Every Kubernetes release ships a corresponding `kubectl` binary for that API version. The tool is installed standalone via package managers (`brew install kubernetes-cli` on macOS, `apt install kubectl` on Debian/Ubuntu, `docker.io/library/alpine:latest` layered with `kubectl`, etc.) or directly from the [official GitHub Releases](https://github.com/kubernetes/kubernetes/releases) page.

At the time of writing, the project carries **100,000+ GitHub stars**, is the de facto standard (only kubectl exists for direct Kubernetes API access), and is actively maintained (commits landing on the main branch multiple times daily).

## How It Works

### Kubernetes API fundamentals — the surface kubectl touches

Verified against the official [Kubernetes API Documentation](https://kubernetes.io/docs/reference/kubernetes-api/) and cross-checked against the current `kubernetes/kubernetes` source:

Kubernetes exposes a **single RESTful HTTP(S) API server** (the **API Server**, running on the control plane). Every object in Kubernetes — Pods, Services, Deployments, ConfigMaps, Secrets, ServiceAccounts, ClusterRoles, ClusterRoleBindings, etc. — is a **REST resource** accessed via standard HTTP verbs (GET, POST, PUT, PATCH, DELETE, WATCH) against a hierarchical URL path structure:

```
https://<API_SERVER>:<PORT>/api/v1/namespaces/<NAMESPACE>/pods/<POD_NAME>
https://<API_SERVER>:<PORT>/apis/apps/v1/namespaces/<NAMESPACE>/deployments/<DEPLOYMENT_NAME>
https://<API_SERVER>:<PORT>/apis/batch/v1/namespaces/<NAMESPACE>/jobs/<JOB_NAME>
https://<API_SERVER>:<PORT>/api/v1/secrets                     # cluster-scoped, no namespace
https://<API_SERVER>:<PORT>/api/v1/nodes                      # cluster-scoped
```

- **API Groups** — collections of related objects. The core group is `/api/v1` (Pods, Services, Nodes, Namespaces, Secrets, ConfigMaps, ServiceAccounts, PersistentVolumes, etc.). Extension groups have their own versioned path: `/apis/apps/v1` (Deployments, StatefulSets, DaemonSets), `/apis/batch/v1` (Jobs, CronJobs), `/apis/policy/v1` (PodDisruptionBudgets, NetworkPolicies), `/apis/storage.k8s.io/v1` (StorageClasses, PersistentVolumeClaims), etc.
- **Verbs** (HTTP methods) — GET (retrieve), POST (create), PUT (replace entire object), PATCH (modify in-place), DELETE (remove), LIST (enumerate all), WATCH (stream changes), DELETECOLLECTION (bulk delete).
- **RBAC enforcement** — the API server's **Admission Controller** intercepts every request, checks the requestor's identity and their ClusterRole/Role bindings, and either permits or denies the operation before any state change occurs.

### kubeconfig: the credential file

Every `kubectl` invocation reads a **`kubeconfig` file** (by default `~/.kube/config`, or specified by `--kubeconfig` or the `KUBECONFIG` environment variable) containing:

```yaml
apiVersion: v1
kind: Config
clusters:
  - name: production-cluster
    cluster:
      server: https://api.production.example.com:6443
      certificate-authority-data: LS0tLS1CRUdJTi... # Base64-encoded CA cert
contexts:
  - name: prod-admin
    context:
      cluster: production-cluster
      user: admin@production
      namespace: default
current-context: prod-admin
users:
  - name: admin@production
    user:
      client-certificate-data: LS0tLS1CRUdJTi... # Base64-encoded client cert
      client-key-data: LS0tLS1CRUdJTi...         # Base64-encoded client key
```

The kubeconfig names:
- **clusters** — API server endpoints and their CA certificates (TLS trust anchors).
- **users** — authentication credentials (client certificates, bearer tokens, basic auth, OIDC, etc.).
- **contexts** — pairings of a cluster + user + optional default namespace.
- **current-context** — which context to use by default on the next `kubectl` command.

`kubectl` uses **mutual TLS** by default: the client loads the user's certificate/key pair and the cluster's CA certificate, then opens an authenticated, encrypted HTTPS connection to the API server. The API server verifies the client cert against its CA and extracts the client's identity from the cert's CN (Common Name) and O (Organization) fields to determine RBAC authorization.

### ServiceAccount tokens: the in-cluster credential

When a Pod is deployed on a Kubernetes node, the node's **kubelet** automatically mounts a **ServiceAccount token** into the Pod's filesystem at `/var/run/secrets/kubernetes.io/serviceaccount/token`. This token is a **JWT (JSON Web Token, RFC 7519)** signed by the API server itself, containing claims including the Pod's namespace and ServiceAccount name. The Pod uses this token to authenticate to the API server — it sends the token as a Bearer token in the HTTP Authorization header of API requests:

```bash
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IkR...
```

The API server verifies the JWT's signature, extracts the ServiceAccount identity from the claims, and applies RBAC rules to determine what the Pod is allowed to do.

This is the **most common credential an attacker targets** once they've achieved initial container breakout — the in-cluster token.

### RBAC: the authorization layer

Kubernetes implements **Role-Based Access Control (RBAC)** as its standard authorization model (enabled by default in most distributions). Every API request is checked against ClusterRole/ClusterRoleBinding or Role/RoleBinding objects:

- **ClusterRole** — a collection of API permissions scoped to the entire cluster (e.g., "list all Pods in any namespace," "read all Secrets everywhere," "create new Deployments").
- **Role** — the namespace-scoped equivalent (e.g., "list Pods in the 'production' namespace only").
- **ClusterRoleBinding** — assigns a ClusterRole to a user/group/ServiceAccount.
- **RoleBinding** — assigns a Role to a user/group/ServiceAccount within a namespace.

A ClusterRole entry looks like:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["admin-secret"]  # optional: restrict to named resource
```

An attacker with a ServiceAccount token can run `kubectl --token <token> auth can-i <verb> <resource>` to check what they're authorized to do, or just attempt an action and get an `Error from server (Forbidden): <resource> is forbidden: User "system:serviceaccount:default:my-sa" cannot <verb> <resource> in the namespace "default"` response.

### Kubernetes API audit logging

When enabled (often via a cluster-wide audit policy), the API server logs every request to an **Audit Log** file, recording:
- The timestamp and request ID.
- The requestor's identity (user, ServiceAccount, etc.).
- The HTTP verb and API resource accessed.
- The request and response payloads (redactable for Secrets).
- The response status code.

This is the **primary signal** for detecting both compromised credentials and RBAC misconfigurations at scale.

## Techniques / Protocols Used

- **HTTPS (TLS 1.2+)** — all kubectl-to-API-server traffic is encrypted.
- **Kubernetes API (HTTP REST)** — the query language is HTTP verbs + standard REST semantics.
- **RBAC (Role-Based Access Control)** — the authorization model.
- **JWT tokens (RFC 7519)** — ServiceAccount authentication.
- **X.509 client certificates** — alternative authentication method (mutual TLS).
- **Namespaces** — logical resource isolation within a cluster (not cryptographic; RBAC is the enforcement boundary).

## Command-Line Switches — Quick Reference

| Flag | Description | Example |
|---|---|---|
| `--kubeconfig` | Path to kubeconfig file (default: `~/.kube/config`, or `KUBECONFIG` env var) | `kubectl --kubeconfig /path/to/admin.conf get pods` |
| `--context` | Use a specific context from kubeconfig (default: current-context) | `kubectl --context=prod-admin get nodes` |
| `-n, --namespace` | Target namespace (default: default namespace in the current context) | `kubectl -n kube-system get pods` |
| `--token` | Bearer token for authentication (bypasses kubeconfig cert/key) | `kubectl --token eyJhbG... --server https://api.example.com:6443 get pods` |
| `--certificate-authority` | Path to CA cert for TLS verification | `kubectl --certificate-authority /path/to/ca.crt --server ... get pods` |
| `--client-certificate` | Path to client cert for mTLS | `kubectl --client-certificate admin.crt --client-key admin.key ... get pods` |
| `--client-key` | Path to client key for mTLS | (paired with `--client-certificate`) |
| `--server` | Kubernetes API server URL (e.g., `https://api.example.com:6443`) | `kubectl --server https://api.prod.example.com:6443 --token ... get nodes` |
| `--insecure-skip-tls-verify` | Skip TLS verification (OPSEC risk: obvious in audit logs if enabled) | `kubectl --insecure-skip-tls-verify --server ... get pods` |
| `--username`, `--password` | Basic auth credentials (rarely used; cert/token preferred) | `kubectl --username admin --password xyz get pods` |
| `-o, --output` | Output format: `json`, `yaml`, `table` (default), `wide` | `kubectl get pods -o json` |
| `--all-namespaces, -A` | List resources across all namespaces | `kubectl get pods -A` |
| `--sort-by` | Sort results by a field | `kubectl get nodes --sort-by=.metadata.creationTimestamp` |
| `-l, --selector` | Filter by label selector (key=value) | `kubectl get pods -l app=nginx` |
| `--field-selector` | Filter by field (metadata.name, status.phase, etc.) | `kubectl get pods --field-selector status.phase=Running` |
| `--watch` | Stream updates (WATCH verb, real-time) | `kubectl get pods --watch` |
| `-f, --filename` | Apply/delete from file or directory | `kubectl apply -f deployment.yaml` |
| `--dry-run=client` | Preview changes without applying to cluster | `kubectl apply -f pod.yaml --dry-run=client` |
| `--as` | Impersonate a user/ServiceAccount (requires `impersonate` permission) | `kubectl --as=system:serviceaccount:default:my-sa get pods` |
| `--as-group` | Impersonate a group (requires `impersonate` permission) | `kubectl --as-group=system:masters get nodes` |
| `--auth-caching` | Enable/disable auth caching (rarely used) | |
| `--cache-dir` | Directory for HTTP cache (rarely used) | |

## Quick Use-Case List

1. **Cluster reconnaissance** — enumerate nodes, namespaces, API resources, RBAC configuration.
2. **Credentials enumeration** — extract Secrets, ConfigMaps containing passwords/tokens/keys.
3. **Pod inspection** — list running Pods, inspect their configuration, check for misconfigurations.
4. **Lateral movement** — create new Pods, exec into running Pods, mount host volumes.
5. **Persistence** — create CronJobs, Deployments, or ServiceAccounts that auto-spawn reverse shells.
6. **Privilege escalation** — detect and exploit overly-permissive RBAC (e.g., `cluster-admin` on default ServiceAccount).
7. **Data exfiltration** — read Secrets/ConfigMaps containing database credentials, API keys, certificates.
8. **Supply-chain compromise** — modify container image references in Deployments to pull malicious images.
9. **Container runtime privilege escape** — use kubectl to deploy a privileged Pod or DaemonSet, then break out of the container via kernel vulnerability.
10. **RBAC auditing** — check what a compromised ServiceAccount can actually do (using `auth can-i` or direct API calls).
11. **Cluster backup theft** — extract ETCD snapshots or backup credentials (if exposed as Secrets).
12. **Cross-namespace lateral movement** — escape from a restricted namespace by exploiting overly-broad Roles.

## Prerequisites

- **Valid credential** to the target Kubernetes cluster. This can be:
  - A **kubeconfig file** (with mTLS certs or embedded tokens) — the most common attacker-acquired credential.
  - A **ServiceAccount token** — commonly found in compromised container filesystems at `/var/run/secrets/kubernetes.io/serviceaccount/token`, or extracted from cluster backups.
  - The **cluster's CA certificate** — necessary for TLS verification (or `--insecure-skip-tls-verify` if not available).
  - The **Kubernetes API server endpoint** — usually resolvable via DNS (e.g., `kubernetes.default.svc.cluster.local` from inside the cluster), or discovered via cloud provider APIs / OSINT.

- **kubectl binary** installed locally (or you can use `kubectl` via a container image: `docker run -it --rm -v ~/.kube/config:/root/.kube/config:ro kubernetes/kubernetes:latest kubectl get pods`).

- **Network access** to the Kubernetes API server (usually TCP/6443, though port varies by installation).

- For specific use cases:
  - **Privilege escalation** requires RBAC misconfiguration (e.g., overly-permissive ClusterRole or namespace-wide Roles).
  - **Container escape** requires running inside a container with a mounted ServiceAccount token; additionally exploiting a kernel vulnerability (like CVE-2021-22555, CVE-2024-21626) to break out to the node.
  - **Persistence via CronJobs** requires `create` permission on `cronjobs.batch` resource in the target namespace.
