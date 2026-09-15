# kubectl — Source Evidence

> **Source Evidence Note:** kubectl is a **local CLI tool** — all operational artifacts live on the attacker's own workstation or jump host, not on the cluster itself (cluster-side artifacts are in `04 - Target Evidence.md`). This page documents what forensic analysts find when seizing or analyzing the attacker's machine.

## Kubeconfig files

The kubeconfig file is the **most obvious attacker artifact** when a credential has been compromised or exfiltrated.

### Default kubeconfig locations

- **Linux/macOS:** `~/.kube/config`
- **Windows:** `%USERPROFILE%\.kube\config`
- **Environment variable override:** any value in `KUBECONFIG` (can be a colon- or semicolon-separated list of paths)

Forensic analysts should:
1. **Check the default location first:** `ls -la ~/.kube/`
2. **Grep shell history for `--kubeconfig`:** `grep -r "kubeconfig" ~/.bash_history ~/.zsh_history`
3. **Check for multiple kubeconfigs:** Some attackers maintain a separate kubeconfig per target (e.g., `~/.kube/prod.conf`, `~/.kube/staging.conf`, `~/kubeconfigs/cluster1.yaml`)

### Kubeconfig structure — what it reveals

A kubeconfig file in plain text contains:

```yaml
clusters:
  - cluster:
      server: https://api.production-cluster.example.com:6443
      certificate-authority-data: LS0tLS1CRUdJTi...  # Base64-encoded CA cert
    name: prod-cluster
contexts:
  - context:
      cluster: prod-cluster
      namespace: default
      user: prod-admin
    name: prod-admin-context
current-context: prod-admin-context
users:
  - name: prod-admin
    user:
      client-certificate-data: LS0tLS1CRUdJTi...  # Base64-encoded client cert
      client-key-data: LS0tLS1CRUdJTi...          # Base64-encoded client key
```

From this single file, an analyst can:
- **Identify the target cluster:** API server endpoint (e.g., `api.production-cluster.example.com`).
- **Extract authentication material:** Client certificates and keys (Base64-encoded but trivially decoded).
- **Determine access scope:** Namespaces the context defaults to.
- **Timeline correlation:** File modification time indicates when the credential was last used or copied.

**Strongest signal:** If the kubeconfig contains **mTLS client certificates** (Base64-encoded X.509 certs), decode and inspect the certificate metadata:
- **Subject CN (Common Name):** Often the username (e.g., `CN=admin`).
- **Subject O (Organization):** May indicate role or team.
- **Validity period:** Expiration date of the credential.
- **Issuer:** Name of the cluster CA.

```bash
# Decode a Base64 client certificate from kubeconfig and inspect it
echo "LS0tLS1CRUdJTi..." | base64 -d | openssl x509 -text -noout
```

## Shell command history

Kubectl commands leave traces in shell history files:

- **Bash:** `~/.bash_history`
- **Zsh:** `~/.zsh_history`
- **Fish:** `~/.local/share/fish/fish_history`

### Common patterns to hunt for

```bash
grep -E "kubectl|kubeconfig" ~/.bash_history
grep -E "get secrets|get pods|get nodes" ~/.bash_history
grep -E "exec.*bash|exec.*sh" ~/.bash_history           # kubectl exec into pods
grep -E "apply -f|create -f" ~/.bash_history             # kubectl apply/create from files
```

**Evasion resistance:** Shell history is truncated if the attacker explicitly clears it (`history -c`, `rm ~/.bash_history`, `export HISTFILE=/dev/null` before running commands), but:
- File timestamps still show when history was last written.
- Tools like `auditd` (Linux) log execve() calls independent of shell history.
- Parent process logs (Sysmon on Windows, auditd on Linux) capture the full command line regardless of shell history.

## kubectl HTTP cache

kubectl caches HTTP responses (particularly list operations) to avoid redundant API calls:

- **Linux/macOS:** `~/.kube/cache/http_cache/`
- **Windows:** `%LOCALAPPDATA%\kubectl\cache\http_cache\`

The cache is a **key-value store** indexed by URL path. Attackers clearing this cache (`rm -rf ~/.kube/cache/`) is common OPSEC practice, but the cache directory itself being present (even empty) is evidence of kubectl use.

**Forensic value:** Limited — the cache is compressed and truncated, but tool timestamps (directory creation/modification) can indicate tool usage windows.

## Credential file artifacts

If an attacker constructs kubeconfig dynamically (not from a stolen file), they may create temporary files:

- **Temporary kubeconfigs:** `/tmp/kubeconfig-*`, `~/.kube/temp-*`
- **Token files:** `.token`, `.jwt` in home or temp directories
- **Certificate files:** `.crt`, `.key` files not integrated into kubeconfig

## kubectl logs in process accounting

If the system has process accounting enabled (`acct` daemon on Unix), or if the attacker's commands were logged by a parent shell/terminal:

- **Linux auditd:** `/var/log/audit/audit.log` contains `execve()` system call logs with full command-line arguments
- **Process memory:** A running `kubectl` process shows its full command line in `/proc/[PID]/cmdline` or via `ps` output

**Evasion-resistant signal:** Process accounting and auditd are **independent of shell history** — they log at the kernel level and survive shell history deletion.

## SSH/remote access logs

If the attacker used kubectl via SSH (e.g., from a jump box to the operator's workstation):

- **OpenSSH:** `~/.ssh/authorized_keys`, `~/.ssh/known_hosts`, `~/.ssh/id_*`
- **SSH client logs:** `~/.ssh/client_log` (if enabled)
- **Terminal session logs:** Many organizations capture terminal sessions for compliance

Timeline correlation: Compare SSH connection times with kubectl command timestamps.

## Network connection artifacts

On systems with network connection logging enabled:

- **netstat/ss snapshots:** `netstat -an > netstat.txt` captured at forensic time may show TCP connections to Kubernetes API servers
- **tcpdump/packet capture:** HTTPS traffic to the API server (port 6443 by default) — the TLS certificate contains the API server hostname
- **Firewall logs:** Egress connections to API server IPs

**Evasion-resistant signal:** TLS Server Name Indication (SNI) and certificate inspection can identify Kubernetes API traffic by hostname.

## Kubectl plugins and extensions

Attackers sometimes add custom kubectl plugins (which execute from `~/.kube/plugins/` or `PATH`):

```bash
ls -la ~/.kube/plugins/
```

Malicious plugins could hook kubectl operations for credential theft or persistence.

## Kubeconfig in environment variables

Some systems record environment variables in logs:

```bash
env | grep -i kube
ps aux | grep kubectl  # Shows command-line args including --kubeconfig
```

## Strongest Source Evidence Signal

**The kubeconfig file itself** is the most reliable, specific, and timeline-anchored signal:

1. **Location:** File path (default `~/.kube/config` or `KUBECONFIG` environment variable value).
2. **Modification time:** When the credential was last used.
3. **Content:** The exact cluster endpoint, namespaces, and authentication material.
4. **Decoded client certificates:** Username, role, and expiration (if using mTLS).

If a kubeconfig is found on a forensic image, you can immediately:
- Identify the compromised cluster.
- Extract the full authentication material (if it contains embedded certificates/tokens).
- Cross-correlate with the target cluster's audit logs to see what this credential did (see `04 - Target Evidence.md`).

**Evasion-resistant:** The kubeconfig file is passive data; it survives shell history deletion and terminal clearing. However, attackers who exfiltrate the kubeconfig and delete it from the source machine will leave only:
- Temporary file artifacts (if kubeconfig was first written to `/tmp/`).
- Process logs (from when kubectl was invoked).
- Network connection logs (to the API server).
