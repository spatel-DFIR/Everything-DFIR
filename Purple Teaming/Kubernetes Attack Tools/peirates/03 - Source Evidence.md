# peirates — Source Evidence

## peirates binary

**Presence of the binary itself is the strongest signal:**

- **Binary location:** `/usr/local/bin/peirates`, `/opt/peirates`, `./peirates` in home or temp directory
- **Source code:** Cloned `aquasecurity/peirates` Git repo

```bash
find / -name "peirates" 2>/dev/null
find / -name "peirates*" -o -name "*peirates*" 2>/dev/null
```

## Network connections (internal only)

Unlike kube-hunter, peirates makes connections **from within the cluster**, so outbound connections to the API server (port 443, service `kubernetes.default`) would appear in process netstat logs inside the container.

## Shell history inside the container

If bash is available in the container:

```bash
# Inside a compromised container
cat ~/.bash_history | grep -E "peirates|exploit|escape"
history | grep peirates
```

## Kernel module artifacts (if exploiting kernel CVE)

If a kernel vulnerability is exploited (Dirty COW, Netfilter), the attack may:
- **Write to read-only pages** (Dirty COW creates memory corruption traces).
- **Modify iptables rules** (Netfilter CVE).
- **Spawn root processes** — child processes with UID 0 when the container runs as non-root.

---

## Strongest Source Evidence Signal

**The peirates binary itself** — finding the binary indicates intentional Kubernetes privilege escalation tooling. Paired with proof of execution (shell history, process logs), the evidence is definitive.

However, peirates' true signal is **behavioral**: spawning of unexpected child processes, kernel privilege escalation attempts, or root-owned processes spawning from a non-root container — these are detected more reliably through runtime monitoring than file-based forensics.
