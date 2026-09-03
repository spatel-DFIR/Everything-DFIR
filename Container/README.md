# Container DFIR Field Reference

Forensics and incident response for containerized environments — Docker, Kubernetes, and Podman. Organized by technology with paired theory/investigation notes: understanding internals (how it works, every component) then practical triage workflows (what an analyst runs first, then next). Core principle: *a container is just namespaced, cgroup-limited host processes with a layered filesystem — investigate from the host.*

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Quick Navigation: Start Here

**For new users:** Start with [`00 - Container Fundamentals`](<00 - Container Fundamentals.md>) — understand namespaces, cgroups, overlayfs, runtime architecture, and the host/container boundary. Then jump to the technology you're investigating (Docker, Kubernetes, or Podman).

**Common Scenarios — which notes to open:**

| Scenario | Start With | Then Read |
|----------|-----------|-----------|
| **Docker host investigation** | [Docker Architecture](<Docker/01 - Docker Architecture and Components.md>) | [Investigating Docker](<Docker/02 - Investigating Docker.md>), [Image Analysis](<Docker/03 - Docker Image and Layer Analysis.md>) |
| **Kubernetes cluster compromise** | [Kubernetes Architecture](<Kubernetes/01 - Kubernetes Architecture and Components.md>) | [Investigating Kubernetes](<Kubernetes/02 - Investigating Kubernetes.md>), [Cluster Compromise Playbook](<Playbooks/Kubernetes Cluster Compromise Playbook.md>) |
| **Container escape / privilege abuse** | [Escapes and Privilege Abuse](<Escapes and Privilege Abuse.md>) | [Container Fundamentals](<00 - Container Fundamentals.md>), [Linux Live Response](../Linux/10%20-%20Live%20Response%20and%20Volatile%20Data.md) |
| **Rootless / Podman host** | [Podman Architecture](<Podman/01 - Podman Architecture and Components.md>) | [Investigating Podman](<Podman/02 - Investigating Podman.md>) |
| **Cryptojacking / resource abuse** | [Container Cryptojacking Playbook](<Playbooks/Container Cryptojacking Playbook.md>) | [Runtime Detection](<Runtime Detection and Logging.md>), [Linux Rootkit Playbook](../Linux/15%20-%20Threat%20Landscape%20and%20Playbooks/Linux%20Rootkit%20Playbook.md) |
| **Exposed API / compromised registry** | [Exposed Docker API Playbook](<Playbooks/Exposed Docker API Playbook.md>) | [Docker Image Analysis](<Docker/03 - Docker Image and Layer Analysis.md>), [Evidence Collection](<Evidence Collection.md>) |
| **Backdoored image detection** | [Backdoored Image Playbook](<Playbooks/Backdoored Image Playbook.md>) | [Docker Image Analysis](<Docker/03 - Docker Image and Layer Analysis.md>), [ELF Malware Triage](../Linux/11b%20-%20ELF%20and%20Malware%20Triage.md) |
| **Capturing evidence for analysis** | [Evidence Collection](<Evidence Collection.md>) | Container/Docker/Kubernetes-specific playbooks as needed |

---

## How This Platform Is Organized

**Container Fundamentals:** Understand the building blocks — namespaces, cgroups, overlayfs, runtime architecture (Docker, containerd, runc, Podman). Essential before diving into specific technologies.

**Docker:** Three paired notes — architecture (the Docker KB), investigation workflow (analyst triage order), image/layer analysis (unpacking, hashing, payload inspection).

**Kubernetes:** Two paired notes — architecture (cluster components, API server, etcd, control plane), investigation workflow (cluster-wide triage, RBAC, secret inspection).

**Podman:** Two paired notes — daemonless/rootless architecture (systemd integration, user namespace mapping), investigation workflow.

**Cross-Cutting Notes:** Container escapes (T1611), runtime detection/logging (Falco, Tracee, auditd, eBPF), evidence collection and preservation.

**Playbooks:** End-to-end scenarios (cryptojacking, exposed API, escape chains, backdoored images, cluster compromise).

**Host Connection:** Container forensics depends heavily on host investigation — cross-links to [Linux](../Linux/README.md) for live response, memory forensics, persistence mechanisms, and auditd.

---

## Module Status

- ✅ **In Depth:** 28 markdown files covering Docker, Kubernetes, Podman internals, escapes, runtime detection, audit logging, supply-chain forensics, and 5 playbooks
- ✅ **Complete:** Advanced Kubernetes audit logging (API server events, RBAC hunting, secret exfiltration detection); supply-chain security (image signing, vulnerability scanning, registry forensics, build pipeline investigation)
- ⏳ **Deferred:** Managed service forensics (ECS, AKS, GKE) — deferred to [Cloud/](../Cloud/README.md) platform
- **Note:** Archived versions of previous notes in `Container/_archived/` (preserved for reference)

---

## Module Structure

```
Container/ (26 files total)
├── README.md ⭐ START HERE
│   ├── Quick Navigation Table (8 scenarios)
│   ├── Scope Clarity (theory + investigation notes paired)
│   └── Module Status & Contents
├── 00 - Container Fundamentals.md (15 KB) ⭐ ENTRY POINT
│   ├── Namespaces (pid, mnt, net, ipc, uts, user)
│   ├── Cgroups (resource limiting)
│   ├── overlayfs (layered filesystems)
│   ├── OCI runtime (runc, containerd, cri-o)
│   └── Host/Container boundary investigation model
├── Docker/ ⭐ DOCKER FORENSICS
│   ├── 01 - Docker Architecture and Components.md (theory)
│   ├── 02 - Investigating Docker.md (triage workflow)
│   └── 03 - Docker Image and Layer Analysis.md (unpacking, payload inspection)
├── Kubernetes/ ⭐ KUBERNETES FORENSICS
│   ├── 01 - Kubernetes Architecture and Components.md (cluster topology, control plane)
│   └── 02 - Investigating Kubernetes.md (cluster-wide triage, RBAC, secrets)
├── Podman/
│   ├── 01 - Podman Architecture and Components.md (daemonless, rootless, systemd)
│   └── 02 - Investigating Podman.md (user namespace mapping, investigation workflow)
├── Cross-Cutting Topics/ ⭐ ADVANCED TOPICS
│   ├── Escapes and Privilege Abuse.md (T1611, kernel exploits, privileged containers)
│   ├── Runtime Detection and Logging.md (Falco, Tracee, auditd, eBPF tracing)
│   ├── Evidence Collection.md (acquisition methodology, data preservation)
│   ├── Networking and Network Forensics.md (network namespace, service discovery)
│   ├── Kubernetes Audit Logging and Forensic Analysis.md (API server events, RBAC hunting, secret exfil detection)
│   └── Supply Chain Security and Image Scanning Forensics.md (image signatures, vulnerability scanning, registry forensics, build pipeline investigation)
├── Playbooks/
│   ├── Container Cryptojacking Playbook.md
│   ├── Exposed Docker API Playbook.md
│   ├── Backdoored Image Playbook.md
│   ├── Container Escape Playbook.md
│   └── Kubernetes Cluster Compromise Playbook.md
├── Container Posters/ (0 PDFs currently)
│   └── [Community contribution opportunity]
└── _archived/ (previous note versions)
    └── Historical versions preserved for reference
```

---

## Conventions & Voice

- **Quick Triage** block first — native CLI commands (docker, kubectl, podman) for immediate triage
- **Paired notes:** Theory notes explain *what/why*; investigation notes show *how*, ordered as an analyst actually works a case
- 🔴 marks high-value / red-flag items — easily missed containers, suspicious layers, privilege escalation indicators
- Commands blank-line separated; tables explain output meaning and interpretation
- MITRE ATT&CK technique IDs tagged per note (verify against current Enterprise matrix)
- Heavy cross-reference to Linux notes — a container process is a host process; use Linux persistence, memory, live-response guidance

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify container runtime behavior against your specific version and configuration.
- **Built from container runtime documentation and public incident response research.** Not affiliated with or endorsing any vendor or training provider.
- **Scope:** Container/Kubernetes forensics on-host (Docker, Podman, runc/containerd, Kubernetes). Managed cloud services (ECS, AKS, GKE) are in [Cloud/](../Cloud/README.md). Linux host-side investigation uses [Linux/](../Linux/README.md) notes.

---

## License

The notes in this repository are released under the [MIT License](../LICENSE).
