# Everything-DFIR Field Reference

A hands-on **Digital Forensics & Incident Response** reference spanning Windows, Linux, macOS, Container, and Cloud platforms — built for use *during live incidents*, not as a textbook. Every note opens with native commands for immediate triage; deeper sections provide context and interpretation. Organized by investigative goal, not file count.

---

## Quick Start by Role

Use this router to find the right platform in 1–2 clicks:

| Your Situation | Start Here | Next Steps |
|---|---|---|
| Windows ransomware / lateral movement / persistence | [Windows README](Windows/README.md) → Scenario table | Threat playbook or artifact reference |
| Linux webserver compromise / rootkit hunt | [Linux README](Linux/README.md) → Scenario table | Persistence overview or forensics guide |
| macOS incident response / timeline reconstruction | [macOS README](macOS/README.md) → Scenario table | Artifact reference or evidence collection |
| AWS / Azure / GCP investigation | [Cloud README](Cloud/README.md) → Provider table | Service-specific deep-dive or cross-cloud bridge |
| Container / Kubernetes forensics | [Container README](Container/README.md) → Scenario table | Runtime triage or evidence collection |
| Purple teaming / understanding attack evidence | [Purple Teaming README](Purple%20Teaming/README.md) → Tool table | Tool mechanics and target/source evidence |

---

## Platform Overview

| Platform | Status | Investigative Focus | Best For |
|---|---|---|---|
| [**Windows**](Windows/README.md) | ✅ Complete | Host-level forensics: event logs, registry, program execution, persistence, lateral movement, memory | DFIR on Windows enterprise, ransomware response, active-incident triage |
| [**Linux**](Linux/README.md) | ✅ Complete | OS internals, system logs, persistence mechanisms, filesystem, memory, live response | Server/Linux forensics, webshell hunting, rootkit detection |
| [**macOS**](macOS/README.md) | ✅ Complete | OS fundamentals, Unified Logs, TCC/SIP, filesystem, artifacts, persistence | macOS incident response, timeline reconstruction, hunt workflows |
| [**Container**](Container/README.md) | ✅ In Depth | Docker/containerd/Kubernetes (28 notes), runtime triage, image forensics, audit logging, supply chain; full platform coverage including advanced Kubernetes audit and supply-chain security | Container escape analysis, Kubernetes forensics, malicious-image detection, registry compromise investigation |
| [**Cloud**](Cloud/README.md) | ✅ In Depth | AWS, Azure/M365/Entra, Google Cloud/Workspace, cross-cloud correlation (233+ notes) | Cloud-native incidents, authentication/authorization abuse, multi-cloud attacks |
| [**Purple Teaming**](Purple%20Teaming/README.md) | ✅ In Depth | Operator tradecraft (61 tools, 590+ files), attack evidence, detection evasion | Understanding tool-specific evidence, purple team exercises, evasion research |
| [**WSL**](WSL/) | ✅ In Depth | Windows/Linux hybrid investigation (4 comprehensive notes covering artifacts, registry, configuration, hunting) | WSL-specific forensics, hybrid incident response, cross-OS investigation |

---

## Repository Structure at a Glance

```
Everything-DFIR/ (1,100+ files)
├── Windows/ (100 files) ⭐ Complete
│   ├── README.md (scenario router + entry points)
│   ├── 01–22: Atomic reference notes (artifacts, event logs, program execution, persistence, lateral movement, etc.)
│   ├── NTFS/ (8-file deep-dive on filesystem internals)
│   ├── GPO/ (6-file deep-dive on Group Policy)
│   ├── Playbooks/ (9 end-to-end scenarios: ransomware, RDP, phishing, supply-chain, etc.)
│   └── Posters/ (22 reference materials)
├── Linux/ (81 files) ⭐ Complete
│   ├── README.md (scenario router + entry points)
│   ├── 01–05: Core concepts (filesystem, permissions, users, shells, hardening)
│   ├── 06–09: Logs, filesystems, artifacts, persistence (13 families)
│   ├── 10–14: Live response, memory, timelining, remediation
│   ├── 15: Playbooks (5 scenarios)
│   ├── Linux-RTR/: Live response scripts (hunt_persistence.sh, hunt_intrusion.sh)
│   └── Posters/ (3 reference materials)
├── macOS/ (68 files) ⭐ Complete
│   ├── README.md (scenario router + entry points)
│   ├── 01–08: Core concepts (filesystem, permissions, SIP, TCC, FileVault, shells)
│   ├── 09: Unified Logs (11-note deep-dive: system, auth, Wi-Fi, Bluetooth, TCC, crash logs, etc.)
│   ├── 10–14: Filesystems, artifacts (14 families), persistence (8 families), timelining
│   ├── 16–18: Remediation, playbooks, enterprise management
│   └── Posters/ (5 reference materials)
├── Container/ (28 files) ⭐ In Depth
│   ├── README.md (scenario router + entry points)
│   ├── 00: Container fundamentals (namespaces, cgroups, OCI runtime)
│   ├── Docker/ (3 files: architecture, investigation, image analysis)
│   ├── Kubernetes/ (2 files: architecture, investigation)
│   ├── Podman/ (2 files: architecture, investigation)
│   ├── Audit Logging & Forensic Analysis (Kubernetes API server deep-dive)
│   ├── Supply Chain Security & Image Scanning (registry, signatures, CI/CD forensics)
│   ├── Playbooks/ (5 scenarios: cryptojacking, exposed API, escape chains, etc.)
│   └── Escapes, Runtime Detection, Evidence Collection (cross-cutting topics)
├── Cloud/ (233 files) ⭐ In Depth
│   ├── README.md (3-provider router + cross-cloud bridges)
│   ├── 00–06: Shared foundation (fundamentals, identity, acquisition, correlation, threat landscape, service equivalents)
│   ├── Amazon/AWS/ (27 service-specific notes: IAM, CloudTrail, S3, EC2, Lambda, RDS, VPC, EKS, ECS, etc.)
│   ├── Microsoft/ (63 notes: Entra ID, Azure resources, M365 audit, Exchange, SharePoint, Teams)
│   ├── Google/ (64 notes: GCP resources, Workspace audit, BigQuery, Pub/Sub, Cloud SQL, etc.)
│   ├── Cross-Cloud Investigations/ (10 files: bridge notes for AWS↔Azure, AWS↔GCP, Azure↔GCP, multi-cloud playbooks)
│   └── Posters/ (13 reference materials)
├── Purple Teaming/ (590+ files) ⭐ In Depth
│   ├── README.md (tool index + 5-file schema)
│   ├── 61 tool folders (Mimikatz, Impacket, BloodHound, Cobalt Strike, Nmap, Metasploit, etc.)
│   │   └── Each tool: Overview, Hands-On Use Cases, Source Evidence, Target Evidence, Detection & Hunting
│   ├── Playbooks/ (cross-tool scenarios, evasion techniques)
│   └── Posters/ (1 reference material)
├── WSL/ (4 files) ⭐ In Depth
│   ├── README.md (hybrid investigation router)
│   ├── 01: WSL Artifacts on Windows Host (vhdx, registry, event logs)
│   ├── 02: Investigating Linux Inside WSL (distro filesystem, cross-OS investigation)
│   ├── 03: WSL Registry & Configuration Deep-Dive (complete LXSS reference, flags interpretation)
│   └── 04: WSL-Specific Hunting & Detection (process ancestry, registry hunting, timeline correlation)
├── README.md (this file)
├── LICENSE (MIT + third-party attribution)
├── CLAUDE.md (local development guidelines)
└── .gitignore (excludes local PLANNING/IDEAS/WIP files from public repo)
```

---

## How This Repository Is Organized

Everything-DFIR uses a consistent structure across all platforms to enable fast navigation during incidents:

**Atomic Reference Notes** — Each platform folder contains 15–25 numbered notes (e.g., `01 - Program Execution.md`, `12 - Lateral Movement.md`), each covering a distinct artifact family or investigation technique. Open the note for your current finding; cross-reference sections tell you what to check next.

**Quick Triage Blocks** — Every note opens with 4–8 native commands (PowerShell, bash, SQL, etc.) for immediate hypothesis testing on a live system or image.

**Deep-Dive Folders** — Complex topics (Windows NTFS internals, Group Policy, Linux filesystems) get multi-note sequences with sequential reading order (00→final). Use as a reference after the first read-through.

**Playbooks** — End-to-end scenarios (Ransomware, RDP Brute-Force, Webshell, Rootkit) synthesize evidence from atomic notes into a structured investigation workflow. Open when you know the threat type.

**Scenario Routers** — Each platform README includes a "Common Scenarios" table mapping threat/goal to the right notes. Use this to jump to your current investigation phase.

**Cross-Platform Links** — Browser and cloud-storage local artifacts (Chrome, OneDrive) are covered in Windows/macOS notes; server-side evidence (CloudTrail, M365 audit) lives in the Cloud platform, with cross-references in both directions.

---

## Reading Conventions

Each note follows a consistent structure:

- **Opening pitch** (1–2 sentences) — What this note covers and why you need it
- **Quick Triage block** (4–8 commands) — Run these first; verify your hypothesis before diving deeper
- **Contents** (clickable anchors) — Jump to the section you need; test anchors on GitHub
- **Scenario → Command → Interpretation** sections — Find your problem; see the command; understand the output
- 🔴 **Red flags** — High-value evidence or common misinterpretations (max 1–2 per note)
- **Cross-references** — Links to related notes in the same or different platform

**MITRE ATT&CK tags** are noted where they apply; verify against the current Enterprise matrix.

---

## Disclaimers & Scope

- **Field reference, not substitute for understanding.** Verify artifact behavior against the specific OS/version in front of you — paths, registry keys, and log formats evolve.
- **Built from public DFIR research.** Not affiliated with, endorsed by, or representing any vendor or training provider.
- **Use as triage reference during incidents.** Pair with formal forensic analysis, verification with multiple tools, and understanding of your specific environment.

---

## License

The notes in this repository are released under the [MIT License](LICENSE). Bundled third-party reference PDFs (SANS and community cheat sheets, posters) remain under their original authors' copyright and terms.

