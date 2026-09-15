# Purple Teaming Module

A tool-first offensive/defensive reference covering 61 attack tools and 80+ sub-tools — understand operator tradecraft (how to run each tool) and defensive detection (evidence left behind). Each tool has standardized sections covering usage, target/source evidence, and hunting strategies ranked by evasion resistance.

> Part of the [Everything-DFIR](../README.md) repository.
> Released under the [MIT License](../LICENSE).

---

## Module Status

- ✅ **Complete:** 61 primary tool folders (with ~80+ sub-tools); 200+ markdown files across Reconnaissance, Initial Access, Lateral Movement, Persistence, Privilege Escalation, Credential Access, C2, Exfiltration
- Coverage: All MITRE ATT&CK techniques referenced; cross-linked to Windows/Linux/Cloud notes for blue-team detection perspective
- Structure: Standardized 5-file format per tool (Overview, Use Cases, Source Evidence, Target Evidence, Detection & Hunting)

---

## Quick Start by Role

**New to purple teaming?**
1. Read the [Module Structure](#module-structure-standardized-5-file-format) section below (5-minute overview)
2. Choose your use case (Reconnaissance → Lateral Movement → Persistence)
3. Open a tool folder: each has the same 5-file structure
4. Use `02 - Hands-On Use Cases.md` for commands; `03–05` for evidence

**Responding to an incident and need to understand evidence?**
1. You know the attack (e.g., "lateral movement via PsExec")
2. Find the tool in the [All Tools](#all-tools-61-primary-tool-folders) table below
3. Open `04 - Target Evidence.md` to see what the attack leaves on the victim
4. Jump to the platform note (Windows/Linux/Cloud) for detection/hunting commands

**Red/blue teamer looking for evasion gaps?**
1. Find the tool in the [All Tools](#all-tools-61-primary-tool-folders) table
2. Open `05 - Detection and Hunting.md` → review "Evasion Resistance" rankings
3. Cross-check with platform notes (Windows/Linux) to find blue-team blind spots

---

## Module Structure: Standardized 5-File Format

### Single-Purpose Tools
5 markdown files per tool:
1. `01 - Overview.md` — History, mechanics, protocols, command switches, use cases, prerequisites
2. `02 - Hands-On Use Cases.md` — Full commands + MITRE ATT&CK IDs per scenario
3. `03 - Source Evidence.md` — What the operation leaves on the attacker's host
4. `04 - Target Evidence.md` — What the operation leaves on the target/destination host
5. `05 - Detection and Hunting.md` — Hands-on hunt commands, ranked by evasion resistance

### Tools with Sub-Tools (Suites)
Each sub-tool gets its own subfolder with 5 files (01-05). The suite folder contains:
- `00 - {SuiteName} Overview.md` — Explains the suite and links to each sub-tool
- Subfolders for each sub-tool

**Example: Impacket suite (7 sub-tools)**
```
Impacket/
├── 00 - Impacket Overview.md
├── psexec/
│   ├── 01 - Overview.md
│   ├── 02 - Hands-On Use Cases.md
│   ├── 03 - Source Evidence.md
│   ├── 04 - Target Evidence.md
│   └── 05 - Detection and Hunting.md
├── wmiexec/
│   ├── 01 - Overview.md
│   ├── 02 - Hands-On Use Cases.md
│   ├── 03 - Source Evidence.md
│   ├── 04 - Target Evidence.md
│   └── 05 - Detection and Hunting.md
├── secretsdump/
│   └── (same 5-file structure)
├── smbexec/
│   └── (same 5-file structure)
├── ticketer/
│   └── (same 5-file structure)
├── GetUserSPNs/
│   └── (same 5-file structure)
└── ntlmrelayx/
    └── (same 5-file structure)
```

---

## All Tools (61 primary tool folders)

| # | Tool | Folder |
|---|------|--------|
| 1 | Masscan | [Masscan/](Masscan/) |
| 2 | Nmap | [Nmap/](Nmap/) |
| 3 | Responder | [Responder/](Responder/) |
| 4 | Metasploit (9 sub-tools) | [Metasploit/](Metasploit/) |
| 5 | Mimikatz (3 sub-tools) | [Mimikatz/](Mimikatz/) |
| 6 | Hashcat | [Hashcat/](Hashcat/) |
| 7 | Sliver | [Sliver/](Sliver/) |
| 8 | Seatbelt | [Seatbelt/](Seatbelt/) |
| 9 | Impacket (7 sub-tools) | [Impacket/](Impacket/) |
| 10 | BloodHound (2 sub-tools) | [BloodHound/](BloodHound/) |
| 11 | Atomic Red Team | [Atomic%20Red%20Team/](Atomic%20Red%20Team/) |
| 12 | PowerShell Empire | [PowerShell%20Empire/](PowerShell%20Empire/) |
| 13 | LOLBins (14 sub-tools) | [LOLBins/](LOLBins/) |
| 14 | Cobalt Strike | [Cobalt%20Strike/](Cobalt%20Strike/) |
| 15 | AdFind | [AdFind/](AdFind/) |
| 16 | Rclone | [Rclone/](Rclone/) |
| 17 | AnyDesk | [AnyDesk/](AnyDesk/) |
| 18 | PsExec | [PsExec/](PsExec/) |
| 19 | Advanced IP Scanner / SoftPerfect NetScan (2 sub-tools) | [Advanced%20IP%20Scanner-SoftPerfect%20NetScan/](Advanced%20IP%20Scanner-SoftPerfect%20NetScan/) |
| 20 | Rubeus | [Rubeus/](Rubeus/) |
| 21 | LaZagne | [LaZagne/](LaZagne/) |
| 22 | ProcDump | [ProcDump/](ProcDump/) |
| 23 | NetExec | [NetExec/](NetExec/) |
| 24 | Hydra | [Hydra/](Hydra/) |
| 25 | PowerSploit (2 sub-tools) | [PowerSploit/](PowerSploit/) |
| 26 | GhostPack (5 sub-tools) | [GhostPack/](GhostPack/) |
| 27 | Certipy | [Certipy/](Certipy/) |
| 28 | AADInternals | [AADInternals/](AADInternals/) |
| 29 | TrevorSpray-Spray365 (2 sub-tools) | [TrevorSpray-Spray365/](TrevorSpray-Spray365/) |
| 30 | Veil-Evasion | [Veil-Evasion/](Veil-Evasion/) |
| 31 | DefenderCheck-SharpBlock (2 sub-tools) | [DefenderCheck-SharpBlock/](DefenderCheck-SharpBlock/) |
| 32 | Shodan | [Shodan/](Shodan/) |
| 33 | DNSRecon-DNSDumpster (2 sub-tools) | [DNSRecon-DNSDumpster/](DNSRecon-DNSDumpster/) |
| 34 | EyeWitness | [EyeWitness/](EyeWitness/) |
| 35 | Pcredz | [Pcredz/](Pcredz/) |
| 36 | ngrok | [ngrok/](ngrok/) |
| 37 | John the Ripper | [John%20the%20Ripper/](John%20the%20Ripper/) |
| 38 | evil-winrm | [evil-winrm/](evil-winrm/) |
| 39 | WinPEAS-LinPEAS (2 sub-tools) | [WinPEAS-LinPEAS/](WinPEAS-LinPEAS/) |
| 40 | Potato Family (3 sub-tools) | [Potato%20Family/](Potato%20Family/) |
| 41 | Chisel-Ligolo-ng-proxychains (3 sub-tools) | [Chisel-Ligolo-ng-proxychains/](Chisel-Ligolo-ng-proxychains/) |
| 42 | Scapy | [Scapy/](Scapy/) |
| 43 | Sulley-boofuzz (2 sub-tools) | [Sulley-boofuzz/](Sulley-boofuzz/) |
| 44 | pwntools | [pwntools/](pwntools/) |
| 45 | Immunity Debugger-mona (2 sub-tools) | [Immunity%20Debugger-mona/](Immunity%20Debugger-mona/) |
| 46 | WinDbg | [WinDbg/](WinDbg/) |
| 47 | pefile | [pefile/](pefile/) |
| 48 | GraphRunner | [GraphRunner/](GraphRunner/) |
| 49 | Pacu | [Pacu/](Pacu/) |
| 50 | ScoutSuite | [ScoutSuite/](ScoutSuite/) |
| 51 | Prowler | [Prowler/](Prowler/) |
| 52 | Trufflehog-Gitleaks (2 sub-tools) | [Trufflehog-Gitleaks/](Trufflehog-Gitleaks/) |
| 53 | Kubernetes Attack Tools (3 sub-tools) | [Kubernetes%20Attack%20Tools/](Kubernetes%20Attack%20Tools/) |
| 54 | Havoc | [Havoc/](Havoc/) |
| 55 | Mythic | [Mythic/](Mythic/) |
| 56 | Burp Suite | [Burp%20Suite/](Burp%20Suite/) |
| 57 | sqlmap | [sqlmap/](sqlmap/) |
| 58 | ffuf-gobuster (2 sub-tools) | [ffuf-gobuster/](ffuf-gobuster/) |
| 59 | Nikto | [Nikto/](Nikto/) |
| 60 | Coercion Primitives (4 sub-tools) | [Coercion%20Primitives/](Coercion%20Primitives/) |

---

## Template Details

### 01 - Overview.md
- **History** — Origin, author, why it exists, version milestones
- **How It Works** — Protocol/mechanics detail (forensics-relevant depth)
- **Techniques/Protocols Used** — SMB, RPC, LDAP, Kerberos, WinRM, etc.
- **Command-Line Switches — Quick Reference** — Man-page style table of all flags
- **Quick Use-Case List** — All realistic scenarios the tool is used for
- **Prerequisites** — What an operator must already have

### 02 - Hands-On Use Cases.md
- One section per realistic use case (descriptive headers, not "Use Case 1/2/3")
- Full command(s) with step-by-step where needed
- MITRE ATT&CK technique/sub-technique ID(s) per use case

### 03 - Source Evidence.md
- Shell/command history
- Tool-specific local artifacts
- Local network-connection state
- Cached credential material
- Process artifacts
- OS-level audit trail
- Memory-forensics angle
- Timeline correlation

### 04 - Target Evidence.md
- Event logs (exact event IDs — Security, Sysmon, PowerShell, etc.)
- Prefetch, LNK files
- Registry keys
- Filesystem artifacts
- Network-layer evidence
- Endpoint-security-product signature behavior
- Memory artifacts
- Timeline-building walkthrough

### 05 - Detection and Hunting.md
Two subsections:
- **Hunting on Source** — Find artifacts in 03
- **Hunting on Target** — Find artifacts in 04

Hunt commands ranked by invariant strength (which survive evasion options).

---

## Conventions & Voice

- **Operator perspective first** — Commands and output shown as an attacker would see them
- **Defender perspective second** — Evidence sections show exactly what defenders find during investigation
- 🔴 marks high-confidence indicators and easily-missed evidence
- Commands shown with language context (bash, PowerShell, C#, Python, etc.)
- MITRE ATT&CK technique IDs on every use case; verify against current Enterprise matrix
- Evasion resistance rankings in hunting sections indicate which detection methods survive common evasion techniques

---

## Disclaimers & Scope

- **For authorized security testing and incident response only.** Not for unauthorized access or malicious purposes.
- **Built from official tool documentation and published security research.** All commands verified against GitHub repositories.
- **Purple teaming context:** This module shows both offensive usage AND defensive detection. Use to understand your blind spots and harden detection.
- **Scope:** Tool mechanics, tradecraft, and evidence. Prerequisite knowledge assumed (networking, OS internals, attack frameworks). Does not cover initial reconnaissance of targets outside your scope.
- **Cross-references:** Platform notes (Windows, Linux, Cloud) show how to detect and hunt this evidence in your environment. Start there for your specific blue-team context.

---

## License

The notes in this repository are released under the [MIT License](../LICENSE).

---

**Last updated:** 2026-08-12
