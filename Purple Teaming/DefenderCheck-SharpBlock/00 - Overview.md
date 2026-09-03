# DefenderCheck / SharpBlock — Overview

This folder bundles **two complementary Windows security-testing tools** — matterpreter's **DefenderCheck** and CCob's **SharpBlock** — because they represent the two layers of a complete signature-evasion and EDR-bypass workflow:

1. **DefenderCheck** = Offline signature testing (attacker's machine, pre-deployment).
2. **SharpBlock** = Inline EDR blocking (target's machine, post-compromise).

They are not the same codebase, the same author, or the same attack stage — DefenderCheck prepares payloads by identifying flagged bytes; SharpBlock executes them by blinding EDR. Both are open-source, C#-based, and ubiquitous in modern red-team tooling and threat-actor TTPs. This page exists to make the workflow and implications clear rather than let two security-testing utilities blur together.

## Contents
- [Why These Two Are Bundled](#why-these-two-are-bundled)
- [The Core Distinction — Offline Testing vs. Inline Evasion](#the-core-distinction--offline-testing-vs-inline-evasion)
- [Side-by-Side Comparison](#side-by-side-comparison)
- [When an Analyst Sees One vs. the Other](#when-an-analyst-sees-one-vs-the-other)
- [Sub-Tool Table of Contents](#sub-tool-table-of-contents)

---

## Why These Two Are Bundled

Both tools solve a single problem encountered in **post-compromise hands-on-keyboard access**: *"How do I execute my malware/tools without EDR or Defender catching it?"* — but they solve it at different stages:

- **DefenderCheck** answers: *"Which bytes in my payload will Defender flag?"* Operator tests locally, modifies payload, re-tests.
- **SharpBlock** answers: *"How do I stop EDR from seeing my payload's execution?"* Operator executes on target, blocks EDR DLL entry points, injects beacon.

Together, they form a **complete evasion workflow**: obfuscate payloads offline (DefenderCheck) → bypass EDR inline (SharpBlock) → execute undetected.

### Real-World Adoption

- **Threat-actor groups**: Red-team operations, ransomware crews, and APT organizations use DefenderCheck to iterate on payloads; SharpBlock to execute them without EDR detection.
- **Red-team engagements**: Penetration testers use both tools during authorized testing to simulate advanced attacker capabilities.
- **Security research**: Malware analysts and EDR vendors study both tools to understand evasion techniques and improve detection.

### Why Not Separate Folders?

Pairing them (like `Advanced IP Scanner-SoftPerfect NetScan/`) emphasizes the **workflow dependency**: DefenderCheck results feed into SharpBlock payload selection. An analyst encountering both tools on a single host should understand that they work together, not in isolation.

---

## The Core Distinction — Offline Testing vs. Inline Evasion

**Read each sub-tool's own `01 - Overview.md` for full mechanics** — this is the fast disambiguation an analyst needs before reading either page in depth:

```
DefenderCheck                              SharpBlock
─────────────                              ──────────
Runs on ATTACKER's machine                 Runs on TARGET's machine
Pre-deployment (payload preparation)       Post-compromise (hands-on execution)
                    │                                      │
Binary signature testing:                  EDR DLL blocking:
  Identify flagged bytes in payload          Prevent EDR DLL initialization
  via binary splitting algorithm             via debugger API + DLL entry-point hooking
                    │                                      │
Output: Hex offset + byte content           Output: Injected beacon (silent, undetected)
        (actionable for payload obfuscation)           (assumes Defender is configured)
                    │                                      │
Prerequisites: Defender enabled            Prerequisites: Target process, EDR DLL name,
              Real-time protection disabled             Payload binary (local/HTTP/pipe)
                    │                                      │
                    ▼                                       ▼
     Modify payload source code             Re-enable EDR (optional), maintain access
     Re-compile, re-test with DC            via injected beacon (C2 callback)
     [Repeat until CLEAN]
```

**In Plain English:**
- **DefenderCheck** = "Show me which bytes Defender detects so I can modify them."
- **SharpBlock** = "I'll stop EDR from seeing my payload, so I can execute undetected."

---

## Side-by-Side Comparison

| | DefenderCheck | SharpBlock |
|---|---|---|
| **Author / Repo** | matterpreter (`github.com/matterpreter/DefenderCheck`) | CCob (`github.com/CCob/SharpBlock`) |
| **License** | BSD 3-Clause | Unspecified (verify in repo) |
| **Execution Context** | Attacker's offline machine (test/dev environment) | Target's machine (post-compromise) |
| **Purpose** | Identify Defender-flagged bytes in payloads (offline testing) | Bypass EDR by blocking DLL entry points (inline evasion) |
| **Primary Mechanism** | Binary splitting algorithm (divide-and-conquer) | Debugger API + DLL entry-point hooking + process hollowing |
| **Prerequisites** | Windows Defender enabled, real-time protection disabled | Target process, EDR DLL name, payload binary |
| **Time to Execute** | Minutes (per payload, iterative testing) | Seconds (single injection, then beacon callback) |
| **Artifacts Left Behind** | Minimal (temporary test files auto-deleted; Defender disable registry key) | Moderate (SharpBlock.exe on disk, injected beacon in memory, network C2 callback) |
| **Privilege Required** | No elevation needed | No elevation needed (but injection success depends on target process privilege) |
| **Failure Mode** | Defender still flags modified payload → repeat obfuscation cycle | EDR not blinded; injection detected or beacon detected → alert/block |
| **Detection Difficulty** | Forensically minimal; best detected via process logs + registry tampering | Moderate; injectable via process injection signatures, parent-child anomalies, network C2 IOCs |
| **MITRE ATT&CK Mapping** | T1140 (Deobfuscate/Decode), T1027 (Obfuscated Files), T1036 (Masquerading) | T1562.001 (Disable/Modify Tools), T1055 (Process Injection), T1140 (Deobfuscate/Decode) |
| **Automation / C2 Integration** | Standalone tool; can be scripted (batch/PowerShell for multi-payload testing) | Integrates with Cobalt Strike, Sliver, Empire (named pipe payload delivery, parent process spoofing) |

## When an Analyst Sees One vs. the Other

### Seeing DefenderCheck (without SharpBlock)

**Signal:** DefenderCheck binary and/or batch scripts invoking it on an attacker/analyst machine.

**Analyst Conclusion:** 
- Red-team infrastructure or penetration testing lab is actively developing payloads.
- Operator has not yet deployed to targets (or deployment is on a separate machine).
- This is **preparation stage**, not active exploitation.
- Look for staged payloads (beacon.exe, custom tools) in the same directory or parent locations.

### Seeing SharpBlock (without DefenderCheck)

**Signal:** SharpBlock.exe executed on a production/user host; injected beacon callback observed.

**Analyst Conclusion:**
- Attacker has **already gained hands-on access** to the target.
- Attacker is using SharpBlock to execute malware/tools while blinding EDR.
- This is **active exploitation**, not preparation.
- Immediate response required: isolate host, kill beacon, investigate how attacker got there.

### Seeing Both Together

**Signal:** DefenderCheck on attacker infrastructure (red-team machine); SharpBlock + beacon on target host; timeline shows DefenderCheck usage ~days before SharpBlock deployment.

**Analyst Conclusion:**
- **Full attack workflow detected:**
  1. Attacker prepared payload with DefenderCheck (tested against Defender).
  2. Attacker gained access to target.
  3. Attacker deployed SharpBlock on target to bypass EDR.
  4. Attacker injected prepared beacon.
- This is a sophisticated, multi-stage attack by a patient, skilled adversary.
- Investigate all intermediate stages (how was access gained? what other tools were deployed?).

### Seeing DefenderCheck Alongside Other Evasion Tools

**Signal:** DefenderCheck paired with Veil-Evasion, custom encoders, obfuscators on attacker machine.

**Analyst Conclusion:**
- Attacker is building a **layered evasion strategy**: encode payload (Veil) → test signature evasion (DefenderCheck) → inject via SharpBlock (if deployment is observed).
- Sophisticated toolchain indicates disciplined, organized attack group.

---

## Sub-Tool Table of Contents

| Sub-Tool | Covers | Key Focus |
|---|---|---|
| [`DefenderCheck/`](DefenderCheck/01%20-%20Overview.md) | matterpreter's signature-evasion research utility. Binary splitting algorithm to pinpoint Defender-flagged bytes. **Offline testing** on attacker's machine to prepare Defender-clean payloads before deployment. Registry MRU trail is minimal; Defender disable is required; execution timeline leaves Event Logs but minimal disk artifacts. | How to identify and obfuscate malicious code signatures. |
| [`SharpBlock/`](SharpBlock/01%20-%20Overview.md) | CCob's EDR-bypass injection tool. Debugger API + DLL entry-point hooking + process hollowing to block EDR, inject payloads, and execute undetected. **Inline evasion** on target's machine during hands-on compromise. Integrates with Cobalt Strike, supports multiple EDR targets (Falcon, MDE, Sentinel One). Process execution, command-line spoofing, and network C2 callback are primary forensic signals. | How to block EDR DLL initialization and inject malware undetected. |

Both sub-tool folders share this page's workflow framing and the "Offline Testing vs. Inline Evasion" distinction above — neither re-derives it. Each folder's five-file structure (01-05) follows the standard Purple Teaming template: Overview, Hands-On Use Cases, Source Evidence, Target Evidence, Detection & Hunting.

---

## Attack Timeline Example

```
Timeline: Ransomware Intrusion via DefenderCheck + SharpBlock

Day 1 (Preparation):
  - Attacker develops custom ransomware variant (ported Conti source, custom obfuscation).
  - Attacker runs DefenderCheck on variant multiple times to identify flagged bytes.
  - Attacker modifies source, recompiles, re-tests with DefenderCheck.
  - After ~10 iterations, DefenderCheck reports: "No threat found"
  - Payload is now Defender-clean.

Day 8 (Deployment):
  - Attacker delivers phishing email with trojanized Office macro → initial access.
  - Victim opens macro → reverse shell spawned.
  - Attacker reverse-tunnels through victim's network.
  - Attacker uploads SharpBlock.exe + beacon.exe to target.

Day 8, 14:00:
  - Attacker executes SharpBlock to spawn cmd.exe, block Falcon EDR DLL (csagent.dll),
    inject Defender-clean ransomware variant.
  - Ransomware executes, scans network, encrypts files.
  - Falcon EDR (blocked by SharpBlock) does not detect execution.

Day 8, 15:00:
  - Blue team detects encrypted files in SMB shares.
  - Incident response launched; host isolation → process execution timeline reviewed.
  - SharpBlock.exe and injection pattern identified.
  - Timeline shows: DefenderCheck usage ~8 days ago on attacker infrastructure (if recovered).

Forensic findings:
  - On attacker machine: DefenderCheck binary, batch script automating payload testing,
    multiple ransomware variants (v1-v10, each testing a different obfuscation technique).
  - On target machine: SharpBlock.exe, ransomware variant (Defender-clean), Event Log 4688
    showing SharpBlock execution + cmd.exe injection, Falcon EDR DLL in blocked list.
  - Network IOCs: Ransomware command-and-control server (if applicable).
```

---

## Cross-Link Philosophy

Both DefenderCheck and SharpBlock are **defensive-tool evasion utilities**. Related tools in this repo:

- **Veil-Evasion** (`Purple Teaming/Veil-Evasion/`): Payload encoding/obfuscation (complements DefenderCheck's signature testing).
- **Mimikatz** (`Purple Teaming/Mimikatz/`): Credential extraction (often injected via SharpBlock in lateral movement).
- **GhostPack** (`Purple Teaming/GhostPack/`): C# red-team utilities (Rubeus, Seatbelt often executed via SharpBlock injection).
- **Cobalt Strike** (`Purple Teaming/Cobalt Strike/`): C2 framework (integrates SharpBlock for inline beacon injection).
- **Windows Defender** (`Windows/11 - Defense Evasion/AMSI, ETW, Windows Defender.md`): Artifact deep dive on Defender architecture, evasion techniques, and detection bypass mechanics.
- **Process Injection** (`Windows/11 - Lateral Movement/Process Injection.md`): Detailed mechanics of process hollowing and DLL blocking.

---

## Summary

**DefenderCheck + SharpBlock = Complete Evasion Workflow**

1. **DefenderCheck** (offline, preparation): Identify and obfuscate Defender-flagged bytes so payloads pass static scanning.
2. **SharpBlock** (inline, execution): Block EDR DLL entry points so behavioral detection is impossible.
3. **Result**: Undetected malware execution in a fully-EDR-protected environment.

Both tools are open-source, widely adopted by red teams and threat actors, and critical to understand for both offensive and defensive operations. Understanding their mechanics, forensic artifacts, and detection signatures is essential for modern incident response and threat hunting.

---

## Acknowledgments

- **matterpreter** for DefenderCheck (signature evasion research).
- **CCob** for SharpBlock (EDR evasion research).
- **Cobalt Strike** for popularizing the EDR-bypass workflow in commercial red-team platforms.
- **Blue teams** who have detected these tools and shared indicators.
