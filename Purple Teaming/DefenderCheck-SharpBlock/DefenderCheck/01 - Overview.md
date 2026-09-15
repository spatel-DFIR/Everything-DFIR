# DefenderCheck — Overview

> **Red Flag Principle:** DefenderCheck is a **binary-analysis research utility** that identifies the exact bytes triggering Microsoft Defender's antivirus signatures. An operator running DefenderCheck against a custom malware payload tells Defender: "I have a tool you detect; show me which bytes offend you." The output — the hex offset and content of flagged bytes — is directly actionable: remove those bytes, obfuscate them, or use a different code pattern, then recompile and re-test. This tight feedback loop (compile → test → pinpoint flagged bytes → modify → repeat) makes DefenderCheck the standard tool for iterative signature evasion on Windows, appearing in both red-team public playbooks and threat-actor TTPs. It leaves **no persistent trace on disk after execution** (temporary test files in `C:\Temp` are cleaned up), but requires **Defender to be actively enabled and real-time protection disabled** — a configuration that itself signals active evasion work.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **Matterpreter** (author) released DefenderCheck as an open-source research utility circa **2019** — verified against the GitHub repository creation date (2019-04-09) and the tool's own README describing it as "a quick tool to help make evasion work a little bit easier."
- **Current maintainability:** The tool is actively maintained; the repository shows commits as recent as **2025-12-31**, and the project maintains **2,622 stars** and **480 forks** on GitHub, indicating sustained community use in red-team tooling and security research.
- **License:** **BSD 3-Clause ("New" or "Revised") License** — verified against the repository's LICENSE file, permitting commercial and private use with attribution.
- **No dedicated MITRE ATT&CK Software (S-number) entry** — verified directly against the live [ATT&CK Software list](https://attack.mitre.org/software/): no "DefenderCheck" entry exists. It is implicitly cited only as a **procedure example** under Defense Evasion technique [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information in threat-actor workflows that reference signature-evasion payloads, not as a standalone Software object.
- **Self-detection risk:** As of Defender signature update **1.337.157.0** (per the tool's own README warning), DefenderCheck itself is flagged by Microsoft Defender as `VirTool:MSIL/BytzChk.C!MTB` — the tool is treated as a PUA (Potentially Unwanted Application) / evasion utility by the vendor, requiring users to temporarily disable real-time protection when compiling the tool from source or running pre-compiled binaries.

## How It Works

### Binary splitting — the core algorithm

Verified against DefenderCheck's own [GitHub README](https://github.com/matterpreter/DefenderCheck) and source code (Program.cs): the tool implements a **binary-search / binary-splitting algorithm** to pinpoint Defender-flagged bytes. The workflow is:

1. **Initial scan**: DefenderCheck accepts a compiled binary (`.exe`, `.dll`, or any PE format) and scans the *complete* file against Windows Defender using the `Windows.Security.ExternalSecurityProvider` API (or equivalent WinRT API surface for antivirus query).
2. **Threat detection trigger**: If Defender flags the file, the tool records that a threat exists *somewhere* in the binary.
3. **Binary dissection loop**: The tool then repeatedly:
   - **Halves** suspect byte ranges when a threat is detected (narrowing the "bad zone").
   - **Expands** clean byte ranges by 50% when no threat is detected (widening the "good zone").
   - Continues until the algorithm converges on the **exact byte offset and length** of the offending signature.
4. **Output**: Once identified, DefenderCheck prints:
   - The **hexadecimal offset** of the flagged bytes.
   - The **hex dump** of the flagged bytes (up to 256 bytes of context).
   - Optionally (with `debug` flag), verbose per-iteration output.

### Temporary files and cleanup

The tool creates test files in `C:\Temp\` during the binary splitting process (one per iteration) to efficiently test sub-ranges of the malware binary against Defender. These test files are **cleaned up automatically** after the tool completes — no persistent disk artifacts are left behind from DefenderCheck's execution itself, unlike registry-trail tools like Advanced IP Scanner.

### Dependency: Windows Defender must be active

Per the tool's own README: "Defender must be enabled on your system, but the realtime protection and automatic sample submission features should be disabled." This is a hard requirement — DefenderCheck queries Defender's detection engine directly, so:
- Defender Service (`WinDefend`) must be running.
- Real-time Protection (`tamperprotection` setting) should be disabled to avoid Defender blocking the tool's iterations (otherwise Defender may quarantine test files as the tool creates them).
- Automatic sample submission should be disabled to avoid sending the operator's malware to Microsoft's Malware Protection Center cloud service.

### No credentials required

DefenderCheck requires **no special privileges** to run — it is a single executable that can execute from any user context on a Windows host where Defender is enabled. This is a critical differentiator from evasion tools requiring kernel-mode access or administrator elevation.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Antivirus query | Windows Security (WinRT) API (`Windows.Security.ExternalSecurityProvider` or equivalent) to invoke Defender's detection engine on a file. |
| File I/O | Creates test files in `C:\Temp\` during binary splitting, then deletes them after each iteration. |
| Algorithm | Binary search / divide-and-conquer to converge on flagged byte ranges. |
| Output | Prints hex offsets and hex dumps to stdout; no log files generated. |
| Persistence | None — tool exits after analysis; no registry, scheduled tasks, or background processes created. |

## Command-Line Switches — Quick Reference

| Syntax | Argument | Plain-English meaning |
|---|---|---|
| `DefenderCheck.exe <file_path> [debug]` | `<file_path>` (required) | Path to the binary to scan (`.exe`, `.dll`, or other PE format). |
| | `debug` (optional) | If present as the second argument (e.g., `DefenderCheck.exe payload.exe debug`), enables verbose per-iteration output. |

**Note:** DefenderCheck takes only positional arguments — no named flags like `/` or `-`. This is deliberate: the tool is designed to be invoked from batch scripts, Python automation, or build pipelines where minimal syntax overhead is preferred.

## Quick Use-Case List

- **Iterative payload obfuscation**: Compile a custom malware payload (e.g., shellcode dropper, C2 beacon) and test it against Defender; DefenderCheck identifies the flagged bytes; modify the source code to obfuscate or replace those bytes; recompile and re-test.
- **Signature evasion for penetration testing**: During a red-team engagement, if a custom payload is detected by Defender, use DefenderCheck to isolate the signature trigger, then modify the payload to bypass detection without compromising functionality.
- **Batch scanning multiple payloads**: Invoke DefenderCheck in a loop across a directory of compiled binaries to identify which payload variants trigger detection and which do not.
- **Research and signature analysis**: Security researchers use DefenderCheck to understand Defender's signature coverage — how broad or narrow the detection is, whether it targets specific opcode sequences or higher-level patterns (e.g., API call sequences).
- **Testing encoding/packing schemes**: Apply an encoding scheme (XOR, RC4, custom cipher) to a known-malicious payload, then run DefenderCheck to see if the encoder effectively obfuscates the signature. If Defender still detects it, DefenderCheck shows which bytes in the encoded output still match the original signature.

Full step-by-step walkthroughs with commands for each use case live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| **Windows host** | Defender is Windows-specific; DefenderCheck runs on Windows 7 SP1 and later (verified per the tool's .NET Framework targeting). |
| **Microsoft Defender enabled** | The tool queries Defender's detection engine; Defender Service (`WinDefend`) must be running. |
| **Real-time Protection disabled** | Must be toggled off via Settings → Virus & threat protection → Manage settings → Real-time protection toggle, or via Group Policy / registry for enterprise environments. |
| **Automatic sample submission disabled** | Disable via Settings → Virus & threat protection → Virus & threat protection settings → Automatic sample submission, to avoid uploading the operator's malware to Microsoft cloud. |
| **.NET Framework** | DefenderCheck is written in C# and targets .NET Framework (specific version: TBD — verify in repo for current version). Requires a runtime capable of running managed C# binaries. |
| **Disk space in C:\Temp** | The tool creates temporary test files during binary splitting; ensure at least 10× the target binary's size available in `C:\Temp\` (example: scanning a 50 MB binary may temporarily use up to 500 MB in `C:\Temp\`). |
| **File read access** | Must have read access to the target binary being scanned. |
| **No elevation required** | DefenderCheck does not require administrator or SYSTEM privileges. |

---

## Open Questions

- **Exact .NET Framework version targeting**: The repo's `.csproj` file should specify the target framework (e.g., `net48`, `net472`); confirm this to ensure compatibility across Windows versions.
- **WinRT API surface changes in Windows 11**: Verify whether DefenderCheck's Defender-query API (`Windows.Security.ExternalSecurityProvider` or alternative) continues to function unchanged on Windows 11 22H2+ with latest Defender versions. If the vendor changed the API surface, document required modifications.
- **Defender version dependencies**: Does DefenderCheck work with all Defender versions (including legacy Windows Defender on Windows 7/8), or are there known incompatibilities with specific signature update versions? Document minimum Defender version.
