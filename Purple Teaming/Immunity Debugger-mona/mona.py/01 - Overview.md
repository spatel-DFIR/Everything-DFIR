# mona.py — Overview

🔴 **mona.py is a free, open-source Python plugin for Immunity Debugger that automates crash analysis, ROP gadget discovery, badchar identification, and pattern-offset calculations—eliminating manual tedium in exploit development and making it the de-facto standard extension to Immunity Debugger for training and adversary tools alike.**

## History

**mona.py** is developed by **Corelan** (Peter Van Eeckhoutte), a Belgian security researcher and trainer specializing in exploit development.

- **First Released:** ~2010 (as a Metasploit plugin, then ported to Immunity Debugger)
- **Current Maintainer:** Corelan (Peter Van Eeckhoutte, Corelan Team)
- **License:** BSD 3-Clause (open-source, free)
- **Repository:** `https://github.com/corelan/mona` (archived, last push 2026-04-30)
- **Status:** Actively developed until mid-2026; considered stable/feature-complete for exploit-dev use, though new functionality additions are rare

**Key Adoption Points:**
- **Immediate Predecessor:** Metasploit's `pattern_create` and `pattern_offset` utilities (manual command-line tools for crash analysis).
- **Integration:** mona.py is distributed as a `.py` file installed into Immunity Debugger's `PyCommands` plugin folder; loads automatically on Immunity startup.
- **Course Integration:** SEC660 (SANS Advanced Exploit Writing) explicitly teaches mona.py usage in stack overflow labs; also widely used in OSCP training.

**Archived Status Note (2026-04-30):**
The repository is archived but not deleted; the tool is feature-complete and stable. No ongoing updates are expected. Users should verify version 2.0+ (current stable) for production use.

---

## How It Works

### Architecture

**mona.py runs inside the Immunity Debugger Python environment (PyCommand)** as a plugin module. It does not operate as a standalone tool; it requires Immunity Debugger to be running and a debugged process to be paused (e.g., at a breakpoint or crash).

#### Core Workflow

1. **User Invokes mona Command:** In the Immunity PyCommand console, user types `!mona <command> <options>`.
2. **mona.py Parses Arguments:** The plugin parses the command string and routes to appropriate function.
3. **Memory Access:** mona.py reads/writes process memory via Immunity's Python API (`read_memory()`, `write_memory()`).
4. **Analysis Engine:** Depending on command:
   - **Crash Analysis:** Inspects register state, stack contents, SEH chain, heap metadata.
   - **ROP Gadget Mining:** Scans loaded modules' `.text` sections for gadget sequences.
   - **Pattern/Offset:** Generates unique byte patterns and calculates offsets.
   - **Badchar Detection:** Compares input vs. output byte sequences to identify corruption.
5. **Output:** Results printed to Immunity's log pane; optionally saved to files (.txt, .py, .asm).

#### Key Modules (No Official Sub-Modules)

Unlike Metasploit or Impacket, mona.py is a **single monolithic script** (2000+ lines), not a collection of modules. However, it is conceptually organized into command families:

| Command Family | Purpose | Example Commands |
|---|---|---|
| **Pattern** | Unique pattern generation and offset calculation | `pattern_create`, `pattern_offset`, `pattern_search` |
| **ROP Gadgets** | ROP chain discovery | `rop`, `rop --chain`, `rop --bypass` |
| **Badchars** | Byte filtering analysis | `bytearray`, `badchars`, `badchars -b` |
| **Analysis** | Crash classification and exploitability | `analyze`, `info` |
| **SEH** | Structured Exception Handling inspection | `seh`, `seh -m` |
| **Config** | Module settings, ignore lists | `config`, `config --file` |
| **Misc** | Utilities, helpers | `egg`, `zp`, `unicode`, `pe` |

---

## Techniques/Protocols Used

| Technique/Protocol | Usage |
|---|---|
| **Windows Debug API** | Access to debugged process memory (via Immunity Debugger's Python bindings) |
| **Pattern Generation (De Bruijn)** | Creating unique byte sequences to identify crash offsets |
| **Memory Scanning (x86/x64)** | Opcode pattern matching to find ROP gadgets in module memory |
| **Stack/Heap Inspection** | Manual memory analysis to classify crash type |
| **SEH Chain Traversal** | Walking the SEH linked list to identify exploit opportunities |
| **PE Header Parsing** | Reading module base addresses and section boundaries |
| **x86/x64 Assembly** | Gadget identification and validation |

---

## Command-Line Switches — Quick Reference

**mona.py commands are invoked via the Immunity PyCommand console, not as CLI arguments.** Each command has sub-options.

| Command | Purpose | Usage |
|---|---|---|
| `!mona pattern_create -l <size>` | Generate unique byte pattern of given length | `!mona pattern_create -l 1000` → creates 1000-byte pattern |
| `!mona pattern_offset -q <value>` | Find offset of a 4-byte value in a pattern | `!mona pattern_offset -q 0x41424344` → offset to "ABCD" |
| `!mona bytearray -b <badchars>` | Generate bytearray with specified bytes excluded | `!mona bytearray -b "\x00\x0A"` → array without null/newline |
| `!mona badchars -b <badchars>` | Compare input vs. memory to identify corrupted bytes | `!mona badchars -b "\x00"` → shows which bytes didn't survive |
| `!mona rop --chain <intent>` | Generate ROP chain for specific purpose | `!mona rop --chain "call esp"` or `!mona rop --chain "ret2libc"` |
| `!mona rop -m <modules>` | Find ROP gadgets in specified modules only | `!mona rop -m "ntdll,kernel32"` |
| `!mona rop -b <badchars>` | Find ROP gadgets avoiding specified bytes | `!mona rop -b "\x00"` |
| `!mona analyze` | Auto-classify crash type and exploitability | `!mona analyze` (run at crash breakpoint) |
| `!mona seh` | Inspect and list SEH chain | `!mona seh` |
| `!mona seh -m <module>` | Find SEH pop/pop/ret gadgets in module | `!mona seh -m "ntdll"` |
| `!mona egg -t <egg>` | Search for egg-hunter pattern (useful for heap exploitation) | `!mona egg -t "w00t"` |
| `!mona config --file <file>` | Load/save mona configuration (e.g., ignored modules) | `!mona config --file "mona_config.txt"` |
| `!mona info` | Print current module info (loaded modules, base addresses) | `!mona info` |
| `!mona pe` | Parse and display PE header info for loaded modules | `!mona pe` |
| `!mona find -s <pattern> -m <module>` | Search for specific byte pattern in module | `!mona find -s "\xFF\xE4" -m "kernel32"` (find JMP ESP) |
| `!mona unicode` | Generate unicode-safe shellcode or payloads | `!mona unicode --input <file>` |

**Note:** Most commands support `-o` (output file), `-file` (config file), and `-v` (verbose) options.

---

## Quick Use-Case List

1. **Stack Overflow Pattern Offset Discovery** — Create unique crash pattern, send to vulnerable app, capture crash, use pattern_offset to find exact EIP/ROP-pivot offset.
2. **ROP Gadget Mining (ASLR Bypass)** — Discover "pop pop ret" gadgets across all loaded modules, build ROP chain to bypass ASLR/DEP.
3. **Badchar Identification** — Generate bytearray, inject into vulnerable buffer, use badchars to identify bytes truncated/corrupted during transmission.
4. **SEH Chain Exploitation Setup** — Inspect SEH frames, find pop/pop/ret gadgets, build SEH-override payload.
5. **Heap Spray + Egg Hunter** — Use egg command to locate egg-hunt payload in heap after spray operation.
6. **ROP Chain Generation** — Auto-generate Turing-complete ROP chains for VirtualAlloc/WriteProcessMemory/CreateRemoteThread workflows.
7. **Crash Analysis & Exploitability Assessment** — Load crash dump, run analyze, get auto-classification (stack overflow, heap corruption, NULL deref, etc.) and exploitability score.
8. **Module Base Address Discovery** — List all loaded modules and their base addresses (useful for info-leak verification).
9. **Gadget Validation (Post-Deployment)** — After exploiting a target, use mona to verify gadgets actually exist at addresses in the target's live memory (useful if ASLR/version variance is suspected).
10. **Custom Shellcode Encoding** — Use mona's encoding/obfuscation helpers to regenerate shellcode avoiding specific badchars.
11. **DEP Bypass Chain Construction** — Generate ROP chains that call VirtualAlloc/WriteProcessMemory to make stack writable, then redirect execution to shellcode.
12. **Chained Workflow with Metasploit** — mona patterns can be integrated with msfpattern for unified pattern-based crash analysis across tools.

---

## Prerequisites

**Required:**
- Immunity Debugger installed and licensed ($995).
- mona.py installed in Immunity's plugins folder (`%APPDATA%\Immunity Inc\Debugger\PyCommands\mona.py`).
- A debugged process paused at a breakpoint or crash (mona requires the process to be stopped, not running).
- Target binary with known/discovered vulnerability (buffer overflow, heap corruption, etc.).
- Understanding of x86/x64 assembly and ROP gadget construction.

**Optional:**
- Metasploit msfpattern (for pattern generation before mona, though mona's pattern_create replaces this).
- Ropper or other ROP gadget searcher (for comparison; mona's ROP chain generation is purpose-built for simplicity).
- WinDbg or Volatility (for deep memory forensics beyond mona's scope).

**Operator Context:**
- Typically used by exploit developers during development phase (not in active exploitation on the target).
- Assumed to have administrative access to the debugged machine (required to debug SYSTEM/elevated processes).

---

## See Also

- [Immunity Debugger Overview](../Immunity%20Debugger/01%20-%20Overview.md) — mona.py runs only inside Immunity Debugger; see Immunity's docs for debugger mechanics.
- **SEC660 / GXPN** — SANS Advanced Exploit Writing course; mona.py is the recommended tool for lab exercises.
- **OSCP Training** — Widely used in stack overflow labs; part of the standard training toolkit.
- **Windows/Threat Landscape and Playbooks/Exploit Development and Code Execution Playbook** — contextual exploitability assessment and post-exploitation correlation.
- **Metasploit/msfvenom** — For shellcode generation compatible with mona's badchar analysis.
