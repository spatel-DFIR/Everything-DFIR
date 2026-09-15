# Immunity Debugger — Overview

🔴 **Immunity Debugger is a commercial, closed-source Windows userland debugger with built-in Python scripting (via PyCommand), making it the primary platform for exploit development in training and adversary-assumed tooling alongside plugin extensions like mona.py for automated crash analysis and ROP gadget hunting.**

## History

**Immunity Debugger** is a commercial Windows debugger developed by Immunity Inc. It emerged in the mid-2000s as a more user-friendly alternative to OllyDbg and WinDbg for exploit development, particularly within training environments like OSCP and exploit-dev courses.

- **Original Release:** ~2004 (closed-source, proprietary)
- **Current Status:** Commercial software ($995 per license, Immunity Inc.)
- **License:** Proprietary (closed-source, not open-source)
- **Primary Audience:** Exploit developers, security researchers, pentesters, malware analysts
- **Platform:** Windows only (32-bit and 64-bit support)
- **No Official Public Repository:** Immunity Inc. does not publish source code or maintain a public GitHub repository. Binaries are distributed directly via license purchase from immunity.com.

**Key Adoption Points:**
- OSCP and SEC660 students commonly use Immunity Debugger for stack-based buffer overflow labs, where its Python scripting and GUI interactivity dominate over command-line alternatives (GDB on Linux).
- mona.py plugin (free, by Corelan) has become a de-facto standard companion since ~2010, automating pattern finding, ROP gadget discovery, and crash triage — so widely paired that "Immunity + mona" is discussed as a single toolset in most exploit-dev curricula.

---

## How It Works

### Architecture

Immunity Debugger operates as a **userland debugger**:
1. **Attachment/Launch:** Debugger injects into a target process via the Windows Debug API (`DebugActiveProcess()`, `CreateProcessW()` with `DEBUG_PROCESS` flag).
2. **Breakpoint Mechanism:** Software breakpoints (`int 3` / `0xCC` opcode insertion, per-process per-address), hardware breakpoints (x86 DR0-DR7 registers, 4 total), and conditional breakpoints via Python hooks.
3. **Single-Step Execution:** Trap Flag (TF, bit 8 of EFLAGS) for step-through; TRACE exception fires per instruction.
4. **Memory Access:** Direct process memory read/write via Windows API (`ReadProcessMemory()`, `WriteProcessMemory()`).
5. **Register Inspection:** Full x86/x64 register state (EAX, EBX, ECX, EDX, ESP, EBP, ESI, EDI, EIP, EFLAGS, segment registers) inspectable and modifiable during pause.
6. **Python Scripting (PyCommand):** Immunity's proprietary Python environment (bundled Python interpreter) allows custom plugins/scripts to hook breakpoints, modify memory, automate crash analysis, and generate payloads — **this is the distinctive feature that attracts exploit developers over raw WinDbg.**

### Protocol/Mechanics Detail

**Debugging Loop:**
```
Attacker → [Immunity Debugger] → [Debug API] → Target Process (debuggee)
  Launch/Attach
    ↓
  Install Breakpoint (0xCC opcode write to code section)
    ↓
  Continue Execution (SetThreadContext, ContinueDebugEvent)
    ↓
  Hit Breakpoint → Exception (EXCEPTION_BREAKPOINT)
    ↓
  Pause, Inspect Registers/Memory, Run Python Hooks
    ↓
  Step / Set Conditional Breakpoint / Modify Memory
    ↓
  Resume
```

**Named Pipe/IPC:** None — Immunity Debugger communicates only with the local Windows Debug API, not with remote processes. Debugging is local only (no remote debugging equivalent to GDB's remote protocol).

**Output Handling:** Debuggee stdout/stderr captured in Immunity's own GUI log pane; breakpoint hits/register states printed to the Immunity console; Python hooks can log to files or external tools.

---

## Techniques/Protocols Used

| Technique/Protocol | Usage |
|---|---|
| **Windows Debug API** | `DebugActiveProcess()`, `CreateProcessW(DEBUG_PROCESS)`, `WaitForDebugEvent()`, `ContinueDebugEvent()`, `SetThreadContext()`, `GetThreadContext()` — core debugger attachment and control |
| **x86/x64 Exception Handling** | EXCEPTION_BREAKPOINT (0x80000003), EXCEPTION_SINGLE_STEP (0x80000004), EXCEPTION_ACCESS_VIOLATION, EXCEPTION_STACK_OVERFLOW — debugger-intercepted exceptions |
| **Software Breakpoints** | `int 3` (0xCC opcode) inserted into executable memory; replaced with original byte on continuation |
| **Hardware Breakpoints** | x86 Debug Registers (DR0, DR1, DR2, DR3 for addresses; DR6 for status; DR7 for control), per-thread, max 4 simultaneous |
| **Python Scripting** | PyCommand environment bundled with Immunity; can intercept breakpoints, modify registers/memory, generate ROP gadgets (via mona.py plugin) |
| **SEH (Structured Exception Handling)** | Inspection and modification of SEH chains for bypass/exploitation techniques |
| **DEP/ASLR Analysis** | Manual inspection (via mona.py automation); no native DEP bypass — bypasses must be coded/staged by operator |

---

## Command-Line Switches — Quick Reference

Immunity Debugger is primarily a **GUI application** with limited command-line switches. Most interactions occur through the GUI and Python console.

| Switch | Purpose | Usage Example |
|---|---|---|
| `-c <script>` | Execute a Python script immediately on launch | `Debugger64.exe -c "run" vulnerable.exe` |
| `-p <process-id>` | Attach to an existing process by PID | `Debugger64.exe -p 1234` |
| `<binary>` | Launch and debug a binary directly | `Debugger64.exe vulnerable.exe` |
| No switch | Launch GUI without a target | `Debugger64.exe` (open GUI, attach manually later) |

**PyCommand Console (Interactive):**
Once the debugger is running and a breakpoint is hit or you pause execution, the PyCommand console (bottom pane of the GUI) accepts Python commands directly:
- `help` — list available PyCommand functions
- `stepinto()` — step into the next instruction
- `stepover()` — step over (execute without stepping into calls)
- `run()` — continue execution
- `bp(address)` — set a breakpoint at an address (e.g., `bp("0x004011A0")`)
- `write_memory(address, data)` — write to process memory
- `read_memory(address, length)` — read from process memory
- Custom Python can import mona.py's modules (if installed) to run advanced analysis

**GUI Interaction (Not CLI):**
- Right-click any address in the disassembly view to set/remove breakpoints.
- Double-click a register or memory cell to edit in-place.
- Drag and drop data into memory pane to patch bytes.

---

## Quick Use-Case List

1. **Basic Program Debugging** — Launch a vulnerable binary, set breakpoint at a function entry point, inspect register state before/after function calls.
2. **Breakpoint-Driven Control Flow** — Set breakpoints at specific code addresses (e.g., `strcpy` call), inspect arguments (stack/registers), step through caller's exception handling.
3. **Buffer Overflow PoC Development** — Crash a binary with a fuzzer, open crash dump or re-run vulnerable code in debugger, step through stack corruption, verify EIP control.
4. **ROP Gadget Discovery** — Use mona.py's `pattern create` to generate unique crash pattern, trigger crash, use mona's pattern-offset analysis to find stack offset to EIP/ROP pivot.
5. **Stack-Based Exploitation Walkthrough** — Step through shellcode injection: observe argument marshaling, breakpoint at `ret` instruction, observe ESP/EIP transition to shellcode.
6. **SEH Chain Exploitation** — Inspect SEH chain structure (via manual memory inspection or mona.py's `seh` command), identify overwrite opportunity, verify SEH-chain rewrite points before final exploit.
7. **Badchar Identification** — Inject mona.py's `bytearray` patterns, step through string-copy functions, use mona's badchar-detection to identify bytes that truncate/corrupt payload.
8. **ASLR Bypass Verification** — Run binary multiple times, inspect base addresses of modules (DLL list in Immunity GUI), verify ASLR-bypass technique (e.g., heap spray, info leak) works.
9. **Crash Log Analysis & Triage** — Load a minidump (File → Open Crash Dump), inspect exception context, use mona.py's `!mona analyze` to auto-classify crash type (heap corruption, stack overflow, NULL deref, etc.).
10. **Shellcode Validation** — Inject shellcode at a writable address, set breakpoint at shellcode entry, step through first few instructions to verify correct encoding (no bad chars, no truncation).
11. **Multi-Stage Payload Verification** — Debug Stage 1 (stager), set breakpoint before Stage 2 allocation, inspect heap, verify Stage 2 binary lands at expected address before execution.
12. **Live Patching for Exploit Refinement** — Pause at a crash point, patch the binary in memory (overwrite opcodes), resume execution to test the fix without rebuilding.

---

## Prerequisites

**Per Use Case:**

| Use Case | Prerequisites |
|---|---|
| Basic debugging, breakpoints, stepping | Immunity Debugger license; target binary (compiled or prebuilt); Windows machine (admin recommended for some attach scenarios) |
| ROP gadget discovery, crash analysis | Immunity Debugger + mona.py plugin installed; target binary with known vulnerability or fuzzer-generated crash; sec tools (Metasploit msfpattern for pattern creation, though mona.py replaces this) |
| SEH exploitation | Windows system with SEH-enabled code (pre-Windows Vista, or opt-in on newer Windows); Immunity Debugger; understanding of SEH structure and overwrite mechanics |
| ASLR bypass verification | Windows 6.0+ (Vista/Server 2008+) with ASLR enabled; Immunity Debugger; knowledge of ASLR bypass technique being tested (heap spray, info leak, etc.) |
| Crash dump analysis | Minidump file (.dmp) from application crash; Immunity Debugger; optional mona.py for auto-analysis |
| Live memory patching | Immunity Debugger; writable target address space; shellcode or patch bytes; understanding of x86 encoding to avoid bad chars |

**Operator-Side Requirements:**
- Windows machine (can be Windows 7 – Windows 11; 32-bit or 64-bit Debugger64.exe matched to target process bitness)
- Administrator rights (optional, but required for attaching to some processes or debugging drivers)
- Immunity Debugger license ($995, commercial; no free tier)
- mona.py plugin (free, open-source, installed separately into Immunity's plugin folder)
- Familiarity with x86/x64 assembly, stack layout, and exploit mechanics (not a beginner tool)

---

## See Also

- [mona.py Overview](../mona.py/01%20-%20Overview.md) — free plugin that extends Immunity Debugger's crash analysis and ROP gadget discovery (often discussed as a single tool)
- **WinDbg** (Wave 4 #10) — alternative Windows debugger (free, command-line/GUI hybrid, steeper learning curve but more powerful for kernel debugging)
- **pwntools** (Wave 4 #8) — Linux exploit-dev scripting library; Immunity Debugger is the Windows equivalent for interactive debugging
- **GDB** (`Windows/` exploit-dev context in another repo) — Linux userland debugger, similar role to Immunity on Windows but free and open-source
- **SEC660** (SANS Advanced Exploit Writing course) — primary adopter of Immunity Debugger for stack overflow labs; Immunity is listed as the recommended/assumed debugger in lab materials
