# Sulley — Protocol Fuzzing Framework

## History

**Sulley** is a pure-Python fuzzing framework developed by **OpenRCE** (originally by Pedram Amini) between 2007 and 2014. The framework was one of the earliest comprehensive, stateful protocol fuzzers designed to model entire network protocols, not just mutate binary blobs. Sulley 1.0 is the stable release (as of the master branch); the project has entered maintenance-only mode since ~2015, with the author explicitly recommending **boofuzz** (its active successor) for new work.

- **Repository:** https://github.com/OpenRCE/sulley (main, stable branch)
- **Unstable Branch:** https://github.com/OpenRCE/sulley/tree/Sulley1.1 (development branch, 1.1 changes)
- **License:** GNU General Public License v2.0
- **Last Update:** 2020-12-29 (stable branch)
- **Stars:** 1,448
- **Primary Author/Maintainer:** Pedram Amini (OpenRCE), now in stewardship mode

## How It Works

Sulley models network protocols as a **state machine with fuzzable primitives**. Rather than randomly mutating byte sequences (mutation-only fuzzers), Sulley builds well-formed protocol messages from scratch, then intelligently corrupts specific fields.

### Core Architecture

1. **Primitives** — atomic fuzzable data types:
   - `String()`, `Bytes()` — fixed/variable-length data
   - `UShort()`, `UInt()`, `ULong()` — unsigned integers (configurable byte order)
   - `SignedInt()`, `Float()`, `Double()` — signed/floating-point types
   - `Checksum()`, `Size()` — computed fields (CRC, length prefixes) that update automatically
   - `BitField()` — sub-byte bit-level fuzzing

2. **Blocks** — group primitives into logical message structures:
   - Nesting: blocks can contain other blocks
   - Conditionals: `If()` blocks only render under certain fuzzing variants
   - Repeating: `Repeat()` blocks for variable-length arrays/lists
   - Encoding: optional Base64/hex wrapping

3. **Requests** — named, fuzzable network messages:
   - Each request is a block-tree of primitives
   - Requests are grouped into protocol definitions

4. **Sessions** — the orchestrator:
   - Manages target instrumentation (process monitors, network monitors)
   - Iterates through fuzz case generation
   - Sends requests to the target via configured connections
   - Records crashes and categorizes failures

5. **Connections** — protocol-layer abstractions:
   - TCP/UDP sockets
   - Raw sockets (Ethernet)
   - Serial (COM ports)
   - RPC (custom via pedrpc)

6. **Instrumentation**:
   - **Process Monitor** — Windows/Unix process health, crash detection, automatic target restart
   - **Network Monitor** — packet capture and filtering
   - Custom failure callbacks (Python functions)

### Fuzzing Workflow

```
1. Define protocol primitives and blocks (structure)
2. Create named requests (protocol messages)
3. Open a session with target instrumentation (crash detection, reset)
4. For each fuzz variant:
   a. Render the request(s) from the current fuzz state
   b. Send to target
   c. Receive response (if applicable)
   d. Check instrumentation for crashes/anomalies
   e. Record results (passed/failed/crashed)
   f. Advance fuzz state (next variant)
5. Analyze results for unique crash signatures (exploitation leads)
```

### Key Characteristic: Stateful Fuzzing

Unlike tools like AFL++ (coverage-guided) or Burp Intruder (web-only), Sulley is **protocol-aware**: it understands that a protocol is a sequence of state transitions. A single fuzz variant might be:
- "Corrupt byte 3 of the login request" (state 0→1)
- Then send a valid "list files" request (state 1→2)
- Then send a corrupted "download" request (state 2→3)

This allows fuzzing of vulnerabilities that only manifest after a specific sequence of operations — far more realistic than stateless message mutation.

## Techniques/Protocols Used

- **Protocols Covered:** Protocol-agnostic (user-defined). Examples in the repository include:
  - HTTP (basic web server fuzzing)
  - FTP (file transfer protocol)
  - SMB (Windows file sharing) — complex, multi-stage
  - Custom binary protocols (Trillian chat, etc.)

- **Underlying Mechanisms:**
  - TCP/UDP socket I/O
  - Raw packet crafting (Scapy-like)
  - Named pipes and IPC (Windows)
  - Serial port communication
  - Custom RPC (pedrpc) for out-of-process monitoring

- **Crash Detection:**
  - Process exit code / signal (Unix)
  - Windows exception (access violation, segfault)
  - Debugger breakpoints (if attached)
  - Custom instrumentation callbacks (user-defined logic)

## Command-Line Switches — Quick Reference

Sulley is **not a CLI tool** — it is a **Python library**. Fuzzing campaigns are defined as Python scripts (often named `fuzz_*.py` by convention) that import Sulley modules and call them directly. No command-line flags; configuration is done in code.

Example invocation:
```bash
python3 fuzz_target_http.py
```

Key library entry points:
- `sulley.sessions.Session()` — create a fuzzing session
- `sulley.blocks.Request()` — define a network message
- `sulley.primitives.*` — data types
- `sulley.process_monitor.ProcessMonitor()` — Windows crash detection
- `sulley.process_monitor_unix.ProcessMonitor()` — Unix crash detection
- `sulley.network_monitor.NetworkMonitor()` — packet sniffing

No built-in web UI or result browser — results are logged to files and post-processed by the operator.

## Quick Use-Case List

1. **Stateful protocol fuzzing** — network service with a defined state machine (login → commands → disconnect)
2. **Custom protocol definition** — non-standard wire formats not handled by generalist tools
3. **Crash reproduction** — take a known crash signature and generate a minimal PoC
4. **Parallel fuzzing** — run multiple fuzz workers against the same target
5. **Automated target reset** — crash and reboot the target, continue fuzzing unattended
6. **Binary protocol fuzzing** — proprietary wire formats (not HTTP, not text-based)
7. **Embedded/firmware fuzzing** — serial-connected device (bootloader, UART console)
8. **Integration with crash analysis** — export crash test cases for manual exploit development
9. **Long-running unattended campaigns** — run for hours/days, collect all crash-triggering sequences
10. **Post-compromise protocol fuzzing** — fuzz internal RPC/IPC protocols after gaining code execution

## Prerequisites

- **Python 2.7 or Python 3.6+** (Sulley 1.0 uses Python 2.7; later versions support Python 3)
- **Target access** — network/process access to the protocol implementation being fuzzed
- **Instrumentation setup** (varies by use case):
  - Process Monitor: requires WinDbg/gdb-like debugging capability, local admin rights on Windows
  - Network Monitor: raw socket capability (requires root/admin on many systems)
  - Serial: physical or virtual COM port access
- **Patience** — stateful protocol fuzzing is deliberate and can take hours/days to cover all variants
- **Protocol knowledge** — understanding the target protocol structure (request/response format, state transitions) — this is the main up-front work

---

## Architecture Depth: Primitives and Mutation

### Fuzzing Modes

Sulley generates fuzz variants in several modes (iterative, not random):

1. **Valid fuzzing** — render each primitive with its valid value, collect baseline (crash-free test data)
2. **Bit-level fuzzing** — flip single bits in each field, one at a time
3. **Byte-level fuzzing** — replace each byte with boundary values (0x00, 0xFF, 0x7F, 0x80)
4. **String fuzzing** — replace string fields with known crash-triggering patterns (SQLi payloads, buffer overflow patterns, format strings, etc.)
5. **Size field fuzzing** — corrupt length/count fields to cause buffer overflows or off-by-one errors
6. **Checksum fuzzing** — intentionally corrupt checksums/CRCs to trigger validation failures

Each mode iterates through all fuzzable fields independently, generating thousands of test cases.

### Crash Categorization

When a crash is detected, Sulley captures:
- **Test case ID** — which fuzz variant triggered it
- **Crash type** — exception type, address, signal
- **Crash address** — (Windows/debugger) EIP/RIP value, heap/stack/code region
- **Call stack** — if debugger attached
- **Register state** — for reproduction

Multiple crashes are **deduplicated** by signature (e.g., all crashes at address `0x41414141` are grouped as one unique bug). This prevents "duplicate crash" noise and highlights novel exploitable behaviors.

### Encoding and Checksums

Sulley automatically handles:
- **CRC16/CRC32/Adler32/MD5** checksums — declare a field as `Checksum()`, specify algorithm and scope, Sulley updates it on each render
- **Length prefixes** — declare a field as `Size()`, and it auto-updates when its target block changes
- **Base64/Hex encoding** — wrap a block in `Block(..., encoder=base64/hex)`, and rendering automatically encodes
- **Byte order** — `UInt(..., endian='>')` for big-endian, default is little-endian

This allows fuzzing of **inner** (unencoded) field values while Sulley automatically fixes up the outer **structural** fields (length, checksum), avoiding false crashes due to malformed wrapper fields.

---

## Reference Documentation

- **Official Wiki:** https://github.com/OpenRCE/sulley/wiki
- **Documentation (limited):** https://github.com/OpenRCE/sulley/tree/master/docs
- **Examples:** https://github.com/OpenRCE/sulley/tree/master/requests (example protocol definitions)
- **Note:** Much Sulley knowledge is embedded in the source code itself and community write-ups; official docs are sparse
