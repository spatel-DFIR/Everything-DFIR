# boofuzz — Protocol Fuzzing Framework (Sulley Successor)

## History

**boofuzz** is the actively maintained successor to Sulley, forked and continued by **Jeremy Thorpe (jtpereyda)** starting in 2015 after Sulley entered maintenance mode. boofuzz retains Sulley's core philosophy (stateful protocol fuzzing) while modernizing the codebase for Python 3 compatibility, improving documentation, and simplifying installation and extensibility.

- **Repository:** https://github.com/jtpereyda/boofuzz
- **Official Tagline:** "Network Protocol Fuzzing for Humans"
- **License:** GNU General Public License v2.0
- **Current Version:** v0.4.3+ (actively maintained)
- **Last Update:** 2026-08-06 (very recent)
- **Stars:** 2,354 (vs. Sulley's 1,448)
- **Python Support:** Python 2.7+ and Python 3.6+ (unlike Sulley 1.0, which is Python 2.7 only)
- **Installation:** `pip install boofuzz` (simple, clean)

## Key Differences from Sulley

| Aspect | Sulley 1.0 | boofuzz |
|--------|-----------|---------|
| **Python Support** | Python 2.7 only | Python 2.7 + Python 3.6+ |
| **Maintenance** | Archived (since ~2015) | Active (commits in 2026) |
| **Installation** | Complex, pip unreliable | `pip install boofuzz` (works) |
| **Documentation** | Sparse, wiki-based | Complete, official ReadTheDocs |
| **CLI** | None (library only) | Minimal CLI support (mostly library) |
| **Test Result Logging** | Text log only | Text + CSV export + Database (SQLite) |
| **Connection Types** | TCP, UDP, RPC, Serial | TCP, UDP, SSL, Serial, raw sockets, Ethernet, custom |
| **Failure Detection** | ProcessMonitor, NetworkMonitor | ProcessMonitor, NetworkMonitor, CallbackMonitor, generic |
| **Extensibility** | Good (for 2014) | Better (modern architecture) |
| **Bug Fixes** | None (archived) | Ongoing (security + stability) |

## How It Works

boofuzz operates on the **identical conceptual model as Sulley**: define a protocol using primitives and blocks, then fuzz variants through all permutations, sending to a target and monitoring for crashes.

### Core Architecture (Familiar to Sulley Users)

1. **Primitives** — atomic data types (String, Bytes, UShort, UInt, Checksum, Size, etc.)
2. **Blocks** — groupings of primitives with nesting, conditionals, and repeating
3. **Requests** — named message templates built from block-trees
4. **Connections** — transport layer (TCP, UDP, SSL, Serial, raw socket, custom)
5. **Sessions** — the orchestrator (target connection, instrumentation, fuzz iteration)
6. **Monitors** — crash detection and target reset (ProcessMonitor, NetworkMonitor, custom callbacks)

### Key Classes (API Entry Points)

```python
from boofuzz import Session, SocketConnection, Target, Request
from boofuzz import s_initialize, s_static, s_string, s_bytes, s_size, s_checksum

# Session: Main orchestrator
session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.100", 80, proto="tcp"),
    ),
    log_dir="./fuzz_results"
)

# Requests: Named message templates
s_initialize("HTTP_GET")
s_static("GET /")
s_string("index.html", fuzzable=True)
s_static(" HTTP/1.1\r\n\r\n")

# Fuzz and run
session.fuzz(s_get("HTTP_GET"))
session.run()
```

### Improvements Over Sulley

1. **Better Logging:** Results are stored in SQLite database (queryable) + CSV export, not just text logs
2. **More Connection Types:** Built-in SSL/TLS, Ethernet raw sockets, UDP broadcast
3. **Improved Process Monitor:** More robust crash detection, fewer false negatives
4. **Python 3:** Modern language, type hints, better error messages
5. **Active Development:** Security fixes, bug fixes, new features
6. **Documentation:** Full API reference on ReadTheDocs (boofuzz.readthedocs.io)

## Techniques/Protocols Used

- **Protocol-Agnostic:** Like Sulley, user defines the protocol via primitives/blocks
- **Example Protocols Included:**
  - HTTP (FTP, SMTP, POP3, IMAP examples in repo)
  - Custom binary protocols
  - Serial/embedded protocols
  - Network protocols (DNS, NTP, TFTP)
  - IoT/firmware protocols (CAN bus examples)

## Command-Line Interface

**boofuzz is primarily a library, not a CLI tool.** Like Sulley, campaigns are defined as Python scripts. However, boofuzz has minimal CLI support:

```bash
# No direct CLI invocation; use scripts:
python3 fuzz_target.py

# To run a specific example from the repo:
python3 examples/ftp_simple.py
python3 examples/http_simple.py
```

**Library Entry Points (in code):**

```python
from boofuzz import Session, Target, SocketConnection
from boofuzz import s_initialize, s_static, s_string, s_bytes, s_size, s_checksum
from boofuzz import process_monitor, network_monitor
from boofuzz.fuzz_logger import FuzzLogger
```

No CLI flags; configure entirely in Python scripts.

## Quick Use-Case List

1. **Stateful protocol fuzzing** — multi-message protocol sequences
2. **Network service fuzzing** — TCP/UDP services (HTTP, FTP, etc.)
3. **Crash identification and reproduction** — find and verify protocol vulnerabilities
4. **Firmware/embedded device fuzzing** — serial protocols, CAN bus, UART
5. **Parallel fuzzing** — multiple workers for speed
6. **Long-running unattended campaigns** — hours/days of fuzzing with automatic logging
7. **IoT device testing** — constrained networks, protocol-aware approach
8. **Custom protocol definition** — non-standard wire formats (binary protocols)
9. **Crash categorization** — boofuzz deduplicates crashes by signature (exception type, address)
10. **Integration with Wireshark** — capture network traffic during fuzzing for manual analysis
11. **Result export and analysis** — CSV/database output for post-processing
12. **Debugger integration** — GDB/WinDbg attached to target for detailed crash analysis

## Prerequisites

- **Python 3.6+** (Python 2.7 also supported, but deprecated)
- **pip** package manager
- **Target access** — network/process access to service being fuzzed
- **Optional: Debugging tools** — WinDbg (Windows), GDB (Linux) for crash analysis
- **Optional: Instrumentation** — ProcessMonitor or custom failure callback

## Architecture Depth: Main Changes from Sulley

### Logging and Result Storage

**Sulley:** Text log files only (index.html, crash files, per-test logs)

**boofuzz:** Multiple formats:
- **SQLite Database:** `fuzz_results.db` — queryable, structured
- **CSV Export:** `fuzz_results.csv` — importable into Excel/spreadsheet
- **Text Log:** `fuzz_results.txt` — human-readable
- **Curses UI:** Live real-time display of fuzzing progress (Linux/Mac)

**Example querying boofuzz results:**

```python
import sqlite3

db = sqlite3.connect("fuzz_results.db")
cursor = db.cursor()

# Find all crashes:
cursor.execute("SELECT test_case_num, crash_type FROM test_case WHERE passed = 0")
for row in cursor:
    print(f"Test case {row[0]} crashed with: {row[1]}")
```

### Connection Types (Expanded)

**Sulley:** TCP, UDP, RPC, Serial

**boofuzz adds:**
- **SSL/TLS** — encrypted connections
- **Raw Ethernet** — layer 2 fuzzing
- **UDP Broadcast** — network-wide fuzzing
- **Custom Connections** — operator-defined transport classes

### Monitor Types (Expanded)

**Sulley:** ProcessMonitor, NetworkMonitor

**boofuzz adds:**
- **CallbackMonitor** — arbitrary Python function checking for failure
- **GenericMonitor** — base class for custom monitors
- **Better error detection:** Memory leaks, hangs, not just crashes

### Request Definitions (Same as Sulley)

Blocks, primitives, size/checksum auto-update work identically. boofuzz is backward-compatible with Sulley request definitions (with minor syntax adjustments).

---

## Reference Documentation

- **Official Documentation:** https://boofuzz.readthedocs.io/ (complete, well-maintained)
- **Quick Start:** https://boofuzz.readthedocs.io/quickstart/ (recommended starting point)
- **API Reference:** https://boofuzz.readthedocs.io/boofuzz/ (function signatures)
- **Examples:** https://github.com/jtpereyda/boofuzz/tree/master/examples (FTP, HTTP, DNS, etc.)
- **Request Definitions:** https://github.com/jtpereyda/boofuzz/tree/master/request_definitions (pre-built protocol templates)
- **GitHub Issues:** https://github.com/jtpereyda/boofuzz/issues (bug reports, feature requests)

---

## Installation

```bash
# Simple:
pip install boofuzz

# From source (for latest development):
git clone https://github.com/jtpereyda/boofuzz.git
cd boofuzz
pip install -e .
```

**Compatibility:** Installs cleanly on Windows, Linux, macOS. Python 3 recommended.

---

## Positioning: Sulley vs. boofuzz

**Use Sulley if:**
- You're analyzing a legacy system (2007-2014 era)
- You need historical knowledge of the framework
- You're restricted to Python 2.7 (unlikely in 2026)

**Use boofuzz if:**
- You're fuzzing a modern target
- You want active maintenance and bug fixes
- You're fuzzing IoT/firmware devices
- You want better logging/result analysis
- You prefer Python 3
- You need SSL/TLS or Ethernet fuzzing

**In 2026, boofuzz is the clear choice for new work.**
