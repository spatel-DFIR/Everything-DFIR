# Sulley + boofuzz — Protocol Fuzzing Framework Family

A unified overview of two related protocol fuzzing frameworks: **Sulley** (legacy, 2007-2014) and **boofuzz** (active successor, 2015+). Despite different maintenance states, both embody the same core philosophy: **stateful, protocol-aware fuzzing** rather than blind mutation.

---

## Executive Summary

| Aspect | Sulley | boofuzz |
|--------|--------|---------|
| **Active** | ❌ No (archived ~2015) | ✅ Yes (commits in 2026) |
| **Python Version** | 2.7 only | 2.7 + 3.6+ |
| **Installation** | Complex, unreliable pip | `pip install boofuzz` ✅ |
| **Documentation** | Sparse, wiki-based | Complete, ReadTheDocs |
| **Result Logging** | Text logs, index.html | SQLite DB + CSV + text |
| **Supported Transports** | TCP, UDP, RPC, Serial | TCP, UDP, SSL, Serial, Ethernet, raw sockets |
| **Failure Detection** | ProcessMonitor, NetworkMonitor | ProcessMonitor, NetworkMonitor, CallbackMonitor |
| **Real-World Use (2026)** | Historical/legacy | Active (IoT, firmware, protocols) |
| **Recommendation** | Reference only | **Use this for new work** |

---

## Lineage and Fork History

### Sulley (2007-2014): The Original

**Pedram Amini (OpenRCE)** created Sulley as a revolutionary fuzzing framework that moved beyond simple byte mutation. Key insight: **protocols have state machines**. A buffer overflow might only be exploitable after successful authentication and entering a specific protocol state. Sulley automated this.

**Key Releases:**
- **v1.0 (2007-2014):** Stable, Python 2.7
- **v1.1 (unstable branch):** Development-phase improvements (never finalized)
- **Maintenance Stop (c. 2015):** Author moved to other projects; repository marked maintenance-only

**Legacy Impact:** Sulley set the standard for stateful fuzzing and remains the reference architecture for protocol-aware testing.

### boofuzz (2015-2026): Active Continuation

**Jeremy Thorpe (jtpereyda)** forked Sulley in 2015 when it became clear the original would not continue. boofuzz retains 100% of Sulley's core philosophy while modernizing:

- **Python 3 support** (critical for modern deployments)
- **Better logging** (SQLite + CSV, not just text)
- **More connection types** (SSL/TLS, Ethernet, custom)
- **Active maintenance** (security fixes, bug fixes, community support)
- **Documentation** (official ReadTheDocs, comprehensive examples)

**Current Status (2026):** Actively maintained, used in real-world IoT/firmware pentests, ~2,354 GitHub stars

---

## Architectural Philosophy: Stateful Protocol Fuzzing

Both Sulley and boofuzz implement **stateful fuzzing**, which is fundamentally different from mutation-only tools like AFL++ or Burp Intruder.

### Stateful vs. Mutation-Only

**Mutation-Only Approach (AFL++, standard fuzzers):**
1. Take input (file, HTTP request)
2. Randomly mutate bits/bytes
3. Send to target, check if it crashes
4. Repeat 1000s of times
5. Weakness: Doesn't understand protocol structure; invalid messages fail fast

**Stateful Protocol Fuzzing (Sulley, boofuzz):**
1. Define protocol as state machine (login → list → download → logout)
2. For each fuzz variant:
   - Render valid messages up to target state
   - Fuzz the field of interest at that state
   - Send the complete sequence
   - Monitor for crashes at any point
3. Strength: Tests realistic protocol interactions; discovers state-transition bugs

### Example: Why Stateful Matters

```
Mutation-only approach:
- Mutate "USER anonymous\r\n" → "US\xff\x00 anomym\r\n"
- Send to FTP server
- Server rejects (invalid command)
- No crash, test case discarded

Stateful approach (Sulley/boofuzz):
- Send valid "USER anonymous\r\n" (state 0→1)
- Send valid "PASS user@example.com\r\n" (state 1→2)
- Send FUZZED "LIST \xff\xff\xff\r\n" (state 2→3, list parsing path)
- Server attempts to parse list directory with corrupted size field
- Buffer overflow triggers → crash detected
```

The key: **Sulley/boofuzz reach protocol states that mutation-only tools never test**, because those tools generate invalid intermediate messages that fail fast.

---

## Fuzzing Framework Comparison Matrix

| Feature | Sulley | boofuzz | AFL++ | Burp Intruder | Honggfuzz |
|---------|--------|---------|-------|---------------|-----------|
| **Stateful Fuzzing** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Protocol Definition** | Custom blocks/primitives | Custom blocks/primitives | File-based mutations | HTTP-only | File-based mutations |
| **Network Protocols** | ✅ TCP/UDP | ✅ TCP/UDP/SSL | ❌ (file-based) | HTTP only | ❌ (file-based) |
| **Coverage-Guided** | ❌ | ❌ | ✅ (main feature) | ❌ | ✅ |
| **Crash Deduplication** | ✅ (signature-based) | ✅ (signature-based) | ✅ (crash hash) | Limited | ✅ |
| **Parallel Fuzzing** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Python Library** | ✅ | ✅ | ❌ (CLI-driven) | ❌ (web UI) | ❌ (CLI-driven) |
| **Ease of Use** | Medium | Easy | Hard (requires build setup) | Easy (GUI) | Medium |
| **Target Type** | Network services, embedded | Network services, embedded, IoT | Binaries, file parsers | Web applications | Any (file input) |
| **Maintenance Status (2026)** | ❌ Archived | ✅ Active | ✅ Active | ✅ Active (commercial) | ✅ Active |

---

## Use-Case Decision Tree

**Does your target accept network input?**
- ✅ Yes → Is it a well-defined protocol? → ✅ Yes → **Use boofuzz (or Sulley for historical context)**
- ✅ Yes → Is it HTTP/web APIs? → ✅ Yes → **Use Burp Intruder** (simpler, focused)
- ❌ No → **Use AFL++** or file-based fuzzer

**Protocol categories where Sulley/boofuzz excel:**
- FTP, SMTP, POP3, IMAP (mail protocols)
- SSH, Telnet (remote access)
- SMB, RPC (file sharing, inter-process)
- Proprietary binary protocols (embedded systems, IoT, custom applications)
- Kerberos, LDAP (directory services)
- SIP, H.323 (VoIP)
- Any protocol where **order of operations matters** (stateful)

---

## Shared Features (Both Frameworks)

### 1. Primitive Data Types
```
String(), Bytes(), Dword(), Checksum(), Size(), ...
```

### 2. Block Nesting
```
Groups of primitives organized hierarchically
Conditional blocks (If/Else)
Repeating blocks (Repeat)
```

### 3. Automatic Field Updates
```
Checksum() automatically recalculates CRC/MD5
Size() automatically updates length fields
Eliminates false crashes due to malformed wrappers
```

### 4. Instrumentation
```
ProcessMonitor: Detects crashes, automatic target restart
NetworkMonitor: Captures traffic, packet analysis
Custom callbacks: Arbitrary failure detection (user-defined)
```

### 5. Crash Categorization
```
Crashes deduplicated by signature (exception type + address)
Avoids "duplicate crash" noise
Highlights novel, exploitable bugs
```

### 6. Long-Running Unattended Operation
```
Runs for hours/days without operator interaction
Automatic target restart on crash
Can test 100,000+ variants in one session
Operators come back to find crash PoCs
```

---

## Forensic Differentiation (Attacker's Machine)

### Sulley Artifacts
- **Script:** `from sulley import *`
- **Results:** `fuzz_results/index.html` (text log), crash files, per-test logs
- **Logging:** Text-only (no database)

### boofuzz Artifacts
- **Script:** `from boofuzz import *`
- **Results:** `boofuzz.db` (SQLite), `boofuzz.csv`, text logs
- **Logging:** Structured database + spreadsheet export

**Key Differentiator:** **boofuzz.db** is unmistakable. If found on an attacker's machine, **it's boofuzz, not Sulley.**

---

## Target-Side Forensics (Indistinguishable)

From a **target's perspective**, Sulley and boofuzz are forensically identical:

- **Crashes:** Multiple fault addresses in short time (both)
- **Error logs:** Protocol violations, malformed messages (both)
- **Service restarts:** Crash → restart → crash loop (both)
- **Network traffic:** Malformed protocol messages with systematic variation (both)

**Differentiation requires access to attacker's machine** (where boofuzz.db would be found).

---

## When to Use Each

### Use Sulley If:
1. You're analyzing a **2007-2014 era attack** (forensic analysis)
2. You need **historical context** on protocol fuzzing
3. You're constrained to **Python 2.7** (increasingly rare)
4. You're reviewing legacy research/PoCs

### Use boofuzz If:
1. You're **fuzzing a new target** (current era)
2. You're on **Python 3** (default for modern systems)
3. You want **active maintenance and bug fixes**
4. You need **better logging** (SQLite + CSV export)
5. You're testing **IoT/firmware** (serial, Ethernet, embedded)
6. You need **SSL/TLS fuzzing** capabilities
7. You want **official documentation** and community support

**TL;DR:** boofuzz is the clear choice for all new work in 2026. Sulley is for understanding history and legacy cases.

---

## Installation Summary

### Sulley (Not Recommended)
```bash
git clone https://github.com/OpenRCE/sulley.git
cd sulley
python setup.py install  # Fragile, Python 2.7 only
```

### boofuzz (Recommended)
```bash
pip install boofuzz  # Simple, works with Python 3
```

---

## Documentation and Resources

### Sulley
- **Official GitHub:** https://github.com/OpenRCE/sulley
- **Wiki:** https://github.com/OpenRCE/sulley/wiki (minimal)
- **Papers:** Pedram Amini's original 2007 research (archived)

### boofuzz
- **Official GitHub:** https://github.com/jtpereyda/boofuzz
- **Documentation:** https://boofuzz.readthedocs.io/ (complete)
- **Quick Start:** https://boofuzz.readthedocs.io/quickstart/
- **Examples:** https://github.com/jtpereyda/boofuzz/tree/master/examples
- **Request Definitions:** Pre-built protocol templates (FTP, HTTP, DNS, etc.)

---

## Relationship to Other Tools in This Module

### Cross-Links to Related Purple Teaming Tools

**Fuzzing Framework Cousins:**
- **Scapy** (`Purple Teaming/Scapy/`) — Packet crafting/generation, complementary to Sulley/boofuzz
- **AFL++** (`Purple Teaming/AFL++/` if built) — Coverage-guided fuzzing for binaries/files (different paradigm)

**Crash Analysis (Post-Fuzzing):**
- **Immunity Debugger** (`Purple Teaming/Immunity Debugger/` if built) — Analyze crash dumps, develop exploits
- **GDB / WinDbg** — Debugger integration for detailed crash analysis

**Protocol References:**
- `Windows/` notes on SMB, RPC, Kerberos (protocols often fuzzed with Sulley/boofuzz)
- `Linux/` notes on SSH, network services (common fuzzing targets)
- `Cloud/` notes on APIs (HTTP fuzzing via boofuzz possible, though Burp Intruder often preferred for APIs)

---

## Key Takeaways

1. **Sulley and boofuzz are siblings**, not competitors — boofuzz is Sulley's modern, maintained successor
2. **Stateful fuzzing is different** from mutation-only approaches — both frameworks test realistic protocol state sequences
3. **Target-side forensics are identical** (crashes, errors, restarts) — differentiation requires attacker's machine analysis
4. **boofuzz is the clear choice for 2026** — active maintenance, Python 3, better logging, complete documentation
5. **boofuzz.db is definitive evidence** of boofuzz use (SQLite database with complete fuzzing records)
6. **Both belong to the "deep protocol testing" category** — complementary to tools like AFL++ (file-based) and Burp Intruder (HTTP-focused)

---

## Summary Table: Sub-Tool Navigation

| Sub-Folder | Purpose | Key Artifact |
|------------|---------|-------------|
| **`Sulley/`** | Legacy framework (2007-2014), Python 2.7, text-based logging | Text logs, crash files, fuzz script imports `sulley` |
| **`boofuzz/`** | Active successor (2015-2026), Python 3, SQLite + CSV logging | boofuzz.db database, boofuzz.csv, fuzz script imports `boofuzz` |

Each sub-folder contains 5 files: 01 - Overview, 02 - Hands-On, 03 - Source Evidence, 04 - Target Evidence, 05 - Detection & Hunting.

---

**Navigate to `Sulley/` or `boofuzz/` for detailed operational and forensic guidance per framework.**
