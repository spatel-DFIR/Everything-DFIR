# Sulley — Hands-On Use Cases

All use cases are **Python scripts** invoking the Sulley library. Each example demonstrates a distinct attack pattern. Assume Sulley is installed via `pip install sulley` (note: this installs the legacy 1.0; for Python 3 support, install from git).

---

## 1. Stateful FTP Fuzzing

**Scenario:** Fuzz an FTP server through a complete session (login → list → download).

**File:** `fuzz_ftp_stateful.py`

```python
from sulley import *

# Define the FTP protocol
s_initialize("USER")
s_static("USER ")
s_string("anonymous", fuzzable=True)
s_static("\r\n")

s_initialize("PASS")
s_static("PASS ")
s_string("user@example.com", fuzzable=True)
s_static("\r\n")

s_initialize("LIST")
s_static("LIST\r\n")

s_initialize("RETR")
s_static("RETR ")
s_string("file.txt", fuzzable=True)
s_static("\r\n")

# Create a session with target instrumentation
sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.100", 21, proto="tcp"),
    ),
    sleep_time=0.01,
)

# Define the fuzzing sequence: stateful, multi-message
sess.connect(s_get("USER"))
sess.recv(1024)  # Expect "220 FTP Server" and "331 User OK"

sess.fuzz(s_get("PASS"))  # Fuzz password field
sess.recv(1024)

sess.fuzz(s_get("LIST"))  # Fuzz LIST command
sess.recv(1024)

sess.fuzz(s_get("RETR"))  # Fuzz filename in RETR
sess.recv(1024)

sess.run()

# **MITRE ATT&CK Mapping:**
# T1046 — Network Service Scanning (identifying FTP services)
# T1589.002 — Gather Victim Network Information → Credentials (FTP auth testing)
# T1021.021 — Remote Services → FTP (exploiting protocol vulnerability)
```

**Key Points:**
- `s_initialize()` defines a named message template
- `s_static()` defines fixed (unfuzzed) text
- `s_string()` and other primitives with `fuzzable=True` are varied during fuzzing
- `sess.fuzz()` means "fuzz this message; all previous messages are sent unchanged"
- `sess.recv()` waits for target response (fails the test case if target crashes/closes)

**Detection Angle:** The target's IDS/WAF would see multiple malformed FTP commands; legitimate users send clean commands in this exact sequence only once. Repeated PASS/LIST/RETR fuzz variants are anomalous.

---

## 2. Binary Protocol Fuzzing with Checksums

**Scenario:** Fuzz a proprietary binary protocol with CRC32 checksums and a length prefix.

**File:** `fuzz_binary_with_checksum.py`

```python
from sulley import *

# Define a custom binary protocol:
# [Version:byte] [Type:byte] [Reserved:byte] [Length:u16-LE] [Payload] [CRC32]

s_initialize("custom_msg")
s_byte(0x01)                              # Protocol version
s_byte(0x42, fuzzable=True)               # Message type (fuzzable)
s_byte(0x00)                              # Reserved
s_size("payload", endian="<", length=2)  # Payload length (auto-updated by Sulley)

s_push("payload")
s_string("A" * 100, fuzzable=True)        # Variable-length payload
s_pop()

s_checksum("crc", algorithm="crc32", fuzzable=False)  # CRC covers everything before this

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.100.50", 9999, proto="tcp"),
    ),
    sleep_time=0.001,
)

sess.connect(s_get("custom_msg"))
sess.fuzz(s_get("custom_msg"))
sess.recv(4)  # Expect 4-byte ACK

sess.run()

# **MITRE ATT&CK Mapping:**
# T1046 — Network Service Scanning (service reconnaissance)
# T1589.001 — Gather Victim Network Information → Infrastructure Details
# T1204 — User Execution (triggering protocol parsing, potential RCE)
```

**Key Points:**
- `s_size()` and `s_checksum()` are **structural** fields — Sulley updates them automatically
- `s_push()/s_pop()` define the scope of a `Size()` or `Checksum()`
- Even though the payload is fuzzed, the length and CRC stay valid — prevents false crashes
- This technique catches bugs in **semantic validation**, not just structure validation

**Detection Angle:** Target logs malformed payloads and checksum failures. Volume of failures in a short time = fuzzing.

---

## 3. Parallel Fuzzing with Multiple Workers

**Scenario:** Speed up fuzzing by running 4 parallel fuzz workers against the same target.

**File:** `fuzz_parallel.py`

```python
from sulley import *
import sys

# Command-line: python3 fuzz_parallel.py 0  # worker 0 out of 4
worker_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0

s_initialize("HTTP_GET")
s_static("GET /")
s_string("index.html", fuzzable=True)
s_static(" HTTP/1.1\r\nHost: ")
s_string("example.com", fuzzable=True)
s_static("\r\n\r\n")

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.200", 80, proto="tcp"),
    ),
    sleep_time=0.05,
    log_dir="./fuzz_results",
    crash_filename="http_crash",
)

# Partition the fuzz space by worker ID
# Each worker fuzzes a different range of variants
sess.fuzz(s_get("HTTP_GET"), start_index=worker_id * 10000, stop_index=(worker_id + 1) * 10000)

sess.run()

# **MITRE ATT&CK Mapping:**
# T1046 — Network Service Scanning
# T1039 — Data from Network Shared Drive (HTTP GET paths)
# T1587.004 — Develop Capabilities → Exploit (discovering HTTP parsing vulns)
```

**Key Points:**
- Workers partition the fuzz space (`start_index`, `stop_index`)
- Each worker maintains its own session/connection
- Crashes are deduplicated and logged centrally (same log directory)
- On a multi-core system, this effectively multiplies fuzzing speed

**Detection Angle:** 4 simultaneous connections with distinct HTTP paths, each with malformed syntax, repeated in parallel.

---

## 4. Crash Reproduction

**Scenario:** A crash was found; reproduce it with the minimal test case.

**File:** `reproduce_crash.py`

```python
from sulley import *

# From the fuzz log, we know test case #4521 crashed with:
# "GET /../../etc/passwd HTTP/1.1"
# We reproduce this specific variant:

s_initialize("HTTP_GET")
s_static("GET /")
s_dword(0xffffffff, fuzzable=True)  # Exact byte sequence that crashed
s_static(" HTTP/1.1\r\n\r\n")

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.200", 80, proto="tcp"),
    ),
)

# Skip all non-crashing test cases, jump directly to #4521
sess.fuzz(s_get("HTTP_GET"), start_index=4521, stop_index=4522)

sess.run()

# **MITRE ATT&CK Mapping:**
# T1587.004 — Develop Capabilities → Exploit
# T1203 — Exploitation for Client Execution (triggering the target crash)
```

**Key Points:**
- `start_index` / `stop_index` allow jumping to a specific test case
- Useful for analyzing crashes in a debugger attached to the target
- Minimal, reproducible test case can be extracted and manually crafted (PoC)

**Detection Angle:** A single, repeated malformed request from the fuzzer's source IP — looks like debugging/exploitation research.

---

## 5. Embedded/Firmware Fuzzing via Serial

**Scenario:** Fuzz a device's UART bootloader interface.

**File:** `fuzz_bootloader_serial.py`

```python
from sulley import *

# Bootloader protocol: [0x55 sync] [command:byte] [data_len:byte] [data] [checksum:byte]
s_initialize("bootloader_cmd")
s_static("\x55")                    # Sync byte
s_byte(0x01, fuzzable=True)         # Command (e.g., 0x01=read, 0x02=write)
s_size("data", length=1)            # Data length
s_push("data")
s_bytes(b"\x00" * 32, fuzzable=True)  # Up to 32 bytes of fuzzable payload
s_pop()
s_checksum("chk", algorithm="sum", fuzzable=False)

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SerialConnection(
            port="/dev/ttyUSB0",
            baudrate=115200,
        ),
    ),
    sleep_time=0.1,  # Bootloader is slow
)

sess.connect(s_get("bootloader_cmd"))
sess.recv(2)  # Bootloader ACK

sess.fuzz(s_get("bootloader_cmd"))
sess.recv(2)

sess.run()

# **MITRE ATT&CK Mapping:**
# T1542.001 — Pre-OS Boot → System Firmware (bootloader fuzzing)
# T1586 — Compromise Accounts (firmware access, potential persistence)
```

**Key Points:**
- `SerialConnection` instead of `SocketConnection`
- Useful for physical penetration testing of embedded devices
- No network; debug via physical access to the device's UART pins

**Detection Angle:** Malformed commands on the serial port; legitimate bootloaders accept specific command sequences only once.

---

## 6. Custom Failure Callback

**Scenario:** Catch not just crashes, but also application-specific failures (e.g., logging errors).

**File:** `fuzz_with_callback.py`

```python
from sulley import *
import subprocess

def check_target_logs(target, fuzz_data):
    """Custom callback to detect failures via application logs."""
    # Read the target's log file
    try:
        with open("/var/log/myapp.log", "r") as f:
            log_tail = f.readlines()[-10:]  # Last 10 lines
            for line in log_tail:
                if "ERROR" in line or "SEGFAULT" in line or "PANIC" in line:
                    print(f"[CRASH DETECTED] {line}")
                    return True  # Failure detected
    except:
        pass
    return False  # No failure

s_initialize("custom_protocol")
s_static("CMD ")
s_string("list", fuzzable=True)
s_static("\n")

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.50", 5000, proto="tcp"),
    ),
    sleep_time=0.01,
)

# Register the custom callback
sess.register_logger(check_target_logs)

sess.connect(s_get("custom_protocol"))
sess.fuzz(s_get("custom_protocol"))

sess.run()

# **MITRE ATT&CK Mapping:**
# T1587.004 — Develop Capabilities → Exploit
# T1203 — Exploitation for Client Execution
```

**Key Points:**
- Custom Python callbacks can detect **any** failure condition, not just crashes
- Useful if the target doesn't crash but logs errors
- Callbacks are called after each fuzz test case

**Detection Angle:** Rapid log growth; unusual error patterns in application logs.

---

## 7. Unattended Long-Running Campaign

**Scenario:** Run Sulley for 8 hours unattended, fuzzing a complex protocol, with automatic target reboot on crash.

**File:** `fuzz_long_running.py`

```python
from sulley import *
import time

def restart_target():
    """Restart the target host after a crash."""
    import subprocess
    subprocess.call(["ssh", "root@192.168.1.100", "shutdown -r now"])
    time.sleep(30)  # Wait for reboot

s_initialize("complex_msg")
# ... complex multi-stage protocol definition ...

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.100", 1234, proto="tcp"),
    ),
    log_dir="./long_fuzz_results",
    sleep_time=0.005,
    restart_sleep_time=30,
)

# Register process monitor for automatic target health checks
from sulley.process_monitor import ProcessMonitor
pmgr = ProcessMonitor(host="192.168.1.100", username="root")
# ... configure process to monitor ...

sess.fuzz(s_get("complex_msg"), num_gen=1000000)  # 1M test cases

sess.run()

# **MITRE ATT&CK Mapping:**
# T1587.004 — Develop Capabilities → Exploit
# T1204 — User Execution (triggering crashes through protocol)
```

**Key Points:**
- `num_gen=1000000` limits total test cases (otherwise infinite)
- Process monitor can optionally trigger `restart_target()` callback
- Logs accumulate in a central directory
- Fuzzer continues from where it left off if restarted (warm start)

**Detection Angle:** Sustained, low-rate malformed traffic for hours; crashes followed by reboots; log spam.

---

## 8. Integration with GDB/Debugger

**Scenario:** Attach GDB to the target and let Sulley pause and collect crash details on each crash.

**File:** `fuzz_with_gdb.py`

```python
from sulley import *
from sulley.process_monitor_unix import ProcessMonitor

s_initialize("debug_msg")
s_byte(0x41, fuzzable=True)
s_bytes(b"\x00" * 128, fuzzable=True)

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("127.0.0.1", 5555, proto="tcp"),
    ),
    log_dir="./gdb_fuzz",
)

# Attach a Unix process monitor (uses GDB internally)
pmgr = ProcessMonitor(
    host="127.0.0.1",
    username="ubuntu",
    password="password",
    process_name="vulnerable_app",
    log_level=ProcessMonitor.LOGS_ALL,
)
sess.attach_crash_logger(pmgr)

sess.fuzz(s_get("debug_msg"))
sess.run()

# **MITRE ATT&CK Mapping:**
# T1587.004 — Develop Capabilities → Exploit
# T1203 — Exploitation for Client Execution
```

**Key Points:**
- `ProcessMonitor` spawns GDB and collects crash info (register state, stack trace)
- Detailed crash data is logged for manual analysis
- Requires remote access (SSH) or local debugging privileges

**Detection Angle:** GDB process spawning on the target; crash dumps in system logs; potential debugger network traffic.

---

## 9. Export Crash Test Cases for Exploit Development

**Scenario:** Sulley found a crash; export the exact byte sequence for use in a standalone exploit.

**File:** `extract_crash.py`

```python
#!/usr/bin/env python3
# Post-processing script run after Sulley's fuzzing campaign

import os
import sys

log_dir = "./fuzz_results"

# Parse Sulley's crash log
for crash_file in os.listdir(log_dir):
    if crash_file.startswith("crash"):
        print(f"[+] Found crash: {crash_file}")
        crash_path = os.path.join(log_dir, crash_file)
        
        with open(crash_path, "rb") as f:
            crash_bytes = f.read()
        
        # Export as Python bytes literal
        print(f"Crash bytes ({len(crash_bytes)} bytes):")
        print(f"crash_payload = {repr(crash_bytes)}")
        
        # Export as hex for manual reconstruction
        print(f"Hex dump:")
        print(crash_bytes.hex())

# **MITRE ATT&CK Mapping:**
# T1587.004 — Develop Capabilities → Exploit
# T1203 — Exploitation for Client Execution (exploit testing)
```

**Detection Angle:** Developers/analysts examining crash logs; potential exploitation attempt if the crash PoC is weaponized.

---

## 10. Multi-Protocol Fuzzing (Sequential Protocols)

**Scenario:** Fuzz a server that requires successful login before accepting other commands (state-dependent protocol).

**File:** `fuzz_auth_required.py`

```python
from sulley import *

# LOGIN request (must succeed or rest of protocol is blocked)
s_initialize("LOGIN")
s_static("LOGIN ")
s_string("admin", fuzzable=False)  # Valid username
s_static(" ")
s_string("password123", fuzzable=False)  # Valid password
s_static("\n")

# EXECUTE request (only valid after successful LOGIN)
s_initialize("EXECUTE")
s_static("EXEC ")
s_string("id", fuzzable=True)  # Fuzz the command parameter
s_static("\n")

# UPLOAD request
s_initialize("UPLOAD")
s_static("PUT ")
s_string("file.bin", fuzzable=True)
s_static("\n")
s_bytes(b"\x00" * 256, fuzzable=True)  # File content
s_static("\n")

sess = sessions.Session(
    target=sessions.target.Target(
        connection=sessions.target.connection.SocketConnection("192.168.1.75", 2222, proto="tcp"),
    ),
    sleep_time=0.01,
)

# Sequence: LOGIN (once), then fuzz EXECUTE and UPLOAD
sess.connect(s_get("LOGIN"))
sess.recv(128)  # "OK" response

# Fuzz multiple commands in sequence after successful auth
sess.fuzz(s_get("EXECUTE"))
sess.recv(128)

# Reset connection, re-authenticate, fuzz next command
sess.reset()
sess.connect(s_get("LOGIN"))
sess.recv(128)

sess.fuzz(s_get("UPLOAD"))
sess.recv(128)

sess.run()

# **MITRE ATT&CK Mapping:**
# T1021.021 — Remote Services → SSH (protocol fuzzing post-auth)
# T1204 — User Execution (malicious protocol parsing)
```

**Key Points:**
- `sess.reset()` closes and reopens the connection
- Allows testing of post-authentication protocol phases
- Each command can be fuzzed independently within its own state

**Detection Angle:** Multiple login attempts followed by varied malformed commands; or a single login then many exploit attempts.

---

## Summary: Attack Pattern Detection

All Sulley usage follows a consistent fingerprint:

1. **Source behavior:** Repetitive, malformed protocol messages from a single source IP
2. **Target behavior:** Protocol violations (invalid checksums, out-of-order commands, buffer overflows)
3. **Timeline:** Hundreds of requests in minutes → hours (not normal user traffic)
4. **Payload variation:** Same message structure with different field values, systematically
5. **Crash correlation:** Crashes cluster around certain payload values (exploitable bugs)

MITRE ATT&CK mappings:
- **T1046** — Network Service Scanning (identifying services to fuzz)
- **T1587.004** — Develop Capabilities → Exploit (fuzzing for vulns)
- **T1203** — Exploitation for Client Execution (triggering crashes)
- **T1021.021** — Remote Services → SSH (fuzzing authenticated services)
- **T1542.001** — Pre-OS Boot (firmware/bootloader fuzzing)
