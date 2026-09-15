# boofuzz — Hands-On Use Cases

All examples use the boofuzz library (installed via `pip install boofuzz`). API is nearly identical to Sulley, with improvements in logging and connection types.

---

## 1. Simple FTP Fuzzing with CSV Export

**File:** `fuzz_ftp.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string

# Define FTP protocol
s_initialize("FTP_USER")
s_static("USER ")
s_string("admin", fuzzable=True)
s_static("\r\n")

s_initialize("FTP_PASS")
s_static("PASS ")
s_string("password", fuzzable=True)
s_static("\r\n")

s_initialize("FTP_LIST")
s_static("LIST\r\n")

# Create session with result export to CSV
session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.100", 21, proto="tcp"),
    ),
    log_dir="./ftp_fuzz_results",
    sleep_time=0.01,
)

# Connect, send valid AUTH, then fuzz LIST
session.connect(s_get("FTP_USER"))
session.recv(1024)

session.connect(s_get("FTP_PASS"))
session.recv(1024)

session.fuzz(s_get("FTP_LIST"))
session.recv(1024)

session.run()

# **MITRE ATT&CK:**
# T1046 — Network Service Scanning
# T1589.002 — Gather Victim Network Information → Credentials
# T1021.021 — Remote Services → FTP
```

**Result:** `ftp_fuzz_results/` contains `fuzz_results.csv` (spreadsheet-importable) + SQLite DB

---

## 2. HTTP Fuzzing with Real-Time Curses UI (Linux)

**File:** `fuzz_http_live.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string, s_dword
from boofuzz.fuzz_logger_curses import FuzzLoggerCurses

# Define HTTP GET request
s_initialize("HTTP_GET")
s_static("GET /")
s_string("index.html", fuzzable=True)
s_static(" HTTP/1.1\r\nHost: ")
s_string("example.com", fuzzable=True)
s_static("\r\nUser-Agent: ")
s_string("Mozilla/5.0", fuzzable=True)
s_static("\r\n\r\n")

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.200", 80, proto="tcp"),
    ),
    log_dir="./http_results",
)

# Add live curses-based UI (Linux/Mac only)
session.add_logger(FuzzLoggerCurses())

session.fuzz(s_get("HTTP_GET"), num_gen=10000)
session.run()

# **MITRE ATT&CK:**
# T1046 — Network Service Scanning
# T1587.004 — Develop Capabilities → Exploit
```

**Output:** Real-time progress bar showing test cases/sec, crash count, current variant

---

## 3. SSL/TLS Protocol Fuzzing (boofuzz-specific)

**File:** `fuzz_tls_server.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_bytes

# TLS Record Layer fuzzing (simplified)
s_initialize("TLS_RECORD")
s_byte(0x16)  # TLS Content Type: Handshake
s_word(0x0303)  # TLS Version 1.2
s_word(200, fuzzable=True)  # Length field (fuzzed)
s_bytes(b"\x00" * 200, fuzzable=True)  # Record payload

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.175", 443, proto="ssl", sslname=None),
        # Connection type: "ssl" for encrypted fuzzing
    ),
    log_dir="./tls_fuzz_results",
)

session.fuzz(s_get("TLS_RECORD"))
session.run()

# **MITRE ATT&CK:**
# T1046 — Network Service Scanning
# T1587.004 — Develop Capabilities → Exploit
# T1001 — Data Obfuscation (testing encrypted protocols)
```

**Key:** boofuzz's `SocketConnection(..., proto="ssl")` handles SSL/TLS wrapping automatically

---

## 4. Stateful Multi-Message Protocol

**File:** `fuzz_auth_required.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string

# Protocol: LOGIN req → EXEC cmd req → LOGOUT
s_initialize("LOGIN")
s_static("LOGIN ")
s_string("admin", fuzzable=False)
s_static(" ")
s_string("correct_password", fuzzable=False)
s_static("\n")

s_initialize("EXEC")
s_static("EXEC ")
s_string("ls -la", fuzzable=True)  # Fuzz the command parameter
s_static("\n")

s_initialize("LOGOUT")
s_static("QUIT\n")

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.75", 2222, proto="tcp"),
    ),
    log_dir="./auth_fuzz_results",
)

# Sequence: LOGIN (once), fuzz EXEC, reset, repeat
for i in range(100):  # 100 fuzz iterations
    session.reset()
    session.connect(s_get("LOGIN"))
    session.recv(64)  # "OK" response
    
    session.fuzz(s_get("EXEC"))
    session.recv(1024)
    
    session.disconnect()

session.run()

# **MITRE ATT&CK:**
# T1021.021 — Remote Services → SSH (post-auth fuzzing)
# T1204 — User Execution (command execution)
```

---

## 5. Callback-Based Failure Detection (Custom Monitoring)

**File:** `fuzz_with_callback.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string

def check_response_validity(target, fuzz_data):
    """Custom callback: check if response contains error keyword."""
    try:
        response = target.recv(1024)
        if b"ERROR" in response or b"FAIL" in response or b"CRASH" in response:
            print("[!] Failure detected in response")
            return False  # Indicate failure
        return True  # Success
    except Exception as e:
        return False

s_initialize("COMMAND")
s_static("CMD ")
s_string("status", fuzzable=True)
s_static("\n")

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.50", 5000, proto="tcp"),
    ),
    log_dir="./callback_results",
)

# Register custom callback monitor
from boofuzz import CallbackMonitor
session.add_callback_monitor(check_response_validity)

session.fuzz(s_get("COMMAND"))
session.run()

# **MITRE ATT&CK:**
# T1587.004 — Develop Capabilities → Exploit
```

---

## 6. Parallel Fuzzing with Multiple Workers

**File:** `fuzz_parallel.py`

```python
#!/usr/bin/env python3
import sys
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string

worker_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0
total_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 4

s_initialize("HTTP_GET")
s_static("GET /")
s_string("index.html", fuzzable=True)
s_static(" HTTP/1.1\r\n\r\n")

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.200", 80, proto="tcp"),
    ),
    log_dir=f"./fuzz_results_worker{worker_id}",
)

# Partition fuzz space
start_index = worker_id * 10000
stop_index = (worker_id + 1) * 10000

session.fuzz(s_get("HTTP_GET"), start_index=start_index, stop_index=stop_index)
session.run()

# Usage:
# python3 fuzz_parallel.py 0 4  # Worker 0 of 4
# python3 fuzz_parallel.py 1 4  # Worker 1 of 4
# ... etc, run all 4 in parallel
```

---

## 7. DNS Protocol Fuzzing (Pre-Built Request)

**File:** `fuzz_dns.py` (using boofuzz's built-in DNS template)

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz.request_definitions import dns

# boofuzz includes pre-built DNS protocol definition
# Use it instead of defining from scratch
session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.1", 53, proto="udp"),
    ),
    log_dir="./dns_fuzz_results",
)

# Fuzz the DNS response message
session.fuzz(dns.get("dns_response"))
session.run()

# **MITRE ATT&CK:**
# T1590.002 — Gather Victim Network Information → DNS (DNS enum → fuzzing)
# T1046 — Network Service Scanning
```

**Benefit:** boofuzz includes `request_definitions/` with common protocols pre-defined (FTP, HTTP, DNS, NTP, TFTP, etc.)

---

## 8. Serial/Embedded Device Fuzzing

**File:** `fuzz_bootloader_serial.py`

```python
from boofuzz import Session, SerialConnection, Target
from boofuzz import s_initialize, s_static, s_byte, s_bytes, s_size, s_checksum

# Bootloader protocol: [sync] [cmd] [len] [data...] [CRC]
s_initialize("bootloader")
s_static(b"\x55")  # Sync byte
s_byte(0x02, fuzzable=True)  # Command (fuzzable)
s_size("payload", length=1)
s_push("payload")
s_bytes(b"\x00" * 64, fuzzable=True)
s_pop()
s_checksum("crc", algorithm="crc32", fuzzable=False)

session = Session(
    target=Target(
        connection=SerialConnection(
            port="/dev/ttyUSB0",  # or "COM3" on Windows
            baudrate=115200,
        ),
    ),
    log_dir="./bootloader_fuzz_results",
)

session.connect(s_get("bootloader"))
session.recv(2)  # Bootloader ACK

session.fuzz(s_get("bootloader"))
session.recv(2)

session.run()

# **MITRE ATT&CK:**
# T1542.001 — Pre-OS Boot → Firmware
# T1586 — Compromise Accounts (firmware access)
```

---

## 9. Process Monitor Integration (Windows)

**File:** `fuzz_with_procmon.py`

```python
from boofuzz import Session, SocketConnection, Target
from boofuzz import s_initialize, s_static, s_string
from boofuzz.process_monitor import ProcessMonitor

s_initialize("CMD")
s_static("EXEC ")
s_string("whoami", fuzzable=True)
s_static("\n")

session = Session(
    target=Target(
        connection=SocketConnection("192.168.1.100", 3333, proto="tcp"),
    ),
    log_dir="./procmon_fuzz_results",
)

# Attach Windows Process Monitor (requires WinDbg/admin rights)
proc_mon = ProcessMonitor(
    host="192.168.1.100",
    username="Administrator",
    password="password",
    process_name="myservice.exe",
    log_level=ProcessMonitor.LOGS_ALL,
)
session.attach_crash_logger(proc_mon)

session.fuzz(s_get("CMD"))
session.run()

# **MITRE ATT&CK:**
# T1587.004 — Develop Capabilities → Exploit
```

---

## 10. Crash Extraction and PoC Generation

**File:** `extract_crashes.py`

```python
#!/usr/bin/env python3
import sqlite3
import os

# Query boofuzz's SQLite database for crashes
db_path = "./fuzz_results/boofuzz.db"

if os.path.exists(db_path):
    db = sqlite3.connect(db_path)
    cursor = db.cursor()
    
    # Find all crashes
    cursor.execute("""
        SELECT test_case_num, test_case_data FROM test_case 
        WHERE passed = 0 
        ORDER BY test_case_num
    """)
    
    crashes = cursor.fetchall()
    
    for test_num, payload in crashes:
        print(f"\n[+] Crash #{test_num}")
        print(f"Payload ({len(payload)} bytes):")
        print(f"  Python bytes: {repr(payload)}")
        print(f"  Hex: {payload.hex()}")
        
        # Export as raw binary file
        with open(f"crash_{test_num}.bin", "wb") as f:
            f.write(payload)
        print(f"  Saved to: crash_{test_num}.bin")
    
    db.close()
else:
    print(f"Database not found: {db_path}")

# **Output:** Crash PoC binary files, ready for manual testing/exploitation
```

---

## Summary: boofuzz Attack Signature

All boofuzz campaigns follow the same pattern as Sulley:

1. **Source:** Repeated, malformed protocol messages from single IP
2. **Target:** Crashes, restarts, protocol errors
3. **Timeline:** Hundreds of requests in minutes → hours
4. **Payload:** Systematic field variation

**MITRE ATT&CK:**
- T1046 — Network Service Scanning
- T1587.004 — Develop Capabilities → Exploit
- T1203 — Exploitation for Client Execution
- T1542.001 — Pre-OS Boot (firmware)
- T1001 — Data Obfuscation (encrypted protocol fuzzing)

**Distinguishing boofuzz from Sulley:** CSV result export + SQLite database (vs. Sulley's text-only logs) is a strong indicator of boofuzz use.
