# Sulley — Target Evidence

What appears on the target system when Sulley fuzzes it.

## 1. Application Crashes and Core Dumps

**Primary Indicator:** The target service crashes repeatedly, correlating with fuzzing activity.

### Windows: Exception Records
- **Event Log:** Security, Application, or System logs (Event ID varies by service)
- **Typical Entry:**
  ```
  Event ID: 1000 (Application Hang) or 1001 (Bucket ID, Crash)
  Source: Windows Error Reporting
  Description: "myapp.exe has stopped working"
  Fault address: 0x401234
  Exception code: 0xc0000374 (Heap corruption)
  Timestamp: Correlates with fuzzer's test case log
  ```

### Linux/Unix: Core Dumps
- **Location:** `/var/crash/` or current working directory (if coredumps enabled via `ulimit -c unlimited`)
- **Files:** `core`, `core.12345` (PID-suffixed)
- **Forensic Value:** VERY HIGH — can be analyzed with GDB to determine the crash condition
- **Example Analysis:**
  ```bash
  $ gdb ./myapp core.12345
  (gdb) where
  #0  0x00007ffff7a1234 in malloc () from /lib64/libc.so.6
  #1  0x0000000000401234 in process_request () at main.c:234
  #2  0x0000000000401500 in handle_connection () at main.c:450
  (gdb) print $rax
  $1 = 0xffffffffffffffff  # -1, likely a size overflow
  ```
- **Preservation:** Core dumps can be large (10s of MB); operators may attempt to delete them

### macOS: Crash Reports
- **Location:** `~/Library/Logs/DiagnosticMessages/` or `/Library/Logs/CrashReporter/`
- **Files:** `.crash` (text format with stack trace)
- **Example Content:**
  ```
  Process:               vulnerable_app [12345]
  Path:                  /Applications/vulnerable_app
  Identifier:            com.example.vulnerable
  Version:               1.0
  Exception Type:        EXC_BAD_ACCESS (SIGSEGV)
  Exception Codes:       KERN_INVALID_ADDRESS at 0x0000000041414141
  VM Regions Near 0x41414141:
  
  Thread 0 Crashed:
  0   vulnerable_app         0x000000010001234 in process_request + 1234 (main.c:234)
  ```

## 2. Service Restart Patterns

**Pattern:** Service crashes → restarts → crashes again, in a loop

- **Windows Event Log (System channel):**
  - **Event ID 7034:** Service crashed unexpectedly (repeated, within seconds/minutes of each other)
  - **Event ID 7035:** Service sent a control signal (restart)
  - **Timestamp Clustering:** 100+ crashes in 1 hour = fuzzing signature
  
- **Linux syslog:**
  ```
  Aug 11 14:23:45 target kernel: [12345.678901] myapp[12456]: segmentation fault at ip 401234 sp 7fff1234 error 4 in myapp[400000+2000]
  Aug 11 14:23:46 target systemd[1]: myapp.service: Main process exited, code=exited, status=139/SEGV
  Aug 11 14:23:47 target systemd[1]: myapp.service: Unit entered failed state.
  Aug 11 14:23:50 target systemd[1]: myapp.service: Service hold-off time over, scheduling restart.
  Aug 11 14:23:50 target systemd[1]: myapp.service: Attempting restart.
  Aug 11 14:23:50 target systemd[1]: Started My Application.
  Aug 11 14:23:51 target kernel: [12350.123456] myapp[12567]: segmentation fault at ip 401300 sp 7fff1230 error 4 in myapp[400000+2000]
  ```

- **Detection Signal:** Multiple crashes with **different fault addresses** in close temporal proximity = fuzzing (as opposed to a single bug that always crashes at the same address)

## 3. Network Traffic Anomalies

**Pattern:** Malformed protocol messages arriving in high volume

### Packet Analysis (tcpdump/Wireshark on target)
- **Source:** Single attacker IP
- **Destination:** Target service port
- **Message Characteristics:**
  - Structurally similar (same message format)
  - Field variations (same field position, different values in successive packets)
  - Protocol violations:
    - Invalid checksums (if protocol has CRC/MD5)
    - Out-of-order state (e.g., RETR command before LOGIN in FTP)
    - Truncated/oversized payloads
    - Invalid length fields (declared size doesn't match actual data)

### Example (FTP Fuzzing):
```
Frame 1: CLIENT -> SERVER
    FTP Request: USER anonymous
    Response: 331 User OK

Frame 2: CLIENT -> SERVER
    FTP Request: PASS user@example.com
    Response: 230 User logged in

Frame 3: CLIENT -> SERVER (FUZZED)
    FTP Request: LIST \x00\x00\x00\x00\x00
    Response: 500 Syntax error (or crash)

Frame 4: CLIENT -> SERVER (FUZZED)
    FTP Request: LIST \xff\xff\xff\xff
    Response: Connection reset / no response (crash)
```

### Detection via IDS/WAF
- **Snort/Suricata Rules:**
  - "Multiple failed commands from single source in short time"
  - Protocol state violations (FTP out-of-order commands)
  - Oversized or null-byte payloads in protocols where they're unexpected
- **WAF (Web Application Firewall):**
  - High rate of 400/500 responses from single IP
  - Repeated path fuzzing (GET /index.html, GET /..%00.. , GET /\x00\x01, etc.)

## 4. Application Logs

**Protocol-Specific Error Logging:**

If the target application logs its own protocol violations, Sulley's fuzz traffic will generate error entries.

### HTTP Server Example:
```
192.168.1.50 - - [11/Aug/2026 14:23:45 +0000] "GET /\x00\x01\x02 HTTP/1.1" 400 0
192.168.1.50 - - [11/Aug/2026 14:23:46 +0000] "GET /index.html\xff HTTP/1.1" 400 0
192.168.1.50 - - [11/Aug/2026 14:23:47 +0000] "GET / HTTP/1." 400 0
192.168.1.50 - - [11/Aug/2026 14:23:48 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 0
192.168.1.50 - - [11/Aug/2026 14:23:49 +0000] "" 400 0
```

### Custom Protocol Server Example:
```
[14:23:45] ERROR: Invalid checksum on RETR command
[14:23:46] ERROR: Out-of-sequence command (expected AUTH, got EXEC)
[14:23:47] ERROR: Buffer overflow in size field, truncating to 65535
[14:23:48] WARNING: Null bytes in filename parameter
[14:23:49] CRITICAL: Segmentation fault in handler_retr(), terminating
```

**Forensic Value:** VERY HIGH — directly documents what Sulley sent, and how the target reacted

## 5. Memory Dumps and Debugger Artifacts

**If target is running under a debugger:**

### Windows WinDbg Artifacts:
- **Process dump files:** `AppName.DMP` (user-space memory dump, 100s of MB)
  - Location: `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\` or custom location
  - Contains: Crash context, registers, stack trace
- **Crash dump data:** Extracted by Windows Error Reporting (WER) service
  - Accessible via "View Event Details" in Event Viewer

### Linux GDB Artifacts:
- **Core dump:** Contains full memory image of crashed process (often 100s of MB)
  - Analyzable with `gdb --core=core.12345 ./binary`
- **GDB session history:** If debugger was interactive, `.gdb_history` on the operator's machine (not target)

### Mac LLDB Artifacts:
- **Crash report file:** `.crash` file (text format, contains stack trace)
- **Extended details:** Fault address, exception type, thread state

**Detection:** Large dump files in standard locations; timestamps correlating with crash events

## 6. Prefetch and Execution Artifacts

### Windows Prefetch:
- **File:** `%SystemRoot%\Prefetch\MYAPP.EXE-<hash>.pf`
- **Content:** Run count, timestamps of execution, DLL dependencies loaded
- **Evidence:** Multiple prefetch hits (each time the crashed service restarts)
- **Example (WinPrefetchView output):**
  ```
  Filename: MYAPP.EXE
  Prefetch Hash: ABCD1234
  # of runs: 47 (indicates 47 process invocations)
  Creation Date: 2026-08-11 14:23:00
  Last Execution Date: 2026-08-11 14:40:00
  ```

### Linux Execution Artifacts:
- **Shell history on target:** (if fuzzer has shell access) — `~/.bash_history` may record service restart commands
- **Process accounting (psacct):** If enabled, logs every process execution with timing/PID/user
  - File: `/var/log/account/`
- **Audit logs (auditd):** If enabled with syscall rules, records every execve() call
  ```
  type=EXECVE msg=audit(1597091025.123:4567): argc=1 a0="/usr/bin/myapp"
  type=EXIT msg=audit(1597091025.124:4567): exit=139 success=no
  ```

## 7. System Resource Usage Spikes

**Detection Vector:** Monitor resource consumption during fuzzing

### Memory Usage:
- **Typical:** Application uses steady-state memory
- **During Fuzzing:** Memory may spike briefly on each crash, then reset (if monitoring/restart is involved)
- **Observability:** `top`, `/proc/[PID]/status`, Resource Monitor (Windows)

### CPU Usage:
- **Pattern:** If the target service is CPU-bound, CPU spike → crash → restart → CPU spike again
- **Timeline:** Repeated 100+ times per hour during fuzzing

### Disk I/O:
- **Core dumps:** Large I/O writes when core dumps are generated
- **Logs:** Sustained elevated write rate if target is logging all protocol violations

## 8. Firewall and Network Monitoring Logs

### IDS/Intrusion Detection System (Snort, Suricata):
- **Alert Logs:** "Protocol anomaly detected" or "Known fuzzer detected"
- **Example Alert:**
  ```
  [Classification: Protocol Command Decode] [Priority: 3]
  06/13-14:23:47.123456  [**] PROTOCOL-HTTP HTTP request with null bytes [**] [Classification: Protocol Command Decode] [Priority: 3] {TCP} 192.168.1.50:54321 -> 192.168.1.200:80
  ```

### WAF/Load Balancer Logs:
- **Rate limiting:** If WAF/LB detects high request rate from one IP, may log or block
- **Anomaly detection:** High rate of errors (4xx/5xx) responses
- **Example (Nginx):**
  ```
  192.168.1.50 - - [11/Aug/2026:14:23:45 +0000] "GET /\x00 HTTP/1.1" 400 0 "-" "-" 0.001
  192.168.1.50 - - [11/Aug/2026:14:23:46 +0000] "GET /\xff HTTP/1.1" 400 0 "-" "-" 0.001
  [alert] 12345#12345: *1 client 192.168.1.50 reached max_fails=5 failures=5, terminal status=400, total time=1s
  ```

## 9. Anti-Virus and Endpoint Detection Response (EDR)

### Windows Defender / Antimalware Service Executable:
- **Suspicious behavior detection:** Process crash loop (crash + restart repeating)
- **Memory anomalies:** Heap corruption detected
- **Logs:** Windows Defender event logs (Event ID 1000-1002 for real-time protection alerts)

### Third-Party EDR (CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne):
- **Process crash detection:** Automated alerts on repeated crashes
- **Timeline Event:** "Process [myapp.exe] terminated abnormally 47 times in the last hour"
- **Network Detection:** Sustained malformed traffic from single IP → alert generated
- **Behavioral Alert:** "Potential exploit development activity detected"

## 10. Timeline Correlation: Target-Side

| Time | Event | Artifact |
|------|-------|----------|
| T+0 | Sulley connects to target | TCP SYN in network logs, IDS alert on connection |
| T+0.5 | First valid request (baseline) | Protocol log entry (successful) |
| T+1 | Fuzz test case #1 (malformed) | 400/500 error in HTTP log, protocol error in app log |
| T+2 | Fuzz test case #2 (crash trigger) | Application crash, exception logged, core dump generated |
| T+2.1 | Monitoring script detects crash | Process restart logged in system event log |
| T+2.5 | Service restarts, Sulley reconnects | New TCP connection, service comes online |
| T+3 | Fuzz test case #3 | Another error/crash |
| ... | Repeated 100s of times | Sustained pattern of crashes, errors, restarts |
| T+3600 | Fuzzing stops | No more connections, error rate drops to zero |

**Forensic Reconstruction:** Operator can walk a timeline analyst through exactly what each fuzz variant was testing, by correlating test-case number with target timestamps.

---

## Evasion Opportunities

**Limited on Target:** Unlike the source (operator's machine), the target cannot easily hide Sulley activity:

- **Crash cannot be hidden** — the service either crashed or didn't (EDR, logs, and process monitoring will detect)
- **Error logs are automatic** — applications log protocol violations by design
- **Core dumps are kernel-level** — no user-mode code can prevent them (on Unix)

**Possible mitigations (by target admin):**

- Disable crash logging (makes post-incident analysis harder, but does hide evidence)
- Disable core dumps (prevents detailed crash analysis, but crash still logged in syslog)
- Disable EDR/antimalware (not practical for critical services)
- Disable protocol error logging (possible but suspicious, degrades security posture)

**Counter-measure:** If Sulley crashes a target and the operator doesn't find logs, **check the target for evidence of logging being disabled** — a form of anti-forensics in itself.

---

## Summary: Target-Side Detection

**Highest-confidence indicators (in order):**

1. **Crash + restart + crash cycle** with different fault addresses and timestamps correlating to network activity
2. **Protocol error logs** showing systematically varied payloads (same structure, different fields)
3. **Core dumps** with multiple fault addresses (not one reproducible bug, but many)
4. **Network packet analysis** showing malformed messages with field-level variation
5. **IDS alerts** for protocol anomalies from single source IP
6. **EDR timeline** showing process crashes, restarts, and malformed network activity

**False-positive risk:** LOW — this pattern is specific to protocol fuzzing and unlikely to occur from normal operations.
