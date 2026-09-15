# Sulley — Source Evidence

What remains on the operator's host after running a Sulley fuzzing campaign.

## 1. Fuzzing Script

**File:** `fuzz_target_*.py` (named by convention, any name allowed)

- **Location:** Operator's working directory (anywhere Python can run it)
- **Artifact Type:** Python source code
- **Forensic Value:** HIGH — the script explicitly defines the target (host, port), protocol structure (blocks/primitives), and fuzzing strategy
- **Preservation:** Rarely deleted; operators keep fuzz scripts for reproducibility
- **Example Content:**
  ```python
  from sulley import *
  s_initialize("HTTP_GET")
  s_static("GET /")
  s_string("index.html", fuzzable=True)
  sess = sessions.Session(
      target=sessions.target.Target(
          connection=sessions.target.connection.SocketConnection("192.168.1.200", 80, proto="tcp"),
      ),
  )
  sess.fuzz(s_get("HTTP_GET"))
  sess.run()
  ```
- **Detection Signal:** Presence of `from sulley import *` and `sessions.Session()` calls on disk = Sulley fuzzing script

## 2. Fuzzing Logs and Results Directory

**Directory:** `./fuzz_results/` (or `log_dir=` parameter from the script)

**Subdirectories:**

### `index.html`
- Text file listing all test cases and their status (PASS, FAIL, CRASH, SKIP)
- Format: tab-separated, human-readable
- **Example:**
  ```
  Test Case #0000: PASS
  Test Case #0001: PASS
  Test Case #0042: CRASH (Exception 0xc0000374)
  Test Case #0043: PASS
  ```

### `crash/` or crash-named files
- **Files:** `crash-0042`, `crash-0043`, etc. (one per unique crash signature)
- **Content:** Raw binary data — exact bytes sent to the target when crash occurred
- **Forensic Value:** EXTREMELY HIGH — each crash file is a weaponizable PoC

### `logs/` subdirectory
- Detailed logs for each test case, including:
  - Exact bytes sent and received
  - Timing information
  - Target response
  - Failure reason (if applicable)
- **Format:** Text, human-readable

### `process_monitor.log` (if ProcessMonitor attached)
- Debugger/crash data:
  - Exception type and address
  - Register state (EIP/RIP)
  - Thread ID
  - Stack trace (if GDB attached)
- **Forensic Value:** HIGH — direct link between fuzzing activity and target crashes

### `.dbg` files (Windows Process Monitor)
- Compiled debug data from WinDbg
- **Forensic Value:** MEDIUM — requires specialized tools to parse

## 3. Python Process Memory

**Detection Vector:** Active Sulley process

- **Process Name:** `python` or `python3`
- **Command Line:** `python3 fuzz_target_http.py`
- **Memory Contents:**
  - Fuzz state machine (all request definitions in memory)
  - Open socket connections (established, one per target connection)
  - Target response data (buffered in memory)
  - Test case counter and current variant parameters
- **Tool:** Volatility, WinDbg, GDB can dump and analyze
- **Live Detection:** `ps aux | grep sulley` or monitor for Python processes with high network activity

## 4. Network Connections (Live Process)

**Detection Vector:** Network socket state on the operator's system

- **Established Connections:** TCP connections to target host(s)
- **Details:** Can be enumerated via:
  - Linux: `netstat -anp`, `ss -anp` (PID associated with fuzzer process)
  - Windows: `netstat -ano` (PID), Task Manager, or `Get-NetTCPConnection` (PowerShell)
- **Pattern:** Single source IP → single target IP/port, repeated connection/disconnect cycles
- **Example (Linux):**
  ```
  Proto Local Address         Foreign Address         State       PID
  tcp   192.168.1.50:54321    192.168.1.200:80        ESTABLISHED 12345
  tcp   192.168.1.50:54322    192.168.1.200:80        TIME_WAIT   12345
  tcp   192.168.1.50:54323    192.168.1.200:80        ESTABLISHED 12345
  ```
- **Temporal Signature:** Many connections in quick succession (sub-second intervals)
- **Artifacts:**
  - `/proc/[PID]/fd/` (Linux) — open file descriptors, sockets visible here
  - Process handle table (Windows) — visible with Process Explorer

## 5. Shell History

**Files:**
- Linux: `~/.bash_history`, `~/.zsh_history`
- Windows PowerShell: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Evidence:**
```bash
$ history
...
1024  python3 fuzz_target_http.py
1025  python3 fuzz_target_http.py
1026  # Script crashed, restarting...
1027  python3 fuzz_target_http.py
1028  tail -f fuzz_results/index.html
1029  ls -la fuzz_results/crash*
1030  hexdump -C fuzz_results/crash-0042 | head -20
```

**Forensic Value:** MEDIUM — confirms fuzzing activity, reveals operator intent and debugging workflow

## 6. Disk Space and I/O Patterns

**Forensic Vector:** File system activity

- **Disk I/O rate:** High (logs written per test case, often 1000s/sec)
- **File growth:** Fuzz results directory grows rapidly (100s of MB over hours)
- **Disk space used:** Typical campaign:
  - 100,000 test cases × ~200 bytes/log entry = ~20 MB logs
  - Crash files (~1-10 KB each) × ~10-100 crashes = ~100-1000 KB
  - Total: ~20-50 MB per campaign, depending on protocol complexity
- **Detection:** Sudden spike in disk writes from a single process; large unexplained log directory

**Tool:** `iotop` (Linux), Resource Monitor (Windows) can show per-process I/O

## 7. Installed Sulley Module

**Location:** Python site-packages

- **Path:** `/usr/local/lib/python3.x/dist-packages/sulley/` (Linux) or `C:\Python3x\Lib\site-packages\sulley\` (Windows)
- **Artifact:** Directory listing shows when Sulley was installed (file timestamps)
- **Detection:** Presence of Sulley library = operator had access to fuzzing framework

**Command to check:**
```bash
python3 -c "import sulley; print(sulley.__file__)"
```

## 8. System Binaries Invoked by Sulley

**If ProcessMonitor is used (Windows):**
- **WinDbg.exe** — debugger binary runs as a subprocess of the Python fuzzer
- **Crash dumps** — Written to `C:\Users\[User]\AppData\Local` (configurable)
- **registry values modified** (if debugger attaches) — HKLM\Software\Microsoft\Windows\AeDebug

**If Network Monitor is used:**
- **TCPDump / Wireshark** — pcap capture may be started as subprocess
- **Temporary pcap files** — in /tmp or %TEMP%

**Detection:** Child process tree of Python shows WinDbg or packet sniffer children

## 9. Environmental Artifacts

**Python imports loaded:**
- Sulley's pedrpc module (RPC server for remote monitoring)
- Socket libraries, subprocess libraries, etc.

**Open file descriptors (on operator machine):**
- Fuzz script itself (if interpreted, keeping .py file open)
- Log files being written
- Socket connections (open, TIME_WAIT, CLOSE_WAIT)

## 10. Temporal Artifacts: Timeline Correlation

**Typical workflow timeline:**

| Time | Event | Artifact |
|------|-------|----------|
| T+0 | Operator runs fuzz script | Shell history entry, process spawn |
| T+0.1 | Sulley initializes, connects to target | Network connection established |
| T+0.5 | First fuzz test case sent | Fuzz results log entry #0 |
| T+1 | Hundreds of test cases, writes accumulated | Fuzz results dir grows, disk I/O spike |
| T+3600 (1 hour later) | Crash detected (test case #42) | Crash file created, process monitor log updated |
| T+3601 | Operator checks results | New shell command: `ls -la fuzz_results/crash*` |
| T+3620 | Script finishes or killed | Process exits, network connections close |
| T+3621 | Operator archives results | `tar czf fuzz_campaign_backup.tar.gz fuzz_results/` in shell history |

---

## Detection Strategy: Source-Side

**High-Confidence Indicators (in priority order):**

1. **Fuzz results directory structure** — if `fuzz_results/index.html` + `crash/` subdirs found on disk, **this is definitively a fuzzing campaign**
2. **Sulley Python scripts** — grep for `sessions.Session()` + `s_initialize()` = fuzzing script
3. **Crash files** — presence of structured, binary-identical test case payloads in a results directory
4. **Process monitor logs** — WinDbg-format crash dumps linked to fuzzing
5. **Network socket pattern** — sustained, rapid connection/reconnection to a single target:port

**Lower-Confidence Indicators:**

- Shell history mentioning fuzzing or target IP
- Installed Sulley library (presence, not deployment)
- Python processes with high network I/O

---

## Evasion Opportunities (and Counter-Measures)

**Operator can hide:**
- Fuzz script in obfuscated/encrypted Python
- Fuzz results directory path (`log_dir=/dev/shm/hidden` — RAM disk, no disk trace after reboot)
- ProcessMonitor subprocess (silence stderr/stdout, run in background)

**Counter-measure:**
- Monitor for Python processes with network connections to unusual targets
- Look for crash signatures in target-side logs (if Sulley succeeds in crashing something, the target will record it)
- Memory forensics: dump running Python processes and search for Sulley module strings

---

## Reference: Log File Formats

### index.html (Fuzz Results Summary)
```
Fuzz Results Summary
====================

Total Test Cases: 50000
Passed:           49988
Failed:           10
Crashed:          2

Unique Crashes:   2

Test Case #00000: PASS
Test Case #00001: PASS
...
Test Case #00042: CRASH (Exception 0xc0000374 at 0x401000)
...
```

### Crash File (Binary)
Raw bytes, exactly as sent to target. No metadata wrapper. Example:
```
$ xxd fuzz_results/crash-0042 | head -5
00000000: 4745 5420 2f2e 2e2f 2e2e 2f65 7463 2f70  GET /../../etc/p
00000010: 6173 7377 6420 4854 5450 2f31 2e31 0d0a  asswd HTTP/1.1..
```

---

## Summary

**Operator-side artifacts are forensically rich:** Sulley campaigns leave extensive logs, crash data, and script files that precisely document what was fuzzed and what was found. The most incriminating artifacts are:

1. Fuzz results directory (proves fuzzing occurred)
2. Crash files (weaponizable PoCs)
3. Fuzz script (reveals target and strategy)
4. Timeline correlation (script execution → target crash → operator analysis)

**Assume these will be found if the operator's machine is imaged; Sulley does not provide built-in sanitization.**
