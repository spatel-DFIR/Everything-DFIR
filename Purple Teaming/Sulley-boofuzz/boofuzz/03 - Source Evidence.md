# boofuzz — Source Evidence

Artifacts left on the operator's machine after running a boofuzz fuzzing campaign. Nearly identical to Sulley, with key difference: boofuzz results use **SQLite database** instead of text-only logs.

## 1. Fuzzing Script

**File:** `fuzz_target_*.py` (any name, located in operator's working directory)

- **Detection:** Look for `from boofuzz import` imports and `Session()` calls
- **Forensic Value:** VERY HIGH — defines target, protocol, and fuzzing strategy
- **Signature:** Unlike Sulley (which uses `sulley` module), boofuzz scripts import from `boofuzz` package
- **Example:**
  ```python
  from boofuzz import Session, SocketConnection, Target, s_initialize
  ```

---

## 2. boofuzz Results Directory

**Directory:** `./fuzz_results/` (or custom `log_dir=` path)

### SQLite Database (Key Difference from Sulley)
- **File:** `boofuzz.db` (SQLite 3 format)
- **Contents:** Test cases, results, pass/fail status, crash data
- **Forensic Value:** VERY HIGH — queryable, structured records of all fuzzing activity
- **Example Query:**
  ```bash
  sqlite3 boofuzz.db "SELECT COUNT(*) FROM test_case WHERE passed = 0;" # Count crashes
  ```
- **Tables:**
  - `test_case` — one row per fuzz variant (ID, pass/fail, data, timestamp)
  - `crash` — crash details (exception type, address, call stack)
  - `mutation` — fuzz variant metadata (field name, type, value)

### CSV Export
- **File:** `boofuzz.csv` (spreadsheet format)
- **Contents:** Tab-separated, importable into Excel/LibreOffice
- **Forensic Value:** HIGH — human-readable test case summary

### Text Log
- **File:** `boofuzz_1.log`, `boofuzz_2.log`, etc. (one per session)
- **Contents:** Human-readable test execution log
- **Format:** Plain text, includes test case IDs, status, timestamp

### Crash Directory
- **Subdirectory:** `crash/` (optional, if crashes captured)
- **Files:** `crash_123`, `crash_456`, etc. (binary PoC payloads)
- **Forensic Value:** EXTREMELY HIGH — weaponizable test cases

---

## 3. Python Process and Memory

**Active boofuzz Process:**
- **Process Name:** `python`, `python3`
- **Command Line:** `python3 fuzz_target.py`
- **Memory Contents:** Request definitions, fuzz state, open sockets, target responses
- **Detection:** `ps aux | grep boofuzz` or monitor for Python + network activity

---

## 4. Network Socket State

**During Execution:**
- **Established Connections:** TCP to target host
- **Detection:** `netstat -anp`, `ss -anp` (Linux) or `netstat -ano` (Windows)
- **Pattern:** Single source IP → single target:port, rapid connection/reconnection

---

## 5. Shell History

**Files:**
- Linux: `~/.bash_history`, `~/.zsh_history`
- Windows PowerShell: `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

**Evidence:**
```bash
$ history | grep boofuzz
1024  python3 fuzz_http_server.py
1025  tail -f fuzz_results/boofuzz_1.log
1026  sqlite3 fuzz_results/boofuzz.db "SELECT * FROM test_case LIMIT 10;"
1027  ls -la fuzz_results/crash*
```

---

## 6. Disk I/O and File Growth

**Signatures:**
- Rapid file creation in `fuzz_results/` directory
- SQLite database growing (1000s of rows per second)
- CSV file growth (megabytes per hour)
- Crash files accumulating

**Detection:**
```bash
du -sh fuzz_results/
# 50MB in 1 hour = active fuzzing campaign

watch -n 1 "wc -l fuzz_results/boofuzz.csv"
# Rapidly increasing line count
```

---

## 7. Installed boofuzz Module

**Location:** Python site-packages

- **Path:** `/usr/local/lib/python3.x/dist-packages/boofuzz/` (Linux)
- **Detection:** `python3 -c "import boofuzz; print(boofuzz.__file__)"`
- **File timestamps:** Installation date

---

## Summary: Key Distinguishers from Sulley

**boofuzz-specific artifacts:**
1. **boofuzz.db** SQLite database (vs. Sulley's text index.html)
2. **boofuzz.csv** spreadsheet export (vs. Sulley's text logs)
3. **boofuzz module imports** (vs. sulley module)
4. **Log files named boofuzz_1.log, boofuzz_2.log** (vs. Sulley's generic "logs/")

**If you find boofuzz.db or boofuzz.csv, it's definitely boofuzz, not Sulley.**

---

## Evasion and Counter-Measures

**Operator can hide:**
- Fuzz script (delete after running)
- Results directory (use RAM disk: `log_dir=/dev/shm/hidden`)
- ProcessMonitor subprocess (background execution)

**Counter-measure:**
- Target-side analysis (crashes, error logs) reveals fuzzing regardless of source cleanup
- Memory forensics: search for boofuzz module strings or database signatures
- Timeline analysis: Python process execution + network activity + target crashes

---

## Timeline Correlation

| Time | Source Activity | Artifact |
|------|-----------------|----------|
| T+0 | Script execution | Shell history entry, process spawn |
| T+0.1 | Connect to target | Network connection established |
| T+1 | First fuzz test | boofuzz.db row 1 created, CSV updated |
| T+100 | Continuous fuzzing | boofuzz.db grows, CSV grows, disk I/O spike |
| T+3600 | Crash detected | crash/crash_42 file created, boofuzz.db updated with crash entry |
| T+3601 | Operator analysis | New shell command: `sqlite3 boofuzz.db "SELECT * FROM crash;"` |
| T+3620 | Script finishes | Process exits, connections close |
| T+3621 | Archive results | `tar czf campaign_backup.tar.gz fuzz_results/` in shell history |

---

## SQLite Analysis (Forensic Depth)

**Example: Analyzing boofuzz.db with standard SQLite tools:**

```bash
# Open database
sqlite3 ./fuzz_results/boofuzz.db

# List all tables
.tables

# Show schema
.schema test_case

# Extract crash information
SELECT test_case_num, payload, crash_type, crash_address 
FROM test_case 
WHERE passed = 0 
ORDER BY crash_type;

# Export crash payload as binary
SELECT payload 
FROM test_case 
WHERE test_case_num = 42;

# Count crashes by type
SELECT crash_type, COUNT(*) as count 
FROM test_case 
WHERE passed = 0 
GROUP BY crash_type 
ORDER BY count DESC;
```

**Forensic Value:** This data is more structured and analyzable than Sulley's text logs, making attribution and reconstruction easier.

---

## Key Artifacts Priority

1. **boofuzz.db SQLite database** — Highest priority, definitive proof
2. **Crash files** — Weaponizable PoCs
3. **boofuzz.csv** — Human-readable summary
4. **Fuzz script** — Shows target and strategy
5. **Shell history** — Confirms operator intent and post-fuzz analysis
6. **Process accounting** — Timeline of execution
7. **Network connections** — Temporal link to target
