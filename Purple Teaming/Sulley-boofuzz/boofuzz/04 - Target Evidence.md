# boofuzz — Target Evidence

Target-side evidence is nearly identical to Sulley, since boofuzz is semantically the same (stateful protocol fuzzing). Key difference: **boofuzz's better logging** may result in more detailed application error logs on the target.

## 1. Application Crashes and Core Dumps

**Pattern:** Service crashes repeatedly at different memory addresses (stateful fuzzing testing multiple state transitions)

### Windows
- **Event Log (Application):** Event ID 1000, 1001 (Application crash)
- **Event Log (System):** Event ID 7034, 7035 (Service crash, restart)
- **Crash Dumps:** `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\`

### Linux/Unix
- **Syslog:** "segmentation fault at ip [address]" entries
- **Core Dumps:** `/var/crash/core*` or current working directory
- **Systemd Logs:** `journalctl -u service_name` shows repeated exits

**Example Timeline (Linux):**
```
Aug 11 14:23:00 target kernel: myapp[12456]: segmentation fault at ip 401234
Aug 11 14:23:02 target systemd[1]: myapp.service: Main process exited, code=exited, status=139
Aug 11 14:23:05 target systemd[1]: myapp.service: Attempting restart.
Aug 11 14:23:06 target kernel: myapp[12467]: segmentation fault at ip 401300
Aug 11 14:23:08 target systemd[1]: myapp.service: Main process exited, code=exited, status=139
... repeated 50+ times in 1 hour
```

---

## 2. Network Traffic Anomalies

**Pattern:** High volume of malformed protocol messages from single source IP

### tcpdump/Wireshark Analysis
- **Source IP:** Attacker's machine
- **Destination:** Target service port
- **Message Structure:** Repeated, with systematic field variation
- **Protocol Violations:**
  - Invalid checksums
  - Oversized/truncated payloads
  - Out-of-state commands
  - Null bytes in unexpected fields

### IDS/WAF Alerts
- "Protocol anomaly detected"
- "Multiple malformed requests from single IP"
- "High error rate from source IP" (4xx/5xx responses)

---

## 3. Application Error Logs

**Key Difference from Sulley:** boofuzz users often add better logging callbacks, resulting in **more verbose target-side logs**.

### HTTP Server Example
```
192.168.1.50 - - [11/Aug/2026:14:23:45 +0000] "GET /\x00index.html HTTP/1." 400 0
192.168.1.50 - - [11/Aug/2026:14:23:46 +0000] "GET /\xff\xff HTTP/1.1" 400 0
192.168.1.50 - - [11/Aug/2026:14:23:47 +0000] "GET /index.html\x00 HTTP/1.1" 400 0
[alert] 12345#12345: *1 client 192.168.1.50 reached max_fails=5 failures=5
```

### Custom Protocol Server
```
[14:23:45] ERROR: Invalid checksum in RETR
[14:23:46] ERROR: Payload size mismatch, expected 256, got 12345
[14:23:47] ERROR: Out-of-sequence command
[14:23:48] CRITICAL: Heap overflow detected, terminating process
```

**Forensic Value:** Application logs directly document what boofuzz sent and how the target reacted

---

## 4. Service Restart Patterns

**Signature:** Service crashes → restarts → crashes again, rapidly

### Windows Event Logs
- **Event ID 7034:** "Service terminated unexpectedly" (repeated in minutes)
- **Clustering:** 50+ restarts in 1 hour = fuzzing activity

### Linux Systemd
- **Pattern:** Multiple "exited" entries clustered
- **Command:** `journalctl -u service_name | grep -E "exited|restart" | wc -l`
  - Normal: 1-5 per week
  - During fuzzing: 50+ per hour

---

## 5. Memory Dumps and Debugger Artifacts

**If Target Running Under Debugger:**

### Windows
- **Crash Dumps:** `[AppName].dmp` (100s of MB)
- **Location:** `C:\ProgramData\Microsoft\Windows\WER\ReportArchive/`
- **Analysis:** WinDbg + `!analyze -v` command

### Linux/Unix
- **Core Dumps:** `core`, `core.12345` (PID-suffixed)
- **Analysis:** `gdb binary core.12345` → `where`, `print $rax`

**Key:** Multiple dumps with **different fault addresses** = boofuzz testing different code paths

---

## 6. Prefetch and Execution Artifacts

### Windows Prefetch
- **File:** `%SystemRoot%\Prefetch\[APP].EXE-<hash>.pf`
- **Evidence:** Run count (e.g., "47 runs" = 47 process invocations/crashes)
- **Timestamps:** Multiple execution times clustered in short window

### Linux Process Accounting
- **File:** `/var/log/account/`
- **Evidence:** Multiple execve() entries for target process with short intervals

---

## 7. EDR and Endpoint Security Alerts

### Windows Defender / Antimalware
- **Alert Type:** Process crash loop
- **Message:** "Process [myapp.exe] terminated abnormally 47 times"
- **Behavioral Detection:** Potential exploit/fuzzing activity

### Third-Party EDR (CrowdStrike, Defender for Endpoint, SentinelOne)
- **Timeline Event:** "Process crash rate anomaly detected"
- **Network Detection:** "Sustained malformed network traffic from single IP"
- **Alert:** "Potential exploit development activity"

---

## 8. Timeline Correlation (Target)

| Time | Event | Artifact |
|------|-------|----------|
| T+0 | TCP connection from attacker | Network monitor, connection log |
| T+0.5 | First fuzz test case sent | Application log entry (error) |
| T+2 | Crash triggered | Exception logged, core dump generated |
| T+2.1 | Process restart | Event ID 7034/7035 logged |
| T+2.5 | Attacker reconnects | New connection established |
| T+3 | Next crash | Another core dump, another event log entry |
| T+100 (cluster) | 50+ crashes in 1 hour | System log flooded with crash entries |
| T+3600 | Fuzzing stops | No more connections, error rate drops |

---

## 9. Evasion Opportunities (Limited)

**Target cannot hide crashes:** They're kernel/OS-level, automatic logging

**Possible mitigations (weak):**
- Disable crash logging (degrades security posture, suspicious)
- Disable core dumps (prevents detailed analysis, but crash still logged)
- Clear event logs (forensic artifact itself — suspicious)

**Strong counter:** If target admin claims "no crashes" but network packets show malformed traffic, **check for logs being cleared** (a form of anti-forensics)

---

## 10. Distinguishing boofuzz from Sulley (Target-Side)

**On the target, detection is nearly identical.** Both cause crashes, restarts, and protocol errors.

**Minor differences:**

| Signal | Sulley | boofuzz |
|--------|--------|---------|
| **Crash Pattern** | Multiple fault addresses | Multiple fault addresses (same) |
| **Error Logs** | Generic protocol errors | May be slightly more verbose (if boofuzz has better logging callbacks) |
| **Timing** | Rapid succession (1000s/hour) | Same (1000s/hour) |
| **Network Traffic** | Malformed messages | Same (malformed messages) |

**Bottom line:** Target-side, both tools are **forensically indistinguishable**. Differentiation happens on the source machine (boofuzz.db vs. Sulley's text logs).

---

## High-Confidence Detection Checklist (Target)

- [ ] **Multiple crashes with distinct fault addresses** in < 1 hour
- [ ] **Crash + restart cycle** (service crashes, restarts, crashes again, repeated 50+ times)
- [ ] **Protocol error logs** showing systematic field-level variation (same message type, different fields)
- [ ] **All crashes from same source IP** (vs. distributed attack)
- [ ] **Timeline correlation:** Network traffic timestamps match crash log timestamps exactly
- [ ] **Core dumps or crash dumps** with different call stacks (different code paths fuzzed)
- [ ] **IDS/WAF alerts** for "protocol anomaly" from single source

**If ≥3 of these are present, protocol fuzzing attack (boofuzz or Sulley) is high-confidence.**

---

## Key Takeaway

**Target evidence does not distinguish boofuzz from Sulley.** Both result in crashes, restarts, and protocol errors. **Source machine (attacker's computer) is where differentiation occurs** — boofuzz.db vs. Sulley's text logs.
