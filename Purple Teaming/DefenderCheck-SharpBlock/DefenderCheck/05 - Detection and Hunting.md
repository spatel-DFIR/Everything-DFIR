# DefenderCheck — Detection and Hunting

## Hunting on Source (Attacker/Red-Team Host)

**Goal:** Identify systems where DefenderCheck was executed (payload testing environment).

### Hunt 1: Process Execution — DefenderCheck by Name

**Signal:** Process named `DefenderCheck.exe` or containing "DefenderCheck" in command line.

**SIEM/Log Query (Windows Event Log, Event ID 4688):**
```
EventID == 4688 AND (
  Image CONTAINS "DefenderCheck" OR
  CommandLine CONTAINS "DefenderCheck"
)
```

**Splunk Query:**
```
index=windows EventCode=4688 (Image="*DefenderCheck.exe" OR CommandLine="*DefenderCheck*")
| stats count by host, User, CommandLine, src_ip
```

**Sigma Rule Concept:**
```yaml
title: DefenderCheck Execution
logsource:
  product: windows
  service: security
detection:
  process_creation:
    EventID: 4688
    Image|endswith:
      - defendercheck.exe
      - DefenderCheck.exe
    CommandLine|contains: DefenderCheck
  condition: process_creation
```

**Expected Result:**
- Hosts running offensive security tooling.
- Research networks (academic, security company labs).
- Attacker infrastructure (if DefenderCheck was executed within a compromised host or C2 session — rare but possible).

**False Positives:**
- Legitimate malware research environments (university labs, antivirus vendor labs).
- Penetration testing labs.

**Mitigation:** Whitelist known security research infrastructure; alert on DefenderCheck execution outside those environments.

---

### Hunt 2: Defender Disablement Correlating with Payload Scanning

**Signal:** Registry key `DisableRealtimeMonitoring` set to 1, followed by batch/PowerShell script execution or process launch of unknown binaries in Temp.

**SIEM Query (correlate Event 4657 [Registry] + Event 4688 [Process]):**
```
[Registry Event] (
  EventID == 4657 AND
  ObjectName CONTAINS "DisableRealtimeMonitoring" AND
  NewValue == "1" AND
  Timestamp >= T-5min
) FOLLOWED BY [Process Event] (
  EventID == 4688 AND
  (Image CONTAINS "DefenderCheck" OR CommandLine CONTAINS "Temp" OR CommandLine CONTAINS "Payload")
) WITHIN 5 minutes
```

**Expected Result:**
- Suspicious correlation between Defender disable and payload testing.

---

### Hunt 3: Batch Script Invoking DefenderCheck

**Signal:** Batch or PowerShell script files (`*.bat`, `*.ps1`) containing the string "DefenderCheck" or invoking it in a loop.

**File System Search (Live Host or Forensics):**
```bash
# Search for scripts containing "DefenderCheck"
grep -r "DefenderCheck" --include="*.bat" --include="*.ps1" C:\*
grep -r "DefenderCheck" %TEMP%
grep -r "DefenderCheck" %USERPROFILE%
```

**Expected Result:**
- Script files like `scan_payloads.bat`, `test_evasion.ps1`.
- Script contents revealing payload paths, target binaries, output logging.

---

### Hunt 4: Prefetch Files

**Signal:** Prefetch file for DefenderCheck exists (`DEFENDERCHECK.EXE-*.pf`).

**File System Search:**
```bash
dir C:\Windows\Prefetch\DEFENDERCHECK.EXE-*.pf
```

**Analysis (with Prefetch parser tool):**
```
Prefetch File: DEFENDERCHECK.EXE-ABC123.pf
Run Count: 5
Last Execution Time: 2024-01-15 14:08:32
Referenced DLLs:
  - C:\Windows\System32\kernel32.dll
  - C:\Windows\System32\ntdll.dll
  - C:\Windows\System32\user32.dll
  ... [Windows core DLLs only, no malware staging DLLs]
```

**Expected Result:**
- Confirms DefenderCheck execution with timestamps.
- Shows how many times it was run (iteration count).

---

### Hunt 5: NTFS File System Journal ($UsnJrnl) — Binary Splitting Signature

**Signal:** Rapid creation and deletion of files in `C:\Temp\` matching a pattern (e.g., successive numerical suffixes), suggesting binary splitting iterations.

**Forensic Analysis (using tools like MFTECmd, usnjournal parsers):**
```
File: C:\Temp\payload_chunk_001.bin
Created: 2024-01-15 14:06:50.123
Deleted: 2024-01-15 14:06:50.456
File: C:\Temp\payload_chunk_002.bin
Created: 2024-01-15 14:06:50.567
Deleted: 2024-01-15 14:06:50.789
[... many more in rapid succession ...]
```

**Pattern Recognition:**
- 50+ file creation/deletion events in <60 seconds.
- Filenames with numeric suffixes in sequence.
- File sizes that are fractions of the original binary (consistent with binary splitting).

**Expected Result:**
- High-confidence indicator of binary analysis/splitting on the host.

---

### Hunt 6: Defender Configuration Tampering Timeline

**Signal:** Registry key `DisableRealtimeMonitoring` is modified from 0 → 1 → 0 (disabled then re-enabled), during a short time window.

**Event Log Analysis:**
```
Timestamp: 2024-01-15 14:06:00 — DisableRealtimeMonitoring changed from 0 to 1
Timestamp: 2024-01-15 14:06:05 to 14:15:00 — [Payload testing window]
Timestamp: 2024-01-15 14:15:30 — DisableRealtimeMonitoring changed from 1 to 0
```

**SIEM Alert:**
```
Alert: Defender Disable/Enable Cycle Detected
Duration: <15 minutes
Correlation: Coincides with payload execution or file activity in Temp
Risk Level: High
```

**Expected Result:**
- Attacker behavior: disable Defender, test payload, re-enable Defender (cleanup).

---

## Hunting on Target (Victim Host)

**Goal:** Identify if a target host was used to test payloads with DefenderCheck (post-compromise).

### Hunt 1: DefenderCheck Process Execution on Target

**SIEM Query (Event 4688):**
```
EventID == 4688 AND Image CONTAINS "DefenderCheck"
```

**Expected Result:**
- High-severity finding: attacker hands-on-keyboard access to the target.

---

### Hunt 2: Defender Disablement Followed by Hands-On Access

**Signal:** Registry key `DisableRealtimeMonitoring` set to 1, followed by RDP/interactive session activity, followed by binary execution in Temp.

**SIEM Query (correlate Event 4624 [Logon] + Event 4657 [Registry] + Event 4688 [Process]):**
```
[Logon Event] (
  EventID == 4624 AND
  LogonType IN (3, 7, 10) [Network, Interactive, RDP] AND
  Timestamp >= T-30min
) FOLLOWED BY [Registry Event] (
  EventID == 4657 AND
  ObjectName CONTAINS "DisableRealtimeMonitoring" AND
  NewValue == "1"
) FOLLOWED BY [Process Event] (
  EventID == 4688 AND
  Image CONTAINS "cmd.exe" or "powershell.exe"
) WITHIN 30 minutes
```

**Expected Result:**
- Attacker gained interactive access and disabled Defender for payload testing.

---

### Hunt 3: Unusual Payload Binaries in Temp Directories

**Signal:** Executables in `C:\Temp\` or `C:\Windows\Temp\` with suspicious names or characteristics.

**File Scanning (Yara, YARA rules, or string matching):**
```
Directory: C:\Temp\
Files: *.exe, *.dll, *.bin
Suspicious Characteristics:
  - Filename contains: beacon, payload, shellcode, dropper, rat, loader
  - File size > 10 KB (typical binary)
  - Creation timestamp during intrusion window
  - Hash not in clean file database (not a known legitimate tool)
```

**Expected Result:**
- Discovered payload staged for testing or execution.

---

### Hunt 4: Binary Splitting Pattern in File System Journal

**Forensic Query (carve $UsnJrnl):**
```
Pattern: Rapid creation/deletion of files in C:\Temp\ with size progression
Example:
  payload_001.tmp (50 KB created/deleted)
  payload_002.tmp (25 KB created/deleted)
  payload_003.tmp (62 KB created/deleted)
  [...]
  Total: 50+ files in <60 seconds
```

**Expected Result:**
- Binary analysis/splitting activity detected; likely payload optimization or evasion testing.

---

### Hunt 5: Modified Malware Variants (Indirect Evidence)

**Signal:** Multiple versions of the same malware with slight variations (different strings, PE headers, timestamps).

**Malware Analysis (Hash Clustering, Fuzzy Matching):**
```
Malware Hash: abc123def456 (known Cobalt Strike beacon)
Variant 1: abc123def456 (original, detected by 60/70 antivirus vendors)
Variant 2: xyz789uvw012 (similar to Variant 1, 5 byte differences, detected by 8/70 vendors)
Variant 3: aaa111bbb222 (similar to Variant 1, 50 byte differences, detected by 2/70 vendors)

Analysis:
  Variant 1 vs 2: Hardcoded string changed (C2 address obfuscated)
  Variant 2 vs 3: API call sequence altered (detection evasion)
```

**Expected Result:**
- Confirms iterative obfuscation/evasion testing.

---

### Hunt 6: Hands-On RDP/Interactive Access Correlating with Payload Execution

**SIEM Timeline Analysis:**
```
2024-01-15 14:00 — Event 4624: RDP logon (source 203.0.113.45)
2024-01-15 14:05 — Event 4688: cmd.exe spawned by svchost (unusual parent)
2024-01-15 14:06 — Event 4657: DisableRealtimeMonitoring = 1
2024-01-15 14:10 — Event 4688: Test payload execution in Temp
2024-01-15 14:15 — Event 4688: beacon.exe execution
2024-01-15 14:16 — Network: Outbound connection to 192.0.2.10:4444
2024-01-15 14:30 — Event 4624: RDP logoff
```

**Risk Assessment:**
- RDP session + Defender disable + payload execution + C2 callback = **Confirmed compromise + hands-on attack**.

---

## Detection Rules (Sigma/YARA Examples)

### Sigma Rule: DefenderCheck Process Execution
```yaml
title: DefenderCheck Malware Analysis Tool Execution
logsource:
  product: windows
  service: security
detection:
  process_execution:
    EventID: 4688
    Image|endswith:
      - \defendercheck.exe
      - \DefenderCheck.exe
  condition: process_execution
falsepositives:
  - Legitimate malware research on dedicated lab systems
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.t1140
```

### Sigma Rule: Defender Disable + Batch Script Execution
```yaml
title: Defender Disabled Followed by Batch Script Execution
logsource:
  product: windows
detection:
  defender_disable:
    EventID: 4657
    ObjectName|contains: DisableRealtimeMonitoring
    NewValue: 1
    Timestamp: T-10m
  batch_execution:
    EventID: 4688
    Image|endswith:
      - \cmd.exe
      - \powershell.exe
    CommandLine|contains:
      - .bat
      - .ps1
  condition: defender_disable and batch_execution
level: medium
```

### YARA Rule: DefenderCheck Binary Pattern
```yara
rule DefenderCheck_Executable {
    meta:
        description = "Detect DefenderCheck malware analysis utility"
        author = "DFIR Team"
        date = "2024-01-15"
    strings:
        $pdb = "DefenderCheck.pdb" nocase
        $string1 = "No threat found" nocase
        $string2 = "Flagged bytes at offset" nocase
        $string3 = "Binary splitting" nocase
        $mz = "MZ" at 0
    condition:
        $mz and (2 of ($string*) or $pdb)
}
```

---

## Summary: Key Indicators Table

| Indicator | Location | Severity | Confidence | Huntable |
|---|---|---|---|---|
| **DefenderCheck.exe process** | Event Log 4688 (source host) | Critical | Very High | Yes — direct process name match. |
| **DefenderCheck in batch script** | File system (*.bat, *.ps1) | High | High | Yes — grep/find for filename. |
| **Prefetch file** | `C:\Windows\Prefetch\DEFENDERCHECK.EXE-*.pf` | Medium | High | Yes — file existence check. |
| **$UsnJrnl binary splitting pattern** | NTFS journal (source host) | High | Medium | Yes — forensic parsing (requires disk image). |
| **DisableRealtimeMonitoring = 1** | Registry Event Log 4657 | High | High | Yes — registry change audit. |
| **Disable/re-enable cycle** | Event Log 4657 timeline | High | High | Yes — SIEM correlation. |
| **RDP + DefenderCheck + payload execution** | Event Log 4624, 4688 correlation | Critical | High | Yes — SIEM timeline correlation. |
| **Payload variant clustering** | Malware hash analysis | Medium | Medium | Yes — VirusTotal, Cuckoo, local sandbox. |
| **C2 callback after payload execution** | Network logs (firewall, DNS) | High | Medium | Yes — network monitoring. |

---

## Response Playbook

### If DefenderCheck is Detected

1. **Immediate Actions:**
   - Isolate the host from the network (defender + attacker attribution).
   - Preserve memory dump (capture running processes, network connections).
   - Preserve disk image (for $UsnJrnl, file system journal analysis).

2. **Investigation:**
   - Timeline: When was DefenderCheck executed? (Prefetch timestamp + Event Log 4688).
   - What payload was tested? (File name in command line, directory scan for test binaries).
   - What modifications were made? (Hash comparison with known malware variants).
   - Where did the attacker come from? (Event 4624 source IP, network logs).

3. **Artifact Collection:**
   - Prefetch files (`C:\Windows\Prefetch\`).
   - Event logs (Security, System, Windows Defender).
   - Registry hives (HKEY_LOCAL_MACHINE\SYSTEM, HKEY_LOCAL_MACHINE\SAM, HKEY_USERS).
   - File system image (for forensic analysis, $UsnJrnl carving).
   - Network logs (firewall, IDS/IPS, DNS, proxy).

4. **Containment:**
   - Disable attacker's access (RDP session, service account, lateral movement paths).
   - Re-enable Defender (if disabled).
   - Update EDR signatures (if available).
   - Scan all systems for the identified payload variant.

5. **Eradication:**
   - Remove payload binaries.
   - Remove persistence mechanisms (scheduled tasks, registry Run keys, WMI subscriptions).
   - Reset compromised credentials.
   - Patch exploited vulnerabilities.

6. **Post-Incident:**
   - Write timeline for incident report.
   - Share payload hash + characteristics with SOC for ongoing detection.
   - Review Defender policies across enterprise (ensure DisableRealtimeMonitoring is not set globally).

---

## Cross-Links

- **Related Tools:** See `SharpBlock/` (EDR evasion) and `Veil-Evasion/` (encoding/obfuscation) for complementary evasion techniques.
- **Artifact Deep Dives:** See `Windows/11 - Defense Evasion/AMSI, ETW, Windows Defender.md` for Defender architecture and detection bypass details.
- **Forensic Techniques:** See `Windows/11 - Evidence Collection/Registry, Event Logs, MFT.md` for detailed registry/event log analysis methodology.
