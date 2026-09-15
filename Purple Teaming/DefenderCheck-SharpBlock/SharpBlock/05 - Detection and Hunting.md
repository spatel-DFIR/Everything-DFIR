# SharpBlock — Detection and Hunting

## Hunting on Source (Red-Team/Attacker Host)

**Goal:** Identify systems where SharpBlock was staged and prepared (attacker infrastructure).

### Hunt 1: SharpBlock Binary by Name

**Signal:** File named `SharpBlock.exe` exists on a host (likely red-team infrastructure, not a typical user/workstation host).

**File System Search:**
```bash
# Live host
Get-ChildItem -Recurse -Filter "*SharpBlock*" -ErrorAction SilentlyContinue

# Forensic image
Find all files named *SharpBlock* in the disk image
```

**Expected Result:**
- SharpBlock.exe in red-team infrastructure, staged payloads directory, or tools folder.
- If found on a user workstation, indicates red-team compromise of that workstation.

**Whitelisting:**
- Legitimate penetration testing vendors (Red Teaming firms) may have SharpBlock in their infrastructure — coordinate with them to whitelist legitimate activity.

---

### Hunt 2: SharpBlock Source Repository

**Signal:** Git repository (`github.com/CCob/SharpBlock`) cloned locally.

**File System Search:**
```bash
# Look for .git directory with CCob/SharpBlock reference
grep -r "CCob/SharpBlock" .git/config
grep -r "SharpBlock" .git/refs/heads/*
```

**Expected Result:**
- `.git/config` contains: `url = https://github.com/CCob/SharpBlock.git`
- Commit history shows when tool was accessed and by whom.

---

### Hunt 3: Process Execution — SharpBlock by Name

**SIEM/Log Query (Event ID 4688):**
```
EventID == 4688 AND Image CONTAINS "SharpBlock"
```

**Expected Result:**
- SharpBlock.exe executed on red-team host.
- Command-line shows EDR DLL names (e.g., `csagent.dll`, `falcon.dll`), payload paths.

---

### Hunt 4: Payload Staging Artifacts

**Signal:** Multiple beacon/payload binaries in the same directory, correlated with SharpBlock presence.

**File System Hunt:**
```
Directory: C:\Tools\payloads\ or similar
Files:
  - beacon.exe (Cobalt Strike)
  - beacon_x64.exe
  - rubeus.exe (Kerberos extraction)
  - mimikatz.exe (credential theft)
  - SharpBlock.exe
```

**Forensic Correlation:**
- All files in the same directory.
- File timestamps show they were staged together.
- Hash analysis correlates them across incidents.

---

### Hunt 5: Cobalt Strike Integration

**Signal:** Cobalt Strike Aggressor scripts or team server configuration referencing SharpBlock.

**Search:**
```bash
# Cobalt Strike directory
~/.cobaltstrike/scripts/*
grep -r "SharpBlock" ~/.cobaltstrike/scripts/
```

**Expected Result:**
- Aggressor script wrapper for SharpBlock.
- Team server logs showing SharpBlock-based payload generation.

---

## Hunting on Target (Victim Host)

**Goal:** Identify hosts where SharpBlock was executed to inject malware or tools.

### Hunt 1: SharpBlock Binary on Disk

**Signal:** File `SharpBlock.exe` exists in Temp, Tools, or staging directories (not typical on user workstations).

**Live Hunt:**
```powershell
Get-ChildItem -Path C:\Temp, C:\Windows\Temp, C:\Tools -Recurse -Filter "*SharpBlock*" -ErrorAction SilentlyContinue
```

**Forensic Hunt:**
```bash
# Carve deleted SharpBlock.exe from disk image
Find files with known SharpBlock hash in unallocated clusters
```

**Expected Result:**
- **Critical finding:** SharpBlock.exe on production/user host indicates compromise and EDR bypass attempt.

---

### Hunt 2: Suspicious Process Execution (Event ID 4688)

**Signal:** SharpBlock.exe executed, or process spawned with EDR DLL names in command line.

**SIEM Query:**
```
EventID == 4688 AND (
  Image LIKE "*SharpBlock*" OR
  CommandLine LIKE "*csagent.dll*" OR
  CommandLine LIKE "*falcon*" OR
  CommandLine LIKE "*amsi.dll*" OR
  CommandLine LIKE "*edr*" OR
  CommandLine LIKE "*edrmgr*"
)
```

**Expected Result:**
- SharpBlock execution or process spawning with EDR DLL names.

---

### Hunt 3: Anomalous Process Injection Patterns

**Signal:** Process spawned in suspended state, then resumed with different behavior than expected.

**EDR-Based Hunt (if available):**
```
Detection:
  - Process created with CREATE_SUSPENDED flag
  - Memory injection detected (WriteProcessMemory API)
  - DLL entry point hooked or blocked
  - Parent-child process relationship anomaly
```

**Expected Result:**
- Behavioral alert from EDR indicating injection.

---

### Hunt 4: Parent Process Spoofing

**Signal:** Discrepancy between declared parent process (in Event Log 4688) and actual parent (from process tree tools).

**SIEM Correlation:**
```
Event 4688: cmd.exe spawned notepad.exe
Process Explorer: svchost.exe → notepad.exe
Discrepancy = Parent spoofing detected
```

**Huntable Pattern:**
```
Anomalous parent-child relationships:
  - svchost.exe → cmd.exe
  - svchost.exe → notepad.exe
  - svchost.exe → rundll32.exe
  - explorer.exe → system32 binary (unusual)
```

**YARA/Sigma rule concept:**
```yaml
title: Anomalous Parent-Child Process Relationship
logsource:
  product: windows
  service: security
detection:
  process_creation:
    EventID: 4688
    ParentImage|endswith:
      - svchost.exe
      - lsass.exe
      - csrss.exe
    Image|endswith:
      - cmd.exe
      - powershell.exe
      - notepad.exe
      - rundll32.exe
  condition: process_creation
```

---

### Hunt 5: EDR DLL Absence in Injected Process

**Signal:** Expected EDR DLL (e.g., `csagent.dll`) is not loaded in processes where it normally should be.

**Baseline:** Establish baseline of which processes normally load EDR DLLs.

**Anomaly Detection:**
```
Expected: All user processes load csagent.dll (Crowdstrike)
Actual: Process XYZ does not load csagent.dll
Conclusion: EDR DLL blocked or bypassed (consistent with SharpBlock)
```

**Sysmon-Based Hunt (Event ID 7 - Image Loaded):**
```
Sysmon Rule:
  NOT (ImageLoaded CONTAINS "csagent.dll") AND Process == "beacon.exe"
  → Alert: EDR DLL not loaded in beacon process
```

---

### Hunt 6: Command-Line Spoofing via PEB Modification

**Signal:** Command-line in Event Log 4688 contradicts actual process behavior.

**Example:**
```
Event 4688: cmd.exe /c echo test
Actual behavior: Outbound TCP connection to 192.0.2.10:4444 (C2 callback)
```

**Huntable Pattern:**
```
CommandLine contains innocent-looking text (echo, calc, notepad, powershell -NoP)
But network indicators show C2 callback or file exfiltration
→ Likely command-line spoofing
```

---

### Hunt 7: Beacon / Payload Network Indicators

**Signal:** Outbound C2 callback from a process that doesn't match its declared purpose.

**Network Hunt (Firewall, Proxy, Network TAP):**
```
Source IP: 192.168.1.50 (victim workstation)
Destination: 192.0.2.10:4444 (attacker C2 server)
Process: cmd.exe (spoofed), but traffic pattern matches Cobalt Strike beacon
→ Beacon callback via injected process
```

**Beacon Fingerprints:**
- **HTTP POST** to `/submit` endpoint (Cobalt Strike).
- **SSL/TLS certificate**: Self-signed, specific issuer patterns.
- **Traffic pattern**: Regular beacons at interval (5s, 60s, etc.).
- **User-Agent**: `Windows Update` or other spoofed UA.

**Huntable SIEM Query:**
```
DestinationIp == 192.0.2.10 AND DestinationPort == 4444 AND SourceIp == 192.168.1.50
OR User-Agent == "Windows-Update-Agent" AND DestinationDomain == suspicious_domain
```

---

### Hunt 8: EDR Alert Absence During Injection

**Signal:** EDR platform logs exist, but show **no injection/process-manipulation alerts** during the suspected injection window.

**SIEM Hunt:**
```
Time Window: 2024-01-15 14:06:00 to 14:06:30
EDR Alerts: NONE (expected: multiple alerts for process injection, DLL hooking)
Conclusion: EDR was bypassed (consistent with SharpBlock usage)
```

**Contrast with Normal Injection:**
```
Normal Injection (not bypassed):
  Event 1001: Injection attempt detected
  Event 1116: Malicious payload detected
  Action: Quarantine/kill process

SharpBlock Injection (bypassed):
  Event Log: EMPTY (no alerts)
  Conclusion: EDR was blinded by DLL blocking
```

---

## Detection Rules (Sigma/YARA)

### Sigma Rule: SharpBlock Execution
```yaml
title: SharpBlock EDR Bypass Tool Execution
logsource:
  product: windows
  service: security
detection:
  process_execution:
    EventID: 4688
    Image|endswith:
      - \sharpblock.exe
      - \SharpBlock.exe
    CommandLine|contains|all:
      - "-n" or "--name" or "-c" or "--copyright" or "-d" or "--description"
      - "csagent" or "falcon" or "amsi" or "edr" or "crowdstrike"
  condition: process_execution
falsepositives:
  - Legitimate penetration testing on authorized infrastructure
level: critical
tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.t1055
```

### Sigma Rule: Anomalous Parent-Child Relationship (Post-Spoofing)
```yaml
title: Suspicious Parent-Child Process Relationship (EDR Bypass)
logsource:
  product: windows
  service: security
detection:
  process_creation:
    EventID: 4688
    ParentImage|endswith:
      - svchost.exe
      - lsass.exe
      - csrss.exe
      - services.exe
    Image|endswith:
      - cmd.exe
      - powershell.exe
      - notepad.exe
      - rundll32.exe
  condition: process_creation
falsepositives:
  - Some legitimate administrative tools may spawn these processes (rare)
level: high
tags:
  - attack.defense_evasion
  - attack.t1036.005
```

### Sigma Rule: EDR DLL Bypass (Missing in Process)
```yaml
title: EDR DLL Not Loaded in Process (Blocking Suspected)
logsource:
  product: windows
  service: sysmon
detection:
  image_loaded:
    EventID: 7
  anomaly:
    NOT (ImageLoaded CONTAINS "csagent.dll") AND Image CONTAINS "beacon.exe"
  condition: image_loaded AND anomaly
level: high
tags:
  - attack.defense_evasion
  - attack.t1562
```

### YARA Rule: SharpBlock Binary Detection
```yara
rule SharpBlock_EDR_Bypass {
    meta:
        description = "Detect SharpBlock EDR bypass tool"
        author = "DFIR Team"
        date = "2024-01-15"
    strings:
        $mz = "MZ" at 0
        $string1 = "SharpBlock" nocase
        $string2 = "DisableRealtimeMonitoring" nocase
        $string3 = "csagent.dll" nocase
        $string4 = "--ppid" nocase
        $function1 = "WriteProcessMemory" nocase
        $function2 = "CreateRemoteThread" nocase
    condition:
        $mz and (2 of ($string*) or 2 of ($function*))
}
```

---

## Summary: Detection Table

| Hunt | Location | Severity | Confidence | Method |
|---|---|---|---|---|
| **SharpBlock.exe on disk** | Target host, Temp dirs | Critical | Very High | File system search, hash lookup. |
| **Process execution (Event 4688)** | Target host Event Logs | Critical | Very High | SIEM query on 4688. |
| **Anomalous process relationships** | Event Logs, process tools | High | High | Correlation analysis, process tree review. |
| **EDR DLL absence** | Sysmon Event 7 | High | Medium | Baseline deviation analysis. |
| **Command-line spoofing** | Event 4688 + behavior | Medium | Medium | Discrepancy detection (command vs. behavior). |
| **C2 callback network indicators** | Firewall, DNS, proxy logs | High | High | Network IOC matching, traffic pattern analysis. |
| **EDR alert absence** | EDR platform logs | High | Medium | Negative hunt (absence of expected alerts). |
| **Payload binary** | Temp dirs, disk image | High | High | File system search, hash lookup. |

---

## Response Playbook

### Alert Triggering (Detection)
1. SIEM alert fires: `SharpBlock.exe executed` or `Anomalous process injection detected`.
2. Security analyst investigates.

### Immediate Response (First 30 Minutes)
1. **Isolate host** from network (prevent C2 callback).
2. **Capture memory** (for in-memory beacon analysis).
3. **Preserve event logs** (copy to secure server before attacker covers tracks).
4. **Check other hosts** for similar indicators (lateral movement detection).

### Investigation (30 Minutes - 2 Hours)
1. **Timeline reconstruction:**
   - When was SharpBlock executed? (Event 4688 timestamp)
   - What process was injected? (parent-child relationship)
   - What payload was injected? (beacon.exe hash, file path)
   - When did C2 callback occur? (network log timestamp)

2. **Scope assessment:**
   - How many hosts affected?
   - What user accounts were compromised?
   - What data/systems were accessed via beacon?

3. **Attribution:**
   - Where did attacker come from? (RDP source IP, reverse shell origin)
   - What access method was used? (credential compromise, phishing, exploit)?
   - Are there indicators of compromise on other systems?

### Containment (2 - 4 Hours)
1. **Disable attacker's access:**
   - Reset compromised user passwords.
   - Disable/revoke compromised credentials.
   - Kill attacker's logon sessions (RDP, reverse shell).
   - Block attacker's IP at firewall/WAF.

2. **Disable beacon communication:**
   - Block C2 domain/IP at firewall.
   - Interrupt DNS resolution for C2 domain.
   - If possible, kill injected beacon process (but avoid alerting attacker).

3. **Restore EDR service:**
   - Re-enable Crowdstrike, Sentinel One, MDE (if disabled).
   - Verify EDR is monitoring all hosts.

### Eradication (4 - 8 Hours)
1. **Remove attacker tools:**
   - Delete SharpBlock.exe.
   - Delete beacon/payload binaries.
   - Delete attacker-created files/scripts.

2. **Remove persistence:**
   - Delete scheduled tasks created by beacon.
   - Remove registry Run keys.
   - Delete startup folder scripts.
   - Check for WMI event subscriptions.

3. **Patch vulnerabilities:**
   - Identify exploited vulnerability (if applicable).
   - Deploy patch or workaround.

### Recovery (8 - 24+ Hours)
1. **Restore systems:**
   - Reimage compromised hosts (if necessary).
   - Verify legitimate functionality is restored.

2. **Verify EDR coverage:**
   - Confirm EDR is reporting from all hosts.
   - Run EDR health check.

3. **Monitor for re-compromise:**
   - Increase logging/alerting sensitivity.
   - Hunt for related indicators across infrastructure.

### Post-Incident (24+ Hours)
1. **Root cause analysis:**
   - How did attacker gain initial access?
   - Why did EDR bypass succeed? (Was DLL blocking the weakness?)
   - Are there systemic security gaps?

2. **Lessons learned:**
   - Update detection rules (add SharpBlock signatures).
   - Improve EDR configuration (reduce bypass opportunities).
   - Enhance EDR behavioral monitoring (catch injections despite DLL blocking).

3. **Documentation:**
   - Write incident report with timeline, scope, impact.
   - Share IOCs with SOC, peers, threat intelligence platforms.

---

## EDR Resilience Improvements

**After discovering SharpBlock usage, implement:**

1. **Behavioral Detection Enhancements:**
   - Monitor for process suspension/injection patterns (even if DLL blocking occurs).
   - Detect memory injection via API call sequences (WriteProcessMemory, SetThreadContext).
   - Alert on unusual parent-child relationships (svchost → cmd.exe).

2. **Kernel-Level Monitoring:**
   - Deploy kernel-level EDR (harder to bypass than user-mode hooks).
   - Monitor system calls directly (avoid relying on DLL entry points).

3. **AMSI/ETW Strengthening:**
   - Implement additional layers of AMSI integration (redundant hooks).
   - Use ETW providers that SharpBlock cannot disable.
   - Monitor for AMSI/ETW disable attempts.

4. **Process Hollowing Detection:**
   - Monitor for process creation with CREATE_SUSPENDED flag.
   - Detect memory region modifications (MapViewOfFile, WriteProcessMemory on process image).

5. **Command-Line Spoofing Countermeasures:**
   - Monitor both PEB (Process Environment Block) command-line and direct API parameters.
   - Alert on discrepancies.

---

## Cross-Links

- **EDR Architecture**: See `Windows/11 - Defense Evasion/AMSI, ETW, Windows Defender.md` for AMSI/ETW bypass details.
- **Process Injection Techniques**: See `Windows/11 - Lateral Movement/Process Injection.md` for process hollowing mechanisms.
- **Advanced Hunting Queries**: See `SIEM & Detection/Sigma Rules, KQL, SPL.md` for advanced SIEM query syntax.
- **Incident Response Playbook**: See `Incident Response/Investigation Playbook.md` for detailed IR procedures.
