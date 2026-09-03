# DefenderCheck — Target Evidence

**Where to look on the target (victim) host for evidence of DefenderCheck usage or its impact.**

## Key Distinction

DefenderCheck is a **tool run on the attacker's/red-team's source host**, not directly on the target. However, the *impact* of DefenderCheck — modified payloads that bypass Defender signatures because they were tested with DefenderCheck — will manifest on the target. Additionally, if an attacker gains hands-on access to a target host and runs DefenderCheck *there* (to test payloads directly against that host's specific Defender version), forensic evidence appears on the target.

---

## Scenario 1: Target Evidence of DefenderCheck Usage on the Target Itself

**When:** An attacker gains interactive shell or RDP access to a target host and runs DefenderCheck locally to test payloads.

### Process Execution Evidence

- **Event Log: Security (Event ID 4688 - Process Creation)**
  ```
  Process Name: DefenderCheck.exe
  Command Line: DefenderCheck.exe C:\Windows\Temp\beacon.exe
  Parent Process: cmd.exe or powershell.exe
  Timestamp: <date/time during suspected intrusion>
  ```
  
  **Huntable in Log Analytics / SIEM:**
  ```
  EventID == 4688 AND CommandLine CONTAINS "DefenderCheck"
  ```

- **Windows Defender / Security Events (Event ID 1001, 1116-1118)**
  - Event ID 1001: DefenderCheck itself flagged as `VirTool:MSIL/BytzChk.C!MTB` (if Defender was not disabled).
  - Event ID 1116: Threat detected in target binary (e.g., beacon.exe).
  - Event ID 1006: Scan completed.

### Defender Configuration Change Evidence

**Registry Keys Modified:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender
  DisableRealtimeMonitoring = 1 (set to 1 to allow DefenderCheck)

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection
  DisableBehaviorMonitoring = 1
  DisableOnAccessProtection = 1
```

**Event Log Evidence:**
- **Event ID 2004 (System)**: Real-time protection disabled (if logged).
- **Event ID 5000/5001 (Windows Defender)**: Service stopped/started events around DefenderCheck execution.

### File System Evidence

**Temporary test files in C:\Temp\ (from binary splitting):**
- Even though DefenderCheck auto-cleans these files, forensic recovery via $MFT or unallocated clusters may reveal:
  ```
  Deleted File: C:\Temp\beacon.exe.test.001
  Deleted File: C:\Temp\beacon.exe.test.002
  ...
  ```
  
- File system journal ($UsnJrnl) shows rapid creation/deletion pattern (characteristic of binary splitting).

**Prefetch artifacts:**
- `C:\Windows\Prefetch\DEFENDERCHECK.EXE-<hash>.pf`

### Payload Evidence

**Tested payloads left on disk:**
- `C:\Temp\beacon.exe` (the payload DefenderCheck was analyzing).
- `C:\Windows\Temp\payload.bin` (common staging location).
- Versions/variants of the same payload (e.g., `beacon_v1.exe`, `beacon_v2.exe`, `beacon_clean.exe`).

**Huntable patterns:**
- Multiple versions of the same executable with similar names.
- Executables in Temp directories with creation times in quick succession.
- Executables matching known malware families (via hash, name, strings).

---

## Scenario 2: Target Evidence of Modified Payloads (Indirect DefenderCheck Impact)

**When:** An attacker tested payloads with DefenderCheck on their own host, then deployed the *modified* version to the target.

### Payload Characteristics

The deployed payload will show evidence of **obfuscation/modification**, distinct from known malware baselines:

#### Type 1: Hardcoded String Modifications
**Original malware signature:**
```
C:\Temp\payload.exe:
  Strings: "192.168.1.100:4444" (known C2 server)
```

**After DefenderCheck + obfuscation:**
```
Modified payload:
  Strings: Encrypted/encoded C2 (e.g., "9D 87 2A 4B ..." XOR-encoded)
  Or: C2 loaded at runtime from registry/file
```

**On target**, evidence appears as:
- Binary without obvious strings (strings utility returns minimal results).
- Registry queries for C2 domain (if loaded from `HKCU\Software\<random>`).
- Network connections to C2 server (traffic analysis).

#### Type 2: API Call Obfuscation
**Original sequence:**
```
VirtualAlloc → memcpy → CreateThread
```

**After obfuscation (to evade Defender):**
```
VirtualAlloc → GetTickCount → Sleep → memcpy → InterlockedCompareExchange → CreateThread
[junk code inserted to break signature matching]
```

**On target**, evidence appears as:
- Unusual API call sequences in process memory (unpacker or virtualized code).
- Behavior-based detection (EDR tools may flag the API sequence even if Defender signature misses it).

#### Type 3: PE Header Modifications
**Original malware header:**
```
PE signature: 0x5A4D (MZ)
Sections: .text, .data, .rsrc
```

**After obfuscation:**
```
PE signature: still 0x5A4D (must be valid)
Sections: .text, .data, .rsrc, .payload, .stub (extra sections added)
Timestamp: Changed to evade signature
```

**On target**, evidence appears as:
- Non-standard PE sections (via PE analysis tools).
- Suspicious section names (`.xor`, `.decoy`, etc.).
- Mismatched Authenticode signature (if tampered with).

---

## Scenario 3: Behavioral Evidence (No Direct DefenderCheck Artifacts)

**When:** The attacker ran DefenderCheck on their host, modified the payload to be Defender-clean, then deployed it. The target sees *only* the modified payload's behavior, not DefenderCheck itself.

### Payload Execution Indicators

**Process Behavior:**
- **Unusual parent-child relationships**: Binary executed from Temp, spawned by Explorer or cmd.exe.
- **Direct network communication**: Immediate C2 callback after payload execution (no delay).
- **Privileged access requests**: Binary requests admin rights or token impersonation.

**Network Indicators:**
- **C2 traffic pattern**: Regular beacons to external IP (over HTTP, DNS, or encrypted channel).
- **Tool-specific traffic**: Known C2 frameworks (Cobalt Strike, Metasploit, Empire) have characteristic network signatures.

**File System Indicators:**
- **Persistence mechanisms**: Registry Run keys, scheduled tasks, WMI event subscriptions (created by the payload).
- **Data staging**: Files encrypted/compressed in AppData or Temp.
- **Tool deployment**: Child tools staged in Temp or AppData before execution.

### Defender/EDR Evidence

If the payload *was* Defender-clean but later detected by EDR:
- **EDR detection**: Carbon Black, Crowdstrike, or Defender for Endpoint may detect the payload's *behavior* even if the signature was bypassed.
- **Behavioral alerts**: Memory corruption, registry tampering, suspicious API calls.

**Event Log Evidence:**
- **Event ID 5000**: Defender service running (attacker did not permanently disable it).
- **Event ID 1001**: Threat detected (later, if Defender was re-enabled or signature updated).
- **Event ID 1116**: Threat detected in memory or file (behavior-based detection).

---

## Scenario 4: Hands-On Keyboard Access Indicators

**When:** An attacker gained interactive access via RDP, local shell, or C2 session and used DefenderCheck on the target interactively.

### Evidence Collection Checklist

| Artifact | Expected Finding | Forensic Value |
|---|---|---|
| **Event Log 4688 (Process Creation)** | `cmd.exe`, `powershell.exe` spawning `DefenderCheck.exe` | High — direct evidence of DefenderCheck usage. |
| **Event Log 4688 (RDP Logon)** | Logon Type 10 (RDP) or 7 (interactive), username/domain, source IP. | High — shows attacker's origin. |
| **$UsnJrnl (file creation/deletion)** | Rapid file create/delete cycles in C:\Temp\ | Medium — supports binary splitting hypothesis. |
| **MFT records (deleted files)** | Filenames like `beacon.exe.tmp.*`, size progression | Medium — forensic-only recovery. |
| **Prefetch** | `DEFENDERCHECK.EXE-*.pf` exists | Medium — confirms tool execution. |
| **Registry timestamp** | `DisableRealtimeMonitoring` modified during intrusion window | High — correlates with DefenderCheck needs. |
| **Temp directory** | Payload binaries with timestamps | High — shows attacker's staging location. |
| **Shortcut/LNK files** | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` | Low — may reference DefenderCheck or payloads if opened via File Explorer. |

### Timeline Reconstruction

```
2024-01-15 14:00 — RDP login from 203.0.113.45 (attacker)
2024-01-15 14:05 — Event 4688: cmd.exe spawned
2024-01-15 14:06 — Registry modified: DisableRealtimeMonitoring = 1
2024-01-15 14:07 — Event 4688: DefenderCheck.exe launched
                    Command: DefenderCheck.exe C:\Temp\beacon.exe
2024-01-15 14:08 — $UsnJrnl: 50+ file creation/deletion events in C:\Temp\
2024-01-15 14:12 — Registry modified: DisableRealtimeMonitoring = 0 (re-enabled)
2024-01-15 14:15 — Event 4688: beacon.exe executed from C:\Temp\
2024-01-15 14:16 — Network: Outbound connection to 192.0.2.10:4444 (C2 server)
2024-01-15 14:30 — RDP logout
```

**Analyst Conclusion:** Attacker gained RDP access, disabled Defender, tested payload with DefenderCheck, re-enabled Defender, executed payload, established C2 callback. Entire operation took ~30 minutes.

---

## Scenario 5: Absence of Payload Artifacts (Evasion Success)

**When:** DefenderCheck was used successfully; Defender never detected the payload; the payload evaded static signature detection.

### What *Won't* Appear

- **No Defender Event ID 1001** (threat detected at file).
- **No Defender Event ID 1116** (threat detected in folder).
- **No quarantine event**.
- **Binary allowed to execute without Defender intervention**.

### What *Will* Appear

- **Process execution** (Event 4688): payload.exe executed, spawned child processes.
- **Network traffic** (if monitored): C2 beacons outbound.
- **Registry modifications**: Persistence mechanisms.
- **File system changes**: Data written to Temp, AppData.

**Hunting Strategy:**
Since static Defender detection is absent, pivot to:
1. **Behavioral detection** (EDR tools, SIEM rules).
2. **Network detection** (DNS logs for C2 domain resolution, firewall logs for unusual outbound connections).
3. **Hash reputation** (submit binary to VirusTotal; if ≤5 vendors detect it, it's likely a Defender-evasion variant).

---

## Summary: On-Target Indicators

| Indicator | Severity | Confidence | Notes |
|---|---|---|---|
| **Process: DefenderCheck.exe** | Critical | Very High | Direct proof of DefenderCheck usage on target. |
| **Registry: DisableRealtimeMonitoring = 1** | High | High | Prerequisite for DefenderCheck; timestamp correlates with tool execution. |
| **$UsnJrnl: Rapid file create/delete in C:\Temp\** | High | Medium | Binary splitting pattern; may be deleted post-cleanup. |
| **Payload binary in Temp with DefenderCheck-compatible name** | High | Medium | Staging location for tested payloads. |
| **Event 4688: Defender-flagged tool execution** | Medium | Medium | If Defender itself catches DefenderCheck's execution. |
| **RDP logon + DefenderCheck execution within minutes** | High | High | Attacker hands-on-keyboard access + payload testing. |
| **Absence of Defender alerts for payload** | Medium | Low | Could indicate successful evasion via DefenderCheck, or payload never executed. |
| **Modified malware variant (strings/PE headers altered)** | Medium | Low | Suggests obfuscation, but many malware variants exist; weak link to DefenderCheck specifically. |

---

## Cross-Link to Windows Artifacts

**For deeper context on Defender's own artifacts, see:**
- `Windows/11 - Defense Evasion/AMSI, ETW, Windows Defender.md` — Defender configuration, registry keys, event logs, and detection bypass techniques.

**For broader hands-on access indicators, see:**
- `Windows/11 - Evidence Collection/Registry, Event Logs, MFT.md` — Detailed registry and event log artifact analysis.
- `Windows/11 - Evidence Collection/Prefetch, Shimcache, Timeline.md` — Execution timeline reconstruction.

---

## Key Takeaway for Defenders

**DefenderCheck is a "bring your own binary" tool** — it doesn't *attack* the target; it helps attackers *prepare* attack payloads. Its presence on a target indicates the attacker has already achieved hands-on access or is actively testing payloads for deployment.

**Most reliable on-target signal:** Combination of:
1. **Defender disabled** (registry evidence).
2. **DefenderCheck or payload execution** (process logs).
3. **Rapid file cycles in Temp** (file system journal).
4. **C2 callback shortly after** (network logs).

Any one in isolation is weak; all four together is conclusive.
