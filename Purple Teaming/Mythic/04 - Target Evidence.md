# Mythic C2 — Target Evidence

Target evidence is what remains on the **compromised host** after a Mythic agent is deployed and commands are executed. This varies significantly by agent type (Windows, Linux, macOS) and C2 profile (HTTP, DNS, SMB).

## Filesystem Artifacts

### Agent Binary Artifacts

**Windows (Apollo/Poseidon)**

```
C:\Windows\Temp\<agent-name>.exe              # Staged executable
C:\Users\<user>\AppData\Local\Temp\*.exe      # Alternate temp location
C:\ProgramData\Mythic\agent.exe               # If written to ProgramData
```

**Hunt signal:**
- Unsigned or unusual signer certificate (many Mythic-generated binaries are unsigned or self-signed).
- PE timestamps clustered around engagement dates.
- Recently-created executables in `%TEMP%` with unusual names (random 8-character names without extensions: `abc12def.exe`).

**Linux/macOS**

```
/tmp/<agent-name>                             # Temp directory
/var/tmp/<agent-name>                         # Alternate temp
/opt/beacon.sh                                # If persistence installed
~/.<hidden-folder>/agent                      # Hidden in home directory
```

### Dumped Credential/Loot Artifacts

Commands like `dump_lsass`, `dump_sam`, `keylog` generate temporary files:

**Windows:**

```
C:\Windows\Temp\debug.dmp                     # LSASS memory dump
C:\Windows\Temp\sam.tmp                       # SAM registry hive
C:\Windows\Temp\system.tmp                    # SYSTEM registry hive
C:\Windows\Temp\security.tmp                  # SECURITY hive
C:\Users\<user>\AppData\Local\Temp\key.log    # Keylog output
```

**Timeline:**
- Dump commands create these files in quick succession (~1-3 seconds apart).
- Files persist until the operator downloads them or the agent is killed.
- Operator typically deletes them after exfiltration, but filesystem recovery can find deleted entries.

### Command Execution Artifacts

**Batch file staging** (common for lateral movement/evasion):

```
C:\Windows\Temp\<random>.bat                  # Batch script
C:\Windows\Temp\<random>.vbs                  # VBScript
C:\Windows\Temp\<random>.ps1                  # PowerShell script
```

**Hunt signal:**
- Batch/script files in `%TEMP%` with random names.
- Scripts executed once then deleted (MFT records show create/delete timestamps clustered).
- Script content (via MFT file recovery) reveals command strings (e.g., `net group "Domain Admins"`).

---

## Windows Event Logs

### Event 4688: Process Creation (Sysmon 1)

Every time a Mythic agent spawns a child process, it logs:

```
Event ID 4688 (requires "Audit Process Creation" enabled)
EventType: Process Creation
Creator Process ID: <agent-pid> (e.g., 2048 for apollo.exe)
New Process ID: <child-pid>
New Process Name: C:\Windows\System32\cmd.exe
Process Command Line: "cmd.exe" /c whoami
Parent Image: C:\Windows\Temp\apollo.exe
```

**Timeline:**
- Agent launches, receives queued tasks.
- On each task execution, child process created and logs Event 4688.
- Timestamps cluster around C2 check-in times (e.g., every 5 seconds if sleep interval is 5s).

**Hunt signal:**
- `cmd.exe` spawned from unusual parent (apollo.exe, poseidon.exe, rogue, etc.) is distinctive.
- Parent process lacking obvious administrative tools hints at C2 implant.

### Event 4690: Attempted Credential Access (Privilege Escalation)

LSASS dump attempts generate UAC/privilege escalation events:

```
Event ID 4690 (Attempt to Revoke a Credential)
Requester Process ID: <agent-pid>
Requester Process Name: C:\Windows\Temp\apollo.exe
Target Credential: LSASS Handle
```

**Alternative signal — Sysmon Event 10:** Direct access to LSASS:

```
Sysmon Event 10: Process Access
SourceImage: C:\Windows\Temp\apollo.exe
SourceProcessId: 2048
TargetImage: C:\Windows\System32\lsass.exe
TargetProcessId: 568
GrantedAccess: 0x1F3FFF (full process access)
```

### Event 7045: Service Installation (Persistence)

If a Mythic agent installs a scheduled task or service for persistence:

```
Event ID 7045: A service was installed in the system
Service Name: WindowsUpdate (or other innocuous name)
Service File Name: C:\Windows\Temp\beacon.exe
Service Type: 10 (Win32OwnProcess)
Service Start Type: Disabled|Automatic|Manual
```

**Hunt signal:**
- Service installed with unusual command line (e.g., service pointing to `%TEMP%\beacon.exe`).
- Service name chosen to blend in (WindowsUpdate, Software Protection, etc.).
- Timestamp correlates with agent deployment.

### Event 4697: Registry-Based Service Configuration

When using `schtasks.exe` to create scheduled tasks:

```
Event ID 4697: A user attempted to create a scheduled task
Task Name: WindowsUpdate
Task Content: "<Task><Actions><Exec><Command>C:\Windows\Temp\beacon.exe</Command></Exec></Actions></Task>"
User: DOMAIN\User (or SYSTEM if elevated)
```

### Event 4624: Account Logon

Lateral movement via agent-spawned authentication (e.g., `net use \\target\IPC$`):

```
Event ID 4624: An account was successfully logged on
Logon Type: 3 (Network)
Logon Process: NtLmSsp
Source Network Address: <agent-host-IP>
Source Port: <ephemeral>
Account Name: DOMAIN\Administrator (if credentials were used)
Workstation Name: <agent-hostname>
```

**Hunt signal:**
- Logon events with unusual source workstations (internal servers shouldn't logon to DC).
- Logon type 3 (network) from non-standard source.

---

## Sysmon Events (Windows)

Assuming Sysmon is installed and logging:

### Sysmon Event 1: Process Creation (Detailed)

```
Sysmon Event 1
EventType: CreateProcess
Image: C:\Windows\System32\cmd.exe
CommandLine: cmd /c whoami
ParentImage: C:\Windows\Temp\apollo.exe
ParentProcessId: 2048
ProcessId: 3192
User: DOMAIN\User
Hashes: MD5=abc123def456..., SHA256=...
Signed: False (or unusual signer)
```

**Frequency:** One Event 1 per command executed. If agent sleep is 5s and 10 commands are queued, expect ~10 events over ~50 seconds.

### Sysmon Event 3: Network Connection

```
Sysmon Event 3
EventType: NetworkConnect
Image: C:\Windows\Temp\apollo.exe
SourceIp: 192.168.1.50 (target)
SourcePort: 54321
DestinationIp: 203.0.113.100 (operator's Mythic server)
DestinationPort: 80 (HTTP C2)
Protocol: tcp
Connection: 3 (closed)
Duration: 2 (seconds)
```

**Hunt signal:**
- C2 binary (apollo.exe, poseidon.exe) making outbound network connections.
- Destination IP/port matching known Mythic infrastructure.
- Repeated connections at regular intervals (5s sleep interval = connection every ~5-10s).

### Sysmon Event 7: Image Load (DLL Loading)

```
Sysmon Event 7
EventType: CreateRemoteThread
Image: C:\Windows\Temp\apollo.exe
ImageLoaded: C:\Windows\System32\msvcrt.dll
ImageLoaded: C:\Windows\System32\ntdll.dll
Signed: True (legitimate Windows DLLs)
```

**Hunt signal:**
- Agent binary loading legitimate Windows DLLs is expected (no anomaly).
- But in combination with network connections and child process spawning, is part of the behavioral signature.

### Sysmon Event 10: Process Access

```
Sysmon Event 10
EventType: ProcessAccess
SourceImage: C:\Windows\Temp\apollo.exe
SourceProcessId: 2048
TargetImage: C:\Windows\System32\lsass.exe
TargetProcessId: 568
GrantedAccess: 0x1F3FFF
CallTrace: C:\Windows\System32\ntdll.dll+...
```

**Hunt signal:**
- Non-system process accessing lsass with full access (0x1F3FFF).
- CallTrace showing ntdll API calls (OpenProcess, ReadProcessMemory).
- Timing just before LSASS dump file creation suggests credential harvesting.

---

## Registry Artifacts

### Persistence Via Scheduled Tasks (Registry)

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdate\
  (subkeys indicate a scheduled task was registered)

HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\
  (task GUIDs and definitions stored here)
```

**Hunt signal:**
- Scheduled task created with unusual command (pointing to `%TEMP%\beacon.exe`).
- Task timestamps correlate with agent deployment.

### Service Registration

```
HKLM\System\CurrentControlSet\Services\<ServiceName>\
  ImagePath: C:\Windows\Temp\beacon.exe
  Start: 2 (Automatic) or 3 (Manual)
  Type: 10 (Win32OwnProcess)
  ServiceDll: (if applicable)
```

**Hunt signal:**
- Service pointing to unusual binary path (`%TEMP%`, `%APPDATA%`).
- Service name chosen to blend in (Microsoft*, Windows*, System*, etc.).

### Run/RunOnce Keys (Alternative Persistence)

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run\
  "WindowsUpdate": "C:\Windows\Temp\beacon.exe"
  "Software Protection": "C:\Users\Public\spp.exe"
```

**Hunt signal:**
- Run key with unusual binary path or unsigned binary.

### MRU Lists (User Activity)

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
  (most recently used commands entered via cmd.exe/powershell)

Example entry: "cmd /c whoami" -> "a"
  (indicates operator ran this command via agent)
```

---

## Network-Layer Evidence

### HTTP C2 Traffic (Sysmon Event 3, Zeek, Netflow)

**TCP connection pattern (HTTP profile):**

```
Source: 192.168.1.50 (compromised host)
Source Port: 54321 (ephemeral)
Destination: 203.0.113.100 (operator's server)
Destination Port: 80
Protocol: TCP
Duration: ~2-5 seconds
Data Volume: 512 bytes → 1 KB (initial beacon)
Frequency: Every 5 seconds ± jitter (if sleep=5s, jitter=30%)
```

**Wireshark / Zeek Inspection:**

```
HTTP POST /api/task HTTP/1.1
Host: 203.0.113.100
Content-Length: 512
Content-Type: application/json

[Encrypted JSON blob with AES-256-GCM]
```

**Response:**

```
HTTP/1.1 200 OK
Content-Length: 256

[Encrypted task list from Mythic server]
```

**Hunt signal:**
- Regular HTTP connections to a single external IP, repeating at intervals.
- Connection duration and data volume consistent with C2 check-in.
- User-Agent header may be customized but typically Windows UA.

### DNS C2 Traffic (DNS profile)

**DNS query pattern:**

```
Source: 192.168.1.50
Source Port: 53 (or random high port)
Destination: <DNS resolver IP> or <operator-controlled NS>
Query Type: A / TXT / CNAME
Query: <base64-beacon-data>.c2.attacker.com

Response:
TXT: <base64-encrypted-task>
OR
A: <encoded-task-IP> (e.g., 10.0.0.1 = task ID encoded in octets)
```

**Frequency:** Every 5 seconds ± jitter, like HTTP.

**Hunt signal:**
- DNS queries to operator-controlled domain.
- Queries with base64-looking subdomains (high entropy).
- Repeated queries at regular intervals (not typical user behavior).

### SMB Pivoting (Named Pipes)

**Network connections (for peer-to-peer relay):**

```
Source: 192.168.1.50 (compromised host A)
Source Port: 445 (SMB)
Destination: 192.168.1.51 (compromised host B)
Destination Port: 445

Protocol: SMB2 / SMB3
Share: IPC$
Named Pipe: \\.\pipe\msagent_<random>
```

**Hunt signal:**
- SMB connections between internal hosts (unusual for typical workstations).
- Named pipe names with suspicious patterns (msagent_*, svcctl_*, etc.).
- Event 5140 (SMB share mounted) on target Host B from Host A.

---

## Process Tree and Memory Artifacts

### Behavioral Signature: Process Tree

```
cmd.exe (or powershell.exe)
  └── C:\Windows\Temp\apollo.exe (agent parent)
       └── C:\Windows\System32\cmd.exe (for each queued command)
            └── whoami.exe
       └── C:\Windows\System32\cmd.exe
            └── ipconfig.exe
       └── C:\Windows\System32\cmd.exe
            └── net.exe group "Domain Admins"
```

**Hunt signal:**
- Multiple cmd.exe children spawned from a suspicious parent in quick succession.
- Parent binary located in `%TEMP%` or `%APPDATA%`.
- No user interactive activity (no shell prompt, no user-initiated commands visible in command-line history).

### Memory Forensics (Volatility)

If a memory dump is acquired:

```bash
# volatility -f memory.dmp windows.pstree.PsTree
cmd.exe (Parent: System)
  └── apollo.exe (PID 2048, unsigned, path=C:\Windows\Temp\apollo.exe)
       └── cmd.exe (PID 3192, temporary child process)
       └── powershell.exe (PID 3456, temporary child process)
       └── net.exe (PID 3800, temporary child process)

# volatility -f memory.dmp windows.handles.Handles | grep 203.0.113.100
# (Shows open network handles to Mythic server)

# volatility -f memory.dmp windows.vads.Vads
# (Virtual address descriptors of apollo.exe showing mapped DLLs, executable heap regions)
```

**Hunt signal:**
- Unsigned process with network handles.
- Loaded DLLs consistent with .NET (if Apollo) or Python runtime (if Poseidon).

---

## Agent-Specific Artifacts

### Apollo (C# Agent) on Windows

**Artifacts:**
- `.NET CLR Runtime` event log entries (Event ID 1000-1026 if .NET exception logging is enabled).
- Temporary .NET assembly files in `C:\Windows\Temp` or `C:\ProgramData\<hidden>`.
- Heap memory containing .NET metadata (if memory dump acquired).

**Forensic signature:**
- Process loads mscorlib.dll, System.dll (characteristic of .NET runtime).
- Signed by operator's certificate (or unsigned, if self-signed or no signing applied).

### Poseidon (Python Agent) on Windows/Linux/macOS

**Artifacts:**
- Python interpreter in use (or embedded Python if statically compiled).
- `.pyc` bytecode files in temp directories or Python cache.
- Python imports visible in process memory (e.g., `requests` module for HTTP).

**Forensic signature:**
- Process tree showing `python.exe` or embedded Python binary.
- Network libraries (requests, dns.resolver) loaded.

### Rogue (Go Agent)

**Artifacts:**
- Statically compiled, minimal runtime dependencies.
- No obvious .NET or Python indicators.
- Large binary (5-50 MB depending on capabilities).

**Forensic signature:**
- Binary linked against Go runtime libraries.
- Minimal external DLL dependencies (unlike .NET or Python).

---

## Timeline Reconstruction: Target-Side Events

| Time | Source | Event | MITRE ID |
|---|---|---|---|
| 2025-08-12 09:30 | Sysmon 1 | apollo.exe executed from C:\Windows\Temp\ | T1204.002 |
| 2025-08-12 09:31 | Sysmon 3 | apollo.exe connects to 203.0.113.100:80 | T1071.001 |
| 2025-08-12 09:32 | Event 4688 | cmd.exe spawned by apollo.exe (whoami) | T1059.003 |
| 2025-08-12 09:33 | Event 4688 | cmd.exe spawned by apollo.exe (ipconfig) | T1033 |
| 2025-08-12 09:34 | Sysmon 3 | apollo.exe connects again (callback) | T1071.001 |
| 2025-08-12 09:35 | Event 4688 | cmd.exe spawned, executing: `reg save HKLM\SAM` | T1003.002 |
| 2025-08-12 09:40 | Sysmon 3 | apollo.exe connects (upload LSASS dump) | T1041 |
| 2025-08-12 10:00 | Event 4697 | Scheduled task "WindowsUpdate" created | T1053.005 |
| 2025-08-12 10:05 | Registry | HKLM\...Schedule\TaskCache\Tree\WindowsUpdate created | T1053.005 |

**Correlated timeline:** Apollo executed → contacted C2 → executed enumeration commands → dumped credentials → created persistence task → confirmed callback.

---

## IOC Summary for Target Host Detection

| Category | IOC | Strength |
|---|---|---|
| **Process** | apollo.exe, poseidon.exe, rogue (unsigned or unusual signer) | Very High |
| **Process** | Parent process is .exe in %TEMP% spawning cmd.exe | Very High |
| **Network** | Outbound TCP to single IP:80/443 at regular intervals (5s ±30%) | Very High |
| **Network** | DNS queries to base64-like subdomains (high entropy) | High |
| **Network** | SMB connections to internal hosts (for pivoting) | Medium |
| **Event Log** | Event 4688 with parent=C:\Windows\Temp\*.exe | High |
| **Event Log** | Event 4690 (LSASS access attempt) + Sysmon 10 | High |
| **Event Log** | Event 7045 (service) or 4697 (scheduled task) with unusual command | High |
| **File System** | C:\Windows\Temp\<random>.exe (recent creation) | Medium (matches many malware) |
| **File System** | LSASS dump, SAM hive files in %TEMP% | Very High |
| **Sysmon** | Event 1: cmd.exe parent=apollo.exe, Event 3: outbound to C2 | Very High |
| **Sysmon** | Event 10: non-system process accessing lsass.exe | Very High |
| **Sysmon** | Event 3: repeated connections at regular intervals | High |
| **Registry** | Scheduled task registry keys with C:\Windows\Temp\*.exe | High |
| **Memory** | apollo.exe in memory with .NET runtime loaded | High |

---

## Comparison With Other C2 Frameworks

| Detection Signal | Mythic (HTTP) | Cobalt Strike | Sliver | Notes |
|---|---|---|---|---|
| **Process Injection** | Agent-dependent (Apollo can, Poseidon can) | Beacon default behavior | Implant default | Mythic flexibility depends on agent type |
| **Named Pipes** | SMB profile only, named `msagent_*` | Standard `MSSE-<UUID>` | Standard `wg_*` | Agent/profile-specific naming |
| **Service/Task** | Operator-configurable persistence | BeaconHttpServer service | Custom per deployment | Mythic requires explicit persistence command |
| **C2 Cert** | Operator customizes per profile, or HTTP (no cert) | Watermark signature (unless Malleable) | Dynamically generated per implant | Mythic profiles handle cert separately |
| **Binary Hash** | Unique per build (different encryption keys) | Same hash across identical builds | Unique per build (random keys) | All three avoid static hash IOCs |
| **JA3/JARM** | Customizable via HTTP profile parameters | Customizable via Malleable profile | Fixed per transport (unless profile customized) | Mythic and Cobalt Strike more flexible |

---

## Defense and Remediation: Target Cleanup

### Immediate Response (If Compromise Detected)

1. **Kill the agent process** — terminate apollo.exe/poseidon.exe by PID.
2. **Remove persistence** — delete scheduled tasks, services, registry Run keys.
3. **Close listening ports** — if agent spawned a listening service, terminate it.
4. **Invalidate compromised credentials** — force password resets for accounts used by agent or accessed during compromise.
5. **Isolate from network** — disconnect host to prevent further C2 communication.

### Preventive Measures

1. **Process monitoring** — EDR/Sysmon alerting on child processes spawned from unusual parents (especially from %TEMP%).
2. **Network segmentation** — restrict outbound HTTP/HTTPS/DNS from user workstations to approved external hosts only.
3. **Disable unnecessary services** — disable RDP, WinRM, SMB on hosts that don't need them (reduces lateral movement).
4. **Credential Guard** — Windows Defender Credential Guard protects LSASS from unauthorized access (requires TPM 2.0).
5. **LSA Protection (RunAsPPL)** — run lsass.exe as Protected Process Light to prevent direct dumping (highest evasion-resistance).
6. **Scheduled Task hardening** — alert on/block task creation by non-administrative processes.
7. **DNS monitoring** — alert on DNS queries to internal/external C2 infrastructure.
