# Immunity Debugger — Target Evidence

Immunity Debugger is a **source-machine tool only** — it runs on the attacker's workstation and debugs binaries on that same machine. Evidence of exploitation developed via Immunity Debugger appears on the **target system** only after the exploit payload is deployed and executed. There is no "Immunity Debugger running" signature on the target itself.

## What Appears on the Target

The target's evidence depends entirely on **what exploit was developed in Immunity Debugger** and what **the exploit payload does**. Common scenarios:

### Scenario 1: Buffer Overflow Exploit (Shellcode Injection)

**Goal:** Overflow a stack buffer, control EIP, and execute shellcode.

**Target Evidence:**

#### Process Memory & Crash

- **Crash Dump (.dmp):** If the vulnerable application crashes before executing the shellcode:
  - Exception code: `0xC0000005` (EXCEPTION_ACCESS_VIOLATION) or `0xC0000374` (HEAP_CORRUPTION).
  - Exception address: The address where the exploit triggered (e.g., a bad `jmp eax` after EIP is overwritten).
  - Stack frame: Corrupted stack with attacker-controlled values (e.g., return addresses pointing to writable memory or ROP gadgets).

- **Running Process:** If shellcode executes successfully:
  - No crash; the shellcode establishes a reverse shell, downloads a payload, or spawns a new process.

#### Process Creation (Post-Exploitation)

If the shellcode spawns a new process (e.g., `cmd.exe` or a reverse shell):
- **Sysmon Event ID 1 / Windows Security Event ID 4688:** New process created.
  - Parent: The vulnerable application (e.g., `app.exe`).
  - Child: `cmd.exe`, `powershell.exe`, or attacker's custom payload.
  - **Anomaly Signal:** A crash-prone application (e.g., a vulnerable service) spawning `cmd.exe` or `powershell.exe` is highly suspicious.

#### Memory Corruption Artifacts

- **Stack:** Overwritten with attacker's pattern (recognizable if the exploit used a known pattern like `AAAA...BBBB...CCCC...`).
- **Heap:** Potential heap corruption if the overflow spilled into heap memory.
- **SEH Chain (if exploited):** Overwritten SEH frame pointers pointing to attacker-controlled ROP gadgets.

---

### Scenario 2: ROP Chain Execution (No Shellcode)

**Goal:** Overflow stack, control EIP, and chain ROP gadgets to call Windows APIs (e.g., `VirtualAlloc`, `WinExec`, `LoadLibrary`).

**Target Evidence:**

#### API Call Artifacts

- **Registry Modifications:** If ROP chain calls `RegSetValueEx`, registry keys are modified.
  - Detection: Registry auditing (Sysmon Event ID 13, Windows Event ID 4657).

- **File Creation/Modification:** If ROP chain calls `CreateFileA`, files are written/read.
  - Detection: File system event logs (Sysmon Event ID 11, Windows Event ID 4663).

- **Persistence:** If ROP chain modifies `Run` keys or creates scheduled tasks.
  - Detection: Registry/scheduler event logs (Sysmon Event ID 13, Windows Event ID 4662, 4698).

#### Process Termination

- **Sysmon Event ID 5 / Windows Event ID 4689:** Process termination.
  - Often follows a successful ROP-chain exploitation (the vulnerable process crashes or is terminated by the OS after executing arbitrary code).

---

### Scenario 3: Function Pointer Overwrite (Without Stack Overflow)

**Goal:** Overwrite a function pointer in memory (e.g., in the heap or `.data` section) to redirect execution.

**Target Evidence:**

#### Memory Anomalies

- **Heap Corruption (if function pointer is on the heap):**
  - Detection: Application crash with `EXCEPTION_HEAP_CORRUPTION`.
  - Evidence: Heap metadata is corrupted; the OS terminates the process for security.

- **Control Flow Hijacking:**
  - If the function pointer is successfully overwritten and dereferenced, execution jumps to the attacker's address.
  - Evidence: Process crash at an unexpected address, or successful code execution if the pointer was overwritten with a valid gadget/shellcode address.

---

## Event Log Entries

### Sysmon

| Event ID | Log Name | Trigger | Forensic Value |
|---|---|---|---|
| **1** | Process Creation | Vulnerable app spawns child process (shellcode callback) | Parent-child relationship anomaly: `vulnerable.exe` → `cmd.exe` |
| **5** | Process Terminated | Vulnerable app crashes or is terminated after exploitation | Timestamp of crash; process ID; exit code |
| **7** | Image Loaded (DLL Load) | ROP chain calls `LoadLibraryA`, new DLL is loaded | New DLL path, load address, timestamp |
| **9** | Raw Access Thread | Exploit uses raw disk access (rare for standard stack overflow) | Raw disk access attempt (unusual in normal app behavior) |
| **11** | File Created | Shellcode or ROP chain creates files (payload drop, log file) | File path, timestamps |
| **13** | Registry Set Value | ROP chain modifies registry (persistence, config) | Registry key path, value name, data |

### Windows Security Event Log

| Event ID | Trigger | Forensic Value |
|---|---|---|
| **4688** | Process Creation | Vulnerable app spawns child (with /ProcessName parameter showing new process) |
| **4689** | Process Termination | Vulnerable app exits (with exit status code) |
| **4656/4663** | File Access | Shellcode reads/writes files (if auditing is enabled) |
| **4657** | Registry Value Changed | ROP chain modifies registry (if registry auditing is enabled) |
| **4688 (audit success)** | Process started by service | Vulnerable service spawning child process is suspicious |

### PowerShell Event Log

If shellcode or ROP chain executes PowerShell:
- **Event ID 400 (Operational):** PowerShell engine start
- **Event ID 403 (Operational):** PowerShell engine stop
- **Event ID 4104 (Script Block Logging):** PowerShell script block execution (if enabled)
- **Event ID 4103 (Module Logging):** PowerShell module activity

**Example:**
```
Event ID 4104, PowerShell Script Block Logging
ScriptBlockText: powershell -Command "whoami" (or reverse shell one-liner)
```

---

## Registry Artifacts

### Application-Specific Registry

**Vulnerable Application's Registry Key:**
- Typical: `HKCU\Software\<ApplicationName>`
- May contain configuration, recent file list, crash recovery data.
- **Evidence:** If the vulnerable app is a parser/document handler, the registry may log recent file access (MRU list).

### Persistence Registry (Post-Exploitation)

If the exploit's shellcode/ROP chain establishes persistence:
- **Run Keys:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` or `HKLM\...\Run`
- **RunOnce Keys:** `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- **Services:** `HKLM\System\CurrentControlSet\Services\<NewService>`
- **Scheduled Tasks:** `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`

---

## Filesystem Artifacts

### Application Working Directory

**Vulnerable Application's Directories:**
- Temp files, cache, logs (depends on the app).

### Payload/Shellcode Artifacts (Post-Exploitation)

- **Dropped Files:** Shellcode or ROP chain may write a second-stage payload to disk.
  - Typical: `%APPDATA%\`, `%TEMP%`, `%WINDIR%`, or a non-standard directory.
  - **Example:** `C:\Windows\Temp\random_12chars.exe` (a reverse shell).

### Crash Dumps

- **Windows Crash Dumps:** If the vulnerable app crashes during exploitation and crash dump collection is enabled:
  - Default location: `%LOCALAPPDATA%\CrashDumps\` or `C:\ProgramData\Microsoft\Windows\WER\`
  - **Forensic Value:** Full process memory snapshot at crash time; can reveal stack corruption, ROP chain addresses, shellcode bytes.

---

## Network Evidence

### Outbound Connections (Post-Exploitation)

If shellcode establishes a network callback (reverse shell, C2 beacon):
- **Netstat/Network Monitoring (Sysmon Event ID 3, Zeek/NetFlow):**
  - Source: Vulnerable app's process (via its own network socket).
  - Destination: Attacker's C2 server (IP, port).
  - **Protocol:** TCP/UDP (depending on shellcode).

**Example:**
```
vulnerable.exe -> 192.168.1.100:4444 (reverse shell on TCP 4444)
```

### DNS Resolution (Post-Exploitation)

- **Event ID 3003 (Sysmon DNS Query):** Vulnerable app queries attacker's C2 domain.
- **Example:** `vulnerable.exe` queries `attacker-c2.com`, resolves to attacker's IP.

---

## Endpoint Security Product Signatures

### Antivirus/EDR Behavior Detection

**Common Signatures:**
- **Stack Smashing Detection:** EDR monitors for stack overflow patterns (large buffer writes to the stack, return address overwrite).
- **Shellcode Detection:** Memory scanner flags shellcode-like byte patterns (e.g., `\x90\x90...` NOP sleds, `\xff\xe4` JMP ESP).
- **Heap Corruption:** Heap integrity checks detect corruption.

**Immunity Debugger + Exploit Evasion:**
- Modern EDR solutions (Defender for Endpoint, CrowdStrike Falcon, Velociraptor) flag anomalous memory writes and control-flow hijacking.
- If the operator used mona.py to craft badchar-clean shellcode and obfuscate stack patterns, some signatures may be evaded.
- However, the **fundamental anomaly** (a legitimate app crashing and executing code from unexpected memory) is difficult to hide.

### Windows Defender Behavior

- **Behavioral Rules:** Detects suspicious shellcode execution.
- **Signature:** If the shellcode contains known malware patterns (e.g., `cmd.exe /c whoami`), Defender may flag it.
- **In-Memory Detection:** Real-time scanning of process memory during shellcode injection.

---

## Memory Forensics

### Live Memory Analysis (Post-Crash)

If a crash dump is captured (manually or automatically):
- **Process Memory:** The vulnerable app's entire memory image is in the dump.
- **Stack Corruption:** Overwritten return addresses, canary values, SEH frames.
- **Heap Corruption:** Overwritten heap metadata, freed object markers.
- **Shellcode Presence:** If shellcode was injected into a writable heap region, it's visible in the dump (recognizable by opcodes like `\x90\x90...`).

**Volatility 3 Analysis:**
```bash
volatility3 -f crash.dmp windows.pslist  # List processes at crash time
volatility3 -f crash.dmp windows.memmap --pid=<PID>  # Map process memory
volatility3 -f crash.dmp windows.dumpfiles --pid=<PID>  # Extract executables/DLLs
# Search for shellcode patterns:
volatility3 -f crash.dmp linux.strings | grep -E "\\x90{4,}|\\xff\\xe4"  # NOP sleds, JMP ESP
```

---

## Timeline: Exploitation Event Sequence

**Typical sequence when an Immunity-developed exploit is deployed:**

| Time | Target Event | Log Entry | Forensic Signal |
|---|---|---|---|
| T0 | Vulnerable app receives exploit payload (via network, file, etc.) | Network connection (Sysmon Event 3) or File Creation (Sysmon Event 11) | Inbound connection or file drop; network pcap shows exploit data |
| T0+1s | Stack/heap is corrupted; code is injected | — (in-memory only) | Memory corruption; EDR flag; memory dump shows shellcode bytes |
| T0+2s | EIP is diverted to shellcode or ROP chain | — (in-memory) | Control flow hijacking; EDR behavioral flag |
| T0+5s | Shellcode spawns `cmd.exe` or reverse shell connects | Process Creation (Sysmon Event 1); Network Connection (Sysmon Event 3) | Anomalous child process parent; outbound network socket to attacker IP |
| T0+10s | Vulnerable app crashes (if shellcode didn't cleanly exit) | Process Termination (Sysmon Event 5); Windows Event 1001 (crash dump auto-save) | Exception code `0xC0000005` or `0xC0000374`; crash dump in `CrashDumps/` |
| T0+30s | Post-exploitation activity begins (file creation, registry changes) | Sysmon Events 11, 13; Windows Events 4656, 4663 | Timeline correlation: post-crash activity matches persistence payload |

---

## Distinguishing Immunity-Developed Exploits from Other Attack Methods

### Immunity vs. Manual Stack Smash

- **Immunity:** Exploit is typically precise (exact offset to EIP, clean gadget chains, tested for ASLR/DEP bypass).
- **Manual/Cobalt Strike:** May use generic stack-overflow exploits with less precision; may rely on brute-force or less sophisticated ROP chains.

### Immunity vs. Fuzzer-Generated Exploit

- **Immunity:** Exploit is deterministic, tested, often with multiple ROP gadgets.
- **Fuzzer-Generated (AFL, LibFuzzer):** Crashes are chaotic; the "exploit" is often just the crash input itself, not a crafted payload.

### Immunity vs. Pre-Built Exploit (Metasploit, Exploit-DB)

- **Immunity:** Exploit may be customized for a specific target binary version (exact gadget addresses, target-specific offsets).
- **Pre-Built:** Exploit is generic, targets known vulnerable versions; may use standard shellcode (msfvenom-generated).

**Detection Signal:** If the target shows precise, multi-stage ROP chains with custom gadget ordering and badchar-free shellcode, it suggests careful, local exploit development (consistent with Immunity Debugger usage).

---

## See Also

- [Immunity Debugger Source Evidence](../Immunity%20Debugger/03%20-%20Source%20Evidence.md) — what's left on the attacker's machine.
- [mona.py Target Evidence](../mona.py/04%20-%20Target%20Evidence.md) — if the exploit was created using mona.py automation.
- **Windows/12 - Lateral Movement** — post-exploitation activity timeline and event correlation.
- **Windows/Threat Landscape and Playbooks/Exploit Development and Code Execution Playbook** — end-to-end detection strategy for buffer-overflow and ROP-chain exploits.
