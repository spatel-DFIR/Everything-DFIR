# pwntools — Target Evidence

Target evidence is what appears on the **compromised host** when exploited by a pwntools-based attack. Evidence varies based on exploit technique (buffer overflow, ROP, format string, etc.) but revolves around **process behavior**, **memory corruption**, **event logs**, **filesystem artifacts**, and **privilege escalation**.

---

## 1. Process-Level Evidence

### Unexpected Process Spawning

When exploit calls `system()` or `execve()` via shellcode/ROP:

```
vulnapp (PID 1234)
  └─ /bin/bash (PID 5678, spawned unexpectedly)
     └─ /bin/sh (PID 5679, spawned from /bin/bash)
```

**Artifacts:**

| Source | Event | Details |
|--------|-------|---------|
| **Sysmon Event 1 (Windows)** | Process creation | ParentImage: vuln.exe or vulnapp, Image: cmd.exe or powershell.exe, ParentCommandLine: (shellcode output or truncated). |
| **auditd (Linux)** | EXECVE audit | parent comm=vulnapp, exe=/bin/bash, args=[shellcode generated string]. |
| **Process telemetry** (Falcon, CrowdStrike) | Parent-child relationship | Unexpected shell spawned from unrelated binary. |
| **ps/tasklist snapshot** | Running process list | bash/cmd.exe with parent = vuln process, suspicious timing. |

### Memory Corruption and Crash

After overflow, if return address is incorrect:

```
PID 1234: vulnapp SEGFAULT (signal 11)
  Registers at crash:
    rax = 0x4141414141414141  (AAAA... — buffer contents)
    rip = 0x4242424242424242  (BBBB... — overwritten return address)
    rsp = 0x7fffffffde00 (stack pointer, corrupted)
```

**Artifacts:**

| Source | Event | Details |
|--------|-------|---------|
| **Kernel log / dmesg** | Segmentation fault | `[PID] segfault at address rip=0x... rsp=0x... error=0x...`. |
| **Core dump** | /var/crash/ or /proc/sys/kernel/core_pattern | Memory snapshot at crash time; includes register state, stack, heap. |
| **System log** | /var/log/syslog, /var/log/messages | `kernel: [...] killed vulnapp[PID]: segmentation fault ...`. |
| **Application log** | App-specific log file | "Unexpected termination" or "Signal 11 received". |

### Process Privilege Escalation

If exploit targets setuid binary or UAC-elevated process:

```
vulnapp (EUID=0, EGID=0)  ← Exploit succeeded; now running as root
  └─ /bin/bash (EUID=0, EGID=0)
```

**Artifacts:**

| Source | Event | Details |
|--------|-------|---------|
| **Sysmon Event 1** | Process creation | ParentImage vuln.exe running with System/Administrator token, IntegrityLevel: System. |
| **ps/Get-Process** | Process listing | UID=0 (root) or Name running at SYSTEM level unexpectedly. |
| **Lastlog** | Root login event | If shell exfiltrates bash prompt with `id` output. |
| **wtmp/utmp** | Login session | New login session as root (if interactive shell logs in). |

---

## 2. Memory Evidence

### Exploited Process Memory State

At the moment of exploitation, target process memory contains:

```
0x7fffffffde00 (stack):
  [Exploit Payload]
  [ROP Gadget Addresses]
  [Shellcode Bytes]
  [Leaked Addresses (from info-disclosure phase)]

0x601000 (heap):
  [Heap metadata corruption]
  [Chunk pointers to attacker-controlled memory]

0x400000 (text segment):
  [Original binary code]
  [No modifications — shellcode runs from stack/heap]
```

**Artifacts:**

| Source | Evidence | Details |
|--------|----------|---------|
| **Core dump analysis** | /var/crash/core.vulnapp.1234 | Full memory snapshot; can extract shellcode, ROP addresses, leaked values. |
| **Memory forensics** | Extract from live system via /proc/PID/maps + memdump tools | Stack canary value (if present), heap allocations, stack layout. |
| **Debugger (gdb post-crash)** | gdb core.vulnapp.1234 | `x/100bx $rsp` — hex dump of stack showing payload, `info registers` — corrupted registers. |
| **Volatility / Rekall** | Advanced memory analysis | ELF binary reconstruction, module loading order, string searches for ROP gadgets. |

### Leaked Address Artifacts

If exploit uses information-disclosure to leak addresses:

```
/proc/PID/maps (at exploit time):
  7f0000000000-7f0000100000 r-xp /lib/x86_64-linux-gnu/libc.so.6
  7ffff7200000-7ffff7300000 rw-p [heap]
  7ffffffde000-7ffffffff000 rw-p [stack]
```

**Evidence:**
- Memory layout preserved in core dump (ASLR values at time of crash).
- Leaked addresses appear in process memory/core dump.
- Timing of layout randomization enables ASLR bypass attribution.

---

## 3. Event Logs

### Linux auditd and Kernel Logs

#### Process Execution Audit

```bash
type=EXECVE msg=audit(1691764425.234:567): argc=1 a0="/bin/bash"
type=EXECVEAT msg=audit(1691764425.234:568): argc=2 a0="/tmp" a1="payload.sh"
```

**Related Events:**
- `EXECVE` — Process fork and exec.
- `FORK` — Process cloning.
- `EXIT` — Process termination (signal 11 crash).

#### File Access Audit

```bash
type=OPEN msg=audit(1691764425.234:569): flags=O_CREAT|O_WRONLY a0="/tmp/shell.sh"
type=OPENAT msg=audit(1691764425.234:570): name="/etc/passwd"
```

**Analysis:** Audit trail shows unexpected file access (e.g., reading /etc/shadow after exploit).

### Windows Event Logs

#### Process Creation (Event ID 1, Sysmon)

```xml
<Event>
  <System>
    <EventID>1</EventID>
    <Provider>Sysmon</Provider>
  </System>
  <EventData>
    <Data Name="ParentImage">C:\vulnerable_app.exe</Data>
    <Data Name="ParentCommandLine">C:\vulnerable_app.exe</Data>
    <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
    <Data Name="CommandLine">C:\Windows\System32\cmd.exe /c whoami</Data>
    <Data Name="ParentProcessId">1234</Data>
    <Data Name="ProcessId">5678</Data>
  </EventData>
</Event>
```

**Analysis:** Unexpected process spawning from non-system binary (vulnerable_app.exe spawning cmd.exe).

#### Image Load (Event ID 7, Sysmon)

```xml
<Event>
  <Data Name="Image">C:\vulnerable_app.exe</Data>
  <Data Name="ImageLoaded">C:\Windows\System32\msvcrt.dll</Data>
  <Data Name="Hashes">MD5=..., SHA256=...</Data>
</Event>
```

**Analysis:** If shellcode loads unusual DLLs (e.g., WinINet for C2), detected via image-load events.

#### Network Connection (Event ID 3, Sysmon)

```xml
<Event>
  <Data Name="SourceIp">192.168.1.100</Data>
  <Data Name="SourcePort">54321</Data>
  <Data Name="DestinationIp">10.0.0.5</Data>
  <Data Name="DestinationPort">9000</Data>
  <Data Name="Protocol">tcp</Data>
  <Data Name="InitiatedConnection">true</Data>
  <Data Name="SourcePortName">vulnapp</Data>
</Event>
```

**Analysis:** Unexpected outbound connection from vulnerable process to attacker IP.

---

## 4. Network Evidence

### Inbound Connection

When attacker connects to vulnerable service:

```
TCP.SYN: 10.1.1.50:54321 → 192.168.1.100:9000
TCP.SYN-ACK: 192.168.1.100:9000 → 10.1.1.50:54321
TCP.ACK: 10.1.1.50:54321 → 192.168.1.100:9000
[Exploit payload data]
TCP.RST or TCP.FIN
```

**Artifacts on target:**

| Source | Event | Details |
|--------|-------|---------|
| **tcpdump / pcap** | TCP handshake + data | Source IP 10.1.1.50, port 54321 (ephemeral), binary protocol data, payload bytes. |
| **Firewall logs** | Connection allowed or blocked | If firewall auditing enabled, inbound connection event. |
| **netstat** (at time of attack) | Established socket | `ESTABLISHED` state from vulnerable process to 10.1.1.50. |
| **lsof** (at time of attack) | Open file descriptor | vulnerable_app PID shows socket to 10.1.1.50:54321. |
| **IDS/IPS logs** | Payload signatures | If IDS detects pwntools exploit pattern (unlikely for custom payloads). |

### Outbound Reverse Connection

If shellcode connects back to attacker:

```
vulnapp (PID 1234) initiates:
TCP.SYN: 192.168.1.100:random → 10.1.1.50:4444
TCP.SYN-ACK: 10.1.1.50:4444 → 192.168.1.100:random
TCP.ACK: 192.168.1.100:random → 10.1.1.50:4444
[Shell output/command data]
```

**Artifacts:**

| Source | Evidence | Details |
|--------|----------|---------|
| **pcap / tcpdump** | Outbound connection | Target IP initiates to attacker's listening port (e.g., 4444). |
| **Firewall/WAF logs** | Egress connection | If outbound filtering enabled, logged attempt. |
| **DNS logs** | DNS query (if shellcode does hostname resolution) | Query for attacker domain or IP reverse-lookup. |
| **Flow logs** (VPC/NSG) | Connection record | Source/destination IPs, ports, protocol, bytes transferred. |

---

## 5. Filesystem Artifacts

### Temporary Files Created by Exploit

If shellcode writes to filesystem:

```bash
/tmp/
├─ payload_cache_12345
├─ /tmp/shell.sh  (if exploit uses temp script)
└─ /var/tmp/cache (alternative temp location)
```

**Artifacts:**

| Source | Evidence | Details |
|--------|----------|---------|
| **File creation** | mtime = exploit execution time | Timestamp correlates with crash/process spawning. |
| **File permissions** | 0600 or 0755 | Reflects umask of exploited process (often world-writable if vuln process runs as root). |
| **File content** | Shell script, binary payload, config | Reveals post-exploitation commands. |
| **Inode analysis** | Allocation time | Sequential inode numbers indicate rapid file creation during exploit. |

### Executable Patching

If exploit modifies binary on disk:

```
Before: /usr/bin/vuln_binary (original, size 123456 bytes)
After:  /usr/bin/vuln_binary (modified, size 124000 bytes)
         └─ Modifications: injected ROP gadgets, changed entry point
```

**Artifacts:**

| Source | Evidence | Details |
|--------|----------|---------|
| **File hash** | Before/after MD5/SHA256 differ | Indicates on-disk modification. |
| **Binary diff** | hexdump -C binary.before binary.after | Show exact bytes changed (gadgets, entry point, relocations). |
| **ELF header** | Entry point (e_entry field) | Changed from 0x400000 to 0x401234 (attacker's code). |
| **File backup** | .bak, .orig files | Attacker may leave backup; cleanup oversight. |

### Log File Artifacts

Target application or system logs may record exploit:

```
/var/log/app.log:
  [2026-08-11 14:23:45] Input buffer overflow detected in process_input()
  [2026-08-11 14:23:46] Process terminated with signal 11

/var/log/auth.log:
  Aug 11 14:23:47 target kernel: [PID=1234] segfault at 4141414141414141 ...

/var/log/syslog:
  Aug 11 14:23:48 target kernel: ... memory.oom-control: permission denied
  Aug 11 14:23:49 target systemd: service crashed unexpectedly
```

---

## 6. Privilege-Escalation Artifacts

### Setuid Binary Exploitation

Exploit targets a setuid binary (e.g., `/usr/bin/sudo`, `/bin/mount`):

**Before:**
```
$ ls -l /usr/bin/sudo
-rwsr-xr-x 1 root root 149K sudo
$ whoami
user
```

**After Exploitation:**
```
$ whoami
root
$ id
uid=0(root) gid=0(root) groups=0(root)
```

**Evidence:**
- Shell spawned with EUID=0 (root).
- Unexpected privilege escalation in process tree.
- Possible `/etc/sudoers` modification (if post-exploitation).

### Stack Canary Bypass

If exploit bypasses stack canary:

```
Before canary check:
  rax (canary value) = 0x5a5a5a5a
  *rsp (expected) = 0x5a5a5a5a  ← Match, no crash

After overflow (with canary leaked and preserved):
  rax (canary value) = 0x5a5a5a5a
  *rsp (preserved value) = 0x5a5a5a5a  ← Match despite overflow
  rip = 0x401234 (attacker's address)  ← Now control flow is hijacked
```

**Evidence:**
- No crash (no signal 11), but unexpected code execution.
- Core dump absent (process doesn't crash, continues or calls system()).
- Log entries for shell spawning without preceding segfault.

---

## 7. Security Product Signatures

### Endpoint Detection and Response (EDR)

Antivirus/EDR suites detect common exploit patterns:

| Product | Signature/Behavior | Trigger |
|---------|---|---|
| **Windows Defender** | `Behavior:Win32/Shellcode.gen`, `Rootkit:HEUR!` | Injected code execution, ROP chain pattern. |
| **CrowdStrike Falcon** | Suspicious process spawning, ROP execution, shellcode execution | Call-stack anomaly, memory permission changes, shellcode heuristics. |
| **Splunk/Elastic (EDR)** | Process creation with unexpected parent, reverse shell behavior | Parent-child relationship ML model, network egress from unexpected process. |

### Kernel-Level Detection

- **SMEP/SMAP bypass** — Kernel patches detect Ring 3 (user) code executing Ring 0 (kernel) operations (on systems with SMEP enabled).
- **CFI (Control Flow Integrity)** — Detects ROP gadget chaining (if CFI is enabled on the binary).

---

## 8. Application Behavior Anomalies

### Unexpected System Calls

Vulnerable binary makes unexpected syscalls after overflow:

```
Normal execution:
  open("/data/file.txt", O_RDONLY)
  read(fd, buffer, 256)
  close(fd)

After ROP exploitation:
  open("/etc/shadow", O_RDONLY)  ← Unexpected file access
  execve("/bin/bash", [], 0)     ← Unexpected process spawn
  socket(AF_INET, SOCK_STREAM)   ← Unexpected network call
```

**Detection via:**
- **strace output** — Unusual syscall sequence post-crash.
- **AppArmor/SELinux logs** — Policy violations (accessing /etc/shadow without permission).
- **Seccomp violations** — If binary uses syscall filtering, shellcode attempt to make forbidden syscall.

### Return-Oriented Programming (ROP) Signature

ROP chains have characteristic instruction patterns:

```
Gadget 1: 0x401234 pop rdi; ret
Gadget 2: 0x402000 mov rsi, rax; pop rax; ret
Gadget 3: 0x403000 jmp [rax]
```

**Detection:**
- **Backward branch pattern** — Many ret instructions (0xc3) in unusual places.
- **Alignment anomalies** — Gadgets often split across aligned boundaries (detection bypassing technique, but also a signature).
- **Leaked register values** — If core dump captured, registers contain gadget addresses (e.g., rip=0x401234).

---

## 9. Memory-Mapped File and Address Space Evidence

### ASLR State at Exploit Time

Core dump captures memory layout:

```
ELF Header (core dump):
  NOTE segment (prstatus): pid=1234, signal=11, registers
  NOTE segment (psinfo): state=Z (zombie), uid=0
  LOAD segment: 0x400000-0x401000 (text, binary code)
  LOAD segment: 0x7fffffffde00-0x7ffffffff000 (stack)
  LOAD segment: 0x7f0000000000-0x7f0000100000 (libc at 0x7f00...)
```

**Analysis:**
- libc base address (7f0000000000) can be extracted.
- Correlate with known ASLR seed or entropy source.
- If crashed twice, compare layouts (should differ if ASLR working).

### Heap Layout

Heap vulnerability exploitation leaves heap metadata corruption:

```
Before: malloc_chunk { size=0x100, prev_size=0x50, ... }
After:  malloc_chunk { size=0x41414141, prev_size=0x42424242, ... } ← Corrupted by overflow
```

**Evidence in core dump:**
- Heap chunks with impossible sizes (0x41414141 = AAAA....).
- Forward/backward pointers point to attacker-controlled memory.
- Chunk list is broken (next chunk offset invalid).

---

## 10. Timeline Reconstruction

### Exploit Execution Timeline

```
2026-08-11 14:23:40  Target starts vulnerable service
2026-08-11 14:23:45  Attacker connects (TCP SYN observed on network)
2026-08-11 14:23:46  Attacker sends exploit payload
2026-08-11 14:23:46  Target process receives and processes payload
2026-08-11 14:23:46  Return address overwritten, ROP chain executed
2026-08-11 14:23:47  /bin/bash spawned (Process Event 1, Sysmon)
2026-08-11 14:23:47  Shell interactive session established
2026-08-11 14:23:50  Attacker runs commands (whoami, id, cat /etc/shadow, etc.)
2026-08-11 14:24:00  Attacker disconnects
2026-08-11 14:24:01  Vulnerable process terminates
```

**Correlation points:**
- Network packet timestamp (when payload sent) ↔ Process crash timestamp.
- Process spawning time ↔ Shell command execution time ↔ File access in logs.
- Reverse shell connection time ↔ SSH/network egress in firewall logs.

---

## 11. Summary: Target Evidence Priority

### High-Priority Artifacts (Direct Exploitation Evidence)

1. **Process crash/segfault** (signal 11, core dump) — Defines exploit moment.
2. **Unexpected process spawning** (Sysmon Event 1, auditd) — Direct evidence of code execution.
3. **Memory state** (core dump, /proc snapshots) — Exploited payload, ROP gadgets, leaked addresses.
4. **Network connection logs** — Attacker IP/port, timing, data flow.

### Medium-Priority Artifacts (Correlation and Context)

5. **Event logs** (auditd EXECVE, Windows Security Event 1) — Timeline and process details.
6. **File artifacts** (/tmp files, modified binaries) — Post-exploitation evidence.
7. **Firewall/IDS logs** — Connection details, policy violations.

### Low-Priority Artifacts (Confirmation)

8. **Application logs** — Verbose context; often missing or rotated.
9. **ASLR layout** (from core dump) — ASLR bypass confirmation; usually not actionable alone.
10. **Heap analysis** — Useful for heap-exploitation attribution; requires deep analysis.

