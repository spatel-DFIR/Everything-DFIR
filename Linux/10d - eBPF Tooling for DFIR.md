# eBPF Tooling for DFIR

eBPF lets you run sandboxed programs inside the kernel to observe syscalls, process execution, network activity, and file access in real time — which makes it both a powerful live-hunting instrument and, in the wrong hands, a stealthy rootkit technology. For DFIR this note has two faces: using eBPF tools (`bpftrace`, the bcc suite, Falco, Tracee) to watch a suspected-live host catch activity that never touches disk, and detecting *malicious* eBPF programs that an attacker loaded to hide or intercept.

> 🔴 eBPF sees fileless and in-memory activity that disk forensics can't — a `memfd`-executed payload, a short-lived process, a syscall an LKM would hide from `ps`. But the same power means an attacker's own eBPF program can hook and hide things too, so treat a loaded, unexplained eBPF program with the same suspicion as an unknown kernel module.

## Contents

- [Quick Triage](#quick-triage)
- [What to Check for What](#what-to-check-for-what)
- [What eBPF Gives You](#what-ebpf-gives-you)
- [bpftrace One-Liners](#bpftrace-one-liners)
- [The bcc Toolkit](#the-bcc-toolkit)
- [Seeing Inside Encrypted C2](#seeing-inside-encrypted-c2)
- [Falco and Tracee](#falco-and-tracee)
- [Detecting Malicious eBPF](#detecting-malicious-ebpf)
- [Deep Threat Hunts](#deep-threat-hunts)
- [Getting Max Value](#getting-max-value)
- [Correlate With](#correlate-with)
- [Scenarios](#scenarios)
- [Red Flags](#red-flags)

## Quick Triage

```bash
# Live process executions as they happen (catches short-lived processes)
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%d %s\n", pid, str(args->filename)); }'

# What eBPF programs are loaded right now (attacker eBPF hides here)
bpftool prog show

# bcc: live exec trace with args + parent
execsnoop-bpfcc

# bcc: outbound TCP connects with process
tcpconnect-bpfcc
```

## What to Check for What

*(live host + root + modern kernel only — not for dead images)*

| Investigative question | Tool |
|------------------------|------|
| Catch fileless / short-lived execution? | `execsnoop-bpfcc`; execve tracepoint; `memfd_create` trace |
| See argv of a `curl\|bash` one-liner? | `bpftrace … execve { join(args->argv) }` |
| Read **plaintext** of encrypted C2/exfil? | `sslsniff-bpfcc` (SSL_write uprobe) |
| Capture commands with history disabled? | `bashreadline-bpfcc`; `ttysnoop-bpfcc` |
| Attribute a connection to a process live? | `tcpconnect-bpfcc`; `tcpaccept-bpfcc` (listener) |
| Catch a live privesc? | `setuids-bpfcc`; `capable-bpfcc` |
| Is a **malicious** eBPF program loaded? | `bpftool prog show` + attribute + `prog dump` |
| eBPF persistence? | pinned objects under `/sys/fs/bpf/` |

## What eBPF Gives You

eBPF attaches to kernel hook points — tracepoints, kprobes, and more — to observe events with full context (PID, args, return values) at low overhead. For an active investigation that means you can watch the exact behaviors that leave no disk artifact.

| Capability | DFIR use |
|------------|----------|
| Syscall / execve tracing | Catch short-lived and fileless process execution |
| Network hooks | Attribute connections to processes as they open |
| File-open tracing | See what a suspect process reads/writes live |
| Uprobe on library calls | Observe decrypted data before it hits the network |

The requirement is a live host with a modern kernel (eBPF-capable) and root — this is a live-response technique, not something you run on a dead image.

## bpftrace One-Liners

`bpftrace` is the awk-like front end for ad-hoc eBPF — perfect for a targeted question on a live host.

```bash
# Every execve with pid + filename (see what's really running)
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf("%d %s\n", pid, str(args->filename)); }'

# Full argv of new processes (catches curl|bash and one-liners)
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv); }'

# Files being opened, with process name
bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'

# Outbound connections (who is calling home)
bpftrace -e 'kprobe:tcp_connect { printf("%s pid %d\n", comm, pid); }'

# memfd_create calls (fileless execution primitive)
bpftrace -e 'tracepoint:syscalls:sys_enter_memfd_create { printf("%s pid %d created memfd\n", comm, pid); }'
```

🔴 The `memfd_create` and full-argv traces are especially valuable — they catch fileless execution and pasted one-liners *as they happen*, which is often the only chance to see a payload that deletes itself immediately.

## The bcc Toolkit

The bcc suite ships dozens of ready-made tracing tools (on Debian/Ubuntu they're suffixed `-bpfcc`; on others just the tool name). These are pre-built for common DFIR questions.

```bash
# New process executions with args + parent
execsnoop-bpfcc

# Outbound TCP connections with process
tcpconnect-bpfcc

# TCP accepts (inbound - catches a bind shell / backdoor listener)
tcpaccept-bpfcc

# Files opened, live
opensnoop-bpfcc

# New files created
filelife-bpfcc

# Shell commands executed (bash uprobe)
bashreadline-bpfcc

# Keystrokes on a specific TTY (watch an attacker's live session)
ttysnoop-bpfcc /dev/pts/0

# Live privilege escalations
setuids-bpfcc

capable-bpfcc                 # capability checks (what a process is asking the kernel for)
```

🔴 `bashreadline-bpfcc` captures interactive shell commands even when history is disabled (it hooks the readline call directly), and `tcpaccept-bpfcc` surfaces a backdoor listener the moment it accepts a connection — both defeat common attacker evasions. `ttysnoop-bpfcc` lets you watch an attacker's interactive session keystroke-by-keystroke in real time.

## Seeing Inside Encrypted C2

🔴 The killer eBPF technique against encryption: hook the TLS library's `SSL_write`/`SSL_read` with a **uprobe** and read the **plaintext** *before* it's encrypted (or after it's decrypted). This is often the only way to see the content of an encrypted C2 or exfil channel from the host itself — no key, no MITM.

```bash
# bcc: dump plaintext passing through OpenSSL/GnuTLS/NSS
sslsniff-bpfcc

# bpftrace equivalent: uprobe on SSL_write to see outbound plaintext
bpftrace -e 'uprobe:/lib/x86_64-linux-gnu/libssl.so.3:SSL_write { printf("%s: %s\n", comm, str(arg1)); }'
```

The decrypted beacon/exfil content (commands, staged data, credentials) appears in the clear — a decisive artifact when the payload and traffic are otherwise opaque.

## Falco and Tracee

For continuous, rule-based detection rather than ad-hoc tracing, Falco and Tracee are eBPF-based engines with libraries of behavioral rules. In containers these are frequently the only record of an in-memory attack (see the Container Runtime Detection note); on hosts they alert on shell spawns, sensitive-file reads, privilege escalations, and escapes.

```bash
# Falco alerts (rule matches: shell in unexpected context, sensitive reads, etc.)
journalctl -u falco 2>/dev/null; cat /var/log/falco/falco.log 2>/dev/null

# Tracee: eBPF-based runtime tracing/detection
tracee --output json 2>/dev/null | head
```

## Detecting Malicious eBPF

eBPF is increasingly used *offensively* — to hide processes, intercept credentials, or backdoor a host at the kernel level without loading a traditional module. Enumerate what's loaded and look for what you can't explain.

```bash
# List all loaded eBPF programs
bpftool prog show

# List eBPF maps (data structures the programs use)
bpftool map show

# Which program is attached where (kprobes/tracepoints/XDP hooks)
bpftool link show

# Pinned eBPF objects on the bpf filesystem (persistence)
ls -laR /sys/fs/bpf/ 2>/dev/null
```

🔴 An eBPF program you can't attribute to a known monitoring tool (Falco, Tracee, your EDR, Cilium) is suspicious — malicious eBPF can hook `getdents` to hide files, tap `tcp_sendmsg` to steal data, or drop packets to hide C2. A **pinned** program under `/sys/fs/bpf/` is set up to persist. Cross-reference loaded programs against the monitoring stack you baselined in the Enterprise note.

```bash
# Disassemble a suspect program to see what it does (what it hooks = its purpose)
bpftool prog dump xlated id <ID>

# Is unprivileged BPF locked down? (should be 1 on a hardened host)
sysctl kernel.unprivileged_bpf_disabled 2>/dev/null
```

🔴 Known offensive-eBPF families (ebpfkit, TripleCross, boopkit) hook `getdents64` (hide files/PIDs), `tcp_*` (steal/hide traffic), or install an XDP program (packet-level backdoor). A program hooking those functions that you can't tie to a monitoring tool is an **eBPF rootkit**.

## Deep Threat Hunts

*(seasoned-DFIR; live host, root)*

```bash
# 1. Live exec + full argv (fileless/one-liners as they run)
bpftrace -e 'tracepoint:syscalls:sys_enter_execve { join(args->argv); }'

# 2. memfd_create (fileless primitive)
bpftrace -e 'tracepoint:syscalls:sys_enter_memfd_create { printf("%s %d\n", comm, pid); }'

# 3. Plaintext of encrypted C2/exfil (SSL_write)
sslsniff-bpfcc

# 4. Interactive commands + tty keystrokes even with history off
bashreadline-bpfcc

# 5. Live privesc + inbound listeners
setuids-bpfcc & tcpaccept-bpfcc

# 6. Enumerate + ATTRIBUTE loaded eBPF (attacker eBPF hides here)
bpftool prog show; bpftool link show; ls -laR /sys/fs/bpf/ 2>/dev/null

# 7. Disassemble the unexplained program
bpftool prog dump xlated id <ID>

# 8. Hardening posture
sysctl kernel.unprivileged_bpf_disabled 2>/dev/null
```

**Hunt ideas:**

- **`sslsniff` / an `SSL_write` uprobe reads the plaintext** of encrypted C2 and exfil before TLS — the one way to see inside encrypted traffic from the host itself.
- **`bashreadline` + `ttysnoop` capture what an attacker types** even with history disabled — they hook readline/tty directly.
- **Attribute every loaded eBPF program** to a known tool (Falco/Tracee/EDR/Cilium); the unexplained one is a possible eBPF rootkit.
- **Disassemble a suspect program** (`bpftool prog dump xlated`) — what it hooks (`getdents`=hide, `tcp_sendmsg`=steal) reveals its purpose.
- **A pinned program under `/sys/fs/bpf/`** is eBPF persistence — enumerate it.

## Getting Max Value

- **Live-only, root, modern kernel** — eBPF is a live-response instrument, not for dead images.
- **`sslsniff`/`SSL_write` uprobe is the plaintext window** into encrypted C2 and exfil.
- **Enumerate + attribute loaded eBPF, then disassemble** the one you can't explain.
- **Feed exec/connect traces into the timeline** while you watch a suspected-live host.
- **Pair with Falco/Tracee** for continuous rule-based detection instead of ad-hoc tracing.

## Correlate With

| To answer… | Pivot to |
|------------|----------|
| Fileless/deleted artifact recovery | **Live Response** (10), **Trash and Deleted** (08) |
| eBPF rootkit vs LKM rootkit | **Kernel Modules and LKM Rootkits** |
| The process behind a traced connect | **Live Response** (10), **Network and PCAP** (10c) |
| Container runtime detection (Falco/Tracee) | **Container → Runtime Detection and Logging** (C06) |
| Reverse a captured payload | **ELF and Malware Triage** (11b) |
| Is unprivileged BPF hardened? | **SELinux AppArmor and Kernel Hardening** (05) |

## Scenarios

- **Fileless catch:** `memfd_create` + `execve` traces catch a self-deleting payload as it runs.
- **Plaintext C2:** `sslsniff` reveals the decrypted beacon content before it's encrypted.
- **History-proof keystrokes:** `bashreadline`/`ttysnoop` captures commands with history off.
- **eBPF rootkit:** an unexplained loaded program hooking `getdents64` to hide files.
- **Live privesc:** `setuids`/`capable` catches the escalation as it happens.

## Red Flags

| Finding | Why it matters |
|---------|----------------|
| `memfd_create` from an unexpected process | Fileless execution in progress |
| `execve` of interpreters/downloaders you didn't expect | Live payload execution |
| `tcpaccept` showing an unexplained listener | Bind-shell / backdoor |
| Loaded eBPF program not tied to a known tool | Possible eBPF rootkit / interceptor |
| Pinned eBPF object under `/sys/fs/bpf/` | eBPF persistence |
| Shell commands captured that aren't in history | History evasion in use |
| Loaded program hooking `getdents`/`tcp_sendmsg`/XDP | eBPF rootkit (hide/steal/backdoor) |
| `kernel.unprivileged_bpf_disabled = 0` | Unprivileged BPF attack surface open |

## Resources

- bpftrace — https://github.com/bpftrace/bpftrace
- bcc tools — https://github.com/iovisor/bcc
- Falco — https://falco.org ; Tracee — https://github.com/aquasecurity/tracee
- `bpftool(8)` man page; offensive-eBPF research (ebpfkit, TripleCross)
- MITRE ATT&CK: T1014 (Rootkit), T1620 (Reflective Loading), T1040 (Network Sniffing), T1562.001 (Impair Defenses)
