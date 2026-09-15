# pwntools — Overview

🔴 **Red Flag:** pwntools is a **library, not a standalone CLI tool** — operators write Python scripts importing it. Every use case here is a `.py` PoC embedding pwntools, meaning the Python process itself is the offensive artifact, alongside any subprocess activity (connection I/O, process spawning, memory dumps, binary patching) the script invokes. This shapes both the source evidence (script text, Python process execution, network sockets) and the hunting posture (script-source inspection, process telemetry on the operator host).

## History

**Author/Maintainer:** Gallopsled (GitHub organization), with core development driven by the Pwn2Win/DEF CON CTF community.

**Origin:** Created as a CTF (Capture The Flag) framework and exploit-development library, pwntools evolved to become the de facto standard for rapid binary-exploitation prototyping in the security research and pentesting communities. It abstracts away the low-level socket handling, binary parsing, and assembly work that would otherwise require hand-written code for each exploit.

**License:** MIT, hosted at https://github.com/Gallopsled/pwntools.

**Current Maintenance:** Actively maintained as of 2026, with Python 3.10+ support in recent releases. The project is best supported on 64-bit Ubuntu LTS (22.04, 24.04) but runs on most POSIX-like systems (Linux, BSD, macOS with limitations).

**Notable Versions:**
- **pwntools 3.x** — established the core tubes/ROP/shellcraft/elf API.
- **pwntools 4.x** — Python 3 migration, dropped Python 2 support.
- **pwntools 4.13+** — enhanced gdbserver and dynamic ELF manipulation support.

---

## How It Works

pwntools operates as an **exploit-development library**, structured around six core concepts:

### 1. Tubes: Communication Abstraction

The `pwnlib.tubes` module provides a **unified I/O abstraction** across different target-access methods:

- **`process()`** — Fork a local binary and communicate via stdin/stdout pipes.
- **`remote(host, port)`** — TCP socket to a remote service.
- **`ssh()`** — Remote command execution and port forwarding via SSH.
- **`listen(port)`** — Listen for an incoming connection (for reverse shells).
- **`serialtube()`** — Serial port communication (embedded systems, IoT).

Each returns a **tube object** with identical methods (`send()`, `recv()`, `sendline()`, `recvline()`, `interactive()`) regardless of the underlying protocol. This means a single exploit script works against a local binary, a remote service, or a service accessed over SSH with only the connection line changing.

**Protocol Handling:** Tubes automatically handle character encoding (bytes ↔ strings), line buffering, and timeouts. An operator can test an exploit locally against a vulnerable binary, then rotate a single parameter (`process("./vuln")` → `remote("10.0.0.1", 9000)`) to attack the live target.

### 2. Shellcraft: Payload Generation

`pwnlib.shellcraft` is a **database of shellcode templates**, organized by architecture (amd64, i386, arm, aarch64, mips, riscv64, loongarch64) and operating system (linux, freebsd, android).

Common payloads available as functions:
- **`sh()`** — Interactive shell.
- **`cat(filename)`** — Read file contents.
- **`write(fd, data, length)`** — Write to file descriptor.
- **`execve(binary, argv, envp)`** — Execute a program.
- **`connect(ip, port, sock)`** — Connect to a remote host.
- **`bindsh(port)`** — Listen for a reverse connection.
- **`socket()`, `listen()`, `accept()`** — Network primitives.

Usage:
```python
from pwnlib.shellcraft import amd64
shellcode = amd64.linux.sh()  # Returns raw bytes
```

These are **pre-written, optimized assembly snippets**, saving hours compared to hand-writing and testing assembly for each payload. Operators can chain snippets (e.g., `dup2()` then `execve()`) to build complex payloads.

### 3. ROP: Gadget Chaining

`pwnlib.rop` automates **Return-Oriented Programming** exploit construction, which chains existing code fragments (gadgets) to control program behavior without injecting executable code.

**Core Classes:**
- **`ROP(elf_object)`** — Analyzes a binary for gadgets and builds chains.
- **`Gadget`** — Represents a single ROP gadget (instruction sequence).

**Workflow:**
1. Load the binary: `elf = ELF("./target")`.
2. Initialize ROP scanner: `rop = ROP(elf)`.
3. Build the chain: `rop.call(elf.symbols['system'], ['/bin/sh'])`.
4. Extract bytes: `payload = rop.chain()`.

**Internals:** The library uses `capstone` (disassembler) to locate gadgets, caches results, and filters by bad-character constraints (e.g., avoiding null bytes). It understands calling conventions (amd64 System V ABI, 32-bit cdecl, ARM EABI) to automatically place arguments in correct registers.

### 4. ELF Parsing: Binary Analysis

`pwnlib.elf` provides **structured access to ELF binary metadata**:

```python
elf = ELF("./target")
elf.symbols['system']          # Function address
elf.got['libc.so.6.exit']      # GOT entry address
elf.plt['printf']              # PLT stub for printf
elf.search(b"flag{")           # Search binary for bytes
elf.checksec()                 # Security properties (ASLR, NX, canary, etc.)
```

The parser automatically handles:
- Symbol tables and relocation entries.
- Section and segment data.
- Security property queries (ASLR, NX, stack canaries, FORTIFY).
- DWARF debugging information (if present).

### 5. Assembly & Disassembly

`pwnlib.asm` and `pwnlib.disasm` wrap `keystone` (assembler) and `capstone` (disassembler):

```python
from pwnlib.asm import asm
from pwnlib.disasm import disasm

# Assemble x86-64 assembly to shellcode
code = asm("mov rax, 0x60; syscall")  # execve on Linux

# Disassemble raw bytes
disasm(b"\x48\xc7\xc0\x60\x00\x00\x00\x0f\x05")
```

### 6. GDB Integration

`pwnlib.gdb` automates debugger attachment during exploit development:

```python
gdb.attach(p)                    # Attach GDB to process `p`, open terminal
gdb.debug("./target", """
break main
continue
""")                              # Launch under GDB with script

# Programmatic inspection (requires gdb-python API)
gdb.execute("info registers")
```

This eliminates manual attach/detach cycles and enables breakpoint automation.

---

## Techniques & Protocols Used

| Concept | Description |
|---------|-------------|
| **Buffer Overflow** | Overwriting memory to redirect execution. |
| **Return-Oriented Programming (ROP)** | Chaining existing code gadgets to bypass NX/DEP. |
| **Format String Exploitation** | Leveraging `printf`-style functions for memory read/write. |
| **Shellcode Injection** | Injecting raw bytecode and jumping to it. |
| **ASLR Bypass** | Information leaks to defeat address randomization. |
| **Stack Canary Bypass** | Leaking or bypassing stack protection checks. |
| **Heap Exploitation** | Corrupting heap metadata for memory control. |
| **SROP (Sigreturn-Oriented Programming)** | Chaining syscalls via signal frames. |
| **Ret2dlresolve** | Exploiting lazy binding in dynamic linkers. |
| **Kerberos/LDAP** | Cloud/network attacks (via modules like `AADInternals` analogs). |

**Underlying Protocols:**
- **TCP/UDP** (via `remote()`, `listen()`).
- **SSH** (via `ssh()` module).
- **Named pipes** (local process communication).
- **System calls** (Linux syscall interface for shellcode).
- **ELF binary format** (reading/writing exploit payloads into binaries).

---

## Python API Reference — Key Functions

Unlike tools with CLI switches, pwntools is an **importable library**. Here are the primary entry points:

### Tubes (Communication)

| Function | Purpose |
|----------|---------|
| `process(binary, args, ...)`  | Fork and pipe to local binary. |
| `remote(host, port)` | TCP socket to remote host. |
| `ssh(host, user, password, ...)` | SSH connection and remote execution. |
| `listen(port)` | Listen for reverse connection. |
| `p.send(data)` | Write raw bytes. |
| `p.sendline(data)` | Write line (auto newline). |
| `p.recv(n)` | Read up to n bytes. |
| `p.recvline()` | Read until newline. |
| `p.recvuntil(delimiter)` | Read until delimiter found. |
| `p.interactive()` | Hand control to user (drop to shell). |
| `p.close()` | Close connection. |

### Shellcraft (Payload Generation)

| Syntax | Purpose |
|--------|---------|
| `shellcraft.amd64.linux.sh()` | x86-64 interactive shell. |
| `shellcraft.amd64.linux.cat("flag.txt")` | Cat a file. |
| `shellcraft.i386.linux.connect(ip, port)` | x86 connect-back payload. |
| `shellcraft.arm.linux.execve(...)` | ARM execute command. |

### ROP (Gadget Chaining)

| Function | Purpose |
|----------|---------|
| `ROP(elf_obj)` | Initialize ROP scanner. |
| `rop.call(func_addr, [args])` | Add function call to chain. |
| `rop.raw(bytes)` | Append raw bytes. |
| `rop.chain()` | Compile chain to bytes. |
| `rop.dump()` | Print chain as addresses. |

### ELF (Binary Analysis)

| Function | Purpose |
|----------|---------|
| `ELF(path)` | Load and parse ELF binary. |
| `elf.symbols['func']` | Get function address. |
| `elf.got['lib.func']` | Get GOT entry. |
| `elf.plt['func']` | Get PLT stub. |
| `elf.search(bytes)` | Search binary for bytes/strings. |
| `elf.checksec()` | Query security properties. |

### Assembly & Disassembly

| Function | Purpose |
|----------|---------|
| `asm("mov rax, 1; syscall")` | Assemble to bytecode. |
| `disasm(bytes)` | Disassemble to text. |

### GDB Integration

| Function | Purpose |
|----------|---------|
| `gdb.attach(process_obj)` | Attach debugger. |
| `gdb.debug(binary, script)` | Launch under GDB. |
| `gdb.corefile(process_obj)` | Dump core file. |

---

## Quick Use-Case List

1. **Socket Connection to Vulnerable Service** — Open a TCP connection to a listening vulnerable binary and send payloads interactively.
2. **Local Buffer Overflow with ROP Chain** — Overflow a local binary's stack, build a ROP chain to call `system("/bin/sh")`.
3. **Shellcode Generation and Injection** — Generate platform-specific shellcode (e.g., x86-64 `execve /bin/sh`), inject into buffer overflow, jump to it.
4. **ELF Binary Analysis for Exploit Development** — Parse target binary to find gadgets, function addresses, GOT entries, and security properties (ASLR, NX, canaries).
5. **Ret2libc Exploit** — Leak libc base address via information disclosure, calculate system() address, build ROP to call it.
6. **GDB-Assisted Debugging During Development** — Attach debugger to running exploit, set breakpoints, inspect memory/registers mid-exploitation.
7. **SSH-Based Remote Exploitation** — Use SSH tube to run exploit against a remote binary with `ssh.process()`.
8. **Format String Exploitation** — Craft format-string payloads to leak stack data or write to arbitrary memory.
9. **ASLR Bypass via Information Leak** — Extract a libc/RELRO address, calculate base, build gadget chains with calculated addresses.
10. **Stack Canary Leaking** — Design payload to leak the canary value, then craft overflow that preserves it.
11. **Heap Exploitation Scripting** — Craft heap-metadata corruption payloads to achieve UAF or overflow primitives.
12. **Chaining Exploits with Metasploit** — Use pwntools to generate/test payloads, integrate with Metasploit or standalone framework.

---

## Prerequisites by Use Case

| Use Case | Prerequisites |
|----------|---|
| All | Python 3.10+, pwntools installed (`pip install pwntools`). |
| Local binary testing | Vulnerable binary (source or compiled), understanding of the vulnerability. |
| Remote exploitation | Network access to target, vulnerability details (type, offset, etc.). |
| ROP chain building | Binary (with symbols or no ASLR), capstone/keystone libraries (auto-installed). |
| Shellcode generation | Target architecture known (amd64, i386, ARM, etc.), OS (Linux, FreeBSD, Android). |
| GDB debugging | GDB installed, local binary, gdbserver (for remote attach). |
| SSH exploitation | SSH credentials, sshpass or SSH key-based auth, remote binary access. |
| Format string | Vulnerable binary, understanding of format-string vulnerability layout. |
| Heap exploitation | Heap exploitation primitive (e.g., use-after-free, overflow), ptmalloc/malloc internals knowledge. |

---

## Cross-References

- **SEC660 (Advanced Penetration Testing, Exploit Writing & Ethical Hacking)** — Linux binary exploitation, ROP chains, shellcode generation align with SEC660's exploit-development curriculum.
- **Metasploit msfvenom/msfconsole** — pwntools and Metasploit serve similar roles; pwntools for fine-grained binary exploitation, Metasploit for orchestration.
- **GDB** — pwntools integrates with GDB; see `GDB` documentation for breakpoint/watch-point concepts.
- **Capstone/Keystone** — Underlying disassembler/assembler libraries (auto-installed with pwntools).
- **Linux Exploit Mechanics** — See `Linux/` module for kernel data structures, syscall interface, and memory-layout concepts.

