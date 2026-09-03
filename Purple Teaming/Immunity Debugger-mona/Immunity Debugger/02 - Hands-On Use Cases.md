# Immunity Debugger — Hands-On Use Cases

## Launching and Attaching to a Vulnerable Binary

**Goal:** Start debugging a binary from scratch, set a breakpoint at the entry point, and observe the process state.

**MITRE ATT&CK:** Not directly applicable (this is a defensive reverse-engineering activity, but operators use the same techniques to understand their own payloads).

```bash
# From the command line:
C:\path\to\Debugger64.exe C:\path\to\vulnerable.exe
```

Once Immunity opens:
1. The target binary launches automatically and pauses at the entry point.
2. In the Immunity GUI, the CPU disassembly pane shows the current instruction (EIP).
3. The Register pane (upper right) displays EAX, EBX, ECX, EDX, ESP, EBP, ESI, EDI, EIP, EFLAGS.
4. Press F9 (or click the "Run" button) to execute until the next breakpoint or exception.

**Attaching to an Already-Running Process:**
```bash
C:\path\to\Debugger64.exe -p <PID>
```
Or via GUI: File → Attach → select process from the list.

---

## Setting Breakpoints and Inspecting Function Arguments

**Goal:** Pause execution at a specific function (e.g., `strcpy`) and inspect the arguments passed on the stack.

**MITRE ATT&CK:** T1082 (System Information Discovery, if analyzing code to understand system calls) or T1010 (Application Window Discovery).

```python
# In the Immunity PyCommand console, after pausing:

# Method 1: Set breakpoint at an address in the GUI
# Right-click the disassembly line where strcpy() is called
# Select "Breakpoint" → "Toggle Breakpoint"

# Method 2: Set breakpoint programmatically from PyCommand
bp("0x00401234")  # Breakpoint at address 0x00401234

# Once breakpoint is hit (execution pauses), inspect the stack:
read_memory(esp, 16)  # Read 16 bytes starting at ESP (stack pointer)

# Print argument values (caller's perspective):
# On x86 stdcall, first arg is at ESP+4, second at ESP+8, etc.
arg1_addr = read_memory(esp + 4, 4)  # Read pointer to first arg
arg2_addr = read_memory(esp + 8, 4)  # Read second arg

# Step into the function call (F7 or stepinto()):
stepinto()

# Step over the function call (F8 or stepover()):
stepover()
```

**Expected Behavior:**
- Breakpoint fires when `strcpy` is called.
- The stack pointer (ESP) points to the return address; ESP+4 points to the destination buffer address; ESP+8 points to the source string address.
- Stepping into reveals the function's prologue (typically `push ebp; mov ebp, esp`) and frame setup.

---

## Identifying Stack Corruption and Finding the EIP Offset

**Goal:** Crash a binary with a buffer overflow, identify the exact offset where you control the Instruction Pointer (EIP), and craft a payload.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) or T1534 (Internal Spearphishing) in an exploitation workflow.

```bash
# Step 1: Generate a crash with a unique pattern (using mona.py, covered in the mona.py section)
# For now, assume you've created a crash payload:

python -c "print('A'*500)" > crash.txt  # Naive crash with 500 A's

# Step 2: Replay the crash in Immunity Debugger
Debugger64.exe C:\vulnerable.exe

# (Feed crash.txt into the vulnerable program via your normal input method)
# The program crashes, and Immunity catches the exception.

# Step 3: Inspect EIP and the stack
# In the CPU disassembly, note the value of EIP after the crash.
# Example: EIP = 0x41414141 (0x41 is the ASCII code for 'A')
# This means you've overwritten EIP with 'A's, so you're "on the right track."

# Step 4: Use mona.py to find the exact offset (see mona.py section for detail)
# For now, manual method:
# In PyCommand, log the memory at ESP and surrounding area:

esp_value = read_memory(esp, 100)  # Read 100 bytes from stack
# Copy this output, use an online pattern-offset tool or mona.py's !mona pattern_offset

# Example: If mona tells you the offset is 264, craft a new payload:
# payload = "A"*264 + "BBBB" + ... (rest of payload)
```

**Expected Behavior:**
- First crash: EIP = 0x41414141 (generic 'A' overwrite).
- After using mona.py's pattern_offset: You learn that offset 264 is where EIP sits.
- Second crash: Payload = "A"*264 + struct.pack("<I", rop_gadget_address) + ... → EIP now contains the address of a ROP gadget you control.

---

## Step-By-Step Shellcode Validation

**Goal:** Inject shellcode into writable memory, set a breakpoint at the shellcode entry point, and step through the first few instructions to verify correct encoding.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution) in an exploit workflow; T1140 (Deobfuscation/Decode Files or Information) if analyzing encoded shellcode.

```python
# Assume you've already crashed the binary and reached the shellcode injection stage.
# After exploit payload is sent (or injected via memory), Immunity is paused.

# Step 1: Locate writable memory (e.g., heap, stack, or DLL .data section)
# In the Memory Map pane (View → Memory Map), look for sections marked with +W (writable)
# Example: 0x00420000-0x00430000 (Heap, Read/Write)

# Step 2: Write shellcode to that address using mona.py or manual write
shellcode_addr = 0x00420000
shellcode = b"\x90\x90\x90\x90"  # NOP sled for illustration
write_memory(shellcode_addr, shellcode)

# Step 3: Set a breakpoint at the shellcode entry and continue
bp(shellcode_addr)
run()  # Continue until shellcode is reached

# Step 4: Step through shellcode instruction-by-instruction
stepinto()  # Execute one instruction (should be NOP)
# Inspect registers/memory after each step to verify state
```

**Expected Behavior:**
- After stepping into the shellcode, EIP updates to the first instruction of the shellcode.
- Each `stepinto()` advances EIP by the instruction's length (e.g., NOP is 1 byte).
- If shellcode is corrupted (bad chars, truncation), you'll see unexpected instruction encodings (e.g., `xchg eax, eax` instead of your intended `mov eax, ...`).

---

## SEH Chain Inspection and Exploitation Setup

**Goal:** Inspect the Structured Exception Handling (SEH) chain, identify the SEH frame on the stack, and prepare to overwrite it with an attacker-controlled pointer.

**MITRE ATT&CK:** T1055 (Process Injection) or T1183 (Image Trusted Execution) in an SEH-chain abuse exploitation workflow.

```python
# Immunity Debugger paused at a breakpoint (e.g., mid-execution of vulnerable code)

# Step 1: Locate the SEH chain on the stack (x86 convention)
# The first SEH frame is typically at FS:[0], which points to TEB.ExceptionList
# Read the TEB:

# On x86 (32-bit), FS:[0] contains a pointer to the first SEH frame
# Immunity's View → Stack pane shows the raw stack memory
# Manually inspect: the SEH chain consists of linked records:
#   [DWORD: next_SEH_frame] [DWORD: SEH_handler_address]

# Step 2: Use mona.py to analyze the SEH chain (easier)
# In PyCommand: !mona seh
# mona will print all SEH frames currently active

# Step 3: Manually inspect a specific SEH frame
# Example: If the first SEH frame is at 0x0012FE00:
seh_frame = read_memory(0x0012FE00, 8)
# First 4 bytes: pointer to next SEH frame
# Next 4 bytes: pointer to the SEH handler function

# Step 4: Verify the SEH handler's address
# If the handler is at a fixed address (e.g., `ntdll!KiUserExceptionDispatcher`),
# you can overwrite it with a "POP POP RET" gadget for SEH-chain bypass exploitation

# Example: Overwrite the SEH handler with a gadget address
gadget_addr = 0x7E123456  # A "POP POP RET" gadget from ntdll.dll
write_memory(0x0012FE04, struct.pack("<I", gadget_addr))  # Overwrite handler

# Step 5: Trigger the exception to test the exploit
# Continue execution and force an exception (e.g., NULL dereference):
run()
# Once exception fires, the SEH handler will be called at your gadget address
```

**Expected Behavior:**
- Before exploitation: SEH chain shows legitimate handlers from the application and Windows DLLs.
- After overwriting: The SEH frame's handler field points to your ROP gadget.
- When an exception occurs: The OS dispatches to your gadget instead of the original handler, giving you code execution control.

---

## Analyzing a Minidump for Crash Triage

**Goal:** Load a Windows minidump (.dmp file) from a crashed application, inspect the exception context, and use mona.py to auto-classify the crash type.

**MITRE ATT&CK:** T1055 (Process Injection) or T1622 (Debugger Evasion) if analyzing a crash caused by protective mechanisms.

```bash
# From the Immunity GUI, open a crash dump:
# File → Open Crash Dump (select .dmp file)

# Immunity loads the dump and pauses at the exception address
# The CPU disassembly shows the faulting instruction
# The Registers pane shows the exception context (EAX, EBX, etc. at crash time)
```

```python
# In PyCommand, run mona.py's analyze command:
!mona analyze

# mona will output:
# - Crash Type: Stack Overflow / Heap Corruption / NULL Dereference / etc.
# - Faulting Instruction: The opcode that caused the exception
# - Register State: Controlled/Uncontrolled values
# - Exploitability Assessment: "Probably Exploitable" / "Probably Not Exploitable" / etc.

# Example output:
# [*] Crash Type: Stack Overflow
# [*] Controlled Bytes: EBP = 0x41414141 (fully controlled)
# [*] EIP = 0x42424242 (fully controlled)
# [*] Exploitability: Probably Exploitable
```

**Expected Behavior:**
- mona's analyze output tells you whether the crash is exploitable and which registers you control.
- A "Probably Exploitable" crash with EIP controlled means you can redirect execution; stack overflow confirms you can stage ROP chains.

---

## ASLR Verification and Module Base Discovery

**Goal:** Determine if ASLR is enabled, identify the actual base addresses of modules (DLLs) loaded, and verify an info-leak or ASLR-bypass technique.

**MITRE ATT&CK:** T1578 (ASLR Bypass) techniques verification.

```python
# In Immunity Debugger, inspect the module base addresses:

# Method 1: GUI
# View → Executable Modules (or press Ctrl+E in some versions)
# This pane lists all loaded DLLs and their current base addresses

# Example output:
# ntdll.dll         0x7FFC0000
# kernel32.dll      0x7FFA0000
# msvcrt.dll        0x7FF70000
# custom.dll        0x04000000

# Method 2: PyCommand
# Immunity's scripting can enumerate modules:
# (Note: this is pseudocode; actual API depends on Immunity's Python bindings)

# Step 1: Run the binary multiple times and observe base addresses
# Close the debugger (or detach from process)
# Relaunch: Debugger64.exe vulnerable.exe
# Check View → Executable Modules again
# Repeat 3-4 times

# Step 2: Compare addresses
# If base addresses are identical across runs → ASLR is likely OFF (or disabled for that process)
# If base addresses change randomly → ASLR is ON

# Step 3: Verify ASLR-bypass technique
# If using heap spray (Windows 7-10): spray 0x0c0c0c0c addresses, then trigger a dereference
# Breakpoint at the dereference, inspect memory: verify your sprayed payload is at the predicted address
bp("0x00401234")  # Breakpoint at dereference instruction
run()
# After breakpoint hits, check if register (e.g., EAX) now points to your sprayed heap object

# Step 4: Info-leak verification
# If your exploit includes an info-leak (e.g., reading a pointer from memory):
# After the leak is triggered, inspect the leaked value in PyCommand:
leaked_addr = read_memory(leak_addr, 4)
# Verify it matches a known module base (e.g., leaked_addr == ntdll.dll base)
```

**Expected Behavior:**
- ASLR OFF: Module base addresses remain constant across runs.
- ASLR ON: Module base addresses change.
- Heap spray exploit: After spray, predicted addresses contain your payload.
- Info-leak exploit: Leaked pointer matches a known module or heap object.

---

## Live Memory Patching for Exploit Development

**Goal:** Pause at a crash point, patch the binary's code or data in memory (without rebuilding), and resume to test the fix.

**MITRE ATT&CK:** T1211 (Exploitation for Privilege Escalation) if developing a PoC exploit.

```python
# Immunity Debugger is paused at a breakpoint or exception

# Step 1: Locate the instruction or data to patch
# In the CPU disassembly, find the problematic instruction
# Example: You want to replace `jne 0x00401234` with `jmp 0x00401234` (remove the condition)

# The original instruction at 0x00401100 is: "jne short 0x00401234"
# You want to write: "jmp short 0x00401234"

# Find the opcode difference:
# jne short: 0x75
# jmp short: 0xEB

# Step 2: Write the patched bytes to memory
write_memory(0x00401100, b"\xEB")  # Replace 0x75 with 0xEB

# Step 3: Step/run to test the patch
stepinto()  # Execute the patched instruction
# or
run()  # Continue execution with the patch active

# Step 4: Verify the patch worked
# If the patched instruction was "jmp", execution should jump to the target
# If the original was a conditional branch, the jump should now be unconditional
```

**Expected Behavior:**
- After patching and continuing, the binary executes with the new instruction.
- If patch is correct, the exploit workflow (e.g., reaching the shellcode) proceeds as intended.
- If patch is incorrect, a new crash may occur (helping you refine the fix).

---

## Chained Workflow: Fuzzing + Crash Analysis + Exploit Development

**Goal:** Use an external fuzzer to generate crashes, import the crash context into Immunity + mona.py, and develop an exploit based on the analysis.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution).

```bash
# Step 1: Fuzz the target binary to find a crash
# (Using a tool like AFL, libFuzzer, or custom Python fuzzer)
# Assume fuzzer generates a crash input: crash_input.bin

# Step 2: Replay the crash in Immunity Debugger
Debugger64.exe vulnerable.exe < crash_input.bin

# (If the binary is a service or network app, pipe the input via your normal attack vector)

# Step 3: Once crashed, open the crash dump
# Immunity catches the exception
# File → Save Crash Dump (save as crash.dmp)

# Step 4: Analyze with mona.py
# In PyCommand:
!mona analyze
# mona outputs crash type, controlled registers, exploitability assessment

# Step 5: If exploitable, craft the payload
# Use mona.py's pattern create/offset tools (see mona.py section)
# Iterate: create pattern → crash → find offset → refine payload

# Step 6: Verify the exploit payload
# Write the payload to a file: exploit.bin
# Replay in Immunity: Debugger64.exe vulnerable.exe < exploit.bin
# Set breakpoint at shellcode address, continue, verify shellcode is reached

# Step 7: Test on live target (outside the debugger)
# Run the exploit against the live vulnerable service
# Verify code execution on the target
```

**Expected Behavior:**
- Fuzzer generates diverse crash inputs, Immunity catches them.
- mona's analysis identifies exploitable crashes (EIP controlled, stack corruption, etc.).
- Payload refinement: each iteration moves closer to reliable code execution.
- Final payload works both in the debugger and on the live target.

---

## Badchar Identification Using mona.py

**Goal:** Identify bytes that are filtered or corrupted during payload transmission, ensuring the final exploit shellcode avoids them.

**MITRE ATT&CK:** T1203 (Exploitation for Client Execution), specifically the preparation phase of exploit development.

```python
# Assume you're at the point where you can control the stack and inject data,
# but suspect certain bytes are being stripped (e.g., null bytes, newlines, etc.)

# Step 1: Generate a bytearray with all possible byte values using mona.py
!mona bytearray -b "\x00"  # Create an array without null bytes
# mona outputs a Python list of hex bytes: ['\x01', '\x02', ..., '\xff']

# Step 2: Inject the bytearray into the vulnerable buffer
# The payload is a large buffer containing all byte values
# Send it to the target, trigger the vulnerability

# Step 3: Inspect the received/corrupted data
# Use a memory access tool or crash dump to read what made it through
# Compare the received data to the original bytearray

# Step 4: Use mona.py to find badchars
!mona badchars -b "\x00\x0A"  # Mark 0x00 (null) and 0x0A (newline) as badchars
# mona outputs: "Badchars: 0x00 0x0A"
# (This is simplified; real mona.py analysis is more sophisticated)

# Step 5: Regenerate shellcode without badchars
# Use msfvenom or a similar tool with the badchar list:
msfvenom -p windows/exec CMD=calc.exe -b "\x00\x0A" -f python
# msfvenom generates shellcode that avoids 0x00 and 0x0A

# Step 6: Verify the new shellcode
# Inject the cleaned shellcode, verify it reaches the target without corruption
```

**Expected Behavior:**
- Initial bytearray contains all bytes; after transmission, some bytes are missing.
- mona identifies which bytes were stripped.
- Regenerated shellcode avoids badchars and survives transmission intact.

