# WinDbg — Hands-On Use Cases

## Opening and analyzing a crash dump

**MITRE ATT&CK:** T1005 (Data from Local System) / Passive analysis  
**Scenario:** A Windows service crashes with a STOP code or memory access violation. The system generates a kernel memory dump or the operator uses ProcDump to capture a user-mode dump. WinDbg is used to analyze what went wrong.

### Live kernel crash dump analysis

```
# On a target that has crashed and generated a kernel dump (or test via offline dump)
C:\> windbg -dump C:\Windows\Minidump\Latest.dmp
# or
C:\> windbg.exe -dump "C:\Users\Attacker\Documents\MEMORY.DMP"

# Inside the debugger:
0:000> !analyze -v
# Output: detailed analysis of the crash (faulting address, exception code, etc.)

0:000> !bugcheck
# Output: STOP code details

0:000> kv
# Output: kernel-mode stack backtrace showing call path to the crash
```

### User-mode process dump analysis

```
# Analyze a user-mode crash dump (e.g., from a vulnerable application)
C:\> windbg -dump "C:\Dumps\notepad.0x1234.dmp"

0:000> !analyze -v
# Example output (simplified):
# FAULTING_IP: notepad!main+0x123
# EXCEPTION_RECORD: c0000374 - Heap corruption
# FAULT_ADDRESS: 0x00abcdef
```

---

## Recording process execution with Time Travel Debugging (TTD)

**MITRE ATT&CK:** T1005 (Data from Local System), T1113 (Screen Capture)  
**Scenario:** An attacker is testing a payload (shellcode, exploit, privilege escalation) and wants to record every instruction and memory access to replay later offline, stepping through the exploit logic, inspecting register state, and analyzing failure points.

### Record from process launch

```
# Start WinDbg with TTD recording enabled
C:\> windbg -record -pn cmd.exe
# or launch a new process directly:
C:\> windbg -record C:\Temp\malware.exe

# Inside WinDbg (UI):
# File → Record and Diagnose → Record Target
# or use the Recorder tab

# Run the target process (manually navigate, trigger exploit, etc.)

# When done, press Ctrl+Break in the debugger or use menu → Stop Recording

# Output: .run and .idx files written to default location
#         (typically C:\Users\<User>\Documents\)
```

### Replay and search a TTD trace

```
# Load a previously recorded trace
C:\> windbg -replay "C:\Users\Attacker\Documents\malware.run"

# Inside the debugger (Replay tab active)
0:000> !tt.index
# Output: Successfully created index (if not already present)

# Seek to a specific position in the trace
0:000> !tt.position
# Output: Position: current timeline position and percentage

# Go to the end of the trace
0:000> g
# (execution proceeds to the end, or to the next breakpoint)

# Rewind to a specific point (backward/forward navigation)
0:000> p     # step backwards through one instruction
0:000> pc    # step backward to previous call instruction

# Set a breakpoint that triggers in the replay
0:000> bp breakpoint_address
0:000> g     # execution fast-forwards to breakpoint, can be replayed multiple times

# Search for a specific memory write using debugger object model (dx)
0:000> dx @$curprocess.TTD.Memory(0xabcdef00, 0xabcdef04, 1).Where(m => m.Address == 0xabcdef00)
# Output: list of memory accesses to the specified address range
```

### TTD + shellcode analysis example

Scenario: Testing a ROP-chain-based privilege escalation. Record the process from launch through token-duplication exploit.

```
# Record the target service with TTD
C:\> windbg -record notepad.exe

# Navigate to trigger the exploit in the test app
# (e.g., click a button that runs shellcode or local-privesc payload)

# Ctrl+Break to stop recording

# Later, replay the trace
C:\> windbg -replay "C:\Users\Attacker\Documents\notepad.run"

# Inside replay, find the exact instruction where a token handle is duplicated
0:000> u kernel32!DuplicateTokenEx
# (disassemble the function)

0:000> bp kernel32!DuplicateTokenEx
0:000> g
# (jump to the breakpoint)

# Step through the token operation
0:000> p
0:000> p
0:000> p
# Inspect register state after the call
0:000> r
# Output: register values at this point in execution

# View local variables or stack frame
0:000> dv
# Output: local variables and their values

# Inspect the duplicated token handle
0:000> ? eax
# (if eax holds the token handle after DuplicateTokenEx)
```

---

## Live user-mode process debugging

**MITRE ATT&CK:** T1005 (Data from Local System)  
**Scenario:** An attacker wants to debug a Windows service or GUI application live, halting execution at breakpoints, inspecting memory, and modifying register state to test exploit behavior.

### Attach to a running process

```
# List running processes and find the target PID
C:\> tasklist | findstr notepad
# notepad.exe   4052

# Attach WinDbg to the process
C:\> windbg -p 4052
# (or attach via UI: File → Attach to Process)

# Inside the debugger, the process is halted at the first breakpoint
# (or running, depending on -a flag)

# Set a breakpoint at a function
0:000> bp ntdll!RtlAllocateHeap
0:000> g
# (process resumes; breaks when RtlAllocateHeap is called)

# Inspect the call stack
0:000> k
# Output: return addresses showing the call path to this function

# View parameters (on x64, first 4 integer params in rcx, rdx, r8, r9)
0:000> r rcx
# (inspect first parameter)

# Step through the function
0:000> t
# (trace into, executing one instruction)

0:000> p
# (step over a call)

# Continue until next breakpoint or exception
0:000> g
```

### Conditional breakpoint (break on heap corruption)

Scenario: A heap corruption bug corrupts a specific memory location. Set a breakpoint that fires when that location is written.

```
# Set a data breakpoint (access breakpoint) on a memory address
0:000> ba w 4 0x12345678
# (break on Write, 4-byte access, at address 0x12345678)

0:000> ba r 4 0x12345678
# (break on Read)

0:000> bl
# (list all breakpoints)

0:000> g
# (run until the breakpoint is hit)

# When the breakpoint triggers, inspect the register state
0:000> r
# Output: register values at the moment of the memory access

# Inspect the value that was written
0:000> dd 0x12345678
# (display 4-byte values starting at that address)
```

---

## Managed code (.NET) crash analysis

**MITRE ATT&CK:** T1005 (Data from Local System)  
**Scenario:** A .NET application crashes or hangs. The attacker wants to analyze the managed heap, view the exception details, and inspect .NET threads.

### Debug a .NET crash dump with SOS

```
# Open a .NET application crash dump
C:\> windbg -dump "C:\Dumps\DotNetApp.dmp"

# Load the SOS extension for managed code debugging
0:000> .load sos.dll

# Verify SOS loaded
0:000> .chain
# (output shows sos.dll in the extension chain)

# Display the last exception
0:000> !sos.PrintException
# Output: exception type, message, stack trace (managed)

# Show all managed threads
0:000> !sos.Threads
# Output: list of managed thread objects and their states

# Dump the managed heap to find suspicious objects
0:000> !sos.DumpHeap
# (large output; grep for specific types or use size filters)

0:000> !sos.DumpHeap -mt 0x<MethodTableAddress>
# (dump objects of a specific type)

# Get the GC root(s) keeping an object alive
0:000> !sos.GCRoot 0x<ObjectAddress>
# Output: chain of references keeping the object allocated
```

### Attach to a live .NET process

```
# Attach to a running .NET application
C:\> windbg -p 1234
# (or use UI: File → Attach to Process)

# Once attached and paused:
0:000> .load sos.dll

# Break into the .NET code
0:000> sxe CLRN
# (set exception handling for CLR Notification)

0:000> g
# (wait for CLR to initialize)

# Now use SOS commands
0:000> !sos.Threads
0:000> !sos.DumpHeap
0:000> !sos.PrintException
```

---

## Kernel-mode driver debugging

**MITRE ATT&CK:** T1547 (Boot or Logon Initialization), T1014 (Rootkit)  
**Scenario:** Testing a kernel-mode driver (e.g., a rootkit driver for stealth or capability) or analyzing a kernel crash. Requires kernel debugging setup (serial port, USB, or network connection between two machines).

### Setup kernel debugging (serial connection, target machine)

```
# On the TARGET machine (the one being debugged), enable kernel debugging:
# (requires admin and reboot)

C:\> bcdedit /debug on
C:\> bcdedit /dbgsettings serial debugport:1 baudrate:115200

# Restart the target machine; it will wait for a kernel debugger to connect
```

### Connect from the HOST (debugging machine)

```
# On the HOST (the debugger machine):
C:\> windbg -k com:port=COM1,baud=115200
# (if using serial; COM1 or COM2 depending on hardware)

# or for USB:
C:\> windbg -k usb:targetname=<name>
# (where <name> is from bcdedit /dbgsettings usb target=<name>)

# Inside WinDbg (host), you're now connected to the target kernel
0:kd> g
# (kernel resumes execution)

# Set a breakpoint on a kernel function
0:kd> bp ntdll!NtCreateFile
0:kd> g

# Inspect kernel state
0:kd> r
# (kernel registers)

0:kd> !process 0 0
# (list all processes)

0:kd> dps <address>
# (dump memory as pointer-size values + symbols)
```

---

## Shellcode development and testing

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information)  
**Scenario:** Developing and testing ROP gadgets, heap-spray payloads, or function-hooking shellcode. Use WinDbg to trace execution step-by-step, verify register/stack state, and validate payload behavior.

### Record shellcode execution with TTD

```
# Create a test harness (C program that invokes shellcode)
C:\> windbg -record shellcode_test.exe

# In the WinDbg UI:
# File → Record and Diagnose → Record Target

# Let the test harness run (triggering the shellcode)
# Observe: does it crash, hang, or complete?

# Stop recording: Ctrl+Break or menu → Stop Recording

# Replay the trace
C:\> windbg -replay shellcode_test.run

# Inspect exact execution flow
0:000> u rip
# (disassemble at the current instruction pointer)

# Step through shellcode instruction-by-instruction
0:000> p
0:000> p
0:000> p

# Check register state after each step
0:000> r rax
0:000> r rsp
0:000> r
# (all registers)

# Inspect stack and heap memory where the shellcode operates
0:000> dps rsp L10
# (dump 10 pointer-size values on the stack)

0:000> dd 0x<heapaddr> L20
# (dump 20 double-word values from heap)
```

---

## Exploit development: heap-spray and data-corruption analysis

**MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)  
**Scenario:** Testing a heap-spray exploit that overwrites a pointer or object metadata. Use WinDbg to inspect heap state before/after the spray, verify the corruption, and confirm exploit success.

### Analyze heap layout with TTD

```
# Record the heap-spray exploit
C:\> windbg -record exploit_test.exe

# Replay the trace
C:\> windbg -replay exploit_test.run

# Inspect heap before the spray
# (seek to the beginning of the trace)
0:000> !tt.position
# Output: position 0% of trace

# Find the heap allocation function
0:000> bp ntdll!RtlAllocateHeap
0:000> g
# (break at first allocation)

# Inspect the allocated memory
0:000> r rcx
# (first parameter, typically the heap handle)

# Dump the heap
0:000> !heap -h 0x<heaphandle>
# (if available in the version)

0:000> dd <allocated_address> L20
# (dump memory at the allocated address)

# Record the original pointer value
# (note the address and contents)

# Now seek forward in the trace to AFTER the heap spray
# (use !tt.position to track position percentage)
0:000> g
# (execution continues)

# Check if the pointer was overwritten
0:000> dd <allocated_address>
# (compare with the earlier value)

# If overwritten: exploit worked! Verify the new value points to attacker-controlled memory
0:000> ??<new_pointer_value>
# (evaluate the new value)

0:000> du <new_pointer_value>
# (if it's a Unicode string or known structure, inspect it)
```

---

## Remote debugging (multi-machine)

**MITRE ATT&CK:** T1570 (Lateral Tool Transfer)  
**Scenario:** An attacker is debugging a process on a remote machine over a network (e.g., attacking a cloud VM, testing code on a target server). WinDbg supports remote debugging via named pipes or TCP.

### Start a remote debugging server (on target machine)

```
# On the TARGET machine (the process to debug)
C:\> windbg -server tcp:Port=5005 -pn vulnerable_app.exe
# (starts a debugging server on TCP port 5005, attaches to vulnerable_app.exe)

# Or start WinDbg first, then enable server mode:
0:000> .server tcp:Port=5005
# Output: Debugging server started on port 5005
```

### Connect from remote debugging client (on attacker machine)

```
# On the ATTACKER machine (the debugger client)
C:\> windbg -remote tcp:Port=5005,Server=<target-ip>
# (example: tcp:Port=5005,Server=192.168.1.100)

# Inside the remote WinDbg session:
0:000> g
# (execution resumes on the target)

0:000> bp function_address
0:000> g
# (sets breakpoint, target breaks)

# All standard commands work (memory inspection, stepping, etc.)
```

**Note:** Remote debugging is typically not used in red-team payloads (it requires WinDbg listening on a network port, which is noisy). More commonly, attackers record with TTD locally and exfiltrate the trace files.

---

## Comparing before/after patches (binary diffing)

**MITRE ATT&CK:** T1526 (Gather Victim Information)  
**Scenario:** A vulnerability was patched. The attacker wants to understand what changed. Record execution on both the vulnerable and patched binaries, load both traces, and compare register/memory state at the vulnerable address.

### Record vulnerable version

```
C:\> windbg -record vulnerable_app.exe
# (trigger the vulnerability)
# Ctrl+Break to stop

# Traces saved as vulnerable_app.run and .idx
```

### Record patched version

```
C:\> windbg -record patched_app.exe
# (attempt to trigger the same vulnerability; it should fail or behave differently)
# Ctrl+Break to stop

# Traces saved as patched_app.run and .idx
```

### Compare traces

```
# Replay vulnerable trace
C:\> windbg -replay vulnerable_app.run

# Find the vulnerable code
0:000> bp <vulnerable_instruction_address>
0:000> g

# Note register state
0:000> r
# (record the registers)

0:000> dps <memory_location> L10
# (record memory state)

# In a separate terminal, replay patched trace
C:\> windbg -replay patched_app.run

# Jump to the same location
0:000> bp <same_address>
0:000> g

# Compare register and memory state
0:000> r
# (different? the patch may modify register flow)

0:000> dps <same_memory_location> L10
# (is the memory protected or zeroed? the patch may add initialization)
```

