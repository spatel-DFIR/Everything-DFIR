# mona.py — Target Evidence

mona.py is a **source-machine tool only** — it runs on the attacker's workstation as a plugin to Immunity Debugger. Like Immunity Debugger itself, mona.py leaves **no trace on the target system** after exploitation. All evidence on the target is from the **exploit payload** that was developed/crafted with mona.py's help.

## What Appears on the Target

The target's evidence depends entirely on **what mona.py was used to create** (ROP chain, badchar-clean shellcode, etc.), not on mona.py itself.

### Scenario 1: Stack Overflow with mona.py-Generated ROP Chain

**Attacker's Workflow:**
1. Run `!mona pattern_create` → generate crash pattern (source only).
2. Crash app, run `!mona analyze` → identify exploitability (source only).
3. Run `!mona rop --chain "VirtualAlloc"` → generate ROP chain (source only, saved to mona_chain.py).
4. Embed mona-generated chain into exploit binary.
5. Deploy exploit on target.

**Target Evidence (from the exploit, not from mona.py):**

#### Crash Artifacts

- **Exception Code:** `0xC0000005` (ACCESS_VIOLATION) if ROP chain fails; if successful, no crash (code execution succeeds).
- **Crash Dump:** If application crashes during exploitation:
  - Stack frame shows ROP gadget addresses (the actual chain addresses, sourced from the target's own modules).
  - Memory corruption signature consistent with stack overflow (overwritten return address, SEH frame overwrite if applicable).

#### Process Creation (Post-Exploitation)

- **Sysmon Event ID 1:** Shellcode spawns `cmd.exe`, reverse shell, or second-stage payload.
  - Parent: The vulnerable application.
  - Child: Attacker's chosen payload.

#### Memory & Register State

- If crash dump is captured, memory shows:
  - Corrupted stack with ROP gadget addresses (pointer to `kernel32.VirtualAlloc`, stack pivoting gadgets, etc.).
  - Heap or writable region containing shellcode (if ROP chain successfully allocated/copied it).

### Scenario 2: Badchar-Clean Shellcode (via mona.py)

**Attacker's Workflow:**
1. Run `!mona bytearray -b "\x00\x0A"` → generate bytearray excluding null bytes and newlines (source only).
2. Run `!mona badchars -b "\x00\x0A"` → identify corrupted bytes (source only).
3. Regenerate shellcode with `msfvenom -b "\x00\x0A"` using mona's findings.
4. Deploy badchar-free shellcode on target.

**Target Evidence (from shellcode, not from mona.py):**

#### No mona-Specific Signature on Target

- The target has no way to know the shellcode was validated with mona.py.
- Shellcode bytes themselves are the only evidence; they're identical whether developed with mona.py or another tool.

#### Shellcode Execution Evidence

- **Behavior:** Shellcode opens reverse shell, establishes C2 connection, spawns processes — all standard post-exploitation signs.
- **No mona Marker:** The shellcode contains no metadata indicating mona.py was used to craft it.

### Scenario 3: SEH Chain Exploitation (via mona.py)

**Attacker's Workflow:**
1. Run `!mona seh` → list SEH frames (source only).
2. Run `!mona seh -m "ntdll"` → find pop/pop/ret gadgets (source only).
3. Craft SEH-override payload using gadget addresses.
4. Deploy on target.

**Target Evidence (from SEH overflow, not from mona.py):**

#### SEH Chain Corruption

- **Registry/Memory:** SEH frame pointer overwritten with pop/pop/ret gadget address.
- **Event Log:** If exception occurs during exploitation (before SEH override takes effect):
  - Windows Security Event ID 4689 (process termination).
  - Sysmon Event ID 5 (process terminated with exception code).

#### Code Execution

- **Gadget Execution:** pop/pop/ret gadget executes, then jumps to shellcode.
- **Evidence:** Same as shellcode execution (child process creation, network beacons, etc.).

---

## Event Logs & Monitoring

### Process Execution Events

**Sysmon Event ID 1 (Process Creation):**
- **Parent:** Vulnerable application.
- **Child:** cmd.exe, powershell.exe, or attacker's payload.
- **Signal:** Unexpected process spawning from a known vulnerable app is suspicious, regardless of whether it was mona-developed.

### Crash Events

**Windows Event ID 1001 (Application Crash) or Sysmon Event ID 5 (Process Terminated):**
- **Faulting Process:** Vulnerable application.
- **Exception Code:** Varies (0xC0000005, 0xC0000374, depending on exploit type).
- **No mona-Specific Code:** Exception codes are generic; mona.py has no bearing on them.

### Heap/Stack Corruption Indicators

**EDR Behavioral Alert Examples (EDR sees the effects, not mona.py):**
- "Stack buffer overflow detected"
- "Heap corruption attempt blocked"
- "Suspicious ROP gadget execution"

---

## Memory Forensics (Post-Exploitation)

### Crash Dump Analysis

If a crash dump is captured, it contains:

**Stack Corruption:**
```
Address    | Data (hex)             | Interpretation
0x0012FEF0 | 41 41 41 41           | Overwritten buffer (attacker's padding)
0x0012FEF4 | 42 42 42 42           | Attacker's marker bytes
0x0012FEF8 | CD 90 12 7C           | ROP gadget address (pop pop ret in ntdll)
0x0012FEFC | 78 56 34 12           | Next gadget address or shellcode pointer
```

**Forensic Interpretation:**
- mona.py generated the gadget addresses (0x7C1290CD, 0x12345678).
- The dump shows the result of mona's `rop --chain` execution.
- However, the dump itself contains no metadata saying "mona.py was used here."

### Volatility/Memory Analysis

```bash
# Volatility inspection of crash dump
volatility3 -f crash.dmp windows.strings
# Search for ROP gadget patterns (xchg, pop, call, ret opcodes)
# Result: Gadget sequences visible in memory, but no "mona.py" text artifact

# Conclusion: ROP chain is evident (structured gadget layout), but the tool used to generate it is not.
```

---

## Network Evidence (Post-Exploitation)

### No Network Trace of mona.py

- mona.py does not generate network traffic.
- If the shellcode establishes a reverse shell or C2 callback, that traffic originates from the **shellcode**, not from mona.py.
- Network analysts see outbound connections from the vulnerable application, not any mona-specific pattern.

---

## EDR/Endpoint Security Product Signatures

### mona.py Evasion

mona.py is designed to **help avoid EDR signatures**:
- `!mona rop -b "\x00"` filters gadgets to avoid null-byte-based YARA rules.
- `!mona badchars` ensures shellcode avoids corruption by content filters (e.g., DLP, firewall content inspection).
- Operator can use mona's badchar findings to regenerate shellcode with obfuscation.

### Target-Side Detection (Independent of mona.py)

- **EDR Behavioral Detection:** Detects stack overflow, ROP chain execution, code injection patterns.
- **Signature-Based:** Detects known shellcode signatures (msfvenom-generated payloads, known C2 beacons).
- **Heuristic:** Detects anomalous memory writes, control-flow hijacking, unexpected child process spawning.

**Critically:** None of these detections are specific to mona.py. They would trigger regardless of whether the exploit was developed with mona.py, WinDbg, or written by hand.

---

## Timeline: Exploit Development → Deployment → Target Traces

**What an Analyst Sees on the Target:**

| Time | Target Event | Log Entry | Source of Evidence |
|---|---|---|---|
| T-2h | (nothing) | — | Operator is running mona on their source machine |
| T-1h | (nothing) | — | Operator is analyzing crashes with mona |
| T-30m | (nothing) | — | Operator is generating ROP chains with mona |
| T0 | Vulnerable app receives exploit payload (via network/file) | Sysmon Event 3 (network) or Event 11 (file creation) | Network PCAP or filesystem; no mona signature |
| T0+1s | Stack/heap overwrite; shellcode injection | (in-memory only) | EDR behavioral alert (if enabled) |
| T0+2s | Code execution (ROP chain runs, shellcode runs) | (in-memory only) | Memory dump would show ROP gadget layout, but no "mona" marker |
| T0+5s | Shellcode spawns cmd.exe or reverse shell | Sysmon Event 1 (process creation) | Anomalous child process from vulnerable app |
| T0+10s | Post-exploitation activity | Sysmon Events 11, 13 (file/registry creation) | Timeline correlation with shellcode execution |

**Key Point:** An analyst examining the target's memory dump, event logs, and filesystem will see evidence of **exploit-development quality** (precise ROP chains, badchar-free shellcode, staged payload architecture) but will NOT see any direct evidence that mona.py was used.

---

## Distinguishing mona.py-Developed Exploits from Others

### Indirect Indicators (High Confidence, Not Definitive)

**Exploit Characteristics Suggesting mona.py Use:**
1. **Precise ROP Gadget Chaining:** mona's automatic chain generation produces well-structured, multi-stage ROP chains.
2. **Badchar-Free Shellcode:** If analysis shows shellcode avoids specific bytes (e.g., 0x00, 0x0A, 0x0D), it suggests `mona badchars` analysis was done.
3. **Multiple Gadgets from Same Module:** mona's module-specific searching (`rop -m "kernel32"`) creates gadget chains biased toward one or two modules.
4. **Exact Stack Offset:** If the exploit hits the exact crash offset without trial-and-error, it suggests `mona pattern_offset` was used for precision.

**Not Definitive Because:**
- Other tools (Ropper, custom scripts) can produce identical artifacts.
- Manual ROP chain crafting can also be precise and structured.

### Cannot Distinguish Definitively

The following **cannot** be determined from target evidence alone:
- Was `!mona rop --chain` used or was the ROP chain hand-crafted?
- Was `!mona badchars` used or was the operator just careful about shellcode encoding?
- Was `!mona pattern_create` used or was the crash offset discovered by trial-and-error?

**Definitive Proof Requires Source Machine Evidence:**
- mona_*.txt files on attacker's disk.
- .udd project files documenting mona commands.
- PowerShell history showing mona commands.

---

## See Also

- [Immunity Debugger Target Evidence](../Immunity%20Debugger/04%20-%20Target%20Evidence.md) — complement with Immunity Debugger exploitation artifacts.
- [mona.py Source Evidence](../mona.py/03%20-%20Source%20Evidence.md) — what IS visible on the source machine.
- **Windows/12 - Lateral Movement** — post-exploitation activity following successful exploit execution.
- **Windows/Threat Landscape and Playbooks/Exploit Development and Code Execution Playbook** — end-to-end exploitation detection strategy.
