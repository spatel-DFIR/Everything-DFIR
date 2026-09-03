# Immunity Debugger + mona.py — Suite Overview

## Why They're Bundled

**Immunity Debugger + mona.py** form a **complete Windows exploit-development workbench** that has become the de-facto standard in training (OSCP, SEC660) and real-world adversary operations alike. While they are technically separate projects, they are **functionally inseparable**: Immunity Debugger provides the debugging platform; mona.py eliminates the manual tedium of crash analysis, pattern-offset calculation, and ROP gadget discovery.

### The Pairing

| Component | Role | Provided By | Status |
|---|---|---|---|
| **Immunity Debugger** | Userland debugger; GUI-based debugging + Python scripting environment | Immunity Inc. (commercial, $995) | Proprietary; actively maintained |
| **mona.py** | Free plugin extending Immunity; automates crash analysis, ROP gadget mining, badchar identification | Corelan (Peter Van Eeckhoutte) | Open-source (BSD 3-Clause); archived (stable, 2.0+ is final) |

### Why Separate Pages, Bundled Folder

- **Immunity Debugger** can be used independently for manual debugging, memory inspection, live patching (see `01 - Overview.md`).
- **mona.py** strictly requires Immunity Debugger to be running; it adds automation on top.
- **Bundled folder** acknowledges the inseparability in practice: an operator deploying "Immunity for exploit dev" universally installs mona.py alongside it.

---

## Workflow: From Crash to Deployed Exploit

### Typical Exploit Development Phases (Using Immunity + mona.py)

```
Phase 1: Vulnerability Discovery
  └─ Fuzzer crashes vulnerable app
  └─ Operator launches Immunity Debugger, loads crash dump
  └─ mona.py: !mona analyze → "Stack Overflow, Probably Exploitable"

Phase 2: Crash Triage
  └─ Operator: !mona pattern_create -l 1000 → generate crash pattern
  └─ Rerun vulnerable app with pattern input → crash
  └─ mona.py: !mona pattern_offset -q 0x41306241 → offset = 264

Phase 3: Gadget Mining
  └─ Operator: !mona rop --chain "VirtualAlloc" → auto-generate ROP chain
  └─ Output: mona_chain.py (Python code for ROP chain)

Phase 4: Badchar Identification
  └─ Operator: !mona bytearray -b "\x00" → generate test bytearray
  └─ Inject bytearray, crash app, analyze received bytes
  └─ mona.py: !mona badchars → identify corrupted bytes (e.g., 0x0A, 0x0D)

Phase 5: Shellcode Preparation
  └─ Operator: msfvenom ... -b "\x00\x0A\x0D" → generate badchar-clean shellcode
  └─ (mona.py's badchar findings feed into msfvenom filter)

Phase 6: Exploit Integration
  └─ Operator embeds ROP chain (from Phase 3) + shellcode (from Phase 5)
  └─ Craft payload: [padding 264] + [ROP chain] + [shellcode]
  └─ Test locally in Immunity Debugger → success
  └─ Compile exploit.exe

Phase 7: Deployment
  └─ Deploy exploit.exe on target
  └─ Exploit triggers, ROP chain executes, shellcode spawns reverse shell
```

---

## Pricing & Licensing

| Tool | License | Cost | Source |
|---|---|---|---|
| **Immunity Debugger** | Proprietary (closed-source) | $995 per license | immunity.com (direct purchase) |
| **mona.py** | BSD 3-Clause (open-source) | Free | github.com/corelan/mona (archived) |

**Total Cost for Setup:** ~$1000 (Immunity Debugger) + $0 (mona.py) = ~$1000 per operator.

**Enterprise Deployment:** Many organizations standardize on Immunity + mona.py for exploit-development training labs, purchasing volume licenses.

---

## Feature Matrix & Capability Comparison

### Immunity Debugger Core Features

| Feature | Status | Notes |
|---|---|---|
| **GUI Debugger** | ✅ Included | User-friendly disassembly, registers, memory panes |
| **Breakpoints (software/hardware)** | ✅ Included | Software (0xCC injection), hardware (DR0-DR7 registers) |
| **Single-Stepping** | ✅ Included | Step-into, step-over, step-out commands |
| **Python Scripting (PyCommand)** | ✅ Included | Custom plugins, automation, hook breakpoints |
| **Memory Read/Write** | ✅ Included | Direct `read_memory()`, `write_memory()` API |
| **Process Attachment/Launch** | ✅ Included | Attach to running process or launch new binary |
| **Crash Dump Inspection** | ✅ Included | Open .dmp files, inspect exception context |
| **Remote Debugging** | ❌ Not Available | Debugging is local-only |
| **Kernel Debugging** | ❌ Not Available | Userland debugger only (WinDbg is the alternative for kernel) |

### mona.py Plugin Features

| Feature | Status | Notes |
|---|---|---|
| **Pattern Generate/Offset** | ✅ Included | De Bruijn sequence for crash offset discovery |
| **ROP Gadget Discovery** | ✅ Included | Automated gadget scanning across loaded modules |
| **ROP Chain Generation** | ✅ Included | Automatic Turing-complete chain building |
| **Badchar Identification** | ✅ Included | Compare input vs. corrupted bytes |
| **SEH Chain Inspection** | ✅ Included | List SEH frames, find pop/pop/ret gadgets |
| **Crash Analysis/Classification** | ✅ Included | Auto-classify crash type (stack overflow, heap corruption, etc.) |
| **Exploitability Assessment** | ✅ Included | Estimate "Probably Exploitable" likelihood |
| **Egg Hunter Pattern** | ✅ Included | Locate injected egg patterns in heap |
| **Module Base Discovery** | ✅ Included | List all loaded modules + base addresses |
| **Unicode Handling** | ✅ Included | Generate unicode-safe payloads |
| **Config Management** | ✅ Included | Save/load ignored modules, badchar lists |
| **Custom Encoding** | ⚠️ Limited | Helpers for common obfuscation; not a full encoder framework |

---

## When to Choose Immunity Debugger + mona.py

### Use Immunity + mona.py If:

✅ **Stack-based buffer overflow exploitation** — exact offset discovery, ROP chain automation.
✅ **OSCP/SEC660 Training** — both courses assume Immunity + mona.py.
✅ **Windows userland exploit development** — GUI-friendly, Python-scriptable.
✅ **Crash analysis & triage** — mona's auto-analysis saves hours per crash.
✅ **Badchar-aware shellcode generation** — mona's badchar findings feed exploit generation.
✅ **Educational/Training Labs** — standard toolkit, widely documented, community-supported.

### Choose Alternatives If:

❌ **Linux Exploit Development** → GDB + GDB plugins (Peda, GEF), pwntools.
❌ **Kernel Debugging** → WinDbg (Kernel Debugger).
❌ **Closed/Proprietary Exploit-Dev** → IDA Pro + Hex Rays Decompiler (reverse-engineering focus).
❌ **Free-Only Budget** → GDB (Linux) or WinDbg (Windows, free but steeper learning curve).

---

## Attack Chain: How These Tools Fit Into Exploit Development

```
Reconnaissance & Vulnerability Discovery
  ↓
Vulnerability Exploitation Development
  ├─ Fuzz target app (external tool)
  ├─ Immunity Debugger: Load crash, pause at exception
  ├─ mona.py: !mona analyze → classify crash as exploitable
  ├─ mona.py: !mona pattern_create → offset discovery
  ├─ mona.py: !mona rop --chain → ROP chain generation
  ├─ mona.py: !mona badchars → badchar identification
  ├─ Immunitu Debugger: Test payload, step-through, verify success
  └─ Compile final exploit binary
  ↓
Exploit Deployment on Target
  ├─ (No Immunity Debugger or mona.py on target)
  ├─ Exploit runs standalone
  └─ ROP chain + shellcode execute
  ↓
Post-Exploitation
  └─ Reverse shell, C2 beacon, lateral movement, etc.
```

**Key Point:** Immunity + mona.py are **development tools only**. They leave no trace on the target after exploitation. All evidence on the target is from the **exploit itself** (ROP chains, shellcode, post-exploitation payloads).

---

## Cross-Links: Related Tools & Concepts

### Windows Exploit Development Context

- **WinDbg** (Wave 4 #10) — Alternative Windows debugger (free, command-line heavy, more powerful for kernel/driver debugging).
- **pwntools** (Wave 4 #8) — Linux exploit-dev scripting library; equivalent role on Linux what Immunity+mona.py play on Windows.
- **Metasploit msfvenom** (Wave 1 `Metasploit/`) — Shellcode generator; badchar-aware output via `msfvenom -b` flag, often used with mona.py's badchar findings.
- **Metasploit msfpattern** (deprecated, replaced by mona.py) — Pattern-based crash analysis; mona.py is the modern replacement.

### DFIR Evidence Context

- **Windows/12 - Lateral Movement** — post-exploitation activity after successful exploit.
- **Windows/Threat Landscape and Playbooks/Exploit Development and Code Execution Playbook** — end-to-end detection strategy.
- **SEC660 / GXPN** — SANS Advanced Exploit Writing course (primary adopter of Immunity + mona.py).

---

## Archived Status: mona.py 2.0 as Final

**Repository:** `https://github.com/corelan/mona` (archived, last push 2026-04-30)

**Meaning:** No new features are planned or being added. mona.py 2.0+ is considered **feature-complete** and stable. Users should:
1. Install version 2.0+ (available on the GitHub releases page).
2. Assume no further updates.
3. Submit bug reports to Corelan (though response time may be slow for an archived project).

**Implication for Defenders:** mona.py's functionality is stable and predictable. Signatures and detection rules based on mona.py 2.0 behavior remain valid without concern for incompatible updates.

---

## Summary Table: Immunity Debugger + mona.py as a Pair

| Aspect | Immunity Debugger | mona.py | Combined Capability |
|---|---|---|---|
| **Installation** | License purchase + install binary | Copy mona.py to PyCommands folder | Full exploit-dev workbench |
| **Automation Level** | Manual GUI interaction or custom Python scripts | Automated crash analysis, ROP gadget mining | Reduces manual toil from hours to minutes per crash |
| **Cost** | $995 | Free | ~$1000 total |
| **Learning Curve** | Moderate (GUI-based, friendly) | Low (commands are straightforward) | High value for investment |
| **Community** | Immunity Inc. + training providers | Corelan Team + open-source contributors | Very active for training; stable for production |
| **License Type** | Proprietary | Open-source (BSD) | Mixed; proprietary core + open-source extension |
| **Best Use Case** | Stack-based buffer overflow labs | Crash triage + ROP chain automation | OSCP/SEC660 training, Windows exploit development |

---

## See Also

- [Immunity Debugger — Full Overview](Immunity%20Debugger/01%20-%20Overview.md)
- [mona.py — Full Overview](mona.py/01%20-%20Overview.md)
- **Windows/Threat Landscape and Playbooks** — for post-exploitation detection/hunting.
- **SEC660 / GXPN Course Materials** — Immunity + mona.py is the assumed toolkit.
- **OSCP Training** — Stack overflow labs extensively use Immunity + mona.py.
