# mona.py — Source Evidence

mona.py leaves traces on the **attacking/source machine** where Immunity Debugger and mona.py are installed. Since mona.py is a plugin that runs only inside Immunity Debugger, all source artifacts are related to Immunity Debugger usage, with mona-specific extensions.

## Plugin Installation & Filesystem Artifacts

### mona.py Installation Location

**Standard Installation Path:**
```
%APPDATA%\Immunity Inc\Debugger\PyCommands\mona.py
```

**Alternative Installation Paths:**
- `C:\Program Files\Immunity Inc\Debugger\PyCommands\mona.py` (system-wide install)
- Any custom Immunity Debugger plugins folder (if non-standard path is configured)

### File Artifacts

**mona.py Script File:**
- **File:** `mona.py` (Python source file, typically 2000+ lines)
- **Size:** ~50-100 KB (depends on version)
- **Modification Date:** Indicates when mona was last installed or updated.
- **Timestamp Forensics:** Recent modification suggests active exploit development setup.

**mona.py Generated Output Files:**

When mona.py runs commands, it generates output files in the **current working directory** (or a specified output path via `-o` flag):

| Output File | mona Command | Content |
|---|---|---|
| `mona_pattern.txt` | `pattern_create` | The generated unique pattern (bytes used to find crash offset) |
| `mona_gadgets.txt` | `rop` | All discovered ROP gadgets and their addresses |
| `mona_chain.py` | `rop --chain` | Python code for the generated ROP chain |
| `mona_badchars.txt` | `badchars` | Analysis results showing which bytes were corrupted |
| `mona_crash_analysis.txt` | `analyze` | Crash classification and exploitability assessment |
| `mona_seh.txt` | `seh` | SEH chain inspection results |
| `mona_modules.txt` | `info` | List of loaded modules and base addresses |

**Example Timeline Correlation:**
```
2026-08-11 14:30:00  mona_pattern.txt created (pattern generated for fuzzing)
2026-08-11 14:35:00  vulnerable.exe crashed (Immunity breakpoint hit)
2026-08-11 14:36:00  mona_crash_analysis.txt created (analyze command run)
2026-08-11 14:40:00  mona_gadgets.txt created (rop command to find gadgets)
2026-08-11 14:45:00  mona_chain.py created (rop --chain to generate exploit)
2026-08-11 15:00:00  exploit.exe created (final exploit binary)
2026-08-11 15:05:00  exploit deployed on target
```

---

## PyCommand Console History

### Command History (If Logged)

**Immunity Debugger PyCommand Console:**
- Immunity Debugger does not automatically log PyCommand history by default.
- However, if the operator is running Immunity in a terminal/console window, shell history may capture commands.

**PowerShell History (if Immunity was launched from PowerShell):**
```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

Might contain:
```
C:\path\to\Debugger64.exe C:\vulnerable.exe
```

### Immunity Log Pane Output

**If Logged/Captured:**
- Immunity Debugger's log pane (bottom panel) displays all mona.py output.
- This output is not automatically persisted to disk; it's displayed in the GUI only.
- **However:** If the operator captures/screenshots or logs the console output, mona commands and results may be cached.

**Typical mona Output Logged in GUI:**
```
[*] Searching for ROP gadgets
[*] Found 1234 gadgets
[*] Building ROP chain for: VirtualAlloc
[*] Chain generated and saved to mona_chain.py
```

---

## Process & Memory Artifacts (Runtime)

### Debugger64.exe Process Memory

**While Immunity Debugger is running with mona.py loaded:**
- Immunity's process memory contains the mona.py module code (in-memory, not extracted).
- The debugged binary's entire memory image is also in Immunity's process space (via `read_memory()` calls).
- If a memory dump is captured (Belkasoft, Volatility) while Immunity is debugging, the dump contains:
  - mona.py module state
  - Debugged binary's memory snapshot
  - Pattern/gadget data structures

**Indicator:** Large memory footprint for Debugger64.exe (because it holds copies of debugged binaries in memory).

---

## Network & Remote Storage Artifacts

### No Network Activity by mona.py

mona.py does not generate network traffic by itself. It:
- Does not download gadgets from remote sources
- Does not phone-home to Corelan
- Does not validate licenses over network

**However:** If an operator uses mona-generated ROP chains to **create a C2 payload** that later beacons out, the network traffic is from the payload/C2, not from mona.py.

---

## Registry Artifacts

### Immunity Debugger Registry Entries

**HKCU\Software\Immunity Inc\Debugger:**
- Stores Immunity preferences, window layout, plugin configurations.
- **mona-related entries:** If mona is configured (e.g., via `config --file`), paths to config files may be stored here.

**HKCU\Software\Immunity Inc\Debugger\PyCommands:**
- Lists installed Python plugins (including mona.py).

---

## Timeline Correlation: Exploit Development Workflow

**Typical operator workflow with mona.py:**

| Time | Activity | Artifact | Forensic Signal |
|---|---|---|---|
| T-2h | Debugger64.exe launched; target binary loaded | Debugger64.exe process creation (Sysmon Event 1) | GUI window opens; .udd file created |
| T-1.5h | mona pattern_create; pattern injected into app | mona_pattern.txt created | File timestamp; pattern visible in file |
| T-1h | App crashes; mona analyze run | mona_crash_analysis.txt created | File timestamp; crash classification output |
| T-45m | mona rop; gadgets discovered | mona_gadgets.txt created | File with ROP gadget addresses |
| T-30m | mona rop --chain; exploit chain generated | mona_chain.py created | Python code ready for payload injection |
| T-15m | Exploit tested locally in debugger | Repeated Debugger64.exe restarts; .udd updates | Multiple process creation events |
| T0 | Exploit.exe deployed on target | Exploit copied to staging area | File creation on network share or temp folder |
| T+5m | — | Exploit runs on target | Reverse shell established; post-exploitation activity starts |

---

## Summary: Detecting mona.py Setup on Source Machine

| Artifact | Location | Signal |
|---|---|---|
| **mona.py plugin file** | `%APPDATA%\Immunity Inc\Debugger\PyCommands\mona.py` | Plugin presence; recent modification indicates exploit-dev setup |
| **mona_pattern.txt** | Working directory (where Debugger64.exe was run) | Unique pattern for crash finding |
| **mona_gadgets.txt** | Working directory | ROP gadget enumeration; directly reveals exploit-dev activity |
| **mona_chain.py** | Working directory | Python-formatted ROP chain; smoking gun for exploit construction |
| **mona_crash_analysis.txt** | Working directory | Crash classification and exploitability; confirms vulnerability analysis |
| **mona_*.txt output files** | Working directory or user-specified -o path | Timeline of analysis steps; correlates to exploit stages |
| **.udd project files** | User-defined (Desktop, Documents, project folder) | Immunity session metadata including mona command history |
| **Debugger64.exe process** | Process list, Sysmon Event 1 | Parent-child to debugged binary; timestamps of analysis session |
| **PowerShell history** | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` | Commands that launched Debugger64.exe + mona |
| **Recent Files / MRU** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | Recently-opened .udd files or debugged binary paths |
| **RAM (live memory dump)** | Volatile memory | Debugger64.exe process memory contains mona.py module + debugged binary |

---

## See Also

- [Immunity Debugger Source Evidence](../Immunity%20Debugger/03%20-%20Source%20Evidence.md) — complement with general Immunity Debugger artifacts.
- [mona.py Target Evidence](../mona.py/04%20-%20Target%20Evidence.md) — what appears on the target after exploitation.
- **Windows/12 - Lateral Movement** — post-exploitation activity timeline correlation.
