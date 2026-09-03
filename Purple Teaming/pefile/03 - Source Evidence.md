# pefile — Source Evidence

All evidence from pefile execution lives on the **operator's/analyst's own machine** — the Python process, script file, and any output the script produces. No network or target-touching activity occurs.

---

## Process execution and command history

### Python process

When a pefile script executes, the Python interpreter itself is the hosting process:

```
python.exe (or python3.exe on Unix/macOS) → runs the operator's script → imports pefile
```

**What gets logged:**

| Artifact | Detail |
|---|---|
| **Sysmon Event 1 (Process Create)** | `python.exe` or `python3` process creation, with command line containing the script path (e.g., `python.exe analyze_malware.py malware.exe`) |
| **Event 4688 (Process Create, auditing enabled)** | Same as Sysmon 1 — parent process, image name, command line |
| **PowerShell Execution Logs** | If the script is called from PowerShell (e.g., `python .\analyze.py`), Event 4103 (Module Logging) or 4104 (Script Block Logging) may capture the invocation |
| **Shell history** | Bash: `~/.bash_history` (if Python was invoked from bash); Zsh: `~/.zsh_history`; PowerShell: `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` (if available) |
| **Windows Run MRU** | If launched via Win+R dialog, registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |

**Hunting note:** The command line in Event 4688 is the **primary** signal — it contains the full path to the operator's analysis script and any arguments (e.g., the path to the binary being analyzed). If the script path is a network share, UNC path logging becomes relevant.

### Python import and module loading

pefile is a single-file module (`pefile.py`, ~3500 lines), plus optional `peutils.py` and an `ordlookup/` directory of PEiD signature data. When imported:

```python
import pefile
```

Python loads the module into memory. This registers in:

| Artifact | Detail |
|---|---|
| **Sysmon Event 7 (Image Load)** | Not guaranteed — image loading for Python modules is rarely logged with default Sysmon rules (only DLL loads into process are logged, not Python `.py` modules) |
| **ETW (Event Tracing for Windows)** | Process and Module Enumeration events if tracing is enabled; unlikely in default config |
| **.pyc cache files** | Python bytecode cache written to `__pycache__/pefile.cpython-3X.pyc` in the same directory as pefile.py or in the system site-packages directory (e.g., `C:\Python39\Lib\site-packages\__pycache__\`) |

**Hunting note:** The `.pyc` file's timestamp can indicate when the module was first imported; the bytecode itself is a compiled form of the source, which can be decompiled back to source with tools like `uncompyle6` or `decompyle3`, exposing analyst methodology.

---

## Script file and artifacts

### The analyst's own script

The Python script that calls pefile is the primary artifact:

```
C:\temp\analyze_binaries.py         # The analyst's script
C:\Windows\System32\kernel32.dll     # The binary being analyzed (not created by pefile)
```

**What filesystem operations occur:**

| Operation | Detail |
|---|---|
| **Script read** | The operator's script file is read into memory and executed by the Python interpreter. Standard file-read ACLs apply. |
| **Script creation** | If the script is written by the operator directly on the analysis machine, the file's creation/modification time, ownership, and ACLs are logged in $MFT and USN Journal. |
| **pefile.py read** | The pefile module itself is read from disk (either installed via pip in site-packages, or from a local copy in the same directory). Filesystem $MFT and Prefetch logs will record this read. |

**Hunting note:**

- **$MFT ($USN Journal):** Records read/write/access of the script file and pefile module. The operator's script name is often descriptive (e.g., `analyze_malware.py`, `extract_imports.py`), making analyst intent obvious in retrospect.
- **Prefetch files:** Windows creates `C:\Windows\Prefetch\python.exe-<hash>.pf` (or `python3.exe-<hash>.pf` on Unix) if prefetch logging is enabled. The hash incorporates the command line and DLLs loaded, so analyzing the Prefetch file can reveal which binaries were processed.
- **Recent files / File Explorer MRU:** If the script accesses files via the file browser first (before running the script), those files may appear in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU`.

### Output files

If the pefile script writes results to disk:

```python
# Example: Script that saves analysis results
import pefile
import json

pe = pefile.PE('malware.exe')
analysis = {
    'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
    'is_dll': bool(pe.FILE_HEADER.Characteristics & 0x2000),
    'sections': [s.Name.decode().strip() for s in pe.sections]
}

with open('analysis_output.json', 'w') as f:
    json.dump(analysis, f, indent=2)
```

**Output file artifacts:**

| Artifact | Detail |
|---|---|
| **File creation** | The output file (`analysis_output.json`, etc.) is written to the filesystem, logged in $MFT with creation/modification times |
| **File content** | The content reveals analyst methodology — e.g., extracting imports reveals which binaries were analyzed; a report on packed binaries reveals the analyst is looking for evasion techniques |
| **Temporary files** | If the script uses Python's `tempfile` module or writes to `%TEMP%`, those files are also logged |
| **File permissions** | pefile does not set restrictive file permissions on output; files inherit the creator's default umask, typically world-readable on Unix or user-readable on Windows |

**Hunting note:** Output files are often the **richest** source of analyst activity — their content directly names the binaries analyzed, the findings, and the script's purpose. A forensic investigator finding `packer_analysis_report.txt` listing 50 malware binaries with their packer signatures has recovered the analyst's entire workflow.

---

## Network connectivity

### pip installation

If pefile was installed via pip on the source machine:

```bash
pip3 install pefile
```

**Network artifacts:**

| Event | Detail |
|---|---|
| **Outbound HTTPS** | Connection to PyPI (`pypi.org` / `pypi.python.org`, port 443) to download the pefile package |
| **DNS queries** | `pypi.org`, `pypi.python.org`, `files.pythonhosted.org` (CDN for package hosting) |
| **HTTP referer logs** | If PyPI logs referers, the operator's Python version and system info may be visible |
| **IP geolocation** | Analyst's public IP is revealed to PyPI's logs (if captured) |

**When it doesn't happen:** If pefile was pre-installed in a corporate environment or airgapped machine, no installation-time network activity occurs. The operator simply imports the pre-existing module.

**Hunting note:** PyPI has basic logging but is not a sensitive service — pip package downloads are expected, non-anomalous activity on most networks. The real signal is the **combination** of pip install + analysis script creation, which together suggest threat-analysis workflows.

### pefile itself: zero network

pefile as a library has **zero network functionality** — once imported, it never makes outbound connections, DNS queries, or phone-home calls. It's entirely self-contained. Any network activity observed during pefile execution originates in the operator's own script (e.g., if the script downloads binaries to analyze).

---

## Registry modifications

pefile does not modify the Windows registry. However, the Python interpreter may:

| Artifact | Detail |
|---|---|
| **Python version registry** | Windows Python stores installation metadata in `HKLM\Software\Python\PythonCore\<version>` or `HKCU\Software\Python`, accessed at startup but not modified by pefile |
| **File associations** | If Python is associated with `.py` files, the registry tracks this, but pefile does not trigger updates |

**Hunting note:** No registry signals are specific to pefile execution.

---

## Memory forensics

### Live memory

A running Python process executing pefile holds:

| Artifact | Detail |
|---|---|
| **Python heap** | The PE object (containing parsed headers, sections, imports, etc.) is allocated on the Python heap. A memory dump of the python.exe process would reveal the pefile module, any analyzed binary data, and the operator's script logic. |
| **Module imports** | The `pefile` module is loaded into the process's module list (visible via `lsof` on Unix, or Process Explorer on Windows) |
| **.pyc bytecode** | If the script itself was compiled to `.pyc`, the bytecode is in memory (decompilable) |

**Hunting note:** Memory forensics on a running Python process would reveal the operator's entire analysis session, including binaries analyzed and findings computed. This is a powerful forensic signal if live-memory capture is possible.

### Dump files

If the operator uses a Python debugger or calls `sys.getsizeof()` on large objects, memory usage spikes. Crash dumps created by the OS (e.g., if python.exe crashes) may be written to `%LOCALAPPDATA%\CrashDumps\` or `C:\ProgramData\Microsoft\Windows\WER\`.

---

## Disk forensics and timeline

### File allocation table ($MFT)

Every file read/written by pefile-based scripts is logged:

| File | $MFT Entry |
|---|---|
| `analyze.py` (analyst's script) | Creation time, modification time, last access time, owner |
| `pefile.py` (module) | Access time (every time the module is imported) |
| `malware.exe` (analyzed binary) | Access time (every time analyzed) |
| `output.json` (results) | Creation/modification time |

**Hunting note:** The $MFT is immutable on live filesystems (though can be edited offline in forensic images). The timeline of file access — script creation → binary analysis → output generation — reconstructs the analyst's workflow chronologically.

### Deleted files and recovery

If the operator deletes analysis scripts or output files:

| Artifact | Detail |
|---|---|
| **Unallocated clusters** | Deleted file content persists in unallocated space until overwritten |
| **File recovery tools** | `carving` tools (e.g., `strings`, `file recovery` utilities) can recover partial content |
| **Slack space** | Data fragments at the end of allocated clusters may contain forensically-valuable scraps |

**Hunting note:** Deleting output is easily discoverable via unallocated-space forensics.

---

## Python cache and compiled artifacts

### `__pycache__/` directory

When Python imports pefile, it writes a compiled `.pyc` file to cache the bytecode:

```
C:\Python39\Lib\site-packages\pefile\__pycache__\pefile.cpython-39.pyc
```

or (for locally-installed pefile):

```
.\pefile\__pycache__\pefile.cpython-39.pyc
```

**Forensic value:**

| Detail | Value |
|---|---|
| **Timestamp** | Indicates when pefile was first imported in this Python environment |
| **Bytecode** | Decompilable to Python source code via `uncompyle6`, revealing pefile's implementation (not the analyst's own script, but pefile's internals) |
| **Presence** | Indicates pefile was used at some point in this Python installation |

**Hunting note:** The presence/absence and timestamp of `.pyc` files can establish rough timelines for when analysis occurred, especially if multiple analysis runs across different dates left multiple `.pyc` versions.

### pip metadata

If pefile was installed via pip, metadata is stored in:

```
C:\Python39\Lib\site-packages\pefile-2024.8.26.dist-info\
```

Contents:

| File | Value |
|---|---|
| `METADATA` | Package version (2024.8.26), author, license, download URL |
| `RECORD` | List of all files installed (pefile.py, peutils.py, ordlookup/) |
| `entry_points.txt` | (empty for pefile, no CLI entry point) |

**Hunting note:** The presence of the `.dist-info/` directory confirms pefile was installed via pip and provides exact version information. The install timestamp (directory creation time in $MFT) is useful for timeline reconstruction.

---

## Command-line arguments and logging

### Captured arguments to Python

When pefile is invoked, the full command line is visible to process-level audit logs:

**Example command:**
```
python.exe analyze_malware.py C:\temp\malware.exe --output report.json
```

**Logged in:**

| Log | Entry |
|---|---|
| **Sysmon Event 1** | `CommandLine: python.exe analyze_malware.py C:\temp\malware.exe --output report.json` |
| **Event 4688 (if auditing)** | `Process Name: python.exe`, `Command Line: python.exe analyze_malware.py...` |
| **Prefetch file** | The hash includes the command line, making it partially recoverable from Prefetch analysis |

**Hunting note:** The command line directly exposes which binaries were analyzed. If the operator names the script descriptively (e.g., `find_packed_malware.py`), the analyst's intent is obvious.

---

## Summary: Timeline of a typical pefile analysis session

1. **Script creation** ($MFT) — `analyze.py` is written to disk
2. **Python interpreter launch** (Sysmon 1, Event 4688) — command line includes script path and binary path
3. **pefile module import** ($MFT access time on pefile.py, .pyc creation if first import)
4. **Binary file read** ($MFT access time on `malware.exe`)
5. **Analysis computation** (in-memory only, invisible except via memory dump)
6. **Output file write** ($MFT creation time on `output.json` or similar)
7. **Script cleanup (optional)** (file deletion, recoverable from unallocated space)

**Forensic value:** Almost all signals live on the analyst's own machine — **the target host sees nothing**. An investigator with access to the analyst's computer can reconstruct the entire analysis workflow via filesystem and process logs. For a defender hunting for such activity, look for:

- Python processes with descriptive script names
- Combinations of script creation + binary read + output file write in quick succession
- pefile in site-packages (via pip listing or filesystem scan)
- Output files with analysis results (JSON, CSV, text reports naming binaries and findings)

