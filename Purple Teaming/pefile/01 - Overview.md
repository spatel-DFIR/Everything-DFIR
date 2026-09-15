# pefile — Overview

> 🔴 **Red Flag Principle:** pefile is a **Python library/parsing tool**, not an exploitation tool — it never touches a target host at all. An operator embeds it into analysis/automation scripts that parse Windows PE binaries *locally on their own machine*: a malware sample, a staged payload, a legitimate binary from the target for fingerprinting, or any other PE-format binary already present on the attacker's system. The only network activity pefile itself generates is incidental to Python or the host environment (e.g., pip install), not pefile-specific. The operative distinction from the module's perspective is therefore **where the evidence lives**: `04 - Target Evidence.md` is deliberately thin (no target-side artifacts exist), and `03 - Source Evidence.md` owns the evidentiary weight — the Python process running the script, the script file itself, cached Python bytecode, and any output files the script writes (a parsed binary report, a packer signature match, a certificate dump, etc.). This shapes pefile's entire forensic posture as a local analysis/automation tool embedded in broader attack workflows rather than a direct-access mechanism.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Library API — Quick Reference](#library-api--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified directly against the official repository, [`erocarrera/pefile`](https://github.com/erocarrera/pefile):

- **Primary author:** [Ero Carrera](https://github.com/erocarrera) (`ero.carrera@gmail.com`). Repository created April 2015, actively maintained through August 2026 (latest push 2026-08-09).
- **License:** MIT, permitting unrestricted commercial and private use.
- **Current version:** **2024.8.26** (released 2024-08-26), versioned using a calendar scheme (YYYY.MM.DD) since moving from traditional semantic versioning. This is not the package version string — the actual PyPI package name is simply `pefile`, installable via `pip3 install pefile`.
- **Python support:** Python **3.6+** required (pure Python, no C extensions or external dependencies). The project explicitly **dropped Python 2 support** — the codebase is Python 3 only, verified against `pyproject.toml` which specifies `requires-python = ">=3.6.0"` and the GitHub Actions CI testing against Python 3.8 through 3.12.
- **Purpose:** pefile emerged as a response to the complexity of PE format documentation and the lack of a pure-Python reference implementation. Rather than requiring operators/analysts to hand-parse binary structures or shell out to external C-based tools, pefile abstracts away the PE file format's complexity, exposing PE headers, sections, imports, exports, resources, debug information, and certificates as object attributes — making it embeddable in Python-based analysis pipelines without binary dependencies.
- **Dependencies:** pefile is self-contained. The module has **zero external dependencies** beyond the Python standard library — it works on Windows, macOS, and Linux identically, with no reliance on OS-specific APIs or third-party packages.
- **Known users:** VirusTotal (malware scanning), Cuckoo (dynamic malware analysis), CAPE (behavioral analysis sandbox), Immunity Debugger, PE Tree (GUI PE inspector), MultiScanner (MITRE threat detection framework), and hundreds of custom internal security tools across incident response, threat intelligence, and malware analysis teams.
- **Packer detection:** pefile ships with **PEiD's packer signatures** — a community-maintained database of cryptographic signatures for detecting common packers (UPX, ASPack, PECompact, FSG, etc.), originally from the now-defunct PEiD project. The signatures are embedded as a `.py` data file and exposed via the `match_expr()` method. This is the *only* built-in packer-detection capability; other detection frameworks (e.g., Yara, Ghidra, Binary Ninja) are separate tools.

## How It Works

pefile is a **binary structure parser** — it reads a PE file from disk (or from a bytes object in memory), maps the file's raw bytes against the Windows PE format specification, and exposes the resulting structures as Python object attributes. The parsing is **entirely offline** and **read-only by default**.

### Core parsing flow

```
┌─────────────────────────┐
│ PE file on disk         │
│ (exe/dll/sys/etc.)      │
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ PE.__init__() constructor                               │
│ ├─ Parse DOS header (offset 0x00)                       │
│ ├─ Follow e_lfanew pointer to PE signature + headers    │
│ │  └─ File header (machine, sections count, etc.)       │
│ │  └─ Optional header (entry point, subsystem, etc.)    │
│ ├─ Parse section headers                                │
│ ├─ Parse section data (code, data, rsrc, etc.)          │
│ ├─ Parse directories (IAT, reloc, debug, cert, etc.)    │
│ └─ Store all as object attributes (PE.DOS_HEADER, etc.) │
└────────────┬────────────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────────────┐
│ Operator's Python script accesses                        │
│ ├─ PE.DOS_HEADER.e_lfanew                               │
│ ├─ PE.FILE_HEADER.NumberOfSections                      │
│ ├─ PE.OPTIONAL_HEADER.AddressOfEntryPoint               │
│ ├─ PE.sections (iterable of section objects)            │
│ ├─ PE.DIRECTORY_ENTRY_IMPORT (imports table)            │
│ ├─ PE.DIRECTORY_ENTRY_EXPORT (exports table)            │
│ ├─ PE.DIRECTORY_ENTRY_RESOURCE (resource section)       │
│ ├─ PE.DIRECTORY_ENTRY_DEBUG (debug info)                │
│ ├─ PE.DIRECTORY_ENTRY_CERTIFICATE (signing certs)       │
│ └─ PE.DIRECTORY_ENTRY_RELOCATION (reloc table)          │
└─────────────────────────────────────────────────────────┘
```

### Attribute naming convention

pefile adheres closely to the official Windows PE specification's own C struct names. For example:

- `IMAGE_DOS_HEADER` struct → `PE.DOS_HEADER` attribute
- `IMAGE_FILE_HEADER` struct → `PE.FILE_HEADER` attribute
- `IMAGE_OPTIONAL_HEADER` struct → `PE.OPTIONAL_HEADER` attribute (with machine-dependent layout — 32-bit vs. 64-bit)
- `IMAGE_IMPORT_DESCRIPTOR` → `PE.DIRECTORY_ENTRY_IMPORT[i].dll` (DLL name), `PE.DIRECTORY_ENTRY_IMPORT[i].imports` (list of imported functions)
- `IMAGE_EXPORT_DIRECTORY` → `PE.DIRECTORY_ENTRY_EXPORT.symbols` (list of exported functions with addresses and ordinals)

Non-standard shortcuts exist for convenience (e.g., `PE.get_section_by_name()`, `PE.write()`, `PE.dump_info()`), but the core attributes stick to the spec.

### Packer detection via PEiD signatures

pefile includes a method `match_expr()` that compares a PE's raw section data (typically the first section, `.text` or `.code`) against a database of known cryptographic signatures from the PEiD project:

```python
pe = pefile.PE('malware.exe')
packer = pe.match_expr(pe.sections[0].get_data())
# Returns something like "UPX 3.x" or "ASPack 2.12c" if matched,
# or None if no signature matches
```

This method is **not** built into the default parsing loop — the operator must explicitly call it on specific section data. It identifies common packers and obfuscators by cryptographic signature matching (looking for distinctive byte patterns in the `.text` section), not by heuristics or behavior analysis.

### Optional modification (read-mostly, with caveats)

pefile includes basic write support via `PE.write()` — an operator can overwrite specific fields in a parsed PE object and write the modified binary back to disk. The caveats are significant:

- **No structure rearrangement:** pefile does not resize or move PE sections to make room for new data. Overwriting works only if the new value fits in the existing space.
- **Header-field focus:** most use cases are limited to modifying individual header fields (entry point, subsystem, machine type, checksum, etc.), not inserting entirely new sections or resources.
- **Untested edge case:** modifications to complex structures (import tables, relocations, certificates) are largely untested in the wild and carry a real risk of producing unparseable binaries.

For these reasons, pefile is primarily a *read* tool, with write support as a secondary, careful-use feature.

## Techniques / Protocols Used

pefile has no network protocol surface — it works entirely offline, parsing binary structures according to the official PE format specification.

| Layer | Detail |
|---|---|
| **Binary format** | PE/COFF (Portable Executable / Common Object File Format), as specified in Microsoft's official PE format documentation and the ECMA-335 standard (for .NET assemblies). Machine types: x86, x64, ARM, ARM64, etc. Subsystems: native, Windows GUI, Windows console, Posix, EFI, etc. |
| **Signature/certificate parsing** | Basic parsing of the PKCS#7 structure in the Certificate Directory (`IMAGE_DIRECTORY_ENTRY_SECURITY`); full cryptographic validation of Authenticode signatures requires external tools (Didier Stevens's `verify-sigs` project or similar) — pefile reads the structure, not verifies the crypto. |
| **Debug information** | Parses CV (CodeView) and COFF debug information from the Debug Directory; does not interpret the full PDB format — that requires the separate PDB parser or a debugger's native implementation. |
| **Resource parsing** | Walks the resource section's directory tree (`.rsrc`), exposing resource names, types, languages, and raw data offsets; does not parse resource-type-specific data (strings, icons, version info require secondary parsing after extraction). |
| **PEiD signatures** | Embedded cryptographic hashes/regex patterns for common packers and obfuscators, compared against section data via `match_expr()`. |

## Library API — Quick Reference

Verified live against [`erocarrera/pefile`](https://github.com/erocarrera/pefile)'s `pefile.py` source (the main module is a single 3000+-line file). This covers the core API; the full interface includes ~200 helper methods and attributes, but the below are what operators most commonly use in practice.

### Parsing and construction

| Method/Attribute | Purpose |
|---|---|
| `PE(filename)` or `PE(data=bytes_obj, fast_load=False)` | Construct a PE object by parsing a file path or raw bytes. `fast_load=True` skips some optional directories (debug, relocation, etc.) for speed. |
| `PE.close()` | Close the file handle if opened from disk. |
| `PE.get_section_by_name(name)` | Return a section object by name string (e.g., `.text`). |
| `PE.get_section_by_rva(rva)` | Return the section containing a given Relative Virtual Address. |
| `PE.get_data(rva, size)` | Extract `size` bytes from the PE at a given RVA (does virtual-address-to-file-offset translation). |

### Headers

| Attribute | Value |
|---|---|
| `PE.DOS_HEADER` | DOS MZ header (`e_magic`, `e_lfanew`, `e_lfanew` points to PE signature offset) |
| `PE.NT_HEADERS` | Alias for the combined File Header + Optional Header |
| `PE.FILE_HEADER` | `Machine`, `NumberOfSections`, `TimeDateStamp`, `PointerToSymbolTable`, `NumberOfSymbols`, `SizeOfOptionalHeader`, `Characteristics` |
| `PE.OPTIONAL_HEADER` | `Magic` (0x10b = 32-bit, 0x20b = 64-bit), `AddressOfEntryPoint`, `ImageBase`, `SectionAlignment`, `FileAlignment`, `Subsystem`, `DllCharacteristics`, `SizeOfStackReserve`, `SizeOfHeapReserve`, etc. |

### Sections

| Attribute | Value |
|---|---|
| `PE.sections` | List of section objects (`IMAGE_SECTION_HEADER`), each with `.Name`, `.VirtualSize`, `.VirtualAddress`, `.SizeOfRawData`, `.PointerToRawData`, `.Characteristics`, `.get_data()` method. |
| `PE.DIRECTORY_ENTRY_SECTIONS` | Same as `PE.sections` (alternate name). |

### Imports/Exports

| Attribute | Value |
|---|---|
| `PE.DIRECTORY_ENTRY_IMPORT` | List of import descriptors; each descriptor has `.dll` (string), `.imports` (list of imported functions). Each import has `.name` (function name), `.address`, `.ordinal`. |
| `PE.DIRECTORY_ENTRY_EXPORT` | Export descriptor with `.symbols` (list of exported functions), each with `.name`, `.address`, `.ordinal`. |
| `PE.DIRECTORY_ENTRY_FORWARDED_EXPORTS` | Re-exported functions (forward references). |

### Resources

| Attribute | Value |
|---|---|
| `PE.DIRECTORY_ENTRY_RESOURCE` | Tree of resource entries; walkable via `.entries` (list). Each entry has `.id` (resource ID), `.name` (if named), `.struct` (the raw data structure). Requires secondary parsing for resource-type-specific data (strings, icons, versions). |

### Debug information

| Attribute | Value |
|---|---|
| `PE.DIRECTORY_ENTRY_DEBUG` | List of debug directory entries, each with `.Type` (CV_COFF, CodeView, etc.), `.PointerToRawData`, `.SizeOfData`. The `Type` value determines what the raw data contains. |

### Certificates/signatures

| Attribute | Value |
|---|---|
| `PE.DIRECTORY_ENTRY_CERTIFICATE` | List of certificate entries (PKCS#7 structures); basic parsing only — full Authenticode validation requires `verify-sigs` or similar. |

### Relocations

| Attribute | Value |
|---|---|
| `PE.DIRECTORY_ENTRY_RELOCATION` | List of relocation blocks (one per section that contains relocations), each with `.VirtualAddress`, `.SizeOfBlock`, `.entries` (list of individual relocation records). |

### Warnings and diagnostics

| Attribute | Value |
|---|---|
| `PE.OPTIONAL_HEADER.DATA_DIRECTORIES` | All 16 standard PE directories; empty/zero values here indicate which directories are present or absent. |
| `PE.get_warnings()` | List of warnings pefile found during parsing (malformed fields, suspicious values, deprecated flags). |

### Write support

| Method | Purpose |
|---|---|
| `PE.write(filename)` | Write the parsed + optionally modified PE back to disk. |
| Field overwrite | Assign directly to parsed fields, e.g. `PE.OPTIONAL_HEADER.AddressOfEntryPoint = 0x4000`. |

### Packer detection

| Method | Purpose |
|---|---|
| `PE.match_expr(data, yara_rules=None)` | Match PEiD signatures against section data; optionally supply external Yara rules for more sophisticated detection. Returns matched signature name or None. |

## Quick Use-Case List

- Basic PE header parsing and inspection (DOS, file, optional headers)
- Enumerating sections (.text, .data, .rsrc, .reloc, etc.) and their properties
- Extracting the import address table (IAT) — list all DLLs and imported functions
- Inspecting the export table — enumerate exported functions, ordinals, addresses
- Resource section analysis — extract strings, icons, version information, locales
- Digital signature/certificate inspection (basic parsing; full Authenticode validation requires `verify-sigs`)
- Packer detection using embedded PEiD signatures (UPX, ASPack, PECompact, etc.)
- Calculating and validating entry point addresses
- Relocation table inspection — identify position-independent references
- Debug information extraction (CV/COFF debug symbols, PDB path recovery)
- Malware/payload analysis integration — parse suspected binaries in staged-download workflows
- Binary comparison for patch detection (comparing headers/section hashes before/after patches)
- Suspicious-value detection and flagging (anomalous entry points, odd characteristics flags, etc.)
- Basic PE modification (overwriting header fields: entry point, subsystem, checksum)
- Bulk PE enumeration across a filesystem or captured artifact set

Full walkthroughs with code snippets for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.6+ | Pure Python, no compiled extensions; works identically on Windows, macOS, Linux. |
| pefile installed | Via `pip3 install pefile` (zero external dependencies; installs instantly). |
| PE binary to parse | Can be a local file path or raw bytes in memory — an `.exe`, `.dll`, `.sys` (Windows driver), `.efi` (UEFI firmware), or any other PE-format binary. |
| No network requirement | pefile has zero network functionality; all work is local and offline. |
| No special privileges | Runs as a regular unprivileged user; no admin/root required. File permissions must allow read access to the binary being parsed. |
| Permissions | No special Windows privileges or capabilities required (neither SeDebugPrivilege nor administrative group membership); basic file-read access sufficient. |

