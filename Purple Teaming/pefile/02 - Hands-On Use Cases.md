# pefile — Hands-On Use Cases

Every section below corresponds to a use case listed in `01 - Overview.md`'s Quick Use-Case List, with executable code snippets and MITRE ATT&CK technique citations where applicable.

---

## Basic PE header parsing and inspection

**Context:** Understanding a binary's basic properties before deeper analysis — machine type, compilation timestamp, subsystem, linked libraries.

```python
import pefile

pe = pefile.PE('C:\\Windows\\System32\\kernel32.dll')

print(f"Machine type: {pe.FILE_HEADER.Machine}")        # 0x14c = i386, 0x8664 = x64
print(f"Sections: {pe.FILE_HEADER.NumberOfSections}")
print(f"Compiled: {pe.FILE_HEADER.TimeDateStamp}")       # Unix timestamp
print(f"Entry point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")      # 2 = Windows GUI, 3 = console
print(f"DLL characteristics: 0x{pe.OPTIONAL_HEADER.DllCharacteristics:x}")
print(f"ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")
print(f"Warnings: {pe.get_warnings()}")
```

**MITRE ATT&CK:** [T1010 (Application Window Discovery)](https://attack.mitre.org/techniques/T1010/) and [T1217 (Browser Bookmark Discovery)](https://attack.mitre.org/techniques/T1217/) — general reconnaissance, binary fingerprinting for targeting pre-exploitation. More broadly, **[T1592 (Gather Victim Host Information)](https://attack.mitre.org/techniques/T1592/)** when used to profile OS binaries for compatibility checks.

---

## Enumerating sections and their properties

**Context:** Identifying section names, sizes, memory protections, and physical location — critical for understanding memory layout, identifying code vs. data, and spotting anomalies.

```python
import pefile

pe = pefile.PE('malware.exe')

for section in pe.sections:
    print(f"Name: {section.Name.decode().strip()}")
    print(f"  Virtual size: 0x{section.VirtualSize:x}")
    print(f"  Virtual address: 0x{section.VirtualAddress:x}")
    print(f"  Raw size: 0x{section.SizeOfRawData:x}")
    print(f"  Raw pointer: 0x{section.PointerToRawData:x}")
    print(f"  Characteristics: 0x{section.Characteristics:x}")
    # Characteristics: 0x60000020 = readable + executable
    
# Check for suspicious sections (e.g., non-standard names)
suspicious = [s for s in pe.sections if s.Name not in [b'.text\x00\x00\x00', b'.data\x00\x00\x00', b'.rsrc\x00\x00\x00']]
if suspicious:
    print("Non-standard sections found:", [s.Name for s in suspicious])
```

**MITRE ATT&CK:** [T1106 (Native API)](https://attack.mitre.org/techniques/T1106/) — understanding section characteristics informs memory-protection evasion (e.g., marking a data section executable before code injection). General reconnaissance for exploit development targeting.

---

## Extracting the import address table (IAT)

**Context:** Understanding which DLLs and functions a binary depends on — critical for identifying capabilities, potential attack surface, and suspicious imports.

```python
import pefile

pe = pefile.PE('C:\\Windows\\System32\\cmd.exe')

if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for dll in pe.DIRECTORY_ENTRY_IMPORT:
        dll_name = dll.dll.decode()
        print(f"DLL: {dll_name}")
        for func in dll.imports:
            if func.name:
                print(f"  {func.name.decode()}")
            else:
                print(f"  Ordinal: {func.ordinal}")

# Example: detecting C2 indicators (suspicious API imports)
# Look for kernel32.InternetOpen/CreateProcessA/SetWindowsHookEx combinations
suspicious_apis = {'InternetOpen', 'InternetConnect', 'HttpOpenRequest', 
                    'CreateRemoteThread', 'SetWindowsHookEx', 'VirtualAllocEx'}

found_apis = set()
for dll in pe.DIRECTORY_ENTRY_IMPORT:
    for func in dll.imports:
        if func.name and func.name.decode() in suspicious_apis:
            found_apis.add(func.name.decode())

if found_apis:
    print(f"Suspicious imports: {found_apis}")
```

**MITRE ATT&CK:** [T1106 (Native API)](https://attack.mitre.org/techniques/T1106/), [T1559 (Inter-Process Communication)](https://attack.mitre.org/techniques/T1559/), [T1071 (Application Layer Protocol)](https://attack.mitre.org/techniques/T1071/) — understanding imported functions reveals the binary's capability set and communications potential. Common in malware pre-execution analysis and behavioral forensics.

---

## Inspecting the export table

**Context:** Understanding which functions a DLL exposes — important for analyzing libraries, identifying undocumented APIs, and understanding loaded code's public interface.

```python
import pefile

pe = pefile.PE('C:\\Windows\\System32\\ntdll.dll')

if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    export_dir = pe.DIRECTORY_ENTRY_EXPORT
    print(f"Exports from: {export_dir.name.decode() if hasattr(export_dir, 'name') else 'unknown'}")
    
    for symbol in export_dir.symbols[:20]:  # First 20 to avoid spam
        print(f"  {symbol.name.decode() if symbol.name else 'Ordinal'}: "
              f"0x{symbol.address:x} (Ordinal: {symbol.ordinal})")

# Useful for identifying injected or reflectively-loaded DLLs
# (checking if expected exports are missing or present in unexpected binaries)
```

**MITRE ATT&CK:** [T1218 (System Binary Proxy Execution)](https://attack.mitre.org/techniques/T1218/) and related techniques — understanding exported functions helps identify legitimate vs. trojanized system DLLs, or detecting proxy-execution techniques that call specific exports.

---

## Resource section analysis

**Context:** Extracting embedded data — strings, icons, version information, dialogs, etc. — which often contain metadata, configuration, or payload data.

```python
import pefile
import struct

pe = pefile.PE('application.exe')

if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    resources = pe.DIRECTORY_ENTRY_RESOURCE
    
    # Iterate through resource entries
    def walk_resources(entry, level=0):
        if hasattr(entry, 'directory'):
            for res in entry.directory.entries:
                print(f"{'  ' * level}Resource ID: {res.id}, Name: {res.name}")
                walk_resources(res, level + 1)
    
    walk_resources(resources)
    
    # Extract version information
    # VS_VERSION_INFO structure is typically in DIRECTORY_ENTRY_RESOURCE
    # Requires secondary parsing of version-info strings
    for res_type in resources.entries:
        if res_type.id == 16:  # RT_VERSION
            print(f"Version resource found at ID {res_type.id}")
```

**MITRE ATT&CK:** [T1057 (Process Discovery)](https://attack.mitre.org/techniques/T1057/) and [T1518 (Software Discovery)](https://attack.mitre.org/techniques/T1518/) — extracting version info and resource data helps identify target OS/application versions for exploit selection. Also relevant to **[T1082 (System Information Discovery)](https://attack.mitre.org/techniques/T1082/)** when analyzing binaries for version detection.

---

## Digital signature and certificate inspection

**Context:** Reading Authenticode signatures and embedded certificates — important for verifying binary legitimacy, detecting signature spoofing, and understanding certificate chains.

```python
import pefile

pe = pefile.PE('signed_binary.exe')

if hasattr(pe, 'DIRECTORY_ENTRY_CERTIFICATE'):
    certs = pe.DIRECTORY_ENTRY_CERTIFICATE
    print(f"Certificate count: {len(certs)}")
    
    for i, cert in enumerate(certs):
        print(f"Certificate {i}:")
        print(f"  Revision: {cert.dwRevision}")
        print(f"  Cert type: {cert.dwCertificateType}")
        print(f"  Length: {cert.dwLength}")
        print(f"  Raw data (first 64 bytes): {cert.bCertificate[:64].hex()}")
else:
    print("No Authenticode certificate found")

# NOTE: pefile only reads the certificate structure; full cryptographic
# validation requires verify-sigs (Didier Stevens) or similar tools
```

**MITRE ATT&CK:** [T1036.004 (Masquerading: Masquerade Task Scheduler Task)](https://attack.mitre.org/techniques/T1036/), [T1553 (Subvert Trust Controls)](https://attack.mitre.org/techniques/T1553/) — attackers forge or steal code-signing certificates to evade signature-based detection. Certificate analysis is critical for identifying proxy-execution and signed-binary-abuse techniques.

---

## Packer detection using PEiD signatures

**Context:** Identifying whether a binary is packed (compressed/encrypted) and with what tool — critical for determining if static analysis is feasible or if unpacking is required.

```python
import pefile

pe = pefile.PE('suspected_packed.exe')

# Iterate over sections and check each for packer signatures
for section in pe.sections:
    section_data = section.get_data()
    
    # Try to match PEiD signatures
    matched = pe.match_expr(section_data)
    
    if matched:
        print(f"Section {section.Name.decode().strip()}: {matched}")
    else:
        print(f"Section {section.Name.decode().strip()}: No match")

# Heuristic: if .text section is very small and .data is large,
# likely packed (legitimate binaries have most code in .text)
text_section = pe.get_section_by_name('.text')
if text_section and text_section.VirtualSize < 0x1000:
    print("WARNING: .text section suspiciously small — likely packed")
```

**MITRE ATT&CK:** [T1027 (Obfuscated Files or Information)](https://attack.mitre.org/techniques/T1027/), [T1140 (Deobfuscate/Decode Files or Information)](https://attack.mitre.org/techniques/T1140/) — packer detection is a prerequisite for static malware analysis; packed binaries require unpacking before meaningful analysis is feasible.

---

## Calculating and validating entry point addresses

**Context:** Understanding where execution begins — critical for disassembly, hook placement, and identifying entry-point manipulation attacks.

```python
import pefile

pe = pefile.PE('application.exe')

entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
image_base = pe.OPTIONAL_HEADER.ImageBase

# RVA (Relative Virtual Address) is relative to ImageBase
entry_point_va = image_base + entry_point_rva

print(f"Entry point RVA: 0x{entry_point_rva:x}")
print(f"Entry point VA (absolute): 0x{entry_point_va:x}")

# Validate entry point is within a code section
section = pe.get_section_by_rva(entry_point_rva)
if section:
    print(f"Entry point is in section: {section.Name.decode().strip()}")
    offset_in_section = entry_point_rva - section.VirtualAddress
    print(f"Offset within section: 0x{offset_in_section:x}")
else:
    print("ERROR: Entry point RVA points to invalid location!")

# Heuristic for suspicious entry points:
# - Pointing to data section instead of code
# - Pointing to .rsrc (resource) section
# - Pointing beyond image bounds
if section and section.Name.decode().strip() not in ['.text', '.code']:
    print("WARNING: Unusual entry point location")
```

**MITRE ATT&CK:** [T1027 (Obfuscated Files or Information)](https://attack.mitre.org/techniques/T1027/), [T1106 (Native API)](https://attack.mitre.org/techniques/T1106/) — entry-point manipulation is used in exploit development, shellcode injection, and anti-analysis techniques.

---

## Relocation table inspection

**Context:** Identifying position-independent references and understanding how the binary was designed to load at different base addresses — important for ASLR compatibility and exploit development.

```python
import pefile

pe = pefile.PE('application.exe')

if hasattr(pe, 'DIRECTORY_ENTRY_RELOCATION') and pe.DIRECTORY_ENTRY_RELOCATION:
    print(f"Total relocation blocks: {len(pe.DIRECTORY_ENTRY_RELOCATION)}")
    
    for reloc_block in pe.DIRECTORY_ENTRY_RELOCATION:
        print(f"Block at VA: 0x{reloc_block.VirtualAddress:x}, "
              f"Size: {reloc_block.SizeOfBlock}, "
              f"Entries: {len(reloc_block.entries)}")
        
        # Print first few relocations
        for reloc in reloc_block.entries[:5]:
            print(f"  Type: {reloc.type}, RVA: 0x{reloc.rva:x}")
else:
    print("No relocations found (binary is position-dependent or RIP-relative)")

# Significance: if a binary has no relocations, it is reliant on a
# fixed ImageBase address and may fail to load at alternative addresses
```

**MITRE ATT&CK:** [T1106 (Native API)](https://attack.mitre.org/techniques/T1106/) — relocation tables are critical for understanding memory layout and implementing code injection that preserves relocation integrity.

---

## Debug information extraction

**Context:** Recovering debug metadata — PDB paths, source file names, symbol tables — which can leak information about build systems and source locations.

```python
import pefile

pe = pefile.PE('application.pdb')

if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') and pe.DIRECTORY_ENTRY_DEBUG:
    for debug_entry in pe.DIRECTORY_ENTRY_DEBUG:
        print(f"Debug type: {debug_entry.Type}")  # 2 = CodeView (CV), 1 = COFF
        print(f"Size: {debug_entry.SizeOfData}")
        
        if debug_entry.Type == 2:  # CodeView
            # CodeView format: 4-byte signature, followed by PDB path string
            raw_data = pe.get_data(debug_entry.PointerToRawData, debug_entry.SizeOfData)
            # Skip first 4 bytes (signature) and decode as ASCII/UTF-8
            pdb_path = raw_data[4:].split(b'\x00')[0].decode('utf-8', errors='ignore')
            print(f"PDB path: {pdb_path}")
else:
    print("No debug directory found")

# Significance: PDB paths can reveal developer machine names, internal paths,
# build systems — valuable OSINT during pre-exploitation reconnaissance
```

**MITRE ATT&CK:** [T1592 (Gather Victim Host Information)](https://attack.mitre.org/techniques/T1592/) — debug metadata is a valuable passive-recon source, leaking internal infrastructure details.

---

## Malware/payload analysis integration

**Context:** Embedding pefile in larger analysis pipelines — staged downloads, payload analysis, behavioral sandboxing.

```python
import pefile
import hashlib
import json

def analyze_binary(binary_path):
    """Analyze a suspected malicious binary."""
    try:
        pe = pefile.PE(binary_path, fast_load=False)
    except pefile.PEFormatError as e:
        return {"error": f"Not a valid PE: {e}"}
    
    analysis = {
        "machine": pe.FILE_HEADER.Machine,
        "sections_count": pe.FILE_HEADER.NumberOfSections,
        "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        "is_64bit": pe.OPTIONAL_HEADER.Magic == 0x20b,
        "is_dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "is_console": pe.OPTIONAL_HEADER.Subsystem == 3,
        "imports": [],
        "exports": [],
        "has_relocs": bool(hasattr(pe, 'DIRECTORY_ENTRY_RELOCATION')),
        "has_debug": bool(hasattr(pe, 'DIRECTORY_ENTRY_DEBUG')),
        "has_cert": bool(hasattr(pe, 'DIRECTORY_ENTRY_CERTIFICATE')),
        "packer": None,
        "warnings": pe.get_warnings()
    }
    
    # Collect imports
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for dll in pe.DIRECTORY_ENTRY_IMPORT:
            for func in dll.imports[:5]:  # First 5 only
                if func.name:
                    analysis["imports"].append({
                        "dll": dll.dll.decode(),
                        "func": func.name.decode()
                    })
    
    # Check for packer in .text section
    text_section = pe.get_section_by_name('.text')
    if text_section:
        data = text_section.get_data()[:4096]  # First 4KB
        packer = pe.match_expr(data)
        if packer:
            analysis["packer"] = packer
    
    return analysis

# Usage in a threat-intelligence pipeline
result = analyze_binary('malware.exe')
print(json.dumps(result, indent=2))
```

**MITRE ATT&CK:** [T1140 (Deobfuscate/Decode Files or Information)](https://attack.mitre.org/techniques/T1140/), [T1027 (Obfuscated Files or Information)](https://attack.mitre.org/techniques/T1027/) — pefile integration in sandboxes and analysis pipelines enables automated triage of suspected payloads.

---

## Binary comparison for patch detection

**Context:** Comparing two binaries (before/after patches) to identify what changed — useful for forensic reconstruction, supply-chain analysis, and verifying patch application.

```python
import pefile
import hashlib

def binary_diff_summary(before_path, after_path):
    """Compare two binaries at the PE header level."""
    pe_before = pefile.PE(before_path)
    pe_after = pefile.PE(after_path)
    
    differences = {}
    
    # Compare basic headers
    if pe_before.FILE_HEADER.TimeDateStamp != pe_after.FILE_HEADER.TimeDateStamp:
        differences['timestamp'] = f"{pe_before.FILE_HEADER.TimeDateStamp} -> {pe_after.FILE_HEADER.TimeDateStamp}"
    
    if pe_before.OPTIONAL_HEADER.AddressOfEntryPoint != pe_after.OPTIONAL_HEADER.AddressOfEntryPoint:
        differences['entry_point'] = f"0x{pe_before.OPTIONAL_HEADER.AddressOfEntryPoint:x} -> 0x{pe_after.OPTIONAL_HEADER.AddressOfEntryPoint:x}"
    
    # Compare section counts
    if pe_before.FILE_HEADER.NumberOfSections != pe_after.FILE_HEADER.NumberOfSections:
        differences['section_count'] = f"{pe_before.FILE_HEADER.NumberOfSections} -> {pe_after.FILE_HEADER.NumberOfSections}"
    
    # Compare section hashes (detect code changes)
    for sec_name in ['.text', '.data', '.rsrc']:
        sec_before = pe_before.get_section_by_name(sec_name)
        sec_after = pe_after.get_section_by_name(sec_name)
        
        if sec_before and sec_after:
            hash_before = hashlib.sha256(sec_before.get_data()).hexdigest()
            hash_after = hashlib.sha256(sec_after.get_data()).hexdigest()
            
            if hash_before != hash_after:
                differences[f'{sec_name}_changed'] = True
    
    return differences

# Usage
diffs = binary_diff_summary('kernel32_before.dll', 'kernel32_after.dll')
if diffs:
    print(f"Differences detected: {diffs}")
else:
    print("Binaries are identical at the PE header level")
```

**MITRE ATT&CK:** [T1552 (Unsecured Credentials)](https://attack.mitre.org/techniques/T1552/) and forensic-reconstruction contexts — detecting patch application status and supply-chain modifications.

---

## Suspicious-value detection and flagging

**Context:** Identifying anomalies in PE headers that indicate malware, corruption, or unusual build artifacts.

```python
import pefile

def check_suspicious_pe(binary_path):
    """Audit a PE for suspicious header values."""
    pe = pefile.PE(binary_path)
    flags = []
    
    # Check for suspicious characteristics
    if pe.FILE_HEADER.Characteristics & 0x0001:
        flags.append("RELOCATION_INFO_STRIPPED: Unusual on user binaries")
    
    if pe.OPTIONAL_HEADER.Magic == 0x107:
        flags.append("ROM_IMAGE: Very rare in practice")
    
    # Check for anomalous entry point (pointing to non-code section)
    ep_section = pe.get_section_by_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    if ep_section and ep_section.Name.decode().strip() == '.rsrc':
        flags.append("Entry point in .rsrc: Highly suspicious")
    
    # Check for zero entry point (e.g., DLLs without entry point)
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0 and not (pe.FILE_HEADER.Characteristics & 0x2000):
        flags.append("Zero entry point on non-DLL: Malformed")
    
    # Check timestamp (Jan 1, 1970 is often malware/test binaries)
    if pe.FILE_HEADER.TimeDateStamp == 0:
        flags.append("Timestamp = 0 (Jan 1, 1970): Likely malware or test binary")
    
    # Check for suspiciously small code section
    text = pe.get_section_by_name('.text')
    if text and text.VirtualSize < 0x100:
        flags.append(".text section < 256 bytes: Likely packed or stub")
    
    # Check for no imports (very rare)
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        flags.append("No imports: Shellcode or statically-linked — unusual for user binaries")
    
    # Return built-in pefile warnings
    flags.extend(pe.get_warnings())
    
    return flags

# Usage
suspicious_flags = check_suspicious_pe('malware.exe')
if suspicious_flags:
    print("Suspicious flags detected:")
    for flag in suspicious_flags:
        print(f"  - {flag}")
```

**MITRE ATT&CK:** [T1027 (Obfuscated Files or Information)](https://attack.mitre.org/techniques/T1027/), [T1140 (Deobfuscate/Decode Files or Information)](https://attack.mitre.org/techniques/T1140/) — anomaly detection in PE headers is a standard malware-triage technique.

---

## Basic PE modification

**Context:** Overwriting specific header fields for payload staging, testing, or evasion — e.g., changing entry point, subsystem, DLL characteristics.

```python
import pefile
import shutil

# IMPORTANT: Only modify copies; original forensic artifacts must be preserved
binary_path = 'test.exe'
backup_path = binary_path + '.bak'
shutil.copy(binary_path, backup_path)

pe = pefile.PE(binary_path)

# Example: Change entry point (would cause execution to jump elsewhere)
# This is used in some exploit-development workflows to redirect code flow
original_ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x5000

print(f"Entry point changed from 0x{original_ep:x} to 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")

# Example: Change subsystem (from GUI to console or vice versa)
# pe.OPTIONAL_HEADER.Subsystem = 3  # 2 = GUI, 3 = Console

# Example: Update checksum (checksum field is rarely actually validated,
# but for completeness, one would need to recalculate it)
# pe.OPTIONAL_HEADER.CheckSum = calculate_checksum(pe)  # Not built into pefile

# Write modified PE to disk
pe.write(binary_path)
print(f"Modified PE written to {binary_path}")

# NOTE: pefile's write() capability is limited and carries risk —
# it cannot rearrange structures or resize sections, only overwrite
# existing fields. Use with extreme caution in production.
```

**MITRE ATT&CK:** [T1140 (Deobfuscate/Decode Files or Information)](https://attack.mitre.org/techniques/T1140/) — modifying PE headers is used in unpacking, re-hosting, and exploit-development workflows.

---

## Bulk PE enumeration across a filesystem

**Context:** Scanning a directory or artifact collection to triage binaries — classify by architecture, identify outliers, detect packed files.

```python
import pefile
import os
from pathlib import Path

def scan_binaries(directory, extensions=['.exe', '.dll', '.sys']):
    """Scan a directory for PE binaries and collect metadata."""
    results = []
    
    for ext in extensions:
        for filepath in Path(directory).glob(f'**/*{ext}'):
            try:
                pe = pefile.PE(str(filepath), fast_load=True)
                
                entry = {
                    'path': str(filepath),
                    'is_64bit': pe.OPTIONAL_HEADER.Magic == 0x20b,
                    'is_dll': bool(pe.FILE_HEADER.Characteristics & 0x2000),
                    'timestamp': pe.FILE_HEADER.TimeDateStamp,
                    'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                }
                
                # Check for packer (quick check on .text section)
                text = pe.get_section_by_name('.text')
                if text:
                    data = text.get_data()[:2048]
                    packer = pe.match_expr(data)
                    entry['packer'] = packer
                
                results.append(entry)
            except (pefile.PEFormatError, Exception) as e:
                # Log non-PE files or corrupted files
                pass
    
    return results

# Usage: Find all 64-bit DLLs in System32
scan_results = scan_binaries('C:\\Windows\\System32', extensions=['.dll'])
for result in scan_results:
    if result['is_64bit'] and result['is_dll']:
        print(f"{result['path']}: {result.get('packer', 'unpacked')}")
```

**MITRE ATT&CK:** [T1518 (Software Discovery)](https://attack.mitre.org/techniques/T1518/), [T1087 (Account Discovery)](https://attack.mitre.org/techniques/T1087/) — binary enumeration is a reconnaissance step in exploit development and targeted-malware tailoring.

---

