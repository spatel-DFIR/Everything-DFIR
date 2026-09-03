# DefenderCheck — Hands-On Use Cases

## Use Case 1: Iterative Payload Obfuscation — Custom C2 Beacon

**Scenario:** A red-team operator has compiled a custom Cobalt Strike beacon variant (using Artifact Kit or custom source). Defender flags the beacon on download. The operator uses DefenderCheck to identify the flagged bytes, then modifies the beacon source to bypass detection.

**Step 1: Initial Test**
```bash
# Copy the compiled beacon to an isolated test host with Defender enabled
# Disable real-time protection temporarily
DefenderCheck.exe C:\Tools\beacon.exe
```

**Expected Output:**
```
DefenderCheck.exe - Identify the bytes that Microsoft Defender flags on
Type: VirTool:Win32/Generickd!mt (or similar signature)
File size: 262144
Flagged bytes at offset: 0x1A2F0
00000000: 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 ...
[continues with hex dump]
```

**Step 2: Analyze & Modify**
The operator identifies that bytes at offset `0x1A2F0` are flagged. This might be:
- A hardcoded C2 server address string.
- A known API call sequence (e.g., `GetProcAddress` followed by `CreateRemoteThread`).
- A PE header pattern or resource section.

The operator modifies the beacon source:
- If it's a string: replace the server address with a variable or encrypted constant.
- If it's an API call pattern: insert a garbage instruction or split the sequence.
- If it's a PE header: apply custom header obfuscation (e.g., add extra sections, modify timestamps).

**Step 3: Recompile & Re-test**
```bash
# Recompile the beacon with modifications
csc.exe /target:exe /out:beacon_v2.exe beacon_modified.cs

# Re-run DefenderCheck
DefenderCheck.exe C:\Tools\beacon_v2.exe
```

**Expected Outcome:**
- If modifications were sufficient, DefenderCheck outputs "No threat found."
- If Defender still flags it, DefenderCheck identifies a *different* offset, indicating that the previous obfuscation worked but another signature exists.
- The operator repeats the cycle: modify, recompile, re-test.

**MITRE ATT&CK Mapping:**
- **T1140** - Deobfuscate/Decode Files or Information (using DefenderCheck to guide obfuscation).
- **T1036** - Masquerading (modifying signatures to avoid detection).
- **T1027** - Obfuscated Files or Information (iterative obfuscation).

---

## Use Case 2: Testing Encoding Schemes — XOR-Encoded Shellcode

**Scenario:** A red-team operator has shellcode (raw byte sequence) that executes `cmd.exe` with reverse shell behavior. Defender detects raw shellcode. The operator encodes it with XOR, wraps it in a stub that decodes at runtime, and uses DefenderCheck to verify evasion.

**Step 1: Create Encoded Payload**
```c
// original_shellcode.bin — raw shellcode, detected by Defender
// encoder.c — simple XOR encoder
unsigned char shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, ... }; // Original

unsigned char encoded[sizeof(shellcode)];
for (int i = 0; i < sizeof(shellcode); i++) {
    encoded[i] = shellcode[i] ^ 0xAA; // XOR with key 0xAA
}

// decoder_stub.c — wraps encoded shellcode with runtime decoder
// Decodes at execution time before jumping to shellcode
```

**Step 2: Compile & Test**
```bash
# Compile the stub + encoded shellcode into an executable
cl.exe /out:decoder_stub.exe decoder_stub.c

# Test against Defender
DefenderCheck.exe C:\Tools\decoder_stub.exe
```

**Expected Output (Detection):**
```
File size: 131072
Flagged bytes at offset: 0x2000
Signature: Trojan:MSIL/Exeloaded!b
[hex dump of flagged region]
```

**Step 3: Analyze Failure**
The flagged bytes might reveal:
- The encoded shellcode itself is still recognizable (pattern matching on encoded form).
- The decoder stub's API call sequence is flagged (e.g., `VirtualAlloc` → `memcpy` → `CreateThread` signature).
- The PE header or import table is flagged.

**Step 4: Iterate**
- If the encoded shellcode is flagged: try a different encoding scheme (RC4, AES, custom cipher).
- If the decoder API sequence is flagged: split the sequence with junk code or indirect calls.
- Recompile and re-test.

**MITRE ATT&CK Mapping:**
- **T1027** - Obfuscated Files or Information (encoding the shellcode).
- **T1140** - Deobfuscate/Decode Files or Information (runtime decoding).
- **T1055** - Process Injection (if the shellcode performs injection).

---

## Use Case 3: Batch Scanning Payload Variants

**Scenario:** A red-team operator has compiled multiple variants of a custom tool (different feature flags, hardcoded C2 servers, etc.). They want to quickly identify which variants are detected and which are clean, to select the cleanest variant for deployment.

**Step 1: Create a Batch Script**
```batch
@echo off
REM scan_payloads.bat — batch scan multiple payloads
setlocal enabledelayedexpansion

for %%F in (C:\Payloads\variant_*.exe) do (
    echo.
    echo Scanning: %%F
    DefenderCheck.exe %%F > results_%%~nF.txt 2>&1
    
    if errorlevel 1 (
        echo [DETECTED] %%F >> detection_log.txt
    ) else (
        echo [CLEAN] %%F >> detection_log.txt
    )
)

echo.
echo Results saved to detection_log.txt
```

**Step 2: Run the Batch**
```bash
C:\Tools\scan_payloads.bat
```

**Expected Output:**
```
Scanning: C:\Payloads\variant_1.exe
[DETECTED - flagged at 0x5A00]

Scanning: C:\Payloads\variant_2.exe
[DETECTED - flagged at 0x6B20]

Scanning: C:\Payloads\variant_3.exe
[CLEAN - No threat found]

Detection log written to detection_log.txt
```

**Step 3: Select & Deploy**
The operator selects `variant_3.exe` (clean) for deployment, knowing it passes Defender checks on the target network.

**MITRE ATT&CK Mapping:**
- **T1036** - Masquerading (selecting the variant that avoids detection).
- **T1140** - Deobfuscate/Decode Files or Information (if variants use different obfuscation techniques).

---

## Use Case 4: Research — Understanding Defender's Signature Scope

**Scenario:** A security researcher wants to understand how Defender's signature for a known malware family (e.g., a specific ransomware variant) is structured. They compile the original source, run DefenderCheck to identify the flagged bytes, then modify them in isolation to understand the signature's boundaries.

**Step 1: Baseline Detection**
```bash
DefenderCheck.exe C:\Malware\ransomware_original.exe
```

**Output:**
```
Flagged bytes at offset: 0x10000, length: 32 bytes
00010000: 52 61 6E 73 6F 6D 77 61 72 65 5F 56 31 5F 47 ...
[Hex dump of 32 bytes]
```

**Step 2: Targeted Modification**
The researcher extracts those 32 bytes and creates three test binaries:
1. Original (with flagged bytes unchanged) — **will detect**.
2. First half modified (first 16 bytes XORed) — **test to see if the signature is position-specific**.
3. Second half modified (last 16 bytes XORed) — **test to see which half of the 32 bytes is critical**.

**Step 3: Re-test Each**
```bash
DefenderCheck.exe test_original.exe      # Expected: DETECTED
DefenderCheck.exe test_half1_modified.exe # Expected: DETECTED or CLEAN?
DefenderCheck.exe test_half2_modified.exe # Expected: DETECTED or CLEAN?
```

**Expected Findings:**
- If both halves separately are CLEAN but together are DETECTED → Defender's signature requires the **full 32-byte sequence**.
- If modifying the first 16 bytes makes it CLEAN → The signature focuses on the **first half** (likely the ransomware's encryption key or a magic constant).
- If modifying the second 16 bytes makes it CLEAN → The signature focuses on the **second half** (likely an API call pattern or code segment).

**Insight Gained:**
The researcher can now write a detailed analysis of Defender's signature, informing:
- How broad the signature is (family-wide vs. specific variant).
- Whether the signature is a **static pattern** (exact bytes) or **semantic** (API call sequences, etc.).
- How much obfuscation is required to bypass it.

**MITRE ATT&CK Mapping:**
- **T1036** - Masquerading (modifying malware to understand evasion requirements).
- **T1140** - Deobfuscate/Decode Files or Information (reverse-engineering Defender's signatures).

---

## Use Case 5: Post-Engagement Cleanup Risk — Evidence Recovery

**Scenario:** A red-team operator used DefenderCheck during an engagement to test custom payloads on the target network. The engagement ends; the operator cleans up and leaves the host. Days later, a blue-team analyst acquires a forensic image of that host and hunts for evidence of the red-team activity.

**Why This Matters for Defenders:**
DefenderCheck itself leaves **no persistent disk artifacts** (temporary test files are auto-cleaned), but the **fact that Defender was disabled** is itself suspicious. The operator must have:
1. Disabled real-time protection (registry change: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring`).
2. Disabled automatic sample submission (registry change).
3. Potentially created a scheduled task or script to re-enable Defender after testing (leaving cleanup scripts in AppData or Temp).

**Step 1: Forensic Acquisition**
The blue-team analyst acquires the suspect host's disk image (via forensic tool, BitLocker recovery key, etc.).

**Step 2: Hunt for Defender Disablement**
The analyst queries:
```registry
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\DisableRealtimeMonitoring
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\DisableRealtimeMonitoring
```

**Expected Finding (If DefenderCheck was used):**
```
DisableRealtimeMonitoring = 1 (DWORD)
LastModified = <timestamp during suspected intrusion period>
```

**Step 3: Look for Reenablement Scripts**
The analyst searches `C:\Temp\`, `%TEMP%\`, AppData for batch/PowerShell scripts that re-enable Defender:
```batch
# Suspicious script left behind: re-enable.bat
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false"
```

**Step 4: Correlate with Event Log**
The analyst searches Windows Event Logs:
- **Event ID 5000** (Defender service started/stopped).
- **Event ID 1001/1002** (Threat detected/quarantined) — sudden absence of expected detections during a suspected intrusion window.
- **System event log** — registry changes related to Defender policy.

**MITRE ATT&CK Mapping:**
- **T1562.001** - Disable or Modify Tools (disabling Defender to allow DefenderCheck and custom payloads to run).
- **T1564** - Hide Artifacts (DefenderCheck's auto-cleanup, or operator cleanup of Defender disable scripts).

---

## Summary Table — When Each Use Case Applies

| Use Case | When It Happens | Attacker Goal | Defender Hunting Focus |
|---|---|---|---|
| **1: Iterative Beacon Obfuscation** | During payload development, pre-deployment. | Ensure custom C2 beacon passes Defender on target. | Registry/event log showing Defender disabled; process execution of DefenderCheck; sudden surge in payload compilation. |
| **2: Encoding Scheme Testing** | During evasion technique development. | Verify encoding scheme bypasses signature detection. | Same as above; also look for encoder/decoder stubs in source code or temp files. |
| **3: Batch Variant Scanning** | After compiling multiple tool variants. | Select the cleanest variant for operational deployment. | Batch scripts invoking DefenderCheck; results files listing variant detection status. |
| **4: Signature Research** | During tool/malware analysis for publication. | Understand Defender's signature structure for research writeup. | DefenderCheck usage on lab/research networks (less suspicious than operational networks); publication of findings online. |
| **5: Post-Engagement Cleanup Risk** | After red-team operation (blue-team forensics). | Attacker is gone; blue team hunts for evidence. | Defender disable registry keys; Defender-reenablement scripts; event log gaps; DefenderCheck executable left behind. |

---

## Key Evasion Workflow — The Complete Cycle

```
1. Compile custom payload (e.g., beacon.exe)
   ↓
2. Run DefenderCheck against it
   ↓
   ├─→ CLEAN? → Proceed to deployment.
   └─→ DETECTED? → Identify flagged bytes (step 3)
   ↓
3. Analyze flagged bytes
   ├─→ Is it a hardcoded string? Replace/encrypt it.
   ├─→ Is it an API call pattern? Insert junk or split the call.
   └─→ Is it PE metadata? Apply custom headers.
   ↓
4. Modify source code (step 3 results)
   ↓
5. Recompile payload
   ↓
6. Go to step 2 (re-test)
   ↓
   [Repeat until CLEAN]
```

This cycle is **the standard red-team signature-evasion workflow** — DefenderCheck is the tool that accelerates the feedback loop by pinpointing exactly which bytes need modification.
