# RoguePotato — Source Evidence

## Attacker-side artifacts

RoguePotato's source-side evidence is similar to PrintSpoofer/JuicyPotato (process-based) but includes **network traffic** to the redirector, adding an observable dimension absent in the other two.

### Process execution

**RoguePotato.exe process:**
- Runs as service account (e.g., MSSQL, NETWORK SERVICE).
- Initiates RPC traffic to the redirector (`-r <IP>:<port>`).
- Waits for relayed SYSTEM token.
- Spawns child process (specified by `-e`) as SYSTEM.
- Exits after the spawned child is running.

**Sysmon Event 1 signature:**
```
ParentImage: C:\Path\To\RoguePotato.exe (or renamed)
Image: cmd.exe / powershell.exe / payload.exe
User: NT AUTHORITY\SYSTEM
```

### Network artifacts (distinctive)

**RoguePotato → Redirector traffic:**

| Direction | Protocol | Indicator | Significance |
|---|---|---|---|
| **Target → Redirector** | RPC (TCP, typically high port) | Outbound connection from service account to attacker-controlled IP | **Highly suspicious** — direct pivot point indicator. |
| **Redirector → Target** | RPC relay response | Return traffic with SYSTEM-context RPC data | Completes the exploit handshake. |

**Network observables:**
- **Source IP:** Target machine (service account context).
- **Destination IP:** Redirector machine (attacker-controlled, e.g., 10.10.10.10).
- **Port:** Typically high ephemeral (redirector port, e.g., 9999).
- **Protocol:** RPC (raw TCP, not HTTP/HTTPS).
- **Volume:** Brief burst of RPC traffic (exploit is fast, ~1-2 seconds).

**Zeek/Snort signature pattern:**
```
TCP flow: <target> → <attacker_redirector>:<high_port>
RPC protocol on non-standard port (port != 135)
Duration: <5 seconds
Data volume: Small (RPC headers + SYSTEM token data)
```

### Command-line artifacts

**RoguePotato command line:**
```
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe"
```

**Stored in:**
- Sysmon Event 1.
- Windows Event 4688.
- PowerShell history (if invoked from PowerShell).

**Distinctive indicators:**
- `-r <external_IP>:<port>` — Immediately reveals the redirector address (critical Intel for defenders).
- `-e <command>` — The attacker's goal.

### Artifact retention

| Artifact | Retention | Notes |
|---|---|---|
| Process tree (Sysmon 1) | Until exit; logs persist. | Covers RoguePotato spawn and child process spawn. |
| Command line (Sysmon 1, Event 4688) | Same as process tree. | **Reveals the redirector IP** — a major give-away. |
| Network flow logs (Zeek, NetFlow) | Until log rotation. | RPC traffic to external IP is **permanently logged** if network monitoring is active. |
| RoguePotato binary | On disk (if staged). | Can be deleted by operator. |

---

## Summary

**RoguePotato source artifacts:**
1. **Process tree:** Service account running RoguePotato → SYSTEM-context child.
2. **Command line:** Exposes the redirector IP (`-r` flag).
3. **Network traffic:** Outbound RPC connection to the redirector (highly observable).

**Key difference from PrintSpoofer/JuicyPotato:** The **network traffic is the smoking gun**. Defenders running network monitoring (Zeek, NetFlow, firewall logs) will detect the outbound RPC connection to the attacker's redirector, making RoguePotato significantly noisier than its predecessors.
