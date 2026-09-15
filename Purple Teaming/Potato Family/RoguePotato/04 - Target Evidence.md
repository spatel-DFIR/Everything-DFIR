# RoguePotato — Target Evidence

## Target-side artifacts

RoguePotato's target evidence is **identical to PrintSpoofer/JuicyPotato** (a SYSTEM-context spawned process), but adds **network-visible RPC traffic** as an additional indicator absent in the other two.

### Process execution anomalies

**Expected parent-child relationship:**
- **RoguePotato.exe** (parent, service account)
  - └─ **Spawned process** (child, SYSTEM context)

Or, depending on RPC interception:
- **WER or vulnerable RPC service**
  - └─ **Spawned process** (SYSTEM child, via RoguePotato manipulation)

**Sysmon Event 1 (Process Create):**
- **ParentImage:** RoguePotato.exe or service (depends on RPC context).
- **Image:** The spawned process (e.g., `cmd.exe`).
- **User:** `NT AUTHORITY\SYSTEM`.
- **CommandLine:** The command specified by `-e`.

### Event Logs

#### Windows Event 4688 (Process Creation)

Similar to PrintSpoofer; captures the spawned SYSTEM process.

#### Windows Event 5156 (Firewall Allowed Connection) — if WER initiates outbound traffic

If RoguePotato triggers WER to connect to the redirector, Event 5156 may log this outbound RPC connection.

```
Event 5156:
  Application: C:\Windows\System32\wer.exe (or RoguePotato.exe)
  Direction: Outbound
  Remote Address: 10.10.10.10 (redirector IP)
  Remote Port: 9999
  Protocol: TCP/RPC
```

### Network artifacts (distinctive)

**Outbound RPC traffic (visible on network monitors, firewalls):**

```
TCP Connection:
  Source: <target_IP>
  Source Port: <ephemeral>
  Destination: <redirector_IP> (e.g., 10.10.10.10)
  Destination Port: <redirector_port> (e.g., 9999)
  Protocol: RPC
  Duration: <5 seconds
  Data volume: Small (RPC handshake + token relay)
```

**This is the **most distinctive** RoguePotato indicator** — the outbound connection to an external/redirector IP is network-observable, unlike PrintSpoofer/JuicyPotato's local-only operations.

### File/Registry artifacts

Same as PrintSpoofer/JuicyPotato — all artifacts come from the spawned child process. Examples:

- Credential dump output file.
- Reverse shell outbound connection.
- Registry modifications (if the spawned command modifies registry).
- Scheduled task creation (if the spawned command uses `schtasks`).

### Timeline reconstruction

| Time | Event | Source |
|---|---|---|
| 14:23:45 | RoguePotato.exe execution | Sysmon 1 |
| 14:23:45 | Outbound RPC connection to redirector | Firewall log 5156, Zeek flow |
| 14:23:46 | Redirector relays SYSTEM token back | Network monitor |
| 14:23:46 | SYSTEM-context process spawned | Sysmon 1 (Process Create) |
| 14:23:46 | Child process executes command | Sysmon 11 (FileCreate), Sysmon 3 (Network) |
| 14:23:47 | Output file written | Sysmon 11 (FileCreate) |
| 14:23:47 | Child process exits | Sysmon 5 (Process Terminated) |
| 14:23:47 | Outbound RPC connection closes | Firewall log 5158 (connection closed) |

---

## Distinguishing RoguePotato from other Potato tools

| Tool | Distinctive Signature | Network Visibility |
|---|---|---|
| **RoguePotato** | Outbound RPC connection to external/redirector IP; SYSTEM child process. | **High** — network-observable. |
| **PrintSpoofer** | SYSTEM child of spoolsv.exe; no outbound RPC. | **Low** — local-only. |
| **JuicyPotato** | SYSTEM child of variable COM service; no outbound RPC. | **Low** — local-only. |

**RoguePotato is the noisiest** in terms of network visibility.

---

## Summary

**RoguePotato target evidence:**
1. **Process tree:** Service account → SYSTEM child (same as PrintSpoofer/JuicyPotato).
2. **Network traffic:** Outbound RPC connection to redirector IP (unique, highly observable).
3. **Event logs:** 4688 (process creation), possibly 5156 (firewall allowed connection).
4. **Spawned command artifacts:** File/registry/network artifacts depend on the `-e` command.

The **outbound RPC connection is the primary RoguePotato discriminator** — defenders should hunt for unexpected outbound RPC traffic on non-standard ports, especially from service account contexts (MSSQL, WinRM, etc.).
