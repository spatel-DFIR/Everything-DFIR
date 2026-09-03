# JuicyPotato — Source Evidence

## Attacker-side artifacts

JuicyPotato leaves source-side evidence similar to PrintSpoofer: primarily process-based, with minimal file artifacts if the binary is cleaned up.

### Process execution and COM server binding

**JuicyPotato.exe process:**
- Runs with the service account's privileges (e.g., IIS app pool, MSSQL service account).
- Binds a COM server on the local port specified by `-l` (e.g., port 10000).
- Listens for SYSTEM-running services to instantiate the specified CLSID.
- When a SYSTEM process connects, JuicyPotato captures and impersonates its token.
- Spawns the child process (specified by `-p`) as SYSTEM.
- Remains in memory until the spawned child exits (or longer, depending on operator design).

**Sysmon Event 1 signature:**
```
ParentImage: C:\Path\To\JuicyPotato.exe (or renamed binary)
Image: cmd.exe / powershell.exe / payload.exe
User: NT AUTHORITY\SYSTEM (elevation indicator)
```

### Command-line artifacts

**JuicyPotato command line:**
```
JuicyPotato.exe -l 10000 -p "cmd.exe" -a "whoami > C:\temp.txt"
```

**Stored in:**
- Sysmon Event 1 (Process Create).
- Windows Event 4688 (if process auditing enabled).
- PowerShell history (if invoked from PowerShell).
- Memory (Process Environment Block).

**Important:** The `-c <CLSID>` flag exposes the specific CLSID used; defenders can correlate this with known vulnerable COM objects.

### Network artifacts (minimal)

**Local COM binding:**
- JuicyPotato listens on `127.0.0.1:<port>` (specified by `-l`).
- This is **local-only RPC**, not network-visible.
- No outbound network traffic originates from JuicyPotato itself.
- However, if the spawned process (e.g., `nc.exe`, PowerShell reverse shell) initiates network traffic, it appears under that child process.

### Artifact retention

| Artifact | Retention | Notes |
|---|---|---|
| Process tree (Sysmon 1) | Until process exits; logs persist. | Covers the escalation event. |
| Command line | Same as process tree. | Reveals the CLSID, port, and spawned program. |
| JuicyPotato binary | On disk (if written there). | Can be deleted by operator. |
| PowerShell history | Until session closes or cleared. | If invoked from PowerShell. |

### Evidentiary value

**JuicyPotato's source-side evidence is critical for timeline correlation:**

1. **JuicyPotato.exe spawn time** → **Child process spawn time** (typically <1 second difference).
2. **Child process actions** are directly attributable to the escalation event.
3. **CLSID in the command line** reveals the specific exploitation method (useful for threat hunting).

---

## Summary

Source-side evidence for JuicyPotato is similar to PrintSpoofer but includes an additional indicator: **the CLSID in the command line**. Defenders can hunt for specific CLSID values in process-creation events, making JuicyPotato slightly noisier than PrintSpoofer in terms of observability. The legacy nature of the tool (2018, abandoned 2020) means it's less commonly used today, so any sighting should be flagged.
