# JuicyPotato — Target Evidence

## Target-side artifacts

JuicyPotato does not perform actions on the target itself—only the spawned child process does. Target-side evidence is therefore **what the spawned command does**, not JuicyPotato's own actions.

### Process execution anomalies

**Expected parent-child relationship on target:**
- **COM service running as SYSTEM** (e.g., spoolsv.exe, wlms.exe, OneSyncSvc, or another service)
  - └─ **Spawned process** (e.g., cmd.exe, powershell.exe, custom payload)

However, modern EDR logging may attribute the spawned process directly to the **JuicyPotato.exe** parent or show the COM service as parent, depending on how the RPC/COM context is resolved.

**Sysmon Event 1 (Process Create):**
- **ParentImage:** COM service or JuicyPotato parent.
- **Image:** The spawned process (e.g., `cmd.exe`).
- **User:** `NT AUTHORITY\SYSTEM`.
- **CommandLine:** The command specified by `-a`.

### Event Logs

#### Windows Event 4688 (Process Creation)

Similar to PrintSpoofer, but the parent is a **COM object**, not Print Spooler. This can vary by CLSID.

#### Sysmon Event 1 (Process Create)

Captures the spawned process and its SYSTEM context. The parent may be ambiguous depending on the COM object used.

### File/Registry/Network artifacts

Same as PrintSpoofer—**all artifacts come from the spawned child process**, not JuicyPotato. Examples:

- **Credential dump output file** (if `-p "mimikatz.exe"`).
- **Reverse shell outbound connection** (if `-p "nc.exe"` with network arguments).
- **Registry modifications** (if the spawned command modifies HKLM).
- **Scheduled task creation** (if the spawned command uses `schtasks`).

### Timeline reconstruction

| Time | Event | Source |
|---|---|---|
| 14:23:45 | JuicyPotato.exe execution | Sysmon 1 |
| 14:23:45 | COM server binds to local port | (Not directly logged) |
| 14:23:46 | SYSTEM-context process spawned | Sysmon 1 (Process Create) |
| 14:23:46 | Child process executes command | Sysmon 11 (FileCreate), Sysmon 3 (Network) |
| 14:23:47 | Output file written | Sysmon 11 (FileCreate) |
| 14:23:47 | Child process exits | Sysmon 5 (Process Terminated) |

---

## Distinguishing JuicyPotato from other Potato tools

| Tool | Distinctive Signature | Parent Process |
|---|---|---|
| **JuicyPotato** | Spawned SYSTEM child; parent is COM-service-dependent (varies by CLSID). | Varies (COM object instantiation). |
| **PrintSpoofer** | Spawned SYSTEM child of spoolsv.exe (Print Spooler). | `spoolsv.exe` (fixed). |
| **RoguePotato** | Spawned SYSTEM child; involves RPC relay from external redirector machine. | May show network RPC activity. |

**JuicyPotato detection difficulty:** The parent process varies, making it harder to detect than PrintSpoofer (which always involves Print Spooler). However, the **CLSID in the command line** is a tell.

---

## Summary

JuicyPotato's target evidence is essentially **identical to PrintSpoofer** (a SYSTEM-context child process) but with the added complexity that the **parent COM service varies** depending on the CLSID used. Defenders should hunt for the process-tree anomaly (low-privilege context → SYSTEM child) rather than a specific parent process name, since JuicyPotato's parent is variable.
