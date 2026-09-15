# Coercer — Target Evidence

Evidence on victim (target) host after Coercer coercion.

---

## Event Logs

### Event ID 5156 (Network Connection Allowed)

**Location:** Security Event Log

When target RPC service connects to attacker's IP (coercion callback):

```
Event ID: 5156
Application Name: C:\Windows\System32\svchost.exe (RPC service)
Direction: Outbound
Source Address: 192.168.1.10 (target DC)
Source Port: 50000 (ephemeral)
Destination Address: 192.168.1.99 (attacker)
Destination Port: 445 (SMB) or 139 (NetBIOS) or custom
Protocol: TCP
Filter: EFS RPC / Print Spooler / VSS
Action: Allow
```

**Red flags:** Outbound connection from DC to unexpected external IP, especially on port 445/139.

### Event ID 4625 (Authentication Failure) — Optional

If Coercer uses a low-privilege account that fails RPC bind:

```
Event ID: 4625
Logon Type: 3 (Network)
Failure Code: C0000022 (STATUS_ACCESS_DENIED)
Process Name: C:\Windows\System32\svchost.exe
Source IP: 192.168.1.99 (attacker)
```

### Event ID 4648 (Explicit Credentials)

If coercion forced credential usage:

```
Event ID: 4648
Logon Type: 9 (NewCredentials)
Process: svchost.exe (RPC service)
Target User: attacker (if relay succeeded)
Target Server: <attacker-ip>:445
```

---

## RPC/SMB Protocol Artifacts

### RPC connection from target to attacker

**netstat / ss on target:**
```bash
netstat -ano | grep 192.168.1.99
# TCP    192.168.1.10:50000  192.168.1.99:445   ESTABLISHED
```

### Network packet trace (tcpdump)

```
Packet: SMB_NEGOTIATE (from target to attacker)
  Source: 192.168.1.10:50000
  Destination: 192.168.1.99:445
  
Packet: NTLMSSP_NEGOTIATE (RPC auth)
  User: CORP\DC01$
  Domain: CORP
```

---

## Service-Specific Logs

### EFS (Encrypting File System) coercion

**Location:** Event Viewer → Applications and Services Logs → Microsoft-Windows-NTFS → Operational

```
Event ID: 1008 (EFS Activity)
Activity: File encryption operation initiated
Source: RPC call from <attacker-ip>
File Path: (temporary EFS work path)
Timestamp: [time of coercion]
```

### Print Spooler coercion

**Location:** Event Viewer → Applications and Services Logs → Microsoft-Windows-PrintService

```
Event ID: 307 (Document printed)
Document: (printer job from coercion)
Printer: (attacker's printer UNC path)
Status: Job sent to <attacker-ip>
```

### VSS / ShadowCoerce

**Location:** Event Viewer → Applications and Services Logs → Microsoft-Windows-Backup

```
Event ID: 1018 (Shadow Copy created)
Source: RPC call / VSS
Destination: <attacker-ip>:\share
```

---

## File System Artifacts

**Temporary files created during coercion:**
- `C:\Windows\Temp\<random>.tmp` — EFS temp files
- `C:\ProgramData\Microsoft\Windows\PrintService\...` — Printer job spool
- `C:\$Recycle.Bin\<guid>` — VSS temporary objects (if coercion triggers VSS operations)

---

## Strongest Signals (Target)

1. **Event 5156 (outbound connection)** from DC to unexpected external IP on port 445/139 — nearly impossible to hide without disabling auditing.
2. **Outbound SMB connection from system process (svchost)** — legitimate services don't typically connect outbound to random IPs.
3. **Combination of Event ID + network connection + RPC protocol** — Correlating all three is definitive.

---

**Next:** See `05 - Detection and Hunting.md`.
