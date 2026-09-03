# PrinterBug — Target Evidence

**Victim (DC) artifacts from PrinterBug coercion.**

---

## Event Logs

### Event ID 5156 (Outbound Network Connection)

```
Event ID: 5156
Process: spoolsv.exe (Print Spooler service)
Direction: Outbound
Source: 192.168.1.10:ephemeral
Destination: 192.168.1.99:445
Action: Allow
```

**Red flag:** Print Spooler initiating outbound SMB is unusual.

### Event ID 1010 / 1011 (Print Spooler Events)

**Location:** Microsoft-Windows-PrintService/Operational

```
Event ID: 1010
Event: Printer added or modified
Printer: \\192.168.1.99\printer$\spooler
```

### Event ID 4625 / 5140 (SMB Access)

If relay succeeded:
```
Event ID: 5140
Share: \\192.168.1.99\share
Access: ReadData/WriteData
```

---

## Network Artifacts

**RPC Endpoint Mapper query:**
```
Packet: EPM_LOOKUP_HANDLE_W
  Source: 192.168.1.99:50000
  Destination: 192.168.1.10:135
  Query: RPRN (Print Server RPC UUID)
```

**SMB connection for printer enumeration:**
```
Packet: SMB_NEGOTIATE
  Source: 192.168.1.10:ephemeral
  Destination: 192.168.1.99:445
  
Packet: NTLMSSP_NEGOTIATE
  User: CORP\DC01$
```

---

## Print Spooler Service Logs

**Location:** System Event Log or Print Service logs

```
Event ID: 1000 (Print Spooler startup)
Event ID: 1010 (Printer enumeration attempt to \\192.168.1.99)
Event ID: 1014 (Printer access failure — expected if attacker's printer is fake)
```

---

## Strongest Signals (Target)

1. **Event 5156: spoolsv.exe outbound SMB to unexpected IP** — Definitive.
2. **Outbound port 445 from Print Spooler** — Highly distinctive.
3. **Event 1010: Printer added/modified pointing to attacker UNC** — Confirms RPRN coercion.
4. **Correlation of RPC port 135 query + SMB 445 outbound** — Coercion pattern.

---

**Next:** See `05 - Detection and Hunting.md`.
