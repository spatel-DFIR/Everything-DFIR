# PetitPotam — Target Evidence

**Victim-side (DC) artifacts from PetitPotam coercion.**

---

## Event Logs

### Event ID 5156 (Network Connection)

**Security Event Log:**

```
Event ID: 5156
Source: System (SYSTEM account)
Process: svchost.exe (EFS service)
Direction: Outbound
Source Address: 192.168.1.10 (DC)
Source Port: ephemeral (50000+)
Destination Address: 192.168.1.99 (attacker)
Destination Port: 445 (SMB)
Action: Allow
```

**Red flag:** Outbound SMB from DC to unexpected external IP.

### Event ID 5140 (SMB Object Accessed)

If relay succeeded:

```
Event ID: 5140
Network Share Name: \\192.168.1.99\share
Source Address: 192.168.1.10
Share Access: ReadData
```

### Event ID 4625 (Authentication Failure)

If PetitPotam failed (e.g., EFS not available):

```
Event ID: 4625
Failure Code: C0000225 (STATUS_NOT_FOUND)
Source IP: 192.168.1.99
```

---

## Network Artifacts

**SMB connection:**
```
Packet: SMB_NEGOTIATE
  Source: 192.168.1.10:ephemeral
  Destination: 192.168.1.99:445
  
Packet: NTLMSSP_NEGOTIATE
  User: CORP\DC01$
  Domain: CORP
```

**RPC packets (port 135 Endpoint Mapper):**
```
Packet: RPC EPM_LOOKUP_HANDLE_W
  Source: 192.168.1.99:50000
  Destination: 192.168.1.10:135
  Protocol: efsrpc (UUID 12345678-...)
```

---

## EFS / File Activity

**Event ID 1008 (EFS Activity):**

```
Event ID: 1008
Activity: File encryption initiated
Request Source: RPC from 192.168.1.99
File Path: \\192.168.1.99\share\<filename>
Timestamp: [time of coercion]
```

---

## Strongest Signals (Target)

1. **Event 5156 + outbound SMB + svchost.exe** — Definitive.
2. **Outbound to port 445 from DC to unknown IP** — Highly suspicious.
3. **Event 1008 (EFS RPC)** + **outbound connection** — Coercion confirmed.
4. **RPC Endpoint Mapper query to attacker IP** — Pre-coercion activity.

---

**Next:** See `05 - Detection and Hunting.md`.
