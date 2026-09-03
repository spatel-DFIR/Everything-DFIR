# PrinterBug — Detection and Hunting

---

## Hunting on Source

```bash
# Look for printerbug / spoolsample process
ps aux | grep -i "printerbug\|spoolsample"

# Check shell history
grep -i printerbug ~/.bash_history

# Monitor Responder for DC$ captures
tail -f logs/SMB-NTLMv2-Client-*.txt | grep "\$::"
```

---

## Hunting on Target (DC)

### Hunt 1: Event 5156 — Print Spooler Outbound SMB

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object {
  $_.Message -match "spoolsv.exe|PrintSpooler" -and
  $_.Message -match "445"
}
```

### Hunt 2: Print Spooler Logs

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PrintService/Operational'
  ID=@(1010, 1014)
  StartTime=(Get-Date).AddHours(-24)
}
```

### Hunt 3: RPC Port 135 + Outbound 445 Correlation

```powershell
# Events within 5 seconds: port 135 query + port 445 outbound
# Indicates RPC coercion pattern
```

---

## Evasion Resistance Ranking

| Signal | Resistance |
|---|---|
| **Event 5156 spoolsv.exe outbound** | Very High — native Windows audit |
| **Outbound port 445 from Print Spooler** | Very High — network observable |
| **Event 1010 (printer enumeration)** | High — service logs default-on |
| **RPC Endpoint Mapper query** | Medium-High — observed in port 135 traffic |

---

## Detection Rule (Sigma)

```yaml
title: PrinterBug - Print Spooler RPC Coercion
logsource:
  product: windows
  service: security
detection:
  network_outbound:
    EventID: 5156
    Image|endswith: spoolsv.exe
    DestinationPort: 445
    DestinationIp: NOT ("192.168.*" OR "10.0.*")
  condition: network_outbound
falsepositives:
  - Legitimate printer drivers updating
  - Print server replication
```

---

## Most Evasion-Proof Signal

**Event 5156 (spoolsv.exe outbound 445)** is nearly impossible to hide:
- Only deletable via admin privileges.
- Backed up by system logging infrastructure.
- Correlates directly to RPC coercion pattern.

---

**Next:** See `00 - Coercion Primitives Overview.md` for comparison.
