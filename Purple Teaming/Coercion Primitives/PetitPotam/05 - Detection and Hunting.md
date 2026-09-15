# PetitPotam — Detection and Hunting

---

## Hunting on Source (Attacker)

```bash
# Look for PetitPotam process or RPC traffic
ps aux | grep PetitPotam

# Check shell history
grep -i "petitpotam\|EfsRpc" ~/.bash_history

# Monitor Responder for DC$ machine account captures
grep "\$::" logs/SMB-NTLMv2-Client-*.txt
```

---

## Hunting on Target (DC)

### Hunt 1: Event 5156 (Outbound SMB from svchost)

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object {
  $_.Message -match "svchost.exe|lsass.exe" -and
  $_.Message -match "445|139" -and
  $_.Message -notmatch "known-servers"
}
```

### Hunt 2: RPC Endpoint Mapper queries to unknown IPs

```powershell
# Event ID 5156 on port 135
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
} | Where-Object { $_.Message -match "135" }
```

### Hunt 3: EFS activity + outbound network connection correlation

```powershell
# Correlate Event 1008 (EFS) with Event 5156 (network) within 5 seconds
$efsPetitpotam = @()
$events = Get-WinEvent -FilterHashtable @{
  LogName=@('Security','Microsoft-Windows-NTFS/Operational')
}

# Look for EFS event followed closely by outbound 445
```

---

## Evasion Resistance Ranking

| Signal | Evasion Difficulty |
|---|---|
| **Event 5156 outbound SMB** | Very High — native Windows audit |
| **Port 445 outbound from DC to unknown IP** | Very High — visible in netstat / network |
| **RPC Endpoint Mapper activity** | High — observed in port 135 traffic |
| **EFS service logs** | Medium — can be disabled but default-on |
| **PetitPotam process** | Low — short-lived; process terminates quickly |
| **Shell history** | Low — deletable by attacker |

---

## Detection Rules

### Sigma Rule: EFS Coercion

```yaml
title: PetitPotam - EFS RPC Coercion
logsource:
  product: windows
  service: security
detection:
  network_outbound:
    EventID: 5156
    Image|endswith:
      - svchost.exe
      - lsass.exe
    DestinationPort: 445
    DestinationIp: NOT ("192.168.*" OR "10.0.*")
  filter:
    Action: Allow
  condition: network_outbound and filter
falsepositives:
  - Legitimate DFS replication
  - Legitimate administrative shares
```

---

## Most Evasion-Proof Signal

**Combination of:**
1. **Event 5156 (outbound 445 from svchost)**
2. **Source = DC**
3. **Destination = external/unexpected IP**
4. **Timestamp = within 10 seconds of PetitPotam execution**

This triple correlation is **nearly impossible to hide** without disabling all Windows auditing.

---

**Next:** See `00 - Coercion Primitives Overview.md`.
