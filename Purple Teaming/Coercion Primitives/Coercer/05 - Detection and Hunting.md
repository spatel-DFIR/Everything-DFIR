# Coercer — Detection and Hunting

---

## Hunting on Source (Attacker)

### Hunt 1: Coercer process and command-line

```bash
ps aux | grep coercer
# or
ps aux | grep -E "python.*coercer|Coercer"

# Output:
# root 12345 ... python3 -m coercer -u CORP\attacker -p password ...
```

### Hunt 2: Shell history with Coercer commands

```bash
grep -i coercer ~/.bash_history ~/.zsh_history /root/.bash_history
```

### Hunt 3: Responder/ntlmrelayx logs (hash captures)

```bash
grep "CORP\\\\" logs/SMB-NTLMv2-Client-*.txt
# Look for DC$ or service accounts (indicators of coercion)
```

---

## Hunting on Target (Victim / DC)

### Hunt 1: Event 5156 (outbound connections from svchost)

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { 
  $_.Message -match "svchost.exe" -and 
  $_.Message -match "445|139" -and
  $_.Message -notmatch "known-servers"
} | Select-Object TimeGenerated, Message
```

### Hunt 2: Unexpected outbound SMB connections (netstat)

```powershell
Get-NetTCPConnection -State Established | 
  Where-Object { $_.LocalAddress -eq "192.168.1.10" -and $_.RemotePort -eq 445 } | 
  Select-Object RemoteAddress, RemotePort, CreationTime
```

### Hunt 3: RPC service outbound activity (Event 5156 + RPC)

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { 
  $_.Properties[8] -match "System|LocalSystem" -and  # Process user = SYSTEM
  $_.Properties[4] -notmatch "192.168" -and           # Destination not internal
  $_.Properties[5] -eq 445                            # Port 445
}
```

### Hunt 4: EFS coercion artifacts (EFS logs)

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-NTFS/Operational'
  ID=1008
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "RPC|coerce" }
```

### Hunt 5: Print Spooler coercion

```powershell
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-PrintService/Operational'
  ID=307
  StartTime=(Get-Date).AddHours(-24)
} | Where-Object { $_.Message -match "<unexpected-ip>" }
```

---

## Evasion Resistance Ranking

| Signal | Evasion Difficulty |
|---|---|
| **Event 5156 outbound from svchost** | Very High — native audit, can only disable via admin account |
| **Outbound SMB port 445 from DC** | Very High — observed in netstat / network monitoring |
| **RPC call triggering service callback** | Medium-High — logged at RPC level if auditing enabled |
| **Service-specific logs (EFS, Print)** | Medium — can be disabled but logged by default |
| **Coercer process + command-line** | Low — only visible if process running; shell history can be deleted |

---

## Detection Rules (Pseudocode)

### Windows Event Log Correlation

```powershell
# Detect DC initiating outbound SMB to unknown IP
$events = Get-WinEvent -FilterHashtable @{
  LogName='Security'
  ID=5156
  StartTime=(Get-Date).AddHours(-24)
}

$suspicious = $events | Where-Object {
  $_.Properties[1] -match "System|NT AUTHORITY" -and  # Process = system service
  $_.Properties[8] -match "svchost.exe|csrss.exe" -and
  $_.Properties[4] -notin @("192.168.1.1", "192.168.1.2", "192.168.1.3") -and  # Not known gateway/internal
  $_.Properties[5] -eq 445  # SMB port
}

if ($suspicious) {
  Write-Host "Potential Coercer attack detected: outbound RPC coercion"
}
```

### Sysmon Rule (RPC Service Outbound)

```yaml
title: Potential RPC Coercion (Coercer)
logsource:
  product: windows
  service: sysmon
detection:
  outbound_rpc:
    EventID: 3  # Network connection
    SourceIp: 192.168.1.10  # DC
    DestinationPort: 445
    Image|endswith:
      - svchost.exe
      - lsass.exe
      - csrss.exe
  filter_internal:
    DestinationIp:
      - 192.168.*
      - 10.0.*
  condition: outbound_rpc and not filter_internal
falsepositives:
  - Legitimate DFS replication / SMB access
action: alert
```

---

## Mitigation

1. **Prevent coercion:** Disable vulnerable RPC methods at firewall / RPC-level (rare, complex).
2. **Require SMB signing:** Prevents relay attacks even if coercion succeeds.
3. **Monitor Event 5156:** Alert on DC outbound to unknown IPs on 445/139.
4. **Restrict RPC access:** Firewall RPC endpoints (limited effectiveness).
5. **Patch:** Apply Microsoft patches for CVE-2021-36942 (EFS), CVE-2019-1350 (PrinterBug), etc.

---

**Next:** See `00 - Coercion Primitives Overview.md` for comparison with other coercion primitives.
