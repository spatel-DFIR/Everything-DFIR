## Hunting Priority Table

| Signal | Rank |
|--------|------|
| Persistent HTTPS connection + periodic small frames (keep-alive) | #1 |
| HTTP/2 protocol on non-web port (8080, 8888) | #2 |
| Process name chisel or renamed variant | #3 |
| TLS SNI mismatch (SNI ≠ cert CN) | #4 |
| Command-line arguments (chisel client/server flags) | #5 |

## Windows Hunting

```powershell
# Sysmon Event 1: Process creation
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {$_.Properties[20].Value -like '*chisel*'} |
  Format-Table TimeCreated, @{Label='CommandLine'; Expression={$_.Properties[20].Value}}

# Network connections to suspicious ports
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in @(8080, 8888, 31337)}

# Event 5156: Network connections
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156} |
  Where-Object {$_.Properties[13].Value -notin @(80, 443, 8443)}
```

## Linux Hunting

```bash
ps aux | grep -i chisel
netstat -tnp | grep 8080
lsof -i :8080
grep chisel ~/.bash_history
```

## PCAP Analysis

```bash
tcpdump -i any -w tunnel.pcap 'tcp port 8080 and (tcp[tcpflags] & tcp-syn) != 0'
tshark -r tunnel.pcap -Y "http2.type == 0x04" -V | head -30
```

## Remediation

1. Capture process/network state before killing
2. Kill process: killall -9 chisel
3. Firewall rule: Block IP of server
4. Check persistence: cron, Task Scheduler, services
5. Memory dump if available
