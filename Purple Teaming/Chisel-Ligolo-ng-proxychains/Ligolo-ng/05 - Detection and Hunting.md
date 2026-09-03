## Hunting Priority Table

| Signal | Rank |
|--------|------|
| TUN interface creation + kernel routes | #1 (relay-side; most obvious) |
| Persistent connection to port 11601 | #2 |
| Process: ligolo-ng agent with -connect flag | #3 |
| Scheduled task/cron with ligolo-ng | #4 |
| Memory: Relay address in agent process strings | #5 |

## Windows Hunting

```powershell
# Sysmon Event 1
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=1} |
  Where-Object {$_.Properties[20].Value -like '*ligolo*'}

# Network: Port 11601
Get-NetTCPConnection | Where-Object {$_.RemotePort -eq 11601}
```

## Linux Hunting

```bash
ps aux | grep ligolo
netstat -tnp | grep 11601
ip link show | grep tun
ip route show | grep tun0
grep ligolo ~/.bash_history
```

## Relay-Side Detection (Attacker Host)

```bash
# TUN interface is definitive
ip link show | grep tun
# Processes listening on 11601
lsof -i :11601
# Routes to internal subnets
ip route show | grep 241.  # Ligolo uses 241.x.x.x by default
```

## Remediation

1. Kill agent process
2. On relay: Remove TUN interface (ip link del tun0)
3. Remove routes (ip route del ...)
4. Firewall: Block port 11601 to relay IP
5. Check persistence (cron, Task Scheduler, systemd services)
