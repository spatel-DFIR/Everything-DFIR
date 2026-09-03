## Hunting Priority Table

| Signal | Rank |
|--------|------|
| LD_PRELOAD environment variable (definitive) | #1 |
| Shell history: proxychains4 invocations | #2 |
| Parent: shell; child: reconnaissance tool | #3 |
| Outbound connection to SOCKS proxy | #4 |
| libproxychains.so library on disk | #5 |
| proxychains4 binary in PATH | #6 |

## Linux/macOS Hunting

```bash
# Active processes with LD_PRELOAD
for pid in $(pgrep -f '.*'); do
  if [ -f /proc/$pid/environ ]; then
    if grep -q 'LD_PRELOAD' /proc/$pid/environ; then
      ps -p $pid -o pid,ppid,cmd=
    fi
  fi
done

# Shell history
grep proxychains ~/.bash_history ~/.*_history

# Binaries/libraries
find / -name 'proxychains4' 2>/dev/null
find / -name 'libproxychains*.so*' 2>/dev/null
```

## Process Inspection

```bash
# Running processes
ps aux | grep proxychains
ps -eo ppid,pid,cmd | grep -E "proxychains|nmap|ssh|curl"

# Network connections
netstat -tnp | grep 1080
lsof -i :1080
```

## Cross-Host Scanning

```bash
for host in $(cat hostlist.txt); do
  echo "=== $host ==="
  ssh $host "ps -e -o env= | grep LD_PRELOAD && echo FOUND || echo Clean"
done
```

## Remediation

1. Kill process: killall proxychains4
2. Remove binaries: rm /usr/local/bin/proxychains4
3. Remove library: rm /usr/lib/libproxychains*.so*
4. Remove config: rm ~/.proxychains/proxychains.conf
5. Check persistence (cron, alias, function)
6. Firewall: Block SOCKS endpoint port
