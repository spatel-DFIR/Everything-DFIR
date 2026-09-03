## Relay Host Artifacts

**TUN Interface:** ip link show tun0 (Linux), Get-NetAdapter (Windows)
**Process:** ligolo-ng relay, listening on 0.0.0.0:11601
**Routing:** ip route show | grep tun0 (routes to internal subnets)
**No disk artifacts:** Config in memory or YAML file

## Agent Host Artifacts

**Process:** ligolo-ng agent -connect relay-ip:port
**Network:** Persistent TCP/TLS to relay
**No disk artifacts:** Binary only
**Shell history:** grep "ligolo-ng" ~/.bash_history
**Persistence:** Task Scheduler (Windows) or cron (Linux)

## Timeline
Binary deployed → Process execution → Outbound connection to relay → TUN interface created (relay side)
