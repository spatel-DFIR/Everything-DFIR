## Attacker/Pivoting Host Artifacts

**Binary:** proxychains4 wrapper script + libproxychains.so library
**Config:** proxychains.conf (contains proxy list, may have credentials)
**Process:** proxychains4 wrapper spawns child binary (nmap, ssh, curl, etc.)
**Environment:** LD_PRELOAD=/path/to/libproxychains.so visible in env dump
**Shell history:** grep "proxychains4" ~/.bash_history
**Network:** Outbound to SOCKS proxy endpoint (e.g., 127.0.0.1:1080)

## Timeline
Config deployment → proxychains4 invocation → LD_PRELOAD injection → Child process spawns → SOCKS connection
