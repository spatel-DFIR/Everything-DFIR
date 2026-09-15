## Network-Layer Evidence

**Inbound:** Connections appear to originate from SOCKS proxy endpoint (e.g., internal Chisel server)
**Source IP:** Matches SOCKS proxy IP, not attacker's actual IP
**Pattern:** Tool-specific (nmap: SYN flood; SSH: port 22; HTTP: port 80/443)

## Behavioral Mismatch

**Process vs. Traffic:** On proxy host, process is "chisel" but traffic patterns are "nmap"
**Signature gap:** Defenders see nmap behavior but binary wasn't nmap

## Timeline
SOCKS connection from attacker → Proxy relays to target → Target sees connection from proxy IP

## Detection: proxychains Use

**LD_PRELOAD in environment variable** (definitive signal)
**Shell history with proxychains4 invocations**
**Parent-child mismatch:** shell → proxychains4 → tool binary
**Connection to SOCKS endpoint** from reconnaissance tool
