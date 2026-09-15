## Network-Layer Evidence

**Inbound:** TCP connection from internal host (agent location) to target services
**IDS/Firewall:** Connection appears to originate from agent's IP, not attacker's

## Process Evidence (Windows)

**Sysmon Event 1:** ligolo-ng.exe with -connect flag
**Event 5156:** Outbound TCP to relay IP:11601

## Agent Connection Fingerprint

**TLS negotiation** on non-standard port 11601
**Persistent connection** maintained
**Binary protocol** (not HTTP/HTTPS)

## Comparison vs. Chisel

- No HTTP/2 signature (pure TLS)
- Port 11601 (vs. Chisel's 8080)
- Agent initiates (vs. Chisel client), so connection direction matters
- No SOCKS endpoint visible (direct routing via TUN)

## Timeline
Agent process start → TLS handshake (1-3s) → Relay creates routes → Tunnel active
