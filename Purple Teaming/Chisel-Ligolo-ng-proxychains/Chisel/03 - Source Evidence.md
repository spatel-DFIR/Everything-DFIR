## Attacker Host Artifacts

**Process:** chisel.exe or renamed variant, parent=shell/C2 session
**Command line:** chisel server --port 8080 OR chisel client https://...
**Network:** Outbound HTTPS to attacker infrastructure
**Listening ports:** netstat shows listening on 8080 (server) or ephemeral (client listening for local)
**Shell history:** grep "chisel" ~/.bash_history
**Memory:** TLS keys, tunneling rules, forwarded ports
**No disk artifacts:** proxychains doesn't write temp files by default

## Timeline
- Binary deployment → Process creation → Outbound connection → Tunnel established
- Server: Process listening on port precedes client connections
- Client: Outbound connection correlates with operator pivoting moment
