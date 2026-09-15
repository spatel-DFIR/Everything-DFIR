## Network-Layer Evidence

**Firewall logs:** TCP connection to Chisel server port (8080, 8888, etc.)
**IDS:** TLS negotiation, HTTP/2 protocol preface ("PRI * HTTP/2.0"), persistent connection
**Zeek:** HTTP/2 over TLS on non-standard port

## Process Evidence (Windows)

**Sysmon Event 1:** chisel.exe process creation with server/client arguments
**Event 5156:** Outbound TCP to server IP:port
**No service installation:** Chisel doesn't register as Windows service by default

## Traffic Patterns

- Sustained HTTPS connection (not connection-per-request like browsers)
- Periodic small frames (keepalive pings)
- Continuous bidirectional data when tools active
- Mismatch: TLS SNI might not match certificate CN (custom certs)

## Timeline
Connection start → TLS handshake (1-3s) → Data transfer → Keep-alive pings (25s intervals)
