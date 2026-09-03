🔴 **RED FLAG:** Ligolo-ng creates a TUN interface on the operator's host, seamlessly routing internal networks without SOCKS wrappers; the agent requires zero elevated privileges while the relay does, making privilege escalation invisible in target logs but clearly visible on the attacker's TUN device creation + kernel routing table.

## History

**Ligolo-ng** by nicocha30, current version **v0.9.1** (released 2026-08-11). Rewrite of original Ligolo tool. GitHub: [github.com/nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng). Licensed under GPLv3.

## Key Mechanics

- **TUN Interface:** Relay creates userland network stack via Gvisor; packets → agent network operations
- **Agent/Relay:** Agent (no privileges) connects to relay (requires root for TUN), establishes persistent tunnel
- **Automatic Routing:** Relay auto-discovers internal subnets, configures kernel routes
- **Direct Tool Execution:** Tools work directly (nmap SYN, ping, SSH) without SOCKS wrapper
- **Multiplayer:** Web UI, daemon mode, multiple agents per relay

## Command-Line Switches

**Relay:** `ligolo-ng relay -addr 0.0.0.0:11601`
**Agent:** `ligolo-ng agent -connect 203.0.113.1:11601 --insecure`

## Quick Use-Case List

1. Basic agent tunnel + auto-routing
2. Direct nmap scanning (no proxychains)
3. Multi-tool chaining (SSH, curl, MySQL via TUN)
4. Reverse tunnel (callback)
5. Chained with C2
6. Persistence (Task Scheduler/cron)
7. Daemon/service mode
8. Multiple agents per relay
9. Web UI orchestration
10. Auto-bind (expose internal services)
11. Automatic subnet discovery
12. Network resilience (auto-reconnect)

## Prerequisites

**Relay:** Root/admin required (TUN creation), listener port 11601 open
**Agent:** No privileges required, outbound access to relay
