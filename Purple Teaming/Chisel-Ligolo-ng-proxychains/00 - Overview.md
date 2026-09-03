# Tunneling Primitives: Chisel, Ligolo-ng, and proxychains

Three distinct tunneling approaches for network pivoting, each with different mechanisms, prerequisites, and operational characteristics. This overview covers the shared purpose (bypassing network segmentation), the defining technical differences, and when to choose each.

## Shared Purpose

All three tools solve the same problem: **enabling tool execution and network access beyond an operator's direct reach.**

**Scenario:** Attacker compromises a host on a restricted internal network. That host has network access to sensitive systems (database, file server, domain controller) but the attacker's own machine does not. These tools create a virtual "bridge" from the attacker's machine through the compromised host to internal services.

## Quick Decision Matrix

| Use Case | Chisel | Ligolo-ng | proxychains |
|----------|--------|-----------|-----------|
| **Egress filtering (HTTP/2 evasion)** | ✅ Best | ✅ Good | ✅ Via upstream |
| **Direct tool execution (no wrapper)** | ❌ Needs SOCKS | ✅ Best | ❌ Needs LD_PRELOAD |
| **No privilege requirement** | ✅ Yes | ❌ Relay needs root | ✅ Yes |
| **Windows support** | ✅ Yes | ✅ Yes | ❌ No |
| **Performance (>100 Mbps)** | ⚠️ Medium | ✅ High | ✅ High |
| **TUN interface artifact** | ❌ No | ✅ Yes (obvious) | ❌ No |
| **LD_PRELOAD detection risk** | ❌ No | ❌ No | ✅ Yes (if checked) |

## Choose Chisel if:
- Egress filtering blocks non-HTTP ports
- SOCKS5-compatible tools available (nmap, curl, ssh)
- No elevated privileges on attacker host
- Windows targets needed
- Simple single-binary deployment valued

## Choose Ligolo-ng if:
- Root/admin access on attacker infrastructure available
- Direct tool execution needed (nmap SYN, SSH, psql directly)
- High performance required
- Multiple internal subnets to expose
- Team orchestration valuable (web UI)

## Choose proxychains if:
- Chisel or Ligolo-ng SOCKS endpoint already running
- Tool doesn't support SOCKS5 natively
- Stealthy binary wrapping valuable
- Linux/macOS/BSD only environment
- Minimize deployed binaries

## Common Chaining Pattern

```
Attacker → Chisel/Ligolo-ng tunnel → Internal host (SOCKS endpoint)
                                      ↓
                           proxychains wrapper
                           ↓
                         Tool execution (nmap, curl, etc.)
                           ↓
                       Internal network
```

## Documentation Structure

- **[Chisel/](Chisel/)** — HTTP/2-over-TLS tunneling, SOCKS5 endpoint
- **[Ligolo-ng/](Ligolo-ng/)** — TUN interface-based direct routing, agent/relay
- **[proxychains/](proxychains/)** — LD_PRELOAD wrapper for transparent tool proxying

Each sub-folder contains the full 5-file template: Overview, Hands-On Use Cases, Source Evidence, Target Evidence, Detection & Hunting.

## Artifact Summary

| Tool | Key Artifacts | Detection Difficulty |
|------|---|---|
| **Chisel** | HTTP/2 on port 8080/8888, `chisel` process, persistent HTTPS pattern | Medium |
| **Ligolo-ng** | TUN interface, `ligolo-ng` process, persistent TLS port 11601, route configuration | Easy (TUN is obvious) |
| **proxychains** | LD_PRELOAD env var (definitive), `proxychains4` wrapper, shell history | Hard (if not looking for LD_PRELOAD) |

All three are **tunneling primitives**, not C2 frameworks. They enable other tools to reach internal networks; they don't command & control themselves. Operators layer them: tunnel establishes access, proxychains wraps tools, tools do the offensive work.

See individual sub-tool pages for command reference, detailed evidence analysis, and hunting procedures.
