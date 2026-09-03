🔴 **RED FLAG:** proxychains wraps any Unix/Linux binary with LD_PRELOAD, redirecting network calls through SOCKS proxies; the wrapper is invisible to the target application (works with unmodified binaries), but the LD_PRELOAD variable itself is visible in environment dumps and child process listings.

## History

**proxychains-ng** by rofl0r, current version **v4.17** (released 2024-01-21). Successor to original proxychains. GitHub: [github.com/rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng). Licensed under GPL2.

## Key Mechanics

- **LD_PRELOAD Injection:** Wrapper sets LD_PRELOAD=/path/to/libproxychains.so, exec's binary
- **Transparent Proxying:** Intercepts socket(), connect(), and other libc network calls
- **Proxy Types:** SOCKS4, SOCKS4a, SOCKS5, HTTP CONNECT
- **Chain Modes:** Strict, random, round-robin, dynamic (skip dead proxies)
- **TCP Only:** SOCKS doesn't support UDP/ICMP
- **DNS via Proxy:** proxy_dns option resolves hostnames through SOCKS5

## Command-Line Switches

```
proxychains4 -f <config> <binary> <args>

proxychains.conf:
  strict_chain / random_chain / round_robin_chain / dynamic_chain
  proxy_dns [on|off]
  [ProxyList]
  socks5 127.0.0.1 1080
  http    proxy.internal:8080
```

## Quick Use-Case List

1. Nmap via SOCKS (recon through proxy)
2. SSH through SOCKS (lateral movement)
3. Curl/wget through proxy (web enumeration)
4. Database clients (MySQL, PostgreSQL)
5. DNS pivoting (proxy_dns)
6. Reverse shell callback via proxy
7. Chained with C2
8. Multi-proxy load-balancing
9. Covert tool masquerading (process name mismatch)
10. Local pivoting (pre-tunnel setup)
11. Protocol mixing (SOCKS + HTTP proxies in chain)
12. Legacy tool wrapping (no SOCKS5 support)

## Prerequisites

**Linux/macOS/BSD only** (no Windows native support)
**Upstream SOCKS/HTTP proxy** (doesn't work standalone; needs Chisel, Ligolo-ng, SSH, etc.)
**Dynamically-linked binaries** (LD_PRELOAD works; static binaries bypass it)
