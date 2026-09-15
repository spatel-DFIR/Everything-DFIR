# Coercer — Overview

> 🔴 **Red Flag Principle:** Coercer is a **CVE aggregator** — a single tool wrapping 10+ distinct RPC coercion primitives (each originally a separate CVE exploit). No single Coercer-specific network signature exists; detection must focus on the **underlying RPC methods** it activates (EFS, PrinterBug, ShadowCoerce, etc.), each of which has its own event-log footprint.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Coercer was written by **Podalirius** (@podalirius) and published under the `p0dalirius/Coercer` GitHub repository, licensed under **GPLv3**.

Verified against the live repository state:

- **Initial release (2021)** — unified framework aggregating multiple RPC coercion CVEs (EFS, PrinterBug, ShadowCoerce, etc.) into one tool.
- **v3.0+ (2022-2023)** — significant expansion of integrated CVEs; real-time module discovery from the DC.
- **v4.0+ (2024)** — continued refinement; added additional coercion primitives (NetLogon, DFS, etc.).
- **Maintained through 2026** — actively updated with new CVEs and protocol refinements.

**Design philosophy:** Unlike mitm6 (IPv6 spoofing) or Responder (name-resolution poisoning), Coercer is a **RPC-method aggregator** — it doesn't invent new attack surfaces, it **collects existing CVE exploits into one binary**. Each integrated CVE is independently exploitable; Coercer simply provides unified CLI/API access.

## How It Works

Coercer forces a target (usually a DC or file server) to authenticate to an attacker-controlled server by invoking **RPC methods that trigger authentication as a side effect**. Unlike relay attacks (which intercept authentication in-flight), coercion creates authentication **on demand**, on whatever schedule the attacker chooses.

### The Coercion Pattern

All Coercer's integrated techniques follow the same flow:

```
1. Attacker's machine runs Coercer + Responder/ntlmrelayx (listening on port X)
2. Coercer calls a specific RPC method on the target (DC, file server, etc.)
3. Target's service (RPC server) handles the RPC call
4. As part of handling that RPC method, the service:
   - Opens a connection BACK to the attacker's IP (coercion trigger)
   - Typically to a named pipe, SMB share, or printer port
   - Needs to authenticate as the service account (often SYSTEM or machine$)
5. Target connects to attacker's Responder/ntlmrelayx listener
6. NTLM authentication exchanged; hash captured or relayed
```

**Why it works:** The target's service code has built-in, legitimate RPC handlers that *inadvertently trigger authentication* — the service doesn't know it's connecting to an attacker, it just executes its designed functionality (e.g., encrypt a file, share a print job, replicate a domain object).

### Integrated RPC Coercion CVEs

Coercer aggregates the following (verified from the source `coercers/` module directory):

| CVE | Protocol / Method | Target | Trigger |
|---|---|---|---|
| **CVE-2021-36942** | MS-EFSRPC (Encrypting File System RPC) | DC, file servers | Call `EfsRpcEncryptFileSrv` → target encrypts a file, connecting to the attacker-specified UNC path |
| **CVE-2019-1350** | MS-RPRN (Print Spooler RPC) | DC, file servers | Call `RpcRemoteFindFirstPrinter` → Print Spooler attempts to access attacker-specified printer port |
| **CVE-2021-1453** | MS-RPRN variant | DC | Similar to CVE-2019-1350, alternative entry point |
| **CVE-2019-1708** | MS-EFSR variant | DC, file servers | Alternative EFS RPC entry point |
| **CVE-2020-1472** (Zerologon) | MS-NRPC (Netlogon) | DC | Call Netlogon RPC with crafted challenge → DC computes weak hash |
| **CVE-2020-1472 (non-CVE variant)** | MS-NRPC | DC | Netlogon secure channel reset coercion |
| **ShadowCoerce** | MS-FSRVP (File Server Remote VSS Proxy) | File server, DC | Call `GetShadowCopyData` → target attempts to access attacker's SMB share |
| **DFS Coercion** | MS-DFSC (DFS: Referrals and Replication) | DC, file server | Call DFS RPC methods → target enumerates DFS referrals to attacker-controlled server |
| **LDAP Channel Binding (variant)** | MS-SAMR / MS-LSAD | DC | Coerce via LDAP channel binding downgrade (less common) |

Not all are always compiled in; availability depends on Coercer version and compile-time flags.

## Techniques / Protocols Used

| Protocol | Detail | Impact |
|---|---|---|
| **MS-EFSRPC (EFS RPC)** | Encrypting File System Remote Procedure Call | Force file encryption connecting to attacker UNC |
| **MS-RPRN (Print Spooler RPC)** | Print Server Remote Procedure Call (PrinterBug) | Force printer spool job to attacker port |
| **MS-NRPC (Netlogon RPC)** | Netlogon Secure Channel (Zerologon) | Force DC secure-channel computation |
| **MS-FSRVP (File Server Remote VSS)** | Volume Shadow Copy Proxy (ShadowCoerce) | Force VSS to attacker SMB share |
| **MS-DFSC (DFS Referrals)** | Distributed File System | Force DFS referral to attacker server |
| **NTLM Authentication** | Challenge/response over coerced connection | Captured or relayed (not cracked locally) |
| **SMB named pipes / UNC paths** | Connection targets | Attacker-controlled listener receives auth |
| **RPC bind / call protocol** | Microsoft RPC protocol (DCERPC over SMB) | Invokes the vulnerable RPC method |

## Command-Line Switches — Quick Reference

Coercer's CLI is designed for enumeration + exploitation in one binary. Core switches:

| Flag | Argument | Purpose |
|---|---|---|
| `-d DOMAIN` | Domain name (e.g., corp.local) | **Required**: target domain (for LDAP lookup of DC) |
| `-u USER` | Username (domain\user or user@domain) | **Required**: attacker's credentials for LDAP enumeration |
| `-p PASSWORD` | Password | **Required**: attacker's password (or `-hashes` for hash auth) |
| `-hashes LM:NT` | Hashes (LM deprecated) | Alternative to password; `-hashes :NTHASH` for NT-only |
| `-t TARGET` | Target IP/hostname | DC or file server to coerce |
| `-tr TARGET-LIST` | File with targets (one per line) | Coerce multiple targets in batch |
| `--listener IP` | Attacker's IP | IP to connect back to (for NTLM capture); usually your Responder host |
| `--port PORT` | Port number | Which port listener is on (default varies by method) |
| `-co METHOD` | Coercion method (efsrpc, rprn, etc.) | Specific CVE to use; `-co all` tries all |
| `-vv` / `-v` | (none) | Verbose / very verbose output |
| `--time-delay SECONDS` | Delay between attempts | Slow down detection (evasion) |
| `--no-tls` | (none) | Disable TLS for RPC binding (rarely needed) |

**Note:** Unlike mitm6 (no credentials needed), Coercer **requires valid domain credentials** to authenticate to the RPC endpoint. This is a key difference.

## Quick Use-Case List

1. **Forced NTLM capture via EFS coercion** — Call EFS RPC to force target to connect and authenticate.
2. **PrinterBug exploitation (MS-RPRN)** — Coerce via Print Spooler RPC (oldest, most reliable).
3. **ShadowCoerce (VSS)** — Force Volume Shadow Copy to attacker's SMB share.
4. **Netlogon secure-channel reset (MS-NRPC)** — Force DC to reset channel to attacker.
5. **DFS referral coercion** — Force DFS client to query attacker's DFS server.
6. **Batch coercion against all DCs in domain** — Use `-tr` to coerce multiple targets simultaneously.
7. **Evasion via time-delay** — Slow down coercion (time-delayed, randomized) to evade time-based detection.
8. **Coerce specific target (non-DC)** — Force file server, print server, or other service account to authenticate.
9. **Credential validation + coercion** — Verify domain creds work before coercing.
10. **All-methods brute-force** — Use `-co all` to try every available coercion technique (most likely to succeed).

## Prerequisites

1. **Valid domain credentials** — Must authenticate to the RPC endpoint as an authenticated user (often low-privilege is sufficient).
2. **Network access to target** — Must be able to reach the target's SMB/RPC port (445).
3. **Listener running** — Must have Responder or ntlmrelayx running on the attacker host, listening for the callback.
4. **RPC endpoint available** — Target must have the specific RPC service running (most DCs have all coercion methods available).
5. **NTLM enabled** — Target must support NTLM auth (standard on all Windows DCs).
6. **No SMB signing** — If SMB signing is enforced, some coercion methods will fail; relay still works but requires `-auth-smb` creds in ntlmrelayx.
7. **Attacker IP must be routeable** — Target must be able to reach the attacker's listening IP address.

---

**Next:** See `02 - Hands-On Use Cases.md` for full command walkthroughs of each coercion technique.
