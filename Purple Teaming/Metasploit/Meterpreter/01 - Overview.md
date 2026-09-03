# Metasploit — Meterpreter — Overview

> 🔴 **Red Flag Principle:** Meterpreter's core payload (`metsrv.dll`) is **reflectively loaded straight into a process's memory** — mapped, relocated, and executed by a custom in-memory loader that never calls `LoadLibrary` and never writes the payload to disk as a file — and every command/response after that rides a binary **Type-Length-Value (TLV)** protocol over a single socket, AES-256-CBC-encrypted end-to-end on any currently maintained build. There is no payload file to hash and no wire traffic to read in cleartext. Hunting Meterpreter means hunting a **process-memory and network-protocol** signature, not a file signature — everything in `04 - Target Evidence.md` and `05 - Detection and Hunting.md` follows from that one fact.

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command Reference — Quick Reference](#command-reference--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Meterpreter ("Meta-Interpreter") has been **part of Metasploit since 2004**, originally written in C by **Matt "skape" Miller**, per Rapid7's own Meterpreter documentation ([docs.metasploit.com](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/)). It predates the 2007 Ruby rewrite of the core Framework — Meterpreter's server-side components (`metsrv.dll` and its extension DLLs) are native C, not Ruby; only the client-side session-handling logic lives in the Ruby Framework. Non-Windows implementations followed later: Python, PHP, and Java Meterpreter variants exist for cross-platform targets, contributed by numerous authors over the years — this note focuses on the Windows-native implementation, the one referenced by nearly all public detection research.

Meterpreter's defining delivery mechanism, **Reflective DLL Injection**, is credited to security researcher **Stephen Fewer**, whose technique patches a DLL's own PE header so the DLL can act as its own loader — no dependency on the Windows loader's normal `LoadLibrary` path. Meterpreter's server-side source (`metsrv.dll` and the `ext_server_*` extension DLLs) lives in Rapid7's companion repository, [`github.com/rapid7/metasploit-payloads`](https://github.com/rapid7/metasploit-payloads), developed alongside the main [`rapid7/metasploit-framework`](https://github.com/rapid7/metasploit-framework) repo. Both are maintained by **Rapid7, Inc.** under the **3-clause BSD license (BSD-3-Clause)**, confirmed against the repos' own `LICENSE` files.

Meterpreter's protocol has changed materially over its lifetime — most notably, **Metasploit Framework 6.0 (2020)** added native end-to-end TLV encryption (AES-256-CBC, key negotiated via RSA) across every Meterpreter implementation and transport. Earlier Framework releases obfuscated only the fixed TLV packet header (a 4-byte XOR key) and did not encrypt packet data by default. This version boundary matters for anyone reasoning about wire-level detectability of older captures or legacy-agent engagements — see [How It Works](#how-it-works) below.

## How It Works

```
Attacker (msfconsole handler)                         Target process
──────────────────────────────                        ───────────────
1. Exploit succeeds, or operator runs a
   staged payload (windows/meterpreter/reverse_tcp)
                                                         stage0 (stager, small stub)
                                                         connects back to handler ──┐
2. Handler sends stage1 over the connection ───────────▶ receives metsrv.dll bytes  │
   (the full Meterpreter DLL, header-patched              (patched PE header,        │
   to be position-independent / shellcode-callable)        exports ReflectiveLoader) │
                                                                                       │
3. Target-side ReflectiveLoader() executes:                                          │
     ├─ Locates its own base address in memory                                       │
     ├─ Parses its own PE headers (no LoadLibrary call)                              │
     ├─ Manually maps sections, resolves imports,                                    │
     │    applies relocations                                                        │
     └─ Calls its own DllMain — metsrv.dll is now                                     │
          running, fully in memory, no file ever                                     │
          written to disk for the payload itself      ◀──────────────────────────────┘

4. RSA-based key negotiation over the TLV channel      Session key established.
   establishes a per-session AES-256-CBC key             Every subsequent TLV
   (Framework 6.0+; see History above).                   packet's data is now
   stdapi extension auto-loads.                            encrypted, not just
                                                             header-obfuscated.
                                                            getuid / sysinfo / ps
                                                            all answered from here.

5. Operator loads extensions on demand ─────────────────▶ kiwi.dll / incognito.dll /
   (load kiwi, load incognito, load extapi)                extapi.dll reflectively
                                                             loaded the SAME way as
                                                             metsrv.dll — uploaded over
                                                             the TLV channel, mapped in
                                                             memory, registers new
                                                             commands with the running
                                                             core

6. migrate <PID> ───────────────────────────────────────▶ OpenProcess (needs
                                                             SeDebugPrivilege for a
                                                             cross-user-context target)
                                                            VirtualAllocEx (RWX region)
                                                            WriteProcessMemory (copies
                                                             metsrv.dll into new process)
                                                            CreateRemoteThread (executes
                                                             it — reflective load repeats
                                                             inside the NEW process)
                                                            Original process's Meterpreter
                                                             thread exits; TLV session
                                                             continues, now backed by the
                                                             new process
```

Step-by-step:

1. **Delivery** — Meterpreter arrives either **staged** (a small `stage0` stub — placed by the exploit or dropper — connects back and pulls down the full `metsrv.dll` as `stage1`) or **stageless** (the full DLL ships in one blob, no second download required). Naming convention in every payload path: staged payloads use a slash (`windows/x64/meterpreter/reverse_tcp`), stageless use an underscore (`windows/x64/meterpreter_reverse_tcp`). Staged is smaller for the initial delivery vector (useful where the exploit's buffer/space is constrained) but needs a second, uninterrupted network round-trip to become a working session; stageless is larger up front but self-contained — the whole tool in `msfvenom/` covers payload generation for both in depth.
2. **Reflective loading** — `metsrv.dll`'s PE header is patched (Stephen Fewer's Reflective DLL Injection technique) so the DLL exports a `ReflectiveLoader` function capable of mapping and initializing *itself* in memory — no `LoadLibrary`, no on-disk DLL for the Windows loader to register, no corresponding "module load" the normal way. This is the single biggest reason Meterpreter's target-side file footprint is thin (see `04 - Target Evidence.md`).
3. **Session establishment over TLV** — once resident, `metsrv.dll` speaks a binary **Type-Length-Value (TLV)** protocol over the same socket the stager/stageless payload connected with. Every packet carries a fixed-shape header — a 4-byte XOR key, a 16-byte session GUID, a 4-byte encryption-scheme flag, a 4-byte length, and a 4-byte packet type — ahead of the TLV-encoded data itself. On **Metasploit Framework 6.0 and later**, the encryption flag is set from session start: an RSA-based handshake negotiates a per-session **AES-256-CBC** key, and every packet's data (not just the header) is encrypted with it — applied uniformly across the Windows, Python, PHP, and Java implementations and every transport. This is separate from **"Paranoid Mode"**, an opt-in feature (`set PayloadUUIDTracking true` / certificate-hash options on the handler) that adds SSL certificate hash-pinning for `reverse_https`/`reverse_http` specifically, defending against a MITM'd TLS handler rather than encrypting the TLV payload itself.
4. **Extension loading** — the `stdapi` extension (filesystem, process, and network primitives, plus screen/webcam/mic capture and keylogging) loads automatically on session start. Everything else loads on demand via `load <extension>`:
   - `priv` — privilege-escalation helpers (`getsystem`) and an in-memory `hashdump`.
   - `incognito` — enumerates and impersonates Windows access tokens present on the host.
   - `kiwi` — Mimikatz's credential-extraction routines reimplemented as a Meterpreter extension. **This note does not re-document Mimikatz internals** — see `../../Mimikatz/00 - Mimikatz Overview.md` and `../../Mimikatz/sekurlsa (Credential Dumping)/` for the underlying LSASS-memory mechanics kiwi's commands are built on.
   - `extapi` — extended API surface: Active Directory queries (`adsi`), clipboard read/monitor (`clipboard`), offline `NTDS.dit` parsing (`ntds`), PuTTY/Pageant SSH-agent hijacking (`pageant`), Windows service enumeration/control beyond `stdapi`'s process primitives (`service`), desktop window enumeration (`window`), and WMI queries (`wmi`).
   - `espia` — legacy screen-capture extension (`screengrab`), largely superseded by `stdapi`'s `screenshot` in current builds but still present in the source tree.
   - `sniffer` — in-memory packet capture directly off a target NIC (`sniffer_interfaces`, `sniffer_start`, `sniffer_dump`, `sniffer_stop`) without installing WinPcap/Npcap on the target.
   - `lanattacks` — turns the compromised host into an attack platform against its own local segment: a rogue DHCP server (`dhcp_start`/`dhcp_stop`/`dhcp_set_option`, configurable `ROUTER`/`DNSSERVER`/`DHCPIPSTART`-`DHCPIPEND` options) plus a bundled TFTP component, used for LAN-local MITM/PXE-style attacks launched from inside the target network rather than the operator's own segment.

   Loading works the same way stage1 did: the client uploads the extension DLL's bytes over the existing TLV channel, the server reflectively maps it into the *current* process's memory, and it registers its new command set with the running `metsrv.dll` core. No extension DLL touches disk on the target.
5. **`migrate`** — moves the running Meterpreter server from its current process into a different one, typically for stability (surviving the original process exiting) or stealth (leaving a process the operator caused to spawn, like a dropped payload's own `.exe`, and settling into a long-lived benign process such as `explorer.exe` or a service host). Mechanically this is classic Windows process injection: `OpenProcess` (requires `SeDebugPrivilege` to open a process running as a different, typically higher-privileged, user), `VirtualAllocEx` to carve out an RWX region in the target, `WriteProcessMemory` to copy the reflective-loader-capable DLL in, and `CreateRemoteThread` to kick off execution — the reflective-load sequence from step 2 then repeats inside the new process. The old process's Meterpreter thread terminates; the TLV session continues uninterrupted from the operator's point of view, now backed by different target-side process memory. No new network connection is created for a same-host migrate.
6. **`getsystem`** — privilege escalation to `NT AUTHORITY\SYSTEM` via one of three built-in techniques, tried in order until one succeeds (see the techniques table in `02 - Hands-On Use Cases.md`) — named-pipe impersonation (in-memory or dropper variant) or SYSTEM token duplication.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Initial delivery | Reflective DLL Injection (Stephen Fewer's technique) — `metsrv.dll` maps and initializes itself in memory via a patched PE header and exported `ReflectiveLoader`, no disk file for the payload |
| Session protocol | Binary TLV (Type-Length-Value); AES-256-CBC-encrypted per-packet with an RSA-negotiated session key on Framework 6.0+ (see History) |
| Transport | `reverse_tcp` (raw persistent socket), `reverse_http`/`reverse_https` (WinInet-based HTTP(S) polling, proxy-aware, `reverse_https` TLS-wrapped), `bind_tcp` (target listens, operator connects in) — see the transport comparison in `02 - Hands-On Use Cases.md` |
| Extension loading | Same reflective-load mechanism as the initial stage — extension DLLs (`stdapi`, `priv`, `incognito`, `kiwi`, `extapi`, `espia`, `sniffer`, `lanattacks`) are uploaded over the live TLV channel and mapped in-process, never written to disk |
| Process migration | Classic Win32 injection: `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` |
| Privilege escalation (`getsystem`) | Named-pipe impersonation (in-memory `cmd.exe`, or disk-dropper `rundll32` variant) or SYSTEM token duplication via `SeDebugPrivilege` |
| Credential access (`kiwi`) | In-memory Mimikatz functionality reimplemented as a Meterpreter extension — LSASS memory parsing for plaintext/hash/ticket credential material, no separate `mimikatz.exe` needed. See `../../Mimikatz/` |
| Token abuse (`incognito`) | Enumerates and impersonates available Windows access tokens on the compromised host |
| Extended enumeration/hijack (`extapi`) | AD (ADSI) queries, clipboard capture, offline NTDS.dit parsing, SSH-agent (Pageant) hijack, service control, window enumeration, WMI queries |
| LAN-local attacks (`lanattacks`) | Rogue DHCP server + TFTP served directly from the compromised host's NIC, targeting the local broadcast segment |

## Command Reference — Quick Reference

Meterpreter console commands — this is the shell/payload's own command set, **not** `msfconsole`'s module-handling commands (those are covered in `../00 - Metasploit Overview.md`). Verified against Rapid7's Meterpreter documentation (`docs.metasploit.com`, `docs.rapid7.com/metasploit`) and the `metasploit-framework`/`metasploit-payloads` source.

**Core**

| Command | Plain-English meaning |
|---|---|
| `background` (`bg`) | Suspend the current session and return to the `msfconsole` prompt without closing it |
| `sessions -i <id>` | Return to (interact with) a backgrounded session by ID, from `msfconsole` |
| `sysinfo` | OS, hostname, and architecture of the compromised host |
| `getuid` | The user context the Meterpreter server is currently running as |
| `getpid` | The process ID Meterpreter is currently resident in |
| `ps` | List running processes on the target — used to pick a `migrate` target |
| `migrate <PID>` | Move the Meterpreter server into a different process (see How It Works above) |
| `load <extension>` | Load an extension (`kiwi`, `incognito`, `priv`, `extapi`, `espia`, `sniffer`, `lanattacks`) into the current session |
| `run <script/module>` | Execute a post-exploitation script or module against the current session |
| `exit` / `quit` | Terminate the session outright (as opposed to `background`, which only suspends it) |

**File System**

| Command | Plain-English meaning |
|---|---|
| `ls` / `cd` / `pwd` | Directory listing / change directory / print working directory, target-side |
| `upload <local> <remote>` | Push a file from the operator's machine to the target |
| `download <remote> <local>` | Pull a file from the target to the operator's machine |
| `cat <file>` | Print a target file's contents to the console |
| `edit <file>` | Open a target file in a local text editor over the session |
| `search -f <pattern>` | Search the target filesystem for matching filenames |

**Networking**

| Command | Plain-English meaning |
|---|---|
| `ipconfig` / `route` | Target network interface details / view or modify the target's routing table (used to pivot Framework traffic through the session) |
| `run autoroute -s <CIDR>` | Post module wrapper around `route add` — the common way operators actually add a pivot route in practice |
| `portfwd add -l <lport> -r <rhost> -p <rport>` | Forward a local port on the operator's machine through the session to a target-reachable host:port |
| `transport list` | Show configured C2 transports and which is active |
| `transport add -t <type> -l <lhost> -p <lport>` | Add a new transport (e.g. `reverse_https`) to a live session for failover/hopping |

**System / Execution**

| Command | Plain-English meaning |
|---|---|
| `execute -f <path> -i -H` | Run a target-side executable; `-i` interacts with it, `-H` hides its window |
| `shell` | Drop into a native `cmd.exe` shell inside the current Meterpreter session |
| `kill <PID>` | Terminate a target-side process |
| `clearev` | Clear the target's Windows Event Logs (Security/System/Application) — a strong, deliberate anti-forensics action, not a byproduct of anything else in this list |

**User Interface / Surveillance (`stdapi`)**

| Command | Plain-English meaning |
|---|---|
| `screenshot` | Capture the target's current screen |
| `webcam_list` / `webcam_snap` / `webcam_stream` | Enumerate attached webcams / capture a single still / stream continuous frames |
| `record_mic` | Capture audio from an attached microphone for a specified duration |
| `keyscan_start` / `keyscan_dump` / `keyscan_stop` | Start, retrieve, and stop a keystroke-capture session |

**Privilege / Credential (`priv` / `kiwi` / `incognito`)**

| Command | Plain-English meaning |
|---|---|
| `getsystem` | Attempt privilege escalation to SYSTEM via the built-in technique chain (see `02 - Hands-On Use Cases.md`) |
| `hashdump` (`priv`) | In-memory SAM dump — injects code to read the SAM database out of memory rather than touching the on-disk hive file |
| `creds_all` (`kiwi`) | Run all of kiwi's in-memory credential-harvesting routines (MSV, WDigest, Kerberos, SSP, TSPKG) in one pass — see `../../Mimikatz/sekurlsa (Credential Dumping)/` for what these providers actually hold and why |
| `lsa_dump_sam` / `lsa_dump_secrets` (`kiwi`) | Kiwi's own SAM / LSA-secrets dump path, independent of `priv`'s `hashdump` |
| `dcsync` (`kiwi`) | Perform a DCSync-style credential extraction against a domain controller from the compromised session |
| `golden_ticket_create` (`kiwi`) | Forge a Kerberos golden ticket using material recovered via kiwi |
| `wifi_list` (`kiwi`) | Enumerate saved Wi-Fi profiles and, where recoverable, their stored keys |
| `list_tokens -u` (`incognito`) | Enumerate Windows access tokens available on the host |
| `impersonate_token <token>` (`incognito`) | Impersonate a specific enumerated token |
| `rev2self` | Drop any impersonated token and return to the session's original security context |

**Extended API (`extapi`) and Situational Extensions**

| Command | Plain-English meaning |
|---|---|
| `adsi_domain_query` (`extapi`) | Query Active Directory over ADSI directly from the session, without dropping a separate LDAP tool |
| `clipboard_get_data` / `clipboard_monitor_start` (`extapi`) | Grab the current clipboard contents, or start a continuous clipboard-change monitor |
| `ntds_parse` (`extapi`) | Parse an offline copy of `NTDS.dit` (e.g. pulled via `secretsdump`-style extraction elsewhere in the session) |
| `pagent_send_query` (`extapi`) | Hijack a running PuTTY Pageant SSH-agent process to sign requests with keys it holds, without extracting the private key itself |
| `service_enum` / `service_control` (`extapi`) | Enumerate/query/start/stop Windows services beyond `stdapi`'s process-level primitives |
| `window_enum` (`extapi`) | Enumerate desktop windows on the target, including hidden ones |
| `wmi_query` (`extapi`) | Run a WMI query directly from the session |
| `screengrab` (`espia`) | Legacy screen-capture command, superseded by `stdapi`'s `screenshot` in current builds |
| `sniffer_start` / `sniffer_dump` / `sniffer_stop` (`sniffer`) | Start/retrieve/stop an in-memory packet capture off a target NIC — no WinPcap/Npcap install needed on the target |
| `dhcp_start` / `dhcp_stop` (`lanattacks`) | Stand up/tear down a rogue DHCP server directly from the compromised host, for LAN-local MITM against the target's own broadcast segment |

## Quick Use-Case List

- Initial staged shell delivered by an exploit module (`windows/meterpreter/reverse_tcp`)
- Stageless payload for locked-down egress or unreliable second-stage delivery
- Migrating to a stable, long-lived process for session survivability
- Credential harvesting via the `kiwi` extension (in-memory Mimikatz)
- Credential harvesting via `hashdump` (`priv` extension, in-memory SAM read)
- Token impersonation via `incognito` for lateral privilege abuse
- Privilege escalation to SYSTEM via `getsystem`
- Network pivoting/port-forwarding through a compromised host (`portfwd`, `autoroute`/`route`)
- Screenshot and keylogging for situational awareness
- Webcam and microphone capture via `stdapi`'s surveillance commands
- Active Directory/clipboard/NTDS enumeration via `extapi`
- LAN-local rogue-DHCP/TFTP attacks via `lanattacks`, launched from inside the target network
- Persistence via a `run persistence`-style post module launched from the session
- Transport hopping/failover between `reverse_tcp`/`reverse_https`/`bind_tcp` on a live session
- Chained straight out of an exploit module (e.g. an EternalBlue-class RCE dropping Meterpreter directly, no separate delivery step)
- Fleet-wide post-exploitation scripting across many simultaneous sessions via `msfconsole`'s session-broadcast commands

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Initial code execution | Meterpreter has to arrive somehow — an exploit module, a manually delivered `msfvenom`-generated payload, or another tool chaining into it. This note assumes that step already happened; see `../msfvenom/` for payload-generation mechanics |
| Network reachability back to a handler | Reverse transports need outbound connectivity from target to operator; `bind_tcp` needs inbound reachability to the target instead |
| `SeDebugPrivilege` (for cross-user `migrate` or SYSTEM token-duplication `getsystem`) | Migrating into a process owned by a different user, or the token-duplication `getsystem` technique, needs this privilege — typically present for local administrators |
| Local administrator rights (for named-pipe `getsystem` techniques) | Both named-pipe impersonation techniques assume the current context already has admin-equivalent rights on the box |
| Extension DLL availability | `load kiwi`/`load incognito`/`load extapi`/etc. require the corresponding extension DLL to be present in the Framework's `data/meterpreter/` directory on the operator's machine — standard in any default install |
| Framework version 6.0+ for native TLV encryption | End-to-end AES-256-CBC session encryption is the default on any currently maintained Metasploit Framework install; an operator running a legacy pre-6.0 Framework build (uncommon, but possible on stale infrastructure) gets only header obfuscation, not full payload encryption — relevant when assessing whether a captured PCAP is realistically decryptable |
