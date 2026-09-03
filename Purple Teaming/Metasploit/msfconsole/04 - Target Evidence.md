# Metasploit — msfconsole — Target Evidence

msfconsole has **no single target-side signature of its own** — it's an orchestrator that drives thousands of different `exploit`/`auxiliary`/`post` modules, and the actual target-side footprint depends entirely on which module ran and which payload it delivered. An `ms17_010_eternalblue` run leaves SMB/EternalBlue-specific evidence; a credential-spraying auxiliary module leaves a burst of failed-then-successful logon events; a `post/windows/gather` module leaves whatever that specific module touches. **This page does not attempt to catalog every module's individual target footprint** — that lives with the module category itself (`../Exploit Modules/`, `../Auxiliary Modules/`, `../Post-Exploitation Modules/`) or with the specific payload (`../Meterpreter/04 - Target Evidence.md`). What this page covers is the one component that genuinely is universal to msfconsole regardless of which module produced it: **the handler/callback traffic pattern** produced by `exploit/multi/handler`, and how to reason about direction and timing when that's the only clue available.

## Contents
- [The Handler Is a Network-Layer Signature, Not a Host Artifact](#the-handler-is-a-network-layer-signature-not-a-host-artifact)
- [Traffic Direction — the Key Discriminator](#traffic-direction--the-key-discriminator)
- [Network-Layer Evidence](#network-layer-evidence)
- [What Happens on the Target Once Caught](#what-happens-on-the-target-once-caught)
- [Where Module-Specific Target Evidence Actually Lives](#where-module-specific-target-evidence-actually-lives)
- [Building a Timeline](#building-a-timeline)

---

## The Handler Is a Network-Layer Signature, Not a Host Artifact

`exploit/multi/handler` runs entirely on the **operator's** box (see `03 - Source Evidence.md`) — it never writes a file, creates a registry key, or touches an event log on the target. Its only observable effect on the target side is the network connection the target's already-running payload makes to reach it (or, for `bind_tcp`, the connection the handler makes *to* the target). Everything else a target-side investigator would look for — Prefetch, Amcache, Event IDs for the stager's own execution — belongs to *how the payload got onto and ran on the target in the first place* (the delivery mechanism: an exploit module, a `psexec.py`-style push, a phishing-delivered `msfvenom` executable), not to the handler itself.

## Traffic Direction — the Key Discriminator

> 🔴 **Critical for triage.** Most lateral-movement tools in this module (Impacket's `psexec.py`/`wmiexec.py`, NetExec, etc.) show the **operator's** box initiating a connection *to* the target. A `multi/handler` catching a `reverse_tcp`/`reverse_http`/`reverse_https` payload is the **opposite**: the compromised **target** initiates the outbound connection *to* the operator's listener. If you're looking at NetFlow/firewall logs and trying to decide whether a given internal-to-external (or internal-to-internal) connection represents an operator reaching in or a beacon reaching out, the direction of the *first* packet in the flow is the tell — a target-initiated outbound connection to an unfamiliar external (or unusual internal) IP, especially one that recurs at a regular or semi-regular interval, is the signature to hunt, not an inbound one.

| Transport | Who initiates | What it looks like |
|---|---|---|
| `reverse_tcp` | Target → operator | A single long-lived TCP connection from the target, held open for the session's duration |
| `reverse_http` / `reverse_https` | Target → operator | Periodic polling HTTP(S) requests (WinInet-based on Windows targets — see `../Meterpreter/01 - Overview.md`), not one continuous socket. `reverse_https` is TLS-wrapped |
| `bind_tcp` | Operator → target | The target listens; the **operator's** box makes the outbound connection — the only transport where the direction matches the rest of this module's tools |

## Network-Layer Evidence

| Source | What It Shows |
|---|---|
| NetFlow / firewall logs | A new, target-initiated outbound flow to an external (or unexpected internal) IP:port, often the first indicator available in environments without endpoint logging at all. For `reverse_tcp`, expect one long-lived flow; for `reverse_http(s)`, expect a recurring pattern of short flows to the same destination at a roughly consistent interval |
| Zeek `conn.log` | Same signal, richer metadata — flow duration is itself informative: a `reverse_tcp` session shows one very long-duration connection versus the short, repeated connections a `reverse_http(s)` polling pattern produces |
| Zeek `http.log` / `ssl.log` | For `reverse_http`/`reverse_https`, the request/response pattern and (for unencrypted `reverse_http`, or a TLS-terminating proxy in front of `reverse_https`) URI structure, User-Agent string, and any default/custom certificate fields configured on the handler (`HandlerSSLCert`) |
| Proxy logs | If the target's egress goes through a corporate web proxy, `reverse_http`/`reverse_https`'s WinInet-based transport respects that proxy configuration — proxy logs may be the only visibility into this traffic at all in a well-segmented network, since it never appears in a network sensor watching the perimeter directly |

## What Happens on the Target Once Caught

Once the handler completes the callback and a session is established, everything that follows is **payload-specific**, not msfconsole-specific:

- **Meterpreter payloads** (`windows/x64/meterpreter/reverse_tcp` and family) — reflective in-memory loading, TLV protocol, extension loading, `migrate`, `getsystem`, and every associated Sysmon/Event-Log/memory-forensics signature are covered in full in `../Meterpreter/04 - Target Evidence.md` and `../Meterpreter/05 - Detection and Hunting.md`. Not re-derived here.
- **Shell payloads** (`windows/x64/shell_reverse_tcp` and similar) — a plain command-shell process (`cmd.exe`) with a network handle back to the operator; whatever the operator subsequently types is a normal `cmd.exe` child-process chain, evidenced the same way any other remote-shell activity is (process creation events, command-line auditing).
- **However the payload arrived** — via an exploit module (`../Exploit Modules/`), a `psexec.py`-style push (`../../Impacket/psexec/04 - Target Evidence.md`), or a manually delivered `msfvenom` file (`../msfvenom/04 - Target Evidence.md`) — that delivery mechanism's own filesystem/registry/event-log footprint is a **separate, prior** artifact layer from the handler catch itself, and is documented on the corresponding sub-tool's own Target Evidence page.

## Where Module-Specific Target Evidence Actually Lives

| If the module was... | See |
|---|---|
| An `exploit/*` module | `../Exploit Modules/04 - Target Evidence.md` |
| An `auxiliary/*` module (scanner, DoS, fuzzer) | `../Auxiliary Modules/04 - Target Evidence.md` |
| A `post/*` module run against an existing session | `../Post-Exploitation Modules/04 - Target Evidence.md` |
| Metasploit's own SMB `psexec`-style module (`exploit/windows/smb/psexec`) | `../Metasploit PsExec (exploit-windows-smb-psexec)/04 - Target Evidence.md` |
| The delivered payload was Meterpreter | `../Meterpreter/04 - Target Evidence.md` |
| The delivered file was generated by `msfvenom` | `../msfvenom/04 - Target Evidence.md` |

## Building a Timeline

Because msfconsole's own target-side contribution is limited to the handler's network flow, the highest-value timeline anchor available from *this* page alone is: **[whatever the delivery mechanism's own artifacts show — see the table above] → target-initiated outbound connection to the handler's `LHOST:LPORT` (NetFlow/Zeek `conn.log`) → session establishment (payload-specific artifacts in `../Meterpreter/04 - Target Evidence.md` or equivalent) → post-exploitation activity.** Correlating the network flow's start timestamp against the operator-side `sessions.opened_at` database column (see `03 - Source Evidence.md`) is what ties a specific handler job, on a specific operator box, to a specific compromised host — the same correlation principle used throughout this module, just applied to an inbound-direction (from the target's perspective) rather than outbound-direction connection.
