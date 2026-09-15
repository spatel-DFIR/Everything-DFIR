# ngrok — Target Evidence

## Reframe: "target" for a tunneling tool is a network-perimeter question first

Per `03 - Source Evidence.md`'s opening reframe, when ngrok tunnels a service that already lives on the compromised host (RDP/SMB/reverse-shell exposure), that same host is both source and target — every artifact in `03` applies directly here too, and this file's filesystem/process/event-log sections describe that single host. What's genuinely distinct to *this* file, regardless of which role the host is playing, is the **network-perimeter evidence**: because ngrok's entire mechanism is a sustained outbound connection (`01 - Overview.md`'s architecture diagram), the organization's own firewall, proxy, and DNS logs are frequently the richest — sometimes the *only* — evidence available, especially when the host itself is never recovered for endpoint forensics at all (a BYOD device, a host wiped before response, or the phishing-kit-hosting case where the "target" is an external victim's browser, not an asset the investigating org controls).

## Contents
- [Filesystem Artifacts](#filesystem-artifacts)
- [Windows Event Logs](#windows-event-logs)
- [Sysmon](#sysmon)
- [Network-Layer Evidence — the Core Evidentiary Set](#network-layer-evidence--the-core-evidentiary-set)
- [Endpoint Security Product Behavior](#endpoint-security-product-behavior)
- [Memory Forensics](#memory-forensics)
- [Building a Timeline](#building-a-timeline)
- [Distinguishing Legitimate Developer Use from Malicious Abuse](#distinguishing-legitimate-developer-use-from-malicious-abuse)

---

## Filesystem Artifacts

| Artifact | Path | Notes |
|---|---|---|
| `ngrok.yml` config file | `%LocalAppData%\ngrok\ngrok.yml` (Windows), `~/.config/ngrok/ngrok.yml` (Linux), `~/Library/Application Support/ngrok/ngrok.yml` (macOS) | Same file/path catalog as `03 - Source Evidence.md` — present here too whenever the tunneling host and the exposed-service host are the same machine |
| `ngrok` binary | Wherever the operator placed it — no standard install path, since ngrok ships as a single portable executable with no installer requirement | An EV-signed (`01 - Overview.md`, since 2026-02-24) but otherwise unremarkable Go binary; no ngrok-specific PE resource has been confirmed to embed a distinctive `OriginalFileName` value the way AnyDesk's does — **flagged as unverified rather than asserted**, and not to be relied on as a rename-survival signal until independently confirmed against a live sample |
| Windows service binary copy (if `ngrok service install` used) | Wherever `--config`/the install step pointed, commonly alongside the original binary | Standard Windows-service-registration pattern, not an ngrok-specific artifact |

## Windows Event Logs

Where ngrok is tunneling RDP or SMB on the same host it's running on, the exposed service's **own** logon/access events fire exactly as if the connection arrived over a normal network path — ngrok is transparent at this layer, so this module does not re-derive that evidence table:

- RDP session evidence (Security 4624/4625 Logon Type 10, TerminalServices-RemoteConnectionManager 1149, etc.) — see `Windows/12 - Lateral Movement.md` and the existing `Windows/` RDP-specific notes for the full event-ID catalog; the only ngrok-specific wrinkle is that the connecting **source IP** recorded in these events will be ngrok's own edge infrastructure IP, not the operator's real IP — the operator's actual origin is not recoverable from the target host's own logs at all in this configuration.
- SMB/lateral-movement evidence via a tunneled 445 — see `Windows/12 - Lateral Movement.md` and `Impacket/`'s own Target Evidence pages for the exact event-ID sets those tools generate; again, the ngrok tunnel only changes the apparent source IP, not the underlying SMB/RPC evidence itself.

## Sysmon

| Event ID | Signal |
|---|---|
| 1 (Process Create) | `ngrok.exe`/`ngrok` launching, with the full command line (`ngrok http 8080`, `ngrok tcp 3389`, etc. — directly states operator intent, `03 - Source Evidence.md`) |
| 3 (Network Connect) | The persistent outbound connection to the control-channel domain, and (for the host being tunneled *from*, if different from the exposed-service host) any local loopback connection from the agent to the upstream service it's forwarding to |
| 11 (FileCreate) | `ngrok.yml` creation/modification if `ngrok config add-authtoken` was run on this host |
| 22 (DNSEvent) | Resolution of `connect.<region>.ngrok-agent.com` / `tunnel.<region>.ngrok.com` (control channel) and, separately, whatever public endpoint domain was assigned (`*.ngrok.io`, `*.ngrok.app`, `*.ngrok-free.app`, `*.ngrok-free.dev`) — the single most durable DNS signal this tool generates, per `01 - Overview.md`'s red-flag callout |

## Network-Layer Evidence — the Core Evidentiary Set

| Signal | Detail | Confidence |
|---|---|---|
| DNS/TLS-SNI to the control-channel domain | `connect.<region>.ngrok-agent.com` (current agents, v3.3.0+) or `tunnel.<region>.ngrok.com` (legacy) — verified against community-documented agent connect-URL behavior; this connection is **mandatory** for the agent to function at all | **High** — an operator cannot remove this without abandoning ngrok's architecture entirely |
| DNS/TLS-SNI to the public endpoint domain | `*.ngrok.io`, `*.ngrok.app`, `*.ngrok-free.app`, `*.ngrok-free.dev` | **High on the free/default tier** — but a **paid bring-your-own custom domain** (`01 - Overview.md`'s domain-tier table) replaces this with the operator's own domain in TLS SNI, meaning this specific signal is evadable on paid plans; the control-channel domain above is not |
| Sustained long-lived TCP 443 flow | A single flow persisting for the entire tunnel-active window, rather than the short discrete connections typical of ordinary web browsing | Medium — useful for anomaly/duration-based detection (unusually long-lived outbound 443 sessions) even where the destination hostname itself isn't directly loggable (e.g. TLS 1.3 with ECH, or DNS-over-HTTPS bypassing local DNS logging) |
| TLS session content | Standard TLS — no plaintext content recoverable from a passive capture beyond SNI/certificate metadata at connection setup | N/A for content inspection; destination/duration metadata is what's actually usable |
| Source IP as seen by the exposed service | Will be an ngrok edge IP, not the operator's real IP, for the RDP/SMB self-tunnel case (Windows Event Logs, above) | N/A for attribution — this is an evidentiary *gap*, not a signal, worth stating explicitly rather than silently omitting |

## Endpoint Security Product Behavior

Same allowlisting dynamic already documented for AnyDesk (`AnyDesk/04 - Target Evidence.md`): ngrok is a **legitimately EV-signed binary** (`01 - Overview.md`, since 2026-02-24) from a well-known, widely-installed developer tool vendor — many EDR/AV products score a known-good vendor signature at low suspicion by default, and ngrok is genuinely present on a huge number of legitimate developer workstations already, so raw presence triggers little reflexive suspicion. No ngrok-specific CVE or compromised-certificate incident comparable to AnyDesk's February 2024 event has surfaced in the sources checked for this note — flagged as a genuine difference rather than an oversight; this tool's abuse detection leans almost entirely on network-destination and behavioral signals (below) rather than any static-signature weakness in the binary itself.

## Memory Forensics

Covered in full in `03 - Source Evidence.md`'s Memory Forensics section — identical artifact set (authtoken/session token, current tunnel address, in-flight HTTP request data for the inspection UI) regardless of which role (self-tunnel target, or attacker-owned infrastructure) the host is playing.

## Building a Timeline

1. Delivery — `ngrok` binary appearing on disk (Sysmon 11), or first `ngrok.exe` process creation if it arrived via an existing foothold rather than a fresh drop
2. Configuration — `ngrok config add-authtoken` execution or `ngrok.yml` creation/modification (Sysmon 1/11), or an `NGROK_AUTHTOKEN`-set environment observed in process/shell data (`03 - Source Evidence.md`)
3. Tunnel start — the control-channel DNS resolution and TCP 443 connection establishing (Sysmon 22/3) — this timestamp brackets the start of the entire tunnel-active window
4. Exposed-service activity — for a self-tunneled RDP/SMB case, the target service's own logon/session events (Windows Event Logs, above) fall *inside* the bracket established in step 3; for a phishing-kit or C2-fronting case, the first inbound request through the tunnel (only recoverable from the source-side inspection UI, `03 - Source Evidence.md`, if that host is in scope)
5. Persistence check — was `ngrok service install` used (OS-level service-registration artifacts, `03 - Source Evidence.md`), or was this a single foreground process that ends when the terminal/session closes?
6. Teardown — process termination (Sysmon 5, if logged) and the corresponding drop in the control-channel TCP flow (Network-Layer Evidence, above) — this closes the bracket opened in step 3

## Distinguishing Legitimate Developer Use from Malicious Abuse

ngrok's install base is overwhelmingly legitimate — it is a mainstream developer tool for exposing local development servers, webhook receivers, and demos, used constantly in normal software-engineering workflows with zero malicious intent. No single artifact in this file proves abuse on its own, the same caveat this module already makes for AnyDesk and every other dual-use tool. The differentiators that actually matter in practice:

- **What's being tunneled.** A developer exposing a local `localhost:3000` web-app dev server for a demo or webhook test looks structurally different from a tunnel targeting **RDP (3389) or SMB (445)** on a production or domain-joined host — those two ports have essentially no legitimate justification for ngrok exposure in most enterprise environments and should be treated as a high-confidence signal on their own.
- **Which account.** Correlate the authtoken/account recovered in `03 - Source Evidence.md` against your organization's own known, approved ngrok accounts (if developers are permitted to use it at all) — an unrecognized account is a stronger signal than the tool's mere presence.
- **Persistence configuration.** A `ngrok service install`-registered, reboot-surviving tunnel on a server-class asset is a materially different risk posture than a developer's foreground `ngrok http 3000` running only while they're actively working, closing when their terminal does.
- **Policy stance.** Per the same CISA guidance this module already cites for AnyDesk/RMM tools generally: if ngrok is not part of an environment's approved developer-tooling baseline at all, block egress to its control-channel and endpoint domains outright (proxy/firewall category block, or explicit domain blocklist) rather than only monitoring; if it is legitimately used by engineering teams, scope the policy to **which hosts and which local ports** may be tunneled, not a blanket allow/deny on the tool itself.
