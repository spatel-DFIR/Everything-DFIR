# ngrok — Overview

> 🔴 **Red Flag Principle:** ngrok's entire design is **outbound-only** — the agent running on a host always *initiates* a connection out to ngrok's cloud, and public traffic is routed back down through that already-established tunnel. **No inbound port is ever opened on the tunneled host**, which is precisely why it defeats NAT/firewall egress-filtering the way it does: from the network's own perspective, the traffic is indistinguishable in shape from any other outbound HTTPS session. The one thing an operator cannot remove from that picture: the agent's persistent control-channel connection to a `*.ngrok-agent.com`/`*.ngrok.com` hostname, and — unless they're paying for a bring-your-own custom domain — the public endpoint itself resolves under ngrok's own namespace (`*.ngrok.io`, `*.ngrok.app`, `*.ngrok-free.app`, `*.ngrok-free.dev`). Hunt the DNS/TLS-SNI destination, not "is there a listening port."

## Contents
- [History](#history)
- [How It Works](#how-it-works)
- [Techniques / Protocols Used](#techniques--protocols-used)
- [Command-Line Switches — Quick Reference](#command-line-switches--quick-reference)
- [Quick Use-Case List](#quick-use-case-list)
- [Prerequisites](#prerequisites)

---

## History

Verified against ngrok's own [FAQ](https://ngrok.com/docs/faq/) and corroborating sources ([ngrok's About page](https://ngrok.com/about), Twilio's own retrospective interview with the founder):

- ngrok was created by **Alan Shreve** ("inconshreveable"), then a software developer at Twilio — per ngrok's own FAQ, "the first prototype for ngrok was committed on March 20th, 2013" and released as **free, open-source software on GitHub**, written in Go partly as a language-learning exercise.
- The project grew organically to **5 million users** on a bootstrapped, customer-revenue-funded model for **seven years** before the company (now **ngrok, Inc.**) raised a **$50 million Series A in 2022** — its first outside funding.
- **Version lineage**, per ngrok's own docs: **v1**, "the original open source ngrok agent," is now explicitly "no longer developed, supported, or maintained." The current agent is **v3**, a closed-source, commercially operated rewrite — config files, CLI flags, and API described in this note are all v3-current.
- **February 24, 2026** — ngrok began signing Windows binaries with a **DigiCert EV (Extended Validation) certificate** issued to **ngrok, Inc.**, replacing the standard (OV) certificate used previously (verified against [ngrok's own blog post](https://ngrok.com/blog/windows-ev-certificate)). EV signing grants Microsoft's SmartScreen immediate trust with no "unknown publisher" warning — directly relevant to `04 - Target Evidence.md`'s endpoint-security-behavior discussion, since it means a fresh `ngrok.exe` download now carries the same class of trusted-vendor signature that already makes tools like AnyDesk (`AnyDesk/`) attractive for abuse.
- **MITRE ATT&CK tracks ngrok as its own numbered Software entry, [S0508](https://attack.mitre.org/software/S0508/)** — unlike most legitimate dual-use tools in this module (AnyDesk, Rclone), which appear only as technique procedure examples, ngrok gets a dedicated entry describing it plainly as "a legitimate reverse proxy tool" leveraged by threat actors "for lateral movement and data exfiltration." MITRE credits it to five named groups: **Scattered Spider (G1015)**, **OilRig (G0049)**, **Ember Bear (G1003)** (Ukraine-targeted intrusions), **LazyScripter (G0140)**, and **Fox Kitten (G0117)**, plus the **SharePoint ToolShell Exploitation (C0058)** campaign.

## How It Works

### Architecture — agent, control channel, and edge

ngrok has **no operator-controlled server component**, the same structural point already made about AnyDesk (`AnyDesk/01 - Overview.md`) — every ngrok user runs the same off-the-shelf agent, and the vendor's own cloud infrastructure (the "edge") brokers every public connection. Verified against ngrok's [Agent docs](https://ngrok.com/docs/agent/) and corroborating technical write-ups on the agent-to-edge connect domain:

```
[ Public Internet ]                    [ ngrok Cloud Edge ]                [ ngrok Agent (on the tunneled host) ]
        │                                       │                                       │
        │                                       │◄── 1. Agent authenticates with its ───┤
        │                                       │     authtoken and opens a persistent  │
        │                                       │     outbound TLS 443 control-channel  │
        │                                       │     connection to connect.<region>    │
        │                                       │     .ngrok-agent.com (legacy agents:  │
        │                                       │     tunnel.<region>.ngrok.com,        │
        │                                       │     pre-agent-v3.3.0)                 │
        │                                       │                                       │
        │                                       │──── 2. Edge assigns a public URL ────►│
        │                                       │     (random subdomain, the account's  │
        │                                       │     one free static dev-domain, or a  │
        │                                       │     paid reserved/custom domain)      │
        │                                       │                                       │
        │── 3. Client requests the public URL ─►│                                       │
        │   e.g. https://random123.ngrok-       │                                       │
        │   free.app or tcp://1.tcp.ngrok.io:N  │                                       │
        │                                       │── 4. Traffic multiplexed down the ───►│
        │                                       │     SAME already-open control         │
        │                                       │     connection — no new inbound       │
        │                                       │     connection to the agent's host    │
        │                                       │     is ever made                      │
        │                                       │                                       │
        │                                       │                                       │── 5. Agent forwards to
        │                                       │                                       │   the local upstream
        │                                       │                                       │   (127.0.0.1:<port>,
        │                                       │                                       │   or another reachable
        │                                       │                                       │   host/IP)
```

- **Outbound-only by design.** Step 1 is the single fact that explains every downstream evidentiary and evasion property in this note: because the agent dials out and multiplexes all subsequent traffic (control *and* tunneled data) over that one connection, there is structurally no firewall rule, port-forward, or router configuration for a defender to find on the tunneled host's own network edge — the entire mechanism is indistinguishable in shape from a normal outbound HTTPS session until you inspect the destination.
- **Public endpoint domain tiers**, verified against ngrok's [domains documentation](https://ngrok.com/docs/universal-gateway/domains/) and corroborating reporting on the 2023 pricing change:

  | Tier | Domain example | Persistence | Cost |
  |---|---|---|---|
  | Ephemeral random URL | `85ee564738gc.ngrok.io`-style, new on every `--url ''`/no-URL invocation | Changes every run | **Paid plans only** — per ngrok's own docs, "random domain generation... is only available on paid plans" |
  | Free static dev domain | `panda-new-kit.ngrok-free.app`-style | **Persists indefinitely across agent restarts and reboots** — it's assigned once to the account | **Free** — every free account gets exactly one |
  | Reserved/custom ("branded") domain | `c2.attacker-owned-domain.com` via CNAME, or a reserved `foo.ngrok.app` subdomain | Persists until explicitly released | **Paid ("Pay-as-you-go") plans** |

  This inverts a common assumption worth stating plainly, since it's directly relevant to persistence: **a free ngrok account is now the one that gets a fixed, unchanging public hostname by default** — genuinely fresh random subdomains on every run (the classic evasion move) require a paid plan. See `05 - Detection and Hunting.md` for how this reshapes the hunting-priority ranking.
- **HTTP vs. TCP vs. TLS tunnels** — `ngrok http` terminates and inspects HTTP(S) at ngrok's edge (enabling the request-inspection UI, header injection, Basic Auth gating, traffic policies); `ngrok tcp` and `ngrok tls` instead forward the raw byte stream (or raw TLS stream) straight through with no protocol awareness — this is the mode used to expose non-HTTP services like RDP (3389) or SMB (445) that have nothing to do with HTTP at all.
- **Local web inspection interface** — the agent binds a local-only web UI, by default `127.0.0.1:4040` (verified against ngrok's [web inspection interface docs](https://ngrok.com/docs/agent/web-inspection-interface/)), showing every HTTP request/response that transited an HTTP tunnel in real time — including source IPs, headers, and bodies — with a **Replay** feature to resend a captured request. This is a genuine local artifact-generation point covered in `03 - Source Evidence.md`.

## Techniques / Protocols Used

| Layer | Detail |
|---|---|
| Control channel | Persistent outbound TLS 443 session from agent to `connect.<region>.ngrok-agent.com` (current) or `tunnel.<region>.ngrok.com` (legacy, pre-3.3.0 agents) |
| Public endpoint (HTTP mode) | TLS-terminated HTTP(S) at ngrok's edge, forwarded to the local upstream; supports Basic Auth gating, header rewriting, and inline traffic-policy YAML |
| Public endpoint (TCP/TLS mode) | Raw byte-stream or raw-TLS forwarding with no protocol parsing — used for RDP, SMB, SSH, or any custom binary protocol |
| Authentication | Account-bound authtoken (`ngrok config add-authtoken`, or the `NGROK_AUTHTOKEN` environment variable, which ngrok's own docs state "take[s] precedence over" the config-file value) |
| Local inspection | `127.0.0.1:4040` web UI/API, request capture and replay |
| Multi-tunnel orchestration | `ngrok.yml` v3 config (`agent:`/`endpoints:` keys) + `ngrok start` to launch several named endpoints from one invocation |

## Command-Line Switches — Quick Reference

Verified against ngrok's own [CLI reference](https://ngrok.com/docs/agent/), [HTTP endpoint docs](https://ngrok.com/docs/http/), and [TCP endpoint docs](https://ngrok.com/docs/universal-gateway/tcp/). Covers the commands/flags that matter for reading or writing a real invocation, not an exhaustive reproduction of `ngrok help`.

| Command / Flag | Plain-English meaning |
|---|---|
| `ngrok http <port\|url\|file://path>` | Exposes a local HTTP(S) service (or a local directory, served as static files) through an ngrok endpoint |
| `ngrok tcp <port\|host:port>` | Exposes a local **non-HTTP** service (RDP, SMB, SSH, a raw listener) by forwarding a raw TCP stream |
| `ngrok tls <port>` | Exposes a local service over raw TLS, for a custom protocol that isn't HTTP but still wants ngrok's TLS termination |
| `--url <url>` | Binds the tunnel to a specific public address — a previously reserved static domain/TCP address, or the account's free static dev domain — instead of a freshly random one |
| `--basic-auth <user:pass>` | Requires HTTP Basic Authentication before ngrok forwards a request to the local service (repeatable for multiple credential pairs) |
| `--request-header-add <header:value>` | Injects an additional HTTP header onto every request before it reaches the local upstream service |
| `--traffic-policy-file <path>` | Loads a YAML file of request/response inspection and routing rules, instead of specifying behavior purely via flags |
| `--upstream-tls-verify` | Makes the agent validate the local (upstream) service's own TLS certificate before forwarding to it — **off by default**, since ngrok assumes the local service sits on a trusted/private network |
| `--upstream-tls-verify-cas <path>` | CA bundle used when the above verification is turned on |
| `--upstream-protocol <http1\|http2>` | Sets which HTTP version the agent speaks to the local upstream service |
| `--upstream-proxy-protocol 2` (TCP tunnels) | Prepends a PROXY-protocol v2 header when forwarding, so the local service can see the real original client IP instead of a loopback address |
| `--authtoken <token>` | Supplies the account authtoken for this single invocation only, without writing it into `ngrok.yml` at all |
| `--config <path>` | Uses an alternate config file path (or merges multiple, if repeated) instead of the default OS location |
| `--metadata <string>` | Attaches an opaque, operator-defined tag to the tunnel session, visible via the API/dashboard — a bookkeeping field an operator could also misuse or accidentally leave identifying |
| `ngrok start <name> [<name>...] \| --all` | Launches one or more named endpoints already defined in `ngrok.yml` in a single command — how multiple simultaneous tunnels (e.g. RDP + a C2 listener) get brought up together |
| `ngrok config add-authtoken <token>` | Writes the account authtoken into `ngrok.yml`, permanently associating this installed agent with an ngrok account until changed |
| `ngrok config add-api-key <key>` | Stores an ngrok API key in the config file, for `ngrok api ...` calls |
| `ngrok config check` | Validates the config file's syntax and reports its resolved location |
| `ngrok config edit` | Opens the config file in the default editor |
| `ngrok config upgrade` | Migrates an older (v1/v2) config file to the current v3 schema |
| `ngrok service install` / `start` / `stop` / `restart` / `uninstall` | Registers (or controls) the agent as a background OS service — a Windows service, systemd unit, or launchd job — so tunnels persist across reboots and logins with no foreground terminal needed |
| `ngrok update` | Self-updates the agent binary to the latest released version |
| `ngrok diagnose` | Runs connectivity diagnostics against ngrok's own cloud infrastructure |
| `ngrok api <resource> <verb>` | Issues authenticated calls to ngrok's REST API directly from the CLI (e.g. `ngrok api reserved-domains list`) — how an operator manages reserved domains/addresses without ever touching the web dashboard |
| `ngrok version` / `ngrok credits` | Prints the installed agent version, or license/attribution info |
| `ngrok completion` | Generates shell tab-completion code |

## Quick Use-Case List

- HTTP tunnel exposing a locally-hosted phishing kit to the public internet under an ngrok domain
- HTTP(S) tunnel as an inbound-friendly callback front for an HTTP(S)-based C2 framework listener
- TCP tunnel exposing RDP (3389) on an already-compromised host for direct outside remote-desktop access
- TCP tunnel exposing SMB (445) so lateral-movement tooling on the operator's own machine can reach the target directly
- TCP tunnel fronting a raw reverse-shell/`nc` listener
- Reserved or free static domain used specifically for a **persistent, unchanging** C2 callback address that survives agent restarts and reboots
- TLS tunnel (`ngrok tls`) for a custom, non-HTTP C2 protocol that still wants TLS termination at ngrok's edge
- Serving a local directory (`ngrok http file://...`) as a payload-staging/drop server for ingress tool transfer
- Chained workflow: fronting an already-running C2 framework's HTTP(S) listener with an ngrok tunnel to bypass egress filtering entirely
- Fleet-wide/multi-host use: one ngrok agent per compromised host, each opening its own outbound tunnel back through the same (or different) operator account, as redundant per-host access channels
- Gating an exposed endpoint with `--basic-auth` so ngrok's public, guessable subdomain space can't be stumbled onto by scanners/researchers
- Installing the agent as a persistent background OS service (`ngrok service install`/`start`) so the tunnel survives reboots without a visible foreground process
- Using the local inspection UI (`127.0.0.1:4040`) to review captured credentials/requests from an active phishing tunnel in near-real time

Full walkthroughs with commands and MITRE ATT&CK mapping for every item above live in `02 - Hands-On Use Cases.md`.

## Prerequisites

| Requirement | Notes |
|---|---|
| ngrok account + authtoken | Required for essentially all use since ngrok's account-gating change — a free signup is enough for one HTTP/TCP/TLS tunnel at a time on the account's free static dev domain; reserved/custom domains, multiple simultaneous tunnels beyond the free limit, and traffic-policy features need a paid plan |
| Outbound reachability | The tunneled host needs outbound TCP 443 reachable to ngrok's control-channel domain (`connect.<region>.ngrok-agent.com`) — no inbound port is ever required |
| Local service to expose | Whatever is being tunneled (RDP, SMB, a C2 listener, a phishing kit's web server) must already be running and reachable from the host running the ngrok agent |
| Binary/install | A single portable `ngrok` executable (Windows/Linux/macOS) — no separate server component to install, unlike a C2 framework's Team Server |
| Reserved/custom domain (persistence use case) | Requires a paid plan and a one-time API/dashboard reservation step before it can be referenced with `--url` |
