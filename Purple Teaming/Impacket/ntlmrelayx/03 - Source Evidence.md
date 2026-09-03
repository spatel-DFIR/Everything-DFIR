# Impacket — ntlmrelayx.py — Source Evidence

Evidence left on the **attacking/relay** host. `ntlmrelayx.py` is structurally different from every other Impacket tool already covered in this folder — `psexec.py`/`wmiexec.py`/`smbexec.py`/`secretsdump.py` are all **one-shot clients** that connect out, do one thing, and exit. `ntlmrelayx.py` is a **long-running listener** — it binds multiple server sockets and waits, sometimes for hours, for inbound authentication to arrive. That difference reshapes almost every artifact class below: the network-state signature is unlike anything else in this folder, the process runs far longer (raising its odds of being caught live), and the loot it produces is heterogeneous — hashes, `.pfx` certificates, `.eml` files, `.sam` dumps, and NTDS output can all come out of a single invocation depending on which relay targets fired.

## Contents
- [Local Output Files — Loot Is Heterogeneous by Design](#local-output-files--loot-is-heterogeneous-by-design)
- [Live Process State — a Long-Running Listener, Not a One-Shot Client](#live-process-state--a-long-running-listener-not-a-one-shot-client)
- [Local Network-Connection State — Multiple Bound Listening Servers at Once](#local-network-connection-state--multiple-bound-listening-servers-at-once)
- [Shell History](#shell-history)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Local Output Files — Loot Is Heterogeneous by Design

Unlike `secretsdump.py`, where every output file is some flavor of credential dump, `ntlmrelayx.py`'s `-l`/`--lootdir` (default: current directory) can accumulate radically different artifact types in the same run, one per attack module that fired:

| Extension / pattern | Produced by | Notes |
|---|---|---|
| `<host>_samhashes.sam` | Default SMB relay | Local SAM hashes only — see `02`'s correction: no LSA-Secrets equivalent from this path |
| `<username>.pfx` | ADCS attack (HTTP or ICPR) | PKCS#12 certificate + private key — a **durable, long-lived credential**, not a point-in-time hash; treat its presence as evidence of an ongoing access grant, not just a completed action |
| `<host>_<timestamp>_sccm_policies_loot/` (directory) | `--sccm-policies` | Contains the fake device's own generated `cert.pem`/`key.pem`, `guid.txt`, `client_name.txt`, `policies.json`/`policies.raw`, and one subdirectory per decrypted secret policy — the Network Access Account credential pair is the highest-value item inside |
| `<host>_<timestamp>_sccm_dp_loot/` (directory), `packages/<packageID>/...` | `--sccm-dp` | Raw files pulled off the Distribution Point — scripts, task-sequence XML, `.pfx` certs, whatever matched the configured extension list |
| `mail_<user>-<mailbox>_<index>.eml` | IMAP attack | One file per harvested message |
| `hashes.*` (encrypted-hash / NTDS-style output) | DCSync relay (Zerologon path) | Written by the reused `NTDSHashes` class — same extension family as `secretsdump.py`'s own `.ntds`/`.ntds.kerberos` output, see `Impacket/secretsdump/03 - Source Evidence.md` |
| Restore-state files (`writeRestoreData`) | LDAP ACL/delegation attacks | The LDAP attack module writes a **restore file recording the pre-attack state of whatever it modified** — this is itself a notable artifact: its presence proves an LDAP-write attack ran and documents exactly what value to roll back to, which is also directly useful to an incident responder doing remediation |

A single `ls -R` of the lootdir after a multi-protocol relay session can therefore look like several unrelated tools' output sitting side by side — that heterogeneity is itself a tell that `ntlmrelayx.py` (or something functionally identical) produced it, rather than a single-purpose credential-dumping tool.

## Live Process State — a Long-Running Listener, Not a One-Shot Client

```bash
ps aux | grep -i ntlmrelayx
```
Because `ntlmrelayx.py` runs indefinitely (until the operator kills it or its target list is exhausted with `-remove-target` behavior in play), it has a **materially longer live-process window** than any sibling tool in this folder — a `psexec.py` shell might exist as a process for seconds; an `ntlmrelayx.py` listener realistically runs for the duration of an entire engagement day. The full command line (target list flags, `-c`/`-e` payloads, `--adcs`/`--delegate-access`/`--sccm-*` attack flags) is visible via `/proc/<pid>/cmdline` for that entire window, to any local user on a shared operator box. `-tf` invocations are especially notable here — the file path itself, if recoverable, enumerates the full intended target scope even before any relay succeeds.

## Local Network-Connection State — Multiple Bound Listening Servers at Once

This is the single most distinctive source-side signature `ntlmrelayx.py` has that no other tool in this folder shares — a **live socket footprint spanning several simultaneously bound listening ports**, not one outbound client connection:

```bash
ss -tlnp | grep -E ':445|:80|:9389|:6666|:135|:1433|:3389|:5985|:5986'
```

| Port | Server | Notes |
|---|---|---|
| 445 | SMB | Disabled with `--no-smb-server`; conflicts with a genuine SMB service on the same host unless that's stopped first — a host running both a real file server and `ntlmrelayx.py`'s SMB listener is a contradiction worth investigating |
| 80 / configurable ranges | HTTP | `--http-port`, supports comma-lists/ranges — an unusually wide simultaneous port-range bind (`8000-8010` alongside `80`) is itself atypical of ordinary web server configuration |
| 9389 | WCF/ADWS | Rare to see anything legitimately listening here outside a real Domain Controller |
| 6666 | RAW | No legitimate common service uses this port by convention — a strong positional anomaly on its own |
| 135 | RPC | Overlaps with genuine RPC endpoint mapper usage, weaker signal in isolation |
| 1433 | MSSQL | Anomalous on a host that isn't a database server |
| 3389 | RDP | Anomalous alongside the rest of this set on a non-RDS host |
| 5985/5986 | WinRM | Same anomaly reasoning as RDP |

**The pattern that matters is not any single port — it's several of these bound simultaneously by one process**, especially combinations that make no sense for a single legitimate service (SMB + MSSQL + RDP listeners all owned by the same PID, for instance). `--no-<protocol>-server` flags narrow this footprint deliberately — an operator using them to avoid a suspiciously broad simultaneous bind is itself an OPSEC tell worth correlating against how many relay-target protocol types actually appear in the same run's loot/logs.

```bash
lsof -i -P -n | grep ntlmrelayx
```
`lsof` (or `ss -p` where privileged) ties each bound port back to the same PID directly — the fastest way to confirm "one process, many simultaneous servers" live on a suspected relay host.

**Outbound connection state** (the relay-target leg) is comparatively unremarkable — one outbound TCP connection per active relay target, torn down and re-established as targets rotate (`-tf`) or new authentication arrives. `-socks` mode adds a further distinctive local listener (`-socks-port`, default 1080) plus an HTTP control-API port (`-http-api-port`, default 9090), both worth adding to the port-sweep above when SOCKS usage is suspected.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | The full invocation, including target lists, attack-specific flags (`--delegate-access`, `--adcs`, `--sccm-policies`), and inline credentials (`-auth-smb`) — the flag combination alone reveals attacker intent precisely (e.g. `-t dcsync://` plus no `-auth-smb` unambiguously signals a Zerologon-dependent DCSync attempt, not a legitimate-rights DCSync) |
| zsh | `~/.zsh_history` | Same content, plus timestamp with `EXTENDED_HISTORY` |
| fish | `~/.local/share/fish/fish_history` | YAML-structured, native per-command timestamps |

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Version matters more here than for most sibling tools — the `--sccm-policies`/`--sccm-dp`/`--remove-sign-seal` (CVE-2025-33073) flags are all comparatively recent additions; an older install simply lacks them |
| Script location | `find / -iname "ntlmrelayx.py" 2>/dev/null` | Source checkout, pip console-script, or pipx isolated environment |
| Git checkout evidence | `.git/logs/HEAD` inside a cloned `impacket/` directory | Pins the exact revision and therefore the exact attack-module set available |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path, and specifically under `impacket/examples/ntlmrelayx/attacks/` and `.../clients/` | A coarse "which attack modules were ever imported/exercised on this box" signal — a `.pyc` for `dcsyncclient.py` existing is a meaningful marker even without a matching shell-history line |

## OS-Level Audit Trail

```bash
ausearch -x ntlmrelayx.py 2>/dev/null
```
Same value proposition as the rest of this folder — generated at the kernel `execve` level, survives a shell-history wipe. Given how long-lived the process is, an `auditd` record for `ntlmrelayx.py`'s start time can meaningfully predate any target-side evidence by hours, since the listener may have sat idle waiting for an authentication attempt before anything downstream happened at all.

## Memory Forensics

If the operator box is seized/imaged while `ntlmrelayx.py` is still running (a materially more likely scenario here than for any one-shot sibling tool, given the process lifetime):

- **Live relay state** — the process holds in memory the target list, any currently-in-progress NTLM Type1/2/3 exchanges, and (for `-socks` mode) the full set of currently-alive relayed sessions and their session keys. A memory capture (`gcore`, VM snapshot) taken mid-engagement can reveal sessions that never made it to a completed attack module and therefore left **no loot file at all** — the only place that access ever existed was in this process's memory.
- **Recovered credential/certificate material** — for a DCSync relay, the Zerologon-derived Netlogon session key and the resulting NTDS data pass through memory before (or instead of, if a run is interrupted) landing in an output file. For an ADCS relay, the generated RSA private key exists in memory before being serialized into the `.pfx`.
- A targeted string/regex search for PEM/PKCS12 headers (`-----BEGIN`, PFX magic bytes), NTLM hash format (`[0-9a-f]{32}`), or SOCKS-proxy session-table structures is a viable recovery path independent of what made it to disk.

## Timeline Correlation Value

`ntlmrelayx.py`'s source-side timeline has a structure the one-shot sibling tools don't: **listener start time is frequently disconnected from attack execution time by an arbitrary, unpredictable gap** — the process can sit bound and idle for hours before any authentication arrives to relay. This means the operator-side "when did this start" artifact (process start via `ps`/`auditd`, or the listening-socket bind time) is **not** a reliable proxy for "when did the attack happen" the way it is for `psexec.py`'s near-instantaneous connect-then-execute pattern. The event that actually anchors a timeline is the **first successfully relayed authentication**, which correlates against target-side evidence in two places at once — the **victim's** outbound authentication attempt (whatever triggered it — Responder poisoning, a coercion primitive's forced auth) and **Target B's** inbound logon (`04 - Target Evidence.md`). Build the timeline from that middle point outward in both directions, rather than assuming the operator-side process-start timestamp is where the story begins.
