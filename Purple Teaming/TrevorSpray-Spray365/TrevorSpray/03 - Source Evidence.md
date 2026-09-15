# TrevorSpray — Source Evidence

What the operation leaves on the **attacking/source** host (the box actually running `trevorspray`, or an SSH proxy host it round-robins through).

## Contents
- [The `~/.trevorspray/` Directory — the Whole Story](#the-trevorspray-directory--the-whole-story)
- [Shell/Command History](#shellcommand-history)
- [Process Artifacts](#process-artifacts)
- [Network Connection State](#network-connection-state)
- [SSH Proxy Host Artifacts](#ssh-proxy-host-artifacts)
- [Memory-Forensics Angle](#memory-forensics-angle)
- [Timeline-Correlation Value](#timeline-correlation-value)

---

## The `~/.trevorspray/` Directory — the Whole Story

Every run creates/updates this directory under the invoking user's home — verified directly against `trevorspray/lib/trevor.py` and `trevorspray/lib/logger.py`:

| File/Dir | Written by | Contents |
|---|---|---|
| `trevorspray.log` | `logger.py` (`FileHandler`, always on, DEBUG level regardless of console verbosity) | The complete run log — every request, every proxy assignment, every `AADSTS` response, timestamped, **even flags/behavior not shown on the console at default verbosity**. This is the single richest source-side artifact: it exists whether or not `-v` was passed at the console. |
| `tried_logins.txt` | `trevor.py` on `stop()` | Every `user:password` combo ever attempted for a given module+URL, keyed as `"<ModuleClassName>|<url>|<user>|<password>"` — a durable, cumulative fingerprint of the exact scope of every spray this operator (or this home directory) has ever run against a given target, across sessions |
| `existent_users.txt` | `trevor.py` on `stop()` | Every username the tool determined "exists" (via spray response or enumeration) across all runs — cumulative |
| `valid_logins.txt` | `trevor.py` on `stop()` | Every fully valid `user:password` combo ever found — cumulative, **plaintext**, and the single most sensitive artifact this tool produces on the source host |
| `loot/` | `discover.py`, `looters/msol.py` | Recon exports (`recon_<domain>_other_tenant_domains.txt`) and any downloaded Offline Address Book `.lzx` files pulled during the legacy-auth loot phase — the `.lzx` files are LZX-compressed and require `libmspack` to extract, but their mere presence proves a successful EWS/Autodiscover MFA-bypass hit occurred |

None of this is deleted automatically, ever — it accumulates across every invocation against every target from the same home directory. A forensic acquisition of an operator's box (or a compromised pentest-infrastructure VPS) that turns up `~/.trevorspray/` is effectively a complete operational history: every target domain, every username tried, and every valid credential found, in one place.

## Shell/Command History

Standard shell history (`~/.bash_history`, `~/.zsh_history`) captures the literal `trevorspray` invocation **including any password passed via `-p`/`--passwords` directly on the command line** rather than via a file — a common operator mistake for a "just testing one password" quick run. Passwords passed as file paths (`-p passwords.txt`) don't appear in history directly, but the file's own path and existence do.

## Process Artifacts

- Process name/command line: `trevorspray` (installed as a `pyproject.toml` console script — `trevorspray = 'trevorspray.cli:main'`) or `python3 -m trevorspray...` if run from source. Full argv, including `-u`/`-p`/`--url`/`-s` targets, is visible to anything with `ps`/`/proc/<pid>/cmdline` access while running.
- Because `--ssh` proxying is implemented via **actual local SSH client connections** (through `trevorproxy`'s `SSHProxy`, not a raw socket trick), each configured `-s user@host` target shows up as a **real, separate `ssh` child process** for the duration of the spray — visible in process listings and in the parent process's own audit/EDR telemetry as a `trevorspray → ssh` spawn relationship.
- `--subnet` spoofing requires and shells out to `iptables` (checked for at startup via `shutil.which`) — an `iptables` invocation from a Python process is itself an anomalous parent/child pairing worth flagging on a suspected attacker-controlled Linux host.

## Network Connection State

- Direct-mode (no `--ssh`/`--subnet`/`--proxy`) runs show a large number of short-lived outbound HTTPS connections from the operator's box directly to Microsoft/target infrastructure (`login.microsoft.com`, `login.microsoftonline.com`, `outlook.office365.com`, the target's own ADFS/Okta/VPN host, etc.) — netstat/`ss` at spray time will show many connections to a small set of destination IPs/hostnames in rapid succession.
- SSH-proxy mode instead shows persistent outbound SSH (TCP/22 by default) connections to each `-s` host, each tunneling a local SOCKS5 listener (`127.0.0.1:<base-port + N>` — default base port **33482**) that the actual HTTP client library connects through. A `netstat -tlnp` on the operator's box during a spray will show several `LISTEN` sockets clustered around port 33482+N — a distinctive local artifact independent of any traffic capture.
- `--subnet` mode requires the operator's own interface to be able to source-address-spoof — `ip -6 addr show` / `ip route` state on that box will reflect the configured `/64` if `iptables` rules were added persistently rather than cleaned up.

## SSH Proxy Host Artifacts

Each `-s user@host` target is a **separate system with its own evidentiary trail** — often overlooked because analysis focuses on the operator's own box:

- SSHD auth logs (`/var/log/auth.log` or equivalent) on the proxy host record every connection from the operator's real originating IP, including timestamps that bound the spray session.
- A high volume of short-lived outbound HTTPS connections *originating from the proxy host itself* toward the same Microsoft/target endpoints, correlated in time with the SSH session above — the proxy host is, from the target's perspective, the actual source IP of the spray traffic and carries its own local network-connection-state evidence exactly as described above.
- If the proxy host is a rented/disposable VPS, its provisioning/billing record (hosting provider logs, not filesystem evidence) is frequently the only durable link back to the operator once the VPS itself is destroyed post-engagement.

## Memory-Forensics Angle

- The Python process holds the full in-memory `Credential`/proxy-thread state for the run's duration — usernames, passwords, and every `AADSTS` response text are resident in the interpreter's heap while running. A memory acquisition of a live `trevorspray` process (or a crash dump) can recover the full in-progress credential set even if `~/.trevorspray/valid_logins.txt` hasn't been flushed yet (writes to that file only happen in `stop()`, i.e. at the very end of a run or on a clean `KeyboardInterrupt`).
- An unclean process kill (`kill -9`, VM snapshot revert, host power loss) means `tried_logins.txt`/`valid_logins.txt`/`existent_users.txt` are **never written** — only `trevorspray.log` (a live `FileHandler`, flushed incrementally line-by-line) survives an abrupt termination. This makes the log file the more forensically durable artifact of the two in a rushed/interrupted-operation scenario.

## Timeline-Correlation Value

`trevorspray.log`'s timestamped, DEBUG-level entries — one line per HTTP attempt, per proxy assignment, per detected lockout — give second-level granularity that lines up directly against the target-side Entra ID Sign-in Log timestamps in `04 - Target Evidence.md`. Because the log records **which proxy/IP served each request**, it's the definitive source-side answer to "which of our several egress IPs generated this specific target-side sign-in event" when reconciling a purple-team exercise's attacker-side and defender-side timelines.
