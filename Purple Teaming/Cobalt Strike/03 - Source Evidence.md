# Cobalt Strike — Source Evidence

What an operation leaves behind on the **Team Server / operator side** — the Linux host running `teamserver`, and the operator's own Client console. Cobalt Strike being closed-source and network-based means this section leans more heavily on the framework's own documented logging/data-model behavior (verified against Fortra's docs and Google Cloud's technical breakdown) than on reverse-engineered internals — flagged inline where a detail is third-party-inferred rather than vendor-confirmed.

## Contents
- [Team Server Process and License File](#team-server-process-and-license-file)
- [Team Server Logs](#team-server-logs)
- [Team Server Data Store](#team-server-data-store)
- [Malleable C2 Profile File](#malleable-c2-profile-file)
- [Network State](#network-state)
- [Operator Client Artifacts](#operator-client-artifacts)
- [Shell History](#shell-history)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Team Server Process and License File

The Team Server runs as a Java process (`java ... cobaltstrike.jar server ...`, launched by the `teamserver` shell script) — visible via `ps`/`Get-Process` equivalents as a long-lived `java` process holding open the management port and every configured listener port. Its license artifact, **`CobaltStrike.auth`**, sits alongside the install and is the source of the watermark value embedded in every Beacon this server generates (`01 - Overview.md`) — its presence, modification time, and (where forensically recoverable) contents are directly relevant to establishing whether an install is a legitimate licensed copy or a fabricated/cracked one.

## Team Server Logs

Per Google Cloud's technical breakdown of Cobalt Strike's on-disk logging behavior, an active engagement's Team Server directory accumulates a structured, **plaintext** log tree under the install's `logs/` directory:

| Path pattern | Contents |
|---|---|
| `logs/<date>/<internal-ip>/<beacon-id>.log` | Full plaintext command history for one specific Beacon session — every operator command and its returned output |
| `logs/<date>/events.log` | Operator connection events and initial Beacon callback events |
| `logs/<date>/web.log` | Every web request the Team Server's listeners served, including stager downloads |

This is the single richest source-side evidentiary artifact for reconstructing exactly what an operator did, in order, against which target — a direct analog to a shell operator's own command history, except captured server-side and covering every session the Team Server ever handled, not just one operator's local terminal.

## Team Server Data Store

The Team Server persists its session/listener/credential state as serialized Java objects under the install's `data/` directory — again per Google Cloud's breakdown:

- **`sessions.bin`** — historical Beacon session records and metadata (host, first/last check-in, architecture, etc.)
- **`listeners.bin`** — every listener job ever configured on this Team Server, including inactive/stopped ones
- **`credentials.bin`** — the full credential data model (everything captured via `logonpasswords`/`hashdump`/`dcsync`/manual entry), independent of whether any individual Beacon session is still active

These `.bin` files persist the engagement's state across a Team Server restart — recovering them from a compromised or seized Team Server host reconstructs the operator's full session/credential picture even if the live process has already been killed.

## Malleable C2 Profile File

The `.profile` file passed to `teamserver` at startup (`01 - Overview.md`) is itself a durable artifact: its full contents describe exactly how this deployment's network traffic was shaped (URIs, headers, User-Agent, sleep/jitter, DNS options) — recovering it turns every downstream network IOC in `04 - Target Evidence.md` from a guess into a confirmed match, and is the single highest-value artifact for building a precise network detection against this specific deployment rather than a generic "default Cobalt Strike" one.

## Network State

- **TCP 50050** — the Team Server's TLS-protected, password-authenticated management port; a live `ss -tlnp`/`netstat` capture on the server host shows this bound regardless of which C2 transports are configured, and any established connections on it identify connected operator Client consoles by source IP.
- **Configured listener ports** — whatever HTTP(S)/DNS/SMB/TCP ports the operator stood up (`01 - Overview.md`'s listener table); cross-reference against a live `jobs`-equivalent capture rather than assuming defaults, since every listener port is operator-configurable.
- Google Cloud's writeup flags that the Team Server's management port **lacks default authentication hardening beyond the shared password** — scanners can enumerate exposed Team Servers by probing for the characteristic TLS handshake on 50050 even without valid credentials, a network-recon angle worth noting for source-side hunting on infrastructure an analyst suspects may be a rogue/unauthorized Team Server.

## Operator Client Artifacts

On any machine that might be an operator's Client console (not just the Team Server host itself):

- The Client's local connection profile/config (host, port, saved credentials for auto-reconnect) — exact path is version- and OS-dependent; search broadly by filename pattern rather than assuming one fixed location.
- **`.cobaltstrike.beacon_keys`** — the serialized keystore of Beacon connection keys on the Team Server side; a matching public key across two Beacons indicates the same Team Server keystore, with the same "copy ≠ same physical server" caveat that applies to the watermark (`01 - Overview.md`).

## Shell History

Bash/zsh history on the Team Server host is the most direct evidence of the `teamserver` launch command itself — including the profile path and Kill Date argument, both otherwise only recoverable from the running process's argument list or the profile file directly:

```
grep -E 'teamserver|c2lint' ~/.bash_history ~/.zsh_history
```

## Memory Forensics

A live or recently-terminated `teamserver` Java process's memory holds material not persisted to the `.bin` data store in real time: in-flight beacon tasking not yet returned, the decrypted license/watermark derivation, and (per the licensing discussion in `01 - Overview.md`) any private key material backing the Beacon connection keystore. Acquire with a platform-appropriate Linux memory tool (AVML/LiME) rather than treating this as a query-style hunt — it's an acquisition step.

## Timeline Correlation Value

Every artifact above — the per-beacon `.log` file's command timestamps, `events.log`'s callback timestamps, and the `web.log`'s stager-download timestamps — carries **server-side wall-clock timestamps that are authoritative for correlating operator action to target-side effect** (`04 - Target Evidence.md`'s event-log/Sysmon timestamps). Where source and target evidence are both recoverable, cross-referencing a `beacon-id.log` command against the matching target-host Sysmon/event-log entry in the same narrow time window is the strongest possible confirmation that a given host action was in fact Cobalt Strike-driven, rather than inferred from indicators alone.
