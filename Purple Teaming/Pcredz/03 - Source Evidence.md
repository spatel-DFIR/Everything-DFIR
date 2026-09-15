# Pcredz — Source Evidence

Evidence left on the **operator/analyst host** Pcredz was run from. Two very different profiles apply depending on mode: `-f`/`-d` (offline file parsing) is a one-shot, short-lived process with no network footprint of its own; `-i` (live capture) is a long-running, promiscuous-mode listener closer in shape to `Responder/`'s footprint — though, per `01 - Overview.md`'s red-flag principle, it never sends a packet, so its network-visible signature is fundamentally different from a poisoner's.

## Contents
- [Output Files](#output-files)
- [In-Memory State — What Does NOT Persist](#in-memory-state--what-does-not-persist)
- [Live Process, Promiscuous-Mode, and Socket State](#live-process-promiscuous-mode-and-socket-state)
- [Shell History](#shell-history)
- [Installation Artifacts and Version Dating](#installation-artifacts-and-version-dating)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Output Files

Verified against `write_data()` and the `run()`/`__main__` block in the live v2.1.0 source. All output lands under `-o`'s target directory (default: the current working directory at invocation) — a fixed `logs/` subdirectory for per-protocol credential files, plus a session log one level up:

```
<output-dir>/
├── CredentialDump-Session.log       # every match, EVERY time, always appended
│                                      (not gated by -v, not deduplicated)
└── logs/
    ├── NTLMv1.txt                    # hashcat -m 5500
    ├── NTLMv2.txt                    # hashcat -m 5600
    ├── MSKerb.txt                    # hashcat -m 7500
    ├── HTTP-Basic.txt
    ├── HTTP-PasswordFields.txt
    ├── FTP-Plaintext.txt
    ├── IRC-Plaintext.txt
    ├── SMTP-Plaintext.txt
    ├── LDAP-Simple.txt
    ├── MSSQL-Plaintext.txt
    ├── SNMPv1.txt                    # community strings, SNMPv1
    └── SNMPv2c.txt                   # community strings, SNMPv2c
```

Two facts worth building triage logic on:

- **The set of filenames present directly enumerates which protocols yielded a hit** during that run, without opening any of them — the same file-listing-as-triage-shortcut pattern used in `Responder/03 - Source Evidence.md`.
- **`logs/*.txt` files are always deduplicated** on a `(filename, credential)` key, regardless of `-v` — `-v` only affects console repetition. **`CredentialDump-Session.log` is never deduplicated** — it's written via a Python `logging.FileHandler` on every single match, verbose or not — meaning the session log is the more complete record of *how many times* a given credential was observed, while the `.txt` files answer only *whether* it was observed at all. This is the inverse of what a reader might assume from the README's blanket "same credentials only logged once (unless `-v`)" claim, which is imprecise about which output it applies to.
- A **disabled protocol (`--disable`) produces literally nothing in either location** — the extractor function returns before any write call, so absence of a file (or absence of session-log lines for that credential type) is ambiguous between "protocol wasn't present in the traffic" and "protocol was deliberately disabled." Cross-reference the invocation itself (shell history, below) to resolve that ambiguity.

## In-Memory State — What Does NOT Persist

Unlike `Responder/`, which persists every capture to a queryable `Responder.db` SQLite database, **Pcredz has no equivalent structured/persistent store at all**. The NTLM-challenge cache, the FTP/IRC/SMTP username-correlation cache, and the credential dedup set are all plain in-memory Python dictionaries/sets, and — critically — they're explicitly reset (`.clear()`) at the start of **every** file processed in `-d` mode, and lost entirely on process exit or interruption in `-i` mode. Practical consequence for an analyst: if a live Pcredz process is killed before a clean exit, **only what was already flushed to `logs/*.txt` or the session log survives** — anything held only in the in-memory challenge/correlation cache (e.g. an NTLM Type 2 challenge seen but never matched to its Type 3 response before the kill) is gone. This makes a live memory capture of a still-running Pcredz process (see [Memory Forensics](#memory-forensics)) disproportionately valuable compared to the flat-file output alone.

## Live Process, Promiscuous-Mode, and Socket State

```bash
# Process check
ps aux | grep -i pcredz

# Promiscuous-mode flag on the capture NIC — the single most distinctive
# live-mode artifact, since legitimate traffic on that host rarely needs it
ip link show eth0 | grep -i promisc

# Alternative / older systems
ifconfig eth0 | grep -i promisc
```

`pcapy.open_live()` is called with promiscuous mode explicitly enabled (`True`) — there is no flag to run Pcredz in non-promiscuous mode. On a host that has no other legitimate reason to be sniffing (i.e., not a dedicated network-monitoring appliance), a NIC sitting in promiscuous mode is a strong, easily-checked indicator that **something** is capturing broadly on that interface — it doesn't by itself prove Pcredz specifically, but combined with the process check above it's close to conclusive. No listening sockets are opened at all in live mode (Pcredz reads raw frames via `libpcap`, it doesn't bind a port) — this is a meaningful contrast with `Responder/`'s live footprint, which binds a dozen-plus privileged ports simultaneously and is trivially visible via `ss -lunp`.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | The invocation line reveals input mode (`-f`/`-d`/`-i`), any `--disable`/`--exclude-host` scoping (which resolves the "empty output" ambiguity noted above), and the `-o` output path if a non-default location was used |
| zsh | `~/.zsh_history` | Same content, timestamped by default under `EXTENDED_HISTORY` |

Unlike a credentialed lateral-movement tool, the invocation line itself never contains a target credential — Pcredz takes no auth arguments of its own, only capture-scoping ones.

## Installation Artifacts and Version Dating

| Artifact | Command | Notes |
|---|---|---|
| Git checkout and version | `find / -iname "Pcredz" -type f 2>/dev/null`, then `git -C <path> log -1` and `git -C <path> describe --tags` | Pins the exact commit/tag in use — directly relevant given how much changed at the v2.1.0 rewrite (see `01 - Overview.md`'s History) |
| Installed pcap library — **version-dating signal** | `pip3 show pcapy-ng` vs. `pip3 show python-libpcap` (or `pip3 list \| grep -i pcap`) | **`pcapy-ng` present → v2.1.0 or later** (post-2025-12-30) — current NTLM/HTTP/FTP/IRC/LDAP/SMTP/Kerberos/SNMP/MSSQL protocol set only, no IMAP/POP3/Citrix-ICA, vestigial `-c` flag, IPv4-only. **`python-libpcap`/`pylibpcap` present → v2.0.x or earlier** — has working credit-card Luhn-check extraction and IMAP/POP3/Citrix-ICA parsing the current version lacks. This single library-presence check is the fastest way to date which feature set/output-file set an operator's install actually has, without needing the git history at all |
| Docker image (if used) | `docker images \| grep -i pcredz` and `docker inspect <image>` | The official `Dockerfile` pins `python:3.11-slim-bookworm` and installs `pcapy-ng` fresh at build time — a locally-built Pcredz image is inherently current-version unless the operator explicitly checked out an older tag before building |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing (uncommon by default, more likely on hardened/monitored red-team infrastructure):

```bash
ausearch -x Pcredz 2>/dev/null
ausearch -x python3 -k pcap_capability 2>/dev/null   # if a rule keys on CAP_NET_RAW usage
```

As with any interpreted-language tool, `execve`-level audit records survive a shell-history wipe (`history -c`) in a way bash/zsh history does not — worth checking even when the shell history shows nothing.

## Memory Forensics

For the **live capture mode specifically**, a memory capture of a still-running Pcredz process is high-value for the reason described above under [In-Memory State](#in-memory-state--what-does-not-persist): the NTLM challenge cache and username-correlation cache exist **only** in process memory, meaning a still-running instance can contain in-progress capture state (a challenge seen but not yet matched, an SMTP AUTH LOGIN username awaiting its paired password line) that will never appear in any log file if the process is killed uncleanly rather than allowed to exit normally. For offline `-f`/`-d` mode, memory forensics value is much lower — the process is short-lived and its state is fully flushed to disk before it exits under normal operation.

## Timeline Correlation Value

Because Pcredz produces no target-side network signature of its own (see `04 - Target Evidence.md`'s reframe), the source-side session log's timestamps are frequently the **only** first-party timing evidence available for when a given credential was actually observed — this is a sharper dependency on source-side evidence than most tools in this repo, where target-side event logs are usually the stronger anchor. Where Pcredz was run **alongside** `Responder/` (see `02 - Hands-On Use Cases.md`'s chained scenario), correlate Pcredz's `CredentialDump-Session.log` timestamps against Responder's own `Poisoners-Session.log`/`Responder.db` timestamps for the same victim IP — a near-simultaneous entry in both is strong corroboration that the same capture session produced both, useful when only one of the two tools' output survived intact.
