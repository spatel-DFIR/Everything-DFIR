# Certipy — Source Evidence

What the **host running Certipy** leaves behind. Certipy is normally run from a Linux (or macOS/Windows) operator box with no code execution on any domain-joined host required for its LDAP/RPC/Kerberos commands — so unlike a tool that drops a service or DLL on a target, almost everything distinctive about a Certipy operation lives here, on the attacking side: its very specific and predictable output-file naming (see `01`), Python package/install artifacts, `KRB5CCNAME` environment state, and — for the one command that does touch a remote host's filesystem (`ca -backup`) — the local copies of what it steals. Cross-link `Linux/04 - Shells and Command History.md`, `Linux/10c - Network and PCAP Forensics.md`, and `Linux/11 - Memory Forensics.md` for the generic Linux-host mechanics assumed throughout rather than re-derived here; `GhostPack/Certify/01 - Overview.md`'s Prerequisites table documents the mirror-image Windows-operator case if Certipy is instead run from a compiled `Certipy.exe` (see `01`'s History section for why that binary exists at all).

## Contents
- [Shell / Command History](#shell--command-history)
- [Python Package and Install Artifacts](#python-package-and-install-artifacts)
- [Output Files — Certipy's Own Predictable Naming](#output-files--certipys-own-predictable-naming)
- [Kerberos Credential-Cache Environment State](#kerberos-credential-cache-environment-state)
- [Process Artifacts](#process-artifacts)
- [Local Network-Connection State](#local-network-connection-state)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell / Command History

Certipy is a CLI-only tool with no GUI mode — every invocation appears in shell history in full:

- **`.bash_history`/`.zsh_history`** on the operator's own box (or, more often in practice, a shared attacking VM/jump host) captures every `certipy` invocation verbatim, including `-u`/`-p` credentials in cleartext on the command line unless `-hashes`/`-k` (ccache) was used instead — the single richest source-side artifact for reconstructing exactly which templates, CAs, and target identities (`-upn`/`-sid`/`-dns`) were probed or exploited, in order.
- **Command-line credential exposure is a real, structural weakness of Certipy's own design**: `-p 'Passw0rd!'` on the command line is visible not just in shell history but in `/proc/<pid>/cmdline` for the process's entire lifetime (see Process Artifacts below) — an operator who wants to avoid this needs to use `-hashes`/`-k`/an interactive password prompt (Certipy prompts if `-p` is omitted with `-u` given), none of which is the default.
- **Redirected relay-listener output**, if the operator backgrounded `certipy relay` with `nohup`/`screen`/`tmux` and redirected stdout to a file, persists the full relay session log (every coerced authentication captured, every template requested) independent of shell history — a `.log`/`.out` file with Certipy's own `[*]`-prefixed log lines is a durable, easily-overlooked artifact on a compromised relay host.

## Python Package and Install Artifacts

Certipy's install footprint is straightforward Python package evidence, distinct from a compiled-binary tool:

- **`pip`/`pipx` metadata** — `pip show certipy-ad` (note the package name mismatch from the `certipy` command itself, see `01`) or, for a `pipx`-managed install, `~/.local/pipx/venvs/certipy-ad/` containing the isolated virtualenv, its `pip freeze`-recoverable dependency list (`impacket~=0.13.0`, `ldap3`, `cryptography`, etc.), and install timestamps in the venv directory's own metadata.
- **`pip`'s own install/download cache** (`~/.cache/pip/`) may retain the downloaded wheel for `certipy-ad` and its dependencies, with modification timestamps bounding when the tool was first installed on this host — useful for distinguishing "operator brought this tool with them" from "operator installed it fresh on a newly compromised pivot host."
- **The `bloodhound` optional extra** (`pip install certipy-ad[bloodhound]`, pulling in `neo4j~=5.28.1`) is itself a signal if present but the base `certipy-ad` package is not paired with any other BloodHound-collection tooling on the same host — it specifically indicates the operator intended to use `parse -use-owned-sids` against a Neo4j instance, not just run `find`/`req` standalone.
- **A locally cloned/built copy of the GitHub repo** (rather than a `pip`-installed package) leaves the full `.git/` history, `pyproject.toml`, and source tree on disk — recoverable commit hashes can pin the exact version/feature-set the operator was running, which matters given the real command-surface differences across Certipy's `2.x`/`4.x`/`5.x` lines (see `01`'s History section).
- **The official pre-compiled `Certipy.exe`** (see `01` — the CI-built Windows release asset), if this is the artifact recovered instead of a Python install, carries standard PE metadata (`OriginalFileName`, version info, and a publicly documented SHA-256 per GitHub release) that a pip-installed `certipy` command never will — see `05` for why this makes hash/PE matching a real (if narrow) signal specifically for the compiled-binary case.

## Output Files — Certipy's Own Predictable Naming

Every Certipy command that produces material writes it to disk under a naming convention fixed in source (verified in `01` against `certipy/lib/req.py`, `certipy/commands/find.py`, `certipy/commands/auth.py`, `certipy/commands/ca.py`) — recovering these files on a seized attacking host (or a compromised relay/pivot box) directly reconstructs what was done, often without needing shell history at all:

| File pattern | Produced by | What it reveals |
|---|---|---|
| `<timestamp>_Certipy.txt` + `<timestamp>_Certipy.json` | `find` (default, no output flag given) | Full enumeration results — every template/CA seen and every ESC flag raised, with the 14-digit timestamp bounding exactly when recon ran |
| `<prefix>_Templates_Certipy.csv`, `<prefix>_CAs_Certipy.csv` | `find -csv` | Same data, spreadsheet-friendly — two files always produced together |
| `<identity>.pfx` (identity-derived, lowercased, trailing `$` stripped) | `req`, successful | The requested/stolen certificate and private key — `<identity>` names exactly who was impersonated, independent of which account actually made the request |
| `<request-id>.key` | `req` against a manager-approval-pending template | An **unencrypted PEM private key**, written to disk before any matching certificate exists — a distinctive, easily searched (`find . -name "*.key" -newer ...`) pending-request artifact |
| `<identity>.ccache` / `<identity>.kirbi` | `auth` (default) / `auth -kirbi` | A redeemed Kerberos credential — presence alone confirms the operator successfully authenticated as `<identity>`, not just requested a cert |
| `pfx.p12` then `<CA-Common-Name>.pfx` | `ca -backup` | The raw, still-`certipy`-password-protected CA key backup, then the re-packaged unprotected version — see `01`'s Red Flag callout and `04` for the remote-side half of this artifact |
| `<subject>_forged.pfx` (or `-out`-specified name) | `forge` | An offline-minted certificate — its mere existence, with no matching `req`/`relay` invocation in history, indicates the operator already possessed a CA private key |

## Kerberos Credential-Cache Environment State

- **`KRB5CCNAME`**, when exported to point at a `.ccache` file obtained via `certipy auth` (or `shadow ... auto`), persists in the operator's shell session environment and — critically — in `/proc/<pid>/environ` for any subsequent process launched from that shell (Certipy itself, or a chained Impacket tool like `secretsdump.py -k`). A live-response capture of `/proc/<pid>/environ` on a still-running attacking process is one of the few ways to recover the **exact ccache path** an operator used without needing the file to still be on disk.
- **`.bashrc`/`.zshrc`/wrapper scripts** that persistently `export KRB5CCNAME=...` (rather than a one-off shell command) indicate the operator built a repeatable operational setup on this host rather than a single ad hoc session — worth flagging as evidence of a staged/prepared attacking environment, not opportunistic use.
- **Standard Kerberos ccache file structure** applies once a `.ccache`/`.kirbi` is recovered — see `Windows/` and `Mimikatz/kerberos (Golden-Silver Ticket)/`'s existing ticket-structure documentation for what's parseable out of the file itself (principal name, realm, validity window); not re-derived here since the ccache format itself is identical regardless of which tool produced it.

## Process Artifacts

- **Process list / `ps`/`/proc/<pid>/cmdline`** during a live run shows a `python3`/`certipy` (or `Certipy.exe`) process with the **full command line visible**, including any cleartext `-p`/`-hashes`/`-pfx-password` argument — the direct target for `auditd`'s `execve` logging on Linux or Sysmon Event ID 1 on Windows (cross-link `Linux/10b - Process Trees and Execution Lineage.md` for the auditd-side mechanics, not re-derived here).
- **Child processes: none under normal operation.** Certipy's LDAP/RPC/Kerberos/HTTP work happens entirely in-process via Impacket and `cryptography`-library calls — there is no distinctive child-process tree to hunt on the attacking host itself, in contrast to a target-side artifact like `ca -backup`'s remote `certutil.exe` spawn (see `04`).
- **File descriptor count** during `relay` (a listening SMB server) or a long `find` enumeration against a large forest is modestly elevated but not distinctive on its own — `lsof -p <pid>` shows the listening socket(s) and active LDAP/RPC connections, useful mainly for confirming a `relay` process is actively listening vs. already exited.

## Local Network-Connection State

- **`find`/`req`/`account`/`shadow`/`ca` (client operations)** produce ordinary outbound LDAP (389/636), RPC (dynamic port or `\pipe\cert`/`\pipe\winreg` over 445), and occasionally HTTP(S) (80/443) connections from the Certipy process to the DC/CA — visible via `netstat`/`ss` on the attacking host, correlatable one-to-one against the target-side connection log (`04`).
- **`relay` is the one command that listens rather than connects** — `netstat -ltnp`/`ss -ltnp` on the attacking host will show a process bound to `0.0.0.0:445` (or the `-interface`/`-port` override) in `LISTEN` state for the duration of the operation, a distinctive local signature independent of whether a victim has authenticated to it yet.
- **`-forever`** on `relay` means this listening state persists indefinitely rather than exiting after one successful relay — a long-lived `LISTEN` socket on 445 from a non-Samba/non-Windows process is itself worth flagging on a Linux attacking host under any host-level monitoring.

## Memory Forensics

Certipy holds the requested/stolen private key material — and, transiently, the U2U-recovered NT hash during `auth` — in Python process memory for the process's lifetime. A live memory capture of a still-running Certipy process can recover this material even if the operator used `-no-save`/`-no-hash` to suppress the corresponding disk write, or before a `.pfx`/`.ccache` file is flushed to disk. Because Certipy is pure Python (no native LSASS-style memory protections apply), a straightforward process-memory dump (`gcore`, `/proc/<pid>/mem` read) on Linux is sufficient — there is no equivalent of the Windows LSASS-protection/PPL barrier that other tools in this repo (`Mimikatz/`, `ProcDump/`) have to work around.

## Timeline Correlation Value

The output-file naming table above gives an unusually precise, tool-native timeline for free: `find`'s own 14-digit timestamp prefix, a `.pfx`'s file-creation time (the moment a cert was issued/stolen), and a `.ccache`'s creation time (the moment it was redeemed) can be laid out in strict chronological order **without needing shell history at all**, since Certipy's own default filenames embed or closely track each step's own timing. That source-side sequence is the anchor for correlating against `04 - Target Evidence.md`'s CA-side request-ID/event-log timeline — a `req` invocation's local timestamp should fall within seconds of the CA's own logged request (where auditing is enabled at all, see `04`), and a `ca -backup`'s local `pfx.p12` creation time should align tightly with the ephemeral `Certipy`-named SVCCTL service's brief lifetime on the CA server.
