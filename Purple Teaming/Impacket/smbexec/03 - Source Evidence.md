# Impacket — smbexec.py — Source Evidence

Evidence left on the **attacking/operator** host — the Linux (occasionally Windows) box `smbexec.py` was launched *from*. Like its siblings, `smbexec.py` writes **no persistent session log of its own** — there is no "smbexec history file." What's specific to this tool (vs. `psexec.py`/`wmiexec.py`) is a **simpler, single-connection network fingerprint** for `-mode SHARE`, a **locally-bound listening-socket footprint unique to `-mode SERVER`**, and the fact that — because every typed command is re-sent as a literal `echo`-wrapped string — the operator's **entire command history for the session** passes through this process's memory, not just the initial credentials.

## Contents
- [Shell History](#shell-history)
- [Live Process State](#live-process-state)
- [SERVER-Mode-Specific Artifacts](#server-mode-specific-artifacts)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line **including credentials in cleartext** if typed inline (`user:password@target`). Unlike `wmiexec.py`, `smbexec.py` has **no `-A` authentication-file flag** — there is no built-in way to keep a plaintext password off the shell command line short of sourcing it from an environment variable or letting the tool prompt via `getpass()` |
| zsh | `~/.zsh_history` | Same content, plus a timestamp prefix by default if `EXTENDED_HISTORY` is enabled |
| fish | `~/.local/share/fish/fish_history` | YAML-structured, includes a `when:` Unix timestamp per command natively |

Because `smbexec.py` always drops into its own interactive shell rather than accepting a one-shot `command` argument, an operator scripting non-interactive use has to **pipe** a command in (`echo "whoami" | smbexec.py ...` — see `02 - Hands-On Use Cases.md`) — that piped string is itself typically visible in shell history or in a wrapping script's own source on disk, an artifact class `psexec.py`/`wmiexec.py`'s CLI-argument model doesn't generate in quite the same way.

## Live Process State

```bash
ps aux | grep -i smbexec
```
While running, the full invocation — including any inline credentials — is visible in `/proc/<pid>/cmdline` to **any other local user or process** on the box, identical to the exposure risk documented for `psexec.py`/`wmiexec.py`.

## SERVER-Mode-Specific Artifacts

`-mode SERVER` requires root/administrator privileges on the operator's own machine to bind TCP 445 — this generates artifact classes the default `SHARE` mode never touches:

| Artifact | Command | Notes |
|---|---|---|
| Elevation to bind port 445 | `grep -i smbexec /var/log/auth.log` or `journalctl _COMM=sudo \| grep -i smbexec` | A `sudo smbexec.py -mode SERVER ...` invocation logs a privilege-escalation event on the operator box itself — a source-side tell that's specific to this one mode |
| Ad hoc SMB server temp directory | `find / -maxdepth 3 -iname "*smbserver*" -o -iname "*.tmp" -newer /etc/hostname 2>/dev/null` | Impacket's bundled `SMBServer` creates a temporary directory to back its dummy `TMP` share (`SMBSERVER_DIR`) — worth locating during a live-response pass on a still-running operator box |
| Live listening socket | `ss -tlnp \| grep :445` | Confirms an active SMB listener bound locally — combined with root/sudo context, a strong indicator `-mode SERVER` is in active use |

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Confirms version — the batch/echo command template has been stable across recent releases, but version still matters for exact string matching |
| Script location | `find / -iname "smbexec.py" 2>/dev/null` | Locates a source checkout, a pip-installed console script, or a `pipx` isolated environment |
| Git checkout evidence | `.git/logs/HEAD`, `git log` inside a cloned `impacket/` directory | Shows exactly which revision was in use if the operator cloned from source rather than `pip install`-ing |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path | `.pyc` mtimes can survive a `history -c` shell-history wipe and coarsely bound when the tool was first imported/run on this box |

## Network Evidence

`smbexec.py`'s **default (`SHARE`) mode network fingerprint is the simplest of the three Impacket lateral-movement tools in this folder** — one SMB session on a fixed port for the entire session, no dynamic RPC port ever negotiated (SVCCTL rides the SMB named pipe transport, not DCOM):

| Artifact | Command | Notes |
|---|---|---|
| Live socket state | `ss -tnp \| grep -E ':445\|:139'` | The one persistent TCP connection carrying both the SVCCTL execution channel and the output-relay share access — present for the entire session |
| Connection tracking | `conntrack -L \| grep -E ':445\|:139'` (if `conntrack` is present) | Survives slightly past process exit compared to `ss` |
| `-mode SERVER` additional socket | `ss -tlnp \| grep :445` | The **locally bound listening** socket — see [SERVER-Mode-Specific Artifacts](#server-mode-specific-artifacts) above. Also expect an **inbound** connection from the target IP once it pushes output back via its `copy` clause |
| DNS cache / resolver logs | `systemd-resolved` journal, or `/etc/hosts` edits | If the operator added a manual hosts-file entry to satisfy Kerberos SPN resolution |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing enabled:

```bash
ausearch -x smbexec.py 2>/dev/null
# or, broader:
ausearch -k exec_python 2>/dev/null   # if a custom audit rule tags Python execve calls
```
This is the **only** artifact class here that reliably survives a `history -c` / shell-history deletion, since it's generated at the kernel level (`execve` syscall) independent of the shell.

## Memory Forensics

If the operator box itself is seized/imaged as part of an insider-threat or compromised-infrastructure investigation:
- Process memory of a still-running `smbexec.py` invocation can contain the plaintext password, NT hash, or AES key even when the *displayed* `ps`/`cmdline` output was suppressed (e.g. credentials sourced from an environment variable or the interactive password prompt rather than the command line).
- **Every command typed into the semi-interactive shell gets built into a full `echo`/redirect/batch-file string inside this process before it's ever sent to the target** — meaning a memory capture mid-session can recover not just the initial authentication material, but the **entire command history of the engagement up to that point**, since Python's reference-counted string objects for those constructed command strings tend to persist in the interpreter's heap well past their last use.
- If `-shell-type powershell` was used, the **plaintext** command text is present in memory before it gets base64-encoded — recovering it doesn't require decoding the base64 blob that ends up in the target's process list/logs.

## Timeline Correlation Value

None of the artifacts above are useful in isolation the way the target-side burst of System 7045 events is (see `04 - Target Evidence.md`) — their real value is **timeline correlation**: matching an operator-side shell-history/`auditd` timestamp, or the single persistent SMB socket's connection-establishment time, against the target-side Security 4624 (Type 3 logon — expect just **one** for the whole session, a useful contrast against the *many* 7045 events that follow it) is what turns "a smbexec.py invocation happened somewhere" and "a burst of same-named service installs happened somewhere" into a single, provable causal chain tying a specific operator, a specific box, and a specific victim host together.
