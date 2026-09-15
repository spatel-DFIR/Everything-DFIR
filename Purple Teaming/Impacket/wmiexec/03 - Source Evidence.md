# Impacket — wmiexec.py — Source Evidence

Evidence left on the **attacking/operator** host — the Linux (occasionally Windows) box `wmiexec.py` was launched *from*. Like `psexec.py`, `wmiexec.py` writes **no persistent session log of its own** — there is no "wmiexec history file" to find. What's specific to this tool (vs. psexec) is the **dual-connection network fingerprint** it leaves while running, and the local file evidence from `lput`/`lget` if the operator used the interactive shell's file-transfer commands.

## Contents
- [Shell History](#shell-history)
- [Live Process State](#live-process-state)
- [Local File Artifacts from lput/lget](#local-file-artifacts-from-lputlget)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line **including credentials in cleartext** if typed inline (`user:password@target`) rather than via `-A authfile`. `HISTCONTROL=ignorespace` (leading space) is a common operator habit to suppress this |
| zsh | `~/.zsh_history` | Same content, plus a timestamp prefix by default if `EXTENDED_HISTORY` is enabled — directly useful for timeline building |
| fish | `~/.local/share/fish/fish_history` | YAML-structured, includes a `when:` Unix timestamp per command natively |

An operator using `-A wmiexec.auth` (see `02 - Hands-On Use Cases.md`) removes the credential from the command line entirely — the shell history then only shows the auth-file path and target, not the secret itself. The auth file's own path and mtime become the more interesting artifact in that case (see [Impacket Installation Artifacts](#impacket-installation-artifacts)).

## Live Process State

```bash
ps aux | grep -i wmiexec
```
While running, the full invocation — including any inline credentials — is visible in `/proc/<pid>/cmdline` to **any other local user or process** on the box, identical to psexec's exposure risk.

## Local File Artifacts from lput/lget

If the operator used the interactive shell's `lput`/`lget` commands (see `02 - Hands-On Use Cases.md`):

| Artifact | Notes |
|---|---|
| `lput` source file | The **local** file uploaded to the target still exists on the operator box at whatever path was given — its presence, mtime, and hash tie the operator's toolkit directly to whatever landed on the target |
| `lget` destination file | Files pulled *from* the target land in the operator's **current local working directory** (`os.getcwd()` at the time, adjustable with `lcd`) — a direct copy of exfiltrated target-host data sitting on the operator box, often the highest-value single artifact recoverable from a seized attacker workstation |

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Confirms version — the `-shell-type powershell` encoding wrapper and argument set have been stable across recent releases, but confirming version still matters for exact behavior matching |
| Script location | `find / -iname "wmiexec.py" 2>/dev/null` | Locates a source checkout, a pip-installed console script, or a `pipx` isolated environment |
| Auth-file remnant | `find / -iname "*.auth" -newer /etc/hostname 2>/dev/null` | If `-A` was used, the auth file itself (plaintext credentials in `smbclient`-style format) may still be sitting on disk |
| Git checkout evidence | `.git/logs/HEAD`, `git log` inside a cloned `impacket/` directory | Shows exactly which revision was in use if the operator cloned from source rather than `pip install`-ing |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path | `.pyc` mtimes can survive a `history -c` shell-history wipe and coarsely bound when the tool was first imported/run on this box |

## Network Evidence

`wmiexec.py`'s network fingerprint is **structurally different from psexec.py's** — it opens up to two independent connections instead of one:

| Artifact | Command | Notes |
|---|---|---|
| Live socket state — DCOM/RPC | `ss -tnp \| grep -E ':135\|:49[0-9]{3}\|:5[0-9]{4}\|:6[0-4][0-9]{3}\|:65[0-5][0-9]{2}'` | The RPC endpoint-mapper bind (135) followed by a connection to a dynamically negotiated high port — **always present**, since this is the execution channel and is never skipped by any flag |
| Live socket state — SMB | `ss -tnp \| grep :445` | **Only present** if output capture is enabled (default) — absent entirely if `-nooutput` or `-silentcommand` was used. Its *absence* alongside an active DCOM connection is itself informative: it narrows the session to one of those two flags |
| Connection tracking | `conntrack -L \| grep -E ':135\|:445'` (if `conntrack` tooling is present) | Survives slightly past process exit compared to `ss` |
| DNS cache / resolver logs | `systemd-resolved` journal, or `/etc/hosts` edits | If the operator added a manual hosts-file entry to satisfy Kerberos SPN resolution (see `01 - Overview.md`'s `-target-ip` prerequisite note) |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing enabled:

```bash
ausearch -x wmiexec.py 2>/dev/null
# or, broader:
ausearch -k exec_python 2>/dev/null   # if a custom audit rule tags Python execve calls
```
This is the **only** artifact class here that reliably survives a `history -c` / shell-history deletion, since it's generated at the kernel level (`execve` syscall) independent of the shell.

## Memory Forensics

If the operator box itself is seized/imaged:
- Process memory of a still-running `wmiexec.py` invocation can contain the plaintext password, NT hash, or AES key even when the *displayed* `ps`/`cmdline` output was suppressed (e.g. credentials sourced from an environment variable or an `-A` auth file rather than the command line).
- Because `wmiexec.py` maintains two live protocol connections (SMB and DCOM) simultaneously for the life of a session, memory captured mid-session is more likely to contain **both** authentication contexts resident at once than a psexec.py capture would — Python's reference-counted string objects for both connections' credential material tend to persist together in the same heap region.
- If the operator used `-shell-type powershell`, the **plaintext** command text is present in memory before it gets base64-encoded — recovering it doesn't require decoding the base64 blob that ends up in the target's process list/logs.

## Timeline Correlation Value

None of the artifacts above are useful in isolation the way the target-side `WmiPrvSE.exe` process-creation event is (see `04 - Target Evidence.md`) — their real value is **timeline correlation**: matching an operator-side shell-history or `auditd` timestamp, or the DCOM/RPC-plus-optional-SMB socket state above, against a target-side Security 4624 (two, potentially — one per connection) and a Sysmon Event 1 for `WmiPrvSE.exe`'s child process, is what turns "a wmiexec.py invocation happened somewhere" and "WmiPrvSE.exe spawned something unusual somewhere" into a single, provable causal chain tying a specific operator, a specific box, and a specific victim host together.
