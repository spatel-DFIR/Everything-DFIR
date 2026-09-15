# Impacket — psexec.py — Source Evidence

Evidence left on the **attacking/operator** host — the Linux (occasionally Windows) box `psexec.py` was launched *from*. `psexec.py` itself writes **no persistent session log of its own** — there is no "psexec history file" to find. Everything recoverable here is either generic shell/process/OS-audit trail, or artifacts of the Python/Impacket installation itself. Treat this section as "what does a generic Linux operator-box investigation turn up," not "what does this specific tool log."

## Contents
- [Shell History](#shell-history)
- [Live Process State](#live-process-state)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line **including credentials in cleartext** if typed inline (`user:password@target`) rather than sourced from a variable/file. `HISTCONTROL=ignorespace` (a leading space before the command) is a common operator habit to suppress this — its *absence* in a history file with an otherwise-consistent operational tempo is itself worth noting |
| zsh | `~/.zsh_history` | Same content, plus a timestamp prefix by default (`EXTENDED_HISTORY`) if the operator's `.zshrc` enables it — directly useful for timeline building without needing `HISTTIMEFORMAT` tricks |
| fish | `~/.local/share/fish/fish_history` | YAML-structured, includes a `when:` Unix timestamp per command natively — the easiest shell history to timeline-correlate if the operator used fish |

`HISTTIMEFORMAT` (bash) must be set **before** the session for `history` to show timestamps retroactively read from `.bash_history` — if unset, `.bash_history` on disk has no per-line timestamp at all and only ordering (not exact time) is recoverable unless correlated against another artifact (auth logs, `stat` mtime of the history file itself as an upper bound).

## Live Process State

```bash
ps aux | grep -i psexec
```
While `psexec.py` is running, the full invocation — including any inline credentials — is visible in `/proc/<pid>/cmdline` to **any other local user or process** on the box, not just root. On a shared operator VM or a compromised operator workstation, this is a realistic secondary credential-exposure vector distinct from the shell-history risk above.

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Confirms version — matters because the embedded RemCom binary's exact bytes (and therefore its hash) have changed across a small number of Impacket releases; a hash IOC list needs to be version-aware |
| Script location | `find / -iname "psexec.py" 2>/dev/null` | Locates a source checkout, a pip-installed copy under a venv (`.../site-packages/impacket/examples/`... actually installed as a console script `psexec.py` on `PATH`), or a `pipx` isolated environment |
| Git checkout evidence | `.git/logs/HEAD`, `git log` inside a cloned `impacket/` directory | If the operator cloned from source rather than `pip install`-ing, commit history/dates show exactly which revision (and therefore which RemCom binary variant) was in use |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path | `.pyc` file mtimes can survive a `history -c` shell-history wipe and coarsely bound when the tool was first imported/run on this box |

## Network Evidence

| Artifact | Command | Notes |
|---|---|---|
| Live socket state | `ss -tnp \| grep :445` | Shows the established TCP 445 connection to the target while `psexec.py` is actively running |
| Connection tracking | `conntrack -L \| grep :445` (if `conntrack` tooling is present) | Survives slightly past process exit compared to `ss`, useful if you catch the box moments after the operator disconnects |
| DNS cache / resolver logs | `systemd-resolved` journal, or `/etc/hosts` edits | If the operator added a manual hosts-file entry to satisfy Kerberos SPN resolution (see `01 - Overview.md`'s `-target-ip` prerequisite note), that edit itself is an artifact with its own mtime |

## OS-Level Audit Trail

If `auditd` is running with syscall auditing enabled (not default on most distros, but common on hardened operator boxes or in monitored red-team infrastructure):

```bash
ausearch -x psexec.py 2>/dev/null
# or, broader:
ausearch -k exec_python 2>/dev/null   # if a custom audit rule tags Python execve calls
```
This is the **only** artifact class here that reliably survives a `history -c` / shell-history deletion, since it's generated at the kernel level (`execve` syscall) independent of the shell.

## Memory Forensics

If the operator box itself is seized/imaged as part of an insider-threat or compromised-infrastructure investigation:
- Process memory of a still-running `psexec.py` invocation can contain the plaintext password or NT hash even when the *displayed* `ps`/`cmdline` output was suppressed (e.g. credentials sourced from an environment variable rather than the command line) — a full memory capture (`gcore`, or a VM snapshot) followed by string/YARA search against the target IP and known credential patterns is a viable recovery path this section's other artifacts don't cover.
- Python's own process memory retains recently-used string objects (including credential strings passed into Impacket's SMB session-setup calls) well past their last use in code, due to reference counting/garbage-collection timing — don't assume memory evidence is limited to what's on the current call stack.

## Timeline Correlation Value

None of the artifacts above are useful in isolation the way the target-side Event ID 7045 is (see `04 - Target Evidence.md`) — their real value is **timeline correlation**: matching an operator-side shell-history or `auditd` timestamp against a target-side Security 4624 (Type 3 logon) or System 7045 (service install) timestamp is what turns "a psexec.py invocation happened somewhere" and "a suspicious service was installed somewhere" into a single, provable causal chain tying a specific operator, a specific box, and a specific victim host together.
