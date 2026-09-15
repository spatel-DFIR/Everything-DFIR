# Impacket — GetUserSPNs.py (Kerberoasting) — Source Evidence

Evidence left on the **attacking/operator** host. Like the rest of the Impacket `examples/` family, `GetUserSPNs.py` writes no persistent session log of its own — what it *does* leave behind is largely determined by which output flags the operator chose (`-outputfile`, `-save`, or neither), plus the same general-purpose artifact classes every Impacket tool in this repo leaves.

## Contents
- [Shell History](#shell-history)
- [Live Process State](#live-process-state)
- [Output Artifacts — Hash Files and Saved Tickets](#output-artifacts--hash-files-and-saved-tickets)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)
- [Handoff Into Hashcat](#handoff-into-hashcat)

---

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line, including any inline `domain/user:password` credential and, critically, the flag set used — `-stealth`, `-machine-only`, `-request-user`, `-no-preauth` each signal a distinctly different operational intent, so the flag combination itself is evidentiary, not just the fact that `GetUserSPNs.py` ran |
| zsh | `~/.zsh_history` | Same content; timestamped if `EXTENDED_HISTORY` is set |
| fish | `~/.local/share/fish/fish_history` | YAML-structured, native per-command timestamp |

```bash
grep -iE "GetUserSPNs|kerberoast|request-user|request-machine|no-preauth|stealth" ~/.bash_history ~/.zsh_history 2>/dev/null
```

## Live Process State

```bash
ps aux | grep -i GetUserSPNs
```
While running, the full invocation — including any inline credential — is visible in `/proc/<pid>/cmdline` to any other local user or process on the box, the same exposure every other Impacket example script in this repo carries.

## Output Artifacts — Hash Files and Saved Tickets

The single most direct evidence of what this tool actually recovered:

| Flag used | Artifact | Notes |
|---|---|---|
| `-outputfile <name>` | `<name>` — plaintext file, one `$krb5tgs$<etype>$...` line per requested account | The **highest-value artifact on the operator host**: it directly names every target account and the crackable material for each. mtime brackets the run's completion |
| `-save` | `<username>.ccache` — one file per requested account, full ticket (not just the crackable hash) | A live, reusable Kerberos ticket, not just cracking material — presence of `.ccache` files (rather than/alongside a hash file) signals pass-the-ticket intent, not offline cracking intent |
| Neither flag, with `-request` | Nothing written to disk — hash lines print to **stdout only** | If the operator redirected stdout to a file manually (`> loot.txt`) or piped into another tool, that redirection target is functionally the same artifact as `-outputfile`'s, just under whatever name the operator chose rather than the tool's own naming |
| No `-request`/`-request-user`/`-request-machine` at all | Only the console enumeration table (SPN/Name/MemberOf/PasswordLastSet/LastLogon/Delegation), never written to disk unless redirected | Confirms an enumeration-only pass — no TGS-REQ occurred, so there's nothing to find target-side either (see `04 - Target Evidence.md`) |

```bash
find / -iname "*.ccache" -newer /etc/hostname 2>/dev/null
find / -iname "kerberoast*" -o -iname "*.hash" -o -iname "*.txt" -newer /etc/hostname 2>/dev/null | \
  xargs grep -l '\$krb5tgs\$' 2>/dev/null
```
The second command is the more reliable one — it doesn't depend on the operator having used an obviously-named output file; it greps file *content* for the `$krb5tgs$` signature regardless of filename.

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Confirms version — flag surface (`-stealth`, `-machine-only`, `-no-preauth`) is a relatively recent addition to this script; an older installed version may lack one or more of these flags entirely |
| Script location | `find / -iname "GetUserSPNs.py" 2>/dev/null` | Locates a source checkout, pip-installed console script, or pipx-isolated environment |
| Git checkout evidence | `.git/logs/HEAD`, `git log` inside a cloned `impacket/` directory | Identifies the exact revision, relevant given the flag-surface note above |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path | `.pyc` mtimes can survive a `history -c` shell-history wipe |

## Network Evidence

```bash
# LDAP (enumeration leg) and Kerberos (AS-REQ/TGS-REQ legs)
ss -tnp | grep -E ':389|:636|:88'
```
`GetUserSPNs.py`'s network footprint is a clean two-protocol sequence: an LDAP session (TCP 389, or 636 for LDAPS) for enumeration, followed by Kerberos traffic (TCP or UDP 88) for the AS-REQ and every subsequent TGS-REQ. Unlike `secretsdump.py`/`psexec.py`/`wmiexec.py`, there is **no SMB or RPC leg at all** — this tool never touches the target host directly, only the Domain Controller's LDAP and Kerberos services. A single connection to a DC on 389/636 immediately followed by a burst of connections/exchanges on 88 from the same source, with no SMB (445) or RPC (135) traffic alongside it, is a distinctive enough shape to be worth noting on its own.

```bash
# Connection tracking, if conntrack is present — survives slightly past process exit
conntrack -L | grep -E ':389|:636|:88'
```

## OS-Level Audit Trail

```bash
ausearch -x GetUserSPNs.py 2>/dev/null
# or, broader, if a custom rule tags Python execve calls:
ausearch -k exec_python 2>/dev/null
```
The only artifact class here that reliably survives a shell-history wipe, since it's generated at the kernel `execve` level rather than by the shell.

## Memory Forensics

If the operator box is seized/imaged while the process is still resident or recently exited:
- Process memory can contain the plaintext password/NTLM hash/AES key used to authenticate, even when the *displayed* `ps`/`cmdline` output doesn't show it (e.g. sourced from an environment variable).
- Every decoded `TGS_REP`'s `enc-part` cipher bytes pass through process memory before being hex-encoded into the `$krb5tgs$...` string — a memory capture mid-run can recover crackable material for accounts whose ticket the tool hadn't finished writing to disk yet.
- If `-save` was used, the in-memory `CCache` objects (session keys, ticket structures) for every requested account are resident simultaneously for the life of the run — a single memory capture can yield reusable tickets for every target account roasted in that session, not just one.

## Timeline Correlation Value

None of the artifacts above carry much weight in isolation — their value is in **timeline correlation** against the target-side evidence in `04 - Target Evidence.md`: matching a shell-history or `auditd` execve timestamp, or the LDAP-then-Kerberos network-connection window above, against the corresponding burst of Event 4769s on the Domain Controller (each one timestamped, each one naming the requesting principal, the target SPN, and the issued ticket-encryption type) is what turns "GetUserSPNs.py ran on this box, sometime" into a provable, minute-by-minute reconstruction of exactly which accounts were roasted, in what order, and with what encryption type each one actually yielded.

## Handoff Into Hashcat

Cracking is a **separate tool, a separate process, and frequently a separate machine** from the one that ran `GetUserSPNs.py` — an `-outputfile` hash file is routinely copied off the initial-access box entirely before any cracking attempt begins, specifically to keep GPU-bound cracking work off a machine the operator doesn't want lingering on the target network. See `Hashcat/03 - Source Evidence.md` for what that separate cracking process leaves behind on whatever machine actually runs it, and `Hashcat/01 - Overview.md`'s red-flag callout for why that page's Target Evidence section is deliberately thin — hashcat itself never touches the domain at all.
