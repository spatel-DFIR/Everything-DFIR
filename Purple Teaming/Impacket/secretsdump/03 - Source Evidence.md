# Impacket — secretsdump.py — Source Evidence

Evidence left on the **attacking/operator** host. As with `psexec.py`/`wmiexec.py`, `secretsdump.py` writes **no built-in session log** — the closest thing is whatever the operator directed via `-outputfile`, which is itself a first-class piece of loot, not just an artifact. This section leans on the same generic Linux-operator-box investigation baseline as the rest of this Impacket folder; only the parts genuinely specific to `secretsdump.py` are called out in depth.

## Contents
- [Local Output Files — The Loot Itself](#local-output-files--the-loot-itself)
- [Shell History](#shell-history)
- [Live Process State](#live-process-state)
- [Impacket Installation Artifacts](#impacket-installation-artifacts)
- [Network Evidence](#network-evidence)
- [OS-Level Audit Trail](#os-level-audit-trail)
- [Memory Forensics](#memory-forensics)
- [Timeline Correlation Value](#timeline-correlation-value)

---

## Local Output Files — The Loot Itself

This is the single highest-value artifact class on the operator side for this specific tool — unlike `psexec.py`, where the operator side has almost nothing tool-specific, `secretsdump.py` runs frequently produce **durable local files containing recovered credential material in the clear** (as hashes, which are themselves directly usable for pass-the-hash without further cracking).

| Extension | Content | Notes |
|---|---|---|
| `.sam` | Local SAM database dump (`user:rid:lmhash:nthash:::`) | Written by `SAMHashes.export()` — one line per local account, plus history lines if `-history` was set |
| `.secrets` | LSA Secrets dump | Written by `LSASecrets.exportSecrets()` |
| `.cached` | Cached domain logons (MSCache2/DCC2, format `domain/user:$DCC2$<iter>#user#hash`) | Written by `LSASecrets.exportCached()` |
| `.ntds` | Full NTDS.dit NTLM hash dump (`domain\user:rid:lmhash:nthash:::`) | Written by `NTDSHashes.dump()` when `-outputfile` is set |
| `.ntds.kerberos` | Kerberos keys (AES128/AES256/RC4) per account | Only written when `-just-dc-ntlm` was **not** used |
| `.ntds.cleartext` | Any reversibly-encrypted/cleartext credential material recovered from `supplementalCredentials` | Only written when `-just-dc-ntlm` was **not** used |

**All extensions share one base filename** (`-outputfile <base>` → `<base>.sam`, `<base>.secrets`, etc.), so a single directory listing (`ls loot/`) immediately reveals the full scope of what a given `-outputfile` run recovered — the presence of a `.ntds` file alongside `.ntds.kerberos` is itself proof a full (not `-just-dc-ntlm`-limited) domain pull occurred. **Resume state** (`-resumefile`) is a further durable artifact: its presence and modification history document exactly how far a large, possibly multi-session NTDS pull progressed, and can itself be examined to determine whether a pull actually completed or was abandoned partway through.

If output was **not** redirected via `-outputfile`, the recovered hashes still appear in whatever terminal-scrollback or logging mechanism captured the operator's session (tmux/screen scrollback buffer, a script(1) transcript, a redirected `> results.txt` shell capture) — treat console-only runs as producing the *same* sensitivity of artifact, just less predictably located.

## Shell History

| Shell | File | Notes |
|---|---|---|
| bash | `~/.bash_history` | Full command line, **including the target FQDN/IP and any inline credentials** — `-just-dc`/`-just-dc-user`/`-ldapfilter` arguments in particular reveal exactly which accounts or account classes were targeted, which is itself intent evidence (e.g. `-just-dc-user krbtgt` is unambiguous Golden Ticket staging) |
| zsh | `~/.zsh_history` | Same content, plus timestamp if `EXTENDED_HISTORY` is enabled |
| fish | `~/.local/share/fish/fish_history` | YAML-structured with native per-command timestamps |

## Live Process State

```bash
ps aux | grep -i secretsdump
```
As with the rest of this Impacket family, the full invocation (including `-hashes`/`-aesKey` material passed inline) is visible via `/proc/<pid>/cmdline` to any local user on a shared operator box for the process's lifetime — a large `-just-dc` run against a big domain can leave this exposed for a meaningfully longer window than a quick `psexec.py` shell, simply because the operation itself takes longer.

## Impacket Installation Artifacts

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Version matters here more than for `psexec.py`, since `secretsdump.py`'s flag surface (`-use-remoteSSWMI`, `-use-keylist`, `-trust-keys`) has grown substantially across releases — an older Impacket install simply won't support some of these use cases at all, which is useful context when scoping what an operator *could* have done from a given toolset version |
| Script location | `find / -iname "secretsdump.py" 2>/dev/null` | Source checkout, pip console-script, or pipx isolated environment |
| Git checkout evidence | `.git/logs/HEAD` inside a cloned `impacket/` directory | Pins the exact revision, and therefore the exact flag/behavior set, available to the operator |
| Python bytecode cache | `__pycache__/*.pyc` under the impacket package path | Coarse "first run on this box" bound, survives `history -c` |

## Network Evidence

| Artifact | Command | Notes |
|---|---|---|
| Live socket state | `ss -tnp \| grep -E ':445\|:135'` | TCP 445 for Path 1 (Remote Registry) and Path 2's fallback VSS methods; TCP 135 (then a dynamic high port) additionally for Path 2's default DRSUAPI mode |
| Connection tracking | `conntrack -L \| grep -E ':445\|:135'` | Survives briefly past process exit |
| DNS/hosts evidence | resolver logs, `/etc/hosts` edits | A manual hosts-file entry to satisfy Kerberos SPN resolution against a DC hostname is the same tell documented in `Impacket/psexec/03 - Source Evidence.md` |

## OS-Level Audit Trail

```bash
ausearch -x secretsdump.py 2>/dev/null
```
Same value proposition as the rest of this folder — the one artifact class here that survives a shell-history wipe, since it's generated at the kernel `execve` level rather than by the shell.

## Memory Forensics

If the operator box is seized/imaged:
- A still-running `secretsdump.py` process's memory can contain **already-decrypted credential material** mid-processing — recovered NTLM hashes, Kerberos keys, and cleartext secrets exist as live Python string/bytes objects during the decrypt loop, well before (or even if never) written to an `-outputfile`. This is a materially richer memory-forensics target than `psexec.py`'s operator-side memory, since the *entire point* of this tool's execution is to hold credential material in memory.
- A full memory capture (`gcore`, VM snapshot) followed by a targeted string/regex search for NTLM hash format (`[0-9a-f]{32}`), `$DCC2$` prefixes, or Kerberos key-length hex blobs is a viable recovery path independent of whatever output files were or weren't retained on disk.

## Timeline Correlation Value

The operator-side artifacts above are most valuable **paired** against target-side evidence: a `.bash_history` entry for a `-just-dc` run, timestamped, correlated against a target-DC's Security 4662 (or MDI alert 2006, cross-linked from `Mimikatz/lsadump (DCSync)/04 - Target Evidence.md`) in the same window turns "a `secretsdump.py` invocation happened somewhere" into a provable causal chain. For Path 1 (Remote Registry) runs, correlate against the target's `%SystemRoot%\Temp\<random>.tmp` hive-file creation/deletion window (`04 - Target Evidence.md`) the same way. **For Path 3 (offline/local) runs, there is no target-side network artifact to correlate against at all** — the operator-side output-file timestamp is the *only* dating evidence available for when the offline analysis occurred, which is itself an important limitation to flag in any timeline built around this tool.
