# Impacket — ticketer.py — Source Evidence

Evidence left on the **operator's own** host. `ticketer.py`'s default forging path (no `-request`/`-impersonate`) is pure local Python computation with zero network I/O — the same thin-trail dynamic `Mimikatz/kerberos (Golden-Silver Ticket)/03 - Source Evidence.md` describes for `kuhl_m_kerberos_golden_data()`. What's different here: `ticketer.py` **always** writes a durable file (there is no in-process injection option, unlike Mimikatz's `/ptt`), which means the source-side artifact for this tool is *stronger and more consistently present* than Mimikatz's equivalent — there's no "skip the disk entirely" variant to account for.

## Contents
- [Shell History](#shell-history)
- [Local Output File — The .ccache Itself](#local-output-file--the-ccache-itself)
- [KRB5CCNAME Environment Variable](#krb5ccname-environment-variable)
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
| bash | `~/.bash_history` | Full command line — for a plain forge, this includes the forged identity and the **raw krbtgt/service-account key material in hex, in the clear**, same sensitivity class as the equivalent PSReadLine exposure documented for `kerberos::golden` in `Mimikatz/kerberos (Golden-Silver Ticket)/03 - Source Evidence.md`. For `-request`/`-impersonate` runs, the history line **additionally** contains the `-user`/`-password` of whatever account was used to fetch the real template ticket — a second, distinct credential exposure beyond the forging key itself |
| zsh | `~/.zsh_history` | Same content, plus timestamp if `EXTENDED_HISTORY` is enabled |
| fish | `~/.local/share/fish/fish_history` | YAML-structured with native per-command timestamps |

## Local Output File — The .ccache Itself

**This is the single highest-value, most consistently-present artifact this tool produces.** Unlike Mimikatz's `kerberos::golden`, which can skip the disk entirely via `/ptt`, `ticketer.py`'s `saveTicket()` **always** writes a file — there is no injection-only mode. Verified directly from source:

| Detail | Behavior |
|---|---|
| Default filename | `<target>.ccache`, in the current working directory — `/` in the target name is replaced with `.` (e.g. a target of `CORP/evil` saves as `CORP.evil.ccache`) |
| Format | Standard MIT Kerberos credential-cache format, readable by `klist`, `kinit`-family tooling, and any other Impacket example script's `-k` flag |
| **In-place update behavior** | If `$KRB5CCNAME` is already set and points at an **existing** file, `saveTicket()` loads that file via `CCache.loadFile()` and adds the new ticket to it, rather than always creating a fresh standalone file — meaning a single `.ccache` file recovered from an operator's host can contain **multiple** forged/legitimate tickets accumulated across several `ticketer.py` invocations, not just the most recent one |
| Sensitivity | Directly and immediately replayable — like a recovered `.kirbi`, treat a `.ccache` file as equivalent to a live, valid credential, not just evidence a forging attempt occurred |

```bash
find / -iname "*.ccache" -newer /etc/hostname 2>/dev/null
```

## KRB5CCNAME Environment Variable

`ticketer.py` reads `$KRB5CCNAME` at save time (above); every other Impacket example script reads the same variable at auth time via `-k`. On the operator's host, this variable's value — whether set in the current shell, exported in a profile/rc file, or present in a running process's environment block — directly names the forged ticket's on-disk location:

```bash
echo $KRB5CCNAME
grep -rn "KRB5CCNAME" ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile 2>/dev/null
cat /proc/<pid>/environ 2>/dev/null | tr '\0' '\n' | grep KRB5CCNAME
```
A `KRB5CCNAME` value pointing at a path that doesn't match any obvious legitimate Kerberos workflow (a home-directory `kinit`-managed default cache, a service's own configured cache path) is itself worth flagging — it's the environment-level equivalent of the `.ccache` file discovery above, and survives even if the file itself has since been deleted (the path string remains in shell config/history).

## Live Process State

```bash
ps aux | grep -i ticketer
```
As with the rest of this Impacket family, the full invocation — including `-nthash`/`-aesKey`/`-password` material passed inline — is visible via `/proc/<pid>/cmdline` to any local user on a shared operator box for the process's lifetime. `ticketer.py`'s runtime is typically very short (a single local computation, or one to two round-trips for `-request`/`-impersonate`), so this window is narrower than a long-running `secretsdump.py -just-dc` pull, but not zero.

## Impacket Installation Artifacts

Same pattern as `Impacket/secretsdump/03 - Source Evidence.md` — not re-derived in full:

| Artifact | Command | Notes |
|---|---|---|
| Package metadata | `pip3 show impacket` | Version matters here specifically for `-impersonate`/Sapphire Ticket support, which is a comparatively recent addition — an older Impacket install may only support plain Golden/Silver and `-request`/Diamond |
| Script location | `find / -iname "ticketer.py" 2>/dev/null` | Source checkout, pip console-script, or pipx isolated environment |
| Git checkout evidence | `.git/logs/HEAD` inside a cloned `impacket/` directory | Pins the exact revision, and therefore whether `-impersonate` was even available to the operator |

## Network Evidence

**Sharply split by mode — restate this from `01 - Overview.md` because it drives what's even worth looking for:**

| Mode | Network activity from the forging step itself |
|---|---|
| Plain Golden/Silver (no `-request`, no `-impersonate`) | **None.** Confirmed directly from source header: "No traffic is generated against the KDC" |
| `-request` (Diamond) | **One real Kerberos exchange** — `getKerberosTGT()` (and `getKerberosTGS()` if `-spn` is also set) — outbound to the KDC on Kerberos ports before any forgery happens |
| `-request` + `-impersonate` (Sapphire) | **Two real exchanges** — the `-request` TGT/TGS fetch above, **plus** a separate S4U2Self+U2U `TGS-REQ`/`TGS-REP` round-trip via `sendReceive()` |

```bash
ss -tnp | grep -E ':88|:464'
```
An operator host showing outbound connections to a Domain Controller on Kerberos ports (UDP/TCP 88) in the same window as a `ticketer.py -request`/`-impersonate` command in shell history is meaningful corroborating evidence — and, unlike the plain-forge case, this pattern is **expected and by-design** for these two modes, not a sign the operator's own machine was used to *inject/use* the ticket afterward (that's a separate, later step — see `Impacket/psexec/03 - Source Evidence.md` and siblings for what *using* a ticket via another Impacket tool looks like on the operator side).

## OS-Level Audit Trail

```bash
ausearch -x ticketer.py 2>/dev/null
```
Same value proposition as every sibling note in this folder — the one artifact class here that survives a shell-history wipe, since it's generated at the kernel `execve` level rather than by the shell.

## Memory Forensics

If the operator box is seized/imaged while `ticketer.py` is still running (or shortly after, before Python's garbage collector reclaims the relevant objects):
- The plaintext key material (`-nthash`/`-aesKey`), the fabricated or cloned PAC, and the ticket's session key all exist as live Python `bytes`/`str` objects in the process's own memory during the forge — recoverable via a memory capture even if the run used `-request`/`-impersonate` and the real template ticket itself was never written to disk separately.
- For `-request`/`-impersonate` runs specifically, the **genuine** TGT/TGS obtained from the KDC (`self.__tgt`, `self.__tgt_session_key` in source) also exists in memory for the process's lifetime — a second, distinct piece of live credential material beyond the final forged ticket, tied to whatever account was used for `-user`.

## Timeline Correlation Value

For a **plain Golden/Silver forge**, the operator-side artifacts documented above — shell history (with the raw key), the `.ccache` file itself, and its `KRB5CCNAME` reference — are the **entire** evidentiary record of the forging step; there is nothing target-side to correlate against until the ticket is actually used (`04 - Target Evidence.md`). This mirrors the Silver Ticket half of `Mimikatz/kerberos (Golden-Silver Ticket)/03 - Source Evidence.md`'s "Timeline Correlation Value" section exactly, and applies here to **both** Golden and Silver, since neither one's *creation* touches a DC with this tool.

For **`-request`/`-impersonate` runs**, correlate the operator-side shell-history timestamp against the **real** Event 4768/4769 the template-fetch step generates on the DC, tied to the `-user` account (`04 - Target Evidence.md`) — this is a genuinely new correlation opportunity that doesn't exist for plain forging or for any of Mimikatz's `kerberos::golden` variants, since Mimikatz has no equivalent "fetch a real ticket first" mode.
